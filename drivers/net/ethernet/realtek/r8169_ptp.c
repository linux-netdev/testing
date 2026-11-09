// SPDX-License-Identifier: GPL-2.0-only
/* r8169_ptp.c: RealTek 8169/8168/8101/8125 ethernet driver.
 *
 * PTP hardware clock and timestamping support for RTL8127A.
 */

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/ethtool.h>
#include <linux/iopoll.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/ptp_classify.h>
#include <linux/skbuff.h>
#include <linux/timekeeping.h>

#include "r8169.h"
#include "r8169_ptp.h"

/* PTP registers, accessed through the PHY OCP interface */
#define PTP_CTL				0xe400
#define PTP_CTL_EN			BIT(0)
#define PTP_CTL_TYPE_3			0x003f
#define PTP_INER			0xe402
#define PTP_INSR			0xe404
#define PTP_INT_RX_TS			BIT(2)
#define PTP_INT_TX_TS			BIT(3)
#define PTP_SYNCE_CTL			0xe406
#define PTP_SYNCE_EN			BIT(0)
#define PTP_GEN_CFG			0xe408
#define PTP_GEN_CFG_INT_CLR_MODE	BIT(0)
#define PTP_CLK_CFG			0xe410
#define PTP_CLK_CFG_EXEC		BIT(0)
#define PTP_CLK_CFG_MODE		GENMASK(3, 1)
#define PTP_TRX_TS_STA			0xe430
#define PTP_TRX_TS_RD			BIT(0)
#define PTP_TRX_TS_SEL_RX		BIT(1)
#define PTP_TRX_TS_MSGTYPE		GENMASK(3, 2)
#define PTP_TRX_TS_EXEC			BIT(4)
#define PTP_TRX_TS_TX_PDLYRSP_RDY	BIT(12)
#define PTP_TRX_TS_TX_PDLYREQ_RDY	BIT(13)
#define PTP_TRX_TS_TX_DLYREQ_RDY	BIT(14)
#define PTP_TRX_TS_TX_SYNC_RDY		BIT(15)
#define PTP_TRX_TS_TX_RDY		GENMASK(15, 12)
/* Time registers, PTP_CFG_TIME for the clock, PTP_TRX_TS_TIME for packets */
#define PTP_CFG_TIME			0xe412
#define PTP_TRX_TS_TIME			0xe446
#define PTP_TIME_NS_LO			0x0
#define PTP_TIME_NS_HI			0x2
#define PTP_TIME_S_LO			0x4
#define PTP_TIME_S_MI			0x6
#define PTP_TIME_S_HI			0x8
#define PTP_TIME_NS_HI_MASK		GENMASK(13, 0)
#define PTP_TIME_NSEC_MASK		GENMASK(29, 0)
#define PTP_TIME_SEC_MASK		GENMASK_ULL(47, 0)
#define PTP_RATE_HI_MASK		GENMASK(21, 16)

#define PTP_MAX_ADJ			488281
#define RTL8169_PTP_TX_TIMEOUT		(15 * HZ)

/* ptp->state bits */
enum rtl8169_ptp_state {
	RTL8169_PTP_TX_IN_PROGRESS,
};

/* PTP_CLK_CFG clock adjust modes */
enum rtl8169_ptp_clkadj_mode {
	PTP_CLKADJ_DIRECT_READ		= 4,
	PTP_CLKADJ_DIRECT_WRITE		= 6,
	PTP_CLKADJ_INC_STEP		= 8,
	PTP_CLKADJ_DEC_STEP		= 10,
	PTP_CLKADJ_RATE_WRITE		= 14,
};

static u16 rtl8169_ptp_read(struct rtl8169_ptp *ptp, u32 reg)
{
	return r8168_phy_ocp_read(ptp->tp, reg);
}

static void rtl8169_ptp_write(struct rtl8169_ptp *ptp, u32 reg, u16 val)
{
	r8168_phy_ocp_write(ptp->tp, reg, val);
}

static void rtl8169_ptp_modify(struct rtl8169_ptp *ptp, u32 reg, u16 mask,
			       u16 set)
{
	u16 val = rtl8169_ptp_read(ptp, reg);

	rtl8169_ptp_write(ptp, reg, (val & ~mask) | set);
}

/* Poll until (reg & mask) is non-zero (set == true) or zero (set == false).
 * Returns the last register value read, or -ETIMEDOUT.
 */
static int rtl8169_ptp_poll(struct rtl8169_ptp *ptp, u32 reg, u16 mask,
			    bool set)
{
	u16 val;
	int ret;

	ret = read_poll_timeout_atomic(rtl8169_ptp_read, val,
				       !!(val & mask) == set, 1, 1000, false,
				       ptp, reg);
	if (ret) {
		if (net_ratelimit())
			netdev_err(ptp->dev, "PTP reg 0x%04x poll timeout\n",
				   reg);
		return ret;
	}

	return val;
}

static void rtl8169_ptp_clkadj(struct rtl8169_ptp *ptp,
			       enum rtl8169_ptp_clkadj_mode mode)
{
	rtl8169_ptp_modify(ptp, PTP_CLK_CFG, PTP_CLK_CFG_MODE,
			   PTP_CLK_CFG_EXEC | mode);
	rtl8169_ptp_poll(ptp, PTP_CLK_CFG, PTP_CLK_CFG_EXEC, false);
}

static void rtl8169_ptp_read_time(struct rtl8169_ptp *ptp, u32 base,
				  struct timespec64 *ts)
{
	u64 sec;
	u32 nsec;

	nsec = rtl8169_ptp_read(ptp, base + PTP_TIME_NS_HI) &
	       PTP_TIME_NS_HI_MASK;
	nsec <<= 16;
	nsec |= rtl8169_ptp_read(ptp, base + PTP_TIME_NS_LO);

	sec = rtl8169_ptp_read(ptp, base + PTP_TIME_S_HI);
	sec <<= 16;
	sec |= rtl8169_ptp_read(ptp, base + PTP_TIME_S_MI);
	sec <<= 16;
	sec |= rtl8169_ptp_read(ptp, base + PTP_TIME_S_LO);

	ts->tv_sec = sec;
	ts->tv_nsec = nsec;
}

static void rtl8169_ptp_write_time(struct rtl8169_ptp *ptp,
				   const struct timespec64 *ts)
{
	u64 sec = ts->tv_sec & PTP_TIME_SEC_MASK;
	u32 nsec = ts->tv_nsec & PTP_TIME_NSEC_MASK;

	rtl8169_ptp_write(ptp, PTP_CFG_TIME + PTP_TIME_NS_LO, nsec);
	rtl8169_ptp_write(ptp, PTP_CFG_TIME + PTP_TIME_NS_HI, nsec >> 16);
	rtl8169_ptp_write(ptp, PTP_CFG_TIME + PTP_TIME_S_LO, sec);
	rtl8169_ptp_write(ptp, PTP_CFG_TIME + PTP_TIME_S_MI, sec >> 16);
	rtl8169_ptp_write(ptp, PTP_CFG_TIME + PTP_TIME_S_HI, sec >> 32);
}

/* Latch the RX or TX timestamp of the given message type into the
 * PTP_TRX_TS_TIME registers.
 */
static void rtl8169_ptp_trx_ts_cmd(struct rtl8169_ptp *ptp, u16 cmd)
{
	rtl8169_ptp_modify(ptp, PTP_TRX_TS_STA,
			   PTP_TRX_TS_SEL_RX | PTP_TRX_TS_MSGTYPE,
			   PTP_TRX_TS_RD | cmd);
	rtl8169_ptp_poll(ptp, PTP_TRX_TS_STA, PTP_TRX_TS_RD, false);
}

static void rtl8169_ptp_egress_time(struct rtl8169_ptp *ptp,
				    struct timespec64 *ts)
{
	u8 msgtype;
	int val;

	val = rtl8169_ptp_poll(ptp, PTP_TRX_TS_STA, PTP_TRX_TS_TX_RDY, true);
	if (val < 0)
		val = 0;

	switch (val & PTP_TRX_TS_TX_RDY) {
	case PTP_TRX_TS_TX_PDLYRSP_RDY:
		msgtype = PTP_MSGTYPE_PDELAY_RESP;
		break;
	case PTP_TRX_TS_TX_PDLYREQ_RDY:
		msgtype = PTP_MSGTYPE_PDELAY_REQ;
		break;
	case PTP_TRX_TS_TX_DLYREQ_RDY:
		msgtype = PTP_MSGTYPE_DELAY_REQ;
		break;
	case PTP_TRX_TS_TX_SYNC_RDY:
	default:
		msgtype = PTP_MSGTYPE_SYNC;
		break;
	}

	rtl8169_ptp_trx_ts_cmd(ptp, FIELD_PREP(PTP_TRX_TS_MSGTYPE, msgtype) |
				    PTP_TRX_TS_EXEC);
	rtl8169_ptp_read_time(ptp, PTP_TRX_TS_TIME, ts);
}

static void rtl8169_ptp_hwtstamp_enable(struct rtl8169_ptp *ptp, bool enable)
{
	unsigned long flags;

	spin_lock_irqsave(&ptp->lock, flags);

	rtl8169_ptp_modify(ptp, PTP_SYNCE_CTL, PTP_SYNCE_EN, 0);
	if (enable) {
		rtl8169_ptp_modify(ptp, PTP_INER, 0,
				   PTP_INT_RX_TS | PTP_INT_TX_TS);
		rtl8169_ptp_modify(ptp, PTP_GEN_CFG, 0,
				   PTP_GEN_CFG_INT_CLR_MODE);
		rtl8169_ptp_write(ptp, PTP_INSR, 0xffff);
		rtl8169_ptp_write(ptp, PTP_CTL, PTP_CTL_TYPE_3 | BIT(12));
	} else {
		rtl8169_ptp_modify(ptp, PTP_INER,
				   PTP_INT_RX_TS | PTP_INT_TX_TS, 0);
		rtl8169_ptp_modify(ptp, PTP_CTL, PTP_CTL_EN, 0);
	}
	rtl8169_ptp_modify(ptp, 0xa640, 0, BIT(15));

	spin_unlock_irqrestore(&ptp->lock, flags);
}

static void rtl8169_ptp_settime(struct rtl8169_ptp *ptp,
				const struct timespec64 *ts)
{
	unsigned long flags;

	spin_lock_irqsave(&ptp->lock, flags);
	rtl8169_ptp_write_time(ptp, ts);
	rtl8169_ptp_clkadj(ptp, PTP_CLKADJ_DIRECT_WRITE);
	spin_unlock_irqrestore(&ptp->lock, flags);
}

static int rtl8169_ptp_adjfine(struct ptp_clock_info *info, long scaled_ppm)
{
	struct rtl8169_ptp *ptp = container_of(info, struct rtl8169_ptp, info);
	s32 ppb = scaled_ppm_to_ppb(scaled_ppm);
	unsigned long flags;
	u32 rate;

	rate = div_u64((u64)abs(ppb) << 32, NSEC_PER_SEC);
	if (ppb < 0)
		rate = -rate;

	spin_lock_irqsave(&ptp->lock, flags);
	rtl8169_ptp_write(ptp, PTP_CFG_TIME + PTP_TIME_NS_LO, rate);
	rtl8169_ptp_write(ptp, PTP_CFG_TIME + PTP_TIME_NS_HI,
			  FIELD_GET(PTP_RATE_HI_MASK, rate));
	rtl8169_ptp_clkadj(ptp, PTP_CLKADJ_RATE_WRITE);
	spin_unlock_irqrestore(&ptp->lock, flags);

	return 0;
}

static int rtl8169_ptp_adjtime(struct ptp_clock_info *info, s64 delta)
{
	struct rtl8169_ptp *ptp = container_of(info, struct rtl8169_ptp, info);
	struct timespec64 d = ns_to_timespec64(abs(delta));
	unsigned long flags;

	spin_lock_irqsave(&ptp->lock, flags);
	rtl8169_ptp_write_time(ptp, &d);
	rtl8169_ptp_clkadj(ptp, delta < 0 ? PTP_CLKADJ_DEC_STEP :
					    PTP_CLKADJ_INC_STEP);
	spin_unlock_irqrestore(&ptp->lock, flags);

	return 0;
}

static int rtl8169_ptp_gettimex64(struct ptp_clock_info *info,
				  struct timespec64 *ts,
				  struct ptp_system_timestamp *sts)
{
	struct rtl8169_ptp *ptp = container_of(info, struct rtl8169_ptp, info);
	unsigned long flags;

	spin_lock_irqsave(&ptp->lock, flags);
	ptp_read_system_prets(sts);
	rtl8169_ptp_clkadj(ptp, PTP_CLKADJ_DIRECT_READ);
	ptp_read_system_postts(sts);
	rtl8169_ptp_read_time(ptp, PTP_CFG_TIME, ts);
	spin_unlock_irqrestore(&ptp->lock, flags);

	return 0;
}

static int rtl8169_ptp_settime64(struct ptp_clock_info *info,
				 const struct timespec64 *ts)
{
	struct rtl8169_ptp *ptp = container_of(info, struct rtl8169_ptp, info);

	rtl8169_ptp_settime(ptp, ts);

	return 0;
}

static const struct ptp_clock_info rtl8169_ptp_info = {
	.owner		= THIS_MODULE,
	.max_adj	= PTP_MAX_ADJ,
	.adjfine	= rtl8169_ptp_adjfine,
	.adjtime	= rtl8169_ptp_adjtime,
	.gettimex64	= rtl8169_ptp_gettimex64,
	.settime64	= rtl8169_ptp_settime64,
};

static void rtl8169_ptp_tx_complete(struct rtl8169_ptp *ptp,
				    struct skb_shared_hwtstamps *hwts)
{
	struct sk_buff *skb = ptp->tx_skb;

	ptp->tx_skb = NULL;
	clear_bit_unlock(RTL8169_PTP_TX_IN_PROGRESS, &ptp->state);

	if (hwts)
		skb_tstamp_tx(skb, hwts);
	dev_kfree_skb_any(skb);
}

static void rtl8169_ptp_tx_work(struct work_struct *work)
{
	struct rtl8169_ptp *ptp = container_of(work, struct rtl8169_ptp,
					       tx_work);
	struct skb_shared_hwtstamps hwts = {};
	struct timespec64 ts;
	unsigned long flags;
	bool ready;

	if (!ptp->tx_skb)
		return;

	if (time_is_before_jiffies(ptp->tx_start + RTL8169_PTP_TX_TIMEOUT)) {
		spin_lock_irqsave(&ptp->lock, flags);
		rtl8169_ptp_write(ptp, PTP_INSR, PTP_INT_TX_TS);
		spin_unlock_irqrestore(&ptp->lock, flags);

		ptp->tx_timeouts++;
		rtl8169_ptp_tx_complete(ptp, NULL);
		return;
	}

	spin_lock_irqsave(&ptp->lock, flags);
	ready = rtl8169_ptp_read(ptp, PTP_INSR) & PTP_INT_TX_TS;
	if (ready) {
		rtl8169_ptp_write(ptp, PTP_INSR, PTP_INT_TX_TS);
		rtl8169_ptp_egress_time(ptp, &ts);
	}
	spin_unlock_irqrestore(&ptp->lock, flags);

	if (!ready) {
		schedule_work(&ptp->tx_work);
		return;
	}

	hwts.hwtstamp = timespec64_to_ktime(ts);
	ptp->tx_pkts++;
	rtl8169_ptp_tx_complete(ptp, &hwts);
}

void rtl8169_ptp_tx_tstamp(struct rtl8169_ptp *ptp, struct sk_buff *skb)
{
	if (ptp->config.tx_type != HWTSTAMP_TX_ON ||
	    test_and_set_bit_lock(RTL8169_PTP_TX_IN_PROGRESS, &ptp->state)) {
		ptp->tx_skipped++;
		return;
	}

	skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
	ptp->tx_skb = skb_get(skb);
	ptp->tx_start = jiffies;
	schedule_work(&ptp->tx_work);
}

void rtl8169_ptp_rx_tstamp(struct rtl8169_ptp *ptp, struct sk_buff *skb)
{
	unsigned int ptp_class;
	struct ptp_header *hdr;
	struct timespec64 ts;
	unsigned long flags;
	u8 msgtype;

	if (!READ_ONCE(ptp->rx_enabled))
		return;

	ptp_class = ptp_classify_raw(skb);
	if (ptp_class == PTP_CLASS_NONE)
		return;

	skb_reset_mac_header(skb);
	hdr = ptp_parse_header(skb, ptp_class);
	if (unlikely(!hdr))
		return;

	/* Only event messages are timestamped by the hardware */
	msgtype = ptp_get_msgtype(hdr, ptp_class);
	if (msgtype > PTP_MSGTYPE_PDELAY_RESP)
		return;

	spin_lock_irqsave(&ptp->lock, flags);
	rtl8169_ptp_trx_ts_cmd(ptp, PTP_TRX_TS_SEL_RX |
				    FIELD_PREP(PTP_TRX_TS_MSGTYPE, msgtype) |
				    PTP_TRX_TS_EXEC);
	rtl8169_ptp_read_time(ptp, PTP_TRX_TS_TIME, &ts);
	spin_unlock_irqrestore(&ptp->lock, flags);

	skb_hwtstamps(skb)->hwtstamp = timespec64_to_ktime(ts);
}

int rtl8169_ptp_hwtstamp_get(struct rtl8169_ptp *ptp,
			     struct kernel_hwtstamp_config *config)
{
	hwtstamp_config_to_kernel(config, &ptp->config);

	return 0;
}

int rtl8169_ptp_hwtstamp_set(struct rtl8169_ptp *ptp,
			     struct kernel_hwtstamp_config *config,
			     struct netlink_ext_ack *extack)
{
	bool enable = false;
	bool rx_enabled;

	if (!ptp->clock)
		return -ENETDOWN;

	if (config->flags)
		return -EINVAL;

	switch (config->tx_type) {
	case HWTSTAMP_TX_ON:
		enable = true;
		break;
	case HWTSTAMP_TX_OFF:
		break;
	default:
		return -ERANGE;
	}

	switch (config->rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		rx_enabled = false;
		break;
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
		config->rx_filter = HWTSTAMP_FILTER_PTP_V2_EVENT;
		rx_enabled = true;
		enable = true;
		break;
	default:
		return -ERANGE;
	}

	if (ptp->config.tx_type != config->tx_type ||
	    ptp->config.rx_filter != config->rx_filter) {
		hwtstamp_config_from_kernel(&ptp->config, config);
		rtl8169_ptp_hwtstamp_enable(ptp, enable);
	}
	WRITE_ONCE(ptp->rx_enabled, rx_enabled);

	return 0;
}

int rtl8169_ptp_get_ts_info(struct rtl8169_ptp *ptp,
			    struct kernel_ethtool_ts_info *info)
{
	info->so_timestamping = SOF_TIMESTAMPING_TX_SOFTWARE |
				SOF_TIMESTAMPING_TX_HARDWARE |
				SOF_TIMESTAMPING_RX_HARDWARE |
				SOF_TIMESTAMPING_RAW_HARDWARE;

	if (ptp->clock)
		info->phc_index = ptp_clock_index(ptp->clock);

	info->tx_types = BIT(HWTSTAMP_TX_OFF) | BIT(HWTSTAMP_TX_ON);
	info->rx_filters = BIT(HWTSTAMP_FILTER_NONE) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_EVENT) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_L4_EVENT) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_SYNC) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_L4_SYNC) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_DELAY_REQ) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ);

	return 0;
}

void rtl8169_ptp_get_ts_stats(struct rtl8169_ptp *ptp,
			      struct ethtool_ts_stats *stats)
{
	stats->pkts = ptp->tx_pkts;
	stats->lost = ptp->tx_timeouts;
	stats->err = ptp->tx_skipped;
}

void rtl8169_ptp_set_local_time(struct rtl8169_ptp *ptp)
{
	struct timespec64 ts;

	ktime_get_real_ts64(&ts);
	rtl8169_ptp_settime(ptp, &ts);
}

void rtl8169_ptp_init(struct rtl8169_ptp *ptp)
{
	struct ptp_clock *clock;

	ptp->info = rtl8169_ptp_info;
	snprintf(ptp->info.name, sizeof(ptp->info.name), "%pm",
		 ptp->dev->dev_addr);

	clock = ptp_clock_register(&ptp->info, ptp->parent);
	if (IS_ERR(clock)) {
		netdev_err(ptp->dev, "failed to register PTP clock: %pe\n",
			   clock);
		return;
	}
	ptp->clock = clock;

	ptp->config.tx_type = HWTSTAMP_TX_OFF;
	ptp->config.rx_filter = HWTSTAMP_FILTER_NONE;
	rtl8169_ptp_hwtstamp_enable(ptp, false);
}

void rtl8169_ptp_stop(struct rtl8169_ptp *ptp)
{
	if (!ptp->clock)
		return;

	ptp->config.tx_type = HWTSTAMP_TX_OFF;
	ptp->config.rx_filter = HWTSTAMP_FILTER_NONE;
	WRITE_ONCE(ptp->rx_enabled, false);
	rtl8169_ptp_hwtstamp_enable(ptp, false);
	cancel_work_sync(&ptp->tx_work);
	if (ptp->tx_skb)
		rtl8169_ptp_tx_complete(ptp, NULL);

	ptp_clock_unregister(ptp->clock);
	ptp->clock = NULL;
}

void rtl8169_ptp_setup(struct rtl8169_ptp *ptp, struct rtl8169_private *tp,
		       struct net_device *dev, struct device *parent)
{
	ptp->tp = tp;
	ptp->dev = dev;
	ptp->parent = parent;
	spin_lock_init(&ptp->lock);
	INIT_WORK(&ptp->tx_work, rtl8169_ptp_tx_work);
}
