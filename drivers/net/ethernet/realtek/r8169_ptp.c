// SPDX-License-Identifier: GPL-2.0-only
/* r8169_ptp.c: RealTek 8169/8168/8101/8125 ethernet driver.
 *
 * PTP hardware clock support for RTL8127A.
 */

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/iopoll.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/netdevice.h>
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

	rtl8169_ptp_hwtstamp_enable(ptp, false);
}

void rtl8169_ptp_stop(struct rtl8169_ptp *ptp)
{
	if (!ptp->clock)
		return;

	rtl8169_ptp_hwtstamp_enable(ptp, false);

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
}
