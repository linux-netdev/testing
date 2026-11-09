/* SPDX-License-Identifier: GPL-2.0-only */
/* r8169_ptp.h: RealTek 8169/8168/8101/8125 ethernet driver.
 *
 * PTP hardware clock and timestamping support.
 */

#ifndef _R8169_PTP_H
#define _R8169_PTP_H

#include <linux/net_tstamp.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

struct device;
struct ethtool_ts_stats;
struct kernel_ethtool_ts_info;
struct net_device;
struct netlink_ext_ack;
struct rtl8169_private;
struct sk_buff;

struct rtl8169_ptp {
	struct rtl8169_private *tp;
	struct net_device *dev;
	struct device *parent;
	struct ptp_clock_info info;
	struct ptp_clock *clock;
	spinlock_t lock;	/* serialize PTP register access sequences */
	struct hwtstamp_config config;
	bool rx_enabled;
	struct work_struct tx_work;
	struct sk_buff *tx_skb;
	unsigned long tx_start;
	unsigned long state;
	u64 tx_pkts;
	u64 tx_timeouts;
	u64 tx_skipped;
};

void rtl8169_ptp_setup(struct rtl8169_ptp *ptp, struct rtl8169_private *tp,
		       struct net_device *dev, struct device *parent);
void rtl8169_ptp_init(struct rtl8169_ptp *ptp);
void rtl8169_ptp_stop(struct rtl8169_ptp *ptp);
void rtl8169_ptp_set_local_time(struct rtl8169_ptp *ptp);
void rtl8169_ptp_tx_tstamp(struct rtl8169_ptp *ptp, struct sk_buff *skb);
void rtl8169_ptp_rx_tstamp(struct rtl8169_ptp *ptp, struct sk_buff *skb);
int rtl8169_ptp_hwtstamp_get(struct rtl8169_ptp *ptp,
			     struct kernel_hwtstamp_config *config);
int rtl8169_ptp_hwtstamp_set(struct rtl8169_ptp *ptp,
			     struct kernel_hwtstamp_config *config,
			     struct netlink_ext_ack *extack);
int rtl8169_ptp_get_ts_info(struct rtl8169_ptp *ptp,
			    struct kernel_ethtool_ts_info *info);
void rtl8169_ptp_get_ts_stats(struct rtl8169_ptp *ptp,
			      struct ethtool_ts_stats *stats);

#endif /* _R8169_PTP_H */
