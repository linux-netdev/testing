/* SPDX-License-Identifier: GPL-2.0-only */
/* r8169_ptp.h: RealTek 8169/8168/8101/8125 ethernet driver.
 *
 * PTP hardware clock support.
 */

#ifndef _R8169_PTP_H
#define _R8169_PTP_H

#include <linux/ptp_clock_kernel.h>
#include <linux/spinlock.h>

struct device;
struct net_device;
struct rtl8169_private;

struct rtl8169_ptp {
	struct rtl8169_private *tp;
	struct net_device *dev;
	struct device *parent;
	struct ptp_clock_info info;
	struct ptp_clock *clock;
	spinlock_t lock;	/* serialize PTP register access sequences */
};

void rtl8169_ptp_setup(struct rtl8169_ptp *ptp, struct rtl8169_private *tp,
		       struct net_device *dev, struct device *parent);
void rtl8169_ptp_init(struct rtl8169_ptp *ptp);
void rtl8169_ptp_stop(struct rtl8169_ptp *ptp);
void rtl8169_ptp_set_local_time(struct rtl8169_ptp *ptp);

#endif /* _R8169_PTP_H */
