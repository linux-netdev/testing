/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NETNS_FLOW_TABLE_H
#define __NETNS_FLOW_TABLE_H

#include <linux/spinlock.h>
#include <linux/types.h>

struct nf_flow_table_stat {
	unsigned int count_wq_add;
	unsigned int count_wq_del;
	unsigned int count_wq_stats;
};

struct netns_ft {
	/* Protects nr_ft and exiting. */
	spinlock_t		lock;
	/* Number of flowtables attached to this netns. */
	int			nr_ft;
	/* Set at netns exit; the statistics are then released by the
	 * last flowtable teardown.
	 */
	bool			exiting;
	struct nf_flow_table_stat __percpu *stat;
};
#endif
