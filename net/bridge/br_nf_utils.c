// SPDX-License-Identifier: GPL-2.0-only
#include <linux/netdevice.h>
#include <linux/netfilter.h>

#include "br_private.h"

static bool nf_br_fdb_valid_dst(const struct net_device *dev,
				const unsigned char *addr, u16 vid)
{
	const struct net_bridge_fdb_entry *f;
	const struct net_bridge_port *p;

	p = br_port_get_check_rcu(dev);
	if (!p)
		return false;

	if (!vid && br_opt_get(p->br, BROPT_VLAN_ENABLED))
		vid = br_get_pvid(nbp_vlan_group_rcu(p));

	/* Offloaded packets do not refresh the entry, it can age out. */
	f = br_fdb_find_rcu(p->br, addr, vid);

	return !f || br_fdb_dst_port(f) == p;
}

static const struct nf_br_utils nf_br_utils = {
	.fdb_valid_dst	= nf_br_fdb_valid_dst,
};

void br_nf_utils_init(void)
{
	rcu_assign_pointer(nf_br_utils_hook, &nf_br_utils);
}

void br_nf_utils_fini(void)
{
	RCU_INIT_POINTER(nf_br_utils_hook, NULL);
}
