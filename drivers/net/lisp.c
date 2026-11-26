// SPDX-License-Identifier: GPL-2.0
/* LISP: data plane of the Locator/ID Separation Protocol, RFC 9300.
 *
 * Copyright (c) 2026 Vincent Jardin <vjardin@free.fr>, Free Mobile
 */

#include <linux/hash.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_arp.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/rculist.h>
#include <net/dsfield.h>
#include <net/dst_metadata.h>
#include <net/gro_cells.h>
#include <net/gso.h>
#include <net/icmp.h>
#include <net/inet_ecn.h>
#include <net/ip6_route.h>
#include <net/ip_tunnels.h>
#include <net/ipv6.h>
#include <net/l3mdev.h>
#include <net/netns/generic.h>
#include <net/rtnetlink.h>
#include <net/udp_tunnel.h>

/* RFC 9300, section 5.1 */
#define LISP_UDP_PORT		4341

/* RFC 9300, section 5.3 */
struct lisphdr {
	u8	flags;
	u8	nonce[3];
	__be32	iid_lsb;
};

#define LISP_F_I		0x08	/* an instance ID is present */
#define LISP_F_KK		0x03	/* the payload is encrypted, RFC 8061 */
#define LISP_IID_SHIFT		8
#define LISP_IID_MAX		0xffffff

#define LISP_BASE_HLEN		(sizeof(struct udphdr) + sizeof(struct lisphdr))
#define LISP_IPV4_HLEN		(sizeof(struct iphdr) + LISP_BASE_HLEN)
#define LISP_IPV6_HLEN		(sizeof(struct ipv6hdr) + LISP_BASE_HLEN)

#define LISP_IID_HASH_BITS	10
#define LISP_IID_HASH_SIZE	BIT(LISP_IID_HASH_BITS)

static unsigned int lisp_net_id;

struct lisp_net {
	struct list_head	dev_list;
	struct list_head	sock_list;
	/* protects the two lists, and the devices of the sockets */
	struct mutex		lock;
};

struct lisp_dev;

/* The UDP sockets of an l3mdev, shared by the devices that use it. */
struct lisp_sock {
	struct sock		*sk4;
	struct sock		*sk6;
	struct lisp_dev __rcu	*md_dev;
	struct list_head	list;
	struct rcu_head		rcu;
	int			refcnt;
	struct hlist_head	iid_list[LISP_IID_HASH_SIZE];
};

struct lisp_dev {
	struct hlist_node	hlist;
	struct list_head	next;
	struct net		*net;	/* netns of the RLOCs */
	struct net_device	*dev;
	struct lisp_sock __rcu	*sock;
	struct gro_cells	gro_cells;
	struct in6_addr		local6;
	__be32			local;
	u32			iid;
	int			link;
	bool			collect_md;
};

static struct hlist_head *lisp_iid_head(struct lisp_sock *ls, u32 iid)
{
	return &ls->iid_list[hash_32(iid, LISP_IID_HASH_BITS)];
}

static struct lisp_dev *lisp_lookup(struct lisp_sock *ls, u32 iid)
{
	struct lisp_dev *lisp;

	/* A device that left for another socket may still be walked here. */
	hlist_for_each_entry_rcu(lisp, lisp_iid_head(ls, iid), hlist)
		if (lisp->iid == iid && rcu_access_pointer(lisp->sock) == ls)
			return lisp;

	return rcu_dereference(ls->md_dev);
}

/* RFC 9300, section 5.3: the inner header gets the congestion indication and
 * the DSCP of the outer header, and its TTL when that one is lower.
 */
static int lisp_decap_fields(struct sk_buff *skb, u8 tos, u8 ttl)
{
	u8 dscp = tos & ~INET_ECN_MASK;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;

	if (skb->protocol == htons(ETH_P_IP)) {
		if (skb_ensure_writable(skb, sizeof(*iph)))
			return -ENOMEM;

		iph = ip_hdr(skb);
		if (INET_ECN_decapsulate(skb, tos, iph->tos) > 1)
			return -EINVAL;

		ipv4_change_dsfield(iph, INET_ECN_MASK, dscp);
		if (ttl < iph->ttl) {
			csum_replace2(&iph->check, htons(iph->ttl << 8),
				      htons(ttl << 8));
			iph->ttl = ttl;
		}
		return 0;
	}

	if (skb_ensure_writable(skb, sizeof(*ip6h)))
		return -ENOMEM;

	ip6h = ipv6_hdr(skb);
	if (INET_ECN_decapsulate(skb, tos, ipv6_get_dsfield(ip6h)) > 1)
		return -EINVAL;

	if (ttl >= ip6h->hop_limit &&
	    dscp == (ipv6_get_dsfield(ip6h) & ~INET_ECN_MASK))
		return 0;

	skb_postpull_rcsum(skb, ip6h, sizeof(*ip6h));
	ipv6_change_dsfield(ip6h, INET_ECN_MASK, dscp);
	if (ttl < ip6h->hop_limit)
		ip6h->hop_limit = ttl;
	skb_postpush_rcsum(skb, ip6h, sizeof(*ip6h));

	return 0;
}

static int lisp_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	unsigned short family = AF_INET6;
	struct metadata_dst *tun_dst;
	const struct lisphdr *lh;
	struct lisp_sock *ls;
	struct lisp_dev *lisp;
	unsigned int len;
	__be16 proto;
	u32 iid = 0;
	u8 tos, ttl;
	int err;

	ls = rcu_dereference_sk_user_data(sk);
	if (!ls)
		goto drop;

	if (!pskb_may_pull(skb, LISP_BASE_HLEN + 1))
		goto drop;

	lh = (const struct lisphdr *)(udp_hdr(skb) + 1);
	if (lh->flags & LISP_F_KK)
		goto drop;

	if (lh->flags & LISP_F_I)
		iid = be32_to_cpu(lh->iid_lsb) >> LISP_IID_SHIFT;

	lisp = lisp_lookup(ls, iid);
	if (!lisp)
		goto drop;

	switch (*(const u8 *)(lh + 1) >> 4) {
	case 4:
		proto = htons(ETH_P_IP);
		break;
	case 6:
		if (!ipv6_mod_enabled())
			goto rx_dropped;
		proto = htons(ETH_P_IPV6);
		break;
	default:
		goto rx_frame_error;
	}

	if (skb->protocol == htons(ETH_P_IP)) {
		family = AF_INET;
		tos = ip_hdr(skb)->tos;
		ttl = ip_hdr(skb)->ttl;
	} else {
		tos = ipv6_get_dsfield(ipv6_hdr(skb));
		ttl = ipv6_hdr(skb)->hop_limit;
	}

	if (iptunnel_pull_header(skb, LISP_BASE_HLEN, proto,
				 !net_eq(lisp->net, dev_net(lisp->dev))))
		goto rx_dropped;

	if (lisp->collect_md) {
		IP_TUNNEL_DECLARE_FLAGS(flags) = { };

		__set_bit(IP_TUNNEL_KEY_BIT, flags);
		tun_dst = udp_tun_rx_dst(skb, family, flags,
					 key32_to_tunnel_id(cpu_to_be32(iid)),
					 0);
		if (!tun_dst)
			goto rx_dropped;

		skb_dst_set(skb, &tun_dst->dst);
	}

	skb->dev = lisp->dev;
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);

	if (!pskb_inet_may_pull(skb)) {
		DEV_STATS_INC(lisp->dev, rx_length_errors);
		DEV_STATS_INC(lisp->dev, rx_errors);
		goto drop;
	}

	err = lisp_decap_fields(skb, tos, ttl);
	if (err == -ENOMEM)
		goto rx_dropped;
	if (err)
		goto rx_frame_error;

	len = skb->len;
	if (gro_cells_receive(&lisp->gro_cells, skb) == NET_RX_SUCCESS)
		dev_dstats_rx_add(lisp->dev, len);

	return 0;

rx_frame_error:
	DEV_STATS_INC(lisp->dev, rx_frame_errors);
	DEV_STATS_INC(lisp->dev, rx_errors);
	goto drop;
rx_dropped:
	dev_dstats_rx_dropped(lisp->dev);
drop:
	kfree_skb(skb);
	return 0;
}

static int lisp_udp_encap_err_lookup(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

static struct sock *lisp_udp_sock(struct net *net, int ifindex,
				  unsigned short family, struct lisp_sock *ls)
{
	struct udp_tunnel_sock_cfg tunnel_cfg = { };
	struct udp_port_cfg udp_conf = { };
	struct socket *sock;
	int err;

	udp_conf.family = family;
	udp_conf.ipv6_v6only = family == AF_INET6;
	udp_conf.local_udp_port = htons(LISP_UDP_PORT);
	udp_conf.bind_ifindex = ifindex;

	err = udp_sock_create(net, &udp_conf, &sock);
	if (err < 0)
		return ERR_PTR(err);

	udp_allow_gso(sock->sk);

	tunnel_cfg.sk_user_data = ls;
	tunnel_cfg.encap_type = 1;
	tunnel_cfg.encap_rcv = lisp_udp_encap_recv;
	tunnel_cfg.encap_err_lookup = lisp_udp_encap_err_lookup;
	setup_udp_tunnel_sock(net, sock->sk, &tunnel_cfg);

	return sock->sk;
}

static void lisp_sock_release(struct lisp_sock *ls)
{
	udp_tunnel_sock_release(ls->sk4);
	if (ls->sk6)
		udp_tunnel_sock_release(ls->sk6);
	kfree_rcu(ls, rcu);
}

/* A socket per family, as vxlan and geneve have: an IPv6 socket only takes
 * the IPv4 packets too when net.ipv6.bindv6only allows it.
 */
static struct lisp_sock *lisp_sock_create(struct net *net, int ifindex)
{
	struct lisp_sock *ls;
	struct sock *sk;

	ls = kzalloc_obj(*ls);
	if (!ls)
		return ERR_PTR(-ENOMEM);

	ls->refcnt = 1;

	sk = lisp_udp_sock(net, ifindex, AF_INET, ls);
	if (IS_ERR(sk)) {
		kfree(ls);
		return ERR_CAST(sk);
	}
	ls->sk4 = sk;

	if (!ipv6_mod_enabled())
		return ls;

	sk = lisp_udp_sock(net, ifindex, AF_INET6, ls);
	if (IS_ERR(sk)) {
		lisp_sock_release(ls);
		return ERR_CAST(sk);
	}
	ls->sk6 = sk;

	return ls;
}

static bool lisp_sock_busy(struct lisp_sock *ls, const struct lisp_dev *lisp)
{
	const struct lisp_dev *tmp;

	if (lisp->collect_md)
		return rcu_access_pointer(ls->md_dev);

	hlist_for_each_entry(tmp, lisp_iid_head(ls, lisp->iid), hlist)
		if (tmp->iid == lisp->iid)
			return true;

	return false;
}

/* The l3mdev of the RLOCs: the link, or the one that the link is in. */
static int lisp_l3mdev(const struct lisp_dev *lisp)
{
	if (!lisp->link)
		return 0;

	return l3mdev_master_upper_ifindex_by_index(lisp->net, lisp->link);
}

static int lisp_open(struct net_device *dev)
{
	struct lisp_dev *lisp = netdev_priv(dev);
	struct lisp_sock *ls, *found = NULL;
	struct lisp_net *ln;
	int ifindex;
	int err = 0;

	ifindex = lisp_l3mdev(lisp);

	ln = net_generic(lisp->net, lisp_net_id);
	mutex_lock(&ln->lock);

	list_for_each_entry(ls, &ln->sock_list, list) {
		if (ls->sk4->sk_bound_dev_if == ifindex) {
			found = ls;
			break;
		}
	}

	if (found) {
		if (lisp_sock_busy(found, lisp)) {
			err = -EBUSY;
			goto unlock;
		}
		found->refcnt++;
	} else {
		found = lisp_sock_create(lisp->net, ifindex);
		if (IS_ERR(found)) {
			err = PTR_ERR(found);
			goto unlock;
		}
		list_add(&found->list, &ln->sock_list);
	}

	rcu_assign_pointer(lisp->sock, found);
	if (lisp->collect_md)
		rcu_assign_pointer(found->md_dev, lisp);
	else
		hlist_add_head_rcu(&lisp->hlist,
				   lisp_iid_head(found, lisp->iid));

unlock:
	mutex_unlock(&ln->lock);
	return err;
}

static int lisp_stop(struct net_device *dev)
{
	struct lisp_dev *lisp = netdev_priv(dev);
	struct lisp_sock *ls;
	struct lisp_net *ln;

	ln = net_generic(lisp->net, lisp_net_id);
	mutex_lock(&ln->lock);

	ls = rcu_dereference_protected(lisp->sock, lockdep_is_held(&ln->lock));
	RCU_INIT_POINTER(lisp->sock, NULL);
	if (lisp->collect_md)
		RCU_INIT_POINTER(ls->md_dev, NULL);
	else
		hlist_del_rcu(&lisp->hlist);

	if (--ls->refcnt) {
		mutex_unlock(&ln->lock);
		return 0;
	}

	list_del(&ls->list);
	mutex_unlock(&ln->lock);

	lisp_sock_release(ls);

	return 0;
}

/* RFC 9300, section 7.2: the sender of a packet that does not fit the path to
 * the RLOC is told what fits, whatever its DF bit. It cannot be told less
 * than the minimum MTU of its protocol: what is not larger is then sent in
 * an outer packet that may be fragmented.
 */
static int lisp_check_pmtu(struct sk_buff *skb, const struct dst_entry *dst,
			   unsigned int hlen, bool *frag)
{
	int min_mtu = skb->protocol == htons(ETH_P_IPV6) ? IPV6_MIN_MTU :
							   IPV4_MIN_MTU;
	int room = dst_mtu(dst) - hlen;
	u32 mtu = max(room, min_mtu);

	*frag = room < min_mtu;

	if (skb_is_gso(skb) ? skb_gso_validate_network_len(skb, mtu) :
			      skb->len <= mtu)
		return 0;

	skb_dst_update_pmtu_no_confirm(skb, mtu);

	if (skb->protocol == htons(ETH_P_IP))
		icmp_ndo_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			      htonl(mtu));
	else
		icmpv6_ndo_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu);

	return -EMSGSIZE;
}

/* RFC 9300, section 5.3: the outer header gets the DSCP and the TTL of the
 * inner header, unless the tunnel metadata sets them.
 */
static u8 lisp_encap_dsfield(const struct sk_buff *skb,
			     const struct ip_tunnel_key *key)
{
	return key->tos ? : ip_tunnel_get_dsfield(ip_hdr(skb), skb);
}

static void lisp_encap_fields(const struct sk_buff *skb,
			      const struct ip_tunnel_key *key, u8 dsfield,
			      u8 *tos, u8 *ttl)
{
	const struct iphdr *iph = ip_hdr(skb);

	*tos = ip_tunnel_ecn_encap(dsfield, iph, skb);
	*ttl = key->ttl ? : ip_tunnel_get_ttl(iph, skb);
}

/* The route to the RLOC is the one of the DSCP of the outer header. The one
 * that the encapsulation caches was looked up with its own DSCP.
 */
static struct dst_cache *lisp_dst_cache(const struct sk_buff *skb,
					const struct ip_tunnel_info *info,
					u8 dsfield)
{
	if (((dsfield ^ info->key.tos) & ~INET_ECN_MASK) ||
	    !ip_tunnel_dst_cache_usable(skb, info))
		return NULL;

	return (struct dst_cache *)&info->dst_cache;
}

static int lisp_build_skb(struct sk_buff *skb, const struct dst_entry *dst,
			  unsigned int hlen, u32 iid, bool udp_sum)
{
	struct lisphdr *lh;
	int err;

	err = skb_cow_head(skb, LL_RESERVED_SPACE(dst_dev(dst)) +
			   dst->header_len + hlen);
	if (unlikely(err))
		return err;

	err = udp_tunnel_handle_offloads(skb, udp_sum);
	if (err)
		return err;

	lh = __skb_push(skb, sizeof(*lh));
	memset(lh, 0, sizeof(*lh));
	if (iid) {
		lh->flags = LISP_F_I;
		lh->iid_lsb = cpu_to_be32(iid << LISP_IID_SHIFT);
	}
	skb_set_inner_protocol(skb, skb->protocol);

	return 0;
}

static int lisp_xmit_skb(struct sk_buff *skb, struct net_device *dev,
			 struct sock *sk, const struct ip_tunnel_info *info,
			 u32 iid)
{
	bool udp_sum = test_bit(IP_TUNNEL_CSUM_BIT, info->key.tun_flags);
	const struct lisp_dev *lisp = netdev_priv(dev);
	bool xnet = !net_eq(lisp->net, dev_net(dev));
	const struct ip_tunnel_key *key = &info->key;
	u8 dsfield = lisp_encap_dsfield(skb, key);
	struct ip_tunnel_key local_key;
	struct rtable *rt;
	__be16 sport;
	__be32 saddr;
	u8 tos, ttl;
	bool frag;
	int err;

	if (!key->u.ipv4.src && lisp->local) {
		local_key = *key;
		local_key.u.ipv4.src = lisp->local;
		key = &local_key;
	}

	sport = udp_flow_src_port(lisp->net, skb, 0, 0, false);
	rt = udp_tunnel_dst_lookup(skb, dev, lisp->net, lisp->link, &saddr,
				   key, sport, htons(LISP_UDP_PORT), dsfield,
				   lisp_dst_cache(skb, info, dsfield));
	if (IS_ERR(rt))
		return PTR_ERR(rt);

	err = lisp_check_pmtu(skb, &rt->dst, LISP_IPV4_HLEN, &frag);
	if (err)
		goto free_dst;

	lisp_encap_fields(skb, key, dsfield, &tos, &ttl);
	skb_scrub_packet(skb, xnet);

	err = lisp_build_skb(skb, &rt->dst, LISP_IPV4_HLEN, iid, udp_sum);
	if (err)
		goto free_dst;

	udp_tunnel_xmit_skb(rt, sk, skb, saddr, key->u.ipv4.dst, tos, ttl,
			    frag ? 0 : htons(IP_DF), sport,
			    htons(LISP_UDP_PORT), xnet, !udp_sum, 0);
	return 0;

free_dst:
	dst_release(&rt->dst);
	return err;
}

static int lisp6_xmit_skb(struct sk_buff *skb, struct net_device *dev,
			  struct sock *sk, const struct ip_tunnel_info *info,
			  u32 iid)
{
	bool udp_sum = test_bit(IP_TUNNEL_CSUM_BIT, info->key.tun_flags);
	const struct lisp_dev *lisp = netdev_priv(dev);
	bool xnet = !net_eq(lisp->net, dev_net(dev));
	const struct ip_tunnel_key *key = &info->key;
	u8 dsfield = lisp_encap_dsfield(skb, key);
	struct ip_tunnel_key local_key;
	struct dst_entry *dst;
	struct in6_addr saddr;
	__be16 sport;
	u8 tos, ttl;
	bool frag;
	int err;

	if (ipv6_addr_any(&key->u.ipv6.src) && !ipv6_addr_any(&lisp->local6)) {
		local_key = *key;
		local_key.u.ipv6.src = lisp->local6;
		key = &local_key;
	}

	sport = udp_flow_src_port(lisp->net, skb, 0, 0, false);
	dst = udp_tunnel6_dst_lookup(skb, dev, lisp->net, sk, lisp->link,
				     &saddr, key, sport, htons(LISP_UDP_PORT),
				     dsfield,
				     lisp_dst_cache(skb, info, dsfield));
	if (IS_ERR(dst))
		return PTR_ERR(dst);

	err = lisp_check_pmtu(skb, dst, LISP_IPV6_HLEN, &frag);
	if (err)
		goto free_dst;

	lisp_encap_fields(skb, key, dsfield, &tos, &ttl);
	skb_scrub_packet(skb, xnet);

	err = lisp_build_skb(skb, dst, LISP_IPV6_HLEN, iid, udp_sum);
	if (err)
		goto free_dst;

	skb->ignore_df = frag;
	udp_tunnel6_xmit_skb(dst, sk, skb, dev, &saddr, &key->u.ipv6.dst, tos,
			     ttl, key->label, sport, htons(LISP_UDP_PORT),
			     !udp_sum, 0);
	return 0;

free_dst:
	dst_release(dst);
	return err;
}

static netdev_tx_t lisp_xmit(struct sk_buff *skb, struct net_device *dev)
{
	const struct ip_tunnel_info *info = skb_tunnel_info(skb);
	const struct lisp_dev *lisp = netdev_priv(dev);
	const struct lisp_sock *ls;
	u32 iid = lisp->iid;
	int err = -EINVAL;

	if (skb->protocol != htons(ETH_P_IP) &&
	    (skb->protocol != htons(ETH_P_IPV6) || !ipv6_mod_enabled()))
		goto tx_error;

	if (!pskb_inet_may_pull(skb))
		goto tx_error;

	if (unlikely(!info || !(info->mode & IP_TUNNEL_INFO_TX)))
		goto tx_error;

	if (lisp->collect_md) {
		u64 tun_id = be64_to_cpu(info->key.tun_id);

		if (tun_id > LISP_IID_MAX)
			goto tx_error;
		iid = tun_id;
	}

	rcu_read_lock();
	ls = rcu_dereference(lisp->sock);
	if (!ls)
		err = -ESHUTDOWN;
	else if (ip_tunnel_info_af(info) == AF_INET)
		err = lisp_xmit_skb(skb, dev, ls->sk4, info, iid);
	else if (ls->sk6)
		err = lisp6_xmit_skb(skb, dev, ls->sk6, info, iid);
	else
		err = -EAFNOSUPPORT;
	rcu_read_unlock();

	if (likely(!err))
		return NETDEV_TX_OK;

tx_error:
	dev_kfree_skb(skb);

	if (err == -ELOOP)
		DEV_STATS_INC(dev, collisions);
	else if (err == -ENETUNREACH)
		DEV_STATS_INC(dev, tx_carrier_errors);

	DEV_STATS_INC(dev, tx_errors);
	return NETDEV_TX_OK;
}

static int lisp_init(struct net_device *dev)
{
	struct lisp_dev *lisp = netdev_priv(dev);
	int err;

	err = gro_cells_init(&lisp->gro_cells, dev);
	if (err)
		return err;

	netdev_lockdep_set_classes(dev);
	return 0;
}

static void lisp_uninit(struct net_device *dev)
{
	struct lisp_dev *lisp = netdev_priv(dev);

	gro_cells_destroy(&lisp->gro_cells);
}

static int lisp_get_iflink(const struct net_device *dev)
{
	const struct lisp_dev *lisp = netdev_priv(dev);

	return lisp->link ? : READ_ONCE(dev->ifindex);
}

static const struct net_device_ops lisp_netdev_ops = {
	.ndo_init		= lisp_init,
	.ndo_uninit		= lisp_uninit,
	.ndo_open		= lisp_open,
	.ndo_stop		= lisp_stop,
	.ndo_start_xmit		= lisp_xmit,
	.ndo_get_iflink		= lisp_get_iflink,
};

static const struct device_type lisp_type = {
	.name = "lisp",
};

static void lisp_setup(struct net_device *dev)
{
	dev->netdev_ops = &lisp_netdev_ops;
	dev->needs_free_netdev = true;
	SET_NETDEV_DEVTYPE(dev, &lisp_type);

	dev->features |= NETIF_F_SG | NETIF_F_HW_CSUM | NETIF_F_FRAGLIST;
	dev->features |= NETIF_F_RXCSUM;
	dev->features |= NETIF_F_GSO_SOFTWARE;
	dev->hw_features |= NETIF_F_SG | NETIF_F_HW_CSUM | NETIF_F_FRAGLIST;
	dev->hw_features |= NETIF_F_RXCSUM;
	dev->hw_features |= NETIF_F_GSO_SOFTWARE;

	dev->type = ARPHRD_NONE;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->needed_headroom = LL_MAX_HEADER + LISP_IPV6_HLEN;
	dev->mtu = ETH_DATA_LEN - LISP_IPV6_HLEN;
	dev->min_mtu = IPV4_MIN_MTU;
	dev->max_mtu = IP_MAX_MTU - LISP_IPV4_HLEN;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP;
	dev->priv_flags |= IFF_NO_QUEUE;
	dev->lltx = true;
	dev->pcpu_stat_type = NETDEV_PCPU_STAT_DSTATS;

	netif_keep_dst(dev);
	netif_set_tso_max_size(dev, GSO_MAX_SIZE);
}

static const struct netlink_range_validation lisp_iid_range = {
	.max = LISP_IID_MAX,
};

static const struct nla_policy lisp_policy[IFLA_LISP_MAX + 1] = {
	[IFLA_LISP_UNSPEC]		= { .strict_start_type = IFLA_LISP_ID },
	[IFLA_LISP_ID]			= NLA_POLICY_FULL_RANGE(NLA_U32,
								&lisp_iid_range),
	[IFLA_LISP_COLLECT_METADATA]	= { .type = NLA_FLAG },
	[IFLA_LISP_LOCAL]		= { .type = NLA_BE32 },
	[IFLA_LISP_LOCAL6]		=
		NLA_POLICY_EXACT_LEN(sizeof(struct in6_addr)),
};

static int lisp_validate(struct nlattr *tb[], struct nlattr *data[],
			 struct netlink_ext_ack *extack)
{
	if (!data)
		return 0;

	if (data[IFLA_LISP_LOCAL]) {
		__be32 addr = nla_get_in_addr(data[IFLA_LISP_LOCAL]);

		if (ipv4_is_zeronet(addr) || ipv4_is_multicast(addr) ||
		    ipv4_is_lbcast(addr)) {
			NL_SET_ERR_MSG_ATTR(extack, data[IFLA_LISP_LOCAL],
					    "The local RLOC is not a unicast address");
			return -EINVAL;
		}
	}

	if (data[IFLA_LISP_LOCAL6]) {
		struct in6_addr addr = nla_get_in6_addr(data[IFLA_LISP_LOCAL6]);

		if (ipv6_addr_type(&addr) != IPV6_ADDR_UNICAST) {
			NL_SET_ERR_MSG_ATTR(extack, data[IFLA_LISP_LOCAL6],
					    "The local RLOC is not a global unicast address");
			return -EINVAL;
		}
	}

	return 0;
}

static int lisp_newlink(struct net_device *dev,
			struct rtnl_newlink_params *params,
			struct netlink_ext_ack *extack)
{
	struct net *link_net = rtnl_newlink_link_net(params);
	struct lisp_net *ln = net_generic(link_net, lisp_net_id);
	struct lisp_dev *lisp = netdev_priv(dev);
	struct nlattr **data = params->data;
	struct nlattr **tb = params->tb;
	const struct lisp_dev *tmp;
	int ifindex;
	int err;

	if (!data ||
	    !data[IFLA_LISP_ID] == !data[IFLA_LISP_COLLECT_METADATA]) {
		NL_SET_ERR_MSG(extack,
			       "Either an instance ID or the collection of metadata is required");
		return -EINVAL;
	}

	lisp->net = link_net;
	lisp->dev = dev;
	INIT_LIST_HEAD(&lisp->next);

	lisp->collect_md = nla_get_flag(data[IFLA_LISP_COLLECT_METADATA]);
	lisp->iid = nla_get_u32_default(data[IFLA_LISP_ID], 0);
	lisp->local = nla_get_in_addr_default(data[IFLA_LISP_LOCAL], 0);
	if (data[IFLA_LISP_LOCAL6])
		lisp->local6 = nla_get_in6_addr(data[IFLA_LISP_LOCAL6]);

	if (tb[IFLA_LINK]) {
		lisp->link = nla_get_u32(tb[IFLA_LINK]);
		if (!__dev_get_by_index(link_net, lisp->link)) {
			NL_SET_BAD_ATTR(extack, tb[IFLA_LINK]);
			return -ENODEV;
		}
	}

	ifindex = lisp_l3mdev(lisp);
	mutex_lock(&ln->lock);
	list_for_each_entry(tmp, &ln->dev_list, next) {
		if (lisp_l3mdev(tmp) != ifindex ||
		    tmp->collect_md != lisp->collect_md)
			continue;

		if (lisp->collect_md) {
			mutex_unlock(&ln->lock);
			NL_SET_ERR_MSG(extack,
				       "A LISP device already collects the metadata of these RLOCs");
			return -EEXIST;
		}
		if (tmp->iid == lisp->iid) {
			mutex_unlock(&ln->lock);
			NL_SET_ERR_MSG(extack,
				       "A LISP device already has this instance ID for these RLOCs");
			return -EEXIST;
		}
	}
	mutex_unlock(&ln->lock);

	err = register_netdevice(dev);
	if (err)
		return err;

	mutex_lock(&ln->lock);
	list_add(&lisp->next, &ln->dev_list);
	mutex_unlock(&ln->lock);

	return 0;
}

static void lisp_dellink(struct net_device *dev, struct list_head *head)
{
	struct lisp_dev *lisp = netdev_priv(dev);
	struct lisp_net *ln = net_generic(lisp->net, lisp_net_id);

	mutex_lock(&ln->lock);
	if (!list_empty(&lisp->next)) {
		list_del_init(&lisp->next);
		unregister_netdevice_queue_net(dev_net(dev), dev, head);
	}
	mutex_unlock(&ln->lock);
}

static size_t lisp_get_size(const struct net_device *dev)
{
	return nla_total_size(sizeof(u32)) +		/* IFLA_LISP_ID */
	       nla_total_size(0) +	/* IFLA_LISP_COLLECT_METADATA */
	       nla_total_size(sizeof(struct in_addr)) +	/* IFLA_LISP_LOCAL */
	       nla_total_size(sizeof(struct in6_addr));	/* IFLA_LISP_LOCAL6 */
}

static int lisp_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	const struct lisp_dev *lisp = netdev_priv(dev);

	if (lisp->collect_md) {
		if (nla_put_flag(skb, IFLA_LISP_COLLECT_METADATA))
			return -EMSGSIZE;
	} else if (nla_put_u32(skb, IFLA_LISP_ID, lisp->iid)) {
		return -EMSGSIZE;
	}

	if (lisp->local &&
	    nla_put_in_addr(skb, IFLA_LISP_LOCAL, lisp->local))
		return -EMSGSIZE;

	if (!ipv6_addr_any(&lisp->local6) &&
	    nla_put_in6_addr(skb, IFLA_LISP_LOCAL6, &lisp->local6))
		return -EMSGSIZE;

	return 0;
}

static struct net *lisp_get_link_net(const struct net_device *dev)
{
	const struct lisp_dev *lisp = netdev_priv(dev);

	return lisp->net;
}

static struct rtnl_link_ops lisp_link_ops __read_mostly = {
	.kind		= "lisp",
	.maxtype	= IFLA_LISP_MAX,
	.policy		= lisp_policy,
	.priv_size	= sizeof(struct lisp_dev),
	.setup		= lisp_setup,
	.validate	= lisp_validate,
	.newlink	= lisp_newlink,
	.dellink	= lisp_dellink,
	.get_size	= lisp_get_size,
	.fill_info	= lisp_fill_info,
	.get_link_net	= lisp_get_link_net,
};

static __net_init int lisp_init_net(struct net *net)
{
	struct lisp_net *ln = net_generic(net, lisp_net_id);

	INIT_LIST_HEAD(&ln->dev_list);
	INIT_LIST_HEAD(&ln->sock_list);
	mutex_init(&ln->lock);

	return 0;
}

static void __net_exit lisp_exit_rtnl_net(struct net *net,
					  struct list_head *dev_kill_list)
{
	struct lisp_net *ln = net_generic(net, lisp_net_id);
	struct lisp_dev *lisp, *next;

	mutex_lock(&ln->lock);
	list_for_each_entry_safe(lisp, next, &ln->dev_list, next) {
		list_del_init(&lisp->next);
		unregister_netdevice_queue_net(net, lisp->dev, dev_kill_list);
	}
	mutex_unlock(&ln->lock);
}

static void __net_exit lisp_exit_net(struct net *net)
{
	struct lisp_net *ln = net_generic(net, lisp_net_id);

	WARN_ON_ONCE(!list_empty(&ln->dev_list));
	WARN_ON_ONCE(!list_empty(&ln->sock_list));
}

static int lisp_netdevice_event(struct notifier_block *nb, unsigned long event,
				void *ptr)
{
	struct net_device *link = netdev_notifier_info_to_dev(ptr);
	struct net *net = dev_net(link);
	struct lisp_dev *lisp, *next;
	struct lisp_net *ln;
	LIST_HEAD(kill);

	if (event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;

	ln = net_generic(net, lisp_net_id);
	mutex_lock(&ln->lock);
	list_for_each_entry_safe(lisp, next, &ln->dev_list, next) {
		if (lisp->link != link->ifindex)
			continue;

		list_del_init(&lisp->next);
		unregister_netdevice_queue_net(net, lisp->dev, &kill);
	}
	mutex_unlock(&ln->lock);

	unregister_netdevice_many(&kill);

	return NOTIFY_DONE;
}

static struct notifier_block lisp_notifier_block __read_mostly = {
	.notifier_call = lisp_netdevice_event,
};

static struct pernet_operations lisp_net_ops = {
	.init		= lisp_init_net,
	.exit_rtnl	= lisp_exit_rtnl_net,
	.exit		= lisp_exit_net,
	.id		= &lisp_net_id,
	.size		= sizeof(struct lisp_net),
};

static int __init lisp_init_module(void)
{
	int err;

	err = register_pernet_subsys(&lisp_net_ops);
	if (err)
		return err;

	err = register_netdevice_notifier(&lisp_notifier_block);
	if (err)
		goto unregister_pernet;

	err = rtnl_link_register(&lisp_link_ops);
	if (err)
		goto unregister_notifier;

	return 0;

unregister_notifier:
	unregister_netdevice_notifier(&lisp_notifier_block);
unregister_pernet:
	unregister_pernet_subsys(&lisp_net_ops);
	return err;
}
late_initcall(lisp_init_module);

static void __exit lisp_cleanup_module(void)
{
	rtnl_link_unregister(&lisp_link_ops);
	unregister_netdevice_notifier(&lisp_notifier_block);
	unregister_pernet_subsys(&lisp_net_ops);
}
module_exit(lisp_cleanup_module);

MODULE_ALIAS_RTNL_LINK("lisp");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincent Jardin <vjardin@free.fr>");
MODULE_DESCRIPTION("Data plane of the Locator/ID Separation Protocol (LISP)");
