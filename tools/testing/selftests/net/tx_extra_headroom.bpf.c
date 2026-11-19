// SPDX-License-Identifier: GPL-2.0
/* Record the headroom fields of a test packet. */
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define UDP_TEST_PORT 9999

struct net_device {
	unsigned short needed_headroom;
	unsigned short tx_extra_headroom;
} __attribute__((preserve_access_index));

struct sk_buff {
	struct net_device *dev;
	__u8 pp_recycle:1;
} __attribute__((preserve_access_index));

void *bpf_cast_to_kern_ctx(void *obj) __ksym;

__u32 count;
__u32 needed_headroom;
__u32 tx_extra_headroom;
bool pp_recycle;

static bool is_test_packet(struct __sk_buff *skb)
{
	struct ipv6hdr ip6h;
	struct udphdr udph;
	struct iphdr iph;
	__u32 off;

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph)))
			return false;
		if (iph.protocol != IPPROTO_UDP)
			return false;
		off = ETH_HLEN + sizeof(iph);
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip6h, sizeof(ip6h)))
			return false;
		if (ip6h.nexthdr != IPPROTO_UDP)
			return false;
		off = ETH_HLEN + sizeof(ip6h);
	} else {
		return false;
	}

	if (bpf_skb_load_bytes(skb, off, &udph, sizeof(udph)))
		return false;

	return udph.dest == bpf_htons(UDP_TEST_PORT);
}

/* Attached at tcx ingress and at tcx egress. */
SEC("tc")
int record(struct __sk_buff *skb)
{
	struct sk_buff *kskb;

	if (!is_test_packet(skb))
		return TCX_NEXT;

	kskb = bpf_cast_to_kern_ctx(skb);
	needed_headroom = kskb->dev->needed_headroom;
	tx_extra_headroom = kskb->dev->tx_extra_headroom;
	/* For a frags program, generic XDP copies into a page_pool page. */
	pp_recycle = BPF_CORE_READ_BITFIELD(kskb, pp_recycle);
	count++;

	return TCX_NEXT;
}

char _license[] SEC("license") = "GPL";
