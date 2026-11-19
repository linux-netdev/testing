// SPDX-License-Identifier: GPL-2.0
/* Record the headroom fields of a test packet and push headers onto it. */
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
#define PUSH_LEN 20
#define PUSH_MARK 0x1d

struct net_device {
	unsigned short needed_headroom;
	unsigned short tx_extra_headroom;
} __attribute__((preserve_access_index));

struct sk_buff {
	struct net_device *dev;
	unsigned char *head;
	unsigned char *data;
	__u8 pp_recycle:1;
} __attribute__((preserve_access_index));

void *bpf_cast_to_kern_ctx(void *obj) __ksym;

__u32 count;
__u32 needed_headroom;
__u32 tx_extra_headroom;
bool pp_recycle;
__u32 pushes;
__u32 headroom;
bool reallocated;

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

static int push(struct __sk_buff *skb, int len)
{
	struct sk_buff *kskb;
	unsigned char *head;

	if (skb->mark != PUSH_MARK && !is_test_packet(skb))
		return TCX_NEXT;

	kskb = bpf_cast_to_kern_ctx(skb);
	headroom = kskb->data - kskb->head;

	/* pskb_expand_head() always allocates a new skb->head. */
	head = kskb->head;
	if (!bpf_skb_adjust_room(skb, len, BPF_ADJ_ROOM_MAC, 0))
		pushes++;
	if (kskb->head != head)
		reallocated = true;

	/* The next program cannot parse the packet after the push. */
	skb->mark = PUSH_MARK;
	return TCX_NEXT;
}

SEC("tcx/egress")
int push_untagged(struct __sk_buff *skb)
{
	return push(skb, PUSH_LEN);
}

SEC("tcx/egress")
__attribute__((btf_decl_tag("tx_extra_headroom:20")))
int push_tagged(struct __sk_buff *skb)
{
	return push(skb, PUSH_LEN);
}

SEC("tcx/egress")
__attribute__((btf_decl_tag("tx_extra_headroom:30")))
int push_tagged_30(struct __sk_buff *skb)
{
	return push(skb, 30);
}

SEC("tcx/egress")
__attribute__((btf_decl_tag("tx_extra_headroom:512")))
int tag_max(struct __sk_buff *skb)
{
	return TCX_NEXT;
}

char _license[] SEC("license") = "GPL";
