// SPDX-License-Identifier: GPL-2.0
/* Record the headroom of a test packet and whether a push reallocates it. */
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define UDP_TEST_PORT 9999
#define PUSH_LEN 20

struct sk_buff {
	unsigned char *head;
	unsigned char *data;
} __attribute__((preserve_access_index));

void *bpf_cast_to_kern_ctx(void *obj) __ksym;

__u32 count;
__u32 headroom;
int err;
bool reallocated;

static bool is_test_packet(struct __sk_buff *skb)
{
	struct udphdr udph;
	struct iphdr iph;

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return false;

	if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph)))
		return false;

	if (iph.protocol != IPPROTO_UDP)
		return false;

	if (bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(iph), &udph,
			       sizeof(udph)))
		return false;

	return udph.dest == bpf_htons(UDP_TEST_PORT);
}

SEC("tc/egress")
int push(struct __sk_buff *skb)
{
	struct sk_buff *kskb;
	unsigned char *head;

	if (!is_test_packet(skb))
		return TC_ACT_OK;

	kskb = bpf_cast_to_kern_ctx(skb);
	count++;
	headroom = kskb->data - kskb->head;

	/* pskb_expand_head() always allocates a new skb->head. */
	head = kskb->head;
	err = bpf_skb_adjust_room(skb, PUSH_LEN, BPF_ADJ_ROOM_MAC, 0);
	reallocated = kskb->head != head;

	return TC_ACT_SHOT;
}

char __license[] SEC("license") = "GPL";
