// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("tc")
__attribute__((btf_decl_tag("tx_extra_headroom:512")))
__success
int tag_max(struct __sk_buff *skb)
{
	return 0;
}

SEC("tc")
__attribute__((btf_decl_tag("tx_extra_headroom:513")))
__failure __msg("invalid tx_extra_headroom tag '513'")
int tag_above_max(struct __sk_buff *skb)
{
	return 0;
}

SEC("tc")
__attribute__((btf_decl_tag("tx_extra_headroom:+20")))
__failure __msg("invalid tx_extra_headroom tag '+20'")
int tag_plus_sign(struct __sk_buff *skb)
{
	return 0;
}

SEC("tc")
__attribute__((btf_decl_tag("tx_extra_headroom:20")))
__attribute__((btf_decl_tag("tx_extra_headroom:30")))
__failure __msg("multiple tx_extra_headroom tags for main subprog")
int tag_twice(struct __sk_buff *skb)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
