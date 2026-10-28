#!/bin/bash
# SPDX-License-Identifier: GPL-2.0+
#
# Verify RFC 9486 C2 for ECMP: with hash policy 0 (the default), the ECMP
# nexthop chosen for a packet carrying IOAM options must be the same as for
# the identical packet without them.
#
# Two scenarios, matching the two places where IOAM changed the hashed
# IPv6 nexthdr:
#
# 1) transit node: alpha inserts an IOAM Hop-by-Hop option (inline mode);
#    beta forwards with a multipath route. Policy 0 hashed the raw
#    nexthdr (NEXTHDR_HOP vs IPPROTO_ICMPV6), so beta could pick a
#    different ECMP sibling than for the same packet without IOAM.
#
# 2) encapsulating node: beta itself encapsulates (ioam6 encap mode,
#    tunnel dst = original dst, tunnel src pinned) over a multipath
#    route. The ioam6 re-lookup hashed NEXTHDR_HOP instead of the
#    transformed packet's real nexthdr (IPPROTO_IPV6). The baseline is
#    the same encapsulation without the IOAM option: a plain ip6ip6
#    tunnel over the same multipath route, with the same outer
#    addresses.
#
# Hash policy 0 hashes addresses, the flow label and the nexthdr (not L4
# ports), so whether both variants land on the same ECMP sibling depends
# on the per-netns hash seed. Each test therefore repeats with several
# seeds and fails on the first divergence: pre-fix kernels fail with
# high probability, fixed kernels always pass.
#
# Topology:
#
#   alpha                   beta                      gamma
#   veth0 2001:db8:1::2 <-> veth0 2001:db8:1::1
#                           veth1 2001:db8:2:1::1 <-> veth0 2001:db8:2:1::2
#                           veth2 2001:db8:2:2::1 <-> veth1 2001:db8:2:2::2
#
# beta's ECMP route: 2001:db8:2:1::2/128
#   nexthop via 2001:db8:2:1::2 dev veth1
#   nexthop via 2001:db8:2:2::2 dev veth2
#
# Scenario 1 sends to 2001:db8:2:1::2 (gamma). Scenario 2 sends to
# 2001:db8:3::2, which beta encapsulates towards 2001:db8:2:1::2. The
# link gamma received the packets on is detected from tc flower
# counters (read via jq) on the ingress of gamma's veth0/veth1. The
# filters match the exact measurement packets: ICMPv6 echo requests
# for scenario 1, and the outer addresses of the ip6ip6 packets for
# scenario 2 (flower classifies outer headers only).

# shellcheck disable=SC2154,SC2329
source lib.sh

readonly PKTS=3
readonly SEEDS="1 2 3 4 5 6 7 8 9 10 11 12"

ip6tnl_loaded=0

cleanup()
{
	cleanup_all_ns

	if [ "$ip6tnl_loaded" != 0 ]; then
		modprobe -r ip6_tunnel &>/dev/null
	fi
}

# Replace the tc measurement filters on gamma's ECMP links. $1 is the
# flower match list, e.g. "ip_proto icmpv6 type 128 src_ip <sender>"
# for plain IPv6 echo requests, or the outer addresses for ip6ip6
# packets (flower classifies the outer header only, see
# FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP in cls_flower).
set_measure_filters()
{
	local match=$1
	local dev

	for dev in veth0 veth1; do
		tc -n "$ns_gamma" qdisc del dev "$dev" clsact &>/dev/null
		tc -n "$ns_gamma" qdisc add dev "$dev" clsact || return 1
		# shellcheck disable=SC2086
		tc -n "$ns_gamma" filter add dev "$dev" ingress pref 1 \
			protocol ipv6 flower skip_hw $match action pass || return 1
	done
}

# Number of packets counted by the measurement filter on gamma's $1.
icmp_packets()
{
	tc -n "$ns_gamma" -s -j filter show dev "$1" ingress |
		jq '[.[] | .options.actions[]?.stats |
		    (.packets // .basic.packets // 0)] | add // 0'
}

# Send PKTS pings from alpha to $1 and report which of gamma's links
# received them: "A" (veth0), "B" (veth1), "TIE" or "LOST:<a>:<b>".
measure_link()
{
	local dst=$1
	local a0 b0 da db

	a0=$(icmp_packets veth0)
	b0=$(icmp_packets veth1)

	ip netns exec "$ns_alpha" \
		ping -6 -q -c "$PKTS" -i 0.2 -W 1 -w 2 "$dst" &>/dev/null || true

	da=$(($(icmp_packets veth0) - a0))
	db=$(($(icmp_packets veth1) - b0))

	if [ $((da + db)) -lt "$PKTS" ]; then
		echo "LOST:$da:$db"
		return
	fi

	if [ "$da" -gt "$db" ]; then
		echo "A"
	elif [ "$db" -gt "$da" ]; then
		echo "B"
	else
		echo "TIE"
	fi
}

set_alpha_plain()
{
	ip -netns "$ns_alpha" -6 route replace 2001:db8:2:1::/64 \
		via 2001:db8:1::1 dev veth0
}

set_alpha_ioam()
{
	ip -netns "$ns_alpha" -6 route replace 2001:db8:2:1::/64 \
		encap ioam6 mode inline trace prealloc \
		type 0x800000 ns 0 size 12 \
		via 2001:db8:1::1 dev veth0
}

set_beta_tnl()
{
	# Recreate the tunnel: ip6_tnl caches the outer dst per CPU for a
	# few seconds, and neither the route change below nor the
	# fib_multipath_hash_seed write resets it. A stale cache would
	# resolve the outer sibling under a previous seed (or on another
	# CPU), making the baseline flip between attempts of one seed.
	ip -netns "$ns_beta" link del ioamcmp &>/dev/null
	ip -netns "$ns_beta" link add name ioamcmp type ip6tnl \
		mode ip6ip6 local 2001:db8:2:1::1 remote 2001:db8:2:1::2
	ip -netns "$ns_beta" link set ioamcmp up
	ip -netns "$ns_beta" -6 route replace 2001:db8:3::2/128 dev ioamcmp
}

set_beta_ioam_encap()
{
	ip -netns "$ns_beta" -6 route replace 2001:db8:3::2/128 \
		encap ioam6 mode encap tunsrc 2001:db8:2:1::1 tundst 2001:db8:2:1::2 \
		trace prealloc type 0x800000 ns 0 size 12 dev veth1
}

# $1: description; $2: function installing the without-IOAM variant;
# $3: function installing the with-IOAM variant; $4: destination.
run_scenario()
{
	local desc=$1
	local plain=$2
	local ioam=$3
	local dst=$4
	local seed pl il

	log_info "$desc"

	for seed in $SEEDS; do
		RET=0
		ip netns exec "$ns_beta" \
			sysctl -wq net.ipv4.fib_multipath_hash_seed="$seed"

		if ! $plain; then
			RET=$ksft_fail
			log_test "$desc (plain route setup failed, seed $seed)"
			continue
		fi
		pl=$(measure_link "$dst")
		if ! $ioam; then
			RET=$ksft_fail
			log_test "$desc (ioam route setup failed, seed $seed)"
			continue
		fi
		il=$(measure_link "$dst")

		case "$pl$il" in
		*LOST*)
			RET=$ksft_fail
			log_test "$desc (lost packets, seed $seed: without=$pl with=$il)"
			continue
			;;
		*TIE*)
			RET=$ksft_fail
			log_test "$desc (no clear link, seed $seed)"
			continue
			;;
		esac

		if [ "$pl" = "$il" ]; then
			log_test "$desc (seed $seed: same link $pl)"
		else
			RET=$ksft_fail
			log_test "$desc (diverged on seed $seed: without IOAM via link $pl, with IOAM via link $il)"
		fi
	done
}

setup_topology()
{
	local dev

	setup_ns ns_alpha ns_beta ns_gamma || return 1

	ip link add veth0 netns "$ns_alpha" type veth \
		peer name veth0 netns "$ns_beta" || return 1
	ip link add veth1 netns "$ns_beta" type veth \
		peer name veth0 netns "$ns_gamma" || return 1
	ip link add veth2 netns "$ns_beta" type veth \
		peer name veth1 netns "$ns_gamma" || return 1

	ip -n "$ns_alpha" addr add 2001:db8:1::2/64 dev veth0 nodad
	ip -n "$ns_beta" addr add 2001:db8:1::1/64 dev veth0 nodad
	ip -n "$ns_beta" addr add 2001:db8:2:1::1/64 dev veth1 nodad
	ip -n "$ns_beta" addr add 2001:db8:2:2::1/64 dev veth2 nodad
	ip -n "$ns_gamma" addr add 2001:db8:2:1::2/64 dev veth0 nodad
	ip -n "$ns_gamma" addr add 2001:db8:2:2::2/64 dev veth1 nodad

	ip -n "$ns_alpha" link set veth0 up
	ip -n "$ns_beta" link set veth0 up
	ip -n "$ns_beta" link set veth1 up
	ip -n "$ns_beta" link set veth2 up
	ip -n "$ns_gamma" link set veth0 up
	ip -n "$ns_gamma" link set veth1 up

	ip netns exec "$ns_alpha" sysctl -wq net.ipv6.auto_flowlabels=0
	ip netns exec "$ns_alpha" \
		sysctl -wq net.ipv6.conf.veth0.accept_ra=0
	ip netns exec "$ns_beta" sysctl -wq net.ipv6.conf.all.forwarding=1
	ip netns exec "$ns_beta" \
		sysctl -wq net.ipv6.fib_multipath_hash_policy=0
	ip netns exec "$ns_gamma" sysctl -wq net.ipv6.conf.veth0.accept_ra=0
	ip netns exec "$ns_gamma" sysctl -wq net.ipv6.conf.veth1.accept_ra=0

	for dev in veth0 veth1 veth2
	do
		ip netns exec "$ns_beta" \
			sysctl -wq net.ipv6.conf.$dev.accept_ra=0
		ip netns exec "$ns_beta" \
			sysctl -wq net.ipv6.conf.$dev.ioam6_enabled=1
	done

	# The ECMP route under test (scenario 1 hashes its selection at
	# beta's input; scenario 2 at the encapsulating re-lookup).
	ip -netns "$ns_beta" -6 route add 2001:db8:2:1::2/128 \
		nexthop via 2001:db8:2:1::2 dev veth1 \
		nexthop via 2001:db8:2:2::2 dev veth2

	ip -netns "$ns_alpha" -6 route add 2001:db8:2:1::/64 \
		via 2001:db8:1::1 dev veth0
	ip -netns "$ns_alpha" -6 route add 2001:db8:3::/64 \
		via 2001:db8:1::1 dev veth0
	ip -netns "$ns_gamma" -6 route add 2001:db8:1::/64 \
		via 2001:db8:2:1::1 dev veth0

	# drop unreachable message when ping 2001:db8:3::2
	tc -n "$ns_alpha" qdisc add dev veth0 clsact
	tc -n "$ns_alpha" filter add dev veth0 ingress pref 1 \
                protocol ipv6 flower skip_hw ip_proto icmpv6 type 1 action drop

}

setup_tunnel()
{
	if ! lsmod 2>/dev/null | grep -q "ip6_tunnel"; then
		modprobe ip6_tunnel &>/dev/null
		lsmod 2>/dev/null | grep -q "ip6_tunnel" || \
			ip a 2>/dev/null | grep -q "ip6tnl0" || return 1
		ip6tnl_loaded=1
	fi

	ip -netns "$ns_beta" link add name ioamcmp type ip6tnl \
		mode ip6ip6 local 2001:db8:2:1::1 remote 2001:db8:2:1::2 \
		2>/dev/null || return 1
	ip -netns "$ns_beta" link set ioamcmp up
}

################################################################################
#                                                                              #
#                                     MAIN                                     #
#                                                                              #
################################################################################

require_command ip
require_command jq
require_command ping
require_command tc

if [ ! -e /proc/sys/net/ipv4/fib_multipath_hash_seed ]; then
	log_test_skip "Kernel without CONFIG_IP_ROUTE_MULTIPATH."
	exit "${EXIT_STATUS}"
fi

setup_topology || { log_test_skip "Setup failed."; exit "${EXIT_STATUS}"; }
trap cleanup EXIT

# Compat check: can this kernel insert an IOAM trace into a route?
if ! ip -netns "$ns_alpha" -6 route replace 2001:db8:2:1::/64 \
	encap ioam6 mode inline trace prealloc type 0x800000 ns 0 size 12 \
	via 2001:db8:1::1 dev veth0 &>/dev/null
then
	log_test_skip "Cannot attach an IOAM trace to a route"
	exit "${EXIT_STATUS}"
fi

log_info "IOAM + ECMP (RFC 9486 C2, hash policy 0)"

# Warm up both ECMP links (first-packet neighbor/RA activity) and check
# basic connectivity before measuring.
set_alpha_plain
measure_link 2001:db8:2:1::2 >/dev/null

# Scenario 1 counts the ICMPv6 echo requests sent by alpha.
if ! set_measure_filters "ip_proto icmpv6 type 128 src_ip 2001:db8:1::2"; then
	log_test_skip "Cannot install tc flower measurement filters"
	exit "${EXIT_STATUS}"
fi
run_scenario \
	"Transit input ECMP with/without IOAM" \
	set_alpha_plain set_alpha_ioam 2001:db8:2:1::2

if setup_tunnel; then
	# Scenario 2 counts the outer ip6ip6 packets: the echo request is
	# not visible to flower (outer headers only), so match the pinned
	# tunnel addresses instead. No need to check return value again as
	# we have done it at scenario 1
	set_measure_filters "src_ip 2001:db8:2:1::1 dst_ip 2001:db8:2:1::2"
	set_beta_tnl
	measure_link 2001:db8:3::2 >/dev/null

	run_scenario \
		"Encapsulating node re-lookup ECMP with/without IOAM" \
		set_beta_tnl set_beta_ioam_encap 2001:db8:3::2
else
	log_test_skip "Encapsulating node re-lookup ECMP with/without IOAM (no ip6_tunnel)"
fi

exit "${EXIT_STATUS}"
