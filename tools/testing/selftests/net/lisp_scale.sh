#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2026 Vincent Jardin <vjardin@free.fr>, Free Mobile
#
# Scale of the LISP data plane of drivers/net/lisp.c: the mappings of many
# remote sites on one device of an xTR. A site is an RLOC, which is a nexthop,
# and EID prefixes, which are routes to it. The sites with an even number have
# an IPv4 RLOC, the others an IPv6 one. Each site has two IPv4 and two IPv6 EID
# prefixes.
#
# x2 stands for all the remote sites: their RLOCs and their EIDs are local to
# it, and it answers to the EIDs of x1.
#
#   x1 (VRF "site")                                    x2
#   172.16.0.1, fd01::1    lisp101 ...... lisp101      10.0.0.0/8, fd00::/16
#   192.0.2.1, 2001:db8:1::1  veth        veth         198.18.0.0/15,
#                                                      2001:db8:ffff::/48
#
# LISP_SITES is the number of sites: 40000 by default, 8000 on a slow machine,
# which is also the least: the tests change sites of their own, below 8000.

source lib.sh

if [[ $KSFT_MACHINE_SLOW == yes ]]; then
	: "${LISP_SITES:=8000}"
else
	: "${LISP_SITES:=40000}"
fi

ALL_TESTS="
	install_test
	stats_test
	move_test
	replace_test
	withdraw_test
	churn_test
	down_test
"

X1_RLOC4=192.0.2.1
X1_RLOC6=2001:db8:1::1

# The nexthop of a site has its number plus 1 as ID. Those of the sites that
# move are above the others, and the groups above them.
NH_MOVED=1000000
NH_GROUP=2000000

################################################################################
# Helpers

site_addr()
{
	local site=$1; shift
	local format=$1; shift

	awk -v i="$site" "BEGIN { printf \"$format\", $* }"
}

site_rloc()
{
	local site=$1; shift

	if (( site % 2 )); then
		site_addr "$site" "2001:db8:ffff:%x::1" i
	else
		site_addr "$site" "198.18.%d.%d" "int(i / 256), i % 256"
	fi
}

# The IPv4 RLOC that a site gets when a test moves it.
site_moved_rloc()
{
	site_addr "$1" "198.19.%d.%d" "int(i / 256), i % 256"
}

site_eid4()
{
	site_addr "$1" "10.%d.%d.129" "int(i / 256), i % 256"
}

site_eid6()
{
	site_addr "$1" "fd00:%x:1::1" i
}

sites_batch()
{
	local family=$1; shift
	local first=$1; shift
	local last=$1; shift
	local program=$1; shift

	awk -v first="$first" -v last="$last" -v moved="$NH_MOVED" \
	    -v group="$NH_GROUP" "
	BEGIN {
		for (i = first; i < last; i++) {
			nh = i + 1
			hi = int(i / 256)
			lo = i % 256
			if (i % 2) {
				encap = \"ip6\"
				rloc = sprintf(\"2001:db8:ffff:%x::1\", i)
			} else {
				encap = \"ip\"
				rloc = sprintf(\"198.18.%d.%d\", hi, lo)
			}
			$program
		}
	}" | ip -n "$x1" ${family:+-$family} -batch -
}

SITE_ROUTES='
	printf "route %s 10.%d.%d.0/25 vrf site nhid %d\n", cmd, hi, lo, to
	printf "route %s 10.%d.%d.128/25 vrf site nhid %d\n", cmd, hi, lo, to
	printf "route %s fd00:%x:0::/64 vrf site nhid %d\n", cmd, i, to
	printf "route %s fd00:%x:1::/64 vrf site nhid %d\n", cmd, i, to
'

sites_add()
{
	local first=$1; shift
	local last=$1; shift

	sites_batch 6 "$first" "$last" '
		printf "nexthop add id %d encap %s dst %s dev lisp101\n", \
			nh, encap, rloc
	' && sites_batch "" "$first" "$last" \
		"cmd = \"add\"; to = nh; $SITE_ROUTES"
}

count_nexthops()
{
	ip -n "$x1" nexthop show dev lisp101 | wc -l
}

count_routes()
{
	local family=$1; shift

	ip -n "$x1" "-$family" route show vrf site | grep -c " nhid "
}

site_ping()
{
	local site=$1; shift

	ip netns exec "$x1" ping -q -c 1 -W 2 -I site "$(site_eid4 "$site")" \
		> /dev/null 2>&1 &&
	ip netns exec "$x1" ping -q -c 1 -W 2 -I site "$(site_eid6 "$site")" \
		> /dev/null 2>&1
}

rloc_filter()
{
	local rloc=$1; shift
	local protocol=ip

	[[ $rloc == *:* ]] && protocol=ipv6
	tc -n "$x2" filter add dev eth0 ingress protocol $protocol pref 1 \
		flower dst_ip "$rloc" action pass
}

rloc_packets()
{
	tc -n "$x2" -j -s filter show dev eth0 ingress pref 1 |
		jq '[.[] | select(.options.actions) |
		     .options.actions[0].stats.packets] | add'
	tc -n "$x2" filter del dev eth0 ingress pref 1
}

site_check()
{
	local site=$1; shift
	local rloc=$1; shift

	rloc_filter "$rloc"
	site_ping "$site"
	check_err $? "no answer from the site $site"
	(( $(rloc_packets) == 2 ))
	check_err $? "the site $site is not reached through $rloc"
}

elapsed()
{
	local start=$1; shift

	echo "$(( $(timestamp_ms) - start )) ms"
}

################################################################################
# Setup

setup()
{
	local ns

	setup_ns x1 x2 || return

	ip link add eth0 netns "$x1" type veth peer name eth0 netns "$x2"
	for ns in "$x1" "$x2"; do
		ip netns exec "$ns" sysctl -wq net.ipv4.ip_forward=1
		ip netns exec "$ns" sysctl -wq net.ipv6.conf.all.forwarding=1
		ip -n "$ns" link set eth0 up
	done

	ip -n "$x1" addr add $X1_RLOC4/30 dev eth0
	ip -n "$x1" addr add $X1_RLOC6/64 dev eth0 nodad
	ip -n "$x1" route add 198.18.0.0/15 via 192.0.2.2
	ip -n "$x1" -6 route add 2001:db8:ffff::/48 via 2001:db8:1::2
	ip -n "$x1" link add site type vrf table 10
	ip -n "$x1" link set site up
	ip -n "$x1" link add lisp101 type lisp id 101 \
		local $X1_RLOC4 local $X1_RLOC6 || return
	ip -n "$x1" link set lisp101 master site up
	ip -n "$x1" addr add 172.16.0.1/32 dev lisp101
	ip -n "$x1" addr add fd01::1/128 dev lisp101 nodad

	ip -n "$x2" addr add 192.0.2.2/30 dev eth0
	ip -n "$x2" addr add 2001:db8:1::2/64 dev eth0 nodad
	ip -n "$x2" route add local 198.18.0.0/15 dev lo
	ip -n "$x2" -6 route add local 2001:db8:ffff::/48 dev lo
	ip -n "$x2" route add local 10.0.0.0/8 dev lo
	ip -n "$x2" -6 route add local fd00::/16 dev lo
	ip -n "$x2" link add lisp101 type lisp id 101
	ip -n "$x2" link set lisp101 up
	ip -n "$x2" route add 172.16.0.1/32 encap ip dst $X1_RLOC4 dev lisp101
	ip -n "$x2" -6 route add fd01::1/128 encap ip6 dst $X1_RLOC6 \
		dev lisp101
	tc -n "$x2" qdisc add dev eth0 clsact
}

cleanup()
{
	cleanup_all_ns
}

################################################################################
# Tests

install_test()
{
	local start
	local site

	RET=0

	start=$(timestamp_ms)
	sites_add 0 "$LISP_SITES"
	check_err $? "the sites are not installed"
	log_info "$LISP_SITES sites installed in $(elapsed "$start")"

	(( $(count_nexthops) == LISP_SITES ))
	check_err $? "unexpected count of nexthops"
	(( $(count_routes 4) == 2 * LISP_SITES ))
	check_err $? "unexpected count of IPv4 routes"
	(( $(count_routes 6) == 2 * LISP_SITES ))
	check_err $? "unexpected count of IPv6 routes"

	for site in 0 1 $((LISP_SITES / 2)) $((LISP_SITES / 2 + 1)) \
		    $((LISP_SITES - 2)) $((LISP_SITES - 1)); do
		site_check "$site" "$(site_rloc "$site")"
	done

	log_test "$LISP_SITES sites: $LISP_SITES nexthops, $((4 * LISP_SITES)) routes"
}

stats_test()
{
	local rx_before
	local tx_before
	local packets
	local i

	RET=0

	ip -n "$x1" nexthop add id $NH_GROUP group 6001/6002
	sites_batch "" 6000 6064 "cmd = \"replace\"; to = group; $SITE_ROUTES"

	tx_before=$(ip -n "$x1" -j -s link show dev lisp101 |
		    jq '.[0].stats64.tx.packets')
	rx_before=$(ip -n "$x1" -j -s link show dev lisp101 |
		    jq '.[0].stats64.rx.packets')
	for i in $(seq 6000 6063); do
		site_ping "$i"
		check_err $? "no answer from the site $i"
	done

	(( $(ip -n "$x1" -j -s link show dev lisp101 |
	     jq '.[0].stats64.tx.packets') == tx_before + 128 ))
	check_err $? "unexpected count of sent packets"
	(( $(ip -n "$x1" -j -s link show dev lisp101 |
	     jq '.[0].stats64.rx.packets') == rx_before + 128 ))
	check_err $? "unexpected count of received packets"

	packets=$(ip -n "$x1" -j -s nexthop show id $NH_GROUP |
		  jq -c '[.[0].group_stats[].packets]')
	(( $(jq 'add' <<< "$packets") >= 128 ))
	check_err $? "unexpected count of the packets of the group: $packets"
	[[ $(jq 'min' <<< "$packets") != 0 ]]
	check_err $? "an RLOC of the group is not used: $packets"

	sites_batch "" 6000 6064 "cmd = \"replace\"; to = nh; $SITE_ROUTES"
	ip -n "$x1" nexthop del id $NH_GROUP
	log_test "Counters of the device and of a group"
}

move_test()
{
	local start

	RET=0

	start=$(timestamp_ms)
	sites_batch 6 1000 2000 '
		printf "nexthop add id %d encap ip dst 198.19.%d.%d dev lisp101\n", \
			moved + i, hi, lo
	' && sites_batch "" 1000 2000 \
		"cmd = \"replace\"; to = moved + i; $SITE_ROUTES" &&
	sites_batch "" 1000 2000 'printf "nexthop del id %d\n", nh'
	check_err $? "the sites are not moved"
	log_info "1000 sites moved to new nexthops in $(elapsed "$start")"

	(( $(count_nexthops) == LISP_SITES ))
	check_err $? "unexpected count of nexthops"
	site_check 1000 "$(site_moved_rloc 1000)"
	site_check 1999 "$(site_moved_rloc 1999)"
	site_check 2000 "$(site_rloc 2000)"

	log_test "RLOC changed with new nexthops"
}

replace_test()
{
	local start

	RET=0

	start=$(timestamp_ms)
	sites_batch 6 2000 2100 '
		printf "nexthop replace id %d encap ip dst 198.19.%d.%d dev lisp101\n", \
			nh, hi, lo
	'
	check_err $? "the nexthops are not replaced"
	log_info "100 nexthops replaced in $(elapsed "$start")"

	site_check 2000 "$(site_moved_rloc 2000)"
	site_check 2099 "$(site_moved_rloc 2099)"
	site_check 2100 "$(site_rloc 2100)"

	log_test "RLOC changed in place"
}

withdraw_test()
{
	local start

	RET=0

	start=$(timestamp_ms)
	sites_batch "" 3000 4000 '
		printf "route del 10.%d.%d.0/25 vrf site\n", hi, lo
		printf "route del 10.%d.%d.128/25 vrf site\n", hi, lo
		printf "route del fd00:%x:0::/64 vrf site\n", i
		printf "route del fd00:%x:1::/64 vrf site\n", i
	' && sites_batch "" 3000 4000 'printf "nexthop del id %d\n", nh'
	check_err $? "the sites are not withdrawn"
	log_info "1000 sites withdrawn in $(elapsed "$start")"

	start=$(timestamp_ms)
	sites_batch "" 4000 4100 'printf "nexthop del id %d\n", nh'
	check_err $? "the nexthops are not removed"
	log_info "100 nexthops removed with their routes in $(elapsed "$start")"

	(( $(count_nexthops) == LISP_SITES - 1100 ))
	check_err $? "unexpected count of nexthops"
	(( $(count_routes 4) == 2 * (LISP_SITES - 1100) ))
	check_err $? "unexpected count of IPv4 routes"
	(( $(count_routes 6) == 2 * (LISP_SITES - 1100) ))
	check_err $? "unexpected count of IPv6 routes"

	site_ping 3500
	check_fail $? "an answer from a site that left"
	site_ping 4050
	check_fail $? "an answer from a site whose nexthop was removed"
	site_check 4100 "$(site_rloc 4100)"

	log_test "Sites withdrawn"
}

churn_test()
{
	local loops=()
	local pids=()
	local rounds=0
	local site
	local out
	local pid

	RET=0

	out=$(mktemp -d)
	for site in 5500 5501; do
		ip netns exec "$x1" ping -q -f -w 10 -I site \
			"$(site_eid4 "$site")" > "$out/$site.4" 2>&1 &
		pids+=($!)
		ip netns exec "$x1" ping -q -f -w 10 -I site \
			"$(site_eid6 "$site")" > "$out/$site.6" 2>&1 &
		pids+=($!)
	done

	for site in 5000 5001; do
		while :; do
			ip netns exec "$x1" ping -q -f -w 1 -I site \
				"$(site_eid4 "$site")"
			ip netns exec "$x1" ping -q -f -w 1 -I site \
				"$(site_eid6 "$site")"
		done > /dev/null 2>&1 &
		loops+=($!)
	done

	while kill -0 "${pids[0]}" 2> /dev/null; do
		sites_batch "" 5000 5200 'printf "nexthop del id %d\n", nh'
		sites_add 5000 5200
		check_err $? "the sites are not installed again"
		sites_batch 6 5000 5016 '
			printf "nexthop replace id %d encap ip dst 198.19.%d.%d dev lisp101\n", \
				nh, hi, lo
		'
		sites_batch 6 5000 5016 '
			printf "nexthop replace id %d encap %s dst %s dev lisp101\n", \
				nh, encap, rloc
		'
		rounds=$((rounds + 1))
	done
	log_info "$rounds rounds of changes under traffic"

	for pid in "${loops[@]}"; do
		kill_process "$pid"
	done
	for pid in "${pids[@]}"; do
		wait "$pid"
		check_err $? "no answer from a site that did not change"
	done
	# The ping that a loop was running goes on for a second without it.
	ip netns pids "$x1" | xargs -r kill 2> /dev/null

	# The changes of the other sites cost them less than half their packets.
	for site in 5500 5501; do
		awk '/packets transmitted/ { n++; if ($4 * 2 < $1) lost = 1 }
		     END { exit lost || n != 2 }' "$out/$site.4" "$out/$site.6"
		check_err $? "most packets of a site that did not change are lost"
	done
	rm -rf "$out"

	(( $(count_nexthops) == LISP_SITES - 1100 ))
	check_err $? "unexpected count of nexthops"
	site_check 5002 "$(site_rloc 5002)"
	site_check 5199 "$(site_rloc 5199)"
	site_check 5500 "$(site_rloc 5500)"

	log_test "Mappings changed under traffic"
}

down_test()
{
	local start
	local pid

	RET=0

	ip netns exec "$x1" ping -q -f -w 4 -I site "$(site_eid4 7500)" \
		> /dev/null 2>&1 &
	pid=$!

	start=$(timestamp_ms)
	ip -n "$x1" link set lisp101 down
	log_info "device down with its nexthops and routes in $(elapsed "$start")"
	(( $(count_nexthops) == 0 ))
	check_err $? "nexthops outlive the device"
	(( $(count_routes 4) == 0 && $(count_routes 6) == 0 ))
	check_err $? "routes outlive the device"

	ip -n "$x1" link set lisp101 up
	ip -n "$x1" addr add fd01::1/128 dev lisp101 nodad
	sites_add 7000 7100
	check_err $? "no site can be installed again"
	site_check 7000 "$(site_rloc 7000)"
	site_check 7099 "$(site_rloc 7099)"

	start=$(timestamp_ms)
	ip -n "$x1" link del lisp101
	log_info "device deleted in $(elapsed "$start")"
	(( $(ip -n "$x1" nexthop | wc -l) == 0 ))
	check_err $? "nexthops outlive the device"
	wait $pid

	log_test "Device down and deleted"
}

################################################################################
# Main

require_command jq

if ! ip link help lisp 2>&1 | grep -q "^Usage: ... lisp"; then
	echo "SKIP: iproute2 does not know the lisp devices"
	exit "$ksft_skip"
fi

if (( LISP_SITES < 8000 || LISP_SITES > 65536 )); then
	echo "SKIP: LISP_SITES must be between 8000 and 65536"
	exit "$ksft_skip"
fi

trap cleanup EXIT

setup_ns probe
out=$(ip -n "$probe" link add lisp0 type lisp id 1 2>&1)
if [[ $out == *"Unknown device type"* ]]; then
	echo "SKIP: the kernel does not have the lisp devices (CONFIG_LISP)"
	exit "$ksft_skip"
fi
cleanup_ns "$probe"

if ! setup; then
	echo "FAIL: the setup of the test failed"
	exit "$ksft_fail"
fi

tests_run

exit "$EXIT_STATUS"
