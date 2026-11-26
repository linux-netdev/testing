#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2026 Vincent Jardin <vjardin@free.fr>, Free Mobile
#
# Test the LISP data plane of drivers/net/lisp.c between two xTRs.
#
# The EIDs of x1 are in the VRF "site" and its RLOCs in the VRF "wan". x2 keeps
# everything in its main table. The instance 101 has one LISP device on each
# xTR. The instance 102 has a device on x1, in the VRF "site2", and uses a device
# that collects metadata on x2.
#
#  h1          x1                         core               x2            h2
#  10.1.0.2    10.1.0.1 (site)                               10.2.0.1      10.2.0.2
#  fd00:1::2   fd00:1::1                                     fd00:2::1     fd00:2::2
#        veth       lisp101 (site)                    lisp101      veth
#                   lisp102 (site2)                   lispmd
#                   192.0.2.1 (wan)      192.0.2.2
#                   2001:db8:1::1  veth  2001:db8:1::2
#                                        198.51.100.2        198.51.100.1
#                                        2001:db8:2::2  veth 2001:db8:2::1

source lib.sh

# shellcheck disable=SC2155 # prefer RO variable over return value from cmd
readonly CLI="$(dirname "$(readlink -f "$0")")/../../../net/ynl/pyynl/cli.py"

ALL_TESTS="
	netlink_test
	ping_test
	fields_test
	mtu_test
	pmtu_test
	multipath_test
	instance_test
	receive_test
	rpfilter_test
	updown_test
	tcp_test
	cross_vrf_test
	cross_netns_test
	netns_test
"

LISP_PORT=4341
IID=101

X1_RLOC4=192.0.2.1
X1_RLOC6=2001:db8:1::1
X2_RLOC4=198.51.100.1
X2_RLOC6=2001:db8:2::1

# ID of the nexthop that reaches the other xTR at its RLOC of a family
NH4=14
NH6=16
# IDs of the nexthops that a test makes for itself
NH_FIELDS=24
NH_GROUP=30
NH_INSTANCE=40
NH_OTHER=99

# An RLOC that is not the one of an xTR
OTHER_RLOC4=203.0.113.9

TCP_PORT=5000
TCP_TIMEOUT=60
TCP_FILE=

################################################################################
# Helpers

h1_ping()
{
	ip netns exec "$h1" ping -q -c 1 -W 2 "$@" > /dev/null 2>&1
}

h2_ping()
{
	ip netns exec "$h2" ping -q -c 1 -W 1 "$@" > /dev/null 2>&1
}

tc_packets()
{
	local ns=$1; shift
	local dev=$1; shift
	local pref=$1; shift

	tc -n "$ns" -j -s filter show dev "$dev" ingress pref "$pref" |
		jq '[.[] | select(.options.actions) |
		     .options.actions[0].stats.packets] | add'
}

# On the core, coming from x1.
core_packets()
{
	tc_packets "$core" c1 "$1"
}

h2_packets()
{
	tc_packets "$h2" eth0 "$1"
}

link_stat()
{
	local ns=$1; shift
	local dev=$1; shift
	local stat=$1; shift

	ip -n "$ns" -j -s -s link show dev "$dev" | jq ".[0].stats64$stat"
}

# What the kernel answers to the creation of a device with these attributes,
# which ip refuses to send.
ynl_add()
{
	local data=$1; shift

	ip netns exec "$x2" "$CLI" --family rt-link --create --excl \
		--do newlink --json "{\"ifname\": \"t0\",
			\"linkinfo\": {\"kind\": \"lisp\", \"data\": $data}}" 2>&1
}

# The EID prefixes of the instance 101 use the RLOCs of a family.
use_rlocs()
{
	local family=$1; shift
	local nh=NH$family

	ip -n "$x1" route replace 10.2.0.0/24 vrf site nhid "${!nh}"
	ip -n "$x1" -6 route replace fd00:2::/64 vrf site nhid "${!nh}"
	ip -n "$x2" route replace 10.1.0.0/24 nhid "${!nh}"
	ip -n "$x2" -6 route replace fd00:1::/64 nhid "${!nh}"
}

core_send()
{
	local bytes=$1; shift

	ip netns exec "$core" bash -c \
		"printf '$bytes' > /dev/udp/$X1_RLOC4/$LISP_PORT"
}

################################################################################
# Setup

host_setup()
{
	local ns=$1; shift
	local id=$1; shift

	ip -n "$ns" link set eth0 up
	ip -n "$ns" addr add "10.$id.0.2/24" dev eth0
	ip -n "$ns" addr add "fd00:$id::2/64" dev eth0 nodad
	ip -n "$ns" route add default via "10.$id.0.1"
	ip -n "$ns" -6 route add default via "fd00:$id::1"
	tc -n "$ns" qdisc add dev eth0 clsact
}

setup()
{
	local ns

	setup_ns h1 x1 core x2 h2 || return

	for ns in "$h1" "$x1" "$core" "$x2" "$h2"; do
		ip netns exec "$ns" sysctl -wq net.ipv6.conf.all.accept_dad=0
		ip netns exec "$ns" sysctl -wq net.ipv6.conf.default.accept_dad=0
	done
	ip netns exec "$x2" sysctl -wq net.ipv6.bindv6only=1

	ip link add eth0 netns "$h1" type veth peer name eth0 netns "$x1"
	ip link add eth1 netns "$x1" type veth peer name c1 netns "$core"
	ip link add eth1 netns "$x2" type veth peer name c2 netns "$core"
	ip link add eth0 netns "$h2" type veth peer name eth0 netns "$x2"

	for ns in "$x1" "$core" "$x2"; do
		ip netns exec "$ns" sysctl -wq net.ipv4.ip_forward=1
		ip netns exec "$ns" sysctl -wq net.ipv6.conf.all.forwarding=1
	done

	host_setup "$h1" 1
	host_setup "$h2" 2

	ip -n "$core" link set c1 up
	ip -n "$core" link set c2 up
	ip -n "$core" addr add 192.0.2.2/30 dev c1
	ip -n "$core" addr add 2001:db8:1::2/64 dev c1 nodad
	ip -n "$core" addr add 198.51.100.2/30 dev c2
	ip -n "$core" addr add 2001:db8:2::2/64 dev c2 nodad
	tc -n "$core" qdisc add dev c1 clsact
	tc -n "$core" qdisc add dev c2 clsact

	# The packets of the instance 101, by family of RLOC: the I flag and
	# the instance ID after the UDP header, and DF in the IPv4 header.
	tc -n "$core" filter add dev c1 ingress protocol ip pref 4 u32 \
		match ip protocol 17 0xff match ip dport $LISP_PORT 0xffff \
		match u16 0x4000 0xffff at 6 match u8 0x08 0xff at 28 \
		match u32 $((IID << 8)) 0xffffffff at 32 action continue
	tc -n "$core" filter add dev c1 ingress protocol ipv6 pref 6 u32 \
		match ip6 protocol 17 0xff match ip6 dport $LISP_PORT 0xffff \
		match u8 0x08 0xff at 48 \
		match u32 $((IID << 8)) 0xffffffff at 52 action continue

	ip -n "$x1" link add site type vrf table 10
	ip -n "$x1" link add wan type vrf table 20
	ip -n "$x1" link add site2 type vrf table 30
	ip -n "$x1" link set site up
	ip -n "$x1" link set wan up
	ip -n "$x1" link set site2 up
	ip -n "$x1" link set eth0 master site up
	ip -n "$x1" link set eth1 master wan up
	ip -n "$x1" addr add 10.1.0.1/24 dev eth0
	ip -n "$x1" addr add fd00:1::1/64 dev eth0 nodad
	ip -n "$x1" addr add $X1_RLOC4/30 dev eth1
	ip -n "$x1" addr add $X1_RLOC6/64 dev eth1 nodad
	ip -n "$x1" route add default vrf wan via 192.0.2.2
	ip -n "$x1" -6 route add default vrf wan via 2001:db8:1::2

	ip -n "$x1" link add link wan name lisp101 type lisp id $IID \
		local $X1_RLOC4 local $X1_RLOC6 || return
	ip -n "$x1" link set lisp101 master site up
	ip -n "$x1" -6 nexthop add id $NH4 encap ip dst $X2_RLOC4 dev lisp101
	ip -n "$x1" -6 nexthop add id $NH6 encap ip6 dst $X2_RLOC6 dev lisp101

	ip -n "$x2" link set eth0 up
	ip -n "$x2" link set eth1 up
	ip -n "$x2" addr add 10.2.0.1/24 dev eth0
	ip -n "$x2" addr add fd00:2::1/64 dev eth0 nodad
	ip -n "$x2" addr add $X2_RLOC4/30 dev eth1
	ip -n "$x2" addr add $X2_RLOC6/64 dev eth1 nodad
	ip -n "$x2" route add default via 198.51.100.2
	ip -n "$x2" -6 route add default via 2001:db8:2::2

	ip -n "$x2" link add lisp101 type lisp id $IID
	ip -n "$x2" link set lisp101 up
	ip -n "$x2" -6 nexthop add id $NH4 encap ip dst $X1_RLOC4 dev lisp101
	ip -n "$x2" -6 nexthop add id $NH6 encap ip6 dst $X1_RLOC6 dev lisp101

	use_rlocs 4
}

cleanup()
{
	[[ -n $TCP_FILE ]] && rm -f "$TCP_FILE" "$TCP_FILE.out"
	cleanup_all_ns
}

################################################################################
# Tests

netlink_test()
{
	local out

	RET=0

	out=$(ip -n "$x2" link add t0 type lisp id $IID 2>&1)
	check_fail $? "an instance ID is used twice"
	[[ $out == *"already has this instance ID"* ]]
	check_err $? "unexpected error for a used instance ID: $out"

	ip -n "$x2" link add t1 type lisp external
	check_err $? "no device that collects metadata"
	out=$(ip -n "$x2" link add t0 type lisp external 2>&1)
	check_fail $? "two devices collect metadata"
	[[ $out == *"already collects the metadata"* ]]
	check_err $? "unexpected error for a second device with metadata: $out"
	out=$(ip -n "$x2" -d -j link show dev t1 |
	      jq -c '.[0].linkinfo.info_data')
	[[ $out == '{"external":true}' ]]
	check_err $? "unexpected attributes with metadata: $out"
	ip -n "$x2" link del t1

	out=$(ip -n "$x2" link add t0 type lisp id 7 local 224.0.0.1 2>&1)
	check_fail $? "a multicast local RLOC is accepted"
	[[ $out == *"not a unicast address"* ]]
	check_err $? "unexpected error for a multicast RLOC: $out"

	out=$(ip -n "$x2" link add t0 type lisp id 7 local fe80::1 2>&1)
	check_fail $? "a link-local local RLOC is accepted"
	[[ $out == *"not a global unicast address"* ]]
	check_err $? "unexpected error for a link-local RLOC: $out"

	out=$(ip -n "$x2" link set lisp101 type lisp id 7 2>&1)
	check_fail $? "the instance ID of a device can be changed"
	[[ $out == *"Operation not supported"* ]]
	check_err $? "unexpected error for a change: $out"
	ip -n "$x1" link set lisp101 type lisp local 192.0.2.99 2> /dev/null
	check_fail $? "a local RLOC of a device can be changed"

	ip -n "$x2" link add t0 type lisp id 16777215 local 192.0.2.9 \
		local 2001:db8::9
	check_err $? "the highest instance ID is refused"
	out=$(ip -n "$x2" -d -j link show dev t0 | jq -c \
		'.[0] | [.mtu, .linkinfo.info_data.id,
			 .linkinfo.info_data.local, .linkinfo.info_data.local6]')
	[[ $out == '[1444,16777215,"192.0.2.9","2001:db8::9"]' ]]
	check_err $? "unexpected attributes: $out"
	ip -n "$x2" link del t0

	[[ $(ip -n "$x1" -j link show dev lisp101 | jq -r '.[0].link') == wan ]]
	check_err $? "the link of the RLOCs is not reported"

	# The same instance ID can be used with RLOCs of another l3mdev, but
	# not twice with the same one.
	ip -n "$x1" link add link site2 name t0 type lisp id $IID
	check_err $? "an instance ID cannot be used with two l3mdevs"
	ip -n "$x1" link set t0 up
	check_err $? "an instance ID cannot be up with two l3mdevs"
	ip -n "$x1" link del t0

	out=$(ip -n "$x1" link add link eth1 name t0 type lisp id $IID 2>&1)
	check_fail $? "an instance ID is used twice with the links of an l3mdev"
	[[ $out == *"already has this instance ID"* ]]
	check_err $? "unexpected error for a used l3mdev: $out"

	# A link that joins the l3mdev later: the device cannot be up.
	ip -n "$x1" link add port9 type dummy
	ip -n "$x1" link add link port9 name t0 type lisp id $IID
	check_err $? "an instance ID cannot be used with a link of the main table"
	ip -n "$x1" link set port9 master wan
	out=$(ip -n "$x1" link set t0 up 2>&1)
	check_fail $? "an instance ID is up twice with the same l3mdev"
	[[ $out == *"Device or resource busy"* ]]
	check_err $? "unexpected error for a used l3mdev: $out"

	# A device goes with its link.
	ip -n "$x1" link del port9
	busywait "$BUSYWAIT_TIMEOUT" bash -c \
		"! ip -n $x1 link show dev t0 > /dev/null 2>&1"
	check_err $? "a device outlives its link"

	log_test "Device attributes"

	if ! "$CLI" --family rt-link --list-ops > /dev/null 2>&1; then
		log_test_skip "Device attributes that ip does not send" \
			"YNL CLI not usable"
		return
	fi

	RET=0

	out=$(ynl_add '{"id": 16777216}')
	[[ $out == *"Numerical result out of range"* ]]
	check_err $? "unexpected answer to an instance ID of 25 bits: $out"
	out=$(ynl_add '{"local": "192.0.2.9"}')
	[[ $out == *"Invalid argument"* ]]
	check_err $? "unexpected answer without instance ID: $out"
	out=$(ynl_add '{"id": 7, "collect-metadata": true}')
	[[ $out == *"Invalid argument"* ]]
	check_err $? "unexpected answer with an instance ID and metadata: $out"
	out=$(ynl_add '{"id": 7, "local": "192.0.2.9"}')
	check_err $? "unexpected answer to valid attributes: $out"
	ip -n "$x2" link del t0

	log_test "Device attributes that ip does not send"
}

rloc_family_test()
{
	local family=$1; shift
	local other=$1; shift
	local before_other
	local before

	RET=0

	use_rlocs "$family"
	before=$(core_packets "$family")
	before_other=$(core_packets "$other")

	h1_ping 10.2.0.2
	check_err $? "no answer from the IPv4 EID"
	h1_ping fd00:2::2
	check_err $? "no answer from the IPv6 EID"

	(( $(core_packets "$family") - before == 2 ))
	check_err $? "unexpected LISP header with IPv$family RLOCs"
	(( $(core_packets "$other") == before_other ))
	check_err $? "packets sent to IPv$other RLOCs"

	log_test "IPv4 and IPv6 EIDs with IPv$family RLOCs"
}

ping_test()
{
	rloc_family_test 4 6
	rloc_family_test 6 4
	use_rlocs 4
}

# The TTL and the DSCP of a packet go to the outer header, then come back with
# what the core did to them. The host sends 20, x1 forwards 19, which the core
# gets in the outer header and forwards as 18. x2 forwards 17.
fields_test()
{
	RET=0

	tc -n "$core" filter add dev c1 ingress protocol ip pref 10 u32 \
		match ip dport $LISP_PORT 0xffff match ip tos 0x28 0xff \
		match u8 19 0xff at 8 action pass
	tc -n "$h2" filter add dev eth0 ingress protocol ip pref 10 u32 \
		match ip protocol 1 0xff match ip tos 0x28 0xff \
		match u8 17 0xff at 8 action pass
	tc -n "$h2" filter add dev eth0 ingress protocol ipv6 pref 11 u32 \
		match ip6 protocol 58 0xff match ip6 priority 0x28 0xff \
		match u8 17 0xff at 7 action pass

	h1_ping -t 20 -Q 0x28 10.2.0.2
	check_err $? "no answer from the IPv4 EID"
	h1_ping -t 20 -Q 0x28 fd00:2::2
	check_err $? "no answer from the IPv6 EID"

	(( $(core_packets 10) == 2 ))
	check_err $? "the outer header did not inherit the TTL and the DSCP"
	(( $(h2_packets 10) == 1 ))
	check_err $? "the IPv4 packet did not get the outer TTL and DSCP"
	(( $(h2_packets 11) == 1 ))
	check_err $? "the IPv6 packet did not get the outer TTL and DSCP"

	tc -n "$core" filter del dev c1 ingress pref 10
	tc -n "$h2" filter del dev eth0 ingress pref 10
	tc -n "$h2" filter del dev eth0 ingress pref 11
	log_test "TTL and DSCP inherited"

	RET=0

	ip -n "$x1" -6 nexthop add id $NH_FIELDS encap ip dst $X2_RLOC4 ttl 5 \
		tos 0x40 dev lisp101
	ip -n "$x1" route replace 10.2.0.0/24 vrf site nhid $NH_FIELDS
	ip -n "$x1" -6 route replace fd00:2::/64 vrf site nhid $NH_FIELDS

	tc -n "$core" filter add dev c1 ingress protocol ip pref 10 u32 \
		match ip dport $LISP_PORT 0xffff match ip tos 0x42 0xff \
		match u8 5 0xff at 8 action pass
	tc -n "$core" filter add dev c2 egress protocol ip pref 10 u32 \
		match ip dport $LISP_PORT 0xffff match ip tos 0x02 0x03 \
		action pedit ex munge ip tos set 0x03 retain 0x03 \
		pipe action csum ip4h
	tc -n "$h2" filter add dev eth0 ingress protocol ip pref 10 u32 \
		match ip protocol 1 0xff match ip tos 0x43 0xff \
		match u8 3 0xff at 8 action pass
	tc -n "$h2" filter add dev eth0 ingress protocol ipv6 pref 11 u32 \
		match ip6 protocol 58 0xff match ip6 priority 0x43 0xff \
		match u8 3 0xff at 7 action pass

	h1_ping -Q 0x2a 10.2.0.2
	check_err $? "no answer from the IPv4 EID"
	h1_ping -Q 0x2a fd00:2::2
	check_err $? "no answer from the IPv6 EID"

	(( $(core_packets 10) == 2 ))
	check_err $? "the outer header did not get the TTL and DSCP of the nexthop"
	(( $(h2_packets 10) == 1 ))
	check_err $? "the IPv4 packet did not get the outer TTL, DSCP and ECN"
	(( $(h2_packets 11) == 1 ))
	check_err $? "the IPv6 packet did not get the outer TTL, DSCP and ECN"

	tc -n "$core" filter del dev c1 ingress pref 10
	tc -n "$core" filter del dev c2 egress pref 10
	tc -n "$h2" filter del dev eth0 ingress pref 10
	tc -n "$h2" filter del dev eth0 ingress pref 11
	use_rlocs 4
	ip -n "$x1" nexthop del id $NH_FIELDS
	log_test "TTL and DSCP of the nexthop, congestion marked by the core"
}

mtu_test()
{
	local family

	for family in 4 6; do
		RET=0
		use_rlocs "$family"

		h1_ping -M do -s 1416 10.2.0.2
		check_err $? "an IPv4 packet of 1444 bytes is lost"
		h1_ping -M do -s 1417 10.2.0.2
		check_fail $? "an IPv4 packet of 1445 bytes goes through"
		h1_ping -s 1396 fd00:2::2
		check_err $? "an IPv6 packet of 1444 bytes is lost"
		h1_ping -s 1397 fd00:2::2
		check_fail $? "an IPv6 packet of 1445 bytes goes through"
		h1_ping -s 3000 10.2.0.2
		check_err $? "IPv4 fragments are lost"

		log_test "Device MTU with IPv$family RLOCs"
	done

	ip -n "$h1" route flush cache
	ip -n "$h1" -6 route flush cache
	use_rlocs 4
}

pmtu_family_test()
{
	local family=$1; shift
	local hlen=$1; shift
	local mtu=$((1400 - hlen))

	RET=0
	use_rlocs "$family"

	h1_ping -M do -s 1372 10.2.0.2
	check_fail $? "a packet goes through a path that is too small"
	h1_ping -M do -s 1372 10.2.0.2
	check_fail $? "a packet goes through a path that is known as too small"
	ip -n "$h1" route get 10.2.0.2 | grep -qw "mtu $mtu"
	check_err $? "no IPv4 path MTU of $mtu on the host"
	h1_ping -M do -s $((mtu - 28)) 10.2.0.2
	check_err $? "an IPv4 packet of the path MTU is lost"

	h1_ping -s 1352 fd00:2::2
	check_fail $? "an IPv6 packet goes through a path that is too small"
	ip -n "$h1" -6 route get fd00:2::2 | grep -qw "mtu $mtu"
	check_err $? "no IPv6 path MTU of $mtu on the host"
	h1_ping -s $((mtu - 48)) fd00:2::2
	check_err $? "an IPv6 packet of the path MTU is lost"

	log_test "Path MTU with IPv$family RLOCs"

	ip -n "$h1" route flush cache
	ip -n "$h1" -6 route flush cache
	ip -n "$x1" route flush cache
	ip -n "$x1" -6 route flush cache
}

frag_family_test()
{
	local family=$1; shift

	RET=0
	use_rlocs "$family"

	# x1 learns the path MTU to the RLOC with a first packet.
	h1_ping -s 1232 fd00:2::2
	h1_ping -s 1232 fd00:2::2
	check_err $? "an IPv6 packet of 1280 bytes is lost"
	h1_ping -s 1233 fd00:2::2
	check_fail $? "an IPv6 packet of 1281 bytes goes through"
	ip -n "$h1" -6 route get fd00:2::2 | grep -qw "mtu 1280"
	check_err $? "no IPv6 path MTU of 1280 on the host"

	log_test "Path that leaves less than 1280 bytes, IPv$family RLOCs"

	ip -n "$h1" -6 route flush cache
	ip -n "$x1" route flush cache
	ip -n "$x1" -6 route flush cache
}

pmtu_test()
{
	ip -n "$core" link set c2 mtu 1400
	ip -n "$x2" link set eth1 mtu 1400

	pmtu_family_test 4 36
	pmtu_family_test 6 56

	ip -n "$core" link set c2 mtu 1300
	ip -n "$x2" link set eth1 mtu 1300

	frag_family_test 4
	frag_family_test 6

	ip -n "$core" link set c2 mtu 1500
	ip -n "$x2" link set eth1 mtu 1500
	use_rlocs 4
}

multipath_test()
{
	local before4
	local before6
	local i

	RET=0

	for i in $(seq 16 47); do
		ip -n "$h2" addr add "10.2.0.$i/24" dev eth0
	done
	ip -n "$x1" nexthop add id $NH_GROUP group $NH4/$NH6
	ip -n "$x1" route replace 10.2.0.0/24 vrf site nhid $NH_GROUP

	before4=$(core_packets 4)
	before6=$(core_packets 6)
	for i in $(seq 16 47); do
		h1_ping "10.2.0.$i"
		check_err $? "no answer from 10.2.0.$i"
	done

	(( $(core_packets 4) > before4 ))
	check_err $? "nothing was sent to the IPv4 RLOC of the group"
	(( $(core_packets 6) > before6 ))
	check_err $? "nothing was sent to the IPv6 RLOC of the group"
	(( $(core_packets 4) + $(core_packets 6) - before4 - before6 == 32 ))
	check_err $? "packets were not sent once"

	# The group counts what it sends to each RLOC.
	(( $(ip -n "$x1" -j -s nexthop show id $NH_GROUP | jq --argjson id $NH4 \
	     '.[0].group_stats[] | select(.id == $id) | .packets') ==
	   $(core_packets 4) - before4 ))
	check_err $? "unexpected count of the packets sent to the IPv4 RLOC"
	(( $(ip -n "$x1" -j -s nexthop show id $NH_GROUP | jq --argjson id $NH6 \
	     '.[0].group_stats[] | select(.id == $id) | .packets') ==
	   $(core_packets 6) - before6 ))
	check_err $? "unexpected count of the packets sent to the IPv6 RLOC"

	use_rlocs 4
	ip -n "$x1" nexthop del id $NH_GROUP
	for i in $(seq 16 47); do
		ip -n "$h2" addr del "10.2.0.$i/24" dev eth0
	done
	log_test "Group of nexthops"
}

# Another instance uses the same sockets: a device in another VRF of x1, and
# the device that collects metadata on x2, where the routes give the instance
# ID.
instance_test()
{
	local rx_before
	local tx_errors
	local family
	local addr

	RET=0

	ip -n "$x1" link add link wan name lisp102 type lisp id 102
	ip -n "$x1" link set lisp102 master site2 up
	ip -n "$x1" addr add 10.9.1.1/32 dev lisp102
	ip -n "$x1" addr add fd00:91::1/128 dev lisp102 nodad

	ip -n "$x2" link add lispmd type lisp external
	ip -n "$x2" link set lispmd up
	ip -n "$x2" link add dummy0 type dummy
	ip -n "$x2" link set dummy0 up
	ip -n "$x2" addr add 10.9.2.1/24 dev dummy0
	ip -n "$x2" addr add fd00:92::1/64 dev dummy0 nodad
	tc -n "$x2" qdisc add dev lispmd clsact

	for family in 4 6; do
		if [[ $family == 4 ]]; then
			ip -n "$x1" -6 nexthop add id $NH_INSTANCE encap ip \
				dst $X2_RLOC4 dev lisp102
			ip -n "$x2" -6 nexthop add id $NH_INSTANCE encap ip \
				id 102 dst $X1_RLOC4 dev lispmd
			tc -n "$x2" filter add dev lispmd ingress pref 1 \
				flower enc_key_id 102 enc_src_ip $X1_RLOC4 \
				action pass
		else
			ip -n "$x1" -6 nexthop replace id $NH_INSTANCE encap ip6 \
				dst $X2_RLOC6 dev lisp102
			ip -n "$x2" -6 nexthop replace id $NH_INSTANCE encap ip6 \
				id 102 dst $X1_RLOC6 dev lispmd
			tc -n "$x2" filter add dev lispmd ingress pref 1 \
				flower enc_key_id 102 enc_src_ip $X1_RLOC6 \
				action pass
		fi
		ip -n "$x1" route replace 10.9.2.0/24 vrf site2 nhid $NH_INSTANCE
		ip -n "$x1" -6 route replace fd00:92::/64 vrf site2 \
			nhid $NH_INSTANCE
		ip -n "$x2" route replace 10.9.1.0/24 nhid $NH_INSTANCE
		ip -n "$x2" -6 route replace fd00:91::/64 nhid $NH_INSTANCE

		rx_before=$(link_stat "$x1" lisp101 .rx.packets)
		for addr in 10.9.2.1 fd00:92::1; do
			ip netns exec "$x1" ping -q -c 1 -W 2 -I site2 "$addr" \
				> /dev/null 2>&1
			check_err $? "no answer from $addr with IPv$family RLOCs"
		done

		(( $(tc_packets "$x2" lispmd 1) == 2 ))
		check_err $? "no metadata with IPv$family RLOCs"
		(( $(link_stat "$x1" lisp101 .rx.packets) == rx_before ))
		check_err $? "packets received by another instance"

		tc -n "$x2" filter del dev lispmd ingress pref 1
	done

	h1_ping 10.2.0.2
	check_err $? "the first instance is lost"

	# An instance ID that does not fit the header: the device refuses it.
	ip -n "$x2" -6 route del fd00:91::/64
	ip -n "$x2" -6 nexthop replace id $NH_INSTANCE encap ip id 16777216 \
		dst $X1_RLOC4 dev lispmd
	tx_errors=$(link_stat "$x2" lispmd .tx.errors)
	ip netns exec "$x2" ping -q -c 1 -W 1 10.9.1.1 > /dev/null 2>&1
	check_fail $? "an instance ID of 25 bits is sent"
	(( $(link_stat "$x2" lispmd .tx.errors) == tx_errors + 1 ))
	check_err $? "an instance ID of 25 bits is not refused by the device"

	ip -n "$x2" route del 10.9.1.0/24
	ip -n "$x2" nexthop del id $NH_INSTANCE
	ip -n "$x2" link del dummy0
	ip -n "$x2" link del lispmd
	ip -n "$x1" link del lisp102
	log_test "Instances with a device each and with metadata"
}

receive_test()
{
	local frame_errors
	local length_errors
	local rx

	RET=0

	rx=$(link_stat "$x1" lisp101 .rx.packets)
	frame_errors=$(link_stat "$x1" lisp101 .rx.frame_errors)
	length_errors=$(link_stat "$x1" lisp101 .rx.length_errors)

	# Neither IPv4 nor IPv6 after the header.
	core_send '\x08\x00\x00\x00\x00\x00\x65\x00\x00\x00\x00\x00'
	busywait "$BUSYWAIT_TIMEOUT" until_counter_is \
		"== $((frame_errors + 1))" \
		link_stat "$x1" lisp101 .rx.frame_errors > /dev/null
	check_err $? "a payload of an unknown version is not counted"

	# An IPv4 header that is cut.
	core_send '\x08\x00\x00\x00\x00\x00\x65\x00\x45\x00\x00\x00'
	busywait "$BUSYWAIT_TIMEOUT" until_counter_is \
		"== $((length_errors + 1))" \
		link_stat "$x1" lisp101 .rx.length_errors > /dev/null
	check_err $? "a short payload is not counted"

	# An encrypted payload, an unknown instance, and no instance.
	core_send '\x09\x00\x00\x00\x00\x00\x65\x00\x00\x00\x00\x00'
	core_send '\x08\x00\x00\x00\x00\x00\x66\x00\x00\x00\x00\x00'
	core_send '\x00\x00\x00\x00\x00\x00\x65\x00\x00\x00\x00\x00'
	core_send '\x08\x00\x00\x00\x00\x00\x65\x00\x00\x00\x00\x00'
	busywait "$BUSYWAIT_TIMEOUT" until_counter_is \
		"== $((frame_errors + 2))" \
		link_stat "$x1" lisp101 .rx.frame_errors > /dev/null
	check_err $? "packets of other instances are counted"

	# Without the I flag, the instance is 0.
	ip -n "$x1" link add link wan name lisp0 type lisp id 0
	ip -n "$x1" link set lisp0 up
	core_send '\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00'
	busywait "$BUSYWAIT_TIMEOUT" until_counter_is "== 1" \
		link_stat "$x1" lisp0 .rx.frame_errors > /dev/null
	check_err $? "a packet without instance ID is not for the instance 0"
	ip -n "$x1" link del lisp0

	(( $(link_stat "$x1" lisp101 .rx.packets) == rx ))
	check_err $? "packets were received"

	# A route without RLOC.
	ip -n "$x1" route add 10.3.0.0/24 vrf site dev lisp101
	rx=$(link_stat "$x1" lisp101 .tx.errors)
	h1_ping -W 1 10.3.0.1
	(( $(link_stat "$x1" lisp101 .tx.errors) == rx + 1 ))
	check_err $? "a packet without RLOC is not counted"
	ip -n "$x1" route del 10.3.0.0/24 vrf site

	log_test "Packets that are dropped"
}

# the reverse path filter of IPv4 dropped on x1
x1_filtered()
{
	ip netns exec "$x1" nstat -asz TcpExtIPReversePathFilter |
		awk '$1 == "TcpExtIPReversePathFilter" { print $2 }'
}

h1_echos()
{
	ip netns exec "$h1" nstat -asz IcmpInEchos |
		awk '$1 == "IcmpInEchos" { print $2 }'
}

rpfilter_test()
{
	local filtered
	local echos
	local all

	RET=0

	use_rlocs 4
	all=$(ip netns exec "$x1" sysctl -n net.ipv4.conf.all.rp_filter)
	ip netns exec "$x1" sysctl -qw net.ipv4.conf.all.rp_filter=0
	ip netns exec "$x1" sysctl -qw net.ipv4.conf.lisp101.rp_filter=1

	h2_ping 10.1.0.2
	check_err $? "a source is dropped, whose route sends to the device"

	# The route of the source has another RLOC than the one of x2.
	ip -n "$x1" -6 nexthop add id $NH_OTHER encap ip dst $OTHER_RLOC4 \
		dev lisp101
	ip -n "$x1" route replace 10.2.0.0/24 vrf site nhid $NH_OTHER
	echos=$(h1_echos)
	h2_ping 10.1.0.2
	busywait "$BUSYWAIT_TIMEOUT" until_counter_is "== $((echos + 1))" \
		h1_echos > /dev/null
	check_err $? "a source is dropped for the RLOC that it comes from"

	ip -n "$x1" link add nomap type dummy
	ip -n "$x1" link set nomap master site up
	ip -n "$x1" route replace 10.2.0.0/24 vrf site dev nomap
	filtered=$(x1_filtered)
	h2_ping 10.1.0.2
	busywait "$BUSYWAIT_TIMEOUT" until_counter_is "== $((filtered + 1))" \
		x1_filtered > /dev/null
	check_err $? "a source without mapping is not dropped by the filter"

	ip netns exec "$x1" sysctl -qw net.ipv4.conf.lisp101.rp_filter=0
	echos=$(h1_echos)
	h2_ping 10.1.0.2
	busywait "$BUSYWAIT_TIMEOUT" until_counter_is "== $((echos + 1))" \
		h1_echos > /dev/null
	check_err $? "a source without mapping is dropped without the filter"

	ip netns exec "$x1" sysctl -qw net.ipv4.conf.all.rp_filter="$all"
	ip -n "$x1" link del nomap
	ip -n "$x1" nexthop del id $NH_OTHER
	use_rlocs 4
	h2_ping 10.1.0.2
	check_err $? "no connectivity after the test"

	log_test "Reverse path filter on a device"
}

updown_test()
{
	RET=0

	ip -n "$x1" link add link wan name lisp102 type lisp id 102
	ip -n "$x1" link set lisp102 up
	ip -n "$x1" link set lisp101 down
	h1_ping -W 1 10.2.0.2
	check_fail $? "an answer through a device that is down"

	ip -n "$x1" nexthop show id $NH4 > /dev/null 2>&1
	check_fail $? "a nexthop outlives its device"
	ip -n "$x1" link set lisp101 up
	ip -n "$x1" -6 nexthop add id $NH4 encap ip dst $X2_RLOC4 dev lisp101
	ip -n "$x1" -6 nexthop add id $NH6 encap ip6 dst $X2_RLOC6 dev lisp101
	use_rlocs 4
	ip -n "$x1" link del lisp102
	h1_ping 10.2.0.2
	check_err $? "no answer once the device is up again"

	ip -n "$x1" link set lisp101 down
	ip -n "$x1" link set lisp101 up
	ip -n "$x1" -6 nexthop add id $NH4 encap ip dst $X2_RLOC4 dev lisp101
	ip -n "$x1" -6 nexthop add id $NH6 encap ip6 dst $X2_RLOC6 dev lisp101
	use_rlocs 4
	h1_ping fd00:2::2
	check_err $? "no answer with a new socket"

	log_test "Devices going down and up"
}

tcp_family_test()
{
	local family=$1; shift
	local addr=$1; shift
	local pid

	ip netns exec "$h2" timeout $TCP_TIMEOUT socat -u \
		"TCP$family-LISTEN:$TCP_PORT,reuseaddr" \
		"OPEN:$TCP_FILE.out,creat,trunc" &
	pid=$!
	wait_local_port_listen "$h2" $TCP_PORT tcp
	if ip netns exec "$h1" timeout $TCP_TIMEOUT socat -u "OPEN:$TCP_FILE" \
			"TCP$family:$addr:$TCP_PORT"; then
		wait $pid
		check_err $? "the listener of $addr did not end"
	else
		check_err 1 "no TCP connection to $addr"
		kill_process $pid
	fi

	cmp -s "$TCP_FILE" "$TCP_FILE.out"
	check_err $? "the data sent to $addr is not what was received"
}

tcp_test()
{
	local family

	if ! command -v socat > /dev/null; then
		log_test_skip "TCP" "socat not installed"
		return
	fi

	TCP_FILE=$(mktemp)
	head -c 16M /dev/urandom > "$TCP_FILE"

	for family in 4 6; do
		RET=0
		use_rlocs "$family"
		tcp_family_test 4 10.2.0.2
		tcp_family_test 6 "[fd00:2::2]"
		log_test "TCP with IPv$family RLOCs"
	done
	use_rlocs 4
}

# Two xTRs whose EIDs and RLOCs are in two routing domains with the same
# addresses: the EID of an xTR is the RLOC of the other one. A packet and its
# outer header have then the same addresses, the other way around, and they
# only reach their destinations when each one is routed in its own domain.
CROSS_A4=192.0.2.9
CROSS_A6=2001:db8:3::1
CROSS_B4=192.0.2.10
CROSS_B6=2001:db8:3::2

cross_nexthops()
{
	local ns=$1; shift
	local rloc4=$1; shift
	local rloc6=$1; shift

	ip -n "$ns" -6 nexthop add id $NH4 encap ip dst "$rloc4" dev lisp0
	ip -n "$ns" -6 nexthop add id $NH6 encap ip6 dst "$rloc6" dev lisp0
}

cross_routes()
{
	local ns=$1; shift
	local nh=$1; shift
	local eid4=$1; shift
	local eid6=$1; shift

	ip -n "$ns" route replace "$eid4/32" "$@" nhid "$nh"
	ip -n "$ns" -6 route replace "$eid6/128" "$@" nhid "$nh"
}

cross_ping()
{
	local ns=$1; shift
	local eid4=$1; shift
	local eid6=$1; shift
	local before

	before=$(link_stat "$ns" lisp0 .rx.packets)
	ip netns exec "$ns" ping -q -c 1 -W 2 "$@" "$eid4" > /dev/null 2>&1
	check_err $? "no answer from the EID $eid4"
	ip netns exec "$ns" ping -q -c 1 -W 2 "$@" "$eid6" > /dev/null 2>&1
	check_err $? "no answer from the EID $eid6"
	(( $(link_stat "$ns" lisp0 .rx.packets) == before + 2 ))
	check_err $? "the answers did not come through the LISP device"
}

# The first xTR has its EIDs in a VRF and its RLOCs in the main table, the
# second one has its RLOCs in a VRF and its EIDs in the main table.
#
#   y1                                           y2
#   VRF "eid", lisp0: B4, B6 ................... lisp0: A4, A6
#   eth0: A4, A6 ------------------------------- VRF "rloc", eth0: B4, B6
cross_vrf_test()
{
	local family
	local before
	local ns
	local nh

	setup_ns y1 y2
	ip link add eth0 netns "$y1" type veth peer name eth0 netns "$y2"

	for ns in "$y1" "$y2"; do
		ip -n "$ns" rule add pref 32765 table local
		ip -n "$ns" rule del pref 0
		ip -n "$ns" -6 rule add pref 32765 table local
		ip -n "$ns" -6 rule del pref 0
	done

	ip -n "$y1" link set eth0 up
	ip -n "$y1" addr add $CROSS_A4/30 dev eth0
	ip -n "$y1" addr add $CROSS_A6/64 dev eth0 nodad
	ip -n "$y1" link add eid type vrf table 10
	ip -n "$y1" link set eid up
	ip -n "$y1" link add lisp0 type lisp id 7
	ip -n "$y1" link set lisp0 master eid up
	ip -n "$y1" addr add $CROSS_B4/32 dev lisp0
	ip -n "$y1" addr add $CROSS_B6/128 dev lisp0 nodad
	cross_nexthops "$y1" $CROSS_B4 $CROSS_B6

	ip -n "$y2" link add rloc type vrf table 10
	ip -n "$y2" link set rloc up
	ip -n "$y2" link set eth0 master rloc up
	ip -n "$y2" addr add $CROSS_B4/30 dev eth0
	ip -n "$y2" addr add $CROSS_B6/64 dev eth0 nodad
	ip -n "$y2" link add link rloc name lisp0 type lisp id 7
	ip -n "$y2" link set lisp0 up
	ip -n "$y2" addr add $CROSS_A4/32 dev lisp0
	ip -n "$y2" addr add $CROSS_A6/128 dev lisp0 nodad
	cross_nexthops "$y2" $CROSS_A4 $CROSS_A6

	for family in 4 6; do
		RET=0
		nh=NH$family
		cross_routes "$y1" "${!nh}" $CROSS_A4 $CROSS_A6 vrf eid
		cross_routes "$y2" "${!nh}" $CROSS_B4 $CROSS_B6

		cross_ping "$y1" $CROSS_A4 $CROSS_A6 -I eid
		cross_ping "$y2" $CROSS_B4 $CROSS_B6

		# In the main table of y1, the same addresses are the RLOCs
		# of y2, which answer without LISP.
		before=$(link_stat "$y1" lisp0 .tx.packets)
		ip netns exec "$y1" ping -q -c 1 -W 2 $CROSS_B4 > /dev/null 2>&1
		check_err $? "no answer from the RLOC $CROSS_B4"
		ip netns exec "$y1" ping -q -c 1 -W 2 $CROSS_B6 > /dev/null 2>&1
		check_err $? "no answer from the RLOC $CROSS_B6"
		(( $(link_stat "$y1" lisp0 .tx.packets) == before ))
		check_err $? "packets for an RLOC were sent to the LISP device"

		log_test "EIDs and RLOCs in a VRF and the main table, IPv$family RLOCs"
	done

	cleanup_ns "$y1" "$y2"
}

# Both xTRs have their EIDs in a netns and their RLOCs in another one. The
# netns of the EIDs has no other device than the LISP one.
#
#   ain                                          bin
#   lisp0: B4, B6 .............................. lisp0: A4, A6
#   aout                                         bout
#   eth0: A4, A6 ------------------------------- eth0: B4, B6
cross_netns_test()
{
	local family
	local nh

	setup_ns ain aout bin bout
	ip link add eth0 netns "$aout" type veth peer name eth0 netns "$bout"

	ip -n "$aout" link set eth0 up
	ip -n "$aout" addr add $CROSS_A4/30 dev eth0
	ip -n "$aout" addr add $CROSS_A6/64 dev eth0 nodad
	ip -n "$ain" link add lisp0 link-netns "$aout" type lisp id 8
	ip -n "$ain" link set lisp0 up
	ip -n "$ain" addr add $CROSS_B4/32 dev lisp0
	ip -n "$ain" addr add $CROSS_B6/128 dev lisp0 nodad
	cross_nexthops "$ain" $CROSS_B4 $CROSS_B6

	ip -n "$bout" link set eth0 up
	ip -n "$bout" addr add $CROSS_B4/30 dev eth0
	ip -n "$bout" addr add $CROSS_B6/64 dev eth0 nodad
	ip -n "$bin" link add lisp0 link-netns "$bout" type lisp id 8
	ip -n "$bin" link set lisp0 up
	ip -n "$bin" addr add $CROSS_A4/32 dev lisp0
	ip -n "$bin" addr add $CROSS_A6/128 dev lisp0 nodad
	cross_nexthops "$bin" $CROSS_A4 $CROSS_A6

	for family in 4 6; do
		RET=0
		nh=NH$family
		cross_routes "$ain" "${!nh}" $CROSS_A4 $CROSS_A6
		cross_routes "$bin" "${!nh}" $CROSS_B4 $CROSS_B6

		cross_ping "$ain" $CROSS_A4 $CROSS_A6
		cross_ping "$bin" $CROSS_B4 $CROSS_B6

		log_test "EIDs and RLOCs in two netns, IPv$family RLOCs"
	done

	cleanup_ns "$ain" "$aout" "$bin" "$bout"
}

netns_test()
{
	local port

	RET=0
	port=$(printf ':%04X' $LISP_PORT)

	setup_ns eid rloc
	ip -n "$eid" link add lisp0 link-netns "$rloc" type lisp id 5
	check_err $? "no device with a link netns"
	ip -n "$eid" link set lisp0 up
	ip -n "$eid" -d link show dev lisp0 | grep -q link-netns
	check_err $? "the link netns is not reported"
	ip netns exec "$rloc" grep -q "$port " /proc/net/udp /proc/net/udp6
	check_err $? "no socket in the link netns"
	ip netns exec "$eid" grep -q "$port " /proc/net/udp /proc/net/udp6
	check_fail $? "a socket in the netns of the device"

	cleanup_ns "$rloc"
	busywait "$BUSYWAIT_TIMEOUT" bash -c \
		"! ip -n $eid link show dev lisp0 > /dev/null 2>&1"
	check_err $? "the device outlives the netns of its RLOCs"
	cleanup_ns "$eid"

	log_test "RLOCs in another netns"
}

################################################################################
# Main

require_command jq

if ! ip link help lisp 2>&1 | grep -q "^Usage: ... lisp"; then
	echo "SKIP: iproute2 does not know the lisp devices"
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
