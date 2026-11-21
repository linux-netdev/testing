#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Check the IPv4 IDs of a TCP stream that GRO merged and software
# segmentation split again across a tunnel. A sender in NSRC writes
# segments with fixed or incrementing IDs onto a veth with GRO on in
# NRTR, which forwards the merged packets:
#
#  encap:       into an IPIP, GRE or VXLAN tunnel over IPv4 or IPv6,
#               segmented on the underlay towards NMID
#  decap:       out of VXLAN, received from NSRC with one header fixed and
#               the other incrementing, into an IPIP tunnel towards NMID
#  encap+decap: into a tunnel that NMID ends without segmenting, and on
#               to NDST, segmented there
#  esp:         into an ESP SA in tunnel or transport mode offloaded to
#               netdevsim, which segments the packet in software and does
#               not encrypt it
#
# The inner IDs must come out as they went in, and the IDs of a new outer
# IPv4 header must be unique, or for ESP tunnel mode, whose outer IDs start
# at 0 for each packet with DF set, increment within each packet. ESP
# transport mode keeps the sender's IPv4 header and its ID. A run in which
# GRO merged nothing is skipped.

source lib.sh

NSRC=""
NRTR=""
NMID=""
NDST=""

SEGS=40
BURSTS=10
TOTAL=$((SEGS * BURSTS))
INNER_SRC=10.1.0.1
INNER_DST=10.9.0.2
VX_MAC=02:00:00:00:00:42
TUN_MAC=02:00:00:00:00:99
MID_MAC=02:00:00:00:00:98
TX=tcp_fixedid
NSIM_ID=$((RANDOM % 1024 + 1024))
NSIM_BUS=/sys/bus/netdevsim
NSIM_IDS=()

NOSEG="tso gso tx-gre-segmentation tx-gre-csum-segmentation
       tx-ipxip4-segmentation tx-ipxip6-segmentation
       tx-udp_tnl-segmentation tx-udp_tnl-csum-segmentation"

# nsim_add <id> <ns>: create netdevsim device <id> with one port in <ns>,
# record <id> for nsim_del and put the port's name in NSIM_DEV
nsim_add() {
	NSIM_DEV=""
	echo "$1 1" | ip netns exec "$2" tee "$NSIM_BUS/new_device" \
		>/dev/null 2>&1 || return 1
	NSIM_IDS+=("$1")
	NSIM_DEV=$(ip netns exec "$2" ls "$NSIM_BUS/devices/netdevsim$1/net")
	[ -n "$NSIM_DEV" ]
}

# nsim_del: delete the netdevsim devices that nsim_add created
nsim_del() {
	local id

	for id in "${NSIM_IDS[@]}"; do
		echo "$id" > "$NSIM_BUS/del_device"
	done
	NSIM_IDS=()
}

cleanup() {
	nsim_del
	cleanup_all_ns
	rm -f "$RESULT"
}

trap cleanup EXIT

# NSRC s0 - r0 NRTR r1 - m1 NMID m2 - d2 NDST
setup() {
	setup_ns NSRC NRTR NMID NDST || return "$ksft_skip"

	ip link add s0 netns "$NSRC" type veth peer name r0 netns "$NRTR"
	ip link add r1 netns "$NRTR" type veth peer name m1 netns "$NMID"
	ip link add m2 netns "$NMID" type veth peer name d2 netns "$NDST"

	ip -n "$NRTR" addr add 10.1.0.2/24 dev r0
	ip -n "$NRTR" addr add 10.2.0.1/24 dev r1
	ip -n "$NRTR" addr add fd02::1/64 dev r1 nodad
	ip -n "$NMID" addr add 10.2.0.2/24 dev m1
	ip -n "$NMID" addr add fd02::2/64 dev m1 nodad
	ip -n "$NMID" addr add 10.4.0.1/24 dev m2
	ip -n "$NDST" addr add 10.4.0.2/24 dev d2
	ip -n "$NSRC" link set s0 up
	ip -n "$NRTR" link set r0 up
	ip -n "$NRTR" link set r1 up
	ip -n "$NMID" link set m1 up
	ip -n "$NMID" link set m2 up
	ip -n "$NDST" link set d2 up

	ip netns exec "$NRTR" sysctl -qw net.ipv4.ip_forward=1
	ip netns exec "$NMID" sysctl -qw net.ipv4.ip_forward=1
	for ns in "$NRTR" "$NMID"; do
		ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 \
			net.ipv4.conf.default.rp_filter=0
	done

	# veth passes packets to GRO only if the sender does not do TSO
	ip netns exec "$NRTR" ethtool -K r0 gro on >/dev/null ||
		return "$ksft_skip"
	ip netns exec "$NSRC" ethtool -K s0 tso off >/dev/null ||
		return "$ksft_skip"
	# release the sender's segments in bursts for GRO to merge
	tc -n "$NSRC" qdisc add dev s0 root netem slot 20ms 20ms \
		packets "$SEGS" || return "$ksft_skip"
}

# tunnel <ns> <name> <type> <family> <local> <remote>
tunnel() {
	local ns=$1 name=$2 type=$3 family=$4 local=$5 remote=$6

	case "$type" in
	ipip)
		if [ "$family" = 4 ]; then
			ip -n "$ns" link add "$name" type ipip \
				local "$local" remote "$remote"
		else
			ip -n "$ns" link add "$name" type ip6tnl mode ipip6 \
				local "$local" remote "$remote" encaplimit none
		fi ;;
	gre)
		if [ "$family" = 4 ]; then
			ip -n "$ns" link add "$name" type gre \
				local "$local" remote "$remote"
		else
			ip -n "$ns" link add "$name" type ip6gre \
				local "$local" remote "$remote" encaplimit none
		fi ;;
	vxlan)
		ip -n "$ns" link add "$name" address "$TUN_MAC" type vxlan \
			id 7 dstport 4789 local "$local" remote "$remote" \
			nolearning ;;
	esac || return 1
	# no IPv6 link-local traffic in the tx_packets of the tunnel
	ip netns exec "$ns" sysctl -qw "net.ipv6.conf.$name.disable_ipv6=1"
	ip -n "$ns" link set "$name" up
}

# route_into <ns> <dev>: send INNER_DST into <dev>
route_into() {
	ip -n "$1" route add "$INNER_DST/32" dev "$2"
	ip -n "$1" neigh add "$INNER_DST" lladdr "$TUN_MAC" dev "$2" \
		2>/dev/null
	return 0
}

# noseg <ns> <dev>: segment everything in software before <dev>
noseg() {
	local f

	for f in $NOSEG; do
		ip netns exec "$1" ethtool -K "$2" "$f" off >/dev/null 2>&1
	done
}

tx_packets() {
	ip netns exec "$1" cat "/sys/class/net/$2/statistics/tx_packets"
}

# fwd_packets <ns>: packets forwarded, a GSO packet counting once
fwd_packets() {
	ip netns exec "$1" cat /proc/net/snmp | awk '/^Ip: [0-9]/ { print $7 }'
}

# check <name> <result> <want: fixed|incr> <outer: 0|unique|incr> <sent>
# <sent> is the number of packets forwarded, a GSO packet counting once
check() {
	local name=$1 res=$2 want=$3 outer=$4 sent=$5
	local frames outer_ids inner_ids inner_bad outer_incr incr

	read -r _ frames _ _ _ outer_ids _ inner_ids _ inner_bad _ outer_incr \
		<<< "$res"
	RET=0
	if [ -z "$outer_incr" ]; then
		check_err 1 "no result from the receiver${res:+: $res}"
		log_test "$name"
		return
	fi
	check_err $((frames != TOTAL)) "$frames of $TOTAL segments received"
	check_err "$inner_bad" "$inner_bad inner IDs not sent"
	if [ "$want" = fixed ]; then
		check_err $((inner_ids != 1)) "$inner_ids inner IDs, want 1"
	else
		check_err $((inner_ids != TOTAL)) \
			"$inner_ids inner IDs, want $TOTAL"
	fi
	# the outer IDs of packets that GRO did not merge show nothing
	if [ "$RET" -eq 0 ] && [ "$sent" -ge "$TOTAL" ]; then
		ret_set_ksft_status "$ksft_skip" "GRO did not merge"
		log_test "$name"
		return
	fi
	if [ "$outer" = unique ]; then
		check_err $((outer_ids != frames)) \
			"$outer_ids outer IDs for $frames segments"
	elif [ "$outer" = incr ]; then
		# all but the first segment of each packet
		incr=$((frames - sent))
		check_err $((outer_incr < incr)) \
			"$outer_incr outer IDs increment, want $incr"
	fi
	log_test "$name"
}

# capture <ns> <dev> <want: fixed|incr>: start the receiver in the
# background, pid in CAP_PID, and wait until it is bound
capture() {
	local f=""

	[ "$3" = fixed ] && f=-f
	: > "$RESULT"
	ip netns exec "$1" "$TX" -R -i "$2" -c "$TOTAL" -w 3000 $f > "$RESULT" &
	CAP_PID=$!
	if ! slowwait 10 grep -q ready "$RESULT"; then
		kill "$CAP_PID" 2>/dev/null
		echo "not bound within 10 s" > "$RESULT"
	fi
}

run_encap() {
	local type=$1 family=$2 want=$3
	local r0mac t0 laddr=10.2.0.1 raddr=10.2.0.2
	local f=""

	setup || { log_test_skip "encap $type IPv$family"; return; }
	if [ "$family" = 6 ]; then
		laddr=fd02::1
		raddr=fd02::2
	fi
	if ! tunnel "$NRTR" tun0 "$type" "$family" "$laddr" "$raddr"; then
		log_test_skip "encap $type IPv$family"
		cleanup_all_ns
		return
	fi
	route_into "$NRTR" tun0
	noseg "$NRTR" r1

	r0mac=$(ip -n "$NRTR" -br link show r0 | awk '{ print $3 }')
	capture "$NMID" m1 "$want"
	t0=$(tx_packets "$NRTR" tun0)
	[ "$want" = fixed ] && f=-f
	ip netns exec "$NSRC" "$TX" -T -i s0 -M "$r0mac" -s "$INNER_SRC" \
		-d "$INNER_DST" -n "$SEGS" -b "$BURSTS" $f
	wait "$CAP_PID"
	check "encap $type IPv$family, $want inner IDs" \
		"$(tail -n 1 "$RESULT")" "$want" \
		"$([ "$family" = 4 ] && echo unique || echo 0)" \
		$(($(tx_packets "$NRTR" tun0) - t0))
	cleanup_all_ns
}

# run_decap <fixed: inner|outer>: VXLAN from NSRC, decapsulated in NRTR
run_decap() {
	local fixed=$1 want=incr flags=-F
	local r0mac t0

	setup || { log_test_skip "decap"; return; }
	ip -n "$NRTR" link add vx0 address "$VX_MAC" type vxlan id 42 \
		dstport 4789 local 10.1.0.2 nolearning ||
		{ log_test_skip "decap"; cleanup_all_ns; return; }
	ip -n "$NRTR" addr add 10.3.0.2/24 dev vx0
	ip -n "$NRTR" link set vx0 up
	if ! tunnel "$NRTR" tun0 ipip 4 10.2.0.1 10.2.0.2; then
		log_test_skip "decap"
		cleanup_all_ns
		return
	fi
	route_into "$NRTR" tun0
	noseg "$NRTR" r1

	if [ "$fixed" = inner ]; then
		want=fixed
		flags=-f
	fi
	r0mac=$(ip -n "$NRTR" -br link show r0 | awk '{ print $3 }')
	capture "$NMID" m1 "$want"
	t0=$(tx_packets "$NRTR" tun0)
	ip netns exec "$NSRC" "$TX" -T -i s0 -M "$r0mac" -s 10.3.0.1 \
		-d "$INNER_DST" -n "$SEGS" -b "$BURSTS" \
		-V 10.1.0.1,10.1.0.2 -m "$VX_MAC" $flags
	wait "$CAP_PID"
	check "decap VXLAN with fixed $fixed IDs, into IPIP" \
		"$(tail -n 1 "$RESULT")" "$want" unique \
		$(($(tx_packets "$NRTR" tun0) - t0))
	cleanup_all_ns
}

# run_encap_decap <type>: NRTR encapsulates, NMID decapsulates the GSO
# packet without segmenting it and forwards it to NDST
run_encap_decap() {
	local type=$1
	local r0mac t0

	setup || { log_test_skip "encap+decap $type"; return; }
	if ! tunnel "$NRTR" tun0 "$type" 4 10.2.0.1 10.2.0.2 ||
	   ! tunnel "$NMID" tun0 "$type" 4 10.2.0.2 10.2.0.1; then
		log_test_skip "encap+decap $type"
		cleanup_all_ns
		return
	fi
	route_into "$NRTR" tun0
	# VXLAN drops frames from its own address as loops
	if [ "$type" = vxlan ]; then
		ip -n "$NMID" link set tun0 address "$MID_MAC"
		ip -n "$NRTR" neigh replace "$INNER_DST" lladdr "$MID_MAC" \
			dev tun0
	fi
	ip -n "$NMID" route add "$INNER_DST/32" via 10.4.0.2
	ip -n "$NDST" addr add "$INNER_DST/32" dev d2
	noseg "$NMID" m2

	r0mac=$(ip -n "$NRTR" -br link show r0 | awk '{ print $3 }')
	capture "$NDST" d2 fixed
	t0=$(tx_packets "$NRTR" tun0)
	ip netns exec "$NSRC" "$TX" -T -i s0 -M "$r0mac" -s "$INNER_SRC" \
		-d "$INNER_DST" -n "$SEGS" -b "$BURSTS" -f
	wait "$CAP_PID"
	check "encap+decap $type, fixed inner IDs" "$(tail -n 1 "$RESULT")" \
		fixed 0 $(($(tx_packets "$NRTR" tun0) - t0))
	cleanup_all_ns
}

# run_esp <mode>: NRTR forwards into an ESP SA in tunnel or transport
# mode, offloaded to a netdevsim port with TSO off and linked to a
# netdevsim port in NMID
run_esp() {
	local mode=$1 key=0x3132333435363738393031323334353664636261
	local src=10.5.0.1 dst=10.5.0.2 outer=incr
	local r0mac rdev mdev rif mif rfd mfd t0

	if [ "$mode" = transport ]; then
		src=$INNER_SRC
		dst=$INNER_DST
		outer=0
	fi

	setup || { log_test_skip "esp $mode"; return; }
	if ! modprobe -q netdevsim 2>/dev/null &&
	   [ ! -w "$NSIM_BUS/new_device" ]; then
		log_test_skip "esp $mode: no netdevsim"
		cleanup_all_ns
		return
	fi
	if ! nsim_add "$NSIM_ID" "$NRTR"; then
		log_test_skip "esp $mode: netdevsim"
		nsim_del
		cleanup_all_ns
		return
	fi
	rdev=$NSIM_DEV
	if ! nsim_add $((NSIM_ID + 1)) "$NMID"; then
		log_test_skip "esp $mode: netdevsim"
		nsim_del
		cleanup_all_ns
		return
	fi
	mdev=$NSIM_DEV
	rif=$(ip netns exec "$NRTR" cat "/sys/class/net/$rdev/ifindex")
	mif=$(ip netns exec "$NMID" cat "/sys/class/net/$mdev/ifindex")
	exec {rfd}<"/run/netns/$NRTR" {mfd}<"/run/netns/$NMID"
	echo "$rfd:$rif $mfd:$mif" > "$NSIM_BUS/link_device"
	exec {rfd}<&- {mfd}<&-

	ip -n "$NRTR" addr add 10.5.0.1/24 dev "$rdev"
	ip -n "$NMID" addr add 10.5.0.2/24 dev "$mdev"
	ip -n "$NRTR" link set "$rdev" up
	ip -n "$NMID" link set "$mdev" up
	ip -n "$NRTR" neigh add 10.5.0.2 dev "$rdev" lladdr \
		"$(ip -n "$NMID" -br link show "$mdev" | awk '{ print $3 }')"
	ip -n "$NRTR" route add "$INNER_DST/32" via 10.5.0.2 dev "$rdev"
	ip netns exec "$NRTR" ethtool -K "$rdev" tso off >/dev/null
	if ! ip -n "$NRTR" xfrm state add src "$src" dst "$dst" \
		proto esp spi 0x100 reqid 1 mode "$mode" \
		aead 'rfc4106(gcm(aes))' "$key" 128 \
		offload dev "$rdev" dir out ||
	   ! ip -n "$NRTR" xfrm policy add dir out \
		src "$INNER_SRC/32" dst "$INNER_DST/32" \
		tmpl src "$src" dst "$dst" proto esp reqid 1 mode "$mode"; then
		log_test_skip "esp $mode: no ESP offload"
		nsim_del
		cleanup_all_ns
		return
	fi

	r0mac=$(ip -n "$NRTR" -br link show r0 | awk '{ print $3 }')
	capture "$NMID" "$mdev" fixed
	t0=$(fwd_packets "$NRTR")
	ip netns exec "$NSRC" "$TX" -T -i s0 -M "$r0mac" -s "$INNER_SRC" \
		-d "$INNER_DST" -n "$SEGS" -b "$BURSTS" -f
	wait "$CAP_PID"
	check "esp $mode offload, fixed inner IDs" "$(tail -n 1 "$RESULT")" \
		fixed "$outer" $(($(fwd_packets "$NRTR") - t0))
	nsim_del
	cleanup_all_ns
}

require_command ethtool
require_command tc
check_gen_prog "$TX"

RESULT=$(mktemp)

for type in ipip gre vxlan; do
	for family in 4 6; do
		run_encap "$type" "$family" fixed
		run_encap "$type" "$family" incr
	done
done
run_decap inner
run_decap outer
for type in ipip gre vxlan; do
	run_encap_decap "$type"
done
for mode in tunnel transport; do
	run_esp "$mode"
done

exit "$EXIT_STATUS"
