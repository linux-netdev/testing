#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Test net.ipv4.tcp_l3mdev_exempt_ports.
#
# With tcp_l3mdev_accept=1, a listener that is not bound to a device also
# matches connections that arrive in a VRF. For a port listed in
# tcp_l3mdev_exempt_ports it must not: only a listener bound to the VRF
# may take such a connection. Connections in the default VRF are not
# affected.
#
#  ns_c (client in VRF)       ns_s (server)       ns_d (client, default VRF)
#      veth0 ------------- veth_vrf [vrf red]
#                             veth_def ----------------- veth0

# ns_s, ns_c and ns_d are assigned by setup_ns, and the test functions
# are called through ALL_TESTS.
# shellcheck disable=SC2154,SC2329

source lib.sh

PORT=12345
OTHER_PORT=23456
VRF=red
VRF_TABLE=1000

VRF_SRV4=172.16.1.1
VRF_CLI4=172.16.1.2
DEF_SRV4=172.16.2.1
DEF_CLI4=172.16.2.2
VRF_SRV6=2001:db8:1::1
VRF_CLI6=2001:db8:1::2
DEF_SRV6=2001:db8:2::1
DEF_CLI6=2001:db8:2::2

# nettest server exit code when no connection arrives before its timeout
SRV_TIMEOUT=2

ALL_TESTS="
	unbound_listener
	vrf_and_unbound_listeners
	default_vrf_unaffected
"

cleanup()
{
	cleanup_all_ns
}

setup_fail()
{
	echo "FAIL: setup"
	exit "$ksft_fail"
}

setup()
{
	setup_ns ns_s ns_c ns_d || exit "$ksft_skip"

	if ! ip -n "$ns_s" link add "$VRF" type vrf table "$VRF_TABLE"; then
		echo "SKIP: VRF not supported"
		exit "$ksft_skip"
	fi

	if ! ip netns exec "$ns_s" \
	     test -e /proc/sys/net/ipv4/tcp_l3mdev_exempt_ports; then
		echo "SKIP: net.ipv4.tcp_l3mdev_exempt_ports not supported"
		exit "$ksft_skip"
	fi

	ip -n "$ns_s" -batch - <<-EOF || setup_fail
		link set $VRF up
		link add veth_vrf type veth peer name veth0 netns $ns_c
		link set veth_vrf master $VRF
		link set veth_vrf up
		addr add $VRF_SRV4/24 dev veth_vrf
		addr add $VRF_SRV6/64 dev veth_vrf nodad
		link add veth_def type veth peer name veth0 netns $ns_d
		link set veth_def up
		addr add $DEF_SRV4/24 dev veth_def
		addr add $DEF_SRV6/64 dev veth_def nodad
	EOF

	ip -n "$ns_c" -batch - <<-EOF || setup_fail
		link set veth0 up
		addr add $VRF_CLI4/24 dev veth0
		addr add $VRF_CLI6/64 dev veth0 nodad
	EOF

	ip -n "$ns_d" -batch - <<-EOF || setup_fail
		link set veth0 up
		addr add $DEF_CLI4/24 dev veth0
		addr add $DEF_CLI6/64 dev veth0 nodad
	EOF

	ip netns exec "$ns_s" sysctl -wq net.ipv4.tcp_l3mdev_accept=1 ||
		setup_fail
}

set_exempt()
{
	ip netns exec "$ns_s" sysctl -wq net.ipv4.tcp_l3mdev_exempt_ports="$1"
}

# Start a server in the background. nettest sets SO_REUSEPORT on its
# listeners, so an unbound and a VRF-bound listener can share the port.
# $1: IP version, $2: "vrf" or "unbound"
start_server()
{
	local args=()

	[ "$1" = 6 ] && args+=(-6)
	[ "$2" = vrf ] && args+=(-I "$VRF")
	ip netns exec "$ns_s" nettest "${args[@]}" -s -p "$PORT" -t 3 -q &
}

# $1: client netns, $2: IP version, $3: server address
connect()
{
	local args=()

	[ "$2" = 6 ] && args+=(-6)
	ip netns exec "$1" nettest "${args[@]}" -r "$3" -p "$PORT" -t 2 -q
}

listeners_are()
{
	local n

	n=$(ip netns exec "$ns_s" ss -Hltn "sport = :$PORT" | wc -l)
	[ "$n" -eq "$1" ]
}

# $1: number of listeners to wait for on $PORT
wait_listeners()
{
	slowwait 2 listeners_are "$1"
}

# $1: exit code of a server that must not have received a connection
check_timeout()
{
	[ "$1" -eq "$SRV_TIMEOUT" ]
	check_err $? "$2 exited with $1, expected timeout"
}

unbound_listener()
{
	local ver addr pid rc

	for ver in 4 6; do
		addr=$VRF_SRV4
		[ "$ver" = 6 ] && addr=$VRF_SRV6

		RET=0
		set_exempt "$OTHER_PORT"
		start_server "$ver" unbound
		pid=$!
		wait_listeners 1
		check_err $? "listener did not start"
		connect "$ns_c" "$ver" "$addr"
		check_err $? "VRF connection failed"
		wait "$pid"
		check_err $? "unbound listener did not get the connection"
		log_test "IPv$ver: not exempt, unbound listener gets VRF conn"

		RET=0
		set_exempt "$PORT"
		start_server "$ver" unbound
		pid=$!
		wait_listeners 1
		check_err $? "listener did not start"
		connect "$ns_c" "$ver" "$addr"
		check_fail $? "VRF connection succeeded"
		wait "$pid"
		rc=$?
		check_timeout "$rc" "unbound listener"
		log_test "IPv$ver: exempt, unbound listener gets no VRF conn"
	done
	set_exempt ""
}

# Both an unbound and a VRF-bound listener on the port. The VRF connection
# must reach the VRF-bound one, whichever listener was created first.
vrf_and_unbound_listeners()
{
	local ver addr order first second pid_first pid_second
	local rc_first rc_second rc_vrf rc_unbound

	set_exempt "$PORT"
	for ver in 4 6; do
		addr=$VRF_SRV4
		[ "$ver" = 6 ] && addr=$VRF_SRV6

		for order in "unbound vrf" "vrf unbound"; do
			read -r first second <<< "$order"
			RET=0

			start_server "$ver" "$first"
			pid_first=$!
			wait_listeners 1
			check_err $? "first listener did not start"
			start_server "$ver" "$second"
			pid_second=$!
			wait_listeners 2
			check_err $? "second listener did not start"

			connect "$ns_c" "$ver" "$addr"
			check_err $? "VRF connection failed"

			wait "$pid_first"
			rc_first=$?
			wait "$pid_second"
			rc_second=$?
			if [ "$first" = vrf ]; then
				rc_vrf=$rc_first
				rc_unbound=$rc_second
			else
				rc_vrf=$rc_second
				rc_unbound=$rc_first
			fi
			check_err "$rc_vrf" "VRF listener did not get the conn"
			check_timeout "$rc_unbound" "unbound listener"

			log_test "IPv$ver: exempt, $first first, VRF one wins"
		done
	done
	set_exempt ""
}

default_vrf_unaffected()
{
	local ver addr pid

	set_exempt "$PORT"
	for ver in 4 6; do
		addr=$DEF_SRV4
		[ "$ver" = 6 ] && addr=$DEF_SRV6

		RET=0
		start_server "$ver" unbound
		pid=$!
		wait_listeners 1
		check_err $? "listener did not start"
		connect "$ns_d" "$ver" "$addr"
		check_err $? "default VRF connection failed"
		wait "$pid"
		check_err $? "unbound listener did not get the connection"
		log_test "IPv$ver: exempt, unbound listener gets default conn"
	done
	set_exempt ""
}

trap cleanup EXIT

check_gen_prog nettest
setup
tests_run

exit "$EXIT_STATUS"
