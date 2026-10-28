#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Test that IPv6 anycast addresses work. There are two ways to configure IPv6
# anycast addresses: by opening a socket with the IPV6_JOIN_ANYCAST sockopt,
# and automatically joining to the subnet-router anycast address. For simplicity
# we'll use the 2nd method: when forwarding is enabled, the kernel automatically
# joins the subnet-router anycast address (prefix with all host bits zero).

ALL_TESTS="
	test_ipv6_ping_anycast
	test_ipv6_ping_anycast_src
"

source lib.sh

H1_ADDR=2001:db8::1/64
H2_ADDR=2001:db8::2/64
ANYCAST_ADDR="2001:db8::"

# shellcheck disable=SC2329
cleanup()
{
	cleanup_ns $ns1 $ns2
}


setup() {
	setup_ns ns1 ns2
	ip -netns $ns1 link add veth0 type veth peer name veth0 netns $ns2

	ip netns exec $ns1 sysctl -qw net.ipv6.conf.veth0.forwarding=0
	ip netns exec $ns2 sysctl -qw net.ipv6.conf.veth0.forwarding=1
	ip netns exec $ns2 sysctl -qw net.ipv6.icmp.echo_ignore_anycast=0
	ip netns exec $ns2 sysctl -qw net.ipv6.anycast_src_echo_reply=0

	ip -netns $ns1 -6 addr add "$H1_ADDR" dev veth0 nodad
	ip -netns $ns1 link set dev veth0 up
	ip -netns $ns2 -6 addr add "$H2_ADDR" dev veth0 nodad
	ip -netns $ns2 link set dev veth0 up
}

# shellcheck disable=SC2329
test_ipv6_ping_anycast() {
	RET=0
	if ! ip netns exec $ns1 ping -6 -c 3 -w 5 "$ANYCAST_ADDR" &>/dev/null; then
		RET=$ksft_fail
	fi
	log_test "${FUNCNAME[0]}"
}

# shellcheck disable=SC2329
test_ipv6_ping_anycast_src() {
	# Also check that the echo-reply came from saddr=$ANYCAST_ADDR
	RET=0
	ip netns exec $ns2 sysctl -qw net.ipv6.anycast_src_echo_reply=1
	if ! ip netns exec $ns1 ping -6 -c 3 -w 5 "$ANYCAST_ADDR" 2>/dev/null \
	     | grep "$ANYCAST_ADDR:" &>/dev/null; then
		RET=$ksft_fail
	fi
	ip netns exec $ns2 sysctl -qw net.ipv6.anycast_src_echo_reply=0
	log_test "${FUNCNAME[0]}"
}

trap cleanup EXIT
setup
tests_run
exit $EXIT_STATUS
