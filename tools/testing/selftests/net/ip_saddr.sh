#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# Test the correct behaviour with outgoing packets regarding the source address.
# RFC 4862: an invalid address MUST NOT be used as the source address of
# outbound packets.
# However, with the TRANSPARENT and HDRINCL sockopts, any saddr is allowed.
#
# There are 2 kind of tests, all server & client in different namespaces:
# - TCP / UDP:
#    1. The client establish a connection with the server
#    2. The server address is removed/invalidated
#    3. The server tries to send a message to the client
# - HDRINCL (using raw socket):
#    1. The server start listening
#    2. The client address is removed/invalidated
#    3. The client tries to send a message to the server
#
# The expectation is that the message is not received by the peer, except when
# using TRANSPARENT or HDRINCL where we expect to receive it.
#
# Test the following permutations:
# - IPv4 / IPv6
# - TCP / UDP / raw-with-HDRINCL
# - For TCP & UDP: normal socket / TRANSPARENT socket
# - One of the following address invalidation actions:
#     - Don't invalidate (keep the address configured). In this case we expect
#       to always receive the message.
#     - Manually delete the address.
#     - Leave the address to expire its valid_lft.
#     - Use a foreign address (an address that it's not configured on the host).
#       This one can't be tested with TCP, the connection cannot be established.
#
# Important: we have a secondary address on the same network configured all the
# time in both the client and the server. We do this because, otherwise, the
# kernel doesn't know a route when we invalidate/remove the main address. If it
# failed because of this, we wouldn't be testing the validation of the source
# address, which is this file's goal

# shellcheck disable=SC2329

ALL_TESTS="
        test_keep_addr_ipv4_tcp_normal
        test_keep_addr_ipv4_udp_normal
        test_keep_addr_ipv6_tcp_normal
        test_keep_addr_ipv6_udp_normal
        test_keep_addr_ipv4_tcp_transparent
        test_keep_addr_ipv4_udp_transparent
        test_keep_addr_ipv6_tcp_transparent
        test_keep_addr_ipv6_udp_transparent
        test_keep_addr_ipv4_hdrincl
        test_keep_addr_ipv6_hdrincl
        test_remove_addr_ipv4_tcp_normal
        test_remove_addr_ipv4_udp_normal
        test_remove_addr_ipv6_tcp_normal
        test_remove_addr_ipv6_udp_normal
        test_remove_addr_ipv4_tcp_transparent
        test_remove_addr_ipv4_udp_transparent
        test_remove_addr_ipv6_tcp_transparent
        test_remove_addr_ipv6_udp_transparent
        test_remove_addr_ipv4_hdrincl
        test_remove_addr_ipv6_hdrincl
        test_expire_addr_ipv4_tcp_normal
        test_expire_addr_ipv4_udp_normal
        test_expire_addr_ipv6_tcp_normal
        test_expire_addr_ipv6_udp_normal
        test_expire_addr_ipv4_tcp_transparent
        test_expire_addr_ipv4_udp_transparent
        test_expire_addr_ipv6_tcp_transparent
        test_expire_addr_ipv6_udp_transparent
        test_expire_addr_ipv4_hdrincl
        test_expire_addr_ipv6_hdrincl
        test_foreign_addr_ipv4_udp_normal
        test_foreign_addr_ipv6_udp_normal
        test_foreign_addr_ipv4_udp_transparent
        test_foreign_addr_ipv6_udp_transparent
        test_foreign_addr_ipv4_hdrincl
        test_foreign_addr_ipv6_hdrincl
"

source lib.sh

SRV_ADDR4=172.16.1.1/16
SRV_ADDR6=2001:db8:1::1/64
CLI_ADDR4=172.16.1.2/16
CLI_ADDR6=2001:db8:1::2/64
SENDER_ADDR4=172.16.1.3/16
SENDER_ADDR6=2001:db8:1::3/64
FOREIGN_ADDR4=172.16.1.4/16
FOREIGN_ADDR6=2001:db8:1::4/64
PORT=12345

##########################
# Global setup & cleanup
##########################

cleanup() {
	cleanup_ns "$ns_srv" "$ns_cli"
	rm -rf "$SRV_SYNC_DIR"
}

setup() {
	setup_ns ns_srv ns_cli
	ip -n $ns_srv link add eth0 netns $ns_cli type veth peer eth0

	ip -n $ns_cli link set lo up
	ip -n $ns_cli link set eth0 up
	ip -n $ns_cli addr add "$CLI_ADDR4" dev eth0
	ip -n $ns_cli addr add "$CLI_ADDR6" dev eth0 nodad

	ip -n $ns_srv link set lo up
	ip -n $ns_srv link set eth0 up
	ip -n $ns_srv addr add "$SRV_ADDR4" dev eth0
	ip -n $ns_srv addr add "$SRV_ADDR6" dev eth0 nodad

	SRV_SYNC_DIR="$(mktemp -d)"
	SRV_SYNC_FILE="$SRV_SYNC_DIR/sync_fifo"
	mkfifo "$SRV_SYNC_FILE"
}

#################################
# Tests setup, cleanup & helpers
#################################

setup_test_tcp_udp() {
	local ipvx="$1"
	local proto="$2"
	local sock_type="$3"
	local sync_file="$4"
	local nodad addr_args
	CLOSE_FD3=
	RET=0

	if [ "$sock_type" = "hdrincl" ]; then
		RET=$ksft_fail
		return 1
	fi

	shift 4
	[ "$ipvx" = "ipv6" ] && nodad="nodad"
	[ "$#" -gt 0 ] && addr_args="$*"

	if [ "$ipvx" = "ipv6" ]; then
		SENDER_ADDR="$SENDER_ADDR6"
		FOREIGN_ADDR="$FOREIGN_ADDR6"
	elif [ "$ipvx" = "ipv4" ]; then
		SENDER_ADDR="$SENDER_ADDR4"
		FOREIGN_ADDR="$FOREIGN_ADDR4"
	else
		RET=$ksft_fail
		return 1
	fi

	# start the C helper server and wait until it's listening
	ip netns exec $ns_srv \
		./ip_saddr "$ipvx" "$proto" "$PORT" "$sock_type" "$sync_file" &
	SRV_PID=$!
	wait_local_port_listen "$ns_srv" "$PORT" "$proto"

	# the message is sent from the server, configure SENDER_ADDR on it
	ip -n $ns_srv addr add "$SENDER_ADDR" dev eth0 $nodad $addr_args
}

setup_test_hdrincl() {
	local ipvx="$1"
	local sock_type="$2"
	local nodad addr_args
	RET=0

	if [ "$sock_type" != "hdrincl" ]; then
		RET=$ksft_fail
		return 1
	fi

	shift 2
	[ "$ipvx" = "ipv6" ] && nodad="nodad"
	[ "$#" -gt 0 ] && addr_args="$*"

	if [ "$ipvx" = "ipv6" ]; then
		SENDER_ADDR="$SENDER_ADDR6"
		FOREIGN_ADDR="$FOREIGN_ADDR6"
		SRV_ADDR="$SRV_ADDR6"
	elif [ "$ipvx" = "ipv4" ]; then
		SENDER_ADDR="$SENDER_ADDR4"
		FOREIGN_ADDR="$FOREIGN_ADDR4"
		SRV_ADDR="$SRV_ADDR4"
	else
		RET=$ksft_fail
		return 1
	fi

	# the message is sent from the client, configure SENDER_ADDR on it
	ip -n $ns_cli addr add "$SENDER_ADDR" dev eth0 $nodad $addr_args

	# start the C helper server and wait until it's listening
	exec 3< <(exec ip netns exec $ns_srv ./ip_saddr "$ipvx" "raw")
	SRV_PID=$!
	CLOSE_FD3=yes
	wait_raw_sock_listen_any_addr "$ipvx" "$ns_srv"
}

set_test_result() {
	local sock_type="$1"
	local normal_expect_empty="$2"
	local srv_msg="$3"

	if [ "$normal_expect_empty" = "yes" ] && [ "$sock_type" = "normal" ]
        then
		[ "$srv_msg" != "" ] && RET=$ksft_fail
	else
		[ "$srv_msg" = "" ] && RET=$ksft_fail
	fi
}

cleanup_test() {
	kill "$SRV_PID" &>/dev/null
	wait "$SRV_PID"
	ip -n $ns_srv addr del "$SENDER_ADDR" dev eth0 &>/dev/null
	ip -n $ns_cli addr del "$SENDER_ADDR" dev eth0 &>/dev/null
	[ "$CLOSE_FD3" = "yes" ] && exec 3<&-
}

wait_raw_sock_listen_any_addr() {
	local ipvx="$1"
	local ns="$2"
	local ptrn proto found i

	if [ "$ipvx" = "ipv4" ]; then
		ptrn='^00000000:'
		proto=raw
	elif [ "$ipvx" = "ipv6" ]; then
		ptrn='^00000000000000000000000000000000:'
		proto=raw6
	else
		RET=$ksft_fail
		return 1
	fi
	for i in $(seq 10); do
		found="$(ip netns exec "$ns" cat "/proc/net/$proto" | \
			awk -vptrn="$ptrn" '$2 ~ ptrn {print "yes"}')"
		[ "$found" = "yes" ] && return 0
		sleep 0.1
	done
	RET=$ksft_fail
	return 1
}

wait_addr_missing() {
	local ns="$1"
	local iface="$2"
	local addr="$3"
	local timeout="${4:-1}"

	for i in $(seq $((timeout * 10))); do
		ip -n "$ns" -br a show dev "$iface" | grep -q "$addr" || return 0
		sleep 0.1
	done
	RET=$ksft_fail
	return 1
}

##########################
# Test cases
##########################

# Open a TCP/UDP connection and wait for a message from the server. The address
# is still configured, so the expectation is to always receive the message.
test_keep_addr_tcp_udp() {
	local test_name="$1"
	local ipvx="$2"
	local proto="$3"
	local sock_type="$4"
	local srv_msg

	setup_test_tcp_udp "$ipvx" "$proto" "$sock_type" ""
	srv_msg="$(ip netns exec $ns_cli bash -c "
                        exec 3<>'/dev/$proto/${SENDER_ADDR%/*}/$PORT'
                        [ '$proto' = 'udp' ] && echo 'x' >&3
                        timeout 2s cat <&3
                        exec 3<&-
                ")"
	set_test_result "$sock_type" "no" "$srv_msg"
	cleanup_test
	log_test "$test_name"
}

# Send a message to the server through a raw socket with HDRINCL.
test_keep_addr_hdrincl() {
	local test_name="$1"
	local ipvx="$2"
	local srv_msg

	setup_test_hdrincl "$ipvx" "hdrincl"
	ip netns exec $ns_cli \
		./ip_saddr "$ipvx" "raw" "${SENDER_ADDR%/*}" "${SRV_ADDR%/*}"
	srv_msg="$(timeout 2s cat <&3)"
	set_test_result "hdrincl" "" "$srv_msg"
	cleanup_test
	log_test "$test_name"
}

# Open a TCP/UDP connection to the server, remove the address from the server
# and wait for a message from it. As the address is no longer present, the
# expectation is not to receive the message, except for transparent sockets.
test_remove_addr_tcp_udp() {
	local test_name="$1"
	local ipvx="$2"
	local proto="$3"
	local sock_type="$4"
	local srv_msg

	setup_test_tcp_udp "$ipvx" "$proto" "$sock_type" "$SRV_SYNC_FILE"
	srv_msg="$(ip netns exec $ns_cli bash -c "
                        exec 3<>'/dev/$proto/${SENDER_ADDR%/*}/$PORT'
                        [ '$proto' = 'udp' ] && echo 'x' >&3
                        ip -n $ns_srv addr del '$SENDER_ADDR' dev eth0
                        wait_addr_missing '$ns_srv' eth0 '$SENDER_ADDR'
                        echo 'x' > '$SRV_SYNC_FILE'
                        timeout 2s cat <&3
                        exec 3<&-
                ")"
	set_test_result "$sock_type" "yes" "$srv_msg"
	cleanup_test
	log_test "$test_name"
}

# Start listening by the server, remove the address from the client and send a
# message to the server through a raw socket with HDRINCL. Because of the
# HDRINCL, the expectation is to receive the message despite the removed address
test_remove_addr_hdrincl() {
	local test_name="$1"
	local ipvx="$2"
	local srv_msg

	setup_test_hdrincl "$ipvx" "hdrincl"
	ip -n $ns_cli addr del "$SENDER_ADDR" dev eth0
	wait_addr_missing "$ns_cli" eth0 "$SENDER_ADDR"
	ip netns exec $ns_cli \
		./ip_saddr "$ipvx" "raw" "${SENDER_ADDR%/*}" "${SRV_ADDR%/*}"
	srv_msg="$(timeout 2s cat <&3)"
	set_test_result "hdrincl" "" "$srv_msg"
	cleanup_test
	log_test "$test_name"
}

# Open a TCP/UDP connection to the server, wait until its address expires and
# wait for a message from it. As the address is no longer present, the
# expectation is not to receive the message, except for transparent sockets.
test_expire_addr_tcp_udp() {
	local test_name="$1"
	local ipvx="$2"
	local proto="$3"
	local sock_type="$4"
	local srv_msg

	setup_test_tcp_udp "$ipvx" "$proto" "$sock_type" "$SRV_SYNC_FILE" preferred_lft 1 valid_lft 1
	srv_msg="$(ip netns exec $ns_cli bash -c "
                        exec 3<>'/dev/$proto/${SENDER_ADDR%/*}/$PORT'
                        [ '$proto' = 'udp' ] && echo 'x' >&3
                        wait_addr_missing '$ns_srv' eth0 '$SENDER_ADDR' 5
                        echo 'x' > '$SRV_SYNC_FILE'
                        timeout 2s cat <&3
                        exec 3<&-
                ")"
	set_test_result "$sock_type" "yes" "$srv_msg"
	cleanup_test
	log_test "$test_name"
}

# Start listening by the server, wait until the client's address expires and
# send a message to the server through a raw socket with HDRINCL. Because of the
# HDRINCL, the expectation is to receive the message despite the expired address
test_expire_addr_hdrincl() {
	local test_name="$1"
	local ipvx="$2"
	local srv_msg

	setup_test_hdrincl "$ipvx" "hdrincl" preferred_lft 1 valid_lft 1
	wait_addr_missing "$ns_cli" eth0 "$SENDER_ADDR" 5
	ip netns exec $ns_cli \
		./ip_saddr "$ipvx" "raw" "${SENDER_ADDR%/*}" "${SRV_ADDR%/*}"
	srv_msg="$(timeout 2s cat <&3)"
	set_test_result "hdrincl" "" "$srv_msg"
	cleanup_test
	log_test "$test_name"
}

# Try to receive an UDP message from the server using a non-existent source
# address. The expectation is not to receive the message except with transparent
# sockets. This cannot be tested with TCP because the incoming packets are
# dropped, so the TCP connection cannot be established.
test_foreign_addr_udp() {
	local test_name="$1"
	local ipvx="$2"
	local sock_type="$3"
	local srv_msg

	setup_test_tcp_udp "$ipvx" "udp" "$sock_type" ""
	srv_msg="$(ip netns exec $ns_cli bash -c "
                        exec 3<>'/dev/udp/${FOREIGN_ADDR%/*}/$PORT'
                        cli_port=\"\$(ss -uanp | grep \"pid=\$BASHPID,fd=3\" | awk '{print \$4}' | sed 's/.*://')\"
                        echo \"${FOREIGN_ADDR%/*} \$cli_port\" >/dev/udp/${SENDER_ADDR%/*}/$PORT
                        timeout 2s cat <&3
                        exec 3<&-
                ")"
	set_test_result "$sock_type" "yes" "$srv_msg"
	cleanup_test
	log_test "$test_name"
}

# Send a message to the server through a raw socket with HDRINCL. As the socket
# is configured as HDRINCL, the expectation is to receive the message.
test_foreign_addr_hdrincl() {
	local test_name="$1"
	local ipvx="$2"
	local srv_msg

	setup_test_hdrincl "$ipvx" "hdrincl"
	ip netns exec $ns_cli \
		./ip_saddr "$ipvx" "raw" "${FOREIGN_ADDR%/*}" "${SRV_ADDR%/*}"
	srv_msg="$(timeout 2s cat <&3)"
	set_test_result "hdrincl" "" "$srv_msg"
	cleanup_test
	log_test "$test_name"
}

test_keep_addr_ipv4_tcp_normal() {
	test_keep_addr_tcp_udp "${FUNCNAME[0]}" ipv4 tcp normal
}

test_keep_addr_ipv4_udp_normal() {
	test_keep_addr_tcp_udp "${FUNCNAME[0]}" ipv4 udp normal
}

test_keep_addr_ipv6_tcp_normal() {
	test_keep_addr_tcp_udp "${FUNCNAME[0]}" ipv6 tcp normal
}

test_keep_addr_ipv6_udp_normal() {
	test_keep_addr_tcp_udp "${FUNCNAME[0]}" ipv6 udp normal
}

test_keep_addr_ipv4_tcp_transparent() {
	test_keep_addr_tcp_udp "${FUNCNAME[0]}" ipv4 tcp transparent
}

test_keep_addr_ipv4_udp_transparent() {
	test_keep_addr_tcp_udp "${FUNCNAME[0]}" ipv4 udp transparent
}

test_keep_addr_ipv6_tcp_transparent() {
	test_keep_addr_tcp_udp "${FUNCNAME[0]}" ipv6 tcp transparent
}

test_keep_addr_ipv6_udp_transparent() {
	test_keep_addr_tcp_udp "${FUNCNAME[0]}" ipv6 udp transparent
}

test_keep_addr_ipv4_hdrincl() {
	test_keep_addr_hdrincl "${FUNCNAME[0]}" ipv4
}

test_keep_addr_ipv6_hdrincl() {
	test_keep_addr_hdrincl "${FUNCNAME[0]}" ipv6
}

test_remove_addr_ipv4_tcp_normal() {
	test_remove_addr_tcp_udp "${FUNCNAME[0]}" ipv4 tcp normal
}

test_remove_addr_ipv4_udp_normal() {
	test_remove_addr_tcp_udp "${FUNCNAME[0]}" ipv4 udp normal
}

test_remove_addr_ipv6_tcp_normal() {
	test_remove_addr_tcp_udp "${FUNCNAME[0]}" ipv6 tcp normal
}

test_remove_addr_ipv6_udp_normal() {
	test_remove_addr_tcp_udp "${FUNCNAME[0]}" ipv6 udp normal
}

test_remove_addr_ipv4_tcp_transparent() {
	test_remove_addr_tcp_udp "${FUNCNAME[0]}" ipv4 tcp transparent
}

test_remove_addr_ipv4_udp_transparent() {
	test_remove_addr_tcp_udp "${FUNCNAME[0]}" ipv4 udp transparent
}

test_remove_addr_ipv6_tcp_transparent() {
	test_remove_addr_tcp_udp "${FUNCNAME[0]}" ipv6 tcp transparent
}

test_remove_addr_ipv6_udp_transparent() {
	test_remove_addr_tcp_udp "${FUNCNAME[0]}" ipv6 udp transparent
}

test_remove_addr_ipv4_hdrincl() {
	test_remove_addr_hdrincl "${FUNCNAME[0]}" ipv4
}

test_remove_addr_ipv6_hdrincl() {
	test_remove_addr_hdrincl "${FUNCNAME[0]}" ipv6
}

test_expire_addr_ipv4_tcp_normal() {
	test_expire_addr_tcp_udp "${FUNCNAME[0]}" ipv4 tcp normal
}

test_expire_addr_ipv4_udp_normal() {
	test_expire_addr_tcp_udp "${FUNCNAME[0]}" ipv4 udp normal
}

test_expire_addr_ipv6_tcp_normal() {
	test_expire_addr_tcp_udp "${FUNCNAME[0]}" ipv6 tcp normal
}

test_expire_addr_ipv6_udp_normal() {
	test_expire_addr_tcp_udp "${FUNCNAME[0]}" ipv6 udp normal
}

test_expire_addr_ipv4_tcp_transparent() {
	test_expire_addr_tcp_udp "${FUNCNAME[0]}" ipv4 tcp transparent
}

test_expire_addr_ipv4_udp_transparent() {
	test_expire_addr_tcp_udp "${FUNCNAME[0]}" ipv4 udp transparent
}

test_expire_addr_ipv6_tcp_transparent() {
	test_expire_addr_tcp_udp "${FUNCNAME[0]}" ipv6 tcp transparent
}

test_expire_addr_ipv6_udp_transparent() {
	test_expire_addr_tcp_udp "${FUNCNAME[0]}" ipv6 udp transparent
}

test_expire_addr_ipv4_hdrincl() {
	test_expire_addr_hdrincl "${FUNCNAME[0]}" ipv4
}

test_expire_addr_ipv6_hdrincl() {
	test_expire_addr_hdrincl "${FUNCNAME[0]}" ipv6
}

test_foreign_addr_ipv4_udp_normal() {
	test_foreign_addr_udp "${FUNCNAME[0]}" ipv4 normal
}

test_foreign_addr_ipv6_udp_normal() {
	test_foreign_addr_udp "${FUNCNAME[0]}" ipv6 normal
}

test_foreign_addr_ipv4_udp_transparent() {
	test_foreign_addr_udp "${FUNCNAME[0]}" ipv4 transparent
}

test_foreign_addr_ipv6_udp_transparent() {
	test_foreign_addr_udp "${FUNCNAME[0]}" ipv6 transparent
}

test_foreign_addr_ipv4_hdrincl() {
	test_foreign_addr_hdrincl "${FUNCNAME[0]}" ipv4
}

test_foreign_addr_ipv6_hdrincl() {
	test_foreign_addr_hdrincl "${FUNCNAME[0]}" ipv6
}

export -f wait_addr_missing
trap cleanup EXIT
setup
tests_run
exit $EXIT_STATUS
