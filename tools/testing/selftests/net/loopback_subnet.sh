#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# Test loopback subnets (a.k.a. AnyIP). The topology is a client and a server,
# with the server having a loopback subnet. Test permutations of the following
# variations:
# - ipv4 / ipv6
# - ping from client / localhost ping from the server itself
# - loopback subnet in the local table / loopback subnet in other table
#
#                           ns_srv | ns_cli
# ---------------------------------|--------------
#     [ lo ]            [ eth0 ]---|---[ eth0 ]
# LO_SUBNET(route)     SRV_IFADDR  |  CLI_IFADDR

# shellcheck disable=SC2329

ALL_TESTS="
        test_loopback_subnet_from_localhost_ipv4
        test_loopback_subnet_from_localhost_ipv6
        test_loopback_subnet_from_remote_ipv4
        test_loopback_subnet_from_remote_ipv6
        test_loopback_subnet_from_localhost_ipv4_table
        test_loopback_subnet_from_localhost_ipv6_table
        test_loopback_subnet_from_remote_ipv4_table
        test_loopback_subnet_from_remote_ipv6_table
"

source "lib.sh"

LO_SUBNET4=192.168.88.0/24
LO_ADDR4=192.168.88.14    # Just any address in LO_SUBNET4
LO_SUBNET6=2001:db8:88::/64
LO_ADDR6=2001:db8:88::54  # Just any address in LO_SUBNET6
SRV_IFADDR4=192.168.99.1
SRV_IFADDR6=2001:db8:99::1
CLI_IFADDR4=192.168.99.2
CLI_IFADDR6=2001:db8:99::2
RT_TABLE=200

cleanup() {
	cleanup_ns $ns_srv $ns_cli
}

setup() {
        setup_ns ns_srv ns_cli
        ip -n $ns_srv link add eth0 netns $ns_cli type veth peer eth0

        ip -n $ns_srv link set eth0 up
        ip -n $ns_srv link set lo up
        ip -n $ns_srv addr add "$SRV_IFADDR4/24" dev eth0
        ip -n $ns_srv addr add "$SRV_IFADDR6/64" dev eth0 nodad

        ip -n $ns_cli link set eth0 up
        ip -n $ns_cli addr add "$CLI_IFADDR4/24" dev eth0
        ip -n $ns_cli addr add "$CLI_IFADDR6/64" dev eth0 nodad
        ip -n $ns_cli route add "$LO_SUBNET4" via "$SRV_IFADDR4"
        ip -n $ns_cli route add "$LO_SUBNET6" via "$SRV_IFADDR6"
}

setup_loopback_subnets() {
        local rt_table="${1:-local}"

        ip -n $ns_srv route add local "$LO_SUBNET4" dev lo table "$rt_table"
        ip -n $ns_srv route add local "$LO_SUBNET6" dev lo table "$rt_table"
        if [[ $rt_table != local && $rt_table != 255 ]]; then
                ip -n $ns_srv rule add from all lookup "$rt_table"
        fi
}

cleanup_loopback_subnets() {
        local rt_table="${1:-local}"

        ip -n $ns_srv route del local "$LO_SUBNET4" dev lo table "$rt_table"
        ip -n $ns_srv route del local "$LO_SUBNET6" dev lo table "$rt_table"
        if [[ $rt_table != local && $rt_table != 255 ]]; then
                ip -n $ns_srv rule del from all lookup "$rt_table"
        fi
}

run_test() {
        local test_name="$1"
        local ns="$2"
        local ping_addr="$3"
        local rt_table="$4"

        RET=0
        setup_loopback_subnets "$rt_table"
        if ! ip netns exec "$ns" ping -c 3 "$ping_addr" &>/dev/null; then
                if [[ $FAIL_TO_XFAIL = yes ]]; then
                        RET=$ksft_xfail
                else
                        RET=$ksft_fail
                fi
        fi
        cleanup_loopback_subnets "$rt_table"
        log_test "$test_name"
}

test_loopback_subnet_from_localhost_ipv4() {
        run_test "${FUNCNAME[0]}" "$ns_srv" "$LO_ADDR4"
}

test_loopback_subnet_from_localhost_ipv6() {
        run_test "${FUNCNAME[0]}" "$ns_srv" "$LO_ADDR6"
}

test_loopback_subnet_from_remote_ipv4() {
        run_test "${FUNCNAME[0]}" "$ns_cli" "$LO_ADDR4"
}

test_loopback_subnet_from_remote_ipv6() {
        run_test "${FUNCNAME[0]}" "$ns_cli" "$LO_ADDR6"
}

test_loopback_subnet_from_localhost_ipv4_table() {
        xfail run_test "${FUNCNAME[0]}" "$ns_srv" "$LO_ADDR4" "$RT_TABLE"
}

test_loopback_subnet_from_localhost_ipv6_table() {
        xfail run_test "${FUNCNAME[0]}" "$ns_srv" "$LO_ADDR6" "$RT_TABLE"
}

test_loopback_subnet_from_remote_ipv4_table() {
        xfail run_test "${FUNCNAME[0]}" "$ns_cli" "$LO_ADDR4" "$RT_TABLE"
}

test_loopback_subnet_from_remote_ipv6_table() {
        xfail run_test "${FUNCNAME[0]}" "$ns_cli" "$LO_ADDR6" "$RT_TABLE"
}

trap cleanup EXIT
setup
tests_run
exit $EXIT_STATUS
