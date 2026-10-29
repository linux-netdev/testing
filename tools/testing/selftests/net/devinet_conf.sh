#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source lib.sh

cleanup()
{
	cleanup_all_ns
}

trap cleanup EXIT

prepare_inheritance()
{
	local ns=$1
	local result=$2
	local current
	local probe
	local value

	if ! current=$(ip netns exec "$ns" \
		sysctl -n net.ipv4.conf.lo.arp_ignore); then
		echo "ERROR: failed to read lo/arp_ignore in $ns"
		return "$ksft_fail"
	fi
	if ((current == 0)); then
		probe=1
	else
		probe=0
	fi

	if ! ip netns exec "$ns" sysctl -qw \
		net.ipv4.conf.default.arp_ignore="$probe"; then
		echo "ERROR: failed to update default/arp_ignore in $ns"
		return "$ksft_fail"
	fi
	if ! value=$(ip netns exec "$ns" \
		sysctl -n net.ipv4.conf.lo.arp_ignore); then
		echo "ERROR: failed to read lo/arp_ignore in $ns"
		return "$ksft_fail"
	fi
	if ((value != probe)); then
		echo "SKIP: lo/arp_ignore does not inherit conf/default in $ns"
		return "$ksft_skip"
	fi

	printf -v "$result" '%d' "$probe"
}

# Adding the loopback address marks all devconf settings as explicit.
# Leave it unconfigured so default inheritance remains active.
failed_ns="failed-$(mktemp -u XXXXXX)"
if ! ip netns add "$failed_ns"; then
	echo "Failed to create network namespace $failed_ns"
	exit "$ksft_skip"
fi
NS_LIST+=("$failed_ns")

explicit_ns="explicit-$(mktemp -u XXXXXX)"
if ! ip netns add "$explicit_ns"; then
	echo "Failed to create network namespace $explicit_ns"
	exit "$ksft_skip"
fi
NS_LIST+=("$explicit_ns")

prepare_inheritance "$failed_ns" failed_value
ret=$?
((ret == 0)) || exit "$ret"
prepare_inheritance "$explicit_ns" explicit_value
ret=$?
((ret == 0)) || exit "$ret"
failed_next=$((!failed_value))
explicit_next=$((!explicit_value))

RET=0
ip netns exec "$failed_ns" sh -c \
	'printf x > /proc/sys/net/ipv4/conf/lo/arp_ignore' 2>/dev/null
check_fail $? "invalid arp_ignore write was accepted"
ip netns exec "$failed_ns" sysctl -qw \
	net.ipv4.conf.default.arp_ignore="$failed_next"
check_err $? "failed to update default arp_ignore"
value=$(ip netns exec "$failed_ns" sysctl -n net.ipv4.conf.lo.arp_ignore)
check_err $? "failed to read lo arp_ignore"
check_err "$((value != failed_next))" \
	"failed write prevented lo from inheriting arp_ignore"
log_test "Failed devinet write preserves inheritance"

RET=0
ip netns exec "$explicit_ns" sysctl -qw \
	net.ipv4.conf.lo.arp_ignore="$explicit_value"
check_err $? "failed to explicitly set lo arp_ignore"
ip netns exec "$explicit_ns" sysctl -qw \
	net.ipv4.conf.default.arp_ignore="$explicit_next"
check_err $? "failed to update default arp_ignore"
value=$(ip netns exec "$explicit_ns" sysctl -n net.ipv4.conf.lo.arp_ignore)
check_err $? "failed to read lo arp_ignore"
check_err "$((value != explicit_value))" \
	"explicit lo arp_ignore unexpectedly inherited the default"
log_test "Valid same-value devinet write prevents inheritance"

exit "$EXIT_STATUS"
