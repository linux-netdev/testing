#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Re-owning an already dormant PERSIST table used to call
# nf_tables_table_disable() from nf_tables_commit(), which unregistered a
# basechain hook that was never registered and triggered
# WARN_ONCE("hook not found") in __nf_unregister_net_hook().
#
# The WARN taints the kernel, so this test checks the taint state instead
# of parsing dmesg.

source "$(dirname "$0")/lib.sh"

checktool "nft --version" "run nft"

if [ "$(id -u)" -ne 0 ]; then
	echo "SKIP: root is required to create an owner table"
	exit $ksft_skip
fi

read t < /proc/sys/kernel/tainted
if [ "$t" -ne 0 ]; then
	echo "SKIP: kernel is already tainted"
	exit $ksft_skip
fi

cleanup()
{
	nft delete table ip nft_dormant_rt 2>/dev/null || true
}
trap cleanup EXIT

nft delete table ip nft_dormant_rt 2>/dev/null || true

# The nft process exits after this command, leaving a dormant PERSIST
# orphan table behind.
if ! nft add table ip nft_dormant_rt '{ flags dormant,persist,owner; }'; then
	echo "SKIP: nft does not support table owner/persist flags"
	exit $ksft_skip
fi

# A basechain added while the table is dormant does not register its hook.
nft add chain ip nft_dormant_rt c '{ type filter hook output priority 0; }' || exit 1

# Re-own the orphan with DORMANT still set.  On the buggy tree this calls
# nf_tables_table_disable() and unregisters the never-registered hook.
nft add table ip nft_dormant_rt '{ flags dormant,persist,owner; }' || exit 1

read t < /proc/sys/kernel/tainted
if [ "$t" -ne 0 ]; then
	echo "FAIL: re-owning an already dormant table tainted the kernel"
	dmesg | tail -n 20
	exit 1
fi

echo "PASS"
exit 0
