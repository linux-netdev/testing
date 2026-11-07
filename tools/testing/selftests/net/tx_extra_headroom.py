#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""Tests for the IFLA_TX_EXTRA_HEADROOM link attribute."""

import socket
from pathlib import Path

from lib.py import ksft_run, ksft_exit, ksft_eq, ksft_raises, KsftSkipEx
from lib.py import ksft_variants, KsftNamedVariant
from lib.py import ip, tc, bpftool, bpf_prog_map_ids
from lib.py import NetNS, NetNSEnter
from lib.py import Netlink, NlError, RtnlFamily

ATTR = "tx-extra-headroom"
MAX = 512
BPF_OBJ = Path(__file__).parent / "tx_extra_headroom.bpf.o"
PORT = 9999  # UDP_TEST_PORT in tx_extra_headroom.bpf.c
PUSH = 20  # PUSH_LEN in tx_extra_headroom.bpf.c


def ifindex(name):
    """Return the ifindex of device name."""
    return ip(f"link show dev {name}", json=True)[0]["ifindex"]


def get(rtnl, idx):
    """Return the IFLA_TX_EXTRA_HEADROOM value of ifindex idx."""
    link = rtnl.getlink({"ifi-index": idx})
    if ATTR not in link:
        raise KsftSkipEx("no IFLA_TX_EXTRA_HEADROOM support")
    return link[ATTR]


def set_hr(rtnl, idx, val):
    """Set IFLA_TX_EXTRA_HEADROOM of ifindex idx to val."""
    get(rtnl, idx)  # an old kernel ignores the attribute
    rtnl.setlink({"ifi-index": idx, ATTR: val})


def test_default_and_set() -> None:
    """Default is 0, values up to the maximum are accepted, 0 resets."""
    with NetNS() as ns, NetNSEnter(str(ns)):
        ip("link add dummy0 type dummy")
        rtnl = RtnlFamily()
        idx = ifindex("dummy0")

        ksft_eq(get(rtnl, idx), 0)
        for val in (1, 256, MAX):
            set_hr(rtnl, idx, val)
            ksft_eq(get(rtnl, idx), val)
            ksft_eq(rtnl.getlink({"ifi-index": idx})["headroom"], 0,
                    "needed_headroom")
        set_hr(rtnl, idx, 0)
        ksft_eq(get(rtnl, idx), 0)


def test_reject_above_max() -> None:
    """Values above the maximum are rejected by the policy."""
    with NetNS() as ns, NetNSEnter(str(ns)):
        ip("link add dummy0 type dummy")
        rtnl = RtnlFamily()
        idx = ifindex("dummy0")

        set_hr(rtnl, idx, 128)
        with ksft_raises(NlError):
            set_hr(rtnl, idx, MAX + 1)
        ksft_eq(get(rtnl, idx), 128)


def test_newlink() -> None:
    """The attribute can be supplied when the link is created."""
    with NetNS() as ns, NetNSEnter(str(ns)):
        rtnl = RtnlFamily()
        rtnl.newlink({"ifname": "dummy0", "linkinfo": {"kind": "dummy"},
                      ATTR: 64},
                     flags=[Netlink.NLM_F_CREATE, Netlink.NLM_F_EXCL])
        ksft_eq(get(rtnl, ifindex("dummy0")), 64)


def test_notification() -> None:
    """A change produces a link notification carrying the new value."""
    with NetNS() as ns, NetNSEnter(str(ns)):
        ip("link add dummy0 type dummy")
        ip("link set dev dummy0 up")
        rtnl = RtnlFamily()
        idx = ifindex("dummy0")

        rtnl.ntf_subscribe("rtnlgrp-link")
        set_hr(rtnl, idx, 192)

        seen = None
        for msg in rtnl.poll_ntf(duration=1):
            if msg["name"] == "getlink" and msg["msg"]["ifi-index"] == idx:
                seen = msg["msg"][ATTR]
                break
        ksft_eq(seen, 192)


def test_survives_down_up() -> None:
    """Toggling the link does not reset the value."""
    with NetNS() as ns, NetNSEnter(str(ns)):
        ip("link add dummy0 type dummy")
        rtnl = RtnlFamily()
        idx = ifindex("dummy0")

        set_hr(rtnl, idx, 96)
        ip("link set dev dummy0 up")
        ksft_eq(get(rtnl, idx), 96)
        ip("link set dev dummy0 down")
        ksft_eq(get(rtnl, idx), 96)


def test_survives_netns_move() -> None:
    """Moving the link to another namespace keeps the value."""
    with NetNS() as ns1, NetNS() as ns2:
        with NetNSEnter(str(ns1)):
            ip("link add dummy0 type dummy")
            rtnl = RtnlFamily()
            set_hr(rtnl, ifindex("dummy0"), 160)
            ip(f"link set dev dummy0 netns {ns2}")

        with NetNSEnter(str(ns2)):
            rtnl = RtnlFamily()
            ksft_eq(get(rtnl, ifindex("dummy0")), 160)


def test_not_inherited() -> None:
    """Stacked devices do not inherit the value of the device below."""
    with NetNS() as ns, NetNSEnter(str(ns)):
        ip("link add dummy0 type dummy")
        rtnl = RtnlFamily()
        set_hr(rtnl, ifindex("dummy0"), 224)

        ip("link add link dummy0 name dummy0.10 type vlan id 10")
        ksft_eq(get(rtnl, ifindex("dummy0.10")), 0)
        ksft_eq(rtnl.getlink({"ifi-index": ifindex("dummy0.10")})["headroom"],
                4, "vlan needed_headroom")


def setup_veth(peer_ns):
    """Create veth0 in the current netns and its peer veth1 in peer_ns."""
    ip("link add veth0 type veth peer name veth1")
    ip(f"link set veth1 netns {peer_ns}")
    ip("addr add 192.0.2.1/24 dev veth0")
    ip("link set veth0 up")
    ip("addr add 192.0.2.2/24 dev veth1", ns=peer_ns)
    ip("link set veth1 up", ns=peer_ns)
    peer_mac = ip("link show dev veth1", json=True, ns=peer_ns)[0]["address"]
    ip(f"neigh replace 192.0.2.2 lladdr {peer_mac} dev veth0 nud permanent")


def load_tc_prog(dev, direction):
    """Attach the tc/<direction> program to dev, return its .bss map id."""
    tc(f"qdisc add dev {dev} clsact")
    tc(f"filter add dev {dev} {direction} bpf da obj {BPF_OBJ} "
       f"sec tc/{direction}")
    filters = tc(f"filter show dev {dev} {direction}", json=True)
    prog_id = next(f["options"]["prog"]["id"] for f in filters
                   if "options" in f)
    return next(map_id for name, map_id in bpf_prog_map_ids(prog_id).items()
                if name.endswith(".bss"))


def read_bss(map_id):
    """Return the global variables of the tc program as a dict."""
    dump = bpftool(f"map dump id {map_id}", json=True)[0]
    return {name: val for var in dump["formatted"]["value"][".bss"]
            for name, val in var.items()}


def send_udp4():
    """Send one UDP packet from veth0 to veth1."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"x", ("192.0.2.2", PORT))


# A local IPv4 UDP packet on veth gets LL_ALLOC_SPACE() =
# ((14 + tx_extra_headroom) & ~15) + 16 bytes of headroom. The Ethernet
# header takes 14 of them. The push reallocates if less than PUSH bytes are
# left.
@ksft_variants([
    KsftNamedVariant("udp4_0", send_udp4, 0, 2),
    KsftNamedVariant("udp4_17", send_udp4, 17, 18),
    KsftNamedVariant("udp4_18", send_udp4, 18, 34),
    KsftNamedVariant("udp4_256", send_udp4, 256, 258),
])
def test_push(send, hr, headroom) -> None:
    """Check the headroom of one packet and whether a push reallocates it."""
    with NetNS() as send_ns, NetNS() as peer_ns, NetNSEnter(str(send_ns)):
        setup_veth(peer_ns)
        set_hr(RtnlFamily(), ifindex("veth0"), hr)
        map_id = load_tc_prog("veth0", "egress")
        send()
        bss = read_bss(map_id)

    ksft_eq(bss["count"], 1, "test packets seen")
    ksft_eq(bss["headroom"], headroom, "headroom before the push")
    ksft_eq(bss["err"], 0, "bpf_skb_adjust_room() return value")
    ksft_eq(bss["reallocated"], headroom < PUSH, "push reallocated the head")


def main() -> None:
    """Run all test cases."""
    ksft_run([test_default_and_set,
              test_reject_above_max,
              test_newlink,
              test_notification,
              test_survives_down_up,
              test_survives_netns_move,
              test_not_inherited,
              test_push])
    ksft_exit()


if __name__ == "__main__":
    main()
