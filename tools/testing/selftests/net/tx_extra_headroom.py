#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""Tests for tx_extra_headroom."""

import socket
import struct
from pathlib import Path

from lib.py import ksft_run, ksft_exit, ksft_eq, ksft_gt
from lib.py import KsftSkipEx, KsftFailEx
from lib.py import ksft_busy_wait, ksft_variants, KsftNamedVariant
from lib.py import cmd, defer, ip, bpftool, bpf_prog_map_ids
from lib.py import NetNS, NetNSEnter

BPF_OBJ = Path(__file__).parent / "tx_extra_headroom.bpf.o"
XDP_OBJ = Path(__file__).parent / "lib/xdp_dummy.bpf.o"
XDP_HELPER = Path(__file__).parent / "lib/xdp_helper"
PIN_DIR = Path("/sys/fs/bpf/tx_extra_headroom")
PORT = 9999  # UDP_TEST_PORT in tx_extra_headroom.bpf.c
ETH_P_ALL = 0x0003
XDP_PACKET_HEADROOM = 256


def _setup_addrs(peer_ns, dev, peer):
    """Add addresses to dev and to peer in peer_ns, and bring both up."""
    ip(f"addr add 192.0.2.1/24 dev {dev}")
    ip(f"addr add 2001:db8::1/64 dev {dev} nodad")
    ip(f"link set {dev} up")
    ip(f"addr add 192.0.2.2/24 dev {peer}", ns=peer_ns)
    ip(f"addr add 2001:db8::2/64 dev {peer} nodad", ns=peer_ns)
    ip(f"link set {peer} up", ns=peer_ns)
    peer_mac = ip(f"link show dev {peer}", json=True, ns=peer_ns)[0]["address"]
    for addr in ("192.0.2.2", "2001:db8::2"):
        ip(f"neigh replace {addr} lladdr {peer_mac} dev {dev} nud permanent")


def _setup_veth(peer_ns):
    """Create veth0 in the current netns and its peer veth1 in peer_ns."""
    ip("link add veth0 type veth peer name veth1")
    ip(f"link set veth1 netns {peer_ns}")
    _setup_addrs(peer_ns, "veth0", "veth1")


def _attach_xdp(peer_ns, mode="xdpgeneric", dev="veth1"):
    """Attach xdp_dummy to dev in peer_ns."""
    # For a frags program, generic XDP copies into a page_pool page.
    ip(f"link set dev {dev} {mode} obj {XDP_OBJ} sec xdp.frags", ns=peer_ns)


def _load_progs():
    """Load the programs of BPF_OBJ, return the id of their .bss map."""
    cmd(f"rm -rf {PIN_DIR}", shell=True, fail=False)
    bpftool(f"prog loadall {BPF_OBJ} {PIN_DIR}")
    defer(cmd, f"rm -rf {PIN_DIR}", shell=True, fail=False)
    prog_id = bpftool(f"prog show pinned {PIN_DIR}/record", json=True)["id"]
    return next(map_id for name, map_id in bpf_prog_map_ids(prog_id).items()
                if name.endswith(".bss"))


def _attach_tcx(dev, direction, prog):
    """Attach program prog to tcx ingress or egress of dev."""
    bpftool(f"net attach tcx_{direction} pinned {PIN_DIR}/{prog} dev {dev}")


def _read_bss(map_id):
    """Return the global variables of the programs as a dict."""
    dump = bpftool(f"map dump id {map_id}", json=True)[0]
    return {name: val for var in dump["formatted"]["value"][".bss"]
            for name, val in var.items()}


def _send_udp4():
    """Send one UDP packet from veth0 to veth1."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"x", ("192.0.2.2", PORT))


def _send_udp6():
    """Send one UDP packet from veth0 to veth1 over IPv6."""
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
        s.sendto(b"x", ("2001:db8::2", PORT))


def _csum(data):
    """Return the Internet checksum of data."""
    data += b"\0" * (len(data) % 2)
    return 0xffff - sum(struct.unpack(f"!{len(data) // 2}H", data)) % 0xffff


def _ipv4_udp():
    """Return an IPv4 UDP packet from veth0 to veth1."""
    udp = struct.pack("!HHHH", PORT, PORT, 9, 0) + b"x"
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64,
                      socket.IPPROTO_UDP, 0, socket.inet_aton("192.0.2.1"),
                      socket.inet_aton("192.0.2.2"))
    return iph[:10] + struct.pack("!H", _csum(iph)) + iph[12:] + udp


def _ipv6_udp():
    """Return an IPv6 UDP packet from veth0 to veth1."""
    src = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    dst = socket.inet_pton(socket.AF_INET6, "2001:db8::2")
    udp = struct.pack("!HHHH", PORT, PORT, 9, 0) + b"x"
    pseudo = src + dst + struct.pack("!IxxxB", len(udp), socket.IPPROTO_UDP)
    udp = udp[:6] + struct.pack("!H", _csum(pseudo + udp)) + udp[8:]
    return (struct.pack("!IHBB", 6 << 28, len(udp), socket.IPPROTO_UDP, 64) +
            src + dst + udp)


def _eth_frame():
    """Return an Ethernet frame with _ipv4_udp() from veth0 to veth1."""
    src = ip("link show dev veth0", json=True)[0]["address"]
    dst = ip("neigh show 192.0.2.2 dev veth0", json=True)[0]["lladdr"]
    return bytes.fromhex((dst + src).replace(":", "") + "0800") + _ipv4_udp()


def _send_raw4():
    """Send one UDP packet from veth0 to veth1 with an IPv4 raw socket."""
    with socket.socket(socket.AF_INET, socket.SOCK_RAW,
                       socket.IPPROTO_RAW) as s:
        s.sendto(_ipv4_udp(), ("192.0.2.2", 0))


def _send_raw6():
    """Send one UDP packet from veth0 to veth1 with an IPv6 raw socket."""
    with socket.socket(socket.AF_INET6, socket.SOCK_RAW,
                       socket.IPPROTO_RAW) as s:
        s.sendto(_ipv6_udp(), ("2001:db8::2", 0))


def _send_packet():
    """Send one UDP packet from veth0 to veth1 with an AF_PACKET socket."""
    # With protocol 0 the socket receives nothing, so the skb is not cloned.
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as s:
        s.bind(("veth0", 0))
        s.send(_eth_frame())


def _send_xsk():
    """Send one UDP packet from veth0 to veth1 with an AF_XDP socket."""
    xdp = cmd(f"{XDP_HELPER} - -", fail=False)
    if xdp.ret == 255:
        raise KsftSkipEx("AF_XDP unsupported")
    if xdp.ret > 0:
        raise KsftFailEx("unable to create AF_XDP socket")
    ifindex = socket.if_nametoindex("veth0")
    cmd(f"{XDP_HELPER} {ifindex} 0 -t {_eth_frame().hex()}")


@ksft_variants([
    KsftNamedVariant("udp4", _send_udp4),
    KsftNamedVariant("udp6", _send_udp6),
    KsftNamedVariant("raw4", _send_raw4),
    KsftNamedVariant("raw6", _send_raw6),
    KsftNamedVariant("packet", _send_packet),
    KsftNamedVariant("xsk", _send_xsk),
])
def test_peer_xdp(send) -> None:
    """Check that generic XDP on the veth peer does not copy the skb.

    Each sender allocates the skb in a different function.
    """
    with NetNS() as send_ns, NetNS() as peer_ns, NetNSEnter(str(send_ns)):
        _setup_veth(peer_ns)
        map_id = _load_progs()
        _attach_xdp(peer_ns)
        with NetNSEnter(str(peer_ns)):
            _attach_tcx("veth1", "ingress", "record")
        send()
        ksft_busy_wait(lambda: _read_bss(map_id)["count"] == 1)
        bss = _read_bss(map_id)

    ksft_eq(bss["pp_recycle"], False, "generic XDP copied the skb")


def test_peer_xdp_cloned() -> None:
    """Check that pp_recycle is set when generic XDP copies a cloned skb."""
    with NetNS() as send_ns, NetNS() as peer_ns, NetNSEnter(str(send_ns)):
        _setup_veth(peer_ns)
        map_id = _load_progs()
        _attach_xdp(peer_ns)
        with NetNSEnter(str(peer_ns)):
            _attach_tcx("veth1", "ingress", "record")
        # A packet socket for ETH_P_ALL holds a clone of the skb, so generic
        # XDP copies it.
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                           socket.htons(ETH_P_ALL)) as s:
            s.bind(("veth0", 0))
            _send_udp4()
            ksft_busy_wait(lambda: _read_bss(map_id)["count"] == 1)
        bss = _read_bss(map_id)

    ksft_eq(bss["pp_recycle"], True, "generic XDP did not copy the skb")


def test_peer_xdp_netkit() -> None:
    """Check that generic XDP on the netkit peer does not copy the skb."""
    with NetNS() as send_ns, NetNS() as peer_ns, NetNSEnter(str(send_ns)):
        # L2 mode has MAC addresses and ARP, as on veth.
        ip(f"link add nk0 type netkit mode l2 peer name nk1 netns {peer_ns}")
        _setup_addrs(peer_ns, "nk0", "nk1")
        map_id = _load_progs()
        _attach_xdp(peer_ns, dev="nk1")
        with NetNSEnter(str(peer_ns)):
            _attach_tcx("nk1", "ingress", "record")
        _send_udp4()
        ksft_busy_wait(lambda: _read_bss(map_id)["count"] == 1)
        bss = _read_bss(map_id)

    ksft_eq(bss["pp_recycle"], False, "generic XDP copied the skb")


@ksft_variants([
    KsftNamedVariant("generic", "xdpgeneric"),
    KsftNamedVariant("native", "xdpdrv"),
])
def test_detach(mode) -> None:
    """Check that XDP on the veth peer sets tx_extra_headroom until detach."""
    with NetNS() as send_ns, NetNS() as peer_ns, NetNSEnter(str(send_ns)):
        _setup_veth(peer_ns)
        map_id = _load_progs()
        _attach_tcx("veth0", "egress", "record")
        _attach_xdp(peer_ns, mode)
        _send_udp4()
        ksft_eq(_read_bss(map_id)["tx_extra_headroom"], XDP_PACKET_HEADROOM)
        ip(f"link set dev veth1 {mode} off", ns=peer_ns)
        _send_udp4()
        ksft_eq(_read_bss(map_id)["tx_extra_headroom"], 0)


def test_bond() -> None:
    """Check that XDP that a bond propagates to the veth peer counts."""
    with NetNS() as send_ns, NetNS() as peer_ns, NetNSEnter(str(send_ns)):
        _setup_veth(peer_ns)
        map_id = _load_progs()
        _attach_tcx("veth0", "egress", "record")
        ip("link add bond0 type bond mode balance-rr", ns=peer_ns)
        # A bond only enslaves a device that is down.
        ip("link set dev veth1 down", ns=peer_ns)
        ip("link set dev veth1 master bond0", ns=peer_ns)
        _attach_xdp(peer_ns, "xdpdrv", "bond0")
        _send_udp4()
        ksft_eq(_read_bss(map_id)["tx_extra_headroom"], XDP_PACKET_HEADROOM)
        ip("link set dev bond0 xdpdrv off", ns=peer_ns)
        _send_udp4()
        ksft_eq(_read_bss(map_id)["tx_extra_headroom"], 0)


def test_bridge_vxlan() -> None:
    """Check that needed_headroom counts toward the headroom for XDP."""
    with NetNS() as send_ns, NetNS() as peer_ns, NetNSEnter(str(send_ns)):
        _setup_veth(peer_ns)
        map_id = _load_progs()
        _attach_tcx("veth0", "egress", "record")
        ip("link add br0 type bridge", ns=peer_ns)
        ip("link set dev veth1 master br0", ns=peer_ns)
        # The bridge raises needed_headroom of veth1, and of veth0 with it.
        ip("link add vxlan0 type vxlan id 1 dstport 4789", ns=peer_ns)
        ip("link set dev vxlan0 master br0", ns=peer_ns)
        # tx_extra_headroom is not recalculated when needed_headroom
        # changes, so attach XDP after the vxlan port.
        _attach_xdp(peer_ns)
        _send_udp4()
        bss = _read_bss(map_id)

    ksft_gt(bss["needed_headroom"], 0,
            "vxlan port did not raise needed_headroom")
    ksft_eq(bss["needed_headroom"] + bss["tx_extra_headroom"],
            XDP_PACKET_HEADROOM)


def main() -> None:
    """Run all test cases."""
    ksft_run([test_peer_xdp,
              test_peer_xdp_cloned,
              test_peer_xdp_netkit,
              test_detach,
              test_bond,
              test_bridge_vxlan])
    ksft_exit()


if __name__ == "__main__":
    main()
