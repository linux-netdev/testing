#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""NETLINK_ROUTE live-switch semantics; no tracing dependency."""
import contextlib
import ctypes
import errno
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import threading
import time
import argparse
import tempfile
import shutil
import sys

p = argparse.ArgumentParser()
p.add_argument('--output', type=Path)
a = p.parse_args()
if os.geteuid() != 0 or not shutil.which('ip') or not hasattr(os, 'setns'):
    print('1..0 # SKIP requires root, iproute2 and Python os.setns')
    sys.exit(4)
control = Path('/proc/sys/net/core/netlink_route_mc_index')
if not control.exists():
    print('1..0 # SKIP kernel has no netlink_route_mc_index sysctl')
    sys.exit(4)
root = a.output or Path(tempfile.mkdtemp(prefix='netlink-switch-'))
if a.output:
    root.mkdir(exist_ok=False, parents=True)
saved_mode = control.read_text()
print('TAP version 13', flush=True)
original = os.open("/proc/self/ns/net", os.O_RDONLY)
# Probe namespace creation before beginning behavioural assertions.
probe_lib = ctypes.CDLL(None, use_errno=True)
if probe_lib.unshare(0x40000000):
    probe_errno = ctypes.get_errno()
    os.close(original)
    if probe_errno in (errno.EPERM, errno.EINVAL, errno.ENOSYS):
        print('1..0 # SKIP cannot create a network namespace')
        sys.exit(4)
    raise OSError(probe_errno, os.strerror(probe_errno))
os.setns(original, 0)

namespaces, sockets, checks = [], [], []
sequence = 0


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT,
                                   timeout=20).strip()


def record(name, **details):
    checks.append(dict(name=name, passed=True, **details))
    print(f'ok {len(checks)} - {name}', flush=True)
    print('# '+json.dumps(checks[-1]), flush=True)


def namespace(suffix):
    name = f"nlsw-{os.getpid()}-" + suffix
    command("ip", "netns", "add", name)
    namespaces.append(name)
    command("ip", "-n", name, "link", "set", "lo", "up")
    return name


@contextlib.contextmanager
def enter(name):
    fd = os.open("/run/netns/" + name, os.O_RDONLY)
    os.setns(fd, 0)
    try:
        yield
    finally:
        os.setns(original, 0)
        os.close(fd)


def subscriber(name, allns=False):
    with enter(name):
        sk = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
        sk.setsockopt(270, 8, int(allns))
        sk.bind((0, 1 << 10))  # RTNLGRP_IPV6_ROUTE = 11
        sk.setblocking(False)
    sockets.append(sk)
    return sk


def mode(value):
    control.write_text(str(value) + "\n")
    assert int(control.read_text()) == value


def drain(sk):
    found = []
    while select.select([sk], [], [], 0)[0]:
        data = sk.recv(262144)
        offset = 0
        while offset < len(data):
            length, kind, flags, seq, pid = struct.unpack_from("IHHII", data, offset)
            assert 16 <= length <= len(data) - offset
            found.append((kind, data[offset + 16:offset + length]))
            offset += (length + 3) & ~3
        assert offset == len(data)
    return found


def notify(expected, selected=None):
    global sequence
    sequence += 1
    for sk in sockets:
        if sk.fileno() >= 0:
            drain(sk)
    command("ip", "-n", tx, "-6", "route", "add",
            f"fdab:abcd::{sequence:x}/128", "dev", "lo")
    for sk, count in expected.items():
        messages = [m for m in drain(sk) if m[0] == 24 and m[1][0] == 10]
        assert len(messages) == count, (sequence, sk.fileno(), count, len(messages))
    return None


try:
    mode(0)
    for bad in ("-1\n", "2\n", "garbage\n"):
        try:
            control.write_text(bad)
        except OSError as error:
            assert error.errno == errno.EINVAL, error
        else:
            raise AssertionError("invalid value accepted: " + bad)
        assert control.read_text().strip() == "0"
    record("disabled-setting-and-invalid-values-rejected")

    tx, monitor, unmapped = [namespace(n) for n in ("tx", "monitor", "unmapped")]
    with enter(tx):
        assert not control.exists(), "global control exposed in child netns"
    record("control-only-visible-in-initial-netns")
    command("ip", "-n", monitor, "netns", "set", tx, "71")
    local = subscriber(tx)
    local_all = subscriber(tx, True)
    ordinary = subscriber(monitor)
    cross = subscriber(monitor, True)
    no_map = subscriber(unmapped, True)
    expected = {local: 1, local_all: 1, ordinary: 0, cross: 1, no_map: 0}

    paths = []
    for value in (0, 1, 0, 1):
        mode(value)
        paths.append(dict(mode=value, receive_check=notify(expected)))
    record("live-switch-with-existing-local-and-cross-sockets", paths=paths)

    mode(0)
    late_local = subscriber(tx)
    late_cross = subscriber(monitor, True)
    local.setsockopt(270, 2, 11)
    cross.setsockopt(270, 8, 0)
    subscriber(tx).close()
    subscriber(monitor, True).close()
    mode(1)
    changed = {**expected, local: 0, cross: 0, late_local: 1, late_cross: 1}
    notify(changed)
    mode(0)
    local.setsockopt(270, 1, 11)
    cross.setsockopt(270, 8, 1)
    mode(1)
    expected.update({late_local: 1, late_cross: 1})
    notify(expected)
    record("indexes-maintained-while-off-for-join-drop-option-and-close")

    mode(0)
    pool = [subscriber(unmapped, True) for _ in range(80)]
    mode(1)
    notify({**expected, **{sk: 0 for sk in pool}})
    for sk in pool:
        sk.close()
    record("enabled-forces-index-despite-large-cross-list")

    stop, started = threading.Event(), threading.Event()
    updates, errors = [0], []

    def toggle():
        try:
            while not stop.is_set():
                mode(updates[0] % 2)
                updates[0] += 1
                started.set()
                time.sleep(0.001)
        except BaseException as error:
            errors.append(repr(error))

    worker = threading.Thread(target=toggle)
    worker.start()
    assert started.wait(5)
    try:
        for _ in range(40):
            notify(expected)
    finally:
        stop.set()
        worker.join(5)
    assert not worker.is_alive() and not errors, errors
    assert updates[0] >= 2
    record("concurrent-switch-no-missing-or-duplicate", notifications=40,
           switch_writes=updates[0])
    print(f'1..{len(checks)}', flush=True)
    (root / "switch-test.json").write_text(json.dumps(checks, indent=2) + "\n")
finally:
    if control.exists():
        control.write_text(saved_mode)
    for sk in sockets:
        sk.close()
    os.setns(original, 0)
    os.close(original)
    for name in reversed(namespaces):
        subprocess.run(["ip", "netns", "del", name], check=True)
