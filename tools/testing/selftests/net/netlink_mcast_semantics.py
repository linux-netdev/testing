#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""NETLINK_ROUTE multicast semantic checks, independent of the lab."""
import argparse
import array
import contextlib
import ctypes
import errno
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess as sp
import time
import tempfile
import shutil
import sys

SOL_NETLINK = 270
ROUTE6, ROUTE4, LINK, ADDR4, ADDR6, NEXTHOP = 11, 7, 1, 5, 9, 32
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--output', type=Path)
args = ap.parse_args()
if os.geteuid() != 0 or not shutil.which('ip') or not hasattr(os, 'setns'):
    print('1..0 # SKIP requires root, iproute2 and Python os.setns')
    sys.exit(4)
out = args.output or Path(tempfile.mkdtemp(prefix='netlink-mcast-'))
if args.output:
    out.mkdir(exist_ok=False, parents=True)
cases, sockets, namespaces = [], [], []
prefix = f'nlmc-{os.getpid()}-'
if not Path('/proc/sys/net/ipv4/nexthop_compat_mode').exists():
    print('1..0 # SKIP requires IPv4/IPv6 nexthop support')
    sys.exit(4)
print('TAP version 13', flush=True)
original = os.open('/proc/self/ns/net', os.O_RDONLY)
# Probe namespace creation before beginning behavioural assertions.
probe_lib = ctypes.CDLL(None, use_errno=True)
if probe_lib.unshare(0x40000000):
    probe_errno = ctypes.get_errno()
    os.close(original)
    if probe_errno in (errno.EPERM, errno.EINVAL, errno.ENOSYS):
        print('1..0 # SKIP cannot create a network namespace')
        sys.exit(4)
    raise OSError(probe_errno, os.strerror(probe_errno))
try:
    for probe_protocol in (0, 4, 16):
        socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, probe_protocol).close()
except OSError as probe_error:
    if probe_error.errno in (errno.EPROTONOSUPPORT, errno.EAFNOSUPPORT):
        print('1..0 # SKIP missing required Netlink protocol')
        os.setns(original, 0)
        os.close(original)
        sys.exit(4)
    raise
os.setns(original, 0)


def cmd(*a):
    return sp.check_output(a, text=True, stderr=sp.STDOUT, timeout=30).strip()

def ns(name):
    name = prefix+name
    cmd('ip', 'netns', 'add', name)
    namespaces.append(name)
    cmd('ip', '-n', name, 'link', 'set', 'lo', 'up')
    return name

@contextlib.contextmanager
def enter(name):
    fd = os.open('/run/netns/'+name, os.O_RDONLY)
    os.setns(fd, 0)
    try:
        yield
    finally:
        os.setns(original, 0)
        os.close(fd)

def sock(name, groups=(), allns=False, rcvbuf=4*1024*1024, protocol=0):
    with enter(name):
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, protocol)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        s.setsockopt(SOL_NETLINK, 3, 1)  # NETLINK_PKTINFO
        if allns:
            s.setsockopt(SOL_NETLINK, 8, 1)
        s.bind((0, 0))
        for group in groups:
            s.setsockopt(SOL_NETLINK, 1, group)
        s.setblocking(False)
    sockets.append(s)
    return s

def messages(s, wait=0.025, allow_enobufs=False):
    result, errors = [], []
    while select.select([s], [], [], wait)[0]:
        try:
            data, ancillary, flags, address = s.recvmsg(262144, 512)
        except OSError as e:
            if e.errno == errno.ENOBUFS and allow_enobufs:
                errors.append(e.errno)
                continue
            raise
        assert not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
        tags = {kind: struct.unpack('i', value[:4])[0]
                for level, kind, value in ancillary if level == SOL_NETLINK}
        offset = 0
        while offset < len(data):
            length, kind, nlflags, seq, pid = struct.unpack_from('IHHII', data, offset)
            assert 16 <= length <= len(data)-offset
            result.append(dict(type=kind, flags=nlflags, seq=seq,
                               family=data[offset+16] if length > 16 else None,
                               tags=tags, data=data[offset+16:offset+length]))
            offset += (length+3) & ~3
        assert offset == len(data)
        wait = 0
    return result, errors

def clean():
    # One settle interval per preparation boundary; idle sockets do not each
    # add another interval. Expected notification reads still wait explicitly.
    time.sleep(0.025)
    for s in sockets:
        if s.fileno() >= 0:
            messages(s,wait=0)

def record(name, **details):
    cases.append(dict(name=name, passed=True, **details))
    (out/'cases.json').write_text(json.dumps(cases, indent=2))
    print(f'ok {len(cases)} - {name}', flush=True)
    print('# '+json.dumps(cases[-1]), flush=True)

def route(name, family=6):
    dest = 'fdab:123::1/128' if family == 6 else '198.18.0.1/32'
    cmd('ip', '-n', name, '-'+str(family), 'route', 'replace', dest, 'dev', 'lo')

def expect(s, count, kind=24, family=10, cross=None, group=ROUTE6):
    found, errors = messages(s)
    chosen = [m for m in found if m['type'] == kind and m['family'] == family]
    assert len(chosen) == count, (count, [(m['type'], m['family'],m['tags']) for m in found])
    for m in chosen:
        assert m['tags'].get(3) == group, m
        assert m['tags'].get(8) == cross, m
    return len(chosen)

def nlmsg(kind, flags, seq, body):
    return struct.pack('IHHII', 16+len(body), kind, flags, seq, 0)+body

def attr(kind, body):
    value = struct.pack('HH', len(body)+4, kind)+body
    return value+b'\0'*((-len(value)) % 4)

def slow_queue(tx, no_enobufs, broadcast_error=False):
    slow = sock(tx, [ROUTE6], rcvbuf=4096)
    slow.setsockopt(SOL_NETLINK, 5, int(no_enobufs))
    slow.setsockopt(SOL_NETLINK, 4, int(broadcast_error))
    sender = sock(tx)
    request = b''
    for i in range(200):
        body = struct.pack('BBBBBBBBI', 10, 128, 0, 0, 254, 186, 0, 1, 0)
        body += attr(1, socket.inet_pton(socket.AF_INET6, 'fdab:456::'+format(i+1,'x')))
        body += attr(4, struct.pack('I', 1))
        request += nlmsg(24, 1|4|0x100|0x400, i+1, body)
    sender.sendto(request, (0, 0))
    acks, errors = messages(sender, 1)
    assert len(acks) == 200 and all(m['type']==2 and struct.unpack_from('i',m['data'])[0]==0 for m in acks)
    delivered, overflows = messages(slow, allow_enobufs=True)
    assert 0 < len(delivered) < 200
    assert bool(overflows) == (not no_enobufs), (len(delivered),overflows)
    slow.close(); sender.close()
    return dict(acks=len(acks), delivered=len(delivered), enobufs=len(overflows))

try:
    tx, rx, nomap = ns('tx'), ns('rx'), ns('nomap')
    cmd('ip', 'netns', 'exec', rx, 'ip', 'netns', 'set', tx, '71')
    local = sock(tx, [ROUTE6])
    local_all = sock(tx, [ROUTE6], allns=True)
    wrong = sock(tx, [LINK])
    multi = sock(tx, [ROUTE6, LINK])
    foreign = sock(rx, [ROUTE6])
    cross = sock(rx, [ROUTE6], allns=True)
    unmapped = sock(nomap, [ROUTE6], allns=True)
    clean(); route(tx)
    assert [expect(s,n,cross=x) for s,n,x in
            [(local,1,None),(local_all,1,None),(wrong,0,None),(multi,1,None),
             (foreign,0,None),(cross,1,71),(unmapped,0,None)]] == [1,1,0,1,0,1,0]
    record('local-group-multiple-sockets-multiple-groups-and-cross-nsid',
           local=3, cross=1, cross_nsid=71, foreign_ordinary=0, missing_map=0,
           local_all_nsid_duplicates=0)

    high = sock(tx, [ROUTE6, 33, 34])
    mask = high.getsockopt(SOL_NETLINK, 9, 128)
    assert struct.unpack_from('=I', mask, 4)[0] & 2
    clean(); route(tx); expect(high, 1)
    high.close()
    record('membership-above-32-and-matching-route-group')

    # Toggle an already subscribed foreign socket, then last-membership removal.
    for enabled in [0,1,0,1]:
        cross.setsockopt(SOL_NETLINK, 8, enabled)
        clean(); route(tx)
        expect(cross,enabled,cross=71)
    record('listen-all-nsid-toggle-after-subscription', transitions=[0,1,0,1])
    cross.setsockopt(SOL_NETLINK, 2, ROUTE6)
    clean(); route(tx); expect(cross,0)
    cross.setsockopt(SOL_NETLINK, 1, ROUTE6)
    clean(); route(tx); expect(cross,1,cross=71)
    record('cross-last-drop-and-rejoin')

    local.setsockopt(SOL_NETLINK, 2, ROUTE6)
    clean(); route(tx); expect(local,0)
    local.setsockopt(SOL_NETLINK, 1, LINK)
    local.setsockopt(SOL_NETLINK, 1, ROUTE6)
    local.setsockopt(SOL_NETLINK, 2, LINK)
    clean(); route(tx); expect(local,1)
    local.bind((local.getsockname()[0],0))
    clean(); route(tx); expect(local,0)
    local.bind((local.getsockname()[0],1<<(ROUTE6-1)))
    clean(); route(tx); expect(local,1)
    record('first-last-membership-rebind-and-multi-group-updates')

    # Receive-side classic BPF filter remains applied by do_one_broadcast().
    class Filter(ctypes.Structure):
        _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_=[('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
    insn=Filter(6,0,0,0); prog=Program(1,ctypes.pointer(insn))
    libc=ctypes.CDLL(None,use_errno=True)
    assert libc.setsockopt(local.fileno(),socket.SOL_SOCKET,26,ctypes.byref(prog),ctypes.sizeof(prog))==0
    clean(); route(tx); expect(local,0)
    local.setsockopt(socket.SOL_SOCKET,27,0)
    clean(); route(tx); expect(local,1)
    record('socket-bpf-receive-filter')

    # file_ns_capable() checks the credentials captured when the socket opened.
    parent, child = socket.socketpair()
    pid=os.fork()
    if pid==0:
        try:
            parent.close()
            class CapHeader(ctypes.Structure):
                _fields_=[('version',ctypes.c_uint),('pid',ctypes.c_int)]
            class CapData(ctypes.Structure):
                _fields_=[('effective',ctypes.c_uint),('permitted',ctypes.c_uint),('inheritable',ctypes.c_uint)]
            header=CapHeader(0x20080522,0); caps=(CapData*2)()
            assert libc.capget(ctypes.byref(header),caps)==0
            for f in ['effective','permitted','inheritable']:
                setattr(caps[0],f,getattr(caps[0],f)&~(1<<11))
            assert libc.capset(ctypes.byref(header),caps)==0
            with enter(rx):
                denied=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,0)
                denied.bind((0,1<<(ROUTE6-1)))
                try:
                    denied.setsockopt(SOL_NETLINK,8,1)
                except PermissionError:
                    pass
                else:
                    raise AssertionError('unprivileged setsockopt unexpectedly succeeded')
            child.sendmsg([b'fd'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[denied.fileno()]))])
            os._exit(0)
        except BaseException:
            import traceback
            traceback.print_exc(); os._exit(1)
    child.close()
    data, anc, flags, addr=parent.recvmsg(16,socket.CMSG_SPACE(4))
    assert os.waitpid(pid,0)[1]==0
    fd=array.array('i'); fd.frombytes(anc[0][2][:4])
    denied=socket.socket(fileno=fd[0]); denied.setblocking(False); sockets.append(denied)
    denied.setsockopt(SOL_NETLINK,8,1)
    clean(); route(tx); expect(denied,0); expect(cross,1,cross=71)
    denied.close(); parent.close()
    record('cross-namespace-capability-denied-and-set-option-denied')

    ipv4=sock(tx,[ROUTE4]); clean(); route(tx,4)
    expect(ipv4,1,family=2,group=ROUTE4); expect(local,0)
    cmd('ip','-n',tx,'-4','route','del','198.18.0.1/32')
    expect(ipv4,1,kind=25,family=2,group=ROUTE4)
    clean(); cmd('ip','-n',tx,'-6','route','del','fdab:123::1/128')
    expect(local,1,kind=25); expect(cross,1,kind=25,cross=71)
    record('ipv4-ipv6-route-add-delete-and-family-group-filter')
    link=sock(tx,[LINK]); a4=sock(tx,[ADDR4]); a6=sock(tx,[ADDR6]); nh=sock(tx,[NEXTHOP])
    clean(); cmd('ip','-n',tx,'link','add','nl-dummy','type','dummy')
    expect(link,1,kind=16,family=0,group=LINK)
    cmd('ip','-n',tx,'link','set','nl-dummy','up'); clean()
    cmd('ip','-n',tx,'addr','add','198.19.0.1/24','dev','nl-dummy')
    expect(a4,1,kind=20,family=2,group=ADDR4)
    cmd('ip','-n',tx,'-6','addr','add','fdab:999::1/64','dev','nl-dummy','nodad')
    expect(a6,1,kind=20,family=10,group=ADDR6)
    clean(); cmd('ip','-n',tx,'-6','nexthop','add','id','101','dev','lo')
    expect(nh,1,kind=104,family=10,group=NEXTHOP)
    cmd('ip','-n',tx,'nexthop','del','id','101')
    expect(nh,1,kind=105,family=10,group=NEXTHOP)
    clean(); cmd('ip','-n',tx,'addr','del','198.19.0.1/24','dev','nl-dummy')
    expect(a4,1,kind=21,family=2,group=ADDR4)
    clean(); cmd('ip','-n',tx,'-6','addr','del','fdab:999::1/64','dev','nl-dummy')
    expect(a6,1,kind=21,family=10,group=ADDR6)
    clean(); cmd('ip','-n',tx,'link','del','nl-dummy')
    expect(link,1,kind=17,family=0,group=LINK)
    record('link-address-ipv4-ipv6-and-nexthop-add-delete')

    route(tx)
    sender=sock(tx)
    sender.sendto(nlmsg(26,1|0x300,100,bytes([10])+b'\0'*11),(0,0))
    dump,errs=messages(sender,1)
    assert dump and dump[-1]['type']==3 and all(m['seq']==100 for m in dump)
    assert any(m['type']==24 for m in dump)
    bad=struct.pack('BBBBBBBBI',10,129,0,0,254,186,0,1,0)
    sender.sendto(nlmsg(24,1|4|0x400|0x100,101,bad),(0,0))
    ack,errs=messages(sender,1)
    assert len(ack)==1 and ack[0]['type']==2 and ack[0]['seq']==101
    code=struct.unpack_from('i',ack[0]['data'])[0]
    assert code==-errno.EINVAL,code
    record('unicast-route-dump-and-invalid-request-error-ack',error=code)

    # Change candidate population without changing the true recipients.
    # Extra sockets use LINK and carry no IPv6-route data.
    pool=[]
    transitions=[]
    for target in (0,48,64,80,128,64,48,0):
        while len(pool)<target:
            pool.append(sock(nomap,[LINK]))
        while len(pool)>target:
            pool.pop().close()
        clean(); route(tx)
        expect(local,1); expect(local_all,1); expect(cross,1,cross=71)
        if target:
            # Toggle cross-netns membership while true route recipients stay fixed.
            for enabled in (1,0):
                for extra in pool: extra.setsockopt(SOL_NETLINK,8,enabled)
                clean(); route(tx)
                expect(local,1); expect(local_all,1); expect(cross,1,cross=71)
        transitions.append(target)
    record('candidate-population-transitions-no-missing-or-duplicate',sizes=transitions)
    # A mapped OVS-style listener must still receive LINK/ADDR on indexed path.
    ovs=sock(rx,[1,5,9,12],allns=True)
    field_pool=[sock(nomap,[LINK]) for _ in range(128)]
    clean(); cmd('ip','-n',tx,'link','add','nlg-ovs','type','dummy')
    expect(ovs,1,kind=16,family=0,group=LINK,cross=71)
    cmd('ip','-n',tx,'link','set','nlg-ovs','up'); clean()
    cmd('ip','-n',tx,'addr','add','198.20.1.1/32','dev','nlg-ovs')
    expect(ovs,1,kind=20,family=2,group=ADDR4,cross=71)
    clean(); cmd('ip','-n',tx,'-6','addr','add','fdaa:908::1/128','dev','nlg-ovs','nodad')
    expect(ovs,1,kind=20,family=10,group=ADDR6,cross=71)
    clean(); cmd('ip','-n',tx,'link','del','nlg-ovs'); clean()
    for extra in field_pool: extra.close()
    ovs.close()
    record('mapped-ovs-style-link-address-notifications-with-128-foreign')

    probe=sock(tx,allns=True)
    # Unsubscribed option changes, duplicate joins, partial/last drops and rebind.
    for enabled in (0,1,0,1): probe.setsockopt(SOL_NETLINK,8,enabled)
    for group in (ROUTE6,ROUTE6,LINK): probe.setsockopt(SOL_NETLINK,1,group)
    clean(); route(tx); expect(probe,1)
    probe.setsockopt(SOL_NETLINK,2,LINK)
    clean(); route(tx); expect(probe,1)
    probe.setsockopt(SOL_NETLINK,2,ROUTE6)
    clean(); route(tx); expect(probe,0)
    for _ in range(2): probe.bind((probe.getsockname()[0],1<<(ROUTE6-1)))
    clean(); route(tx); expect(probe,1)
    probe.close()
    record('duplicate-and-partial-membership-transitions')
    for compat in (0,1):
        cmd('ip','netns','exec',tx,'sysctl','-qw',f'net.ipv4.nexthop_compat_mode={compat}')
        cmd('ip','-n',tx,'-6','nexthop','add','id','200','dev','lo')
        cmd('ip','-n',tx,'-6','route','add','fdab:888::1/128','nhid','200')
        clean()
        cmd('ip','-n',tx,'-6','nexthop','replace','id','200','blackhole')
        expect(local,compat); expect(cross,compat,cross=71)
        clean(); cmd('ip','-n',tx,'nexthop','del','id','200')
        expect(local,compat,kind=25); expect(cross,compat,kind=25,cross=71)
        record('nexthop-reference-compat-'+str(compat),route_change_notifications=compat,route_delete_notifications=compat)

    # Close regular listeners before deliberately flooding a small queue.
    for s in sockets:
        s.close()
    record('slow-reader-default-enobufs',**slow_queue(tx,False))
    record('slow-reader-no-enobufs-option',**slow_queue(tx,True))
    record('slow-reader-broadcast-error-option-keeps-success-acks',**slow_queue(tx,False,True))

    sink=sock(tx,protocol=2)
    user_local=sock(tx,[1],protocol=2)
    user_foreign=sock(rx,[1],protocol=2)
    user_cross=sock(rx,[1],allns=True,protocol=2)
    user_sender=sock(tx,protocol=2)
    payload=nlmsg(42,0,900,b'\0usersock-regression')
    assert user_sender.sendto(payload,(sink.getsockname()[0],1))==len(payload)
    expect(user_local,1,kind=42,family=0,group=1)
    expect(user_foreign,0,kind=42,family=0,group=1)
    expect(user_cross,1,kind=42,family=0,group=1,cross=71)
    unicast, errs = messages(sink)
    assert len(unicast) == 1 and unicast[0]['type'] == 42
    assert unicast[0]['data'] == payload[16:]
    record('usersock-multicast-local-cross-and-unicast-unchanged')

    # Generic-netlink control query and SOCK_DIAG dump use untouched protocols.
    with enter(tx):
        generic=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,16)
        generic.bind((0,0)); generic.setblocking(False); sockets.append(generic)
        generic.sendto(nlmsg(16,1|4,701,struct.pack('BBH',3,1,0)+attr(2,b'nlctrl\0')),(0,0))
        g,errs=messages(generic,1)
        assert any(m['type']==16 and m['seq']==701 for m in g)
        diag=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,4)
        diag.bind((0,0)); diag.setblocking(False); sockets.append(diag)
        # netlink_diag_req is 20 bytes: family/protocol/pad, inode/show/cookie[2].
        req=struct.pack('BBHIIII',socket.AF_NETLINK,0,0,0,1|8,0xffffffff,0xffffffff)
        diag.sendto(nlmsg(20,1|0x300,702,req),(0,0))
        d,errs=messages(diag,1)
        assert d and d[-1]['type']==3 and any(m['type']==20 for m in d)
    record('generic-netlink-and-sock-diag',generic_reply=True,diag_records=sum(m['type']==20 for m in d))
    record('proc-netlink-visible',lines=len(Path('/proc/net/netlink').read_text().splitlines()))
    print(f'1..{len(cases)}', flush=True)
    (out/'complete.json').write_text(json.dumps(dict(success=True,kernel=os.uname().release,
        boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),cases=len(cases)),indent=2))
finally:
    for s in sockets:
        s.close()
    os.setns(original,0); os.close(original)
    for name in reversed(namespaces):
        sp.run(['ip','netns','del',name],check=False,stdout=sp.DEVNULL,stderr=sp.DEVNULL)
