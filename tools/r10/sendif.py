#!/usr/bin/env python3
"""Diagnostic: send one UDP datagram forced out en2 and see if it arrives.

This answers the only question that matters before the real experiment: can a
datagram be made to leave through the TARGET device (en2, the RTL8127) when
another interface on the same subnet would otherwise win the route?

It does not record experiment evidence; it prints what happened.
"""
import re
import socket
import struct
import subprocess
import sys
import time

IP_BOUND_IF = 25


def index_from_netstat(name):
    r = subprocess.run(['/usr/sbin/netstat', '-i', '-f', 'inet'],
                       capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if not line.startswith(name + ' '):
            continue
        m = re.search(r'<Link#(\d+)>', line)
        if m:
            return int(m.group(1))
    return None


def main():
    if len(sys.argv) < 5:
        print('usage: sendif.py <iface> <local-ip> <peer-ip> <peer-port>')
        return 2
    iface, local, peer, port = (sys.argv[1], sys.argv[2], sys.argv[3],
                                int(sys.argv[4]))
    idx = index_from_netstat(iface)
    print('iface=%s index=%s local=%s peer=%s:%d' % (iface, idx, local, peer, port))
    if idx is None:
        return 1

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, idx)
    s.bind((local, 0))
    s.settimeout(2.0)
    print('bound %s:%d' % s.getsockname())

    payload = struct.pack('>III', 0x31424F49, 0xFEEDFACE, 1) + b'.' * 20
    t0 = time.monotonic_ns()
    s.sendto(payload, (peer, port))
    print('sent %d bytes' % len(payload))
    try:
        data, addr = s.recvfrom(4096)
        t1 = time.monotonic_ns()
        print('GOT REPLY from %s:%d len=%d rtt_ns=%d' %
              (addr[0], addr[1], len(data), t1 - t0))
        print('payload match: %s' % (data == payload))
        return 0
    except socket.timeout:
        print('NO REPLY within 2 s')
        return 1
    finally:
        s.close()


if __name__ == '__main__':
    sys.exit(main())
