#!/usr/bin/env python3
"""Diagnostic: obtain the Darwin interface index and test IP_BOUND_IF.

macOS does not implement SIOCGIFINDEX on an AF_INET socket the way Linux does.
The portable way is getifaddrs(), whose ifa_name gives the BSD name and whose
entries carry the index in ifa_addr->sa_len ordering -- but the simplest
reliable source is `ifconfig -v` / the routing socket. Here we use
getifaddrs() via ctypes, which returns ifa_name and ifa_flags; the INDEX comes
from the kernel's if_data through SIOCGIFINDEX on an AF_ROUTE socket.

If none of that works, we fall back to matching netstat's <Link#N> column,
which prints exactly the interface index.
"""
import re
import socket
import struct
import subprocess
import sys

IP_BOUND_IF = 25


def index_from_netstat(name):
    """netstat -i prints the index as <Link#N> in the Network column."""
    r = subprocess.run(['/usr/sbin/netstat', '-i', '-f', 'inet'],
                       capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if not line.startswith(name + ' '):
            continue
        m = re.search(r'<Link#(\d+)>', line)
        if m:
            return int(m.group(1))
    # Also try the full list, including interfaces with no IPv4 address.
    r = subprocess.run(['/usr/sbin/netstat', '-i'], capture_output=True,
                       text=True)
    for line in r.stdout.splitlines():
        if not line.startswith(name + ' '):
            continue
        m = re.search(r'<Link#(\d+)>', line)
        if m:
            return int(m.group(1))
    return None


def main():
    if len(sys.argv) < 2:
        print('usage: bindif-probe.py <iface> [local-ip]')
        return 2
    iface = sys.argv[1]
    local = sys.argv[2] if len(sys.argv) > 2 else None

    idx = index_from_netstat(iface)
    print('iface=%s index=%s' % (iface, idx))
    if idx is None:
        print('FAIL: cannot determine the interface index')
        return 1
    if not local:
        return 0

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, idx)
        print('IP_BOUND_IF set OK')
    except OSError as e:
        print('FAIL IP_BOUND_IF: %s' % e)
        s.close()
        return 1
    try:
        s.bind((local, 0))
        print('bind OK -> %s:%d' % s.getsockname())
    except OSError as e:
        print('FAIL bind: %s' % e)
        s.close()
        return 1
    print('RESULT: socket pinned to %s from %s' % (iface, local))
    s.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
