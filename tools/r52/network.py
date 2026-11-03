#!/usr/bin/env python3
"""Validate existing endpoints and bind every client socket to its real ifindex."""
import ipaddress
import re
import socket
import subprocess
import sys
import time
from common import protocol as P


def network(endpoint, wait=0):
    iface = endpoint['interface']
    index = socket.if_nametoindex(iface)
    local = P.sockaddr(endpoint['local_ipv6'], 0, index)
    peer = P.sockaddr(endpoint['peer_ipv6'], endpoint['port'], index)
    if any(address[3] not in (0, index) for address in (local, peer)):
        raise ValueError('IPv6 scope differs from the selected interface ' + iface)
    deadline = time.monotonic() + wait
    while True:
        result = subprocess.run(['ifconfig', iface], capture_output=True, text=True)
        addresses = []
        for line in result.stdout.splitlines():
            match = re.search(r'\binet6\s+(\S+)', line)
            if match and 'tentative' not in line and 'duplicated' not in line:
                addresses.append(str(ipaddress.IPv6Address(match[1].split('%', 1)[0])))
        if (result.returncode == 0 and local[0] in addresses and
                'status: active' in result.stdout and re.search(r'\bmtu\s+1500\b', result.stdout)):
            return local, peer, index
        if time.monotonic() >= deadline:
            raise RuntimeError('existing IPv6 address/link/MTU is not ready on ' + iface)
        time.sleep(.5)


def bind_interface(conn, index):
    if sys.platform != 'darwin':
        raise RuntimeError('R52 client interface binding requires macOS')
    # XNU bsd/netinet6/in6.h: IPV6_BOUND_IF is a set/get integer option, 125.
    option = getattr(socket, 'IPV6_BOUND_IF', 125)
    conn.setsockopt(socket.IPPROTO_IPV6, option, index)
    if conn.getsockopt(socket.IPPROTO_IPV6, option) != index:
        raise RuntimeError('IPv6 socket did not retain its selected interface')
