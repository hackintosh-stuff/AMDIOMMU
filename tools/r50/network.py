#!/usr/bin/env python3
"""Read the selected ordinary IPv6 address and route without configuring them."""
import ipaddress
import re
import socket
import subprocess
import time
from common import protocol as P


def network(iface, peer, local, wait=0):
    scope = socket.if_nametoindex(iface)
    source, destination = P.sockaddr(local, 0, scope), P.sockaddr(peer, 0, scope)
    for address in (source, destination):
        if address[3] not in (0, scope):
            raise ValueError('IPv6 scope must select ' + iface + ' on this machine')
    route_target = destination[0]
    if ipaddress.IPv6Address(destination[0]).is_link_local:
        route_target += '%' + iface
    deadline = time.monotonic() + wait
    while True:
        interface = subprocess.run(['ifconfig', iface], capture_output=True, text=True)
        addresses = []
        for line in interface.stdout.splitlines():
            match = re.search(r'\binet6\s+(\S+)', line)
            if match and 'tentative' not in line and 'duplicated' not in line:
                addresses.append(str(ipaddress.IPv6Address(match[1].split('%', 1)[0])))
        route = subprocess.run(['route', '-n', 'get', '-inet6', route_target],
                               capture_output=True, text=True)
        interfaces = re.findall(r'^\s*interface:\s*(\S+)', route.stdout, re.MULTILINE)
        if (interface.returncode == route.returncode == 0 and source[0] in addresses and
                'status: active' in interface.stdout and
                re.search(r'\bmtu\s+1500\b', interface.stdout) and interfaces == [iface]):
            return source, destination
        if time.monotonic() >= deadline:
            raise RuntimeError('ordinary IPv6 address/link/MTU/peer route is not ready on ' + iface)
        time.sleep(.5)
