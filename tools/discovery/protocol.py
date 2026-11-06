#!/usr/bin/env python3
"""Reuse the finite byte protocol with an IPv6-only transport identity."""
import importlib.util
import ipaddress
from pathlib import Path
import socket

_path = Path(__file__).resolve().parents[1] / 'tcp4/protocol.py'
_spec = importlib.util.spec_from_file_location('_r47_payload_base', _path)
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)
_base.MAGIC = b'R47TCP1\0'
MAGIC, HEADER, CHUNK = _base.MAGIC, _base.HEADER, _base.CHUNK
TRANSFERS = _base.TRANSFERS
request, parse_request = _base.request, _base.parse_request
chunks, expected_digest = _base.chunks, _base.expected_digest
receive, send_json, receive_json = _base.receive, _base.send_json, _base.receive_json
stream, transfer_record = _base.stream, _base.transfer_record
validate_receipt = _base.validate_receipt


def sockaddr(value, port, default_scope=0):
    """Resolve only a numeric IPv6 literal; scope belongs to this machine."""
    host, separator, zone = value.partition('%')
    address = ipaddress.IPv6Address(host)
    if address.ipv4_mapped or address.is_unspecified or address.is_multicast:
        raise ValueError('an ordinary unicast IPv6 address is required')
    scope = default_scope if address.is_link_local else 0
    if separator:
        scope = int(zone) if zone.isdecimal() else socket.if_nametoindex(zone)
    if address.is_link_local and scope <= 0:
        raise ValueError('a link-local IPv6 address needs its local interface scope')
    return (str(address), port, 0, scope)


def endpoint(value):
    address = ipaddress.IPv6Address(value[0].split('%', 1)[0])
    if address.ipv4_mapped:
        raise RuntimeError('IPv4-mapped transport does not exercise IPv6 TSO')
    return {'address': str(address), 'port': value[1], 'scope_id': value[3]}


def transport(sock):
    if sock.family != socket.AF_INET6:
        raise RuntimeError('the connected socket is not AF_INET6')
    return {'family': 'IPv6', 'local': endpoint(sock.getsockname()),
            'peer': endpoint(sock.getpeername())}


def validate_transport(receipt, local):
    """Compare address/port across machines; scope IDs are local namespaces."""
    if receipt.get('family') != 'IPv6':
        raise RuntimeError('the peer did not confirm an IPv6 connection')
    for mine, theirs in (('local', 'peer'), ('peer', 'local')):
        if any(local[mine][key] != receipt[theirs][key] for key in ('address', 'port')):
            raise RuntimeError('peer IPv6 socket endpoints differ')
