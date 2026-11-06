#!/usr/bin/env python3
"""Ordinary mapped IPv6 TCP/TSO before and after one interface down/up."""
import argparse
import json
import socket
import subprocess
import time
from common import identity, module, project_path, protocol as P, snapshot

NETWORK = module('_r48_network_checks', 'tools/dma32/network.py').network


def transfer(peer, local, token, phase, direction, size):
    started = time.monotonic_ns()
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as conn:
        conn.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        conn.settimeout(60)
        conn.bind(local)
        conn.connect(peer)
        endpoints = P.transport(conn)
        conn.sendall(P.request(token, phase, direction, size))
        ready = P.receive_json(conn)
        if any(ready.get(key) != wanted for key, wanted in (
                ('event', 'ready'), ('token', token), ('phase', phase), ('direction', direction))):
            raise RuntimeError('peer did not accept this transfer')
        P.validate_transport(ready, endpoints)
        result = P.stream(conn, token, phase, direction, size, sending=direction == 'upload')
        if direction == 'download':
            P.send_json(conn, dict(result, token=token, phase=phase, direction=direction, **endpoints))
        receipt = P.receive_json(conn)
        P.validate_receipt(receipt, token, phase, direction, size, result['sha256'])
        P.validate_transport(receipt, endpoints)
    record = dict(P.transfer_record('client', token, phase, direction, result, started), **endpoints)
    record.update(peer_bytes=receipt['bytes'], peer_sha256=receipt['sha256'],
                  peer_receipt_local=receipt['local'], peer_receipt_peer=receipt['peer'])
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('out', nargs='?', default='runs/r48')
    parser.add_argument('--iface', default='en2')
    parser.add_argument('--local', required=True, help='existing numeric IPv6 on en2')
    parser.add_argument('--peer', required=True, help='numeric peer IPv6; scope belongs to the Mac')
    parser.add_argument('--port', type=int, default=9114)
    args = parser.parse_args()
    if args.iface != 'en2' or not 0 < args.port <= 65535:
        raise ValueError('the selected target must be en2 with a valid TCP port')
    out = project_path(args.out)
    token = int((out / 'token.txt').read_text().strip(), 0)
    P.request(token, *P.TRANSFERS[0])
    if (out / 'snapshots').exists():
        raise ValueError('this run already has snapshots; preserve its evidence')
    local, peer = NETWORK(args.iface, args.peer, args.local, wait=20)
    peer = (peer[0], args.port, peer[2], peer[3])
    ok = False
    with (out / 'client.log').open('x', encoding='utf-8', newline='\n') as log:
        emit = lambda value: print(json.dumps(value, sort_keys=True), file=log, flush=True)
        try:
            emit({'event': 'start', 'side': 'client', 'token': token, 'family': 'IPv6',
                  'interface': args.iface, 'local': P.endpoint(local), 'peer': P.endpoint(peer)})
            first = snapshot(out / 'snapshots', 'before')
            initial = identity(first)
            for phase, direction, size in P.TRANSFERS[:2]:
                emit(transfer(peer, local, token, phase, direction, size))
            before_down = snapshot(out / 'snapshots', 'pre-down')
            if identity(before_down) != initial:
                raise RuntimeError('device domain changed during normal IPv6 TCP')
            emit({'event': 'ifdown-begin', 'time_ns': time.monotonic_ns()})
            try:
                subprocess.run(['ifconfig', args.iface, 'down'], check=True)
                down = snapshot(out / 'snapshots', 'down')
                if down['mapper']['liveCount'] != 67 or identity(down) != initial:
                    raise RuntimeError('normal down did not retain the same 67 resource mappings')
                emit({'event': 'ifdown-done', 'live_maps': 67, 'time_ns': time.monotonic_ns()})
            finally:
                subprocess.run(['ifconfig', args.iface, 'up'], check=True)
                emit({'event': 'ifup-requested', 'time_ns': time.monotonic_ns()})
            NETWORK(args.iface, args.peer, args.local, wait=20)
            for phase, direction, size in P.TRANSFERS[2:]:
                emit(transfer(peer, local, token, phase, direction, size))
            after = snapshot(out / 'snapshots', 'after-up')
            if identity(after) != initial:
                raise RuntimeError('device domain changed after ordinary interface up')
            ok = True
            emit({'event': 'result', 'side': 'client', 'ok': True, 'transfers': 4, 'family': 'IPv6'})
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            emit({'event': 'result', 'side': 'client', 'ok': False, 'error': str(exc)})
    (out / 'load.txt').write_bytes(('scope : r48-dma32-ivrs-pci-ipv6-tcp-tso6\nload_peer : [%s]:%d\n'
                                  'load_local : %s\nresult : %s\n' %
                                  (args.peer, args.port, args.local, 'OK' if ok else 'FAIL')).encode())
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
