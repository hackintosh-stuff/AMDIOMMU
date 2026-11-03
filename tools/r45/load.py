#!/usr/bin/env python3
"""Normal mapped TCP/TSO4 before and after one ordinary interface down/up."""
import argparse
import json
import socket
import subprocess
import time
from common import identity, module, project_path, protocol as P, snapshot

NETWORK = module('_r45_network_checks', 'tools/r44/load.py').network


def transfer(peer, local, token, phase, direction, size):
    started = time.monotonic_ns()
    with socket.create_connection(peer, timeout=60, source_address=(local, 0)) as conn:
        conn.sendall(P.request(token, phase, direction, size))
        ready = P.receive_json(conn)
        if ready != {'event': 'ready', 'token': token, 'phase': phase, 'direction': direction}:
            raise RuntimeError('peer did not accept this transfer')
        result = P.stream(conn, token, phase, direction, size, sending=direction == 'upload')
        if direction == 'download':
            P.send_json(conn, dict(result, token=token, phase=phase, direction=direction))
        receipt = P.receive_json(conn)
        P.validate_receipt(receipt, token, phase, direction, size, result['sha256'])
    record = P.transfer_record('client', token, phase, direction, result, started)
    record.update(peer_bytes=receipt['bytes'], peer_sha256=receipt['sha256'])
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('out', nargs='?', default='runs/r45')
    parser.add_argument('--iface', default='en2')
    parser.add_argument('--peer', default='192.168.50.122')
    parser.add_argument('--port', type=int, default=9111)
    args = parser.parse_args()
    if args.iface != 'en2':
        raise ValueError('the selected target is en2')
    out = project_path(args.out)
    token = int((out / 'token.txt').read_text().strip(), 0)
    P.request(token, *P.TRANSFERS[0])
    if (out / 'snapshots').exists():
        raise ValueError('this run already has snapshots; preserve its evidence')
    local = NETWORK(args.iface, args.peer, wait=20)
    ok = False
    with (out / 'client.log').open('x', encoding='utf-8', newline='\n') as log:
        emit = lambda value: print(json.dumps(value, sort_keys=True), file=log, flush=True)
        try:
            emit({'event': 'start', 'side': 'client', 'token': token,
                  'interface': args.iface, 'local': local, 'peer': args.peer, 'port': args.port})
            first = snapshot(out / 'snapshots', 'before')
            initial = identity(first)
            for phase, direction, size in P.TRANSFERS[:2]:
                emit(transfer((args.peer, args.port), local, token, phase, direction, size))
            before_down = snapshot(out / 'snapshots', 'pre-down')
            if identity(before_down) != initial:
                raise RuntimeError('device domain changed during normal TCP')
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
            NETWORK(args.iface, args.peer, local, wait=20)
            for phase, direction, size in P.TRANSFERS[2:]:
                emit(transfer((args.peer, args.port), local, token, phase, direction, size))
            after = snapshot(out / 'snapshots', 'after-up')
            if identity(after) != initial:
                raise RuntimeError('device domain changed after ordinary interface up')
            ok = True
            emit({'event': 'result', 'side': 'client', 'ok': True, 'transfers': 4})
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            emit({'event': 'result', 'side': 'client', 'ok': False, 'error': str(exc)})
    (out / 'load.txt').write_bytes(('scope : r45-ordinary-tcp-tso4\nload_peer : %s:%d\n'
                                  'load_local : %s\nresult : %s\n' %
                                  (args.peer, args.port, local, 'OK' if ok else 'FAIL')).encode())
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
