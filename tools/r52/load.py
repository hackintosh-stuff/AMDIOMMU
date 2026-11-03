#!/usr/bin/env python3
"""Two explicit IPv6 endpoints; off baseline or one mapped A-down/B-live cycle."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import socket
import subprocess
import threading
import time
from common import (boot_mode, configuration, module, project_path, protocol as P,
                    roles, snapshot, write_json)

N = module('_r52_network', 'tools/r52/network.py')


def transfer(endpoint, token, phase, direction, size, ready_barrier=None):
    local, peer, index = N.network(endpoint, wait=20)
    started = time.monotonic_ns()
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as conn:
        conn.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        conn.settimeout(60)
        N.bind_interface(conn, index)
        conn.bind(local)
        conn.connect(peer)
        endpoints = P.transport(conn)
        conn.sendall(P.request(token, phase, direction, size))
        ready = P.receive_json(conn)
        if any(ready.get(key) != wanted for key, wanted in (
                ('event', 'ready'), ('token', token), ('phase', phase), ('direction', direction))):
            raise RuntimeError('peer did not accept this transfer')
        P.validate_transport(ready, endpoints)
        if ready_barrier is not None:
            ready_barrier.wait(timeout=30)
        payload_start = time.monotonic_ns()
        result = P.stream(conn, token, phase, direction, size, sending=direction == 'upload')
        payload_end = time.monotonic_ns()
        if direction == 'download':
            P.send_json(conn, dict(result, token=token, phase=phase, direction=direction, **endpoints))
        receipt = P.receive_json(conn)
        P.validate_receipt(receipt, token, phase, direction, size, result['sha256'])
        P.validate_transport(receipt, endpoints)
    record = dict(P.transfer_record('client', token, phase, direction, result, started), **endpoints)
    record.update(start_ns=started, end_ns=time.monotonic_ns(),
                  payload_start_ns=payload_start, payload_end_ns=payload_end,
                  interface=endpoint['interface'], ifindex=index, bound_ifindex=index,
                  requester=endpoint['requester'], peer_bytes=receipt['bytes'],
                  peer_sha256=receipt['sha256'], peer_receipt_local=receipt['local'],
                  peer_receipt_peer=receipt['peer'])
    return record


def before_traffic(endpoints, token):
    """Two finite workers exercise the shared command path at the same time."""
    ready = threading.Barrier(2)
    def worker(role):
        records = []
        try:
            for index, (phase, direction, size) in enumerate(P.transfers('off', role)):
                records.append(transfer(endpoints[role], token, phase, direction, size,
                                        ready_barrier=ready if index == 0 else None))
            return records
        except BaseException:
            ready.abort()
            raise
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {role: executor.submit(worker, role) for role in ('a', 'b')}
        # Keep deterministic evidence order; real payload timestamps prove overlap.
        return [record for role in ('a', 'b') for record in futures[role].result()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('out')
    parser.add_argument('--config', required=True)
    parser.add_argument('--mode', choices=('off', 'auto'), default='auto')
    parser.add_argument('--token', type=lambda value: int(value, 0))
    args = parser.parse_args()
    config = configuration(project_path(args.config))
    endpoints, out = roles(config), project_path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    token_path = out / 'token.txt'
    token = args.token if args.token is not None else (
        int(token_path.read_text().strip(), 0) if token_path.exists() else 0x52c0de52)
    P.request(token, *P.TRANSFERS[0])
    if (out / 'client.log').exists() or (out / 'snapshots').exists():
        raise ValueError('this output already contains a run; preserve its evidence')
    token_path.write_text('0x%08x\n' % token, encoding='utf-8')
    write_json(out / 'endpoints.json', config)
    write_json(out / 'run.json', {'mode': args.mode, 'token': token, 'config': config,
                                 'roles': endpoints, 'scope': 'r52'})
    ok = False
    with (out / 'client.log').open('x', encoding='utf-8', newline='\n') as log:
        emit = lambda value: print(json.dumps(value, sort_keys=True), file=log, flush=True)
        try:
            boot = boot_mode(args.mode)
            (out / 'running-boot-args.txt').write_text(boot + '\n', encoding='utf-8')
            emit({'event': 'start', 'side': 'client', 'token': token, 'mode': args.mode,
                  'family': 'IPv6', 'roles': endpoints})
            for endpoint in endpoints.values():
                N.network(endpoint, wait=120)
            snapshot(out / 'snapshots', 'before', config, args.mode)
            for record in before_traffic(endpoints, token):
                emit(record)
            if args.mode == 'auto':
                iface = endpoints['a']['interface']
                emit({'event': 'ifdown-begin', 'interface': iface, 'time_ns': time.monotonic_ns()})
                try:
                    subprocess.run(['ifconfig', iface, 'down'], check=True)
                    emit({'event': 'ifdown-done', 'interface': iface, 'time_ns': time.monotonic_ns()})
                    for phase, direction, size in P.TRANSFERS[4:6]:
                        emit(transfer(endpoints['b'], token, phase, direction, size))
                    snapshot(out / 'snapshots', 'down', config, args.mode)
                finally:
                    emit({'event': 'ifup-requested', 'interface': iface, 'time_ns': time.monotonic_ns()})
                    subprocess.run(['ifconfig', iface, 'up'], check=True)
                for phase, direction, size in P.TRANSFERS[6:]:
                    emit(transfer(endpoints['a'], token, phase, direction, size))
                snapshot(out / 'snapshots', 'after-up', config, args.mode)
            else:
                snapshot(out / 'snapshots', 'after', config, args.mode)
            ok = True
            emit({'event': 'result', 'side': 'client', 'ok': True, 'family': 'IPv6',
                  'transfers': len(P.transfers(args.mode))})
        except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
            emit({'event': 'result', 'side': 'client', 'ok': False, 'error': str(exc)})
    (out / 'load.txt').write_text('scope : r52-two-device-ipv6\nmode : %s\nresult : %s\n' %
                                (args.mode, 'OK' if ok else 'FAIL'), encoding='utf-8')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
