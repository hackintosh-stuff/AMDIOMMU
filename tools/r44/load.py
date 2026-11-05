#!/usr/bin/env python3
"""8192 ordinary requests, 125 s idle, then normal interface down/up."""
import argparse
import re
import socket
import subprocess
import time
from common import (ROOT, active, identity, load_helpers as L, protocol as P,
                    project_path, snapshot)


def network(iface, peer, local=None, wait=0):
    deadline = time.monotonic() + wait
    while True:
        text = L.command('ifconfig', iface, required=False)
        addr = re.search(r'\binet ([0-9.]+) ', text)
        if (addr and (local is None or addr[1] == local) and 'status: active' in text and
                re.search(r'\bmtu 1500\b', text) and L.route(peer) == iface):
            return addr[1]
        if time.monotonic() >= deadline:
            raise RuntimeError('ordinary interface/address/MTU/peer route is not ready')
        time.sleep(.5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('out', nargs='?', default='runs/r44')
    parser.add_argument('--iface', default='en2')
    parser.add_argument('--peer', default='192.168.50.122')
    parser.add_argument('--port', default=9110, type=int)
    args = parser.parse_args()
    if args.iface != 'en2':
        raise ValueError('the selected target is en2')
    out = project_path(args.out)
    token = int((out / 'token.txt').read_text().strip(), 0)
    P.payload(token, 1)
    if int((out / 'requests.txt').read_text()) != len(P.REQUESTS):
        raise ValueError('8192 requests required')
    if (out / 'client.log').exists() or (out / 'snapshots').exists():
        raise ValueError('this run already has evidence; do not overwrite it')
    peer = (args.peer, args.port)
    local = network(args.iface, args.peer, wait=20)
    result = 1
    with (out / 'client.log').open('w', encoding='utf-8', newline='\n') as log:
        def emit(line):
            print(line, file=log, flush=True)
        def observe(emit, phase, expected=None):
            value = snapshot(out / 'snapshots', 'phase%d' % phase)
            current = identity(value)
            if not active(value) or (expected is not None and current != expected):
                raise RuntimeError('ordinary device mapper is not active or its domain changed')
            emit('client_mapper_phase phase=%d identity=%s t_ns=%d' %
                 (phase, ','.join(str(x) for x in current), L.now()))
            return current
        def idle(emit, deadline):
            begin = L.now()
            emit('client_mapper_idle_begin seconds=125 t_ns=%d' % begin)
            end = begin + 125_000_000_000
            while L.now() < end:
                if L.now() >= deadline:
                    raise RuntimeError('client budget expired during idle')
                time.sleep(min(5, max(0, (end - L.now()) / 1e9)))
            emit('client_mapper_idle_end t_ns=%d' % L.now())
        order = L.OrdSeq()
        try:
            emit('client_start mode=auto token=0x%08x iface=%s local=%s peer=%s:%d t_ns=%d' %
                 (token, args.iface, local, *peer, L.now()))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                L.bind_local(sock, local, emit)
                sock.settimeout(1)
                sock.sendto(P.SEED, peer)
                echoed, source = sock.recvfrom(8192)
                if echoed != P.SEED or source != peer:
                    raise RuntimeError('peer liveness echo differs')
                for _ in range(20):
                    if not L.ord_probe(sock, peer, order.next(), emit, 'pre'):
                        raise RuntimeError('ordinary pre-traffic failed')
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                result = L.exchange(sock, local, peer, token, emit, order,
                                    client_deadline_ns=L.now() + L.CLIENT_BUDGET_NS,
                                    persistent_session=True, phase_observer=observe,
                                    idle_handler=idle)
            if result:
                raise RuntimeError('finite traffic failed')
            before = snapshot(out / 'snapshots', 'pre-down')
            if not active(before):
                raise RuntimeError('mapper failed before normal disable')
            emit('client_ifdown_begin t_ns=%d' % L.now())
            try:
                subprocess.run(['ifconfig', args.iface, 'down'], check=True)
                down = snapshot(out / 'snapshots', 'down')
                emit('client_ifdown_done live_maps=%d t_ns=%d' %
                     (down['mapper']['liveCount'], L.now()))
                if (not active(down) or identity(down) != identity(before) or
                        down['mapper']['liveCount'] != 67):
                    raise RuntimeError('down must retain the 64 RX groups and 3 fixed mappings')
            finally:
                # This is the paired normal lifecycle action, including on a
                # failed observation. It never retries application requests.
                subprocess.run(['ifconfig', args.iface, 'up'], check=True)
                emit('client_ifup_requested t_ns=%d' % L.now())
            network(args.iface, args.peer, local, wait=20)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                L.bind_local(sock, local, emit)
                sock.settimeout(1)
                for _ in range(3):
                    if not L.ord_probe(sock, peer, order.next(), emit, 'after-up'):
                        raise RuntimeError('ordinary traffic did not resume after interface up')
            after = snapshot(out / 'snapshots', 'after-up')
            if not active(after) or identity(after) != identity(before):
                raise RuntimeError('normal interface up changed or lost the device domain')
            emit('client_result OK')
            result = 0
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            emit('client_error %s' % exc)
            emit('client_result FAIL')
            result = 1
    (out / 'load.txt').write_bytes(('scope : r44-ordinary-device-iomapper\n'
                                  'load_peer : %s:%d\nload_local : %s\nresult : %s\n' %
                                  (*peer, local, 'OK' if result == 0 else 'FAIL')).encode('utf-8'))
    return result


if __name__ == '__main__':
    raise SystemExit(main())
