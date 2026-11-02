#!/usr/bin/env python3
"""Round20 finite peer: validate every byte BEFORE echo, echo only in order.

Runs on the Windows host. One nonmagic 1024-byte seed primes the observation
log as in r15/r16; then exactly the 16 declared requests, each echoed only
after its full payload matched. No flood, no retransmission, no reordering.
"""
import argparse
import select
import socket
import time
from protocol import REQUESTS, SEED, evidence, identify, payload


def serve(s, token, seconds, emit):
    emit('peer_start bind=%s:%d token=0x%08x' % (*s.getsockname(), token))
    end = time.monotonic() + seconds
    received = []
    bad = 0
    seed_seen = False
    endpoint = None
    while time.monotonic() < end and len(received) < len(REQUESTS):
        if not select.select([s], [], [], min(.2, max(0, end - time.monotonic())))[0]:
            continue
        try:
            data, addr = s.recvfrom(8192)
        except ConnectionResetError:
            continue
        when = time.monotonic_ns()
        if data == SEED and not seed_seen and not received:
            seed_seen = True
            emit('peer_seed_recv len=1024 nonmagic=1 from=%s:%d t=%d' % (*addr, when))
            n = s.sendto(data, addr)
            if n != len(data):
                raise RuntimeError('short seed send')
            emit('peer_seed_sent len=1024 to=%s:%d t=%d' % (*addr, time.monotonic_ns()))
            continue
        ident = identify(data)
        req = ident[1] if ident else 0
        tok = ident[0] if ident else 0
        expected_req = len(received) + 1
        valid = (ident == (token, expected_req) and req in REQUESTS and
                 data == payload(token, req) and (endpoint is None or addr == endpoint))
        emit('peer_recv token=0x%08x req=%d %s payload_ok=%d from=%s:%d t=%d' %
             (tok, req, evidence(data), int(valid), *addr, when))
        if not valid:
            bad += 1
            continue  # Never echo invalid or out-of-sequence application bytes.
        endpoint = addr
        received.append(req)
        n = s.sendto(data, addr)
        if n != len(data):
            raise RuntimeError('short UDP send')
        emit('peer_sent token=0x%08x req=%d %s to=%s:%d t=%d' %
             (token, req, evidence(data), *addr, time.monotonic_ns()))
    emit('peer_stop received=%d bad=%d seed=%d' % (len(received), bad, int(seed_seen)))
    return 0 if received == list(REQUESTS) and bad == 0 and seed_seen else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--log', required=True)
    ap.add_argument('--run-token', required=True, type=lambda x: int(x, 0))
    ap.add_argument('--bind', default='192.168.50.122')
    ap.add_argument('--port', type=int, default=9110)
    ap.add_argument('--seconds', type=float, default=600)
    a = ap.parse_args()
    payload(a.run_token, 1)  # Validate the token before binding.
    if not 0 < a.seconds <= 900:
        raise ValueError('peer duration must be bounded to (0,900] seconds')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        s.bind((a.bind, a.port))
        with open(a.log, 'w', encoding='utf-8', newline='\n') as f:
            return serve(s, a.run_token, a.seconds,
                         lambda line: print(line, file=f, flush=True))


if __name__ == '__main__':
    raise SystemExit(main())
