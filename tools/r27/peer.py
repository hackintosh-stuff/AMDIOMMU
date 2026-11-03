#!/usr/bin/env python3
"""Round36 finite UDP peer: byte validation, group-local reorder, no duplicates.

The 8192 R27P application requests are ordinary traffic to the driver.  Keep
echoing seed and ordinary probes after the batch so exit recovery is observable.
"""
import argparse
from pathlib import Path
import select
import socket
import time
from protocol import (BURST, REQUESTS, SEED, bursts, evidence, identify,
                      ordinary, ordinary_seq, payload, tail, tail_identify,
                      tail_done, tail_done_identify, TAIL_MAX)

PEER_MAX_SECONDS = 1800
ROOT = Path(__file__).resolve().parents[2]


def serve(s, token, seconds, emit, idle_exit=0):
    emit('peer_start bind=%s:%d token=0x%08x' % (*s.getsockname(), token))
    end = time.monotonic() + seconds
    last_seen = time.monotonic()
    received = set()
    groups = bursts()
    bad = 0
    seed_seen = False
    endpoint = None
    tail_seen = set()
    tail_done_seen = False
    while time.monotonic() < end:
        if idle_exit and time.monotonic() - last_seen > idle_exit:
            emit('peer_idle_exit idle_s=%.1f' % (time.monotonic() - last_seen))
            break
        if not select.select([s], [], [], min(.2, max(0, end - time.monotonic())))[0]:
            continue
        last_seen = time.monotonic()
        try:
            data, addr = s.recvfrom(8192)
        except ConnectionResetError:
            continue
        when = time.monotonic_ns()
        # The seed is repeatable liveness traffic, never an application request.
        if data == SEED:
            seed_seen = True
            emit('peer_seed_recv len=1024 nonmagic=1 from=%s:%d t=%d' % (*addr, when))
            if s.sendto(data, addr) != len(data):
                raise RuntimeError('short seed send')
            emit('peer_seed_sent len=1024 to=%s:%d t=%d' % (*addr, time.monotonic_ns()))
            continue
        oseq = ordinary_seq(data)
        if oseq is not None:
            valid = data == ordinary(oseq)
            emit('peer_ord_recv seq=%d %s payload_ok=%d from=%s:%d t=%d' %
                 (oseq, evidence(data), int(valid), *addr, when))
            if not valid:
                bad += 1
                continue
            if s.sendto(data, addr) != len(data):
                raise RuntimeError('short ordinary send')
            emit('peer_ord_sent seq=%d to=%s:%d t=%d' %
                 (oseq, *addr, time.monotonic_ns()))
            continue
        done_id = tail_done_identify(data)
        if done_id is not None:
            tok, seq = done_id
            valid = (tok == token and 1 <= seq <= TAIL_MAX and
                     not tail_done_seen and addr == endpoint and
                     received == set(REQUESTS) and
                     tail_seen == set(range(1, seq + 1)) and
                     data == tail_done(token, seq))
            emit('peer_tail_done_recv token=0x%08x seq=%d %s payload_ok=%d from=%s:%d t=%d' %
                 (tok, seq, evidence(data), int(valid), *addr, when))
            if not valid:
                bad += 1
                continue
            tail_done_seen = True
            if s.sendto(data, addr) != len(data):
                raise RuntimeError('short tail termination send')
            emit('peer_tail_done_sent token=0x%08x seq=%d %s to=%s:%d t=%d' %
                 (tok, seq, evidence(data), *addr, time.monotonic_ns()))
            continue
        tail_id = tail_identify(data)
        if tail_id is not None:
            tok, seq = tail_id
            valid = (tok == token and 1 <= seq <= TAIL_MAX and not tail_done_seen and
                     seq not in tail_seen and addr == endpoint and
                     received == set(REQUESTS) and data == tail(token, seq))
            emit('peer_tail_recv token=0x%08x seq=%d %s payload_ok=%d from=%s:%d t=%d' %
                 (tok, seq, evidence(data), int(valid), *addr, when))
            if not valid:
                bad += 1
                continue
            tail_seen.add(seq)
            if s.sendto(data, addr) != len(data):
                raise RuntimeError('short tail send')
            emit('peer_tail_sent token=0x%08x seq=%d %s to=%s:%d t=%d' %
                 (tok, seq, evidence(data), *addr, time.monotonic_ns()))
            continue
        ident = identify(data)
        req = ident[1] if ident else 0
        tok = ident[0] if ident else 0
        group_index = len(received) // BURST
        current = groups[group_index] if group_index < len(groups) else ()
        valid = (ident is not None and tok == token and req in current and
                 req not in received and data == payload(token, req) and
                 (endpoint is None or addr == endpoint))
        emit('peer_recv token=0x%08x req=%d %s payload_ok=%d from=%s:%d t=%d' %
             (tok, req, evidence(data), int(valid), *addr, when))
        if not valid:
            bad += 1
            continue
        endpoint = addr
        received.add(req)
        if s.sendto(data, addr) != len(data):
            raise RuntimeError('short UDP send')
        emit('peer_sent token=0x%08x req=%d %s to=%s:%d t=%d' %
             (token, req, evidence(data), *addr, time.monotonic_ns()))
    emit('peer_stop received=%d bad=%d seed=%d' % (len(received), bad, int(seed_seen)))
    return 0 if received == set(REQUESTS) and bad == 0 and seed_seen else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--log', default='runs/r36/peer.log')
    ap.add_argument('--run-token', required=True, type=lambda x: int(x, 0))
    ap.add_argument('--bind', default='192.168.50.122')
    ap.add_argument('--port', type=int, default=9110)
    ap.add_argument('--seconds', type=float, default=600)
    ap.add_argument('--idle-exit', type=float, default=0,
                    help='stop after this many seconds without any packet '
                         '(0 disables); allow boot, the 125 s idle period and exit')
    a = ap.parse_args()
    payload(a.run_token, 1)
    if not 0 < a.seconds <= PEER_MAX_SECONDS:
        raise ValueError('peer duration must be bounded to (0,%d] seconds' %
                         PEER_MAX_SECONDS)
    if not 0 <= a.idle_exit < a.seconds:
        raise ValueError('--idle-exit must be in [0, seconds)')
    log = Path(a.log)
    if not log.is_absolute():
        log = ROOT / log
    log.parent.mkdir(parents=True, exist_ok=True)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        s.bind((a.bind, a.port))
        with log.open('w', encoding='utf-8', newline='\n') as f:
            return serve(s, a.run_token, a.seconds,
                         lambda line: print(line, file=f, flush=True),
                         idle_exit=a.idle_exit)


if __name__ == '__main__':
    raise SystemExit(main())
