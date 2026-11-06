#!/usr/bin/env python3
"""Round25 finite peer: validate every byte before echo; accept each ID once.

Runs on the Windows host. One nonmagic 1024-byte seed primes the observation
log; then the 512 monotonic declared business requests, each echoed only after its full
payload matched; and ordinary (non-selected) probes echoed at any time.

ROUND 22: the loop no longer stops after the 16th business request. Round 21's
version did, so the peer was already gone when the client sent its POST-EXIT
ordinary probes -- those three timeouts then looked exactly like "ordinary
traffic does not resume after the window", while the driver had in fact
resumed correctly and the peer had simply exited. The process is still bounded
by --seconds and --idle-exit; it just stops on TIME, not on request count.
"""
import argparse
import select
import socket
import time
from protocol import (REQUESTS, SEED, evidence, identify, ordinary_seq, payload)


# A full run is: reboot -> POST -> probe installs -> 3 s pre-window -> DTE flip
# -> 60 s main window -> recovery -> ioreg/capture. Minutes, not hours.
#
# Round23: raised from 600 to 1800 s on request. Round 23 spends extra boots on
# the network topology (the USB NIC is disabled for the whole round), and a peer
# that expires mid-session turns a healthy run into 16 timeouts that read like a
# driver fault -- round 22 lost a boot to exactly that. The bound still exists so
# an unbounded UDP listener cannot be left behind; it is just no longer shorter
# than a session.
PEER_MAX_SECONDS = 1800


def serve(s, token, seconds, emit, idle_exit=0):
    emit('peer_start bind=%s:%d token=0x%08x' % (*s.getsockname(), token))
    end = time.monotonic() + seconds
    last_seen = time.monotonic()
    received = []
    seen = set()
    bad = 0
    seed_seen = False
    endpoint = None
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
        # The seed is a LIVENESS probe and must answer EVERY time it is asked,
        # including after the business batch.
        #
        # Round 21 shipped `and not seed_seen` here, so later seeds were
        # received and dropped; round 22 then shipped `and not received`, which
        # made every seed AFTER the 16th request fall through to the business
        # path, be logged as payload_ok=0 and be silently NOT echoed. That
        # second form is why the pre-capture liveness check failed on a healthy
        # peer. A seed is never a business request, at any point in the run.
        if data == SEED:
            seed_seen = True
            emit('peer_seed_recv len=1024 nonmagic=1 from=%s:%d t=%d' % (*addr, when))
            n = s.sendto(data, addr)
            if n != len(data):
                raise RuntimeError('short seed send')
            emit('peer_seed_sent len=1024 to=%s:%d t=%d' % (*addr, time.monotonic_ns()))
            continue
        # Round22: ordinary traffic probes are echoed but NEVER counted as
        # business requests. They exist to prove that plain communication still
        # works before, during and after the translation window; counting them
        # as requests would corrupt the controlled request set, and rejecting
        # them as "bad" would make a correct run look failed.
        oseq = ordinary_seq(data)
        if oseq is not None:
            emit('peer_ord_recv seq=%d %s from=%s:%d t=%d' %
                 (oseq, evidence(data), *addr, when))
            n = s.sendto(data, addr)
            if n != len(data):
                raise RuntimeError('short ordinary send')
            emit('peer_ord_sent seq=%d to=%s:%d t=%d' %
                 (oseq, *addr, time.monotonic_ns()))
            continue
        ident = identify(data)
        req = ident[1] if ident else 0
        tok = ident[0] if ident else 0
        # Sending IDs is monotonic; UDP delivery within a group need not be.
        # A duplicate remains an error and is never echoed or credited twice.
        valid = (tok == token and req in REQUESTS and req not in seen and
                 data == payload(token, req) and (endpoint is None or addr == endpoint))
        emit('peer_recv token=0x%08x req=%d %s payload_ok=%d from=%s:%d t=%d' %
             (tok, req, evidence(data), int(valid), *addr, when))
        if not valid:
            bad += 1
            continue  # Never echo invalid or duplicate application bytes.
        endpoint = addr
        received.append(req)
        seen.add(req)
        n = s.sendto(data, addr)
        if n != len(data):
            raise RuntimeError('short UDP send')
        emit('peer_sent token=0x%08x req=%d %s to=%s:%d t=%d' %
             (token, req, evidence(data), *addr, time.monotonic_ns()))
    emit('peer_stop received=%d bad=%d seed=%d' % (len(received), bad, int(seed_seen)))
    return 0 if seen == set(REQUESTS) and bad == 0 and seed_seen else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--log', required=True)
    ap.add_argument('--run-token', required=True, type=lambda x: int(x, 0))
    ap.add_argument('--bind', default='192.168.50.122')
    ap.add_argument('--port', type=int, default=9110)
    ap.add_argument('--seconds', type=float, default=600)
    ap.add_argument('--idle-exit', type=float, default=0,
                    help='also stop after this many seconds with no packet at '
                         'all (0 disables); keeps a forgotten peer off the port '
                         'without cutting a live run short')
    a = ap.parse_args()
    payload(a.run_token, 1)  # Validate the token before binding.
    # Round21: the ceiling used to be 900 s with no relationship to anything
    # else. load.py waits at most 100 s for authorization and the probe refuses
    # maps 120 s after activation, so a peer outliving the run by eight minutes
    # is pure risk: it keeps the port and, worse, reads as "still running" the
    # next time somebody checks netstat. The bound stays (an unbounded UDP
    # listener is not acceptable) but now reflects the slowest legitimate run.
    if not 0 < a.seconds <= PEER_MAX_SECONDS:
        raise ValueError('peer duration must be bounded to (0,%d] seconds '
                         '(boot + window + batch fits in it); use --idle-exit '
                         'to also stop when nothing arrives' % PEER_MAX_SECONDS)
    if not 0 <= a.idle_exit < a.seconds:
        raise ValueError('--idle-exit must be in [0, seconds)')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        s.bind((a.bind, a.port))
        with open(a.log, 'w', encoding='utf-8', newline='\n') as f:
            return serve(s, a.run_token, a.seconds,
                         lambda line: print(line, file=f, flush=True),
                         idle_exit=a.idle_exit)


if __name__ == '__main__':
    raise SystemExit(main())
