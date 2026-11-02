#!/usr/bin/env python3
"""Round17 boot load: one r15 nonmagic seed, fresh authorization, 32 serial UDP.

Each request waits for the previous echo and then pauses 150 ms, so exactly one
of this round's packets is in flight in the driver's single mapping slot at a
time. The batch is deliberately larger than the old four-request / eight
cumulative-record limits: that is what makes per-packet recycling observable.
"""
import argparse
from pathlib import Path
import re
import socket
import subprocess
import time
from protocol import REQUESTS, SEED, evidence, length_of, payload


def now():
    return time.clock_gettime_ns(time.CLOCK_UPTIME_RAW)


def command(*args, required=True):
    return subprocess.run(args, capture_output=True, text=True, check=required).stdout


def route(peer):
    text = command('route', '-n', 'get', peer, required=False)
    m = re.search(r'interface:\s*(\S+)', text)
    return m.group(1) if m else None


def bind_local(s, local, emit, tries=60, delay=.5):
    """Bind the declared source address, tolerating a boot-time address race.

    This launchd job starts at boot; on one run the address was already listed
    on en2 but the socket bind still returned EADDRNOTAVAIL (errno 49), i.e. the
    assignment had not finished at the socket layer. Retrying a bounded number
    of times is honest waiting, not a relaxed check: the address must be the
    declared one, and failure is still fatal after the deadline.
    """
    for attempt in range(tries):
        try:
            s.bind((local, 0))
            if attempt:
                emit('client_bind_retry attempts=%d' % (attempt + 1))
            return
        except OSError as exc:
            if exc.errno not in (49, 48) or attempt + 1 == tries:
                raise
            time.sleep(delay)


def exchange(s, local, peer, token, emit):
    bind_local(s, local, emit)
    s.settimeout(.5)
    emit('client_bound %s:%d' % s.getsockname())
    sent = acked = bad = 0
    for order, req in enumerate(REQUESTS):
        data = payload(token, req)
        before = now()
        if s.sendto(data, peer) != len(data):
            raise RuntimeError('short UDP send')
        sent += 1
        emit('client_sent token=0x%08x req=%d %s t_ns=%d' %
             (token, req, evidence(data), before))
        try:
            echoed, source = s.recvfrom(8192)
        except socket.timeout:
            bad += 1
            emit('client_timeout token=0x%08x req=%d' % (token, req))
        else:
            valid = echoed == data and source == peer
            bad += int(not valid)
            acked += int(valid)
            emit('client_recv token=0x%08x req=%d %s payload_ok=%d from=%s:%d t_ns=%d' %
                 (token, req, evidence(echoed), int(valid), *source, now()))
        if order + 1 < len(REQUESTS):
            time.sleep(.15)  # Serial application requests, no retransmit/flood.
    emit('client_summary sent=%d acked=%d bad=%d' % (sent, acked, bad))
    return 0 if (sent, acked, bad) == (len(REQUESTS), len(REQUESTS), 0) else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('out')
    ap.add_argument('--iface', default='en2')
    ap.add_argument('--peer', default='192.168.50.122')
    ap.add_argument('--port', type=int, default=9110)
    ap.add_argument('--authorize-key', default='m2-3b-authorize')
    ap.add_argument('--authorize-value', default='done')
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    token = int((out / 'token.txt').read_text().strip(), 0)
    if int((out / 'batch.txt').read_text().strip()) != len(REQUESTS):
        raise ValueError('round19 requires batch%d' % len(REQUESTS))
    payload(token, 1)
    with (out / 'load.txt').open('w') as f:
        def log(line):
            print(line, file=f, flush=True)
        log('load_iface : %s' % a.iface)
        log('load_peer : %s:%d' % (a.peer, a.port))
        log('load_run_token : 0x%08x' % token)
        log('load_requests : %d' % len(REQUESTS))
        log('load_payload_bytes : %s' % ','.join(
            '%d:%d' % (r, length_of(r)) for r in REQUESTS))
        deadline = time.monotonic() + 100
        seeded = False
        while time.monotonic() < deadline:
            ip = command('ifconfig', a.iface, required=False)
            match = re.search(r'\binet (\S+)', ip)
            if match and 'status: active' in ip and route(a.peer) == a.iface:
                local = match.group(1)
                if not seeded:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as seed:
                        seed.bind((local, 0))
                        seed.settimeout(.15)
                        seed.sendto(SEED, (a.peer, a.port))
                        try:
                            echoed, source = seed.recvfrom(8192)
                            valid = echoed == SEED and source == (a.peer, a.port)
                            log('load_seed_echo : %s nonmagic=1 at=%d' % (valid, now()))
                        except socket.timeout:
                            log('load_seed_echo : timeout nonmagic=1')
                    seeded = True
                props = command('ioreg', '-l', '-w0', '-r', '-c',
                                'org_example_AMDMapperProbe', required=False)
                expression = r'"' + re.escape(a.authorize_key) + r'" = "' + \
                    re.escape(a.authorize_value) + r'"'
                if re.search(expression, props) and '"m2-b2-r15-authorize" = "done"' in props:
                    stamp = re.search(r'"m2-b2-r15-inv-time" = "(0x[0-9a-fA-F]+)"', props)
                    if not stamp or not 0 <= now() - int(stamp.group(1), 0) <= 400000000:
                        log('load_result FAIL-authorization-already-stale')
                        return 2
                    break
            time.sleep(.05)
        else:
            log('load_result FAIL-no-fresh-authorization')
            return 2
        if route(a.peer) != a.iface:
            log('load_result FAIL-wrong-interface')
            return 2
        log('load_route_interface : %s' % a.iface)
        log('load_local : %s' % local)
        log('load_mach_at_start_ns : %d' % now())
        (out / 'netstat-before.txt').write_text(command('netstat', '-I', a.iface, '-b'))
        time.sleep(.08)
        with (out / 'client.log').open('w') as client:
            def emit(line):
                print(line, file=client, flush=True)
            emit('client_iface %s' % a.iface)
            emit('client_peer %s:%d' % (a.peer, a.port))
            emit('client_run_token 0x%08x' % token)
            emit('client_requests %d' % len(REQUESTS))
            emit('client_route_interface %s' % a.iface)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                rc = exchange(s, local, (a.peer, a.port), token, emit)
            emit('client_result %s' % ('OK' if rc == 0 else 'PROBLEM'))
        (out / 'netstat-after.txt').write_text(command('netstat', '-I', a.iface, '-b'))
        log('load_mach_end_ns : %d' % now())
        log('load_done')
        return rc


if __name__ == '__main__':
    raise SystemExit(main())
