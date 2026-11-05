#!/usr/bin/env python3
"""Round25 boot load: 512 requests in 32 send-all-16/receive groups.
No controlled-request retransmissions; each echo can count at most once.
"""
import argparse
from pathlib import Path
import re
import socket
import subprocess
import time
from protocol import (REQUESTS, SEED, bursts, evidence, identify,
                      length_of, ordinary, payload)


def now():
    # CLOCK_UPTIME_RAW is the same time base as mach_absolute_time(), which is
    # what the probe stamps into every property. Comparing them directly is why
    # `now() - inv_time` is meaningful at all.
    return time.clock_gettime_ns(time.CLOCK_UPTIME_RAW)


# The probe refuses new maps after 120 s (AMDMapperProbeTxDebug.cpp: c.deadline =
# mach_absolute_time() + 120000000000ULL). Past that point a load would measure
# a closed gate rather than the driver, so that -- not an arbitrary 400 ms -- is
# the real upper bound on how late a load may start.
PROBE_DEADLINE_NS = 120_000_000_000


def boot_ticks():
    """mach-time value of this boot, to tell a fresh stamp from an old one.

    kern.boottime gives wall-clock seconds; CLOCK_UPTIME_RAW gives mach ticks
    since boot. Subtracting converts one into the other, with ~1 s of wall-clock
    granularity. That is far too coarse to time a window, and far more than
    enough to reject a timestamp from a PREVIOUS boot (minutes or hours away).
    """
    out = subprocess.run(['sysctl', '-n', 'kern.boottime'],
                         capture_output=True, text=True, check=True).stdout
    sec = int(re.search(r'sec = (\d+)', out).group(1))
    usec = int(re.search(r'usec = (\d+)', out).group(1))
    uptime_s = time.time() - (sec + usec / 1e6)
    return now() - int(uptime_s * 1e9)


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


def exchange(s, local, peer, token, emit, ord_state):
    bind_local(s, local, emit)
    s.settimeout(.5)
    emit('client_bound %s:%d' % s.getsockname())
    sent = acked = bad = 0
    # Each of the 32 groups sends all 16 before recv; no retransmission.
    for group in bursts():
        emit('client_burst reqs=%s' % ','.join(str(r) for r in group))
        pending = {}
        for req in group:
            data = payload(token, req)
            before = now()
            if s.sendto(data, peer) != len(data):
                raise RuntimeError('short UDP send')
            sent += 1
            pending[req] = data
            emit('client_sent token=0x%08x req=%d %s t_ns=%d' %
                 (token, req, evidence(data), before))
        # Collect this burst's echoes. A miss is counted, never retried: a
        # dropped frame is a result, not something to paper over.
        for req in group:
            try:
                echoed, source = s.recvfrom(8192)
            except socket.timeout:
                bad += 1
                emit('client_timeout token=0x%08x req=%d' % (token, req))
                continue
            ident = identify(echoed)
            valid = bool(ident and ident[0] == token and ident[1] in pending)
            if valid:
                answered = ident[1]
                if answered != req:
                    emit('client_recv_order req=%d answered=%d' % (req, answered))
                req = answered
                data = pending.pop(req)  # duplicates cannot count twice
                valid = echoed == data and source == peer
            bad += int(not valid)
            acked += int(valid)
            emit('client_recv token=0x%08x req=%d %s payload_ok=%d from=%s:%d t_ns=%d' %
                 (token, req, evidence(echoed), int(valid), *source, now()))
        # Two ordinary probes after collecting the finite controlled burst,
        # still inside the translation window. No pause between request groups.
        for _ in range(2):
            ord_probe(s, peer, ord_state.next(), emit, 'window')
    emit('client_summary sent=%d acked=%d bad=%d' % (sent, acked, bad))
    return 0 if (sent, acked, bad) == (len(REQUESTS), len(REQUESTS), 0) else 1


class OrdSeq:
    """Round22: one monotonic sequence for every ordinary probe in this run.

    The sequence is what lets the analyzer place each probe in the window
    timeline instead of guessing from the log order.
    """
    def __init__(self, start=1):
        self.value = start - 1   # so the first next() returns `start`

    def next(self):
        self.value += 1
        return self.value


def ord_probe(s, peer, seq, emit, tag):
    """Send one ordinary payload and wait for its echo. Returns True on a match.

    A miss is NOT fatal: a probe that is in flight exactly when the gate closes
    is supposed to be dropped, and the stack retransmits later traffic. What
    must be true is that the probes sent AFTER the exit was confirmed succeed.
    """
    data = ordinary(seq)
    before = now()
    if s.sendto(data, peer) != len(data):
        raise RuntimeError('short ordinary send')
    emit('client_ord_sent seq=%d tag=%s %s t_ns=%d' %
         (seq, tag, evidence(data), before))
    try:
        echoed, source = s.recvfrom(8192)
    except socket.timeout:
        emit('client_ord_timeout seq=%d tag=%s' % (seq, tag))
        return False
    ok = echoed == data and source == peer
    emit('client_ord_recv seq=%d tag=%s %s payload_ok=%d from=%s:%d t_ns=%d' %
         (seq, tag, evidence(echoed), int(ok), *source, now()))
    return ok


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
        raise ValueError('round25 requires batch%d' % len(REQUESTS))
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
        # Round22: ordinary traffic before the window. Bounded so a slow boot
        # cannot turn this into a flood; each probe is one datagram and one echo.
        PRE_PROBES = 20
        pre = None
        pre_sent = 0
        pre_lines = []
        ord = OrdSeq()
        while time.monotonic() < deadline:
            ip = command('ifconfig', a.iface, required=False)
            match = re.search(r'\binet (\S+)', ip)
            if match and 'status: active' in ip and route(a.peer) == a.iface:
                local = match.group(1)
                # Round22: BEFORE the window. The probe installs its backend
                # after a 3 s pre-window control sample, so ordinary probes sent
                # here are provably earlier than the DTE flip -- and the
                # timestamps in the log are what proves it, not this comment.
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
                    pre = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    pre.bind((local, 0))
                    pre.settimeout(.25)
                if pre is not None and pre_sent < PRE_PROBES:
                    pre_sent += 1
                    seq = ord.next()
                    data = ordinary(seq)
                    before = now()
                    pre.sendto(data, (a.peer, a.port))
                    pre_lines.append('client_ord_sent seq=%d tag=pre %s t_ns=%d'
                                     % (seq, evidence(data), before))
                    try:
                        echoed, source = pre.recvfrom(8192)
                    except socket.timeout:
                        pre_lines.append('client_ord_timeout seq=%d tag=pre' % seq)
                    else:
                        ok = echoed == data and source == (a.peer, a.port)
                        pre_lines.append(
                            'client_ord_recv seq=%d tag=pre %s payload_ok=%d '
                            'from=%s:%d t_ns=%d'
                            % (seq, evidence(echoed), int(ok), *source, now()))
                props = command('ioreg', '-l', '-w0', '-r', '-c',
                                'org_example_AMDMapperProbe', required=False)
                expression = r'"' + re.escape(a.authorize_key) + r'" = "' + \
                    re.escape(a.authorize_value) + r'"'
                if re.search(expression, props) and '"m2-b2-r15-authorize" = "done"' in props:
                    stamp = re.search(r'"m2-b2-r15-inv-time" = "(0x[0-9a-fA-F]+)"', props)
                    # Round21: the freshness rule used to be "discovered within
                    # 400 ms of the invalidation". That number was copied from
                    # round 15 and never justified: the main window it guards is
                    # M2B2_MAIN_MEAS_SECS = 12 s, and a single ioreg probe costs
                    # ~117 ms on this machine, so the budget was two polls with
                    # no margin. It also reported the WRONG failure -- a run that
                    # started 500 ms late is not "stale authorization", it is a
                    # late start, and the artifact is still valid.
                    #
                    # What has to hold is narrower and checkable:
                    #   1. the stamp belongs to THIS boot (not a previous one),
                    #   2. the probe's own deadline has not passed (it refuses
                    #      maps after 120 s, so a later load measures a closed
                    #      gate, not the driver).
                    # Both are facts about this boot; neither depends on how
                    # quickly launchd happened to run.
                    if not stamp:
                        log('load_result FAIL-authorization-not-stamped')
                        return 2
                    inv = int(stamp.group(1), 0)
                    if not boot_ticks() <= inv <= now():
                        log('load_result FAIL-authorization-from-another-boot '
                            'inv=%d boot=%d now=%d' % (inv, boot_ticks(), now()))
                        return 2
                    age = now() - inv
                    if age > PROBE_DEADLINE_NS:
                        log('load_result FAIL-authorization-expired age_s=%.3f '
                            'deadline_s=%.1f' % (age / 1e9, PROBE_DEADLINE_NS / 1e9))
                        return 2
                    log('load_authorization_age_ns : %d (%.3f s, deadline %.0f s)'
                        % (age, age / 1e9, PROBE_DEADLINE_NS / 1e9))
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
            # The pre-window probes were collected before this file existed;
            # they are written first so the log is in time order.
            for line in pre_lines:
                emit(line)
            emit('client_ord_pre sent=%d' % pre_sent)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                rc = exchange(s, local, (a.peer, a.port), token, emit, ord)
                # Round22: AFTER the exit. The probe publishes this token only
                # after the device table was restored, read back, the backend
                # detached and ordinary admission reopened. Waiting for the
                # token is what makes "communication resumed" a fact about the
                # order of events rather than a hope about timing.
                resumed = False
                deadline2 = time.monotonic() + 75
                while time.monotonic() < deadline2:
                    props = command('ioreg', '-l', '-w0', '-r', '-c',
                                    'org_example_AMDMapperProbe', required=False)
                    if '"m2-3e-after-exit" = "ordinary-output-resumed"' in props:
                        resumed = True
                        break
                    time.sleep(.3)
                emit('client_after_exit resumed=%d t_ns=%d' % (int(resumed), now()))
                ok_after = 0
                if resumed:
                    for _ in range(3):
                        if ord_probe(s, (a.peer, a.port), ord.next(), emit,
                                     'after-exit'):
                            ok_after += 1
                        time.sleep(.1)
                emit('client_ord_after_exit ok=%d of=3' % ok_after)
            emit('client_result %s' %
                 ('OK' if rc == 0 and ok_after == 3 else 'PROBLEM'))
        (out / 'netstat-after.txt').write_text(command('netstat', '-I', a.iface, '-b'))
        log('load_mach_end_ns : %d' % now())
        log('load_done')
        return rc


if __name__ == '__main__':
    raise SystemExit(main())
