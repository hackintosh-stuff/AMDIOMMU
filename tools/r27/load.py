#!/usr/bin/env python3
"""Round40 device domain: 4096 requests, 125 s idle, another 4096, explicit stop.
Wait for fixed/RX IOVA mappings, then drive normal replacement and local stop.
Both phases run after setup worker exit in the same service-owned domain.
Only an active all-standard domain permits the batch; never retransmit requests.
"""
import argparse
import importlib.util
from pathlib import Path
import re
import socket
import subprocess
import time
from protocol import (REQUESTS, SEED, bursts, evidence, identify,
                      length_of, ordinary, payload, tail, tail_identify,
                      tail_done, tail_done_identify, TAIL_MAX)

ROOT = Path(__file__).resolve().parents[2]
_session_spec = importlib.util.spec_from_file_location('round31_session',
                                                      ROOT / 'tools/r31/session.py')
session = importlib.util.module_from_spec(_session_spec)
_session_spec.loader.exec_module(session)


def now():
    # CLOCK_UPTIME_RAW is the same time base as mach_absolute_time(), which is
    # what the probe stamps into every property. Comparing them directly is why
    # `now() - inv_time` is meaningful at all.
    return time.clock_gettime_ns(time.CLOCK_UPTIME_RAW)


# A finite client budget includes the deliberate idle interval. The kernel
# session itself has no timer: R31Stop is what begins the normal drain.
CLIENT_BUDGET_NS = 300_000_000_000
SESSION_IDLE_SECONDS = 125
SESSION_SPLIT = 4096


def observe_domain(emit, phase, expected=None):
    """Record the actual live domain before a normal traffic phase."""
    state = session.status()
    if (state.get('domain-mode') != 'service-owned' or
            state.get('domain-state') != 'active' or
            state.get('setup-worker-active') != 0 or
            state.get('install-count') != 1):
        raise RuntimeError('service-owned domain is not active after setup worker exit')
    keys = ('setup-worker-exit-time', 'root-pa', 'dt-pa', 'command-pa')
    identity = tuple(state.get(key, 0) for key in keys)
    if not all(isinstance(value, int) and value > 0 for value in identity):
        raise RuntimeError('domain ownership addresses or setup exit are missing')
    if expected is not None and identity != expected:
        raise RuntimeError('device domain changed between traffic phases')
    stamp = now()
    if identity[0] > stamp:
        raise RuntimeError('setup exit follows the live domain observation')
    emit('client_domain phase=%d mode=service-owned state=active setup_worker=0 '
         'setup_exit=%d root_pa=0x%x dt_pa=0x%x command_pa=0x%x installs=1 t_ns=%d' %
         (phase, *identity, stamp))
    return identity


def session_idle(emit, client_deadline_ns):
    if session.status().get('session-state') != 'active':
        raise RuntimeError('session is not active before idle')
    begin = now()
    emit('client_session_idle_begin seconds=%d state=active t_ns=%d' %
         (SESSION_IDLE_SECONDS, begin))
    end = begin + SESSION_IDLE_SECONDS * 1_000_000_000
    while True:
        current = now()
        if client_deadline_ns is not None and current >= client_deadline_ns:
            raise RuntimeError('client budget exhausted during session idle')
        if current >= end:
            break
        time.sleep(min(5, (end - current) / 1e9))
    if session.status().get('session-state') != 'active':
        raise RuntimeError('session did not remain active through idle')
    emit('client_session_idle_end state=active t_ns=%d' % now())


def request_session_stop(emit):
    stamp = now()
    emit('client_stop_begin request_ns=%d' % stamp)
    emit('client_session_stop_request t_ns=%d' % stamp)
    session.stop()
    emit('client_session_stop_ack t_ns=%d' % now())


def drain_tail(s, peer, token, emit):
    """Legacy finite-path helper; the current native session never calls it."""
    emit('client_drain_observed t_ns=%d' % now())
    sent = received = 0
    released = False
    deadline = time.monotonic() + 12
    s.settimeout(.25)
    while sent < TAIL_MAX and time.monotonic() < deadline:
        pending = set()
        for seq in range(sent + 1, min(sent + 17, TAIL_MAX + 1)):
            data = tail(token, seq)
            if s.sendto(data, peer) != len(data):
                raise RuntimeError('short tail send')
            emit('client_tail_send token=0x%08x seq=%d %s t_ns=%d' %
                 (token, seq, evidence(data), now()))
            pending.add(seq)
        sent += len(pending)
        group_end = min(deadline, time.monotonic() + 1)
        while pending and time.monotonic() < group_end:
            try:
                data, source = s.recvfrom(8192)
            except socket.timeout:
                continue
            ident = tail_identify(data)
            seq = ident[1] if ident else 0
            ok = (source == peer and ident == (token, seq) and seq in pending
                  and data == tail(token, seq))
            emit('client_tail_recv token=0x%08x seq=%d %s payload_ok=%d t_ns=%d' %
                 (token, seq, evidence(data), int(ok), now()))
            if not ok:
                return False
            pending.remove(seq)
            received += 1
        if pending:
            emit('client_tail_timeout pending=%s' % ','.join(map(str, sorted(pending))))
            break
        props = command('ioreg', '-l', '-w0', '-r', '-c',
                        'org_example_AMDMapperProbe', required=False)
        if '"m2-3h-rx-state" = "draining"' not in props:
            released = '"m2-3h-rx-state" = "drained-and-unmapped"' in props
            if released:
                emit('client_tail_drain_ended t_ns=%d' % now())
            break
        emit('client_tail_drain_still_active t_ns=%d' % now())
    emit('client_tail_summary sent=%d received=%d max=%d' % (sent, received, TAIL_MAX))
    if not released or sent == 0 or sent != received:
        return False

    # The RX release and tail-wait properties are published separately. All
    # issued tail echoes are already received; send no more tail batches.
    wait_end = min(deadline, time.monotonic() + 1)
    while '"m2-3i-tail-state" = "waiting"' not in props and time.monotonic() < wait_end:
        time.sleep(.02)
        props = command('ioreg', '-l', '-w0', '-r', '-c',
                        'org_example_AMDMapperProbe', required=False)
    remaining = deadline - time.monotonic()
    if ('"m2-3h-rx-state" = "drained-and-unmapped"' not in props or
            '"m2-3i-tail-state" = "waiting"' not in props or remaining <= 0):
        return False

    # One terminal echo closes the real tail before the probe closes TX.
    data = tail_done(token, sent)
    s.settimeout(min(1, remaining))
    before = now()
    if s.sendto(data, peer) != len(data):
        raise RuntimeError('short tail termination send')
    emit('client_tail_done_send token=0x%08x seq=%d %s t_ns=%d' %
         (token, sent, evidence(data), before))
    try:
        echoed, source = s.recvfrom(8192)
    except socket.timeout:
        emit('client_tail_done_timeout token=0x%08x seq=%d t_ns=%d' %
             (token, sent, now()))
        return False
    ident = tail_done_identify(echoed)
    seq = ident[1] if ident else 0
    ok = source == peer and ident == (token, sent) and echoed == data
    emit('client_tail_done_recv token=0x%08x seq=%d %s payload_ok=%d t_ns=%d' %
         (token, seq, evidence(echoed), int(ok), now()))
    return ok


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


def wait_local_address(iface, local, emit, timeout=20.0, delay=.25):
    """Wait until the interface really owns the declared address again.

    The local stop resets the NIC and rebuilds the physical ring, so macOS
    detaches and re-attaches the interface address around that transition. A
    socket bound to the old assignment then fails sendto with EADDRNOTAVAIL
    (errno 49). Waiting for the address to be listed again is honest waiting
    for the documented recovery, not a relaxed check: the address must be the
    declared one and the deadline still fails the run.
    """
    deadline = time.monotonic() + timeout
    wanted = 'inet %s ' % local
    attempt = 0
    while True:
        if wanted in command('ifconfig', iface, required=False):
            if attempt:
                emit('client_address_wait attempts=%d' % attempt)
            return True
        if time.monotonic() >= deadline:
            emit('client_address_wait timeout attempts=%d' % attempt)
            return False
        attempt += 1
        time.sleep(delay)


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


def exchange(s, local, peer, token, emit, ord_state, client_deadline_ns=None,
             persistent_session=False):
    bind_local(s, local, emit)
    s.settimeout(.5)
    emit('client_bound %s:%d' % s.getsockname())
    sent = acked = bad = 0
    if persistent_session:
        domain_identity = observe_domain(emit, 1)
        emit('client_session_phase phase=1 first=1 last=4096 t_ns=%d' % now())
    # Each of the 512 groups sends all 16 before recv; no retransmission.
    for group in bursts():
        if persistent_session and group[0] == SESSION_SPLIT + 1:
            session_idle(emit, client_deadline_ns)
            observe_domain(emit, 2, domain_identity)
            emit('client_session_phase phase=2 first=4097 last=8192 t_ns=%d' % now())
        if client_deadline_ns is not None and now() >= client_deadline_ns:
            emit('client_budget_expired sent=%d acked=%d' % (sent, acked))
            break
        emit('client_burst reqs=%s' % ','.join(str(r) for r in group))
        pending = {}
        for req in group:
            data = payload(token, req)
            before = now()
            if client_deadline_ns is not None and before >= client_deadline_ns:
                emit('client_budget_expired sent=%d acked=%d' % (sent, acked))
                break
            if s.sendto(data, peer) != len(data):
                raise RuntimeError('short UDP send')
            sent += 1
            pending[req] = data
            emit('client_sent token=0x%08x req=%d %s t_ns=%d' %
                 (token, req, evidence(data), before))
        # Collect this burst's echoes. A miss is counted, never retried: a
        # dropped frame is a result, not something to paper over.
        for req in tuple(pending):
            if client_deadline_ns is not None:
                remaining = (client_deadline_ns - now()) / 1e9
                if remaining <= 0:
                    break
                s.settimeout(min(.5, remaining))
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
                data = pending[req]
                valid = echoed == data and source == peer
                if valid:
                    pending.pop(req)  # duplicates cannot count twice
            bad += int(not valid)
            acked += int(valid)
            emit('client_recv token=0x%08x req=%d %s payload_ok=%d from=%s:%d t_ns=%d' %
                 (token, req, evidence(echoed), int(valid), *source, now()))
        # Two ordinary probes after collecting the finite application burst,
        # still inside the active translation session.
        for _ in range(2):
            if client_deadline_ns is not None:
                remaining = (client_deadline_ns - now()) / 1e9
                if remaining <= 0:
                    break
                s.settimeout(min(.5, remaining))
            ord_probe(s, peer, ord_state.next(), emit, 'window')
    emit('client_summary sent=%d acked=%d bad=%d' % (sent, acked, bad))
    return 0 if (sent, acked, bad) == (len(REQUESTS), len(REQUESTS), 0) else 1


class OrdSeq:
    """One monotonic sequence for every ordinary probe in this run.

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

    Record each miss without retrying so the analyzer can place it against the
    window timeline. All three probes AFTER confirmed exit must succeed.
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
    ap.add_argument('out', nargs='?', default='runs/r40')
    ap.add_argument('--iface', default='en2')
    ap.add_argument('--peer', default='192.168.50.122')
    ap.add_argument('--port', type=int, default=9110)
    ap.add_argument('--authorize-key', default='m2-3b-authorize')
    ap.add_argument('--authorize-value', default='done')
    a = ap.parse_args()
    out = Path(a.out)
    if not out.is_absolute():
        out = ROOT / out
    out.mkdir(parents=True, exist_ok=True)
    token = int((out / 'token.txt').read_text().strip(), 0)
    if int((out / 'batch.txt').read_text().strip()) != 512:
        raise ValueError('round27 keeps the kernel declaration batch512')
    if int((out / 'requests.txt').read_text().strip()) != len(REQUESTS):
        raise ValueError('round40 requires 8192 application requests')
    payload(token, 1)
    with (out / 'load.txt').open('w') as f:
        def log(line):
            print(line, file=f, flush=True)
        log('load_iface : %s' % a.iface)
        log('load_peer : %s:%d' % (a.peer, a.port))
        log('load_run_token : 0x%08x' % token)
        log('load_token_scope : userspace-only')
        log('load_payload_magic : R27P nonbusiness=1')
        log('load_requests : %d' % len(REQUESTS))
        log('load_kernel_batch : 512')
        log('load_payload_bytes : %s' % ','.join(
            '%d:%d' % (r, length_of(r)) for r in REQUESTS))
        deadline = time.monotonic() + 100
        seeded = False
        # Startup ordinary traffic. Bounded so a slow boot
        # cannot turn this into a flood; each probe is one datagram and one echo.
        PRE_PROBES = 20
        pre_sent = 0
        pre_lines = []
        ord = OrdSeq()
        while time.monotonic() < deadline:
            ip = command('ifconfig', a.iface, required=False)
            match = re.search(r'\binet (\S+)', ip)
            if match and 'status: active' in ip and route(a.peer) == a.iface:
                local = match.group(1)
                # Collect up to 20 startup probes before starting the batch.
                # Only their timestamps can establish whether each preceded
                # the DTE flip; a late launch must not invent pre-window proof.
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
                if pre_sent < PRE_PROBES:
                    # Entry now resets the NIC to program the fixed DMA IOVAs.
                    # Rebind each startup probe just as the accepted exit path
                    # does when configd republishes the interface address.
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as pre:
                        bind_local(pre, local, pre_lines.append, tries=20, delay=.25)
                        pre.settimeout(.25)
                        pre_sent += 1
                        ord_probe(pre, (a.peer, a.port), ord.next(),
                                  pre_lines.append, 'pre')
                props = command('ioreg', '-l', '-w0', '-r', '-c',
                                'org_example_AMDMapperProbe', required=False)
                expression = r'"' + re.escape(a.authorize_key) + r'" = "' + \
                    re.escape(a.authorize_value) + r'"'
                if re.search(expression, props):
                    if '"m2-3h-rx-ready" = "yes"' not in props:
                        time.sleep(.02)
                        continue
                    if '"m2-3h-rx-mode" = "native-ring-batch16"' not in props:
                        log('load_result FAIL-not-native-RX')
                        return 2
                    state = session.parse_status(props)
                    if state.get('session-mode') != 'explicit-stop':
                        log('load_result FAIL-not-explicit-stop-session')
                        return 2
                    if state.get('session-state') != 'active':
                        time.sleep(.02)
                        continue
                    if state.get('domain-mode') != 'service-owned':
                        log('load_result FAIL-not-service-owned-domain')
                        return 2
                    if (state.get('domain-state') != 'active' or
                            state.get('setup-worker-active') != 0 or
                            not state.get('setup-worker-exit-time')):
                        time.sleep(.02)
                        continue
                    if '"m2-3g-mode" = "all-standard"' not in props:
                        log('load_result FAIL-not-all-standard')
                        return 2
                    if '"m2-3e-after-exit"' in props:
                        log('load_result FAIL-window-already-exited')
                        return 2
                    stamp = re.search(r'"m2-3o-rx-ready-time" = "(0x[0-9a-fA-F]+)"', props)
                    # Preserve same-boot freshness. An active persistent
                    # session has no authorization-age expiry.
                    if not stamp:
                        log('load_result FAIL-authorization-not-stamped')
                        return 2
                    inv = int(stamp.group(1), 0)
                    boot = boot_ticks()
                    current = now()
                    if not boot <= inv <= current:
                        log('load_result FAIL-authorization-from-another-boot '
                            'inv=%d boot=%d now=%d' % (inv, boot, current))
                        return 2
                    age = current - inv
                    if pre_sent < PRE_PROBES:
                        continue
                    log('load_m2_3g_mode : all-standard')
                    log('load_m2_3h_rx : native-ring-batch16')
                    log('load_authorization_age_ns : %d (%.3f s, explicit-stop)'
                        % (age, age / 1e9))
                    log('load_session : 4096+4096 idle=125s explicit-stop=1 service-owned=1')
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
            emit('client_token_scope userspace-only')
            emit('client_payload_magic R27P nonbusiness=1')
            emit('client_m2_3g_mode all-standard')
            emit('client_session_mode explicit-stop')
            emit('client_requests %d' % len(REQUESTS))
            emit('client_route_interface %s' % a.iface)
            # The pre-window probes were collected before this file existed;
            # they are written first so the log is in time order.
            for line in pre_lines:
                emit(line)
            emit('client_ord_pre sent=%d' % pre_sent)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                rc = 1
                try:
                    rc = exchange(s, local, (a.peer, a.port), token, emit, ord,
                                  client_deadline_ns=now() + CLIENT_BUDGET_NS,
                                  persistent_session=True)
                except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                    emit('client_session_error %s' % exc)
                # One stop request per load, including an incomplete batch.
                # No client retry can disguise which action triggered drain.
                stop_ok = False
                try:
                    request_session_stop(emit)
                    stop_ok = True
                except (OSError, RuntimeError) as exc:
                    emit('client_session_stop_error %s' % exc)
                    rc = 1
                # AFTER the exit. The probe publishes this property only
                # after the device table was restored, read back, the backend
                # detached and ordinary admission reopened. Waiting for the
                # property is what makes "communication resumed" a fact about the
                # order of events rather than a hope about timing.
                resumed = False
                deadline2 = time.monotonic() + 90
                while time.monotonic() < deadline2:
                    props = command('ioreg', '-l', '-w0', '-r', '-c',
                                    'org_example_AMDMapperProbe', required=False)
                    # Stop makes no network requests. The driver stops DMA,
                    # retires the ring locally and restores ordinary traffic.
                    if ('"m2-3e-after-exit" = "ordinary-output-resumed"' in props and
                            session.parse_status(props).get('session-state') == 'stopped'):
                        resumed = True
                        stamp = now()
                        emit('client_session_stopped t_ns=%d' % stamp)
                        emit('client_stop_end stopped_ns=%d' % stamp)
                        break
                    time.sleep(.3)
                emit('client_after_exit resumed=%d t_ns=%d' % (int(resumed), now()))
                ok_after = 0
                if resumed and wait_local_address(a.iface, local, emit):
                    # The local stop detached and re-attached the interface
                    # address, so the pre-stop socket no longer has a usable
                    # source. Bind a fresh socket per probe on the restored
                    # address; a datagram that never left is not a retransmit.
                    for _ in range(3):
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ps:
                            try:
                                bind_local(ps, local, emit, tries=20, delay=.25)
                                ps.settimeout(.5)
                                if ord_probe(ps, (a.peer, a.port), ord.next(),
                                             emit, 'after-exit'):
                                    ok_after += 1
                            except OSError as exc:
                                emit('client_ord_after_exit error %s' % exc)
                        time.sleep(.1)
                emit('client_ord_after_exit ok=%d of=3' % ok_after)
                if not resumed or ok_after != 3 or not stop_ok:
                    rc = 1
            emit('client_result %s' %
                 ('OK' if rc == 0 and ok_after == 3 else 'PROBLEM'))
        (out / 'netstat-after.txt').write_text(command('netstat', '-I', a.iface, '-b'))
        log('load_mach_end_ns : %d' % now())
        log('load_done')
        return rc


if __name__ == '__main__':
    raise SystemExit(main())
