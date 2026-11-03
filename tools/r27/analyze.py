#!/usr/bin/env python3
"""Round32: dynamic IOVA mappings in the explicit-stop RX1024 session.

The 8192 userspace request IDs are unrelated to the internal mapping-attempt
IDs. Cumulative counts cover all mapped TX; only the final 32 retirement
records carry individual PTE/lifecycle evidence. Legacy decoders are loaded
under a distinct module name and their full-history assertions are unchanged.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
import types


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
A = _load_module('_round27_legacy_decoders', HERE.parent / 'r21/analyze.py')
PROTOCOL = _load_module('_round27_application_protocol', HERE / 'protocol.py')
BURST, REQUESTS = PROTOCOL.BURST, PROTOCOL.REQUESTS
bursts, payload = PROTOCOL.bursts, PROTOCOL.payload

SCOPE = 'round32-dynamic-IOVA; normal-capacity-probe; explicit-stop-RX1024-session; 4096+4096-after-125s-idle'
REQUEST_COUNT = len(REQUESTS)
WINDOW_PROBES = 2 * len(bursts())
MIN_MAPPINGS = REQUEST_COUNT + WINDOW_PROBES
RX_VERSION, RX_COUNT = 4, 1024
RX_DRIVER_BYTES, RX_BACKEND_BYTES = 311376, 204864
RX_BASE, RX_STRIDE, RX_CAPACITY = 0x1000200000, 8192, 4096
ALL_STANDARD_MODE = 2
DOMAIN_VERSION, DOMAIN_HEADER, DOMAIN_RECORD_BYTES = 4, 80, 1304
DOMAIN_ARENA_PAGES, DOMAIN_MAX_MAP_PAGES, DOMAIN_SEGMENTS, MAPPING_SLOTS = 256, 32, 16, 16
HISTORY_CAPACITY = 32
TAIL = DOMAIN_HEADER + HISTORY_CAPACITY * DOMAIN_RECORD_BYTES
DOMAIN_PROBE_OFFSET = TAIL + 176
DOMAIN_BYTES = DOMAIN_PROBE_OFFSET + 2 * DOMAIN_RECORD_BYTES
DRIVER_VERSION, DRIVER_BYTES = 7, A.DRIVER_HEADER + HISTORY_CAPACITY * A.DRIVER_RECORD_BYTES
STD_VERSION, STD_BYTES = 5, A.STD_HEADER + HISTORY_CAPACITY * A.STD_RECORD_BYTES
# Snapshot.commandCapacity and m2-3b-command-capacity count 16-byte entries;
# M23_CMD_BUF_SIZE in the producer counts bytes. Do not compare unlike units.
COMMAND_RING_BYTES, COMMAND_ENTRY_BYTES = 8192, 16
COMMAND_CAPACITY = COMMAND_RING_BYTES // COMMAND_ENTRY_BYTES


def decode_domain_record(blob, at):
    r = A.unpack('handle tMapPublish tMapInv tClearPublish tRetireInv count '
                 'pages token req status maplen basePage recordIndex', '5Q8I', blob, at)
    r['segments'] = [A.unpack('pa bytes iova', '3Q', blob, at + 72 + j * 24)
                     for j in range(DOMAIN_SEGMENTS)]
    for j, key in enumerate(('physical', 'mapPte', 'clearPte')):
        r[key] = struct.unpack_from('<32Q', blob, at + 456 + j * 256)
    r['mapCommand'] = A.cmdrec(blob, at + 1224)
    r['retireCommand'] = A.cmdrec(blob, at + 1264)
    return r


def decode_domain(blob):
    A.need(len(blob) == DOMAIN_BYTES, 'domain v4 size must be %d' % DOMAIN_BYTES)
    h = A.unpack('version bytes count flags iovaBase iovaBytes rootPA leafPA '
                 'ptBase ptBytes rootLevel devid domid active', '4I6Q4I', blob)
    A.need(h['version'] == DOMAIN_VERSION and h['bytes'] == len(blob), 'domain v4 ABI missing')
    h.update(A.unpack('historyTotal historyStart mapsTotal retiresTotal '
                      'commandCapacity commandSubmits commandCompleted commandWraps '
                      'commandPostWrapCompleted liveOwners slotsUsed maxLiveOwners ' +
                      ' '.join('slotUse%d' % i for i in range(MAPPING_SLOTS)) +
                      ' completionSequence livePages peakPages maxMappedPages reusedAllocations '
                      'probeMaps probeUnmaps probePeakOwners probeMaxPages probePassed probeReused '
                      'probeStart probeEnd', '28IQ10I2Q', blob, TAIL))
    rows = [decode_domain_record(blob, DOMAIN_HEADER + i * DOMAIN_RECORD_BYTES)
            for i in range(HISTORY_CAPACITY)]
    h['probeFirst'] = decode_domain_record(blob, DOMAIN_PROBE_OFFSET)
    h['probeReuse'] = decode_domain_record(blob, DOMAIN_PROBE_OFFSET + DOMAIN_RECORD_BYTES)
    return h, rows


def decode_std(blob):
    # Reuse the unchanged record decoder with its version constant scoped to
    # this call; never mutate analyze.py globals or its legacy full-history gate.
    A.need(len(blob) == STD_BYTES, 'standard v5 snapshot size differs')
    decoder = types.FunctionType(A.decode_std.__code__, dict(A.__dict__, STD_VERSION=STD_VERSION))
    h, rows = decoder(blob)
    h['historyTotal'], h['historyStart'], h['highReqAccepts'] = h.pop('r0'), h.pop('r1'), h.pop('r2')
    return h, rows


def retained(h, rows, total_key, expected_total):
    total, start, count = h[total_key], h['historyStart'], h['count']
    A.need(total == expected_total and total >= MIN_MAPPINGS and
           count == HISTORY_CAPACITY and start == total - HISTORY_CAPACITY,
           'expected total=N>=%d/count32/start=N-32' % MIN_MAPPINGS)
    return [rows[seq % 32] for seq in range(start, total)]


def decode_rx(blob):
    A.need(len(blob) == RX_DRIVER_BYTES, 'RX driver snapshot must be %d bytes' % RX_DRIVER_BYTES)
    h = A.unpack('version bytes state flags generation mapCount posted completed '
                 'restored pendingPosted businessToken tailSeq poolId tInstalled '
                 'tDisarmed tLastRestore', '12I4Q', blob)
    A.need(h['version'] == RX_VERSION and h['bytes'] == len(blob), 'RX driver ABI differs')
    maps = [A.unpack('pa iova tMapInv entryId capacity', '3Q2I', blob, 80 + i * 32)
            for i in range(RX_COUNT)]
    rows = []
    for i in range(RX_COUNT):
        at = 80 + RX_COUNT * 32 + i * 272
        w = A.unpack('originalPA sparePA iova tPost tDone tRestoreOwn '
                     'slot entryId flags token reqId doneLength doneStatus reserved',
                     '6Q8I', blob, at)
        w.update(A.unpack('tLastPost tLastDone postCount doneCount reuseCount sampleCount',
                          '2Q4I', blob, at + 80))
        w['samples'] = [A.unpack('tPost tDone cycle token reqId doneLength doneStatus flags',
                                 '2Q6I', blob, at + 112 + j * 40) for j in range(4)]
        rows.append(w)
    return h, maps, rows


def decode_rx_backend(blob):
    A.need(len(blob) == RX_BACKEND_BYTES, 'RX backend snapshot must be %d bytes' % RX_BACKEND_BYTES)
    h = A.unpack('version bytes flags count mapCalls mapOk mapRejects unmapCalls '
                 'unmapOk liveOwners ready reserved tReady tDrained', '12I2Q', blob)
    A.need(h['version'] == RX_VERSION and h['bytes'] == len(blob), 'RX backend ABI differs')
    rows = []
    for i in range(RX_COUNT):
        at = 64 + i * 200
        r = A.unpack('pa iova mapLength tMapPublish tMapInv tUnmapPublish tUnmapInv',
                     '7Q', blob, at)
        r['mapPte'] = struct.unpack_from('<2Q', blob, at + 56)
        r['clearPte'] = struct.unpack_from('<2Q', blob, at + 72)
        r.update(A.unpack('entryId capacity pages mapOptions mapResult unmapResult flags reserved',
                          '8I', blob, at + 88))
        r['mapCommand'] = A.cmdrec(blob, at + 120)
        r['unmapCommand'] = A.cmdrec(blob, at + 160)
        rows.append(r)
    return h, rows


def rx_leaf_address(pt, root_pa, pt_base, level, iova):
    """Find this stripe's L1 table through the exported parent entries.

    RX1024 spans five L1 tables. The TX snapshot's leafPA identifies only the
    first one, so it cannot locate every RX leaf after the window grows.
    """
    A.need(level in (3, 4), 'impossible RX root level')
    pa = root_pa
    while level > 1:
        A.need(pa & 4095 == 0 and 0 <= pa - pt_base <= len(pt) - 4096,
               'RX parent table outside the exported arena')
        index = (iova >> (12 + 9 * (level - 1))) & 511
        entry = struct.unpack_from('<Q', pt, pa - pt_base + 8 * index)[0]
        A.need(entry & 1 and entry & A.PTE_IR and (entry >> 9) & 7 == level - 1,
               'RX parent table missing or wrong level')
        pa = entry & 0x000FFFFFFFFFF000
        level -= 1
    return pa


def check(cap):
    cap = Path(cap)
    checks = []
    mapped_total = None
    def run(name, fn):
        try:
            detail = fn()
            checks.append({'id': name, 'state': 'ok', 'detail': detail})
        except (A.Refused, OSError, ValueError, KeyError, IndexError, struct.error) as exc:
            checks.append({'id': name, 'state': 'FAIL', 'detail': str(exc)})
    def result():
        return {'scope': SCOPE, 'ok': bool(checks) and all(c['state'] == 'ok' for c in checks),
                'checks': checks, 'limitations': [
                'Only the retained 32 retirement records have individual PTE/lifecycle evidence; '
                '%s overwritten records are not individually proved.' %
                (mapped_total - HISTORY_CAPACITY if mapped_total is not None and
                 mapped_total >= HISTORY_CAPACITY else 'earlier'),
                'Application IDs 1..8192 are userspace integrity IDs, not TX mapping-attempt IDs; RX business correlation uses observed R27P headers.',
                'Application logs prove bytes; cumulative counters prove all-TX standard-path totals; '
                'retained 32 prove PTE/lifecycle relations.']}
    try:
        _, _, P, blob = A.read_capture(cap)
        dh, dom = decode_domain(blob('m2-3b-domain-raw', 'r21-domain-raw.bin'))
        # Capacity-probe mappings are ordinary mapper calls, counted honestly
        # in the domain totals but not in the driver's transmitted-frame totals.
        mapped_total = dh['mapsTotal'] - dh['probeMaps']
        gh, drv = A.decode_driver(blob('rtl812x-txmap-raw', 'r21-driver-raw.bin'))
        gh['historyStart'] = gh.pop('reserved')
        A.need(gh['version'] == DRIVER_VERSION and len(drv) == HISTORY_CAPACITY and gh['bytes'] == DRIVER_BYTES,
               'native v7 ABI missing')
        sh, std = decode_std(blob('rtl812x-txmap-std-raw', 'r21-std-raw.bin'))
        bh = A.decode_block(blob('rtl812x-txmap-block-raw', 'r21-block-raw.bin'))
        pt = blob('m2-3b-pt-raw', 'r21-pt-raw.bin')
        rh, rxmaps, rxwitnesses = decode_rx(blob('m2-3h-rx-raw', 'r27-rx-raw.bin'))
        rb, rxrecords = decode_rx_backend(blob('m2-3h-rx-map-raw', 'r27-rx-map-raw.bin'))
        client = (cap / 'client.log').read_text(encoding='utf-8')
        peer = (cap / 'peer.log').read_text(encoding='utf-8')
        driver = (cap / 'driver-obs.txt').read_text(encoding='utf-8')
        token = gh['token']
        A.need(0 < token < 0x80000000 and sh['token'] == bh['token'] == token,
               'inconsistent/non-low-half token')
        A.need(dh['devid'] == gh['bdf'] == sh['bdf'] == bh['bdf'], 'capture device association differs')
        checks.append({'id': 'capture-ABI-domain4-native7-std5-rx4', 'state': 'ok'})
    except (A.Refused, OSError, ValueError, KeyError, IndexError, struct.error) as exc:
        checks.append({'id': 'capture-ABI-domain4-native7-std5-rx4', 'state': 'FAIL', 'detail': str(exc)})
        return result()

    def driver_property(key, numeric=False):
        pattern = r'"' + re.escape(key) + r'"\s*=\s*(?:"([^"\n]*)"|(0x[0-9a-fA-F]+|\d+))(?=\s|$)'
        matches = list(re.finditer(pattern, driver))
        A.need(len(matches) == 1, 'missing or repeated driver property: ' + key)
        value = matches[0][1] if matches[0][1] is not None else matches[0][2]
        if numeric:
            A.need(re.fullmatch(r'0x[0-9a-fA-F]+|\d+', value) is not None,
                   'not an unsigned driver counter: ' + key)
            return int(value, 16 if value.startswith('0x') else 10)
        return value

    def logs():
        records = {}
        for text, names in ((client, ('client_sent', 'client_recv')),
                            (peer, ('peer_recv', 'peer_sent'))):
            for name in names:
                lines = [(i, line) for i, line in enumerate(text.splitlines())
                         if line.startswith(name + ' ')]
                ids = []
                for _, line in lines:
                    m = re.match(name + r' token=(0x[0-9a-fA-F]+) req=(\d+) len=(\d+) '
                                 r'sha256=([0-9a-f]{64}) payload=([0-9a-f]+)(?: |$)', line)
                    A.need(m is not None, 'malformed ' + name)
                    tok, req, size, sha, data = int(m[1], 16), int(m[2]), int(m[3]), m[4], bytes.fromhex(m[5])
                    A.need(tok == token and data == payload(token, req) and len(data) == size and
                           hashlib.sha256(data).hexdigest() == sha, 'invalid bytes/hash/token: ' + name)
                    if name in ('peer_recv', 'client_recv'):
                        A.need(re.search(r'(?:^| )payload_ok=1(?: |$)', line) is not None,
                               name + ': payload/source was rejected')
                    ids.append(req)
                A.need(len(ids) == len(REQUESTS) and set(ids) == set(REQUESTS),
                       name + ': missing or duplicate requests')
                if name == 'client_sent':
                    A.need(ids == list(REQUESTS), 'client sends are not monotonic')
                else:
                    # UDP receives/echoes may permute inside a burst. The client
                    # must finish that burst before admitting the next one.
                    for i, group in enumerate(bursts()):
                        A.need(set(ids[i * BURST:(i + 1) * BURST]) == set(group),
                               name + ': request crossed a burst boundary')
                records[name] = [(at, name.rsplit('_', 1)[1], req)
                                 for (at, _), req in zip(lines, ids)]
        client_lines = client.splitlines()
        A.need([line for line in client_lines if line.startswith('client_summary ')] ==
               ['client_summary sent=%d acked=%d bad=0' % (REQUEST_COUNT, REQUEST_COUNT)] and
               [line for line in client_lines if line.startswith('client_result ')] == ['client_result OK'],
               'client success summary missing')
        A.need(not any(line.startswith('client_timeout ') for line in client_lines),
               'application request timed out')
        events = sorted(records['client_sent'] + records['client_recv'])
        A.need(len(events) == 2 * REQUEST_COUNT, 'unexpected event count')
        markers = [(i, line) for i, line in enumerate(client_lines) if line.startswith('client_burst ')]
        A.need(len(markers) == len(bursts()), 'expected %d groups' % len(bursts()))
        for i, requests in enumerate(bursts()):
            group = events[i * 2 * BURST:(i + 1) * 2 * BURST]
            A.need([e[1] for e in group] == ['sent'] * BURST + ['recv'] * BURST,
                   'group not all16 send-before-receive')
            at, marker = markers[i]
            A.need(marker == 'client_burst reqs=' + ','.join(map(str, requests)) and
                   (i == 0 or events[i * 2 * BURST - 1][0] < at) and at < group[0][0],
                   'burst declaration or position differs')
        peer_events = sorted(records['peer_recv'] + records['peer_sent'])
        for i in range(len(REQUESTS)):
            recv, sent = peer_events[2 * i:2 * i + 2]
            A.need(recv[1] == 'recv' and sent[1] == 'sent' and recv[2] == sent[2],
                   'peer echo was not paired with its validated receive')
        return {'requests': REQUEST_COUNT, 'groups': len(bursts()), 'groupSize': BURST, 'duplicates': 0,
                'receiveOrder': 'permutation within each group only'}
    run('full8192-bytes-no-retry-no-duplicate-credit', logs)

    def session_lifecycle():
        A.need(P.get('m2-3l-session-mode') == 'explicit-stop' and
               P.get('m2-3l-session-state') == 'stopped',
               'explicit-stop session did not finish stopped')
        A.need(P.get('m2-3l-tx-deadline') == 0 and
               P.get('m2-b2-r15-authorize-deadline') == 0,
               'TX/RX authorization still has a timed deadline')
        start = P['m2-3l-session-start']
        stopped = P['m2-3l-stop-request-time']
        end = P['m2-3l-session-end']

        def one(pattern, name):
            values = re.findall('^' + pattern + '$', client, re.M)
            A.need(len(values) == 1, 'missing/repeated session ' + name)
            return int(values[0])

        phase1 = one(r'client_session_phase phase=1 first=1 last=4096 t_ns=(\d+)', 'phase1')
        phase2 = one(r'client_session_phase phase=2 first=4097 last=8192 t_ns=(\d+)', 'phase2')
        idle_begin = one(r'client_session_idle_begin seconds=125 state=active t_ns=(\d+)', 'idle begin')
        idle_end = one(r'client_session_idle_end state=active t_ns=(\d+)', 'idle end')
        request = one(r'client_session_stop_request t_ns=(\d+)', 'stop request')
        ack = one(r'client_session_stop_ack t_ns=(\d+)', 'stop acknowledgement')
        observed_end = one(r'client_session_stopped t_ns=(\d+)', 'stopped observation')
        halves = ([], [])
        for req, stamp in re.findall(r'^client_(?:sent|recv) .* req=(\d+) .* t_ns=(\d+)$', client, re.M):
            halves[int(req) > 4096].append(int(stamp))
        A.need(len(halves[0]) == len(halves[1]) == 8192,
               'session phases do not each contain 4096 requests and replies')
        A.need(0 < rb['tReady'] <= start <= phase1 <= min(halves[0]) <= max(halves[0]) <= idle_begin and
               idle_end <= phase2 <= min(halves[1]) <= max(halves[1]) <= request,
               'session request phases overlap idle or stop')
        A.need(idle_end - idle_begin >= 125_000_000_000 and
               min(halves[1]) - start > 120_000_000_000,
               'second 4096 requests did not survive the old 60/120-second limits')
        A.need(request <= stopped <= ack and stopped <= rh['tDisarmed'] and
               rh['tDisarmed'] < P['m2-3i-tail-confirmed-time'] <=
               P['m2-3e-t-resume'] <= end <= observed_end,
               'explicit stop/drain/tail/restore/session-end order differs')
        return {'mode': 'explicit-stop', 'state': 'stopped', 'requestsPerPhase': 4096,
                'idleSeconds': (idle_end - idle_begin) / 1e9,
                'secondPhaseAfterSeconds': (min(halves[1]) - start) / 1e9,
                'stopRequests': 1, 'txDeadline': 0, 'rxDeadline': 0,
                'durationSeconds': (end - start) / 1e9}
    run('persistent-session-125s-idle-second4096-explicit-stop-and-restore', session_lifecycle)

    def drain_tail():
        observed = re.findall(r'^client_drain_observed t_ns=(\d+)$', client, re.M)
        A.need(len(observed) == 1 and rh['tDisarmed'] <= int(observed[0]) < P['m2-3i-tail-confirmed-time'],
               'published drain observation missing/outside tail phase')
        groups = {}
        for text, names in ((client, ('client_tail_send', 'client_tail_recv')),
                            (peer, ('peer_tail_recv', 'peer_tail_sent'))):
            for name in names:
                rows = {}
                for line in text.splitlines():
                    if not line.startswith(name + ' '):
                        continue
                    m = re.fullmatch(name + r' token=(0x[0-9a-fA-F]+) seq=(\d+) len=(\d+) '
                                     r'sha256=([0-9a-f]{64}) payload=([0-9a-f]+)'
                                     r'(?: payload_ok=(1))?(?: (?:from|to)=[^ ]+)? t(?:_ns)?=(\d+)', line)
                    A.need(m is not None, 'malformed drain tail: ' + name)
                    tok, seq, size = int(m[1], 16), int(m[2]), int(m[3])
                    data, stamp = bytes.fromhex(m[5]), int(m[7])
                    A.need(tok == token and 1 <= seq <= 4096 and seq not in rows and
                           data == PROTOCOL.tail(token, seq) and len(data) == size and
                           hashlib.sha256(data).hexdigest() == m[4], 'tail identity/bytes/hash differs')
                    if name.endswith('recv'):
                        A.need(m[6] == '1', 'tail receive not validated')
                    if name.startswith('client_'):
                        A.need(int(observed[0]) <= stamp and rh['tDisarmed'] <= stamp,
                               'tail precedes published drain')
                    rows[seq] = stamp
                groups[name] = rows
        sent, received = groups['client_tail_send'], groups['client_tail_recv']
        A.need(sent and set(sent) == set(received) == set(groups['peer_tail_recv']) ==
               set(groups['peer_tail_sent']) and set(sent) == set(range(1, len(sent) + 1)),
               'missing/duplicate drain-tail exchange')
        after_exit = re.findall(r'^client_after_exit resumed=1 t_ns=(\d+)$', client, re.M)
        drain_checks = re.findall(r'^client_tail_drain_(ended|still_active) t_ns=(\d+)$', client, re.M)
        A.need(len(after_exit) == 1 and
               max(list(sent.values()) + list(received.values())) < int(after_exit[0]),
               'tail extended beyond its final burst/after-exit')
        A.need(len(drain_checks) == (len(sent) + 15) // 16 and
               all(kind == 'still_active' for kind, _ in drain_checks[:-1]) and
               drain_checks[-1][0] == 'ended',
               'missing/repeated/intermediate drain-end observation')
        for group, (_, stamp) in enumerate(drain_checks):
            ids = range(group * 16 + 1, min((group + 1) * 16, len(sent)) + 1)
            A.need(max(received[seq] for seq in ids) <= int(stamp) < int(after_exit[0]),
                   'drain-state check precedes its completed burst')
            if (group + 1) * 16 < len(sent):
                A.need(int(stamp) <= sent[(group + 1) * 16 + 1], 'tail started next burst before drain-state check')
        for seq in sent:
            A.need(sent[seq] <= received[seq] and
                   groups['peer_tail_recv'][seq] <= groups['peer_tail_sent'][seq], 'tail event order differs')
        A.need(re.findall(r'^client_tail_summary .*$', client, re.M) ==
               ['client_tail_summary sent=%d received=%d max=4096' % (len(sent), len(received))],
               'drain-tail summary missing/inconsistent')
        main_times = [int(t) for t in re.findall(r'^client_(?:sent|recv) .* t_ns=(\d+)$', client, re.M)]
        A.need(len(main_times) == 2 * REQUEST_COUNT and main_times == sorted(main_times) and
               max(main_times) <= int(observed[0]), 'main traffic timing overlaps drain tail')
        return {'sent': len(sent), 'received': len(received), 'max': 4096,
                'beganDuringPhysicalDrain': min(sent.values()) <= rh['tLastRestore']}
    run('published-drain-R28T-tail-integrity', drain_tail)

    def tail_done():
        last = re.findall(r'^client_tail_summary sent=(\d+) received=(\d+) max=4096$', client, re.M)
        A.need(len(last) == 1 and last[0][0] == last[0][1], 'tail count before done is not closed')
        seq = int(last[0][0])
        A.need(1 <= seq <= PROTOCOL.TAIL_MAX and seq == rh['tailSeq'] == P['m2-3i-tail-seq'],
               'tail-done sequence differs from client/driver/probe')
        stamps = {}
        for text, names in ((client, ('client_tail_done_send', 'client_tail_done_recv')),
                            (peer, ('peer_tail_done_recv', 'peer_tail_done_sent'))):
            for name in names:
                lines = [line for line in text.splitlines() if line.startswith(name + ' ')]
                A.need(len(lines) == 1, 'tail-done must occur exactly once: ' + name)
                m = re.fullmatch(name + r' token=(0x[0-9a-fA-F]+) seq=(\d+) len=(\d+) '
                                 r'sha256=([0-9a-f]{64}) payload=([0-9a-f]+)'
                                 r'(?: payload_ok=(1))?(?: (?:from|to)=[^ ]+)? t(?:_ns)?=(\d+)', lines[0])
                A.need(m is not None, 'malformed tail-done: ' + name)
                data = bytes.fromhex(m[5])
                A.need(int(m[1], 16) == token and int(m[2]) == seq and
                       data == PROTOCOL.tail_done(token, seq) and int(m[3]) == len(data) == 12 and
                       m[4] == hashlib.sha256(data).hexdigest(), 'tail-done bytes/token/hash mismatch')
                if name.endswith('recv'):
                    A.need(m[6] == '1', 'tail-done receive was rejected')
                stamps[name] = int(m[7])
        tail_receives = [int(t) for t in re.findall(r'^client_tail_recv .* t_ns=(\d+)$', client, re.M)]
        A.need(len(tail_receives) == seq and max(tail_receives) <= stamps['client_tail_done_send'] <=
               stamps['client_tail_done_recv'], 'tail-done preceded the last completed tail batch')
        A.need(stamps['peer_tail_done_recv'] <= stamps['peer_tail_done_sent'], 'peer done echo order differs')
        # The parser observes the echo before enqueueInputPacket. Userland may
        # receive that already-enqueued echo after the probe closes the TX gate.
        confirmed = P['m2-3i-tail-confirmed-time']
        A.need(P['m2-3i-tail-state'] == 'confirmed' and rh['state'] == 4 and not rh['pendingPosted'] and
               max(r['tUnmapInv'] for r in rxrecords) <= confirmed and
               stamps['client_tail_done_send'] <= confirmed <= P['m2-3e-exit-gate-close'],
               'TX closed before the restored RX ring observed the tail-done echo')
        after = re.findall(r'^client_after_exit resumed=1 t_ns=(\d+)$', client, re.M)
        A.need(len(after) == 1 and stamps['client_tail_done_recv'] < int(after[0]),
               'exit declared before client validated the done echo')
        return {'sequence': seq, 'bytes': 12, 'confirmationObserved': confirmed,
                'clientEchoReceived': stamps['client_tail_done_recv'], 'retries': 0}
    run('R29D-tail-finished-before-TX-close', tail_done)

    def counters():
        A.need(mapped_total >= MIN_MAPPINGS, 'fewer than %d mapped ordinary TX frames' % MIN_MAPPINGS)
        A.need(dh['probeMaps'] == dh['probeUnmaps'] and
               all(dh[k] == mapped_total + dh['probeMaps']
                   for k in ('mapsTotal', 'retiresTotal', 'historyTotal')),
               'domain totals do not equal transmitted TX plus capacity-probe mappings')
        for h, keys in ((sh, ('accepts', 'unmaps', 'historyTotal')), (gh, ('retired',))):
            A.need(all(h[k] == mapped_total for k in keys),
                   'cumulative map/unmap/retirement total differs: ' + str({k: h[k] for k in keys}))
        A.need(sh['mode'] == ALL_STANDARD_MODE and
               driver_property('R26TxMode') == 'all-standard' and
               P['m2-3g-mode'] == 'all-standard' and
               P['m2-3c-mode'] == 'standard-iomapper' and
               driver_property('rtl812x-txmap-mode') == 'native-mbuf-standard-iomapper-v1',
               'mode 2 all-standard evidence missing')
        totals = {key: driver_property('R26Tx' + key, True)
                  for key in ('Mapped', 'Unmarked', 'LegacySelected', 'Attempts')}
        A.need(totals['Mapped'] == mapped_total == totals['Unmarked'] + totals['LegacySelected'] and
               totals['Unmarked'] >= MIN_MAPPINGS and totals['Attempts'] >= mapped_total,
               'all-TX mapped/unmarked/legacy/attempt counts disagree')
        for key in ('m2-3c-map-calls', 'm2-3c-map-ok', 'm2-3c-unmap-ok',
                    'm2-3b-map-accepted', 'm2-3b-retires'):
            A.need(P[key] == dh['mapsTotal'], key + ' !=TX+probe')
        for key in ('m2-3c-insert-calls', 'm2-3c-map-rejects', 'm2-3b-map-rejected',
                    'm2-3c-cover-calls'):
            A.need(P[key] == 0, key + ' !=0')
        A.need(driver_property('rtl812x-txmap-cover-calls', True) == 0,
               'ordinary TX used the identity cover path')
        A.need(not any(sh[k] for k in ('rejects', 'unsupported', 'pinned')) and
               not any(gh[k] for k in ('dropped', 'rejected')), 'driver fallback/refusal/pin')
        return dict(totals, mode=ALL_STANDARD_MODE, standardAccepts=mapped_total,
                    standardUnmaps=sh['unmaps'], retired=gh['retired'], coverCalls=0,
                    domainMaps=dh['mapsTotal'], capacityProbeMaps=dh['probeMaps'])
    run('all-TX-standard-mode2-cumulative-and-unmarked-no-cover', counters)

    def mapped_pages(record):
        A.need(record['handle'] > 0 and record['status'] == 3 and
               1 <= record['count'] <= DOMAIN_SEGMENTS and
               1 <= record['pages'] <= DOMAIN_MAX_MAP_PAGES and
               0 <= record['basePage'] <= DOMAIN_ARENA_PAGES - record['pages'] and
               0 <= record['recordIndex'] < MAPPING_SLOTS,
               'dynamic allocation record is incomplete or outside the arena')
        first = A.K_BASE + record['basePage'] * 4096
        expect = {}
        for segment in record['segments'][:record['count']]:
            A.need(segment['bytes'] > 0 and segment['pa'] != segment['iova'] and
                   (segment['pa'] & 4095) == (segment['iova'] & 4095),
                   'dynamic mapping segment is empty, identity or changes the page offset')
            for page in range(((segment['pa'] & 4095) + segment['bytes'] + 4095) // 4096):
                index = (segment['iova'] - first) // 4096 + page
                A.need(0 <= index < record['pages'] and index not in expect,
                       'dynamic allocation pages overlap or escape the recorded allocation')
                expect[index] = (segment['pa'] & ~4095) + page * 4096
        A.need(len(expect) == record['pages'], 'dynamic allocation page count differs')
        for index, pa in expect.items():
            got, leaf = A.walk_with_leaf(pt, dh['rootPA'], dh['ptBase'], dh['leafPA'], dh['rootLevel'],
                                         first + index * 4096, record['mapPte'][index])
            A.need(got == pa == record['physical'][index] and
                   leaf == record['mapPte'][index] and record['clearPte'][index] == 0,
                   'dynamic allocation PTE mapping or confirmed clear differs')
        A.need(0 < record['tMapPublish'] <= record['tMapInv'] <=
               record['tClearPublish'] <= record['tRetireInv'], 'dynamic mapping lifecycle order differs')
        for key in ('mapCommand', 'retireCommand'):
            command = record[key]
            A.need(command['expected'] > 0 and command['expected'] == command['observed'] and
                   command['words'] == [0, dh['domid'] | (3 << 28), 0xfffff003, 0x7fffffff],
                   'dynamic mapping invalidation was not confirmed')
        A.need(record['mapCommand']['expected'] < record['retireCommand']['expected'] <=
               dh['completionSequence'] and
               record['mapCommand']['tComplete'] == record['tMapInv'] and
               record['retireCommand']['tComplete'] == record['tRetireInv'],
               'dynamic mapping completion order differs')
        return expect

    def geometry():
        A.need(dh['iovaBase'] == A.K_BASE and dh['iovaBytes'] == DOMAIN_ARENA_PAGES * 4096,
               'dynamic IOVA arena geometry differs')
        uses = [dh['slotUse%d' % i] for i in range(MAPPING_SLOTS)]
        A.need(dh['slotsUsed'] == sum(1 << i for i, count in enumerate(uses) if count) and
               sum(uses) == dh['mapsTotal'], 'mapping-record use totals differ')
        A.need(1 <= gh['maxHeld'] == sh['maxHeld'] <= dh['maxLiveOwners'] <= MAPPING_SLOTS,
               'driver/backend peak owners exceed mapping-record capacity')
        A.need(dh['probePassed'] == dh['probeReused'] == 1 and
               dh['probeMaps'] == dh['probeUnmaps'] == 9 and
               dh['probePeakOwners'] == 8 and dh['probeMaxPages'] >= 8,
               'normal capacity probe did not complete eight live mappings, wide map and reuse')
        A.need(dh['livePages'] == 0 and
               dh['maxLiveOwners'] >= dh['probePeakOwners'] and
               dh['probeMaxPages'] <= dh['maxMappedPages'] <= DOMAIN_MAX_MAP_PAGES and
               dh['probeMaxPages'] + 7 <= dh['peakPages'] <= DOMAIN_ARENA_PAGES and
               dh['reusedAllocations'] > 0, 'dynamic allocator usage/recovery evidence differs')
        first, reuse = dh['probeFirst'], dh['probeReuse']
        for record in (first, reuse):
            mapped_pages(record)
            A.need(record['pages'] >= 8 and record['req'] == record['token'] == 0,
                   'wide capacity probe was not a generic mapper allocation')
        A.need(first['handle'] != reuse['handle'] and
               first['basePage'] == reuse['basePage'] and first['pages'] == reuse['pages'] and
               0 < P['m2-3e-t-translate-on'] <= dh['probeStart'] <= first['tMapPublish'] and
               first['tRetireInv'] < reuse['tMapPublish'] <= reuse['tRetireInv'] <= dh['probeEnd'] and
               first['retireCommand']['expected'] < reuse['mapCommand']['expected'] and
               dh['probeEnd'] <= P['m2-3e-t-gate-open'],
               'capacity probe did not retire before reusing its allocation and opening TX')
        vals = {}
        for key in ('R24TxWaits', 'R24TxResumes', 'R24TxWakes', 'R24TxPending'):
            m = re.search(r'"' + key + r'" = (\d+)', driver)
            A.need(m is not None, 'missing ' + key)
            vals[key] = int(m[1])
        A.need(vals['R24TxPending'] == 0, 'backpressure request remains pending')
        return dict(vals, arenaPages=DOMAIN_ARENA_PAGES, recordCapacity=MAPPING_SLOTS,
                    maxMappedPages=dh['maxMappedPages'], peakPages=dh['peakPages'], livePages=0,
                    reusedAllocations=dh['reusedAllocations'], probeMaps=dh['probeMaps'],
                    probeUnmaps=dh['probeUnmaps'], probePeakOwners=dh['probePeakOwners'],
                    probePages=first['pages'], firstBasePage=first['basePage'],
                    reusedBasePage=reuse['basePage'])
    run('dynamic-IOVA-wide-map-eight-live-and-confirmed-reuse', geometry)

    def commands():
        A.need(dh['commandCapacity'] == COMMAND_CAPACITY and dh['commandWraps'] >= 2 and
               dh['commandPostWrapCompleted'] > 0, 'original command ring wrap evidence missing')
        A.need(dh['commandSubmits'] == dh['commandCompleted'] == dh['completionSequence'] and
               dh['commandCompleted'] >= 2 * mapped_total,
               'commands not completely acknowledged')
        # Every m2b2Submit publishes a command/CompletionWait pair; the context
        # starts at slot zero. Keep the latest producer's exact wrap accounting.
        A.need(dh['commandWraps'] == dh['commandSubmits'] * 2 // dh['commandCapacity'] and
               dh['commandPostWrapCompleted'] == dh['commandCompleted'] - (dh['commandCapacity'] // 2 - 1),
               'wrap/post-wrap counters disagree with original-capacity pair submission')
        A.need(dh['commandCompleted'] >= dh['mapsTotal'] + dh['retiresTotal'] and
               dh['commandPostWrapCompleted'] <= dh['commandCompleted'],
               'command totals cannot cover the map and retire invalidations')
        for key, prop in (('commandCapacity', 'm2-3b-command-capacity'),
                          ('commandSubmits', 'm2-3b-submits'),
                          ('commandCompleted', 'm2-3b-command-completed'),
                          ('commandWraps', 'm2-3b-command-wraps'),
                          ('commandPostWrapCompleted', 'm2-3b-command-post-wrap-completed'),
                          ('completionSequence', 'm2-3b-completion-sequence')):
            A.need(P[prop] == dh[key], 'command raw/property mismatch: ' + prop)
        return dict({k: dh[k] for k in ('commandCapacity', 'commandSubmits', 'commandCompleted', 'commandWraps',
                                       'commandPostWrapCompleted', 'completionSequence')},
                    commandCapacityUnit='16-byte entries', commandRingBytes=COMMAND_RING_BYTES)
    run('original8192-command-ring-wraps-and-postwrap-completion', commands)

    def histories():
        dd = retained(dh, dom, 'historyTotal', mapped_total + dh['probeMaps'])
        gg = retained(gh, drv, 'retired', mapped_total)
        ss = retained(sh, std, 'historyTotal', mapped_total)
        # Retirement order is not issue/request order with concurrent mappings.
        # Match standard/backend by real mapper handle, native by token/request.
        # Standard mode stamps stdW.handle, not current.request.handle (native
        # handle remains zero). Never infer handle from ring position/request ID.
        attempts = driver_property('R26TxAttempts', True)
        for rows in (gg, ss):
            ids = {r['req'] for r in rows}
            A.need(len(ids) == HISTORY_CAPACITY and all(1 <= req <= attempts for req in ids),
                   'invalid/duplicate retained internal mapping-attempt IDs')
        for rows in (dd, ss):
            A.need(all(r['handle'] > 0 for r in rows) and len({r['handle'] for r in rows}) == 32,
                   'duplicate or zero retained standard/backend handles')
        A.need({r['handle'] for r in dd} == {r['handle'] for r in ss},
               'retained histories disagree on completed handles')
        A.need(all(r['handle'] == 0 for r in gg), 'unexpected native handle in standard mode')
        domains = {r['handle']: r for r in dd}
        drivers = {(r['token'], r['req']): r for r in gg}
        A.need(len(drivers) == 32 and set(drivers) == {(r['token'], r['req']) for r in ss},
               'retained native/standard token/request sets differ')
        intervals = []
        for w in ss:
            d, g = domains[w['handle']], drivers[(w['token'], w['req'])]
            A.need(g['tMap'] == w['tPrepared'], 'native/standard prepare stamp differs')
            req = w['req']
            # IOMapper sees no packet/request metadata. Domain rows deliberately
            # carry zero req/token; match them to packet witnesses by issued handle.
            A.need(d['req'] == d['token'] == 0 and g['req'] == req and
                   g['token'] == w['token'] == token,
                   'retained handle/request/token association differs')
            A.need(g['version'] == DRIVER_VERSION and w['version'] == STD_VERSION and w['flags'] == 3 and d['status'] == 3 and
                   g['retired'] == 1 and w['memory'] and w['command'], 'incomplete standard lifecycle')
            A.need(g['cumulative'] < g['doneClose'], 'close pointer did not pass retained generation')
            n = w['segCount']
            A.need(1 <= n <= 8 and n == d['count'] == g['count'] and 1 <= w['mbufSegments'] <= 8,
                   'segment geometry inconsistent')
            A.need(w['completeResult'] == w['prepareResult'] == w['segmentResult'] == 0, 'standard result not success')
            A.need(0 < d['tMapPublish'] <= d['tMapInv'] <= g['tOwn'] <= g['tDone'] <=
                   d['tClearPublish'] <= d['tRetireInv'] <= g['tFree'], 'map/OWN/completion/retire/free order')
            A.need(0 < w['tBegin'] <= w['tPrepared'] <= w['tSegmented'] <= w['tCommit'] and
                   0 < w['tCompleteBegin'] <= w['tCompleteEnd'] <= w['tFree'] == g['tFree'], 'standard object lifetime order')
            mapped_pages(d)
            for i in range(n):
                s, ws, gs = d['segments'][i], w['segments'][i], g['descriptors'][i]
                A.need(s['iova'] == ws['address'] == gs['address'] == g['iova'][i]['address'] and
                       s['bytes'] == ws['length'] == gs['length'] and s['pa'] != s['iova'], 'identity/fallback or run differs')
                # Standard mode does not export Request.physical (only the
                # direct mapper fills it). Real PA evidence is the backend's
                # segments/physical/PTE triple checked below, not this zero field.
                A.need(g['physical'][i]['address'] == g['physical'][i]['length'] == 0,
                       'unexpected native physical run in standard mode')
                A.need(g['doneOpts1'][i] & 0x80000000, 'descriptor not submitted')
            intervals.append((d['tMapPublish'], d['tRetireInv'],
                              d['basePage'], d['basePage'] + d['pages']))
            A.need(w['mapAddress'] == w['segments'][0]['address'] and d['maplen'] >= w['descriptorLength'],
                   'map address/unmap length invalid')
            # The internal req is not a userspace UDP ID. Compare the actual
            # mapped frame/segment/descriptor lengths, never payload(token, req).
            A.need(w['descriptorLength'] == sum(s['length'] for s in w['segments'][:n]) ==
                   sum(s['length'] for s in g['descriptors'][:n]) > 0,
                   'frame/run/descriptor byte mismatch')
        for i, (start, end, first, last) in enumerate(intervals):
            for start2, end2, first2, last2 in intervals[i + 1:]:
                if max(start, start2) < min(end, end2):
                    A.need(max(first, first2) >= min(last, last2),
                           'simultaneously live mappings overlap in the dynamic arena')
        timeline = sorted([(start, 1) for start, _, _, _ in intervals] +
                          [(end, -1) for _, end, _, _ in intervals])
        live = peak = 0
        for _, delta in timeline:
            live += delta
            peak = max(peak, live)
        A.need(1 < peak <= MAPPING_SLOTS, 'retained mappings do not show bounded overlap')
        return {'peakRetainedLive': peak, 'retained': 32, 'internalRequests': sorted(r['req'] for r in ss), 'correlation': 'standard/backend nonzero handle; native run-token+internal-attempt, prepare/free stamps, segments/descriptors',
                'handles': sorted(domains), 'nativeHandles': sorted({g['handle'] for g in gg}),
                'historyTotal': mapped_total, 'historyStart': mapped_total - HISTORY_CAPACITY,
                'domainHistoryTotal': dh['historyTotal'], 'capacityProbeMaps': dh['probeMaps'],
                'overwrittenNotIndividuallyProved': mapped_total - HISTORY_CAPACITY}
    run('retained32-standard-handles-PTE-and-retirement-lifecycles', histories)

    def exit_state():
        A.need(dh['liveOwners'] == dh['active'] == dh['flags'] == sh['pinned'] == 0 and P['m2-3b-owners-held'] == 0,
               'live backend owner remains')
        A.need(P['m2-3b-slots-live'] == P['m2-3i-exit-driver-live'] == P['m2-3i-exit-driver-held'] == 0 and
               P['m2-3i-exit-driver-mapped'] == P['m2-3i-exit-driver-retired'] == mapped_total,
               'software retirement barrier was not closed')
        A.need(bh['outstanding'] == bh['liveCount'] == bh['liveHandle'] == bh['state'] == 0 and
               not bh['liveFlags'] & 4 and bh['txDirty'] == bh['txNext'] and bh['txClose'] == bh['txTail'],
               'ring/driver not quiescent')
        A.need(bh['sampleStage'] == 3 and bh['sampleSeq'] > 0 and bh['quiesced'] == 1 and
               bh['activeCover'] == 0 and bh['ringBytes'] == 1024 * bh['ringDescSize'],
               'not actual exit ring sample')
        # Production exports total/new/raw events, not win-type2-count. Require
        # an empty, running, non-overflowed event log, not missing-field defaults.
        event_keys = ('m2-b2-win-entries', 'm2-b2-win-new-entries', 'm2-b2-win-raw-count',
                      'm2-b2-win-pre-backlog', 'm2-b2-win-devid-mismatch')
        for key in event_keys + ('m2-3c-cover-unconf',):
            A.need(P[key] == 0, 'fault/unconfirmed: ' + key)
        A.need(P['m2-b2-window-valid'] == 'yes' and P['m2-b2-win-raw-truncated'] == 'no',
               'invalid/truncated event window')
        positions = [P['m2-b2-win-' + k] for k in ('head-start', 'tail-start', 'head-end', 'tail-end')]
        A.need(len(set(positions)) == 1 and 0 <= positions[0] < 8192 and positions[0] % 16 == 0,
               'event ring not empty and unchanged')
        statuses = [P['m2-b2-win-status-' + k] for k in ('start', 'end')]
        # AMDMapperProbeInternal.hpp: overflow=bit0, event-log-running=bit3.
        A.need(all(not (status & 1) and (status & 8) for status in statuses),
               'event log overflowed or was stopped')
        return {'pending': 0, 'owners': 0, 'pinned': 0, 'ringOutstanding': 0, 'devicePageFaults': 0,
                'eventCounts': {k: P[k] for k in event_keys}, 'eventPositions': positions,
                'eventStatuses': statuses, 'rawTruncated': P['m2-b2-win-raw-truncated']}
    run('zero-pending-owners-pins-ring-and-no-device-page-fault', exit_state)

    def window():
        tokens = {'m2-3e-enter': 'gate-open-after-dte-and-invalidations', 'm2-3e-enter-drain': 'drained',
                  'm2-3e-exit-drain': 'drained', 'm2-3e-translate-off': 'confirmed-by-register-readback',
                  'm2-3e-exit-detach': 'detached', 'm2-3e-after-exit': 'ordinary-output-resumed',
                  'm2-3b-cleanup': 'detached-after-restore-confirmed'}
        for key, val in tokens.items():
            A.need(P[key] == val, 'window phase missing: ' + key)
        for key in ('m2-3e-enter-last-inflight', 'm2-3e-enter-last-ring', 'm2-3e-exit-last-inflight', 'm2-3e-exit-last-ring'):
            A.need(P[key] == 0, 'boundary not drained: ' + key)
        enter = [P[k] for k in ('m2-3e-enter-gate-close', 'm2-3e-enter-submit-done', 'm2-3e-enter-drain-done',
                                'm2-b2-dma-t-dte-written', 'm2-3e-t-translate-on', 'm2-3e-t-gate-open')]
        leave = [P[k] for k in ('m2-3e-exit-gate-close', 'm2-3e-exit-submit-done', 'm2-3e-exit-drain-done',
                                'm2-3i-exit-retire-confirmed-time', 'm2-b2-t-recovery-start',
                                'm2-3e-t-translate-off', 'm2-3e-t-detach', 'm2-3e-t-resume')]
        A.need(all(t > 0 for t in enter + leave) and enter == sorted(enter) and leave == sorted(leave) and enter[-1] < leave[0],
               'window entry/exit timestamps out of order')
        for rows in (drv, std):
            for r in rows:
                A.need(enter[-1] <= r.get('tOwn', r.get('tBegin', 0)) <= r['tFree'] <= leave[3],
                       'retained generation outside same window')
        return {'entry': enter, 'exit': leave, 'domain': dh['domid'], 'device': dh['devid']}
    run('same-domain-window-enter-and-exit-order', window)

    def ordinary():
        records = A._ord_records(client)
        oks = [r for r in records if r['kind'] == 'recv' and r.get('ok') == 1]
        before = [r for r in oks if r['tag'] == 'pre' and 0 < r['t'] < P['m2-3e-enter-gate-close']]
        during = [r for r in oks if r['tag'] == 'window' and P['m2-3e-t-translate-on'] <= r['t'] <= P['m2-3e-exit-gate-close']]
        after = [r for r in oks if r['tag'] == 'after-exit' and r['t'] > P['m2-3e-t-resume']]
        seen = {r['seq'] for r in A._ord_records(peer) if r['kind'] == 'recv'}
        A.need(len(before) >= 20 and len(during) >= WINDOW_PROBES and len(after) >= 3 and
               all(r['seq'] in seen for r in before + during + after),
               'ordinary pre20/window%d/after3 evidence missing' % WINDOW_PROBES)
        return {'before': len(before), 'during': len(during), 'after': len(after)}
    run('ordinary-traffic-before-during-and-three-after', ordinary)
    def rx_mappings():
        A.need(P['m2-3h-rx-mode'] == 'standard-nonidentity-cyclic1024' and
               P['m2-3h-rx-state'] == 'drained-and-unmapped' and
               P['m2-3h-rx-ready'] == 'no', 'RX run did not reach its released final state')
        A.need(rb['count'] == rb['mapCalls'] == rb['mapOk'] == rb['unmapCalls'] ==
               rb['unmapOk'] == RX_COUNT and rb['flags'] == rb['mapRejects'] ==
               rb['liveOwners'] == 0 and rb['ready'] == 1,
               'RX1024 map/unmap totals or final backend owners differ')
        A.need(0 < rb['tReady'] <= rb['tDrained'] <= P['m2-3e-exit-gate-close'],
               'RX ready/drained timestamps differ from the active window')
        A.need(P['m2-3h-rx-live-owners'] == P['m2-3h-rx-pending'] == 0,
               'RX raw/property final ownership differs')
        A.need(rh['mapCount'] == RX_COUNT and rh['businessToken'] == token,
               'RX mapping declaration has the wrong count/run token')
        by_id = {m['entryId']: m for m in rxmaps}
        A.need(len(by_id) == RX_COUNT and set(by_id) == {r['entryId'] for r in rxrecords},
               'RX driver/backend entry IDs differ or repeat')
        iovas, leaf_tables = set(), set()
        sequences = {d[key]['expected'] for d in dom + [dh['probeFirst'], dh['probeReuse']]
                     for key in ('mapCommand', 'retireCommand')}
        for i, r in enumerate(rxrecords):
            m = by_id[r['entryId']]
            label = 'RX map entry %d: ' % r['entryId']
            pages = ((r['pa'] & 4095) + RX_CAPACITY + 4095) // 4096
            expected = RX_BASE + i * RX_STRIDE + (r['pa'] & 4095)
            A.need(r['entryId'] == 1024 + i and r['pa'] > 0 and r['iova'] == expected and
                   r['iova'] != r['pa'] and r['capacity'] == RX_CAPACITY and
                   r['mapLength'] == RX_CAPACITY and r['pages'] == pages and 1 <= pages <= 2 and
                   (r['mapOptions'] & 0x2),
                   label + 'unexpected nonidentity stripe or buffer geometry')
            A.need((m['pa'], m['iova'], m['capacity'], m['tMapInv']) ==
                   (r['pa'], r['iova'], r['capacity'], r['tMapInv']),
                   label + 'driver mapping was not the completed backend mapping')
            A.need(r['flags'] == 31 and r['mapResult'] == r['unmapResult'] == 0 and
                   0 < P['m2-3e-t-translate-on'] <= r['tMapPublish'] <= r['tMapInv'] <= rb['tReady'] and
                   rb['tDrained'] <= r['tUnmapPublish'] <= r['tUnmapInv'] <=
                   P['m2-3e-t-translate-off'] and r['tUnmapInv'] < P['m2-b2-t-recovery-start'],
                    label + 'map/unmap confirmation or order differs')
            for key in ('mapCommand', 'unmapCommand'):
                c = r[key]
                A.need(c['expected'] > 0 and c['expected'] == c['observed'] and
                       c['tComplete'] > 0, label + 'CompletionWait mismatch')
                A.need(c['words'] == [0, dh['domid'] | (3 << 28), 0xfffff003, 0x7fffffff],
                       label + 'not full-domain PDE-inclusive invalidation')
                A.need(c['expected'] not in sequences,
                       label + 'repeated shared command completion sequence')
                sequences.add(c['expected'])
            A.need(r['mapCommand']['expected'] < r['unmapCommand']['expected'] <= dh['completionSequence'] and
                   r['mapCommand']['tComplete'] == r['tMapInv'] and
                   r['unmapCommand']['tComplete'] == r['tUnmapInv'],
                   label + 'completion order/timestamps differ')
            for j in range(2):
                if j >= pages:
                    A.need(r['mapPte'][j] == r['clearPte'][j] == 0,
                           label + 'unused page carries a mapping')
                    continue
                pa = (r['pa'] & ~4095) + j * 4096
                iova = (r['iova'] & ~4095) + j * 4096
                A.need(iova not in iovas and r['mapPte'][j] & A.PTE_IW and
                       r['clearPte'][j] == 0, label + 'RX page repeated, not writable, or not cleared')
                iovas.add(iova)
                leaf_pa = rx_leaf_address(pt, dh['rootPA'], dh['ptBase'], dh['rootLevel'], iova)
                leaf_tables.add(leaf_pa)
                got, pte = A.walk_with_leaf(pt, dh['rootPA'], dh['ptBase'], leaf_pa,
                                            dh['rootLevel'], iova, r['mapPte'][j])
                A.need(got == pa and pte == r['mapPte'][j], label + 'RX PTE does not map the spare PA')
        A.need(dh['commandCompleted'] >= 2 * (dh['mapsTotal'] + RX_COUNT),
               'shared command ring total cannot cover TX, capacity probe and RX invalidations')
        return {'mapped': RX_COUNT, 'unmapped': RX_COUNT, 'liveOwners': 0,
                'writablePages': len(iovas), 'leafTables': len(leaf_tables),
                'iovaBase': RX_BASE, 'slotBytes': RX_STRIDE,
                'mapBeforePost': True, 'unmapAfterDrain': True}
    run('rx1024-standard-mapping-PTE-and-confirmed-unmap', rx_mappings)

    def rx_completions():
        A.need(rh['state'] == 4 and rh['flags'] == 0 and rh['generation'] > 0 and rh['poolId'] > 0 and
               rh['mapCount'] == rh['restored'] == RX_COUNT and
               rh['posted'] == rh['completed'] >= 4 * RX_COUNT and
               rh['posted'] == sum(w['postCount'] for w in rxwitnesses) and
               rh['completed'] == sum(w['doneCount'] for w in rxwitnesses) and
               rh['pendingPosted'] == 0, 'RX1024 cumulative DMA counts or association restoration differs')
        A.need(0 < rh['tInstalled'] <= rb['tReady'] <= rh['tDisarmed'] <= rb['tDrained'] and
               rh['tLastRestore'] == max(w['tRestoreOwn'] for w in rxwitnesses) <= rb['tDrained'],
               'RX driver installation/drain/last-restore timestamps differ')
        records = {r['entryId']: r for r in rxrecords}
        A.need(len({w['entryId'] for w in rxwitnesses}) == RX_COUNT and
               {w['entryId'] for w in rxwitnesses} == set(records) and
               len({w['slot'] for w in rxwitnesses}) == RX_COUNT,
               'RX cyclic entry IDs or ring slots repeat')
        replies, sends = {}, {}
        peer_ids = set()
        for line in client.splitlines():
            match = re.match(r'client_(sent|recv) token=(0x[0-9a-fA-F]+) req=(\d+) len=(\d+) '
                             r'sha256=([0-9a-f]{64}) payload=([0-9a-f]+).* t_ns=(\d+)$', line)
            if match:
                tok, req = int(match[2], 16), int(match[3])
                data = bytes.fromhex(match[6])
                A.need(tok == token and data == payload(token, req) and len(data) == int(match[4]) and
                       hashlib.sha256(data).hexdigest() == match[5], 'RX-correlated client bytes differ')
                (sends if match[1] == 'sent' else replies)[req] = int(match[7])
        for line in peer.splitlines():
            match = re.match(r'peer_sent token=(0x[0-9a-fA-F]+) req=(\d+) len=(\d+) '
                             r'sha256=([0-9a-f]{64}) payload=([0-9a-f]+)(?: |$)', line)
            if match:
                tok, req = int(match[1], 16), int(match[2])
                data = bytes.fromhex(match[5])
                A.need(tok == token and data == payload(token, req) and len(data) == int(match[3]) and
                       hashlib.sha256(data).hexdigest() == match[4], 'RX-correlated peer reply bytes differ')
                peer_ids.add(req)
        business, final_business = [], []
        for w in rxwitnesses:
            r = records[w['entryId']]
            label = 'RX completion entry %d: ' % w['entryId']
            A.need(w['flags'] == 7 and 0 <= w['slot'] < 1024 and
                   w['sparePA'] == r['pa'] and w['iova'] == r['iova'] and
                   w['originalPA'] > 0 and w['originalPA'] not in (w['sparePA'], w['iova']),
                   label + 'posted/done/restored addresses or witness flags differ')
            A.need(0 < r['tMapInv'] <= rh['tInstalled'] <= w['tPost'] <= w['tDone'] <=
                   w['tRestoreOwn'] <= rb['tDrained'] <= r['tUnmapPublish'] <= r['tUnmapInv'] and
                   P['m2-3e-t-gate-open'] <= w['tPost'],
                   label + 'map/post/DMA/restore/drain/unmap order differs')
            A.need(w['postCount'] == w['doneCount'] >= 4 and
                   w['reuseCount'] == w['postCount'] - 1 and w['sampleCount'] == 4,
                   label + 'cyclic counts differ')
            A.need(w['tPost'] == w['samples'][0]['tPost'] and
                   w['samples'][-1]['tDone'] <= w['tLastDone'] == w['tDone'] and
                   w['tLastPost'] <= rh['tDisarmed'] < w['tRestoreOwn'] and
                   w['tLastPost'] < w['tLastDone'] < w['tRestoreOwn'],
                   label + 'first/final cycle or disarm/restore order differs')
            previous = r['tMapInv']
            for cycle, sample in enumerate(w['samples'], 1):
                A.need(sample['cycle'] == cycle and sample['flags'] == 3 and
                       previous < sample['tPost'] < sample['tDone'],
                       label + 'sample identity/flags/time order differs')
                previous = sample['tDone']
            if w['postCount'] == 4:
                last = w['samples'][-1]
                A.need(w['tLastPost'] == last['tPost'] and all(w[k] == last[k] for k in
                       ('tDone', 'token', 'reqId', 'doneLength', 'doneStatus')),
                       label + 'final witness is inconsistent with fourth sample')
            else:
                A.need(previous < w['tLastPost'], label + 'final reuse precedes retained cycles')
            for sample in w['samples'] + [w]:
                A.need(not sample['doneStatus'] & 0x80000000 and
                       (sample['doneStatus'] & 0x1fff) == sample['doneLength'] and
                       0 < sample['doneLength'] <= RX_CAPACITY,
                       label + 'hardware completion status/length differs')
                if sample['token'] or sample['reqId']:
                    req = sample['reqId']
                    A.need(sample['token'] == token and req in REQUESTS and req in sends and
                           req in replies and req in peer_ids,
                           label + 'observed R27P reply is absent from application logs')
                    A.need(sample['doneLength'] == len(payload(token, req)) + 46 and
                           sends[req] <= sample['tDone'] <= replies[req],
                           label + 'R27P frame/FCS length or delivery order differs')
                    if sample is not w:
                        business.append(req)
                    elif w['postCount'] > 4:
                        final_business.append(req)
        A.need(business and len(set(business + final_business)) == len(business + final_business),
               'no unique sampled R27P completions correlate to userspace logs')
        return {'posted': rh['posted'], 'completed': rh['completed'], 'restored': RX_COUNT, 'pending': 0,
                'sampledCompletions': RX_COUNT * 4,
                'businessCompletions': len(business), 'nonBusinessSamples': RX_COUNT * 4 - len(business),
                'additionalFinalBusinessCompletions': len(final_business),
                'applicationRequests': sorted(business),
                'correlation': 'first four cycles per association and final completion; R27P token+ID and FCS length',
                'scope': '1024 cyclic spare associations; first four cycles retained, cumulative DMA totals'}
    run('rx1024-real-DMA-restoration-and-application-correlation', rx_completions)
    return result()


if __name__ == '__main__':
    report = check(Path(sys.argv[1]))
    text = json.dumps(report, indent=2) + '\n'
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(text, encoding='utf-8')
    else:
        print(text)
    raise SystemExit(0 if report['ok'] else 1)
