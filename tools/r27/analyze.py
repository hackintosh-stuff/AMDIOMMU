#!/usr/bin/env python3
"""Round43: stop NIC DMA before DTE entry and keep the translated window IOVA-only.

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

SCOPE = 'round43-stop-before-DTE; IOVA-only-lifecycle; empty-final-leaves; local-NIC-stop; no-peer-drain-tail; synchronous-RX-batch16; service-owned-domain; 4096+4096-after-125s-idle'
REQUEST_COUNT = len(REQUESTS)
WINDOW_PROBES = 2 * len(bursts())
MIN_MAPPINGS = REQUEST_COUNT + WINDOW_PROBES
RX_VERSION, RX_COUNT = 5, 1024
RX_BATCH_MAX = 16
RX_DRIVER_BYTES, RX_BACKEND_BYTES = 270432, 475216
RX_DRIVER_HEADER, RX_DRIVER_SLOT_BYTES = 96, 264
RX_BACKEND_HEADER, RX_BACKEND_SLOT_BYTES = 80, 464
RX_WITNESS_BYTES, RX_MAP_RECORD_BYTES = 104, 224
PHYSICAL_LAYOUT_VERSION, PHYSICAL_LAYOUT_BYTES = 1, 64
PHYSICAL_LAYOUT_HEADER, PHYSICAL_SPAN_BYTES, PHYSICAL_SPAN_COUNT = 16, 16, 3
RX_STOP_BEFORE_DTE_OP, RX_CAPTURE_ACTIVE_OP = 9, 12
STOP_VERSION, STOP_BYTES, STOP_TIME_OFFSET = 1, 96, 48
WITNESS_STOP_RETIRED = 16
FIXED_VERSION, FIXED_COUNT, FIXED_PAGES = 1, 3, 16
FIXED_BASE, FIXED_STRIDE = 0x1000100000, 0x10000
FIXED_DRIVER_BYTES, FIXED_DRIVER_HEADER, FIXED_DRIVER_OBJECT_BYTES = 368, 80, 96
FIXED_BACKEND_BYTES, FIXED_BACKEND_HEADER, FIXED_RECORD_BYTES = 1376, 56, 440
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
    h = A.unpack('version bytes state flags businessToken slotCount maps unmaps '
                 'posted completed replaced restored pendingPosted tailSeq nativeActive stopRetired '
                 'ringId tInstalled tDisarmed tLastRestore', '16I4Q', blob)
    A.need(h['version'] == RX_VERSION and h['bytes'] == len(blob), 'RX driver ABI differs')
    rows = []
    for i in range(RX_COUNT):
        at = RX_DRIVER_HEADER + i * RX_DRIVER_SLOT_BYTES
        slot = A.unpack('originalPA currentPA tPhysicalOwn mapCount unmapCount postCount doneCount '
                        'replaceCount sampleCount flags stopRetired', '3Q8I', blob, at)
        def witness(offset):
            return A.unpack('generation memory command pa iova tMapInv tPost tDone tUnmapInv '
                            'slot flags token reqId doneLength doneStatus replaced reserved',
                            '9Q8I', blob, offset)
        slot['first'] = witness(at + RX_DRIVER_SLOT_BYTES - 2 * RX_WITNESS_BYTES)
        slot['last'] = witness(at + RX_DRIVER_SLOT_BYTES - RX_WITNESS_BYTES)
        rows.append(slot)
    return h, rows


def decode_stop(blob):
    A.need(len(blob) == STOP_BYTES, 'RX stop record must be %d bytes' % STOP_BYTES)
    h = A.unpack('version bytes stopCalls resetVerified commandBefore commandStopped '
                 'interruptMaskBefore interruptMaskStopped rxNextBefore rxNextAfter '
                 'stopRetired restored tStopBegin tStopped tLastUnmap tLastRestore '
                 'tResumeBegin tResumed', '12I6Q', blob)
    A.need(h['version'] == STOP_VERSION and h['bytes'] == len(blob),
           'RX stop record ABI differs')
    return h


def decode_fixed_driver(blob):
    A.need(len(blob) == FIXED_DRIVER_BYTES, 'fixed DMA driver snapshot size differs')
    h = A.unpack('version bytes count flags entryCalls resetVerified commandBefore commandStopped '
                 'interruptMaskBefore interruptMaskStopped generationBefore generationAfter '
                 'tStopBegin tStopped tProgrammed tActive', '12I4Q', blob)
    A.need(h['version'] == FIXED_VERSION and h['bytes'] == len(blob) and h['count'] == FIXED_COUNT,
           'fixed DMA driver ABI differs')
    rows = [A.unpack('memory command pa bytes iova registerBefore registerActive registerPhysical '
                     'tMapReady tUnmapReady kind mapOptions mapCount unmapCount', '10Q4I', blob,
                     FIXED_DRIVER_HEADER + i * FIXED_DRIVER_OBJECT_BYTES) for i in range(FIXED_COUNT)]
    return h, rows


def decode_fixed_backend(blob):
    A.need(len(blob) == FIXED_BACKEND_BYTES, 'fixed DMA backend snapshot size differs')
    h = A.unpack('version bytes count flags boundPairs liveOwners mapCalls mapOk '
                 'unmapCalls unmapOk entered reserved tEntered', '12IQ', blob)
    A.need(h['version'] == FIXED_VERSION and h['bytes'] == len(blob) and h['count'] == FIXED_COUNT,
           'fixed DMA backend ABI differs')
    rows = []
    for i in range(FIXED_COUNT):
        at = FIXED_BACKEND_HEADER + i * FIXED_RECORD_BYTES
        r = A.unpack('memory command pa bytes iova tMapPublish tMapInv tUnmapPublish tUnmapInv '
                     'kind pages mapOptions flags mapResult unmapResult mapCalls unmapCalls',
                     '9Q8I', blob, at)
        r['mapPte'] = struct.unpack_from('<16Q', blob, at + 104)
        r['clearPte'] = struct.unpack_from('<16Q', blob, at + 232)
        r['mapCommand'] = A.cmdrec(blob, at + 360)
        r['unmapCommand'] = A.cmdrec(blob, at + 400)
        rows.append(r)
    return h, rows


def decode_rx_backend(blob):
    A.need(len(blob) == RX_BACKEND_BYTES, 'RX backend snapshot must be %d bytes' % RX_BACKEND_BYTES)
    h = A.unpack('version bytes flags count mapCalls mapOk mapRejects unmapCalls '
                 'unmapOk liveOwners ready coverCalls coverOk coverFailed boundPairs reserved '
                 'tReady tDrained', '16I2Q', blob)
    A.need(h['version'] == RX_VERSION and h['bytes'] == len(blob), 'RX backend ABI differs')
    rows = []
    for i in range(RX_COUNT):
        at = RX_BACKEND_HEADER + i * RX_BACKEND_SLOT_BYTES
        slot = A.unpack('mapCount unmapCount sampleCount flags', '4I', blob, at)
        def mapping(offset):
            r = A.unpack('generation memory command pa iova mapLength '
                         'tMapPublish tMapInv tUnmapPublish tUnmapInv', '10Q', blob, offset)
            r['mapPte'] = struct.unpack_from('<2Q', blob, offset + 80)
            r['clearPte'] = struct.unpack_from('<2Q', blob, offset + 96)
            r.update(A.unpack('slot pages mapOptions flags mapResult unmapResult mapBatch unmapBatch',
                              '8I', blob, offset + 112))
            r['mapCommand'] = A.cmdrec(blob, offset + 144)
            r['unmapCommand'] = A.cmdrec(blob, offset + 184)
            return r
        slot['first'] = mapping(at + RX_BACKEND_SLOT_BYTES - 2 * RX_MAP_RECORD_BYTES)
        slot['last'] = mapping(at + RX_BACKEND_SLOT_BYTES - RX_MAP_RECORD_BYTES)
        rows.append(slot)
    return h, rows


def rx_leaf_address(pt, root_pa, pt_base, level, iova):
    """Find this stripe's L1 table through the exported parent entries.

    RX1024 spans four L1 tables after the separate TX L1. The TX snapshot's
    leafPA cannot locate the RX leaves on its own.
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


def decode_physical_layout(blob):
    A.need(len(blob) == PHYSICAL_LAYOUT_BYTES, 'physical layout must be 64 bytes')
    h = A.unpack('version bytes generation count', '4I', blob)
    A.need(h['version'] == PHYSICAL_LAYOUT_VERSION and h['bytes'] == len(blob) and
           h['generation'] > 0 and h['count'] == PHYSICAL_SPAN_COUNT,
           'physical layout ABI or ring generation differs')
    spans = []
    for i, name in enumerate(('txRing', 'rxRing', 'tally')):
        span = A.unpack('pa bytes', '2Q', blob, PHYSICAL_LAYOUT_HEADER + i * PHYSICAL_SPAN_BYTES)
        span['name'] = name
        spans.append(span)
    return h, spans


def physical_pages(ranges):
    pages = set()
    for pa, size in ranges:
        A.need(pa > 0 and size > 0 and pa + size <= 1 << 52,
               'physical DMA span is empty or outside the address width')
        pages.update(range(pa & ~4095, pa + size, 4096))
    return pages


def page_leaves(pt, root_pa, pt_base, level, read_only_window=None):
    """Enumerate every present 4 KiB leaf in an immutable arena copy.

    Identity leaves and RX mappings are read/write because the device reads and
    writes them. The standard TX path maps its IOVA window device-read-only
    (the device only reads those buffers), so leaves inside that window may
    carry IR without IW; every other leaf must have both bits.
    """
    A.need(level in (3, 4), 'impossible page-table root level')
    pages, pending = {}, [(root_pa, level, 0)]
    while pending:
        table, depth, base = pending.pop()
        A.need(table & 4095 == 0 and 0 <= table - pt_base <= len(pt) - 4096,
               'page table outside the exported arena')
        entries = struct.unpack_from('<512Q', pt, table - pt_base)
        for index, entry in enumerate(entries):
            if not entry & 1:
                continue
            address = base | (index << (12 + 9 * (depth - 1)))
            target = entry & 0x000FFFFFFFFFF000
            device_read_only = bool(read_only_window) and \
                read_only_window[0] <= address < read_only_window[1]
            A.need(entry & A.PTE_IR and (entry & A.PTE_IW or device_read_only) and
                   (entry >> 9) & 7 == depth - 1,
                   'page table contains a large leaf or wrong permissions/level')
            if depth > 1:
                pending.append((target, depth - 1, address))
            else:
                pages[address] = target
    return pages


def identity_leaf_pages(pt, root_pa, pt_base, level):
    # All TX/RX IOVAs have retired at final capture.
    pages = page_leaves(pt, root_pa, pt_base, level)
    A.need(all(address == target for address, target in pages.items()),
           'remaining physical leaf is not identity-mapped')
    return set(pages)


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
                'retained 32 prove TX PTE/lifecycle relations; RX retains each slot’s first and final IOVA generation.']}
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
        rh, rxslots = decode_rx(blob('rtl812x-r34-rx-native-raw', 'r34-rx-driver.bin'))
        rb, rxbackend = decode_rx_backend(blob('m2-3o-rx-backend-raw', 'r34-rx-backend.bin'))
        stop = decode_stop(blob('rtl812x-r39-rx-stop-raw', 'r39-rx-stop.bin'))
        fh, fixed_driver = decode_fixed_driver(blob('rtl812x-r40-fixed-dma-raw', 'r40-fixed-driver.bin'))
        fb, fixed_backend = decode_fixed_backend(blob('m2-3u-fixed-dma-raw', 'r40-fixed-backend.bin'))
        rxrecords = [slot['last'] for slot in rxbackend]
        client = (cap / 'client.log').read_text(encoding='utf-8')
        peer = (cap / 'peer.log').read_text(encoding='utf-8')
        driver = (cap / 'driver-obs.txt').read_text(encoding='utf-8')
        token = gh['token']
        A.need(0 < token < 0x80000000 and sh['token'] == bh['token'] == token,
               'inconsistent/non-low-half token')
        A.need(dh['devid'] == gh['bdf'] == sh['bdf'] == bh['bdf'], 'capture device association differs')
        checks.append({'id': 'capture-ABI-domain4-native7-std5-nativeRX5', 'state': 'ok'})
    except (A.Refused, OSError, ValueError, KeyError, IndexError, struct.error) as exc:
        checks.append({'id': 'capture-ABI-domain4-native7-std5-nativeRX5', 'state': 'FAIL', 'detail': str(exc)})
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
        A.need(P.get('m2-3l-tx-deadline') == 0,
               'TX authorization still has a timed deadline')
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
        A.need(request <= stopped <= ack and stopped <= rh['tDisarmed'] <=
               stop['tStopped'] <= rb['tDrained'] <=
               P['m2-3e-t-resume'] <= end <= observed_end,
               'explicit stop/local retirement/restore/session-end order differs')
        # The two observations happen after the setup worker has returned,
        # before each half of actual network traffic. The same owned resources
        # survive the 125-second idle; final properties retain their identity.
        A.need(P.get('m2-3n-domain-mode') == 'service-owned' and
               P.get('m2-3n-domain-state') == 'stopped' and
               P.get('m2-3n-setup-worker-active') == 0 and
               P.get('m2-3n-install-count') == 1,
               'service-owned domain did not complete one setup/teardown lifecycle')
        identity = tuple(P.get('m2-3n-' + key, 0) for key in
                         ('setup-worker-exit-time', 'root-pa', 'dt-pa', 'command-pa'))
        A.need(all(isinstance(value, int) and value > 0 for value in identity) and
               identity[1] == dh['rootPA'], 'persistent domain resource identity differs')
        observations = re.findall(
            r'^client_domain phase=([12]) mode=service-owned state=active setup_worker=0 '
            r'setup_exit=(\d+) root_pa=(0x[0-9a-fA-F]+) dt_pa=(0x[0-9a-fA-F]+) '
            r'command_pa=(0x[0-9a-fA-F]+) installs=1 t_ns=(\d+)$', client, re.M)
        A.need(len(observations) == 2 and [row[0] for row in observations] == ['1', '2'] and
               len(re.findall(r'^client_domain .*$', client, re.M)) == 2,
               'two active domain observations after setup exit are missing')
        observation_times = []
        for row in observations:
            A.need(tuple(int(value, 0) for value in row[1:5]) == identity,
                   'device domain was rebuilt or changed between traffic phases')
            observation_times.append(int(row[5]))
        A.need(start <= identity[0] <= observation_times[0] <= phase1 and
               idle_end <= observation_times[1] <= phase2 and
               stopped <= P['m2-3n-teardown-start'] <= rh['tDisarmed'] and
               P['m2-3e-t-resume'] <= P['m2-3n-teardown-end'] <= end,
               'setup worker exit or separate teardown order differs')
        return {'mode': 'service-owned', 'state': 'stopped', 'requestsPerPhase': 4096,
                'idleSeconds': (idle_end - idle_begin) / 1e9,
                'secondPhaseAfterSeconds': (min(halves[1]) - start) / 1e9,
                'stopRequests': 1, 'txDeadline': 0, 'rxDeadline': 0,
                'durationSeconds': (end - start) / 1e9,
                'setupWorkerExited': identity[0], 'activeObservations': 2,
                'rootPA': identity[1], 'deviceTablePA': identity[2],
                'commandPA': identity[3], 'domainInstalls': 1,
                'teardownStart': P['m2-3n-teardown-start'],
                'teardownEnd': P['m2-3n-teardown-end']}
    run('service-owned-domain-after-setup-exit-125s-idle-stop-and-restore', session_lifecycle)

    def local_stop():
        A.need(stop['stopCalls'] == stop['resetVerified'] == 1 and
               stop['commandBefore'] & 0x1c == 0x0c and
               stop['commandStopped'] & 0x1c == 0 and
               stop['interruptMaskStopped'] == 0 and
               0 <= stop['rxNextBefore'] < RX_COUNT and stop['rxNextAfter'] == 0,
               'NIC stop/reset readback or restored ring index differs')
        A.need(stop['restored'] == rh['restored'] == RX_COUNT and
               0 < stop['stopRetired'] == rh['stopRetired'] <= RX_COUNT and
               stop['tLastUnmap'] == max(r['tUnmapInv'] for r in rxrecords) and
               stop['tLastRestore'] == rh['tLastRestore'] ==
               max(s['tPhysicalOwn'] for s in rxslots),
               'local stop record differs from final RX retirement/restoration')
        order = [P['m2-3l-stop-request-time'], P['m2-3e-exit-gate-close'],
                 P['m2-3e-exit-drain-done'], rh['tDisarmed'], stop['tStopBegin'],
                 stop['tStopped'], stop['tLastUnmap'], stop['tLastRestore'],
                 rb['tDrained'], P['m2-b2-t-recovery-start']]
        A.need(all(t > 0 for t in order) and order == sorted(order),
               'RX mappings retired before TX drain/NIC stop or after IOMMU recovery')
        A.need(P['m2-3e-t-translate-off'] <= stop['tResumeBegin'] <=
               stop['tResumed'] == driver_property('rtl812x-r35-rx-resume-time', True) <=
               P['m2-3e-t-detach'] <= P['m2-3e-t-resume'],
               'physical NIC did not resume after translation restore and before TX reopen')
        return dict(stop, stopMethod='local NIC reset with register readback',
                    completionAccounting='posted = completed + stopRetired')
    run('local-NIC-stop-before-RX-retirement', local_stop)

    def autonomous_stop():
        def one(pattern, name):
            rows = re.findall('^' + pattern + '$', client, re.M)
            A.need(len(rows) == 1, 'missing/repeated local stop ' + name)
            return int(rows[0])
        begin = one(r'client_stop_begin request_ns=(\d+)', 'begin')
        end = one(r'client_stop_end stopped_ns=(\d+)', 'end')
        A.need(begin == one(r'client_session_stop_request t_ns=(\d+)', 'request') and
               end == one(r'client_session_stopped t_ns=(\d+)', 'stopped observation') and
               begin <= P['m2-3l-stop-request-time'] <= stop['tStopBegin'] <=
               stop['tResumed'] <= P['m2-3l-session-end'] <= end <=
               one(r'client_after_exit resumed=1 t_ns=(\d+)', 'after-exit observation'),
               'local stop request/physical resume/end observations differ')
        A.need(not re.search(r'^client_tail_', client, re.M) and
               not re.search(r'^peer_tail_', peer, re.M) and rh['tailSeq'] == 0,
               'normal stop still uses the R28T/R29D peer tail')
        sends = [int(t) for t in re.findall(
            r'^client_(?:sent|ord_sent|seed_sent) .* t_ns=(\d+)$', client, re.M)]
        A.need(sends and not any(begin <= t < end for t in sends),
               'client sent network traffic while waiting for local stop')
        after = [r for r in A._ord_records(client) if r['kind'] == 'recv' and
                 r.get('ok') == 1 and r['tag'] == 'after-exit' and r['t'] >= end]
        A.need(len(after) >= 3, 'ordinary receive did not recover after local stop')
        return {'requestTime': begin, 'observedStopped': end, 'peerTailPackets': 0,
                'clientSendsDuringStop': 0, 'ordinaryAfterExit': len(after),
                'stopRetired': stop['stopRetired']}
    run('peer-independent-stop-and-physical-resume', autonomous_stop)

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
        enter = [P[k] for k in ('m2-3e-enter-gate-close', 'm2-3e-enter-submit-done', 'm2-3e-enter-drain-done')]
        enter += [fh['tStopBegin'], fh['tStopped'], P['m2-b2-dma-t-dte-written'],
                  P['m2-3e-t-translate-on'], fh['tProgrammed'], fh['tActive'],
                  P['m2-3e-t-gate-open']]
        leave = [P[k] for k in ('m2-3e-exit-gate-close', 'm2-3e-exit-submit-done', 'm2-3e-exit-drain-done',
                                'm2-3i-exit-retire-confirmed-time')]
        leave += [stop['tStopBegin'], stop['tStopped'], rb['tDrained'],
                  P['m2-b2-t-recovery-start'], P['m2-3e-t-translate-off'],
                  stop['tResumeBegin'], stop['tResumed'],
                  P['m2-3e-t-detach'], P['m2-3e-t-resume']]
        A.need(all(t > 0 for t in enter + leave) and enter == sorted(enter) and leave == sorted(leave) and enter[-1] < leave[0],
               'window entry/exit timestamps out of order')
        for rows in (drv, std):
            for r in rows:
                A.need(enter[-1] <= r.get('tOwn', r.get('tBegin', 0)) <= r['tFree'] <= leave[3],
                       'retained generation outside same window')
        # These readbacks diagnose the entry handoff; the ordinary traffic and
        # native RX checks still establish whether receive processing works.
        irq = {name: driver_property('rtl812x-r41-irq-' + name, True)
               for name in ('pending', 'masked', 'armed', 'expected')}
        irq['maskedBeforeEnable'] = irq['masked'] == 0
        irq['expectedMaskRestored'] = irq['armed'] == irq['expected'] > 0
        return {'entry': enter, 'exit': leave, 'domain': dh['domid'], 'device': dh['devid'],
                'entryIRQ': irq}
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

    def fixed_mappings(layout, spans, active_pt, active_leaves, tx_sequences):
        A.need(fh['flags'] == fb['flags'] == fb['boundPairs'] == fb['liveOwners'] == 0 and
               fh['entryCalls'] == fh['resetVerified'] == fb['entered'] == 1 and
               fb['mapCalls'] == fb['mapOk'] == fb['unmapCalls'] == fb['unmapOk'] == FIXED_COUNT,
               'fixed DMA entry, standard mapping totals or final owners differ')
        A.need(fh['commandBefore'] & 0x1c == 0x0c and fh['commandStopped'] & 0x1c == 0 and
               fh['interruptMaskStopped'] == 0 and
               fh['generationBefore'] == layout['generation'] and
               fh['generationAfter'] > fh['generationBefore'],
               'fixed DMA entry reset/readback or ring generation differs')
        A.need(P['m2-3e-enter-drain-done'] <= fh['tStopBegin'] <= fh['tStopped'] <
               P['m2-b2-dma-t-dte-written'] <= P['m2-3e-t-translate-on'] <
               rh['tInstalled'] <= fh['tProgrammed'] <= fh['tActive'] == fb['tEntered'] <=
               P['m2-3e-t-gate-open'] <= rb['tReady'],
               'NIC was not stopped before DTE entry or fixed DMA was not active before admission')
        sequences, expected_pages, pairs = set(), {}, set()
        for i, (span, driver_object, r) in enumerate(zip(spans, fixed_driver, fixed_backend)):
            label = 'fixed DMA %s: ' % span['name']
            A.need(r['kind'] == driver_object['kind'] == i and
                   r['pa'] == driver_object['pa'] == span['pa'] and
                   r['bytes'] == driver_object['bytes'] == span['bytes'] and
                   all(r[k] == driver_object[k] for k in ('memory', 'command', 'iova', 'mapOptions')),
                   label + 'immutable physical span and driver/backend mapping differ')
            pair = (r['memory'], r['command'])
            A.need(all(pair) and pair not in pairs and r['flags'] == 7 and
                   r['mapResult'] == r['unmapResult'] == 0 and
                   r['mapCalls'] == r['unmapCalls'] == driver_object['mapCount'] ==
                   driver_object['unmapCount'] == 1 and r['mapOptions'] & 2,
                   label + 'standard MD/Cmd lifecycle or DMA direction differs')
            pairs.add(pair)
            pages = ((r['pa'] & 4095) + r['bytes'] + 4095) // 4096
            A.need(0 < pages == r['pages'] <= FIXED_PAGES and
                   r['iova'] == FIXED_BASE + i * FIXED_STRIDE + (r['pa'] & 4095) != r['pa'] and
                   driver_object['registerBefore'] == driver_object['registerPhysical'] == r['pa'] and
                   driver_object['registerActive'] == r['iova'],
                   label + 'IOVA geometry or actual NIC address readback differs')
            A.need(P['m2-3e-t-translate-on'] <= r['tMapPublish'] <= r['tMapInv'] <=
                   driver_object['tMapReady'] <= fh['tProgrammed'] and
                   stop['tStopped'] <= r['tUnmapPublish'] <= r['tUnmapInv'] <=
                   driver_object['tUnmapReady'] <= rb['tDrained'] <= P['m2-b2-t-recovery-start'],
                   label + 'map before programming/unmap after local stop order differs')
            for phase in ('map', 'unmap'):
                c = r[phase + 'Command']
                A.need(0 < c['expected'] == c['observed'] <= dh['completionSequence'] and
                       c['expected'] not in sequences | tx_sequences and
                       c['words'] == [0, dh['domid'] | (3 << 28), 0xfffff003, 0x7fffffff] and
                       c['tComplete'] == r['tMapInv' if phase == 'map' else 'tUnmapInv'],
                       label + 'confirmed standard invalidation command differs')
                sequences.add(c['expected'])
            A.need(r['mapCommand']['expected'] < r['unmapCommand']['expected'],
                   label + 'unmap command precedes map')
            for j in range(FIXED_PAGES):
                A.need(r['clearPte'][j] == 0 and (j < pages or r['mapPte'][j] == 0),
                       label + 'retired or unused fixed IOVA leaf is not empty')
                if j >= pages:
                    continue
                address = (r['iova'] & ~4095) + j * 4096
                target = (r['pa'] & ~4095) + j * 4096
                table = rx_leaf_address(active_pt, dh['rootPA'], dh['ptBase'], dh['rootLevel'], address)
                pte = struct.unpack_from('<Q', active_pt,
                                         table - dh['ptBase'] + ((address >> 12) & 511) * 8)[0]
                A.need(active_leaves.get(address) == target and pte == r['mapPte'][j] and
                       pte & A.PTE_IR and pte & A.PTE_IW,
                       label + 'active fixed IOVA PTE differs from its physical DMA span')
                expected_pages[address] = target
        actual_fixed = {a: target for a, target in active_leaves.items()
                        if FIXED_BASE <= a < FIXED_BASE + FIXED_COUNT * FIXED_STRIDE}
        A.need(actual_fixed == expected_pages and fixed_driver[0]['iova'] == bh['ringAddr'],
               'fixed IOVA window or sampled TX ring base differs')
        return {'objects': fixed_driver, 'mapped': fb['mapOk'], 'unmapped': fb['unmapOk'],
                'liveOwners': fb['liveOwners'], 'boundPairs': fb['boundPairs'],
                'iovaPages': len(expected_pages), 'entryStopTime': fh['tStopped'],
                'programmedTime': fh['tProgrammed'], 'activeTime': fh['tActive'],
                'generationBefore': fh['generationBefore'], 'generationAfter': fh['generationAfter']}, sequences

    def rx_mappings():
        A.need(P['m2-3h-rx-mode'] == 'native-ring-batch16' and
               P['m2-3h-rx-state'] == 'drained-and-unmapped' and
               P['m2-3h-rx-ready'] == 'no', 'native RX did not reach its released final state')
        A.need(P['m2-3p-rx-source'] ==
               driver_property('rtl812x-r35-rx-source') == 'lucy-normal-ring' and
               P['m2-3x-rx-manifest-ranges'] == RX_COUNT and
               0 < P['m2-3x-rx-manifest-time'] <= P['m2-3e-enter-gate-close'] and
               P['m2-3p-rx-bootstrap-ranges'] == 0 and
               P['m2-3p-rx-pool-rpcs'] == P['m2-3p-rx-spares'] ==
               driver_property('rtl812x-r35-rx-experimental-pool', True) ==
               driver_property('rtl812x-r35-rx-spares', True) == 0 and
               P['m2-3p-rx-ring-id'] ==
               driver_property('rtl812x-r35-rx-ring-id', True) == rh['ringId'] > 0,
               'RX manifest did not describe the same ordinary Lucy ring without an experimental pool')
        layout, fixed_spans = decode_physical_layout(
            blob('rtl812x-r37-physical-layout', 'r37-physical-layout.bin'))
        A.need(P['m2-3r-physical-mode'] == 'iova-only' and
               layout['generation'] == P['m2-3p-rx-ring-generation'] and
               fixed_spans[0]['bytes'] == bh['ringBytes'],
               'physical layout mode, ring generation or TX ring identity differs')
        fixed_pages = physical_pages((s['pa'], s['bytes']) for s in fixed_spans)
        current_pages = physical_pages((s['currentPA'], RX_CAPACITY) for s in rxslots)
        active_pt = blob('m2-3x-active-pt-raw', 'r43-active-pt-raw.bin')
        A.need(len(active_pt) == len(pt) == dh['ptBytes'],
               'active and final page-table arena sizes differ')
        active_leaves = page_leaves(active_pt, dh['rootPA'], dh['ptBase'], dh['rootLevel'],
                                    (dh['iovaBase'], dh['iovaBase'] + dh['iovaBytes']))
        active_identity = {address for address, target in active_leaves.items() if address == target}
        rx_end = RX_BASE + RX_COUNT * RX_STRIDE
        A.need(not active_identity and
               all(FIXED_BASE <= address < FIXED_BASE + FIXED_COUNT * FIXED_STRIDE or
                   dh['iovaBase'] <= address < dh['iovaBase'] + dh['iovaBytes'] or
                   RX_BASE <= address < rx_end for address, target in active_leaves.items()) and
               all(RX_BASE + i * RX_STRIDE in active_leaves for i in range(RX_COUNT)),
               'active tree retains identity pages or leaves outside fixed/TX/RX IOVA windows')
        first_post = min(s['first']['tPost'] for s in rxslots)
        last_first_post = max(s['first']['tPost'] for s in rxslots)
        authorized = driver_property('rtl812x-r35-rx-authorize-time', True)
        active_capture = P['m2-3x-active-capture-time']
        active_ready = driver_property('rtl812x-r43-rx-active-ready-time', True)
        A.need(driver_property('rtl812x-r38-rx-first-iova-slots', True) == RX_COUNT and
               driver_property('rtl812x-r38-rx-last-first-iova-time', True) == last_first_post and
               fh['tStopped'] < P['m2-b2-dma-t-dte-written'] <=
               P['m2-3e-t-translate-on'] < first_post <= last_first_post <= rh['tInstalled'] <=
               active_capture <= active_ready <
               fh['tProgrammed'] <= fh['tActive'] <= authorized <=
               P['m2-3e-t-gate-open'] <= P['m2-3l-stop-request-time'] <= rh['tDisarmed'],
               'NIC stop, DTE entry, initial IOVA publication and active snapshot order differs')
        final_leaves = page_leaves(pt, dh['rootPA'], dh['ptBase'], dh['rootLevel'],
                                   (dh['iovaBase'], dh['iovaBase'] + dh['iovaBytes']))
        A.need(not final_leaves and
               P['m2-3s-fixed-pages'] == P['m2-3r-bootstrap-pages'] ==
               P['m2-3s-bootstrap-removed-pages'] ==
               P['m2-3r-restore-added-pages'] == P['m2-3r-identity-pages'] == 0,
               'IOVA-only lifecycle created identity mappings or retained final present leaves')
        resumed = driver_property('rtl812x-r35-rx-resume-time', True)
        A.need(P['m2-3p-rx-physical-resume'] == 'done' and
               P['m2-3e-t-translate-off'] <= resumed <= P['m2-3e-t-resume'],
               'normal RX replacement did not resume after register restoration')
        A.need(rb['count'] == RX_COUNT and rb['mapCalls'] == rb['mapOk'] ==
               rb['unmapCalls'] == rb['unmapOk'] == rh['maps'] == rh['unmaps'] and
               rb['mapOk'] == rh['posted'] and
               rb['flags'] == rb['mapRejects'] == rb['liveOwners'] == rb['boundPairs'] ==
               rb['coverCalls'] == rb['coverOk'] == rb['coverFailed'] == 0 and rb['ready'] == 1,
               'driver-owned RX map/unmap totals, zero physical cover or final ownership differs')
        A.need(0 < rb['tReady'] == P['m2-3o-rx-ready-time'] <=
               P['m2-3e-exit-gate-close'] <= stop['tStopped'] <= rb['tDrained'] and
               P['m2-3h-rx-live-owners'] == P['m2-3h-rx-pending'] == 0,
               'native RX readiness/drain or raw/property ownership differs')
        tx_sequences = {d[key]['expected'] for d in dom + [dh['probeFirst'], dh['probeReuse']]
                        for key in ('mapCommand', 'retireCommand')}
        fixed_detail, fixed_sequences = fixed_mappings(
            layout, fixed_spans, active_pt, active_leaves, tx_sequences)
        rx_sequences = {}
        batch_stats = {key: P['m2-3q-rx-' + key] for key in
                       ('map-invalidations', 'unmap-invalidations', 'map-batch-calls',
                        'unmap-batch-calls', 'map-batch-slots', 'unmap-batch-slots', 'max-batch')}
        for phase, total in (('map', rb['mapOk']), ('unmap', rb['unmapOk'])):
            calls = batch_stats[phase + '-batch-calls']
            slots = batch_stats[phase + '-batch-slots']
            invalidations = batch_stats[phase + '-invalidations']
            A.need(0 < calls <= slots <= RX_BATCH_MAX * calls and slots <= total and
                   invalidations == total - slots + calls,
                   phase + ' batch members/standard calls/invalidation totals differ')
        logical = rb['mapOk'] + rb['unmapOk']
        invalidations = batch_stats['map-invalidations'] + batch_stats['unmap-invalidations']
        A.need(1 < batch_stats['max-batch'] <= RX_BATCH_MAX and invalidations < logical,
               'normal RX did not exercise multi-slot invalidation coalescing')
        memory_ids, command_ids, leaf_tables, iovas = set(), set(), set(), set()
        initial_rx_pages = {}
        for i, (slot, driver_slot) in enumerate(zip(rxbackend, rxslots)):
            A.need(slot['flags'] == 0 and slot['sampleCount'] == 1 and
                   slot['mapCount'] == slot['unmapCount'] == driver_slot['mapCount'] ==
                   driver_slot['unmapCount'] == driver_slot['postCount'],
                   'RX slot %d mapping generations or retained sample differs' % i)
            pair = tuple(slot['first'][k] for k in ('memory', 'command'))
            A.need(all(pair) and pair[0] not in memory_ids and pair[1] not in command_ids,
                   'RX slot %d has missing or shared driver MD/Cmd identity' % i)
            memory_ids.add(pair[0]); command_ids.add(pair[1])
            for kind in ('first', 'last'):
                r, w = slot[kind], driver_slot[kind]
                label = 'RX slot %d %s: ' % (i, kind)
                generation = 1 if kind == 'first' else slot['mapCount']
                pages = ((r['pa'] & 4095) + RX_CAPACITY + 4095) // 4096
                A.need(r['slot'] == i and r['generation'] == generation and
                       tuple(r[k] for k in ('memory', 'command')) == pair and
                       r['pa'] > 0 and r['iova'] == RX_BASE + i * RX_STRIDE + (r['pa'] & 4095) and
                       r['iova'] != r['pa'] and r['mapLength'] == RX_CAPACITY and
                       r['pages'] == pages and 1 <= pages <= 2 and (r['mapOptions'] & 2),
                       label + 'unexpected driver-owned mapping geometry or generation')
                A.need(all(r[k] == w[k] for k in
                           ('generation', 'memory', 'command', 'pa', 'iova', 'tMapInv', 'tUnmapInv', 'slot')),
                       label + 'driver DMA witness is not the registered mapping')
                if kind == 'first':
                    A.need(r['pa'] == driver_slot['originalPA'] and r['mapBatch'] == 0 and
                           P['m2-3e-t-translate-on'] < r['tMapPublish'] <= r['tMapInv'] <=
                           w['tPost'] <= rh['tInstalled'] and
                           fh['tActive'] < w['tDone'],
                           label + 'install mapping was not posted directly before NIC enable')
                    for j in range(pages):
                        address = (r['iova'] & ~4095) + j * 4096
                        initial_rx_pages[address] = (r['pa'] & ~4095) + j * 4096
                stop_retired = bool(w['flags'] & WITNESS_STOP_RETIRED)
                A.need(r['flags'] == 7 and r['mapResult'] == r['unmapResult'] == 0 and
                       P['m2-3e-t-translate-on'] <= r['tMapPublish'] <= r['tMapInv'] <=
                       w['tPost'] <= r['tUnmapPublish'] <= r['tUnmapInv'] <=
                       rb['tDrained'] < P['m2-b2-t-recovery-start'],
                       label + 'map/OWN/unmap completion order differs')
                if stop_retired:
                    A.need(kind == 'last' and w['flags'] == 5 | WITNESS_STOP_RETIRED and
                           w['tDone'] == 0 and w['tPost'] <= stop['tStopped'] <= r['tUnmapPublish'],
                           label + 'uncompleted OWN retired before confirmed NIC stop')
                else:
                    A.need(w['flags'] == 7 and w['tPost'] < w['tDone'] <= r['tUnmapPublish'],
                           label + 'map/OWN/DMA/unmap completion order differs')
                for key in ('mapCommand', 'unmapCommand'):
                    c = r[key]
                    packed = r['mapBatch' if key == 'mapCommand' else 'unmapBatch']
                    first, width = packed & 0xffff, packed >> 16
                    A.need(c['expected'] > 0 and c['expected'] == c['observed'] and
                           c['words'] == [0, dh['domid'] | (3 << 28), 0xfffff003, 0x7fffffff] and
                           c['expected'] not in tx_sequences and c['expected'] not in fixed_sequences,
                           label + 'invalidation command/completion or TX/fixed sequence differs')
                    if packed:
                        A.need(first < RX_COUNT and 1 <= width <= RX_BATCH_MAX and
                               (i - first) % RX_COUNT < width,
                               label + 'slot is outside its declared invalidation batch')
                    else:
                        width = 1
                    signature = (key, packed, c['observed'], tuple(c['words']), c['tComplete'])
                    group = rx_sequences.get(c['expected'])
                    if group is None:
                        group = rx_sequences[c['expected']] = {'signature': signature, 'slots': set()}
                    else:
                        A.need(packed and group['signature'] == signature,
                               label + 'shared RX completion is not the same batch and phase')
                    A.need(i not in group['slots'] and len(group['slots']) < width,
                           label + 'repeated slot or too many retained members for this batch')
                    group['slots'].add(i)
                A.need(r['mapCommand']['expected'] < r['unmapCommand']['expected'] <= dh['completionSequence'] and
                       r['mapCommand']['tComplete'] == r['tMapInv'] and
                       r['unmapCommand']['tComplete'] == r['tUnmapInv'],
                       label + 'command confirmation timestamps differ')
                for j in range(2):
                    if j >= pages:
                        A.need(r['mapPte'][j] == r['clearPte'][j] == 0, label + 'unused PTE is not empty')
                        continue
                    iova = (r['iova'] & ~4095) + j * 4096
                    A.need(r['mapPte'][j] & A.PTE_IW and r['clearPte'][j] == 0,
                           label + 'RX PTE not writable or not cleared')
                    iovas.add(iova)
                    leaf_pa = rx_leaf_address(pt, dh['rootPA'], dh['ptBase'], dh['rootLevel'], iova)
                    leaf_tables.add(leaf_pa)
                    got, pte = A.walk_with_leaf(pt, dh['rootPA'], dh['ptBase'], leaf_pa,
                                                dh['rootLevel'], iova, r['mapPte'][j])
                    A.need(pte == r['mapPte'][j] and
                           (j != 0 or got == (r['pa'] & ~4095)),
                           label + 'RX PTE walk differs from the mapped receive buffer')
        active_rx_pages = {address: target for address, target in active_leaves.items()
                           if RX_BASE <= address < rx_end}
        A.need(active_rx_pages == initial_rx_pages and
               len(active_leaves) == len(initial_rx_pages) + fixed_detail['iovaPages'],
               'pre-enable active leaves differ from initial RX and fixed IOVA mappings')
        A.need(sum(s['mapCount'] for s in rxbackend) == rb['mapOk'] and
               sum(s['unmapCount'] for s in rxbackend) == rb['unmapOk'] and
               dh['commandCompleted'] >= 2 * dh['mapsTotal'] + invalidations + 2 * FIXED_COUNT,
               'shared command totals do not cover TX/probe, RX and fixed DMA')
        return {'mapped': rb['mapOk'], 'unmapped': rb['unmapOk'], 'initialMappings': RX_COUNT,
                'initialMappingsPosted': RX_COUNT, 'unpostedInitialMappings': 0,
                'stoppedBeforeDTE': True, 'initialIOVABeforeNICEnable': True,
                'driverOwnedPairs': len(memory_ids), 'liveOwners': 0,
                'source': 'lucy-normal-ring', 'ringId': rh['ringId'],
                'manifestRanges': RX_COUNT, 'bootstrapRanges': 0,
                'experimentalPoolRPCs': 0, 'experimentalSpares': 0,
                'physicalMode': 'iova-only', 'physicalLayoutGeneration': layout['generation'],
                'fixedPhysicalSpans': fixed_spans, 'fixedPhysicalPages': len(fixed_pages),
                'fixedDMA': fixed_detail,
                'bootstrapPages': 0, 'bootstrapRemovedPages': 0,
                'activeIdentityPages': len(active_identity),
                'activeRxIovaPages': sum(RX_BASE <= address < rx_end for address in active_leaves),
                'initialFirstPost': first_post, 'initialLastPost': last_first_post,
                'activeCaptureTime': active_capture, 'activeReadyTime': active_ready,
                'authorizedTime': authorized, 'restoreAddedPages': 0,
                'finalPresentLeaves': len(final_leaves), 'identityPages': 0, 'identityBytes': 0,
                'currentBufferPages': len(current_pages),
                'physicalCoverCalls': rb['coverCalls'],
                'physicalEvidence': 'NIC stopped before DTE entry; active initial RX and fixed DMA use IOVA; final tree has no present leaves; current physical buffers resume after original IOMMU restoration',
                'normalReplacementResumedAt': resumed,
                'mapInvalidations': batch_stats['map-invalidations'],
                'unmapInvalidations': batch_stats['unmap-invalidations'],
                'mapBatchCalls': batch_stats['map-batch-calls'],
                'unmapBatchCalls': batch_stats['unmap-batch-calls'],
                'mapBatchSlots': batch_stats['map-batch-slots'],
                'unmapBatchSlots': batch_stats['unmap-batch-slots'],
                'maxBatch': batch_stats['max-batch'],
                'meanMapBatch': batch_stats['map-batch-slots'] / batch_stats['map-batch-calls'],
                'meanUnmapBatch': batch_stats['unmap-batch-slots'] / batch_stats['unmap-batch-calls'],
                'invalidationCyclesSaved': logical - invalidations,
                'retainedInvalidationGroups': len(rx_sequences),
                'batchEvidence': 'retained members only; shared phase/range/command/completion',
                'retainedGenerations': RX_COUNT * 2, 'writablePages': len(iovas),
                'leafTables': len(leaf_tables), 'iovaBase': RX_BASE, 'slotBytes': RX_STRIDE,
                'mapBeforeOwn': True, 'unmapAfterCompletionOrNICStop': True}
    run('rx1024-driver-owned-MD-Cmd-repeated-mapping-and-unmap', rx_mappings)

    def rx_completions():
        A.need(rh['state'] == 4 and rh['flags'] == rh['nativeActive'] == rh['pendingPosted'] == 0 and
               rh['slotCount'] == rh['restored'] == RX_COUNT and rh['ringId'] > 0 and
               rh['businessToken'] == token and rh['posted'] == rh['completed'] + rh['stopRetired'] and
               rh['completed'] >= 2 * RX_COUNT and
               rh['posted'] == sum(s['postCount'] for s in rxslots) and
               rh['completed'] == sum(s['doneCount'] for s in rxslots) and
               rh['stopRetired'] == sum(s['stopRetired'] for s in rxslots) ==
               stop['stopRetired'] == P['m2-3h-rx-stop-retired'] and
               rh['replaced'] == sum(s['replaceCount'] for s in rxslots) > 0,
               'native RX cumulative DMA, normal replacement or restoration differs')
        A.need(0 < rh['tInstalled'] <= rb['tReady'] <= rh['tDisarmed'] <= rb['tDrained'] and
               rh['tLastRestore'] == max(s['tPhysicalOwn'] for s in rxslots) <= rb['tDrained'],
               'native RX install/disarm/physical restore order differs')
        replies, sends, peer_ids = {}, {}, set()
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
        business, replacements, changed, completed_samples = [], 0, 0, 0
        for i, slot in enumerate(rxslots):
            first, last = slot['first'], slot['last']
            label = 'native RX slot %d: ' % i
            A.need(slot['flags'] == 0 and slot['sampleCount'] == 1 and
                   slot['postCount'] == slot['doneCount'] + slot['stopRetired'] and
                   slot['doneCount'] >= 2 and slot['stopRetired'] in (0, 1) and
                   bool(last['flags'] & WITNESS_STOP_RETIRED) == bool(slot['stopRetired']) and
                   first['generation'] == 1 < last['generation'] == slot['mapCount'] and
                   first['tUnmapInv'] < last['tMapInv'] and
                   0 < slot['originalPA'] and 0 < slot['currentPA'] != last['iova'] and
                   rh['tDisarmed'] <= last['tUnmapInv'] <= slot['tPhysicalOwn'] and
                   stop['tStopped'] <= slot['tPhysicalOwn'],
                   label + 'first/final generation or current-buffer physical restoration differs')
            changed += first['pa'] != last['pa']
            for w in (first, last):
                if w['flags'] & WITNESS_STOP_RETIRED:
                    A.need(w is last and w['slot'] == i and w['flags'] == (5 | WITNESS_STOP_RETIRED) and
                           w['tDone'] == w['token'] == w['reqId'] == w['doneLength'] == w['replaced'] == 0 and
                           w['tPost'] <= stop['tStopped'] <= w['tUnmapInv'],
                           label + 'local stop retirement was relabelled as a DMA completion')
                    continue
                A.need(w['slot'] == i and w['flags'] == 7 and w['replaced'] in (0, 1) and
                       not w['doneStatus'] & 0x80000000 and
                       (w['doneStatus'] & 0x1fff) == w['doneLength'] and
                       0 < w['doneLength'] <= RX_CAPACITY,
                       label + 'DMA completion status/length or witness flags differ')
                completed_samples += 1
                replacements += w['replaced']
                if w['token'] or w['reqId']:
                    req = w['reqId']
                    A.need(w['token'] == token and req in REQUESTS and req in sends and
                           req in replies and req in peer_ids and
                           w['doneLength'] == len(payload(token, req)) + 46 and
                           sends[req] <= w['tDone'] <= replies[req],
                           label + 'R27P completion does not match actual application reply')
                    business.append(req)
        A.need(business and len(set(business)) == len(business),
               'unique business DMA sample is missing from native RX')
        return {'posted': rh['posted'], 'completed': rh['completed'], 'stopRetired': rh['stopRetired'],
                'restored': RX_COUNT,
                'pending': 0, 'replacements': rh['replaced'], 'retainedReplacementSamples': replacements,
                'firstLastPADifferentSlots': changed, 'sampledCompletions': completed_samples,
                'businessCompletions': len(business), 'applicationRequests': sorted(business),
                'correlation': 'first completed and final retired IOVA generation per slot; '
                               'real completions use R27P token+ID and FCS length; '
                               'stop retirement does not claim DMA completion',
                'scope': 'ordinary Lucy ring; driver-owned MD/Cmd pairs; normal mbuf replacement; '
                         'PA comparison covers first/final retained generations only; cumulative totals'}
    run('rx1024-native-replacement-DMA-and-current-buffer-restore', rx_completions)
    return result()


if __name__ == '__main__':
    report = check(Path(sys.argv[1]))
    text = json.dumps(report, indent=2) + '\n'
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(text, encoding='utf-8')
    else:
        print(text)
    raise SystemExit(0 if report['ok'] else 1)
