#!/usr/bin/env python3
"""Independent Round15 finite RX proof from exported bytes (no kext verdicts).

Walk the full capacity of every before/after pool entry and conservative RX-set
range against the complete used page-table arena. Correlate replacement records
with raw rearm records and later RX completions. This is an RX-only supplement,
not a replacement for analyze-round12.py's business/window/command checks.
Usage: py -3 tools/r15/analyze.py CAPTURE [OUTPUT_JSON]
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('round12_decode', ROOT / 'tools' / 'analyze-round12.py')
A = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A)
MODE = 'bootstrap-plus-owned-sparse4k'
PAGE = 4096
BOOTSTRAP_END = 16 << 30
ADDR_MASK = 0x000FFFFFFFFFF000
PR, IR, IW = 1, 1 << 61, 1 << 62
POOL_BYTES, ENTRY_COUNT, WITNESS_COUNT = 30328, 1088, 64


class Refused(ValueError):
    pass


def need(condition, why):
    if not condition:
        raise Refused(why)


def log_rows(text, tag):
    """Parse only explicit event rows, retaining line refs and rejecting duplicate keys."""
    out = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.startswith(tag + ' '):
            continue
        pairs = re.findall(r'(\w+)=([^\s]+)', line)
        row = dict(pairs)
        row['_line'] = number
        row['_valid'] = len(pairs) == len(set(k for k, _ in pairs))
        out.append(row)
    return out


def log_number(row, field):
    try:
        value = row[field]
        return int(value, 16 if value.lower().startswith('0x') else 10)
    except (KeyError, TypeError, ValueError):
        return None


def completion_log_proof(witness, done_ns, logs, flood):
    """Join one raw completion to the actual peer send and validated Mac receive.

    Windows peer time and Python3.9 final-client time are NOT comparable to the
    Mac kernel's mach clock. Only flood t_ns uses CLOCK_UPTIME_RAW explicitly.
    Lengths here are UDP payload bytes; this finite non-VLAN IPv4/UDP stimulus
    has 42 bytes of Ethernet/IP/UDP headers. Witness.doneLength is the raw
    descriptor length INCLUDING the four-byte FCS; OBS.len excludes that FCS.
    """
    logs = logs or {}
    filename = 'flood-client.log' if flood else 'client.log'
    text = logs.get(filename, '')
    tag = 'flood_recv' if flood else 'client_recv'
    bound_tag = 'flood_bound' if flood else 'client_bound'
    endpoints = re.findall(r'^' + bound_tag + r' ([^\s]+)\s*$', text, re.M)
    endpoint = endpoints[0] if len(endpoints) == 1 else None
    token, req = witness['token'], witness['reqId']
    payload_bytes = 1024 if flood else 32
    match = lambda row: (row['_valid'] and log_number(row, 'token') == token and
                         log_number(row, 'req') == req)
    sent = [r for r in log_rows(logs.get('peer.log', ''), 'peer_sent')
            if match(r) and r.get('to') == endpoint and endpoint is not None]
    received = [r for r in log_rows(text, tag) if match(r)]
    peer_endpoints = {r.get('bind') for r in log_rows(logs.get('peer.log', ''), 'peer_start')
                      if r['_valid'] and r.get('bind')}
    peer_endpoint = next(iter(peer_endpoints)) if len(peer_endpoints) == 1 else None
    reasons = []
    if endpoint is None:
        reasons.append('missing-or-ambiguous-Mac-bound-endpoint')
    if len(sent) != 1 or log_number(sent[0], 'len') != payload_bytes:
        reasons.append('missing-ambiguous-or-wrong-length-peer-send')
    if len(received) != 1:
        reasons.append('missing-or-ambiguous-Mac-receive')
    if witness['doneLength'] != payload_bytes + 46:
        reasons.append('kernel-frame-length-does-not-match-full-payload')
    if flood and len(received) == 1:
        row = received[0]
        if log_number(row, 'len') != payload_bytes or log_number(row, 'payload_ok') != 1:
            reasons.append('Mac-did-not-log-full-validated-payload')
        if peer_endpoint is None or row.get('from') != peer_endpoint:
            reasons.append('Mac-flood-source-does-not-match-peer-endpoint')
        when = log_number(row, 't_ns')
        if when is None or when < done_ns:
            reasons.append('Mac-receive-precedes-kernel-completion-or-time-missing')
    if not flood:
        # Existing final client logs recv only after data == its sent payload.
        # Bind that record to its explicit full-length send; never order clocks.
        client_sent = [r for r in log_rows(text, 'client_sent') if match(r)]
        if len(client_sent) != 1 or log_number(client_sent[0], 'len') != payload_bytes:
            reasons.append('final-client-full-payload-send-missing-or-ambiguous')
    return {'ok': not reasons, 'why': reasons, 'peer_log': 'peer.log',
            'peer_send_lines': [r['_line'] for r in sent], 'mac_log': filename,
            'mac_receive_lines': [r['_line'] for r in received],
            'endpoint': endpoint, 'peer_endpoint': peer_endpoint, 'payload_bytes': payload_bytes,
            'kernel_frame_bytes': witness['doneLength']}


def decode_pool(blob):
    need(len(blob) == POOL_BYTES, 'pool: fixed ABI size must be 30328')
    names = ('version bytes state generation poolId tPrepared tAuthorized '
             'mapCompletedAt deadline epoch vtdPath mtu bufferSize entryCount '
             'spareCount allocationAttempts highSpareCount replacements '
             'completions rxCompletions copyFailures flags replaceLimit reserved0 reserved1').split()
    h = dict(zip(names, struct.unpack_from('<4I5Q16I', blob)))
    need(h['version'] == 1 and h['bytes'] == POOL_BYTES, 'pool: unknown ABI')
    need(h['entryCount'] == ENTRY_COUNT and h['spareCount'] == 64,
         'pool: expected current1024 plus finite64 spare entries')
    need(h['replacements'] <= WITNESS_COUNT, 'pool: witness count exceeds ABI')
    need(not any(blob[26232 + h['replacements'] * 64:]),
         'pool: witness body exists beyond declared replacements')
    enames = ('addr capacity id kind reserved').split()
    entries = [dict(zip(enames, struct.unpack_from('<Q4I', blob, 120 + i * 24)))
               for i in range(ENTRY_COUNT)]
    wnames = ('oldAddr newAddr tPost tDone slot capacity entryId flags token '
              'reqId doneLength doneStatus').split()
    witnesses = [dict(zip(wnames, struct.unpack_from('<4Q8I', blob, 26232 + i * 64)))
                 for i in range(h['replacements'])]
    return h, entries, witnesses


class Tables:
    """Only reads owned arena bytes; no physical-memory dereference or global top."""
    def __init__(self, blob, base, root, level):
        need(base > 0 and base % PAGE == 0 and len(blob) % PAGE == 0,
             'PT: bad arena geometry')
        need(level in (3, 4), 'PT: expected mode3/mode4')
        self.blob, self.base, self.root, self.level = blob, base, root, level
        self.entry(root, 0)

    def entry(self, table, index):
        need(table % PAGE == 0 and self.base <= table <= self.base + len(self.blob) - PAGE,
             'PT: table outside exported arena')
        return struct.unpack_from('<Q', self.blob, table - self.base + index * 8)[0]

    @staticmethod
    def decode(raw, level):
        need(raw & PR, 'PT: absent entry')
        need(raw & ~(ADDR_MASK | IR | IW | (1 << 60) | 0xE01) == 0,
             'PT: unexpected reserved encoding bits')
        nl = (raw >> 9) & 7
        if nl == 0:
            size = 1 << (9 * level + 3)
            out = raw & ADDR_MASK
            need(out % size == 0, 'PT: unaligned default leaf')
            return ('leaf', out, size)
        # This exact experiment uses default leaves, never enlarged NL=7 or skips.
        need(level > 1 and nl == level - 1, 'PT: illegal/unexpected NextLevel')
        return ('table', raw & ADDR_MASK, nl)

    def walk(self, addr, capacity):
        end = addr + capacity
        need(addr > 0 and capacity > 0 and end < (1 << 64), 'range: zero/overflow')
        need(end <= 1 << (12 + 9 * self.level), 'range: root address width exceeded')
        need(not (addr < 0x100000000 and end > 0xE0000000), 'range: known MMIO hole')
        cur, paths = addr, []
        while cur < end:
            table, level, path = self.root, self.level, []
            while True:
                ix = (cur >> (9 * level + 3)) & 511
                raw = self.entry(table, ix)
                need(raw & IW, 'PT: RX write permission absent at a path level')
                kind, out, value = self.decode(raw, level)
                path.append({'table': table, 'level': level, 'index': ix, 'raw': raw})
                if kind == 'table':
                    table, level = out, value
                    continue
                need(out + (cur & (value - 1)) == cur, 'PT: nonidentity leaf')
                step = min(end - cur, value - (cur & (value - 1)))
                paths.append({'from': cur, 'bytes': step, 'leafSize': value, 'path': path})
                cur += step
                break
        return paths

    def sparse_leaves(self, entries):
        """Reject broad high mappings: every high 4KiB page must be owned."""
        owned = set()
        for e in entries:
            lo, hi = e['addr'] & -PAGE, (e['addr'] + e['capacity'] + PAGE - 1) & -PAGE
            need(hi - lo <= 1 << 20, 'pool: implausibly large entry capacity')
            owned.update(range(lo, hi, PAGE))
        pending, visited, high = [(self.root, self.level, 0)], set(), []
        while pending:
            table, level, iova = pending.pop()
            need(table not in visited, 'PT: cycle/aliased table page')
            visited.add(table)
            need(len(visited) <= len(self.blob) // PAGE, 'PT: table traversal budget')
            span = 1 << (9 * level + 3)
            for ix in range(512):
                raw = self.entry(table, ix)
                if not raw & PR:
                    continue
                kind, out, value = self.decode(raw, level)
                here = iova + ix * span
                need(raw & IW and raw & IR, 'PT: reachable entry lacks IR/IW')
                if kind == 'table':
                    pending.append((out, value, here))
                else:
                    need(out == here, 'PT: nonidentity reachable leaf')
                    if here + value > BOOTSTRAP_END:
                        need(value == PAGE and here in owned,
                             'PT: high leaf is not one actual-owned 4KiB page')
                        high.append(here)
        return high


def analyze_payloads(p, before_blob, after_blob, table_blob, rx_blob, obs_blob, logs=None):
    checks, details = [], {}

    def check(cid, ok, detail=''):
        checks.append({'id': cid, 'state': 'ok' if ok else 'fail', 'detail': detail})
        return ok

    def guarded(cid, operation):
        try:
            value = operation()
            check(cid, True)
            return value
        except (Refused, KeyError, TypeError, ValueError, struct.error) as exc:
            check(cid, False, str(exc))
            return None

    need(p.get('m2-b2-r15-map-mode') == MODE, 'not the Round15 sparse-owned mode')
    bh, before, _ = decode_pool(before_blob)
    ah, after, witnesses = decode_pool(after_blob)
    numer, denom = p.get('m2-b2-r15-timebase-numer'), p.get('m2-b2-r15-timebase-denom')
    need(isinstance(numer, int) and isinstance(denom, int) and numer > 0 and denom > 0,
         'timebase: positive numer/denom required')
    ns = lambda ticks: ticks * numer // denom
    ws, we = p.get('m2-b2-dma-t-win-start'), p.get('m2-b2-dma-t-win-end')
    need(isinstance(ws, int) and isinstance(we, int) and 0 < ws < we,
         'actual DMA-window bounds absent/invalid')
    need(0 < bh['bufferSize'] <= 65536 and
         all(0 < e['capacity'] <= 65536 and 0 < e['addr'] < (1 << 52) for e in before + after),
         'pool: invalid/full-capacity bound exceeded')
    check('pool-states', bh['state'] == 1 and ah['state'] in (2, 3))
    check('pool-identity', bh['poolId'] != 0 and all(bh[k] == ah[k] for k in
          ('poolId', 'generation', 'epoch', 'vtdPath', 'mtu', 'bufferSize', 'tPrepared')))
    check('pool-manifest-stable', before == after)
    check('pool-no-loss-or-reset', bh['flags'] == ah['flags'] == 0 and
          bh['copyFailures'] == ah['copyFailures'] == 0 and ah['vtdPath'] == 0)
    check('pool-finite', 0 < ah['replaceLimit'] <= 64 and
          0 < ah['replacements'] <= ah['replaceLimit'] and
          0 < ah['completions'] <= ah['replacements'] and
          64 <= bh['allocationAttempts'] <= 576)
    check('pool-before-unmodified', bh['replacements'] == bh['completions'] == 0)
    ids = {e['id']: e for e in before}
    ranges = {(e['addr'], e['capacity']) for e in before}
    check('pool-unique-manifest', len(ids) == len(ranges) == ENTRY_COUNT and
          len({e['addr'] for e in before}) == ENTRY_COUNT)
    check('pool-entry-kinds', sum(e['kind'] == 1 for e in before) == 1024 and
          sum(e['kind'] == 2 for e in before) == 64 and
          {e['id'] for e in before if e['kind'] == 1} == set(range(1024)) and
          {e['id'] for e in before if e['kind'] == 2} == set(range(1024, 1088)) and
          all(e['capacity'] == bh['bufferSize'] for e in before))
    source_counts = {'native_ring': sum(e['kind'] == 1 and e['reserved'] == 0 for e in before),
                     'native_spare': sum(e['kind'] == 2 and e['reserved'] == 0 for e in before),
                     'external_spare': sum(e['kind'] == 2 and e['reserved'] == 2 for e in before)}
    check('pool-entry-sources', all((e['kind'] == 1 and e['reserved'] == 0) or
          (e['kind'] == 2 and e['reserved'] in (0, 2)) for e in before))
    # Legacy Run1 has native-only entries and no physical counter. Missing is
    # zero only in that case: any source2 entry still requires a positive counter.
    physical_attempts = p.get('m2-b2-r15-physical-allocation-attempts', 0)
    native_attempts = (bh['allocationAttempts'] - physical_attempts
                       if isinstance(physical_attempts, int) else None)
    check('pool-physical-allocation-bound', isinstance(physical_attempts, int) and
          0 <= physical_attempts <= 64 and source_counts['external_spare'] <= physical_attempts and
          (source_counts['external_spare'] == 0 or physical_attempts > 0))
    check('pool-native-allocation-bound', isinstance(native_attempts, int) and
          source_counts['native_spare'] <= native_attempts <= 512)
    check('pool-allocation-counter-stable', bh['allocationAttempts'] == ah['allocationAttempts'])
    details['allocation_policy'] = {'source_counts': source_counts,
        'entry_source_values': {'0': 'native-mbuf', '2': 'external-IOBuffer-mbuf_attachcluster'},
        'total_attempts': bh['allocationAttempts'], 'total_attempt_limit': 576,
        'native_attempts': native_attempts, 'native_attempt_limit': 512,
        'physical_attempts': physical_attempts, 'physical_attempt_limit': 64,
        'physical_counter_present': 'm2-b2-r15-physical-allocation-attempts' in p,
        'physical_counter_source': 'm2-b2-r15-physical-allocation-attempts',
        'external_owned_bytes': sum(e['capacity'] for e in before if e['reserved'] == 2)}
    sorted_ranges = sorted(ranges)
    check('pool-no-overlap', all(a + c <= b for (a, c), (b, _) in
                               zip(sorted_ranges, sorted_ranges[1:])))
    check('pool-high-spare-count', bh['highSpareCount'] == ah['highSpareCount'] ==
          sum(e['kind'] == 2 and e['addr'] + e['capacity'] > BOOTSTRAP_END for e in before))
    map_ns, dte_ns = p.get('m2-b2-r15-map-time'), p.get('m2-b2-dma-t-dte-written')
    inv_ns = p.get('m2-b2-r15-inv-time')
    guarded('pool-visibility-timeline', lambda: need(
        ns(bh['tPrepared']) <= map_ns < dte_ns < inv_ns == ns(ah['mapCompletedAt'])
        <= ns(ah['tAuthorized']) <= ws < we <= ns(ah['deadline']),
        'required prepared<=map<DTE<invalidation<=authorization<=window<=deadline'))
    rx = A.decode_rxpost(rx_blob)
    need(rx['ok'], 'RX raw: ' + str(rx['why']))
    rh = rx['hdr']
    details['timeline_ns'] = {'prepared': ns(bh['tPrepared']), 'map_completed': map_ns,
        'dte_written': dte_ns, 'invalidation_complete': inv_ns,
        'authorized': ns(ah['tAuthorized']), 'window_start': ws, 'window_end': we,
        'rx_published': ns(rh['tPublished']), 'deadline': ns(ah['deadline'])}
    check('rx-published-through-end', ns(rh['tPublished']) >= we)
    check('rx-baseline-clean', rh['baselineSlots'] == rh['baselineValid'] == 1024 and
          rh['baselineTorn'] == rh['baselineGenMoved'] == rh['baselineCapBad'] == 0 and
          rh['baselineAddrZero'] == rh['flags'] == rh['dropped'] == rh['wrapped'] == 0 and
          rh['epoch'] == ah['epoch'])
    check('rx-baseline-body', {s['slot'] for s in rx['slots']} == set(range(1024)) and
          all(s['gen'] == rh['ringGen'] and s['capacity'] == bh['bufferSize'] and
              not s['flags'] & 0x70 and s['addr'] > 0 and
              ((s['blen'] & (1 << 31) and s['flags'] & 4 and
                s['blen'] & 0x3FFFFFFF == s['capacity']) or
               (not s['blen'] & (1 << 31) and s['flags'] & 8)) for s in rx['slots']))
    wm, head = p.get('m2-b2-rxset-watermark'), rh['head']
    need(isinstance(wm, int) and 0 <= wm <= head and
         head - wm <= rh['rearmCapacity'] <= 4096 and len(rx['rearms']) <= 4096,
         'RX raw: missing pre-window watermark or unbounded rearm suffix')
    check('rx-rearm-body', all(r['capacity'] == bh['bufferSize'] and
          r['blenRaw'] & 0x3FFFFFFF == r['capacity'] and r['blenRaw'] & (1 << 31) and
          0 <= r['slot'] < 1024 and r['addr'] > 0 for r in rx['rearms']))
    tickets = [r['seq'] >> 1 for r in rx['rearms'] if r['seq'] and not r['seq'] & 1]
    check('rx-gap-free', len(tickets) == len(rx['rearms']) == len(set(tickets)) and
          set(range(wm + 1, head + 1)).issubset(tickets) and
          rh['rearmPublished'] >= rh['rearmRequired'] and
          p.get('m2-b2-rxset-pre-ring-gen') == rh['ringGen'] == ah['generation'] != 0)
    rebuilt, stats = A.rebuild_rx_set(rx)
    details['rx_set'] = stats
    need(table_blob and len(table_blob) == p.get('m2-b2-r15-pt-used-pages', 0) * PAGE,
         'PT: used-pages disagrees with exact exported prefix')
    root, level = p.get('m2-b2-pt-root-pa'), p.get('m2-b2-page-mode')
    tables = Tables(table_blob, p.get('m2-b2-r15-pt-base'), root, level)
    dte = p.get('m2-b2-rxset-dte-raw', 0)
    check('pt-root-dte-binding', dte & 3 == 3 and dte & IR and dte & IW and
          dte & ADDR_MASK == root and
          (dte >> 9) & 7 == level and p.get('m2-b2-rxset-dte-root-pa') == root and
          p.get('m2-b2-rxset-root-level') == level)
    high = guarded('sparse-only-owned-high-pages', lambda: tables.sparse_leaves(before))
    details['high_mapped_pages'] = high
    for label, collection in (('pool-before', before), ('pool-after', after),
                              ('rxset', list(rebuilt.values()))):
        failures, walked = [], 0
        for entry in collection:
            try:
                tables.walk(entry['addr'], entry['capacity'])
                walked += 1
            except Refused as exc:
                failures.append({'addr': entry['addr'], 'capacity': entry['capacity'], 'why': str(exc)})
        details[label] = {'ranges': len(collection), 'ok': walked, 'failures': failures,
            'bytes_total': sum(e['capacity'] for e in collection),
            'min_addr': min((e['addr'] for e in collection), default=None),
            'max_end': max((e['addr'] + e['capacity'] for e in collection), default=None)}
        check(label + '-full-capacity-covered', bool(collection) and not failures,
              '%d/%d ranges independently walked' % (walked, len(collection)))
    n_events = p.get('m2-b2-win-raw-count')
    need(isinstance(n_events, int) and 0 <= n_events <= 512 and
         p.get('m2-b2-win-raw-truncated') == 'no', 'events: missing/truncated raw event window')
    faults = []
    for i in range(n_events):
        text = p.get('m2-b2-win-raw%d' % i)
        need(isinstance(text, str) and re.fullmatch('[0-9a-fA-F]{32}', text),
             'events: malformed raw entry')
        words = [int(text[j:j + 8], 16) for j in range(0, 32, 8)]
        if words[1] >> 28 == 2:
            raw_addr = words[2] | words[3] << 32
            addr = raw_addr & -PAGE
            try:
                path = tables.walk(addr, PAGE)
                why = None
            except Refused as exc:
                path, why = None, str(exc)
            faults.append({'addr': addr, 'raw_addr': raw_addr, 'device': words[0] & 0xFFFF, 'path': path,
                           'why': why, 'in_owned_pool': any(e['addr'] <= raw_addr <
                           e['addr'] + e['capacity'] for e in before)})
    details['faults'] = faults
    # The producer omits the per-type counter only on its empty-window branch.
    # Absence is zero ONLY with three independent explicit zero counts; a
    # nonempty or partially described window still requires the real counter.
    empty_window = (len(faults) == 0 and all(p.get(key) == 0 for key in
        ('m2-b2-win-new-entries', 'm2-b2-win-entries', 'm2-b2-win-raw-count')))
    type2_present = 'm2-b2-win-type2-count' in p
    check('fault-count-agrees',
          p.get('m2-b2-win-type2-count') == len(faults) if type2_present else empty_window,
          'type2=%s decoded=%d explicitEmpty=%s'
          % (p.get('m2-b2-win-type2-count'), len(faults), empty_window))
    check('fault-actual-paths', all(f['path'] is not None for f in faults),
          'fault addresses are judged from raw table paths, never the bootstrap limit')
    need(len(obs_blob) >= A.HDR_BYTES and
         (len(obs_blob) - A.HDR_BYTES) % A.REC_BYTES == 0, 'OBS: ragged raw snapshot')
    oh = A.decode_header(obs_blob)
    need((oh['magic'], oh['version'], oh['recSize']) == (A.OBS_MAGIC, 2, 72) and
         0 < oh['recordCount'] <= 512, 'OBS: bad ABI/finite suffix bound')
    records = [A.valid_record(obs_blob, oh, i) for i in range(oh['recordCount'])]
    # A publication may honestly be the normal last512 suffix. Defined
    # TRUNCATED means omitted pre-window history, not a hole in included tickets.
    # Its oldest actual record must still reach the actual window start.
    oldest_obs = min((r['t'] for r in records if r is not None), default=0)
    obs_contiguous = (all(r is not None and r['t'] > 0 for r in records) and
        0 < oh['firstTicket'] == oh['head'] - oh['recordCount'] + 1 and
        oh['lastTicket'] == oh['head'] and oh['validCount'] == oh['recordCount'] and
        oh['recordCount'] == min(oh['head'], 512) <= oh['capacity'] and
        bool(oh['flags'] & 4) == (oh['head'] > oh['recordCount']))
    obs_clean = (oh['dropped'] == oh['wrapped'] == oh['lostCount'] == 0 and
        oh['flags'] & ~4 == 0 and obs_contiguous and oh['epoch'] == ah['epoch'] and
        0 < ns(oldest_obs) <= ws and ns(oh['tPublished']) >= we)
    check('obs-clean-and-current', obs_clean,
          'flags=%d includedTickets=%d..%d oldestNS=%d window=%d..%d publishedNS=%d'
          % (oh['flags'], oh['firstTicket'], oh['lastTicket'], ns(oldest_obs), ws, we,
             ns(oh['tPublished'])))
    details['obs_window'] = {'header': oh, 'included_tickets_contiguous': obs_contiguous,
        'oldest_ns': ns(oldest_obs), 'actual_window_start_ns': ws,
        'actual_window_end_ns': we, 'published_ns': ns(oh['tPublished'])}
    token, batch = p.get('m2-b2-obs-declared-token'), p.get('m2-b2-obs-expected-batch')
    need(isinstance(token, int) and token != 0 and isinstance(batch, int) and batch > 0,
         'controlled token/batch missing')
    check('finite-business-obs-scope', p.get('m2-b2-r15-obs-scope') ==
          'declared-business-only; all-rxpost-and-pool-witnesses-retained' and
          bh['reserved0'] == ah['reserved0'] == token and ah['reserved1'] >= bh['reserved1'])
    details['obs_scope'] = {'scope': p.get('m2-b2-r15-obs-scope'),
                            'declared_token': ah['reserved0'],
                            'filtered_before_tickets': ah['reserved1'],
                            'claim': 'finite declared business, not all TX traffic'}
    check('witness-unique-replacements', len({w['entryId'] for w in witnesses}) == len(witnesses) and
          len({w['newAddr'] for w in witnesses}) == len(witnesses))
    flood_token = p.get('m2-b2-r15-flood-token')
    flood_first, flood_last = p.get('m2-b2-r15-flood-req-first'), p.get('m2-b2-r15-flood-req-last')
    check('flood-identity', flood_token == token ^ 0x80000000 and
          isinstance(flood_first, int) and isinstance(flood_last, int) and
          0 < flood_first <= flood_last)
    completed, background, controlled = 0, 0, []
    kernel_controlled, log_proofs = [], {}
    slot_address = {e['id']: e['addr'] for e in before if e['kind'] == 1}
    for i, w in enumerate(witnesses):
        entry = ids.get(w['entryId'], {})
        posted = ns(w['tPost'])
        linked = (entry.get('kind') == 2 and entry.get('addr') == w['newAddr'] and
                  entry.get('capacity') == w['capacity'] and
                  (w['oldAddr'], w['capacity']) in ranges and w['oldAddr'] != w['newAddr'] and
                  slot_address.get(w['slot']) == w['oldAddr'] and
                  0 <= w['slot'] < 1024 and ws <= posted <= we and
                  posted >= ns(ah['tAuthorized']) and w['flags'] & ~1 == 0)
        slot_address[w['slot']] = w['newAddr']
        rearm = [r for r in rx['rearms'] if r['seq'] and not r['seq'] & 1 and
                 r['addr'] == w['newAddr'] and r['oldAddr'] == w['oldAddr'] and
                 r['slot'] == w['slot'] and r['capacity'] == w['capacity'] and
                 posted <= ns(r['t']) <= we]
        check('witness%d-post-rearm' % i, linked and bool(rearm))
        if not w['flags'] & 1:
            check('witness%d-pending-consistent' % i, all(w[k] == 0 for k in
                  ('tDone', 'token', 'reqId', 'doneLength', 'doneStatus')))
            continue
        completed += 1
        done = ns(w['tDone'])
        # Completion evidence is the independently latched fixed64 Witness
        # array, not the last512 mixed OBS records. An absent suffix row cannot
        # erase a completed witness; a present row must nevertheless agree.
        matching = [r for r in records if r is not None and r['kind'] == 3 and
                    r['addr'] == w['newAddr'] and r['slot'] == w['slot'] and
                    r['token'] == w['token'] and r['reqId'] == w['reqId']]
        # OBS reports pktSize after subtracting FCS; the latched witness
        # reports descriptor raw length. Keep both meanings, not a relaxed match.
        suffix_agrees = all(r['len'] + 4 == w['doneLength'] and r['opts1'] == w['doneStatus'] and
                            posted < ns(r['t']) <= we and not r['flags'] & (1 << 6)
                            for r in matching)
        valid = (linked and bool(rearm) and posted < done <= we and
                 any(ns(r['t']) < done for r in rearm) and
                 4 < w['doneLength'] <= w['capacity'] and
                 w['doneLength'] == w['doneStatus'] & 0x1FFF and
                 not w['doneStatus'] & ((1 << 31) | (1 << 21)) and suffix_agrees)
        check('witness%d-later-completion' % i, valid)
        final_id = w['token'] == token and 1 <= w['reqId'] <= batch
        flood_id = (w['token'] == flood_token and isinstance(flood_first, int) and
                    isinstance(flood_last, int) and flood_first <= w['reqId'] <= flood_last)
        if valid and (final_id or flood_id):
            kernel_controlled.append(i)
            proof = completion_log_proof(w, done, logs, flood=flood_id)
            log_proofs[i] = proof
            check('witness%d-controlled-payload' % i, proof['ok'], '; '.join(proof['why']))
            if proof['ok']:
                controlled.append(i)
        elif valid:
            background += 1
    check('witness-completion-count', completed == ah['completions'])
    check('controlled-replacement-completed', bool(controlled))
    details['witnesses'] = {'posted': len(witnesses), 'completed': completed,
                            'pending': len(witnesses) - completed,
                            'background_completed': background,
                            'kernel_controlled': kernel_controlled,
                            'controlled': controlled, 'payload_log_proofs': log_proofs,
                            'raw': witnesses}
    # A high address is a reported dimension, NOT a precondition for the finite run.
    details['above_16gib_owned'] = sum(e['addr'] + e['capacity'] > BOOTSTRAP_END for e in before)
    details['above_16gib_controlled'] = [i for i in controlled if
        witnesses[i]['newAddr'] + witnesses[i]['capacity'] > BOOTSTRAP_END]
    return {'scope': 'round15-finite-rx-only', 'ok': all(c['state'] == 'ok' for c in checks),
            'checks': checks, 'details': details}


def capture_blob(cap, raw, props, key, sha_key, filename):
    matches = {bytes.fromhex(x) for x in re.findall(r'"' + re.escape(key) + r'"\s*=\s*<([0-9a-fA-F]+)>', raw)}
    need(len(matches) == 1, key + ': missing/conflicting raw OSData')
    blob = matches.pop()
    file = cap / filename
    if file.exists():
        need(file.read_bytes() == blob, filename + ': archived file differs from OSData')
    sha = hashlib.sha256(blob).hexdigest()
    need(props.get(sha_key) == sha, key + ': sha256 mismatch/missing')
    return blob


def main():
    if len(sys.argv) not in (2, 3):
        print(__doc__)
        return 2
    cap = Path(sys.argv[1])
    try:
        p = A.hexprops((cap / 'props.txt').read_text(encoding='utf-8', errors='replace'))
        raw = (cap / 'props.raw.txt').read_text(encoding='utf-8', errors='replace')
        args = []
        for key, sha, name in (
                ('m2-b2-r15-pool-before-raw', 'm2-b2-r15-pool-before-sha256', 'r15-pool-before-raw.bin'),
                ('m2-b2-r15-pool-raw', 'm2-b2-r15-pool-sha256', 'r15-pool-raw.bin'),
                ('m2-b2-r15-pt-raw', 'm2-b2-r15-pt-sha256', 'r15-pt-raw.bin'),
                ('m2-b2-rxset-raw', 'm2-b2-rxset-raw-sha256', 'rxset-raw.bin'),
                ('m2-b2-obs-snapshot-used', 'm2-b2-obs-used-sha256', 'obs-snapshot-used.bin')):
            args.append(capture_blob(cap, raw, p, key, sha, name))
        logs = {name: ((cap / name).read_text(encoding='utf-8', errors='replace')
                       if (cap / name).is_file() else '')
                for name in ('peer.log', 'flood-client.log', 'client.log')}
        result = analyze_payloads(p, *args, logs=logs)
    except (OSError, Refused, TypeError, KeyError, ValueError, struct.error) as exc:
        result = {'scope': 'round15-finite-rx-only', 'ok': False, 'refused': str(exc)}
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if len(sys.argv) == 3:
        Path(sys.argv[2]).write_text(text + '\n', encoding='utf-8')
    print(text)
    return 2 if 'refused' in result else (0 if result['ok'] else 1)


if __name__ == '__main__':
    sys.exit(main())
