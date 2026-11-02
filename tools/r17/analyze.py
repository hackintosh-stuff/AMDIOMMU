#!/usr/bin/env python3
"""Independent Round17 proof: native-mbuf TX mapping with per-packet recycling.

No producer success string is a verdict. Everything below is recomputed from
exported bytes and the two endpoint logs:

  * domain ABI  -> per generation: real physical segments, actual map PTEs,
    actual clear PTEs, both raw invalidation commands with their CompletionWait;
  * page tables -> for every descriptor IOVA, walk root -> leaf from the
    exported arena and require it to resolve to the generation's own PA;
  * driver ABI  -> per generation: handle, descriptors as programmed, close
    pointer sample, tOwn / tFree;
  * OBS records -> the actual submit/done pair by cumulative index;
  * client/peer -> the full application bytes of all 32 requests.

The round-17 questions the checks answer, in order:
  1. is the DMA backing the packet's OWN physical segments (no staging copy)?
  2. do the descriptors carry non-identity IOVAs derived from those pages?
  3. did the hardware complete each one (close pointer, not OWN readback)?
  4. was each mbuf released after ITS retire, before the next request mapped?
  5. is the live DMA-owner count bounded (never a function of how many
     requests have succeeded so far)?
  6. does at least one generation exercise a cross-page or multi-segment map?

Usage: py -3 tools/r17/analyze.py CAPTURE [OUTPUT_JSON]
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from protocol import REQUESTS, length_of, payload   # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('r15decode', ROOT / 'tools/r15/analyze.py')
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)
need, Refused, A = R.need, R.Refused, R.A

PAGE = 4096
BASE = 0x1000000000
MASK = 0x000FFFFFFFFFF000
FC, IR, IW = 1 << 60, 1 << 61, 1 << 62
DOMAIN_HEADER, DOMAIN_RECORD_BYTES, DOMAIN_RECORDS = 80, 720, len(REQUESTS)
DRIVER_HEADER, DRIVER_RECORD_BYTES = 88, 576
DRIVER_MAGIC = 0x37315854
FRAME_OVERHEAD = 42          # Ethernet 14 + IPv4 20 + UDP 8, no VLAN
EXPECTED_SUBMITS = 2 * len(REQUESTS)
BUDGET_FLOOR = EXPECTED_SUBMITS


def unpack(names, fmt, blob, off=0):
    return dict(zip(names.split(), struct.unpack_from('<' + fmt, blob, off)))


def command(blob, off):
    r = unpack('d0 d1 d2 d3 expected observed tComplete', '4I3Q', blob, off)
    r['words'] = [r.pop('d%d' % i) for i in range(4)]
    return r


def decode_domain(blob):
    need(len(blob) == DOMAIN_HEADER + DOMAIN_RECORDS * DOMAIN_RECORD_BYTES,
         'domain: fixed ABI size for %d records required' % DOMAIN_RECORDS)
    h = unpack('version bytes count flags iovaBase iovaBytes rootPA leafPA '
               'ptBase ptBytes rootLevel devid domid active', '4I6Q4I', blob)
    # The allocation is fixed at 32 slots. `count` may be smaller (an aborted
    # run); completeness is a separate CHECK, so a partial run is still
    # decodable and still archiveable.
    need(h['version'] == 2 and h['bytes'] == len(blob) and
         0 < h['count'] <= DOMAIN_RECORDS, 'domain: unknown ABI or record count')
    records = []
    for i in range(DOMAIN_RECORDS):
        at = DOMAIN_HEADER + i * DOMAIN_RECORD_BYTES
        r = unpack('handle tMapPublish tMapInv tClearPublish tRetireInv count pages '
                   'token req status reserved', '5Q6I', blob, at)
        r['segments'] = [unpack('pa bytes iova', '3Q', blob, at + 64 + j * 24)
                         for j in range(8)]
        for j, key in enumerate(('physical', 'mapPte', 'clearPte')):
            r[key] = list(struct.unpack_from('<16Q', blob, at + 256 + j * 128))
        r['mapCommand'] = command(blob, at + 640)
        r['retireCommand'] = command(blob, at + 680)
        records.append(r)
    return h, records


def decode_driver(blob):
    need(len(blob) == DRIVER_HEADER + DOMAIN_RECORDS * DRIVER_RECORD_BYTES,
         'driver: fixed ABI size for %d witnesses required' % DOMAIN_RECORDS)
    h = unpack('magic version bytes count bdf token dropped state retired '
               'rejected maxHeld reserved txNext txDirty txClose txFree '
               'txDescDone completeCalls completeHits lastSeenSlot tPublished',
               '20IQ', blob)
    need(h['magic'] == DRIVER_MAGIC and h['version'] == 2 and
         h['bytes'] == len(blob) and 0 <= h['count'] <= DOMAIN_RECORDS,
         'driver: unknown ABI or impossible witness count')
    rows = []
    for i in range(DOMAIN_RECORDS):
        at = DRIVER_HEADER + i * DRIVER_RECORD_BYTES
        r = unpack('version bytes bdf token req count handle tMap tDone tRetire',
                   '6I4Q', blob, at)
        r['physical'] = [unpack('address length', '2Q', blob, at + 56 + j * 16)
                         for j in range(8)]
        r['iova'] = [unpack('address length', '2Q', blob, at + 184 + j * 16)
                     for j in range(8)]
        r.update(unpack('tOwn tFree cumulative firstSlot lastSlot retired '
                        'doneClose closeMask', '2Q6I', blob, at + 312))
        r['descriptors'] = [unpack('address length opts1 opts2', '2Q2I', blob,
                                   at + 352 + j * 24) for j in range(8)]
        r['doneOpts1'] = list(struct.unpack_from('<8I', blob, at + 544))
        rows.append(r)
    return h, rows


class Tables:
    """Walk the exported arena, substituting the generation's own map PTEs.

    The final table cannot prove an earlier translation, so the leaf page is
    read from the record's captured mapPte (the actual bytes hardware used at
    that time) while every parent entry comes from the exported arena.
    """

    def __init__(self, blob, header, leaves):
        self.blob, self.h, self.leaves = blob, header, leaves
        need(header['ptBase'] > 0 and header['ptBase'] % PAGE == 0 and
             len(blob) == header['ptBytes'] and len(blob) % PAGE == 0,
             'PT: invalid exported arena geometry')
        need(header['rootLevel'] in (3, 4), 'PT: expected mode3/4')
        need(header['leafPA'] % PAGE == 0, 'PT: this fixed IOVA starts at leaf index 0')

    def entry(self, table, index):
        need(table % PAGE == 0 and
             self.h['ptBase'] <= table <= self.h['ptBase'] + len(self.blob) - PAGE,
             'PT: path outside owned exported arena')
        if table == self.h['leafPA'] and index < 16:
            return self.leaves[index]
        return struct.unpack_from('<Q', self.blob, table - self.h['ptBase'] + index * 8)[0]

    def walk(self, addr, size):
        need(addr > 0 and 0 < size <= 65536 and addr + size < 1 << 64, 'PT: invalid range')
        cur, out = addr, []
        while cur < addr + size:
            table, level, path = self.h['rootPA'], self.h['rootLevel'], []
            while True:
                index = cur >> (9 * level + 3) & 511
                raw = self.entry(table, index)
                need(raw & IR, 'PT: TX read absent')
                kind, pa, value = R.Tables.decode(raw, level)
                path.append({'table': table, 'level': level, 'index': index, 'raw': raw})
                if kind == 'table':
                    table, level = pa, value
                    continue
                need(level == 1 and table == self.h['leafPA'] and value == PAGE,
                     'PT: TX did not reach the declared 4KiB leaf page')
                step = min(addr + size - cur, value - (cur & (value - 1)))
                out.append({'iova': cur, 'pa': pa + (cur & (value - 1)), 'bytes': step,
                            'path': path})
                cur += step
                break
        return out


def bytes_logs(token, logs):
    """All four byte-identical observations of all 32 requests, plus chronology."""
    proof = {}
    bound = re.findall(r'^client_bound (\S+)\s*$', logs.get('client.log', ''), re.M)
    starts = R.log_rows(logs.get('peer.log', ''), 'peer_start')
    need(len(bound) == len(starts) == 1 and starts[0]['_valid'], 'logs: ambiguous endpoints')
    endpoint, peer = bound[0], starts[0].get('bind')
    need(peer and R.log_number(starts[0], 'token') == token, 'logs: peer token missing/wrong')
    for file, tag, endpoint_field, expected_endpoint in (
            ('client.log', 'client_sent', None, None),
            ('peer.log', 'peer_recv', 'from', endpoint),
            ('peer.log', 'peer_sent', 'to', endpoint),
            ('client.log', 'client_recv', 'from', peer)):
        rows = R.log_rows(logs.get(file, ''), tag)
        need(len(rows) == len(REQUESTS), 'logs: %s must have exactly %d %s rows'
             % (file, len(REQUESTS), tag))
        need([R.log_number(r, 'req') for r in rows] == list(REQUESTS),
             'logs: duplicate/out-of-order request in %s' % tag)
        for row, req in zip(rows, REQUESTS):
            expected = payload(token, req)
            need(row['_valid'] and R.log_number(row, 'token') == token and
                 R.log_number(row, 'len') == length_of(req) and
                 row.get('payload') == expected.hex() and
                 row.get('sha256') == hashlib.sha256(expected).hexdigest(),
                 'logs: full raw application bytes/hash of req %d do not match' % req)
            if endpoint_field:
                need(row.get(endpoint_field) == expected_endpoint, 'logs: wrong endpoint')
            if tag in ('peer_recv', 'client_recv'):
                need(R.log_number(row, 'payload_ok') == 1,
                     'logs: receiver did not validate every byte of req %d' % req)
            proof.setdefault(req, {})[tag] = {'file': file, 'line': row['_line'],
                                              'payload': expected.hex()}
    sent = R.log_rows(logs['client.log'], 'client_sent')
    received = R.log_rows(logs['client.log'], 'client_recv')
    need(all(0 < R.log_number(s, 't_ns') < R.log_number(r, 't_ns')
             for s, r in zip(sent, received)), 'logs: send/echo chronology is not serial')
    need(all(R.log_number(sent[i + 1], 't_ns') - R.log_number(received[i], 't_ns') >= 150000000
             for i in range(len(sent) - 1)),
         'logs: next request must wait at least 150 ms after the previous echo')
    seed = R.log_rows(logs.get('peer.log', ''), 'peer_seed_recv')
    stop = R.log_rows(logs.get('peer.log', ''), 'peer_stop')
    need(len(seed) == 1 and R.log_number(seed[0], 'nonmagic') == 1 and
         R.log_number(seed[0], 'len') == 1024, 'logs: r15 nonmagic seed missing')
    need(len(stop) == 1 and all(R.log_number(stop[0], k) == v for k, v in
         (('received', len(REQUESTS)), ('bad', 0), ('seed', 1))),
         'logs: peer incomplete/rejected traffic')
    return proof


def analyze_payloads(p, domain_blob, pt_blob, driver_blob, obs_blob, logs, metadata=None):
    checks, details = [], {}
    metadata = metadata or {}

    def check(cid, operation):
        try:
            result = operation()
            need(result is not False, 'condition false')
            checks.append({'id': cid, 'state': 'ok'})
            return result
        except (Refused, KeyError, TypeError, ValueError, struct.error) as e:
            checks.append({'id': cid, 'state': 'fail', 'detail': str(e)})
            return None

    h, domain = decode_domain(domain_blob)
    dh, driver = decode_driver(driver_blob)
    details['capture_identity'] = metadata
    details['tx_ring_accounting'] = {
        k: dh[k] for k in ('txNext', 'txDirty', 'txClose', 'txFree', 'txDescDone',
                           'completeCalls', 'completeHits', 'lastSeenSlot')}
    details['cleanup_state'] = metadata.get('cleanup')
    mode = metadata.get('driverMode')
    check('native-mbuf-mode-and-binary-binding', lambda:
          mode == 'native-mbuf-explicit-iova-v1' and
          metadata.get('cleanup') == 'detached-before-DTE-restore' and
          metadata.get('installedDriverVersion') == metadata.get('loadedDriverVersion') == '1.1.202' and
          bool(metadata.get('installedDriverUUID')) and
          metadata.get('installedDriverUUID') == metadata.get('loadedDriverUUID') and
          metadata.get('installedProbeVersion') == metadata.get('loadedProbeVersion') == '0.27.0' and
          bool(metadata.get('installedProbeUUID')) and
          metadata.get('installedProbeUUID') == metadata.get('loadedProbeUUID'))
    details['dma_buffer_scope'] = ('original mbuf physical segments; the driver '
                                   'declares native-mbuf-explicit-iova-v1 and none '
                                   'of the round-16 staging properties')

    token = p.get('m2-b2-obs-declared-token')
    ws, we = p.get('m2-b2-dma-t-win-start'), p.get('m2-b2-dma-t-win-end')
    need(isinstance(ws, int) and isinstance(we, int) and 0 < ws < we, 'window: bounds missing')
    need(p.get('m2-b2-r15-timebase-numer') == p.get('m2-b2-r15-timebase-denom') == 1,
         'timebase: current fixed tick/ns ABI requires unit scale')

    check('domain-clean-at-export', lambda: h['count'] == DOMAIN_RECORDS and
          h['flags'] == h['active'] == 0 and h['iovaBase'] == BASE and
          h['iovaBytes'] == 16 * PAGE and
          [r['handle'] for r in domain] == list(range(1, DOMAIN_RECORDS + 1)) and
          [r['req'] for r in domain] == list(REQUESTS))
    check('domain-driver-binding', lambda: h['devid'] == dh['bdf'] == 0x2500 and
          dh['count'] == DOMAIN_RECORDS and dh['retired'] == DOMAIN_RECORDS and
          dh['token'] == token and dh['dropped'] == dh['state'] == 0 and
          dh['rejected'] == 0 and dh['maxHeld'] == 1 and
          p.get('m2-b2-pt-root-pa') == h['rootPA'] and
          p.get('m2-b2-page-mode') == h['rootLevel'])
    dte = p.get('m2-b2-rxset-dte-raw', 0)
    check('actual-dte-root-binding', lambda: dte & 3 == 3 and bool(dte & IR) and bool(dte & IW) and
          dte & MASK == h['rootPA'] and (dte >> 9) & 7 == h['rootLevel'] and
          p.get('m2-b2-rxset-dte-root-pa') == h['rootPA'] and
          p.get('m2-b2-rxset-root-level') == h['rootLevel'])
    details['payloads'] = check('full-application-bytes-32', lambda: bytes_logs(token, logs))

    Tables(pt_blob, h, [0] * 16)  # Validate the fixed final arena geometry first.
    leaf_offset = h['leafPA'] - h['ptBase']
    need(0 <= leaf_offset <= len(pt_blob) - PAGE, 'PT: leaf not in arena')
    check('final-retired-leaves-absent', lambda: not any(pt_blob[leaf_offset:leaf_offset + 16 * 8]))

    need(len(obs_blob) >= A.HDR_BYTES and (len(obs_blob) - A.HDR_BYTES) % A.REC_BYTES == 0,
         'OBS: ragged publication')
    oh = A.decode_header(obs_blob)
    need((oh['magic'], oh['version'], oh['recSize']) == (A.OBS_MAGIC, 2, 72) and
         0 < oh['recordCount'] <= 512, 'OBS: bad fixed ABI/count')
    obs = [A.valid_record(obs_blob, oh, i) for i in range(oh['recordCount'])]
    need(all(r is not None for r in obs), 'OBS: torn records')
    check('obs-window-covers-run', lambda: oh['dropped'] == oh['lostCount'] == 0 and
          oh['flags'] & ~4 == 0 and oh['busDevFn'] == h['devid'] and
          oh['vendorId'] == 0x10EC and oh['epoch'] > 0 and
          min(r['t'] for r in obs) <= ws < we <= oh['tPublished'])

    sequences, walked, reuse, pages_forms = [], [], [], []
    for index, req in enumerate(REQUESTS):
        r, d = domain[index], driver[index]

        def prove(r=r, d=d, req=req):
            n = r['count']
            need(1 <= n <= 8 and 1 <= r['pages'] <= 16, 'invalid segment/page bound')
            need(r['status'] == 3 and r['reserved'] == 0 and r['token'] == token and
                 r['req'] == req and d['version'] == 2 and d['bytes'] == 312 and
                 d['req'] == req and d['token'] == token and d['bdf'] == h['devid'] and
                 d['count'] == n and d['handle'] == r['handle'] and d['retired'] == 1,
                 'raw handles/requests disagree')
            need(d['tMap'] == r['tMapInv'] and d['tRetire'] == r['tRetireInv'],
                 'backend times disagree')
            need(ws <= r['tMapPublish'] <= r['tMapInv'] < d['tOwn'] < d['tDone'] <=
                 r['tClearPublish'] <= r['tRetireInv'] <= d['tFree'] <= dh['tPublished'] and
                 r['tRetireInv'] <= we,
                 'map/invalidate/OWN/done/clear/invalidate/free ordering')
            sends = [x for x in R.log_rows(logs['client.log'], 'client_sent')
                     if R.log_number(x, 'req') == req]
            receives = [x for x in R.log_rows(logs['client.log'], 'client_recv')
                        if R.log_number(x, 'req') == req]
            need(len(sends) == len(receives) == 1 and
                 R.log_number(sends[0], 't_ns') <= r['tMapPublish'] and
                 d['tOwn'] <= R.log_number(receives[0], 't_ns'),
                 'actual client send/echo chronology mismatch')
            at, paths, frame_bytes = 0, [], 0
            tables = Tables(pt_blob, h, r['mapPte'])
            for j, s in enumerate(r['segments'][:n]):
                off = s['pa'] & 4095
                pages = (off + s['bytes'] + 4095) // PAGE
                need(s['pa'] > 0 and s['pa'] + s['bytes'] < 1 << 52 and
                     0 < s['bytes'] <= 65536 and at + pages <= 16 and
                     s['iova'] == BASE + at * PAGE + off and s['iova'] != s['pa'],
                     'plan geometry/identity fallback')
                need(d['physical'][j] == {'address': s['pa'], 'length': s['bytes']} and
                     d['iova'][j] == {'address': s['iova'], 'length': s['bytes']},
                     'driver/backend segment mismatch')
                desc = d['descriptors'][j]
                need(desc['address'] == s['iova'] and desc['length'] == s['bytes'] and
                     desc['opts1'] & (1 << 31) and desc['opts1'] & 0xFFFF == s['bytes'],
                     'actual descriptor addr/length/OWN')
                for k in range(pages):
                    physical = (s['pa'] & -PAGE) + k * PAGE
                    need(r['physical'][at + k] == physical and
                         r['mapPte'][at + k] == physical | FC | IR | 1,
                         'actual map PTE/physical page mismatch or unexpected permissions')
                path = tables.walk(s['iova'], s['bytes'])
                need(all(x['pa'] == s['pa'] + x['iova'] - s['iova'] for x in path),
                     'IOVA walk does not resolve the actual PA')
                paths.extend(path)
                frame_bytes += s['bytes']
                submits = [x for x in obs if x['kind'] == 1 and x['token'] == token and
                           x['reqId'] == req and x['cum'] == d['cumulative'] + j]
                need(len(submits) == 1, 'missing/duplicate actual OBS submit')
                sub = submits[0]
                need(sub['addr'] == desc['address'] and sub['len'] == desc['length'] and
                     sub['opts1'] == (desc['opts1'] & ~(1 << 31) if j == 0 else desc['opts1']) and
                     sub['opts2'] == desc['opts2'] and
                     r['tMapInv'] <= sub['t'] <= d['tOwn'] < d['tDone'] and
                     not sub['flags'] & 3 and sub['slot'] == (d['firstSlot'] + j) % 1024,
                     'OBS actual descriptor disagrees with driver raw')
                dones = [x for x in obs if x['kind'] == 2 and x['cum'] == sub['cum']]
                need(len(dones) == 1 and sub['t'] < dones[0]['t'] <= d['tDone'] and
                     dones[0]['slot'] == sub['slot'] and dones[0]['gen'] == sub['gen'],
                     'real close-pointer completion missing/ambiguous')
                at += pages
            need(at == r['pages'] and all(v == 0 for v in
                 r['physical'][at:] + r['mapPte'][at:] + r['clearPte']),
                 'page count, trailing map pages or actual retire PTE clears disagree')
            need(all(not any(s.values()) for s in r['segments'][n:]) and
                 all(not any(s.values()) for key in ('physical', 'iova', 'descriptors')
                     for s in d[key][n:]), 'undeclared segment body')
            mask = d['closeMask']
            need(1023 <= mask <= 0xFFFFFFFF and mask & (mask + 1) == 0 and
                 n <= ((d['doneClose'] - d['cumulative']) & mask) <= (mask + 1) // 2 and
                 d['doneClose'] <= mask,
                 'hardware close pointer did not retire every packet descriptor')
            need(frame_bytes == length_of(req) + FRAME_OVERHEAD,
                 'expected non-VLAN frame length / mapped bytes mismatch')
            need(d['lastSlot'] == (d['firstSlot'] + n - 1) % 1024,
                 'last descriptor slot disagrees with segment count')
            # The words the device left in the ring are RECORDED here, not
            # asserted on: this chip/driver combination runs with TX_NO_CLOSE,
            # and the driver's own reap loop walks the close pointer instead of
            # testing the OWN bit. Round 17 measured that the OWN bit is NOT
            # cleared on completion (posted == final in every generation), so
            # using it as a completion signal would be a fabricated criterion.
            # Real completion is proven by the close pointer above and by the
            # peer's received bytes.
            for key, stamp in (('mapCommand', 'tMapInv'), ('retireCommand', 'tRetireInv')):
                c = r[key]
                need(c['words'] == [0, h['domid'] | (3 << 28), 0xFFFFF003, 0x7FFFFFFF] and
                     0 < c['expected'] == c['observed'] and c['tComplete'] == r[stamp],
                     'real full-domain PDE invalidation/CompletionWait mismatch')
                sequences.append(c['expected'])
            pages_forms.append({'req': req, 'segments': n, 'pages': r['pages'],
                                'bytes': frame_bytes})
            return {'handle': r['handle'], 'req': req, 'walk': paths,
                    'driver': d, 'domain': r,
                    'hardware_final_opts1': [hex(v) for v in d['doneOpts1'][:n]]}
        proof = check('request%02d-native-map-to-retire-free' % req, prove)
        if proof:
            walked.append(proof)

    # The command budget: exactly two submissions per generation, consecutive.
    check('command-budget-and-completions', lambda: len(sequences) == EXPECTED_SUBMITS and
          sequences == list(range(sequences[0], sequences[0] + EXPECTED_SUBMITS)) and
          p.get('m2-3b-submits') == sequences[-1] and
          p.get('m2-3b-submit-budget', 0) >= BUDGET_FLOOR and
          p.get('m2-3b-map-accepted') == len(REQUESTS) and
          p.get('m2-3b-map-rejected') == 0 and
          p.get('m2-3b-retires') == len(REQUESTS))

    # Per-packet recycling: each generation's mbuf is freed in its own window,
    # never accumulating until Detach and never overlapping the next request.
    def per_packet():
        rows = []
        for i in range(len(REQUESTS) - 1):
            a, b = driver[i], driver[i + 1]
            need(a['tFree'] and b['tMap'] and a['tFree'] < b['tMap'],
                 'req %d mbuf survived into the next request' % REQUESTS[i])
            rows.append({'req': REQUESTS[i], 'tFree': a['tFree'],
                         'nextMapPublish': b['tMap'],
                         'gap_ns': b['tMap'] - a['tFree']})
        # Bounded ownership derived from the record timeline, not from a count.
        live, high = 0, 0
        events = []
        for d in driver:
            events.append((d['tMap'] if d['tMap'] else 0, 1))
            events.append((d['tFree'], -1))
        for _, delta in sorted(events):
            live += delta
            high = max(high, live)
        need(high == 1, 'more than one DMA owner was live at once (max %d)' % high)
        need(dh['maxHeld'] == 1 and p.get('m2-3b-live-owner-max') == 1 and
             p.get('m2-3b-owners-held') == 0, 'published owner counters disagree')
        return {'pairs': rows, 'max_live_owners': high,
                'owner_scope': 'one live mbuf at a time; count does not grow with '
                               'cumulative successful requests'}
    details['per_packet_recycling'] = check('per-packet-free-and-bounded-owners', per_packet)

    # Resource reuse. Round17 maps native segments, whose in-page offset is not
    # controllable, so the reusable unit is the IOVA PAGE SLOT, not an exact
    # byte range: a later generation must land on a page a retired generation
    # used, and the earlier retire invalidation must be strictly before it.
    for i in range(len(domain) - 1):
        old, new = domain[i], domain[i + 1]
        old_pages = {s['iova'] & -PAGE for s in old['segments'][:old['count']]}
        new_pages = {s['iova'] & -PAGE for s in new['segments'][:new['count']]}
        common = old_pages & new_pages
        if old['tRetireInv'] < new['tMapPublish'] and common:
            exact = [{'old': a, 'new': b} for a in old['segments'][:old['count']]
                     for b in new['segments'][:new['count']] if a['iova'] == b['iova']]
            reuse.append({'oldHandle': old['handle'], 'newHandle': new['handle'],
                          'reusedPageSlots': sorted(common),
                          'oldPAs': [s['pa'] for s in old['segments'][:old['count']]],
                          'newPAs': [s['pa'] for s in new['segments'][:new['count']]],
                          'oldRetireInv': old['tRetireInv'],
                          'newMapPublish': new['tMapPublish'],
                          'exactByteRangeReuse': exact})
    check('iova-page-slot-reuse-after-retire', lambda:
          len(reuse) == len(REQUESTS) - 1 and len(walked) == len(REQUESTS))
    details['reuse_scope'] = ('IOVA page slots are handed out again only after the '
                              'previous generation retire invalidation; the start '
                              'byte offset may differ between generations because the '
                              'native segment offsets differ')

    # The evidence shape asked for explicitly: at least one real multi-segment
    # or cross-page transmit (a software-only test does not count).
    def forms():
        multi = [x for x in pages_forms if x['segments'] > 1]
        cross = [x for x in pages_forms if x['pages'] > x['segments']]
        need(multi or cross, 'no multi-segment and no cross-page TX sample in this run')
        return {'multi_segment': multi, 'cross_page': cross,
                'note': 'distinguishes a real hardware mapping from the host test'}
    details['segment_forms'] = check('real-multi-segment-or-cross-page-sample', forms)

    check('fault-window-empty', lambda: all(p.get(k) == 0 for k in
          ('m2-b2-win-new-entries', 'm2-b2-win-entries', 'm2-b2-win-raw-count')))

    details.update({
        'domain_header': h, 'driver_header': dh,
        'requests': walked, 'reuse': reuse,
        'segment_forms': pages_forms,
        'completion_evidence': 'hardware TX close-pointer cumulative, not descriptor '
                              'OWN readback',
        'free_scope': 'each mbuf is released by its own successful retire, before the '
                      'next request maps; no quarantine to Detach'})
    return {'scope': 'round17-native-tx-per-packet-recycle',
            'ok': all(c['state'] == 'ok' for c in checks),
            'checks': checks, 'details': details}


def raw_export(cap, raw, key, filename):
    matches = {bytes.fromhex(x) for x in
               re.findall(r'"' + re.escape(key) + r'"\s*=\s*<([0-9a-fA-F]+)>', raw)}
    need(len(matches) == 1, key + ': missing/conflicting raw OSData')
    blob = matches.pop()
    if (cap / filename).exists():
        need((cap / filename).read_bytes() == blob, filename + ': archived bytes differ')
    return blob


def capture_metadata(cap):
    def text(name):
        path = cap / name
        return path.read_text(encoding='utf-8', errors='replace') if path.exists() else ''
    modes = set(re.findall(r'"rtl812x-txmap-mode"\s*=\s*"([^"]+)"', text('driver-obs.txt')))
    need(len(modes) <= 1, 'conflicting driver TX mapping modes')
    cleanup = set(re.findall(r'"m2-3b-cleanup"\s*=\s*"([^"]+)"', text('props.txt')))
    need(len(cleanup) <= 1, 'conflicting TX cleanup tokens')
    system, loaded = text('system.txt'), text('r17-version-confirmation.txt')
    result = {'driverMode': next(iter(modes)) if modes else None,
              'cleanup': next(iter(cleanup)) if cleanup else None}
    for label, bundle in (('Driver', 'RTL812xLucy'), ('Probe', 'AMDMapperProbe')):
        versions = re.findall(r'^' + bundle + r'_version\s*:\s*(\S+)', system, re.M)
        uuids = re.findall(r'^' + bundle + r'_uuid\s*:\s*(\S+)', system, re.M)
        live = re.findall(r'\b' + bundle + r'\s+\(([^)]+)\)\s+([A-Fa-f0-9-]+)', loaded)
        need(len(versions) <= 1 and len(uuids) <= 1 and len(live) <= 1,
             'ambiguous ' + label + ' identity')
        result['installed' + label + 'Version'] = versions[0] if versions else None
        result['installed' + label + 'UUID'] = uuids[0].upper() if uuids else None
        result['loaded' + label + 'Version'] = live[0][0] if live else None
        result['loaded' + label + 'UUID'] = live[0][1].upper() if live else None
    return result


def main():
    if len(sys.argv) not in (2, 3):
        print(__doc__)
        return 2
    cap = Path(sys.argv[1])
    try:
        p = A.hexprops((cap / 'props.txt').read_text(encoding='utf-8', errors='replace'))
        raw = (cap / 'props.raw.txt').read_text(encoding='utf-8', errors='replace')
        blobs = [raw_export(cap, raw, key, name) for key, name in (
            ('m2-3b-domain-raw', 'r17-domain-raw.bin'),
            ('m2-3b-pt-raw', 'r17-pt-raw.bin'),
            ('m2-3b-driver-raw', 'r17-driver-raw.bin'),
            ('m2-b2-obs-snapshot-used', 'obs-snapshot-used.bin'))]
        logs = {name: (cap / name).read_text(encoding='utf-8', errors='replace')
                for name in ('client.log', 'peer.log')}
        result = analyze_payloads(p, *blobs, logs, metadata=capture_metadata(cap))
        result['exports_sha256'] = [hashlib.sha256(x).hexdigest() for x in blobs]
    except (OSError, Refused, KeyError, TypeError, ValueError, struct.error) as e:
        result = {'scope': 'round17-native-tx-per-packet-recycle', 'ok': False,
                  'refused': str(e)}
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if len(sys.argv) == 3:
        Path(sys.argv[2]).write_text(text + '\n', encoding='utf-8')
    print(text)
    return 2 if 'refused' in result else (0 if result['ok'] else 1)


if __name__ == '__main__':
    raise SystemExit(main())
