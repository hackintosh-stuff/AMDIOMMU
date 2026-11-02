#!/usr/bin/env python3
"""Independent Round16 finite TX proof. No producer success strings are verdicts.

Decode both raw ABIs, reconstruct each live PTE generation from its actual leaf
reads + stable final parent tables, walk descriptor IOVAs to physical bytes,
and join hardware-close done, invalidation, quarantine/free and full peer bytes.
The final table alone cannot prove earlier translations. CPU reads are limited
to exported OSData. Usage: analyze.py CAPTURE [OUTPUT_JSON]
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
from protocol import REQUESTS, payload
ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('r15decode', ROOT / 'tools/r15/analyze.py')
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)
need, Refused, A = R.need, R.Refused, R.A
PAGE, BASE, MASK, FC, IR, IW = 4096, 0x1000000000, 0x000FFFFFFFFFF000, 1 << 60, 1 << 61, 1 << 62
DOMAIN_BYTES, DOMAIN_RECORD_BYTES = 5840, 720
DRIVER_BYTES, DRIVER_RECORD_BYTES = 2216, 544


def unpack(names, fmt, blob, off=0):
    return dict(zip(names.split(), struct.unpack_from('<' + fmt, blob, off)))


def command(blob, off):
    r = unpack('d0 d1 d2 d3 expected observed tComplete', '4I3Q', blob, off)
    r['words'] = [r.pop('d%d' % i) for i in range(4)]
    return r


def decode_domain(blob):
    need(len(blob) == DOMAIN_BYTES, 'domain: fixed ABI size 5840 required')
    h = unpack('version bytes count flags iovaBase iovaBytes rootPA leafPA ptBase ptBytes rootLevel devid domid active', '4I6Q4I', blob)
    need(h['version'] == 1 and h['bytes'] == DOMAIN_BYTES and 0 < h['count'] <= 8,
         'domain: unknown ABI or count')
    need(not any(blob[80 + h['count'] * DOMAIN_RECORD_BYTES:]), 'domain: undeclared trailing records')
    records = []
    for i in range(h['count']):
        at = 80 + i * DOMAIN_RECORD_BYTES
        r = unpack('handle tMapPublish tMapInv tClearPublish tRetireInv count pages token req status reserved', '5Q6I', blob, at)
        r['segments'] = [unpack('pa bytes iova', '3Q', blob, at + 64 + j * 24) for j in range(8)]
        for j, key in enumerate(('physical', 'mapPte', 'clearPte')):
            r[key] = list(struct.unpack_from('<16Q', blob, at + 256 + j * 128))
        r['mapCommand'] = command(blob, at + 640)
        r['retireCommand'] = command(blob, at + 680)
        records.append(r)
    return h, records


def decode_driver(blob):
    need(len(blob) == DRIVER_BYTES, 'driver: fixed ABI size 2216 required')
    h = unpack('magic version bytes count bdf token dropped state tPublished', '8IQ', blob)
    need((h['magic'], h['version'], h['bytes'], h['count']) == (0x36315854, 1, DRIVER_BYTES, 4),
         'driver: unknown ABI or not exactly four retired witnesses')
    rows = []
    for i in range(4):
        at = 40 + i * DRIVER_RECORD_BYTES
        r = unpack('version bytes bdf token req count handle tMap tDone tRetire', '6I4Q', blob, at)
        r['physical'] = [unpack('address length', '2Q', blob, at + 56 + j * 16) for j in range(8)]
        r['iova'] = [unpack('address length', '2Q', blob, at + 184 + j * 16) for j in range(8)]
        r.update(unpack('tOwn tFree cumulative firstSlot lastSlot retired doneClose closeMask', '2Q6I', blob, at + 312))
        r['descriptors'] = [unpack('address length opts1 opts2', '2Q2I', blob, at + 352 + j * 24) for j in range(8)]
        rows.append(r)
    return h, rows


class Tables:
    def __init__(self, blob, header, leaves):
        self.blob, self.h, self.leaves = blob, header, leaves
        need(header['ptBase'] > 0 and header['ptBase'] % PAGE == 0 and
             len(blob) == header['ptBytes'] and len(blob) % PAGE == 0,
             'PT: invalid exported arena geometry')
        need(header['rootLevel'] in (3, 4), 'PT: expected mode3/4')
        need(header['leafPA'] % PAGE == 0, 'PT: this fixed IOVA starts at leaf index0')

    def entry(self, table, index):
        need(table % PAGE == 0 and self.h['ptBase'] <= table <= self.h['ptBase'] + len(self.blob) - PAGE,
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
                out.append({'iova': cur, 'pa': pa + (cur & (value - 1)), 'bytes': step, 'path': path})
                cur += step
                break
        return out


def bytes_logs(token, logs):
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
        need(len(rows) == 4, 'logs: %s must have exactly four %s rows' % (file, tag))
        need([R.log_number(r, 'req') for r in rows] == list(REQUESTS), 'logs: duplicate/out-of-order request')
        for row, req in zip(rows, REQUESTS):
            expected = payload(token, req)
            need(row['_valid'] and R.log_number(row, 'token') == token and
                 R.log_number(row, 'len') == 32 and row.get('payload') == expected.hex() and
                 row.get('sha256') == hashlib.sha256(expected).hexdigest(),
                 'logs: full raw application bytes/hash do not match clean4')
            if endpoint_field:
                need(row.get(endpoint_field) == expected_endpoint, 'logs: wrong endpoint')
            if tag in ('peer_recv', 'client_recv'):
                need(R.log_number(row, 'payload_ok') == 1, 'logs: receiver did not validate every byte')
            proof.setdefault(req, {})[tag] = {'file': file, 'line': row['_line'], 'payload': expected.hex()}
    sent = R.log_rows(logs['client.log'], 'client_sent')
    received = R.log_rows(logs['client.log'], 'client_recv')
    need(all(0 < R.log_number(s, 't_ns') < R.log_number(r, 't_ns')
             for s, r in zip(sent, received)), 'logs: send/echo chronology is not serial')
    need(all(R.log_number(sent[i + 1], 't_ns') - R.log_number(received[i], 't_ns') >= 150000000
             for i in range(3)), 'logs: next request must wait at least 150 ms after previous echo')
    seed = R.log_rows(logs.get('peer.log', ''), 'peer_seed_recv')
    stop = R.log_rows(logs.get('peer.log', ''), 'peer_stop')
    need(len(seed) == 1 and R.log_number(seed[0], 'nonmagic') == 1 and
         R.log_number(seed[0], 'len') == 1024, 'logs: r15 nonmagic seed missing')
    need(len(stop) == 1 and all(R.log_number(stop[0], k) == v for k, v in
         (('received', 4), ('bad', 0), ('seed', 1))), 'logs: peer incomplete/rejected traffic')
    return proof


def analyze_payloads(p, domain_blob, pt_blob, driver_blob, obs_blob, logs, metadata=None):
    checks, details = [], {}
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
    metadata = metadata or {}
    mode = metadata.get('driverMode')
    if mode is not None or '1.1.201' in (metadata.get('installedDriverVersion'), metadata.get('loadedDriverVersion')):
        check('real-tx-staging-mode-and-binary-binding', lambda:
              mode == 'page-aligned-real-tx-staging-v1' and
              metadata.get('installedDriverVersion') == metadata.get('loadedDriverVersion') == '1.1.201' and
              bool(metadata.get('installedDriverUUID')) and
              metadata.get('installedDriverUUID') == metadata.get('loadedDriverUUID') and
              metadata.get('installedProbeVersion') == metadata.get('loadedProbeVersion') == '0.26.0' and
              bool(metadata.get('installedProbeUUID')) and
              metadata.get('installedProbeUUID') == metadata.get('loadedProbeUUID'))
        check('real-tx-staging-aligned-distinct-backing', lambda:
              all(r['count'] == r['pages'] == 1 and r['segments'][0]['bytes'] == 74 and
                  r['segments'][0]['iova'] == BASE and r['segments'][0]['pa'] % PAGE == 0 for r in domain) and
              len({r['segments'][0]['pa'] for r in domain}) == 4)
        details['dma_buffer_scope'] = 'controlled page-aligned real TX staging copy; not direct original-mbuf zero-copy'
    else:
        details['dma_buffer_scope'] = 'original physical TX segments; no staging mode declared'
    details['capture_identity'] = metadata
    token = p.get('m2-b2-obs-declared-token')
    ws, we = p.get('m2-b2-dma-t-win-start'), p.get('m2-b2-dma-t-win-end')
    need(isinstance(ws, int) and isinstance(we, int) and 0 < ws < we, 'window: bounds missing')
    need(p.get('m2-b2-r15-timebase-numer') == p.get('m2-b2-r15-timebase-denom') == 1,
         'timebase: current fixed tick/ns ABI requires unit scale')
    check('domain-finite-clean', lambda: h['count'] == 4 and h['flags'] == h['active'] == 0 and
          h['iovaBase'] == BASE and h['iovaBytes'] == 16 * PAGE and
          [r['handle'] for r in domain] == [1, 2, 3, 4] and
          [r['req'] for r in domain] == list(REQUESTS))
    check('domain-driver-binding', lambda: h['devid'] == dh['bdf'] == 0x2500 and
          dh['token'] == token and dh['dropped'] == dh['state'] == 0 and
          p.get('m2-b2-pt-root-pa') == h['rootPA'] and p.get('m2-b2-page-mode') == h['rootLevel'])
    dte = p.get('m2-b2-rxset-dte-raw', 0)
    check('actual-dte-root-binding', lambda: dte & 3 == 3 and dte & IR and dte & IW and
          dte & MASK == h['rootPA'] and (dte >> 9) & 7 == h['rootLevel'] and
          p.get('m2-b2-rxset-dte-root-pa') == h['rootPA'] and
          p.get('m2-b2-rxset-root-level') == h['rootLevel'])
    details['payloads'] = check('clean4-full-application-bytes', lambda: bytes_logs(token, logs))
    Tables(pt_blob, h, [0] * 16)  # Validate fixed final arena geometry before indexing.
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
    check('obs-clean-current-window', lambda: oh['dropped'] == oh['wrapped'] == oh['lostCount'] == 0 and
          oh['flags'] & ~4 == 0 and oh['firstTicket'] == oh['head'] - oh['recordCount'] + 1 > 0 and
          oh['lastTicket'] == oh['head'] and oh['validCount'] == oh['recordCount'] and
          oh['recordCount'] == min(oh['head'], 512) <= oh['capacity'] and
          bool(oh['flags'] & 4) == (oh['head'] > oh['recordCount']) and
          oh['busDevFn'] == h['devid'] and oh['vendorId'] == 0x10EC and oh['epoch'] > 0 and
          min(r['t'] for r in obs) > 0 and min(r['t'] for r in obs) <= ws < we <= oh['tPublished'])
    business = [r for r in obs if r['pkt'] & 1 and r['kind'] in (1, 3, 4)]
    check('obs-exact-four-business', lambda: all(r['token'] == token and r['reqId'] in REQUESTS and
          ws <= r['t'] <= we for r in business) and
          all(sum(r['kind'] == k and r['reqId'] == req for r in business) ==
              (next((d['count'] for d in driver if d['req'] == req), -1) if k == 1 else 1)
              for req in REQUESTS for k in (1, 3, 4)))
    sequences, walked, reuse = [], [], []
    for r, d in zip(domain, driver):
        req = r['req']
        def prove(r=r, d=d):
            n = r['count']
            need(1 <= n <= 8 and 1 <= r['pages'] <= 16, 'invalid segment/page bound')
            need(r['status'] == 3 and r['reserved'] == 0 and r['token'] == token and
                 d['version'] == 1 and d['bytes'] == 312 and d['req'] == req and
                 d['token'] == token and d['bdf'] == h['devid'] and d['count'] == n and
                 d['handle'] == r['handle'] and d['retired'] == 1, 'raw handles/requests disagree')
            need(d['tMap'] == r['tMapInv'] and d['tRetire'] == r['tRetireInv'], 'backend times disagree')
            need(ws <= r['tMapPublish'] <= r['tMapInv'] < d['tOwn'] < d['tDone'] <=
                 r['tClearPublish'] <= r['tRetireInv'] <= d['tFree'] <= dh['tPublished'] and
                 r['tRetireInv'] <= we, 'map/invalidate/OWN/done/clear/invalidate/free ordering')
            sends = [x for x in R.log_rows(logs['client.log'], 'client_sent') if R.log_number(x, 'req') == req]
            receives = [x for x in R.log_rows(logs['client.log'], 'client_recv') if R.log_number(x, 'req') == req]
            rx = [x for x in business if x['kind'] == 3 and x['reqId'] == req]
            bell = [x for x in business if x['kind'] == 4 and x['reqId'] == req]
            need(len(sends) == len(receives) == len(rx) == len(bell) == 1 and
                 R.log_number(sends[0], 't_ns') <= r['tMapPublish'] and
                 d['tOwn'] <= bell[0]['t'] <= rx[0]['t'] <= R.log_number(receives[0], 't_ns') and
                 rx[0]['len'] == 74 and not rx[0]['flags'] & 64,
                 'actual client/doorbell/RX chronology or raw RX length/error mismatch')
            at, paths = 0, []
            tables = Tables(pt_blob, h, r['mapPte'])
            for j, s in enumerate(r['segments'][:n]):
                off = s['pa'] & 4095
                pages = (off + s['bytes'] + 4095) // PAGE
                need(s['pa'] > 0 and s['pa'] + s['bytes'] < 1 << 52 and
                     0 < s['bytes'] <= 65536 and at + pages <= 16 and
                     s['iova'] == BASE + at * PAGE + off and s['iova'] != s['pa'], 'plan geometry/identity fallback')
                need(d['physical'][j] == {'address': s['pa'], 'length': s['bytes']} and
                     d['iova'][j] == {'address': s['iova'], 'length': s['bytes']}, 'driver/backend segment mismatch')
                desc = d['descriptors'][j]
                need(desc['address'] == s['iova'] and desc['length'] == s['bytes'] and
                     desc['opts1'] & (1 << 31) and desc['opts1'] & 0xFFFF == s['bytes'], 'actual descriptor addr/length/OWN')
                for k in range(pages):
                    physical = (s['pa'] & -PAGE) + k * PAGE
                    need(r['physical'][at + k] == physical and r['mapPte'][at + k] == physical | FC | IR | 1,
                         'actual map PTE/physical page mismatch or unexpected permissions')
                path = tables.walk(s['iova'], s['bytes'])
                need(all(x['pa'] == s['pa'] + x['iova'] - s['iova'] for x in path), 'IOVA walk does not resolve actual PA')
                paths.extend(path)
                submits = [x for x in obs if x['kind'] == 1 and x['token'] == token and x['reqId'] == req and
                           x['cum'] == d['cumulative'] + j]
                need(len(submits) == 1, 'missing/duplicate actual OBS submit')
                sub = submits[0]
                need(sub['addr'] == desc['address'] and sub['len'] == desc['length'] and
                     sub['opts1'] == (desc['opts1'] & ~(1 << 31) if j == 0 else desc['opts1']) and
                     sub['opts2'] == desc['opts2'] and
                     r['tMapInv'] <= sub['t'] <= d['tOwn'] < d['tDone'] and not sub['flags'] & 3 and
                     sub['slot'] == (d['firstSlot'] + j) % 1024,
                     'OBS actual descriptor disagrees with driver raw')
                dones = [x for x in obs if x['kind'] == 2 and x['cum'] == sub['cum']]
                need(len(dones) == 1 and sub['t'] < dones[0]['t'] <= d['tDone'] and
                     dones[0]['slot'] == sub['slot'] and dones[0]['gen'] == sub['gen'],
                     'real close-pointer completion missing/ambiguous')
                at += pages
            need(at == r['pages'] and all(v == 0 for v in r['physical'][at:] + r['mapPte'][at:] + r['clearPte']),
                 'page count, trailing map pages or actual retire PTE clears disagree')
            need(all(not any(s.values()) for s in r['segments'][n:]) and
                 all(not any(s.values()) for key in ('physical', 'iova', 'descriptors') for s in d[key][n:]),
                 'undeclared segment body')
            mask = d['closeMask']
            need(1023 <= mask <= 0xFFFFFFFF and mask & (mask + 1) == 0 and
                 n <= ((d['doneClose'] - d['cumulative']) & mask) <= (mask + 1) // 2 and
                 d['doneClose'] <= mask, 'hardware close pointer did not retire every packet descriptor')
            need(d['lastSlot'] == (d['firstSlot'] + n - 1) % 1024 and
                 sum(s['bytes'] for s in r['segments'][:n]) == 74, 'expected non-VLAN 32-byte UDP frame/slots')
            for key, stamp in (('mapCommand', 'tMapInv'), ('retireCommand', 'tRetireInv')):
                c = r[key]
                need(c['words'] == [0, h['domid'] | (3 << 28), 0xFFFFF003, 0x7FFFFFFF] and
                     0 < c['expected'] == c['observed'] and c['tComplete'] == r[stamp],
                     'real full-domain PDE invalidation/CompletionWait mismatch')
                sequences.append(c['expected'])
            return {'handle': r['handle'], 'req': req, 'walk': paths, 'driver': d, 'domain': r}
        proof = check('request%d-map-to-retire-free' % req, prove)
        if proof:
            walked.append(proof)
    check('command-completion-generations', lambda: len(sequences) == 8 and
          sequences == list(range(sequences[0], sequences[0] + 8)))
    for old, new in ((old, new) for i, old in enumerate(domain) for new in domain[i + 1:]):
        old_d = next((d for d in driver if d['handle'] == old['handle']), None)
        if old_d and old['tRetireInv'] < new['tMapPublish'] and old_d['tFree'] >= new['tRetireInv']:
            for a in old['segments'][:old['count']]:
                for b in new['segments'][:new['count']]:
                    if a['iova'] == b['iova'] and a['pa'] != b['pa'] and payload(token, old['req']) != payload(token, new['req']):
                        reuse.append({'oldHandle': old['handle'], 'newHandle': new['handle'],
                                      'iova': a['iova'], 'oldPA': a['pa'], 'newPA': b['pa']})
    check('real-same-iova-different-pa-content-reuse', lambda: bool(reuse) and len(walked) == 4)
    check('fault-window-empty', lambda: all(p.get(k) == 0 for k in
          ('m2-b2-win-new-entries', 'm2-b2-win-entries', 'm2-b2-win-raw-count')))
    details.update({'domain_header': h, 'driver_header': dh, 'requests': walked, 'reuse': reuse,
                    'completion_evidence': 'hardware TX close-pointer cumulative, not descriptor OWN readback',
                    'free_scope': 'mbuf quarantine until detach; IOVA reuse requires retire invalidation, not early physical free'})
    return {'scope': 'round16-finite-nonidentity-tx', 'ok': all(c['state'] == 'ok' for c in checks),
            'checks': checks, 'details': details}


def raw_export(cap, raw, key, filename):
    matches = {bytes.fromhex(x) for x in re.findall(r'"' + re.escape(key) + r'"\s*=\s*<([0-9a-fA-F]+)>', raw)}
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
    system, loaded = text('system.txt'), text('r16-version-confirmation.txt')
    result = {'driverMode': next(iter(modes)) if modes else None}
    for label, bundle in (('Driver', 'RTL812xLucy'), ('Probe', 'AMDMapperProbe')):
        versions = re.findall(r'^' + bundle + r'_version\s*:\s*(\S+)', system, re.M)
        uuids = re.findall(r'^' + bundle + r'_uuid\s*:\s*(\S+)', system, re.M)
        live = re.findall(r'\b' + bundle + r'\s+\(([^)]+)\)\s+([A-Fa-f0-9-]+)', loaded)
        need(len(versions) <= 1 and len(uuids) <= 1 and len(live) <= 1, 'ambiguous ' + label + ' identity')
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
            ('m2-3a-domain-raw', 'r16-domain-raw.bin'), ('m2-3a-pt-raw', 'r16-pt-raw.bin'),
            ('m2-3a-driver-raw', 'r16-driver-raw.bin'), ('m2-b2-obs-snapshot-used', 'obs-snapshot-used.bin'))]
        logs = {name: (cap / name).read_text(encoding='utf-8', errors='replace') for name in ('client.log', 'peer.log')}
        result = analyze_payloads(p, *blobs, logs, metadata=capture_metadata(cap))
        result['exports_sha256'] = [hashlib.sha256(x).hexdigest() for x in blobs]
    except (OSError, Refused, KeyError, TypeError, ValueError, struct.error) as e:
        result = {'scope': 'round16-finite-nonidentity-tx', 'ok': False, 'refused': str(e)}
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if len(sys.argv) == 3:
        Path(sys.argv[2]).write_text(text + '\n', encoding='utf-8')
    print(text)
    return 2 if 'refused' in result else (0 if result['ok'] else 1)


if __name__ == '__main__':
    raise SystemExit(main())
