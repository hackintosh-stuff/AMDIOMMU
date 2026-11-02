#!/usr/bin/env python3
"""Round18 independent analysis: did the STANDARD mapper path really run?

Input is one capture directory produced by tools/r18/capture.sh. Every verdict
here is computed from raw exports, never from a success string a producer wrote
about itself:

  * r17-domain-raw.bin   -- the probe's page-table records (720 B stride)
  * r17-pt-raw.bin       -- the page-table arena (walked from the root PA)
  * rtl812x-txmap-raw    -- the driver's per-generation witness (576 B stride)
  * rtl812x-txmap-std-raw-- the driver's standard-object witness (240 B stride)
  * obs-snapshot-used.bin-- TX ring observations (submit/done/close)
  * client.log / peer.log-- the two ends' bytes

The round-17 witness layout is deliberately UNCHANGED, so the round-17 archive
stays decodable with tools/r17/analyze.py while this file adds the standard-path
evidence on top.

Usage: py -3 tools/r18/analyze.py CAPTURE [OUT.json]
"""
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

REQUESTS = list(range(1, 17))
DOMAIN_HEADER, DOMAIN_RECORD_BYTES = 80, 720
DRIVER_MAGIC, DRIVER_HEADER, DRIVER_RECORD_BYTES = 0x37315854, 88, 576
STD_MAGIC, STD_HEADER, STD_RECORD_BYTES = 0x38315854, 72, 240
OBS_MAGIC = 0x3731584F
PTE_IR, PTE_IW = 1 << 61, 1 << 62
K_BASE = 0x1000000000
K_MAX_PAGES = 16


class Refused(Exception):
    pass


def need(cond, msg):
    if not cond:
        raise Refused(msg)


def unpack(names, fmt, blob, off=0):
    return dict(zip(names.split(), struct.unpack_from('<' + fmt, blob, off)))


def cmdrec(blob, off):
    r = unpack('d0 d1 d2 d3 expected observed tComplete', '4I3Q', blob, off)
    r['words'] = [r.pop('d%d' % i) for i in range(4)]
    return r


def decode_domain(blob):
    # r17domain::Snapshot (unchanged layout, 80 B header + 32 x 720 B records)
    h = unpack('version bytes count flags iovaBase iovaBytes rootPA leafPA '
               'ptBase ptBytes rootLevel devid domid active', '4I6Q4I', blob)
    need(h['version'] == 2 and h['bytes'] == len(blob) and 0 < h['count'] <= 32,
         'domain blob: unknown ABI or record count')
    rows = []
    for i in range(32):
        at = DOMAIN_HEADER + i * DOMAIN_RECORD_BYTES
        r = unpack('handle tMapPublish tMapInv tClearPublish tRetireInv count '
                   'pages token req status reserved', '5Q6I', blob, at)
        r['segments'] = [unpack('pa bytes iova', '3Q', blob, at + 64 + j * 24)
                         for j in range(8)]
        for j, key in enumerate(('physical', 'mapPte', 'clearPte')):
            r[key] = list(struct.unpack_from('<16Q', blob, at + 256 + j * 128))
        r['mapCommand'] = cmdrec(blob, at + 640)
        r['retireCommand'] = cmdrec(blob, at + 680)
        rows.append(r)
    return h, rows


def decode_driver(blob):
    h = unpack('magic version bytes count bdf token dropped state retired '
               'rejected maxHeld reserved txNext txDirty txClose txFree '
               'txDescDone completeCalls completeHits lastSeenSlot tPublished',
               '20IQ', blob)
    need(h['magic'] == DRIVER_MAGIC and h['bytes'] == len(blob),
         'driver blob: bad magic/size')
    rows = []
    for i in range(32):
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


def decode_std(blob):
    h = unpack('magic version bytes count bdf token accepts rejects '
               'unsupported unmaps pinned maxHeld mode r0 r1 r2 tPublished',
               '16IQ', blob)
    need(h['magic'] == STD_MAGIC and h['bytes'] == len(blob),
         'std blob: bad magic/size')
    rows = []
    for i in range(32):
        at = STD_HEADER + i * STD_RECORD_BYTES
        r = unpack('version bytes req token handle segCount mapOptions flags',
                   '8I', blob, at)
        r.update(unpack('memory command mapAddress mapLength descriptorOffset '
                        'descriptorLength', '6Q', blob, at + 32))
        r['segments'] = [unpack('address length', '2Q', blob, at + 80 + j * 16)
                         for j in range(4)]
        r.update(unpack('tBegin tPrepared tSegmented tCommit tDone tCompleteBegin '
                        'tCompleteEnd tFree', '8Q', blob, at + 144))
        r.update(unpack('prepareResult segmentResult completeResult mbufSegments '
                        'r0 r1 r2 r3', '8I', blob, at + 208))
        rows.append(r)
    return h, rows


def decode_obs(blob):
    h = unpack('magic version bytes recordBytes count head dropped flags token '
               'bdf reserved', '10I', blob)
    return h


def walk_with_leaf(pt, root_pa, pt_base, leaf_pa, level, iova, leaf_pte):
    """Walk root -> leaf after installing THIS generation's recorded leaf.

    The exported arena is post-retire, so every leaf of a completed generation
    is legitimately absent. The parent chain is still real: it comes from the
    export, and the only thing substituted is the one leaf PTE the probe
    recorded for this generation. The slot is separately required to be zero in
    the untouched export, which is what proves the retire cleared it.
    """
    slot = leaf_pa - pt_base + 8 * ((iova >> 12) & 511)
    need(0 <= slot <= len(pt) - 8, 'leaf slot outside the exported arena')
    need(struct.unpack_from('<Q', pt, slot)[0] == 0,
         'leaf slot %#x was not cleared in the export' % iova)
    patched = bytearray(pt)
    struct.pack_into('<Q', patched, slot, leaf_pte)
    return walk(bytes(patched), root_pa, pt_base, level, iova)


def walk(pt, root_pa, pt_base, level, iova):
    """Walk the exported page table from its root PA to the 4 KiB leaf."""
    if not (level in (3, 4)):
        raise Refused('impossible root level %r' % (level,))
    def table(pa):
        need((pa & 4095) == 0 and pa >= pt_base and pa - pt_base < len(pt),
             'page-table link outside the exported arena')
        off = pa - pt_base
        return list(struct.unpack_from('<512Q', pt, off))
    pa, lvl = root_pa, level
    while lvl > 1:
        ix = (iova >> (12 + 9 * (lvl - 1))) & 511
        e = table(pa)[ix]
        need(e & 1, 'missing table at level %d for iova %#x' % (lvl, iova))
        need(e & PTE_IR, 'table without read permission at level %d' % lvl)
        nxt = e & 0x000FFFFFFFFFF000
        need(nxt, 'table entry without a next-level address')
        pa, lvl = nxt, lvl - 1
    e = table(pa)[(iova >> 12) & 511]
    need(e & 1, 'absent leaf for iova %#x' % iova)
    need((e >> 9) & 7 == 0, 'leaf is not a 4 KiB default leaf')
    need(e & PTE_IR, 'leaf without read permission')
    return (e & 0x000FFFFFFFFFF000) + (iova & 4095), e


def payloads(log_text):
    out = {}
    for line in log_text.splitlines():
        if not line.startswith('client_sent ') and not line.startswith('peer_recv '):
            continue
        m = re.search(r'\breq=(\d+) len=(\d+) sha256=([0-9a-f]{64}) payload=([0-9a-f]*)', line)
        if not m:
            continue
        kind = line.split(' ', 1)[0]
        out.setdefault(int(m.group(1)), {})[kind] = (
            int(m.group(2)), m.group(3), bytes.fromhex(m.group(4)))
    return out


def read_capture(cap):
    props = (cap / 'props.txt').read_text(encoding='utf-8', errors='replace')
    raw = (cap / 'props.raw.txt').read_text(encoding='utf-8', errors='replace')

    def blob_of(key, filename):
        path = cap / filename
        if path.is_file():
            return path.read_bytes()
        m = re.search(r'"%s" = <([0-9a-fA-F\s]+)>' % re.escape(key), raw)
        need(m is not None, 'missing raw export %s' % key)
        return bytes.fromhex(re.sub(r'\s+', '', m.group(1)))

    hexprops = {}
    for line in props.splitlines():
        # setHexProperty publishes "0x…" either bare or quoted; both are numbers.
        m = re.search(r'"([^"]+)" = "?(0x[0-9a-fA-F]+)"?', line)
        if m:
            hexprops[m.group(1)] = int(m.group(2), 16)
            continue
        m = re.search(r'"([^"]+)" = "([^"]*)"', line)
        if m:
            hexprops[m.group(1)] = m.group(2)
    return props, raw, hexprops, blob_of


def analyze(cap):
    props, raw, P, blob_of = read_capture(cap)
    domain_blob = blob_of('m2-3b-domain-raw', 'r18-domain-raw.bin')
    pt_blob = blob_of('m2-3b-pt-raw', 'r18-pt-raw.bin')
    driver_blob = blob_of('rtl812x-txmap-raw', 'r18-driver-raw.bin')
    std_blob = blob_of('rtl812x-txmap-std-raw', 'r18-std-raw.bin')

    dh, dom = decode_domain(domain_blob)
    gh, drv = decode_driver(driver_blob)
    sh, std = decode_std(std_blob)
    # Both ends are parsed into one table: the sent bytes come from the client
    # log, the received bytes from the peer log, and neither side's summary is
    # trusted for the comparison.
    pl = payloads((cap / 'client.log').read_text(encoding='utf-8', errors='replace'))
    for req, entry in payloads((cap / 'peer.log').read_text(encoding='utf-8',
                                                           errors='replace')).items():
        pl.setdefault(req, {}).update(entry)
    # The driver publishes its own mode string on its own node, not on the probe.
    driver_text = (cap / 'driver-obs.txt').read_text(encoding='utf-8', errors='replace')
    loaded = (cap / 'r18-version-confirmation.txt').read_text(encoding='utf-8',
                                                              errors='replace')
    meta = json.loads((cap / 'R18-EXPORTS.json').read_text(encoding='utf-8'))
    checks = []

    # Indexing rule: both record arrays are COMPACTED (only accepted
    # generations get a slot), so raw positions are NOT request ids. Everything
    # below is keyed by the request number each producer stamped.
    std_by_req = {w['req']: w for w in std if w['req']}
    drv_by_req = {g['req']: g for g in drv if g['req']}
    dom_by_handle = {d['handle']: d for d in dom[:dh['count']] if d['handle']}
    # "Accepted" means the mapper published a mapping for it. Completion of that
    # mapping (kUnmapped) is a separate, per-request obligation checked below --
    # folding both bits into the selection would let a half-finished generation
    # silently drop out of the per-request evidence instead of failing it.
    accepted = sorted(r for r in REQUESTS
                      if r in std_by_req and (std_by_req[r]['flags'] & 1))
    refused = [r for r in REQUESTS if r not in accepted]
    walked = {}

    def check(cid, fn):
        try:
            detail = fn()
            checks.append({'id': cid, 'state': 'ok', 'detail': detail} if detail
                          else {'id': cid, 'state': 'ok'})
        except Refused as exc:
            checks.append({'id': cid, 'state': 'fail', 'detail': str(exc)})
        except (KeyError, IndexError, ValueError, struct.error) as exc:
            checks.append({'id': cid, 'state': 'fail',
                           'detail': '%s: %s' % (type(exc).__name__, exc)})

    # ---- 1. the standard path is the one that was armed ---------------------
    def mode_armed():
        need(P.get('m2-3c-mode') == 'standard-iomapper',
             'probe mode is %r' % (P.get('m2-3c-mode'),))
        need('native-mbuf-standard-iomapper-v1' in driver_text,
             'driver did not publish the standard-mode string')
        need(P.get('m2-3b-cleanup') == 'detached-before-DTE-restore',
             'TX cleanup was not clean: %r' % (P.get('m2-3b-cleanup'),))
        need('1.1.203' in loaded and '0.28.0' in loaded,
             'loaded bundle versions are not the round-18 pair')
        need(P.get('m2-3c-held') == 0, 'probe still holds a live owner')
        return {'cleanup': P.get('m2-3b-cleanup'),
                'accepted': accepted, 'refused': refused}
    check('standard-mapper-mode-armed', mode_armed)

    # ---- 2. probe counters are self-consistent ------------------------------
    def counters():
        calls = P.get('m2-3c-map-calls', 0)
        ok = P.get('m2-3c-map-ok', 0)
        rejects = P.get('m2-3c-map-rejects', 0)
        unmaps = P.get('m2-3c-unmap-ok', 0)
        need(ok == sh['accepts'], 'probe map-ok %d != driver accepts %d'
             % (ok, sh['accepts']))
        need(unmaps == sh['unmaps'], 'probe unmap-ok %d != driver unmaps %d'
             % (unmaps, sh['unmaps']))
        need(calls == ok + rejects, 'probe map calls %d != ok+rejects %d'
             % (calls, ok + rejects))
        need(P.get('m2-3c-insert-calls', 0) == 0,
             'iovmInsert was called: the single-range contract was not used')
        need(dh['count'] == ok, 'probe records %d != accepted maps %d'
             % (dh['count'], ok))
        need(sh['count'] == ok, 'std witnesses %d != accepted maps %d'
             % (sh['count'], ok))
        need(ok == len(accepted), 'accepted set %d != probe map-ok %d'
             % (len(accepted), ok))
        return {'mapCalls': calls, 'mapOk': ok, 'mapRejects': rejects,
                'unmaps': unmaps, 'fragRejects': P.get('m2-3c-frag-rejects', 0),
                'offRejects': P.get('m2-3c-off-rejects', 0),
                'driverUnsupported': sh['unsupported'], 'insertCalls': 0,
                'records': dh['count']}
    check('probe-counters-and-record-count', counters)

    # ---- 3. one complete instance per accepted request ---------------------
    def prove(req):
        w = std_by_req[req]
        need(w['flags'] & 1 and w['flags'] & 2,
             'generation was not mapped AND unmapped (flags=%#x)' % w['flags'])
        need(w['handle'], 'no probe handle')
        need(w['memory'] and w['command'], 'descriptor/command pointer missing')
        need(w['segCount'] == 1, 'command produced %d IOVA segments' % w['segCount'])
        need(w['segments'][0]['length'] == w['descriptorLength'],
             'IOVA segment length differs from the frame')
        need(w['mapAddress'] == w['segments'][0]['address'],
             'mapAddress is not the address the command reported')
        need(w['mapAddress'] >= K_BASE,
             'mapAddress %#x is not in the IOVA window' % w['mapAddress'])
        need(w['completeResult'] == 0, 'complete() returned %#x' % w['completeResult'])
        # the probe's own record of the same generation
        d = dom_by_handle.get(w['handle'])
        need(d is not None, 'no probe record for handle %r' % (w['handle'],))
        need(d['status'] == 3, 'domain status %#x is not map+retire' % d['status'])
        need(d['segments'][0]['iova'] == w['mapAddress'],
             'probe returned %#x but the driver used %#x'
             % (d['segments'][0]['iova'], w['mapAddress']))
        need(d['segments'][0]['bytes'] == w['descriptorLength'],
             'probe mapLength differs from the frame length')
        # the real packet's physical bytes
        g = drv_by_req.get(req)
        need(g is not None, 'no driver witness for request %d' % req)
        need(g['count'] == 1, 'driver witness is not one segment')
        need(g['physical'][0]['address'] == d['segments'][0]['pa'],
             'driver physical PA %#x != probe mapped PA %#x'
             % (g['physical'][0]['address'], d['segments'][0]['pa']))
        need(g['physical'][0]['length'] == w['descriptorLength'],
             'physical length differs')
        need(g['descriptors'][0]['address'] == w['mapAddress'],
             'the TX descriptor did not carry the mapped IOVA')
        need(g['descriptors'][0]['length'] == w['descriptorLength'],
             'descriptor length differs')
        need(g['descriptors'][0]['address'] != g['physical'][0]['address'],
             'descriptor used the physical address (identity)')
        need(g['doneOpts1'][0] & 0x80000000, 'descriptor was not offered by the driver')
        # ordering, with the invalidation completions where they belong
        need(d['tMapPublish'] <= d['tMapInv'] <= g['tOwn'] <= g['tDone'] <=
             d['tClearPublish'] <= d['tRetireInv'] <= g['tFree'],
             'generation timestamps are out of order')
        need(w['tBegin'] <= w['tPrepared'] <= w['tSegmented'] <= w['tCommit'],
             'standard-object timestamps are out of order')
        need(w['tCompleteBegin'] <= w['tCompleteEnd'] <= w['tFree'],
             'unmap is not before the free')
        # the page-table path for the bytes the device actually read
        paths = []
        pages = d['pages']
        need(1 <= pages <= K_MAX_PAGES, 'impossible page count %r' % (pages,))
        base = d['segments'][0]['pa'] - (d['segments'][0]['pa'] & 4095)
        for j in range(pages):
            pa = d['physical'][j]
            need(pa == base + j * 4096,
                 'page %d is not the contiguous neighbour of %#x' % (j, base))
            got, leaf = walk_with_leaf(pt_blob, dh['rootPA'], dh['ptBase'],
                                       dh['leafPA'], dh['rootLevel'],
                                       K_BASE + j * 4096, d['mapPte'][j])
            need(got == pa, 'walk of IOVA page %d gave %#x, mapped %#x' % (j, got, pa))
            need(leaf == d['mapPte'][j], 'exported PTE differs from the walked leaf')
            need(not d['clearPte'][j], 'leaf was not cleared at retire')
            paths.append({'page': j, 'iova': K_BASE + j * 4096, 'pa': pa,
                          'pte': hex(leaf)})
        need(d['mapCommand']['observed'] == d['mapCommand']['expected'] and
             d['retireCommand']['observed'] == d['retireCommand']['expected'],
             'invalidation CompletionWait did not match the submission')
        walked[req] = {'req': req, 'handle': w['handle'],
                       'frameBytes': w['descriptorLength'],
                       'physical': g['physical'][0]['address'],
                       'mapAddress': w['mapAddress'], 'mapLength': w['mapLength'],
                       'memory': hex(w['memory']), 'command': hex(w['command']),
                       'segments': [{'address': s['address'], 'length': s['length']}
                                    for s in w['segments'][:w['segCount']]],
                       'descriptor': {'address': g['descriptors'][0]['address'],
                                      'length': g['descriptors'][0]['length']},
                       'pages': paths,
                       't': {'mapPublish': d['tMapPublish'], 'mapInv': d['tMapInv'],
                             'prepare': w['tPrepared'], 'segments': w['tSegmented'],
                             'own': g['tOwn'], 'done': g['tDone'],
                             'clear': d['tClearPublish'], 'retireInv': d['tRetireInv'],
                             'completeEnd': w['tCompleteEnd'], 'free': g['tFree']},
                       'prepareResult': hex(w['prepareResult']),
                       'completeResult': hex(w['completeResult']),
                       'close': {'cumulative': g['cumulative'],
                                 'done': g['doneClose']}}
        return {'mapAddress': hex(w['mapAddress']),
                'pa': hex(g['physical'][0]['address']), 'pages': pages}

    for req in accepted:
        check('request%02d-standard-map-to-unmap' % req, lambda r=req: prove(r))

    # ---- 4. per-packet recycling over consecutive accepted generations ------
    def recycle():
        need(len(walked) == len(accepted), 'not every accepted request proved out')
        need(len(accepted) > 8, 'fewer accepted requests than the old limit')
        gaps = []
        order = accepted
        for i in range(len(order) - 1):
            a, b = std_by_req[order[i]], std_by_req[order[i + 1]]
            need(a['tFree'] and b['tBegin'], 'missing begin/free stamps')
            need(a['tFree'] < b['tBegin'],
                 'request %d was still owned when %d started mapping'
                 % (order[i], order[i + 1]))
            gaps.append(b['tBegin'] - a['tFree'])
        need(P.get('m2-3b-live-owner-max') == 1,
             'live owner peak %r' % (P.get('m2-3b-live-owner-max'),))
        need(P.get('m2-3b-owners-held') == 0, 'owner still held at export')
        need(sh['maxHeld'] == 1, 'driver held peak %r' % (sh['maxHeld'],))
        need(sh['pinned'] == 0, 'a generation was pinned')
        return {'minFreeToNextMap_ns': min(gaps), 'maxLiveOwners': 1,
                'generations': len(order)}
    check('per-packet-free-and-bounded-owners', recycle)

    # ---- 5. beyond the round-16 cumulative limits --------------------------
    def beyond_old_limits():
        need(len(accepted) > 8, 'only %d accepted generations' % len(accepted))
        need(dh['count'] > 8, 'probe recorded only %d generations' % dh['count'])
        need(len({std_by_req[r]['handle'] for r in accepted}) == len(accepted),
             'handles are not unique')
        need(all(std_by_req[r]['flags'] & 2 for r in accepted),
             'not every generation was unmapped')
        return {'generations': len(accepted),
                'handles': '%d..%d' % (min(std_by_req[r]['handle'] for r in accepted),
                                       max(std_by_req[r]['handle'] for r in accepted))}
    check('beyond-round16-cumulative-limits', beyond_old_limits)

    # ---- 6. unsupported layouts were refused before any hardware -----------
    def refused_ok():
        need(refused, 'no request was refused for an unsupported layout; the '
                      'bounded contract is then untested')
        need(sh['unsupported'] == len(refused),
             'driver counted %d unsupported but %d requests never mapped'
             % (sh['unsupported'], len(refused)))
        for req in refused:
            need(req not in std_by_req or not (std_by_req[req]['flags'] & 1),
                 'request %d was refused yet has a mapping witness' % req)
        need(dh['count'] == len(accepted),
             'the probe recorded a generation the driver did not accept')
        return {'unsupportedLayout': sh['unsupported'], 'refusedRequests': refused,
                'prepareRejects': sh['rejects']}
    check('unsupported-layout-refused-before-hardware', refused_ok)

    # ---- 7. both ends saw the same bytes, for every accepted request -------
    def bytes_ok():
        total = 0
        for req in accepted:
            e = pl.get(req, {})
            need('client_sent' in e and 'peer_recv' in e,
                 'request %d is missing on one end' % req)
            sent, received = e['client_sent'], e['peer_recv']
            need(sent[0] == received[0], 'request %d length differs between ends' % req)
            need(hashlib.sha256(sent[2]).hexdigest() == received[1],
                 'request %d bytes differ at the peer' % req)
            need(walked[req]['frameBytes'] > sent[0], 'frame shorter than payload')
            total += sent[0]
        return {'requests': len(accepted), 'payloadBytes': total}
    check('full-application-bytes', bytes_ok)

    # ---- 8. the close pointer really advanced per generation ---------------
    def completions():
        for req in accepted:
            need(walked[req]['close']['done'],
                 'no close-pointer sample for request %d' % req)
            need(walked[req]['close']['cumulative'] < walked[req]['close']['done'],
                 'close pointer did not advance past request %d' % req)
        return {'requests': len(accepted), 'ringClose': gh['txClose'],
                'ringDone': gh['txDescDone']}
    check('hardware-close-pointer-per-generation', completions)

    ok = all(c['state'] == 'ok' for c in checks)
    return {'scope': 'round18-standard-iomapper-tx', 'ok': ok,
            'checks': checks,
            'details': {'accepted': accepted, 'refused': refused,
                        'requests': [walked[r] for r in accepted if r in walked],
                        'probe': {k: P.get(k) for k in sorted(P) if k.startswith('m2-3c-')},
                        'std': {k: sh[k] for k in ('accepts', 'rejects', 'unsupported',
                                                   'unmaps', 'pinned', 'maxHeld', 'count')},
                        'capture': meta.get('exports', {}),
                        'cleanup': P.get('m2-3b-cleanup')}}


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    cap = Path(sys.argv[1])
    result = analyze(cap)
    text = json.dumps(result, indent=2, default=str)
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(text, encoding='utf-8')
    passed = sum(1 for c in result['checks'] if c['state'] == 'ok')
    print(text if len(sys.argv) <= 2 else '%d/%d checks passed' % (passed, len(result['checks'])))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
