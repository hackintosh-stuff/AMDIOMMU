#!/usr/bin/env python3
"""Round20 independent analysis: did the STANDARD mapper path really run?

Input is one capture directory produced by tools/r20/capture.sh. Every verdict
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

Usage: py -3 tools/r20/analyze.py CAPTURE [OUT.json]
"""
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

REQUESTS = list(range(1, 17))
MULTI_MBUF = (2, 4, 6, 8, 11)   # declared large frames (must be real chains)
DOMAIN_HEADER, DOMAIN_RECORD_BYTES = 80, 720
DRIVER_MAGIC, DRIVER_HEADER, DRIVER_RECORD_BYTES = 0x37315854, 88, 576
# Round20 raised the driver snapshot to version 3 (kCover + 8-segment witness);
# round21 keeps it unchanged.
DRIVER_VERSION = 4
STD_MAGIC, STD_HEADER, STD_RECORD_BYTES = 0x38315854, 72, 304
STD_VERSION, STD_SEGMENTS = 3, 8
# ABI numbers come FROM the C++ headers, not from memory. `abi.py` compiles a
# probe against tools/lucy-obs/*.hpp; `abi.abi()['block_bytes']` is the size the
# driver will actually emit. The literals below are kept only as a redundant
# check (`abi.py --check` asserts they still match) so a header change fails a
# command instead of a hardware run.
BLOCK_MAGIC, BLOCK_BYTES = 0x30325854, 2320
BLOCK_OFF_TSAMPLE = 96
BLOCK_OFF_RINGADDR = 104
BLOCK_OFF_SAMPLESTAGE = 120
BLOCK_OFF_SLOTS = 144
BLOCK_OFF_OUTADDR = 784
BLOCK_OFF_OUTOPTS1 = 1808
BLOCK_STAGE_EXIT = 3
OBS_MAGIC = 0x3731584F
PTE_IR, PTE_IW = 1 << 61, 1 << 62
K_BASE = 0x1000000000
K_MAX_PAGES = 16
# Round23: the 64 GiB window is split into kSlots fixed stripes of this
# many 4 KiB pages each (amdtx::kSlots / kPagesPerSlot). Named here so the
# analyzer's stripe arithmetic cannot drift from the header's.
K_PAGES_PER_SLOT = 4
K_SLOTS = K_MAX_PAGES // K_PAGES_PER_SLOT


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
                   'pages token req status maplen', '5Q6I', blob, at)
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
    need(h['magic'] == STD_MAGIC and h['version'] == STD_VERSION and
         h['bytes'] == len(blob),
         'std blob: bad magic/version/size')
    rows = []
    for i in range(32):
        at = STD_HEADER + i * STD_RECORD_BYTES
        r = unpack('version bytes req token handle segCount mapOptions flags',
                   '8I', blob, at)
        # Only the first `count` witnesses are live; the rest are zero padding.
        if i < h['count']:
            need(r['version'] == STD_VERSION and r['bytes'] == STD_RECORD_BYTES,
                 'std witness %d: bad ABI' % i)
        r.update(unpack('memory command mapAddress mapLength descriptorOffset '
                        'descriptorLength', '6Q', blob, at + 32))
        r['segments'] = [unpack('address length', '2Q', blob, at + 80 + j * 16)
                         for j in range(STD_SEGMENTS)]
        r.update(unpack('tBegin tPrepared tSegmented tCommit tDone tCompleteBegin '
                        'tCompleteEnd tFree', '8Q', blob, at + 80 + STD_SEGMENTS * 16))
        r.update(unpack('prepareResult segmentResult completeResult mbufSegments '
                        'r0 r1 r2 r3', '8I', blob,
                        at + 80 + STD_SEGMENTS * 16 + 64))
        rows.append(r)
    return h, rows


def decode_block(blob):
    """r20tx::Block: the ring sample taken when the experiment stopped."""
    need(len(blob) == BLOCK_BYTES, 'block blob: bad size %d' % len(blob))
    h = unpack('magic version bytes bdf token state txNext txDirty txClose '
               'txTail txFree txDescDone completeCalls completeHits lastSeenSlot '
               'firstSlot liveCount liveHandle liveReq liveSegs liveMbufs '
               'liveFlags nslot outstanding', '24I', blob)
    need(h['magic'] == BLOCK_MAGIC and h['version'] == 2 and
         h['bytes'] == BLOCK_BYTES, 'block blob: bad ABI')
    h['tSample'] = struct.unpack_from('<Q', blob, BLOCK_OFF_TSAMPLE)[0]
    h['ringAddr'] = struct.unpack_from('<Q', blob, BLOCK_OFF_RINGADDR)[0]
    h['ringBytes'], h['ringDescSize'] = struct.unpack_from('<2I', blob, 112)
    # Round21 window-edge context. sampleStage says WHICH step forced this
    # sample; a record whose stage is not kStageExit is not evidence about the
    # exit moment, however recent its timestamp looks.
    (h['sampleStage'], h['sampleSeq'], h['quiesced'], h['activeCover'],
     h['coverCalls'], h['coverRejects']) = struct.unpack_from('<6I', blob, BLOCK_OFF_SAMPLESTAGE)
    h['slots'] = []
    for i in range(16):
        at = BLOCK_OFF_SLOTS + i * 40
        s = unpack('addr mbufData index opts1 opts2 mbufLen flags pad2', '2Q6I',
                   blob, at)
        h['slots'].append(s)
    h['outAddr'] = list(struct.unpack_from('<128Q', blob, BLOCK_OFF_OUTADDR))
    h['outOpts1'] = list(struct.unpack_from('<128I', blob, BLOCK_OFF_OUTOPTS1))
    return h


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


def identity_high_chunks(pt, h, limit=0x400000000):
    """2 MiB identity leaves above the bootstrap limit, from the final export.

    The cover path adds these at runtime and never removes them, so the export
    shows exactly which chunks the device was given for ordinary TX objects.
    Only the identity subtree is scanned (1 GiB indices below the 64 GiB IOVA
    window); the window's own subtree is at index 64.
    """
    base, level, root_pa = h['ptBase'], h['rootLevel'], h['rootPA']

    def table(pa):
        need((pa & 4095) == 0 and pa >= base and pa - base + 4096 <= len(pt),
             'identity scan: table outside the exported arena')
        return list(struct.unpack_from('<512Q', pt, pa - base))

    ADDR = 0x000FFFFFFFFFF000
    if level == 4:
        e = table(root_pa)[0]
        need((e >> 9) & 7 == 3, 'identity scan: root[0] is not a level-3 table')
        t3 = table(e & ADDR)
    elif level == 3:
        t3 = table(root_pa)
    else:
        raise Refused('identity scan: impossible root level %r' % (level,))
    out = []
    for gb in range(limit >> 30, 64):
        e3 = t3[gb]
        if not (e3 & 1):
            continue
        nl = (e3 >> 9) & 7
        if nl == 2:
            t2 = table(e3 & ADDR)
            for ix in range(512):
                e2 = t2[ix]
                if not (e2 & 1) or ((e2 >> 9) & 7) != 0:
                    continue
                chunk = (gb << 30) | (ix << 21)
                out.append({'chunk': chunk, 'pa': e2 & ADDR,
                            'ir': bool(e2 & PTE_IR), 'iw': bool(e2 & PTE_IW)})
        elif nl == 0:
            chunk = gb << 30
            out.append({'chunk': chunk, 'pa': e3 & ADDR,
                        'ir': bool(e3 & PTE_IR), 'iw': bool(e3 & PTE_IW)})
    return out


def _ord_records(text):
    """Parse this round's ordinary-traffic probes out of a client/peer log.

    Each line is one event for one datagram: the sequence number is the join
    key, the SHA-256 is the payload identity, and `t_ns` is CLOCK_UPTIME_RAW --
    the same clock the probe stamps into the window boundaries, which is what
    makes "this echo happened after the resume" checkable rather than assumed.
    """
    out = []
    for line in text.splitlines():
        m = re.match(r'(client|peer)_ord_(sent|recv|timeout) seq=(\d+)'
                     r'(?: tag=(\S+))?(.*)', line)
        if not m:
            continue
        side, kind, seq, tag, rest = m.groups()
        rec = {'side': side, 'kind': kind, 'seq': int(seq), 'tag': tag or ''}
        for key, pat in (('sha256', r'sha256=([0-9a-f]{64})'),
                         ('ok', r'payload_ok=(\d)'),
                         ('t', r't_ns=(\d+)'),
                         ('from', r'from=(\S+)')):
            mm = re.search(pat, rest)
            if mm:
                rec[key] = int(mm.group(1)) if key in ('ok', 't') else mm.group(1)
        out.append(rec)
    return out


def analyze(cap):
    props, raw, P, blob_of = read_capture(cap)
    domain_blob = blob_of('m2-3b-domain-raw', 'r21-domain-raw.bin')
    pt_blob = blob_of('m2-3b-pt-raw', 'r21-pt-raw.bin')
    driver_blob = blob_of('rtl812x-txmap-raw', 'r21-driver-raw.bin')
    std_blob = blob_of('rtl812x-txmap-std-raw', 'r21-std-raw.bin')
    block_blob = blob_of('rtl812x-txmap-block-raw', 'r21-block-raw.bin')

    dh, dom = decode_domain(domain_blob)
    gh, drv = decode_driver(driver_blob)
    sh, std = decode_std(std_blob)
    bh = decode_block(block_blob)
    # Both ends are parsed into one table: the sent bytes come from the client
    # log, the received bytes from the peer log, and neither side's summary is
    # trusted for the comparison.
    pl = payloads((cap / 'client.log').read_text(encoding='utf-8', errors='replace'))
    for req, entry in payloads((cap / 'peer.log').read_text(encoding='utf-8',
                                                           errors='replace')).items():
        pl.setdefault(req, {}).update(entry)
    # The driver publishes its own mode string on its own node, not on the probe.
    driver_text = (cap / 'driver-obs.txt').read_text(encoding='utf-8', errors='replace')
    loaded = (cap / 'r21-version-confirmation.txt').read_text(encoding='utf-8',
                                                              errors='replace')
    meta = json.loads((cap / 'R21-EXPORTS.json').read_text(encoding='utf-8'))
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
        need(P.get('m2-3b-cleanup') == 'detached-after-restore-confirmed',
             'TX cleanup was not clean: %r' % (P.get('m2-3b-cleanup'),))
        # Round22: the loaded identities are compared against the deploy's own
        # record, not against a pair of literals. The literals were rewritten by
        # hand every round, so a version bump made the analyzer reject a correct
        # run -- and a wrong build could still pass if the literals had been
        # updated without care.
        exp_path = cap / 'r21-load/expected-version.json'
        need(exp_path.is_file(), 'expected-version.json missing from the capture')
        expected_kexts = json.loads(exp_path.read_text(encoding='utf-8'))
        for name, info in sorted(expected_kexts.items()):
            need(info['version'] in loaded,
                 'loaded %s is not the deployed version %r'
                 % (name, info['version']))
            need(info['uuid'].upper() in loaded.upper(),
                 'loaded %s UUID %r is absent from the confirmation'
                 % (name, info['uuid']))
        need(P.get('m2-3c-held') == 0, 'probe still holds a live owner')
        return {'cleanup': P.get('m2-3b-cleanup'),
                'kexts': {k: v['version'] for k, v in expected_kexts.items()},
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
        # round20 window accounting: the run counters must agree with the
        # records, run by run -- this is what makes "multi-mbuf support" a
        # measured fact instead of a claim.
        runs = [dom_by_handle[std_by_req[r]['handle']]['count'] for r in accepted]
        need(P.get('m2-3c-runs', 0) == sum(runs),
             'probe counted %d runs, the records hold %d'
             % (P.get('m2-3c-runs', 0), sum(runs)))
        need(P.get('m2-3c-max-runs', 0) == max(runs),
             'probe max-runs %d != record maximum %d'
             % (P.get('m2-3c-max-runs', 0), max(runs)))
        need(P.get('m2-3c-discontig', 0) == sum(1 for n in runs if n > 1),
             'probe discontig %d != multi-run generations %d'
             % (P.get('m2-3c-discontig', 0), sum(1 for n in runs if n > 1)))
        return {'mapCalls': calls, 'mapOk': ok, 'mapRejects': rejects,
                'unmaps': unmaps, 'fragRejects': P.get('m2-3c-frag-rejects', 0),
                'offRejects': P.get('m2-3c-off-rejects', 0),
                'capRejects': P.get('m2-3c-cap-rejects', 0),
                'driverUnsupported': sh['unsupported'], 'insertCalls': 0,
                'records': dh['count'], 'runs': sum(runs), 'maxRuns': max(runs),
                'multiRunGenerations': sum(1 for n in runs if n > 1)}
    check('probe-counters-and-record-count', counters)

    # ---- 3. one complete instance per accepted request ---------------------
    def prove(req):
        w = std_by_req[req]
        need(w['flags'] & 1 and w['flags'] & 2,
             'generation was not mapped AND unmapped (flags=%#x)' % w['flags'])
        need(w['handle'], 'no probe handle')
        need(w['memory'] and w['command'], 'descriptor/command pointer missing')
        nseg = w['segCount']
        need(1 <= nseg <= STD_SEGMENTS, 'command produced %d IOVA segments' % nseg)
        need(1 <= w['mbufSegments'] <= 8,
             'recorded mbuf chain length %d' % w['mbufSegments'])
        covered = sum(s['length'] for s in w['segments'][:nseg])
        need(covered == w['descriptorLength'],
             'DMA runs cover %d of %d frame bytes' % (covered, w['descriptorLength']))
        need(all(s['address'] >= K_BASE for s in w['segments'][:nseg]),
             'a DMA run is outside the IOVA window')
        need(w['mapAddress'] == w['segments'][0]['address'],
             'mapAddress is not the address the command reported')
        need(w['completeResult'] == 0, 'complete() returned %#x' % w['completeResult'])
        # the probe's own record of the same generation
        d = dom_by_handle.get(w['handle'])
        need(d is not None, 'no probe record for handle %r' % (w['handle'],))
        need(d['status'] == 3, 'domain status %#x is not map+retire' % d['status'])
        need(d['count'] == nseg,
             'probe laid out %d runs, the command returned %d' % (d['count'], nseg))
        # TWO independent computations of the same layout must agree run by run:
        # the mapper's (this record) and IODMACommand's (the driver witness).
        for i in range(nseg):
            need(d['segments'][i]['iova'] == w['segments'][i]['address'],
                 'run %d: probe IOVA %#x != command IOVA %#x'
                 % (i, d['segments'][i]['iova'], w['segments'][i]['address']))
            need(d['segments'][i]['bytes'] == w['segments'][i]['length'],
                 'run %d: lengths differ' % i)
        # the exact length the mapper returned, which is what IOKit hands back
        # to iovmUnmapMemory(); a fragmented window is page-aligned per run and
        # therefore strictly longer than the frame.
        # Round23: the offset that matters is inside the generation's own
        # stripe, because that is where its window begins. Using the offset from
        # the whole-window base (round 22) mixes in the stripe and yields a
        # negative length.
        stripe_base = (d['segments'][0]['iova'] - K_BASE) // (
            K_PAGES_PER_SLOT * 4096) * (K_PAGES_PER_SLOT * 4096)
        off0 = d['segments'][0]['iova'] - K_BASE - stripe_base
        need(d['maplen'] >= w['descriptorLength'],
             'recorded unmap length %d is shorter than the frame' % (d['maplen'],))
        winlen = d['pages'] * 4096 - off0
        need(d['maplen'] in (w['descriptorLength'], winlen),
             'recorded unmap length %d is neither the frame %d nor the stripe '
             'window %d (off in stripe %d)'
             % (d['maplen'], w['descriptorLength'], winlen, off0))
        # the real packet's physical bytes, and the descriptors the device read
        g = drv_by_req.get(req)
        need(g is not None, 'no driver witness for request %d' % req)
        need(g['count'] == nseg, 'driver programmed %d descriptors' % g['count'])
        for i in range(nseg):
            need(g['descriptors'][i]['address'] == w['segments'][i]['address'],
                 'descriptor %d did not carry the mapped IOVA' % i)
            need(g['descriptors'][i]['length'] == w['segments'][i]['length'],
                 'descriptor %d length differs' % i)
            need(g['descriptors'][i]['address'] != d['segments'][i]['pa'],
                 'descriptor %d used the physical address (identity)' % i)
            need(g['doneOpts1'][i] & 0x80000000,
                 'descriptor %d was not offered by the driver' % i)
        # ordering, with the invalidation completions where they belong
        need(d['tMapPublish'] <= d['tMapInv'] <= g['tOwn'] <= g['tDone'] <=
             d['tClearPublish'] <= d['tRetireInv'] <= g['tFree'],
             'generation timestamps are out of order')
        need(w['tBegin'] <= w['tPrepared'] <= w['tSegmented'] <= w['tCommit'],
             'standard-object timestamps are out of order')
        need(w['tCompleteBegin'] <= w['tCompleteEnd'] <= w['tFree'],
             'unmap is not before the free')
        # the page-table path for the bytes the device actually read. The
        # window layout is RECONSTRUCTED from the recorded runs (slot per run,
        # page-aligned, first byte keeps its in-page offset) and must match the
        # exported PTEs page by page -- including the padding pages a fragment
        # costs.
        paths = []
        pages = d['pages']
        need(1 <= pages <= K_MAX_PAGES, 'impossible page count %r' % (pages,))
        expect = {}
        for i in range(d['count']):
            pa, ln = d['segments'][i]['pa'], d['segments'][i]['bytes']
            align = pa & 4095
            slot = (d['segments'][i]['iova'] - K_BASE) - align
            npg = (align + ln + 4095) // 4096
            for k in range(npg):
                expect[slot // 4096 + k] = (pa & ~4095) + k * 4096
        need(len(expect) == pages,
             'runs imply %d window pages, the record says %d' % (len(expect), pages))
        # Round23: the page indices are ABSOLUTE window pages, so a generation in
        # stripe k uses k*K_PAGES_PER_SLOT .. and every one must sit inside that
        # same stripe. Checking the stripe here is what proves the fixed layout
        # was respected, rather than merely that some 16 slots were written.
        stripe_of_gen = None
        for j in sorted(expect):
            stripe = j // K_PAGES_PER_SLOT
            if stripe_of_gen is None:
                stripe_of_gen = stripe
            need(stripe == stripe_of_gen,
                 'generation spans stripes %r and %r: its pages are not one '
                 'fixed stripe' % (stripe_of_gen, stripe))
            pa = d['physical'][j]
            need(expect[j] == pa,
                 'window page %d maps %#x, the runs imply %#x' % (j, pa, expect[j]))
            got, leaf = walk_with_leaf(pt_blob, dh['rootPA'], dh['ptBase'],
                                       dh['leafPA'], dh['rootLevel'],
                                       K_BASE + j * 4096, d['mapPte'][j])
            need(got == pa, 'walk of IOVA page %d gave %#x, mapped %#x' % (j, got, pa))
            need(leaf == d['mapPte'][j], 'exported PTE differs from the walked leaf')
            need(not d['clearPte'][j], 'leaf was not cleared at retire')
            paths.append({'page': j, 'iova': K_BASE + j * 4096, 'pa': pa,
                          'pte': hex(leaf),
                          'stripe': stripe})
        need(d['mapCommand']['observed'] == d['mapCommand']['expected'] and
             d['retireCommand']['observed'] == d['retireCommand']['expected'],
             'invalidation CompletionWait did not match the submission')
        walked[req] = {'req': req, 'handle': w['handle'],
                       'frameBytes': w['descriptorLength'],
                       'mbufs': w['mbufSegments'], 'runs': nseg,
                       'mapAddress': w['mapAddress'], 'mapLength': w['mapLength'],
                       'unmapLength': d['maplen'],
                       'memory': hex(w['memory']), 'command': hex(w['command']),
                       'segments': [{'address': s['address'], 'length': s['length']}
                                    for s in w['segments'][:nseg]],
                       'physicalRuns': [{'pa': s['pa'], 'bytes': s['bytes'],
                                         'iova': s['iova']}
                                        for s in d['segments'][:nseg]],
                       'descriptors': [{'address': gg['address'],
                                        'length': gg['length']}
                                       for gg in g['descriptors'][:nseg]],
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
        return {'mapAddress': hex(w['mapAddress']), 'runs': nseg,
                'mbufs': w['mbufSegments'], 'pages': pages,
                'stripe': stripe_of_gen}

    for req in accepted:
        check('request%02d-standard-map-to-unmap' % req, lambda r=req: prove(r))

    # ---- 4. MULTIPLE LIVE MAPPINGS, proved from the timestamps -------------
    #
    # This replaces round 22's "exactly one owner at a time" check, which is the
    # restriction this round exists to remove. The proof is a relation on the
    # records, not a counter the driver reports about itself:
    #
    #     g2 overlapped g1  <=>  g2.tBegin < g1.tFree
    #
    # i.e. the second generation started mapping before the first had finished
    # freeing. Chains of such pairs bound the peak live count.
    def overlap():
        need(len(walked) == len(accepted), 'not every accepted request proved out')
        gen = [(r, std_by_req[r]) for r in accepted]
        pairs = []
        for i in range(len(gen)):
            for j in range(len(gen)):
                if i == j:
                    continue
                a, wa = gen[i]
                b, wb = gen[j]
                if wa['tBegin'] and wb['tBegin'] and wa['tFree'] and \
                        wb['tBegin'] < wa['tFree'] and wb['tBegin'] > wa['tBegin']:
                    pairs.append({'first': a, 'second': b,
                                  'secondBegin': wb['tBegin'],
                                  'firstFree': wa['tFree'],
                                  'overlapNs': wa['tFree'] - wb['tBegin']})
        # The peak simultaneous count, computed by sweeping the begin/free edges.
        edges = []
        for r, w in gen:
            edges.append((w['tBegin'], 1))
            edges.append((w['tFree'], -1))
        edges.sort()
        live = peak = 0
        for _, d in edges:
            live += d
            peak = max(peak, live)
        need(pairs, 'no two mappings were ever live at the same time: the '
                    'batch did not overlap')
        need(peak >= 2, 'computed live peak is %d, so no overlap happened' % peak)
        # The probe and the driver must agree about the peak they observed.
        need(P.get('m2-3b-owners-held') == 0, 'owner still held at export')
        need(sh['pinned'] == 0, 'a generation was pinned')
        need(sh['maxHeld'] >= 2,
             'driver held peak is %r, so it never had two mappings' % (sh['maxHeld'],))
        need(P.get('m2-3b-live-owner-max') == peak,
             'probe peak %r != computed peak %d'
             % (P.get('m2-3b-live-owner-max'), peak))
        return {'peakLive': peak, 'overlapPairs': len(pairs),
                'maxHeld': sh['maxHeld'],
                'widestOverlapNs': max(x['overlapNs'] for x in pairs),
                'example': pairs[0]}
    check('multiple-mappings-live-at-once', overlap)

    # ---- 4b. the fixed stripes never collided ------------------------------
    def stripes_disjoint():
        # Every generation was given a stripe of amdtx::kPagesPerSlot pages, and
        # two LIVE generations must never share one. Checked from the recorded
        # IOVA of each generation against the others that overlapped it.
        need(P.get('m2-3b-slots-capacity') == K_SLOTS,
             'probe reports slot capacity %r, header says %d'
             % (P.get('m2-3b-slots-capacity'), K_SLOTS))
        stripe_of = {}
        for r in accepted:
            w = std_by_req[r]
            off = w['mapAddress'] - K_BASE
            stripe_of[r] = off // (K_PAGES_PER_SLOT * 4096)
        # two generations that overlapped must be in different stripes
        bad = []
        gen = [(r, std_by_req[r]) for r in accepted]
        for i in range(len(gen)):
            for j in range(len(gen)):
                if i == j:
                    continue
                a, wa = gen[i]
                b, wb = gen[j]
                if wa['tFree'] and wb['tBegin'] and wb['tBegin'] < wa['tFree'] \
                        and wb['tBegin'] > wa['tBegin']:
                    if stripe_of[a] == stripe_of[b]:
                        bad.append((a, b, stripe_of[a]))
        need(not bad, 'overlapping generations shared a stripe: %r' % (bad,))
        need(all(0 <= s < K_SLOTS for s in stripe_of.values()),
             'a generation fell outside the striped window: %r' % (stripe_of,))
        used = sorted(set(stripe_of.values()))
        need(len(used) >= 2, 'only %d stripe(s) were ever used' % len(used))
        return {'stripesUsed': used, 'perRequest': stripe_of,
                'slotsUsed': P.get('m2-3b-slots-used')}
    check('window-stripes-never-collide', stripes_disjoint)

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

    # ---- 6. the declared multi-mbuf frames really were multi-mbuf -----------
    def multi_mbuf():
        need(not refused, 'requests refused in the supported range: %r' % (refused,))
        need(sh['unsupported'] == 0,
             'driver counted %d unsupported layouts' % sh['unsupported'])
        need(dh['count'] == len(accepted),
             'the probe recorded a generation the driver did not accept')
        report, scatter = [], 0
        for req in MULTI_MBUF:
            w = std_by_req.get(req)
            need(w is not None and (w['flags'] & 1),
                 'declared large request %d was never mapped' % req)
            d = dom_by_handle[w['handle']]
            # chain length and runs come from the records, never from payload size
            need(w['mbufSegments'] >= 2,
                 'request %d recorded %d mbuf(s), not a real chain'
                 % (req, w['mbufSegments']))
            need(w['segCount'] >= 2,
                 'request %d produced %d DMA run(s)' % (req, w['segCount']))
            need(d['count'] == w['segCount'],
                 'request %d: probe runs %d != command runs %d'
                 % (req, d['count'], w['segCount']))
            pa = [(s['pa'], s['bytes']) for s in d['segments'][:d['count']]]
            contig = all(pa[i][0] + pa[i][1] == pa[i + 1][0]
                         for i in range(len(pa) - 1))
            if not contig:
                scatter += 1
            report.append({'req': req, 'mbufs': w['mbufSegments'],
                           'runs': w['segCount'],
                           'physical': [{'pa': hex(a), 'bytes': n} for a, n in pa],
                           'contiguous': contig,
                           'iova': [hex(s['address'])
                                    for s in w['segments'][:w['segCount']]]})
        need(scatter >= 1,
             'no multi-mbuf sample has non-contiguous physical runs')
        return {'multiMbufRequests': report, 'nonContiguousSamples': scatter}
    check('real-multi-mbuf-multi-run-samples', multi_mbuf)

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

    # ---- 9. the round-19 stall is gone: quiescent ring, no device fault -----
    def no_stall():
        need(P.get('m2-b2-win-type2-count', 0) == 0,
             'IO_PAGE_FAULT in the window: %d'
             % P.get('m2-b2-win-type2-count', 0))
        need(P.get('m2-b2-win-devid-mismatch', 0) == 0,
             'the window recorded an event for another device')
        need(bh['outstanding'] == 0,
             'ring still holds %d unfinished descriptors' % bh['outstanding'])
        need(bh['txDirty'] == bh['txNext'],
             'txDirty %d != txNext %d' % (bh['txDirty'], bh['txNext']))
        need(bh['txClose'] == bh['txTail'],
             'close pointer %d != submitted tail %d'
             % (bh['txClose'], bh['txTail']))
        need(bh['state'] == 0, 'driver state at export is %d, not Idle'
             % bh['state'])
        need(bh['liveHandle'] == 0 and not (bh['liveFlags'] & 4),
             'a generation is still owned/pinned at the export')
        need(bh['ringBytes'] == 1024 * bh['ringDescSize'] and bh['ringDescSize'],
             'ring size %d is not 1024 descriptors of %d'
             % (bh['ringBytes'], bh['ringDescSize']))
        return {'ringAddr': hex(bh['ringAddr']), 'outstanding': 0,
                'txNext': bh['txNext'], 'txClose': bh['txClose'],
                'faultEntries': P.get('m2-b2-win-entries', 0),
                'coverCalls': P.get('m2-3c-cover-calls', 0),
                'coverChunks': P.get('m2-3c-cover-chunks', 0),
                'coverPages': P.get('m2-3c-cover-pages', 0),
                'coverLeaves': P.get('m2-3c-cover-leaves', 0),
                'coverPresent': P.get('m2-3c-cover-present', 0)}
    check('tx-ring-quiescent-no-device-page-fault', no_stall)

    # ---- 10. the runtime cover is visible in the exported page table --------
    def cover_visible():
        # An ordinary packet whose pages all sit below the bootstrap limit needs
        # NO new chunk: cover-calls>0 with cover-chunks==0 is the healthy case
        # for a batch that never touched high memory. Only require the export to
        # contain the chunks the probe says it added.
        chunks = identity_high_chunks(pt_blob, dh)
        need(len(chunks) >= P.get('m2-3c-cover-chunks', 0),
             'export has %d high chunks, the probe counted %d new ones'
             % (len(chunks), P.get('m2-3c-cover-chunks', 0)))
        for c in chunks:
            need(c['pa'] == c['chunk'],
                 'chunk %#x maps %#x, not identity' % (c['chunk'], c['pa']))
            need(c['ir'] and c['iw'], 'chunk %#x lacks RW' % c['chunk'])
        need(len(chunks) >= P.get('m2-3c-cover-chunks', 0),
             'export has %d high chunks, the probe counted %d new ones'
             % (len(chunks), P.get('m2-3c-cover-chunks', 0)))
        return {'chunks': [{'chunk': hex(c['chunk']), 'pa': hex(c['pa'])}
                           for c in chunks],
                'probeCoverChunks': P.get('m2-3c-cover-chunks', 0)}
    check('runtime-identity-coverage-visible-in-export', cover_visible)

    # ---- 11. round 22: the window edges ------------------------------------
    #
    # The checks below are the ORDER, not a summary. Round 21 published "gate
    # closed" and "drained" but the real sequence was flip-then-drain, and its
    # exit opened ordinary output before the hardware restore. Both are now
    # refusals in the driver and are checked here against recorded timestamps:
    # every boundary below is stamped by the driver at the event it names.
    ords = _ord_records((cap / 'client.log').read_text(encoding='utf-8',
                                                       errors='replace'))
    ord_peer = {r['seq'] for r in _ord_records(
        (cap / 'peer.log').read_text(encoding='utf-8', errors='replace'))
        if r['kind'] == 'recv'}

    def window_enter_order():
        need(P.get('m2-3e-enter') == 'gate-open-after-dte-and-invalidations',
             'enter did not complete in order: %r' % (P.get('m2-3e-enter'),))
        need(P.get('m2-3e-enter-drain') == 'drained',
             'the old-mapping drain before the DTE flip was not confirmed: %r'
             % (P.get('m2-3e-enter-drain'),))
        need(P.get('m2-3e-enter-last-inflight', 1) == 0,
             'a submission was still admitted when the window opened: %r'
             % (P.get('m2-3e-enter-last-inflight'),))
        need(P.get('m2-3e-enter-last-ring', 1) == 0,
             'the ring was not empty when the window opened: %r'
             % (P.get('m2-3e-enter-last-ring'),))
        t_close = P.get('m2-3e-enter-gate-close') or 0
        t_submit = P.get('m2-3e-enter-submit-done') or 0
        t_drain = P.get('m2-3e-enter-drain-done') or 0
        t_dte = P.get('m2-b2-dma-t-dte-written') or 0
        t_inv = P.get('m2-3e-t-translate-on') or 0
        t_open = P.get('m2-3e-t-gate-open') or 0
        for name, v in (('gate-close', t_close), ('submit-done', t_submit),
                        ('drain-done', t_drain), ('dte-written', t_dte),
                        ('invalidate-complete', t_inv), ('gate-open', t_open)):
            need(v > 0, 'enter boundary %s was not stamped' % name)
        need(t_close <= t_submit <= t_drain,
             'submitters/ring did not settle in order: %d %d %d'
             % (t_close, t_submit, t_drain))
        need(t_drain <= t_dte,
             'the DTE was written before the old-mapping drain finished: '
             '%d > %d' % (t_drain, t_dte))
        need(t_dte <= t_inv <= t_open,
             'admission was reopened before translation was confirmed: '
             '%d %d %d' % (t_dte, t_inv, t_open))
        return {'gateClose': t_close, 'submitDone': t_submit,
                'drainDone': t_drain, 'dteWritten': t_dte,
                'invalidate': t_inv, 'gateOpen': t_open}
    check('window-enter-stopped-before-dte', window_enter_order)

    def window_exit_order():
        need(P.get('m2-3e-exit-drain') == 'drained',
             'exit drain was not confirmed: %r' % (P.get('m2-3e-exit-drain'),))
        need(P.get('m2-3e-exit-last-inflight', 1) == 0,
             'a submission was still admitted at exit: %r'
             % (P.get('m2-3e-exit-last-inflight'),))
        need(P.get('m2-3e-exit-last-ring', 1) == 0,
             'a descriptor was still owned by hardware at exit: %r'
             % (P.get('m2-3e-exit-last-ring'),))
        need(P.get('m2-3e-translate-off') == 'confirmed-by-register-readback',
             'translation-off was not confirmed by register read-back: %r'
             % (P.get('m2-3e-translate-off'),))
        need(P.get('m2-3e-exit-detach') == 'detached',
             'detach was refused: %r' % (P.get('m2-3e-exit-detach'),))
        need(P.get('m2-3e-after-exit') == 'ordinary-output-resumed',
             'ordinary output was not resumed: %r' % (P.get('m2-3e-after-exit'),))
        need(P.get('m2-3b-cleanup') == 'detached-after-restore-confirmed',
             'cleanup token is %r' % (P.get('m2-3b-cleanup'),))
        t_submit = P.get('m2-3e-exit-submit-done') or 0
        t_drain = P.get('m2-3e-exit-drain-done') or 0
        t_off = P.get('m2-3e-t-translate-off') or 0
        t_detach = P.get('m2-3e-t-detach') or 0
        t_resume = P.get('m2-3e-t-resume') or 0
        for name, v in (('submit-done', t_submit), ('drain-done', t_drain),
                        ('translate-off', t_off), ('detach', t_detach),
                        ('resume', t_resume)):
            need(v > 0, 'exit boundary %s was not stamped' % name)
        need(t_submit <= t_drain,
             'submitters did not leave before the drain was judged: %d %d'
             % (t_submit, t_drain))
        need(t_drain <= t_off,
             'translation was stopped while the device still owned descriptors: '
             '%d > %d' % (t_drain, t_off))
        need(t_off <= t_detach,
             'the backend was detached before the restore was confirmed: '
             '%d > %d' % (t_off, t_detach))
        need(t_detach <= t_resume,
             'ordinary output was resumed before the backend was released: '
             '%d > %d' % (t_detach, t_resume))
        return {'submitDone': t_submit, 'drainDone': t_drain,
                'translateOff': t_off, 'detach': t_detach, 'resume': t_resume}
    check('window-exit-drained-then-restored-then-resumed', window_exit_order)

    def ordinary_traffic_proves_the_window():
        # Ordinary traffic is the OTHER half of "the window is real": the
        # selected frames only prove the controlled path. Each probe is a plain
        # UDP payload (not the selected magic), logged with its request id, a
        # SHA-256 of the bytes and both ends' timestamps.
        t_close = P.get('m2-3e-enter-gate-close') or 0
        t_inv = P.get('m2-3e-t-translate-on') or 0
        t_exitq = P.get('m2-3e-exit-gate-close') or 0
        t_resume = P.get('m2-3e-t-resume') or 0
        ok = [r for r in ords if r['kind'] == 'recv' and r.get('ok') == 1 and
              r.get('t', 0) > 0]
        before = [r for r in ok if r['tag'] == 'pre' and r['t'] < t_close]
        during = [r for r in ok if r['tag'] == 'window' and
                  t_inv <= r['t'] <= t_exitq]
        after = [r for r in ok if r['tag'] == 'after-exit' and r['t'] > t_resume]
        need(before, 'no ordinary request/echo completed before the window')
        need(during, 'no ordinary request/echo completed inside the window')
        need(len(after) >= 3,
             'only %d ordinary request/echo pairs completed after the exit'
             % len(after))
        for r in after:
            need(r['seq'] in ord_peer,
                 'peer has no record of ordinary seq %d' % r['seq'])
        need(P.get('m2-3e-after-exit') == 'ordinary-output-resumed',
             'the resume token is missing, so "after" has no meaning')
        return {'before': len(before), 'during': len(during),
                'after': len(after),
                'seqs': [r['seq'] for r in after]}
    check('ordinary-traffic-before-during-after', ordinary_traffic_proves_the_window)

    def exit_sample_is_the_exit():
        # Round 20 published this record from the throttled path, whose signature
        # ignores ring motion; after Disarm restored Idle the signature was
        # unchanged, the publication was skipped, and the archived sample was
        # 9.014 s older than the window end. The record must now say which step
        # produced it, and that step must be the exit.
        need(bh['version'] == 2, 'block is not the round-21 layout')
        need(bh['sampleStage'] == 3,
             'block sampleStage is %r, not kStageExit(3)'
             % (bh['sampleStage'],))
        need(bh['sampleSeq'] > 1,
             'block sampleSeq %r suggests the exit sample never advanced'
             % (bh['sampleSeq'],))
        # The exit sample is taken AFTER the drain and BEFORE the detach, so the
        # gate is legitimately still CLOSED at that instant: that is the state
        # the window closes in. What must hold is that it is not left closed
        # afterwards, which the entry/detach checks cover.
        need(bh['quiesced'] in (0, 1), 'block reports an impossible gate value')
        need(bh['activeCover'] == 0,
             'block reports %r cover calls in flight at exit' % (bh['activeCover'],))
        # The exit sample is taken at the exit step, i.e. before the restore:
        # the resume time must be LATER than the sample, otherwise the record
        # would be describing a state that was already over.
        t_resume = P.get('m2-3e-t-resume') or 0
        need(t_resume > 0, 'resume time was not stamped')
        need(t_resume >= bh['tSample'],
             'the exit sample was taken after ordinary output resumed')
        return {'sampleStage': bh['sampleStage'], 'sampleSeq': bh['sampleSeq'],
                'tSample': bh['tSample'], 'resume': t_resume,
                'activeCover': bh['activeCover']}
    check('exit-sample-taken-at-the-exit-step', exit_sample_is_the_exit)

    def cover_state_confirmed():
        # The two round-20 cover defects must be absent: no capacity failure
        # left a published-but-reusable page (the probe would report a stop
        # reason), and no invalidate failure was followed by a successful cover
        # of the same chunk.
        need(P.get('m2-3c-cover-unconf', 0) == 0,
             'a cover invalidation failure was not confirmed/resolved')
        stop = P.get('m2-3c-cover-stop')
        need(stop in (None, '', 'cover-table-page-budget') or
             P.get('m2-3c-cover-fails', 0) == 0,
             'cover stopped for %r after %r failures'
             % (stop, P.get('m2-3c-cover-fails', 0)))
        # A failing cover must never be followed by a submitted packet using the
        # same addresses, which is what the driver's coverRejects account for.
        rej = drv[0].get('coverRejects', 0) if drv else 0
        return {'coverCalls': P.get('m2-3c-cover-calls'),
                'coverFails': P.get('m2-3c-cover-fails'),
                'coverUnconf': P.get('m2-3c-cover-unconf'),
                'coverRejects': rej}
    check('cover-failure-state-cannot-be-reused', cover_state_confirmed)

    ok = all(c['state'] == 'ok' for c in checks)
    return {'scope': 'round23-multi-inflight-tx-map-retire', 'ok': ok,
            'checks': checks,
            'details': {'accepted': accepted, 'refused': refused,
                        'requests': [walked[r] for r in accepted if r in walked],
                        'probe': {k: P.get(k) for k in sorted(P) if k.startswith('m2-3c-')},
                        'std': {k: sh[k] for k in ('accepts', 'rejects', 'unsupported',
                                                   'unmaps', 'pinned', 'maxHeld', 'count')},
                        'window': {k: P.get(k) for k in sorted(P) if k.startswith('m2-3e-')},
                        'ring': {k: bh[k] for k in ('txNext', 'txDirty', 'txClose',
                                                    'txTail', 'outstanding', 'ringAddr',
                                                    'ringBytes', 'ringDescSize',
                                                    'state', 'liveHandle')},
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
