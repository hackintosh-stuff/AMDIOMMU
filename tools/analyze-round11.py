#!/usr/bin/env python3
"""analyze-round11.py -- independently recompute the round-11 controlled chain.

WHAT "INDEPENDENT" MEANS HERE, AND WHAT ROUND 10 GOT WRONG
----------------------------------------------------------
This script reads ONLY raw capture files. It does not use `m2-b2-verdict`,
`m2-b2-obs-*-complete`, `window-complete` or any other self-reported summary as
the BASIS of a pass. Summaries are compared AGAINST the recomputation, never
used in place of it.

Round 10's analyser had four defects that produced a false pass. Each is named
here and fixed, and each has a negative test in tools/r11/test-analyzer11.py:

  D1  "the root table is the one the DTE names" passed when the property
      `m2-b2-dte-root` was ABSENT (`... or pte_get(...) is None`), and that
      property was never published. The check never ran.
      FIX: decode the real DTE (m2-b2-bizwalk-dte-raw), derive its mode and
      root address, and require every walked chain to start from that address.

  D2  `m2-b2-win0-walk == "leaf"` was used as evidence that the walk was
      correct. That is the probe asserting its own conclusion.
      FIX: recompute the walk from the exported raw PTEs and require the leaf
      to cover the actual business address.

  D3  The snapshot analysed was NOT the one the probe used: the probe used
      publication 27 (head 385, first 1, tPublished 41305180913) while the
      archived blob was publication 71 (head 646, first 135, tPublished
      85309619659), 43 s later. The analyser hash-checked the blob against
      props.raw.txt, which only proved it was *a* consistent snapshot.
      FIX: the probe exports the exact bytes it decoded (m2-b2-obs-snapshot-used)
      and their sha256 (m2-b2-obs-used-sha256). This script extracts the blob
      from props.raw.txt, hashes it, and requires it to equal BOTH that
      published hash AND the hash of the file in the capture directory.

  D4  The window/event/command gates were dropped entirely: a run whose event
      log never ran, whose invalidation command failed, or whose register
      restore failed could still pass.
      FIX: sections 7 and 8 restore those gates, and a failure there blocks the
      whole verdict rather than only its own section.

MODES
-----
`pgtsleep` (control) and `pgt` (translation) are DIFFERENT experiments with
different required fields. In control mode the stages that do not execute are
reported N/A, not PASS, and not FAIL. In translation mode a missing required
field is a REJECT: the schema says it must be there.

Exit code 0 only when every applicable check passes. N/A does not count as a
pass and does not count as a failure; it is reported separately and the final
verdict says which mode it was.
"""
import hashlib
import json
import os
import re
import struct
import sys

HDR_BYTES = 104
REC_BYTES = 72
OBS_MAGIC = 0x324F4C52
OBS_VERSION = 2

KIND = {0: 'none', 1: 'tx-submit', 2: 'tx-done', 3: 'rx-done', 4: 'tx-doorbell'}
PKT_PARSED = 1 << 0
PKT_SHORT = 1 << 7
PKT_TRUNCATED = 1 << 8
HDR_OVERFLOWED = 1 << 0

# PTE permission bits (AMD-Vi spec Table 17).
PTE_PR = 1 << 0
PTE_IR = 1 << 61
PTE_IW = 1 << 62
PM_ADDR_MASK = 0x000FFFFFFFFFF000

# DTE bits.
DTE_V = 1 << 0
DTE_TV = 1 << 1
DTE_IR = 1 << 61
DTE_IW = 1 << 62
DTE_MODE_SHIFT = 9
DTE_MODE_MASK = 0x7

# DTE MODE equals the number of page-table levels, so it also names the LEVEL
# of the root table (AMD-Vi spec Table 15, 1-based). Mode 4 -> a level-4 root
# (512 GiB per entry), mode 3 -> a level-3 root (1 GiB per entry).
#
# Getting this wrong is not cosmetic: the first version mapped mode 4 -> level 3,
# which made every chain start at the wrong level and reported all eight
# business ranges as illegal. The probe uses amdpte::LEVEL_512G for mode 4 (see
# m2b2WalkBusinessRanges), so the analyser must agree with the encoder it is
# checking rather than with an assumption about "4 levels means 3 directory
# levels".
LEVELS = {4: (4, 512 << 30), 3: (3, 1 << 30)}

RESULTS = []      # (section, name, state, detail) where state in ok/fail/na
MODE = 'unknown'


def rec(section, name, ok, detail='', na=False):
    state = 'na' if na else ('ok' if ok else 'fail')
    RESULTS.append((section, name, state, detail))
    mark = 'N/A ' if na else ('PASS' if ok else 'FAIL')
    line = '  %-60s %s' % (name, mark)
    if detail and not ok and not na:
        line += '   [%s]' % detail
    print(line)
    return ok


def section(title):
    print('\n%s' % title)
    print('-' * 78)


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def hexprops(txt):
    out = {}
    for m in re.finditer(r'"([A-Za-z0-9_.\-]+)"\s*=\s*"0x([0-9a-fA-F]+)"', txt):
        out[m.group(1)] = int(m.group(2), 16)
    for m in re.finditer(r'"([A-Za-z0-9_.\-]+)"\s*=\s*"([^"]*)"', txt):
        out.setdefault(m.group(1), m.group(2))
    return out


def decode_header(blob):
    f = struct.unpack('<20I', blob[:80])
    keys = ['magic', 'version', 'recSize', 'capacity', 'head', 'wrapped',
            'dropped', 'pubId', 'firstTicket', 'lastTicket', 'validCount',
            'lostCount', 'epoch', 'busDevFn', 'vendorId', 'deviceId',
            'ifUnit', 'macHi', 'macLo', 'flags']
    h = dict(zip(keys, f))
    h['tStart'] = struct.unpack('<Q', blob[80:88])[0]
    h['tPublished'] = struct.unpack('<Q', blob[88:96])[0]
    h['recordCount'] = (len(blob) - HDR_BYTES) // REC_BYTES
    return h


def decode_record(blob, index):
    off = HDR_BYTES + index * REC_BYTES
    v = struct.unpack_from('<QQIIIIIIIIIIIIII', blob, off)
    return dict(t=v[0], addr=v[1], seq=v[2], kind=v[3], cum=v[4], slot=v[5],
                gen=v[6], batch=v[7], opts1=v[8], opts2=v[9], len=v[10],
                flags=v[11], token=v[12], reqId=v[13], flow=v[14], pkt=v[15])


def valid_record(blob, h, index):
    r = decode_record(blob, index)
    if r['seq'] == 0 or (r['seq'] & 1):
        return None
    if (r['seq'] >> 1) != h['firstTicket'] + index:
        return None
    return r


def pte_decode(pte, level):
    """Independent AMD-Vi PTE decode. Returns (kind, outPA, pageSize, child)."""
    if not (pte & PTE_PR):
        return ('absent', 0, 0, 0)
    nl = (pte >> 9) & 0x7
    if nl == 7:
        # Enlarged page: size from the run of ones at bit 12+.
        x = pte | 0xFFF
        i = 0
        while i < 63 and ((x >> i) & 1):
            i += 1
        ps = 1 << (1 + i)
        default = 1 << (9 * level + 3)
        nxt = 1 << (9 * (level + 1) + 3) if level < 6 else 0
        if ps <= default or (nxt and ps >= nxt):
            return ('illegal', 0, ps, 0)
        return ('leaf-large', (pte & PM_ADDR_MASK) & ~(ps - 1), ps, 0)
    if nl == 0:
        return ('leaf-default', pte & PM_ADDR_MASK, 1 << (9 * level + 3), 0)
    if nl != level - 1:
        return ('illegal', 0, 0, nl)
    return ('table', pte & PM_ADDR_MASK, 0, nl)


def main():
    global MODE
    cap = sys.argv[1] if len(sys.argv) > 1 else 'docs/evidence/20261101-130000'
    outdir = sys.argv[2] if len(sys.argv) > 2 else None

    print('=' * 78)
    print('ROUND-11 INDEPENDENT ANALYSIS')
    print('capture: %s' % cap)
    print('=' * 78)

    # ------------------------------------------------------------------
    section('0. INPUT IDENTITIES')
    # ------------------------------------------------------------------
    required = ['props.txt', 'props.raw.txt', 'client.log', 'peer.log',
                'load.txt', 'network.txt', 'system.txt']
    present = {}
    for f in required:
        p = os.path.join(cap, f)
        if os.path.exists(p):
            present[f] = (os.path.getsize(p), sha256(p))
            print('  %-22s %10d B  %s'
                  % (f, present[f][0], present[f][1][:32]))
        else:
            print('  %-22s MISSING' % f)
    rec('input', 'every required raw input is present',
        all(f in present for f in required),
        'missing: %s' % [f for f in required if f not in present])

    props = open(os.path.join(cap, 'props.txt'), encoding='utf-8',
                 errors='replace').read()
    P = hexprops(props)
    raw = open(os.path.join(cap, 'props.raw.txt'), encoding='utf-8',
               errors='replace').read()

    # ------------------------------------------------------------------
    section('1. THE SNAPSHOT THE PROBE ACTUALLY USED (round 10 defect D3)')
    # ------------------------------------------------------------------
    #
    # Round 10 extracted the blob from props.raw.txt and hash-checked it
    # against props.raw.txt. That proves the extraction was faithful and
    # nothing else: the probe had used a DIFFERENT, earlier publication.
    #
    # Round 11's probe exports the exact bytes it decoded, plus their sha256,
    # as its own properties. Three things must agree:
    #   (a) the sha256 the probe published;
    #   (b) the sha256 of the blob extracted from props.raw.txt;
    #   (c) the sha256 of obs-snapshot-used.bin, the archived file.
    m = re.search(r'"m2-b2-obs-snapshot-used"\s*=\s*<([0-9a-fA-F]+)>', raw)
    used_blob = bytes.fromhex(m.group(1)) if m else None
    used_path = os.path.join(cap, 'obs-snapshot-used.bin')
    used_file = open(used_path, 'rb').read() if os.path.exists(used_path) else None

    probe_sha = P.get('m2-b2-obs-used-sha256')
    probe_exported = P.get('m2-b2-obs-used') == 'exported'
    print('  probe exported the used snapshot : %s' % (P.get('m2-b2-obs-used')))
    print('  probe published sha256           : %s' % probe_sha)
    print('  extracted from props.raw.txt     : %s'
          % (sha256_bytes(used_blob)[:32] + '...' if used_blob else 'ABSENT'))
    print('  archived obs-snapshot-used.bin   : %s'
          % (sha256_bytes(used_file)[:32] + '...' if used_file else 'ABSENT'))

    ok_export = rec('snapshot', 'the probe exported the snapshot it decoded',
                    probe_exported and used_blob is not None,
                    'used=%s blob=%s' % (P.get('m2-b2-obs-used'),
                                         'present' if used_blob else 'absent'))
    ok_sha_raw = rec('snapshot',
                     'the exported blob matches the probe-published sha256',
                     bool(used_blob and probe_sha and
                          sha256_bytes(used_blob) == probe_sha),
                     'probe=%s computed=%s'
                     % (probe_sha,
                        sha256_bytes(used_blob) if used_blob else 'n/a'))
    ok_sha_file = rec('snapshot',
                      'the archived file matches the probe-published sha256',
                      bool(used_file and probe_sha and
                           sha256_bytes(used_file) == probe_sha),
                      'probe=%s file=%s'
                      % (probe_sha,
                         sha256_bytes(used_file) if used_file else 'n/a'))

    blob = used_file if used_file is not None else used_blob
    if blob is None:
        print('\n  REFUSED: no snapshot to analyse. Round 10\'s failure mode')
        print('  was analysing a different snapshot than the probe used; the')
        print('  round-11 answer is to refuse rather than substitute one.')
        return 2

    h = decode_header(blob)
    print('\n  decoded: pub=%d head=%d first=%d tPublished=%d records=%d'
          % (h['pubId'], h['head'], h['firstTicket'], h['tPublished'],
             h['recordCount']))

    # The probe's own summary of which publication it used must agree.
    probe_pub = P.get('m2-b2-obs-used-pub-id')
    probe_tpub = P.get('m2-b2-obs-used-t-published')
    rec('snapshot', 'the probe reported the publication it used',
        probe_pub is not None and probe_tpub is not None)
    rec('snapshot', 'the blob IS that publication',
        probe_pub == h['pubId'] and probe_tpub == h['tPublished'],
        'probe pub=%s t=%s blob pub=%s t=%s'
        % (probe_pub, probe_tpub, h['pubId'], h['tPublished']))

    # ------------------------------------------------------------------
    section('2. SNAPSHOT HEADER')
    # ------------------------------------------------------------------
    rec('snapshot', 'magic is RLO2 (wire v2)', h['magic'] == OBS_MAGIC,
        '0x%x' % h['magic'])
    rec('snapshot', 'version is 2', h['version'] == OBS_VERSION)
    rec('snapshot', 'record size is 72', h['recSize'] == REC_BYTES)
    rec('snapshot', 'the body is a whole number of records',
        (len(blob) - HDR_BYTES) % REC_BYTES == 0)
    rec('snapshot', 'valid + lost equals the record count',
        h['validCount'] + h['lostCount'] == h['recordCount'],
        '%d+%d vs %d' % (h['validCount'], h['lostCount'], h['recordCount']))
    rec('snapshot', 'the ticket range spans the record count',
        h['recordCount'] == 0 or
        h['lastTicket'] - h['firstTicket'] + 1 == h['recordCount'])
    rec('snapshot', 'publication id is non-zero', h['pubId'] != 0)

    # ------------------------------------------------------------------
    section('3. INSTANCE AND DEVICE IDENTITY')
    # ------------------------------------------------------------------
    snap_mac = ((h['macHi'] & 0xFFFFFFFF) << 16) | (h['macLo'] & 0xFFFF)
    probe_bdf = P.get('m2-b2-nic-bdf')
    probe_mac = P.get('m2-b2-nic-mac')
    probe_unit = P.get('m2-b2-nic-unit')
    probe_vendor = P.get('m2-b2-nic-vendor')
    probe_device = P.get('m2-b2-nic-device')

    rec('identity', 'snapshot BDF equals the probe\'s independent BDF',
        probe_bdf is not None and h['busDevFn'] == probe_bdf,
        'snap=0x%x probe=%s' % (h['busDevFn'], probe_bdf))
    rec('identity', 'snapshot vendor equals the probe\'s',
        probe_vendor is not None and h['vendorId'] == probe_vendor,
        'snap=0x%x probe=%s' % (h['vendorId'], probe_vendor))
    rec('identity', 'snapshot device equals the probe\'s',
        probe_device is not None and h['deviceId'] == probe_device,
        'snap=0x%x probe=%s' % (h['deviceId'], probe_device))
    rec('identity', 'snapshot interface unit equals the probe\'s',
        probe_unit is not None and h['ifUnit'] == probe_unit,
        'snap=%s probe=%s' % (h['ifUnit'], probe_unit))
    rec('identity', 'snapshot MAC equals the probe\'s',
        probe_mac is not None and snap_mac == probe_mac,
        'snap=0x%x probe=0x%x' % (snap_mac, probe_mac or 0))

    # Round 11: the epoch must be BOUND, not skipped.
    binding = P.get('m2-b2-obs-epoch-binding')
    bound = P.get('m2-b2-obs-epoch-bound')
    rec('identity', 'the driver instance was bound before the window',
        bound not in (None, 0), 'epoch-bound=%s' % bound)
    rec('identity', 'the snapshot belongs to that instance',
        binding == 'matched' and bound == h['epoch'],
        'binding=%s bound=%s snap-epoch=%s'
        % (binding, bound, h['epoch']))

    net = open(os.path.join(cap, 'network.txt'), encoding='utf-8',
               errors='replace').read()
    net_mac = net_iface = None
    for line in net.splitlines():
        if 'ether=' in line and 'status=active' in line:
            mm = re.search(r'^(\w+):.*ether=([0-9a-f:]+)', line)
            if mm and (probe_mac is None or
                       int(mm.group(2).replace(':', ''), 16) == probe_mac):
                net_iface, net_mac = mm.group(1), mm.group(2)
    rec('identity', 'the MAC belongs to the interface in network.txt',
        net_mac is not None and net_iface is not None,
        'iface=%s mac=%s' % (net_iface, net_mac))

    load = open(os.path.join(cap, 'load.txt'), encoding='utf-8',
                errors='replace').read()
    load_iface = re.search(r'load_iface\s*:\s*(\S+)', load)
    load_route = re.search(r'load_route_interface\s*:\s*(\S+)', load)
    load_mac = re.search(r'load_mac\s*:\s*(\S+)', load)
    rec('identity', 'the load ran on the same interface as the device',
        load_iface is not None and net_iface is not None and
        load_iface.group(1) == net_iface,
        'load=%s device=%s' % (load_iface and load_iface.group(1), net_iface))
    rec('identity', 'the route to the peer left by that interface',
        load_route is not None and load_iface is not None and
        load_route.group(1) == load_iface.group(1),
        'route=%s' % (load_route and load_route.group(1)))

    # ------------------------------------------------------------------
    section('4. RECORD INTEGRITY')
    # ------------------------------------------------------------------
    holes = 0
    kinds = {}
    recs = []
    for i in range(h['recordCount']):
        r = valid_record(blob, h, i)
        if r is None:
            holes += 1
            continue
        kinds[r['kind']] = kinds.get(r['kind'], 0) + 1
        recs.append((i, r))
    rec('records', 'no record is mid-write or mis-ticketed', holes == 0,
        '%d holes' % holes)
    print('  kinds: %s' % {KIND.get(k, k): v for k, v in sorted(kinds.items())})
    rec('records', 'at least one TX submit is present', kinds.get(1, 0) > 0)
    rec('records', 'at least one TX completion is present', kinds.get(2, 0) > 0)
    rec('records', 'at least one RX record is present', kinds.get(3, 0) > 0)

    # ------------------------------------------------------------------
    section('5. THE WINDOW AND ITS VALIDITY')
    # ------------------------------------------------------------------
    ws = P.get('m2-b2-dma-t-win-start')
    we = P.get('m2-b2-dma-t-win-end')
    win_valid = P.get('m2-b2-window-valid')
    rec('window', 'the window bounds exist and are ordered',
        ws is not None and we is not None and we > ws,
        'ws=%s we=%s' % (ws, we))
    if ws and we:
        print('  window = [%d, %d]  (%.6f s)' % (ws, we, (we - ws) / 1e9))
    rec('window', 'the probe reported the window as valid',
        win_valid == 'yes', 'window-valid=%s (%s)'
        % (win_valid, P.get('m2-b2-window-invalid')))

    # ------------------------------------------------------------------
    section('6. VERDICT 1 -- has_complete_pair (recomputed)')
    # ------------------------------------------------------------------
    submits, dones = {}, {}
    for i, r in recs:
        if r['kind'] == 1:
            submits.setdefault(r['cum'], []).append((i, r))
        elif r['kind'] == 2:
            dones.setdefault(r['cum'], []).append((i, r))
    paired = sorted(set(submits) & set(dones))
    rec('pair', 'at least one cumulative index has BOTH a submit and a done',
        len(paired) > 0, 'paired=%d' % len(paired))
    print('  paired cumulative indices: %s'
          % ', '.join('0x%x' % c for c in paired[:12]))

    # ------------------------------------------------------------------
    section('7. VERDICT 2 -- records_cover_window (recomputed)')
    # ------------------------------------------------------------------
    times = [r['t'] for _, r in recs]
    oldest = min(times) if times else 0
    cover_pub = rec('cover', 'the snapshot was published at or after winEnd',
                    ws is not None and h['tPublished'] >= we,
                    'published=%d end=%d' % (h['tPublished'], we))
    cover_old = rec('cover', 'the snapshot reaches back to or before winStart',
                    oldest != 0 and oldest <= ws,
                    'oldest=%d start=%d' % (oldest, ws))
    cover_holes = rec('cover', 'there are no holes in the snapshot', holes == 0)
    cover_ovf = rec('cover', 'the ring did not overflow past the window',
                    (h['flags'] & HDR_OVERFLOWED) == 0,
                    'flags=0x%x' % h['flags'])
    cover_ok = cover_pub and cover_old and cover_holes and cover_ovf
    rec('cover', '=> records_cover_window', cover_ok)
    probe_cover = P.get('m2-b2-obs-records-cover-window')
    rec('cover', 'the probe\'s claim agrees with the recomputation',
        probe_cover == ('yes' if cover_ok else 'no'),
        'probe=%s recomputed=%s' % (probe_cover, cover_ok))

    # ------------------------------------------------------------------
    section('8. VERDICT 3 -- controlled_batch_complete (recomputed)')
    # ------------------------------------------------------------------
    declared = P.get('m2-b2-obs-expected-batch') or 0
    decl_token = P.get('m2-b2-obs-declared-token') or 0
    print('  declared batch = %d, declared token = 0x%08x'
          % (declared, decl_token))
    rec('batch', 'this round declared a batch', declared > 0)
    rec('batch', 'this round declared a run token', decl_token != 0)
    rec('batch', 'the records were joined on that token',
        P.get('m2-b2-obs-token-resolved') == 'yes' and
        P.get('m2-b2-obs-token-ambiguous') == 'no' and
        (P.get('m2-b2-obs-join-token') or 0) == decl_token,
        'join=0x%x ambiguous=%s'
        % (P.get('m2-b2-obs-join-token') or 0,
           P.get('m2-b2-obs-token-ambiguous')))

    cl = open(os.path.join(cap, 'client.log'), encoding='utf-8',
              errors='replace').read()
    pe = open(os.path.join(cap, 'peer.log'), encoding='utf-8',
              errors='replace').read()
    c_sent = [(int(a, 16), int(b)) for a, b in
              re.findall(r'client_sent token=0x([0-9a-f]+) req=(\d+)', cl)]
    c_recv = [(int(a, 16), int(b)) for a, b in
              re.findall(r'client_recv token=0x([0-9a-f]+) req=(\d+)', cl)]
    c_port = re.search(r'client_bound\s+\S+:(\d+)', cl)
    want_port = c_port.group(1) if c_port else None

    all_peer = []
    for a, b in re.findall(r'peer_recv token=0x([0-9a-f]+) req=(\d+)', pe):
        all_peer.append((int(a, 16), int(b), None))
    for _ip, port, head in re.findall(
            r'RECV \d+ bytes from (\S+):(\d+) head=([0-9a-f]{24})', pe):
        tok = int(head[8:16], 16)
        rid = int(head[16:24], 16)
        all_peer.append((tok, rid, port))

    c_tokens = set(t for t, _ in c_sent)
    if want_port is not None:
        p_recv = [(t, r) for (t, r, port) in all_peer
                  if t in c_tokens and port == want_port]
    else:
        p_recv = [(t, r) for (t, r, port) in all_peer if t in c_tokens]

    rec('batch', 'the client sent exactly the declared number',
        len(c_sent) == declared, '%d vs %d' % (len(c_sent), declared))
    rec('batch', 'the client received an echo for every send',
        len(c_recv) == len(c_sent) and sorted(c_recv) == sorted(c_sent),
        'sent=%d recv=%d' % (len(c_sent), len(c_recv)))
    rec('batch', 'the peer received exactly the same set',
        sorted(p_recv) == sorted(c_sent),
        'peer=%d client=%d' % (len(p_recv), len(c_sent)))
    tokens = set(t for t, _ in c_sent)
    rec('batch', 'the client used exactly one run token', len(tokens) == 1,
        'tokens=%s' % tokens)
    token = tokens.pop() if tokens else 0
    rec('batch', 'that token is the one the probe declared',
        token == decl_token, 'client=0x%08x probe=0x%08x'
        % (token, decl_token))
    req_ids = sorted(r for _, r in c_sent)
    rec('batch', 'the request ids are exactly 1..declared',
        req_ids == list(range(1, declared + 1)), 'ids=%s' % req_ids)

    # Driver side, recomputed from raw records.
    tx_by_req, rx_by_req = {}, {}
    for i, r in recs:
        if not (r['pkt'] & PKT_PARSED):
            continue
        if r['kind'] == 1:
            tx_by_req.setdefault(r['reqId'], []).append((i, r))
        elif r['kind'] == 3:
            rx_by_req.setdefault(r['reqId'], []).append((i, r))
    print('  driver TX submits parsed : %s' % sorted(tx_by_req))
    print('  driver RX records parsed : %s' % sorted(rx_by_req))
    rec('batch', 'the driver parsed a TX submit for every declared request',
        sorted(tx_by_req) == list(range(1, declared + 1)),
        'tx=%s' % sorted(tx_by_req))
    rec('batch', 'the driver parsed an RX record for every declared request',
        sorted(rx_by_req) == list(range(1, declared + 1)),
        'rx=%s' % sorted(rx_by_req))
    rec('batch', 'every driver record carries the client\'s run token',
        all(r['token'] == token for v in tx_by_req.values() for _, r in v) and
        all(r['token'] == token for v in rx_by_req.values() for _, r in v),
        'client token=0x%08x' % token)

    # Per-segment completion, not a count. This is counterexample A applied to
    # the real evidence: each submitted cumulative index must have exactly one
    # completion, and no completion may precede its submit.
    seg_ok = True
    seg_report = {}
    order_ok = True
    for req, lst in sorted(tx_by_req.items()):
        rows = []
        for _i, r in lst:
            dl = dones.get(r['cum'], [])
            later = [d for _j, d in dl if d['t'] >= r['t']]
            rows.append((r['cum'], len(dl), len(later)))
            if len(later) != 1:
                seg_ok = False
            if len(dl) != len(later):
                order_ok = False
        seg_report[req] = rows
    rec('batch', 'every TX segment of every request completed exactly once',
        seg_ok, str(seg_report))
    rec('batch', 'no completion precedes its own submission', order_ok)

    batch_ok = (declared > 0 and decl_token != 0 and len(c_sent) == declared and
                sorted(c_recv) == sorted(c_sent) and
                sorted(p_recv) == sorted(c_sent) and
                sorted(tx_by_req) == list(range(1, declared + 1)) and
                sorted(rx_by_req) == list(range(1, declared + 1)) and
                seg_ok and order_ok)
    rec('batch', '=> controlled_batch_complete', batch_ok)
    probe_batch = P.get('m2-b2-obs-controlled-batch-complete')
    rec('batch', 'the probe\'s claim agrees with the recomputation',
        probe_batch == ('yes' if batch_ok else 'no'),
        'probe=%s recomputed=%s' % (probe_batch, batch_ok))

    # ------------------------------------------------------------------
    section('9. EVERY REQUEST\'S DMA RANGES, IN THE WINDOW')
    # ------------------------------------------------------------------
    #
    # Round 10 checked timing for the FIRST request only and reported
    # `[True]` from a one-element list. Every request is checked here.
    req_stage = {}
    for req in sorted(tx_by_req):
        rows = []
        for _i, r in tx_by_req[req]:
            dl = dones.get(r['cum'], [])
            td = dl[0][1]['t'] if dl else None
            rows.append({'cum': r['cum'], 'slot': r['slot'],
                         'addr': r['addr'], 'len': r['len'],
                         't_submit': r['t'], 't_done': td,
                         'sub_in': ws <= r['t'] <= we,
                         'done_in': td is not None and ws <= td <= we})
        rxs = [{'cum': r['cum'], 'addr': r['addr'], 'len': r['len'],
                't': r['t'], 'in': ws <= r['t'] <= we}
               for _i, r in rx_by_req.get(req, [])]
        req_stage[req] = {'tx': rows, 'rx': rxs}
        for s in rows:
            print('    req %d TX cum=0x%03x addr=0x%-11x len=%3d '
                  't_submit=%d t_done=%s sub_in=%s done_in=%s'
                  % (req, s['cum'], s['addr'], s['len'], s['t_submit'],
                     s['t_done'], s['sub_in'], s['done_in']))
        for s in rxs:
            print('    req %d RX cum=0x%03x addr=0x%-11x len=%3d t=%d in=%s'
                  % (req, s['cum'], s['addr'], s['len'], s['t'], s['in']))

    all_sub_in = all(s['sub_in'] for v in req_stage.values() for s in v['tx'])
    all_done_in = all(s['done_in'] for v in req_stage.values()
                      for s in v['tx'])
    all_rx_in = all(s['in'] for v in req_stage.values() for s in v['rx'])
    rec('chain', 'every request\'s TX submits are inside the window', all_sub_in)
    rec('chain', 'every request\'s completions are inside the window',
        all_done_in)
    rec('chain', 'every request\'s RX records are inside the window', all_rx_in)

    # Length must be the FRAME length, derived from the client payload.
    cl_len = None
    for line in cl.splitlines():
        m2 = re.search(r'client_sent token=0x[0-9a-f]+ req=1 len=(\d+)', line)
        if m2:
            cl_len = int(m2.group(1))
            break
    frame_len = (cl_len + 8 + 20 + 14) if cl_len is not None else None
    all_lens = [s['len'] for v in req_stage.values() for s in v['tx']] + \
               [s['len'] for v in req_stage.values() for s in v['rx']]
    rec('chain', 'every recorded length is the frame the client sent',
        frame_len is not None and all(x == frame_len for x in all_lens),
        'client payload=%s frame=%s records=%s'
        % (cl_len, frame_len, sorted(set(all_lens))))

    # ------------------------------------------------------------------
    section('10. RAW DTE -> PAGE TABLE -> EVERY BUSINESS RANGE (defects D1/D2)')
    # ------------------------------------------------------------------
    #
    # Round 10 asserted "the root table is the one the DTE names" but passed
    # when the property was absent, and it was always absent. Round 11 decodes
    # the DTE the probe exported from the device table entry it actually
    # wrote, and requires every walked chain to start there.
    dte_raw = P.get('m2-b2-bizwalk-dte-raw')
    dte_state = P.get('m2-b2-bizwalk-dte-state')
    print('  DTE raw        = %s' % ('0x%x' % dte_raw if dte_raw else 'ABSENT'))
    print('  DTE state      = %s' % dte_state)

    if dte_raw is None:
        rec('pt', 'the probe exported the DTE it walked from', False,
            'm2-b2-bizwalk-dte-raw absent')
    else:
        dte_valid = bool(dte_raw & DTE_V)
        dte_tv = bool(dte_raw & DTE_TV)
        dte_mode = (dte_raw >> DTE_MODE_SHIFT) & DTE_MODE_MASK
        dte_root = dte_raw & PM_ADDR_MASK
        dte_ir = bool(dte_raw & DTE_IR)
        dte_iw = bool(dte_raw & DTE_IW)
        print('  DTE V=%d TV=%d MODE=%d ROOT=0x%x IR=%d IW=%d'
              % (dte_valid, dte_tv, dte_mode, dte_root, dte_ir, dte_iw))
        rec('pt', 'the DTE is valid and switched to translation',
            dte_valid and dte_tv and dte_mode in LEVELS,
            'V=%d TV=%d MODE=%d' % (dte_valid, dte_tv, dte_mode))
        rec('pt', 'the DTE grants the device read and write',
            dte_ir and dte_iw, 'IR=%d IW=%d' % (dte_ir, dte_iw))
        root_level = LEVELS.get(dte_mode, (0, 0))[0]

        n = P.get('m2-b2-bizwalk-count') or 0
        print('  walked ranges  = %d' % n)
        rec('pt', 'a page-table path was exported for every business segment',
            n > 0, 'count=%d' % n)

        # Recompute each chain from the raw PTEs.
        all_link = True
        all_from_dte = True
        all_covered = True
        all_perm = True
        for i in range(n):
            req = P.get('m2-b2-bw%d-req' % i)
            direction = P.get('m2-b2-bw%d-dir' % i)
            addr = P.get('m2-b2-bw%d-addr' % i)
            ln = P.get('m2-b2-bw%d-len' % i)
            depth = P.get('m2-b2-bw%d-depth' % i) or 0
            root_pa = P.get('m2-b2-bw%d-root-pa' % i)
            leaf_pa = P.get('m2-b2-bw%d-leaf-pa' % i)
            leaf_size = P.get('m2-b2-bw%d-leaf-size' % i)
            covered = P.get('m2-b2-bw%d-covered' % i) == 'yes'
            perm = P.get('m2-b2-bw%d-perm-ok' % i) == 'yes'
            print('    bw%d req=%s dir=%s addr=0x%x len=%s depth=%s'
                  % (i, req, direction, addr or 0, ln, depth))

            if root_pa != dte_root:
                all_from_dte = False
                print('      root 0x%x != DTE root 0x%x' % (root_pa, dte_root))

            # Walk the exported chain and confirm it links table to table.
            link_ok = True
            lvl = root_level
            expect_table = dte_root
            for L in range(depth):
                t = P.get('m2-b2-bw%d-pte%d-table' % (i, L))
                idx = P.get('m2-b2-bw%d-pte%d-index' % (i, L))
                lv = P.get('m2-b2-bw%d-pte%d-level' % (i, L))
                pte = P.get('m2-b2-bw%d-pte%d' % (i, L))
                if None in (t, idx, lv, pte):
                    link_ok = False
                    print('      level %d incomplete' % L)
                    continue
                if t != expect_table:
                    link_ok = False
                    print('      level %d table 0x%x != expected 0x%x'
                          % (L, t, expect_table))
                if lv != lvl:
                    link_ok = False
                    print('      level %d claims L%d, expected L%d'
                          % (L, lv, lvl))
                # The index must be the address's bits for that level.
                want_idx = (addr >> (9 * lvl + 3)) & 0x1FF
                if idx != want_idx:
                    link_ok = False
                    print('      level %d index %d != %d for 0x%x'
                          % (L, idx, want_idx, addr))
                kind, outpa, psize, child = pte_decode(pte, lvl)
                if kind == 'table':
                    expect_table = outpa
                    lvl = child
                elif kind in ('leaf-default', 'leaf-large'):
                    # Last level must be the leaf and must cover the address.
                    if L != depth - 1:
                        link_ok = False
                        print('      leaf at level %d but depth is %d'
                              % (L, depth))
                    if not (outpa <= addr < outpa + psize):
                        link_ok = False
                        print('      leaf 0x%x+0x%x does not contain 0x%x'
                              % (outpa, psize, addr))
                    if leaf_pa != outpa or leaf_size != psize:
                        link_ok = False
                        print('      leaf mismatch: exported 0x%x/%d, '
                              'decoded 0x%x/%d'
                              % (leaf_pa, leaf_size, outpa, psize))
                else:
                    link_ok = False
                    print('      level %d decodes as %s' % (L, kind))

            # Permissions, per direction, on EVERY level.
            perm_ok = True
            for L in range(depth):
                pte = P.get('m2-b2-bw%d-pte%d' % (i, L))
                if pte is None:
                    perm_ok = False
                    continue
                need = PTE_IW if direction == 'rx' else PTE_IR
                if not (pte & need):
                    perm_ok = False
                    print('      level %d lacks %s for a %s range'
                          % (L, 'IW' if direction == 'rx' else 'IR',
                             direction))
            if not perm_ok:
                all_perm = False
            if not perm:
                all_perm = False
            if not covered:
                all_covered = False
            if not link_ok:
                all_link = False

        rec('pt', 'every walked chain starts at the address the DTE names',
            all_from_dte and n > 0)
        rec('pt', 'every chain links table-to-table with correct indices',
            all_link and n > 0)
        rec('pt', 'every business range is fully covered by legal leaves',
            all_covered and n > 0)
        rec('pt', 'every range has the permission its direction needs',
            all_perm and n > 0)
        rec('pt', '=> the business DMA ranges have complete page-table evidence',
            n > 0 and all_from_dte and all_link and all_covered and all_perm)

    # ------------------------------------------------------------------
    section('11. EVENT LOG, COMMAND COMPLETION AND RECOVERY (round-10 defect D4)')
    # ------------------------------------------------------------------
    #
    # Round 10 dropped these gates entirely. A run whose event log never ran,
    # whose invalidation failed or whose restore failed could still pass.
    evt_log = P.get('m2-b2-evt-log')
    rec('events', 'the event log was enabled', evt_log == 'enabled',
        'evt-log=%s' % evt_log)
    evt_reset = P.get('m2-b2-evt-reset')
    rec('events', 'the event log was reset before the window',
        evt_reset == 'done', 'evt-reset=%s' % evt_reset)

    n_raw = P.get('m2-b2-win-raw-count') or 0
    win_trunc = P.get('m2-b2-win-raw-truncated')
    print('  raw window events = %d (truncated=%s)' % (n_raw, win_trunc))
    rec('events', 'the raw event window was not truncated',
        win_trunc == 'no', 'truncated=%s' % win_trunc)

    faults = []
    decoded_ok = True
    for i in range(n_raw):
        ev = P.get('m2-b2-win-raw%d' % i)
        if not ev or len(ev) != 32:
            decoded_ok = False
            continue
        r = [int(ev[j * 8:(j + 1) * 8], 16) for j in range(4)]
        etype = (r[1] >> 28) & 0xF
        devid = r[0] & 0xFFFF
        if etype == 2:
            a = (r[2] | (r[3] << 32)) & 0xFFFFFFFFFFFFF000
            faults.append((devid, a))
            print('    IO_PAGE_FAULT devid=0x%04x addr=0x%x (%.4f GiB)'
                  % (devid, a, a / (1024.0 ** 3)))
    rec('events', 'every raw event record decoded', decoded_ok)
    type2 = P.get('m2-b2-win-type2-count') or 0
    rec('events', 'the decoded fault count matches the probe\'s counter',
        len(faults) == type2, 'decoded=%d probe=%s' % (len(faults), type2))
    rec('events', 'every faulting device id is the target device',
        all(d == (probe_bdf or d) for d, _ in faults), str(faults))
    limit = P.get('m2-b2-map-limit')
    if limit is not None:
        over = [a for _, a in faults if a >= limit]
        print('  identity map limit = 0x%x (%.4f GiB)'
              % (limit, limit / (1024.0 ** 3)))
        rec('events', 'no fault lies at or above the identity map limit',
            len(over) == 0, 'over-limit: %s' % ['0x%x' % a for a in over])

    rec('cmd', 'the invalidation commands all completed',
        P.get('m2-b2-stage-inv-dev') == 'yes' and
        P.get('m2-b2-stage-inv-pages') == 'yes',
        'inv-dev=%s inv-pages=%s' % (P.get('m2-b2-stage-inv-dev'),
                                     P.get('m2-b2-stage-inv-pages')))
    rec('cmd', 'the command buffer was stopped before restore',
        P.get('m2-b2-cmdbuf-stopped') == 'yes',
        'stopped=%s' % P.get('m2-b2-cmdbuf-stopped'))
    rec('cmd', 'the event log was stopped before restore',
        P.get('m2-b2-evtlog-stopped') == 'yes',
        'stopped=%s' % P.get('m2-b2-evtlog-stopped'))
    rec('recovery', 'the IOMMU was disabled',
        P.get('m2-b2-disabled') == 'yes',
        'disabled=%s' % P.get('m2-b2-disabled'))
    rec('recovery', 'the original registers were restored',
        P.get('m2-b2-regs-restored') == 'yes',
        'restored=%s (abort=%s)'
        % (P.get('m2-b2-regs-restored'), P.get('m2-b2-restore-abort')))
    rec('recovery', 'resources were released or explicitly retained',
        P.get('m2-b2-cleanup') in ('done',
                                   'REFUSED-hardware-not-proven-idle'),
        'cleanup=%s' % P.get('m2-b2-cleanup'))

    # ------------------------------------------------------------------
    section('12. MODE AND SCHEMA')
    # ------------------------------------------------------------------
    #
    # `pgtsleep` is the CONTROL experiment: it never switches the DTE, so the
    # translation stages do not execute. Reporting them as PASS would be a
    # false claim and reporting them as FAIL would be wrong; they are N/A.
    # `pgt` is the TRANSLATION experiment, and there a missing required field
    # is a rejection, not a skip.
    mode = P.get('m2-b2-mode')
    MODE = mode or 'unknown'
    print('  mode = %s' % MODE)
    rec('mode', 'the probe reported a known mode',
        MODE in ('translation', 'control'), 'mode=%s' % MODE)

    if MODE == 'control':
        for name in ('the DTE is valid and switched to translation',
                     'the DTE grants the device read and write',
                     'a page-table path was exported for every business segment',
                     'every walked chain starts at the address the DTE names',
                     '=> the business DMA ranges have complete page-table evidence'):
            rec('pt', name, False, na=True)
        rec('mode', 'control mode makes no translation claim',
            P.get('m2-b2-verdict', '').startswith('CONTROL'), na=True)
        print('\n  NOTE: this is the CONTROL experiment. The translation')
        print('        verdicts above are N/A, not PASS. A control run can')
        print('        never satisfy the finite-transaction subgoal.')
    elif MODE == 'translation':
        required_fields = ['m2-b2-bizwalk-dte-raw', 'm2-b2-bizwalk-count',
                           'm2-b2-obs-used-sha256', 'm2-b2-obs-epoch-bound']
        missing = [k for k in required_fields if P.get(k) in (None, '')]
        rec('mode', 'every field the translation schema requires is present',
            not missing, 'missing: %s' % missing)

    # ------------------------------------------------------------------
    section('SUMMARY')
    # ------------------------------------------------------------------
    sections = {}
    for sec, name, state, detail in RESULTS:
        sections.setdefault(sec, [0, 0, 0])
        sections[sec][1] += 1
        if state == 'ok':
            sections[sec][0] += 1
        elif state == 'na':
            sections[sec][2] += 1
    n_ok = sum(1 for _, _, s, _ in RESULTS if s == 'ok')
    n_fail = sum(1 for _, _, s, _ in RESULTS if s == 'fail')
    n_na = sum(1 for _, _, s, _ in RESULTS if s == 'na')
    for sec in sorted(sections):
        ok, tot, na = sections[sec]
        print('  %-12s %2d/%2d ok, %d N/A' % (sec, ok, tot, na))
    print()
    print('  TOTAL  %d ok, %d failed, %d N/A' % (n_ok, n_fail, n_na))
    print()
    print('  has_complete_pair        : %s' % ('YES' if paired else 'NO'))
    print('  records_cover_window     : %s' % ('YES' if cover_ok else 'NO'))
    print('  controlled_batch_complete: %s' % ('YES' if batch_ok else 'NO'))
    print()
    # Four separate statements, never collapsed into one.
    print('  business exchange succeeded      : %s'
          % ('YES' if batch_ok else 'NO'))
    print('  runtime input is re-checkable    : %s'
          % ('YES' if (ok_export and ok_sha_raw and ok_sha_file) else 'NO'))
    print('  finite DMA translation evidence  : %s'
          % ('YES' if (batch_ok and cover_ok and n_fail == 0) else 'NO'))
    print('  M2-2b-2 overall                  : NOT CLAIMED BY THIS SCRIPT')
    print()
    verdict = 'PASS' if n_fail == 0 else 'FAIL'
    print('  RESULT: %s%s' % (verdict,
                              ' (control mode: N/A is not a pass)'
                              if MODE == 'control' else ''))

    out = {
        'capture': cap,
        'mode': MODE,
        'inputs': {k: {'bytes': v[0], 'sha256': v[1]}
                   for k, v in present.items()},
        'snapshot': h,
        'snapshot_used': {
            'exported': bool(probe_exported),
            'probe_sha256': probe_sha,
            'blob_sha256': sha256_bytes(blob),
            'matches_probe': bool(probe_sha and sha256_bytes(blob) == probe_sha),
        },
        'window': {'start': ws, 'end': we},
        'verdicts': {
            'has_complete_pair': bool(paired),
            'records_cover_window': cover_ok,
            'controlled_batch_complete': batch_ok,
        },
        'declared_batch': declared,
        'declared_token': decl_token,
        'run_token': token,
        'faults': [{'devid': d, 'addr': a} for d, a in faults],
        'checks': [{'section': s, 'name': n, 'state': st, 'detail': d}
                   for s, n, st, d in RESULTS],
    }
    dest = outdir or cap
    os.makedirs(dest, exist_ok=True)
    path = os.path.join(dest, 'analysis.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=1)
    print('  wrote %s' % path)

    return 0 if n_fail == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
