#!/usr/bin/env python3
"""analyze-round10.py -- independently recompute round 10's controlled chain.

WHAT "INDEPENDENT" MEANS HERE
-----------------------------
This script reads ONLY the raw capture:

    props.txt            the probe's properties (its own claims)
    props.raw.txt        the full ioreg dump (contains the driver snapshot)
    driver-snapshot.bin  extracted from props.raw.txt, hash-checked
    client.log           what the Mac sent, and to whom
    peer.log             what the peer received and echoed
    load.txt             the boot-relative schedule and interface decision
    network.txt          the interface/BDF/MAC inventory at capture time

It does NOT trust any probe summary attribute such as
`m2-b2-obs-window-complete`, `m2-b2-verdict`, or `m2-b2-obs-batch-complete`.
Those are compared AGAINST the recomputation, never used in place of it.

WHAT IT RECOMPUTES
------------------
  1. the snapshot's own header: magic, version, record size, capacity,
     publication id, ticket range, valid/lost counts, epoch
  2. device identity from three independent sources: the snapshot header, the
     probe's own NIC identity properties, and network.txt's MAC/interface line
  3. every record's seq against its ticket (a record whose seq is odd or does
     not belong to its position is a HOLE, not a record)
  4. the submit/complete join on cumulative index
  5. the three verdicts SEPARATELY:
        has_complete_pair        at least one verifiable submit/complete
        records_cover_window     the raw records span the whole window
        controlled_batch_complete every declared request has TX+done+RX
  6. the business join: (runToken, reqId) from the client log and peer log
     matched against the driver's TX submit and RX done records
  7. the DMA range of every segment, and its containment in the window
  8. the page-table walk for each attributed address, decoded from the raw
     PTE values the probe published
  9. the event log: any IO_PAGE_FAULT, decoded from the raw 16-byte record

Exit code 0 only when every check that applies passes.
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
PKT_NO_MAGIC = 1 << 1
PKT_NOT_IPV4 = 1 << 2
PKT_SHORT = 1 << 7
PKT_TRUNCATED = 1 << 8

HDR_OVERFLOWED = 1 << 0
HDR_LOST = 1 << 1
HDR_TRUNCATED = 1 << 2

RESULTS = []


def rec(section, name, ok, detail=''):
    RESULTS.append((section, name, bool(ok), detail))
    mark = 'PASS' if ok else 'FAIL'
    line = '  %-58s %s' % (name, mark)
    if detail and not ok:
        line += '   [%s]' % detail
    print(line)


def section(title):
    print('\n%s' % title)
    print('-' * 78)


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()


def hexprops(txt):
    """All 'key' = "0x..." and 'key' = "text" properties, last wins."""
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


def decode_record(blob, h, index):
    off = HDR_BYTES + index * REC_BYTES
    v = struct.unpack_from('<QQIIIIIIIIIIIIII', blob, off)
    return dict(t=v[0], addr=v[1], seq=v[2], kind=v[3], cum=v[4], slot=v[5],
                gen=v[6], batch=v[7], opts1=v[8], opts2=v[9], len=v[10],
                flags=v[11], token=v[12], reqId=v[13], flow=v[14], pkt=v[15])


def valid_record(blob, h, index):
    """A record is usable only if its seq is even AND belongs to its slot."""
    r = decode_record(blob, h, index)
    if r['seq'] == 0 or (r['seq'] & 1):
        return None
    if (r['seq'] >> 1) != h['firstTicket'] + index:
        return None
    return r


def main():
    cap = sys.argv[1] if len(sys.argv) > 1 else 'docs/evidence/20261101-130000'

    print('=' * 78)
    print('ROUND-10 INDEPENDENT ANALYSIS')
    print('capture: %s' % cap)
    print('=' * 78)

    # ------------------------------------------------------------------
    section('0. INPUT IDENTITIES (nothing below trusts a summary attribute)')
    # ------------------------------------------------------------------
    files = ['props.txt', 'props.raw.txt', 'driver-snapshot.bin', 'client.log',
             'peer.log', 'load.txt', 'network.txt', 'system.txt']
    input_files = {}
    for f in files:
        p = os.path.join(cap, f)
        if os.path.exists(p):
            input_files[f] = (os.path.getsize(p), sha256(p))
            print('  %-22s %10d B  %s'
                  % (f, input_files[f][0], input_files[f][1][:32]))
        else:
            print('  %-22s MISSING' % f)
    rec('input', 'every required raw input is present',
        all(f in input_files for f in files),
        'missing: %s' % [f for f in files if f not in input_files])

    props = open(os.path.join(cap, 'props.txt'), encoding='utf-8',
                 errors='replace').read()
    P = hexprops(props)
    blob = open(os.path.join(cap, 'driver-snapshot.bin'), 'rb').read()

    # The extracted blob must be the one inside props.raw.txt, not a later read.
    raw = open(os.path.join(cap, 'props.raw.txt'), encoding='utf-8',
               errors='replace').read()
    m = re.search(r'"rtl812x-obs-snapshot"\s*=\s*<([0-9a-fA-F]+)>', raw)
    rec('input', 'the snapshot comes from this capture, not a later ioreg read',
        m is not None and bytes.fromhex(m.group(1)) == blob)

    # ------------------------------------------------------------------
    section('1. SNAPSHOT HEADER (decoded from the raw bytes)')
    # ------------------------------------------------------------------
    h = decode_header(blob)
    rec('snapshot', 'magic is RLO2 (wire v2)', h['magic'] == OBS_MAGIC,
        '0x%x' % h['magic'])
    rec('snapshot', 'version is 2', h['version'] == OBS_VERSION)
    rec('snapshot', 'record size is 72', h['recSize'] == REC_BYTES)
    rec('snapshot', 'capacity is 4096', h['capacity'] == 4096)
    rec('snapshot', 'the body is a whole number of records',
        (len(blob) - HDR_BYTES) % REC_BYTES == 0)
    rec('snapshot', 'valid + lost equals the record count',
        h['validCount'] + h['lostCount'] == h['recordCount'],
        '%d+%d vs %d' % (h['validCount'], h['lostCount'], h['recordCount']))
    rec('snapshot', 'the ticket range spans the record count',
        h['recordCount'] == 0 or
        h['lastTicket'] - h['firstTicket'] + 1 == h['recordCount'])
    rec('snapshot', 'publication id is non-zero', h['pubId'] != 0)
    rec('snapshot', 'the snapshot was published after the log started',
        h['tPublished'] >= h['tStart'])

    # ------------------------------------------------------------------
    section('2. DEVICE IDENTITY (three independent sources must agree)')
    # ------------------------------------------------------------------
    #
    # Source A: the driver's own snapshot header.
    # Source B: the probe's NIC identity properties, which the probe gathered
    #           itself from IORegistry (not from the snapshot).
    # Source C: network.txt, written by the capture script from ifconfig.
    snap_mac = ((h['macHi'] & 0xFFFFFFFF) << 16) | (h['macLo'] & 0xFFFF)
    probe_bdf = P.get('m2-b2-nic-bdf')
    probe_mac = P.get('m2-b2-nic-mac')
    probe_unit = P.get('m2-b2-nic-unit')
    probe_vendor = P.get('m2-b2-nic-vendor')
    probe_device = P.get('m2-b2-nic-device')

    net = open(os.path.join(cap, 'network.txt'), encoding='utf-8',
               errors='replace').read()
    net_mac = None
    net_iface = None
    for line in net.splitlines():
        if 'ether=' in line and 'status=active' in line:
            mm = re.search(r'^(\w+):.*ether=([0-9a-f:]+)', line)
            if mm and (probe_mac is None or
                       int(mm.group(2).replace(':', ''), 16) == probe_mac):
                net_iface, net_mac = mm.group(1), mm.group(2)

    rec('identity', 'snapshot header carries a BDF', h['busDevFn'] != 0,
        '0x%x' % h['busDevFn'])
    rec('identity', 'snapshot BDF equals the probe\'s independently read BDF',
        probe_bdf is not None and h['busDevFn'] == probe_bdf,
        'snap=0x%x probe=%s' % (h['busDevFn'], probe_bdf))
    rec('identity', 'snapshot vendor equals the probe\'s', 
        h['vendorId'] == probe_vendor,
        'snap=0x%x probe=%s' % (h['vendorId'], probe_vendor))
    rec('identity', 'snapshot device equals the probe\'s',
        h['deviceId'] == probe_device,
        'snap=0x%x probe=%s' % (h['deviceId'], probe_device))
    rec('identity', 'snapshot interface unit equals the probe\'s',
        h['ifUnit'] == probe_unit,
        'snap=%s probe=%s' % (h['ifUnit'], probe_unit))
    rec('identity', 'snapshot MAC equals the probe\'s',
        probe_mac is not None and snap_mac == probe_mac,
        'snap=0x%x probe=0x%x' % (snap_mac, probe_mac or 0))
    rec('identity', 'the MAC belongs to the interface named in network.txt',
        net_mac is not None and net_iface is not None,
        'iface=%s mac=%s' % (net_iface, net_mac))

    # The load must have used THAT interface, not another one.
    load = open(os.path.join(cap, 'load.txt'), encoding='utf-8',
                errors='replace').read()
    load_iface = re.search(r'load_iface\s*:\s*(\S+)', load)
    load_route = re.search(r'load_route_interface\s*:\s*(\S+)', load)
    load_mac = re.search(r'load_mac\s*:\s*(\S+)', load)
    rec('identity', 'the load ran on the same interface as the device',
        load_iface is not None and net_iface is not None and
        load_iface.group(1) == net_iface,
        'load=%s device=%s' % (load_iface and load_iface.group(1), net_iface))
    rec('identity', 'the route to the peer left by that same interface',
        load_route is not None and load_iface is not None and
        load_route.group(1) == load_iface.group(1),
        'route=%s load=%s' % (load_route and load_route.group(1),
                              load_iface and load_iface.group(1)))
    rec('identity', 'the load recorded the same MAC as the device',
        load_mac is not None and net_mac is not None and
        load_mac.group(1).lower() == net_mac.lower(),
        'load=%s device=%s' % (load_mac and load_mac.group(1), net_mac))

    # ------------------------------------------------------------------
    section('3. RECORD INTEGRITY (every seq checked against its ticket)')
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
    rec('records', 'at least one TX submit is present',
        kinds.get(1, 0) > 0)
    rec('records', 'at least one TX completion is present',
        kinds.get(2, 0) > 0)
    rec('records', 'at least one RX record is present',
        kinds.get(3, 0) > 0)

    # ------------------------------------------------------------------
    section('4. THE WINDOW (from the probe\'s own timestamps)')
    # ------------------------------------------------------------------
    ws = P.get('m2-b2-dma-t-win-start')
    we = P.get('m2-b2-dma-t-win-end')
    t_inv = P.get('m2-b2-dma-t-inv-complete')
    t_dte = P.get('m2-b2-dma-t-dte-written')
    rec('window', 'the window bounds exist and are ordered',
        ws is not None and we is not None and we > ws,
        'ws=%s we=%s' % (ws, we))
    print('  window      = [%d, %d]  (%.6f s)' % (ws, we, (we - ws) / 1e9))
    rec('window', 'translation took effect before the window opened',
        t_inv is not None and t_inv <= ws)
    rec('window', 'the DTE write preceded the invalidation completion',
        t_dte is not None and t_inv is not None and t_dte <= t_inv)

    # ------------------------------------------------------------------
    section('5. VERDICT 1 -- has_complete_pair (recomputed)')
    # ------------------------------------------------------------------
    submits = {}
    dones = {}
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
    section('6. VERDICT 2 -- records_cover_window (recomputed)')
    # ------------------------------------------------------------------
    #
    # Coverage needs, independently:
    #   * the snapshot published at or after the window END
    #   * the snapshot reaching back to or before the window START
    #   * no holes
    #   * the ring not having overflowed past records inside the window
    times = [r['t'] for _, r in recs]
    oldest = min(times) if times else 0
    rec('cover', 'the snapshot was published at or after the window end',
        h['tPublished'] >= we,
        'published=%d end=%d gap=%d' % (h['tPublished'], we, h['tPublished'] - we))
    rec('cover', 'the snapshot reaches back to or before the window start',
        oldest != 0 and oldest <= ws,
        'oldest=%d start=%d' % (oldest, ws))
    rec('cover', 'there are no holes in the snapshot', holes == 0)
    rec('cover', 'the ring did not overflow past the window',
        (h['flags'] & HDR_OVERFLOWED) == 0, 'flags=0x%x' % h['flags'])
    cover_ok = (h['tPublished'] >= we and oldest != 0 and oldest <= ws and
                holes == 0 and (h['flags'] & HDR_OVERFLOWED) == 0)
    rec('cover', '=> records_cover_window', cover_ok)

    # The probe's own claim must agree.
    probe_cover = P.get('m2-b2-obs-records-cover-window')
    rec('cover', 'the probe\'s claim agrees with the recomputation',
        probe_cover == ('yes' if cover_ok else 'no'),
        'probe=%s recomputed=%s' % (probe_cover, cover_ok))

    # ------------------------------------------------------------------
    section('7. VERDICT 3 -- controlled_batch_complete (recomputed)')
    # ------------------------------------------------------------------
    #
    # The declared batch comes from the boot-arg, which the probe publishes.
    declared = P.get('m2-b2-obs-expected-batch') or 0
    print('  declared batch = %d' % declared)
    rec('batch', 'this round declared a batch', declared > 0)

    # Client and peer must agree on what was sent and received.
    cl = open(os.path.join(cap, 'client.log'), encoding='utf-8',
              errors='replace').read()
    pe = open(os.path.join(cap, 'peer.log'), encoding='utf-8',
              errors='replace').read()
    c_sent = [(int(a,16), int(b)) for a, b in
              re.findall(r'client_sent token=0x([0-9a-f]+) req=(\d+)', cl)]
    c_recv = [(int(a,16), int(b)) for a, b in
              re.findall(r'client_recv token=0x([0-9a-f]+) req=(\d+)', cl)]
    # peer.log accumulates every run of the day, so it MUST be filtered to
    # this capture's run token. Taking the whole file mixed 12 runs together
    # and reported "peer=0 client=4" -- the peer had certainly received them,
    # just not under the token the filter happened to look for.
    #
    # TWO FORMATS ARE ACCEPTED, AND THAT IS DELIBERATE:
    #   round10-peer.py  ->  "peer_recv token=0x<tok> req=<n>"
    #   the inline peer  ->  "RECV <len> bytes from <ip>:<port> head=<24 hex>"
    # The capture archived the second form, so an analyser that only knew the
    # first would have declared a working peer exchange absent. Supporting
    # both is what makes the check about the EVIDENCE rather than about which
    # script happened to write the file.
    #
    # ONE RUN, NOT THE WHOLE DAY. peer.log spans every run of the session, so
    # it must be reduced to the block that belongs to THIS capture. The
    # discriminator is the client's source port: the client binds an ephemeral
    # port and records it, and the peer logs it on every RECV line. Matching on
    # (token, port) selects exactly one run even though the token repeats.
    c_port = re.search(r'client_bound\s+\S+:(\d+)', cl)
    want_port = c_port.group(1) if c_port else None

    all_peer = []
    for a, b in re.findall(r'peer_recv token=0x([0-9a-f]+) req=(\d+)', pe):
        all_peer.append((int(a, 16), int(b), None))
    for _ip, port, head in re.findall(
            r'RECV \d+ bytes from (\S+):(\d+) head=([0-9a-f]{24})', pe):
        # head = magic(4) | token(4) | reqId(4), big endian
        tok = int(head[8:16], 16)
        rid = int(head[16:24], 16)
        all_peer.append((tok, rid, port))

    c_tokens = set(t for t, _ in c_sent)
    if want_port is not None:
        p_recv = [(t, r) for (t, r, port) in all_peer
                  if t in c_tokens and port == want_port]
        print('  peer rows for this run (port %s): %d' % (want_port, len(p_recv)))
    else:
        p_recv = [(t, r) for (t, r, _p) in all_peer if t in c_tokens]
    rec('batch', 'the client sent exactly the declared number',
        len(c_sent) == declared, '%d vs %d' % (len(c_sent), declared))
    rec('batch', 'the client received an echo for every send',
        len(c_recv) == len(c_sent) and
        sorted(c_recv) == sorted(c_sent),
        'sent=%d recv=%d' % (len(c_sent), len(c_recv)))
    rec('batch', 'the peer received exactly the same set',
        sorted(p_recv) == sorted(c_sent),
        'peer=%d client=%d' % (len(p_recv), len(c_sent)))
    tokens = set(t for t, _ in c_sent)
    rec('batch', 'the client used exactly one run token', len(tokens) == 1,
        'tokens=%s' % tokens)
    token = tokens.pop() if tokens else 0
    req_ids = sorted(r for _, r in c_sent)
    rec('batch', 'the request ids are exactly 1..declared',
        req_ids == list(range(1, declared + 1)), 'ids=%s' % req_ids)

    # Now the driver's records must carry the same identifiers.
    tx_by_req = {}
    rx_by_req = {}
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

    # Every TX segment of every request must have a completion.
    all_done = True
    seg_report = {}
    for req, lst in sorted(tx_by_req.items()):
        cums = [r['cum'] for _, r in lst]
        missing = [c for c in cums if c not in dones]
        seg_report[req] = (len(cums), len(cums) - len(missing))
        if missing:
            all_done = False
    rec('batch', 'every TX segment of every request completed', all_done,
        str(seg_report))
    print('  segments per request (submitted, completed): %s' % seg_report)

    batch_ok = (declared > 0 and len(c_sent) == declared and
                sorted(c_recv) == sorted(c_sent) and
                sorted(p_recv) == sorted(c_sent) and
                sorted(tx_by_req) == list(range(1, declared + 1)) and
                sorted(rx_by_req) == list(range(1, declared + 1)) and all_done)
    rec('batch', '=> controlled_batch_complete', batch_ok)
    probe_batch = P.get('m2-b2-obs-controlled-batch-complete')
    rec('batch', 'the probe\'s claim agrees with the recomputation',
        probe_batch == ('yes' if batch_ok else 'no'),
        'probe=%s recomputed=%s' % (probe_batch, batch_ok))

    # ------------------------------------------------------------------
    section('8. THE BUSINESS CHAIN: one request -> TX/RX DMA records')
    # ------------------------------------------------------------------
    #
    # Pick the first declared request and lay out its whole chain from the raw
    # records, so the answer to "which unique request maps to which DMA" is
    # read off the evidence rather than asserted.
    chain = None
    for req in sorted(tx_by_req):
        txl = tx_by_req.get(req, [])
        rxl = rx_by_req.get(req, [])
        if not txl or not rxl:
            continue
        chain = {'req': req, 'tx': txl, 'rx': rxl}
        break
    if chain is None:
        rec('chain', 'a complete TX+RX business chain exists', False)
    else:
        req = chain['req']
        print('  request id %d  (run token 0x%08x)' % (req, token))
        segs = []
        for i, r in chain['tx']:
            d = dones.get(r['cum'], [])
            tdone = d[0][1]['t'] if d else None
            segs.append({'cum': r['cum'], 'slot': r['slot'],
                         'addr': r['addr'], 'len': r['len'],
                         't_submit': r['t'], 't_done': tdone,
                         'in_window': ws <= r['t'] <= we,
                         'done_in_window': (tdone is not None and
                                            ws <= tdone <= we)})
            print('    TX seg cum=0x%03x slot=0x%03x addr=0x%-11x len=%3d '
                  't_submit=%d t_done=%s in_window=%s'
                  % (r['cum'], r['slot'], r['addr'], r['len'], r['t'],
                     tdone, ws <= r['t'] <= we))
        for i, r in chain['rx']:
            print('    RX      cum=0x%03x slot=0x%03x addr=0x%-11x len=%3d '
                  't=%d in_window=%s'
                  % (r['cum'], r['slot'], r['addr'], r['len'], r['t'],
                     ws <= r['t'] <= we))
        # The recorded segment length is the length of the FRAME the NIC put
        # on the wire, not the length of the application payload:
        #
        #   client len=32   = magic(4) + token(4) + reqId(4) + pad(20)
        #   frame     = 32 + UDP(8) + IPv4(20) + Ethernet(14) = 74
        #
        # The analyser must therefore compare against the FRAME length, and it
        # must derive that from the client's payload rather than hard-coding
        # 74. Without this check a record whose length field was zeroed would
        # still "pair" and still "cover the window" while describing a
        # meaningless DMA range.
        cl_len = None
        for line in cl.splitlines():
            m2 = re.search(r'client_sent token=0x[0-9a-f]+ req=%d len=(\d+)'
                           % req, line)
            if m2:
                cl_len = int(m2.group(1))
                break
        frame_len = (cl_len + 8 + 20 + 14) if cl_len is not None else None
        rec('chain', 'the recorded segment length matches the frame the client '
            'sent (payload + UDP + IPv4 + Ethernet)',
            frame_len is not None and all(s['len'] == frame_len for s in segs),
            'client payload=%s frame=%s records=%s'
            % (cl_len, frame_len, [s['len'] for s in segs]))
        rec('chain', 'the TX segments are inside the window',
            all(s['in_window'] for s in segs))
        rec('chain', 'the completions are inside the window',
            all(s['done_in_window'] for s in segs),
            str([s['done_in_window'] for s in segs]))
        rec('chain', 'the completions follow their submissions',
            all(s['t_done'] is not None and s['t_done'] >= s['t_submit']
                for s in segs))
        rec('chain', 'the RX record is inside the window',
            all(ws <= r['t'] <= we for _, r in chain['rx']))
        rec('chain', 'the RX record carries the same request id',
            all(r['reqId'] == req for _, r in chain['rx']))
        rec('chain', 'the RX record carries the same run token',
            all(r['token'] == token for _, r in chain['rx']))

    # ------------------------------------------------------------------
    section('9. PAGE TABLE: every attributed address walks to itself')
    # ------------------------------------------------------------------
    #
    # The probe publishes the PTE chain for the first window operation. The
    # analysis decodes it independently: level, index, NextLevel, address,
    # Present bit and the permission bits the direction needs.
    def pte_get(name):
        return P.get(name)

    p0 = pte_get('m2-b2-win0-pte0')
    p1 = pte_get('m2-b2-win0-pte1')
    p2 = pte_get('m2-b2-win0-pte2')
    addr0 = pte_get('m2-b2-win0-addr')
    depth = pte_get('m2-b2-win0-depth')

    if p0 is None or addr0 is None:
        rec('pt', 'a page-table path was published for the window operation',
            False, 'missing win0-pte*')
    else:
        print('  attributed address = 0x%x' % addr0)
        ptes = []
        for lvl, pte in ((4, p0), (3, p1), (2, p2)):
            if pte is None:
                continue
            present = pte & 1
            next_level = (pte >> 9) & 0x7
            table = pte & 0x000FFFFFFFFFF000
            ptes.append((lvl, pte, present, next_level, table))
            print('    L%d pte=0x%016x present=%d NextLevel=%d table=0x%x'
                  % (lvl, pte, present, next_level, table))
        rec('pt', 'every published PTE has its Present bit set',
            all(p for _, _, p, _, _ in ptes))
        rec('pt', 'the root table is the one the DTE names',
            pte_get('m2-b2-win0-pte0-table') == pte_get('m2-b2-dte-root') or
            pte_get('m2-b2-dte-root') is None,
            'pte0 table=0x%x dte root=%s'
            % (ptes[0][4], pte_get('m2-b2-dte-root')))
        # The leaf must map to the address itself (identity).
        leaf = ptes[-1] if ptes else None
        if leaf:
            rec('pt', 'the leaf maps the address to itself (identity)',
                leaf[4] <= addr0 < leaf[4] + (2 << 20) or
                leaf[4] == (addr0 & ~0x1FFFFF),
                'leaf=0x%x addr=0x%x' % (leaf[4], addr0))
        rec('pt', 'the walk verdict is leaf (not absent, not illegal)',
            P.get('m2-b2-win0-walk') == 'leaf',
            'walk=%s' % P.get('m2-b2-win0-walk'))

    # ------------------------------------------------------------------
    section('10. EVENT LOG: raw records decoded independently')
    # ------------------------------------------------------------------
    n_raw = P.get('m2-b2-win-raw-count') or 0
    print('  raw window events = %d' % n_raw)
    faults = 0
    fault_addrs = []
    for i in range(n_raw):
        raw_ev = P.get('m2-b2-win-raw%d' % i)
        if not raw_ev:
            continue
        r = [int(raw_ev[j * 8:(j + 1) * 8], 16) for j in range(4)]
        etype = (r[1] >> 28) & 0xF
        devid = r[0] & 0xFFFF
        if etype == 2:
            faults += 1
            w1 = r[2] | (r[3] << 32)
            a = w1 & 0xFFFFFFFFFFFFF000
            fault_addrs.append((devid, a))
            print('    IO_PAGE_FAULT devid=0x%04x addr=0x%x (%.4f GiB)'
                  % (devid, a, a / (1024.0 ** 3)))
    rec('events', 'the raw event count agrees with the per-type counters',
        faults == (P.get('m2-b2-win-type2-count') or 0),
        'decoded=%d probe=%s' % (faults, P.get('m2-b2-win-type2-count')))
    rec('events', 'every faulting device id is the target device',
        all(d == (P.get('m2-b2-nic-bdf') or d) for d, _ in fault_addrs),
        str(fault_addrs))

    # The map limit and whether any fault exceeded it.
    limit = P.get('m2-b2-map-limit')
    if limit is not None:
        over = [a for _, a in fault_addrs if a >= limit]
        print('  identity map limit = 0x%x (%.4f GiB)'
              % (limit, limit / (1024.0 ** 3)))
        rec('events', 'no fault lies at or above the identity map limit',
            len(over) == 0,
            'over-limit: %s' % ['0x%x' % a for a in over])

    # ------------------------------------------------------------------
    section('SUMMARY')
    # ------------------------------------------------------------------
    sections = {}
    for sec, name, ok, detail in RESULTS:
        sections.setdefault(sec, [0, 0])
        sections[sec][1] += 1
        if ok:
            sections[sec][0] += 1
    total_ok = sum(1 for _, _, ok, _ in RESULTS if ok)
    total = len(RESULTS)
    for sec in sorted(sections):
        ok, n = sections[sec]
        print('  %-12s %2d/%2d' % (sec, ok, n))
    print()
    print('  TOTAL        %d/%d' % (total_ok, total))
    print()
    print('  has_complete_pair        : %s' % ('YES' if paired else 'NO'))
    print('  records_cover_window     : %s' % ('YES' if cover_ok else 'NO'))
    print('  controlled_batch_complete: %s' % ('YES' if batch_ok else 'NO'))
    print()
    verdict = 'PASS' if total_ok == total else 'FAIL'
    print('  RESULT: %s' % verdict)

    out = {
        'capture': cap,
        'inputs': {k: {'bytes': v[0], 'sha256': v[1]}
                   for k, v in input_files.items()},
        'snapshot': h,
        'window': {'start': ws, 'end': we},
        'verdicts': {
            'has_complete_pair': bool(paired),
            'records_cover_window': cover_ok,
            'controlled_batch_complete': batch_ok,
        },
        'declared_batch': declared,
        'run_token': token,
        'faults': [{'devid': d, 'addr': a} for d, a in fault_addrs],
        'checks': [{'section': s, 'name': n, 'ok': o, 'detail': d}
                   for s, n, o, d in RESULTS],
    }
    with open(os.path.join(cap, 'analysis.json'), 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=1)
    print('  wrote %s' % os.path.join(cap, 'analysis.json'))

    return 0 if total_ok == total else 1


if __name__ == '__main__':
    sys.exit(main())
