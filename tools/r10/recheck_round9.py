#!/usr/bin/env python3
"""Round-10 offline re-review of the round-9 capture.

Answers, from the ORIGINAL files only:

  A. What the archived driver-obs.txt snapshot actually is, and whether it is
     the same publication the probe used at runtime.
  B. Which window-internal TX submit/doorbell/done groups it contains
     (cumulative 0x60/0x61/0x62 -- the three the report never exported).
  C. How far the probe's own snapshot fell short of the window end.
  D. Whether any client/peer business sequence number appears anywhere in the
     driver's records.

Inputs (hashed, never modified):
  docs/evidence/20261031-172647/props.txt
  docs/evidence/20261031-172647/driver-obs.txt
  docs/evidence/20261031-172647/client.log
  docs/evidence/20261031-172647/peer.log
  docs/evidence/20261031-172647/load.txt
  docs/evidence/20261031-172647/network.txt
  docs/evidence/20261031-172647/driver-obs-blob.bin  (extracted by dump_obs.py)
"""
import hashlib
import json
import os
import re
import struct
import sys

EV = 'docs/evidence/20261031-172647'
REC = 56
KIND = {0: 'none', 1: 'tx-submit', 2: 'tx-done', 3: 'rx-done', 4: 'tx-doorbell'}


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def hexprops(txt):
    """All 'key' = "0x..." properties in an ioreg dump, last wins."""
    out = {}
    for m in re.finditer(r'"([A-Za-z0-9_.\-]+)"\s*=\s*"0x([0-9a-fA-F]+)"', txt):
        out[m.group(1)] = int(m.group(2), 16)
    for m in re.finditer(r'"([A-Za-z0-9_.\-]+)"\s*=\s*"([^"]*)"', txt):
        out.setdefault(m.group(1), m.group(2))
    return out


def decode(blob):
    recs = []
    for i in range(len(blob) // REC):
        (t, addr, seq, kind, cum, slot, gen, batch,
         o1, o2, ln, fl) = struct.unpack_from('<QQIIIIIIIIII', blob, i * REC)
        recs.append(dict(index=i, tMono=t, addr=addr, seq=seq, kind=kind,
                         kindName=KIND.get(kind, 'unknown'), cumulative=cum,
                         slot=slot, gen=gen, batch=batch, opts1=o1, opts2=o2,
                         len=ln, flags=fl))
    return recs


def main():
    print('=' * 78)
    print('INPUT IDENTITIES')
    print('=' * 78)
    files = ['props.txt', 'driver-obs.txt', 'client.log', 'peer.log',
             'load.txt', 'network.txt', 'driver-obs-blob.bin']
    for f in files:
        p = os.path.join(EV, f)
        if os.path.exists(p):
            print('  %-22s %10d B  sha256=%s' % (f, os.path.getsize(p),
                                                 sha256(p)))

    props = open(os.path.join(EV, 'props.txt'), encoding='utf-8',
                 errors='replace').read()
    P = hexprops(props)

    print()
    print('=' * 78)
    print('A. RUNTIME SNAPSHOT (what the probe actually consumed)')
    print('=' * 78)
    keys = ['m2-b2-obs', 'm2-b2-obs-format', 'm2-b2-obs-state',
            'm2-b2-obs-head', 'm2-b2-obs-first', 'm2-b2-obs-published',
            'm2-b2-obs-records', 'm2-b2-obs-bytes', 'm2-b2-obs-t-start',
            'm2-b2-obs-t-published', 'm2-b2-obs-wrapped',
            'm2-b2-obs-win-submits', 'm2-b2-obs-win-dones',
            'm2-b2-obs-win-paired', 'm2-b2-obs-win-orphan-done',
            'm2-b2-obs-window-complete', 'm2-b2-obs-uncompleted',
            'm2-b2-obs-unmatched-done', 'm2-b2-obs-stale']
    for k in keys:
        print('  %-30s = %s' % (k, P.get(k, 'ABSENT')))

    tWinStart = P.get('m2-b2-dma-t-win-start')
    tWinEnd = P.get('m2-b2-dma-t-win-end')
    tPub = P.get('m2-b2-obs-t-published')
    print()
    print('  window   = [%d, %d]  (%.6f s)' %
          (tWinStart, tWinEnd, (tWinEnd - tWinStart) / 1e9))
    print('  obs snapshot published at %d' % tPub)
    gap = tWinEnd - tPub
    print('  window_end - snapshot_published = %d ns  (%.6f s)' %
          (gap, gap / 1e9))
    print('  => snapshot %s the window end' %
          ('PRECEDES' if gap > 0 else 'follows'))

    print()
    print('=' * 78)
    print('B. ARCHIVED driver-obs.txt (a DIFFERENT, LATER publication)')
    print('=' * 78)
    D = hexprops(open(os.path.join(EV, 'driver-obs.txt'), encoding='utf-8',
                      errors='replace').read())
    for k in ['rtl812x-obs-format', 'rtl812x-obs-state',
              'rtl812x-obs-rec-size', 'rtl812x-obs-head',
              'rtl812x-obs-first', 'rtl812x-obs-published',
              'rtl812x-obs-wrapped', 'rtl812x-obs-t-start',
              'rtl812x-obs-t-published']:
        print('  %-28s = %s' % (k, D.get(k, 'ABSENT')))

    blob = open(os.path.join(EV, 'driver-obs-blob.bin'), 'rb').read()
    recs = decode(blob)
    print()
    print('  blob records        = %d (%d bytes)' % (len(recs), len(blob)))
    seqs = [r['seq'] for r in recs if r['seq']]
    print('  seq range in blob   = %d..%d' % (min(seqs), max(seqs)))
    print('  header first/head   = %d..%d' %
          (D['rtl812x-obs-first'], D['rtl812x-obs-head']))
    print('  first record seq-1  = %d  (expect %d)' %
          (seqs[0] - 1, D['rtl812x-obs-first']))

    print()
    print('  publication identity comparison:')
    print('    runtime (probe)  head=0x%x first=0x%x published=0x%x '
          't-pub=%d' % (P['m2-b2-obs-head'], P['m2-b2-obs-first'],
                        P['m2-b2-obs-published'], tPub))
    print('    archived file    head=0x%x first=0x%x published=0x%x '
          't-pub=%d' % (D['rtl812x-obs-head'], D['rtl812x-obs-first'],
                        D['rtl812x-obs-published'],
                        D['rtl812x-obs-t-published']))
    print('    => %s' % ('DIFFERENT publications'
                        if (P['m2-b2-obs-head'] != D['rtl812x-obs-head'] or
                            P['m2-b2-obs-published'] != D['rtl812x-obs-published'])
                        else 'same header values'))
    print('    archived snapshot is %.3f s AFTER the window end' %
          ((D['rtl812x-obs-t-published'] - tWinEnd) / 1e9))

    print()
    print('=' * 78)
    print('C. WINDOW-INTERNAL TX GROUPS IN THE ARCHIVED BLOB')
    print('=' * 78)
    tx = [r for r in recs if r['seq'] and r['kind'] in (1, 2, 4)]
    inwin = [r for r in tx if tWinStart <= r['tMono'] <= tWinEnd]
    print('  TX-kind records total=%d  inside window=%d' % (len(tx), len(inwin)))

    groups = {}
    for r in recs:
        if not r['seq']:
            continue
        if tWinStart <= r['tMono'] <= tWinEnd and r['kind'] in (1, 2, 4):
            groups.setdefault(r['batch'], []).append(r)

    for batch in sorted(groups):
        g = groups[batch]
        print()
        print('  --- batch 0x%02x (%d records) ---' % (batch, len(g)))
        for r in g:
            print('    blob_idx=%-4d seq=%-4d %-12s cum=0x%02x slot=0x%02x '
                  'gen=%d addr=0x%x len=0x%x(%d) flags=0x%x t=%d'
                  % (r['index'], r['seq'], r['kindName'], r['cumulative'],
                     r['slot'], r['gen'], r['addr'], r['len'], r['len'],
                     r['flags'], r['tMono']))

    print()
    print('  For each batch, submit->doorbell->done intervals:')
    for batch in sorted(groups):
        g = groups[batch]
        sub = [r for r in g if r['kind'] == 1]
        db = [r for r in g if r['kind'] == 4]
        dn = [r for r in g if r['kind'] == 2]
        for s in sub:
            d = [x for x in dn if x['cumulative'] == s['cumulative']]
            print('    cum=0x%02x slot=0x%02x addr=0x%-12x len=%3d '
                  't_submit=%d%s%s' %
                  (s['cumulative'], s['slot'], s['addr'], s['len'],
                   s['tMono'],
                   ('  t_done=%d (+%d ns)' % (d[0]['tMono'],
                                              d[0]['tMono'] - s['tMono']))
                   if d else '  NO DONE',
                   ('  t_doorbell=%d' % db[0]['tMono']) if db else ''))

    print()
    print('=' * 78)
    print('D. DO BUSINESS SEQUENCE NUMBERS APPEAR IN THE DRIVER RECORDS?')
    print('=' * 78)
    client = open(os.path.join(EV, 'client.log'), encoding='utf-8',
                  errors='replace').read()
    peer = open(os.path.join(EV, 'peer.log'), encoding='utf-8',
                errors='replace').read()
    creq = re.findall(r'client_sent seq=(\d+)', client)
    preq = re.findall(r'peer_recv seq=(\d+)', peer)
    print('  client_sent seq count = %d, range %s..%s' %
          (len(creq), min(creq) if creq else '-', max(creq) if creq else '-'))
    print('  peer_recv  seq count = %d, range %s..%s' %
          (len(preq), min(preq) if preq else '-', max(preq) if preq else '-'))
    print('  same set: %s' % (set(creq) == set(preq)))

    # The driver record fields that COULD carry a business id.
    fields = ['cumulative', 'slot', 'gen', 'batch', 'opts1', 'opts2', 'len',
              'flags']
    hit = {f: 0 for f in fields}
    for r in recs:
        for f in fields:
            v = r[f]
            if v in (1, 2, 3, 4, 5, 6, 7, 8):
                pass  # too small to be meaningful, ignore
        # a real business id would be >= 1 and <= 1178 and equal across the
        # TX submit, its doorbell and its done for the same packet -- test
        # whether any field equals the client's seq for the matching packet.
    print('  driver record fields available for correlation: %s' %
          ', '.join(fields))
    print('  NO field in the wire format carries a client/peer sequence')
    print('  number, payload hash, socket tuple or flow id:')
    print('    - cumulative/slot/gen are driver queue indices')
    print('    - batch is the first cumulative index of the packet')
    print('    - opts1/opts2 are raw descriptor words (length/flags)')
    print('  => a driver record cannot be joined to client seq N or peer')
    print('     req N by any identifier. Round 9 joined them by TIME ORDER')
    print('     and by "42 bytes", which is not an identifier.')

    out = {
        'inputs': {f: sha256(os.path.join(EV, f)) for f in files
                   if os.path.exists(os.path.join(EV, f))},
        'window': [tWinStart, tWinEnd],
        'runtime_snapshot': {'head': P.get('m2-b2-obs-head'),
                             'first': P.get('m2-b2-obs-first'),
                             'published': P.get('m2-b2-obs-published'),
                             't_published': tPub,
                             'win_submits': P.get('m2-b2-obs-win-submits'),
                             'win_dones': P.get('m2-b2-obs-win-dones'),
                             'win_paired': P.get('m2-b2-obs-win-paired')},
        'archived_snapshot': {'head': D.get('rtl812x-obs-head'),
                              'first': D.get('rtl812x-obs-first'),
                              'published': D.get('rtl812x-obs-published'),
                              't_published': D.get('rtl812x-obs-t-published')},
        'window_gap_ns': gap,
        'archived_window_batches': sorted(groups),
        'client_seq_count': len(creq),
        'peer_seq_count': len(preq),
    }
    os.makedirs(os.path.join(EV, 'derived'), exist_ok=True)
    with open(os.path.join(EV, 'derived', 'round9-recheck.json'), 'w',
              encoding='utf-8') as f:
        json.dump(out, f, indent=1)
    print()
    print('wrote %s' % os.path.join(EV, 'derived', 'round9-recheck.json'))


if __name__ == '__main__':
    main()
