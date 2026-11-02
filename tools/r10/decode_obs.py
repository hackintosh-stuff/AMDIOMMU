#!/usr/bin/env python3
"""Round-10: independent decoder for the driver's published obs log.

Decodes the raw byte blob that the probe actually copied out of the driver's
IORegistry property. This is deliberately NOT the probe's summary attributes:
every number here is recomputed from the 56-byte records.

Wire format (tools/lucy-obs/RTL812xObsLog.hpp, kObsVersion 1):

  offset  size  field
  0       8     tMono
  8       8     addr
  16      4     seq          (absolute index + 1, written LAST)
  20      4     kind
  24      4     cumulative
  28      4     slot
  32      4     gen
  36      4     batch
  40      4     opts1
  44      4     opts2
  48      4     len
  52      4     flags
"""
import argparse
import hashlib
import json
import struct
import sys

REC = 56
KIND = {0: 'none', 1: 'tx-submit', 2: 'tx-done', 3: 'rx-done', 4: 'tx-doorbell'}
FLAG = {0: 'len-unknown', 1: 'tso', 2: 'first-frag', 3: 'last-frag',
        4: 'ring-end', 5: 'desc-own', 6: 'rx-error'}


def decode(blob):
    n = len(blob) // REC
    out = []
    for i in range(n):
        off = i * REC
        t, addr, seq, kind, cum, slot, gen, batch, o1, o2, ln, fl = \
            struct.unpack_from('<QQIIIIIIIIII', blob, off)
        out.append(dict(index=i, tMono=t, addr=addr, seq=seq, kind=kind,
                        kindName=KIND.get(kind, 'unknown'), cumulative=cum,
                        slot=slot, gen=gen, batch=batch, opts1=o1, opts2=o2,
                        len=ln, flags=fl,
                        flagNames=[v for k, v in FLAG.items() if fl & (1 << k)],
                        valid=(seq != 0)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('blob')
    ap.add_argument('--kind', default=None)
    ap.add_argument('--cum', default=None, help='cumulative index, 0x.. or dec')
    ap.add_argument('--json', default=None)
    ap.add_argument('--summary', action='store_true')
    a = ap.parse_args()

    blob = open(a.blob, 'rb').read()
    print('blob %s bytes=%d sha256=%s' %
          (a.blob, len(blob), hashlib.sha256(blob).hexdigest()))
    recs = decode(blob)
    written = [r for r in recs if r['seq'] != 0]
    print('records=%d written=%d' % (len(recs), len(written)))
    if written:
        print('seq range = %d..%d (expect 1..%d for head)' %
              (min(r['seq'] for r in written), max(r['seq'] for r in written),
               max(r['seq'] for r in written)))
    kinds = {}
    for r in written:
        kinds[r['kindName']] = kinds.get(r['kindName'], 0) + 1
    print('kinds =', json.dumps(kinds, sort_keys=True))

    if a.kind:
        want = KIND.get(int(a.kind)) if a.kind.isdigit() else a.kind
        recs = [r for r in recs if r['kindName'] == want]
    if a.cum:
        c = int(a.cum, 0)
        recs = [r for r in recs if r['cumulative'] == c]

    for r in recs:
        if not r['valid']:
            continue
        print('idx=%-4d seq=%-5d %-12s cum=0x%03x(%d) slot=0x%03x gen=%d '
              'batch=0x%x addr=0x%x len=0x%x(%d) flags=0x%x %s t=%d'
              % (r['index'], r['seq'], r['kindName'], r['cumulative'],
                 r['cumulative'], r['slot'], r['gen'], r['batch'], r['addr'],
                 r['len'], r['len'], r['flags'], ','.join(r['flagNames']),
                 r['tMono']))
    if a.json:
        with open(a.json, 'w', encoding='utf-8') as f:
            json.dump(recs, f, indent=1)


if __name__ == '__main__':
    main()
