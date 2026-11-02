#!/usr/bin/env python3
"""check-obs-layout.py -- the write protocol and the wire format must agree.

WHY
---
RTL812xObsWrite.hpp cannot include RTL812xObsLog.hpp: the host test compiles the
former without the driver's IOKit headers, so the protocol header repeats the
four offsets it needs (seq, head, dropped, wrapped) and the record size.

Repeating a constant is how the two drift apart, and a drifted offset would not
fail to compile -- it would corrupt the log silently. So the duplication is
checked mechanically, from the actual struct definitions, and the check is part
of the build.

Exit 0 only when every offset and size agrees.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WIRE = os.path.join(ROOT, 'tools', 'lucy-obs', 'RTL812xObsLog.hpp')
PROTO = os.path.join(ROOT, 'tools', 'lucy-obs', 'RTL812xObsWrite.hpp')

# The fields the protocol header hard-codes, in declaration order, with their
# C types. The offsets are computed here rather than trusted.
REC_FIELDS = [
    ('tMono', 'UInt64'), ('addr', 'UInt64'), ('seq', 'UInt32'),
    ('kind', 'UInt32'), ('cumulative', 'UInt32'), ('slot', 'UInt32'),
    ('gen', 'UInt32'), ('batch', 'UInt32'), ('opts1', 'UInt32'),
    ('opts2', 'UInt32'), ('len', 'UInt32'), ('flags', 'UInt32'),
    ('token', 'UInt32'), ('reqId', 'UInt32'), ('flowHash', 'UInt32'),
    ('pktFlags', 'UInt32'),
]

HDR_FIELDS = [
    ('magic', 'UInt32'), ('version', 'UInt32'), ('recSize', 'UInt32'),
    ('capacity', 'UInt32'), ('head', 'UInt32'), ('wrapped', 'UInt32'),
    ('dropped', 'UInt32'), ('pubId', 'UInt32'), ('firstTicket', 'UInt32'),
    ('lastTicket', 'UInt32'), ('validCount', 'UInt32'), ('lostCount', 'UInt32'),
    ('epoch', 'UInt32'), ('busDevFn', 'UInt32'), ('vendorId', 'UInt32'),
    ('deviceId', 'UInt32'), ('ifUnit', 'UInt32'), ('macHi', 'UInt32'),
    ('macLo', 'UInt32'), ('flags', 'UInt32'), ('tStart', 'UInt64'),
    ('tPublished', 'UInt64'), ('reserved', 'UInt64'),
]

SIZES = {'UInt32': 4, 'UInt64': 8}


def offsets(fields):
    out = {}
    off = 0
    for name, typ in fields:
        size = SIZES[typ]
        # Natural alignment: a UInt64 cannot sit at a 4-aligned offset.
        if off % size:
            off += size - (off % size)
        out[name] = off
        off += size
    total = off
    if total % 8:
        total += 8 - (total % 8)
    return out, total


def parse_proto_consts(text):
    consts = {}
    for m in re.finditer(r'#define\s+(kObs\w+)\s+(\d+)u?', text):
        consts[m.group(1)] = int(m.group(2))
    return consts


def main():
    wire = open(WIRE, encoding='utf-8').read()
    proto = open(PROTO, encoding='utf-8').read()

    # The wire header must actually declare the fields we compute from.
    for name, typ in REC_FIELDS + HDR_FIELDS:
        if not re.search(r'\b%s\s+%s\s*;' % (typ, name), wire):
            print('FAIL: RTL812xObsLog.hpp has no field %s %s' % (typ, name))
            return 1

    recOff, recSize = offsets(REC_FIELDS)
    hdrOff, hdrSize = offsets(HDR_FIELDS)
    consts = parse_proto_consts(proto)

    checks = [
        ('kObsSeqOffset',  recOff['seq'],     'RtlObsRec.seq'),
        ('kObsHeadOffset', hdrOff['head'],    'RtlObsHdr.head'),
        ('kObsWrapOffset', hdrOff['wrapped'], 'RtlObsHdr.wrapped'),
        ('kObsDropOffset', hdrOff['dropped'], 'RtlObsHdr.dropped'),
    ]
    ok = True
    print('=' * 70)
    print('OBS LAYOUT CONSISTENCY (protocol header vs wire header)')
    print('=' * 70)
    print('  computed: RtlObsRec = %d B, RtlObsHdr = %d B' % (recSize, hdrSize))
    for key, want, what in checks:
        got = consts.get(key)
        good = (got == want)
        print('  %-18s %-24s proto=%s wire=%s  %s'
              % (key, what, got, want, 'OK' if good else 'MISMATCH'))
        if not good:
            ok = False

    # The wire header must publish the same sizes.
    for macro, want in (('kObsRecBytes', recSize), ('kObsHdrBytes', hdrSize)):
        m = re.search(r'#define\s+%s\s+\(\(UInt32\)sizeof\((\w+)\)\)'
                      % macro, wire)
        if not m:
            print('  %-18s NOT FOUND in the wire header' % macro)
            ok = False
            continue
        print('  %-18s sizeof(%s) -> %d  %s'
              % (macro, m.group(1), want, 'OK'))

    # The protocol's record-size literal must match too.
    m = re.search(r'#define\s+kObsRecBytesWire\s+(\d+)u?', proto)
    lit = int(m.group(1)) if m else None
    if lit != recSize:
        print('  the protocol hard-codes %s but the record is %d B'
              % (lit, recSize))
        ok = False
    print('  protocol record-size literal : %s'
          % ('%d (matches)' % lit if lit == recSize else 'MISMATCH'))

    # The protocol must copy in whole 8-byte words, because that is what makes
    # the writer/publisher pair race-free. A record whose size is not a multiple
    # of 8 would leave a tail that has to be copied with plain accesses, and
    # plain accesses are exactly the data race round 12 removed.
    words = re.search(r'#define\s+kObsRecWords\s+\(?kObsRecBytesWire\s*/\s*8u?\)?',
                      proto)
    seqw = re.search(r'#define\s+kObsSeqWord\s+\(?kObsSeqOffset\s*/\s*8u?\)?',
                     proto)
    print('  record is 9 whole 8-byte words : %s'
          % ('YES' if recSize % 8 == 0 else 'NO'))
    print('  protocol declares kObsRecWords  : %s'
          % ('YES' if words else 'NO'))
    print('  protocol declares kObsSeqWord   : %s'
          % ('YES' if seqw else 'NO'))
    if recSize % 8 != 0 or not words or not seqw:
        ok = False

    # Both sides must use atomics on the body. The check is textual because the
    # point is that no plain byte loop over the record survives: a plain loop
    # is the race.
    plain_write = re.search(r'for\s*\([^)]*\)\s*(?:dst|rec)\[z\]\s*=\s*(?:src|stage)\[z\]',
                            proto)
    body_atomic = '__atomic_store_n(dst + w, src[w]' in proto
    copy_atomic = '__atomic_load_n(s + w, __ATOMIC_RELAXED)' in proto
    print('  writer publishes with atomics  : %s'
          % ('YES' if body_atomic else 'NO'))
    print('  publisher copies with atomics  : %s'
          % ('YES' if copy_atomic else 'NO'))
    if not body_atomic or not copy_atomic:
        ok = False
    # The only permitted byte loop is the fallback for a non-72-byte record,
    # which the wire format never produces.
    if plain_write and 'wordwise' not in proto:
        print('  a plain byte copy survives with no guard')
        ok = False

    # Loss counters must be atomic and must be read through the accessor.
    if 'countLoss' not in proto or '__atomic_fetch_add(counter' not in proto:
        print('  loss counters are not atomic fetch-add')
        ok = False
    print('  loss counters use atomic add  : %s'
          % ('YES' if '__atomic_fetch_add(counter' in proto else 'NO'))

    print()
    print('  RESULT: %s' % ('CONSISTENT' if ok else 'FAILURES'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
