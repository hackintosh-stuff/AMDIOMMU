#!/usr/bin/env python3
"""check-rxpost-layout.py -- the RX post wire format has THREE declarations.

WHY THIS EXISTS
---------------
The same 160-byte header and two record types are declared in three places, for
three different reasons:

  tools/lucy-obs/RTL812xRxPost.hpp   the DRIVER writes them (C++ structs)
  probe/amd_iommu_rxset_core.hpp      the PROBE reads them (byte offsets)
  tests/rxpost-test.cpp              the HOST TEST drives both

The driver's header cannot be included by the probe (it lives in the patched
third-party tree, and the probe must not depend on a file the driver build
owns), and the probe's core cannot include it either (it must compile without
IOKit). So the layout is repeated, and repetition is how layouts drift.

A drift here does not fail to compile. It decodes `capacity` out of the middle
of `addr` and produces a set of plausible-looking wrong ranges -- and "every
range covered" would be a statement about addresses nobody uses.

This script parses all three declarations and requires them to agree exactly:
field order, field sizes, total sizes, and the protocol's seq word.
Exit 0 only when every one matches.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DRV = os.path.join(ROOT, 'tools', 'lucy-obs', 'RTL812xRxPost.hpp')
CORE = os.path.join(ROOT, 'probe', 'amd_iommu_rxset_core.hpp')
TEST = os.path.join(ROOT, 'tests', 'rxpost-test.cpp')
# A fourth declaration (the round-12 analyser) was checked here until that file
# was retired; the three files above are the whole contract now.

SIZES = {'u32': 4, 'u64': 8, 'UInt32': 4, 'UInt64': 8}

# The header, as the driver declares it. This list is the REFERENCE; the other
# two files are checked against it rather than against each other, so a change
# has to be made in one place and the check then names every file that did not
# follow.
HDR_FIELDS = [
    ('magic', 4), ('version', 4), ('recSizeSlot', 4), ('recSizeRearm', 4),
    ('head', 4), ('wrapped', 4), ('dropped', 4), ('slotCapacity', 4),
    ('rearmCapacity', 4), ('rearmFirstSeq', 4), ('ringGen', 4),
    ('baselineActive', 4), ('baselineSlots', 4), ('baselineValid', 4),
    ('baselineAddrZero', 4), ('baselineCapDesc', 4), ('baselineCapConst', 4),
    ('baselineCapBad', 4), ('baselineTorn', 4), ('baselineCount', 4),
    ('baselineGenMoved', 4), ('pubId', 4), ('epoch', 4), ('ifUnit', 4),
    ('vtdPath', 4), ('rxBufferSize', 4), ('flags', 4), ('pad0', 4),
    ('tBaseline', 8), ('rearmSeqAtBaseline', 8), ('tPublished', 8),
    ('rearmRequired', 4), ('rearmPublished', 4), ('reserved', 16),
]

SLOT_FIELDS = [('addr', 8), ('blenRaw', 8), ('slot', 4), ('capacity', 4),
               ('flags', 4), ('gen', 4)]

REARM_FIELDS = [('tMono', 8), ('addr', 8), ('oldAddr', 8), ('blenRaw', 8),
                ('seq', 4), ('slot', 4), ('capacity', 4), ('flags', 4)]

# The probe core declares the header as an enum of byte offsets. These are the
# offsets it needs to agree with, computed from HDR_FIELDS above.
def hdr_offsets(fields):
    out = {}
    off = 0
    for name, size in fields:
        if name == 'reserved':
            out[name] = off
            off += size
            continue
        # Natural alignment: a u64 cannot sit at a 4-aligned offset.
        if size == 8 and off % 8:
            off += 8 - (off % 8)
        out[name] = off
        off += size
    total = off
    if total % 8:
        total += 8 - (total % 8)
    return out, total


def parse_driver(text):
    """Parse the driver header's three structs into [(name, size)] lists."""
    def struct_body(name):
        m = re.search(r'struct %s\s*\{(.*?)\n\};' % name, text, re.S)
        if not m:
            return None
        body = m.group(1)
        out = []
        for line in body.split('\n'):
            line = re.sub(r'/\*.*?\*/', '', line).strip()
            m2 = re.match(r'^(u32|u64)\s+(\w+)(\[(\d+)\])?\s*;', line)
            if not m2:
                continue
            n = int(m2.group(4)) if m2.group(4) else 1
            out.append((m2.group(2), SIZES[m2.group(1)] * n))
        return out
    return (struct_body('Hdr'), struct_body('SlotRec'), struct_body('RearmRec'))


def parse_core_enum(text):
    """Parse the probe core's RXB_* enum into {name: value}.

    There is more than one enum in that header (the flag bits follow), so the
    right one is located by the member it must contain rather than by being
    first. Taking the first enum would silently return the FLAGS block and every
    offset check would then compare against None.
    """
    i = text.find('RXB_MAGIC')
    if i < 0:
        return {}
    start = text.rfind('enum {', 0, i)
    end = text.find('};', i)
    if start < 0 or end < 0:
        return {}
    out = {}
    val = 0
    for line in text[start + 6:end].split('\n'):
        line = line.split('//')[0].strip().rstrip(',')
        if not line:
            continue
        if '=' in line:
            name, v = line.split('=', 1)
            name = name.strip()
            v = v.strip()
            try:
                val = int(v, 0)
            except ValueError:
                continue
            out[name] = val
        else:
            out[line.strip()] = val
        val += 1
    return out


def main():
    print('=' * 78)
    print('RX POST WIRE LAYOUT (driver structs vs probe offsets vs the test)')
    print('=' * 78)

    for p in (DRV, CORE, TEST):
        if not os.path.isfile(p):
            print('FAIL: missing %s' % os.path.relpath(p, ROOT))
            return 1

    drv_text = open(DRV, encoding='utf-8').read()
    core_text = open(CORE, encoding='utf-8').read()
    test_text = open(TEST, encoding='utf-8').read()

    hdr, slot, rearm = parse_driver(drv_text)
    ok = True

    # ---- 1. the driver's own declarations match the reference list ----
    def cmp(name, got, want):
        nonlocal ok
        if got is None:
            print('  %-22s NOT FOUND in the driver header' % name)
            ok = False
            return
        gn = [n for n, _ in got]
        wn = [n for n, _ in want]
        if gn != wn:
            print('  %-22s field list differs' % name)
            print('    driver: %s' % gn)
            print('    wanted: %s' % wn)
            ok = False
            return
        gs = [s for _, s in got]
        ws = [s for _, s in want]
        if gs != ws:
            print('  %-22s field sizes differ: %s vs %s' % (name, gs, ws))
            ok = False
            return
        print('  %-22s %2d fields, %3d B  OK' % (name, len(gn), sum(gs)))

    cmp('Hdr', hdr, HDR_FIELDS)
    cmp('SlotRec', slot, SLOT_FIELDS)
    cmp('RearmRec', rearm, REARM_FIELDS)

    # ---- 2. the driver's static_asserts must name the real sizes ----
    for macro, want in (('SlotRec', 32), ('RearmRec', 48), ('Hdr', 160)):
        m = re.search(r'static_assert\(sizeof\(rxpost::%s\)\s*==\s*(\d+)'
                      % macro, drv_text)
        got = int(m.group(1)) if m else None
        good = (got == want)
        print('  %-22s static_assert %s  %s'
              % ('sizeof(%s)' % macro, got, 'OK' if good else 'MISMATCH'))
        if not good:
            ok = False

    # ---- 3. the probe's byte offsets must equal the driver's layout ----
    offs, total = hdr_offsets(HDR_FIELDS)
    e = parse_core_enum(core_text)
    print()
    print('  header: driver struct = %d B, probe RXB_HDR_BYTES = %s'
          % (total, e.get('RXB_HDR_BYTES')))
    if e.get('RXB_HDR_BYTES') != total:
        print('  MISMATCH: the probe would read every field at the wrong offset')
        ok = False

    # The probe's enum names differ from the struct fields (RXB_ prefix, and a
    # couple of spellings), so the mapping is explicit rather than guessed.
    pairs = [
        ('RXB_MAGIC', 'magic'), ('RXB_VERSION', 'version'),
        ('RXB_RECSIZE_SLOT', 'recSizeSlot'),
        ('RXB_RECSIZE_REARM', 'recSizeRearm'),
        ('RXB_HEAD', 'head'), ('RXB_WRAPPED', 'wrapped'),
        ('RXB_DROPPED', 'dropped'), ('RXB_SLOT_CAPACITY', 'slotCapacity'),
        ('RXB_REARM_CAPACITY', 'rearmCapacity'),
        ('RXB_REARM_FIRSTSEQ', 'rearmFirstSeq'), ('RXB_RING_GEN', 'ringGen'),
        ('RXB_BASELINE_ACTIVE', 'baselineActive'),
        ('RXB_BASELINE_SLOTS', 'baselineSlots'),
        ('RXB_BASELINE_VALID', 'baselineValid'),
        ('RXB_BASELINE_ZERO', 'baselineAddrZero'),
        ('RXB_BASELINE_CAPD', 'baselineCapDesc'),
        ('RXB_BASELINE_CAPC', 'baselineCapConst'),
        ('RXB_BASELINE_CAPBAD', 'baselineCapBad'),
        ('RXB_BASELINE_TORN', 'baselineTorn'),
        ('RXB_BASELINE_COUNT', 'baselineCount'),
        ('RXB_BASELINE_GENMOV', 'baselineGenMoved'),
        ('RXB_PUB_ID', 'pubId'), ('RXB_EPOCH', 'epoch'),
        ('RXB_IF_UNIT', 'ifUnit'), ('RXB_VTD_PATH', 'vtdPath'),
        ('RXB_RX_BUFFER_SIZE', 'rxBufferSize'), ('RXB_FLAGS', 'flags'),
        ('RXB_T_BASELINE_LO', 'tBaseline'),
        ('RXB_WATERMARK_LO', 'rearmSeqAtBaseline'),
        ('RXB_T_PUBLISHED_LO', 'tPublished'),
        ('RXB_REARM_REQUIRED', 'rearmRequired'),
        ('RXB_REARM_PUBLISHED', 'rearmPublished'),
    ]
    bad = []
    for ename, fname in pairs:
        if e.get(ename) != offs[fname]:
            bad.append((ename, e.get(ename), offs[fname]))
    if bad:
        print('  MISMATCH in %d offset(s):' % len(bad))
        for ename, got, want in bad[:8]:
            print('    %-24s probe=%s driver=%s' % (ename, got, want))
        ok = False
    else:
        print('  all %d header offsets agree  OK' % len(pairs))

    # ---- 4. the record sizes must agree on all three sides ----
    print()
    slot_off = 0
    rearm_off = 0
    for name, size in SLOT_FIELDS:
        if name == 'slot':
            slot_off = slot_off
        slot_off += size
    rearm_off = 0
    rearm_seq = None
    for name, size in REARM_FIELDS:
        if size == 8 and rearm_off % 8:
            rearm_off += 8 - (rearm_off % 8)
        if name == 'seq':
            rearm_seq = rearm_off
        rearm_off += size

    checks = [
        ('RXB_SLOT_BYTES', sum(s for _, s in SLOT_FIELDS), 'slot record'),
        ('RXB_REARM_BYTES', sum(s for _, s in REARM_FIELDS), 'rearm record'),
    ]
    for ename, want, what in checks:
        got = e.get(ename)
        good = (got == want)
        print('  %-22s %s = %s (struct says %d)  %s'
              % (what, ename, got, want, 'OK' if good else 'MISMATCH'))
        if not good:
            ok = False

    # ---- 5. the protocol's seq word ----
    #
    # The rearm ring reuses obslog's ticket protocol, which assumes `seq` is the
    # low half of a whole 8-byte word. If the field ever moved to a non-8-aligned
    # offset the protocol would split a word between two fields.
    m = re.search(r'#define kRxPostRearmSeqOff\s+\(\(unsigned int\)'
                  r'__builtin_offsetof\(rxpost::RearmRec,\s*seq\)\)', drv_text)
    print()
    print('  seq offset in the driver struct : %s' % rearm_seq)
    print('  kRxPostRearmSeqOff macro        : %s'
          % ('present' if m else 'NOT FOUND'))
    if not m:
        ok = False
    if rearm_seq is None or rearm_seq % 8 != 0:
        print('  MISMATCH: seq is not 8-byte aligned; the protocol cannot use '
              'a whole-word atomic')
        ok = False
    else:
        print('  seq word index                  : %d  OK' % (rearm_seq // 8))

    # The probe must read seq from the same byte.
    m2 = re.search(r'a\.seq\s*=\s*rd32\(p \+ (\d+)\)', core_text)
    got = int(m2.group(1)) if m2 else None
    print('  probe reads seq at byte         : %s  %s'
          % (got, 'OK' if got == rearm_seq else 'MISMATCH'))
    if got != rearm_seq:
        ok = False

    # ---- 6. the test must use the same sizes ----
    #
    # The host test asserts against the header directly, so this is a weaker
    # check; it exists to catch a test that hard-codes a stale size and would
    # then pass while exercising a different layout.
    print()
    for name, want in (('kRxPostSlotBytes', sum(s for _, s in SLOT_FIELDS)),
                       ('kRxPostRearmBytes', sum(s for _, s in REARM_FIELDS))):
        used = name in test_text
        print('  %-22s used by the test  %s' % (name, 'YES' if used else 'no'))
        if not used:
            print('    (the test relies on sizeof(); acceptable, noted)')

    # The former fourth declaration (tools/analyze-round12.py) was retired with
    # that file; the three declarations above are the whole contract now.

    print()
    print('  RESULT: %s' % ('CONSISTENT' if ok else 'FAILURES'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
