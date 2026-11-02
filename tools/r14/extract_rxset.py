#!/usr/bin/env python3
"""extract_rxset.py -- round 14: extract the RX post blob the probe DECODED.

WHY THIS IS A SEPARATE EXTRACTOR FROM extract_snapshot.py
--------------------------------------------------------
The two blobs answer different questions and are published as different
properties:

  rtl812x-obs-snapshot   the driver's submit/complete log (round 10/11)
  rtl812x-rxpost         the RX baseline + rearm log   (round 14)

The probe exports the exact bytes it decoded for EACH as
`m2-b2-obs-snapshot-used` and `m2-b2-rxset-raw`, with the sha256 it computed
alongside. This script does the same three things for the RX blob that round 11
did for the observation log:

  1. extract the probe's export (NOT the driver's live property) to
     rxset-raw.bin;
  2. hash the result and require it to equal the probe's published sha256, so
     the archived bytes are provably the ones the set was built from;
  3. ALSO extract the driver's own property to rxset-driver-later.bin, clearly
     labelled, so the gap between the two publications is a measurement.

Exit non-zero when the probe did not export a blob it claims to have used.
"The run looked fine but there is no re-checkable input" is the failure this
script exists to make impossible.
"""
import hashlib
import os
import re
import struct
import sys

HDR_BYTES = 160
SLOT_BYTES = 32
REARM_BYTES = 48
SLOT_MAX = 1024

HDR_NAMES = [
    'magic', 'version', 'recSizeSlot', 'recSizeRearm',
    'head', 'wrapped', 'dropped', 'slotCapacity', 'rearmCapacity',
    'rearmFirstSeq', 'ringGen', 'baselineActive',
    'baselineSlots', 'baselineValid', 'baselineAddrZero',
    'baselineCapDesc', 'baselineCapConst', 'baselineCapBad', 'baselineTorn',
    'baselineCount', 'baselineGenMoved', 'pubId', 'epoch', 'ifUnit',
    'vtdPath', 'rxBufferSize', 'flags', 'pad0',
]


def sha(b):
    return hashlib.sha256(b).hexdigest()


def summary(blob, label):
    if len(blob) < HDR_BYTES:
        print('  %-24s shorter than a header (%d B)' % (label, len(blob)))
        return None
    f = struct.unpack('<28I', blob[:112])
    d = dict(zip(HDR_NAMES, f))
    tbase, watermark, tpub = struct.unpack('<3Q', blob[112:136])
    required, published = struct.unpack('<2I', blob[136:144])
    slots_b = SLOT_MAX * SLOT_BYTES
    rest = len(blob) - HDR_BYTES - slots_b
    n = rest // REARM_BYTES if rest >= 0 else -1
    print('  %-24s %6d B  pub=%d head=%d gen=%d baseline=%d rearm=%d/%d'
          % (label, len(blob), d['pubId'], d['head'], d['ringGen'],
             d['baselineSlots'], published, required))
    print('  %-24s watermark=%d tBaseline=%d tPublished=%d'
          % ('', watermark, tbase, tpub))
    return {'hdr': d, 'watermark': watermark, 'tbaseline': tbase,
            'tpub': tpub, 'required': required, 'published': published,
            'rearm_records': n}


def main():
    cap = sys.argv[1] if len(sys.argv) > 1 else '.'
    raw_path = os.path.join(cap, 'props.raw.txt')
    props_path = os.path.join(cap, 'props.txt')
    if not os.path.exists(raw_path):
        print('FAIL: no props.raw.txt in %s' % cap)
        return 1
    raw = open(raw_path, encoding='utf-8', errors='replace').read()
    props = (open(props_path, encoding='utf-8', errors='replace').read()
             if os.path.exists(props_path) else '')

    print('=' * 78)
    print('EXTRACTING THE RX POST BLOB THE PROBE USED')
    print('capture: %s' % cap)
    print('=' * 78)

    # ---- 1. did the probe say it exported one? ----
    mstate = re.search(r'"m2-b2-rxset-raw-state"\s*=\s*"([^"]*)"', props)
    state = mstate.group(1) if mstate else '(absent)'
    print('  probe m2-b2-rxset-raw-state : %s' % state)

    m = re.search(r'"m2-b2-rxset-raw"\s*=\s*<([0-9a-fA-F]+)>', raw)
    if not m:
        # A probe that never read the publication is a legitimate outcome, but
        # it is NOT a coverage result. Say which it is instead of writing an
        # empty file that a later reader could mistake for a set.
        mwhy = re.search(r'"m2-b2-rxset-why"\s*=\s*"([^"]*)"', props)
        why = mwhy.group(1) if mwhy else '(absent)'
        print('  FAIL: the probe did not export m2-b2-rxset-raw.')
        print('        probe reason: %s' % why)
        print('        Without it the RX set has no re-checkable input.')
        with open(os.path.join(cap, 'RXSET-NOT-EXPORTED.txt'), 'w') as f:
            f.write('m2-b2-rxset-raw : ABSENT\n')
            f.write('m2-b2-rxset-why : %s\n' % why)
            f.write('\nThe probe did not decode an rtl812x-rxpost blob, so this\n'
                    'run has no RX coverage evidence. This is a REFUSAL, not a\n'
                    'pass: a set that was never read cannot be covered.\n')
        return 1
    used = bytes.fromhex(m.group(1))

    # ---- 2. the probe's published sha256 ----
    sm = (re.search(r'"m2-b2-rxset-raw-sha256"\s*=\s*"([0-9a-f]{64})"', props)
          or re.search(r'"m2-b2-rxset-raw-sha256"\s*=\s*"([0-9a-f]{64})"', raw))
    if not sm:
        print('  FAIL: the probe did not publish m2-b2-rxset-raw-sha256.')
        return 1
    probe_sha = sm.group(1)
    used_sha = sha(used)
    print('  probe published sha256 : %s' % probe_sha)
    print('  extracted bytes sha256 : %s' % used_sha)
    if used_sha != probe_sha:
        print('  FAIL: the exported bytes do not hash to the published value.')
        return 1
    print('  MATCH: the export IS the blob the probe decoded.')

    out = os.path.join(cap, 'rxset-raw.bin')
    with open(out, 'wb') as f:
        f.write(used)
    info = summary(used, 'rxset-raw.bin')
    print('  wrote %s' % out)

    # ---- 3. the driver's own property, never used as evidence ----
    m2 = re.search(r'"rtl812x-rxpost"\s*=\s*<([0-9a-fA-F]+)>', raw)
    if m2:
        later = bytes.fromhex(m2.group(1))
        with open(os.path.join(cap, 'rxset-driver-later.bin'), 'wb') as f:
            f.write(later)
        linfo = summary(later, 'rxset-driver-later')
        if info and linfo:
            print()
            print('  NOTE: rxset-driver-later.bin is the driver node at ioreg')
            print('        time, a LATER publication. It is kept so the gap is')
            print('        visible, never as evidence.')
            print('        publication %d (probe) vs %d (later), tPublished '
                  'differs by %.3f s'
                  % (info['hdr']['pubId'], linfo['hdr']['pubId'],
                     (linfo['tpub'] - info['tpub']) / 1e9))

    # ---- 4. what the probe concluded, for the human reading the archive ----
    for key in ('m2-b2-rxset', 'm2-b2-rxset-why', 'm2-b2-rxset-set-why',
                'm2-b2-rxset-complete', 'm2-b2-rxset-ranges',
                'm2-b2-rxset-walked', 'm2-b2-rxset-ok', 'm2-b2-rxset-fail',
                'm2-b2-rxset-walk', 'm2-b2-rxset-watermark',
                'm2-b2-rxset-head'):
        mm = re.search(r'"%s"\s*=\s*"([^"]*)"' % re.escape(key), props)
        if mm:
            print('  %-28s %s' % (key, mm.group(1)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
