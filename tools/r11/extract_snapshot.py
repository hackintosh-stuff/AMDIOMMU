#!/usr/bin/env python3
"""extract_snapshot.py -- round 11: extract the snapshot the probe ACTUALLY used.

WHY THIS REPLACES THE ROUND-10 VERSION
--------------------------------------
Round 10's extractor pulled `rtl812x-obs-snapshot` out of props.raw.txt and
hash-checked it against props.raw.txt. That proves the extraction was faithful
and NOTHING about whether it was the snapshot the probe decoded.

It was not. The probe used publication 27 (head 385, firstTicket 1,
tPublished 41,305,180,913 ns). props.raw.txt is a dump of the whole IOService
plane taken after the run, and by then the driver's watchdog had published
publication 71 (head 646, firstTicket 135, tPublished 85,309,619,659 ns) -- 43
seconds later. The analyser's 61 checks were all run against the later one.

Round 11's probe exports the exact bytes it decoded, as
`m2-b2-obs-snapshot-used`, plus their sha256 as `m2-b2-obs-used-sha256`.
This script:

  1. extracts that property (NOT rtl812x-obs-snapshot) to
     obs-snapshot-used.bin;
  2. hashes the result and requires it to equal the probe's published sha256;
  3. ALSO extracts the driver's own property, if present, to
     driver-snapshot-later.bin -- clearly named, never used as evidence, so a
     human can see how far apart the two publications are;
  4. prints both, so the difference is visible rather than inferred.

Exit non-zero if the probe's export is missing or the hash does not match. A
missing export is not "nothing to do": it means the round has no re-checkable
input, which is exactly the round-10 failure.
"""
import hashlib
import os
import re
import struct
import sys

HDR_BYTES = 104
REC_BYTES = 72


def sha(b):
    return hashlib.sha256(b).hexdigest()


def header_summary(blob, label):
    if len(blob) < HDR_BYTES:
        print('  %-22s shorter than a header (%d B)' % (label, len(blob)))
        return
    f = struct.unpack('<20I', blob[:80])
    names = ['magic', 'version', 'recSize', 'capacity', 'head', 'wrapped',
             'dropped', 'pubId', 'firstTicket', 'lastTicket', 'validCount',
             'lostCount', 'epoch', 'busDevFn', 'vendorId', 'deviceId',
             'ifUnit', 'macHi', 'macLo', 'flags']
    d = dict(zip(names, f))
    tp = struct.unpack('<Q', blob[88:96])[0]
    print('  %-22s %d B  pub=%d head=%d first=%d tPublished=%d records=%d'
          % (label, len(blob), d['pubId'], d['head'], d['firstTicket'], tp,
             (len(blob) - HDR_BYTES) // REC_BYTES))


def main():
    cap = sys.argv[1] if len(sys.argv) > 1 else 'docs/evidence/20261101-130000'
    raw_path = os.path.join(cap, 'props.raw.txt')
    props_path = os.path.join(cap, 'props.txt')
    if not os.path.exists(raw_path):
        print('FAIL: no props.raw.txt in %s' % cap)
        return 1

    raw = open(raw_path, encoding='utf-8', errors='replace').read()
    props = (open(props_path, encoding='utf-8', errors='replace').read()
             if os.path.exists(props_path) else '')

    print('=' * 78)
    print('EXTRACTING THE SNAPSHOT THE PROBE USED')
    print('capture: %s' % cap)
    print('=' * 78)

    # ---- 1. the probe's own export ----
    m = re.search(r'"m2-b2-obs-snapshot-used"\s*=\s*<([0-9a-fA-F]+)>', raw)
    if not m:
        print('  FAIL: the probe did not export m2-b2-obs-snapshot-used.')
        print('        Without it there is no way to prove which snapshot the')
        print('        verdicts were computed from. Round 10 analysed a')
        print('        publication 43 s later than the one the probe used.')
        return 1
    used = bytes.fromhex(m.group(1))

    # ---- 2. the probe's published sha256 ----
    sm = re.search(r'"m2-b2-obs-used-sha256"\s*=\s*"([0-9a-f]{64})"', props) or \
         re.search(r'"m2-b2-obs-used-sha256"\s*=\s*"([0-9a-f]{64})"', raw)
    if not sm:
        print('  FAIL: the probe did not publish m2-b2-obs-used-sha256.')
        return 1
    probe_sha = sm.group(1)

    used_sha = sha(used)
    print('  probe published sha256 : %s' % probe_sha)
    print('  extracted bytes sha256 : %s' % used_sha)
    if used_sha != probe_sha:
        print('  FAIL: the exported bytes do not hash to the published value.')
        print('        The export is not the snapshot the probe decoded.')
        return 1
    print('  MATCH: the export IS the snapshot the probe decoded.')

    used_path = os.path.join(cap, 'obs-snapshot-used.bin')
    with open(used_path, 'wb') as f:
        f.write(used)
    header_summary(used, 'obs-snapshot-used.bin')
    print('  wrote %s' % used_path)

    # ---- 3. the driver's later property, kept but never used as evidence ----
    m2 = re.search(r'"rtl812x-obs-snapshot"\s*=\s*<([0-9a-fA-F]+)>', raw)
    if m2:
        later = bytes.fromhex(m2.group(1))
        later_path = os.path.join(cap, 'driver-snapshot-later.bin')
        with open(later_path, 'wb') as f:
            f.write(later)
        header_summary(later, 'driver-snapshot-later')
        print('  wrote %s' % later_path)
        print()
        print('  NOTE: driver-snapshot-later.bin is the driver node\'s state at')
        print('        ioreg time. It is NOT the snapshot the probe used and')
        print('        must never be analysed as if it were. Round 10 did')
        print('        exactly that.')
        # Show the gap explicitly, so it is a measurement rather than a story.
        if len(later) >= 96 and len(used) >= 96:
            lu = struct.unpack('<I', used[28:32])[0]
            ll = struct.unpack('<I', later[28:32])[0]
            tu = struct.unpack('<Q', used[88:96])[0]
            tl = struct.unpack('<Q', later[88:96])[0]
            print('        publication %d (probe) vs %d (later), '
                  'tPublished differs by %.3f s'
                  % (lu, ll, (tl - tu) / 1e9))

    # ---- 4. what the probe said it used ----
    for key in ('m2-b2-obs-used-pub-id', 'm2-b2-obs-used-t-published',
                'm2-b2-obs-used-bytes', 'm2-b2-obs-used-hash-stable',
                'm2-b2-obs-epoch-binding', 'm2-b2-obs-epoch-bound'):
        mm = re.search(r'"%s"\s*=\s*"([^"]*)"' % re.escape(key), props)
        if mm:
            print('  %-28s %s' % (key, mm.group(1)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
