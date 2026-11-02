#!/usr/bin/env python3
"""Round-10: extract the driver snapshot the probe ACTUALLY consumed.

WHY THIS IS THE ONLY CORRECT SOURCE
-----------------------------------
The snapshot is a single OSData property (`rtl812x-obs-snapshot`) on the
RTL8125 driver node. `props.txt` in the capture is the probe node's properties,
which include the *decoded summary* the probe produced but NOT the raw bytes.

The raw bytes live in `props.raw.txt` (the full ioreg dump) because the driver
node is in there. Reading ioreg again NOW would give a DIFFERENT, later
publication -- that is exactly the mistake round 9 made when it archived a
snapshot 87 s newer than the runtime one and quoted it as if it were the same.

So: pull the blob out of the capture's own props.raw.txt, hash it, and write
it beside the capture. Every later tool reads that file, never ioreg.
"""
import hashlib
import os
import re
import sys

CAP = sys.argv[1] if len(sys.argv) > 1 else 'docs/evidence/20261101-130000'
RAW = os.path.join(CAP, 'props.raw.txt')
OUT = os.path.join(CAP, 'driver-snapshot.bin')


def main():
    txt = open(RAW, encoding='utf-8', errors='replace').read()
    m = re.search(r'"rtl812x-obs-snapshot"\s*=\s*<([0-9a-fA-F]+)>', txt)
    if not m:
        raise SystemExit('no rtl812x-obs-snapshot in %s' % RAW)
    blob = bytes.fromhex(m.group(1))
    with open(OUT, 'wb') as f:
        f.write(blob)
    print('props.raw.txt   %d B  sha256=%s'
          % (os.path.getsize(RAW), hashlib.sha256(
              open(RAW, 'rb').read()).hexdigest()))
    print('snapshot        %d B  sha256=%s'
          % (len(blob), hashlib.sha256(blob).hexdigest()))
    print('written         %s' % OUT)

    # Sanity: the header must be self-consistent before anything trusts it.
    import struct
    if len(blob) < 104:
        raise SystemExit('snapshot shorter than a header')
    f = struct.unpack('<20I', blob[:80])
    names = ['magic', 'version', 'recSize', 'capacity', 'head', 'wrapped',
             'dropped', 'pubId', 'firstTicket', 'lastTicket', 'validCount',
             'lostCount', 'epoch', 'busDevFn', 'vendorId', 'deviceId',
             'ifUnit', 'macHi', 'macLo', 'flags']
    for n, v in zip(names, f):
        print('  %-12s 0x%-10x %d' % (n, v, v))
    print('  tStart      %d' % struct.unpack('<Q', blob[80:88])[0])
    print('  tPublished  %d' % struct.unpack('<Q', blob[88:96])[0])
    print('  records     %d' % ((len(blob) - 104) // 72))


if __name__ == '__main__':
    main()
