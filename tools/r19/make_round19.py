#!/usr/bin/env python3
"""Derive tools/r19 from tools/r18 (one-shot bootstrap, kept for provenance).

Round 19 is the same pipeline with a wider accepted layout, so the tooling is
copied and renamed rather than re-invented. The driver template and the host
tests are then edited by hand -- this script only does the mechanical part and
refuses to run twice.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / 'tools' / 'r18'
DST = ROOT / 'tools' / 'r19'
FILES = ['driver-template.py', 'test-native-main.inc', 'test-driver.py',
         'analyze.py', 'test-analyze.py', 'protocol.py', 'load.py', 'peer.py',
         'capture.sh', 'capture-archive.py', 'deploy.py', 'disarm-next.py',
         'verify-final-state.py', 'load-daemon.plist']


def main():
    DST.mkdir(exist_ok=True)
    for name in FILES:
        src = SRC / name
        dst = DST / name
        if dst.exists():
            print('refusing to overwrite %s' % dst, file=sys.stderr)
            return 1
        text = src.read_text(encoding='utf-8')
        dst.write_text(text, encoding='utf-8', newline='\n')
    # Mechanical renames: only the tooling's own round labels change. The driver
    # keeps the r18std:: namespace, the RTL812xTxMapStd.hpp ABI and the m2-3c-*
    # probe properties, because the standard path is the same code in the driver
    # and the same properties in the probe.
    for name in FILES:
        p = DST / name
        text = p.read_text(encoding='utf-8')
        text = text.replace('tools/r18', 'tools/r19')
        text = text.replace('org.example.round18load', 'org.example.round19load')
        text = text.replace('round18load', 'round19load')
        text = text.replace('r18cap-run4c', 'r19cap-run1')
        text = text.replace('r18-run6-20261101', 'r19-run1-20261101')
        text = text.replace('round18', 'round19').replace('Round18', 'Round19')
        text = text.replace('round 18', 'round 19')
        text = text.replace('r18-', 'r19-')
        p.write_text(text, encoding='utf-8', newline='\n')
    print('tools/r19 bootstrapped from tools/r18 (%d files)' % len(FILES))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
