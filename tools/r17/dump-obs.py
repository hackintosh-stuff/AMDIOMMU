#!/usr/bin/env python3
"""Decode the probe's used OBS snapshot straight off ioreg (diagnostics only).

Prints the publication header and every business record for the declared token
so the actual submit/done pairing of one run can be inspected without a capture
directory. Not evidence: analyze.py re-derives everything from archived bytes.
"""
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('round12_decode',
                                             ROOT / 'tools' / 'analyze-round12.py')
A = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A)


def main():
    token = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0
    text = subprocess.check_output(
        ['ioreg', '-l', '-w0', '-r', '-c', 'org_maz1_AMDMapperProbe'], text=True)
    matches = re.findall(r'"m2-b2-obs-snapshot-used"\s*=\s*<([0-9a-fA-F]+)>', text)
    if len(matches) != 1:
        print('snapshot property missing or duplicated: %d' % len(matches))
        return 2
    blob = bytes.fromhex(matches[0])
    h = A.decode_header(blob)
    print('records=%d head=%d dropped=%d wrapped=%d lost=%d flags=0x%x tPublished=%d' % (
        h['recordCount'], h['head'], h['dropped'], h['wrapped'], h['lostCount'],
        h['flags'], h['tPublished']))
    rows = [A.valid_record(blob, h, i) for i in range(h['recordCount'])]
    bad = sum(1 for r in rows if r is None)
    print('torn=%d' % bad)
    for r in rows:
        if r is None:
            continue
        if token and r['token'] != token:
            continue
        print('kind=%d cum=%-5d slot=%-4d gen=%-3d len=%-5d addr=0x%x opts1=0x%08x '
              'req=%d pkt=0x%x flags=0x%x t=%d' % (
                  r['kind'], r['cum'], r['slot'], r['gen'], r['len'], r['addr'],
                  r['opts1'], r['reqId'], r['pkt'], r['flags'], r['t']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
