#!/usr/bin/env python3
"""Decode the live driver TX snapshot straight off ioreg (diagnostics only).

Reads the OSData published as rtl812x-txmap-raw and prints the header plus one
line per recorded generation. It is a debugging aid, not evidence: nothing here
is used by analyze.py, and analyze.py never trusts a decoded summary either.
"""
import re
import subprocess
import sys

sys.path.insert(0, __file__.rsplit('/', 1)[0])
from analyze import decode_driver  # noqa: E402


def main():
    text = subprocess.check_output(['ioreg', '-l', '-w0', '-r', '-c', 'RTL8125'],
                                   text=True)
    matches = re.findall(r'"rtl812x-txmap-raw"\s*=\s*<([0-9a-fA-F]+)>', text)
    if len(matches) != 1:
        print('raw snapshot property missing or duplicated: %d' % len(matches))
        return 2
    blob = bytes.fromhex(matches[0])
    h, rows = decode_driver(blob)
    print('bytes=%d count=%d bdf=0x%x token=0x%08x dropped=%u state=%u '
          'retired=%u rejected=%u maxHeld=%u' % (
              h['bytes'], h['count'], h['bdf'], h['token'], h['dropped'],
              h['state'], h['retired'], h['rejected'], h['maxHeld']))
    for i, r in enumerate(rows[:h['count']]):
        segs = [(s['address'], s['length']) for s in r['iova'][:r['count']]]
        desc = [(d['address'], d['length'], d['opts1'] & 0xFFFFFFFF)
                for d in r['descriptors'][:r['count']]]
        print('%2d req=%2d handle=%d segs=%d tMap=%d tOwn=%d tDone=%d tRetire=%d '
              'tFree=%d firstSlot=%d close=%d/%d' % (
                  i + 1, r['req'], r['handle'], r['count'], r['tMap'], r['tOwn'],
                  r['tDone'], r['tRetire'], r['tFree'], r['firstSlot'],
                  r['doneClose'], r['closeMask']))
        print('    physical=%s' % ([(s['address'], s['length'])
                                   for s in r['physical'][:r['count']]],))
        print('    iova=%s' % (segs,))
        print('    desc=%s' % (desc,))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
