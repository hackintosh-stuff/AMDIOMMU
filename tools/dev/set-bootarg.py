#!/usr/bin/env python3
"""Set the EFI boot-args to declare this run's token and batch.

WHY THE EFI FILE AND NOT JUST `nvram`
-------------------------------------
OpenCore's `NVRAM:Add` overwrites the NVRAM boot-args on EVERY boot. Changing
only `nvram boot-args` therefore never takes effect: the next boot replaces it
with whatever the config.plist says. This project lost two runs to that.

The declaration has to be written into BOTH places:
  * config.plist  -- so it survives the boot;
  * nvram         -- so it applies to a reboot that happens before OpenCore
                     rewrites it (and so a read-back can be checked now).

Usage: set-bootarg.py <config.plist> <amdiommu-value>
Prints the old and new value, and verifies the write.
"""
import os
import plistlib
import shutil
import sys

GUID = '7C436110-AB2A-4BBB-A880-FE41995C9F82'


def main():
    if len(sys.argv) < 3:
        print('usage: set-bootarg.py <config.plist> <amdiommu-value>')
        return 2
    path, value = sys.argv[1], sys.argv[2]
    if not os.path.isfile(path):
        print('FAIL: no config.plist at %s' % path)
        return 1
    with open(path, 'rb') as f:
        d = plistlib.load(f)
    try:
        cur = d['NVRAM']['Add'][GUID]['boot-args']
    except KeyError:
        print('FAIL: the NVRAM:Add boot-args entry is not where it is expected')
        return 1

    toks = [t for t in cur.split() if not t.startswith('amdiommu=')]
    toks.append(value)
    new = ' '.join(toks)
    print('old: %s' % cur)
    print('new: %s' % new)

    d['NVRAM']['Add'][GUID]['boot-args'] = new
    # Atomic replace: write to a sibling then rename, so an interrupted write
    # cannot leave a truncated config.plist on the EFI partition.
    tmp = path + '.tmp'
    with open(tmp, 'wb') as f:
        plistlib.dump(d, f)
    shutil.move(tmp, path)

    with open(path, 'rb') as f:
        back = plistlib.load(f)
    got = back['NVRAM']['Add'][GUID]['boot-args']
    if got != new:
        print('FAIL: the write did not stick; read back %r' % got)
        return 1
    print('verified: config.plist now declares %s'
          % [t for t in got.split() if t.startswith('amdiommu=')])
    return 0


if __name__ == '__main__':
    sys.exit(main())
