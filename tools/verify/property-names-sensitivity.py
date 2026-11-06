#!/usr/bin/env python3
"""verify-property-names-sensitivity.py -- the collision check must SEE one.

WHY THIS EXISTS
---------------
The first version of tools/verify/property-names.py used one regex with
`[^,]+` for the leading argument, so it required a comma before the property key.
Every two-argument `setProperty("key", value)` was skipped, and the script
reported "no collisions" -- while the collision it exists for was present in the
tree. A checker that silently sees nothing passes every assertion it makes.

So this script reintroduces the exact round-14 defect (a status string written
under the blob's property name) into a COPY of the kext sources and requires the
checker to report it, naming the property.

It also requires the real tree to pass, so a checker that fails on everything
cannot be mistaken for sensitivity.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SRC = os.path.join(ROOT, 'kext', 'AMDMapperProbeRxSetDebug.cpp')
CHECKER = os.path.join(HERE, 'property-names.py')

FAILS = []


def check(name, ok, detail=''):
    print('  %-62s %s%s' % (name, 'PASS' if ok else 'FAIL',
                            '   [%s]' % detail if detail and not ok else ''))
    if not ok:
        FAILS.append(name)


def run_checker(root):
    """Run the checker with ROOT overridden to `root`."""
    # The checker computes ROOT from its own location, so the tree to scan is
    # supplied by copying the checker next to the mutated tree instead of by
    # patching it -- a patched checker would not be the shipped one.
    #
    # When `root` IS the real tree the copy would be onto itself, so that case
    # runs the shipped file in place.
    if os.path.abspath(root) == os.path.abspath(ROOT):
        target = CHECKER
    else:
        tools = os.path.join(root, 'tools', 'r14')
        os.makedirs(tools, exist_ok=True)
        target = os.path.join(tools, 'property-names.py')
        shutil.copy(CHECKER, target)
    r = subprocess.run([sys.executable, target],
                       capture_output=True, text=True)
    return r, (r.stdout + r.stderr)


def main():
    print('=' * 78)
    print('PROPERTY-NAME CHECK: is it sensitive to a real collision?')
    print('=' * 78)

    if not os.path.isfile(SRC):
        print('FAIL: missing %s' % SRC)
        return 1

    # ---- 1. the real tree must pass ----
    r, out = run_checker(ROOT)
    check('the real tree passes the collision check', r.returncode == 0,
          (out or '')[-400:])
    check('the checker reports how much it scanned',
          'property writes matched' in out, (out or '')[-300:])

    # ---- 2. a mutated copy must FAIL, naming the property ----
    #
    # The work tree is created under the PROJECT, not under the platform temp
    # directory: the Windows sandbox refuses writes to a temp path it created for
    # another process, and a PermissionError there would read as a checker
    # failure. tools/dev/patch-rmtree.py's force-delete handles the read-only
    # bits a copied tree inherits.
    work = os.path.join(ROOT, 'build-work-r14', 'propname-case')
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work, exist_ok=True)
    try:
        dst_kext = os.path.join(work, 'kext')
        shutil.copytree(os.path.join(ROOT, 'kext'), dst_kext)
        p = os.path.join(dst_kext, 'AMDMapperProbeRxSetDebug.cpp')
        text = open(p, encoding='utf-8').read()

        # Reintroduce the defect: the status string goes back under the blob's
        # key. This is the exact line that was wrong.
        needle = 'setProperty("m2-b2-rxset-raw-state",'
        if needle not in text:
            check('the shipped source has the corrected property name', False)
            return 1
        text = text.replace(needle,
                            'setProperty("m2-b2-rxset-raw",', 1)
        with open(p, 'w', newline='\n') as f:
            f.write(text)

        r2, out2 = run_checker(work)
        check('the collided tree FAILS the check', r2.returncode != 0,
              'it exited 0 -- the checker cannot see the defect')
        check('the failure names m2-b2-rxset-raw',
              'm2-b2-rxset-raw' in out2, (out2 or '')[-400:])
        check('the failure explains that IOKit replaces the property',
              'IOKit replaces a property' in out2, (out2 or '')[-400:])
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print()
    print('  RESULT: %s' % ('COLLISION CHECK IS SENSITIVE' if not FAILS
                            else 'FAILURES: %s' % FAILS))
    return 0 if not FAILS else 1


if __name__ == '__main__':
    sys.exit(main())
