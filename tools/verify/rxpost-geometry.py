#!/usr/bin/env python3
"""verify-rxpost-geometry.py -- the geometry assertion must be SENSITIVE.

WHY THIS EXISTS
---------------
Round 14's first real-machine run failed with `ragged-rearm-body`. The cause was
that publishCopy() started its copy at offset 0, so the slot array overwrote the
header, and the blob came out kRxPostHdrBytes short.

The host test did not catch it, because its publish() helper used the same wrong
origin for writing and for reading. Adding an assertion is not enough: an
assertion that would also pass on the broken code proves nothing. So this script
reintroduces the exact defect -- one line, `u32 off = kRxPostHdrBytes;` becomes
`u32 off = 0;` -- rebuilds the SAME test source against it, and requires the
geometry checks to FAIL.

It also requires the same build to pass with the defect removed, so a test that
fails for an unrelated reason cannot be mistaken for sensitivity.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
HDR = os.path.join(ROOT, 'tools', 'lucy-obs', 'RTL812xRxPost.hpp')
TEST = os.path.join(ROOT, 'tests', 'rxpost-test.cpp')
KEXT = os.path.join(ROOT, 'probe')

FAILS = []


def check(name, ok, detail=''):
    print('  %-62s %s%s' % (name, 'PASS' if ok else 'FAIL',
                            '   [%s]' % detail if detail and not ok else ''))
    if not ok:
        FAILS.append(name)


def build_and_run(hdr_text, work, tag):
    d = os.path.join(work, tag)
    os.makedirs(d, exist_ok=True)
    shutil.copy(HDR, os.path.join(d, 'RTL812xRxPost.hpp'))
    with open(os.path.join(d, 'RTL812xRxPost.hpp'), 'w', newline='\n') as f:
        f.write(hdr_text)
    # The write protocol header is needed too, unmodified.
    shutil.copy(os.path.join(ROOT, 'tools', 'lucy-obs', 'RTL812xObsWrite.hpp'),
                os.path.join(d, 'RTL812xObsWrite.hpp'))
    exe = os.path.join(d, 'rxpost-test')
    c = subprocess.run(
        ['clang++', '-std=c++17', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
         '-O1', '-g', '-pthread', '-fsanitize=thread',
         '-I', KEXT, '-I', d, TEST, '-o', exe],
        capture_output=True, text=True)
    if c.returncode != 0:
        return None, (c.stderr or c.stdout)[-600:]
    r = subprocess.run([exe], capture_output=True, text=True)
    return r, (r.stdout + r.stderr)


def main():
    print('=' * 78)
    print('RX POST GEOMETRY: is the layout assertion sensitive to the defect?')
    print('=' * 78)

    if not (os.path.isfile(HDR) and os.path.isfile(TEST)):
        print('FAIL: missing header or test source')
        return 1

    good = open(HDR, encoding='utf-8').read()

    # The exact line that was wrong.
    if 'u32 off = kRxPostHdrBytes;' not in good:
        print('  FAIL: the corrected origin line is not present in the header.')
        print('        This check cannot tell what "the defect" is any more.')
        return 1

    broken = good.replace('u32 off = kRxPostHdrBytes;', 'u32 off = 0;', 1)

    work = tempfile.mkdtemp(prefix='rxgeom.')
    try:
        # ---- 1. the shipped header must pass ----
        r, out = build_and_run(good, work, 'good')
        check('the shipped header builds and the test passes',
              r is not None and r.returncode == 0,
              (out or '')[-300:] if r is None or r.returncode != 0 else '')

        # ---- 2. the broken header must FAIL the geometry checks ----
        r2, out2 = build_and_run(broken, work, 'broken')
        if r2 is None:
            check('the offset-0 variant builds', False, (out2 or '')[-400:])
        else:
            check('the offset-0 variant builds', True)
            check('the offset-0 variant FAILS the test', r2.returncode != 0,
                  'it exited 0 -- the geometry assertion is not sensitive')
            # And the failure must be the geometry checks, named, not something
            # incidental that happens to also be non-zero.
            #
            # The search is over the WHOLE output, not its tail: the broken
            # header also makes the concurrent test report a million torn
            # records, and a tail-only search would miss the geometry lines at
            # the top. That is not a hypothetical -- it is why this check failed
            # the first time it ran.
            for phrase in ('the header survived the copy',
                           'the slot array begins at kRxPostHdrBytes (slot byte 0 is 0)',
                           'publishCopy reports header + slots + rearms'):
                check('the failure names "%s"' % phrase,
                      phrase in out2,
                      'not found anywhere in %d bytes of output'
                      % len(out2 or ''))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print()
    print('  RESULT: %s' % ('GEOMETRY CHECK IS SENSITIVE' if not FAILS
                            else 'FAILURES: %s' % FAILS))
    return 0 if not FAILS else 1


if __name__ == '__main__':
    sys.exit(main())
