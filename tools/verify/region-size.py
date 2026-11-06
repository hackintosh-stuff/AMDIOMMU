#!/usr/bin/env python3
"""verify-region-size.py -- the region/layout assertions must REJECT the defect.

WHY THIS EXISTS
---------------
Round 14's run 5 panicked ~242 s after boot:

    Kernel trap type 14 = page fault, WRITE
    obslog::writeRecordSized<...>  <- rxpostRecordRearm <- rxInterrupt

because `kRxPostRegionBytes` was defined as `kRxPostSnapshotMax` -- one slot
array too small -- while `rxpostInit()` places the ring after TWO slot arrays.

The fix added compile-time static_asserts and a host test. Adding an assertion is
not enough: an assertion that would also pass on the broken code proves nothing.
So this script restores the EXACT broken definition in a copy of the header and
requires the build to FAIL, with a diagnostic naming the region/ring relation.

It also requires the shipped header to compile and pass, so a header that fails
for an unrelated reason cannot be mistaken for sensitivity.
"""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
HDR = os.path.join(ROOT, 'tools', 'lucy-obs', 'RTL812xRxPost.hpp')
TEST = os.path.join(ROOT, 'tests', 'rxpost-test.cpp')
KEXT = os.path.join(ROOT, 'kext')
WORKDIR = os.path.join(ROOT, 'build-work-r14', 'region-case')

FAILS = []


def check(name, ok, detail=''):
    print('  %-62s %s%s' % (name, 'PASS' if ok else 'FAIL',
                            '   [%s]' % detail if detail and not ok else ''))
    if not ok:
        FAILS.append(name)


def build(work, tag, hdr_text):
    d = os.path.join(work, tag)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, 'RTL812xRxPost.hpp'), 'w', newline='\n') as f:
        f.write(hdr_text)
    shutil.copy(os.path.join(ROOT, 'tools', 'lucy-obs', 'RTL812xObsWrite.hpp'),
                os.path.join(d, 'RTL812xObsWrite.hpp'))
    exe = os.path.join(d, 'rxpost-test')
    c = subprocess.run(
        ['clang++', '-std=c++17', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
         '-O1', '-g', '-pthread', '-fsanitize=thread',
         '-I', KEXT, '-I', d, TEST, '-o', exe],
        capture_output=True, text=True)
    if c.returncode != 0:
        return None, (c.stderr or c.stdout)
    r = subprocess.run([exe], capture_output=True, text=True)
    return r, (r.stdout + r.stderr)


def main():
    print('=' * 78)
    print('RX POST REGION: does the build reject a region one slot array short?')
    print('=' * 78)

    if not (os.path.isfile(HDR) and os.path.isfile(TEST)):
        print('FAIL: missing header or test source')
        return 1

    good = open(HDR, encoding='utf-8').read()

    # The corrected definition must be present, or this check cannot name the
    # defect it is testing for.
    if 'kRxPostSlotTables 2u' not in good:
        print('  FAIL: the header does not define kRxPostSlotTables 2u.')
        print('        This check cannot tell what "the defect" is any more.')
        return 1

    # ---- the exact regression: region == snapshot (one slot array) ----
    #
    # Restore the old single-line definition by replacing the whole corrected
    # block's RESULT with the snapshot size. The static_asserts below it then
    # have to fire.
    broken = good
    marker = '#define kRxPostSlotTables 2u'
    i = broken.find(marker)
    if i < 0:
        print('  FAIL: could not locate the definition to mutate')
        return 1
    # Replace `kRxPostSlotTables 2u` with `1u`: with one slot array the region
    # becomes exactly kRxPostSnapshotMax, i.e. the shipped bug's arithmetic,
    # while the layout code that uses TWO arrays is untouched.
    broken = broken.replace('#define kRxPostSlotTables 2u',
                            '#define kRxPostSlotTables 1u', 1)

    shutil.rmtree(WORKDIR, ignore_errors=True)
    os.makedirs(WORKDIR, exist_ok=True)
    try:
        # ---- 1. the shipped header must build and pass ----
        r, out = build(WORKDIR, 'good', good)
        check('the shipped header builds and the test passes',
              r is not None and r.returncode == 0,
              (out or '')[-500:] if r is None or r.returncode != 0 else '')

        # ---- 2. one slot array must NOT survive ----
        #
        # EITHER outcome is a valid rejection: the build may fail on a
        # static_assert, or the host test may fail its arithmetic. What matters
        # is that the defect cannot pass silently, and that the failure names the
        # region/ring relation rather than something incidental.
        r2, out2 = build(WORKDIR, 'broken', broken)
        rejected = (r2 is None) or (r2.returncode != 0)
        check('the one-slot-array variant is REJECTED', rejected,
              'it built and passed (rc=%s) -- the layout assertion is not '
              'sensitive' % (r2.returncode if r2 else '?'))
        if rejected:
            # The header's own static_asserts are written in terms of
            # kRxPostSlotTables on BOTH sides, so they move together and do not
            # fire; the sensitivity lives in the host test, which compares
            # against a literal 2. Both are accepted here, and the specific
            # check that fired is named.
            fired = [p for p in
                     ('the driver keeps exactly two slot arrays',
                      'kRxPostRearmsOff matches header + TWO slot arrays',
                      'the region is header + two slot arrays + the whole ring',
                      'kRxPostSlotTables must equal',
                      'kRxPostRegionBytes must be')
                     if p in (out2 or '')]
            check('the rejection names the region/ring relation', bool(fired),
                  'none of the expected diagnostics appeared in %d bytes'
                  % len(out2 or ''))
            if fired:
                print('    fired: %s' % fired)
    finally:
        shutil.rmtree(WORKDIR, ignore_errors=True)

    print()
    print('  RESULT: %s' % ('REGION CHECK IS SENSITIVE' if not FAILS
                            else 'FAILURES: %s' % FAILS))
    return 0 if not FAILS else 1


if __name__ == '__main__':
    sys.exit(main())
