#!/usr/bin/env python3
"""verify-counterexamples.py -- prove the round-11 tests can actually fail.

WHY THIS EXISTS
---------------
A test that passes is not evidence unless it would have failed on the defect it
claims to catch. Round 10's "18/18 negatives" were counted from "exit non-zero
and the output mentions an assertion name", which a crash or a missing file also
satisfies. So this script does the opposite of adding tests: it MUTATES the
production header back towards the round-10 behaviour, one defect at a time,
and requires the specific named check to report ok=false.

The three mutations are the three defects the round-11 brief names:

  A  `allSegDone` reverts to a completion COUNT comparison
     -> "A: not all segments completed" must fail
  B  the window binding is dropped from the batch verdict
     -> "B: so the batch is NOT complete" must fail
  C  the token filter is dropped from the business fold
     -> "C: so the batch is NOT complete" must fail

Each mutation must also be CONFIRMED to have changed the input: the script
compares the mutated header against the original byte for byte and refuses to
report on a mutation that changed nothing.

Exit code 0 only when every mutation is both applied and caught.
"""
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HDR = os.path.join(ROOT, 'kext', 'amd_iommu_dma_observe.hpp')
TEST = os.path.join(ROOT, 'tests', 'dma-observe-test.cpp')
WORK = os.path.join(ROOT, 'build-work-r11', 'mutation')

CXX = os.environ.get('CXX', 'clang++')
CXXFLAGS = ['-std=c++17', '-Wall', '-Wextra', '-Wpedantic', '-Werror', '-O1',
            '-g', '-I', os.path.join(ROOT, 'include'),
            '-I', os.path.join(ROOT, 'kext')]
SOURCES = ['src/IdentityMap.cpp', 'src/Ivrs.cpp', 'src/IvrsTopology.cpp',
           'tests/dma-observe-test.cpp']

# (name, needle, replacement, the assertion that must FAIL, why this is the
#  round-10 shape and not a cosmetic edit)
MUTATIONS = [
    # Round 10 counted a completion RECORD, not a completed SEGMENT:
    #     b->segDone++;                                   // per matching done
    #     b.allSegDone = (segDone == segCount && ...);    // so 2 == 2 passed
    # Restoring that counting loop is the defect; the assertion that must
    # break is the one that says segment 97 never completed.
    ('A-count-records-not-segments',
     '            if (b.segDoneCount[s] == 0) {\n'
     '                b.segMissingDone++;\n'
     '            } else {\n'
     '                b.segDone++;\n'
     '                if (b.segDoneCount[s] > 1) b.segDupDone += b.segDoneCount[s] - 1;\n'
     '            }',
     '            b.segDone += b.segDoneCount[s];',
     'A: not all segments completed, despite done-records == segment-count'),

    # Round 10's batch predicate never looked at the window at all; the only
    # window check lived in the "first window operation" the report quoted.
    # Forcing allStagesInWindow true is that behaviour. (There is a second,
    # independent guard -- windowOk in the final conjunction -- which is why
    # the mutation targets the per-op flag: it is the one that decides
    # batchComplete.)
    ('B-drop-window-binding',
     '            b.allStagesInWindow = (b.submitInWindow && b.doneInWindow &&\n'
     '                                   b.rxinWindow);',
     '            b.allStagesInWindow = true;',
     'B: so the batch is NOT complete'),

    ('C-drop-token-filter',
     'if (j.joinToken != 0 && r.token != j.joinToken) {\n'
     '            j.batchForeignToken++;\n'
     '            continue;\n'
     '        }',
     'if (false) {\n'
     '            j.batchForeignToken++;\n'
     '            continue;\n'
     '        }',
     'C: so the batch is NOT complete'),
]


def build_and_run(tag):
    """Compile the tree as it currently stands and return (ok, failed_names)."""
    exe = os.path.join(WORK, 't-%s' % tag)
    cmd = [CXX] + CXXFLAGS + SOURCES + ['-o', exe]
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if p.returncode != 0:
        return None, ['COMPILE FAILED: ' + p.stderr.strip()[:400]]
    r = subprocess.run([exe], capture_output=True, text=True)
    failed = []
    for line in r.stdout.splitlines():
        if line.startswith('FAIL: '):
            failed.append(line[6:].split(' (got')[0].strip())
    return r.returncode, failed


def main():
    if os.path.isdir(WORK):
        shutil.rmtree(WORK)
    os.makedirs(WORK)

    orig = open(HDR, 'rb').read()
    print('=' * 78)
    print('ROUND-11 MUTATION TEST: does each counterexample actually catch its defect?')
    print('=' * 78)

    rc, failed = build_and_run('baseline')
    if rc is None:
        print('baseline does not compile:')
        for f in failed:
            print('  ' + f)
        return 1
    if rc != 0:
        print('REFUSED: the unmutated tree already fails. A mutation test on a')
        print('         red baseline proves nothing.')
        for f in failed:
            print('  - ' + f)
        return 1
    print('  baseline: all checks pass (0 failed)')
    print()

    all_ok = True
    for name, needle, repl, must_fail in MUTATIONS:
        src = open(HDR, encoding='utf-8').read()
        if needle not in src:
            print('  %-34s REFUSED: anchor not found' % name)
            all_ok = False
            continue
        mutated = src.replace(needle, repl, 1)
        if mutated == src:
            print('  %-34s REFUSED: mutation changed nothing' % name)
            all_ok = False
            continue
        # Confirm the mutation really altered the file before compiling it.
        open(HDR, 'w', encoding='utf-8', newline='\n').write(mutated)
        try:
            after = open(HDR, 'rb').read()
            if after == orig:
                print('  %-34s REFUSED: on-disk header is unchanged' % name)
                all_ok = False
                continue
            rc, failed = build_and_run(name)
        finally:
            open(HDR, 'wb').write(orig)

        if rc is None:
            print('  %-34s COMPILE FAILED under mutation' % name)
            for f in failed:
                print('      ' + f)
            all_ok = False
            continue

        hit = any(must_fail in f for f in failed)
        print('  %-34s %s' % (name, 'CAUGHT' if hit else 'NOT CAUGHT'))
        print('      target assertion : %s' % must_fail)
        print('      failing checks   : %s'
              % (failed if failed else '(none: the mutated build PASSED)'))
        if not hit:
            all_ok = False

    print()
    # Restore and re-verify, so a failed run cannot leave the tree mutated.
    open(HDR, 'wb').write(orig)
    rc, failed = build_and_run('restored')
    restored = (rc == 0 and not failed)
    print('  header restored and baseline re-run: %s'
          % ('PASS' if restored else 'FAIL'))
    if not restored:
        all_ok = False

    print()
    print('  RESULT: %s' % ('ALL MUTATIONS CAUGHT' if all_ok else 'FAILURES'))
    return 0 if all_ok else 1


if __name__ == '__main__':
    sys.exit(main())
