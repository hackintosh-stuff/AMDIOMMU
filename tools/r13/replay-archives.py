#!/usr/bin/env python3
"""replay-archives.py -- re-judge the existing REAL archives under the current
analyser.

WHY THIS IS A SEPARATE, REQUIRED STEP
-------------------------------------
Every hardening could have been bought by making the analyser stricter in a way
that also rejects the evidence that already exists. That would be a regression
disguised as a fix. So the two round-12 archives -- one that PASSED and one the
production gate REFUSED -- are re-judged here, and the expected outcome is
stated in advance:

  20261101-014200  PASS.  4 requests, token 0x9e8100d3, 8 ranges, zero faults.
  20261101-013600  FAIL.  The launchd job read round 11's token (0xa3dbba85)
                          while the boot-arg declared 0x72b14304, so the probe
                          refused and the controlled batch is not complete.

The round-11 archive (20261101-140000) is replayed too, because the round-12
report said the new analyser still scored it 96/96 and that claim has to keep
being true -- or be withdrawn.

WHAT IS ASSERTED, PER ARCHIVE
-----------------------------
  * the exit code;
  * the three recomputed BUSINESS verdicts;
  * the SPECIFIC checks the round-13 hardening added, so the replay shows they
    RAN rather than being N/A or absent;
  * for the refused archive, that the failure is the token binding and not
    something incidental.

WHAT ROUND 14 CHANGED ABOUT `finite`, AND WHY THIS FILE HAD TO CHANGE WITH IT
-----------------------------------------------------------------------------
Through round 13 `finite_translation_evidence` was
`is_translation and batch_ok and cover_ok and window_state_ok and n_fail == 0`.
None of those terms mentions the RX direction, so every archive that passed it
was reporting "finite" about the TX path plus eight sampled RX buffers.

Round 14 added the RX posted-buffer set as a named term. The archives were made
by probes that have no RX post code at all, so that term cannot hold for them
and `finite` is now correctly NO -- with `rxset-*` named as the missing terms.

That is not a regression in the archives, it is a correction of what the word
"finite" was claiming. This file therefore asserts:

  * the business verdicts are UNCHANGED (the archives still judge the same);
  * `finite` is now NO for every pre-round-14 archive, and the ONLY reason is
    the RX set -- asserted by name, so a future unrelated failure cannot hide
    behind this explanation.
"""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
ANALYZER = os.path.join(ROOT, 'tools', 'analyze-round12.py')
WORK = os.path.join(ROOT, 'build-work-r13', 'replay')

FAILS = []

# Round 13 added these; a replay must show them running.
ROUND13_CHECKS = [
    'win-status-present', 'win-status-run-start', 'win-status-run-end',
    'win-status-no-overflow', 'win-status-ptr-aligned',
    'win-status-head-stable', 'win-status-span',
    'loss-wrapped', 'loss-wrapped-agrees',
]

# Round 14 added these. For a pre-round-14 capture they must be N/A -- NOT
# absent (which would mean the analyser does not know them) and NOT failed
# (which would blame the archive for not containing code that did not exist).
ROUND14_CHECKS = [
    'rxset-present', 'rxset-baseline-full', 'rxset-baseline-current',
    'rxset-no-gap', 'rxset-no-loss', 'rxset-not-truncated',
    'rxset-gen-stable', 'rxset-set-complete', 'rxset-ranges-agree',
    'rxset-all-walked', 'rxset-arith-closes', 'rxset-all-covered',
    'rxset-walk-dte',
]


def check(name, ok, detail=''):
    print('  %-66s %s%s' % (name, 'PASS' if ok else 'FAIL',
                            '   [%s]' % detail if detail and not ok else ''))
    if not ok:
        FAILS.append(name)
    return ok


def run(cap):
    out = os.path.join(WORK, os.path.basename(cap))
    os.makedirs(out, exist_ok=True)
    r = subprocess.run([sys.executable, ANALYZER, cap, out],
                       capture_output=True, text=True)
    j = os.path.join(out, 'analysis.json')
    data = json.load(open(j)) if os.path.exists(j) else None
    return r, data


def replay(label, cap, want_rc, want_verdicts, want_finite):
    print('\n%s' % ('-' * 78))
    print('%s  (%s)' % (label, os.path.basename(cap)))
    print('-' * 78)
    if not os.path.isdir(cap):
        check('%s: the archive is present' % label, False, cap)
        return
    r, data = run(cap)
    if data is None:
        check('%s: the analyser produced a structured result' % label, False,
              (r.stderr or r.stdout)[-400:])
        return
    check('%s: the analyser produced a structured result' % label, True)

    st = {c['id']: c['state'] for c in data['checks']}
    ids = [c['id'] for c in data['checks']]
    nfail = sum(1 for v in st.values() if v == 'fail')

    check('%s: exit code is %d' % (label, want_rc), r.returncode == want_rc,
          'exit=%d' % r.returncode)
    check('%s: no check id appears twice' % label, len(ids) == len(set(ids)),
          '%d ids, %d unique' % (len(ids), len(set(ids))))

    v = data.get('verdicts') or {}
    for key, want in want_verdicts.items():
        check('%s: %s is %s' % (label, key, 'YES' if want else 'NO'),
              bool(v.get(key)) == want, 'got %r' % v.get(key))

    got_finite = bool(data.get('finite_translation_evidence'))
    # ROUND 14: `finite` now includes the RX posted-buffer set, which no
    # pre-round-14 probe could produce. The expected value is therefore NO for
    # every archive in this list -- and the REASON must be the RX set, named,
    # rather than some other term that happens to be false.
    check('%s: finite translation evidence is %s'
          % (label, 'YES' if want_finite else 'NO'),
          got_finite == want_finite, 'got %r' % got_finite)

    if not want_finite:
        # The analyser names the missing terms when it refuses `finite`. Those
        # names are asserted to be exactly the round-14 RX checks: an unrelated
        # failure would otherwise be able to hide behind this explanation.
        missing = data.get('finite_missing') or []
        unexpected = [c for c in missing if not c.startswith('rxset-')]
        check('%s: the ONLY reason finite is NO is the RX set' % label,
              bool(missing) and not unexpected,
              'missing: %s (non-rxset: %s)' % (missing, unexpected))

    # The round-13 checks must have RUN, not vanished.
    missing13 = [c for c in ROUND13_CHECKS if c not in st]
    check('%s: every round-13 check id is present' % label, not missing13,
          'absent: %s' % missing13)
    na13 = [c for c in ROUND13_CHECKS if st.get(c) == 'na']
    check('%s: none of the round-13 checks is N/A in translation mode' % label,
          not na13, 'N/A: %s' % na13)

    # The round-14 checks must be KNOWN and N/A, never absent and never failed.
    absent14 = [c for c in ROUND14_CHECKS if c not in st]
    check('%s: every round-14 check id is present' % label, not absent14,
          'absent: %s' % absent14)
    bad14 = [c for c in ROUND14_CHECKS if st.get(c) == 'fail']
    check('%s: no round-14 check blames this pre-round-14 archive' % label,
          not bad14, 'failed: %s' % bad14)
    na14 = [c for c in ROUND14_CHECKS if st.get(c) == 'na']
    check('%s: the round-14 checks are N/A, not silently passed' % label,
          len(na14) == len(ROUND14_CHECKS),
          'N/A: %d of %d' % (len(na14), len(ROUND14_CHECKS)))

    if want_rc == 1:
        # The refusal must be the token binding, not something incidental.
        check('%s: the token binding is what fails' % label,
              st.get('batch-token-matches') == 'fail' or
              st.get('batch-token-joined') == 'fail',
              'token checks: %s'
              % {k: st.get(k) for k in
                 ('batch-token-matches', 'batch-token-joined',
                  'batch-token-declared')})
        check('%s: the window itself is still valid' % label,
              st.get('win-valid') == 'ok' and
              st.get('win-status-run-start') == 'ok',
              'a refusal for an unrelated reason would not reproduce round 12')

    print('    %d ok, %d failed, %d N/A'
          % (sum(1 for x in st.values() if x == 'ok'), nfail,
             sum(1 for x in st.values() if x == 'na')))


def main():
    os.makedirs(WORK, exist_ok=True)
    print('=' * 78)
    print('ARCHIVE REPLAY: do the existing real archives still judge the same?')
    print('=' * 78)
    print()
    print('  NOTE: `finite` is NO for all three archives below, and that is a')
    print('  CORRECTION rather than a regression. Through round 13 the word did')
    print('  not include the RX direction at all; it meant "the business ranges')
    print('  are mapped". Round 14 made the RX posted-buffer set a named term,')
    print('  and a pre-round-14 probe has no code that could produce it. The')
    print('  business verdicts are unchanged, and that is what is asserted.')

    # want_finite is False for all three: they predate the RX set.
    replay('run 2 (round 12, PASSED)',
           os.path.join(ROOT, 'docs', 'evidence', '20261101-014200'),
           0,
           {'has_complete_pair': True,
            'records_cover_window': True,
            'controlled_batch_complete': True},
           False)

    replay('run 1 (round 12, gate-refused)',
           os.path.join(ROOT, 'docs', 'evidence', '20261101-013600'),
           1,
           {'has_complete_pair': True,
            'records_cover_window': True,
            'controlled_batch_complete': False},
           False)

    replay('round 11 (PASSED)',
           os.path.join(ROOT, 'docs', 'evidence', '20261101-140000'),
           0,
           {'has_complete_pair': True,
            'records_cover_window': True,
            'controlled_batch_complete': True},
           False)

    # The round-13 capture: same story, and it is the one whose `finite YES`
    # the round-13 report quoted. Re-judged here so the withdrawal is explicit.
    replay('round 13 (PASSED)',
           os.path.join(ROOT, 'docs', 'evidence', '20261031-203651'),
           0,
           {'has_complete_pair': True,
            'records_cover_window': True,
            'controlled_batch_complete': True},
           False)

    print()
    print('  RESULT: %s' % ('ARCHIVES JUDGE THE SAME' if not FAILS
                            else 'FAILURES: %s' % FAILS))
    return 0 if not FAILS else 1


if __name__ == '__main__':
    sys.exit(main())
