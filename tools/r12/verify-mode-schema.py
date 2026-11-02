#!/usr/bin/env python3
"""verify-mode-schema.py -- does the analyser really handle the two modes?

WHY THIS IS SEPARATE FROM THE MUTATION SUITE
--------------------------------------------
The mutation suite asks "does a broken capture get rejected". This asks a
different question: "does a VALID capture of each kind get judged by the right
rules". An analyser that rejected everything would pass the mutation suite and
fail this one, which is exactly the failure mode a negative-only suite has.

THE FOUR PROPERTIES
-------------------
  1. A real control capture: every translation-only check is N/A, nothing
     fails, and the script never claims finite DMA translation evidence.
  2. A control capture RELABELLED as translation: rejected. This is the
     property that makes (1) meaningful -- if a control capture were also
     acceptable as a translation capture, then the N/A set would be decoration
     rather than a schema.
  3. A translation capture RELABELLED as control: rejected on its shape, not
     accepted because the label says control. The control schema asserts the
     translation fields are ABSENT; a capture that carries them is not a
     control capture no matter what its mode property says.
  4. No check id appears twice in any run. Round 11's control-mode N/A rows
     were appended by NAME and silently overwrote the results they were meant
     to stand beside.
"""
import json
import os
import re
import shutil
import subprocess
import sys

def rmtree_force(path):
    """Remove a tree, clearing read-only bits first.

    Windows sets a read-only attribute on files extracted from an archive; a
    plain shutil.rmtree then fails with WinError 5 and aborts the run. A
    cleanup failure must not be reported as a test failure.
    """
    def onerror(func, p, _exc):
        try:
            os.chmod(p, 0o777)
        except OSError:
            pass
        try:
            func(p)
        except OSError:
            pass

    if os.path.isdir(path):
        shutil.rmtree(path, onerror=onerror)



HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
ANALYZER = os.path.join(ROOT, 'tools', 'analyze-round12.py')
WORK = os.path.join(ROOT, 'build-work-r12', 'modes')

# The checks that depend on the DTE being switched, a window being measured,
# and a snapshot being decoded. In control mode every one of them must be N/A.
TRANSLATION_ONLY = [
    'pt-dte', 'pt-dte-translating', 'pt-dte-perms', 'pt-expected',
    'pt-count', 'pt-covered', 'pt-perm', 'pt-evidence',
    'win-bounds', 'win-valid',
    # ROUND 13 (N1): the raw event-log STATUS words are sampled only inside the
    # measurement window, so they are translation-only too.
    'win-status-present', 'win-status-run-start', 'win-status-run-end',
    'win-status-no-overflow', 'win-status-ptr-aligned',
    'win-status-head-stable', 'win-status-span',
    'evt-enabled', 'evt-reset', 'evt-not-truncated', 'evt-decoded',
    # ROUND 13: the entry-level status check was renamed from `evt-status`, so
    # the round-12 spelling no longer matches anything. Keeping the old name
    # here is how this list silently stopped covering the check it names.
    'evt-entry-status', 'evt-fault-count', 'evt-devid', 'evt-limit',
    'cmd-records', 'cmd-expected-eq-observed', 'cmd-inv-completed',
    'cmd-buffer-stopped', 'cmd-evtlog-stopped',
    'tl-fields', 'tl-order', 'tl-business-inside',
    'chain-tx-in', 'chain-done-in', 'chain-rx-in', 'chain-frame-len',
    'pair-exists', 'cover-verdict', 'cover-agrees',
    'batch-declared', 'batch-token-declared', 'batch-token-joined',
    'batch-one-token', 'batch-verdict', 'batch-agrees',
    'snap-exported', 'snap-sha-raw', 'snap-sha-file', 'snap-pub-known',
    'snap-pub-is-blob',
    # ROUND 13 (N3): these all need the probe-used snapshot, which the control
    # branch never produces. They are N/A in control mode, not absent.
    'hdr-magic', 'hdr-version', 'hdr-recsize', 'hdr-whole', 'hdr-valid-lost',
    'hdr-tickets', 'hdr-pubid',
    'loss-dropped', 'loss-lostcount', 'loss-overflowed', 'loss-flag',
    'loss-probe-agrees', 'loss-wrapped', 'loss-wrapped-agrees',
    'rec-no-holes', 'rec-submits', 'rec-rx',
    'id-bdf', 'id-vendor', 'id-device', 'id-unit', 'id-mac',
    'id-epoch-match',
]

FAILS = []


def check(name, ok, detail=''):
    print('  %-64s %s%s' % (name, 'PASS' if ok else 'FAIL',
                            '   [%s]' % detail if detail and not ok else ''))
    if not ok:
        FAILS.append(name)
    return ok


def run(cap, outdir):
    r = subprocess.run([sys.executable, ANALYZER, cap, outdir],
                       capture_output=True, text=True)
    j = os.path.join(outdir, 'analysis.json')
    data = json.load(open(j)) if os.path.exists(j) else None
    return r, data


def states(data):
    return {c['id']: c['state'] for c in data['checks']}


def main():
    if len(sys.argv) < 2:
        print('usage: verify-mode-schema.py <control-fixture> <translation-capture>')
        return 2
    control = sys.argv[1]
    real = sys.argv[2]

    if os.path.isdir(WORK):
        rmtree_force(WORK)
    os.makedirs(WORK)

    print('=' * 78)
    print('MODE SCHEMA: are the two experiments judged by their own rules?')
    print('=' * 78)

    # ------------------------------------------------------------------
    print('\n1. a real control capture')
    # ------------------------------------------------------------------
    r, data = run(control, os.path.join(WORK, 'control'))
    if data is None:
        check('the control capture produces a structured result', False,
              r.stderr.strip()[:160])
        print('\n  RESULT: FAILURES')
        return 1
    st = states(data)
    check('the mode is detected as control-sleep-only',
          data['mode'] == 'control-sleep-only', 'mode=%r' % data['mode'])

    n_fail = sum(1 for v in st.values() if v == 'fail')
    check('no check FAILS on a valid control capture', n_fail == 0,
          '%d failed: %s' % (n_fail,
                             [k for k, v in st.items() if v == 'fail'][:5]))

    missing_na = [c for c in TRANSLATION_ONLY if st.get(c) != 'na']
    check('every translation-only check is N/A', not missing_na,
          'not N/A: %s' % missing_na[:6])

    check('the script does NOT claim finite DMA translation evidence',
          'finite DMA translation evidence  : YES' not in r.stdout,
          'the control run claimed translation evidence')

    check('the result line says CONTROL, not PASS',
          'RESULT: CONTROL' in r.stdout,
          [l for l in r.stdout.splitlines() if l.startswith('  RESULT')])

    # The ids must be unique: a duplicate would mean an N/A overwrote a result.
    ids = [c['id'] for c in data['checks']]
    check('no check id appears twice', len(ids) == len(set(ids)),
          '%d ids, %d unique' % (len(ids), len(set(ids))))

    # ------------------------------------------------------------------
    print('\n2. a control capture relabelled as translation')
    # ------------------------------------------------------------------
    d = os.path.join(WORK, 'relabel-translation')
    shutil.copytree(control, d)
    p = os.path.join(d, 'props.txt')
    t = open(p, encoding='utf-8').read()
    t2 = re.sub(r'("m2-b2-mode"\s*=\s*)"[^"]*"',
                lambda m: m.group(1) + '"translation"', t, count=1)
    check('the relabelling actually changed the file', t2 != t)
    open(p, 'w', encoding='utf-8').write(t2)
    r, data = run(d, os.path.join(WORK, 'relabel-translation-out'))
    if data is None:
        check('the relabelled capture is judged (not refused)', False,
              r.stderr.strip()[:160])
    else:
        st = states(data)
        n_fail = sum(1 for v in st.values() if v == 'fail')
        check('a control capture relabelled as translation is REJECTED',
              n_fail > 0, 'nothing failed, so the label alone decides the '
              'schema -- the N/A set is decoration')
        check('and it fails on the missing translation fields, not on a crash',
              st.get('schema-fields') == 'fail',
              'schema-fields=%r' % st.get('schema-fields'))

    # ------------------------------------------------------------------
    print('\n3. a translation capture relabelled as control')
    # ------------------------------------------------------------------
    d = os.path.join(WORK, 'relabel-control')
    shutil.copytree(real, d)
    p = os.path.join(d, 'props.txt')
    t = open(p, encoding='utf-8').read()
    t2 = re.sub(r'("m2-b2-mode"\s*=\s*)"[^"]*"',
                lambda m: m.group(1) + '"control-sleep-only"', t, count=1)
    check('the relabelling actually changed the file', t2 != t)
    open(p, 'w', encoding='utf-8').write(t2)
    r, data = run(d, os.path.join(WORK, 'relabel-control-out'))
    if data is None:
        check('the relabelled capture is judged (not refused)', False,
              r.stderr.strip()[:160])
    else:
        st = states(data)
        # The control schema asserts the translation fields are ABSENT. This
        # capture carries them, so its SHAPE contradicts its label. The
        # analyser must say so rather than accept the label.
        shape = st.get('schema-control-shape')
        check('a translation capture relabelled as control is flagged',
              shape == 'fail',
              'schema-control-shape=%r (a capture carrying bizwalk/obs/window '
              'fields is not a control run)' % shape)
        check('and it still does not claim translation evidence',
              'finite DMA translation evidence  : YES' not in r.stdout,
              'a capture labelled control claimed translation evidence')

    # ------------------------------------------------------------------
    print('\n4. the real translation capture')
    # ------------------------------------------------------------------
    r, data = run(real, os.path.join(WORK, 'translation'))
    if data is None:
        check('the translation capture produces a structured result', False,
              r.stderr.strip()[:160])
    else:
        st = states(data)
        check('the mode is detected as translation',
              data['mode'] == 'translation', 'mode=%r' % data['mode'])
        n_fail = sum(1 for v in st.values() if v == 'fail')
        check('no check fails on the real capture', n_fail == 0,
              [k for k, v in st.items() if v == 'fail'][:5])
        check('the control-mode N/A rules do NOT apply to it',
              st.get('schema-control-na') == 'na' and
              st.get('schema-control-shape') is None,
              'schema-control-na=%r' % st.get('schema-control-na'))
        check('the translation-only checks actually RAN (not N/A)',
              all(st.get(c) != 'na' for c in
                  ('pt-dte', 'pt-count', 'pt-covered', 'pt-evidence')),
              [c for c in ('pt-dte', 'pt-count', 'pt-covered', 'pt-evidence')
               if st.get(c) == 'na'])

    print()
    print('  RESULT: %s' % ('MODE SCHEMA CORRECT' if not FAILS
                            else 'FAILURES: %s' % FAILS))
    return 0 if not FAILS else 1


if __name__ == '__main__':
    sys.exit(main())
