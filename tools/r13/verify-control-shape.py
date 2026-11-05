#!/usr/bin/env python3
"""verify-control-shape.py -- does the analyser's control schema match the CODE?

THE PROBLEM THIS SOLVES
-----------------------
Round 12's control fixture and the analyser's control schema were written from a
READING of `runM22b2PageTableProbe()`, and they agreed with each other while both
disagreeing with the source:

  * the schema asserted `m2-b2-stage-inv-all` / `-inv-dev` / `-inv-pages` are
    ABSENT in control mode. They are not -- the control branch does `goto
    recover`, and step 18 (which publishes them) runs after the label;
  * the fixture carried `m2-b2-obs-snapshot-used`, which the control branch
    cannot produce, and that hid the fact that the analyser refused a
    legitimate control capture;
  * the fixture dropped the control stage's own timing (`m2-b2-ctl-t-*`), which
    the branch publishes unconditionally.

Two documents agreeing with each other is not evidence. This script compares
BOTH of them against the source, which is the thing that decides.

WHAT IT CHECKS
--------------
  A. the derivation (tools/r13/control-shape.py) succeeds and finds the three
     regions: before the branch, inside it, and after `recover:`;
  B. every property the derivation classifies as control-reachable is either
     in the analyser's `must_be_present` list or deliberately excluded, and
     the two lists are printed so a reader can see the difference;
  C. no property in the analyser's `must_be_absent` list is control-reachable;
  D. the fixture carries every `always` property and no `translation_only` one;
  E. the fixture and the analyser agree on the control stage's timing shape.

It reads the analyser's lists out of the Python source rather than importing it,
because importing runs the analysis.
"""
import ast
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SHAPE = os.path.join(ROOT, 'tools', 'r13', 'control-shape.py')
PGT = os.path.join(ROOT, 'kext', 'AMDMapperProbePgtDebug.cpp')
ANALYZER = os.path.join(ROOT, 'tools', 'analyze-round12.py')
FIXTURE = os.path.join(ROOT, 'tools', 'r12', 'make-control-fixture.py')
WORK = os.path.join(ROOT, 'build-work-r13', 'ctlshape')

FAILS = []


def check(name, ok, detail=''):
    print('  %-66s %s%s' % (name, 'PASS' if ok else 'FAIL',
                            '   [%s]' % detail if detail and not ok else ''))
    if not ok:
        FAILS.append(name)
    return ok


def list_literal(path, func_marker, var_name):
    """Read `var_name = [ ... ]` from a function in a Python source file.

    Parsed with `ast`, so a list written across lines, with comments and with
    string concatenation, is read correctly -- and a comment containing the
    variable name cannot be mistaken for the assignment.
    """
    tree = ast.parse(open(path, encoding='utf-8').read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == var_name:
                    try:
                        val = ast.literal_eval(node.value)
                    except (ValueError, SyntaxError):
                        return None
                    if isinstance(val, (list, tuple)):
                        return [str(x) for x in val]
    return None


def main():
    os.makedirs(WORK, exist_ok=True)
    print('=' * 78)
    print('CONTROL SHAPE: does the schema match the PRODUCTION branch?')
    print('=' * 78)

    # ------------------------------------------------------------------
    print('\nA. the derivation from the source')
    # ------------------------------------------------------------------
    r = subprocess.run([sys.executable, SHAPE, PGT], capture_output=True,
                       text=True)
    if r.returncode != 0:
        check('control-shape.py derives the shape', False,
              (r.stderr or r.stdout).strip()[-400:])
        print('\n  RESULT: FAILURES')
        return 1
    check('control-shape.py derives the shape', True)
    shape = json.loads(r.stdout)
    print('    always=%d  conditional=%d  translation_only=%d'
          % (len(shape['always']), len(shape['conditional']),
             len(shape['translation_only'])))
    check('it found a non-trivial unconditional set', len(shape['always']) > 20)
    check('it found a non-trivial translation-only set',
          len(shape['translation_only']) > 50)
    # The three properties that round 12 got wrong must be in the RIGHT bucket.
    check('the control stage timing is control-reachable',
          'm2-b2-ctl-t-start' in shape['always'] and
          'm2-b2-ctl-t-end' in shape['always'],
          'round 12 dropped these from the fixture')
    check('the control DTE statement is control-reachable',
          'm2-b2-dte' in shape['always'])
    check('the command-record count is control-reachable',
          'm2-b2-cmd-record-count' in shape['conditional'] or
          'm2-b2-cmd-record-count' in shape['always'],
          'step 18.1b runs on the recover path, so a control run publishes it')
    check('the invalidation stage words are control-reachable',
          'm2-b2-stage-inv-all' in shape['conditional'] or
          'm2-b2-stage-inv-all' in shape['always'],
          'round 12 asserted they were absent')

    # ------------------------------------------------------------------
    print('\nB/C. the analyser\'s control schema vs the derivation')
    # ------------------------------------------------------------------
    present = list_literal(ANALYZER, 'is_control', 'must_be_present')
    absent = list_literal(ANALYZER, 'is_control', 'must_be_absent')
    check('the analyser declares a must_be_present list',
          present is not None and len(present) > 10,
          'found %r' % (present,))
    check('the analyser declares a must_be_absent list',
          absent is not None and len(absent) > 20,
          'found %r' % (absent,))
    if present is None or absent is None:
        print('\n  RESULT: FAILURES')
        return 1

    reachable = set(shape['always']) | set(shape['conditional'])
    trans = set(shape['translation_only'])

    # C: nothing the analyser forbids may be reachable.
    bad_absent = sorted(set(absent) & reachable)
    check('no property the analyser forbids is control-reachable',
          not bad_absent, 'forbidden but reachable: %s' % bad_absent)

    # B: every `always` property is required by the analyser.
    #
    # Some are genuinely optional: the analyser does not check every
    # diagnostic. So the check is "every required property is reachable AND
    # every always-property is either required or explicitly listed as not
    # checked". The second list is printed, not silently tolerated.
    not_required = sorted(set(shape['always']) - set(present))
    check('every control-reachable property the analyser requires is real',
          not (set(present) - reachable),
          'required but NOT control-reachable: %s'
          % sorted(set(present) - reachable))
    print('    always-published but not required by the analyser (%d):'
          % len(not_required))
    for p in not_required:
        print('       %s' % p)

    # The specific round-12 errors, as named assertions.
    check('the analyser no longer forbids the invalidation stage words',
          'm2-b2-stage-inv-all' not in absent)
    check('the analyser no longer forbids the control stage timing',
          'm2-b2-ctl-t-start' not in absent)
    check('the analyser forbids the probe-used snapshot',
          'm2-b2-obs-snapshot-used' in absent,
          'the control branch cannot produce it, so its presence means the '
          'capture is not a control run')
    check('the analyser forbids the nic identity fields',
          'm2-b2-nic-bdf' in absent,
          'step 16c is after the goto, so control mode never publishes them')
    check('the analyser requires the control stage duration',
          'm2-b2-ctl-dur-ms' in present)

    # ------------------------------------------------------------------
    print('\nD. the fixture vs the derivation')
    # ------------------------------------------------------------------
    fx = os.path.join(WORK, 'fixture')
    if os.path.isdir(fx):
        import shutil
        shutil.rmtree(fx, ignore_errors=True)
    r = subprocess.run(
        [sys.executable, FIXTURE, fx, '--shape',
         os.path.join(WORK, 'shape.json')],
        capture_output=True, text=True)
    # Write the derivation first, so --shape has something to read.
    open(os.path.join(WORK, 'shape.json'), 'w').write(json.dumps(shape))
    r = subprocess.run(
        [sys.executable, FIXTURE, fx, '--shape',
         os.path.join(WORK, 'shape.json')],
        capture_output=True, text=True)
    check('the fixture builds against the derivation', r.returncode == 0,
          (r.stderr or r.stdout).strip()[-400:])
    props = {}
    p = os.path.join(fx, 'props.txt')
    if os.path.exists(p):
        for line in open(p, encoding='utf-8'):
            m = re.search(r'"([^"]+)"\s*=\s*"([^"]*)"', line)
            if m:
                props[m.group(1)] = m.group(2)
    written = set(props)
    check('the fixture carries every always-published property',
          not (set(shape['always']) - written),
          'missing: %s' % sorted(set(shape['always']) - written))
    check('the fixture carries NO translation-only property',
          not (trans & written),
          'written but impossible in control mode: %s'
          % sorted(trans & written))
    check('the fixture carries NO probe-used snapshot',
          'm2-b2-obs-snapshot-used' not in written)
    check('the fixture carries the control stage timing',
          'm2-b2-ctl-t-start' in written and 'm2-b2-ctl-t-end' in written)

    # ------------------------------------------------------------------
    print('\nE. the fixture is judged, and judged as CONTROL')
    # ------------------------------------------------------------------
    out = os.path.join(WORK, 'out')
    r = subprocess.run([sys.executable, ANALYZER, fx, out],
                       capture_output=True, text=True)
    j = os.path.join(out, 'analysis.json')
    check('the analyser produces a structured result for it',
          os.path.exists(j), (r.stderr or '')[-300:])
    if os.path.exists(j):
        data = json.load(open(j))
        st = {c['id']: c['state'] for c in data['checks']}
        nfail = sum(1 for v in st.values() if v == 'fail')
        check('no check fails on the control fixture', nfail == 0,
              [k for k, v in st.items() if v == 'fail'][:5])
        check('the mode is control-sleep-only',
              data['mode'] == 'control-sleep-only', data['mode'])
        check('the script does NOT claim finite translation evidence',
              'finite DMA translation evidence  : YES' not in r.stdout)
        check('the result line says CONTROL',
              'RESULT: CONTROL' in r.stdout)

    print()
    print('  RESULT: %s' % ('CONTROL SHAPE MATCHES THE CODE' if not FAILS
                            else 'FAILURES: %s' % FAILS))
    return 0 if not FAILS else 1


if __name__ == '__main__':
    sys.exit(main())
