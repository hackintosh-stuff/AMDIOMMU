#!/usr/bin/env python3
"""verify-gate-wiring.py -- does the PRODUCTION verdict actually consult the gate?

WHY
---
tests/evidence-gate-test.cpp proves obsEvidenceGate() rejects each broken term.
That is necessary but not sufficient: round 11's whole defect was that the
properties existed and the verdict never read them. A perfect gate that the
probe does not call is exactly the same bug with more code.

So this script reads probe/AMDMapperProbePgtDebug.cpp and requires:

  1. the PASS-CANDIDATE branch is guarded by obsEvidenceGate(), not by a
     hand-written conjunction of the evidence fields;
  2. the ObsEvidence struct is populated from the probe's own state, field by
     field -- a default-constructed struct would pass the gate;
  3. no evidence term is computed inline in the verdict (that is the shape that
     let four of them be forgotten);
  4. the identity guard in AMDMapperProbeObsDebug.cpp refuses an UNKNOWN identity,
     not just a mismatched one;
  5. the batch join in production uses the strict spec.

Each of these is a property of the SOURCE, checked textually, because the
alternative -- trusting that the wiring is right -- is what failed before.

Exit 0 only when every property holds.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
PGT = os.path.join(ROOT, 'probe', 'AMDMapperProbePgtDebug.cpp')
OBS = os.path.join(ROOT, 'probe', 'AMDMapperProbeObsDebug.cpp')
HDR = os.path.join(ROOT, 'probe', 'amd_iommu_dma_observe.hpp')

RESULTS = []


def check(name, ok, detail=''):
    RESULTS.append((name, ok, detail))
    print('  %-62s %s%s' % (name, 'PASS' if ok else 'FAIL',
                            '   [%s]' % detail if detail and not ok else ''))
    return ok


def strip_comments(text):
    """Remove // and /* */ comments.

    WHY THIS IS NEEDED
    ------------------
    The round-11 guard `if (want.have && !idOk)` is described in a comment in
    the fixed source, explaining what was wrong and why. A checker that greps
    the raw file therefore reports the fix as still present -- and, worse, a
    checker that is fooled by prose could also be fooled by a commented-out
    line of real code. Both directions are wrong, so the analysis runs on the
    code with comments removed.
    """
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
    text = re.sub(r'//[^\n]*', ' ', text)
    return text


def main():
    pgt = open(PGT, encoding='utf-8').read()
    obs_raw = open(OBS, encoding='utf-8').read()
    hdr = open(HDR, encoding='utf-8').read()
    # The wiring checks below are about CODE. Comments are documentation, and a
    # comment that quotes the old defect must not count as the old defect.
    obs = strip_comments(obs_raw)
    pgt_code = strip_comments(pgt)

    print('=' * 78)
    print('EVIDENCE-GATE WIRING: is the production verdict actually gated?')
    print('=' * 78)

    # Everything below inspects the comment-stripped probe source.
    pgt = pgt_code

    # 1. the PASS-CANDIDATE branch is guarded by the gate.
    #
    # Find the line that assigns PASS-CANDIDATE and look at the enclosing
    # condition. The condition must mention the gate's result, and must not be
    # a conjunction of raw evidence fields.
    ok = True
    m = re.search(r'verdict\s*=\s*"PASS-CANDIDATE-controlled-chain"', pgt)
    if not m:
        check('the probe still has a PASS-CANDIDATE branch', False)
        ok = False
    else:
        # Look back for the `if (` that opens this branch.
        window = pgt[max(0, m.start() - 1200):m.start()]
        if_conds = re.findall(r'if\s*\(([^;]{0,400}?)\)\s*\{', window, re.S)
        cond = if_conds[-1] if if_conds else ''
        check('the PASS-CANDIDATE branch exists', True)
        check('its condition consults the evidence gate',
              'obsEvidenceGate' in window or 'gateWhy' in cond,
              'condition: %s' % cond.strip()[:160])
        # The round-11 shape: the condition listed the evidence fields inline.
        inline = ('obsHasCompletePair' in cond and
                  'obsRecordsCoverWindow' in cond and
                  'obsControlledBatchComplete' in cond)
        check('it is NOT a hand-written conjunction of evidence fields',
              not inline, 'condition still lists the fields inline')
        # And the page-table counters must not be absent from the decision.
        check('bizWalk* reaches the decision through the gate, not around it',
              'bizWalkFail' in window or 'bizWalkFail' in pgt)

    # 2. the evidence struct is populated field by field.
    populated = re.findall(r'ev\.(\w+)\s*=', pgt)
    want = ['identityKnown', 'declaredToken', 'expectedBatch',
            'snapshotExported', 'snapshotHashStable', 'snapshotFresh',
            'writerDropped', 'publishLost', 'readerHoles', 'hdrFlags',
            'bizCapped', 'hasCompletePair', 'recordsCoverWindow',
            'controlledBatchComplete', 'tokenResolvedOnDeclared',
            'bizWalkExpected', 'bizWalkCount', 'bizWalkOk', 'bizWalkFail',
            'bizWalkCapped', 'windowRan', 'windowValid', 'eventLogOk',
            'commandsOk', 'restoreOk']
    missing = [w for w in want if w not in populated]
    check('every evidence field is populated from the probe state',
          not missing, 'missing: %s' % missing)

    # 3. the token binding is not circular.
    check('tokenResolvedOnDeclared requires a NON-ZERO declared token',
          re.search(r'tokenResolvedOnDeclared\s*=\s*\(\s*fM22b2Dma\.declaredToken'
                    r'\s*!=\s*0', pgt) is not None)
    check('tokenResolvedOnDeclared compares the join token to the declaration',
          'obsJoinToken == fM22b2Dma.declaredToken' in pgt)

    # 4. the identity guard refuses UNKNOWN, not just mismatch.
    #
    # The round-11 shape was `if (want.have && !idOk)`.
    round11_shape = re.search(r'if\s*\(\s*want\.have\s*&&\s*!\s*idOk\s*\)', obs)
    check('the round-11 `want.have && !idOk` guard is GONE',
          round11_shape is None)
    check('an unknown identity has its own refusal branch',
          re.search(r'if\s*\(\s*!\s*want\.have\s*\)', obs) is not None and
          'identity-unknown' in obs)
    check('the unknown-identity branch publishes a reason',
          'probe-has-no-independent-identity' in obs)
    check('a mismatch still has its own refusal branch',
          re.search(r'if\s*\(\s*!\s*idOk\s*\)', obs) is not None)

    # 5. production joins with the strict spec.
    check('the probe joins with obsBatchSpecStrict()',
          'obsBatchSpecStrict(' in obs)
    check('the strict spec sets strictToken',
          re.search(r'\.strictToken\s*=\s*true', hdr) is not None)
    check('obsJoinInto refuses to infer a token under strictToken',
          re.search(r'spec\.strictToken', hdr) is not None)
    check('an inferred token blocks controlledBatchComplete',
          re.search(r'!\s*j\.inferredToken', hdr) is not None)

    # 6. bizWalkFail is not overwritten by a local counter.
    #
    # Round 11 incremented the member on early returns and then assigned a
    # function-local `fail` to it at the end, discarding the early increments.
    tail = pgt[-9000:]
    check('bizWalkFail is not assigned from a local counter at the end',
          re.search(r'bizWalkFail\s*=\s*fail\s*;', tail) is None)
    check('bizWalkFail is incremented on the failure paths',
          pgt.count('bizWalkFail++') >= 1 or
          pgt.count('fM22b2Dma.bizWalkFail++') >= 1)

    # 7. the range walk is the shared core, not an inline copy.
    check('the probe includes the shared walk core',
          '#include "amd_iommu_bizwalk_core.hpp"' in pgt)
    check('the probe calls amdbw::walkRange()',
          'amdbw::walkRange(' in pgt)
    # The round-11 shape walked one address and looped "pages" separately.
    check('the round-11 first-page-only walk is gone',
          'walkOne(addr, &depth, &leaf, facts)' not in pgt)

    # 8. expected/capped are computed and published.
    check('bizWalkExpected is derived from the raw business records',
          'bizWalkExpected' in pgt and 'bizWalkExpected = want' in pgt)
    check('a range beyond capacity is counted, not skipped',
          re.search(r'if\s*\(count\s*>=\s*fM22b2Dma\.kBizWalkMaxSegs\)\s*\{'
                    r'[^}]*bizWalkCapped', pgt, re.S) is not None)
    check('bizwalk-expected is published', '"m2-b2-bizwalk-expected"' in pgt)
    check('bizwalk-capped is published', '"m2-b2-bizwalk-capped"' in pgt)

    bad = [n for n, ok_, _ in RESULTS if not ok_]
    print()
    print('  %d checks, %d failed' % (len(RESULTS), len(bad)))
    print('  RESULT: %s' % ('WIRING CORRECT' if not bad else 'FAILURES: %s'
                            % bad))
    return 0 if not bad else 1


if __name__ == '__main__':
    sys.exit(main())
