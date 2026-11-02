#!/usr/bin/env python3
"""fix-r12-tests.py -- declare the run token in the round-11 batch tests.

WHY THIS IS NEEDED
------------------
Round 12 made the production join STRICT: a run token must be declared before
the records are read, because inferring it from the records being judged is
circular (see ObsBatchSpec::strictToken and the new gate term
"token-not-resolved-on-declaration").

The round-11 tests called obsBatchSpecOf(expectedBatch, 0, ...) -- no token --
and then asserted `controlledBatchComplete`. Those assertions were passing
precisely BECAUSE the token was being inferred from the records. They are now
correctly refused, so the tests have to declare the token their fixtures
actually carry.

This is a fix to the TESTS, not to the production rule. Each edit is anchored
on the assertion that identifies the case, so a wrong anchor fails loudly
instead of silently editing the wrong block.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
TARGET = os.path.join(ROOT, 'tests', 'dma-observe-test.cpp')

# (anchor assertion, old spec line, new spec line)
EDITS = [
    ('check(j.hasCompletePair, "A: a complete pair exists");',
     'obsBatchSpecOf(1, 0, winStart, winEnd)',
     'obsBatchSpecOf(1, 7, winStart, winEnd)'),
    ('check(j.hasCompletePair, "C: a pair exists");',
     'obsBatchSpecOf(2, 0, winStart, winEnd)',
     'obsBatchSpecOf(2, 7, winStart, winEnd)'),
    ('check(j.hasCompletePair, "D: request 1 is a complete pair");',
     'obsBatchSpecOf(2, 0, winStart, winEnd)',
     'obsBatchSpecOf(2, 7, winStart, winEnd)'),
    ('checkU64(j.bizCount, 1, "both segments fold into ONE business op");',
     'obsBatchSpecOf(1, 0, winStart, winEnd)',
     'obsBatchSpecOf(1, 0xA1B2C3D4, winStart, winEnd)'),
    ('checkU64(j.batchUnexpected, 1, "an out-of-range request is counted");',
     'obsBatchSpecOf(1, 0, winStart, winEnd)',
     'obsBatchSpecOf(1, 7, winStart, winEnd)'),
    # NOTE: the "single-request batch is complete" assertion at the end of the
    # two-segment case is in the SAME block as the "both segments fold into ONE
    # business op" assertion above, so it is covered by that edit. Listing it
    # separately made this script refuse -- correctly -- because the spec it
    # would have replaced was no longer there. That refusal is the reason to
    # keep the anchor-based check rather than a blind text replace.
]


def main():
    with open(TARGET, encoding='utf-8', newline='') as f:
        src = f.read()
    if '\r' in src:
        print('REFUSED: the target contains CR bytes')
        return 1

    for anchor, old, new in EDITS:
        if anchor not in src:
            print('REFUSED: anchor not found: %s' % anchor)
            return 1
        pos = src.index(anchor)
        before = src[:pos]
        # The spec that belongs to this case is the LAST one before the anchor.
        # Requiring that -- rather than a fixed byte distance -- is what makes
        # the edit provably touch the right case: if any other spec sits
        # between them, this anchor's case is not the one being edited.
        last = before.rfind('obsBatchSpecOf(')
        if last < 0:
            print('REFUSED: no spec at all before the anchor: %s' % anchor)
            return 1
        if before[last:last + len(old)] != old:
            print('REFUSED: the spec for "%s" is %r, not %r'
                  % (anchor[:40], before[last:last + len(old)], old))
            return 1
        src = src[:last] + new + src[last + len(old):]

    with open(TARGET, 'w', encoding='utf-8', newline='') as f:
        f.write(src)
    print('declared the run token in %d round-11 batch tests' % len(EDITS))
    return 0


if __name__ == '__main__':
    sys.exit(main())
