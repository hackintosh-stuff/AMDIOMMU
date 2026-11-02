#!/usr/bin/env python3
"""control-shape.py -- what does the PRODUCTION control branch actually publish?

WHY THIS EXISTS
---------------
Round 12's control fixture was written by hand from a reading of the code, and
it got the shape wrong in BOTH directions:

  * it INVENTED `m2-b2-obs-snapshot-used`, a property the control branch cannot
    produce (it takes `goto recover` before `m2b2ReadDriverObs()`), which hid
    the fact that the analyser refused a legitimate control capture;
  * it DELETED `m2-b2-stage-inv-all` / `-inv-dev` / `-inv-pages` and the
    command records, which the control branch DOES publish -- step 18 runs on
    the `recover` path, after the `goto`.

A hand-written list is a claim about the code. This script DERIVES the list from
the code, so the fixture and the schema cannot drift from the production branch
without one of the three failing.

HOW IT DECIDES
--------------
It parses the body of `runM22b2PageTableProbe()` by brace matching (so it does
not wander into the other functions in the same file), then classifies every
`setProperty` / `setHexProperty` call site inside that body:

  control     before the `if (fM22b2SleepOnly)` branch, or at/after `recover:`
  translation between the two -- skipped by the control branch's `goto recover`

Within `control`, a call is `always` when it sits at the function's own brace
depth (it runs unconditionally on that path) and `conditional` when it is
nested inside an `if`. The distinction matters: a fixture must contain every
`always` property, and may contain a `conditional` one only with the value the
condition implies.

Output: a Python dict literal on stdout, plus a human-readable listing on
stderr when --verbose is given.
"""
import json
import re
import sys

FN = 'runM22b2PageTableProbe'


def find_function(text, name):
    """Return (start, end) character offsets of the function body braces."""
    m = re.search(r'\b' + name + r'\s*\(', text)
    if not m:
        raise SystemExit('refused: %s() not found' % name)
    # the body's opening brace is the first '{' after the parameter list closes
    i = m.end()
    depth = 1
    while i < len(text) and depth:
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
        i += 1
    while i < len(text) and text[i] != '{':
        i += 1
    start = i
    depth = 0
    while i < len(text):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return start, i
        i += 1
    raise SystemExit('refused: unbalanced braces in %s()' % name)


def strip_comments(text):
    """Blank out // and /* */ comments, PRESERVING LENGTH.

    Round 12's gate-wiring checker read a comment and reported the old defect as
    still present. The same mistake here would invent a property.

    Length must be preserved because the control-branch and `recover:` offsets
    are computed on the original text and then used to classify call sites in
    the stripped text. The first version of this function DELETED comments, so
    every offset after the first block comment was shifted and a property from
    the translation-only region was classified as unconditional.
    """
    out = list(text)
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '/' and i + 1 < n and text[i + 1] == '/':
            while i < n and text[i] != '\n':
                out[i] = ' '
                i += 1
        elif c == '/' and i + 1 < n and text[i + 1] == '*':
            out[i] = out[i + 1] = ' '
            i += 2
            while i + 1 < n and not (text[i] == '*' and text[i + 1] == '/'):
                if text[i] != '\n':
                    out[i] = ' '
                i += 1
            if i + 1 < n:
                out[i] = out[i + 1] = ' '
                i += 2
        elif c == '"' or c == "'":
            q = c
            i += 1
            while i < n and text[i] != q:
                if text[i] == '\\':
                    i += 1
                i += 1
            i += 1
        else:
            i += 1
    return ''.join(out)


def match_brace(text, open_at):
    """Index of the '}' matching the '{' at open_at."""
    depth = 0
    i = open_at
    while i < len(text):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise SystemExit('refused: unbalanced braces')


def main():
    if len(sys.argv) < 2:
        print('usage: control-shape.py <AMDMapperProbePgt.cpp> [--verbose]',
              file=sys.stderr)
        return 2
    verbose = '--verbose' in sys.argv
    text = open(sys.argv[1], encoding='utf-8').read()
    start, end = find_function(text, FN)
    body = text[start:end]

    # The control branch's own block, and the `recover:` label, relative to the
    # body. The region between the branch's closing brace and `recover:` is the
    # translation-only region -- the control path's `goto recover` jumps over
    # it. The branch's INTERIOR is not translation-only; it is the control
    # experiment itself, and that is where the control stage's own timing is
    # published.
    m = re.search(r'if\s*\(\s*fM22b2SleepOnly\s*\)\s*\{', body)
    if not m:
        raise SystemExit('refused: the control branch was not found in %s()'
                         % FN)
    branch_open = m.end() - 1
    branch_close = match_brace(body, branch_open)
    m = re.search(r'^\s*recover:\s*$', body, re.M)
    if not m:
        raise SystemExit('refused: the `recover:` label was not found')
    rec_at = m.start()

    clean = strip_comments(body)
    # strip_comments preserves length, so the offsets above still apply.

    def depth_at(pos):
        d = 0
        for i in range(pos):
            if clean[i] == '{':
                d += 1
            elif clean[i] == '}':
                d -= 1
        return d

    pat = re.compile(r'set(?:Hex)?Property\(\s*(?:this\s*,\s*)?"([^"]+)"')

    # PASS 1: which property NAMES appear anywhere on the control-reachable
    # path?
    #
    # This must be a separate pass. A name can be published both inside the
    # control branch AND in the translation-only region: `m2-b2-dte` is
    # "NOT-switched-control" in the branch and "switched-to-translation" after
    # it, and `m2-b2-stage` / `m2-b2-verdict` appear on every path. Classifying
    # per call site and unioning put such a name in BOTH lists, so the fixture
    # cross-check demanded a translation-only property be absent that a control
    # run really does publish. Reachability is a property of the NAME.
    reachable = set()
    for mm in pat.finditer(clean):
        pos = mm.start()
        if pos < branch_open or pos <= branch_close or pos >= rec_at:
            reachable.add(mm.group(1))

    # PASS 2: classify by region and brace depth.
    always, conditional, translation = [], [], []
    for mm in pat.finditer(clean):
        name = mm.group(1)
        pos = mm.start()
        if name not in reachable:
            if name not in translation:
                translation.append(name)
            continue
        if pos < branch_open or pos >= rec_at:
            base = 1              # runs on both paths, at function depth
        else:
            base = 2              # runs only in control, inside the branch
        bucket = always if depth_at(pos) == base else conditional
        if name not in bucket:
            bucket.append(name)

    out = {
        'function': FN,
        'always': sorted(always),
        'conditional': sorted(conditional),
        'translation_only': sorted(translation),
    }
    if verbose:
        print('%s(): %d unconditional, %d conditional, %d translation-only'
              % (FN, len(out['always']), len(out['conditional']),
                 len(out['translation_only'])), file=sys.stderr)
        for k in ('always', 'conditional', 'translation_only'):
            print('\n%s (%d):' % (k, len(out[k])), file=sys.stderr)
            for p in out[k]:
                print('   %s' % p, file=sys.stderr)
    print(json.dumps(out, indent=1, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
