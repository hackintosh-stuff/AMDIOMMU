#!/usr/bin/env python3
"""patch-analyzer12-modes2.py -- two gaps the mode verifier found.

GAP 1: a check that is conditional on a FIELD can vanish instead of going N/A.
-----------------------------------------------------------------------------
`evt-limit` is only recorded when `m2-b2-map-limit` exists, and
`tl-business-inside` was only recorded in the translation branch. In control
mode both simply disappeared from the output.

A missing row is worse than an N/A row. The summary counts N/A and says so;
a missing row silently changes the denominator, so "0 failed" is computed over
a smaller set than the reader expects. Every check id must appear in every run.

GAP 2: the control-shape check passed unconditionally.
-----------------------------------------------------
`schema-control-shape` was written as `rec(..., True, ...)`, which means a
capture labelled control was accepted as control no matter what it contained.
The property it is supposed to assert is real: a control run never walks a page
table, never decodes a snapshot and never declares a token, so a capture that
carries those fields is NOT a control capture regardless of its label.

That is what makes the control-mode N/A set meaningful. If a translation
capture could be relabelled "control" and pass, the N/A rows would be a way to
avoid checks rather than a statement about which experiment ran.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
TARGET = os.path.join(ROOT, 'tools', 'analyze-round12.py')

SUBS = [
    # ---- GAP 1a: evt-limit must be recorded even when there is no limit ---
    ("""    limit = P.get('m2-b2-map-limit')
    if limit is not None:
        over = [a for _, a in faults if a >= limit]
        print('  identity map limit = 0x%x (%.4f GiB)'
              % (limit, limit / (1024.0 ** 3)))
        rec('events', 'evt-limit', 'no fault lies at or above the identity map limit',
            len(over) == 0, 'over-limit: %s' % ['0x%x' % a for a in over],
            na=is_control)""",
     """    limit = P.get('m2-b2-map-limit')
    if limit is not None:
        over = [a for _, a in faults if a >= limit]
        print('  identity map limit = 0x%x (%.4f GiB)'
              % (limit, limit / (1024.0 ** 3)))
        rec('events', 'evt-limit', 'no fault lies at or above the identity map limit',
            len(over) == 0, 'over-limit: %s' % ['0x%x' % a for a in over],
            na=is_control)
    else:
        # A check that is conditional on a FIELD must still be recorded. A
        # missing row changes the denominator of the summary without saying so;
        # an N/A row is counted and printed.
        rec('events', 'evt-limit',
            'no fault lies at or above the identity map limit', False,
            'm2-b2-map-limit absent', na=True)"""),

    # ---- GAP 1b: tl-business-inside must be recorded in control mode -----
    ("""    if is_control:
        rec('timeline', 'tl-fields', 'the timeline fields are present',
            have_timeline, na=True)
        rec('timeline', 'tl-order', 'the timeline is ordered', False, na=True)""",
     """    if is_control:
        rec('timeline', 'tl-fields', 'the timeline fields are present',
            have_timeline, na=True)
        rec('timeline', 'tl-order', 'the timeline is ordered', False, na=True)
        # The control branch has no translation window, so there is no window
        # for a business record to fall inside. Recorded as N/A rather than
        # omitted, so every run reports the same check ids.
        rec('timeline', 'tl-business-inside',
            'every business record falls inside the translation window',
            False, na=True)"""),

    # ---- GAP 2: the control-shape check must actually check --------------
    ("""        must_be_absent = ['m2-b2-bizwalk-dte-raw', 'm2-b2-bizwalk-count',
                          'm2-b2-obs-used-sha256', 'm2-b2-obs-declared-token']
        still_present = [k for k in must_be_absent if P.get(k) is not None]
        rec('schema', 'schema-control-shape',
            'the control capture has the fields a control run really lacks',
            True,
            'present-but-unexpected: %s' % still_present)
        if still_present:
            print('  NOTE: a control run should not publish %s. Their presence')
            print('        means the capture is not a pure control branch.')""",
     """        # Fields a control run CANNOT produce, because the branch that
        # produces them never executes. Their presence is not a warning: it
        # means the capture is not a control capture, whatever its label says.
        must_be_absent = ['m2-b2-bizwalk-dte-raw', 'm2-b2-bizwalk-count',
                          'm2-b2-obs-used-sha256', 'm2-b2-obs-declared-token',
                          'm2-b2-dma-t-win-start', 'm2-b2-dma-t-win-end',
                          'm2-b2-dma-t-translate-on', 'm2-b2-dma-t-inv-complete']
        still_present = [k for k in must_be_absent if P.get(k) is not None]
        rec('schema', 'schema-control-shape',
            'the control capture has the fields a control run really lacks',
            not still_present,
            'present-but-impossible-in-control-mode: %s' % still_present)
        if still_present:
            print('  NOTE: a control run never walks a page table, decodes a')
            print('        snapshot, opens a window or switches the DTE, so a')
            print('        capture carrying those fields is NOT a control run.')
            print('        Relabelling a translation capture does not make it')
            print('        one, and accepting it would turn the control N/A set')
            print('        into a way of skipping checks.')"""),
]


def main():
    with open(TARGET, encoding='utf-8', newline='') as f:
        src = f.read()
    if '\r' in src:
        print('REFUSED: the target contains CR bytes')
        return 1
    applied = 0
    for old, new in SUBS:
        if src.count(old) != 1:
            print('REFUSED: anchor appears %d times:\n---\n%s\n---'
                  % (src.count(old), old[:220]))
            return 1
        src = src.replace(old, new, 1)
        applied += 1
    with open(TARGET, 'w', encoding='utf-8', newline='') as f:
        f.write(src)
    print('applied %d fixes' % applied)
    return 0


if __name__ == '__main__':
    sys.exit(main())
