#!/usr/bin/env python3
"""Round-3 re-analysis, reading the ORIGINAL evidence instead of hardcoded
sample values.

WHY THIS WAS REWRITTEN
----------------------
The first version of this script embedded the numbers it then "analysed"
(DATA = [("baseline-1", 14, ...), ...]). That is not verification: the script
could not detect a missing field, and it re-derived the same model rather than
reading what the machine actually recorded. It also asserted a conclusion
("the fault count is INDEPENDENT of page-table content") that a 3-window
sample cannot support.

This version reads a timestamped `ioreg` dump and reports what is actually
present. Fields the 0.18.0 capture does not contain are reported as MISSING,
and the conclusion is downgraded accordingly.

Usage:
    py -3 tools/analyze-round3.py docs/evidence/20261031-160500/props.txt
    py -3 tools/analyze-round3.py docs/evidence/20261031-161200/props.txt
"""
import re
import sys

# Fields a 0.18.0 capture was expected to contain.
EXPECTED_0180 = [
    "m2-b2-verdict",
    "m2-b2-stage",
    "m2-b2-base1",
    "m2-b2-base2",
    "m2-b2-base3",
    "m2-b2-base-max",
    "m2-b2-cls-a1-count",
    "m2-b2-cls-b-count",
    "m2-b2-cls-a2-count",
    "m2-b2-cls-verdict",
    "m2-b2-leafprobe-faults",
    "m2-b2-leafprobe-verdict",
    "m2-b2-neg-count",
    "m2-b2-domid0-faults",
    "m2-b2-domid1-faults",
]

# Fields that a RELIABLE window would need but 0.18.0 never published.
# Their absence is the reason round 3's numbers cannot be reconciled with a
# known observation window.
NEEDED_BUT_ABSENT = [
    "m2-b2-window-valid",
    "m2-b2-win-dur-ms",
    "m2-b2-win-head-start",
    "m2-b2-win-tail-start",
    "m2-b2-win-head-end",
    "m2-b2-win-tail-end",
    "m2-b2-win-status-start",
    "m2-b2-win-status-end",
    "m2-b2-win-entries",
    "m2-b2-win-devid-mismatch",
    "m2-b2-cmd-submits",
    "m2-b2-cmd-completed",
    "m2-b2-inv-domid",
    "m2-b2-regs-restored",
]


def parse_props(text):
    out = {}
    pat = re.compile(r'"([A-Za-z0-9\-\.]+)"\s*=\s*(?:"([^"]*)"|([^,\n}]+))')
    for m in pat.finditer(text):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else m.group(3).strip()
        if key.startswith("m2-b2-"):
            out[key] = val
    return out


def as_int(v):
    if v is None:
        return None
    v = v.strip()
    try:
        return int(v, 16) if v.lower().startswith("0x") else int(v, 10)
    except ValueError:
        return None


def main():
    if len(sys.argv) < 2:
        print("usage: analyze-round3.py <props.txt>")
        return 2

    path = sys.argv[1]
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            props = parse_props(f.read())
    except IOError as e:
        print("cannot read {}: {}".format(path, e))
        return 2

    print("Round-3 RE-ANALYSIS from original evidence")
    print("=" * 74)
    print("source : {}".format(path))
    print("verdict: {}".format(props.get("m2-b2-verdict", "<missing>")))
    print()

    print("Fields present in this 0.18.0 capture")
    print("-" * 74)
    missing_expected = []
    for k in EXPECTED_0180:
        v = props.get(k)
        if v is None:
            missing_expected.append(k)
            print("  {:<34} MISSING".format(k))
        else:
            print("  {:<34} {}".format(k, v))

    print()
    print("Fields a reliable window would need")
    print("-" * 74)
    absent = []
    for k in NEEDED_BUT_ABSENT:
        if k not in props:
            absent.append(k)
    if absent:
        print("  ABSENT ({} of {}):".format(len(absent), len(NEEDED_BUT_ABSENT)))
        for k in absent:
            print("    " + k)
        print()
        print("  Without these, the capture does not record")
        print("    - whether the event log was running or overflowed,")
        print("    - the measured duration of any window,")
        print("    - the HEAD/TAIL positions bracketing each window,")
        print("    - whether commands completed,")
        print("    - whether registers were restored.")
        print("  A count with no window metadata cannot be reconciled with")
        print("  any other count. This is why the round-3 numbers could not")
        print("  be verified, independently of the 20s/2s question.")
    else:
        print("  all present")

    print()
    print("=" * 74)
    print("CONCLUSION (downgraded from the original script)")
    print("=" * 74)
    print()
    print("The original script claimed:")
    print("  'the fault count is INDEPENDENT of page-table content'")
    print()
    print("That claim is NOT supported by this evidence:")
    print()
    b = [as_int(props.get("m2-b2-base{}".format(i))) for i in (1, 2, 3)]
    b = [x for x in b if x is not None]
    if b:
        print("  baseline windows : {}".format(b))
        print("  observed spread  : {}".format(max(b) - min(b)))
        print()
    print("  With three baseline windows the spread alone is comparable to")
    print("  the differences being compared, so the correct statement is:")
    print()
    print("    'in this capture the counts lacked discriminating power'")
    print()
    print("  which is weaker than 'the counts are independent of content'.")
    print("  The stronger claim needs a designed comparison with repeated")
    print("  windows per condition, which round 4 did not attempt either.")
    print()
    print("Also note: round 4 found the 0.18.0 sampler itself violated the")
    print("producer/consumer protocol (it rewrote EVT_TAIL and rewound")
    print("EVT_HEAD while logging was live), so counts taken by it are not")
    print("comparable to counts taken by the 0.19.0 sampler.")
    return 0 if not missing_expected else 1


if __name__ == "__main__":
    sys.exit(main())
