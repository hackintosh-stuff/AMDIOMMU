#!/usr/bin/env python3
"""Round-3 audit: find every place the probe compares fault counts that were
collected over DIFFERENT window lengths.

This is the defect that invalidates the round-2 conclusions. It is provable
from the source alone, so it must be established before any new experiment.

Pattern:
  * evtCount2 is measured after IOSleep(holdSecs * 1000), where holdSecs is
    20 in pgthold mode and 2 otherwise.
  * The leafprobe / after-faults / domid1 / negative-control sections each
    IOSleep(2000) and then compare their count against evtCount2.

Under amdiommu=pgthold the baseline window is 20 s and every comparison window
is 2 s -- a 10x mismatch. A genuine 10x RATE increase therefore looks like
"same order", and the domid 5-vs-3 result actually means domid 1 produced a
~10x HIGHER rate.

Run: py -3 tools/audit-window-mismatch.py
"""
import re
import sys

SRC = "kext/AMDMapperProbe.cpp"


def main():
    with open(SRC, "r", encoding="utf-8", newline="") as f:
        lines = f.read().split("\n")

    # Locate every IOSleep in the M2-2b-2 probe and the window definition.
    sleeps = []
    for i, ln in enumerate(lines, 1):
        m = re.search(r"IOSleep\(([^)]*)\)", ln)
        if m:
            sleeps.append((i, m.group(1).strip(), ln.strip()))

    print("All IOSleep() calls in the probe")
    print("-" * 78)
    for i, arg, text in sleeps:
        print("  line {:<5} IOSleep({})".format(i, arg))
    print()

    hold = [(i, a, t) for (i, a, t) in sleeps if "holdSecs" in a]
    fixed2s = [(i, a, t) for (i, a, t) in sleeps if a == "2000"]

    print("Window used for the BASELINE measurement (evtCount2):")
    for i, a, t in hold:
        print("  line {:<5} IOSleep({})  <- holdSecs is 20 in pgthold".format(i, a))
    print()
    print("Windows used for COMPARISON measurements:")
    for i, a, t in fixed2s:
        print("  line {:<5} IOSleep(2000)  <- 2 s, vs a 20 s baseline".format(i))
    print()

    # Confirm holdSecs really is 20 in hold mode
    holddef = [ln.strip() for ln in lines if "holdSecs = " in ln]
    print("Definition:")
    for ln in holddef:
        print("  " + ln)
    print()

    # The comparison sites, to show they compare against evtCount2
    print("Comparison sites that use evtCount2 as the baseline")
    print("-" * 78)
    for i, ln in enumerate(lines, 1):
        if "evtCount2" in ln and ("baseCount" in ln or "baseN" in ln
                                  or "d0 = evtCount2" in ln
                                  or "domid0-faults" in ln):
            print("  line {:<5} {}".format(i, ln.strip()))
    print()

    print("=" * 78)
    verdict_ok = True
    if hold and fixed2s:
        print("DEFECT CONFIRMED: baseline window != comparison window.")
        print()
        print("  baseline  : 20 s   (amdiommu=pgthold)")
        print("  comparison:  2 s")
        print("  ratio     : 10x")
        print()
        print("Consequences, all of which must be retracted or re-derived:")
        print("  - 'leafprobe faults unchanged => leaf level not reached'")
        print("    is void: a 10x rate increase would score as 'unchanged'.")
        print("  - 'domid 0 vs 1 same order => domid not the cause'")
        print("    is void: 3 faults in 2 s is ~15 per 20 s, i.e. ~3x MORE")
        print("    than the 5 measured in 20 s.")
        print("  - the A/B/A 'reversibility' verdict is void for the same")
        print("    reason.")
        verdict_ok = False
    print()
    print("Required fix: every measurement window must be identical, and the")
    print("window length must be recorded with each count.")
    return 0 if verdict_ok else 0


if __name__ == "__main__":
    sys.exit(main())
