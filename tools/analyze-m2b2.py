#!/usr/bin/env python3
"""Parse AMDMapperProbe M2-2b-2 ioreg properties into a verdict.

Reads `ioreg -l -w0 -c org_maz1_AMDMapperProbe` output (stdin or a file)
and prints a structured report focused on the questions this round must
answer:

  1. Did the hardware log events, and of WHICH TYPE?
     (type was never recorded before -- IO_PAGE_FAULT and PAGE_TAB_ERR
      mean completely different things)
  2. Do the fault addresses fall inside the mapped identity range?
  3. Does the page table actually contain every in-range fault address?
  4. Did zeroing the whole leaf table change the fault count?

Usage:
    py -3 analyze-m2b2.py props.txt
    ssh ... 'ioreg -l -w0 -c org_maz1_AMDMapperProbe' | py -3 analyze-m2b2.py -
"""
import re
import sys

# Property keys this report cares about, grouped by the question they answer.
GROUPS = [
    ("Identity / setup", [
        "m2-b2-stage", "m2-b2-verdict", "m2-b2-identity", "m2-b2-enabled",
        "m2-b2-evt-log", "m2-b2-control-on", "m2-b2-orig-control",
        "m2-b2-tgt-bus", "m2-b2-tgt-dev", "m2-b2-tgt-fn",
        "m2-b2-target-devid",
    ]),
    ("Page table build", [
        "m2-b2-pt-pa", "m2-b2-pt-bytes", "m2-b2-pt-pages",
        "m2-b2-leaf-mode", "m2-b2-level-mode", "m2-b2-page-mode",
        "m2-b2-map-limit", "m2-b2-walk", "m2-b2-walk-bad",
        "m2-b2-walk-samples", "m2-b2-walk-firstbad",
    ]),
    ("DTE switch", [
        "m2-b2-dte", "m2-b2-dte-before", "m2-b2-dte-after",
        "m2-b2-dte-pass", "m2-b2-dte-xlate",
        "m2-b2-inv-all", "m2-b2-inv", "m2-b2-inv-addr", "m2-b2-inv-loops",
    ]),
    ("Event log -- window", [
        "m2-b2-window-secs", "m2-b2-settle-faults",
        "m2-b2-evt-head2", "m2-b2-evt-tail2", "m2-b2-evt-count2",
        "m2-b2-evt-total", "m2-b2-evt-head-mod",
    ]),
    ("Event log -- type breakdown (NEW)", [
        "m2-b2-evt-dominant", "m2-b2-evt-dominant-count",
        "m2-b2-evt-type1-count", "m2-b2-evt-type2-count",
        "m2-b2-evt-type3-count", "m2-b2-evt-type4-count",
        "m2-b2-evt-type5-count", "m2-b2-evt-type6-count",
        "m2-b2-evt-type8-count",
        "m2-b2-evt-flag-rw", "m2-b2-evt-flag-i", "m2-b2-evt-bad-devid",
    ]),
    ("Address distribution (NEW)", [
        "m2-b2-fault-inrange", "m2-b2-fault-outofrange",
        "m2-b2-fault-addr-min", "m2-b2-fault-addr-max",
        "m2-b2-fault-walk-present", "m2-b2-fault-walk-absent",
        "m2-b2-fault-walk-1stabsent", "m2-b2-fault-walk-1stoa",
        "m2-b2-fault-walk-verdict", "m2-b2-fault-walk-meaning",
    ]),
    ("Leaf-level reachability (REDONE)", [
        "m2-b2-leafprobe-baseline", "m2-b2-leafprobe-iova",
        "m2-b2-leafprobe-page", "m2-b2-leafprobe-found",
        "m2-b2-leafprobe-inv", "m2-b2-leafprobe-faults",
        "m2-b2-leafprobe-verdict", "m2-b2-leafprobe-meaning",
        "m2-b2-leafprobe-restore",
    ]),
    ("Negative control", [
        "m2-b2-neg-count", "m2-b2-neg-name", "m2-b2-neg-type",
        "m2-b2-neg-devid", "m2-b2-negative-control", "m2-b2-test-validity",
    ]),
    ("Restore", [
        "m2-b2-disabled", "m2-b2-dte-restore", "m2-b2-restore-inv",
        "m2-b2-final-control", "m2-b2-final-devicetable",
        "m2-b2-final-cmdbuf", "m2-b2-final-evtbuf",
        "m2-b2-cleanup",
    ]),
]

EVENT_TYPES = {
    1: "ILL_DEV_TABLE_ENTRY",
    2: "IO_PAGE_FAULT",
    3: "DEV_TAB_HARDWARE_ERROR",
    4: "PAGE_TAB_HARDWARE_ERROR",
    5: "ILLEGAL_COMMAND_ERROR",
    6: "COMMAND_HARDWARE_ERROR",
    7: "IOTLB_INV_TIMEOUT",
    8: "INVALID_DEVICE_REQUEST",
}


def parse(text):
    """Extract m2-b2-* = <value> pairs from ioreg -l output."""
    props = {}
    # ioreg prints:  "m2-b2-verdict" = "PASS-..."
    for m in re.finditer(r'"?(m2-b2-[a-z0-9-]+)"?\s*=\s*("?)([^"\n]*)\2', text):
        props[m.group(1)] = m.group(3).strip()
    return props


def num(v):
    if v is None:
        return None
    v = v.strip().strip('"')
    try:
        if v.lower().startswith("0x"):
            return int(v, 16)
        return int(v)
    except ValueError:
        return None


def main():
    if len(sys.argv) > 1 and sys.argv[1] != "-":
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    else:
        text = sys.stdin.read()

    props = parse(text)
    if not props:
        print("No m2-b2-* properties found in input.")
        print("Check that the probe ran and ioreg was captured correctly.")
        return 1

    for title, keys in GROUPS:
        rows = [(k, props[k]) for k in keys if k in props]
        if not rows:
            continue
        print()
        print(title)
        print("-" * 70)
        for k, v in rows:
            short = k.replace("m2-b2-", "")
            print("  %-28s %s" % (short, v))

    print()
    print("=" * 70)
    print("VERDICT")
    print("=" * 70)

    # --- event type: the question that was never answered before ---
    dom = props.get("m2-b2-evt-dominant", "none")
    domn = num(props.get("m2-b2-evt-dominant-count"))
    total = num(props.get("m2-b2-evt-total"))
    print()
    print("1. Event type (previously never recorded)")
    if dom == "none" or not domn:
        print("   no events in the window")
    else:
        print("   dominant type : %s  (%s events)" % (dom, domn))
        if total:
            print("   total decoded : %d of %s reported"
                  % (total, props.get("m2-b2-evt-count2", "?")))
        if dom == "IO_PAGE_FAULT":
            print("   -> PTE not present or permission denied (page table says NO)")
        elif dom == "PAGE_TAB_ERR":
            print("   -> PTE malformed (page table structure itself is bad)")
        elif dom == "DEV_TAB_ERR":
            print("   -> DTE malformed (device table entry is bad)")
        elif dom in ("ILL_CMD", "CMD_HARD_ERR"):
            print("   -> COMMAND error; page-table conclusions are INVALID")

    # --- address coverage ---
    inr = num(props.get("m2-b2-fault-inrange"))
    outr = num(props.get("m2-b2-fault-outofrange"))
    print()
    print("2. Fault address coverage")
    if inr is None and outr is None:
        print("   not measured")
    else:
        print("   in-range     : %s" % inr)
        print("   out-of-range : %s" % outr)
        if inr == 0 and outr:
            print("   -> ALL faults outside the mapped range: the page table")
            print("      was never exercised. Previous FAIL verdict is UNSAFE.")

    # --- does the table contain them ---
    wp = num(props.get("m2-b2-fault-walk-present"))
    wa = num(props.get("m2-b2-fault-walk-absent"))
    wv = props.get("m2-b2-fault-walk-verdict")
    print()
    print("3. Does the page table contain the faulting addresses?")
    print("   verdict: %s" % wv)
    if wa:
        print("   -> %s in-range addresses are MISSING from the table"
              % wa)
        print("      first missing: %s"
              % props.get("m2-b2-fault-walk-1stabsent", "?"))
    elif wp:
        print("   -> all %s in-range addresses ARE mapped; problem is hardware-side"
              % wp)

    # --- leaf reachability ---
    lv = props.get("m2-b2-leafprobe-verdict")
    print()
    print("4. Leaf-level reachability (whole leaf table zeroed)")
    print("   baseline faults (intact table) : %s"
          % props.get("m2-b2-leafprobe-baseline", "?"))
    print("   faults with leaf table zeroed : %s"
          % props.get("m2-b2-leafprobe-faults", "?"))
    print("   verdict: %s" % lv)
    if lv == "LEAF-LEVEL-REACHED":
        print("   -> hardware DOES walk down to the leaf level")
    elif lv == "LEAF-LEVEL-NOT-REACHED":
        print("   -> hardware does NOT reach the leaf level")
    elif lv and lv.startswith("INCONCLUSIVE"):
        print("   -> still ambiguous: fault count same order as baseline")

    print()
    print("5. Final state")
    print("   %s" % props.get("m2-b2-verdict", "?"))
    print("   final-control: %s" % props.get("m2-b2-final-control", "?"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
