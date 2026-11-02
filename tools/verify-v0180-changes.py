#!/usr/bin/env python3
"""Offline structural check of the v0.18.0 changes.

Verifies, from the source text only (no hardware):
  1. every event-count measurement now goes through m2b2MeasureEvents()
  2. no bare IOSleep(2000) measurement windows remain
  3. the window length is a single constant
  4. the classification block sets the translation DTE explicitly (it must
     not rely on savedDte0, which is the PASSTHROUGH entry)
  5. A/B/A is symmetric: A and A' both install dteRoot, B clears only V
  6. the V-bit delta is exactly one bit

Run: py -3 tools/verify-v0180-changes.py
"""
import io
import re
import sys

SRC = "kext/AMDMapperProbe.cpp"


def main():
    with io.open(SRC, encoding="utf-8", newline="") as f:
        text = f.read()
    lines = text.split("\n")

    problems = []
    notes = []

    # 1/2/3 -- measurement windows
    helper = "static UInt32 m2b2MeasureEvents(" in text
    print("1. m2b2MeasureEvents() helper present            : {}".format(helper))
    if not helper:
        problems.append("helper missing")

    meas_const = re.search(r"#define M2B2_MEAS_SECS\s+(\d+)", text)
    print("2. M2B2_MEAS_SECS                                : {}".format(
        meas_const.group(1) if meas_const else "MISSING"))
    if not meas_const:
        problems.append("window constant missing")

    bare = []
    for i, ln in enumerate(lines, 1):
        # Strip a line comment before testing: my own explanatory comments
        # quote the old IOSleep(2000) text, and those must not count as code.
        code = ln.split("//", 1)[0]
        if re.search(r"IOSleep\(2000\)", code):
            bare.append((i, code.strip()))
    print("3. remaining bare IOSleep(2000) windows          : {}".format(len(bare)))
    for i, ln in bare:
        print("     line {}: {}".format(i, ln))
    if bare:
        problems.append("{} bare 2s window(s) remain".format(len(bare)))

    calls = len(re.findall(r"m2b2MeasureEvents\(base, evtBuf\)", text))
    print("4. m2b2MeasureEvents() call sites                : {}".format(calls))
    if calls < 5:
        problems.append("expected >=5 measurement call sites, found {}".format(calls))

    # 4 -- classification block must install dteRoot explicitly
    cls_start = text.find("第 15d 步")
    if cls_start < 0:
        problems.append("classification block not found")
        print("5. classification block                          : MISSING")
    else:
        cls_end = text.find("第 16 步", cls_start)
        block = text[cls_start:cls_end if cls_end > 0 else len(text)]
        print("5. classification block found, {} bytes".format(len(block)))

        installs_root = block.count("dte[tgt * 4 + 0] = dteRoot;")
        uses_saved = "dte[tgt * 4 + 0] = savedDte0 & ~DTE_V;" in block
        restore_saved = "dte[tgt * 4 + 0] = savedDte0;" in block

        print("   A  installs dteRoot explicitly                : {}x".format(
            installs_root))
        print("   A' installs dteRoot explicitly                : {}".format(
            "dte[tgt * 4 + 0] = dteRoot;" in block))
        print("   B  clears V from dteRoot (not savedDte0)      : {}".format(
            "dte[tgt * 4 + 0] = dteRoot & ~DTE_V;" in block))
        print("   still references savedDte0 & ~DTE_V (bad)     : {}".format(
            uses_saved))
        print("   restores savedDte0 at the end (good)          : {}".format(
            restore_saved))

        if installs_root < 2:
            problems.append(
                "A/A' must both install dteRoot (found {})".format(installs_root))
        if uses_saved:
            problems.append("B still derives from savedDte0 (passthrough!)")
        if "dte[tgt * 4 + 0] = dteRoot & ~DTE_V;" not in block:
            problems.append("B does not clear V from dteRoot")
        if not restore_saved:
            problems.append("block does not restore savedDte0 at the end")

    # 6 -- V-bit delta is exactly one bit
    print("6. DTE_V defined as a single bit                  : {}".format(
        "DTE_V    (1ULL << 0)" in text))
    if "DTE_V    (1ULL << 0)" not in text:
        problems.append("DTE_V is not (1ULL << 0)")

    # The verdict must be type-based, not count-based
    typebased = ("bType[M2B2_EVENT_ILL_DEV] > 0" in text
                 and "bType[M2B2_EVENT_DEV_TAB_ERR] > 0" in text)
    print("7. verdict is event-TYPE based, not count based   : {}".format(
        typebased))
    if not typebased:
        problems.append("verdict is not type-based")

    print()
    print("=" * 62)
    if problems:
        print("FAIL ({} problem(s))".format(len(problems)))
        for p in problems:
            print("  - " + p)
        return 1
    print("ALL OFFLINE CHECKS PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
