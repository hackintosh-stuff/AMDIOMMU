#!/usr/bin/env python3
"""Add first-failure recording to every `goto recover` site (v0.20.0).

Why: the task requires "保留首个失败阶段及恢复结果，避免后来的通用状态掩盖
原因".  Round 4 only ever published the LAST stage property written, so an
early abort followed by the generic step-19 verdict lost the real cause.

Each abort site now records firstFailStage / firstFailReason before jumping
to recover, guarded so the FIRST one wins.

Run from MSI_X570/amd-iommu/:
    py -3 tools/add-first-fail.py
"""
import io
import sys

P = "kext/AMDMapperProbe.cpp"

# (anchor block that must appear exactly once, replacement)
EDITS = [
    (
        '''            setProperty("m2-b2-verdict", "INVALID-evt-log-will-not-stop");
            setProperty("m2-b2-stage", "11-abort-evt-log");
            goto recover;''',
        '''            setProperty("m2-b2-verdict", "INVALID-evt-log-will-not-stop");
            setProperty("m2-b2-stage", "11-abort-evt-log");
            if (!firstFailStage) {
                firstFailStage = "11-abort-evt-log";
                firstFailReason = "event log could not be stopped before reset";
            }
            goto recover;''',
    ),
    (
        '''        setProperty("m2-b2-verdict", "INVALID-inv-all-no-completion");
        setProperty("m2-b2-stage", "12-abort-inv-all");
        goto recover;''',
        '''        setProperty("m2-b2-verdict", "INVALID-inv-all-no-completion");
        setProperty("m2-b2-stage", "12-abort-inv-all");
        if (!firstFailStage) {
            firstFailStage = "12-abort-inv-all";
            firstFailReason = "CMD_INV_ALL did not complete";
        }
        goto recover;''',
    ),
    (
        '''            setProperty("m2-b2-verdict", "INVALID-inv-dev-entry");
            setProperty("m2-b2-stage", "15-abort-inv-dev-entry");
            goto recover;''',
        '''            setProperty("m2-b2-verdict", "INVALID-inv-dev-entry");
            setProperty("m2-b2-stage", "15-abort-inv-dev-entry");
            if (!firstFailStage) {
                firstFailStage = "15-abort-inv-dev-entry";
                firstFailReason = "CMD_INV_DEV_ENTRY did not complete";
            }
            goto recover;''',
    ),
    (
        '''            setProperty("m2-b2-verdict", "INVALID-inv-pages");
            setProperty("m2-b2-stage", "15-abort-inv-pages");
            goto recover;''',
        '''            setProperty("m2-b2-verdict", "INVALID-inv-pages");
            setProperty("m2-b2-stage", "15-abort-inv-pages");
            if (!firstFailStage) {
                firstFailStage = "15-abort-inv-pages";
                firstFailReason = "CMD_INV_IOMMU_PAGES did not complete";
            }
            goto recover;''',
    ),
]

# The pgtsleep control branch jumps to recover by design; it is not a failure,
# so it must NOT set firstFailStage. Assert that we left it alone.

def main():
    with io.open(P, "r", encoding="utf-8", newline="") as f:
        src = f.read()

    if "\r" in src:
        print("ERROR: source contains CR bytes", file=sys.stderr)
        return 1

    for i, (old, new) in enumerate(EDITS):
        n = src.count(old)
        if n != 1:
            print("ERROR: edit {} anchor appears {} times".format(i, n),
                  file=sys.stderr)
            return 1
        src = src.replace(old, new)

    # Sanity: the control branch must still jump without recording a failure.
    ctrl = '''        setProperty("m2-b2-stage", "13-control-complete");
        goto recover;'''
    if src.count(ctrl) != 1:
        print("ERROR: control branch anchor not found exactly once",
              file=sys.stderr)
        return 1

    # 1 declaration + 1 pre-window site + the 4 abort sites above = 6
    if src.count("firstFailStage = ") != 6:
        print("ERROR: expected 6 firstFailStage assignments, found {}".format(
            src.count("firstFailStage = ")), file=sys.stderr)
        return 1

    with io.open(P, "w", encoding="utf-8", newline="") as f:
        f.write(src)

    print("OK: 4 abort sites now record the first failure "
          "(plus the pre-window site already present)")
    print("CR bytes: 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
