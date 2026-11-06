#!/usr/bin/env python3
"""Negative regression tests for tools/analyze-round6.py.

WHY THIS EXISTS
---------------
The round-5 analyser passed captures it should have rejected, because it
compared values that could both be `None`:

    hs == he            # both absent -> True
    subs == comp        # both absent -> True
    recs == subs        # both absent -> True

and because it never decoded the stop STATUS word, never cross-checked the
per-command records, and never reconciled the raw event array with the
counters. Those are exactly the four defects the task names.

These tests build minimal synthetic captures in a temp directory, run the
REAL analyser as a subprocess, and assert its exit code. They do not
reimplement the decision logic -- if they did, they would only test
themselves.

Exit codes under test:
    2 = cannot analyse (missing / malformed)
    3 = INVALID (a check failed, or two encodings disagree)
    1 = valid but not a pass
    0 = valid pass

Usage:
    py -3 tools/test-analyzer.py
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ANALYZER = os.path.join(HERE, "analyze-round6.py")

# ---------------------------------------------------------------------------
# A baseline capture that MUST be accepted as valid. Every negative test is
# this capture with exactly one thing broken, so a failure pinpoints the
# check that was supposed to catch it.
# ---------------------------------------------------------------------------
BASE = {
    "m2-b2-verdict": '"FAIL-io-page-faults-observed"',
    "m2-b2-stage": '"19-complete-faults"',
    "m2-b2-first-fail-stage": '"none"',
    "m2-b2-target-devid": "0x2500",
    "m2-b2-dump-root-pa": "0x2e9c0000",
    "m2-b2-dump-root-level": "0x4",
    "m2-b2-dump-page-mode": "0x4",
    "m2-b2-dump-pt-pages": "0x13",
    "m2-b2-dump-map-limit": "0x400000000",
    "m2-b2-dump-leaf-encoding": '"NextLevel0-2MiB-default"',
    "m2-b2-pre-window-ran": '"yes"',
    "m2-b2-pre-valid": '"yes"',
    "m2-b2-pre-entries-count": "0x0",
    "m2-b2-pre-backlog": "0x0",
    "m2-b2-pre-raw-truncated": '"no"',
    "m2-b2-main-window-ran": '"yes"',
    "m2-b2-window-valid": '"yes"',
    "m2-b2-win-dur-ms": "0xbb8",
    "m2-b2-meas-secs": "0x3",
    "m2-b2-win-head-start": "0x0",
    "m2-b2-win-tail-start": "0x0",
    "m2-b2-win-head-end": "0x0",
    "m2-b2-win-tail-end": "0x10",
    "m2-b2-win-status-start": "0x1a",
    "m2-b2-win-status-end": "0x1a",
    "m2-b2-win-entries": "0x1",
    "m2-b2-win-new-entries": "0x1",
    "m2-b2-win-devid-mismatch": "0x0",
    "m2-b2-win-pre-backlog": "0x0",
    "m2-b2-win-raw-truncated": '"no"',
    "m2-b2-win-raw-count": "0x1",
    "m2-b2-win-raw0": '"000025002000000005d1999c00000004"',
    "m2-b2-win-type2-name": '"IO_PAGE_FAULT"',
    "m2-b2-win-type2-count": "0x1",
    "m2-b2-win-dominant": '"IO_PAGE_FAULT"',
    "m2-b2-win-dominant-count": "0x1",
    "m2-b2-cmd-submits": "0x3",
    "m2-b2-cmd-completed": "0x3",
    "m2-b2-cmd-record-count": "0x3",
    "m2-b2-cmd0-label": '"inv-all"',
    "m2-b2-cmd0-dwords": '"08000000000000000000000000000000"',
    "m2-b2-cmd0-expected": "0x1",
    "m2-b2-cmd0-observed": "0x1",
    "m2-b2-cmd0-loops": "0x0",
    "m2-b2-cmd0-ok": '"yes"',
    "m2-b2-cmd1-label": '"inv-dev-entry"',
    "m2-b2-cmd1-dwords": '"02002500000000000000000000000000"',
    "m2-b2-cmd1-expected": "0x2",
    "m2-b2-cmd1-observed": "0x2",
    "m2-b2-cmd1-loops": "0x0",
    "m2-b2-cmd1-ok": '"yes"',
    "m2-b2-cmd2-label": '"inv-iommu-pages"',
    "m2-b2-cmd2-dwords": '"03000000000000000000000000000000"',
    "m2-b2-cmd2-expected": "0x3",
    "m2-b2-cmd2-observed": "0x3",
    "m2-b2-cmd2-loops": "0x0",
    "m2-b2-cmd2-ok": '"yes"',
    "m2-b2-disabled": '"yes"',
    "m2-b2-cmdbuf-stopped": '"yes"',
    "m2-b2-evtlog-stopped": '"yes"',
    "m2-b2-cmdbuf-stop-status": "0x2",
    "m2-b2-evtlog-stop-status": "0x2",
    "m2-b2-final-control": "0x220000000400",
    "m2-b2-orig-control-echo": "0x220000000400",
    "m2-b2-regs-restored": '"yes"',
    "m2-b2-cleanup": '"done"',
    "m2-b2-fault-inrange": "0x0",
    "m2-b2-fault-outofrange": "0x1",
    "m2-b2-fault-walk-present": "0x0",
    "m2-b2-fault-walk-illegal": "0x0",
    "m2-b2-fault-walk-absent": "0x1",
    "m2-b2-dma-obs": '"complete"',
    "m2-b2-dma-tx-completions-valid": '"yes"',
    "m2-b2-fault-obs-set-ranges": "0x5",
    "m2-b2-fault-in-live-set": "0x0",
    "m2-b2-fault-ownership-unknown": "0x1",
}


def render(props):
    lines = ["+-o AMDMapperProbe  <class org_maz1_AMDMapperProbe>"]
    for k, v in props.items():
        lines.append('    "%s" = %s' % (k, v))
    return "\n".join(lines) + "\n"


def run_case(name, props, want_code, tmpdir):
    path = os.path.join(tmpdir, name + ".txt")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(render(props))
    p = subprocess.run([sys.executable, ANALYZER, path],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    got = p.returncode
    ok = (got == want_code)
    return ok, got, p.stdout.decode("utf-8", "replace")


def variant(changes=None):
    """BASE with the given {full-field-name: value} overrides applied.

    Keys are the real property names, so there is no name mangling to get
    wrong. A value of None removes the field entirely.
    """
    d = dict(BASE)
    for k, v in (changes or {}).items():
        if v is None:
            d.pop(k, None)
        else:
            d[k] = v
    return d


def main():
    cases = []

    def C(name, want, changes=None):
        cases.append((name, variant(changes), want))

    # ---- 0. the baseline must be accepted (valid, FAIL outcome) ----
    C("baseline-valid", 1)

    # ---- 1. missing required fields must not compare equal ----
    # Round 5's hs == he passed when BOTH were absent.
    C("missing-head-start", 2, {"m2-b2-win-head-start": None})
    C("missing-head-end", 2, {"m2-b2-win-head-end": None})
    C("missing-both-heads", 2, {"m2-b2-win-head-start": None,
                                 "m2-b2-win-head-end": None})
    C("missing-submits", 2, {"m2-b2-cmd-submits": None})
    C("missing-completed", 2, {"m2-b2-cmd-completed": None})
    C("missing-both-cmd-counts", 2, {"m2-b2-cmd-submits": None,
                                     "m2-b2-cmd-completed": None})
    C("missing-verdict", 2, {"m2-b2-verdict": None})
    C("missing-map-limit", 2, {"m2-b2-dump-map-limit": None})
    C("missing-dma-obs", 2, {"m2-b2-dma-obs": None})

    # ---- 2. illegal numbers must be rejected, not become None ----
    C("devid-not-hex", 2, {"m2-b2-target-devid": '"0xZZ"'})
    C("devid-decimal", 2, {"m2-b2-target-devid": "9472"})
    C("entries-yes", 2, {"m2-b2-win-entries": '"yes"'})
    C("duration-empty", 2, {"m2-b2-win-dur-ms": '""'})
    C("status-negative", 2, {"m2-b2-win-status-start": "-1"})
    C("raw-count-not-hex", 2, {"m2-b2-win-raw-count": '"many"'})
    C("window-valid-number", 2, {"m2-b2-window-valid": "0x1"})

    # ---- 3. command records contradicting the summary ----
    C("record-says-not-ok", 3, {"m2-b2-cmd1-ok": '"no"'})
    C("record-ok-but-mismatch", 3, {"m2-b2-cmd2-observed": "0x9"})
    C("record-notok-but-equal", 3, {"m2-b2-cmd0-ok": '"no"'})
    C("summary-overcounts", 3, {"m2-b2-cmd-completed": "0x2"})
    C("record-missing", 3, {"m2-b2-cmd2-ok": None})
    C("record-dwords-bad", 3, {"m2-b2-cmd1-dwords": '"xyz"'})

    # ---- 4. CmdBufRun not cleared while claiming stopped ----
    C("cmdbuf-run-still-set", 3, {"m2-b2-cmdbuf-stop-status": "0x12"})
    C("evtlog-run-still-set", 3, {"m2-b2-evtlog-stop-status": "0xa"})
    C("cmdbuf-claim-no-but-bit-clear", 3,
      {"m2-b2-cmdbuf-stopped": '"no"'})
    C("stop-status-overflow", 3, {"m2-b2-cmdbuf-stop-status": "0x3"})

    # ---- 5. control branch with a pre-existing failure ----
    C("control-with-restore-failure", 3,
      {"m2-b2-verdict": '"CONTROL-sleep-only-no-dte-change"',
       "m2-b2-regs-restored": '"MISMATCH"',
       "m2-b2-final-control": "0x220000000401"})
    C("control-with-cmd-timeout", 3,
      {"m2-b2-verdict": '"CONTROL-sleep-only-no-dte-change"',
       "m2-b2-cmd-completed": "0x1"})
    C("control-clean", 1,
      {"m2-b2-verdict": '"CONTROL-sleep-only-no-dte-change"',
       "m2-b2-stage": '"19-control-preserved"'})

    # ---- 6. recovery / restore inconsistencies ----
    C("control-not-restored", 3, {"m2-b2-final-control": "0x220000000401"})
    C("cleanup-refused", 3, {"m2-b2-cleanup": '"REFUSED"'})
    C("disabled-claim-no", 3, {"m2-b2-disabled": '"no"'})

    # ---- 7. event accounting inconsistencies ----
    C("truncation-flag-lies", 3, {"m2-b2-win-entries": "0x5"})
    C("type-sum-mismatch", 3, {"m2-b2-win-type2-count": "0x2"})
    C("new-entries-wrong", 3, {"m2-b2-win-new-entries": "0x5"})
    C("raw-declared-absent", 3, {"m2-b2-win-raw-count": "0x2"})
    C("fault-not-walked", 3, {"m2-b2-fault-walk-absent": "0x0"})

    # ---- 8. observation never ran ----
    C("observation-skipped", 3, {"m2-b2-dma-obs": '"SKIP-no-bar2"'})
    C("no-observed-ranges", 3, {"m2-b2-fault-obs-set-ranges": "0x0"})

    # ---- 9. the round-4 leaf encoding must be caught ----
    C("old-illegal-leaf", 3,
      {"m2-b2-dump-leaf-encoding": '"NextLevel7-2MiB"'})

    # ---- 10. valid capture with no events -> INDETERMINATE, not pass ----
    C("no-events", 1, {
        "m2-b2-win-entries": "0x0",
        "m2-b2-win-new-entries": "0x0",
        "m2-b2-win-raw-count": "0x0",
        "m2-b2-win-raw0": None,
        "m2-b2-win-type2-name": None,
        "m2-b2-win-type2-count": None,
        "m2-b2-win-dominant": '"none"',
        "m2-b2-win-dominant-count": "0x0",
        "m2-b2-fault-outofrange": "0x0",
        "m2-b2-fault-walk-absent": "0x0",
        "m2-b2-fault-in-live-set": "0x0",
        "m2-b2-fault-ownership-unknown": "0x0",
        "m2-b2-verdict": '"INDETERMINATE-no-events"',
    })

    tmpdir = os.path.join(HERE, "..", "build-work-analyser-test")
    tmpdir = os.path.abspath(tmpdir)
    if not os.path.isdir(tmpdir):
        os.makedirs(tmpdir)
    npass = 0
    nfail = 0
    print("Negative regression tests for analyze-round6.py")
    print("=" * 78)
    print("analyzer : %s" % ANALYZER)
    print("workdir  : %s" % tmpdir)
    print()

    for name, props, want in cases:
        ok, got, out = run_case(name, props, want, tmpdir)
        if ok:
            npass += 1
            print("PASS %-38s exit=%d" % (name, got))
        else:
            nfail += 1
            print("FAIL %-38s exit=%d want=%d" % (name, got, want))
            tail = out.strip().splitlines()[-14:]
            for line in tail:
                print("       " + line)

    print()
    print("%d passed, %d failed" % (npass, nfail))
    if nfail == 0:
        print("RESULT: ALL ANALYSER REGRESSIONS PASS")
        return 0
    print("RESULT: FAILURES")
    return 1


if __name__ == "__main__":
    sys.exit(main())
