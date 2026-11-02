#!/usr/bin/env python3
"""Round-8 analyser negative regressions.

WHAT THIS FILE PROVES, AND WHAT IT DOES NOT
-------------------------------------------
This file tests the PYTHON ANALYSER (tools/analyze-round8.py). It does NOT
test the production C++ judgement: that is done by
tests/dma-observe-test.cpp (which compiles the shared core the kext includes)
and by tools/verify-round8.py's MUTATION class (which re-injects each defect
into the core and requires the C++ tests to fail). The two are separate
claims and must not be conflated:

  * a pass here means "the analyser rejects this capture for this reason";
  * a pass there means "the production core computes this differently".

A capture that the analyser accepts has only been shown to be internally
coherent. Whether the probe can produce such a capture is a real-machine
question.

METHOD
------
Every test starts from one COHERENT synthetic capture and injects exactly one
defect. The assertion is not merely "non-zero exit" -- an analyser that
rejected everything would pass that. Each test asserts the SPECIFIC verdict
that must fail and the SPECIFIC reason text that must appear.

Usage:
    py -3 tools/test-analyzer8.py
Exit code 0 = every regression behaved as required.
"""
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(ROOT, "build-work-analyser-test8")
ANALYSER = os.path.join(ROOT, "tools", "analyze-round8.py")

PASS = 0
FAIL = 0
FAILURES = []


def record(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("  [PASS] {}".format(name))
    else:
        FAIL += 1
        FAILURES.append((name, detail))
        print("  [FAIL] {}".format(name))
        for line in str(detail).splitlines()[:12]:
            print("         {}".format(line))


# ---------------------------------------------------------------------------
# The coherent baseline. Every value here is internally consistent: the
# accounting invariant holds, the timestamps nest, the coverage claim matches
# the per-path values, and the completion progress is attributed.
# ---------------------------------------------------------------------------
BASE = {
    # identity
    "m2-b2-verdict": "PASS-CANDIDATE-no-events-with-completions",
    "m2-b2-stage": "19-no-events-with-completions",
    "m2-b2-mode": "translation",
    "m2-b2-target-devid": "0x2500",
    # page table
    "m2-b2-dump-root-pa": "0x301c0000",
    "m2-b2-dump-root-level": "0x4",
    "m2-b2-dump-page-mode": "0x4",
    "m2-b2-dump-pt-pages": "0x13",
    "m2-b2-dump-map-limit": "0x400000000",
    "m2-b2-dump-leaf-encoding": "NextLevel0-2MiB-default",
    "m2-b2-dump-forensic-base": "0x301c0000",
    "m2-b2-dump-forensic-bytes": "0x13000",
    "m2-b2-dump-count": "0x0",
    # stages
    "m2-b2-stage-evt-reset": "yes",
    "m2-b2-stage-inv-all": "yes",
    "m2-b2-stage-inv-dev": "yes",
    "m2-b2-stage-inv-pages": "yes",
    "m2-b2-stage-control-done": "no",
    # commands
    "m2-b2-cmd-submits": "0x3",
    "m2-b2-cmd-completed": "0x3",
    "m2-b2-cmd-record-count": "0x3",
    # recovery
    "m2-b2-disabled": "yes",
    "m2-b2-cmdbuf-stopped": "yes",
    "m2-b2-evtlog-stopped": "yes",
    "m2-b2-cmdbuf-stop-status": "0x0",
    "m2-b2-evtlog-stop-status": "0x0",
    "m2-b2-final-control": "0x220000000400",
    "m2-b2-orig-control-echo": "0x220000000400",
    "m2-b2-regs-restored": "yes",
    "m2-b2-cleanup": "done",
    "m2-b2-t-recovery-start": "0x941a643f5",
    # observation accounting
    "m2-b2-dma-obs": "complete",
    "m2-b2-dma-trust": "trusted",
    "m2-b2-dma-layout-known": "no",
    "m2-b2-dma-ranges": "0x40",
    "m2-b2-dma-dropped": "0xb6",
    "m2-b2-dma-raw-offered": "0x46a",
    "m2-b2-dma-merged-total": "0xf6",
    "m2-b2-dma-unscanned": "0x0",
    "m2-b2-dma-envelope-valid": "yes",
    "m2-b2-dma-envelope-lo": "0x2ae58000",
    "m2-b2-dma-envelope-hi": "0x4030e45fc",
    "m2-b2-dma-read-ok": "0x3",
    "m2-b2-dma-read-outofmap": "0x0",
    "m2-b2-dma-read-notram": "0x0",
    "m2-b2-dma-tx-slots": "0x400",
    "m2-b2-dma-tx-zeroaddr": "0x396",
    "m2-b2-dma-tx-done-with-addr": "0x0",
    # per-path coverage: TX window-complete, everything else a snapshot
    "m2-b2-dma-cov-txring": "snapshot-only",
    "m2-b2-dma-cov-rxring": "snapshot-only",
    "m2-b2-dma-cov-txbuf": "window-complete",
    "m2-b2-dma-cov-rxbuf": "snapshot-only",
    "m2-b2-dma-cov-stat": "snapshot-only",
    "m2-b2-dma-cov-weakest": "snapshot-only",
    "m2-b2-dma-cov-all-window": "no",
    # read basis
    "m2-b2-dma-tx-ring-basis": "register+content-fingerprint",
    "m2-b2-dma-rx-ring-basis": "register+content-fingerprint",
    "m2-b2-dma-tx-ring-decoded": "0x1e",
    "m2-b2-dma-rx-ring-ringend-at-last": "0x1",
    "m2-b2-dma-len-unknown": "0x0",
    # close pointer
    "m2-b2-dma-cloptr-reg": "0xd34",
    "m2-b2-dma-cloptr-width": "0x4",
    "m2-b2-dma-cloptr-mask": "0x7fffffff",
    "m2-b2-dma-cloptr-before": "0x6a",
    "m2-b2-dma-cloptr-after": "0x6d",
    "m2-b2-dma-cloptr-delta": "0x3",
    "m2-b2-dma-cloptr-delta-valid": "yes",
    "m2-b2-dma-cfgmethod": "0x2a",
    "m2-b2-dma-noclosever": "0x6",
    "m2-b2-dma-chip-known": "yes",
    "m2-b2-dma-tailptr-before": "0x6a",
    "m2-b2-dma-tailptr-after": "0x6d",
    "m2-b2-dma-tx-window-covered": "yes",
    # window scan: 3 submitted, all 3 decoded, all completed in window
    "m2-b2-dma-win-scan": "done",
    "m2-b2-dma-win-cov-reason": "ok",
    "m2-b2-dma-win-submits": "0x3",
    "m2-b2-dma-win-completes": "0x3",
    "m2-b2-dma-win-visited": "0x3",
    "m2-b2-dma-win-decoded": "0x3",
    "m2-b2-dma-win-overwritten": "0x0",
    "m2-b2-dma-win-inflight": "0x0",
    "m2-b2-dma-win-completed": "0x3",
    "m2-b2-dma-win-completed-in-window": "0x3",
    "m2-b2-dma-win-len-unknown": "0x0",
    "m2-b2-dma-win-gen-before": "0x0",
    "m2-b2-dma-win-gen-after": "0x0",
    "m2-b2-dma-win-1st-completed-addr": "0x3c5f460e0",
    "m2-b2-dma-win-1st-completed-len": "0x56",
    "m2-b2-dma-win-1st-completed-slot": "0x6a",
    "m2-b2-dma-win-1st-completed-gen": "0x0",
    "m2-b2-dma-win-walk": "identity-mapped",
    "m2-b2-dma-tx-life-inflight": "0x0",
    "m2-b2-dma-tx-life-completed": "0x3",
    "m2-b2-dma-tx-life-snapshot": "0x0",
    "m2-b2-dma-tx-life-unknown": "0x0",
    # time boundaries: all on one monotonic clock, properly nested
    "m2-b2-dma-t-obs-before": "0x88e670746",
    "m2-b2-dma-t-obs-after": "0x88eb4b03e",
    "m2-b2-dma-t-clo-before": "0x88e6864f6",
    "m2-b2-dma-t-tail-before": "0x88e687000",
    "m2-b2-dma-t-translate-on": "0x88e690000",
    "m2-b2-dma-t-win-start": "0x88e700000",
    "m2-b2-dma-t-win-end": "0x88eb00000",
    "m2-b2-dma-t-tail-after": "0x88eb01000",
    "m2-b2-dma-t-clo-after": "0x88eb02000",
    "m2-b2-dma-t-translate-off": "0x941a643f5",
    # faults
    "m2-b2-fault-inrange": "0x0",
    "m2-b2-fault-outofrange": "0x0",
    "m2-b2-fault-walk-present": "0x0",
    "m2-b2-fault-walk-illegal": "0x0",
    "m2-b2-fault-walk-absent": "0x0",
    "m2-b2-fault-observed-absent": "0x0",
    "m2-b2-fault-coverage": "snapshot-only",
    "m2-b2-fault-negative-sound": "no",
    "m2-b2-fault-negative-scope":
        "tx-path-only-rx-and-rings-not-covered",
    # DMA walk
    "m2-b2-dma-walk-count": "0x6",
    "m2-b2-dma-walk-present": "0x6",
    "m2-b2-dma-walk-verdict": "all-identity-mapped",
    # event window
    "m2-b2-pre-window-ran": "yes",
    "m2-b2-pre-valid": "yes",
    "m2-b2-main-window-ran": "yes",
    "m2-b2-window-valid": "yes",
    "m2-b2-win-dur-ms": "0xbb8",
    "m2-b2-meas-secs": "0x3",
    "m2-b2-win-head-start": "0x0",
    "m2-b2-win-tail-start": "0x0",
    "m2-b2-win-head-end": "0x0",
    "m2-b2-win-tail-end": "0x0",
    "m2-b2-win-status-start": "0x18",
    "m2-b2-win-status-end": "0x18",
    "m2-b2-win-entries": "0x0",
    "m2-b2-win-new-entries": "0x0",
    "m2-b2-win-devid-mismatch": "0x0",
    "m2-b2-win-pre-backlog": "0x0",
    "m2-b2-win-raw-truncated": "no",
    "m2-b2-win-raw-count": "0x0",
}

# Three command records, each self-consistent.
BASE_CMDS = [
    ("inv-all", "08000000000000000000000000000000", "0x1", "0x1", "0x5"),
    ("inv-dev-entry", "00000250020000000000000000000000", "0x1", "0x1", "0x7"),
    ("inv-iommu-pages", "00000000030000000000000000000000", "0x1", "0x1", "0x9"),
]


def render(props, cmds):
    """Render a capture in the same shape `ioreg` prints it.

    The analyser parses `"key" = "value"` pairs, which is what the real
    capture files contain. An earlier version of this file emitted plist XML
    and every test failed with "no m2-b2-* properties found" -- the harness
    was wrong, not the analyser.
    """
    lines = ["+-o AMDMapperProbe  <class org_example_AMDMapperProbe>", "  {",
             '    "IOClass" = "org_example_AMDMapperProbe"']
    for k, v in props.items():
        lines.append('    "{}" = "{}"'.format(k, v))
    for i, (label, dwords, exp, obs, loops) in enumerate(cmds):
        for suffix, val in (("label", label), ("dwords", dwords),
                            ("expected", exp), ("observed", obs),
                            ("loops", loops), ("ok", "yes")):
            lines.append('    "m2-b2-cmd{}-{}" = "{}"'.format(i, suffix, val))
    lines.append("  }")
    return "\n".join(lines) + "\n"


def run(props, cmds=None, name="capture"):
    if not os.path.isdir(WORK):
        os.makedirs(WORK)
    path = os.path.join(WORK, name + ".txt")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(render(props, BASE_CMDS if cmds is None else cmds))
    p = subprocess.run([sys.executable, ANALYSER, path],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def variant(**overrides):
    p = dict(BASE)
    for k, v in overrides.items():
        key = k.replace("__", "-").replace("_", "-")
        # keys are given in property spelling with __ for '-'
        p[key] = v
    return p


def expect_reject(name, props, needle, want_code=None, cmds=None):
    rc, out = run(props, cmds=cmds, name=name)
    if rc == 0:
        record(name, False, "analyser ACCEPTED a defective capture")
        return
    if want_code is not None and rc != want_code:
        record(name, False,
               "exit {} (wanted {}); output:\n{}".format(rc, want_code, out))
        return
    if needle and needle not in out:
        record(name, False,
               "exit {} but reason {!r} not in output:\n{}".format(
                   rc, needle, out[-3000:]))
        return
    record(name, True, "")


def expect_accept(name, props, cmds=None):
    rc, out = run(props, cmds=cmds, name=name)
    if rc not in (0, 1):
        record(name, False, "coherent capture rejected (exit {}):\n{}".format(
            rc, out[-3000:]))
        return
    if "INVALID" in out and rc == 3:
        record(name, False, "coherent capture judged INVALID:\n{}".format(
            out[-3000:]))
        return
    record(name, True, "")


# ===========================================================================
# 0. The baseline must be accepted. Without this, every rejection below
#    proves nothing: an analyser that rejects everything rejects these too.
# ===========================================================================
def baseline_is_accepted():
    print("\n0. BASELINE")
    expect_accept("coherent round-8 translation capture is accepted", BASE)


# ===========================================================================
# 1. Post-sample time EARLIER than the pre-stage.
#    Round 7 could not catch this: it only compared the two samples with each
#    other, and both were "present".
# ===========================================================================
def t_clo_after_before_pre():
    print("\n1. POST-SAMPLE EARLIER THAN THE PRE-STAGE")
    p = variant(**{"m2-b2-dma-t-clo-after": "0x88e600000"})
    expect_reject("post-sample earlier than pre-sample is rejected",
                  p, "not earlier than the pre-sample")
    p2 = variant(**{"m2-b2-dma-t-clo-before": "0x88eb50000"})
    expect_reject("pre-sample after the window start is rejected",
                  p2, "pre-sample precedes the measurement window")


# ===========================================================================
# 2. Post-sample time LATER than recovery.
#    A sample taken after recovery is not a measurement of the window: by
#    then the DTE has been switched back and the IOMMU is disabled.
# ===========================================================================
def t_clo_after_after_recovery():
    print("\n2. POST-SAMPLE LATER THAN RECOVERY")
    p = variant(**{"m2-b2-dma-t-clo-after": "0x941a70000"})
    expect_reject("post-sample after recovery is rejected",
                  p, "post-sample precedes recovery")


# ===========================================================================
# 3. Command buffer claims stopped but the STATUS bit says it is running.
#    Round 7 compared the claim with the bit and accepted a capture where
#    both said "still running". The bit itself must be clear.
# ===========================================================================
def cmdbuf_still_running():
    print("\n3. COMMAND BUFFER DECLARED STOPPED BUT STATUS SAYS RUNNING")
    # Honest capture: the claim matches the bit, but the bit is SET.
    p = variant(**{"m2-b2-cmdbuf-stopped": "no",
                   "m2-b2-cmdbuf-stop-status": "0x10"})
    expect_reject("claim matching a RUNNING cmdbuf is still rejected",
                  p, "hardware run bit is actually clear")
    # Dishonest capture: claim says stopped, bit says running.
    p2 = variant(**{"m2-b2-cmdbuf-stopped": "yes",
                    "m2-b2-cmdbuf-stop-status": "0x10"})
    expect_reject("claim contradicting a RUNNING cmdbuf is rejected",
                  p2, "stop claim matches STATUS")
    p3 = variant(**{"m2-b2-evtlog-stopped": "no",
                    "m2-b2-evtlog-stop-status": "0x08"})
    expect_reject("claim matching a RUNNING event log is still rejected",
                  p3, "hardware run bit is actually clear")


# ===========================================================================
# 4. Delta is zero but the capture claims completion progress.
#    Round 7 accepted this: it required delta-valid=yes but never delta>0.
# ===========================================================================
def zero_delta_claims_progress():
    print("\n4. ZERO DELTA BUT PROGRESS CLAIMED")

    def zero_delta(verdict, stage):
        p = variant(**{"m2-b2-verdict": verdict, "m2-b2-stage": stage,
                       "m2-b2-dma-cloptr-after": "0x6a",
                       "m2-b2-dma-cloptr-delta": "0x0",
                       "m2-b2-dma-win-completes": "0x0",
                       "m2-b2-dma-win-completed": "0x0",
                       "m2-b2-dma-win-completed-in-window": "0x0",
                       "m2-b2-dma-win-inflight": "0x3",
                       "m2-b2-dma-tx-life-inflight": "0x3",
                       "m2-b2-dma-tx-life-completed": "0x0"})
        # No completion was attributed, so these must not be present.
        for k in ("m2-b2-dma-win-1st-completed-addr",
                  "m2-b2-dma-win-1st-completed-len",
                  "m2-b2-dma-win-1st-completed-slot",
                  "m2-b2-dma-win-1st-completed-gen"):
            p.pop(k, None)
        return p

    expect_reject("delta 0 with a pass-candidate verdict is rejected",
                  zero_delta("PASS-CANDIDATE-no-events-with-completions",
                             "19-no-events-with-completions"),
                  "requires delta > 0")
    # A zero delta with an honest INDETERMINATE verdict must be accepted, so
    # the check targets the claim and not the value.
    expect_accept("zero delta with an honest indeterminate verdict is "
                  "accepted",
                  zero_delta("INDETERMINATE-no-events-no-dma-evidence",
                             "19-indeterminate-no-dma"))


# ===========================================================================
# 5. Unscanned slots are non-zero but a path claims window coverage.
# ===========================================================================
def unscanned_but_complete():
    print("\n5. UNSCANNED SLOTS BUT COMPLETENESS CLAIMED")
    p = variant(**{"m2-b2-dma-unscanned": "0x800"})
    expect_reject("unscanned slots with a window-complete path is rejected",
                  p, "unscanned slots are zero whenever any path claims")
    # The same capture with every path demoted to a snapshot is coherent: the
    # unscanned slots and the snapshot claim agree.
    p2 = variant(**{"m2-b2-dma-unscanned": "0x800",
                    "m2-b2-dma-cov-txbuf": "snapshot-only"})
    expect_accept("unscanned slots with snapshot-only coverage is accepted",
                  p2)


# ===========================================================================
# 6. Chip configuration incompatible with the register identity.
# ===========================================================================
def chip_identity_incompatible():
    print("\n6. CHIP CONFIGURATION INCOMPATIBLE WITH REGISTER IDENTITY")
    # cfgmethod 42 implies noCloseVer 6 -> 0x0D34/4/0x7FFFFFFF.
    # Claim noCloseVer 3 (16-bit, 0x2802) while keeping cfgmethod 42.
    p = variant(**{"m2-b2-dma-noclosever": "0x3",
                   "m2-b2-dma-cloptr-reg": "0x2802",
                   "m2-b2-dma-cloptr-width": "0x2",
                   "m2-b2-dma-cloptr-mask": "0xffff"})
    expect_reject("cfgmethod 42 with noCloseVer 3 is rejected",
                  p, "noCloseVer follows from the configuration method")
    # A register that does not belong to the declared version.
    p2 = variant(**{"m2-b2-dma-cloptr-reg": "0x2800"})
    expect_reject("register not implied by noCloseVer is rejected",
                  p2, "close-pointer register matches the chip's version")
    # Mask = ring size: the round-6 defect.
    p3 = variant(**{"m2-b2-dma-cloptr-mask": "0x3ff"})
    expect_reject("ring-sized mask is rejected", p3, "not the ring size")
    # cfgmethod 41 also implies 6; check the sibling branch.
    p4 = variant(**{"m2-b2-dma-cfgmethod": "0x29",
                    "m2-b2-dma-noclosever": "0x5"})
    expect_reject("cfgmethod 41 with noCloseVer 5 is rejected",
                  p4, "noCloseVer follows from the configuration method")


# ===========================================================================
# 7. A control-mode capture that follows the production flow and lacks the
#    not-executed stage fields.
#    Round 7 required the window fields unconditionally, so a control capture
#    had to either omit them (malformed) or invent them. Here they must be
#    genuinely absent and the capture must still be analysable.
# ===========================================================================
def control_mode_without_window_fields():
    print("\n7. CONTROL MODE WITHOUT THE NOT-EXECUTED STAGE FIELDS")
    p = dict(BASE)
    p["m2-b2-mode"] = "control-sleep-only"
    p["m2-b2-verdict"] = "CONTROL-sleep-only-no-dte-change"
    p["m2-b2-stage"] = "19-control-preserved"
    p["m2-b2-stage-control-done"] = "yes"
    p["m2-b2-stage-inv-dev"] = "no"
    p["m2-b2-stage-inv-pages"] = "no"
    # The translation window never ran: drop every field only it produces.
    for k in list(p.keys()):
        if (k.startswith("m2-b2-win-") or k.startswith("m2-b2-pre-") or
                k in ("m2-b2-dma-t-win-start", "m2-b2-dma-t-win-end",
                      "m2-b2-dma-t-translate-on",
                      "m2-b2-dma-t-translate-off",
                      "m2-b2-dma-t-tail-before",
                      "m2-b2-dma-t-tail-after",
                      "m2-b2-dma-t-clo-after",
                      "m2-b2-dma-win-scan",
                      "m2-b2-dma-win-cov-reason",
                      "m2-b2-dma-tx-window-covered")):
            p.pop(k, None)
        elif k.startswith("m2-b2-dma-win-"):
            p.pop(k, None)
        elif k.startswith("m2-b2-dma-tx-life-"):
            p.pop(k, None)
    # The DMA observation itself did not run in this mode.
    p["m2-b2-dma-obs"] = "SKIP-no-dma-observation-in-control-mode"
    p["m2-b2-dma-cloptr-delta-valid"] = "no-observation-incomplete"
    for k in ("m2-b2-dma-cloptr-after", "m2-b2-dma-cloptr-delta",
              "m2-b2-dma-tailptr-before", "m2-b2-dma-tailptr-after"):
        p.pop(k, None)

    rc, out = run(p, name="control_ok")
    if rc not in (0, 1):
        record("control capture without window fields is analysable",
               False, "exit {}:\n{}".format(rc, out[-3000:]))
        return
    record("control capture without window fields is analysable", True, "")
    if "not applicable" not in out:
        record("control capture reports the checks as not applicable",
               False, "no 'not applicable' in output:\n{}".format(out[-2000:]))
        return
    record("control capture reports the checks as not applicable", True, "")

    # Now the inverse: a control capture that DOES claim a translation
    # verdict is inconsistent and must be rejected.
    p2 = dict(p)
    p2["m2-b2-verdict"] = "PASS-CANDIDATE-no-events-with-completions"
    expect_reject("control mode claiming a translation pass is rejected",
                  p2, "does not claim a translation verdict")


# ===========================================================================
# Additional coverage-consistency regressions (the round-8 bucket)
# ===========================================================================
def coverage_generalisation():
    print("\n8. COVERAGE GENERALISATION")
    # TX window-complete reported as device-wide coverage.
    p = variant(**{"m2-b2-dma-cov-rxbuf": "window-complete",
                   "m2-b2-dma-cov-stat": "window-complete",
                   "m2-b2-dma-cov-rxring": "window-complete",
                   "m2-b2-dma-cov-txring": "window-complete",
                   "m2-b2-dma-cov-weakest": "snapshot-only"})
    expect_reject("weakest coverage that ignores a snapshot path is rejected",
                  p, "weakest coverage equals the weakest per-path value")

    # All paths window-complete but the weakest field says snapshot.
    p2 = variant(**{"m2-b2-dma-cov-rxbuf": "window-complete",
                    "m2-b2-dma-cov-stat": "window-complete",
                    "m2-b2-dma-cov-rxring": "window-complete",
                    "m2-b2-dma-cov-txring": "window-complete",
                    "m2-b2-dma-cov-weakest": "window-complete",
                    "m2-b2-dma-cov-all-window": "yes",
                    "m2-b2-fault-coverage": "window-complete",
                    "m2-b2-fault-negative-sound": "yes",
                    "m2-b2-fault-negative-scope":
                        "device-wide-all-paths-covered"})
    expect_accept("all paths window-complete with matching scope is accepted",
                  p2)

    # Fault classification using a stronger coverage than the observation.
    p3 = variant(**{"m2-b2-fault-coverage": "window-complete"})
    expect_reject("fault coverage stronger than the observation is rejected",
                  p3, "fault classification used the weakest path coverage")

    # Negative claimed sound while a path is only a snapshot.
    p4 = variant(**{"m2-b2-fault-negative-sound": "yes"})
    expect_reject("negative soundness without all-path coverage is rejected",
                  p4, "negative-soundness flag matches all-window coverage")

    # Scope string contradicting the flag.
    p5 = variant(**{"m2-b2-fault-negative-scope":
                    "device-wide-all-paths-covered"})
    expect_reject("device-wide scope with TX-only coverage is rejected",
                  p5, "negative scope agrees with the all-window flag")


def read_basis_regressions():
    print("\n9. READ BASIS")
    p = variant(**{"m2-b2-dma-tx-ring-basis": "register-only"})
    expect_reject("register-only is not enough to trust ring contents",
                  p, "register-only is never enough")
    p2 = variant(**{"m2-b2-dma-rx-ring-basis": "register+content-fingerprint",
                    "m2-b2-dma-rx-ring-ringend-at-last": "0x0"})
    expect_reject("fingerprint basis with no RingEnd evidence is rejected",
                  p2, "fingerprint basis implies the fingerprint actually")
    p3 = variant(**{"m2-b2-dma-tx-ring-basis": "bogus-basis"})
    expect_reject("unknown read basis is rejected", p3, "known value")


def window_scan_arithmetic():
    print("\n10. WINDOW SCAN ARITHMETIC")
    p = variant(**{"m2-b2-dma-win-visited": "0x2"})
    expect_reject("visited not equal to submits is rejected",
                  p, "every submitted index was visited")
    p2 = variant(**{"m2-b2-dma-win-decoded": "0x2"})
    expect_reject("decoded plus overwritten not equal to visited is rejected",
                  p2, "decoded plus overwritten equals visited")
    p3 = variant(**{"m2-b2-dma-win-inflight": "0x2"})
    expect_reject("inflight plus completed not equal to decoded is rejected",
                  p3, "inflight plus completed equals decoded")
    p4 = variant(**{"m2-b2-dma-win-cov-reason": "ring-overwritten"})
    expect_reject("covered claim with a ring-overwritten reason is rejected",
                  p4, "TX window-covered claim agrees with the scan reason")
    p5 = variant(**{"m2-b2-dma-win-completes": "0x5"})
    expect_reject("window completes disagreeing with the delta is rejected",
                  p5, "window completes agree with the close-pointer delta")
    p6 = variant(**{"m2-b2-dma-win-scan": "SKIP-no-ring"})
    expect_reject("in-window completion without a scan is rejected",
                  p6, "a window completion implies the scan ran")


def envelope_regressions():
    print("\n11. ENVELOPE AND DESCRIPTORS")
    # The round-6 archive contradiction: envelope-hi below a descriptor.
    # 0x3fec620e0 is the real round-6 txdesc4 address and it is genuinely
    # above this baseline's envelope-hi (0x4030e45fc)?  No: 0x3fec620e0 <
    # 0x4030e45fc. The baseline envelope is larger than the round-6 one, so
    # the defect is injected by LOWERING the envelope to the round-6 value.
    p = dict(BASE)
    p["m2-b2-dma-envelope-hi"] = "0x3f80a4000"
    p["m2-b2-dma-txdesc4"] = ("opts1=b0000056 opts2=00000000 "
                              "addr=00000003fec620e0 len=0x56")
    expect_reject("descriptor above the envelope is rejected",
                  p, "outside envelope")
    # A window completion outside the envelope.
    p2 = variant(**{"m2-b2-dma-win-1st-completed-addr": "0x500000000"})
    expect_reject("window completion outside the envelope is rejected",
                  p2, "first attributed completion lies inside the envelope")
    # Undecoded lengths blocking an exact negative.
    p3 = variant(**{"m2-b2-dma-len-unknown": "0x2",
                    "m2-b2-dma-cov-rxbuf": "window-complete",
                    "m2-b2-dma-cov-stat": "window-complete",
                    "m2-b2-dma-cov-rxring": "window-complete",
                    "m2-b2-dma-cov-txring": "window-complete",
                    "m2-b2-dma-cov-weakest": "window-complete",
                    "m2-b2-dma-cov-all-window": "yes",
                    "m2-b2-fault-coverage": "window-complete",
                    "m2-b2-fault-negative-sound": "yes",
                    "m2-b2-fault-negative-scope":
                        "device-wide-all-paths-covered"})
    expect_reject("undecoded lengths with an exact negative are rejected",
                  p3, "undecoded lengths block an exact negative")


def malformed_and_missing():
    print("\n12. MALFORMED AND MISSING FIELDS")
    p = variant(**{"m2-b2-dma-cloptr-mask": "0x7fffffffextra"})
    expect_reject("malformed hex is rejected", p, "not a 0x-prefixed hex")
    p2 = dict(BASE)
    p2.pop("m2-b2-dma-cov-txbuf")
    expect_reject("missing per-path coverage is rejected", p2, "missing")
    p3 = variant(**{"m2-b2-mode": "not-a-mode"})
    expect_reject("unknown mode is rejected", p3, "known mode")
    # An old capture that lacks the round-8 fields entirely.
    rc, out = run(BASE, name="probe_old")
    old = {k: v for k, v in BASE.items()
           if not k.startswith("m2-b2-dma-cov-") and
           not k.startswith("m2-b2-dma-win-") and
           "ring-basis" not in k and "len-unknown" not in k}
    rc2, out2 = run(old, name="old_shape")
    if rc2 != 2:
        record("a capture without round-8 fields cannot be analysed", False,
               "exit {} (wanted 2)".format(rc2))
    else:
        record("a capture without round-8 fields cannot be analysed", True)


def round7_capture_is_rejected():
    print("\n13. THE ROUND-7 REAL CAPTURE")
    path = os.path.join(ROOT, "docs", "evidence", "20261031-064350",
                        "props.txt")
    if not os.path.isfile(path):
        record("round-7 capture present", False, "not found: " + path)
        return
    p = subprocess.run([sys.executable, ANALYSER, path],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = p.stdout.decode("utf-8", "replace")
    if p.returncode != 2:
        record("round-7 real capture is refused as un-analysable", False,
               "exit {} (wanted 2):\n{}".format(p.returncode, out[-2000:]))
        return
    record("round-7 real capture is refused as un-analysable", True, "")
    if "m2-b2-dma-cov-txbuf" not in out:
        record("refusal names a round-8 field it lacks", False,
               "expected the missing-field list to name cov-txbuf")
        return
    record("refusal names a round-8 field it lacks", True, "")


def main():
    print("Round-8 analyser negative regressions")
    print("=" * 78)
    print("analyser: {}".format(ANALYSER))

    baseline_is_accepted()
    t_clo_after_before_pre()
    t_clo_after_after_recovery()
    cmdbuf_still_running()
    zero_delta_claims_progress()
    unscanned_but_complete()
    chip_identity_incompatible()
    control_mode_without_window_fields()
    coverage_generalisation()
    read_basis_regressions()
    window_scan_arithmetic()
    envelope_regressions()
    malformed_and_missing()
    round7_capture_is_rejected()

    print()
    print("=" * 78)
    print("{} passed, {} failed".format(PASS, FAIL))
    if FAIL:
        for name, detail in FAILURES:
            print("  FAILED: {}".format(name))
        print("RESULT: FAILURES")
        return 1
    print("RESULT: ALL CHECKS PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
