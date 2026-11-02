#!/usr/bin/env python3
"""Round-9 analyser negative regressions.

WHAT THIS FILE PROVES, AND WHAT IT DOES NOT
-------------------------------------------
This file tests the PYTHON ANALYSER (tools/analyze-round9.py). It does NOT
test the production C++ judgement: that is done by tests/dma-observe-test.cpp
(which compiles the shared core the kext includes) and by
tools/verify-round9.py's MUTATION class (which re-injects each defect into the
core and requires the C++ tests to fail). The two are separate claims and must
not be conflated:

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

The seven defects the round-9 task names explicitly are in groups 1..7. The
remaining groups cover the checks those seven depend on.

Usage:
    py -3 tools/test-analyzer9.py
Exit code 0 = every regression behaved as required.
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(ROOT, "build-work-analyser-test9")
ANALYSER = os.path.join(ROOT, "tools", "analyze-round9.py")

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
        for line in str(detail).splitlines()[:14]:
            print("         {}".format(line))


# ---------------------------------------------------------------------------
# The coherent baseline.
#
# Every value here is internally consistent AND recomputable: the tail delta
# gives 3 submits, the close-pointer delta gives 3 completes with an empty
# queue at the start, the page-table chain independently decodes
# 0x37a0a32e0 to itself, and the driver's records pair 3 submits with 3
# completions on the same cumulative indices.
#
# The page-table numbers are the REAL round-8 values, and they really do
# decode: L4 0x371c0000[0] -> L3 0x371c1000, L3 0x371c1000[0xd] ->
# L2 0x371cf000, L2 0x371cf000[0x1d0] -> 2 MiB leaf at 0x37a000000, and
# 0x37a000000 + 0xa32e0 = 0x37a0a32e0.
# ---------------------------------------------------------------------------
BASE = {
    # identity
    "m2-b2-verdict": "PASS-CANDIDATE-controlled-with-completions",
    "m2-b2-stage": "19-controlled-chain-complete",
    "m2-b2-mode": "translation",
    "m2-b2-target-devid": "0x2500",
    # page table
    "m2-b2-dump-root-pa": "0x371c0000",
    "m2-b2-dump-root-level": "0x4",
    "m2-b2-dump-page-mode": "0x4",
    "m2-b2-dump-pt-pages": "0x13",
    "m2-b2-dump-map-limit": "0x400000000",
    "m2-b2-dump-leaf-encoding": "NextLevel0-2MiB-default",
    "m2-b2-dump-forensic-base": "0x371c0000",
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
    "m2-b2-t-recovery-start": "0x94a603798",
    # observation accounting
    "m2-b2-dma-obs": "complete",
    "m2-b2-dma-trust": "trusted",
    "m2-b2-dma-layout-known": "no",
    "m2-b2-dma-ranges": "0x40",
    "m2-b2-dma-dropped": "0xaf",
    "m2-b2-dma-raw-offered": "0x468",
    "m2-b2-dma-merged-total": "0xef",
    "m2-b2-dma-unscanned": "0x0",
    "m2-b2-dma-envelope-valid": "yes",
    "m2-b2-dma-envelope-lo": "0x31e54000",
    "m2-b2-dma-envelope-hi": "0x3fd527ffc",
    "m2-b2-dma-read-ok": "0x3",
    "m2-b2-dma-read-outofmap": "0x0",
    "m2-b2-dma-read-notram": "0x0",
    "m2-b2-dma-tx-slots": "0x400",
    "m2-b2-dma-tx-zeroaddr": "0x396",
    "m2-b2-dma-tx-done-with-addr": "0x396",
    # per-path coverage: TX window-complete, everything else a snapshot
    "m2-b2-dma-cov-txring": "snapshot-only",
    "m2-b2-dma-cov-rxring": "snapshot-only",
    "m2-b2-dma-cov-txbuf": "window-complete",
    "m2-b2-dma-cov-rxbuf": "snapshot-only",
    "m2-b2-dma-cov-stat": "snapshot-only",
    "m2-b2-dma-cov-weakest": "snapshot-only",
    "m2-b2-dma-cov-all-window": "no",
    "m2-b2-fault-coverage": "snapshot-only",
    "m2-b2-fault-negative-sound": "no",
    "m2-b2-fault-negative-scope": "tx-path-only-rx-and-rings-not-covered",
    # read basis
    "m2-b2-dma-tx-ring-basis": "register+content-fingerprint",
    "m2-b2-dma-rx-ring-basis": "register+content-fingerprint",
    "m2-b2-dma-tx-ring-decoded": "0x68",
    "m2-b2-dma-rx-ring-ringend-at-last": "0x1",
    "m2-b2-dma-len-unknown": "0x0",
    # close pointer
    "m2-b2-dma-cloptr-reg": "0xd34",
    "m2-b2-dma-cloptr-width": "0x4",
    "m2-b2-dma-cloptr-mask": "0x7fffffff",
    "m2-b2-dma-cloptr-before": "0x68",
    "m2-b2-dma-cloptr-after": "0x6b",
    "m2-b2-dma-cloptr-delta": "0x3",
    "m2-b2-dma-cloptr-delta-valid": "yes",
    "m2-b2-dma-txconfig": "0x6f900f40",
    "m2-b2-dma-cfgmethod": "0x2a",
    "m2-b2-dma-noclosever": "0x6",
    "m2-b2-dma-chip-known": "yes",
    "m2-b2-dma-tailptr-before": "0x68",
    "m2-b2-dma-tailptr-after": "0x6b",
    "m2-b2-dma-tx-window-covered": "yes",
    # window scan: 3 submitted, 3 decoded, 3 completed in window
    "m2-b2-dma-win-scan": "done",
    "m2-b2-dma-win-cov-reason": "ok",
    "m2-b2-dma-win-quality": "exact",
    "m2-b2-dma-win-exact": "yes",
    "m2-b2-dma-win-stop-reason": "0x0",
    "m2-b2-dma-win-stop-reason-name": "ok",
    "m2-b2-dma-win-skipped": "0x0",
    "m2-b2-dma-win-records-lost": "0x0",
    "m2-b2-dma-win-submits": "0x3",
    "m2-b2-dma-win-completes": "0x3",
    "m2-b2-dma-win-visited": "0x3",
    "m2-b2-dma-win-decoded": "0x3",
    "m2-b2-dma-win-overwritten": "0x0",
    "m2-b2-dma-win-addr-zero": "0x0",
    "m2-b2-dma-win-inflight": "0x0",
    "m2-b2-dma-win-completed": "0x3",
    "m2-b2-dma-win-completed-in-window": "0x3",
    "m2-b2-dma-win-prewin-completed": "0x0",
    "m2-b2-dma-win-inflight-at-start": "0x0",
    "m2-b2-dma-win-len-unknown": "0x0",
    "m2-b2-dma-win-gen-before": "0x0",
    "m2-b2-dma-win-gen-after": "0x0",
    "m2-b2-dma-win-1st-completed-addr": "0x37a0a32e0",
    "m2-b2-dma-win-1st-completed-len": "0x2a",
    "m2-b2-dma-win-1st-completed-slot": "0x68",
    "m2-b2-dma-win-1st-completed-gen": "0x0",
    "m2-b2-dma-win-walk": "identity-mapped",
    "m2-b2-dma-tx-life-inflight": "0x0",
    "m2-b2-dma-tx-life-completed": "0x68",
    "m2-b2-dma-tx-life-snapshot": "0x0",
    "m2-b2-dma-tx-life-unknown": "0x0",
    # the driver's own records
    "m2-b2-obs": "complete",
    "m2-b2-obs-format": "rtl812x-obs/1",
    "m2-b2-obs-state": "ok",
    "m2-b2-obs-why": "ok",
    "m2-b2-obs-head": "0x2a",
    "m2-b2-obs-published": "0x2a",
    "m2-b2-obs-first": "0x0",
    "m2-b2-obs-wrapped": "0x0",
    "m2-b2-obs-t-start": "0x890000000",
    "m2-b2-obs-t-published": "0x94a610000",
    "m2-b2-obs-ops": "0x3",
    "m2-b2-obs-submits": "0x3",
    "m2-b2-obs-dones": "0x3",
    "m2-b2-obs-doorbells": "0x1",
    "m2-b2-obs-rx-done": "0x14",
    "m2-b2-obs-rx-addr-zero": "0x0",
    "m2-b2-obs-stale": "0x0",
    "m2-b2-obs-unmatched-done": "0x0",
    "m2-b2-obs-uncompleted": "0x0",
    "m2-b2-obs-overflow": "0x0",
    "m2-b2-obs-all-completed": "yes",
    "m2-b2-obs-win-submits": "0x3",
    "m2-b2-obs-win-dones": "0x3",
    "m2-b2-obs-win-paired": "0x3",
    "m2-b2-obs-win-orphan-done": "0x0",
    "m2-b2-obs-window-complete": "yes",
    "m2-b2-obs-source": "driver-child",
    "m2-b2-obs-first-submit-t": "0x8976d0000",
    "m2-b2-obs-last-done-t": "0x94a3f0000",
    "m2-b2-obs-first-rx-addr": "0x1f3a0a000",
    "m2-b2-obs-last-rx-addr": "0x1f3c0b000",
    "m2-b2-obs-op-cum": "0x68",
    "m2-b2-obs-op-slot": "0x68",
    "m2-b2-obs-op-gen": "0x0",
    "m2-b2-obs-op-addr": "0x37a0a32e0",
    "m2-b2-obs-op-len": "0x2a",
    "m2-b2-obs-op-flags": "0x2a",
    "m2-b2-obs-op-t-submit": "0x8976d0000",
    "m2-b2-obs-op-t-compl": "0x94a3f0000",
    # time boundaries: the post-sample lies INSIDE the window
    "m2-b2-dma-t-obs-before": "0x896f86417",
    "m2-b2-dma-t-obs-after": "0x94a42a093",
    "m2-b2-dma-t-clo-before": "0x896f9cf69",
    "m2-b2-dma-t-tail-before": "0x896f9cf9b",
    "m2-b2-dma-t-dte-written": "0x896f80000",
    "m2-b2-dma-t-inv-complete": "0x896f8215f",
    "m2-b2-dma-t-translate-on": "0x896f8215f",
    "m2-b2-dma-t-win-start": "0x8976ca3b6",
    "m2-b2-dma-t-clo-after": "0x94a3fcba7",
    "m2-b2-dma-t-tail-after": "0x94a3fcbd0",
    "m2-b2-dma-t-win-end": "0x94a3fcf00",
    "m2-b2-dma-t-translate-off": "0x94a603798",
    "m2-b2-dma-boundary-in-window": "yes",
    # faults: none
    "m2-b2-fault-inrange": "0x0",
    "m2-b2-fault-outofrange": "0x0",
    "m2-b2-fault-walk-present": "0x0",
    "m2-b2-fault-walk-illegal": "0x0",
    "m2-b2-fault-walk-absent": "0x0",
    "m2-b2-fault-observed-absent": "0x0",
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

# The page-table chain for 0x37a0a32e0, under the "win" tag. These are the
# real round-8 values; the chain really decodes to the address.
BASE_WALK = [
    ("table", "0x371c0000", "level", "0x4", "index", "0x0",
     "pte", "0x60000000371c1601"),
    ("table", "0x371c1000", "level", "0x3", "index", "0xd",
     "pte", "0x60000000371cf401"),
    ("table", "0x371cf000", "level", "0x2", "index", "0x1d0",
     "pte", "0x700000037a000001"),
]

BASE_CMDS = [
    ("inv-all", "08000000000000000000000000000000", "0x1", "0x1", "0x5"),
    ("inv-dev-entry", "00000250020000000000000000000000", "0x1", "0x1", "0x7"),
    ("inv-iommu-pages", "00000000030000000000000000000000", "0x1", "0x1", "0x9"),
]


def render(props, cmds, walk):
    """Render a capture in the same shape `ioreg` prints it.

    The analyser parses `"key" = "value"` pairs, which is what the real
    capture files contain. Emitting plist XML instead was a real bug in round
    8's harness: every test failed with "no m2-b2-* properties found" and the
    harness looked broken when it was the renderer.
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
    if walk:
        lines.append('    "m2-b2-win0-depth" = "{}"'.format(len(walk)))
        # The address being walked, so the analyser can check that the
        # attributed completion address really is a descriptor of this window.
        lines.append('    "m2-b2-win0-addr" = "0x37a0a32e0"')
        for j, tup in enumerate(walk):
            d = dict(zip(tup[0::2], tup[1::2]))
            for s in ("table", "level", "index"):
                lines.append('    "m2-b2-win0-pte{}-{}" = "{}"'.format(
                    j, s, d[s]))
            lines.append('    "m2-b2-win0-pte{}" = "{}"'.format(j, d["pte"]))
    lines.append("  }")
    return "\n".join(lines) + "\n"


def safe_name(name):
    """Turn a test description into a filename Windows accepts.

    A description like "tail 0x68 -> 0x68 ..." contains '>' which NTFS rejects
    inside a path component; the harness failed with OSError rather than a
    test result. Keep the readable stem, replace anything that is not
    alphanumeric, space, dash or underscore.
    """
    out = []
    for ch in name:
        out.append(ch if (ch.isalnum() or ch in " -_") else "_")
    s = "".join(out).strip()
    return s[:120] or "capture"


def run(props, cmds=None, walk=None, name="capture"):
    if not os.path.isdir(WORK):
        os.makedirs(WORK)
    path = os.path.join(WORK, safe_name(name) + ".txt")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(render(props, BASE_CMDS if cmds is None else cmds,
                       BASE_WALK if walk is None else walk))
    p = subprocess.run([sys.executable, ANALYSER, path],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def variant(**overrides):
    p = dict(BASE)
    for k, v in overrides.items():
        key = k.replace("__", "-").replace("_", "-")
        p[key] = v
    return p


def expect_reject(name, props, needle, want_code=None, cmds=None, walk=None):
    rc, out = run(props, cmds=cmds, walk=walk, name=name)
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


def expect_accept(name, props, cmds=None, walk=None):
    rc, out = run(props, cmds=cmds, walk=walk, name=name)
    if rc not in (0, 1):
        record(name, False, "coherent capture rejected (exit {}):\n{}".format(
            rc, out[-3000:]))
        return
    record(name, True, "")


# ===========================================================================
# 0. The baseline must be accepted. Without this, every rejection below
#    proves nothing: an analyser that rejects everything rejects these too.
# ===========================================================================
def baseline_is_accepted():
    print("\n0. BASELINE")
    expect_accept("coherent round-9 translation capture is accepted", BASE)
    # And the control-mode shape must be accepted too, so the N/A path is
    # not just "everything is required".
    p = dict(BASE)
    p["m2-b2-mode"] = "control-sleep-only"
    p["m2-b2-verdict"] = "CONTROL-sleep-only-no-dte-change"
    p["m2-b2-stage"] = "13-control-complete"
    p["m2-b2-stage-control-done"] = "yes"
    p["m2-b2-stage-inv-dev"] = "no"
    p["m2-b2-stage-inv-pages"] = "no"
    for k in list(p.keys()):
        if (k.startswith("m2-b2-win-") or k.startswith("m2-b2-pre-") or
                k.startswith("m2-b2-dma-win-") or
                k.startswith("m2-b2-dma-cov-") or
                k.startswith("m2-b2-dma-t-") or
                k.startswith("m2-b2-obs-") or
                k.startswith("m2-b2-dma-tx-life-") or
                k.startswith("m2-b2-fault-") or
                k in ("m2-b2-dma-cloptr-before", "m2-b2-dma-cloptr-after",
                      "m2-b2-dma-cloptr-delta",
                      "m2-b2-dma-cloptr-delta-valid",
                      "m2-b2-dma-tailptr-before",
                      "m2-b2-dma-tailptr-after",
                      "m2-b2-dma-tx-window-covered",
                      "m2-b2-dma-boundary-in-window",
                      "m2-b2-dma-tx-ring-basis",
                      "m2-b2-dma-rx-ring-basis",
                      "m2-b2-dma-tx-ring-decoded",
                      "m2-b2-dma-rx-ring-ringend-at-last",
                      "m2-b2-dma-len-unknown")):
            p.pop(k, None)
    p["m2-b2-dma-obs"] = "SKIP-observation-did-not-complete"
    rc, out = run(p, walk=[], name="control_ok")
    if rc not in (0, 1):
        record("control capture is analysable", False,
               "exit {}:\n{}".format(rc, out[-3000:]))
    else:
        record("control capture is analysable", True, "")
        if "not applicable" not in out:
            record("control capture reports the skipped checks as N/A", False,
                   "no 'not applicable' in output:\n{}".format(out[-2000:]))
        else:
            record("control capture reports the skipped checks as N/A", True,
                   "")


# ===========================================================================
# 1. tail before and after are the SAME, yet the capture claims 3 submits.
#    Round 8 published both values but never compared their difference with
#    the claimed count.
# ===========================================================================
def tail_delta_contradiction():
    print("\n1. TAIL UNCHANGED BUT 3 SUBMITS CLAIMED")
    p = variant(m2__b2__dma__tailptr__after="0x68")
    expect_reject("tail 0x68 -> 0x68 with 3 submits is rejected",
                  p, "submit count equals the recomputed tail delta")
    # The inverse: the tail advanced by 5 but only 3 are claimed.
    p2 = variant(m2__b2__dma__tailptr__after="0x6d")
    expect_reject("tail 0x68 -> 0x6d with 3 submits is rejected",
                  p2, "submit count equals the recomputed tail delta")


# ===========================================================================
# 2. Every first-completion field is deleted, yet the capture claims the
#    completions were attributed.
#    Round 8 accepted this: the check was guarded by the field's presence, so
#    deleting it made the check not run.
# ===========================================================================
def attribution_record_deleted():
    print("\n2. FIRST-COMPLETION RECORD DELETED BUT ATTRIBUTION CLAIMED")
    p = dict(BASE)
    for k in ("m2-b2-dma-win-1st-completed-addr",
              "m2-b2-dma-win-1st-completed-len",
              "m2-b2-dma-win-1st-completed-slot",
              "m2-b2-dma-win-1st-completed-gen"):
        p.pop(k, None)
    expect_reject("no first-completion record but 3 attributed is rejected",
                  p, "a positive attribution requires the raw first-completion")


# ===========================================================================
# 3. The attributed address is not the address of any descriptor of this
#    window.
# ===========================================================================
def attributed_address_mismatch():
    print("\n3. ATTRIBUTED ADDRESS DOES NOT MATCH THE WINDOW DESCRIPTOR")
    # win0-addr comes from the page-table dump; the chain is walked for
    # 0x37a0a32e0. Claim the completion happened at a different address.
    p = variant(m2__b2__dma__win__1st__completed__addr="0x37a0b2000")
    expect_reject("an attributed address that is not a window descriptor is "
                  "rejected", p,
                  "the attributed address is a descriptor of this window")
    # And the driver-record cross-check must also catch it.
    p2 = variant(m2__b2__obs__op__addr="0x37a0c3000")
    expect_reject("a driver record whose address differs is rejected",
                  p2, "the paired record's address matches the attributed")


# ===========================================================================
# 4. The leaf PTE is zero, or the walk is NOT-MAPPED, but the capture keeps
#    the claim that the operation completed through the current page table.
# ===========================================================================
def leaf_not_mapped():
    print("\n4. LEAF PTE ZERO / NOT-MAPPED BUT MAPPING CLAIMED")

    # (a) the leaf PTE is zero
    walk = list(BASE_WALK)
    walk[2] = ("table", "0x371cf000", "level", "0x2", "index", "0x1d0",
               "pte", "0x0")
    p = variant()
    expect_reject("a zero leaf PTE is rejected", p,
                  "independently decodes to the address", walk=walk)

    # (b) a pointer that names a child level two steps down is illegal: at
    #     level 2 the only legal non-leaf NextLevel is 1.
    walk2 = list(BASE_WALK)
    walk2[2] = ("table", "0x371cf000", "level", "0x2", "index", "0x1d0",
                "pte", "0x600000037a000601")
    expect_reject("a level-2 pointer to a level-3 table is rejected", p,
                  "independently decodes to the address", walk=walk2)

    # (c) the capture's own walk verdict says NOT-MAPPED while the claim
    #     stands, and the chain really does not map it.
    p2 = variant(m2__b2__dma__win__walk="NOT-MAPPED")
    expect_reject("a NOT-MAPPED verdict contradicting a mapped chain is "
                  "rejected", p2,
                  "the walk verdict agrees with the independent decode")

    # (d) the leaf encodes NextLevel=7 at level 2: an enlarged leaf, which
    #     cannot be sized from the PTE alone and is refused.
    walk3 = list(BASE_WALK)
    walk3[2] = ("table", "0x371cf000", "level", "0x2", "index", "0x1d0",
                "pte", "0x700000037a000e01")
    expect_reject("a NextLevel=7 leaf is rejected", p,
                  "independently decodes to the address", walk=walk3)

    # (e) a pointer at level 4 that names level 2 instead of level 3.
    walk4 = list(BASE_WALK)
    walk4[0] = ("table", "0x371c0000", "level", "0x4", "index", "0x0",
                "pte", "0x60000000371c1401")
    expect_reject("a level-4 pointer skipping a level is rejected", p,
                  "independently decodes to the address", walk=walk4)

    # (f) a table address in the chain that does not match where the previous
    #     PTE points: the "chain" would be two unrelated tables.
    walk5 = list(BASE_WALK)
    walk5[1] = ("table", "0x371c2000", "level", "0x3", "index", "0xd",
                "pte", "0x60000000371cf401")
    expect_reject("a chain whose table address does not follow is rejected",
                  p, "independently decodes to the address", walk=walk5)

    # (g) the wrong index for the address at that level.
    walk6 = list(BASE_WALK)
    walk6[1] = ("table", "0x371c1000", "level", "0x3", "index", "0xe",
                "pte", "0x60000000371cf401")
    expect_reject("a chain using the wrong index is rejected", p,
                  "independently decodes to the address", walk=walk6)


# ===========================================================================
# 5. tx-window-covered = no, or the pointers unreadable, but the capture
#    claims the TX window was complete.
# ===========================================================================
def coverage_claim_contradiction():
    print("\n5. TX WINDOW CLAIMED COMPLETE WITH AN INCONSISTENT SCAN")
    p = variant(m2__b2__dma__tx__window__covered="no")
    expect_reject("covered=no with an 'ok' scan reason is rejected",
                  p, "TX window-covered claim agrees with the scan reason")

    # A covered claim over a non-exact scan.
    p2 = variant(m2__b2__dma__win__exact="no")
    expect_reject("a covered claim over a non-exact scan is rejected",
                  p2, "a window-covered claim requires an exact scan")

    # A covered claim with a lost record.
    p3 = variant(m2__b2__dma__win__records__lost="0x1")
    expect_reject("a covered claim with a lost record is rejected",
                  p3, "a window-covered claim requires an exact scan")

    # A covered claim while pointers were unreadable.
    p4 = variant(m2__b2__dma__cloptr__delta__valid="no-pointers-unreadable",
                 m2__b2__dma__tx__window__covered="yes")
    expect_reject("a covered claim with unreadable pointers is rejected",
                  p4, "close-pointer delta was reported unusable")


# ===========================================================================
# 6. The close-pointer post-sample exceeds the counter mask, or the raw
#    TxConfig does not derive the claimed identity.
# ===========================================================================
def identity_and_mask_contradiction():
    print("\n6. SAMPLE OUTSIDE THE MASK, OR IDENTITY NOT DERIVABLE")
    # A post-sample with a bit above the 31-bit mask set.
    p = variant(m2__b2__dma__cloptr__after="0x8000006b")
    expect_reject("a post-sample outside the counter mask is rejected",
                  p, "close-pointer delta is the mask-based difference")

    # The raw TxConfig re-derives cfgMethod 41, not the claimed 42.
    p2 = variant(m2__b2__dma__txconfig="0x6f800f40")
    expect_reject("a TxConfig that re-derives a different cfgMethod is "
                  "rejected", p2,
                  "raw TxConfig re-derives the claimed configuration method")

    # The raw TxConfig is absent entirely: the identity cannot be checked.
    p3 = dict(BASE)
    p3.pop("m2-b2-dma-txconfig", None)
    expect_reject("a missing raw TxConfig is rejected", p3,
                  "m2-b2-dma-txconfig is absent")

    # cfgMethod and noCloseVer disagree with each other.
    p4 = variant(m2__b2__dma__noclosever="0x3")
    expect_reject("cfgMethod 42 with noCloseVer 3 is rejected", p4,
                  "noCloseVer follows from the configuration method")


# ===========================================================================
# 7. The completion or tail sample lies OUTSIDE the accepted time range.
#    This is the round-8 defect: the sampling span was WIDER than the window.
# ===========================================================================
def sample_outside_window():
    print("\n7. SAMPLE OUTSIDE THE ACCEPTED TIME RANGE")
    # The post-sample is after the window closed: round 8's own shape.
    p = variant(m2__b2__dma__t__clo__after="0x94a41ed33")
    expect_reject("a post-sample after the window closed is rejected",
                  p, "close-pointer post-sample lies inside the window")

    # The tail sample is after the window closed.
    p2 = variant(m2__b2__dma__t__tail__after="0x94a4204f3")
    expect_reject("a tail sample after the window closed is rejected",
                  p2, "tail-pointer post-sample lies inside the window")

    # The capture admits the boundary was outside.
    p3 = variant(m2__b2__dma__boundary__in__window="no")
    expect_reject("a capture admitting an outside boundary is rejected",
                  p3, "the capture agrees the boundary sample was inside")

    # A post-sample before the window opened.
    p4 = variant(m2__b2__dma__t__clo__after="0x880000000")
    expect_reject("a post-sample before the window opened is rejected", p4,
                  "close-pointer post-sample lies inside the window")

    # A post-sample after recovery.
    p5 = variant(m2__b2__dma__t__clo__after="0x94a700000",
                 m2__b2__dma__t__win__end="0x94a800000")
    expect_reject("a post-sample after recovery is rejected", p5,
                  "close-pointer post-sample precedes recovery")


# ===========================================================================
# Additional round-9 regressions
# ===========================================================================
def driver_record_consistency():
    print("\n8. DRIVER-RECORD CONSISTENCY")
    # An incomplete join.
    p = variant(m2__b2__obs__win__paired="0x2",
                m2__b2__obs__win__complete="no")
    expect_reject("an incomplete driver-record join is rejected", p,
                  "the driver's records show a complete submit/complete "
                  "pair inside the window")

    # An orphan completion.
    p2 = variant(m2__b2__obs__win__orphan__done="0x2",
                 m2__b2__obs__win__complete="no")
    expect_reject("an orphan completion is rejected", p2,
                  "the driver's records show a complete submit/complete "
                  "pair inside the window")

    # The slot does not follow from the cumulative index.
    p3 = variant(m2__b2__obs__op__slot="0x69")
    expect_reject("a slot that does not follow from the cumulative index is "
                  "rejected", p3,
                  "the paired record's cumulative index matches its slot")

    # The generation does not follow from the cumulative index.
    p4 = variant(m2__b2__obs__op__gen="0x2")
    expect_reject("a generation that does not follow is rejected", p4,
                  "the paired record's generation follows from its cumulative")

    # The paired operation's completion precedes its submission.
    p5 = variant(m2__b2__obs__op__t__compl="0x890000000")
    expect_reject("a completion before its submission is rejected", p5,
                  "the paired operation completed after it was submitted")

    # The paired operation lies outside the window.
    p6 = variant(m2__b2__obs__op__t__submit="0x880000000")
    expect_reject("a paired operation submitted before the window is "
                  "rejected", p6,
                  "the paired operation was submitted inside the window")

    # The driver's records did not run at all.
    p7 = dict(BASE)
    for k in list(p7.keys()):
        if k.startswith("m2-b2-obs-"):
            p7.pop(k, None)
    expect_reject("a missing driver-record set is rejected", p7,
                  "missing required field")


def control_mode_shape():
    print("\n9. CONTROL-MODE SHAPE")
    p = dict(BASE)
    p["m2-b2-mode"] = "control-sleep-only"
    p["m2-b2-verdict"] = "PASS-CANDIDATE-controlled-with-completions"
    p["m2-b2-stage"] = "13-control-complete"
    p["m2-b2-stage-control-done"] = "yes"
    p["m2-b2-stage-inv-dev"] = "no"
    p["m2-b2-stage-inv-pages"] = "no"
    for k in list(p.keys()):
        if (k.startswith("m2-b2-win-") or k.startswith("m2-b2-pre-") or
                k.startswith("m2-b2-dma-win-") or
                k.startswith("m2-b2-dma-cov-") or
                k.startswith("m2-b2-dma-t-") or
                k.startswith("m2-b2-obs-") or
                k.startswith("m2-b2-dma-tx-life-") or
                k.startswith("m2-b2-fault-")):
            p.pop(k, None)
    p["m2-b2-dma-obs"] = "SKIP-observation-did-not-complete"
    expect_reject("control mode claiming a translation pass is rejected", p,
                  "does not claim a translation verdict", walk=[])

    # A translation-mode capture with no window fields must be refused as
    # malformed, not silently judged against the control check set.
    p2 = dict(BASE)
    for k in list(p2.keys()):
        if k.startswith("m2-b2-win-") or k.startswith("m2-b2-dma-win-"):
            p2.pop(k, None)
    expect_reject("translation mode without window fields is refused", p2,
                  "missing required field")


def arithmetic_regressions():
    print("\n10. ARITHMETIC")
    # in-flight + completed != decoded
    p = variant(m2__b2__dma__win__inflight="0x1")
    expect_reject("inflight+completed != decoded is rejected", p,
                  "inflight plus completed equals decoded")

    # decoded + overwritten != visited
    p2 = variant(m2__b2__dma__win__overwritten="0x1")
    expect_reject("decoded+overwritten != visited is rejected", p2,
                  "decoded plus overwritten equals visited")

    # visited + skipped != submits
    p3 = variant(m2__b2__dma__win__skipped="0x2")
    expect_reject("visited+skipped != submits is rejected", p3,
                  "every submitted index was visited or accounted for")

    # in-window completions exceed the total
    p4 = variant(m2__b2__dma__win__completed__in__window="0x5")
    expect_reject("in-window completions exceeding the total are rejected", p4,
                  "in-window completions do not exceed total completions")

    # The inherited-queue accounting must add up.
    p5 = variant(m2__b2__dma__win__prewin__completed="0x2")
    expect_reject("pre-window completions that do not add up are rejected", p5,
                  "inherited-queue completions are accounted for")

    # The close-pointer delta must agree with the window completes.
    p6 = variant(m2__b2__dma__win__completes="0x4",
                 m2__b2__dma__win__completed="0x4",
                 m2__b2__dma__win__completed__in__window="0x4")
    expect_reject("window completes disagreeing with the delta are rejected",
                  p6, "window completes agree with the close-pointer delta")


def envelope_regressions():
    print("\n11. ENVELOPE AND COVERAGE")
    # The attributed address lies outside the envelope.
    p = variant(m2__b2__dma__win__1st__completed__addr="0x500000000")
    expect_reject("an attributed address outside the envelope is rejected", p,
                  "the attributed address is a descriptor of this window")

    # A device-wide negative with TX-only coverage.
    p2 = variant(m2__b2__fault__negative__sound="yes",
                 m2__b2__fault__negative__scope=
                 "device-wide-all-paths-covered")
    expect_reject("a device-wide negative with TX-only coverage is rejected",
                  p2, "negative-soundness flag matches all-window coverage")

    # Unscanned slots with a window-complete path.
    p3 = variant(m2__b2__dma__unscanned="0x800")
    expect_reject("unscanned slots with a window-complete path is rejected",
                  p3, "unscanned slots are zero whenever any path claims")


def main():
    print("Round-9 analyser negative regressions")
    print("=" * 78)

    baseline_is_accepted()
    tail_delta_contradiction()
    attribution_record_deleted()
    attributed_address_mismatch()
    leaf_not_mapped()
    coverage_claim_contradiction()
    identity_and_mask_contradiction()
    sample_outside_window()
    driver_record_consistency()
    control_mode_shape()
    arithmetic_regressions()
    envelope_regressions()

    print("\n" + "=" * 78)
    print("{} passed, {} failed".format(PASS, FAIL))
    if FAIL == 0:
        print("RESULT: ALL REGRESSIONS BEHAVED AS REQUIRED")
        return 0
    print("RESULT: FAILURES")
    for name, detail in FAILURES:
        print("  - {}".format(name))
    return 1


if __name__ == "__main__":
    sys.exit(main())
