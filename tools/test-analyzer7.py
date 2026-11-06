#!/usr/bin/env python3
"""Negative regression tests for tools/analyze-round7.py.

Every test takes a *valid* round-7 capture and injects exactly one defect,
then asserts that the analyser rejects it in the specific way expected. A
test that merely asserts "non-zero exit" is not enough: a checker that
rejects everything would pass such a test while being useless. So each
test names the check that must fail.

The baseline capture is synthesised from the field schema, with values that
describe a coherent translation run. Tests then mutate one field.

Usage:
    py -3 tools/test-analyzer7.py
Exit code 0 = all regressions caught.
"""
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ANALYSER = os.path.join(HERE, "analyze-round7.py")
# The DSH session temp area is not writable under workspace-write, so the
# scratch directory lives inside the project.
SCRATCH = os.path.join(os.path.dirname(HERE), "build-work-analyser-test")

# ---------------------------------------------------------------------------
# A coherent baseline capture.
#
# These are SYNTHETIC values that satisfy every invariant the analyser
# checks. They are not a real capture and are never presented as one; their
# only purpose is to give each negative test a valid starting point.
# ---------------------------------------------------------------------------
BASE = {
    "m2-b2-verdict": "PASS-CANDIDATE-no-events-with-completions",
    "m2-b2-stage": "19-no-events-with-completions",
    "m2-b2-mode": "translation",
    "m2-b2-target-devid": "0x2500",

    "m2-b2-dump-root-pa": "0x2e7c0000",
    "m2-b2-dump-root-level": "0x4",
    "m2-b2-dump-page-mode": "0x4",
    "m2-b2-dump-pt-pages": "0x13",
    "m2-b2-dump-map-limit": "0x400000000",
    "m2-b2-dump-leaf-encoding": "NextLevel0-2MiB-default",
    "m2-b2-dump-forensic-base": "0x2e7c0000",
    "m2-b2-dump-forensic-bytes": "0x13000",
    "m2-b2-dump-count": "0x0",

    "m2-b2-stage-evt-reset": "yes",
    "m2-b2-stage-inv-all": "yes",
    "m2-b2-stage-inv-dev": "yes",
    "m2-b2-stage-inv-pages": "yes",
    "m2-b2-stage-control-done": "no",

    "m2-b2-cmd-submits": "0x3",
    "m2-b2-cmd-completed": "0x3",
    "m2-b2-cmd-record-count": "0x3",

    "m2-b2-disabled": "yes",
    "m2-b2-cmdbuf-stopped": "yes",
    "m2-b2-evtlog-stopped": "yes",
    "m2-b2-cmdbuf-stop-status": "0x2",
    "m2-b2-evtlog-stop-status": "0x2",
    "m2-b2-final-control": "0x220000000400",
    "m2-b2-orig-control-echo": "0x220000000400",
    "m2-b2-regs-restored": "yes",
    "m2-b2-cleanup": "done",

    "m2-b2-dma-obs": "complete",
    "m2-b2-dma-trust": "trusted",
    "m2-b2-dma-layout-known": "no",
    "m2-b2-dma-ranges": "0x10",
    "m2-b2-dma-dropped": "0x0",
    "m2-b2-dma-raw-offered": "0x40",
    "m2-b2-dma-merged-total": "0x10",
    "m2-b2-dma-unscanned": "0x0",
    "m2-b2-dma-envelope-valid": "yes",
    "m2-b2-dma-envelope-lo": "0x29438000",
    "m2-b2-dma-envelope-hi": "0x3ff000000",
    "m2-b2-dma-coverage": "window-complete",
    "m2-b2-dma-read-ok": "0x0",
    "m2-b2-dma-read-outofmap": "0x10",
    "m2-b2-dma-read-notram": "0x0",
    "m2-b2-dma-tx-slots": "0x400",
    "m2-b2-dma-tx-zeroaddr": "0x175",
    "m2-b2-dma-tx-done-with-addr": "0x0",

    "m2-b2-dma-cloptr-reg": "0xd34",
    "m2-b2-dma-cloptr-width": "0x4",
    "m2-b2-dma-cloptr-mask": "0x7fffffff",
    "m2-b2-dma-cloptr-before": "0x28b",
    "m2-b2-dma-cloptr-after": "0x290",
    "m2-b2-dma-cloptr-delta": "0x5",
    "m2-b2-dma-cloptr-delta-valid": "yes",
    "m2-b2-dma-tx-window-covered": "yes",
    "m2-b2-dma-cfgmethod": "0x29",
    "m2-b2-dma-noclosever": "0x6",
    "m2-b2-dma-chip-known": "yes",

    "m2-b2-dma-t-obs-before": "0x1000",
    "m2-b2-dma-t-obs-after": "0x2000",
    "m2-b2-dma-t-clo-before": "0x1800",
    "m2-b2-dma-t-clo-after": "0x2400",
    "m2-b2-t-recovery-start": "0x3000",

    "m2-b2-fault-inrange": "0x0",
    "m2-b2-fault-outofrange": "0x0",
    "m2-b2-fault-walk-present": "0x0",
    "m2-b2-fault-walk-illegal": "0x0",
    "m2-b2-fault-walk-absent": "0x0",
    "m2-b2-fault-observed-absent": "0x0",
    "m2-b2-fault-coverage": "window-complete",
    "m2-b2-fault-negative-sound": "yes",

    "m2-b2-dma-walk-count": "0x3",
    "m2-b2-dma-walk-present": "0x3",
    "m2-b2-dma-walk-verdict": "all-identity-mapped",

    # window
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
    "m2-b2-win-status-start": "0x1a",
    "m2-b2-win-status-end": "0x1a",
    "m2-b2-win-entries": "0x0",
    "m2-b2-win-new-entries": "0x0",
    "m2-b2-win-devid-mismatch": "0x0",
    "m2-b2-win-pre-backlog": "0x0",
    "m2-b2-win-raw-truncated": "no",
    "m2-b2-win-raw-count": "0x0",
}

# Descriptor dumps. Their addresses must lie inside the envelope.
BASE_DESC = {
    "m2-b2-dma-txdesc0":
        "opts1=a0000036 opts2=00000000 addr=00000003d1c0cdca len=0x36",
    "m2-b2-dma-txdesc1":
        "opts1=80000008 opts2=00000000 addr=00000003d7d8b2e0 len=0x8",
}

# Per-command records for the three commands the probe submits.
BASE_CMDS = [
    ("inv-all", "00000000800000000000000000000000", "0x1", "0x1"),
    ("inv-dev-entry", "00002500200000000000000000000000", "0x2", "0x2"),
    ("inv-iommu-pages", "0000000030000000fffff0037fffffff", "0x3", "0x3"),
]


def render(props, descs, cmds):
    lines = ["+-o org_maz1_AMDMapperProbe  <class org_maz1_AMDMapperProbe>"]
    lines.append("  | {")
    for k, v in props.items():
        lines.append('  |   "{}" = "{}"'.format(k, v))
    for k, v in descs.items():
        lines.append('  |   "{}" = "{}"'.format(k, v))
    for i, (label, dwords, exp, obs) in enumerate(cmds):
        lines.append('  |   "m2-b2-cmd{}-label" = "{}"'.format(i, label))
        lines.append('  |   "m2-b2-cmd{}-dwords" = "{}"'.format(i, dwords))
        lines.append('  |   "m2-b2-cmd{}-expected" = "{}"'.format(i, exp))
        lines.append('  |   "m2-b2-cmd{}-observed" = "{}"'.format(i, obs))
        lines.append('  |   "m2-b2-cmd{}-loops" = "0x5d7"'.format(i))
        lines.append('  |   "m2-b2-cmd{}-ok" = "yes"'.format(i))
    lines.append("  | }")
    return "\n".join(lines) + "\n"


def run(props, descs=None, cmds=None):
    """Render a capture, run the analyser, return (rc, stdout)."""
    if descs is None:
        descs = dict(BASE_DESC)
    if cmds is None:
        cmds = list(BASE_CMDS)
    text = render(props, descs, cmds)
    if not os.path.isdir(SCRATCH):
        os.makedirs(SCRATCH)
    path = os.path.join(SCRATCH, "capture.txt")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    p = subprocess.run([sys.executable, ANALYSER, path],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def variant(**changes):
    p = dict(BASE)
    p.update(changes)
    return p


def expect_reject(name, props, needle, descs=None, cmds=None):
    """Assert the analyser exits 3 and the named check fails."""
    rc, out = run(props, descs, cmds)
    if rc != 3:
        return False, "{}: expected exit 3, got {} (needle={!r})".format(
            name, rc, needle)
    if needle and needle not in out:
        return False, "{}: exit 3 but check {!r} not reported".format(
            name, needle)
    return True, ""


def expect_accept(name, props, descs=None, cmds=None):
    rc, out = run(props, descs, cmds)
    if rc not in (0, 1):
        return False, "{}: expected a functional verdict, got exit {}: {}".format(
            name, rc, out.strip().splitlines()[-1] if out.strip() else "")
    return True, ""


TESTS = []


def test(fn):
    TESTS.append(fn)
    return fn


# ===========================================================================
# Baseline sanity: the coherent capture must be ACCEPTED, otherwise every
# negative test below would pass for the wrong reason.
# ===========================================================================
@test
def baseline_is_valid():
    return expect_accept("baseline", variant())


# ===========================================================================
# Counterexample 1 (task section 二.1): a descriptor address outside the
# declared envelope. This is the exact contradiction found in round 6's own
# archive (envelope-hi 0x3f80a4000, txdesc4 addr 0x3fec620e0).
# ===========================================================================
@test
def desc_address_outside_envelope():
    descs = dict(BASE_DESC)
    # Above envelope-hi 0x3ff000000.
    descs["m2-b2-dma-txdesc2"] = (
        "opts1=90000014 opts2=00000000 addr=0000000405711b9c len=0x14")
    return expect_reject(
        "descriptor above envelope", variant(), "inside the envelope",
        descs=descs)


@test
def round6_archive_shape_is_rejected():
    # The exact round-6 archive shape: envelope-hi = 0x3f80a4000 while
    # txdesc4.addr = 0x3fec620e0. Reproducing the real contradiction is the
    # point of counterexample 1, so it gets its own test with the real
    # numbers rather than a made-up pair.
    descs = dict(BASE_DESC)
    descs["m2-b2-dma-txdesc4"] = (
        "opts1=90000014 opts2=00000000 addr=00000003fec620e0 len=0x14")
    descs["m2-b2-dma-txdesc5"] = (
        "opts1=b0000056 opts2=00000000 addr=00000003fec600e2 len=0x56")
    return expect_reject(
        "round-6 archive contradiction",
        variant(**{"m2-b2-dma-envelope-hi": "0x3f80a4000",
                   "m2-b2-dma-envelope-lo": "0x29438000"}),
        "inside the envelope", descs=descs)


@test
def desc_address_below_envelope():
    descs = dict(BASE_DESC)
    descs["m2-b2-dma-txdesc3"] = (
        "opts1=80000008 opts2=00000000 addr=0000000000100000 len=0x8")
    return expect_reject(
        "descriptor below envelope", variant(), "inside the envelope",
        descs=descs)


# ===========================================================================
# Counterexample 2 (task section 二.2): the accounting invariant. A full set
# with dropped intervals must still satisfy merged == saved + dropped.
# ===========================================================================
@test
def accounting_double_count():
    # Round 6's bug: dropped counted both merged intervals and raw addresses.
    return expect_reject(
        "merged != saved + dropped",
        variant(**{"m2-b2-dma-merged-total": "0x30",
                   "m2-b2-dma-ranges": "0x10",
                   "m2-b2-dma-dropped": "0x427"}),
        "merged intervals equal saved plus dropped")


@test
def raw_less_than_merged():
    return expect_reject(
        "raw offered < merged",
        variant(**{"m2-b2-dma-raw-offered": "0x4",
                   "m2-b2-dma-merged-total": "0x10"}),
        "raw offered addresses is at least the merged count")


# ===========================================================================
# Counterexample 3 (task section 二.3): an above-16-GiB descriptor must be
# RECORDED. If it is, the envelope must contain it; if the envelope stops at
# 16 GiB while a descriptor sits above it, that is the round-6 defect.
# ===========================================================================
@test
def above_16g_descriptor_inside_envelope():
    # A capture where the descriptor is above 16 GiB AND the envelope covers
    # it must be accepted -- the address was recorded, which is the point.
    descs = dict(BASE_DESC)
    descs["m2-b2-dma-txdesc2"] = (
        "opts1=90000014 opts2=00000000 addr=0000000405711b9c len=0x14")
    return expect_accept(
        "above-16GiB descriptor recorded",
        variant(**{"m2-b2-dma-envelope-hi": "0x405712000"}),
        descs=descs)


@test
def above_16g_descriptor_excluded():
    # The same descriptor with a 16 GiB-capped envelope is the contradiction.
    descs = dict(BASE_DESC)
    descs["m2-b2-dma-txdesc2"] = (
        "opts1=90000014 opts2=00000000 addr=0000000405711b9c len=0x14")
    return expect_reject(
        "above-16GiB descriptor outside a 16GiB envelope",
        variant(**{"m2-b2-dma-envelope-hi": "0x400000000"}),
        "inside the envelope", descs=descs)


# ===========================================================================
# Counterexample 4 (task section 二.4): address + length, page crossing and
# overflow. The analyser cannot see individual segments, but it CAN see the
# read-verdict accounting, which is where an overflowing range lands.
# ===========================================================================
@test
def read_verdicts_exceed_ranges():
    return expect_reject(
        "read verdicts exceed saved ranges",
        variant(**{"m2-b2-dma-read-ok": "0x8",
                   "m2-b2-dma-read-outofmap": "0x8",
                   "m2-b2-dma-read-notram": "0x8",
                   "m2-b2-dma-ranges": "0x10"}),
        "read verdicts account for at most the saved ranges")


# ===========================================================================
# Close-pointer semantics (task section 四).
# ===========================================================================
@test
def cloptr_mask_is_ring_size():
    # 0x3ff == 1023: the round-6 mistake of treating the cumulative counter
    # as a ring index.
    return expect_reject(
        "close-pointer mask is the ring size",
        variant(**{"m2-b2-dma-cloptr-mask": "0x3ff",
                   "m2-b2-dma-cloptr-delta": "0x0"}),
        "count mask is not the ring size")


@test
def cloptr_register_wrong_for_chip():
    # Ver 6 must use 0x0D34; 0x2800 belongs to ver 4/5.
    return expect_reject(
        "close-pointer register wrong for ver 6",
        variant(**{"m2-b2-dma-cloptr-reg": "0x2800"}),
        "close-pointer register matches the chip")


@test
def cloptr_width_wrong_for_chip():
    return expect_reject(
        "close-pointer width wrong for ver 6",
        variant(**{"m2-b2-dma-cloptr-width": "0x2"}),
        "close-pointer width matches the chip")


@test
def cloptr_delta_not_mask_based():
    # 1000 -> 2024: the mask-based answer is 1024; a ring-modulo answer is 0.
    # Claiming 0 while the samples say 1024 must be caught.
    return expect_reject(
        "delta is a ring-modulo zero",
        variant(**{"m2-b2-dma-cloptr-before": "0x3e8",
                   "m2-b2-dma-cloptr-after": "0x7e8",
                   "m2-b2-dma-cloptr-delta": "0x0"}),
        "close-pointer delta is the mask-based difference")


@test
def cloptr_delta_1000_to_2024_correct():
    # The correct delta of 1024 must be accepted.
    return expect_accept(
        "1000 -> 2024 is 1024",
        variant(**{"m2-b2-dma-cloptr-before": "0x3e8",
                   "m2-b2-dma-cloptr-after": "0x7e8",
                   "m2-b2-dma-cloptr-delta": "0x400"}))


@test
def cloptr_delta_above_half_mask():
    # A jump of more than half the counter space looks like a reset.
    return expect_reject(
        "delta above half the mask",
        variant(**{"m2-b2-dma-cloptr-before": "0x1000",
                   "m2-b2-dma-cloptr-after": "0x40101000",
                   "m2-b2-dma-cloptr-delta": "0x40000000"}),
        "close-pointer delta is below half the mask")


@test
def cloptr_delta_claimed_valid_but_unusable():
    # If the probe says the delta is unusable, the verdict must not be a
    # PASS-CANDIDATE that depends on it.
    return expect_reject(
        "unusable delta with a pass-candidate verdict",
        variant(**{"m2-b2-dma-cloptr-delta-valid":
                   "no-implausible-reset-or-identity-change"}),
        "verdict does not rely on it")


@test
def cloptr_sample_exceeds_width():
    return expect_reject(
        "16-bit sample above 0xffff",
        variant(**{"m2-b2-dma-noclosever": "0x3",
                   "m2-b2-dma-cloptr-reg": "0x2802",
                   "m2-b2-dma-cloptr-width": "0x2",
                   "m2-b2-dma-cloptr-mask": "0xffff",
                   "m2-b2-dma-cloptr-before": "0x1ffff"}),
        "close-pointer sample fits its width")


@test
def cloptr_unknown_chip():
    return expect_reject(
        "unknown chip identity",
        variant(**{"m2-b2-dma-chip-known": "no"}),
        "chip identity is known")


@test
def cloptr_unknown_version():
    return expect_reject(
        "unknown close-pointer version",
        variant(**{"m2-b2-dma-chip-known": "no",
                   "m2-b2-dma-noclosever": "0x9"}),
        "one of the known versions")


# ===========================================================================
# Time boundaries (task section 四).
# ===========================================================================
@test
def time_obs_reversed():
    return expect_reject(
        "observation end before start",
        variant(**{"m2-b2-dma-t-obs-before": "0x2000",
                   "m2-b2-dma-t-obs-after": "0x1000",
                   "m2-b2-dma-t-clo-before": "0x1800",
                   "m2-b2-t-recovery-start": "0x3000"}),
        "observation end is after its start")


@test
def time_cloptr_outside_observation():
    return expect_reject(
        "close-pointer sample outside observation",
        variant(**{"m2-b2-dma-t-clo-before": "0x5000"}),
        "close-pointer sample is inside the observation")


@test
def time_recovery_before_observation():
    return expect_reject(
        "recovery before observation end",
        variant(**{"m2-b2-t-recovery-start": "0x1500"}),
        "recovery starts after the observation")


# ===========================================================================
# Control mode (task section 五).
# ===========================================================================
@test
def control_mode_without_completion():
    # The control branch was SELECTED but its stage never completed. Round 6
    # would still have emitted CONTROL because it only looked at the choice.
    return expect_reject(
        "control stage did not complete",
        variant(**{"m2-b2-mode": "control-sleep-only",
                   "m2-b2-verdict": "CONTROL-sleep-only-no-dte-change",
                   "m2-b2-stage": "13-control-complete",
                   "m2-b2-stage-control-done": "no"}),
        "control stage actually completed")


@test
def control_mode_completed_is_accepted():
    return expect_accept(
        "control stage completed",
        variant(**{"m2-b2-mode": "control-sleep-only",
                   "m2-b2-verdict": "CONTROL-sleep-only-no-dte-change",
                   "m2-b2-stage": "13-control-complete",
                   "m2-b2-stage-control-done": "yes"}))


@test
def control_mode_after_failed_reset():
    # A control run whose event-log reset failed must NOT claim CONTROL.
    return expect_reject(
        "control claimed after failed reset",
        variant(**{"m2-b2-mode": "control-sleep-only",
                   "m2-b2-verdict": "CONTROL-sleep-only-no-dte-change",
                   "m2-b2-stage": "13-control-complete",
                   "m2-b2-stage-control-done": "yes",
                   "m2-b2-stage-evt-reset": "no"}),
        "event log was reset")


@test
def translation_mode_claims_control_done():
    return expect_reject(
        "translation mode claims a control stage",
        variant(**{"m2-b2-stage-control-done": "yes"}),
        "control stage not claimed in translation mode")


@test
def translation_mode_missing_invalidation():
    return expect_reject(
        "translation without INV_IOMMU_PAGES",
        variant(**{"m2-b2-stage-inv-pages": "no"}),
        "INV_IOMMU_PAGES completed")


# ===========================================================================
# Stop confirmation must come from the hardware word (task section 五).
# ===========================================================================
@test
def stop_claim_contradicts_status():
    # Claim "stopped" while CmdBufRun is still set in STATUS.
    return expect_reject(
        "cmdbuf stop claim contradicts STATUS",
        variant(**{"m2-b2-cmdbuf-stop-status": "0x12",
                   "m2-b2-cmdbuf-stopped": "yes"}),
        "command buffer stop claim matches STATUS")


@test
def evtlog_claim_contradicts_status():
    return expect_reject(
        "evtlog stop claim contradicts STATUS",
        variant(**{"m2-b2-evtlog-stop-status": "0x1a",
                   "m2-b2-evtlog-stopped": "yes"}),
        "event log stop claim matches STATUS")


@test
def overflow_at_stop():
    return expect_reject(
        "overflow bit set at stop",
        variant(**{"m2-b2-cmdbuf-stop-status": "0x3",
                   "m2-b2-cmdbuf-stopped": "no"}),
        "STATUS has no EventOverflow")


# ===========================================================================
# Enum fields must reject arbitrary strings (task section 五).
# ===========================================================================
@test
def bogus_coverage_string():
    return expect_reject(
        "bogus coverage value",
        variant(**{"m2-b2-dma-coverage": "probably-fine"}),
        "coverage is a known value")


@test
def bogus_lifecycle_string():
    return expect_reject(
        "bogus lifecycle value",
        variant(),
        "range metadata uses only known enumerations",
        descs=dict(BASE_DESC, **{
            "m2-b2-dma-range0-life": "maybe-live"}))


@test
def bogus_purpose_string():
    return expect_reject(
        "bogus purpose value",
        variant(),
        "range metadata uses only known enumerations",
        descs=dict(BASE_DESC, **{
            "m2-b2-dma-range0-purpose": "packet-thing"}))


@test
def bogus_read_verdict_string():
    return expect_reject(
        "bogus read verdict",
        variant(),
        "range metadata uses only known enumerations",
        descs=dict(BASE_DESC, **{
            "m2-b2-dma-range0-read": "fine"}))


@test
def bogus_mode_string():
    return expect_reject(
        "bogus mode",
        variant(**{"m2-b2-mode": "translation-ish"}),
        "experiment mode is a known mode")


@test
def bogus_verdict_string():
    return expect_reject(
        "bogus verdict",
        variant(**{"m2-b2-verdict": "probably fine"}),
        "verdict is a recognised token")


@test
def bogus_stage_string():
    return expect_reject(
        "bogus stage",
        variant(**{"m2-b2-stage": "somewhere"}),
        "stage is a recognised token")


# ===========================================================================
# Missing / malformed fields must be CANNOT-ANALYSE (exit 2), never a
# silently satisfied check.
# ===========================================================================
@test
def missing_field_is_not_silently_ok():
    p = dict(BASE)
    del p["m2-b2-dma-coverage"]
    rc, out = run(p)
    if rc != 2:
        return False, "missing field: expected exit 2, got {}".format(rc)
    return True, ""


@test
def malformed_hex_is_rejected():
    # A malformed value must be CANNOT-ANALYSE (exit 2), not a validity
    # failure (exit 3): the capture cannot be interpreted at all.
    rc, out = run(variant(**{"m2-b2-dma-envelope-hi": "not-a-number"}))
    if rc != 2:
        return False, "malformed hex: expected exit 2, got {}".format(rc)
    if "not a 0x-prefixed hex number" not in out:
        return False, "malformed hex: reason not reported"
    return True, ""


@test
def yesno_field_with_number():
    p = dict(BASE)
    p["m2-b2-disabled"] = "1"
    rc, out = run(p)
    if rc != 2:
        return False, "yes/no field with '1': expected exit 2, got {}".format(rc)
    return True, ""


# ===========================================================================
# Address observation completeness.
# ===========================================================================
@test
def observation_did_not_run():
    return expect_reject(
        "observation skipped",
        variant(**{"m2-b2-dma-obs": "SKIP-no-bar2"}),
        "device DMA observation ran")


@test
def no_ranges_recorded():
    return expect_reject(
        "no ranges",
        variant(**{"m2-b2-dma-ranges": "0x0",
                   "m2-b2-dma-merged-total": "0x0"}),
        "at least one DMA range")


@test
def envelope_missing():
    return expect_reject(
        "no envelope",
        variant(**{"m2-b2-dma-envelope-valid": "no"}),
        "envelope exists")


@test
def negative_sound_flag_lies():
    # Claims a sound negative while coverage is snapshot-only.
    return expect_reject(
        "negative-sound with snapshot coverage",
        variant(**{"m2-b2-dma-coverage": "snapshot-only",
                   "m2-b2-fault-coverage": "snapshot-only",
                   "m2-b2-fault-negative-sound": "yes"}),
        "negative ownership soundness flag matches coverage")


@test
def fault_coverage_differs_from_observation():
    return expect_reject(
        "fault coverage differs from observation coverage",
        variant(**{"m2-b2-fault-coverage": "snapshot-only"}),
        "fault classification used the same coverage")


@test
def dma_walk_found_nothing():
    # If the walker cannot map the device's OWN addresses, every "absent"
    # verdict it produces is void.
    return expect_reject(
        "no live DMA address mapped",
        variant(**{"m2-b2-dma-walk-count": "0x3",
                   "m2-b2-dma-walk-present": "0x0",
                   "m2-b2-dma-walk-verdict": "SOME-NOT-MAPPED"}),
        "every live DMA address walked to an identity leaf")


@test
def dma_walk_empty():
    return expect_reject(
        "no DMA addresses walked",
        variant(**{"m2-b2-dma-walk-count": "0x0",
                   "m2-b2-dma-walk-present": "0x0",
                   "m2-b2-dma-walk-verdict": "no-addresses-observed"}),
        "DMA walk examined at least one live address")


# ===========================================================================
# Event window reconciliation.
# ===========================================================================
@test
def entries_without_raw_when_not_truncated():
    return expect_reject(
        "entries claimed but no raw and no truncation",
        variant(**{"m2-b2-win-entries": "0x3",
                   "m2-b2-win-raw-count": "0x0",
                   "m2-b2-win-raw-truncated": "no"}),
        "truncation flag agrees")


@test
def per_type_sum_mismatch():
    p = variant(**{"m2-b2-win-entries": "0x2",
                   "m2-b2-win-raw-truncated": "yes",
                   "m2-b2-win-type2-count": "0x5"})
    return expect_reject(
        "per-type sum != entries", p,
        "per-type counters sum to the window entry count")


@test
def truncated_flag_lies():
    return expect_reject(
        "truncation flag false while entries exceed raw",
        variant(**{"m2-b2-win-entries": "0x3",
                   "m2-b2-win-raw-count": "0x0",
                   "m2-b2-win-raw-truncated": "no"}),
        "truncation flag agrees")


@test
def command_record_claims_ok_but_mismatched():
    cmds = list(BASE_CMDS)
    cmds[0] = ("inv-all", "00000000800000000000000000000000", "0x1", "0x2")
    return expect_reject(
        "record claims ok with mismatched values", variant(),
        "every retained command record is self-consistent", cmds=cmds)


@test
def command_record_claims_fail_but_equal():
    cmds = list(BASE_CMDS)
    cmds[0] = ("inv-all", "00000000800000000000000000000000", "0x1", "0x1")
    # Now flip its ok to "no".
    p = variant()
    text_ok = True
    # Rebuild with the record marked not-ok by post-processing.
    descs = dict(BASE_DESC)
    lines = ["+-o org_maz1_AMDMapperProbe"]
    lines.append("  | {")
    for k, v in p.items():
        lines.append('  |   "{}" = "{}"'.format(k, v))
    for k, v in descs.items():
        lines.append('  |   "{}" = "{}"'.format(k, v))
    for i, (label, dwords, exp, obs) in enumerate(cmds):
        lines.append('  |   "m2-b2-cmd{}-label" = "{}"'.format(i, label))
        lines.append('  |   "m2-b2-cmd{}-dwords" = "{}"'.format(i, dwords))
        lines.append('  |   "m2-b2-cmd{}-expected" = "{}"'.format(i, exp))
        lines.append('  |   "m2-b2-cmd{}-observed" = "{}"'.format(i, obs))
        lines.append('  |   "m2-b2-cmd{}-loops" = "0x5d7"'.format(i))
        okv = "no" if i == 0 else "yes"
        lines.append('  |   "m2-b2-cmd{}-ok" = "{}"'.format(i, okv))
    lines.append("  | }")
    text = "\n".join(lines) + "\n"
    if not os.path.isdir(SCRATCH):
        os.makedirs(SCRATCH)
    path = os.path.join(SCRATCH, "capture.txt")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    proc = subprocess.run([sys.executable, ANALYSER, path],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = proc.stdout.decode("utf-8", "replace")
    if proc.returncode != 3:
        return False, "claims-fail-but-equal: expected exit 3, got {}".format(
            proc.returncode)
    if "self-consistent" not in out:
        return False, "claims-fail-but-equal: check not reported"
    return True, ""


@test
def head_moved_during_window():
    return expect_reject(
        "HEAD moved",
        variant(**{"m2-b2-win-head-start": "0x0",
                   "m2-b2-win-head-end": "0x10"}),
        "HEAD unchanged during window")


@test
def window_duration_wrong():
    return expect_reject(
        "duration inconsistent",
        variant(**{"m2-b2-win-dur-ms": "0x1"}),
        "measured duration consistent with nominal")


@test
def event_overflow_at_window_start():
    return expect_reject(
        "overflow at window start",
        variant(**{"m2-b2-win-status-start": "0x1b"}),
        "no EVT_OVERFLOW at window start")


# ===========================================================================
# PR=0 must not report PR-only fields (task section 五).
# ===========================================================================
@test
def pr0_with_rz_set_is_rejected():
    # An IO_PAGE_FAULT with PR=0 and RZ=1. Spec Table 57: RZ is only
    # meaningful when PR=1, so this is either a decode error or a corrupted
    # event -- either way it must not be reported as a cause.
    descs = dict(BASE_DESC)
    # d1: type 2 in bits 31:28, PR(bit20)=0, RZ(bit23)=1
    d1 = (0x2 << 28) | (1 << 23)
    descs["m2-b2-win-raw0"] = "00002500{:08x}05711b9c00000004".format(d1)
    p = variant(**{"m2-b2-win-entries": "0x1",
                   "m2-b2-win-raw-count": "0x1",
                   "m2-b2-win-raw-truncated": "no",
                   "m2-b2-win-type2-count": "0x1",
                   "m2-b2-win-dominant": "IO_PAGE_FAULT",
                   "m2-b2-win-dominant-count": "0x1",
                   "m2-b2-fault-outofrange": "0x1",
                   "m2-b2-fault-walk-absent": "0x1",
                   "m2-b2-fault-observed-absent": "0x1",
                   "m2-b2-dump-count": "0x1",
                   "m2-b2-verdict": "FAIL-io-page-faults-observed",
                   "m2-b2-stage": "19-complete-faults"})
    return expect_reject("PR=0 with RZ=1", p,
                         "PR=0 faults do not report PR-only cause fields",
                         descs=descs)


@test
def foreign_devid_event_is_rejected():
    descs = dict(BASE_DESC)
    descs["m2-b2-win-raw0"] = "000099001000000005711b9c00000004"
    p = variant(**{"m2-b2-win-entries": "0x1",
                   "m2-b2-win-raw-count": "0x1",
                   "m2-b2-win-raw-truncated": "no",
                   "m2-b2-win-type1-count": "0x1",
                   "m2-b2-win-dominant": "ILLEGAL_DEV_TABLE_ENTRY",
                   "m2-b2-win-dominant-count": "0x1",
                   "m2-b2-verdict": "FAIL-non-fault-events-observed",
                   "m2-b2-stage": "19-complete-other-events"})
    return expect_reject("foreign devid in raw event", p,
                         "every retained raw event belongs to the target device",
                         descs=descs)


# ===========================================================================
# Verdict / mode consistency.
# ===========================================================================
@test
def control_verdict_in_translation_mode():
    return expect_reject(
        "CONTROL verdict in translation mode",
        variant(**{"m2-b2-verdict": "CONTROL-sleep-only-no-dte-change",
                   "m2-b2-stage": "19-control-preserved"}),
        "translation mode does not emit a CONTROL verdict")


@test
def not_restored_is_rejected():
    return expect_reject(
        "registers not restored",
        variant(**{"m2-b2-regs-restored": "MISMATCH"}),
        "registers restored")


@test
def control_not_restored_is_rejected():
    return expect_reject(
        "CONTROL not restored to original",
        variant(**{"m2-b2-final-control": "0x220000001405"}),
        "CONTROL restored to its original value")


@test
def iommu_left_enabled_is_rejected():
    return expect_reject(
        "IOMMU left enabled",
        variant(**{"m2-b2-disabled": "no"}),
        "IOMMU disabled")


def main():
    if not os.path.isdir(SCRATCH):
        os.makedirs(SCRATCH)
    passed = 0
    failed = 0
    for fn in TESTS:
        try:
            ok, why = fn()
        except Exception as e:      # noqa: BLE001 - report, do not crash
            ok, why = False, "{}: raised {}: {}".format(fn.__name__,
                                                       type(e).__name__, e)
        if ok:
            passed += 1
        else:
            failed += 1
            print("FAIL: {}".format(why or fn.__name__))
    print()
    print("{} passed, {} failed".format(passed, failed))
    if failed == 0:
        print("RESULT: ALL NEGATIVE REGRESSIONS CAUGHT")
        return 0
    print("RESULT: FAILURES")
    return 1


if __name__ == "__main__":
    sys.exit(main())
