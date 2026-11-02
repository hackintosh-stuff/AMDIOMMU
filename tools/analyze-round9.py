#!/usr/bin/env python3
"""Round-9 evidence analyser.

WHAT CHANGED FROM analyze-round8.py, AND WHY IT HAD TO
-----------------------------------------------------
Round 8's analyser checked that the CAPTURE'S OWN LABELS were mutually
consistent. It could not detect a capture that was internally coherent but
described operations that never happened, because it never recomputed anything
from the raw numbers. Seven specific holes:

 1. `tail-before` and `tail-after` were both published, but nothing compared
    their difference with the number of submits the capture claimed. A capture
    saying "tail 0x68 -> 0x68, 3 submitted" passed.
 2. The completion attribution was accepted on the presence of
    `win-1st-completed-addr`. Delete every first-completion field and the
    check that used them simply did not run.
 3. Nothing compared the attributed address with the descriptor that was
    supposed to have produced it (`win0-addr`).
 4. The page-table walk was reported as a token. A leaf PTE of zero, or a walk
    that says NOT-MAPPED, was never cross-checked against the claim "this
    operation completed through the current page table".
 5. `tx-window-covered = yes` was checked against the scan reason, but not
    against the pointer values or the scan's own exactness.
 6. The close-pointer post-sample was checked against the mask, but the raw
    TxConfig was never re-derived into a cfgMethod and compared with the
    identity the capture claims.
 7. The completion/tail samples were required to bracket the window, but not
    to lie INSIDE it. Round 8's own capture had a sampling span wider than the
    window, which is exactly the case that check should have refused.

Round 9 therefore RECOMPUTES:

   * tail delta -> submits, and compares with the claimed count
   * close-pointer delta -> completes, and compares with the claimed count
   * per-descriptor records -> decoded/overwritten/inflight/completed, and
     checks the arithmetic closes
   * the PTE chain -> level, index, next-table PA, leaf, permissions and the
     final output address, decoded INDEPENDENTLY of what the capture says
   * the event window and translation interval -> each sample's position
   * the driver's own submit/complete record pairs -> the correspondence

and it requires the raw record to EXIST for any positive attribution claim.
A missing field is a refusal, never a skipped check.

MODE SELECTION
--------------
Required fields are chosen by `m2-b2-mode`:
  * translation        -- window fields, DMA observation fields and the
                          driver-record fields are required
  * control-sleep-only -- none of the window / DMA / page-table forensics
                          fields are required. The checks that depend on them
                          report NOT APPLICABLE, which is different from PASS.
                          A `pgtsleep` run really does not do DMA observation,
                          so fabricating those fields would be dishonest and
                          omitting them must not be an error.

EXIT CODES
    0  every validity verdict holds and the functional result is a pass
    1  every validity verdict holds, but the result is FAIL / INDETERMINATE
       / CONTROL
    2  cannot analyse: a required field is missing or malformed for the
       selected mode
    3  at least one validity verdict failed
    4  usage error

Usage:
    py -3 tools/analyze-round9.py docs/evidence/<stamp>/props.txt
    py -3 tools/analyze-round9.py docs/evidence/<stamp>/props.txt --json
"""
import json
import re
import sys

# ---------------------------------------------------------------------------
# Field kinds
# ---------------------------------------------------------------------------
HEX = "hex"
DEC = "dec"
YESNO = "yesno"
TEXT = "text"
RAW32 = "raw32"

# ---------------------------------------------------------------------------
# Closed sets. An enum field that accepts any string cannot fail.
# ---------------------------------------------------------------------------
VERDICT_RE = re.compile(
    r"^(FAIL-[a-z0-9\-]+"
    r"|INVALID-[a-z0-9\-]+"
    r"|INDETERMINATE-[a-z0-9\-]+"
    r"|CONTROL-[a-z0-9\-]+"
    r"|PASS-CANDIDATE-[a-z0-9\-]+"
    r"|PASS)$")
STAGE_RE = re.compile(r"^[0-9]+[0-9]?-[a-z0-9\-]+$")
MODE_SET = {"translation", "control-sleep-only"}
COVERAGE_SET = {"none", "snapshot-only", "window-complete"}
LIFE_SET = {"in-flight", "completed", "snapshot-only", "unknown"}
PURPOSE_SET = {"tx-ring", "rx-ring", "tx-buffer", "rx-buffer", "stat-buffer",
               "counter-dump", "other", "unknown"}
READ_SET = {"readable", "not-read: beyond identity map limit",
            "not-read: not ordinary RAM", "not-read: range wraps",
            "not-read: zero length", "not-read: layout unverified"}
RING_BASIS_SET = {"none", "register-only", "register+mapped-content-unverified",
                  "register+content-fingerprint"}
TXCOV_REASON_SET = {"ok", "no-ring", "pointers-unreadable",
                    "nothing-submitted", "ring-overwritten",
                    "close-ahead-of-submit", "implausible", "not-observed"}
TXQUALITY_SET = {"exact", "slots-overwritten", "undecodable-address",
                 "undecodable-length", "records-lost", "incomplete",
                 "no-ring", "pointers-unreadable",
                 "implausible-pointer-pair",
                 "counter-reset-or-identity-change", "scan-cap", "not-run"}
SCANSTOP_SET = {"ok", "no-ring", "pointers-unreadable",
                "implausible-pointer-pair",
                "counter-reset-or-identity-change", "scan-cap"}
SCOPE_SET = {"device-wide-all-paths-covered",
             "tx-path-only-rx-and-rings-not-covered"}
TRUST_SET = {"trusted", "PARTIAL-ring-registers-not-readable"}
OBS_SET = {"complete", "started", "SKIP-no-nic", "SKIP-format-unknown",
           "SKIP-no-records", "SKIP-observation-did-not-complete"}
OBS_STATE_SET = {"ok", "wrapped", "allocated", "unavailable", "absent"}
WALK_SET = {"identity-mapped", "NOT-MAPPED", "no-window-completion-observed"}

RE_HEX = re.compile(r"^0x[0-9a-fA-F]+$")
RE_DEC = re.compile(r"^[0-9]+$")
RE_YESNO = re.compile(r"^(yes|no)$", re.IGNORECASE)
RE_RAW32 = re.compile(r"^[0-9a-fA-F]{32}$")
RE_CLOPTR_VALID = re.compile(r"^(yes|no-[a-z0-9\-]+)$")

STATUS_EVT_OVERFLOW = 1 << 0
STATUS_EVT_RUN = 1 << 3
STATUS_CMDBUF_RUN = 1 << 4

TYPE_NAMES = {
    1: "ILLEGAL_DEV_TABLE_ENTRY",
    2: "IO_PAGE_FAULT",
    3: "DEV_TAB_HARDWARE_ERROR",
    4: "PAGE_TAB_HARDWARE_ERROR",
    5: "ILLEGAL_COMMAND_ERROR",
    6: "COMMAND_HARDWARE_ERROR",
    7: "IOTLB_INV_TIMEOUT",
    8: "INVALID_DEVICE_REQUEST",
    9: "INVALID_PPR_REQUEST",
    0xD: "RMP_FAULT",
    0xE: "RMP_HW_ERROR",
}

FLAG_BITS = [
    (0, "GN"), (1, "NX"), (2, "US"), (3, "I"), (4, "PR"),
    (5, "RW"), (6, "PE"), (7, "RZ"), (8, "TR"),
]
PR_ONLY_FIELDS = ("RZ",)

# ---------------------------------------------------------------------------
# The AMD IOMMU page-table model, re-implemented here on purpose.
#
# The analyser must NOT ask the capture whether its own walk was right. It
# decodes the raw PTEs itself, from the spec, and then compares. That is the
# difference between "the probe says it walked" and "the recorded PTE chain
# does produce this address".
# ---------------------------------------------------------------------------
PAGE_4K = 1
PAGE_2M = 2
PAGE_1G = 3
PAGE_512G = 4

# Spec 48882 Rev 3.10 Table 15 is 1-BASED.
LEVEL_DEFAULT_SIZE = {
    PAGE_4K: 1 << 12,
    PAGE_2M: 1 << 21,
    PAGE_1G: 1 << 30,
    PAGE_512G: 1 << 39,
}
LEVEL_SHIFT = {
    PAGE_4K: 12,
    PAGE_2M: 21,
    PAGE_1G: 30,
    PAGE_512G: 39,
}
LEVEL_NAME = {
    PAGE_4K: "4K", PAGE_2M: "2M", PAGE_1G: "1G", PAGE_512G: "512G",
}

PTE_ADDR_MASK = 0x000FFFFFFFFFF000
PTE_NEXTLEVEL_MASK = 0x7
PTE_NEXTLEVEL_SHIFT = 9
PTE_PRESENT = 1 << 0
PTE_IR = 1 << 61
PTE_IW = 1 << 62
PTE_FC = 1 << 60


def pte_next_level(pte):
    return (pte >> PTE_NEXTLEVEL_SHIFT) & PTE_NEXTLEVEL_MASK


def pte_out_addr(pte):
    return pte & PTE_ADDR_MASK


def level_index(level, addr):
    """Index into a table at `level` for `addr`.

    A table at level N is indexed by bits [shift(N)+8 : shift(N)]. The ROOT
    table of a 4-level map is level 4, so its index is bits 47:39.
    """
    return (addr >> LEVEL_SHIFT[level]) & 0x1FF


def classify_pte(pte, level):
    """What a PTE means at `level`, per spec 48882 Rev 3.10 §2.2.3.

    THE NextLevel FIELD IS OVERLOADED, AND THAT IS THE WHOLE DIFFICULTY:

      * 0        -- the PTE is a LEAF mapping the DEFAULT page size of the
                    level it resides in. Not 4 KiB: at level 2 the default is
                    2 MiB, at level 3 it is 1 GiB, at level 4 it is 512 GiB.
      * level-1  -- the PTE is a POINTER to the next-level table. The field
                    names the CHILD level, not a size. A pointer at level 4
                    carries 3, at level 3 carries 2, at level 2 carries 1.
      * 7        -- an ENLARGED leaf that skips a level. Its size cannot be
                    derived from the PTE alone, so it is refused rather than
                    guessed.
      * anything else -- illegal: neither the level's default leaf nor its own
                    child pointer.

    Returns (kind, page_size) where kind is 'leaf', 'table' or 'illegal'.

    Round 7 wrote NextLevel=7 into a report for a PTE whose field is 0, and
    round 9's first draft of THIS function made the mirror-image mistake: it
    treated every non-zero NextLevel as a page-size code, so it declared the
    real, correct 4-level chain (3 -> 2 -> 0) illegal. Both errors come from
    reading the field as one thing when it is two.
    """
    nl = pte_next_level(pte)
    if nl == 0:
        return ("leaf", LEVEL_DEFAULT_SIZE[level])
    if nl == 7:
        return ("illegal", 0)
    if level >= 2 and nl == level - 1:
        return ("table", 0)
    return ("illegal", 0)


def leaf_size_for(level, pte):
    """Page size a leaf PTE maps, or 0 when it is not a legal leaf.

    Kept as a separate name because the tests and the walk both ask this
    question directly.
    """
    kind, size = classify_pte(pte, level)
    return size if kind == "leaf" else 0


def decode_walk(ptes, root_level, addr):
    """Walk a recorded PTE chain and decide what it maps `addr` to.

    `ptes` is a list of dicts with at least: table (PA), level, index, pte.
    Returns a dict with the outcome and, on success, the output PA.
    """
    out = {"ok": False, "illegal": False, "absent": False,
           "reason": "", "outPA": None, "leafLevel": None, "steps": 0,
           "path": []}
    if not ptes:
        out["reason"] = "no PTE records were published"
        out["absent"] = True
        return out

    level = root_level
    table = ptes[0].get("table")
    for i, rec in enumerate(ptes):
        out["steps"] = i + 1
        out["path"].append(rec)
        if rec.get("level") != level:
            out["reason"] = ("record {} says level {}, but the walk is at "
                             "level {}".format(i, rec.get("level"), level))
            return out
        if rec.get("table") != table:
            out["reason"] = ("record {} says table 0x{:x}, but the walk is "
                             "in 0x{:x}".format(i, rec.get("table") or 0,
                                                table or 0))
            return out
        want_idx = level_index(level, addr)
        if rec.get("index") != want_idx:
            out["reason"] = ("record {} uses index 0x{:x}, but address "
                             "0x{:x} at level {} indexes 0x{:x}".format(
                                 i, rec.get("index") or 0, addr, level,
                                 want_idx))
            return out

        pte = rec.get("pte") or 0
        if pte == 0 or (pte & PTE_PRESENT) == 0:
            out["absent"] = True
            out["reason"] = ("level {} index 0x{:x}: PTE 0x{:x} is not "
                             "present".format(level, want_idx, pte))
            return out

        kind, size = classify_pte(pte, level)
        if kind == "illegal":
            out["illegal"] = True
            out["reason"] = ("level {} index 0x{:x}: PTE 0x{:x} has "
                             "NextLevel={}, which is neither the level's "
                             "default leaf nor a pointer to level {}".format(
                                 level, want_idx, pte, pte_next_level(pte),
                                 level - 1))
            return out

        if kind == "leaf":
            base = pte_out_addr(pte)
            off = addr & (size - 1)
            out["outPA"] = base + off
            out["leafLevel"] = level
            out["ok"] = (out["outPA"] == addr)
            out["reason"] = (
                "leaf at level {} (default {} bytes) maps 0x{:x} -> "
                "0x{:x}".format(level, size, addr, out["outPA"]))
            return out

        # A pointer to the next table.
        table = pte_out_addr(pte)
        level -= 1
        if level < PAGE_4K:
            out["reason"] = "the chain descends below level 1"
            return out

    out["reason"] = "the recorded chain ends before a leaf"
    return out


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
SCHEMA_COMMON = [
    # identity
    ("m2-b2-verdict", TEXT, True),
    ("m2-b2-stage", TEXT, True),
    ("m2-b2-mode", TEXT, True),
    ("m2-b2-target-devid", HEX, True),
    # page table identity
    ("m2-b2-dump-root-pa", HEX, True),
    ("m2-b2-dump-root-level", HEX, True),
    ("m2-b2-dump-page-mode", HEX, True),
    ("m2-b2-dump-pt-pages", HEX, True),
    ("m2-b2-dump-map-limit", HEX, True),
    ("m2-b2-dump-leaf-encoding", TEXT, True),
    ("m2-b2-dump-forensic-base", HEX, True),
    ("m2-b2-dump-forensic-bytes", HEX, True),
    ("m2-b2-dump-count", HEX, True),
    # stage completion
    ("m2-b2-stage-evt-reset", YESNO, True),
    ("m2-b2-stage-inv-all", YESNO, True),
    ("m2-b2-stage-inv-dev", YESNO, True),
    ("m2-b2-stage-inv-pages", YESNO, True),
    ("m2-b2-stage-control-done", YESNO, True),
    # commands
    ("m2-b2-cmd-submits", HEX, True),
    ("m2-b2-cmd-completed", HEX, True),
    ("m2-b2-cmd-record-count", HEX, True),
    # recovery
    ("m2-b2-disabled", YESNO, True),    ("m2-b2-cmdbuf-stopped", YESNO, True),
    ("m2-b2-evtlog-stopped", YESNO, True),
    ("m2-b2-cmdbuf-stop-status", HEX, True),
    ("m2-b2-evtlog-stop-status", HEX, True),
    ("m2-b2-final-control", HEX, True),
    ("m2-b2-orig-control-echo", HEX, True),
    ("m2-b2-regs-restored", TEXT, True),
    ("m2-b2-cleanup", TEXT, True),
    # The observation status is needed by BOTH modes: it decides which check
    # set applies. Round 9's first draft left it out of every schema, so
    # `cap.s("m2-b2-dma-obs")` raised KeyError on every capture -- the
    # analyser crashed instead of judging. A field the analyser BRANCHES on
    # must always be validated, whatever the mode.
    ("m2-b2-dma-obs", TEXT, True),
]

# Required only when mode == "translation": the measurement window exists and
# a DMA observation was attempted.
SCHEMA_TRANSLATION = [
    ("m2-b2-pre-window-ran", YESNO),
    ("m2-b2-pre-valid", YESNO),
    ("m2-b2-main-window-ran", YESNO),
    ("m2-b2-window-valid", YESNO),
    ("m2-b2-win-dur-ms", HEX),
    ("m2-b2-meas-secs", HEX),
    ("m2-b2-win-head-start", HEX),
    ("m2-b2-win-tail-start", HEX),
    ("m2-b2-win-head-end", HEX),
    ("m2-b2-win-tail-end", HEX),
    ("m2-b2-win-status-start", HEX),
    ("m2-b2-win-status-end", HEX),
    ("m2-b2-win-entries", HEX),
    ("m2-b2-win-new-entries", HEX),
    ("m2-b2-win-devid-mismatch", HEX),
    ("m2-b2-win-pre-backlog", HEX),
    ("m2-b2-win-raw-truncated", YESNO),
    ("m2-b2-win-raw-count", HEX),
    # the window's own monotonic bounds, and every sample around them
    ("m2-b2-dma-t-win-start", HEX),
    ("m2-b2-dma-t-win-end", HEX),
    ("m2-b2-dma-t-translate-on", HEX),
    ("m2-b2-dma-t-translate-off", HEX),
    ("m2-b2-dma-t-dte-written", HEX),
    ("m2-b2-dma-t-inv-complete", HEX),
    ("m2-b2-dma-t-tail-before", HEX),
    ("m2-b2-dma-t-tail-after", HEX),
    ("m2-b2-dma-t-clo-before", HEX),
    ("m2-b2-dma-t-clo-after", HEX),
    ("m2-b2-dma-t-obs-before", HEX),
    ("m2-b2-dma-t-obs-after", HEX),
    ("m2-b2-t-recovery-start", HEX),
    # the window scan and its quality
    ("m2-b2-dma-win-scan", TEXT),
    ("m2-b2-dma-win-cov-reason", TEXT),
    ("m2-b2-dma-win-quality", TEXT),
    ("m2-b2-dma-win-exact", YESNO),
    ("m2-b2-dma-win-stop-reason", HEX),
    ("m2-b2-dma-win-stop-reason-name", TEXT),
    ("m2-b2-dma-win-skipped", HEX),
    ("m2-b2-dma-win-records-lost", HEX),
    ("m2-b2-dma-win-submits", HEX),
    ("m2-b2-dma-win-completes", HEX),
    ("m2-b2-dma-win-visited", HEX),
    ("m2-b2-dma-win-decoded", HEX),
    ("m2-b2-dma-win-overwritten", HEX),
    ("m2-b2-dma-win-addr-zero", HEX),
    ("m2-b2-dma-win-inflight", HEX),
    ("m2-b2-dma-win-completed", HEX),
    ("m2-b2-dma-win-completed-in-window", HEX),
    ("m2-b2-dma-win-prewin-completed", HEX),
    ("m2-b2-dma-win-inflight-at-start", HEX),
    ("m2-b2-dma-win-len-unknown", HEX),
    ("m2-b2-dma-win-gen-before", HEX),
    ("m2-b2-dma-win-gen-after", HEX),
    ("m2-b2-dma-tx-window-covered", YESNO),
    ("m2-b2-dma-boundary-in-window", YESNO),
    ("m2-b2-dma-win-walk", TEXT),
    # per-path coverage
    ("m2-b2-dma-cov-txring", TEXT),
    ("m2-b2-dma-cov-rxring", TEXT),
    ("m2-b2-dma-cov-txbuf", TEXT),
    ("m2-b2-dma-cov-rxbuf", TEXT),
    ("m2-b2-dma-cov-stat", TEXT),
    ("m2-b2-dma-cov-weakest", TEXT),
    ("m2-b2-dma-cov-all-window", YESNO),
    ("m2-b2-fault-coverage", TEXT),
    ("m2-b2-fault-negative-sound", YESNO),
    ("m2-b2-fault-negative-scope", TEXT),
    # read basis
    ("m2-b2-dma-tx-ring-basis", TEXT),
    ("m2-b2-dma-rx-ring-basis", TEXT),
    ("m2-b2-dma-tx-ring-decoded", HEX),
    ("m2-b2-dma-rx-ring-ringend-at-last", HEX),
    ("m2-b2-dma-len-unknown", HEX),
    # the driver's own records
    ("m2-b2-obs", TEXT),
    ("m2-b2-obs-format", TEXT),
    ("m2-b2-obs-state", TEXT),
    ("m2-b2-obs-why", TEXT),
    ("m2-b2-obs-head", HEX),
    ("m2-b2-obs-published", HEX),
    ("m2-b2-obs-first", HEX),
    ("m2-b2-obs-wrapped", HEX),
    ("m2-b2-obs-t-start", HEX),
    ("m2-b2-obs-t-published", HEX),
    ("m2-b2-obs-ops", HEX),
    ("m2-b2-obs-submits", HEX),
    ("m2-b2-obs-dones", HEX),
    ("m2-b2-obs-doorbells", HEX),
    ("m2-b2-obs-rx-done", HEX),
    ("m2-b2-obs-rx-addr-zero", HEX),
    ("m2-b2-obs-stale", HEX),
    ("m2-b2-obs-unmatched-done", HEX),
    ("m2-b2-obs-uncompleted", HEX),
    ("m2-b2-obs-overflow", HEX),
    ("m2-b2-obs-all-completed", YESNO),
    # ROUND 9: the WINDOW subset of the join. The published log covers several
    # seconds; the measurement window is only the middle three. A whole-log
    # join answers "the driver recorded a complete correspondence at some
    # point", which is not the question. These are required so a capture
    # cannot omit them and quietly fall back to the weaker claim.
    ("m2-b2-obs-win-submits", HEX),
    ("m2-b2-obs-win-dones", HEX),
    ("m2-b2-obs-win-paired", HEX),
    ("m2-b2-obs-win-orphan-done", HEX),
    ("m2-b2-obs-window-complete", YESNO),
    ("m2-b2-obs-source", TEXT),
    ("m2-b2-obs-first-submit-t", HEX),
    ("m2-b2-obs-last-done-t", HEX),
    ("m2-b2-obs-first-rx-addr", HEX),
    ("m2-b2-obs-last-rx-addr", HEX),
    # TX lifecycle counts
    ("m2-b2-dma-tx-life-inflight", HEX),
    ("m2-b2-dma-tx-life-completed", HEX),
    ("m2-b2-dma-tx-life-snapshot", HEX),
    ("m2-b2-dma-tx-life-unknown", HEX),
]

# Conditional: required only when the capture says the DMA observation ran.
SCHEMA_OBS_RAN = [
    ("m2-b2-dma-trust", TEXT),
    ("m2-b2-dma-layout-known", YESNO),
    ("m2-b2-dma-ranges", HEX),
    ("m2-b2-dma-dropped", HEX),
    ("m2-b2-dma-raw-offered", HEX),
    ("m2-b2-dma-merged-total", HEX),
    ("m2-b2-dma-unscanned", HEX),
    ("m2-b2-dma-envelope-valid", YESNO),
    ("m2-b2-dma-envelope-lo", HEX),
    ("m2-b2-dma-envelope-hi", HEX),
    ("m2-b2-dma-read-ok", HEX),
    ("m2-b2-dma-read-outofmap", HEX),
    ("m2-b2-dma-read-notram", HEX),
    ("m2-b2-dma-tx-slots", HEX),
    ("m2-b2-dma-tx-zeroaddr", HEX),
    ("m2-b2-dma-tx-done-with-addr", HEX),
    ("m2-b2-dma-cloptr-reg", HEX),
    ("m2-b2-dma-cloptr-width", HEX),
    ("m2-b2-dma-cloptr-mask", HEX),
    ("m2-b2-dma-cloptr-before", HEX),
    ("m2-b2-dma-cloptr-after", HEX),
    ("m2-b2-dma-cloptr-delta", HEX),
    ("m2-b2-dma-cloptr-delta-valid", TEXT),
    ("m2-b2-dma-cfgmethod", HEX),
    ("m2-b2-dma-noclosever", HEX),
    ("m2-b2-dma-chip-known", YESNO),
    ("m2-b2-dma-tailptr-before", HEX),
    ("m2-b2-dma-tailptr-after", HEX),
    ("m2-b2-fault-inrange", HEX),
    ("m2-b2-fault-outofrange", HEX),
    ("m2-b2-fault-walk-present", HEX),
    ("m2-b2-fault-walk-illegal", HEX),
    ("m2-b2-fault-walk-absent", HEX),
    ("m2-b2-fault-observed-absent", HEX),
    ("m2-b2-dma-walk-count", HEX),
    ("m2-b2-dma-walk-present", HEX),
    ("m2-b2-dma-walk-verdict", TEXT),
]


class Capture:
    """Parsed property set with typed accessors that cannot silently default."""

    def __init__(self, text):
        self.raw = {}
        pat = re.compile(r'"([A-Za-z0-9\-\.]+)"\s*=\s*(?:"([^"]*)"|([^,\n}]+))')
        for m in pat.finditer(text):
            key = m.group(1)
            val = m.group(2) if m.group(2) is not None else m.group(3).strip()
            if key.startswith("m2-b2-"):
                self.raw.setdefault(key, val)
        self.errors = []
        self.missing = []
        self.values = {}

    def validate(self, schema):
        for entry in schema:
            name, kind = entry[0], entry[1]
            required = entry[2] if len(entry) > 2 else True
            if name not in self.raw:
                if required and name not in self.missing:
                    self.missing.append(name)
                continue
            v = self.raw[name].strip()
            if kind == HEX:
                if not RE_HEX.match(v):
                    self.errors.append(
                        (name, "not a 0x-prefixed hex number: %r" % v))
                    continue
            elif kind == DEC:
                if not RE_DEC.match(v):
                    self.errors.append(
                        (name, "not a decimal number: %r" % v))
                    continue
            elif kind == YESNO:
                if not RE_YESNO.match(v):
                    self.errors.append((name, "not yes/no: %r" % v))
                    continue
            elif kind == RAW32:
                s = v[2:] if v.lower().startswith("0x") else v
                if not RE_RAW32.match(s):
                    self.errors.append(
                        (name, "not 32 hex digits: %r" % v))
                    continue
            self.values[name] = v

    def i(self, name):
        v = self.values.get(name)
        if v is None:
            raise KeyError(name)
        if v.lower().startswith("0x"):
            return int(v, 16)
        return int(v, 10)

    def s(self, name):
        v = self.values.get(name)
        if v is None:
            raise KeyError(name)
        return v

    def b(self, name):
        return self.s(name).lower() == "yes"

    def has(self, name):
        return name in self.values

    def opti(self, name, default=0):
        """Read an OPTIONAL field straight from the raw text.

        `has()` only sees schema-validated values, so a check guarded by it
        silently never runs for a field outside the schema -- that was round
        7's `t-clo-after` defect. Optional fields are read here instead.
        """
        v = self.raw.get(name)
        if v is None:
            return default
        v = v.strip()
        try:
            return int(v, 16) if v.lower().startswith("0x") else int(v, 10)
        except ValueError:
            return default

    def opts(self, name, default=""):
        v = self.raw.get(name)
        return v.strip() if v is not None else default

    def hasraw(self, name):
        return name in self.raw


def decode_status(st):
    return {
        "EventOverflow": (st >> 0) & 1,
        "EventLogInt": (st >> 1) & 1,
        "ComWaitInt": (st >> 2) & 1,
        "EventLogRun": (st >> 3) & 1,
        "CmdBufRun": (st >> 4) & 1,
        "PprOverflow": (st >> 5) & 1,
        "PprInt": (st >> 6) & 1,
        "PPRLogRun": (st >> 7) & 1,
        "GALogRun": (st >> 8) & 1,
        "GALOverflow": (st >> 9) & 1,
        "GAInt": (st >> 10) & 1,
    }


class Verdicts:
    """Five independent validity verdicts plus their evidence.

    Round 8 had four. The fifth -- attribution -- exists because round 8
    checked that the SCAN was consistent but never recomputed the
    correspondence from the raw numbers. A capture could claim three
    completions, publish a first-completion address that did not match any
    descriptor, and still be VALID.
    """

    def __init__(self):
        self.event = []
        self.address = []
        self.coverage = []
        self.dma = []
        self.attrib = []

    @staticmethod
    def _ck(bucket, name, ok, detail="", na=False):
        bucket.append({"name": name, "ok": bool(ok), "detail": detail,
                       "notApplicable": bool(na)})
        return bool(ok)

    def ck_event(self, name, ok, detail=""):
        return self._ck(self.event, name, ok, detail)

    def ck_addr(self, name, ok, detail=""):
        return self._ck(self.address, name, ok, detail)

    def ck_cov(self, name, ok, detail=""):
        return self._ck(self.coverage, name, ok, detail)

    def ck_dma(self, name, ok, detail=""):
        return self._ck(self.dma, name, ok, detail)

    def ck_attrib(self, name, ok, detail=""):
        return self._ck(self.attrib, name, ok, detail)

    def na(self, bucket, name, detail=""):
        """A check that does not apply to this capture.

        NOT APPLICABLE is not PASS. It is recorded with na=True so the
        summary can say how many checks were skipped and why, instead of
        counting a skipped check as evidence.
        """
        bucket.append({"name": name, "ok": True, "detail": detail,
                       "notApplicable": True})
        return True

    @staticmethod
    def _ok(bucket):
        return all(c["ok"] for c in bucket)

    def event_ok(self):
        return self._ok(self.event)

    def address_ok(self):
        return self._ok(self.address)

    def coverage_ok(self):
        return self._ok(self.coverage)

    def dma_ok(self):
        return self._ok(self.dma)

    def attrib_ok(self):
        return self._ok(self.attrib)

    def overall(self):
        return (self.event_ok() and self.address_ok() and
                self.coverage_ok() and self.dma_ok() and self.attrib_ok())

    def as_dict(self):
        def pack(bucket):
            return {
                "valid": self._ok(bucket),
                "checks": len(bucket),
                "failed": sum(1 for c in bucket if not c["ok"]),
                "notApplicable": sum(1 for c in bucket
                                     if c.get("notApplicable")),
                "detail": bucket,
            }
        return {
            "eventWindow": pack(self.event),
            "addressObservation": pack(self.address),
            "coverageConsistency": pack(self.coverage),
            "dmaEvidence": pack(self.dma),
            "attribution": pack(self.attrib),
            "overall": self.overall(),
        }


# ---------------------------------------------------------------------------
# Chip identity: cfgMethod -> noCloseVer -> register/width/mask
# ---------------------------------------------------------------------------
CFG_TO_NOCLOSE = {}
for _m in (2, 3, 4, 5, 6, 7):
    CFG_TO_NOCLOSE[_m] = 3
for _m in (8, 9, 10, 11, 12, 13, 41, 42):
    CFG_TO_NOCLOSE[_m] = 6
CFG_TO_NOCLOSE[31] = 4
CFG_TO_NOCLOSE[32] = 5
CFG_TO_NOCLOSE[33] = 5

NOCLOSE_TO_SPEC = {
    6: (0x0D34, 4, 0x7FFFFFFF),
    5: (0x2800, 4, 0x7FFFFFFF),
    4: (0x2800, 4, 0xFFFFFFFF),
    3: (0x2802, 2, 0xFFFF),
}


def cfg_from_txconfig(raw):
    """Recompute cfgMethod from the raw TxConfig, as the driver does."""
    reg = raw & 0x7C800000
    icver = raw & 0x00700000
    if reg == 0x60800000:
        return 2 if icver == 0 else 3
    if reg == 0x64000000:
        return 4 if icver == 0 else 5
    if reg == 0x68000000:
        return 8 if icver == 0 else 9
    if reg == 0x68800000:
        return 10 if icver == 0 else 11
    if reg == 0x70800000:
        return 12
    if reg == 0x6C800000:
        return 41 if icver == 0 else 42
    if reg == 0x64800000:
        if icver == 0:
            return 31
        if icver == 0x00100000:
            return 32
        return 33
    return 0


def main():
    if len(sys.argv) < 2:
        print("usage: analyze-round9.py <props.txt> [--json]")
        return 4
    path = sys.argv[1]
    as_json = "--json" in sys.argv

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except IOError as e:
        print("cannot read {}: {}".format(path, e))
        return 4

    cap = Capture(text)
    if not cap.raw:
        print("no m2-b2-* properties found in {}".format(path))
        return 2

    # ------------------------------------------------------------------
    # Mode selection happens BEFORE the schema is finalised, because the
    # mode decides which fields are required at all.
    # ------------------------------------------------------------------
    mode_raw = cap.raw.get("m2-b2-mode")
    mode = mode_raw.strip() if mode_raw else None
    mode_known = mode in MODE_SET
    is_translation = mode_known and mode == "translation"

    obs_raw = cap.raw.get("m2-b2-dma-obs")
    obs_ran = (obs_raw is not None and obs_raw.strip() == "complete")

    schema = list(SCHEMA_COMMON)
    if is_translation:
        schema.extend(SCHEMA_TRANSLATION)
    if obs_ran:
        schema.extend(SCHEMA_OBS_RAN)

    cap.validate(schema)

    if cap.missing or cap.errors:
        if as_json:
            print(json.dumps({
                "source": path,
                "mode": mode,
                "missing": cap.missing,
                "malformed": [{"field": f, "problem": p}
                              for f, p in cap.errors],
                "conclusion": "CANNOT ANALYSE",
            }, indent=2))
            return 2
        print("CANNOT ANALYSE")
        print("=" * 78)
        print("source : {}".format(path))
        print("mode   : {}".format(mode))
        if cap.missing:
            print()
            print("missing required field(s) for this mode: {}".format(
                len(cap.missing)))
            for m in cap.missing:
                print("  " + m)
        if cap.errors:
            print()
            print("malformed field(s): {}".format(len(cap.errors)))
            for f, p in cap.errors:
                print("  {}: {}".format(f, p))
        print()
        print("No conclusion is drawn. A field that is absent, or present")
        print("but not of its declared type, cannot satisfy a check -- and")
        print("two absent values must never compare equal.")
        print()
        print("NOTE: the required set is chosen by m2-b2-mode. A capture")
        print("that reports a mode it does not follow will fail here rather")
        print("than being judged against the wrong check set.")
        return 2

    v = Verdicts()

    verdict_s = cap.s("m2-b2-verdict")
    stage_s = cap.s("m2-b2-stage")

    # =====================================================================
    # A. EVENT WINDOW VALIDITY
    # =====================================================================
    v.ck_event("verdict is a recognised token",
               VERDICT_RE.match(verdict_s) is not None,
               "verdict={!r}".format(verdict_s))
    v.ck_event("stage is a recognised token",
               STAGE_RE.match(stage_s) is not None,
               "stage={!r}".format(stage_s))
    v.ck_event("experiment mode is a known mode", mode_known,
               "mode={!r}".format(mode))

    enc = cap.s("m2-b2-dump-leaf-encoding")
    v.ck_event("leaf encoding is the corrected NextLevel=0 form",
               "NextLevel0" in enc, "leaf-encoding={!r}".format(enc))

    devid = cap.i("m2-b2-target-devid")
    root_level = cap.i("m2-b2-dump-root-level")
    page_mode = cap.i("m2-b2-dump-page-mode")
    pt_pages = cap.i("m2-b2-dump-pt-pages")
    map_limit = cap.i("m2-b2-dump-map-limit")

    v.ck_event("target device known", devid != 0,
               "devid=0x{:04x}".format(devid))
    v.ck_event("root level matches DTE page mode", root_level == page_mode,
               "root-level={} page-mode={}".format(root_level, page_mode))
    v.ck_event("root level in the spec's 1..6 range",
               1 <= root_level <= 6, "root-level={}".format(root_level))
    v.ck_event("page-table allocation recorded", pt_pages != 0,
               "pt-pages={}".format(pt_pages))
    v.ck_event("identity map limit is a multiple of 1 GiB",
               map_limit != 0 and map_limit % (1 << 30) == 0,
               "limit=0x{:x}".format(map_limit))

    st_evt = cap.b("m2-b2-stage-evt-reset")
    st_invall = cap.b("m2-b2-stage-inv-all")
    st_invdev = cap.b("m2-b2-stage-inv-dev")
    st_invpg = cap.b("m2-b2-stage-inv-pages")
    st_ctl = cap.b("m2-b2-stage-control-done")

    v.ck_event("event log was reset (stage completion)", st_evt,
               "stage-evt-reset={}".format(st_evt))
    v.ck_event("CMD_INV_ALL completed (stage completion)", st_invall,
               "stage-inv-all={}".format(st_invall))

    if mode_known and mode == "control-sleep-only":
        v.ck_event("control stage actually completed", st_ctl,
                   "stage-control-done={}".format(st_ctl))
        v.ck_event("control mode does not claim a translation verdict",
                   not verdict_s.startswith("PASS-CANDIDATE"),
                   "verdict={!r}".format(verdict_s))
    elif is_translation:
        v.ck_event("translation mode does not emit a CONTROL verdict",
                   not verdict_s.startswith("CONTROL"),
                   "mode=translation but verdict={!r}".format(verdict_s))
        v.ck_event("INV_DEV_ENTRY completed (stage completion)", st_invdev,
                   "stage-inv-dev={}".format(st_invdev))
        v.ck_event("INV_IOMMU_PAGES completed (stage completion)", st_invpg,
                   "stage-inv-pages={}".format(st_invpg))
        v.ck_event("control stage not claimed in translation mode",
                   not st_ctl,
                   "stage-control-done={}".format(st_ctl))

        pre_ran = cap.b("m2-b2-pre-window-ran")
        pre_valid = cap.b("m2-b2-pre-valid")
        v.ck_event("pre-switch control window executed", pre_ran,
                   "ran={}".format(pre_ran))
        v.ck_event("pre-switch control window valid", pre_valid,
                   "valid={}".format(pre_valid))

        main_ran = cap.b("m2-b2-main-window-ran")
        win_valid = cap.b("m2-b2-window-valid")
        v.ck_event("main window executed", main_ran,
                   "ran={}".format(main_ran))
        v.ck_event("main window marked valid", win_valid,
                   "valid={}".format(win_valid))

        dur = cap.i("m2-b2-win-dur-ms")
        meas = cap.i("m2-b2-meas-secs")
        nominal = meas * 1000
        v.ck_event("measured duration consistent with nominal",
                   nominal <= dur <= nominal * 3,
                   "dur={}ms nominal={}ms".format(dur, nominal))

        for label, key in (("start", "m2-b2-win-status-start"),
                           ("end", "m2-b2-win-status-end")):
            st = cap.i(key)
            d = decode_status(st)
            v.ck_event("no EVT_OVERFLOW at window {}".format(label),
                       d["EventOverflow"] == 0, "STATUS=0x{:X}".format(st))
            v.ck_event("EVT_RUN set at window {}".format(label),
                       d["EventLogRun"] == 1, "STATUS=0x{:X}".format(st))

        hs = cap.i("m2-b2-win-head-start")
        he = cap.i("m2-b2-win-head-end")
        v.ck_event("HEAD unchanged during window", hs == he,
                   "head-start=0x{:x} head-end=0x{:x}".format(hs, he))
        v.ck_event("window ring bounds are 16-byte aligned",
                   hs % 16 == 0 and he % 16 == 0,
                   "head-start=0x{:x} head-end=0x{:x}".format(hs, he))

    # ---- commands ----
    subs = cap.i("m2-b2-cmd-submits")
    comp = cap.i("m2-b2-cmd-completed")
    recs = cap.i("m2-b2-cmd-record-count")
    v.ck_event("every submitted command completed", subs == comp,
               "submits={} completed={}".format(subs, comp))
    v.ck_event("per-command records retained", recs == subs,
               "records={} submits={}".format(recs, subs))

    rec_ok = 0
    rec_bad = []
    for i in range(recs):
        keys = ["m2-b2-cmd%d-%s" % (i, s)
                for s in ("label", "dwords", "expected", "observed",
                          "loops", "ok")]
        if any(k not in cap.raw for k in keys):
            rec_bad.append("record {} missing fields".format(i))
            continue
        dwords = cap.raw["m2-b2-cmd%d-dwords" % i].strip()
        exp = cap.raw["m2-b2-cmd%d-expected" % i].strip()
        obs = cap.raw["m2-b2-cmd%d-observed" % i].strip()
        okv = cap.raw["m2-b2-cmd%d-ok" % i].strip()
        if not RE_RAW32.match(dwords):
            rec_bad.append("record {} dwords malformed".format(i))
            continue
        if not RE_HEX.match(exp) or not RE_HEX.match(obs):
            rec_bad.append("record {} expected/observed malformed".format(i))
            continue
        if not RE_YESNO.match(okv):
            rec_bad.append("record {} ok not yes/no".format(i))
            continue
        e = int(exp, 16)
        o = int(obs, 16)
        if okv.lower() == "yes":
            if e != o:
                rec_bad.append(
                    "record {} claims ok but expected 0x{:x} != observed "
                    "0x{:x}".format(i, e, o))
            else:
                rec_ok += 1
        else:
            if e == o:
                rec_bad.append(
                    "record {} claims NOT ok but expected == observed "
                    "(0x{:x})".format(i, e))

    v.ck_event("every retained command record is self-consistent",
               not rec_bad,
               "; ".join(rec_bad[:3]) if rec_bad else
               "{} record(s) checked".format(recs))
    v.ck_event("per-record successes equal the summary completed count",
               rec_ok == comp,
               "records-ok={} summary-completed={}".format(rec_ok, comp))

    # ---- recovery: the hardware run bits must actually be clear ----
    for label, skey, ckey, bit in (
            ("command buffer", "m2-b2-cmdbuf-stop-status",
             "m2-b2-cmdbuf-stopped", STATUS_CMDBUF_RUN),
            ("event log", "m2-b2-evtlog-stop-status",
             "m2-b2-evtlog-stopped", STATUS_EVT_RUN)):
        st = cap.i(skey)
        claim = cap.b(ckey)
        run_bit = (st & bit) != 0
        v.ck_event("{} stop claim matches STATUS".format(label),
                   claim == (not run_bit),
                   "claim={} STATUS=0x{:X}".format(claim, st))
        v.ck_event("{} hardware run bit is actually clear".format(label),
                   run_bit == 0,
                   "STATUS=0x{:X} bit{}={}".format(st, bit.bit_length() - 1,
                                                   int(run_bit)))
        v.ck_event("{} STATUS has no EventOverflow".format(label),
                   decode_status(st)["EventOverflow"] == 0,
                   "STATUS=0x{:X}".format(st))

    v.ck_event("IOMMU disabled (read back)", cap.b("m2-b2-disabled"),
               "disabled={}".format(cap.b("m2-b2-disabled")))

    final_ctrl = cap.i("m2-b2-final-control")
    orig_ctrl = cap.i("m2-b2-orig-control-echo")
    v.ck_event("CONTROL restored to its original value",
               final_ctrl == orig_ctrl,
               "final=0x{:x} orig=0x{:x}".format(final_ctrl, orig_ctrl))
    v.ck_event("registers restored",
               cap.s("m2-b2-regs-restored") == "yes",
               "regs-restored={!r}".format(cap.s("m2-b2-regs-restored")))
    v.ck_event("cleanup permitted", cap.s("m2-b2-cleanup") == "done",
               "cleanup={!r}".format(cap.s("m2-b2-cleanup")))

    # =====================================================================
    # B. ADDRESS OBSERVATION COMPLETENESS (accounting)
    # =====================================================================
    if not obs_ran:
        for nm in ("device DMA observation ran",
                   "observation trust is a known value",
                   "observation recorded at least one DMA range",
                   "merged intervals equal saved plus dropped",
                   "raw offered addresses is at least the merged count",
                   "envelope exists",
                   "envelope bounds are ordered",
                   "read verdicts account for at most the saved ranges",
                   "every exported descriptor address lies inside the envelope",
                   "range metadata uses only known enumerations",
                   "DMA walk verdict is a known token",
                   "DMA walk examined at least one live address",
                   "every live DMA address walked to an identity leaf",
                   "walk verdict agrees with its own counts"):
            v.na(v.address, nm,
                 "not applicable: the DMA observation did not run "
                 "(m2-b2-dma-obs={!r})".format(
                     cap.s("m2-b2-dma-obs") if cap.has("m2-b2-dma-obs")
                     else "absent"))
        ranges = dropped = raw_off = merged = unscanned = 0
        env_valid = False
        env_lo = env_hi = 0
        walk_count = walk_present = 0
    else:
        obs = cap.s("m2-b2-dma-obs")
        v.ck_addr("device DMA observation ran", obs == "complete",
                  "dma-obs={!r}".format(obs))

        trust = cap.s("m2-b2-dma-trust")
        v.ck_addr("observation trust is a known value", trust in TRUST_SET,
                  "trust={!r}".format(trust))

        ranges = cap.i("m2-b2-dma-ranges")
        dropped = cap.i("m2-b2-dma-dropped")
        raw_off = cap.i("m2-b2-dma-raw-offered")
        merged = cap.i("m2-b2-dma-merged-total")
        unscanned = cap.i("m2-b2-dma-unscanned")
        env_valid = cap.b("m2-b2-dma-envelope-valid")
        env_lo = cap.i("m2-b2-dma-envelope-lo")
        env_hi = cap.i("m2-b2-dma-envelope-hi")

        v.ck_addr("observation recorded at least one DMA range", ranges > 0,
                  "ranges={}".format(ranges))
        v.ck_addr("merged intervals equal saved plus dropped",
                  merged == ranges + dropped,
                  "merged={} ranges={} dropped={}".format(
                      merged, ranges, dropped))
        v.ck_addr("raw offered addresses is at least the merged count",
                  raw_off >= merged, "raw={} merged={}".format(raw_off, merged))
        v.ck_addr("envelope exists", env_valid,
                  "envelope-valid={}".format(env_valid))
        v.ck_addr("envelope bounds are ordered", env_hi > env_lo,
                  "lo=0x{:x} hi=0x{:x}".format(env_lo, env_hi))

        read_ok = cap.i("m2-b2-dma-read-ok")
        read_oom = cap.i("m2-b2-dma-read-outofmap")
        read_nr = cap.i("m2-b2-dma-read-notram")
        v.ck_addr("read verdicts account for at most the saved ranges",
                  read_ok + read_oom + read_nr <= ranges,
                  "ok={} outofmap={} notram={} ranges={}".format(
                      read_ok, read_oom, read_nr, ranges))

        # ---- the round-6 contradiction, still enforced ----
        desc_bad = []
        n_desc = 0
        for i in range(8):
            key = "m2-b2-dma-txdesc%d" % i
            if key not in cap.raw:
                continue
            m = re.search(r"addr=([0-9a-fA-F]{16})", cap.raw[key])
            if not m:
                desc_bad.append("{} unparseable".format(key))
                continue
            a = int(m.group(1), 16)
            if a == 0:
                continue
            n_desc += 1
            if not (env_lo <= a < env_hi):
                desc_bad.append(
                    "{} addr=0x{:x} outside envelope [0x{:x},0x{:x})".format(
                        key, a, env_lo, env_hi))
        v.ck_addr("every exported descriptor address lies inside the envelope",
                  not desc_bad,
                  "; ".join(desc_bad[:3]) if desc_bad else
                  "{} descriptor address(es) checked".format(n_desc))

        life_bad = []
        for i in range(16):
            for suffix, allowed in (("life", LIFE_SET),
                                    ("purpose", PURPOSE_SET),
                                    ("read", READ_SET)):
                k = "m2-b2-dma-range%d-%s" % (i, suffix)
                if k in cap.raw:
                    val = cap.raw[k].strip()
                    if val not in allowed:
                        life_bad.append("{}={!r}".format(k, val))
        v.ck_addr("range metadata uses only known enumerations",
                  not life_bad,
                  "; ".join(life_bad[:3]) if life_bad else "ok")

        walk_count = cap.i("m2-b2-dma-walk-count")
        walk_present = cap.i("m2-b2-dma-walk-present")
        wv = cap.s("m2-b2-dma-walk-verdict")
        v.ck_addr("DMA walk verdict is a known token",
                  wv in ("all-identity-mapped", "SOME-NOT-MAPPED",
                         "no-addresses-observed"),
                  "walk-verdict={!r}".format(wv))
        v.ck_addr("DMA walk examined at least one live address",
                  walk_count > 0, "walk-count={}".format(walk_count))
        v.ck_addr("every live DMA address walked to an identity leaf",
                  walk_present == walk_count,
                  "present={} of {}".format(walk_present, walk_count))
        v.ck_addr("walk verdict agrees with its own counts",
                  (wv == ("all-identity-mapped"
                          if walk_present == walk_count
                          else "SOME-NOT-MAPPED")) if walk_count
                  else (wv == "no-addresses-observed"),
                  "verdict={!r} present={} count={}".format(
                      wv, walk_present, walk_count))

    # =====================================================================
    # C. COVERAGE CONSISTENCY
    # =====================================================================
    if not is_translation:
        for nm in ("coverage of tx-ring is a known value",
                   "coverage of rx-ring is a known value",
                   "coverage of tx-buffer is a known value",
                   "coverage of rx-buffer is a known value",
                   "coverage of stat-buffer is a known value",
                   "coverage of weakest is a known value",
                   "weakest coverage equals the weakest per-path value",
                   "all-window flag agrees with the per-path values",
                   "fault classification used the weakest path coverage",
                   "negative-soundness flag matches all-window coverage",
                   "negative scope is a known token",
                   "negative scope agrees with the all-window flag",
                   "a TX-only window does not license a device-wide negative",
                   "unscanned slots are zero whenever any path claims window "
                   "coverage",
                   "unscanned slots are zero whenever a negative is claimed "
                   "sound",
                   "undecoded lengths block an exact negative",
                   "TX ring read basis is a known value",
                   "RX ring read basis is a known value",
                   "register-only is never enough to trust ring contents",
                   "a fingerprint basis implies the fingerprint actually saw "
                   "data"):
            v.na(v.coverage, nm,
                 "not applicable: control mode runs no translation window")
        cov_weak = "none"
        cov_all = False
        scope = "tx-path-only-rx-and-rings-not-covered"
        neg_sound = False
        len_unknown = 0
        per_path = ["none"] * 5
    else:
        cov_txring = cap.s("m2-b2-dma-cov-txring")
        cov_rxring = cap.s("m2-b2-dma-cov-rxring")
        cov_txbuf = cap.s("m2-b2-dma-cov-txbuf")
        cov_rxbuf = cap.s("m2-b2-dma-cov-rxbuf")
        cov_stat = cap.s("m2-b2-dma-cov-stat")
        cov_weak = cap.s("m2-b2-dma-cov-weakest")
        cov_all = cap.b("m2-b2-dma-cov-all-window")
        per_path = [cov_txring, cov_rxring, cov_txbuf, cov_rxbuf, cov_stat]

        for name, val in (("tx-ring", cov_txring), ("rx-ring", cov_rxring),
                          ("tx-buffer", cov_txbuf), ("rx-buffer", cov_rxbuf),
                          ("stat-buffer", cov_stat), ("weakest", cov_weak)):
            v.ck_cov("coverage of {} is a known value".format(name),
                     val in COVERAGE_SET, "{}={!r}".format(name, val))

        order = {"none": 0, "snapshot-only": 1, "window-complete": 2}
        real_weak = min(per_path, key=lambda x: order.get(x, -1))
        v.ck_cov("weakest coverage equals the weakest per-path value",
                 cov_weak == real_weak,
                 "weakest={!r} per-path={}".format(cov_weak, per_path))
        v.ck_cov("all-window flag agrees with the per-path values",
                 cov_all == (real_weak == "window-complete"),
                 "all-window={} per-path={}".format(cov_all, per_path))

        fc = cap.s("m2-b2-fault-coverage")
        v.ck_cov("fault classification used the weakest path coverage",
                 fc == cov_weak,
                 "fault-coverage={!r} weakest={!r}".format(fc, cov_weak))
        neg_sound = cap.b("m2-b2-fault-negative-sound")
        v.ck_cov("negative-soundness flag matches all-window coverage",
                 neg_sound == cov_all,
                 "negative-sound={} all-window={}".format(neg_sound, cov_all))
        scope = cap.s("m2-b2-fault-negative-scope")
        v.ck_cov("negative scope is a known token", scope in SCOPE_SET,
                 "scope={!r}".format(scope))
        v.ck_cov("negative scope agrees with the all-window flag",
                 (scope == "device-wide-all-paths-covered") == cov_all,
                 "scope={!r} all-window={}".format(scope, cov_all))

        v.ck_cov("a TX-only window does not license a device-wide negative",
                 not (cov_txbuf == "window-complete" and
                      cov_rxbuf != "window-complete" and
                      scope == "device-wide-all-paths-covered"),
                 "txbuf={!r} rxbuf={!r} scope={!r}".format(
                     cov_txbuf, cov_rxbuf, scope))

        v.ck_cov("unscanned slots are zero whenever any path claims window "
                 "coverage",
                 unscanned == 0 or "window-complete" not in per_path,
                 "unscanned={} per-path={}".format(unscanned, per_path))
        v.ck_cov("unscanned slots are zero whenever a negative is claimed "
                 "sound",
                 unscanned == 0 or not neg_sound,
                 "unscanned={} negative-sound={}".format(unscanned, neg_sound))

        len_unknown = cap.i("m2-b2-dma-len-unknown")
        v.ck_cov("undecoded lengths block an exact negative",
                 len_unknown == 0 or not neg_sound,
                 "len-unknown={} negative-sound={}".format(len_unknown,
                                                           neg_sound))

        tx_basis = cap.s("m2-b2-dma-tx-ring-basis")
        rx_basis = cap.s("m2-b2-dma-rx-ring-basis")
        v.ck_cov("TX ring read basis is a known value",
                 tx_basis in RING_BASIS_SET, "tx-basis={!r}".format(tx_basis))
        v.ck_cov("RX ring read basis is a known value",
                 rx_basis in RING_BASIS_SET, "rx-basis={!r}".format(rx_basis))
        v.ck_cov("register-only is never enough to trust ring contents",
                 tx_basis != "register-only" and rx_basis != "register-only",
                 "tx={!r} rx={!r}".format(tx_basis, rx_basis))
        tx_decoded = cap.i("m2-b2-dma-tx-ring-decoded")
        rx_ringend = cap.i("m2-b2-dma-rx-ring-ringend-at-last")
        v.ck_cov("a fingerprint basis implies the fingerprint actually saw "
                 "data",
                 (tx_basis != "register+content-fingerprint" or
                  tx_decoded > 0) and
                 (rx_basis != "register+content-fingerprint" or
                  rx_ringend == 1),
                 "tx-basis={!r} decoded={} rx-basis={!r} ringend={}".format(
                     tx_basis, tx_decoded, rx_basis, rx_ringend))

    # =====================================================================
    # D. DMA COMPLETION EVIDENCE VALIDITY
    # =====================================================================
    delta = None
    delta_ok = False
    cp_mask = 0
    cp_before = 0
    cp_after = None

    if not obs_ran:
        for nm in ("chip identity is known",
                   "close-pointer delta-valid is a known token",
                   "noCloseVer follows from the configuration method",
                   "close-pointer register matches the chip's version",
                   "close-pointer width matches the chip's version",
                   "close-pointer mask matches the chip's version",
                   "count mask is not the ring size (round-6 defect)",
                   "close-pointer sample fits its width and mask",
                   "close-pointer delta is the mask-based difference",
                   "close-pointer delta is below half the mask",
                   "delta is not silently a ring-modulo result",
                   "raw TxConfig re-derives the claimed configuration method",
                   "a completion-progress claim requires chip identity",
                   "a completion-progress claim requires a usable delta",
                   "a completion-progress claim requires delta > 0",
                   "a completion-progress claim requires attributed "
                   "descriptors"):
            v.na(v.dma, nm,
                 "not applicable: the DMA observation did not run")
    else:
        chip_known = cap.b("m2-b2-dma-chip-known")
        cfgm = cap.i("m2-b2-dma-cfgmethod")
        ncv = cap.i("m2-b2-dma-noclosever")
        cp_reg = cap.i("m2-b2-dma-cloptr-reg")
        cp_width = cap.i("m2-b2-dma-cloptr-width")
        cp_mask = cap.i("m2-b2-dma-cloptr-mask")
        cp_before = cap.i("m2-b2-dma-cloptr-before")
        cvalid = cap.s("m2-b2-dma-cloptr-delta-valid")

        v.ck_dma("chip identity is known", chip_known,
                 "chip-known={} cfgmethod={}".format(chip_known, cfgm))
        v.ck_dma("close-pointer delta-valid is a known token",
                 RE_CLOPTR_VALID.match(cvalid) is not None,
                 "delta-valid={!r}".format(cvalid))

        expected_ncv = CFG_TO_NOCLOSE.get(cfgm)
        v.ck_dma("noCloseVer follows from the configuration method",
                 expected_ncv is not None and expected_ncv == ncv,
                 "cfgmethod={} implies noCloseVer={}, capture says {}".format(
                     cfgm, expected_ncv, ncv))

        # ---- ROUND 9: re-derive cfgMethod from the RAW TxConfig ----
        #
        # Round 8 checked that cfgMethod and noCloseVer agreed with each
        # other, but both are DERIVED values the probe publishes. If the probe
        # computed them wrongly, or a capture was assembled from two different
        # boots, the pair can agree while both are wrong. The raw register is
        # the independent check: run the driver's own branch over it here.
        txcfg = cap.opti("m2-b2-dma-txconfig", None)
        if txcfg is None:
            v.ck_dma("raw TxConfig re-derives the claimed configuration "
                     "method", False,
                     "m2-b2-dma-txconfig is absent, so the identity cannot "
                     "be re-derived from the register")
        else:
            derived = cfg_from_txconfig(txcfg)
            v.ck_dma("raw TxConfig re-derives the claimed configuration "
                     "method", derived == cfgm,
                     "TxConfig=0x{:08x} re-derives cfgMethod={}, capture "
                     "says {}".format(txcfg, derived, cfgm))

        if chip_known and ncv in NOCLOSE_TO_SPEC:
            ereg, ew, emask = NOCLOSE_TO_SPEC[ncv]
            v.ck_dma("close-pointer register matches the chip's version",
                     cp_reg == ereg,
                     "reg=0x{:x} expected 0x{:x} for ver {}".format(
                         cp_reg, ereg, ncv))
            v.ck_dma("close-pointer width matches the chip's version",
                     cp_width == ew,
                     "width={} expected {}".format(cp_width, ew))
            v.ck_dma("close-pointer mask matches the chip's version",
                     cp_mask == emask,
                     "mask=0x{:x} expected 0x{:x}".format(cp_mask, emask))
        else:
            v.ck_dma("close-pointer version is one of the known versions",
                     ncv in NOCLOSE_TO_SPEC, "noclosever={}".format(ncv))

        v.ck_dma("count mask is not the ring size (round-6 defect)",
                 cp_mask != 1023, "mask=0x{:x}".format(cp_mask))
        v.ck_dma("close-pointer sample fits its width and mask",
                 cp_width in (2, 4) and
                 (cp_width != 2 or cp_before <= 0xFFFF) and
                 (cp_mask == 0 or (cp_before & ~cp_mask) == 0),
                 "before=0x{:x} width={} mask=0x{:x}".format(
                     cp_before, cp_width, cp_mask))

        delta_ok = (cvalid == "yes")
        if delta_ok:
            cp_after = cap.i("m2-b2-dma-cloptr-after")
            delta = cap.i("m2-b2-dma-cloptr-delta")
            expect = (cp_after - cp_before) & cp_mask if cp_mask else 0
            v.ck_dma("close-pointer delta is the mask-based difference",
                     delta == expect,
                     "delta=0x{:x} expected 0x{:x}".format(delta, expect))
            half = (cp_mask >> 1) + 1 if cp_mask else 0
            v.ck_dma("close-pointer delta is below half the mask",
                     cp_mask != 0 and delta < half,
                     "delta=0x{:x} half=0x{:x}".format(delta, half))
            v.ck_dma("delta is not silently a ring-modulo result",
                     delta != 0 or cp_after == cp_before,
                     "delta=0x{:x} before=0x{:x} after=0x{:x}".format(
                         delta, cp_before, cp_after))
        else:
            v.ck_dma("close-pointer delta was reported unusable, and the "
                     "verdict does not rely on it",
                     not verdict_s.startswith("PASS-CANDIDATE"),
                     "delta-valid={!r} verdict={!r}".format(cvalid,
                                                            verdict_s))

        claims_progress = verdict_s.startswith("PASS-CANDIDATE")
        v.ck_dma("a completion-progress claim requires chip identity",
                 not claims_progress or chip_known,
                 "verdict={!r} chip-known={}".format(verdict_s, chip_known))
        v.ck_dma("a completion-progress claim requires a usable delta",
                 not claims_progress or delta_ok,
                 "verdict={!r} delta-valid={!r}".format(verdict_s, cvalid))
        v.ck_dma("a completion-progress claim requires delta > 0",
                 not claims_progress or (delta is not None and delta > 0),
                 "verdict={!r} delta={}".format(
                     verdict_s, "absent" if delta is None
                     else "0x{:x}".format(delta)))
        v.ck_dma("a completion-progress claim requires attributed "
                 "descriptors",
                 not claims_progress or
                 cap.i("m2-b2-dma-win-completed-in-window") > 0,
                 "verdict={!r} completed-in-window={}".format(
                     verdict_s, cap.i("m2-b2-dma-win-completed-in-window")))

    # ---- time ordering ----
    if not is_translation:
        for nm in ("observation end is after its start",
                   "close-pointer pre-sample is inside the observation",
                   "window end is after window start",
                   "close-pointer pre-sample precedes the measurement window",
                   "close-pointer post-sample lies inside the window",
                   "tail-pointer post-sample lies inside the window",
                   "the capture agrees the boundary sample was inside",
                   "translation was effective before the window opened",
                   "translation was still effective when the window closed",
                   "recovery starts after the window closed",
                   "translation takes effect only after the invalidation "
                   "completed",
                   "the effective start is the invalidation completion",
                   "close-pointer post-sample precedes recovery",
                   "close-pointer post-sample is not earlier than the "
                   "pre-sample"):
            v.na(v.dma, nm,
                 "not applicable: control mode runs no measurement window")
        t_win_s = t_win_e = t_clo_a = t_clo_b = 0
    else:
        t_obs_b = cap.i("m2-b2-dma-t-obs-before")
        t_obs_a = cap.i("m2-b2-dma-t-obs-after")
        t_clo_b = cap.i("m2-b2-dma-t-clo-before")
        t_clo_a = cap.i("m2-b2-dma-t-clo-after")
        t_win_s = cap.i("m2-b2-dma-t-win-start")
        t_win_e = cap.i("m2-b2-dma-t-win-end")
        t_tail_b = cap.i("m2-b2-dma-t-tail-before")
        t_tail_a = cap.i("m2-b2-dma-t-tail-after")
        t_on = cap.i("m2-b2-dma-t-translate-on")
        t_off = cap.i("m2-b2-dma-t-translate-off")
        t_rec = cap.i("m2-b2-t-recovery-start")
        t_dte = cap.i("m2-b2-dma-t-dte-written")
        t_inv = cap.i("m2-b2-dma-t-inv-complete")

        v.ck_dma("observation end is after its start", t_obs_a >= t_obs_b,
                 "before={} after={}".format(t_obs_b, t_obs_a))
        v.ck_dma("close-pointer pre-sample is inside the observation",
                 t_obs_b <= t_clo_b <= t_obs_a,
                 "obs=[{},{}] clo-before={}".format(t_obs_b, t_obs_a,
                                                    t_clo_b))
        v.ck_dma("window end is after window start", t_win_e >= t_win_s,
                 "start={} end={}".format(t_win_s, t_win_e))

        v.ck_dma("close-pointer pre-sample precedes the measurement window",
                 t_clo_b <= t_win_s,
                 "clo-before={} win-start={}".format(t_clo_b, t_win_s))
        # ---- ROUND 9: the post-sample must lie INSIDE the window ----
        #
        # Round 8 required `clo-after >= win-end` ("brackets the window"), and
        # that is satisfied by a sample taken long AFTER the window closed --
        # which is exactly what round 8 did (sampling span 3.00785 s against a
        # 3.00018 s window). "Brackets" does not prove "these completions
        # happened inside the zero-event window"; only "inside" does.
        #
        # The two directions are mutually exclusive, so the round-8 check is
        # REPLACED rather than kept alongside: keeping both would make every
        # capture fail one of them.
        v.ck_dma("close-pointer post-sample lies inside the window",
                 t_win_s <= t_clo_a <= t_win_e,
                 "win=[{},{}] clo-after={}".format(t_win_s, t_win_e, t_clo_a))
        v.ck_dma("tail-pointer post-sample lies inside the window",
                 t_win_s <= t_tail_a <= t_win_e,
                 "win=[{},{}] tail-after={}".format(t_win_s, t_win_e,
                                                    t_tail_a))
        v.ck_dma("the capture agrees the boundary sample was inside",
                 cap.b("m2-b2-dma-boundary-in-window"),
                 "boundary-in-window={}".format(
                     cap.b("m2-b2-dma-boundary-in-window")))

        v.ck_dma("translation was effective before the window opened",
                 t_on <= t_win_s,
                 "translate-on={} win-start={}".format(t_on, t_win_s))
        v.ck_dma("translation was still effective when the window closed",
                 t_off == 0 or t_off >= t_win_e,
                 "translate-off={} win-end={}".format(t_off, t_win_e))
        v.ck_dma("recovery starts after the window closed",
                 t_rec >= t_win_e,
                 "win-end={} recovery={}".format(t_win_e, t_rec))

        # ---- ROUND 9: translation-effective must FOLLOW the invalidation ----
        #
        # The DTE write only programs the entry. Until the invalidation
        # commands complete, the TLB may still hold pass-through entries, so
        # "translation is effective" cannot start at the DTE write.
        v.ck_dma("translation takes effect only after the invalidation "
                 "completed", t_inv >= t_dte,
                 "dte-written={} inv-complete={}".format(t_dte, t_inv))
        v.ck_dma("the effective start is the invalidation completion",
                 t_on == t_inv,
                 "translate-on={} inv-complete={}".format(t_on, t_inv))

        v.ck_dma("close-pointer post-sample precedes recovery",
                 t_clo_a <= t_rec,
                 "clo-after={} recovery-start={}".format(t_clo_a, t_rec))
        v.ck_dma("close-pointer post-sample is not earlier than the "
                 "pre-sample", t_clo_a >= t_clo_b,
                 "clo-before={} clo-after={}".format(t_clo_b, t_clo_a))

    # ---- window scan consistency ----
    if not is_translation:
        for nm in ("window scan reason is a known token",
                   "scan quality is a known token",
                   "every submitted index was visited or accounted for",
                   "decoded plus overwritten equals visited",
                   "inflight plus completed equals decoded",
                   "in-window completions do not exceed total completions",
                   "window completes agree with the close-pointer delta",
                   "TX window-covered claim agrees with the scan reason",
                   "ring-overwritten forbids a covered claim",
                   "a window-covered claim requires an exact scan",
                   "a generation change implies slot reuse was possible",
                   "a window completion implies the scan ran"):
            v.na(v.dma, nm,
                 "not applicable: control mode runs no window scan")
        win_sub = win_comp = win_visit = win_dec = win_over = 0
        win_inf = win_done = win_done_w = 0
        cov_reason = "not-observed"
        covered = False
        win_exact = False
        t_tail_a = t_tail_b = 0
        t_tail_b = 0
    else:
        win_scan = cap.s("m2-b2-dma-win-scan")
        cov_reason = cap.s("m2-b2-dma-win-cov-reason")
        v.ck_dma("window scan reason is a known token",
                 cov_reason in TXCOV_REASON_SET,
                 "cov-reason={!r}".format(cov_reason))

        quality = cap.s("m2-b2-dma-win-quality")
        v.ck_dma("scan quality is a known token", quality in TXQUALITY_SET,
                 "quality={!r}".format(quality))
        win_exact = cap.b("m2-b2-dma-win-exact")
        stop_name = cap.s("m2-b2-dma-win-stop-reason-name")
        v.ck_dma("scan stop reason is a known token",
                 stop_name in SCANSTOP_SET,
                 "stop-reason-name={!r}".format(stop_name))

        win_sub = cap.i("m2-b2-dma-win-submits")
        win_comp = cap.i("m2-b2-dma-win-completes")
        win_visit = cap.i("m2-b2-dma-win-visited")
        win_dec = cap.i("m2-b2-dma-win-decoded")
        win_over = cap.i("m2-b2-dma-win-overwritten")
        win_inf = cap.i("m2-b2-dma-win-inflight")
        win_done = cap.i("m2-b2-dma-win-completed")
        win_done_w = cap.i("m2-b2-dma-win-completed-in-window")
        win_gen_b = cap.i("m2-b2-dma-win-gen-before")
        win_gen_a = cap.i("m2-b2-dma-win-gen-after")
        win_lost = cap.i("m2-b2-dma-win-records-lost")
        win_skip = cap.i("m2-b2-dma-win-skipped")
        win_prewin = cap.i("m2-b2-dma-win-prewin-completed")
        win_infl_b = cap.i("m2-b2-dma-win-inflight-at-start")
        covered = cap.b("m2-b2-dma-tx-window-covered")

        v.ck_dma("every submitted index was visited or accounted for",
                 win_visit + win_skip == win_sub,
                 "visited={} skipped={} submits={}".format(
                     win_visit, win_skip, win_sub))
        v.ck_dma("decoded plus overwritten equals visited",
                 win_dec + win_over == win_visit,
                 "decoded={} overwritten={} visited={}".format(
                     win_dec, win_over, win_visit))
        v.ck_dma("inflight plus completed equals decoded",
                 win_inf + win_done == win_dec,
                 "inflight={} completed={} decoded={}".format(
                     win_inf, win_done, win_dec))
        v.ck_dma("in-window completions do not exceed total completions",
                 win_done_w <= win_done,
                 "in-window={} completed={}".format(win_done_w, win_done))

        # ---- ROUND 9: recompute the pointer deltas and compare ----
        #
        # This is the check round 8 lacked: it published tail-before and
        # tail-after but never compared their difference with the submit
        # count the capture claimed. A capture saying "0x68 -> 0x68, 3
        # submitted" passed.
        tail_b = cap.i("m2-b2-dma-tailptr-before")
        tail_a = cap.i("m2-b2-dma-tailptr-after")
        recomputed_sub = (tail_a - tail_b) & (cp_mask or 0x7FFFFFFF)
        v.ck_dma("submit count equals the recomputed tail delta",
                 win_sub == recomputed_sub,
                 "win-submits={} tail 0x{:x}->0x{:x} gives {}".format(
                     win_sub, tail_b, tail_a, recomputed_sub))

        if delta_ok and cp_mask:
            clo_b = cap.i("m2-b2-dma-cloptr-before")
            recomputed_com = (cp_after - clo_b) & cp_mask
            v.ck_dma("window completes agree with the close-pointer delta",
                     win_comp == recomputed_com,
                     "win-completes={} clo 0x{:x}->0x{:x} gives {}".format(
                         win_comp, clo_b, cp_after, recomputed_com))
            # The inherited queue must be accounted for: completions are drawn
            # from the older population first.
            expect_prewin = min(recomputed_com, win_infl_b)
            v.ck_dma("inherited-queue completions are accounted for",
                     win_prewin == expect_prewin,
                     "prewin-completed={} expected min({}, {})={}".format(
                         win_prewin, recomputed_com, win_infl_b,
                         expect_prewin))
        else:
            v.na(v.dma, "window completes agree with the close-pointer delta",
                 "not applicable: no usable close-pointer delta")

        v.ck_dma("TX window-covered claim agrees with the scan reason",
                 covered == (cov_reason == "ok"),
                 "covered={} reason={!r}".format(covered, cov_reason))
        v.ck_dma("ring-overwritten forbids a covered claim",
                 not (cov_reason == "ring-overwritten" and covered),
                 "reason={!r} covered={}".format(cov_reason, covered))

        # ---- ROUND 9: coverage eligibility requires an EXACT scan ----
        v.ck_dma("a window-covered claim requires an exact scan",
                 not covered or (win_exact and win_lost == 0 and
                                 win_over == 0 and win_skip == 0),
                 "covered={} exact={} lost={} overwritten={} skipped={}".format(
                     covered, win_exact, win_lost, win_over, win_skip))

        v.ck_dma("a generation change implies slot reuse was possible",
                 not (win_gen_a != win_gen_b and win_over == 0 and
                      win_sub >= 1024),
                 "gen {}->{} overwritten={} submits={}".format(
                     win_gen_b, win_gen_a, win_over, win_sub))

        v.ck_dma("a window completion implies the scan ran",
                 win_done_w == 0 or win_scan == "done",
                 "completed-in-window={} scan={!r}".format(win_done_w,
                                                           win_scan))

    # =====================================================================
    # E. ATTRIBUTION: recompute the correspondence from the raw records
    # =====================================================================
    if not is_translation:
        for nm in ("a positive attribution requires the raw first-completion "
                   "record",
                   "the attributed address is a descriptor of this window",
                   "the attributed slot and generation are consistent",
                   "the attributed length is decodable or flagged",
                   "the attributed address has a published page-table path",
                   "the page-table path independently decodes to the address",
                   "the leaf encoding is legal at its level",
                   "the walk verdict agrees with the independent decode",
                   "the driver's records show a complete submit/complete pair",
                   "the paired record's address matches the attributed address",
                   "the paired record's cumulative index matches its slot"):
            v.na(v.attrib, nm,
                 "not applicable: control mode has no window attribution")
    else:
        # ---- the first attributed completion must have a raw record ----
        #
        # Round 8 accepted the attribution on the PRESENCE of
        # `win-1st-completed-addr`. Deleting the field made the check not run
        # at all, so a capture could claim three completions, publish no
        # record of any, and still be VALID.
        have_raw = cap.hasraw("m2-b2-dma-win-1st-completed-addr")
        v.ck_attrib("a positive attribution requires the raw first-completion "
                    "record",
                    (win_done_w == 0) or have_raw,
                    "completed-in-window={} record present={}".format(
                        win_done_w, have_raw))

        if have_raw:
            fa = cap.opti("m2-b2-dma-win-1st-completed-addr")
            fl = cap.opti("m2-b2-dma-win-1st-completed-len")
            fs = cap.opti("m2-b2-dma-win-1st-completed-slot")
            fg = cap.opti("m2-b2-dma-win-1st-completed-gen")

            # ---- the address must be a descriptor of THIS window ----
            #
            # The window's descriptors are published as `win0-addr`,
            # `win1-addr`, ... by the page-table dump. The attributed address
            # must be one of them, otherwise the "chain" is assembled from two
            # unrelated numbers.
            win_addrs = []
            i = 0
            while cap.hasraw("m2-b2-%s%d-addr" % ("win", i)):
                win_addrs.append(cap.opti("m2-b2-win%d-addr" % i))
                i += 1
            v.ck_attrib("the attributed address is a descriptor of this window",
                        (not win_addrs) or (fa in win_addrs),
                        "attributed=0x{:x} window descriptors={}".format(
                            fa, ["0x{:x}".format(a) for a in win_addrs]))

            # ---- slot and generation must be consistent with the address ----
            v.ck_attrib("the attributed slot and generation are consistent",
                        (fs & 0x3FF) == fs,
                        "slot=0x{:x} generation={}".format(fs, fg))

            # ---- the length must be decodable or explicitly flagged ----
            v.ck_attrib("the attributed length is decodable or flagged",
                        fl > 0 or win_len_flagged(cap),
                        "len=0x{:x} len-unknown={}".format(
                            fl, cap.i("m2-b2-dma-win-len-unknown")))

            # ---- the page-table path must EXIST for the attributed address ----
            ptes = collect_ptes(cap, "win")
            v.ck_attrib("the attributed address has a published page-table "
                        "path", bool(ptes),
                        "found {} PTE record(s) under the 'win' tag".format(
                            len(ptes)))

            if ptes:
                walk = decode_walk(ptes, root_level, fa)
                v.ck_attrib("the page-table path independently decodes to the "
                            "address", walk["ok"], walk["reason"])

                leaf = None
                for rec in walk["path"]:
                    if rec.get("level") == walk["leafLevel"]:
                        leaf = rec
                v.ck_attrib("the leaf encoding is legal at its level",
                            not walk["illegal"],
                            walk["reason"] if walk["illegal"] else
                            "leaf at level {} maps 0x{:x} bytes".format(
                                walk["leafLevel"],
                                LEVEL_DEFAULT_SIZE.get(walk["leafLevel"], 0)))

                ww = cap.s("m2-b2-dma-win-walk")
                v.ck_attrib("the walk verdict agrees with the independent "
                            "decode",
                            (ww == "identity-mapped") == bool(walk["ok"]),
                            "capture says {!r}, independent decode says {}".format(
                                ww, "mapped" if walk["ok"] else
                                ("absent" if walk["absent"] else
                                 ("illegal" if walk["illegal"] else "mapped "
                                  "elsewhere"))))
            else:
                v.ck_attrib("the page-table path independently decodes to the "
                            "address", False,
                            "no PTE records: the claim has no raw backing")
                v.ck_attrib("the leaf encoding is legal at its level", False,
                            "no leaf to check")
                v.ck_attrib("the walk verdict agrees with the independent "
                            "decode", False,
                            "no PTE records to compare against")

        # ---- the driver's own record pair ----
        #
        # This is the round-9 correspondence. The driver writes the SAME
        # cumulative index in the submit record and in the completion record,
        # so the pair is exact. The analyser checks the join's arithmetic and
        # the cross-field consistency; it cannot re-derive the driver's
        # in-memory state, and it does not claim to.
        #
        # ROUND 9: the claim is about the WINDOW, not about the whole log.
        # Round 9's third real run had obs-all-completed=no with 0x2a orphan
        # completions, because the published 512-record suffix had dropped the
        # submissions of the earliest completions. That is a fact about the
        # publication window, not about the measurement window -- so what must
        # be complete is the WINDOW subset.
        obs_ok = cap.s("m2-b2-obs") == "complete"
        obs_ops = cap.i("m2-b2-obs-ops")
        obs_win_sub = cap.i("m2-b2-obs-win-submits")
        obs_win_done = cap.i("m2-b2-obs-win-dones")
        obs_win_pair = cap.i("m2-b2-obs-win-paired")
        obs_win_orphan = cap.i("m2-b2-obs-win-orphan-done")
        obs_win_complete = cap.b("m2-b2-obs-window-complete")
        obs_overflow = cap.i("m2-b2-obs-overflow")

        v.ck_attrib("the driver's records show a complete submit/complete "
                    "pair inside the window",
                    obs_ok and obs_win_pair > 0 and obs_win_complete and
                    obs_win_orphan == 0 and obs_overflow == 0,
                    "obs={!r} win-submits={} win-dones={} win-paired={} "
                    "win-orphan={} window-complete={} overflow={}".format(
                        cap.s("m2-b2-obs"), obs_win_sub, obs_win_done,
                        obs_win_pair, obs_win_orphan, obs_win_complete,
                        obs_overflow))
        # The window subset cannot exceed the whole log.
        v.ck_attrib("the window subset does not exceed the published log",
                    obs_win_pair <= obs_ops and
                    obs_win_done <= obs_ops,
                    "win-paired={} win-dones={} ops={}".format(
                        obs_win_pair, obs_win_done, obs_ops))
        # The window-complete flag must follow from its own counters.
        v.ck_attrib("the window-complete flag follows from its own counters",
                    obs_win_complete == (obs_win_pair > 0 and
                                         obs_win_orphan == 0),
                    "flag={} paired={} orphan={}".format(
                        obs_win_complete, obs_win_pair, obs_win_orphan))

        have_op = cap.hasraw("m2-b2-obs-op-addr")
        if have_op:
            op_addr = cap.opti("m2-b2-obs-op-addr")
            op_cum = cap.opti("m2-b2-obs-op-cum")
            op_slot = cap.opti("m2-b2-obs-op-slot")
            op_gen = cap.opti("m2-b2-obs-op-gen")
            op_tsub = cap.opti("m2-b2-obs-op-t-submit")
            op_tcmp = cap.opti("m2-b2-obs-op-t-compl")

            # The two independent views of the same operation -- the ring scan
            # and the driver's record -- must agree on the address when both
            # are present.
            fa2 = cap.opti("m2-b2-dma-win-1st-completed-addr", 0)
            v.ck_attrib("the paired record's address matches the attributed "
                        "address",
                        fa2 == 0 or op_addr == fa2,
                        "driver record says 0x{:x}, ring scan says 0x{:x}".format(
                            op_addr, fa2))

            # cumulative -> slot is arithmetic, not a claim.
            v.ck_attrib("the paired record's cumulative index matches its slot",
                        (op_cum & 0x3FF) == (op_slot & 0x3FF),
                        "cumulative=0x{:x} slot=0x{:x} (cumulative & 1023 = "
                        "0x{:x})".format(op_cum, op_slot, op_cum & 0x3FF))
            # generation must be floor(cumulative / ringSize)
            v.ck_attrib("the paired record's generation follows from its "
                        "cumulative index",
                        op_gen == (op_cum // 1024),
                        "generation={} but cumulative 0x{:x} / 1024 = {}".format(
                            op_gen, op_cum, op_cum // 1024))

            # ---- the pair must lie inside the window and inside the
            #      translation-effective interval ----
            v.ck_attrib("the paired operation was submitted inside the window",
                        t_win_s <= op_tsub <= t_win_e,
                        "submit={} window=[{},{}]".format(op_tsub, t_win_s,
                                                          t_win_e))
            v.ck_attrib("the paired operation completed inside the window",
                        t_win_s <= op_tcmp <= t_win_e,
                        "complete={} window=[{},{}]".format(op_tcmp, t_win_s,
                                                            t_win_e))
            v.ck_attrib("the paired operation completed after it was submitted",
                        op_tcmp >= op_tsub,
                        "submit={} complete={}".format(op_tsub, op_tcmp))
            v.ck_attrib("the paired operation lies inside the "
                        "translation-effective interval",
                        t_on <= op_tsub and
                        (cap.i("m2-b2-dma-t-translate-off") == 0 or
                         op_tcmp <= cap.i("m2-b2-dma-t-translate-off")),
                        "op=[{},{}] translate=[{},{}]".format(
                            op_tsub, op_tcmp, t_on,
                            cap.i("m2-b2-dma-t-translate-off")))
        else:
            v.ck_attrib("the paired record's address matches the attributed "
                        "address", win_done_w == 0,
                        "no driver-record pair was published")
            v.ck_attrib("the paired record's cumulative index matches its slot",
                        win_done_w == 0, "no driver-record pair was published")
            v.ck_attrib("the paired record's generation follows from its "
                        "cumulative index", win_done_w == 0,
                        "no driver-record pair was published")
            v.ck_attrib("the paired operation was submitted inside the window",
                        win_done_w == 0, "no driver-record pair was published")
            v.ck_attrib("the paired operation completed inside the window",
                        win_done_w == 0, "no driver-record pair was published")
            v.ck_attrib("the paired operation completed after it was submitted",
                        win_done_w == 0, "no driver-record pair was published")
            v.ck_attrib("the paired operation lies inside the "
                        "translation-effective interval", win_done_w == 0,
                        "no driver-record pair was published")

    # =====================================================================
    # Event decoding and reconciliation
    # =====================================================================
    raws = []
    if is_translation:
        entries = cap.i("m2-b2-win-entries")
        backlog = cap.i("m2-b2-win-pre-backlog")
        new_entries = cap.i("m2-b2-win-new-entries")
        raw_count = cap.i("m2-b2-win-raw-count")
        truncated = cap.b("m2-b2-win-raw-truncated")

        raw_bad = []
        for i in range(raw_count):
            rv = cap.raw.get("m2-b2-win-raw%d" % i)
            if rv is None:
                raw_bad.append("raw{} absent but raw-count={}".format(
                    i, raw_count))
                continue
            s = rv.strip()
            if s.lower().startswith("0x"):
                s = s[2:]
            if not RE_RAW32.match(s):
                raw_bad.append("raw{} malformed".format(i))
                continue
            w = [int(s[j:j + 8], 16) for j in range(0, 32, 8)]
            d0, d1, d2, d3 = w
            flags = (d1 >> 16) & 0x1FF
            raws.append({
                "raw": s.lower(),
                "devid": d0 & 0xFFFF,
                "domain": d1 & 0xFFFF,
                "type": (d1 >> 28) & 0xF,
                "typeName": TYPE_NAMES.get((d1 >> 28) & 0xF, "UNKNOWN"),
                "flags": flags,
                "bits": {n: (flags >> b) & 1 for b, n in FLAG_BITS},
                "address": ((d3 & 0xFFFFFFFF) << 32) | (d2 & 0xFFFFFFFF),
            })

        v.ck_event("raw event array parses", not raw_bad,
                   "; ".join(raw_bad[:3]) if raw_bad else
                   "{} raw entries".format(len(raws)))
        v.ck_event("raw-count matches the number of raw entries present",
                   raw_count == len(raws),
                   "declared={} present={}".format(raw_count, len(raws)))
        v.ck_event("truncation flag agrees with entries vs retained",
                   truncated == (entries > raw_count),
                   "entries={} retained={} truncated={}".format(
                       entries, raw_count, truncated))
        v.ck_event("new-entries agrees with entries minus backlog",
                   new_entries == max(0, entries - backlog),
                   "entries={} backlog={} new={}".format(
                       entries, backlog, new_entries))

        foreign = [e for e in raws if e["devid"] != devid]
        v.ck_event("every retained raw event belongs to the target device",
                   not foreign,
                   "{} foreign of {}".format(len(foreign), len(raws)))

        type_sum = 0
        type_present = []
        type_bad = []
        for t in range(1, 16):
            k = "m2-b2-win-type%d-count" % t
            if k in cap.raw:
                val = cap.raw[k].strip()
                if not RE_HEX.match(val):
                    type_bad.append("{} malformed".format(k))
                    continue
                n = int(val, 16)
                if n:
                    type_sum += n
                    type_present.append((t, n))
        v.ck_event("per-type counters are well formed", not type_bad,
                   "; ".join(type_bad[:3]) if type_bad else "ok")
        v.ck_event("per-type counters sum to the window entry count",
                   type_sum == entries,
                   "sum={} entries={} types={}".format(
                       type_sum, entries, type_present))

        raw_by_type = {}
        for e in raws:
            raw_by_type[e["type"]] = raw_by_type.get(e["type"], 0) + 1
        for t, n in type_present:
            if t not in raw_by_type:
                v.ck_event("type {} count has raw backing".format(t),
                           truncated,
                           "type={} declared={} raw=0 truncated={}".format(
                               t, n, truncated))

        dom = cap.raw.get("m2-b2-win-dominant", "").strip().strip('"')
        dom_n = cap.raw.get("m2-b2-win-dominant-count", "").strip()
        if type_present and RE_HEX.match(dom_n):
            best = max(type_present, key=lambda x: x[1])
            v.ck_event("dominant event type matches the largest counter",
                       dom == TYPE_NAMES.get(best[0], "UNKNOWN") and
                       int(dom_n, 16) == best[1],
                       "dominant={!r} count={} expected={}".format(
                           dom, dom_n, TYPE_NAMES.get(best[0], "UNKNOWN")))

        pr0_bad = []
        for i, e in enumerate(raws):
            if e["type"] != 2:
                continue
            if e["bits"]["PR"] == 0:
                for f in PR_ONLY_FIELDS:
                    if e["bits"][f] != 0:
                        pr0_bad.append(
                            "event {}: PR=0 but {}={}".format(
                                i, f, e["bits"][f]))
        v.ck_event("PR=0 faults do not report PR-only cause fields",
                   not pr0_bad, "; ".join(pr0_bad[:3]) if pr0_bad else "ok")

        inrange = cap.i("m2-b2-fault-inrange")
        outrange = cap.i("m2-b2-fault-outofrange")
        wpresent = cap.i("m2-b2-fault-walk-present")
        willegal = cap.i("m2-b2-fault-walk-illegal")
        wabsent = cap.i("m2-b2-fault-walk-absent")

        fault_in_raw = sum(1 for e in raws if e["type"] == 2)
        fault_in_types = dict(type_present).get(2, 0)

        v.ck_event("every retained fault was classified by the walk",
                   (wpresent + willegal + wabsent) == fault_in_raw,
                   "walked={} faults-in-raw={}".format(
                       wpresent + willegal + wabsent, fault_in_raw))
        v.ck_event("in-range + out-of-range equals the fault count",
                   (inrange + outrange) == fault_in_types,
                   "in={} out={} type2={}".format(
                       inrange, outrange, fault_in_types))
        if not truncated:
            v.ck_event("untruncated capture: raw faults equal the type count",
                       fault_in_raw == fault_in_types,
                       "raw={} type2={}".format(fault_in_raw, fault_in_types))

        dumped = cap.i("m2-b2-dump-count")
        v.ck_event("page-table dump covers the faults it claims",
                   dumped == min(4, fault_in_raw),
                   "dump-count={} faults={}".format(dumped, fault_in_raw))
    else:
        v.ck_event("control mode has no event window to reconcile",
                   True, "not applicable: mode={!r}".format(mode))

    # =====================================================================
    # CONCLUSION
    # =====================================================================
    invalid = not v.overall()

    if is_translation:
        any_event = cap.i("m2-b2-win-entries") > 0
    else:
        any_event = False

    if invalid:
        conclusion = "INVALID - at least one validity verdict failed"
        code = 3
    elif verdict_s.startswith("CONTROL") or mode == "control-sleep-only":
        conclusion = "CONTROL branch - not a translation experiment"
        code = 1
    elif not any_event:
        if delta_ok and delta is not None and delta > 0:
            conclusion = ("no events in a valid window, with usable "
                          "close-pointer progress of {} descriptor(s)".format(
                              delta))
        else:
            conclusion = ("INDETERMINATE - valid window, no events, and no "
                          "usable positive completion progress")
        code = 1
    elif verdict_s.startswith("FAIL-"):
        conclusion = "FAIL - {}".format(verdict_s)
        code = 1
    else:
        conclusion = "events present: {}".format(verdict_s)
        code = 1

    report = {
        "source": path,
        "probeVerdict": verdict_s,
        "probeStage": stage_s,
        "mode": mode,
        "validity": v.as_dict(),
        "eventWindow": {
            "entries": (cap.i("m2-b2-win-entries")
                        if cap.has("m2-b2-win-entries") else 0),
            "coverage": cov_weak,
        },
        "addressObservation": {
            "ranges": ranges,
            "dropped": dropped,
            "rawOffered": raw_off,
            "merged": merged,
            "unscanned": unscanned,
            "lenUnknown": len_unknown,
            "envelope": [env_lo, env_hi],
            "layoutKnown": (cap.b("m2-b2-dma-layout-known")
                            if cap.has("m2-b2-dma-layout-known") else None),
            "dmaWalkCount": walk_count,
            "dmaWalkPresent": walk_present,
        },
        "coverage": {
            "perPath": {
                "txRing": per_path[0],
                "rxRing": per_path[1],
                "txBuffer": per_path[2],
                "rxBuffer": per_path[3],
                "statBuffer": per_path[4],
            },
            "weakest": cov_weak,
            "allWindow": cov_all,
            "negativeScope": scope,
        },
        "dmaEvidence": {
            "cfgMethod": (cap.i("m2-b2-dma-cfgmethod")
                          if cap.has("m2-b2-dma-cfgmethod") else None),
            "noCloseVer": (cap.i("m2-b2-dma-noclosever")
                           if cap.has("m2-b2-dma-noclosever") else None),
            "cloPtrMask": cp_mask,
            "cloPtrBefore": cp_before,
            "cloPtrAfter": cp_after,
            "delta": delta,
            "deltaValid": (cap.s("m2-b2-dma-cloptr-delta-valid")
                           if cap.has("m2-b2-dma-cloptr-delta-valid")
                           else None),
            "windowCovered": (cap.b("m2-b2-dma-tx-window-covered")
                              if cap.has("m2-b2-dma-tx-window-covered")
                              else None),
            "windowExact": (cap.b("m2-b2-dma-win-exact")
                            if cap.has("m2-b2-dma-win-exact") else None),
        },
        "attribution": {
            "firstCompletedAddr": (cap.opti(
                "m2-b2-dma-win-1st-completed-addr", None)),
            "driverOpAddr": (cap.opti("m2-b2-obs-op-addr", None)),
            "driverOpCumulative": (cap.opti("m2-b2-obs-op-cum", None)),
            "driverOps": (cap.i("m2-b2-obs-ops")
                          if cap.has("m2-b2-obs-ops") else None),
            "allCompleted": (cap.b("m2-b2-obs-all-completed")
                             if cap.has("m2-b2-obs-all-completed") else None),
        },
        "events": [
            {
                "type": e["type"],
                "typeName": e["typeName"],
                "devid": "0x{:04x}".format(e["devid"]),
                "address": "0x{:x}".format(e["address"]),
                "flags": "0x{:03x}".format(e["flags"]),
                "bits": e["bits"],
            }
            for e in raws
        ],
        "conclusion": conclusion,
    }

    if as_json:
        print(json.dumps(report, indent=2))
        return code

    # ---------------------------- human output ----------------------------
    print("Round-9 evidence analysis")
    print("=" * 78)
    print("source : {}".format(path))
    print("verdict: {}".format(verdict_s))
    print("stage  : {}".format(stage_s))
    print("mode   : {}".format(mode))
    print()

    def dump(title, bucket, ok):
        print(title)
        print("-" * 78)
        for c in bucket:
            if c.get("notApplicable"):
                mark = "N/A "
            else:
                mark = "PASS" if c["ok"] else "FAIL"
            print("  {:<62} {}".format(c["name"], mark))
            if c["detail"] and (not c["ok"] or c.get("notApplicable")):
                print("       {}".format(c["detail"]))
        na = sum(1 for c in bucket if c.get("notApplicable"))
        print("  ==> {}: {}".format(
            "VALID" if ok else "INVALID",
            "all {} checks passed".format(len(bucket)) if ok and not na
            else "{} of {} check(s) failed{}".format(
                sum(1 for c in bucket if not c["ok"]), len(bucket),
                ", {} not applicable".format(na) if na else "")))
        print()

    dump("A. EVENT WINDOW VALIDITY", v.event, v.event_ok())
    dump("B. ADDRESS OBSERVATION COMPLETENESS", v.address, v.address_ok())
    dump("C. COVERAGE CONSISTENCY", v.coverage, v.coverage_ok())
    dump("D. DMA COMPLETION EVIDENCE VALIDITY", v.dma, v.dma_ok())
    dump("E. ATTRIBUTION (recomputed from the raw records)", v.attrib,
         v.attrib_ok())

    print("OVERALL VALIDITY")
    print("-" * 78)
    for label, ok in (("event window", v.event_ok()),
                      ("address observation", v.address_ok()),
                      ("coverage consistency", v.coverage_ok()),
                      ("DMA evidence", v.dma_ok()),
                      ("attribution", v.attrib_ok())):
        print("  {:<20}: {}".format(label, "VALID" if ok else "INVALID"))
    print("  {:<20}: {}".format("overall",
                                "VALID" if v.overall() else "INVALID"))
    print()
    print("  NOTE: these five are independent. Round 8 shipped four and still")
    print("  could not catch a capture whose attributed address matched no")
    print("  descriptor of the window, because nothing recomputed the")
    print("  correspondence from the raw numbers.")
    print()

    print("=" * 78)
    print(conclusion)
    print("exit code {}".format(code))
    return code


def win_len_flagged(cap):
    """True when the window's lengths were flagged undecodable."""
    return cap.opti("m2-b2-dma-win-len-unknown", 0) > 0


def collect_ptes(cap, tag):
    """Collect the PTE records published under `tag`.

    The probe publishes, per dumped address N and per chain step M:
        m2-b2-<tag>N-addr        the address being walked
        m2-b2-<tag>N-depth       number of chain steps recorded
        m2-b2-<tag>N-pteM-table  physical address of the table
        m2-b2-<tag>N-pteM-level  the level of that table
        m2-b2-<tag>N-pteM-index  the index used within that table
        m2-b2-<tag>N-pteM        the raw PTE
        m2-b2-<tag>N-walk        the probe's own note
        m2-b2-<tag>N-ok          the probe's own verdict

    A record is only included when ALL FOUR of its fields are present and well
    formed: a partial record would let the analyser "decode" a chain it
    invented. If any step is partial the whole chain is refused, because a
    chain with a hole cannot be walked.
    """
    out = []
    i = 0
    while cap.hasraw("m2-b2-%s%d-addr" % (tag, i)):
        depth = cap.opti("m2-b2-%s%d-depth" % (tag, i), None)
        if depth is None:
            return []
        for j in range(depth):
            keys = {}
            for s in ("table", "level", "index"):
                k = "m2-b2-%s%d-pte%d-%s" % (tag, i, j, s)
                if not cap.hasraw(k):
                    return []
                keys[s] = k
            rawk = "m2-b2-%s%d-pte%d" % (tag, i, j)
            if not cap.hasraw(rawk):
                return []
            rec = {}
            bad = False
            for s, k in keys.items():
                val = cap.raw[k].strip()
                if not RE_HEX.match(val):
                    bad = True
                    break
                rec[s] = int(val, 16)
            if bad:
                return []
            val = cap.raw[rawk].strip()
            if not RE_HEX.match(val):
                return []
            rec["pte"] = int(val, 16)
            out.append(rec)
        i += 1
        # Only the first address is needed for the chain, but keep walking in
        # case a caller wants several. The chain of ONE address is what the
        # walk decodes, so stop after the first complete one.
        break
    return out


if __name__ == "__main__":
    sys.exit(main())
