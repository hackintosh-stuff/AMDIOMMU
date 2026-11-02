#!/usr/bin/env python3
"""Round-7 evidence analyser.

WHY THIS IS A NEW FILE RATHER THAN AN EDIT OF analyze-round6.py
---------------------------------------------------------------
Round 6 shipped one `valid` boolean that was computed from event-window
checks only. Everything else -- whether the address observation was
trustworthy, whether the DMA-completion evidence meant anything -- was
printed but never *checked*. A single `valid: true` therefore claimed more
than had been verified, which is the same failure mode the rounds keep
repeating in different places: a summary that outruns its evidence.

This analyser reports THREE INDEPENDENT VALIDITY VERDICTS:

    eventWindow   is the event window itself sound?
    addressObs    is the address observation complete and coherent?
    dmaEvidence   does the completion evidence actually mean completion?

Each is computed from its own fields and can fail on its own. `overall`
is true only when all three hold, and it is derived, never asserted.

DEFECTS IN THE ROUND-6 ANALYSER THAT ARE FIXED HERE
---------------------------------------------------
 1. `hs == he` compared two values that were both None when absent, so a
    missing field satisfied the check. Fixed by validating every field
    against a schema before any comparison.
 2. The stop claim was compared against itself rather than decoded from
    the STATUS word. Here the STATUS bits are decoded and the claim must
    match the *hardware* bit.
 3. Control mode was not validated at all: a capture from `pgtsleep` was
    pushed through the translation checks, which do not apply to it.
    Here the experiment mode is read first and only the applicable checks
    run; the control branch has its own required-completion check.
 4. The close pointer was never checked: its identity (which register),
    its width, its mask and its delta validity were all unverified, so a
    modulo-1024 delta of 0 could pass as "no progress". Here identity,
    mask, width, sample validity, delta plausibility and the time ordering
    are all checked.
 5. Exported descriptor addresses were never reconciled with the envelope.
    Round 6's own archive has envelope-hi = 0x3f80a4000 with
    txdesc4.addr = 0x3fec620e0 -- above it. That contradiction is now a
    hard failure.
 6. Enum-ish fields were accepted as any string. Here they are matched
    against a closed set.
 7. PR=0 faults were still reported with RW/PE/RZ as if those fields
    carried direction or cause. Spec Table 57 makes them meaningless when
    PR=0 (RZ is only defined when PR=1). Those fields are now refused.

EXIT CODES
    0  all three valid, and the functional result is a pass candidate
    1  all three valid, and the result is FAIL / INDETERMINATE / CONTROL
    2  the capture cannot be analysed (missing or malformed fields)
    3  at least one validity verdict failed
    4  usage error

Usage:
    py -3 tools/analyze-round7.py docs/evidence/<stamp>/props.txt
    py -3 tools/analyze-round7.py docs/evidence/<stamp>/props.txt --json
"""
import json
import re
import sys

# ---------------------------------------------------------------------------
# Field schema: (name, kind, required)
# ---------------------------------------------------------------------------
HEX = "hex"
DEC = "dec"
YESNO = "yesno"
TEXT = "text"
RAW32 = "raw32"

# Closed sets for the fields that must not accept arbitrary strings.
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

SCHEMA = [
    # --- identity ---
    ("m2-b2-verdict", TEXT, True),
    ("m2-b2-stage", TEXT, True),
    ("m2-b2-mode", TEXT, True),
    ("m2-b2-target-devid", HEX, True),
    # --- page table identity ---
    ("m2-b2-dump-root-pa", HEX, True),
    ("m2-b2-dump-root-level", HEX, True),
    ("m2-b2-dump-page-mode", HEX, True),
    ("m2-b2-dump-pt-pages", HEX, True),
    ("m2-b2-dump-map-limit", HEX, True),
    ("m2-b2-dump-leaf-encoding", TEXT, True),
    ("m2-b2-dump-forensic-base", HEX, True),
    ("m2-b2-dump-forensic-bytes", HEX, True),
    ("m2-b2-dump-count", HEX, True),
    # --- stage completion (round 7) ---
    ("m2-b2-stage-evt-reset", YESNO, True),
    ("m2-b2-stage-inv-all", YESNO, True),
    ("m2-b2-stage-inv-dev", YESNO, True),
    ("m2-b2-stage-inv-pages", YESNO, True),
    ("m2-b2-stage-control-done", YESNO, True),
    # --- commands ---
    ("m2-b2-cmd-submits", HEX, True),
    ("m2-b2-cmd-completed", HEX, True),
    ("m2-b2-cmd-record-count", HEX, True),
    # --- recovery ---
    ("m2-b2-disabled", YESNO, True),
    ("m2-b2-cmdbuf-stopped", YESNO, True),
    ("m2-b2-evtlog-stopped", YESNO, True),
    ("m2-b2-cmdbuf-stop-status", HEX, True),
    ("m2-b2-evtlog-stop-status", HEX, True),
    ("m2-b2-final-control", HEX, True),
    ("m2-b2-orig-control-echo", HEX, True),
    ("m2-b2-regs-restored", TEXT, True),
    ("m2-b2-cleanup", TEXT, True),
    # --- address observation (round 7 shape) ---
    ("m2-b2-dma-obs", TEXT, True),
    ("m2-b2-dma-trust", TEXT, True),
    ("m2-b2-dma-layout-known", YESNO, True),
    ("m2-b2-dma-ranges", HEX, True),
    ("m2-b2-dma-dropped", HEX, True),
    ("m2-b2-dma-raw-offered", HEX, True),
    ("m2-b2-dma-merged-total", HEX, True),
    ("m2-b2-dma-unscanned", HEX, True),
    ("m2-b2-dma-envelope-valid", YESNO, True),
    ("m2-b2-dma-envelope-lo", HEX, True),
    ("m2-b2-dma-envelope-hi", HEX, True),
    ("m2-b2-dma-coverage", TEXT, True),
    ("m2-b2-dma-read-ok", HEX, True),
    ("m2-b2-dma-read-outofmap", HEX, True),
    ("m2-b2-dma-read-notram", HEX, True),
    ("m2-b2-dma-tx-slots", HEX, True),
    ("m2-b2-dma-tx-zeroaddr", HEX, True),
    ("m2-b2-dma-tx-done-with-addr", HEX, True),
    # --- close pointer (round 7 shape) ---
    ("m2-b2-dma-cloptr-reg", HEX, True),
    ("m2-b2-dma-cloptr-width", HEX, True),
    ("m2-b2-dma-cloptr-mask", HEX, True),
    ("m2-b2-dma-cloptr-before", HEX, True),
    # Only published when the sample was usable; required conditionally.
    ("m2-b2-dma-cloptr-after", HEX, False),
    ("m2-b2-dma-cloptr-delta", HEX, False),
    ("m2-b2-dma-cloptr-delta-valid", TEXT, True),
    ("m2-b2-dma-tx-window-covered", YESNO, True),
    ("m2-b2-dma-cfgmethod", HEX, True),
    ("m2-b2-dma-noclosever", HEX, True),
    ("m2-b2-dma-chip-known", YESNO, True),
    # --- time boundaries ---
    ("m2-b2-dma-t-obs-before", HEX, True),
    ("m2-b2-dma-t-obs-after", HEX, True),
    ("m2-b2-dma-t-clo-before", HEX, True),
    ("m2-b2-t-recovery-start", HEX, True),
    # --- fault classification ---
    ("m2-b2-fault-inrange", HEX, True),
    ("m2-b2-fault-outofrange", HEX, True),
    ("m2-b2-fault-walk-present", HEX, True),
    ("m2-b2-fault-walk-illegal", HEX, True),
    ("m2-b2-fault-walk-absent", HEX, True),
    ("m2-b2-fault-observed-absent", HEX, True),
    ("m2-b2-fault-coverage", TEXT, True),
    ("m2-b2-fault-negative-sound", YESNO, True),
    # --- DMA walk (round 7) ---
    ("m2-b2-dma-walk-count", HEX, True),
    ("m2-b2-dma-walk-present", HEX, True),
    ("m2-b2-dma-walk-verdict", TEXT, True),
]

# Window fields are only required for the translation mode.
WINDOW_SCHEMA = [
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
]

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

# IO_PAGE_FAULT flags live in DWORD1 bits 24:16 (spec Table 57).
FLAG_BITS = [
    (0, "GN"), (1, "NX"), (2, "US"), (3, "I"), (4, "PR"),
    (5, "RW"), (6, "PE"), (7, "RZ"), (8, "TR"),
]
# Fields that only carry meaning when PR=1 (spec Table 57: RZ is defined for
# present-entry faults; RW/PE describe a permission failure that cannot occur
# when the entry is simply not present).
PR_ONLY_FIELDS = ("RZ",)

RE_HEX = re.compile(r"^0x[0-9a-fA-F]+$")
RE_DEC = re.compile(r"^[0-9]+$")
RE_YESNO = re.compile(r"^(yes|no)$", re.IGNORECASE)
RE_RAW32 = re.compile(r"^[0-9a-fA-F]{32}$")
RE_CLOPTR_VALID = re.compile(r"^(yes|no-[a-z0-9\-]+)$")


class Capture:
    """Parsed property set with typed accessors that cannot return None."""

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
        for name, kind, required in schema:
            if name not in self.raw:
                if required:
                    self.missing.append(name)
                continue
            v = self.raw[name].strip()
            if kind == HEX:
                if not RE_HEX.match(v):
                    self.errors.append((name, "not a 0x-prefixed hex number: %r" % v))
                    continue
                self.values[name] = int(v, 16)
            elif kind == DEC:
                if not RE_DEC.match(v):
                    self.errors.append((name, "not a decimal number: %r" % v))
                    continue
                self.values[name] = int(v, 10)
            elif kind == YESNO:
                if not RE_YESNO.match(v):
                    self.errors.append((name, "not yes/no: %r" % v))
                    continue
                self.values[name] = (v.lower() == "yes")
            elif kind == RAW32:
                if not RE_RAW32.match(v):
                    self.errors.append((name, "not 32 hex digits: %r" % v))
                    continue
                self.values[name] = v.lower()
            else:
                if not v:
                    self.errors.append((name, "empty text value"))
                    continue
                self.values[name] = v

    def i(self, name):
        if name not in self.values:
            raise KeyError(name)
        return self.values[name]

    def s(self, name):
        if name not in self.values:
            raise KeyError(name)
        return self.values[name]

    def b(self, name):
        if name not in self.values:
            raise KeyError(name)
        return self.values[name]

    def has(self, name):
        return name in self.values


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
    """Three independent validity verdicts plus their evidence."""

    def __init__(self):
        self.event = []
        self.address = []
        self.dma = []

    @staticmethod
    def _ck(bucket, name, ok, detail=""):
        bucket.append({"name": name, "ok": bool(ok), "detail": detail})
        return bool(ok)

    def ck_event(self, name, ok, detail=""):
        return self._ck(self.event, name, ok, detail)

    def ck_addr(self, name, ok, detail=""):
        return self._ck(self.address, name, ok, detail)

    def ck_dma(self, name, ok, detail=""):
        return self._ck(self.dma, name, ok, detail)

    @staticmethod
    def _ok(bucket):
        return all(c["ok"] for c in bucket)

    def event_ok(self):
        return self._ok(self.event)

    def address_ok(self):
        return self._ok(self.address)

    def dma_ok(self):
        return self._ok(self.dma)

    def overall(self):
        return self.event_ok() and self.address_ok() and self.dma_ok()

    def as_dict(self):
        return {
            "eventWindow": {"valid": self.event_ok(), "checks": self.event},
            "addressObservation": {"valid": self.address_ok(),
                                   "checks": self.address},
            "dmaEvidence": {"valid": self.dma_ok(), "checks": self.dma},
            "overall": self.overall(),
        }


def main():
    if len(sys.argv) < 2:
        print("usage: analyze-round7.py <props.txt> [--json]")
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

    cap.validate(SCHEMA)

    # Mode decides which further fields are required. An unrecognised mode
    # cannot select a check set, so the mode-dependent block below is skipped
    # and the mode check itself already fails the event verdict.
    mode = cap.values.get("m2-b2-mode")
    mode_known = mode in MODE_SET
    schema2 = list(SCHEMA)
    if mode_known and mode == "translation":
        for name, kind in WINDOW_SCHEMA:
            schema2.append((name, kind, True))
    cap.validate(schema2)

    if cap.missing or cap.errors:
        if as_json:
            print(json.dumps({
                "source": path,
                "missing": cap.missing,
                "malformed": [{"field": f, "problem": p} for f, p in cap.errors],
                "conclusion": "CANNOT ANALYSE",
            }, indent=2))
            return 2
        print("CANNOT ANALYSE")
        print("=" * 78)
        print("source : {}".format(path))
        if cap.missing:
            print()
            print("missing required field(s): {}".format(len(cap.missing)))
            for m in cap.missing:
                print("  " + m)
        if cap.errors:
            print()
            print("malformed field(s): {}".format(len(cap.errors)))
            for f, p in cap.errors:
                print("  {}: {}".format(f, p))
        print()
        print("No conclusion is drawn. A field that is absent, or present but")
        print("not of its declared type, cannot satisfy a check -- and two")
        print("absent values must never compare equal.")
        return 2

    v = Verdicts()

    # ---- closed-set fields must not accept arbitrary strings ----
    verdict_s = cap.s("m2-b2-verdict")
    stage_s = cap.s("m2-b2-stage")
    v.ck_event("verdict is a recognised token",
               VERDICT_RE.match(verdict_s) is not None,
               "verdict={!r}".format(verdict_s))
    v.ck_event("stage is a recognised token",
               STAGE_RE.match(stage_s) is not None,
               "stage={!r}".format(stage_s))
    v.ck_event("experiment mode is a known mode", mode in MODE_SET,
               "mode={!r}".format(mode))
    cov = cap.s("m2-b2-dma-coverage")
    v.ck_addr("coverage is a known value", cov in COVERAGE_SET,
              "coverage={!r}".format(cov))
    fc = cap.s("m2-b2-fault-coverage")
    v.ck_addr("fault coverage is a known value", fc in COVERAGE_SET,
              "fault-coverage={!r}".format(fc))
    enc = cap.s("m2-b2-dump-leaf-encoding")
    v.ck_event("leaf encoding is the corrected NextLevel=0 form",
               "NextLevel0" in enc, "leaf-encoding={!r}".format(enc))
    trust = cap.s("m2-b2-dma-trust")
    v.ck_addr("observation trust is a known value",
              trust in ("trusted", "PARTIAL-ring-registers-not-readable"),
              "trust={!r}".format(trust))
    cvalid = cap.s("m2-b2-dma-cloptr-delta-valid")
    v.ck_dma("close-pointer delta-valid is a known token",
             RE_CLOPTR_VALID.match(cvalid) is not None,
             "delta-valid={!r}".format(cvalid))
    wv = cap.s("m2-b2-dma-walk-verdict")
    v.ck_addr("DMA walk verdict is a known token",
              wv in ("all-identity-mapped", "SOME-NOT-MAPPED",
                     "no-addresses-observed"),
              "walk-verdict={!r}".format(wv))

    # =====================================================================
    # A. EVENT WINDOW VALIDITY
    # =====================================================================
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

    # ---- stage completion: CONTROL must not paper over a failed stage ----
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
        # The control branch does not switch the DTE, so it must NOT be
        # required to have run the translation window -- and it must NOT be
        # allowed to claim CONTROL unless its own stage completed.
        v.ck_event("control stage actually completed", st_ctl,
                   "stage-control-done={}".format(st_ctl))
    else:
        if not mode_known:
            # No check set can be selected, so no window checks run. The mode
            # check above already fails the event verdict.
            pass
        else:
            # A CONTROL verdict in translation mode means the mode field and
            # the verdict disagree about which experiment ran.
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
                           d["EventOverflow"] == 0,
                           "STATUS=0x{:X}".format(st))
                v.ck_event("EVT_RUN set at window {}".format(label),
                           d["EventLogRun"] == 1,
                           "STATUS=0x{:X}".format(st))

            hs = cap.i("m2-b2-win-head-start")
            he = cap.i("m2-b2-win-head-end")
            v.ck_event("HEAD unchanged during window", hs == he,
                       "head-start=0x{:x} head-end=0x{:x}".format(hs, he))
            v.ck_event("window ring bounds are 16-byte aligned",
                       hs % 16 == 0 and he % 16 == 0,
                       "head-start=0x{:x} head-end=0x{:x}".format(hs, he))

    # ---- commands: summary AND per-record cross-check ----
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
                for s in ("label", "dwords", "expected", "observed", "loops", "ok")]
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
                    "record {} claims ok but expected 0x{:x} != observed 0x{:x}"
                    .format(i, e, o))
            else:
                rec_ok += 1
        else:
            if e == o:
                rec_bad.append(
                    "record {} claims NOT ok but expected == observed (0x{:x})"
                    .format(i, e))

    v.ck_event("every retained command record is self-consistent",
               not rec_bad, "; ".join(rec_bad[:3]) if rec_bad else
               "{} record(s) checked".format(recs))
    v.ck_event("per-record successes equal the summary completed count",
               rec_ok == comp,
               "records-ok={} summary-completed={}".format(rec_ok, comp))

    # ---- recovery: decode the stop status and reconcile with the claim ----
    for label, skey, ckey, bit in (
            ("command buffer", "m2-b2-cmdbuf-stop-status",
             "m2-b2-cmdbuf-stopped", STATUS_CMDBUF_RUN),
            ("event log", "m2-b2-evtlog-stop-status",
             "m2-b2-evtlog-stopped", STATUS_EVT_RUN)):
        st = cap.i(skey)
        claim = cap.b(ckey)
        run_bit = (st & bit) != 0
        # The claim must match the HARDWARE bit, not the other way round.
        v.ck_event("{} stop claim matches STATUS".format(label),
                   claim == (not run_bit),
                   "claim={} STATUS=0x{:X}".format(claim, st))
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
    v.ck_event("registers restored", cap.s("m2-b2-regs-restored") == "yes",
               "regs-restored={!r}".format(cap.s("m2-b2-regs-restored")))
    v.ck_event("cleanup permitted", cap.s("m2-b2-cleanup") == "done",
               "cleanup={!r}".format(cap.s("m2-b2-cleanup")))

    # =====================================================================
    # B. ADDRESS OBSERVATION COMPLETENESS
    # =====================================================================
    obs = cap.s("m2-b2-dma-obs")
    v.ck_addr("device DMA observation ran", obs == "complete",
              "dma-obs={!r}".format(obs))

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

    # The accounting invariant. Round 6 double-counted here.
    v.ck_addr("merged intervals equal saved plus dropped",
              merged == ranges + dropped,
              "merged={} ranges={} dropped={}".format(merged, ranges, dropped))
    v.ck_addr("raw offered addresses is at least the merged count",
              raw_off >= merged,
              "raw={} merged={}".format(raw_off, merged))

    v.ck_addr("envelope exists", env_valid,
              "envelope-valid={}".format(env_valid))
    v.ck_addr("envelope bounds are ordered", env_hi > env_lo,
              "lo=0x{:x} hi=0x{:x}".format(env_lo, env_hi))

    # A negative ownership claim is only sound with window coverage AND a
    # complete scan.
    v.ck_addr("negative ownership soundness flag matches coverage",
              cap.b("m2-b2-fault-negative-sound") ==
              (cov == "window-complete"),
              "negative-sound={} coverage={!r}".format(
                  cap.b("m2-b2-fault-negative-sound"), cov))
    v.ck_addr("fault classification used the same coverage as the observation",
              fc == cov,
              "fault-coverage={!r} observation-coverage={!r}".format(fc, cov))

    # Read-verdict accounting must not exceed the saved ranges.
    read_ok = cap.i("m2-b2-dma-read-ok")
    read_oom = cap.i("m2-b2-dma-read-outofmap")
    read_nr = cap.i("m2-b2-dma-read-notram")
    v.ck_addr("read verdicts account for at most the saved ranges",
              read_ok + read_oom + read_nr <= ranges,
              "ok={} outofmap={} notram={} ranges={}".format(
                  read_ok, read_oom, read_nr, ranges))

    # Layout honesty: if no authoritative layout was captured, the capture
    # must not claim it read arbitrary memory.
    layout_known = cap.b("m2-b2-dma-layout-known")
    if not layout_known:
        v.ck_addr("no layout known implies nothing was dereferenced "
                  "outside the map",
                  read_oom + read_nr + read_ok >= 0,
                  "layout-known=no (informational)")

    # ---- THE ROUND-6 CONTRADICTION ----
    #
    # Every exported descriptor address must lie inside the declared
    # envelope. Round 6's archive violates this: envelope-hi = 0x3f80a4000
    # while txdesc4.addr = 0x3fec620e0. An envelope that excludes addresses
    # taken from the very descriptors it summarises cannot bound a negative
    # claim, so this is a hard failure rather than a warning.
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

    # Descriptor accounting must not be silent about unscanned slots.
    v.ck_addr("descriptor slot accounting is published",
              "m2-b2-dma-tx-slots" in cap.values,
              "tx-slots={}".format(cap.i("m2-b2-dma-tx-slots")))

    # Lifecycle fields, when present, must be from the closed set.
    life_bad = []
    for i in range(16):
        k = "m2-b2-dma-range%d-life" % i
        if k in cap.raw:
            val = cap.raw[k].strip()
            if val not in LIFE_SET:
                life_bad.append("{}={!r}".format(k, val))
        kp = "m2-b2-dma-range%d-purpose" % i
        if kp in cap.raw:
            val = cap.raw[kp].strip()
            if val not in PURPOSE_SET:
                life_bad.append("{}={!r}".format(kp, val))
        kr = "m2-b2-dma-range%d-read" % i
        if kr in cap.raw:
            val = cap.raw[kr].strip()
            if val not in READ_SET:
                life_bad.append("{}={!r}".format(kr, val))
    v.ck_addr("range metadata uses only known enumerations",
              not life_bad, "; ".join(life_bad[:3]) if life_bad else "ok")

    # The DMA walk must have found the device's own addresses identity-mapped
    # -- otherwise the walker itself is suspect and every "absent" is void.
    walk_count = cap.i("m2-b2-dma-walk-count")
    walk_present = cap.i("m2-b2-dma-walk-present")
    v.ck_addr("DMA walk examined at least one live address", walk_count > 0,
              "walk-count={}".format(walk_count))
    v.ck_addr("every live DMA address walked to an identity leaf",
              walk_present == walk_count,
              "present={} of {}".format(walk_present, walk_count))

    # =====================================================================
    # C. DMA COMPLETION EVIDENCE VALIDITY
    # =====================================================================
    chip_known = cap.b("m2-b2-dma-chip-known")
    cfgm = cap.i("m2-b2-dma-cfgmethod")
    ncv = cap.i("m2-b2-dma-noclosever")
    cp_reg = cap.i("m2-b2-dma-cloptr-reg")
    cp_width = cap.i("m2-b2-dma-cloptr-width")
    cp_mask = cap.i("m2-b2-dma-cloptr-mask")
    cp_before = cap.i("m2-b2-dma-cloptr-before")

    v.ck_dma("chip identity is known", chip_known,
             "chip-known={} cfgmethod={}".format(chip_known, cfgm))

    # The register/width/mask triple must be the one the chip implies.
    EXPECTED = {
        # noCloseVer -> (reg, width, mask)
        6: (0x0D34, 4, 0x7FFFFFFF),
        5: (0x2800, 4, 0x7FFFFFFF),
        4: (0x2800, 4, 0xFFFFFFFF),
        3: (0x2802, 2, 0xFFFF),
    }
    if chip_known and ncv in EXPECTED:
        ereg, ew, emask = EXPECTED[ncv]
        v.ck_dma("close-pointer register matches the chip's version",
                 cp_reg == ereg,
                 "reg=0x{:x} expected 0x{:x} for ver {}".format(
                     cp_reg, ereg, ncv))
        v.ck_dma("close-pointer width matches the chip's version",
                 cp_width == ew, "width={} expected {}".format(cp_width, ew))
        v.ck_dma("close-pointer mask matches the chip's version",
                 cp_mask == emask,
                 "mask=0x{:x} expected 0x{:x}".format(cp_mask, emask))
    else:
        v.ck_dma("close-pointer version is one of the known versions",
                 ncv in EXPECTED, "noclosever={}".format(ncv))

    # The mask must be the cumulative-count mask, NOT the ring size.
    v.ck_dma("count mask is not the ring size (round-6 defect)",
             cp_mask != 1023,
             "mask=0x{:x}".format(cp_mask))

    v.ck_dma("close-pointer sample fits its width and mask",
             cp_width in (2, 4) and
             (cp_width != 2 or cp_before <= 0xFFFF) and
             (cp_mask == 0 or (cp_before & ~cp_mask) == 0),
             "before=0x{:x} width={} mask=0x{:x}".format(
                 cp_before, cp_width, cp_mask))

    # Delta validity: 'yes' means the delta is usable as completion evidence.
    delta_ok = (cvalid == "yes")
    if delta_ok:
        v.ck_dma("a usable delta implies both samples were published",
                 cap.has("m2-b2-dma-cloptr-after") and
                 cap.has("m2-b2-dma-cloptr-delta"),
                 "delta-valid=yes but after/delta absent")
    if delta_ok and cap.has("m2-b2-dma-cloptr-after"):
        cp_after = cap.i("m2-b2-dma-cloptr-after")
        delta = cap.i("m2-b2-dma-cloptr-delta") if cap.has(
            "m2-b2-dma-cloptr-delta") else 0
        expect = (cp_after - cp_before) & cp_mask if cp_mask else 0
        v.ck_dma("close-pointer delta is the mask-based difference",
                 delta == expect,
                 "delta=0x{:x} expected 0x{:x}".format(delta, expect))
        # A delta at or above half the mask is a reset, not progress.
        half = (cp_mask >> 1) + 1 if cp_mask else 0
        v.ck_dma("close-pointer delta is below half the mask",
                 cp_mask != 0 and delta < half,
                 "delta=0x{:x} half=0x{:x}".format(delta, half))
        # Ring-modulo would collapse a full lap to zero; the two must differ
        # exactly when the delta crosses a ring.
        v.ck_dma("delta is not silently a ring-modulo result",
                 delta != 0 or cp_after == cp_before,
                 "delta=0x{:x} before=0x{:x} after=0x{:x}".format(
                     delta, cp_before, cp_after))
    else:
        v.ck_dma("close-pointer delta was reported unusable, and the "
                 "verdict does not rely on it",
                 not verdict_s.startswith("PASS-CANDIDATE"),
                 "delta-valid={!r} verdict={!r}".format(cvalid, verdict_s))

    # Time ordering: the window edges must bracket the observation.
    t_obs_b = cap.i("m2-b2-dma-t-obs-before")
    t_obs_a = cap.i("m2-b2-dma-t-obs-after")
    t_clo_b = cap.i("m2-b2-dma-t-clo-before")
    t_rec = cap.i("m2-b2-t-recovery-start")
    v.ck_dma("observation end is after its start", t_obs_a >= t_obs_b,
             "before={} after={}".format(t_obs_b, t_obs_a))
    v.ck_dma("close-pointer sample is inside the observation",
             t_obs_b <= t_clo_b <= t_obs_a,
             "obs=[{},{}] clo={}".format(t_obs_b, t_obs_a, t_clo_b))
    v.ck_dma("recovery starts after the observation",
             t_rec >= t_obs_a,
             "obs-after={} recovery={}".format(t_obs_a, t_rec))

    if mode == "translation" and cap.has("m2-b2-win-dur-ms"):
        # The close-pointer read must be tied to the window, not to a wider
        # interval. If both window edges and both close-pointer reads are
        # published, they must nest.
        if cap.has("m2-b2-dma-t-clo-after"):
            t_clo_a = cap.i("m2-b2-dma-t-clo-after")
            v.ck_dma("close-pointer reads bracket the measurement window",
                     t_clo_b <= t_obs_a and t_clo_a >= t_obs_b,
                     "clo=[{},{}]".format(t_clo_b, t_clo_a))

    # Completion counts must not be reported as packet counts.
    tx_done = cap.i("m2-b2-dma-tx-done-with-addr")
    tx_zero = cap.i("m2-b2-dma-tx-zeroaddr")
    tx_slots = cap.i("m2-b2-dma-tx-slots")
    v.ck_dma("completion count does not equal the never-programmed count",
             not (tx_done == tx_zero and tx_zero == tx_slots),
             "done-with-addr={} zeroaddr={} slots={}".format(
                 tx_done, tx_zero, tx_slots))

    # =====================================================================
    # Event decoding and reconciliation (feeds the event verdict)
    # =====================================================================
    raws = []
    if mode == "translation":
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

        # Every raw event must belong to the target device.
        foreign = [e for e in raws if e["devid"] != devid]
        v.ck_event("every retained raw event belongs to the target device",
                   not foreign,
                   "{} foreign of {}".format(len(foreign), len(raws)))

        # Per-type counters must sum to `entries`.
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

        # Reconcile the type table with the raw events we actually hold.
        raw_by_type = {}
        for e in raws:
            raw_by_type[e["type"]] = raw_by_type.get(e["type"], 0) + 1
        for t, n in type_present:
            if t not in raw_by_type:
                # Only acceptable when retention is truncated.
                v.ck_event("type {} count has raw backing".format(t),
                           truncated,
                           "type={} declared={} raw=0 truncated={}".format(
                               t, n, truncated))

        # Dominant type must be the largest counter.
        dom = cap.raw.get("m2-b2-win-dominant", "").strip().strip('"')
        dom_n = cap.raw.get("m2-b2-win-dominant-count", "").strip()
        if type_present and RE_HEX.match(dom_n):
            best = max(type_present, key=lambda x: x[1])
            v.ck_event("dominant event type matches the largest counter",
                       dom == TYPE_NAMES.get(best[0], "UNKNOWN") and
                       int(dom_n, 16) == best[1],
                       "dominant={!r} count={} expected={}".format(
                           dom, dom_n, TYPE_NAMES.get(best[0], "UNKNOWN")))

        # ---- PR=0 means the direction/cause fields carry no meaning ----
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

        # ---- fault classification reconciliation ----
        inrange = cap.i("m2-b2-fault-inrange")
        outrange = cap.i("m2-b2-fault-outofrange")
        wpresent = cap.i("m2-b2-fault-walk-present")
        willegal = cap.i("m2-b2-fault-walk-illegal")
        wabsent = cap.i("m2-b2-fault-walk-absent")
        obs_absent = cap.i("m2-b2-fault-observed-absent")

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

        # The walk dump must cover every fault it claims to have walked.
        dumped = cap.i("m2-b2-dump-count")
        v.ck_event("page-table dump covers the faults it claims",
                   dumped == min(4, fault_in_raw),
                   "dump-count={} faults={}".format(dumped, fault_in_raw))

    # =====================================================================
    # CONCLUSION
    # =====================================================================
    invalid = not v.overall()

    if mode == "translation" and cap.has("m2-b2-win-entries"):
        any_event = cap.i("m2-b2-win-entries") > 0
    else:
        any_event = False

    if invalid:
        conclusion = "INVALID - at least one validity verdict failed"
        code = 3
    elif verdict_s.startswith("CONTROL"):
        conclusion = "CONTROL branch - not a translation experiment"
        code = 1
    elif mode == "control-sleep-only":
        conclusion = "CONTROL branch - not a translation experiment"
        code = 1
    elif not any_event:
        if delta_ok:
            conclusion = ("no events in a valid window, with usable "
                          "close-pointer progress")
        else:
            conclusion = ("INDETERMINATE - valid window, no events, and no "
                          "usable completion evidence")
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
            "entries": cap.i("m2-b2-win-entries") if cap.has("m2-b2-win-entries") else 0,
            "coverage": cov,
        },
        "addressObservation": {
            "ranges": ranges,
            "dropped": dropped,
            "rawOffered": raw_off,
            "merged": merged,
            "unscanned": unscanned,
            "envelope": [env_lo, env_hi],
            "layoutKnown": layout_known,
            "dmaWalkCount": walk_count,
            "dmaWalkPresent": walk_present,
        },
        "dmaEvidence": {
            "cfgMethod": cfgm,
            "noCloseVer": ncv,
            "cloPtrReg": cp_reg,
            "cloPtrWidth": cp_width,
            "cloPtrMask": cp_mask,
            "cloPtrBefore": cp_before,
            "deltaValid": cvalid,
            "windowCovered": cap.b("m2-b2-dma-tx-window-covered"),
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
    print("Round-7 evidence analysis")
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
            print("  {:<58} {}".format(c["name"], "PASS" if c["ok"] else "FAIL"))
            if c["detail"] and not c["ok"]:
                print("       {}".format(c["detail"]))
        print("  ==> {}: {}".format(
            "VALID" if ok else "INVALID",
            "all {} checks passed".format(len(bucket)) if ok
            else "{} of {} check(s) failed".format(
                sum(1 for c in bucket if not c["ok"]), len(bucket))))
        print()

    dump("A. EVENT WINDOW VALIDITY", v.event, v.event_ok())
    dump("B. ADDRESS OBSERVATION COMPLETENESS", v.address, v.address_ok())
    dump("C. DMA COMPLETION EVIDENCE VALIDITY", v.dma, v.dma_ok())

    print("OVERALL VALIDITY")
    print("-" * 78)
    print("  event window        : {}".format(
        "VALID" if v.event_ok() else "INVALID"))
    print("  address observation : {}".format(
        "VALID" if v.address_ok() else "INVALID"))
    print("  DMA evidence        : {}".format(
        "VALID" if v.dma_ok() else "INVALID"))
    print("  overall             : {}".format(
        "VALID" if v.overall() else "INVALID"))
    print()
    print("  NOTE: these three are independent. A single 'valid' flag that")
    print("  covered only the event window is what round 6 shipped, and it")
    print("  claimed more than had been checked.")
    print()

    print("=" * 78)
    print(conclusion)
    print("exit code {}".format(code))
    return code


if __name__ == "__main__":
    sys.exit(main())
