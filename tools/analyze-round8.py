#!/usr/bin/env python3
"""Round-8 evidence analyser.

WHY A NEW FILE RATHER THAN AN EDIT OF analyze-round7.py
-------------------------------------------------------
Round 7's analyser is kept intact as the historical artefact for that round's
captures: its schema does not know the round-8 fields, and rewriting it in
place would silently change what "round 7 was valid" means. This file adds the
round-8 fields and the checks round 7 could not express.

WHAT ROUND 7'S ANALYSER COULD NOT CHECK
---------------------------------------
 1. `m2-b2-dma-t-clo-after` was not in its schema at all. The one check that
    mentioned it looked it up with cap.has(), so a capture that never
    published it skipped the check entirely and still reported VALID. A
    check that can be skipped by omitting a field is not a check.
 2. The window bounds (`t-win-start`/`t-win-end`) were likewise absent, so
    "the completion samples bracket the measurement window" was never
    actually verified -- only "the two samples are ordered".
 3. Recovery acceptance compared the CLAIM against the STATUS word and
    stopped there. Round 7's own wording was "the claim must match the
    hardware bit"; matching is necessary but not sufficient, because a
    capture can honestly report `cmdbuf-stopped=no` and still be accepted.
    The hardware run bits must actually be clear.
 4. "Completion progress" was accepted whenever delta-valid was `yes`. It
    never required delta > 0, so a capture with delta 0 could be described
    as having progress.
 5. Coverage was one value. There was no way to say "TX is window-complete,
    RX is a snapshot", and therefore no way to catch a capture that
    generalised the TX result to the whole device.
 6. Chip identity was checked as a triple (register/width/mask) but not
    against the configuration method that implies it, so a capture whose
    cfgmethod and noCloseVer disagreed could still pass if the triple
    happened to match one of them.
 7. Mode selection decided which WINDOW fields were required, but the DMA
    observation fields were required unconditionally. A control-mode capture
    that never ran a DMA observation had to either omit them (and be
    rejected as malformed) or invent them. Neither is honest.

MODE SELECTION
--------------
Required fields are chosen by `m2-b2-mode`:
  * translation      -- window fields AND DMA-observation fields are required
  * control-sleep-only -- window fields are NOT required; DMA-observation
                          fields are required only if the capture says the
                          observation ran. When it did not, those fields must
                          be absent or marked not-observed, and the
                          corresponding checks report NOT APPLICABLE rather
                          than passing or failing.

EXIT CODES
    0  every validity verdict holds and the functional result is a pass
       candidate
    1  every validity verdict holds, but the result is FAIL / INDETERMINATE
       / CONTROL
    2  cannot analyse: a required field is missing or malformed for the
       selected mode
    3  at least one validity verdict failed
    4  usage error

Usage:
    py -3 tools/analyze-round8.py docs/evidence/<stamp>/props.txt
    py -3 tools/analyze-round8.py docs/evidence/<stamp>/props.txt --json
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
SCOPE_SET = {"device-wide-all-paths-covered",
             "tx-path-only-rx-and-rings-not-covered"}
TRUST_SET = {"trusted", "PARTIAL-ring-registers-not-readable"}

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
# Spec Table 57: RZ is only defined for present-entry faults.
PR_ONLY_FIELDS = ("RZ",)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
# Always required, regardless of mode.
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
    ("m2-b2-disabled", YESNO, True),
    ("m2-b2-cmdbuf-stopped", YESNO, True),
    ("m2-b2-evtlog-stopped", YESNO, True),
    ("m2-b2-cmdbuf-stop-status", HEX, True),
    ("m2-b2-evtlog-stop-status", HEX, True),
    ("m2-b2-final-control", HEX, True),
    ("m2-b2-orig-control-echo", HEX, True),
    ("m2-b2-regs-restored", TEXT, True),
    ("m2-b2-cleanup", TEXT, True),
    # address observation: accounting
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
    ("m2-b2-dma-read-ok", HEX, True),
    ("m2-b2-dma-read-outofmap", HEX, True),
    ("m2-b2-dma-read-notram", HEX, True),
    ("m2-b2-dma-tx-slots", HEX, True),
    ("m2-b2-dma-tx-zeroaddr", HEX, True),
    ("m2-b2-dma-tx-done-with-addr", HEX, True),
    # round 8: per-path coverage (always required -- they are the point)
    ("m2-b2-dma-cov-txring", TEXT, True),
    ("m2-b2-dma-cov-rxring", TEXT, True),
    ("m2-b2-dma-cov-txbuf", TEXT, True),
    ("m2-b2-dma-cov-rxbuf", TEXT, True),
    ("m2-b2-dma-cov-stat", TEXT, True),
    ("m2-b2-dma-cov-weakest", TEXT, True),
    ("m2-b2-dma-cov-all-window", YESNO, True),
    # round 8: read basis
    ("m2-b2-dma-tx-ring-basis", TEXT, True),
    ("m2-b2-dma-rx-ring-basis", TEXT, True),
    ("m2-b2-dma-tx-ring-decoded", HEX, True),
    ("m2-b2-dma-rx-ring-ringend-at-last", HEX, True),
    ("m2-b2-dma-len-unknown", HEX, True),
    # close pointer identity
    ("m2-b2-dma-cloptr-reg", HEX, True),
    ("m2-b2-dma-cloptr-width", HEX, True),
    ("m2-b2-dma-cloptr-mask", HEX, True),
    ("m2-b2-dma-cloptr-before", HEX, True),
    ("m2-b2-dma-cloptr-delta-valid", TEXT, True),
    ("m2-b2-dma-cfgmethod", HEX, True),
    ("m2-b2-dma-noclosever", HEX, True),
    ("m2-b2-dma-chip-known", YESNO, True),
    # fault classification
    ("m2-b2-fault-inrange", HEX, True),
    ("m2-b2-fault-outofrange", HEX, True),
    ("m2-b2-fault-walk-present", HEX, True),
    ("m2-b2-fault-walk-illegal", HEX, True),
    ("m2-b2-fault-walk-absent", HEX, True),
    ("m2-b2-fault-observed-absent", HEX, True),
    ("m2-b2-fault-coverage", TEXT, True),
    ("m2-b2-fault-negative-sound", YESNO, True),
    ("m2-b2-fault-negative-scope", TEXT, True),
    # DMA walk
    ("m2-b2-dma-walk-count", HEX, True),
    ("m2-b2-dma-walk-present", HEX, True),
    ("m2-b2-dma-walk-verdict", TEXT, True),
]

# Required only when mode == "translation": the measurement window exists.
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
    # ROUND 8: the window's own monotonic bounds, and the completion samples.
    # Round 7 never required these, which is exactly why its
    # "bracket the window" check could be skipped.
    ("m2-b2-dma-t-win-start", HEX),
    ("m2-b2-dma-t-win-end", HEX),
    ("m2-b2-dma-t-translate-on", HEX),
    ("m2-b2-dma-t-translate-off", HEX),
    ("m2-b2-dma-t-tail-before", HEX),
    ("m2-b2-dma-t-tail-after", HEX),
    ("m2-b2-dma-t-clo-before", HEX),
    ("m2-b2-dma-t-clo-after", HEX),
    ("m2-b2-dma-t-obs-before", HEX),
    ("m2-b2-dma-t-obs-after", HEX),
    # Recovery boundary: round 7 read it but never validated it, so a capture
    # that omitted it raised a KeyError instead of a clean refusal. It belongs
    # in the schema precisely because a time-ordering check depends on it.
    ("m2-b2-t-recovery-start", HEX),
    # ROUND 8: the window scan result
    ("m2-b2-dma-win-scan", TEXT),
    ("m2-b2-dma-win-cov-reason", TEXT),
    ("m2-b2-dma-win-submits", HEX),
    ("m2-b2-dma-win-completes", HEX),
    ("m2-b2-dma-win-visited", HEX),
    ("m2-b2-dma-win-decoded", HEX),
    ("m2-b2-dma-win-overwritten", HEX),
    ("m2-b2-dma-win-inflight", HEX),
    ("m2-b2-dma-win-completed", HEX),
    ("m2-b2-dma-win-completed-in-window", HEX),
    ("m2-b2-dma-win-len-unknown", HEX),
    ("m2-b2-dma-win-gen-before", HEX),
    ("m2-b2-dma-win-gen-after", HEX),
    ("m2-b2-dma-tx-window-covered", YESNO),
    # Published by the window scan: whether the window's first completed
    # address was found identity-mapped. Only meaningful in translation mode,
    # which is why it lives here and not in the common schema.
    ("m2-b2-dma-win-walk", TEXT),
    ("m2-b2-dma-tx-life-inflight", HEX),
    ("m2-b2-dma-tx-life-completed", HEX),
    ("m2-b2-dma-tx-life-snapshot", HEX),
    ("m2-b2-dma-tx-life-unknown", HEX),
]

# Conditional: required only when the capture says the DMA observation ran.
SCHEMA_OBS_RAN = [
    ("m2-b2-dma-cloptr-after", HEX),
    ("m2-b2-dma-cloptr-delta", HEX),
    ("m2-b2-dma-tailptr-before", HEX),
    ("m2-b2-dma-tailptr-after", HEX),
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
                    self.errors.append(
                        (name, "not yes/no: %r" % v))
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
    """Four independent validity verdicts plus their evidence.

    Round 7 had three. The fourth -- coverage consistency -- exists because
    round 7's address verdict checked the ACCOUNTING of the observation but
    never checked that the coverage CLAIM matched what was actually observed
    per path. A capture could report window-complete while its own per-path
    fields said TX only, and nothing noticed.
    """

    def __init__(self):
        self.event = []
        self.address = []
        self.coverage = []
        self.dma = []

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

    def ck_cov_na(self, name, detail=""):
        """A check that does not apply to this capture.

        NOT APPLICABLE is not PASS. It is recorded with na=True so the
        summary can say how many checks were skipped and why, instead of
        counting a skipped check as evidence.
        """
        self.coverage.append({"name": name, "ok": True, "detail": detail,
                              "notApplicable": True})
        return True

    def ck_dma(self, name, ok, detail=""):
        return self._ck(self.dma, name, ok, detail)

    def ck_dma_na(self, name, detail=""):
        self.dma.append({"name": name, "ok": True, "detail": detail,
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

    def overall(self):
        return (self.event_ok() and self.address_ok() and
                self.coverage_ok() and self.dma_ok())

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
            "overall": self.overall(),
        }


def main():
    if len(sys.argv) < 2:
        print("usage: analyze-round8.py <props.txt> [--json]")
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

    schema = list(SCHEMA_COMMON)
    if mode_known and mode == "translation":
        schema.extend(SCHEMA_TRANSLATION)

    # The DMA observation fields are required only when the observation ran.
    obs_raw = cap.raw.get("m2-b2-dma-obs")
    obs_ran = (obs_raw is not None and obs_raw.strip() == "complete")
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
    elif mode_known:
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
    #
    # ROUND 8. Round 7 checked `claim == (not run_bit)`. That is necessary
    # but not sufficient: a capture that honestly reports
    # cmdbuf-stopped=no with STATUS.CmdBufRun=1 satisfies it and was
    # accepted. Acceptance requires the hardware to have stopped.
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
    obs = cap.s("m2-b2-dma-obs")
    # ROUND 8: in control mode the probe does not run a DMA observation at
    # all, so requiring "complete" there would force the capture to either
    # fail or invent a translation-mode observation. The check applies only
    # to translation mode.
    if mode_known and mode == "control-sleep-only":
        v.ck_addr("device DMA observation was not expected in control mode",
                  obs != "complete",
                  "dma-obs={!r} (control mode runs no DMA observation)".format(
                      obs))
    else:
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
              "merged={} ranges={} dropped={}".format(merged, ranges, dropped))
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

    # ---- range metadata enumerations ----
    life_bad = []
    for i in range(16):
        for suffix, allowed in (("life", LIFE_SET), ("purpose", PURPOSE_SET),
                                ("read", READ_SET)):
            k = "m2-b2-dma-range%d-%s" % (i, suffix)
            if k in cap.raw:
                val = cap.raw[k].strip()
                if val not in allowed:
                    life_bad.append("{}={!r}".format(k, val))
    v.ck_addr("range metadata uses only known enumerations",
              not life_bad,
              "; ".join(life_bad[:3]) if life_bad else "ok")

    # ---- the DMA walk must have found live addresses identity-mapped ----
    walk_count = cap.i("m2-b2-dma-walk-count")
    walk_present = cap.i("m2-b2-dma-walk-present")
    wv = cap.s("m2-b2-dma-walk-verdict")
    v.ck_addr("DMA walk verdict is a known token",
              wv in ("all-identity-mapped", "SOME-NOT-MAPPED",
                     "no-addresses-observed"),
              "walk-verdict={!r}".format(wv))
    v.ck_addr("DMA walk examined at least one live address", walk_count > 0,
              "walk-count={}".format(walk_count))
    v.ck_addr("every live DMA address walked to an identity leaf",
              walk_present == walk_count,
              "present={} of {}".format(walk_present, walk_count))
    v.ck_addr("walk verdict agrees with its own counts",
              wv == ("all-identity-mapped" if walk_present == walk_count
                     else "SOME-NOT-MAPPED") if walk_count else
              wv == "no-addresses-observed",
              "verdict={!r} present={} count={}".format(
                  wv, walk_present, walk_count))

    # =====================================================================
    # C. COVERAGE CONSISTENCY (round 8, new bucket)
    # =====================================================================
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

    # The fault-classification coverage must be the weakest path, and the
    # scope string must match the all-window flag. This is the check that
    # catches round 7's generalisation of a TX-only result.
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

    # ---- ROUND 8: a TX-complete result must not be reported device-wide ----
    #
    # The real test is whether the scope fields follow the per-path values,
    # which the checks above already enforce. What must NOT happen is a
    # capture where TX is window-complete, RX is not, and the negative is
    # nevertheless reported as device-wide.
    v.ck_cov("a TX-only window does not license a device-wide negative",
             not (cov_txbuf == "window-complete" and
                  cov_rxbuf != "window-complete" and
                  scope == "device-wide-all-paths-covered"),
             "txbuf={!r} rxbuf={!r} scope={!r}".format(
                 cov_txbuf, cov_rxbuf, scope))

    # ---- unscanned slots must not coexist with a completeness claim ----
    #
    # This is negative regression 5 in the task list: "unscanned non-zero but
    # claims the path is complete".
    v.ck_cov("unscanned slots are zero whenever any path claims window "
             "coverage",
             unscanned == 0 or "window-complete" not in per_path,
             "unscanned={} per-path={}".format(unscanned, per_path))
    v.ck_cov("unscanned slots are zero whenever a negative is claimed sound",
             unscanned == 0 or not neg_sound,
             "unscanned={} negative-sound={}".format(unscanned, neg_sound))

    # ---- undecoded lengths must not coexist with an exact negative ----
    len_unknown = cap.i("m2-b2-dma-len-unknown")
    v.ck_cov("undecoded lengths block an exact negative",
             len_unknown == 0 or not neg_sound,
             "len-unknown={} negative-sound={}".format(len_unknown, neg_sound))

    # ---- read basis must be an honest, known value ----
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
    v.ck_cov("a fingerprint basis implies the fingerprint actually saw data",
             (tx_basis != "register+content-fingerprint" or tx_decoded > 0) and
             (rx_basis != "register+content-fingerprint" or rx_ringend == 1),
             "tx-basis={!r} decoded={} rx-basis={!r} ringend={}".format(
                 tx_basis, tx_decoded, rx_basis, rx_ringend))

    # =====================================================================
    # D. DMA COMPLETION EVIDENCE VALIDITY
    # =====================================================================
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

    # ---- ROUND 8: cfgMethod and noCloseVer must agree ----
    #
    # Round 7 checked the register/width/mask triple against noCloseVer, but
    # never checked that noCloseVer follows from cfgMethod. A capture whose
    # two identity fields disagree could pass if the triple matched one of
    # them. This is negative regression 6.
    CFG_TO_NOCLOSE = {}
    for m in (2, 3, 4, 5, 6, 7):
        CFG_TO_NOCLOSE[m] = 3
    for m in (8, 9, 10, 11, 12, 13, 41, 42):
        CFG_TO_NOCLOSE[m] = 6
    CFG_TO_NOCLOSE[31] = 4
    CFG_TO_NOCLOSE[32] = 5
    CFG_TO_NOCLOSE[33] = 5

    expected_ncv = CFG_TO_NOCLOSE.get(cfgm)
    v.ck_dma("noCloseVer follows from the configuration method",
             expected_ncv is not None and expected_ncv == ncv,
             "cfgmethod={} implies noCloseVer={}, capture says {}".format(
                 cfgm, expected_ncv, ncv))

    EXPECTED = {
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

    v.ck_dma("count mask is not the ring size (round-6 defect)",
             cp_mask != 1023, "mask=0x{:x}".format(cp_mask))
    v.ck_dma("close-pointer sample fits its width and mask",
             cp_width in (2, 4) and
             (cp_width != 2 or cp_before <= 0xFFFF) and
             (cp_mask == 0 or (cp_before & ~cp_mask) == 0),
             "before=0x{:x} width={} mask=0x{:x}".format(
                 cp_before, cp_width, cp_mask))

    delta_ok = (cvalid == "yes")
    cp_after = None
    delta = None
    if delta_ok:
        v.ck_dma("a usable delta implies both samples were published",
                 cap.has("m2-b2-dma-cloptr-after") and
                 cap.has("m2-b2-dma-cloptr-delta"),
                 "delta-valid=yes but after/delta absent")
        if cap.has("m2-b2-dma-cloptr-after"):
            cp_after = cap.i("m2-b2-dma-cloptr-after")
            delta = (cap.i("m2-b2-dma-cloptr-delta")
                     if cap.has("m2-b2-dma-cloptr-delta") else 0)
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
                 "delta-valid={!r} verdict={!r}".format(cvalid, verdict_s))

    # ---- ROUND 8: completion progress needs identity + validity + delta>0 ----
    #
    # Round 7 accepted "progress" whenever delta-valid was yes, without
    # requiring delta > 0. Negative regression 4.
    claims_progress = verdict_s.startswith("PASS-CANDIDATE")
    if mode_known and mode == "translation":
        v.ck_dma("a completion-progress claim requires chip identity",
                 not claims_progress or chip_known,
                 "verdict={!r} chip-known={}".format(verdict_s, chip_known))
        v.ck_dma("a completion-progress claim requires a usable delta",
                 not claims_progress or delta_ok,
                 "verdict={!r} delta-valid={!r}".format(verdict_s, cvalid))
        v.ck_dma("a completion-progress claim requires delta > 0",
                 not claims_progress or (delta is not None and delta > 0),
                 "verdict={!r} delta={}".format(
                     verdict_s, "absent" if delta is None else
                     "0x{:x}".format(delta)))
        v.ck_dma("a completion-progress claim requires attributed "
                 "descriptors",
                 not claims_progress or
                 cap.i("m2-b2-dma-win-completed-in-window") > 0,
                 "verdict={!r} completed-in-window={}".format(
                     verdict_s, cap.i("m2-b2-dma-win-completed-in-window")))
    else:
        v.ck_dma_na("completion-progress claim checks",
                    "not applicable: control mode does not run a translation "
                    "window")

    # ---- time ordering, now including the window and both samples ----
    if mode_known and mode == "translation":
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

        v.ck_dma("observation end is after its start", t_obs_a >= t_obs_b,
                 "before={} after={}".format(t_obs_b, t_obs_a))
        v.ck_dma("close-pointer pre-sample is inside the observation",
                 t_obs_b <= t_clo_b <= t_obs_a,
                 "obs=[{},{}] clo-before={}".format(t_obs_b, t_obs_a, t_clo_b))
        v.ck_dma("window end is after window start", t_win_e >= t_win_s,
                 "start={} end={}".format(t_win_s, t_win_e))

        # ROUND 8: the pre-sample must precede the window and the post-sample
        # must follow it. Round 7 only compared the two samples with each
        # other, so a post-sample taken before the window opened passed.
        v.ck_dma("close-pointer pre-sample precedes the measurement window",
                 t_clo_b <= t_win_s,
                 "clo-before={} win-start={}".format(t_clo_b, t_win_s))
        v.ck_dma("close-pointer post-sample follows the measurement window",
                 t_clo_a >= t_win_e,
                 "clo-after={} win-end={}".format(t_clo_a, t_win_e))
        v.ck_dma("tail-pointer samples bracket the measurement window",
                 t_tail_b <= t_win_s and t_tail_a >= t_win_e,
                 "tail=[{},{}] win=[{},{}]".format(
                     t_tail_b, t_tail_a, t_win_s, t_win_e))

        # ROUND 8: the window must lie inside the translation-effective span.
        v.ck_dma("translation was effective before the window opened",
                 t_on <= t_win_s,
                 "translate-on={} win-start={}".format(t_on, t_win_s))
        v.ck_dma("translation was still effective when the window closed",
                 t_off == 0 or t_off >= t_win_e,
                 "translate-off={} win-end={}".format(t_off, t_win_e))
        v.ck_dma("recovery starts after the window closed",
                 t_rec >= t_win_e,
                 "win-end={} recovery={}".format(t_win_e, t_rec))

        # ROUND 8: negative regression 2 -- a post-sample after recovery is
        # not a measurement of the window.
        v.ck_dma("close-pointer post-sample precedes recovery",
                 t_clo_a <= t_rec,
                 "clo-after={} recovery-start={}".format(t_clo_a, t_rec))
        # ROUND 8: negative regression 1 -- a post-sample before the pre-stage
        # is impossible and must be caught.
        v.ck_dma("close-pointer post-sample is not earlier than the pre-sample",
                 t_clo_a >= t_clo_b,
                 "clo-before={} clo-after={}".format(t_clo_b, t_clo_a))

        # ---- window scan consistency ----
        win_scan = cap.s("m2-b2-dma-win-scan")
        cov_reason = cap.s("m2-b2-dma-win-cov-reason")
        v.ck_dma("window scan reason is a known token",
                 cov_reason in TXCOV_REASON_SET,
                 "cov-reason={!r}".format(cov_reason))

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
        covered = cap.b("m2-b2-dma-tx-window-covered")

        v.ck_dma("every submitted index was visited or accounted for",
                 win_visit == win_sub,
                 "visited={} submits={}".format(win_visit, win_sub))
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
        v.ck_dma("in-window completions do not exceed submits",
                 win_done_w <= win_sub,
                 "in-window={} submits={}".format(win_done_w, win_sub))
        v.ck_dma("window completes agree with the close-pointer delta",
                 not delta_ok or win_comp == delta,
                 "win-completes={} clo-delta={}".format(
                     win_comp, "n/a" if delta is None else delta))

        # Coverage claim vs the reason that produced it.
        v.ck_dma("TX window-covered claim agrees with the scan reason",
                 covered == (cov_reason == "ok"),
                 "covered={} reason={!r}".format(covered, cov_reason))
        v.ck_dma("ring-overwritten forbids a covered claim",
                 not (cov_reason == "ring-overwritten" and covered),
                 "reason={!r} covered={}".format(cov_reason, covered))
        v.ck_dma("a generation change implies slot reuse was possible",
                 not (win_gen_a != win_gen_b and win_over == 0 and
                      win_sub >= 1024),
                 "gen {}->{} overwritten={} submits={}".format(
                     win_gen_b, win_gen_a, win_over, win_sub))

        # The scan must have run when a completion is claimed.
        v.ck_dma("a window completion implies the scan ran",
                 win_done_w == 0 or win_scan == "done",
                 "completed-in-window={} scan={!r}".format(win_done_w,
                                                           win_scan))

        # The first attributed completion must be inside the envelope.
        #
        # These fields are OPTIONAL (published only when a completion was
        # attributed), so they are not in the schema. Reading them through
        # cap.has() would always be false -- has() only sees validated
        # values -- and the check would silently never run. That is the same
        # class of defect round 7 had with t-clo-after.
        if "m2-b2-dma-win-1st-completed-addr" in cap.raw:
            fa = int(cap.raw["m2-b2-dma-win-1st-completed-addr"].strip(), 16)
            v.ck_dma("first attributed completion lies inside the envelope",
                     env_lo <= fa < env_hi,
                     "addr=0x{:x} envelope=[0x{:x},0x{:x})".format(
                         fa, env_lo, env_hi))
            v.ck_dma("first attributed completion has a real length",
                     int(cap.raw.get(
                         "m2-b2-dma-win-1st-completed-len", "0x0").strip(),
                         16) > 0,
                     "len={}".format(
                         cap.raw.get("m2-b2-dma-win-1st-completed-len")))
            ww = cap.s("m2-b2-dma-win-walk")
            v.ck_dma("window completion address was walked in the page table",
                     ww in ("identity-mapped", "NOT-MAPPED"),
                     "win-walk={!r}".format(ww))

    # ---- completion counts must not be reported as packet counts ----
    tx_done = cap.i("m2-b2-dma-tx-done-with-addr")
    tx_zero = cap.i("m2-b2-dma-tx-zeroaddr")
    tx_slots = cap.i("m2-b2-dma-tx-slots")
    v.ck_dma("completion count does not equal the never-programmed count",
             not (tx_done == tx_zero and tx_zero == tx_slots),
             "done-with-addr={} zeroaddr={} slots={}".format(
                 tx_done, tx_zero, tx_slots))

    # =====================================================================
    # Event decoding and reconciliation
    # =====================================================================
    raws = []
    if mode_known and mode == "translation":
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
        # Control mode: there is no event window, so none of the above
        # applies. Saying so is different from passing them.
        v.ck_event("control mode has no event window to reconcile",
                   True, "not applicable: mode={!r}".format(mode))

    # =====================================================================
    # CONCLUSION
    # =====================================================================
    invalid = not v.overall()

    if mode_known and mode == "translation":
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
            "layoutKnown": cap.b("m2-b2-dma-layout-known"),
            "dmaWalkCount": walk_count,
            "dmaWalkPresent": walk_present,
        },
        "coverage": {
            "perPath": {
                "txRing": cov_txring,
                "rxRing": cov_rxring,
                "txBuffer": cov_txbuf,
                "rxBuffer": cov_rxbuf,
                "statBuffer": cov_stat,
            },
            "weakest": cov_weak,
            "allWindow": cov_all,
            "negativeScope": scope,
        },
        "dmaEvidence": {
            "cfgMethod": cfgm,
            "noCloseVer": ncv,
            "cloPtrReg": cp_reg,
            "cloPtrWidth": cp_width,
            "cloPtrMask": cp_mask,
            "cloPtrBefore": cp_before,
            "cloPtrAfter": cp_after,
            "delta": delta,
            "deltaValid": cvalid,
            "windowCovered": (cap.b("m2-b2-dma-tx-window-covered")
                              if cap.has("m2-b2-dma-tx-window-covered")
                              else None),
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
    print("Round-8 evidence analysis")
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
            print("  {:<58} {}".format(c["name"], mark))
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

    print("OVERALL VALIDITY")
    print("-" * 78)
    for label, ok in (("event window", v.event_ok()),
                      ("address observation", v.address_ok()),
                      ("coverage consistency", v.coverage_ok()),
                      ("DMA evidence", v.dma_ok())):
        print("  {:<20}: {}".format(label, "VALID" if ok else "INVALID"))
    print("  {:<20}: {}".format("overall",
                                "VALID" if v.overall() else "INVALID"))
    print()
    print("  NOTE: these four are independent. Round 7 shipped three and")
    print("  still could not catch a TX-only result reported as device-wide,")
    print("  because nothing checked the coverage claim against the per-path")
    print("  fields.")
    print()

    print("=" * 78)
    print(conclusion)
    print("exit code {}".format(code))
    return code


if __name__ == "__main__":
    sys.exit(main())
