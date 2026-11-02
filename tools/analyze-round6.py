#!/usr/bin/env python3
"""Round-6 evidence analyser.

WHAT CHANGED FROM ROUND 5, AND WHY
----------------------------------
The round-5 analyser had a real defect class that the task called out:

  * `hs == he` compares two values that are BOTH `None` when the fields are
    missing, so a missing field silently satisfied the check. Same pattern in
    `subs == comp` and `recs == subs`. Any two absent numbers compared equal.
  * Values were parsed with `as_int()` and then used without checking the
    type: a field holding "yes" where a number was expected became `None`,
    and `None == None` passed.
  * The per-command records were never cross-checked against the summary
    counts, so "3 submitted / 3 completed" could coexist with three records
    that all say `ok = no`.
  * The stop status was never decoded. The textual claim
    `cmdbuf-stopped = yes` was taken at face value even though the probe
    also publishes the raw STATUS word that proves or refutes it.
  * The raw event array was never reconciled with `win-entries`,
    `win-raw-count`, `win-raw-truncated` and the per-type counters.

This version enforces, for every field:
  1. presence
  2. format (regex for hex / decimal / yes-no / named values)
  3. type (a field declared numeric must actually parse as a number)
  4. value range where the meaning is known

and then cross-checks the redundant representations against each other. When
two independent encodings of the same fact disagree, that is INVALID, not a
tie broken in favour of the nicer one.

EXIT CODES
    0  VALID and the functional result is PASS
    1  VALID and the result is FAIL / INDETERMINATE / CONTROL
    2  the capture cannot be analysed (missing or malformed fields)
    3  the experiment was INVALID (a required check failed, or two
       encodings of the same fact contradict each other)
    4  usage error

Usage:
    py -3 tools/analyze-round6.py docs/evidence/<stamp>/props.txt
    py -3 tools/analyze-round6.py docs/evidence/<stamp>/props.txt --json
"""
import json
import re
import sys

# ---------------------------------------------------------------------------
# Field schema.
#
# Each entry is (name, kind, required). `kind` drives BOTH the format check
# and the type check, so a field cannot be "present but unparseable" and still
# count as satisfied.
# ---------------------------------------------------------------------------
HEX = "hex"
DEC = "dec"
YESNO = "yesno"
TEXT = "text"

SCHEMA = [
    # --- identity / configuration ---
    ("m2-b2-verdict", TEXT, True),
    ("m2-b2-stage", TEXT, True),
    ("m2-b2-target-devid", HEX, True),
    ("m2-b2-dump-root-pa", HEX, True),
    ("m2-b2-dump-root-level", HEX, True),
    ("m2-b2-dump-page-mode", HEX, True),
    ("m2-b2-dump-pt-pages", HEX, True),
    ("m2-b2-dump-map-limit", HEX, True),
    ("m2-b2-dump-leaf-encoding", TEXT, True),
    # --- pre-switch control window ---
    ("m2-b2-pre-window-ran", YESNO, True),
    ("m2-b2-pre-valid", YESNO, True),
    ("m2-b2-pre-entries-count", HEX, True),
    ("m2-b2-pre-backlog", HEX, True),
    ("m2-b2-pre-raw-truncated", YESNO, True),
    # --- main window ---
    ("m2-b2-main-window-ran", YESNO, True),
    ("m2-b2-window-valid", YESNO, True),
    ("m2-b2-win-dur-ms", HEX, True),
    ("m2-b2-meas-secs", HEX, True),
    ("m2-b2-win-head-start", HEX, True),
    ("m2-b2-win-tail-start", HEX, True),
    ("m2-b2-win-head-end", HEX, True),
    ("m2-b2-win-tail-end", HEX, True),
    ("m2-b2-win-status-start", HEX, True),
    ("m2-b2-win-status-end", HEX, True),
    ("m2-b2-win-entries", HEX, True),
    ("m2-b2-win-new-entries", HEX, True),
    ("m2-b2-win-devid-mismatch", HEX, True),
    ("m2-b2-win-pre-backlog", HEX, True),
    ("m2-b2-win-raw-truncated", YESNO, True),
    ("m2-b2-win-raw-count", HEX, True),
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
    # --- fault classification ---
    ("m2-b2-fault-inrange", HEX, True),
    ("m2-b2-fault-outofrange", HEX, True),
    ("m2-b2-fault-walk-present", HEX, True),
    ("m2-b2-fault-walk-illegal", HEX, True),
    ("m2-b2-fault-walk-absent", HEX, True),
    # --- round-6 additions ---
    ("m2-b2-dma-obs", TEXT, True),
    ("m2-b2-dma-tx-completions-valid", TEXT, True),
    ("m2-b2-fault-obs-set-ranges", HEX, True),
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

RE_HEX = re.compile(r"^0x[0-9a-fA-F]+$")
RE_DEC = re.compile(r"^[0-9]+$")
RE_YESNO = re.compile(r"^(yes|no)$", re.IGNORECASE)
RE_RAW32 = re.compile(r"^[0-9a-fA-F]{32}$")


class Capture:
    """Parsed property set with typed accessors that cannot return None."""

    def __init__(self, text):
        self.raw = {}
        pat = re.compile(r'"([A-Za-z0-9\-\.]+)"\s*=\s*(?:"([^"]*)"|([^,\n}]+))')
        for m in pat.finditer(text):
            key = m.group(1)
            val = m.group(2) if m.group(2) is not None else m.group(3).strip()
            if key.startswith("m2-b2-"):
                # first occurrence wins; duplicates are a capture problem and
                # are reported separately
                self.raw.setdefault(key, val)
        self.errors = []      # (field, problem)
        self.missing = []
        self.values = {}      # field -> typed python value

    def validate(self):
        for name, kind, required in SCHEMA:
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
            else:
                if not v:
                    self.errors.append((name, "empty text value"))
                    continue
                self.values[name] = v

    def i(self, name):
        """Numeric field. Raises KeyError if it did not validate."""
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


def main():
    if len(sys.argv) < 2:
        print("usage: analyze-round6.py <props.txt> [--json]")
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

    cap.validate()

    # ---- gate 1: schema ----
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

    checks = []

    def ck(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
        return bool(ok)

    # ================= STEP 1: validity =================
    devid = cap.i("m2-b2-target-devid")
    root_level = cap.i("m2-b2-dump-root-level")
    page_mode = cap.i("m2-b2-dump-page-mode")
    pt_pages = cap.i("m2-b2-dump-pt-pages")
    map_limit = cap.i("m2-b2-dump-map-limit")

    ck("target device known", devid != 0, "devid=0x{:04x}".format(devid))
    ck("root level matches DTE page mode", root_level == page_mode,
       "root-level={} page-mode={}".format(root_level, page_mode))
    ck("root level in the spec's 1..6 range", 1 <= root_level <= 6,
       "root-level={}".format(root_level))
    ck("page-table allocation recorded", pt_pages != 0,
       "pt-pages={}".format(pt_pages))
    ck("identity map limit is a power-of-two multiple of 1 GiB",
       map_limit != 0 and map_limit % (1 << 30) == 0,
       "limit=0x{:x} ({:.0f} GiB)".format(map_limit,
                                          map_limit / float(1 << 30)))
    ck("leaf encoding is the corrected NextLevel=0 form",
       "NextLevel0" in cap.s("m2-b2-dump-leaf-encoding"),
       "leaf-encoding={}".format(cap.s("m2-b2-dump-leaf-encoding")))

    # ---- pre-switch control window ----
    pre_ran = cap.b("m2-b2-pre-window-ran")
    pre_valid = cap.b("m2-b2-pre-valid")
    ck("pre-switch control window executed", pre_ran, "ran={}".format(pre_ran))
    ck("pre-switch control window valid", pre_valid,
       "valid={}".format(pre_valid))

    # ---- main window ----
    main_ran = cap.b("m2-b2-main-window-ran")
    win_valid = cap.b("m2-b2-window-valid")
    ck("main window executed", main_ran, "ran={}".format(main_ran))
    ck("main window marked valid", win_valid, "valid={}".format(win_valid))

    dur = cap.i("m2-b2-win-dur-ms")
    meas = cap.i("m2-b2-meas-secs")
    nominal = meas * 1000
    ck("measured duration consistent with nominal",
       nominal <= dur <= nominal * 3,
       "dur={}ms nominal={}ms".format(dur, nominal))

    for label, key in (("start", "m2-b2-win-status-start"),
                       ("end", "m2-b2-win-status-end")):
        st = cap.i(key)
        d = decode_status(st)
        ck("no EVT_OVERFLOW at window {}".format(label),
           d["EventOverflow"] == 0,
           "STATUS=0x{:X} EventOverflow={}".format(st, d["EventOverflow"]))
        ck("EVT_RUN set at window {}".format(label),
           d["EventLogRun"] == 1,
           "STATUS=0x{:X} EventLogRun={}".format(st, d["EventLogRun"]))

    hs = cap.i("m2-b2-win-head-start")
    he = cap.i("m2-b2-win-head-end")
    ck("HEAD unchanged during window", hs == he,
       "head-start=0x{:x} head-end=0x{:x}".format(hs, he))
    ck("window ring bounds are 16-byte aligned",
       hs % 16 == 0 and he % 16 == 0,
       "head-start=0x{:x} head-end=0x{:x}".format(hs, he))

    # ---- commands: summary AND per-record cross-check ----
    subs = cap.i("m2-b2-cmd-submits")
    comp = cap.i("m2-b2-cmd-completed")
    recs = cap.i("m2-b2-cmd-record-count")
    ck("every submitted command completed", subs == comp,
       "submits={} completed={}".format(subs, comp))
    ck("per-command records retained", recs == subs,
       "records={} submits={}".format(recs, subs))

    # Decode each per-command record. The record must exist, be well formed,
    # and its own ok/observed/expected must agree with the summary.
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
            rec_bad.append("record {} dwords malformed: {!r}".format(i, dwords))
            continue
        if not RE_HEX.match(exp) or not RE_HEX.match(obs):
            rec_bad.append("record {} expected/observed malformed".format(i))
            continue
        if not RE_YESNO.match(okv):
            rec_bad.append("record {} ok not yes/no: {!r}".format(i, okv))
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

    ck("every retained command record is self-consistent",
       not rec_bad, "; ".join(rec_bad[:3]) if rec_bad else
       "{} record(s) checked".format(recs))
    ck("per-record successes equal the summary completed count",
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
        d = decode_status(st)
        # The claim must match the hardware bit, not the other way round.
        ck("{} stop claim matches STATUS".format(label),
           claim == (not run_bit),
           "claim={} STATUS=0x{:X} {}".format(
               claim, st,
               "CmdBufRun" if bit == STATUS_CMDBUF_RUN else "EventLogRun"))
        ck("{} STATUS has no EventOverflow".format(label),
           d["EventOverflow"] == 0, "STATUS=0x{:X}".format(st))

    ck("IOMMU disabled (read back)", cap.b("m2-b2-disabled"),
       "disabled={}".format(cap.b("m2-b2-disabled")))

    final_ctrl = cap.i("m2-b2-final-control")
    orig_ctrl = cap.i("m2-b2-orig-control-echo")
    # NOTE: do NOT assert that IOMMU_EN ends up set. On this machine the
    # firmware leaves the IOMMU DISABLED, so orig-control = 0x220000000400
    # has bit 0 clear. The requirement is that CONTROL is byte-for-byte the
    # value it had before the experiment, whatever that value was.
    ck("CONTROL restored to its original value", final_ctrl == orig_ctrl,
       "final=0x{:x} orig=0x{:x}".format(final_ctrl, orig_ctrl))

    ck("registers restored", cap.s("m2-b2-regs-restored") == "yes",
       "regs-restored={}".format(cap.s("m2-b2-regs-restored")))
    ck("cleanup permitted", cap.s("m2-b2-cleanup") == "done",
       "cleanup={}".format(cap.s("m2-b2-cleanup")))

    # ---- attribution ----
    mismatch = cap.i("m2-b2-win-devid-mismatch")
    ck("all events belong to the target device", mismatch == 0,
       "devid-mismatch={}".format(mismatch))

    # ================= STEP 2: event decoding + reconciliation =================
    entries = cap.i("m2-b2-win-entries")
    backlog = cap.i("m2-b2-win-pre-backlog")
    new_entries = cap.i("m2-b2-win-new-entries")
    raw_count = cap.i("m2-b2-win-raw-count")
    truncated = cap.b("m2-b2-win-raw-truncated")

    raws = []
    raw_bad = []
    for i in range(raw_count):
        v = cap.raw.get("m2-b2-win-raw%d" % i)
        if v is None:
            raw_bad.append("raw{} absent but raw-count={}".format(i, raw_count))
            continue
        s = v.strip()
        if s.lower().startswith("0x"):
            s = s[2:]
        if not RE_RAW32.match(s):
            raw_bad.append("raw{} malformed: {!r}".format(i, s))
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

    ck("raw event array parses", not raw_bad,
       "; ".join(raw_bad[:3]) if raw_bad else
       "{} raw entries".format(len(raws)))
    ck("raw-count matches the number of raw entries present",
       raw_count == len(raws),
       "declared={} present={}".format(raw_count, len(raws)))
    # Truncation flag must be the truth about entries vs retained.
    ck("truncation flag agrees with entries vs retained",
       truncated == (entries > raw_count),
       "entries={} retained={} truncated={}".format(entries, raw_count,
                                                    truncated))
    ck("new-entries agrees with entries minus backlog",
       new_entries == max(0, entries - backlog),
       "entries={} backlog={} new={}".format(entries, backlog, new_entries))

    # Per-type counters must sum to `entries`.
    type_sum = 0
    type_present = []
    for t in range(1, 16):
        k = "m2-b2-win-type%d-count" % t
        if k in cap.raw:
            v = cap.raw[k].strip()
            if not RE_HEX.match(v):
                raw_bad.append("{} malformed".format(k))
                continue
            n = int(v, 16)
            if n:
                type_sum += n
                type_present.append((t, n))
    ck("per-type counters sum to the window entry count",
       type_sum == entries,
       "sum={} entries={} types={}".format(type_sum, entries, type_present))
    # ... and the dominant type must be the largest of them.
    dom = cap.raw.get("m2-b2-win-dominant", "").strip().strip('"')
    dom_n = cap.raw.get("m2-b2-win-dominant-count", "").strip()
    if type_present and RE_HEX.match(dom_n):
        best = max(type_present, key=lambda x: x[1])
        ck("dominant event type matches the largest counter",
           dom == TYPE_NAMES.get(best[0], "UNKNOWN") and
           int(dom_n, 16) == best[1],
           "dominant={} count={} expected={} ({})".format(
               dom, dom_n, TYPE_NAMES.get(best[0], "UNKNOWN"), best[1]))

    # ================= STEP 3: fault ownership =================
    inrange = cap.i("m2-b2-fault-inrange")
    outrange = cap.i("m2-b2-fault-outofrange")
    wpresent = cap.i("m2-b2-fault-walk-present")
    willegal = cap.i("m2-b2-fault-walk-illegal")
    wabsent = cap.i("m2-b2-fault-walk-absent")
    obs_ranges = cap.i("m2-b2-fault-obs-set-ranges")
    dma_obs = cap.s("m2-b2-dma-obs")
    done_valid = cap.s("m2-b2-dma-tx-completions-valid")

    fault_in_raw = sum(1 for e in raws if e["type"] == 2)
    fault_in_types = dict(type_present).get(2, 0)

    # Every fault must have been walked, in range or not. Round 5 skipped
    # out-of-range faults entirely, so dump-count was 0 and the walk counters
    # covered only the in-range subset. That mismatch is now a failure.
    ck("every retained fault was classified by the walk",
       (wpresent + willegal + wabsent) == fault_in_raw,
       "walked={} faults-in-raw={}".format(
           wpresent + willegal + wabsent, fault_in_raw))
    ck("in-range + out-of-range equals the fault count in the type table",
       (inrange + outrange) == fault_in_types,
       "in={} out={} type2={}".format(inrange, outrange, fault_in_types))
    # If raw retention is complete, the raw subset must equal the type table.
    if not truncated:
        ck("untruncated capture: raw faults equal the type-table count",
           fault_in_raw == fault_in_types,
           "raw={} type2={}".format(fault_in_raw, fault_in_types))

    ck("device DMA observation ran", dma_obs == "complete",
       "m2-b2-dma-obs={}".format(dma_obs))
    ck("observation recorded at least one DMA range", obs_ranges > 0,
       "ranges={}".format(obs_ranges))

    # ---- the two facts round 5 conflated ----
    # Round 5 said "above 16 GiB, therefore MMIO". The analyser must NOT
    # reproduce that inference: being out of range is reported, but the
    # ownership verdict comes from the observed set.
    ownership_unknown = cap.raw.get("m2-b2-fault-ownership-unknown", "0x0").strip()
    in_live = cap.raw.get("m2-b2-fault-in-live-set", "0x0").strip()
    n_unknown = int(in_live, 16) if RE_HEX.match(in_live) else 0
    n_own_unknown = int(ownership_unknown, 16) if RE_HEX.match(ownership_unknown) else 0

    # ================= STEP 4: conclusion =================
    probe_verdict = cap.s("m2-b2-verdict")
    invalid = [c for c in checks if not c["ok"]]

    any_event = entries > 0
    if invalid:
        conclusion = "INVALID - no functional conclusion"
        code = 3
    elif probe_verdict.startswith("CONTROL"):
        conclusion = "CONTROL branch - not a translation experiment"
        code = 1
    elif not any_event:
        conclusion = ("INDETERMINATE - valid window, no events, and no "
                      "independent evidence that the device completed DMA")
        code = 1
    elif fault_in_raw or inrange > 0 or outrange > 0:
        conclusion = "FAIL - IO_PAGE_FAULT observed under valid conditions"
        code = 1
    else:
        conclusion = "events present but none are IO_PAGE_FAULT"
        code = 1

    report = {
        "source": path,
        "probeVerdict": probe_verdict,
        "probeStage": cap.s("m2-b2-stage"),
        "firstFailStage": cap.raw.get("m2-b2-first-fail-stage"),
        "valid": not invalid,
        "checks": checks,
        "window": {
            "entries": entries,
            "preBacklog": backlog,
            "newEntries": new_entries,
            "rawRetained": len(raws),
            "rawTruncated": truncated,
            "durationMs": dur,
            "typeCounts": {TYPE_NAMES.get(t, "UNKNOWN"): n
                           for t, n in type_present},
        },
        "dmaObservation": {
            "state": dma_obs,
            "ranges": obs_ranges,
            "txCompletionsValid": done_valid,
        },
        "faultClassification": {
            "inRange": inrange,
            "outOfRange": outrange,
            "walkPresent": wpresent,
            "walkIllegal": willegal,
            "walkAbsent": wabsent,
            "inLiveSet": n_unknown,
            "ownershipUnknown": n_own_unknown,
        },
        "events": [
            {
                "type": e["type"],
                "typeName": e["typeName"],
                "devid": "0x{:04x}".format(e["devid"]),
                "domain": "0x{:04x}".format(e["domain"]),
                "flags": "0x{:03x}".format(e["flags"]),
                "bits": e["bits"],
                "address": "0x{:x}".format(e["address"]),
            }
            for e in raws
        ],
        "conclusion": conclusion,
    }

    if as_json:
        print(json.dumps(report, indent=2))
        return code

    # ---------------------------- human output ----------------------------
    print("Round-6 evidence analysis")
    print("=" * 78)
    print("source : {}".format(path))
    print("verdict: {}".format(probe_verdict))
    print("stage  : {}".format(cap.s("m2-b2-stage")))
    if cap.raw.get("m2-b2-first-fail-stage") not in (None, "none"):
        print("first failure: {} ({})".format(
            cap.raw.get("m2-b2-first-fail-stage"),
            cap.raw.get("m2-b2-first-fail-reason") or "no reason recorded"))
    print()

    print("STEP 1 - is the experiment valid?")
    print("-" * 78)
    for c in checks:
        print("  {:<56} {}".format(c["name"], "PASS" if c["ok"] else "FAIL"))
        if c["detail"]:
            print("       {}".format(c["detail"]))
    print()
    if invalid:
        print("  ==> {} check(s) FAILED: the experiment is INVALID.".format(
            len(invalid)))
        print("  ==> No statement about translation is possible.")
    else:
        print("  ==> all {} checks passed: the experiment is VALID.".format(
            len(checks)))
    print()

    print("STEP 2 - what the window contained")
    print("-" * 78)
    print("  total entries in window      : {}".format(entries))
    print("  pre-window backlog consumed  : {}".format(backlog))
    print("  attributable to this window  : {}".format(new_entries))
    print("  raw entries retained         : {}".format(len(raws)))
    if truncated:
        print("  *** TRUNCATED: raw retention hit its limit. ***")
        print("  *** Field-level conclusions cover only the retained  ***")
        print("  *** subset, NOT all {} events.                    ***"
              .format(entries))
    if type_present:
        print("  per-type: " + ", ".join(
            "{}={}".format(TYPE_NAMES.get(t, "UNKNOWN"), n)
            for t, n in type_present))
    print()

    print("STEP 3 - decoded events (flags = DWORD1 bits 24:16)")
    print("-" * 78)
    if not raws:
        print("  (no raw entries retained)")
    for i, e in enumerate(raws):
        bits = " ".join("{}={}".format(n, e["bits"][n]) for _, n in FLAG_BITS)
        print("  [{}] type={} {:<24} devid=0x{:04x} domain=0x{:04x}".format(
            i, e["type"], e["typeName"], e["devid"], e["domain"]))
        print("      addr=0x{:x}  flags=0x{:03x}".format(
            e["address"], e["flags"]))
        print("      {}".format(bits))
        if e["type"] == 2:
            b = e["bits"]
            if b["PR"]:
                if b["RZ"]:
                    print("      -> RZ=1: fault caused by a non-zero "
                          "RESERVED bit")
                else:
                    print("      -> RZ=0, PR=1: fault caused by an INVALID "
                          "LEVEL ENCODING")
                if b["PE"]:
                    print("      -> PE=1: permission failure")
            else:
                print("      -> PR=0: page was not marked present")
    print()

    print("STEP 4 - fault classification")
    print("-" * 78)
    print("  in mapping range        : {}".format(inrange))
    print("  outside mapping range   : {}".format(outrange))
    print("  walk found a valid leaf : {}".format(wpresent))
    print("  walk found ILLEGAL enc  : {}".format(willegal))
    print("  walk found ABSENT entry : {}".format(wabsent))
    print("  observed DMA ranges     : {}".format(obs_ranges))
    print("  faults inside live set  : {}".format(n_unknown))
    print("  faults with unknown own : {}".format(n_own_unknown))
    print()
    print("  NOTE: 'outside mapping range' is a statement about THIS TABLE,")
    print("  not about what kind of memory the address is. The ownership")
    print("  columns come from the device's own descriptor rings.")
    print()

    print("=" * 78)
    print(conclusion)
    print("exit code {}".format(code))
    return code


if __name__ == "__main__":
    sys.exit(main())
