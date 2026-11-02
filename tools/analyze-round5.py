#!/usr/bin/env python3
"""Round-5 evidence analyser.

DESIGN RULE
-----------
This script decides whether the experiment was VALID **before** it says
anything about the functional result. If a required field is missing, or a
required check fails, it must not print "failed under valid conditions" or
"passed" -- it prints INVALID and exits non-zero.

Round 4's analyser checked a handful of fields and then always reported a
conclusion; it also had no way to tell "the main window never ran" from
"the main window ran and saw nothing".

EXIT CODES
    0  experiment VALID and the functional result is a PASS
    1  experiment VALID and the functional result is FAIL or INDETERMINATE
    2  the capture cannot be analysed (missing/unparseable fields)
    3  the experiment was INVALID (a required check failed)
    4  usage error

So CI or a shell `&&` chain can gate on validity separately from outcome.

Usage:
    py -3 tools/analyze-round5.py docs/evidence/<stamp>/props.txt
    py -3 tools/analyze-round5.py docs/evidence/<stamp>/props.txt --json
"""
import json
import re
import sys

# ---------------------------------------------------------------------------
# Fields that MUST be present for the capture to be analysable at all.
# Absence of any of these => exit 2 (cannot analyse), never a conclusion.
# ---------------------------------------------------------------------------
REQUIRED = [
    # identity / configuration
    "m2-b2-verdict",
    "m2-b2-stage",
    "m2-b2-target-devid",
    "m2-b2-dump-root-pa",
    "m2-b2-dump-root-level",
    "m2-b2-dump-page-mode",
    "m2-b2-dump-pt-pages",
    # window 1 (pre-switch control)
    "m2-b2-pre-window-ran",
    "m2-b2-pre-valid",
    # window 2 (main)
    "m2-b2-main-window-ran",
    "m2-b2-window-valid",
    "m2-b2-win-dur-ms",
    "m2-b2-meas-secs",
    "m2-b2-win-head-start",
    "m2-b2-win-tail-start",
    "m2-b2-win-head-end",
    "m2-b2-win-tail-end",
    "m2-b2-win-status-start",
    "m2-b2-win-status-end",
    "m2-b2-win-entries",
    "m2-b2-win-devid-mismatch",
    "m2-b2-win-pre-backlog",
    "m2-b2-win-raw-truncated",
    # commands
    "m2-b2-cmd-submits",
    "m2-b2-cmd-completed",
    "m2-b2-cmd-record-count",
    # recovery
    "m2-b2-disabled",
    "m2-b2-cmdbuf-stopped",
    "m2-b2-evtlog-stopped",
    "m2-b2-regs-restored",
    "m2-b2-cleanup",
    # fault classification
    "m2-b2-fault-inrange",
    "m2-b2-fault-walk-present",
    "m2-b2-fault-walk-illegal",
    "m2-b2-fault-walk-absent",
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
    0xd: "RMP_FAULT",
    0xe: "RMP_HW_ERROR",
}

# IO_PAGE_FAULT flags live in DWORD1 bits 24:16 (spec Table 57).
# Field bit 0 == DWORD1 bit 16. The low half of DWORD1 is DomainID.
FLAG_BITS = [
    (0, "GN"), (1, "NX"), (2, "US"), (3, "I"), (4, "PR"),
    (5, "RW"), (6, "PE"), (7, "RZ"), (8, "TR"),
]


def parse_props(text):
    out = {}
    pat = re.compile(r'"([A-Za-z0-9\-\.]+)"\s*=\s*(?:"([^"]*)"|([^,\n}]+))')
    for m in pat.finditer(text):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else m.group(3).strip()
        if key.startswith("m2-b2-"):
            out[key] = val
    return out


def as_int(v):
    if v is None:
        return None
    v = v.strip()
    try:
        return int(v, 16) if v.lower().startswith("0x") else int(v, 10)
    except ValueError:
        return None


def main():
    if len(sys.argv) < 2:
        print("usage: analyze-round5.py <props.txt> [--json]")
        return 4
    path = sys.argv[1]
    as_json = "--json" in sys.argv

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            props = parse_props(f.read())
    except IOError as e:
        print("cannot read {}: {}".format(path, e))
        return 4

    if not props:
        print("no m2-b2-* properties found in {}".format(path))
        return 2

    missing = [k for k in REQUIRED if k not in props]
    if missing:
        if as_json:
            print(json.dumps({"source": path, "missing": missing,
                              "conclusion": "CANNOT ANALYSE"}, indent=2))
        else:
            print("CANNOT ANALYSE: {} required field(s) missing".format(
                len(missing)))
            for m in missing:
                print("  " + m)
            print()
            print("No conclusion is drawn. A capture without these fields")
            print("cannot establish whether the experiment was valid.")
        return 2

    def g(k):
        return props.get(k)

    def gi(k):
        return as_int(props.get(k))

    checks = []

    def ck(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
        return ok

    # ================= STEP 1: was the experiment VALID? =================
    devid = gi("m2-b2-target-devid")
    root_level = gi("m2-b2-dump-root-level")
    page_mode = gi("m2-b2-dump-page-mode")
    pt_pages = gi("m2-b2-dump-pt-pages")

    ck("target device known", devid not in (None, 0),
       "devid=0x{:04x}".format(devid or 0))

    # A Mode=N table has a level-N root (spec Table 7/15).
    ck("root level matches DTE page mode", root_level == page_mode,
       "root-level={} page-mode={}".format(root_level, page_mode))

    # The table must be a plausible allocation (not zero, not absurd).
    ck("page-table allocation recorded", pt_pages not in (None, 0),
       "pt-pages={}".format(pt_pages))

    # ---- pre-switch control window ----
    pre_ran = (g("m2-b2-pre-window-ran") or "").lower() == "yes"
    pre_valid = (g("m2-b2-pre-valid") or "").lower() == "yes"
    ck("pre-switch control window executed", pre_ran,
       "m2-b2-pre-window-ran={}".format(g("m2-b2-pre-window-ran")))
    ck("pre-switch control window valid", pre_valid,
       "m2-b2-pre-valid={}".format(g("m2-b2-pre-valid")))

    # ---- main window ----
    main_ran = (g("m2-b2-main-window-ran") or "").lower() == "yes"
    win_valid = (g("m2-b2-window-valid") or "").lower() == "yes"
    ck("main window executed", main_ran,
       "m2-b2-main-window-ran={}".format(g("m2-b2-main-window-ran")))
    ck("main window marked valid", win_valid,
       "m2-b2-window-valid={}".format(g("m2-b2-window-valid")))

    dur = gi("m2-b2-win-dur-ms")
    meas = gi("m2-b2-meas-secs")
    if dur is not None and meas is not None:
        nominal = meas * 1000
        ck("measured duration consistent with nominal",
           nominal <= dur <= nominal * 3,
           "dur={}ms nominal={}ms".format(dur, nominal))
    else:
        ck("measured duration present", False, "dur/meas missing")

    for label, key in (("start", "m2-b2-win-status-start"),
                       ("end", "m2-b2-win-status-end")):
        st = gi(key)
        if st is None:
            ck("STATUS at window {} present".format(label), False, "")
            continue
        ck("no EVT_OVERFLOW at window {}".format(label),
           (st & STATUS_EVT_OVERFLOW) == 0, "STATUS=0x{:X}".format(st))
        ck("EVT_RUN set at window {}".format(label),
           (st & STATUS_EVT_RUN) != 0, "STATUS=0x{:X}".format(st))

    # HEAD must not move during a window (software owns it).
    hs, he = gi("m2-b2-win-head-start"), gi("m2-b2-win-head-end")
    ck("HEAD unchanged during window", hs == he,
       "head-start={} head-end={}".format(hs, he))

    # ---- commands ----
    subs = gi("m2-b2-cmd-submits")
    comp = gi("m2-b2-cmd-completed")
    recs = gi("m2-b2-cmd-record-count")
    ck("every submitted command completed", subs == comp,
       "submits={} completed={}".format(subs, comp))
    ck("per-command records retained", recs == subs,
       "records={} submits={}".format(recs, subs))

    # ---- recovery ----
    ck("IOMMU disabled (read back)", (g("m2-b2-disabled") or "") == "yes",
       "m2-b2-disabled={}".format(g("m2-b2-disabled")))
    ck("command buffer stopped (CmdBufRun==0)",
       (g("m2-b2-cmdbuf-stopped") or "") == "yes",
       "m2-b2-cmdbuf-stopped={}".format(g("m2-b2-cmdbuf-stopped")))
    ck("event log stopped (EventLogRun==0)",
       (g("m2-b2-evtlog-stopped") or "") == "yes",
       "m2-b2-evtlog-stopped={}".format(g("m2-b2-evtlog-stopped")))
    ck("registers restored", (g("m2-b2-regs-restored") or "") == "yes",
       "m2-b2-regs-restored={}".format(g("m2-b2-regs-restored")))
    ck("cleanup permitted", (g("m2-b2-cleanup") or "") == "done",
       "m2-b2-cleanup={}".format(g("m2-b2-cleanup")))

    # ---- attribution ----
    mismatch = gi("m2-b2-win-devid-mismatch")
    ck("all events belong to the target device", mismatch == 0,
       "devid-mismatch={}".format(mismatch))

    # The verdict the probe itself reached must not contradict the checks.
    probe_verdict = g("m2-b2-verdict") or ""

    invalid = [c for c in checks if not c["ok"]]

    # ================= STEP 2: event decoding =================
    entries = gi("m2-b2-win-entries")
    backlog = gi("m2-b2-win-pre-backlog") or 0
    truncated = (g("m2-b2-win-raw-truncated") or "").lower() == "yes"

    raws = []
    for i in range(64):
        v = g("m2-b2-win-raw{}".format(i))
        if v is None:
            continue
        s = v.strip().lower()
        if s.startswith("0x"):
            s = s[2:]
        if len(s) != 32:
            continue
        w = [int(s[j:j + 8], 16) for j in range(0, 32, 8)]
        d0, d1, d2, d3 = w
        flags = (d1 >> 16) & 0x1FF
        raws.append({
            "raw": s,
            "devid": d0 & 0xFFFF,
            "domain": d1 & 0xFFFF,
            "type": (d1 >> 28) & 0xF,
            "typeName": TYPE_NAMES.get((d1 >> 28) & 0xF, "UNKNOWN"),
            "flags": flags,
            "bits": {n: (flags >> b) & 1 for b, n in FLAG_BITS},
            "address": ((d3 & 0xFFFFFFFF) << 32) | (d2 & 0xFFFFFFFF),
        })

    # ================= STEP 3: functional result =================
    inrange = gi("m2-b2-fault-inrange")
    wpresent = gi("m2-b2-fault-walk-present")
    willegal = gi("m2-b2-fault-walk-illegal")
    wabsent = gi("m2-b2-fault-walk-absent")

    new_entries = (entries - backlog) if (entries is not None and
                                          entries >= backlog) else 0
    any_event = bool(entries and entries > 0)
    fault_events = sum(1 for e in raws if e["type"] == 2)

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
    elif fault_events or (inrange or 0) > 0:
        conclusion = "FAIL - IO_PAGE_FAULT observed under valid conditions"
        code = 1
    else:
        conclusion = "events present but none are IO_PAGE_FAULT"
        code = 1

    report = {
        "source": path,
        "probeVerdict": probe_verdict,
        "probeStage": g("m2-b2-stage"),
        "firstFailStage": g("m2-b2-first-fail-stage"),
        "valid": not invalid,
        "checks": checks,
        "window": {
            "entries": entries,
            "preBacklog": backlog,
            "newEntries": new_entries,
            "rawRetained": len(raws),
            "rawTruncated": truncated,
            "durationMs": dur,
        },
        "faultClassification": {
            "inRange": inrange,
            "walkPresent": wpresent,
            "walkIllegal": willegal,
            "walkAbsent": wabsent,
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
    print("Round-5 evidence analysis")
    print("=" * 78)
    print("source : {}".format(path))
    print("verdict: {}".format(probe_verdict or "<missing>"))
    print("stage  : {}".format(g("m2-b2-stage")))
    if g("m2-b2-first-fail-stage") not in (None, "none"):
        print("first failure: {} ({})".format(
            g("m2-b2-first-fail-stage"),
            g("m2-b2-first-fail-reason") or "no reason recorded"))
    print()

    print("STEP 1 - is the experiment valid?")
    print("-" * 78)
    for c in checks:
        print("  {:<50} {}".format(c["name"], "PASS" if c["ok"] else "FAIL"))
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

    print("STEP 4 - fault classification against the exported table")
    print("-" * 78)
    print("  in mapping range        : {}".format(inrange))
    print("  walk found a valid leaf : {}".format(wpresent))
    print("  walk found ILLEGAL enc  : {}".format(willegal))
    print("  walk found ABSENT entry : {}".format(wabsent))
    print()

    print("=" * 78)
    print(conclusion)
    print("exit code {}".format(code))
    return code


if __name__ == "__main__":
    sys.exit(main())
