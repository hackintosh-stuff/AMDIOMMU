#!/usr/bin/env python3
"""Round-4 evidence analyser.

Unlike analyze-round3.py, this script does NOT contain hardcoded sample values.
It reads the actual `ioreg` dump from a timestamped evidence directory and
reports every required field, flagging missing ones explicitly.

That distinction matters: round 3's analyser embedded the numbers it was
"analysing", so it could not detect that a field was absent from the real
capture, and it re-derived the same model rather than reading the machine.

Usage:
    py -3 tools/analyze-round4.py docs/evidence/<stamp>/props.txt
    py -3 tools/analyze-round4.py docs/evidence/<stamp>/props.txt --json
"""
import json
import re
import sys

# Fields the probe must publish for a window to be considered analysable.
REQUIRED = [
    ("m2-b2-verdict", "string"),
    ("m2-b2-stage", "string"),
    ("m2-b2-meas-secs", "hex"),
    ("m2-b2-window-valid", "string"),
    ("m2-b2-win-dur-ms", "hex"),
    ("m2-b2-win-head-start", "hex"),
    ("m2-b2-win-tail-start", "hex"),
    ("m2-b2-win-head-end", "hex"),
    ("m2-b2-win-tail-end", "hex"),
    ("m2-b2-win-status-start", "hex"),
    ("m2-b2-win-status-end", "hex"),
    ("m2-b2-win-entries", "hex"),
    ("m2-b2-win-devid-mismatch", "hex"),
    ("m2-b2-target-devid", "hex"),
    ("m2-b2-cmd-submits", "hex"),
    ("m2-b2-cmd-completed", "hex"),
    ("m2-b2-inv-domid", "hex"),
    ("m2-b2-cleanup", "string"),
    ("m2-b2-regs-restored", "string"),
]

# Fields that are required only in some branches.
CONDITIONAL = {
    "m2-b2-window-invalid": "when m2-b2-window-valid = no",
    "m2-b2-evt-reset": "always, but tolerated missing in old captures",
    "m2-b2-disabled": "always",
    "m2-b2-evtlog-stopped": "always",
}

EVT_OVERFLOW = 1 << 0
EVT_RUN = 1 << 3

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


def parse_props(text):
    """Parse `key = value` lines from an ioreg dump.

    Accepts both `"key" = "value"` (quoted strings) and `"key" = 0x...`
    (numbers), which is how ioreg emits them.
    """
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
        if v.lower().startswith("0x"):
            return int(v, 16)
        return int(v, 10)
    except ValueError:
        return None


def main():
    if len(sys.argv) < 2:
        print("usage: analyze-round4.py <props.txt> [--json]")
        return 2

    path = sys.argv[1]
    as_json = "--json" in sys.argv

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except IOError as e:
        print("cannot read {}: {}".format(path, e))
        return 2

    props = parse_props(text)
    if not props:
        print("no m2-b2-* properties found in {}".format(path))
        return 2

    report = {"source": path, "missing": [], "warnings": [], "checks": []}

    # ---- required fields ----
    for key, kind in REQUIRED:
        if key not in props:
            report["missing"].append({"field": key, "required": kind})
    for key, why in CONDITIONAL.items():
        if key not in props:
            report["warnings"].append({"field": key, "note": why})

    def get(key):
        return props.get(key)

    def geti(key):
        return as_int(props.get(key))

    # ---- window validity ----
    valid = (get("m2-b2-window-valid") or "").lower()
    dur = geti("m2-b2-win-dur-ms")
    meas = geti("m2-b2-meas-secs")
    status_end = geti("m2-b2-win-status-end")
    status_start = geti("m2-b2-win-status-start")
    entries = geti("m2-b2-win-entries")
    mismatch = geti("m2-b2-win-devid-mismatch")

    report["checks"].append({
        "name": "window marked valid", "ok": valid == "yes",
        "detail": "m2-b2-window-valid = {}".format(get("m2-b2-window-valid")),
    })

    if dur is not None and meas is not None:
        nominal = meas * 1000
        # IOSleep guarantees "at least"; allow generous overshoot.
        ok = dur >= nominal and dur <= nominal * 3
        report["checks"].append({
            "name": "measured duration consistent with nominal",
            "ok": ok,
            "detail": "dur={} ms, nominal={} ms".format(dur, nominal),
        })
    else:
        report["checks"].append({
            "name": "measured duration present", "ok": False,
            "detail": "dur={} meas={}".format(dur, meas),
        })

    for label, st in (("start", status_start), ("end", status_end)):
        if st is None:
            continue
        report["checks"].append({
            "name": "no EVT_OVERFLOW at window {}".format(label),
            "ok": (st & EVT_OVERFLOW) == 0,
            "detail": "STATUS=0x{:X}".format(st),
        })
        report["checks"].append({
            "name": "EVT_RUN set at window {}".format(label),
            "ok": (st & EVT_RUN) != 0,
            "detail": "STATUS=0x{:X}".format(st),
        })

    # ---- command completion ----
    subs = geti("m2-b2-cmd-submits")
    comp = geti("m2-b2-cmd-completed")
    if subs is not None and comp is not None:
        report["checks"].append({
            "name": "every submitted command completed",
            "ok": subs == comp,
            "detail": "submits={} completed={}".format(subs, comp),
        })
    else:
        report["checks"].append({
            "name": "command counters present", "ok": False,
            "detail": "submits={} completed={}".format(subs, comp),
        })

    # ---- recovery ----
    report["checks"].append({
        "name": "registers restored",
        "ok": (get("m2-b2-regs-restored") or "") == "yes",
        "detail": "m2-b2-regs-restored = {}".format(
            get("m2-b2-regs-restored")),
    })
    report["checks"].append({
        "name": "cleanup permitted",
        "ok": (get("m2-b2-cleanup") or "") == "done",
        "detail": "m2-b2-cleanup = {}".format(get("m2-b2-cleanup")),
    })

    # ---- device attribution ----
    if mismatch is not None:
        report["checks"].append({
            "name": "all events belong to the target device",
            "ok": mismatch == 0,
            "detail": "devid-mismatch={}".format(mismatch),
        })

    # ---- event type decoding from raw bytes ----
    raw = []
    i = 0
    while True:
        v = get("m2-b2-win-raw{}".format(i))
        if v is None:
            break
        raw.append(v)
        i += 1
    decoded = []
    for v in raw:
        s = v.strip().lower()
        if s.startswith("0x"):
            s = s[2:]
        if len(s) != 32:
            report["warnings"].append({
                "field": "raw", "note": "unexpected raw length: " + v})
            continue
        w = [int(s[j:j + 8], 16) for j in range(0, 32, 8)]
        etype = (w[1] >> 28) & 0xF
        flags = (w[1] >> 16) & 0xFFF
        devid = w[0] & 0xFFFF
        addr = (w[3] << 32) | w[2]
        decoded.append({
            "type": etype,
            "typeName": TYPE_NAMES.get(etype, "UNKNOWN"),
            "devid": "0x{:04x}".format(devid),
            "flags": "0x{:03x}".format(flags),
            "rw": bool(flags & 0x020),
            "instr": bool(flags & 0x008),
            "address": "0x{:x}".format(addr),
        })
    report["decodedEvents"] = decoded

    # ---- verdict ----
    verdict = get("m2-b2-verdict") or ""
    report["verdict"] = verdict
    if verdict.startswith("INVALID"):
        report["conclusion"] = "EXPERIMENT INVALID - no causal conclusion"
    elif verdict.startswith("INDETERMINATE"):
        report["conclusion"] = "INDETERMINATE - conditions met, no decisive evidence"
    elif verdict.startswith("FAIL"):
        report["conclusion"] = "FAIL - concrete failure observed under valid conditions"
    elif verdict.startswith("PASS"):
        report["conclusion"] = "PASS - requires full functional acceptance"
    else:
        report["conclusion"] = "UNRECOGNISED verdict"

    if as_json:
        print(json.dumps(report, indent=2))
        return 0 if not report["missing"] else 1

    # ---- human report ----
    print("Round-4 evidence analysis")
    print("=" * 74)
    print("source : {}".format(path))
    print("verdict: {}".format(verdict or "<missing>"))
    print()
    print("Required fields")
    print("-" * 74)
    if report["missing"]:
        print("  MISSING ({}):".format(len(report["missing"])))
        for m in report["missing"]:
            print("    {:<34} ({})".format(m["field"], m["required"]))
    else:
        print("  all {} required fields present".format(len(REQUIRED)))
    if report["warnings"]:
        print("  conditional/optional absent:")
        for w in report["warnings"]:
            print("    {:<34} {}".format(w["field"], w["note"]))

    print()
    print("Checks")
    print("-" * 74)
    for c in report["checks"]:
        print("  {:<52} {}".format(c["name"], "PASS" if c["ok"] else "FAIL"))
        if c.get("detail"):
            print("       {}".format(c["detail"]))

    print()
    print("Decoded raw events ({})".format(len(decoded)))
    print("-" * 74)
    if not decoded:
        print("  (none captured)")
    for e in decoded:
        print("  type={:<2} {:<26} devid={} rw={} addr={}".format(
            e["type"], e["typeName"], e["devid"], e["rw"], e["address"]))

    print()
    print("=" * 74)
    print(report["conclusion"])
    if entries is not None:
        print("window entries = {}".format(entries))
    return 0 if not report["missing"] else 1


if __name__ == "__main__":
    sys.exit(main())
