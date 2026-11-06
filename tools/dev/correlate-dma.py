#!/usr/bin/env python3
"""Correlate the probe's translation window with externally-measured traffic.

WHY THIS EXISTS, AND WHAT ROUND 5 GOT WRONG
-------------------------------------------
Round 5 concluded "56 packets moved under translation" from a difference of
two `netstat` samples taken at whole-second boundaries. That claim has four
problems the task calls out:

  1. Second resolution against a 3-second window means the boundary
     attribution is +/- 1 s, i.e. up to 2/3 of the window.
  2. The probe's wall clock (`clock_get_calendar_nanotime`) and the shell's
     `date +%s` are two different time bases. Round 5 never recorded the
     correspondence between them, so the alignment was assumed.
  3. A missing sample and a zero delta were indistinguishable: if the
     sampler did not cover the window, the code fell back to the nearest
     sample and reported a number anyway.
  4. Interface counters are published by the driver from a hardware counter
     dump, and that dump can lag. So a counter delta is NOT the number of
     DMA operations completed inside the window -- it is an upper bound on
     activity that had completed and been published by the closing sample.

This version:
  * requires samples that actually bracket both window edges, and refuses to
    report a delta when they do not
  * works in milliseconds
  * records the sampler's own identity and load outcome instead of assuming
    them
  * separates "counter advanced" from "DMA completed in the window", and
    names the lag explicitly
  * treats the probe's own descriptor-based completion count as the primary
    evidence, and this sampler as corroboration
  * refuses to report a delta across a counter reset

Usage:
    py -3 tools/dev/correlate-dma.py <dma-window.tsv> <props.txt> [--json]

Exit codes:
    0  window covered and traffic observed
    1  window covered but no traffic observed
    2  cannot correlate (no coverage / missing fields / counter reset)
"""
import io
import json
import re
import sys


def parse_props(text):
    out = {}
    pat = re.compile(r'"([A-Za-z0-9\-\.]+)"\s*=\s*(?:"([^"]*)"|([^,\n}]+))')
    for m in pat.finditer(text):
        k = m.group(1)
        v = m.group(2) if m.group(2) is not None else m.group(3).strip()
        out[k] = v
    return out


def as_int(v):
    if v is None:
        return None
    v = v.strip()
    try:
        return int(v, 16) if v.lower().startswith("0x") else int(v, 10)
    except ValueError:
        return None


def parse_tsv(path):
    rows = []
    for line in io.open(path, encoding="utf-8", errors="replace"):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        if line.startswith("wall_ms"):
            continue
        f = line.split("\t")
        if len(f) < 5:
            continue
        try:
            rows.append({
                "t": int(f[0]), "ipkts": int(f[1]), "ierrs": int(f[2]),
                "opkts": int(f[3]), "oerrs": int(f[4]),
            })
        except ValueError:
            continue
    rows.sort(key=lambda r: r["t"])
    return rows


def parse_meta(path):
    out = {}
    try:
        for line in io.open(path, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    except IOError:
        return out
    return out


def sample_at(rows, t):
    """Last sample at or before t, or None."""
    best = None
    for r in rows:
        if r["t"] <= t:
            best = r
        else:
            break
    return best


def sample_after(rows, t):
    """First sample at or after t, or None."""
    for r in rows:
        if r["t"] >= t:
            return r
    return None


def strip(d):
    """Flatten a delta for both JSON and the human report.

    The sample rows are kept under `fromRow` / `toRow` so emit() can print
    the absolute counters without depending on keys that were dropped.
    """
    if d is None:
        return None
    out = {k: v for k, v in d.items() if k not in ("from", "to")}
    out["fromRow"] = d.get("from")
    out["toRow"] = d.get("to")
    return out


def emit(result, as_json, code):
    if as_json:
        print(json.dumps(result, indent=2))
        return code

    print("DMA correlation")
    print("=" * 78)
    print("sampler : {}".format(result["source_tsv"]))
    print("props   : {}".format(result["source_props"]))
    print("samples : {}".format(result["samples"]))
    meta = result.get("meta") or {}
    if meta:
        print("iface   : {} (link#{})".format(meta.get("iface", "?"),
                                              meta.get("linkno", "?")))
        print("src     : {}".format(meta.get("srcaddr", "?")))
        print("load    : sent={} received={}".format(
            meta.get("load_sent", "?"), meta.get("load_received", "?")))
    print()

    for label in ("pre", "main"):
        w = result["windows"].get(label)
        if not w:
            continue
        name = ("PRE  (DTE passthrough)" if label == "pre"
                else "MAIN (DTE translation)")
        print("{}  [{} .. {}] ms".format(name, w["lo_ms"], w["hi_ms"]))
        d = w.get("delta")
        if d is None:
            print("  no sample coverage")
        else:
            print("  bracket {} .. {} ms (span {} ms)".format(
                d["from_t"], d["to_t"], d["to_t"] - d["from_t"]))
            fr, to = d.get("fromRow"), d.get("toRow")
            if fr is not None and to is not None:
                print("    ipkts {} -> {}  (+{})".format(
                    fr["ipkts"], to["ipkts"], d["ipkts"]))
                print("    opkts {} -> {}  (+{})".format(
                    fr["opkts"], to["opkts"], d["opkts"]))
            else:
                print("    ipkts delta +{}  opkts delta +{}".format(
                    d["ipkts"], d["opkts"]))
            print("    errors i/o +{} / +{}".format(d["ierrs"], d["oerrs"]))
        print()

    pc = result.get("probe_completion") or {}
    print("Probe-side completion evidence (primary)")
    print("-" * 78)
    print("  observation state       : {}".format(pc.get("state", "?")))
    print("  TX DescOwn-cleared delta: {} ({})".format(
        pc.get("completions"), pc.get("valid", "?")))
    print()

    print("=" * 78)
    print(result["status"])
    print(result["reason"])
    print()
    print("HOW TO READ THIS")
    print("-" * 78)
    print("  The interface counters are published by the driver from a")
    print("  hardware counter dump, so they can lag the actual traffic. A")
    print("  delta therefore says 'this much activity had completed and been")
    print("  published by the closing sample'. It is NOT a count of DMA")
    print("  operations inside the window, and on its own it cannot tell a")
    print("  stalled data path from a stalled statistics dump.")
    print()
    print("  The primary evidence is the TX descriptor DescOwn delta the")
    print("  probe reads straight from the ring: the hardware clears that")
    print("  bit when it has finished a transfer, independent of the")
    print("  driver's statistics path. When the two disagree, trust the")
    print("  descriptor, and say so.")
    return code


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv
    if len(args) < 2:
        print("usage: correlate-dma.py <dma-window.tsv> <props.txt> [--json]")
        return 2
    tsv, props_path = args[0], args[1]

    props = parse_props(io.open(props_path, encoding="utf-8",
                                errors="replace").read())
    rows = parse_tsv(tsv)
    meta = parse_meta(re.sub(r"\.tsv$", ".meta", tsv))

    result = {
        "source_tsv": tsv,
        "source_props": props_path,
        "samples": len(rows),
        "meta": meta,
        "status": None,
        "reason": None,
        "windows": {},
    }

    if not rows:
        result["status"] = "CANNOT-CORRELATE"
        result["reason"] = "the sampler produced no rows"
        return emit(result, as_json, 2)

    pre_s = as_int(props.get("m2-b2-pre-wall-start"))
    pre_e = as_int(props.get("m2-b2-pre-wall-end"))
    win_s = as_int(props.get("m2-b2-win-wall-start"))
    win_e = as_int(props.get("m2-b2-win-wall-end"))
    dur_ms = as_int(props.get("m2-b2-win-dur-ms"))

    if None in (pre_s, pre_e, win_s, win_e):
        result["status"] = "CANNOT-CORRELATE"
        result["reason"] = ("the probe did not publish all four wall-clock "
                            "bounds")
        return emit(result, as_json, 2)

    # The probe publishes whole seconds only. Widen to a conservative
    # interval rather than pretending to millisecond precision: the window
    # started somewhere inside [win_s, win_s+1) and ended inside
    # [win_e, win_e+1).
    win_lo = win_s * 1000
    win_hi = (win_e + 1) * 1000
    pre_lo = pre_s * 1000
    pre_hi = (pre_e + 1) * 1000

    result["windows"]["main"] = {"lo_ms": win_lo, "hi_ms": win_hi,
                                 "nominal_ms": dur_ms}
    result["windows"]["pre"] = {"lo_ms": pre_lo, "hi_ms": pre_hi}

    pre_a = sample_at(rows, pre_lo)
    pre_b = sample_after(rows, pre_hi)
    win_a = sample_at(rows, win_lo)
    win_b = sample_after(rows, win_hi)

    if win_a is None or win_b is None:
        result["status"] = "CANNOT-CORRELATE"
        result["reason"] = (
            "the sampler does not bracket the translation window "
            "(first sample %d, last sample %d, window %d..%d ms)"
            % (rows[0]["t"], rows[-1]["t"], win_lo, win_hi))
        return emit(result, as_json, 2)

    covered_ms = win_b["t"] - win_a["t"]
    result["windows"]["main"]["covered_ms"] = covered_ms
    if dur_ms is not None and covered_ms + 2000 < dur_ms:
        result["status"] = "CANNOT-CORRELATE"
        result["reason"] = (
            "sample span %d ms is much shorter than the %d ms window"
            % (covered_ms, dur_ms))
        return emit(result, as_json, 2)

    def delta(a, b):
        if a is None or b is None:
            return None
        return {
            "ipkts": b["ipkts"] - a["ipkts"],
            "opkts": b["opkts"] - a["opkts"],
            "ierrs": b["ierrs"] - a["ierrs"],
            "oerrs": b["oerrs"] - a["oerrs"],
            "from_t": a["t"], "to_t": b["t"],
            "from": a, "to": b,
        }

    pre_d = delta(pre_a, pre_b)
    win_d = delta(win_a, win_b)
    result["windows"]["pre"]["delta"] = strip(pre_d)
    result["windows"]["main"]["delta"] = strip(win_d)

    # ---- counter resets / wrap ----
    resets = []
    prev = None
    for r in rows:
        if prev is not None:
            if r["ipkts"] < prev["ipkts"] or r["opkts"] < prev["opkts"]:
                resets.append({"t": r["t"],
                               "ipkts": [prev["ipkts"], r["ipkts"]],
                               "opkts": [prev["opkts"], r["opkts"]]})
        prev = r
    result["counter_resets"] = resets
    if resets:
        result["status"] = "CANNOT-CORRELATE"
        result["reason"] = ("interface counters went backwards %d time(s); "
                            "a delta across a reset is meaningless"
                            % len(resets))
        return emit(result, as_json, 2)

    # ---- the probe's own, better evidence ----
    result["probe_completion"] = {
        "state": props.get("m2-b2-dma-obs", ""),
        "valid": props.get("m2-b2-dma-tx-completions-valid", ""),
        "completions": as_int(props.get("m2-b2-dma-tx-completions")),
    }

    tx = win_d["opkts"] if win_d else 0
    rx = win_d["ipkts"] if win_d else 0
    errs = (win_d["ierrs"] + win_d["oerrs"]) if win_d else 0
    result["windows"]["main"]["tx"] = tx
    result["windows"]["main"]["rx"] = rx
    result["windows"]["main"]["errors"] = errs

    if tx > 0 or rx > 0:
        result["status"] = "TRAFFIC-OBSERVED"
        result["reason"] = ("the interface counters advanced across the "
                            "translation window")
        code = 0
    else:
        result["status"] = "NO-TRAFFIC"
        result["reason"] = ("the interface counters did not advance across "
                            "the translation window")
        code = 1

    return emit(result, as_json, code)


if __name__ == "__main__":
    sys.exit(main())
