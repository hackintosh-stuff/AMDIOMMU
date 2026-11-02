#!/usr/bin/env python3
"""Decode the round-4 raw event entries with the CORRECT flag field.

Why this rewrite
----------------
The first version of this script read the flags as `dword1 & 0xFFFF`.
That is wrong. Per AMD IOMMU Spec 48882 Rev 3.10, Table 57
("IO_PAGE_FAULT Event Log Buffer Entry Fields"), DWORD1 is laid out as:

    bits 31:28   EventCode (0010b = IO_PAGE_FAULT)
    bits 27:25   Reserved
    bit  24      TR   translation / transaction
    bit  23      RZ   reserved bit not zero OR invalid level encoding
    bit  22      PE   permission indicator
    bit  21      RW   read/write
    bit  20      PR   present
    bit  19      I    interrupt
    bit  18      US   user/supervisor
    bit  17      NX   no execute
    bit  16      GN   guest/nested
    bits 15:0    D/P  DomainID or PASID

So the flag field is DWORD1 bits 24:16, i.e. (dword1 >> 16) & 0x1FF,
NOT (dword1 & 0xFFFF) -- the low half is the DomainID.

This matters: round 4's summary said only "all events are type 2". The
DomainID in those entries is 0 (consistent with the experiment's domain 0),
which a low-half read reports as "flags = 0x0000" and thus as "no flags at
all" -- hiding the fact that PR and RW are set.

Usage:
    py -3 tools/extract-raw-events.py docs/evidence/<stamp>/props.txt
    py -3 tools/extract-raw-events.py docs/evidence/<stamp>/props.txt --json
"""
import json
import re
import sys

# ---------------------------------------------------------------------------
# IO_PAGE_FAULT flag bits: DWORD1 bits 24:16, expressed here as offsets
# into the 9-bit flag field (bit 0 of the field == DWORD1 bit 16).
#
# Source: AMD IOMMU Spec 48882 Rev 3.10, Table 57 (pp. 152-153).
# Independently corroborated by Linux v6.6 amd_iommu_types.h:153-156, which
# defines EVENT_FLAGS_SHIFT 0x10, EVENT_FLAGS_MASK 0xfff, EVENT_FLAG_RW 0x020
# (field bit 5 -> DWORD1 bit 21) and EVENT_FLAG_I 0x008 (field bit 3 ->
# DWORD1 bit 19). Both agree on the two bits Linux names.
# ---------------------------------------------------------------------------
FLAG_BITS = [
    (0, "GN", "guest/nested: 1 = transaction used a GVA, 0 = a GPA"),
    (1, "NX", "no-execute as requested by the peripheral (0 without PASID)"),
    (2, "US", "user/supervisor: 0 = supervisor, 1 = user"),
    (3, "I",  "interrupt: 1 = interrupt request, 0 = memory request"),
    (4, "PR", "present: 1 = page was marked present / DTE V=1"),
    (5, "RW", "read/write: 1 = write, 0 = read"),
    (6, "PE", "permission: 1 = lacked permission, 0 = had permission"),
    (7, "RZ", "reserved bit set, or invalid level encoding (only if PR=1)"),
    (8, "TR", "translation request (vs. transaction request)"),
]

# Bits 27:25 of DWORD1 are reserved per Table 57.
RESERVED_FLAG_MASK = 0x7 << 9

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
    out = {}
    pat = re.compile(r'"([A-Za-z0-9\-\.]+)"\s*=\s*(?:"([^"]*)"|([^,\n}]+))')
    for m in pat.finditer(text):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else m.group(3).strip()
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


def decode_flags(flags):
    """flags is the 9-bit field (DWORD1 bits 24:16)."""
    parts = []
    for bit, name, _desc in FLAG_BITS:
        parts.append("{}= {}".format(name.ljust(2), (flags >> bit) & 1))
    return "  ".join(parts)


def interpret(flags):
    """Turn the flag field into the fault cause the spec defines.

    Only the interpretations the spec states explicitly are returned;
    anything else is left as an open question rather than guessed.
    """
    pr = (flags >> 4) & 1
    pe = (flags >> 6) & 1
    rz = (flags >> 7) & 1
    tr = (flags >> 8) & 1
    i = (flags >> 3) & 1
    rw = (flags >> 5) & 1

    notes = []
    if i:
        notes.append("interrupt request, not a DMA transaction")
    if tr:
        notes.append("translation request, not a transaction request")
    if not pr:
        notes.append("page was NOT marked present (or DTE V=0)")
    else:
        # RZ and PE are only meaningful when PR=1 (spec, Table 57).
        if pe:
            notes.append("permission failure (PE=1)")
        else:
            notes.append("permissions were sufficient (PE=0)")
        if rz:
            notes.append("fault caused by a non-zero reserved bit (RZ=1)")
        else:
            notes.append("fault caused by an INVALID LEVEL ENCODING (RZ=0)")
    if not i and not tr:
        notes.append("RW={} ({})".format(rw, "write" if rw else "read"))
    return notes


def main():
    if len(sys.argv) < 2:
        print("usage: extract-raw-events.py <props.txt> [--json]")
        return 2
    path = sys.argv[1]
    as_json = "--json" in sys.argv
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            props = parse_props(f.read())
    except IOError as e:
        print("cannot read {}: {}".format(path, e))
        return 2

    reported = as_int(props.get("m2-b2-win-entries"))
    raw_count = as_int(props.get("m2-b2-win-raw-count"))
    truncated = props.get("m2-b2-win-raw-truncated")

    raws = []
    for i in range(64):
        v = props.get("m2-b2-win-raw{}".format(i))
        if v is None:
            continue
        s = v.strip().lower()
        if s.startswith("0x"):
            s = s[2:]
        if len(s) != 32:
            print("  raw{}: unexpected length {} -> {}".format(i, len(s), s))
            continue
        w = [int(s[k * 8:(k + 1) * 8], 16) for k in range(4)]
        raws.append((i, w))

    entries = []
    for i, w in raws:
        d0, d1, d2, d3 = w
        devid = d0 & 0xFFFF
        domid = d1 & 0xFFFF
        flags = (d1 >> 16) & 0x1FF
        reserved = (d1 >> 16) & RESERVED_FLAG_MASK
        etype = (d1 >> 28) & 0xF
        addr = ((d3 & 0xFFFFFFFF) << 32) | (d2 & 0xFFFFFFFF)
        entries.append({
            "index": i,
            "raw": "{:08x}{:08x}{:08x}{:08x}".format(*w),
            "devid": "0x{:04x}".format(devid),
            "domain": "0x{:04x}".format(domid),
            "type": etype,
            "typeName": TYPE_NAMES.get(etype, "UNKNOWN"),
            "flags": "0x{:03x}".format(flags),
            "flagsValue": flags,
            "reservedFlagBitsSet": reserved != 0,
            "flagBits": {name: (flags >> bit) & 1 for bit, name, _ in FLAG_BITS},
            "interpretation": interpret(flags),
            "address": "0x{:x}".format(addr),
        })

    report = {
        "source": path,
        "windowEntriesReported": reported,
        "rawRetained": len(entries),
        "rawTruncated": truncated,
        "truncated": (reported is not None and len(entries) < reported),
        "entries": entries,
    }

    if as_json:
        print(json.dumps(report, indent=2))
        return 0

    print("Raw event entries saved by the probe")
    print("=" * 78)
    print("source: {}".format(path))
    print()
    print("m2-b2-win-entries        = {}".format(reported))
    print("raw entries retained     = {}".format(len(entries)))
    if truncated:
        print("m2-b2-win-raw-truncated  = {}".format(truncated))
    if reported is not None and len(entries) < reported:
        print()
        print("  TRUNCATED: {} of {} entries retained as raw bytes."
              .format(len(entries), reported))
        print("  Conclusions about ADDRESS DISTRIBUTION or flag mix apply to")
        print("  the retained subset only, not to all {} events.".format(reported))
    print()

    print("Decoded entries (flags = DWORD1 bits 24:16)")
    print("-" * 78)
    for e in entries:
        print("  raw{:<2} devid={} domain={} type={} {}".format(
            e["index"], e["devid"], e["domain"], e["type"], e["typeName"]))
        print("        addr={}  flags={}  {}".format(
            e["address"], e["flags"], decode_flags(e["flagsValue"])))
        if e["reservedFlagBitsSet"]:
            print("        WARNING: reserved flag bits (DWORD1 27:25) set")
        for n in e["interpretation"]:
            print("        -> {}".format(n))

    print()
    print("Distinct (type, flags, domain, devid) combinations")
    print("-" * 78)
    hist = {}
    for e in entries:
        key = (e["type"], e["flags"], e["domain"], e["devid"])
        hist[key] = hist.get(key, 0) + 1
    for (etype, flags, dom, devid), n in sorted(hist.items()):
        print("  type={} {} flags={} domain={} devid={}  x{}".format(
            etype, TYPE_NAMES.get(etype, "UNKNOWN"), flags, dom, devid, n))

    print()
    print("=" * 78)
    print("SCOPE: these are the entries the probe RETAINED, not necessarily")
    print("every entry the hardware produced. m2-b2-win-entries is the")
    print("authoritative total for the window.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
