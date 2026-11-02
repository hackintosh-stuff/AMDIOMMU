#!/usr/bin/env python3
"""Independent decoder for the page-table bytes the probe exported.

CRITICAL DISTINCTION
--------------------
Round 3's verify-identity-exhaustive.py rebuilt the table in Python from the
same constants the C code uses, then checked the rebuild. That proves the
MODEL is self-consistent; it says nothing about the bytes in DRAM.

This script takes the real exported values (`m2-b2-dump*` properties read back
by ioreg from the live probe) and decodes them with rules transcribed from
AMD IOMMU Spec 48882 Rev 3.10 and Linux v6.6 -- independently of the C code.

WHAT CHANGED IN ROUND 5 (and why the round-4 version was wrong)
---------------------------------------------------------------
The round-4 decoder had no notion of table level. It read a leaf PTE and
computed `pte_page_size(pte)` unconditionally, then compared the output
address mask. Because the builder and the decoder shared the same wrong
assumption (NextLevel=7 for every 2 MiB leaf), the decoder "confirmed" a
table the hardware was rejecting.

The spec (48882 Rev 3.10, section 2.2.3, p. 80) is explicit:

    "The page size specified by this method must be larger than the default
     page size and smaller than the default page size for the next higher
     level."

So decoding REQUIRES the level the PTE sits at. This decoder therefore:
  * reads `m2-b2-dump-root-level` and walks level by level;
  * treats NextLevel==0 as "the default page size OF THAT LEVEL", not 4 KiB;
  * rejects NextLevel==7 when the encoded size is not strictly between this
    level's default and the next level's default;
  * validates the full path (each PDE must point at the next level down),
    not just the final address mask.

Usage:
    py -3 tools/decode-exported-pagetable.py docs/evidence/<stamp>/props.txt
    py -3 tools/decode-exported-pagetable.py docs/evidence/<stamp>/props.txt --json
"""
import json
import re
import sys

# ---- Linux v6.6 amd_iommu_types.h / spec Table 17 ----
PM_ADDR_MASK = 0x000FFFFFFFFFF000
PTE_PR = 1 << 0
PTE_FC = 1 << 60
PTE_IR = 1 << 61
PTE_IW = 1 << 62
NEXT_LEVEL_SHIFT = 9
NEXT_LEVEL_MASK = 0x7

# Spec 48882 Table 15 "Page Table Level Parameters" is 1-BASED:
#   Level 1 = 4 KiB, Level 2 = 2 MiB, Level 3 = 1 GiB, Level 4 = 512 GiB
LEVEL_DEFAULT = {
    1: 1 << 12,
    2: 1 << 21,
    3: 1 << 30,
    4: 1 << 39,
    5: 1 << 48,
    6: 1 << 57,
}


def index_shift(level):
    return 9 * level + 3


def index_at(level, iova):
    return (iova >> index_shift(level)) & 0x1FF


def next_level(pte):
    return (pte >> NEXT_LEVEL_SHIFT) & NEXT_LEVEL_MASK


def level_enc(level):
    return (level << NEXT_LEVEL_SHIFT) & 0xE00


def encoded_large_page_size(pte):
    """PTE_PAGE_SIZE(pte) = 1 << (1 + ffz(pte | 0xfff))"""
    x = pte | 0xFFF
    i = 0
    while i < 63 and ((x >> i) & 1):
        i += 1
    return 1 << (1 + i)


def page_size_pte_count(ps):
    n = 0
    p = ps
    while p > 1:
        p >>= 1
        n += 1
    if n < 12:
        return 0
    return 1 << ((n - 12) % 9)


class Decoded(object):
    def __init__(self, kind, level, raw):
        self.kind = kind          # absent | table | leaf-default | leaf-large | illegal
        self.level = level
        self.raw = raw
        self.page_size = 0
        self.out_pa = 0
        self.child_level = 0
        self.pte_count = 1
        self.reason = None


def decode_pte(pte, level):
    d = Decoded("absent", level, pte)
    if not (pte & PTE_PR):
        d.reason = "PR=0 (entry not present)"
        return d

    nl = next_level(pte)

    if nl == 7:
        ps = encoded_large_page_size(pte)
        d.page_size = ps
        lo = LEVEL_DEFAULT.get(level)
        hi = LEVEL_DEFAULT.get(level + 1)
        if lo is None:
            d.kind = "illegal"
            d.reason = "level {} out of range".format(level)
            return d
        if ps <= lo:
            d.kind = "illegal"
            d.reason = (
                "NextLevel=7 encodes 0x{:x}, which is not LARGER than the "
                "level-{} default 0x{:x}; spec 48882 2.2.3 requires it to be "
                "strictly larger, so this must be NextLevel=0".format(
                    ps, level, lo))
            return d
        if hi is not None and ps >= hi:
            d.kind = "illegal"
            d.reason = (
                "NextLevel=7 encodes 0x{:x}, which reaches the level-{} "
                "default 0x{:x}; use a table at that level".format(
                    ps, level + 1, hi))
            return d
        d.kind = "leaf-large"
        d.out_pa = (pte & PM_ADDR_MASK) & ~(ps - 1)
        d.pte_count = page_size_pte_count(ps)
        return d

    if nl == 0:
        # NextLevel 0 = the DEFAULT page size for this level. NOT "4 KiB".
        d.kind = "leaf-default"
        d.page_size = LEVEL_DEFAULT.get(level, 0)
        d.out_pa = pte & PM_ADDR_MASK
        d.pte_count = 1
        return d

    if nl != level - 1:
        d.kind = "illegal"
        d.child_level = nl
        d.reason = ("NextLevel={} does not point at level {} "
                    "(level skipping is not supported)".format(nl, level - 1))
        return d

    d.kind = "table"
    d.child_level = nl
    d.out_pa = pte & PM_ADDR_MASK
    return d


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
        print("usage: decode-exported-pagetable.py <props.txt> [--json]")
        return 2
    path = sys.argv[1]
    as_json = "--json" in sys.argv

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            props = parse_props(f.read())
    except IOError as e:
        print("cannot read {}: {}".format(path, e))
        return 2

    root_pa = as_int(props.get("m2-b2-dump-root-pa"))
    root_level = as_int(props.get("m2-b2-dump-root-level"))
    page_mode = as_int(props.get("m2-b2-dump-page-mode"))
    pt_pages = as_int(props.get("m2-b2-dump-pt-pages"))
    dump_count = as_int(props.get("m2-b2-dump-count"))

    failures = []
    missing = []
    for name, val in (("m2-b2-dump-root-pa", root_pa),
                      ("m2-b2-dump-root-level", root_level),
                      ("m2-b2-dump-page-mode", page_mode),
                      ("m2-b2-dump-pt-pages", pt_pages),
                      ("m2-b2-dump-count", dump_count)):
        if val is None:
            missing.append(name)

    report = {
        "source": path,
        "missing": missing,
        "rootPA": root_pa,
        "rootLevel": root_level,
        "pageMode": page_mode,
        "paths": [],
        "failures": failures,
    }

    if missing:
        report["conclusion"] = (
            "CANNOT DECODE: capture lacks {}".format(", ".join(missing)))
        if as_json:
            print(json.dumps(report, indent=2))
        else:
            print("MISSING EXPORTED FIELDS ({}):".format(len(missing)))
            for m in missing:
                print("  " + m)
            print()
            if "m2-b2-dump-root-level" in missing:
                print("This capture predates the round-5 fix and does NOT")
                print("record the level of each exported PTE. Without the")
                print("level there is no way to tell whether NextLevel=0")
                print("means 4 KiB or 2 MiB, so the table CANNOT be judged.")
            print("This capture CANNOT be used to verify the page table.")
        return 1

    # The DTE Mode field is the number of levels, so Mode=4 -> level-4 root.
    if page_mode is not None and page_mode != root_level:
        failures.append(
            "page-mode={} but root-level={}; a Mode=N table has a level-N root"
            .format(page_mode, root_level))

    if not as_json:
        print("Decoding EXPORTED page-table bytes (level-aware)")
        print("=" * 78)
        print("source: {}".format(path))
        print()
        print("  root PA    = 0x{:x}".format(root_pa))
        print("  root level = {}   (spec Table 15 numbering; 1 = 4 KiB)"
              .format(root_level))
        print("  page mode  = {}".format(page_mode))
        print("  pt pages   = {}  ({} KiB)".format(pt_pages,
                                                    (pt_pages or 0) * 4))
        print("  dumps      = {}".format(dump_count))
        print()

    # ---- per-fault exported paths ----
    for i in range(dump_count):
        addr = as_int(props.get("m2-b2-dump{}-addr".format(i)))
        depth = as_int(props.get("m2-b2-dump{}-depth".format(i)))
        if addr is None:
            failures.append("dump{} has no address".format(i))
            continue

        # New format: explicit per-level PTEs. Old format: root/l2/leaf.
        ptes = []
        if depth is not None:
            for j in range(depth):
                lv = as_int(props.get("m2-b2-dump{}-pte{}-level".format(i, j)))
                pv = as_int(props.get("m2-b2-dump{}-pte{}".format(i, j)))
                if lv is None or pv is None:
                    failures.append(
                        "dump{} pte{} missing level or value".format(i, j))
                    continue
                ptes.append((lv, pv))
        else:
            # Legacy capture: we do NOT know the level of each entry, and
            # guessing is exactly the round-4 mistake. Refuse to judge.
            failures.append(
                "dump{} predates level export; cannot decode without guessing"
                .format(i))
            continue

        entry = {"index": i, "address": "0x{:x}".format(addr),
                 "depth": len(ptes), "steps": [], "ok": False}

        if not as_json:
            print("  fault address 0x{:x}  ({} PTEs exported)"
                  .format(addr, len(ptes)))

        # Walk the exported chain, verifying each level in turn.
        chain_ok = True
        for k, (lv, pv) in enumerate(ptes):
            d = decode_pte(pv, lv)
            step = {
                "step": k,
                "level": lv,
                "pte": "0x{:016x}".format(pv),
                "kind": d.kind,
                "pageSize": d.page_size,
                "outPA": "0x{:x}".format(d.out_pa),
                "reason": d.reason,
            }
            entry["steps"].append(step)

            if not as_json:
                print("    [{0}] level {1}  PTE 0x{2:016x}".format(k, lv, pv))
                print("         PR={} FC={} IR={} IW={} NextLevel={}".format(
                    (pv >> 0) & 1, (pv >> 60) & 1, (pv >> 61) & 1,
                    (pv >> 62) & 1, next_level(pv)))
                print("         decoded: {}".format(d.kind))
                if d.reason:
                    print("         reason : {}".format(d.reason))
                if d.page_size:
                    print("         page sz: 0x{:x}  ({} PTEs)".format(
                        d.page_size, d.pte_count))
                if d.kind in ("leaf-default", "leaf-large"):
                    print("         out PA : 0x{:x}".format(d.out_pa))

            if d.kind == "absent":
                failures.append(
                    "dump{} step{} level{}: PTE not present".format(i, k, lv))
                chain_ok = False
                break
            if d.kind == "illegal":
                failures.append(
                    "dump{} step{} level{}: ILLEGAL ENCODING - {}".format(
                        i, k, lv, d.reason))
                chain_ok = False
                break

            is_last = (k == len(ptes) - 1)
            if d.kind == "table":
                if is_last:
                    failures.append(
                        "dump{} ends on a table PDE at level {}, no leaf"
                        .format(i, lv))
                    chain_ok = False
                    break
                nxt_lv, _ = ptes[k + 1]
                if nxt_lv != d.child_level:
                    failures.append(
                        "dump{} step{}: NextLevel says level {} but the next "
                        "exported PTE is at level {}".format(
                            i, k, d.child_level, nxt_lv))
                    chain_ok = False
                    break
            else:
                # leaf: must be the last step
                if not is_last:
                    failures.append(
                        "dump{} step{}: leaf at level {} but {} more PTEs "
                        "follow".format(i, k, lv, len(ptes) - k - 1))
                    chain_ok = False
                    break
                # identity check
                want = addr & ~(d.page_size - 1)
                if d.out_pa != want:
                    failures.append(
                        "dump{} leaf maps 0x{:x}, not identity 0x{:x}".format(
                            i, d.out_pa, want))
                    chain_ok = False
                    break

        entry["ok"] = chain_ok
        if chain_ok and not as_json:
            last = entry["steps"][-1]
            print("    -> VALID identity map, page size {}".format(
                last["pageSize"]))
        report["paths"].append(entry)
        if not as_json:
            print()

    if not report["paths"]:
        failures.append("no per-fault paths exported")

    report["conclusion"] = (
        "EXPORTED TABLE DECODES CORRECTLY" if not failures
        else "EXPORTED TABLE HAS PROBLEMS")

    if as_json:
        print(json.dumps(report, indent=2))
        return 0 if not failures else 1

    print("=" * 78)
    if failures:
        print("PROBLEMS ({}):".format(len(failures)))
        for f in failures:
            print("  - " + f)
        return 1

    print("EXPORTED TABLE DECODES CORRECTLY")
    print()
    print("SCOPE: this decodes the bytes the probe READ BACK from its own")
    print("page table on the live machine, using the level recorded with")
    print("each PTE. It shows the table is well formed. It does NOT show")
    print("the IOMMU walked it successfully -- the event log has to")
    print("establish that.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
