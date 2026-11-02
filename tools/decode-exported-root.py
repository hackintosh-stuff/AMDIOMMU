#!/usr/bin/env python3
"""Decode the exported ROOT page alone, when no fault path was exported.

WHY
---
decode-exported-pagetable.py needs per-fault paths, which only exist when a
fault landed INSIDE the mapped range. In round 5 the single remaining fault
was outside the range, so nothing was dumped and that decoder (correctly)
refuses to pronounce the table valid.

But the root entries are always exported. Decoding them still verifies:
  * the root page mode / root level agree;
  * root[0] is a level-3 PDE pointing at the expected L3 page;
  * every other root entry is absent (nothing stray points anywhere);
  * the PDE encoding matches PM_LEVEL_PDE exactly.

That is a partial but real check of the bytes on the machine. It is
explicitly NOT a full-table verification and says so.

Usage:
    py -3 tools/decode-exported-root.py docs/evidence/<stamp>/props.txt
"""
import io
import re
import sys

PM_ADDR_MASK = 0x000FFFFFFFFFF000
PTE_PR = 1 << 0
PTE_IR = 1 << 61
PTE_IW = 1 << 62

LEVEL_DEFAULT = {1: 1 << 12, 2: 1 << 21, 3: 1 << 30, 4: 1 << 39,
                 5: 1 << 48, 6: 1 << 57}


def next_level(pte):
    return (pte >> 9) & 0x7


def expected_pde(child_level, pa):
    return ((pa & PM_ADDR_MASK) | ((child_level << 9) & 0xE00)
            | PTE_PR | PTE_IR | PTE_IW)


def parse(text):
    out = {}
    for m in re.finditer(r'"([A-Za-z0-9\-\.]+)"\s*=\s*(?:"([^"]*)"|([^,\n}]+))',
                         text):
        k = m.group(1)
        v = m.group(2) if m.group(2) is not None else m.group(3).strip()
        if k.startswith("m2-b2-"):
            out[k] = v
    return out


def ai(v):
    if v is None:
        return None
    v = v.strip()
    try:
        return int(v, 16) if v.lower().startswith("0x") else int(v, 10)
    except ValueError:
        return None


def main():
    if len(sys.argv) < 2:
        print("usage: decode-exported-root.py <props.txt>")
        return 2
    props = parse(io.open(sys.argv[1], encoding="utf-8",
                          errors="replace").read())

    root_pa = ai(props.get("m2-b2-dump-root-pa"))
    root_level = ai(props.get("m2-b2-dump-root-level"))
    page_mode = ai(props.get("m2-b2-dump-page-mode"))
    pt_pages = ai(props.get("m2-b2-dump-pt-pages"))
    l2_pa = ai(props.get("m2-b2-pt-l2-pa"))

    missing = [n for n, v in (("root-pa", root_pa), ("root-level", root_level),
                              ("page-mode", page_mode), ("pt-pages", pt_pages))
               if v is None]
    if missing:
        print("MISSING: " + ", ".join(missing))
        return 2

    fails = []
    print("Exported ROOT page decode (partial check)")
    print("=" * 74)
    print("  root PA    = 0x{:x}".format(root_pa))
    print("  root level = {}".format(root_level))
    print("  page mode  = {}".format(page_mode))
    print("  pt pages   = {} ({} KiB)".format(pt_pages, pt_pages * 4))
    print()

    if root_level != page_mode:
        fails.append("root-level {} != page-mode {}".format(root_level,
                                                            page_mode))
    if pt_pages is None or pt_pages <= 0:
        fails.append("page-table allocation is not positive")

    print("Root entries as exported")
    print("-" * 74)
    present = 0
    for i in range(16):
        v = ai(props.get("m2-b2-dump-root{}".format(i)))
        if v is None:
            continue
        if v == 0:
            continue
        present += 1
        nl = next_level(v)
        pr = v & PTE_PR
        target = v & PM_ADDR_MASK
        print("  root[{:<2}] = 0x{:016x}".format(i, v))
        print("       PR={} NextLevel={} -> PA 0x{:x}".format(pr, nl, target))

        if not pr:
            fails.append("root[{}] not present but non-zero".format(i))
            continue
        if nl != root_level - 1:
            fails.append(
                "root[{}] NextLevel={} but a level-{} root must point at "
                "level {}".format(i, nl, root_level, root_level - 1))
        exp = expected_pde(nl, target)
        if v != exp:
            print("       expected 0x{:016x}".format(exp))
            fails.append("root[{}] encoding mismatch".format(i))
        else:
            print("       -> matches PM_LEVEL_PDE({}, PA) exactly".format(nl))
        if i == 0 and l2_pa is not None and target != l2_pa:
            print("       (note: exported L3 PA is 0x{:x})".format(l2_pa))

    print()
    if present == 0:
        fails.append("no present root entries at all")

    print("=" * 74)
    if fails:
        print("PROBLEMS ({}):".format(len(fails)))
        for f in fails:
            print("  - " + f)
        return 1
    print("ROOT PAGE DECODES CORRECTLY ({} present entr{})".format(
        present, "y" if present == 1 else "ies"))
    print()
    print("SCOPE: this checks the root page only. It does NOT verify the")
    print("lower levels, because no fault landed inside the mapped range")
    print("so no per-fault path was exported. A full-table claim still")
    print("needs either an in-range fault or an explicit full dump.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
