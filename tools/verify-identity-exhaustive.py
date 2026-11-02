#!/usr/bin/env python3
"""Exhaustive OFFLINE model check of the identity page table.

WHAT THIS IS, AND WHAT IT IS NOT
--------------------------------
This script rebuilds the page table in Python from the documented constants
and walks EVERY 2 MiB page of the full 16 GiB. It is a MODEL CHECK.

It does NOT read the machine. The script that reads real exported bytes is
tools/decode-exported-pagetable.py. Keeping them separate matters: round 3
claimed "all 8192 entries verified" on the strength of a model rebuild, which
proved only that the model agreed with itself.

WHY IT WAS REWRITTEN IN ROUND 5
-------------------------------
The round-4 version of this script mirrored the round-4 builder, including
its defect: it encoded every 2 MiB leaf as NextLevel=7 and then "verified"
that encoding. A model that shares an assumption with the code cannot
detect a wrong assumption.

It also modelled the WRONG LAYOUT. The production 4-level table is

    root (level 4) -> L3 (level 3, one per 1 GiB) -> L2 (level 2, leaves)

whereas the old model had root(3) -> L2(2) -> leaf(1) -- the Linux 0-based
shift-index numbering mistaken for the spec's 1-based level numbering.

This version models the production structure and uses the same level-aware
decoding rules as the shared C core (kext/amd_iommu_pte_core.hpp) and as
AMD IOMMU Spec 48882 Rev 3.10.

Spec / Linux references:
  Spec 48882 Rev 3.10 Table 15: level 1 = 4 KiB, 2 = 2 MiB, 3 = 1 GiB, 4 = 512 GiB
  Spec 48882 Rev 3.10 sec 2.2.3 p.80: a NextLevel=7 page size "must be larger
      than the default page size and smaller than the default page size for
      the next higher level"
  Linux v6.6 amd_iommu_types.h: PM_LEVEL_SHIFT, PM_LEVEL_ENC, PM_LEVEL_PDE,
      PAGE_SIZE_PTE, PAGE_SIZE_PTE_COUNT
  Linux v6.6 io_pgtable.c:394-398: `count > 1` selects the NextLevel=7 branch

Usage:
    py -3 tools/verify-identity-exhaustive.py
Exit code 0 only if every check passes.
"""
import sys

# ---- Linux v6.6 macros ----
PM_ADDR_MASK = 0x000FFFFFFFFFF000
PTE_PR = 1 << 0
PTE_FC = 1 << 60
PTE_IR = 1 << 61
PTE_IW = 1 << 62

# ---- Spec 48882 Table 15 (1-BASED levels) ----
LEVEL_DEFAULT = {
    1: 1 << 12,
    2: 1 << 21,
    3: 1 << 30,
    4: 1 << 39,
    5: 1 << 48,
    6: 1 << 57,
}

PAGE_SIZE = 0x1000
LARGE_PAGE = 0x200000
GIB = 1 << 30
IDENTITY_LIMIT = 0x400000000          # 16 GiB
PTE_COUNT = 512


def index_shift(level):
    return 9 * level + 3


def index_at(level, iova):
    return (iova >> index_shift(level)) & 0x1FF


def next_level(pte):
    return (pte >> 9) & 0x7


def level_enc(level):
    return (level << 9) & 0xE00


def page_size_pte_count(ps):
    n = ps.bit_length() - 1
    return 1 << ((n - 12) % 9)


def make_table_pde(child_level, pa):
    return ((pa & PM_ADDR_MASK) | level_enc(child_level)
            | PTE_PR | PTE_IR | PTE_IW)


def make_default_leaf(level, pa):
    """NextLevel=0: maps the DEFAULT page size of `level`. No size bits."""
    del level  # encoding is identical; the size comes from the level
    return (pa & PM_ADDR_MASK) | PTE_PR | PTE_FC | PTE_IR | PTE_IW


def make_large_leaf(pa, ps):
    """NextLevel=7: enlarged page, size in the OA low bits."""
    base = ((pa | (ps - 1)) & ~(ps >> 1)) & PM_ADDR_MASK
    return base | level_enc(7) | PTE_PR | PTE_FC | PTE_IR | PTE_IW


def encoded_large_page_size(pte):
    x = pte | 0xFFF
    i = 0
    while i < 63 and ((x >> i) & 1):
        i += 1
    return 1 << (1 + i)


def decode(pte, level):
    """Return (kind, page_size, out_pa, reason). Mirrors the C core."""
    if not (pte & PTE_PR):
        return ("absent", 0, 0, "PR=0")
    nl = next_level(pte)
    if nl == 7:
        ps = encoded_large_page_size(pte)
        lo = LEVEL_DEFAULT.get(level)
        hi = LEVEL_DEFAULT.get(level + 1)
        if lo is None:
            return ("illegal", ps, 0, "level out of range")
        if ps <= lo:
            return ("illegal", ps, 0,
                    "enlarged size 0x{:x} not larger than level-{} default "
                    "0x{:x}".format(ps, level, lo))
        if hi is not None and ps >= hi:
            return ("illegal", ps, 0,
                    "enlarged size 0x{:x} reaches level-{} default 0x{:x}"
                    .format(ps, level + 1, hi))
        return ("leaf-large", ps, (pte & PM_ADDR_MASK) & ~(ps - 1), None)
    if nl == 0:
        return ("leaf-default", LEVEL_DEFAULT[level], pte & PM_ADDR_MASK, None)
    if nl != level - 1:
        return ("illegal", 0, 0,
                "NextLevel={} skips a level (expected {})".format(nl, level - 1))
    return ("table", 0, pte & PM_ADDR_MASK, None)


# ---------------------------------------------------------------------------
# Build the table exactly as production does (PAGE_MODE_4_LEVEL).
#   page 0      root (level 4)
#   page 1      L3   (level 3)
#   page 2..17  L2   (level 2) one per 1 GiB, holding the 2 MiB leaves
# ---------------------------------------------------------------------------
ROOT_PAGE = 0
L3_PAGE = 1
L2_BASE = 2
L2_PAGES = IDENTITY_LIMIT // GIB          # 16
TOTAL_PAGES = 1 + 1 + L2_PAGES            # 18


def build(pt_pa, leaf_mode):
    """leaf_mode: 'default' (correct) or 'nextlevel7' (the round-4 defect)."""
    pages = {i: [0] * PTE_COUNT for i in range(TOTAL_PAGES)}

    def pa_of(page_idx):
        return pt_pa + page_idx * PAGE_SIZE

    pages[ROOT_PAGE][0] = make_table_pde(3, pa_of(L3_PAGE))

    for gb in range(L2_PAGES):
        l2_page = L2_BASE + gb
        pages[L3_PAGE][gb] = make_table_pde(2, pa_of(l2_page))
        base_1g = gb << 30
        for i in range(PTE_COUNT):
            pa = base_1g + (i << 21)
            if leaf_mode == "default":
                pages[l2_page][i] = make_default_leaf(2, pa)
            else:
                pages[l2_page][i] = make_large_leaf(pa, LARGE_PAGE)

    return pages


def walk(pages, pt_pa, iova, root_level=4):
    """Walk with full level tracking. Returns (ok, out_pa, ps, reason)."""
    level = root_level
    table_pa = pt_pa
    for _ in range(8):
        page_idx = (table_pa - pt_pa) // PAGE_SIZE
        if page_idx not in pages:
            return (False, 0, 0, "PDE points outside the allocation")
        pte = pages[page_idx][index_at(level, iova)]
        kind, ps, out_pa, reason = decode(pte, level)
        if kind == "absent":
            return (False, 0, 0, "absent at level {}".format(level))
        if kind == "illegal":
            return (False, 0, 0, "illegal at level {}: {}".format(level, reason))
        if kind in ("leaf-default", "leaf-large"):
            return (True, out_pa | (iova & (ps - 1)), ps, None)
        level -= 1
        table_pa = out_pa
    return (False, 0, 0, "walk did not terminate")


def main():
    fails = []
    checks = 0

    def ck(cond, what):
        nonlocal checks
        checks += 1
        if not cond:
            fails.append(what)

    pt_pa = 0x2fbc0000     # the live machine's allocation, for realism

    # ================= 1. Correct table: exhaustive identity =================
    print("1. Exhaustive walk of the CORRECT (NextLevel=0) table")
    print("-" * 74)
    pages = build(pt_pa, "default")
    bad = 0
    first_bad = None
    for iova in range(0, IDENTITY_LIMIT, LARGE_PAGE):
        ok, out_pa, ps, why = walk(pages, pt_pa, iova)
        if not ok or out_pa != iova or ps != LARGE_PAGE:
            bad += 1
            if first_bad is None:
                first_bad = (iova, why, out_pa)
    n = IDENTITY_LIMIT // LARGE_PAGE
    ck(bad == 0, "{} of {} 2 MiB pages failed (first: {})".format(
        bad, n, first_bad))
    print("   walked {} 2 MiB pages of 16 GiB, {} failures".format(n, bad))
    print("   page-table allocation: {} pages = {} KiB".format(
        TOTAL_PAGES, TOTAL_PAGES * 4))
    ck(TOTAL_PAGES == 18, "allocation should be 18 pages")
    ck(n == 8192, "8192 leaf entries describe 16 GiB")
    print()

    # ============ 2. The round-4 defect must be detected by the model =======
    print("2. The same model applied to the ROUND-4 (NextLevel=7) table")
    print("-" * 74)
    pages_bad = build(pt_pa, "nextlevel7")
    ok, out_pa, ps, why = walk(pages_bad, pt_pa, 0x384514000)
    ck(not ok, "round-4 table must NOT walk successfully")
    ck(why is not None and "not larger than" in (why or ""),
       "reason should name the size rule, got: {}".format(why))
    print("   walk at 0x384514000 -> {} ".format("FAILS as expected" if not ok
                                                 else "UNEXPECTEDLY OK"))
    print("   reason: {}".format(why))

    # Count how many of the 8192 pages the model rejects.
    bad2 = 0
    for iova in range(0, IDENTITY_LIMIT, LARGE_PAGE):
        ok2, _, _, _ = walk(pages_bad, pt_pa, iova)
        if not ok2:
            bad2 += 1
    ck(bad2 == 8192, "round-4 table should be rejected at every page, "
                     "got {}".format(bad2))
    print("   rejected at {}/8192 pages".format(bad2))
    print()

    # ==================== 3. The exact exported values ======================
    print("3. Reproduce the live exported PDEs bit-for-bit")
    print("-" * 74)
    live_root0 = 0x600000002fbc1601
    live_l2 = 0x600000002fbd0401
    live_leaf_bad = 0x70000003844ffe01
    live_leaf_good = 0x7000000384400001

    ck(make_table_pde(3, 0x2fbc1000) == live_root0,
       "root[0] re-encode mismatch")
    ck(make_table_pde(2, 0x2fbd0000) == live_l2, "L2[0] re-encode mismatch")
    ck(make_large_leaf(0x384400000, LARGE_PAGE) == live_leaf_bad,
       "make_large_leaf reproduces the shipped bad value")
    ck(make_default_leaf(2, 0x384400000) == live_leaf_good,
       "make_default_leaf produces the corrected value")
    ck(decode(live_leaf_bad, 2)[0] == "illegal",
       "shipped leaf must decode as illegal at level 2")
    ck(decode(live_leaf_good, 2)[0] == "leaf-default",
       "corrected leaf must decode as a default leaf at level 2")
    print("   root[0] 0x{:016x}  OK".format(live_root0))
    print("   L2[0]   0x{:016x}  OK".format(live_l2))
    print("   leaf    0x{:016x}  -> ILLEGAL at level 2 (shipped)".format(
        live_leaf_bad))
    print("   leaf    0x{:016x}  -> valid default 2 MiB leaf".format(
        live_leaf_good))
    print()

    # ================= 4. Boundary and end-of-range cases ===================
    print("4. Boundaries and end of range")
    print("-" * 74)
    for iova in (0x0, 0x1, 0xFFF, 0x1000, 0x1FFFFF, 0x200000,
                 0x40000000, 0x100000000, 0x200000000,
                 0x3FFE00000, 0x3FFFFFFF0, IDENTITY_LIMIT - 1):
        ok, out_pa, ps, why = walk(pages, pt_pa, iova)
        ck(ok and out_pa == iova,
           "identity failed at 0x{:x}: {}".format(iova, why))
    print("   12 boundary IOVAs all translate identically")

    ok, _, _, why = walk(pages, pt_pa, IDENTITY_LIMIT)
    ck(not ok, "16 GiB itself must NOT be mapped (got ok, {})".format(why))
    print("   16 GiB itself is not mapped (correct: the limit is exclusive)")
    print()

    # ==================== 5. Count vs allocation distinction ================
    print("5. 'maps 16 GiB' vs 'allocates 76 KiB' are different facts")
    print("-" * 74)
    ck(TOTAL_PAGES * 4 == 72,
       "the correct table is 72 KiB, not 76 KiB "
       "(76 KiB was the round-4 layout with an unused bad-root page)")
    print("   mapping coverage : {} GiB".format(IDENTITY_LIMIT // GIB))
    print("   allocation       : {} pages = {} KiB".format(
        TOTAL_PAGES, TOTAL_PAGES * 4))
    print()

    print("=" * 74)
    if fails:
        print("FAILURES ({}):".format(len(fails)))
        for f in fails:
            print("  - " + f)
        print("RESULT: FAIL ({}/{} checks)".format(checks - len(fails), checks))
        return 1
    print("ALL {} MODEL CHECKS PASS".format(checks))
    print()
    print("SCOPE: this is a MODEL. It shows the documented construction")
    print("rules produce a valid identity map, and that the round-4 leaf")
    print("rule does not. It does NOT read the machine. For the bytes that")
    print("are actually in DRAM, run tools/decode-exported-pagetable.py on")
    print("a capture that includes m2-b2-dump-root-level.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
