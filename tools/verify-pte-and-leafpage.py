#!/usr/bin/env python3
"""Verify the dumped leaf PTE against Linux, and check which leaf table
the probe actually zeroed.

Two questions:
  1. Is the 64-bit PTE bit-identical to what Linux's PAGE_SIZE_PTE would
     produce for this IOVA?  (if yes, the encoding is not the problem)
  2. Does the leaf table index the probe reported (0x9) actually serve the
     faulting IOVA (0x385a00000)?  (if not, the leaf experiment zeroed the
     WRONG table and proved nothing)
"""

# ---- Linux macros, copied verbatim from amd_iommu_types.h ----
PM_ADDR_MASK = 0x000FFFFFFFFFF000
IOMMU_PTE_PR = 1 << 0
IOMMU_PTE_FC = 1 << 60
IOMMU_PTE_IR = 1 << 61
IOMMU_PTE_IW = 1 << 62


def pm_level_enc(x):
    return (x << 9) & 0xE00


def page_size_pte(address, pagesize):
    return (address | (pagesize - 1)) & (~(pagesize >> 1)) & PM_ADDR_MASK


def pte_page_size(pte):
    # 1 << (1 + ffz(pte | 0xfff))
    v = pte | 0xFFF
    ffz = 0
    while (v >> ffz) & 1:
        ffz += 1
    return 1 << (1 + ffz)


def build_linux_leaf(pa, pagesize=0x200000):
    pte = page_size_pte(pa, pagesize)
    pte |= pm_level_enc(7) | IOMMU_PTE_PR | IOMMU_PTE_FC
    pte |= IOMMU_PTE_IR | IOMMU_PTE_IW
    return pte


IOVA = 0x385A00000
DUMPED = 0x7000000385AFFE01
# ioreg reports this as the hex string "0x10" = 16. Reading it as decimal
# 10 would wrongly suggest the probe zeroed the wrong table.
REPORTED_LEAF_PAGE = 0x10

ROOT_PAGES = 1
L2_PAGES = 1
LEAF_BASE = ROOT_PAGES + L2_PAGES   # = 2


def main():
    print("=" * 72)
    print("1. Is the dumped PTE what Linux would produce?")
    print("=" * 72)
    expect = build_linux_leaf(IOVA)
    print("  IOVA                : 0x%X" % IOVA)
    print("  dumped PTE          : 0x%016X" % DUMPED)
    print("  Linux PAGE_SIZE_PTE : 0x%016X" % expect)
    print("  identical           : %s" % (DUMPED == expect))
    print()
    print("  decoded fields of the dumped PTE:")
    print("    PR  (bit0)        : %d" % (DUMPED & 1))
    print("    NEXT_LEVEL(9..11) : %d  (7 = large page)" % ((DUMPED >> 9) & 7))
    print("    FC  (bit60)       : %d" % ((DUMPED >> 60) & 1))
    print("    IR  (bit61)       : %d" % ((DUMPED >> 61) & 1))
    print("    IW  (bit62)       : %d" % ((DUMPED >> 62) & 1))
    print("    OA field          : 0x%X" % (DUMPED & PM_ADDR_MASK))
    print("    page base (OA&~2M): 0x%X" % ((DUMPED & PM_ADDR_MASK) & ~0x1FFFFF))
    print("    decoded page size : 0x%X" % pte_page_size(DUMPED))
    print("    identity?         : %s"
          % (((DUMPED & PM_ADDR_MASK) & ~0x1FFFFF) == (IOVA & ~0x1FFFFF)))

    print()
    print("=" * 72)
    print("2. Which leaf table actually serves this IOVA?")
    print("=" * 72)
    i3 = (IOVA >> 39) & 0x1FF
    i2 = (IOVA >> 30) & 0x1FF
    i1 = (IOVA >> 21) & 0x1FF
    i0 = (IOVA >> 12) & 0x1FF
    print("  IOVA 0x%X = %.3f GiB" % (IOVA, IOVA / 2**30))
    print("  i3 (root idx) = %d" % i3)
    print("  i2 (L2   idx) = %d   <- one L2 entry covers 1 GiB" % i2)
    print("  i1 (leaf idx) = %d" % i1)
    print("  i0            = %d" % i0)
    print()
    print("  Page-table layout: page 0 = root, page 1 = L2,")
    print("                     pages 2..17 = leaf tables for GiB 0..15")
    print()
    expected_page = LEAF_BASE + i2
    print("  leaf table serving this IOVA : page %d (0x%X)"
          % (expected_page, expected_page))
    print("  leaf table the probe zeroed  : page %d (0x%X)"
          % (REPORTED_LEAF_PAGE, REPORTED_LEAF_PAGE))
    print()
    if expected_page != REPORTED_LEAF_PAGE:
        wrong_gib = REPORTED_LEAF_PAGE - LEAF_BASE
        print("  *** MISMATCH ***")
        print("  The probe zeroed the leaf table for GiB %d," % wrong_gib)
        print("  but the faulting IOVA lives in GiB %d." % i2)
        print("  Zeroing an unrelated table cannot change anything for this")
        print("  device, which is exactly what we observe (9 -> 10 -> 8).")
        print()
        print("  => The leaf-level experiment was INVALID.")
        print("     It zeroed the wrong table, so it says nothing about")
        print("     whether the hardware reaches the leaf level.")
    else:
        print("  OK: the probe zeroed the correct table.")


if __name__ == "__main__":
    main()
