#!/usr/bin/env python3
"""Verify all three page-table levels against Linux's macros.

v0.16.0 dumped root / L2 / leaf for the faulting IOVA. If all three match
Linux bit for bit, the page table is not the problem and the fault must
come from something the hardware sees differently from the CPU.
"""
PM_ADDR_MASK = 0x000FFFFFFFFFF000
PR = 1 << 0
FC = 1 << 60
IR = 1 << 61
IW = 1 << 62


def enc(x):
    return (x << 9) & 0xE00


def pde(level, addr):
    """Linux PM_LEVEL_PDE: no FC on non-leaf entries."""
    return (addr & PM_ADDR_MASK) | enc(level) | PR | IR | IW


def leaf2m(addr):
    p = (addr | 0x1FFFFF) & ~0x100000 & PM_ADDR_MASK
    return p | enc(7) | PR | FC | IR | IW


def show(name, got, want):
    ok = "OK " if got == want else "BAD"
    print("  [%s] %-14s got  0x%016X" % (ok, name, got))
    print("        %-14s want 0x%016X" % ("", want))
    if got != want:
        print("        XOR  0x%016X" % (got ^ want))
    return got == want


def main():
    # Values captured from the v0.16.0 run
    IOVA = 0x34400000
    ROOT_PTE = 0x60000000397C1601
    L2_PTE = 0x60000000397C2401
    LEAF_PTE = 0x70000000344FFE01
    ROOT_PA = 0x397C0000
    L2_PA = 0x397C1000
    LEAF_PA = 0x397C2000

    print("=" * 74)
    print("Page-table levels for IOVA 0x%X" % IOVA)
    print("=" * 74)

    allok = True
    print()
    print("root (level 3 -> level 2), Linux PM_LEVEL_PDE(3, L2_PA):")
    allok &= show("root", ROOT_PTE, pde(3, L2_PA))

    print()
    print("L2 (level 2 -> level 1), Linux PM_LEVEL_PDE(2, LEAF_PA):")
    allok &= show("l2", L2_PTE, pde(2, LEAF_PA))

    print()
    print("leaf (level 7, 2 MiB), Linux PAGE_SIZE_PTE(IOVA,2M)|...:")
    allok &= show("leaf", LEAF_PTE, leaf2m(IOVA))

    print()
    print("-" * 74)
    print("All three levels identical to Linux: %s" % allok)
    print("-" * 74)

    print()
    print("=" * 74)
    print("What the CPU sees vs what the IOMMU must see")
    print("=" * 74)
    print()
    print("  The CPU built these entries through the virtual pointer `pt`.")
    print("  The IOMMU reads them from ROOT_PA = 0x%X." % ROOT_PA)
    print("  m2-b2-pa-va = identical proves pt and ptPA are the same pages")
    print("  *as the CPU reads them*.")
    print()
    print("  Both of those reads go through the CPU cache. Neither proves")
    print("  the bytes ever reached DRAM, which is where the IOMMU reads.")
    print()
    print("  That single gap explains EVERY observation at once:")
    print("    * every fault address IS mapped in the CPU's view")
    print("    * the hardware faults on all of them anyway")
    print("    * an all-zero root also faults (stale zeros look the same)")
    print("    * zeroing a leaf table barely changes anything (both look 0)")
    print()
    print("  => Next experiment: write the page table through an UNCACHED")
    print("     mapping so the bytes are guaranteed to be in DRAM, and see")
    print("     whether the faults disappear.")


if __name__ == "__main__":
    main()
