#!/usr/bin/env python3
"""Decode the AMD-Vi EFR and CONTROL values actually measured on this machine,
using the bit definitions from Linux v6.6 amd_iommu_types.h.

Purpose: the round-2 record claims FEATURE_IA was never checked. If FEATURE_IA
is 0 then CMD_INV_ALL (type 0x08) does not exist on this part, and
iommu_flush_all_caches() takes the three-separate-flush path instead. That
distinction decides whether our single INV_ALL after enable is legitimate.
"""
import sys

EFR = 0x058F77EF22294A5A
EFR2 = 0x0
CONTROL = 0x220000000400

# amd_iommu_types.h:87-112
FEATURES = [
    (0,  "FEATURE_PREFETCH"),
    (1,  "FEATURE_PPR"),
    (2,  "FEATURE_X2APIC"),
    (3,  "FEATURE_NX"),
    (4,  "FEATURE_GT"),
    (6,  "FEATURE_IA"),
    (7,  "FEATURE_GA"),
    (8,  "FEATURE_HE"),
    (9,  "FEATURE_PC"),
    (21, "FEATURE_GAM_VAPIC"),
    (48, "FEATURE_GIOSUP"),
    (50, "FEATURE_EPHSUP"),
    (52, "FEATURE_HDSUP"),
    (63, "FEATURE_SNP"),
]

# amd_iommu_types.h:159-181
CONTROLS = [
    (0,  "CONTROL_IOMMU_EN"),
    (1,  "CONTROL_HT_TUN_EN"),
    (2,  "CONTROL_EVT_LOG_EN"),
    (3,  "CONTROL_EVT_INT_EN"),
    (4,  "CONTROL_COMWAIT_EN"),
    (8,  "CONTROL_PASSPW_EN"),
    (9,  "CONTROL_RESPASSPW_EN"),
    (10, "CONTROL_COHERENT_EN"),
    (11, "CONTROL_ISOC_EN"),
    (12, "CONTROL_CMDBUF_EN"),
    (13, "CONTROL_PPRLOG_EN"),
    (14, "CONTROL_PPRINT_EN"),
    (15, "CONTROL_PPR_EN"),
    (16, "CONTROL_GT_EN"),
    (17, "CONTROL_GA_EN"),
    (25, "CONTROL_GAM_EN"),
    (28, "CONTROL_GALOG_EN"),
    (29, "CONTROL_GAINT_EN"),
    (50, "CONTROL_XT_EN"),
    (51, "CONTROL_INTCAPXT_EN"),
    (59, "CONTROL_IRTCACHEDIS"),
    (61, "CONTROL_SNPAVIC_EN"),
]


def bits(value, table, label):
    print("{} = 0x{:016X}".format(label, value))
    for bit, name in table:
        print("  bit{:>2} {:<22} = {}".format(bit, name, (value >> bit) & 1))
    known = 0
    for bit, _ in table:
        known |= 1 << bit
    unknown = value & ~known
    print("  --- bits set but not named in Linux v6.6 headers ---")
    if unknown == 0:
        print("  (none)")
    else:
        for bit in range(64):
            if (unknown >> bit) & 1:
                print("  bit{:>2} {:<22} = 1".format(bit, "(undefined)"))
    print()


def main():
    bits(EFR, FEATURES, "EFR")
    print("EFR2 = 0x{:016X} (all-zero => no extended feature of interest)".format(EFR2))
    print()
    bits(CONTROL, CONTROLS, "CONTROL (firmware baseline)")

    # The decision this script exists for:
    ia = (EFR >> 6) & 1
    gt = (EFR >> 4) & 1
    print("=" * 62)
    print("FEATURE_IA (bit 6) = {}".format(ia))
    print("FEATURE_GT (bit 4) = {}".format(gt))
    print()
    if ia:
        print("=> CMD_INV_ALL exists; iommu_flush_all_caches() uses a single")
        print("   INV_ALL. Our post-enable INV_ALL is legitimate.")
    else:
        print("=> CMD_INV_ALL does NOT exist on this part.")
        print("   Linux iommu_flush_all_caches() (iommu.c:1299-1308) then runs")
        print("   flush_dte_all + flush_irt_all + flush_tlb_all instead.")
        print("   Our post-enable INV_ALL (type 0x08) is NOT a valid command.")
    if not gt:
        print("=> CMD_INV_DEV_ENTRY also unavailable (FEATURE_GT=0).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
