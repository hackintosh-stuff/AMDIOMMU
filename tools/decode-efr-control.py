#!/usr/bin/env python3
"""Decode AMD-Vi EFR / CONTROL bit fields against Linux definitions.

Bit names come from linux/drivers/iommu/amd/amd_iommu_types.h:
  FEATURE_*  (EFR, MMIO 0x30)
  CONTROL_*  (CONTROL, MMIO 0x18)
and init.c iommu_init_flags() / early_enable_iommu().

Run:  py -3 decode-efr-control.py
"""

EFR = 0x058F77EF22294A5A
CONTROL_BASELINE = 0x220000000400
EFR2 = 0x0

# ---- EFR (Extended Feature Register) ----
EFR_BITS = {
    0: "PREFETCH",
    1: "PPR",
    2: "X2APIC",
    3: "NX",
    4: "GT",
    5: "rsvd",
    6: "IA",
    7: "GA",
    8: "HE",
    9: "PC",
    10: "HATS[0]",
    11: "HATS[1]",
    12: "GATS[0]",
    13: "GATS[1]",
    14: "GLX[0]",
    15: "GLX[1]",
    16: "rsvd",
    17: "rsvd",
    18: "rsvd",
    19: "rsvd",
    20: "rsvd",
    21: "GAM_VAPIC",
    22: "rsvd",
    23: "rsvd",
    24: "rsvd",
    25: "rsvd",
    26: "rsvd",
    27: "rsvd",
    28: "rsvd",
    29: "rsvd",
    30: "rsvd",
    31: "rsvd",
    32: "PASMAX[0]",
    33: "PASMAX[1]",
    34: "PASMAX[2]",
    35: "PASMAX[3]",
    36: "PASMAX[4]",
    37: "rsvd",
    38: "rsvd",
    39: "rsvd",
    40: "rsvd",
    41: "rsvd",
    42: "rsvd",
    43: "rsvd",
    44: "rsvd",
    45: "PERF_OPT",
    46: "rsvd",
    47: "rsvd",
    48: "GIOSUP",
    49: "HASUP",
    50: "EPHSUP",
    51: "rsvd",
    52: "HDSUP",
    53: "rsvd",
    54: "rsvd",
    55: "rsvd",
    56: "rsvd",
    57: "rsvd",
    58: "rsvd",
    59: "rsvd",
    60: "rsvd",
    61: "rsvd",
    62: "rsvd",
    63: "SNP",
}

# ---- CONTROL (MMIO 0x18) ----
CONTROL_BITS = {
    0: "IOMMU_EN",
    1: "HT_TUN_EN",
    2: "EVT_LOG_EN",
    3: "EVT_INT_EN",
    4: "COMWAIT_EN",
    5: "INV_TIMEOUT[0]",
    6: "INV_TIMEOUT[1]",
    7: "INV_TIMEOUT[2]",
    8: "PASSPW_EN",
    9: "RESPASSPW_EN",
    10: "COHERENT_EN",
    11: "ISOC_EN",
    12: "CMDBUF_EN",
    13: "PPRLOG_EN",
    14: "PPRINT_EN",
    15: "PPR_EN",
    16: "GT_EN",
    17: "GA_EN",
    25: "GAM_EN",
    28: "GALOG_EN",
    29: "GAINT_EN",
    30: "rsvd",
    31: "rsvd",
    41: "UNKNOWN_41",
    43: "NUM_INT_REMAP_MODE[0]",
    44: "NUM_INT_REMAP_MODE[1]",
    45: "EPH_EN",
    50: "XT_EN",
    51: "INTCAPXT_EN",
    58: "GCR3TRPMODE",
    59: "IRTCACHEDIS",
    61: "SNPAVIC_EN",
}


def decode(value, table, width=64, label=""):
    print("=" * 78)
    print("%s = 0x%0*X" % (label, width // 4, value))
    print("=" * 78)
    set_bits = []
    for b in range(width):
        if (value >> b) & 1:
            name = table.get(b, "?")
            set_bits.append((b, name))
    if not set_bits:
        print("  (no bits set)")
    for b, name in set_bits:
        print("  bit %-2d  %s" % (b, name))
    return set_bits


def main():
    decode(EFR, EFR_BITS, 64, "EFR (MMIO 0x30)")
    print()
    decode(EFR2, EFR_BITS, 64, "EFR2 (MMIO 0x38)")
    print()

    setb = decode(CONTROL_BASELINE, CONTROL_BITS, 64,
                  "CONTROL baseline (firmware preset)")
    print()
    print("-" * 78)
    print("Firmware preset bits = %s" % [b for b, _ in setb])
    print("-" * 78)

    # Sanity checks that matter for the M2-2b-2 failure analysis.
    print()
    print("Derived checks")
    print("-" * 78)
    checks = [
        ("FEATURE_NX (bit3)", (EFR >> 3) & 1,
         "if 0, page-table modes with <4 GiB coverage are illegal"),
        ("FEATURE_GT (bit4)", (EFR >> 4) & 1, "guest translation"),
        ("FEATURE_PC (bit9)", (EFR >> 9) & 1, "performance counters"),
        ("FEATURE_HASUP (bit49)", (EFR >> 49) & 1, "host address translation"),
        ("FEATURE_EPHSUP (bit50)", (EFR >> 50) & 1,
         "enhanced PPR handling -> explains CONTROL bit45"),
        ("FEATURE_HDSUP (bit52)", (EFR >> 52) & 1, "host dirty support"),
        ("FEATURE_SNP (bit63)", (EFR >> 63) & 1,
         "if 1, IOMMU_EN may be locked by firmware"),
        ("CONTROL IOMMU_EN (bit0)", (CONTROL_BASELINE >> 0) & 1,
         "must be 0 before we program anything"),
        ("CONTROL COHERENT_EN (bit10)", (CONTROL_BASELINE >> 10) & 1,
         "IOMMU walks page tables cache-coherently"),
        ("CONTROL CMDBUF_EN (bit12)", (CONTROL_BASELINE >> 12) & 1,
         "must be 0 before we program the command buffer"),
        ("CONTROL EVT_LOG_EN (bit2)", (CONTROL_BASELINE >> 2) & 1,
         "must be 0 before we program the event buffer"),
        ("CONTROL bit41", (CONTROL_BASELINE >> 41) & 1,
         "undocumented in Linux; firmware preset"),
        ("CONTROL EPH_EN (bit45)", (CONTROL_BASELINE >> 45) & 1,
         "firmware preset, matches FEATURE_EPHSUP"),
    ]
    for name, val, note in checks:
        print("  %-28s = %d   %s" % (name, val, note))

    print()
    print("=" * 78)
    print("Conclusion")
    print("=" * 78)
    nx = (EFR >> 3) & 1
    if nx:
        print("  FEATURE_NX=1 -> 3-level and 4-level page tables are both legal.")
        print("  Page-table mode is therefore NOT the cause of the M2-2b-2 freeze.")
    else:
        print("  FEATURE_NX=0 -> only page-table modes covering <4 GiB are legal!")
        print("  That would fully explain the freeze: 4-level and 3-level both")
        print("  violate the feature contract.")

    snp = (EFR >> 63) & 1
    if snp:
        print("  WARNING: FEATURE_SNP=1 -> IOMMU_EN might be locked.")
    else:
        print("  FEATURE_SNP=0 -> no SNP lock on IOMMU_EN.")


if __name__ == "__main__":
    main()
