#!/usr/bin/env python3
"""Decode the AMD-Vi MMIO STATUS register (0x2020).

Bit definitions from linux/drivers/iommu/amd/amd_iommu_types.h.

The critical bit for this investigation is EVT_OVERFLOW (bit 0): if the
event ring wrapped during the observation window, the 38 events we
decoded are NOT the complete set and any count-based conclusion is void.
"""
import sys

STATUS_BITS = {
    0: "EVT_OVERFLOW",
    1: "EVT_INT",
    2: "COM_WAIT_INT",
    3: "EVT_RUN",
    4: "(undefined in Linux header)",
    5: "PPR_OVERFLOW",
    6: "PPR_INT",
    7: "PPR_RUN",
    8: "GALOG_RUN",
    9: "GALOG_OVERFLOW",
    10: "GALOG_INT",
}


def decode(v):
    print("STATUS = 0x%X" % v)
    print()
    for b in range(11):
        on = (v >> b) & 1
        print("  bit %-2d  %-26s = %d" % (b, STATUS_BITS.get(b, "?"), on))
    print()
    print("-" * 60)
    if (v >> 0) & 1:
        print("EVT_OVERFLOW = 1  ->  event ring wrapped!")
        print("  The decoded event count is a LOWER BOUND only;")
        print("  count-based comparisons are NOT trustworthy.")
    else:
        print("EVT_OVERFLOW = 0  ->  no wrap; the decoded events are the")
        print("  complete set for the window. Counts are trustworthy.")
    if (v >> 3) & 1:
        print("EVT_RUN = 1       ->  event logging was active.")
    else:
        print("EVT_RUN = 0       ->  event logging was NOT active (suspicious).")


if __name__ == "__main__":
    val = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x1A
    decode(val)
