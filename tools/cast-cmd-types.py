#!/usr/bin/env python3
"""Cast the AMD-Vi command type shifts to UInt32.

M2B2_CMD_INV_ALL is 0x08; 0x08 << 28 = 0x80000000 which does not fit in a
signed int, so the shift is performed in signed arithmetic and then converted
to UInt32, tripping -Wsign-conversion. An explicit cast makes the intent
unsigned and keeps the build warning-free under -Werror.
"""
import io

P = "kext/AMDMapperProbe.cpp"

REPS = [
    ("(M2B2_CMD_COMPL_WAIT << 28),",
     "((UInt32)M2B2_CMD_COMPL_WAIT << 28),"),
    ("0, (M2B2_CMD_INV_ALL << 28), 0, 0)) {",
     "0, ((UInt32)M2B2_CMD_INV_ALL << 28), 0, 0)) {"),
    ("(M2B2_CMD_INV_DEV_ENTRY << 28), 0, 0)) {",
     "((UInt32)M2B2_CMD_INV_DEV_ENTRY << 28), 0, 0)) {"),
    ("ctx.domid | (M2B2_CMD_INV_IOMMU_PAGES << 28),",
     "ctx.domid | ((UInt32)M2B2_CMD_INV_IOMMU_PAGES << 28),"),
]


def main():
    with io.open(P, encoding="utf-8", newline="") as f:
        s = f.read()
    for a, b in REPS:
        n = s.count(a)
        s = s.replace(a, b)
        print("{:>2}x  {}".format(n, a[:52]))
    with io.open(P, "w", encoding="utf-8", newline="") as f:
        f.write(s)


if __name__ == "__main__":
    main()
