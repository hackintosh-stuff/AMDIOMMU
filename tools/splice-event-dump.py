#!/usr/bin/env python3
"""Splice the regenerated event-dump block into AMDMapperProbe.cpp.

Replaces the region from the "第 15b 步" marker up to (but not including)
the "第 16b 步" marker with the contents of evt-block.cpp.

Refuses to write unless exactly one start marker and one end marker are
found, so a silent mismatch can never corrupt the source.
"""
import sys

SRC = r"MSI_X570\amd-iommu\kext\AMDMapperProbe.cpp"
BLK = r"MSI_X570\amd-iommu\tools\evt-block.cpp"

START = "    // ---- 第 15b 步"
END = "    // ---- 第 16b 步"


def main():
    with open(SRC, "r", encoding="utf-8", newline="") as f:
        src = f.read()
    with open(BLK, "r", encoding="utf-8", newline="") as f:
        blk = f.read()

    src = src.replace("\r\n", "\n")
    blk = blk.replace("\r\n", "\n").replace("\r", "\n")
    if not blk.endswith("\n"):
        blk += "\n"
    blk += "\n"

    ns = src.count(START)
    ne = src.count(END)
    print("start markers: %d" % ns)
    print("end markers  : %d" % ne)
    if ns != 1 or ne != 1:
        print("REFUSING to splice: marker counts are not exactly 1")
        return 1

    i = src.index(START)
    j = src.index(END)
    if j <= i:
        print("REFUSING: end marker precedes start marker")
        return 1

    old = src[i:j]
    print("old region: %d bytes, %d lines" % (len(old), old.count("\n")))
    print("new block : %d bytes, %d lines" % (len(blk), blk.count("\n")))

    out = src[:i] + blk + src[j:]
    with open(SRC, "w", encoding="utf-8", newline="\n") as f:
        f.write(out)
    print("spliced OK, new file %d bytes" % len(out.encode("utf-8")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
