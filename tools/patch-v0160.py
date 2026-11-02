#!/usr/bin/env python3
"""v0.16.0: dump every level of the walk for the faulting IOVA.

Why this is the right next step
-------------------------------
v0.15.0 established three facts:

  1. The leaf PTE is BYTE-IDENTICAL to what Linux's PAGE_SIZE_PTE would
     produce (0x7000000385AFFE01, verified against the macros).
  2. Every in-range fault address IS present in the table (walk-present=9,
     absent=0), and the address is identity-mapped.
  3. Zeroing the ENTIRE leaf table for the exact GiB that faults
     (page 16 = GiB 14, verified to be the right table) changed nothing:
     9 -> 10 -> 8 faults.

Fact 3 is the decisive one. If the hardware walked down to the leaf level
for that address, removing every leaf PTE for that whole GiB would have to
change its behaviour. It did not. So the hardware faults BEFORE the leaf
level -- at the root or the L2 -- or it never walks our table at all.

But the root and L2 entries have never been dumped. The software walk
proves they are present *as we wrote them*; it cannot prove the hardware
reads them from where we think. This patch records:

  * root entry for the faulting IOVA (root[0] in 4-level, root[i2] in 3-level)
  * L2 entry for the faulting IOVA
  * the leaf PTE (already added in v0.15.0)
  * the DTE as re-read from the device table
  * a compact software-walk trace with all three levels

Then the three levels can be compared against Linux's PM_LEVEL_PDE /
PAGE_SIZE_PTE macros offline, and if all three match, the only remaining
explanation is that the hardware is not using our root pointer at all.
"""
import sys

SRC = r"MSI_X570\amd-iommu\kext\AMDMapperProbe.cpp"

ANCHOR = """            // 把这一项的**真实 64 位值**记下来。
            // 这样编码对不对可以直接与 Linux 的期望值逐行比对，
            // 不必再从"软件走表通过"反推。"""

# The actual anchor text in the file (see v0.15.0 patch).
ANCHOR = """            // 把这一项的**真实 64 位值**记下来。
            // 这样编码对不对可以直接与 Linux 的期望值逐位比对，
            // 不必再从"软件走表通过"反推。
            {
                const UInt32 leafIdxDump = fM22b2Use4K ? pI0 : pI1;
                setHexProperty(this, "m2-b2-leafprobe-pte",
                               leafTbl[leafIdxDump]);
            }
"""

REPLACEMENT = """            // 把**每一层**的真实 64 位值都记下来。
            //
            // 为什么必须逐层 dump：
            //   v0.15.0 已经证明叶子项与 Linux 逐位相同，而且把整张叶子表
            //   清零后 fault 数几乎不变（9 -> 10 -> 8）。这说明硬件在到达
            //   叶子层**之前**就已经 fault 了。那么问题只可能在根层或 L2 层，
            //   或者硬件根本没读我们这张根表。
            //   而根项与 L2 项此前**从未被 dump 过**——软件走表只能证明
            //   "我们写进去的是这些值"，不能证明"硬件读的是这些值"。
            {
                const UInt32 leafIdxDump = fM22b2Use4K ? pI0 : pI1;
                setHexProperty(this, "m2-b2-leafprobe-pte",
                               leafTbl[leafIdxDump]);

                // ---- 根层 ----
                const UInt64 rootPte = root[fM22b2Use3L ? pI2 : pI3];
                setHexProperty(this, "m2-b2-walk-root-pte", rootPte);

                // ---- L2 层（4 级才有；3 级模式下根项直接指向叶子表）----
                if (!fM22b2Use3L) {
                    const UInt64 l2pa = rootPte & M2B2_PTE_ADDR_MASK;
                    if (l2pa >= (UInt64)ptPA &&
                        l2pa < (UInt64)ptPA + ptBytes) {
                        volatile UInt64 *l2t = (volatile UInt64 *)
                            ((UInt8 *)pt + (l2pa - (UInt64)ptPA));
                        setHexProperty(this, "m2-b2-walk-l2-pte", l2t[pI2]);
                        setHexProperty(this, "m2-b2-walk-l2-pa", l2pa);
                    } else {
                        setProperty("m2-b2-walk-l2-pte", "OUT-OF-RANGE");
                    }
                }

                // ---- 目标 DTE 的实际内容（从设备表重新读回）----
                setHexProperty(this, "m2-b2-walk-dte0", dte[tgt * 4 + 0]);
                setHexProperty(this, "m2-b2-walk-dte1", dte[tgt * 4 + 1]);

                // ---- 对照：这些表页自身的物理地址 ----
                setHexProperty(this, "m2-b2-walk-root-pa", rootPA);
                setHexProperty(this, "m2-b2-walk-leaf-pa",
                               (UInt64)ptPA +
                                   (UInt64)leafPageIdx * M2B2_PAGE_SIZE);
            }
"""


def main():
    with open(SRC, "r", encoding="utf-8", newline="") as f:
        src = f.read()
    src = src.replace("\r\n", "\n")

    n = src.count(ANCHOR)
    print("anchor occurrences: %d" % n)
    if n != 1:
        print("REFUSING: anchor not unique")
        return 1

    src = src.replace(ANCHOR, REPLACEMENT, 1)
    with open(SRC, "w", encoding="utf-8", newline="\n") as f:
        f.write(src)
    print("patched OK, %d bytes" % len(src.encode("utf-8")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
