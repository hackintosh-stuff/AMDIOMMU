#!/usr/bin/env python3
"""Patch AMDMapperProbe.cpp with three decisive additions (v0.15.0).

1. PA<->VA correspondence check for the page table.
   This project already had one PA/VA confusion incident (flush_dcache64).
   The software walk reads PTEs through the VIRTUAL pointer `pt`, while the
   hardware reads them through the PHYSICAL base we wrote into the DTE. If
   those two do not actually describe the same memory, the walk proves
   nothing. This maps ptPA physically and compares byte for byte.

2. Dump the actual 64-bit leaf PTE for the faulting IOVA.
   So the encoding can be checked against Linux's expected value directly
   instead of being inferred.

3. A/B/A reversibility control for the leaf-level experiment.
   Last run gave 38 faults with the intact table and 16 with the whole leaf
   table zeroed. Fewer, not more. That is only evidence if the change is
   caused by zeroing the table and not by the device backing off over time.
   Measuring a THIRD window after restoring the table settles it:
     restored ~= baseline  -> the effect is reversible, therefore causal
     restored << baseline  -> plain time decay, previous conclusion void
"""
import sys

SRC = r"MSI_X570\amd-iommu\kext\AMDMapperProbe.cpp"

# ---------------------------------------------------------------- anchor 1
A1 = "    // ---- 第 5 步：清命令缓冲、cmd_sem、事件缓冲 ----"

B1 = r'''    // ---- 第 4b 步：验证页表物理地址与虚拟地址确实指向同一块内存 ----
    //
    // 为什么必须有这一步：
    //   软件走表（第 4 步）用的是**虚拟指针** pt；
    //   硬件走表用的是 DTE 里的 **物理基址** rootPA。
    //   如果这两者不是同一块内存，那么"软件走表通过"对硬件毫无意义——
    //   我们验证的是另一块内存。
    //
    // 本项目已经犯过一次 PA/VA 混淆（flush_dcache64 传物理地址 → 两次 panic），
    // 所以这个假设不能靠"应该没问题"过关，必须实测。
    //
    // 做法：把 ptPA 按物理地址映射进来，与 pt 逐字节比较。
    //   全部相同 → 软件走表的结论对硬件有效
    //   有差异   → 之前所有"页表正确"的结论都不成立
    {
        IOMemoryDescriptor *ptChk = IOMemoryDescriptor::withPhysicalAddress(
            (IOPhysicalAddress)ptPA, (IOByteCount)ptBytes, kIODirectionNone);
        if (!ptChk) {
            setProperty("m2-b2-pa-va", "FAIL-md");
        } else {
            IOMemoryMap *ptChkMap =
                ptChk->map(kIOMapInhibitCache | kIOMapAnywhere);
            if (!ptChkMap) {
                setProperty("m2-b2-pa-va", "FAIL-map");
            } else {
                volatile UInt64 *ptPhys =
                    (volatile UInt64 *)ptChkMap->getVirtualAddress();
                UInt64 mism = 0;
                UInt64 firstMism = 0;
                for (UInt64 i = 0; i < ptQwords; i++) {
                    if (ptPhys[i] != pt[i]) {
                        if (mism == 0) firstMism = i * 8;
                        mism++;
                    }
                }
                setHexProperty(this, "m2-b2-pa-va-mismatch", mism);
                if (mism) {
                    setHexProperty(this, "m2-b2-pa-va-firstmism", firstMism);
                }
                setProperty("m2-b2-pa-va",
                    mism == 0 ? "identical"
                              : "MISMATCH-pa-is-not-the-va-memory");
                ptChkMap->release();
            }
            ptChk->release();
        }
    }

'''

# ---------------------------------------------------------------- anchor 2
A2 = """        const UInt32 pI2 = (UInt32)((probeIova >> 30) & 0x1FF);
        const UInt32 pI3 = (UInt32)((probeIova >> 39) & 0x1FF);"""

B2 = """        const UInt32 pI2 = (UInt32)((probeIova >> 30) & 0x1FF);
        const UInt32 pI3 = (UInt32)((probeIova >> 39) & 0x1FF);
        const UInt32 pI1 = (UInt32)((probeIova >> 21) & 0x1FF);
        const UInt32 pI0 = (UInt32)((probeIova >> 12) & 0x1FF);"""

# ---------------------------------------------------------------- anchor 3
A3 = """        if (leafTbl) {
            // 保存整张表，然后整张清零。"""

B3 = """        if (leafTbl) {
            // 把这一项的**真实 64 位值**记下来。
            // 这样编码对不对可以直接与 Linux 的期望值逐位比对，
            // 不必再从"软件走表通过"反推。
            {
                const UInt32 leafIdxDump = fM22b2Use4K ? pI0 : pI1;
                setHexProperty(this, "m2-b2-leafprobe-pte",
                               leafTbl[leafIdxDump]);
            }

            // 保存整张表，然后整张清零。"""

# ---------------------------------------------------------------- anchor 4
A4 = """            OSSynchronizeIO();
            setProperty("m2-b2-leafprobe-restore", "done");
        }
    }"""

B4 = r'''            OSSynchronizeIO();
            setProperty("m2-b2-leafprobe-restore", "done");

            // ---- A/B/A 可逆性对照（本轮新增，用于排除时间衰减）----
            //
            // 上一段观察到：表完好 38 个 fault，整张叶子表清零后 16 个。
            // 数量变**少**了。这可能有两种解释：
            //   (a) 清零叶子表确实改变了硬件行为（硬件走得到叶子层）
            //   (b) 设备随时间自己退避了，与叶子表无关
            // 只有把表恢复后再测一次才能分开：
            //   恢复到接近 38 → 可逆 → 是清零造成的，结论 (a) 成立
            //   仍然停在 16  → 不可逆 → 是时间衰减，上一段结论作废
            {
                mmioWrite64(base, M2B2_OFF_EVT_HEAD, 0);
                mmioWrite64(base, M2B2_OFF_EVT_TAIL, 0);
                for (UInt32 i = 0; i < (M2B2_EVT_BUFFER_SIZE / 4); i++) {
                    evtBuf[i] = 0;
                }
                IOSleep(2000);
                const UInt64 afHead = mmioRead64(base, M2B2_OFF_EVT_HEAD);
                const UInt64 afTail = mmioRead64(base, M2B2_OFF_EVT_TAIL);
                const UInt64 afCount = (afTail >= afHead)
                    ? ((afTail - afHead) / 16) : 0;
                setHexProperty(this, "m2-b2-leafprobe-after-faults", afCount);

                // 判定：恢复后是否回到基线量级
                const UInt64 baseN = evtCount2;
                const char *rev;
                if (baseN == 0) {
                    rev = "no-baseline";
                } else if (afCount * 2 >= baseN) {
                    rev = "REVERSIBLE-zeroing-caused-the-change";
                } else {
                    rev = "TIME-DECAY-not-caused-by-leaf-table";
                }
                setProperty("m2-b2-leafprobe-reversibility", rev);
            }
        }
    }'''


def main():
    with open(SRC, "r", encoding="utf-8", newline="") as f:
        src = f.read()
    src = src.replace("\r\n", "\n")

    patches = [
        ("PA/VA check", A1, B1),
        ("leaf indices", A2, B2),
        ("PTE dump", A3, B3),
        ("A/B/A control", A4, B4),
    ]

    for name, anchor, repl in patches:
        n = src.count(anchor)
        print("%-16s anchor occurrences: %d" % (name, n))
        if n != 1:
            print("  REFUSING: anchor is not unique")
            return 1

    for name, anchor, repl in patches:
        src = src.replace(anchor, repl, 1)
        print("  applied: %s" % name)

    with open(SRC, "w", encoding="utf-8", newline="\n") as f:
        f.write(src)
    print("patched OK, %d bytes" % len(src.encode("utf-8")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
