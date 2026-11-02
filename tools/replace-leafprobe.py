#!/usr/bin/env python3
"""Replace the 16b leaf-probe block with a discriminating version.

Why replace rather than patch:
  The old probe cleared ONE leaf PTE and counted faults. But the correct
  page table ALREADY produces 6-12 faults in the same 2 s window, so
  "faults > 0" cannot distinguish
      (a) hardware reached the leaf level and saw PR=0
      (b) hardware never reached the leaf level
  Both produce faults. The criterion had no discriminating power.

New probe: keep the root and L2 valid, zero the ENTIRE leaf table that
serves the faulting address, and compare the fault COUNT against the
steady-state count measured with the intact table.

  faults_leaf_zeroed >> faults_intact   -> hardware walks to the leaf level
  faults_leaf_zeroed ~= faults_intact   -> hardware stops above the leaf level

The comparison baseline is evtCount2, measured a few lines earlier with
the intact table, so the two numbers come from the same boot and the
same device state.
"""
import sys

SRC = r"MSI_X570\amd-iommu\kext\AMDMapperProbe.cpp"

START = "    // ---- 第 16b 步"
END = "    // ---- 第 16 步：阴性对照"

BLOCK = r'''    // ---- 第 16b 步：叶子层可达性（有区分力的版本）----
    //
    // 【2026-10-31 重做】上一版只清零**一个**叶子 PTE，然后把
    // "faults > 0" 当成"硬件读到了叶子层"。这个判据是无效的：
    // 正确页表本身在同样 2 秒窗口里就有 6~12 个 fault，清掉一项后是 11 个。
    // 两种情况都 fault，无法区分
    //   (a) 硬件走到了叶子层，看到 PR=0 而报错
    //   (b) 硬件根本没走到叶子层，fault 另有原因
    //
    // 有区分力的做法：**整张叶子表清零**，与"表完好"时的稳态 fault 数比较。
    //   faults_leaf_zeroed >> faults_intact → 硬件确实走到叶子层
    //   faults_leaf_zeroed ≈  faults_intact → 硬件在叶子层之上就停了
    //
    // 基线用 evtCount2（同一启动、同一设备状态、表完好时测得的稳态计数），
    // 所以两个数字可比。
    {
        // 基线：表完好时的稳态 fault 数（第 15 步刚测过）
        setHexProperty(this, "m2-b2-leafprobe-baseline", evtCount2);

        // 目标：选一个设备实际访问过、且在映射范围内的 fault 地址。
        // 若所有 fault 都在范围外，退回到一个已知在范围内的地址。
        UInt64 probeIova = 0;
        {
            const UInt64 lim = fM22b2Use4K ? M2B2_4K_MAP_LIMIT
                                           : M2B2_IDENTITY_LIMIT;
            if (evtFirstAbsent && evtFirstAbsent < lim) {
                probeIova = evtFirstAbsent;
            } else if (evtFirstOA && evtFirstOA < lim) {
                probeIova = evtFirstOA;
            } else {
                probeIova = 0x10000000ULL;   // 256 MiB，恒等映射内
            }
        }
        setHexProperty(this, "m2-b2-leafprobe-iova", probeIova);

        const UInt32 pI2 = (UInt32)((probeIova >> 30) & 0x1FF);
        const UInt32 pI3 = (UInt32)((probeIova >> 39) & 0x1FF);

        // 定位服务这个 IOVA 的**整张叶子表**
        volatile UInt64 *leafTbl = NULL;
        UInt32 leafPageIdx = 0;
        if (fM22b2Use3L) {
            const UInt64 rpte = root[pI2];
            if (rpte & M2B2_PTE_PR) {
                const UInt64 lpa = rpte & M2B2_PTE_ADDR_MASK;
                if (lpa >= (UInt64)ptPA && lpa < (UInt64)ptPA + ptBytes) {
                    leafPageIdx = (UInt32)((lpa - (UInt64)ptPA) /
                                           M2B2_PAGE_SIZE);
                    leafTbl = pt + (UInt64)leafPageIdx * M2B2_PTE_COUNT;
                }
            }
        } else {
            const UInt64 rpte = root[pI3];
            if (rpte & M2B2_PTE_PR) {
                const UInt64 l2pa = rpte & M2B2_PTE_ADDR_MASK;
                if (l2pa >= (UInt64)ptPA && l2pa < (UInt64)ptPA + ptBytes) {
                    volatile UInt64 *l2t = (volatile UInt64 *)
                        ((UInt8 *)pt + (l2pa - (UInt64)ptPA));
                    const UInt64 lpte = l2t[pI2];
                    if (lpte & M2B2_PTE_PR) {
                        const UInt64 lpa = lpte & M2B2_PTE_ADDR_MASK;
                        if (lpa >= (UInt64)ptPA && lpa < (UInt64)ptPA + ptBytes) {
                            leafPageIdx = (UInt32)((lpa - (UInt64)ptPA) /
                                                   M2B2_PAGE_SIZE);
                            leafTbl = pt + (UInt64)leafPageIdx * M2B2_PTE_COUNT;
                        }
                    }
                }
            }
        }
        setHexProperty(this, "m2-b2-leafprobe-page", leafPageIdx);
        setProperty("m2-b2-leafprobe-found", leafTbl ? "yes" : "no");

        if (leafTbl) {
            // 保存整张表，然后整张清零。
            // 保存到栈上不可行（512 * 8 = 4 KiB），所以存到备用页里。
            // 用阴性对照要用的那页之前的空间不合适，这里单独用
            // badRoot 页——它在本步还没被写入（第 16 步才清零）。
            const UInt32 savePageIdx =
                M2B2_ROOT_PAGES +
                (fM22b2Use3L
                    ? M2B2_3L_LEAF_PAGES
                    : (M2B2_L2_PAGES +
                       (fM22b2Use4K ? (M2B2_4K_L1_PAGES + M2B2_4K_LEAF_PAGES)
                                    : M2B2_LEAF_PAGES)));
            volatile UInt64 *savePage =
                pt + (UInt64)savePageIdx * M2B2_PTE_COUNT;

            for (UInt32 i = 0; i < M2B2_PTE_COUNT; i++) {
                savePage[i] = leafTbl[i];
                leafTbl[i] = 0;
            }
            OSSynchronizeIO();

            // 清事件日志，用"根/L2 有效 + 整张叶子表为零"观察 2 秒
            mmioWrite64(base, M2B2_OFF_EVT_HEAD, 0);
            mmioWrite64(base, M2B2_OFF_EVT_TAIL, 0);
            for (UInt32 i = 0; i < (M2B2_EVT_BUFFER_SIZE / 4); i++) evtBuf[i] = 0;

            // 通知硬件重读（DTE 没变，但要刷 TLB 让旧的叶子项失效）
            {
                m2b2WriteCmd(ctx.cmdBuf, ctx.idx, tgt,
                             (M2B2_CMD_INV_DEV_ENTRY << 28), 0, 0);
                ctx.idx++;
                const UInt64 invAddr = m2b2InvAddress();
                m2b2WriteCmd(ctx.cmdBuf, ctx.idx,
                             0,
                             0 | (M2B2_CMD_INV_IOMMU_PAGES << 28),
                             (UInt32)(invAddr & 0xFFFFFFFF) | M2B2_CMD_PDE_MASK,
                             (UInt32)(invAddr >> 32));
                ctx.idx++;
                const UInt64 s = ++ctx.seq;
                m2b2WriteCmd(ctx.cmdBuf, ctx.idx,
                             (UInt32)((UInt64)semPA & 0xFFFFFFFF) | 0x01,
                             (UInt32)((UInt64)semPA >> 32) |
                                 (M2B2_CMD_COMPL_WAIT << 28),
                             (UInt32)(s & 0xFFFFFFFF),
                             (UInt32)(s >> 32));
                ctx.idx++;
                ctx.tail = ctx.idx * 16;
                mmioWrite64(base, M2B2_OFF_CMD_TAIL, ctx.tail);
                UInt32 loops = 0;
                UInt64 obs = 0;
                while (loops < M2B1_LOOP_TIMEOUT) {
                    obs = *sem;
                    if (obs == s) break;
                    loops++;
                }
                setProperty("m2-b2-leafprobe-inv",
                            (obs == s) ? "done" : "FAIL-no-completion");
            }

            IOSleep(2000);
            const UInt64 lpHead = mmioRead64(base, M2B2_OFF_EVT_HEAD);
            const UInt64 lpTail = mmioRead64(base, M2B2_OFF_EVT_TAIL);
            const UInt64 lpCount = (lpTail >= lpHead)
                ? ((lpTail - lpHead) / 16) : 0;
            setHexProperty(this, "m2-b2-leafprobe-faults", lpCount);

            // ---- 判据：与基线比较，而不是与 0 比较 ----
            //
            // 阈值取 2 倍：硬件若真的走到叶子层，整张表 512 项全失效，
            // 设备每一次 DMA 都会 fault，数量应远超稳态的个位数。
            // 若只是"表完好时本来就有几个 fault"，两者应同量级。
            const UInt64 base = evtCount2;
            const char *verdict;
            const char *meaning;
            if (lpCount > 0 && lpCount > base * 2) {
                verdict = "LEAF-LEVEL-REACHED";
                meaning = "zeroing-whole-leaf-table-multiplies-faults";
            } else if (lpCount == 0) {
                verdict = "LEAF-LEVEL-NOT-REACHED";
                meaning = "zeroing-whole-leaf-table-produces-no-faults";
            } else {
                verdict = "INCONCLUSIVE-same-order-as-baseline";
                meaning = "fault-count-unchanged-hardware-probably-stops-above-leaf";
            }
            setProperty("m2-b2-leafprobe-verdict", verdict);
            setProperty("m2-b2-leafprobe-meaning", meaning);

            // 恢复整张叶子表
            for (UInt32 i = 0; i < M2B2_PTE_COUNT; i++) {
                leafTbl[i] = savePage[i];
            }
            OSSynchronizeIO();
            setProperty("m2-b2-leafprobe-restore", "done");
        }
    }

'''

if __name__ == "__main__":
    with open(SRC, "r", encoding="utf-8", newline="") as f:
        src = f.read()
    src = src.replace("\r\n", "\n")

    ns = src.count(START)
    ne = src.count(END)
    print("start markers: %d" % ns)
    print("end markers  : %d" % ne)
    if ns != 1 or ne != 1:
        print("REFUSING: marker counts are not exactly 1")
        sys.exit(1)

    i = src.index(START)
    j = src.index(END)
    if j <= i:
        print("REFUSING: end marker precedes start marker")
        sys.exit(1)

    old = src[i:j]
    print("old region: %d bytes, %d lines" % (len(old), old.count("\n")))

    blk = BLOCK.replace("\r\n", "\n").replace("\r", "\n")
    out = src[:i] + blk + src[j:]

    with open(SRC, "w", encoding="utf-8", newline="\n") as f:
        f.write(out)
    print("replaced OK, new file %d bytes" % len(out.encode("utf-8")))
