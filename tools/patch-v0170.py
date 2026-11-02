#!/usr/bin/env python3
"""v0.17.0: A/B test of the domain id inside one boot.

Evidence that domid 0 is special
--------------------------------
linux/drivers/iommu/amd/iommu.c:1895
    return ida_alloc_range(&pdom_ids, 1, MAX_DOMAIN_ID - 1, GFP_ATOMIC);

Linux never hands out domain id 0 to a paging domain. And iommu.c:2205

    if (old_domid) { amd_iommu_flush_tlb_domid(iommu, old_domid); }

treats 0 as the "no previous domain" sentinel. Every M2-2b-2 run so far
used domid 0 in BOTH the DTE (data[1]) and INV_IOMMU_PAGES (data[1]).

Why an A/B inside one boot
--------------------------
Rebooting per hypothesis is expensive and noisy: the device's DMA pattern
differs from boot to boot (baseline fault counts have ranged 9..38 across
runs). Comparing two windows inside the SAME boot removes that variance.

Design
------
  window 1: domid 0, translate, 2 s, count faults      (existing baseline)
  window 2: domid 1, same table, 2 s, count faults     (new)

If window 2 is dramatically lower, or the device starts working, domid 0
was the problem. If window 2 is the same, domid is eliminated.

The DTE is restored to passthrough afterwards exactly as before, so the
safety properties of this step are unchanged.
"""
import sys

SRC = r"MSI_X570\amd-iommu\kext\AMDMapperProbe.cpp"

ANCHOR = """    // ---- 第 16 步：阴性对照（验证"0 fault"到底意味着什么）----"""

BLOCK = r'''    // ---- 第 15c 步：DOMID A/B 对照（本轮新增，唯一未测过的 Linux 差异）----
    //
    // 到此为止已经排除了：
    //   页表三层编码   → 与 Linux 逐位相同（v0.16.0 已 dump 并核对）
    //   PA/VA 不一致   → m2-b2-pa-va = identical
    //   缺映射         → fault-walk-present = 全部命中，absent = 0
    //   叶子层不可达   → 清零整张叶子表，fault 数无实质变化
    //   缓存一致性     → CONTROL_COHERENT_EN 已置位（固件预设 bit10）
    //
    // 剩下唯一"我们与 Linux 不同、且从未测过"的一点是 **domain id**：
    //   Linux:  ida_alloc_range(&pdom_ids, 1, MAX_DOMAIN_ID - 1, ...)
    //           —— 从不把 0 分配给 paging domain
    //           iommu.c:2205 `if (old_domid)` 把 0 当作"没有旧域"的哨兵
    //   我们:   DTE data[1] = 0，INV_IOMMU_PAGES data[1] = 0
    //
    // 如果硬件同样把 domid 0 视为"无域"，那么翻译必然全部失败——
    // 与"每个地址都 fault"完全吻合。
    //
    // 为什么在同一次启动里做 A/B：不同启动之间设备的 DMA 模式差异很大
    // （基线 fault 数在 9~38 之间波动），跨启动比较无法区分
    // "domid 造成的差异" 与 "启动间的自然波动"。同一启动内两段对比才干净。
    {
        // 记下第一段（domid 0）的结果作为对照基线
        setHexProperty(this, "m2-b2-domid0-faults", evtCount2);

        // 换成 domid 1：只改 DTE 的 data[1]，页表完全不动
        const UInt64 domid1 = 1;
        dte[tgt * 4 + 1] = domid1;
        OSSynchronizeIO();

        // 通知硬件：先失效 DTE，再按新 domid 失效页表
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
            setProperty("m2-b2-domid1-inv",
                        (obs == s) ? "done" : "FAIL-no-completion");
        }

        // 清事件日志，用 domid 1 观察同样 2 秒
        mmioWrite64(base, M2B2_OFF_EVT_HEAD, 0);
        mmioWrite64(base, M2B2_OFF_EVT_TAIL, 0);
        for (UInt32 i = 0; i < (M2B2_EVT_BUFFER_SIZE / 4); i++) evtBuf[i] = 0;

        IOSleep(2000);

        const UInt64 d1Head = mmioRead64(base, M2B2_OFF_EVT_HEAD);
        const UInt64 d1Tail = mmioRead64(base, M2B2_OFF_EVT_TAIL);
        const UInt64 d1Count = (d1Tail >= d1Head)
            ? ((d1Tail - d1Head) / 16) : 0;
        setHexProperty(this, "m2-b2-domid1-faults", d1Count);
        setHexProperty(this, "m2-b2-domid1-dte0", dte[tgt * 4 + 0]);
        setHexProperty(this, "m2-b2-domid1-dte1", dte[tgt * 4 + 1]);

        // ---- 判据 ----
        //
        // 注意不能只看"fault 变少"：设备会随时间退避，fault 数本身
        // 就会漂移。所以要求的是**量级变化**，而不是任何减少。
        const UInt64 d0 = evtCount2;
        const char *dv;
        const char *dm;
        if (d0 == 0) {
            dv = "no-domid0-baseline";
            dm = "cannot-compare";
        } else if (d1Count * 4 < d0) {
            dv = "DOMID0-IS-THE-PROBLEM";
            dm = "domid1-faults-much-lower-than-domid0";
        } else if (d1Count > d0 * 2) {
            dv = "domid1-worse";
            dm = "unexpected-more-faults-with-domid1";
        } else {
            dv = "domid-not-the-cause";
            dm = "same-order-with-domid0-and-domid1";
        }
        setProperty("m2-b2-domid-verdict", dv);
        setProperty("m2-b2-domid-meaning", dm);

        // 恢复 DTE 到直通（保持本步骤原有的安全收尾）
        dte[tgt * 4 + 0] = savedDte0;
        dte[tgt * 4 + 1] = savedDte1;
        dte[tgt * 4 + 2] = 0;
        dte[tgt * 4 + 3] = 0;
        OSSynchronizeIO();
        setProperty("m2-b2-domid-restore", "done");
    }

'''


def main():
    with open(SRC, "r", encoding="utf-8", newline="") as f:
        src = f.read()
    src = src.replace("\r\n", "\n")

    n = src.count(ANCHOR)
    print("anchor occurrences: %d" % n)
    if n != 1:
        print("REFUSING: anchor not unique")
        return 1

    src = src.replace(ANCHOR, BLOCK + ANCHOR, 1)
    with open(SRC, "w", encoding="utf-8", newline="\n") as f:
        f.write(src)
    print("patched OK, %d bytes" % len(src.encode("utf-8")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
