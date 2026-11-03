// AMDMapperProbeDma.cpp -- DMA observation: rings, segments, event log
//
// Part of the AMDMapperProbe kext. Split out of the original
// single-file AMDMapperProbe.cpp by tools/split-probe.py; the
// function bodies are unchanged and in their original order.

#include "AMDMapperProbe.hpp"
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOWorkLoop.h>

// IOPCIDevice.h 在 SDK 里自身会触发两个 -Werror 级警告：
//   1. IOPCIDevice 被标 __kpi_deprecated("Use PCIDriverKit")
//   2. 其内部的 setProperty 重载未标 override（-Winconsistent-missing-override）
//
// 这两条都是 **Apple 头文件自身的问题**，不是本项目的代码缺陷：
//   - PCIDriverKit 是用户态 DriverKit 框架，无法实现 IOMapper 子类，
//     本项目必须是内核内 IOKit kext，只能用 IOPCIDevice。
//   - override 警告来自 SDK 声明，我们无法也不应修改 SDK 头。
//
// 因此仅在包含该头时抑制这两条，不全局关闭——其他真正的
// deprecation / override 问题仍会照常报错。
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Winconsistent-missing-override"
#include <IOKit/pci/IOPCIDevice.h>
#pragma clang diagnostic pop

#include <pexpert/pexpert.h>
#include <mach/kmod.h>
#include <mach/mach_time.h>
#include <kern/clock.h>
#include <libkern/OSByteOrder.h>

// 页表编码/解码的唯一实现。生产代码与 host 回归测试**包含同一个文件**，
// 测试跑的就是这里的分支，不是另写一份 Python 复述。
// 见 tests/pte-core-test.cpp 与 docs/m2-2b-2-round5-result.md。
#include "amd_iommu_pte_core.hpp"

// OSPtr<T> 的定义取决于 IOKIT_ENABLE_SHARED_PTR（SDK libkern/c++/OSPtr.h）：
//   定义时 = OSSharedPtr<T>；未定义时 = T*。SDK 默认未定义。
#if defined(IOKIT_ENABLE_SHARED_PTR)
    #define M1A_HAS_SHARED_PTR 1
#else
    #define M1A_HAS_SHARED_PTR 0
#endif

#include "AMDMapperProbeInternal.hpp"

// ===== AMDMapperProbeDma.cpp (original lines 3087..3116) =====
// ---- 第七轮：按芯片身份读关闭指针 / 尾指针 ----
//
// 第六轮的做法是"探测三个候选寄存器，取第一个非零且 < 1024 的"。
// 那不是身份判据，是猜测：一个陈旧或无关的寄存器只要恰好读出一个
// 小数字就会赢得选举。寄存器其实是芯片配置方式的确定性函数，而配置
// 方式可以从 TxConfig(0x40) 读出来并完全复现驱动的分支：
//
//   rtl812xIdentifyChip()      RTL812xLucyHardware.cpp:167
//     reg = TxConfig & 0x7c800000 ; ICVerID = TxConfig & 0x00700000
//     0x6C800000 + ICVerID 0 -> CFG_METHOD_41 ; 0x100000 -> 42
//   rtl812xx.cpp:17494-17507   HwSuppTxNoCloseVer（41/42 -> 6）
//   rtl812xx.cpp:17511-17525   MaxTxDescPtrMask（ver 6 -> 0x7FFFFFFF）
//   rtl812xx.cpp:17214-17232   rtl8125_setup_mqs_reg()
//     ver 6 -> HW_CLO_PTR0_8125BP = 0x0D34 / SW_TAIL_PTR0_8125BP = 0x0D30
//   RTL812xLucyHardware.cpp:1178 rtl812xGetHwCloPtr()
//     ver 3 -> RTL_R16，其余 RTL_R32
bool org_example_AMDMapperProbe::m2b2ReadCloPtr(volatile UInt8 *bar,
                                                UInt32 *out) {
    if (!bar || !out) return false;
    const amdobs::CloPtrSpec spec =
        amdobs::cloPtrSpecFor(fM22b2Dma.noCloseVer);
    if (!spec.valid) return false;
    const UInt32 v = (spec.width == 2)
        ? (UInt32)(*(volatile UInt16 *)(bar + spec.reg))
        : *(volatile UInt32 *)(bar + spec.reg);
    // 宽度与掩码都必须成立，否则这个样本不可解释。
    if (!amdobs::cloPtrSampleValid(v, spec.width, spec.mask)) return false;
    *out = v;
    return true;
}

// ===== AMDMapperProbeDma.cpp (original lines 3118..3126) =====
bool org_example_AMDMapperProbe::m2b2ReadTailPtr(volatile UInt8 *bar,
                                                 UInt32 *out) {
    if (!bar || !out) return false;
    const amdobs::CloPtrSpec spec =
        amdobs::cloPtrSpecFor(fM22b2Dma.noCloseVer);
    if (!spec.valid) return false;
    *out = *(volatile UInt32 *)(bar + spec.tailReg);
    return true;
}

// ===== AMDMapperProbeDma.cpp (original lines 3128..3233) =====
// ---- 第七轮：把描述符里的 (地址, 长度) 收进集合 ----
//
// 【与第六轮的根本差别】
//   第六轮在插入前调用 inIdentityRam()，其 RAM_TOP 固定 16 GiB。于是
//   "16 GiB 及以上的描述符地址"——恰恰是本轮要调查的那一类——在进入
//   集合之前就被丢掉了。集合随后"证明"fault 不在设备集合内，而它从来
//   就不可能在里面。
//
//   现在：**所有非零地址一律记录**，无论它在哪里。能不能读那块内存由
//   readVerdict() 单独判定，结果作为元数据保存。记录地址从不要求读它。
//
// 【第八轮：生命周期真的接进来了】
//   第七轮的版本收下了 tailCum / cloCum 两个参数，然后 `(void)` 掉，
//   只要能读到关闭指针就把每一条非零地址标成 LIFE_INFLIGHT。第七轮
//   采集里 tail = clo = 0x6a，也就是队列**已经排空**，而每一条历史
//   地址仍被报成 in-flight。
//
//   现在逐条按累计索引判定：txSlotCumulative() 给出该槽当前对应的累计
//   位置，再与关闭指针比较。同一个槽里可能已经是后一代的描述符，所以
//   生命周期必须按"这个槽现在的描述符"算，不能按"这个槽曾经有过描述符"。
void org_example_AMDMapperProbe::m2b2CollectTxSegments(const UInt8 *ring,
                                                       UInt32 count,
                                                       UInt32 tailCum,
                                                       UInt32 cloCum) {
    if (!ring) return;
    // 每个描述符最多一段，段数不会超过槽数。分批处理，避免一次申请过大。
    const UInt32 kBatch = 256;
    amdobs::Seg *segs = (amdobs::Seg *)IOMalloc(kBatch * sizeof(amdobs::Seg));
    if (!segs) {
        fM22b2Dma.unscanned += count;
        setProperty("m2-b2-dma-tx-collect", "SKIP-alloc-failed");
        return;
    }
    const UInt32 mask = fM22b2Dma.cloPtrMask
        ? fM22b2Dma.cloPtrMask : 0x7FFFFFFFu;
    UInt32 done = 0;
    UInt32 lifeCounts[4] = { 0, 0, 0, 0 };
    while (done < count) {
        const UInt32 n = ((count - done) < kBatch) ? (count - done) : kBatch;
        UInt32 used = 0;
        for (UInt32 k = 0; k < n; k++) {
            const UInt32 slot = done + k;
            const UInt8 *d = ring + (UInt64)slot * amdobs::TX_DESC_STRIDE;
            const UInt64 addr = amdobs::rd64(d + 8);
            if (addr == 0) continue;          // 从未编程：不是 DMA 目标
            const UInt32 opts1 = amdobs::rd32(d);
            UInt32 len = opts1 & amdobs::TX_DESC_LENMASK;
            const bool tso =
                (opts1 & (amdobs::TX_DESC_LARGESEND | amdobs::TX_DESC_GSO4 |
                          amdobs::TX_DESC_GSO6)) != 0;
            // 【第八轮】TSO 的 16 位字段是 MSS 不是长度；零长度也无法
            // 表达。两者都只能给一个**界**，必须打上 LEN_UNKNOWN，使
            // 它不能参与精确覆盖的论证。第七轮直接把 0x1000 当成真长度。
            UInt32 flags = 0;
            if (tso) {
                flags |= amdobs::RANGE_LEN_UNKNOWN | amdobs::RANGE_FROM_TSO;
                if (len == 0) len = 0x1000;
            } else if (len == 0) {
                flags |= amdobs::RANGE_LEN_UNKNOWN;
                len = 0x1000;
            }
            segs[used].base = addr;
            segs[used].len = len;
            segs[used].flags = flags;
            segs[used].pad = 0;
            used++;
            // 【第八轮】逐槽生命周期，而不是"有关闭指针就全标 in-flight"。
            const UInt32 life = amdobs::txSlotLifecycle(
                slot, tailCum, cloCum, 1024, mask, fM22b2Dma.haveCloPtr);
            if (life < 4) lifeCounts[life]++;
        }
        // insertSegments 每批只能给一个 lifecycle。取**最保守**的那个：
        // 只要有一条不确定，整批就不说成在途。逐条计数另行发布。
        UInt32 life;
        if (!fM22b2Dma.haveCloPtr) {
            life = amdobs::LIFE_SNAPSHOT;
        } else if (lifeCounts[amdobs::LIFE_SNAPSHOT] ||
                   lifeCounts[amdobs::LIFE_UNKNOWN]) {
            life = amdobs::LIFE_SNAPSHOT;
        } else if (lifeCounts[amdobs::LIFE_INFLIGHT] &&
                   !lifeCounts[amdobs::LIFE_COMPLETED]) {
            life = amdobs::LIFE_INFLIGHT;
        } else if (lifeCounts[amdobs::LIFE_COMPLETED] &&
                   !lifeCounts[amdobs::LIFE_INFLIGHT]) {
            life = amdobs::LIFE_COMPLETED;
        } else {
            // 混合：既有在途又有已交还。用 snapshot 表示"这一批不能
            // 用一个词概括"，而不是挑一个好看的。
            life = amdobs::LIFE_SNAPSHOT;
        }
        amdobs::insertSegments(fM22b2AddrSet, segs, used, amdobs::PURP_TX_BUF,
                               life, fM22b2Policy);
        done += n;
    }
    IOFree(segs, kBatch * sizeof(amdobs::Seg));

    // 逐类计数单独发布，使"混合"这个结论可被外部核对。
    setHexProperty(this, "m2-b2-dma-tx-life-inflight",
                   (UInt64)lifeCounts[amdobs::LIFE_INFLIGHT]);
    setHexProperty(this, "m2-b2-dma-tx-life-completed",
                   (UInt64)lifeCounts[amdobs::LIFE_COMPLETED]);
    setHexProperty(this, "m2-b2-dma-tx-life-snapshot",
                   (UInt64)lifeCounts[amdobs::LIFE_SNAPSHOT]);
    setHexProperty(this, "m2-b2-dma-tx-life-unknown",
                   (UInt64)lifeCounts[amdobs::LIFE_UNKNOWN]);
}

// ===== AMDMapperProbeDma.cpp (original lines 3235..3275) =====
void org_example_AMDMapperProbe::m2b2CollectRxSegments(const UInt8 *ring,
                                                       UInt32 count) {
    if (!ring) return;
    const UInt32 kBatch = 256;
    amdobs::Seg *segs = (amdobs::Seg *)IOMalloc(kBatch * sizeof(amdobs::Seg));
    if (!segs) {
        fM22b2Dma.unscanned += count;
        setProperty("m2-b2-dma-rx-collect", "SKIP-alloc-failed");
        return;
    }
    UInt32 done = 0;
    while (done < count) {
        const UInt32 n = ((count - done) < kBatch) ? (count - done) : kBatch;
        UInt32 used = 0;
        for (UInt32 k = 0; k < n; k++) {
            const UInt32 slot = done + k;
            const UInt8 *d = ring + (UInt64)slot * amdobs::RX_DESC_STRIDE;
            const UInt64 addr = amdobs::rd64(d + 8);
            if (addr == 0) continue;
            // RX 描述符的 blen 低 16 位是缓冲长度；驱动恒填 kRxBufferSize。
            const UInt32 blen = amdobs::rd32(d);
            UInt32 len = blen & 0xFFFF;
            UInt32 flags = 0;
            if (len == 0) {
                // 驱动恒填 kRxBufferSize，读到 0 说明这条不是有效描述符。
                // 仍然记录地址（可能是设备正在用的），但长度只能给界。
                len = 0x1000;
                flags |= amdobs::RANGE_LEN_UNKNOWN;
            }
            segs[used].base = addr;
            segs[used].len = len;
            segs[used].flags = flags;
            segs[used].pad = 0;
            used++;
        }
        amdobs::insertSegments(fM22b2AddrSet, segs, used, amdobs::PURP_RX_BUF,
                               amdobs::LIFE_SNAPSHOT, fM22b2Policy);
        done += n;
    }
    IOFree(segs, kBatch * sizeof(amdobs::Seg));
}

// ===== AMDMapperProbeDma.cpp (original lines 3277..3495) =====
// ---- 第八轮：窗口结束后的描述符生命周期扫描 ----
//
// 【为什么必须单独一个函数，而不能复用窗口前那次采集】
//
//   窗口前那次采集只知道"窗口开始时环里有什么"。它无法回答本轮的核心
//   问题：**窗口内提交的那几个描述符，各自的地址、长度、代次、完成状态
//   是什么**。
//
//   窗口两端的两个累计指针正好给出这个集合：[tailBefore, tailAfter) 就是
//   窗口内提交的全部累计索引。逐条走一遍，每条都能落到具体槽位与代次。
//
// 【为什么必须在窗口之后读】
//   完成状态由窗口结束时的关闭指针决定。窗口中间读只能得到中间态。
//
// 【并发条件与局限】（诚实列出，不藏在实现里）
//   - 读环时设备可能仍在写。但 [tailBefore, tailAfter) 之外的描述符不在
//     我们的遍历范围内，而范围内的描述符不会被改写：驱动只有提交新描述符
//     时才会改写槽位，那会把尾指针推过它。
//   - 驱动从不清除已完成描述符的地址字段，所以已完成的窗口描述符的字节
//     会一直保留到该槽被复用。这正是 txWindowCoverageOf() 里
//     `submits < ringSize` 这个条件的作用。
//   - 若窗口提交量达到环大小，最早的那几条已被覆盖。它们被计入
//     winOverwritten，不会被悄悄丢掉。
void org_example_AMDMapperProbe::m2b2ScanTxWindowAfter(const UInt8 *ring,
                                                       UInt32 count) {
    fM22b2Dma.winSubmits = fM22b2Dma.winCompletes = 0;
    fM22b2Dma.winVisited = fM22b2Dma.winDecoded = 0;
    fM22b2Dma.winOverwritten = 0;
    fM22b2Dma.winInflight = fM22b2Dma.winCompleted = 0;
    fM22b2Dma.winCompletedInWindow = 0;
    fM22b2Dma.winLenUnknown = fM22b2Dma.winTsoSlots = 0;
    fM22b2Dma.winGenBefore = fM22b2Dma.winGenAfter = 0;
    fM22b2Dma.winCovReason = amdobs::TXCOV_NO_RING;
    fM22b2Dma.winRecordsLost = 0;
    fM22b2Dma.winExact = false;
    fM22b2Dma.winQualityName = "not-run";
    fM22b2Dma.haveFirstCompleted = false;
    fM22b2Dma.winFirstCompletedAddr = 0;
    fM22b2Dma.winFirstCompletedLen = 0;
    fM22b2Dma.winFirstCompletedSlot = 0;
    fM22b2Dma.winFirstCompletedGen = 0;
    fM22b2WinSet.clear();

    if (!ring || count == 0) {
        setProperty("m2-b2-dma-win-scan", "SKIP-no-ring");
        return;
    }
    if (!fM22b2Dma.haveTailPtr || !fM22b2Dma.haveCloPtr) {
        fM22b2Dma.winCovReason = amdobs::TXCOV_NO_POINTERS;
        setProperty("m2-b2-dma-win-scan", "SKIP-no-pointers");
        setProperty("m2-b2-dma-win-cov-reason",
                    amdobs::txCoverageReasonName(fM22b2Dma.winCovReason));
        setProperty("m2-b2-dma-win-quality", "pointers-unreadable");
        return;
    }

    const UInt32 mask = fM22b2Dma.cloPtrMask
        ? fM22b2Dma.cloPtrMask : 0x7FFFFFFFu;

    fM22b2Dma.tWinScanStart = m2b2NowNS();

    // 【第九轮】窗口记录用**独立的**保存容量。
    //
    //   第八轮把窗口内那几条描述符塞进与几千条历史 RX/TX 快照共用的
    //   AddrSet（容量 64）。历史快照先填满，窗口记录就被丢进 dropped——
    //   于是"窗口内 3 条提交"可能在集合里一条都没有，而 dropped 只是
    //   变大。小规模受控操作的记录必须独立，否则它永远排在最后。
    //
    //   现在窗口记录写进 fM22b2WinSet，容量与快照集合分开，分析器可以
    //   分别核对两者的记账不变式。
    const UInt32 kBatch = 256;
    amdobs::Seg *segs = (amdobs::Seg *)IOMalloc(kBatch * sizeof(amdobs::Seg));
    UInt32 used = 0;
    UInt32 recordsLost = 0;
    UInt32 lifeCounts[4] = { 0, 0, 0, 0 };

    const amdobs::TxWindowScan sc = amdobs::scanTxWindow(
        ring, count,
        fM22b2Dma.tailPtrBefore, fM22b2Dma.tailPtrAfter,
        fM22b2Dma.cloPtrBefore, fM22b2Dma.cloPtrAfter,
        mask, true,
        [&](const amdobs::TxWindowDesc &d) {
            if (d.addr != 0) {
                if (segs && used < kBatch) {
                    segs[used].base = d.addr;
                    segs[used].len = d.len;
                    segs[used].flags = d.flags | amdobs::RANGE_IN_WINDOW;
                    segs[used].pad = 0;
                    used++;
                } else {
                    // 保存容量用尽：这条描述符**存在且可解码**，但没能留下
                    // 记录。它必须计入 recordsLost，使覆盖资格被撤回，
                    // 而不是静默消失。
                    recordsLost++;
                }
            }
            if (d.lifecycle < 4) lifeCounts[d.lifecycle]++;
        });

    // 窗口内的描述符按"窗口内提交"记录。lifecycle 取最保守值。
    if (segs && used) {
        UInt32 life;
        if (lifeCounts[amdobs::LIFE_SNAPSHOT] ||
            lifeCounts[amdobs::LIFE_UNKNOWN]) {
            life = amdobs::LIFE_SNAPSHOT;
        } else if (sc.inflight && sc.completed) {
            life = amdobs::LIFE_SNAPSHOT;
        } else if (sc.completed && !sc.inflight) {
            life = amdobs::LIFE_COMPLETED;
        } else {
            life = amdobs::LIFE_INFLIGHT;
        }
        amdobs::insertSegments(fM22b2WinSet, segs, used,
                               amdobs::PURP_TX_BUF, life, fM22b2Policy);
    }
    if (segs) IOFree(segs, kBatch * sizeof(amdobs::Seg));

    fM22b2Dma.tWinScanEnd = m2b2NowNS();

    fM22b2Dma.winSubmits = sc.coverage.submits;
    fM22b2Dma.winCompletes = sc.coverage.completes;
    fM22b2Dma.winVisited = sc.visited;
    fM22b2Dma.winDecoded = sc.decoded;
    fM22b2Dma.winOverwritten = sc.overwritten;
    fM22b2Dma.winInflight = sc.inflight;
    fM22b2Dma.winCompleted = sc.completed;
    fM22b2Dma.winCompletedInWindow = sc.completedInWindow;
    fM22b2Dma.winLenUnknown = sc.lenUnknown;
    fM22b2Dma.winTsoSlots = sc.tsoSlots;
    fM22b2Dma.winGenBefore = sc.coverage.genBefore;
    fM22b2Dma.winGenAfter = sc.coverage.genAfter;
    fM22b2Dma.winCovReason = sc.coverage.reason;
    fM22b2Dma.winRecordsLost = recordsLost;
    if (sc.firstCompletedAddr != 0) {
        fM22b2Dma.haveFirstCompleted = true;
        fM22b2Dma.winFirstCompletedAddr = sc.firstCompletedAddr;
        fM22b2Dma.winFirstCompletedLen = sc.firstCompletedLen;
        fM22b2Dma.winFirstCompletedSlot = sc.firstCompletedSlot;
        fM22b2Dma.winFirstCompletedGen = sc.firstCompletedGen;
    }

    // 【第九轮】扫描质量决定覆盖资格。
    //
    //   第八轮把计数器都发出来了，但 covered 只看指针算术：扫描提前停止、
    //   记录丢失、长度不可解码，全都不影响 tx-window-covered = yes。
    //   现在这些都会撤回资格——"发出来了"与"算进去了"是两件事。
    const amdobs::TxWindowQuality q =
        amdobs::txWindowQualityOf(sc, recordsLost);
    fM22b2Dma.winExact = q.exact;
    fM22b2Dma.winQualityName = amdobs::txWindowQualityName(q);
    const bool eligible = sc.coverage.covered && q.exact;

    // TX 缓冲路径的覆盖只在这里成立，而且只在这一个路径上。
    fM22b2Dma.pathCov.set(amdobs::PATH_TX_BUF,
                          eligible ? amdobs::COV_WINDOW
                                   : amdobs::COV_SNAPSHOT);
    fM22b2Dma.txWindowCovered = eligible;

    setProperty("m2-b2-dma-win-scan", "done");
    setProperty("m2-b2-dma-win-cov-reason",
                amdobs::txCoverageReasonName(sc.coverage.reason));
    setProperty("m2-b2-dma-win-quality", fM22b2Dma.winQualityName);
    setProperty("m2-b2-dma-win-exact", q.exact ? "yes" : "no");
    setHexProperty(this, "m2-b2-dma-win-records-lost",
                   (UInt64)recordsLost);
    setHexProperty(this, "m2-b2-dma-win-stop-reason",
                   (UInt64)sc.stopReason);
    setProperty("m2-b2-dma-win-stop-reason-name",
                amdobs::txScanStopName(sc.stopReason));
    setHexProperty(this, "m2-b2-dma-win-skipped",
                   (UInt64)sc.historicalSkipped);
    setHexProperty(this, "m2-b2-dma-win-prewin-completed",
                   (UInt64)sc.preWindowCompleted);
    setHexProperty(this, "m2-b2-dma-win-inflight-at-start",
                   (UInt64)sc.coverage.inFlightAtStart);
    setHexProperty(this, "m2-b2-dma-win-submits",
                   (UInt64)fM22b2Dma.winSubmits);
    setHexProperty(this, "m2-b2-dma-win-completes",
                   (UInt64)fM22b2Dma.winCompletes);
    setHexProperty(this, "m2-b2-dma-win-visited", (UInt64)sc.visited);
    setHexProperty(this, "m2-b2-dma-win-decoded", (UInt64)sc.decoded);
    setHexProperty(this, "m2-b2-dma-win-overwritten", (UInt64)sc.overwritten);
    setHexProperty(this, "m2-b2-dma-win-addr-zero", (UInt64)sc.addrZero);
    setHexProperty(this, "m2-b2-dma-win-inflight", (UInt64)sc.inflight);
    setHexProperty(this, "m2-b2-dma-win-completed", (UInt64)sc.completed);
    setHexProperty(this, "m2-b2-dma-win-completed-in-window",
                   (UInt64)sc.completedInWindow);
    setHexProperty(this, "m2-b2-dma-win-len-unknown", (UInt64)sc.lenUnknown);
    setHexProperty(this, "m2-b2-dma-win-tso", (UInt64)sc.tsoSlots);
    setHexProperty(this, "m2-b2-dma-win-gen-before", (UInt64)sc.coverage.genBefore);
    setHexProperty(this, "m2-b2-dma-win-gen-after", (UInt64)sc.coverage.genAfter);
    setHexProperty(this, "m2-b2-dma-t-win-scan-start", fM22b2Dma.tWinScanStart);
    setHexProperty(this, "m2-b2-dma-t-win-scan-end", fM22b2Dma.tWinScanEnd);
    setProperty("m2-b2-dma-tx-window-covered",
                eligible ? "yes" : "no");

    // 窗口集合的记账（与快照集合分开核对）。
    setHexProperty(this, "m2-b2-winset-ranges",
                   (UInt64)fM22b2WinSet.n);
    setHexProperty(this, "m2-b2-winset-raw-offered",
                   (UInt64)fM22b2WinSet.rawOffered);
    setHexProperty(this, "m2-b2-winset-merged-total",
                   (UInt64)fM22b2WinSet.mergedTotal);
    setHexProperty(this, "m2-b2-winset-dropped",
                   (UInt64)fM22b2WinSet.droppedCount);
    setHexProperty(this, "m2-b2-winset-len-unknown",
                   (UInt64)fM22b2WinSet.savedLenUnknown);

    if (fM22b2Dma.haveFirstCompleted) {
        setHexProperty(this, "m2-b2-dma-win-1st-completed-addr",
                       fM22b2Dma.winFirstCompletedAddr);
        setHexProperty(this, "m2-b2-dma-win-1st-completed-len",
                       (UInt64)fM22b2Dma.winFirstCompletedLen);
        setHexProperty(this, "m2-b2-dma-win-1st-completed-slot",
                       (UInt64)fM22b2Dma.winFirstCompletedSlot);
        setHexProperty(this, "m2-b2-dma-win-1st-completed-gen",
                       (UInt64)fM22b2Dma.winFirstCompletedGen);
    }
}

// ===== AMDMapperProbeDma.cpp (original lines 4477..4601) =====
void org_example_AMDMapperProbe::m2b2PublishDmaDefaults() {
    setProperty("m2-b2-dma-layout-known",
                fM22b2Dma.layoutKnown ? "yes" : "no");
    setHexProperty(this, "m2-b2-dma-tx-slots", fM22b2Dma.txSlots);
    setHexProperty(this, "m2-b2-dma-tx-zeroaddr", fM22b2Dma.txAddrZero);
    setHexProperty(this, "m2-b2-dma-tx-done-with-addr",
                   fM22b2Dma.txDoneWithAddrBefore);
    setHexProperty(this, "m2-b2-dma-ranges", fM22b2Dma.ranges);
    setHexProperty(this, "m2-b2-dma-dropped", fM22b2Dma.dropped);
    setHexProperty(this, "m2-b2-dma-raw-offered", fM22b2Dma.rawOffered);
    setHexProperty(this, "m2-b2-dma-merged-total", fM22b2Dma.mergedTotal);
    setHexProperty(this, "m2-b2-dma-unscanned", fM22b2Dma.unscanned);
    setProperty("m2-b2-dma-envelope-valid",
                fM22b2Dma.envValid ? "yes" : "no");
    setHexProperty(this, "m2-b2-dma-envelope-lo", fM22b2Dma.envLo);
    setHexProperty(this, "m2-b2-dma-envelope-hi", fM22b2Dma.envHi);
    setProperty("m2-b2-dma-coverage",
                amdobs::coverageName(fM22b2Dma.coverage));
    setHexProperty(this, "m2-b2-dma-read-ok", fM22b2Dma.readOkCount);
    setHexProperty(this, "m2-b2-dma-read-outofmap",
                   fM22b2Dma.readOutOfMapCount);
    setHexProperty(this, "m2-b2-dma-read-notram",
                   fM22b2Dma.readNotRamCount);
    setHexProperty(this, "m2-b2-dma-cloptr-reg", fM22b2Dma.cloPtrReg);
    setHexProperty(this, "m2-b2-dma-cloptr-width", fM22b2Dma.cloPtrWidth);
    setHexProperty(this, "m2-b2-dma-cloptr-mask", fM22b2Dma.cloPtrMask);
    setHexProperty(this, "m2-b2-dma-cloptr-before", fM22b2Dma.cloPtrBefore);
    setHexProperty(this, "m2-b2-dma-cfgmethod", fM22b2Dma.cfgMethod);
    setHexProperty(this, "m2-b2-dma-noclosever", fM22b2Dma.noCloseVer);
    setProperty("m2-b2-dma-chip-known",
                fM22b2Dma.chipKnown ? "yes" : "no");
    setProperty("m2-b2-dma-tx-window-covered",
                fM22b2Dma.txWindowCovered ? "yes" : "no");
    setProperty("m2-b2-dma-cloptr-delta-valid", "no-observation-incomplete");
    setHexProperty(this, "m2-b2-dma-t-obs-before", fM22b2Dma.tObsBefore);
    setHexProperty(this, "m2-b2-dma-t-obs-after", fM22b2Dma.tObsAfter);
    setHexProperty(this, "m2-b2-dma-t-clo-before", fM22b2Dma.tCloBefore);

    // 【第八轮】SKIP 路径同样发布逐路径覆盖与窗口扫描字段，且明确标注
    // 为未观察。否则分析器只能报"字段缺失"，而事实是"观察跑了但没走完"。
    setProperty("m2-b2-dma-cov-txring", "none");
    setProperty("m2-b2-dma-cov-rxring", "none");
    setProperty("m2-b2-dma-cov-txbuf", "none");
    setProperty("m2-b2-dma-cov-rxbuf", "none");
    setProperty("m2-b2-dma-cov-stat", "none");
    setProperty("m2-b2-dma-cov-weakest", "none");
    setProperty("m2-b2-dma-cov-all-window", "no");
    setProperty("m2-b2-dma-tx-ring-basis", "none");
    setProperty("m2-b2-dma-rx-ring-basis", "none");
    setHexProperty(this, "m2-b2-dma-tx-ring-decoded", 0);
    setHexProperty(this, "m2-b2-dma-rx-ring-ringend-at-last", 0);
    setHexProperty(this, "m2-b2-dma-len-unknown", 0);
    setProperty("m2-b2-dma-win-scan", "SKIP-observation-did-not-complete");
    setHexProperty(this, "m2-b2-dma-win-submits", 0);
    setHexProperty(this, "m2-b2-dma-win-completes", 0);
    setHexProperty(this, "m2-b2-dma-win-visited", 0);
    setHexProperty(this, "m2-b2-dma-win-decoded", 0);
    setHexProperty(this, "m2-b2-dma-win-overwritten", 0);
    setHexProperty(this, "m2-b2-dma-win-inflight", 0);
    setHexProperty(this, "m2-b2-dma-win-completed", 0);
    setHexProperty(this, "m2-b2-dma-win-completed-in-window", 0);
    setHexProperty(this, "m2-b2-dma-win-len-unknown", 0);
    setHexProperty(this, "m2-b2-dma-win-tso", 0);
    setHexProperty(this, "m2-b2-dma-win-gen-before", 0);
    setHexProperty(this, "m2-b2-dma-win-gen-after", 0);
    setProperty("m2-b2-dma-win-cov-reason", "not-observed");
    setHexProperty(this, "m2-b2-dma-tx-life-inflight", 0);
    setHexProperty(this, "m2-b2-dma-tx-life-completed", 0);
    setHexProperty(this, "m2-b2-dma-tx-life-snapshot", 0);
    setHexProperty(this, "m2-b2-dma-tx-life-unknown", 0);

    // 【第九轮】SKIP 路径也必须发布窗口质量、边界位置与驱动日志字段。
    //
    // 理由同上一段：分析器需要能区分"这一项不适用"与"这一项缺失"。
    // 缺失只能报 CANNOT ANALYSE，而那等于说"我没有数据"——事实是
    // "观察没走完，原因如下"。
    setProperty("m2-b2-dma-win-quality", "not-run");
    setProperty("m2-b2-dma-win-exact", "no");
    setHexProperty(this, "m2-b2-dma-win-records-lost", 0);
    setHexProperty(this, "m2-b2-dma-win-stop-reason", 0);
    setProperty("m2-b2-dma-win-stop-reason-name", "no-ring");
    setHexProperty(this, "m2-b2-dma-win-skipped", 0);
    setHexProperty(this, "m2-b2-dma-win-prewin-completed", 0);
    setHexProperty(this, "m2-b2-dma-win-inflight-at-start", 0);
    setHexProperty(this, "m2-b2-dma-win-addr-zero", 0);
    setProperty("m2-b2-dma-boundary-in-window", "no");
    setHexProperty(this, "m2-b2-winset-ranges", 0);
    setHexProperty(this, "m2-b2-winset-raw-offered", 0);
    setHexProperty(this, "m2-b2-winset-merged-total", 0);
    setHexProperty(this, "m2-b2-winset-dropped", 0);
    setHexProperty(this, "m2-b2-winset-len-unknown", 0);
    setProperty("m2-b2-obs", "SKIP-observation-did-not-complete");
    setProperty("m2-b2-obs-format", "absent");
    setProperty("m2-b2-obs-state", "absent");
    setProperty("m2-b2-obs-why", "not-read");
    setHexProperty(this, "m2-b2-obs-head", 0);
    setHexProperty(this, "m2-b2-obs-published", 0);
    setHexProperty(this, "m2-b2-obs-first", 0);
    setHexProperty(this, "m2-b2-obs-wrapped", 0);
    setHexProperty(this, "m2-b2-obs-bytes", 0);
    setHexProperty(this, "m2-b2-obs-records", 0);
    setHexProperty(this, "m2-b2-obs-t-start", 0);
    setHexProperty(this, "m2-b2-obs-t-published", 0);
    setHexProperty(this, "m2-b2-obs-ops", 0);
    setHexProperty(this, "m2-b2-obs-submits", 0);
    setHexProperty(this, "m2-b2-obs-dones", 0);
    setHexProperty(this, "m2-b2-obs-doorbells", 0);
    setHexProperty(this, "m2-b2-obs-rx-done", 0);
    setHexProperty(this, "m2-b2-obs-rx-addr-zero", 0);
    setHexProperty(this, "m2-b2-obs-stale", 0);
    setHexProperty(this, "m2-b2-obs-unmatched-done", 0);
    setHexProperty(this, "m2-b2-obs-uncompleted", 0);
    setHexProperty(this, "m2-b2-obs-overflow", 0);
    setProperty("m2-b2-obs-all-completed", "no");
    setHexProperty(this, "m2-b2-obs-win-submits", 0);
    setHexProperty(this, "m2-b2-obs-win-dones", 0);
    setHexProperty(this, "m2-b2-obs-win-paired", 0);
    setHexProperty(this, "m2-b2-obs-win-orphan-done", 0);
    setProperty("m2-b2-obs-window-complete", "no");
    setProperty("m2-b2-obs-source", "none");
    setHexProperty(this, "m2-b2-obs-first-submit-t", 0);
    setHexProperty(this, "m2-b2-obs-last-done-t", 0);
    setHexProperty(this, "m2-b2-obs-first-rx-addr", 0);
    setHexProperty(this, "m2-b2-obs-last-rx-addr", 0);
}

// ===== AMDMapperProbeDma.cpp (original lines 4603..5183) =====
void org_example_AMDMapperProbe::observeDeviceDma() {
    fM22b2Dma.ran = false;
    fM22b2Dma.barMapped = false;
    fM22b2Dma.barBase = 0;
    fM22b2Dma.barLen = 0;
    fM22b2Dma.haveTxRing = false;
    fM22b2Dma.txRingBase = 0;
    fM22b2Dma.haveRxRing = false;
    fM22b2Dma.rxRingBase = 0;
    fM22b2Dma.haveStat = false;
    fM22b2Dma.statBase = 0;
    fM22b2Dma.haveCounter = false;
    fM22b2Dma.counterAddr = 0;
    fM22b2Dma.txSlots = fM22b2Dma.txOwned = fM22b2Dma.txDone = 0;
    fM22b2Dma.txAddrZero = 0;
    fM22b2Dma.txTsoSlots = 0;
    fM22b2Dma.rxSlots = fM22b2Dma.rxOwned = fM22b2Dma.rxDone = 0;
    fM22b2Dma.rxAddrZero = 0;
    fM22b2Dma.txFirstAddr = fM22b2Dma.rxFirstAddr = 0;
    fM22b2Dma.ranges = fM22b2Dma.dropped = 0;
    fM22b2Dma.rawOffered = fM22b2Dma.mergedTotal = 0;
    fM22b2Dma.unscanned = 0;
    fM22b2Dma.txBufRanges = fM22b2Dma.rxBufRanges = 0;
    fM22b2Dma.envValid = false;
    fM22b2Dma.envLo = fM22b2Dma.envHi = 0;
    fM22b2Dma.readOkCount = 0;
    fM22b2Dma.readOutOfMapCount = 0;
    fM22b2Dma.readNotRamCount = 0;
    fM22b2Dma.coverage = amdobs::COV_NONE;
    fM22b2Dma.txDoneWithAddrBefore = 0;
    fM22b2Dma.txDoneWithAddrAfter = 0;
    fM22b2Dma.haveCloPtr = false;
    fM22b2Dma.cloPtrBefore = 0;
    fM22b2Dma.cloPtrAfter = 0;
    fM22b2Dma.cloPtrReg = 0;
    fM22b2Dma.cloPtrWidth = 0;
    fM22b2Dma.cloPtrMask = 0;
    fM22b2Dma.txConfigRaw = 0;
    fM22b2Dma.cfgMethod = 0;
    fM22b2Dma.noCloseVer = 0;
    fM22b2Dma.chipKnown = false;
    fM22b2Dma.haveCloDelta = false;
    fM22b2Dma.cloDelta = 0;
    fM22b2Dma.cloDeltaValid = false;
    fM22b2Dma.haveTailPtr = false;
    fM22b2Dma.tailPtrBefore = 0;
    fM22b2Dma.tailPtrAfter = 0;
    fM22b2Dma.txWindowCovered = false;
    fM22b2Dma.haveDoneDelta = false;
    fM22b2Dma.skipReason = nullptr;

    // 时间边界：单调纳秒，便于与窗口起止逐项核对。
    fM22b2Dma.tObsBefore = m2b2NowNS();

    setProperty("m2-b2-dma-obs", "started");

    // ---- 0. 物理布局策略 ----
    //
    // 【第七轮】这里只建立"能不能读"的判据，**不**参与记录。
    // 恒等映射上限是 16 GiB（M2-2b-2 的覆盖范围），它不是 RAM 上限；
    // 第六轮把它当成 RAM 上限去做记录过滤，正是本轮要修的错误之一。
    //
    // layoutKnown 保持 false：本轮没有取得与**本次启动**对应的权威
    // 物理布局，所以任何地址都不解引用，但一律记录。这是诚实的做法：
    // 宁可少读一块内存，也不要把一个猜出来的布局当成事实。
    fM22b2Policy = amdobs::defaultMapPolicy();
    fM22b2Policy.limit = M2B2_IDENTITY_LIMIT;
    fM22b2Policy.layoutKnown = false;
    fM22b2Dma.layoutKnown = false;
    fM22b2Dma.layoutSource = "none-per-boot-source-unavailable";
    setProperty("m2-b2-dma-layout-known", "no");
    setProperty("m2-b2-dma-layout-source",
                "no authoritative per-boot physical layout was captured");

    // ---- 1. 找网卡的 IOPCIDevice ----
    //
    // IOPCIDevice 在 SDK 里被标了 __kpi_deprecated("Use PCIDriverKit")，
    // 而本工程用 -Werror 编译，所以必须局部压掉这条诊断。
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    IOPCIDevice *nic = nullptr;
    {
        IOService *svc = findNicServiceOnly();
        if (svc) {
            nic = OSDynamicCast(IOPCIDevice, svc);
            if (!nic) svc->release();
        }
    }
#pragma clang diagnostic pop
    if (!nic) {
        fM22b2Dma.skipReason = "no-nic-pcidevice";
        setProperty("m2-b2-dma-obs", "SKIP-no-nic-pcidevice");
        fM22b2Dma.tObsAfter = m2b2NowNS();
        m2b2PublishDmaDefaults();
        return;
    }

    // ---- 2. 取 BAR2 的物理区间并只读映射 ----
    //
    // 【v0.21.7 修正：必须按配置寄存器取，不能按数组索引取】
    // getDeviceMemoryWithIndex(2) 是设备内存数组的第 3 个元素，不是 BAR2；
    // 实测返回 {0xfc860000,0x4000} 而真正的 BAR2 是 {0xfc800000,0x40000}。
    // 正确接口是 getDeviceMemoryWithRegister()。
    IODeviceMemory *dm =
        nic->getDeviceMemoryWithRegister(kIOPCIConfigBaseAddress2);
    if (!dm) {
        nic->release();
        fM22b2Dma.skipReason = "no-bar2-device-memory";
        setProperty("m2-b2-dma-obs", "SKIP-no-bar2");
        fM22b2Dma.tObsAfter = m2b2NowNS();
        m2b2PublishDmaDefaults();
        return;
    }
    const IOPhysicalAddress barPhys = dm->getPhysicalAddress();
    const IOByteCount     barSize = dm->getLength();
    setHexProperty(this, "m2-b2-dma-bar-pa", (UInt64)barPhys);
    setHexProperty(this, "m2-b2-dma-bar-len", (UInt64)barSize);
    setProperty("m2-b2-dma-bar-src", "kIOPCIConfigBaseAddress2");

    if (barPhys == 0 || barSize == 0 || barSize > 0x1000000) {
        nic->release();
        fM22b2Dma.skipReason = "implausible-bar";
        setProperty("m2-b2-dma-obs", "SKIP-implausible-bar");
        fM22b2Dma.tObsAfter = m2b2NowNS();
        m2b2PublishDmaDefaults();
        return;
    }

    IOMemoryMap *barMap =
        nic->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress2,
                                         kIOMapInhibitCache | kIOMapReadOnly);
    if (!barMap) {
        nic->release();
        fM22b2Dma.skipReason = "bar-map-failed";
        setProperty("m2-b2-dma-obs", "SKIP-bar-map-failed");
        fM22b2Dma.tObsAfter = m2b2NowNS();
        m2b2PublishDmaDefaults();
        return;
    }
    volatile UInt8 *bar =
        (volatile UInt8 *)(uintptr_t)barMap->getVirtualAddress();
    fM22b2Dma.barMapped = true;
    fM22b2Dma.barBase = (UInt64)barPhys;
    fM22b2Dma.barLen = (UInt64)barSize;
    setProperty("m2-b2-dma-obs", "bar-mapped-readonly");

    // ---- 3. 芯片身份：关闭指针的寄存器由它推导，不靠选举 ----
    //
    // 第六轮"取第一个非零且 < 1024 的候选寄存器"不是身份判据。寄存器是
    // 芯片配置方式的确定性函数，而配置方式可以从 TxConfig(0x40) 读出
    // 并完全复现驱动的分支（见 amd_iommu_dma_observe.hpp 的推导注释）。
    {
        const UInt32 txConfig = *(volatile UInt32 *)(bar + amdobs::REG_TX_CONFIG);
        const amdobs::ChipId chip = amdobs::identifyChip(txConfig);
        const amdobs::CloPtrSpec spec = amdobs::cloPtrSpecFor(chip.noCloseVer);

        fM22b2Dma.txConfigRaw = txConfig;
        fM22b2Dma.cfgMethod = chip.cfgMethod;
        fM22b2Dma.noCloseVer = chip.noCloseVer;
        fM22b2Dma.chipKnown = chip.known;
        fM22b2Dma.cloPtrReg = spec.reg;
        fM22b2Dma.cloPtrWidth = spec.width;
        fM22b2Dma.cloPtrMask = spec.mask;

        setHexProperty(this, "m2-b2-dma-txconfig", (UInt64)txConfig);
        setHexProperty(this, "m2-b2-dma-cfgmethod", (UInt64)chip.cfgMethod);
        setHexProperty(this, "m2-b2-dma-noclosever", (UInt64)chip.noCloseVer);
        setProperty("m2-b2-dma-chip-known", chip.known ? "yes" : "NO");
        setHexProperty(this, "m2-b2-dma-cloptr-reg", (UInt64)spec.reg);
        setHexProperty(this, "m2-b2-dma-cloptr-width", (UInt64)spec.width);
        setHexProperty(this, "m2-b2-dma-cloptr-mask", (UInt64)spec.mask);
        setProperty("m2-b2-dma-cloptr-id-src",
                    chip.known ? "derived-from-TxConfig"
                               : "unknown-chip-no-register");
    }

    // ---- 4. 读设备自己的 DMA 基址寄存器 ----
    //
    // 这些是驱动写进去、硬件照着访问的地址。读它们等于问设备
    // "你现在在访问哪些内存"，与驱动走不走 mapper 无关。
    m2b2ReadBar64(bar, amdobs::REG_TX_DESC_LOW, amdobs::REG_TX_DESC_HIGH,
                  &fM22b2Dma.txRingBase);
    fM22b2Dma.haveTxRing = (fM22b2Dma.txRingBase != 0);
    m2b2ReadBar64(bar, amdobs::REG_RX_DESC_LOW, amdobs::REG_RX_DESC_HIGH,
                  &fM22b2Dma.rxRingBase);
    fM22b2Dma.haveRxRing = (fM22b2Dma.rxRingBase != 0);
    m2b2ReadBar64(bar, amdobs::REG_COUNTER_LOW, amdobs::REG_COUNTER_HIGH,
                  &fM22b2Dma.counterAddr);
    fM22b2Dma.haveCounter = (fM22b2Dma.counterAddr != 0);

    // 关闭指针与尾指针：按推导出的寄存器读，并记录时刻。
    {
        UInt32 v = 0;
        if (m2b2ReadCloPtr(bar, &v)) {
            fM22b2Dma.haveCloPtr = true;
            fM22b2Dma.cloPtrBefore = v;
            fM22b2Dma.tCloBefore = m2b2NowNS();
        }
        UInt32 t = 0;
        if (m2b2ReadTailPtr(bar, &t)) {
            fM22b2Dma.haveTailPtr = true;
            fM22b2Dma.tailPtrBefore = t;
            fM22b2Dma.tTailBefore = m2b2NowNS();
        }
        setHexProperty(this, "m2-b2-dma-cloptr-before",
                       (UInt64)fM22b2Dma.cloPtrBefore);
        setHexProperty(this, "m2-b2-dma-tailptr-before",
                       (UInt64)fM22b2Dma.tailPtrBefore);
        setProperty("m2-b2-dma-cloptr-usable",
                    fM22b2Dma.haveCloPtr ? "yes" : "no");
    }

    setHexProperty(this, "m2-b2-dma-tx-ring", fM22b2Dma.txRingBase);
    setHexProperty(this, "m2-b2-dma-rx-ring", fM22b2Dma.rxRingBase);
    setHexProperty(this, "m2-b2-dma-counter", fM22b2Dma.counterAddr);
    setProperty("m2-b2-dma-tx-ring-src",
                fM22b2Dma.haveTxRing ? "register" : "zero-not-programmed");
    setProperty("m2-b2-dma-rx-ring-src",
                fM22b2Dma.haveRxRing ? "register" : "zero-not-programmed");

    // ---- 5. 建立地址集合 ----
    //
    // 【第七轮】所有地址一律记录。能不能读由 readVerdict 单独判定。
    //
    // 【第九轮】窗口记录用独立的集合，这里清空的是快照集合，窗口集合在
    // 窗口扫描时清空。两者容量分开，小规模受控操作不会排在几千条历史
    // 快照之后被丢掉。
    amdobs::AddrSet &set = fM22b2AddrSet;
    set.clear();
    fM22b2WinSet.clear();

    const UInt64 kTxDescBytes = 1024ULL * amdobs::TX_DESC_STRIDE;   // 32 KiB
    const UInt64 kRxDescBytes = 1024ULL * amdobs::RX_DESC_STRIDE;   // 16 KiB
    const UInt64 kStatBytes   = 0x1000ULL;

    // The NIC reports bus addresses. Native fixed DMA now uses IOVAs, while
    // a CPU IOMemoryDescriptor still needs the registered buffer's real PA.
    // Keep the bus values in the observation set and resolve only CPU reads.
    UInt64 txReadPA = fM22b2Dma.txRingBase;
    UInt64 rxReadPA = fM22b2Dma.rxRingBase;
    const bool txBacking = !fR31Session ||
        r40FixedReadPA(r40fixed::kTxRing, fM22b2Dma.txRingBase, kTxDescBytes, &txReadPA);
    const bool rxBacking = !fR31Session ||
        r40FixedReadPA(r40fixed::kRxRing, fM22b2Dma.rxRingBase, kRxDescBytes, &rxReadPA);
    const auto txReadVerdict = txBacking ?
        amdobs::readVerdictDeviceReported(txReadPA, kTxDescBytes, fM22b2Policy) :
        amdobs::RD_UNVERIFIED;
    const auto rxReadVerdict = rxBacking ?
        amdobs::readVerdictDeviceReported(rxReadPA, kRxDescBytes, fM22b2Policy) :
        amdobs::RD_UNVERIFIED;
    setHexProperty(this, "m2-b2-dma-tx-ring-read-pa", txBacking ? txReadPA : 0);
    setHexProperty(this, "m2-b2-dma-rx-ring-read-pa", rxBacking ? rxReadPA : 0);

    // 环与统计缓冲的地址**无条件登记**。它们是设备确定会访问的内存。
    if (fM22b2Dma.haveTxRing) {
        set.insert(fM22b2Dma.txRingBase, kTxDescBytes, amdobs::PURP_TX_RING,
                   amdobs::LIFE_INFLIGHT, txReadVerdict);
    }
    if (fM22b2Dma.haveRxRing) {
        set.insert(fM22b2Dma.rxRingBase, kRxDescBytes, amdobs::PURP_RX_RING,
                   amdobs::LIFE_INFLIGHT, rxReadVerdict);
    }
    if (fM22b2Dma.haveCounter && (fM22b2Dma.counterAddr & ~0xFFFULL) != 0) {
        fM22b2Dma.statBase = fM22b2Dma.counterAddr & ~0xFFFULL;
        fM22b2Dma.haveStat = true;
        set.insert(fM22b2Dma.statBase, kStatBytes, amdobs::PURP_COUNTER_DUMP,
                   amdobs::LIFE_INFLIGHT,
                   amdobs::readVerdictDeviceReported(fM22b2Dma.statBase, kStatBytes,
                                       fM22b2Policy));
        setHexProperty(this, "m2-b2-dma-stat-base", fM22b2Dma.statBase);
    }

    // 映射环内存的**独立**判据：这里才用 readVerdict，且只用于决定是否
    // 去读描述符。记录已经完成，读失败不影响归属集合。
    {
        const char *whyTx = nullptr;
        const bool txOk =
            fM22b2Dma.haveTxRing && txBacking &&
            amdobs::plausibleRingBase(txReadPA, kTxDescBytes,
                                      M2B2_IDENTITY_LIMIT, &whyTx) &&
            txReadVerdict == amdobs::RD_OK;
        const char *whyRx = nullptr;
        const bool rxOk =
            fM22b2Dma.haveRxRing && rxBacking &&
            amdobs::plausibleRingBase(rxReadPA, kRxDescBytes,
                                      M2B2_IDENTITY_LIMIT, &whyRx) &&
            rxReadVerdict == amdobs::RD_OK;
        setProperty("m2-b2-dma-tx-ring-trusted", txOk ? "yes" : "NO");
        setProperty("m2-b2-dma-rx-ring-trusted", rxOk ? "yes" : "NO");
        if (!txOk && fM22b2Dma.haveTxRing) {
            setProperty("m2-b2-dma-tx-ring-why",
                        whyTx ? whyTx : "not readable under current policy");
            // 环地址已记录，但内容读不到 -> 无法枚举描述符 -> 这些槽未扫描。
            fM22b2Dma.unscanned += 1024;
        }
        if (!rxOk && fM22b2Dma.haveRxRing) {
            setProperty("m2-b2-dma-rx-ring-why",
                        whyRx ? whyRx : "not readable under current policy");
            fM22b2Dma.unscanned += 1024;
        }
        setProperty("m2-b2-dma-trust",
                    (txOk && rxOk) ? "trusted"
                                   : "PARTIAL-ring-registers-not-readable");
        if (!txOk) fM22b2Dma.haveTxRing = false;
        if (!rxOk) fM22b2Dma.haveRxRing = false;
    }

    // ---- 5b. 读环内存的依据：指纹必须真的能失败 ----
    //
    // 【第八轮】第七轮的放行条件是"设备寄存器说它用这个地址"。那只能
    // 证明**设备被编程**使用它，不能证明：这块内存仍是驱动的环对象、
    // 仍存活、以及这个 PA 映射到它。读错 PA 会 panic，所以那个理由少
    // 了一步。
    //
    // 探针看不到驱动的 IOBufferMemoryDescriptor，所以"就是那个对象"在
    // 这里无法直接证明。能证明的是**内容与驱动构出来的环一致**：
    //   - RX 环的最后一个描述符带 RingEnd（驱动在 setup 时写死，
    //     之后从不清除），这是结构指纹；
    //   - TX 环的地址非零、长度字段在 16 位内或带 TSO 位。
    // 一页随机内存不会满足"RingEnd 恰好在最后一槽"。这是真能失败的检查。
    //
    // 指纹不通过时：**地址照旧保留**，只是不信任其内容并停止解引用。
    {
        fM22b2Dma.txRingBasis = amdobs::RB_NONE;
        fM22b2Dma.rxRingBasis = amdobs::RB_NONE;
        fM22b2Dma.txRingFpOk = false;
        fM22b2Dma.rxRingFpOk = false;
        fM22b2Dma.txRingDecoded = 0;
        fM22b2Dma.rxRingRingEndAtLast = 0;
        setProperty("m2-b2-dma-tx-ring-basis", "none");
        setProperty("m2-b2-dma-rx-ring-basis", "none");
    }

    // ---- 6. 读描述符环，按实际格式收集 (地址, 长度) ----
    //
    // 这一步是核心：描述符里的 addr 字段就是设备下一次 DMA 的目标，
    // 长度字段给出这段 DMA 的真实大小（不再一律按一页近似）。
    if (fM22b2Dma.haveTxRing) {
        IOMemoryDescriptor *ringMd =
            IOMemoryDescriptor::withPhysicalAddress(txReadPA,
                                                    kTxDescBytes,
                                                    kIODirectionIn);
        if (ringMd) {
            IOMemoryMap *rm = ringMd->map(kIOMapInhibitCache | kIOMapReadOnly);
            if (rm) {
                const UInt8 *rb =
                    (const UInt8 *)(uintptr_t)rm->getVirtualAddress();

                // 指纹：内容是否真的像驱动构出来的 TX 环。
                const amdobs::TxRingFingerprint fp =
                    amdobs::txRingFingerprint(rb, 1024);
                fM22b2Dma.txRingDecoded = fp.decoded;
                fM22b2Dma.txRingFpOk = fp.ok;
                fM22b2Dma.txRingBasis = fp.ok ? amdobs::RB_FINGERPRINT
                                              : amdobs::RB_REGISTER_AND_MAP;
                setProperty("m2-b2-dma-tx-ring-basis",
                            amdobs::ringBasisName(fM22b2Dma.txRingBasis));
                setHexProperty(this, "m2-b2-dma-tx-ring-decoded",
                               (UInt64)fp.decoded);
                setHexProperty(this, "m2-b2-dma-tx-ring-badlen",
                               (UInt64)fp.badLen);
                if (!fp.ok) {
                    // 指纹不通过：不把这块内存的内容当成环。
                    setProperty("m2-b2-dma-tx-ring-fp", "FAIL-content-mismatch");
                    fM22b2Dma.unscanned += 1024;
                    rm->release();
                    ringMd->release();
                    fM22b2Dma.haveTxRing = false;
                    goto afterTxRing;
                }
                setProperty("m2-b2-dma-tx-ring-fp", "ok");

                const amdobs::TxRingStats ts = amdobs::scanTxRing(rb, 1024);
                fM22b2Dma.txSlots = ts.slots;
                fM22b2Dma.txOwned = ts.owned;
                fM22b2Dma.txDone = ts.done;
                fM22b2Dma.txAddrZero = ts.addrZero;
                fM22b2Dma.txTsoSlots = ts.tsoSlots;
                fM22b2Dma.txFirstAddr = ts.firstAddr;
                fM22b2Dma.txDoneWithAddrBefore = ts.doneWithAddr;

                // 原始三字段导出：判断 stride / 环基址 / 长度字段是否对。
                for (UInt32 di = 0; di < 8; di++) {
                    const UInt8 *dd =
                        rb + (UInt64)di * amdobs::TX_DESC_STRIDE;
                    char k[56];
                    char v[128];
                    snprintf(k, sizeof(k), "m2-b2-dma-txdesc%u", di);
                    snprintf(v, sizeof(v),
                             "opts1=%08x opts2=%08x addr=%016llx len=0x%x",
                             amdobs::rd32(dd), amdobs::rd32(dd + 4),
                             (unsigned long long)amdobs::rd64(dd + 8),
                             amdobs::rd32(dd) & amdobs::TX_DESC_LENMASK);
                    setProperty(k, v);
                }

                m2b2CollectTxSegments(rb, 1024, fM22b2Dma.tailPtrBefore,
                                      fM22b2Dma.cloPtrBefore);
                rm->release();
            } else {
                setProperty("m2-b2-dma-tx-scan", "map-failed");
                fM22b2Dma.unscanned += 1024;
            }
            ringMd->release();
        } else {
            setProperty("m2-b2-dma-tx-scan", "md-failed");
            fM22b2Dma.unscanned += 1024;
        }
    }
afterTxRing:

    if (fM22b2Dma.haveRxRing) {
        IOMemoryDescriptor *ringMd =
            IOMemoryDescriptor::withPhysicalAddress(rxReadPA,
                                                    kRxDescBytes,
                                                    kIODirectionIn);
        if (ringMd) {
            IOMemoryMap *rm = ringMd->map(kIOMapInhibitCache | kIOMapReadOnly);
            if (rm) {
                const UInt8 *rb =
                    (const UInt8 *)(uintptr_t)rm->getVirtualAddress();

                // 指纹：驱动在 setup 时把 RingEnd 写进最后一个描述符，
                // 之后从不清除。它出现在那个位置，是"这块 PA 就是 RX 环"
                // 目前能取得的最强证据。
                const amdobs::RxRingFingerprint fp =
                    amdobs::rxRingFingerprint(rb, 1024);
                fM22b2Dma.rxRingRingEndAtLast = fp.ringEndAtLast;
                fM22b2Dma.rxRingFpOk = fp.ok;
                fM22b2Dma.rxRingBasis = fp.ok ? amdobs::RB_FINGERPRINT
                                              : amdobs::RB_REGISTER_AND_MAP;
                setProperty("m2-b2-dma-rx-ring-basis",
                            amdobs::ringBasisName(fM22b2Dma.rxRingBasis));
                setHexProperty(this, "m2-b2-dma-rx-ring-decoded",
                               (UInt64)fp.decoded);
                setHexProperty(this, "m2-b2-dma-rx-ring-ringend-at-last",
                               (UInt64)fp.ringEndAtLast);
                if (!fp.ok) {
                    setProperty("m2-b2-dma-rx-ring-fp", "FAIL-content-mismatch");
                    fM22b2Dma.unscanned += 1024;
                    rm->release();
                    ringMd->release();
                    fM22b2Dma.haveRxRing = false;
                    goto afterRxRing;
                }
                setProperty("m2-b2-dma-rx-ring-fp", "ok");

                const amdobs::RxRingStats rs = amdobs::scanRxRing(rb, 1024);
                fM22b2Dma.rxSlots = rs.slots;
                fM22b2Dma.rxOwned = rs.owned;
                fM22b2Dma.rxDone = rs.done;
                fM22b2Dma.rxAddrZero = rs.addrZero;
                fM22b2Dma.rxFirstAddr = rs.firstAddr;
                m2b2CollectRxSegments(rb, 1024);
                rm->release();
            } else {
                setProperty("m2-b2-dma-rx-scan", "map-failed");
                fM22b2Dma.unscanned += 1024;
            }
            ringMd->release();
        } else {
            setProperty("m2-b2-dma-rx-scan", "md-failed");
            fM22b2Dma.unscanned += 1024;
        }
    }
afterRxRing:

    fM22b2Dma.ranges = set.n;
    fM22b2Dma.dropped = set.droppedCount;
    fM22b2Dma.rawOffered = set.rawOffered;
    fM22b2Dma.mergedTotal = set.mergedTotal;
    fM22b2Dma.unscanned += set.unscanned;
    fM22b2Dma.envValid = set.envValid;
    fM22b2Dma.envLo = set.envLo;
    fM22b2Dma.envHi = set.envHi;

    // 读取许可统计：记录每条区间为什么可读 / 不可读。
    for (UInt32 i = 0; i < set.n; i++) {
        if (set.r[i].readable == amdobs::RD_OK) fM22b2Dma.readOkCount++;
        else if (set.r[i].readable == amdobs::RD_OUT_OF_MAP)
            fM22b2Dma.readOutOfMapCount++;
        else if (set.r[i].readable == amdobs::RD_NOT_RAM)
            fM22b2Dma.readNotRamCount++;
    }

    // 覆盖范围：一次快照。窗口覆盖要等窗口结束后由尾指针推进量判定。
    //
    // 【第八轮】逐路径初始化。此刻所有路径都只有快照；TX 缓冲路径的
    // 整窗覆盖要等窗口结束后的 m2b2ScanTxWindowAfter() 才能成立。
    // 环与统计缓冲**不会**获得整窗覆盖：我们没有对它们做窗口论证。
    fM22b2Dma.pathCov.clear();
    fM22b2Dma.pathCov.set(amdobs::PATH_TX_RING, amdobs::COV_SNAPSHOT);
    fM22b2Dma.pathCov.set(amdobs::PATH_RX_RING, amdobs::COV_SNAPSHOT);
    fM22b2Dma.pathCov.set(amdobs::PATH_TX_BUF, amdobs::COV_SNAPSHOT);
    fM22b2Dma.pathCov.set(amdobs::PATH_RX_BUF, amdobs::COV_SNAPSHOT);
    fM22b2Dma.pathCov.set(amdobs::PATH_STAT, amdobs::COV_SNAPSHOT);
    fM22b2Dma.coverage = amdobs::COV_SNAPSHOT;

    fM22b2Dma.tObsAfter = m2b2NowNS();

    // ---- 7. 发布结果 ----
    setHexProperty(this, "m2-b2-dma-tx-slots", fM22b2Dma.txSlots);
    setHexProperty(this, "m2-b2-dma-tx-owned", fM22b2Dma.txOwned);
    setHexProperty(this, "m2-b2-dma-tx-done", fM22b2Dma.txDone);
    setHexProperty(this, "m2-b2-dma-tx-done-with-addr",
                   fM22b2Dma.txDoneWithAddrBefore);
    setHexProperty(this, "m2-b2-dma-tx-zeroaddr", fM22b2Dma.txAddrZero);
    setHexProperty(this, "m2-b2-dma-tx-tso", fM22b2Dma.txTsoSlots);
    setHexProperty(this, "m2-b2-dma-tx-firstaddr", fM22b2Dma.txFirstAddr);
    setHexProperty(this, "m2-b2-dma-rx-slots", fM22b2Dma.rxSlots);
    setHexProperty(this, "m2-b2-dma-rx-owned", fM22b2Dma.rxOwned);
    setHexProperty(this, "m2-b2-dma-rx-done", fM22b2Dma.rxDone);
    setHexProperty(this, "m2-b2-dma-rx-zeroaddr", fM22b2Dma.rxAddrZero);
    setHexProperty(this, "m2-b2-dma-rx-firstaddr", fM22b2Dma.rxFirstAddr);

    // 五类计数分开发布，互不混用。
    setHexProperty(this, "m2-b2-dma-ranges", fM22b2Dma.ranges);
    setHexProperty(this, "m2-b2-dma-dropped", fM22b2Dma.dropped);
    setHexProperty(this, "m2-b2-dma-raw-offered", fM22b2Dma.rawOffered);
    setHexProperty(this, "m2-b2-dma-merged-total", fM22b2Dma.mergedTotal);
    setHexProperty(this, "m2-b2-dma-unscanned", fM22b2Dma.unscanned);
    setProperty("m2-b2-dma-envelope-valid",
                fM22b2Dma.envValid ? "yes" : "no");
    setHexProperty(this, "m2-b2-dma-envelope-lo", fM22b2Dma.envLo);
    setHexProperty(this, "m2-b2-dma-envelope-hi", fM22b2Dma.envHi);
    setProperty("m2-b2-dma-coverage",
                amdobs::coverageName(fM22b2Dma.coverage));

    setHexProperty(this, "m2-b2-dma-read-ok", fM22b2Dma.readOkCount);
    setHexProperty(this, "m2-b2-dma-read-outofmap",
                   fM22b2Dma.readOutOfMapCount);
    setHexProperty(this, "m2-b2-dma-read-notram", fM22b2Dma.readNotRamCount);

    setHexProperty(this, "m2-b2-dma-t-obs-before", fM22b2Dma.tObsBefore);
    setHexProperty(this, "m2-b2-dma-t-obs-after", fM22b2Dma.tObsAfter);
    setHexProperty(this, "m2-b2-dma-t-clo-before", fM22b2Dma.tCloBefore);

    // 【第八轮】逐路径覆盖状态单独发布。
    // 一个总的 coverage 值不足以表达"TX 完整、RX 只是快照"，
    // 而把后者当前者用，正是第七轮过度概括的位置。
    setProperty("m2-b2-dma-cov-txring",
                amdobs::coverageName(fM22b2Dma.pathCov.txRing));
    setProperty("m2-b2-dma-cov-rxring",
                amdobs::coverageName(fM22b2Dma.pathCov.rxRing));
    setProperty("m2-b2-dma-cov-txbuf",
                amdobs::coverageName(fM22b2Dma.pathCov.txBuf));
    setProperty("m2-b2-dma-cov-rxbuf",
                amdobs::coverageName(fM22b2Dma.pathCov.rxBuf));
    setProperty("m2-b2-dma-cov-stat",
                amdobs::coverageName(fM22b2Dma.pathCov.stat));
    setProperty("m2-b2-dma-cov-weakest",
                amdobs::coverageName(fM22b2Dma.pathCov.weakest()));
    setProperty("m2-b2-dma-cov-all-window",
                fM22b2Dma.pathCov.allWindow() ? "yes" : "no");

    // 【第八轮】读环内存的依据逐项发布。
    setProperty("m2-b2-dma-tx-ring-basis",
                amdobs::ringBasisName(fM22b2Dma.txRingBasis));
    setProperty("m2-b2-dma-rx-ring-basis",
                amdobs::ringBasisName(fM22b2Dma.rxRingBasis));
    setHexProperty(this, "m2-b2-dma-tx-ring-decoded",
                   (UInt64)fM22b2Dma.txRingDecoded);
    setHexProperty(this, "m2-b2-dma-rx-ring-ringend-at-last",
                   (UInt64)fM22b2Dma.rxRingRingEndAtLast);
    // 长度无法解码的区间数：非零时不得作精确覆盖的否定。
    setHexProperty(this, "m2-b2-dma-len-unknown",
                   (UInt64)set.savedLenUnknown);

    // 区间明细（有限条数，避免属性爆炸）
    for (UInt32 i = 0; i < set.n && i < 16; i++) {
        char k[56];
        snprintf(k, sizeof(k), "m2-b2-dma-range%u-base", i);
        setHexProperty(this, k, set.r[i].base);
        snprintf(k, sizeof(k), "m2-b2-dma-range%u-len", i);
        setHexProperty(this, k, set.r[i].len);
        snprintf(k, sizeof(k), "m2-b2-dma-range%u-purpose", i);
        setProperty(k, amdobs::purposeName(set.r[i].purpose));
        snprintf(k, sizeof(k), "m2-b2-dma-range%u-life", i);
        setProperty(k, amdobs::lifecycleName(set.r[i].lifecycle));
        snprintf(k, sizeof(k), "m2-b2-dma-range%u-read", i);
        setProperty(k, amdobs::readVerdictName(set.r[i].readable));
    }
    setHexProperty(this, "m2-b2-dma-range-listed",
                   (UInt64)((set.n < 16) ? set.n : 16));

    fM22b2Dma.ran = true;
    // "complete" means the observation ran. It does NOT mean the values are
    // usable; m2-b2-dma-trust carries that separate judgement.
    setProperty("m2-b2-dma-obs", "complete");

    barMap->release();
    nic->release();
}
