// AMDMapperProbeB1B2.cpp -- M1 mapper self-tests (B1, B2, B2a, B2b)
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

// ===== AMDMapperProbeB1B2.cpp (original lines 217..242) =====
// ------------------------------------------------------------------ B1 自测

void org_example_AMDMapperProbe::runB1SelfTest() {
    if (!fTarget) {
        setProperty("m1b-selftest", "SKIP-no-target");
        return;
    }

    IOMapper *before = probeRawMapper(fTarget);
    if (before) {
        setProperty("m1b-selftest", "ABORT-pre-existing-mapper");
        return;
    }
    setProperty("m1b-before", "NULL-as-expected");

    fTarget->setProperty("iommu-parent", this);

    IOMapper *after = probeRawMapper(fTarget);
    if (after == this) {
        setProperty("m1b-selftest", "PASS-real-device-found-our-mapper");
    } else if (after) {
        setProperty("m1b-selftest", "FAIL-wrong-mapper");
    } else {
        setProperty("m1b-selftest", "FAIL-still-NULL");
    }
}

// ===== AMDMapperProbeB1B2.cpp (original lines 308..392) =====
// ---------------------------------------------------------------- B2-0 自测

// 用我们自己的 buffer 与 mapper 构造一次真实的 IODMACommand 流程。
//
// 复现的正是 RTL812xLucy 对描述符环做的事：
//     IODMACommand::withSpecification(..., mapper, NULL)
//     setMemoryDescriptor(md)   ← 内部会调用我们的 iovmMapMemory
//
// 全程没有硬件参与：buffer 由我们分配，IOVA 不会被任何设备使用。
void org_example_AMDMapperProbe::runB2SelfTest() {
    const IOByteCount kBufSize = 16 * 4096;

    IOBufferMemoryDescriptor *bmd = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
        kernel_task,
        kIODirectionInOut | kIOMemoryPhysicallyContiguous,
        kBufSize,
        0xFFFFFFFFFFFFFF00ULL);
    if (!bmd) {
        setProperty("m1b2-alloc", "FAIL-buffer");
        return;
    }
    setProperty("m1b2-alloc", "OK");
    setHexProperty(this, "m1b2-bufsize", kBufSize);

    if (bmd->prepare() != kIOReturnSuccess) {
        setProperty("m1b2-prepare", "FAIL");
        bmd->release();
        return;
    }
    setProperty("m1b2-prepare", "OK");

    // 显式把我们的 mapper 传进去——与 Lucy 驱动的用法一致。
    IODMACommand *cmd = IODMACommand::withSpecification(
        kIODMACommandOutputHost64,
        64,             // numAddressBits
        0,              // maxSegmentSize
        IODMACommand::kMapped,
        0,              // maxTransferSize
        1,              // alignment
        this,           // mapper ← 关键：我们的 mapper
        NULL);
    if (!cmd) {
        setProperty("m1b2-cmd", "FAIL-withSpecification");
        bmd->complete();
        bmd->release();
        return;
    }
    setProperty("m1b2-cmd", "OK");

    // 这一行会触发 iovmMapMemory（经 prepare 内部的多段路径）。
    // 注意：B2-0 刻意保持窗口**关闭**，行为与 0.4.0 完全一致，
    // 这样两次部署的结果可以直接对比，不会因为实现变化而失去基线。
    // 成功路径由紧随其后的 B2-a 负责观察。
    // fProbeCallActive 让 iovmMapMemory 知道这是探针自己发起的，
    // 从而不会把这次（注定失败的）调用误算成真实设备调用。
    fProbeCallActive = true;
    IOReturn ret = cmd->setMemoryDescriptor(bmd);
    fProbeCallActive = false;

    setHexProperty(this, "m1b2-setmd-ret", (uint64_t)(uint32_t)ret);
    setProperty("m1b2-setmd",
        (ret == kIOReturnSuccess) ? "SUCCESS" : "FAILED-as-expected");
    setHexProperty(this, "m1b2-mapcalls", fMapCalls);

    if (ret == kIOReturnSuccess) {
        IODMACommand::Segment64 seg;
        UInt64 offset = 0;
        UInt32 numSegs = 1;

        if (cmd->gen64IOVMSegments(&offset, &seg, &numSegs) == kIOReturnSuccess) {
            setProperty("m1b2-gen64", "OK");
            setHexProperty(this, "m1b2-seg0-iova", seg.fIOVMAddr);
            setHexProperty(this, "m1b2-seg0-len", seg.fLength);
        } else {
            setProperty("m1b2-gen64", "FAILED");
        }
        cmd->clearMemoryDescriptor();
    }

    cmd->release();
    bmd->complete();
    bmd->release();

    setProperty("m1b2-done", "yes");
}

// ===== AMDMapperProbeB1B2.cpp (original lines 394..487) =====
// ---------------------------------------------------------------- B2-a 自测
//
// 两组对照：
//   ok   —— 物理连续的 64 KiB，期望 iovmMapMemory 返回成功 + 恒等映射
//   frag —— 碎片化的 8 MiB，期望返回 kIOReturnUnsupported 并被计数
//
// 成败判定不靠 IOLog（会滚出 msgbuf），全部落到 IORegistry 属性。

void org_example_AMDMapperProbe::runB2OneTest(
    const char *tag, bool wantContiguous, IOByteCount size) {

    IOOptionBits opts = kIODirectionInOut;
    if (wantContiguous) opts |= kIOMemoryPhysicallyContiguous;

    IOBufferMemoryDescriptor *bmd = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
        kernel_task, opts, size, 0xFFFFFFFFFFFFFF00ULL);
    if (!bmd) {
        setStrTagged(this, tag, "alloc", "FAIL");
        return;
    }
    setStrTagged(this, tag, "alloc", "OK");
    setHexTagged(this, tag, "size", size);

    if (bmd->prepare() != kIOReturnSuccess) {
        setStrTagged(this, tag, "prepare", "FAIL");
        bmd->release();
        return;
    }

    // 先独立探测这块 buffer 的实际物理布局，作为对照基准。
    ProbeRun run = probeSegmentRun(bmd, 0, size);
    setHexTagged(this, tag, "segs", run.segCount);
    setHexTagged(this, tag, "firstpa", run.firstPA);
    setStrTagged(this, tag, "contig",
        run.error ? "ERROR" : (run.contiguous ? "yes" : "no"));

    IODMACommand *cmd = IODMACommand::withSpecification(
        kIODMACommandOutputHost64, 64, 0, IODMACommand::kMapped,
        0, 1, this, NULL);
    if (!cmd) {
        setStrTagged(this, tag, "cmd", "FAIL");
        bmd->complete();
        bmd->release();
        return;
    }

    uint32_t beforeOk     = fMapOkCalls;
    uint32_t beforeFrag   = fMapRejectFragCalls;
    uint32_t beforeOther  = fMapRejectOtherCalls;

    // 打开窗口，并且只对这个 cmd 有效（双重闸门）。
    fExpectedCmd = cmd;
    fMapWindowOpen = true;
    fProbeCallActive = true;
    IOReturn ret = cmd->setMemoryDescriptor(bmd);
    fProbeCallActive = false;
    fMapWindowOpen = false;
    fExpectedCmd = nullptr;

    setHexTagged(this, tag, "ret", (uint64_t)(uint32_t)ret);
    setHexTagged(this, tag, "okdelta",     fMapOkCalls         - beforeOk);
    setHexTagged(this, tag, "fragdelta",   fMapRejectFragCalls - beforeFrag);
    setHexTagged(this, tag, "otherdelta",  fMapRejectOtherCalls - beforeOther);

    if (ret == kIOReturnSuccess) {
        setStrTagged(this, tag, "result", "MAPPED");

        IODMACommand::Segment64 seg;
        UInt64 offset = 0;
        UInt32 numSegs = 1;
        if (cmd->gen64IOVMSegments(&offset, &seg, &numSegs) == kIOReturnSuccess) {
            setHexTagged(this, tag, "iova", seg.fIOVMAddr);
            setHexTagged(this, tag, "seg0len", seg.fLength);
            setHexTagged(this, tag, "nsegs", numSegs);
            // 恒等映射的判定：IOVA 必须等于 buffer 的物理起点。
            setStrTagged(this, tag, "identity",
                (seg.fIOVMAddr == run.firstPA && seg.fLength == size)
                    ? "yes" : "NO");
        } else {
            setStrTagged(this, tag, "gen64", "FAILED");
        }

        cmd->clearMemoryDescriptor();   // → iovmUnmapMemory
        setHexTagged(this, tag, "unmapcalls", fUnmapCalls);
    } else if (ret == kIOReturnUnsupported) {
        setStrTagged(this, tag, "result", "REJECTED-unsupported");
    } else {
        setStrTagged(this, tag, "result", "FAILED-other");
    }

    cmd->release();
    bmd->complete();
    bmd->release();
}

// ===== AMDMapperProbeB1B2.cpp (original lines 489..521) =====
void org_example_AMDMapperProbe::runB2aSelfTest() {
    // B2-0 刚刚跑过一次（窗口关闭 → 计入 rejectOther）。先把 B2-a 自己的
    // 计数器归零，让下面报出来的数字只反映 B2-a 的两次对照，
    // 不与 B2-0 的观测调用混在一起。
    fMapOkCalls = fMapRejectFragCalls = fMapRejectOtherCalls = 0;
    fUnmapOkCalls = 0;

    // 对照 1：物理连续，期望成功。
    runB2OneTest("m1b2a-ok", true, 16 * 4096);

    // 对照 2：碎片化，期望被拒。8 MiB 普通 buffer 几乎不可能物理连续。
    runB2OneTest("m1b2a-frag", false, 8 * 1024 * 1024);

    setHexProperty(this, "m1b2a-okcalls", fMapOkCalls);
    setHexProperty(this, "m1b2a-fragcalls", fMapRejectFragCalls);
    setHexProperty(this, "m1b2a-othercalls", fMapRejectOtherCalls);
    setHexProperty(this, "m1b2a-unmapok", fUnmapOkCalls);

    // 最后一次成功映射的摘要（也让 fLast* 四个成员被真正读取）
    setHexProperty(this, "m1b2a-last-segs", fLastSegCount);
    setHexProperty(this, "m1b2a-last-pa", fLastFirstPA);
    setHexProperty(this, "m1b2a-last-len", fLastLength);
    setHexProperty(this, "m1b2a-last-off", fLastOffset);

    // 总判定：连续成功 + 碎片被拒，两者都成立才算 PASS。
    if (fMapOkCalls > 0 && fMapRejectFragCalls > 0) {
        setProperty("m1b2a-selftest", "PASS-contig-mapped-frag-rejected");
    } else if (fMapOkCalls > 0) {
        setProperty("m1b2a-selftest", "PARTIAL-contig-mapped-frag-untested");
    } else {
        setProperty("m1b2a-selftest", "FAIL-no-successful-map");
    }
}

// ===== AMDMapperProbeB1B2.cpp (original lines 523..540) =====
// ------------------------------------------------------ B2-b 映射表操作
//
// 恒等映射不需要页表，但必须**记住哪些区间被映射过**，
// 否则 mapToPhysicalAddress 无法区分「我映射的」与「别人问的」，
// unmap 也无法校验参数。

org_example_AMDMapperProbe::MapEntry *
org_example_AMDMapperProbe::allocMapEntry() {
    for (int i = 0; i < kMaxActiveMaps; i++) {
        if (!fMaps[i].used) {
            fMaps[i].used = true;
            uint32_t n = usedMapEntries();
            if (n > fTablePeak) fTablePeak = n;
            return &fMaps[i];
        }
    }
    return nullptr;     // 表满
}

// ===== AMDMapperProbeB1B2.cpp (original lines 542..554) =====
// 按 (pa,len) 精确匹配释放。恒等映射下 pa 就是 IOVA，unmap 时内核会把
// 我们当初返回的值原样传回来（IOMemoryDescriptor::dmaUnmap → iovmUnmapMemory）。
bool org_example_AMDMapperProbe::freeMapEntry(uint64_t pa, uint64_t len) {
    for (int i = 0; i < kMaxActiveMaps; i++) {
        if (fMaps[i].used && fMaps[i].pa == pa && fMaps[i].len == len) {
            fMaps[i].used = false;
            fMaps[i].pa = 0;
            fMaps[i].len = 0;
            return true;
        }
    }
    return false;
}

// ===== AMDMapperProbeB1B2.cpp (original lines 556..562) =====
uint32_t org_example_AMDMapperProbe::usedMapEntries() {
    uint32_t n = 0;
    for (int i = 0; i < kMaxActiveMaps; i++) {
        if (fMaps[i].used) n++;
    }
    return n;
}

// ===== AMDMapperProbeB1B2.cpp (original lines 564..573) =====
void org_example_AMDMapperProbe::publishB2bStats() {
    setHexProperty(this, "m1bb-realmapcalls", fRealMapCalls);
    setHexProperty(this, "m1bb-realmapok", fRealMapOk);
    setHexProperty(this, "m1bb-realfrag", fRealMapRejectFrag);
    setHexProperty(this, "m1bb-realnoslot", fRealMapRejectNoSlot);
    setHexProperty(this, "m1bb-realunmap", fRealUnmapCalls);
    setHexProperty(this, "m1bb-tablepeak", fTablePeak);
    setHexProperty(this, "m1bb-tableused", usedMapEntries());
    setHexProperty(this, "m1bb-publishhits", fPublishHits);
}

// ===== AMDMapperProbeB1B2.cpp (original lines 7407..7417) =====
// ------------------------------------------------------------- 统计属性刷新

// 只在调用次数变化时刷新，避免每次映射都 setProperty（持续分配内存）。
void org_example_AMDMapperProbe::publishMapStats(bool force) {
    if (!force && fMapCalls == fPublishedMapCalls) return;
    fPublishedMapCalls = fMapCalls;
    setHexProperty(this, "m1b2-mapcalls", fMapCalls);
    setHexProperty(this, "m1b2-unmapcalls", fUnmapCalls);
    setHexProperty(this, "m1b2-insertcalls", fInsertCalls);
    setHexProperty(this, "m1b2-physaddrcalls", fPhysAddrCalls);
}
