// AMDMapperProbePgt.cpp -- M2-2b-2 page-table experiment
//
// Part of the AMDMapperProbe kext. Split out of the original
// single-file AMDMapperProbe.cpp by tools/split-probe.py; the
// function bodies are unchanged and in their original order.

#include "AMDMapperProbe.hpp"
// Round22: the exit sample is taken at an explicitly named window step, so this
// file needs the same r20tx::kStage* values the driver uses. Including the
// header (rather than re-typing the number) is what keeps the two sides equal.
#include "../tools/lucy-obs/RTL812xTxMapStd.hpp"
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
// 【第十二轮】整段业务区间走表的核心。与 host 回归编译**同一份**文件，
// 所以"生产走表"与"测试走表"不是两份互相印证的实现。
#include "amd_iommu_bizwalk_core.hpp"

// OSPtr<T> 的定义取决于 IOKIT_ENABLE_SHARED_PTR（SDK libkern/c++/OSPtr.h）：
//   定义时 = OSSharedPtr<T>；未定义时 = T*。SDK 默认未定义。
#if defined(IOKIT_ENABLE_SHARED_PTR)
    #define M1A_HAS_SHARED_PTR 1
#else
    #define M1A_HAS_SHARED_PTR 0
#endif

#include "AMDMapperProbeInternal.hpp"

OSDefineMetaClassAndStructors(R27ProbeTimer, IOTimerEventSource);

R27ProbeTimer *R27ProbeTimer::create(OSObject *owner, Action action) {
    R27ProbeTimer *timer = new R27ProbeTimer;
    if (timer && !timer->init(owner, action)) {
        timer->release();
        timer = nullptr;
    }
    return timer;
}

// ===== AMDMapperProbePgt.cpp (original lines 5206..5278) =====
bool org_example_AMDMapperProbe::scheduleM22b2() {
    if (!parsePgtBootArg()) {
        setProperty("m2-b2-gate", "closed");
        setProperty("m2-b2-stage", "1-skipped-no-bootarg");
        return false;
    }
    setProperty("m2-b2-gate", "open");

    // 叶子页大小模式：amdiommu=pgt4k 选 4 KiB，amdiommu=pgt 选 2 MiB 大页。
    // 用同一个 boot-arg 的两个取值，避免依赖第二个参数
    // （实测 m2b2delay 那类附加参数没有被 PE_parse_boot_argn 取到）。
    fM22b2Use4K = parsePgt4kBootArg();
    // 【v0.20.0】pgthold / pgtsleep 已不再改变测量窗口长度。
    // 旧代码用它们把基线窗口从 2 秒拉到 20 秒，而对照仍固定 2 秒，
    // 造成 10 倍错配（见 m2b2MeasureEvents 注释）。现在窗口恒为
    // M2B2_MEAS_SECS，这两个模式只保留历史语义标记，不再影响计数。
    fM22b2Hold  = parsePgtHoldBootArg();
    fM22b2SleepOnly = parsePgtSleepBootArg();
    fM22b2Use3L = parsePgt3lBootArg();
    setProperty("m2-b2-leaf-mode-src",
        fM22b2Use4K ? "amdiommu=pgt4k" : "amdiommu=pgt");
    setProperty("m2-b2-hold-mode",
        fM22b2SleepOnly ? "sleep-only-marker"
                        : (fM22b2Hold ? "hold-marker" : "none"));
    setProperty("m2-b2-level-mode", fM22b2Use3L ? "3-level" : "4-level");
    setHexProperty(this, "m2-b2-meas-secs", M2B2_MEAS_SECS);

    // 延迟值：默认 20000 ms，可用 m2b2delay=<秒> 覆盖（上限 300 秒）
    uint32_t delayMS = 20000;
    uint32_t overrideMS = 0;
    if (parseM22b2Delay(&overrideMS)) {
        delayMS = overrideMS;
        setProperty("m2-b2-delay-source", "boot-arg");
    } else {
        setProperty("m2-b2-delay-source", "default");
    }
    fM22b2DelayMS = delayMS;
    setHexProperty(this, "m2-b2-delay-ms", (UInt64)delayMS);

    IOWorkLoop *wl = getWorkLoop();
    if (!wl) {
        setProperty("m2-b2-verdict", "FAIL-no-workloop");
        setProperty("m2-b2-stage", "1-FAIL-no-workloop");
        return false;
    }

    fM22b2Timer = R27ProbeTimer::create(
        this, &org_example_AMDMapperProbe::m22b2TimerFired);
    if (!fM22b2Timer) {
        setProperty("m2-b2-verdict", "FAIL-no-timer");
        setProperty("m2-b2-stage", "1-FAIL-no-timer");
        return false;
    }
    if (wl->addEventSource(fM22b2Timer) != kIOReturnSuccess) {
        setProperty("m2-b2-verdict", "FAIL-timer-add");
        setProperty("m2-b2-stage", "1-FAIL-timer-add");
        fM22b2Timer->release();
        fM22b2Timer = nullptr;
        return false;
    }
    if (fM22b2Timer->setTimeoutMS(delayMS) != kIOReturnSuccess) {
        setProperty("m2-b2-verdict", "FAIL-timer-arm");
        setProperty("m2-b2-stage", "1-FAIL-timer-arm");
        wl->removeEventSource(fM22b2Timer);
        fM22b2Timer->release();
        fM22b2Timer = nullptr;
        return false;
    }

    setProperty("m2-b2-stage", "2-scheduled");
    setProperty("m2-b2-schedule", "armed");
    return true;
}

// ===== AMDMapperProbePgt.cpp (original lines 5280..5293) =====
void org_example_AMDMapperProbe::m22b2TimerFired(
    OSObject *owner, IOTimerEventSource *sender) {
    (void)sender;
    org_example_AMDMapperProbe *self =
        OSDynamicCast(org_example_AMDMapperProbe, owner);
    if (!self) return;

    // 定时器是一次性的：触发后不再重排。
    self->setProperty("m2-b2-schedule", "fired");

    // 在 workloop 上下文里跑。这里可以 IOSleep（会短暂阻塞 workloop），
    // 但整个探测本来就有 2 秒观察窗口，且只跑一次，代价可接受。
    self->runM22b2PageTableProbe();
}

// ===== AMDMapperProbePgt.cpp (original lines 5310..7405) =====
void org_example_AMDMapperProbe::runM22b2PageTableProbe() {
    setProperty("m2-b2-stage", "0-start");
    fR15Service = nullptr;
    bzero(&fR15Request, sizeof(fR15Request));
    fR15MapTicks = 0;
    fR15InvTicks = 0;
    R15Scope r15Scope = {this};

    // 门控已在 scheduleM22b2() 里检查过（只有 amdiommu=pgt 才会走到这里）。
    // 这里不再重复 parsePgtBootArg()，避免两处逻辑漂移。

    // ---- 阶段状态（v0.20.0）----
    //
    // 【为什么必须在函数最开头就初始化】
    //   第四轮的两个窗口结构 winPre / winMain 是**未初始化的栈变量**，
    //   只有在对应阶段真的执行到 m2b2SampleEvents() 时才被写。
    //   而判定阶段无条件读 winMain.valid / winMain.entries。
    //   于是"采样前就失败"的路径会读到栈垃圾——恰好非 0 时，
    //   就会把一个根本没跑过的窗口当成"有效窗口且无事件"，
    //   进而给出 INDETERMINATE 这种看起来像"测过但没结论"的判定。
    //
    //   这里显式初始化，并额外用两个布尔量记录"这个阶段到底有没有执行"，
    //   让判定阶段能区分"执行了且无事件"与"根本没执行"。
    // 【v0.21.7】窗口结构改放成员，不再占栈。
    //
    // 每个 org_example_AMDMapperProbe::M22b2EventWindow 是 0x1A8 = 424 字节（含 16*4 个 UInt32 原始事件）。
    // 两个加起来 848 字节，正是把本函数帧从 4096 以下推过 __chkstk 阈值的
    // 最后一根稻草（实测 0x1040 = 4160）。第五轮把 org_example_AMDMapperProbe::kM22b2RawKeep 从 32
    // 降到 16 只是绕过症状；把结构移到成员才是消除弱引用的正解。
    org_example_AMDMapperProbe::M22b2EventWindow &winPre = fM22b2WinPre;
    org_example_AMDMapperProbe::M22b2EventWindow &winMain = fM22b2WinMain;
    for (UInt32 t = 0; t < 16; t++) {
        winPre.typeCount[t] = 0;
        winMain.typeCount[t] = 0;
    }
    winPre.valid = false;  winPre.invalidReason = "not-run";
    winMain.valid = false; winMain.invalidReason = "not-run";
    winPre.entries = 0;    winMain.entries = 0;
    winPre.rawCount = 0;   winMain.rawCount = 0;
    winPre.durMS = 0;      winMain.durMS = 0;
    winPre.devidMismatch = 0; winMain.devidMismatch = 0;

    // 记录"该阶段是否真的执行过"。0 = 没执行，1 = 执行了。
    bool preWindowRan = false;
    bool mainWindowRan = false;

    // 首个失败阶段。一旦置位就不再被后续的通用状态覆盖——
    // 这是任务要求的"保留首个失败阶段，避免后来的通用状态掩盖原因"。
    const char *firstFailStage = nullptr;
    const char *firstFailReason = nullptr;

    setProperty("m2-b2-pre-window-ran", "no");
    setProperty("m2-b2-main-window-ran", "no");

    // ---- 第 1 步：分配全部内存 ----
    //
    // 页表用一块连续内存装下所有页。
    // 为什么一块而不是每页单独分配：
    //   单独分配会得到不连续的物理页，需要用 getPhysicalSegment 逐个取，
    //   代码复杂且容易在某个下标上取错。一块连续内存里各页的物理地址
    //   就是 base + n*4096，不可能算错。
    //
    // 2 MiB 模式：1 根 + 1 L2 + 16 叶子 + 1 空根 = 19 页 = 76 KiB
    // 4 KiB 模式：1 根 + 1 L2 + 32 叶子 + 1 空根 = 35 页 = 140 KiB
    const UInt32 basePtPageCount =
        fM22b2Use4K ? M2B2_4K_TOTAL_PAGES
                    : (fM22b2Use3L ? M2B2_3L_TOTAL_PAGES : M2B2_TOTAL_PAGES);
    // Bounded extra arena for sparse 4KiB mappings of actual retained RX
    // allocations. This is table capacity, NOT an identity-mapped RAM limit.
    const UInt32 ptPageCount = basePtPageCount + 128u;
    const UInt64 ptBytes = (UInt64)ptPageCount * M2B2_PAGE_SIZE;

    IOBufferMemoryDescriptor *ptMem =
        IOBufferMemoryDescriptor::withCapacity(
            (vm_size_t)ptBytes, kIODirectionOut, true);
    IOBufferMemoryDescriptor *tbl =
        IOBufferMemoryDescriptor::withCapacity(
            (vm_size_t)M22B_TABLE_SIZE_FULL, kIODirectionOut, true);
    IOBufferMemoryDescriptor *cmdBufMd =
        IOBufferMemoryDescriptor::withCapacity(
            (vm_size_t)M23_CMD_BUF_SIZE, kIODirectionOut, true);
    IOBufferMemoryDescriptor *semMd =
        IOBufferMemoryDescriptor::withCapacity(
            (vm_size_t)M2B2_PAGE_SIZE, kIODirectionOut, true);
    IOBufferMemoryDescriptor *evtMd =
        IOBufferMemoryDescriptor::withCapacity(
            (vm_size_t)M2B2_EVT_BUFFER_SIZE, kIODirectionOut, true);

    if (!ptMem || !tbl || !cmdBufMd || !semMd || !evtMd) {
        setProperty("m2-b2-verdict", "FAIL-alloc");
        setProperty("m2-b2-stage", "2-FAIL-alloc");
        if (ptMem)    ptMem->release();
        if (tbl)      tbl->release();
        if (cmdBufMd) cmdBufMd->release();
        if (semMd)    semMd->release();
        if (evtMd)    evtMd->release();
        return;
    }

    IOByteCount sl = 0;
    addr64_t ptPA = ptMem->getPhysicalSegment(0, &sl, kIOMemoryMapperNone);
    bool memOk = ptPA && ((UInt64)sl >= ptBytes);

    addr64_t tblPA = 0, cmdPA = 0, semPA = 0, evtPA = 0;
    if (memOk) {
        tblPA = tbl->getPhysicalSegment(0, &sl, kIOMemoryMapperNone);
        memOk = tblPA && ((UInt64)sl >= M22B_TABLE_SIZE_FULL);
    }
    if (memOk) {
        cmdPA = cmdBufMd->getPhysicalSegment(0, &sl, kIOMemoryMapperNone);
        memOk = cmdPA && ((UInt64)sl >= M23_CMD_BUF_SIZE);
    }
    if (memOk) {
        semPA = semMd->getPhysicalSegment(0, &sl, kIOMemoryMapperNone);
        memOk = semPA && ((UInt64)sl >= M2B2_PAGE_SIZE);
    }
    if (memOk) {
        evtPA = evtMd->getPhysicalSegment(0, &sl, kIOMemoryMapperNone);
        memOk = evtPA && ((UInt64)sl >= M2B2_EVT_BUFFER_SIZE);
    }

    if (!memOk) {
        setProperty("m2-b2-verdict", "FAIL-memory");
        setProperty("m2-b2-stage", "3-FAIL-mem");
        ptMem->release(); tbl->release(); cmdBufMd->release();
        semMd->release(); evtMd->release();
        return;
    }

    // 全部必须 4 KiB 对齐（页表页本身要求；其余是寄存器写入要求）
    if ((ptPA & 0xFFF) || (tblPA & 0xFFF) || (cmdPA & 0xFFF) ||
        (semPA & 0xFFF) || (evtPA & 0xFFF)) {
        setProperty("m2-b2-verdict", "FAIL-not-aligned");
        setProperty("m2-b2-stage", "3-FAIL-align");
        ptMem->release(); tbl->release(); cmdBufMd->release();
        semMd->release(); evtMd->release();
        return;
    }

    setHexProperty(this, "m2-b2-pt-pa", (UInt64)ptPA);
    setHexProperty(this, "m2-b2-pt-bytes", ptBytes);
    setHexProperty(this, "m2-b2-pt-pages", ptPageCount);
    setHexProperty(this, "m2-b2-tbl-pa", (UInt64)tblPA);
    setHexProperty(this, "m2-b2-cmd-pa", (UInt64)cmdPA);
    setHexProperty(this, "m2-b2-sem-pa", (UInt64)semPA);
    setHexProperty(this, "m2-b2-evt-pa", (UInt64)evtPA);

    // ---- 第 2 步：建设备表（全直通）----
    volatile UInt64 *dte = (volatile UInt64 *)tbl->getBytesNoCopy();
    const UInt32 dteCount = (UInt32)(M22B_TABLE_SIZE_FULL / M22B_DTE_SIZE);
    const UInt64 pt0 = DTE_V | DTE_TV | DTE_IR | DTE_IW;
    for (UInt32 i = 0; i < dteCount; i++) {
        dte[i * 4 + 0] = pt0;
        dte[i * 4 + 1] = 0;
        dte[i * 4 + 2] = 0;
        dte[i * 4 + 3] = 0;
    }
    setProperty("m2-b2-dt", "built-passthrough");

    // ---- 第 3 步：建 4 级恒等页表 ----
    //
    // 页表页在 ptMem 里的布局（页号从 0 开始）：
    //   page 0            : 根表（level 3）
    //   page 1 .. 16      : L2 表（level 2），每个覆盖 1 GiB
    //   page 17 .. 8208   : 叶子表（level 1），每个覆盖 1 GiB 里的 512 个 2 MiB
    volatile UInt64 *pt = (volatile UInt64 *)ptMem->getBytesNoCopy();

    // 先整体清零：未使用的项必须是 0（PR=0 表示不存在），
    // 否则硬件会去解引用垃圾地址。
    const UInt64 ptQwords = ptBytes / 8;
    for (UInt64 i = 0; i < ptQwords; i++) pt[i] = 0;

    const UInt64 rootPageIdx  = 0;
    const UInt64 l2PageBase   = rootPageIdx + M2B2_ROOT_PAGES;    // 1
    const UInt64 leafPageBase = l2PageBase + M2B2_L2_PAGES;       // 2

    // 物理地址换算：页号 → 物理地址
    // ptPA 是这块连续内存的物理基址，第 n 页的物理地址 = ptPA + n*4096
    const UInt64 rootPA = (UInt64)ptPA + rootPageIdx * M2B2_PAGE_SIZE;
    const UInt64 l2PA   = (UInt64)ptPA + l2PageBase  * M2B2_PAGE_SIZE;

    volatile UInt64 *root = pt + rootPageIdx * M2B2_PTE_COUNT;
    volatile UInt64 *l2   = pt + l2PageBase  * M2B2_PTE_COUNT;

    // 根表项：指向唯一的 L2 表。
    // 2 MiB 模式：16 GiB 全部落在 IOVA 0..0x3FFFFFFFF，即 idx3 = 0。
    // 4 KiB 模式：只映射 64 MiB，同样 idx3 = 0。
    // 【3 级模式】根表本身就是"第 2 级"，**没有 L2 这一层**：
    //   根表项直接指向叶子表，所以这里不能写 root[0] = TablePte(3,...)。
    if (!fM22b2Use3L) {
        root[0] = m2b2TablePte(3, l2PA);
    }

    if (fM22b2Use3L) {
        // ---- 3 级 + 2 MiB 大页：root(2) → 叶子(1)，覆盖 16 GiB ----
        //
        // PAGE_MODE_3_LEVEL = 3 → 根表是第 2 级，每项覆盖 1 GiB。
        // 16 GiB 用根表的 16 项（root[0..15]），每项直接指向一张叶子表。
        // 叶子表每项 2 MiB，512 项覆盖 1 GiB。
        //
        // 注意叶子表从 l2PageBase 开始放（这一页原本给 L2 用，3 级模式下没有 L2）。
        for (UInt32 gb = 0; gb < M2B2_3L_LEAF_PAGES; gb++) {
            const UInt64 leafPageIdx = leafPageBase + gb;
            const UInt64 leafPA = (UInt64)ptPA + leafPageIdx * M2B2_PAGE_SIZE;

            // 根表项（第 2 级）直接指向叶子表（第 1 级）
            root[gb] = m2b2TablePte(2, leafPA);

            volatile UInt64 *leaf = pt + leafPageIdx * M2B2_PTE_COUNT;
            const UInt64 base1G = (UInt64)gb << 30;
            for (UInt32 i = 0; i < M2B2_PTE_COUNT; i++) {
                const UInt64 pa = base1G + ((UInt64)i << 21);
                leaf[i] = m2b2LargeLeaf(pa);
            }
        }
    } else if (!fM22b2Use4K) {
        // ---- 2 MiB 大页：16 张叶子表，每张覆盖 1 GiB ----
        for (UInt32 gb = 0; gb < M2B2_LEAF_PAGES; gb++) {
            const UInt64 leafPageIdx = leafPageBase + gb;
            const UInt64 leafPA = (UInt64)ptPA + leafPageIdx * M2B2_PAGE_SIZE;

            // idx2 = (addr >> 30) & 0x1ff，1 GiB 步长下就是 gb
            l2[gb] = m2b2TablePte(2, leafPA);

            // 叶子表：512 个 2 MiB 项，覆盖 [gb*1GiB, (gb+1)*1GiB)
            volatile UInt64 *leaf = pt + leafPageIdx * M2B2_PTE_COUNT;
            const UInt64 base1G = (UInt64)gb << 30;
            for (UInt32 i = 0; i < M2B2_PTE_COUNT; i++) {
                const UInt64 pa = base1G + ((UInt64)i << 21);
                leaf[i] = m2b2LargeLeaf(pa);
            }
        }
    } else {
        // ---- 4 KiB 小页：root(3) → L2(2) → L1(1) → 叶子(0)，覆盖 16 GiB ----
        //
        // 层级覆盖范围：
        //   L2 的一项覆盖 1 GiB；16 GiB 需要 16 项 → l2[0..15] 各指向一个 L1 表
        //   L1 的一项覆盖 2 MiB；一个 L1 表 512 项 = 1 GiB
        //   叶子的每一项覆盖 4 KiB；一张叶子表 512 项 = 2 MiB
        //
        // 所以：16 个 L1 表 × 512 项 = 8192 张叶子表，正好覆盖 16 GiB。
        const UInt64 l1PageBase = leafPageBase;                 // 紧跟 L2
        const UInt64 leaf0PageBase = l1PageBase + M2B2_4K_L1_PAGES;

        for (UInt32 gb = 0; gb < M2B2_4K_L1_PAGES; gb++) {
            const UInt64 l1PageIdx = l1PageBase + gb;
            const UInt64 l1PA = (UInt64)ptPA + l1PageIdx * M2B2_PAGE_SIZE;
            volatile UInt64 *l1 = pt + l1PageIdx * M2B2_PTE_COUNT;

            // L2[gb] 指向第 gb 个 L1 表（level 2 项指向第 1 级表）
            l2[gb] = m2b2TablePte(2, l1PA);

            // 这个 L1 表覆盖 [gb*1GiB, (gb+1)*1GiB)，共 512 张叶子表
            for (UInt32 li = 0; li < M2B2_PTE_COUNT; li++) {
                const UInt64 leafGlobal = (UInt64)gb * M2B2_PTE_COUNT + li;
                const UInt64 leafPageIdx = leaf0PageBase + leafGlobal;
                const UInt64 leafPA =
                    (UInt64)ptPA + leafPageIdx * M2B2_PAGE_SIZE;

                // L1 的第 li 项指向一张叶子表（level 1 项指向第 0 级表）
                l1[li] = m2b2TablePte(1, leafPA);

                volatile UInt64 *leaf = pt + leafPageIdx * M2B2_PTE_COUNT;
                const UInt64 base2M = ((UInt64)gb << 30) + ((UInt64)li << 21);
                for (UInt32 i = 0; i < M2B2_PTE_COUNT; i++) {
                    const UInt64 pa = base2M + ((UInt64)i << 12);
                    leaf[i] = m2b2SmallLeaf(pa);
                }
            }
        }
    }

    // Establish the driver's complete finite allocation domain BEFORE the
    // DTE can switch. The driver becomes copy-only until explicitly authorized;
    // all ordinary replacement allocations are excluded for this transaction.
    if (!fM22b2SleepOnly &&
        (!m2b2R15PrepareMap(pt, (UInt64)ptPA, ptPageCount - 4, basePtPageCount) ||
         !r17Prepare(pt, (UInt64)ptPA, ptPageCount))) {
        setProperty("m2-b2-verdict", "FAIL-r15-owned-pre-map");
        setProperty("m2-b2-stage", "3b-abort-owned-map");
        ptMem->release(); tbl->release(); cmdBufMd->release();
        semMd->release(); evtMd->release();
        return;
    }
    setProperty("m2-b2-pt", "built-4level-identity");
    setProperty("m2-b2-leaf-mode", fM22b2Use4K ? "4KiB" : "2MiB");
    setHexProperty(this, "m2-b2-map-limit",
                   fM22b2Use4K ? M2B2_4K_MAP_LIMIT : M2B2_IDENTITY_LIMIT);
    setHexProperty(this, "m2-b2-pt-root-pa", rootPA);
    setHexProperty(this, "m2-b2-pt-l2-pa", l2PA);
    setHexProperty(this, "m2-b2-leaf-pages",
                   fM22b2Use4K ? M2B2_4K_LEAF_PAGES : M2B2_LEAF_PAGES);
    setHexProperty(this, "m2-b2-leaf-ptes",
                   fM22b2Use4K ? M2B2_4K_LEAF_PTES : M2B2_LEAF_PTE_COUNT);
    setHexProperty(this, "m2-b2-l2-pages", M2B2_L2_PAGES);
    setHexProperty(this, "m2-b2-l1-pages",
                   fM22b2Use4K ? M2B2_4K_L1_PAGES : 0);

    // ---- 第 4 步：页表自检（软件走表，不碰硬件）----
    //
    // 在把这张表交给硬件之前，先用**与解码器同一份实现**走一遍。
    //
    // 【第五轮重写】第四轮这段是手写的逐级 if/else，它对叶子的判据是
    //     lvl == M2B2_LEVEL_7 && m2b2PtePageSize(pte1) == 2MiB
    // 也就是"叶子必须 NextLevel=7"。这与构表函数用了同一个错误假设，
    // 所以**自检通过只能证明两者一致，不能证明编码正确**。
    //
    // 现在改成调用 amdpte::walkPageTable()，它要求逐级携带表级，
    // 并把"扩展页大小必须严格大于本级默认值"这条规范规则编进解码器。
    // 于是"构表错 + 自检错"这种共同错误会在自检阶段就被抓住。
    {
        bool walkOk = true;
        UInt32 walkBad = 0;
        UInt64 walkFirstBad = 0;
        UInt32 walkChecked = 0;
        const char *walkFirstReason = nullptr;

        // 抽样覆盖：页内偏移、页边界、2 MiB 边界、1/4/8/15/16 GiB 边界。
        const UInt64 samples[] = {
            0x0ULL, 0x1ULL, 0xFFFULL, 0x1000ULL,
            0x1FFFFFULL, 0x200000ULL, 0x3FFFFFULL,
            0x40000000ULL,                  // 1 GiB 边界
            0x100000000ULL,                 // 4 GiB 边界
            0x200000000ULL,                 // 8 GiB 边界
            0x3C0000000ULL,                 // 15 GiB
            0x3FFE00000ULL,                 // 16 GiB - 2 MiB
            0x3FFFFFFF0ULL,                 // 16 GiB - 16
        };
        const UInt32 nSamples = (UInt32)(sizeof(samples) / sizeof(samples[0]));

        const UInt64 mapLimit = fM22b2Use4K ? M2B2_4K_MAP_LIMIT
                                            : M2B2_IDENTITY_LIMIT;

        // 走表读取器：把 PTE 的物理地址换算成 pt 里的偏移。
        // 越界读返回 0（PR=0 → 解码为 absent），绝不越界访问。
        volatile UInt64 *ptv = pt;
        const UInt64 ptBase = (UInt64)ptPA;
        const UInt64 ptEnd  = ptBase + ptBytes;
        auto readPte = [ptv, ptBase, ptEnd](UInt64 tablePA, unsigned idx)
                           -> amdpte::u64 {
            if (tablePA < ptBase || tablePA >= ptEnd) return 0;
            const UInt64 byteOff = tablePA - ptBase;
            if (byteOff + 8ULL * idx + 8ULL > ptEnd - ptBase) return 0;
            return (amdpte::u64)ptv[byteOff / 8 + idx];
        };

        // 根表级：4 级模式 = 4，3 级模式 = 3（规范 1-based 编号）
        const unsigned rootLevel =
            fM22b2Use3L ? amdpte::LEVEL_1G : amdpte::LEVEL_512G;

        for (UInt32 s = 0; s < nSamples; s++) {
            const UInt64 iova = samples[s];
            if (iova >= mapLimit) continue;
            walkChecked++;

            const amdpte::WalkResult r =
                amdpte::walkPageTable(readPte, rootLevel, rootPA, iova);
            if (!r.ok || r.outPA != iova) {
                walkOk = false;
                if (walkBad == 0) {
                    walkFirstBad = iova;
                    walkFirstReason = r.reason;
                }
                walkBad++;
            }
        }
        (void)walkFirstReason;

        setHexProperty(this, "m2-b2-walk-samples", nSamples);
        setHexProperty(this, "m2-b2-walk-checked", walkChecked);
        setHexProperty(this, "m2-b2-walk-bad", walkBad);
        if (!walkOk) setHexProperty(this, "m2-b2-walk-firstbad", walkFirstBad);
        setProperty("m2-b2-walk", walkOk ? "ok" : "FAIL");

        if (!walkOk) {
            setProperty("m2-b2-verdict", "FAIL-software-walk");
            setProperty("m2-b2-stage", "5-FAIL-walk");
            ptMem->release(); tbl->release(); cmdBufMd->release();
            semMd->release(); evtMd->release();
            return;
        }
    }

    // ---- 第 4b 步：验证页表物理地址与虚拟地址确实指向同一块内存 ----
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


    volatile UInt32 *cmdBuf = (volatile UInt32 *)cmdBufMd->getBytesNoCopy();
    for (UInt32 i = 0; i < (M23_CMD_BUF_SIZE / 4); i++) cmdBuf[i] = 0;

    volatile UInt64 *sem = (volatile UInt64 *)semMd->getBytesNoCopy();
    *sem = 0;

    volatile UInt32 *evtBuf = (volatile UInt32 *)evtMd->getBytesNoCopy();
    for (UInt32 i = 0; i < (M2B2_EVT_BUFFER_SIZE / 4); i++) evtBuf[i] = 0;

    // ---- 第 6 步：映射 MMIO，验证身份 ----
    //
    // MMIO 窗口既读又写，方向保持 kIODirectionNone（与 M2-1/M2-2b-1 一致）。
    // 上面把 buffer 改成 kIODirectionOut 是针对**页表/设备表/命令缓冲**
    // 那些"由 CPU 写、由设备读"的内存，不适用于 MMIO 映射。
    IOMemoryDescriptor *md =
        IOMemoryDescriptor::withPhysicalAddress(
            (IOPhysicalAddress)M21_MMIO_BASE,
            (IOByteCount)M21_MMIO_LEN, kIODirectionNone);
    if (!md) {
        setProperty("m2-b2-verdict", "FAIL-mmio-md");
        setProperty("m2-b2-stage", "6-FAIL-md");
        ptMem->release(); tbl->release(); cmdBufMd->release();
        semMd->release(); evtMd->release();
        return;
    }
    IOMemoryMap *map = md->map(kIOMapInhibitCache | kIOMapAnywhere);
    if (!map) {
        setProperty("m2-b2-verdict", "FAIL-mmio-map");
        setProperty("m2-b2-stage", "6-FAIL-map");
        md->release();
        ptMem->release(); tbl->release(); cmdBufMd->release();
        semMd->release(); evtMd->release();
        return;
    }
    volatile UInt8 *base = (volatile UInt8 *)map->getVirtualAddress();

    if (mmioRead64(base, M21_OFF_EXT_FEAT) != M21_EFR_EXPECTED) {
        setProperty("m2-b2-verdict", "FAIL-efr-mismatch");
        setProperty("m2-b2-stage", "7-aborted-identity");
        map->release(); md->release();
        ptMem->release(); tbl->release(); cmdBufMd->release();
        semMd->release(); evtMd->release();
        return;
    }
    setProperty("m2-b2-identity", "confirmed");

    // ---- 第 7 步：记录原状态 ----
    const UInt64 origDT   = mmioRead64(base, M2B2_OFF_DEV_TABLE);
    const UInt64 origCmd  = mmioRead64(base, M2B2_OFF_CMD_BUF);
    const UInt64 origEvt  = mmioRead64(base, M2B2_OFF_EVT_BUF);
    const UInt64 origCtrl = mmioRead64(base, M2B2_OFF_CONTROL);
    setHexProperty(this, "m2-b2-orig-control", origCtrl);

    if (origCtrl & M2B2_CTRL_IOMMU_EN) {
        setProperty("m2-b2-verdict", "ABORT-already-enabled");
        setProperty("m2-b2-stage", "8-aborted");
        map->release(); md->release();
        ptMem->release(); tbl->release(); cmdBufMd->release();
        semMd->release(); evtMd->release();
        return;
    }

    // ---- 第 8 步：确定目标设备的 devid（必须在使能之前！）----
    //
    // 【2026-10-30 严重事故】这一步原先放在使能之后，且从 fNicDevice 取设备。
    // 但 fNicDevice 只在 amdiommu=arm 时才被设置；本轮用的是 amdiommu=pgt，
    // 所以 fNicDevice 为 NULL → tgtOk=false → 函数在**IOMMU 已使能**的状态下
    // 直接 return，并 release 了设备表内存。
    //
    // 后果：IOMMU 仍在运行，DEV_TABLE 指向已被释放的 2 MiB 内存，
    // 命令缓冲也已被释放。硬件继续按那张"野指针表"翻译全系统 DMA，
    // 启动在 0.42 秒处死锁，连续两次复现。
    //
    // 两条教训：
    //   1. 所有"可能失败"的前置条件都必须在**碰硬件之前**检查完。
    //      一旦使能了 IOMMU，后面不允许有任何裸 return。
    //   2. 不要复用带副作用的成员变量（fNicDevice 受 fArmed 控制），
    //      这里需要的是一个**只读查找**，与是否放行无关。
    UInt32 tgt = 0;
    bool tgtOk = false;
    {
        IOService *nicSvc = findNicServiceOnly();
        if (nicSvc) {
            // IOPCIDevice 被标 deprecated，但本 kext 必须是内核内 IOMapper 子类，
            // PCIDriverKit（用户态）无法替代。与 runM20ConfigProbe 同样处理：
            // 只在这个小范围内抑制，不做全局抑制。
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            IOPCIDevice *nicPci = OSDynamicCast(IOPCIDevice, nicSvc);
            if (nicPci) {
                const UInt8 b = nicPci->getBusNumber();
                const UInt8 d = nicPci->getDeviceNumber();
                const UInt8 f = nicPci->getFunctionNumber();
                tgt = ((UInt32)b << 8) | ((UInt32)d << 3) | (UInt32)f;
                tgtOk = true;
                setHexProperty(this, "m2-b2-tgt-bus", b);
                setHexProperty(this, "m2-b2-tgt-dev", d);
                setHexProperty(this, "m2-b2-tgt-fn", f);
            }
#pragma clang diagnostic pop
            nicSvc->release();
        }
    }
    setHexProperty(this, "m2-b2-tgt-hint", M2B2_TARGET_DEVID_HINT);
    setHexProperty(this, "m2-b2-target-devid", tgt);
    setProperty("m2-b2-tgt-source",
        tgtOk ? "IOPCIDevice-accessors" : "FAIL-no-nic-device");

    if (!tgtOk) {
        // 此时**还没碰过任何硬件寄存器**，可以安全返回。
        setProperty("m2-b2-verdict", "FAIL-no-target-devid");
        setProperty("m2-b2-stage", "8-FAIL-no-devid");
        map->release(); md->release();
        ptMem->release(); tbl->release(); cmdBufMd->release();
        semMd->release(); evtMd->release();
        return;
    }
    if (tgt != M2B2_TARGET_DEVID_HINT) {
        setProperty("m2-b2-tgt-mismatch",
            "runtime-devid-differs-from-0x3700");
    } else {
        setProperty("m2-b2-tgt-mismatch", "none");
    }

    // ---- 第 9 步：配置并使能（含事件日志）----
    //
    // 顺序严格照抄 early_enable_iommu()（init.c:2798-2811）：
    //   设备表 → 命令缓冲 → 事件缓冲 → 使能
    const UInt64 dtEntry = ((UInt64)tblPA & ~0xFFFULL) |
                           ((M22B_TABLE_SIZE_FULL >> 12) - 1);
    const UInt64 cmdEntry = ((UInt64)cmdPA & ~0xFFFULL) | M23_CMD_SIZE_CODE;
    const UInt64 evtEntry = ((UInt64)evtPA & ~0xFFFULL) | M2B2_EVT_LEN_MASK;

    // ---- 确保页表与设备表对设备可见 ----
    //
    // 【2026-10-31 修正】这里原先调用了 flush_dcache64((addr64_t)ptPA, ...)，
    // 把**物理地址**当成**虚拟地址**传给了内核 API。
    // 即使该 API 在 x86 上是空实现，传错地址族也是明确的错误，
    // 而且实测随后出现了启动异常。已改为安全做法：
    //
    //   1. IOBufferMemoryDescriptor 已用 kIODirectionOut 分配
    //      （见上面第 1 步），IOKit 会保证这块内存对设备可见；
    //   2. 再加 OSSynchronizeIO() 强制写顺序，防止编译器/CPU 重排
    //      导致 MMIO 寄存器先于内存写入生效。
    //
    // 为什么不需要显式 flush：
    //   x86 的缓存是**硬件一致**的（IOMMU 走表时会 snoop CPU 缓存），
    //   且 AMD-Vi 的 CONTROL_COHERENT_EN 已置位（实测 control-on
    //   含 bit10）。Linux 在 x86 上也不对页表做 dcache flush，
    //   它依赖的正是同一套硬件一致性。
    OSSynchronizeIO();
    setProperty("m2-b2-cache-flush", "io-sync-only");

    mmioWrite64(base, M2B2_OFF_DEV_TABLE, dtEntry);
    mmioWrite64(base, M2B2_OFF_CMD_BUF, cmdEntry);
    mmioWrite64(base, M2B2_OFF_EVT_BUF, evtEntry);
    mmioWrite64(base, M2B2_OFF_CMD_HEAD, 0);
    mmioWrite64(base, M2B2_OFF_CMD_TAIL, 0);
    mmioWrite64(base, M2B2_OFF_EVT_HEAD, 0);
    mmioWrite64(base, M2B2_OFF_EVT_TAIL, 0);

    UInt64 ctrl = mmioRead64(base, M2B2_OFF_CONTROL);
    ctrl |= M2B2_CTRL_CMDBUF_EN;
    mmioWrite64(base, M2B2_OFF_CONTROL, ctrl);

    ctrl = mmioRead64(base, M2B2_OFF_CONTROL);
    ctrl |= M2B2_CTRL_EVT_LOG_EN;
    mmioWrite64(base, M2B2_OFF_CONTROL, ctrl);

    ctrl = mmioRead64(base, M2B2_OFF_CONTROL);
    ctrl |= M2B2_CTRL_IOMMU_EN;
    mmioWrite64(base, M2B2_OFF_CONTROL, ctrl);

    const UInt64 ctrlOn = mmioRead64(base, M2B2_OFF_CONTROL);
    setProperty("m2-b2-enabled",
        (ctrlOn & M2B2_CTRL_IOMMU_EN) ? "yes" : "no");
    setProperty("m2-b2-evt-log",
        (ctrlOn & M2B2_CTRL_EVT_LOG_EN) ? "enabled" : "no");
    setHexProperty(this, "m2-b2-control-on", ctrlOn);

    // ---- 第 10 步：命令上下文 ----
    //
    // 所有 devid / domid / page-mode / 根表地址 / 完成信号地址都由 ctx
    // 持有，失效命令一律从它取值。旧代码在 DOMID 分支里改了 DTE 的
    // domain 却仍用 domain 0 发 INV_IOMMU_PAGES，那等于刷了一个不存在的
    // 域；现在这种不一致在结构上不可能发生。
    M2B2CmdCtx ctx;
    ctx.buf = cmdBuf;
    ctx.sem = sem;
    ctx.semPA = (UInt64)semPA;
    ctx.idx = 0;
    ctx.tail = 0;
    ctx.domid = 0;
    ctx.devid = tgt;
    ctx.pageMode = 0;
    ctx.rootPA = 0;
    ctx.failed = false;
    ctx.failReason = nullptr;
    ctx.submits = 0;
    ctx.completed = 0;
    ctx.lastSem = 0;
    ctx.lastLoops = 0;
    ctx.recordCount = 0;

    // 恢复状态：只有这里全部为 true 才允许释放内存
    bool hwStopped      = false;
    bool cmdBufStopped  = false;
    bool evtLogStopped  = false;
    bool regsRestored   = false;
    bool safeToFree     = false;

    // ---- 第七轮：阶段完成状态 ----
    //
    // 判定必须能区分"某阶段执行了并成功"与"某阶段根本没走到"。
    // 第六轮的 CONTROL 分支只看 fM22b2SleepOnly 这个**选择**，不看
    // 控制阶段是否真的跑完：前置的事件日志重置失败、命令失败、恢复失败
    // 都会被 CONTROL 覆盖掉，于是"我选了控制模式"变成了万能结论。
    //
    // 现在每一道前置门都有自己的布尔量，CONTROL 只有在它们全部成立、
    // 且控制阶段本身确实完成时才允许输出。
    bool evtResetOk     = false;   // 第 11 步：事件日志重置成功
    bool invAllOk       = false;   // 第 12 步：CMD_INV_ALL 完成
    bool invDevOk       = false;   // 第 15 步(a)：INV_DEV_ENTRY 完成
    bool invPagesOk     = false;   // 第 15 步(b)：INV_IOMMU_PAGES 完成
    bool controlDone    = false;   // 控制阶段（pgtsleep）确实跑完

    // 【第八轮】窗口结束时的边界采样结果。
    //
    // 必须声明在这里而不是第 16b 步里：本函数有多处 `goto recover`
    // 从第 11~15 步跳过来，C++ 不允许跳过带初始化的声明。把它们放在
    // 所有 goto 之前，既满足语言规则，也让"恢复路径也能看到这些值"
    // 成为结构上的事实而不是约定。
    UInt32 tailAfterRaw = 0;
    bool   tailAfterOk  = false;
    UInt32 cloAfterRaw  = 0;
    bool   cloAfterOk   = false;

    // 【第九轮】窗口内后置采样。
    //
    // 采样状态与映射都必须在所有 goto 之前声明（同上：C++ 不允许 goto
    // 跳过带初始化的声明）。postMap 由第 16 步创建、窗口一关闭就释放，
    // 所以"窗口内读过寄存器"只发生在窗口内部。
    M2b2PostSample postSample;
    postSample.bar = nullptr;
    postSample.reg = 0;
    postSample.width = 0;
    postSample.mask = 0;
    postSample.tailReg = 0;
    postSample.haveBar = false;
    postSample.cloRaw = 0;
    postSample.cloOk = false;
    postSample.tailRaw = 0;
    postSample.tailOk = false;
    postSample.tClo = 0;
    postSample.tTail = 0;
    bool postSampleDone = false;
    IOMemoryMap *postMap = nullptr;

    // 窗口记录（winPre / winMain）已在函数开头初始化，见那里的说明。

    // ---- 第 11 步：按规范重置事件日志 ----
    //
    // 这是唯一允许写 HEAD/TAIL 的入口：先停 EVT_LOG_EN、等 EVT_RUN=0，
    // 再归零、清 overflow 位、重新使能。日志运行期间绝不触碰 TAIL。
    {
        const bool ok = m2b2ResetEventLog(base);
        setProperty("m2-b2-evt-reset", ok ? "done" : "FAIL-cannot-stop-log");
        if (!ok) {
            // 无法确认日志已停 → 不碰缓冲、不做实验，直接进入恢复
            setProperty("m2-b2-verdict", "INVALID-evt-log-will-not-stop");
            setProperty("m2-b2-stage", "11-abort-evt-log");
            if (!firstFailStage) {
                firstFailStage = "11-abort-evt-log";
                firstFailReason = "event log could not be stopped before reset";
            }
            goto recover;
        }
        evtResetOk = true;
    }

    // ---- 第 12 步：使能后先清一次缓存（此时仍全直通）----
    //
    // CMD_INV_ALL (type 0x08) 在 FEATURE_IA=1 时合法（第三轮已解码确认）。
    if (!m2b2Submit(base, &ctx, "inv-all",
                    0, ((UInt32)M2B2_CMD_INV_ALL << 28), 0, 0)) {
        setProperty("m2-b2-inv-all", "FAIL-no-completion");
        setProperty("m2-b2-verdict", "INVALID-inv-all-no-completion");
        setProperty("m2-b2-stage", "12-abort-inv-all");
        if (!firstFailStage) {
            firstFailStage = "12-abort-inv-all";
            firstFailReason = "CMD_INV_ALL did not complete";
        }
        goto recover;
    }
    setProperty("m2-b2-inv-all", "done");
    invAllOk = true;

    // ---- 第 13 步：纯睡眠对照（pgtsleep）----
    //
    // 该分支**不切换 DTE**，只做与 pgthold 相同的长睡眠，用来区分
    // "翻译导致设备冻结" 与 "长 IOSleep 阻塞 workloop 导致测量假象"。
    //
    // 【明确时长】本分支固定 20 秒，**不是** M2B2_MEAS_SECS。它的用途
    // 是从外部用 netstat 观察设备是否仍在收发，需要足够长的时间窗；
    // 而它不产生任何用于比较的事件计数，所以不存在与其他窗口错配的问题。
    if (fM22b2SleepOnly) {
        setProperty("m2-b2-sleep-only", "yes");
        setProperty("m2-b2-dte", "NOT-switched-control");
        setHexProperty(this, "m2-b2-window-secs", 20);
        // 控制阶段的时间边界也必须是可核对的单调时间。
        const UInt64 tCtl0 = m2b2NowNS();
        const UInt64 wCtl0 = m2b2WallSecs();
        setHexProperty(this, "m2-b2-ctl-t-start", tCtl0);
        setHexProperty(this, "m2-b2-ctl-wall-start", wCtl0);
        IOSleep(20000);
        const UInt64 tCtl1 = m2b2NowNS();
        setHexProperty(this, "m2-b2-ctl-t-end", tCtl1);
        setHexProperty(this, "m2-b2-ctl-wall-end", m2b2WallSecs());
        setHexProperty(this, "m2-b2-ctl-dur-ms", m2b2ToMS(tCtl1 - tCtl0));
        setProperty("m2-b2-sleep-only", "done");

        // 【第七轮】控制阶段确实完成了。
        //
        // 这个布尔量是 CONTROL 判定的**必要条件**：只有前置重置、命令、
        // 以及控制阶段本身都成立，才允许输出 CONTROL。第六轮只看
        // fM22b2SleepOnly 这个"选择"，于是任何真实失败都会被覆盖。
        controlDone = true;

        setProperty("m2-b2-evt-window", "none-in-sleep-only-branch");
        setProperty("m2-b2-verdict", "CONTROL-sleep-only-no-dte-change");
        setProperty("m2-b2-stage", "13-control-complete");
        goto recover;
    }

    // ---- 第 14 步：建设备表项并切换目标设备到翻译 ----
    //
    // set_dte_entry()（iommu.c:1580-1602）：
    //   pte_root = root_pa | (mode << 9) | IR | IW | V | TV
    {
        const UInt64 pageMode = fM22b2Use3L ? M2B2_PAGE_MODE_3_LEVEL
                                            : M2B2_PAGE_MODE_4_LEVEL;
        setHexProperty(this, "m2-b2-page-mode", pageMode);

        const UInt64 dteRoot = (rootPA & M2B2_PTE_ADDR_MASK) |
                               ((pageMode & M2B2_DEV_ENTRY_MODE_MASK)
                                << M2B2_DEV_ENTRY_MODE_SHIFT) |
                               DTE_IR | DTE_IW | DTE_V | DTE_TV;

        const UInt64 dtePassthrough = DTE_V | DTE_TV | DTE_IR | DTE_IW;
        setHexProperty(this, "m2-b2-dte-pass", dtePassthrough);
        setHexProperty(this, "m2-b2-dte-xlate", dteRoot);
        setHexProperty(this, "m2-b2-dte-before", dte[tgt * 4 + 0]);

        ctx.domid = 0;
        ctx.pageMode = (UInt32)pageMode;
        ctx.rootPA = rootPA;

        // 切换前先采一个窗口：此时 DTE 仍是直通，任何事件都不是翻译造成的。
        m2b2SampleEvents(base, evtBuf, M2B2_MEAS_SECS, tgt, &winPre);
        preWindowRan = true;
        setProperty("m2-b2-pre-window-ran", "yes");
        setHexProperty(this, "m2-b2-pre-entries", winPre.entries);
        setProperty("m2-b2-pre-valid", winPre.valid ? "yes" : "no");
        if (!winPre.valid) {
            setProperty("m2-b2-pre-invalid", winPre.invalidReason);
        }

        // 【v0.20.0】winPre 无效时**不允许**继续做翻译实验。
        // 理由：winPre 的作用是给出"同一台设备、同一段时间、未切换 DTE"
        // 的对照。若它本身无效（溢出 / 日志停了 / 条目撕裂），后面的主窗口
        // 即使有效也无法归因——我们失去了基线。继续做下去只会得到
        // 一个无法解释的数字，正是第三、四轮反复出问题的那种结果。
        if (!winPre.valid) {
            firstFailStage = "14-pre-window-invalid";
            firstFailReason = winPre.invalidReason;
            setProperty("m2-b2-first-fail-stage", firstFailStage);
            setProperty("m2-b2-first-fail-reason", firstFailReason);
            setProperty("m2-b2-verdict", "INVALID-pre-window");
            setProperty("m2-b2-stage", "14-abort-pre-window");
            // DTE 尚未改动，无需改回；直接进入恢复。
            goto recover;
        }

        // ---- 第 14b 步：进入窗口的前半段（round22 顺序修正）----
        //
        // 【为什么必须在这里，而不是在写 DTE 之后】
        //   第 21 轮的顺序是"写 DTE → 两条失效 → Install → 排空 → 开闸"。
        //   排空发生在 DTE 已经切换之后，于是"旧映射下已交给硬件的 TX"
        //   实际上已经被新表翻译过了；更糟的是，一个已经通过旧路径、还没
        //   写 OWN 的输出线程既不在闸门计数里，也不在环占用里，排空对它
        //   视而不见。
        //
        //   现在的顺序：Install（关闭接纳，发布状态）→ 等提交者退出并排空
        //   旧映射的环 → 再写 DTE → 失效 → 才打开接纳。DTE 切换不会与任何
        //   未完成的提交并发，因为接纳字节的引用计数把它们都算进来了。
        //
        // 【为什么 Install 放在 pre-window 之后】
        //   pre-window 是"DTE 仍是直通"的对照采样，要跑 3 秒。Install 会
        //   关闭接纳，把对照窗口里的普通流量全部丢掉。所以先采完对照，再
        //   Install。
        if (!r17Activate(base, &ctx)) {
            setProperty("m2-3b-authorize", "FAIL-install");
            firstFailStage = "14b-abort-install";
            firstFailReason = "backend install refused";
            goto recover;
        }
        if (!r17StopSubmit(2000, "enter")) {
            firstFailStage = "14b-abort-enter-drain";
            firstFailReason = "old-mapping descriptors did not drain before the DTE flip";
            setProperty("m2-3e-enter", "FAIL-not-stopped-dte-not-flipped");
            goto recover;
        }
        setProperty("m2-3e-enter", "stopped-before-dte");

        dte[tgt * 4 + 0] = dteRoot;
        dte[tgt * 4 + 1] = ctx.domid;   // data[1] 低 16 位 = domain id
        dte[tgt * 4 + 2] = 0;
        dte[tgt * 4 + 3] = 0;
        setHexProperty(this, "m2-b2-dte-after", dte[tgt * 4 + 0]);
        setHexProperty(this, "m2-b2-dte-domid", dte[tgt * 4 + 1]);
        setProperty("m2-b2-dte", "switched-to-translation");
        OSSynchronizeIO();
        // 【第九轮】DTE 写入完成的时刻。这只是"写下去了"，不等于翻译已生效：
        // 失效命令还没提交，TLB 里可能仍是旧表项。真正的生效起点在
        // 第 15 步两条失效命令都收到完成之后记为 tInvComplete。
        fM22b2Dma.tDteWritten = m2b2NowNS();
        setHexProperty(this, "m2-b2-dma-t-dte-written",
                       fM22b2Dma.tDteWritten);
    }

    // ---- 第 15 步：失效命令（全部从 ctx 取参数）----
    //
    // 顺序照抄 Linux attach_device：先 INV_DEV_ENTRY，再刷 TLB。
    // INV_IOMMU_PAGES 的 domain 取 ctx.domid —— 这正是旧代码的缺陷所在。
    {
        const UInt64 invAddr = m2b2InvAddress();
        setHexProperty(this, "m2-b2-inv-addr", invAddr);

        // (a) INV_DEV_ENTRY：data[0] = devid，type 在 data[1] bit28
        if (!m2b2Submit(base, &ctx, "inv-dev-entry",
                        ctx.devid,
                        ((UInt32)M2B2_CMD_INV_DEV_ENTRY << 28), 0, 0)) {
            setProperty("m2-b2-inv", "FAIL-inv-dev-entry-no-completion");
            setProperty("m2-b2-verdict", "INVALID-inv-dev-entry");
            setProperty("m2-b2-stage", "15-abort-inv-dev-entry");
            if (!firstFailStage) {
                firstFailStage = "15-abort-inv-dev-entry";
                firstFailReason = "CMD_INV_DEV_ENTRY did not complete";
            }
            goto recover;
        }

        // (b) INV_IOMMU_PAGES：整个地址空间，domain 来自 ctx
        //     data[1] 低 16 位 = domid；PDE 位表示连 PDE 一起失效
        if (!m2b2Submit(base, &ctx, "inv-iommu-pages",
                        0,
                        ctx.domid | ((UInt32)M2B2_CMD_INV_IOMMU_PAGES << 28),
                        (UInt32)(invAddr & 0xFFFFFFFF) | M2B2_CMD_PDE_MASK,
                        (UInt32)(invAddr >> 32))) {
            setProperty("m2-b2-inv", "FAIL-inv-pages-no-completion");
            setProperty("m2-b2-verdict", "INVALID-inv-pages");
            setProperty("m2-b2-stage", "15-abort-inv-pages");
            if (!firstFailStage) {
                firstFailStage = "15-abort-inv-pages";
                firstFailReason = "CMD_INV_IOMMU_PAGES did not complete";
            }
            goto recover;
        }

        setProperty("m2-b2-inv", "dev-entry+pages-flushed");
        invDevOk = true;
        invPagesOk = true;
        setHexProperty(this, "m2-b2-inv-domid", ctx.domid);
        setHexProperty(this, "m2-b2-cmd-submits", ctx.submits);
        setHexProperty(this, "m2-b2-cmd-completed", ctx.completed);
        setHexProperty(this, "m2-b2-inv-sem", ctx.lastSem);
        setHexProperty(this, "m2-b2-inv-loops", ctx.lastLoops);

        // 【第九轮】翻译**生效**的时刻是这里，不是写 DTE 的那一刻。
        //
        //   第八轮把 tTranslateOn 记在 dte[] 写完之后。可是那时失效命令
        //   还没提交，IOMMU 的 TLB 里可能仍是直通表项；"DTE 已写"与
        //   "翻译已生效"是两件事，把它们合成一个时刻会让"窗口在翻译
        //   生效区间内"这句话缺少它需要的前提。
        //
        //   两条命令都收到了完成信号之后，才把这一刻记为生效起点。
        fR15InvTicks = mach_absolute_time();
        fM22b2Dma.tInvComplete = m2b2NowNS();
        fM22b2Dma.tTranslateOn = fM22b2Dma.tInvComplete;
        setHexProperty(this, "m2-b2-dma-t-inv-complete",
                       fM22b2Dma.tInvComplete);
        setHexProperty(this, "m2-b2-dma-t-translate-on",
                       fM22b2Dma.tTranslateOn);
    }

    // ---- 第 15b 步：设备 DMA 观察（v0.21.7）----
    //
    // 【为什么放在这里，而不是更早或更晚】
    //
    //   更早不行：此刻 DTE 刚切到翻译、失效命令刚完成，设备可能还在
    //   重新取描述符，读到的环状态不是稳态。
    //
    //   更晚不行：必须在主窗口**之前**读一次 TX 完成计数，才能在窗口
    //   之后再读一次，用两次之差证明"设备在这段时间里真的完成了传输"。
    //   这正是第五轮缺失的那类证据：当时的 netstat 差值是秒级的，
    //   无法把某个包归到窗口内，也无法排除统计发布延迟。
    //
    //   本步只读：不写设备寄存器，不改变 DMA 路径。
    observeDeviceDma();
    setProperty("m2-b2-dma-obs-before-window",
                fM22b2Dma.ran ? "yes" : "no");

    // ---- 第 15c 步：绑定本次驱动实例（必须在窗口之前）----
    //
    // 【为什么放在这里】
    //   驱动观测日志的 epoch 是"驱动实例"的标识。要让"这份快照属于本次
    //   实例"成为可核验的事实，绑定值必须在读到证据**之前**定下来。
    //   第 16c 步（窗口之后）才读快照，所以绑定点选在这里。
    //
    // 【第十轮为什么没有这一步】
    //   读侧把 want.epoch 写成 0，而 0 表示"不检查"。整条保护因此从未
    //   生效：驱动重载后同一块卡的新实例会被当成旧的。
    m2b2BindDriverInstance();
    setHexProperty(this, "m2-b2-epoch-bound-at-window",
                   (UInt64)fM22b2Dma.epochBound);
    setHexProperty(this, "m2-b2-epoch-bound-before-window",
                   fM22b2Dma.tWinStart);

    // ---- 第 15d 步：RX 投递缓冲区集合的**水位**（必须在窗口之前）----
    //
    // 【为什么只在这里读一次，而且只记水位】
    //   本轮要证明的是"窗口内设备可能写入的每一个 RX 缓冲区都被映射"。
    //   集合由两半组成：窗口前的基线槽表，以及基线之后、窗口结束之前的
    //   每一条重新投递记录。要判断"哪些重新投递属于本窗口"，就必须在
    //   窗口打开**之前**把驱动的重投递计数记下来——之后序号大于它的，
    //   都是窗口（及其紧邻的采集区间）产生的。
    //
    // 【为什么不能等窗口之后再一起读】
    //   那样"窗口之前已经发生的重投递"和"窗口内发生的"就无法区分：基线
    //   槽表只反映最后一次采集，被它替换掉的缓冲区会两头都不在，集合
    //   悄悄变小，而"全部覆盖"仍然成立。这正是本轮要消除的失效形态。
    //
    // 本步只读属性，不写设备寄存器，也不改变 DMA 路径。
    m2b2RxSetRead(true);
    // Replacements are impossible until both mapping and invalidation have
    // completed. Authorization accepts no new DMA addresses from the probe.
    setHexProperty(this, "m2-b2-r15-flood-token",
                   fM22b2Dma.declaredToken ^ 0x80000000u);
    setHexProperty(this, "m2-b2-r15-flood-req-first", 10001);
    setHexProperty(this, "m2-b2-r15-flood-req-last", 11200);
    // ---- 第 15e 步：打开接纳（round22 顺序修正）----
    //
    // 【顺序】第 14b 步已经停掉接纳、等提交者退出、排空旧映射；第 14 步
    // 切换了 DTE；第 15 步两条失效命令都收到了完成。只有到这一刻，"设备
    // 通过本表翻译"才是成立的事实，因此也只有到这一刻才允许重新接纳：
    //
    //   * 普通包 PA 会改用新表解析（新表只保证 [0,16GiB) 恒等，
    //     r17TxCover 负责在写 OWN 之前补上窗口外的块）；
    //   * 受控包的 64GiB IOVA 只有在新表生效后才有意义。
    //
    // 【为什么不在第 14 步之前"只加一个 gate 检查"】
    //   第 21 轮就是这么做的：Install 之后关一个 flag，再读环占用。可是
    //   一个已经通过 flag 检查、还没写 OWN 的输出线程不在任何计数里，
    //   排空会把它当成"已经结束"，于是 DTE 切换与它的 OWN 写并发。现在
    //   接纳是一个原子字（关闭位 + 引用计数），线程在"获准"的同一刻被
    //   计数，在写完 OWN 之后才离开，排空等的是这个计数。
    // Round22: hand the domain the CURRENT command-ring cursors. Install copied
    // them before the two invalidations above were submitted, so without this
    // the first controlled map would append at a consumed slot and its
    // CompletionWait would never be signalled.
    r17SyncCommand(&ctx);
    if (!r17EnterComplete(fM22b2Dma.tTranslateOn)) {
        firstFailStage = "15e-abort-enter-resume";
        firstFailReason = "admission refused to reopen after the DTE flip";
        goto recover;
    }
    // RX DMACommands use the already handed-over R17 command cursor. Prepare
    // and Install complete before R15 is allowed to publish any RX IOVA.
    if (!r27RxBegin()) {
        firstFailStage = "15e-abort-rx-standard-map";
        firstFailReason = "standard RX mappings or pool binding failed";
        goto recover;
    }
    if (!m2b2R15Authorize()) {
        firstFailStage = "15e-abort-pool-authorize";
        firstFailReason = "finite RX domain rejected authorization";
        goto recover;
    }
    r27RxReady();

    // ---- 第 16 步：稳态观察窗口（唯一的功能判据窗口）----
    //
    // 严格按规范消费事件环：只推进 HEAD，绝不写 TAIL，不清空缓冲。
    // 窗口有效性由 m2b2SampleEvents 判定；无效即"无法判定"，不是 0 事件。
    //
    // 【第九轮】窗口前先把后置采样需要的 BAR2 映射准备好，并把采样函数
    // 交给 m2b2SampleEvents()。这样采样发生在窗口**内部**，而不是窗口
    // 返回之后。映射失败时 postSampleDone 保持 false，后面的边界判定
    // 会如实报"没有后置采样"，而不是用一个更宽的区间充数。
    {
        postSample.reg = fM22b2Dma.cloPtrReg;
        postSample.width = fM22b2Dma.cloPtrWidth;
        postSample.mask = fM22b2Dma.cloPtrMask;
        postSample.tailReg = 0;
        postSample.haveBar = false;
        postSample.cloOk = false;
        postSample.tailOk = false;
        postSample.cloRaw = 0;
        postSample.tailRaw = 0;
        postSample.tClo = 0;
        postSample.tTail = 0;

        const amdobs::CloPtrSpec spec =
            amdobs::cloPtrSpecFor(fM22b2Dma.noCloseVer);
        if (spec.valid) postSample.tailReg = spec.tailReg;

        if (fM22b2Dma.ran && fM22b2Dma.haveCloPtr && spec.valid) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            IOService *svc = findNicServiceOnly();
            IOPCIDevice *nic2 = svc ? OSDynamicCast(IOPCIDevice, svc)
                                    : nullptr;
            if (svc && !nic2) svc->release();
#pragma clang diagnostic pop
            if (nic2) {
                postMap =
                    nic2->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress2,
                                                      kIOMapInhibitCache |
                                                      kIOMapReadOnly);
                nic2->release();
                if (postMap) {
                    postSample.bar =
                        (volatile UInt8 *)(uintptr_t)postMap->getVirtualAddress();
                    postSample.haveBar = (postSample.bar != nullptr);
                }
            }
        }
        postSampleDone = postSample.haveBar;
        if (!postSampleDone) {
            setProperty("m2-b2-dma-post-sample", "SKIP-no-bar");
        }
    }

    m2b2SampleEvents(base, evtBuf, M2B2_MAIN_MEAS_SECS, tgt, &winMain,
                     postSampleDone ? m2b2DoPostSample : nullptr,
                     postSampleDone ? &postSample : nullptr);
    mainWindowRan = true;
    setProperty("m2-b2-main-window-ran", "yes");

    // 【第九轮】把窗口边界存成成员，供驱动日志的窗口内配对使用。
    // 这一步必须在这里完成：m2b2ReadDriverObs() 要用它过滤记录，而那一步
    // 早于第 19 步对 winMain.valid 的最终判定。
    fM22b2Dma.tWinStart = winMain.tStart;
    fM22b2Dma.tWinEnd = winMain.tEnd;

    // 采样用的映射在窗口关闭后立即释放：之后的扫描用另外的映射，
    // 这样"窗口内读过寄存器"这件事只发生在窗口内部。
    if (postMap) {
        postMap->release();
        postMap = nullptr;
        postSample.bar = nullptr;
        postSample.haveBar = false;
    }

    // ---- 第 16b 步：窗口内后置采样已经完成，这里只做结果处理 ----
    //
    // 【第九轮重排：采样移进窗口内部】
    //
    //   第八轮的做法：窗口返回之后再读两个寄存器。结果是
    //   [tCloBefore, tCloAfter] ⊇ [tWinStart, tWinEnd]，
    //   跨度 3.00785 秒包住窗口 3.00018 秒。这个方向只能证明"完成发生在
    //   窗口结束之前或之后"，不能证明"完成发生在零事件窗口内"。
    //
    //   现在后置采样由 m2b2SampleEvents() 在 IOSleep 返回之后、tEnd 记录
    //   之前调用 m2b2DoPostSample() 完成，所以
    //
    //       tWinStart <= tCloAfter <= tTailAfter <= tWinEnd
    //
    //   采样本身落在窗口内。窗口关闭后不再读任何设备寄存器。
    //
    //   剩余测量误差仍然存在，但它的**方向**变了：关闭指针与尾指针之间
    //   只隔几十纳秒，而两者都远早于 tWinEnd，所以窗口末尾那一点点时间
    //   里的完成没有被计入——这是漏计，不是多计。方向上是保守的：
    //   不会把"设备还在工作"读成"设备停下来了"。
    //
    //   不声称"误差最多一个描述符"：没有吞吐上界依据。两个采样时刻都
    //   发布，任何人可以据此判断量级。
    {
        fM22b2Dma.boundaryInWindow = false;
        if (postSampleDone) {
            const UInt64 tS = winMain.tStart;
            const UInt64 tE = winMain.tEnd;
            fM22b2Dma.boundaryInWindow =
                (tS != 0 && tE != 0 &&
                 postSample.tClo >= tS && postSample.tTail <= tE);
        }
        setProperty("m2-b2-dma-boundary-in-window",
                    fM22b2Dma.boundaryInWindow ? "yes" : "no");
        if (postSampleDone) {
            setHexProperty(this, "m2-b2-dma-t-clo-after",
                           postSample.tClo);
            setHexProperty(this, "m2-b2-dma-t-tail-after",
                           postSample.tTail);
        }
    }

    if (postSampleDone && postSample.cloOk) {
        cloAfterRaw = postSample.cloRaw;
        cloAfterOk = true;
        fM22b2Dma.tCloAfter = postSample.tClo;
    }
    if (postSampleDone && postSample.tailOk) {
        tailAfterRaw = postSample.tailRaw;
        tailAfterOk = true;
        fM22b2Dma.tTailAfter = postSample.tTail;
    }
    if (!postSampleDone) {
        setProperty("m2-b2-dma-cloptr-delta-valid",
                    "no-post-sample-not-taken");
        setProperty("m2-b2-dma-tx-window-covered", "no");
    }

    // --- 段 1 的结果处理（纯计算，不碰硬件、不扫描）---
    if (cloAfterOk) {
        fM22b2Dma.cloPtrAfter = cloAfterRaw;
        fM22b2Dma.haveCloDelta = true;

        // 掩码差值，不是环取模。
        const UInt32 delta = amdobs::cloPtrDelta(
            fM22b2Dma.cloPtrBefore, cloAfterRaw, fM22b2Dma.cloPtrMask);
        const bool plausible = amdobs::cloPtrDeltaPlausible(
            delta, fM22b2Dma.cloPtrMask);

        setHexProperty(this, "m2-b2-dma-cloptr-after", (UInt64)cloAfterRaw);
        setHexProperty(this, "m2-b2-dma-cloptr-delta", (UInt64)delta);
        // 同时给出"按环取模"的结果，让两种解释的差别可见。
        setHexProperty(this, "m2-b2-dma-cloptr-delta-ringmod",
                       (UInt64)amdobs::cloPtrRingIndex(delta, 1024));

        if (!plausible) {
            // 差值大到无法解释：更像计数器重置或设备更换，而不是
            // "设备完成了半个计数器空间的描述符"。
            fM22b2Dma.cloDelta = 0;
            fM22b2Dma.cloDeltaValid = false;
            setProperty("m2-b2-dma-cloptr-delta-valid",
                        "no-implausible-reset-or-identity-change");
        } else {
            fM22b2Dma.cloDelta = delta;
            fM22b2Dma.cloDeltaValid = true;
            setProperty("m2-b2-dma-cloptr-delta-valid", "yes");
        }
    } else if (fM22b2Dma.ran && fM22b2Dma.haveCloPtr) {
        setProperty("m2-b2-dma-cloptr-delta-valid",
                    "no-sample-invalid-for-width-or-mask");
    }

    if (tailAfterOk) {
        fM22b2Dma.tailPtrAfter = tailAfterRaw;
        setHexProperty(this, "m2-b2-dma-tailptr-after",
                       (UInt64)tailAfterRaw);
    }

    // --- 段 2：窗口扫描（边界已固定，此后不再影响边界值）---
    //
    // 【为什么必须在这里，而不是在两次采样之间】
    //   扫描 1024 个描述符、发布几十个属性都要时间。放在两次边界采样
    //   之间，就会把"完成进展"的区间撑得比主窗口还宽——第七轮正是
    //   这样：两次采样相距 3.00694 秒，中间还夹着整个扫描。
    if (fM22b2Dma.ran && fM22b2Dma.haveTxRing && tailAfterOk) {
        const UInt64 bytes = 1024ULL * amdobs::TX_DESC_STRIDE;
        const char *why = nullptr;
        if (amdobs::plausibleRingBase(fM22b2Dma.txRingBase, bytes,
                                      M2B2_IDENTITY_LIMIT, &why) &&
            amdobs::readVerdictDeviceReported(fM22b2Dma.txRingBase, bytes,
                                fM22b2Policy) == amdobs::RD_OK) {
            IOMemoryDescriptor *winMd = IOMemoryDescriptor::withPhysicalAddress(
                fM22b2Dma.txRingBase, bytes, kIODirectionIn);
            if (winMd) {
                IOMemoryMap *m = winMd->map(kIOMapInhibitCache | kIOMapReadOnly);
                if (m) {
                    const UInt8 *rb =
                        (const UInt8 *)(uintptr_t)m->getVirtualAddress();
                    m2b2ScanTxWindowAfter(rb, 1024);
                    m->release();
                } else {
                    setProperty("m2-b2-dma-win-scan", "SKIP-remap-failed");
                }
                winMd->release();
            } else {
                setProperty("m2-b2-dma-win-scan", "SKIP-md-failed");
            }
        } else {
            setProperty("m2-b2-dma-win-scan", "SKIP-ring-not-readable");
        }
    } else if (fM22b2Dma.ran) {
        setProperty("m2-b2-dma-win-scan",
                    tailAfterOk ? "SKIP-no-tx-ring" : "SKIP-no-tail-pointer");
    }

    // ---- 第 16c 步：读驱动侧观测日志（第九轮新增）----
    //
    // 【为什么在窗口之后读】
    //   日志记录的是提交与完成的**实际发生**，窗口内的记录才是本窗口的
    //   证据。驱动每秒把一段后缀复制进属性，所以这里读到的是最新一次
    //   发布，覆盖窗口内那几秒。
    //
    // 【为什么这一条能替代读环作为主证据】
    //   读环只能看到"窗口之后的字节"：证明不了代次，也恢复不了 TSO 的
    //   真实长度。日志里每条记录都带着驱动自己算的累计索引，提交与完成
    //   按同一个数字配对，不涉及对槽位复用的推断。
    //
    //   读环仍然保留：它是唯一不依赖驱动配合的观测，且它的包络是
    //   fault 分类的输入。两者不互相替代，报告里分开说。
    //
    // 【第十轮】先取目标网卡身份，再读快照。
    //   顺序不能反：m2b2ReadDriverObs() 要用这一组去核对快照头部的
    //   vendor/device/BDF/MAC/ifUnit。第九轮没有这一步，于是"记录属于
    //   目标设备"从未被检验过——而那一轮的负载其实走的是另一块网卡。
    //
    // 【第十一轮】实例 epoch 的绑定发生在第 15b 步（窗口之前），不在这里。
    //   这一点是刻意的：在窗口之后取 epoch 等于用被检验的对象去定义检验
    //   标准。这里的读侧只使用那个已经定下来的值。
    m2b2CaptureNicIdentity();
    m2b2ReadDriverObs();

    // ---- 第 16d 步：窗口结束后的 DescOwn 计数（只作旁证）----
    //
    // DescOwn 在本芯片上不被硬件清除，所以这个差值恒为 0（已连续三轮
    // 观察到 done == zeroaddr）。它保留在这里是为了让"DescOwn 不是完成
    // 信号"这件事每次都可见，而不是被删掉后变成一段传闻。
    if (fM22b2Dma.ran) {
        const int after = m2b2ScanTxDone();
        fM22b2Dma.txDoneWithAddrAfter = (after >= 0) ? (UInt32)after : 0;
        fM22b2Dma.haveDoneDelta = (after >= 0);
        setHexProperty(this, "m2-b2-dma-tx-done-after",
                       (after >= 0) ? (UInt64)after : 0);
        if (after >= 0) {
            const UInt32 before = fM22b2Dma.txDoneWithAddrBefore;
            const UInt32 now = (UInt32)after;
            if (now >= before) {
                setHexProperty(this, "m2-b2-dma-tx-completions",
                               (UInt64)(now - before));
                setProperty("m2-b2-dma-tx-completions-valid", "yes");
            } else {
                setHexProperty(this, "m2-b2-dma-tx-completions", 0);
                setProperty("m2-b2-dma-tx-completions-valid",
                            "no-ring-wrapped-or-reset");
            }
        } else {
            setProperty("m2-b2-dma-tx-completions-valid", "no-cannot-read-ring");
        }
    } else {
        setProperty("m2-b2-dma-tx-completions-valid", "no-observation-skipped");
    }

    // 覆盖范围最终值。
    //
    // 【第七轮】一次快照只能支撑**肯定**归属："fault 地址落在设备正在用
    // 的区间里" 是可靠的。反过来，"fault 地址不在集合里" 并不能推出
    // "设备没用过它"——设备可能在一秒前用过。
    //
    // 【第八轮】不再用**一个** coverage 值代表所有路径。
    //
    //   第七轮把 txWindowCovered 的结果直接赋给 fM22b2Dma.coverage，
    //   然后第 17 步用这一个值去分类每一条 fault。但 TX 的整窗覆盖
    //   只对 TX 缓冲成立：RX 缓冲走 mbuf_data_to_physical()，环与统计
    //   缓冲走 IODMACommand，这三条路径一次窗口扫描都看不到。
    //
    //   现在 fM22b2Dma.coverage 是**逐路径记录里最弱的那一个**，
    //   而 classifyFault 另有 allPathsCovered 参数来决定它能否说成
    //   全设备的结论。
    fM22b2Dma.coverage = fM22b2Dma.pathCov.weakest();
    setProperty("m2-b2-dma-coverage",
                amdobs::coverageName(fM22b2Dma.coverage));
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

    // 【第八轮】边界时刻全部发布，使"完成进展"能与明确的窗口逐项核对。
    setHexProperty(this, "m2-b2-dma-t-translate-on",
                   fM22b2Dma.tTranslateOn);
    setHexProperty(this, "m2-b2-dma-t-translate-off",
                   fM22b2Dma.tTranslateOff);
    // 【第九轮】DTE 写入与失效完成分开：只有后者才是翻译生效的起点。
    setHexProperty(this, "m2-b2-dma-t-dte-written",
                   fM22b2Dma.tDteWritten);
    setHexProperty(this, "m2-b2-dma-t-inv-complete",
                   fM22b2Dma.tInvComplete);
    setHexProperty(this, "m2-b2-dma-t-tail-before", fM22b2Dma.tTailBefore);
    setHexProperty(this, "m2-b2-dma-t-tail-after", fM22b2Dma.tTailAfter);
    setHexProperty(this, "m2-b2-dma-t-clo-after", fM22b2Dma.tCloAfter);
    setHexProperty(this, "m2-b2-dma-t-win-start", winMain.tStart);
    setHexProperty(this, "m2-b2-dma-t-win-end", winMain.tEnd);

    setHexProperty(this, "m2-b2-dma-cloptr-before",
                   (UInt64)fM22b2Dma.cloPtrBefore);
    setHexProperty(this, "m2-b2-dma-t-clo-before", fM22b2Dma.tCloBefore);

    setHexProperty(this, "m2-b2-meas-secs", M2B2_MEAS_SECS);
    setHexProperty(this, "m2-b2-window-secs", M2B2_MEAS_SECS);
    setProperty("m2-b2-window-valid", winMain.valid ? "yes" : "no");
    if (!winMain.valid) {
        setProperty("m2-b2-window-invalid", winMain.invalidReason);
    }
    setHexProperty(this, "m2-b2-win-dur-ms", winMain.durMS);
    setHexProperty(this, "m2-b2-win-wall-start", winMain.wallStart);
    setHexProperty(this, "m2-b2-win-wall-end", winMain.wallEnd);
    setHexProperty(this, "m2-b2-pre-wall-start", winPre.wallStart);
    setHexProperty(this, "m2-b2-pre-wall-end", winPre.wallEnd);
    setHexProperty(this, "m2-b2-pre-dur-ms", winPre.durMS);
    setHexProperty(this, "m2-b2-win-head-start", winMain.headStart);
    setHexProperty(this, "m2-b2-win-tail-start", winMain.tailStart);
    setHexProperty(this, "m2-b2-win-head-end", winMain.headEnd);
    setHexProperty(this, "m2-b2-win-tail-end", winMain.tailEnd);
    setHexProperty(this, "m2-b2-win-status-start", winMain.statusStart);
    setHexProperty(this, "m2-b2-win-status-end", winMain.statusEnd);
    setHexProperty(this, "m2-b2-win-entries", winMain.entries);
    setHexProperty(this, "m2-b2-win-devid-mismatch", winMain.devidMismatch);
    setHexProperty(this, "m2-b2-status", (UInt64)winMain.statusEnd);
    // v0.20.0：截断标记与前置积压（必须与分析一起发布）
    setProperty("m2-b2-win-raw-truncated",
                winMain.rawTruncated ? "yes" : "no");
    setHexProperty(this, "m2-b2-win-pre-backlog", winMain.preBacklog);
    setHexProperty(this, "m2-b2-win-new-entries",
                   (winMain.entries >= winMain.preBacklog)
                       ? (winMain.entries - winMain.preBacklog) : 0);
    setHexProperty(this, "m2-b2-pre-backlog", winPre.preBacklog);
    setProperty("m2-b2-pre-raw-truncated",
                winPre.rawTruncated ? "yes" : "no");
    setHexProperty(this, "m2-b2-pre-entries-count", winPre.entries);

    // 逐类型计数 + 原始事件（供离线解码，不再只留总数）
    for (UInt32 t = 1; t < 16; t++) {
        if (winMain.typeCount[t] == 0) continue;
        char k[48];
        snprintf(k, sizeof(k), "m2-b2-win-type%u-name", t);
        setProperty(k, m2b2EventTypeName(t));
        snprintf(k, sizeof(k), "m2-b2-win-type%u-count", t);
        setHexProperty(this, k, winMain.typeCount[t]);
    }
    setHexProperty(this, "m2-b2-win-raw-count", winMain.rawCount);
    for (UInt32 i = 0; i < winMain.rawCount; i++) {
        char k[48];
        snprintf(k, sizeof(k), "m2-b2-win-raw%u", i);
        char v[96];
        snprintf(v, sizeof(v), "%08x%08x%08x%08x",
                 winMain.raw[i][0], winMain.raw[i][1],
                 winMain.raw[i][2], winMain.raw[i][3]);
        setProperty(k, v);
    }

    // 主类型（只报最多的那一种，附规范名称）
    {
        UInt32 bestT = 0, bestN = 0;
        for (UInt32 t = 1; t < 16; t++) {
            if (winMain.typeCount[t] > bestN) {
                bestN = winMain.typeCount[t];
                bestT = t;
            }
        }
        setProperty("m2-b2-win-dominant",
                    bestT ? m2b2EventTypeName(bestT) : "none");
        setHexProperty(this, "m2-b2-win-dominant-count", bestN);
    }

    // ---- 第 17 步：把窗口内的 IO_PAGE_FAULT 地址逐个对照页表 ----
    //
    // 【第五轮重写】第四轮这里也是手写逐级 if/else，并且判据是
    // "叶子 PR=1 就算 present"——它**没有检查叶子的编码是否合法**。
    // 所以一张用非法 NextLevel=7 写成的表，在这里会被报成
    // "walk-present = 8"，也就是"地址都被映射了"，而实际上硬件
    // 正是因为那个非法编码才报的 fault。这正是第四轮把
    // "页表看起来完全正确"与"硬件报 fault"并列成矛盾的原因：
    // 那个"看起来正确"是同一个错误假设的产物。
    //
    // 现在用 amdpte::walkPageTable()，它区分 present / absent / illegal。
    // 对本案（第四轮的 8 条样本，RZ=0 且 PR=1），正确结果是 illegal。
    //
    // 【第六轮补充】范围外地址也要走表，不能因为"超出覆盖范围"就跳过。
    //   第五轮的 m2-b2-dump-count = 0 正是这样来的：唯一那条 fault 在
    //   16 GiB 之外，于是取证被整段跳过，低层表项一次都没被读过。
    //   走表本身是安全的（只读我们自己分配的表内存），结论会明确写成
    //   "absent at level N"，这就是"当前表没有覆盖它"的直接证据。
    {
        UInt32 evtInRange = 0, evtOutOfRange = 0;
        UInt32 evtWalkPresent = 0, evtWalkAbsent = 0, evtWalkIllegal = 0;
        UInt32 evtFlagRz = 0, evtFlagPe = 0, evtFlagPr = 0;
        UInt32 evtWrite = 0, evtRead = 0, evtInterrupt = 0;
        UInt64 evtMinAddr = 0, evtMaxAddr = 0, evtFirstAbsent = 0;
        UInt64 evtFirstIllegal = 0;
        // v0.21.7：把每条 fault 的地址对照**设备实际在用的地址集合**
        UInt32 evtInLiveSet = 0, evtInDeadSet = 0;
        UInt32 evtInsideMapUnobserved = 0, evtUnknownOwnership = 0;
        // 第七轮：快照覆盖下"本次没观察到"是单独一类，不与"确定不在集合内"
        // 混为一谈。
        UInt32 evtObservedAbsent = 0;
        UInt64 evtFirstInLive = 0;
        setProperty("m2-b2-fault-map-basis", "actual-page-table-not-bootstrap-limit");

        // 直接引用第 15b 步观察到的集合（成员，不是栈）。
        //
        // 【为什么不在这里复制一份】
        //   AddrSet 是 48*24+8 = 1160 字节。在栈上复制一份会把
        //   runM22b2PageTableProbe() 的帧推过 __chkstk 阈值（实测
        //   0x14D0 = 5328 字节就已经触发），于是二进制里出现对
        //   ____chkstk_darwin 的弱引用，kmutil 直接拒绝这个 kext。
        //   用 const 引用既省栈，也保证分类用的是同一份快照。
        const amdobs::AddrSet &obsSet = fM22b2AddrSet;
        setHexProperty(this, "m2-b2-fault-obs-set-ranges", (UInt64)obsSet.n);

        volatile UInt64 *ptv = pt;
        const UInt64 ptBase = (UInt64)ptPA;
        const UInt64 ptEnd = ptBase + ptBytes;
        auto readPte17 = [ptv, ptBase, ptEnd](UInt64 tablePA, unsigned idx)
                             -> amdpte::u64 {
            if (tablePA < ptBase || tablePA >= ptEnd) return 0;
            const UInt64 byteOff = tablePA - ptBase;
            if (byteOff + 8ULL * idx + 8ULL > ptEnd - ptBase) return 0;
            return (amdpte::u64)ptv[byteOff / 8 + idx];
        };
        const unsigned rootLevel17 =
            fM22b2Use3L ? amdpte::LEVEL_1G : amdpte::LEVEL_512G;

        for (UInt32 i = 0; i < winMain.rawCount; i++) {
            const UInt32 r1 = winMain.raw[i][1];
            const UInt32 r2 = winMain.raw[i][2];
            const UInt32 r3 = winMain.raw[i][3];

            const UInt32 t = (r1 >> M2B2_EVENT_TYPE_SHIFT) &
                             M2B2_EVENT_TYPE_MASK;
            if (t != M2B2_EVENT_IO_FAULT) continue;

            // 标志域是 dword1 的 bit24:16（规范表 57），**不是**低 16 位。
            // 低 16 位是 DomainID/PASID。第四轮把它当标志读，于是
            // domain=0 的条目全部显示成 "flags=0x000"，把 PR/RW 一起藏掉了。
            const UInt32 fl = (r1 >> 16) & 0x1FF;
            const UInt32 fPr = (fl >> 4) & 1;
            const UInt32 fRw = (fl >> 5) & 1;
            const UInt32 fPe = (fl >> 6) & 1;
            const UInt32 fRz = (fl >> 7) & 1;
            const UInt32 fI  = (fl >> 3) & 1;
            if (fPr) evtFlagPr++;
            if (fPe) evtFlagPe++;
            if (fRz) evtFlagRz++;
            if (fI)  evtInterrupt++;
            else if (fRw) evtWrite++;
            else evtRead++;

            const UInt64 addr = ((UInt64)r3 << 32) | r2;
            if (evtMinAddr == 0 || addr < evtMinAddr) evtMinAddr = addr;
            if (addr > evtMaxAddr) evtMaxAddr = addr;

            const amdpte::WalkResult actualWalk = amdpte::walkPageTable(
                readPte17, rootLevel17, rootPA, addr);

            // ---- 地址归属（第七轮）----
            //
            // 判据是"设备是否在用这个地址"，**不是**"它是否在 16 GiB 之上"。
            // 第五轮把后者当成前者，于是把范围外 fault 直接说成 MMIO。
            //
            // 第七轮加入覆盖维度：一次快照只能支撑**肯定**归属。
            // "地址不在观察到的集合里" 不等于 "设备没用过它"——设备可能
            // 在一秒前用过。只有整窗覆盖（COV_WINDOW）才允许更强的否定。
            {
                const amdobs::FaultClass fc = amdobs::classifyFault(
                    addr, obsSet, fM22b2Policy, fM22b2Dma.coverage,
                    fM22b2Dma.pathCov.allWindow(), true, actualWalk.ok);
                if (fc.own == amdobs::OWN_IN_LIVE_SET) {
                    evtInLiveSet++;
                    if (evtFirstInLive == 0) evtFirstInLive = addr;
                } else if (fc.own == amdobs::OWN_IN_COMPLETED_SET ||
                           fc.own == amdobs::OWN_IN_SNAPSHOT_SET) {
                    evtInDeadSet++;
                } else if (fc.own == amdobs::OWN_IN_ENVELOPE_GAP) {
                    evtInsideMapUnobserved++;
                } else if (fc.own == amdobs::OWN_OBSERVED_ABSENT) {
                    evtObservedAbsent++;
                } else {
                    // OWN_OUTSIDE_ENVELOPE, OWN_TX_WINDOW_ABSENT and
                    // OWN_ENVELOPE_UNKNOWN all land here: none of them puts
                    // the address in the device's set. They are distinguished
                    // by the per-fault property string, not by this counter.
                    evtUnknownOwnership++;
                }
                char k[56];
                char v[192];
                snprintf(k, sizeof(k), "m2-b2-fault%u-ownership", i);
                snprintf(v, sizeof(v), "%s (%s)", amdobs::ownershipName(fc.own),
                         amdobs::purposeName(fc.purpose));
                setProperty(k, v);
                snprintf(k, sizeof(k), "m2-b2-fault%u-reason", i);
                setProperty(k, fc.reason);
            }

            // Sparse high mappings and holes are distinguished by the actual
            // table, never by the bootstrap's historical 16GiB scalar limit.
            if (!actualWalk.ok) evtOutOfRange++;
            else evtInRange++;

            const amdpte::WalkResult &r = actualWalk;
            if (r.ok && r.outPA == addr) {
                evtWalkPresent++;
            } else if (r.illegal) {
                evtWalkIllegal++;
                if (evtFirstIllegal == 0) evtFirstIllegal = addr;
            } else {
                evtWalkAbsent++;
                if (evtFirstAbsent == 0) evtFirstAbsent = addr;
            }
        }

        setHexProperty(this, "m2-b2-fault-inrange", evtInRange);
        setHexProperty(this, "m2-b2-fault-outofrange", evtOutOfRange);
        setHexProperty(this, "m2-b2-fault-walk-present", evtWalkPresent);
        setHexProperty(this, "m2-b2-fault-walk-absent", evtWalkAbsent);
        setHexProperty(this, "m2-b2-fault-walk-illegal", evtWalkIllegal);
        setHexProperty(this, "m2-b2-fault-addr-min", evtMinAddr);
        setHexProperty(this, "m2-b2-fault-addr-max", evtMaxAddr);
        // v0.21.7 归属统计
        setHexProperty(this, "m2-b2-fault-in-live-set", evtInLiveSet);
        setHexProperty(this, "m2-b2-fault-in-dead-set", evtInDeadSet);
        setHexProperty(this, "m2-b2-fault-inside-map-unobserved",
                       evtInsideMapUnobserved);
        setHexProperty(this, "m2-b2-fault-ownership-unknown",
                       evtUnknownOwnership);
        // 第七轮：单列"本次未观察到"。
        setHexProperty(this, "m2-b2-fault-observed-absent",
                       evtObservedAbsent);
        setProperty("m2-b2-fault-coverage",
                    amdobs::coverageName(fM22b2Dma.coverage));
        // 【第八轮】否定结论的适用范围必须与覆盖一致。
        //
        //   第七轮这里只判断 coverage == COV_WINDOW。但 coverage 当时是
        //   由 TX 的整窗覆盖算出来的，却被当成全设备的。现在：
        //     - fault-negative-sound = 所有路径都整窗覆盖（唯一能支持
        //       全设备否定的条件）
        //     - fault-negative-scope  = 实际能说到哪一步
        const bool allCov = fM22b2Dma.pathCov.allWindow();
        setProperty("m2-b2-fault-negative-sound", allCov ? "yes" : "NO");
        setProperty("m2-b2-fault-negative-scope",
                    allCov ? "device-wide-all-paths-covered"
                           : "tx-path-only-rx-and-rings-not-covered");
        setProperty("m2-b2-fault-cov-all-window", allCov ? "yes" : "no");
        if (evtFirstInLive) {
            setHexProperty(this, "m2-b2-fault-1st-in-live", evtFirstInLive);
        }
        if (evtFirstAbsent) {
            setHexProperty(this, "m2-b2-fault-walk-1stabsent", evtFirstAbsent);
        }
        if (evtFirstIllegal) {
            setHexProperty(this, "m2-b2-fault-walk-1stillegal",
                           evtFirstIllegal);
        }

        // 故障标志统计（按规范表 57 解码，而不是只数 type==2 的个数）
        setHexProperty(this, "m2-b2-flags-pr", evtFlagPr);
        setHexProperty(this, "m2-b2-flags-pe", evtFlagPe);
        setHexProperty(this, "m2-b2-flags-rz", evtFlagRz);
        setHexProperty(this, "m2-b2-flags-read", evtRead);
        setHexProperty(this, "m2-b2-flags-write", evtWrite);
        setHexProperty(this, "m2-b2-flags-interrupt", evtInterrupt);
    }

    // ---- 第 17b 步：导出**实际**页表路径（第七轮重写）----
    //
    // 【为什么必须逐级真读，而不是推断】
    //   第六轮导出了 root[0..15]，看到 root[1..15] 全为 0，就写下
    //   "所以 L3[16] 根本不存在"。那句话听起来像观测，其实是推断：
    //   它假设了根项与下层表之间的对应关系，而**从未去读那一项**。
    //   如果根表索引算错、或 root[0] 指向的 L3 页基址不对，结论就完全
    //   不同，而输出会一模一样。
    //
    //   本轮对每个地址真正逐级读取，并把每一级的
    //     - 表物理地址 tablePA
    //     - 表级 level（规范 1-based）
    //     - 索引 index（该级用地址的哪 9 位）
    //     - 原始 PTE
    //     - 解码结论
    //   全部导出。这样"absent at level 3, index 16"是一个**读到的**结果，
    //   任何人可以用同样的表字节复核。
    //
    // 【同时导出正常路径】
    //   只导出失败路径无法证明走表本身是对的：如果 walker 有 bug，它会
    //   把一切都报成 absent，而输出看起来仍然"合理"。所以同时对若干条
    //   设备实际在用的 DMA 地址走表，它们必须命中叶子并翻译回自身
    //   （恒等映射）。一组 present + 一组 absent 才是完整证据。
    {
        setHexProperty(this, "m2-b2-dump-root-pa", rootPA);
        setHexProperty(this, "m2-b2-dump-l2-pa", l2PA);
        setHexProperty(this, "m2-b2-dump-page-mode", (UInt64)ctx.pageMode);
        setHexProperty(this, "m2-b2-dump-pt-pages", (UInt64)ptPageCount);
        const UInt64 dumpLimit = fM22b2Use4K ? M2B2_4K_MAP_LIMIT
                                             : M2B2_IDENTITY_LIMIT;
        setHexProperty(this, "m2-b2-dump-map-limit", dumpLimit);
        const unsigned dumpRootLevel =
            fM22b2Use3L ? amdpte::LEVEL_1G : amdpte::LEVEL_512G;
        setHexProperty(this, "m2-b2-dump-root-level",
                       (UInt64)dumpRootLevel);
        setProperty("m2-b2-dump-leaf-encoding",
                    fM22b2Use4K ? "NextLevel0-4KiB-default"
                                : "NextLevel0-2MiB-default");

        // 根表内容仍然导出（便于核对 root[0] 的编码），但**不再**用它
        // 推断下层内容。推断与观测必须分开。
        for (UInt32 i = 0; i < 16; i++) {
            char k[48];
            snprintf(k, sizeof(k), "m2-b2-dump-root%u", i);
            setHexProperty(this, k, root[i]);
        }

        // 取证覆盖范围：我们实际读了这块内存的哪一段。
        setHexProperty(this, "m2-b2-dump-forensic-base", (UInt64)ptPA);
        setHexProperty(this, "m2-b2-dump-forensic-bytes", ptBytes);

        volatile UInt64 *ptv = pt;
        const UInt64 ptBase = (UInt64)ptPA;
        const UInt64 ptEnd = ptBase + ptBytes;
        auto readPteB = [ptv, ptBase, ptEnd](UInt64 tablePA, unsigned idx)
                            -> amdpte::u64 {
            if (tablePA < ptBase || tablePA >= ptEnd) return 0;
            const UInt64 byteOff = tablePA - ptBase;
            if (byteOff + 8ULL * idx + 8ULL > ptEnd - ptBase) return 0;
            return (amdpte::u64)ptv[byteOff / 8 + idx];
        };

        // 对一条地址逐级走表并导出全部中间事实。
        //
        // 返回 true 表示走到叶子且翻译回自身（恒等映射成立）。
        // `tag` 用来区分 fault 路径与正常 DMA 路径。
        struct WalkExport {
            UInt32 walked;
            UInt32 present;
        } we;
        we.walked = 0;
        we.present = 0;

        auto dumpPath = [&](const char *tag, UInt32 idx, UInt64 addr,
                            bool *outOk) {
            char k[64];
            char v[128];
            snprintf(k, sizeof(k), "m2-b2-%s%u-addr", tag, idx);
            snprintf(v, sizeof(v), "0x%llx", addr);
            setProperty(k, v);

            UInt64 vals[6];
            unsigned lvls[6];
            UInt64 tbls[6];
            unsigned idxs[6];
            UInt32 n = 0;
            unsigned lvl = dumpRootLevel;
            UInt64 tablePA = rootPA;
            const char *walkNote = "reached-leaf";
            bool ok = false;

            while (n < 6) {
                const unsigned ix = amdpte::indexAt(lvl, addr);
                const amdpte::u64 pte = readPteB(tablePA, ix);
                vals[n] = (UInt64)pte;
                lvls[n] = lvl;
                tbls[n] = tablePA;
                idxs[n] = ix;
                n++;
                const amdpte::DecodedPte d = amdpte::decodePte(pte, lvl);
                if (d.kind == amdpte::PTE_TABLE) {
                    lvl = d.childLevel;
                    tablePA = d.outPA;
                    continue;
                }
                if (d.kind == amdpte::PTE_ABSENT) {
                    walkNote = "absent";
                } else if (d.kind == amdpte::PTE_ILLEGAL) {
                    walkNote = "illegal";
                } else {
                    walkNote = "leaf";
                    ok = (d.outPA | (addr & (d.pageSize - 1))) == addr;
                }
                break;
            }

            snprintf(k, sizeof(k), "m2-b2-%s%u-depth", tag, idx);
            setHexProperty(this, k, n);
            for (UInt32 j = 0; j < n; j++) {
                // 表物理地址：证明我们读的是哪一张表
                snprintf(k, sizeof(k), "m2-b2-%s%u-pte%u-table",
                         tag, idx, j);
                setHexProperty(this, k, tbls[j]);
                // 表级：解码的必要输入，不能由解码器自己猜
                snprintf(k, sizeof(k), "m2-b2-%s%u-pte%u-level",
                         tag, idx, j);
                setHexProperty(this, k, lvls[j]);
                // 索引：该级用了地址的哪 9 位
                snprintf(k, sizeof(k), "m2-b2-%s%u-pte%u-index",
                         tag, idx, j);
                setHexProperty(this, k, idxs[j]);
                // 原始表项
                snprintf(k, sizeof(k), "m2-b2-%s%u-pte%u",
                         tag, idx, j);
                setHexProperty(this, k, vals[j]);
            }
            snprintf(k, sizeof(k), "m2-b2-%s%u-walk", tag, idx);
            setProperty(k, walkNote);
            snprintf(k, sizeof(k), "m2-b2-%s%u-ok", tag, idx);
            setProperty(k, ok ? "yes" : "no");
            snprintf(k, sizeof(k), "m2-b2-%s%u-idx", tag, idx);
            snprintf(v, sizeof(v), "i4=%u,i3=%u,i2=%u,i1=%u",
                     amdpte::indexAt(amdpte::LEVEL_512G, addr),
                     amdpte::indexAt(amdpte::LEVEL_1G, addr),
                     amdpte::indexAt(amdpte::LEVEL_2M, addr),
                     amdpte::indexAt(amdpte::LEVEL_4K, addr));
            setProperty(k, v);
            we.walked++;
            if (ok) we.present++;
            if (outOk) *outOk = ok;
        };

        // (a) 每条 IO_PAGE_FAULT 的真实路径
        UInt32 dumped = 0;
        for (UInt32 i = 0; i < winMain.rawCount && dumped < 4; i++) {
            const UInt32 r1 = winMain.raw[i][1];
            const UInt32 t = (r1 >> M2B2_EVENT_TYPE_SHIFT) &
                             M2B2_EVENT_TYPE_MASK;
            if (t != M2B2_EVENT_IO_FAULT) continue;
            const UInt64 addr =
                ((UInt64)winMain.raw[i][3] << 32) | winMain.raw[i][2];
            bool ok = false;
            dumpPath("dump", dumped, addr, &ok);
            char k[64];
            snprintf(k, sizeof(k), "m2-b2-dump%u-in-map", dumped);
            setProperty(k, (addr >= dumpLimit) ? "no-outside-coverage" : "yes");
            snprintf(k, sizeof(k), "m2-b2-dump%u-limit", dumped);
            setHexProperty(this, k, dumpLimit);
            dumped++;
        }
        setHexProperty(this, "m2-b2-dump-count", (UInt64)dumped);

        // (b) 若干条设备实际在用的 DMA 地址：正常路径必须命中叶子
        //
        // 这一组是"走表本身是对的"的证据。若 walker 有 bug 而把所有地址
        // 都报 absent，这一组的 ok 也会是 no，从而暴露问题。
        {
            UInt64 dmaAddrs[8];
            const char *dmaTags[8];
            UInt32 nDma = 0;
            // 【第八轮】优先走**窗口内实际完成**的那条描述符的地址。
            // 这是本轮要求的那条链：提交 -> 地址 -> 页表 -> 完成。
            // 只走环基址与"第一条描述符"无法把它接到某一次完成上。
            if (fM22b2Dma.haveFirstCompleted &&
                fM22b2Dma.winFirstCompletedAddr != 0) {
                dmaAddrs[nDma] = fM22b2Dma.winFirstCompletedAddr;
                dmaTags[nDma] = "win";
                nDma++;
            }
            if (fM22b2Dma.haveTxRing) {
                dmaAddrs[nDma] = fM22b2Dma.txRingBase;
                dmaTags[nDma] = "dma";
                nDma++;
            }
            if (fM22b2Dma.haveRxRing) {
                dmaAddrs[nDma] = fM22b2Dma.rxRingBase;
                dmaTags[nDma] = "dma";
                nDma++;
            }
            if (fM22b2Dma.haveStat) {
                dmaAddrs[nDma] = fM22b2Dma.statBase;
                dmaTags[nDma] = "dma";
                nDma++;
            }
            if (fM22b2Dma.txFirstAddr) {
                dmaAddrs[nDma] = fM22b2Dma.txFirstAddr;
                dmaTags[nDma] = "dma";
                nDma++;
            }
            if (fM22b2Dma.rxFirstAddr) {
                dmaAddrs[nDma] = fM22b2Dma.rxFirstAddr;
                dmaTags[nDma] = "dma";
                nDma++;
            }

            UInt32 good = 0;
            UInt32 winGood = 0;
            for (UInt32 i = 0; i < nDma; i++) {
                bool ok = false;
                dumpPath(dmaTags[i], i, dmaAddrs[i], &ok);
                if (ok) {
                    good++;
                    if (dmaTags[i][0] == 'w') winGood++;
                }
            }
            setHexProperty(this, "m2-b2-dma-walk-count", (UInt64)nDma);
            setHexProperty(this, "m2-b2-dma-walk-present", (UInt64)good);
            // 窗口内完成的那条地址是否也走到了恒等叶子。这是
            // "提交—地址—页表—完成"这条链的最后一环。
            setProperty("m2-b2-dma-win-walk",
                        fM22b2Dma.haveFirstCompleted
                            ? (winGood ? "identity-mapped" : "NOT-MAPPED")
                            : "no-window-completion-observed");
            // 设备在用地址中能被恒等翻译的比例。这是"表对不对"的直接
            // 证据，而不仅是"fault 地址有没有被覆盖"。
            setProperty("m2-b2-dma-walk-verdict",
                        (nDma == 0) ? "no-addresses-observed"
                                    : (good == nDma ? "all-identity-mapped"
                                                    : "SOME-NOT-MAPPED"));
        }

        setHexProperty(this, "m2-b2-walk-total", (UInt64)we.walked);
        setHexProperty(this, "m2-b2-walk-present", (UInt64)we.present);
    }

    // ---- 第 17c 步：为每个受控请求的每个 TX/RX 段走真实页表 ----
    //
    // 【为什么放在恢复之前】
    //   走表读的是本次实验建的页表内存。恢复流程在确认硬件停止后会
    //   释放它；之后再走表就是 use-after-free。这里与第 17b 步一样，
    //   仍在 DTE 指向翻译表的区间内。
    //
    // 【为什么传 pt / ptPA / ptBytes】
    //   它们是本函数的局部变量，作用域正好覆盖这块内存的生命周期。
    //   提升成成员会让它活过 free，那正是要避免的形态。
    m2b2WalkBusinessRanges(dte, tgt, pt, (UInt64)ptPA, ptBytes);

    // ---- 第 17d 步：RX 投递缓冲区集合的读入、构造与走表 ----
    //
    // 【顺序】
    //   1. 读窗口之后的那份 rtl812x-rxpost（基线 + 重投递记录 + 原始字节）；
    //   2. 用第 15d 步记下的水位把它拼成集合 S；
    //   3. 对 S 的每个区间走表，判据与业务区间完全相同（RX 需要 IW）。
    //
    // 【为什么仍在恢复之前】
    //   与第 17c 步同一个理由：走表读的是本次实验建的页表内存，恢复流程
    //   之后会释放它。传 pt / ptPA / ptBytes 而不是把它们提升成成员，
    //   也是同一个理由——成员会活过 free。
    //
    // 【失败不隐藏】
    //   读不到发布、集合不完整、区间走表失败，三种情况分别有独立的稳定
    //   token（m2-b2-rxset-why / -set-why / -walk），并且都以"未证明"
    //   而不是"零失败"的形式记录。
    if (m2b2RxSetRead(false)) {
        m2b2WalkRxSet(dte, tgt, pt, (UInt64)ptPA, ptBytes);
    }
    m2b2PublishRxSet();

recover:
    // Disarm cyclic repost, then keep TX OPEN for the bounded userspace echo
    // tail that returns every pending RX IOVA to its physical ring buffer.
    // Standard RX unmaps still run under translation and the shared command
    // buffer. On failure pin BEFORE closing TX so diagnostics/tail can continue.
    const bool rxDrained = r27RxFinish(15000);
    if (!rxDrained) {
        // No TX close, DTE restoration, command stop, detach or table free.
        setProperty("m2-3b-cleanup", "PINNED-RX-no-DTE-restore");
        setProperty("m2-b2-verdict", "INVALID-RX-outstanding-or-unmap-pinned");
        setProperty("m2-b2-stage", "17e-pinned-RX");
        r17Export(&ctx);
        return;
    }
    if (!r29WaitTailDone(5000)) {
        setProperty("m2-3b-cleanup", "PINNED-tail-no-DTE-restore");
        setProperty("m2-b2-verdict", "INVALID-tail-not-confirmed");
        setProperty("m2-b2-stage", "17e-pinned-tail");
        r17Export(&ctx);
        return;
    }
    // ---- 第 17e 步：退出窗口的前半段（round22）----
    //
    // 【顺序】停止接纳 → 等已获准的提交写完 OWN → 排空硬件持有的 TX →
    // 强制采退出快照。这几步都发生在翻译**仍然生效**的时候：硬件此刻可能
    // 还持有描述符，它们必须继续被正确翻译，所以这里绝不能先改 DTE。
    //
    // 【失败即钉住】排空失败时不做 Disarm、不做 Detach、不恢复 DTE，把表、
    // 命令缓冲和 backend 全部留在原处，并如实报告。第 21 轮的失败路径是
    // "drained=false 仍然 Disarm/Detach → 返回失败"，结果是翻译留在原地、
    // 而 Disarm 顺手打开了普通提交：普通包在没有 cover 的表上被放行。
    const bool hadWindow = r17Installed();
    if (hadWindow) {
        const bool stopped = r17StopSubmit(2000, "exit");
        // 退出记录就在这一步取：排空成功与否都要取，失败时记录里的占用
        // 正是"为什么被钉住"的证据。
        r17SampleExit(r20tx::kStageExit);
        if (!stopped) {
            setProperty("m2-3b-cleanup", "PINNED-outstanding-no-DTE-restore");
            setProperty("m2-b2-verdict", "INVALID-TX-outstanding-pinned");
            setProperty("m2-b2-stage", "17e-pinned-outstanding");
            r17Export(&ctx);
            return;
        }
    }
    // ---- 第 18 步：恢复（状态机，任何一步失败都阻止释放）----
    //
    // 恢复阶段的时间边界也发布出来，使"停止—确认—还原"能被核对。
    fM22b2Dma.tRecoveryStart = m2b2NowNS();
    setHexProperty(this, "m2-b2-t-recovery-start", fM22b2Dma.tRecoveryStart);
    //
    // 【第五轮重写】第四轮这里有两个真问题：
    //
    //  (a) `cmdBufStopped = true;` 是**直接赋值**，没有任何硬件依据。
    //      属性里写的是 "yes"，但它并不代表硬件真的停了命令缓冲。
    //      规范 48882 §3.4.16：STATUS[4] = CmdBufRun，"1 = the IOMMU may
    //      fetch commands from the command buffer"。必须读它，而不是假设。
    //
    //  (b) 停止阶段里 `c |= (origCtrl & M2B2_CTRL_CMDBUF_EN)` 把**原始使能位
    //      又写回去了**。也就是说"停止"这一步可能反而把命令缓冲重新使能。
    //      原始状态只能在确认停稳、且要恢复寄存器时一次性还原，不能在
    //      停止阶段提前恢复。事件日志那一行有同样的问题。
    //
    // 现在的顺序（依据规范 §2.4 / §2.5.1 的重启流程，以及 Linux
    // iommu_disable() init.c:470-495 的实践）：
    //   1. 清 CMDBUF_EN / EVT_LOG_EN，把两个"停止"位都置 0，**不**还原原值；
    //   2. 有界等待 STATUS.CmdBufRun == 0 与 STATUS.EventLogRun == 0；
    //   3. 清 IOMMU_EN 并读回确认；
    //   4. 三者都确认后才允许还原基址寄存器与原始使能状态；
    //   5. 寄存器读回全部等于原值，才允许释放内存。
    //
    // 每一步的 CONTROL/STATUS 实际读回值、等待轮数与是否超时都发布成属性，
    // 使"停没停"可以被外部复核，而不是靠一个硬编码的 yes。

    // 18.1 先关两个使能位（不还原原值）
    {
        UInt64 c = mmioRead64(base, M2B2_OFF_CONTROL);
        c &= ~M2B2_CTRL_CMDBUF_EN;
        c &= ~M2B2_CTRL_EVT_LOG_EN;
        mmioWrite64(base, M2B2_OFF_CONTROL, c);
        setHexProperty(this, "m2-b2-stop-control-write", c);
        setHexProperty(this, "m2-b2-stop-control-readback",
                       mmioRead64(base, M2B2_OFF_CONTROL));
    }

    // 18.1b 发布逐条命令记录（命令字 / 预期值 / 观测值 / 阶段）
    {
        setHexProperty(this, "m2-b2-cmd-record-count",
                       (UInt64)ctx.recordCount);
        for (UInt32 i = 0; i < ctx.recordCount; i++) {
            const M2B2CmdRecord *r = &ctx.records[i];
            char k[56];
            char v[128];
            snprintf(k, sizeof(k), "m2-b2-cmd%u-label", i);
            setProperty(k, r->label);
            snprintf(k, sizeof(k), "m2-b2-cmd%u-dwords", i);
            snprintf(v, sizeof(v), "%08x%08x%08x%08x",
                     r->d0, r->d1, r->d2, r->d3);
            setProperty(k, v);
            snprintf(k, sizeof(k), "m2-b2-cmd%u-expected", i);
            setHexProperty(this, k, r->expected);
            snprintf(k, sizeof(k), "m2-b2-cmd%u-observed", i);
            setHexProperty(this, k, r->observed);
            snprintf(k, sizeof(k), "m2-b2-cmd%u-loops", i);
            setHexProperty(this, k, (UInt64)r->loops);
            snprintf(k, sizeof(k), "m2-b2-cmd%u-ok", i);
            setProperty(k, r->ok ? "yes" : "no");
        }
    }

    // 18.2 有界等待 CmdBufRun 清零（规范 STATUS[4]）
    {
        UInt32 loops = 0;
        UInt32 st = mmioRead32(base, M2B2_OFF_STATUS);
        while (loops < M2B1_LOOP_TIMEOUT) {
            st = mmioRead32(base, M2B2_OFF_STATUS);
            if ((st & M2B2_STATUS_CMDBUF_RUN) == 0) break;
            loops++;
        }
        cmdBufStopped = ((st & M2B2_STATUS_CMDBUF_RUN) == 0);
        setHexProperty(this, "m2-b2-cmdbuf-stop-loops", loops);
        setHexProperty(this, "m2-b2-cmdbuf-stop-status", st);
        setProperty("m2-b2-cmdbuf-stopped",
                    cmdBufStopped ? "yes" : "FAIL-cmdbuf-still-running");
        if (!cmdBufStopped) {
            setProperty("m2-b2-cmdbuf-stop-timeout", "yes");
        }
    }

    // 18.3 有界等待 EventLogRun 清零（规范 STATUS[3]）
    {
        UInt32 loops = 0;
        UInt32 st = mmioRead32(base, M2B2_OFF_STATUS);
        while (loops < M2B1_LOOP_TIMEOUT) {
            st = mmioRead32(base, M2B2_OFF_STATUS);
            if ((st & M2B2_STATUS_EVT_RUN) == 0) break;
            loops++;
        }
        evtLogStopped = ((st & M2B2_STATUS_EVT_RUN) == 0);
        setHexProperty(this, "m2-b2-evtlog-stop-loops", loops);
        setHexProperty(this, "m2-b2-evtlog-stop-status", st);
        setProperty("m2-b2-evtlog-stopped",
                    evtLogStopped ? "yes" : "FAIL-still-running");
    }

    // 18.4 最后才停 IOMMU 本体，并读回确认
    {
        UInt64 c = mmioRead64(base, M2B2_OFF_CONTROL);
        c &= ~M2B2_CTRL_IOMMU_EN;
        mmioWrite64(base, M2B2_OFF_CONTROL, c);
        const UInt64 rb = mmioRead64(base, M2B2_OFF_CONTROL);
        hwStopped = ((rb & M2B2_CTRL_IOMMU_EN) == 0);
        setHexProperty(this, "m2-b2-disabled-readback", rb);
        setProperty("m2-b2-disabled",
                    hwStopped ? "yes" : "FAIL-still-enabled");
    }

    // 18.5 三项都确认停稳后，才还原基址寄存器与原始使能状态
    if (hwStopped && cmdBufStopped && evtLogStopped) {
        // 基址寄存器先还原，最后再把 CONTROL 整体写回原值。
        // 顺序不能反：先把 CONTROL 还原成"已使能"，硬件就会立刻去读
        // 还指向我们缓冲区的基址寄存器。
        mmioWrite64(base, M2B2_OFF_DEV_TABLE, origDT);
        mmioWrite64(base, M2B2_OFF_CMD_BUF, origCmd);
        mmioWrite64(base, M2B2_OFF_EVT_BUF, origEvt);
        mmioWrite64(base, M2B2_OFF_CONTROL, origCtrl);
        OSSynchronizeIO();

        const UInt64 fc = mmioRead64(base, M2B2_OFF_CONTROL);
        const UInt64 fdt = mmioRead64(base, M2B2_OFF_DEV_TABLE);
        const UInt64 fcm = mmioRead64(base, M2B2_OFF_CMD_BUF);
        const UInt64 fev = mmioRead64(base, M2B2_OFF_EVT_BUF);

        setHexProperty(this, "m2-b2-final-control", fc);
        setHexProperty(this, "m2-b2-final-devicetable", fdt);
        setHexProperty(this, "m2-b2-final-cmdbuf", fcm);
        setHexProperty(this, "m2-b2-final-evtbuf", fev);
        setHexProperty(this, "m2-b2-orig-control-echo", origCtrl);

        regsRestored = (fc == origCtrl) && (fdt == origDT) &&
                       (fcm == origCmd) && (fev == origEvt);
        setProperty("m2-b2-regs-restored",
                    regsRestored ? "yes" : "MISMATCH");
        safeToFree = regsRestored;
    } else {
        setProperty("m2-b2-regs-restored", "skipped-hardware-not-stopped");
        setProperty("m2-b2-restore-abort",
            "refusing to rewrite base registers while hardware may still "
            "reference them");
        // 明确记录是哪一项没停住，而不是只给一个笼统的失败
        const char *why = !hwStopped      ? "iommu-en-still-set"
                        : !cmdBufStopped  ? "cmdbuf-run-still-set"
                                          : "eventlog-run-still-set";
        setProperty("m2-b2-restore-abort-reason", why);
        safeToFree = false;
    }

    // ---- 第 18b 步：确认翻译已停止，然后才拆 backend（round22）----
    //
    // 【顺序】第 18 步把设备表基址与控制寄存器写回原值并读回比对。只有四项
    // 读回全部等于原值，"翻译已停止、原始状态已恢复"才是事实；也只有到这时
    // 才允许 Detach（释放 callback/context/backend），最后才重新接纳普通输出。
    //
    // 【为什么 Detach 必须在恢复之后】第 21 轮的 Detach 出现在恢复之前，而且
    // 它顺手把接纳打开了：恢复失败时翻译还指着我们的表，普通包却已经开始在
    // 没有 cover 的情况下提交。现在 Detach 不再改接纳，接纳只由 kResume 打开，
    // 而 kResume 只在读完寄存器、确认恢复之后调用。
    if (regsRestored) {
        // 这一刻才是"翻译停止"的实际时间，不是恢复阶段的开始。
        fM22b2Dma.tTranslateOff = m2b2NowNS();
        setHexProperty(this, "m2-b2-dma-t-translate-off", fM22b2Dma.tTranslateOff);
        setProperty("m2-3e-translate-off", "confirmed-by-register-readback");
        r17SetTranslateOff(fM22b2Dma.tTranslateOff);
    }
    if (hadWindow) {
        if (!regsRestored) {
            // 拒绝在硬件仍可能引用我们的表时拆 backend：callback、表、命令
            // 缓冲全部留下，接纳保持关闭（普通输出停住），并如实报告。
            setProperty("m2-3b-cleanup", "PINNED-restore-incomplete");
            setProperty("m2-b2-verdict", "INVALID-restore-incomplete-pinned");
            setProperty("m2-b2-stage", "18b-pinned-restore");
            r17Export(&ctx);
            return;
        }
        if (!r17Detach()) {
            setProperty("m2-3b-cleanup", "PINNED-detach-refused");
            setProperty("m2-b2-verdict", "INVALID-detach-refused-pinned");
            setProperty("m2-b2-stage", "18c-pinned-detach");
            r17Export(&ctx);
            return;
        }
        // Detach 成功 = 受控接纳已撤销、callback/context 已清空、翻译已停止。
        // 只有到这一刻才允许普通输出重新流动。
        const bool resumed = r17ResumeOutput();
        r17Export(&ctx);
        r17Release();
        if (!resumed) {
            setProperty("m2-3b-cleanup", "PINNED-resume-refused");
            setProperty("m2-b2-verdict", "INVALID-resume-refused-pinned");
            setProperty("m2-b2-stage", "18d-pinned-resume");
            return;
        }
        setProperty("m2-3b-cleanup", "detached-after-restore-confirmed");
    } else {
        r17Release();
        setProperty("m2-3b-cleanup", "no-window-installed");
    }
    // Stop swaps after translation is off; installed RX objects remain retained
    // and copy-only, never freed while the NIC can still reach them.
    m2b2R15Finish();

    // ---- 第 19 步：判定 ----
    //
    // 严格区分四类，不把"没测到"写成"通过"，也不把"计数变化"当因果：
    //   INVALID        采样/命令/恢复任一条件不成立 → 本轮无结论
    //   CONTROL        控制分支（pgtsleep）的判定，不被翻译判定覆盖
    //   INDETERMINATE  条件成立但缺少目标设备活动的证据 → 无法判定
    //   FAIL           有效条件下观察到具体失败
    //   PASS           仅当全部功能验收条件同时满足（本轮无法给出）
    //
    // 【v0.20.0 修正】判定不再无条件读 winMain：先看主窗口是否真的执行过。
    // 没执行过就是"没测"，既不是 PASS 也不是 FAIL。
    {
        const bool cmdOk     = !ctx.failed;
        const bool winOk     = (mainWindowRan && winMain.valid);
        const bool restoreOk = safeToFree;

        const bool anyEvent    = winOk && (winMain.entries > 0);
        const bool allOurDevid = (winMain.devidMismatch == 0);

        const char *verdict;
        const char *stage;

        // 【第七轮修正：控制分支必须有"完成"证据，不能只看"选择"】
        //
        // 第六轮把 `fM22b2SleepOnly` 当作控制分支成立的全部条件。那是把
        // **选择**当成了**结果**：只要启动参数是 pgtsleep，即使事件日志
        // 重置失败、CMD_INV_ALL 超时、甚至恢复都没做完，最终判定也会被
        // 改写成 CONTROL——真实失败被这个选择本身掩盖了。
        //
        // 现在的顺序：
        //   1. 恢复失败 —— 最高优先，硬件状态不明，任何结论都不可信
        //   2. 命令失败 —— 失效命令没完成，翻译窗口从未正确建立
        //   3. 前置门未过 —— 事件日志重置 / INV_ALL 未完成
        //   4. 控制分支 —— 只有 controlDone（控制阶段确实跑完）才输出
        //   5. 翻译分支的窗口/事件判定
        //
        // 控制分支不切换 DTE，所以"主窗口没跑"对它是**正常**的，不能被
        // 判成 INVALID-main-window-not-executed。分支 4 在分支 5 之前，
        // 正是为了这一点。
        if (!restoreOk) {
            verdict = "INVALID-restore-incomplete";
            stage   = "19-invalid-restore";
        } else if (!cmdOk) {
            verdict = "INVALID-command-did-not-complete";
            stage   = "19-invalid-cmd";
        } else if (!evtResetOk || !invAllOk) {
            // 前置门没通过：控制分支也不能输出 CONTROL，因为控制阶段
            // 赖以成立的硬件状态从未建立。
            verdict = "INVALID-precondition-not-established";
            stage   = "19-invalid-precondition";
        } else if (fM22b2SleepOnly) {
            if (!controlDone) {
                // 选了控制模式，但控制阶段没跑完。这既不是 CONTROL，
                // 也不是翻译实验——它只是没做完。
                verdict = "INVALID-control-stage-did-not-complete";
                stage   = "19-invalid-control";
            } else {
                // 控制实验：不切 DTE、不产生翻译窗口，结论就是"控制组完成"。
                verdict = "CONTROL-sleep-only-no-dte-change";
                stage   = "19-control-preserved";
            }
        } else if (!mainWindowRan) {
            // 主窗口根本没跑：明确说"没测"，不猜结论。
            verdict = "INVALID-main-window-not-executed";
            stage   = "19-invalid-not-executed";
        } else if (!winOk) {
            verdict = "INVALID-event-window";
            stage   = "19-invalid-window";
        } else if (anyEvent && !allOurDevid) {
            verdict = "INDETERMINATE-events-from-other-devices";
            stage   = "19-indeterminate-devid";
        } else if (anyEvent && winMain.typeCount[M2B2_EVENT_IO_FAULT] > 0) {
            // 有效窗口里确实观察到 IO_PAGE_FAULT：具体失败，证据已记录
            verdict = "FAIL-io-page-faults-observed";
            stage   = "19-complete-faults";
        } else if (anyEvent) {
            // 有事件但不是 IO_PAGE_FAULT：类型已逐条记录，按类型定性
            verdict = "FAIL-non-fault-events-observed";
            stage   = "19-complete-other-events";
        } else if (fM22b2Dma.cloDeltaValid && fM22b2Dma.cloDelta > 0) {
            // 【第七轮】窗口内没有事件，**且**硬件关闭指针以可解释的方式
            // 前进了。
            //
            // 比第五轮强得多的结论类别：
            //   - 关闭指针前进 => 设备确实把描述符交还给了驱动，
            //     即真的完成了 DMA，而不只是"没有报错"；
            //   - 事件数为 0 => 这些 DMA 全部被翻译表成功翻译。
            //
            // 但要求 cloDeltaValid：掩码差值必须可解释（不是重置、不是
            // 设备更换）。第六轮用环取模，1000 -> 2024 会得到 0，把
            // "完成了 1024 个描述符"读成"什么都没做"。
            //
            // 【第八轮】还要求窗口扫描真的把这几条完成归因到具体描述符。
            //
            // 【第九轮】再收紧三处，因为第八轮仍然接受了一些不该接受的
            // 采集：
            //
            //   (a) 后置采样必须落在窗口**内部**。第八轮的采样包住窗口
            //       （跨度 3.00785 秒对窗口 3.00018 秒），那个方向证明不了
            //       "完成发生在零事件窗口内"。
            //   (b) 扫描必须 exact：提前停止、记录丢失、长度不可解码、
            //       槽位被覆盖，任何一项成立都撤回覆盖资格。
            //   (c) 必须有一条来自**驱动侧记录**的完整配对——提交与完成
            //       按同一个累计索引对上，且该地址有页表路径。只有读环的
            //       聚合计数不够：那只能说明"计数器动了"。
            //
            // 仍然不是 PASS：这是单次受控实验，不是持续负载与稳定性。
            // 【第十轮】再收紧一处：第九轮的 PASS-CANDIDATE 只要求
            // "驱动记录里有一对窗口内的配对"，但那一对可能来自
            // **另一块网卡**的流量，而且快照本身可能早于窗口终点。
            //
            // 现在要求三个**互相独立**的判据同时成立：
            //
            //   obsHasCompletePair        至少一条可核对的提交/完成
            //   obsRecordsCoverWindow     原始记录完整覆盖 [winStart, winEnd]
            //   obsControlledBatchComplete 本次有限批次的预期业务全部完成
            //
            // 并且仍然要求读环独立把完成归因到具体描述符（读环与驱动记录
            // 是两条独立路径，互相印证才不是自说自话）。
            //
            // 只满足"有一对"而覆盖不成立时，落到
            // INDETERMINATE-snapshot-does-not-cover-window——这正是第九轮
            // 的实际状态：它有配对，但快照比窗口终点早 530957131 ns。
            const bool windowOk2 =
                fM22b2Dma.boundaryInWindow && fM22b2Dma.winExact;
            const bool ringAttributed =
                fM22b2Dma.winCompletedInWindow > 0 &&
                fM22b2Dma.haveFirstCompleted;

            // ---- 第十二轮：把"证据资格"接进最终判定 ----
            //
            // 第十一轮算了七类证据属性并逐个发布，但最终 PASS-CANDIDATE
            // 只消费了其中三项。于是出现了这样的形态：
            //
            //   * 业务区间走表全军覆没（bizWalkFail > 0）仍然 PASS；
            //   * 设备身份未知（nicIdentityKnown = false）被
            //     `if (want.have && !idOk)` 放行；
            //   * token 未声明（0）时从被检查的记录里反推一个，判据循环；
            //   * bizWalkFail 在早退分支里 ++ 过，随后被函数末尾的局部
            //     fail 覆盖。
            //
            // 现在判定不再手写合取，而是调用 amdobs::obsEvidenceGate()：
            // 生产路径与 host 回归跑的是**同一个函数**，每一条反例在
            // tests/dma-observe-test.cpp 里逐项证伪。发布属性不等于使用
            // 属性，这个函数就是把"使用"变成结构事实的地方。
            amdobs::ObsEvidence ev;
            ev.identityKnown     = fM22b2Dma.nicIdentityKnown;
            ev.declaredToken     = fM22b2Dma.declaredToken;
            ev.expectedBatch     = fM22b2Dma.expectedBatch;
            ev.snapshotExported  = fM22b2Dma.obsUsedExported;
            ev.snapshotHashStable = fM22b2Dma.obsUsedHashStable;
            ev.snapshotFresh     = fM22b2Dma.obsUsedIsFresh;
            ev.writerDropped     = fM22b2Dma.obsDropped;
            ev.publishLost       = fM22b2Dma.obsLostCount;
            ev.readerHoles       = fM22b2Dma.obsStale;
            ev.hdrFlags          = fM22b2Dma.obsHdrFlags;
            ev.bizCapped         = fM22b2Dma.obsBizCapped;
            ev.hasCompletePair   = fM22b2Dma.obsHasCompletePair;
            ev.recordsCoverWindow = fM22b2Dma.obsRecordsCoverWindow;
            ev.controlledBatchComplete = fM22b2Dma.obsControlledBatchComplete;
            // 只有"声明的 token 就是实际用于归并的那个"才算绑定成立。
            // token 为 0 时 joinToken 可能是从记录里推出来的，那是循环。
            ev.tokenResolvedOnDeclared =
                (fM22b2Dma.declaredToken != 0 &&
                 fM22b2Dma.obsJoinToken == fM22b2Dma.declaredToken &&
                 fM22b2Dma.obsTokenResolved &&
                 !fM22b2Dma.obsTokenAmbiguous);
            ev.bizWalkExpected   = fM22b2Dma.bizWalkExpected;
            ev.bizWalkCount      = fM22b2Dma.bizWalkCount;
            ev.bizWalkOk         = fM22b2Dma.bizWalkOk;
            ev.bizWalkFail       = fM22b2Dma.bizWalkFail;
            ev.bizWalkCapped     = fM22b2Dma.bizWalkCapped;
            // ---- 第十四轮：RX 投递缓冲区集合 ----
            //
            // 这些项进入同一个门禁，而不是作为"旁边的补充信息"。理由与
            // 第十二轮把 bizWalk 接进判据时相同：**发布属性不等于使用属性**。
            // 如果 RX 集合只被打印出来而不参与判定，那么"RX 整窗覆盖"就会
            // 再次退化成报告里的一句话，而不是一个会让 PASS 失败的条件。
            //
            // 【三个失败原因必须可分辨】
            //   门禁对"环被套圈"、"记录丢失"、"集合被预算截断"给出不同的
            //   token，因为它们对应完全不同的补救。若三者都写成
            //   `!rxSetComplete`，报告就只能说"集合不完整"，而这句话对
            //   定位问题没有用。所以它们从**核心给出的那一个 token** 派生
            //   （rxsetSetWhy），而不是各自再判一次——一份定义，三个投影。
            ev.rxSetPresent  = fM22b2Dma.rxsetPresent;
            ev.rxSetComplete = fM22b2Dma.rxsetComplete;
            ev.rxSetRanges   = fM22b2Dma.rxsetRanges;
            ev.rxSetWalked   = fM22b2Dma.rxsetWalked;
            ev.rxSetOk       = fM22b2Dma.rxsetOk;
            ev.rxSetFail     = fM22b2Dma.rxsetFail;
            ev.rxSetCapped   = fM22b2Dma.rxsetCapped;
            ev.rxSetGenStable = (fM22b2Dma.rxsetRingGen != 0 &&
                                 fM22b2Dma.rxsetRingGen ==
                                     fM22b2Dma.rxsetPreRingGen);
            {
                const char *sw = fM22b2Dma.rxsetSetWhy;
                const bool complete = (sw == nullptr);
                ev.rxSetNoGap  = complete ||
                                 !amdobs::obsStrEq(sw,
                                     "rearm-ring-lapped-past-baseline");
                ev.rxSetNoLoss = complete ||
                                 (!amdobs::obsStrEq(sw,
                                      "rearm-publication-truncated") &&
                                  !amdobs::obsStrEq(sw,
                                      "rearm-records-missing"));
            }
            ev.windowRan         = mainWindowRan;
            ev.windowValid       = winMain.valid;
            ev.eventLogOk        = evtResetOk && invAllOk;
            ev.commandsOk        = cmdOk;
            ev.restoreOk         = restoreOk;

            const char *gateWhy = amdobs::obsEvidenceGate(ev);
            fM22b2Dma.evidenceWhy = gateWhy;
            fM22b2Dma.evidenceOk = (gateWhy == nullptr);
            setProperty("m2-b2-evidence-gate",
                        gateWhy ? "REFUSED" : "PASS");
            setProperty("m2-b2-evidence-gate-why",
                        gateWhy ? gateWhy : "all-conditions-hold");
            setProperty("m2-b2-evidence-gate-text",
                        amdobs::obsEvidenceGateText(gateWhy));

            if (windowOk2 && gateWhy == nullptr && ringAttributed) {
                verdict = "PASS-CANDIDATE-controlled-chain";
                stage   = "19-controlled-chain-complete";
            } else if (!windowOk2) {
                // 边界或扫描质量不成立：连"这些完成在窗口内"都不能说。
                verdict = "INDETERMINATE-boundary-or-scan-not-exact";
                stage   = "19-indeterminate-boundary";
            } else if (gateWhy != nullptr) {
                // 证据资格不足。原因由 obsEvidenceGate() 给出，逐项可读，
                // 不再压缩成一个笼统的"没通过"。
                verdict = "INDETERMINATE-evidence-insufficient";
                stage   = "19-indeterminate-evidence";
            } else if (!fM22b2Dma.obsHasCompletePair) {
                // 关闭指针动了，但驱动侧记录里没有任何可核对的配对。
                verdict = "INDETERMINATE-no-driver-record-pair";
                stage   = "19-indeterminate-no-obs-pair";
            } else if (!fM22b2Dma.obsRecordsCoverWindow) {
                // 有配对，但快照没有覆盖整个窗口。这是第九轮的真实状态，
                // 而第九轮把它判成了通过。
                verdict = "INDETERMINATE-snapshot-does-not-cover-window";
                stage   = "19-indeterminate-obs-coverage";
            } else if (!fM22b2Dma.obsControlledBatchComplete) {
                // 覆盖成立，但本次有限批次没有全部完成。
                verdict = "INDETERMINATE-controlled-batch-incomplete";
                stage   = "19-indeterminate-batch";
            } else {
                // 证据齐全，但读环没能把完成归因到具体描述符。
                verdict = "INDETERMINATE-completions-not-attributed";
                stage   = "19-indeterminate-unattributed";
            }
        } else {
            // 窗口有效、无事件，**且没有完成证据**。这时什么都不能说：
            // 设备可能根本没工作，也可能工作了但统计没发布。
            verdict = "INDETERMINATE-no-events-no-dma-evidence";
            stage   = "19-indeterminate-no-dma";
        }

        setProperty("m2-b2-verdict", verdict);
        setProperty("m2-b2-stage", stage);
        fM22b2Dma.tRecoveryEnd = m2b2NowNS();
        setHexProperty(this, "m2-b2-t-recovery-end", fM22b2Dma.tRecoveryEnd);

        // 每个前置门的实际完成状态，逐项发布，便于独立复核。
        setProperty("m2-b2-stage-evt-reset", evtResetOk ? "yes" : "no");
        setProperty("m2-b2-stage-inv-all", invAllOk ? "yes" : "no");
        setProperty("m2-b2-stage-inv-dev", invDevOk ? "yes" : "no");
        setProperty("m2-b2-stage-inv-pages", invPagesOk ? "yes" : "no");
        setProperty("m2-b2-stage-control-done", controlDone ? "yes" : "no");
        setProperty("m2-b2-mode",
                    fM22b2SleepOnly ? "control-sleep-only" : "translation");

        // 首个失败阶段单独保留，不被上面的通用状态覆盖。
        if (firstFailStage) {
            setProperty("m2-b2-first-fail-stage", firstFailStage);
            if (firstFailReason) {
                setProperty("m2-b2-first-fail-reason", firstFailReason);
            }
        } else {
            setProperty("m2-b2-first-fail-stage", "none");
        }

        // 两个窗口"到底有没有执行过"的最终值。属性在采样时已写过一次，
        // 这里用判定实际所用的布尔量重写，保证记录与判定完全一致。
        setProperty("m2-b2-pre-window-ran", preWindowRan ? "yes" : "no");
        setProperty("m2-b2-main-window-ran", mainWindowRan ? "yes" : "no");
    }

    // ---- 第 20 步：资源处置 ----
    //
    // 只有 safeToFree 才释放；否则保持内存有效并记录后续处置要求。
    if (safeToFree) {
        map->release();
        md->release();
        ptMem->release();
        tbl->release();
        cmdBufMd->release();
        semMd->release();
        evtMd->release();
        setProperty("m2-b2-cleanup", "done");
    } else {
        // 不释放：硬件可能仍引用这些地址。宁可泄漏，也不要让 IOMMU
        // 继续按已被回收的内存翻译全系统 DMA（2026-10-30 就是这样
        // 连续两次启动死锁的）。
        setProperty("m2-b2-cleanup", "REFUSED-hardware-not-proven-idle");
        setProperty("m2-b2-cleanup-action",
            "memory intentionally retained; reboot required");
        setHexProperty(this, "m2-b2-leaked-pt-pa", (UInt64)ptPA);
        setHexProperty(this, "m2-b2-leaked-dt-pa", (UInt64)tblPA);
        setHexProperty(this, "m2-b2-leaked-cmd-pa", (UInt64)cmdPA);
        setHexProperty(this, "m2-b2-leaked-sem-pa", (UInt64)semPA);
        setHexProperty(this, "m2-b2-leaked-evt-pa", (UInt64)evtPA);
    }
}
// ---------------------------------------------------------------------------
// 【第十二轮】业务区间的走表：整段 [addr, addr+len)、每一叶、逐级原始 PTE
// ---------------------------------------------------------------------------
//
// 第十一轮的这条路径有三个假通过形态，全部在本轮修掉：
//
//   1. 只导出**第一页**的路径，却对整段声称 covered。一条 74 字节的报文
//      从叶末前 16 字节开始时会跨进下一叶，而下一叶的路径从未导出；
//      分析器手里只有一叶的原始 PTE，却看到"整段已覆盖"的结论。
//   2. 覆盖循环在解码失败时退回 4096 字节步长，可能整段跳过缺口。
//   3. `count >= kBizWalkMaxSegs` 时直接 return，既不计数也不降级，
//      于是"只走了一部分"与"全部合格"在输出上无法区分。
//
// 现在走表逻辑搬到 kext/amd_iommu_bizwalk_core.hpp，探针与 host 回归
// 编译**同一份**代码。这里只负责：取 DTE、给 readEntry 加边界、把结果
// 发布出去，以及把 expected/count/ok/fail/capped 四个数分别记账。
void org_example_AMDMapperProbe::m2b2WalkBusinessRanges(
        const volatile UInt64 *dte, UInt32 tgt,
        const volatile UInt64 *ptv, UInt64 ptBase, UInt64 ptBytes) {
    // 四个账各自独立。第十一轮的 bizWalkFail 在早退分支里被 ++ 过，随后
    // 又被函数末尾的局部 fail 覆盖——早退造成的失败因此从输出里消失了。
    // 现在任何一条失败路径都只改这四个成员，末尾不再有局部计数器。
    fM22b2Dma.bizWalkCount = 0;
    fM22b2Dma.bizWalkOk = 0;
    fM22b2Dma.bizWalkFail = 0;
    fM22b2Dma.bizWalkCapped = 0;

    // ---- 期望区间数：由**原始业务记录**推出 ----
    //
    // 这是"应走表多少段"的唯一来源，不是"实际走了多少段"。两者不等就说明
    // 有区间没走表，而第十一轮只判"走到的那些是否通过"。
    {
        UInt32 want = 0;
        const amdobs::ObsJoin &j0 = fM22b2ObsJoin;
        for (UInt32 k = 0; k < j0.bizCount; k++) {
            const amdobs::ObsBizOp &b = j0.biz[k];
            for (UInt32 s = 0; s < b.segCount && s < amdobs::OBS_MAX_SEGS; s++)
                want++;
            if (b.haveRx) want++;
        }
        fM22b2Dma.bizWalkExpected = want;
    }

    // ---- 起点：本次实验里**实际**写到设备表里的那条 DTE ----
    //
    // 第十轮的分析器有一项 "the root table is the one the DTE names"，判据是
    //
    //     pte_get('m2-b2-win0-pte0-table') == pte_get('m2-b2-dte-root')
    //         or pte_get('m2-b2-dte-root') is None
    //
    // 而 m2-b2-dte-root 这个属性**从来没有被发布过**，于是右边恒为真，
    // 这一项从未检查任何东西。现在改为从 dte[] 读回真实值，并把它一起
    // 导出，使"根表来自实际 DTE"成为可核对的事实而不是一句声明。
    const UInt64 dteRaw = (UInt64)dte[tgt * 4 + 0];
    const UInt64 dteMode =
        (dteRaw >> M2B2_DEV_ENTRY_MODE_SHIFT) & M2B2_DEV_ENTRY_MODE_MASK;
    const UInt64 dteRootPA = dteRaw & M2B2_PTE_ADDR_MASK;
    const bool dteValid = (dteRaw & DTE_V) != 0;
    const bool dteTranslate = (dteRaw & DTE_TV) != 0 && dteMode != 0;
    const unsigned rootLevel =
        (dteMode == 3) ? amdpte::LEVEL_1G
                       : (dteMode == 4 ? amdpte::LEVEL_512G : 0);

    setHexProperty(this, "m2-b2-bizwalk-dte-raw", dteRaw);
    setHexProperty(this, "m2-b2-bizwalk-dte-mode", dteMode);
    setHexProperty(this, "m2-b2-bizwalk-dte-root-pa", dteRootPA);
    setHexProperty(this, "m2-b2-bizwalk-root-level", (UInt64)rootLevel);
    setProperty("m2-b2-bizwalk-dte-state",
                !dteValid ? "not-valid"
                          : (!dteTranslate ? "passthrough-not-translating"
                                           : "translation"));

    if (!dteValid || !dteTranslate || rootLevel == 0) {
        // DTE 不处于可走表的状态：**每一个**期望区间都记为未证明。
        // 不是"0 个失败"，而是"期望 N 个、证明 0 个"。
        fM22b2Dma.bizWalkFail = fM22b2Dma.bizWalkExpected;
        setProperty("m2-b2-bizwalk", "SKIP-dte-not-translating");
        setProperty("m2-b2-bizwalk-why",
                    !dteValid ? "dte-not-valid"
                              : (!dteTranslate ? "dte-passthrough"
                                               : "dte-mode-unsupported"));
        setHexProperty(this, "m2-b2-bizwalk-expected",
                       (UInt64)fM22b2Dma.bizWalkExpected);
        setHexProperty(this, "m2-b2-bizwalk-count", 0);
        setHexProperty(this, "m2-b2-bizwalk-ok", 0);
        setHexProperty(this, "m2-b2-bizwalk-fail",
                       (UInt64)fM22b2Dma.bizWalkFail);
        setHexProperty(this, "m2-b2-bizwalk-capped", 0);
        return;
    }

    // ---- 读取页表内存的唯一入口 ----
    //
    // 只允许读本次分配的页表块，越界返回 0（0 的 PR=0，解码为 absent，
    // 不会伪造出叶子）。与第 17b 步同一套边界检查。
    const UInt64 ptEnd = ptBase + ptBytes;
    if (!ptv || ptEnd <= ptBase) {
        fM22b2Dma.bizWalkFail = fM22b2Dma.bizWalkExpected;
        setProperty("m2-b2-bizwalk", "SKIP-no-page-table-memory");
        setHexProperty(this, "m2-b2-bizwalk-expected",
                       (UInt64)fM22b2Dma.bizWalkExpected);
        setHexProperty(this, "m2-b2-bizwalk-count", 0);
        setHexProperty(this, "m2-b2-bizwalk-ok", 0);
        setHexProperty(this, "m2-b2-bizwalk-fail",
                       (UInt64)fM22b2Dma.bizWalkFail);
        setHexProperty(this, "m2-b2-bizwalk-capped", 0);
        return;
    }

    auto readEntry = [&](UInt64 tablePA, unsigned index) -> UInt64 {
        if (tablePA < ptBase || tablePA >= ptEnd) return 0;
        const UInt64 byteOff = tablePA - ptBase;
        if (byteOff + 8ULL * (UInt64)index + 8ULL > ptBytes) return 0;
        return (UInt64)ptv[byteOff / 8 + index];
    };

    // ---- 逐请求、逐方向、逐段 ----
    const amdobs::ObsJoin &j = fM22b2ObsJoin;
    UInt32 count = 0;

    auto recordRange = [&](UInt32 reqId, UInt8 isRx, UInt8 segIdx,
                           UInt64 addr, UInt32 len) {
        // 容量上限：**记一笔降级**，不是静默丢弃。第十一轮在这里 return，
        // 于是被丢掉的区间在输出上不存在。
        if (count >= fM22b2Dma.kBizWalkMaxSegs) {
            fM22b2Dma.bizWalkCapped++;
            return;
        }

        auto &w = fM22b2Dma.bizWalk[count];
        w.reqId = reqId;
        w.isRx = isRx;
        w.segIndex = segIdx;
        w.addr = addr;
        w.len = len;
        w.rootPA = dteRootPA;
        w.rootLevel = rootLevel;
        w.dteRaw = dteRaw;
        w.leafPA = 0;
        w.leafSize = 0;
        w.leafLevel = 0;
        w.pagesChecked = 0;
        w.pagesBad = 0;
        w.overflow = 0;
        w.capped = 0;
        w.leafCount = 0;
        w.depth = 0;
        w.covered = 0;
        w.permOk = 0;
        w.why = "ok";

        // 同一份核心代码：探针与 host 回归都跑 amdbw::walkRange()。
        amdbw::RangeResult r;
        amdbw::walkRange(readEntry, rootLevel, dteRootPA, addr, len,
                         isRx != 0, r);

        w.overflow  = r.overflow ? 1 : 0;
        w.capped    = r.capped ? 1 : 0;
        w.covered   = r.covered ? 1 : 0;
        w.permOk    = r.permOk ? 1 : 0;
        w.leafCount = (UInt8)(r.leafCount > 255 ? 255 : r.leafCount);
        w.pagesChecked = r.leavesChecked;
        w.pagesBad     = r.leavesBad;
        w.why = r.why ? r.why : "ok";

        if (r.leafCount > 0) {
            const amdbw::Path &p0 = r.path[0];
            w.depth = (UInt8)(p0.depth > M22b2DmaObs::kBizWalkMaxLevels
                                  ? M22b2DmaObs::kBizWalkMaxLevels : p0.depth);
            w.leafPA = p0.leafPA;
            w.leafSize = p0.leafSize;
            w.leafLevel = p0.leafLevel;
        }
        for (UInt32 li = 0; li < r.leafCount && li < amdbw::kMaxLeaves; li++) {
            const amdbw::Path &p = r.path[li];
            auto &dst = w.path[li];
            dst.depth = (UInt8)(p.depth > M22b2DmaObs::kBizWalkMaxLevels
                                    ? M22b2DmaObs::kBizWalkMaxLevels : p.depth);
            dst.leafPA = p.leafPA;
            dst.leafSize = p.leafSize;
            dst.leafLevel = p.leafLevel;
            dst.coversFrom = p.coversFrom;
            dst.coversBytes = p.coversBytes;
            for (UInt32 k = 0; k < dst.depth; k++) {
                dst.tablePA[k] = p.table[k];
                dst.index[k] = p.index[k];
                dst.level[k] = p.level[k];
                dst.pte[k] = p.pte[k];
            }
        }

        if (r.ok)                 fM22b2Dma.bizWalkOk++;
        else if (r.capped)        fM22b2Dma.bizWalkCapped++;
        else                      fM22b2Dma.bizWalkFail++;
        count++;
    };

    for (UInt32 k = 0; k < j.bizCount; k++) {
        const amdobs::ObsBizOp &b = j.biz[k];
        if (b.segCount == 0) continue;
        for (UInt32 s = 0; s < b.segCount && s < amdobs::OBS_MAX_SEGS; s++) {
            recordRange(b.reqId, 0, (UInt8)s, b.segAddr[s], b.segLen[s]);
        }
        if (b.haveRx) {
            recordRange(b.reqId, 1, 0, b.rxAddr, b.rxLen);
        }
    }

    // 走到这里时 count/ok/fail/capped 已经是最终值；**不再有**局部 fail
    // 覆盖成员计数的机会。
    fM22b2Dma.bizWalkCount = count;

    setHexProperty(this, "m2-b2-bizwalk-expected",
                   (UInt64)fM22b2Dma.bizWalkExpected);
    setHexProperty(this, "m2-b2-bizwalk-count", (UInt64)count);
    setHexProperty(this, "m2-b2-bizwalk-ok", (UInt64)fM22b2Dma.bizWalkOk);
    setHexProperty(this, "m2-b2-bizwalk-fail", (UInt64)fM22b2Dma.bizWalkFail);
    setHexProperty(this, "m2-b2-bizwalk-capped",
                   (UInt64)fM22b2Dma.bizWalkCapped);
    setProperty("m2-b2-bizwalk",
                count == 0 ? "SKIP-no-business-ranges"
                           : ((fM22b2Dma.bizWalkFail == 0 &&
                               fM22b2Dma.bizWalkCapped == 0)
                                  ? "all-covered" : "SOME-NOT-COVERED"));

    // ---- 逐段发布 ----
    //
    // 每段的每一叶的每一级都发布：表物理地址、索引、级别、原始 PTE。这是
    // "这条业务 DMA 区间经过了哪条真实页表路径"的唯一可复核形式；分析器
    // 据此独立解码，不依赖这里的任何结论字符串。
    //
    // 旧属性名（m2-b2-bw%d-pte%d-*）保留为**第一叶**的别名，这样第十一轮
    // 的归档仍然可被同一分析器读出；跨叶区间额外有 m2-b2-bw%d-leaf%d-*。
    for (UInt32 i = 0; i < count; i++) {
        const auto &w = fM22b2Dma.bizWalk[i];
        char k[64];
        snprintf(k, sizeof(k), "m2-b2-bw%u-req", (unsigned)i);
        setHexProperty(this, k, (UInt64)w.reqId);
        snprintf(k, sizeof(k), "m2-b2-bw%u-dir", (unsigned)i);
        setProperty(k, w.isRx ? "rx" : "tx");
        snprintf(k, sizeof(k), "m2-b2-bw%u-seg", (unsigned)i);
        setHexProperty(this, k, (UInt64)w.segIndex);
        snprintf(k, sizeof(k), "m2-b2-bw%u-addr", (unsigned)i);
        setHexProperty(this, k, w.addr);
        snprintf(k, sizeof(k), "m2-b2-bw%u-len", (unsigned)i);
        setHexProperty(this, k, (UInt64)w.len);
        snprintf(k, sizeof(k), "m2-b2-bw%u-depth", (unsigned)i);
        setHexProperty(this, k, (UInt64)w.depth);
        snprintf(k, sizeof(k), "m2-b2-bw%u-leaf-pa", (unsigned)i);
        setHexProperty(this, k, w.leafPA);
        snprintf(k, sizeof(k), "m2-b2-bw%u-leaf-size", (unsigned)i);
        setHexProperty(this, k, w.leafSize);
        snprintf(k, sizeof(k), "m2-b2-bw%u-leaf-level", (unsigned)i);
        setHexProperty(this, k, (UInt64)w.leafLevel);
        snprintf(k, sizeof(k), "m2-b2-bw%u-covered", (unsigned)i);
        setProperty(k, w.covered ? "yes" : "no");
        snprintf(k, sizeof(k), "m2-b2-bw%u-perm-ok", (unsigned)i);
        setProperty(k, w.permOk ? "yes" : "no");
        snprintf(k, sizeof(k), "m2-b2-bw%u-pages", (unsigned)i);
        setHexProperty(this, k, (UInt64)w.pagesChecked);
        snprintf(k, sizeof(k), "m2-b2-bw%u-pages-bad", (unsigned)i);
        setHexProperty(this, k, (UInt64)w.pagesBad);
        snprintf(k, sizeof(k), "m2-b2-bw%u-why", (unsigned)i);
        setProperty(k, w.why);
        snprintf(k, sizeof(k), "m2-b2-bw%u-overflow", (unsigned)i);
        setProperty(k, w.overflow ? "yes" : "no");
        snprintf(k, sizeof(k), "m2-b2-bw%u-capped", (unsigned)i);
        setProperty(k, w.capped ? "yes" : "no");
        // 走表起点：与 DTE 同源，使"根表来自实际 DTE"可核对
        snprintf(k, sizeof(k), "m2-b2-bw%u-root-pa", (unsigned)i);
        setHexProperty(this, k, w.rootPA);
        snprintf(k, sizeof(k), "m2-b2-bw%u-root-level", (unsigned)i);
        setHexProperty(this, k, (UInt64)w.rootLevel);
        snprintf(k, sizeof(k), "m2-b2-bw%u-dte", (unsigned)i);
        setHexProperty(this, k, w.dteRaw);

        // 叶数：跨叶区间必须逐叶导出，否则"整段已覆盖"无法核对。
        snprintf(k, sizeof(k), "m2-b2-bw%u-leaves", (unsigned)i);
        setHexProperty(this, k, (UInt64)w.leafCount);

        for (UInt32 li = 0; li < w.leafCount; li++) {
            const auto &p = w.path[li];
            snprintf(k, sizeof(k), "m2-b2-bw%u-leaf%u-pa", (unsigned)i,
                     (unsigned)li);
            setHexProperty(this, k, p.leafPA);
            snprintf(k, sizeof(k), "m2-b2-bw%u-leaf%u-size", (unsigned)i,
                     (unsigned)li);
            setHexProperty(this, k, p.leafSize);
            snprintf(k, sizeof(k), "m2-b2-bw%u-leaf%u-from", (unsigned)i,
                     (unsigned)li);
            setHexProperty(this, k, p.coversFrom);
            snprintf(k, sizeof(k), "m2-b2-bw%u-leaf%u-bytes", (unsigned)i,
                     (unsigned)li);
            setHexProperty(this, k, p.coversBytes);
            for (UInt32 L = 0; L < p.depth; L++) {
                snprintf(k, sizeof(k), "m2-b2-bw%u-leaf%u-pte%u-table",
                         (unsigned)i, (unsigned)li, (unsigned)L);
                setHexProperty(this, k, p.tablePA[L]);
                snprintf(k, sizeof(k), "m2-b2-bw%u-leaf%u-pte%u-index",
                         (unsigned)i, (unsigned)li, (unsigned)L);
                setHexProperty(this, k, (UInt64)p.index[L]);
                snprintf(k, sizeof(k), "m2-b2-bw%u-leaf%u-pte%u-level",
                         (unsigned)i, (unsigned)li, (unsigned)L);
                setHexProperty(this, k, (UInt64)p.level[L]);
                snprintf(k, sizeof(k), "m2-b2-bw%u-leaf%u-pte%u",
                         (unsigned)i, (unsigned)li, (unsigned)L);
                setHexProperty(this, k, p.pte[L]);
            }
        }

        // 旧名别名（= 第一叶），只覆盖第一叶的级数。
        if (w.leafCount > 0) {
            const auto &p = w.path[0];
            for (UInt32 L = 0; L < p.depth; L++) {
                snprintf(k, sizeof(k), "m2-b2-bw%u-pte%u-table", (unsigned)i,
                         (unsigned)L);
                setHexProperty(this, k, p.tablePA[L]);
                snprintf(k, sizeof(k), "m2-b2-bw%u-pte%u-index", (unsigned)i,
                         (unsigned)L);
                setHexProperty(this, k, (UInt64)p.index[L]);
                snprintf(k, sizeof(k), "m2-b2-bw%u-pte%u-level", (unsigned)i,
                         (unsigned)L);
                setHexProperty(this, k, (UInt64)p.level[L]);
                snprintf(k, sizeof(k), "m2-b2-bw%u-pte%u", (unsigned)i,
                         (unsigned)L);
                setHexProperty(this, k, p.pte[L]);
            }
        }
    }
}


