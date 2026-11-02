// AMDMapperProbeTable.cpp -- M2-2a-2/2a-3 device table, enable, cmd channel
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

// ===== AMDMapperProbeTable.cpp (original lines 1442..1662) =====

void org_example_AMDMapperProbe::runM22bTableProbe() {
    setProperty("m2-2b-stage", "0-start");

    if (!parseTableBootArg()) {
        setProperty("m2-2b-gate", "closed");
        setProperty("m2-2b-stage", "1-skipped-no-bootarg");
        return;
    }
    setProperty("m2-2b-gate", "open");

    // ---- 第 1 步：尝试分配物理连续内存 ----
    //
    // withCapacity(capacity, direction, withContiguousMemory=true)
    // 第三个参数是关键：它要求底层内存物理连续。
    IOBufferMemoryDescriptor *buf = nullptr;
    UInt64 tableSize = 0;

    for (int attempt = 0; attempt < 2; attempt++) {
        UInt64 want = (attempt == 0) ? M22B_TABLE_SIZE_FULL : M22B_TABLE_SIZE_MIN;
        IOBufferMemoryDescriptor *b =
            IOBufferMemoryDescriptor::withCapacity(
                (vm_size_t)want, kIODirectionNone, true);
        if (b) {
            buf = b;
            tableSize = want;
            break;
        }
        // 记录失败，继续试更小的
        if (attempt == 0) setProperty("m2-2b-2mib", "FAILED");
    }

    if (!buf) {
        setProperty("m2-2b-verdict", "FAIL-no-contiguous-memory");
        setProperty("m2-2b-stage", "2-FAIL-alloc");
        return;
    }
    if (tableSize == M22B_TABLE_SIZE_FULL) {
        setProperty("m2-2b-2mib", "ok");
    }
    setHexProperty(this, "m2-2b-tablesize", tableSize);

    // ---- 第 2 步：取物理地址，确认真的连续 ----
    //
    // withContiguousMemory=true 应当保证连续，但必须实测确认：
    // 取 offset 0 与最后一个 DTE 的物理地址，两者之差必须等于
    // (count-1)*32。若不等，说明并非真的连续，绝不能交给硬件。
    UInt32 dteCount = (UInt32)(tableSize / M22B_DTE_SIZE);
    setHexProperty(this, "m2-2b-dtecount", dteCount);

    IOByteCount segLen = 0;
    addr64_t paBase = buf->getPhysicalSegment(0, &segLen, kIOMemoryMapperNone);
    if (!paBase) {
        setProperty("m2-2b-verdict", "FAIL-no-physical-address");
        setProperty("m2-2b-stage", "3-FAIL-pa");
        buf->release();
        return;
    }
    setHexProperty(this, "m2-2b-pa", (UInt64)paBase);
    setHexProperty(this, "m2-2b-seglen", (UInt64)segLen);

    // 段长必须覆盖整张表
    bool contiguous = ((UInt64)segLen >= tableSize);
    setProperty("m2-2b-contiguous", contiguous ? "yes" : "no");
    if (!contiguous) {
        setProperty("m2-2b-verdict", "FAIL-not-contiguous");
        setProperty("m2-2b-stage", "3-FAIL-seglen");
        buf->release();
        return;
    }

    // 基址必须 4 KiB 对齐（硬件要求，size 编码以 4 KiB 为单位）
    bool aligned = (((UInt64)paBase & 0xFFF) == 0);
    setProperty("m2-2b-aligned", aligned ? "yes" : "no");
    if (!aligned) {
        setProperty("m2-2b-verdict", "FAIL-not-page-aligned");
        setProperty("m2-2b-stage", "3-FAIL-align");
        buf->release();
        return;
    }

    // ---- 第 3 步：填表 ----
    //
    // 全部 DTE 填「直通」：V=1, TV=1, IR=1, IW=1, DOMID=0, MODE=0, HOST_TRP=0。
    // 与 Linux set_dte_passthrough() 一致（iommu.c:2164-2173）。
    //
    // 为什么 DOMID 用 0：直通域不需要真实的域隔离；Linux 用的是
    // identity_domain.id，但那个值取决于它的分配器。我们用 0 表示
    // "直通域"，语义清晰且不与他人冲突（IOMMU 关闭，不会被消费）。
    volatile UInt64 *dte = (volatile UInt64 *)buf->getBytesNoCopy();
    if (!dte) {
        setProperty("m2-2b-verdict", "FAIL-no-virtual-address");
        setProperty("m2-2b-stage", "4-FAIL-va");
        buf->release();
        return;
    }

    const UInt64 passthrough0 = DTE_V | DTE_TV | DTE_IR | DTE_IW;
    const UInt64 passthrough1 = 0;   // DOMID = 0

    for (UInt32 i = 0; i < dteCount; i++) {
        dte[i * 4 + 0] = passthrough0;   // data[0]
        dte[i * 4 + 1] = passthrough1;   // data[1]
        dte[i * 4 + 2] = 0;              // data[2]
        dte[i * 4 + 3] = 0;              // data[3]
    }
    setProperty("m2-2b-filled", "yes");
    setHexProperty(this, "m2-2b-dte0", passthrough0);

    // 抽查第一个与最后一个 DTE，确认写入生效
    UInt64 first0 = dte[0];
    UInt64 last0  = dte[(dteCount - 1) * 4];
    setHexProperty(this, "m2-2b-firstdte", first0);
    setHexProperty(this, "m2-2b-lastdte", last0);
    bool fillOk = (first0 == passthrough0 && last0 == passthrough0);
    setProperty("m2-2b-fillcheck", fillOk ? "ok" : "MISMATCH");

    // ---- 第 4 步：写 MMIO_DEV_TABLE_OFFSET ----
    //
    // 编码：entry = pa | ((size >> 12) - 1)
    //   Linux init.c:401-404：
    //     entry = iommu_virt_to_phys(dev_table);
    //     entry |= (dev_table_size >> 12) - 1;
    //
    // 2 MiB → (0x200000>>12)-1 = 0x1FF
    // 4 KiB → (0x1000>>12)-1 = 0x0
    UInt64 sizeCode = (tableSize >> 12) - 1;
    UInt64 entry = ((UInt64)paBase & ~0xFFFULL) | sizeCode;
    setHexProperty(this, "m2-2b-sizecode", sizeCode);
    setHexProperty(this, "m2-2b-entry", entry);

    // 映射 MMIO（可写）
    IOMemoryDescriptor *md =
        IOMemoryDescriptor::withPhysicalAddress(
            (IOPhysicalAddress)M21_MMIO_BASE,
            (IOByteCount)M21_MMIO_LEN,
            kIODirectionNone);
    if (!md) {
        setProperty("m2-2b-verdict", "FAIL-mmio-md");
        setProperty("m2-2b-stage", "5-FAIL-mmio-md");
        buf->release();
        return;
    }

    IOMemoryMap *map = md->map(kIOMapInhibitCache | kIOMapAnywhere);
    if (!map) {
        setProperty("m2-2b-verdict", "FAIL-mmio-map");
        setProperty("m2-2b-stage", "5-FAIL-mmio-map");
        md->release();
        buf->release();
        return;
    }

    volatile UInt8 *base = (volatile UInt8 *)map->getVirtualAddress();

    // 写前身份复验（同 M2-2a-1 的理由）
    UInt64 efr = mmioRead64(base, M21_OFF_EXT_FEAT);
    if (efr != M21_EFR_EXPECTED) {
        setProperty("m2-2b-verdict", "FAIL-efr-mismatch");
        setProperty("m2-2b-stage", "6-aborted-identity");
        map->release();
        md->release();
        buf->release();
        return;
    }
    setProperty("m2-2b-identity", "confirmed");

    UInt64 origEntry = mmioRead64(base, M21_OFF_DEV_TABLE);
    setHexProperty(this, "m2-2b-orig-entry", origEntry);

    mmioWrite64(base, M21_OFF_DEV_TABLE, entry);
    UInt64 readback = mmioRead64(base, M21_OFF_DEV_TABLE);
    setHexProperty(this, "m2-2b-readback", readback);

    // 判据用掩码（M2-2a-1 的教训：bit 63:52 是保留位）
    UInt64 expected = entry & 0x000FFFFFFFFFFFFFULL;
    setHexProperty(this, "m2-2b-expected", expected);
    bool tableOk = (readback == expected);
    setProperty("m2-2b-tableset", tableOk ? "yes" : "no");

    // ---- 第 5 步：确认 IOMMU 仍然关闭 ----
    //
    // 这是本步骤最重要的安全检查：我们只写了 DEV_TABLE，绝不能碰到 CONTROL。
    UInt64 ctl = mmioRead64(base, M21_OFF_CONTROL);
    setHexProperty(this, "m2-2b-control", ctl);
    if (ctl & 0x1ULL) {
        setProperty("m2-2b-iommu-enabled", "YES-unexpected");
    } else {
        setProperty("m2-2b-iommu-enabled", "no-as-expected");
    }

    // ---- 第 6 步：恢复 ----
    //
    // 因为 IOMMU 没使能，这张表不会被硬件读取。但为了保持
    // "进入时什么样、离开时什么样"，把寄存器恢复原值（0）。
    // 内存由 buf 持有，随 buf->release() 释放。
    mmioWrite64(base, M21_OFF_DEV_TABLE, origEntry);
    UInt64 restored = mmioRead64(base, M21_OFF_DEV_TABLE);
    setHexProperty(this, "m2-2b-restored", restored);
    setProperty("m2-2b-restore", (restored == origEntry) ? "ok" : "MISMATCH");

    // ---- 判定 ----
    if (fillOk && tableOk && (restored == origEntry)) {
        setProperty("m2-2b-verdict", "PASS-table-built");
        setProperty("m2-2b-stage", "7-complete");
    } else if (!fillOk) {
        setProperty("m2-2b-verdict", "FAIL-fill");
        setProperty("m2-2b-stage", "7-complete-fill-failed");
    } else if (!tableOk) {
        setProperty("m2-2b-verdict", "FAIL-table-register");
        setProperty("m2-2b-stage", "7-complete-register-failed");
    } else {
        setProperty("m2-2b-verdict", "FAIL-restore");
        setProperty("m2-2b-stage", "7-complete-restore-failed");
    }

    map->release();
    md->release();
    buf->release();
    setProperty("m2-2b-cleanup", "done");
}

// ===== AMDMapperProbeTable.cpp (original lines 1664..1701) =====
// ------------------------------------ M2-2a-3：短窗口使能测试（最高风险）

// ============================ 这一步做什么 ============================
//
// 完整走一遍 Linux early_enable_iommu() 的使能序列，但**在极短窗口后立即禁用**：
//
//   1. 建设备表（全直通，与 M2-2a-2 相同）
//   2. 写 MMIO_DEV_TABLE_OFFSET
//   3. 分配命令缓冲（8 KiB），写 MMIO_CMD_BUF_OFFSET（基址 | MMIO_CMD_SIZE_512）
//   4. 复位 cmd head/tail 为 0
//   5. 置 CONTROL_CMDBUF_EN
//   6. 置 CONTROL_IOMMU_EN          ← 从这一刻起，全系统 DMA 走设备表
//   7. 立刻读 MMIO_STATUS，确认 IOMMU 真的起来了
//   8. 立刻清 CONTROL_IOMMU_EN      ← 窗口关闭
//   9. 确认 IOMMU 已回到关闭状态
//
// 为什么做短窗口而不是长期使能：
//   使能动作本身可能立即崩溃（设备表地址错、size 编码错、命令缓冲未就绪）。
//   如果短窗口就崩，说明配置有根本问题，不必冒险长时间运行。
//   如果短窗口通过，才谈"使能后长期运行"。
//
// ============================ 为什么不做事件日志 ============================
//
// Linux 的 early_enable_iommu() 顺序里**没有** enable_event_buffer()。
// 事件日志是在 init_iommu_one_late() 里单独开的，晚于 IOMMU 使能。
// 本轮也不开：事件日志只影响故障记录，不影响翻译本身。
// 少做一件事，就少一个可能出错的环节。
//
// ============================ 关键寄存器 ============================
//
// MMIO_CMD_BUF_OFFSET (0x08) 的编码与 DEV_TABLE 类似但**不同**：
//   Linux: entry = phys(cmd_buf) | MMIO_CMD_SIZE_512
//   MMIO_CMD_SIZE_512 = 0x9ULL << 56      ← 高位！不是低位
//   命令缓冲固定 512 项 × 16 B = 8 KiB
//
// 这一点容易搞错：DEV_TABLE 的 size 编码在低位（bit 0..11），
// 而 CMD_BUF 的 size 编码在 bit 56..59。写错了硬件会找不到命令缓冲。
#define M23_OFF_CMD_BUF     0x0008

// ===== AMDMapperProbeTable.cpp (original lines 1706..1914) =====

void org_example_AMDMapperProbe::runM23EnableProbe() {
    setProperty("m2-3-stage", "0-start");

    if (!parseEnableBootArg()) {
        setProperty("m2-3-gate", "closed");
        setProperty("m2-3-stage", "1-skipped-no-bootarg");
        return;
    }
    setProperty("m2-3-gate", "open");

    // ---- 第 1 步：分配设备表（2 MiB，全直通）----
    IOBufferMemoryDescriptor *tbl =
        IOBufferMemoryDescriptor::withCapacity(
            (vm_size_t)M22B_TABLE_SIZE_FULL, kIODirectionNone, true);
    if (!tbl) {
        setProperty("m2-3-verdict", "FAIL-table-alloc");
        setProperty("m2-3-stage", "2-FAIL-table");
        return;
    }

    IOByteCount tblSegLen = 0;
    addr64_t tblPA = tbl->getPhysicalSegment(0, &tblSegLen, kIOMemoryMapperNone);
    if (!tblPA || (UInt64)tblSegLen < M22B_TABLE_SIZE_FULL ||
        ((UInt64)tblPA & 0xFFF)) {
        setProperty("m2-3-verdict", "FAIL-table-memory");
        setProperty("m2-3-stage", "2-FAIL-table-mem");
        tbl->release();
        return;
    }
    setHexProperty(this, "m2-3-tbl-pa", (UInt64)tblPA);

    // 填全直通 DTE
    volatile UInt64 *dte = (volatile UInt64 *)tbl->getBytesNoCopy();
    UInt32 dteCount = (UInt32)(M22B_TABLE_SIZE_FULL / M22B_DTE_SIZE);
    const UInt64 pt0 = DTE_V | DTE_TV | DTE_IR | DTE_IW;
    for (UInt32 i = 0; i < dteCount; i++) {
        dte[i * 4 + 0] = pt0;
        dte[i * 4 + 1] = 0;
        dte[i * 4 + 2] = 0;
        dte[i * 4 + 3] = 0;
    }
    setProperty("m2-3-table", "filled");

    // ---- 第 2 步：分配命令缓冲（8 KiB）----
    IOBufferMemoryDescriptor *cmdbuf =
        IOBufferMemoryDescriptor::withCapacity(
            (vm_size_t)M23_CMD_BUF_SIZE, kIODirectionNone, true);
    if (!cmdbuf) {
        setProperty("m2-3-verdict", "FAIL-cmdbuf-alloc");
        setProperty("m2-3-stage", "3-FAIL-cmdbuf");
        tbl->release();
        return;
    }

    IOByteCount cmdSegLen = 0;
    addr64_t cmdPA = cmdbuf->getPhysicalSegment(0, &cmdSegLen, kIOMemoryMapperNone);
    if (!cmdPA || (UInt64)cmdSegLen < M23_CMD_BUF_SIZE) {
        setProperty("m2-3-verdict", "FAIL-cmdbuf-memory");
        setProperty("m2-3-stage", "3-FAIL-cmdbuf-mem");
        cmdbuf->release();
        tbl->release();
        return;
    }
    setHexProperty(this, "m2-3-cmd-pa", (UInt64)cmdPA);

    // 清零命令缓冲（避免残留垃圾被硬件当成命令执行）
    {
        volatile UInt64 *cb = (volatile UInt64 *)cmdbuf->getBytesNoCopy();
        for (UInt32 i = 0; i < (M23_CMD_BUF_SIZE / 8); i++) cb[i] = 0;
    }
    setProperty("m2-3-cmdbuf", "zeroed");

    // ---- 第 3 步：映射 MMIO ----
    IOMemoryDescriptor *md =
        IOMemoryDescriptor::withPhysicalAddress(
            (IOPhysicalAddress)M21_MMIO_BASE,
            (IOByteCount)M21_MMIO_LEN,
            kIODirectionNone);
    if (!md) {
        setProperty("m2-3-verdict", "FAIL-mmio-md");
        setProperty("m2-3-stage", "4-FAIL-md");
        cmdbuf->release();
        tbl->release();
        return;
    }

    IOMemoryMap *map = md->map(kIOMapInhibitCache | kIOMapAnywhere);
    if (!map) {
        setProperty("m2-3-verdict", "FAIL-mmio-map");
        setProperty("m2-3-stage", "4-FAIL-map");
        md->release();
        cmdbuf->release();
        tbl->release();
        return;
    }
    volatile UInt8 *base = (volatile UInt8 *)map->getVirtualAddress();

    // 写前身份复验
    if (mmioRead64(base, M21_OFF_EXT_FEAT) != M21_EFR_EXPECTED) {
        setProperty("m2-3-verdict", "FAIL-efr-mismatch");
        setProperty("m2-3-stage", "5-aborted-identity");
        map->release(); md->release(); cmdbuf->release(); tbl->release();
        return;
    }
    setProperty("m2-3-identity", "confirmed");

    // ---- 第 4 步：记录原状态，供恢复 ----
    UInt64 origDT    = mmioRead64(base, M21_OFF_DEV_TABLE);
    UInt64 origCmd   = mmioRead64(base, M23_OFF_CMD_BUF);
    UInt64 origCtrl  = mmioRead64(base, M21_OFF_CONTROL);
    setHexProperty(this, "m2-3-orig-devicetable", origDT);
    setHexProperty(this, "m2-3-orig-cmdbuf", origCmd);
    setHexProperty(this, "m2-3-orig-control", origCtrl);

    // 安全前提：进来时 IOMMU 必须是关的。若不是，立即中止。
    if (origCtrl & M23_CTRL_IOMMU_EN) {
        setProperty("m2-3-verdict", "ABORT-already-enabled");
        setProperty("m2-3-stage", "6-aborted-pre-enabled");
        map->release(); md->release(); cmdbuf->release(); tbl->release();
        return;
    }

    // ---- 第 5 步：写设备表与命令缓冲寄存器 ----
    UInt64 dtEntry = ((UInt64)tblPA & ~0xFFFULL) |
                     ((M22B_TABLE_SIZE_FULL >> 12) - 1);
    UInt64 cmdEntry = ((UInt64)cmdPA & ~0xFFFULL) | M23_CMD_SIZE_CODE;

    setHexProperty(this, "m2-3-devicetable-entry", dtEntry);
    setHexProperty(this, "m2-3-cmdbuf-entry", cmdEntry);

    mmioWrite64(base, M21_OFF_DEV_TABLE, dtEntry);
    mmioWrite64(base, M23_OFF_CMD_BUF, cmdEntry);
    setProperty("m2-3-regs", "written");

    // 复位 cmd head/tail（Linux amd_iommu_reset_cmd_buffer）
    mmioWrite64(base, 0x2000, 0);   // MMIO_CMD_HEAD
    mmioWrite64(base, 0x2008, 0);   // MMIO_CMD_TAIL

    // ---- 第 6 步：使能命令缓冲 ----
    //
    // 用 read-modify-write，保留固件预设位（COHERENT_EN/EPH_EN 等）。
    UInt64 ctrl = mmioRead64(base, M21_OFF_CONTROL);
    ctrl |= M23_CTRL_CMDBUF_EN;
    mmioWrite64(base, M21_OFF_CONTROL, ctrl);
    UInt64 ctrlAfterCmd = mmioRead64(base, M21_OFF_CONTROL);
    setHexProperty(this, "m2-3-control-after-cmdbuf", ctrlAfterCmd);
    setProperty("m2-3-cmdbuf-enabled",
        (ctrlAfterCmd & M23_CTRL_CMDBUF_EN) ? "yes" : "no");

    // ---- 第 7 步：使能 IOMMU —— 窗口打开 ----
    ctrl = mmioRead64(base, M21_OFF_CONTROL);
    ctrl |= M23_CTRL_IOMMU_EN;
    mmioWrite64(base, M21_OFF_CONTROL, ctrl);

    UInt64 ctrlEnabled = mmioRead64(base, M21_OFF_CONTROL);
    setHexProperty(this, "m2-3-control-enabled", ctrlEnabled);
    bool reallyEnabled = (ctrlEnabled & M23_CTRL_IOMMU_EN) != 0;
    setProperty("m2-3-enabled", reallyEnabled ? "yes" : "no");

    // 读状态寄存器（只读，无副作用）
    UInt32 status = mmioRead32(base, M21_OFF_STATUS);
    setHexProperty(this, "m2-3-status", (UInt64)status);

    // ---- 第 8 步：立即禁用 —— 窗口关闭 ----
    //
    // 无论上面读到什么，这一步都必须执行。
    ctrl = mmioRead64(base, M21_OFF_CONTROL);
    ctrl &= ~M23_CTRL_IOMMU_EN;
    mmioWrite64(base, M21_OFF_CONTROL, ctrl);

    UInt64 ctrlDisabled = mmioRead64(base, M21_OFF_CONTROL);
    setHexProperty(this, "m2-3-control-disabled", ctrlDisabled);
    bool reallyDisabled = (ctrlDisabled & M23_CTRL_IOMMU_EN) == 0;
    setProperty("m2-3-disabled", reallyDisabled ? "yes" : "no");

    // ---- 第 9 步：恢复全部寄存器 ----
    mmioWrite64(base, M21_OFF_DEV_TABLE, origDT);
    mmioWrite64(base, M23_OFF_CMD_BUF, origCmd);
    // 命令缓冲使能位也恢复（先关再写，避免硬件还指着已释放的内存）
    ctrl = mmioRead64(base, M21_OFF_CONTROL);
    ctrl &= ~M23_CTRL_CMDBUF_EN;
    ctrl |= (origCtrl & M23_CTRL_CMDBUF_EN);
    mmioWrite64(base, M21_OFF_CONTROL, ctrl);

    UInt64 finalCtrl = mmioRead64(base, M21_OFF_CONTROL);
    setHexProperty(this, "m2-3-final-control", finalCtrl);
    setHexProperty(this, "m2-3-final-devicetable",
                   mmioRead64(base, M21_OFF_DEV_TABLE));
    setHexProperty(this, "m2-3-final-cmdbuf", mmioRead64(base, M23_OFF_CMD_BUF));

    // ---- 判定 ----
    if (reallyEnabled && reallyDisabled) {
        setProperty("m2-3-verdict", "PASS-enable-disable-window");
        setProperty("m2-3-stage", "7-complete");
    } else if (!reallyEnabled) {
        setProperty("m2-3-verdict", "FAIL-did-not-enable");
        setProperty("m2-3-stage", "7-complete-not-enabled");
    } else {
        setProperty("m2-3-verdict", "FAIL-could-not-disable");
        setProperty("m2-3-stage", "7-complete-still-enabled");
    }

    map->release();
    md->release();
    cmdbuf->release();
    tbl->release();
    setProperty("m2-3-cleanup", "done");
}

// ===== AMDMapperProbeTable.cpp (original lines 1965..2211) =====
void org_example_AMDMapperProbe::runM2b1CmdProbe() {
    setProperty("m2-b1-stage", "0-start");

    if (!parseCmdBootArg()) {
        setProperty("m2-b1-gate", "closed");
        setProperty("m2-b1-stage", "1-skipped-no-bootarg");
        return;
    }
    setProperty("m2-b1-gate", "open");

    // ---- 第 1 步：分配三块内存 ----
    //   tbl     : 2 MiB 设备表（全直通）
    //   cmdbuf  : 8 KiB 命令缓冲
    //   cwwb    : 4 KiB 完成信号（cmd_sem）
    IOBufferMemoryDescriptor *tbl =
        IOBufferMemoryDescriptor::withCapacity(
            (vm_size_t)M22B_TABLE_SIZE_FULL, kIODirectionNone, true);
    IOBufferMemoryDescriptor *cmdbuf =
        IOBufferMemoryDescriptor::withCapacity(
            (vm_size_t)M23_CMD_BUF_SIZE, kIODirectionNone, true);
    IOBufferMemoryDescriptor *cwwb =
        IOBufferMemoryDescriptor::withCapacity(
            (vm_size_t)0x1000, kIODirectionNone, true);

    if (!tbl || !cmdbuf || !cwwb) {
        setProperty("m2-b1-verdict", "FAIL-alloc");
        setProperty("m2-b1-stage", "2-FAIL-alloc");
        if (tbl) tbl->release();
        if (cmdbuf) cmdbuf->release();
        if (cwwb) cwwb->release();
        return;
    }

    IOByteCount sl = 0;
    addr64_t tblPA = tbl->getPhysicalSegment(0, &sl, kIOMemoryMapperNone);
    bool memOk = tblPA && ((UInt64)sl >= M22B_TABLE_SIZE_FULL);

    addr64_t cmdPA = 0;
    addr64_t semPA = 0;
    if (memOk) {
        cmdPA = cmdbuf->getPhysicalSegment(0, &sl, kIOMemoryMapperNone);
        memOk = cmdPA && ((UInt64)sl >= M23_CMD_BUF_SIZE);
    }
    if (memOk) {
        semPA = cwwb->getPhysicalSegment(0, &sl, kIOMemoryMapperNone);
        memOk = semPA && ((UInt64)sl >= 0x1000);
    }

    if (!memOk) {
        setProperty("m2-b1-verdict", "FAIL-memory");
        setProperty("m2-b1-stage", "3-FAIL-mem");
        tbl->release();
        cmdbuf->release();
        cwwb->release();
        return;
    }

    setHexProperty(this, "m2-b1-tbl-pa", (UInt64)tblPA);
    setHexProperty(this, "m2-b1-cmd-pa", (UInt64)cmdPA);
    setHexProperty(this, "m2-b1-sem-pa", (UInt64)semPA);

    // 三块都必须 4 KiB 对齐
    if (((UInt64)tblPA & 0xFFF) || ((UInt64)cmdPA & 0xFFF) ||
        ((UInt64)semPA & 0xFFF)) {
        setProperty("m2-b1-verdict", "FAIL-not-aligned");
        setProperty("m2-b1-stage", "3-FAIL-align");
        tbl->release(); cmdbuf->release(); cwwb->release();
        return;
    }

    // ---- 第 2 步：填表、清命令缓冲、清 cmd_sem ----
    volatile UInt64 *dte = (volatile UInt64 *)tbl->getBytesNoCopy();
    UInt32 dteCount = (UInt32)(M22B_TABLE_SIZE_FULL / M22B_DTE_SIZE);
    const UInt64 pt0 = DTE_V | DTE_TV | DTE_IR | DTE_IW;
    for (UInt32 i = 0; i < dteCount; i++) {
        dte[i * 4 + 0] = pt0;
        dte[i * 4 + 1] = 0;
        dte[i * 4 + 2] = 0;
        dte[i * 4 + 3] = 0;
    }

    volatile UInt32 *cmdBuf = (volatile UInt32 *)cmdbuf->getBytesNoCopy();
    for (UInt32 i = 0; i < (M23_CMD_BUF_SIZE / 4); i++) cmdBuf[i] = 0;

    volatile UInt64 *sem = (volatile UInt64 *)cwwb->getBytesNoCopy();
    *sem = 0;
    setProperty("m2-b1-mem", "prepared");

    // ---- 第 3 步：映射 MMIO ----
    IOMemoryDescriptor *md =
        IOMemoryDescriptor::withPhysicalAddress(
            (IOPhysicalAddress)M21_MMIO_BASE,
            (IOByteCount)M21_MMIO_LEN, kIODirectionNone);
    if (!md) {
        setProperty("m2-b1-verdict", "FAIL-mmio-md");
        setProperty("m2-b1-stage", "4-FAIL-md");
        tbl->release(); cmdbuf->release(); cwwb->release();
        return;
    }
    IOMemoryMap *map = md->map(kIOMapInhibitCache | kIOMapAnywhere);
    if (!map) {
        setProperty("m2-b1-verdict", "FAIL-mmio-map");
        setProperty("m2-b1-stage", "4-FAIL-map");
        md->release();
        tbl->release(); cmdbuf->release(); cwwb->release();
        return;
    }
    volatile UInt8 *base = (volatile UInt8 *)map->getVirtualAddress();

    if (mmioRead64(base, M21_OFF_EXT_FEAT) != M21_EFR_EXPECTED) {
        setProperty("m2-b1-verdict", "FAIL-efr-mismatch");
        setProperty("m2-b1-stage", "5-aborted-identity");
        map->release(); md->release();
        tbl->release(); cmdbuf->release(); cwwb->release();
        return;
    }
    setProperty("m2-b1-identity", "confirmed");

    // ---- 第 4 步：记录原状态 ----
    UInt64 origDT   = mmioRead64(base, M21_OFF_DEV_TABLE);
    UInt64 origCmd  = mmioRead64(base, M23_OFF_CMD_BUF);
    UInt64 origCtrl = mmioRead64(base, M21_OFF_CONTROL);
    setHexProperty(this, "m2-b1-orig-control", origCtrl);

    if (origCtrl & M23_CTRL_IOMMU_EN) {
        setProperty("m2-b1-verdict", "ABORT-already-enabled");
        setProperty("m2-b1-stage", "6-aborted");
        map->release(); md->release();
        tbl->release(); cmdbuf->release(); cwwb->release();
        return;
    }

    // ---- 第 5 步：配置并使能 ----
    UInt64 dtEntry  = ((UInt64)tblPA & ~0xFFFULL) |
                      ((M22B_TABLE_SIZE_FULL >> 12) - 1);
    UInt64 cmdEntry = ((UInt64)cmdPA & ~0xFFFULL) | M23_CMD_SIZE_CODE;

    mmioWrite64(base, M21_OFF_DEV_TABLE, dtEntry);
    mmioWrite64(base, M23_OFF_CMD_BUF, cmdEntry);
    mmioWrite64(base, M2B1_CMD_HEAD_OFFSET, 0);
    mmioWrite64(base, M2B1_CMD_TAIL_OFFSET, 0);

    UInt64 ctrl = mmioRead64(base, M21_OFF_CONTROL);
    ctrl |= M23_CTRL_CMDBUF_EN;
    mmioWrite64(base, M21_OFF_CONTROL, ctrl);

    ctrl = mmioRead64(base, M21_OFF_CONTROL);
    ctrl |= M23_CTRL_IOMMU_EN;
    mmioWrite64(base, M21_OFF_CONTROL, ctrl);

    UInt64 ctrlOn = mmioRead64(base, M21_OFF_CONTROL);
    setProperty("m2-b1-enabled",
        (ctrlOn & M23_CTRL_IOMMU_EN) ? "yes" : "no");
    setHexProperty(this, "m2-b1-control-on", ctrlOn);

    // ---- 第 6 步：发一条 CMD_COMPL_WAIT ----
    //
    // 序列号用 1（初值 0，变化即证明执行）。
    const UInt32 kSeq = 1;
    UInt64 seq = (UInt64)kSeq;

    UInt32 d0 = (UInt32)((UInt64)semPA & 0xFFFFFFFF) | M2B1_CMD_STORE_MASK;
    UInt32 d1 = (UInt32)((UInt64)semPA >> 32) | (M2B1_CMD_COMPL_WAIT << 28);
    UInt32 d2 = (UInt32)(seq & 0xFFFFFFFF);
    UInt32 d3 = (UInt32)(seq >> 32);

    setHexProperty(this, "m2-b1-cmd-d0", d0);
    setHexProperty(this, "m2-b1-cmd-d1", d1);
    setHexProperty(this, "m2-b1-cmd-d2", d2);
    setHexProperty(this, "m2-b1-cmd-d3", d3);

    writeCmd(cmdBuf, 0, d0, d1, d2, d3);
    setProperty("m2-b1-cmd", "written");

    // 推进 tail：硬件从 tail 处取命令
    // 注意 Linux 用 writel(tail, ...)，tail 是字节偏移
    UInt32 newTail = 16;   // 一条命令 16 字节
    mmioWrite64(base, M2B1_CMD_TAIL_OFFSET, newTail);
    setHexProperty(this, "m2-b1-tail", newTail);

    // ---- 第 7 步：轮询 cmd_sem，等硬件写回 ----
    UInt32 loops = 0;
    UInt64 observed = 0;
    while (loops < M2B1_LOOP_TIMEOUT) {
        observed = *sem;
        if (observed != 0) break;
        loops++;
    }

    setHexProperty(this, "m2-b1-sem-value", observed);
    setHexProperty(this, "m2-b1-loops", loops);

    bool cmdWorked = (observed == seq);
    setProperty("m2-b1-cmd-executed", cmdWorked ? "yes" : "no");

    // 读 head/tail 看硬件消费到哪了
    UInt64 hwHead = mmioRead64(base, M2B1_CMD_HEAD_OFFSET);
    UInt64 hwTail = mmioRead64(base, M2B1_CMD_TAIL_OFFSET);
    setHexProperty(this, "m2-b1-hw-head", hwHead);
    setHexProperty(this, "m2-b1-hw-tail", hwTail);

    UInt32 status = mmioRead32(base, M21_OFF_STATUS);
    setHexProperty(this, "m2-b1-status", (UInt64)status);
    if (status & 0x1) {
        setProperty("m2-b1-evt-overflow", "YES");
    } else {
        setProperty("m2-b1-evt-overflow", "no");
    }

    // ---- 第 8 步：立即禁用并恢复 ----
    ctrl = mmioRead64(base, M21_OFF_CONTROL);
    ctrl &= ~M23_CTRL_IOMMU_EN;
    mmioWrite64(base, M21_OFF_CONTROL, ctrl);
    UInt64 ctrlOff = mmioRead64(base, M21_OFF_CONTROL);
    setProperty("m2-b1-disabled",
        (ctrlOff & M23_CTRL_IOMMU_EN) ? "no" : "yes");

    mmioWrite64(base, M21_OFF_DEV_TABLE, origDT);
    mmioWrite64(base, M23_OFF_CMD_BUF, origCmd);
    ctrl = mmioRead64(base, M21_OFF_CONTROL);
    ctrl &= ~M23_CTRL_CMDBUF_EN;
    ctrl |= (origCtrl & M23_CTRL_CMDBUF_EN);
    mmioWrite64(base, M21_OFF_CONTROL, ctrl);

    setHexProperty(this, "m2-b1-final-control",
                   mmioRead64(base, M21_OFF_CONTROL));
    setHexProperty(this, "m2-b1-final-devicetable",
                   mmioRead64(base, M21_OFF_DEV_TABLE));
    setHexProperty(this, "m2-b1-final-cmdbuf",
                   mmioRead64(base, M23_OFF_CMD_BUF));

    // ---- 判定 ----
    if (cmdWorked) {
        setProperty("m2-b1-verdict", "PASS-command-channel-works");
        setProperty("m2-b1-stage", "7-complete");
    } else {
        setProperty("m2-b1-verdict", "FAIL-no-completion");
        setProperty("m2-b1-stage", "7-complete-no-completion");
    }

    map->release();
    md->release();
    tbl->release();
    cmdbuf->release();
    cwwb->release();
    setProperty("m2-b1-cleanup", "done");
}
