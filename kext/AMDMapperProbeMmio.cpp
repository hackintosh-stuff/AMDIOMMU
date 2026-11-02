// AMDMapperProbeMmio.cpp -- M2-0/1/2a-1 MMIO read and write probes
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

// ===== AMDMapperProbeMmio.cpp (original lines 807..991) =====
// ------------------------------------------------- M2-0b：PCI 配置空间只读探测

// 为什么要有这一步（M2-0 之后）：
//
//   M2-0 的结论是「IVRS 的 0xFD380000 才对，DSDT 的 _CRS 0xFEB80000 是陈旧
//   声明」。但那个结论的证据全在 Linux 侧：
//     - Linux 源码用 h->mmio_phys（init.c:1755），不用 _CRS
//     - Linux dmesg 的 `Using global IVHD EFR:0x0` 反证 EFR 来自 MMIO 读取
//   这些证明了 0xFD380000 在 **Linux 下**可读，没有证明 macOS 下如何。
//
//   IOMMU 的 capability block 里有它自己的 BAR，是硬件当前的权威值。
//   把它和 IVRS 的 base 一比，就能在 macOS 侧独立判定：
//     - 若 BAR == 0xFD380000 → 与 IVRS 一致，_CRS 确为陈旧，M2-1 可用该地址
//     - 若 BAR == 0xFEB80000 → 反过来，_CRS 才对，M2-0 结论要推翻
//     - 若 BAR 是第三个值   → 两个来源都不可信，M2-1 必须改用 BAR
//
// 全部只读。configRead8/16/32 只读 PCI 配置空间，不碰任何 MMIO，
// 不写任何寄存器，不改变任何设备状态。
//
// 已知限制：
//   configAccess() 要求 !isInactive() && reserved && parent
//   且 configProt 不允许读时会被拒（返回 0xFFFFFFFF）。
//   所以本函数必须能区分「读到全 1」与「读被拒」——两者都返回 0xFFFFFFFF，
//   靠 device-id / vendor-id 是否能正常读出来判断通道是否通。
//
// 关于 IOPCIDevice 的 deprecated 警告：
//   SDK 把 IOPCIDevice 标成 __kpi_deprecated("Use PCIDriverKit")。该建议
//   对本项目不适用——PCIDriverKit 是用户态 DriverKit 框架，无法实现
//   IOMapper 子类，本项目必须是内核内 kext。且我们只用**只读**的
//   configRead8/16/32，这两个符号已确认存在于运行内核的 IOPCIFamily
//   导出表中。因此只在**本函数内**关掉该警告，不做全局抑制。
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
void org_example_AMDMapperProbe::runM20ConfigProbe() {
    setProperty("m2-stage", "0-config-probe-start");

    if (!fTarget) {
        setProperty("m2-config", "SKIP-no-target");
        return;
    }

    IOPCIDevice *pci = OSDynamicCast(IOPCIDevice, fTarget);
    if (!pci) {
        setProperty("m2-config", "FAIL-target-not-IOPCIDevice");
        return;
    }

    // ---- 第 1 步：验证配置空间通道本身是否可用 ----
    //
    // vendor-id 在 0x00，device-id 在 0x02。这两个值我们从 IORegistry
    // 属性已知（0x1022 / 0x1481），所以它们可以当「通道自检」：
    // 若读出来不是这两个值，说明 configRead 被拒或返回垃圾，
    // 后面所有 BAR 读数都不可信。
    UInt16 vid = pci->configRead16(0x00);
    UInt16 did = pci->configRead16(0x02);

    setHexProperty(this, "m2-cfg-vid", vid);
    setHexProperty(this, "m2-cfg-did", did);

    if (vid != 0x1022 || did != 0x1481) {
        // 通道不通。不能继续，否则 BAR 读数是垃圾。
        setProperty("m2-config", "FAIL-channel-not-usable");
        setProperty("m2-config-note",
                    "vid/did mismatch => configRead blocked or inactive");
        return;
    }
    setProperty("m2-config", "channel-ok");

    // ---- 第 2 步：读 capability 链表，找 AMD IOMMU capability ----
    //
    // CapID 0x0F = Secure Device (AMD IOMMU capability 用的就是这个 ID)。
    // 实测 macOS 的 "Capability Offsets" 里 SecureCapability = 64 (0x40)。
    //
    // 我们不盲信那个属性，自己走一遍链表——这样即使属性缺失也能工作，
    // 且能顺带验证属性里的值与链表一致。
    UInt16 status = pci->configRead16(0x06);
    bool capListSupported = (status & 0x0010) != 0;   // Status[4] = Capabilities List
    setProperty("m2-cfg-caplist", capListSupported ? "yes" : "no");

    if (!capListSupported) {
        setProperty("m2-config", "FAIL-no-capability-list");
        return;
    }

    UInt8 capPtr = (UInt8)(pci->configRead8(0x34) & 0xFC);  // 低 2 位保留
    setHexProperty(this, "m2-cfg-cap0", capPtr);

    UInt8 iommuCap = 0;
    UInt8 walk = capPtr;
    // 最多走 48 步（PCI 规范上限 48 个 capability），并检测环。
    for (int i = 0; i < 48 && walk >= 0x40; i++) {
        UInt16 hdr = pci->configRead16(walk);
        UInt8 capId = (UInt8)(hdr & 0xFF);
        UInt8 next  = (UInt8)((hdr >> 8) & 0xFC);

        if (capId == 0x0F) {        // Secure Device / AMD IOMMU
            iommuCap = walk;
            break;
        }
        if (next == 0 || next == walk) break;   // 链表结束或自环
        walk = next;
    }

    if (!iommuCap) {
        setProperty("m2-config", "FAIL-no-iommu-capability");
        return;
    }

    setHexProperty(this, "m2-cfg-iommu-cap", iommuCap);
    setProperty("m2-config", "capability-found");

    // ---- 第 3 步：读 capability 头部与 BAR ----
    //
    // AMD IOMMU capability 结构（相对 cap 起始）：
    //   +0x00 u32 : CapID(8) | CapPtr(8) | CapHdr(16)
    //   +0x04 u64 : Base Address（bit0 = lock，需屏蔽）
    //   +0x0C u16 : PCI Segment Group
    //   +0x0E u16 : IOMMU Info
    //   +0x10 u32 : IOMMU Feature Reporting
    //   +0x14 u32 : IOMMU Attributes
    //   +0x18 u64 : EFR Image
    //   +0x20 u64 : EFR Image 2
    UInt32 capHdr = pci->configRead32(iommuCap);
    setHexProperty(this, "m2-cfg-caphdr", capHdr);

    UInt32 barLo = pci->configRead32((UInt8)(iommuCap + 0x04));
    UInt32 barHi = pci->configRead32((UInt8)(iommuCap + 0x08));

    setHexProperty(this, "m2-cfg-barlo-raw", barLo);
    setHexProperty(this, "m2-cfg-barhi-raw", barHi);

    // bit0 是 lock 位，不是地址位。
    UInt64 bar = ((UInt64)barHi << 32) | (UInt64)(barLo & ~1u);
    setHexProperty(this, "m2-cfg-bar", bar);

    UInt16 segGroup = pci->configRead16((UInt8)(iommuCap + 0x0C));
    UInt16 iommuInfo = pci->configRead16((UInt8)(iommuCap + 0x0E));
    setHexProperty(this, "m2-cfg-seggroup", segGroup);
    setHexProperty(this, "m2-cfg-iommuinfo", iommuInfo);

    UInt32 featRep = pci->configRead32((UInt8)(iommuCap + 0x10));
    setHexProperty(this, "m2-cfg-featrep", featRep);

    UInt32 attrs = pci->configRead32((UInt8)(iommuCap + 0x14));
    setHexProperty(this, "m2-cfg-attrs", attrs);

    // EFR Image：这是 IVRS 0x11 块里那个字段的硬件侧副本。
    // 若它与 IVRS 的 0x058F77EF22294A5A 相等，说明两者是同一份数据。
    UInt32 efrLo = pci->configRead32((UInt8)(iommuCap + 0x18));
    UInt32 efrHi = pci->configRead32((UInt8)(iommuCap + 0x1C));
    UInt64 efr = ((UInt64)efrHi << 32) | (UInt64)efrLo;
    setHexProperty(this, "m2-cfg-efr", efr);

    // ---- 第 4 步：给出判定 ----
    //
    // 判据是 BAR 与两个候选地址的比较。这是本函数唯一的目的。
    const UInt64 kIvrsBase = 0xFD380000ULL;   // IVRS 0x10 与 0x11 块都写这个
    const UInt64 kCrsBase  = 0xFEB80000ULL;   // DSDT _CRS 的 Memory32Fixed
    const UInt64 kEfrKnown = 0x058F77EF22294A5AULL;  // IVRS EFR 字段实测值

    if (bar == kIvrsBase) {
        setProperty("m2-config-verdict", "BAR==IVRS(0xFD380000)");
        setProperty("m2-config-meaning", "IVRS correct, _CRS stale");
    } else if (bar == kCrsBase) {
        setProperty("m2-config-verdict", "BAR==_CRS(0xFEB80000)");
        setProperty("m2-config-meaning", "_CRS correct, IVRS stale!");
    } else if (bar == 0) {
        setProperty("m2-config-verdict", "BAR==0");
        setProperty("m2-config-meaning", "BAR not programmed / unreadable");
    } else {
        setProperty("m2-config-verdict", "BAR==third-value");
        setProperty("m2-config-meaning", "neither IVRS nor _CRS; trust BAR");
    }

    // EFR 比对：独立的第二重判据。
    // 若 EFR 与 IVRS 一致，说明这块 capability 结构我们读的位置是对的，
    // 从而 BAR 读数也可信。若不一致，BAR 读数就要打折扣。
    if (efr == kEfrKnown) {
        setProperty("m2-cfg-efr-match", "yes");
    } else {
        setProperty("m2-cfg-efr-match", "no");
    }

    setProperty("m2-stage", "1-config-probe-done");
}

// ===== AMDMapperProbeMmio.cpp (original lines 1022..1022) =====


// ===== AMDMapperProbeMmio.cpp (original lines 1116..1226) =====
void org_example_AMDMapperProbe::runM21MmioProbe() {
    setProperty("m2-m1-stage", "0-start");

    // ---- 门控：默认不执行 ----
    if (!parseMmioBootArg()) {
        setProperty("m2-m1-gate", "closed");
        setProperty("m2-m1-stage", "1-skipped-no-bootarg");
        return;
    }
    setProperty("m2-m1-gate", "open");

    // ---- 建立物理地址描述符 ----
    //
    // withPhysicalAddress 描述一段物理地址。这里描述的是 IOMMU 的 MMIO 窗口。
    // 返回 OSPtr，SDK 默认（未定义 IOKIT_ENABLE_SHARED_PTR）时就是裸指针。
    IOMemoryDescriptor *md =
        IOMemoryDescriptor::withPhysicalAddress(
            (IOPhysicalAddress)M21_MMIO_BASE,
            (IOByteCount)M21_MMIO_LEN,
            kIODirectionNone);
    if (!md) {
        setProperty("m2-m1-stage", "2-FAIL-withPhysicalAddress-null");
        return;
    }
    setProperty("m2-m1-md", "created");

    // ---- 映射进内核空间 ----
    //
    // kIOMapInhibitCache 是必须的：MMIO 寄存器不能被 CPU cache 缓冲，
    // 否则读到的是旧值、写入也不生效。这不是优化，是正确性要求。
    // kIOMapReadOnly 再加一道保险：即使代码有 bug 也写不进去。
    IOMemoryMap *map = md->map(kIOMapInhibitCache | kIOMapReadOnly | kIOMapAnywhere);
    if (!map) {
        setProperty("m2-m1-stage", "3-FAIL-map-null");
        md->release();
        return;
    }
    setProperty("m2-m1-map", "ok");

    IOVirtualAddress va = map->getVirtualAddress();
    if (!va) {
        setProperty("m2-m1-stage", "4-FAIL-no-virtual-address");
        map->release();
        md->release();
        return;
    }
    setHexProperty(this, "m2-m1-va", (UInt64)va);
    setHexProperty(this, "m2-m1-maplen", (UInt64)map->getLength());
    setProperty("m2-m1-stage", "5-mapped");

    volatile UInt8 *base = (volatile UInt8 *)va;

    // ---- 阶段 A：只读 EFR，这是唯一判据 ----
    //
    // 只读这一个寄存器。若地址错了，最坏结果是读到一个无关的 64 位值，
    // 我们立即停止，不会继续碰别的偏移。
    UInt64 efr = mmioRead64(base, M21_OFF_EXT_FEAT);
    setHexProperty(this, "m2-m1-efr", efr);
    setHexProperty(this, "m2-m1-efr-expected", M21_EFR_EXPECTED);

    if (efr != M21_EFR_EXPECTED) {
        setProperty("m2-m1-verdict", "FAIL-efr-mismatch");
        setProperty("m2-m1-stage", "6-stopped-efr-mismatch");
        // 不继续读其他寄存器——地址可能是错的，继续读只会增加风险。
        map->release();
        md->release();
        return;
    }

    // EFR 匹配 → 地址正确、映射正确、MMIO 可读。
    setProperty("m2-m1-verdict", "PASS-efr-match");
    setProperty("m2-m1-stage", "7-efr-verified");

    // ---- 阶段 B：EFR 已验证，读其他只读寄存器作为附加情报 ----
    //
    // 这些读数不影响判据，只是为 M2-2 提供基线：
    //   - DEV_TABLE 若非零，说明有人已经配置过设备表（不该发生）
    //   - CONTROL 的 IOMMU_EN 位若为 1，说明 IOMMU 已在运行（危险信号）
    //   - STATUS 的 EVT_RUN 等位反映日志是否在跑
    UInt64 devTable = mmioRead64(base, M21_OFF_DEV_TABLE);
    UInt64 control  = mmioRead64(base, M21_OFF_CONTROL);
    UInt32 status   = mmioRead32(base, M21_OFF_STATUS);

    setHexProperty(this, "m2-m1-devicetable", devTable);
    setHexProperty(this, "m2-m1-control", control);
    setHexProperty(this, "m2-m1-status", (UInt64)status);

    // 关键安全检查：IOMMU 必须处于关闭状态。
    // 若 CONTROL 的 bit0（IOMMU_EN）为 1，说明有别人在用它，
    // 我们的 M2-2 绝不能贸然接管。
    if (control & 0x1ULL) {
        setProperty("m2-m1-iommu-enabled", "YES-unexpected");
    } else {
        setProperty("m2-m1-iommu-enabled", "no-as-expected");
    }

    // DEV_TABLE 为 0 意味着从未被编程过——正是我们预期的干净状态。
    if (devTable == 0) {
        setProperty("m2-m1-devicetable-clean", "yes");
    } else {
        setProperty("m2-m1-devicetable-clean", "no");
    }

    setProperty("m2-m1-stage", "8-complete");

    // ---- 清理 ----
    // 必须 unmap 并释放。留着映射会让这段 MMIO 一直占着内核虚拟地址。
    map->release();
    md->release();
    setProperty("m2-m1-cleanup", "done");
}

// ===== AMDMapperProbeMmio.cpp (original lines 1228..1267) =====
// ------------------------------------------------- M2-2a-1：最小 MMIO 写测试

// 目的：只回答一个问题——**这个 MMIO 窗口能不能写？**
//
// 不使能 IOMMU、不分配设备表、不发命令。只做一次"写一个值、读回、恢复原值"。
//
// 为什么选 MMIO_DEV_TABLE_OFFSET (0x0000) 作为靶子：
//   - 它是 IOMMU 唯一一个"写了也不会立刻产生副作用"的寄存器：
//     只有 CONTROL_IOMMU_EN 置位后，硬件才会真正去用它。
//   - 当前 IOMMU 完全关闭（M2-1 实测 control 所有使能位为 0），
//     此时写它纯粹是存储，不会被任何硬件逻辑消费。
//   - 它当前值是 0x0（M2-1 实测），所以"恢复原值"就是写回 0，
//     即使恢复失败，留下的也是一个"未编程"的干净状态。
//
// 为什么不用 CONTROL 寄存器做写测试：
//   写 CONTROL 有真实风险——任何一位写错都可能使能 IOMMU 或清掉固件预设。
//   DEV_TABLE 没有这个风险。
//
// 测试值的选择（0.10.0 首次实测后修正）：
//   初版写 0xDEADBEEF00000000 并直接比较读回值，得到 "FAIL-write-did-not-stick"。
//   实测读回 0x000DBEEF00000000 —— **只丢了 bit 63:52**，bit 51:0 完全保留。
//
//   这不是写失败，而是硬件按规范屏蔽了保留位：
//     AMD IOMMU 的 DEV_TABLE 基址寄存器只实现 bit 51:0
//     （Linux: `#define PM_ADDR_MASK 0x000ffffffffff000ULL`，
//      且 iommu_set_device_table() 写入的 entry 只有基址 + size 编码）。
//     bit 63:52 是保留的只读零，写进去读出来就是 0。
//
//   所以判据必须是「读回值 == 写入值 & 实现掩码」，不能直接比较。
//   这是我在设计判据时犯的错，不是硬件的问题。
//
// 为什么仍然用这个标记值：
//   0xDEADBEEF00000000 落在 bit 63:32，其中 bit 51:32 会被保留，
//   但 bit 51:12 是真实地址位、bit 11:0 是 size 编码位——足以证明写入生效。
//   改用一个只占 bit 51:12 的模式更干净。
#define M22_OFF_DEV_TABLE   0x0000
// 只使用 bit 51:12（地址位），避开保留位与 size 编码位。
#define M22_WRITE_PATTERN   0x000ABCDEF0000000ULL
// 硬件实现的位掩码：DEV_TABLE 基址寄存器只有 bit 51:0。
#define M22_IMPL_MASK       0x000FFFFFFFFFFFFFULL

// ===== AMDMapperProbeMmio.cpp (original lines 1269..1391) =====
void org_example_AMDMapperProbe::runM22aWriteProbe() {
    setProperty("m2-2a-stage", "0-start");

    // 门控：必须是 amdiommu=write 才执行。
    // 与 mmio（只读）分开，因为这是第一次写硬件，风险等级不同。
    if (!parseWriteBootArg()) {
        setProperty("m2-2a-gate", "closed");
        setProperty("m2-2a-stage", "1-skipped-no-bootarg");
        return;
    }
    setProperty("m2-2a-gate", "open");

    // ---- 映射，这次要可写 ----
    //
    // 与 M2-1 的差别：去掉 kIOMapReadOnly。
    // 仍保留 kIOMapInhibitCache —— MMIO 不可缓存是正确性要求。
    IOMemoryDescriptor *md =
        IOMemoryDescriptor::withPhysicalAddress(
            (IOPhysicalAddress)M21_MMIO_BASE,
            (IOByteCount)M21_MMIO_LEN,
            kIODirectionNone);
    if (!md) {
        setProperty("m2-2a-stage", "2-FAIL-md-null");
        return;
    }

    IOMemoryMap *map = md->map(kIOMapInhibitCache | kIOMapAnywhere);
    if (!map) {
        setProperty("m2-2a-stage", "3-FAIL-map-null");
        md->release();
        return;
    }

    IOVirtualAddress va = map->getVirtualAddress();
    if (!va) {
        setProperty("m2-2a-stage", "4-FAIL-no-va");
        map->release();
        md->release();
        return;
    }
    setProperty("m2-2a-map", "ok-rw");

    volatile UInt8 *base = (volatile UInt8 *)va;

    // ---- 第 1 步：先确认 EFR 仍匹配 ----
    //
    // 这是"映射对了"的自检。M2-1 已验证过一次，这里再验一次：
    // 万一这次映射到了别处，后面的写就会落到错误地址上。
    // 所以写之前必须重新确认身份。
    UInt64 efr = mmioRead64(base, M21_OFF_EXT_FEAT);
    setHexProperty(this, "m2-2a-efr", efr);
    if (efr != M21_EFR_EXPECTED) {
        setProperty("m2-2a-verdict", "FAIL-efr-mismatch-before-write");
        setProperty("m2-2a-stage", "5-aborted-identity-check");
        map->release();
        md->release();
        return;
    }
    setProperty("m2-2a-identity", "confirmed");

    // ---- 第 2 步：记录原值 ----
    UInt64 orig = mmioRead64(base, M22_OFF_DEV_TABLE);
    setHexProperty(this, "m2-2a-devicetable-orig", orig);

    // ---- 第 3 步：写标记值，读回 ----
    //
    // 这是本项目的**第一次硬件写**。
    mmioWrite64(base, M22_OFF_DEV_TABLE, M22_WRITE_PATTERN);
    UInt64 readback = mmioRead64(base, M22_OFF_DEV_TABLE);

    setHexProperty(this, "m2-2a-wrote", M22_WRITE_PATTERN);
    setHexProperty(this, "m2-2a-readback", readback);
    setHexProperty(this, "m2-2a-impl-mask", M22_IMPL_MASK);

    // 判据：只比较硬件实际实现的位（bit 51:0）。
    // 高位是保留的只读零，写进去读出来必然是 0——那不是失败。
    UInt64 expected = M22_WRITE_PATTERN & M22_IMPL_MASK;
    setHexProperty(this, "m2-2a-expected", expected);

    bool writeOk = (readback == expected);
    if (writeOk) {
        setProperty("m2-2a-writable", "yes");
    } else {
        setProperty("m2-2a-writable", "no");
    }
    // ---- 第 4 步：立即恢复原值 ----
    //
    // 无论上一步成功与否都要恢复。这是不可省略的清理动作。
    mmioWrite64(base, M22_OFF_DEV_TABLE, orig);
    UInt64 restored = mmioRead64(base, M22_OFF_DEV_TABLE);
    setHexProperty(this, "m2-2a-restored", restored);

    bool restoreOk = (restored == orig);
    setProperty("m2-2a-restore", restoreOk ? "ok" : "MISMATCH");

    // ---- 第 5 步：确认 IOMMU 仍然关闭 ----
    //
    // 写 DEV_TABLE 不应该改变 CONTROL。若变了，说明我们写错了偏移，
    // 那是一个必须立即知道的事实。
    UInt64 ctl = mmioRead64(base, M21_OFF_CONTROL);
    setHexProperty(this, "m2-2a-control-after", ctl);
    if (ctl & 0x1ULL) {
        setProperty("m2-2a-iommu-enabled", "YES-unexpected");
    } else {
        setProperty("m2-2a-iommu-enabled", "no-as-expected");
    }

    // ---- 判定 ----
    if (writeOk && restoreOk) {
        setProperty("m2-2a-verdict", "PASS-mmio-writable");
        setProperty("m2-2a-stage", "6-complete");
    } else if (!writeOk) {
        setProperty("m2-2a-verdict", "FAIL-write-did-not-stick");
        setProperty("m2-2a-stage", "6-complete-write-failed");
    } else {
        setProperty("m2-2a-verdict", "FAIL-restore-mismatch");
        setProperty("m2-2a-stage", "6-complete-restore-failed");
    }

    map->release();
    md->release();
    setProperty("m2-2a-cleanup", "done");
}
