// AMDMapperProbeNic.cpp -- NIC discovery, publish notifier, arming
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

// ===== AMDMapperProbeNic.cpp (original lines 156..215) =====

// ===== AMDMapperProbeNic.cpp (original lines 575..618) =====
// ------------------------------------------------------ B2-b 发布通知（解决竞态）
//
// 目标：在 Lucy probe/start **之前**把 iommu-parent 挂到网卡上。
//
// 为什么用 gIOFirstPublishNotification 而不是枚举或延时：
//   IOKit 文档（IOService.h:279）明确：registerService 时会先构造匹配列表
//   （含已安装的 publish 通知），**然后**才 attach/probe/start 驱动。
//   所以在 publish 通知里挂属性，一定早于 Lucy 读它。
//   枚举（serviceMatching）要求 PCI 枚举完成，太晚；
//   延时（thread_call）不确定，且 start() 里不便等待。
//
// 为什么不用 gIOMatchedNotification：
//   那个是「驱动已经 probe 并 start 完」才投递，对我们是**太晚**的。
//
// 注意 handler 必须返回 true，否则通知会被自动移除。

bool org_example_AMDMapperProbe::publishHandler(
    void *target, void *refCon, IOService *newService, IONotifier *notifier) {
    (void)refCon; (void)notifier;

    org_example_AMDMapperProbe *self =
        (org_example_AMDMapperProbe *)target;
    if (!self || !newService) return true;
    if (self->fR44Auto) {
        // One path for explicit requester offers and the legacy default.
        // It also marks known unselected clients for physical DMA.
        self->r44AttachAuto(newService);
        return true;
    }

#if AMD_MAPPER_PROBE_DEBUG
    // Legacy experiments keep their original RTL8127-only target.
    OSData *did = OSDynamicCast(OSData, newService->copyProperty("device-id"));
    bool isTarget = false;
    if (did && did->getLength() >= 2) {
        const UInt8 *p = (const UInt8 *)did->getBytesNoCopy();
        isTarget = (p[0] == 0x27 && p[1] == 0x81);
    }
    if (did) did->release();

    if (!isTarget) return true;     // 不是网卡，继续等

    self->fPublishHits++;
    self->setProperty("r44-notify-hits", (unsigned long long)self->fPublishHits, 64);

    // 已经挂过就不再重复（gIOFirstPublishNotification 每实例只投一次，
    // 但 kIOServiceSynchronous 下可能在同一实例上重复触发）
    if (self->fNicDevice == newService) return true;

    self->armNic(newService);
#endif /* AMD_MAPPER_PROBE_DEBUG */
    return true;
}

// ===== AMDMapperProbeNic.cpp (original lines 620..644) =====
// 给网卡挂 iommu-parent。可在 start() 里调用，也可在通知回调里调用。

// ===== AMDMapperProbeNic.cpp (original lines 646..669) =====
void org_example_AMDMapperProbe::installPublishNotifier() {
    // 匹配字典：只关心 IOPCIDevice。device-id 在 handler 里核对，
    // 因为 publish 阶段的属性可能还没全部就位，用 propertyMatching 过滤
    // 反而可能漏掉。
    OSDictionary *matching = IOService::serviceMatching("IOPCIDevice");
    if (!matching) {
        setProperty("m1bb-notifier", "FAIL-no-matching");
        return;
    }

    fPublishNotifier = IOService::addMatchingNotification(
        gIOFirstPublishNotification,
        matching,
        &org_example_AMDMapperProbe::publishHandler,
        this,       // target
        nullptr,    // refCon
        0);         // priority

    // addMatchingNotification 不消耗字典引用（与 addNotification 不同），
    // 所以这里要自己释放。
    matching->release();

    setProperty("m1bb-notifier", fPublishNotifier ? "installed" : "FAIL");
}

// ===== AMDMapperProbeNic.cpp (original lines 698..804) =====

// R52 auto mode enumerates endpoints, never a first match or a saved NIC path.
// The first-publish callback uses the same per-requester attach routine.
void org_example_AMDMapperProbe::r52AttachExistingDevices() {
    OSDictionary *matching = IOService::serviceMatching("IOPCIDevice");
    if (!matching) return;
    OSIterator *it = IOService::getMatchingServices(matching);
    matching->release();
    if (!it) return;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    while (OSObject *object = it->getNextObject()) {
        IOPCIDevice *pci = OSDynamicCast(IOPCIDevice, object);
        if (pci) r44AttachAuto(pci);
    }
#pragma clang diagnostic pop
    it->release();
}
