// AMDMapperProbe.cpp -- entry point, IOMapper contract, kmod glue
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
#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSDictionary.h>

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

#define super IOMapper
OSDefineMetaClassAndStructors(org_example_AMDMapperProbe, IOMapper);

// ===== AMDMapperProbe.cpp (original lines 76..142) =====
bool org_example_AMDMapperProbe::initHardware(IOService *provider) {
    (void)provider;
    fTarget = nullptr;
    fNicDevice = nullptr;
    fMapCalls = fUnmapCalls = fInsertCalls = fPhysAddrCalls = 0;
    fPublishedMapCalls = 0;
    fMapOkCalls = fMapRejectFragCalls = fMapRejectOtherCalls = 0;
    fUnmapOkCalls = 0;
    fMapWindowOpen = false;
    fProbeCallActive = false;
    fExpectedCmd = nullptr;
    fLastSegCount = 0;
    fLastFirstPA = 0;
    fLastLength = 0;
    fLastOffset = 0;

    // ---- B2-b ----
    fArmed = false;
    fPublishNotifier = nullptr;
    fPublishHits = 0;
    fLateAttach = false;
    fRealMapCalls = fRealMapOk = 0;
    fRealMapRejectFrag = fRealMapRejectNoSlot = 0;
    fRealUnmapCalls = 0;
    fTablePeak = 0;

    // ---- M2-2b-2 延迟定时器 ----
    fM22b2Timer = nullptr;
    fM22b2DelayMS = 0;
    fR31Session = false;
    fR31StopRequested = 0;
    fR31WorkerActive = 0;
    fR31StopRequestTime = 0;
    fR31SessionCompleted = false;
    fR33Domain = nullptr;
    fR33TeardownState = 0;
    fR33InstallCount = 0;
    fR34Rx = nullptr;
    for (int i = 0; i < kMaxActiveMaps; i++) {
        fMaps[i].pa = 0;
        fMaps[i].len = 0;
        fMaps[i].used = false;
    }

    // ---- 崩溃安全：把 fAllocName 归零 ----
    //
    // 为什么必须做（这是 B2-a 才引入的新风险）：
    //   B2-a 是第一个会让 iovmMapMemory **返回成功**的版本。一旦成功，
    //   IOMemoryDescriptor::dmaMapRecord() 会执行
    //       if ((alloc = mapper->fAllocName)) kern_allocation_update_size(alloc, ...);
    //   也就是说它会解引用 fAllocName。而在 0.4.0 及之前，映射全部失败，
    //   这行代码从未被执行过，所以从未暴露。
    //
    //   fAllocName 只存在于 XNU_KERNEL_PRIVATE 视图（IOMapper.h:75），
    //   第三方 kext 看不到这个名字；但在 SDK 视图里它就落在
    //   __reserved[6]（offset 48..56）。tools/layout-check.cpp 已用
    //   offsetof 机械验证过这条别名关系（48 == 48）。
    //
    //   正常路径下 fAllocName 由 IOMapper::copyMapperForDeviceWithIndex()
    //   在返回 mapper 前分配（IOMapper.cpp:211-223），而 B1 的
    //   runB1SelfTest() 正好会调用它。但它只在 fAllocName 为 **NULL** 时
    //   才分配；若这里是未初始化垃圾值，它会被当成合法指针解引用 → panic。
    //
    //   所以：先清零 → copyMapperForDevice 看到 NULL → 正确分配。
    //   若 B1 没跑（findTarget 失败），fAllocName 保持 NULL，
    //   dmaMapRecord 的 if 判断为假，同样安全。两条路都安全。
    //
    // 为什么不会破坏 fPageSize：
    //   __reserved[6] 占 [48,56)，fPageSize 在 [60,64)，不重叠
    //   （layout-check 已断言 56 <= 60）。而且 fPageSize 是
    //   IOMapper::start() 在 initHardware() **之后**才写的，
    //   时序上也不会被这里覆盖。
    __reserved[6] = 0;

    return true;
}

// ===== AMDMapperProbe.cpp (original lines 7584..7713) =====
bool org_example_AMDMapperProbe::start(IOService *provider) {
    setProperty("m1b-stage", "0-entered-start");

    // 安全闸门：必须在 super::start() 之前。
    // IOMapper::start() 在 fIsSystem 为真时会 gSystem = this，全局副作用且不可撤销。
    fIsSystem = false;

    if (!super::start(provider)) {
        setProperty("m1b-stage", "1-super-start-FAILED");
        return false;
    }
    setProperty("m1b-stage", "2-super-start-ok");

    // ---- B2-b：先决定是否放行真实设备 ----
    fArmed = parseArmBootArg();
    setProperty("m1bb-armed", fArmed ? "yes" : "no");

    // ---- B2-b：安装发布通知，抢在 Lucy probe 之前挂 iommu-parent ----
    //
    // 这是解决 0.6.0 竞态的关键。之前直接在 start() 里设属性，
    // 与 Lucy 读属性的顺序没有保证，导致三次重启成功/失败/成功。
    // 现在改由 gIOFirstPublishNotification 在设备注册瞬间挂属性，
    // 一定早于任何驱动的 probe/start。
    //
    // 同时保留 start() 里的兜底查找：若通知因某种原因没赶上
    // （例如网卡在探针 start() 之前就已发布完），仍尝试直接挂，
    // 并用 m1bb-nic-busy = yes-too-late 标记「这次可能太晚了」。
    if (fArmed) {
        installPublishNotifier();

        // 兜底：设备若已存在（通知不会重放已发布实例的 FirstPublish），
        // 直接找一次。
        if (!fNicDevice) {
            if (findNic()) {
                armNic(fNicDevice);
                fLateAttach = true;
                setProperty("m1bb-late-attach", "yes");
            } else {
                setProperty("m1bb-late-attach", "no-nic-yet");
            }
        }
    } else {
        setProperty("m1bb-parent", "not-armed");
    }

    // ---- B1：真实设备拿到 mapper ----
    if (!findTarget()) {
        setProperty("m1b-stage", "3-target-not-found");
    } else {
        setProperty("m1b-stage", "3-target-found");
        runB1SelfTest();

        // ---- M2-0b：只读 PCI 配置空间，取 IOMMU 自己的 BAR ----
        //
        // 放在 B1 之后而不是之前：runB1SelfTest() 会调
        // copyMapperForDevice()，它会给 fAllocName 分配记录名，
        // 属于 B1 的既有行为。M2-0b 完全独立、只读，顺序不影响它，
        // 但放在后面可以让失败时 m1b-stage 先反映 B1 的结果。
        runM20ConfigProbe();
    }

    // ---- M2-1：只读 MMIO 探测（boot-arg 门控，默认不执行）----
    //
    // 放在最后：它是本轮唯一真正接触 MMIO 的代码，
    // 让它前面的所有既有阶段先跑完，失败时 m1b-stage 已经反映完毕，
    // 不会掩盖任何回归。
    runM21MmioProbe();

    // ---- M2-2a-1：最小 MMIO 写测试（boot-arg 门控，默认不执行）----
    //
    // 放在最后：它是本项目第一次写硬件。
    // 前面所有只读阶段先跑完，任何回归都能在它之前被看到。
    runM22aWriteProbe();

    // ---- M2-2a-2：建设备表（boot-arg 门控，默认不执行）----
    //
    // 建一张全直通的设备表并写进基址寄存器，但**不使能 IOMMU**。
    // IOMMU 关闭时硬件不读这张表，所以系统行为必须完全不变。
    runM22bTableProbe();

    // ---- M2-2a-3：短窗口使能测试（boot-arg 门控，默认不执行）----
    //
    // 最高风险的一步：使能 IOMMU 后全系统 DMA 走设备表。
    // 但窗口极短——使能、读状态、立即禁用。
    // 放在最后，前面所有阶段先跑完。
    runM23EnableProbe();

    // ---- M2-2b-1：命令通道验证（boot-arg 门控，默认不执行）----
    //
    // M2-2a-3 只配置了命令缓冲，从未真正发过命令。
    // 这一步发一条 CMD_COMPL_WAIT，验证命令通道真的能用。
    // 仍是短窗口：使能 → 发一条 → 轮询 → 立即禁用。
    runM2b1CmdProbe();

    // ---- M2-2b-2：4 级恒等页表 + 单设备 DTE 切换（boot-arg 门控）----
    //
    // 【不能在这里直接跑】探针的 start() 早于 PCI 枚举完成与 Lucy 配置网卡，
    // 那时目标设备还没有 DMA，"切换后 0 fault"测不到任何东西。
    // 改为挂一次性定时器，延迟到系统稳定后再执行。
    /* Round 10: the DECLARED size of this round's controlled batch.
     *
     * controlledBatchComplete answers "did every request THIS ROUND
     * declared complete?". That declaration must come from here, not be
     * inferred from the records -- inferring it would be "however many I
     * saw is however many there were", which is circular.
     *
     * 0 means "not declared", and obsJoinInto() turns that into
     * controlledBatchComplete = false with reason "batch-not-declared".
     * "Not declared" is never treated as "zero requests, all complete". */
    fM22b2Dma.expectedBatch = m2b2ReadDeclaredBatch();

    /* Round 11: the run token is declared the same way, from the same
     * boot-arg. A batch declaration without a token cannot distinguish two
     * runs, so "token A's req1 + token B's req2" used to fold into one
     * complete batch of 2. See ObsBatchSpec in amd_iommu_dma_observe.hpp.
     *
     * 0 still means "not declared", and obsJoinInto() then either infers the
     * token (only when every parsed record agrees on one) or refuses the
     * batch claim with "run-token-not-declared". */
    fM22b2Dma.declaredToken = m2b2ReadDeclaredToken();
    setHexProperty(this, "m2-b2-declared-token",
                   (UInt64)fM22b2Dma.declaredToken);

    scheduleM22b2();

    // ---- B2-0：观察调用契约（窗口关闭，行为与 0.4.0 相同）----
    runB2SelfTest();

    // ---- B2-a：真正实现恒等映射 ----
    runB2aSelfTest();

    publishB2bStats();

    if (IOMapper::gSystem) {
        setProperty("m1b-gsystem", "NONNULL");
    } else {
        setProperty("m1b-gsystem", "NULL-as-expected");
    }

    setProperty("m1b-stage", "4-complete");
    return true;
}

// ===== AMDMapperProbe.cpp (original lines 7715..7747) =====
void org_example_AMDMapperProbe::r31RequestStop() {
    // RPC/service-stop callers only register a request. The worker owns every
    // state publication, RX/TX drain and hardware restoration operation.
    UInt64 expected = 0;
    const UInt64 now = mach_absolute_time();
    (void)__atomic_compare_exchange_n(&fR31StopRequestTime, &expected, now,
                                     false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    __atomic_store_n(&fR31StopRequested, 1u, __ATOMIC_RELEASE);
    r33ScheduleDomainStop();
}

IOReturn org_example_AMDMapperProbe::setProperties(OSObject *properties) {
    OSDictionary *dict = OSDynamicCast(OSDictionary, properties);
    OSObject *request = dict ? dict->getObject("R31Stop") : nullptr;
    if (!request) return super::setProperties(properties);
    if (request != kOSBooleanTrue) return kIOReturnBadArgument;
    if (!fR31Session) return kIOReturnNotReady;
    r31RequestStop();
    return kIOReturnSuccess;
}

void org_example_AMDMapperProbe::stop(IOService *provider) {
    // Cancel under the timer's gate so the once-only launch has either
    // completed or been cancelled. Keep the source installed until after the
    // join: openClientGate/closeClientGate need its workloop association.
    IOWorkLoop *wl = fM22b2Timer ? fM22b2Timer->getWorkLoop() : nullptr;
    const bool callerInGate = wl && wl->inGate();
    if (fM22b2Timer) {
        if (wl && !callerInGate) fM22b2Timer->closeClientGate();
        fM22b2Timer->cancelTimeout();
        if (wl) fM22b2Timer->openClientGate();
    }

    // Wait for domain teardown as well as workers: setup can return before the
    // queued stop worker begins. Its mapper/provider dependencies stay alive
    // across that handoff. Never hold the probe workloop gate across the join.
    if (fR31Session) {
        r31RequestStop();
        while (__atomic_load_n(&fR31WorkerActive, __ATOMIC_ACQUIRE) ||
               r33DomainStopPending())
            IOSleep(10);
    }
    if (wl && callerInGate) fM22b2Timer->closeClientGate();
    if (fM22b2Timer) {
        if (wl) wl->removeEventSource(fM22b2Timer);
        fM22b2Timer->release();
        fM22b2Timer = nullptr;
    }
    fMapWindowOpen = false;
    fArmed = false;

    // 先摘通知，避免 stop 之后回调仍被投递（那时对象正在拆除）
    if (fPublishNotifier) {
        fPublishNotifier->disable();
        fPublishNotifier->release();
        fPublishNotifier = nullptr;
    }

    if (fNicDevice) {
        fNicDevice->removeProperty("iommu-parent");
        fNicDevice->release();
        fNicDevice = nullptr;
    }
    if (fTarget) {
        fTarget->removeProperty("iommu-parent");
        fTarget->release();
        fTarget = nullptr;
    }
    super::stop(provider);
}

// ===== AMDMapperProbe.cpp (original lines 7749..7751) =====
uint64_t org_example_AMDMapperProbe::getPageSize() const {
    return 4096;
}

// ===== AMDMapperProbe.cpp (original lines 7753..7943) =====
// ------------------------------------------------------ IOMapper 子类接口实现
//
// B2-a 的语义：**只支持物理连续的单段**，且必须返回恰好 length。
//
// 为什么 mapLength 必须恰好等于 length（这是整个实现的安全支点）：
//   IODMACommand::prepare() 拿到返回值后立刻检查
//       if (kIOReturnSuccess == ret && mapArgs.fAllocLength
//           && (mapArgs.fAllocLength != mapArgs.fLength))   → 多段分支
//   而多段分支第一行就是
//       assert(mapArgs.fAllocLength > mapArgs.fLength);      // IODMACommand.cpp:946
//   恒等映射永远给不出比请求更长的区间。所以只要我们不等于 length，
//   内核就会在 assert 上 panic。返回恰好 length 则整个多段分支被跳过，
//   genIOVMSegments 走 fMapSegmentsCount==0 的快路径：
//       state->fIOVMAddr = fLocalMapperAlloc + offset - fPreparedOffset
//   正是恒等映射。

IOReturn org_example_AMDMapperProbe::iovmMapMemory(
    IOMemoryDescriptor *memory,
    uint64_t descriptorOffset,
    uint64_t length,
    uint32_t mapOptions,
    const IODMAMapSpecification *mapSpecification,
    IODMACommand *dmaCommand,
    const IODMAMapPageList *pageList,
    uint64_t *mapAddress,
    uint64_t *mapLength) {

    fMapCalls++;

    // 只记录第一次调用的完整参数，避免属性无限增长。
    if (fMapCalls == 1) {
        setHexProperty(this, "m1b2-first-offset", descriptorOffset);
        setHexProperty(this, "m1b2-first-length", length);
        setHexProperty(this, "m1b2-first-options", mapOptions);
        setProperty("m1b2-first-has-memory", memory ? "yes" : "no");
        setProperty("m1b2-first-has-spec", mapSpecification ? "yes" : "no");
        setProperty("m1b2-first-has-pagelist", pageList ? "yes" : "no");
        setProperty("m1b2-first-has-cmd", dmaCommand ? "yes" : "no");

        if (mapSpecification) {
            setHexProperty(this, "m1b2-first-numbits",
                mapSpecification->numAddressBits);
            setHexProperty(this, "m1b2-first-align",
                mapSpecification->alignment);
            setProperty("m1b2-first-has-device",
                mapSpecification->device ? "yes" : "no");
        }
        if (pageList) {
            setHexProperty(this, "m1b2-first-pagecount",
                pageList->pageListCount);
            setHexProperty(this, "m1b2-first-pageoffset",
                pageList->pageOffset);
        }
    }

    if (mapAddress) *mapAddress = 0;
    if (mapLength)  *mapLength  = 0;

    // ---- 分流：探针自己发起的调用 还是 真实设备 ----
    //
    // 判据是 fProbeCallActive，**不是** fMapWindowOpen。
    // 这两者的区别正是 0.6.0 首次部署暴露的 bug：
    //   B2-0 是「探针发起、窗口关闭」（刻意保留旧行为做基线），
    //   若用窗口判断，它会被当成真实设备调用，使 m1bb-realmapcalls 虚高。
    // 实测第一次部署就报了 realmapcalls=1、first-len=0x10000，
    // 而那正是 B2-0 的 16 KiB buffer，不是网卡。
    bool isProbeCall = fProbeCallActive;

    if (r34RxCandidate(memory, dmaCommand))
        return r34RxMap(memory, descriptorOffset, length, mapOptions,
                       mapSpecification, dmaCommand, pageList,
                       mapAddress, mapLength);

    // The RX commands describe the driver's retained spare mbufs. Dispatch
    // before TX/self-test handling, using registered MD/command identities.
    if (r27RxCandidate(memory, dmaCommand))
        return r27RxMap(memory, descriptorOffset, length, mapOptions,
                       mapSpecification, dmaCommand, pageList,
                       mapAddress, mapLength);

    // ---- ROUND 18: the standard path, and why it is checked first ----
    // r18StdReady() is true only when THIS run installed the round-17/18 domain
    // with a standard mode (selected or all-TX) AND the driver handed back this very object as its
    // mapper. In that configuration a real-device call is a packet the driver
    // described with an IOMemoryDescriptor and mapped through an IODMACommand
    // built on purpose; the identity path below must not answer it, or the
    // packet would silently be sent through a physical address again.
    if (!isProbeCall && r18StdReady()) {
        IOReturn kr = r18StdMap(memory, descriptorOffset, length, mapOptions,
                                mapSpecification, dmaCommand, pageList,
                                mapAddress, mapLength);
        publishStdStats();
        return kr;
    }

    if (!isProbeCall) {
        // 真实设备调用
        fRealMapCalls++;

        if (!fArmed) {
            // 未授权：保持 B2-a 的行为，拒绝并计数。
            fMapRejectOtherCalls++;
            if (fRealMapCalls == 1) {
                setProperty("m1bb-first-unarmed", "rejected");
                setHexProperty(this, "m1bb-first-len", length);
            }
            publishB2bStats();
            publishMapStats(false);
            return kIOReturnUnsupported;
        }

        if (!mapAddress || !mapLength || !memory || !length) {
            fMapRejectOtherCalls++;
            publishB2bStats();
            return kIOReturnUnsupported;
        }

        ProbeRun rrun = probeSegmentRun(memory, descriptorOffset, length);
        if (rrun.error) {
            fMapRejectOtherCalls++;
            publishB2bStats();
            return kIOReturnUnsupported;
        }

        if (!rrun.contiguous) {
            // 真实设备遇到碎片：恒等映射表达不了，只能拒绝。
            // 这正是 useAppleVTD 为真时数据包 buffer 会撞上的情况，
            // 也是 M2 页表要解决的真正问题。
            fRealMapRejectFrag++;
            if (fRealMapRejectFrag == 1) {
                setHexProperty(this, "m1bb-firstfrag-len", length);
                setHexProperty(this, "m1bb-firstfrag-segs", rrun.segCount);
            }
            publishB2bStats();
            return kIOReturnUnsupported;
        }

        MapEntry *e = allocMapEntry();
        if (!e) {
            fRealMapRejectNoSlot++;
            publishB2bStats();
            return kIOReturnUnsupported;
        }
        e->pa  = rrun.firstPA;
        e->len = length;

        *mapAddress = rrun.firstPA;
        *mapLength  = length;        // 同样必须恰好等于 length

        fRealMapOk++;
        if (fRealMapOk == 1) {
            setHexProperty(this, "m1bb-first-ok-pa", rrun.firstPA);
            setHexProperty(this, "m1bb-first-ok-len", length);
            setHexProperty(this, "m1bb-first-ok-off", descriptorOffset);
            setHexProperty(this, "m1bb-first-ok-opts", mapOptions);
            setHexProperty(this, "m1bb-first-ok-segs", rrun.segCount);
            setProperty("m1bb-first-ok-cmd",
                dmaCommand ? "nonnull" : "null");
        }
        publishB2bStats();
        publishMapStats(false);
        return kIOReturnSuccess;
    }

    // ---- 探针自身发起的调用 ----
    //
    // 只有窗口打开时（B2-a 的两组对照）才返回成功；
    // B2-0 的调用窗口关闭，保持旧行为（返回 kIOReturnUnsupported）。
    if (!fMapWindowOpen || dmaCommand != fExpectedCmd) {
        fMapRejectOtherCalls++;
        publishMapStats(false);
        return kIOReturnUnsupported;
    }

    if (!mapAddress || !mapLength || !memory || !length) {
        fMapRejectOtherCalls++;
        publishMapStats(false);
        return kIOReturnUnsupported;
    }

    ProbeRun run = probeSegmentRun(memory, descriptorOffset, length);
    if (run.error) {
        fMapRejectOtherCalls++;
        publishMapStats(false);
        return kIOReturnUnsupported;
    }

    if (!run.contiguous) {
        // 碎片化：恒等映射无法用单个标量描述，只能拒绝。
        // 这不是实现缺陷，是 iovmMapMemory 接口表达力的边界。
        fMapRejectFragCalls++;
        if (fMapRejectFragCalls == 1) {
            setHexProperty(this, "m1b2a-firstfrag-segs", run.segCount);
            setHexProperty(this, "m1b2a-firstfrag-len", length);
        }
        publishMapStats(false);
        return kIOReturnUnsupported;
    }

    // 物理连续 → 恒等映射：IOVA 直接等于物理地址。
    *mapAddress = run.firstPA;
    *mapLength  = length;        // 必须**恰好**等于 length，见上方注释

    // 自测的映射也登记进表，让 mapToPhysicalAddress 统一按表查询。
    {
        MapEntry *e = allocMapEntry();
        if (e) { e->pa = run.firstPA; e->len = length; }
    }

    fMapOkCalls++;
    fLastSegCount = run.segCount;
    fLastFirstPA  = run.firstPA;
    fLastLength   = length;
    fLastOffset   = descriptorOffset;

    publishMapStats(false);
    return kIOReturnSuccess;
}

// ===== AMDMapperProbe.cpp (original lines 7945..7972) =====
IOReturn org_example_AMDMapperProbe::iovmUnmapMemory(
    IOMemoryDescriptor *memory, IODMACommand *dmaCommand,
    uint64_t mapAddress, uint64_t mapLength) {
    (void)memory;

    fUnmapCalls++;

    if (r34RxCandidate(memory, dmaCommand) ||
        (fR34Rx && r27RxOwnsAddress(mapAddress)))
        return r34RxUnmap(memory, dmaCommand, mapAddress, mapLength);
    if (r27RxCandidate(memory, dmaCommand) || r27RxOwnsAddress(mapAddress))
        return r27RxUnmap(memory, dmaCommand, mapAddress, mapLength);

    // ROUND 18: an address inside our own bounded IOVA window can only have come
    // from r18StdMap(), so this is the framework completing that mapping. It is
    // dispatched before the identity bookkeeping below, which knows nothing
    // about IOVAs and would not find an entry for them.
    if (r18StdOwnsAddress(mapAddress)) {
        IOReturn kr = r18StdUnmap(memory, dmaCommand, mapAddress, mapLength);
        publishStdStats();
        return kr;
    }

    // 判断这是真实设备的 unmap 还是自测的：自测期间 dmaCommand 是探针的，
    // 而 IODMACommand::complete() 调用 unmap 时 fMapWindowOpen 已经关了，
    // 所以不能用窗口判断。改用「表里是否有这一项」——
    // 两类映射都登记在同一张表里，按 (pa,len) 精确匹配即可。
    bool freed = freeMapEntry(mapAddress, mapLength);

    if (freed) {
        fUnmapOkCalls++;
    }

    // 真实设备的 unmap 单独计数：判据是 dmaCommand 不是探针的预期命令。
    // 注意 fExpectedCmd 在自测结束后已被置空，所以自测的 unmap 也会
    // 落到这一支；为区分，额外要求 fArmed 为真（只有装了卡才会开）。
    if (fArmed && dmaCommand && dmaCommand != fExpectedCmd) {
        fRealUnmapCalls++;
        publishB2bStats();
    }

    publishMapStats(false);
    return kIOReturnSuccess;
}

// ===== AMDMapperProbe.cpp (original lines 7974..7983) =====
IOReturn org_example_AMDMapperProbe::iovmInsert(
    uint32_t options, uint64_t mapAddress, uint64_t offset,
    uint64_t physicalAddress, uint64_t length) {
    (void)options; (void)mapAddress; (void)offset;
    (void)physicalAddress; (void)length;

    fInsertCalls++;
    // In the standard path this must stay ZERO: returning mapLength == length
    // makes IODMACommand take its single-range contract, which never calls
    // iovmInsert(). A nonzero count here would mean the round-18 layout bound
    // was silently exceeded.
    if (r18StdReady()) fStdInsertRejects++;
    publishStdStats();
    publishMapStats(false);
    return kIOReturnUnsupported;
}

// ===== AMDMapperProbe.cpp (original lines 7985..8007) =====
uint64_t org_example_AMDMapperProbe::mapToPhysicalAddress(uint64_t mappedAddress) {
    fPhysAddrCalls++;

    if (r27RxOwnsAddress(mappedAddress)) {
        uint64_t pa = 0;
        return r27RxTranslate(mappedAddress, &pa) ? pa : 0;
    }

    // ROUND 18: a real page-table translation for the addresses this backend
    // actually installed. Outside that window nothing is claimed (see below).
    if (r18StdOwnsAddress(mappedAddress)) {
        uint64_t pa = 0;
        if (r18StdTranslate(mappedAddress, &pa)) {
            fStdWalkCalls++;
            publishStdStats();
            return pa;
        }
        return 0;
    }

    publishMapStats(false);

    // 只对**我们确实映射过**的区间返回恒等结果。
    // 区间之外一律返回 0，表示「我不知道」，而不是假装翻译成功。
    //
    // 这一点很重要：IOMemoryDescriptor 会在某些路径上用
    //     mapper->mapToPhysicalAddress(addr) 与真实 PA 比对（见 xnu 里
    //     被 #if 0 包住的那段 panic 检查），如果我们在未映射区间乱返回，
    //     就会把错误地址喂给驱动。
    //
    // B2-b 起改为查表：真实设备会同时持有多个映射（Lucy 有三个描述符环），
    // 单变量无法表达。
    for (int i = 0; i < kMaxActiveMaps; i++) {
        if (!fMaps[i].used) continue;
        if (mappedAddress >= fMaps[i].pa
            && mappedAddress < (fMaps[i].pa + fMaps[i].len)) {
            return mappedAddress;   // 恒等：IOVA == PA
        }
    }
    return 0;
}

// ===== kmod trailer (original lines 8009..8016) =====
extern "C" {
extern kern_return_t _start(kmod_info_t *, void *);
extern kern_return_t _stop(kmod_info_t *, void *);
KMOD_EXPLICIT_DECL(org.example.AMDMapperProbe, "0.48.0", _start, _stop);
__attribute__((visibility("hidden"))) kmod_start_func_t *_realmain = nullptr;
__attribute__((visibility("hidden"))) kmod_stop_func_t *_antimain = nullptr;
__attribute__((visibility("hidden"))) int _kext_apple_cc = __APPLE_CC__;
}
