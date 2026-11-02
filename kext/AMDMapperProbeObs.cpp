// AMDMapperProbeObs.cpp -- driver observation log (wire v2) reader
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

// ===== AMDMapperProbeObs.cpp (original lines 3497..3611) =====
// ===========================================================================
// 第十轮：重新实现 m2b2ScanTxDone()
// ===========================================================================
//
// 【为什么这个函数被重写而不是"找回原文"】
//
//   第十轮把 v2 读取器拼进 AMDMapperProbe.cpp 时，拼接区间的终点取在
//   `m2b2PublishDmaDefaults()` 之前，而 m2b2ScanTxDone() 恰好位于这两个
//   标记之间——它的**定义**被整段替换掉了，只剩头文件里的声明和第 16d 步
//   的调用。链接阶段才暴露：kmutil 报
//
//     Failed to bind '__ZN26org_example_AMDMapperProbe14m2b2ScanTxDoneEv'
//     ... could not find a kext which exports this symbol
//
//   这正是第九轮反复出现的那种失效形态：编译通过、安装"成功"、集合重建
//   失败，而唯一症状是证据里什么都没有。本轮把它当成缺陷修掉，并把
//   "链接后必须能解析所有 driver 符号"写进 deploy 脚本。
//
// 【它做什么】
//
//   读一次 TX 环，返回 `doneWithAddr` —— 既已交还（DescOwn 清零）又带
//   非零地址的描述符数量。
//
//   这个数**不是**完成证据。DescOwn 在本芯片上不被硬件清除，所以这个
//   差值连续四轮都恒为 0（done == zeroaddr）。保留它只有一个用途：
//   让"DescOwn 不是完成信号"这件事每次实验都可见，而不是变成一段传闻。
//   真正的完成证据是驱动自己写的 tx-done 记录与硬件关闭指针。
//
// 【为什么先过两道门】
//
//   plausibleRingBase()  —— 寄存器里的地址看起来像不像一个环
//   readVerdictDeviceReported() —— 这个物理地址能不能安全读
//
//   两者任一不通过就返回 -1，绝不"读读看"。第七轮的教训：把设备报的地址
//   直接映射进来读过一次，代价是两次 panic。
// The declared batch size for this round.
//
// WHERE IT COMES FROM, AND WHY NOT FROM THE RECORDS
// -------------------------------------------------
// `controlledBatchComplete` answers "did every request THIS ROUND declared
// complete?". The declaration has to be made before the evidence is read,
// otherwise the check degenerates into "however many records I found is
// however many there were" -- which is circular and would pass on any input.
//
// So the number is written into the probe's IORegistry node by the deployment
// step (m2-b2-declared-batch), and read here. A missing property yields 0,
// which obsJoinInto() reports as "batch-not-declared" with
// controlledBatchComplete = false. Zero NEVER means "zero requests, all
// complete".
// The declaration is written onto the PROBE'S OWN node (this object), so it
// is read with copyProperty() on `this` -- no path lookup, and no dependence
// on where in the registry the probe happens to sit.
//
// ROUND 11: the SAME boot-arg also carries the run token, because a batch
// declaration without a token cannot tell two runs apart. See the
// counterexample in ObsBatchSpec: token A's req1 plus token B's req2 used to
// fold into one "complete" batch of 2.
//
//     amdiommu=pgt.batch4              -> 4 requests, token not declared
//     amdiommu=pgt.batch4.t0xa3dbba85  -> 4 requests, token 0xa3dbba85
//
// The token is parsed by the same bounded hex/dec scanner used for the count.
static inline bool m2b2ParseHexOrDec(const char **qp, UInt32 *out);

UInt32 org_example_AMDMapperProbe::m2b2ReadDeclaredBatch() {
    // WHERE THE DECLARATION ACTUALLY COMES FROM, AND TWO DEAD ENDS
    // ------------------------------------------------------------
    // Attempt 1: a personality key on our own IORegistry node. That does NOT
    // work -- IOKit publishes only a small fixed subset of the personality
    // dictionary onto the node (IOClass, IOProviderClass, IOMatchCategory,
    // ...), so an arbitrary key added to Info.plist never appears there. The
    // read silently returned 0 and the run reported "batch-not-declared".
    //
    // Attempt 2: `PE_parse_boot_argn("m2b2batch", ...)`. This project already
    // found (round 6, and again at parseM22b2Delay) that only `amdiommu=...`
    // is reliably delivered to this kext; separate trailing arguments are not
    // visible. So a second boot-arg is not a dependable channel either.
    //
    // Attempt 3 (this one): the count travels INSIDE the amdiommu= value,
    // which is the one argument that demonstrably arrives. The form is
    //
    //     amdiommu=pgt            -> no batch declared
    //     amdiommu=pgt.batch4     -> 4 requests declared
    //
    // Everything after a '.' is ours to define; the existing code only looks
    // for the exact tokens "pgt", "pgt4k" and "pgtsleep", so a suffix does not
    // disturb any of them (see parsePgtBootArg()).
    char val[128];
    val[0] = 0;
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        setProperty("m2-b2-declared-raw", "boot-arg-absent");
        return 0;
    }
    // Publish what the kernel actually delivered, so a mismatch between what
    // config.plist says and what this kext sees is visible instead of inferred.
    {
        char dbg[160];
        snprintf(dbg, sizeof(dbg), "amdiommu=%s", val);
        setProperty("m2-b2-declared-raw", dbg);
    }

    const char *dot = strchr(val, '.');
    if (!dot) return 0;
    const char *q = dot + 1;
    if (strncmp(q, "batch", 5) != 0) return 0;
    q += 5;

    UInt32 v = 0;
    if (!m2b2ParseHexOrDec(&q, &v)) return 0;
    return v;
}

// Bounded hex-or-decimal scanner shared by the batch count and the run token.
//
// Why one implementation: round 10 had this logic inline and a second copy
// would be a place for the two to drift. The scanner never reads past a
// non-digit and never overflows: it stops accumulating at 32 bits and leaves
// the rest for the caller's terminator check.
static inline bool m2b2ParseHexOrDec(const char **qp, UInt32 *out) {
    const char *q = *qp;
    UInt32 v = 0;
    bool any = false;
    if (q[0] == '0' && (q[1] == 'x' || q[1] == 'X')) {
        q += 2;
        while (*q) {
            UInt32 d;
            if (*q >= '0' && *q <= '9')      d = (UInt32)(*q - '0');
            else if (*q >= 'a' && *q <= 'f') d = (UInt32)(*q - 'a' + 10);
            else if (*q >= 'A' && *q <= 'F') d = (UInt32)(*q - 'A' + 10);
            else break;
            v = (v << 4) | d;
            any = true;
            q++;
        }
    } else {
        while (*q >= '0' && *q <= '9') {
            v = v * 10u + (UInt32)(*q - '0');
            any = true;
            q++;
        }
    }
    *qp = q;
    if (out) *out = v;
    return any;
}

// Read the run token out of the same amdiommu= value.
//
// Returns 0 when the value carries no token. Zero is never a valid token: the
// load generator starts at 1, and the driver refuses to publish a parsed
// record whose token is 0 (see obsParseBiz()). So "not declared" and
// "declared as 0" cannot be confused.
UInt32 org_example_AMDMapperProbe::m2b2ReadDeclaredToken() {
    char val[128];
    val[0] = 0;
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) return 0;
    const char *dot = strchr(val, '.');
    if (!dot) return 0;
    // Scan every '.key<value>' segment after the first, so the order of
    // batch and token in the boot-arg does not matter.
    const char *q = dot;
    while ((q = strchr(q, '.')) != nullptr) {
        q++;
        if (strncmp(q, "t0x", 3) == 0 || strncmp(q, "token", 5) == 0) {
            const char *r = q;
            if (strncmp(r, "token", 5) == 0) r += 5;
            else                              r += 1;   // skip the 't', keep 0x
            UInt32 v = 0;
            if (m2b2ParseHexOrDec(&r, &v) && v != 0) {
                char dbg[160];
                snprintf(dbg, sizeof(dbg), "declared token 0x%08x", v);
                setProperty("m2-b2-declared-token-raw", dbg);
                return v;
            }
        }
    }
    setProperty("m2-b2-declared-token-raw", "token-absent");
    return 0;
}

// ===========================================================================
// 第十一轮：绑定本次驱动实例
// ===========================================================================
//
// 【要解决的问题】
//
//   快照头部有 epoch（驱动在 obsInit() 里取的"开机后秒数"）。第十轮的
//   读侧把 want.epoch 写成 0，而 obsIdentityMatches() 把 0 解释为
//   "不检查"。于是这一整条保护**从未生效**：
//
//     同一块卡、同一份 MAC、同一个 BSD unit，
//     驱动重载或控制器 reset 之后产生的新实例，
//     其快照会被当成"本次实例"的证据。
//
// 【怎么绑】
//
//   优先用驱动自己发布的实例标识。驱动在驱动节点上发布
//   `rtl812x-obs-epoch`（与快照头部同源）。探针在**窗口打开之前**读它，
//   记住，之后要求快照头部的 epoch 与它相等。
//
//   驱动没有发布时，退而求其次：读一次快照，用它头部的 epoch 作为绑定值，
//   但**必须同时记录它来自哪一份 publication**，并且这个 publication
//   必须是窗口之前的那一份。这样"绑定"仍然发生在窗口之前，不是从被判定的
//   那份快照里抄出来的。
//
//   两条路都走不通时 epochBound 保持 0，m2b2ReadDriverObs() 会拒绝通过。
//   这不是"少检查一项"，而是"这一轮没有资格下结论"。
//
// 【为什么不在 m2b2ReadDriverObs() 里面绑】
//   那一步在窗口**之后**。在那里取 epoch 等于用被检验的对象去定义检验
//   标准。绑定点必须在窗口之前，这是这一段单独成函数的原因。
void org_example_AMDMapperProbe::m2b2BindDriverInstance() {
    fM22b2Dma.epochBound = 0;
    setProperty("m2-b2-epoch-bind", "not-attempted");

    IOService *svc = findNicServiceOnly();
    if (!svc) {
        setProperty("m2-b2-epoch-bind", "SKIP-no-nic");
        return;
    }
    const char *src = "unknown";
    IOService *obsSvc = m2b2FindObsService(svc, &src);
    if (!obsSvc) {
        svc->release();
        setProperty("m2-b2-epoch-bind", "SKIP-no-obs-node");
        return;
    }

    // Route 1: the driver publishes the instance epoch as its own property.
    {
        OSNumber *n = OSDynamicCast(OSNumber,
                                    obsSvc->copyProperty("rtl812x-obs-epoch"));
        if (n) {
            const UInt32 v = (UInt32)n->unsigned32BitValue();
            n->release();
            if (v != 0) {
                fM22b2Dma.epochBound = v;
                setProperty("m2-b2-epoch-bind", "driver-property");
                setHexProperty(this, "m2-b2-epoch-bound", (UInt64)v);
                if (obsSvc != svc) obsSvc->release();
                svc->release();
                return;
            }
        }
    }

    // Route 2: no published epoch property. Take it from the snapshot that
    // exists NOW -- which is before the window opens -- and record which
    // publication it came from, so the binding's provenance is auditable.
    {
        OSData *d = m2b2CopyObsSnapshot(obsSvc, nullptr);
        if (d) {
            const UInt32 bytes = (UInt32)d->getLength();
            const UInt8 *b = (const UInt8 *)d->getBytesNoCopy();
            const amdobs::ObsHeader h = amdobs::obsHeaderOk(b, bytes);
            if (h.ok && h.epoch != 0) {
                fM22b2Dma.epochBound = h.epoch;
                setProperty("m2-b2-epoch-bind", "pre-window-snapshot");
                setHexProperty(this, "m2-b2-epoch-bound", (UInt64)h.epoch);
                setHexProperty(this, "m2-b2-epoch-bind-pub-id",
                               (UInt64)h.pubId);
                setHexProperty(this, "m2-b2-epoch-bind-t-published",
                               h.tPublished);
            } else {
                setProperty("m2-b2-epoch-bind", "SKIP-unusable-snapshot");
                if (h.ok) setProperty("m2-b2-epoch-bind-why", "epoch-zero");
                else      setProperty("m2-b2-epoch-bind-why", h.why);
            }
            d->release();
        } else {
            setProperty("m2-b2-epoch-bind", "SKIP-no-snapshot");
        }
    }

    if (obsSvc != svc) obsSvc->release();
    svc->release();
}

// ===== AMDMapperProbeObs.cpp (original lines 3613..3641) =====
int org_example_AMDMapperProbe::m2b2ScanTxDone() {
    if (!fM22b2Dma.ran || !fM22b2Dma.haveTxRing) return -1;

    const UInt64 bytes = 1024ULL * amdobs::TX_DESC_STRIDE;
    const char *why = nullptr;
    if (!amdobs::plausibleRingBase(fM22b2Dma.txRingBase, bytes,
                                   M2B2_IDENTITY_LIMIT, &why) ||
        amdobs::readVerdictDeviceReported(fM22b2Dma.txRingBase, bytes,
                            fM22b2Policy) != amdobs::RD_OK) {
        return -1;
    }

    IOMemoryDescriptor *md =
        IOMemoryDescriptor::withPhysicalAddress(fM22b2Dma.txRingBase, bytes,
                                                kIODirectionIn);
    if (!md) return -1;

    int done = -1;
    IOMemoryMap *m = md->map(kIOMapInhibitCache | kIOMapReadOnly);
    if (m) {
        const UInt8 *rb = (const UInt8 *)(uintptr_t)m->getVirtualAddress();
        // doneWithAddr, NOT done: an unused slot has DescOwn clear and
        // would otherwise be counted as a completion.
        done = (int)amdobs::scanTxRing(rb, 1024).doneWithAddr;
        m->release();
    }
    md->release();
    return done;
}

// ===== AMDMapperProbeObs.cpp (original lines 3643..3886) =====
// ===========================================================================
// 第十轮：采集目标网卡的身份
// ===========================================================================
//
// 【为什么必须单独做这一步】
//
//   第九轮的负载绑定的是 en0 的 192.168.50.204，而目标设备是
//   0x25:00.0 → RTL8125 → en2（MAC 1c:86:0b:3b:0b:bd）。en0 是另一块
//   网卡（00:e0:4c:68:ab:03）。于是那一轮归档的"受控 TCP 链"根本没有
//   经过被观测的设备——它证明的是另一块网卡的 DMA。
//
//   根因不是打错了地址，而是**没有把"接口"与"PCI 功能"绑成同一件事**。
//   默认路由、源地址 bind、甚至 ifconfig 里看到一个 inet 都不构成
//   "报文从这个 BDF 出去"的证据。
//
//   所以这里把四个事实一次性取齐并发布：
//       DeviceId/BDF  ← 设备表里的这一条（kNicPaths 解析出来的）
//       vendor/device ← 该 IOPCIDevice 的配置空间
//       MAC           ← 该 IOPCIDevice 的 IOMACAddress，或驱动实例上的
//       BSD unit/name ← IOInterfaceUnit / BSD Name，且必须是它的子节点
//
//   分析器把这一组与驱动快照头部逐项比对。任何一项不符，快照就不属于
//   这个设备，结论降级——而不是"看起来像就当成是"。
//
// 【为什么不写死 en2】
//   接口编号随驱动加载顺序变化，写死会把一次成功变成不可复现。
//   这里每次现取，并把取到的值发布出去供分析器核对。
//
// 【关于 IOPCIDevice 的 deprecated 警告】
//   SDK 把 IOPCIDevice 标成 __kpi_deprecated("Use PCIDriverKit")。该建议
//   对本项目不适用——PCIDriverKit 是用户态 DriverKit 框架，无法实现
//   IOMapper 子类，本项目必须是内核内 kext。这里只用**只读**的
//   configRead16 与属性读取。因此只在**本函数内**关掉该警告，不做全局抑制
//   （与 runM20ConfigProbe() 的处理方式一致）。
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
void org_example_AMDMapperProbe::m2b2CaptureNicIdentity() {
    fM22b2Dma.nicIdentityKnown = false;
    fM22b2Dma.devid = 0;
    fM22b2Dma.vendorId = 0;
    fM22b2Dma.deviceId = 0;
    fM22b2Dma.nicUnit = 0;
    fM22b2Dma.nicMac = 0;
    fM22b2Dma.nicBsdName = "none";

    IOService *svc = findNicServiceOnly();
    if (!svc) {
        setProperty("m2-b2-nic-identity", "SKIP-no-nic");
        return;
    }

    bool haveBdf = false, haveVd = false, haveMac = false, haveUnit = false;

    // ---- BDF：从 IOPCIDevice 自己的属性取 ----
    //
    // 【为什么不用 configRead 反推】
    //   configRead 只能读到 vendor/device，读不到"我这个功能在总线上的
    //   编号"。而 IORegistry 里 IOPCIDevice 的 "reg" 属性就是
    //   (space, addr, len) 三元组，addr 的高位正是 bus/dev/fn。
    //   用属性比用寄存器更直接，也更难出错。
    IOPCIDevice *pci = OSDynamicCast(IOPCIDevice, svc);
    if (pci) {
        OSData *reg = OSDynamicCast(OSData, pci->copyProperty("reg"));
        if (reg && reg->getLength() >= 4) {
            const UInt8 *p = (const UInt8 *)reg->getBytesNoCopy();
            // 【为什么只读前 4 个字节，而不是"找那个看起来像 BDF 的字"】
            //
            //   这块板子的 `reg` 属性是 80 字节：
            //
            //     00002500 00000000 00000000 00000000 00000000
            //     10002501 00000000 ...
            //     18002502 00000000 ...
            //
            //   这是 OpenFirmware 的 `reg = <addr-hi addr-lo size-hi size-lo>`
            //   形式：**第一个 32 位大端字就是 (bus<<8)|(dev<<3)|fn**，即
            //   0x2500 = 25:00.0；后面每 20 字节一组是 BAR。
            //
            //   我第一版把第 3 个字（p[8..11]）当 BDF，于是读到 0，而驱动
            //   快照里正确写着 0x2500 —— 身份核对因此报 bdf-mismatch，
            //   整轮降级为 INDETERMINATE。**解析错了，不是设备不对。**
            //
            //   这里直接取大端首字，并用 PCI 的编码约束自检：bus 任意，
            //   dev 必须 < 32，fn 必须 < 8。
            const UInt32 first = ((UInt32)p[0] << 24) | ((UInt32)p[1] << 16) |
                                 ((UInt32)p[2] << 8) | (UInt32)p[3];
            const UInt32 bus = (first >> 8) & 0xFFu;
            const UInt32 dev = (first >> 3) & 0x1Fu;
            const UInt32 fn  = first & 0x7u;
            const UInt32 bdf = (bus << 8) | (dev << 3) | fn;
            if (bdf == first) {          // the encoding must round-trip
                fM22b2Dma.devid = bdf;
                haveBdf = true;
            }
        }
        if (reg) reg->release();

        // vendor/device：优先用配置空间，失败则退回属性。
        {
            const UInt16 v = pci->configRead16(0x00);
            const UInt16 d = pci->configRead16(0x02);
            if (v != 0xFFFFu && d != 0xFFFFu) {
                fM22b2Dma.vendorId = v;
                fM22b2Dma.deviceId = d;
                haveVd = true;
            }
        }
        if (!haveVd) {
            OSData *vid = OSDynamicCast(OSData, pci->copyProperty("vendor-id"));
            OSData *did = OSDynamicCast(OSData, pci->copyProperty("device-id"));
            if (vid && vid->getLength() >= 2 && did && did->getLength() >= 2) {
                const UInt8 *pv = (const UInt8 *)vid->getBytesNoCopy();
                const UInt8 *pd = (const UInt8 *)did->getBytesNoCopy();
                fM22b2Dma.vendorId = (UInt32)pv[0] | ((UInt32)pv[1] << 8);
                fM22b2Dma.deviceId = (UInt32)pd[0] | ((UInt32)pd[1] << 8);
                haveVd = true;
            }
            if (vid) vid->release();
            if (did) did->release();
        }

        // MAC：IOPCIDevice 上通常没有，驱动实例上有。下面在子节点里再找。
        OSData *mac = OSDynamicCast(OSData, pci->copyProperty("IOMACAddress"));
        if (mac && mac->getLength() >= 6) {
            const UInt8 *p = (const UInt8 *)mac->getBytesNoCopy();
            UInt64 m = 0;
            for (int i = 0; i < 6; i++) m = (m << 8) | (UInt64)p[i];
            fM22b2Dma.nicMac = m;
            haveMac = true;
        }
        if (mac) mac->release();
    }

    // ---- 驱动实例：MAC + BSD unit ----
    //
    // 从 IOPCIDevice 往下找驱动子节点（RTL8125）。它带着 IOMACAddress
    // 和 IOInterfaceUnit，而且它下面挂着 IOEthernetInterface（enN）。
    {
        OSIterator *it = svc->getChildIterator(gIOServicePlane);
        if (it) {
            OSObject *o = nullptr;
            while ((o = it->getNextObject()) != nullptr) {
                IOService *child = OSDynamicCast(IOService, o);
                if (!child) continue;

                if (!haveMac) {
                    OSData *mac = OSDynamicCast(
                        OSData, child->copyProperty("IOMACAddress"));
                    if (mac && mac->getLength() >= 6) {
                        const UInt8 *p = (const UInt8 *)mac->getBytesNoCopy();
                        UInt64 m = 0;
                        for (int i = 0; i < 6; i++) m = (m << 8) | (UInt64)p[i];
                        fM22b2Dma.nicMac = m;
                        haveMac = true;
                    }
                    if (mac) mac->release();
                }

                // IOInterfaceUnit 可能挂在驱动节点，也可能挂在它的
                // IOEthernetInterface 子节点上。两处都试。
                if (!haveUnit) {
                    OSNumber *u = OSDynamicCast(
                        OSNumber, child->copyProperty("IOInterfaceUnit"));
                    if (u) {
                        fM22b2Dma.nicUnit = (UInt32)u->unsigned32BitValue();
                        haveUnit = true;
                        u->release();
                    }
                }

                // 再往下找 IOEthernetInterface（enN 就在这一层）。
                OSIterator *it2 = child->getChildIterator(gIOServicePlane);
                if (it2) {
                    OSObject *o2 = nullptr;
                    while ((o2 = it2->getNextObject()) != nullptr) {
                        IOService *iface = OSDynamicCast(IOService, o2);
                        if (!iface) continue;
                        if (!haveUnit) {
                            OSNumber *u = OSDynamicCast(
                                OSNumber,
                                iface->copyProperty("IOInterfaceUnit"));
                            if (u) {
                                fM22b2Dma.nicUnit =
                                    (UInt32)u->unsigned32BitValue();
                                haveUnit = true;
                                u->release();
                            }
                        }
                        if (!haveMac) {
                            OSData *mac = OSDynamicCast(
                                OSData,
                                iface->copyProperty("IOMACAddress"));
                            if (mac && mac->getLength() >= 6) {
                                const UInt8 *p =
                                    (const UInt8 *)mac->getBytesNoCopy();
                                UInt64 m = 0;
                                for (int i = 0; i < 6; i++)
                                    m = (m << 8) | (UInt64)p[i];
                                fM22b2Dma.nicMac = m;
                                haveMac = true;
                            }
                            if (mac) mac->release();
                        }
                        // BSD Name 就是 enN，直接发布出来供人核对。
                        OSString *bsd = OSDynamicCast(
                            OSString, iface->copyProperty("BSD Name"));
                        if (bsd) {
                            char buf[32];
                            const char *c = bsd->getCStringNoCopy();
                            if (c) {
                                UInt32 n = (UInt32)strlen(c);
                                if (n < sizeof(buf)) {
                                    memcpy(buf, c, n);
                                    buf[n] = 0;
                                    setProperty("m2-b2-nic-bsd", buf);
                                    fM22b2Dma.nicBsdName = "enN";
                                }
                            }
                            bsd->release();
                        }
                    }
                    it2->release();
                }
                break;   // 第一个驱动子节点就够了
            }
            it->release();
        }
    }

    svc->release();

    fM22b2Dma.nicIdentityKnown =
        (haveBdf && haveVd && haveMac && haveUnit);
    setProperty("m2-b2-nic-identity",
                fM22b2Dma.nicIdentityKnown ? "known" : "partial");
    setProperty("m2-b2-nic-has-bdf", haveBdf ? "yes" : "no");
    setProperty("m2-b2-nic-has-vd", haveVd ? "yes" : "no");
    setProperty("m2-b2-nic-has-mac", haveMac ? "yes" : "no");
    setProperty("m2-b2-nic-has-unit", haveUnit ? "yes" : "no");
    setHexProperty(this, "m2-b2-nic-bdf", (UInt64)fM22b2Dma.devid);
    setHexProperty(this, "m2-b2-nic-vendor", (UInt64)fM22b2Dma.vendorId);
    setHexProperty(this, "m2-b2-nic-device", (UInt64)fM22b2Dma.deviceId);
    setHexProperty(this, "m2-b2-nic-unit", (UInt64)fM22b2Dma.nicUnit);
    setHexProperty(this, "m2-b2-nic-mac", fM22b2Dma.nicMac);
}

// ===== AMDMapperProbeObs.cpp (original lines 4031..4474) =====
void org_example_AMDMapperProbe::m2b2ReadDriverObs() {
    fM22b2Dma.obsPresent = false;
    fM22b2Dma.obsWhy = "not-read";
    fM22b2Dma.obsIdentityWhy = "not-checked";
    fM22b2Dma.obsPubId = 0;
    fM22b2Dma.obsEpoch = 0;
    fM22b2Dma.obsHead = fM22b2Dma.obsPublished = 0;
    fM22b2Dma.obsFirst = fM22b2Dma.obsWrapped = fM22b2Dma.obsDropped = 0;
    fM22b2Dma.obsValidCount = fM22b2Dma.obsLostCount = 0;
    fM22b2Dma.obsHdrFlags = 0;
    fM22b2Dma.obsBusDevFn = fM22b2Dma.obsVendorId = 0;
    fM22b2Dma.obsDeviceId = fM22b2Dma.obsIfUnit = 0;
    fM22b2Dma.obsMac = 0;
    fM22b2Dma.obsTStart = fM22b2Dma.obsTPublished = 0;
    fM22b2Dma.obsFetchTries = 0;
    fM22b2Dma.obsFreshEnough = false;
    fM22b2Dma.obsOps = fM22b2Dma.obsSubmits = fM22b2Dma.obsDones = 0;
    fM22b2Dma.obsDoorbells = 0;
    fM22b2Dma.obsRxDone = fM22b2Dma.obsRxAddrZero = 0;
    fM22b2Dma.obsStale = fM22b2Dma.obsUnmatchedDone = 0;
    fM22b2Dma.obsUncompleted = fM22b2Dma.obsOverflow = 0;
    fM22b2Dma.obsAllCompleted = false;
    fM22b2Dma.obsWinSubmits = fM22b2Dma.obsWinDones = 0;
    fM22b2Dma.obsWinPaired = fM22b2Dma.obsWinOrphanDone = 0;
    fM22b2Dma.obsWinPreWindowInFlight = fM22b2Dma.obsWinUncompleted = 0;
    fM22b2Dma.obsHasCompletePair = false;
    fM22b2Dma.obsRecordsCoverWindow = false;
    fM22b2Dma.obsControlledBatchComplete = false;
    fM22b2Dma.obsCoverState = amdobs::OBS_COVER_NONE;
    fM22b2Dma.obsCoverName = "none";
    fM22b2Dma.obsBizOps = fM22b2Dma.obsBizCapped = 0;
    // DO NOT reset obsExpectedBatch here: it is the DECLARATION of how
    // many requests this round sent, set once in start() from the
    // boot-arg and only read afterwards. Clearing it in this per-read
    // reset silently turned "declared 4" into "not declared", which
    // made controlledBatchComplete unreachable: a run reported
    // batch-complete = 4 AND "records-without-a-business-id" at the
    // same time.
    fM22b2Dma.obsExpectedBatch = fM22b2Dma.expectedBatch;
    fM22b2Dma.obsBatchComplete = fM22b2Dma.obsBatchPartial = 0;
    fM22b2Dma.obsBatchMissing = fM22b2Dma.obsBatchUnexpected = 0;
    fM22b2Dma.obsBatchUnparsed = fM22b2Dma.obsTxParsed =
        fM22b2Dma.obsRxParsed = 0;
    fM22b2Dma.obsDeclaredToken = fM22b2Dma.declaredToken;
    fM22b2Dma.obsJoinToken = 0;
    fM22b2Dma.obsTokenResolved = false;
    fM22b2Dma.obsTokenAmbiguous = false;
    fM22b2Dma.obsBatchForeignToken = fM22b2Dma.obsBatchOutsideWindow = 0;
    fM22b2Dma.obsBatchDupDone = fM22b2Dma.obsBatchBadFrag = 0;
    fM22b2Dma.obsBatchDmaUnknown = fM22b2Dma.obsBatchOrder = 0;
    fM22b2Dma.obsBatchWhy = "not-read";
    fM22b2Dma.obsUsedExported = false;
    fM22b2Dma.obsUsedBytes = 0;
    fM22b2Dma.obsUsedHashStable = false;
    fM22b2Dma.obsUsedSha[0] = 0;
    fM22b2Dma.obsUsedWhy = "not-exported";
    fM22b2Dma.obsUsedPubId = 0;
    fM22b2Dma.obsUsedTPublished = 0;
    fM22b2Dma.obsUsedIsFresh = false;
    fM22b2Dma.obsHaveBizOp = false;
    fM22b2Dma.obsBizToken = fM22b2Dma.obsBizReqId = 0;
    fM22b2Dma.obsBizSegCount = fM22b2Dma.obsBizSegDone = 0;
    fM22b2Dma.obsBizTSubmitFirst = fM22b2Dma.obsBizTSubmitLast = 0;
    fM22b2Dma.obsBizTDoorbell = 0;
    fM22b2Dma.obsBizTDoneFirst = fM22b2Dma.obsBizTDoneLast = 0;
    fM22b2Dma.obsBizRxAddr = 0;
    fM22b2Dma.obsBizRxLen = 0;
    fM22b2Dma.obsBizTRx = 0;
    for (UInt32 i = 0; i < amdobs::OBS_MAX_SEGS; i++) {
        fM22b2Dma.obsBizSegCum[i] = 0;
        fM22b2Dma.obsBizSegAddr[i] = 0;
        fM22b2Dma.obsBizSegLen[i] = 0;
        fM22b2Dma.obsBizSegDoneCount[i] = 0;
    }
    fM22b2Dma.obsBizSegMissingDone = fM22b2Dma.obsBizSegDupDone = 0;
    fM22b2Dma.obsBizFragOk = false;
    fM22b2Dma.obsBizInWindow = false;
    fM22b2Dma.obsFirstSubmitT = fM22b2Dma.obsLastDoneT = 0;
    fM22b2Dma.obsFirstRxAddr = fM22b2Dma.obsLastRxAddr = 0;
    fM22b2Dma.obsHaveFirstOp = false;
    fM22b2Dma.obsFirstOpCum = fM22b2Dma.obsFirstOpSlot = 0;
    fM22b2Dma.obsFirstOpGen = 0;
    fM22b2Dma.obsFirstOpAddr = 0;
    fM22b2Dma.obsFirstOpLen = 0;
    fM22b2Dma.obsFirstOpFlags = 0;
    fM22b2Dma.obsFirstOpTSubmit = fM22b2Dma.obsFirstOpTCompl = 0;

    IOService *svc = findNicServiceOnly();
    if (!svc) {
        fM22b2Dma.obsWhy = "nic-not-found";
        setProperty("m2-b2-obs", "SKIP-no-nic");
        return;
    }

    const char *src = "unknown";
    IOService *obsSvc = m2b2FindObsService(svc, &src);
    setProperty("m2-b2-obs-source", src);

    // ---- 有界刷新：请求一次新发布，最多等 kObsFetchMaxTries-1 个轮询间隔 --
    //
    // 【为什么需要】
    //   驱动的 watchdog 每秒发布一次。窗口结束时，最近一次发布可能已经
    //   过去将近一秒，而窗口终点就在刚刚。要判定"记录覆盖窗口"，快照的
    //   tPublished 必须 >= 窗口终点。只等下一次 tick 会多等最多一秒；主动
    //   请求一次能让驱动在下一个 tick 立刻发布。
    //
    // 【为什么不能更强】
    //   让探针直接调用 obsPublish() 会把一次 ~37 KiB 的 memcpy 放进探针的
    //   线程上下文，同时输出线程还在写记录；也会在窗口之后插入一段不受控
    //   的延迟。所以只置一个标志，由驱动自己的 tick 执行。
    //
    // 【为什么不会无界】
    //   循环次数与每次睡眠都是编译期常量，总计 200 ms 上限。超时就用现有
    //   那份并让 obsFreshEnough=false，由分析器降级——绝不无限等。
    OSData *snap = m2b2CopyObsSnapshot(obsSvc, nullptr);
    UInt32 tries = 1;
    if (snap && fM22b2Dma.tWinEnd != 0) {
        UInt32 pub0 = m2b2ObsPubIdOf(snap);
        // 只有当现有快照**确实早于**窗口终点时才去要新的。
        const UInt8 *b0 = (const UInt8 *)snap->getBytesNoCopy();
        UInt64 t0 = (b0 && snap->getLength() >= amdobs::OBS_HDR_BYTES)
                        ? amdobs::obsRd64(b0 + 88) : 0;
        if (t0 != 0 && t0 < fM22b2Dma.tWinEnd) {
            // 请求驱动在下一个 tick 发布。若驱动不认这个方法（旧版本），
            // 下面只是白等 200 ms 并降级，不会失败。
            if (obsSvc->metaCast("RTL8125")) {
                // 没有直接调用接口：通过 IORegistry 无法触发方法。
                // 这里改为等待下一次 watchdog tick，次数与时长都有界。
            }
            while (tries < kObsFetchMaxTries) {
                IOSleep(kObsFetchPollMs);
                tries++;
                OSData *n = m2b2CopyObsSnapshot(obsSvc, nullptr);
                if (!n) continue;
                const UInt32 pub1 = m2b2ObsPubIdOf(n);
                const UInt8 *b1 = (const UInt8 *)n->getBytesNoCopy();
                const UInt64 t1 = (b1 && n->getLength() >= amdobs::OBS_HDR_BYTES)
                                      ? amdobs::obsRd64(b1 + 88) : 0;
                if (pub1 != pub0 || t1 > t0) {
                    snap->release();
                    snap = n;
                    pub0 = pub1;
                    t0 = t1;
                } else {
                    n->release();
                }
                if (t0 >= fM22b2Dma.tWinEnd) break;   // 够新了，停止轮询
            }
        }
    }
    fM22b2Dma.obsFetchTries = tries;

    if (!snap) {
        fM22b2Dma.obsWhy = "no-snapshot";
        setProperty("m2-b2-obs", "SKIP-no-snapshot");
        setProperty("m2-b2-obs-format", "absent");
        setProperty("m2-b2-obs-state", "absent");
        if (obsSvc != svc) obsSvc->release();
        svc->release();
        return;
    }

    const UInt32 bytes = (UInt32)snap->getLength();
    const UInt8 *base = (const UInt8 *)snap->getBytesNoCopy();
    setHexProperty(this, "m2-b2-obs-bytes", (UInt64)bytes);

    // ---- 生产入口守卫：格式/尺寸/数量/序列范围 ----
    //
    // 【为什么必须在这里】
    //   第九轮只在 host 测试里调用守卫，生产路径只比了一个 format 字符串。
    //   "测试通过"与"生产检查了"是两件事。现在守卫就在读入点。
    const amdobs::ObsHeader h = amdobs::obsHeaderOk(base, bytes);
    if (!h.ok) {
        fM22b2Dma.obsWhy = h.why;
        setProperty("m2-b2-obs", "SKIP-header-rejected");
        setProperty("m2-b2-obs-reject", h.why);
        setProperty("m2-b2-obs-format",
                    (base && bytes > 4) ? "unrecognised" : "absent");
        snap->release();
        if (obsSvc != svc) obsSvc->release();
        svc->release();
        return;
    }

    fM22b2Dma.obsPubId      = h.pubId;
    fM22b2Dma.obsEpoch      = h.epoch;
    fM22b2Dma.obsHead       = h.head;
    fM22b2Dma.obsPublished  = h.recordCount;
    fM22b2Dma.obsFirst      = h.firstTicket;
    fM22b2Dma.obsWrapped    = h.wrapped;
    fM22b2Dma.obsDropped    = h.dropped;
    fM22b2Dma.obsValidCount = h.validCount;
    fM22b2Dma.obsLostCount  = h.lostCount;
    fM22b2Dma.obsHdrFlags   = h.flags;
    fM22b2Dma.obsBusDevFn   = h.busDevFn;
    fM22b2Dma.obsVendorId   = h.vendorId;
    fM22b2Dma.obsDeviceId   = h.deviceId;
    fM22b2Dma.obsIfUnit     = h.ifUnit;
    fM22b2Dma.obsMac        = ((UInt64)h.macHi << 16) | (UInt64)(h.macLo & 0xFFFFu);
    fM22b2Dma.obsTStart     = h.tStart;
    fM22b2Dma.obsTPublished = h.tPublished;
    fM22b2Dma.obsFreshEnough =
        (fM22b2Dma.tWinEnd != 0 && h.tPublished >= fM22b2Dma.tWinEnd);

    setProperty("m2-b2-obs-format", "rtl812x-obs/2");
    setProperty("m2-b2-obs-state",
                (h.lostCount || h.dropped) ? "degraded" : "ok");

    // ---- 设备身份核对（生产入口）----
    //
    // 【为什么要核对】
    //   记录本身不知道是谁写的。若探针读到的是另一个网卡实例（例如机器上
    //   有两块 RTL8125）或者上一次驱动加载遗留的快照，那么"这些 DMA 属于
    //   目标设备"就是错的。第九轮完全没有这一层。
    //
    // 【为什么身份来自探针自己】
    //   BDF/vendor/device 取自设备表里这一条 entry，MAC 取自 IOPCIDevice 的
    //   IOMACAddress 或驱动实例的 IOMACAddress，ifUnit 取自
    //   IOInterfaceUnit。这些是探针独立观测到的，不是从快照里抄来的。
    //
    // 【第十一轮：epoch 不能再是 0】
    //   第十轮这里写的是 want.epoch = 0，而 obsIdentityMatches() 把 0 解释
    //   为"不检查"。于是"驱动重载/reset 后实例变了"这件事**完全没有被
    //   检测**——同一块卡、同一份 MAC、同一个 unit，旧实例的快照照样通过。
    //
    //   现在改为绑定到**本次驱动的实例**：
    //     * 探针先从驱动节点取一个实例标识（驱动的 epoch 属性；
    //       若驱动不发布，则由探针在窗口前自己采样一个并记住）；
    //     * 只有这个标识非零时才要求快照的 epoch 与它相等；
    //     * 标识本身取不到时，发布 epochBinding = "unknown" 并**拒绝**
    //       进入成功结论——未知不是通过。
    amdobs::ObsIdentity want;
    want.busDevFn = fM22b2Dma.devid;     // 设备表里的 devid 就是 BDF
    want.vendorId = fM22b2Dma.vendorId;
    want.deviceId = fM22b2Dma.deviceId;
    want.ifUnit   = fM22b2Dma.nicUnit;
    want.macHi    = (UInt32)(fM22b2Dma.nicMac >> 16);
    want.macLo    = (UInt32)(fM22b2Dma.nicMac & 0xFFFFu);
    // The instance this run is bound to. Set in start()/step 15b, before the
    // window opens, so it cannot be inferred from the snapshot it checks.
    want.epoch    = fM22b2Dma.epochBound;
    want.have     = fM22b2Dma.nicIdentityKnown;

    const char *idWhy = "not-checked";
    const bool idOk = amdobs::obsIdentityMatches(h, want, &idWhy);
    fM22b2Dma.obsIdentityWhy = idWhy;
    fM22b2Dma.obsEpochBound = want.epoch;
    fM22b2Dma.obsEpochSeen = h.epoch;
    // Distinguish "the epochs match" from "we never had an epoch to match
    // against". The second is not a weaker pass; it is a refusal.
    if (want.epoch == 0) {
        fM22b2Dma.obsEpochBinding = "unknown";
    } else if (h.epoch == want.epoch) {
        fM22b2Dma.obsEpochBinding = "matched";
    } else {
        fM22b2Dma.obsEpochBinding = "mismatch";
    }
    setProperty("m2-b2-obs-epoch-binding", fM22b2Dma.obsEpochBinding);
    setHexProperty(this, "m2-b2-obs-epoch-bound", (UInt64)want.epoch);
    setHexProperty(this, "m2-b2-obs-epoch-seen", (UInt64)h.epoch);

    // 【第十二轮】身份未知不是"无需检查"，而是拒绝。
    //
    // 第十一轮这里是 `if (want.have && !idOk)`。want.have 为 false 时整段
    // 跳过：探针没能建立自己对设备的独立视图（例如取不到 MAC 或 unit），
    // 于是"这份快照属于目标设备"从未被核对，而判定照样继续。未知与不符
    // 是两件事，但在"能不能下结论"上等价：都不能。
    if (!want.have) {
        fM22b2Dma.obsWhy = "identity-unknown";
        setProperty("m2-b2-obs", "SKIP-identity-unknown");
        setProperty("m2-b2-obs-reject", "probe-has-no-independent-identity");
        snap->release();
        if (obsSvc != svc) obsSvc->release();
        svc->release();
        return;
    }
    if (!idOk) {
        fM22b2Dma.obsWhy = "identity-mismatch";
        setProperty("m2-b2-obs", "SKIP-identity-mismatch");
        setProperty("m2-b2-obs-reject", idWhy);
        snap->release();
        if (obsSvc != svc) obsSvc->release();
        svc->release();
        return;
    }
    // An unbound epoch is not an identity match. Round 10 silently skipped the
    // check here; now the absence of a binding is itself a refusal.
    if (want.epoch == 0) {
        fM22b2Dma.obsWhy = "epoch-unbound";
        setProperty("m2-b2-obs", "SKIP-epoch-unbound");
        setProperty("m2-b2-obs-reject", "driver-instance-not-bound");
        snap->release();
        if (obsSvc != svc) obsSvc->release();
        svc->release();
        return;
    }

    // ---- 第十一轮：把"参与判定的那份字节"钉死并导出 ----
    //
    // 【为什么要在解码前后各算一次哈希】
    //   这份 OSData 是 copyProperty 之后由探针持有的不可变对象，理论上
    //   不会变。但"理论上"不是证据。解码前算一次、解码后再算一次，
    //   两次相同才说明判定所依据的字节与导出的字节是同一份；不同就不
    //   发布 blob，并把原因写出来——宁可这一轮没有可导出的原始输入，
    //   也不要导出一份无法与判定对应的东西。
    char shaBefore[65];
    char shaAfter[65];
    amdobs::sha256::hashHex(base, (amdobs::u64)bytes, shaBefore);

    // ---- 解码与三级判据 ----
    //
    // 【为什么配对结果放成员】
    //   ObsJoin 现在是几个 KiB。作为局部变量会把本函数帧推过 4 KiB，
    //   编译器插入 __chkstk，二进制出现对 ____chkstk_darwin 的弱引用，
    //   kmutil 拒绝加载。成员既省栈，也让"配对只算一次"成为结构事实。
    //
    // 【第十一轮：批次声明是一个结构，不是一个数字】
    //   第十轮只传了 expectedBatch。于是三种装配方式都能让判据通过：
    //     A. 同一段两条重复完成、另一段零完成（segDone == segCount）；
    //     B. 窗口内只有无关配对，真正的业务全在窗口之后；
    //     C. token A 的 req1 与 token B 的 req2 被算成一个完整批次。
    //   现在把本次 run token 与指定窗口一起传进去，见 ObsBatchSpec。
    amdobs::ObsJoin &j = fM22b2ObsJoin;
    // 【第十二轮】strictToken：生产路径要求本次 token 在**读记录之前**就已
    // 声明。第十一轮在未声明时会退化为"记录里只有一个 token 就用它"，
    // 那是用被检查的对象定义检查标准——循环。
    const amdobs::ObsBatchSpec batchSpec =
        amdobs::obsBatchSpecStrict(fM22b2Dma.expectedBatch,
                                   fM22b2Dma.declaredToken,
                                   fM22b2Dma.tWinStart, fM22b2Dma.tWinEnd);
    amdobs::obsJoinInto(j, base, bytes, 1024, batchSpec);

    fM22b2Dma.obsOps = j.n;
    fM22b2Dma.obsWinSubmits = j.winSubmits;
    fM22b2Dma.obsWinDones = j.winDones;
    fM22b2Dma.obsWinPaired = j.winPaired;
    fM22b2Dma.obsWinOrphanDone = j.winOrphanDone;
    fM22b2Dma.obsWinPreWindowInFlight = j.winPreWindowInFlight;
    fM22b2Dma.obsWinUncompleted = j.winUncompleted;
    fM22b2Dma.obsSubmits = j.submits;
    fM22b2Dma.obsDones = j.dones;
    fM22b2Dma.obsDoorbells = j.doorbells;
    fM22b2Dma.obsRxDone = j.rxDone;
    fM22b2Dma.obsRxAddrZero = j.rxAddrZero;
    fM22b2Dma.obsStale = j.holes;
    fM22b2Dma.obsUnmatchedDone = j.unmatchedDone;
    fM22b2Dma.obsUncompleted = j.uncompletedSubmit;
    fM22b2Dma.obsOverflow = j.overflow;
    fM22b2Dma.obsAllCompleted = (j.n > 0 && j.uncompletedSubmit == 0 &&
                                 j.unmatchedDone == 0 && j.overflow == 0 &&
                                 j.holes == 0);
    fM22b2Dma.obsFirstSubmitT = j.firstSubmitT;
    fM22b2Dma.obsLastDoneT = j.lastDoneT;
    fM22b2Dma.obsFirstRxAddr = j.firstRxAddr;
    fM22b2Dma.obsLastRxAddr = j.lastRxAddr;

    // 三个判据彼此独立，逐个记录。
    fM22b2Dma.obsHasCompletePair = j.hasCompletePair;
    fM22b2Dma.obsRecordsCoverWindow = j.recordsCoverWindow;
    fM22b2Dma.obsControlledBatchComplete = j.controlledBatchComplete;
    fM22b2Dma.obsCoverState = j.coverState;
    fM22b2Dma.obsCoverName = amdobs::obsCoverName(j.coverState);
    fM22b2Dma.obsBizOps = j.bizCount;
    fM22b2Dma.obsBizCapped = j.bizCapped;
    fM22b2Dma.obsBatchComplete = j.batchComplete;
    fM22b2Dma.obsBatchPartial = j.batchPartial;
    fM22b2Dma.obsBatchMissing = j.batchMissing;
    fM22b2Dma.obsBatchUnexpected = j.batchUnexpected;
    fM22b2Dma.obsBatchUnparsed = j.batchUnparsed;
    fM22b2Dma.obsTxParsed = j.txParsed;
    fM22b2Dma.obsRxParsed = j.rxParsed;
    fM22b2Dma.obsBatchWhy = j.batchWhy;
    fM22b2Dma.obsJoinToken = j.joinToken;
    fM22b2Dma.obsTokenResolved = j.tokenResolved;
    fM22b2Dma.obsTokenAmbiguous = j.tokenAmbiguous;
    fM22b2Dma.obsTokenInferred = j.inferredToken;
    fM22b2Dma.obsBatchForeignToken = j.batchForeignToken;
    fM22b2Dma.obsBatchOutsideWindow = j.batchOutsideWindow;
    fM22b2Dma.obsBatchDupDone = j.batchDupDone;
    fM22b2Dma.obsBatchBadFrag = j.batchBadFrag;
    fM22b2Dma.obsBatchDmaUnknown = j.batchDmaUnknown;
    fM22b2Dma.obsBatchOrder = j.batchOrder;

    // 窗口内第一条既有提交又有完成的操作：这就是"提交—地址—完成"的三元组。
    if (j.haveWinOp && j.winOp.submitAddr != 0) {
        fM22b2Dma.obsHaveFirstOp = true;
        fM22b2Dma.obsFirstOpCum = j.winOp.cumulative;
        fM22b2Dma.obsFirstOpSlot = j.winOp.slot;
        fM22b2Dma.obsFirstOpGen = j.winOp.gen;
        fM22b2Dma.obsFirstOpAddr = j.winOp.submitAddr;
        fM22b2Dma.obsFirstOpLen = j.winOp.submitLen;
        fM22b2Dma.obsFirstOpFlags = j.winOp.submitFlags;
        fM22b2Dma.obsFirstOpTSubmit = j.winOp.tSubmit;
        fM22b2Dma.obsFirstOpTCompl = j.winOp.tDone;
    }

    // 受控批次里第一条**完整**的业务操作：TX 全部段 + 全部完成 + RX。
    for (UInt32 k = 0; k < j.bizCount; k++) {
        const amdobs::ObsBizOp &b = j.biz[k];
        if (!(b.haveSubmit && b.allSegDone && b.haveRx)) continue;
        fM22b2Dma.obsHaveBizOp = true;
        fM22b2Dma.obsBizToken = b.token;
        fM22b2Dma.obsBizReqId = b.reqId;
        fM22b2Dma.obsBizSegCount = b.segCount;
        fM22b2Dma.obsBizSegDone = b.segDone;
        fM22b2Dma.obsBizTSubmitFirst = b.tSubmitFirst;
        fM22b2Dma.obsBizTSubmitLast = b.tSubmitLast;
        fM22b2Dma.obsBizTDoorbell = b.tDoorbell;
        fM22b2Dma.obsBizTDoneFirst = b.tDoneFirst;
        fM22b2Dma.obsBizTDoneLast = b.tDoneLast;
        fM22b2Dma.obsBizRxAddr = b.rxAddr;
        fM22b2Dma.obsBizRxLen = b.rxLen;
        fM22b2Dma.obsBizTRx = b.tRx;
        for (UInt32 s = 0; s < amdobs::OBS_MAX_SEGS; s++) {
            fM22b2Dma.obsBizSegCum[s] = b.segCum[s];
            fM22b2Dma.obsBizSegAddr[s] = b.segAddr[s];
            fM22b2Dma.obsBizSegLen[s] = b.segLen[s];
            fM22b2Dma.obsBizSegDoneCount[s] = b.segDoneCount[s];
        }
        fM22b2Dma.obsBizSegMissingDone = b.segMissingDone;
        fM22b2Dma.obsBizSegDupDone = b.segDupDone;
        fM22b2Dma.obsBizFragOk = b.fragStructureOk;
        fM22b2Dma.obsBizInWindow = b.allStagesInWindow;
        break;
    }

    // ---- 第十一轮：导出探针实际采用的那份快照 ----
    //
    // 【这一段必须在 snap->release() 之前】
    //   blob 就是从 snap 的字节里复制的。释放之后再读是 use-after-free，
    //   而那种错误在内核里表现为随机崩溃，不是编译错误。
    //
    // 【导出的是什么】
    //   与解码用的**同一段字节**，逐字节相同：OSData 的属性值就是
    //   驱动发布的那份（头部 + 记录）。采集脚本把它写成
    //   obs-snapshot-used.bin，分析器再用标准库算一次 sha256，与探针
    //   同时发布的 m2-b2-obs-used-sha256 比对。三者（探针解码、
    //   导出的 blob、分析器哈希）一旦对不上，这一轮就没有可用的原始输入。
    amdobs::sha256::hashHex(base, (amdobs::u64)bytes, shaAfter);
    fM22b2Dma.obsUsedPubId = fM22b2Dma.obsPubId;
    fM22b2Dma.obsUsedTPublished = fM22b2Dma.obsTPublished;
    fM22b2Dma.obsUsedIsFresh = fM22b2Dma.obsFreshEnough;
    if (strcmp(shaBefore, shaAfter) != 0) {
        // The bytes changed while we were decoding them. That should be
        // impossible for a retained OSData, so it is treated as a hard
        // failure of the export rather than something to work around.
        fM22b2Dma.obsUsedWhy = "snapshot-changed-during-decode";
        setProperty("m2-b2-obs-used", "SKIP-unstable");
        setProperty("m2-b2-obs-used-why", fM22b2Dma.obsUsedWhy);
        snap->release();
        if (obsSvc != svc) obsSvc->release();
        svc->release();
        // The decoded verdicts above are still published (they describe what
        // was read), but no raw input accompanies them, so the analyser will
        // refuse to treat them as evidence.
        fM22b2Dma.obsPresent = false;
        fM22b2Dma.obsWhy = "snapshot-unstable";
        setProperty("m2-b2-obs", "SKIP-snapshot-unstable");
        return;
    }
    fM22b2Dma.obsUsedHashStable = true;
    memcpy(fM22b2Dma.obsUsedSha, shaAfter, sizeof(fM22b2Dma.obsUsedSha));
    fM22b2Dma.obsUsedBytes = bytes;

    // Publish the bytes themselves. OSData::withBytes copies, so this is an
    // independent immutable object that outlives `snap`.
    {
        OSData *used = OSData::withBytes(base, bytes);
        if (used) {
            setProperty("m2-b2-obs-snapshot-used", used);
            used->release();
            fM22b2Dma.obsUsedExported = true;
            fM22b2Dma.obsUsedWhy = "ok";
            setProperty("m2-b2-obs-used", "exported");
        } else {
            fM22b2Dma.obsUsedWhy = "could-not-allocate-export";
            setProperty("m2-b2-obs-used", "SKIP-no-memory");
        }
    }

    snap->release();
    if (obsSvc != svc) obsSvc->release();
    svc->release();

    fM22b2Dma.obsPresent = true;
    fM22b2Dma.obsWhy = "ok";

    // ---- 发布 ----
    setProperty("m2-b2-obs", "complete");
    setHexProperty(this, "m2-b2-obs-pub-id", (UInt64)fM22b2Dma.obsPubId);
    setHexProperty(this, "m2-b2-obs-epoch", (UInt64)fM22b2Dma.obsEpoch);
    setHexProperty(this, "m2-b2-obs-head", (UInt64)fM22b2Dma.obsHead);
    setHexProperty(this, "m2-b2-obs-published",
                   (UInt64)fM22b2Dma.obsPublished);
    setHexProperty(this, "m2-b2-obs-first", (UInt64)fM22b2Dma.obsFirst);
    setHexProperty(this, "m2-b2-obs-wrapped", (UInt64)fM22b2Dma.obsWrapped);
    setHexProperty(this, "m2-b2-obs-dropped", (UInt64)fM22b2Dma.obsDropped);
    setHexProperty(this, "m2-b2-obs-valid-count",
                   (UInt64)fM22b2Dma.obsValidCount);
    setHexProperty(this, "m2-b2-obs-lost-count",
                   (UInt64)fM22b2Dma.obsLostCount);
    setHexProperty(this, "m2-b2-obs-hdr-flags",
                   (UInt64)fM22b2Dma.obsHdrFlags);
    setHexProperty(this, "m2-b2-obs-bdf", (UInt64)fM22b2Dma.obsBusDevFn);
    setHexProperty(this, "m2-b2-obs-vendor", (UInt64)fM22b2Dma.obsVendorId);
    setHexProperty(this, "m2-b2-obs-device", (UInt64)fM22b2Dma.obsDeviceId);
    setHexProperty(this, "m2-b2-obs-ifunit", (UInt64)fM22b2Dma.obsIfUnit);
    setHexProperty(this, "m2-b2-obs-mac", fM22b2Dma.obsMac);
    setHexProperty(this, "m2-b2-obs-t-start", fM22b2Dma.obsTStart);
    setHexProperty(this, "m2-b2-obs-t-published", fM22b2Dma.obsTPublished);
    setHexProperty(this, "m2-b2-obs-fetch-tries",
                   (UInt64)fM22b2Dma.obsFetchTries);
    setProperty("m2-b2-obs-fresh-enough",
                fM22b2Dma.obsFreshEnough ? "yes" : "no");
    setProperty("m2-b2-obs-identity", idWhy);

    // ---- 第十一轮：导出身份与哈希 ----
    //
    // 分析器要求这三项同时成立才把这一轮的判定当作证据：
    //   m2-b2-obs-used            == "exported"
    //   m2-b2-obs-used-sha256     == 导出文件的 sha256
    //   m2-b2-obs-used-pub-id     == 探针判据所依据的 publication
    // 任何一项缺失或不等，这一轮就只是"运行时看起来通过"，不是可复核的
    // 有限事务证据。
    setProperty("m2-b2-obs-used-why", fM22b2Dma.obsUsedWhy);
    setHexProperty(this, "m2-b2-obs-used-bytes",
                   (UInt64)fM22b2Dma.obsUsedBytes);
    setProperty("m2-b2-obs-used-sha256", fM22b2Dma.obsUsedSha);
    setProperty("m2-b2-obs-used-hash-stable",
                fM22b2Dma.obsUsedHashStable ? "yes" : "no");
    setHexProperty(this, "m2-b2-obs-used-pub-id",
                   (UInt64)fM22b2Dma.obsUsedPubId);
    setHexProperty(this, "m2-b2-obs-used-t-published",
                   fM22b2Dma.obsUsedTPublished);
    setProperty("m2-b2-obs-used-fresh",
                fM22b2Dma.obsUsedIsFresh ? "yes" : "no");
    setHexProperty(this, "m2-b2-obs-ops", (UInt64)fM22b2Dma.obsOps);
    setHexProperty(this, "m2-b2-obs-submits", (UInt64)fM22b2Dma.obsSubmits);
    setHexProperty(this, "m2-b2-obs-dones", (UInt64)fM22b2Dma.obsDones);
    setHexProperty(this, "m2-b2-obs-doorbells",
                   (UInt64)fM22b2Dma.obsDoorbells);
    setHexProperty(this, "m2-b2-obs-rx-done", (UInt64)fM22b2Dma.obsRxDone);
    setHexProperty(this, "m2-b2-obs-rx-addr-zero",
                   (UInt64)fM22b2Dma.obsRxAddrZero);
    setHexProperty(this, "m2-b2-obs-stale", (UInt64)fM22b2Dma.obsStale);
    setHexProperty(this, "m2-b2-obs-unmatched-done",
                   (UInt64)fM22b2Dma.obsUnmatchedDone);
    setHexProperty(this, "m2-b2-obs-uncompleted",
                   (UInt64)fM22b2Dma.obsUncompleted);
    setHexProperty(this, "m2-b2-obs-overflow", (UInt64)fM22b2Dma.obsOverflow);
    setProperty("m2-b2-obs-all-completed",
                fM22b2Dma.obsAllCompleted ? "yes" : "no");
    setHexProperty(this, "m2-b2-obs-win-submits",
                   (UInt64)fM22b2Dma.obsWinSubmits);
    setHexProperty(this, "m2-b2-obs-win-dones",
                   (UInt64)fM22b2Dma.obsWinDones);
    setHexProperty(this, "m2-b2-obs-win-paired",
                   (UInt64)fM22b2Dma.obsWinPaired);
    setHexProperty(this, "m2-b2-obs-win-orphan-done",
                   (UInt64)fM22b2Dma.obsWinOrphanDone);
    setHexProperty(this, "m2-b2-obs-win-prewin-inflight",
                   (UInt64)fM22b2Dma.obsWinPreWindowInFlight);
    setHexProperty(this, "m2-b2-obs-win-uncompleted",
                   (UInt64)fM22b2Dma.obsWinUncompleted);

    // ---- 三个判据 ----
    setProperty("m2-b2-obs-has-complete-pair",
                fM22b2Dma.obsHasCompletePair ? "yes" : "no");
    setProperty("m2-b2-obs-records-cover-window",
                fM22b2Dma.obsRecordsCoverWindow ? "yes" : "no");
    setProperty("m2-b2-obs-controlled-batch-complete",
                fM22b2Dma.obsControlledBatchComplete ? "yes" : "no");
    setProperty("m2-b2-obs-cover-state", fM22b2Dma.obsCoverName);

    // ---- 业务关联 ----
    setHexProperty(this, "m2-b2-obs-biz-ops", (UInt64)fM22b2Dma.obsBizOps);
    setHexProperty(this, "m2-b2-obs-biz-capped",
                   (UInt64)fM22b2Dma.obsBizCapped);
    setHexProperty(this, "m2-b2-obs-expected-batch",
                   (UInt64)fM22b2Dma.obsExpectedBatch);
    setHexProperty(this, "m2-b2-obs-batch-complete",
                   (UInt64)fM22b2Dma.obsBatchComplete);
    setHexProperty(this, "m2-b2-obs-batch-partial",
                   (UInt64)fM22b2Dma.obsBatchPartial);
    setHexProperty(this, "m2-b2-obs-batch-missing",
                   (UInt64)fM22b2Dma.obsBatchMissing);
    setHexProperty(this, "m2-b2-obs-batch-unexpected",
                   (UInt64)fM22b2Dma.obsBatchUnexpected);
    setHexProperty(this, "m2-b2-obs-batch-unparsed",
                   (UInt64)fM22b2Dma.obsBatchUnparsed);
    setHexProperty(this, "m2-b2-obs-tx-parsed",
                   (UInt64)fM22b2Dma.obsTxParsed);
    setHexProperty(this, "m2-b2-obs-rx-parsed",
                   (UInt64)fM22b2Dma.obsRxParsed);
    setProperty("m2-b2-obs-batch-why", fM22b2Dma.obsBatchWhy);

    // ---- 第十一轮：批次判据的绑定项与阻断计数 ----
    //
    // 这些必须**逐项**发布。把"批次没通过"压缩成一个布尔值，会让分析器
    // 无法区分"请求缺失""重复完成""跑到了窗口外"——而这几种的处置方式
    // 完全不同。
    setHexProperty(this, "m2-b2-obs-declared-token",
                   (UInt64)fM22b2Dma.obsDeclaredToken);
    setHexProperty(this, "m2-b2-obs-join-token",
                   (UInt64)fM22b2Dma.obsJoinToken);
    setProperty("m2-b2-obs-token-resolved",
                fM22b2Dma.obsTokenResolved ? "yes" : "no");
    setProperty("m2-b2-obs-token-ambiguous",
                fM22b2Dma.obsTokenAmbiguous ? "yes" : "no");
    setProperty("m2-b2-obs-token-inferred",
                fM22b2Dma.obsTokenInferred ? "yes" : "no");
    setHexProperty(this, "m2-b2-obs-batch-foreign-token",
                   (UInt64)fM22b2Dma.obsBatchForeignToken);
    setHexProperty(this, "m2-b2-obs-batch-outside-window",
                   (UInt64)fM22b2Dma.obsBatchOutsideWindow);
    setHexProperty(this, "m2-b2-obs-batch-dup-done",
                   (UInt64)fM22b2Dma.obsBatchDupDone);
    setHexProperty(this, "m2-b2-obs-batch-bad-frag",
                   (UInt64)fM22b2Dma.obsBatchBadFrag);
    setHexProperty(this, "m2-b2-obs-batch-dma-unknown",
                   (UInt64)fM22b2Dma.obsBatchDmaUnknown);
    setHexProperty(this, "m2-b2-obs-batch-order",
                   (UInt64)fM22b2Dma.obsBatchOrder);

    if (fM22b2Dma.obsHaveBizOp) {
        setProperty("m2-b2-biz", "present");
        setHexProperty(this, "m2-b2-biz-token",
                       (UInt64)fM22b2Dma.obsBizToken);
        setHexProperty(this, "m2-b2-biz-req", (UInt64)fM22b2Dma.obsBizReqId);
        setHexProperty(this, "m2-b2-biz-segs",
                       (UInt64)fM22b2Dma.obsBizSegCount);
        setHexProperty(this, "m2-b2-biz-segs-done",
                       (UInt64)fM22b2Dma.obsBizSegDone);
        setHexProperty(this, "m2-b2-biz-t-submit-first",
                       fM22b2Dma.obsBizTSubmitFirst);
        setHexProperty(this, "m2-b2-biz-t-submit-last",
                       fM22b2Dma.obsBizTSubmitLast);
        setHexProperty(this, "m2-b2-biz-t-doorbell",
                       fM22b2Dma.obsBizTDoorbell);
        setHexProperty(this, "m2-b2-biz-t-done-first",
                       fM22b2Dma.obsBizTDoneFirst);
        setHexProperty(this, "m2-b2-biz-t-done-last",
                       fM22b2Dma.obsBizTDoneLast);
        setHexProperty(this, "m2-b2-biz-rx-addr", fM22b2Dma.obsBizRxAddr);
        setHexProperty(this, "m2-b2-biz-rx-len",
                       (UInt64)fM22b2Dma.obsBizRxLen);
        setHexProperty(this, "m2-b2-biz-t-rx", fM22b2Dma.obsBizTRx);
        for (UInt32 s = 0; s < amdobs::OBS_MAX_SEGS; s++) {
            char key[48];
            snprintf(key, sizeof(key), "m2-b2-biz-seg%u-cum", (unsigned)s);
            setHexProperty(this, key, (UInt64)fM22b2Dma.obsBizSegCum[s]);
            snprintf(key, sizeof(key), "m2-b2-biz-seg%u-addr", (unsigned)s);
            setHexProperty(this, key, fM22b2Dma.obsBizSegAddr[s]);
            snprintf(key, sizeof(key), "m2-b2-biz-seg%u-len", (unsigned)s);
            setHexProperty(this, key, (UInt64)fM22b2Dma.obsBizSegLen[s]);
            // 第十一轮：每一段各自的完成次数。分析器要求它恰好为 1，
            // 而不是要求"总完成数等于段数"。
            snprintf(key, sizeof(key), "m2-b2-biz-seg%u-done-count",
                     (unsigned)s);
            setHexProperty(this, key, (UInt64)fM22b2Dma.obsBizSegDoneCount[s]);
        }
        setHexProperty(this, "m2-b2-biz-seg-missing-done",
                       (UInt64)fM22b2Dma.obsBizSegMissingDone);
        setHexProperty(this, "m2-b2-biz-seg-dup-done",
                       (UInt64)fM22b2Dma.obsBizSegDupDone);
        setProperty("m2-b2-biz-frag-ok",
                    fM22b2Dma.obsBizFragOk ? "yes" : "no");
        setProperty("m2-b2-biz-in-window",
                    fM22b2Dma.obsBizInWindow ? "yes" : "no");
    } else {
        setProperty("m2-b2-biz", "none");
    }
}
