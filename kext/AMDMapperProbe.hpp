#pragma once
#include <IOKit/IOMapper.h>
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/IODMACommand.h>
#include <kern/thread.h>

// 设备 DMA 观察用的纯逻辑核心（区间集合、fault 分类、描述符解码）。
// 与 host 回归测试包含同一个文件，见 tests/dma-observe-test.cpp。
#include "amd_iommu_dma_observe.hpp"

// 第十四轮：RX 投递缓冲区集合的构造与解码。同样是"探针与 host 回归编译
// 同一个文件"，见 tests/rxpost-test.cpp。
#include "amd_iommu_rxset_core.hpp"
#include "../tools/lucy-obs/RTL812xRxPool.hpp"
#include "../tools/lucy-obs/RTL812xRxMap.hpp"
#include "../tools/lucy-obs/RTL812xRxNative.hpp"
#include "../tools/lucy-obs/RTL812xFixedDma.hpp"
// Round17: native-mbuf TX mapping ABI (round16's RTL812xTxMap.hpp is kept as
// the archived staging ABI and is no longer included by the probe).
#include "../tools/lucy-obs/RTL812xTxMapNative.hpp"

class IOTimerEventSource;   // 前置声明，避免头文件相互包含
class R27ProbeTimer;

// M1-B 探针（B1 + B2-0 + B2-a）
//
// B1：给真实但不做 DMA 的设备 IOMA（pci1022,1481）设 iommu-parent，
//     验证 copyMapperForDevice(realDevice) 返回本 mapper。
//
// B2-0：用**自己的** IOBufferMemoryDescriptor + 自己的 mapper 构造一次
//       真实的 IODMACommand 流程，记录 iovmMapMemory 实际收到的参数。
//
// B2-a：真正实现「物理连续单段」的恒等映射，并观察成功路径。
//       关键约束：*mapLength 必须**恰好等于** length。
//       返回比 length 更大的值会让 IODMACommand 走进多段分支，
//       而那条分支在 IODMACommand.cpp:946 有
//           assert(mapArgs.fAllocLength > mapArgs.fLength);
//       恒等映射给不出更长的区间，一旦走到就会 panic。
//       返回恰好 length 则 fAllocLength == fLength，多段分支整个跳过。
//
// 明确不做：
//   - 不发布 gSystem（fIsSystem 恒 false）
//   - 不支持碎片化 buffer（接口表达力不足，见 m1b-b2-0-result.md §6）
//   - 不改任何第三方驱动
class org_example_AMDMapperProbe : public IOMapper {
    OSDeclareDefaultStructors(org_example_AMDMapperProbe);

protected:
    bool initHardware(IOService *provider) override;

public:
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    IOReturn setProperties(OSObject *properties) override;

    uint64_t getPageSize() const override;

    IOReturn iovmMapMemory(IOMemoryDescriptor *memory,
        uint64_t descriptorOffset,
        uint64_t length,
        uint32_t mapOptions,
        const IODMAMapSpecification *mapSpecification,
        IODMACommand *dmaCommand,
        const IODMAMapPageList *pageList,
        uint64_t *mapAddress,
        uint64_t *mapLength) override;

    IOReturn iovmUnmapMemory(IOMemoryDescriptor *memory,
        IODMACommand *dmaCommand,
        uint64_t mapAddress,
        uint64_t mapLength) override;

    IOReturn iovmInsert(uint32_t options,
        uint64_t mapAddress,
        uint64_t offset,
        uint64_t physicalAddress,
        uint64_t length) override;

    uint64_t mapToPhysicalAddress(uint64_t mappedAddress) override;

private:
    IOService *fTarget;          // B1 靶子（IOMA）
    // Round44: a persistent per-device mapper. Ordinary IODMACommand calls
    // use this backend without the experiment's registered object bindings.
    bool fR44Auto = false;
    struct R44Controller;
    R44Controller *fR44Controller = nullptr;
    struct R44MapperState;
    R44MapperState *fR44Mapper = nullptr;
    bool r44StartAuto();
    bool r44AttachAuto(IOService *);
    bool r44StopAuto();
    bool r44Invalidate();
    void r44PublishAuto();
    bool r44PrepareMappings(volatile UInt64 *, UInt64, UInt32, UInt32);
    bool r44QuiesceMappings();
    bool r44ReleaseMappings();
    UInt32 r44LiveMappings() const;
    void r44PublishMappings();
    IOReturn r44MapMemory(IOMemoryDescriptor *, uint64_t, uint64_t, uint32_t,
        const IODMAMapSpecification *, IODMACommand *, const IODMAMapPageList *,
        uint64_t *, uint64_t *);
    IOReturn r44UnmapMemory(IOMemoryDescriptor *, IODMACommand *, uint64_t, uint64_t);
    bool r44Translate(uint64_t, uint64_t *) const;

    // Round17: native-mbuf TX mapping. One live owner, evidence and command
    // budget bounded separately (see kext/AMDMapperProbeTx.cpp).
    struct R17Domain;
    R17Domain *fR17 = nullptr;
    bool r17Prepare(volatile UInt64 *, UInt64, UInt32);
    bool r17Activate(volatile UInt8 *, void *);
    void r17Export(void *);
    static IOReturn r17Callback(void *, UInt32, r17tx::Request *);
    void r17Release();
    // ---- round 21/22: the translation window edges ----
    //
    // The window is not "the period between two r17* calls"; it is the period
    // during which the device actually translates through this backend. Both
    // edges are ordered against the ORDINARY output path, which keeps running,
    // so both are built on the driver's submission barrier rather than on a
    // flag the probe sets and hopes nobody is inside:
    //
    //   enter: stop admission -> wait for admitted submitters to set OWN ->
    //          wait for the ring to hold nothing -> flip DTE + invalidate ->
    //          confirm -> open admission
    //   exit:  stop admission -> wait submitters -> drain the ring ->
    //          forced exit sample -> restore DTE + flush + read back ->
    //          detach -> resume ordinary output
    //
    // `r17Gate` is the single place that talks to the barrier; `r17StopSubmit`
    // is the only wait, and it runs on the probe's thread -- never inside the
    // driver's gate or workloop.
    bool r17Gate(bool quiesce, UInt32 *outstanding, UInt32 *activeCover,
                 UInt32 *inFlight = nullptr, UInt32 *ringOwn = nullptr);
    // Closes admission, then waits for submitters, descriptors, driver held/live
    // generations and backend owners to drain, with every retirement and command
    // completion confirmed. Polling does not hold the driver's gate or d->lock.
    bool r17StopSubmit(UInt32 budgetMs, const char *edge);
    bool r17BackendDrained();
    // Second half of the enter edge: only after the DTE flip and both domain
    // invalidations completed. `tInvComplete` is that completion time, which is
    // what "translation is in effect from here" means.
    bool r17EnterComplete(UInt64 tInvComplete);
    // Exit, after the caller restored the device table and read it back:
    // revoke controlled admission and release the backend, then (separately)
    // let ordinary output flow again. Neither opens admission implicitly.
    bool r17Detach();
    bool r17ResumeOutput();
    // Round22: the translation-off time is decided by AMDMapperProbePgt.cpp (it
    // is the register read-back), but the value belongs to the window record.
    // R17Domain is private to AMDMapperProbeTx.cpp, so it travels through here
    // instead of being written across translation units.
    void r17SetTranslateOff(UInt64);
    // Round22: the domain keeps its own copy of the command-ring cursors, which
    // it uses for every invalidation (map, unmap, cover). The caller must hand
    // it the CURRENT position after it has submitted commands on its own copy --
    // otherwise the domain appends at a stale slot and its CompletionWait never
    // arrives. This is exactly what moving Install before the DTE flip exposed.
    void r17SyncCommand(void *);
    // R17Domain is incomplete outside AMDMapperProbeTx.cpp; the window state is
    // read through this instead of by reaching into the struct.
    bool r17Installed() const;
    // Force the driver to sample the ring for a specific window step.
    void r17SampleExit(UInt32 stage);
    void r17PublishWindow();
    // Round18: the SAME domain, entered through the IOMapper virtuals that
    // IODMACommand calls, instead of through the platform callback. Bounded to
    // one physically contiguous page run per call (the layout a single-mbuf TX
    // packet has); everything else is refused before any PTE is written.
    bool r18StdReady() const;
    bool r32CapacityProbe();
    // True only for an address inside the domain's own bounded IOVA window, so
    // an unrelated mapper call can never be routed into (or counted as) this
    // path.
    bool r18StdOwnsAddress(uint64_t iova) const;
    // Real page-table translation for mapToPhysicalAddress(); false when the
    // entry is absent (never a fabricated identity result).
    bool r18StdTranslate(uint64_t iova, uint64_t *outPA) const;
    IOReturn r18StdMap(IOMemoryDescriptor *, uint64_t, uint64_t, uint32_t,
        const IODMAMapSpecification *, IODMACommand *, const IODMAMapPageList *,
        uint64_t *, uint64_t *);
    IOReturn r18StdUnmap(IOMemoryDescriptor *, IODMACommand *, uint64_t, uint64_t);
    // Published counters, so "the standard path ran" is never inferred from the
    // driver's own success string.
    uint32_t fStdMapCalls = 0, fStdMapOk = 0, fStdMapRejects = 0;
    uint32_t fStdUnmapCalls = 0, fStdUnmapOk = 0;
    uint32_t fStdPageRuns = 0, fStdFragRejects = 0, fStdOffsetRejects = 0;
    uint32_t fStdInsertRejects = 0, fStdWalkCalls = 0;
    /* round19: multi-run windows */
    uint32_t fStdRuns = 0, fStdDiscontig = 0, fStdMaxRuns = 0, fStdCapRejects = 0;
    void publishStdStats();

    // Round30: 1024 cyclic RX mappings. Commands are registered by BOTH object
    // identities before IOKit can call the mapper. They never consume TX slots.
    struct R27RxDomain;
    R27RxDomain *fR27Rx = nullptr;
    bool r27RxRequested() const;
    bool r27RxBegin();
    void r27RxReady();
    bool r27RxFinish(UInt32 budgetMs);
    bool r29WaitTailDone(UInt32 budgetMs);
    void r27RxExport();
    void r27RxRelease();
    IOReturn r27RxControl(UInt32 op);
    bool r27RxCandidate(IOMemoryDescriptor *, IODMACommand *) const;
    bool r27RxOwnsAddress(uint64_t) const;
    bool r27RxTranslate(uint64_t, uint64_t *) const;
    IOReturn r27RxMap(IOMemoryDescriptor *, uint64_t, uint64_t, uint32_t,
        const IODMAMapSpecification *, IODMACommand *, const IODMAMapPageList *,
        uint64_t *, uint64_t *);
    IOReturn r27RxUnmap(IOMemoryDescriptor *, IODMACommand *, uint64_t, uint64_t);

    // Round34: Lucy owns the standard objects and replaces the real RX mbufs.
    // This service owns only routing identities, PTEs and mapping evidence.
    struct R34RxDomain;
    R34RxDomain *fR34Rx = nullptr;
    bool r40FixedCandidate(IOMemoryDescriptor *, IODMACommand *) const;
    bool r40FixedOwnsAddress(uint64_t) const;
    bool r40FixedTranslate(uint64_t, uint64_t *) const;
    bool r40FixedReadPA(UInt32, UInt64, UInt64, UInt64 *) const;
    IOReturn r40FixedOperation(r34rx::Binding *);
    IOReturn r40FixedMap(IOMemoryDescriptor *, uint64_t, uint64_t, uint32_t,
        const IODMAMapSpecification *, IODMACommand *, const IODMAMapPageList *,
        uint64_t *, uint64_t *);
    IOReturn r40FixedUnmap(IOMemoryDescriptor *, IODMACommand *, uint64_t, uint64_t);
    bool r34RxPrepareMap(volatile UInt64 *, UInt64, UInt32, UInt32);
    bool r34RxStopBeforeDte();
    bool r34RxBegin();
    bool r34RxAuthorize();
    bool r34RxResumePhysical();
    bool r34RxFinish(UInt32 budgetMs);
    bool r34RxTailDone(UInt32 budgetMs);
    void r34RxReady();
    void r34RxExport();
    void r34RxRelease();
    IOReturn r34RxControl(UInt32 op);
    static int r34RxCallback(void *, r34rx::Binding *);
    IOReturn r34RxOperation(r34rx::Binding *);
    IOReturn r34RxBatch(r34rx::Binding *);
    bool r34RxCandidate(IOMemoryDescriptor *, IODMACommand *) const;
    IOReturn r34RxMap(IOMemoryDescriptor *, uint64_t, uint64_t, uint32_t,
        const IODMAMapSpecification *, IODMACommand *, const IODMAMapPageList *,
        uint64_t *, uint64_t *);
    IOReturn r34RxUnmap(IOMemoryDescriptor *, IODMACommand *, uint64_t, uint64_t);

    // ---- B2 观测计数器 ----
    // iovmMapMemory 可能被高频调用，不能每次都 setProperty（会持续分配内存）。
    // 策略：只记录第一次、最后一次与累计次数，次数变化时才刷新属性。
    uint32_t fMapCalls;
    uint32_t fUnmapCalls;
    uint32_t fInsertCalls;
    uint32_t fPhysAddrCalls;
    uint32_t fPublishedMapCalls;

    // ---- B2-a 判定结果 ----
    uint32_t fMapOkCalls;          // 物理连续、已成功返回恒等映射
    uint32_t fMapRejectFragCalls;  // 物理不连续 → kIOReturnUnsupported
    uint32_t fMapRejectOtherCalls; // 参数不合法 / 窗口关闭
    uint32_t fUnmapOkCalls;

    // 安全闸门（自测用）：只有探针自测期间才允许真正返回成功。
    // 除了「窗口打开」之外还要求 dmaCommand 必须是探针自己创建的那个，
    // 这样即使将来有真实设备拿到本 mapper，也不可能在自测窗口内
    // 拿到一个「看起来成功」的映射。
    bool fMapWindowOpen;
    IODMACommand *fExpectedCmd;

    // 「这次调用来自探针自己」的标志，与 fMapWindowOpen 是两回事：
    //   fProbeCallActive  本次 setMemoryDescriptor 是探针发起的（B2-0 / B2-a）
    //   fMapWindowOpen    这次允许返回成功（只有 B2-a 的两组对照会打开）
    // B2-0 是「探针发起但窗口关闭」，若只用窗口判断，它会被误算成
    // 「真实设备调用」——0.6.0 首次部署就踩了这个坑（m1bb-realmapcalls
    // 报 1，其实来自 B2-0 的 16 KiB buffer）。
    bool fProbeCallActive;

    // ---- B2-b：真实设备支持 ----
    //
    // 与 B2-a 的根本差别：B2-a 同一时刻只维护**一个**活跃映射（自测串行），
    // 而 RTL812xLucy 在 start() 里就要同时建立**三个**映射：
    //   txBufDesc  (16 KiB)  setupTxResources()   → txDescDmaCmd
    //   rxBufDesc  (16 KiB)  setupRxResources()   → rxDescDmaCmd
    //   statBufDesc(~300 B)  setupStatResources() → statDescDmaCmd
    // 之后若 useAppleVTD 为真还会再映射数据包 buffer。
    // 所以必须改成映射表，不能再用单变量。
    //
    // 为什么是固定数组而不是动态分配：iovmMapMemory 可能在中断/门控上下文
    // 被调用，那里不能安全地 IOMalloc。32 项对当前用途绰绰有余，
    // 满了就返回失败并计数（宁可拒绝，也不要在内核里分配内存）。
    enum { kMaxActiveMaps = 32 };

    struct MapEntry {
        uint64_t pa;        // 物理地址（恒等映射下也等于 IOVA）
        uint64_t len;
        bool     used;
    };
    MapEntry fMaps[kMaxActiveMaps];

    // 真实设备闸门：只有 boot-arg `amdiommu=arm` 时才允许真实设备拿到映射。
    // 这是第二道独立开关——装了卡不等于自动放行，必须显式加启动参数。
    bool      fArmed;
    IOService *fNicDevice;      // B2-b 靶子（RTL8127 PCI 设备）

    // 启动时序（0.6.0 实测教训）：
    //   探针匹配 IOResources，start() 极早。此时 serviceMatching(IOPCIDevice)
    //   返回空集——PCI 枚举还没完成，findNic() 报 ABSENT-no-rtl8127，
    //   而几秒后同一台机器上 pci10ec,8127 明明存在。
    //   B1 一直成功是因为它走 IOACPIPlane 路径，那些节点在 EFI 阶段已建立。
    //   所以 findNic() 改为优先按 IODeviceTree 路径定位。
    //
    // 竞态（0.6.0 实测：三次重启成功/失败/成功）：
    //   Lucy 在 start() 里读一次 iommu-parent 且不重试。探针设属性的时刻
    //   与 Lucy 读它的时刻之间没有顺序保证，于是时灵时不灵。
    //
    // 解法：改用 gIOFirstPublishNotification。
    //   按 IOKit 文档（IOService.h:279）：
    //     "When an IOService is published with registerService, the matching
    //      and probing process begins ... A list of matching dictionaries from
    //      the catalog **and installed publish notification requests** ...
    //      is constructed ... After probe, the driver is detached ...
    //      For each category, the highest scoring driver ... its start method
    //      called."
    //   即 publish 通知在 probe/start **之前**投递。设备一注册我们就挂属性，
    //   Lucy 之后 probe/start 时一定能读到。
    IONotifier *fPublishNotifier;
    uint32_t    fPublishHits;       // 通知回调命中次数
    bool        fLateAttach;        // 是否走了「通知没赶上」的兜底路径

    // ---- B2-b 观测 ----
    uint32_t fRealMapCalls;       // 非探针 cmd 的映射请求
    uint32_t fRealMapOk;          // 其中成功的
    uint32_t fRealMapRejectFrag;  // 碎片被拒
    uint32_t fRealMapRejectNoSlot;// 表满
    uint32_t fRealUnmapCalls;
    uint32_t fTablePeak;          // 峰值占用

    // 最后一次成功映射的摘要
    uint32_t fLastSegCount;
    uint64_t fLastFirstPA;
    uint64_t fLastLength;
    uint64_t fLastOffset;

    bool findTarget();
    bool findNic();

    // 只读查找网卡服务，**不**设置 fNicDevice、不依赖 fArmed。
    //
    // 为什么单独一个函数：M2-2b-2 需要在 amdiommu=pgt 下拿到目标设备的
    // BDF，但此时 fArmed=false、fNicDevice 为 NULL。直接复用 findNic()
    // 会修改状态并与 arm 流程耦合；复用 fNicDevice 则得到 NULL。
    // 调用方负责 release 返回值。
    IOService *findNicServiceOnly();
    bool armNic(IOService *nic);
    void installPublishNotifier();
    static bool publishHandler(void *target, void *refCon,
                               IOService *newService, IONotifier *notifier);
    void runB1SelfTest();
    void runB2SelfTest();
    void runB2aSelfTest();
    void runB2OneTest(const char *tag, bool wantContiguous, IOByteCount size);
    void publishMapStats(bool force);
    void publishB2bStats();

    // ---- M2-0b：PCI 配置空间只读探测 ----
    //
    // 目的：M2-0 的结论是 IVRS 的 0xFD380000 才对，DSDT 的 _CRS（0xFEB80000）
    // 是陈旧声明。但那个结论依赖 Linux 侧证据，macOS 侧还没有独立验证。
    //
    // IOMMU 的 capability block（实测 cap_ptr = 0x40）里有它自己的 MMIO BAR：
    //   cap_ptr + 0x00 : CapID(8) | CapPtr(8) | CapHdr(16)
    //   cap_ptr + 0x04 : BAR low  (bit0 是 lock 位，需屏蔽)
    //   cap_ptr + 0x08 : BAR high
    // 这是硬件当前的、权威的 BAR 值，比 DSDT 的静态声明可信。
    //
    // 全部只读：configRead8/16/32 只做 PCI 配置读，不写任何寄存器。
    void runM20ConfigProbe();

    // ---- M2-1：只读 MMIO 探测 ----
    //
    // 本项目第一次碰 MMIO。三重保护：
    //   1. boot-arg `amdiommu=mmio` 门控，默认完全不执行
    //   2. 只读，且映射用 kIOMapReadOnly
    //   3. 分阶段：先只读 EFR 一个寄存器，与 Linux 实测值比对，
    //      不匹配立即停止，不继续碰其他偏移
    void runM21MmioProbe();

    // ---- M2-2a-1：最小 MMIO 写测试 ----
    //
    // 只回答一个问题：这个 MMIO 窗口能不能写。
    // 不使能 IOMMU、不分配设备表、不发命令。
    //
    // 做法：写标记值到 DEV_TABLE 寄存器 → 读回 → 恢复原值 → 确认 CONTROL 未变。
    // 门控：boot-arg `amdiommu=write`。
    //
    // 为什么选 DEV_TABLE 做靶子：它是唯一"写了也不会立刻产生副作用"的寄存器
    // ——只有 CONTROL_IOMMU_EN 置位后硬件才会用它，而当前 IOMMU 完全关闭。
    // 且它当前值为 0，即使恢复失败留下的也是"未编程"的干净状态。
    void runM22aWriteProbe();

    // ---- M2-2a-2：建设备表（不使能）----
    //
    // 分配物理连续内存 → 全填直通 DTE → 写 DEV_TABLE 基址寄存器 →
    // 确认 CONTROL 未被改变 → 恢复原值。
    //
    // **不使能 IOMMU**。这是本步骤的核心价值：IOMMU 关闭时硬件不读这张表，
    // 所以系统行为必须完全不变，从而把"表对不对"与"使能后稳不稳"彻底分开。
    //
    // 门控：boot-arg `amdiommu=table`。
    void runM22bTableProbe();

    // ---- M2-2a-3：短窗口使能测试（最高风险）----
    //
    // 完整走 Linux early_enable_iommu() 的使能序列，但**极短窗口后立即禁用**：
    //   建设备表 → 写 DEV_TABLE → 分配命令缓冲 → 写 CMD_BUF →
    //   复位 head/tail → CMDBUF_EN → **IOMMU_EN** → 读 STATUS →
    //   立即清 IOMMU_EN → 确认已关闭 → 恢复所有寄存器
    //
    // 门控：boot-arg `amdiommu=enable`。
    //
    // 为什么短窗口：使能动作本身可能立即崩溃（地址错、编码错、命令缓冲未就绪）。
    // 短窗口若崩，说明配置有根本问题，不必冒险长期运行。
    void runM23EnableProbe();

    // ---- M2-2b-1：命令通道验证 ----
    //
    // M2-2a-3 只"配置"了命令缓冲，从未发过命令。
    // 这一步发一条 CMD_COMPL_WAIT，验证三件事：
    //   命令格式正确  → 硬件能解析（type 在 data[1] 的 bit28..31）
    //   tail 推进正确 → 硬件能看到新命令
    //   cmd_sem 地址正确 → 硬件能写回完成信号
    //
    // 门控：boot-arg `amdiommu=cmd`。
    //
    // 这是全新组件：三块内存（设备表 / 命令缓冲 / 完成信号）同时在场，
    // 且第一次真正驱动硬件执行动作。仍是短窗口。
    void runM2b1CmdProbe();

    // ---- M2-2b-2：4 级恒等页表 + 单设备 DTE 切换 ----
    //
    // M2-2b-1 证明了命令通道可用。这一步证明**页表机制**：
    //   建 4 级页表 → 填恒等映射 → 使能 → CMD_INV_ALL →
    //   把目标设备的 DTE 从直通改成翻译 → INV_DEV_ENTRY + INV_IOMMU_PAGES →
    //   确认硬件接受（无 fault 事件）→ 全部恢复原状。
    //
    // 门控：boot-arg `amdiommu=pgt`。
    //
    // 新增观测手段：**事件日志**。开启 EVT_LOG_EN 后 IOMMU 会把自己的
    // IO_PAGE_FAULT / DEV_TAB_ERR 写进我们指定的内存，这是前面所有步骤
    // 都没有的能力——之前只能靠"系统有没有崩"来间接判断。
    //
    // 【2026-10-31 关键修正】本函数**不能**在 start() 里直接跑。
    //
    // 实测：把 RTL8127 用 SFP+ 光缆接上局域网、手动 `ifconfig en2 up`
    // 之后它确实有 DMA（Ipkts 从 0 涨到 157）。但只要重启，en2 又回到
    // `media: <unknown type>`、零包——因为探针的 start() 比 Lucy 配置网卡
    // **更早**。所以"切换后 0 fault"仍然测不到东西。
    //
    // 解法：用 IOTimerEventSource 把整个探测推迟到 start() 返回之后
    // （默认 20 秒），那时 PCI 枚举、网卡驱动、链路协商都已完成。
    // 这样既不阻塞启动，又能在有真实 DMA 的窗口里做实验。
    void runM22b2PageTableProbe();
    struct R33DeviceDomain;
    void finishM22b2PageTableProbe(R33DeviceDomain *, bool finishWindow);

    // 延迟调度：在 start() 末尾挂一个一次性定时器，到点后调用
    // runM22b2PageTableProbe()。返回 false 表示调度失败（记录属性后放弃）。
    bool scheduleM22b2();

    // 定时器回调（静态，符合 IOTimerEventSource::Action 签名）
    static void m22b2TimerFired(OSObject *owner, IOTimerEventSource *sender);

    // Round33: setup transfers its hardware resources to the service and
    // returns. Explicit stop launches a separate worker for drain + restore.
    bool r31SessionRequested() const;
    static void r31SessionWorker(void *parameter, wait_result_t result);
    static void r33DomainStopWorker(void *parameter, wait_result_t result);
    void r33ScheduleDomainStop();
    bool r33DomainStopPending() const;
    void r31RequestStop();
    bool fR31Session = false;
    volatile UInt32 fR31StopRequested = 0;
    volatile UInt32 fR31WorkerActive = 0;
    volatile UInt64 fR31StopRequestTime = 0;
    bool fR31SessionCompleted = false; // written/read by the worker only
    R33DeviceDomain *fR33Domain = nullptr;
    volatile UInt32 fR33TeardownState = 0; // 0 active, 1 queued/running, 2 finished
    UInt32 fR33InstallCount = 0;

    R27ProbeTimer *fM22b2Timer;   // 一次性定时器（stop() 里释放）
    uint32_t            fM22b2DelayMS; // 延迟毫秒数（可被 boot-arg 覆盖）

    // 叶子页大小模式：
    //   false = 2 MiB 大页（覆盖全部 16 GiB）
    //   true  = 4 KiB 小页（覆盖全部 16 GiB，用于判别大页编码是否被硬件接受）
    // 由 boot-arg `amdiommu=pgt4k` 选择。
    bool                fM22b2Use4K;

    // 保持翻译生效的长时间观察模式（`amdiommu=pgthold`）。
    // 观察窗口从 2 秒延长到 M2B2_HOLD_SECS 秒，期间 DTE 一直指向翻译表，
    // 便于从外部用 netstat 观察设备是否仍在正常收发。
    bool                fM22b2Hold;

    // 纯睡眠对照（`amdiommu=pgtsleep`）：保持 DTE 直通，只做同样的 20 秒
    // IOSleep，用来判断"计数冻结"是翻译造成的，还是长睡眠阻塞 workloop 造成的。
    bool                fM22b2SleepOnly;

    // 页表级数模式（`amdiommu=pgt3l`）：
    //   false = PAGE_MODE_4_LEVEL（根表项覆盖 512 GiB）
    //   true  = PAGE_MODE_3_LEVEL（根表项覆盖 1 GiB，与 16 GiB RAM 匹配）
    bool                fM22b2Use3L;

    // 设备 DMA 观察（v0.21.0）。
    //
    // 第五轮唯一没答上的问题就是"那条范围外 fault 的地址，是不是设备真的
    // 在用"。当时的判据是 m1bb-realmapcalls，而它是 0——因为 RTL812xLucy
    // 在 useAppleVTD 为假时根本不走 mapper，直接用裸物理地址。所以那个
    // 计数器无法排除任何东西。
    //
    // 现在的做法是直接读设备：从 BAR2 读出 TX/RX 描述符环基址、统计缓冲
    // 基址、以及 CounterAddr 寄存器，再把环里的描述符地址收集成一个
    // 区间集合。这些是设备真正会去访问的地址，与驱动走不走 mapper 无关。
    //
    // 只读：不写任何设备寄存器，不改变驱动的 DMA 路径。
    void observeDeviceDma();

    // 只读 TX 环，返回 DescOwn 已清的槽数；-1 = 读不到。
    // 窗口前后各调一次，差值即窗口内完成记录数。
    int m2b2ScanTxDone();

    // 每个窗口最多保留多少条原始事件（16 字节/条）供离线解码。
    //
    // 【v0.20.0】从 8 提高到 16。第四轮只保留 8 条，而窗口里实际有
    // 14~17 条，于是任何"地址分布 / 标志位构成"的结论都只覆盖了不到
    // 一半的事件。16 条覆盖迄今观察到的最大窗口（17 条）并留有余量。
    //
    // 【v0.21.0】窗口结构已移到成员（见下面的 fM22b2WinPre / fM22b2WinMain），
    // 不再占 runM22b2PageTableProbe() 的栈，所以这个上限不再受
    // __chkstk 阈值约束。
public:
    static const unsigned kM22b2RawKeep = 16;

private:

    // 事件窗口记录。
    //
    // 【为什么必须有这个结构】
    //   旧实现 m2b2MeasureEvents() 只返回一个 UInt32，且把 0 同时用于
    //     (a) 窗口内真的没有事件
    //     (b) 日志溢出 / 条目未完成 / 采样失败
    //   两者含义完全相反，混在一起使此前所有"0 fault"结论都不可解释。
    //
    // 现在每个窗口完整记录：单调起止时间、实测时长、HEAD/TAIL 两端值、
    // STATUS 两端值、逐类型计数、devid 不匹配数、原始事件字节。
    // valid=false 时 invalidReason 指出具体原因，该窗口**不得**当作 0 事件。
public:
    struct M22b2EventWindow {
        bool        valid;
        const char *invalidReason;
        uint64_t    tStart;
        uint64_t    tEnd;
        uint64_t    durMS;           // 实测时长（不是标称值）
        uint64_t    wallStart;       // 墙钟秒，供外部 netstat 采样对齐
        uint64_t    wallEnd;
        uint32_t    headStart;
        uint32_t    tailStart;
        uint32_t    headEnd;
        uint32_t    tailEnd;
        uint32_t    statusStart;
        uint32_t    statusEnd;
        uint32_t    entries;
        uint32_t    typeCount[16];
        uint32_t    devidMismatch;
        uint32_t    rawCount;
        // 保留数量是否被上限截断。true 表示 entries > rawCount，
        // 此时 raw 只是抽样，不能代表全部事件。
        bool        rawTruncated;
        // 前置积压：窗口开始时 [HEAD, TAIL) 里已存在、尚未被消费的条目。
        // 这些是**上一个窗口或切换过程**产生的事件，不属于本窗口的新事件。
        uint32_t    preBacklog;
        uint32_t    raw[kM22b2RawKeep][4];
    };

private:
    // 两个窗口实例。放在成员里而不是栈上：每个 424 字节，两个 848 字节，
    // 正好是把 runM22b2PageTableProbe() 帧推过 __chkstk 阈值的那部分。
    M22b2EventWindow fM22b2WinPre;
    M22b2EventWindow fM22b2WinMain;

public:

    // 观察结果（由 observeDeviceDma() 填充，第 17 步用它分类 fault）
    //
    // 【第七轮重写】第六轮这个结构的语义有两处错误，都在此修正：
    //
    //  (1) 收集描述符地址前先调用 inIdentityRam()（RAM_TOP = 16 GiB），
    //      于是**本轮要调查的那类地址在进入集合前就被丢掉了**。集合随后
    //      "证明" fault 不在设备集合内——它从来就不可能在里面。
    //      现在：记录与解引用彻底分开。所有描述符地址一律记录；
    //      readVerdict 只决定"能不能读那块内存"，结果作为元数据保存。
    //
    //  (2) 关闭指针按 1024 取模算差值。硬件计数器是 31 位累计量
    //      （MaxTxDescPtrMask = 0x7FFFFFFF），1000 -> 2024 的正确答案是
    //      1024，按环取模却得到 0——把"设备完成了 1024 个描述符"读成
    //      "设备什么也没做"，恰好是最不能弄错的方向。
    struct M22b2DmaObs {
        bool     ran;
        bool     barMapped;
        uint64_t barBase;      // BAR2 物理基址
        uint64_t barLen;

        // ---- 第十轮：目标设备的独立身份 ----
        //
        // 【为什么要有这一组】
        //   第九轮完全没有核对"这些驱动记录属于哪块设备"。记录里没有
        //   vendor/device/BDF，探针也没有拿自己的观测去比对，于是"记录
        //   属于目标设备"是一个假设。
        //
        //   这一组由**探针自己**从设备表与 IORegistry 取得，独立于驱动
        //   发布的任何东西。分析器拿它与快照头部逐项比对，不一致就拒收。
        //
        // 【为什么 MAC 与 ifUnit 也要】
        //   同一台机器可能有两块同型号网卡（BDF 不同但 vendor/device 相同），
        //   也可能驱动重载后接口编号变化。MAC + ifUnit 是"这个网络接口就是
        //   那个 PCI 功能"的可核对证据，而不是"编号看起来像"。
        bool     nicIdentityKnown;
        uint32_t devid;            // 设备表里的 devid，就是 BDF
        uint32_t vendorId;
        uint32_t deviceId;
        uint32_t nicUnit;          // BSD unit（en2 -> 2）
        uint64_t nicMac;           // 48 位 MAC
        const char *nicBsdName;    // "en2"
        // 第十轮受控批次声明的请求数；0 表示本轮没有声明批次。
        uint32_t expectedBatch;

        // ---- 第十一轮：本次运行的 run token 声明 ----
        //
        // 【为什么必须声明，不能从记录里推】
        //   第十轮的批次判据只按 reqId 归并，没有 token 概念。于是
        //   "token A 的 req1 + token B 的 req2" 会被算成一个完整的 2 请求
        //   批次——两次不同的运行被拼成一次。
        //
        //   这里在**读证据之前**把本轮 token 定下来（负载脚本与 boot-arg
        //   用同一个值），记录里 token 不符的一律计入 batchForeignToken。
        //   未声明（0）时退化为"记录里只有一个 token 才采用"，两个以上
        //   就报 tokenAmbiguous 并拒绝通过。
        uint32_t declaredToken;

        // ---- 第十一轮：本次驱动实例绑定 ----
        //
        // 窗口打开之前由 m2b2BindDriverInstance() 设定，之后只读。
        // 0 表示没能绑定，此时批次判据拒绝通过（未知不是通过）。
        uint32_t epochBound;

        // 从寄存器读出的设备地址
        bool     haveTxRing;
        uint64_t txRingBase;
        bool     haveRxRing;
        uint64_t rxRingBase;
        bool     haveStat;
        uint64_t statBase;
        bool     haveCounter;
        uint64_t counterAddr;

        // 描述符扫描结果
        uint32_t txSlots;
        uint32_t txOwned;
        uint32_t txDone;
        uint32_t txAddrZero;
        uint32_t txTsoSlots;
        uint32_t rxSlots;
        uint32_t rxOwned;
        uint32_t rxDone;
        uint32_t rxAddrZero;
        uint64_t txFirstAddr;
        uint64_t rxFirstAddr;

        // 收集到的地址区间与**五类互不混用的计数**（第七轮）
        //
        //   rawOffered   描述符/寄存器里取到的原始地址数
        //   mergedTotal  合并后的区间数 == savedCount + droppedCount
        //   savedCount   真正存进集合的
        //   droppedCount 因容量上限没存下的（包络仍然覆盖它们）
        //   unscanned    完全没能检查的槽（环映射失败等）
        uint32_t ranges;          // == savedCount，保留旧属性名
        uint32_t dropped;         // == droppedCount
        uint32_t rawOffered;
        uint32_t mergedTotal;
        uint32_t unscanned;
        uint32_t txBufRanges;
        uint32_t rxBufRanges;

        // 所有观察到的区间的包络（含因容量上限被丢弃的）。
        bool     envValid;
        uint64_t envLo;
        uint64_t envHi;

        // 【第七轮】物理布局与读取许可
        //
        // 恒等映射上限**不是** RAM 上限；本轮不再用它做记录过滤，
        // 只用它回答"能不能读"。没有权威布局时 layoutKnown = false，
        // 任何地址都不解引用，但一律记录。
        bool     layoutKnown;
        const char *layoutSource;   // "probe" / "none"
        uint32_t readOkCount;
        uint32_t readOutOfMapCount;
        uint32_t readNotRamCount;

        // 【第七轮】覆盖范围
        //
        // COV_NONE / COV_SNAPSHOT / COV_WINDOW。快照只能支撑**肯定**
        // 归属；"设备没用过这个地址"需要整窗覆盖。
        uint32_t coverage;

        // 设备完成证据。
        uint32_t txDoneWithAddrBefore;
        uint32_t txDoneWithAddrAfter;
        bool     haveDoneDelta;

        // 【第七轮】关闭指针：身份由芯片推导，不再"取第一个非零候选"。
        bool     haveCloPtr;
        uint32_t cloPtrBefore;
        uint32_t cloPtrAfter;
        uint32_t cloPtrReg;      // 由 ChipId 推导，不是选举
        uint32_t cloPtrWidth;
        uint32_t cloPtrMask;     // MaxTxDescPtrMask
        uint32_t txConfigRaw;
        uint32_t cfgMethod;
        uint32_t noCloseVer;
        bool     chipKnown;
        bool     haveCloDelta;
        uint32_t cloDelta;       // 掩码差值，不是环取模
        bool     cloDeltaValid;  // 样本合法且差值可解释

        // 环尾指针（累计提交计数），用于判断窗口覆盖
        bool     haveTailPtr;
        uint32_t tailPtrBefore;
        uint32_t tailPtrAfter;
        bool     txWindowCovered;

        // ---- 第八轮：窗口扫描与代次 ----
        //
        // 第七轮的采集器没有调用 txSlotLifecycle()：它忽略了自己的
        // tailCum/cloCum 参数，只要能读到关闭指针就把所有非零 TX 地址
        // 标成 in-flight。第七轮采集里 tail = clo = 0x6a（队列已排空），
        // 却仍把每条历史地址报成 in-flight。
        //
        // 现在由 scanTxWindow() 按 [tailBefore, tailAfter) 逐个累计索引
        // 走表，每条都带自己的槽位、代次、地址、长度与完成状态。
        uint32_t winSubmits;         // 窗口内提交的描述符数
        uint32_t winCompletes;       // 窗口内交还的描述符数
        uint32_t winVisited;         // 实际访问的累计索引数
        uint32_t winDecoded;         // 成功解码的
        uint32_t winOverwritten;     // 槽位已被复用的（描述符已不在环里）
        uint32_t winInflight;
        uint32_t winCompleted;
        uint32_t winCompletedInWindow;
        uint32_t winLenUnknown;      // 长度无法解码的（TSO / 零长）
        uint32_t winTsoSlots;
        uint32_t winGenBefore;       // 窗口起点的代次
        uint32_t winGenAfter;        // 窗口终点的代次
        uint32_t winCovReason;       // TxCoverageReason
        // 第一个"窗口内完成"的描述符：把正的完成增量落到具体操作上。
        bool     haveFirstCompleted;
        uint64_t winFirstCompletedAddr;
        uint32_t winFirstCompletedLen;
        uint32_t winFirstCompletedSlot;
        uint32_t winFirstCompletedGen;

        // ---- 第八轮：逐路径覆盖 ----
        //
        // 第七轮只有一个 coverage 值，却被用于所有路径。TX 是整窗覆盖，
        // RX / 环 / 统计缓冲只是快照。把 TX 的结论推广到全设备，是同一
        // 种过度概括换了个位置。
        amdobs::PathCoverage pathCov;

        // ---- 第八轮：读环内存的依据 ----
        //
        // 设备寄存器只能证明"设备被编程使用这个地址"，不能证明这块内存
        // 仍是驱动的环对象、仍存活、且这个 PA 映射到它。指纹必须真的
        // 可能失败，才算一个检查。
        uint32_t txRingBasis;        // RingBasis
        uint32_t rxRingBasis;
        uint32_t txRingDecoded;      // 指纹里解码出的描述符数
        uint32_t rxRingRingEndAtLast;
        bool     txRingFpOk;
        bool     rxRingFpOk;

        // 【第七轮】时间边界：全部单调纳秒，可逐项核对
        uint64_t tObsBefore;      // 窗口前观察
        uint64_t tWinStart;
        uint64_t tWinEnd;
        uint64_t tObsAfter;       // 窗口后观察
        uint64_t tCloBefore;
        uint64_t tCloAfter;
        uint64_t tRecoveryStart;
        uint64_t tRecoveryEnd;

        // ---- 第八轮：边界时刻（全部同一单调时钟）----
        uint64_t tTranslateOn;    // DTE 切到翻译生效
        uint64_t tTranslateOff;   // DTE 切回直通（恢复开始前）
        uint64_t tTailBefore;     // 窗口前读尾指针的时刻
        uint64_t tTailAfter;      // 窗口后读尾指针的时刻
        uint64_t tWinScanStart;   // 窗口后环扫描开始
        uint64_t tWinScanEnd;     // 窗口后环扫描结束

        // ---- 第九轮：时间边界重排 ----
        //
        // 第八轮把 tTranslateOn 记在"写 DTE"的那一刻。DTE 写下去不等于
        // 翻译已经生效：失效命令还没提交、TLB 里可能还是旧表项。现在
        // 两个时刻分开发布，tTranslateOn 取**失效命令全部完成之后**。
        //
        // 同理，第八轮的两次 CloPtr 采样夹在窗口外面（跨度 3.00785 秒 >
        // 窗口 3.00018 秒），所以"完成发生在零事件窗口内"这句话其实
        // 没有被证明。现在后置采样发生在窗口**内部**的最后一刻，窗口
        // 关闭之后不再读寄存器。
        uint64_t tDteWritten;     // DTE 写入完成
        uint64_t tInvComplete;    // 两条失效命令都收到完成
        // 主窗口的单调边界 tWinStart / tWinEnd 在第七轮就已声明（见上），
        // 本轮直接用它们给驱动日志的配对做窗口过滤。
        uint64_t tCloAfterInWin;  // 窗口内后置采样的起点（= tCloAfter）
        bool     boundaryInWindow; // 后置采样确实发生在窗口内

        // ---- 第十一轮：探针实际采用的那份快照 ----
        //
        // 【第十轮在这里出了什么错】
        //   探针确实读到了一份新鲜快照（publication 27，tPublished
        //   41,305,180,913 ns，窗口终点 40,843,902,421 ns，覆盖成立）。
        //   但归档时是从 props.raw.txt 里另取一份，而那是全 IOService
        //   plane 的 dump，里面的驱动节点已经是 43 秒后的 publication 71。
        //   于是"运行时结论"与"归档输入"是两件事，分析器验的是后者。
        //
        //   修法不是让采集脚本更小心，而是让**探针自己**把参与判定的
        //   那份字节原样交出来：一份 OSData 属性
        //   m2-b2-obs-snapshot-used，内容就是当时解码用的那些字节，
        //   逐字节相同。采集脚本把它落盘，分析器校验它的哈希等于
        //   探针在属性里同时发布的 m2-b2-obs-used-sha256。
        //
        // 【为什么还要单独记一个哈希】
        //   属性是文本，blob 是二进制。若只导出 blob，谁也不能证明它与
        //   当时判定用的是同一份。探针在解码前后各算一次哈希，两次不同
        //   就说明 OSData 在手里被改过（不该发生，但可检测），此时不发布
        //   blob 并把原因写出来。
        bool     obsUsedExported;      // blob 已发布
        uint32_t obsUsedBytes;         // 发布的字节数
        bool     obsUsedHashStable;    // 解码前后的哈希一致
        char     obsUsedSha[65];       // 十六进制 sha256（64 + NUL）
        const char *obsUsedWhy;        // 未发布的原因
        // 这份快照是不是"为了覆盖窗口而主动刷新拿到的那一份"。
        // 与 obsFetchTries 配合，使"有界刷新生效"可被独立核对。
        uint32_t obsUsedPubId;
        uint64_t obsUsedTPublished;
        bool     obsUsedIsFresh;       // tPublished >= tWinEnd

        // ---- 第十一轮：驱动实例绑定 ----
        //
        // 【为什么必须绑，而不能"只要求内部一致"】
        //   第十轮的 want.epoch = 0，而 obsIdentityMatches() 把 0 解释为
        //   "不检查"。同一块卡、同一份 MAC、同一个 BSD unit，驱动重载或
        //   控制器 reset 之后产生的新实例，其快照会被当作本次实例的证据。
        //
        //   现在在**窗口打开之前**把实例 epoch 定下来（从驱动节点读，或由
        //   探针采样并记住），之后要求快照头部的 epoch 与它相等。取不到
        //   就发布 epochBinding = "unknown" 并拒绝通过——未知不是通过。
        uint32_t obsEpochBound;        // 本轮的实例标识（0 = 未绑定）
        uint32_t obsEpochSeen;         // 快照头部带来的 epoch
        const char *obsEpochBinding;   // "matched" / "mismatch" / "unknown"

        // ---- 第十轮：驱动侧观测日志（线格式 v2）----
        //
        // 读环只能看到"窗口之后的字节"，无法证明那些字节属于同一代次，
        // 也无法恢复 TSO 段的真实长度。驱动现在在自己的提交/完成点记录
        // 元数据，并把**头部+记录**作为**一份** OSData 发布。
        //
        // 【第九轮为什么不够】
        //   1. v1 的 seq 只在末尾写一次，读侧"读 seq、读 body、再读 seq"
        //      在写入过程中会看到**上一次**的 seq 两次，于是把半写状态判为
        //      一致。这不是 seqlock。
        //   2. v1 把 head/first/published/wrapped/t-published 分成五个
        //      OSString，记录是第六个 OSData，六者不构成一个原子发布。
        //   3. 快照发布时间 39963682435 ns 早于窗口终点 40494639566 ns
        //      530957131 ns，"覆盖完整窗口"不成立。
        //   4. 记录里没有任何业务标识，无法与客户端请求对应。
        bool     obsPresent;
        const char *obsWhy;        // 不可用原因，或 "ok"
        const char *obsIdentityWhy; // 身份核对失败原因，或 "ok"
        uint32_t obsPubId;         // 本次采用的 publication ID
        uint32_t obsEpoch;         // 驱动实例 epoch
        uint32_t obsHead;
        uint32_t obsPublished;     // == 快照里的记录数
        uint32_t obsFirst;         // firstTicket
        uint32_t obsWrapped;
        uint32_t obsDropped;
        uint32_t obsValidCount;
        uint32_t obsLostCount;
        uint32_t obsHdrFlags;
        uint32_t obsBusDevFn;
        uint32_t obsVendorId;
        uint32_t obsDeviceId;
        uint32_t obsIfUnit;
        uint64_t obsMac;           // 48 位 MAC
        uint64_t obsTStart;
        uint64_t obsTPublished;
        // 刷新次数与最终采用的那一份是不是"新鲜"的
        uint32_t obsFetchTries;    // 有界轮询了几次
        bool     obsFreshEnough;   // tPublished >= 窗口终点
        // 提交→完成的配对结果
        uint32_t obsOps;
        uint32_t obsSubmits;
        uint32_t obsDones;
        uint32_t obsDoorbells;
        uint32_t obsRxDone;
        uint32_t obsRxAddrZero;
        uint32_t obsStale;
        uint32_t obsUnmatchedDone;
        uint32_t obsUncompleted;
        uint32_t obsOverflow;
        bool     obsAllCompleted;
        // ---- 窗口内的配对 ----
        uint32_t obsWinSubmits;
        uint32_t obsWinDones;
        uint32_t obsWinPaired;
        uint32_t obsWinOrphanDone;
        uint32_t obsWinPreWindowInFlight;
        uint32_t obsWinUncompleted;
        // ---- 第十轮：三个独立判据 ----
        //
        // 这三个必须分开。"已有一对成功"不能顶替"记录覆盖窗口"，两者也都
        // 不能顶替"本次受控批次完成"。
        bool     obsHasCompletePair;
        bool     obsRecordsCoverWindow;
        bool     obsControlledBatchComplete;
        uint32_t obsCoverState;
        const char *obsCoverName;
        // ---- 第十轮：业务关联 ----
        uint32_t obsBizOps;
        uint32_t obsBizCapped;
        uint32_t obsExpectedBatch;
        uint32_t obsBatchComplete;
        uint32_t obsBatchPartial;
        uint32_t obsBatchMissing;
        uint32_t obsBatchUnexpected;
        uint32_t obsBatchUnparsed;
        uint32_t obsTxParsed;
        uint32_t obsRxParsed;
        // ---- 第十一轮：批次判据的绑定项与阻断计数 ----
        uint32_t obsDeclaredToken;      // 声明的 run token（0 = 未声明）
        uint32_t obsJoinToken;          // 实际用于归并的 token
        bool     obsTokenResolved;      // token 来自声明或唯一推断
        bool     obsTokenAmbiguous;     // 记录里出现多个 token
        // 【第十二轮】token 是**推断**出来的（不是读记录之前声明的）。
        // 推断出的 token 不能支撑批次判据：它让"这些记录属于本次运行"
        // 按构造成立。
        bool     obsTokenInferred;
        uint32_t obsBatchForeignToken;  // 属于其它 run 的记录数
        uint32_t obsBatchOutsideWindow; // 各阶段未全部落在窗口内的请求数
        uint32_t obsBatchDupDone;       // 重复完成的请求数
        uint32_t obsBatchBadFrag;       // 段结构不完整的请求数
        uint32_t obsBatchDmaUnknown;    // DMA 区间无法确定的请求数
        uint32_t obsBatchOrder;         // 完成早于提交的请求数
        const char *obsBatchWhy;
        // 受控批次里第一条完整（TX 全段 + 完成 + RX）的业务操作
        bool     obsHaveBizOp;
        uint32_t obsBizToken;
        uint32_t obsBizReqId;
        uint32_t obsBizSegCount;
        uint32_t obsBizSegDone;
        uint64_t obsBizTSubmitFirst;
        uint64_t obsBizTSubmitLast;
        uint64_t obsBizTDoorbell;
        uint64_t obsBizTDoneFirst;
        uint64_t obsBizTDoneLast;
        uint64_t obsBizRxAddr;
        uint32_t obsBizRxLen;
        uint64_t obsBizTRx;
        // 该操作的全部 DMA 段（地址/长度/累计索引）
        uint32_t obsBizSegCum[amdobs::OBS_MAX_SEGS];
        uint64_t obsBizSegAddr[amdobs::OBS_MAX_SEGS];
        uint32_t obsBizSegLen[amdobs::OBS_MAX_SEGS];
        uint32_t obsBizSegDoneCount[amdobs::OBS_MAX_SEGS];
        uint32_t obsBizSegMissingDone;
        uint32_t obsBizSegDupDone;
        bool     obsBizFragOk;
        bool     obsBizInWindow;
        uint64_t obsFirstSubmitT;
        uint64_t obsLastDoneT;
        uint64_t obsFirstRxAddr;
        uint64_t obsLastRxAddr;
        // 第一条完整配对的受控操作：提交—地址—完成三要素都在这里。
        bool     obsHaveFirstOp;
        uint32_t obsFirstOpCum;
        uint32_t obsFirstOpSlot;
        uint32_t obsFirstOpGen;
        uint64_t obsFirstOpAddr;
        uint32_t obsFirstOpLen;
        uint32_t obsFirstOpFlags;
        uint64_t obsFirstOpTSubmit;
        uint64_t obsFirstOpTCompl;

        // ---- 第十一轮：业务地址的原始页表证据 ----
        //
        // 【第十轮为什么不算证据】
        //   报告写的是"L4→L3→L2 恒等叶子，根表来自实际 DTE"，但发布的
        //   样本是 win0（窗口内第一条既有提交又有完成的操作，与业务无关）
        //   和 dma0..dma5（环基址、统计缓冲等设备在用地址的抽样）。
        //   业务 request 1 的 TX 地址 0x3790a57b6 与 RX 地址 0x1f421f000
        //   一个都不在其中。把背景操作的路径接到业务链上，是把"邻近"当
        //   成了"同一"。
        //
        //   现在：对**每一个受控请求的每一个 TX/RX 段**，用该段的
        //   [addr, addr+len) 走表，逐级导出真实的表物理地址、索引、级别、
        //   原始 PTE，并检查区间内每个字节都被合法叶子覆盖。数据来源是
        //   本次实验自己建的表，起点是本步读到的**实际 DTE**。
        //
        // 【为什么单独开一块而不是复用 dumpPath】
        //   dumpPath 一次只走一个地址、只判"翻译回自身"。业务区间要判的
        //   是覆盖与权限，而且要能逐段核对，所以字段结构不同。
        uint32_t bizWalkCount;      // 实际走表的 (请求, 方向, 段) 数
        uint32_t bizWalkOk;         // 其中区间被合法叶子完整覆盖的
        uint32_t bizWalkFail;       // 不成立的
        // ---- 第十二轮：区间集合的两个"账" ----
        //
        // 【bizWalkExpected】
        //   由**原始业务记录**（本次 token 下的每个 req 的每个 TX 段 +
        //   RX 段）推出的应走表区间数。它必须与 bizWalkCount 相等，否则
        //   说明有的区间根本没走表——第十一轮只判"走到的那些是否通过"，
        //   少走几条也能全绿。
        //
        // 【bizWalkCapped】
        //   超出取证容量或预算而被明确降级的区间数。第十一轮在
        //   `count >= kBizWalkMaxSegs` 时直接 return，既不计数也不降级，
        //   于是"只导出了一部分"会被读成"全部合格"。
        uint32_t bizWalkExpected;
        uint32_t bizWalkCapped;
        // 每段最多导出几个不同的叶子。一条 74 字节的报文正常只落在一个
        // 2 MiB 叶子里；跨叶时要把**每个**叶子的完整路径都导出来，否则
        // 分析器只能核对第一叶却看到 covered=yes。
        static const uint32_t kBizWalkMaxLeaves = 4;
        // 每个段最多导出几级；AMD-Vi 最多 6 级，取 6 足够且固定。
        static const uint32_t kBizWalkMaxLevels = 6;
        static const uint32_t kBizWalkMaxSegs = amdobs::OBS_MAX_SEGS * 8;
        // 一条路径：从根到叶的每一级。
        struct BizPath {
            uint8_t  depth;
            uint8_t  reserved[3];
            uint64_t leafPA;        // 命中的叶子基址
            uint64_t leafSize;
            uint32_t leafLevel;
            // 这个叶子覆盖了区间里的哪一段：起点 + 字节数。
            //
            // 【为什么两个都要】
            //   只记字节数，无法核对"两叶加起来正好是整段"——重叠或漏掉的
            //   一段都会让总和看起来正确。起点使每一叶的覆盖可以逐段相加。
            uint64_t coversFrom;
            uint64_t coversBytes;
            uint64_t tablePA[kBizWalkMaxLevels];
            uint32_t index[kBizWalkMaxLevels];
            uint32_t level[kBizWalkMaxLevels];
            uint64_t pte[kBizWalkMaxLevels];
        };
        struct BizWalk {
            uint32_t reqId;
            uint8_t  isRx;          // 0 = TX（设备读），1 = RX（设备写）
            uint8_t  segIndex;
            uint8_t  depth;         // 第一叶的级数（保持旧属性含义）
            uint8_t  covered;       // 区间被完整覆盖
            uint8_t  permOk;        // 该方向的权限位足够
            uint8_t  overflow;      // addr+len 溢出
            uint8_t  capped;        // 叶子数超出 kBizWalkMaxLeaves
            uint8_t  leafCount;     // 实际导出的叶子数
            uint64_t addr;
            uint32_t len;
            uint64_t leafPA;        // 第一叶基址（旧属性）
            uint64_t leafSize;
            uint32_t leafLevel;
            uint64_t rootPA;        // 走表起点（来自实际 DTE）
            uint32_t rootLevel;
            uint64_t dteRaw;        // 走表所依据的 DTE
            uint32_t pagesChecked;  // 区间内检查的叶数
            uint32_t pagesBad;      // 未被合法叶子覆盖的叶数
            const char *why;
            BizPath  path[kBizWalkMaxLeaves];
        };
        BizWalk bizWalk[kBizWalkMaxSegs];

        // ---- 第十四轮：RX 投递缓冲区集合 ----
        //
        // 【第十三轮缺的是什么】
        //   已走表的 8 条区间是"恰好承载了 4 个回声"的那 8 个缓冲区。整环
        //   有 1024 个 4 KiB 缓冲区，窗口内还会被反复重新投递。所以当时
        //   证明的是"抽样被映射"，不是"设备能写的每个缓冲区都被映射"。
        //
        // 【本轮的集合】
        //     S = { 基线槽表里的 (addr, capacity) }
        //       ∪ { 序号大于基线水位的每条重新投递记录的 (addr, capacity) }
        //
        //   基线由驱动在自己的执行路径上采集并每秒刷新一次；探针在**窗口
        //   之前**读一次，记下当时的中投递计数（水位），窗口之后读第二次，
        //   要求"水位之后"的每条记录都在场。于是任何在窗口开始时仍然有
        //   效、之后被替换掉的缓冲区，要么还在最终基线里，要么在重投递
        //   记录里——不会两头都漏。
        //
        // 【为什么集合要放进成员】
        //   3072 个区间 × 24 字节 = 72 KiB。放在 runM22b2PageTableProbe()
        //   的栈上会把栈帧推过 4 KiB 阈值，二进制里出现 ____chkstk_darwin
        //   弱引用，kmutil 直接拒绝整个 bundle（本项目踩过三次）。
        static const uint32_t kRxSetMaxRanges = 3072;
        static const uint32_t kRxSetDetailMax = 64;
        static const uint32_t kRxSetSampleMax = 8;

        struct RxSetDetail {
            uint64_t addr;
            uint32_t capacity;
            uint32_t source;      // amdrx::RX_SRC_*
            uint32_t slot;
            uint8_t  ok;
            uint8_t  permOk;
            uint8_t  leaves;
            uint8_t  reserved;
            const char *why;
        };

        bool     rxsetPresent;
        const char *rxsetWhy;         // 不可用原因，或 "ok"
        const char *rxsetSetWhy;      // 集合构造的结论 token（nullptr = 完整）

        // 两次读取的身份与代数。三者相等才允许把两半拼起来。
        uint32_t rxsetWatermark;      // 窗口**之前**读到的 head
        uint32_t rxsetHead;           // 窗口之后读到的 head
        uint32_t rxsetRingGen;
        uint32_t rxsetPreRingGen;
        uint32_t rxsetEpoch;
        uint32_t rxsetPreEpoch;
        uint32_t rxsetIfUnit;
        uint32_t rxsetVtdPath;

        // 驱动自报的基线统计，逐项与探针独立重算的结果比对。
        uint32_t rxsetBaselineSlots;
        uint32_t rxsetBaselineValid;
        uint32_t rxsetBaselineCapDesc;
        uint32_t rxsetBaselineCapConst;
        uint32_t rxsetBaselineCapBad;
        uint32_t rxsetBaselineTorn;
        uint32_t rxsetBaselineCount;
        uint32_t rxsetBaselineGenMoved;

        // 集合本身的账。
        uint32_t rxsetRanges;
        uint32_t rxsetFromBaseline;
        uint32_t rxsetFromRearm;
        uint32_t rxsetFromBoth;
        uint32_t rxsetCapped;
        uint32_t rxsetSkippedZero;
        uint32_t rxsetSkippedBadCap;
        uint32_t rxsetRearmRequired;
        uint32_t rxsetRearmUsed;
        uint32_t rxsetRearmSeen;
        bool     rxsetComplete;

        // 走表结果。
        uint32_t rxsetWalked;
        uint32_t rxsetOk;
        uint32_t rxsetFail;
        uint32_t rxsetFailCapped;
        uint64_t rxsetMinAddr;
        uint64_t rxsetMaxEnd;
        uint64_t rxsetBytesTotal;
        // 未映射/无权限的那些区间，逐条导出（有上限，超出的计数）。
        uint32_t rxsetFailCount;
        RxSetDetail rxsetFailDetail[kRxSetDetailMax];
        // 通过的那部分只抽样导出完整路径，避免逐槽堆积页表文本。
        uint32_t rxsetSampleCount;
        RxSetDetail rxsetSample[kRxSetSampleMax];
        // 抽样区间的完整路径，与业务区间同一种导出形式。
        struct RxSamplePath {
            uint8_t  leafCount;
            uint8_t  depth;
            uint8_t  reserved[2];
            uint64_t leafPA;
            uint64_t leafSize;
            uint32_t leafLevel;
            uint64_t tablePA[kBizWalkMaxLevels];
            uint32_t index[kBizWalkMaxLevels];
            uint32_t level[kBizWalkMaxLevels];
            uint64_t pte[kBizWalkMaxLevels];
        };
        RxSamplePath rxsetSamplePath[kRxSetSampleMax];

        // 驱动发布的那份原始字节（供分析器独立重算集合）。
        bool     rxsetRawExported;
        uint32_t rxsetRawBytes;
        char     rxsetRawSha[65];
        const char *rxsetRawWhy;

        // 区间数组。成员，不是局部变量（见上面的栈帧说明）。
        amdrx::Range rxsetList[kRxSetMaxRanges];

        // ---- 第九轮：窗口扫描质量 ----
        //
        // 第八轮把计数器都发出来了，但 covered 只看指针算术。扫描提前停止、
        // 记录丢失、长度不可解码，全都不影响 `tx-window-covered = yes`。
        // 现在这些都会撤回资格，而不只是显示在旁边。
        uint32_t winRecordsLost;
        bool     winExact;
        const char *winQualityName;

        // ---- 第十二轮：证据资格的实际结论 ----
        //
        // evidenceOk / evidenceWhy 是 amdobs::obsEvidenceGate() 对**同一份**
        // 证据给出的结论。探针发布它，分析器再独立重算一遍；两者不一致
        // 就说明有一方读错了证据。注意它不是判定字符串的副本：判定还会
        // 叠加窗口边界与读环归因，而那些不属于"证据资格"。
        bool     evidenceOk;
        const char *evidenceWhy;

        const char *skipReason;
    };
    M22b2DmaObs fM22b2Dma;

    // 观察到的设备 DMA 区间集合。
    //
    // 【为什么放在成员里而不是栈上】
    //   AddrSet 现在是 64 个区间，每项 32 字节 = 2048 字节。放进
    //   runM22b2PageTableProbe() 的栈帧会把总帧推过编译器插入 __chkstk
    //   的阈值（4 KiB），于是二进制里出现对 ____chkstk_darwin 的**弱**
    //   引用，kmutil 直接拒绝："Has weak references but does not test for
    //   them." 第六轮就是踩在这个坑上（M2B2_RAW_KEEP 从 8 提到 32 时）。
    //   放到成员里既不占栈，也让第 15b 步与第 17 步共用同一份快照。
    amdobs::AddrSet fM22b2AddrSet;

    // 【第九轮】窗口记录的**独立**容量。
    //
    // 第八轮把窗口内那几条描述符塞进与几千条历史 RX/TX 快照共用的
    // AddrSet（容量 64）。历史快照先填满，窗口记录就被丢进 dropped，
    // 于是"窗口内 3 条提交"可能在集合里一条都没有。小规模受控操作的
    // 记录必须独立，否则它永远排在最后。
    amdobs::AddrSet fM22b2WinSet;

    // 【第九轮】提交/完成配对的暂存。
    //
    // 为什么是成员而不是局部变量：ObsJoin 含 64 个 ObsTxOp，每个约 56 字节，
    // 合计约 3.6 KiB。作为 m2b2ReadDriverObs() 的局部变量会把该函数的栈帧
    // 推过 4 KiB，于是编译器插入 __chkstk，二进制里出现对
    // ____chkstk_darwin 的**弱**引用，kmutil 直接拒绝：
    //   "Has weak references but does not test for them."
    // 第六轮在 M2B2_RAW_KEEP 从 8 提到 32 时踩过同一个坑。
    amdobs::ObsJoin fM22b2ObsJoin;

    // 物理布局策略（恒等映射上限 + RAM 空洞 + 布局是否已知）
    amdobs::MapPolicy fM22b2Policy;

    // 把描述符里的地址+长度收进集合。
    //
    // 与第六轮的关键差别：**不按任何上限过滤**。所有非零地址都进集合，
    // 能不能读那块内存由 readVerdict() 单独判定并作为元数据记录。
    //
    // 【第八轮】这个函数现在真的使用 tailCum/cloCum：它调用
    // scanTxWindow()，按 [tailCum, 窗口后尾指针) 逐个累计索引取描述符，
    // 每条带自己的槽位、代次、生命周期。第七轮版本忽略了这两个参数，
    // 把所有非零地址一律标成 in-flight。
    void m2b2CollectTxSegments(const UInt8 *ring, UInt32 count,
                               UInt32 tailCum, UInt32 cloCum);

    // 【第八轮】窗口结束后的描述符生命周期扫描。
    //
    // 与 m2b2CollectTxSegments 的区别：后者在窗口**之前**取快照（不知道
    // 窗口里发生了什么），这个在窗口**之后**按窗口两端的累计指针逐条
    // 归因。结果写进 fM22b2Dma 的 win* 字段。
    void m2b2ScanTxWindowAfter(const UInt8 *ring, UInt32 count);

    void m2b2CollectRxSegments(const UInt8 *ring, UInt32 count);

    // 【第十轮】读取驱动侧观测日志（线格式 v2）。
    //
    // 与读环的根本区别：这里读的是驱动**仍然持有的**内存对象的副本。
    // 驱动在提交/完成点写入记录，并把**头部+记录**作为**一份** OSData
    // 发布。探针拿到的字节带着驱动自己算出的累计索引，所以"提交—完成"
    // 的配对是按同一个数字对上的，不涉及对槽位复用的推断。
    //
    // 第九轮的 v1 有三个结构性缺陷，v2 逐个修掉（见实现处注释）：
    //   1. seq 只在末尾写一次，读侧无法识别半写状态；
    //   2. 头部与记录分属六个属性，可以来自不同次发布；
    //   3. 记录里没有业务标识，无法与客户端请求对应。
    void m2b2ReadDriverObs();

    // 【第十轮】采集目标网卡的身份（BDF / vendor / device / BSD unit / MAC）。
    //
    // 【为什么要独立采集】
    //   驱动记录本身不知道"我是哪块卡"。若探针不自己观测身份，那么
    //   "这些 DMA 属于目标设备"就只是假设。第九轮正是这样。
    //
    // 【为什么不写死 en2】
    //   接口编号会随驱动加载顺序变化。这里从 IORegistry 现取：
    //   IOInterfaceUnit 给编号，IOMACAddress 给 MAC，父节点给 BDF。
    //   三者一起才能把"网络接口"与"PCI 功能"绑成同一件事。
    void m2b2CaptureNicIdentity();

    // 【第十一轮】为每个受控请求的每个 TX/RX 段采集原始页表证据。
    //
    // 【为什么必须在恢复之前调用】
    //   走表用的是本次实验建的那块页表内存。恢复流程会（在确认硬件停止
    //   后）释放它，之后指针就无效了。所以采集点必须在第 17b 步，
    //   与 DTE 切换仍然生效的时间区间重叠。
    //
    // 【为什么起点必须是实际 DTE】
    //   第十轮的分析器有一项"根表来自 DTE"，但它在 m2-b2-dte-root 不存在
    //   时直接判通过，而该属性从来不存在。这里改为：从 dte[] 里**读回**
    //   目标设备那一条，解码出 mode 与根表地址，把它作为走表起点；同时把
    //   那条 DTE 的原始值一起导出，使"起点来自 DTE"可被独立核对。
    //
    // 页表由 R33DeviceDomain 持有；诊断只在域仍有效时借用这些指针。
    // 恢复硬件并完成诊断后，域统一释放页表，走表函数不保存借用指针。
    void m2b2WalkBusinessRanges(const volatile UInt64 *dte, UInt32 tgt,
                                const volatile UInt64 *ptMem,
                                UInt64 ptBasePA, UInt64 ptBytes);

    // ---- 第十四轮：RX 投递缓冲区集合 ----
    //
    // m2b2RxSetRead()：读一次驱动发布的 rtl812x-rxpost，解出基线槽表、
    //   重投递记录与水位，并当场构造集合 S。`beforeWindow` 决定它扮演哪个
    //   角色：窗口之前那次只记下水位（之后序号大于它的重投递都属于本
    //   窗口），窗口之后那次才是构造集合与导出原始字节的那一次。
    //   返回 false 时 rxsetWhy 说明原因，绝不返回一个"空集合"冒充结果。
    //
    // m2b2WalkRxSet()：对 S 的每个区间走真实页表，复用 amdbw::walkRange()。
    //   与业务区间走表是**同一份**核心代码。
    //
    // m2b2PublishRxSet()：发布计数、逐条失败区间与抽样路径。
    bool m2b2RxSetRead(bool beforeWindow);
    void m2b2WalkRxSet(const volatile UInt64 *dte, UInt32 tgt,
                       const volatile UInt64 *ptMem,
                       UInt64 ptBasePA, UInt64 ptBytes);
    void m2b2PublishRxSet();

    // Shared driver reference and token storage for the historical finite
    // path and native sessions. Sessions use the R34 control, never pool RPCs.
    // The finite path alone retains the R15 ring/spare allocation domain.
    IOService *fR15Service;
    r15pool::Request fR15Request;
    UInt32 fR15PoolRpcCalls;
    UInt64 fR15MapTicks;
    UInt64 fR15InvTicks;
    bool m2b2R15Call(UInt32 op);
    bool m2b2R15PrepareMap(volatile UInt64 *pt, UInt64 ptBase,
                           UInt32 totalPages, UInt32 basePages);
    bool m2b2R15Authorize();
    void m2b2R15Finish();
    void m2b2R15Release();
    struct R15Scope {
        org_example_AMDMapperProbe *self;
        bool transferred = false;
        ~R15Scope() { if (!transferred) self->m2b2R15Release(); }
    };

    // 第十轮：本轮声明的受控批次请求数；0 = 未声明。
    UInt32 m2b2ReadDeclaredBatch();

    // 第十一轮：本轮声明的 run token；0 = 未声明。
    //
    // 批次判据必须绑定到"这一次运行"。只按 reqId 归并会把两次不同运行的
    // 记录拼成一个完整批次——见 amd_iommu_dma_observe.hpp 里
    // ObsBatchSpec 的反例 C。
    UInt32 m2b2ReadDeclaredToken();

    // 第十一轮：在窗口打开之前绑定本次驱动实例的 epoch。
    //
    // 【为什么必须在窗口之前】
    //   若在 m2b2ReadDriverObs()（窗口之后）里取 epoch，就等于用被检验的
    //   对象去定义检验标准。绑定点必须先于证据。
    //
    // 取不到时 epochBound 保持 0，读侧拒绝通过——未知不是通过。
    void m2b2BindDriverInstance();

    // 读关闭指针（按 ChipId 推导的寄存器与宽度）。返回 false = 读不到。
    bool m2b2ReadCloPtr(volatile UInt8 *bar, UInt32 *out);
    bool m2b2ReadTailPtr(volatile UInt8 *bar, UInt32 *out);

    // 把第七轮新增的观察字段写成默认值。
    //
    // 为什么需要：observeDeviceDma() 有多条提前返回路径。若它们只写一个
    // m2-b2-dma-obs 就返回，独立分析器看到的是"字段缺失"，只能报
    // CANNOT ANALYSE——那等于说"我没有数据"，而事实是"观察跑了但无法继续"。
    // 两者含义不同，只有一句诚实。
    void m2b2PublishDmaDefaults();

    // 映射表操作
    MapEntry *allocMapEntry();
    bool      freeMapEntry(uint64_t pa, uint64_t len);
    uint32_t  usedMapEntries();
};
