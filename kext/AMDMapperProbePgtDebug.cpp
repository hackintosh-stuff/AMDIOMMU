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

// IOPCIDevice.h itself triggers two -Werror-level warnings from within the SDK:
//   1. IOPCIDevice is marked __kpi_deprecated("Use PCIDriverKit")
//   2. Its internal setProperty overload is not marked override (-Winconsistent-missing-override)
//
// Both are **problems in Apple's own headers**, not defects in this project's code:
//   - PCIDriverKit is a userspace DriverKit framework and cannot implement an
//     IOMapper subclass; this project must be an in-kernel IOKit kext and can
//     only use IOPCIDevice.
//   - The override warning comes from SDK declarations; we cannot and should
//     not modify SDK headers.
//
// Therefore suppress only these two while including that header, without
// disabling them globally -- other genuine deprecation / override issues
// will still be reported as errors as usual.
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

// The single implementation of page table encoding/decoding. Production code
// and the host regression tests **include the same file**, so the tests run
// exactly these branches rather than a separately written Python restatement.
// See tests/pte-core-test.cpp and docs/m2-2b-2-round5-result.md.
#include "amd_iommu_pte_core.hpp"
// [Round 12] The core of walking whole business ranges with the page table.
// Compiled with the host regression from **the same file**, so "production
// walking" and "test walking" are not two implementations corroborating each
// other.
#include "amd_iommu_bizwalk_core.hpp"

// The definition of OSPtr<T> depends on IOKIT_ENABLE_SHARED_PTR (SDK
// libkern/c++/OSPtr.h): defined = OSSharedPtr<T>; undefined = T*.
// The SDK default is undefined.
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

// The service owns these objects while the device translates through them.
// Active TX/RX callbacks borrow the table/MMIO pointers; the setup stack owns
// none of their lifetime after the Round33 handoff.
struct org_maz1_AMDMapperProbe::R33DeviceDomain {
    bool resourcesReleased;
    IOBufferMemoryDescriptor *ptMem;
    IOBufferMemoryDescriptor *tbl;
    IOBufferMemoryDescriptor *cmdBufMd;
    IOBufferMemoryDescriptor *semMd;
    IOBufferMemoryDescriptor *evtMd;
    IOMemoryDescriptor *md;
    IOMemoryMap *map;
    IOMemoryMap *postMap;
    volatile UInt8 *base;
    volatile UInt64 *pt;
    volatile UInt64 *dte;
    volatile UInt64 *root;
    volatile UInt64 *l2;
    volatile UInt64 *sem;
    volatile UInt32 *evtBuf;
    UInt64 ptPA;
    UInt64 tblPA;
    UInt64 cmdPA;
    UInt64 semPA;
    UInt64 evtPA;
    UInt64 ptBytes;
    UInt64 rootPA;
    UInt64 l2PA;
    UInt64 origDT;
    UInt64 origCmd;
    UInt64 origEvt;
    UInt64 origCtrl;
    UInt32 ptPageCount;
    UInt32 tgt;
    UInt32 tailAfterRaw;
    UInt32 cloAfterRaw;
    bool preWindowRan;
    bool mainWindowRan;
    bool hwStopped;
    bool cmdBufStopped;
    bool evtLogStopped;
    bool regsRestored;
    bool safeToFree;
    bool evtResetOk;
    bool invAllOk;
    bool invDevOk;
    bool invPagesOk;
    bool controlDone;
    bool tailAfterOk;
    bool cloAfterOk;
    bool postSampleDone;
    const char *firstFailStage;
    const char *firstFailReason;
    // Setup/final diagnostic snapshot only. After r17SyncCommand, the active
    // R17Domain owns the sole producer cursor until r17Export returns it.
    M2B2CmdCtx ctx;
    M2b2PostSample postSample;
};

// ===== AMDMapperProbePgt.cpp (original lines 5206..5278) =====
bool org_maz1_AMDMapperProbe::scheduleM22b2() {
    if (!parsePgtBootArg()) {
        setProperty("m2-b2-gate", "closed");
        setProperty("m2-b2-stage", "1-skipped-no-bootarg");
        return false;
    }
    setProperty("m2-b2-gate", "open");

    // Leaf page size mode: amdiommu=pgt4k selects 4 KiB, amdiommu=pgt selects
    // 2 MiB large pages. Two values of the same boot-arg, avoiding a second
    // parameter (measured: extra parameters like m2b2delay were not picked up
    // by PE_parse_boot_argn).
    fM22b2Use4K = parsePgt4kBootArg();
    // [v0.20.0] pgthold / pgtsleep no longer change the measurement window
    // length. The old code used them to stretch the baseline window from 2 s
    // to 20 s while controls stayed at 2 s, creating a 10x mismatch (see the
    // m2b2MeasureEvents comment). The window is now constant
    // M2B2_MEAS_SECS; these two modes keep only their historical semantic
    // markers and no longer affect counting.
    fM22b2Hold  = parsePgtHoldBootArg();
    fM22b2SleepOnly = parsePgtSleepBootArg();
    fM22b2Use3L = parsePgt3lBootArg();
    fR31Session = r31SessionRequested();
    if (fR31Session) {
        setProperty("m2-3l-session-mode", "explicit-stop");
        setProperty("m2-3l-session-state", "preparing");
        setProperty("m2-3n-domain-mode", "service-owned");
        setProperty("m2-3n-domain-state", "preparing");
        setHexProperty(this, "m2-3n-setup-worker-active", 0);
        setHexProperty(this, "m2-3n-install-count", 0);
    }
    setProperty("m2-b2-leaf-mode-src",
        fM22b2Use4K ? "amdiommu=pgt4k" : "amdiommu=pgt");
    setProperty("m2-b2-hold-mode",
        fM22b2SleepOnly ? "sleep-only-marker"
                        : (fM22b2Hold ? "hold-marker" : "none"));
    setProperty("m2-b2-level-mode", fM22b2Use3L ? "3-level" : "4-level");
    setHexProperty(this, "m2-b2-meas-secs", M2B2_MEAS_SECS);

    // Delay value: default 20000 ms, overridable with m2b2delay=<seconds>
    // (capped at 300 s)
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
        this, &org_maz1_AMDMapperProbe::m22b2TimerFired);
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
void org_maz1_AMDMapperProbe::m22b2TimerFired(
    OSObject *owner, IOTimerEventSource *sender) {
    (void)sender;
    org_maz1_AMDMapperProbe *self =
        OSDynamicCast(org_maz1_AMDMapperProbe, owner);
    if (!self) return;

    // The timer is one-shot: it does not reschedule after firing.
    self->setProperty("m2-b2-schedule", "fired");

    if (self->fR31Session) {
        UInt32 inactive = 0;
        if (!__atomic_compare_exchange_n(&self->fR31WorkerActive, &inactive,
                1u, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return;
        setHexProperty(self, "m2-3n-setup-worker-active", 1);
        self->retain();
        thread_t worker = THREAD_NULL;
        const kern_return_t kr = kernel_thread_start(
            &org_maz1_AMDMapperProbe::r31SessionWorker, self, &worker);
        if (kr != KERN_SUCCESS) {
            self->setProperty("m2-3l-session-state", "failed");
            self->setProperty("m2-3n-domain-state", "failed");
            setHexProperty(self, "m2-3n-setup-worker-active", 0);
            setHexProperty(self, "m2-3l-worker-error", (UInt64)kr);
            __atomic_store_n(&self->fR31WorkerActive, 0u, __ATOMIC_RELEASE);
            self->release();
            return;
        }
        // kernel_thread_start returns a caller-owned reference. The worker
        // holds the probe separately and exits after the ownership handoff.
        thread_deallocate(worker);
        return;
    }

    // Legacy finite experiments keep their existing workloop scheduling.
    self->runM22b2PageTableProbe();
}

void org_maz1_AMDMapperProbe::r31SessionWorker(
    void *parameter, wait_result_t result) {
    (void)result;
    org_maz1_AMDMapperProbe *self =
        static_cast<org_maz1_AMDMapperProbe *>(parameter);
    self->runM22b2PageTableProbe();
    if (!__atomic_load_n(&self->fR33Domain, __ATOMIC_ACQUIRE)) {
        self->setProperty("m2-3l-session-state", "failed");
        self->setProperty("m2-3n-domain-state", "failed");
    }
    setHexProperty(self, "m2-3n-setup-worker-exit-time", mach_absolute_time());
    setHexProperty(self, "m2-3n-setup-worker-active", 0);
    __atomic_store_n(&self->fR31WorkerActive, 0u, __ATOMIC_RELEASE);
    // stop() also waits for the service-owned domain, so this handoff cannot
    // allow provider teardown between the two short-lived workers.
    if (__atomic_load_n(&self->fR31StopRequested, __ATOMIC_ACQUIRE))
        self->r33ScheduleDomainStop();
    self->release();
    thread_terminate(current_thread());
}

bool org_maz1_AMDMapperProbe::r33DomainStopPending() const {
    return __atomic_load_n(&fR33Domain, __ATOMIC_ACQUIRE) &&
        __atomic_load_n(&fR33TeardownState, __ATOMIC_ACQUIRE) != 2;
}

void org_maz1_AMDMapperProbe::r33ScheduleDomainStop() {
    if (!fR31Session ||
        !__atomic_load_n(&fR31StopRequested, __ATOMIC_ACQUIRE) ||
        !__atomic_load_n(&fR33Domain, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&fR33TeardownState, __ATOMIC_ACQUIRE)) return;
    UInt32 inactive = 0;
    if (!__atomic_compare_exchange_n(&fR31WorkerActive, &inactive, 1u,
            false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return;
    UInt32 unstarted = 0;
    if (!__atomic_compare_exchange_n(&fR33TeardownState, &unstarted, 1u,
            false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&fR31WorkerActive, 0u, __ATOMIC_RELEASE);
        return;
    }
    retain();
    thread_t worker = THREAD_NULL;
    const kern_return_t kr = kernel_thread_start(
        &org_maz1_AMDMapperProbe::r33DomainStopWorker, this, &worker);
    if (kr != KERN_SUCCESS) {
        setProperty("m2-3l-session-state", "failed");
        setProperty("m2-3n-domain-state", "failed");
        setHexProperty(this, "m2-3n-teardown-worker-error", (UInt64)kr);
        __atomic_store_n(&fR33TeardownState, 2u, __ATOMIC_RELEASE);
        __atomic_store_n(&fR31WorkerActive, 0u, __ATOMIC_RELEASE);
        release();
        return;
    }
    thread_deallocate(worker);
}

void org_maz1_AMDMapperProbe::r33DomainStopWorker(
    void *parameter, wait_result_t result) {
    (void)result;
    auto *self = static_cast<org_maz1_AMDMapperProbe *>(parameter);
    R33DeviceDomain *domain = __atomic_load_n(&self->fR33Domain, __ATOMIC_ACQUIRE);
    setHexProperty(self, "m2-3n-teardown-start", mach_absolute_time());
    self->setProperty("m2-3n-domain-state", "stopping");
    self->finishM22b2PageTableProbe(domain, true);
    // R33 DOMAIN RELEASE: hardware restore and resource release precede the
    // driver's final owner release. Failed drain/restore retains the context.
    const bool completed = domain->resourcesReleased && self->fR31SessionCompleted;
    if (domain->resourcesReleased) {
        __atomic_store_n(&self->fR33Domain, (R33DeviceDomain *)nullptr, __ATOMIC_RELEASE);
        self->m2b2R15Release();
        IOFree(domain, sizeof(*domain));
    }
    setHexProperty(self, "m2-3n-teardown-end", mach_absolute_time());
    setHexProperty(self, "m2-3l-session-end", mach_absolute_time());
    self->setProperty("m2-3l-session-state", completed ? "stopped" : "failed");
    self->setProperty("m2-3n-domain-state", completed ? "stopped" : "failed");
    __atomic_store_n(&self->fR33TeardownState, 2u, __ATOMIC_RELEASE);
    __atomic_store_n(&self->fR31WorkerActive, 0u, __ATOMIC_RELEASE);
    self->release();
    thread_terminate(current_thread());
}

// ===== AMDMapperProbePgt.cpp (original lines 5310..7405) =====
void org_maz1_AMDMapperProbe::runM22b2PageTableProbe() {
    setProperty("m2-b2-stage", "0-start");
    fR15Service = nullptr;
    bzero(&fR15Request, sizeof(fR15Request));
    fR15PoolRpcCalls = 0;
    if (fR31Session) setHexProperty(this, "m2-3p-rx-pool-rpcs", 0);
    fR15MapTicks = 0;
    fR15InvTicks = 0;
    R15Scope r15Scope = {this};
    R33DeviceDomain *domain = (R33DeviceDomain *)IOMalloc(sizeof(R33DeviceDomain));
    if (!domain) {
        setProperty("m2-b2-stage", "2-FAIL-domain-context");
        return;
    }
    bzero(domain, sizeof(*domain));
    struct ContextScope {
        R33DeviceDomain *owned;
        ~ContextScope() { if (owned) IOFree(owned, sizeof(*owned)); }
    } contextScope = {domain};

    // The gate was already checked in scheduleM22b2() (only amdiommu=pgt
    // reaches here). parsePgtBootArg() is deliberately not repeated here to
    // avoid the two sites drifting apart.

    // ---- Stage state (v0.20.0) ----
    //
    // [Why initialization must happen at the very top of the function]
    //   Round 4's two window structs winPre / winMain were **uninitialized
    //   stack variables**, written only if the corresponding stage actually
    //   reached m2b2SampleEvents(). The verdict stage unconditionally reads
    //   winMain.valid / winMain.entries. So a "failed before sampling" path
    //   would read stack garbage -- if it happened to be non-zero, a window
    //   that never ran would be treated as "valid window with no events",
    //   yielding an INDETERMINATE that looks like "tested but no conclusion".
    //
    //   Explicit initialization here, plus two booleans recording "did this
    //   stage actually run", lets the verdict stage distinguish "ran and had
    //   no events" from "never ran at all".
    // [v0.21.7] The window structs moved to members, no longer on the stack.
    //
    // Each org_maz1_AMDMapperProbe::M22b2EventWindow is 0x1A8 = 424 bytes
    // (including 16*4 raw UInt32 events). Two of them total 848 bytes -- the
    // last straw that pushed this function's frame past the __chkstk threshold
    // (measured 0x1040 = 4160). Round 5's reduction of
    // org_maz1_AMDMapperProbe::kM22b2RawKeep from 32 to 16 only papered over
    // the symptom; moving the structs to members is the real fix for the weak
    // reference.
    org_maz1_AMDMapperProbe::M22b2EventWindow &winPre = fM22b2WinPre;
    org_maz1_AMDMapperProbe::M22b2EventWindow &winMain = fM22b2WinMain;
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

    // Records "did this stage actually run". 0 = not run, 1 = ran.
    bool preWindowRan = false;
    bool mainWindowRan = false;

    // The first failing stage. Once set it is not overwritten by later generic
    // status -- the task's requirement to "keep the first failing stage so
    // later generic status does not mask the cause".
    const char *firstFailStage = nullptr;
    const char *firstFailReason = nullptr;

    setProperty("m2-b2-pre-window-ran", "no");
    setProperty("m2-b2-main-window-ran", "no");

    // ---- Step 1: allocate all memory ----
    //
    // One contiguous block holds all page table pages.
    // Why one block rather than allocating each page separately:
    //   Separate allocations yield non-contiguous physical pages requiring
    //   getPhysicalSegment per page -- complex code that can easily grab a
    //   wrong index. In one contiguous block every page's physical address is
    //   base + n*4096, which cannot be miscalculated.
    //
    // 2 MiB mode: 1 root + 1 L2 + 16 leaves + 1 empty root = 19 pages = 76 KiB
    // 4 KiB mode: 1 root + 1 L2 + 32 leaves + 1 empty root = 35 pages = 140 KiB
    const bool nativeSparse = fR31Session && !fM22b2SleepOnly;
    const UInt32 legacyBasePtPageCount =
        fM22b2Use4K ? M2B2_4K_TOTAL_PAGES
                    : (fM22b2Use3L ? M2B2_3L_TOTAL_PAGES : M2B2_TOTAL_PAGES);
    // Native starts with only the root and an independent empty reserve page.
    // Keep the existing allocation capacity for the native IOVA tables.
    const UInt32 basePtPageCount = nativeSparse ? 2u : legacyBasePtPageCount;
    const UInt32 ptPageCount = legacyBasePtPageCount + 256u + M2B2_IOVA_RESERVED_PAGES;
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

    // Everything must be 4 KiB aligned (page table pages require it; the rest
    // is a register-write requirement)
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

    // ---- Step 2: build the device table (all pass-through) ----
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

    // ---- Step 3: build the 4-level identity page table ----
    //
    // Page table page layout within ptMem (page numbers from 0):
    //   page 0            : root table (level 3)
    //   page 1 .. 16      : L2 tables (level 2), each covering 1 GiB
    //   page 17 .. 8208   : leaf tables (level 1), each covering the 512
    //                       2 MiB pages of one GiB
    volatile UInt64 *pt = (volatile UInt64 *)ptMem->getBytesNoCopy();

    // Zero everything first: unused entries must be 0 (PR=0 means absent),
    // otherwise the hardware dereferences garbage addresses.
    const UInt64 ptQwords = ptBytes / 8;
    for (UInt64 i = 0; i < ptQwords; i++) pt[i] = 0;

    const UInt64 rootPageIdx  = 0;
    const UInt64 l2PageBase   = rootPageIdx + M2B2_ROOT_PAGES;    // 1
    const UInt64 leafPageBase = l2PageBase + M2B2_L2_PAGES;       // 2

    // Physical address conversion: page number -> physical address.
    // ptPA is the physical base of this contiguous block; page n's physical
    // address = ptPA + n*4096
    const UInt64 rootPA = (UInt64)ptPA + rootPageIdx * M2B2_PAGE_SIZE;
    UInt64 l2PA = (UInt64)ptPA + l2PageBase * M2B2_PAGE_SIZE;

    volatile UInt64 *root = pt + rootPageIdx * M2B2_PTE_COUNT;
    volatile UInt64 *l2   = pt + l2PageBase  * M2B2_PTE_COUNT;

    // Root entries: point to the single L2 table.
    // 2 MiB mode: all 16 GiB falls in IOVA 0..0x3FFFFFFFF, i.e. idx3 = 0.
    // 4 KiB mode: only 64 MiB is mapped, likewise idx3 = 0.
    // [3-level mode] The root table itself is "level 2"; **there is no L2
    // layer**: root entries point directly at leaf tables, so
    // root[0] = TablePte(3,...) must not be written here.
    if (!nativeSparse && !fM22b2Use3L) {
        root[0] = m2b2TablePte(3, l2PA);
    }

    if (nativeSparse) {
        // The native root stays empty until standard IOVA maps are requested.
        // r34RxPrepareMap validates the unchanged physical ring manifest.
    } else if (fM22b2Use3L) {
        // ---- 3-level + 2 MiB large pages: root(2) -> leaf(1), covering 16 GiB ----
        //
        // PAGE_MODE_3_LEVEL = 3 -> the root is level 2, each entry covering
        // 1 GiB. 16 GiB uses root entries 0..15, each pointing directly at one
        // leaf table. Each leaf entry covers 2 MiB; 512 entries cover 1 GiB.
        //
        // Leaf tables start at l2PageBase (that page was reserved for L2; the
        // 3-level mode has no L2).
        for (UInt32 gb = 0; gb < M2B2_3L_LEAF_PAGES; gb++) {
            const UInt64 leafPageIdx = leafPageBase + gb;
            const UInt64 leafPA = (UInt64)ptPA + leafPageIdx * M2B2_PAGE_SIZE;

            // Root entry (level 2) points directly at a leaf table (level 1)
            root[gb] = m2b2TablePte(2, leafPA);

            volatile UInt64 *leaf = pt + leafPageIdx * M2B2_PTE_COUNT;
            const UInt64 base1G = (UInt64)gb << 30;
            for (UInt32 i = 0; i < M2B2_PTE_COUNT; i++) {
                const UInt64 pa = base1G + ((UInt64)i << 21);
                leaf[i] = m2b2LargeLeaf(pa);
            }
        }
    } else if (!fM22b2Use4K) {
        // ---- 2 MiB large pages: 16 leaf tables, each covering 1 GiB ----
        for (UInt32 gb = 0; gb < M2B2_LEAF_PAGES; gb++) {
            const UInt64 leafPageIdx = leafPageBase + gb;
            const UInt64 leafPA = (UInt64)ptPA + leafPageIdx * M2B2_PAGE_SIZE;

            // idx2 = (addr >> 30) & 0x1ff, which at 1 GiB stride is simply gb
            l2[gb] = m2b2TablePte(2, leafPA);

            // Leaf table: 512 2 MiB entries covering [gb*1GiB, (gb+1)*1GiB)
            volatile UInt64 *leaf = pt + leafPageIdx * M2B2_PTE_COUNT;
            const UInt64 base1G = (UInt64)gb << 30;
            for (UInt32 i = 0; i < M2B2_PTE_COUNT; i++) {
                const UInt64 pa = base1G + ((UInt64)i << 21);
                leaf[i] = m2b2LargeLeaf(pa);
            }
        }
    } else {
        // ---- 4 KiB small pages: root(3) -> L2(2) -> L1(1) -> leaf(0), covering 16 GiB ----
        //
        // Coverage per level:
        //   One L2 entry covers 1 GiB; 16 GiB needs 16 entries -> l2[0..15]
        //   each point to one L1 table
        //   One L1 entry covers 2 MiB; one L1 table's 512 entries = 1 GiB
        //   Each leaf entry covers 4 KiB; one leaf table's 512 entries = 2 MiB
        //
        // So: 16 L1 tables x 512 entries = 8192 leaf tables, exactly covering
        // 16 GiB.
        const UInt64 l1PageBase = leafPageBase;                 // right after L2
        const UInt64 leaf0PageBase = l1PageBase + M2B2_4K_L1_PAGES;

        for (UInt32 gb = 0; gb < M2B2_4K_L1_PAGES; gb++) {
            const UInt64 l1PageIdx = l1PageBase + gb;
            const UInt64 l1PA = (UInt64)ptPA + l1PageIdx * M2B2_PAGE_SIZE;
            volatile UInt64 *l1 = pt + l1PageIdx * M2B2_PTE_COUNT;

            // L2[gb] points at the gb-th L1 table (a level 2 entry points at a level 1 table)
            l2[gb] = m2b2TablePte(2, l1PA);

            // This L1 table covers [gb*1GiB, (gb+1)*1GiB), 512 leaf tables in total
            for (UInt32 li = 0; li < M2B2_PTE_COUNT; li++) {
                const UInt64 leafGlobal = (UInt64)gb * M2B2_PTE_COUNT + li;
                const UInt64 leafPageIdx = leaf0PageBase + leafGlobal;
                const UInt64 leafPA =
                    (UInt64)ptPA + leafPageIdx * M2B2_PAGE_SIZE;

                // L1's li-th entry points at one leaf table (a level 1 entry points at a level 0 table)
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

    // Freeze the current RX ring BEFORE the DTE can switch. Native sessions
    // borrow Lucy's existing buffers; the historical finite path uses R15.
    // Native preparation stays copy-only; the NIC stops before DTE entry.
    if (!fM22b2SleepOnly &&
        (!m2b2R15PrepareMap(pt, (UInt64)ptPA,
                           nativeSparse ? ptPageCount : ptPageCount - M2B2_IOVA_RESERVED_PAGES,
                           basePtPageCount) ||
         !r17Prepare(pt, (UInt64)ptPA, ptPageCount))) {
        setProperty("m2-b2-verdict", fR31Session ? "FAIL-native-ring-pre-map"
                                               : "FAIL-r15-owned-pre-map");
        setProperty("m2-b2-stage", "3b-abort-owned-map");
        ptMem->release(); tbl->release(); cmdBufMd->release();
        semMd->release(); evtMd->release();
        return;
    }
    if (nativeSparse) {
        // The IOVA helper allocated the actual child after the empty page.
        // Carry that address into the service-owned domain and later dumps.
        l2PA = fM22b2Use3L ? rootPA : root[0] & M2B2_PTE_ADDR_MASK;
        l2 = pt + (l2PA - (UInt64)ptPA) / sizeof(UInt64);
    }
    setProperty("m2-b2-pt", nativeSparse ? "built-iova-only" : "built-4level-identity");
    setProperty("m2-b2-leaf-mode", (nativeSparse || fM22b2Use4K) ? "4KiB" : "2MiB");
    if (nativeSparse) setProperty("m2-b2-leaf-mode-src", "native-iova-only");
    setHexProperty(this, "m2-b2-map-limit",
                   nativeSparse ? 0 : (fM22b2Use4K ? M2B2_4K_MAP_LIMIT : M2B2_IDENTITY_LIMIT));
    setHexProperty(this, "m2-b2-pt-root-pa", rootPA);
    setHexProperty(this, "m2-b2-pt-l2-pa", l2PA);
    if (!nativeSparse) {
        setHexProperty(this, "m2-b2-leaf-pages",
                       fM22b2Use4K ? M2B2_4K_LEAF_PAGES : M2B2_LEAF_PAGES);
        setHexProperty(this, "m2-b2-leaf-ptes",
                       fM22b2Use4K ? M2B2_4K_LEAF_PTES : M2B2_LEAF_PTE_COUNT);
        setHexProperty(this, "m2-b2-l2-pages", M2B2_L2_PAGES);
        setHexProperty(this, "m2-b2-l1-pages",
                       fM22b2Use4K ? M2B2_4K_L1_PAGES : 0);
    }

    // ---- Step 4: page table self-check (software walk, no hardware touched) ----
    //
    // Before handing this table to the hardware, walk it once using **the same
    // implementation as the decoder**.
    //
    // [Round 5 rewrite] Round 4's version here was hand-written per-level
    // if/else whose leaf criterion was
    //     lvl == M2B2_LEVEL_7 && m2b2PtePageSize(pte1) == 2MiB
    // i.e. "the leaf must have NextLevel=7". That shared the builder's wrong
    // assumption, so **a passing self-check proved only that the two agreed --
    // not that the encoding was correct**.
    //
    // Now it calls amdpte::walkPageTable(), which requires the level to be
    // carried at every step and encodes the spec rule "an extended page size
    // must be strictly larger than this level's default" into the decoder. A
    // shared error of "builder wrong + checker wrong" is thus caught at the
    // self-check stage.
    if (!nativeSparse) {
        bool walkOk = true;
        UInt32 walkBad = 0;
        UInt64 walkFirstBad = 0;
        UInt32 walkChecked = 0;
        const char *walkFirstReason = nullptr;

        // Sample coverage: intra-page offsets, page boundaries, 2 MiB
        // boundaries, and the 1/4/8/15/16 GiB boundaries.
        const UInt64 samples[] = {
            0x0ULL, 0x1ULL, 0xFFFULL, 0x1000ULL,
            0x1FFFFFULL, 0x200000ULL, 0x3FFFFFULL,
            0x40000000ULL,                  // 1 GiB boundary
            0x100000000ULL,                 // 4 GiB boundary
            0x200000000ULL,                 // 8 GiB boundary
            0x3C0000000ULL,                 // 15 GiB
            0x3FFE00000ULL,                 // 16 GiB - 2 MiB
            0x3FFFFFFF0ULL,                 // 16 GiB - 16
        };
        const UInt32 nSamples = (UInt32)(sizeof(samples) / sizeof(samples[0]));

        const UInt64 mapLimit = fM22b2Use4K ? M2B2_4K_MAP_LIMIT
                                            : M2B2_IDENTITY_LIMIT;

        // Walking reader: converts a PTE's physical address into an offset in
        // pt. Out-of-range reads return 0 (PR=0 -> decoded as absent); no
        // out-of-bounds access ever happens.
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

        // Root level: 4-level mode = 4, 3-level mode = 3 (spec numbering is 1-based)
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

    // ---- Step 4b: verify the page table's physical and virtual addresses
    //      really name the same memory ----
    //
    // Why this step must exist:
    //   The software walk (step 4) uses the **virtual pointer** pt;
    //   the hardware walk uses the **physical base** rootPA from the DTE.
    //   If the two are not the same memory, "the software walk passed" means
    //   nothing to the hardware -- we validated different memory.
    //
    // This project has already confused PA/VA once (flush_dcache64 given a
    // physical address -> two panics), so this assumption cannot pass on "it
    // should be fine"; it must be measured.
    //
    // Approach: map ptPA in as a physical address and compare byte for byte
    // with pt.
    //   All identical -> the software walk's verdict is valid for the hardware
    //   Any difference -> every prior "the page table is correct" verdict is void
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

    // ---- Step 6: map the MMIO and verify identity ----
    //
    // The MMIO window is both read and written; the direction stays
    // kIODirectionNone (consistent with M2-1 / M2-2b-1). Setting the buffer to
    // kIODirectionOut above targets the **page table / device table / command
    // buffer** memory ("written by CPU, read by device"), not the MMIO mapping.
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

    // ---- Step 7: record the original state ----
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

    // ---- Step 8: determine the target device's devid (must precede enable!) ----
    //
    // [2026-10-30 serious incident] This step was originally placed after the
    // enable and took the device from fNicDevice. But fNicDevice is set only
    // under amdiommu=arm; this round runs amdiommu=pgt, so fNicDevice was NULL
    // -> tgtOk=false -> the function returned directly **with the IOMMU
    // already enabled**, releasing the device table memory.
    //
    // Consequence: the IOMMU kept running, DEV_TABLE pointed at freed 2 MiB
    // memory, the command buffer was freed too. The hardware went on
    // translating all system DMA through that "wild pointer table"; boot
    // deadlocked at 0.42 s, reproduced twice in a row.
    //
    // Two lessons:
    //   1. Every "can fail" precondition must be checked **before touching the
    //      hardware**. Once the IOMMU is enabled, no bare return is allowed
    //      afterwards.
    //   2. Do not reuse stateful member variables (fNicDevice is governed by
    //      fArmed); what is needed here is a **read-only lookup**, independent
    //      of whether devices are let through.
    UInt32 tgt = 0;
    bool tgtOk = false;
    {
        IOService *nicSvc = findNicServiceOnly();
        if (nicSvc) {
            // IOPCIDevice is marked deprecated, but this kext must be an
            // in-kernel IOMapper subclass; PCIDriverKit (userspace) cannot
            // replace it. Handled like runM20ConfigProbe: suppress only in this
            // small scope, not globally.
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
        // At this point **no hardware register has been touched**; returning is
        // safe.
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

    // ---- Step 9: configure and enable (including the event log) ----
    //
    // The order strictly follows early_enable_iommu() (init.c:2798-2811):
    //   device table -> command buffer -> event buffer -> enable
    const UInt64 dtEntry = ((UInt64)tblPA & ~0xFFFULL) |
                           ((M22B_TABLE_SIZE_FULL >> 12) - 1);
    const UInt64 cmdEntry = ((UInt64)cmdPA & ~0xFFFULL) | M23_CMD_SIZE_CODE;
    const UInt64 evtEntry = ((UInt64)evtPA & ~0xFFFULL) | M2B2_EVT_LEN_MASK;

    // ---- Ensure the page table and device table are visible to the device ----
    //
    // [2026-10-31 fix] This originally called flush_dcache64((addr64_t)ptPA,
    // ...), passing a **physical address** where the kernel API expects a
    // **virtual address**. Even though that API is a no-op on x86, passing the
    // wrong address family is a clear error, and boot anomalies followed in
    // testing. Replaced with the safe approach:
    //
    //   1. IOBufferMemoryDescriptor was allocated with kIODirectionOut (see
    //      step 1 above); IOKit guarantees the memory is visible to the device;
    //   2. OSSynchronizeIO() additionally forces write ordering, preventing
    //      compiler/CPU reordering from letting MMIO register writes land
    //      before the memory writes.
    //
    // Why no explicit flush is needed:
    //   x86 caches are **hardware-coherent** (the IOMMU snoops CPU caches when
    //   walking tables), and AMD-Vi's CONTROL_COHERENT_EN is set (measured:
    //   control-on includes bit10). Linux does not dcache-flush page tables on
    //   x86 either -- it relies on the same hardware coherence.
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

    // ---- Step 10: command context ----
    //
    // All devid / domid / page-mode / root table address / completion signal
    // address are held by ctx, and invalidation commands always take their
    // values from it. The old code changed the DTE's domain in the DOMID branch
    // yet still issued INV_IOMMU_PAGES with domain 0 -- flushing a domain that
    // did not exist. That inconsistency is now structurally impossible.
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

    // Restore state: memory may be freed only if everything here is true
    bool hwStopped      = false;
    bool cmdBufStopped  = false;
    bool evtLogStopped  = false;
    bool regsRestored   = false;
    bool safeToFree     = false;

    // ---- Round 7: stage completion state ----
    //
    // The verdict must distinguish "the stage ran and succeeded" from "the
    // stage was never reached". Round 6's CONTROL branch looked only at the
    // fM22b2SleepOnly **choice**, not at whether the control stage actually
    // completed: a failed event-log reset, a failed command, or a failed
    // recovery would all be overwritten by CONTROL, turning "I chose control
    // mode" into a universal verdict.
    //
    // Every precondition gate now has its own boolean, and CONTROL is emitted
    // only when all of them hold and the control stage itself really finished.
    bool evtResetOk     = false;   // step 11: event log reset succeeded
    bool invAllOk       = false;   // step 12: CMD_INV_ALL completed
    bool invDevOk       = false;   // step 15(a): INV_DEV_ENTRY completed
    bool invPagesOk     = false;   // step 15(b): INV_IOMMU_PAGES completed
    bool controlDone    = false;   // the control stage (pgtsleep) really finished

    // [Round 8] Boundary sampling results at window end.
    //
    // Declared here rather than in step 16b: this function has several
    // `goto recover` jumping in from steps 11-15, and C++ forbids jumping over
    // declarations with initializers. Placing them before all gotos satisfies
    // the language rule and makes "the recovery path can also see these values"
    // a structural fact rather than a convention.
    UInt32 tailAfterRaw = 0;
    bool   tailAfterOk  = false;
    UInt32 cloAfterRaw  = 0;
    bool   cloAfterOk   = false;

    // [Round 9] In-window post-sampling.
    //
    // The sampling state and mapping must also be declared before all gotos
    // (same reason: C++ forbids goto over initialized declarations). postMap is
    // created in step 16 and released as soon as the window closes, so
    // "registers read inside the window" happens only inside the window.
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

    // No captured closure escapes this function. Only the pointed-to hardware
    // objects and plain recovery state transfer into the service context.
    auto saveDomain = [&]() {
        domain->ptMem = ptMem;
        domain->tbl = tbl;
        domain->cmdBufMd = cmdBufMd;
        domain->semMd = semMd;
        domain->evtMd = evtMd;
        domain->md = md;
        domain->map = map;
        domain->postMap = postMap;
        domain->base = base;
        domain->pt = pt;
        domain->dte = dte;
        domain->root = root;
        domain->l2 = l2;
        domain->sem = sem;
        domain->evtBuf = evtBuf;
        domain->ptPA = ptPA;
        domain->tblPA = tblPA;
        domain->cmdPA = cmdPA;
        domain->semPA = semPA;
        domain->evtPA = evtPA;
        domain->ptBytes = ptBytes;
        domain->rootPA = rootPA;
        domain->l2PA = l2PA;
        domain->origDT = origDT;
        domain->origCmd = origCmd;
        domain->origEvt = origEvt;
        domain->origCtrl = origCtrl;
        domain->ptPageCount = ptPageCount;
        domain->tgt = tgt;
        domain->tailAfterRaw = tailAfterRaw;
        domain->cloAfterRaw = cloAfterRaw;
        domain->preWindowRan = preWindowRan;
        domain->mainWindowRan = mainWindowRan;
        domain->hwStopped = hwStopped;
        domain->cmdBufStopped = cmdBufStopped;
        domain->evtLogStopped = evtLogStopped;
        domain->regsRestored = regsRestored;
        domain->safeToFree = safeToFree;
        domain->evtResetOk = evtResetOk;
        domain->invAllOk = invAllOk;
        domain->invDevOk = invDevOk;
        domain->invPagesOk = invPagesOk;
        domain->controlDone = controlDone;
        domain->tailAfterOk = tailAfterOk;
        domain->cloAfterOk = cloAfterOk;
        domain->postSampleDone = postSampleDone;
        domain->firstFailStage = firstFailStage;
        domain->firstFailReason = firstFailReason;
        domain->ctx = ctx;
        domain->postSample = postSample;
    };

    // The window records (winPre / winMain) were initialized at the top of the
    // function; see the explanation there.

    // ---- Step 11: reset the event log per the spec ----
    //
    // This is the only entry allowed to write HEAD/TAIL: first stop
    // EVT_LOG_EN, wait for EVT_RUN=0, then zero, clear the overflow bit, and
    // re-enable. TAIL is never touched while the log runs.
    {
        const bool ok = m2b2ResetEventLog(base);
        setProperty("m2-b2-evt-reset", ok ? "done" : "FAIL-cannot-stop-log");
        if (!ok) {
            // Cannot confirm the log stopped -> do not touch the buffer, do
            // not run the experiment, go straight to recovery
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

    // ---- Step 12: flush caches once after enable (still all pass-through now) ----
    //
    // CMD_INV_ALL (type 0x08) is legal when FEATURE_IA=1 (decoded and confirmed
    // in round 3).
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

    // ---- Step 13: pure-sleep control (pgtsleep) ----
    //
    // This branch **does not switch the DTE**; it only performs the same long
    // sleep as pgthold, distinguishing "translation freezes the device" from
    // "a long IOSleep blocking the workloop creates a measurement artifact".
    //
    // [Explicit duration] This branch is fixed at 20 s, **not** M2B2_MEAS_SECS.
    // Its purpose is to observe from outside via netstat whether the device is
    // still transmitting, which needs a sufficiently long window; it produces
    // no event counts used for comparison, so no window mismatch arises.
    if (fM22b2SleepOnly) {
        setProperty("m2-b2-sleep-only", "yes");
        setProperty("m2-b2-dte", "NOT-switched-control");
        setHexProperty(this, "m2-b2-window-secs", 20);
        // The control stage's time boundaries must also be checkable monotonic
        // time.
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

        // [Round 7] The control stage really completed.
        //
        // This boolean is a **necessary condition** of the CONTROL verdict:
        // only when the preceding reset, the commands, and the control stage
        // itself all hold may CONTROL be emitted. Round 6 looked only at the
        // fM22b2SleepOnly "choice", so any real failure was masked.
        controlDone = true;

        setProperty("m2-b2-evt-window", "none-in-sleep-only-branch");
        setProperty("m2-b2-verdict", "CONTROL-sleep-only-no-dte-change");
        setProperty("m2-b2-stage", "13-control-complete");
        goto recover;
    }

    // ---- Step 14: build the device table entry and switch the target device to translation ----
    //
    // set_dte_entry() (iommu.c:1580-1602):
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

        // Sample one window before the switch: the DTE is still pass-through,
        // so any event is not caused by translation.
        m2b2SampleEvents(base, evtBuf, M2B2_MEAS_SECS, tgt, &winPre);
        preWindowRan = true;
        setProperty("m2-b2-pre-window-ran", "yes");
        setHexProperty(this, "m2-b2-pre-entries", winPre.entries);
        setProperty("m2-b2-pre-valid", winPre.valid ? "yes" : "no");
        if (!winPre.valid) {
            setProperty("m2-b2-pre-invalid", winPre.invalidReason);
        }

        // [v0.20.0] A winPre that is invalid **forbids** continuing the
        // translation experiment. Reason: winPre exists to provide the
        // "same device, same time span, DTE not switched" comparison. If it is
        // itself invalid (overflow / log stopped / torn entries), the main
        // window cannot be attributed even if valid -- the baseline is lost.
        // Continuing only yields an unexplainable number, exactly the failure
        // shape of rounds 3 and 4.
        if (!winPre.valid) {
            firstFailStage = "14-pre-window-invalid";
            firstFailReason = winPre.invalidReason;
            setProperty("m2-b2-first-fail-stage", firstFailStage);
            setProperty("m2-b2-first-fail-reason", firstFailReason);
            setProperty("m2-b2-verdict", "INVALID-pre-window");
            setProperty("m2-b2-stage", "14-abort-pre-window");
            // The DTE was not yet modified, so nothing to revert; go straight
            // to recovery.
            goto recover;
        }

        // ---- Step 14b: the first half of entering the window (round22 ordering fix) ----
        //
        // [Why here and not after writing the DTE]
        //   Round 21's order was "write DTE -> two invalidations -> Install ->
        //   drain -> open the gate". The drain happened after the DTE had
        //   already switched, so TX already handed to the hardware under the
        //   old mapping had in fact been translated by the new table; worse,
        //   an output thread that had passed the old path but not yet written
        //   OWN was in neither the gate count nor the ring occupancy -- the
        //   drain was blind to it.
        //
        //   The order now: Install (close admission, publish state) -> wait for
        //   submitters to exit and drain the old-mapping ring -> write the DTE
        //   -> invalidate -> only then open admission. The DTE switch never
        //   races any outstanding submission, because the admission bytes'
        //   reference count includes them all.
        //
        // [Why Install comes after the pre-window]
        //   The pre-window is the "DTE still pass-through" control sample and
        //   runs 3 s. Install closes admission and would discard all ordinary
        //   traffic inside the control window. So the control sample completes
        //   first, then Install.
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
        // Native physical descriptors remain unchanged during preparation.
        // Stop and verify the actual NIC before switching to an IOVA-only
        // table; no physical bootstrap mapping is needed while DMA is off.
        if (fR31Session && !r34RxStopBeforeDte()) {
            firstFailStage = "14b-abort-native-nic-stop";
            firstFailReason = "native NIC did not stop before the DTE flip";
            goto recover;
        }
        setProperty("m2-3e-enter", "stopped-before-dte");

        dte[tgt * 4 + 0] = dteRoot;
        dte[tgt * 4 + 1] = ctx.domid;   // data[1]'s low 16 bits = domain id
        dte[tgt * 4 + 2] = 0;
        dte[tgt * 4 + 3] = 0;
        setHexProperty(this, "m2-b2-dte-after", dte[tgt * 4 + 0]);
        setHexProperty(this, "m2-b2-dte-domid", dte[tgt * 4 + 1]);
        setProperty("m2-b2-dte", "switched-to-translation");
        OSSynchronizeIO();
        // [Round 9] The moment the DTE write completed. This is only "it was
        // written down", not "translation is in effect": the invalidation
        // commands have not been submitted, and the TLB may still hold old
        // entries. The real activation point is recorded as tInvComplete after
        // both invalidation commands in step 15 receive their completions.
        fM22b2Dma.tDteWritten = m2b2NowNS();
        setHexProperty(this, "m2-b2-dma-t-dte-written",
                       fM22b2Dma.tDteWritten);
    }

    // ---- Step 15: invalidation commands (all parameters from ctx) ----
    //
    // Order follows Linux's attach_device: INV_DEV_ENTRY first, then the TLB
    // flush. INV_IOMMU_PAGES takes its domain from ctx.domid -- exactly where
    // the old code was defective.
    {
        const UInt64 invAddr = m2b2InvAddress();
        setHexProperty(this, "m2-b2-inv-addr", invAddr);

        // (a) INV_DEV_ENTRY: data[0] = devid, type in data[1] bit28
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

        // (b) INV_IOMMU_PAGES: the whole address space, domain from ctx
        //     data[1]'s low 16 bits = domid; the PDE bit invalidates PDEs too
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

        // [Round 9] Translation becomes **effective** here, not at the DTE
        // write.
        //
        //   Round 8 recorded tTranslateOn right after the dte[] writes. But the
        //   invalidation commands had not been submitted yet, and the IOMMU's
        //   TLB might still hold pass-through entries; "the DTE was written"
        //   and "translation is effective" are two different things, and
        //   merging them into one moment leaves "the window lies within the
        //   translation-active interval" without its needed premise.
        //
        //   Only after both commands have received their completions is this
        //   moment recorded as the activation point.
        fR15InvTicks = mach_absolute_time();
        fM22b2Dma.tInvComplete = m2b2NowNS();
        fM22b2Dma.tTranslateOn = fM22b2Dma.tInvComplete;
        setHexProperty(this, "m2-b2-dma-t-inv-complete",
                       fM22b2Dma.tInvComplete);
        setHexProperty(this, "m2-b2-dma-t-translate-on",
                       fM22b2Dma.tTranslateOn);
    }

    // ---- Step 15b: device DMA observation (v0.21.7) ----
    //
    // [Why here, neither earlier nor later]
    //
    //   Earlier does not work: the DTE has just switched to translation and the
    //   invalidations just completed; the device may still be re-fetching
    //   descriptors, so ring state is not steady.
    //
    //   Later does not work: the TX completion count must be read once
    //   **before** the main window and once after, and their difference proves
    //   "the device really completed transfers during this span". That is
    //   exactly the evidence round 5 lacked: its netstat deltas were
    //   second-grained, unable to place a packet inside the window or exclude
    //   statistics publication delay.
    //
    //   This step is read-only: no device register is written, the DMA path is
    //   not altered.
    if (!fR31Session) {
        observeDeviceDma();
        setProperty("m2-b2-dma-obs-before-window",
                    fM22b2Dma.ran ? "yes" : "no");
    }

    // ---- Step 15c: bind this driver instance (must precede the window) ----
    //
    // [Why here]
    //   The driver observation log's epoch identifies the "driver instance".
    //   For "this snapshot belongs to this instance" to be a verifiable fact,
    //   the binding value must be fixed **before** the evidence is read. Step
    //   16c (after the window) is where snapshots are read, so the binding
    //   point is here.
    //
    // [Why round 10 lacked this step]
    //   The reader wrote want.epoch = 0, and 0 means "don't check". The whole
    //   protection never took effect: after a driver reload, a new instance of
    //   the same card was accepted as the old one.
    if (!fR31Session) {
        m2b2BindDriverInstance();
        setHexProperty(this, "m2-b2-epoch-bound-at-window",
                       (UInt64)fM22b2Dma.epochBound);
        setHexProperty(this, "m2-b2-epoch-bound-before-window",
                       fM22b2Dma.tWinStart);
    }

    // ---- Step 15d: the RX posted-buffer set's **watermark** (must precede the window) ----
    //
    // [Why read once here, and only the watermark]
    //   This round must prove "every RX buffer the device may write within the
    //   window is mapped". The set has two halves: the baseline slot table from
    //   before the window, and every re-post record between the baseline and
    //   window end. Deciding "which re-posts belong to this window" requires
    //   recording the driver's re-post counter **before the window opens** --
    //   anything with a later sequence number was produced by the window (and
    //   its immediately adjacent capture interval).
    //
    // [Why both cannot be read together after the window]
    //   Then "re-posts that happened before the window" and "within the window"
    //   become indistinguishable: the baseline slot table reflects only the
    //   last capture, buffers it replaced appear in neither half, the set
    //   silently shrinks -- and "everything covered" still holds. Exactly the
    //   failure shape this round eliminates.
    //
    //   This step reads properties only: no device register writes, no DMA path
    //   changes.
    if (!fR31Session) m2b2RxSetRead(true);
    // Replacements are impossible until both mapping and invalidation have
    // completed. Authorization accepts no new DMA addresses from the probe.
    setHexProperty(this, "m2-b2-r15-flood-token",
                   fM22b2Dma.declaredToken ^ 0x80000000u);
    setHexProperty(this, "m2-b2-r15-flood-req-first", 10001);
    setHexProperty(this, "m2-b2-r15-flood-req-last", 11200);
    // ---- Step 15e: open admission (round22 ordering fix) ----
    //
    // [Order] Step 14b already closed admission, waited for submitters to exit,
    // and drained the old mapping; step 14 switched the DTE; step 15 saw both
    // invalidation commands complete. Only at this moment is "the device
    // translates through this table" an established fact, and only now may
    // admission reopen:
    //
    //   * Ordinary packet PAs will be resolved via the new table (it only
    //     guarantees identity on [0,16GiB); r17TxCover tops up out-of-window
    //     blocks before OWN is written);
    //   * The controlled packets' 64 GiB IOVAs are meaningful only once the new
    //     table is in effect.
    //
    // [Why not "just add a gate check" before step 14]
    //   Round 21 did exactly that: Install closed a flag, then ring occupancy
    //   was read. But an output thread that had passed the flag check and not
    //   yet written OWN was in no counter; the drain treated it as finished, so
    //   the DTE switch raced its OWN write. Admission is now one atomic word
    //   (closed bit + reference count): a thread is counted at the same instant
    //   it is admitted, leaves only after writing OWN, and the drain waits on
    //   that count.
    // Round22: hand the domain the CURRENT command-ring cursors. Install copied
    // them before the two invalidations above were submitted, so without this
    // the first controlled map would append at a consumed slot and its
    // CompletionWait would never be signalled.
    r17SyncCommand(&ctx);
    // Round32: exercise ordinary variable-size mappings while TX admission is
    // still closed. Probe mappings remain in the cumulative domain accounting.
    if (fR31Session && !r32CapacityProbe()) {
        firstFailStage = "15e-abort-dynamic-capacity";
        firstFailReason = "normal dynamic IOVA capacity probe failed";
        goto recover;
    }
    if (!fR31Session && !r17EnterComplete(fM22b2Dma.tTranslateOn)) {
        firstFailStage = "15e-abort-enter-resume";
        firstFailReason = "admission refused to reopen after the DTE flip";
        goto recover;
    }
    // Native Install maps the fixed objects and RX while the NIC is stopped.
    // Authorize captures the initial IOVA table, then restarts with fixed IOVA
    // bases and confirms link/DMA recovery. Packet TX remains closed here.
    if (!r27RxBegin()) {
        firstFailStage = "15e-abort-rx-standard-map";
        firstFailReason = "standard RX mappings or ring binding failed";
        goto recover;
    }
    if (!m2b2R15Authorize()) {
        firstFailStage = "15e-abort-rx-authorize";
        firstFailReason = "RX domain rejected authorization";
        goto recover;
    }
    if (fR31Session) {
        // The entry reset rebuilt indices and the RX baseline. Sample these
        // actual rings after the fixed-address switch, using PA for CPU reads.
        observeDeviceDma();
        setProperty("m2-b2-dma-obs-before-window", fM22b2Dma.ran ? "yes" : "no");
        m2b2BindDriverInstance();
        setHexProperty(this, "m2-b2-epoch-bound-at-window", (UInt64)fM22b2Dma.epochBound);
        setHexProperty(this, "m2-b2-epoch-bound-before-window", fM22b2Dma.tWinStart);
        m2b2RxSetRead(true);
        if (!r17EnterComplete(fM22b2Dma.tTranslateOn)) {
            firstFailStage = "15e-abort-enter-resume";
            firstFailReason = "admission refused after fixed DMA and RX entry";
            goto recover;
        }
    }
    r27RxReady();

    // ---- Step 16: steady-state observation window (the only functional
    //      criterion window) ----
    //
    // Consume the event ring strictly per the spec: advance only HEAD, never
    // write TAIL, never clear the buffer. Window validity is decided by
    // Begin/End; invalid means "cannot judge", not 0 events.
    //
    // [Round 9] Before the window, the BAR2 mapping needed by the post-sample
    // is prepared and the sampling function handed to m2b2EndEventWindow(), so
    // sampling happens **inside** the window rather than after it returns. If
    // the mapping fails, postSampleDone stays false and the boundary verdict
    // later reports "no post-sample" honestly, not padded with a wider
    // interval.
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

    if (!m2b2BeginEventWindow(base, &winMain)) {
        firstFailStage = "16-abort-event-window";
        firstFailReason = winMain.invalidReason;
        goto recover;
    }
    saveDomain();
    if (fR31Session) {
        // R33 DOMAIN HANDOFF: resources and the existing driver/pool reference
        // now belong to the service. Returning must not Disarm the RX pool.
        contextScope.owned = nullptr;
        r15Scope.transferred = true;
        __atomic_store_n(&fR33Domain, domain, __ATOMIC_RELEASE);
        setHexProperty(this, "m2-3n-root-pa", domain->rootPA);
        setHexProperty(this, "m2-3n-dt-pa", domain->tblPA);
        setHexProperty(this, "m2-3n-command-pa", domain->cmdPA);
        setHexProperty(this, "m2-3n-install-count", ++fR33InstallCount);
        setHexProperty(this, "m2-3l-session-start", mach_absolute_time());
        setProperty("m2-3l-session-state", "active");
        setProperty("m2-3n-domain-state", "active");
        return;
    }
    IOSleep(M2B2_MAIN_MEAS_SECS * 1000);
    finishM22b2PageTableProbe(domain, true);
    return;

recover:
    saveDomain();
    finishM22b2PageTableProbe(domain, false);
}

void org_maz1_AMDMapperProbe::finishM22b2PageTableProbe(
    R33DeviceDomain *domain, bool finishWindow) {
    auto &winPre = fM22b2WinPre;
    auto &winMain = fM22b2WinMain;
    auto &ptMem = domain->ptMem;
    auto &tbl = domain->tbl;
    auto &cmdBufMd = domain->cmdBufMd;
    auto &semMd = domain->semMd;
    auto &evtMd = domain->evtMd;
    auto &md = domain->md;
    auto &map = domain->map;
    auto &postMap = domain->postMap;
    auto &base = domain->base;
    auto &pt = domain->pt;
    auto &dte = domain->dte;
    auto &root = domain->root;
    auto &evtBuf = domain->evtBuf;
    auto &ptPA = domain->ptPA;
    auto &tblPA = domain->tblPA;
    auto &cmdPA = domain->cmdPA;
    auto &semPA = domain->semPA;
    auto &evtPA = domain->evtPA;
    auto &ptBytes = domain->ptBytes;
    auto &rootPA = domain->rootPA;
    auto &l2PA = domain->l2PA;
    auto &origDT = domain->origDT;
    auto &origCmd = domain->origCmd;
    auto &origEvt = domain->origEvt;
    auto &origCtrl = domain->origCtrl;
    auto &ptPageCount = domain->ptPageCount;
    auto &tgt = domain->tgt;
    auto &tailAfterRaw = domain->tailAfterRaw;
    auto &cloAfterRaw = domain->cloAfterRaw;
    auto &preWindowRan = domain->preWindowRan;
    auto &mainWindowRan = domain->mainWindowRan;
    auto &hwStopped = domain->hwStopped;
    auto &cmdBufStopped = domain->cmdBufStopped;
    auto &evtLogStopped = domain->evtLogStopped;
    auto &regsRestored = domain->regsRestored;
    auto &safeToFree = domain->safeToFree;
    auto &evtResetOk = domain->evtResetOk;
    auto &invAllOk = domain->invAllOk;
    auto &invDevOk = domain->invDevOk;
    auto &invPagesOk = domain->invPagesOk;
    auto &controlDone = domain->controlDone;
    auto &tailAfterOk = domain->tailAfterOk;
    auto &cloAfterOk = domain->cloAfterOk;
    auto &postSampleDone = domain->postSampleDone;
    auto &firstFailStage = domain->firstFailStage;
    auto &firstFailReason = domain->firstFailReason;
    auto &ctx = domain->ctx;
    auto &postSample = domain->postSample;

    if (!finishWindow) goto recover;
    m2b2EndEventWindow(base, evtBuf, tgt, &winMain,
                      postSampleDone ? m2b2DoPostSample : nullptr,
                      postSampleDone ? &postSample : nullptr);
    if (fR31Session) {
        setHexProperty(this, "m2-3l-stop-request-time",
            __atomic_load_n(&fR31StopRequestTime, __ATOMIC_ACQUIRE));
        setProperty("m2-3l-session-state", "stop-requested");
    }
    mainWindowRan = true;
    setProperty("m2-b2-main-window-ran", "yes");
    fM22b2Dma.tWinStart = winMain.tStart;
    fM22b2Dma.tWinEnd = winMain.tEnd;
    if (postMap) {
        postMap->release();
        postMap = nullptr;
        postSample.bar = nullptr;
        postSample.haveBar = false;
    }

    // ---- Step 16b: the in-window post-sample has already run; only results
    //      are handled here ----
    //
    // [Round 9 reordering: sampling moved inside the window]
    //
    //   Round 8's approach read the two registers after the window returned:
    //   [tCloBefore, tCloAfter] ⊇ [tWinStart, tWinEnd], a 3.00785 s span
    //   wrapping the 3.00018 s window. That direction proves only "completions
    //   happened before or after the window end", not "within the zero-event
    //   window".
    //
    //   The post-sample is performed by m2b2EndEventWindow() calling
    //   m2b2DoPostSample() before recording tEnd, so
    //
    //       tWinStart <= tCloAfter <= tTailAfter <= tWinEnd
    //
    //   The sampling itself falls inside the window. No device register is read
    //   after the window closes.
    //
    //   Residual measurement error remains, but its **direction** changed: the
    //   close and tail pointers are tens of nanoseconds apart, both far earlier
    //   than tWinEnd, so completions in the last sliver of the window are not
    //   counted -- an undercount, not an overcount. Conservative in direction:
    //   it cannot read "the device is still working" as "the device stopped".
    //
    //   No claim of "error at most one descriptor": there is no throughput
    //   upper bound to justify it. Both sampling moments are published; anyone
    //   can judge the magnitude from them.
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

    // --- Segment 1's result handling (pure computation; no hardware, no scan) ---
    if (cloAfterOk) {
        fM22b2Dma.cloPtrAfter = cloAfterRaw;
        fM22b2Dma.haveCloDelta = true;

        // Masked delta, not ring modulo.
        const UInt32 delta = amdobs::cloPtrDelta(
            fM22b2Dma.cloPtrBefore, cloAfterRaw, fM22b2Dma.cloPtrMask);
        const bool plausible = amdobs::cloPtrDeltaPlausible(
            delta, fM22b2Dma.cloPtrMask);

        setHexProperty(this, "m2-b2-dma-cloptr-after", (UInt64)cloAfterRaw);
        setHexProperty(this, "m2-b2-dma-cloptr-delta", (UInt64)delta);
        // The "ring modulo" result is also given, making the difference between
        // the two interpretations visible.
        setHexProperty(this, "m2-b2-dma-cloptr-delta-ringmod",
                       (UInt64)amdobs::cloPtrRingIndex(delta, 1024));

        if (!plausible) {
            // Delta too large to explain: more like a counter reset or a device
            // swap than "the device completed half a counter space of
            // descriptors".
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

    // --- Segment 2: window scan (boundaries are now fixed and no longer
    //      affect boundary values) ---
    //
    // [Why here and not between the two boundary samples]
    //   Scanning 1024 descriptors and publishing dozens of properties takes
    //   time. Placing it between the two boundary samples would stretch the
    //   "completion progress" interval wider than the main window -- round 7
    //   did exactly that: the samples were 3.00694 s apart with the entire scan
    //   sandwiched between.
    if (fM22b2Dma.ran && fM22b2Dma.haveTxRing && tailAfterOk) {
        const UInt64 bytes = 1024ULL * amdobs::TX_DESC_STRIDE;
        const char *why = nullptr;
        UInt64 ringReadPA = fM22b2Dma.txRingBase;
        if ((!fR31Session || r40FixedReadPA(r40fixed::kTxRing,
                 fM22b2Dma.txRingBase, bytes, &ringReadPA)) &&
            amdobs::plausibleRingBase(ringReadPA, bytes,
                                      M2B2_IDENTITY_LIMIT, &why) &&
            amdobs::readVerdictDeviceReported(ringReadPA, bytes,
                                fM22b2Policy) == amdobs::RD_OK) {
            IOMemoryDescriptor *winMd = IOMemoryDescriptor::withPhysicalAddress(
                ringReadPA, bytes, kIODirectionIn);
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

    // ---- Step 16c: read the driver-side observation log (added in round 9) ----
    //
    // [Why read after the window]
    //   The log records submits and completions as they **actually happen**;
    //   records inside the window are this window's evidence. The driver copies
    //   a suffix into the property every second, so what is read here is the
    //   latest publication, covering the seconds inside the window.
    //
    // [Why this replaces ring reading as the primary evidence]
    //   Ring reading sees only "bytes after the window": it cannot prove the
    //   generation nor recover TSO's true length. Each log record carries the
    //   driver's own cumulative index; submit and completion pair on the same
    //   number, with no inference about slot reuse involved.
    //
    //   Ring reading is still kept: it is the only observation independent of
    //   driver cooperation, and its envelope feeds fault classification. The
    //   two do not replace each other; the report keeps them separate.
    //
    // [Round 10] Take the target NIC's identity first, then read the snapshot.
    //   The order cannot be reversed: m2b2ReadDriverObs() uses this set to
    //   verify the snapshot header's vendor/device/BDF/MAC/ifUnit. Round 9 had
    //   no such step, so "the records belong to the target device" was never
    //   tested -- and that round's traffic in fact flowed through another NIC.
    //
    // [Round 11] The instance epoch's binding happened in step 15b (before the
    //   window), not here. That is deliberate: taking the epoch after the
    //   window lets the object under test define the test's standard. This
    //   reader only uses the already-fixed value.
    m2b2CaptureNicIdentity();
    m2b2ReadDriverObs();

    // ---- Step 16d: post-window DescOwn count (circumstantial only) ----
    //
    // DescOwn is not cleared by the hardware on this chip, so this delta is
    // constantly 0 (done == zeroaddr observed three rounds running). It is
    // kept here to make "DescOwn is not a completion signal" visible every
    // time, rather than becoming hearsay once deleted.
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

    // Final coverage value.
    //
    // [Round 7] A single snapshot supports only **positive** attribution:
    // "the fault address falls within the range the device is using" is
    // reliable. The converse -- "the fault address is not in the set" -- does
    // not imply "the device never used it"; it may have used it a second ago.
    //
    // [Round 8] One **single** coverage value no longer stands for all paths.
    //
    //   Round 7 assigned txWindowCovered's result straight into
    //   fM22b2Dma.coverage, and step 17 classified every fault with that one
    //   value. But TX whole-window coverage holds only for TX buffers: RX
    //   buffers go through mbuf_data_to_physical(), and the rings and
    //   statistics buffer go through IODMACommand -- one window scan sees
    //   none of those three paths.
    //
    //   fM22b2Dma.coverage is now **the weakest of the per-path records**, and
    //   classifyFault takes a separate allPathsCovered argument to decide
    //   whether a whole-device claim is permitted.
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

    // [Round 8] All boundary moments are published, so completion progress can
    // be checked item by item against an explicit window.
    setHexProperty(this, "m2-b2-dma-t-translate-on",
                   fM22b2Dma.tTranslateOn);
    setHexProperty(this, "m2-b2-dma-t-translate-off",
                   fM22b2Dma.tTranslateOff);
    // [Round 9] The DTE write and the invalidation completion are separated:
    // only the latter is the point where translation takes effect.
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
    // v0.20.0: truncation marker and pre-existing backlog (must be published
    // together with the analysis)
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

    // Per-type counts + raw events (for offline decoding; no longer totals only)
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

    // Dominant type (only the most frequent is reported, with its spec name)
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

    // ---- Step 17: check each IO_PAGE_FAULT address inside the window against
    //      the page table ----
    //
    // [Round 5 rewrite] Round 4's version here was also hand-written per-level
    // if/else, with the criterion "a leaf with PR=1 counts as present" -- it
    // **never checked whether the leaf's encoding was legal**. So a table
    // written with the illegal NextLevel=7 was reported here as
    // "walk-present = 8", i.e. "every address is mapped", while the hardware
    // faulted precisely because of that illegal encoding. That is exactly why
    // round 4 presented "the page table looks completely correct" and "the
    // hardware faults" as a contradiction: that "looks correct" was a product
    // of the same wrong assumption.
    //
    // Now amdpte::walkPageTable() is used, which distinguishes present /
    // absent / illegal. For this case (round 4's 8 samples, RZ=0 and PR=1),
    // the correct result is illegal.
    //
    // [Round 6 addition] Out-of-range addresses are walked too; they must not
    // be skipped for being "beyond coverage". Round 5's m2-b2-dump-count = 0
    // arose exactly that way: the only fault was above 16 GiB, so forensics
    // was skipped entirely and no low-level entry was ever read. The walk
    // itself is safe (it only reads our own allocated table memory), and the
    // verdict is written plainly as "absent at level N" -- the direct evidence
    // that "the current table does not cover it".
    {
        UInt32 evtInRange = 0, evtOutOfRange = 0;
        UInt32 evtWalkPresent = 0, evtWalkAbsent = 0, evtWalkIllegal = 0;
        UInt32 evtFlagRz = 0, evtFlagPe = 0, evtFlagPr = 0;
        UInt32 evtWrite = 0, evtRead = 0, evtInterrupt = 0;
        UInt64 evtMinAddr = 0, evtMaxAddr = 0, evtFirstAbsent = 0;
        UInt64 evtFirstIllegal = 0;
        // v0.21.7: check each fault's address against **the set of addresses
        // the device is actually using**
        UInt32 evtInLiveSet = 0, evtInDeadSet = 0;
        UInt32 evtInsideMapUnobserved = 0, evtUnknownOwnership = 0;
        // Round 7: "not observed this run" under snapshot coverage is its own
        // class, not conflated with "definitely not in the set".
        UInt32 evtObservedAbsent = 0;
        UInt64 evtFirstInLive = 0;
        setProperty("m2-b2-fault-map-basis", "actual-page-table-not-bootstrap-limit");

        // References directly the set observed in step 15b (a member, not the
        // stack).
        //
        // [Why not copy it here]
        //   AddrSet is 48*24+8 = 1160 bytes. Copying one onto the stack would
        //   push runM22b2PageTableProbe()'s frame past the __chkstk threshold
        //   (measured: 0x14D0 = 5328 bytes already triggers it), producing a
        //   weak reference to ____chkstk_darwin in the binary and an outright
        //   kmutil refusal of this kext. A const reference saves stack and
        //   guarantees classification uses the same snapshot.
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

            // The flags field is dword1's bit24:16 (spec table 57), **not** the
            // low 16 bits. The low 16 bits are DomainID/PASID. Round 4 read
            // them as flags, so every domain=0 entry displayed "flags=0x000",
            // hiding PR/RW along with them.
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

            // ---- Address attribution (round 7) ----
            //
            // The criterion is "is the device using this address", **not** "is
            // it above 16 GiB". Round 5 treated the latter as the former and
            // labelled out-of-range faults as MMIO outright.
            //
            // Round 7 adds the coverage dimension: a single snapshot supports
            // only **positive** attribution. "The address is not in the
            // observed set" does not mean "the device never used it" -- it may
            // have used it a second ago. Only whole-window coverage (COV_WINDOW)
            // permits a stronger negative.
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
        // v0.21.7 attribution statistics
        setHexProperty(this, "m2-b2-fault-in-live-set", evtInLiveSet);
        setHexProperty(this, "m2-b2-fault-in-dead-set", evtInDeadSet);
        setHexProperty(this, "m2-b2-fault-inside-map-unobserved",
                       evtInsideMapUnobserved);
        setHexProperty(this, "m2-b2-fault-ownership-unknown",
                       evtUnknownOwnership);
        // Round 7: "not observed this run" listed separately.
        setHexProperty(this, "m2-b2-fault-observed-absent",
                       evtObservedAbsent);
        setProperty("m2-b2-fault-coverage",
                    amdobs::coverageName(fM22b2Dma.coverage));
        // [Round 8] A negative conclusion's scope must match the coverage.
        //
        //   Round 7 tested only coverage == COV_WINDOW here. But coverage was
        //   then computed from TX's whole-window coverage yet applied to the
        //   whole device. Now:
        //     - fault-negative-sound = every path has whole-window coverage
        //       (the only condition supporting a whole-device negative)
        //     - fault-negative-scope  = how far the negative actually extends
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

        // Fault flag statistics (decoded per spec table 57, not just a count of
        // type==2)
        setHexProperty(this, "m2-b2-flags-pr", evtFlagPr);
        setHexProperty(this, "m2-b2-flags-pe", evtFlagPe);
        setHexProperty(this, "m2-b2-flags-rz", evtFlagRz);
        setHexProperty(this, "m2-b2-flags-read", evtRead);
        setHexProperty(this, "m2-b2-flags-write", evtWrite);
        setHexProperty(this, "m2-b2-flags-interrupt", evtInterrupt);
    }

    // ---- Step 17b: export the **actual** page table paths (round 7 rewrite) ----
    //
    // [Why each level must really be read, not inferred]
    //   Round 6 exported root[0..15], saw root[1..15] all zero, and wrote
    //   "therefore L3[16] does not exist at all". That sentence sounds like an
    //   observation but is an inference: it assumes a correspondence between
    //   root entries and lower tables and **never reads that entry**. If the
    //   root index were miscalculated, or root[0]'s L3 page base were wrong,
    //   the conclusion would be completely different while the output looked
    //   identical.
    //
    //   This round truly reads level by level for each address and exports, per
    //   level:
    //     - the table's physical address tablePA
    //     - the table level (spec numbering, 1-based)
    //     - the index (which 9 bits of the address that level uses)
    //     - the raw PTE
    //     - the decode verdict
    //   "absent at level 3, index 16" is then a **read** result that anyone can
    //   re-verify with the same table bytes.
    //
    // [Normal paths exported too]
    //   Exporting only failure paths cannot prove the walker itself is right:
    //   a buggy walker would report everything absent, and the output would
    //   still "look reasonable". So several DMA addresses the device actually
    //   uses are also walked; they must hit leaves and translate back to
    //   themselves (identity mapping). One set of present + one set of absent
    //   is the complete evidence.
    {
        setHexProperty(this, "m2-b2-dump-root-pa", rootPA);
        setHexProperty(this, "m2-b2-dump-l2-pa", l2PA);
        setHexProperty(this, "m2-b2-dump-page-mode", (UInt64)ctx.pageMode);
        setHexProperty(this, "m2-b2-dump-pt-pages", (UInt64)ptPageCount);
        const UInt64 dumpLimit = fR31Session ? 0 :
            (fM22b2Use4K ? M2B2_4K_MAP_LIMIT : M2B2_IDENTITY_LIMIT);
        setHexProperty(this, "m2-b2-dump-map-limit", dumpLimit);
        const unsigned dumpRootLevel =
            fM22b2Use3L ? amdpte::LEVEL_1G : amdpte::LEVEL_512G;
        setHexProperty(this, "m2-b2-dump-root-level",
                       (UInt64)dumpRootLevel);
        setProperty("m2-b2-dump-leaf-encoding",
                    (fR31Session || fM22b2Use4K) ? "NextLevel0-4KiB-default"
                                               : "NextLevel0-2MiB-default");

        // The root table's contents are still exported (making root[0]'s
        // encoding checkable), but it is **no longer** used to infer lower
        // content. Inference and observation must stay separate.
        for (UInt32 i = 0; i < 16; i++) {
            char k[48];
            snprintf(k, sizeof(k), "m2-b2-dump-root%u", i);
            setHexProperty(this, k, root[i]);
        }

        // Forensic coverage: which part of this memory we actually read.
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

        // Walks one address level by level and exports every intermediate fact.
        //
        // Returning true means it reached a leaf and translated back to itself
        // (identity mapping holds). `tag` distinguishes fault paths from normal
        // DMA paths.
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
                // Table physical address: proves which table we read
                snprintf(k, sizeof(k), "m2-b2-%s%u-pte%u-table",
                         tag, idx, j);
                setHexProperty(this, k, tbls[j]);
                // Table level: a necessary decode input; the decoder must not
                // guess it itself
                snprintf(k, sizeof(k), "m2-b2-%s%u-pte%u-level",
                         tag, idx, j);
                setHexProperty(this, k, lvls[j]);
                // Index: which 9 bits of the address this level used
                snprintf(k, sizeof(k), "m2-b2-%s%u-pte%u-index",
                         tag, idx, j);
                setHexProperty(this, k, idxs[j]);
                // Raw table entry
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

        // (a) The real path of each IO_PAGE_FAULT
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

        // (b) Several DMA addresses the device actually uses: normal paths must
        //     hit leaves
        //
        // This set is the evidence that "the walker itself is right". If a
        // walker bug reported every address absent, this set's ok would also be
        // no, exposing the problem.
        {
            UInt64 dmaAddrs[8];
            const char *dmaTags[8];
            UInt32 nDma = 0;
            // [Round 8] Prefer the address of the descriptor that **actually
            // completed within the window**. That is the chain this round
            // demands: submit -> address -> page table -> completion. Walking
            // only the ring base and "the first descriptor" cannot tie it to a
            // specific completion.
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
            // Whether the address that completed within the window also walked
            // to an identity leaf. This is the last link of the
            // "submit -- address -- page table -- completion" chain.
            setProperty("m2-b2-dma-win-walk",
                        fM22b2Dma.haveFirstCompleted
                            ? (winGood ? "identity-mapped" : "NOT-MAPPED")
                            : "no-window-completion-observed");
            // The fraction of in-use device addresses that identity-translate.
            // This is the direct evidence of "is the table right", not merely
            // "was the fault address covered".
            setProperty("m2-b2-dma-walk-verdict",
                        (nDma == 0) ? "no-addresses-observed"
                                    : (good == nDma ? "all-identity-mapped"
                                                    : "SOME-NOT-MAPPED"));
        }

        setHexProperty(this, "m2-b2-walk-total", (UInt64)we.walked);
        setHexProperty(this, "m2-b2-walk-present", (UInt64)we.present);
    }

    // ---- Step 17c: walk the real page table for every TX/RX segment of every
    //      controlled request ----
    //
    // [Why before recovery]
    //   The walk reads the page table memory built for this experiment. The
    //   recovery flow frees it once hardware shutdown is confirmed; walking
    //   afterwards is use-after-free. As in step 17b, we are still within the
    //   span where the DTE points at the translation table.
    //
    // [Why pt / ptPA / ptBytes are passed]
    //   They are locals of this function whose scope exactly covers this
    //   memory's lifetime. Promoting them to members would let them outlive
    //   the free -- precisely the shape to avoid.
    m2b2WalkBusinessRanges(dte, tgt, pt, (UInt64)ptPA, ptBytes);

    // ---- Step 17d: the RX posted-buffer set's read-in, construction and walk ----
    //
    // [Order]
    //   1. Read the post-window rtl812x-rxpost (baseline + re-post records +
    //      raw bytes);
    //   2. Use the watermark recorded in step 15d to assemble the set S;
    //   3. Walk every range of S, with criteria identical to the business
    //      ranges (RX requires IW).
    //
    // [Why still before recovery]
    //   Same reason as step 17c: the walk reads this experiment's page table
    //   memory, which recovery frees afterwards. Passing pt / ptPA / ptBytes
    //   instead of promoting them to members has the same reason -- members
    //   would outlive the free.
    //
    // [Failures are not hidden]
    //   Missing publication, an incomplete set, and a range walk failure each
    //   have their own stable token (m2-b2-rxset-why / -set-why / -walk), and
    //   all are recorded as "unproven", never as "zero failures".
    if (m2b2RxSetRead(false)) {
        m2b2WalkRxSet(dte, tgt, pt, (UInt64)ptPA, ptBytes);
    }
    m2b2PublishRxSet();

recover:
    if (postMap) {
        postMap->release();
        postMap = nullptr;
        postSample.bar = nullptr;
        postSample.haveBar = false;
    }
    if (fR31Session) setProperty("m2-3l-session-state", "draining");
    const bool hadWindow = r17Installed();
    // Stop admission and drain every accepted TX while translation and the
    // command engine remain active. Native RX then stops the NIC itself;
    // the finite pool still needs TX open until its peer tail has finished.
    auto stopTxAtExit = [&]() -> bool {
        if (!hadWindow) return true;
        const bool stopped = r17StopSubmit(2000, "exit");
        r17SampleExit(r20tx::kStageExit);
        if (!stopped) {
            setProperty("m2-3b-cleanup", "PINNED-outstanding-no-DTE-restore");
            setProperty("m2-b2-verdict", "INVALID-TX-outstanding-pinned");
            setProperty("m2-b2-stage", "17e-pinned-outstanding");
            r17Export(&ctx);
        }
        return stopped;
    };
    if (fR31Session && !stopTxAtExit()) return;

    // Native RX confirms the hardware stop, unmaps every current slot and
    // restores its physical address without peer traffic. The same standard
    // unmaps and physical cover callbacks still finish under translation.
    const bool rxDrained = r27RxFinish(15000);
    if (!rxDrained) {
        // No DTE restoration, command stop, detach or table free.
        setProperty("m2-3b-cleanup", "PINNED-RX-no-DTE-restore");
        setProperty("m2-b2-verdict", "INVALID-RX-outstanding-or-unmap-pinned");
        setProperty("m2-b2-stage", "17e-pinned-RX");
        r17Export(&ctx);
        return;
    }
    if (!fR31Session) {
        if (!r29WaitTailDone(5000)) {
            setProperty("m2-3b-cleanup", "PINNED-tail-no-DTE-restore");
            setProperty("m2-b2-verdict", "INVALID-tail-not-confirmed");
            setProperty("m2-b2-stage", "17e-pinned-tail");
            r17Export(&ctx);
            return;
        }
        if (!stopTxAtExit()) return;
    }
    // ---- Step 18: recovery (a state machine; any failed step blocks freeing) ----
    //
    // The recovery stage's time boundaries are published too, so
    // "stop -- confirm -- restore" can be checked.
    fM22b2Dma.tRecoveryStart = m2b2NowNS();
    setHexProperty(this, "m2-b2-t-recovery-start", fM22b2Dma.tRecoveryStart);
    //
    // [Round 5 rewrite] Round 4 had two real problems here:
    //
    //  (a) `cmdBufStopped = true;` was a **direct assignment** with no hardware
    //      basis. The property said "yes", but that does not mean the hardware
    //      really stopped the command buffer. Spec 48882 §3.4.16: STATUS[4] =
    //      CmdBufRun, "1 = the IOMMU may fetch commands from the command
    //      buffer". It must be read, not assumed.
    //
    //  (b) In the stop stage, `c |= (origCtrl & M2B2_CTRL_CMDBUF_EN)` wrote
    //      **the original enable bit back**. That is, the "stop" step could
    //      re-enable the command buffer. The original state may be restored
    //      only once shutdown is confirmed, and only when restoring registers;
    //      it must not be restored early in the stop stage. The event log line
    //      had the same problem.
    //
    // The order now (per the spec's §2.4 / §2.5.1 restart flow and Linux's
    // iommu_disable() practice, init.c:470-495):
    //   1. Clear CMDBUF_EN / EVT_LOG_EN -- both "stop" bits to 0, **not**
    //      restoring the originals;
    //   2. Bounded wait for STATUS.CmdBufRun == 0 and STATUS.EventLogRun == 0;
    //   3. Clear IOMMU_EN and read back to confirm;
    //   4. Only after all three are confirmed may the base registers and the
    //      original enable state be restored;
    //   5. Memory may be freed only after every register reads back equal to
    //      its original value.
    //
    // Each step's actual CONTROL/STATUS read-backs, wait rounds and timeouts
    // are published as properties, so "did it stop" can be externally verified
    // instead of resting on a hard-coded yes.

    // 18.1 First clear both enable bits (without restoring originals)
    {
        UInt64 c = mmioRead64(base, M2B2_OFF_CONTROL);
        c &= ~M2B2_CTRL_CMDBUF_EN;
        c &= ~M2B2_CTRL_EVT_LOG_EN;
        mmioWrite64(base, M2B2_OFF_CONTROL, c);
        setHexProperty(this, "m2-b2-stop-control-write", c);
        setHexProperty(this, "m2-b2-stop-control-readback",
                       mmioRead64(base, M2B2_OFF_CONTROL));
    }

    // 18.1b Publish per-command records (command words / expected / observed / stage)
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

    // 18.2 Bounded wait for CmdBufRun to clear (spec STATUS[4])
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

    // 18.3 Bounded wait for EventLogRun to clear (spec STATUS[3])
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

    // 18.4 Only last is the IOMMU body stopped, with read-back confirmation
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

    // 18.5 Only after all three are confirmed stopped are the base registers
    //      and original enable state restored
    if (hwStopped && cmdBufStopped && evtLogStopped) {
        // Base registers are restored first; CONTROL as a whole is written back
        // to its original value last. The order cannot be reversed: restoring
        // CONTROL to "enabled" first would make the hardware immediately read
        // base registers still pointing into our buffers.
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
        // Record explicitly which item failed to stop, not a blanket failure
        const char *why = !hwStopped      ? "iommu-en-still-set"
                        : !cmdBufStopped  ? "cmdbuf-run-still-set"
                                          : "eventlog-run-still-set";
        setProperty("m2-b2-restore-abort-reason", why);
        safeToFree = false;
    }

    // ---- Step 18b: confirm translation has stopped, then tear down the
    //      backend (round22) ----
    //
    // [Order] Step 18 wrote the device table base and control registers back to
    // their originals and compared read-backs. Only when all four read back
    // equal are "translation stopped, original state restored" facts; only then
    // may Detach run (releasing callback/context/backend), and only after that
    // is ordinary output re-admitted.
    //
    // [Why Detach must come after recovery] Round 21's Detach ran before
    // recovery, and it also reopened admission: on a recovery failure,
    // translation still pointed at our table while ordinary packets were
    // already submitting without covers. Detach no longer touches admission
    // now; admission is opened only by kResume, which is called only after the
    // registers are read and recovery confirmed.
    if (regsRestored) {
        // This moment is translation-stop's actual time, not the recovery
        // stage's start.
        fM22b2Dma.tTranslateOff = m2b2NowNS();
        setHexProperty(this, "m2-b2-dma-t-translate-off", fM22b2Dma.tTranslateOff);
        setProperty("m2-3e-translate-off", "confirmed-by-register-readback");
        r17SetTranslateOff(fM22b2Dma.tTranslateOff);
        // Native RX has stopped DMA and restored the current physical ring.
        // Only after translation is restored may Lucy restart the NIC. Keep
        // its control context alive until real link/RX/TX recovery is confirmed.
        if (fR31Session && !r34RxResumePhysical()) {
            setProperty("m2-3b-cleanup", "PINNED-native-RX-resume-refused");
            setProperty("m2-b2-verdict", "INVALID-native-RX-resume-refused");
            setProperty("m2-b2-stage", "18b-pinned-native-RX-resume");
            r17Export(&ctx);
            return;
        }
    }
    if (hadWindow) {
        if (!regsRestored) {
            // Refuse to tear down the backend while the hardware may still
            // reference our tables: the callback, the table and the command
            // buffer all stay, admission stays closed (ordinary output halted),
            // and the situation is reported honestly.
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
        // Detach succeeded = controlled admission revoked, callback/context
        // cleared, translation stopped. Only now may ordinary output flow
        // again.
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
    // The finite pool stays copy-only. Native sessions resumed above through
    // their own control after register restoration.
    m2b2R15Finish();

    // ---- Step 19: verdict ----
    //
    // Four classes strictly distinguished: "not measured" is never written as
    // "pass", and "a counter changed" is never taken as causation:
    //   INVALID        any sampling/command/recovery condition failed -> no
    //                  conclusion this round
    //   CONTROL        the control branch's (pgtsleep) verdict, never
    //                  overwritten by the translation verdict
    //   INDETERMINATE  conditions hold but evidence of target-device activity
    //                  is missing -> cannot judge
    //   FAIL           a concrete failure observed under valid conditions
    //   PASS           only when every functional acceptance condition holds
    //                  simultaneously (not attainable this round)
    //
    // [v0.20.0 fix] The verdict no longer unconditionally reads winMain: it
    // first checks whether the main window actually ran. Not having run is "not
    // measured" -- neither PASS nor FAIL.
    {
        const bool cmdOk     = !ctx.failed;
        const bool winOk     = (mainWindowRan && winMain.valid);
        const bool restoreOk = safeToFree;

        const bool anyEvent    = winOk && (winMain.entries > 0);
        const bool allOurDevid = (winMain.devidMismatch == 0);

        const char *verdict;
        const char *stage;

        // [Round 7 fix: the control branch needs evidence of "completion", not
        // merely the "choice"]
        //
        // Round 6 treated `fM22b2SleepOnly` as the whole condition for the
        // control branch. That mistakes a **choice** for a **result**: with the
        // boot-arg pgtsleep, even if the event log reset failed, CMD_INV_ALL
        // timed out, or recovery never finished, the final verdict would be
        // rewritten to CONTROL -- real failures masked by the choice itself.
        //
        // The order now:
        //   1. Recovery failed -- highest priority; hardware state unknown, no
        //      conclusion is trustworthy
        //   2. Command failed -- invalidation commands unfinished, the
        //      translation window was never properly established
        //   3. A precondition gate failed -- event log reset / INV_ALL incomplete
        //   4. Control branch -- emitted only when controlDone (the control
        //      stage really finished)
        //   5. The translation branch's window/event verdict
        //
        // The control branch never switches the DTE, so "main window did not
        // run" is **normal** for it and must not be judged
        // INVALID-main-window-not-executed. Branch 4 precedes branch 5 for
        // exactly that reason.
        if (!restoreOk) {
            verdict = "INVALID-restore-incomplete";
            stage   = "19-invalid-restore";
        } else if (!cmdOk) {
            verdict = "INVALID-command-did-not-complete";
            stage   = "19-invalid-cmd";
        } else if (!evtResetOk || !invAllOk) {
            // A precondition gate failed: the control branch cannot emit
            // CONTROL either, because the hardware state the control stage
            // rests on was never established.
            verdict = "INVALID-precondition-not-established";
            stage   = "19-invalid-precondition";
        } else if (fM22b2SleepOnly) {
            if (!controlDone) {
                // Control mode was selected but the control stage never
                // finished. This is neither CONTROL nor the translation
                // experiment -- it simply did not complete.
                verdict = "INVALID-control-stage-did-not-complete";
                stage   = "19-invalid-control";
            } else {
                // Control experiment: no DTE switch, no translation window;
                // the conclusion is "control group completed".
                verdict = "CONTROL-sleep-only-no-dte-change";
                stage   = "19-control-preserved";
            }
        } else if (!mainWindowRan) {
            // The main window never ran at all: state plainly "not measured";
            // do not guess a conclusion.
            verdict = "INVALID-main-window-not-executed";
            stage   = "19-invalid-not-executed";
        } else if (!winOk) {
            verdict = "INVALID-event-window";
            stage   = "19-invalid-window";
        } else if (anyEvent && !allOurDevid) {
            verdict = "INDETERMINATE-events-from-other-devices";
            stage   = "19-indeterminate-devid";
        } else if (anyEvent && winMain.typeCount[M2B2_EVENT_IO_FAULT] > 0) {
            // IO_PAGE_FAULTs were indeed observed in a valid window: concrete
            // failure, evidence recorded
            verdict = "FAIL-io-page-faults-observed";
            stage   = "19-complete-faults";
        } else if (anyEvent) {
            // Events occurred but none were IO_PAGE_FAULT: types recorded
            // individually; qualify by type
            verdict = "FAIL-non-fault-events-observed";
            stage   = "19-complete-other-events";
        } else if (fM22b2Dma.cloDeltaValid && fM22b2Dma.cloDelta > 0) {
            // [Round 7] No events inside the window, **and** the hardware close
            // pointer advanced in an explainable way.
            //
            // A far stronger conclusion class than round 5:
            //   - the close pointer advancing => the device really handed
            //     descriptors back to the driver, i.e. DMA really completed,
            //     not merely "no errors reported";
            //   - zero events => all that DMA was translated successfully by
            //     the translation table.
            //
            // But cloDeltaValid is required: the masked delta must be
            // explainable (not a reset, not a device swap). Round 6 used ring
            // modulo, where 1000 -> 2024 yields 0, reading "completed 1024
            // descriptors" as "did nothing".
            //
            // [Round 8] Also required: the window scan really attributed these
            // completions to concrete descriptors.
            //
            // [Round 9] Three more tightenings, because round 8 still accepted
            // captures it should not have:
            //
            //   (a) The post-sample must fall **inside** the window. Round 8's
            //       samples wrapped the window (3.00785 s span over a 3.00018 s
            //       window); that direction cannot prove "completions happened
            //       within the zero-event window".
            //   (b) The scan must be exact: early stop, lost records,
            //       undecodable lengths, overwritten slots -- any one withdraws
            //       coverage eligibility.
            //   (c) There must be one complete pairing from **driver-side
            //       records** -- submit and completion matched on the same
            //       cumulative index, with a page table path for that address.
            //       Ring-read aggregate counters alone are not enough: they
            //       show only "the counter moved".
            //
            // Still not PASS: this is a single controlled experiment, not
            // sustained load and stability.
            // [Round 10] One more tightening: round 9's PASS-CANDIDATE required
            // only "one in-window pairing in the driver records", but that pair
            // could come from **another NIC's** traffic, and the snapshot
            // itself could predate the window end.
            //
            // Three **mutually independent** criteria must now hold
            // simultaneously:
            //
            //   obsHasCompletePair        at least one checkable submit/completion
            //   obsRecordsCoverWindow     the raw records fully cover
            //                             [winStart, winEnd]
            //   obsControlledBatchComplete every expected item of this finite
            //                             batch completed
            //
            // And ring reading must still independently attribute completions to
            // concrete descriptors (ring read and driver records are two
            // independent paths; only their mutual corroboration is not
            // self-testimony).
            //
            // When only "there is a pair" holds without coverage, the verdict
            // falls to INDETERMINATE-snapshot-does-not-cover-window -- exactly
            // round 9's actual state: it had the pair, but the snapshot was
            // 530957131 ns older than the window end.
            const bool windowOk2 =
                fM22b2Dma.boundaryInWindow && fM22b2Dma.winExact;
            const bool ringAttributed =
                fM22b2Dma.winCompletedInWindow > 0 &&
                fM22b2Dma.haveFirstCompleted;

            // ---- Round 12: wiring "evidence eligibility" into the final verdict ----
            //
            // Round 11 computed seven classes of evidence properties and
            // published each, but the final PASS-CANDIDATE consumed only three.
            // Shapes like these appeared:
            //
            //   * business-range walks failing across the board
            //     (bizWalkFail > 0) yet still PASS;
            //   * unknown device identity (nicIdentityKnown = false) admitted by
            //     `if (want.have && !idOk)`;
            //   * with the token undeclared (0), one was derived from the very
            //     records under test -- a circular criterion;
            //   * bizWalkFail was ++-ed in an early-exit branch and then
            //     overwritten by the local fail at the function's end.
            //
            // The verdict no longer hand-writes the conjunction but calls
            // amdobs::obsEvidenceGate(): the production path and the host
            // regression run **the same function**, and every counterexample is
            // falsified item by item in tests/dma-observe-test.cpp. Publishing
            // a property is not using it; this function is where "using" becomes
            // a structural fact.
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
            // Binding holds only when "the declared token is the one actually
            // used for joining". With token 0, joinToken may have been derived
            // from the records -- that is circular.
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
            // ---- Round 14: the RX posted-buffer set ----
            //
            // These items enter the same gate rather than standing as
            // "supplementary information beside it". Same reason round 12 wired
            // bizWalk into the criteria: **publishing a property is not using
            // it**. If the RX set were only printed and never part of the
            // verdict, "RX whole-window coverage" would again degrade into a
            // sentence in the report instead of a condition that can fail a
            // PASS.
            //
            // [The three failure causes must be distinguishable]
            //   The gate gives different tokens to "the ring wrapped", "records
            //   were lost", and "the set was budget-truncated", because their
            //   remedies are completely different. If all three were collapsed
            //   into `!rxSetComplete`, the report could only say "the set is
            //   incomplete", which is useless for locating the problem. They
            //   are therefore projections of **the single token the core
            //   provides** (rxsetSetWhy), not three independent judgements --
            //   one definition, three projections.
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
                // Boundaries or scan quality failed: not even "these
                // completions were within the window" may be said.
                verdict = "INDETERMINATE-boundary-or-scan-not-exact";
                stage   = "19-indeterminate-boundary";
            } else if (gateWhy != nullptr) {
                // Insufficient evidence eligibility. The reason comes from
                // obsEvidenceGate(), readable item by item, no longer
                // compressed into a blanket "did not pass".
                verdict = "INDETERMINATE-evidence-insufficient";
                stage   = "19-indeterminate-evidence";
            } else if (!fM22b2Dma.obsHasCompletePair) {
                // The close pointer moved, but the driver-side records contain
                // no checkable pairing.
                verdict = "INDETERMINATE-no-driver-record-pair";
                stage   = "19-indeterminate-no-obs-pair";
            } else if (!fM22b2Dma.obsRecordsCoverWindow) {
                // There is a pairing, but the snapshot does not cover the whole
                // window. This was round 9's real state, which round 9 judged a
                // pass.
                verdict = "INDETERMINATE-snapshot-does-not-cover-window";
                stage   = "19-indeterminate-obs-coverage";
            } else if (!fM22b2Dma.obsControlledBatchComplete) {
                // Coverage holds, but this finite batch did not complete in
                // full.
                verdict = "INDETERMINATE-controlled-batch-incomplete";
                stage   = "19-indeterminate-batch";
            } else {
                // Evidence is complete, but ring reading could not attribute the
                // completions to concrete descriptors.
                verdict = "INDETERMINATE-completions-not-attributed";
                stage   = "19-indeterminate-unattributed";
            }
        } else {
            // Valid window, no events, **and no completion evidence**. Nothing
            // can be said here: the device may not have worked at all, or it
            // worked but the statistics were not published.
            verdict = "INDETERMINATE-no-events-no-dma-evidence";
            stage   = "19-indeterminate-no-dma";
        }

        setProperty("m2-b2-verdict", verdict);
        setProperty("m2-b2-stage", stage);
        fM22b2Dma.tRecoveryEnd = m2b2NowNS();
        setHexProperty(this, "m2-b2-t-recovery-end", fM22b2Dma.tRecoveryEnd);

        // Every precondition gate's actual completion state, published item by
        // item for independent re-checking.
        setProperty("m2-b2-stage-evt-reset", evtResetOk ? "yes" : "no");
        setProperty("m2-b2-stage-inv-all", invAllOk ? "yes" : "no");
        setProperty("m2-b2-stage-inv-dev", invDevOk ? "yes" : "no");
        setProperty("m2-b2-stage-inv-pages", invPagesOk ? "yes" : "no");
        setProperty("m2-b2-stage-control-done", controlDone ? "yes" : "no");
        setProperty("m2-b2-mode",
                    fM22b2SleepOnly ? "control-sleep-only" : "translation");

        // The first failing stage is kept separately, never overwritten by the
        // generic status above.
        if (firstFailStage) {
            setProperty("m2-b2-first-fail-stage", firstFailStage);
            if (firstFailReason) {
                setProperty("m2-b2-first-fail-reason", firstFailReason);
            }
        } else {
            setProperty("m2-b2-first-fail-stage", "none");
        }

        // The final "did these two windows actually run" values. The properties
        // were written once at sampling; here they are rewritten from the
        // booleans the verdict actually used, guaranteeing record and verdict
        // agree exactly.
        setProperty("m2-b2-pre-window-ran", preWindowRan ? "yes" : "no");
        setProperty("m2-b2-main-window-ran", mainWindowRan ? "yes" : "no");
    }

    // ---- Step 20: resource disposition ----
    //
    // Freed only if safeToFree; otherwise the memory is kept valid and the
    // required follow-up disposition is recorded.
    if (safeToFree) {
        map->release();
        md->release();
        ptMem->release();
        tbl->release();
        cmdBufMd->release();
        semMd->release();
        evtMd->release();
        domain->resourcesReleased = true;
        setProperty("m2-b2-cleanup", "done");
        if (fR31Session) {
            fR31SessionCompleted = mainWindowRan && winMain.valid &&
                !firstFailStage && !ctx.failed &&
                __atomic_load_n(&fR31StopRequested, __ATOMIC_ACQUIRE);
        }
    } else {
        // Do not free: the hardware may still reference these addresses. Better
        // to leak than to let the IOMMU go on translating all system DMA through
        // reclaimed memory (this is exactly how boot deadlocked twice in a row
        // on 2026-10-30).
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
// [Round 12] Walking business ranges: the whole [addr, addr+len), every leaf,
// every level's raw PTEs
// ---------------------------------------------------------------------------
//
// Round 11's path had three false-pass shapes, all fixed this round:
//
//   1. Only the **first page's** path was exported while the whole range was
//      claimed covered. A 74-byte packet starting 16 bytes before a leaf's end
//      crosses into the next leaf, whose path was never exported; the analyser
//      held one leaf's raw PTEs yet saw "the whole range is covered".
//   2. The coverage loop fell back to a 4096-byte stride on decode failure,
//      potentially skipping whole gaps.
//   3. On `count >= kBizWalkMaxSegs` it returned directly -- no counting, no
//      downgrade -- making "only partly walked" and "all qualified"
//      indistinguishable in the output.
//
// The walk logic now lives in kext/amd_iommu_bizwalk_core.hpp, compiled by the
// probe and the host regression from **the same** code. This site only: fetch
// the DTE, bound readEntry, publish the results, and account separately for
// expected/count/ok/fail/capped.
void org_maz1_AMDMapperProbe::m2b2WalkBusinessRanges(
        const volatile UInt64 *dte, UInt32 tgt,
        const volatile UInt64 *ptv, UInt64 ptBase, UInt64 ptBytes) {
    // The four ledgers are independent. Round 11's bizWalkFail was ++-ed in an
    // early-exit branch and then overwritten by the local fail at the function's
    // end -- failures caused by early exits vanished from the output. Now every
    // failure path touches only these four members; there are no local counters
    // at the end any more.
    fM22b2Dma.bizWalkCount = 0;
    fM22b2Dma.bizWalkOk = 0;
    fM22b2Dma.bizWalkFail = 0;
    fM22b2Dma.bizWalkCapped = 0;

    // ---- Expected range count: derived from the **raw business records** ----
    //
    // This is the only source of "how many ranges should have been walked",
    // not "how many were actually walked". A mismatch means some ranges were
    // never walked, whereas round 11 only judged "whether the ones reached
    // passed".
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

    // ---- Starting point: the DTE **actually** written into the device table
    //      during this experiment ----
    //
    // Round 10's analyser had a criterion "the root table is the one the DTE
    // names":
    //
    //     pte_get('m2-b2-win0-pte0-table') == pte_get('m2-b2-dte-root')
    //         or pte_get('m2-b2-dte-root') is None
    //
    // But the m2-b2-dte-root property was **never published**, so the right
    // side was always true and the criterion checked nothing. Now the real
    // value is read back from dte[] and exported alongside, making "the root
    // table comes from the actual DTE" a checkable fact rather than a
    // declaration.
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
        // The DTE is not in a walkable state: **every** expected range is
        // recorded as unproven. Not "0 failures", but "N expected, 0 proven".
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

    // ---- The single entry point for reading page table memory ----
    //
    // Only this experiment's allocated page table block may be read;
    // out-of-range returns 0 (PR=0 for 0, decoded as absent, so no leaf can be
    // forged). Same bounds checks as step 17b.
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

    // ---- Per request, per direction, per segment ----
    const amdobs::ObsJoin &j = fM22b2ObsJoin;
    UInt32 count = 0;

    auto recordRange = [&](UInt32 reqId, UInt8 isRx, UInt8 segIdx,
                           UInt64 addr, UInt32 len) {
        // Capacity cap: **record a downgrade**, never a silent drop. Round 11
        // returned here, so the dropped ranges did not exist in the output.
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

        // The same core code: probe and host regression both run
        // amdbw::walkRange().
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

    // At this point count/ok/fail/capped hold their final values; there is
    // **no longer** any local fail that could overwrite the member counters.
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

    // ---- Publish per segment ----
    //
    // Every level of every leaf of every segment is published: table physical
    // address, index, level, raw PTE. This is the only re-checkable form of
    // "which real page table path this business DMA range took"; the analyser
    // decodes it independently and relies on no conclusion string here.
    //
    // The old property names (m2-b2-bw%d-pte%d-*) are kept as aliases of the
    // **first leaf**, so round 11's archives remain readable by the same
    // analyser; cross-leaf ranges additionally have m2-b2-bw%d-leaf%d-*.
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
        // Walk start: same source as the DTE, making "the root table comes from
        // the actual DTE" checkable
        snprintf(k, sizeof(k), "m2-b2-bw%u-root-pa", (unsigned)i);
        setHexProperty(this, k, w.rootPA);
        snprintf(k, sizeof(k), "m2-b2-bw%u-root-level", (unsigned)i);
        setHexProperty(this, k, (UInt64)w.rootLevel);
        snprintf(k, sizeof(k), "m2-b2-bw%u-dte", (unsigned)i);
        setHexProperty(this, k, w.dteRaw);

        // Leaf count: cross-leaf ranges must be exported leaf by leaf, or
        // "the whole range is covered" cannot be checked.
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

        // Old-name aliases (= the first leaf), covering only the first leaf's
        // levels.
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


