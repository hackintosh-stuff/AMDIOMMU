// AMDMapperProbeDebug.cpp -- the retired M2 experiment subsystem's entry
// points (start/stop/iovm*), preserved verbatim from AMDMapperProbe.cpp.
//
// The production build does NOT compile this file: AMDMapperProbe.cpp provides
// the auto/auto-attach-only versions of the same member functions, guarded by
// #if !AMD_MAPPER_PROBE_DEBUG. Build with tools/build-m1a-debug.sh to get the
// historical amdiommu=arm/mmio/write/table/enable/cmd/pgt* modes back.

#include "AMDMapperProbe.hpp"
#include "amd_iommu_device_policy.hpp"
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
#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSDictionary.h>

// The single implementation of page table encoding/decoding. Production code
// and the host regression tests **include the same file**, so the tests run
// exactly these branches rather than a separately written Python restatement.
// See tests/pte-core-test.cpp and docs/m2-2b-2-round5-result.md.
#include "amd_iommu_pte_core.hpp"

// The definition of OSPtr<T> depends on IOKIT_ENABLE_SHARED_PTR (SDK
// libkern/c++/OSPtr.h): defined = OSSharedPtr<T>; undefined = T*.
// The SDK default is undefined.
#if defined(IOKIT_ENABLE_SHARED_PTR)
    #define M1A_HAS_SHARED_PTR 1
#else
    #define M1A_HAS_SHARED_PTR 0
#endif

#include "AMDMapperProbeInternal.hpp"

#define super IOMapper

#if AMD_MAPPER_PROBE_DEBUG

// ===== AMDMapperProbe.cpp (original lines 7584..7713) =====
bool org_example_AMDMapperProbe::start(IOService *provider) {
    setProperty("probe-stage", "0-entered-start");

    // Safety gate: must happen before super::start().
    // When fIsSystem is true, IOMapper::start() sets gSystem = this -- a global
    // side effect that cannot be undone.
    fIsSystem = false;

    if (!super::start(provider)) {
        setProperty("probe-stage", "1-super-start-FAILED");
        return false;
    }
    setProperty("probe-stage", "2-super-start-ok");
    if (fOwner) {
        // This instance is attached to the controller service, not matched to
        // PCI. The owner prepares its domain before publishing iommu-parent.
        fAuto = true;
        setProperty("iommu-mode", "auto");
        setProperty("iommu-role", "device");
        setProperty("iommu-system-mapper", "no");
        return true;
    }

    char mode[32] = {};
    fAuto = PE_parse_boot_argn("amdiommu", mode, sizeof(mode) - 1)
            && (strcmp(mode, "auto") == 0 ||
                strcmp(mode, "auto-attach") == 0);
    // R69: "auto-attach" additionally publishes iommu-parent at first publish,
    // because Apple's own kexts only call IOMapper::copyMapperForDevice() and
    // can never invoke the AMDIOMMUClaimRequesterV1 handshake. Plain "auto"
    // keeps the R54..R67 claim protocol and its analysis exactly as validated.
    fAutoAttach = fAuto && strcmp(mode, "auto-attach") == 0;
    if (fAuto) {
        // Explicit clients claim at pre-open; this owner keeps their domains
        // across ordinary interface down/up.
        return StartAuto();
    }

    // ---- B2-b: first decide whether real devices are let through ----
    fArmed = parseArmBootArg();
    setProperty("m1bb-armed", fArmed ? "yes" : "no");

    // ---- B2-b: install the publish notification, attaching iommu-parent
    //      before Lucy probes ----
    //
    // This is the fix for the 0.6.0 race. Previously the property was set
    // directly in start(), with no ordering guarantee versus Lucy reading it,
    // causing success/failure/success across three reboots. Now
    // gIOFirstPublishNotification attaches the property at the instant the
    // device registers, which is always before any driver's probe/start.
    //
    // The fallback lookup in start() is kept: if the notification somehow
    // missed (e.g. the NIC published before the probe's start()), still try to
    // attach directly and mark "this may be too late" with
    // m1bb-nic-busy = yes-too-late.
    if (fArmed) {
        installPublishNotifier();

        // Fallback: if the device already exists (FirstPublish is not replayed
        // for already-published instances by the notification), look it up
        // directly once.
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

    // ---- B1: the real device obtains the mapper ----
    if (!findTarget()) {
        setProperty("probe-stage", "3-target-not-found");
    } else {
        setProperty("probe-stage", "3-target-found");
        runB1SelfTest();

        // ---- M2-0b: read-only PCI config space, get the IOMMU's own BAR ----
        //
        // Placed after B1 rather than before: runB1SelfTest() calls
        // copyMapperForDevice(), which allocates the record name for
        // fAllocName -- pre-existing B1 behaviour. M2-0b is fully independent
        // and read-only; ordering does not affect it, but placing it later lets
        // m1b-stage reflect B1's result first on failure.
        runM20ConfigProbe();
    }

    // ---- M2-1: read-only MMIO probing (boot-arg gated, not run by default) ----
    //
    // Placed last: it is this round's only code that actually touches MMIO.
    // Letting all pre-existing stages run first means that on failure
    // m1b-stage is already fully reflected and no regression is masked.
    runM21MmioProbe();

    // ---- M2-2a-1: minimal MMIO write test (boot-arg gated, not run by default) ----
    //
    // Placed last: this is the project's first hardware write.
    // All preceding read-only stages finish first, so any regression is seen
    // before it.
    runM22aWriteProbe();

    // ---- M2-2a-2: build the device table (boot-arg gated, not run by default) ----
    //
    // Build an all-pass-through device table and write it into the base
    // register, but **do not enable the IOMMU**. With the IOMMU off the
    // hardware never reads this table, so system behaviour must be completely
    // unchanged.
    runM22bTableProbe();

    // ---- M2-2a-3: short-window enable test (boot-arg gated, not run by default) ----
    //
    // The highest-risk step: once enabled, all system DMA goes through the
    // device table. But the window is extremely short -- enable, read status,
    // immediately disable. Placed last; all preceding stages run first.
    runM23EnableProbe();

    // ---- M2-2b-1: command channel verification (boot-arg gated, not run by default) ----
    //
    // M2-2a-3 only configured the command buffer, never actually issuing a
    // command. This step issues one CMD_COMPL_WAIT to verify the command
    // channel really works. Still a short window: enable -> issue one ->
    // poll -> immediately disable.
    runM2b1CmdProbe();

    // ---- M2-2b-2: 4-level identity page table + single-device DTE switch (boot-arg gated) ----
    //
    // [Cannot run directly here] The probe's start() runs before PCI
    // enumeration completes and before Lucy configures the NIC; at that point
    // the target device has no DMA yet, and "0 faults after switching" would
    // measure nothing. Instead a one-shot timer is scheduled to run later,
    // once the system is stable.
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

    // ---- B2-0: observe the call contract (window closed, behaviour same as 0.4.0) ----
    runB2SelfTest();

    // ---- B2-a: actually implement identity mapping ----
    runB2aSelfTest();

    publishB2bStats();

    if (IOMapper::gSystem) {
        setProperty("iomapper-gsystem", "NONNULL");
    } else {
        setProperty("iomapper-gsystem", "NULL-as-expected");
    }

    setProperty("probe-stage", "4-complete");
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

IOReturn org_example_AMDMapperProbe::callPlatformFunction(
    const OSSymbol *name, bool wait, void *target, void *operation,
    void *unused3, void *unused4) {
    if (name && name->isEqualTo(amd_iommu_policy::kClaim)) {
        if (!target || operation || unused3 || unused4) return kIOReturnBadArgument;
        return AttachAuto(static_cast<IOService *>(target), true)
            ? kIOReturnSuccess : kIOReturnNotReady;
    }
    if (name && name->isEqualTo("R63SetRequesterDMA")) {
        if (!fAuto || !fNicDevice) return kIOReturnNotReady;
        const uintptr_t op = (uintptr_t)operation;
        if (target != fNicDevice || unused3 || unused4 || (op != 1 && op != 2))
            return kIOReturnBadArgument;
        return SetRequesterDMA(op == 1);
    }
    if (name && name->isEqualTo("R47PowerTransition")) {
        if (!fAuto || !fNicDevice) return kIOReturnNotReady;
        const uintptr_t op = (uintptr_t)operation;
        if (target != fNicDevice || unused3 || unused4 || (op != 1 && op != 2))
            return kIOReturnBadArgument;
        return PowerTransition((UInt32)op);
    }
    return super::callPlatformFunction(name, wait, target, operation,
                                      unused3, unused4);
}

IOReturn org_example_AMDMapperProbe::setProperties(OSObject *properties) {
    OSDictionary *dict = OSDynamicCast(OSDictionary, properties);
    OSObject *pmArm = dict ? dict->getObject("R66ArmSystemPM") : nullptr;
    if (pmArm) {
        if (pmArm != kOSBooleanTrue && pmArm != kOSBooleanFalse)
            return kIOReturnBadArgument;
        return SetSystemPM(pmArm == kOSBooleanTrue);
    }
    OSObject *all = dict ? dict->getObject("R52Snapshot") : nullptr;
    if (fAuto && all) {
        if (all != kOSBooleanTrue) return kIOReturnBadArgument;
        if (fOwner) return kIOReturnUnsupported;
        PublishDomains();
        return kIOReturnSuccess;
    }
    OSObject *snapshot = dict ? dict->getObject("R44Snapshot") : nullptr;
    if (fAuto && snapshot) {
        if (snapshot != kOSBooleanTrue) return kIOReturnBadArgument;
        if (fOwner) PublishMappings();
        else PublishDomains();
        return kIOReturnSuccess;
    }
    OSObject *request = dict ? dict->getObject("R31Stop") : nullptr;
    if (!request) return super::setProperties(properties);
    if (request != kOSBooleanTrue) return kIOReturnBadArgument;
    if (!fR31Session) return kIOReturnNotReady;
    r31RequestStop();
    return kIOReturnSuccess;
}

void org_example_AMDMapperProbe::stop(IOService *provider) {
    if (fAuto) {
        if (fPublishNotifier) {
            fPublishNotifier->disable();
            fPublishNotifier->release();
            fPublishNotifier = nullptr;
        }
        if (!StopAuto()) return;
        if (fNicDevice) {
            if (fNicDevice->getProperty("iommu-parent") == this)
                fNicDevice->removeProperty("iommu-parent");
            fNicDevice->release();
            fNicDevice = nullptr;
        }
        super::stop(provider);
        return;
    }
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

    // Remove the notification first so callbacks are not delivered after stop
    // (at that point the object is being torn down)
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
// ------------------------------------------------------ IOMapper subclass interface implementation
//
// B2-a semantics: **only a physically contiguous single segment is supported**,
// and mapLength must be returned as exactly length.
//
// Why mapLength must be exactly length (the safety pivot of the whole
// implementation):
//   After IODMACommand::prepare() gets the return value it immediately checks
//       if (kIOReturnSuccess == ret && mapArgs.fAllocLength
//           && (mapArgs.fAllocLength != mapArgs.fLength))   -> multi-segment path
//   and the first line of the multi-segment path is
//       assert(mapArgs.fAllocLength > mapArgs.fLength);      // IODMACommand.cpp:946
//   An identity mapping can never produce a longer range than requested. So as
//   soon as we return anything != length, the kernel panics on the assert.
//   Returning exactly length skips the whole multi-segment path and
//   genIOVMSegments takes the fMapSegmentsCount==0 fast path:
//       state->fIOVMAddr = fLocalMapperAlloc + offset - fPreparedOffset
//   which is exactly the identity mapping.

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

    if (fAuto)
        return MapMemory(memory, descriptorOffset, length, mapOptions,
                            mapSpecification, dmaCommand, pageList,
                            mapAddress, mapLength);

    fMapCalls++;

    // Record the full arguments of the first call only, so properties do not
    // grow without bound.
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

    // ---- Triage: probe-initiated call vs real device ----
    //
    // The criterion is fProbeCallActive, **not** fMapWindowOpen.
    // The difference between the two is exactly the bug exposed by the first
    // 0.6.0 deployment:
    //   B2-0 is "probe-initiated, window closed" (deliberately keeping the old
    //   behaviour as a baseline); judged by the window it would be counted as
    //   a real device call, inflating m1bb-realmapcalls.
    // The first deployment indeed reported realmapcalls=1, first-len=0x10000
    // -- which was B2-0's 16 KiB buffer, not the NIC.
    bool isProbeCall = fProbeCallActive;

    // Fixed descriptor rings/tally own separate standard DMA command pairs.
    // Their reserved IOVAs do not consume TX packet or RX slot accounting.
    if (r40FixedCandidate(memory, dmaCommand))
        return r40FixedMap(memory, descriptorOffset, length, mapOptions,
                          mapSpecification, dmaCommand, pageList,
                          mapAddress, mapLength);

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
        // Real device call
        fRealMapCalls++;

        if (!fArmed) {
            // Not authorized: keep B2-a behaviour, reject and count.
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
            // A real device hits fragmentation: identity mapping cannot express
            // it, so the only option is to reject. This is exactly the case a
            // packet buffer hits when useAppleVTD is true, and the real problem
            // the M2 page tables exist to solve.
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
        *mapLength  = length;        // must also be exactly length

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

    // ---- Probe-initiated calls ----
    //
    // Success is returned only while the window is open (B2-a's two comparison
    // cases); B2-0's calls keep the old behaviour (kIOReturnUnsupported).
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
        // Fragmented: identity mapping cannot be described by a single scalar,
        // so the only option is to reject. This is not an implementation defect
        // but the limit of the iovmMapMemory interface's expressiveness.
        fMapRejectFragCalls++;
        if (fMapRejectFragCalls == 1) {
            setHexProperty(this, "m1b2a-firstfrag-segs", run.segCount);
            setHexProperty(this, "m1b2a-firstfrag-len", length);
        }
        publishMapStats(false);
        return kIOReturnUnsupported;
    }

    // Physically contiguous -> identity mapping: IOVA equals the physical address.
    *mapAddress = run.firstPA;
    *mapLength  = length;        // must be **exactly** length; see comment above

    // Self-test mappings are registered in the table too, so
    // mapToPhysicalAddress consults it uniformly.
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
    if (fAuto)
        return UnmapMemory(memory, dmaCommand, mapAddress, mapLength);
    (void)memory;

    fUnmapCalls++;

    if (r40FixedCandidate(memory, dmaCommand) || r40FixedOwnsAddress(mapAddress))
        return r40FixedUnmap(memory, dmaCommand, mapAddress, mapLength);

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

    // Decide whether this is a real device's unmap or a self-test one: during
    // self-test dmaCommand is the probe's, and by the time
    // IODMACommand::complete() calls unmap, fMapWindowOpen is already closed,
    // so the window cannot be used for the decision. Instead use "is this entry
    // in the table" -- both kinds of mapping are registered in the same table
    // and matched exactly by (pa,len).
    bool freed = freeMapEntry(mapAddress, mapLength);

    if (freed) {
        fUnmapOkCalls++;
    }

    // Real-device unmaps are counted separately: the criterion is that
    // dmaCommand is not the probe's expected command. Note fExpectedCmd has
    // been cleared after self-test ends, so a self-test unmap would also land
    // in this branch; to distinguish, fArmed is additionally required (only
    // true once the card is installed).
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
    if (fAuto) {
        setProperty("iommu-insert-rejects", (unsigned long long)fInsertCalls, 32);
        return kIOReturnUnsupported;
    }
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
    if (fAuto) {
        uint64_t pa = 0;
        return Translate(mappedAddress, &pa) ? pa : 0;
    }
    fPhysAddrCalls++;

    if (r40FixedOwnsAddress(mappedAddress)) {
        uint64_t pa = 0;
        return r40FixedTranslate(mappedAddress, &pa) ? pa : 0;
    }

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

    // Return identity results only for ranges **we actually mapped**.
    // Outside mapped ranges always return 0, meaning "I don't know", rather
    // than pretending the translation succeeded.
    //
    // This matters: on some paths IOMemoryDescriptor compares
    //     mapper->mapToPhysicalAddress(addr) against the real PA (see the
    //     panic check wrapped in #if 0 in xnu); if we returned arbitrary
    //     values for unmapped ranges, wrong addresses would be fed to drivers.
    //
    // From B2-b this becomes a table lookup: a real device holds several
    // mappings at once (Lucy has three descriptor rings), which a single
    // variable cannot express.
    for (int i = 0; i < kMaxActiveMaps; i++) {
        if (!fMaps[i].used) continue;
        if (mappedAddress >= fMaps[i].pa
            && mappedAddress < (fMaps[i].pa + fMaps[i].len)) {
            return mappedAddress;   // identity: IOVA == PA
        }
    }
    return 0;
}

#endif /* AMD_MAPPER_PROBE_DEBUG */
