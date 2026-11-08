// AMDMapperProbe.cpp -- entry point, IOMapper contract, kmod glue
//
// Part of the AMDMapperProbe kext. Split out of the original
// single-file AMDMapperProbe.cpp by tools/dev/split-probe.py; the
// function bodies are unchanged and in their original order.

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
OSDefineMetaClassAndStructors(org_maz1_AMDMapperProbe, IOMapper);

// ===== AMDMapperProbe.cpp (original lines 76..142) =====
bool org_maz1_AMDMapperProbe::initHardware(IOService *provider) {
    (void)provider;
    fTarget = nullptr;
    fNicDevice = nullptr;
    fAuto = false;
    fController = nullptr;
    fMapper = nullptr;
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

    // ---- M2-2b-2 deferred timer ----
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

    // ---- Crash safety: zero out fAllocName ----
    //
    // Why this is required (a new risk introduced only in B2-a):
    //   B2-a is the first version that lets iovmMapMemory **return success**.
    //   Once it succeeds, IOMemoryDescriptor::dmaMapRecord() executes
    //       if ((alloc = mapper->fAllocName)) kern_allocation_update_size(alloc, ...);
    //   i.e. it dereferences fAllocName. In 0.4.0 and earlier every mapping
    //   failed, that line never executed, and the hazard never surfaced.
    //
    //   fAllocName only exists in the XNU_KERNEL_PRIVATE view (IOMapper.h:75);
    //   third-party kexts cannot see that name, but in the SDK view it lands
    //   in __reserved[6] (offset 48..56). tools/dev/layout-check.cpp has verified
    //   this aliasing mechanically with offsetof (48 == 48).
    //
    //   On the normal path fAllocName is allocated by
    //   IOMapper::copyMapperForDeviceWithIndex() before it returns the mapper
    //   (IOMapper.cpp:211-223), and B1's runB1SelfTest() happens to call it.
    //   But it only allocates when fAllocName is **NULL**; if it holds
    //   uninitialized garbage here, it is dereferenced as a valid-looking
    //   pointer -> panic.
    //
    //   So: zero it first -> copyMapperForDevice sees NULL -> allocates
    //   correctly. If B1 never ran (findTarget failed), fAllocName stays NULL
    //   and dmaMapRecord's if is false -- equally safe. Both paths are safe.
    //
    // Why this cannot corrupt fPageSize:
    //   __reserved[6] occupies [48,56) and fPageSize sits at [60,64); they do
    //   not overlap (layout-check asserts 56 <= 60). Also fPageSize is written
    //   by IOMapper::start() only **after** initHardware(), so in time it can
    //   never be overwritten here either.
    __reserved[6] = 0;

    return true;
}

// ===== production-only member functions =====
//
// The main switch now accepts only amdiommu=passive and amdiommu=auto-attach.
// The retired M2 experiment modes (arm/mmio/write/table/enable/cmd/pgt*)
// and their entry points live in AMDMapperProbeDebug.cpp, compiled by
// tools/build/build-probe-debug.sh with AMD_MAPPER_PROBE_DEBUG=1.
#if !AMD_MAPPER_PROBE_DEBUG

bool org_maz1_AMDMapperProbe::ReadDbgMask() {
    fDbgMask = amdiommu_dbg::kDefault;
    char text[16] = {};
    if (!PE_parse_boot_argn("amdiommu_dbg", text, sizeof(text) - 1)) return true;
    UInt32 parsed = 0;
    if (!amdiommu_dbg::Parse(text, &parsed)) {
        IOLog("AMDMapperProbe: invalid amdiommu_dbg=%s, using 0x%02x\n",
              text, (unsigned)fDbgMask);
        return false;
    }
    fDbgMask = parsed;
    return true;
}

bool org_maz1_AMDMapperProbe::start(IOService *provider) {
    ReadDbgMask();
    if (DbgOn(amdiommu_dbg::kBase)) {
        setProperty("probe-stage", "0-entered-start");
    }

    // Safety gate: must precede super::start(). When fIsSystem is true,
    // IOMapper::start() sets gSystem = this, a global side effect that cannot
    // be undone.
    fIsSystem = false;

    if (!super::start(provider)) {
        if (DbgOn(amdiommu_dbg::kBase)) {
            setProperty("probe-stage", "1-super-start-FAILED");
        }
        return false;
    }
    if (DbgOn(amdiommu_dbg::kBase)) {
        setProperty("probe-stage", "2-super-start-ok");
    }
    if (fOwner) {
        // Device instance attached to the controller service.
        fAuto = true;
        if (DbgOn(amdiommu_dbg::kBase)) {
            setProperty("iommu-mode", "passive");
            setProperty("iommu-role", "device");
            setProperty("iommu-system-mapper", "no");
        }
        return true;
    }

    char mode[32] = {};
    fAuto = PE_parse_boot_argn("amdiommu", mode, sizeof(mode) - 1)
            && (strcmp(mode, "passive") == 0 ||
                strcmp(mode, "auto-attach") == 0);
    fAutoAttach = fAuto && strcmp(mode, "auto-attach") == 0;
    if (fAuto) {
        return StartAuto();
    }

    // No supported mode: stay inert. No notifier, no device arm, no MMIO.
    if (DbgOn(amdiommu_dbg::kBase)) {
        setProperty("probe-stage", "3-no-auto-mode");
        setProperty("iommu-mode", "inert");
    }
    return true;
}

IOReturn org_maz1_AMDMapperProbe::callPlatformFunction(
    const OSSymbol *name, bool wait, void *target, void *operation,
    void *unused3, void *unused4) {
    if (name && name->isEqualTo(amd_iommu_policy::kClaim)) {
        if (!target || operation || unused3 || unused4) return kIOReturnBadArgument;
        return AttachAuto(static_cast<IOService *>(target), true)
            ? kIOReturnSuccess : kIOReturnNotReady;
    }
    // Hook-driven attach: the caller is already past pciDevice->open(), which
    // kClaim refuses by design. Everything else - explicit selection, the
    // offer record, idempotency, rollback - is the same code path.
    if (name && name->isEqualTo(amd_iommu_policy::kAttach)) {
        if (!target || operation || unused3 || unused4) return kIOReturnBadArgument;
        return AttachAuto(static_cast<IOService *>(target), true, true)
            ? kIOReturnSuccess : kIOReturnNotReady;
    }
    // Formerly R63SetRequesterDMA.
    if (name && name->isEqualTo("SetRequesterDMAAccess")) {
        if (!fAuto || !fNicDevice) return kIOReturnNotReady;
        const uintptr_t op = (uintptr_t)operation;
        if (target != fNicDevice || unused3 || unused4 || (op != 1 && op != 2))
            return kIOReturnBadArgument;
        return SetRequesterDMA(op == 1);
    }
    // Formerly R47PowerTransition.
    if (name && name->isEqualTo("RequestPowerTransition")) {
        if (!fAuto || !fNicDevice) return kIOReturnNotReady;
        const uintptr_t op = (uintptr_t)operation;
        if (target != fNicDevice || unused3 || unused4 || (op != 1 && op != 2))
            return kIOReturnBadArgument;
        return PowerTransition((UInt32)op);
    }
    return super::callPlatformFunction(name, wait, target, operation,
                                      unused3, unused4);
}

IOReturn org_maz1_AMDMapperProbe::setProperties(OSObject *properties) {
    OSDictionary *dict = OSDynamicCast(OSDictionary, properties);
    // Formerly R66ArmSystemPM.
    OSObject *pmArm = dict ? dict->getObject("SetSystemPMArmed") : nullptr;
    if (pmArm) {
        if (pmArm != kOSBooleanTrue && pmArm != kOSBooleanFalse)
            return kIOReturnBadArgument;
        return SetSystemPM(pmArm == kOSBooleanTrue);
    }
    // Formerly R52Snapshot.
    OSObject *all = dict ? dict->getObject("PublishAllDomains") : nullptr;
    if (fAuto && all) {
        if (all != kOSBooleanTrue) return kIOReturnBadArgument;
        if (fOwner) return kIOReturnUnsupported;
        PublishDomains();
        return kIOReturnSuccess;
    }
    // Formerly R44Snapshot.
    OSObject *snapshot = dict ? dict->getObject("RefreshSnapshot") : nullptr;
    if (fAuto && snapshot) {
        if (snapshot != kOSBooleanTrue) return kIOReturnBadArgument;
        if (fOwner) PublishMappings();
        else PublishDomains();
        return kIOReturnSuccess;
    }
    return super::setProperties(properties);
}

void org_maz1_AMDMapperProbe::stop(IOService *provider) {
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
    }
    super::stop(provider);
}

uint64_t org_maz1_AMDMapperProbe::getPageSize() const {
    return 4096;
}

IOReturn org_maz1_AMDMapperProbe::iovmMapMemory(
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
    if (mapAddress) *mapAddress = 0;
    if (mapLength)  *mapLength  = 0;
    return kIOReturnUnsupported;
}

IOReturn org_maz1_AMDMapperProbe::iovmUnmapMemory(
    IOMemoryDescriptor *memory, IODMACommand *dmaCommand,
    uint64_t mapAddress, uint64_t mapLength) {
    if (fAuto)
        return UnmapMemory(memory, dmaCommand, mapAddress, mapLength);
    return kIOReturnUnsupported;
}

IOReturn org_maz1_AMDMapperProbe::iovmInsert(
    uint32_t options, uint64_t mapAddress, uint64_t offset,
    uint64_t physicalAddress, uint64_t length) {
    (void)options; (void)mapAddress; (void)offset;
    (void)physicalAddress; (void)length;
    fInsertCalls++;
    if (fAuto) {
        setProperty("iommu-insert-rejects", (unsigned long long)fInsertCalls, 32);
    }
    return kIOReturnUnsupported;
}

uint64_t org_maz1_AMDMapperProbe::mapToPhysicalAddress(uint64_t mappedAddress) {
    if (fAuto) {
        uint64_t pa = 0;
        return Translate(mappedAddress, &pa) ? pa : 0;
    }
    return 0;
}

#endif /* !AMD_MAPPER_PROBE_DEBUG */

// ===== kmod trailer (original lines 8009..8016) =====
extern "C" {
extern kern_return_t _start(kmod_info_t *, void *);
extern kern_return_t _stop(kmod_info_t *, void *);
KMOD_EXPLICIT_DECL(org.maz1.AMDMapperProbe, "0.98.0", _start, _stop);
__attribute__((visibility("hidden"))) kmod_start_func_t *_realmain = nullptr;
__attribute__((visibility("hidden"))) kmod_stop_func_t *_antimain = nullptr;
__attribute__((visibility("hidden"))) int _kext_apple_cc = __APPLE_CC__;
}
