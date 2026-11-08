// AMDMapperProbeNic.cpp -- NIC discovery, publish notifier, arming
//
// Part of the AMDMapperProbe kext. Split out of the original
// single-file AMDMapperProbe.cpp by tools/dev/split-probe.py; the
// function bodies are unchanged and in their original order.

#include "AMDMapperProbe.hpp"
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

// The definition of OSPtr<T> depends on IOKIT_ENABLE_SHARED_PTR (SDK
// libkern/c++/OSPtr.h): defined = OSSharedPtr<T>; undefined = T*.
// The SDK default is undefined.
#if defined(IOKIT_ENABLE_SHARED_PTR)
    #define M1A_HAS_SHARED_PTR 1
#else
    #define M1A_HAS_SHARED_PTR 0
#endif

#include "AMDMapperProbeInternal.hpp"

// ===== AMDMapperProbeNic.cpp (original lines 156..215) =====

// ===== AMDMapperProbeNic.cpp (original lines 575..618) =====
// ------------------------------------------------------ B2-b publish notifier (race fix)
//
// Goal: attach iommu-parent to the NIC **before** Lucy probes/starts it.
//
// Why gIOFirstPublishNotification instead of enumeration or a delay:
//   The IOKit documentation (IOService.h:279) is explicit: at registerService
//   time the matching list is built first (including already-installed publish
//   notifications), and only **then** is the driver attached/probed/started.
//   So attaching the property inside a publish notification always happens
//   earlier than Lucy reading it.
//   Enumeration (serviceMatching) requires PCI enumeration to be complete --
//   too late; a delay (thread_call) is non-deterministic, and waiting inside
//   start() is impractical.
//
// Why not gIOMatchedNotification:
//   That one is delivered only after the driver has already probed and
//   started, which is **too late** for us.
//
// Note: the handler must return true, otherwise the notification is
// automatically removed.

bool org_maz1_AMDMapperProbe::publishHandler(
    void *target, void *refCon, IOService *newService, IONotifier *notifier) {
    (void)refCon; (void)notifier;

    org_maz1_AMDMapperProbe *self =
        (org_maz1_AMDMapperProbe *)target;
    if (!self || !newService) return true;
    if (self->fAuto) {
        // One path for explicit requester offers and the Info.plist default
        // identity list.
        self->AttachAuto(newService);
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

    if (!isTarget) return true;     // not the NIC, keep waiting

    self->fPublishHits++;
    self->setProperty("publish-hits", (unsigned long long)self->fPublishHits, 64);

    // Do not attach twice (gIOFirstPublishNotification is delivered once per
    // instance, but under kIOServiceSynchronous it may fire more than once on
    // the same instance)
    if (self->fNicDevice == newService) return true;

    self->armNic(newService);
#endif /* AMD_MAPPER_PROBE_DEBUG */
    return true;
}

// ===== AMDMapperProbeNic.cpp (original lines 620..644) =====
// Attach iommu-parent to the NIC. Callable from start() or from the
// notification callback.

// ===== AMDMapperProbeNic.cpp (original lines 646..669) =====
void org_maz1_AMDMapperProbe::installPublishNotifier() {
    // Matching dictionary: only IOPCIDevice matters here. The device-id is
    // verified in the handler, because during the publish phase not all
    // properties may be in place yet, and filtering via propertyMatching
    // could actually miss the device.
    OSDictionary *matching = IOService::serviceMatching("IOPCIDevice");
    if (!matching) {
        setProperty("publish-notifier", "FAIL-no-matching");
        return;
    }

    fPublishNotifier = IOService::addMatchingNotification(
        gIOFirstPublishNotification,
        matching,
        &org_maz1_AMDMapperProbe::publishHandler,
        this,       // target
        nullptr,    // refCon
        0);         // priority

    // addMatchingNotification does not consume a reference to the dictionary
    // (unlike addNotification), so we must release it ourselves here.
    matching->release();

    setProperty("publish-notifier", fPublishNotifier ? "installed" : "FAIL");
}

// ===== AMDMapperProbeNic.cpp (original lines 698..804) =====

// R52 auto mode enumerates endpoints, never a first match or a saved NIC path.
// The first-publish callback uses the same per-requester attach routine.
void org_maz1_AMDMapperProbe::AttachExistingDevices() {
    OSDictionary *matching = IOService::serviceMatching("IOPCIDevice");
    if (!matching) return;
    OSIterator *it = IOService::getMatchingServices(matching);
    matching->release();
    if (!it) return;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    while (OSObject *object = it->getNextObject()) {
        IOPCIDevice *pci = OSDynamicCast(IOPCIDevice, object);
        if (pci) AttachAuto(pci);
    }
#pragma clang diagnostic pop
    it->release();
}
