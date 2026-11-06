// AMDMapperProbeNicDebug.cpp -- NIC helper functions used only by the
// retired B1/B2-b/M2-2b-2 experiment path (findTarget/armNic/findNic/
// findNicServiceOnly). Not compiled by the production build.
//
// The shared publish notifier / AttachExistingDevices stay in
// AMDMapperProbeNic.cpp, which both builds compile.

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

#if AMD_MAPPER_PROBE_DEBUG

bool org_maz1_AMDMapperProbe::findTarget() {
    // Strategy 1: direct lookup by path (on the real machine acpi-path =
    // IOACPIPlane:/_SB/PCI0@0/IOMA@2)
    const char *paths[] = {
        "IODeviceTree:/PCI0/IOMA",
        "IOACPIPlane:/_SB/PCI0@0/IOMA@2",
        nullptr
    };
    for (int i = 0; paths[i]; i++) {
        IORegistryEntry *e = IORegistryEntry::fromPath(paths[i]);
        if (!e) continue;
        IOService *svc = OSDynamicCast(IOService, e);
        if (svc && iommuNameMatches(svc)) {
            fTarget = svc;
            setProperty("m1b-find", "OK-by-path");
            setProperty("m1b-target-name", svc->getName());
            setProperty("m1b-target-path", paths[i]);
            return true;
        }
        e->release();
    }

    // Strategy 2: enumerate and verify IOName one by one.
    // serviceMatching + setObject to append a property key is not reliable
    // (0.2.0 testing once returned D002/pci1022,1480), so we must verify
    // ourselves.
    OSDictionary *matching = IOService::serviceMatching("IOPCIDevice");
    if (!matching) {
        setProperty("m1b-find", "FAIL-no-matching-dict");
        return false;
    }
#if M1A_HAS_SHARED_PTR
    OSPtr<OSIterator> iter = IOService::getMatchingServices(matching);
    OSIterator *it = iter.get();
#else
    OSIterator *it = IOService::getMatchingServices(matching);
#endif
    matching->release();

    if (!it) {
        setProperty("m1b-find", "FAIL-no-iterator");
        return false;
    }

    bool found = false;
    OSObject *obj;
    while ((obj = it->getNextObject())) {
        IOService *svc = OSDynamicCast(IOService, obj);
        if (svc && iommuNameMatches(svc)) {
            svc->retain();
            fTarget = svc;
            setProperty("m1b-find", "OK-by-enumerate");
            setProperty("m1b-target-name", svc->getName());
            found = true;
            break;
        }
    }
    it->release();

    if (!found) setProperty("m1b-find", "FAIL-no-iommu-device");
    return found;
}

bool org_maz1_AMDMapperProbe::armNic(IOService *nic) {
    if (!nic) return false;

    if (fNicDevice && fNicDevice != nic) {
        fNicDevice->removeProperty("iommu-parent");
        fNicDevice->release();
    }
    if (fNicDevice != nic) {
        nic->retain();
        fNicDevice = nic;
    }

    nic->setProperty("iommu-parent", this);
    setProperty("m1bb-parent", "set");
    setProperty("m1bb-nic-name", nic->getName());

    // Record "whether it was already claimed by a driver when the property
    // was attached". Via the notification path it has just published, so no
    // driver can hold it yet -> no-good-timing. If the fallback path inside
    // start() finds it already claimed -> yes-too-late, meaning the
    // notification missed the window.
    bool busy = (nic->getProperty("IOClass") != nullptr)
             && (OSDynamicCast(OSString, nic->getProperty("IOClass")) != nullptr);
    setProperty("m1bb-nic-busy", busy ? "yes-too-late" : "no-good-timing");
    return true;
}

bool org_maz1_AMDMapperProbe::findNic() {
    // ---- Strategies 1/2: direct lookup by path ----
    for (int i = 0; kNicPaths[i]; i++) {
        IORegistryEntry *e = IORegistryEntry::fromPath(kNicPaths[i]);
        if (!e) continue;
        IOService *svc = OSDynamicCast(IOService, e);
        if (svc) {
            // Verify device-id to prevent a wrong path from attaching to
            // another device
            OSData *did = OSDynamicCast(OSData, svc->copyProperty("device-id"));
            bool ok = false;
            if (did && did->getLength() >= 2) {
                const UInt8 *p = (const UInt8 *)did->getBytesNoCopy();
                // device-id is little-endian: 0x8127 -> 27 81
                ok = (p[0] == 0x27 && p[1] == 0x81);
            }
            if (did) did->release();

            if (ok) {
                svc->retain();
                fNicDevice = svc;
                setProperty("m1bb-find", (i == 0) ? "OK-by-devicetree"
                                                 : "OK-by-acpipath");
                setProperty("m1bb-nic-name", svc->getName());
                setProperty("m1bb-nic-path", kNicPaths[i]);
                return true;
            }
        }
        e->release();
    }

    // ---- Strategy 3: enumeration (depends on PCI enumeration being done,
    // usually too late) ----
    OSDictionary *matching = IOService::serviceMatching("IOPCIDevice");
    if (!matching) {
        setProperty("m1bb-find", "FAIL-no-matching");
        return false;
    }
#if M1A_HAS_SHARED_PTR
    OSPtr<OSIterator> iter = IOService::getMatchingServices(matching);
    OSIterator *it = iter.get();
#else
    OSIterator *it = IOService::getMatchingServices(matching);
#endif
    matching->release();
    if (!it) {
        setProperty("m1bb-find", "FAIL-no-iterator");
        return false;
    }

    bool found = false;
    OSObject *obj;
    while ((obj = it->getNextObject())) {
        IOService *svc = OSDynamicCast(IOService, obj);
        if (!svc) continue;

        OSObject *nm = svc->copyProperty("IOName");
        if (!nm) continue;
        OSString *s = OSDynamicCast(OSString, nm);
        bool hit = s && (s->isEqualTo("pci10ec,8127") != false);
        nm->release();
        if (!hit) continue;

        // Hit. Note: this fallback path depends on PCI enumeration being
        // complete and is usually too late already (Lucy may have started long
        // ago). The real timing guarantee is the publish notification.
        svc->retain();
        fNicDevice = svc;
        setProperty("m1bb-find", "OK-by-enumerate");
        setProperty("m1bb-nic-name", svc->getName());
        found = true;
        break;
    }
    it->release();

    if (!found) setProperty("m1bb-find", "ABSENT-no-rtl8127");
    return found;
}
// Read-only lookup of the RTL8127 IOService, used by M2-2b-2 to obtain the BDF.
//
// Difference from findNic():
//   findNic()            retains, writes fNicDevice and the m1bb-* properties,
//                        and callers only use it while fArmed, making it part
//                        of the "arm flow".
//   findNicServiceOnly() only looks up and retains the return; the caller
//                        releases it. It touches no member state, so it is
//                        safe to use in pgt mode as well.
//
// Both paths reuse the same set of path constants, guaranteeing they find the
// same device.
IOService *org_maz1_AMDMapperProbe::findNicServiceOnly() {
    for (int i = 0; kNicPaths[i]; i++) {
        IORegistryEntry *e = IORegistryEntry::fromPath(kNicPaths[i]);
        if (!e) continue;
        IOService *svc = OSDynamicCast(IOService, e);
        if (svc) {
            OSData *did = OSDynamicCast(OSData, svc->copyProperty("device-id"));
            bool ok = false;
            if (did && did->getLength() >= 2) {
                const UInt8 *p = (const UInt8 *)did->getBytesNoCopy();
                ok = (p[0] == 0x27 && p[1] == 0x81);
            }
            if (did) did->release();
            if (ok) {
                svc->retain();
                e->release();
                return svc;
            }
        }
        e->release();
    }
    // The path list only resolves once the entry is attached in that plane.
    // The nub itself already exists and is published by the time this kext
    // starts, so enumerating IOPCIDevice and checking the config IDs finds it
    // without depending on either plane's spelling: on this machine the nub is
    // named "ethernet", not "pci10ec,8127", so a name match would miss it.
    OSDictionary *matching = IOService::serviceMatching("IOPCIDevice");
    if (!matching) return nullptr;
    OSIterator *it = IOService::getMatchingServices(matching);
    matching->release();
    if (!it) return nullptr;
    IOService *result = nullptr;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    OSObject *obj;
    while ((obj = it->getNextObject())) {
        IOPCIDevice *pci = OSDynamicCast(IOPCIDevice, obj);
        if (!pci) continue;
        if (pci->configRead16(kIOPCIConfigVendorID) != 0x10ec ||
            pci->configRead16(kIOPCIConfigDeviceID) != 0x8127) continue;
        pci->retain();
        result = pci;
        break;
    }
#pragma clang diagnostic pop
    it->release();
    return result;
}

#endif /* AMD_MAPPER_PROBE_DEBUG */
