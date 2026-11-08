// Shared pre-open handshake for ordinary per-device DMA clients.
#pragma once
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <libkern/c++/OSString.h>

namespace amd_iommu_policy {
static constexpr const char *kOffer = "amdiommu-requester-offer";
static constexpr const char *kClaim = "AMDIOMMUClaimRequesterV1";
// Attach a requester that is already open. This is the verb used by the
// IOMapper::copyMapperForDevice() hook (AMDMapperHook.kext): that hook runs
// after pciDevice->open(), where kClaim is refused by design.
//
// This verb does not carry its own selection logic and must not gain any: it is
// reached for arbitrary PCI devices, and the probe applies the single selection
// rule in one place. Both sources are valid and neither is optional:
//   - amdiommu_devices present  -> that list is the only input; the Info.plist
//     AMDMapperProbeDevices table is ignored entirely (no merging);
//   - amdiommu_devices absent   -> the AMDMapperProbeDevices table is the
//     selection.
// There is deliberately no "select everything" mode. The IOMMU implementation is
// incomplete, so a device outside both lists has no verified translation
// behaviour and must stay on its physical DMA path; a missing or unparseable
// table leaves the selection empty, and an empty selection attaches nothing.
static constexpr const char *kAttach = "AMDIOMMUAttachRequesterV1";
static constexpr const char *kProperty = "amdiommu-dma-policy";
static constexpr const char *kSelected = "selected";
static constexpr const char *kMapped = "mapped";
static constexpr const char *kPassthrough = "passthrough";
static constexpr const char *kFailed = "failed";

// Call before opening the PCI provider. The controller never attaches to an
// already-open device. Explicitly excluded devices take their normal physical
// path immediately; a selected device must not fall back after prepare failed.
// An absent controller preserves the older bounded-wait physical fallback.
inline bool waitForMapper(IOService *device, UInt32 waitMs = 2000) {
    if (!device) return false;
    bool selected = false;
    for (UInt32 elapsed = 0; elapsed <= waitMs; ++elapsed) {
        OSObject *object = device->copyProperty(kProperty);
        OSString *policy = OSDynamicCast(OSString, object);
        const bool passthrough = policy && policy->isEqualTo(kPassthrough);
        const bool failed = policy && policy->isEqualTo(kFailed);
        selected |= policy && (policy->isEqualTo(kSelected) ||
                               policy->isEqualTo(kMapped));
        if (object) object->release();
        if (passthrough) return true;
        if (failed) return false;
        // Claim before PCI open. Stop DMA in the driver before its first map.
        OSObject *offer = device->copyProperty(kOffer);
        if (offer) {
            IOService *owner = OSDynamicCast(IOService, offer);
            const bool ok = owner && owner->callPlatformFunction(kClaim, false, device,
                nullptr, nullptr, nullptr) == kIOReturnSuccess;
            offer->release();
            return ok && device->getProperty("iommu-parent");
        }
        if (device->getProperty("iommu-parent")) return true;
        if (elapsed != waitMs) IOSleep(1);
    }
    return !selected;
}
} // namespace amd_iommu_policy
