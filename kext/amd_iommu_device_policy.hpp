// Shared pre-open handshake for ordinary per-device DMA clients.
#pragma once
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <libkern/c++/OSString.h>

namespace amd_iommu_policy {
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
        if (device->getProperty("iommu-parent")) return true;
        if (elapsed != waitMs) IOSleep(1);
    }
    return !selected;
}
} // namespace amd_iommu_policy
