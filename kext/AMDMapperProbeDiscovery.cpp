// The normal IOMapper path obtains its controller from firmware and PCI.
#include "AMDMapperProbeDiscovery.hpp"
#include "amd_iommu/IvrsTopology.hpp"
#include <IOKit/IOLib.h>
#include <IOKit/acpi/IOACPIPlatformDevice.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSIterator.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
namespace {
constexpr UInt16 kPciSegment = 0;
// Basic registers, command/event indices and status end below 0x4000. The
// optional performance-counter aperture is not used by this backend.
constexpr UInt64 kMmioBytes = 0x4000;
constexpr UInt32 kPciEfrSupported = 1u << 27;

IOPCIDevice *FindIommu(UInt16 deviceID) {
    OSDictionary *matching = IOService::serviceMatching("IOPCIDevice");
    if (!matching) return nullptr;
    OSIterator *it = IOService::getMatchingServices(matching);
    matching->release();
    if (!it) return nullptr;
    IOPCIDevice *found = nullptr;
    OSObject *obj;
    while ((obj = it->getNextObject())) {
        IOPCIDevice *pci = OSDynamicCast(IOPCIDevice, obj);
        if (!pci) continue;
        const UInt16 id = ((UInt16)pci->getBusNumber() << 8) |
            ((UInt16)pci->getDeviceNumber() << 3) | pci->getFunctionNumber();
        if (id != deviceID || pci->configRead16(kIOPCIConfigVendorID) != 0x1022)
            continue;
        pci->retain();
        found = pci;
        break;
    }
    it->release();
    return found;
}

// Any ACPI device exposes the firmware table set; the lookup itself is table
// scoped, so one device is enough. The static IVRS table lives for the boot.
IOACPIPlatformDevice *FindAcpiDevice() {
    OSDictionary *matching = IOService::serviceMatching("IOACPIPlatformDevice");
    if (!matching) return nullptr;
    OSIterator *it = IOService::getMatchingServices(matching);
    matching->release();
    if (!it) return nullptr;
    IOACPIPlatformDevice *found = nullptr;
    OSObject *obj;
    while ((obj = it->getNextObject())) {
        IOACPIPlatformDevice *device = OSDynamicCast(IOACPIPlatformDevice, obj);
        if (!device) continue;
        device->retain();
        found = device;
        break;
    }
    it->release();
    return found;
}
}

bool DiscoverHardware(IOService *probe, IOPCIDevice *nic,
                         HardwareInfo &info) {
    info = {};
    auto failure = [probe](const char *reason) {
        probe->setProperty("discovery-state", reason);
        return false;
    };
    auto number = [probe](const char *key, UInt64 value) {
        probe->setProperty(key, (unsigned long long)value, 64);
    };
    probe->setProperty("discovery-source", "acpi-ivrs+pci");
    probe->setProperty("discovery-state", "reading-ivrs");
    IOACPIPlatformDevice *acpi = FindAcpiDevice();
    if (!acpi) return failure("failed-acpi-device");
    // getACPITableData returns a borrowed const OSData. Retain a separate copy
    // as raw runtime evidence; the parser's views only live inside this call.
    const OSData *table = acpi->getACPITableData("IVRS", 0);
    acpi->release();
    if (!table) return failure("failed-ivrs-missing");
    OSData *raw = OSData::withData(table);
    if (!raw) return failure("failed-ivrs-copy");
    probe->setProperty("discovery-ivrs-raw", raw);
    number("discovery-ivrs-bytes", raw->getLength());
    auto *units = (amd_iommu::IvhdUnitTable *)
        IOMalloc(sizeof(amd_iommu::IvhdUnitTable));
    if (!units) {
        raw->release();
        return failure("failed-ivrs-memory");
    }
    // Keep the bounded topology inventory off the kernel stack. The scalar
    // result survives its release; no unit/block pointer escapes this scope.
    auto finish = [units, raw, probe](const char *state, bool ok) {
        IOFree(units, sizeof(*units));
        raw->release();
        probe->setProperty("discovery-state", state);
        return ok;
    };
    const UInt8 *bytes = (const UInt8 *)raw->getBytesNoCopy();
    const auto topology = amd_iommu::buildTopology(bytes, raw->getLength(), *units);
    if (!topology) {
        probe->setProperty("discovery-detail",
                          amd_iommu::topologyErrorString(topology.error));
        return finish("failed-ivrs-topology", false);
    }
    const auto requester = amd_iommu::resolveRequester(*units, kPciSegment,
        nic->getBusNumber(), nic->getDeviceNumber(), nic->getFunctionNumber());
    number("discovery-ivrs-unit-count", units->count);
    number("discovery-pci-segment", kPciSegment);
    number("discovery-requester-id", requester.deviceId);
    if (!requester) {
        probe->setProperty("discovery-detail",
                          amd_iommu::requesterStatusString(requester.status));
        return finish("failed-ivrs-requester", false);
    }
    const auto &unit = units->units[requester.unitIndex];
    number("discovery-ivrs-unit-index", requester.unitIndex);
    number("discovery-ivrs-block-count", unit.blockCount);
    number("discovery-resolved-requester-id", requester.resolvedDeviceId);
    number("discovery-ivrs-data-setting", requester.dataSetting);
    number("discovery-requester-alias", requester.viaAlias);
    number("discovery-iommu-device-id", unit.deviceId);
    number("discovery-capability-offset", unit.capabilityOffset);
    number("discovery-ivrs-mmio-base", unit.registerBase);
    // The existing per-device DTE policy has no alias/redirection or firmware
    // data-setting handling. This board's plain requester uses neither.
    if (requester.viaAlias || requester.resolvedDeviceId != requester.deviceId ||
        requester.dataSetting != 0)
        return finish("failed-unsupported-requester-policy", false);
    const UInt16 cap = unit.capabilityOffset;
    if (cap < 0x40 || cap > 0xf4 || (cap & 3) || !unit.registerBase ||
        (unit.registerBase & (kMmioBytes - 1)))
        return finish("failed-ivrs-controller-address", false);
    IOPCIDevice *iommu = FindIommu(unit.deviceId);
    if (!iommu) return finish("failed-iommu-pci-device", false);
    const UInt32 header = iommu->configRead32(cap);
    const UInt32 barLo = iommu->configRead32(cap + 4);
    const UInt32 barHi = iommu->configRead32(cap + 8);
    iommu->release();
    const UInt64 pciBase = ((UInt64)barHi << 32) | (barLo & ~0x3fffu);
    number("discovery-capability-header", header);
    number("discovery-pci-mmio-base", pciBase);
    // Secure Device ID 0x0f, subtype 3 (bits 18:16), and the enabled 16 KiB
    // aligned BAR must agree with IVHD before Auto.cpp maps it. BAR bit 0
    // enables MMIO decoding and locks PCI capability writes until reset.
    // No MMIO access occurs during this discovery.
    if ((header & 0xff) != 0x0f || ((header >> 16) & 7) != 3 ||
        !(barLo & 1) || pciBase != unit.registerBase)
        return finish("failed-iommu-pci-identity", false);
    info.mmioBase = unit.registerBase;
    info.mmioBytes = kMmioBytes;
    info.iommuID = unit.deviceId;
    info.capabilityOffset = cap;
    info.capabilityHeader = header;
    info.firmwareEfr = unit.efrImage;
    info.firmwareEfrPresent = unit.efrPresent && (bytes[36] & 1);
    info.pciEfrSupported = (header & kPciEfrSupported) != 0;
    number("discovery-mmio-base", info.mmioBase);
    number("discovery-mmio-size", info.mmioBytes);
    number("discovery-ivrs-efr-present", info.firmwareEfrPresent);
    number("discovery-ivrs-efr", info.firmwareEfr);
    number("discovery-pci-efr-supported", info.pciEfrSupported);
    return finish("ivrs-pci-checked", true);
}
#pragma clang diagnostic pop
