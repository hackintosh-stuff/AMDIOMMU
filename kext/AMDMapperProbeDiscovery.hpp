#pragma once

#include <IOKit/IOService.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Winconsistent-missing-override"
#include <IOKit/pci/IOPCIDevice.h>

// Runtime identity of the IVHD unit that owns the current NIC. This contains
// values only; no pointer borrows the ACPI table or a PCI iterator's lifetime.
struct R47HardwareInfo {
    UInt64 mmioBase;
    UInt64 mmioBytes;
    UInt64 firmwareEfr;
    UInt32 capabilityHeader;
    UInt16 iommuID;
    UInt16 capabilityOffset;
    bool firmwareEfrPresent;
    bool pciEfrSupported;
};

// Read-only discovery for the current segment-0, per-device normal mode.
// MMIO is mapped and checked by r44AttachAuto before its first register write.
bool r47DiscoverHardware(IOService *probe, IOPCIDevice *nic,
                         R47HardwareInfo &info);
#pragma clang diagnostic pop
