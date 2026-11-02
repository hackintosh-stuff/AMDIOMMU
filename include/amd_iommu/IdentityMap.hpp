#pragma once
#include <stdint.h>

namespace amd_iommu {

// A model of one scalar IOMapper result, NOT a scatter/gather list.
// No allocation, no descriptor ownership, no page preparation, no hardware IO.
enum class IdentityStatus {
    Ok,
    InvalidArgument,
    DescriptorRange,
    AddressOverflow,
    ReaderFailed,
    ZeroPhysicalAddress,
    Fragmented,
    Alignment,
    AddressWidth,
    SegmentBudget
};

struct PhysicalRun {
    uint64_t address;
    uint64_t length;
};

// Reader must report the PA and remaining run length at EXACT descriptorOffset.
// It must bypass any existing mapper and operate on already prepared memory.
using PhysicalReader = bool (*)(void *context, uint64_t descriptorOffset,
                                PhysicalRun *run);

struct IdentityRequest {
    uint64_t descriptorLength;
    uint64_t offset;
    uint64_t length;       // zero is invalid; never implicitly maps the whole MD
    uint64_t alignment;    // zero is treated as one, otherwise power-of-two
    uint8_t addressBits;   // 0 or 64 means unrestricted, >64 invalid
    uint32_t segmentBudget; // finite bound on reader calls, >0 required
};

struct IdentityResult {
    uint64_t address;
    uint64_t length;
    uint32_t segmentsRead;
};

// On any failure address/length are zero. Only physically contiguous requests
// succeed; no fake IOVA offsets, coalescing across holes, or bounce buffers.
IdentityStatus validateIdentity(const IdentityRequest &request,
                                PhysicalReader reader, void *context,
                                IdentityResult &result);
const char *identityStatusName(IdentityStatus status);

} // namespace amd_iommu
