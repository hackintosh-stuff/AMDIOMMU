#include "amd_iommu/IdentityMap.hpp"

namespace amd_iommu {
IdentityStatus validateIdentity(const IdentityRequest &r, PhysicalReader reader,
                                void *context, IdentityResult &out) {
    out = {};
    if (!reader || !r.length || !r.segmentBudget || r.addressBits > 64)
        return IdentityStatus::InvalidArgument;
    const uint64_t alignment = r.alignment ? r.alignment : 1;
    if ((alignment & (alignment - 1)) != 0)
        return IdentityStatus::InvalidArgument;
    if (r.offset > r.descriptorLength || r.length > r.descriptorLength - r.offset)
        return IdentityStatus::DescriptorRange;

    const uint64_t maxAddress = ~uint64_t(0);
    const uint64_t addressLimit = (r.addressBits == 0 || r.addressBits == 64)
        ? maxAddress : ((uint64_t(1) << r.addressBits) - 1);
    uint64_t first = 0;
    uint64_t consumed = 0;
    while (consumed < r.length) {
        if (out.segmentsRead == r.segmentBudget)
            return IdentityStatus::SegmentBudget;
        PhysicalRun run{};
        ++out.segmentsRead;
        if (!reader(context, r.offset + consumed, &run) || !run.length)
            return IdentityStatus::ReaderFailed;
        // PA 0 may be valid on some platforms, but descriptor APIs also use it
        // as failure. Deliberately exclude it rather than guess.
        if (!run.address) return IdentityStatus::ZeroPhysicalAddress;
        const uint64_t remaining = r.length - consumed;
        const uint64_t take = run.length < remaining ? run.length : remaining;
        // Check inclusive end; never compute overflowing end-exclusive address.
        if (take - 1 > maxAddress - run.address)
            return IdentityStatus::AddressOverflow;
        if (!consumed) {
            first = run.address;
            if ((first & (alignment - 1)) != 0)
                return IdentityStatus::Alignment;
        } else {
            if (consumed > maxAddress - first)
                return IdentityStatus::AddressOverflow;
            if (run.address != first + consumed)
                return IdentityStatus::Fragmented;
        }
        if (run.address > addressLimit || take - 1 > addressLimit - run.address)
            return IdentityStatus::AddressWidth;
        consumed += take;
    }
    out.address = first;
    out.length = r.length;
    return IdentityStatus::Ok;
}

const char *identityStatusName(IdentityStatus s) {
    switch (s) {
    case IdentityStatus::Ok: return "ok";
    case IdentityStatus::InvalidArgument: return "invalid-argument";
    case IdentityStatus::DescriptorRange: return "descriptor-range";
    case IdentityStatus::AddressOverflow: return "address-overflow";
    case IdentityStatus::ReaderFailed: return "reader-failed";
    case IdentityStatus::ZeroPhysicalAddress: return "zero-physical-address";
    case IdentityStatus::Fragmented: return "fragmented";
    case IdentityStatus::Alignment: return "alignment";
    case IdentityStatus::AddressWidth: return "address-width";
    case IdentityStatus::SegmentBudget: return "segment-budget";
    }
    return "unknown";
}
} // namespace amd_iommu
