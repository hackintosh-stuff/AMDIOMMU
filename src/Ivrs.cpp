#include "amd_iommu/Ivrs.hpp"

namespace amd_iommu {
namespace {

std::uint16_t le16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(p[0] | (std::uint16_t{p[1]} << 8));
}
std::uint32_t le32(const std::uint8_t* p) noexcept {
    return std::uint32_t{le16(p)} | (std::uint32_t{le16(p + 2)} << 16);
}
std::uint64_t le64(const std::uint8_t* p) noexcept {
    return std::uint64_t{le32(p)} | (std::uint64_t{le32(p + 4)} << 32);
}
bool fail(IvrsParseResult& r, IvrsError error, std::size_t offset) noexcept {
    r.error = error;
    r.errorOffset = offset;
    return false;
}
bool knownFixedDevice(std::uint8_t type) noexcept {
    switch (type) {
    case 0: case 1: case 2: case 3: case 4:
    case 0x40: case 0x42: case 0x43: case 0x46: case 0x47: case 0x48:
        return true;
    default:
        return false;
    }
}

// All offset advances use lengths already bounded by subtraction, avoiding
// wraparound and ensuring strict progress. No packed structs or bitfields.
bool walk(const std::uint8_t* bytes, std::size_t length,
          IvrsParseResult& r, const IvrsVisitor* visitor) noexcept {
    std::size_t offset = kIvrsHeaderSize;
    while (offset < length) {
        if (length - offset < 6) {
            return fail(r, IvrsError::TruncatedBlockHeader, offset);
        }
        const auto* p = bytes + offset;
        IvrsBlockView block{};
        block.bytes = p;
        block.offset = offset;
        block.type = p[0];
        block.flags = p[1];
        block.length = le16(p + 2);
        block.deviceId = le16(p + 4);
        if (block.length < 6) {
            return fail(r, IvrsError::InvalidBlockLength, offset + 2);
        }
        if (block.length > length - offset) {
            return fail(r, IvrsError::TruncatedBlock, offset + 2);
        }
        if (block.type == 0x10 || block.type == 0x11 || block.type == 0x40) {
            block.kind = IvrsBlockKind::Ivhd;
            block.fixedSize = block.type == 0x10 ? kIvhd10Size : kIvhd11Or40Size;
            if (block.length < block.fixedSize) {
                return fail(r, IvrsError::InvalidIvhdLength, offset + 2);
            }
            block.capabilityOffset = le16(p + 6);
            block.registerBase = le64(p + 8);
            block.pciSegment = le16(p + 16);
            block.iommuInfo = le16(p + 18);
            block.featureReportingOrAttributes = le32(p + 20);
            if (block.type != 0x10) {
                block.efrImage = le64(p + 24);
            }
            ++r.ivhdCount;
        } else if (block.type >= 0x20 && block.type <= 0x22) {
            block.kind = IvrsBlockKind::Ivmd;
            block.fixedSize = kIvmdSize;
            // No IVMD extension framing is implemented: reject rather than
            // silently treating extra data as a supported memory definition.
            if (block.length != kIvmdSize) {
                return fail(r, IvrsError::InvalidIvmdLength, offset + 2);
            }
            block.auxiliaryData = le16(p + 6);
            block.memoryStart = le64(p + 16);
            block.memoryLength = le64(p + 24);
            ++r.ivmdCount;
        } else {
            ++r.unknownBlockCount;
        }
        ++r.blockCount;
        if (visitor && visitor->block && !visitor->block(visitor->context, block)) {
            return fail(r, IvrsError::VisitorStopped, offset);
        }
        if (block.kind == IvrsBlockKind::Ivhd) {
            std::size_t relative = block.fixedSize;
            while (relative < block.length) {
                const std::size_t remaining = block.length - relative;
                const auto* entry = p + relative;
                std::size_t entrySize = 0;
                bool known = false;
                if (entry[0] == 0xF0) {
                    // HID's UID length is at byte 21, after HID/CID/UID type.
                    if (remaining < 22) {
                        return fail(r, IvrsError::TruncatedDeviceEntry, offset + relative);
                    }
                    entrySize = 22 + std::size_t{entry[21]};
                    known = true;
                } else if (entry[0] < 0x80) {
                    entrySize = entry[0] < 0x40 ? 4 : 8;
                    known = knownFixedDevice(entry[0]);
                } else {
                    // Do not guess 16/32-byte lengths for future/variable formats.
                    return fail(r, IvrsError::UnsupportedDeviceEntry, offset + relative);
                }
                if (entrySize > remaining) {
                    return fail(r, IvrsError::TruncatedDeviceEntry, offset + relative);
                }
                IvrsDeviceView device{};
                device.bytes = entry;
                device.offset = offset + relative;
                device.blockOffset = offset;
                device.length = entrySize;
                device.type = entry[0];
                device.deviceId = le16(entry + 1);
                device.dataSetting = entry[3];
                device.knownType = known;
                ++r.deviceCount;
                if (!known) {
                    ++r.unknownDeviceCount;
                }
                if (visitor && visitor->device && !visitor->device(visitor->context, device)) {
                    return fail(r, IvrsError::VisitorStopped, device.offset);
                }
                relative += entrySize;
            }
        }
        offset += block.length;
    }
    return true;
}

} // namespace

IvrsParseResult parseIvrs(const std::uint8_t* bytes, std::size_t size,
                          const IvrsVisitor& visitor) noexcept {
    IvrsParseResult result{};
    if (!bytes) {
        fail(result, IvrsError::NullInput, 0);
        return result;
    }
    if (size < kAcpiHeaderSize) {
        fail(result, IvrsError::TruncatedAcpiHeader, size);
        return result;
    }
    if (bytes[0] != 'I' || bytes[1] != 'V' || bytes[2] != 'R' || bytes[3] != 'S') {
        fail(result, IvrsError::BadSignature, 0);
        return result;
    }
    const std::size_t length = le32(bytes + 4);
    result.tableLength = length;
    if (length < kIvrsHeaderSize) {
        fail(result, IvrsError::InvalidTableLength, 4);
        return result;
    }
    if (length > size) {
        fail(result, IvrsError::TruncatedTable, 4);
        return result;
    }
    std::uint8_t checksum = 0;
    for (std::size_t i = 0; i < length; ++i) {
        checksum = static_cast<std::uint8_t>(checksum + bytes[i]);
    }
    if (checksum != 0) {
        fail(result, IvrsError::BadChecksum, 9);
        return result;
    }
    if (!walk(bytes, length, result, nullptr)) {
        return result;
    }
    if (!visitor.table && !visitor.block && !visitor.device) {
        return result;
    }
    const IvrsTableView table{bytes, static_cast<std::uint32_t>(length), bytes[8], le32(bytes + 36)};
    if (visitor.table && !visitor.table(visitor.context, table)) {
        fail(result, IvrsError::VisitorStopped, 0);
        return result;
    }
    IvrsParseResult delivery{};
    if (!walk(bytes, length, delivery, &visitor)) {
        // Retain full validated counts, even if visitor intentionally stops.
        fail(result, delivery.error, delivery.errorOffset);
    }
    return result;
}

const char* ivrsErrorString(IvrsError error) noexcept {
    switch (error) {
    case IvrsError::None: return "structurally valid (not hardware validation)";
    case IvrsError::NullInput: return "null input";
    case IvrsError::TruncatedAcpiHeader: return "truncated ACPI header";
    case IvrsError::BadSignature: return "expected IVRS signature";
    case IvrsError::InvalidTableLength: return "IVRS length is below 48";
    case IvrsError::TruncatedTable: return "declared table exceeds input";
    case IvrsError::BadChecksum: return "ACPI checksum mismatch";
    case IvrsError::TruncatedBlockHeader: return "truncated IVRS block header";
    case IvrsError::InvalidBlockLength: return "block length is below 6";
    case IvrsError::TruncatedBlock: return "block exceeds table";
    case IvrsError::InvalidIvhdLength: return "IVHD shorter than fixed prefix";
    case IvrsError::InvalidIvmdLength: return "IVMD length is not 32";
    case IvrsError::TruncatedDeviceEntry: return "device entry exceeds IVHD";
    case IvrsError::UnsupportedDeviceEntry: return "unknown variable/reserved device framing";
    case IvrsError::VisitorStopped: return "visitor requested stop";
    }
    return "unknown parser error";
}

} // namespace amd_iommu
