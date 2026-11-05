#pragma once

#if defined(KERNEL)
// The kext is built with -nostdinc++; this parser needs only the C integer and
// size types, with the same names used by the host build.
#include <stddef.h>
#include <stdint.h>
namespace std {
using ::size_t;
using ::uint8_t;
using ::uint16_t;
using ::uint32_t;
using ::uint64_t;
}
#else
#include <cstddef>
#include <cstdint>
#endif

namespace amd_iommu {

// Structural inspection only. No address in a table is dereferenced.
constexpr std::size_t kAcpiHeaderSize = 36;
constexpr std::size_t kIvrsHeaderSize = 48;
constexpr std::size_t kIvhd10Size = 24;
constexpr std::size_t kIvhd11Or40Size = 40;
constexpr std::size_t kIvmdSize = 32;

enum class IvrsError {
    None,
    NullInput,
    TruncatedAcpiHeader,
    BadSignature,
    InvalidTableLength,
    TruncatedTable,
    BadChecksum,
    TruncatedBlockHeader,
    InvalidBlockLength,
    TruncatedBlock,
    InvalidIvhdLength,
    InvalidIvmdLength,
    TruncatedDeviceEntry,
    UnsupportedDeviceEntry,
    VisitorStopped
};

struct IvrsTableView {
    const std::uint8_t* bytes = nullptr;
    std::uint32_t length = 0;
    std::uint8_t revision = 0;
    std::uint32_t virtualizationInfo = 0;
};

enum class IvrsBlockKind { Ivhd, Ivmd, Unknown };

struct IvrsBlockView {
    const std::uint8_t* bytes = nullptr;
    std::size_t offset = 0; // Relative to start of table.
    std::uint16_t length = 0;
    std::uint8_t type = 0;
    std::uint8_t flags = 0;
    std::uint16_t deviceId = 0;
    IvrsBlockKind kind = IvrsBlockKind::Unknown;
    std::size_t fixedSize = 0; // Zero for unknown block types.

    // IVHD only; numerical firmware claims, NOT mapped hardware resources.
    std::uint16_t capabilityOffset = 0;
    std::uint64_t registerBase = 0;
    std::uint16_t pciSegment = 0;
    std::uint16_t iommuInfo = 0;
    std::uint32_t featureReportingOrAttributes = 0;
    std::uint64_t efrImage = 0; // Only types 0x11 and 0x40.

    // IVMD only; no range, permission or device-selection policy is applied.
    std::uint16_t auxiliaryData = 0;
    std::uint64_t memoryStart = 0;
    std::uint64_t memoryLength = 0;
};

struct IvrsDeviceView {
    const std::uint8_t* bytes = nullptr;
    std::size_t offset = 0;
    std::size_t blockOffset = 0;
    std::size_t length = 0;
    std::uint8_t type = 0;
    std::uint16_t deviceId = 0;
    std::uint8_t dataSetting = 0;
    bool knownType = false; // Framing recognized, not semantic validation.
};

// Return false to stop delivery. Callbacks must not throw or modify the input.
// Views borrow the caller's immutable buffer; never retain them beyond its life.
struct IvrsVisitor {
    void* context = nullptr;
    bool (*table)(void*, const IvrsTableView&) = nullptr;
    bool (*block)(void*, const IvrsBlockView&) = nullptr;
    bool (*device)(void*, const IvrsDeviceView&) = nullptr;
};

struct IvrsParseResult {
    IvrsError error = IvrsError::None;
    std::size_t errorOffset = 0;
    std::size_t tableLength = 0;
    std::size_t blockCount = 0;
    std::size_t ivhdCount = 0;
    std::size_t ivmdCount = 0;
    std::size_t deviceCount = 0;
    std::size_t unknownBlockCount = 0;
    std::size_t unknownDeviceCount = 0;

    explicit operator bool() const noexcept { return error == IvrsError::None; }
};

// Allocation-free, little-endian, unaligned-safe parser. Checks the entire
// declared table before delivering ANY callback. Extra buffer bytes are ignored.
// Success means structural validity only, never hardware support or safe DMA.
// Unknown blocks and unknown fixed 4/8-byte entries are reported as opaque.
// Unknown variable/reserved-size device formats fail closed, except HID 0xF0,
// whose framing is the 22-byte prefix plus its byte-21 UID length.
IvrsParseResult parseIvrs(const std::uint8_t* bytes, std::size_t size,
                          const IvrsVisitor& visitor = {}) noexcept;
const char* ivrsErrorString(IvrsError error) noexcept;

} // namespace amd_iommu
