#include "amd_iommu/Ivrs.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <initializer_list>

namespace {
using namespace amd_iommu;

struct Fixture {
    std::array<std::uint8_t, 2048> bytes{};
    std::size_t size = kIvrsHeaderSize;

    Fixture() {
        bytes[0] = 'I'; bytes[1] = 'V'; bytes[2] = 'R'; bytes[3] = 'S';
        bytes[8] = 2;
        put32(36, 0x12345678);
        seal();
    }
    void put16(std::size_t pos, std::uint16_t value) {
        bytes[pos] = static_cast<std::uint8_t>(value);
        bytes[pos + 1] = static_cast<std::uint8_t>(value >> 8);
    }
    void put32(std::size_t pos, std::uint32_t value) {
        put16(pos, static_cast<std::uint16_t>(value));
        put16(pos + 2, static_cast<std::uint16_t>(value >> 16));
    }
    void put64(std::size_t pos, std::uint64_t value) {
        put32(pos, static_cast<std::uint32_t>(value));
        put32(pos + 4, static_cast<std::uint32_t>(value >> 32));
    }
    std::size_t block(std::uint8_t type, std::uint16_t length) {
        const auto pos = size;
        bytes[pos] = type;
        put16(pos + 2, length);
        size += length;
        seal();
        return pos;
    }
    void seal() {
        put32(4, static_cast<std::uint32_t>(size));
        bytes[9] = 0;
        std::uint8_t sum = 0;
        for (std::size_t i = 0; i < size; ++i) {
            sum = static_cast<std::uint8_t>(sum + bytes[i]);
        }
        bytes[9] = static_cast<std::uint8_t>(0u - sum);
    }
};

struct Seen {
    std::size_t tables = 0;
    std::size_t blocks = 0;
    std::size_t devices = 0;
    IvrsTableView table{};
    IvrsBlockView lastBlock{};
    IvrsDeviceView lastDevice{};
    bool stopTable = false;
    bool stopBlock = false;
    bool stopDevice = false;
};
bool tableCallback(void* context, const IvrsTableView& table) {
    auto& s = *static_cast<Seen*>(context);
    ++s.tables; s.table = table; return !s.stopTable;
}
bool blockCallback(void* context, const IvrsBlockView& block) {
    auto& s = *static_cast<Seen*>(context);
    ++s.blocks; s.lastBlock = block; return !s.stopBlock;
}
bool deviceCallback(void* context, const IvrsDeviceView& device) {
    auto& s = *static_cast<Seen*>(context);
    ++s.devices; s.lastDevice = device; return !s.stopDevice;
}
IvrsVisitor visitor(Seen& s) {
    return {&s, tableCallback, blockCallback, deviceCallback};
}

int failures = 0;
int checks = 0;
void check(bool condition, const char* expression, int line) {
    ++checks;
    if (!condition) {
        ++failures;
        std::fprintf(stderr, "IvrsTests:%d: %s\n", line, expression);
    }
}
#define IVRS_CHECK(expr) check(static_cast<bool>(expr), #expr, __LINE__)

void expectError(const Fixture& f, IvrsError error, std::size_t offset) {
    Seen s{};
    const auto result = parseIvrs(f.bytes.data(), f.size, visitor(s));
    IVRS_CHECK(result.error == error);
    IVRS_CHECK(result.errorOffset == offset);
    IVRS_CHECK(s.tables == 0 && s.blocks == 0 && s.devices == 0);
}

void testHeader() {
    Fixture f;
    Seen s{};
    const auto r = parseIvrs(f.bytes.data(), f.size, visitor(s));
    IVRS_CHECK(r && r.tableLength == 48 && r.blockCount == 0);
    IVRS_CHECK(s.tables == 1 && s.table.revision == 2);
    IVRS_CHECK(s.table.virtualizationInfo == 0x12345678);
    IVRS_CHECK(parseIvrs(nullptr, 0).error == IvrsError::NullInput);
    IVRS_CHECK(parseIvrs(nullptr, 2048).error == IvrsError::NullInput);
    for (std::size_t n = 0; n < 36; ++n) {
        IVRS_CHECK(parseIvrs(f.bytes.data(), n).error == IvrsError::TruncatedAcpiHeader);
    }
    for (std::size_t n = 36; n < 48; ++n) {
        IVRS_CHECK(parseIvrs(f.bytes.data(), n).error == IvrsError::TruncatedTable);
    }
    f.bytes[0] = 'D';
    expectError(f, IvrsError::BadSignature, 0);
    f.bytes[0] = 'I';
    for (std::uint32_t n = 0; n < 48; ++n) {
        f.put32(4, n);
        expectError(f, IvrsError::InvalidTableLength, 4);
    }
    f.seal();
    f.put32(4, 0xFFFFFFFFu);
    expectError(f, IvrsError::TruncatedTable, 4);
    f.seal();
    f.bytes[47] ^= 1;
    expectError(f, IvrsError::BadChecksum, 9);
    f.seal();
    f.bytes[48] = 0xFF; // Outside declared length: excluded from checksum/walk.
    IVRS_CHECK(parseIvrs(f.bytes.data(), 49));

    // No alignment assumptions about the caller's input.
    std::array<std::uint8_t, 49> unaligned{};
    for (std::size_t i = 0; i < 48; ++i) { unaligned[i + 1] = f.bytes[i]; }
    IVRS_CHECK(parseIvrs(unaligned.data() + 1, 48));
}

void testBlocks() {
    for (const std::uint8_t type : {0x10, 0x11, 0x40}) {
        const std::uint16_t base = type == 0x10 ? 24 : 40;
        Fixture f;
        const auto pos = f.block(type, base);
        f.bytes[pos + 1] = 0xA5;
        f.put16(pos + 4, 0x1234);
        f.put16(pos + 6, 0x40);
        f.put64(pos + 8, 0xFEDCBA9876543210ULL);
        f.put16(pos + 16, 3);
        f.put16(pos + 18, 0x5678);
        f.put32(pos + 20, 0x87654321);
        if (type != 0x10) { f.put64(pos + 24, 0x123456789ABCDEF0ULL); }
        f.seal();
        Seen s{};
        const auto r = parseIvrs(f.bytes.data(), f.size, visitor(s));
        IVRS_CHECK(r && r.ivhdCount == 1 && r.deviceCount == 0);
        IVRS_CHECK(s.lastBlock.kind == IvrsBlockKind::Ivhd);
        IVRS_CHECK(s.lastBlock.fixedSize == base && s.lastBlock.type == type);
        IVRS_CHECK(s.lastBlock.flags == 0xA5 && s.lastBlock.deviceId == 0x1234);
        IVRS_CHECK(s.lastBlock.capabilityOffset == 0x40);
        IVRS_CHECK(s.lastBlock.registerBase == 0xFEDCBA9876543210ULL);
        IVRS_CHECK(s.lastBlock.pciSegment == 3 && s.lastBlock.iommuInfo == 0x5678);
        IVRS_CHECK(s.lastBlock.featureReportingOrAttributes == 0x87654321);
        IVRS_CHECK(s.lastBlock.efrImage == (type == 0x10 ? 0 : 0x123456789ABCDEF0ULL));
        for (std::uint16_t n = 6; n < base; ++n) {
            Fixture shortBlock;
            shortBlock.block(type, n);
            expectError(shortBlock, IvrsError::InvalidIvhdLength, 50);
        }
    }
    for (const std::uint8_t type : {0x20, 0x21, 0x22}) {
        Fixture f;
        const auto pos = f.block(type, 32);
        f.put16(pos + 6, 0x4321);
        f.put64(pos + 16, 0xFFFFFFFFFFFFFFF0ULL);
        f.put64(pos + 24, 0x1000); // Overflowing conceptual range is NOT applied.
        f.seal();
        Seen s{};
        const auto r = parseIvrs(f.bytes.data(), f.size, visitor(s));
        IVRS_CHECK(r && r.ivmdCount == 1 && r.deviceCount == 0);
        IVRS_CHECK(s.lastBlock.kind == IvrsBlockKind::Ivmd);
        IVRS_CHECK(s.lastBlock.auxiliaryData == 0x4321);
        IVRS_CHECK(s.lastBlock.memoryStart == 0xFFFFFFFFFFFFFFF0ULL);
        IVRS_CHECK(s.lastBlock.memoryLength == 0x1000);
        for (const std::uint16_t n : {6, 31, 33}) {
            Fixture wrong;
            wrong.block(type, n);
            expectError(wrong, IvrsError::InvalidIvmdLength, 50);
        }
    }
    for (std::size_t n = 1; n < 6; ++n) {
        Fixture f;
        f.size += n; f.seal();
        expectError(f, IvrsError::TruncatedBlockHeader, 48);
    }
    for (std::uint16_t n = 0; n < 6; ++n) {
        Fixture f;
        f.size += 6; f.put16(50, n); f.seal();
        expectError(f, IvrsError::InvalidBlockLength, 50);
    }
    Fixture oversized;
    oversized.size += 6; oversized.put16(50, 0xFFFF); oversized.seal();
    expectError(oversized, IvrsError::TruncatedBlock, 50);

    Fixture unknown;
    unknown.block(0x7F, 7); // Opaque body need not be 4-byte aligned.
    unknown.block(0x10, 24);
    Seen s{};
    const auto r = parseIvrs(unknown.bytes.data(), unknown.size, visitor(s));
    IVRS_CHECK(r && r.blockCount == 2 && r.unknownBlockCount == 1 && r.ivhdCount == 1);
    IVRS_CHECK(s.blocks == 2);
}

void testDevices() {
    for (const std::uint8_t blockType : {0x10, 0x11, 0x40}) {
        const std::uint16_t base = blockType == 0x10 ? 24 : 40;
        for (unsigned t = 0; t < 256; ++t) {
            Fixture f;
            const bool hid = t == 0xF0;
            const std::uint16_t entrySize = hid ? 25 : (t < 0x40 ? 4 : 8);
            const auto pos = f.block(blockType, static_cast<std::uint16_t>(base + entrySize));
            const auto entry = pos + base;
            f.bytes[entry] = static_cast<std::uint8_t>(t);
            f.put16(entry + 1, 0xBEEF); f.bytes[entry + 3] = 0x5A;
            if (hid) { f.bytes[entry + 20] = 2; f.bytes[entry + 21] = 3; }
            f.seal();
            Seen s{};
            const auto r = parseIvrs(f.bytes.data(), f.size, visitor(s));
            if (t >= 0x80 && !hid) {
                IVRS_CHECK(r.error == IvrsError::UnsupportedDeviceEntry);
                IVRS_CHECK(r.errorOffset == entry && s.tables == 0);
            } else {
                const bool known = t <= 4 || t == 0x40 || t == 0x42 || t == 0x43 ||
                    t == 0x46 || t == 0x47 || t == 0x48 || hid;
                IVRS_CHECK(r && r.deviceCount == 1);
                IVRS_CHECK(r.unknownDeviceCount == (known ? 0u : 1u));
                IVRS_CHECK(s.lastDevice.offset == entry && s.lastDevice.blockOffset == pos);
                IVRS_CHECK(s.lastDevice.length == entrySize && s.lastDevice.type == t);
                IVRS_CHECK(s.lastDevice.deviceId == 0xBEEF && s.lastDevice.dataSetting == 0x5A);
                IVRS_CHECK(s.lastDevice.knownType == known);
            }
        }
    }
    for (const std::uint8_t type : {0x02, 0x42, 0xF0}) {
        const std::uint16_t needed = type == 0xF0 ? 22 : (type == 2 ? 4 : 8);
        for (std::uint16_t n = 1; n < needed; ++n) {
            Fixture f;
            const auto pos = f.block(0x10, static_cast<std::uint16_t>(24 + n));
            f.bytes[pos + 24] = type; f.seal();
            expectError(f, IvrsError::TruncatedDeviceEntry, pos + 24);
        }
    }
    for (const std::uint8_t uidLength : {0, 1, 3, 255}) {
        Fixture f;
        const auto pos = f.block(0x40, static_cast<std::uint16_t>(40 + 22 + uidLength + 4));
        f.bytes[pos + 40] = 0xF0;
        f.bytes[pos + 61] = uidLength;
        f.bytes[pos + 62 + uidLength] = 2;
        f.seal();
        IVRS_CHECK(parseIvrs(f.bytes.data(), f.size).deviceCount == 2);
        // Keep a complete 22-byte HID prefix, but truncate the claimed UID.
        if (uidLength != 0) {
            f.put16(pos + 2, 62); f.size = pos + 62; f.seal();
            expectError(f, IvrsError::TruncatedDeviceEntry, pos + 40);
        }
    }
    // An entry may not consume bytes from the next block, even if in the buffer.
    Fixture crossing;
    crossing.block(0x10, 28);
    crossing.bytes[72] = 0x42;
    crossing.block(0x20, 32);
    crossing.seal();
    expectError(crossing, IvrsError::TruncatedDeviceEntry, 72);
}

void testDelivery() {
    Fixture f;
    f.block(0x10, 28); f.bytes[72] = 2;
    f.block(0x11, 44); f.bytes[116] = 2;
    f.seal();
    Seen s{};
    auto r = parseIvrs(f.bytes.data(), f.size, visitor(s));
    IVRS_CHECK(r && r.blockCount == 2 && r.deviceCount == 2);
    IVRS_CHECK(s.tables == 1 && s.blocks == 2 && s.devices == 2);
    for (int mode = 0; mode < 3; ++mode) {
        Seen stopped{};
        stopped.stopTable = mode == 0;
        stopped.stopBlock = mode == 1;
        stopped.stopDevice = mode == 2;
        r = parseIvrs(f.bytes.data(), f.size, visitor(stopped));
        IVRS_CHECK(r.error == IvrsError::VisitorStopped);
        IVRS_CHECK(r.blockCount == 2 && r.deviceCount == 2);
        IVRS_CHECK(r.errorOffset == (mode == 0 ? 0u : (mode == 1 ? 48u : 72u)));
    }
    // Malformation late in the table suppresses even early valid callbacks.
    f.bytes[116] = 0x42; f.seal();
    expectError(f, IvrsError::TruncatedDeviceEntry, 116);
    IVRS_CHECK(ivrsErrorString(IvrsError::None) != nullptr);
    IVRS_CHECK(ivrsErrorString(static_cast<IvrsError>(999)) != nullptr);
}

} // namespace

// Returns failure count, so it can be composed with other portable suites.
int runIvrsTests() {
    failures = 0; checks = 0;
    testHeader(); testBlocks(); testDevices(); testDelivery();
    std::printf("IVRS tests: %d checks, %d failures (synthetic fixtures only)\n", checks, failures);
    return failures;
}

#ifdef AMD_IOMMU_IVRS_TEST_MAIN
int main() { return runIvrsTests() == 0 ? 0 : 1; }
#endif
