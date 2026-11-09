#include "amd_iommu/IvrsTopology.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <initializer_list>

namespace {
using namespace amd_iommu;

int failures = 0;
int checks = 0;
void check(bool condition, const char* expression, int line) {
    ++checks;
    if (!condition) {
        ++failures;
        std::fprintf(stderr, "TopologyTests:%d: %s\n", line, expression);
    }
}
#define TOPO_CHECK(expr) check(static_cast<bool>(expr), #expr, __LINE__)

// Minimal builder: enough to express IVHD/IVMD blocks and device entries.
struct Fixture {
    std::array<std::uint8_t, 4096> bytes{};
    std::size_t size = kIvrsHeaderSize;

    Fixture() {
        bytes[0] = 'I'; bytes[1] = 'V'; bytes[2] = 'R'; bytes[3] = 'S';
        bytes[8] = 2;
        put32(36, 0x00203041);
        seal();
    }
    void put16(std::size_t pos, std::uint16_t v) {
        bytes[pos] = static_cast<std::uint8_t>(v);
        bytes[pos + 1] = static_cast<std::uint8_t>(v >> 8);
    }
    void put32(std::size_t pos, std::uint32_t v) {
        put16(pos, static_cast<std::uint16_t>(v));
        put16(pos + 2, static_cast<std::uint16_t>(v >> 16));
    }
    void put64(std::size_t pos, std::uint64_t v) {
        put32(pos, static_cast<std::uint32_t>(v));
        put32(pos + 4, static_cast<std::uint32_t>(v >> 32));
    }
    // Opens an IVHD block and returns its start offset. Device bytes follow via
    // push*(); close() fixes the length.
    std::size_t openIvhd(std::uint8_t type, std::uint16_t deviceId,
                         std::uint16_t segment, std::uint64_t base,
                         std::uint8_t flags = 0xB0,
                         std::uint64_t efr = 0) {
        const std::size_t fixed = type == 0x10 ? 24 : 40;
        const std::size_t pos = size;
        bytes[pos] = type;
        bytes[pos + 1] = flags;
        put16(pos + 4, deviceId);
        put16(pos + 6, 0x40);
        put64(pos + 8, base);
        put16(pos + 16, segment);
        put16(pos + 18, 0x0001);
        if (type == 0x10) {
            put32(pos + 20, 0x80048F2E);
        } else {
            put32(pos + 20, 0x00040200);
            put64(pos + 24, efr);
            put64(pos + 32, 0);
        }
        size = pos + fixed;
        return pos;
    }
    void close(std::size_t pos) {
        put16(pos + 2, static_cast<std::uint16_t>(size - pos));
        seal();
    }
    void push4(std::uint8_t type, std::uint16_t id, std::uint8_t data) {
        bytes[size] = type;
        put16(size + 1, id);
        bytes[size + 3] = data;
        size += 4;
    }
    void pushAlias(std::uint8_t type, std::uint16_t id, std::uint8_t data,
                   std::uint16_t used) {
        bytes[size] = type;
        put16(size + 1, id);
        bytes[size + 3] = data;
        bytes[size + 4] = 0;
        put16(size + 5, used);
        bytes[size + 7] = 0;
        size += 8;
    }
    void pushSpecial(std::uint16_t id, std::uint8_t data, std::uint8_t handle,
                     std::uint16_t used, std::uint8_t variety) {
        bytes[size] = 0x48;
        put16(size + 1, id);
        bytes[size + 3] = data;
        bytes[size + 4] = handle;
        put16(size + 5, used);
        bytes[size + 7] = variety;
        size += 8;
    }
    void pushExt(std::uint8_t type, std::uint16_t id, std::uint8_t data,
                 std::uint32_t extended) {
        bytes[size] = type;
        put16(size + 1, id);
        bytes[size + 3] = data;
        put32(size + 4, extended);
        size += 8;
    }
    void pushPad8(std::uint8_t type) {
        bytes[size] = type;
        for (int i = 1; i < 8; ++i) bytes[size + i] = 0;
        size += 8;
    }
    // HID entry: 22 fixed bytes plus a UID of `uidLength` characters.
    void pushHid(std::uint8_t uidLength) {
        bytes[size] = 0xF0;
        for (int i = 1; i < 22; ++i) bytes[size + i] = 0;
        bytes[size + 21] = uidLength;
        size += 22 + uidLength;
    }
    void seal() {
        put32(4, static_cast<std::uint32_t>(size));
        bytes[9] = 0;
        std::uint8_t sum = 0;
        for (std::size_t i = 0; i < size; ++i) sum = static_cast<std::uint8_t>(sum + bytes[i]);
        bytes[9] = static_cast<std::uint8_t>(0u - sum);
    }
};

TopologyError errorOf(const Fixture& f, IvhdUnitTable& units) {
    return buildTopology(f.bytes.data(), f.size, units).error;
}

void testSingleUnit() {
    Fixture f;
    const auto pos = f.openIvhd(0x10, 0x0002, 0, 0xFD380000);
    f.push4(0x03, 0x0008, 0x00);
    f.push4(0x04, 0xFFFE, 0x00);
    f.close(pos);
    IvhdUnitTable units{};
    const auto r = buildTopology(f.bytes.data(), f.size, units);
    TOPO_CHECK(r);
    TOPO_CHECK(r.unitCount == 1 && units.count == 1 && units.valid);
    TOPO_CHECK(units.units[0].deviceId == 0x0002);
    TOPO_CHECK(units.units[0].registerBase == 0xFD380000);
    TOPO_CHECK(units.units[0].blockCount == 1);
    TOPO_CHECK(units.units[0].hasFeatureReporting && !units.units[0].efrPresent);
    TOPO_CHECK(r.deviceRanges == 1 && r.duplicateBlockCount == 0);
}

void testDeduplication() {
    Fixture f;
    // The real board emits both forms for one unit, with identical device data.
    auto pos = f.openIvhd(0x10, 0x0002, 0, 0xFD380000);
    f.push4(0x03, 0x0008, 0x00);
    f.push4(0x04, 0xFFFE, 0x00);
    f.close(pos);
    pos = f.openIvhd(0x11, 0x0002, 0, 0xFD380000, 0xB0, 0x058F77EF22294A5AULL);
    f.push4(0x03, 0x0008, 0x00);
    f.push4(0x04, 0xFFFE, 0x00);
    f.close(pos);
    IvhdUnitTable units{};
    const auto r = buildTopology(f.bytes.data(), f.size, units);
    TOPO_CHECK(r);
    TOPO_CHECK(r.parse.ivhdCount == 2);
    TOPO_CHECK(r.unitCount == 1);
    TOPO_CHECK(r.duplicateBlockCount == 1);
    TOPO_CHECK(units.units[0].blockCount == 2);
    TOPO_CHECK(units.units[0].efrPresent);
    TOPO_CHECK(units.units[0].efrImage == 0x058F77EF22294A5AULL);
    TOPO_CHECK(units.units[0].hasAttributes);
    // Counters must reflect one unit's device table, not both descriptions.
    TOPO_CHECK(r.deviceRanges == 1);
    TOPO_CHECK(!units.units[0].conflictingDuplicates);
    TOPO_CHECK(!units.units[0].conflictingDeviceTables);

    // Distinct units must not be merged.
    Fixture g;
    pos = g.openIvhd(0x11, 0x0002, 0, 0xFD380000);
    g.close(pos);
    pos = g.openIvhd(0x11, 0x0003, 0, 0xFD390000);
    g.close(pos);
    IvhdUnitTable u2{};
    const auto r2 = buildTopology(g.bytes.data(), g.size, u2);
    TOPO_CHECK(r2 && r2.unitCount == 2 && r2.duplicateBlockCount == 0);

    // Same DeviceId on a different segment is a different unit.
    Fixture h;
    pos = h.openIvhd(0x11, 0x0002, 0, 0xFD380000);
    h.close(pos);
    pos = h.openIvhd(0x11, 0x0002, 1, 0xFD390000);
    h.close(pos);
    IvhdUnitTable u3{};
    const auto r3 = buildTopology(h.bytes.data(), h.size, u3);
    TOPO_CHECK(r3 && r3.unitCount == 2);
}

void testCrossFormFlags() {
    // AM5 / Phoenix firmware describes one IOMMU twice: the legacy 0x10 block
    // keeps flags 0xB0 while the extended 0x11 block reports 0x30. That single
    // differing bit is firmware bookkeeping, not a second register set, so the
    // table must still build and the requester must still resolve.
    Fixture f;
    auto pos = f.openIvhd(0x10, 0x0002, 0, 0xF7600000, 0xB0);
    f.push4(0x03, 0x0003, 0x00);
    f.push4(0x04, 0xFFFE, 0x00);
    f.close(pos);
    pos = f.openIvhd(0x11, 0x0002, 0, 0xF7600000, 0x30,
                     0x246577EFA2254AFAULL);
    f.push4(0x03, 0x0003, 0x00);
    f.push4(0x04, 0xFFFE, 0x00);
    f.close(pos);
    IvhdUnitTable units{};
    const auto r = buildTopology(f.bytes.data(), f.size, units);
    TOPO_CHECK(r);
    TOPO_CHECK(units.count == 1 && units.units[0].blockCount == 2);
    TOPO_CHECK(!units.units[0].conflictingDuplicates);
    TOPO_CHECK(units.units[0].flagsDifferAcrossForms);
    TOPO_CHECK(units.units[0].flags == 0x30); // extended form is authoritative
    TOPO_CHECK(units.units[0].hasLegacyFlags &&
               units.units[0].legacyFlags == 0xB0);
    TOPO_CHECK(units.units[0].efrPresent &&
               units.units[0].efrImage == 0x246577EFA2254AFAULL);
    const auto m = resolveRequester(units, 0, 0x0D, 0x00, 0x0);
    TOPO_CHECK(m.status == RequesterStatus::Resolved);
    TOPO_CHECK(m.dataSetting == 0x00 && !m.viaAlias);

    // AM4 AGESA keeps the flag byte equal in all three forms. Same verdict,
    // without the cross-form marker; a larger device table in the 0x40 block
    // (HID entries) stays informational.
    Fixture g;
    pos = g.openIvhd(0x10, 0x0002, 0, 0xFD500000, 0xB0);
    g.close(pos);
    pos = g.openIvhd(0x11, 0x0002, 0, 0xFD500000, 0xB0,
                     0x058F77EF22294A5AULL);
    g.close(pos);
    pos = g.openIvhd(0x40, 0x0002, 0, 0xFD500000, 0xB0,
                     0x058F77EF22294A5AULL);
    g.pushHid(0);
    g.close(pos);
    IvhdUnitTable u2{};
    const auto r2 = buildTopology(g.bytes.data(), g.size, u2);
    TOPO_CHECK(r2);
    TOPO_CHECK(u2.units[0].blockCount == 3);
    TOPO_CHECK(!u2.units[0].conflictingDuplicates);
    TOPO_CHECK(!u2.units[0].flagsDifferAcrossForms);
    TOPO_CHECK(u2.units[0].conflictingDeviceTables);
}

void testConflictingDuplicates() {
    Fixture f;
    auto pos = f.openIvhd(0x11, 0x0002, 0, 0xFD380000);
    f.close(pos);
    pos = f.openIvhd(0x11, 0x0002, 0, 0xFD390000); // different register base
    f.close(pos);
    IvhdUnitTable units{};
    const auto r = buildTopology(f.bytes.data(), f.size, units);
    TOPO_CHECK(r.error == TopologyError::ConflictingDuplicates);
    TOPO_CHECK(!r);
    TOPO_CHECK(units.count == 0 && !units.valid);

    // A different EFR image for the same unit is also a conflict.
    Fixture g;
    pos = g.openIvhd(0x11, 0x0002, 0, 0xFD380000, 0xB0, 0x1111);
    g.close(pos);
    pos = g.openIvhd(0x11, 0x0002, 0, 0xFD380000, 0xB0, 0x2222);
    g.close(pos);
    IvhdUnitTable u2{};
    TOPO_CHECK(errorOf(g, u2) == TopologyError::ConflictingDuplicates);

    // Two descriptions of the same form that disagree on flags are still a
    // conflict: only a cross-form difference is treated as bookkeeping.
    Fixture h;
    pos = h.openIvhd(0x11, 0x0002, 0, 0xFD380000, 0xB0, 0x1111);
    h.close(pos);
    pos = h.openIvhd(0x11, 0x0002, 0, 0xFD380000, 0x30, 0x1111);
    h.close(pos);
    IvhdUnitTable u3{};
    TOPO_CHECK(errorOf(h, u3) == TopologyError::ConflictingDuplicates);

    // 0x11 and 0x40 are both extended forms, so they belong to one class and
    // must agree.
    Fixture i;
    pos = i.openIvhd(0x11, 0x0002, 0, 0xFD380000, 0x30, 0x1111);
    i.close(pos);
    pos = i.openIvhd(0x40, 0x0002, 0, 0xFD380000, 0xB0, 0x1111);
    i.close(pos);
    IvhdUnitTable u4{};
    TOPO_CHECK(errorOf(i, u4) == TopologyError::ConflictingDuplicates);
}

void testNoUnits() {
    Fixture f;
    const auto pos = f.openIvhd(0x11, 0x0002, 0, 0xFD380000);
    f.close(pos);
    // A structurally valid table with only an unknown block has no unit.
    IvhdUnitTable units{};
    TOPO_CHECK(buildTopology(f.bytes.data(), f.size, units).unitCount == 1);

    Fixture g; // header only
    IvhdUnitTable u2{};
    const auto r = buildTopology(g.bytes.data(), g.size, u2);
    TOPO_CHECK(r.error == TopologyError::NoIvhdUnits);
    TOPO_CHECK(!r && u2.count == 0);

    // Invalid table surfaces the underlying error instead of topology errors.
    Fixture h;
    h.bytes[0] = 'X';
    h.seal();
    IvhdUnitTable u3{};
    const auto r3 = buildTopology(h.bytes.data(), h.size, u3);
    TOPO_CHECK(r3.error == TopologyError::TableInvalid);
    TOPO_CHECK(r3.ivrsError == IvrsError::BadSignature);
}

void testRangeValidation() {
    // End without start.
    {
        Fixture f;
        const auto pos = f.openIvhd(0x11, 0x0002, 0, 0x1000);
        f.push4(0x04, 0x00FF, 0);
        f.close(pos);
        IvhdUnitTable units{};
        TOPO_CHECK(errorOf(f, units) == TopologyError::EndWithoutStart);
        TOPO_CHECK(units.count == 0);
    }
    // Reversed range.
    {
        Fixture f;
        const auto pos = f.openIvhd(0x11, 0x0002, 0, 0x1000);
        f.push4(0x03, 0x0200, 0);
        f.push4(0x04, 0x0100, 0);
        f.close(pos);
        IvhdUnitTable units{};
        TOPO_CHECK(errorOf(f, units) == TopologyError::ReversedRange);
    }
    // Nested range.
    {
        Fixture f;
        const auto pos = f.openIvhd(0x11, 0x0002, 0, 0x1000);
        f.push4(0x03, 0x0008, 0);
        f.push4(0x03, 0x0100, 0);
        f.push4(0x04, 0x0200, 0);
        f.close(pos);
        IvhdUnitTable units{};
        TOPO_CHECK(errorOf(f, units) == TopologyError::NestedRange);
    }
    // Unterminated range at block end.
    {
        Fixture f;
        const auto pos = f.openIvhd(0x11, 0x0002, 0, 0x1000);
        f.push4(0x03, 0x0008, 0);
        f.close(pos);
        IvhdUnitTable units{};
        TOPO_CHECK(errorOf(f, units) == TopologyError::UnterminatedRange);
    }
    // A single-entry range is legal (start == end).
    {
        Fixture f;
        const auto pos = f.openIvhd(0x11, 0x0002, 0, 0x1000);
        f.push4(0x03, 0x0040, 0);
        f.push4(0x04, 0x0040, 0);
        f.close(pos);
        IvhdUnitTable units{};
        TOPO_CHECK(buildTopology(f.bytes.data(), f.size, units));
        const auto m = resolveRequester(units, 0, 0x00, 0x08, 0);
        TOPO_CHECK(m.status == RequesterStatus::Resolved);
    }
}

void testRequesterResolution() {
    Fixture f;
    const auto pos = f.openIvhd(0x11, 0x0002, 0, 0xFD380000);
    f.push4(0x03, 0x0008, 0x00);
    f.push4(0x04, 0xFFFE, 0x00);
    f.close(pos);
    IvhdUnitTable units{};
    TOPO_CHECK(buildTopology(f.bytes.data(), f.size, units));

    auto m = resolveRequester(units, 0, 0x00, 0x01, 0x0);
    TOPO_CHECK(m.status == RequesterStatus::Resolved);
    TOPO_CHECK(m.deviceId == 0x0008);
    TOPO_CHECK(m.unitIndex == 0);
    TOPO_CHECK(!m.viaAlias && !m.wasAllDevices);

    // The declared range is 0x0008..0xFFFE, an inclusive id range, so it covers
    // every function of every device: 00:01.1 (0x0009) must resolve, not miss.
    m = resolveRequester(units, 0, 0x00, 0x01, 0x1);
    TOPO_CHECK(m.status == RequesterStatus::Resolved);
    TOPO_CHECK(m.deviceId == 0x0009);
    // Below the range start: 00:00.7 encodes as 0x0007.
    m = resolveRequester(units, 0, 0x00, 0x00, 0x7);
    TOPO_CHECK(m.status == RequesterStatus::NotCovered);
    // Above the range end: FF:1F.7 encodes as 0xFFFF.
    m = resolveRequester(units, 0, 0xFF, 0x1F, 0x7);
    TOPO_CHECK(m.status == RequesterStatus::NotCovered);

    // Unknown segment.
    m = resolveRequester(units, 1, 0x00, 0x01, 0);
    TOPO_CHECK(m.status == RequesterStatus::NoUnitForSegment);

    // Invalid BDF is rejected, not masked into a neighbour.
    m = resolveRequester(units, 0, 0x00, 0x20, 0x0);
    TOPO_CHECK(m.status == RequesterStatus::InvalidBdf);
    m = resolveRequester(units, 0, 0x00, 0x01, 0x8);
    TOPO_CHECK(m.status == RequesterStatus::InvalidBdf);

    std::uint16_t id = 0;
    TOPO_CHECK(encodeRequesterId(0x00, 0x01, 0x0, id) && id == 0x0008);
    TOPO_CHECK(encodeRequesterId(0xFF, 0x1F, 0x7, id) && id == 0xFFFF);
    TOPO_CHECK(!encodeRequesterId(0x00, 0x20, 0x0, id));
    TOPO_CHECK(!encodeRequesterId(0x00, 0x00, 0x8, id));

    // An unbuilt table is not silently treated as empty-but-valid.
    IvhdUnitTable empty{};
    m = resolveRequester(empty, 0, 0x00, 0x01, 0);
    TOPO_CHECK(m.status == RequesterStatus::InvalidTopology);
}

void testAliasAndPrecedence() {
    // Real-board shape: broad plain range plus an alias range on top.
    Fixture f;
    const auto pos = f.openIvhd(0x11, 0x0002, 0, 0xFD380000);
    f.push4(0x03, 0x0008, 0x00);
    f.push4(0x04, 0xFFFE, 0x00);
    f.pushAlias(0x43, 0xFF00, 0x00, 0x00A5);
    f.push4(0x04, 0xFFFF, 0x00);
    f.close(pos);
    IvhdUnitTable units{};
    const auto r = buildTopology(f.bytes.data(), f.size, units);
    TOPO_CHECK(r);
    TOPO_CHECK(r.aliasEntries == 1);
    TOPO_CHECK(r.deviceRanges == 2);

    // Inside the alias range: alias wins and redirects to the source-used id.
    auto m = resolveRequester(units, 0, 0xFF, 0x00, 0x0);
    TOPO_CHECK(m.status == RequesterStatus::Resolved);
    TOPO_CHECK(m.viaAlias);
    TOPO_CHECK(m.resolvedDeviceId == 0x00A5);
    TOPO_CHECK(m.shadowedPlainRange);

    // Outside the alias range: the plain range applies.
    m = resolveRequester(units, 0, 0x10, 0x00, 0x0);
    TOPO_CHECK(m.status == RequesterStatus::Resolved);
    TOPO_CHECK(!m.viaAlias);
    TOPO_CHECK(m.resolvedDeviceId == 0x1000);

    // Alias select form behaves like the alias range.
    Fixture g;
    auto p2 = g.openIvhd(0x11, 0x0002, 0, 0x1000);
    g.pushAlias(0x42, 0x0100, 0x05, 0x0200);
    g.close(p2);
    IvhdUnitTable u2{};
    TOPO_CHECK(buildTopology(g.bytes.data(), g.size, u2));
    auto m2 = resolveRequester(u2, 0, 0x01, 0x00, 0x0);
    TOPO_CHECK(m2.status == RequesterStatus::Resolved);
    TOPO_CHECK(m2.viaAlias && m2.resolvedDeviceId == 0x0200);
    TOPO_CHECK(m2.dataSetting == 0x05);

    // "All devices" applies only where nothing more specific claims the id.
    Fixture h;
    auto p3 = h.openIvhd(0x11, 0x0002, 0, 0x1000);
    h.push4(0x01, 0x0000, 0x07);
    h.push4(0x03, 0x0010, 0x00);
    h.push4(0x04, 0x001F, 0x00);
    h.close(p3);
    IvhdUnitTable u3{};
    TOPO_CHECK(buildTopology(h.bytes.data(), h.size, u3));
    auto m3 = resolveRequester(u3, 0, 0x00, 0x03, 0x0); // 0x0018, in range
    TOPO_CHECK(m3.status == RequesterStatus::Resolved);
    TOPO_CHECK(!m3.wasAllDevices && m3.dataSetting == 0x00);
    m3 = resolveRequester(u3, 0, 0x00, 0x00, 0x0); // 0x0000, outside range
    TOPO_CHECK(m3.status == RequesterStatus::Resolved);
    TOPO_CHECK(m3.wasAllDevices && m3.dataSetting == 0x07);
}

void testSpecialAndExtended() {
    // IOAPIC special device: identified by its SOURCE-USED id, not by the entry's
    // own Id field. On this board all three special entries carry Id 0x0000 while
    // naming 0x00A0/0x00A0/0x0001, so treating Id 0x0000 as a wildcard would
    // wrongly report the root complex 00:00.0 as an interrupt controller.
    Fixture f;
    const auto pos = f.openIvhd(0x11, 0x0002, 0, 0x1000);
    f.pushSpecial(0x0000, 0xD7, 0x0D, 0x00A0, 0x01);
    f.close(pos);
    IvhdUnitTable units{};
    TOPO_CHECK(buildTopology(f.bytes.data(), f.size, units));
    // The source-used id 0x00A0 is 00:14.0, an IOAPIC per the firmware.
    auto m = resolveRequester(units, 0, 0x00, 0x14, 0x0);
    TOPO_CHECK(m.status == RequesterStatus::SpecialNotPci);
    TOPO_CHECK(m.isSpecialDevice && m.specialVariety == 0x01);
    // The entry's own Id 0x0000 is NOT special: 00:00.0 is a real PCI device.
    m = resolveRequester(units, 0, 0x00, 0x00, 0x0);
    TOPO_CHECK(m.status != RequesterStatus::SpecialNotPci);
    TOPO_CHECK(m.status == RequesterStatus::NotCovered);

    // Extended select with ATS disabled.
    Fixture g;
    const auto p2 = g.openIvhd(0x11, 0x0002, 0, 0x1000);
    g.pushExt(0x46, 0x0010, 0x03, 0x80000000u);
    g.close(p2);
    IvhdUnitTable u2{};
    TOPO_CHECK(buildTopology(g.bytes.data(), g.size, u2));
    auto m2 = resolveRequester(u2, 0, 0x00, 0x02, 0x0);
    TOPO_CHECK(m2.status == RequesterStatus::Resolved);
    TOPO_CHECK(m2.viaExtended && m2.atsDisabled && m2.dataSetting == 0x03);

    // Extended select with ATS enabled.
    Fixture h;
    const auto p3 = h.openIvhd(0x11, 0x0002, 0, 0x1000);
    h.pushExt(0x46, 0x0010, 0x00, 0x00000000u);
    h.close(p3);
    IvhdUnitTable u3{};
    TOPO_CHECK(buildTopology(h.bytes.data(), h.size, u3));
    auto m3 = resolveRequester(u3, 0, 0x00, 0x02, 0x0);
    TOPO_CHECK(m3.viaExtended && !m3.atsDisabled);

    // Extended range start with ATS disabled.
    Fixture i;
    const auto p4 = i.openIvhd(0x11, 0x0002, 0, 0x1000);
    i.pushExt(0x47, 0x0020, 0x01, 0x80000000u);
    i.push4(0x04, 0x002F, 0x00);
    i.close(p4);
    IvhdUnitTable u4{};
    TOPO_CHECK(buildTopology(i.bytes.data(), i.size, u4));
    auto m4 = resolveRequester(u4, 0, 0x00, 0x04, 0x0);
    TOPO_CHECK(m4.status == RequesterStatus::Resolved);
    TOPO_CHECK(m4.viaExtended && m4.atsDisabled);
}

void testPaddedAndHid() {
    Fixture f;
    const auto pos = f.openIvhd(0x11, 0x0002, 0, 0x1000);
    f.push4(0x00, 0x0000, 0);
    f.pushPad8(0x40);
    f.pushPad8(0x41);
    f.push4(0x03, 0x0010, 0);
    f.push4(0x04, 0x001F, 0);
    f.close(pos);
    IvhdUnitTable units{};
    const auto r = buildTopology(f.bytes.data(), f.size, units);
    TOPO_CHECK(r);
    TOPO_CHECK(r.paddedEntries == 3);
    auto m = resolveRequester(units, 0, 0x00, 0x02, 0x0);
    TOPO_CHECK(m.status == RequesterStatus::Resolved);
}

void testCapacityLimits() {
    // More distinct units than the fixed table can hold must be rejected, not
    // truncated: a partial inventory would look complete.
    Fixture f;
    for (int i = 0; i < static_cast<int>(kMaxIvhdUnits) + 1; ++i) {
        const auto pos = f.openIvhd(0x11, static_cast<std::uint16_t>(0x0100 + i),
                                    0, 0x1000 + static_cast<std::uint64_t>(i) * 0x1000);
        f.close(pos);
    }
    IvhdUnitTable units{};
    const auto r = buildTopology(f.bytes.data(), f.size, units);
    TOPO_CHECK(r.error == TopologyError::TooManyUnits);
    TOPO_CHECK(units.count == 0 && !units.valid);

    // Exactly the limit is accepted.
    Fixture g;
    for (int i = 0; i < static_cast<int>(kMaxIvhdUnits); ++i) {
        const auto pos = g.openIvhd(0x11, static_cast<std::uint16_t>(0x0100 + i),
                                    0, 0x1000 + static_cast<std::uint64_t>(i) * 0x1000);
        g.close(pos);
    }
    IvhdUnitTable u2{};
    const auto r2 = buildTopology(g.bytes.data(), g.size, u2);
    TOPO_CHECK(r2 && r2.unitCount == kMaxIvhdUnits);

    // Too many descriptions of one unit.
    Fixture h;
    for (std::size_t i = 0; i < kMaxBlocksPerUnit + 1; ++i) {
        const auto pos = h.openIvhd(0x11, 0x0002, 0, 0xFD380000);
        h.close(pos);
    }
    IvhdUnitTable u3{};
    TOPO_CHECK(buildTopology(h.bytes.data(), h.size, u3).error ==
               TopologyError::TooManyUnitBlocks);
}

void testIommuUnitAsRequester() {
    // The declared range on this board starts at 0x0008, so 00:00.x is NOT
    // covered -- including the IOMMU's own function 00:00.2 (id 0x0002). This is
    // a real property of the captured table, not an assumption: a driver must
    // not expect the IOMMU's own requester id to appear in its device table.
    Fixture f;
    const auto pos = f.openIvhd(0x11, 0x0002, 0, 0xFD380000);
    f.push4(0x03, 0x0008, 0x00);
    f.push4(0x04, 0xFFFE, 0x00);
    f.close(pos);
    IvhdUnitTable units{};
    TOPO_CHECK(buildTopology(f.bytes.data(), f.size, units));
    const auto m = resolveRequester(units, 0, 0x00, 0x00, 0x2);
    TOPO_CHECK(m.status == RequesterStatus::NotCovered);
    TOPO_CHECK(m.deviceId == 0x0002);
    TOPO_CHECK(m.pciSegment == 0);
    // The very first covered requester is 00:01.0 (0x0008).
    const auto first = resolveRequester(units, 0, 0x00, 0x01, 0x0);
    TOPO_CHECK(first.status == RequesterStatus::Resolved);
}

} // namespace

int runTopologyTests() {
    failures = 0;
    checks = 0;
    testSingleUnit();
    testDeduplication();
    testCrossFormFlags();
    testConflictingDuplicates();
    testNoUnits();
    testRangeValidation();
    testRequesterResolution();
    testAliasAndPrecedence();
    testSpecialAndExtended();
    testPaddedAndHid();
    testCapacityLimits();
    testIommuUnitAsRequester();
    std::printf("Topology tests: %d checks, %d failures\n", checks, failures);
    return failures;
}

#ifdef AMD_IOMMU_TOPOLOGY_TEST_MAIN
int main() { return runTopologyTests() ? 1 : 0; }
#endif
