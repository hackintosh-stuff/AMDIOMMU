#pragma once

#include "amd_iommu/Ivrs.hpp"
#include <cstddef>
#include <cstdint>

namespace amd_iommu {

// Bounded, allocation-free topology layer built on top of parseIvrs().
//
// It answers two questions the structural parser deliberately does not:
//   1. Which *distinct* IOMMU units does this table describe?  (deduplication)
//   2. Which unit and data setting owns a given PCI requester?  (attribution)
//
// Nothing here touches hardware. A "resolved" requester is a firmware claim
// about routing, not proof that a DTE exists or that translation is enabled.

// Fixed capacities keep the layer allocation-free. A table that needs more is
// rejected rather than silently truncated: programming a partial inventory of
// IOMMUs, or dropping one description of a unit, would leave real hardware
// unconfigured while appearing handled.
constexpr std::size_t kMaxIvhdUnits = 16;
constexpr std::size_t kMaxBlocksPerUnit = 4;

// One IVHD subtable. A single unit may be described more than once; real AMD
// firmware on this board emits both a type 0x10 and a type 0x11 block for one
// IOMMU. All descriptions are kept because their device entries form one
// device table in wire order.
struct IvhdBlockRef {
    const std::uint8_t* bytes = nullptr; // Borrowed from the caller's buffer.
    std::size_t offset = 0;              // Relative to table start.
    std::uint16_t length = 0;
    std::size_t fixedSize = 0;           // 24 for 0x10, 40 for 0x11/0x40.
    std::uint8_t type = 0;
};

struct IvhdUnit {
    // Fields whose meaning is identical in every IVHD form.
    std::uint8_t flags = 0;
    std::uint16_t deviceId = 0;
    std::uint16_t pciSegment = 0;
    std::uint16_t capabilityOffset = 0;
    std::uint16_t iommuInfo = 0;
    std::uint64_t registerBase = 0;

    // Offset 20 means different things per block type, so they are kept apart
    // rather than merged into one ambiguous field.
    std::uint32_t featureReporting = 0; // Type 0x10 only.
    bool hasFeatureReporting = false;
    std::uint32_t attributes = 0; // Types 0x11 / 0x40 only.
    bool hasAttributes = false;
    std::uint64_t efrImage = 0; // Types 0x11 / 0x40 only.
    bool efrPresent = false;

    IvhdBlockRef blocks[kMaxBlocksPerUnit]{};
    std::size_t blockCount = 0; // 1 for a single description, more if duplicated.

    // Set when a duplicate description disagrees on a field that has the same
    // meaning in both. Conflicting firmware must not be silently merged.
    bool conflictingDuplicates = false;
    std::size_t conflictBlockOffset = 0;

    // Set when duplicate descriptions carry different device-entry regions.
    // Identical duplication (as on this board) leaves this false.
    bool conflictingDeviceTables = false;
};

struct IvhdUnitTable {
    IvhdUnit units[kMaxIvhdUnits]{};
    std::size_t count = 0;
    bool valid = false; // Only buildTopology() sets this on success.
};

enum class TopologyError {
    None,
    TableInvalid,          // parseIvrs() rejected the table.
    NoIvhdUnits,           // Structurally valid but describes no IOMMU.
    TooManyUnits,          // Exceeds kMaxIvhdUnits.
    TooManyUnitBlocks,     // One unit described more often than kMaxBlocksPerUnit.
    ConflictingDuplicates, // Same (segment, deviceId) described inconsistently.
    NestedRange,           // A range started while another was still open.
    EndWithoutStart,       // Range end with no open range.
    ReversedRange,         // Range end precedes its start.
    UnterminatedRange,     // Block ended with a range still open.
    UnsupportedEntry,      // Device entry framing not decodable.
    UnpairedEntry          // Select/range start that cannot be interpreted.
};

struct IvrsTopologyResult {
    TopologyError error = TopologyError::None;
    std::size_t errorOffset = 0;
    IvrsError ivrsError = IvrsError::None; // Set when error == TableInvalid.
    IvrsParseResult parse{};               // Counts from the structural pass.

    std::size_t unitCount = 0;
    std::size_t duplicateBlockCount = 0;
    std::size_t deviceRanges = 0;   // Closed ranges (plain, alias and extended).
    std::size_t deviceSingles = 0;  // Select, alias-select and extended-select.
    std::size_t aliasEntries = 0;   // Alias select plus alias range starts.
    std::size_t allEntries = 0;     // "All devices" entries.
    std::size_t specialEntries = 0; // IOAPIC/HPET special devices.
    std::size_t hidEntries = 0;     // ACPI HID (_HID-named) devices.
    std::size_t paddedEntries = 0;  // PAD4/PAD8/not-used entries.

    explicit operator bool() const noexcept { return error == TopologyError::None; }
};

// Validates the table structurally, then validates every IVHD device table
// semantically (range nesting, ordering, termination) and fills `units` with one
// entry per distinct IOMMU. On failure `units` is left invalid and must not be
// used.
IvrsTopologyResult buildTopology(const std::uint8_t* bytes, std::size_t size,
                                 IvhdUnitTable& units) noexcept;

enum class RequesterStatus {
    Resolved,         // Exactly one unit claims this requester.
    NotCovered,       // A unit exists for the segment but no entry claims it.
    NoUnitForSegment, // No IVHD unit is described for this PCI segment.
    Ambiguous,        // Two or more distinct claims that cannot be reconciled.
    SpecialNotPci,    // The id names an IOAPIC/HPET, not a PCI requester.
    InvalidBdf,       // Device > 31 or function > 7.
    InvalidTopology   // `units` was not produced by buildTopology().
};

struct RequesterResolution {
    RequesterStatus status = RequesterStatus::InvalidTopology;
    std::uint16_t pciSegment = 0;
    std::uint16_t deviceId = 0;         // Id derived from the request.
    std::uint16_t resolvedDeviceId = 0; // After alias substitution.
    std::size_t unitIndex = 0;          // Index into IvhdUnitTable.
    std::uint8_t dataSetting = 0;       // Data setting of the claiming entry.
    bool viaAlias = false;
    bool viaExtended = false;
    bool atsDisabled = false;           // Meaningful only when viaExtended.
    bool wasAllDevices = false;         // Matched an "all devices" entry.
    bool shadowedPlainRange = false;    // An alias won over a plain match.
    bool isSpecialDevice = false;       // Set for SpecialNotPci.
    std::uint8_t specialVariety = 0;    // 1 = IOAPIC, 2 = HPET.
    std::size_t matchEntryOffset = 0;   // Relative to table start.

    explicit operator bool() const noexcept { return status == RequesterStatus::Resolved; }
};

// PCI requester -> owning unit. Out-of-range device/function values are
// rejected rather than masked, so a caller cannot silently query a neighbour.
RequesterResolution resolveRequester(const IvhdUnitTable& units,
                                     std::uint16_t pciSegment, std::uint8_t bus,
                                     std::uint8_t device,
                                     std::uint8_t function) noexcept;

// Same, for an already-encoded IVRS device id (bus<<8 | dev<<3 | func).
RequesterResolution resolveRequesterDeviceId(const IvhdUnitTable& units,
                                             std::uint16_t pciSegment,
                                             std::uint16_t deviceId) noexcept;

// IVRS device id encoding helper. Returns false for an unrepresentable BDF.
bool encodeRequesterId(std::uint8_t bus, std::uint8_t device,
                       std::uint8_t function, std::uint16_t& deviceId) noexcept;

const char* topologyErrorString(TopologyError error) noexcept;
const char* requesterStatusString(RequesterStatus status) noexcept;

// Precedence used when more than one entry matches one requester. Documented
// interpretation, not a quotation of the AMD specification: "all devices" is a
// catch-all and loses to any specific entry; an alias range exists precisely to
// redirect ids inside it, so it wins over a plain range that also covers them.
// Extended (0x46/0x47) and plain matches are treated as equal rank, so an
// unshadowed tie is reported as Ambiguous rather than guessed.
const char* requesterPrecedenceNote() noexcept;

} // namespace amd_iommu
