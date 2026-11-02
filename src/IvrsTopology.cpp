#include "amd_iommu/IvrsTopology.hpp"

#include <cstring>

namespace amd_iommu {
namespace {

std::uint16_t le16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(p[0] | (std::uint16_t{p[1]} << 8));
}
std::uint32_t le32(const std::uint8_t* p) noexcept {
    return std::uint32_t{le16(p)} | (std::uint32_t{le16(p + 2)} << 16);
}

// Device entry types, per the ACPI/ACPICA IVRS definitions.
constexpr std::uint8_t kPad4 = 0x00;
constexpr std::uint8_t kAll = 0x01;
constexpr std::uint8_t kSelect = 0x02;
constexpr std::uint8_t kStart = 0x03;
constexpr std::uint8_t kEnd = 0x04;
constexpr std::uint8_t kPad8 = 0x40;
constexpr std::uint8_t kNotUsed = 0x41;
constexpr std::uint8_t kAliasSelect = 0x42;
constexpr std::uint8_t kAliasStart = 0x43;
constexpr std::uint8_t kExtSelect = 0x46;
constexpr std::uint8_t kExtStart = 0x47;
constexpr std::uint8_t kSpecial = 0x48;
constexpr std::uint8_t kHid = 0xF0;

constexpr std::uint32_t kAtsDisabled = 1u << 31;

// Match precedence. "All devices" is a catch-all and must never override a more
// specific claim; an alias range exists to redirect ids inside it, so it
// outranks a plain entry covering the same id.
constexpr int kRankNone = 0;
constexpr int kRankAll = 1;
constexpr int kRankPlain = 2;
constexpr int kRankAlias = 3;

struct Match {
    int rank = kRankNone;
    bool found = false;
    bool conflict = false; // Equal-rank claims disagree.
    std::uint16_t resolved = 0;
    std::uint8_t dataSetting = 0;
    bool viaAlias = false;
    bool viaExtended = false;
    bool atsDisabled = false;
    bool wasAll = false;
    std::size_t entryOffset = 0;
};

struct ScanOutcome {
    Match best;    // Highest-ranked claim.
    Match plain;   // Highest-ranked non-alias claim, for shadow reporting.
    bool special = false;
    std::uint8_t specialVariety = 0;
};

void record(Match& m, int rank, std::uint16_t resolved, std::uint8_t dataSetting,
            std::size_t entryOffset, bool viaAlias, bool viaExtended,
            bool atsDisabled, bool wasAll) noexcept {
    if (rank > m.rank) {
        m.rank = rank;
        m.found = true;
        m.conflict = false;
        m.resolved = resolved;
        m.dataSetting = dataSetting;
        m.entryOffset = entryOffset;
        m.viaAlias = viaAlias;
        m.viaExtended = viaExtended;
        m.atsDisabled = atsDisabled;
        m.wasAll = wasAll;
        return;
    }
    if (rank < m.rank || !m.found) {
        return;
    }
    // Equal rank: an identical claim is a duplicate description, not a conflict.
    if (resolved != m.resolved || dataSetting != m.dataSetting ||
        viaAlias != m.viaAlias || wasAll != m.wasAll) {
        m.conflict = true;
    }
}

// Evaluates one IVHD block's device table against `requester`. The block has
// already been validated, so every entry here is in bounds.
void scanBlock(const IvhdBlockRef& block, std::uint16_t requester,
               ScanOutcome& out) noexcept {
    const std::uint8_t* p = block.bytes;
    std::size_t relative = block.fixedSize;
    bool rangeOpen = false;
    std::uint16_t rangeStart = 0;
    std::uint8_t rangeDataSetting = 0;
    int rangeRank = kRankPlain;
    bool rangeExtended = false;
    std::uint16_t rangeUsedId = 0;
    bool rangeAtsDisabled = false;

    while (relative < block.length) {
        const std::uint8_t* entry = p + relative;
        const std::uint8_t type = entry[0];
        if (type == kHid) {
            // HID entries name non-PCI devices by _HID/_CID and never claim a
            // PCI requester id.
            relative += 22 + static_cast<std::size_t>(entry[21]);
            continue;
        }
        const std::size_t entrySize = type < 0x40 ? 4 : 8;
        const std::uint16_t id = le16(entry + 1);
        const std::uint8_t dataSetting = entry[3];
        const std::size_t absoluteOffset = block.offset + relative;

        switch (type) {
        case kAll:
            record(out.best, kRankAll, requester, dataSetting, absoluteOffset,
                   false, false, false, true);
            record(out.plain, kRankAll, requester, dataSetting, absoluteOffset,
                   false, false, false, true);
            break;
        case kSelect:
            if (id == requester) {
                record(out.best, kRankPlain, requester, dataSetting,
                       absoluteOffset, false, false, false, false);
                record(out.plain, kRankPlain, requester, dataSetting,
                       absoluteOffset, false, false, false, false);
            }
            break;
        case kStart:
            rangeOpen = true;
            rangeStart = id;
            rangeDataSetting = dataSetting;
            rangeRank = kRankPlain;
            rangeExtended = false;
            rangeUsedId = 0;
            rangeAtsDisabled = false;
            break;
        case kAliasStart:
            rangeOpen = true;
            rangeStart = id;
            rangeDataSetting = dataSetting;
            rangeRank = kRankAlias;
            rangeExtended = false;
            rangeUsedId = le16(entry + 5);
            rangeAtsDisabled = false;
            break;
        case kExtStart:
            rangeOpen = true;
            rangeStart = id;
            rangeDataSetting = dataSetting;
            rangeRank = kRankPlain;
            rangeExtended = true;
            rangeUsedId = 0;
            rangeAtsDisabled = (le32(entry + 4) & kAtsDisabled) != 0;
            break;
        case kEnd:
            if (rangeOpen && requester >= rangeStart && requester <= id) {
                if (rangeRank == kRankAlias) {
                    // An alias range redirects to the source-used device, so the
                    // data setting of that device applies across the range.
                    record(out.best, kRankAlias, rangeUsedId, rangeDataSetting,
                           absoluteOffset, true, false, false, false);
                } else {
                    record(out.best, rangeRank, requester, rangeDataSetting,
                           absoluteOffset, false, rangeExtended, rangeAtsDisabled,
                           false);
                    record(out.plain, rangeRank, requester, rangeDataSetting,
                           absoluteOffset, false, rangeExtended, rangeAtsDisabled,
                           false);
                }
            }
            rangeOpen = false;
            break;
        case kAliasSelect:
            if (id == requester) {
                record(out.best, kRankAlias, le16(entry + 5), dataSetting,
                       absoluteOffset, true, false, false, false);
            }
            break;
        case kExtSelect:
            if (id == requester) {
                const bool ats = (le32(entry + 4) & kAtsDisabled) != 0;
                record(out.best, kRankPlain, requester, dataSetting,
                       absoluteOffset, false, true, ats, false);
                record(out.plain, kRankPlain, requester, dataSetting,
                       absoluteOffset, false, true, ats, false);
            }
            break;
        case kSpecial:
            // A special entry names an IOAPIC/HPET by its *source-used id*; the
            // entry's own Id field is 0 on this board and must not be treated as
            // a wildcard, which would mask real PCI devices such as 00:00.0.
            if (le16(entry + 5) == requester) {
                out.special = true;
                out.specialVariety = entry[7];
            }
            break;
        case kPad4:
        case kPad8:
        case kNotUsed:
        default:
            break;
        }
        relative += entrySize;
    }
}

// Validates one block's device table. `counts` may be null for duplicate
// descriptions of a unit that was already counted from its first block.
TopologyError validateBlock(const IvhdBlockRef& block, IvrsTopologyResult* counts,
                            std::size_t& errorOffset) noexcept {
    const std::uint8_t* p = block.bytes;
    std::size_t relative = block.fixedSize;
    bool rangeOpen = false;
    std::uint16_t rangeStart = 0;
    std::size_t rangeStartOffset = 0;

    while (relative < block.length) {
        const std::uint8_t* entry = p + relative;
        const std::uint8_t type = entry[0];
        if (type == kHid) {
            if (block.length - relative < 22) {
                errorOffset = block.offset + relative;
                return TopologyError::UnsupportedEntry;
            }
            const std::size_t entrySize = 22 + static_cast<std::size_t>(entry[21]);
            if (block.length - relative < entrySize) {
                errorOffset = block.offset + relative;
                return TopologyError::UnsupportedEntry;
            }
            if (counts) ++counts->hidEntries;
            relative += entrySize;
            continue;
        }
        const std::size_t entrySize = type < 0x40 ? 4 : 8;
        if (block.length - relative < entrySize) {
            errorOffset = block.offset + relative;
            return TopologyError::UnsupportedEntry;
        }
        const std::uint16_t id = le16(entry + 1);
        switch (type) {
        case kAll:
            if (counts) ++counts->allEntries;
            break;
        case kSelect:
        case kExtSelect:
            if (counts) ++counts->deviceSingles;
            break;
        case kAliasSelect:
            if (counts) {
                ++counts->deviceSingles;
                ++counts->aliasEntries;
            }
            break;
        case kStart:
        case kExtStart:
        case kAliasStart:
            if (rangeOpen) {
                errorOffset = block.offset + relative;
                return TopologyError::NestedRange;
            }
            rangeOpen = true;
            rangeStart = id;
            rangeStartOffset = block.offset + relative;
            if (type == kAliasStart && counts) {
                ++counts->aliasEntries;
            }
            break;
        case kEnd:
            if (!rangeOpen) {
                errorOffset = block.offset + relative;
                return TopologyError::EndWithoutStart;
            }
            if (id < rangeStart) {
                errorOffset = block.offset + relative;
                return TopologyError::ReversedRange;
            }
            rangeOpen = false;
            if (counts) ++counts->deviceRanges;
            break;
        case kSpecial:
            if (counts) ++counts->specialEntries;
            break;
        case kPad4:
        case kPad8:
        case kNotUsed:
            if (counts) ++counts->paddedEntries;
            break;
        default:
            errorOffset = block.offset + relative;
            return TopologyError::UnsupportedEntry;
        }
        relative += entrySize;
    }
    if (rangeOpen) {
        errorOffset = rangeStartOffset;
        return TopologyError::UnterminatedRange;
    }
    return TopologyError::None;
}

struct CollectContext {
    IvhdUnitTable* units = nullptr;
    IvrsTopologyResult* result = nullptr;
    TopologyError error = TopologyError::None;
    std::size_t errorOffset = 0;
};

bool onBlock(void* context, const IvrsBlockView& block) {
    auto& c = *static_cast<CollectContext*>(context);
    if (block.kind != IvrsBlockKind::Ivhd) {
        return true;
    }
    // Deduplicate by (PCI segment, DeviceId): firmware may describe one unit
    // more than once, as this board does with a 0x10 and a 0x11 block.
    for (std::size_t i = 0; i < c.units->count; ++i) {
        IvhdUnit& unit = c.units->units[i];
        if (unit.pciSegment != block.pciSegment ||
            unit.deviceId != block.deviceId) {
            continue;
        }
        if (unit.blockCount >= kMaxBlocksPerUnit) {
            c.error = TopologyError::TooManyUnitBlocks;
            c.errorOffset = block.offset;
            return false;
        }
        const IvhdBlockRef ref{block.bytes, block.offset, block.length,
                               block.fixedSize, block.type};
        // Only compare fields whose meaning is identical across block forms.
        const bool sameCore =
            unit.flags == block.flags &&
            unit.capabilityOffset == block.capabilityOffset &&
            unit.iommuInfo == block.iommuInfo &&
            unit.registerBase == block.registerBase;
        bool sameEfr = true;
        if (block.type != 0x10 && unit.efrPresent) {
            sameEfr = unit.efrImage == block.efrImage;
        }
        if (!sameCore || !sameEfr) {
            if (!unit.conflictingDuplicates) {
                unit.conflictingDuplicates = true;
                unit.conflictBlockOffset = block.offset;
            }
        }
        // A difference in the device-entry region between two descriptions of
        // one unit is surfaced, not merged. Type 0x10 and 0x11 blocks may
        // legitimately carry different amounts of data here.
        const IvhdBlockRef& first = unit.blocks[0];
        const std::size_t firstLen = first.length - first.fixedSize;
        const std::size_t thisLen = block.length - block.fixedSize;
        if (firstLen != thisLen ||
            std::memcmp(first.bytes + first.fixedSize, block.bytes + block.fixedSize,
                        firstLen) != 0) {
            unit.conflictingDeviceTables = true;
        }
        unit.blocks[unit.blockCount++] = ref;
        ++c.result->duplicateBlockCount;
        if (block.type != 0x10 && !unit.efrPresent) {
            unit.efrImage = block.efrImage;
            unit.efrPresent = true;
        }
        if (block.type != 0x10 && !unit.hasAttributes) {
            unit.attributes = block.featureReportingOrAttributes;
            unit.hasAttributes = true;
        }
        return true;
    }
    if (c.units->count >= kMaxIvhdUnits) {
        c.error = TopologyError::TooManyUnits;
        c.errorOffset = block.offset;
        return false;
    }
    IvhdUnit& unit = c.units->units[c.units->count++];
    unit.flags = block.flags;
    unit.deviceId = block.deviceId;
    unit.pciSegment = block.pciSegment;
    unit.capabilityOffset = block.capabilityOffset;
    unit.iommuInfo = block.iommuInfo;
    unit.registerBase = block.registerBase;
    if (block.type == 0x10) {
        unit.featureReporting = block.featureReportingOrAttributes;
        unit.hasFeatureReporting = true;
    } else {
        unit.attributes = block.featureReportingOrAttributes;
        unit.hasAttributes = true;
        unit.efrImage = block.efrImage;
        unit.efrPresent = true;
    }
    unit.blocks[0] = {block.bytes, block.offset, block.length, block.fixedSize,
                      block.type};
    unit.blockCount = 1;
    return true;
}

} // namespace

IvrsTopologyResult buildTopology(const std::uint8_t* bytes, std::size_t size,
                                 IvhdUnitTable& units) noexcept {
    units = IvhdUnitTable{};
    IvrsTopologyResult result{};

    CollectContext context{&units, &result, TopologyError::None, 0};
    const IvrsVisitor visitor{&context, nullptr, onBlock, nullptr};
    result.parse = parseIvrs(bytes, size, visitor);
    // A visitor that stops early makes parseIvrs report VisitorStopped. The
    // topology reason is the more specific one, so check it first.
    if (context.error != TopologyError::None) {
        result.error = context.error;
        result.errorOffset = context.errorOffset;
        result.ivrsError = result.parse.error;
        units = IvhdUnitTable{};
        return result;
    }
    if (!result.parse) {
        result.error = TopologyError::TableInvalid;
        result.ivrsError = result.parse.error;
        result.errorOffset = result.parse.errorOffset;
        units = IvhdUnitTable{};
        return result;
    }
    if (units.count == 0) {
        result.error = TopologyError::NoIvhdUnits;
        return result;
    }

    // Validate every block, but count only the first description of each unit so
    // duplicated firmware does not double the reported inventory.
    for (std::size_t i = 0; i < units.count; ++i) {
        const IvhdUnit& unit = units.units[i];
        for (std::size_t b = 0; b < unit.blockCount; ++b) {
            std::size_t offset = 0;
            IvrsTopologyResult* counts = b == 0 ? &result : nullptr;
            const TopologyError error =
                validateBlock(unit.blocks[b], counts, offset);
            if (error != TopologyError::None) {
                result.error = error;
                result.errorOffset = offset;
                units = IvhdUnitTable{};
                return result;
            }
        }
    }
    for (std::size_t i = 0; i < units.count; ++i) {
        if (units.units[i].conflictingDuplicates) {
            result.error = TopologyError::ConflictingDuplicates;
            result.errorOffset = units.units[i].conflictBlockOffset;
            units = IvhdUnitTable{};
            return result;
        }
    }

    result.unitCount = units.count;
    units.valid = true;
    return result;
}

bool encodeRequesterId(std::uint8_t bus, std::uint8_t device,
                       std::uint8_t function, std::uint16_t& deviceId) noexcept {
    if (device > 31 || function > 7) {
        return false;
    }
    deviceId = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bus) << 8) |
        (static_cast<std::uint16_t>(device) << 3) |
        static_cast<std::uint16_t>(function));
    return true;
}

RequesterResolution resolveRequester(const IvhdUnitTable& units,
                                     std::uint16_t pciSegment, std::uint8_t bus,
                                     std::uint8_t device,
                                     std::uint8_t function) noexcept {
    RequesterResolution out{};
    out.pciSegment = pciSegment;
    std::uint16_t id = 0;
    if (!encodeRequesterId(bus, device, function, id)) {
        out.status = RequesterStatus::InvalidBdf;
        return out;
    }
    return resolveRequesterDeviceId(units, pciSegment, id);
}

RequesterResolution resolveRequesterDeviceId(const IvhdUnitTable& units,
                                             std::uint16_t pciSegment,
                                             std::uint16_t deviceId) noexcept {
    RequesterResolution out{};
    out.pciSegment = pciSegment;
    out.deviceId = deviceId;
    out.resolvedDeviceId = deviceId;
    if (!units.valid || units.count == 0) {
        out.status = RequesterStatus::InvalidTopology;
        return out;
    }

    bool sawSegment = false;
    Match best{};
    Match plain{};
    std::size_t bestUnit = 0;
    bool special = false;
    std::uint8_t specialVariety = 0;

    for (std::size_t i = 0; i < units.count; ++i) {
        const IvhdUnit& unit = units.units[i];
        if (unit.pciSegment != pciSegment) {
            continue;
        }
        sawSegment = true;
        ScanOutcome outcome{};
        for (std::size_t b = 0; b < unit.blockCount; ++b) {
            scanBlock(unit.blocks[b], deviceId, outcome);
        }
        if (outcome.special) {
            special = true;
            specialVariety = outcome.specialVariety;
        }
        if (outcome.best.rank > best.rank) {
            best = outcome.best;
            plain = outcome.plain;
            bestUnit = i;
        } else if (outcome.best.rank == best.rank && outcome.best.found &&
                   best.found) {
            if (outcome.best.resolved != best.resolved ||
                outcome.best.dataSetting != best.dataSetting ||
                outcome.best.viaAlias != best.viaAlias) {
                best.conflict = true;
            }
        }
    }

    if (!sawSegment) {
        out.status = RequesterStatus::NoUnitForSegment;
        return out;
    }
    // A special entry is only decisive when nothing claims the id as a requester.
    if (special && !best.found) {
        out.status = RequesterStatus::SpecialNotPci;
        out.isSpecialDevice = true;
        out.specialVariety = specialVariety;
        return out;
    }
    if (!best.found) {
        out.status = RequesterStatus::NotCovered;
        return out;
    }
    if (best.conflict) {
        out.status = RequesterStatus::Ambiguous;
        return out;
    }
    out.status = RequesterStatus::Resolved;
    out.unitIndex = bestUnit;
    out.resolvedDeviceId = best.resolved;
    out.dataSetting = best.dataSetting;
    out.viaAlias = best.viaAlias;
    out.viaExtended = best.viaExtended;
    out.atsDisabled = best.atsDisabled;
    out.wasAllDevices = best.wasAll;
    out.matchEntryOffset = best.entryOffset;
    out.shadowedPlainRange =
        best.viaAlias && plain.found && plain.rank < kRankAlias;
    return out;
}

const char* topologyErrorString(TopologyError error) noexcept {
    switch (error) {
    case TopologyError::None: return "topology valid (structure only)";
    case TopologyError::TableInvalid: return "underlying IVRS table rejected";
    case TopologyError::NoIvhdUnits: return "table describes no IOMMU";
    case TopologyError::TooManyUnits: return "too many distinct IOMMU units";
    case TopologyError::TooManyUnitBlocks: return "one unit described too often";
    case TopologyError::ConflictingDuplicates:
        return "duplicate descriptions of one unit disagree";
    case TopologyError::NestedRange: return "device range started inside another";
    case TopologyError::EndWithoutStart: return "range end without a start";
    case TopologyError::ReversedRange: return "range end precedes its start";
    case TopologyError::UnterminatedRange: return "range left open at block end";
    case TopologyError::UnsupportedEntry: return "undecodable device entry";
    case TopologyError::UnpairedEntry: return "device entry cannot be paired";
    }
    return "unknown topology error";
}

const char* requesterStatusString(RequesterStatus status) noexcept {
    switch (status) {
    case RequesterStatus::Resolved: return "resolved to one unit";
    case RequesterStatus::NotCovered: return "no entry covers this requester";
    case RequesterStatus::NoUnitForSegment: return "no IOMMU for this segment";
    case RequesterStatus::Ambiguous: return "conflicting claims";
    case RequesterStatus::SpecialNotPci: return "IOAPIC/HPET, not a PCI requester";
    case RequesterStatus::InvalidBdf: return "invalid BDF";
    case RequesterStatus::InvalidTopology: return "topology was not built";
    }
    return "unknown requester status";
}

const char* requesterPrecedenceNote() noexcept {
    return "Precedence: alias (0x42/0x43) > plain/extended (0x02/0x03/0x46/0x47) "
           "> all-devices (0x01). Equal-rank disagreement is reported as "
           "ambiguous, never guessed. This ordering is a documented "
           "interpretation of the firmware fields, not a quotation of the AMD "
           "specification, and it does not prove the hardware agrees.";
}

} // namespace amd_iommu
