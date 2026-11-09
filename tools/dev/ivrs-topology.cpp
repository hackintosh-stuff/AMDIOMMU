#include "amd_iommu/IvrsTopology.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

// Offline tool: replay a captured IVRS through the topology layer and print the
// deduplicated units plus resolved requesters. Never touches firmware or MMIO.
namespace {

using namespace amd_iommu;

void printUnit(const IvhdUnit& unit, std::size_t index) {
    std::printf("unit %zu: segment=%u deviceId=0x%04x base=0x%016llx flags=0x%02x\n",
                index, unit.pciSegment, unit.deviceId,
                static_cast<unsigned long long>(unit.registerBase), unit.flags);
    if (unit.hasLegacyFlags && unit.flagsDifferAcrossForms) {
        std::printf("  legacyFlags=0x%02x extendedFlags=0x%02x (differs across forms)\n",
                    unit.legacyFlags, unit.flags);
    }
    std::printf("  blocks=%zu (", unit.blockCount);
    for (std::size_t b = 0; b < unit.blockCount; ++b) {
        std::printf("%s0x%02x@0x%zx", b ? ", " : "", unit.blocks[b].type,
                    unit.blocks[b].offset);
    }
    std::printf(")\n");
    if (unit.efrPresent) {
        std::printf("  efr=0x%016llx\n",
                    static_cast<unsigned long long>(unit.efrImage));
    }
    if (unit.hasAttributes) {
        std::printf("  attributes=0x%08x\n", unit.attributes);
    }
    if (unit.hasFeatureReporting) {
        std::printf("  featureReporting=0x%08x\n", unit.featureReporting);
    }
    std::printf("  duplicateDescriptions=%s deviceTablesIdentical=%s\n",
                unit.blockCount > 1 ? "yes" : "no",
                unit.conflictingDeviceTables ? "no" : "yes");
}

void printRequester(const IvhdUnitTable& units, std::uint16_t segment,
                    unsigned bus, unsigned dev, unsigned fn) {
    const auto r = resolveRequester(units, segment, static_cast<std::uint8_t>(bus),
                                    static_cast<std::uint8_t>(dev),
                                    static_cast<std::uint8_t>(fn));
    std::printf("  %04u:%02x:%02x.%u -> %-32s", segment, bus, dev, fn,
                requesterStatusString(r.status));
    if (r.status == RequesterStatus::Resolved) {
        std::printf(" unit=%zu id=0x%04x->0x%04x data=0x%02x%s%s%s",
                    r.unitIndex, r.deviceId, r.resolvedDeviceId, r.dataSetting,
                    r.viaAlias ? " alias" : "", r.wasAllDevices ? " all" : "",
                    r.atsDisabled ? " ats-off" : "");
    } else if (r.status == RequesterStatus::SpecialNotPci) {
        std::printf(" variety=%u", r.specialVariety);
    }
    std::printf("\n");
}

} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::strcmp(argv[1], "--help") == 0) {
        std::puts("Usage: ivrs-topology IVRS.bin\n"
                  "Replays a captured IVRS through the topology layer: deduplicates\n"
                  "IVHD units and resolves sample PCI requesters. Offline only:\n"
                  "does not collect firmware, touch MMIO, or program a DTE.\n"
                  "Exit: 0 topology valid, 2 usage/IO error, 3 invalid.");
        return 0;
    }
    if (argc != 2) {
        std::fputs("Usage: ivrs-topology IVRS.bin\n", stderr);
        return 2;
    }
    FILE* file = std::fopen(argv[1], "rb");
    if (!file) { std::perror("open IVRS input"); return 2; }
    if (std::fseek(file, 0, SEEK_END) != 0) {
        std::fclose(file); std::fputs("Input must be a seekable file\n", stderr);
        return 2;
    }
    const long size = std::ftell(file);
    if (size < 0 || size > 16 * 1024 * 1024 || std::fseek(file, 0, SEEK_SET) != 0) {
        std::fclose(file); std::fputs("Invalid input size (max 16 MiB)\n", stderr);
        return 2;
    }
    std::vector<std::uint8_t> bytes(size ? static_cast<std::size_t>(size) : 1);
    const std::size_t read = std::fread(bytes.data(), 1, static_cast<std::size_t>(size), file);
    const bool ioError = std::ferror(file) != 0;
    std::fclose(file);
    if (ioError || read != static_cast<std::size_t>(size)) {
        std::fputs("Could not read complete input\n", stderr);
        return 2;
    }

    IvhdUnitTable units{};
    const auto r = buildTopology(bytes.data(), read, units);
    if (!r) {
        std::fprintf(stderr, "topology rejected at offset %zu: %s\n", r.errorOffset,
                     topologyErrorString(r.error));
        if (r.error == TopologyError::TableInvalid) {
            std::fprintf(stderr, "  underlying IVRS error: %s\n",
                         ivrsErrorString(r.ivrsError));
        }
        return 3;
    }

    std::printf("topology valid: units=%zu duplicateBlocks=%zu\n", r.unitCount,
                r.duplicateBlockCount);
    std::printf("entries: ranges=%zu singles=%zu alias=%zu all=%zu special=%zu "
                "hid=%zu padded=%zu\n",
                r.deviceRanges, r.deviceSingles, r.aliasEntries, r.allEntries,
                r.specialEntries, r.hidEntries, r.paddedEntries);
    for (std::size_t i = 0; i < units.count; ++i) {
        printUnit(units.units[i], i);
    }
    const std::uint16_t segment = units.units[0].pciSegment;
    std::puts("sample requesters:");
    printRequester(units, segment, 0x00, 0x00, 0x0);
    printRequester(units, segment, 0x00, 0x00, 0x2); // typical IOMMU function
    printRequester(units, segment, 0x00, 0x01, 0x0);
    printRequester(units, segment, 0x01, 0x00, 0x0);
    printRequester(units, segment, 0x02, 0x00, 0x0);
    printRequester(units, segment, 0x03, 0x00, 0x0);
    printRequester(units, segment, 0x0A, 0x00, 0x0); // typical NVMe slot
    printRequester(units, segment, 0x0C, 0x00, 0x0);
    printRequester(units, segment, 0xFF, 0x00, 0x0);
    std::puts(requesterPrecedenceNote());
    std::puts("NOT hardware validation: no DTE, translation, or isolation is proven.");
    return 0;
}
