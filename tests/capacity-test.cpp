// Host regression for capacity profiles and independent live allocator growth.
//
// These properties are checked against the same
// headers the kext compiles:
//
//   1. The runtime-sized allocator behaves EXACTLY like the compile-time one
//      it replaces, preserving the accepted legacy allocation behaviour.
//   2. The profile table exposes the documented capacities and unknown names
//      are refused instead of silently widening the metadata.
//   3. The independently rounded stores match the shared metadata layout.
//   4. Growth replaces only the exhausted store, preserving the other allocation.
//   5. Record owners above 65535 remain addressable across migration and release.
// Page tables are prebuilt here to isolate metadata migration; incremental
// page-table allocation is exercised by the separate table-growth test.
// This host test does not execute the kext's MapMemory or hardware commands.
#include <cstdint>
#include <cstdio>
#include <cstring>

#include <utility>
#include <vector>

#include "../probe/amd_iommu_mapper_abi.hpp"
#include "../probe/amd_iommu_tx_core.hpp"
#include "../probe/amd_iommu_mapper_storage.hpp"

namespace {

int failures;

void check(bool ok, const char *what) {
    if (!ok) {
        std::printf("FAIL %s\n", what);
        ++failures;
    }
}

bool isZeroed(const void *memory, std::size_t bytes) {
    const auto *data = static_cast<const std::uint8_t *>(memory);
    for (std::size_t i = 0; i < bytes; ++i)
        if (data[i]) return false;
    return true;
}

// Deterministic generator: the whole point is that both allocators see the
// same operation sequence, so the sequence must not depend on the platform.
struct Rng {
    std::uint64_t state;
    std::uint32_t next() {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        return static_cast<std::uint32_t>(state >> 33);
    }
    std::uint32_t below(std::uint32_t n) { return next() % n; }
};

void allocationEquivalence() {
    amdtx::BoundedAllocator<4096, 128> fixed{};
    amdtx::u64 used[4096 / 64] = {};
    amdtx::u64 ever[4096 / 64] = {};
    amdtx::RuntimeAllocator runtime{used, ever, 4096, 128, 0, 0, 0};

    const std::uint32_t alignments[4] = {1, 1, 2, 8};
    std::vector<std::pair<unsigned, unsigned>> live;
    Rng rng{0x5eed1234U};
    unsigned mismatches = 0;
    for (unsigned step = 0; step < 20000; ++step) {
        const bool wantAlloc = live.empty() || rng.below(100) < 62;
        if (wantAlloc) {
            const unsigned pages = 1 + rng.below(128);
            const unsigned align = alignments[rng.below(4)];
            unsigned baseFixed = 0, baseRuntime = 0;
            const bool okFixed = amdtx::allocate(fixed, pages, baseFixed, align);
            const bool okRuntime = amdtx::allocate(runtime, pages, baseRuntime, align);
            if (okFixed != okRuntime || (okFixed && baseFixed != baseRuntime)) ++mismatches;
            if (okFixed) live.emplace_back(baseFixed, pages);
        } else {
            const unsigned pick = rng.below(static_cast<std::uint32_t>(live.size()));
            const auto range = live[pick];
            live.erase(live.begin() + pick);
            const bool okFixed = amdtx::release(fixed, range.first, range.second);
            const bool okRuntime = amdtx::release(runtime, range.first, range.second);
            if (okFixed != okRuntime) ++mismatches;
        }
        if (fixed.livePages != runtime.livePages ||
            fixed.peakPages != runtime.peakPages ||
            fixed.reusedAllocations != runtime.reusedAllocations ||
            std::memcmp(fixed.used, used, sizeof(used)) != 0 ||
            std::memcmp(fixed.ever, ever, sizeof(ever)) != 0) {
            ++mismatches;
        }
        if (mismatches) break;
    }
    check(mismatches == 0, "runtime allocator diverged from the compile-time allocator");
    // The legacy pool must also be fully drainable: every page returns to the
    // bitmap, which is what makes unmap-then-remap reuse identical.
    for (const auto &range : live) amdtx::release(fixed, range.first, range.second);
    for (std::size_t i = 0; i < 4096 / 64; ++i) {
        check(fixed.used[i] == 0, "legacy allocator did not return every page");
    }
}

void profileTable() {
    check(mapper_abi::kProfileLegacy.records == mapper_abi::kRecords,
          "legacy profile changed the record count");
    check(mapper_abi::kProfileLegacy.pages == mapper_abi::kPages,
          "legacy profile changed the IOVA window");
    check(mapper_abi::kProfileLegacy.mapPages == mapper_abi::kMapPages &&
              mapper_abi::kProfileLegacy.runs == mapper_abi::kRuns,
          "legacy profile changed the per-map bound");
    check(mapper_abi::kProfileRl10g.records > mapper_abi::kProfileLegacy.records,
          "rl-10g must size for a packet pool, not for a ring");
    check(mapper_abi::kProfileRl10g.pages % 512 == 0, "leaf tables cover 2 MiB each");
    check(mapper_abi::kProfileRl10g.tablePages >=
              mapper_abi::kProfileRl10g.pages / 512 + 2,
          "profile does not cover its own page tables");
    check(mapper_abi::profileForName(nullptr) == &mapper_abi::kProfileLegacy,
          "missing name must fall back to the legacy profile");
    check(mapper_abi::profileForName("") == &mapper_abi::kProfileLegacy,
          "empty name must fall back to the legacy profile");
    check(mapper_abi::profileForName("rl-10g") == &mapper_abi::kProfileRl10g,
          "rl-10g lookup failed");
    check(mapper_abi::profileForName("rl-l0g") == nullptr,
          "a typo must be refused, never resolved to another profile");
    check(mapper_abi::profileForName("native-legacy") == &mapper_abi::kProfileLegacy,
          "native-legacy lookup failed");
    check(mapper_abi::profileForName("rl-10g-max") == &mapper_abi::kProfileRl10gMax,
          "rl-10g-max lookup failed");
    check(mapper_abi::kProfileRl10gMax.records == 65535 &&
              mapper_abi::kProfileRl10gMax.pages == 262144,
          "the existing rl-10g-max ceiling changed");
    check(mapper_abi::profileForName("dma32-max") == &mapper_abi::kProfileDma32Max &&
              mapper_abi::kProfileDma32Max.records == 131072 &&
              mapper_abi::kProfileDma32Max.pages == 524288,
          "dma32-max must expose the wider record and IOVA capacity");
    check(mapper_abi::kBase + mapper_abi::kProfileDma32Max.pages * 4096ULL ==
              (1ULL << 32),
          "the dma32 window must end at the 32-bit address boundary");
    const mapper_abi::Profile *profiles[] = {
        &mapper_abi::kProfileLegacy, &mapper_abi::kProfileRl10g,
        &mapper_abi::kProfileRl10gMax, &mapper_abi::kProfileDma32Max};
    for (const auto *profile : profiles) {
        const auto capacity = mapper_abi::capacityForProfile(*profile);
        check(capacity.records == profile->records && capacity.pages == profile->pages &&
                  mapper_abi::sameProfileName(
                      mapper_abi::profileNameForCapacity(capacity), profile->name),
              "exact profile capacity lost its display name");
    }
}

void storageArithmetic() {
    // Record metadata is 1024*120 + 16*8 = 123008 -> 126976 bytes.
    // Page metadata is 4096*12 + 8*8 + 2*64*8 = 50240 -> 53248 bytes.
    check(mapper_abi::recordStorageBytesFor(1024) == 126976ULL &&
              mapper_abi::iovaPageStorageBytesFor(4096) == 53248ULL &&
              mapper_abi::metadataBytesFor(mapper_abi::kProfileLegacy) == 180224ULL,
          "legacy metadata must round each independent store to a page");
    check(mapper_abi::recordStorageBytesFor(16384) == 1970176ULL &&
              mapper_abi::iovaPageStorageBytesFor(131072) == 1609728ULL &&
              mapper_abi::metadataBytesFor(mapper_abi::kProfileRl10g) == 3579904ULL,
          "rl-10g metadata size does not match the documented footprint");
    check(mapper_abi::metadataBytesFor(mapper_abi::kProfileRl10g) <
              mapper_abi::kMaxMetadataBytes,
          "rl-10g metadata exceeds the wired-memory guard");
    check(mapper_abi::metadataBytesFor(mapper_abi::kProfileRl10gMax) == 11087872ULL,
          "rl-10g-max metadata size does not match the documented footprint");
    check(mapper_abi::metadataBytesFor(mapper_abi::kProfileRl10gMax) <
              mapper_abi::kMaxMetadataBytes,
          "rl-10g-max metadata exceeds the wired-memory guard");
    check(mapper_abi::metadataBytesFor(mapper_abi::kProfileDma32Max) == 22175744ULL &&
              mapper_abi::metadataBytesFor(mapper_abi::kProfileDma32Max) <
              mapper_abi::kMaxMetadataBytes,
          "dma32-max metadata footprint is wrong or exceeds the wired-memory guard");
    check(mapper_abi::metadataBytesFor(mapper_abi::Capacity{2048, 4096}) == 303104ULL,
          "record-only growth allocated more than its actual metadata capacity");
    check(mapper_abi::metadataBytesFor(mapper_abi::Capacity{1024, 8192}) == 229376ULL &&
              mapper_abi::metadataBytesFor(mapper_abi::Capacity{1024, 16384}) == 331776ULL,
          "page-only growth allocated more than its actual metadata capacity");
    check(mapper_abi::kMappingBytes == 120, "record slot size changed");
}

void devicePolicy() {
    // S2 admission input: only AppleEthernetRL on the auto-attach path widens.
    check(mapper_abi::profileForDevice(0x10ec, 0x8124, true) ==
              &mapper_abi::kProfileRl10gMax,
          "AppleEthernetRL 8124 must take the 10 GbE-sized profile");
    check(mapper_abi::profileForDevice(0x10ec, 0x8127, true) ==
              &mapper_abi::kProfileRl10gMax,
          "AppleEthernetRL 8127 must take the 10 GbE-sized profile");
    check(mapper_abi::profileForDevice(0x10ec, 0x8123, true) ==
              &mapper_abi::kProfileLegacy,
          "device below the Apple RL range must keep the legacy window");
    check(mapper_abi::profileForDevice(0x10ec, 0x8128, true) ==
              &mapper_abi::kProfileLegacy,
          "device above the Apple RL range must keep the legacy window");
    check(mapper_abi::profileForDevice(0x10ec, 0x8168, true) ==
              &mapper_abi::kProfileLegacy,
          "the board RTL8111 must keep the accepted ABI3 arena");
    check(mapper_abi::profileForDevice(0x8086, 0x8127, true) ==
              &mapper_abi::kProfileLegacy,
          "a foreign vendor must not inherit the Apple profile");
    check(mapper_abi::profileForDevice(0x10ec, 0x8127, false) ==
              &mapper_abi::kProfileLegacy,
          "the claim path (Lucy) must keep the accepted ABI3 arena");
    check(mapper_abi::profileForDevice(0x15b3, 0x1015, false) ==
              &mapper_abi::kProfileRl10gMax,
          "Mellanox 0x1015 must be admitted with the 1 GiB arena");
    check(mapper_abi::profileForDevice(0x15b3, 0x1015, true) ==
              &mapper_abi::kProfileRl10gMax,
          "Mellanox admission must not depend on the claim path");
    check(mapper_abi::profileForDevice(0x15b3, 0x101d, false) ==
              &mapper_abi::kProfileRl10gMax,
          "Mellanox 0x101d must be admitted with the 1 GiB arena");
    check(mapper_abi::profileForName("rl-10g-max") ==
              &mapper_abi::kProfileRl10gMax,
          "rl-10g-max profile lookup failed");
    // R70-S6: PCI-class fallback for devices in neither ID table.
    mapper_abi::ProfileSource source = mapper_abi::ProfileSource::legacy;
    check(mapper_abi::profileForDevice(0x9999, 0x0001, true, 0x020000, &source) ==
              &mapper_abi::kProfileRl10gMax,
          "an unlisted network controller must take the 1 GiB arena");
    check(source == mapper_abi::ProfileSource::classTable,
          "the class fallback must be attributed to the class table");
    check(mapper_abi::profileForDevice(0x1b21, 0x0612, true, 0x010601) ==
              &mapper_abi::kProfileRl10g,
          "a storage controller must take the 512 MiB arena");
    check(mapper_abi::profileForDevice(0x8086, 0x1234, true, 0x0c0330) ==
              &mapper_abi::kProfileLegacy,
          "a USB controller must keep the legacy window");
    check(mapper_abi::profileForDevice(0x10ec, 0x8127, true, 0x020000, &source) ==
              &mapper_abi::kProfileRl10gMax &&
              source == mapper_abi::ProfileSource::idTable,
          "the ID table must win over the class fallback");
    check(mapper_abi::profileForDevice(0x9999, 0x0001, false, 0x020000) ==
              &mapper_abi::kProfileLegacy,
          "the claim path must not inherit the class fallback");
    check(mapper_abi::profileForDevice(0x15b3, 0x1015, false, 0x020000) ==
              &mapper_abi::kProfileRl10gMax,
          "Mellanox admission must still ignore the class fallback gate");
}

void capacitySemantics() {
    // The allocator must grant exactly poolPages 1-page spans and then refuse:
    // that is the difference between a ring-sized arena and a pool-sized one.
    amdtx::u64 used[512 / 64] = {};
    amdtx::u64 ever[512 / 64] = {};
    amdtx::RuntimeAllocator runtime{used, ever, 512, 1, 0, 0, 0};
    unsigned granted = 0;
    unsigned base = 0;
    while (amdtx::allocate(runtime, 1, base)) ++granted;
    check(granted == 512, "1-page grants do not fill the pool exactly");
    check(runtime.livePages == 512, "live page accounting differs from grants");
    amdtx::release(runtime, 0, 1);
    check(amdtx::allocate(runtime, 1, base) && base == 0,
          "a released page is not reused first");
    // A multi-page request larger than maxMapPages must be refused, not split.
    check(!amdtx::allocate(runtime, 2, base), "per-map bound was ignored");
}

void growthPolicy() {
    const auto legacy = mapper_abi::capacityForProfile(mapper_abi::kProfileLegacy);
    const auto &ceiling = mapper_abi::kProfileDma32Max;
    auto current = legacy;
    mapper_abi::Capacity target{};
    using mapper_abi::CapacityResource;
    const unsigned recordCapacities[] = {2048, 4096, 8192, 16384, 32768, 65536, 131072};
    for (unsigned records : recordCapacities) {
        const bool grew = mapper_abi::nextCapacity(
            current, ceiling, CapacityResource::recordSlots, target);
        check(grew && target.records == records && target.pages == legacy.pages,
              "record growth must double only the record capacity up to its ceiling");
        if (!grew) return;
        check(mapper_abi::sameProfileName(
                  mapper_abi::profileNameForCapacity(target), "dynamic"),
              "mixed record/page capacity was rounded up to a named profile");
        current = target;
    }
    check(!mapper_abi::nextCapacity(current, ceiling, CapacityResource::recordSlots, target),
          "record capacity grew beyond its ceiling");

    // Reaching the record ceiling must not prevent independent page growth.
    const unsigned pageCapacities[] = {8192, 16384, 32768, 65536, 131072, 262144, 524288};
    for (unsigned pages : pageCapacities) {
        const bool grew = mapper_abi::nextCapacity(
            current, ceiling, CapacityResource::iovaPages, target);
        check(grew && target.pages == pages && target.records == ceiling.records,
              "page growth must double only the page capacity up to its ceiling");
        if (!grew) return;
        current = target;
    }
    check(current.records == ceiling.records && current.pages == ceiling.pages &&
              !mapper_abi::nextCapacity(current, ceiling, CapacityResource::iovaPages, target),
          "independent growth failed to reach and stop at both configured limits");
    check(!mapper_abi::nextCapacity(legacy, mapper_abi::kProfileLegacy,
              CapacityResource::recordSlots, target) &&
              !mapper_abi::nextCapacity(legacy, mapper_abi::kProfileLegacy,
              CapacityResource::iovaPages, target),
          "a forced legacy ceiling must disable both growth resources");
    const auto &previousCeiling = mapper_abi::kProfileRl10gMax;
    check(mapper_abi::nextCapacity({32768, 131072}, previousCeiling,
              CapacityResource::recordSlots, target) &&
              target.records == 65535 && target.pages == 131072,
          "an explicit rl-10g-max ceiling must still clip record growth to 65535");
    current = target;
    check(!mapper_abi::nextCapacity(current, previousCeiling,
              CapacityResource::recordSlots, target),
          "an explicit record ceiling was exceeded");
    check(mapper_abi::nextCapacity(current, previousCeiling,
              CapacityResource::iovaPages, target) &&
              target.records == 65535 && target.pages == 262144,
          "the existing page ceiling must remain independent of its record ceiling");
    // The grown window must keep the measured peak (52,227 pages) covered
    // with headroom, and both metadata stores must stay inside the wired-memory guard.
    check(ceiling.pages >= 4 * 52227,
          "the growth ceiling no longer covers the measured 10 GbE peak");
    check(mapper_abi::metadataBytesFor(ceiling) <= mapper_abi::kMaxMetadataBytes,
          "the growth ceiling exceeds the wired-memory guard");
}

void liveCapacityGrowth() {
    const auto &ceiling = mapper_abi::kProfileRl10gMax;
    auto current = mapper_abi::capacityForProfile(mapper_abi::kProfileLegacy);
    std::vector<amdtx::u64> recordWords(
        mapper_abi::recordStorageBytesFor(current.records) / sizeof(amdtx::u64));
    std::vector<amdtx::u64> pageWords(
        mapper_abi::iovaPageStorageBytesFor(current.pages) / sizeof(amdtx::u64));
    amdmapper::MappingStorage metadata{};
    amdmapper::bindRecordStorage(metadata, recordWords.data(), current.records);
    amdmapper::bindIovaPageStorage(metadata, pageWords.data(), current.pages);
    auto &allocator = metadata.allocator;
    check(metadata.metadataBytes() == mapper_abi::metadataBytesFor(current) &&
              metadata.metadataBytes() < mapper_abi::metadataBytesFor(ceiling),
          "metadata preparation allocated the ceiling instead of the initial profile");

    std::vector<amdtx::u64> tableWords(ceiling.tablePages * 512);
    std::vector<volatile amdtx::u64 *> preparedLeaves(ceiling.pages / 512);
    const amdtx::u64 tablePA = 0x1000000ULL;
    amdsparse::Arena pageTables{tableWords.data(), tablePA, ceiling.tablePages,
                                1, 4, tablePA, 0, 0, nullptr};
    for (unsigned i = 0; i < preparedLeaves.size(); ++i) {
        preparedLeaves[i] = amdtx::prepareAt(pageTables,
            mapper_abi::kBase + static_cast<amdtx::u64>(i) * 0x200000ULL, 512);
        check(preparedLeaves[i] != nullptr, "page-table preparation failed");
        if (!preparedLeaves[i]) return;
        if (i < metadata.pages / 512) metadata.leaves[i] = preparedLeaves[i];
    }

    enum class AllocationResult { mapped, recordsFull, pagesFull };
    unsigned liveCount = 0;
    const auto allocateMapping = [&](unsigned pages) {
        const unsigned slot = amdtx::findNextBitmapPage(
            metadata.liveSlots, 0, metadata.records, false);
        if (slot == metadata.records) return AllocationResult::recordsFull;
        unsigned base = 0;
        if (!amdtx::allocate(allocator, pages, base)) return AllocationResult::pagesFull;
        auto &mapping = metadata.mappings[slot];
        // Opaque identities are copied and compared, never dereferenced by this test.
        mapping.memory = reinterpret_cast<IOMemoryDescriptor *>(
            static_cast<std::uintptr_t>(0x100000 + slot * 16));
        mapping.command = reinterpret_cast<IODMACommand *>(
            static_cast<std::uintptr_t>(0x200000 + slot * 16));
        auto &record = mapping.record;
        record.handle = slot + 1;
        record.recordIndex = slot;
        record.basePage = base;
        record.pages = pages;
        record.mapAddress = mapper_abi::kBase + base * 4096ULL;
        record.firstPA = 0x400000000ULL + base * 4096ULL;
        record.mapLength = record.length = pages * 4096ULL;
        record.runs = 1;
        record.state = mapper_abi::kMapPublished | mapper_abi::kMapConfirmed;
        for (unsigned i = 0; i < pages; ++i) {
            const unsigned page = base + i;
            metadata.physicalByPage[page] = record.firstPA + i * 4096ULL;
            metadata.leaves[page / 512][page % 512] = amdpte::makeDefaultLeaf(
                1, metadata.physicalByPage[page], amdpte::PTE_IR | amdpte::PTE_IW);
        }
        metadata.slotByStartPage[base] = static_cast<uint32_t>(slot + 1);
        metadata.liveSlots[slot / 64] |= 1ULL << (slot % 64);
        ++liveCount;
        return AllocationResult::mapped;
    };
    const auto releaseMapping = [&](unsigned slot) {
        auto &mapping = metadata.mappings[slot];
        const auto &record = mapping.record;
        const unsigned owner = metadata.slotByStartPage[record.basePage];
        const bool owned = owner == slot + 1 &&
            (metadata.liveSlots[slot / 64] & (1ULL << (slot % 64)));
        check(owned, "metadata migration lost a live mapping's owner index");
        if (!owned) return false;
        const bool released = amdtx::release(allocator, record.basePage, record.pages);
        check(released, "a live mapping could not be released after metadata growth");
        if (!released) return false;
        for (unsigned i = 0; i < record.pages; ++i) {
            const unsigned page = record.basePage + i;
            metadata.leaves[page / 512][page % 512] = 0;
        }
        metadata.slotByStartPage[record.basePage] = 0;
        metadata.liveSlots[slot / 64] &= ~(1ULL << (slot % 64));
        mapping.memory = nullptr;
        mapping.command = nullptr;
        --liveCount;
        return true;
    };
    const auto verifyLiveTranslations = [&]() {
        bool valid = true;
        const auto readEntry = [&](amdtx::u64 pa, unsigned index) -> amdtx::u64 {
            const auto *table = amdsparse::table(pageTables, pa);
            return table ? table[index] : 0;
        };
        for (unsigned slot = 0; slot < liveCount && valid; ++slot) {
            const auto &record = metadata.mappings[slot].record;
            for (unsigned i = 0; i < record.pages; ++i) {
                const auto walk = amdpte::walkPageTable(readEntry, pageTables.rootLevel,
                    pageTables.rootPA, record.mapAddress + i * 4096ULL);
                if (!walk.ok || walk.outPA != record.firstPA + i * 4096ULL ||
                    metadata.physicalByPage[record.basePage + i] != walk.outPA) {
                    valid = false;
                    break;
                }
            }
        }
        check(valid, "metadata growth changed an existing IOVA translation or expected PA");
        return valid;
    };
    const auto growStorage = [&](mapper_abi::CapacityResource resource,
                                 const mapper_abi::Capacity &expected) {
        mapper_abi::Capacity next{};
        const bool planned = mapper_abi::nextCapacity(current, ceiling, resource, next);
        const bool selected = planned && next.records == expected.records &&
            next.pages == expected.pages;
        check(selected, "capacity exhaustion grew the wrong resource or selected the wrong size");
        if (!selected) return false;
        const amdmapper::MappingStorage previous = metadata;
        const auto retainedTables = tableWords;
        const auto retainedRoot = pageTables.rootPA;
        const auto retainedTablePages = pageTables.pages;
        const bool recordsGrowing = resource == mapper_abi::CapacityResource::recordSlots;
        const auto retainedWords = recordsGrowing ? pageWords : recordWords;
        bool copied = false;
        {
            const auto bytes = recordsGrowing
                ? mapper_abi::recordStorageBytesFor(next.records)
                : mapper_abi::iovaPageStorageBytesFor(next.pages);
            std::vector<amdtx::u64> expandedWords(bytes / sizeof(amdtx::u64));
            amdmapper::MappingStorage expanded = metadata;
            if (recordsGrowing) {
                amdmapper::bindRecordStorage(expanded, expandedWords.data(), next.records);
                amdmapper::copyRecordStorage(expanded, metadata);
                check(expanded.recordMemory != previous.recordMemory &&
                          expanded.mappings != previous.mappings &&
                          expanded.liveSlots != previous.liveSlots &&
                          expanded.pageMemory == previous.pageMemory &&
                          expanded.pageBytes == previous.pageBytes &&
                          expanded.physicalByPage == previous.physicalByPage &&
                          expanded.slotByStartPage == previous.slotByStartPage &&
                          expanded.leaves == previous.leaves &&
                          expanded.allocator.used == previous.allocator.used &&
                          expanded.allocator.ever == previous.allocator.ever &&
                          pageWords == retainedWords,
                      "record growth must replace only record storage");
            } else {
                amdmapper::bindIovaPageStorage(expanded, expandedWords.data(), next.pages);
                amdmapper::copyIovaPageStorage(expanded, metadata);
                check(expanded.pageMemory != previous.pageMemory &&
                          expanded.physicalByPage != previous.physicalByPage &&
                          expanded.slotByStartPage != previous.slotByStartPage &&
                          expanded.leaves != previous.leaves &&
                          expanded.allocator.used != previous.allocator.used &&
                          expanded.allocator.ever != previous.allocator.ever &&
                          expanded.recordMemory == previous.recordMemory &&
                          expanded.recordBytes == previous.recordBytes &&
                          expanded.mappings == previous.mappings &&
                          expanded.liveSlots == previous.liveSlots &&
                          recordWords == retainedWords,
                      "page growth must replace only page storage");
            }
            copied =
                std::memcmp(expanded.mappings, previous.mappings,
                            previous.records * sizeof(previous.mappings[0])) == 0 &&
                std::memcmp(expanded.physicalByPage, previous.physicalByPage,
                            previous.pages * sizeof(previous.physicalByPage[0])) == 0 &&
                std::memcmp(expanded.slotByStartPage, previous.slotByStartPage,
                            previous.pages * sizeof(previous.slotByStartPage[0])) == 0 &&
                std::memcmp(expanded.liveSlots, previous.liveSlots,
                            ((previous.records + 63) / 64) * sizeof(amdtx::u64)) == 0 &&
                std::memcmp(expanded.leaves, previous.leaves,
                            (previous.pages / 512) * sizeof(previous.leaves[0])) == 0 &&
                std::memcmp(expanded.allocator.used, previous.allocator.used,
                            ((previous.pages + 63) / 64) * sizeof(amdtx::u64)) == 0 &&
                std::memcmp(expanded.allocator.ever, previous.allocator.ever,
                            ((previous.pages + 63) / 64) * sizeof(amdtx::u64)) == 0;
            check(copied, "metadata growth did not preserve an existing array");
            check(expanded.metadataBytes() == mapper_abi::metadataBytesFor(next) &&
                      expanded.records == next.records && expanded.pages == next.pages &&
                      expanded.allocator.poolPages == next.pages &&
                      expanded.allocator.maxMapPages == previous.allocator.maxMapPages &&
                      expanded.allocator.livePages == previous.allocator.livePages &&
                      expanded.allocator.peakPages == previous.allocator.peakPages &&
                      expanded.allocator.reusedAllocations == previous.allocator.reusedAllocations,
                  "metadata growth changed live accounting or failed to increase capacity");
            check(amdtx::findNextBitmapPage(expanded.liveSlots, previous.records,
                      expanded.records, true) == expanded.records &&
                  amdtx::findNextBitmapPage(expanded.allocator.used, previous.pages,
                      expanded.pages, true) == expanded.pages &&
                  amdtx::findNextBitmapPage(expanded.allocator.ever, previous.pages,
                      expanded.pages, true) == expanded.pages &&
                  isZeroed(expanded.mappings + previous.records,
                      (expanded.records - previous.records) * sizeof(expanded.mappings[0])) &&
                  isZeroed(expanded.physicalByPage + previous.pages,
                      (expanded.pages - previous.pages) * sizeof(expanded.physicalByPage[0])) &&
                  isZeroed(expanded.slotByStartPage + previous.pages,
                      (expanded.pages - previous.pages) * sizeof(expanded.slotByStartPage[0])) &&
                  isZeroed(expanded.leaves + previous.pages / 512,
                      ((expanded.pages - previous.pages) / 512) * sizeof(expanded.leaves[0])),
                  "new metadata capacity is not initially free and zeroed");
            for (unsigned i = previous.pages / 512; i < expanded.pages / 512; ++i)
                expanded.leaves[i] = preparedLeaves[i];

            if (recordsGrowing) {
                static_cast<amdmapper::RecordStorage &>(metadata) = expanded;
                recordWords.swap(expandedWords);
            } else {
                static_cast<amdmapper::IovaPageStorage &>(metadata) = expanded;
                pageWords.swap(expandedWords);
            }
            // expandedWords releases only the replaced store at this scope boundary.
        }
        current = next;
        check(tableWords == retainedTables && pageTables.rootPA == retainedRoot &&
                  pageTables.pages == retainedTablePages,
              "metadata growth changed the retained page tables or PTEs");
        // Recheck translations after the replaced allocation has been freed.
        return copied && verifyLiveTranslations();
    };

    // Include normal reuse so the migration must retain a nonzero reuse count.
    check(allocateMapping(1) == AllocationResult::mapped, "initial mapping failed");
    if (!releaseMapping(0)) return;
    for (unsigned i = 0; i < current.records; ++i) {
        const auto result = allocateMapping(1);
        check(result == AllocationResult::mapped, "legacy record fill failed early");
        if (result != AllocationResult::mapped) return;
    }
    check(allocator.reusedAllocations != 0, "the setup did not exercise allocator reuse");
    check(allocateMapping(1) == AllocationResult::recordsFull,
          "legacy record exhaustion was not detected");
    if (!growStorage(mapper_abi::CapacityResource::recordSlots, {2048, 4096})) return;
    check(allocateMapping(1) == AllocationResult::mapped,
          "record-limited mapping did not succeed after metadata growth");

    // Fill each page window with larger maps while record capacity stays 2048.
    const unsigned pageCapacities[] = {8192, 16384};
    for (unsigned nextPages : pageCapacities) {
        while (allocator.livePages < allocator.poolPages) {
            const unsigned remaining = allocator.poolPages - allocator.livePages;
            const unsigned pages = remaining < allocator.maxMapPages
                ? remaining : allocator.maxMapPages;
            const auto result = allocateMapping(pages);
            check(result == AllocationResult::mapped, "page fill failed before the current limit");
            if (result != AllocationResult::mapped) return;
        }
        check(liveCount < current.records, "page fill unexpectedly exhausted record slots");
        check(allocateMapping(1) == AllocationResult::pagesFull,
              "page exhaustion was not detected");
        if (!growStorage(mapper_abi::CapacityResource::iovaPages, {2048, nextPages})) return;
        check(allocateMapping(1) == AllocationResult::mapped,
              "page-limited mapping did not succeed after metadata growth");
    }
    if (!verifyLiveTranslations()) return;
    check(current.records == 2048 && current.pages == 16384,
          "live growth changed capacity that the workload did not exhaust");

    // Old storage has been freed; each live mapping must still resolve and retire.
    for (unsigned slot = 0; slot < metadata.records; ++slot) {
        if (!(metadata.liveSlots[slot / 64] & (1ULL << (slot % 64)))) continue;
        if (!releaseMapping(slot)) return;
    }
    check(liveCount == 0 && allocator.livePages == 0 &&
              amdtx::findNextBitmapPage(allocator.used, 0, metadata.pages, true) == metadata.pages &&
              amdtx::findNextBitmapPage(metadata.liveSlots, 0, metadata.records, true) == metadata.records,
          "metadata growth left live allocations after the final release");
}

// A few live records at high slot numbers exercise the widened owner index
// without filling tens of thousands of mappings just to reach those slots.
void wideRecordOwners() {
    const mapper_abi::Capacity initial{65536, 65536};
    std::vector<amdtx::u64> recordWords(
        mapper_abi::recordStorageBytesFor(initial.records) / sizeof(amdtx::u64));
    std::vector<amdtx::u64> pageWords(
        mapper_abi::iovaPageStorageBytesFor(initial.pages) / sizeof(amdtx::u64));
    amdmapper::MappingStorage metadata{};
    amdmapper::bindRecordStorage(metadata, recordWords.data(), initial.records);
    amdmapper::bindIovaPageStorage(metadata, pageWords.data(), initial.pages);
    amdtx::u64 leafWords[512] = {};
    metadata.leaves[0] = leafWords;
    std::vector<std::pair<unsigned, unsigned>> live;

    const auto mapAtSlot = [&](unsigned slot) {
        unsigned base = 0;
        const bool allocated = slot < metadata.records &&
            amdtx::allocate(metadata.allocator, 1, base);
        check(allocated, "wide-slot mapping could not allocate an IOVA page");
        if (!allocated) return false;
        auto &mapping = metadata.mappings[slot];
        mapping.memory = reinterpret_cast<IOMemoryDescriptor *>(
            static_cast<std::uintptr_t>(0x100000 + slot * 16));
        mapping.command = reinterpret_cast<IODMACommand *>(
            static_cast<std::uintptr_t>(0x200000 + slot * 16));
        auto &record = mapping.record;
        record.handle = slot + 1;
        record.recordIndex = slot;
        record.basePage = base;
        record.pages = record.runs = 1;
        record.mapAddress = mapper_abi::kBase + base * 4096ULL;
        record.firstPA = 0x500000000ULL + base * 4096ULL;
        record.mapLength = record.length = 4096;
        record.options = 3;
        record.state = mapper_abi::kMapPublished | mapper_abi::kMapConfirmed;
        metadata.physicalByPage[base] = record.firstPA;
        metadata.slotByStartPage[base] = static_cast<uint32_t>(slot + 1);
        metadata.liveSlots[slot / 64] |= 1ULL << (slot % 64);
        metadata.leaves[base / 512][base % 512] = amdpte::makeDefaultLeaf(
            1, record.firstPA, amdpte::PTE_IR | amdpte::PTE_IW);
        live.emplace_back(slot, base);
        return true;
    };
    const auto verifyOwners = [&]() {
        for (const auto &entry : live) {
            const uint32_t owner = metadata.slotByStartPage[entry.second];
            const bool found = owner == entry.first + 1 && owner <= metadata.records;
            check(found, "wide record owner was truncated or lost during migration");
            if (!found) return false;
            const auto &record = metadata.mappings[owner - 1].record;
            const auto translated = amdpte::decodePte(
                metadata.leaves[entry.second / 512][entry.second % 512], 1);
            const bool matches = record.recordIndex == entry.first &&
                record.basePage == entry.second &&
                (metadata.liveSlots[entry.first / 64] & (1ULL << (entry.first % 64))) &&
                translated.kind == amdpte::PTE_LEAF_DEFAULT &&
                translated.outPA == record.firstPA &&
                metadata.physicalByPage[entry.second] == record.firstPA;
            check(matches, "owner lookup no longer identifies the retained mapping");
            if (!matches) return false;
        }
        return true;
    };
    if (!mapAtSlot(65534) || !mapAtSlot(65535) || !verifyOwners()) return;

    mapper_abi::Capacity target{};
    const bool planned = mapper_abi::nextCapacity(initial, mapper_abi::kProfileDma32Max,
        mapper_abi::CapacityResource::recordSlots, target);
    check(planned && target.records == 131072 && target.pages == initial.pages,
          "wide record growth did not preserve the independent page capacity");
    if (!planned) return;
    const amdmapper::IovaPageStorage retainedPages = metadata;
    const auto retainedPageWords = pageWords;
    {
        std::vector<amdtx::u64> expandedWords(
            mapper_abi::recordStorageBytesFor(target.records) / sizeof(amdtx::u64));
        amdmapper::RecordStorage expanded{};
        amdmapper::bindRecordStorage(expanded, expandedWords.data(), target.records);
        amdmapper::copyRecordStorage(expanded, metadata);
        static_cast<amdmapper::RecordStorage &>(metadata) = expanded;
        recordWords.swap(expandedWords);
        // The old record store is freed; the original page store remains owned.
    }
    check(metadata.pageMemory == retainedPages.pageMemory &&
              metadata.pageBytes == retainedPages.pageBytes &&
              metadata.physicalByPage == retainedPages.physicalByPage &&
              metadata.slotByStartPage == retainedPages.slotByStartPage &&
              metadata.leaves == retainedPages.leaves &&
              metadata.allocator.used == retainedPages.allocator.used &&
              metadata.allocator.ever == retainedPages.allocator.ever &&
              metadata.allocator.poolPages == retainedPages.allocator.poolPages &&
              metadata.allocator.livePages == retainedPages.allocator.livePages &&
              metadata.allocator.peakPages == retainedPages.allocator.peakPages &&
              metadata.allocator.reusedAllocations == retainedPages.allocator.reusedAllocations &&
              pageWords == retainedPageWords,
          "wide record growth moved or modified page storage");
    if (!verifyOwners() || !mapAtSlot(65536) || !mapAtSlot(131071) ||
            !verifyOwners()) return;

    // Resolve each mapping by the same slot+1 owner index used by unmap.
    for (const auto &entry : live) {
        const uint32_t owner = metadata.slotByStartPage[entry.second];
        auto &mapping = metadata.mappings[owner - 1];
        const auto &record = mapping.record;
        const bool released = amdtx::release(metadata.allocator, record.basePage, record.pages);
        check(released, "a wide-slot mapping could not release its retained IOVA");
        if (!released) return;
        metadata.leaves[record.basePage / 512][record.basePage % 512] = 0;
        metadata.slotByStartPage[record.basePage] = 0;
        metadata.liveSlots[(owner - 1) / 64] &= ~(1ULL << ((owner - 1) % 64));
        mapping.memory = nullptr;
        mapping.command = nullptr;
    }
    check(metadata.allocator.livePages == 0 &&
              amdtx::findNextBitmapPage(metadata.allocator.used, 0, metadata.pages, true) ==
                  metadata.pages &&
              amdtx::findNextBitmapPage(metadata.liveSlots, 0, metadata.records, true) ==
                  metadata.records,
          "wide-slot mappings did not fully retire after metadata migration");
    for (const auto &entry : live) {
        check(metadata.slotByStartPage[entry.second] == 0 &&
                  metadata.leaves[entry.second / 512][entry.second % 512] == 0,
              "a retired wide-slot mapping left an owner or PTE behind");
    }
}

} // namespace

int main() {
    allocationEquivalence();
    profileTable();
    storageArithmetic();
    devicePolicy();
    growthPolicy();
    capacitySemantics();
    liveCapacityGrowth();
    wideRecordOwners();
    if (failures) {
        std::printf("CAPACITY_FAILURES=%d\n", failures);
        return 1;
    }
    std::printf("CAPACITY_OK\n");
    return 0;
}
