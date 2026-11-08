// Host regression for capacity profiles and independent live allocator growth.
//
// These properties are checked against the same
// headers the kext compiles:
//
//   1. The runtime-sized allocator behaves EXACTLY like the compile-time one
//      it replaces, preserving the accepted legacy allocation behaviour.
//   2. The profile table exposes the documented capacities and unknown names
//      are refused instead of silently widening the metadata.
//   3. Retained record and page chunks match shared byte accounting.
//   4. Either resource grows by appending capacity without moving existing chunks.
//   5. Record owners above 65535 remain addressable across growth and release.
//   6. One contiguous IOVA allocation and its export can cross page chunks.
// Page tables are prebuilt here to isolate metadata growth; incremental
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

using RecordChunkWords = std::vector<std::vector<amdtx::u64>>;
using PageChunkWords = std::vector<std::vector<amdtx::u64>>;

void prepareRecordStorage(amdmapper::RecordStorage &storage,
                          RecordChunkWords &words, unsigned records) {
    amdmapper::initializeRecordStorage(storage);
    words.reserve(amdmapper::kMaxRecordChunks);
    while (storage.records < records) {
        unsigned added = storage.records ? storage.records : mapper_abi::kRecords;
        if (added > records - storage.records) added = records - storage.records;
        words.emplace_back(mapper_abi::recordChunkBytesFor(added) / sizeof(amdtx::u64));
        amdmapper::RecordChunk chunk{};
        amdmapper::bindRecordChunk(chunk, words.back().data(), storage.records, added);
        amdmapper::appendRecordChunk(storage, chunk);
    }
}

bool recordChunksRetained(amdmapper::RecordStorage &storage,
                         const std::vector<amdmapper::RecordChunk> &before,
                         const RecordChunkWords &contents) {
    if (storage.recordChunkCount < before.size() || contents.size() < before.size() ||
            storage.liveSlots.storage != &storage)
        return false;
    for (unsigned i = 0; i < before.size(); ++i) {
        const auto &old = before[i];
        const auto &chunk = storage.recordChunks[i];
        if (chunk.memory != old.memory || chunk.bytes != old.bytes ||
                chunk.firstRecord != old.firstRecord || chunk.records != old.records ||
                chunk.mappings != old.mappings || chunk.liveSlots != old.liveSlots ||
                &storage.chunkAtRecord(old.firstRecord) != &storage.recordChunks[i] ||
                &storage.mappingAt(old.firstRecord) != old.mappings ||
                &storage.mappingAt(old.firstRecord + old.records - 1) !=
                    old.mappings + old.records - 1 ||
                &storage.liveSlots[old.firstRecord / 64] != old.liveSlots ||
                std::memcmp(chunk.memory, contents[i].data(), chunk.bytes) != 0)
            return false;
    }
    return true;
}

// Keep the owner object in place: its allocator views refer to its chunk list.
// Build the same geometric sequence as the production growth path.
void preparePageStorage(amdmapper::IovaPageStorage &storage,
                        PageChunkWords &words, unsigned pages) {
    amdmapper::initializeIovaPageStorage(storage);
    words.reserve(sizeof(storage.chunks) / sizeof(storage.chunks[0]));
    while (storage.pages < pages) {
        unsigned added = storage.pages ? storage.pages : mapper_abi::kPages;
        if (added > pages - storage.pages) added = pages - storage.pages;
        words.emplace_back(mapper_abi::iovaPageChunkBytesFor(added) / sizeof(amdtx::u64));
        amdmapper::IovaPageChunk chunk{};
        amdmapper::bindIovaPageChunk(chunk, words.back().data(), storage.pages, added);
        amdmapper::appendIovaPageChunk(storage, chunk);
    }
}

bool pageChunksRetained(amdmapper::IovaPageStorage &storage,
                       const std::vector<amdmapper::IovaPageChunk> &before,
                       const PageChunkWords &contents) {
    if (storage.pageChunkCount < before.size() || contents.size() < before.size())
        return false;
    for (unsigned i = 0; i < before.size(); ++i) {
        const auto &old = before[i];
        const auto &chunk = storage.chunks[i];
        if (chunk.memory != old.memory || chunk.bytes != old.bytes ||
                chunk.firstPage != old.firstPage || chunk.pages != old.pages ||
                chunk.physicalByPage != old.physicalByPage ||
                chunk.slotByStartPage != old.slotByStartPage ||
                chunk.leaves != old.leaves || chunk.used != old.used || chunk.ever != old.ever ||
                &storage.chunkAtPage(old.firstPage) != &storage.chunks[i] ||
                &storage.physicalPage(old.firstPage) != old.physicalByPage ||
                &storage.startPageOwner(old.firstPage) != old.slotByStartPage ||
                &storage.leafTable(old.firstPage / 512) != old.leaves ||
                &storage.allocator.used[old.firstPage / 64] != old.used ||
                &storage.allocator.ever[old.firstPage / 64] != old.ever ||
                std::memcmp(chunk.memory, contents[i].data(), chunk.bytes) != 0)
            return false;
    }
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
    for (const auto &range : live) {
        const bool releasedFixed = amdtx::release(fixed, range.first, range.second);
        const bool releasedRuntime = amdtx::release(runtime, range.first, range.second);
        check(releasedFixed && releasedRuntime,
              "equivalent allocators could not release a retained range");
    }
    for (std::size_t i = 0; i < 4096 / 64; ++i) {
        check(fixed.used[i] == 0 && used[i] == 0,
              "equivalent allocators did not return every page");
    }
    check(fixed.livePages == 0 && runtime.livePages == 0 &&
              fixed.peakPages == runtime.peakPages &&
              fixed.reusedAllocations == runtime.reusedAllocations &&
              std::memcmp(fixed.ever, ever, sizeof(ever)) == 0,
          "draining equivalent allocators changed accounting or reuse history");
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
    check(mapper_abi::recordStorageBytesFor(16384) == 1986560ULL &&
              mapper_abi::iovaPageStorageBytesFor(131072) == 1626112ULL &&
              mapper_abi::metadataBytesFor(mapper_abi::kProfileRl10g) == 3612672ULL,
          "rl-10g metadata size does not match the documented footprint");
    check(mapper_abi::metadataBytesFor(mapper_abi::kProfileRl10g) <
              mapper_abi::kMaxMetadataBytes,
          "rl-10g metadata exceeds the wired-memory guard");
    check(mapper_abi::metadataBytesFor(mapper_abi::kProfileRl10gMax) == 11128832ULL,
          "rl-10g-max metadata size does not match the documented footprint");
    check(mapper_abi::metadataBytesFor(mapper_abi::kProfileRl10gMax) <
              mapper_abi::kMaxMetadataBytes,
          "rl-10g-max metadata exceeds the wired-memory guard");
    check(mapper_abi::metadataBytesFor(mapper_abi::kProfileDma32Max) == 22216704ULL &&
              mapper_abi::metadataBytesFor(mapper_abi::kProfileDma32Max) <
              mapper_abi::kMaxMetadataBytes,
          "dma32-max metadata footprint is wrong or exceeds the wired-memory guard");
    check(mapper_abi::recordChunkBytesFor(1024) == 126976ULL &&
              mapper_abi::recordStorageBytesFor(2048) == 253952ULL &&
              mapper_abi::metadataBytesFor(mapper_abi::Capacity{2048, 4096}) == 307200ULL,
          "record-only growth allocated more than its actual metadata capacity");
    check(mapper_abi::iovaPageStorageBytesFor(8192) == 106496ULL &&
              mapper_abi::iovaPageStorageBytesFor(16384) == 208896ULL &&
              mapper_abi::metadataBytesFor(mapper_abi::Capacity{1024, 8192}) == 233472ULL &&
              mapper_abi::metadataBytesFor(mapper_abi::Capacity{1024, 16384}) == 335872ULL,
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
    RecordChunkWords recordWords;
    PageChunkWords pageWords;
    amdmapper::MappingStorage metadata{};
    prepareRecordStorage(metadata, recordWords, current.records);
    preparePageStorage(metadata, pageWords, current.pages);
    auto &allocator = metadata.allocator;
    check(metadata.metadataBytes() == mapper_abi::metadataBytesFor(current) &&
              metadata.metadataBytes() < mapper_abi::metadataBytesFor(ceiling) &&
              metadata.recordChunkCount == 1 && metadata.pageChunkCount == 1,
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
        if (i < metadata.pages / 512) metadata.leafTable(i) = preparedLeaves[i];
    }

    enum class AllocationResult { mapped, recordsFull, pagesFull };
    unsigned liveCount = 0;
    const auto allocateMapping = [&](unsigned pages) {
        const unsigned slot = amdtx::findNextBitmapPage(
            metadata.liveSlots, 0, metadata.records, false);
        if (slot == metadata.records) return AllocationResult::recordsFull;
        unsigned base = 0;
        if (!amdtx::allocate(allocator, pages, base)) return AllocationResult::pagesFull;
        auto &mapping = metadata.mappingAt(slot);
        // Opaque identities are retained and compared, never dereferenced by this test.
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
            metadata.physicalPage(page) = record.firstPA + i * 4096ULL;
            metadata.leafTable(page / 512)[page % 512] = amdpte::makeDefaultLeaf(
                1, metadata.physicalPage(page), amdpte::PTE_IR | amdpte::PTE_IW);
        }
        metadata.startPageOwner(base) = static_cast<uint32_t>(slot + 1);
        metadata.liveSlots[slot / 64] |= 1ULL << (slot % 64);
        ++liveCount;
        return AllocationResult::mapped;
    };
    const auto releaseMapping = [&](unsigned slot) {
        auto &mapping = metadata.mappingAt(slot);
        const auto &record = mapping.record;
        const unsigned owner = metadata.startPageOwner(record.basePage);
        const bool owned = owner == slot + 1 &&
            (metadata.liveSlots[slot / 64] & (1ULL << (slot % 64)));
        check(owned, "metadata growth lost a live mapping's owner index");
        if (!owned) return false;
        const bool released = amdtx::release(allocator, record.basePage, record.pages);
        check(released, "a live mapping could not be released after metadata growth");
        if (!released) return false;
        for (unsigned i = 0; i < record.pages; ++i) {
            const unsigned page = record.basePage + i;
            metadata.leafTable(page / 512)[page % 512] = 0;
        }
        metadata.startPageOwner(record.basePage) = 0;
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
            const auto &record = metadata.mappingAt(slot).record;
            for (unsigned i = 0; i < record.pages; ++i) {
                const auto walk = amdpte::walkPageTable(readEntry, pageTables.rootLevel,
                    pageTables.rootPA, record.mapAddress + i * 4096ULL);
                if (!walk.ok || walk.outPA != record.firstPA + i * 4096ULL ||
                    metadata.physicalPage(record.basePage + i) != walk.outPA) {
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
        const unsigned retainedRecordChunkCount = metadata.recordChunkCount;
        const std::vector<amdmapper::RecordChunk> retainedRecords(
            metadata.recordChunks, metadata.recordChunks + retainedRecordChunkCount);
        const unsigned retainedPageChunkCount = metadata.pageChunkCount;
        const std::vector<amdmapper::IovaPageChunk> retainedPages(
            metadata.chunks, metadata.chunks + retainedPageChunkCount);
        const auto retainedPageWords = pageWords;
        const auto retainedRecordWords = recordWords;
        const auto retainedTables = tableWords;
        const auto retainedRoot = pageTables.rootPA;
        const auto retainedTablePages = pageTables.pages;
        const auto *retainedAllocator = &allocator;
        const auto *retainedRecordBitmap = &metadata.liveSlots;
        const unsigned retainedMaxMapPages = allocator.maxMapPages;
        const unsigned retainedLivePages = allocator.livePages;
        const unsigned retainedPeakPages = allocator.peakPages;
        const unsigned retainedReusedAllocations = allocator.reusedAllocations;
        const bool recordsGrowing = resource == mapper_abi::CapacityResource::recordSlots;
        if (recordsGrowing) {
            const unsigned addedRecords = next.records - current.records;
            recordWords.emplace_back(
                mapper_abi::recordChunkBytesFor(addedRecords) / sizeof(amdtx::u64));
            amdmapper::RecordChunk added{};
            amdmapper::bindRecordChunk(added, recordWords.back().data(),
                                       current.records, addedRecords);
            check(isZeroed(added.memory, added.bytes) &&
                      added.firstRecord == current.records && added.records == addedRecords &&
                      added.bytes == mapper_abi::recordChunkBytesFor(addedRecords) &&
                      metadata.records == current.records &&
                      metadata.recordChunkCount == retainedRecordChunkCount,
                  "staging a zeroed record chunk exposed capacity before append");
            amdmapper::appendRecordChunk(metadata, added);
        } else {
            const unsigned addedPages = next.pages - current.pages;
            pageWords.emplace_back(
                mapper_abi::iovaPageChunkBytesFor(addedPages) / sizeof(amdtx::u64));
            amdmapper::IovaPageChunk added{};
            amdmapper::bindIovaPageChunk(added, pageWords.back().data(),
                                         current.pages, addedPages);
            check(isZeroed(added.memory, added.bytes) && added.firstPage == current.pages &&
                      added.pages == addedPages &&
                      added.bytes == mapper_abi::iovaPageChunkBytesFor(addedPages) &&
                      metadata.pages == current.pages &&
                      metadata.pageChunkCount == retainedPageChunkCount &&
                      allocator.poolPages == current.pages,
                  "staging a zeroed page chunk exposed capacity before append");
            for (unsigned i = 0; i < added.pages / 512; ++i)
                added.leaves[i] = preparedLeaves[current.pages / 512 + i];
            amdmapper::appendIovaPageChunk(metadata, added);
        }
        const bool recordsRetained = recordChunksRetained(
            metadata, retainedRecords, retainedRecordWords);
        const bool pagesRetained = pageChunksRetained(metadata, retainedPages, retainedPageWords);
        check(recordsRetained && pagesRetained,
              "metadata growth moved or modified a retained record or page chunk");
        check(&metadata.allocator == retainedAllocator &&
                  &metadata.liveSlots == retainedRecordBitmap &&
                  allocator.maxMapPages == retainedMaxMapPages &&
                  allocator.livePages == retainedLivePages &&
                  allocator.peakPages == retainedPeakPages &&
                  allocator.reusedAllocations == retainedReusedAllocations &&
                  allocator.poolPages == next.pages && metadata.pages == next.pages &&
                  metadata.records == next.records &&
                  metadata.recordChunkCount == retainedRecordChunkCount + (recordsGrowing ? 1U : 0U) &&
                  metadata.pageChunkCount == retainedPageChunkCount + (recordsGrowing ? 0U : 1U) &&
                  metadata.recordBytes == mapper_abi::recordStorageBytesFor(next.records) &&
                  metadata.pageBytes == mapper_abi::iovaPageStorageBytesFor(next.pages) &&
                  metadata.metadataBytes() == mapper_abi::metadataBytesFor(next),
              "metadata growth reset allocator state or reported the wrong capacity");
        check(amdtx::findNextBitmapPage(metadata.liveSlots, current.records,
                  next.records, true) == next.records &&
                  amdtx::findNextBitmapPage(allocator.used, current.pages, next.pages, true) ==
                  next.pages &&
                  amdtx::findNextBitmapPage(allocator.ever, current.pages, next.pages, true) ==
                  next.pages,
              "appended metadata capacity was not initially free");
        current = next;
        check(tableWords == retainedTables && pageTables.rootPA == retainedRoot &&
                  pageTables.pages == retainedTablePages,
              "metadata growth changed the retained page tables or PTEs");
        return recordsRetained && pagesRetained && verifyLiveTranslations();
    };

    // Include normal reuse so page append must retain a nonzero reuse count.
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
    check(amdtx::findNextBitmapPage(metadata.liveSlots, 0, metadata.records, false) ==
              mapper_abi::kRecords,
          "the global record bitmap did not find the first appended slot");
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

    // Every original record and page chunk remains owned through the final unmap.
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
    RecordChunkWords recordWords;
    PageChunkWords pageWords;
    amdmapper::MappingStorage metadata{};
    prepareRecordStorage(metadata, recordWords, initial.records);
    preparePageStorage(metadata, pageWords, initial.pages);
    amdtx::u64 leafWords[512] = {};
    metadata.leafTable(0) = leafWords;
    std::vector<std::pair<unsigned, unsigned>> live;

    const auto mapAtSlot = [&](unsigned slot) {
        unsigned base = 0;
        const bool allocated = slot < metadata.records &&
            amdtx::allocate(metadata.allocator, 1, base);
        check(allocated, "wide-slot mapping could not allocate an IOVA page");
        if (!allocated) return false;
        auto &mapping = metadata.mappingAt(slot);
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
        metadata.physicalPage(base) = record.firstPA;
        metadata.startPageOwner(base) = static_cast<uint32_t>(slot + 1);
        metadata.liveSlots[slot / 64] |= 1ULL << (slot % 64);
        metadata.leafTable(base / 512)[base % 512] = amdpte::makeDefaultLeaf(
            1, record.firstPA, amdpte::PTE_IR | amdpte::PTE_IW);
        live.emplace_back(slot, base);
        return true;
    };
    const auto verifyOwners = [&]() {
        unsigned liveSlot = amdtx::findNextBitmapPage(
            metadata.liveSlots, 0, metadata.records, true);
        for (const auto &entry : live) {
            const uint32_t owner = metadata.startPageOwner(entry.second);
            const bool found = owner == entry.first + 1 && owner <= metadata.records &&
                liveSlot == entry.first;
            check(found, "wide owner lookup or global live-slot scan lost a mapping");
            if (!found) return false;
            const auto &record = metadata.mappingAt(owner - 1).record;
            const auto translated = amdpte::decodePte(
                metadata.leafTable(entry.second / 512)[entry.second % 512], 1);
            const bool matches = record.recordIndex == entry.first &&
                record.basePage == entry.second &&
                (metadata.liveSlots[entry.first / 64] & (1ULL << (entry.first % 64))) &&
                translated.kind == amdpte::PTE_LEAF_DEFAULT &&
                translated.outPA == record.firstPA &&
                metadata.physicalPage(entry.second) == record.firstPA;
            check(matches, "owner lookup no longer identifies the retained mapping");
            if (!matches) return false;
            liveSlot = amdtx::findNextBitmapPage(
                metadata.liveSlots, liveSlot + 1, metadata.records, true);
        }
        const bool complete = liveSlot == metadata.records;
        check(complete, "the record bitmap reports a live slot outside the mapping set");
        return complete;
    };
    if (!mapAtSlot(65534) || !mapAtSlot(65535) || !verifyOwners()) return;

    mapper_abi::Capacity target{};
    const bool planned = mapper_abi::nextCapacity(initial, mapper_abi::kProfileDma32Max,
        mapper_abi::CapacityResource::recordSlots, target);
    check(planned && target.records == 131072 && target.pages == initial.pages,
          "wide record growth did not preserve the independent page capacity");
    if (!planned) return;
    const unsigned retainedRecordChunkCount = metadata.recordChunkCount;
    const std::vector<amdmapper::RecordChunk> retainedRecords(
        metadata.recordChunks, metadata.recordChunks + retainedRecordChunkCount);
    const auto retainedRecordWords = recordWords;
    const auto *retainedRecordBitmap = &metadata.liveSlots;
    const unsigned retainedPageChunkCount = metadata.pageChunkCount;
    const std::vector<amdmapper::IovaPageChunk> retainedPages(
        metadata.chunks, metadata.chunks + retainedPageChunkCount);
    const auto retainedPageWords = pageWords;
    const auto *retainedAllocator = &metadata.allocator;
    const unsigned retainedMaxMapPages = metadata.allocator.maxMapPages;
    const unsigned retainedLivePages = metadata.allocator.livePages;
    const unsigned retainedPeakPages = metadata.allocator.peakPages;
    const unsigned retainedReusedAllocations = metadata.allocator.reusedAllocations;
    const unsigned addedRecords = target.records - initial.records;
    recordWords.emplace_back(
        mapper_abi::recordChunkBytesFor(addedRecords) / sizeof(amdtx::u64));
    amdmapper::RecordChunk added{};
    amdmapper::bindRecordChunk(added, recordWords.back().data(),
                               initial.records, addedRecords);
    check(isZeroed(added.memory, added.bytes) && metadata.records == initial.records &&
              metadata.recordChunkCount == retainedRecordChunkCount,
          "preparing the wide record chunk published capacity or nonzero metadata");
    amdmapper::appendRecordChunk(metadata, added);
    check(recordChunksRetained(metadata, retainedRecords, retainedRecordWords) &&
              metadata.recordChunkCount == retainedRecordChunkCount + 1 &&
              metadata.records == target.records &&
              metadata.recordBytes == mapper_abi::recordStorageBytesFor(target.records) &&
              &metadata.liveSlots == retainedRecordBitmap &&
              amdtx::findNextBitmapPage(metadata.liveSlots, initial.records,
                  target.records, true) == target.records,
          "wide record append moved old mappings or failed to add free slots");
    check(pageChunksRetained(metadata, retainedPages, retainedPageWords) &&
              metadata.pageChunkCount == retainedPageChunkCount &&
              metadata.pageBytes == mapper_abi::iovaPageStorageBytesFor(initial.pages) &&
              &metadata.allocator == retainedAllocator &&
              metadata.allocator.poolPages == initial.pages &&
              metadata.allocator.maxMapPages == retainedMaxMapPages &&
              metadata.allocator.livePages == retainedLivePages &&
              metadata.allocator.peakPages == retainedPeakPages &&
              metadata.allocator.reusedAllocations == retainedReusedAllocations,
          "wide record growth moved or modified page chunks");
    if (!verifyOwners() || !mapAtSlot(65536) || !mapAtSlot(131071) ||
            !verifyOwners()) return;

    // Resolve each mapping by the same slot+1 owner index used by unmap.
    for (const auto &entry : live) {
        const uint32_t owner = metadata.startPageOwner(entry.second);
        auto &mapping = metadata.mappingAt(owner - 1);
        const auto &record = mapping.record;
        const bool released = amdtx::release(metadata.allocator, record.basePage, record.pages);
        check(released, "a wide-slot mapping could not release its retained IOVA");
        if (!released) return;
        metadata.leafTable(record.basePage / 512)[record.basePage % 512] = 0;
        metadata.startPageOwner(record.basePage) = 0;
        metadata.liveSlots[(owner - 1) / 64] &= ~(1ULL << ((owner - 1) % 64));
        mapping.memory = nullptr;
        mapping.command = nullptr;
    }
    check(metadata.allocator.livePages == 0 &&
              amdtx::findNextBitmapPage(metadata.allocator.used, 0, metadata.pages, true) ==
                  metadata.pages &&
              amdtx::findNextBitmapPage(metadata.liveSlots, 0, metadata.records, true) ==
                  metadata.records,
          "wide-slot mappings did not fully retire after metadata growth");
    for (const auto &entry : live) {
        check(metadata.startPageOwner(entry.second) == 0 &&
                  metadata.leafTable(entry.second / 512)[entry.second % 512] == 0,
              "a retired wide-slot mapping left an owner or PTE behind");
    }
}

// Chunk boundaries describe metadata ownership, not separate IOVA pools.
void crossChunkAllocation() {
    amdmapper::IovaPageStorage storage{};
    PageChunkWords pageWords;
    preparePageStorage(storage, pageWords, mapper_abi::kPages);
    auto &allocator = storage.allocator;
    std::vector<std::pair<unsigned, unsigned>> prefix;
    const unsigned prefixPages = mapper_abi::kPages - 2;
    while (allocator.livePages < prefixPages) {
        const unsigned remaining = prefixPages - allocator.livePages;
        const unsigned pages = remaining < allocator.maxMapPages
            ? remaining : allocator.maxMapPages;
        const unsigned expectedBase = allocator.livePages;
        unsigned base = 0;
        const bool allocated = amdtx::allocate(allocator, pages, base);
        check(allocated && base == expectedBase, "cross-chunk setup lost its contiguous prefix");
        if (!allocated) return;
        prefix.emplace_back(base, pages);
    }
    constexpr unsigned mappingPages = 4;
    unsigned base = 0;
    check(!amdtx::allocate(allocator, mappingPages, base),
          "the initial page pool unexpectedly fits the cross-chunk mapping");

    pageWords.emplace_back(
        mapper_abi::iovaPageChunkBytesFor(mapper_abi::kPages) / sizeof(amdtx::u64));
    amdmapper::IovaPageChunk added{};
    amdmapper::bindIovaPageChunk(added, pageWords.back().data(),
                                 storage.pages, mapper_abi::kPages);
    amdmapper::appendIovaPageChunk(storage, added);
    const bool allocated = amdtx::allocate(allocator, mappingPages, base);
    check(allocated && base == prefixPages,
          "the global allocator could not span retained and appended page chunks");
    if (!allocated) return;
    check(&storage.chunkAtPage(base) != &storage.chunkAtPage(base + mappingPages - 1),
          "the allocation did not exercise both metadata chunks");

    amdtx::u64 leafWords[2][512] = {};
    storage.leafTable(base / 512) = leafWords[0];
    storage.leafTable((base + mappingPages - 1) / 512) = leafWords[1];
    const uint64_t physical[mappingPages] = {
        0x600003000ULL, 0x700005000ULL, 0x800009000ULL, 0x90000b000ULL};
    storage.startPageOwner(base) = 1;
    for (unsigned i = 0; i < mappingPages; ++i) {
        const unsigned page = base + i;
        storage.physicalPage(page) = physical[i];
        storage.leafTable(page / 512)[page % 512] = amdpte::makeDefaultLeaf(
            1, physical[i], amdpte::PTE_IR | amdpte::PTE_IW);
    }
    mapper_abi::Record exported{};
    exported.header.basePage = base;
    exported.header.pages = mappingPages;
    storage.copyPhysicalPages(base, mappingPages, exported.physical);
    for (unsigned i = 0; i < mappingPages; ++i) {
        const unsigned page = base + i;
        const auto translated = amdpte::decodePte(
            storage.leafTable(page / 512)[page % 512], 1);
        check(exported.physical[i] == physical[i] &&
                  translated.kind == amdpte::PTE_LEAF_DEFAULT &&
                  translated.outPA == exported.physical[i],
              "physical export or PTE lookup lost part of a cross-chunk mapping");
        storage.leafTable(page / 512)[page % 512] = 0;
    }
    storage.startPageOwner(base) = 0;
    check(amdtx::release(allocator, base, mappingPages),
          "the global allocator could not release a cross-chunk mapping");
    check(amdtx::findNextBitmapPage(allocator.used, base, base + mappingPages, true) ==
              base + mappingPages &&
              amdtx::findNextBitmapPage(allocator.ever, base, base + mappingPages, false) ==
                  base + mappingPages && storage.startPageOwner(base) == 0 &&
              isZeroed(leafWords, sizeof(leafWords)),
          "cross-chunk release lost reuse history or left an owner, PTE or live page");
    for (const auto &range : prefix)
        check(amdtx::release(allocator, range.first, range.second),
              "the retained prefix could not be released after page append");
    check(allocator.livePages == 0 &&
              amdtx::findNextBitmapPage(allocator.used, 0, storage.pages, true) == storage.pages,
          "the chunked IOVA pool did not fully drain");
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
    crossChunkAllocation();
    if (failures) {
        std::printf("CAPACITY_FAILURES=%d\n", failures);
        return 1;
    }
    std::printf("CAPACITY_OK\n");
    return 0;
}
