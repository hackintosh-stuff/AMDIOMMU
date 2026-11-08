// Host regression for capacity profiles and live allocator growth.
//
// These properties are checked against the same
// headers the kext compiles:
//
//   1. The runtime-sized allocator behaves EXACTLY like the compile-time one
//      it replaces, preserving the accepted legacy allocation behaviour.
//   2. The profile table exposes the documented capacities and unknown names
//      are refused instead of silently widening the arena.
//   3. The arena arithmetic in amd_iommu_mapper_abi.hpp matches the carve
//      order in AMDMapperProbeMapper.cpp.
//   4. Opening preallocated capacity preserves live allocations and PTEs.
// This host test does not execute the kext's MapMemory or hardware commands.
#include <cstdint>
#include <cstdio>
#include <cstring>

#include <utility>
#include <vector>

#include "../probe/amd_iommu_mapper_abi.hpp"
#include "../probe/amd_iommu_tx_core.hpp"

namespace {

int failures;

void check(bool ok, const char *what) {
    if (!ok) {
        std::printf("FAIL %s\n", what);
        ++failures;
    }
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
    check(mapper_abi::kProfileRl10gMax.records == 65535,
          "measurement ceiling must use the largest UInt16 slot count");
}

void arenaArithmetic() {
    // Hand-computed from the carve order in AMDMapperProbeMapper.cpp:
    // 1024*120 + 4096*8 + 4096*2 + 128 + 8*8 + 2*64*8 = 165056 -> 167936.
    check(mapper_abi::arenaBytesFor(mapper_abi::kProfileLegacy) == 167936ULL,
          "legacy arena size does not match the ABI3 footprint");
    // 16384*120 + 131072*8 + 131072*2 + 256*8 + 256*8 + 2*2048*8 = 3313664,
    // already a whole number of pages.
    check(mapper_abi::arenaBytesFor(mapper_abi::kProfileRl10g) == 3313664ULL,
          "rl-10g arena size does not match the documented footprint");
    check(mapper_abi::arenaBytesFor(mapper_abi::kProfileRl10g) <
              mapper_abi::kMaxArenaBytes,
          "rl-10g arena exceeds the wired-memory guard");
    // Ceiling profile: 65535*120 + 262144*8 + 262144*2 + 1024*8 + 512*8 +
    // 2*4096*8 = 10563464 -> 10563584.
    check(mapper_abi::arenaBytesFor(mapper_abi::kProfileRl10gMax) == 10563584ULL,
          "rl-10g-max arena size does not match the documented footprint");
    check(mapper_abi::arenaBytesFor(mapper_abi::kProfileRl10gMax) <
              mapper_abi::kMaxArenaBytes,
          "rl-10g-max arena exceeds the wired-memory guard");
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
    // Open the next usable capacity profile without exceeding the reservation.
    const auto &legacy = mapper_abi::kProfileLegacy;
    const auto &rl10g = mapper_abi::kProfileRl10g;
    const auto &ceiling = mapper_abi::kProfileRl10gMax;
    check(mapper_abi::nextCapacityProfile(&legacy, &ceiling) == &rl10g,
          "legacy capacity must open the intermediate profile first");
    check(mapper_abi::nextCapacityProfile(&legacy, &rl10g) == &rl10g,
          "a 512 MiB ceiling must still be reachable from the legacy arena");
    check(mapper_abi::nextCapacityProfile(&rl10g, &ceiling) == &ceiling,
          "a domain below its ceiling must still be able to grow");
    check(mapper_abi::nextCapacityProfile(&ceiling, &ceiling) == nullptr,
          "a domain already at its ceiling must not grow");
    check(mapper_abi::nextCapacityProfile(&ceiling, &rl10g) == nullptr,
          "growth must never shrink the arena");
    check(mapper_abi::nextCapacityProfile(&legacy, &legacy) == nullptr,
          "a forced legacy ceiling must disable growth entirely");
    check(mapper_abi::nextCapacityProfile(nullptr, &ceiling) == nullptr,
          "a missing prepared profile must not grow");
    check(mapper_abi::nextCapacityProfile(&legacy, nullptr) == nullptr,
          "a missing ceiling must not grow");
    // A ceiling that cannot describe its own window must be refused: growth would
    // otherwise install a table area smaller than the IOVA range it advertises.
    mapper_abi::Profile shortTables = ceiling;
    shortTables.tablePages = ceiling.pages / 512;
    check(mapper_abi::nextCapacityProfile(&legacy, &shortTables) == nullptr,
          "a ceiling that does not cover its own leaf tables must be refused");
    // The grown window must keep the measured peak (52,227 pages) covered
    // with headroom, and the grown arena must stay inside the wired-memory guard.
    check(ceiling.pages >= 4 * 52227,
          "the growth ceiling no longer covers the measured 10 GbE peak");
    check(mapper_abi::arenaBytesFor(ceiling) <= mapper_abi::kMaxArenaBytes,
          "the growth ceiling exceeds the wired-memory guard");
}

void liveCapacityGrowth() {
    const auto &ceiling = mapper_abi::kProfileRl10gMax;
    const mapper_abi::Profile *current = &mapper_abi::kProfileLegacy;
    std::vector<amdtx::u64> used(ceiling.pages / 64), ever(ceiling.pages / 64);
    std::vector<amdtx::u64> liveSlots((ceiling.records + 63) / 64);
    std::vector<mapper_abi::RecordHeader> records(ceiling.records);
    std::vector<amdtx::u64> tableWords(ceiling.tablePages * 512);
    std::vector<volatile amdtx::u64 *> leaves(ceiling.pages / 512);
    amdtx::RuntimeAllocator allocator{used.data(), ever.data(), current->pages,
                                      current->mapPages, 0, 0, 0};
    const amdtx::u64 tablePA = 0x1000000ULL;
    amdsparse::Arena pageTables{tableWords.data(), tablePA, ceiling.tablePages,
                                1, 4, tablePA, 0, 0, nullptr};
    for (unsigned i = 0; i < leaves.size(); ++i) {
        leaves[i] = amdtx::prepareAt(pageTables,
            mapper_abi::kBase + static_cast<amdtx::u64>(i) * 0x200000ULL, 512);
        check(leaves[i] != nullptr, "ceiling page-table reservation is too small");
        if (!leaves[i]) return;
    }

    enum class AllocationResult { mapped, recordsFull, pagesFull };
    unsigned liveCount = 0;
    const auto allocateMapping = [&](unsigned pages) {
        const unsigned slot = amdtx::findNextBitmapPage(
            liveSlots.data(), 0, current->records, false);
        if (slot == current->records) return AllocationResult::recordsFull;
        unsigned base = 0;
        if (!amdtx::allocate(allocator, pages, base)) return AllocationResult::pagesFull;
        auto &record = records[slot];
        record.handle = slot + 1;
        record.recordIndex = slot;
        record.basePage = base;
        record.pages = pages;
        record.mapAddress = mapper_abi::kBase + base * 4096ULL;
        record.firstPA = 0x400000000ULL + base * 4096ULL;
        record.mapLength = record.length = pages * 4096ULL;
        record.runs = 1;
        for (unsigned i = 0; i < pages; ++i) {
            const unsigned page = base + i;
            leaves[page / 512][page % 512] = amdpte::makeDefaultLeaf(
                1, record.firstPA + i * 4096ULL, amdpte::PTE_IR | amdpte::PTE_IW);
        }
        liveSlots[slot / 64] |= 1ULL << (slot % 64);
        ++liveCount;
        return AllocationResult::mapped;
    };
    const auto verifyLiveTranslations = [&]() {
        bool valid = true;
        const auto readEntry = [&](amdtx::u64 pa, unsigned index) -> amdtx::u64 {
            const auto *table = amdsparse::table(pageTables, pa);
            return table ? table[index] : 0;
        };
        for (unsigned slot = 0; slot < liveCount && valid; ++slot) {
            const auto &record = records[slot];
            for (unsigned i = 0; i < record.pages; ++i) {
                const auto walk = amdpte::walkPageTable(readEntry, pageTables.rootLevel,
                    pageTables.rootPA, record.mapAddress + i * 4096ULL);
                if (!walk.ok || walk.outPA != record.firstPA + i * 4096ULL) {
                    valid = false;
                    break;
                }
            }
        }
        check(valid, "capacity growth changed an existing IOVA translation");
        return valid;
    };
    const auto openNextCapacity = [&](const mapper_abi::Profile &expected) {
        const auto *next = mapper_abi::nextCapacityProfile(current, &ceiling);
        check(next == &expected, "capacity exhaustion selected the wrong next profile");
        if (next != &expected) return false;
        const auto retainedTables = tableWords;
        const auto retainedUsed = used;
        const auto retainedEver = ever;
        const auto retainedSlots = liveSlots;
        const std::vector<mapper_abi::RecordHeader> retainedRecords(
            records.begin(), records.begin() + liveCount);
        const auto retainedAllocator = allocator;
        const auto retainedLeaves = leaves;
        const auto retainedRoot = pageTables.rootPA;
        const auto retainedTablePages = pageTables.pages;

        // Storage and page-table geometry are already reserved at the ceiling.
        current = next;
        allocator.poolPages = current->pages;

        check(tableWords == retainedTables && leaves == retainedLeaves &&
                  pageTables.rootPA == retainedRoot && pageTables.pages == retainedTablePages,
              "opening capacity changed the reserved page-table layout or PTEs");
        check(used == retainedUsed && ever == retainedEver && liveSlots == retainedSlots,
              "opening capacity changed the live allocation bitmaps");
        check(allocator.used == retainedAllocator.used && allocator.ever == retainedAllocator.ever &&
                  allocator.livePages == retainedAllocator.livePages &&
                  allocator.peakPages == retainedAllocator.peakPages &&
                  allocator.reusedAllocations == retainedAllocator.reusedAllocations,
              "opening capacity moved bitmap storage or reset live accounting");
        check(std::memcmp(records.data(), retainedRecords.data(),
                          liveCount * sizeof(records[0])) == 0,
              "opening capacity changed an existing mapping record");
        return verifyLiveTranslations();
    };

    // Fill record capacity while keeping free pages, then retry the same map.
    for (unsigned i = 0; i < current->records; ++i) {
        const auto result = allocateMapping(1);
        check(result == AllocationResult::mapped, "legacy record fill failed early");
        if (result != AllocationResult::mapped) return;
    }
    check(allocateMapping(1) == AllocationResult::recordsFull,
          "legacy record exhaustion was not detected");
    if (!openNextCapacity(mapper_abi::kProfileRl10g)) return;
    check(allocateMapping(1) == AllocationResult::mapped,
          "record-limited mapping did not succeed after capacity growth");

    // Fill the page window with larger maps, leaving record slots available.
    while (allocator.livePages < allocator.poolPages) {
        const unsigned remaining = allocator.poolPages - allocator.livePages;
        const unsigned pages = remaining < current->mapPages ? remaining : current->mapPages;
        const auto result = allocateMapping(pages);
        check(result == AllocationResult::mapped, "intermediate page fill failed early");
        if (result != AllocationResult::mapped) return;
    }
    check(liveCount < current->records, "page fill unexpectedly exhausted record slots");
    check(allocateMapping(1) == AllocationResult::pagesFull,
          "intermediate page exhaustion was not detected");
    if (!openNextCapacity(ceiling)) return;
    check(allocateMapping(1) == AllocationResult::mapped,
          "page-limited mapping did not succeed after capacity growth");
    if (!verifyLiveTranslations()) return;
    check(mapper_abi::nextCapacityProfile(current, &ceiling) == nullptr,
          "capacity growth exceeded the reserved ceiling");

    // Every mapping made before and after both growth steps remains releasable.
    for (unsigned slot = 0; slot < liveCount; ++slot) {
        const auto &record = records[slot];
        check(amdtx::release(allocator, record.basePage, record.pages),
              "a live mapping could not be released after capacity growth");
        for (unsigned i = 0; i < record.pages; ++i) {
            const unsigned page = record.basePage + i;
            leaves[page / 512][page % 512] = 0;
        }
        liveSlots[slot / 64] &= ~(1ULL << (slot % 64));
    }
    check(allocator.livePages == 0 &&
              amdtx::findNextBitmapPage(used.data(), 0, current->pages, true) == current->pages &&
              amdtx::findNextBitmapPage(liveSlots.data(), 0, current->records, true) == current->records,
          "capacity growth left live allocations after the final release");
}

} // namespace

int main() {
    allocationEquivalence();
    profileTable();
    arenaArithmetic();
    devicePolicy();
    growthPolicy();
    capacitySemantics();
    liveCapacityGrowth();
    if (failures) {
        std::printf("CAPACITY_FAILURES=%d\n", failures);
        return 1;
    }
    std::printf("CAPACITY_OK\n");
    return 0;
}
