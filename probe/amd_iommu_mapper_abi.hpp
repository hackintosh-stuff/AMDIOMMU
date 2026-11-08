// Ordinary per-device IOMapper evidence. Published only by RefreshSnapshot=true;
// it does not own the mappings and never limits normal DMA traffic.
// Formerly R44Snapshot.
#pragma once
#include <stdint.h>

namespace mapper_abi {
// Version 5 describes non-contiguous table storage through TableSegment rows.
// Mapping records and the Snapshot byte layout remain compatible with version 4.
static constexpr uint32_t kVersion = 5;
// Ordinary DMA addresses must satisfy a 32-bit IODMACommand as well as 64-bit
// clients. Keep this independent of the legacy experiment's 64 GiB window.
static constexpr uint64_t kBase = 0x80000000ULL; // 2 GiB; every profile stays below 4 GiB
static constexpr uint32_t kPages = 4096, kRecords = 1024;
// ABI4 doubles the per-map bound so a 25/100 GbE client (MLX5 rings) is not
// rejected at 512 KiB. kMaxParts=16 still covers a 1 MiB invalidation range
// (about 9 power-of-two descriptors).
static constexpr uint32_t kMapPages = 256, kRuns = 128;
enum : uint32_t {
    kPrepared = 1, kAccepting = 2, kFailed = 4,
    kMapPublished = 1, kMapConfirmed = 2,
    kClearPublished = 4, kUnmapConfirmed = 8
};
struct RecordHeader {
    uint64_t handle, firstPA, mapAddress, mapLength, descriptorOffset, length;
    // tMapComplete is map-ready: NP-cache-free hardware may need no map CW.
    // tUnmapComplete always follows the completed invalidation before reuse.
    uint64_t tPublish, tMapComplete, tClear, tUnmapComplete;
    uint32_t recordIndex, basePage, pages, runs, options, state;
};
struct Record {
    RecordHeader header;
    // Physical page base for every allocated IOVA page, including the first
    // byte's containing page. Together with options this reconstructs its PTE.
    uint64_t physical[kMapPages];
};
struct Snapshot {
    uint32_t version, bytes, flags, capacityMaps;
    uint32_t capacityPages, maxMapPages, maxRuns, liveCount;
    uint64_t iovaBase, iovaBytes, rootPA, ptBytes;
    uint32_t rootLevel, tablePages, livePages, peakPages;
    uint32_t peakMaps, maxObservedPages, maxObservedRuns, reserved;
    uint64_t mapCalls, mapOk, mapRejected, unmapCalls, unmapOk, unmapRejected;
    // Actual invalidation attempts; map skips are separate registry counters.
    uint64_t invalidates, invalidateFailures, reusedAllocations;
    uint64_t offsetMaps, fragmentedMaps, walks;
    uint64_t preparedAt, firstMapAt, lastMapAt, lastUnmapAt;
    uint64_t snapshotSequence, snapshotTime;
    // Only the most recent successes/failures are retained; authoritative
    // active mappings are exported separately in mapper-live-raw.
    Record lastMap, lastUnmap;
};
// The raw page-table blob concatenates allocations in this order. Resolve a
// PTE physical address through its segment instead of subtracting rootPA.
struct TableSegment {
    uint64_t physicalBase, offset, bytes;
};
static_assert(sizeof(TableSegment) == 24, "page-table segment descriptor");
static_assert(sizeof(RecordHeader) == 104, "ordinary mapper record prefix");
static_assert(sizeof(Record) == 2152, "ordinary mapper record layout");
static_assert(sizeof(Snapshot) == 4544, "ordinary mapper snapshot layout");

// ---------------------------------------------------------------------------
// Profiles select a growth ceiling. Actual record and IOVA capacities grow
// independently from the legacy size; every profile uses the same per-map
// bounds. Page-table growth retains the root and all earlier table pages.
// ---------------------------------------------------------------------------
struct Profile {
    const char *name;
    uint32_t records;
    uint32_t pages;
    uint32_t mapPages;
    uint32_t runs;
    // Budget for preparing this profile in a single allocation. Incremental
    // growth retains earlier allocations and publishes its actual page count.
    uint32_t tablePages;
};
struct Capacity {
    uint32_t records;
    uint32_t pages;
};
enum class CapacityResource { recordSlots, iovaPages };

inline Capacity capacityForProfile(const Profile &profile) {
    return {profile.records, profile.pages};
}

static constexpr Profile kProfileLegacy = {
    "native-legacy", kRecords, kPages, kMapPages, kRuns, 16};
static constexpr Profile kProfileRl10g = {
    "rl-10g", 16384, 131072, kMapPages, kRuns, 260};
// Preserve the existing named 1 GiB ceiling and its record limit.
static constexpr Profile kProfileRl10gMax = {
    "rl-10g-max", 65535, 262144, kMapPages, kRuns, 516};
// Use the complete IOVA window above kBase that 32-bit DMA clients can reach.
// A contiguous build needs 1024 leaves, two L2 directories, L3 and the root.
static constexpr Profile kProfileDma32Max = {
    "dma32-max", 131072, 524288, kMapPages, kRuns, 1028};
static_assert(kProfileLegacy.records == kRecords && kProfileLegacy.pages == kPages,
              "legacy profile must not change the accepted window");
static_assert(kProfileRl10g.pages % 512 == 0, "leaf tables cover 2 MiB each");
static_assert(kProfileRl10g.tablePages >= kProfileRl10g.pages / 512 + 2,
              "profile must cover its own page tables");
static_assert(kProfileRl10g.pages <= 0xffffffffU / 4096U, "IOVA window must fit UInt32 pages");
static_assert(kProfileRl10gMax.pages % 512 == 0, "leaf tables cover 2 MiB each");
static_assert(kProfileRl10gMax.tablePages >= kProfileRl10gMax.pages / 512 + 2,
              "profile must cover its own page tables");
static_assert(kProfileDma32Max.pages % 512 == 0, "leaf tables cover 2 MiB each");
static_assert(kProfileDma32Max.tablePages >= kProfileDma32Max.pages / 512 + 4,
              "dma32 profile must cover both leaf directories and upper levels");
static_assert(kBase + (uint64_t)kProfileDma32Max.pages * 4096ULL == (1ULL << 32),
              "dma32 IOVA window must end at the 32-bit address boundary");

inline bool sameProfileName(const char *a, const char *b) {
    if (!a || !b) return false;
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

// Record slots and IOVA-page metadata have separate retained chunks. Each
// chunk is rounded to a page. The combined guard excludes hardware page tables
// and fixed storage descriptors.
// Keep the arithmetic shared with the host capacity test.
static constexpr uint32_t kMappingBytes = 16 + sizeof(RecordHeader); // 2 pointers + header
static_assert(kMappingBytes == 120, "one record slot is two pointers plus the ABI3 header");
static constexpr uint64_t kMaxMetadataBytes = 64ULL << 20;

inline uint64_t recordChunkBytesFor(uint32_t records) {
    const uint64_t recordWords = ((uint64_t)records + 63) / 64;
    const uint64_t bytes = (uint64_t)records * kMappingBytes +
        recordWords * sizeof(uint64_t);              // liveSlots
    return (bytes + 4095ULL) & ~4095ULL;
}

// Preparation and growth use the same legacy-first geometric chunk sequence.
// A named ceiling can clip the last record chunk below a full doubling.
inline uint64_t recordStorageBytesFor(uint32_t records) {
    uint64_t bytes = 0;
    uint32_t covered = 0;
    while (covered < records) {
        const uint32_t requested = covered ? covered : kRecords;
        const uint32_t remaining = records - covered;
        const uint32_t chunkRecords = requested < remaining ? requested : remaining;
        bytes += recordChunkBytesFor(chunkRecords);
        covered += chunkRecords;
    }
    return bytes;
}

inline uint64_t iovaPageChunkBytesFor(uint32_t pages) {
    const uint64_t pageWords = ((uint64_t)pages + 63) / 64;
    uint64_t bytes = (uint64_t)pages * sizeof(uint64_t);   // physicalByPage
    bytes += (uint64_t)pages * sizeof(uint32_t);           // slotByStartPage
    bytes += ((uint64_t)pages / 512) * sizeof(uint64_t *); // leaves
    bytes += 2 * pageWords * sizeof(uint64_t);       // allocator used/ever
    return (bytes + 4095ULL) & ~4095ULL;
}

// Preparation and growth use the same legacy-first geometric chunk sequence.
// Sum retained chunks rather than treating all IOVA metadata as one allocation.
inline uint64_t iovaPageStorageBytesFor(uint32_t pages) {
    uint64_t bytes = 0;
    uint32_t covered = 0;
    while (covered < pages) {
        const uint32_t requested = covered ? covered : kPages;
        const uint32_t remaining = pages - covered;
        const uint32_t chunkPages = requested < remaining ? requested : remaining;
        bytes += iovaPageChunkBytesFor(chunkPages);
        covered += chunkPages;
    }
    return bytes;
}

inline uint64_t metadataBytesFor(const Capacity &capacity) {
    return recordStorageBytesFor(capacity.records) + iovaPageStorageBytesFor(capacity.pages);
}

inline uint64_t metadataBytesFor(const Profile &profile) {
    return metadataBytesFor(capacityForProfile(profile));
}
// Unknown names must not silently fall back: the caller publishes the request
// and keeps legacy storage, so a typo can never widen the pool.
inline const Profile *profileForName(const char *name) {
    if (!name || !*name) return &kProfileLegacy;
    if (sameProfileName(name, kProfileLegacy.name)) return &kProfileLegacy;
    if (sameProfileName(name, kProfileRl10g.name)) return &kProfileRl10g;
    if (sameProfileName(name, kProfileRl10gMax.name)) return &kProfileRl10gMax;
    if (sameProfileName(name, kProfileDma32Max.name)) return &kProfileDma32Max;
    return nullptr;
}

// A display label must not round a mixed capacity up to a configured profile.
// Numeric record/page limits remain authoritative for dynamically sized storage.
inline const char *profileNameForCapacity(const Capacity &capacity) {
    const Profile *profiles[] = {
        &kProfileLegacy, &kProfileRl10g, &kProfileRl10gMax, &kProfileDma32Max};
    for (const Profile *profile : profiles) {
        if (capacity.records == profile->records && capacity.pages == profile->pages)
            return profile->name;
    }
    return "dynamic";
}

// S2 admission: the vendor/device policy. appleClientPath=true enables the
// identity/class suggestion table; both production modes enable it, so a
// device's suggested ceiling does not depend on how its mapper was attached.
// With false, only the vendor table applies and unlisted devices keep the
// accepted ABI3 arena. The caller applies a boot-arg override beforehand.
//
// R70-S6: when neither the vendor table nor the Apple RL range matches, fall
// back to the PCI class code so an unlisted device still gets a usable arena
// instead of the 16 MiB ABI3 window.
//
// This table records an identity-based capacity suggestion. The configured
// ceiling limits growth; nextCapacity() determines the next allocation
// size when the current record or page limit is exhausted.
enum class ProfileSource { bootArg, idTable, classTable, legacy };

// ---------------------------------------------------------------------------
// Double only the exhausted resource, stopping at its configured ceiling.
// The caller appends metadata and synchronizes any newly added page tables
// before publishing the resulting capacity.
// ---------------------------------------------------------------------------
inline bool nextCapacity(const Capacity &current, const Profile &ceiling,
                         CapacityResource resource, Capacity &target) {
    target = current;
    uint32_t &count = resource == CapacityResource::recordSlots
        ? target.records : target.pages;
    const uint32_t maximum = resource == CapacityResource::recordSlots
        ? ceiling.records : ceiling.pages;
    if (!count || count >= maximum) return false;
    const uint64_t doubled = (uint64_t)count * 2;
    count = doubled < maximum ? (uint32_t)doubled : maximum;
    return true;
}

inline const Profile *profileForClass(uint32_t classCode) {
    // class-code is the 24-bit PCI class in the usual base<<16 | sub<<8 | if
    // layout. Only the base class matters here.
    const uint32_t base = (classCode >> 16) & 0xffffU;
    if (base == 0x02U) return &kProfileRl10gMax;  // network controller
    if (base == 0x01U) return &kProfileRl10g;     // storage controller
    return nullptr;
}

inline const Profile *profileForDevice(uint32_t vendor, uint32_t device,
                                       bool appleClientPath,
                                       uint32_t classCode = 0,
                                       ProfileSource *source = nullptr) {
    const uint32_t vendor16 = vendor & 0xffffU, device16 = device & 0xffffU;
    if (source) *source = ProfileSource::legacy;
    // Mellanox adapters driven by Apple's MLX5 client. No claim path exists
    // for these devices, so the decision happens before the client-path gate.
    // R70-S5 showed the dext command queue times out with no mapper at all,
    // so admission is what makes the next test possible. They use the same
    // 1 GiB ceiling as the measured 10 GbE profile.
    if (vendor16 == 0x15b3U &&
        (device16 == 0x1015U || device16 == 0x1017U || device16 == 0x1019U ||
         device16 == 0x101bU || device16 == 0x101dU)) {
        if (source) *source = ProfileSource::idTable;
        return &kProfileRl10gMax;
    }
    if (!appleClientPath) return &kProfileLegacy;
    // The measured peak of 52,227 IOVA pages on a saturated 10 GbE flow has
    // about 5x headroom under this ceiling. It does not set the actual arena
    // size: records and pages are allocated independently on demand.
    if (vendor16 == 0x10ecU && device16 >= 0x8124U && device16 <= 0x8127U) {
        if (source) *source = ProfileSource::idTable;
        return &kProfileRl10gMax;
    }
    if (const Profile *byClass = profileForClass(classCode)) {
        if (source) *source = ProfileSource::classTable;
        return byClass;
    }
    return &kProfileLegacy;
}
} // namespace mapper_abi
