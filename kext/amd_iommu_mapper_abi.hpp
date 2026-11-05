// Ordinary per-device IOMapper evidence. Published only by R44Snapshot=true;
// it does not own the mappings and never limits normal DMA traffic.
#pragma once
#include <stdint.h>

namespace r44mapper {
static constexpr uint32_t kVersion = 3;
// Ordinary DMA addresses must satisfy a 32-bit IODMACommand as well as 64-bit
// clients. Keep this independent of the legacy experiment's 64 GiB window.
static constexpr uint64_t kBase = 0x80000000ULL; // 2 GiB, 16 MiB pool below 4 GiB
static constexpr uint32_t kPages = 4096, kRecords = 1024;
static constexpr uint32_t kMapPages = 128, kRuns = 128;
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
    // active mappings are exported separately in r44-live-raw.
    Record lastMap, lastUnmap;
};
static_assert(sizeof(RecordHeader) == 104, "ordinary mapper record prefix");
static_assert(sizeof(Record) == 1128, "R59 ordinary mapper record ABI3");
static_assert(sizeof(Snapshot) == 2496, "R59 ordinary mapper snapshot ABI3");

// ---------------------------------------------------------------------------
// Capacity profiles (S1 of docs/m2-3az-round69-capacity-model.md).
//
// A profile decides the arena a domain reserves *before* any client maps:
// record slots, IOVA pages and the page-table area. The ABI3 record/snapshot
// layouts are unchanged in S1, so mapPages/runs stay at their ABI3 values and
// the legacy profile reproduces the accepted behaviour exactly. Raising the
// per-map bound is a separate step because it changes Record.physical[].
//
// The default is the legacy profile: a domain that never selects one behaves
// byte-for-byte like R67-2. "rl-10g" is the conservative starting point for
// Apple's Skywalk packet pools (one segment per iovmMapMemory call); its final
// numbers come from the S3 measurement, not from this table.
// ---------------------------------------------------------------------------
struct Profile {
    const char *name;
    uint32_t records;
    uint32_t pages;
    uint32_t mapPages;
    uint32_t runs;
    uint32_t tablePages;
};
static constexpr Profile kProfileLegacy = {
    "native-legacy", kRecords, kPages, kMapPages, kRuns, 16};
static constexpr Profile kProfileRl10g = {
    "rl-10g", 16384, 131072, kMapPages, kRuns, 260};
static_assert(kProfileLegacy.records == kRecords && kProfileLegacy.pages == kPages,
              "legacy profile must not change the accepted window");
static_assert(kProfileRl10g.pages % 512 == 0, "leaf tables cover 2 MiB each");
static_assert(kProfileRl10g.tablePages >= kProfileRl10g.pages / 512 + 2,
              "profile must cover its own page tables");
static_assert(kProfileRl10g.records <= 0xffff, "slot + 1 must fit in UInt16");
static_assert(kProfileRl10g.pages <= 0xffffffffU / 4096U, "IOVA window must fit UInt32 pages");

inline bool sameProfileName(const char *a, const char *b) {
    if (!a || !b) return false;
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

// Bytes a domain reserves for the capacity-dependent arrays: record slots,
// physical-by-page index, per-start-page slot map, liveness bitmap, leaf
// pointers and the allocator's two bitmaps. Page tables are separate
// (Profile::tablePages). Kept here so tests/ can check the arithmetic without
// compiling the kext.
static constexpr uint32_t kMappingBytes = 16 + sizeof(RecordHeader); // 2 pointers + header
static_assert(kMappingBytes == 120, "one record slot is two pointers plus the ABI3 header");
static constexpr uint64_t kMaxArenaBytes = 64ULL << 20;

inline uint64_t arenaBytesFor(const Profile &p) {
    const uint64_t words = ((uint64_t)p.records + 63) / 64;
    const uint64_t pageWords = ((uint64_t)p.pages + 63) / 64;
    uint64_t bytes = (uint64_t)p.records * kMappingBytes;
    bytes += (uint64_t)p.pages * sizeof(uint64_t);   // physicalByPage
    bytes += (uint64_t)p.pages * sizeof(uint16_t);   // slotByStartPage
    bytes += words * sizeof(uint64_t);               // liveSlots
    bytes += ((uint64_t)p.pages / 512) * sizeof(uint64_t *); // leaves
    bytes += 2 * pageWords * sizeof(uint64_t);       // allocator used/ever
    return (bytes + 4095ULL) & ~4095ULL;
}
// Unknown names must not silently fall back: the caller publishes the request
// and keeps the legacy arena, so a typo can never widen the pool.
inline const Profile *profileForName(const char *name) {
    if (!name || !*name) return &kProfileLegacy;
    if (sameProfileName(name, kProfileLegacy.name)) return &kProfileLegacy;
    if (sameProfileName(name, kProfileRl10g.name)) return &kProfileRl10g;
    return nullptr;
}
} // namespace r44mapper
