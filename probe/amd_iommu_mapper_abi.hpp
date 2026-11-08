// Ordinary per-device IOMapper evidence. Published only by R44Snapshot=true;
// it does not own the mappings and never limits normal DMA traffic.
#pragma once
#include <stdint.h>

namespace mapper_abi {
static constexpr uint32_t kVersion = 4;
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
static_assert(sizeof(RecordHeader) == 104, "ordinary mapper record prefix");
static_assert(sizeof(Record) == 2152, "R70 ordinary mapper record ABI4");
static_assert(sizeof(Snapshot) == 4544, "R70 ordinary mapper snapshot ABI4");

// ---------------------------------------------------------------------------
// Capacity profiles. The ceiling sizes the arena and page-table storage before
// any client maps. Usable records and IOVA pages start at the legacy profile
// and advance through these profiles when allocation exhausts either limit.
// Every profile uses the same per-map bounds and the same snapshot ABI.
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
// Measurement ceiling: 1 GiB / the largest record count the UInt16 slot
// encoding allows. The S3 boot runs on this profile so a first measurement
// cannot repeat R69's exhaustion; the final rl-10g numbers come from it.
static constexpr Profile kProfileRl10gMax = {
    "rl-10g-max", 65535, 262144, kMapPages, kRuns, 516};
static_assert(kProfileLegacy.records == kRecords && kProfileLegacy.pages == kPages,
              "legacy profile must not change the accepted window");
static_assert(kProfileRl10g.pages % 512 == 0, "leaf tables cover 2 MiB each");
static_assert(kProfileRl10g.tablePages >= kProfileRl10g.pages / 512 + 2,
              "profile must cover its own page tables");
static_assert(kProfileRl10g.records <= 0xffff, "slot + 1 must fit in UInt16");
static_assert(kProfileRl10g.pages <= 0xffffffffU / 4096U, "IOVA window must fit UInt32 pages");
static_assert(kProfileRl10gMax.pages % 512 == 0, "leaf tables cover 2 MiB each");
static_assert(kProfileRl10gMax.tablePages >= kProfileRl10gMax.pages / 512 + 2,
              "profile must cover its own page tables");
static_assert(kProfileRl10gMax.records <= 0xffff, "slot + 1 must fit in UInt16");

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
    if (sameProfileName(name, kProfileRl10gMax.name)) return &kProfileRl10gMax;
    return nullptr;
}

// S2 admission: the vendor/device policy. Only Apple's own Ethernet client
// (AppleEthernetRL, 10ec:8124-8127) takes the pool-sized profile, and only on
// the auto-attach path, because that is the one client that cannot call our
// private claim. Lucy, the board RTL8111 and every claim-based path keep the
// accepted ABI3 arena. The caller applies a boot-arg override beforehand.
//
// R70-S6: when neither the vendor table nor the Apple RL range matches, fall
// back to the PCI class code so an unlisted device still gets a usable arena
// instead of the 16 MiB ABI3 window.
//
// This table records an identity-based capacity suggestion. The configured
// ceiling determines reserved storage; nextCapacityProfile() determines the
// next usable capacity when the current record or page limit is exhausted.
enum class ProfileSource { bootArg, idTable, classTable, legacy };

// ---------------------------------------------------------------------------
// Advance usable capacity without replacing its backing storage. Prefer the
// intermediate profile when it fits under the reserved ceiling. The caller
// synchronizes the hardware before publishing the returned limits.
// ---------------------------------------------------------------------------
inline const Profile *nextCapacityProfile(const Profile *current,
                                          const Profile *ceiling) {
    if (!current || !ceiling) return nullptr;
    if (ceiling->pages <= current->pages) return nullptr;
    if (ceiling->records <= current->records) return nullptr;
    if (ceiling->tablePages < ceiling->pages / 512 + 2) return nullptr;
    if (current->pages < kProfileRl10g.pages &&
        current->records < kProfileRl10g.records &&
        ceiling->pages >= kProfileRl10g.pages &&
        ceiling->records >= kProfileRl10g.records)
        return &kProfileRl10g;
    return ceiling;
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
    // R70 measured 52,227 IOVA pages on a saturated 10 GbE flow, so the
    // 512 MiB profile would leave only 2.5x headroom. The 1 GiB profile keeps
    // 5x on pages and 20x on records for the same 10.5 MB of wired memory.
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
