// Ordinary per-device IOMapper evidence. Published only by R44Snapshot=true;
// it does not own the mappings and never limits normal DMA traffic.
#pragma once
#include <stdint.h>

namespace mapper_abi {
static constexpr uint32_t kVersion = 4;
// Ordinary DMA addresses must satisfy a 32-bit IODMACommand as well as 64-bit
// clients. Keep this independent of the legacy experiment's 64 GiB window.
static constexpr uint64_t kBase = 0x80000000ULL; // 2 GiB, 16 MiB pool below 4 GiB
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
    // active mappings are exported separately in r44-live-raw.
    Record lastMap, lastUnmap;
};
static_assert(sizeof(RecordHeader) == 104, "ordinary mapper record prefix");
static_assert(sizeof(Record) == 2152, "R70 ordinary mapper record ABI4");
static_assert(sizeof(Snapshot) == 4544, "R70 ordinary mapper snapshot ABI4");

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
// R71-B changed what this table decides. It no longer sizes the arena a domain
// is prepared with (that is always the legacy one now); it is the *admission
// ceiling* a domain may grow to at its first mapping, and the record of what
// identity-based sizing would have chosen. The arena the client actually gets
// comes from profileForFirstMapGrowth(), not from this table, so a missing or
// wrong entry can no longer leave a real client with 16 MiB.
enum class ProfileSource { bootArg, idTable, classTable, legacy };

// ---------------------------------------------------------------------------
// R71-B: demand-driven growth (amends the R69 §6.1 "arena is fixed at
// admission" contract; see docs/m2-3bd-round71-first-map-growth.md).
//
// S2 sized the arena from device identity before any client had mapped, which
// can only ever be a guess: an unlisted device got 16 MiB, and a listed one
// could still outgrow its table entry. Demand is only observable from a real
// mapping request, and the only moment a rebuild is safe is just before the
// first PTE is published: the DTE still names a passthrough root, the
// controller has never walked these tables, so nothing has to be invalidated
// and there is no live translation to preserve.
//
// A domain is therefore prepared at the smallest arena and may grow exactly
// once, at its first admissible mapping, to the ceiling it was admitted for.
// The decision is a pure comparison so tests/ can check it without a kext.
//
// Invariants:
//   * growth never shrinks - a ceiling that is not strictly larger in both
//     dimensions is not a growth target, it is a policy error;
//   * the ceiling must cover its own leaf tables, or growth would install a
//     table area that cannot describe the IOVA window it advertises;
//   * after the first activation capacity is frozen for the reason R69 §6 gave
//     for forbidding a runtime resize: a live domain must never change the
//     meaning of an address the client is already using.
// ---------------------------------------------------------------------------
inline const Profile *profileForFirstMapGrowth(const Profile *prepared,
                                              const Profile *ceiling) {
    if (!prepared || !ceiling) return nullptr;
    if (ceiling == prepared) return nullptr;
    if (ceiling->pages <= prepared->pages) return nullptr;
    if (ceiling->records <= prepared->records) return nullptr;
    if (ceiling->tablePages < ceiling->pages / 512 + 2) return nullptr;
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
