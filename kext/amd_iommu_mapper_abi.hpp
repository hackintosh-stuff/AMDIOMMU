// Ordinary per-device IOMapper evidence. Published only by R44Snapshot=true;
// it does not own the mappings and never limits normal DMA traffic.
#pragma once
#include <stdint.h>

namespace r44mapper {
static constexpr uint32_t kVersion = 2;
// Ordinary DMA addresses must satisfy a 32-bit IODMACommand as well as 64-bit
// clients. Keep this independent of the legacy experiment's 64 GiB window.
static constexpr uint64_t kBase = 0x80000000ULL; // 2 GiB, 16 MiB pool below 4 GiB
static constexpr uint32_t kPages = 4096, kRecords = 1024;
static constexpr uint32_t kMapPages = 64, kRuns = 64;
enum : uint32_t {
    kPrepared = 1, kAccepting = 2, kFailed = 4,
    kMapPublished = 1, kMapConfirmed = 2,
    kClearPublished = 4, kUnmapConfirmed = 8
};
struct Record {
    uint64_t handle, firstPA, mapAddress, mapLength, descriptorOffset, length;
    uint64_t tPublish, tMapComplete, tClear, tUnmapComplete;
    uint32_t recordIndex, basePage, pages, runs, options, state;
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
    uint64_t invalidates, invalidateFailures, reusedAllocations;
    uint64_t offsetMaps, fragmentedMaps, walks;
    uint64_t preparedAt, firstMapAt, lastMapAt, lastUnmapAt;
    uint64_t snapshotSequence, snapshotTime;
    // Only the most recent successes/failures are retained; authoritative
    // active mappings are exported separately in r44-live-raw.
    Record lastMap, lastUnmap;
};
static_assert(sizeof(Record) == 616, "R49 ordinary mapper record ABI2");
static_assert(sizeof(Snapshot) == 1472, "R49 ordinary mapper snapshot ABI2");
} // namespace r44mapper
