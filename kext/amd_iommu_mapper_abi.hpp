// Ordinary per-device IOMapper evidence. Published only by R44Snapshot=true;
// it does not own the mappings and never limits normal DMA traffic.
#pragma once
#include <stdint.h>

namespace r44mapper {
static constexpr uint32_t kVersion = 1;
static constexpr uint32_t kPages = 4096, kRecords = 1024;
static constexpr uint32_t kMapPages = 32, kRuns = 32;
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
static_assert(sizeof(Record) == 360, "R44 ordinary mapper record ABI1");
static_assert(sizeof(Snapshot) == 960, "R44 ordinary mapper snapshot ABI1");
} // namespace r44mapper
