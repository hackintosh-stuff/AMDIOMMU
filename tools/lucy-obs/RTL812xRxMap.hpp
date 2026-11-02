/* Round29: cyclic RX DMA with a tail-finished observation after RX release.
 * Separate ABI: RTL812xRxPool.hpp remains byte-for-byte compatible.
 * Probe owns the 64 physical MD/DMACommand objects; Lucy retains the actual
 * mbufs until kRelease acknowledges every standard unmap. No kernel pointer
 * crosses this control ABI. Times are mach_absolute_time ticks.
 */
#ifndef RTL812xRxMap_hpp
#define RTL812xRxMap_hpp
#include "AMDAliveTxDomainNative.hpp"
namespace r27rx {
typedef unsigned int u32;
typedef unsigned long long u64;
static const char kFunctionName[] = "rtl812x-r27-rxmap";
static const u64 kIovaBase = 0x1000010000ULL;
enum {
    kVersion = 3, kCount = 64, kPagesPerSlot = 2, kCapacity = 4096,
    kTailMax = 4096,
    kInstall = 1, kSnapshot = 2, kDisarm = 3, kDrain = 4, kRelease = 5,
    kHold = 6,
    kAbsent = 0, kInstalled = 1, kDisarmed = 2, kDrained = 3, kReleased = 4,
    kHeld = 5,
    kFlagAddressMismatch = 1, kFlagRingReset = 2, kFlagBadMapping = 4,
    kFlagStopped = 8, kFlagCopyFailed = 16,
    kWitnessPosted = 1, kWitnessDone = 2, kWitnessRestored = 4,
    kWitnessError = 8,
    kMapRegistered = 1, kMapPublished = 2, kMapInvalidated = 4,
    kMapUnmapped = 8, kMapReleased = 16,
    kBackendMapFailed = 1, kBackendDrainFailed = 2,
    kBackendUnmapFailed = 4, kBackendReleaseFailed = 8
};
struct Mapping {
    u64 pa, iova, tMapInv;
    u32 entryId, capacity;
};
// One-based cycle number; flags use kWitnessPosted/Done/Error. Retain first4.
struct Cycle {
    u64 tPost, tDone;
    u32 cycle, token, reqId, doneLength, doneStatus, flags;
};
struct Witness {
    u64 originalPA, sparePA, iova, tPost, tDone, tRestoreOwn;
    u32 slot, entryId, flags, token, reqId, doneLength, doneStatus, reserved;
    // The 80-byte prefix keeps first post, latest done/payload, final restore.
    // Last stamps track the final DMA, even after sample storage fills.
    u64 tLastPost, tLastDone;
    u32 postCount, doneCount, reuseCount, sampleCount;
    Cycle samples[4];
};
struct Snapshot {
    u32 version, bytes, state, flags;
    u32 generation, mapCount, posted, completed;
    // R29D echoed on the restored ordinary RX ring; never a DMA selector.
    u32 restored, pendingPosted, businessToken, tailSeq;
    u64 poolId, tInstalled, tDisarmed, tLastRestore;
    Mapping maps[kCount];
    Witness witnesses[kCount];
};
struct Request {
    u32 version, bytes, op, expectedGeneration;
    u64 poolId, deadline;
    u32 mapCount, replaceLimit, businessToken, reserved;
    Mapping maps[kCount];
    Snapshot out;
};
// Probe-owned evidence is separate from driver witness storage and TX ABIs.
struct MapRecord {
    u64 pa, iova, mapLength, tMapPublish, tMapInv;
    u64 tUnmapPublish, tUnmapInv, mapPte[2], clearPte[2];
    u32 entryId, capacity, pages, mapOptions;
    u32 mapResult, unmapResult, flags, reserved;
    r17domain::Command mapCommand, unmapCommand;
};
struct BackendSnapshot {
    u32 version, bytes, flags, count;
    u32 mapCalls, mapOk, mapRejects, unmapCalls;
    u32 unmapOk, liveOwners, ready, reserved;
    u64 tReady, tDrained;
    MapRecord records[kCount];
};
static_assert(sizeof(Mapping) == 32, "round27 mapping ABI");
static_assert(sizeof(Cycle) == 40, "round28 cycle ABI");
static_assert(sizeof(Witness) == 272, "round28 witness ABI");
static_assert(sizeof(Snapshot) == 19536, "round28 driver snapshot ABI");
static_assert(sizeof(Request) == 21632, "round28 request ABI");
static_assert(sizeof(MapRecord) == 200, "round27 map record ABI");
static_assert(sizeof(BackendSnapshot) == 12864, "round27 backend snapshot ABI");
} // namespace r27rx
#endif
