/* Round27: finite, one-shot RX DMA through standard IOMapper callbacks.
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
    kVersion = 1, kCount = 64, kPagesPerSlot = 2, kCapacity = 4096,
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
struct Witness {
    u64 originalPA, sparePA, iova, tPost, tDone, tRestoreOwn;
    u32 slot, entryId, flags, token, reqId, doneLength, doneStatus, reserved;
};
struct Snapshot {
    u32 version, bytes, state, flags;
    u32 generation, mapCount, posted, completed;
    u32 restored, pendingPosted, businessToken, reserved;
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
static_assert(sizeof(Witness) == 80, "round27 witness ABI");
static_assert(sizeof(Snapshot) == 7248, "round27 driver snapshot ABI");
static_assert(sizeof(Request) == 9344, "round27 request ABI");
static_assert(sizeof(MapRecord) == 200, "round27 map record ABI");
static_assert(sizeof(BackendSnapshot) == 12864, "round27 backend snapshot ABI");
} // namespace r27rx
#endif
