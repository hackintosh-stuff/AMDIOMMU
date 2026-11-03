/* Native RX: driver-owned receive mappings for the ordinary replacement path.
 * The existing Lucy ring has no experimental pool. Round36 batches confirmed
 * map/unmap invalidations while standard DMA callbacks remain synchronous.
 * Kernel-only control pointers stay in Request/Binding. Exported snapshots
 * contain numeric identities, mapping evidence and completed DMA witnesses.
 * Each slot keeps its first IOVA DMA lifecycle and its latest lifecycle.
 */
#ifndef RTL812X_RX_NATIVE_HPP
#define RTL812X_RX_NATIVE_HPP
#include "AMDAliveTxDomainNative.hpp"
namespace r34rx {
typedef unsigned int u32;
typedef unsigned long long u64;
static const char kFunctionName[] = "rtl812x-r34-rx-native";
static const u64 kIovaBase = 0x1000200000ULL;
enum {
    kVersion = 3, kCount = 1024, kCapacity = 4096, kPagesPerSlot = 2,
    kSamples = 1, kTailMax = 4096, kBatchSize = 16,
    kInstall = 1, kSnapshot = 2, kDisarm = 3, kDrain = 4, kRelease = 5,
    kPrepare = 6, kAuthorize = 7, kResumePhysical = 8,
    kAbsent = 0, kInstalled = 1, kDisarmed = 2, kDrained = 3, kReleased = 4,
    kPrepared = 5,
    kBind = 1, kRead = 2, kCover = 3, kUnbind = 4,
    kBatchMap = 5, kBatchUnmap = 6,
    kMapPublished = 1, kMapInvalidated = 2, kMapUnmapped = 4,
    kWitnessPosted = 1, kWitnessDone = 2, kWitnessUnmapped = 4,
    kWitnessError = 8,
    kFlagMapFailed = 1, kFlagUnmapFailed = 2, kFlagAddressMismatch = 4,
    kFlagStopped = 8, kFlagCoverFailed = 16, kFlagRingReset = 32,
    kFlagCopyFailed = 64
};
struct MapRecord {
    u64 generation, memory, command, pa, iova, mapLength;
    u64 tMapPublish, tMapInv, tUnmapPublish, tUnmapInv;
    u64 mapPte[2], clearPte[2];
    u32 slot, pages, mapOptions, flags;
    // Zero denotes scalar work; batch fields encode firstSlot | (count << 16).
    u32 mapResult, unmapResult, mapBatch, unmapBatch;
    r17domain::Command mapCommand, unmapCommand;
};
struct BackendSlot {
    u32 mapCount, unmapCount, sampleCount, flags;
    MapRecord samples[kSamples], last;
};
struct BackendSnapshot {
    u32 version, bytes, flags, count;
    u32 mapCalls, mapOk, mapRejects, unmapCalls;
    u32 unmapOk, liveOwners, ready, coverCalls;
    u32 coverOk, coverFailed, boundPairs, reserved;
    u64 tReady, tDrained;
    BackendSlot slots[kCount];
};
struct Witness {
    u64 generation, memory, command, pa, iova;
    u64 tMapInv, tPost, tDone, tUnmapInv;
    u32 slot, flags, token, reqId;
    u32 doneLength, doneStatus, replaced, reserved;
};
struct DriverSlot {
    u64 originalPA, currentPA, tPhysicalOwn;
    u32 mapCount, unmapCount, postCount, doneCount;
    u32 replaceCount, sampleCount, flags, reserved;
    Witness samples[kSamples], last;
};
struct Snapshot {
    u32 version, bytes, state, flags;
    u32 businessToken, slotCount, maps, unmaps;
    u32 posted, completed, replaced, restored;
    u32 pendingPosted, tailSeq, nativeActive, reserved;
    u64 ringId, tInstalled, tDisarmed, tLastRestore;
    DriverSlot slots[kCount];
};
struct Binding {
    u32 version, bytes, op, slot;
    void *memory, *command;
    u64 pa, length;
    MapRecord out;
};
typedef int (*Callback)(void *, Binding *);
struct Request {
    u32 version, bytes, op, expectedGeneration;
    u64 ringId, deadline;
    u32 businessToken, reserved;
    void *mapper, *context;
    Callback callback;
    Snapshot out;
};
static_assert(sizeof(MapRecord) == 224, "round34 RX mapping record");
static_assert(sizeof(BackendSlot) == 464, "round34 RX backend slot");
static_assert(sizeof(BackendSnapshot) == 475216, "round34 RX backend snapshot");
static_assert(sizeof(Witness) == 104, "round34 RX driver witness");
static_assert(sizeof(DriverSlot) == 264, "round34 RX driver slot");
static_assert(sizeof(Snapshot) == 270432, "round34 RX driver snapshot");
static_assert(sizeof(Binding) == 272, "round34 RX callback binding");
static_assert(sizeof(Request) == 270496, "round34 RX control request");
} // namespace r34rx
#endif
