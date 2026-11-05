/* Native RX: driver-owned receive mappings for the ordinary replacement path.
 * The existing Lucy ring has no experimental pool. Round36 batches confirmed
 * map/unmap invalidations while standard DMA callbacks remain synchronous.
 * Round37 separately exports the three driver-owned physical DMA objects
 * needed alongside the initial RX buffers by the sparse bootstrap table.
 * Round38 retires the RX bootstrap aliases after every slot has published
 * its first IOVA OWN; fixed DMA objects stay mapped until domain teardown.
 * Round39 stops the NIC locally before retiring the final RX mappings.
 * Stop-retired descriptors remain distinct from observed RX completions.
 * Round43 also stops before the DTE switch, so the entire translated
 * lifetime uses IOVA mappings without bootstrap or physical-return aliases.
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
    kVersion = 5, kCount = 1024, kCapacity = 4096, kPagesPerSlot = 2,
    kPhysicalLayoutVersion = 1, kPhysicalSpanCount = 3,
    kStopVersion = 1,
    kSamples = 1, kTailMax = 4096, kBatchSize = 16,
    kInstall = 1, kSnapshot = 2, kDisarm = 3, kDrain = 4, kRelease = 5,
    kPrepare = 6, kAuthorize = 7, kResumePhysical = 8, kStopBeforeDte = 9,
    kAbsent = 0, kInstalled = 1, kDisarmed = 2, kDrained = 3, kReleased = 4,
    kPrepared = 5,
    kBind = 1, kRead = 2, kCover = 3, kUnbind = 4,
    kBatchMap = 5, kBatchUnmap = 6, kRetireBootstrap = 7,
    // Binding operations 8..11 belong to r40fixed. Operation 7 is legacy.
    kCaptureActive = 12,
    kMapPublished = 1, kMapInvalidated = 2, kMapUnmapped = 4,
    kWitnessPosted = 1, kWitnessDone = 2, kWitnessUnmapped = 4,
    kWitnessError = 8, kWitnessStopRetired = 16,
    kFlagMapFailed = 1, kFlagUnmapFailed = 2, kFlagAddressMismatch = 4,
    kFlagStopped = 8, kFlagCoverFailed = 16, kFlagRingReset = 32,
    kFlagCopyFailed = 64
};
// Immutable for the prepared ring: TX descriptors, RX descriptors, tally.
// This separate property leaves the native RX control/snapshot ABI unchanged.
struct PhysicalSpan {
    u64 pa, bytes;
};
struct PhysicalLayout {
    u32 version, bytes, generation, count;
    PhysicalSpan spans[kPhysicalSpanCount];
};
// One local stop/restart. Register values are actual NIC readbacks; tResumed
// is recorded only after link-up and the RX/TX command bits are confirmed.
struct StopRecord {
    u32 version, bytes, stopCalls, resetVerified;
    u32 commandBefore, commandStopped, interruptMaskBefore, interruptMaskStopped;
    u32 rxNextBefore, rxNextAfter, stopRetired, restored;
    u64 tStopBegin, tStopped, tLastUnmap, tLastRestore, tResumeBegin, tResumed;
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
    u32 replaceCount, sampleCount, flags, stopRetired;
    Witness samples[kSamples], last;
};
struct Snapshot {
    u32 version, bytes, state, flags;
    u32 businessToken, slotCount, maps, unmaps;
    u32 posted, completed, replaced, restored;
    u32 pendingPosted, tailSeq, nativeActive, stopRetired;
    u64 ringId, tInstalled, tDisarmed, tLastRestore;
    DriverSlot slots[kCount];
};
struct Binding {
    u32 version, bytes, op, slot;
    void *memory, *command;
    // kCaptureActive (legacy kRetireBootstrap has the same arguments):
    // slot=0, pa=last first-IOVA-OWN time, length=kCount.
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
static_assert(sizeof(PhysicalSpan) == 16, "round37 physical DMA span");
static_assert(sizeof(PhysicalLayout) == 64, "round37 physical DMA layout");
static_assert(sizeof(StopRecord) == 96, "round39 local RX stop record");
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
