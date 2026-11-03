/* Persistent mappings for Lucy's existing TX ring, RX ring and tally buffer.
 * These three owners use the unused half of the first TX L1 table. They never
 * consume packet records, dynamic TX pages, or native RX mapping counters.
 * Private control reuses r34rx::Binding; standard IODMACommand callbacks map
 * and unmap the registered MD/Cmd pairs through the same backend lock/cursor.
 */
#ifndef RTL812X_FIXED_DMA_HPP
#define RTL812X_FIXED_DMA_HPP
#include "AMDAliveTxDomainNative.hpp"
namespace r40fixed {
typedef unsigned int u32;
typedef unsigned long long u64;
enum {
    kVersion = 1, kCount = 3, kPages = 16,
    kTxRing = 0, kRxRing = 1, kTally = 2,
    // r34rx::Binding operations. Read returns its MapRecord identity, times,
    // flags and commands; the full PTE arrays are exported in BackendSnapshot.
    kBind = 8, kRead = 9, kUnbind = 10, kEntered = 11,
    kMapPublished = 1, kMapInvalidated = 2, kMapUnmapped = 4,
    kFlagMapFailed = 1, kFlagUnmapFailed = 2
};
static const u64 kIovaBase = 0x1000100000ULL;
static const u64 kStride = 0x10000ULL;
struct DriverObject {
    u64 memory, command, pa, bytes, iova;
    u64 registerBefore, registerActive, registerPhysical;
    u64 tMapReady, tUnmapReady;
    u32 kind, mapOptions, mapCount, unmapCount;
};
struct DriverSnapshot {
    u32 version, bytes, count, flags;
    u32 entryCalls, resetVerified, commandBefore, commandStopped;
    u32 interruptMaskBefore, interruptMaskStopped, generationBefore, generationAfter;
    u64 tStopBegin, tStopped, tProgrammed, tActive;
    DriverObject objects[kCount];
};
struct Record {
    u64 memory, command, pa, bytes, iova;
    u64 tMapPublish, tMapInv, tUnmapPublish, tUnmapInv;
    u32 kind, pages, mapOptions, flags;
    u32 mapResult, unmapResult, mapCalls, unmapCalls;
    u64 mapPte[kPages], clearPte[kPages];
    r17domain::Command mapCommand, unmapCommand;
};
struct BackendSnapshot {
    u32 version, bytes, count, flags;
    u32 boundPairs, liveOwners, mapCalls, mapOk;
    u32 unmapCalls, unmapOk, entered, reserved;
    u64 tEntered;
    Record objects[kCount];
};
static_assert(sizeof(DriverObject) == 96, "round40 fixed DMA driver object");
static_assert(sizeof(DriverSnapshot) == 368, "round40 fixed DMA driver snapshot");
static_assert(sizeof(Record) == 440, "round40 fixed DMA backend object");
static_assert(sizeof(BackendSnapshot) == 1376, "round40 fixed DMA backend snapshot");
} // namespace r40fixed
#endif
