/* Round30: kernel-to-kernel RX allocation-domain ABI for 1024 ring spares.
 * No mbuf/kernel pointers are exported. All addresses are actual host physical
 * DMA spans. This version deliberately refuses the AppleVTD/IOVM path.
 * callPlatformFunction(kFunctionName,false,&Request,NULL,NULL,NULL).
 * Request is ~112 KiB: allocate it in persistent/heap memory, never kernel stack.
 * Times use mach_absolute_time ticks, NOT nanoseconds.
 */
#ifndef RTL812xRxPool_hpp
#define RTL812xRxPool_hpp
namespace r15pool {
typedef unsigned int u32;
typedef unsigned long long u64;
static const char kFunctionName[] = "rtl812x-r15-pool";
enum {
    kVersion = 2, kRingCount = 1024, kSpareCount = 1024,
    kMaxEntries = kRingCount + kSpareCount,
    kMaxAttempts = 2048, kExtraIOBufferAttempts = 1024,
    kSourceMbuf = 0, kSourceIOBuffer = 2,
    kMaxWitnesses = kSpareCount,
    kPrepare = 1, kAuthorize = 2, kSnapshot = 3, kDisarm = 4,
    kAbsent = 0, kPrepared = 1, kAuthorized = 2, kDisarmed = 3,
    kEntryRing = 1, kEntrySpare = 2,
    kWitnessCompleted = 1, kWitnessError = 2,
    kFlagExpired = 1, kFlagRingReset = 2, kFlagCopyFailed = 4,
    kFlagAddressMismatch = 8
};
struct Entry {
    u64 addr;
    u32 capacity;
    u32 id;
    u32 kind;
    u32 reserved;               // source: kSourceMbuf=0 or kSourceIOBuffer=2
};
struct Witness {
    u64 oldAddr;
    u64 newAddr;
    u64 tPost;
    u64 tDone;
    u32 slot;
    u32 capacity;
    u32 entryId;
    u32 flags;
    u32 token;
    u32 reqId;
    u32 doneLength;
    u32 doneStatus;
};
struct Snapshot {
    u32 version;
    u32 bytes;
    u32 state;
    u32 generation;
    u64 poolId;
    u64 tPrepared;
    u64 tAuthorized;
    u64 mapCompletedAt;
    u64 deadline;
    u32 epoch;
    u32 vtdPath;
    u32 mtu;
    u32 bufferSize;
    u32 entryCount;
    u32 spareCount;
    u32 allocationAttempts;
    u32 highSpareCount;
    u32 replacements;
    u32 completions;
    u32 rxCompletions;
    u32 copyFailures;
    u32 flags;
    u32 replaceLimit;
    u32 reserved[2];           // [0] declared business token; [1] filtered obs rows
    Entry entries[kMaxEntries];
    Witness witnesses[kMaxWitnesses];
};
struct Request {
    u32 version;
    u32 bytes;
    u32 op;
    u32 expectedGeneration;
    u64 poolId;
    u64 mapCompletedAt;
    u64 deadline;
    u32 replaceLimit;
    u32 reserved;               // Prepare: opt-in declared businessToken, 0=all obs
    Snapshot out;
};
static_assert(sizeof(Entry) == 24, "round15 entry ABI");
static_assert(sizeof(Witness) == 64, "round15 witness ABI");
static_assert(sizeof(Snapshot) == 114808, "round30 pool snapshot ABI");
static_assert(sizeof(Request) == 114856, "round30 pool request ABI");
} // namespace r15pool
#endif
