#ifndef RTL812X_TX_MAP_STD_HPP
#define RTL812X_TX_MAP_STD_HPP
#include <stdint.h>
/* Round18: standard-interface TX mapping witness (kernel-only, same address
 * space). This is the DRIVER's record of what the standard framework did, not a
 * second copy of the probe's page-table record.
 *
 * WHY A SEPARATE STRUCT
 * ---------------------
 *  The round-17 witness (r17tx::Witness) already records the packet's physical
 *  segments, the IOVA the descriptors carry, the descriptor words, the close
 *  pointer sample and the per-packet free. None of that changes when the map is
 *  performed by IOKit instead of by a platform call -- which is exactly why the
 *  round-17 layout is left untouched: its archived captures must stay decodable.
 *
 *  What is NEW here is provenance of the standard objects:
 *    * the IOMemoryDescriptor the packet was handed to,
 *    * the IODMACommand that owns the mapping,
 *    * the IOReturn of setMemoryDescriptor()/prepare() and of complete(),
 *    * the IOVA segments that gen64IOVMSegments() itself produced,
 *    * the probe handle the mapping was issued under, so the driver record and
 *      the probe's page-table record can be matched one-to-one without either
 *      side trusting the other's success string.
 *
 * CONTRACT
 * --------
 *  One witness per retired or pinned generation in a bounded circular history.
 *  Match the driver's witness to the probe by handle, not by array index or by
 *  the packet's request field. A refusal before prepare() has no handle and is
 *  counted, never reported as a successful mapping.
 *
 * ROUND 19
 * --------
 *  kMbufs is the descriptor range bound: the chain is described one range per
 *  mbuf, and a chain longer than that is refused before prepare() rather than
 *  silently truncated. kSegments stays the bound on DMA runs the command may
 *  return for one frame (the mapper's window is page-aligned per run, so a
 *  fragmented frame costs one run per physical run plus padding).
 *
 *  Field semantics that round 18 narrowed and round 19 restores:
 *    * mbufSegments = mbufs in the chain (1..kMbufs), NOT "1";
 *    * segCount     = DMA runs gen64IOVMSegments() returned (>= 1);
 *    * mapLength    = LOGICAL bytes covered (the length the mapper was asked
 *      for); the length IOKit hands back to iovmUnmapMemory() is the mapper's
 *      own contract, >= mapLength for a fragmented layout, and is recorded by
 *      the mapper, not re-derived here.
 *
 * ROUND 20
 * --------
 *  kSegments 8 (version 3): a two-mbuf 1514 B frame can cost up to four runs
 *  (each mbuf may cross one page boundary), and a three-mbuf chain more. The
 *  round-19 bound of 4 would have rolled such a frame back after a successful
 *  map; the witness now records all runs the command can answer.
 */
namespace r18std {
/* Round26 changes request semantics only: mode 2 records the driver's internal
 * map-attempt sequence and the installed run token for every ordinary packet.
 * History geometry and binary field offsets remain unchanged. */
static const uint32_t kVersion = 5, kMax = 32, kSegments = 8, kMbufs = 8;
static const uint32_t kMagic = 0x38315854; /* "TX18" */
/* flags */
enum { kMapped = 1, kUnmapped = 2, kRefused = 4, kPinned = 8, kIdentity = 16 };
struct Segment { uint64_t address, length; };
struct Witness {
    uint32_t version, bytes, req, token; /* mode 2: internal sequence / run token */
    uint32_t handle;      /* probe generation handle; 0 = refused before map */
    uint32_t segCount;    /* segments IODMACommand generated */
    uint32_t mapOptions;  /* mapOptions actually delivered to the mapper */
    uint32_t flags;
    uint64_t memory;      /* IOMemoryDescriptor* the packet was described by */
    uint64_t command;     /* IODMACommand* that owns this mapping */
    uint64_t mapAddress;  /* first IOVA the command reported (== descriptor) */
    uint64_t mapLength;
    uint64_t descriptorOffset; /* prepare() arguments we asked for */
    uint64_t descriptorLength;
    Segment segments[kSegments]; /* gen64IOVMSegments() output, verbatim */
    /* Ordering stamps (mach ticks). tFree is stamped AFTER the mbuf and the
     * standard objects were released. */
    uint64_t tBegin, tPrepared, tSegmented, tCommit, tDone;
    uint64_t tCompleteBegin, tCompleteEnd, tFree;
    uint32_t prepareResult, segmentResult, completeResult, mbufSegments;
    uint32_t reserved0, reserved1, reserved2, reserved3;
};
struct Snapshot {
    uint32_t magic, version, bytes, count;
    uint32_t bdf, token, accepts, rejects;
    uint32_t unsupported, unmaps, pinned, maxHeld;
    uint32_t mode, historyTotal, historyStart, highReqAccepts; // mode 1 selected, 2 all; circular index=seq%32
    uint64_t tPublished;
    Witness witnesses[kMax];
};
static const uint32_t kHeaderBytes = 72;
static const uint32_t kWitnessBytes = 304; /* 8+6*8+8*16+8*8+8*4, aligned */
} /* namespace r18std */

/* Round 20: the blocked-ring record.
 *
 * This is published by the driver with the same throttle as the generation
 * snapshot, and again at Disarm -- which is exactly when the experiment learns
 * that the ring stopped moving. It answers three questions that the per-
 * generation witness cannot:
 *
 *   1. which TX slot is the first unfinished one (txDirty), and what its
 *      descriptor actually contains (addr/length/opts1/opts2/OWN);
 *   2. where the ring itself lives (ringAddr/ringBytes), so an IOMMU fault
 *      address can be classified as ring vs packet data;
 *   3. every outstanding descriptor's address (outAddr), so a fault address can
 *      be matched to the in-flight packet that caused it instead of guessed.
 *
 * The slots array holds the first 8 slots from txDirty and the last 8 before
 * txNext; `index` disambiguates them when the two ranges overlap or wrap.
 */
namespace r20tx {
/* Version 2 (round 21) adds the window-edge sample: `sampleStage` says WHICH
 * step of the enter/exit sequence produced this record, so a sample can no
 * longer be mistaken for the exit moment when it was really taken at the last
 * controlled completion. Round 20 published this block from r17TxPublish(),
 * whose change signature does not include ring or cover motion; after Disarm
 * restored Idle the signature was unchanged and the publication was skipped
 * entirely, leaving a block whose tSample was 9.014 s before the window ended.
 * The exit steps now sample unconditionally into this structure. */
static const uint32_t kVersion = 2, kSlots = 16, kOutstanding = 128;
static const uint32_t kMagic = 0x30325854; /* bytes "TX20" */
enum { kSelected = 1, kHasMbuf = 2, kOwn = 4, kFirst = 8, kLast = 16,
       kRingEnd = 32 };
/* sampleStage: which step forced this sample. */
enum { kStageThrottled = 0, kStageQuiesce = 1, kStageDrained = 2,
       kStageExit = 3, kStageResumed = 4 };
struct Slot {
    uint64_t addr;      /* descriptor address exactly as programmed */
    uint64_t mbufData;  /* txMbufArray[slot] data VA, 0 when the slot owns none */
    uint32_t index;     /* ring slot in [0, kNumTxDesc) */
    uint32_t opts1, opts2;
    uint32_t mbufLen;
    uint32_t flags;     /* the k* bits above */
    uint32_t pad2;
};
struct Block {
    uint32_t magic, version, bytes;
    uint32_t bdf, token, state;
    uint32_t txNext, txDirty, txClose, txTail, txFree, txDescDone;
    uint32_t completeCalls, completeHits, lastSeenSlot;
    uint32_t firstSlot, liveCount, liveHandle, liveReq, liveSegs, liveMbufs,
             liveFlags;
    uint32_t nslot, outstanding;
    uint64_t tSample;
    uint64_t ringAddr;    /* device-visible address of the TX descriptor ring */
    uint32_t ringBytes, ringDescSize;
    /* ---- round 21: window-edge context of THIS sample ---- */
    uint32_t sampleStage;  /* kStage* above */
    uint32_t sampleSeq;    /* monotonic per boot, so two samples never tie */
    uint32_t quiesced;     /* ordinary-submission gate at sample time */
    uint32_t activeCover;  /* kCover calls inside the backend at sample time */
    uint32_t coverCalls, coverRejects;
    Slot slots[kSlots];
    uint64_t outAddr[kOutstanding];  /* first unfinished .. txNext-1 */
    uint32_t outOpts1[kOutstanding];
};
#if defined(__cplusplus)
/* Round 21 first computed this struct as 2328 bytes and the archive agreed with
 * itself, because BOTH the analyzer offset table and the capture validator were
 * derived from that wrong number. The driver actually emits 2320: after
 * `tSample` comes `ringAddr` immediately, and the six new u32s end at 144, so
 * there is no trailing pad before `slots`. The mismatch only surfaced on the
 * machine, as "block blob: bad size".
 *
 * These pin the layout so a future field cannot silently shift every offset the
 * Python analyzer hard-codes. When this assert fires, update BOTH this number
 * and analyze.py's BLOCK_BYTES / offset table together -- that is the point.
 */
static_assert(sizeof(Slot) == 40, "Slot layout changed: update analyze.py");
static_assert(sizeof(Block) == 2320, "Block layout changed: update analyze.py");
static_assert(__builtin_offsetof(Block, tSample) == 96, "Block::tSample moved");
static_assert(__builtin_offsetof(Block, ringAddr) == 104, "Block::ringAddr moved");
static_assert(__builtin_offsetof(Block, sampleStage) == 120, "Block::sampleStage moved");
static_assert(__builtin_offsetof(Block, slots) == 144, "Block::slots moved");
static_assert(__builtin_offsetof(Block, outAddr) == 784, "Block::outAddr moved");
static_assert(__builtin_offsetof(Block, outOpts1) == 1808, "Block::outOpts1 moved");
#endif
} /* namespace r20tx */
#endif
