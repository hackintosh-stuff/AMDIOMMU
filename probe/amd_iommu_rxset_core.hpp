// amd_iommu_rxset_core.hpp -- build the CONSERVATIVE SET of RX buffers the NIC
// may write, from the driver's baseline slot table and its rearm log.
//
// ===========================================================================
// THE QUESTION THIS ANSWERS
// ===========================================================================
//
// Round 13 proved that the eight DMA ranges belonging to four controlled
// requests are mapped. That is a statement about 8 buffers out of ~1024 live
// ones, and about the four instants those buffers were current.
//
// The question M2-2b-2 actually has to answer for the RX direction is:
//
//     every RX buffer the device could write during the window -- is it
//     mapped, and does its page-table path carry write permission?
//
// So the unit of evidence has to be a SET, not a sample:
//
//     S = { (addr, capacity) in the baseline slot table }
//       ∪ { (addr, capacity) from every rearm record with
//           seq > baselineWatermark }
//
// ===========================================================================
// WHY THAT UNION IS A SUPERSET (the argument, stated so it can be attacked)
// ===========================================================================
//
// Let t0 be the instant the baseline capture scanned the descriptors, and let
// [t0, t1] be the interval we must cover.
//
//   * At t0, slot i posts exactly the (addr, capacity) in the baseline record,
//     so every buffer writable AT t0 is in the baseline half.
//
//   * Between t0 and t1 the ONLY way a slot's posted (addr, capacity) changes
//     is a rearm -- the driver rewriting buf.addr/buf.blen at the hand-back
//     site. Every such rewrite appends a rearm record, and the record carries
//     the FINAL values written. So every buffer that becomes writable in
//     (t0, t1] is in the rearm half.
//
//   * A buffer that stops being writable at some point in (t0, t1] is still
//     in the union, which is the safe direction: we claim coverage of more
//     than the device can reach, never less.
//
// Therefore S ⊇ { buffers writable at any instant in [t0, t1] }, provided the
// rearm log has no gap and no loss. Both are checked, not assumed:
//
//   GAP   `rearmFirstSeq <= watermark + 1`. If the ring lapped past the
//         watermark, records between the baseline and the oldest surviving
//         record are gone, and the set is INCOMPLETE. `complete` goes false
//         and the reason is a stable token.
//   LOSS  `dropped == 0` and `wrapped == 0`. A writer that could not take the
//         lock produced no record at all, so a buffer it re-armed is missing
//         from the set with no other symptom.
//
// ===========================================================================
// WHY DEDUPLICATION IS BY (addr, capacity) AND NOT BY SLOT
// ===========================================================================
//
// The same slot is rearmed hundreds of times; the same buffer address can
// migrate between slots; and a buffer re-posted with the same address and the
// same capacity is one range to check, not two. Keying on the slot would make
// the set grow with traffic while saying nothing new, and keying on the
// address alone would hide a capacity change -- which is the thing that
// decides how many bytes the device may write. So the key is the PAIR.
//
// A range that appears in both halves is recorded as SRC_BOTH, because that is
// the one case where the two independent records agree, and a disagreement
// between them would be a real finding rather than noise.
//
// ===========================================================================
// WHAT THIS FILE IS NOT
// ===========================================================================
//
// No IOKit, no allocation, no page-table access. It takes plain arrays of
// decoded records and returns a plain array of ranges. The probe points it at
// a driver publication; the host test points it at literal arrays. Same code,
// so the test exercises the production join rather than a restatement of it.

#pragma once

namespace amdrx {

typedef unsigned long long u64;
typedef unsigned int       u32;

// Where a range in the union came from.
enum {
    RX_SRC_BASELINE = 1u,
    RX_SRC_REARM    = 2u,
    RX_SRC_BOTH     = 3u
};

// One decoded baseline slot record. Field order mirrors the driver's SlotRec.
struct SlotRec {
    u64 addr;
    u64 blenRaw;
    u32 slot;
    u32 capacity;
    u32 flags;
    u32 gen;
};

// One decoded rearm record. Field order mirrors the driver's RearmRec.
//
// `oldAddr` is the address the rearm RETIRED and `addr` the one it installed.
// Both enter the union: see RTL812xRxPost.hpp for why recording only the new
// one leaves a buffer that was posted at the baseline instant in neither half
// when a rearm lands during the baseline scan.
struct RearmRec {
    u64 tMono;
    u64 addr;
    u64 oldAddr;
    u64 blenRaw;
    u32 seq;
    u32 slot;
    u32 capacity;
    u32 flags;
};

// ---- the published blob -------------------------------------------------
//
// Offsets, not a struct: the reader must not depend on the compiler's padding
// of a type it does not share with the driver. These are asserted against the
// driver's own header by tools/verify/rxpost-layout.py, which parses both
// declarations.
enum {
    RXB_MAGIC          = 0,
    RXB_VERSION        = 4,
    RXB_RECSIZE_SLOT   = 8,
    RXB_RECSIZE_REARM  = 12,
    RXB_HEAD           = 16,
    RXB_WRAPPED        = 20,
    RXB_DROPPED        = 24,
    RXB_SLOT_CAPACITY  = 28,
    RXB_REARM_CAPACITY = 32,
    RXB_REARM_FIRSTSEQ = 36,
    RXB_RING_GEN       = 40,
    RXB_BASELINE_ACTIVE= 44,
    RXB_BASELINE_SLOTS = 48,
    RXB_BASELINE_VALID = 52,
    RXB_BASELINE_ZERO  = 56,
    RXB_BASELINE_CAPD  = 60,
    RXB_BASELINE_CAPC  = 64,
    RXB_BASELINE_CAPBAD= 68,
    RXB_BASELINE_TORN  = 72,
    RXB_BASELINE_COUNT = 76,
    RXB_BASELINE_GENMOV= 80,
    RXB_PUB_ID         = 84,
    RXB_EPOCH          = 88,
    RXB_IF_UNIT        = 92,
    RXB_VTD_PATH       = 96,
    RXB_RX_BUFFER_SIZE = 100,
    RXB_FLAGS          = 104,
    RXB_T_BASELINE_LO  = 112,
    RXB_WATERMARK_LO   = 120,
    RXB_T_PUBLISHED_LO = 128,
    RXB_REARM_REQUIRED = 136,
    RXB_REARM_PUBLISHED= 140,
    RXB_HDR_BYTES      = 160,
    RXB_SLOT_BYTES     = 32,
    RXB_REARM_BYTES    = 48,
    RXB_SLOT_MAX       = 1024,
    RXB_REARM_MAX      = 4096
};

enum {
    RXB_FLAG_NO_BASELINE = 1u << 0,
    RXB_FLAG_REARM_LOST  = 1u << 1,
    RXB_FLAG_GEN_MOVED   = 1u << 2,
    RXB_FLAG_TRUNCATED   = 1u << 3
};

static inline u32 rd32(const unsigned char *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static inline u64 rd64(const unsigned char *p) {
    return (u64)rd32(p) | ((u64)rd32(p + 4) << 32);
}

// The decoded header. `ok` is false with a stable `why` on any mismatch, so a
// layout drift is a refusal rather than a plausible-looking decode.
struct BlobHeader {
    u32 magic, version, recSizeSlot, recSizeRearm;
    u32 head, wrapped, dropped, slotCapacity, rearmCapacity;
    u32 rearmFirstSeq, ringGen, baselineActive;
    u32 baselineSlots, baselineValid, baselineAddrZero;
    u32 baselineCapDesc, baselineCapConst, baselineCapBad, baselineTorn;
    u32 baselineCount, baselineGenMoved, pubId, epoch, ifUnit, vtdPath;
    u32 rxBufferSize, flags, rearmRequired, rearmPublished;
    u64 tBaseline, watermark, tPublished;
    u32 slotCount;        // records present in the blob
    u32 rearmCount;       // records present in the blob
    bool ok;
    const char *why;
};

static inline BlobHeader decodeBlob(const unsigned char *b, u64 bytes) {
    BlobHeader h;
    h.magic = 0; h.version = 0; h.recSizeSlot = 0; h.recSizeRearm = 0;
    h.head = 0; h.wrapped = 0; h.dropped = 0; h.slotCapacity = 0;
    h.rearmCapacity = 0; h.rearmFirstSeq = 0; h.ringGen = 0;
    h.baselineActive = 0; h.baselineSlots = 0; h.baselineValid = 0;
    h.baselineAddrZero = 0; h.baselineCapDesc = 0; h.baselineCapConst = 0;
    h.baselineCapBad = 0; h.baselineTorn = 0; h.baselineCount = 0;
    h.baselineGenMoved = 0; h.pubId = 0; h.epoch = 0; h.ifUnit = 0;
    h.vtdPath = 0; h.rxBufferSize = 0; h.flags = 0;
    h.rearmRequired = 0; h.rearmPublished = 0;
    h.tBaseline = 0; h.watermark = 0; h.tPublished = 0;
    h.slotCount = 0; h.rearmCount = 0;
    h.ok = false;
    h.why = "not-decoded";

    if (!b) { h.why = "no-bytes"; return h; }
    if (bytes < (u64)RXB_HDR_BYTES) { h.why = "shorter-than-a-header"; return h; }

    h.magic          = rd32(b + RXB_MAGIC);
    h.version        = rd32(b + RXB_VERSION);
    h.recSizeSlot    = rd32(b + RXB_RECSIZE_SLOT);
    h.recSizeRearm   = rd32(b + RXB_RECSIZE_REARM);
    h.head           = rd32(b + RXB_HEAD);
    h.wrapped        = rd32(b + RXB_WRAPPED);
    h.dropped        = rd32(b + RXB_DROPPED);
    h.slotCapacity   = rd32(b + RXB_SLOT_CAPACITY);
    h.rearmCapacity  = rd32(b + RXB_REARM_CAPACITY);
    h.rearmFirstSeq  = rd32(b + RXB_REARM_FIRSTSEQ);
    h.ringGen        = rd32(b + RXB_RING_GEN);
    h.baselineActive = rd32(b + RXB_BASELINE_ACTIVE);
    h.baselineSlots  = rd32(b + RXB_BASELINE_SLOTS);
    h.baselineValid  = rd32(b + RXB_BASELINE_VALID);
    h.baselineAddrZero = rd32(b + RXB_BASELINE_ZERO);
    h.baselineCapDesc  = rd32(b + RXB_BASELINE_CAPD);
    h.baselineCapConst = rd32(b + RXB_BASELINE_CAPC);
    h.baselineCapBad   = rd32(b + RXB_BASELINE_CAPBAD);
    h.baselineTorn     = rd32(b + RXB_BASELINE_TORN);
    h.baselineCount    = rd32(b + RXB_BASELINE_COUNT);
    h.baselineGenMoved = rd32(b + RXB_BASELINE_GENMOV);
    h.pubId          = rd32(b + RXB_PUB_ID);
    h.epoch          = rd32(b + RXB_EPOCH);
    h.ifUnit         = rd32(b + RXB_IF_UNIT);
    h.vtdPath        = rd32(b + RXB_VTD_PATH);
    h.rxBufferSize   = rd32(b + RXB_RX_BUFFER_SIZE);
    h.flags          = rd32(b + RXB_FLAGS);
    h.tBaseline      = rd64(b + RXB_T_BASELINE_LO);
    h.watermark      = rd64(b + RXB_WATERMARK_LO);
    h.tPublished     = rd64(b + RXB_T_PUBLISHED_LO);
    h.rearmRequired  = rd32(b + RXB_REARM_REQUIRED);
    h.rearmPublished = rd32(b + RXB_REARM_PUBLISHED);

    if (h.magic != 0x4F505852u) { h.why = "bad-magic"; return h; }
    if (h.version != 1u)        { h.why = "unknown-version"; return h; }
    if (h.recSizeSlot != (u32)RXB_SLOT_BYTES) { h.why = "slot-size-mismatch"; return h; }
    if (h.recSizeRearm != (u32)RXB_REARM_BYTES) { h.why = "rearm-size-mismatch"; return h; }
    if (h.slotCapacity != (u32)RXB_SLOT_MAX) { h.why = "slot-capacity-mismatch"; return h; }
    if (h.rearmCapacity == 0 || h.rearmCapacity > (u32)RXB_REARM_MAX) {
        h.why = "rearm-capacity-out-of-range"; return h;
    }

    // The body must be exactly header + slots + the rearms it claims.
    const u64 body = bytes - (u64)RXB_HDR_BYTES;
    const u64 slotBytes = (u64)RXB_SLOT_MAX * (u64)RXB_SLOT_BYTES;
    if (body < slotBytes) { h.why = "body-shorter-than-the-slot-table"; return h; }
    const u64 rest = body - slotBytes;
    if ((rest % (u64)RXB_REARM_BYTES) != 0) { h.why = "ragged-rearm-body"; return h; }
    const u64 n = rest / (u64)RXB_REARM_BYTES;
    if (n > (u64)h.rearmCapacity) { h.why = "more-rearms-than-the-ring"; return h; }
    if ((u32)n != h.rearmPublished) { h.why = "rearm-count-disagrees-with-header"; return h; }

    h.slotCount = RXB_SLOT_MAX;
    h.rearmCount = (u32)n;
    h.ok = true;
    h.why = nullptr;
    return h;
}

// Decode the slot at `i` from a blob.
static inline SlotRec slotAt(const unsigned char *b, u32 i) {
    const unsigned char *p = b + RXB_HDR_BYTES + (u64)i * (u64)RXB_SLOT_BYTES;
    SlotRec s;
    s.addr     = rd64(p + 0);
    s.blenRaw  = rd64(p + 8);
    s.slot     = rd32(p + 16);
    s.capacity = rd32(p + 20);
    s.flags    = rd32(p + 24);
    s.gen      = rd32(p + 28);
    return s;
}

// Decode rearm record `i` from a blob.
static inline RearmRec rearmAt(const unsigned char *b, u32 i) {
    const unsigned char *p =
        b + RXB_HDR_BYTES + (u64)RXB_SLOT_MAX * (u64)RXB_SLOT_BYTES +
        (u64)i * (u64)RXB_REARM_BYTES;
    RearmRec a;
    a.tMono    = rd64(p + 0);
    a.addr     = rd64(p + 8);
    a.oldAddr  = rd64(p + 16);
    a.blenRaw  = rd64(p + 24);
    a.seq      = rd32(p + 32);
    a.slot     = rd32(p + 36);
    a.capacity = rd32(p + 40);
    a.flags    = rd32(p + 44);
    return a;
}

// One range in the union.
struct Range {
    u64 addr;
    u32 capacity;
    u32 source;      // RX_SRC_*
    u32 slot;        // the slot it was last seen on (informational)
    u32 pad;
};

// Result of the join. `why` is a stable token whenever `complete` is false.
struct SetResult {
    u32  ranges;          // distinct (addr, capacity) pairs
    u32  fromBaseline;    // ranges seen in the baseline half
    u32  fromRearm;       // ranges seen in the rearm half
    u32  fromBoth;        // ranges seen in both
    u32  capped;          // ranges dropped because the array was full
    u32  skippedZero;     // records whose address was 0 (never a real buffer)
    u32  skippedBadCap;   // records whose capacity was 0
    u32  rearmSeen;       // rearm records examined
    u32  rearmRequired;   // rearm records the watermark says are needed
    u32  rearmUsed;       // rearm records that were past the watermark
    bool complete;
    const char *why;
};

// Reset a SetResult.
static inline void setResultInit(SetResult &r) {
    r.ranges = 0;
    r.fromBaseline = 0;
    r.fromRearm = 0;
    r.fromBoth = 0;
    r.capped = 0;
    r.skippedZero = 0;
    r.skippedBadCap = 0;
    r.rearmSeen = 0;
    r.rearmRequired = 0;
    r.rearmUsed = 0;
    r.complete = false;
    r.why = "not-built";
}

// Find (addr, capacity) in `out`, or -1. Linear because the arrays are small
// and bounded; a hash table here would be a second thing to get wrong.
static inline int setFind(const Range *out, u32 n, u64 addr, u32 capacity) {
    for (u32 i = 0; i < n; i++) {
        if (out[i].addr == addr && out[i].capacity == capacity) return (int)i;
    }
    return -1;
}

// Build the union.
//
// `watermark` is the rearm counter as it stood BEFORE the baseline scan. A
// rearm record is required when its seq is strictly greater; a record at or
// below the watermark is already reflected in the baseline slot table, and
// including it would double-count without adding coverage.
//
// `head` is the rearm counter at publication time. `rearmFirstSeq` is the
// oldest seq the ring still holds (0 = the ring is empty).
static inline void buildSet(const SlotRec *slots, u32 nSlots,
                            const RearmRec *rearms, u32 nRearms,
                            u32 watermark, u32 head, u32 rearmFirstSeq,
                            Range *out, u32 maxOut,
                            SetResult &r) {
    setResultInit(r);

    if (maxOut == 0) { r.why = "no-output-capacity"; return; }

    // ---- the gap check comes FIRST -------------------------------------
    //
    // If the ring lapped past the watermark, the records between the baseline
    // and the oldest survivor do not exist any more. The union would be a
    // subset and every downstream "all covered" claim would be about a set
    // that is not the one the device could write. Refusing here is the whole
    // point of carrying the watermark.
    r.rearmRequired = (head > watermark) ? (head - watermark) : 0u;
    if (r.rearmRequired > 0) {
        if (rearmFirstSeq == 0) {
            r.why = "rearm-ring-empty-but-records-required";
            return;
        }
        if (rearmFirstSeq > watermark + 1u) {
            r.why = "rearm-ring-lapped-past-baseline";
            return;
        }
        // The publication must actually carry every required record. `nRearms`
        // is what the blob contains, so a short publication is caught here
        // rather than by a header flag the reader could forget to check.
        if (nRearms < r.rearmRequired) {
            r.why = "rearm-publication-truncated";
            return;
        }
    }

    // ---- the baseline half ---------------------------------------------
    for (u32 i = 0; i < nSlots; i++) {
        const SlotRec &s = slots[i];
        if (s.addr == 0) { r.skippedZero++; continue; }
        if (s.capacity == 0) { r.skippedBadCap++; continue; }
        const int at = setFind(out, r.ranges, s.addr, s.capacity);
        if (at >= 0) {
            // Two slots posting the same range: one range, still a baseline
            // find. Do not overwrite the source with something narrower.
            if (out[at].source == RX_SRC_REARM) out[at].source = RX_SRC_BOTH;
            continue;
        }
        if (r.ranges >= maxOut) { r.capped++; continue; }
        Range &d = out[r.ranges++];
        d.addr = s.addr;
        d.capacity = s.capacity;
        d.source = RX_SRC_BASELINE;
        d.slot = s.slot;
        d.pad = 0;
        r.fromBaseline++;
    }

    // ---- the rearm half ------------------------------------------------
    //
    // EVERY record in the publication is consumed, not only the ones past the
    // watermark, because each one names the buffer it RETIRED as well as the
    // one it installed. A record at or below the watermark describes a rearm
    // that completed before the baseline scan started, so its `addr` is
    // already in the baseline -- but its `oldAddr` may have been replaced
    // before the scan and would otherwise be in neither half.
    //
    // `seq` is ticket*2, so the TICKET is seq>>1. Comparing the raw seq with
    // the watermark would count every record as "past the watermark" whenever
    // the watermark was non-zero -- a factor-of-two error in the completeness
    // arithmetic, which is exactly the kind of mistake that turns a partial set
    // into a "complete" one.
    for (u32 i = 0; i < nRearms; i++) {
        const RearmRec &a = rearms[i];
        if (a.seq == 0 || (a.seq & 1u)) continue;   // hole or body in flight
        r.rearmSeen++;
        const u32 ticket = a.seq >> 1;
        if (ticket > watermark) r.rearmUsed++;

        // Two addresses per record, each one a range the device could write.
        // `addr` is live from this rearm onward; `oldAddr` was live until it.
        for (unsigned side = 0; side < 2; side++) {
            const u64 ra = (side == 0) ? a.addr : a.oldAddr;
            if (ra == 0) { r.skippedZero++; continue; }
            if (a.capacity == 0) { r.skippedBadCap++; continue; }
            const int at = setFind(out, r.ranges, ra, a.capacity);
            if (at >= 0) {
                if (out[at].source == RX_SRC_BASELINE)
                    out[at].source = RX_SRC_BOTH;
                out[at].slot = a.slot;
                continue;
            }
            if (r.ranges >= maxOut) { r.capped++; continue; }
            Range &d = out[r.ranges++];
            d.addr = ra;
            d.capacity = a.capacity;
            d.source = RX_SRC_REARM;
            d.slot = a.slot;
            d.pad = 0;
            r.fromRearm++;
        }
    }

    for (u32 i = 0; i < r.ranges; i++) {
        if (out[i].source == RX_SRC_BOTH) r.fromBoth++;
    }

    // A union that dropped ranges because the array was full is NOT the set
    // the device could write, so it cannot be called complete.
    if (r.capped != 0) { r.why = "range-budget-exceeded"; return; }

    // Every record the watermark required must actually have been present.
    // A short read means the ring or the publication lost records between the
    // baseline and the end of the window.
    if (r.rearmUsed != r.rearmRequired) {
        r.why = "rearm-records-missing";
        return;
    }

    if (r.ranges == 0) { r.why = "empty-set"; return; }

    r.complete = true;
    r.why = nullptr;
}

}  // namespace amdrx
