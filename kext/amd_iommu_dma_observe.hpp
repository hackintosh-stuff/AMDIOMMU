// Device-DMA observation core -- shared by the kext and host regression tests.
//
// WHY THIS FILE EXISTS
// --------------------
// Round 5 could not answer "is the faulting address one the device was
// actually programmed with?", because the only counter it had
// (m1bb-realmapcalls) was zero: the RTL812xLucy driver at commit
// 639144d1 takes the mapper path only when useAppleVTD is true, and on this
// machine it is false, so the NIC is programmed with RAW PHYSICAL addresses
// obtained from mbuf_data_to_physical() / getPhysicalSegmentsWithCoalesce().
// Nothing in the mapper is ever consulted for that device.
//
// So the observation has to happen at the device: read the descriptor rings
// the NIC is actually walking, collect the addresses in them, and decide
// whether a faulting address falls inside that set.
//
// ROUND 7: WHAT WAS WRONG WITH THE ROUND-6 VERSION OF THIS FILE
// ------------------------------------------------------------
// Four defects, all of which this rewrite removes. They are listed here
// because each one produced a *plausible-looking* answer, which is the
// dangerous kind:
//
//  (1) RECORDING WAS FILTERED BY THE MAP LIMIT.
//      The kext called inIdentityRam() before inserting an address, and that
//      gate uses RAM_TOP = 16 GiB. So any descriptor address at or above
//      16 GiB -- exactly the class under investigation -- was silently
//      dropped before it could ever be classified. The set then "proved"
//      that the fault was not in the device's set, by never having been
//      allowed to contain such addresses in the first place.
//      FIX: recording and dereferencing are separate decisions.
//      `insert()` never consults a limit. `readVerdict()` decides only
//      whether it is safe to *read* the memory an address points at, and its
//      answer is stored as metadata next to the address.
//
//  (2) THE ENVELOPE STOPPED GROWING ONCE THE SET WAS FULL.
//      insertCoalesced() did `break` after a failed insert, so every later
//      interval was ignored for envelope purposes too. Round 6's own archive
//      contains the proof: envelope-hi = 0x3f80a4000 while txdesc4.addr =
//      0x3fec620e0 and txdesc5.addr = 0x3fec600e2 are both ABOVE it. An
//      envelope that is too small turns "outside the envelope" into a false
//      negative. That is exactly how round 6 concluded more than its
//      evidence allowed.
//      FIX: the loop always runs to the end. Every offered interval grows the
//      envelope whether or not it fits.
//
//  (3) THE COUNTERS WERE DOUBLE-COUNTED AND MIXED.
//      `set.dropped += (n - i) + 1` added *raw addresses* on top of the
//      per-insert increments, so `dropped` mixed "merged intervals that did
//      not fit" with "raw addresses inside them". Nothing distinguished raw
//      descriptors, merged intervals, saved intervals, dropped intervals, and
//      slots never examined at all.
//      FIX: five separate counters, each incremented in exactly one place.
//
//  (4) EVERY NON-ZERO ADDRESS WAS MARKED live = true.
//      One scan cannot know whether a descriptor is in flight, already
//      completed, or merely left over from an earlier generation. Calling all
//      of them "live" overstates what a snapshot can say.
//      FIX: lifecycle is derived from the driver's own cumulative submit and
//      close pointers (see txSlotLifecycle), and a lifecycle that cannot be
//      derived is reported as LIFE_UNKNOWN rather than assumed live.
//
// ROUND 8: WHAT ROUND 7 STILL GOT WRONG
// -------------------------------------
// Round 7 fixed the four defects above and then overstated what it had. The
// corrections are here because each one is a place where a plausible-looking
// result was produced by code that could not support it:
//
//  (5) LIFECYCLE WAS NEVER WIRED INTO PRODUCTION.
//      txSlotLifecycle() existed and was tested, but m2b2CollectTxSegments()
//      never called it: it ignored its own tailCum/cloCum arguments and marked
//      every non-zero TX address LIFE_INFLIGHT as soon as a close pointer was
//      readable. On the round-7 capture tail = clo = 0x6a (queue empty) and
//      every historical address was still reported in-flight.
//      FIX: scanTxWindow() drives the scan from the two cumulative pointers,
//      per slot, with generations, and decides lifecycle per descriptor.
//
//  (6) A SNAPSHOT HIT WAS REPORTED AS A COMPLETED RANGE.
//      classifyFault() used contains(), which ignores lifecycle, and returned
//      OWN_IN_DEAD_SET -- a claim about the past -- for a range that was
//      merely present. FIX: OWN_IN_SNAPSHOT_SET is its own verdict.
//
//  (7) A GAP IN A SNAPSHOT WAS TREATED AS A GAP IN THE WINDOW.
//      OWN_IN_ENVELOPE_GAP fired whenever the set was exact, with the reason
//      "the set is exact, so the device did not use this address". Exactness
//      is about the set; coverage is about time. FIX: a gap needs both.
//
//  (8) ONE COVERAGE VALUE WAS APPLIED TO EVERY PATH.
//      TX was window-covered; RX, the rings and the stats buffer were single
//      observations. FIX: PathCoverage, one value per path, and a negative
//      scoped to the path that was actually covered.
//
//  (9) THE BASIS FOR READING RING MEMORY WAS "A REGISTER SAID SO".
//      A device register proves the device was programmed with an address; it
//      does not prove the memory object is alive or that the PA maps to it.
//      FIX: ring fingerprints (RX RingEnd at the last slot, TX address/length
//      sanity) must pass before contents are trusted. The address is recorded
//      either way.
//
// ROUND 9: WHAT ROUND 8 STILL GOT WRONG
// -------------------------------------
// Round 8 finally wired the scan into production, and then the scan itself
// turned out to be unsafe and to lose records. Each item below is a concrete
// defect in this file, not a documentation issue:
//
// (10) THE WINDOW SCAN WAS UNBOUNDED AND HAD NO STOP CONDITION.
//      `for (k = 0; k < submits; k++)` where `submits` is a 31-bit masked
//      difference. A counter reset, a device swap, or a torn read -- exactly
//      the conditions that mean the numbers cannot be trusted -- produced a
//      loop of up to 2^31 iterations in the kernel. And a close pointer ahead
//      of the submit pointer, which is impossible, was scanned anyway.
//      FIX: TxScanStop. An implausible pair stops before the loop; the loop is
//      capped at TX_MAX_WINDOW_SCAN; indices beyond the cap are counted
//      arithmetically in `historicalSkipped` and never iterated.
//
// (11) "COMPLETES > SUBMITS" WAS TREATED AS AN ERROR.
//      A window that opens with a busy queue legitimately completes older
//      descriptors it never submitted. Round 8 compared `com > sub` and
//      refused that case, while accepting a close pointer that had run past
//      the submit pointer at the window's end. The legal case was rejected and
//      an illegal one accepted -- both in the same comparison.
//      FIX: `inFlightAtStart` is recorded, the bound is `com > sub + behind`,
//      and completions are split into `preWindowCompleted` (older descriptors)
//      and window completions.
//
// (12) SCAN FAILURE DID NOT WITHDRAW COVERAGE.
//      The counters were published, but `covered` depended only on the
//      pointer arithmetic. A scan that stopped early, dropped records, or
//      could not decode a length still produced `tx-window-covered = yes`.
//      FIX: TxWindowQuality. Exactness requires the scan to have completed,
//      nothing overwritten, nothing undecodable, and no record lost.
//
// (13) THE 31-BIT MASK WAS APPLIED TO THE DIFFERENCE BUT NOT TO THE WINDOW.
//      Round 8's own scan indexed with `tailBefore + k` masked, which is
//      right, but the coverage argument compared unmasked values against
//      ringSize. A window spanning a wrap was therefore sized wrongly.
//      FIX: every window quantity goes through the mask, and the pair is
//      refused outright when the masked distance is not representable.
//
// WHAT A SNAPSHOT CAN AND CANNOT PROVE
// ------------------------------------
// This is the single most important idea in this file, and round 6 got it
// wrong in its final report:
//
//   * A POSITIVE answer is sound from a snapshot. If a faulting address is
//     inside a range the device owns right now, the device does use it.
//   * A NEGATIVE answer from a snapshot is NOT sound in general. "Not in the
//     set at time T" does not mean "not the device's memory" -- the device
//     may have used that address at time T-1.
//
// So ownership is only ever reported as a statement about the observation,
// and a "the device does not use this address" conclusion requires coverage
// of the whole window. `Coverage` below records how much was actually
// covered, and classifyFault() refuses to return a definitive negative
// without window coverage.
//
// There is one case where window coverage is genuinely achievable for TX:
// the driver never clears a completed descriptor's address, so the ring at
// the end of the window still holds every descriptor submitted during it,
// provided fewer than ringSize descriptors were submitted. That is
// `txWindowCovered()` below.
//
// WHAT "COMPLETION" MEANS HERE
// ----------------------------
// On this part the hardware does NOT clear DescOwn. Round 6 dumped live
// descriptors that all still had bit 31 set while the interface was moving
// packets, and `tx-done` equalled `tx-zeroaddr` exactly -- the only
// DescOwn-clear slots were the never-programmed ones. The driver itself
// tracks completion through the hardware close pointer:
//
//     numDone = (nextClosePtr - txClosePtr0) & tp->MaxTxDescPtrMask
//
// with MaxTxDescPtrMask = 0x7FFFFFFF for HwSuppTxNoCloseVer 5 and 6, i.e.
// CFG_METHOD_41/42 -- this card. Note the mask is NOT the ring size: the
// close pointer is a free-running cumulative counter, so 1000 -> 2024 is a
// delta of 1024, not 0. Round 6 used a modulo-1024 ring advance and would
// have reported that case as "no progress".
//
// An RX descriptor whose DescOwn bit is SET is still owned by the device
// (empty); cleared means the device has written a frame into it.

#pragma once

namespace amdobs {

typedef unsigned long long u64;
typedef unsigned int       u32;
typedef unsigned char      u8;

// ---- purposes ------------------------------------------------------------

enum Purpose {
    PURP_UNKNOWN = 0,
    PURP_TX_RING,       // descriptor ring itself
    PURP_RX_RING,
    PURP_TX_BUF,        // packet payload the device reads
    PURP_RX_BUF,        // packet payload the device writes
    PURP_STAT,          // hardware statistics dump buffer
    PURP_COUNTER_DUMP,  // address written into CounterAddrLow/High
    PURP_OTHER
};

static inline const char *purposeName(u32 p) {
    switch (p) {
        case PURP_TX_RING:      return "tx-ring";
        case PURP_RX_RING:      return "rx-ring";
        case PURP_TX_BUF:       return "tx-buffer";
        case PURP_RX_BUF:       return "rx-buffer";
        case PURP_STAT:         return "stat-buffer";
        case PURP_COUNTER_DUMP: return "counter-dump";
        case PURP_OTHER:        return "other";
        default:                return "unknown";
    }
}

// ---- lifecycle -----------------------------------------------------------
//
// What the observation can honestly say about one descriptor's DMA range.

enum Lifecycle {
    LIFE_UNKNOWN = 0,   // no evidence; do NOT read this as "not in use"
    LIFE_SNAPSHOT,      // present in the snapshot, liveness not derivable
    LIFE_INFLIGHT,      // submitted and not yet handed back by the device
    LIFE_COMPLETED      // the device has already handed it back
};

static inline const char *lifecycleName(u32 l) {
    switch (l) {
        case LIFE_INFLIGHT:  return "in-flight";
        case LIFE_COMPLETED: return "completed";
        case LIFE_SNAPSHOT:  return "snapshot-only";
        default:             return "unknown";
    }
}

// ---- read permission -----------------------------------------------------
//
// Separate from recording on purpose (defect 1). An address is ALWAYS
// recorded; this only says whether it would have been safe to dereference
// the memory it points at. Recording an address must never require reading
// through it.

enum ReadVerdict {
    RD_OK = 0,        // verified RAM under the current policy
    RD_OUT_OF_MAP,    // beyond the identity map limit
    RD_NOT_RAM,       // inside the MMIO hole or another known non-RAM span
    RD_OVERFLOW,      // base + len wraps the address space
    RD_ZERO_LEN,      // zero-length interval
    RD_UNVERIFIED     // no authoritative physical layout available
};

static inline const char *readVerdictName(u32 v) {
    switch (v) {
        case RD_OK:         return "readable";
        case RD_OUT_OF_MAP: return "not-read: beyond identity map limit";
        case RD_NOT_RAM:    return "not-read: not ordinary RAM";
        case RD_OVERFLOW:   return "not-read: range wraps";
        case RD_ZERO_LEN:   return "not-read: zero length";
        default:            return "not-read: layout unverified";
    }
}

// Physical-layout policy.
//
// `limit` is the IDENTITY MAP limit. It is NOT the top of RAM, and round 5's
// mistake was to treat a RAM size as an address property. The probe sets
// `layoutKnown` only when it has a per-boot source for the layout; otherwise
// every read verdict is RD_UNVERIFIED and nothing is dereferenced.
//
// The hole boundaries below are this machine's firmware-placed 32-bit MMIO
// window. They are a *mapping* concern: mapping a page inside the hole as
// memory would panic the kernel, so it is refused -- but the address is still
// recorded.
struct MapPolicy {
    u64  limit;
    u64  ramHoleLo;
    u64  ramHoleHi;
    bool layoutKnown;
};

static inline MapPolicy defaultMapPolicy() {
    MapPolicy p;
    p.limit = 0x400000000ULL;      // 16 GiB identity map (M2-2b-2's coverage)
    p.ramHoleLo = 0x0E0000000ULL;  // firmware MMIO hole, below 4 GiB
    p.ramHoleHi = 0x100000000ULL;
    p.layoutKnown = false;         // must be proven per boot, not assumed
    return p;
}

// Would it be safe to read the memory at [base, base+len)?
//
// NEVER used to decide whether to record. Only to decide whether to map.
static inline u32 readVerdict(u64 base, u64 len, const MapPolicy &p) {
    if (len == 0) return RD_ZERO_LEN;
    if (base + len < base) return RD_OVERFLOW;
    const u64 end = base + len;
    if (end > p.limit) return RD_OUT_OF_MAP;
    // A range straddling the hole is refused rather than partly trusted.
    if (base < p.ramHoleHi && end > p.ramHoleLo) return RD_NOT_RAM;
    if (!p.layoutKnown) return RD_UNVERIFIED;
    return RD_OK;
}

// Read verdict for an address the DEVICE ITSELF reported, such as a ring base
// read out of TxDescStartAddrLow/High.
//
// WHY THIS IS A SEPARATE FUNCTION, AND WHY IT DOES NOT NEED `layoutKnown`
// ----------------------------------------------------------------------
// The two cases have different risk profiles, and conflating them cost a
// whole boot:
//
//   * A descriptor's `addr` field is an arbitrary 64-bit value sitting in
//     memory. Nothing has validated it. Dereferencing it on the strength of
//     a guessed memory map would be reckless, so it needs an authoritative
//     layout (RD_UNVERIFIED until one exists).
//
//   * A ring base is the address the driver programmed and the HARDWARE IS
//     ALREADY USING. Reading it is exactly as safe as the driver's own
//     access, because it is the same memory the device is walking right now.
//     What can still go wrong is mapping something that is not memory at
//     all, so the limit and the MMIO hole must be checked -- those are the
//     panic risks. `layoutKnown` is not: it is a statement about knowing
//     every RAM boundary, which is not needed to read one address the
//     hardware has already been using successfully.
//
// Round 7's first boot applied RD_UNVERIFIED to ring bases as well, and the
// result was an observation that recorded the right addresses but could read
// none of them: tx-slots = 0, raw-offered = 0, unscanned = 0x800. The
// accounting was honest about being useless, which is why the defect was
// visible at all.
static inline u32 readVerdictDeviceReported(u64 base, u64 len,
                                            const MapPolicy &p) {
    if (len == 0) return RD_ZERO_LEN;
    if (base + len < base) return RD_OVERFLOW;
    const u64 end = base + len;
    if (end > p.limit) return RD_OUT_OF_MAP;
    if (base < p.ramHoleHi && end > p.ramHoleLo) return RD_NOT_RAM;
    return RD_OK;
}

// Retained for callers that only have the map limit and want the hole check.
// Equivalent to readVerdict() with layoutKnown forced true.
static inline bool inIdentityRam(u64 base, u64 len) {
    MapPolicy p = defaultMapPolicy();
    p.layoutKnown = true;
    return readVerdict(base, len, p) == RD_OK;
}

// ---- the observed set ----------------------------------------------------

// Capacity is deliberately modest: this lives in a kext and every slot is
// real memory. It is NOT the mechanism that makes negatives sound -- the
// envelope is. Raising this number does not fix a truncated set; growing the
// envelope over dropped intervals does.
static const unsigned MAX_RANGES = 64;

struct Range {
    u64 base;
    u64 len;
    u32 purpose;
    u32 lifecycle;
    u32 readable;   // ReadVerdict, recorded at insert time
    u32 flags;      // RANGE_* below
};

// ROUND 8: a length that could not be decoded is recorded as such rather than
// being replaced by a guessed page size. A guessed length must never take part
// in an exact-coverage argument, so the flag travels with the range.
enum {
    RANGE_LEN_UNKNOWN = 1u << 0,   // len is a bound, not the real length
    RANGE_IN_WINDOW   = 1u << 1,   // submitted inside the measurement window
    RANGE_FROM_TSO    = 1u << 2    // descriptor had a TSO/GSO command bit
};

struct AddrSet {
    Range    r[MAX_RANGES];
    unsigned n;

    // ---- accounting: five distinct quantities, no double counting ----
    //
    // rawOffered    addresses taken from descriptors / registers, before merge
    // mergedTotal   coalesced intervals produced from them
    // savedCount    intervals actually stored (== n)
    // droppedCount  merged intervals that did not fit
    // unscanned     slots we could not examine at all (ring not mappable etc.)
    //
    // Invariant: mergedTotal == savedCount + droppedCount.
    unsigned rawOffered;
    unsigned mergedTotal;
    unsigned savedCount;
    unsigned droppedCount;
    unsigned zeroLenSkipped;
    unsigned unscanned;
    // ROUND 8: how many of the saved / dropped intervals carried a length we
    // could not decode. An exact-coverage claim is refused when this is
    // non-zero, because a guessed length cannot bound a negative.
    unsigned savedLenUnknown;
    unsigned droppedLenUnknown;

    // Envelope of EVERY interval offered, including ones that did not fit.
    // With the round-7 fix this is complete over all offered intervals even
    // when the set is full.
    u64      envLo;
    u64      envHi;
    bool     envValid;

    void clear() {
        n = 0;
        rawOffered = 0;
        mergedTotal = 0;
        savedCount = 0;
        droppedCount = 0;
        zeroLenSkipped = 0;
        unscanned = 0;
        savedLenUnknown = 0;
        droppedLenUnknown = 0;
        envLo = 0;
        envHi = 0;
        envValid = false;
    }

    // Grow the envelope. Overflow-safe: a wrapping interval cannot be
    // represented, so it widens the envelope to the whole address space
    // rather than being silently clipped.
    void growEnvelope(u64 base, u64 len) {
        const u64 end = base + len;
        if (end < base) {
            // The interval wraps: nothing can be excluded by this envelope.
            envLo = 0;
            envHi = ~0ULL;
            envValid = true;
            return;
        }
        if (!envValid) {
            envLo = base;
            envHi = end;
            envValid = true;
            return;
        }
        if (base < envLo) envLo = base;
        if (end > envHi) envHi = end;
    }

    // Insert one already-merged interval.
    //
    // The envelope is grown FIRST and unconditionally, so a full set can
    // never leave the envelope too small (defect 2). No limit of any kind is
    // consulted here (defect 1).
    bool insert(u64 base, u64 len, u32 purpose, u32 lifecycle, u32 readable,
                u32 flags = 0) {
        if (len == 0) {
            zeroLenSkipped++;
            return false;
        }
        growEnvelope(base, len);
        mergedTotal++;
        if (n >= MAX_RANGES) {
            droppedCount++;
            // A dropped interval may still be the one that matters. Keep the
            // count of dropped intervals that were length-uncertain so the
            // caller can refuse an exact-coverage claim.
            if (flags & RANGE_LEN_UNKNOWN) droppedLenUnknown++;
            return false;
        }
        r[n].base = base;
        r[n].len = len;
        r[n].purpose = purpose;
        r[n].lifecycle = lifecycle;
        r[n].readable = readable;
        r[n].flags = flags;
        n++;
        savedCount = n;
        if (flags & RANGE_LEN_UNKNOWN) savedLenUnknown++;
        return true;
    }

    // Interval containment, half-open [base, base+len).
    bool contains(u64 addr, u32 *purpose) const {
        for (unsigned i = 0; i < n; i++) {
            if (addr >= r[i].base && addr < r[i].base + r[i].len) {
                if (purpose) *purpose = r[i].purpose;
                return true;
            }
        }
        return false;
    }

    bool containsLifecycle(u64 addr, u32 want, u32 *purpose) const {
        for (unsigned i = 0; i < n; i++) {
            if (r[i].lifecycle != want) continue;
            if (addr >= r[i].base && addr < r[i].base + r[i].len) {
                if (purpose) *purpose = r[i].purpose;
                return true;
            }
        }
        return false;
    }

    bool containsLive(u64 addr, u32 *purpose) const {
        return containsLifecycle(addr, LIFE_INFLIGHT, purpose);
    }

    // True when the envelope bounds every address that was offered. Only then
    // can a query outside the envelope be called "outside the set".
    bool envelopeComplete() const { return envValid && unscanned == 0; }

    // The set is exact (nothing was dropped) when this is true.
    //
    // ROUND 8: a set with length-uncertain intervals is NOT exact for the
    // purpose of excluding an address, because "outside this interval" then
    // rests on a length we guessed. Exactness is about the set, so it is
    // reported separately from coverage, which is about time.
    bool exact() const { return droppedCount == 0 && unscanned == 0; }

    // Exact AND every interval's length was decoded. Required before any
    // "the device did not use this address" statement.
    bool exactBounded() const {
        return exact() && savedLenUnknown == 0;
    }
};

// ---- bounded sorting and coalescing -------------------------------------

// Shell sort over u64: no recursion, no allocation, usable in a kext.
static inline void shellSort(u64 *a, unsigned n) {
    static const unsigned gaps[] = { 701, 301, 132, 57, 23, 10, 4, 1 };
    for (unsigned g = 0; g < sizeof(gaps) / sizeof(gaps[0]); g++) {
        const unsigned gap = gaps[g];
        if (gap >= n && gap != 1) continue;
        for (unsigned i = gap; i < n; i++) {
            const u64 tmp = a[i];
            unsigned j = i;
            while (j >= gap && a[j - gap] > tmp) {
                a[j] = a[j - gap];
                j -= gap;
            }
            a[j] = tmp;
        }
    }
}

// One DMA interval to be recorded, before merging.
struct Seg {
    u64 base;
    u64 len;
    u32 flags;      // RANGE_*; RANGE_LEN_UNKNOWN survives the merge
    u32 pad;
};

// Sort + merge a list of (base,len) segments and insert the result.
//
// `segs` is sorted in place; `n` entries are consumed. Returns the number of
// merged intervals stored. Every input segment is accounted for exactly once:
// either it merged into an interval that was stored, or into one that was
// dropped, or it was zero-length. The envelope covers all of them.
static inline unsigned insertSegments(AddrSet &set, Seg *segs, unsigned n,
                                      u32 purpose, u32 lifecycle,
                                      const MapPolicy &policy) {
    if (!segs || n == 0) return 0;

    // Sort by base. Simple insertion sort over segments: n is at most a few
    // thousand and this runs once per ring scan, not per packet.
    for (unsigned i = 1; i < n; i++) {
        const Seg key = segs[i];
        unsigned j = i;
        while (j > 0 && segs[j - 1].base > key.base) {
            segs[j] = segs[j - 1];
            j--;
        }
        segs[j] = key;
    }

    set.rawOffered += n;

    unsigned i = 0;
    while (i < n) {
        const u64 base = segs[i].base;
        u64 end = segs[i].base + segs[i].len;
        u32 flags = segs[i].flags;
        if (end < segs[i].base) {
            // Wrapping segment: widen the envelope to everything and record
            // nothing else about it.
            set.insert(base, ~0ULL, purpose, lifecycle, RD_OVERFLOW,
                       flags | RANGE_LEN_UNKNOWN);
            i++;
            continue;
        }
        i++;
        while (i < n) {
            const u64 nb = segs[i].base;
            const u64 ne = nb + segs[i].len;
            if (nb > end) break;                 // a real gap
            if (ne > end) end = ne;              // overlapping or adjacent
            // The merged interval is only as well known as its least known
            // part: if any constituent had an undecoded length, the merge
            // must inherit that.
            flags |= segs[i].flags & RANGE_LEN_UNKNOWN;
            i++;
        }
        const u64 len = end - base;
        // The read verdict is metadata. It is recorded, never used to filter.
        set.insert(base, len, purpose, lifecycle,
                   readVerdict(base, len, policy), flags);
    }
    return set.savedCount;
}

// Insert `n` page-aligned addresses as page-sized intervals.
//
// Kept for the case where only addresses (not lengths) are known. Prefer
// insertSegments() when the descriptor carries a length.
static inline unsigned insertCoalesced(AddrSet &set, u64 *scratch, unsigned n,
                                       u64 pageSize, u32 purpose,
                                       u32 lifecycle, const MapPolicy &policy) {
    if (!scratch || n == 0 || pageSize == 0) return 0;

    shellSort(scratch, n);

    // Round 7: the loop ALWAYS runs to the end. Round 6 broke out on the first
    // failed insert, so later intervals never grew the envelope -- which is
    // how its own archive ended up with descriptor addresses above
    // envelope-hi.
    unsigned i = 0;
    while (i < n) {
        const u64 base = scratch[i];
        u64 end = base + pageSize;
        if (end < base) {                        // wraps
            set.insert(base, ~0ULL, purpose, lifecycle, RD_OVERFLOW);
            i++;
            continue;
        }
        i++;
        while (i < n && scratch[i] <= end) {
            const u64 e2 = scratch[i] + pageSize;
            if (e2 > end) end = e2;
            i++;
        }
        const u64 len = end - base;
        set.insert(base, len, purpose, lifecycle,
                   readVerdict(base, len, policy));
    }
    set.rawOffered += n;
    return set.savedCount;
}

// ---- coverage ------------------------------------------------------------

// How much of the window the observation actually covers. A negative
// ownership claim requires COV_WINDOW; a snapshot supports only a positive
// one.
enum Coverage {
    COV_NONE = 0,    // nothing observed
    COV_SNAPSHOT,    // one or more instants; negatives are instant-scoped
    COV_WINDOW       // every descriptor used during the window is visible
};

static inline const char *coverageName(u32 c) {
    switch (c) {
        case COV_WINDOW:   return "window-complete";
        case COV_SNAPSHOT: return "snapshot-only";
        default:           return "none";
    }
}

// TX window coverage argument.
//
// The driver never clears a completed descriptor's address: txInterrupt()
// frees the mbuf and advances txDirtyDescIndex, but the descriptor bytes are
// left alone until outputStart() rewrites that slot. So the ring scanned at
// the END of the window still contains the descriptor of every transmission
// submitted during the window, as long as fewer than ringSize descriptors
// were submitted (otherwise an early one has been overwritten).
//
// `tailStart`/`tailEnd` are the driver's cumulative submit pointers read at
// the two window edges. Returns true when the coverage argument holds.
static inline bool txWindowCovered(u32 tailStart, u32 tailEnd, u32 ringSize,
                                   u32 mask) {
    if (ringSize == 0) return false;
    const u32 delta = (u32)((tailEnd - tailStart) & mask);
    // A delta of exactly ringSize means every slot was rewritten: the oldest
    // descriptor of the window has been overwritten, so coverage is lost.
    if (delta == 0) return false;      // nothing submitted: nothing to cover
    return delta < ringSize;
}

// ---- fault classification ------------------------------------------------

// ROUND 8: the round-7 enum conflated two different things.
//
// `contains()` returns true for ANY range, whatever its lifecycle. Round 7
// therefore reported a hit in a snapshot-only range as OWN_IN_DEAD_SET --
// "the address is inside a DMA range the device already handed back". That is
// a claim about the PAST that a single snapshot cannot make: the range was
// merely present when we looked, and liveness was never established. A
// snapshot hit is now its own verdict.
//
// The negative side had the mirror-image defect. `OWN_IN_ENVELOPE_GAP` fired
// whenever the set was exact, even under snapshot coverage, with the reason
// text "the set is exact, so the device did not use this address". Exactness
// is a statement about the SET (nothing was dropped); coverage is a statement
// about TIME (we watched the whole window). A gap in a snapshot says nothing
// about the rest of the window, so a gap now needs window coverage too.
//
// Finally, a negative is only ever licensed for the device path that was
// actually covered. TX window coverage does not cover RX: the RX buffers are
// programmed from mbuf_data_to_physical() on a path the TX ring scan never
// sees. So the strongest negative we can honestly reach with TX-only coverage
// is "not used by the TX path during the window", which is
// OWN_TX_WINDOW_ABSENT -- scoped, not global.
enum Ownership {
    OWN_IN_LIVE_SET = 0,   // inside a range currently in flight
    OWN_IN_COMPLETED_SET,  // inside a range the device already handed back
    OWN_IN_SNAPSHOT_SET,   // inside a range seen in a snapshot; liveness unknown
    OWN_TX_WINDOW_ABSENT,  // not in any TX range across a complete TX window
    OWN_IN_ENVELOPE_GAP,   // inside the envelope, in a gap, set exact + covered
    OWN_OUTSIDE_ENVELOPE,  // outside every range, ALL paths window-covered
    OWN_OBSERVED_ABSENT,   // absent at the observation instants only
    OWN_ENVELOPE_UNKNOWN   // set incomplete: cannot decide
};

static inline const char *ownershipName(Ownership o) {
    switch (o) {
        case OWN_IN_LIVE_SET:      return "in-live-dma-set";
        case OWN_IN_COMPLETED_SET: return "in-completed-dma-range";
        case OWN_IN_SNAPSHOT_SET:  return "in-snapshot-dma-range";
        case OWN_TX_WINDOW_ABSENT: return "absent-from-tx-path-over-window";
        case OWN_OUTSIDE_ENVELOPE: return "outside-observed-dma-envelope";
        case OWN_IN_ENVELOPE_GAP:  return "in-envelope-gap";
        case OWN_OBSERVED_ABSENT:  return "absent-at-observation-instants";
        default:                   return "in-envelope-but-set-incomplete";
    }
}

// True only for the verdicts that license a NEGATIVE ownership statement --
// each one scoped to what was actually covered.
static inline bool ownershipIsNegative(Ownership o) {
    return o == OWN_OUTSIDE_ENVELOPE || o == OWN_IN_ENVELOPE_GAP ||
           o == OWN_OBSERVED_ABSENT || o == OWN_TX_WINDOW_ABSENT;
}

// True only for a negative that holds for the WHOLE device, every path.
// With TX-only coverage this is never available, which is the point: the
// probe must not upgrade a per-path result into a device-wide one.
static inline bool ownershipIsGlobalNegative(Ownership o) {
    return o == OWN_OUTSIDE_ENVELOPE || o == OWN_IN_ENVELOPE_GAP;
}

// True only for the verdicts that license a POSITIVE ownership statement.
static inline bool ownershipIsPositive(Ownership o) {
    return o == OWN_IN_LIVE_SET || o == OWN_IN_COMPLETED_SET ||
           o == OWN_IN_SNAPSHOT_SET;
}

// ---- device paths --------------------------------------------------------
//
// Coverage, and therefore any negative derived from it, is per path. The
// probe publishes one Coverage per path so that "TX is complete" can never be
// read as "RX is complete".
enum PathId {
    PATH_NONE = 0,
    PATH_TX_RING,
    PATH_RX_RING,
    PATH_TX_BUF,
    PATH_RX_BUF,
    PATH_STAT
};

static inline const char *pathName(u32 p) {
    switch (p) {
        case PATH_TX_RING: return "tx-ring";
        case PATH_RX_RING: return "rx-ring";
        case PATH_TX_BUF:  return "tx-buffer";
        case PATH_RX_BUF:  return "rx-buffer";
        case PATH_STAT:    return "stat-buffer";
        default:           return "none";
    }
}

struct FaultClass {
    Ownership own;
    u32       purpose;
    bool      inMappedRange;
    u64       mapLimit;
    const char *reason;
    // ROUND 8: what the verdict is a statement about. A negative that covers
    // only the TX path must say so, and a caller that reports it as a
    // device-wide fact is wrong even though the verdict itself is sound.
    u32       scopePath;     // PATH_* the negative is scoped to, or PATH_NONE
    bool      globalScope;   // true only when every path was window-covered
};

// Classify one faulting DVA against an observed set.
//
// ORDERING MATTERS. Round 5 asked "is it above 16 GiB?" first and concluded
// "therefore MMIO". Here set membership comes first, then the envelope, and
// the map limit is reported as a separate fact that never overrides either.
//
// ROUND 7 added the coverage dimension: a snapshot cannot support "the device
// does not use this address".
//
// ROUND 8 adds two refinements, both of which were holes:
//
//   * A hit in a range whose lifecycle is LIFE_SNAPSHOT is reported as
//     OWN_IN_SNAPSHOT_SET, not as a completed range. Round 7 claimed
//     "in-completed-dma-range" for a range that was merely present.
//
//   * A negative needs window coverage AND, for anything stronger than a
//     per-path statement, coverage of every path. `allPathsCovered` says
//     whether the caller actually has that; when it does not, the strongest
//     honest answer is OWN_TX_WINDOW_ABSENT, scoped to the TX path.
static inline FaultClass classifyFault(u64 addr, const AddrSet &set,
                                       const MapPolicy &policy,
                                       u32 coverage,
                                       bool allPathsCovered = false,
                                       bool actualMapKnown = false,
                                       bool actualMapped = false) {
    FaultClass f;
    f.purpose = PURP_UNKNOWN;
    f.mapLimit = policy.limit; // bootstrap/read-policy fact, not a RAM ceiling
    // Round15 sparse additions cannot be classified with a scalar limit.
    // Production passes the actual page-table result; legacy callers retain
    // their explicitly continuous-map semantics.
    f.inMappedRange = actualMapKnown ? actualMapped : (addr < policy.limit);
    f.scopePath = PATH_NONE;
    f.globalScope = false;

    if (set.containsLive(addr, &f.purpose)) {
        f.own = OWN_IN_LIVE_SET;
        f.reason = "the address is inside a DMA range the device currently owns";
        return f;
    }
    if (set.containsLifecycle(addr, LIFE_COMPLETED, &f.purpose)) {
        f.own = OWN_IN_COMPLETED_SET;
        f.reason = "the address is inside a DMA range the device already "
                   "handed back";
        return f;
    }
    // Round 8: a snapshot hit is NOT a completed-range hit. Answer it before
    // the generic containment test so it cannot be mistaken for one.
    if (set.containsLifecycle(addr, LIFE_SNAPSHOT, &f.purpose)) {
        f.own = OWN_IN_SNAPSHOT_SET;
        f.reason = "the address is inside a DMA range seen in the snapshot; "
                   "whether the device is using it now cannot be derived from "
                   "one observation";
        return f;
    }
    if (set.contains(addr, &f.purpose)) {
        // Present, but the range's lifecycle is unknown. Still a positive
        // statement (the range was observed), just a weaker one.
        f.own = OWN_IN_SNAPSHOT_SET;
        f.reason = "the address is inside an observed DMA range whose "
                   "lifecycle could not be determined";
        return f;
    }
    if (!set.envValid) {
        f.own = OWN_ENVELOPE_UNKNOWN;
        f.reason = "no DMA ranges were observed at all";
        return f;
    }
    if (addr < set.envLo || addr >= set.envHi) {
        // Outside the envelope. The envelope covers dropped intervals too, so
        // this is not affected by truncation -- but it IS affected by whether
        // every descriptor slot could be examined, and by whether the
        // observation spans the window.
        if (set.unscanned != 0) {
            f.own = OWN_ENVELOPE_UNKNOWN;
            f.reason = "outside the observed envelope, but some descriptor "
                       "slots could not be examined, so the envelope is not "
                       "known to bound them";
            return f;
        }
        if (coverage != COV_WINDOW) {
            f.own = OWN_OBSERVED_ABSENT;
            f.reason = "absent at the observation instants; the observation "
                       "is snapshot-only, so this does NOT establish that the "
                       "device never used the address";
            return f;
        }
        if (!allPathsCovered) {
            // Window coverage exists, but only for some paths. Saying
            // "outside every DMA range the device used" would generalise a
            // TX-only result to RX, the rings and the stats buffer.
            f.own = OWN_TX_WINDOW_ABSENT;
            f.scopePath = PATH_TX_BUF;
            f.reason = "not used by the TX path during a complete TX window; "
                       "RX and other paths were not covered for the whole "
                       "window, so this is NOT a device-wide negative";
            return f;
        }
        f.own = OWN_OUTSIDE_ENVELOPE;
        f.globalScope = true;
        f.reason = "the address lies outside every DMA range the device used "
                   "during a window-complete observation of all paths";
        return f;
    }
    // Inside the envelope.
    if (set.exact() && coverage == COV_WINDOW) {
        f.own = OWN_IN_ENVELOPE_GAP;
        f.globalScope = allPathsCovered;
        if (!allPathsCovered) {
            f.scopePath = PATH_TX_BUF;
            f.reason = "inside the observed TX envelope but in a gap; the set "
                       "is exact and the TX window is complete, so the TX path "
                       "did not use it. Other paths were not covered.";
        } else {
            f.reason = "inside the observed envelope but in a gap; the set is "
                       "exact and every path was covered, so the device did "
                       "not use this address during the window";
        }
        return f;
    }
    if (set.exact() && coverage != COV_WINDOW) {
        // Round 7's defect: exactness alone was enough for a gap verdict,
        // even though the observation was one instant. A gap in a snapshot is
        // not a gap in the window.
        f.own = OWN_OBSERVED_ABSENT;
        f.reason = "inside the observed envelope but in a gap at the "
                   "observation instants; the observation is snapshot-only, "
                   "so the gap is not known to hold for the window";
        return f;
    }
    f.own = OWN_ENVELOPE_UNKNOWN;
    f.reason = "inside the observed envelope and the set overflowed, so the "
               "device may have used this address without it being recorded";
    return f;
}

// ---- descriptor decoders -------------------------------------------------

// TX descriptor, 32-byte stride. USE_NEW_TX_DESC is defined by the driver's
// prefix header for this chip, which adds 16 reserved bytes.
//
//   opts1 : bit31 DescOwn | bit30 RingEnd | bit29 FirstFrag | bit28 LastFrag
//           | bit27 LargeSend | bit26 GiantSendv4 | bit25 GiantSendv6
//           | bits 15:0  length (MSS instead of length when TSO is set)
//   opts2 : VLAN tag / MSS
//   addr  : 64-bit DMA address
static const unsigned TX_DESC_STRIDE = 32;
static const u32      TX_DESC_OWN      = 1u << 31;
static const u32      TX_DESC_RINGEND  = 1u << 30;
static const u32      TX_DESC_FIRST    = 1u << 29;
static const u32      TX_DESC_LAST     = 1u << 28;
static const u32      TX_DESC_LARGESEND = 1u << 27;
static const u32      TX_DESC_GSO4     = 1u << 26;
static const u32      TX_DESC_GSO6     = 1u << 25;
static const u32      TX_DESC_LENMASK  = 0xFFFFu;

// RX descriptor, 16-byte stride. The first 8 bytes are `blen`, whose low 32
// bits carry (buffer length | DescOwn | RingEnd).
static const unsigned RX_DESC_STRIDE = 16;
static const u32      RX_DESC_OWN     = 1u << 31;
static const u32      RX_DESC_RINGEND = 1u << 30;

static inline u32 rd32(const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) |
           ((u32)p[3] << 24);
}

static inline u64 rd64(const u8 *p) {
    return (u64)rd32(p) | ((u64)rd32(p + 4) << 32);
}

// One decoded TX descriptor.
struct TxDesc {
    u32 slot;
    u32 opts1;
    u32 opts2;
    u64 addr;
    u32 len;        // opts1 & 0xFFFF; MSS when TSO is set
    bool own;
    bool ringEnd;
    bool first;
    bool last;
    bool tso;
};

// Visit every TX descriptor. Callback based so no array is needed: a ring is
// 1024 slots and the kext must not allocate one record per slot.
template <typename Fn>
inline void forEachTxDesc(const u8 *base, unsigned count, Fn fn) {
    if (!base) return;
    for (unsigned i = 0; i < count; i++) {
        const u8 *d = base + (u64)i * TX_DESC_STRIDE;
        TxDesc t;
        t.slot = i;
        t.opts1 = rd32(d);
        t.opts2 = rd32(d + 4);
        t.addr = rd64(d + 8);
        t.len = t.opts1 & TX_DESC_LENMASK;
        t.own = (t.opts1 & TX_DESC_OWN) != 0;
        t.ringEnd = (t.opts1 & TX_DESC_RINGEND) != 0;
        t.first = (t.opts1 & TX_DESC_FIRST) != 0;
        t.last = (t.opts1 & TX_DESC_LAST) != 0;
        t.tso = (t.opts1 & (TX_DESC_LARGESEND | TX_DESC_GSO4 | TX_DESC_GSO6))
                != 0;
        fn(t);
    }
}

struct RxDesc {
    u32 slot;
    u32 blen;
    u64 addr;
    bool own;
};

template <typename Fn>
inline void forEachRxDesc(const u8 *base, unsigned count, Fn fn) {
    if (!base) return;
    for (unsigned i = 0; i < count; i++) {
        const u8 *d = base + (u64)i * RX_DESC_STRIDE;
        RxDesc r;
        r.slot = i;
        r.blen = rd32(d);
        r.addr = rd64(d + 8);
        r.own = (r.blen & RX_DESC_OWN) != 0;
        fn(r);
    }
}

// Aggregate TX ring statistics.
//
// `done` counts every DescOwn-clear slot, which on this chip means only the
// never-programmed ones -- it is NOT a completion count. `doneWithAddr`
// requires the slot to have been programmed as well. Both are kept so the
// difference stays visible; nothing should report `done` as completions.
struct TxRingStats {
    u32 slots;
    u32 owned;
    u32 done;
    u32 ringEnd;
    u32 addrZero;
    u32 tsoSlots;
    u64 firstAddr;
    u32 doneWithAddr;
};

template <typename Fn>
static inline TxRingStats scanTxRingWith(const u8 *base, unsigned count,
                                         Fn fn) {
    TxRingStats s;
    s.slots = 0; s.owned = 0; s.done = 0; s.ringEnd = 0;
    s.addrZero = 0; s.tsoSlots = 0; s.firstAddr = 0; s.doneWithAddr = 0;
    if (!base) return s;
    forEachTxDesc(base, count, [&](const TxDesc &t) {
        s.slots++;
        if (t.own) s.owned++;
        else       s.done++;
        if (!t.own && t.addr != 0) s.doneWithAddr++;
        if (t.ringEnd) s.ringEnd++;
        if (t.tso) s.tsoSlots++;
        if (t.addr == 0) s.addrZero++;
        else if (s.firstAddr == 0) s.firstAddr = t.addr;
        fn(t);
    });
    return s;
}

static inline TxRingStats scanTxRing(const u8 *base, unsigned count) {
    return scanTxRingWith(base, count, [](const TxDesc &) {});
}

struct RxRingStats {
    u32 slots;
    u32 owned;
    u32 done;
    u32 addrZero;
    u64 firstAddr;
};

template <typename Fn>
static inline RxRingStats scanRxRingWith(const u8 *base, unsigned count,
                                         Fn fn) {
    RxRingStats s;
    s.slots = 0; s.owned = 0; s.done = 0; s.addrZero = 0; s.firstAddr = 0;
    if (!base) return s;
    forEachRxDesc(base, count, [&](const RxDesc &r) {
        s.slots++;
        if (r.own) s.owned++;
        else       s.done++;
        if (r.addr == 0) s.addrZero++;
        else if (s.firstAddr == 0) s.firstAddr = r.addr;
        fn(r);
    });
    return s;
}

static inline RxRingStats scanRxRing(const u8 *base, unsigned count) {
    return scanRxRingWith(base, count, [](const RxDesc &) {});
}

// ---- TX slot lifecycle from the driver's cumulative pointers -------------
//
// This is what replaces round 6's "every non-zero address is live = true".
//
// The driver keeps two cumulative counters:
//   txTailPtr0  -- written to SW_TAIL_PTR; how many descriptors were submitted
//   txClosePtr0 -- read from HW_CLO_PTR;  how many the device handed back
//
// Both are free-running (masked with MaxTxDescPtrMask, 0x7FFFFFFF on this
// part). A slot i corresponds to the largest cumulative index c <= tail with
// c & (ringSize-1) == i. Comparing c with the close pointer tells us whether
// the device has finished with that descriptor.

// Forward declarations: the close-pointer arithmetic lives in its own section
// below, but the TX window coverage argument needs it.
static inline u32  cloPtrDelta(u32 before, u32 after, u32 mask);
static inline bool cloPtrDeltaPlausible(u32 delta, u32 mask);
// Largest cumulative index <= tailCum whose low bits equal `slot`.
static inline u64 txSlotCumulative(u32 slot, u32 tailCum, u32 ringSize) {
    if (ringSize == 0) return 0;
    const u32 ringMask = ringSize - 1;
    const u32 back = (u32)((tailCum - slot) & ringMask);
    return (u64)tailCum - (u64)back;
}

// Lifecycle of one TX slot given the two cumulative pointers.
//
// The queue depth is tiny compared with the counter space, so "is c behind
// clo?" is decided by looking at the forward distance from clo to c: small
// means in flight, huge means already handed back.
static inline u32 txSlotLifecycle(u32 slot, u32 tailCum, u32 cloCum,
                                  u32 ringSize, u32 mask, bool haveClo) {
    if (ringSize == 0) return LIFE_UNKNOWN;
    if (!haveClo) {
        // No close pointer: the snapshot shows the descriptor but says
        // nothing about whether the device is done with it.
        return LIFE_SNAPSHOT;
    }
    const u64 c = txSlotCumulative(slot, tailCum, ringSize);
    const u32 ahead = (u32)(((u32)c - cloCum) & mask);
    // Half the counter space is the decision boundary.
    const u32 half = (mask >> 1) + 1u;
    return (ahead >= half) ? LIFE_COMPLETED : LIFE_INFLIGHT;
}

// Is cumulative index `c` already behind close pointer `cloCum`?
//
// This compares the CUMULATIVE indices directly. It must not be routed
// through txSlotCumulative(): for a descriptor submitted after the snapshot
// that helper returns a wrapped future index and the comparison becomes
// nonsense. Round 8's first draft did exactly that and undercounted the
// window's completions (3 reported as 1).
static inline bool txCumCompleted(u32 c, u32 cloCum, u32 mask) {
    if (mask == 0) return false;
    const u32 ahead = (u32)((c - cloCum) & mask);
    return ahead >= ((mask >> 1) + 1u);
}

// ---- ROUND 8: generation-aware slot lifecycle ----------------------------
//
// txSlotLifecycle() above answers "did the device hand back the descriptor
// that is in this slot NOW". That is necessary but not sufficient for the
// round-8 question, which is "which descriptors were SUBMITTED during the
// window, and what happened to each".
//
// Two cumulative pointers taken at the two window edges give exactly that,
// without needing to instrument the driver:
//
//   tailBefore .. tailAfter   every cumulative index submitted in the window
//   cloBefore  .. cloAfter    every cumulative index the device handed back
//
// Each cumulative index c maps to slot (c & (ringSize-1)) and to a
// GENERATION floor(c / ringSize). A slot's bytes at the end of the window
// belong to the newest generation that wrote it, so comparing the generation
// we recorded against the generation a cumulative index implies is how slot
// reuse becomes visible instead of silently overwriting evidence.
//
// This is the whole coverage argument. It is sound only while the submit
// count is below the ring size; at or above it, an early descriptor of the
// window has been overwritten and the ring no longer holds it.
static inline u32 txGeneration(u32 cumulative, u32 ringSize) {
    if (ringSize == 0) return 0;
    return cumulative / ringSize;
}

// Number of descriptors submitted in the window [tailBefore, tailAfter).
static inline u32 txWindowSubmits(u32 tailBefore, u32 tailAfter, u32 mask) {
    if (mask == 0) return 0;
    return (u32)((tailAfter - tailBefore) & mask);
}

// Number of descriptors the device handed back in the same window.
static inline u32 txWindowCompletes(u32 cloBefore, u32 cloAfter, u32 mask) {
    if (mask == 0) return 0;
    return (u32)((cloAfter - cloBefore) & mask);
}

// Is a slot's current content still the descriptor of cumulative index c?
//
// True when no later submit has reused the slot, i.e. when c is the newest
// descriptor actually WRITTEN into that slot at `tailAfter`.
//
// The newest written index is not txSlotCumulative(slot, tailAfter, ...):
// `tailAfter` is the NEXT index to submit, so when (tailAfter - slot) is a
// multiple of ringSize that helper returns tailAfter itself -- an index that
// has not been written yet. An earlier draft used it, and a descriptor that
// was still present was reported as overwritten.
static inline bool txSlotStillHolds(u32 cumulative, u32 tailAfter,
                                    u32 ringSize) {
    if (ringSize == 0) return false;
    if (tailAfter == 0) return false;         // nothing was ever submitted
    const u32 ringMask = ringSize - 1;
    const u32 slot = cumulative & ringMask;
    const u32 lastWritten = tailAfter - 1;
    const u32 back = (u32)((lastWritten - slot) & ringMask);
    const u32 newest = lastWritten - back;
    return newest == cumulative;
}

// ROUND 8: the coverage verdict for the TX path, with the reasons separated.
//
// Round 7's txWindowCovered() returned a single bool, and its only failure
// mode was "delta == 0" or "delta >= ringSize". It could not express "the
// window submitted more descriptors than the ring holds, so the oldest ones
// are gone" as distinct from "nothing was submitted", and it said nothing at
// all about generations.
enum TxCoverageReason {
    TXCOV_OK = 0,
    TXCOV_NO_RING,
    TXCOV_NO_POINTERS,        // tail or close pointer not readable
    TXCOV_NOTHING_SUBMITTED,  // delta 0: coverage of an empty window
    TXCOV_RING_OVERWRITTEN,   // delta >= ringSize: oldest descriptors gone
    TXCOV_CLO_AHEAD_OF_TAIL,  // impossible: close past submit
    TXCOV_IMPLAUSIBLE         // delta not representable in the mask
};

static inline const char *txCoverageReasonName(u32 r) {
    switch (r) {
        case TXCOV_OK:                return "ok";
        case TXCOV_NO_RING:           return "no-ring";
        case TXCOV_NO_POINTERS:       return "pointers-unreadable";
        case TXCOV_NOTHING_SUBMITTED: return "nothing-submitted";
        case TXCOV_RING_OVERWRITTEN:  return "ring-overwritten";
        case TXCOV_CLO_AHEAD_OF_TAIL: return "close-ahead-of-submit";
        default:                      return "implausible";
    }
}

struct TxWindowCoverage {
    u32  reason;
    u32  submits;      // descriptors submitted in the window
    u32  completes;    // descriptors the device handed back
    u32  genBefore;    // generation at the window start
    u32  genAfter;     // generation at the window end
    // ROUND 9: how many descriptors were ALREADY in flight when the window
    // opened. Without it, `completes > submits` looks like an error, but it is
    // the normal outcome whenever the window inherits a busy queue: the device
    // hands back older descriptors during the window and never submits them.
    u32  inFlightAtStart;
    u32  preWindowCompleted;  // completions attributable to those older ones
    bool covered;      // the ring still holds every window descriptor
};

static inline TxWindowCoverage txWindowCoverageOf(u32 tailBefore,
                                                  u32 tailAfter,
                                                  u32 cloBefore,
                                                  u32 cloAfter,
                                                  u32 ringSize, u32 mask,
                                                  bool havePointers) {
    TxWindowCoverage c;
    c.reason = TXCOV_NO_RING;
    c.submits = 0;
    c.completes = 0;
    c.genBefore = 0;
    c.genAfter = 0;
    c.inFlightAtStart = 0;
    c.preWindowCompleted = 0;
    c.covered = false;
    if (ringSize == 0) return c;
    if (!havePointers || mask == 0) {
        c.reason = TXCOV_NO_POINTERS;
        return c;
    }

    c.genBefore = txGeneration(tailBefore, ringSize);
    c.genAfter = txGeneration(tailAfter, ringSize);

    // ROUND 9: 31-bit wrap is handled by the counter mask, never by plain
    // 32-bit subtraction. txWindowSubmits/txWindowCompletes mask with
    // MaxTxDescPtrMask; the extra guard below is that the resulting distance
    // must be representable at all, otherwise the pair is a reset.
    const u32 sub = txWindowSubmits(tailBefore, tailAfter, mask);
    const u32 com = txWindowCompletes(cloBefore, cloAfter, mask);
    if (!cloPtrDeltaPlausible(sub, mask) ||
        !cloPtrDeltaPlausible(com, mask)) {
        c.reason = TXCOV_IMPLAUSIBLE;
        return c;
    }
    c.submits = sub;
    c.completes = com;

    // How many descriptors the device still owned when the window opened.
    // A close pointer ahead of the submit pointer is a torn or reset pair, and
    // the window is then not interpretable at all.
    const u32 behind = (u32)((tailBefore - cloBefore) & mask);
    if (!cloPtrDeltaPlausible(behind, mask)) {
        c.reason = TXCOV_CLO_AHEAD_OF_TAIL;
        return c;
    }
    c.inFlightAtStart = behind;

    // Completions during the window are drawn from two populations: those
    // already in flight at the start, and those submitted inside it. The older
    // population is served first, so:
    //     preWindowCompleted = min(completes, inFlightAtStart)
    //     window completions = completes - preWindowCompleted
    c.preWindowCompleted = (com < behind) ? com : behind;

    if (sub == 0) {
        // An empty window is a valid observation, but it covers nothing: there
        // is no descriptor whose lifecycle we can report. Round 7 returned
        // false here too, but for the wrong reason ("nothing to cover"), and
        // it reported it through the same path as a genuine coverage failure.
        c.reason = TXCOV_NOTHING_SUBMITTED;
        return c;
    }
    if (sub >= ringSize) {
        // Every slot was rewritten at least once. The oldest descriptor of the
        // window has been overwritten, so the end-of-window ring does NOT hold
        // every window descriptor.
        c.reason = TXCOV_RING_OVERWRITTEN;
        return c;
    }
    // ROUND 9: the device cannot hand back more descriptors than were ever
    // submitted. The bound is (window submits + those already in flight), not
    // just the window submits. Round 8 compared `com > sub` and therefore
    // flagged the perfectly legal "busy queue at window start" case as an
    // error, while accepting a close pointer that had run past the submit
    // pointer at the window's end.
    if (com > sub + behind) {
        c.reason = TXCOV_CLO_AHEAD_OF_TAIL;
        return c;
    }
    // A descriptor cannot be handed back before it is submitted, so the close
    // pointer must not be ahead of the submit pointer at the window's end
    // either.
    const u32 endBehind = (u32)((tailAfter - cloAfter) & mask);
    if (!cloPtrDeltaPlausible(endBehind, mask)) {
        c.reason = TXCOV_CLO_AHEAD_OF_TAIL;
        return c;
    }
    c.reason = TXCOV_OK;
    c.covered = true;
    return c;
}

// Compatibility wrapper. Kept because tests and older call sites use it.
// (The definition lives in the coverage section above; a second one here
// would be a redefinition.)

// ---- ROUND 8: per-descriptor window scan --------------------------------
//
// WHAT THIS FIXES
// ---------------
// Round 7's collector read the whole ring and marked every non-zero address
// "in-flight" as soon as a close pointer was readable, and it never called
// txSlotLifecycle() at all. On the round-7 capture tail = clo = 0x6a, i.e.
// the queue was completely drained, yet every historical TX address was still
// reported in-flight. That is the exact confusion this function removes:
// "the descriptor bytes are still in the ring" is not "the device owns it".
//
// The scan is driven by the two cumulative pointers at the window edges, so
// it visits exactly the descriptors submitted in the window, in submit order,
// each with its own generation and its own completion state:
//
//   for c in [tailBefore, tailAfter):
//       slot = c & (ringSize-1)
//       gen  = c / ringSize
//       if the slot no longer holds c -> the descriptor was overwritten
//       else decode addr/len from that slot, classify against cloAfter
//
// The result is a per-descriptor record, not a bag of addresses. A positive
// close-pointer delta can then be attributed to specific slots, generations,
// addresses and lengths instead of being a bare count.
//
// CONCURRENCY AND LIMITS -- stated, not hidden
// --------------------------------------------
//  * The ring is read while the device may still be writing to it. Each
//    descriptor is read once, and the whole scan happens after the window
//    ends, so a descriptor written DURING the scan is outside
//    [tailBefore, tailAfter) and is not visited. A descriptor inside the
//    range cannot change: the driver only rewrites a slot when it submits a
//    new descriptor, which advances the tail past it.
//  * The driver does not clear a completed descriptor's address, so the
//    bytes of a completed window descriptor survive until the slot is reused.
//    That is what makes the end-of-window scan meaningful, and it is exactly
//    the condition `submits < ringSize` in txWindowCoverageOf().
//  * If the window submitted at least ringSize descriptors, the oldest are
//    gone. Those are counted as `overwritten`, never silently dropped.
//  * A descriptor whose length field is an MSS (TSO) is recorded with
//    RANGE_LEN_UNKNOWN and a page-sized bound. The bound is NOT used to prove
//    anything exact.

struct TxWindowDesc {
    u32  cumulative;   // free-running submit index
    u32  slot;         // ring slot
    u32  generation;   // cumulative / ringSize
    u64  addr;
    u32  len;
    u32  flags;        // RANGE_*
    u32  lifecycle;    // LIFE_INFLIGHT / LIFE_COMPLETED / LIFE_UNKNOWN
    bool completedInWindow;
};

// ROUND 9: why a window scan stopped, or that it covered the whole window.
//
// Round 8's scan had no stop condition and no cap: it walked `submits`
// iterations, and `submits` is a 31-bit difference. A bogus pointer pair -- a
// counter reset, a different device, a torn read -- therefore became a loop of
// up to 2^31 iterations inside the kernel. The cap and the explicit reasons
// exist so a bad pointer pair produces a recorded refusal instead of a hang.
enum TxScanStop {
    TXSCAN_OK = 0,
    TXSCAN_NO_RING,
    TXSCAN_NO_POINTERS,     // tail or close pointer not readable
    TXSCAN_IMPLAUSIBLE,     // close pointer past submit + already-in-flight
    TXSCAN_RESET,           // delta at or above half the mask: counter reset
    TXSCAN_CAP              // window larger than TX_MAX_WINDOW_SCAN
};

static inline const char *txScanStopName(u32 r) {
    switch (r) {
        case TXSCAN_OK:           return "ok";
        case TXSCAN_NO_RING:      return "no-ring";
        case TXSCAN_NO_POINTERS:  return "pointers-unreadable";
        case TXSCAN_IMPLAUSIBLE:  return "implausible-pointer-pair";
        case TXSCAN_RESET:        return "counter-reset-or-identity-change";
        default:                  return "scan-cap";
    }
}

// Upper bound on how many descriptors one window scan will examine.
//
// 4 x the ring size. Anything larger cannot be attributed per descriptor
// anyway (the ring only holds `ringSize` of them), and the point of the cap is
// that no pointer pair can turn into an unbounded kernel loop. Indices beyond
// the cap are counted arithmetically in `historicalSkipped`, never by looping.
static const u32 TX_MAX_WINDOW_SCAN = 4096;

struct TxWindowScan {
    u32  visited;        // descriptors actually examined
    u32  decoded;        // records filled in
    u32  overwritten;    // slots already reused: descriptor no longer present
    u32  addrZero;       // decoded but address zero
    u32  tsoSlots;
    u32  lenUnknown;
    u32  inflight;
    u32  completed;
    u32  completedInWindow;
    // ROUND 9: the scan's own completeness, so that "we stopped" and "there
    // was nothing there" are different outcomes.
    u32  stopReason;         // TxScanStop
    u32  historicalSkipped;  // indices NOT examined, counted arithmetically
    u32  preWindowCompleted; // completions in the window of older descriptors
    u64  firstAddr;
    u64  firstCompletedAddr;
    u32  firstCompletedSlot;
    u32  firstCompletedGen;
    u32  firstCompletedLen;
    TxWindowCoverage coverage;
};

// Whether the scan is good enough to carry a per-descriptor claim.
//
// ROUND 9: round 8 published the counters but let coverage depend only on the
// pointer arithmetic, so a scan that stopped early, dropped records, or could
// not decode a length still produced `tx-window-covered = yes`. Every one of
// those has to withdraw eligibility, not just be visible next to it.
struct TxWindowQuality {
    u32  submits;
    u32  visited;
    u32  decoded;
    u32  overwritten;
    u32  addrZero;
    u32  lenUnknown;
    u32  recordsLost;    // present and decodable, but the caller could not keep it
    u32  stopReason;
    bool exact;          // every submitted index examined and decoded
};

static inline TxWindowQuality txWindowQualityOf(const TxWindowScan &s,
                                                u32 recordsLost) {
    TxWindowQuality q;
    q.submits = s.coverage.submits;
    q.visited = s.visited;
    q.decoded = s.decoded;
    q.overwritten = s.overwritten;
    q.addrZero = s.addrZero;
    q.lenUnknown = s.lenUnknown;
    q.recordsLost = recordsLost;
    q.stopReason = s.stopReason;
    q.exact = (s.stopReason == TXSCAN_OK &&
               s.historicalSkipped == 0 &&
               s.overwritten == 0 &&
               s.addrZero == 0 &&
               s.lenUnknown == 0 &&
               recordsLost == 0 &&
               s.visited == s.coverage.submits &&
               s.decoded + s.overwritten == s.visited);
    return q;
}

static inline const char *txWindowQualityName(const TxWindowQuality &q) {
    if (q.exact) return "exact";
    if (q.stopReason != TXSCAN_OK) return txScanStopName(q.stopReason);
    if (q.overwritten) return "slots-overwritten";
    if (q.addrZero) return "undecodable-address";
    if (q.lenUnknown) return "undecodable-length";
    if (q.recordsLost) return "records-lost";
    return "incomplete";
}

// Scan the descriptors submitted during [tailBefore, tailAfter).
//
// `onDesc` is invoked for every descriptor actually present in the ring, in
// submit order. It is taken by value so a temporary lambda binds; an earlier
// by-reference form rejected every call site that passed one inline.
//
// ROUND 9: the scan is BOUNDED and it STOPS ON A BAD POINTER PAIR.
//
// Round 8 looped `submits` times, and `submits` is a 31-bit masked
// difference. A counter reset, a device swap, or a torn read therefore became
// a loop of up to 2^31 iterations inside the kernel -- an unbounded scan
// triggered by exactly the condition that means "these numbers cannot be
// trusted". Three things changed:
//
//   1. An implausible pair (or a close pointer past the submit pointer) stops
//      the scan before the loop, with the reason recorded.
//   2. The loop is capped at TX_MAX_WINDOW_SCAN. Indices beyond the cap are
//      counted arithmetically in `historicalSkipped`; they are never iterated.
//   3. Every stop makes the scan non-exact, so coverage eligibility is
//      withdrawn rather than merely reported alongside.
template <typename Fn>
static inline TxWindowScan scanTxWindow(const u8 *ring, u32 ringSize,
                                        u32 tailBefore, u32 tailAfter,
                                        u32 cloBefore, u32 cloAfter,
                                        u32 mask, bool havePointers,
                                        Fn onDesc) {
    TxWindowScan s;
    s.visited = 0; s.decoded = 0; s.overwritten = 0; s.addrZero = 0;
    s.tsoSlots = 0; s.lenUnknown = 0;
    s.inflight = 0; s.completed = 0; s.completedInWindow = 0;
    s.stopReason = TXSCAN_OK;
    s.historicalSkipped = 0;
    s.preWindowCompleted = 0;
    s.firstAddr = 0; s.firstCompletedAddr = 0;
    s.firstCompletedSlot = 0; s.firstCompletedGen = 0;
    s.firstCompletedLen = 0;
    s.coverage = txWindowCoverageOf(tailBefore, tailAfter, cloBefore,
                                    cloAfter, ringSize, mask, havePointers);
    s.preWindowCompleted = s.coverage.preWindowCompleted;

    if (!ring || ringSize == 0) {
        s.stopReason = TXSCAN_NO_RING;
        return s;
    }
    if (!havePointers || mask == 0) {
        s.stopReason = TXSCAN_NO_POINTERS;
        return s;
    }
    // The pointer pair itself decides whether there is anything to scan.
    // These are the same conditions txWindowCoverageOf() rejects, mapped onto
    // the scan's own reason so the two never disagree.
    switch (s.coverage.reason) {
        case TXCOV_IMPLAUSIBLE:
            s.stopReason = TXSCAN_RESET;
            return s;
        case TXCOV_CLO_AHEAD_OF_TAIL:
            s.stopReason = TXSCAN_IMPLAUSIBLE;
            return s;
        default:
            break;
    }

    const u32 sub = txWindowSubmits(tailBefore, tailAfter, mask);
    // Visit every submitted cumulative index. For the indices whose slot has
    // since been reused, txSlotStillHolds() reports false and the descriptor
    // is counted as overwritten -- it must NOT be silently skipped, because
    // "we could not examine it" is different from "it was not there".
    //
    // An earlier draft capped the walk at ringSize, which made `overwritten`
    // undercount (3 reported where 2 slots were reused) and made `decoded`
    // depend on the cap rather than on the ring's contents. The cap below is
    // NOT that: it bounds an unbounded input, and what it skips is counted.
    const u32 limit = (sub < TX_MAX_WINDOW_SCAN) ? sub : TX_MAX_WINDOW_SCAN;
    if (limit < sub) {
        s.stopReason = TXSCAN_CAP;
        s.historicalSkipped = sub - limit;
    }

    for (u32 k = 0; k < limit; k++) {
        const u32 c = (u32)((tailBefore + k) & mask);
        s.visited++;

        if (!txSlotStillHolds(c, tailAfter, ringSize)) {
            s.overwritten++;
            continue;
        }

        const u32 slot = c & (ringSize - 1);
        const u8 *d = ring + (u64)slot * TX_DESC_STRIDE;
        const u64 addr = rd64(d + 8);
        const u32 opts1 = rd32(d);
        const bool tso = (opts1 &
                          (TX_DESC_LARGESEND | TX_DESC_GSO4 | TX_DESC_GSO6))
                         != 0;

        u32 len = opts1 & TX_DESC_LENMASK;
        u32 flags = 0;
        if (tso) {
            // The 16-bit field is the MSS, not the length. We cannot recover
            // the real length from the descriptor alone, so it is marked
            // unknown and bounded by one page. Round 7 substituted 4096 and
            // then let that guess take part in coverage arithmetic.
            flags |= RANGE_LEN_UNKNOWN | RANGE_FROM_TSO;
            s.tsoSlots++;
            if (len == 0) len = 0x1000;
        } else if (len == 0) {
            flags |= RANGE_LEN_UNKNOWN;
            // A zero length cannot be recorded: insert() drops it and counts
            // it as zero-length, which would silently lose the descriptor.
            // Bound it by one page like the TSO case, and keep the flag so
            // the bound can never take part in an exact-coverage argument.
            len = 0x1000;
        }
        if (flags & RANGE_LEN_UNKNOWN) s.lenUnknown++;

        // Lifecycle is decided against the END-of-window close pointer: the
        // question is "has the device handed this descriptor back by now".
        // Compare CUMULATIVE indices, not slot numbers.
        const bool doneAtEnd = txCumCompleted(c, cloAfter, mask);
        const bool doneAtStart = txCumCompleted(c, cloBefore, mask);
        const u32 life = doneAtEnd ? LIFE_COMPLETED : LIFE_INFLIGHT;
        // Completed *during* the window means: it was not yet handed back at
        // the start, and it is handed back at the end.
        const bool doneInWindow = !doneAtStart && doneAtEnd;

        if (life == LIFE_COMPLETED) s.completed++;
        else                          s.inflight++;
        if (doneInWindow) {
            s.completedInWindow++;
            if (s.firstCompletedAddr == 0 && addr != 0) {
                s.firstCompletedAddr = addr;
                s.firstCompletedSlot = slot;
                s.firstCompletedGen = txGeneration(c, ringSize);
                s.firstCompletedLen = len;
            }
        }
        if (addr == 0) s.addrZero++;
        else if (s.firstAddr == 0) s.firstAddr = addr;

        TxWindowDesc t;
        t.cumulative = c;
        t.slot = slot;
        t.generation = txGeneration(c, ringSize);
        t.addr = addr;
        t.len = len;
        t.flags = flags;
        t.lifecycle = life;
        t.completedInWindow = doneInWindow;
        onDesc(t);
        s.decoded++;
    }
    return s;
}

// Overload for callers that do not want a callback.
static inline TxWindowScan scanTxWindow(const u8 *ring, u32 ringSize,
                                        u32 tailBefore, u32 tailAfter,
                                        u32 cloBefore, u32 cloAfter,
                                        u32 mask, bool havePointers) {
    struct Noop {
        void operator()(const TxWindowDesc &) const {}
    } noop;
    return scanTxWindow(ring, ringSize, tailBefore, tailAfter, cloBefore,
                        cloAfter, mask, havePointers, noop);
}

// ---- TX completion via the hardware close pointer ------------------------
//
// WHICH REGISTER, AND WHY "FIRST NON-ZERO CANDIDATE" IS NOT AN IDENTITY
// ---------------------------------------------------------------------
// Round 6 probed three registers and took the first that read back non-zero
// and below 1024. That is a guess dressed as a measurement: a stale or
// unrelated register that happens to hold a small number wins the election.
//
// The register is a deterministic function of the chip's configuration
// method, which the driver derives from one readable register:
//
//   rtl812xIdentifyChip()   rtl812xx.cpp / RTL812xLucyHardware.cpp:167
//     val32   = RTL_R32(tp, TxConfig)          // TxConfig = 0x40
//     reg     = val32 & 0x7c800000
//     ICVerID = val32 & 0x00700000
//     case 0x6C800000: ICVerID 0x000000 -> CFG_METHOD_41
//                      ICVerID 0x100000 -> CFG_METHOD_42
//
//   rtl812xx.cpp:17494-17507  HwSuppTxNoCloseVer
//     CFG_METHOD_2..7              -> 3
//     CFG_METHOD_31                -> 4
//     CFG_METHOD_32,33             -> 5
//     CFG_METHOD_8..13, 41, 42     -> 6
//
//   rtl812xx.cpp:17511-17525  MaxTxDescPtrMask
//     HwSuppTxNoCloseVer 5, 6      -> MAX_TX_NO_CLOSE_DESC_PTR_MASK_V4
//                                     = 0x7FFFFFFF
//     4                            -> 0xFFFFFFFF
//     3                            -> 0xFFFF
//
//   rtl812xx.cpp:17214-17232  rtl8125_setup_mqs_reg()
//     case 6 -> HW_CLO_PTR0_8125BP = 0x0D34, SW_TAIL_PTR0_8125BP = 0x0D30
//     case 4,5 -> HW_CLO_PTR0_8126 = 0x2800
//     default  -> HW_CLO_PTR0_8125 = 0x2802  (16-bit, HwSuppTxNoCloseVer 3)
//
//   RTL812xLucyHardware.cpp:1178  rtl812xGetHwCloPtr()
//     HwSuppTxNoCloseVer == 3 -> RTL_R16, otherwise RTL_R32
//
// So: read TxConfig once, derive the method, and the register / width / mask
// all follow. No probing, no election.
static const u32 REG_TX_CONFIG = 0x40;

// The chip's configuration method, as the driver computes it.
struct ChipId {
    u32 txConfigRaw;
    u32 cfgMethod;      // 0 = CFG_METHOD_DEFAULT (unknown part)
    u32 noCloseVer;     // HwSuppTxNoCloseVer
    bool known;
};

static inline ChipId identifyChip(u32 txConfigRaw) {
    ChipId c;
    c.txConfigRaw = txConfigRaw;
    c.cfgMethod = 0;
    c.noCloseVer = 0;
    c.known = false;

    const u32 reg = txConfigRaw & 0x7c800000u;
    const u32 icver = txConfigRaw & 0x00700000u;

    switch (reg) {
        case 0x60800000u:
            c.cfgMethod = (icver == 0x00000000u) ? 2u : 3u;
            break;
        case 0x64000000u:
            c.cfgMethod = (icver == 0x00000000u) ? 4u : 5u;
            break;
        case 0x68000000u:
            c.cfgMethod = (icver == 0x00000000u) ? 8u : 9u;
            break;
        case 0x68800000u:
            c.cfgMethod = (icver == 0x00000000u) ? 10u : 11u;
            break;
        case 0x70800000u:
            c.cfgMethod = 12u;
            break;
        case 0x6C800000u:
            c.cfgMethod = (icver == 0x00000000u) ? 41u : 42u;
            break;
        case 0x64800000u:
            if (icver == 0x00000000u)      c.cfgMethod = 31u;
            else if (icver == 0x00100000u) c.cfgMethod = 32u;
            else                           c.cfgMethod = 33u;
            break;
        default:
            c.cfgMethod = 0;
            break;
    }
    c.known = (c.cfgMethod != 0);

    switch (c.cfgMethod) {
        case 2: case 3: case 4: case 5: case 6: case 7:
            c.noCloseVer = 3; break;
        case 8: case 9: case 10: case 11: case 12: case 13:
        case 41: case 42:
            c.noCloseVer = 6; break;
        case 31:
            c.noCloseVer = 4; break;
        case 32: case 33:
            c.noCloseVer = 5; break;
        default:
            c.noCloseVer = 0; break;
    }
    return c;
}

// Register / width / count mask implied by a configuration method.
struct CloPtrSpec {
    u32  reg;
    u32  width;      // 2 or 4 bytes
    u32  mask;       // MaxTxDescPtrMask
    u32  tailReg;
    bool valid;
};

static inline CloPtrSpec cloPtrSpecFor(u32 noCloseVer) {
    CloPtrSpec s;
    s.reg = 0;
    s.width = 4;
    s.mask = 0;
    s.tailReg = 0;
    s.valid = false;

    switch (noCloseVer) {
        case 4:
        case 5:
            s.reg = 0x2800;          // HW_CLO_PTR0_8126
            s.tailReg = 0x2800;      // SW_TAIL_PTR0_8126 (same register)
            s.width = 4;
            s.mask = (noCloseVer == 4) ? 0xFFFFFFFFu : 0x7FFFFFFFu;
            s.valid = true;
            break;
        case 6:
            s.reg = 0x0D34;          // HW_CLO_PTR0_8125BP
            s.tailReg = 0x0D30;      // SW_TAIL_PTR0_8125BP
            s.width = 4;
            s.mask = 0x7FFFFFFFu;    // MAX_TX_NO_CLOSE_DESC_PTR_MASK_V4
            s.valid = true;
            break;
        case 3:
            s.reg = 0x2802;          // HW_CLO_PTR0_8125
            s.tailReg = 0x2800;      // SW_TAIL_PTR0_8125
            s.width = 2;
            s.mask = 0xFFFFu;        // MAX_TX_NO_CLOSE_DESC_PTR_MASK_V2
            s.valid = true;
            break;
        default:
            break;
    }
    return s;
}

// Backwards-compatible register constants for the three known parts.
static const u32 REG_CLO_PTR_V6  = 0x0D34;   // CFG_METHOD_41/42 (this card)
static const u32 REG_TAIL_PTR_V6 = 0x0D30;
static const u32 REG_CLO_PTR_V45 = 0x2800;   // CFG_METHOD_31..33
static const u32 REG_CLO_PTR_V3  = 0x2802;   // CFG_METHOD_2..7

// ---- close-pointer arithmetic -------------------------------------------
//
// THE ROUND-6 BUG: the probe computed the delta as a modulo-1024 ring
// advance. The hardware counter is cumulative over 31 bits, so:
//
//     1000 -> 2024   round-6 answer: 0     correct answer: 1024
//     1020 -> 4      round-6 answer: 8     correct answer: 8  (coincidence)
//
// A wrong delta is worse than no delta: 0 reads as "the device did nothing",
// which is exactly the conclusion that must never be inferred from a
// misinterpreted counter.
//
// Validity rules, all of which must hold for the delta to be used:
//   * the register identity was derived from the chip, not guessed
//   * both samples were read at the same width
//   * the forward distance is representable within the mask
//   * the two samples belong to the same device instance (no reset)

// Forward distance between two cumulative samples, in descriptor units.
// `mask` is MaxTxDescPtrMask, NOT ringSize - 1.
static inline u32 cloPtrDelta(u32 before, u32 after, u32 mask) {
    if (mask == 0) return 0;
    return (u32)((after - before) & mask);
}

// Is a delta consistent with "the device made progress and nothing else
// happened"? A distance at or above half the mask is indistinguishable from
// the counter having been reset or the device replaced, so it is refused.
static inline bool cloPtrDeltaPlausible(u32 delta, u32 mask) {
    if (mask == 0) return false;
    return delta < ((mask >> 1) + 1u);
}

// A close-pointer sample is only meaningful if it fits the register width.
//
// A width other than 2 or 4 means the register identity was never
// established, so no sample can be trusted -- there is nothing to compare it
// against. That case must return false rather than silently accepting the
// value, which is how a "0" ends up being read as "no progress".
static inline bool cloPtrSampleValid(u32 value, u32 width, u32 mask) {
    if (width != 2 && width != 4) return false;
    if (width == 2 && value > 0xFFFFu) return false;
    if (mask != 0 && (value & ~mask) != 0) {
        // Bits outside the mask are set. On a 31-bit counter that means the
        // top bit is meaningful in some other way, so the sample is suspect.
        return false;
    }
    return true;
}

// A ring index derived from a cumulative counter.
static inline u32 cloPtrRingIndex(u32 cumulative, u32 ringSize) {
    if (ringSize == 0) return 0;
    return cumulative & (ringSize - 1);
}

// ---- ring register decode ------------------------------------------------

static const u32 REG_TX_DESC_LOW    = 0x20;
static const u32 REG_TX_DESC_HIGH   = 0x24;
static const u32 REG_COUNTER_LOW    = 0x10;
static const u32 REG_COUNTER_HIGH   = 0x14;
static const u32 REG_RX_DESC_LOW    = 0xE4;
static const u32 REG_RX_DESC_HIGH   = 0xE8;

// A 64-bit register pair is only usable if the result is non-zero. The driver
// writes the full 64-bit address, so a zero low half with a non-zero high
// half is a torn read, not a valid base.
static inline bool combine64(u32 lo, u32 hi, u64 *out) {
    if (out) *out = ((u64)hi << 32) | (u64)lo;
    return (lo != 0 || hi != 0);
}

// Sanity gate before mapping a physical range read-only. Mapping a bogus PA
// would be a kernel panic, so every candidate has to pass this first.
//
// NOTE: this is a MAPPING gate. It must never be used to decide whether an
// address is recorded -- that was round 6's defect 1.
static inline bool plausibleRingBase(u64 base, u64 bytes, u64 mapLimit,
                                     const char **why) {
    if (base == 0) {
        if (why) *why = "ring base is zero (register not programmed)";
        return false;
    }
    if ((base & 0x3FULL) != 0) {
        if (why) *why = "ring base is not 64-byte aligned";
        return false;
    }
    if (base + bytes < base) {
        if (why) *why = "ring range wraps";
        return false;
    }
    if (base + bytes > mapLimit) {
        if (why) *why = "ring range extends beyond the identity map";
        return false;
    }
    return true;
}

// ---- ROUND 8: the basis for reading ring memory --------------------------
//
// WHAT WAS WRONG WITH readVerdictDeviceReported()
// -----------------------------------------------
// Round 7 introduced it to stop the strict layout requirement from making the
// rings unreadable, and that part was right. But its justification was too
// thin: "the register says the device is using this address, therefore it is
// safe to read". A device register proves the device was PROGRAMMED with an
// address. It does not prove:
//
//   * that the address is backed by the memory object the driver allocated;
//   * that the object is still alive (the driver could have freed it);
//   * that our CPU mapping of that PA reaches the same bytes.
//
// Reading the wrong PA is a kernel panic, so the round-7 argument was one
// step short. Round 8 keeps the address recorded either way and adds a
// positive self-check that must pass before the contents are trusted.
//
// WHAT CAN ACTUALLY BE PROVEN FROM INSIDE THE KEXT
// ------------------------------------------------
// The probe cannot see the driver's IOBufferMemoryDescriptor, so "this is
// that exact object" is not directly provable here. What IS provable, and is
// far stronger than "a register said so", is that the memory we mapped is
// self-consistently the ring the driver built:
//
//   * the RX ring's LAST descriptor must carry RingEnd -- the driver writes
//     `rxDescArray[kRxLastDesc].cmd.opts1 = RingEnd` at setup and nowhere
//     else, so this bit at this index is a structural fingerprint;
//   * every decoded TX address must be non-zero and every length must fit the
//     16-bit field (or carry a TSO command bit);
//   * at least one descriptor must be decodable at all.
//
// A random page of RAM will not satisfy the RingEnd-at-last-slot condition.
// That is a real check with a real failure mode, which is what the round-7
// version lacked.
//
// The probe also reports WHICH of these held, so a future round with access to
// the driver's objects can replace the fingerprint with the stronger proof
// without changing the interface.
enum RingBasis {
    RB_NONE = 0,
    RB_REGISTER_ONLY,      // only "the register names it": NOT enough to read
    RB_REGISTER_AND_MAP,   // mapped, but the contents are not recognisable
    RB_FINGERPRINT         // mapped and the contents match the driver's ring
};

static inline const char *ringBasisName(u32 b) {
    switch (b) {
        case RB_FINGERPRINT:        return "register+content-fingerprint";
        case RB_REGISTER_AND_MAP:   return "register+mapped-content-unverified";
        case RB_REGISTER_ONLY:      return "register-only";
        default:                    return "none";
    }
}

// Structural fingerprint of a TX descriptor ring.
//
// Returns true when the contents look like the ring the driver built. This is
// a positive test: it can fail (and then we do not trust the contents), and
// it cannot be satisfied by an arbitrary page in most cases.
struct TxRingFingerprint {
    u32  decoded;       // slots with a non-zero address
    u32  badLen;        // length field out of range and no TSO bit
    u32  ringEnd;       // slots carrying RingEnd (driver sets it on the last)
    u32  ringEndAtLast; // RingEnd present exactly at index count-1
    bool ok;
};

static inline TxRingFingerprint txRingFingerprint(const u8 *ring,
                                                  u32 count) {
    TxRingFingerprint f;
    f.decoded = 0; f.badLen = 0; f.ringEnd = 0; f.ringEndAtLast = 0;
    f.ok = false;
    if (!ring || count == 0) return f;

    for (u32 i = 0; i < count; i++) {
        const u8 *d = ring + (u64)i * TX_DESC_STRIDE;
        const u32 opts1 = rd32(d);
        const u64 addr = rd64(d + 8);
        const bool tso = (opts1 &
                          (TX_DESC_LARGESEND | TX_DESC_GSO4 | TX_DESC_GSO6))
                         != 0;
        if (opts1 & TX_DESC_RINGEND) {
            f.ringEnd++;
            if (i == count - 1) f.ringEndAtLast = 1;
        }
        if (addr != 0) f.decoded++;
        if (!tso && (opts1 & TX_DESC_LENMASK) == 0 && addr != 0) f.badLen++;
    }
    // A ring the driver has used has at least one programmed descriptor. The
    // RingEnd bit sits on the last slot for RX unconditionally; for TX it is
    // set when the submit pointer passes the last slot, so it is evidence
    // when present but not required for a fresh ring.
    f.ok = (f.decoded > 0) && (f.badLen == 0);
    return f;
}

// Structural fingerprint of an RX descriptor ring.
//
// The driver writes RingEnd into the LAST descriptor at setup and never
// clears it, so its presence at that exact index is the strongest available
// statement that this PA is the RX ring.
struct RxRingFingerprint {
    u32  decoded;       // slots with a non-zero address
    u32  ringEndAtLast; // RingEnd present at index count-1
    u32  ownSet;        // descriptors still owned by the device
    bool ok;
};

static inline RxRingFingerprint rxRingFingerprint(const u8 *ring,
                                                  u32 count) {
    RxRingFingerprint f;
    f.decoded = 0; f.ringEndAtLast = 0; f.ownSet = 0;
    f.ok = false;
    if (!ring || count == 0) return f;

    for (u32 i = 0; i < count; i++) {
        const u8 *d = ring + (u64)i * RX_DESC_STRIDE;
        const u32 blen = rd32(d);
        const u64 addr = rd64(d + 8);
        if (addr != 0) f.decoded++;
        if (blen & RX_DESC_OWN) f.ownSet++;
        if (i == count - 1 && (blen & RX_DESC_RINGEND)) f.ringEndAtLast = 1;
    }
    f.ok = (f.decoded > 0) && (f.ringEndAtLast != 0);
    return f;
}

// ---- ROUND 10: decoding the driver's own observation log (wire v2) --------
//
// WHY THIS REPLACES THE RING SCAN AS THE PRIMARY BASIS
// ---------------------------------------------------
// The window scan above is still useful: it is the only way to see the ring
// without driver cooperation, and it is what the round-8 evidence rests on.
// But it cannot answer "is this the same generation of bytes" or "what was the
// real length of a TSO segment", because both facts are destroyed by the time
// a reader looks at the ring.
//
// The driver records them at the source. This section decodes those records.
// The format is defined in tools/lucy-obs/RTL812xObsLog.hpp, which is the file
// the driver compiles; the constants below must match it, and obsHeaderOk()
// checks magic/version/record size/capacity so a mismatch is a refusal rather
// than a misparse.
//
// WHAT ROUND 9 GOT WRONG, AND WHAT CHANGED
// ----------------------------------------
//   * v1 published head/first/published/wrapped/t-published as five separate
//     OSString properties plus the records as a sixth OSData. The six are not
//     atomic as a group, so a reader could pair a header from publication N
//     with records from N-1. v2 puts ONE header and the records in a single
//     OSData: there is nothing left to tear.
//   * v1's `seq` was written only at the end, so a reader that arrived
//     mid-write saw the PREVIOUS writer's seq before and after its body read
//     and concluded the body was consistent. v2 marks the slot busy first and
//     uses ticket*2|busy, so an in-flight body is detectable.
//   * v1 had no device identity, no epoch and no publication id. v2 has all
//     three, so a snapshot from another device, another driver load, or an
//     older publication can be refused instead of silently used.
//   * v1 had no business identifier, so a driver record could not be joined to
//     a client request. v2 carries (token, reqId, flowHash, pktFlags) on TX
//     submit, doorbell and RX records.
//
// Every field is host endian: the driver and this reader are the same kernel
// on the same machine.
static const u32 OBS_MAGIC = 0x324F4C52u;   // 'RLO2'
static const u32 OBS_VERSION = 2u;
static const u32 OBS_REC_BYTES = 72u;       // 2 x u64 + 14 x u32
// sizeof(RtlObsHdr): 20 x u32 (80) + 3 x u64 (24) = 104, 8-byte aligned.
// The driver publishes this number too; a mismatch is a refusal, not a
// misparse, so the two files cannot drift apart silently.
static const u32 OBS_HDR_BYTES = 104u;
static const u32 OBS_CAPACITY = 4096u;
static const u32 OBS_PUBLISH_MAX = 512u;

enum {
    OBS_KIND_NONE = 0,
    OBS_KIND_TX_SUBMIT = 1,
    OBS_KIND_TX_DONE = 2,
    OBS_KIND_RX_DONE = 3,
    OBS_KIND_TX_DOORBELL = 4
};

static inline const char *obsKindName(u32 k) {
    switch (k) {
        case OBS_KIND_TX_SUBMIT:   return "tx-submit";
        case OBS_KIND_TX_DONE:     return "tx-done";
        case OBS_KIND_RX_DONE:     return "rx-done";
        case OBS_KIND_TX_DOORBELL: return "tx-doorbell";
        default:                   return "none";
    }
}

enum {
    OBS_FLAG_LEN_UNKNOWN = 1u << 0,
    OBS_FLAG_TSO = 1u << 1,
    OBS_FLAG_FIRST_FRAG = 1u << 2,
    OBS_FLAG_LAST_FRAG = 1u << 3,
    OBS_FLAG_RING_END = 1u << 4,
    OBS_FLAG_DESC_OWN = 1u << 5,
    OBS_FLAG_RX_ERROR = 1u << 6
};

enum {
    OBS_PKT_PARSED = 1u << 0,
    OBS_PKT_NO_MAGIC = 1u << 1,
    OBS_PKT_NOT_IPV4 = 1u << 2,
    OBS_PKT_VLAN = 1u << 3,
    OBS_PKT_FRAGMENTED = 1u << 4,
    OBS_PKT_IP_OPTIONS = 1u << 5,
    OBS_PKT_NOT_UDP = 1u << 6,
    OBS_PKT_SHORT = 1u << 7,
    OBS_PKT_TRUNCATED = 1u << 8,
    OBS_PKT_NOT_TX = 1u << 9,
    OBS_PKT_TCP = 1u << 10
};

enum {
    OBS_HDR_OVERFLOWED = 1u << 0,
    OBS_HDR_LOST = 1u << 1,
    OBS_HDR_TRUNCATED = 1u << 2
};

// One decoded record. Field order mirrors RtlObsRec.
struct ObsRec {
    u64  tMono;
    u64  addr;
    u32  seq;
    u32  kind;
    u32  cumulative;
    u32  slot;
    u32  gen;
    u32  batch;
    u32  opts1;
    u32  opts2;
    u32  len;
    u32  flags;
    u32  token;
    u32  reqId;
    u32  flowHash;
    u32  pktFlags;
    bool valid;      // this record's ticket matched and its seq was even
};

static inline u32 obsRd32(const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) |
           ((u32)p[3] << 24);
}

static inline u64 obsRd64(const u8 *p) {
    return (u64)obsRd32(p) | ((u64)obsRd32(p + 4) << 32);
}

// Header of the published snapshot.
//
// This is decoded from the SAME buffer as the records, which is the whole
// point: there is no window in which the header can describe one publication
// and the records another.
struct ObsHeader {
    u32  magic;
    u32  version;
    u32  recSize;
    u32  capacity;
    u32  head;
    u32  wrapped;
    u32  dropped;
    u32  pubId;
    u32  firstTicket;
    u32  lastTicket;
    u32  validCount;
    u32  lostCount;
    u32  epoch;
    u32  busDevFn;
    u32  vendorId;
    u32  deviceId;
    u32  ifUnit;
    u32  macHi;
    u32  macLo;
    u32  flags;
    u64  tStart;
    u64  tPublished;
    u32  recordCount;    // derived: (bytes - hdrBytes) / recSize
    bool ok;
    const char *why;
};

static inline ObsHeader obsHeaderOk(const u8 *blob, u64 bytes) {
    ObsHeader h;
    h.magic = 0; h.version = 0; h.recSize = 0; h.capacity = 0;
    h.head = 0; h.wrapped = 0; h.dropped = 0; h.pubId = 0;
    h.firstTicket = 0; h.lastTicket = 0; h.validCount = 0; h.lostCount = 0;
    h.epoch = 0; h.busDevFn = 0; h.vendorId = 0; h.deviceId = 0;
    h.ifUnit = 0; h.macHi = 0; h.macLo = 0; h.flags = 0;
    h.tStart = 0; h.tPublished = 0; h.recordCount = 0;
    h.ok = false;
    h.why = "not published";
    if (!blob) return h;
    if (bytes < (u64)OBS_HDR_BYTES) { h.why = "shorter than a header"; return h; }

    h.magic       = obsRd32(blob + 0);
    h.version     = obsRd32(blob + 4);
    h.recSize     = obsRd32(blob + 8);
    h.capacity    = obsRd32(blob + 12);
    h.head        = obsRd32(blob + 16);
    h.wrapped     = obsRd32(blob + 20);
    h.dropped     = obsRd32(blob + 24);
    h.pubId       = obsRd32(blob + 28);
    h.firstTicket = obsRd32(blob + 32);
    h.lastTicket  = obsRd32(blob + 36);
    h.validCount  = obsRd32(blob + 40);
    h.lostCount   = obsRd32(blob + 44);
    h.epoch       = obsRd32(blob + 48);
    h.busDevFn    = obsRd32(blob + 52);
    h.vendorId    = obsRd32(blob + 56);
    h.deviceId    = obsRd32(blob + 60);
    h.ifUnit      = obsRd32(blob + 64);
    h.macHi       = obsRd32(blob + 68);
    h.macLo       = obsRd32(blob + 72);
    h.flags       = obsRd32(blob + 76);
    h.tStart      = obsRd64(blob + 80);
    h.tPublished  = obsRd64(blob + 88);
    // 96..103 is `reserved` in the driver's struct; not decoded here.

    if (h.magic != OBS_MAGIC)   { h.why = "bad magic"; return h; }
    if (h.version != OBS_VERSION) { h.why = "unknown version"; return h; }
    if (h.recSize != OBS_REC_BYTES) { h.why = "record size mismatch"; return h; }
    if (h.capacity != OBS_CAPACITY) { h.why = "capacity mismatch"; return h; }

    const u64 body = bytes - (u64)OBS_HDR_BYTES;
    if ((body % (u64)h.recSize) != 0) { h.why = "ragged record body"; return h; }
    const u64 n = body / (u64)h.recSize;
    if (n > (u64)OBS_PUBLISH_MAX) { h.why = "more records than a publish holds"; return h; }
    if (n > (u64)h.capacity) { h.why = "more records than the ring holds"; return h; }
    h.recordCount = (u32)n;

    if (h.validCount > h.recordCount) { h.why = "valid count exceeds records"; return h; }
    if (h.lostCount > h.recordCount)  { h.why = "lost count exceeds records"; return h; }
    if (h.validCount + h.lostCount != h.recordCount) {
        h.why = "valid + lost does not equal the record count";
        return h;
    }
    if (h.recordCount > 0) {
        if (h.firstTicket == 0) {
            h.why = "ticket zero is not a published record";
            return h;
        }
        if (h.lastTicket < h.firstTicket) { h.why = "ticket range inverted"; return h; }
        if ((h.lastTicket - h.firstTicket + 1u) != h.recordCount) {
            h.why = "ticket range does not span the record count";
            return h;
        }
        // `head` counts tickets ISSUED, and tickets start at 1, so the most
        // recently issued ticket is exactly `head`. The invariant is therefore
        // lastTicket <= head, NOT lastTicket < head.
        if (h.head < h.lastTicket) {
            h.why = "head is behind the last ticket";
            return h;
        }
    }
    if (h.tPublished < h.tStart) { h.why = "published before the log existed"; return h; }
    if (h.pubId == 0) { h.why = "publication id is zero"; return h; }

    h.ok = true;
    h.why = "ok";
    return h;
}

// The device identity a reader demands. Filled from the probe's own view of
// the PCI function it is driving the experiment against; a snapshot that does
// not match is refused rather than attributed to the wrong device.
struct ObsIdentity {
    u32  busDevFn;
    u32  vendorId;
    u32  deviceId;
    u32  ifUnit;
    u32  macHi;
    u32  macLo;
    u32  epoch;        // 0 = do not check
    bool have;         // false = identity checks are N/A, not PASS
};

// Returns true when the snapshot's identity matches what the reader demands.
// `why` is set to a stable token on refusal so the analyser can assert on the
// REASON rather than just on a non-zero exit.
static inline bool obsIdentityMatches(const ObsHeader &h,
                                      const ObsIdentity &want,
                                      const char **why) {
    if (why) *why = "ok";
    if (!want.have) { if (why) *why = "identity-not-declared"; return false; }
    if (h.busDevFn != want.busDevFn) { if (why) *why = "bdf-mismatch"; return false; }
    if (h.vendorId != want.vendorId) { if (why) *why = "vendor-mismatch"; return false; }
    if (h.deviceId != want.deviceId) { if (why) *why = "device-mismatch"; return false; }
    if (h.ifUnit != want.ifUnit)     { if (why) *why = "interface-unit-mismatch"; return false; }
    if (h.macHi != want.macHi || h.macLo != want.macLo) {
        if (why) *why = "mac-mismatch"; return false;
    }
    if (want.epoch != 0 && h.epoch != want.epoch) {
        if (why) *why = "epoch-mismatch"; return false;
    }
    return true;
}

// Read one record out of the published snapshot.
//
// The snapshot is a COPY, so the seqlock's live-tear check has already been
// done by the driver at publish time (obsPublish() re-validates each record's
// seq against its ticket after copying). What this function checks is the
// remaining invariant: the record's own seq must be EVEN and must equal
// ticket*2, i.e. it must be a complete, published record of the ticket the
// snapshot claims for that position. Anything else is a hole and is reported
// as invalid rather than used.
static inline ObsRec obsReadRecAt(const u8 *blob, const ObsHeader &h,
                                  u32 index) {
    ObsRec r;
    r.tMono = 0; r.addr = 0; r.seq = 0; r.kind = 0;
    r.cumulative = 0; r.slot = 0; r.gen = 0; r.batch = 0;
    r.opts1 = 0; r.opts2 = 0; r.len = 0; r.flags = 0;
    r.token = 0; r.reqId = 0; r.flowHash = 0; r.pktFlags = 0;
    r.valid = false;
    if (!blob || !h.ok || index >= h.recordCount) return r;

    const u8 *rec = blob + (u64)OBS_HDR_BYTES + (u64)index * (u64)h.recSize;
    const u32 seq = obsRd32(rec + 16);
    if (seq == 0) return r;                 // explicit hole
    if ((seq & 1u) != 0) return r;          // still marked busy: refuse
    const u32 ticket = h.firstTicket + index;
    if ((seq >> 1) != ticket) return r;     // belongs to a different ticket

    r.tMono      = obsRd64(rec + 0);
    r.addr       = obsRd64(rec + 8);
    r.seq        = seq;
    r.kind       = obsRd32(rec + 20);
    r.cumulative = obsRd32(rec + 24);
    r.slot       = obsRd32(rec + 28);
    r.gen        = obsRd32(rec + 32);
    r.batch      = obsRd32(rec + 36);
    r.opts1      = obsRd32(rec + 40);
    r.opts2      = obsRd32(rec + 44);
    r.len        = obsRd32(rec + 48);
    r.flags      = obsRd32(rec + 52);
    r.token      = obsRd32(rec + 56);
    r.reqId      = obsRd32(rec + 60);
    r.flowHash   = obsRd32(rec + 64);
    r.pktFlags   = obsRd32(rec + 68);
    r.valid = true;
    return r;
}

// ---- joining submit records to completion records ------------------------
//
// This is the correspondence the task asks for, and it is exact: the driver
// writes the SAME cumulative index in the submit record and in the completion
// record, because both come from its own counters (txTailPtr0 and txClosePtr0)
// which are the numbers the hardware reports back. No inference about slot
// reuse is involved -- the join key is not the slot.
struct ObsTxOp {
    u32  cumulative;
    u32  slot;
    u32  gen;
    u64  submitAddr;
    u32  submitLen;
    u32  submitFlags;
    u64  tSubmit;
    u64  tDoorbell;    // 0 when the doorbell record was not seen
    bool haveSubmit;
    bool haveDone;
    u64  tDone;
    u32  token;        // business id carried by the submit record
    u32  reqId;
    u32  flowHash;
    u32  pktFlags;
};

static const u32 OBS_MAX_OPS = 64;
// A single controlled request is one small datagram, so it fits in one or two
// segments. Eight is generous and keeps the per-op record bounded.
static const u32 OBS_MAX_SEGS = 8;
static const u32 OBS_MAX_BIZ_OPS = 24;

// ---- what the caller DECLARES about this round's controlled batch --------
//
// ROUND 11. The batch predicate is only meaningful if it is bound to things
// that were fixed BEFORE the evidence was read. Round 10 passed the expected
// request count and nothing else, which left three holes:
//
//   * no run token  -> records from two different runs could be folded into
//     one "complete" batch (counterexample C);
//   * no window     -> a request whose whole TX/done/RX sequence happened
//     AFTER the window could still be counted, as long as some unrelated
//     pair existed inside the window (counterexample B);
//   * no per-segment completion tracking -> two completions for one segment
//     plus none for another satisfied `segDone == segCount`
//     (counterexample A).
//
// So the declaration now travels as a struct, and every field of it is
// something an operator can pin down before the run.
struct ObsBatchSpec {
    u32  expectedBatch;   // declared request count; 0 = undeclared
    u32  runToken;        // declared run token; 0 = derive from the records
    u64  winStart;
    u64  winEnd;
    // When false the window-binding checks are N/A rather than PASS. A caller
    // that has no window is asking a weaker question and must not be able to
    // reach controlledBatchComplete on the strength of it.
    bool requireWindow;

    // ---- ROUND 12: refuse to infer the run token -------------------------
    //
    // Round 11 fell back to "the single token seen in the records" when the
    // caller declared none. That is circular: the token being checked is read
    // out of the very records the check is about, so "these records belong to
    // this run" becomes true by construction.
    //
    // Production sets this. A caller that genuinely has no declaration (a
    // diagnostic reader) can leave it false and will get `tokenResolved` with
    // `inferredToken` set, which the analyser treats as NOT evidence.
    bool strictToken;
    // True when the join token was inferred rather than declared.
    bool inferredToken;
};

// ---- ROUND 12: the success predicate, in ONE place ------------------------
//
// WHY THIS EXISTS
// ---------------
// Round 11 computed seven evidence properties and PUBLISHED them as diagnostic
// attributes, but the probe's own `PASS-CANDIDATE` verdict did not consume four
// of them:
//
//   * `m2-b2-bizwalk-*` (count / ok / fail) were never read by the verdict, so
//     a run whose page-table walk failed every business range could still be
//     stamped PASS-CANDIDATE;
//   * an unknown device identity fell through the `if (want.have && !idOk)`
//     guard and was treated as "nothing to check" rather than a refusal;
//   * a token of 0 was silently replaced by one inferred from the very records
//     being judged, which makes "this run's token" circular;
//   * `bizWalkFail` was incremented on the early-return paths and then
//     OVERWRITTEN by a function-local counter at the end.
//
// Publishing a property is not the same as using it. The fix is structural: the
// conjunction lives here, the production path calls it, and the host test calls
// the SAME function with one counterexample per term. A test that re-implements
// the predicate would prove nothing about the kext.
//
// `why` is a stable token so the analyser and the negative tests can assert on
// the REASON, not merely on a non-zero exit.
struct ObsEvidence {
    // ---- declared before the evidence was read ----
    bool identityKnown;        // the probe has its own view of the device
    u32  declaredToken;        // 0 = not declared -> no run identity
    u32  expectedBatch;        // 0 = no declared request set

    // ---- the snapshot the verdict was computed from ----
    bool snapshotExported;     // the exact bytes were published
    bool snapshotHashStable;   // hash before == hash after the decode
    bool snapshotFresh;        // tPublished >= winEnd

    // ---- loss and truncation ----
    u32  writerDropped;        // writers that could not publish a record
    u32  publishLost;          // holes the publisher found in this snapshot
    u32  readerHoles;          // records the reader refused
    u32  hdrFlags;             // OBS_HDR_* from the snapshot header
    u32  bizCapped;            // business ops beyond OBS_MAX_BIZ_OPS

    // ---- the three join verdicts, each independently computed ----
    bool hasCompletePair;
    bool recordsCoverWindow;
    bool controlledBatchComplete;
    bool tokenResolvedOnDeclared;  // the join used the DECLARED token

    // ---- page-table evidence for every business range ----
    u32  bizWalkExpected;      // ranges the declared records imply
    u32  bizWalkCount;         // ranges actually walked
    u32  bizWalkOk;            // ranges fully covered with the right perms
    u32  bizWalkFail;
    u32  bizWalkCapped;        // ranges/leaves we could not afford to export

    // ---- ROUND 14: the RX posted-buffer SET ----
    //
    // The terms above answer "are the eight business ranges mapped". These
    // answer "is EVERY RX buffer the device could write during the window
    // mapped", which is a different and strictly stronger question: it is about
    // ~1024 buffers plus everything re-posted during the window, not eight
    // samples.
    //
    // Each field is a separate reason token, because "the RX set is not
    // covered" has six distinct causes and collapsing them would make the
    // refusal unactionable.
    bool rxSetPresent;         // the probe decoded an rtl812x-rxpost blob
    bool rxSetComplete;        // the union had no gap, loss or rebuild
    u32  rxSetRanges;          // distinct (addr, capacity) ranges in the union
    u32  rxSetWalked;          // ranges handed to the page-table walk
    u32  rxSetOk;              // ranges fully covered with write permission
    u32  rxSetFail;
    u32  rxSetCapped;          // ranges the export budget could not carry
    bool rxSetGenStable;       // no ring rebuild between the two reads
    bool rxSetNoGap;           // the rearm ring still held the watermark
    bool rxSetNoLoss;          // no dropped / displaced rearm record

    // ---- run preconditions ----
    bool windowRan;
    bool windowValid;
    bool eventLogOk;
    bool commandsOk;
    bool restoreOk;
};

// Returns nullptr when every term holds, otherwise a stable reason token.
//
// The ORDER matters: a reason that invalidates everything else is reported
// first, so a capture with several problems is not labelled with the vaguest.
static inline const char *obsEvidenceGate(const ObsEvidence &e) {
    // Preconditions first: without them there is no experiment to judge.
    if (!e.restoreOk)     return "restore-incomplete";
    if (!e.commandsOk)    return "command-did-not-complete";
    if (!e.eventLogOk)    return "event-log-not-running";
    if (!e.windowRan)     return "window-not-executed";
    if (!e.windowValid)   return "window-invalid";

    // Identity. ROUND 12: an UNKNOWN identity is a refusal, not an exemption.
    // Round 11 wrote `if (want.have && !idOk)`, so `have == false` skipped the
    // check entirely and the run could still be a success candidate.
    if (!e.identityKnown) return "identity-unknown";

    // Run identity. A token inferred from the records being judged is circular.
    if (e.declaredToken == 0) return "token-not-declared";
    if (!e.tokenResolvedOnDeclared) return "token-not-resolved-on-declaration";
    if (e.expectedBatch == 0) return "batch-not-declared";

    // The snapshot the verdict used must be exportable and re-checkable.
    if (!e.snapshotExported)   return "snapshot-not-exported";
    if (!e.snapshotHashStable) return "snapshot-unstable";
    if (!e.snapshotFresh)      return "snapshot-published-before-window-end";

    // Loss. ROUND 12: both production and analyser refuse non-zero loss
    // instead of ignoring it. Round 11 read `dropped` and never used it.
    if (e.writerDropped != 0) return "records-dropped-by-writer";
    if (e.publishLost != 0)   return "records-lost-at-publish";
    if (e.readerHoles != 0)   return "records-unreadable";
    if ((e.hdrFlags & OBS_HDR_OVERFLOWED) != 0) return "ring-overflowed";
    if ((e.hdrFlags & OBS_HDR_LOST) != 0)       return "snapshot-flagged-lost";
    if (e.bizCapped != 0)     return "business-ops-capped";

    // The three join verdicts.
    if (!e.hasCompletePair)         return "no-verifiable-pair";
    if (!e.recordsCoverWindow)      return "records-do-not-cover-window";
    if (!e.controlledBatchComplete) return "controlled-batch-incomplete";

    // Page-table evidence for EVERY business range. ROUND 12: this was the
    // term the round-11 verdict never looked at.
    if (e.bizWalkExpected == 0) return "no-business-ranges-declared";
    if (e.bizWalkCapped != 0)   return "page-table-budget-exceeded";
    if (e.bizWalkCount != e.bizWalkExpected) return "page-table-ranges-missing";
    if (e.bizWalkFail != 0)     return "page-table-evidence-failed";
    if (e.bizWalkOk != e.bizWalkExpected) return "page-table-ranges-unproven";

    // ROUND 14: the RX posted-buffer set.
    //
    // WHY THIS IS THE LAST TERM AND NOT THE FIRST
    // -------------------------------------------
    // A failure here is the most interesting result the experiment can produce,
    // so it would be tempting to report it first. But every term above is a
    // precondition for this one being MEANINGFUL: if the window was invalid or
    // the commands did not complete, the RX set describes a ring that was never
    // put into translation, and reporting "RX ranges unmapped" would be a false
    // alarm about the page tables. Ordering the checks this way keeps each
    // reason token true.
    if (!e.rxSetPresent)  return "rx-set-not-read";
    if (!e.rxSetGenStable) return "rx-ring-rebuilt-during-window";
    if (!e.rxSetNoGap)    return "rx-rearm-log-lapped-baseline";
    if (!e.rxSetNoLoss)   return "rx-rearm-records-lost";
    if (!e.rxSetComplete) return "rx-set-incomplete";
    if (e.rxSetRanges == 0) return "rx-set-empty";
    if (e.rxSetCapped != 0) return "rx-set-budget-exceeded";
    if (e.rxSetWalked != e.rxSetRanges) return "rx-set-ranges-missing";
    if (e.rxSetFail != 0)   return "rx-set-not-covered";
    if (e.rxSetOk != e.rxSetRanges) return "rx-set-ranges-unproven";

    return nullptr;
}

// Local string compare. The header must not assume <string.h> has already been
// included by whoever includes it: the host test includes this header FIRST and
// only then <cstring>, so a call to strcmp here would fail to compile there
// while compiling fine inside the kext. Same code in both places or the test
// proves nothing.
static inline bool obsStrEq(const char *a, const char *b) {
    if (!a || !b) return false;
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

// Human-readable expansion of a gate token, for the property the probe
// publishes next to its verdict. Kept next to the gate so the two cannot drift.
static inline const char *obsEvidenceGateText(const char *why) {
    if (!why) return "all evidence conditions hold";
    if (obsStrEq(why, "restore-incomplete")) return "registers not restored";
    if (obsStrEq(why, "command-did-not-complete")) return "an invalidation command did not complete";
    if (obsStrEq(why, "event-log-not-running")) return "the event log was not running";
    if (obsStrEq(why, "window-not-executed")) return "the measurement window never ran";
    if (obsStrEq(why, "window-invalid")) return "the measurement window is invalid";
    if (obsStrEq(why, "identity-unknown")) return "the target device identity is not known";
    if (obsStrEq(why, "token-not-declared")) return "this run's token was not declared";
    if (obsStrEq(why, "token-not-resolved-on-declaration")) return "the records were not joined on the declared token";
    if (obsStrEq(why, "batch-not-declared")) return "the request set was not declared";
    if (obsStrEq(why, "snapshot-not-exported")) return "the snapshot used was not exported";
    if (obsStrEq(why, "snapshot-unstable")) return "the snapshot changed while it was decoded";
    if (obsStrEq(why, "snapshot-published-before-window-end")) return "the snapshot was published before the window ended";
    if (obsStrEq(why, "records-dropped-by-writer")) return "writers dropped records";
    if (obsStrEq(why, "records-lost-at-publish")) return "the publisher found holes";
    if (obsStrEq(why, "records-unreadable")) return "the reader refused records";
    if (obsStrEq(why, "ring-overflowed")) return "the ring overflowed past the window";
    if (obsStrEq(why, "snapshot-flagged-lost")) return "the snapshot is flagged as lossy";
    if (obsStrEq(why, "business-ops-capped")) return "business operations exceeded the cap";
    if (obsStrEq(why, "no-verifiable-pair")) return "no submit/complete pair is verifiable";
    if (obsStrEq(why, "records-do-not-cover-window")) return "the records do not cover the window";
    if (obsStrEq(why, "controlled-batch-incomplete")) return "the controlled batch did not complete";
    if (obsStrEq(why, "no-business-ranges-declared")) return "no business DMA range was declared";
    if (obsStrEq(why, "page-table-budget-exceeded")) return "the page-table export budget was exceeded";
    if (obsStrEq(why, "page-table-ranges-missing")) return "not every business range was walked";
    if (obsStrEq(why, "page-table-evidence-failed")) return "a business range has no legal page-table path";
    if (obsStrEq(why, "page-table-ranges-unproven")) return "a business range is not fully covered";
    if (obsStrEq(why, "rx-set-not-read")) return "the RX posted-buffer tables were not read";
    if (obsStrEq(why, "rx-ring-rebuilt-during-window")) return "the RX ring was rebuilt during the window";
    if (obsStrEq(why, "rx-rearm-log-lapped-baseline")) return "the RX rearm log lapped past the baseline";
    if (obsStrEq(why, "rx-rearm-records-lost")) return "RX rearm records were dropped or displaced";
    if (obsStrEq(why, "rx-set-incomplete")) return "the RX posted-buffer set is incomplete";
    if (obsStrEq(why, "rx-set-empty")) return "the RX posted-buffer set is empty";
    if (obsStrEq(why, "rx-set-budget-exceeded")) return "the RX set exceeded the export budget";
    if (obsStrEq(why, "rx-set-ranges-missing")) return "not every RX range was walked";
    if (obsStrEq(why, "rx-set-not-covered")) return "an RX buffer the device can write is not mapped";
    if (obsStrEq(why, "rx-set-ranges-unproven")) return "an RX range is not fully covered";
    return "unrecognised reason";
}

static inline ObsBatchSpec obsBatchSpecOf(u32 expectedBatch, u32 runToken,
                                          u64 winStart, u64 winEnd) {
    ObsBatchSpec s;
    s.expectedBatch = expectedBatch;
    s.runToken = runToken;
    s.winStart = winStart;
    s.winEnd = winEnd;
    s.requireWindow = (winStart != 0 && winEnd > winStart);
    s.strictToken = false;
    s.inferredToken = false;
    return s;
}

// Production spelling: the run token MUST have been declared. Used by the
// probe's own read path so "inferred from the records" can never be mistaken
// for "declared before the records were read".
static inline ObsBatchSpec obsBatchSpecStrict(u32 expectedBatch, u32 runToken,
                                              u64 winStart, u64 winEnd) {
    ObsBatchSpec s = obsBatchSpecOf(expectedBatch, runToken, winStart, winEnd);
    s.strictToken = true;
    return s;
}

// One business operation: every TX segment that carried it, the doorbell that
// released them, the completions that returned them, and the RX record of the
// echo. This is the unit the task's "unique request <-> TX/RX DMA records"
// question is answered in.
struct ObsBizOp {
    u32  token;
    u32  reqId;
    u32  flowHash;
    u32  segCount;       // TX submit records with this (token, reqId)
    u32  segCapped;      // segments beyond OBS_MAX_SEGS (truncation, not loss)
    u32  segCum[OBS_MAX_SEGS];
    u64  segAddr[OBS_MAX_SEGS];
    u32  segLen[OBS_MAX_SEGS];
    u64  segTSubmit[OBS_MAX_SEGS];
    u32  segFlags[OBS_MAX_SEGS];

    // ---- ROUND 11: per-segment completion, not a counter -----------------
    //
    // `segDone` used to be a bare counter incremented once per matching
    // completion record. Two completions for segment 96 and none for 97 made
    // it 2, which equalled segCount 2 and satisfied `allSegDone`. That is
    // counterexample A, and it is a false pass: segment 97's DMA range was
    // never proven to have completed.
    //
    // Now each segment gets its own count. Exactly one completion per segment
    // is required; anything else is counted and blocks the claim.
    u32  segDoneCount[OBS_MAX_SEGS];  // completions matched to each segment
    u32  segDone;        // segments with AT LEAST one completion
    u32  segDupDone;     // completions beyond the first for a segment
    u32  segMissingDone; // segments with no completion at all
    u32  segDupCum;      // segments sharing a cumulative index (slot reuse)
    u32  segBadGen;      // cumulative/slot/gen inconsistent with the ring
    bool segDoneBeforeSubmit;  // a completion earlier than its own submit
    bool segAddrZero;          // a submitted segment carries no address
    bool segLenUnknown;        // TSO / kObsFlagLenUnknown on any segment

    // ---- ROUND 11: fragment structure -----------------------------------
    //
    // A packet's first descriptor carries FIRST_FRAG and its last carries
    // LAST_FRAG. Requiring exactly one of each is how a MISSING middle or
    // trailing segment becomes visible: if the last descriptor was dropped
    // from the log, lastFragCount is 0 and the op cannot be called complete
    // even though every segment we DID see has a completion.
    u32  firstFragCount;
    u32  lastFragCount;
    bool fragStructureOk;   // exactly one FIRST and one LAST, no truncation

    // ---- ROUND 11: window binding ---------------------------------------
    //
    // Every stage of the exchange -- each TX submit, each completion, the
    // doorbell and the RX record -- must fall inside the declared window.
    // Counterexample B is a run where the window contains only unrelated
    // traffic and the real exchange happens after the window closes.
    bool submitInWindow;
    bool doneInWindow;
    bool rxinWindow;
    bool allStagesInWindow;
    // True when a stage that IS present falls outside the window. This is
    // deliberately separate from `allStagesInWindow`: a request that simply
    // never completed is "incomplete", while a request whose completion was
    // recorded after the window closed is "outside the window". Conflating
    // the two would label every unfinished request as a window violation.
    bool stageOutsideWindow;

    u64  tSubmitFirst;
    u64  tSubmitLast;
    u64  tDoorbell;
    u64  tDoneFirst;
    u64  tDoneLast;
    bool haveSubmit;
    bool haveDoorbell;
    bool haveDone;       // at least one completion
    bool allSegDone;     // every segment completed exactly once
    bool haveRx;
    u32  rxCum;
    u64  rxAddr;
    u32  rxLen;
    u64  tRx;
    // Every segment's DMA range is known from its own record: real length,
    // real address, no TSO reinterpretation. Without this the "range" in
    // "DMA range" would be a guess.
    bool dmaRangeKnown;
};

// Why a snapshot does or does not cover the measurement window.
enum {
    OBS_COVER_NONE = 0,       // no usable snapshot
    OBS_COVER_TOO_LATE = 1,   // snapshot published before the window ended
    OBS_COVER_TOO_EARLY = 2,  // snapshot does not reach back to the window start
    OBS_COVER_HOLES = 3,      // records inside the window are missing
    OBS_COVER_OVERFLOW = 4,   // the ring wrapped past records in the window
    OBS_COVER_EPOCH = 5,      // snapshot is from another driver instance
    OBS_COVER_IDENTITY = 6,   // snapshot is from another device
    OBS_COVER_FULL = 7        // all of the above hold
};

static inline const char *obsCoverName(u32 c) {
    switch (c) {
        case OBS_COVER_TOO_LATE:   return "published-before-window-end";
        case OBS_COVER_TOO_EARLY:  return "does-not-reach-window-start";
        case OBS_COVER_HOLES:      return "records-missing-inside-window";
        case OBS_COVER_OVERFLOW:   return "ring-overflowed-past-window";
        case OBS_COVER_EPOCH:      return "driver-epoch-mismatch";
        case OBS_COVER_IDENTITY:   return "device-identity-mismatch";
        case OBS_COVER_FULL:       return "full";
        default:                   return "none";
    }
}

struct ObsJoin {
    // ---- whole-snapshot counters ----
    u32  records;         // records present in the snapshot
    u32  holes;           // records the reader refused
    u32  submits;
    u32  dones;
    u32  doorbells;
    u32  rxDone;
    u32  rxAddrZero;
    u32  rxParsed;        // RX records that carried a business id
    u32  txParsed;        // TX submit records that carried a business id
    u32  staleRecords;    // == holes, kept for the older property names
    u32  unmatchedDone;   // completion with no submit anywhere in the snapshot
    u32  uncompletedSubmit;  // submit with no completion anywhere in the snapshot
    u32  overflow;        // ops beyond OBS_MAX_OPS
    u64  firstSubmitT;
    u64  lastDoneT;
    u64  firstRxAddr;
    u64  lastRxAddr;
    u32  rxLenSum;

    // ---- window subset ----
    //
    // The published log covers several seconds, of which the measurement
    // window is only the middle three. These count only the operations whose
    // submit AND completion both fall inside [winStart, winEnd].
    u32  winSubmits;
    u32  winDones;
    u32  winPaired;          // both ends inside the window
    u32  winOrphanDone;      // completion inside the window, submit NOWHERE
    u32  winPreWindowInFlight; // completion inside, submit BEFORE the window
    u32  winUncompleted;     // submitted inside, still in flight at window end

    // ---- the three separate verdicts the task requires ----
    //
    // These are deliberately independent. "One pair succeeded" must not be
    // able to stand in for "the records cover the window", and neither of
    // those may stand in for "the controlled batch finished".
    bool hasCompletePair;      // >= 1 verifiable submit/complete pair
    bool recordsCoverWindow;   // raw records completely cover [winStart,winEnd]
    bool controlledBatchComplete;  // every expected request of this batch done
    u32  coverState;           // OBS_COVER_*
    const char *coverWhy;

    // The first window-internal pair, which is the one a report quotes.
    bool haveWinOp;
    ObsTxOp winOp;

    // ---- business correlation ----
    ObsBizOp biz[OBS_MAX_BIZ_OPS];
    u32  bizCount;
    u32  bizCapped;        // operations beyond OBS_MAX_BIZ_OPS
    u32  expectedBatch;    // declared expected request count (0 = undeclared)
    u32  declaredToken;    // declared run token (0 = not declared)
    u32  batchComplete;    // requests of this batch with TX+done+RX
    u32  batchPartial;     // requests with some but not all of the three
    u32  batchMissing;     // declared requests with no record at all
    u32  batchUnexpected;  // records for requests outside the declared range
    u32  batchUnparsed;    // TX/RX records that carried no business id

    // ---- ROUND 11: why the batch claim is blocked, counted separately ----
    //
    // Each of these is a distinct way the evidence can fail to support
    // "the declared batch completed". Keeping them as counters (rather than
    // folding them into one boolean) is what lets the analyser say WHICH
    // property failed instead of just "not complete".
    u32  batchForeignToken;   // records carrying a different run token
    u32  batchOutsideWindow;  // a request whose stages are not all in-window
    u32  batchDupDone;        // duplicate completions for one segment
    u32  batchBadFrag;        // fragment structure not exactly one/one
    u32  batchDmaUnknown;     // a segment whose DMA range is not known
    u32  batchOrder;          // completion recorded before its own submit
    const char *batchWhy;

    // The declared token actually used for the join: the declared one when
    // the caller supplied it, otherwise the single token seen in the records.
    // `tokenResolved` says which of the two happened, so an analyser can tell
    // "this batch was pinned to a token" from "this batch inferred one".
    u32  joinToken;
    bool tokenResolved;
    bool tokenAmbiguous;      // records carried more than one token
    // ROUND 12: true when the join token was INFERRED from the records rather
    // than declared before they were read. An inferred token cannot support a
    // batch claim: it makes "these records are this run" true by construction.
    bool inferredToken;

    // ---- per-op array kept for the aggregate counters ----
    ObsTxOp op[OBS_MAX_OPS];
    u32  n;

    // Completions inside the window that match NO submit anywhere in the
    // snapshot. These cannot live in op[] (which is built from submits), so
    // they get their own bounded list; otherwise a genuine orphan would be
    // counted in `unmatchedDone` and then silently dropped from the window
    // subset -- which is exactly what happened before this list existed.
    u64  orphanDoneT[OBS_MAX_OPS];
    u32  orphanDoneCount;
};

// Fold the published snapshot into a submit/complete correspondence and the
// three verdicts.
//
// ROUND 10: this fills `j` IN PLACE rather than returning by value. ObsJoin is
// large; returning it puts a temporary of that size on the caller's stack,
// which pushed m2b2ReadDriverObs() past the 4 KiB frame threshold and made
// clang emit a WEAK ____chkstk_darwin reference -- which kmutil refuses with
// "Has weak references but does not test for them."
//
// ROUND 11: the batch declaration is an ObsBatchSpec, not a bare count. See
// the struct's comment for the three false passes a count alone allowed.
static inline void obsJoinInto(ObsJoin &j, const u8 *blob, u64 bytes,
                               u32 ringSize, const ObsBatchSpec &spec) {
    j.records = 0; j.holes = 0;
    j.submits = 0; j.dones = 0; j.doorbells = 0;
    j.rxDone = 0; j.rxAddrZero = 0; j.rxParsed = 0; j.txParsed = 0;
    j.staleRecords = 0; j.unmatchedDone = 0; j.uncompletedSubmit = 0;
    j.overflow = 0;
    j.firstSubmitT = 0; j.lastDoneT = 0;
    j.firstRxAddr = 0; j.lastRxAddr = 0; j.rxLenSum = 0;
    j.winSubmits = 0; j.winDones = 0; j.winPaired = 0;
    j.winOrphanDone = 0; j.winPreWindowInFlight = 0; j.winUncompleted = 0;
    j.hasCompletePair = false;
    j.recordsCoverWindow = false;
    j.controlledBatchComplete = false;
    j.coverState = OBS_COVER_NONE;
    j.coverWhy = "no-snapshot";
    j.haveWinOp = false;
    j.n = 0;
    j.orphanDoneCount = 0;
    j.bizCount = 0; j.bizCapped = 0;
    j.expectedBatch = spec.expectedBatch;
    j.declaredToken = spec.runToken;
    j.batchComplete = 0; j.batchPartial = 0;
    j.batchMissing = 0; j.batchUnexpected = 0; j.batchUnparsed = 0;
    j.batchForeignToken = 0; j.batchOutsideWindow = 0;
    j.batchDupDone = 0; j.batchBadFrag = 0; j.batchDmaUnknown = 0;
    j.batchOrder = 0;
    j.batchWhy = "no-snapshot";
    j.joinToken = 0;
    j.tokenResolved = false;
    j.tokenAmbiguous = false;
    j.inferredToken = false;
    j.winOp.cumulative = 0; j.winOp.slot = 0; j.winOp.gen = 0;
    j.winOp.submitAddr = 0; j.winOp.submitLen = 0; j.winOp.submitFlags = 0;
    j.winOp.tSubmit = 0; j.winOp.tDoorbell = 0;
    j.winOp.haveSubmit = false; j.winOp.haveDone = false; j.winOp.tDone = 0;
    j.winOp.token = 0; j.winOp.reqId = 0; j.winOp.flowHash = 0;
    j.winOp.pktFlags = 0;

    const u64 winStart = spec.winStart;
    const u64 winEnd = spec.winEnd;
    const u32 expectedBatch = spec.expectedBatch;

    const ObsHeader h = obsHeaderOk(blob, bytes);
    if (!h.ok) { j.coverWhy = h.why; j.batchWhy = h.why; return; }
    j.records = h.recordCount;
    j.recordsCoverWindow = false;
    j.coverState = OBS_COVER_NONE;

    // Pass 1: submits. `op[]` keeps a WINDOW-PREFERRED subset.
    const bool haveWin = (winStart != 0 && winEnd > winStart);
    for (u32 i = 0; i < h.recordCount; i++) {
        const ObsRec r = obsReadRecAt(blob, h, i);
        if (!r.valid) { j.holes++; j.staleRecords++; continue; }
        if (r.kind == OBS_KIND_TX_SUBMIT) {
            j.submits++;
            // Only count an unparsed record as a BLOCKER when it could have
            // been one of our requests. Ordinary traffic on the same
            // interface -- ARP, TCP ACKs, DHCP, multicast -- carries no
            // business magic and never will, so treating every such packet
            // as "a record without a business id" made
            // controlledBatchComplete unreachable on any live interface.
            //
            // The distinction: a record blocks the batch claim only if it
            // was a UDP datagram that reached the payload and still had no
            // magic (kObsPktNoMagic), or if the parse could not even get far
            // enough to decide (short/truncated). A record that was
            // positively identified as NOT our protocol (TCP, IPv6, VLAN,
            // fragmented, IP options) is traffic we never claimed to track.
            if (r.pktFlags & OBS_PKT_PARSED) {
                j.txParsed++;
            } else if (r.pktFlags & (OBS_PKT_SHORT | OBS_PKT_TRUNCATED)) {
                // A record we could not even inspect far enough to decide.
                // That is a genuine uncertainty and blocks the batch claim.
                j.batchUnparsed++;
            }
            // kObsPktNoMagic is NOT a blocker. On a live interface the great
            // majority of datagrams carry no business magic -- mDNS, SSDP,
            // NBNS, DHCP, the peer's own broadcast discovery -- and none of
            // them were ever claimed as part of this batch. Counting them
            // made controlledBatchComplete unreachable: a run reached
            // batch-complete = 4 with tx-parsed = rx-parsed = 4 and still
            // reported "records-without-a-business-id".
            //
            // The batch claim is scoped to the DECLARED request ids: every
            // declared id must appear with a full TX/RX pair, and nothing
            // outside the declared range may appear. Unrelated traffic is
            // simply not part of the question.
            if (j.firstSubmitT == 0 || r.tMono < j.firstSubmitT)
                j.firstSubmitT = r.tMono;
            // A submit is kept when it could possibly pair with a completion
            // that lands inside the window. That means anything submitted AT
            // OR BEFORE the window end -- including submits from before the
            // window opened, because those are exactly the legitimate
            // pre-window in-flight items the verdict has to tell apart from
            // orphans. Submits AFTER the window end cannot pair with a
            // window-internal completion and are not kept.
            //
            // (Round 9 kept only in-window submits, which made every
            // pre-window in-flight completion look like an orphan.)
            const bool couldPair = (!haveWin || r.tMono <= winEnd);
            if (!couldPair) continue;   // after the window: not kept, not a loss
            if (j.n < OBS_MAX_OPS) {
                ObsTxOp &o = j.op[j.n];
                o.cumulative = r.cumulative;
                o.slot = r.slot;
                o.gen = (ringSize ? r.cumulative / ringSize : r.gen);
                o.submitAddr = r.addr;
                o.submitLen = r.len;
                o.submitFlags = r.flags;
                o.tSubmit = r.tMono;
                o.tDoorbell = 0;
                o.haveSubmit = true;
                o.haveDone = false;
                o.tDone = 0;
                o.token = r.token;
                o.reqId = r.reqId;
                o.flowHash = r.flowHash;
                o.pktFlags = r.pktFlags;
                j.n++;
            } else {
                j.overflow++;
            }
        } else if (r.kind == OBS_KIND_RX_DONE) {
            j.rxDone++;
            if (r.addr == 0) j.rxAddrZero++;
            if (r.pktFlags & OBS_PKT_PARSED) j.rxParsed++;
            if (j.firstRxAddr == 0) j.firstRxAddr = r.addr;
            j.lastRxAddr = r.addr;
            j.rxLenSum += r.len;
        }
    }

    // Pass 2: completions and doorbells.
    for (u32 i = 0; i < h.recordCount; i++) {
        const ObsRec r = obsReadRecAt(blob, h, i);
        if (!r.valid) continue;
        if (r.kind == OBS_KIND_TX_DONE) {
            j.dones++;
            if (r.tMono > j.lastDoneT) j.lastDoneT = r.tMono;
            bool matched = false;
            for (u32 k = 0; k < j.n; k++) {
                if (j.op[k].cumulative == r.cumulative) {
                    j.op[k].haveDone = true;
                    j.op[k].tDone = r.tMono;
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                j.unmatchedDone++;
                if (j.orphanDoneCount < OBS_MAX_OPS) {
                    j.orphanDoneT[j.orphanDoneCount++] = r.tMono;
                }
            }
        } else if (r.kind == OBS_KIND_TX_DOORBELL) {
            j.doorbells++;
            for (u32 k = 0; k < j.n; k++) {
                if (!j.op[k].haveDone && j.op[k].tDoorbell == 0 &&
                    j.op[k].cumulative < r.cumulative) {
                    j.op[k].tDoorbell = r.tMono;
                }
            }
        }
    }

    for (u32 k = 0; k < j.n; k++) {
        if (!j.op[k].haveDone) j.uncompletedSubmit++;
    }

    // ---- verdict 1: has_complete_pair ----
    //
    // At least one operation whose submit AND completion are both visible in
    // this snapshot. That is the weakest of the three claims and it is the
    // only one round 9 actually established.
    for (u32 k = 0; k < j.n; k++) {
        if (j.op[k].haveSubmit && j.op[k].haveDone) {
            j.hasCompletePair = true;
            break;
        }
    }

    // ---- the window subset ----
    if (haveWin) {
        for (u32 k = 0; k < j.n; k++) {
            const ObsTxOp &o = j.op[k];
            const bool subIn = (o.tSubmit >= winStart && o.tSubmit <= winEnd);
            const bool doneIn = (o.haveDone && o.tDone >= winStart &&
                                 o.tDone <= winEnd);
            if (subIn) j.winSubmits++;
            if (doneIn) {
                j.winDones++;
                if (subIn) {
                    j.winPaired++;
                    if (!j.haveWinOp) {
                        j.winOp = o;
                        j.haveWinOp = true;
                    }
                } else {
                    // A completion inside the window whose submit is BEFORE it:
                    // that is a legitimate pre-window in-flight item, and it is
                    // NOT an orphan. Distinguishing these two is the point.
                    j.winPreWindowInFlight++;
                }
            }
            if (subIn && !o.haveDone) j.winUncompleted++;
        }
        // Genuine orphans: completions inside the window with no submit
        // ANYWHERE in the snapshot. Counted from the raw completion records,
        // not inferred from a counter.
        for (u32 k = 0; k < j.orphanDoneCount; k++) {
            if (j.orphanDoneT[k] >= winStart && j.orphanDoneT[k] <= winEnd)
                j.winOrphanDone++;
        }
    }

    // ---- verdict 2: records_cover_window ----
    //
    // This asks a completely different question from verdict 1: do the RAW
    // records cover the whole time range, with nothing missing inside it?
    //
    // Four independent ways to fail, each reported separately:
    //   * the snapshot was taken before the window ended, so the tail of the
    //     window was never in it (round 9 failed exactly here: published at
    //     39963682435 ns, window ended at 40494639566 ns, 0.53 s short);
    //   * the snapshot does not reach back to the window start;
    //   * there are holes inside the window;
    //   * the ring overflowed, so records that WOULD have been inside it were
    //     overwritten before the snapshot was taken.
    if (!haveWin) {
        j.coverState = OBS_COVER_NONE;
        j.coverWhy = "no-window-declared";
    } else if (h.tPublished < winEnd) {
        j.coverState = OBS_COVER_TOO_LATE;
        j.coverWhy = "published-before-window-end";
    } else if ((h.flags & OBS_HDR_OVERFLOWED) != 0) {
        j.coverState = OBS_COVER_OVERFLOW;
        j.coverWhy = "ring-overflowed-past-window";
    } else if (j.holes != 0) {
        j.coverState = OBS_COVER_HOLES;
        j.coverWhy = "records-missing-inside-window";
    } else {
        // The snapshot must reach back to (or before) the window start. The
        // oldest record it holds is the one at firstTicket; if that record is
        // already INSIDE the window, the part of the window before it was
        // never captured.
        u64 oldest = 0;
        for (u32 i = 0; i < h.recordCount; i++) {
            const ObsRec r = obsReadRecAt(blob, h, i);
            if (!r.valid) continue;
            if (oldest == 0 || r.tMono < oldest) oldest = r.tMono;
        }
        if (oldest == 0 || oldest > winStart) {
            j.coverState = OBS_COVER_TOO_EARLY;
            j.coverWhy = "does-not-reach-window-start";
        } else {
            j.coverState = OBS_COVER_FULL;
            j.coverWhy = "full";
            j.recordsCoverWindow = true;
        }
    }

    // ---- verdict 3: controlled_batch_complete ----
    //
    // ROUND 11: this verdict is now BOUND to four things that were fixed
    // before the evidence was read, because a batch claim that is not bound
    // to them is satisfiable by assembling unrelated records:
    //
    //   1. this run's token          -> counterexample C (token A's req1 +
    //                                   token B's req2 counted as a batch of 2)
    //   2. the declared request set  -> requests outside 1..N are counted
    //   3. the declared window       -> counterexample B (unrelated in-window
    //                                   pair + out-of-window real exchange)
    //   4. per-segment completion    -> counterexample A (two duplicate
    //                                   completions for one segment, none for
    //                                   another)
    //
    // Each of those is a separate counter on ObsJoin, so a failure names the
    // property that failed instead of collapsing into one boolean.

    // -- pass 3a: resolve the run token this batch is pinned to -------------
    //
    // The declaration may carry a token. When it does not, the token is
    // inferred ONLY if the records agree on exactly one; two tokens means the
    // snapshot spans more than one run and no batch claim is possible.
    if (spec.runToken != 0) {
        j.joinToken = spec.runToken;
        j.tokenResolved = true;
    } else if (spec.strictToken) {
        // ROUND 12: production declared no token. Refuse rather than infer.
        // Inferring from the records makes "this run's token" circular.
        j.joinToken = 0;
        j.tokenResolved = false;
        j.inferredToken = false;
    } else {
        u32 seenToken = 0;
        for (u32 i = 0; i < h.recordCount; i++) {
            const ObsRec r = obsReadRecAt(blob, h, i);
            if (!r.valid) continue;
            if ((r.pktFlags & OBS_PKT_PARSED) == 0) continue;
            if (r.token == 0) continue;
            if (seenToken == 0) {
                seenToken = r.token;
            } else if (seenToken != r.token) {
                j.tokenAmbiguous = true;
            }
        }
        j.joinToken = seenToken;
        j.tokenResolved = (seenToken != 0);
        j.inferredToken = j.tokenResolved;
    }

    // -- pass 3b: fold every parsed record into a (token, reqId) operation --
    for (u32 i = 0; i < h.recordCount; i++) {
        const ObsRec r = obsReadRecAt(blob, h, i);
        if (!r.valid) continue;
        if ((r.pktFlags & OBS_PKT_PARSED) == 0) continue;
        if (r.kind != OBS_KIND_TX_SUBMIT && r.kind != OBS_KIND_TX_DOORBELL &&
            r.kind != OBS_KIND_RX_DONE) continue;

        // A record from a different run is NOT this batch's business. It is
        // counted, not silently ignored: a snapshot that contains two runs is
        // weaker evidence even if one of them happens to be complete.
        if (j.joinToken != 0 && r.token != j.joinToken) {
            j.batchForeignToken++;
            continue;
        }

        ObsBizOp *b = nullptr;
        for (u32 k = 0; k < j.bizCount; k++) {
            if (j.biz[k].token == r.token && j.biz[k].reqId == r.reqId) {
                b = &j.biz[k];
                break;
            }
        }
        if (!b) {
            if (j.bizCount >= OBS_MAX_BIZ_OPS) { j.bizCapped++; continue; }
            b = &j.biz[j.bizCount++];
            b->token = r.token;
            b->reqId = r.reqId;
            b->flowHash = r.flowHash;
            b->segCount = 0; b->segCapped = 0; b->segDone = 0;
            b->segDupDone = 0; b->segMissingDone = 0;
            b->segDupCum = 0; b->segBadGen = 0;
            b->segDoneBeforeSubmit = false;
            b->segAddrZero = false; b->segLenUnknown = false;
            b->firstFragCount = 0; b->lastFragCount = 0;
            b->fragStructureOk = false;
            b->submitInWindow = false; b->doneInWindow = false;
            b->rxinWindow = false; b->allStagesInWindow = false;
            b->stageOutsideWindow = false;
            b->dmaRangeKnown = false;
            b->tSubmitFirst = 0; b->tSubmitLast = 0; b->tDoorbell = 0;
            b->tDoneFirst = 0; b->tDoneLast = 0;
            b->haveSubmit = false; b->haveDoorbell = false;
            b->haveDone = false; b->allSegDone = false;
            b->haveRx = false; b->rxCum = 0; b->rxAddr = 0;
            b->rxLen = 0; b->tRx = 0;
            for (u32 s = 0; s < OBS_MAX_SEGS; s++) {
                b->segCum[s] = 0; b->segAddr[s] = 0; b->segLen[s] = 0;
                b->segTSubmit[s] = 0; b->segFlags[s] = 0;
                b->segDoneCount[s] = 0;
            }
        }

        if (r.kind == OBS_KIND_TX_SUBMIT) {
            b->haveSubmit = true;
            if (b->tSubmitFirst == 0 || r.tMono < b->tSubmitFirst)
                b->tSubmitFirst = r.tMono;
            if (r.tMono > b->tSubmitLast) b->tSubmitLast = r.tMono;
            if (r.flags & OBS_FLAG_FIRST_FRAG) b->firstFragCount++;
            if (r.flags & OBS_FLAG_LAST_FRAG)  b->lastFragCount++;
            if (r.addr == 0) b->segAddrZero = true;
            // Two ways a segment's DMA range is not knowable:
            //   * the driver flagged it (TSO/GSO: `len` is the MSS, not the
            //     byte count the device will write);
            //   * the recorded length is zero, which cannot be the length of
            //     a descriptor that carried part of a packet.
            // Either way the range is unknown and the batch must not pass on
            // it. Guessing from a neighbouring segment's length is exactly
            // the kind of inference this round removes.
            if ((r.flags & OBS_FLAG_LEN_UNKNOWN) || r.len == 0)
                b->segLenUnknown = true;
            // Generation must agree with the cumulative index and the ring
            // size the reader was told. A record whose gen disagrees is from
            // a different ring geometry (a driver reload with a different
            // descriptor count), so its cumulative index does not mean what
            // the join assumes.
            if (ringSize != 0 && r.gen != (r.cumulative / ringSize))
                b->segBadGen++;
            if (b->segCount < OBS_MAX_SEGS) {
                // Two segments sharing a cumulative index cannot both be
                // real: the index is unique per descriptor. That is slot
                // reuse or a duplicated record, and either way the DMA range
                // of one of them is unknown.
                for (u32 s = 0; s < b->segCount; s++) {
                    if (b->segCum[s] == r.cumulative) b->segDupCum++;
                }
                b->segCum[b->segCount] = r.cumulative;
                b->segAddr[b->segCount] = r.addr;
                b->segLen[b->segCount] = r.len;
                b->segTSubmit[b->segCount] = r.tMono;
                b->segFlags[b->segCount] = r.flags;
                b->segCount++;
            } else {
                b->segCapped++;
            }
        } else if (r.kind == OBS_KIND_TX_DOORBELL) {
            b->haveDoorbell = true;
            b->tDoorbell = r.tMono;
        } else {   // OBS_KIND_RX_DONE
            b->haveRx = true;
            b->rxCum = r.cumulative;
            b->rxAddr = r.addr;
            b->rxLen = r.len;
            b->tRx = r.tMono;
        }
    }

    // -- pass 3c: attach completions to individual segments ----------------
    //
    // The join key is the cumulative index, which the driver writes from its
    // own submit and completion counters -- the numbers the hardware reports.
    // No inference about slot reuse is involved.
    //
    // What matters here is that the match is per SEGMENT and counted, so a
    // duplicate completion cannot stand in for a missing one.
    for (u32 i = 0; i < h.recordCount; i++) {
        const ObsRec r = obsReadRecAt(blob, h, i);
        if (!r.valid || r.kind != OBS_KIND_TX_DONE) continue;
        for (u32 k = 0; k < j.bizCount; k++) {
            ObsBizOp &b = j.biz[k];
            for (u32 s = 0; s < b.segCount; s++) {
                if (b.segCum[s] != r.cumulative) continue;
                b.segDoneCount[s]++;
                b.haveDone = true;
                if (b.tDoneFirst == 0 || r.tMono < b.tDoneFirst)
                    b.tDoneFirst = r.tMono;
                if (r.tMono > b.tDoneLast) b.tDoneLast = r.tMono;
                // A completion recorded before its own submit is not a
                // completion of it: it is a stale record from an earlier lap
                // of the ring that happens to share the cumulative index.
                if (b.segTSubmit[s] != 0 && r.tMono < b.segTSubmit[s])
                    b.segDoneBeforeSubmit = true;
                break;
            }
        }
    }

    // -- pass 3d: per-op verdicts -----------------------------------------
    for (u32 k = 0; k < j.bizCount; k++) {
        ObsBizOp &b = j.biz[k];

        b.segDone = 0;
        b.segMissingDone = 0;
        b.segDupDone = 0;
        for (u32 s = 0; s < b.segCount; s++) {
            if (b.segDoneCount[s] == 0) {
                b.segMissingDone++;
            } else {
                b.segDone++;
                if (b.segDoneCount[s] > 1) b.segDupDone += b.segDoneCount[s] - 1;
            }
        }

        // Exactly one completion per segment, no truncation, no duplicates.
        b.allSegDone = (b.haveSubmit && b.segCount > 0 && b.segCapped == 0 &&
                        b.segMissingDone == 0 && b.segDupDone == 0 &&
                        !b.segDoneBeforeSubmit);

        // Fragment structure: a packet's first descriptor carries FIRST_FRAG
        // and its last carries LAST_FRAG. Exactly one of each means the log
        // holds the whole packet. A dropped trailing descriptor leaves
        // lastFragCount == 0, which no amount of per-segment completion can
        // repair -- the missing segment's DMA range is simply unknown.
        b.fragStructureOk = (b.firstFragCount == 1 && b.lastFragCount == 1 &&
                             b.segCapped == 0);

        // Every segment's DMA range must be known from its own record.
        b.dmaRangeKnown = (b.segCount > 0 && b.segCapped == 0 &&
                           !b.segAddrZero && !b.segLenUnknown && !b.segBadGen);

        // Window binding, checked per STAGE and for every request -- not just
        // for the first one. Counterexample B depends on this: an in-window
        // unrelated pair plus an out-of-window real exchange must not add up
        // to a pass.
        if (spec.requireWindow) {
            b.submitInWindow = (b.haveSubmit && b.tSubmitFirst >= winStart &&
                                b.tSubmitLast <= winEnd);
            b.doneInWindow = (b.haveDone && b.tDoneFirst >= winStart &&
                              b.tDoneLast <= winEnd);
            b.rxinWindow = (b.haveRx && b.tRx >= winStart && b.tRx <= winEnd);
            b.allStagesInWindow = (b.submitInWindow && b.doneInWindow &&
                                   b.rxinWindow);
            // A PRESENT stage outside the window is a window violation. An
            // absent stage is not: that is "incomplete", reported separately.
            b.stageOutsideWindow =
                ((b.haveSubmit && !b.submitInWindow) ||
                 (b.haveDone && !b.doneInWindow) ||
                 (b.haveRx && !b.rxinWindow));
        } else {
            // No window declared: the stage question is N/A, not PASS. The
            // batch verdict below refuses to pass on an N/A.
            b.submitInWindow = false;
            b.doneInWindow = false;
            b.rxinWindow = false;
            b.allStagesInWindow = false;
            b.stageOutsideWindow = false;
        }
    }

    // -- pass 3e: count the batch outcomes ---------------------------------
    for (u32 k = 0; k < j.bizCount; k++) {
        const ObsBizOp &b = j.biz[k];
        const bool inRange = (expectedBatch != 0 && b.reqId >= 1 &&
                              b.reqId <= expectedBatch);
        if (expectedBatch != 0 && !inRange) { j.batchUnexpected++; continue; }

        // A request that failed any of the binding properties is counted as
        // partial, and the specific counter says which property it was.
        if (b.haveSubmit && b.allSegDone && b.fragStructureOk &&
            b.dmaRangeKnown && b.haveRx && b.allStagesInWindow) {
            j.batchComplete++;
        } else {
            j.batchPartial++;
            if (b.segDupDone != 0 || b.segDoneCount[0] > 1) j.batchDupDone++;
            if (b.haveSubmit && !b.fragStructureOk) j.batchBadFrag++;
            if (b.haveSubmit && !b.dmaRangeKnown) j.batchDmaUnknown++;
            if (b.segDoneBeforeSubmit) j.batchOrder++;
            if (b.stageOutsideWindow) j.batchOutsideWindow++;
        }
    }
    // Duplicate completions can also exist on a segment of an op that is
    // otherwise counted once; scan every op so the counter is not
    // under-reported by the `else` branch above.
    {
        u32 dupOps = 0;
        for (u32 k = 0; k < j.bizCount; k++) {
            if (j.biz[k].segDupDone != 0) dupOps++;
        }
        if (dupOps > j.batchDupDone) j.batchDupDone = dupOps;
    }

    if (expectedBatch != 0) {
        // A declared request with no record at all is MISSING, which is a
        // different failure from a request that started but did not finish.
        for (u32 id = 1; id <= expectedBatch; id++) {
            bool seen = false;
            for (u32 k = 0; k < j.bizCount; k++) {
                if (j.biz[k].reqId == id) { seen = true; break; }
            }
            if (!seen) j.batchMissing++;
        }

        // The full conjunction. Every term is a property that was declared
        // before the evidence was read, or a property of the evidence that a
        // false pass would require ignoring.
        const bool tokenOk = j.tokenResolved && !j.tokenAmbiguous &&
                             !j.inferredToken;   // ROUND 12: declared, not inferred
        const bool windowOk = spec.requireWindow;   // N/A is not PASS
        j.controlledBatchComplete =
            (tokenOk && windowOk &&
             j.batchComplete == expectedBatch &&
             j.batchMissing == 0 && j.batchPartial == 0 &&
             j.batchUnexpected == 0 && j.batchUnparsed == 0 &&
             j.batchForeignToken == 0 && j.batchOutsideWindow == 0 &&
             j.batchDupDone == 0 && j.batchBadFrag == 0 &&
             j.batchDmaUnknown == 0 && j.batchOrder == 0 &&
             j.bizCapped == 0 && j.holes == 0);

        // Order matters: report the most specific reason first, so a capture
        // that has several problems does not get labelled with the vaguest.
        //
        // Run identity first (it invalidates every other statement), then the
        // window binding, then per-request structure, then the aggregate
        // counts. "requests-missing" precedes the per-op property reasons
        // because "a declared request produced no record at all" is a
        // stronger and more actionable statement than "one of the requests I
        // did see has a structural problem".
        if (j.controlledBatchComplete)            j.batchWhy = "complete";
        else if (!j.tokenResolved)                j.batchWhy = "run-token-not-declared";
        // Ambiguity is reported BEFORE inference: "the records span two runs"
        // is a stronger and more specific statement than "the token was not
        // declared", and a reader needs to know that the snapshot is not even
        // about one run. Round 12's first ordering had inference first, which
        // relabelled a two-run snapshot as merely undeclared.
        else if (j.tokenAmbiguous)                j.batchWhy = "records-span-multiple-runs";
        else if (j.inferredToken)                 j.batchWhy = "run-token-was-inferred";
        else if (j.batchForeignToken)             j.batchWhy = "records-from-another-run";
        else if (!spec.requireWindow)             j.batchWhy = "no-window-declared";
        else if (j.batchOutsideWindow)            j.batchWhy = "exchange-outside-the-window";
        else if (j.batchDupDone)                  j.batchWhy = "duplicate-completions";
        else if (j.batchOrder)                    j.batchWhy = "completion-before-submit";
        else if (j.batchUnexpected)               j.batchWhy = "requests-outside-the-declared-batch";
        else if (j.batchMissing)                  j.batchWhy = "requests-missing";
        else if (j.batchBadFrag)                  j.batchWhy = "segment-structure-incomplete";
        else if (j.batchDmaUnknown)               j.batchWhy = "segment-dma-range-unknown";
        else if (j.batchPartial)                  j.batchWhy = "requests-incomplete";
        else if (j.batchUnparsed)                 j.batchWhy = "records-without-a-business-id";
        else if (j.bizCapped)                     j.batchWhy = "business-ops-capped";
        else if (j.holes)                         j.batchWhy = "records-missing";
        else                                      j.batchWhy = "degraded";
    } else {
        j.batchWhy = "batch-not-declared";
    }
}

// Convenience wrapper for callers that can afford the temporary. The host
// tests can (a test binary's stack is not the kernel's); the kext must use
// obsJoinInto() with a member.
static inline ObsJoin obsJoin(const u8 *blob, u64 bytes, u32 ringSize,
                              const ObsBatchSpec &spec) {
    ObsJoin j;
    obsJoinInto(j, blob, bytes, ringSize, spec);
    return j;
}

// Round-10-shaped convenience overload: a declared count with no token and no
// window. It is kept because a caller that genuinely has neither is asking a
// weaker question, and this spelling makes that explicit at the call site.
// It can never reach controlledBatchComplete: with expectedBatch != 0 and no
// window the `no-window-declared` reason fires, and with expectedBatch == 0
// the verdict is `batch-not-declared`.
static inline ObsJoin obsJoin(const u8 *blob, u64 bytes, u32 ringSize,
                              u64 winStart, u64 winEnd,
                              u32 expectedBatch) {
    return obsJoin(blob, bytes, ringSize,
                   obsBatchSpecOf(expectedBatch, 0, winStart, winEnd));
}

// ---- per-path coverage ---------------------------------------------------
//
// Round 7 published ONE coverage value for the whole observation and then used
// it for every path. TX was window-covered; RX, the rings and the stats
// buffer were snapshots. Reporting all of them as "window-complete" is the
// same over-generalisation in a new place.
struct PathCoverage {
    u32  txRing;
    u32  rxRing;
    u32  txBuf;
    u32  rxBuf;
    u32  stat;

    void clear() { txRing = rxRing = txBuf = rxBuf = stat = COV_NONE; }

    u32 get(u32 path) const {
        switch (path) {
            case PATH_TX_RING: return txRing;
            case PATH_RX_RING: return rxRing;
            case PATH_TX_BUF:  return txBuf;
            case PATH_RX_BUF:  return rxBuf;
            case PATH_STAT:    return stat;
            default:           return COV_NONE;
        }
    }

    void set(u32 path, u32 cov) {
        switch (path) {
            case PATH_TX_RING: txRing = cov; break;
            case PATH_RX_RING: rxRing = cov; break;
            case PATH_TX_BUF:  txBuf = cov; break;
            case PATH_RX_BUF:  rxBuf = cov; break;
            case PATH_STAT:    stat = cov; break;
            default: break;
        }
    }

    // The weakest coverage across every path. This is the only value that may
    // be used for a device-wide statement.
    u32 weakest() const {
        u32 w = COV_WINDOW;
        const u32 v[5] = { txRing, rxRing, txBuf, rxBuf, stat };
        for (int i = 0; i < 5; i++) if (v[i] < w) w = v[i];
        return w;
    }

    // True only when every path reached window coverage.
    bool allWindow() const { return weakest() == COV_WINDOW; }
};

// ---- SHA-256, so an exported blob can be tied to the decode that used it ---
//
// WHY THIS IS HERE AND NOT IN THE PROBE
// -------------------------------------
// Round 11 exports the snapshot the probe actually decoded (`m2-b2-obs-
// snapshot-used`) and must also publish a hash of it. If the hash were
// computed by a different implementation than the one the analyser uses, a
// mismatch would be ambiguous: wrong bytes, or wrong hash? Putting the
// implementation in this shared header means the host tests and the kext run
// the SAME code, and the analyser hashes the exported file with a standard
// library. A disagreement is then always about the bytes.
//
// Bounded and allocation-free: no tables, no globals, no IOKit. Same reason
// amd_iommu_pte_core.hpp has no dependencies -- it is included by the kext and
// by a plain host binary.
namespace sha256 {

struct Ctx {
    u32 h[8];
    u64 bits;
    u8  buf[64];
    u32 used;
};

static inline u32 ror(u32 x, unsigned n) { return (x >> n) | (x << (32 - n)); }

static const u32 K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static inline void init(Ctx &c) {
    c.h[0] = 0x6a09e667u; c.h[1] = 0xbb67ae85u;
    c.h[2] = 0x3c6ef372u; c.h[3] = 0xa54ff53au;
    c.h[4] = 0x510e527fu; c.h[5] = 0x9b05688cu;
    c.h[6] = 0x1f83d9abu; c.h[7] = 0x5be0cd19u;
    c.bits = 0;
    c.used = 0;
}

static inline void block(Ctx &c, const u8 *p) {
    u32 w[64];
    for (unsigned i = 0; i < 16; i++) {
        w[i] = ((u32)p[i * 4] << 24) | ((u32)p[i * 4 + 1] << 16) |
               ((u32)p[i * 4 + 2] << 8) | (u32)p[i * 4 + 3];
    }
    for (unsigned i = 16; i < 64; i++) {
        const u32 s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const u32 s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    u32 a = c.h[0], b = c.h[1], cc = c.h[2], d = c.h[3];
    u32 e = c.h[4], f = c.h[5], g = c.h[6], hh = c.h[7];
    for (unsigned i = 0; i < 64; i++) {
        const u32 S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
        const u32 ch = (e & f) ^ (~e & g);
        const u32 t1 = hh + S1 + ch + K[i] + w[i];
        const u32 S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
        const u32 mj = (a & b) ^ (a & cc) ^ (b & cc);
        const u32 t2 = S0 + mj;
        hh = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c.h[0] += a; c.h[1] += b; c.h[2] += cc; c.h[3] += d;
    c.h[4] += e; c.h[5] += f; c.h[6] += g; c.h[7] += hh;
}

static inline void update(Ctx &c, const u8 *p, u64 n) {
    c.bits += n * 8u;
    while (n > 0) {
        const u32 take = (u32)((n < (64u - c.used)) ? n : (64u - c.used));
        for (u32 i = 0; i < take; i++) c.buf[c.used + i] = p[i];
        c.used += take;
        p += take;
        n -= take;
        if (c.used == 64) { block(c, c.buf); c.used = 0; }
    }
}

static inline void finalHex(Ctx &c, char *out65) {
    const u64 totalBits = c.bits;
    u8 pad = 0x80;
    update(c, &pad, 1);
    u8 zero = 0;
    while (c.used != 56) update(c, &zero, 1);
    u8 len[8];
    for (unsigned i = 0; i < 8; i++) len[i] = (u8)(totalBits >> (56 - 8 * i));
    // update() would add these to c.bits; that is harmless because the digest
    // is taken immediately after and the context is not reused.
    update(c, len, 8);

    static const char *hex = "0123456789abcdef";
    for (unsigned i = 0; i < 8; i++) {
        for (unsigned b = 0; b < 4; b++) {
            const u8 v = (u8)(c.h[i] >> (24 - 8 * b));
            out65[i * 8 + b * 2]     = hex[v >> 4];
            out65[i * 8 + b * 2 + 1] = hex[v & 0xF];
        }
    }
    out65[64] = 0;
}

// One-shot helper.
static inline void hashHex(const u8 *p, u64 n, char *out65) {
    Ctx c;
    init(c);
    update(c, p, n);
    finalHex(c, out65);
}

}  // namespace sha256

}  // namespace amdobs
