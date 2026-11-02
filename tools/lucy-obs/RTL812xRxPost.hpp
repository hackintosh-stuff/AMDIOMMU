/*
 * RTL812xRxPost.hpp -- the set of RX buffers the DEVICE may write, expressed
 * as two things that can be joined without a gap:
 *
 *   1. a BASELINE: every RX descriptor's posted address and posted capacity,
 *      captured in the driver's own RX-capable context;
 *   2. a REARM LOG: every time the driver hands a descriptor back to the
 *      hardware, the slot, the FINAL address, the FINAL capacity, a monotonic
 *      sequence number and the time.
 *
 * ===========================================================================
 * WHY THIS FILE EXISTS (round 14)
 * ===========================================================================
 *
 * Through round 13 the evidence answered a narrower question than the one that
 * matters:
 *
 *     "the four controlled requests' TX and RX ranges are mapped"
 *
 * It never answered:
 *
 *     "every RX buffer the NIC could possibly write during the window is
 *      mapped, and mapped with RX write permission"
 *
 * The gap is not a missing check, it is a missing SET. A ring of 1024 RX
 * descriptors holds 1024 page-sized buffers; the driver re-posts them as
 * packets arrive; the ones re-posted during the window are different objects
 * from the ones posted before it. Round 13's eight walked ranges were the
 * buffers that happened to carry the four echoes -- roughly 0.4% of the
 * writable area.
 *
 * ===========================================================================
 * THE SET THIS FILE DEFINES
 * ===========================================================================
 *
 *     S = { (addr, capacity) posted at the baseline }
 *       ∪ { (addr, capacity) re-armed after the baseline and at or before
 *           the end of the window }
 *
 * That union is CONSERVATIVE ON PURPOSE. It is a superset of the buffers the
 * device can write at any instant in the interval, because:
 *
 *   * a buffer that was live at the baseline instant and was replaced before
 *     it could be read is still covered -- it appears in the rearm log;
 *   * a buffer that is re-armed many times with the same address contributes
 *     one range, and de-duplication is by (addr, capacity) rather than by
 *     slot, so slot reuse cannot hide an address.
 *
 * ===========================================================================
 * HOW THE TWO HALVES ARE KEPT GAP-FREE
 * ===========================================================================
 *
 * The baseline is captured and the rearm log is written by the same driver.
 * Three rules make the join exact, and each one is a field a reader checks:
 *
 *   1. THE WATERMARK IS READ BEFORE THE SCAN.
 *      `rearmSeqAtBaseline` is the rearm counter as it stood BEFORE the slot
 *      scan started. A reader therefore needs every rearm record with
 *      seq > that value. If the watermark were read AFTER the scan, a rearm
 *      that happened during the scan would be excluded from the required set
 *      AND might already be reflected in the scan -- so the address it
 *      replaced would appear in neither half. That is the one gap this design
 *      must not have, and reading the watermark first closes it.
 *
 *   2. THE RING MUST STILL HOLD THE WATERMARK.
 *      `rearmFirstSeq` is the oldest sequence number the ring still holds. A
 *      reader requires rearmFirstSeq <= rearmSeqAtBaseline + 1. Otherwise the
 *      ring lapped past the baseline and the set is INCOMPLETE -- reported as
 *      such, never silently narrowed.
 *
 *   3. A RING REBUILD INVALIDATES THE BASELINE.
 *      `ringGen` is bumped by every path that rewrites descriptor addresses
 *      (setup, clearRxTxRings, rxMapBuffers). Every slot record carries the
 *      generation it was filled under, and every rearm record carries the
 *      generation it was written under. A reader requires all three equal.
 *
 * ===========================================================================
 * THE DESCRIPTOR IS READ AS A PAIR, WITH A BOUNDED RETRY
 * ===========================================================================
 *
 * The baseline scan reads descriptor fields that the RX path also writes, so
 * "the watchdog and the RX path are serialised" is NOT assumed. The RX path
 * stores `buf.addr` and then `buf.blen`, so a reader that sees a stable `blen`
 * around its read of `addr` may still have paired a NEWER address with the
 * OLDER length word.
 *
 * The direction of that skew is what makes it safe: `addr` newer than `blen`
 * means the record describes the buffer being posted right now, which is a
 * buffer the device is about to be told about -- conservative. The reverse
 * (addr older than blen) cannot occur with that store order.
 *
 * The scan still retries a bounded number of times when `blen` changes under
 * it, and counts an exhausted retry in `baselineTorn` rather than publishing a
 * pair it could not stabilise.
 *
 * ===========================================================================
 * WHAT THIS FILE IS NOT
 * ===========================================================================
 *
 * It does not allocate, log, touch a register or call IOKit. It is structs,
 * offsets and two pure fill functions plus one copy function, so the host test
 * can drive the very same code the driver runs. Nothing here changes how DMA
 * is mapped.
 */

#ifndef RTL812xRxPost_hpp
#define RTL812xRxPost_hpp

/* 'RXPO' little-endian. A reader that does not recognise magic/version/sizes
 * refuses instead of decoding a layout it guessed. */
#define kRxPostMagic      0x4F505852u
#define kRxPostVersion    1u
#define kRxPostFormat     "rtl812x-rxpost/1"

/* Capacity of the two tables. kRxPostSlots MUST equal the driver's kNumRxDesc;
 * the driver asserts that at compile time so the two cannot drift. */
#define kRxPostSlots      1024u
#define kRxPostSlotsMask  (kRxPostSlots - 1u)
#define kRxPostRearmCap   4096u
#define kRxPostRearmMask  (kRxPostRearmCap - 1u)
/* How many rearm records one publication carries. The live ring is larger so a
 * long run does not lose the baseline watermark, while a single property stays
 * bounded. If more records are REQUIRED than this, the publication says so
 * (`truncated`) instead of quietly publishing a prefix: a prefix would make an
 * incomplete set look complete. */
#define kRxPostPublishRearmMax 2048u

/* Descriptor bit meanings, repeated here because this header must compile in
 * the host test, which has no driver headers. The driver asserts these against
 * the real enumerators at compile time (see the patch's rxpostInit). */
#define kRxPostDescOwn    0x80000000u   /* bit 31: NIC still owns the buffer   */
#define kRxPostRingEnd    0x40000000u   /* bit 30: last descriptor of the ring */
#define kRxPostLenMask    0x3FFFFFFFu   /* everything else is the buffer size  */

/* Slot-record flags. */
#define kRxPostSlotOwned        (1u << 0)  /* DescOwn set: word 0 is the length */
#define kRxPostSlotRingEnd      (1u << 1)  /* RingEnd set in blenRaw            */
#define kRxPostSlotCapFromDesc  (1u << 2)  /* capacity came from the descriptor */
#define kRxPostSlotCapFromConst (1u << 3)  /* capacity came from kRxBufferSize  */
#define kRxPostSlotCapMismatch  (1u << 4)  /* descriptor disagreed with the const */
#define kRxPostSlotAddrZero     (1u << 5)  /* the slot posts no address         */
#define kRxPostSlotTorn         (1u << 6)  /* the pair could not be stabilised  */

/* Rearm-record flags. */
#define kRxPostRearmReplaced   (1u << 0)  /* a NEW buffer was installed        */
#define kRxPostRearmRingEnd    (1u << 1)  /* RingEnd set in blenRaw            */
#define kRxPostRearmOwned      (1u << 2)  /* DescOwn set in blenRaw            */
#define kRxPostRearmAfterReset (1u << 3)  /* written under a bumped ringGen    */
#define kRxPostRearmOldZero    (1u << 4)  /* the retired address was 0         */

/* Header flags. */
#define kRxPostHdrFlagNoBaseline (1u << 0)  /* no capture has completed     */
#define kRxPostHdrFlagRearmLost  (1u << 1)  /* dropped or wrapped != 0      */
#define kRxPostHdrFlagGenMoved   (1u << 2)  /* a capture saw ringGen move   */
#define kRxPostHdrFlagTruncated  (1u << 3)  /* more rearm records needed
                                             * than one publish can carry   */

namespace rxpost {

typedef unsigned long long u64;
typedef unsigned int       u32;
typedef unsigned long long Word;

/* ---- the header -------------------------------------------------------
 *
 * Field ORDER matters beyond readability: `head`, `wrapped` and `dropped` sit
 * at the SAME byte offsets as RtlObsHdr's, so the rearm ring reuses obslog's
 * ticket/loss protocol verbatim. The static asserts below pin that.
 */
struct Hdr {
    u32 magic;              /*   0  kRxPostMagic                            */
    u32 version;            /*   4  kRxPostVersion                          */
    u32 recSizeSlot;        /*   8  32                                      */
    u32 recSizeRearm;       /*  12  40                                      */
    u32 head;               /*  16  rearms ever claimed (absolute)          */
    u32 wrapped;            /*  20  rearm slots overwritten before publish  */
    u32 dropped;            /*  24  rearm writes that lost the lock         */
    u32 slotCapacity;       /*  28  kRxPostSlots                            */
    u32 rearmCapacity;      /*  32  kRxPostRearmCap                         */
    u32 rearmFirstSeq;      /*  36  oldest seq still in the ring (0 = empty)*/
    u32 ringGen;            /*  40  bumped by every ring rebuild            */
    u32 baselineActive;     /*  44  which slot array the publisher reads    */
    u32 baselineSlots;      /*  48  slots examined by the capture           */
    u32 baselineValid;      /*  52  slots posting a non-zero address        */
    u32 baselineAddrZero;   /*  56  slots posting address 0                 */
    u32 baselineCapDesc;    /*  60  capacities read from the descriptor     */
    u32 baselineCapConst;   /*  64  capacities taken from kRxBufferSize     */
    u32 baselineCapBad;     /*  68  descriptor capacity != kRxBufferSize    */
    u32 baselineTorn;       /*  72  pairs that could not be stabilised      */
    u32 baselineCount;      /*  76  successful captures since init          */
    u32 baselineGenMoved;   /*  80  captures abandoned because gen moved    */
    u32 pubId;              /*  84  publication counter, starts at 1        */
    u32 epoch;              /*  88  driver-instance epoch                   */
    u32 ifUnit;             /*  92  BSD unit                                */
    u32 vtdPath;            /*  96  1 when rxInterruptVTD is the live path  */
    u32 rxBufferSize;       /* 100  the driver's kRxBufferSize constant     */
    u32 flags;              /* 104  kRxPostHdrFlag*                         */
    u32 pad0;               /* 108                                          */
    u64 tBaseline;          /* 112  mach_absolute_time of the capture       */
    u64 rearmSeqAtBaseline; /* 120  rearm head BEFORE that capture's scan   */
    u64 tPublished;         /* 128  mach_absolute_time of this publication  */
    u32 rearmRequired;      /* 136  records needed to cover the watermark   */
    u32 rearmPublished;     /* 140  records actually in this blob           */
    u32 reserved[4];        /* 144..159                                     */
};

/* ---- one baseline slot record, 32 bytes = 4 words ---------------------- */
struct SlotRec {
    u64 addr;        /* descriptor buf.addr, raw                          */
    u64 blenRaw;     /* descriptor buf.blen, raw                          */
    u32 slot;        /* ring index                                        */
    u32 capacity;    /* bytes the device may write into [addr, addr+cap)  */
    u32 flags;       /* kRxPostSlot*                                      */
    u32 gen;         /* ringGen this record was filled under              */
};

/* ---- one rearm record, 48 bytes = 6 whole 8-byte words -----------------
 *
 * `seq` sits at offset 32, i.e. word 4, and shares that word with `slot` --
 * the same shape RTL812xObsWrite.hpp's protocol already handles (there it is
 * `seq` + `kind` in word 2). Keeping the protocol word a whole word is what
 * lets the writer and the publisher use 8-byte atomics on both sides.
 *
 * WHY `oldAddr` EXISTS -- the gap it closes
 * -----------------------------------------
 * Recording only the buffer being INSTALLED is not enough, and the first
 * version of this round did exactly that. Consider a rearm that happens while
 * the baseline scan is running:
 *
 *     t0   watermark read
 *     t1   rearm(slot 9): retires A, installs B      <- record: new = B
 *     t2   the scan reaches slot 9 and sees B
 *     t3   head read; publication carries the record
 *
 * The baseline now says B and the rearm log says B, so the union is {B}. But A
 * was the posted buffer from t0 until t1, so the device could write into A for
 * that whole interval -- and A is in NEITHER half. "Every range covered" would
 * then be true of a set that is not the set the device could write.
 *
 * So the record carries the pair: `oldAddr` (what the slot posted before this
 * rearm) and `addr` (what it posts after). The union takes both. That makes the
 * set a superset regardless of whether the scan saw the slot before or after
 * the rearm -- which are the only two possibilities.
 *
 * For a rearm that reuses the same buffer, old == new and the two collapse in
 * the union's de-duplication, which is correct.
 */
struct RearmRec {
    u64 tMono;       /* word 0                                            */
    u64 addr;        /* word 1  FINAL address handed to the hardware      */
    u64 oldAddr;     /* word 2  the address this rearm RETIRED            */
    u64 blenRaw;     /* word 3  FINAL descriptor word 0                   */
    u32 seq;         /* word 4 low  -- protocol-owned, odd = in flight    */
    u32 slot;        /* word 4 high                                       */
    u32 capacity;    /* word 5 low  FINAL capacity handed to the hardware  */
    u32 flags;       /* word 5 high kRxPostRearm*                         */
};

/* The sizes are expressed with plain `unsigned int` rather than the namespace
 * typedef: a macro is expanded wherever it is used, including at file scope in
 * the host test, where `rxpost::u32` is not in scope. */
#define kRxPostHdrBytes    ((unsigned int)sizeof(rxpost::Hdr))
#define kRxPostSlotBytes   ((unsigned int)sizeof(rxpost::SlotRec))
#define kRxPostRearmBytes  ((unsigned int)sizeof(rxpost::RearmRec))
#define kRxPostRearmSeqOff ((unsigned int)__builtin_offsetof(rxpost::RearmRec, seq))
#define kRxPostRearmSeqWord (kRxPostRearmSeqOff / 8u)

/* The published blob: header, ONE slot array, then the rearm ring in ticket
 * order. One OSData, so the baseline and the rearm log cannot come from
 * different publications -- the same reasoning that made the observation log a
 * single property in round 10. */
#define kRxPostSnapshotMax \
    (((unsigned long long)kRxPostHdrBytes) + \
     ((unsigned long long)kRxPostSlots) * ((unsigned long long)kRxPostSlotBytes) + \
     ((unsigned long long)kRxPostRearmCap) * ((unsigned long long)kRxPostRearmBytes))

/* The live region the driver allocates: the header, TWO slot arrays, and the
 * rearm ring.
 *
 * WHY THIS IS NOT kRxPostSnapshotMax
 * ----------------------------------
 * It was, and that was a real-machine panic (round 14, run 5, ~242 s in):
 *
 *     Kernel trap type 14 = page fault, WRITE
 *     com.insanelymac.RTL812xLucy : obslog::writeRecordSized<...>
 *       <- RTL8125::rxpostRecordRearm
 *       <- RTL8125::rxInterrupt
 *       <- RTL8125::pollInputPackets
 *
 * A SNAPSHOT holds one slot array, because the baseline is published from the
 * ACTIVE one. The LIVE REGION holds two, so a capture can fill the inactive one
 * while a publish copies the active one. `kRxPostRegionBytes` was defined as
 * `kRxPostSnapshotMax`, which is one slot array too small, so
 * `rxpostRearms` was placed 32768 bytes past where the size macro thought the
 * ring started -- and the tail of the ring (records ~3414..4095) lived OUTSIDE
 * the IOBufferMemoryDescriptor's mapping. The first few minutes never reached
 * it; the ring filled up and the next write faulted on an unmapped page.
 *
 * Two slot arrays is the layout `rxpostInit()` actually builds:
 *
 *     rxpostSlots[0] = hdr + kRxPostHdrBytes
 *     rxpostSlots[1] = slots[0] + kRxPostSlots*kRxPostSlotBytes
 *     rxpostRearms   = slots[1] + kRxPostSlots*kRxPostSlotBytes
 *
 * so the size macro now says so, and the two are tied together by the
 * compile-time assertions below rather than by a comment. */
#define kRxPostSlotTables 2u
#define kRxPostRegionBytes \
    (((unsigned long long)kRxPostHdrBytes) + \
     ((unsigned long long)kRxPostSlotTables) * \
         ((unsigned long long)kRxPostSlots) * ((unsigned long long)kRxPostSlotBytes) + \
     ((unsigned long long)kRxPostRearmCap) * ((unsigned long long)kRxPostRearmBytes))

/* The offset `rxpostInit()` computes for the ring, expressed as an expression so
 * a layout change breaks the build instead of the machine. */
#define kRxPostRearmsOff \
    (((unsigned long long)kRxPostHdrBytes) + \
     ((unsigned long long)kRxPostSlotTables) * \
         ((unsigned long long)kRxPostSlots) * ((unsigned long long)kRxPostSlotBytes))

/* The region must be large enough to hold the whole ring starting at that
 * offset. This is the exact invariant the panic violated.
 *
 * NOTE ON WHAT THESE ASSERTS CAN AND CANNOT CATCH
 * -----------------------------------------------
 * Both sides below are written in terms of kRxPostSlotTables, so a change to
 * THAT constant alone moves both sides together and the assert still passes.
 * It is a consistency check between the size macro and the offset macro, not a
 * proof about the driver's layout.
 *
 * The tie to the driver's actual layout is:
 *   - `kRxPostSlotTables == 2` here, which documents the number; and
 *   - `sizeof(rxpostSlots)/sizeof(rxpostSlots[0]) == kRxPostSlotTables` in
 *     rxpostInit(), where the driver's own array is visible.
 * That second one is the one that would have failed for the original defect,
 * because the array has two elements and the macro said one.
 *
 * The arithmetic below additionally catches a ring/offset mismatch, and the
 * host test (testRegionHoldsRing) asserts the same numbers against a literal
 * `2` rather than against the macro -- which is what makes it sensitive. */
static_assert(kRxPostSlotTables == 2u,
              "the driver keeps exactly two slot arrays (rxpostSlots[2]): one "
              "the RX path writes, one a publish copies");
static_assert(kRxPostRegionBytes ==
                  kRxPostRearmsOff +
                      ((unsigned long long)kRxPostRearmCap) *
                          ((unsigned long long)kRxPostRearmBytes),
              "kRxPostRegionBytes must be header + 2 slot arrays + the full ring");
static_assert(kRxPostRegionBytes >=
                  kRxPostRearmsOff +
                      ((unsigned long long)kRxPostRearmCap) *
                          ((unsigned long long)kRxPostRearmBytes),
              "the rearm ring must lie entirely inside the allocated region");
/* And a snapshot must still fit: it is the header plus ONE slot array plus the
 * records the publisher keeps, every one of which must be inside the region. */
static_assert(kRxPostSnapshotMax <= kRxPostRegionBytes,
              "a published snapshot must not be larger than the live region");

/* ---- the two pure fill functions --------------------------------------
 *
 * These are the ONLY places that decide what a slot record and a rearm record
 * mean. The driver calls them and the host test calls them, so "the rearm
 * record carries the FINAL address and the FINAL capacity" is a property of
 * one function rather than of a code path.
 */
static inline void fillSlotRec(unsigned char *dst, u32 slot, u64 addr,
                               u64 blenRaw, u32 gen, u32 rxBufferSize,
                               u32 extraFlags) {
    SlotRec *r = (SlotRec *)dst;
    const u32 low = (u32)(blenRaw & 0xFFFFFFFFull);
    const bool owned = (low & kRxPostDescOwn) != 0;

    r->addr = addr;
    r->blenRaw = blenRaw;
    r->slot = slot;
    r->flags = extraFlags;
    r->gen = gen;

    if (owned) {
        /* The descriptor is still the NIC's, so word 0 is the POSTED LENGTH,
         * not a status word. Masking off DescOwn/RingEnd gives exactly the
         * number of bytes the NIC may write. */
        r->capacity = low & kRxPostLenMask;
        r->flags |= kRxPostSlotCapFromDesc;
        if ((low & kRxPostRingEnd) != 0) r->flags |= kRxPostSlotRingEnd;
        if (r->capacity != rxBufferSize) r->flags |= kRxPostSlotCapMismatch;
    } else {
        /* The NIC has filled this descriptor, so word 0 is a STATUS word and
         * its length field is what was RECEIVED -- never what may be written.
         * Using it would be the round-9/10 mistake in a new place: the 74-byte
         * echo would stand in for a 4096-byte buffer. The posted capacity is
         * therefore taken from the driver's own post value and the record says
         * so, so a reader can count how often the fallback was used. */
        r->capacity = rxBufferSize;
        r->flags |= kRxPostSlotCapFromConst;
        if ((low & kRxPostRingEnd) != 0) r->flags |= kRxPostSlotRingEnd;
    }
    if (owned) r->flags |= kRxPostSlotOwned;
    if (addr == 0) r->flags |= kRxPostSlotAddrZero;
}

static inline void fillRearmRec(unsigned char *dst, u32 slot, u64 addr,
                                u64 oldAddr, u64 blenRaw, u64 tMono,
                                u32 extraFlags) {
    RearmRec *r = (RearmRec *)dst;
    const u32 low = (u32)(blenRaw & 0xFFFFFFFFull);

    r->tMono = tMono;
    r->addr = addr;
    r->oldAddr = oldAddr;
    r->blenRaw = blenRaw;
    r->slot = slot;
    /* The capacity in a rearm record is ALWAYS the value being handed to the
     * hardware right now, so it is always readable from the descriptor word --
     * this is the whole point of recording at the hand-back site instead of
     * reusing the observation log's rx-done record, whose `len` is the
     * received packet size. */
    r->capacity = low & kRxPostLenMask;
    r->flags = extraFlags;
    if (oldAddr == 0) r->flags |= kRxPostRearmOldZero;
    if ((low & kRxPostRingEnd) != 0) r->flags |= kRxPostRearmRingEnd;
    if ((low & kRxPostDescOwn) != 0) r->flags |= kRxPostRearmOwned;
    /* seq is protocol-owned; the caller's staging buffer is zeroed first and
     * obslog::writeRecordSized stamps it. Leave it untouched here. */
    r->seq = 0;
}

/* Oldest sequence number still representable in a ring of `cap` whose counter
 * is `head`. 0 means "nothing has been written yet". */
static inline u32 firstSeqFor(u32 head, u32 cap) {
    if (head == 0) return 0;
    if (head <= cap) return 1u;
    return head - cap + 1u;
}

/* Number of rearm records a ring of `cap` holds for `head`. */
static inline u32 rearmCountFor(u32 head, u32 cap) {
    return (head < cap) ? head : cap;
}

/* ---- publish ---------------------------------------------------------
 *
 * Copies the slot array and the rearm ring into `dst` in ticket order, AFTER
 * the header (which the caller fills). Returns the number of bytes written;
 * the caller fills the header.
 *
 * `slotBase` points at the slot array, `rearmBase` at the ring, `head` is the
 * rearm counter as the caller read it (atomically).
 *
 * `want` is how many rearm records the reader will NEED (head minus the
 * baseline watermark). Only `kRxPostPublishRearmMax` fit in one property, so
 * the caller learns both numbers and sets `truncated` when they differ. A
 * silently shortened log would be the exact defect this round is about.
 *
 * Every read is an 8-byte atomic load. That is not decoration: the rearm
 * writer stores with 8-byte atomics, and a plain 32-bit load of `seq` would be
 * a different-width access to the same bytes -- which is the exact data race
 * round 12 removed from the observation log.
 */
static inline u32 publishCopy(const unsigned char *slotBase,
                              const unsigned char *rearmBase,
                              u32 head, u32 want,
                              u32 rearmCap, u32 rearmMask,
                              unsigned char *dst,
                              u32 *publishedOut) {
    /* THE HEADER IS PART OF THE PUBLISHED BLOB, SO THE RECORDS START AFTER IT.
     *
     * The first version of this function started at 0 and wrote the slot array
     * over the header's own bytes. The driver then filled the header AFTER the
     * copy, which overwrote the first five slot records -- and the blob came out
     * exactly kRxPostHdrBytes short, so the reader's
     *
     *     (bytes - hdr - slots) % rearmBytes
     *
     * was non-zero and it refused with `ragged-rearm-body`.
     *
     * That is the right failure (a refusal, not a plausible wrong answer), but
     * the host test did not catch it: the test's publish() helper wrote slots at
     * 0 and read rearms at kRxPostSlots*kRxPostSlotBytes, i.e. it used the SAME
     * wrong origin on both sides and agreed with itself. The test now asserts the
     * origin explicitly. */
    u32 off = kRxPostHdrBytes;

    /* ---- the slot array, verbatim ------------------------------------- */
    {
        const Word *src = (const Word *)slotBase;
        Word *out = (Word *)(dst + off);
        const u32 words = (kRxPostSlots * kRxPostSlotBytes) / 8u;
        for (u32 i = 0; i < words; i++)
            out[i] = __atomic_load_n(src + i, __ATOMIC_RELAXED);
        off += kRxPostSlots * kRxPostSlotBytes;
    }

    /* ---- the rearm ring, oldest first ---------------------------------
     *
     * `n` is what the ring can give up to the requested count, capped by the
     * publish budget. The NEWEST records are kept, because the reader needs
     * the ones nearest its watermark and those are the ones at the end of the
     * ring; publishing the oldest instead would drop exactly the records the
     * window produced.
     */
    {
        const u32 have = (head < rearmCap) ? head : rearmCap;
        u32 n = (want < have) ? want : have;
        if (n > kRxPostPublishRearmMax) n = kRxPostPublishRearmMax;
        const u32 first = firstSeqFor(head, rearmCap) + (have - n);
        for (u32 i = 0; i < n; i++) {
            const u32 ticket = first + i;
            const u32 idx = ticket & rearmMask;
            const unsigned char *src =
                rearmBase + ((unsigned long long)idx) * ((unsigned long long)kRxPostRearmBytes);
            unsigned char *out = dst + off + ((unsigned long long)i) * ((unsigned long long)kRxPostRearmBytes);
            /* Read the whole seq word first: it is the protocol's word and it
             * also carries `slot`, so a narrow read would be a different-width
             * access. An odd seq means a body is in flight; a seq that is not
             * this ticket means the ring lapped us. Both are holes, and a hole
             * is copied as zeros so the reader sees "nothing here" rather than
             * a stale body. */
            const Word w = __atomic_load_n(
                (const Word *)src + kRxPostRearmSeqWord, __ATOMIC_ACQUIRE);
            const u32 seq = (u32)(w & 0xFFFFFFFFull);
            if (seq == 0 || (seq & 1u) || (seq >> 1) != ticket) {
                for (u32 z = 0; z < kRxPostRearmBytes; z++) out[z] = 0;
                continue;
            }
            const Word *s = (const Word *)src;
            Word *d = (Word *)out;
            for (u32 w2 = 0; w2 < kRxPostRearmBytes / 8u; w2++)
                d[w2] = __atomic_load_n(s + w2, __ATOMIC_RELAXED);
            if (__atomic_load_n((const Word *)src + kRxPostRearmSeqWord,
                                __ATOMIC_ACQUIRE) != w) {
                for (u32 z = 0; z < kRxPostRearmBytes; z++) out[z] = 0;
            }
        }
        off += n * kRxPostRearmBytes;
        if (publishedOut) *publishedOut = n;
    }

    return off;
}

}  /* namespace rxpost */

/* The rearm ring reuses obslog's ticket/loss protocol, which hard-codes the
 * three header offsets. If these ever disagree the protocol would read and
 * write the wrong words, silently. Pin them. */
static_assert(__builtin_offsetof(rxpost::Hdr, head) == 16,
              "obslog's ticket protocol expects `head` at offset 16");
static_assert(__builtin_offsetof(rxpost::Hdr, wrapped) == 20,
              "obslog's wrap accounting expects `wrapped` at offset 20");
static_assert(__builtin_offsetof(rxpost::Hdr, dropped) == 24,
              "obslog's loss accounting expects `dropped` at offset 24");
static_assert(sizeof(rxpost::SlotRec) == 32, "slot record must be 4 words");
static_assert(sizeof(rxpost::RearmRec) == 48, "rearm record must be 6 words");
static_assert((kRxPostRearmBytes % 8u) == 0,
              "rearm records must be a whole number of 8-byte words");
static_assert((__builtin_offsetof(rxpost::RearmRec, seq) % 8u) == 0,
              "the seq field must sit on an 8-byte boundary");
static_assert(sizeof(rxpost::Hdr) == 160, "header layout is part of the wire");

#endif /* RTL812xRxPost_hpp */
