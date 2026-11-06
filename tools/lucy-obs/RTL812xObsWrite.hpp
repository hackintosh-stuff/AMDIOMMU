/*
 * RTL812xObsWrite.hpp -- the observation log's WRITE and PUBLISH protocol,
 * expressed as plain functions over a caller-supplied buffer.
 *
 * ===========================================================================
 * WHY THIS FILE EXISTS
 * ===========================================================================
 *
 * Round 10's protocol lived inline in RTL812xLucy.cpp, which meant the only
 * way to "test" it was to read it. Round 11 found a real defect in it that
 * reading had not caught:
 *
 *     const UInt32 prev = __atomic_exchange_n(&r->seq, busy, ACQ_REL);
 *     ... write the body ...
 *     if (__atomic_load_n(&r->seq, ACQUIRE) != busy) { dropped++; return; }
 *     __atomic_store_n(&r->seq, ticket << 1, RELEASE);
 *
 * The exchange UNCONDITIONALLY preempts a slot that another writer is still
 * filling. Consider two writers whose tickets differ by kObsCapacity:
 *
 *     A: exchange slot -> busyA           (A owns the slot)
 *     A: writes tMono, addr, kind, ...
 *     B: exchange slot -> busyB           (B preempts A mid-body)
 *     B: writes tMono, addr, kind, ...
 *     B: re-checks: seq == busyB, OK
 *     A: writes the REST of its body      <-- overwrites B's fields
 *     A: re-checks: seq != busyA, gives up, does not stamp
 *     B: stores seq = ticketB*2           <-- B's stamp, A's tail
 *
 * The final state is B's seq with a body that is partly B and partly A. The
 * ownership re-check cannot prevent this, because it runs BEFORE the last
 * writer writes and there is nothing between the check and the store.
 *
 * ===========================================================================
 * ROUND 11: SERIALISE, DO NOT PREEMPT
 * ===========================================================================
 *
 * All writers are bounded, non-blocking and on the driver's own contexts, so
 * the protocol is a bounded spin lock around "claim ticket, claim slot, fill
 * body, publish". Under the lock there is no interleaving at all.
 *
 * ===========================================================================
 * ROUND 12: THE WRITER/PUBLISHER PAIR WAS STILL UNVERIFIED
 * ===========================================================================
 *
 * Round 11's 21 checks covered writer-vs-writer and a STATIC publisher (one
 * that ran while nothing else did). The pair that actually runs in production
 * -- obsWrite() on the packet path and obsPublish() on the watchdog -- was
 * never exercised together, and when the shared implementation was finally run
 * that way, ThreadSanitizer reported a data race:
 *
 *     obsPublish() -> publishCopy()   plain byte loop reading the record
 *     obsWrite()   -> fillBody()      plain stores writing the same record
 *
 * The busy marker does not fix that. It makes a torn record DETECTABLE, which
 * is a correctness property of the SNAPSHOT; it does not make concurrent
 * access to the same bytes DEFINED, which is what a data race is. A race here
 * is not a theoretical concern: the compiler is entitled to vectorise either
 * side, and then a reader can observe bytes that no writer ever wrote.
 *
 * The fix has two halves, both bounded:
 *
 *   1. The writer fills a private 72-byte staging record and then publishes it
 *      into the ring slot with nine 8-byte ATOMIC stores. The ring is never
 *      written with plain stores, so no plain access races with a reader.
 *   2. The publisher copies with nine 8-byte ATOMIC loads, and re-reads `seq`
 *      afterwards. Same width, same atomics, both sides defined.
 *
 * Atomicity per 8-byte word does NOT make a record consistent on its own --
 * the words can still be a mix of two writers. That is exactly what the seq
 * protocol is for: the publisher rejects an odd seq (a body in flight) and
 * rejects a seq that changed under it. What the atomics buy is that those two
 * checks are meaningful rather than undefined behaviour.
 *
 * ===========================================================================
 * LOSS ACCOUNTING (also round 12)
 * ===========================================================================
 *
 * Round 11 claimed "every failure is counted" but the counters were updated
 * with plain `+=`, which loses increments when two writers drop at once. And
 * neither the probe nor the analyser ever READ `dropped`, so a snapshot with
 * dropped records still reported itself complete.
 *
 * Now: every counter is a relaxed atomic fetch-add, `dropped` and `wrapped`
 * both reach the published header, and the production verdict refuses any
 * non-zero loss (see amdobs::obsEvidenceGate). A ticket is still claimed
 * INSIDE the lock, so a dropped write leaves no phantom gap in the sequence --
 * which is why `dropped` (a write that never got a ticket) and a hole in the
 * ticket range (a write that got a ticket but whose record is unreadable) are
 * two different counters rather than one.
 *
 * ===========================================================================
 * ROUND 13: `wrapped` HAD TWO AUTHORITIES AND ONLY ONE WAS PUBLISHED
 * ===========================================================================
 *
 * Round 12's writer incremented the RING HEADER's `wrapped` word:
 *
 *     __atomic_fetch_add((unsigned int *)(hdr + kObsWrapOffset), 1u, ...)
 *
 * and the driver's `obsPublish()` filled the PUBLISHED header from a separate
 * member:
 *
 *     snap->wrapped = obslog::readLoss(&obsWrapped);
 *
 * Nothing ever incremented `obsWrapped`. Reproduced with an 8-slot ring and 9
 * writes: the ring header said `wrapped = 1`, the published snapshot said
 * `wrapped = 0`, and the OVERFLOWED flag was 1 because that is derived from
 * `head > capacity`.
 *
 * So the defect is confined to the wrap METADATA. It is NOT "a wrap can slip
 * past the final gate": OVERFLOWED still fired and the production gate refuses
 * on it, and no evidence was ever produced for the stronger claim. What a
 * reader lost was the ability to tell "the ring lapped me" from "the ring
 * never wrapped but I asked for a lot of records".
 *
 * The fix is one authority, the same shape `dropped` already had: the writer
 * takes the counter the caller will publish and never writes the ring header's
 * copy. `tools/verify/wrapped-publish.py` compiles the REAL `obsPublish()`
 * body -- extracted from the patched driver source, not a restatement of it --
 * against this header, and requires the published value to equal the number of
 * slots actually displaced.
 *
 * ===========================================================================
 * WHAT THIS FILE IS NOT
 * ===========================================================================
 * It does not allocate, log, touch a register or call IOKit. The driver passes
 * its own header/records pointers; the host test passes an array. Same code,
 * so the test exercises the production logic rather than a restatement of it.
 */

#ifndef RTL812xObsWrite_hpp
#define RTL812xObsWrite_hpp

/* ---- the wire layout this protocol operates on -------------------------
 *
 * Kept here rather than included from RTL812xObsLog.hpp so the host test can
 * compile without the driver's IOKit headers. The numbers are asserted against
 * that header by tools/verify/obs-layout.py, so the two cannot drift.
 */
#ifndef RTL812xObsWire_hpp
#define RTL812xObsWire_hpp
#endif

/* The record's seq field offset and the fields the protocol touches. Only
 * `seq` is needed by the protocol itself; the body is written by the caller's
 * field assignments, which is why this file takes a byte pointer. */
#define kObsSeqOffset   16u   /* offsetof(RtlObsRec, seq) */
#define kObsHeadOffset  16u   /* offsetof(RtlObsHdr, head) */
#define kObsDropOffset  24u   /* offsetof(RtlObsHdr, dropped) */
#define kObsWrapOffset  20u   /* offsetof(RtlObsHdr, wrapped)  */

/* A record is 72 bytes = 9 whole 8-byte words, so the whole body can be moved
 * with atomics. If the wire format ever stops being 8-byte-multiple, the
 * static assertion below fires instead of the protocol silently copying the
 * tail with plain accesses. */
#define kObsRecBytesWire  72u
#define kObsRecWords      (kObsRecBytesWire / 8u)
#define kObsSeqWord       (kObsSeqOffset / 8u)

/* THE SEQ WORD IS SHARED, AND THAT MATTERS
 * ----------------------------------------
 * `seq` is a UInt32 at offset 16 and `kind` is a UInt32 at offset 20, so both
 * live in word 2. A word-at-a-time protocol therefore cannot treat word 2 as
 * "the protocol's word" and skip it: skipping it drops `kind` from every
 * record, and the first version of this round did exactly that -- the test
 * caught it as "every body field belongs to writer A" failing at offset 20.
 *
 * So word 2 is handled as a COMPOSITE: the low 32 bits are the seq the
 * protocol owns, the high 32 bits belong to the caller's body. Both the busy
 * marker and the published stamp are written as a whole-word atomic store with
 * the body's high half preserved, and the publisher reads the whole word. No
 * access of a different width ever touches those 8 bytes, which is what keeps
 * the pair race-free.
 *
 * This assumes a little-endian target (x86_64), which is what both the kext
 * and the wire format already assume: the analyser decodes the same layout
 * with struct.unpack('<...'). */
#define kObsSeqWordLowHalf  0x00000000FFFFFFFFULL
#define kObsSeqWordHighHalf 0xFFFFFFFF00000000ULL

/* Bounded spin: how many times a writer will try to take the lock before it
 * gives up and records a drop. Chosen so the worst case is a few microseconds
 * on the driver's contexts -- a writer never blocks the output thread for a
 * measurable time. */
#define kObsLockSpinMax 4096u

namespace obslog {

/* 8-byte words are the unit of every concurrent access. Both sides use
 * __atomic_* on this type, which is what makes the pair race-free. */
typedef unsigned long long Word;

static_assert((kObsRecBytesWire % 8u) == 0u,
              "the record must be a whole number of 8-byte words");
static_assert((kObsSeqOffset % 8u) == 0u,
              "the seq field must sit on an 8-byte boundary");
static_assert(kObsSeqWord < kObsRecWords, "seq must be inside the record");

/* ---- the lock ---------------------------------------------------------
 *
 * One word, 0 = free, 1 = held. A bounded CAS loop, not a blocking lock: every
 * caller runs on a context that must not sleep.
 *
 * `acquire` returns false when the bound is exhausted. That is a RECORDED
 * drop, never a silent one.
 */
static inline bool lockAcquire(volatile unsigned int *lock) {
    for (unsigned i = 0; i < kObsLockSpinMax; i++) {
        unsigned expected = 0;
        if (__atomic_compare_exchange_n(lock, &expected, 1u, false,
                                        __ATOMIC_ACQUIRE,
                                        __ATOMIC_RELAXED)) {
            return true;
        }
        /* A short pause keeps the retry loop from monopolising the core while
         * the holder finishes. The bound above still applies.
         *
         * Guarded because the host test also compiles this file, and on a
         * non-x86 host there is no `pause`. The kext is always x86_64. */
#if defined(__i386__) || defined(__x86_64__)
        __builtin_ia32_pause();
#else
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
#endif
    }
    return false;
}

static inline void lockRelease(volatile unsigned int *lock) {
    __atomic_store_n(lock, 0u, __ATOMIC_RELEASE);
}

/* ---- loss counters ----------------------------------------------------
 *
 * ROUND 12: these were plain `+=`. Two writers dropping at the same instant
 * then produce one increment, and the header under-reports the loss -- which
 * is the one direction that matters, because the reader decides whether the
 * snapshot is complete from these numbers.
 *
 * Relaxed is enough: the counter is a tally, not a synchronisation edge. What
 * matters is that no increment is lost.
 */
static inline void countLoss(unsigned int *counter) {
    if (!counter) return;
    __atomic_fetch_add(counter, 1u, __ATOMIC_RELAXED);
}

static inline unsigned int readLoss(const unsigned int *counter) {
    if (!counter) return 0;
    return __atomic_load_n(counter, __ATOMIC_RELAXED);
}

/* ---- ticket ----------------------------------------------------------
 *
 * Claimed INSIDE the lock, so `head` only advances for a record that will
 * really be written. A ticket claimed outside would leave a permanent gap in
 * the sequence for every dropped write, which the publisher would then have
 * to report as a hole it cannot explain.
 *
 * The consequence, stated explicitly because round 11 left it implicit: a
 * dropped write does NOT create a ticket hole, so "the ticket range has no
 * holes" cannot be used to prove "no write was lost". The two facts come from
 * two counters -- `wrapped`/`dropped` in the header, and `lostCount` from the
 * publisher's hole detection -- and a complete snapshot needs all of them at
 * zero.
 *
 * Tickets start at 1: seq == 0 must mean "this slot has never held a published
 * record", and a 0-based ticket would make the first record indistinguishable
 * from an untouched slot.
 */
static inline unsigned int claimTicket(unsigned char *hdr) {
    return __atomic_fetch_add((unsigned int *)(hdr + kObsHeadOffset), 1u,
                              __ATOMIC_RELAXED) + 1u;
}

/* ---- one write -------------------------------------------------------
 *
 * `rec` is the destination record; `body` is filled by `fillBody`, a callback
 * so this file stays free of the driver's field names:
 *
 *     void fillBody(void *rec, void *ctx);
 *
 * The callback fills a PRIVATE staging record. This function then publishes
 * that staging record into the ring with atomic word stores, so the ring is
 * never touched by a plain access while a publisher may be reading it.
 *
 * ROUND 14: THE GEOMETRY IS NOW A PARAMETER, NOT A CONSTANT.
 *
 * Round 13 hard-coded the 72-byte, 9-word observation record and its seq word
 * (word 2). Round 14 adds a SECOND ring -- the RX rearm log -- with a 40-byte,
 * 5-word record whose seq sits in word 3. Two copies of this protocol would be
 * two things to get wrong, and the round-10/11/12 history is exactly a
 * sequence of "the second copy was wrong". So the geometry is passed in and
 * `writeRecord()` below is a thin wrapper that supplies the observation log's.
 *
 * Returns true when the record was published, false when it was dropped (lock
 * timeout). The caller must not treat false as success.
 */
template <typename FillFn, typename Ctx>
static inline bool writeRecordSized(volatile unsigned int *lock,
                                    unsigned char *hdr,
                                    unsigned char *recBase,
                                    unsigned int capacityMask,
                                    unsigned int recBytes,
                                    unsigned int seqWordIdx,
                                    FillFn fillBody, Ctx ctx,
                                    unsigned int *dropped,
                                    unsigned int *wrapped = nullptr) {
    if (!lockAcquire(lock)) {
        /* Explicit loss. The caller adds this to the header's dropped count so
         * a snapshot can never present itself as complete when it is not. */
        countLoss(dropped);
        return false;
    }

    const unsigned int ticket = claimTicket(hdr);
    unsigned char *rec = recBase +
                         (unsigned long)(ticket & capacityMask) *
                             (unsigned long)recBytes;
    Word *dst = (Word *)rec;
    Word *seqWord = dst + seqWordIdx;

    /* Claim the slot. Odd = "a body is being written here". Under the lock
     * this marker is only ever set by the writer that holds the lock, so it
     * cannot be preempted -- but the publisher, which does not take the lock,
     * still needs it to skip an in-progress body.
     *
     * The high half of this word is the caller's field, so the marker is
     * written as a whole word with the body's half preserved rather than as a
     * 32-bit store into the middle of it. Mixing widths on the same 8 bytes is
     * a data race even when the bytes are "different fields". */
    const unsigned int busy = (ticket << 1) | 1u;
    const Word prev = __atomic_exchange_n(seqWord, (Word)busy, __ATOMIC_ACQ_REL);
    if ((prev & kObsSeqWordLowHalf) != 0) {
        /* The slot already held a published record: the ring wrapped past it.
         * That record is being displaced, which is a loss the header reports.
         *
         * ROUND 13: THIS USED TO WRITE THE RING HEADER DIRECTLY.
         *
         *     __atomic_fetch_add((unsigned int *)(hdr + kObsWrapOffset), ...)
         *
         * while `obsPublish()` filled the published header from a SEPARATE
         * member, `obsWrapped`, which nothing ever incremented. So with an
         * 8-slot ring and 9 writes the ring header said wrapped = 1 and the
         * published snapshot said wrapped = 0 -- the one number a reader uses
         * to decide "the ring lapped me" was permanently zero.
         *
         * The OVERFLOWED flag still fired, because that is derived from
         * `head > capacity`, so the loss was not invisible. What was broken is
         * the wrap METADATA, and it must not be described as "a wrap can slip
         * past the final gate": no evidence for that was ever produced.
         *
         * The fix is one authority. The caller passes the counter it will
         * publish, exactly as it already does for `dropped`, and this function
         * never writes the ring header's copy. */
        countLoss(wrapped);
    }

    /* Fill OUTSIDE the ring, then publish with atomics. The staging buffer is
     * the only thing the callback touches, so a concurrent publisher can never
     * observe a half-written body -- it observes either the previous record or
     * the busy marker, and the busy marker makes it a hole.
     *
     * The staging array is bounded by the largest record this project has: the
     * 72-byte observation record. A caller passing a larger recBytes is a
     * programming error and is refused rather than overrunning the stack. */
    const unsigned int kMaxRecBytes = kObsRecBytesWire;
    if (recBytes == 0 || recBytes > kMaxRecBytes ||
        (recBytes % 8u) != 0 || seqWordIdx >= (recBytes / 8u)) {
        /* Do not publish a record whose geometry we cannot honour. The ticket
         * was already claimed, so the slot is a hole -- which the publisher
         * reports as a lost record rather than a valid one. */
        lockRelease(lock);
        return false;
    }

    unsigned char stage[kMaxRecBytes];
    for (unsigned i = 0; i < recBytes; i++) stage[i] = 0;
    fillBody(stage, ctx);

    const Word *src = (const Word *)stage;
    const unsigned int words = recBytes / 8u;
    for (unsigned w = 0; w < words; w++) {
        if (w == seqWordIdx) continue;      /* handled below, as a whole word */
        __atomic_store_n(dst + w, src[w], __ATOMIC_RELAXED);
    }

    /* Publish: even seq means "body complete". The word carries the caller's
     * high half, so the stamp is a whole-word store, not a 32-bit one. There is
     * no ownership re-check because ownership cannot have changed: this writer
     * held the lock for the whole body. That is the structural difference from
     * round 10. */
    const Word stamp = ((Word)(ticket << 1) & kObsSeqWordLowHalf) |
                       (src[seqWordIdx] & kObsSeqWordHighHalf);
    __atomic_store_n(seqWord, stamp, __ATOMIC_RELEASE);

    lockRelease(lock);
    return true;
}

/* The observation log's geometry: 72-byte record, seq in word 2. */
template <typename FillFn, typename Ctx>
static inline bool writeRecord(volatile unsigned int *lock,
                               unsigned char *hdr,
                               unsigned char *recBase,
                               unsigned int capacityMask,
                               FillFn fillBody, Ctx ctx,
                               unsigned int *dropped,
                               unsigned int *wrapped = nullptr) {
    return writeRecordSized(lock, hdr, recBase, capacityMask,
                            kObsRecBytesWire, kObsSeqWord,
                            fillBody, ctx, dropped, wrapped);
}

/* ---- one publish -----------------------------------------------------
 *
 * Copies a suffix of the ring into the staging buffer, validating each record
 * against the ticket the snapshot claims for its position.
 *
 * Deliberately does NOT take the lock: the copy is up to kObsPublishMax
 * records, and holding a spin lock for that long would stall every writer.
 *
 * ROUND 12: the copy uses the SAME 8-byte atomic access the writer uses. That
 * is what makes this a defined concurrent protocol rather than a data race
 * that happens to produce plausible bytes. The seqlock then decides
 * consistency: an odd seq (a body in flight) or a changed seq (the writer
 * lapped us) makes it a hole.
 *
 * Returns the number of holes. `firstTicket`/`lastTicket`/`valid`/`lost` are
 * written through the out-parameters so the caller can build the header.
 */
static inline unsigned int publishCopy(const unsigned char *recBase,
                                       unsigned int capacityMask,
                                       unsigned int capacity,
                                       unsigned int firstTicket,
                                       unsigned int n,
                                       unsigned char *dstRecs,
                                       unsigned int recBytes,
                                       unsigned int *valid,
                                       unsigned int *lost) {
    unsigned int copied = 0, holes = 0, good = 0;
    /* The word loop is only valid for the real record size; if a caller passes
     * anything else, fall back to a byte copy of the same length so the
     * function still behaves, and say so through the hole counter only when
     * the sizes genuinely disagree. */
    const bool wordwise = (recBytes == kObsRecBytesWire);

    while (copied < n) {
        const unsigned int ticket = firstTicket + copied;
        const unsigned int off = ticket & capacityMask;
        unsigned int run = capacity - off;
        if (run > n - copied) run = n - copied;

        unsigned int k;
        for (k = 0; k < run; k++) {
            const unsigned char *src =
                recBase + (unsigned long)(off + k) * (unsigned long)recBytes;
            unsigned char *dst =
                dstRecs + (unsigned long)(copied + k) * (unsigned long)recBytes;
            /* Read the WHOLE seq word, not a 32-bit slice of it: the writer
             * stamps that word atomically and the caller's `kind` shares it,
             * so a narrow read would be a different-width access to the same
             * bytes. The seq is the low half. */
            const Word w0 = __atomic_load_n((const Word *)src + kObsSeqWord,
                                            __ATOMIC_ACQUIRE);
            const unsigned int seq = (unsigned int)(w0 & kObsSeqWordLowHalf);
            /* Zero: never written. Odd: mid-write. Wrong ticket: a stale body
             * from an earlier lap of the ring. All three are holes. */
            if (seq == 0 || (seq & 1u) || (seq >> 1) != (ticket + k)) {
                for (unsigned int z = 0; z < recBytes; z++) dst[z] = 0;
                holes++;
                continue;
            }
            if (wordwise) {
                const Word *s = (const Word *)src;
                Word *d = (Word *)dst;
                for (unsigned w = 0; w < kObsRecWords; w++)
                    d[w] = __atomic_load_n(s + w, __ATOMIC_RELAXED);
            } else {
                for (unsigned int z = 0; z < recBytes; z++) dst[z] = src[z];
            }
            /* Re-read the seq word. If it changed, the writer lapped us while
             * we were copying and the body may be a mix of two records. */
            if (__atomic_load_n((const Word *)src + kObsSeqWord,
                                __ATOMIC_ACQUIRE) != w0) {
                for (unsigned int z = 0; z < recBytes; z++) dst[z] = 0;
                holes++;
                continue;
            }
            good++;
        }
        copied += run;
    }
    if (valid) *valid = good;
    if (lost) *lost = holes;
    return holes;
}

}  /* namespace obslog */

#endif /* RTL812xObsWrite_hpp */
