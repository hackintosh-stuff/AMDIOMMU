// rxpost-test.cpp -- the RX posted-buffer SET: baseline capture, rearm log and
// the union that is handed to the page-table walk.
//
// WHAT THIS TEST IS FOR
// ---------------------
// Round 13's RX evidence was the buffers that happened to carry four echoes.
// Round 14 replaces that with a set:
//
//     S = { (addr, capacity) posted at the baseline }
//       ∪ { (addr, capacity) from every rearm after the watermark }
//
// and then walks EVERY range in S. Three things can silently break that, and
// this test is written against those three specifically:
//
//   1. THE REARM RECORD CARRIES THE WRONG CAPACITY.
//      The tempting shortcut is to reuse the observation log's rx-done record,
//      whose `len` is the received packet size (74 bytes for the controlled
//      echo). Recording 74 instead of 4096 would make the walk check a 74-byte
//      window into a 4096-byte buffer and pass while the rest was unmapped.
//      So the test drives the REAL fill function and asserts the capacity is
//      the posted length word, not anything to do with a packet.
//
//   2. THE REARM RECORD CARRIES A STALE ADDRESS.
//      The RX path replaces the buffer before re-programming the descriptor,
//      so the FINAL address is the one in `addr` at the hand-back site. A
//      record that captured the address at the top of the loop would name the
//      buffer being RETIRED, and the walk would prove the wrong range.
//
//   3. THE UNION SILENTLY DROPS RANGES.
//      If the rearm ring lapped past the baseline watermark, or a writer
//      dropped, the union is a subset. A subset that is fully covered is a
//      false pass, so every such condition must make `complete` false with a
//      stable reason.
//
// The test also compiles amd_iommu_rxset_core.hpp, which is the SAME join the
// probe runs, so "the set is complete" is a property of one function.
//
// WHY THE INCLUDES ARE BARE NAMES
// -------------------------------
// tools/test.sh passes -I tools/lucy-obs, and the same test is compiled against
// the OLD protocol header by tools/r14/verify-rearm-protocol.py. A relative
// path would defeat that substitution and every version would "pass".
#include "RTL812xRxPost.hpp"
#include "RTL812xObsWrite.hpp"
#include "amd_iommu_rxset_core.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

static int gPass = 0, gFail = 0;

static void check(bool cond, const char *what) {
    if (cond) {
        gPass++;
    } else {
        gFail++;
        std::printf("FAIL: %s\n", what);
    }
}

static void checkU64(unsigned long long got, unsigned long long want,
                     const char *what) {
    if (got == want) {
        gPass++;
    } else {
        gFail++;
        std::printf("FAIL: %s (got 0x%llx, want 0x%llx)\n", what, got, want);
    }
}

static void checkStr(const char *got, const char *want, const char *what) {
    const char *g = got ? got : "(null)";
    const char *w = want ? want : "(null)";
    if (std::strcmp(g, w) == 0) {
        gPass++;
    } else {
        gFail++;
        std::printf("FAIL: %s (got %s, want %s)\n", what, g, w);
    }
}

// ---------------------------------------------------------------------------
// A rearm ring fixture: the real header layout, the real record size, the real
// write protocol, driven through the real fill function.
// ---------------------------------------------------------------------------
static const unsigned kRing = 8;                    // tiny ring, easy to lap
static const unsigned kRxBufSize = 4096;

struct Ring {
    std::vector<unsigned char> hdr;     // rxpost::Hdr sized
    std::vector<unsigned char> recs;    // cap * 48
    // The slot table is part of every publication, so the fixture carries one
    // even when a test only cares about the rearm log. Passing a null pointer
    // here would be a defect in the CALLER, not something publishCopy should
    // paper over -- the driver always has one.
    std::vector<unsigned char> slots;
    volatile unsigned int lock;
    unsigned int wrapped;
    unsigned int dropped;
    unsigned cap;
    unsigned mask;
    // publishCopy()'s own return value for the last publish(), so the geometry
    // test can assert it rather than only the caller's own arithmetic.
    unsigned lastCopyBytes;

    explicit Ring(unsigned ringCap = kRing)
        : hdr(sizeof(rxpost::Hdr), 0),
          recs(ringCap * kRxPostRearmBytes, 0),
          slots(kRxPostSlots * kRxPostSlotBytes, 0),
          lock(0), wrapped(0), dropped(0),
          cap(ringCap), mask(ringCap - 1), lastCopyBytes(0) {
        rxpost::Hdr *h = (rxpost::Hdr *)&hdr[0];
        h->magic = kRxPostMagic;
        h->version = kRxPostVersion;
        h->recSizeSlot = kRxPostSlotBytes;
        h->recSizeRearm = kRxPostRearmBytes;
        h->slotCapacity = kRxPostSlots;
        h->rearmCapacity = ringCap;
        h->rxBufferSize = kRxBufSize;
        h->ringGen = 1;
    }

    unsigned char *at(unsigned ticket) {
        return &recs[(ticket & mask) * kRxPostRearmBytes];
    }

    unsigned head() {
        // ATOMIC, because the writer claims tickets with an atomic fetch-add on
        // this exact word. A plain read here would be a different-width access
        // to the same bytes -- the data race TSan reported the first time this
        // test was run, and the same class of defect round 12 removed from the
        // observation log.
        return __atomic_load_n((const unsigned int *)&hdr[16],
                               __ATOMIC_ACQUIRE);
    }

    // Write one rearm through the REAL protocol and the REAL fill function.
    //
    // `oldAddr` is the buffer this rearm retires. It is a parameter, not a
    // default, because a rearm that does not say what it replaced leaves that
    // buffer in neither half of the union.
    bool rearm(unsigned slot, unsigned long long addr,
               unsigned long long blenRaw, unsigned long long oldAddr = 0,
               unsigned extra = 0) {
        struct Ctx {
            unsigned slot;
            unsigned long long addr;
            unsigned long long oldAddr;
            unsigned long long blenRaw;
            unsigned extra;
        } ctx = {slot, addr, oldAddr, blenRaw, extra};
        return obslog::writeRecordSized(
            &lock, &hdr[0], &recs[0], mask,
            kRxPostRearmBytes, kRxPostRearmSeqWord,
            [](unsigned char *rec, const Ctx &c) {
                rxpost::fillRearmRec(rec, c.slot, c.addr, c.oldAddr,
                                     c.blenRaw,
                                     (unsigned long long)0x1234 + c.slot,
                                     c.extra);
            },
            ctx, &dropped, &wrapped);
    }

    // Publish into a full blob: header, then the slot table, then the rearm
    // records in ticket order -- exactly the driver's layout.
    //
    // THE HEADER IS FILLED FIRST, by `fillHeader()`, because that is what the
    // driver does: publishCopy() copies RECORDS and must not touch the header.
    // Filling it here is what makes "the header survived the copy" a meaningful
    // assertion rather than a tautology about zeroes.
    unsigned publish(std::vector<unsigned char> &out, unsigned want) {
        out.assign(kRxPostHdrBytes +
                       kRxPostSlots * kRxPostSlotBytes +
                       kRxPostPublishRearmMax * kRxPostRearmBytes, 0);
        fillHeader(&out[0]);
        unsigned published = 0;
        lastCopyBytes = rxpost::publishCopy(&slots[0], &recs[0], head(), want,
                                            cap, mask, &out[0], &published);
        const unsigned len = kRxPostHdrBytes +
                             kRxPostSlots * kRxPostSlotBytes +
                             published * kRxPostRearmBytes;
        out.resize(len);
        return published;
    }

    // What the driver's rxpostPublish() puts in the header before copying.
    void fillHeader(unsigned char *dst) {
        rxpost::Hdr h;
        std::memcpy(&h, &hdr[0], kRxPostHdrBytes);
        h.head = head();
        h.rearmPublished = 0;      // the caller sets this from `published`
        std::memcpy(dst, &h, kRxPostHdrBytes);
    }

    // Where rearm record `i` lives inside a published blob.
    static const rxpost::RearmRec *rearmIn(const std::vector<unsigned char> &b,
                                           unsigned i) {
        return (const rxpost::RearmRec *)
            (&b[kRxPostHdrBytes + kRxPostSlots * kRxPostSlotBytes +
                i * kRxPostRearmBytes]);
    }
};

// ---------------------------------------------------------------------------
// 1. the fill functions: what a record MEANS
// ---------------------------------------------------------------------------
static void testFillSlotRec() {
    std::printf("-- fillSlotRec --\n");

    unsigned char buf[kRxPostSlotBytes];

    // Owned descriptor: word 0 is the POSTED LENGTH, so capacity is that
    // number with DescOwn/RingEnd masked off. This is the case that matters
    // for the baseline: every descriptor the NIC still owns.
    {
        const unsigned long long blen =
            (unsigned long long)(kRxBufSize | kRxPostDescOwn);
        std::memset(buf, 0, sizeof(buf));
        rxpost::fillSlotRec(buf, 7, 0x1f420e000ull, blen, 3, kRxBufSize, 0);
        const rxpost::SlotRec *r = (const rxpost::SlotRec *)buf;
        checkU64(r->addr, 0x1f420e000ull, "owned slot keeps the address");
        checkU64(r->capacity, kRxBufSize, "owned slot capacity = posted length");
        checkU64(r->slot, 7, "owned slot records its index");
        checkU64(r->gen, 3, "owned slot records the ring generation");
        check((r->flags & kRxPostSlotOwned) != 0, "owned flag set");
        check((r->flags & kRxPostSlotCapFromDesc) != 0,
              "capacity came from the descriptor");
        check((r->flags & kRxPostSlotCapFromConst) == 0,
              "owned slot does NOT fall back to the constant");
        check((r->flags & kRxPostSlotCapMismatch) == 0,
              "owned slot capacity agrees with kRxBufSize");
        check((r->flags & kRxPostSlotAddrZero) == 0, "non-zero address");
    }

    // The last descriptor carries RingEnd in the same word. It must not leak
    // into the capacity: a capacity of 0x40001000 would make the walk check
    // 1 GiB of page tables for a 4 KiB buffer.
    {
        const unsigned long long blen =
            (unsigned long long)(kRxBufSize | kRxPostDescOwn | kRxPostRingEnd);
        std::memset(buf, 0, sizeof(buf));
        rxpost::fillSlotRec(buf, 1023, 0x200000000ull, blen, 1, kRxBufSize, 0);
        const rxpost::SlotRec *r = (const rxpost::SlotRec *)buf;
        checkU64(r->capacity, kRxBufSize, "RingEnd does not enter the capacity");
        check((r->flags & kRxPostSlotRingEnd) != 0, "RingEnd recorded as a flag");
    }

    // Not owned: word 0 is a STATUS word whose length field is the RECEIVED
    // length. Using it would be the round-9/10 defect in a new place.
    {
        const unsigned long long status = 74ull;   // a 74-byte echo, no DescOwn
        std::memset(buf, 0, sizeof(buf));
        rxpost::fillSlotRec(buf, 11, 0x1f421f000ull, status, 2, kRxBufSize,
                            0);
        const rxpost::SlotRec *r = (const rxpost::SlotRec *)buf;
        checkU64(r->capacity, kRxBufSize,
                 "unowned slot capacity is the POST value, not the received len");
        checkU64(r->capacity != 74, 1,
                 "the received 74 bytes did not become the capacity");
        check((r->flags & kRxPostSlotCapFromConst) != 0,
              "unowned slot says the capacity came from the constant");
        check((r->flags & kRxPostSlotOwned) == 0, "unowned flag not set");
    }

    // Address 0 is recorded, not dropped: the caller decides what it means.
    {
        std::memset(buf, 0, sizeof(buf));
        rxpost::fillSlotRec(buf, 0, 0, (unsigned long long)kRxPostDescOwn,
                            1, kRxBufSize, 0);
        const rxpost::SlotRec *r = (const rxpost::SlotRec *)buf;
        check((r->flags & kRxPostSlotAddrZero) != 0,
              "a zero address is FLAGGED, not silently omitted");
    }

    // A descriptor whose capacity disagrees with the constant is flagged.
    {
        const unsigned long long blen =
            (unsigned long long)(2048 | kRxPostDescOwn);
        std::memset(buf, 0, sizeof(buf));
        rxpost::fillSlotRec(buf, 5, 0x1000ull, blen, 1, kRxBufSize, 0);
        const rxpost::SlotRec *r = (const rxpost::SlotRec *)buf;
        checkU64(r->capacity, 2048, "the descriptor's own capacity is kept");
        check((r->flags & kRxPostSlotCapMismatch) != 0,
              "a capacity that differs from kRxBufSize is flagged");
    }
}

static void testFillRearmRec() {
    std::printf("-- fillRearmRec --\n");

    unsigned char buf[kRxPostRearmBytes];

    // The central assertion of the round: a rearm record's capacity is the
    // POSTED length from the FINAL descriptor word, and it has nothing to do
    // with a received packet size.
    {
        const unsigned long long blen =
            (unsigned long long)(kRxBufSize | kRxPostDescOwn);
        std::memset(buf, 0, sizeof(buf));
        rxpost::fillRearmRec(buf, 42, 0x1f4300000ull, 0x1f42f0000ull, blen, 999, 0);
        const rxpost::RearmRec *r = (const rxpost::RearmRec *)buf;
        checkU64(r->addr, 0x1f4300000ull, "rearm carries the FINAL address");
        checkU64(r->oldAddr, 0x1f42f0000ull,
                 "rearm carries the address it RETIRED");
        checkU64(r->capacity, kRxBufSize,
                 "rearm carries the FINAL posted capacity");
        checkU64(r->slot, 42, "rearm carries the slot");
        checkU64(r->tMono, 999, "rearm carries the timestamp it was given");
        check((r->flags & kRxPostRearmOwned) != 0, "owned flag from blenRaw");
        checkU64(r->seq, 0,
                 "fillRearmRec leaves seq alone (the protocol owns it)");
    }

    // A second rearm of the same slot with a DIFFERENT buffer must record the
    // new pair, not the old one. This is the "stale address" failure.
    {
        std::memset(buf, 0, sizeof(buf));
        rxpost::fillRearmRec(buf, 42, 0x1f4400000ull, 0x1f4300000ull,
                             (unsigned long long)(kRxBufSize | kRxPostDescOwn),
                             1000, 0);
        const rxpost::RearmRec *r = (const rxpost::RearmRec *)buf;
        checkU64(r->addr, 0x1f4400000ull, "second rearm records the NEW address");
        checkU64(r->oldAddr, 0x1f4300000ull,
                 "second rearm records what it RETIRED (the first buffer)");
        check(r->addr != r->oldAddr, "the two are distinct");
    }

    // RingEnd must not enter the capacity here either.
    {
        std::memset(buf, 0, sizeof(buf));
        rxpost::fillRearmRec(buf, 1023, 0x2000ull, 0x1000ull,
                             (unsigned long long)(kRxBufSize | kRxPostDescOwn |
                                                  kRxPostRingEnd),
                             1, 0);
        const rxpost::RearmRec *r = (const rxpost::RearmRec *)buf;
        checkU64(r->capacity, kRxBufSize, "RingEnd does not enter the capacity");
        check((r->flags & kRxPostRearmRingEnd) != 0, "RingEnd recorded");
    }
}

// ---------------------------------------------------------------------------
// 2. the rearm log: ticket order, holes, and the watermark
// ---------------------------------------------------------------------------
static void testRearmRing() {
    std::printf("-- rearm ring --\n");

    Ring ring;
    std::vector<unsigned char> blob;

    // Nothing written: the publication carries no records and says so.
    {
        unsigned published = ring.publish(blob, 0);
        checkU64(published, 0, "an empty ring publishes nothing");
        checkU64(ring.head(), 0, "an empty ring has head 0");
    }

    // Three rearms, all required, published in ticket order.
    ring.rearm(1, 0x1f0000000ull,
               (unsigned long long)(kRxBufSize | kRxPostDescOwn));
    ring.rearm(2, 0x1f0010000ull,
               (unsigned long long)(kRxBufSize | kRxPostDescOwn));
    ring.rearm(3, 0x1f0020000ull,
               (unsigned long long)(kRxBufSize | kRxPostDescOwn));
    {
        unsigned published = ring.publish(blob, 3);
        checkU64(published, 3, "three rearms publish three records");
        const rxpost::RearmRec *r0 = Ring::rearmIn(blob, 0);
        checkU64(r0[0].addr, 0x1f0000000ull, "record 0 is the oldest rearm");
        checkU64(r0[1].addr, 0x1f0010000ull, "record 1 follows");
        checkU64(r0[2].addr, 0x1f0020000ull, "record 2 follows");
        checkU64(r0[0].seq, 2, "ticket 1 publishes seq 2 (even, not busy)");
        checkU64(r0[2].seq, 6, "ticket 3 publishes seq 6");
    }

    // The watermark: only records AFTER it are required. Requesting 0 gives a
    // zero-length body even though the ring holds records -- that is what a
    // baseline taken after those rearms needs.
    {
        unsigned published = ring.publish(blob, 0);
        checkU64(published, 0,
                 "a watermark at head requires no rearm records");
    }

    // Lap the ring. wrapped must be reported by the CALLER's counter (the same
    // one-authority rule round 13 established for the observation log).
    {
        Ring small;
        for (unsigned i = 0; i < kRing + 1; i++) {
            small.rearm(i, 0x200000000ull + (unsigned long long)i * 0x10000ull,
                        (unsigned long long)(kRxBufSize | kRxPostDescOwn));
        }
        checkU64(small.head(), kRing + 1, "head counts every ticket");
        checkU64(small.wrapped, 1,
                 "the ring reports exactly one displaced record");
        checkU64(small.dropped, 0, "no drops were recorded");
        // The publication must be able to say the ring lapped: firstSeq must
        // be > 1, and the join must refuse.
        checkU64(rxpost::firstSeqFor(small.head(), small.cap), 2,
                 "firstSeqFor reports the oldest surviving ticket");
    }
}

// ---------------------------------------------------------------------------
// 3. the union: what the walk is given
// ---------------------------------------------------------------------------
static void testBuildSet() {
    std::printf("-- buildSet --\n");

    amdrx::Range out[64];
    amdrx::SetResult res;

    // Two baseline slots, one rearm of a third buffer.
    amdrx::SlotRec slots[3];
    std::memset(slots, 0, sizeof(slots));
    slots[0].addr = 0x1f0000000ull; slots[0].capacity = 4096; slots[0].slot = 0;
    slots[1].addr = 0x1f0010000ull; slots[1].capacity = 4096; slots[1].slot = 1;
    slots[2].addr = 0;              slots[2].capacity = 4096; slots[2].slot = 2;

    amdrx::RearmRec rearms[3];
    std::memset(rearms, 0, sizeof(rearms));
    // seq is ticket*2. Ticket 1 is AT the watermark: already in the baseline.
    rearms[0].seq = 2; rearms[0].addr = 0x1f0000000ull; rearms[0].capacity = 4096;
    // Ticket 2 is after it: a NEW buffer, and it RETIRES 0x1f00f0000.
    rearms[1].seq = 4; rearms[1].addr = 0x1f0020000ull;
    rearms[1].oldAddr = 0x1f00f0000ull; rearms[1].capacity = 4096;
    // Ticket 3 re-installs a baseline buffer: the source becomes BOTH.
    rearms[2].seq = 6; rearms[2].addr = 0x1f0010000ull;
    rearms[2].oldAddr = 0x1f0020000ull; rearms[2].capacity = 4096;

    amdrx::buildSet(slots, 3, rearms, 3,
                    /*watermark*/ 1, /*head*/ 3, /*rearmFirstSeq*/ 1,
                    out, 64, res);
    check(res.complete, "a clean union is complete");
    // 2 baseline + {0x1f0020000 (installed by rearm 2), 0x1f00f0000 (retired by
    // rearm 2)} = 4 distinct.
    checkU64(res.ranges, 4, "four distinct ranges");
    checkU64(res.fromBaseline, 2, "two came from the baseline");
    checkU64(res.fromRearm, 2,
             "two came only from the rearm log: the installed and the retired");
    // TWO ranges appear in both halves, for two different reasons, and the
    // count is asserted exactly because either one alone is a weaker claim
    // than the design makes:
    //   * 0x1f0000000 is in the baseline AND re-installed by rearm 1, which is
    //     AT the watermark (a rearm that completed before the scan);
    //   * 0x1f0010000 is in the baseline AND re-installed by rearm 3.
    checkU64(res.fromBoth, 2,
             "two ranges appear in both halves (baseline re-installations)");
    // TWO zero addresses are skipped, from two different places:
    //   * the baseline slot that posts no address;
    //   * rearm 1's `oldAddr`, which is 0 because it is the first rearm of its
    //     slot and therefore has nothing to retire.
    checkU64(res.skippedZero, 2, "both zero addresses were skipped");
    checkU64(res.rearmUsed, 2, "two rearms were past the watermark");
    checkU64(res.rearmRequired, 2, "two rearms were required past the watermark");

    // The RETIRED buffer must be in the set: this is the whole reason the
    // record carries oldAddr. Without it a rearm that lands during the
    // baseline scan leaves the replaced buffer in neither half.
    {
        bool sawRetired = false;
        for (unsigned i = 0; i < res.ranges; i++)
            if (out[i].addr == 0x1f00f0000ull) sawRetired = true;
        check(sawRetired, "the RETIRED buffer is in the set");
    }

    // The zero-address slot must NOT be in the output: walking address 0 is
    // meaningless and its presence would look like a covered range.
    bool sawZero = false;
    for (unsigned i = 0; i < res.ranges; i++)
        if (out[i].addr == 0) sawZero = true;
    check(!sawZero, "no zero address reached the walk");

    // ---- the gap: the ring lapped past the watermark ----
    {
        amdrx::buildSet(slots, 3, rearms, 3,
                        /*watermark*/ 1, /*head*/ 40, /*rearmFirstSeq*/ 30,
                        out, 64, res);
        check(!res.complete, "a lapped ring is not complete");
        checkStr(res.why, "rearm-ring-lapped-past-baseline",
                 "the reason names the lap");
    }

    // ---- the gap: the publication is shorter than required ----
    //
    // `nRearms` is what the blob contains; `rearmRequired` is what the
    // watermark says must be there. Publishing a prefix is the failure.
    {
        amdrx::RearmRec onlyOne[1];
        std::memset(onlyOne, 0, sizeof(onlyOne));
        onlyOne[0].seq = 4; onlyOne[0].addr = 0x1f0020000ull;
        onlyOne[0].capacity = 4096;
        amdrx::buildSet(slots, 3, onlyOne, 1,
                        /*watermark*/ 1, /*head*/ 3, /*rearmFirstSeq*/ 1,
                        out, 64, res);
        check(!res.complete, "a truncated publication is not complete");
        checkStr(res.why, "rearm-publication-truncated",
                 "the reason names the truncation");
    }

    // ---- the gap: records are required but the ring is empty ----
    {
        amdrx::buildSet(slots, 3, rearms, 3,
                        /*watermark*/ 0, /*head*/ 3, /*rearmFirstSeq*/ 0,
                        out, 64, res);
        check(!res.complete, "required records with an empty ring is refused");
        checkStr(res.why, "rearm-ring-empty-but-records-required",
                 "the reason names the empty ring");
    }

    // ---- the budget: the array cannot hold the set ----
    {
        amdrx::Range tiny[2];
        amdrx::buildSet(slots, 3, rearms, 3,
                        /*watermark*/ 1, /*head*/ 3, /*rearmFirstSeq*/ 1,
                        tiny, 2, res);
        check(!res.complete, "a set that does not fit is not complete");
        checkStr(res.why, "range-budget-exceeded",
                 "the reason names the budget");
        check(res.capped != 0, "the dropped ranges were counted");
    }

    // ---- the empty set ----
    {
        amdrx::SlotRec none[1];
        std::memset(none, 0, sizeof(none));
        amdrx::buildSet(none, 1, nullptr, 0, 0, 0, 0, out, 64, res);
        check(!res.complete, "an empty set is not a pass");
        checkStr(res.why, "empty-set", "the reason names the empty set");
    }

    // ---- the same buffer at two capacities is TWO ranges ----
    //
    // This is why the key is (addr, capacity) and not addr: a buffer re-posted
    // with a different posted length is a different number of writable bytes,
    // and collapsing them would check the smaller one only.
    {
        amdrx::RearmRec two[2];
        std::memset(two, 0, sizeof(two));
        two[0].seq = 2; two[0].addr = 0x1f0000000ull; two[0].capacity = 4096;
        two[1].seq = 4; two[1].addr = 0x1f0000000ull; two[1].capacity = 2048;
        amdrx::buildSet(slots, 1, two, 2, 1, 2, 1, out, 64, res);
        check(res.complete, "two capacities at one address is a valid set");
        checkU64(res.ranges, 2, "one address at two capacities is two ranges");
    }
}

// ---------------------------------------------------------------------------
// 3b. the published blob's GEOMETRY
// ---------------------------------------------------------------------------
//
// WHY THIS EXISTS -- and what it cost not to have it
// --------------------------------------------------
// The first version of publishCopy() started at offset 0, so the slot array was
// written over the header. On the real machine the reader computed
//
//     (bytes - 160 - 1024*32) % 48 != 0
//
// and refused the whole publication with `ragged-rearm-body`. That refusal is
// the right behaviour -- it did not invent a plausible answer -- but the host
// test had missed it because its helper used the same wrong origin for writing
// and for reading, so the two agreed with each other.
//
// These assertions are about the LAYOUT CONTRACT a reader relies on:
//   * the slot array begins at kRxPostHdrBytes, not at 0;
//   * the rearm records begin right after the slot array;
//   * the returned length is exactly header + slots + n*rearmBytes.
static void testBlobGeometry() {
    std::printf("-- blob geometry --\n");

    Ring ring;
    ring.rearm(1, 0x1f0000000ull,
               (unsigned long long)(kRxBufSize | kRxPostDescOwn));
    ring.rearm(2, 0x1f0010000ull,
               (unsigned long long)(kRxBufSize | kRxPostDescOwn));

    // Give the slot table a NON-PERIODIC pattern, so a copy to the wrong origin
    // is detectable rather than merely shifted.
    //
    // WHY NOT A 16-BYTE REPEATING PATTERN: the first version used
    // `0xA0 + (i & 0x0F)`, which repeats every 16 bytes. With the slot array
    // copied to offset 0 instead of 160, `blob[160]` was still `0xA0` -- so the
    // "the slot array begins at kRxPostHdrBytes" check PASSED on the broken
    // code. Modulo a prime makes the byte value depend on the absolute index,
    // which is what "at the wrong origin" has to be able to see.
    for (unsigned i = 0; i < kRxPostSlots * kRxPostSlotBytes; i++)
        ring.slots[i] = (unsigned char)(i % 251);

    std::vector<unsigned char> blob;
    unsigned n = ring.publish(blob, 2);
    checkU64(n, 2, "two rearms publish two records");

    // ---- the returned length must equal the layout ----
    const unsigned want_len = kRxPostHdrBytes +
                              kRxPostSlots * kRxPostSlotBytes +
                              n * kRxPostRearmBytes;
    checkU64(blob.size(), want_len,
             "the published length is header + slots + rearms");
    // And publishCopy()'s OWN return value must equal the same thing. The caller
    // computes blob.size() itself, so without this the length assertion would
    // hold no matter what publishCopy returned.
    checkU64(ring.lastCopyBytes, want_len,
             "publishCopy reports header + slots + rearms");
    checkU64((blob.size() - kRxPostHdrBytes -
              kRxPostSlots * kRxPostSlotBytes) % kRxPostRearmBytes, 0,
             "the body after the slot table is a whole number of rearm records");

    // ---- the slot array must start AT the header size, not at 0 ----
    //
    // A copy to offset 0 overwrites the header's magic with the first slot's
    // address bytes, so both halves of this assertion matter: the header must
    // still hold what the caller put there, AND the slot pattern must appear at
    // kRxPostHdrBytes with the value that belongs to slot byte 0.
    rxpost::Hdr hdr;
    std::memcpy(&hdr, &blob[0], kRxPostHdrBytes);
    checkU64(hdr.magic, kRxPostMagic,
             "the header survived the copy (magic intact)");
    checkU64(hdr.version, kRxPostVersion, "the header version survived");

    checkU64(blob[kRxPostHdrBytes], 0 % 251,
             "the slot array begins at kRxPostHdrBytes (slot byte 0 is 0)");
    checkU64(blob[kRxPostHdrBytes + 200], 200 % 251,
             "slot byte 200 is at kRxPostHdrBytes + 200");
    checkU64(blob[0], 0x52,
             "byte 0 is the header's magic ('RXPO' low byte), not a slot");

    // ---- the rearm records must follow the slot table ----
    const rxpost::RearmRec *r = Ring::rearmIn(blob, 0);
    checkU64(r[0].addr, 0x1f0000000ull, "rearm record 0 follows the slots");
    checkU64(r[1].addr, 0x1f0010000ull, "rearm record 1 follows record 0");
}

// ---------------------------------------------------------------------------
// 3c. the LIVE REGION must hold the whole ring
// ---------------------------------------------------------------------------
//
// WHY THIS EXISTS -- it is a post-mortem, not a precaution.
//
// Round 14's run 5 panicked ~242 s after boot with a page fault on a WRITE in
// writeRecordSized <- rxpostRecordRearm <- rxInterrupt. The cause was one
// definition:
//
//     #define kRxPostRegionBytes kRxPostSnapshotMax
//
// A snapshot holds the header, ONE slot array and the rearm records. The live
// region holds the header, TWO slot arrays (so a capture can fill the inactive
// one while a publish copies the active one) and the ring. So the allocation was
// 32768 bytes short and the last ~682 ring records were outside the mapping.
//
// The driver survived the experiment itself because the ring had not filled that
// far yet. It faulted minutes later, when it had.
//
// These assertions are the arithmetic the macro has to satisfy. The compile-time
// static_asserts in the header are the real guard; this test states the numbers
// so a reader can see what "short" meant.
static void testRegionHoldsRing() {
    std::printf("-- region covers the ring --\n");

    const unsigned long long hdr   = kRxPostHdrBytes;
    const unsigned long long slots = (unsigned long long)kRxPostSlots *
                                     (unsigned long long)kRxPostSlotBytes;
    const unsigned long long ring  = (unsigned long long)kRxPostRearmCap *
                                     (unsigned long long)kRxPostRearmBytes;

    // The layout rxpostInit() builds.
    const unsigned long long rearmOff = hdr + 2ull * slots;
    checkU64(kRxPostRearmsOff, rearmOff,
             "kRxPostRearmsOff matches header + TWO slot arrays");
    checkU64(kRxPostRegionBytes, rearmOff + ring,
             "the region is header + two slot arrays + the whole ring");

    // The exact inequality the panic violated.
    check(kRxPostRegionBytes >= rearmOff + ring,
         "the rearm ring lies entirely inside the allocated region");

    // And the defect itself, stated as a number: the OLD definition
    // (kRxPostSnapshotMax) is exactly one slot array too small.
    const unsigned long long old_region = hdr + slots + ring;
    checkU64(kRxPostRegionBytes - old_region, slots,
             "the old definition was short by exactly one slot array");
    check(old_region < rearmOff + ring,
         "the old definition could not have held the ring");

    // A snapshot still fits: it is the header, one slot array, and the records
    // the publisher keeps.
    check(kRxPostSnapshotMax <= kRxPostRegionBytes,
         "a published snapshot fits inside the live region");
    const unsigned long long snapUsed =
        hdr + slots +
        (unsigned long long)kRxPostPublishRearmMax *
            (unsigned long long)kRxPostRearmBytes;
    check(snapUsed <= kRxPostSnapshotMax,
         "the publisher's largest snapshot fits its buffer");

    // Every record index the mask admits must be inside the region. This is the
    // check that would have caught it directly: mask_max * record + record.
    const unsigned long long lastByte =
        rearmOff + (unsigned long long)(kRxPostRearmMask) *
                       (unsigned long long)kRxPostRearmBytes +
        (unsigned long long)kRxPostRearmBytes;
    check(lastByte <= kRxPostRegionBytes,
         "the highest index the mask admits is inside the region");
    checkU64(kRxPostRearmMask, kRxPostRearmCap - 1u,
             "the mask is the ring capacity minus one");
}

// ---------------------------------------------------------------------------
// 4. the join is gap-free under a moving ring
// ---------------------------------------------------------------------------
static void testWatermarkOrder() {
    std::printf("-- watermark order --\n");

    // The rule the design rests on: the watermark is read BEFORE the scan, so
    // a rearm that happens DURING the scan is still required afterwards.
    //
    // Simulate exactly that: read the head, then rearm a slot (changing the
    // descriptor pair the scan will see), then build the set with the OLD
    // watermark. The address that was replaced must still appear.
    Ring ring;
    ring.rearm(9, 0x1f5000000ull,
               (unsigned long long)(kRxBufSize | kRxPostDescOwn));
    const unsigned watermark = ring.head();          // read BEFORE the scan

    // The second rearm retires 0x1f5000000 and installs 0x1f6000000. It is the
    // record's `oldAddr` that carries the retired buffer, so this is the case
    // the field exists for.
    ring.rearm(9, 0x1f6000000ull,                    // happens DURING the scan
               (unsigned long long)(kRxBufSize | kRxPostDescOwn),
               0x1f5000000ull);

    // The scan now sees the NEW pair only; the old buffer is invisible to it.
    amdrx::SlotRec slots[1];
    std::memset(slots, 0, sizeof(slots));
    slots[0].addr = 0x1f6000000ull; slots[0].capacity = 4096; slots[0].slot = 9;

    std::vector<unsigned char> blob;
    unsigned published = ring.publish(blob, ring.head() - watermark);
    checkU64(published, 1, "one rearm is required past the watermark");

    amdrx::RearmRec rearms[1];
    std::memset(rearms, 0, sizeof(rearms));
    std::memcpy(&rearms[0], Ring::rearmIn(blob, 0), kRxPostRearmBytes);

    amdrx::Range out[16];
    amdrx::SetResult res;
    amdrx::buildSet(slots, 1, rearms, 1, watermark, ring.head(),
                    rxpost::firstSeqFor(ring.head(), ring.cap), out, 16, res);
    check(res.complete, "the join is complete");
    checkU64(res.ranges, 2, "both the replaced and the replacing buffer are in");

    bool sawOld = false, sawNew = false;
    for (unsigned i = 0; i < res.ranges; i++) {
        if (out[i].addr == 0x1f5000000ull) sawOld = true;
        if (out[i].addr == 0x1f6000000ull) sawNew = true;
    }
    check(sawOld,
          "the buffer REPLACED during the scan is still in the set");
    check(sawNew, "the replacing buffer is in the set");

    // The counterexample: reading the watermark AFTER the scan makes the
    // required count zero, and the retired buffer then depends entirely on the
    // baseline having seen it. Since the scan saw the NEW pair, it did not --
    // so the set loses a buffer the device could write. Asserting that here is
    // what makes the check above sensitive to the ordering.
    {
        const unsigned lateWatermark = ring.head();
        std::vector<unsigned char> none;
        unsigned n = ring.publish(none, ring.head() - lateWatermark);
        checkU64(n, 0,
                 "a watermark read AFTER the scan requires zero records -- "
                 "which is why the order matters");
        amdrx::buildSet(slots, 1, nullptr, 0, lateWatermark, ring.head(),
                        rxpost::firstSeqFor(ring.head(), ring.cap), out, 16, res);
        bool stillOld = false;
        for (unsigned i = 0; i < res.ranges; i++)
            if (out[i].addr == 0x1f5000000ull) stillOld = true;
        check(!stillOld,
              "with the late watermark the replaced buffer is LOST -- the "
              "defect the early read prevents");
    }
}

// ---------------------------------------------------------------------------
// 5. writer and publisher concurrently, under TSan
// ---------------------------------------------------------------------------
static void testConcurrent() {
    std::printf("-- concurrent writer/publisher --\n");

    // A ring big enough that the publisher can copy between the writer's laps.
    // With the 8-slot fixture the writer laps 130 times per copy, so EVERY
    // ticket the publisher asks for is already gone and "0 accepted" is the
    // correct answer -- which would make this test vacuous rather than wrong.
    // The point here is the protocol under overlap, not the ring's size.
    Ring ring(1024);
    std::atomic<bool> stop(false);
    std::atomic<unsigned> writes(0);

    std::thread writer([&] {
        unsigned i = 0;
        while (!stop.load()) {
            const unsigned long long addr =
                0x1f0000000ull + (unsigned long long)(i & 0xFF) * 0x10000ull;
            ring.rearm(i & kRxPostSlotsMask, addr,
                       (unsigned long long)(kRxBufSize | kRxPostDescOwn));
            i++;
            writes.store(i);
        }
    });

    unsigned reads = 0, accepted = 0, holes = 0, badAccounting = 0;
    for (unsigned it = 0; it < 4000; it++) {
        std::vector<unsigned char> blob;
        unsigned n = ring.publish(blob, 256);
        reads++;
        const rxpost::RearmRec *r = Ring::rearmIn(blob, 0);
        unsigned itAccepted = 0, itHoles = 0;
        for (unsigned i = 0; i < n; i++) {
            if (r[i].seq == 0) { itHoles++; continue; }
            itAccepted++;
            // Homogeneity: every accepted record must have the shape a single
            // writer produces. A mixed body shows up as a capacity that is not
            // the posted length, or an address that is not page-aligned.
            if (r[i].capacity != kRxBufSize) {
                std::printf("FAIL: torn rearm record, capacity 0x%x\n",
                            r[i].capacity);
                gFail++;
            } else if ((r[i].addr & 0xFFFull) != 0) {
                std::printf("FAIL: torn rearm record, address 0x%llx\n",
                            (unsigned long long)r[i].addr);
                gFail++;
            } else if (r[i].seq != (r[i].seq & ~1u)) {
                std::printf("FAIL: an odd seq was accepted (body in flight)\n");
                gFail++;
            } else {
                gPass++;
            }
        }
        // Every record the publication carried is either a hole or accepted.
        // If this identity ever broke, "no holes" would stop meaning anything.
        if (itAccepted + itHoles != n) badAccounting++;
        accepted += itAccepted;
        holes += itHoles;
    }
    stop.store(true);
    writer.join();

    check(reads == 4000, "the publisher completed every iteration");
    check(writes.load() > 0, "the writer produced records");
    check(accepted > 0, "the publisher accepted records");
    check(badAccounting == 0, "accepted + holes == records published, every time");
    std::printf("   (%u accepted, %u holes, %u writes)\n",
                accepted, holes, writes.load());
}

int main() {
    std::printf("==== RX posted-buffer set ====\n");
    testFillSlotRec();
    testFillRearmRec();
    testRearmRing();
    testBuildSet();
    testBlobGeometry();
    testRegionHoldsRing();
    testWatermarkOrder();
    testConcurrent();

    std::printf("\n%d passed, %d failed\n", gPass, gFail);
    if (gFail == 0) std::printf("RESULT: RX POST SET OK\n");
    else            std::printf("RESULT: RX POST SET FAILURES\n");
    return gFail == 0 ? 0 : 1;
}
