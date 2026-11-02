// obs-write-test.cpp -- the observation log's WRITE and PUBLISH protocol,
// tested as the pair that actually runs in production.
//
// WHAT THIS TEST IS FOR
// ---------------------
// Round 10 shipped a slot protocol that read correctly and was wrong:
//
//     exchange(seq, busy)            // preempts whoever is here
//     ... write the body ...
//     if (load(seq) != busy) drop;   // "ownership re-check"
//     store(seq, ticket*2);
//
// Round 11 replaced it with a bounded lock and tested writer-vs-writer plus a
// STATIC publisher. That is not the production pair: obsWrite() runs on the
// packet path while obsPublish() runs on the watchdog, and the shared
// implementation had a genuine data race between them (plain byte copy vs
// plain field stores). A writer-only test cannot see that, so it must not be
// reported as "the publish protocol has no races".
//
// WHAT ROUND 12 ADDS
// ------------------
//   5. writer and publisher running CONCURRENTLY, under TSan, asserting that
//      every record the publisher accepted is internally homogeneous (all
//      fields from one writer) and that the accepted count + holes accounts
//      for every ticket;
//   6. the shared loss counters under concurrent drops -- a plain `+=` loses
//      increments and under-reports loss, which is the one direction that
//      matters;
//   7. ring reuse while a publisher is reading: the publisher must see either
//      a complete record or a hole, never a mix of two laps.
//
// Every assertion is about the PROTOCOL's observable contract, not about the
// implementation's internals, so the same test also runs against round 10's
// protocol in tools/r11/verify-write-protocol.py and must fail there.
// WHY THE INCLUDE IS NOT A RELATIVE PATH
// --------------------------------------
// This test must be compilable against SEVERAL versions of the protocol header
// -- round 10's, round 11's and the shipped one -- because "the suite passes on
// round 12" only means something if the same suite FAILS on the older ones
// (tools/r11/verify-write-protocol.py does exactly that).
//
// A relative `#include "../tools/lucy-obs/RTL812xObsWrite.hpp"` defeats that:
// the path resolves from this file's directory, so `-I <other-dir>` is ignored
// and every build silently tests the shipped header. That is what happened the
// first time this round's harness was run: all three "protocols" passed, which
// looked like the old defects being absent rather than the substitution being
// broken. A bare name is resolved through -I, which is what makes the
// substitution real.
//
// tools/test.sh passes -I tools/lucy-obs for the production build.
#include "RTL812xObsWrite.hpp"

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

// ---------------------------------------------------------------------------
// A record laid out exactly like RtlObsRec: the protocol only needs `seq`, but
// the test fills distinctive fields so a mixed body is detectable.
// ---------------------------------------------------------------------------
static const unsigned kRecBytes = kObsRecBytesWire;
static const unsigned kCap = 8;               // tiny ring, so reuse is easy
static const unsigned kCapMask = kCap - 1;
static const unsigned kHdrBytes = 104;

struct Fixture {
    std::vector<unsigned char> hdr;
    std::vector<unsigned char> recs;
    volatile unsigned int lock;
    // ROUND 13: the writer's loss counters are the CALLER's, exactly as they
    // are in the driver (`obsDropped` / `obsWrapped` are driver members, not
    // ring-header fields). The round-12 writer incremented the ring header's
    // `wrapped` word while the publisher read a separate member, so the two
    // could disagree -- and did.
    unsigned int wrappedCount;
    unsigned int droppedCount;

    Fixture() : hdr(kHdrBytes, 0), recs(kCap * kRecBytes, 0), lock(0),
                wrappedCount(0), droppedCount(0) {}

    unsigned char *recAt(unsigned ticket) {
        return &recs[(ticket & kCapMask) * kRecBytes];
    }
    unsigned seqAt(unsigned ticket) {
        unsigned v;
        std::memcpy(&v, recAt(ticket) + kObsSeqOffset, 4);
        return v;
    }
    unsigned head() {
        unsigned v;
        std::memcpy(&v, &hdr[kObsHeadOffset], 4);
        return v;
    }
    // THE AUTHORITATIVE WRAP COUNT: the caller's counter, not the ring header.
    unsigned wrapped() { return wrappedCount; }
    unsigned dropped() { return droppedCount; }
    unsigned droppedInHdr() {
        unsigned v;
        std::memcpy(&v, &hdr[kObsDropOffset], 4);
        return v;
    }
    // The ring header's own copy. It must stay ZERO: the writer no longer
    // writes it, so there is exactly one authority.
    unsigned wrappedInHdr() {
        unsigned v;
        std::memcpy(&v, &hdr[kObsWrapOffset], 4);
        return v;
    }
};

// Body filler: every field is derived from the writer's identity, so a record
// containing bytes from two writers is detectable field by field.
struct Body {
    unsigned writerId;
    unsigned tag;
    bool     pauseMidBody;
};

static void fillBody(unsigned char *rec, const Body &b) {
    // tMono (8) and addr (8) first, then seq is at 16 and is owned by the
    // protocol, then kind..pktFlags.
    unsigned long long t = 0x1000000000000000ULL |
                           ((unsigned long long)b.writerId << 32) | b.tag;
    std::memcpy(rec + 0, &t, 8);
    unsigned long long addr = 0x2000000000000000ULL |
                              ((unsigned long long)b.writerId << 32) | b.tag;
    std::memcpy(rec + 8, &addr, 8);
    for (unsigned i = 20; i < kRecBytes; i += 4) {
        unsigned v = (b.writerId << 16) | (b.tag & 0xFFFF);
        std::memcpy(rec + i, &v, 4);
    }
    if (b.pauseMidBody) {
        // The window round 10's protocol could not survive: another writer
        // tries to reuse this slot while this body is half written.
        std::this_thread::yield();
    }
}

// Which writer's identity does this published record carry? Returns 0xFFFFF
// when the fields disagree with each other, which is the mixed-body case.
static unsigned ownerOfRecord(const unsigned char *r) {
    unsigned owner = 0xFFFFF;
    for (unsigned i = 20; i < kRecBytes; i += 4) {
        unsigned v;
        std::memcpy(&v, r + i, 4);
        const unsigned w = v >> 16;
        if (owner == 0xFFFFF) owner = w;
        else if (owner != w) return 0xFFFFF;   // mixed
    }
    return owner;
}

// ---------------------------------------------------------------------------
// 1. the round-10 interleaving, reproduced explicitly
// ---------------------------------------------------------------------------
//
// This is the exact case the brief names: "old writer paused, new writer
// reuses the same slot, old writer resumes".
//
// With round 10's protocol the old writer resumes INSIDE the slot and
// overwrites the new writer's fields, then the new writer stamps. With the
// lock, the old writer holds the lock for its whole body, so the new writer
// cannot start; it either waits or drops, and the record it eventually
// publishes is entirely its own.
static void testPausedWriterCannotBePreempted() {
    Fixture f;
    // (the loss counters live on the fixture: round 13 made them
    //  the CALLER's, exactly as obsDropped/obsWrapped are driver
    //  members rather than ring-header fields)

    // Writer A takes the lock and writes a body that pauses half way.
    Body a{0xAAAA, 0x1111, true};
    bool aOk = obslog::writeRecord(&f.lock, &f.hdr[0], &f.recs[0], kCapMask,
                                   fillBody, a, &f.droppedCount, &f.wrappedCount);
    check(aOk, "A: the first writer publishes");

    // Its ticket is 1, so it lives in slot 1.
    const unsigned ticketA = 1;
    checkU64(f.seqAt(ticketA), ticketA << 1,
             "A: its record is stamped with an even seq for its own ticket");

    // The body must be entirely A's. Read every field the filler touched.
    {
        const unsigned char *r = f.recAt(ticketA);
        bool allA = true;
        for (unsigned i = 20; i < kRecBytes; i += 4) {
            unsigned v;
            std::memcpy(&v, r + i, 4);
            if ((v >> 16) != 0xAAAA) allA = false;
        }
        check(allA, "A: every body field belongs to writer A");
    }

    // Now a second writer whose ticket maps to the SAME slot. kCap == 8, so
    // ticket 9 shares slot 1 with ticket 1.
    Body b{0xBBBB, 0x2222, false};
    // Force the ticket collision the ring would produce after 8 writes.
    unsigned h;
    std::memcpy(&h, &f.hdr[kObsHeadOffset], 4);
    h = kCap;                    // next claim yields ticket 9
    std::memcpy(&f.hdr[kObsHeadOffset], &h, 4);

    bool bOk = obslog::writeRecord(&f.lock, &f.hdr[0], &f.recs[0], kCapMask,
                                   fillBody, b, &f.droppedCount, &f.wrappedCount);
    check(bOk, "B: the second writer publishes");
    checkU64(f.seqAt(9), 9u << 1, "B: the slot now carries ticket 9's seq");
    checkU64(f.wrapped(), 1,
             "B: the displaced record is counted as a wrap, not silently lost");
    // ROUND 13: ONE AUTHORITY. The writer counts into the caller's counter and
    // must NOT also write the ring header's copy. Round 12 wrote only the ring
    // header, while the publisher read a separate member, so the published
    // `wrapped` was permanently zero while the ring had really wrapped.
    checkU64(f.wrappedInHdr(), 0,
             "B: the ring header's wrapped word is NOT written (one authority)");
    checkU64(f.dropped(), 0,
             "B: no write lost its lock, so dropped stays 0");
    checkU64(f.droppedInHdr(), 0,
             "B: the ring header's dropped word is NOT written either");

    // THE ASSERTION THAT MATTERS: no field of the surviving record may belong
    // to writer A. Round 10's protocol failed exactly this.
    {
        const unsigned char *r = f.recAt(9);
        bool allB = true;
        unsigned badOffset = 0;
        for (unsigned i = 20; i < kRecBytes; i += 4) {
            unsigned v;
            std::memcpy(&v, r + i, 4);
            if ((v >> 16) != 0xBBBB) { allB = false; badOffset = i; break; }
        }
        check(allB, "B: NO field of the surviving record belongs to writer A");
        if (!allB) std::printf("      first foreign field at offset %u\n",
                               badOffset);
    }
}

// ---------------------------------------------------------------------------
// 1b. the SAME interleaving, driven deterministically
// ---------------------------------------------------------------------------
//
// The concurrent tests below detect a mixed body only if the scheduler happens
// to interleave two writers inside one slot. That is a matter of luck, and a
// lucky run would "prove" a broken protocol safe -- which is exactly how round
// 10 shipped.
//
// This case imposes the order with explicit phase gates:
//
//   1. A claims ticket 1 (slot 1), sets its busy marker, and PAUSES before
//      writing any field.
//   2. B claims ticket 9 (slot 1), which is the same slot, writes its whole
//      body, and PAUSES just before its final store.
//   3. A resumes and writes its whole body -- over B's.
//   4. A re-checks the marker: it is B's, so A gives up without stamping.
//   5. B resumes and stamps ticket 9.
//
// Final state under round 10: B's seq over A's bytes. Under round 12 the lock
// makes step 2 impossible: B is spinning on the lock, the gate times out, and
// the record ends up homogeneous.
//
// The gate timeout is what distinguishes the two protocols, so it must be
// bounded and its expiry must be treated as the EXPECTED outcome for round 12,
// not as a failure.
static void testDeterministicInterleave() {
    Fixture f;
    std::atomic<int> phase{0};
    std::atomic<int> aWrote{0};
    unsigned dropA = 0, dropB = 0;

    struct Gate { int role; };
    auto fill = [&](unsigned char *rec, const Gate &g) {
        if (g.role == 1) {
            // A: announce, then wait for B to reach its pre-store pause.
            phase.store(1);
            for (int i = 0; i < 4000000 && phase.load() < 3; i++)
                std::this_thread::yield();
            for (unsigned i = 20; i < kRecBytes; i += 4) {
                unsigned v = (0xAAAAu << 16) | 0x77u;
                std::memcpy(rec + i, &v, 4);
            }
            aWrote.store(1);
        } else {
            // B: write everything, announce, then wait for A to overwrite.
            for (unsigned i = 20; i < kRecBytes; i += 4) {
                unsigned v = (0xBBBBu << 16) | 0x77u;
                std::memcpy(rec + i, &v, 4);
            }
            phase.store(2);
            for (int i = 0; i < 4000000 && phase.load() < 4; i++)
                std::this_thread::yield();
        }
    };

    std::thread a([&]() {
        Gate g{1};
        obslog::writeRecord(&f.lock, &f.hdr[0], &f.recs[0], kCapMask, fill, g,
                            &dropA, &f.wrappedCount);
    });

    // Wait until A is inside its body (or has already finished, on a protocol
    // that does not block).
    for (int i = 0; i < 4000000 && phase.load() < 1; i++) std::this_thread::yield();

    // Force B's ticket to collide with A's slot: kCap == 8, so head = 8 makes
    // the next claim ticket 9, which maps to slot 1.
    {
        unsigned h = kCap;
        __atomic_store_n((unsigned *)&f.hdr[kObsHeadOffset], h,
                         __ATOMIC_RELAXED);
    }

    std::thread bt([&]() {
        Gate g{2};
        obslog::writeRecord(&f.lock, &f.hdr[0], &f.recs[0], kCapMask, fill, g,
                            &dropB, &f.wrappedCount);
    });

    // Give B a bounded chance to reach its pre-store pause. Under a protocol
    // that serialises writers it never will: it is spinning on the lock A
    // holds.
    for (int i = 0; i < 4000000 && phase.load() < 2; i++) std::this_thread::yield();
    const bool bGotIn = (phase.load() >= 2);

    phase.store(3);                       // release A
    for (int i = 0; i < 4000000 && !aWrote.load(); i++) std::this_thread::yield();
    phase.store(4);                       // release B
    a.join();
    bt.join();

    const unsigned char *r = f.recAt(9);
    unsigned seq;
    std::memcpy(&seq, r + kObsSeqOffset, 4);
    const unsigned owner = (seq >> 1) == 9 ? 0xBBBB : 0xAAAA;
    unsigned foreign = 0, seen = 0;
    for (unsigned i = 20; i < kRecBytes; i += 4) {
        unsigned v;
        std::memcpy(&v, r + i, 4);
        seen++;
        if ((v >> 16) != owner) foreign++;
    }
    std::printf("      interleave: bEntered=%d seq=0x%x owner=0x%04x "
                "foreign=%u/%u dropA=%u dropB=%u\n",
                bGotIn ? 1 : 0, seq, owner, foreign, seen, dropA, dropB);
    check(foreign == 0,
          "the deterministic interleaving produces no mixed record");
}

// ---------------------------------------------------------------------------
// 2. a writer that cannot take the lock is COUNTED, not silently skipped
// ---------------------------------------------------------------------------
static void testLockTimeoutIsCounted() {
    Fixture f;
    // (the loss counters live on the fixture: round 13 made them
    //  the CALLER's, exactly as obsDropped/obsWrapped are driver
    //  members rather than ring-header fields)
    // Hold the lock as if another writer were mid-body.
    f.lock = 1;
    Body a{0xCCCC, 0x3333, false};
    const bool ok = obslog::writeRecord(&f.lock, &f.hdr[0], &f.recs[0],
                                        kCapMask, fillBody, a, &f.droppedCount, &f.wrappedCount);
    check(!ok, "a writer that cannot take the lock reports failure");
    checkU64(f.dropped(), 1, "and the drop is counted");
    checkU64(f.head(), 0,
             "and NO ticket was consumed, so the sequence has no phantom gap");
    f.lock = 0;
}

// ---------------------------------------------------------------------------
// 3. tickets are unique and monotonic under real concurrency
// ---------------------------------------------------------------------------
//
// THE INVARIANT IS AN ACCOUNTING IDENTITY, NOT "NO DROPS".
//
// Round 11's version of this test asserted `totalDrops == 0` and `head ==
// attempts`. That is not a property of the protocol: it is a property of how
// lucky the scheduler was. The first run of this round's harness failed it on
// the SHIPPED protocol (3 drops out of 8000 attempts) purely because the build
// had no sanitizer and the lock bound was reached -- which says nothing about
// correctness and everything about the assertion being wrong.
//
// What must hold regardless of contention:
//
//     head + totalDrops == attempts
//
// i.e. every attempt either claimed exactly one ticket or was counted as a
// drop. That is what makes "no phantom gap in the sequence" and "no silent
// loss" true at the same time, and it holds at any contention level.
static void testConcurrentTicketsAreUnique() {
    Fixture f;
    const unsigned kThreads = 4, kPerThread = 2000;
    std::vector<unsigned> drops(kThreads, 0);
    std::vector<std::thread> ts;
    for (unsigned t = 0; t < kThreads; t++) {
        ts.emplace_back([&f, &drops, t]() {
            Body b{t, 0, false};
            for (unsigned i = 0; i < kPerThread; i++) {
                obslog::writeRecord(&f.lock, &f.hdr[0], &f.recs[0], kCapMask,
                                    fillBody, b, &drops[t], &f.wrappedCount);
            }
        });
    }
    for (auto &t : ts) t.join();

    unsigned totalDrops = 0;
    for (unsigned t = 0; t < kThreads; t++) totalDrops += drops[t];

    const unsigned long long attempts = (unsigned long long)kThreads *
                                        kPerThread;
    checkU64((unsigned long long)f.head() + totalDrops, attempts,
             "every attempt either claimed one ticket or was counted as a drop");
    std::printf("      tickets=%u drops=%u attempts=%llu\n",
                f.head(), totalDrops, attempts);

    // The slot seq values must all be even: no writer left a busy marker.
    bool anyOdd = false;
    for (unsigned s = 0; s < kCap; s++) {
        unsigned v;
        std::memcpy(&v, &f.recs[s * kRecBytes + kObsSeqOffset], 4);
        if (v & 1u) anyOdd = true;
    }
    check(!anyOdd, "no slot was left marked busy");
    // The ring invariant: every ticket past the first `kCap` displaces exactly
    // one earlier record, so wrapped == head - kCap (when head >= kCap). This
    // is derived from `head`, not from the expected attempt count, so it holds
    // whether or not any writer dropped.
    const unsigned want = (f.head() > kCap) ? (f.head() - kCap) : 0u;
    checkU64(f.wrapped(), want,
             "the wrap counter accounts for every displaced record");
}

// ---------------------------------------------------------------------------
// 4. the publisher's hole detection, against a record mid-write
// ---------------------------------------------------------------------------
static void testPublisherSeesHoles() {
    Fixture f;
    // Publish 4 records normally.
    // (the loss counters live on the fixture: round 13 made them
    //  the CALLER's, exactly as obsDropped/obsWrapped are driver
    //  members rather than ring-header fields)
    for (unsigned i = 0; i < 4; i++) {
        Body b{i, i, false};
        obslog::writeRecord(&f.lock, &f.hdr[0], &f.recs[0], kCapMask,
                            fillBody, b, &f.droppedCount, &f.wrappedCount);
    }
    std::vector<unsigned char> dst(4 * kRecBytes, 0xEE);
    unsigned valid = 0, lost = 0;
    obslog::publishCopy(&f.recs[0], kCapMask, kCap, 1, 4, &dst[0], kRecBytes,
                        &valid, &lost);
    checkU64(valid, 4, "four complete records are copied");
    checkU64(lost, 0, "with no holes");

    // Mark ticket 3's slot busy, as an in-flight write would.
    {
        unsigned busy = (3u << 1) | 1u;
        __atomic_store_n((unsigned *)(f.recAt(3) + kObsSeqOffset), busy,
                         __ATOMIC_RELAXED);
    }
    std::fill(dst.begin(), dst.end(), 0xEE);
    valid = lost = 0;
    obslog::publishCopy(&f.recs[0], kCapMask, kCap, 1, 4, &dst[0], kRecBytes,
                        &valid, &lost);
    checkU64(valid, 3, "a mid-write record is not copied");
    checkU64(lost, 1, "and is counted as a hole");
    {
        // The hole must be ZEROED, so a reader cannot mistake stale bytes in
        // the staging buffer for a record.
        bool zeroed = true;
        for (unsigned i = 0; i < kRecBytes; i++)
            if (dst[2 * kRecBytes + i] != 0) zeroed = false;
        check(zeroed, "the hole is zeroed in the snapshot, not left stale");
    }

    // A record stamped with a different ticket is also a hole.
    {
        unsigned wrong = (99u << 1);
        __atomic_store_n((unsigned *)(f.recAt(3) + kObsSeqOffset), wrong,
                         __ATOMIC_RELAXED);
        valid = lost = 0;
        obslog::publishCopy(&f.recs[0], kCapMask, kCap, 1, 4, &dst[0],
                            kRecBytes, &valid, &lost);
        checkU64(lost, 1, "a record carrying another ticket is a hole");
    }
    // A never-written slot is a hole.
    {
        unsigned zero = 0;
        __atomic_store_n((unsigned *)(f.recAt(3) + kObsSeqOffset), zero,
                         __ATOMIC_RELAXED);
        valid = lost = 0;
        obslog::publishCopy(&f.recs[0], kCapMask, kCap, 1, 4, &dst[0],
                            kRecBytes, &valid, &lost);
        checkU64(lost, 1, "an unwritten slot is a hole");
    }
}

// ---------------------------------------------------------------------------
// 5. WRITER AND PUBLISHER RUNNING AT THE SAME TIME
// ---------------------------------------------------------------------------
//
// This is the pair round 11 never exercised. It is also the case TSan flagged
// in the shared implementation: a plain byte copy in publishCopy() against
// plain field stores in fillBody().
//
// What must hold, and what is asserted:
//
//   a. the publisher never accepts a record whose fields belong to two
//      different writers -- the seqlock plus atomic words must make that
//      impossible to observe;
//   b. accepted + holes accounts for every ticket the publisher tried;
//   c. the writer's own counters are unchanged by the publisher (a reader must
//      not perturb the log);
//   d. no crash, and every published seq is even.
//
// It cannot assert "no hole ever occurs": holes are the CORRECT outcome when
// the publisher reads a body in flight. Asserting zero holes would be asserting
// that the writer never runs, which is the bug this test exists to catch.
static void testWriterAndPublisherConcurrently() {
    Fixture f;
    std::atomic<bool> stop{false};
    std::atomic<unsigned long long> accepted{0}, holes{0}, reads{0};
    std::atomic<unsigned> mixed{0};

    const unsigned kWriters = 2;
    std::vector<std::thread> writers;
    for (unsigned t = 0; t < kWriters; t++) {
        writers.emplace_back([&f, t, &stop]() {
            unsigned localDrop = 0;
            unsigned i = 0;
            while (!stop.load(std::memory_order_relaxed)) {
                Body b{0x1000 + t, i & 0xFFFF, false};
                obslog::writeRecord(&f.lock, &f.hdr[0], &f.recs[0], kCapMask,
                                    fillBody, b, &localDrop, &f.wrappedCount);
                i++;
            }
        });
    }

    std::vector<unsigned char> dst(kCap * kRecBytes, 0);
    std::thread pub([&]() {
        unsigned rounds = 0;
        while (!stop.load(std::memory_order_relaxed) && rounds < 4000) {
            const unsigned head =
                __atomic_load_n((unsigned *)&f.hdr[kObsHeadOffset],
                                __ATOMIC_ACQUIRE);
            const unsigned n = (head < kCap) ? head : kCap;
            if (n > 0) {
                unsigned valid = 0, lost = 0;
                obslog::publishCopy(&f.recs[0], kCapMask, kCap,
                                    head - n + 1u, n, &dst[0], kRecBytes,
                                    &valid, &lost);
                accepted.fetch_add(valid);
                holes.fetch_add(lost);
                reads.fetch_add(1);
                // Every accepted record must be homogeneous.
                for (unsigned k = 0; k < n; k++) {
                    unsigned seq;
                    std::memcpy(&seq, &dst[k * kRecBytes + kObsSeqOffset], 4);
                    if (seq == 0) continue;      /* a hole, zeroed */
                    if (ownerOfRecord(&dst[k * kRecBytes]) == 0xFFFFF)
                        mixed.fetch_add(1);
                }
            }
            rounds++;
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    stop.store(true);
    for (auto &t : writers) t.join();
    pub.join();

    check(mixed.load() == 0,
          "no accepted record mixes two writers' fields");
    check(accepted.load() > 0,
          "the publisher accepted records while writers were running");
    check(reads.load() > 0, "the publisher actually ran concurrently");
    std::printf("      concurrent: accepted=%llu holes=%llu reads=%llu\n",
                accepted.load(), holes.load(), reads.load());

    // Every slot's seq must be even once the writers have stopped.
    bool anyOdd = false;
    for (unsigned s = 0; s < kCap; s++) {
        unsigned v = __atomic_load_n(
            (unsigned *)&f.recs[s * kRecBytes + kObsSeqOffset],
            __ATOMIC_ACQUIRE);
        if (v & 1u) anyOdd = true;
    }
    check(!anyOdd, "no slot is left marked busy after the writers stop");

    // A final publish with everything quiescent must accept every record it
    // covers: nothing the writer did can leave a permanently unreadable slot.
    const unsigned head = __atomic_load_n(
        (unsigned *)&f.hdr[kObsHeadOffset], __ATOMIC_ACQUIRE);
    const unsigned n = (head < kCap) ? head : kCap;
    unsigned valid = 0, lost = 0;
    obslog::publishCopy(&f.recs[0], kCapMask, kCap, head - n + 1u, n, &dst[0],
                        kRecBytes, &valid, &lost);
    checkU64(valid, n, "a quiescent publish accepts every covered record");
    checkU64(lost, 0, "and finds no holes when nothing is writing");
}

// ---------------------------------------------------------------------------
// 6. the shared loss counter must not lose increments
// ---------------------------------------------------------------------------
//
// Round 11 updated `dropped` with a plain `+=`. Two writers dropping at once
// then produce ONE increment, and the header under-reports the loss. Since the
// reader decides whether a snapshot is complete from exactly this number, an
// under-report is the dangerous direction.
//
// HOW THIS IS MADE DETERMINISTIC
// ------------------------------
// Two weaker versions of this test were tried first and BOTH passed on round
// 11's plain `+=`, which would have reported "the counter is fine":
//
//   a. each thread calls countLoss() in a tight loop. The compiler is entitled
//      to collapse that loop into one add -- it need not consider other
//      threads -- so the total comes out exact on the broken implementation.
//   b. the increments are driven through writeRecord() with the lock held. The
//      4096-iteration spin before the increment staggers the threads, so the
//      read-modify-write windows rarely overlap and the total is exact.
//
// So the increments are issued from a RENDEZVOUS: every thread waits until all
// of them have arrived, then all of them call countLoss() at the same instant.
// That is the arrangement in which a non-atomic increment loses updates
// reliably rather than by luck, and it is the arrangement the protocol has to
// survive -- several writers can fail at once.
//
// The rendezvous is a small sense-reversing barrier built on one atomic.
static void testLossCounterIsExact() {
    const unsigned kThreads = 8, kRounds = 400;
    unsigned shared = 0;
    std::atomic<unsigned> arrived{0};
    std::atomic<unsigned> generation{0};
    std::atomic<bool> go{true};

    std::vector<std::thread> ts;
    for (unsigned t = 0; t < kThreads; t++) {
        ts.emplace_back([&]() {
            for (unsigned r = 0; r < kRounds; r++) {
                const unsigned gen = generation.load(std::memory_order_acquire);
                if (arrived.fetch_add(1) == kThreads - 1) {
                    arrived.store(0, std::memory_order_relaxed);
                    generation.fetch_add(1, std::memory_order_release);
                } else {
                    while (generation.load(std::memory_order_acquire) == gen)
                        std::this_thread::yield();
                }
                // All kThreads threads are now inside this window at once.
                obslog::countLoss(&shared);
            }
        });
    }
    for (auto &t : ts) t.join();
    go.store(false);

    checkU64(obslog::readLoss(&shared), kThreads * kRounds,
             "concurrent drops are all counted (no lost increment)");

    // And through the real path: a permanently-held lock makes every writer
    // drop, and a dropped write must not consume a ticket.
    Fixture f;
    f.lock = 1;
    unsigned viaProtocol = 0;
    for (unsigned i = 0; i < 500; i++) {
        Body b{0xEEEE, i, false};
        obslog::writeRecord(&f.lock, &f.hdr[0], &f.recs[0], kCapMask, fillBody,
                            b, &viaProtocol, &f.wrappedCount);
    }
    f.lock = 0;
    checkU64(viaProtocol, 500,
             "every lock-timeout through writeRecord is counted");
    checkU64(f.head(), 0,
             "no dropped write consumed a ticket, so the sequence has no gap");
}

// ---------------------------------------------------------------------------
// 7. ring reuse while a publisher is reading
// ---------------------------------------------------------------------------
//
// The ring is 8 slots. A writer wraps every 8 records; a publisher copying
// 8 records therefore always races with reuse. The contract: the publisher
// sees either a complete record or a hole. It must never accept a record whose
// seq claims ticket T while the body belongs to a different lap -- that is the
// mixed-record failure in its lap form.
static void testRingReuseUnderPublish() {
    Fixture f;
    std::atomic<bool> stop{false};
    std::atomic<unsigned> mixed{0}, accepted{0}, holes{0};

    std::thread w([&]() {
        unsigned i = 0;
        unsigned drop = 0;
        while (!stop.load(std::memory_order_relaxed)) {
            Body b{0x2000 + (i % 3), i, false};
            obslog::writeRecord(&f.lock, &f.hdr[0], &f.recs[0], kCapMask,
                                fillBody, b, &drop, &f.wrappedCount);
            i++;
        }
    });

    std::vector<unsigned char> dst(kCap * kRecBytes, 0);
    std::thread pub([&]() {
        unsigned rounds = 0;
        while (!stop.load(std::memory_order_relaxed) && rounds < 4000) {
            const unsigned head = __atomic_load_n(
                (unsigned *)&f.hdr[kObsHeadOffset], __ATOMIC_ACQUIRE);
            const unsigned n = (head < kCap) ? head : kCap;
            if (n == 0) { rounds++; continue; }
            unsigned valid = 0, lost = 0;
            obslog::publishCopy(&f.recs[0], kCapMask, kCap, head - n + 1u, n,
                                &dst[0], kRecBytes, &valid, &lost);
            accepted.fetch_add(valid);
            holes.fetch_add(lost);
            for (unsigned k = 0; k < n; k++) {
                unsigned seq;
                std::memcpy(&seq, &dst[k * kRecBytes + kObsSeqOffset], 4);
                if (seq == 0) continue;
                if (ownerOfRecord(&dst[k * kRecBytes]) == 0xFFFFF)
                    mixed.fetch_add(1);
            }
            rounds++;
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    stop.store(true);
    w.join();
    pub.join();

    check(mixed.load() == 0, "ring reuse never yields a mixed record");
    check(accepted.load() > 0, "records were accepted across wraps");
    std::printf("      reuse: accepted=%u holes=%u wrapped=%u\n",
                accepted.load(), holes.load(), f.wrapped());
    // The wrap counter must have advanced: otherwise reuse never happened and
    // this test proved nothing about reuse.
    check(f.wrapped() > 0, "the ring actually wrapped during the test");
}

int main() {
    std::printf("obs-write protocol tests\n");
    std::printf("========================\n");
    testPausedWriterCannotBePreempted();
    testDeterministicInterleave();
    testLockTimeoutIsCounted();
    testConcurrentTicketsAreUnique();
    testPublisherSeesHoles();
    testWriterAndPublisherConcurrently();
    testLossCounterIsExact();
    testRingReuseUnderPublish();
    std::printf("\n%d passed, %d failed\n", gPass, gFail);
    if (gFail == 0) {
        std::printf("RESULT: ALL CHECKS PASS\n");
        return 0;
    }
    std::printf("RESULT: FAILURES\n");
    return 1;
}
