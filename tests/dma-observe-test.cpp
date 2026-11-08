// Host regression tests for probe/amd_iommu_dma_observe.hpp.
//
// This compiles and runs the SAME header the kext includes, so a pass here
// exercises production logic rather than a Python restatement of it.
//
// Build:
//   clang++ -std=c++17 -O2 -Wall -Wextra -Werror -o dma-observe-test \
//       tests/dma-observe-test.cpp
//
// ROUND 7 GROUPS
// --------------
//  10. RECORDING IS NOT FILTERED BY THE MAP LIMIT
//      Counterexample 3 from the task: a descriptor address above 16 GiB must
//      be recorded and must reach the ownership decision. Round 6 filtered it
//      out with inIdentityRam() before insertion, so the set could never
//      contain the very class of address under investigation.
//  11. ENVELOPE SURVIVES A FULL SET
//      Counterexample 2 from the task: 47 existing intervals plus three
//      non-adjacent ones; the last must still reach the envelope even when it
//      cannot be stored.
//  12. THE ROUND-6 ARCHIVE CONTRADICTION IS DETECTED
//      Counterexample 1: envelope-hi = 0x3f80a4000 while txdesc4.addr =
//      0x3fec620e0 and txdesc5.addr = 0x3fec600e2. These are real values from
//      docs/evidence/20261031-201400. The core must classify them as outside
//      the envelope and the test must be able to state that the old envelope
//      was wrong.
//  13. ADDRESS + LENGTH: PAGE CROSSING AND OVERFLOW
//      Counterexample 4.
//  14. CLOSE-POINTER SEMANTICS
//      Valid zero, cumulative counts above 1023, 1000 -> 2024 == 1024,
//      wrap, reset invalidation, insufficient evidence.
//  15. CHIP IDENTITY DERIVES THE REGISTER
//      The register is a function of TxConfig, not an election among
//      candidates that happen to read non-zero.
//
// ROUND 8 GROUPS
// --------------
//  19. WINDOW SCAN IS THE PRODUCTION COLLECTOR
//      scanTxWindow() is what m2b2CollectTxSegments() now calls. Round 7's
//      collector ignored its tailCum/cloCum arguments and marked every
//      non-zero address in-flight. The round-7 capture had tail = clo = 0x6a
//      (queue empty) and still reported every historical address in-flight.
//  20. SLOT REUSE AND GENERATIONS
//      A reused slot destroys the evidence for the earlier descriptor. That
//      must be counted, not silently overwritten.
//  21. LENGTHS THAT WERE NOT DECODED
//      A TSO descriptor's 16-bit field is the MSS. A guessed length must not
//      take part in a coverage argument.
//  22. PER-PATH COVERAGE
//      TX window coverage must not be reported as device-wide coverage.
//  23. THE BASIS FOR READING RING MEMORY
//      "A register named this address" is not "this PA is the driver's ring
//      object". A fingerprint that can fail is the minimum honest check.

#include "../probe/amd_iommu_dma_observe.hpp"

#include <cstdio>
#include <cstring>

static int gPass = 0;
static int gFail = 0;

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

using namespace amdobs;

static MapPolicy policyAt(u64 limit, bool known) {
    MapPolicy p = defaultMapPolicy();
    p.limit = limit;
    p.layoutKnown = known;
    return p;
}

// ---------------------------------------------------------------- group 1

static void testIntervalContainment() {
    const MapPolicy pol = policyAt(0x400000000ULL, true);

    AddrSet s;
    s.clear();
    check(s.insert(0x1000, 0x1000, PURP_TX_BUF, LIFE_INFLIGHT, RD_OK),
          "insert one range");
    checkU64(s.n, 1, "set holds one range");
    checkU64(s.mergedTotal, 1, "mergedTotal counts it");
    checkU64(s.savedCount, 1, "savedCount counts it");
    checkU64(s.droppedCount, 0, "nothing dropped");

    check(s.contains(0x1000, nullptr), "base is inside");
    check(s.contains(0x1FFF, nullptr), "last byte is inside");
    check(!s.contains(0x2000, nullptr), "end is exclusive");
    check(!s.contains(0x0FFF, nullptr), "below base is outside");

    u32 p = PURP_UNKNOWN;
    check(s.contains(0x1800, &p), "middle is inside");
    checkU64(p, PURP_TX_BUF, "purpose is reported");

    // zero-length inserts must be refused, not stored as a wildcard
    check(!s.insert(0x5000, 0, PURP_OTHER, LIFE_INFLIGHT, RD_OK),
          "zero-length refused");
    checkU64(s.n, 1, "refused insert did not grow the set");
    checkU64(s.zeroLenSkipped, 1, "zero-length is counted separately");

    // A wrapping interval widens the envelope to everything.
    AddrSet w;
    w.clear();
    w.insert(0xFFFFFFFFFFFFF000ULL, 0x2000, PURP_OTHER, LIFE_SNAPSHOT,
             RD_OVERFLOW);
    check(w.envValid, "wrapping interval still yields an envelope");
    checkU64(w.envLo, 0, "wrapping envelope starts at zero");
    checkU64(w.envHi, ~0ULL, "wrapping envelope covers the address space");

    (void)pol;
}

// ---------------------------------------------------------------- group 2

static void testLiveness() {
    AddrSet s;
    s.clear();
    s.insert(0x2000, 0x1000, PURP_TX_BUF, LIFE_INFLIGHT, RD_OK);
    s.insert(0x4000, 0x1000, PURP_RX_BUF, LIFE_COMPLETED, RD_OK);

    check(s.containsLive(0x2000, nullptr), "live range matches containsLive");
    check(!s.containsLive(0x4000, nullptr), "completed range is not live");
    check(s.contains(0x4000, nullptr), "completed range still matches contains");
    check(s.containsLifecycle(0x4000, LIFE_COMPLETED, nullptr),
          "completed range matches its own lifecycle");

    u32 p = PURP_UNKNOWN;
    check(s.containsLive(0x4000, &p) == false, "completed: containsLive false");
    checkU64(p, PURP_UNKNOWN, "purpose untouched when not live");

    // LIFE_UNKNOWN and LIFE_SNAPSHOT are neither live nor dead. A snapshot
    // must not be able to claim a range is in flight.
    AddrSet u;
    u.clear();
    u.insert(0x6000, 0x1000, PURP_TX_BUF, LIFE_SNAPSHOT, RD_OK);
    check(!u.containsLive(0x6000, nullptr),
          "snapshot-only range is not claimed live");
    check(u.containsLifecycle(0x6000, LIFE_SNAPSHOT, nullptr),
          "snapshot-only range keeps its own lifecycle");
}

// ---------------------------------------------------------------- group 3

static void testClassificationOrder() {
    const MapPolicy LIMIT16 = policyAt(0x400000000ULL, true);
    const u32 COV_W = COV_WINDOW;
    const u32 COV_S = COV_SNAPSHOT;

    // ---- a range ABOVE the map limit that the device genuinely owns ----
    // This is the case round 5 got wrong: it concluded "above 16 GiB,
    // therefore MMIO" without ever asking whether the device owned it.
    AddrSet s;
    s.clear();
    s.insert(0x405D19000ULL, 0x1000, PURP_TX_BUF, LIFE_INFLIGHT, RD_OK);

    FaultClass f = classifyFault(0x405D1999CULL, s, LIMIT16, COV_S);
    check(f.own == OWN_IN_LIVE_SET,
          "above-limit address that IS in the set reports set membership");
    checkU64(f.purpose, PURP_TX_BUF, "purpose of that range");
    check(!f.inMappedRange, "inMappedRange still reports the truth");

    // ---- completed range is a different statement from live ----
    AddrSet d;
    d.clear();
    d.insert(0x30000000ULL, 0x1000, PURP_RX_BUF, LIFE_COMPLETED, RD_OK);
    FaultClass f2 = classifyFault(0x30000000ULL, d, LIMIT16, COV_W);
    check(f2.own == OWN_IN_COMPLETED_SET,
          "completed range classified separately");

    // ---- ROUND 8: a snapshot hit is NOT a completed-range hit ----
    // Round 7 used contains(), which ignores lifecycle, so any hit was
    // reported as "in-completed-dma-range" -- a claim about the past that a
    // single observation cannot support.
    AddrSet sn;
    sn.clear();
    sn.insert(0x31000000ULL, 0x1000, PURP_RX_BUF, LIFE_SNAPSHOT, RD_OK);
    FaultClass fsn = classifyFault(0x31000000ULL, sn, LIMIT16, COV_S);
    check(fsn.own == OWN_IN_SNAPSHOT_SET,
          "snapshot hit is reported as a snapshot hit, not as completed");
    check(fsn.own != OWN_IN_COMPLETED_SET,
          "a snapshot must not claim the device already handed it back");
    check(ownershipIsPositive(fsn.own),
          "a snapshot hit IS still a positive statement");
    check(std::strstr(fsn.reason, "cannot be derived") != nullptr,
          "the snapshot reason says liveness is not derivable");

    // ---- an empty set cannot support any negative claim ----
    AddrSet e;
    e.clear();
    FaultClass f3 = classifyFault(0x500000000ULL, e, LIMIT16, COV_W);
    check(f3.own == OWN_ENVELOPE_UNKNOWN,
          "empty set leaves ownership undetermined, not 'outside'");
    FaultClass f3b = classifyFault(0x10000000ULL, e, LIMIT16, COV_W);
    check(f3b.own == OWN_ENVELOPE_UNKNOWN,
          "empty set leaves an in-range address undetermined too");

    // ---- a complete set with WINDOW coverage: negatives are definitive ----
    //
    // ROUND 8: a window-complete negative is now scoped. `allPathsCovered`
    // decides whether it may be stated about the whole device or only about
    // the path that was actually covered.
    AddrSet c;
    c.clear();
    c.insert(0x10000000ULL, 0x1000, PURP_TX_BUF, LIFE_INFLIGHT, RD_OK);
    c.insert(0x20000000ULL, 0x1000, PURP_RX_BUF, LIFE_INFLIGHT, RD_OK);
    FaultClass f4 = classifyFault(0x500000000ULL, c, LIMIT16, COV_W, true);
    check(f4.own == OWN_OUTSIDE_ENVELOPE,
          "outside the envelope with window coverage is definitive");
    check(f4.globalScope, "and is marked as a device-wide statement");
    check(ownershipIsGlobalNegative(f4.own),
          "global negative predicate agrees");
    check(std::strstr(ownershipName(f4.own), "mmio") == nullptr,
          "no classification name claims MMIO");

    // ---- ROUND 8: TX-only coverage must NOT become a device-wide claim ----
    //
    // This is the round-7 over-generalisation: TX was window-covered, RX was
    // a snapshot, and the result was reported as "outside every DMA range the
    // device used during a window-complete observation".
    FaultClass f4t = classifyFault(0x500000000ULL, c, LIMIT16, COV_W, false);
    check(f4t.own == OWN_TX_WINDOW_ABSENT,
          "TX-only coverage yields a TX-scoped negative, not a global one");
    check(!f4t.globalScope, "and it is explicitly not device-wide");
    check(ownershipIsNegative(f4t.own), "it is still a negative");
    check(!ownershipIsGlobalNegative(f4t.own),
          "but not one that may be stated about the whole device");
    check(std::strstr(f4t.reason, "NOT a device-wide") != nullptr,
          "the reason says so in words");

    FaultClass f5 = classifyFault(0x18000000ULL, c, LIMIT16, COV_W, true);
    check(f5.own == OWN_IN_ENVELOPE_GAP,
          "between two complete ranges is a definitive gap");
    FaultClass f6 = classifyFault(0x0FFFFFFFULL, c, LIMIT16, COV_W, true);
    check(f6.own == OWN_OUTSIDE_ENVELOPE, "below the envelope is outside");

    // ---- ROUND 8: a gap in a SNAPSHOT is not a gap in the window ----
    // Round 7 returned OWN_IN_ENVELOPE_GAP here whenever the set was exact,
    // with the reason "the set is exact, so the device did not use this
    // address". Exactness is about the set; coverage is about time.
    FaultClass f5s = classifyFault(0x18000000ULL, c, LIMIT16, COV_S, false);
    check(f5s.own == OWN_OBSERVED_ABSENT,
          "a gap under snapshot coverage is not a definitive gap");
    check(f5s.own != OWN_IN_ENVELOPE_GAP,
          "snapshot exactness alone must not produce a gap verdict");
    check(std::strstr(f5s.reason, "snapshot-only") != nullptr,
          "the reason names the limitation");

    // ---- ROUND 7: the same address with only SNAPSHOT coverage ----
    // The set is exact and the address is outside the envelope, yet a
    // snapshot cannot say "the device never used it". Round 6 made exactly
    // that claim from a snapshot.
    FaultClass f4s = classifyFault(0x500000000ULL, c, LIMIT16, COV_S);
    check(f4s.own == OWN_OBSERVED_ABSENT,
          "snapshot coverage downgrades the negative verdict");
    check(ownershipIsNegative(f4s.own),
          "but it is still a negative-class verdict, not a positive one");
    check(!ownershipIsPositive(f4s.own), "and definitely not positive");
    check(std::strstr(f4s.reason, "does NOT establish") != nullptr,
          "the reason text says what the snapshot cannot establish");

    // ---- unexamined slots poison the envelope ----
    AddrSet x;
    x.clear();
    x.insert(0x10000000ULL, 0x1000, PURP_TX_BUF, LIFE_INFLIGHT, RD_OK);
    x.unscanned = 5;
    FaultClass f9 = classifyFault(0x500000000ULL, x, LIMIT16, COV_W);
    check(f9.own == OWN_ENVELOPE_UNKNOWN,
          "unscanned slots make even a window-complete envelope unusable");

    // ---- overflow: envelope still bounds the negative claim ----
    AddrSet o;
    o.clear();
    for (unsigned i = 0; i < MAX_RANGES; i++) {
        o.insert(0x1000000ULL + (u64)i * 0x1000ULL, 0x1000, PURP_OTHER,
                 LIFE_INFLIGHT, RD_OK);
    }
    // Force overflow with an interval far above the stored ones.
    o.insert(0x80000000ULL, 0x1000, PURP_TX_BUF, LIFE_INFLIGHT, RD_OK);
    check(o.droppedCount > 0, "the far interval did not fit");
    checkU64(o.envHi, 0x80001000ULL,
             "the envelope grew to include the dropped interval");
    FaultClass f7 = classifyFault(0x90000000ULL, o, LIMIT16, COV_W, true);
    check(f7.own == OWN_OUTSIDE_ENVELOPE,
          "outside the envelope stays definitive even with overflow");
    FaultClass f8 = classifyFault(0x40000000ULL, o, LIMIT16, COV_W, true);
    check(f8.own == OWN_ENVELOPE_UNKNOWN,
          "inside the envelope with overflow is NOT a definitive negative");
}

// ---------------------------------------------------------------- group 4

static void testCoalescing() {
    const MapPolicy pol = policyAt(0x400000000ULL, true);
    AddrSet s;
    s.clear();
    u64 scratch[16];

    // Four consecutive pages coalesce into one interval.
    scratch[0] = 0x10000;
    scratch[1] = 0x11000;
    scratch[2] = 0x12000;
    scratch[3] = 0x13000;
    insertCoalesced(s, scratch, 4, 0x1000, PURP_TX_BUF, LIFE_INFLIGHT, pol);
    checkU64(s.n, 1, "four adjacent pages coalesce to one interval");
    checkU64(s.r[0].base, 0x10000, "coalesced base");
    checkU64(s.r[0].len, 0x4000, "coalesced length");
    check(s.contains(0x13FFF, nullptr), "last page still covered");
    check(!s.contains(0x14000, nullptr), "nothing past the end");
    checkU64(s.rawOffered, 4, "four raw addresses were offered");
    checkU64(s.mergedTotal, 1, "one merged interval");

    // Disjoint pages stay separate.
    AddrSet t;
    t.clear();
    scratch[0] = 0x20000;
    scratch[1] = 0x50000;
    insertCoalesced(t, scratch, 2, 0x1000, PURP_RX_BUF, LIFE_INFLIGHT, pol);
    checkU64(t.n, 2, "disjoint pages stay separate");
    check(t.contains(0x20000, nullptr), "first interval present");
    check(t.contains(0x50000, nullptr), "second interval present");
    check(!t.contains(0x30000, nullptr), "gap is NOT covered");

    // Unsorted input must give the same answer as sorted input.
    AddrSet u;
    u.clear();
    scratch[0] = 0x13000;
    scratch[1] = 0x10000;
    scratch[2] = 0x12000;
    scratch[3] = 0x11000;
    insertCoalesced(u, scratch, 4, 0x1000, PURP_TX_BUF, LIFE_INFLIGHT, pol);
    checkU64(u.n, 1, "unsorted input coalesces identically");
    checkU64(u.r[0].base, 0x10000, "unsorted coalesced base");
}

// ------------------------------------------------------- group 10 (task #3)

static void testRecordingIgnoresMapLimit() {
    // THE DEFECT: round 6 called inIdentityRam() before inserting, and that
    // gate uses RAM_TOP = 16 GiB. A descriptor address above 16 GiB therefore
    // never entered the set, and the set then "proved" the fault was not the
    // device's memory by never having been able to contain such an address.
    //
    // Counterexample 3: a descriptor address above 16 GiB must be recorded
    // and must reach the ownership decision.
    const u64 ABOVE = 0x405711b9cULL;          // round-6 archived fault
    const u64 DESC  = 0x3fec620e0ULL;          // round-6 txdesc4

    MapPolicy pol = policyAt(0x400000000ULL, true);

    AddrSet s;
    s.clear();
    // Insert an address well above the 16 GiB map limit.
    check(s.insert(ABOVE & ~0xFFFULL, 0x1000, PURP_TX_BUF, LIFE_INFLIGHT,
                   readVerdict(ABOVE & ~0xFFFULL, 0x1000, pol)),
          "an address above the map limit is still recorded");
    checkU64(s.n, 1, "and it is in the set");
    check(s.contains(ABOVE, nullptr),
          "so a query at that address finds it");

    // The read verdict says it must not be dereferenced; that is metadata.
    checkU64(s.r[0].readable, RD_OUT_OF_MAP,
             "the read verdict records why it must not be read");
    check(std::strstr(readVerdictName(RD_OUT_OF_MAP), "not-read") != nullptr,
          "the verdict text says it is a read decision, not a record decision");

    // And classification finds it as a positive match despite the limit.
    FaultClass f = classifyFault(ABOVE, s, pol, COV_SNAPSHOT);
    check(f.own == OWN_IN_LIVE_SET,
          "above-limit address that is in the set classifies as owned");
    check(!f.inMappedRange, "while still reporting it is outside the map");

    // A whole set of above-limit descriptor addresses must survive.
    AddrSet big;
    big.clear();
    Seg segs[3];
    segs[0].base = DESC;               segs[0].len = 0x100;
    segs[1].base = 0x3fec600e2ULL;     segs[1].len = 0x100;
    segs[2].base = ABOVE;              segs[2].len = 0x100;
    insertSegments(big, segs, 3, PURP_TX_BUF, LIFE_INFLIGHT, pol);
    checkU64(big.n, 3, "all three above-limit segments were recorded");
    checkU64(big.rawOffered, 3, "raw count matches");
    check(big.contains(DESC, nullptr), "txdesc4 address is in the set");
    check(big.contains(0x3fec600e2ULL, nullptr), "txdesc5 address is in the set");

    // readVerdict is a pure read decision and must be usable independently.
    checkU64(readVerdict(0x1000, 0x1000, pol), RD_OK, "low RAM is readable");
    checkU64(readVerdict(0x0F0000000ULL, 0x1000, pol), RD_NOT_RAM,
             "MMIO hole is not readable");
    checkU64(readVerdict(ABOVE, 0x1000, pol), RD_OUT_OF_MAP,
             "above the map limit is not readable");
    checkU64(readVerdict(0xFFFFFFFFFFFFF000ULL, 0x2000, pol), RD_OVERFLOW,
             "a wrapping range is refused");
    checkU64(readVerdict(0x1000, 0, pol), RD_ZERO_LEN, "zero length refused");

    // With no authoritative layout, nothing is dereferenced.
    MapPolicy unknown = policyAt(0x400000000ULL, false);
    checkU64(readVerdict(0x1000, 0x1000, unknown), RD_UNVERIFIED,
             "no layout means no read permission");
    check(std::strstr(readVerdictName(RD_UNVERIFIED), "unverified") != nullptr,
          "and the reason says the layout is unverified");

    // ---- but a DEVICE-REPORTED address does not need the layout ----
    //
    // This distinction cost a whole boot in round 7. Applying the strict
    // verdict to ring bases meant every ring was unreadable, so the
    // observation recorded the right addresses and could read none of them:
    // tx-slots = 0, raw-offered = 0, unscanned = 0x800.
    //
    // A ring base is the address the driver programmed and the hardware is
    // already using, so reading it is exactly as safe as the driver's own
    // access. The panic risks (beyond the map limit, inside the MMIO hole)
    // still apply.
    checkU64(readVerdictDeviceReported(0x33e38000ULL, 0x8000, unknown), RD_OK,
             "a device-reported ring base is readable without a layout");
    checkU64(readVerdictDeviceReported(0x500000000ULL, 0x1000, unknown),
             RD_OUT_OF_MAP,
             "but a device-reported address beyond the map is still refused");
    checkU64(readVerdictDeviceReported(0x0F0000000ULL, 0x1000, unknown),
             RD_NOT_RAM,
             "and one inside the MMIO hole is still refused");
    checkU64(readVerdictDeviceReported(0xFFFFFFFFFFFFF000ULL, 0x2000, unknown),
             RD_OVERFLOW, "and a wrapping one is still refused");
    checkU64(readVerdictDeviceReported(0x1000, 0, unknown), RD_ZERO_LEN,
             "and a zero-length one is still refused");

    // The two verdicts must actually differ, otherwise the split is a no-op.
    check(readVerdict(0x33e38000ULL, 0x8000, unknown) !=
          readVerdictDeviceReported(0x33e38000ULL, 0x8000, unknown),
          "the strict and device-reported verdicts are genuinely different");
}

// ------------------------------------------------------ group 11 (task #2)

static void testEnvelopeSurvivesFullSet() {
    const MapPolicy pol = policyAt(0x400000000ULL, true);

    // Counterexample 2, literally as specified: the set already holds 47
    // intervals, then three non-adjacent intervals arrive. The last one must
    // reach the envelope even if it cannot be stored.
    AddrSet s;
    s.clear();
    for (unsigned i = 0; i < 47; i++) {
        s.insert(0x1000000ULL + (u64)i * 0x2000ULL, 0x1000, PURP_OTHER,
                 LIFE_SNAPSHOT, RD_OK);
    }
    checkU64(s.n, 47, "47 intervals stored");

    u64 scratch[3];
    scratch[0] = 0x200000000ULL;   // 8 GiB
    scratch[1] = 0x2F0000000ULL;   // ~11.75 GiB
    scratch[2] = 0x3FF000000ULL;   // just under 16 GiB, the highest
    insertCoalesced(s, scratch, 3, 0x1000, PURP_TX_BUF, LIFE_INFLIGHT, pol);
    checkU64(s.n, 50, "all three fitted, so all three are stored");
    checkU64(s.envHi, 0x3FF001000ULL,
             "the envelope covers the highest address");

    // Now the case the task is really about: the set is FULL and further
    // intervals cannot be stored. Round 6 broke out of the loop here, so the
    // envelope stopped growing and later (higher) addresses vanished from it.
    AddrSet full;
    full.clear();
    for (unsigned i = 0; i < MAX_RANGES; i++) {
        full.insert(0x1000000ULL + (u64)i * 0x2000ULL, 0x1000, PURP_OTHER,
                    LIFE_SNAPSHOT, RD_OK);
    }
    checkU64(full.n, MAX_RANGES, "set is at capacity");
    const u64 hiBefore = full.envHi;

    // Three non-adjacent intervals, each higher than everything stored.
    u64 over[3];
    over[0] = 0x300000000ULL;
    over[1] = 0x380000000ULL;
    over[2] = 0x3FF000000ULL;
    insertCoalesced(full, over, 3, 0x1000, PURP_TX_BUF, LIFE_INFLIGHT, pol);

    checkU64(full.n, MAX_RANGES, "capacity unchanged: nothing new was stored");
    checkU64(full.droppedCount, 3, "all three dropped intervals are counted");
    checkU64(full.mergedTotal, MAX_RANGES + 3,
             "mergedTotal counts stored plus dropped");
    checkU64(full.savedCount, MAX_RANGES, "savedCount equals the stored count");
    checkU64(full.envHi, 0x3FF001000ULL,
             "THE ENVELOPE STILL GREW over the intervals that did not fit");
    check(full.envHi > hiBefore, "and it grew past where it was before");

    // The accounting invariant must hold exactly.
    checkU64(full.mergedTotal, full.savedCount + full.droppedCount,
             "mergedTotal == savedCount + droppedCount (no double counting)");

    // The negative claim is still bounded by the enlarged envelope.
    FaultClass f = classifyFault(0x3FF000800ULL, full, pol, COV_SNAPSHOT);
    check(f.own != OWN_OBSERVED_ABSENT,
          "a dropped address inside the envelope is NOT called absent");
    FaultClass g = classifyFault(0x500000000ULL, full, pol, COV_WINDOW, true);
    check(g.own == OWN_OUTSIDE_ENVELOPE,
          "an address above the enlarged envelope is still outside");
}

// ------------------------------------------------------ group 12 (task #1)

static void testRound6ArchiveContradiction() {
    // Counterexample 1, using the REAL archived values from
    // docs/evidence/20261031-201400/props.txt:
    //
    //   m2-b2-dma-envelope-hi = 0x3f80a4000
    //   m2-b2-dma-txdesc4     addr = 0x3fec620e0
    //   m2-b2-dma-txdesc5     addr = 0x3fec600e2
    //
    // Both descriptor addresses are ABOVE the envelope the same capture
    // published. An envelope that does not contain addresses taken from the
    // descriptors it claims to summarise is self-contradictory: either the
    // loop stopped early (round-6 defect 2) or something was filtered out.
    // Any downstream "outside the envelope" conclusion built on it is unsound.
    const u64 R6_ENV_LO = 0x29438000ULL;
    const u64 R6_ENV_HI = 0x3f80a4000ULL;
    const u64 R6_TXDESC4 = 0x3fec620e0ULL;
    const u64 R6_TXDESC5 = 0x3fec600e2ULL;

    check(R6_TXDESC4 >= R6_ENV_HI,
          "archived txdesc4 really is above the archived envelope-hi");
    check(R6_TXDESC5 >= R6_ENV_HI,
          "archived txdesc5 really is above the archived envelope-hi");

    // Demonstrate the contradiction through the production classifier: using
    // the round-6 envelope as the set, a descriptor address from the very
    // same capture classifies as "outside" -- which is absurd.
    AddrSet r6;
    r6.clear();
    r6.insert(R6_ENV_LO, R6_ENV_HI - R6_ENV_LO, PURP_OTHER, LIFE_SNAPSHOT,
              RD_OK);
    FaultClass bad = classifyFault(R6_TXDESC4, r6, policyAt(0x400000000ULL, true),
                                   COV_WINDOW, true);
    check(bad.own == OWN_OUTSIDE_ENVELOPE,
          "the round-6 envelope really does exclude a round-6 descriptor");

    // Now show the round-7 core cannot produce that state: offer the same
    // addresses with the set already full, and the envelope still covers them.
    AddrSet good;
    good.clear();
    for (unsigned i = 0; i < MAX_RANGES; i++) {
        good.insert(R6_ENV_LO + (u64)i * 0x1000ULL, 0x1000, PURP_OTHER,
                    LIFE_SNAPSHOT, RD_OK);
    }
    u64 over[2];
    over[0] = R6_TXDESC4;
    over[1] = R6_TXDESC5;
    insertCoalesced(good, over, 2, 0x1000, PURP_TX_BUF, LIFE_INFLIGHT,
                    policyAt(0x400000000ULL, true));
    check(good.envHi > R6_TXDESC4,
          "the round-7 envelope covers txdesc4 even though the set is full");
    FaultClass ok = classifyFault(R6_TXDESC4, good,
                                  policyAt(0x400000000ULL, true), COV_SNAPSHOT);
    check(ok.own != OWN_OUTSIDE_ENVELOPE,
          "so txdesc4 is no longer called 'outside the envelope'");
}

// ------------------------------------------------------ group 13 (task #4)

static void testAddressPlusLength() {
    const MapPolicy pol = policyAt(0x400000000ULL, true);

    // A segment that crosses a page boundary must cover every byte of it.
    AddrSet s;
    s.clear();
    Seg one;
    one.base = 0x1FF0;      // 16 bytes below the 0x2000 boundary
    one.len = 0x20;         // 32 bytes: covers 0x1FF0..0x200F
    insertSegments(s, &one, 1, PURP_TX_BUF, LIFE_INFLIGHT, pol);
    checkU64(s.n, 1, "one segment stored");
    checkU64(s.r[0].len, 0x20, "length preserved exactly, not rounded to pages");
    check(s.contains(0x1FF0, nullptr), "first byte covered");
    check(s.contains(0x1FFF, nullptr), "last byte of the first page covered");
    check(s.contains(0x2000, nullptr), "first byte of the next page covered");
    check(s.contains(0x200F, nullptr), "last byte covered");
    check(!s.contains(0x2010, nullptr), "one byte past the end is not covered");

    // Overlapping segments merge; the union is exact.
    AddrSet m;
    m.clear();
    Seg ov[3];
    ov[0].base = 0x1000; ov[0].len = 0x1000;   // 0x1000..0x1FFF
    ov[1].base = 0x1800; ov[1].len = 0x1000;   // 0x1800..0x27FF overlaps
    ov[2].base = 0x2800; ov[2].len = 0x800;    // adjacent, extends to 0x2FFF
    insertSegments(m, ov, 3, PURP_TX_BUF, LIFE_INFLIGHT, pol);
    checkU64(m.n, 1, "overlapping and adjacent segments merge into one");
    checkU64(m.r[0].base, 0x1000, "merged base");
    checkU64(m.r[0].len, 0x2000, "merged length is the union");
    check(m.contains(0x2FFF, nullptr), "union covers the far end");

    // Unsorted input must produce the same union.
    AddrSet u;
    u.clear();
    Seg uns[3];
    uns[0].base = 0x2800; uns[0].len = 0x800;
    uns[1].base = 0x1000; uns[1].len = 0x1000;
    uns[2].base = 0x1800; uns[2].len = 0x1000;
    insertSegments(u, uns, 3, PURP_TX_BUF, LIFE_INFLIGHT, pol);
    checkU64(u.n, 1, "unsorted overlap also merges");
    checkU64(u.r[0].base, 0x1000, "unsorted merged base");
    checkU64(u.r[0].len, 0x2000, "unsorted merged length");

    // A genuine gap must NOT merge.
    AddrSet g;
    g.clear();
    Seg gap[2];
    gap[0].base = 0x1000; gap[0].len = 0x1000;   // ends 0x1FFF
    gap[1].base = 0x2000; gap[1].len = 0x1000;   // starts 0x2000: adjacent
    insertSegments(g, gap, 2, PURP_TX_BUF, LIFE_INFLIGHT, pol);
    checkU64(g.n, 1, "exactly adjacent segments merge (no gap between them)");

    AddrSet g2;
    g2.clear();
    Seg gap2[2];
    gap2[0].base = 0x1000; gap2[0].len = 0x1000;
    gap2[1].base = 0x2001; gap2[1].len = 0x1000;  // one byte of gap
    insertSegments(g2, gap2, 2, PURP_TX_BUF, LIFE_INFLIGHT, pol);
    checkU64(g2.n, 2, "a one-byte gap keeps the segments separate");
    check(!g2.contains(0x2000, nullptr), "and the gap byte is not covered");

    // Overflow: base + len wrapping must be caught, not silently accepted.
    checkU64(readVerdict(0xFFFFFFFFFFFFF000ULL, 0x2000, pol), RD_OVERFLOW,
             "address + length overflow is detected");
    AddrSet o;
    o.clear();
    Seg wrap;
    wrap.base = 0xFFFFFFFFFFFFF000ULL;
    wrap.len = 0x2000;
    insertSegments(o, &wrap, 1, PURP_OTHER, LIFE_SNAPSHOT, pol);
    checkU64(o.envHi, ~0ULL,
             "a wrapping segment widens the envelope to the whole space");
    checkU64(o.r[0].readable, RD_OVERFLOW,
             "and is marked as not readable because it wraps");

    // A huge but non-wrapping length at the top of the address space.
    checkU64(readVerdict(0xFFFFF00000000000ULL, 0x1000, pol), RD_OUT_OF_MAP,
             "a high but non-wrapping range is out of map, not overflow");
}

// ---------------------------------------------------------------- group 14

static void testClosePointerSemantics() {
    const u32 MASK_V4 = 0x7FFFFFFFu;   // HwSuppTxNoCloseVer 5/6 (this card)
    const u32 RING = 1024;

    // ---- valid zero ----
    // Zero is a legitimate counter value (nothing submitted yet) AND the
    // value an unimplemented register reads back. It must be accepted as a
    // sample but never used on its own as evidence of no progress.
    check(cloPtrSampleValid(0, 4, MASK_V4), "zero is a valid 32-bit sample");
    checkU64(cloPtrDelta(0, 0, MASK_V4), 0, "zero to zero is zero progress");
    check(cloPtrDeltaPlausible(0, MASK_V4), "a zero delta is plausible");

    // ---- legitimate cumulative counts above 1023 ----
    // The counter is cumulative over 31 bits, NOT a ring index. Round 6
    // assumed ringSize and would reject or mis-handle these.
    check(cloPtrSampleValid(5000, 4, MASK_V4),
          "a cumulative count of 5000 is a valid sample");
    check(cloPtrSampleValid(0x7FFFFFFF, 4, MASK_V4),
          "the mask maximum is a valid sample");
    check(!cloPtrSampleValid(0x80000000u, 4, MASK_V4),
          "a value with bits outside the 31-bit mask is refused");
    checkU64(cloPtrRingIndex(5000, RING), 5000 & 1023,
             "ring index is the low 10 bits of the cumulative count");

    // ---- 1000 -> 2024 must be 1024, not 0 ----
    // This is the specific case the task names. Round 6 computed a modulo-1024
    // ring advance: (2024 - 1000) % 1024 == 0, i.e. "no progress", which is
    // the exact opposite of the truth.
    const u32 before = 1000, after = 2024;
    const u32 naiveRing = (u32)((after + RING - before) % RING);
    checkU64(naiveRing, 0, "the round-6 modulo-1024 formula really does give 0");
    checkU64(cloPtrDelta(before, after, MASK_V4), 1024,
             "the mask-based delta gives 1024");
    check(cloPtrDeltaPlausible(1024, MASK_V4),
          "a delta of one full ring is still plausible");
    checkU64(cloPtrRingIndex(before, RING), cloPtrRingIndex(after, RING),
             "both samples map to the same ring index, which is why the "
             "ring-index formula cannot tell them apart");

    // ---- ordinary wrap of the 31-bit counter ----
    checkU64(cloPtrDelta(0x7FFFFFF0u, 0x00000010u, MASK_V4), 0x20,
             "counter wrap across the mask boundary is a small forward step");
    check(cloPtrDeltaPlausible(0x20, MASK_V4), "and it is plausible");

    // ---- reset / identity change ----
    // A backwards jump larger than any queue depth looks like a counter reset
    // or a different device. It must be refused rather than reported as a
    // huge forward distance.
    const u32 huge = cloPtrDelta(0x1000, 0x0100, MASK_V4);
    check(!cloPtrDeltaPlausible(huge, MASK_V4),
          "a backwards jump is refused, not reported as a giant forward delta");
    // The decision boundary is (mask >> 1) + 1 == 0x40000000, not mask >> 1.
    checkU64((MASK_V4 >> 1) + 1u, 0x40000000u, "boundary is half the mask + 1");
    check(!cloPtrDeltaPlausible((MASK_V4 >> 1) + 1u, MASK_V4),
          "the decision boundary itself is refused");
    check(cloPtrDeltaPlausible(MASK_V4 >> 1, MASK_V4),
          "just under the boundary is still accepted");

    // ---- insufficient evidence must be expressible ----
    check(!cloPtrSampleValid(0, 0, 0), "no mask means no usable sample");
    check(!cloPtrDeltaPlausible(0, 0), "and no plausible delta");
    checkU64(cloPtrDelta(5, 9, 0), 0, "zero mask yields zero, not garbage");

    // ---- the register/width/mask triple follows the chip, not an election ----
    const CloPtrSpec v6 = cloPtrSpecFor(6);
    check(v6.valid, "ver 6 has a spec");
    checkU64(v6.reg, REG_CLO_PTR_V6, "ver 6 uses 0x0D34");
    checkU64(v6.tailReg, REG_TAIL_PTR_V6, "ver 6 tail is 0x0D30");
    checkU64(v6.width, 4, "ver 6 is 32-bit");
    checkU64(v6.mask, 0x7FFFFFFF, "ver 6 mask is 0x7FFFFFFF");

    const CloPtrSpec v5 = cloPtrSpecFor(5);
    checkU64(v5.reg, REG_CLO_PTR_V45, "ver 5 uses 0x2800");
    checkU64(v5.mask, 0x7FFFFFFF, "ver 5 also uses the V4 mask");

    const CloPtrSpec v4 = cloPtrSpecFor(4);
    checkU64(v4.reg, REG_CLO_PTR_V45, "ver 4 uses 0x2800");
    checkU64(v4.mask, 0xFFFFFFFF, "ver 4 uses the 32-bit mask");

    const CloPtrSpec v3 = cloPtrSpecFor(3);
    checkU64(v3.reg, REG_CLO_PTR_V3, "ver 3 uses 0x2802");
    checkU64(v3.width, 2, "ver 3 is 16-bit");
    checkU64(v3.mask, 0xFFFF, "ver 3 mask is 0xFFFF");

    check(!cloPtrSpecFor(0).valid, "an unknown version has no spec");
    check(!cloPtrSpecFor(99).valid, "a nonsense version has no spec");

    // ---- window coverage argument ----
    check(txWindowCovered(0, 100, RING, MASK_V4),
          "100 descriptors in a 1024 ring is window-covered");
    check(!txWindowCovered(0, RING, RING, MASK_V4),
          "a full ring means the oldest descriptor was overwritten");
    check(!txWindowCovered(0, 0, RING, MASK_V4),
          "nothing submitted covers nothing");
    check(!txWindowCovered(0, 100, 0, MASK_V4), "zero ring size is not covered");
}

// ---------------------------------------------------------------- group 15

static void testChipIdentity() {
    // The close-pointer register must be DERIVED from the chip, not chosen by
    // whichever candidate happens to read non-zero. Round 6 did the latter.
    //
    // This card is an RTL8127: TxConfig & 0x7c800000 == 0x6C800000, and
    // ICVerID distinguishes rev 1 (CFG_METHOD_41) from rev 2 (CFG_METHOD_42).
    // Both map to HwSuppTxNoCloseVer 6 and therefore 0x0D34 / 0x7FFFFFFF.

    ChipId rev1 = identifyChip(0x6C800000u | 0x00000000u);
    check(rev1.known, "RTL8127 rev 1 is identified");
    checkU64(rev1.cfgMethod, 41, "rev 1 is CFG_METHOD_41");
    checkU64(rev1.noCloseVer, 6, "CFG_METHOD_41 is HwSuppTxNoCloseVer 6");
    checkU64(cloPtrSpecFor(rev1.noCloseVer).reg, 0x0D34,
             "and therefore uses the 0x0D34 close pointer");

    ChipId rev2 = identifyChip(0x6C800000u | 0x00100000u);
    checkU64(rev2.cfgMethod, 42, "rev 2 is CFG_METHOD_42");
    checkU64(rev2.noCloseVer, 6, "CFG_METHOD_42 is also ver 6");
    checkU64(cloPtrSpecFor(rev2.noCloseVer).reg, 0x0D34,
             "so the same register");

    // The other families, to prove the derivation is complete rather than
    // tuned to one part.
    checkU64(identifyChip(0x60800000u).cfgMethod, 2, "RTL8125A -> method 2");
    checkU64(identifyChip(0x60800000u).noCloseVer, 3, "method 2 -> ver 3");
    checkU64(cloPtrSpecFor(3).reg, 0x2802, "ver 3 -> 0x2802");
    checkU64(identifyChip(0x64000000u).cfgMethod, 4, "RTL8125B -> method 4");
    checkU64(identifyChip(0x64800000u).cfgMethod, 31, "RTL8126A -> method 31");
    checkU64(identifyChip(0x64800000u).noCloseVer, 4, "method 31 -> ver 4");
    checkU64(identifyChip(0x64800000u | 0x00100000u).cfgMethod, 32,
             "RTL8126A rev 2 -> method 32");
    checkU64(identifyChip(0x64800000u | 0x00100000u).noCloseVer, 5,
             "method 32 -> ver 5");
    checkU64(cloPtrSpecFor(5).reg, 0x2800, "ver 5 -> 0x2800");

    // An unknown part must say so rather than defaulting to a register.
    ChipId unk = identifyChip(0x00000000u);
    check(!unk.known, "an unrecognised TxConfig is reported as unknown");
    checkU64(unk.noCloseVer, 0, "with no close-pointer version");
    check(!cloPtrSpecFor(unk.noCloseVer).valid,
          "and therefore no register at all, rather than a guess");

    // The round-6 election would have picked whichever of these read
    // non-zero first. Show that the derivation and the election can disagree:
    // on this part 0x2800 reads 0 while 0x0D34 holds the real counter, so an
    // election that prefers the first non-zero candidate only works by luck.
    checkU64(cloPtrSpecFor(6).reg != cloPtrSpecFor(5).reg, 1,
             "ver 6 and ver 5 use different registers, so an election among "
             "candidates cannot be an identity test");
}

// ---------------------------------------------------------------- group 16

static void testDescriptorDecoders() {
    // Synthetic TX ring: 4 slots, 32-byte stride.
    unsigned char tx[4 * TX_DESC_STRIDE];
    std::memset(tx, 0, sizeof(tx));
    // slot 0: device still owns, addr 0x384400000
    {
        unsigned char *d = tx + 0;
        u32 opts1 = TX_DESC_OWN | 0x400;
        std::memcpy(d, &opts1, 4);
        u64 a = 0x384400000ULL;
        std::memcpy(d + 8, &a, 8);
    }
    // slot 1: DescOwn clear, addr 0x29648000
    {
        unsigned char *d = tx + TX_DESC_STRIDE;
        u32 opts1 = 0x400;
        std::memcpy(d, &opts1, 4);
        u64 a = 0x29648000ULL;
        std::memcpy(d + 8, &a, 8);
    }
    // slot 2: RingEnd + FirstFrag + LastFrag, addr 0x29649000
    {
        unsigned char *d = tx + 2 * TX_DESC_STRIDE;
        u32 opts1 = TX_DESC_RINGEND | TX_DESC_FIRST | TX_DESC_LAST | 0x5EA;
        std::memcpy(d, &opts1, 4);
        u64 a = 0x29649000ULL;
        std::memcpy(d + 8, &a, 8);
    }
    // slot 3: unused, addr 0
    TxRingStats ts = scanTxRing(tx, 4);
    checkU64(ts.slots, 4, "tx slots");
    checkU64(ts.owned, 1, "tx owned");
    checkU64(ts.done, 3, "tx done counts every DescOwn-clear slot");
    // The critical distinction: slot 3 is DescOwn-clear AND addr == 0, i.e.
    // never programmed. Counting it as a completion is the 0.21.2 defect.
    checkU64(ts.addrZero, 1, "tx zero addr");
    checkU64(ts.doneWithAddr, 2,
             "only slots that were programmed AND handed back are completions");
    checkU64(ts.firstAddr, 0x384400000ULL, "tx first addr");
    checkU64(ts.ringEnd, 1, "ring end seen");

    // Length is the low 16 bits of opts1 and must survive decoding.
    u32 lens[4] = {0, 0, 0, 0};
    forEachTxDesc(tx, 4, [&](const TxDesc &t) {
        if (t.slot < 4) lens[t.slot] = t.len;
    });
    checkU64(lens[0], 0x400, "slot 0 length");
    checkU64(lens[2], 0x5EA, "slot 2 length");
    checkU64(lens[3], 0, "unused slot has zero length");

    // Flag decode.
    bool sawFirst = false, sawLast = false, sawEnd = false;
    forEachTxDesc(tx, 4, [&](const TxDesc &t) {
        if (t.slot != 2) return;
        sawFirst = t.first;
        sawLast = t.last;
        sawEnd = t.ringEnd;
    });
    check(sawFirst, "FirstFrag decoded");
    check(sawLast, "LastFrag decoded");
    check(sawEnd, "RingEnd decoded");

    // TSO detection: GiantSendv4 means the low 16 bits are MSS, not length.
    unsigned char tso[TX_DESC_STRIDE];
    std::memset(tso, 0, sizeof(tso));
    {
        u32 opts1 = TX_DESC_OWN | TX_DESC_GSO4 | 0x05DC;   // MSS 1500
        std::memcpy(tso, &opts1, 4);
        u64 a = 0x300000000ULL;
        std::memcpy(tso + 8, &a, 8);
    }
    bool isTso = false;
    forEachTxDesc(tso, 1, [&](const TxDesc &t) { isTso = t.tso; });
    check(isTso, "TSO is detected so the length field is not misread");

    // ---- the defect this test exists to prevent ----
    // A ring where NOTHING was ever programmed must report zero completions,
    // even though every slot has DescOwn clear.
    unsigned char txEmpty[8 * TX_DESC_STRIDE];
    std::memset(txEmpty, 0, sizeof(txEmpty));
    TxRingStats te = scanTxRing(txEmpty, 8);
    checkU64(te.done, 8, "empty ring: every slot looks DescOwn-clear");
    checkU64(te.addrZero, 8, "empty ring: every slot has addr 0");
    checkU64(te.doneWithAddr, 0,
             "empty ring: zero completions, not 8 (the 0.21.2 bug)");

    // Synthetic RX ring: 2 slots, 16-byte stride.
    unsigned char rx[2 * RX_DESC_STRIDE];
    std::memset(rx, 0, sizeof(rx));
    {
        u32 blen = RX_DESC_OWN | 0x1000;
        std::memcpy(rx + 0, &blen, 4);
        u64 a = 0x2A000000ULL;
        std::memcpy(rx + 8, &a, 8);
    }
    {
        u32 blen = 0x400;          // device has written a frame
        std::memcpy(rx + RX_DESC_STRIDE, &blen, 4);
        u64 a = 0x2A001000ULL;
        std::memcpy(rx + RX_DESC_STRIDE + 8, &a, 8);
    }
    RxRingStats rs = scanRxRing(rx, 2);
    checkU64(rs.slots, 2, "rx slots");
    checkU64(rs.owned, 1, "rx owned");
    checkU64(rs.done, 1, "rx done");
    checkU64(rs.firstAddr, 0x2A000000ULL, "rx first addr");

    // Null base must not crash and must report zero slots.
    TxRingStats tz = scanTxRing(nullptr, 8);
    checkU64(tz.slots, 0, "null tx ring reports zero slots");
    RxRingStats rz = scanRxRing(nullptr, 8);
    checkU64(rz.slots, 0, "null rx ring reports zero slots");
}

// ---------------------------------------------------------------- group 17

static void testSlotLifecycle() {
    const u32 MASK = 0x7FFFFFFFu;
    const u32 RING = 1024;

    // No close pointer: everything is snapshot-only, never "in flight".
    checkU64(txSlotLifecycle(5, 100, 0, RING, MASK, false), LIFE_SNAPSHOT,
             "without a close pointer a slot is snapshot-only");

    // Submitted 100, device handed back 40: slots 0..39 are done, 40..99 in
    // flight.
    checkU64(txSlotLifecycle(10, 100, 40, RING, MASK, true), LIFE_COMPLETED,
             "slot 10 is behind the close pointer");
    checkU64(txSlotLifecycle(90, 100, 40, RING, MASK, true), LIFE_INFLIGHT,
             "slot 90 is ahead of the close pointer");

    // Cumulative indices beyond the ring size must work.
    checkU64(txSlotCumulative(10, 5000, RING), 5000 - ((5000 - 10) & 1023),
             "cumulative index is the largest value at or below the tail");
    check(txSlotCumulative(10, 5000, RING) <= 5000,
          "and it never exceeds the tail pointer");

    // The round-6 assumption that "non-zero address means live" is not
    // expressible here: lifecycle requires the two pointers, and without
    // them it degrades to SNAPSHOT rather than INFLIGHT.
    checkU64(txSlotLifecycle(0, 0, 0, RING, MASK, false), LIFE_SNAPSHOT,
             "a freshly started ring is snapshot-only, not in-flight");
}

// ---------------------------------------------------------------- group 18

static void testRound6Replay() {
    // Replay round 6's archived fault through the round-7 core.
    //
    // From docs/evidence/20261031-201400:
    //   m2-b2-fault-addr-min = 0x405711b9c
    //   m2-b2-dma-envelope-lo = 0x29438000
    //   m2-b2-dma-envelope-hi = 0x3f80a4000   <-- demonstrably too small
    //
    // The fault is above even the (too small) envelope. Round 6 called that
    // "outside the observed DMA envelope", which was true of its envelope but
    // not a sound statement about the device's memory, for two reasons: the
    // envelope itself was broken, and the observation was a snapshot.
    const u64 R6_FAULT = 0x405711b9cULL;

    // Index decomposition must match the archived i4=0,i3=16,i2=43,i1=273.
    checkU64((R6_FAULT >> 39) & 0x1FF, 0, "i4");
    checkU64((R6_FAULT >> 30) & 0x1FF, 16, "i3");
    checkU64((R6_FAULT >> 21) & 0x1FF, 43, "i2");
    checkU64((R6_FAULT >> 12) & 0x1FF, 273, "i1");
    checkU64(((R6_FAULT >> 30) & 0x1FF) * (1ULL << 30), 0x400000000ULL,
             "L3[16] starts exactly at the 16 GiB map limit");

    // Build a round-7-correct observation from the archived descriptor
    // addresses and confirm the fault is still outside it -- but now the
    // verdict is honest about what that means.
    MapPolicy pol = policyAt(0x400000000ULL, true);
    AddrSet s;
    s.clear();
    Seg descs[6];
    descs[0].base = 0x3d1c0cdcaULL; descs[0].len = 0x200;
    descs[1].base = 0x3d7d8b2e0ULL; descs[1].len = 0x200;
    descs[2].base = 0x3818139f8ULL; descs[2].len = 0x200;
    descs[3].base = 0x3884f1ee0ULL; descs[3].len = 0x200;
    descs[4].base = 0x3fec620e0ULL; descs[4].len = 0x200;
    descs[5].base = 0x3fec600e2ULL; descs[5].len = 0x200;
    insertSegments(s, descs, 6, PURP_TX_BUF, LIFE_INFLIGHT, pol);

    check(s.envHi > 0x3fec600e2ULL,
          "the round-7 envelope contains every descriptor address");

    FaultClass snap = classifyFault(R6_FAULT, s, pol, COV_SNAPSHOT);
    check(snap.own == OWN_OBSERVED_ABSENT,
          "a snapshot yields 'absent at the observation instants'");
    check(!ownershipIsPositive(snap.own),
          "which is NOT a positive ownership claim");

    // ---- ROUND 8: only a global coverage claim may use the strongest form ----
    FaultClass win = classifyFault(R6_FAULT, s, pol, COV_WINDOW, true);
    check(win.own == OWN_OUTSIDE_ENVELOPE,
          "only window coverage licenses the stronger negative verdict");

    // With TX-only coverage the same observation yields the scoped verdict,
    // which is what round 7 should have reported: its RX path was a snapshot.
    FaultClass winTx = classifyFault(R6_FAULT, s, pol, COV_WINDOW, false);
    check(winTx.own == OWN_TX_WINDOW_ABSENT,
          "TX-only coverage cannot support the device-wide statement");
}

// ---------------------------------------------------------------- group 19
//
// ROUND 8: WINDOW SCAN -- the production collector's own logic.
//
// Round 7's m2b2CollectTxSegments() never called txSlotLifecycle(). It marked
// every non-zero TX address in-flight as soon as a close pointer was readable,
// and it ignored its own tailCum/cloCum arguments. On the round-7 capture
// tail = clo = 0x6a, i.e. the queue was empty, yet every historical address
// was reported in-flight.
//
// These tests drive scanTxWindow(), which is what production now calls, with
// the real round-7 values.

// Build a synthetic 1024-slot TX ring with the driver's descriptor layout.
struct TestRing {
    unsigned char bytes[1024 * TX_DESC_STRIDE];

    TestRing() { std::memset(bytes, 0, sizeof(bytes)); }

    void set(u32 slot, u64 addr, u32 len, u32 extraOpts = 0) {
        unsigned char *d = bytes + (u64)slot * TX_DESC_STRIDE;
        const u32 opts1 = (len & TX_DESC_LENMASK) | TX_DESC_OWN | extraOpts;
        std::memcpy(d + 0, &opts1, 4);
        const u32 opts2 = 0;
        std::memcpy(d + 4, &opts2, 4);
        std::memcpy(d + 8, &addr, 8);
    }
};

static void testWindowScanRound7Shape() {
    const u32 MASK = 0x7FFFFFFFu;
    const u32 RING = 1024;

    // The round-7 capture: tail and close pointer are EQUAL (0x6a == 0x6a).
    // The queue is drained: nothing is in flight.
    TestRing r;
    for (u32 i = 0; i < 0x6a; i++) {
        r.set(i, 0x10000000ULL + (u64)i * 0x1000ULL, 0x100);
    }

    // Window with no submits: coverage must say so, and must NOT be "covered".
    TxWindowScan s0 = scanTxWindow(r.bytes, RING, 0x6a, 0x6a, 0x6a, 0x6a,
                                   MASK, true);
    checkU64(s0.coverage.reason, TXCOV_NOTHING_SUBMITTED,
             "tail == clo == 0x6a with no submits: nothing was submitted");
    check(!s0.coverage.covered,
          "an empty window is not 'covered' and must not license a negative");
    checkU64(s0.visited, 0, "no descriptors visited");
    checkU64(s0.inflight, 0,
             "ROUND-7 DEFECT: an empty queue has ZERO in-flight descriptors");

    // Now a window that submits three descriptors (0x6a -> 0x6d) and the
    // device hands all three back (clo 0x6a -> 0x6d).
    r.set(0x6a, 0x20000000ULL, 0x200);
    r.set(0x6b, 0x20001000ULL, 0x300);
    r.set(0x6c, 0x20002000ULL, 0x400);

    TxWindowScan s1 = scanTxWindow(r.bytes, RING, 0x6a, 0x6d, 0x6a, 0x6d,
                                   MASK, true);
    checkU64(s1.coverage.reason, TXCOV_OK, "three submits: coverage is ok");
    check(s1.coverage.covered, "and the ring still holds all three");
    checkU64(s1.coverage.submits, 3, "three descriptors submitted");
    checkU64(s1.coverage.completes, 3, "three descriptors completed");
    checkU64(s1.visited, 3, "three descriptors visited");
    checkU64(s1.decoded, 3, "three decoded");
    checkU64(s1.overwritten, 0, "none overwritten");
    checkU64(s1.completedInWindow, 3, "all three completed inside the window");
    checkU64(s1.inflight, 0, "none still in flight");

    // The three completions must be attributable to specific slots, gens and
    // addresses -- that is the whole point of the round-8 collector.
    checkU64(s1.firstCompletedSlot, 0x6a, "first completion is slot 0x6a");
    checkU64(s1.firstCompletedGen, 0, "generation 0");
    checkU64(s1.firstCompletedLen, 0x200, "and it carries the real length");
    checkU64(s1.firstCompletedAddr, 0x20000000ULL, "and its real address");

    // Every descriptor must be individually attributable.
    {
        u32 seen = 0;
        u64 sum = 0;
        scanTxWindow(r.bytes, RING, 0x6a, 0x6d, 0x6a, 0x6d, MASK, true,
                     [&](const TxWindowDesc &d) {
            seen++;
            sum += d.len;
            checkU64(d.cumulative, 0x6a + seen - 1,
                     "cumulative index advances in submit order");
        });
        checkU64(seen, 3, "callback saw every window descriptor");
        checkU64(sum, 0x200 + 0x300 + 0x400,
                 "lengths come from the descriptors, not a guessed page size");
    }

    // A window where the device completed only two of three.
    TxWindowScan s2 = scanTxWindow(r.bytes, RING, 0x6a, 0x6d, 0x6a, 0x6c,
                                   MASK, true);
    checkU64(s2.completedInWindow, 2, "two completions inside the window");
    checkU64(s2.inflight, 1, "one descriptor still in flight");

    // Coverage requires submits < ringSize.
    TxWindowScan s3 = scanTxWindow(r.bytes, RING, 0, RING, 0, 0, MASK, true);
    checkU64(s3.coverage.reason, TXCOV_RING_OVERWRITTEN,
             "submitting a full ring loses the oldest descriptors");
    check(!s3.coverage.covered, "and coverage is refused");

    // Close pointer ahead of the submit pointer is impossible.
    TxWindowScan s4 = scanTxWindow(r.bytes, RING, 0x6a, 0x6b, 0x6a, 0x6f,
                                   MASK, true);
    checkU64(s4.coverage.reason, TXCOV_CLO_AHEAD_OF_TAIL,
             "completing more than was submitted is refused");

    // No pointers: coverage is refused and nothing is claimed.
    TxWindowScan s5 = scanTxWindow(r.bytes, RING, 0x6a, 0x6d, 0, 0, MASK,
                                   false);
    checkU64(s5.coverage.reason, TXCOV_NO_POINTERS,
             "without pointers there is no coverage argument");
    checkU64(s5.visited, 0, "and nothing is visited");
}

// ---------------------------------------------------------------- group 20
//
// ROUND 8: SLOT REUSE AND GENERATIONS.
//
// The coverage argument rests on "the ring still holds every descriptor
// submitted during the window". That is only true while the window submitted
// fewer than ringSize descriptors. A slot reused inside the window destroys
// the evidence for the earlier descriptor, and that must be visible rather
// than silently overwriting the record.

static void testSlotReuseAndGenerations() {
    const u32 MASK = 0x7FFFFFFFu;
    const u32 RING = 1024;

    checkU64(txGeneration(0, RING), 0, "cumulative 0 is generation 0");
    checkU64(txGeneration(1023, RING), 0, "the last slot of gen 0");
    checkU64(txGeneration(1024, RING), 1, "cumulative 1024 starts generation 1");
    checkU64(txGeneration(2048, RING), 2, "and 2048 starts generation 2");

    // A slot still holds cumulative c when nothing later reused it.
    check(txSlotStillHolds(0x6a, 0x6d, RING),
          "slot 0x6a still holds its descriptor when tail is 0x6d");
    // Exactly one full lap later, slot 0x6a has been written once more but
    // its newest write is still cumulative 0x6a itself: the NEXT submit into
    // that slot would be 0x6a + 1024, which has not happened yet.
    check(txSlotStillHolds(0x6a, 0x6a + RING, RING),
          "after a full lap the slot still holds the old descriptor");
    // One more submit past that point reuses the slot for real.
    check(!txSlotStillHolds(0x6a, 0x6a + RING + 1, RING),
          "one submit further and the slot has been reused");
    // The newest written index is tailAfter - 1, not tailAfter: reporting the
    // latter made a still-present descriptor look overwritten.
    check(!txSlotStillHolds(0x6b, 0x6b, RING),
          "a descriptor at the submit pointer itself has not been written");

    // Window coverage arithmetic.
    checkU64(txWindowSubmits(0x6a, 0x6d, MASK), 3, "three submits");
    checkU64(txWindowCompletes(0x6a, 0x6d, MASK), 3, "three completes");
    checkU64(txWindowSubmits(1000, 2024, MASK), 1024,
             "1000 -> 2024 is 1024 submits, not zero");
    checkU64(txWindowCompletes(1000, 2024, MASK), 1024,
             "and 1024 completes, not zero");

    // ---- the overwrite case, made concrete ----
    //
    // Window submits exactly ringSize descriptors. Every slot is rewritten at
    // least once, so the ring at the end of the window holds the LAST
    // generation only. Reporting "the ring holds every window descriptor"
    // here would be false.
    TxWindowCoverage full = txWindowCoverageOf(0, RING, 0, RING, RING, MASK,
                                               true);
    checkU64(full.reason, TXCOV_RING_OVERWRITTEN,
             "a full-ring window is not covered");
    checkU64(full.genBefore, 0, "generation at window start");
    checkU64(full.genAfter, 1, "generation at window end advanced");

    // One descriptor short of a full ring is still covered.
    TxWindowCoverage almost = txWindowCoverageOf(0, RING - 1, 0, RING - 1,
                                                 RING, MASK, true);
    checkU64(almost.reason, TXCOV_OK, "one short of a full ring is covered");

    // ---- a reused slot inside the window is detected, not overwritten ----
    TestRing r;
    // 5 submits inside the window; the last one reuses the first slot because
    // the ring wrapped. Use a small ring to make the wrap happen in-window.
    const u32 SMALL = 4;
    r.set(0, 0x1000, 0x10);
    r.set(1, 0x2000, 0x20);
    r.set(2, 0x3000, 0x30);
    r.set(3, 0x4000, 0x40);
    // Now overwrite slot 0 and 1 with a new generation.
    r.set(0, 0x5000, 0x50);
    r.set(1, 0x6000, 0x60);

    TxWindowScan s = scanTxWindow(r.bytes, SMALL, 0, 6, 0, 0, MASK, true);
    checkU64(s.coverage.reason, TXCOV_RING_OVERWRITTEN,
             "6 submits into a 4-slot ring loses the oldest two");
    checkU64(s.overwritten, 2,
             "the two overwritten descriptors are counted, not ignored");
    checkU64(s.decoded, 4, "the four still present are decoded");
    // Every submitted cumulative index is visited exactly once, whether or
    // not its descriptor survived. Skipping the lost ones would make
    // `overwritten` undercount and hide the loss.
    checkU64(s.visited, 6, "every submitted index is visited exactly once");

    // A descriptor present in the ring but belonging to a LATER generation
    // must not be attributed to the earlier cumulative index.
    check(!txSlotStillHolds(0, 6, SMALL),
          "slot 0 belongs to cumulative 4, not cumulative 0");
    check(txSlotStillHolds(4, 6, SMALL), "cumulative 4 is the current owner");
}

// ---------------------------------------------------------------- group 21
//
// ROUND 8: LENGTHS THAT WERE NOT DECODED.
//
// A TSO descriptor's 16-bit field is the MSS, not the length. Round 7
// substituted 0x1000 and let that guess take part in coverage arithmetic.
// A guessed length must never bound a negative.

static void testUnknownLengths() {
    const u32 MASK = 0x7FFFFFFFu;
    const u32 RING = 1024;
    const MapPolicy pol = policyAt(0x400000000ULL, true);

    TestRing r;
    r.set(0, 0x10000000ULL, 0x400, TX_DESC_GSO4);   // TSO: 0x400 is the MSS
    r.set(1, 0x10001000ULL, 0x500);                 // normal: real length
    r.set(2, 0x10002000ULL, 0);                     // zero length: unknown

    TxWindowScan s = scanTxWindow(r.bytes, RING, 0, 3, 0, 3, MASK, true);
    checkU64(s.visited, 3, "three descriptors");
    checkU64(s.tsoSlots, 1, "one TSO descriptor");
    checkU64(s.lenUnknown, 2,
             "the TSO one and the zero-length one have undecoded lengths");

    // Recorded as intervals, the unknown ones must carry the flag so a
    // coverage claim cannot quietly rely on them.
    AddrSet set;
    set.clear();
    Seg segs[3];
    u32 n = 0;
    scanTxWindow(r.bytes, RING, 0, 3, 0, 3, MASK, true,
                 [&](const TxWindowDesc &d) {
        if (d.addr == 0) return;
        segs[n].base = d.addr;
        segs[n].len = d.len;
        segs[n].flags = d.flags;
        segs[n].pad = 0;
        n++;
    });
    insertSegments(set, segs, n, PURP_TX_BUF, LIFE_INFLIGHT, pol);

    checkU64(set.savedLenUnknown, 2,
             "two stored intervals carry an undecoded length");
    check(!set.exactBounded(),
          "so the set is not exact-bounded and cannot support a negative");
    check(set.exact(), "although it is exact in the dropped/unscanned sense");

    // A set with only decodable lengths IS exact-bounded.
    AddrSet clean;
    clean.clear();
    Seg one[1];
    one[0].base = 0x10001000ULL;
    one[0].len = 0x500;
    one[0].flags = 0;
    one[0].pad = 0;
    insertSegments(clean, one, 1, PURP_TX_BUF, LIFE_INFLIGHT, pol);
    checkU64(clean.savedLenUnknown, 0, "no undecoded lengths");
    check(clean.exactBounded(), "so this set IS exact-bounded");
}

// ---------------------------------------------------------------- group 22
//
// ROUND 8: PER-PATH COVERAGE.
//
// Round 7 published one coverage value and applied it to every path. TX was
// window-covered; RX, the rings and the stats buffer were single observations.

static void testPerPathCoverage() {
    PathCoverage pc;
    pc.clear();
    checkU64(pc.weakest(), COV_NONE, "an empty record is the weakest");
    check(!pc.allWindow(), "and does not claim window coverage");

    pc.set(PATH_TX_BUF, COV_WINDOW);
    pc.set(PATH_TX_RING, COV_WINDOW);
    pc.set(PATH_RX_RING, COV_WINDOW);
    pc.set(PATH_RX_BUF, COV_SNAPSHOT);
    pc.set(PATH_STAT, COV_SNAPSHOT);
    checkU64(pc.get(PATH_TX_BUF), COV_WINDOW, "TX buffers are window-covered");
    checkU64(pc.get(PATH_RX_BUF), COV_SNAPSHOT,
             "RX buffers are only a snapshot");
    checkU64(pc.weakest(), COV_SNAPSHOT,
             "the weakest path bounds any device-wide statement");
    check(!pc.allWindow(),
          "TX being complete must not make the record claim the whole device");

    pc.set(PATH_RX_BUF, COV_WINDOW);
    check(!pc.allWindow(), "one path still behind: not all window");
    pc.set(PATH_STAT, COV_WINDOW);
    check(pc.allWindow(), "every path window-covered: now it may claim so");
}

// ---------------------------------------------------------------- group 23
//
// ROUND 8: THE BASIS FOR READING RING MEMORY.
//
// readVerdictDeviceReported() only proves "a register names this address".
// That is not the same as "this PA is the driver's ring object and it is
// alive". A fingerprint that can actually fail is the minimum honest check.

static void testRingBasis() {
    check(std::strcmp(ringBasisName(RB_REGISTER_ONLY), "register-only") == 0,
          "register-only is named honestly");
    check(std::strstr(ringBasisName(RB_FINGERPRINT), "fingerprint") != nullptr,
          "the strongest basis names the fingerprint");

    // An all-zero page is not a ring: no address anywhere.
    unsigned char zero[1024 * TX_DESC_STRIDE];
    std::memset(zero, 0, sizeof(zero));
    TxRingFingerprint fz = txRingFingerprint(zero, 1024);
    check(!fz.ok, "an all-zero page is not accepted as a TX ring");
    checkU64(fz.decoded, 0, "and it decodes nothing");

    // A ring with programmed descriptors passes.
    TestRing r;
    for (u32 i = 0; i < 8; i++) r.set(i, 0x10000000ULL + (u64)i * 0x1000ULL,
                                      0x100);
    TxRingFingerprint fr = txRingFingerprint(r.bytes, 1024);
    check(fr.ok, "a ring with programmed descriptors passes");
    checkU64(fr.decoded, 8, "eight decoded descriptors");
    checkU64(fr.badLen, 0, "no impossible lengths");

    // A descriptor with a zero length and no TSO bit is impossible: the
    // driver always writes a real length or a TSO command bit.
    TestRing bad;
    bad.set(0, 0x10000000ULL, 0x100);
    {
        unsigned char *d = bad.bytes;
        const u32 opts1 = TX_DESC_OWN;      // length 0, no TSO
        std::memcpy(d, &opts1, 4);
        const u64 a = 0x20000000ULL;
        std::memcpy(d + 8, &a, 8);
    }
    TxRingFingerprint fb = txRingFingerprint(bad.bytes, 1024);
    check(!fb.ok, "a zero-length non-TSO descriptor fails the fingerprint");
    checkU64(fb.badLen, 1, "and is counted");

    // RX: the driver writes RingEnd into the LAST descriptor at setup and
    // never clears it. Its presence at that index is the structural mark.
    unsigned char rx[1024 * RX_DESC_STRIDE];
    std::memset(rx, 0, sizeof(rx));
    RxRingFingerprint rz = rxRingFingerprint(rx, 1024);
    check(!rz.ok, "an all-zero page is not accepted as an RX ring");

    for (u32 i = 0; i < 1024; i++) {
        unsigned char *d = rx + (u64)i * RX_DESC_STRIDE;
        const u32 blen = 0x1000 | RX_DESC_OWN;
        std::memcpy(d, &blen, 4);
        const u64 a = 0x30000000ULL + (u64)i * 0x1000ULL;
        std::memcpy(d + 8, &a, 8);
    }
    {
        unsigned char *d = rx + (u64)1023 * RX_DESC_STRIDE;
        u32 blen = 0;
        std::memcpy(&blen, d, 4);
        blen |= RX_DESC_RINGEND;
        std::memcpy(d, &blen, 4);
    }
    RxRingFingerprint rg = rxRingFingerprint(rx, 1024);
    check(rg.ok, "the driver's RX ring shape passes");
    checkU64(rg.ringEndAtLast, 1, "RingEnd is at the last slot");
    checkU64(rg.decoded, 1024, "every slot has an address");

    // Move RingEnd off the last slot: the fingerprint must fail.
    {
        unsigned char *last = rx + (u64)1023 * RX_DESC_STRIDE;
        u32 blen = 0;
        std::memcpy(&blen, last, 4);
        blen &= ~RX_DESC_RINGEND;
        std::memcpy(last, &blen, 4);
        unsigned char *mid = rx + (u64)500 * RX_DESC_STRIDE;
        std::memcpy(&blen, mid, 4);
        blen |= RX_DESC_RINGEND;
        std::memcpy(mid, &blen, 4);
    }
    RxRingFingerprint rw = rxRingFingerprint(rx, 1024);
    check(!rw.ok, "RingEnd anywhere else fails the fingerprint");
}

// ---- ROUND 9: the scan must be bounded and must stop on a bad pair --------
//
// Round 8 looped `submits` times, and `submits` is a 31-bit masked difference.
// A counter reset, a device swap, or a torn read therefore became a loop of up
// to 2^31 iterations inside the kernel -- triggered by exactly the condition
// that says the numbers cannot be trusted. These tests assert the stop, not
// just that a reason was recorded.
static void testScanBounds() {
    TestRing r;
    for (u32 i = 0; i < 16; i++) r.set(i, 0x20000000ULL + (u64)i * 0x1000ULL,
                                       0x100);

    // (a) A delta at or above half the mask is a reset, not a window.
    {
        const u32 mask = 0x7FFFFFFFu;
        const u32 tailBefore = 0x10;
        const u32 tailAfter = (tailBefore + 0x40000000u) & mask;  // huge
        TxWindowScan s = scanTxWindow(r.bytes, 1024, tailBefore, tailAfter,
                                      tailBefore, tailAfter, mask, true);
        checkU64(s.stopReason, TXSCAN_RESET,
                 "an implausible delta stops the scan as a reset");
        checkU64(s.visited, 0,
                 "and visits NOTHING: the loop never runs");
        checkU64(s.coverage.reason, TXCOV_IMPLAUSIBLE,
                 "coverage agrees with the stop reason");
    }

    // (b) A close pointer ahead of the submit pointer is impossible.
    {
        const u32 mask = 0x7FFFFFFFu;
        TxWindowScan s = scanTxWindow(r.bytes, 1024, 0x100, 0x104,
                                      0x200, 0x204, mask, true);
        checkU64(s.stopReason, TXSCAN_IMPLAUSIBLE,
                 "a close pointer past the submit pointer stops the scan");
        checkU64(s.visited, 0, "and nothing is visited");
    }

    // (c) A legal but large window is capped, and the skipped indices are
    //     COUNTED, not iterated. 5000 > TX_MAX_WINDOW_SCAN (4096).
    {
        const u32 mask = 0x7FFFFFFFu;
        TxWindowScan s = scanTxWindow(r.bytes, 1024, 0x0, 5000,
                                      0x0, 5000, mask, true);
        checkU64(s.stopReason, TXSCAN_CAP, "an oversized window is capped");
        checkU64(s.visited, TX_MAX_WINDOW_SCAN,
                 "exactly the cap is visited");
        checkU64(s.historicalSkipped, 5000 - TX_MAX_WINDOW_SCAN,
                 "the remainder is counted arithmetically");
        checkU64(s.visited + s.historicalSkipped, 5000,
                 "visited plus skipped accounts for every submitted index");
    }

    // (d) The cap must be non-exact, so coverage eligibility is withdrawn.
    {
        const u32 mask = 0x7FFFFFFFu;
        TxWindowScan s = scanTxWindow(r.bytes, 1024, 0x0, 5000,
                                      0x0, 5000, mask, true);
        TxWindowQuality q = txWindowQualityOf(s, 0);
        check(!q.exact, "a capped scan is not exact");
        check(std::strcmp(txWindowQualityName(q), "scan-cap") == 0,
              "and says so by name");
    }

    // (e) A window with no descriptors at all is not an error, but it covers
    //     nothing either.
    {
        const u32 mask = 0x7FFFFFFFu;
        TxWindowScan s = scanTxWindow(r.bytes, 1024, 0x40, 0x40,
                                      0x40, 0x40, mask, true);
        checkU64(s.stopReason, TXSCAN_OK, "an empty window scans cleanly");
        checkU64(s.coverage.reason, TXCOV_NOTHING_SUBMITTED,
                 "and reports that nothing was submitted");
        check(!s.coverage.covered, "an empty window covers nothing");
    }
}

// ---- ROUND 9: 31-bit wrap must use the counter mask, not plain 32-bit ----
static void testCounterWrap() {
    const u32 mask = 0x7FFFFFFFu;

    // A window that crosses the 31-bit boundary. Plain u32 subtraction gives
    // 0x8000000A here (a huge number); the masked difference is 10.
    const u32 before = 0x7FFFFFFBu;      // 2147483643
    const u32 after  = 0x00000005u;      // 5
    checkU64(txWindowSubmits(before, after, mask), 10,
             "a submit window crossing the 31-bit boundary is 10, not 2^31+10");
    checkU64(txWindowCompletes(before, after, mask), 10,
             "the completion window uses the same masking");
    check((u32)(after - before) != 10u,
          "plain 32-bit subtraction would NOT give 10 (the defect)");

    // The same pair through the coverage function must be accepted.
    TxWindowCoverage c = txWindowCoverageOf(before, after, before, after,
                                            1024, mask, true);
    checkU64(c.submits, 10, "coverage agrees the window is 10 descriptors");
    checkU64(c.completes, 10, "and that 10 completed");
    checkU64(c.reason, TXCOV_OK, "a wrapping window is not an error");

    // A window whose masked distance is not representable must be refused.
    TxWindowCoverage bad = txWindowCoverageOf(0, 0x40000000u, 0, 0x40000000u,
                                              1024, mask, true);
    checkU64(bad.reason, TXCOV_IMPLAUSIBLE,
             "a distance at half the mask is refused as a reset");
}

// ---- ROUND 9: a window that opens with a busy queue -----------------------
//
// "Completes > submits" is the NORMAL outcome when the window inherits work.
// Round 8 compared `com > sub` and refused it -- rejecting the legal case --
// while accepting a close pointer that had run past the submit pointer at the
// window's end. Both halves of that comparison were wrong.
static void testPreWindowInFlight() {
    const u32 mask = 0x7FFFFFFFu;

    // 5 descriptors were already in flight; the window submits 3 more and the
    // device hands back 6 (the 5 old ones plus 1 of the new).
    const u32 tailBefore = 0x100;
    const u32 cloBefore  = tailBefore - 5;      // 5 behind
    const u32 tailAfter  = tailBefore + 3;
    const u32 cloAfter   = cloBefore + 6;

    TxWindowCoverage c = txWindowCoverageOf(tailBefore, tailAfter,
                                            cloBefore, cloAfter,
                                            1024, mask, true);
    checkU64(c.inFlightAtStart, 5,
             "the queue depth at the window start is recorded");
    checkU64(c.submits, 3, "3 submitted inside the window");
    checkU64(c.completes, 6, "6 handed back inside the window");
    checkU64(c.preWindowCompleted, 5,
             "5 of those completions belong to the older population");
    checkU64(c.reason, TXCOV_OK,
             "completes > submits is legal when the window opened busy");
    check(c.covered, "and the window still covers its own descriptors");

    // The same numbers with an empty queue at the start would be impossible.
    TxWindowCoverage bad = txWindowCoverageOf(tailBefore, tailAfter,
                                              tailBefore, tailAfter + 3,
                                              1024, mask, true);
    checkU64(bad.reason, TXCOV_CLO_AHEAD_OF_TAIL,
             "completing more than were ever submitted is still refused");

    // A drained queue at the start: every completion is a window completion.
    TxWindowCoverage drained = txWindowCoverageOf(0x200, 0x203,
                                                  0x200, 0x203,
                                                  1024, mask, true);
    checkU64(drained.inFlightAtStart, 0, "a drained queue starts at zero");
    checkU64(drained.preWindowCompleted, 0,
             "so no completion belongs to an older population");
}

// ---- ROUND 9: scan quality must withdraw coverage, not just report ------
static void testScanQuality() {
    // 64 slots programmed, so windows starting at index 16 have real data.
    TestRing r;
    for (u32 i = 0; i < 64; i++) r.set(i, 0x20000000ULL + (u64)i * 0x1000ULL,
                                       0x100);

    const u32 mask = 0x7FFFFFFFu;

    // A clean window: 3 submitted, 3 decoded, all completed.
    {
        TxWindowScan s = scanTxWindow(r.bytes, 1024, 0x10, 0x13,
                                      0x10, 0x13, mask, true);
        checkU64(s.visited, 3, "the clean window visited 3");
        checkU64(s.decoded, 3, "and decoded 3");
        checkU64(s.overwritten, 0, "with nothing overwritten");
        checkU64(s.lenUnknown, 0, "and no undecodable length");
        TxWindowQuality q = txWindowQualityOf(s, 0);
        check(q.exact, "a clean 3-descriptor window is exact");
        check(std::strcmp(txWindowQualityName(q), "exact") == 0,
              "and is named exact");
    }

    // One record lost by the caller: the scan saw it, the collector could not
    // keep it. That must withdraw exactness.
    {
        TxWindowScan s = scanTxWindow(r.bytes, 1024, 0x10, 0x13,
                                      0x10, 0x13, mask, true);
        TxWindowQuality q = txWindowQualityOf(s, 1);
        check(!q.exact, "a lost record makes the scan non-exact");
        check(std::strcmp(txWindowQualityName(q), "records-lost") == 0,
              "and the reason names the loss");
    }

    // A TSO descriptor has no decodable length, so the scan is not exact even
    // though every descriptor was visited.
    {
        TestRing t;
        t.set(0, 0x30000000ULL, 0x100);
        {
            unsigned char *d = t.bytes;
            u32 opts1 = TX_DESC_GSO4 | TX_DESC_OWN | 0x05b4;   // MSS in the
            std::memcpy(d, &opts1, 4);                         // length field
            u64 a = 0x30000000ULL;
            std::memcpy(d + 8, &a, 8);
        }
        TxWindowScan s = scanTxWindow(t.bytes, 1024, 0x0, 0x1, 0x0, 0x1,
                                      mask, true);
        checkU64(s.lenUnknown, 1, "the TSO descriptor's length is unknown");
        TxWindowQuality q = txWindowQualityOf(s, 0);
        check(!q.exact, "an undecodable length makes the scan non-exact");
        check(std::strcmp(txWindowQualityName(q), "undecodable-length") == 0,
              "and the reason names the length");
    }

    // A slot that was reused cannot be examined, so the scan is not exact.
    {
        TestRing small;
        for (u32 i = 0; i < 4; i++)
            small.set(i, 0x40000000ULL + (u64)i * 0x1000ULL, 0x100);
        // 6 submits into a 4-slot ring: the first 2 are overwritten.
        TxWindowScan s = scanTxWindow(small.bytes, 4, 0x0, 0x6, 0x0, 0x6,
                                      mask, true);
        checkU64(s.overwritten, 2, "2 of the 6 were overwritten");
        checkU64(s.visited, 6, "all 6 were visited");
        checkU64(s.decoded, 4, "4 could be decoded");
        TxWindowQuality q = txWindowQualityOf(s, 0);
        check(!q.exact, "overwritten slots make the scan non-exact");
        check(std::strcmp(txWindowQualityName(q), "slots-overwritten") == 0,
              "and the reason names the overwrite");
    }

    // A decoded-but-zero address is also not exact: there is nothing to
    // attribute and nothing to record. Slot 0 of a fresh ring is untouched,
    // so its address field is zero.
    {
        TestRing z;
        for (u32 i = 1; i < 8; i++)
            z.set(i, 0x50000000ULL + (u64)i * 0x1000ULL, 0x100);
        TxWindowScan s = scanTxWindow(z.bytes, 1024, 0x0, 0x1, 0x0, 0x1,
                                      mask, true);
        checkU64(s.visited, 1, "one index visited");
        checkU64(s.addrZero, 1, "a zero address is counted");
        TxWindowQuality q = txWindowQualityOf(s, 0);
        check(!q.exact, "a zero address makes the scan non-exact");
        check(std::strcmp(txWindowQualityName(q), "undecodable-address") == 0,
              "and the reason names the address");
    }
}

// ---- ROUND 10: the v2 snapshot, its seqlock, its identity, its verdicts ---
//
// Every test here compiles the SAME header the kext includes, so a change that
// breaks the production path breaks these tests too.

// Lay out one v2 snapshot in `buf`: header, then `n` records whose seq values
// are ticket*2 (published) unless `busyIndex` is >= 0, in which case that
// record's seq is ticket*2+1 (mid-write).
struct V2Snap {
    unsigned char buf[OBS_HDR_BYTES + 16 * OBS_REC_BYTES];
    u64 bytes;
    ObsHeader hdr;
};

static void v2Header(unsigned char *buf, u32 firstTicket, u32 count,
                     u64 tPublished, u32 epoch, u32 bdf, u32 vid, u32 did,
                     u32 ifUnit, u64 mac, u32 flags, u32 lostCount,
                     u32 pubId) {
    std::memset(buf, 0, OBS_HDR_BYTES + (u64)count * OBS_REC_BYTES);
    u32 magic = OBS_MAGIC, ver = OBS_VERSION, rs = OBS_REC_BYTES;
    u32 cap = OBS_CAPACITY;
    u32 head = firstTicket + count;
    u32 wrapped = 0, dropped = 0;
    u32 lastTicket = count ? (firstTicket + count - 1) : 0;
    u32 validCount = count - lostCount;
    u32 macHi = (u32)(mac >> 16);
    u32 macLo = (u32)(mac & 0xFFFFu);
    u64 tStart = 1000;
    u64 reserved = 0;
    std::memcpy(buf + 0, &magic, 4);
    std::memcpy(buf + 4, &ver, 4);
    std::memcpy(buf + 8, &rs, 4);
    std::memcpy(buf + 12, &cap, 4);
    std::memcpy(buf + 16, &head, 4);
    std::memcpy(buf + 20, &wrapped, 4);
    std::memcpy(buf + 24, &dropped, 4);
    std::memcpy(buf + 28, &pubId, 4);
    std::memcpy(buf + 32, &firstTicket, 4);
    std::memcpy(buf + 36, &lastTicket, 4);
    std::memcpy(buf + 40, &validCount, 4);
    std::memcpy(buf + 44, &lostCount, 4);
    std::memcpy(buf + 48, &epoch, 4);
    std::memcpy(buf + 52, &bdf, 4);
    std::memcpy(buf + 56, &vid, 4);
    std::memcpy(buf + 60, &did, 4);
    std::memcpy(buf + 64, &ifUnit, 4);
    std::memcpy(buf + 68, &macHi, 4);
    std::memcpy(buf + 72, &macLo, 4);
    std::memcpy(buf + 76, &flags, 4);
    std::memcpy(buf + 80, &tStart, 8);
    std::memcpy(buf + 88, &tPublished, 8);
    std::memcpy(buf + 96, &reserved, 8);
}

static void v2Rec(unsigned char *buf, u32 index, u32 firstTicket, u32 kind,
                  u32 cumulative, u32 slot, u64 addr, u32 len, u32 flags,
                  u64 tMono, u32 token, u32 reqId, u32 pktFlags,
                  bool busy) {
    unsigned char *r = buf + OBS_HDR_BYTES + (u64)index * OBS_REC_BYTES;
    const u32 ticket = firstTicket + index;
    u32 seq = busy ? ((ticket << 1) | 1u) : (ticket << 1);
    u32 gen = cumulative / 1024u;
    u32 batch = cumulative;
    u32 o1 = 0, o2 = 0, flow = 0x1234;
    std::memcpy(r + 0, &tMono, 8);
    std::memcpy(r + 8, &addr, 8);
    std::memcpy(r + 16, &seq, 4);
    std::memcpy(r + 20, &kind, 4);
    std::memcpy(r + 24, &cumulative, 4);
    std::memcpy(r + 28, &slot, 4);
    std::memcpy(r + 32, &gen, 4);
    std::memcpy(r + 36, &batch, 4);
    std::memcpy(r + 40, &o1, 4);
    std::memcpy(r + 44, &o2, 4);
    std::memcpy(r + 48, &len, 4);
    std::memcpy(r + 52, &flags, 4);
    std::memcpy(r + 56, &token, 4);
    std::memcpy(r + 60, &reqId, 4);
    std::memcpy(r + 64, &flow, 4);
    std::memcpy(r + 68, &pktFlags, 4);
}

// A one-segment packet: descriptor 0 is both the first and the
// last fragment. The driver emits exactly this (round-10 archive:
// every business TX submit carries flags = 0xc).
static const u32 kFragBoth = OBS_FLAG_FIRST_FRAG | OBS_FLAG_LAST_FRAG;

// --- 1. the header guard rejects every malformed shape -------------------
static void testV2HeaderGuard() {
    unsigned char buf[OBS_HDR_BYTES + 8 * OBS_REC_BYTES];
    v2Header(buf, 100, 8, 5000, 42, 0x2500, 0x10EC, 0x8127, 2,
             0x1c860b3b0bbdULL, 0, 0, 7);
    const u64 bytes = OBS_HDR_BYTES + 8 * OBS_REC_BYTES;
    for (u32 i = 0; i < 8; i++)
        v2Rec(buf, i, 100, OBS_KIND_TX_SUBMIT, i, i, 0x1000ULL * i, 42, 0,
              2000 + i, 0, 0, 0, false);

    ObsHeader h = obsHeaderOk(buf, bytes);
    check(h.ok, "a well-formed v2 snapshot is accepted");
    checkU64(h.recordCount, 8, "and reports eight records");
    checkU64(h.pubId, 7, "the publication id is decoded");
    checkU64(h.ifUnit, 2, "the interface unit is decoded");

    // Wrong magic.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        u32 bad = 0xDEADBEEFu;
        std::memcpy(t, &bad, 4);
        ObsHeader x = obsHeaderOk(t, bytes);
        check(!x.ok, "a bad magic is refused");
        check(std::strcmp(x.why, "bad magic") == 0, "and the reason is named");
    }
    // A v1 snapshot must be refused, not misparsed: v1's header is 48 bytes
    // and its records are 56, so decoding it as v2 would read garbage.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        u32 v1magic = 0x314F4C52u, v1ver = 1u, v1rs = 56u, v1cap = 4096u;
        std::memcpy(t + 0, &v1magic, 4);
        std::memcpy(t + 4, &v1ver, 4);
        std::memcpy(t + 8, &v1rs, 4);
        std::memcpy(t + 12, &v1cap, 4);
        ObsHeader x = obsHeaderOk(t, bytes);
        check(!x.ok, "a round-9 v1 snapshot is refused");
    }
    // Record size mismatch.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        u32 bad = 64;
        std::memcpy(t + 8, &bad, 4);
        check(!obsHeaderOk(t, bytes).ok, "a wrong record size is refused");
    }
    // Capacity mismatch.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        u32 bad = 1024;
        std::memcpy(t + 12, &bad, 4);
        check(!obsHeaderOk(t, bytes).ok, "a wrong capacity is refused");
    }
    // Ragged body.
    check(!obsHeaderOk(buf, bytes - 4).ok,
          "a body that is not a whole number of records is refused");
    // validCount + lostCount must equal the record count.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        u32 bad = 3;
        std::memcpy(t + 44, &bad, 4);
        check(!obsHeaderOk(t, bytes).ok,
              "valid+lost disagreeing with the record count is refused");
    }
    // The ticket range must span the record count.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        u32 bad = 103;     // first=100, last should be 107
        std::memcpy(t + 36, &bad, 4);
        check(!obsHeaderOk(t, bytes).ok,
              "a ticket range that does not span the records is refused");
    }
    // head must be past the last ticket.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        u32 bad = 100;
        std::memcpy(t + 16, &bad, 4);
        check(!obsHeaderOk(t, bytes).ok,
              "a head behind the last ticket is refused");
    }
    // Published before the log existed.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        u64 bad = 1;
        std::memcpy(t + 88, &bad, 8);
        check(!obsHeaderOk(t, bytes).ok,
              "a publication older than the log is refused");
    }
    // Publication id zero is not a publication.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        u32 bad = 0;
        std::memcpy(t + 28, &bad, 4);
        check(!obsHeaderOk(t, bytes).ok, "publication id zero is refused");
    }
    // Truncated buffer.
    check(!obsHeaderOk(buf, OBS_HDR_BYTES - 1).ok,
          "a buffer shorter than a header is refused");
}

// --- 2. the seqlock: a busy record is never used -------------------------
//
// This is the defect round 9 shipped. v1 wrote seq only at the end, so a
// reader arriving mid-write saw the PREVIOUS seq before and after its body
// read and called the record valid. v2 marks the slot busy first.
static void testV2Seqlock() {
    unsigned char buf[OBS_HDR_BYTES + 4 * OBS_REC_BYTES];
    const u64 bytes = OBS_HDR_BYTES + 4 * OBS_REC_BYTES;
    v2Header(buf, 10, 4, 9000, 1, 0x2500, 0x10EC, 0x8127, 2, 0x112233445566ULL,
             0, 0, 1);
    v2Rec(buf, 0, 10, OBS_KIND_TX_SUBMIT, 0, 0, 0xAAA0, 42, 0, 100, 0, 0, 0,
          false);
    // Record 1 is mid-write: seq is odd.
    v2Rec(buf, 1, 10, OBS_KIND_TX_SUBMIT, 1, 1, 0xBBB0, 42, 0, 200, 0, 0, 0,
          true);
    v2Rec(buf, 2, 10, OBS_KIND_TX_SUBMIT, 2, 2, 0xCCC0, 42, 0, 300, 0, 0, 0,
          false);
    v2Rec(buf, 3, 10, OBS_KIND_TX_SUBMIT, 3, 3, 0xDDD0, 42, 0, 400, 0, 0, 0,
          false);

    const ObsHeader h = obsHeaderOk(buf, bytes);
    check(h.ok, "the snapshot with one busy record is structurally valid");
    check(!obsReadRecAt(buf, h, 1).valid,
          "a record whose seq is odd (mid-write) is refused");
    check(obsReadRecAt(buf, h, 0).valid, "its neighbours are still usable");
    check(obsReadRecAt(buf, h, 2).valid, "and so is the one after it");

    // The join must count the busy record as a hole, not as a submit.
    ObsJoin j = obsJoin(buf, bytes, 1024, 0, 0, 0);
    checkU64(j.holes, 1, "the busy record is counted as a hole");
    checkU64(j.submits, 3, "and is not counted as a submit");
    check(!j.recordsCoverWindow,
          "a snapshot with a hole cannot claim window coverage");

    // A record whose seq belongs to a DIFFERENT ticket (stale body from an
    // earlier lap of the ring) must also be refused.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        v2Rec(t, 1, 10, OBS_KIND_TX_SUBMIT, 1, 1, 0xBBB0, 42, 0, 200, 0, 0, 0,
              false);
        // Now stamp it with ticket 11's seq instead of 11's own.
        u32 wrong = (20u << 1);
        std::memcpy(t + OBS_HDR_BYTES + OBS_REC_BYTES + 16, &wrong, 4);
        const ObsHeader h2 = obsHeaderOk(t, bytes);
        check(!obsReadRecAt(t, h2, 1).valid,
              "a record stamped with another ticket's seq is refused");
    }
    // seq == 0 is an explicit hole.
    {
        unsigned char t[sizeof(buf)];
        std::memcpy(t, buf, bytes);
        u32 zero = 0;
        std::memcpy(t + OBS_HDR_BYTES + 16, &zero, 4);
        const ObsHeader h2 = obsHeaderOk(t, bytes);
        check(!obsReadRecAt(t, h2, 0).valid, "seq zero is an explicit hole");
    }
}

// --- 3. identity: a snapshot from another device is refused --------------
static void testV2Identity() {
    unsigned char buf[OBS_HDR_BYTES + 2 * OBS_REC_BYTES];
    const u64 bytes = OBS_HDR_BYTES + 2 * OBS_REC_BYTES;
    v2Header(buf, 1, 2, 9000, 55, 0x2500, 0x10EC, 0x8127, 2,
             0x1c860b3b0bbdULL, 0, 0, 3);
    v2Rec(buf, 0, 1, OBS_KIND_TX_SUBMIT, 0, 0, 0x1000, 42, 0, 100, 0, 0, 0,
          false);
    v2Rec(buf, 1, 1, OBS_KIND_TX_DONE, 0, 0, 0, 0, 0, 200, 0, 0, 0, false);
    const ObsHeader h = obsHeaderOk(buf, bytes);
    check(h.ok, "the identity fixture is well formed");

    ObsIdentity want;
    want.busDevFn = 0x2500; want.vendorId = 0x10EC; want.deviceId = 0x8127;
    want.ifUnit = 2;
    want.macHi = 0x1c860b3b; want.macLo = 0x0bbd;
    want.epoch = 55; want.have = true;
    const char *why = nullptr;
    check(obsIdentityMatches(h, want, &why), "a matching identity is accepted");
    check(std::strcmp(why, "ok") == 0, "and the reason is ok");

    // Each field must be able to reject on its own.
    { ObsIdentity w = want; w.busDevFn = 0x2501;
      check(!obsIdentityMatches(h, w, &why), "a different BDF is refused");
      check(std::strcmp(why, "bdf-mismatch") == 0, "reason names the BDF"); }
    { ObsIdentity w = want; w.vendorId = 0x8086;
      check(!obsIdentityMatches(h, w, &why), "a different vendor is refused");
      check(std::strcmp(why, "vendor-mismatch") == 0, "reason names the vendor"); }
    { ObsIdentity w = want; w.deviceId = 0x8125;
      check(!obsIdentityMatches(h, w, &why), "a different device is refused");
      check(std::strcmp(why, "device-mismatch") == 0, "reason names the device"); }
    { ObsIdentity w = want; w.ifUnit = 0;
      check(!obsIdentityMatches(h, w, &why), "a different interface is refused");
      check(std::strcmp(why, "interface-unit-mismatch") == 0,
            "reason names the interface"); }
    { ObsIdentity w = want; w.macHi ^= 1;
      check(!obsIdentityMatches(h, w, &why), "a different MAC is refused");
      check(std::strcmp(why, "mac-mismatch") == 0, "reason names the MAC"); }
    { ObsIdentity w = want; w.epoch = 54;
      check(!obsIdentityMatches(h, w, &why), "a different epoch is refused");
      check(std::strcmp(why, "epoch-mismatch") == 0, "reason names the epoch"); }
    // An undeclared identity is NOT a pass.
    { ObsIdentity w = want; w.have = false;
      check(!obsIdentityMatches(h, w, &why),
            "an undeclared identity is not a pass");
      check(std::strcmp(why, "identity-not-declared") == 0,
            "and says so"); }
}

// --- 4. the three verdicts are independent ------------------------------
//
// The whole point of round 10's rework: "one pair succeeded" must not stand in
// for "the records cover the window", and neither may stand in for "the batch
// finished". Each of the three must be able to fail while the others hold.
static void testV2ThreeVerdicts() {
    const u64 winStart = 2000, winEnd = 8000;
    unsigned char buf[OBS_HDR_BYTES + 16 * OBS_REC_BYTES];

    // ---- case A: everything holds ----
    {
        const u32 n = 6;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        // One record before the window so the snapshot reaches back past it.
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42, kFragBoth,
              3000, 7, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 2, 1, OBS_KIND_TX_DOORBELL, 97, 0, 0, 0, 0, 3100, 7, 1,
              OBS_PKT_PARSED, false);
        v2Rec(buf, 3, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0,
              false);
        v2Rec(buf, 4, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 60, 0, 4000,
              7, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 5, 1, OBS_KIND_RX_DONE, 951, 951, 0x1f002000, 60, 0, 8500,
              0, 0, 0, false);
        const ObsBatchSpec spec = obsBatchSpecOf(1, 7, winStart, winEnd);
        ObsJoin j = obsJoin(buf, bytes, 1024, spec);
        check(j.hasCompletePair, "A: a complete pair exists");
        check(j.recordsCoverWindow, "A: the records cover the window");
        check(j.controlledBatchComplete, "A: the batch is complete");
        checkU64(j.winPaired, 1, "A: one window-internal pair");
        checkU64(j.batchComplete, 1, "A: one request fully accounted");
        checkU64(j.batchMissing, 0, "A: nothing missing");
    }

    // ---- case B: one pair, but the snapshot predates the window end ----
    //
    // This is EXACTLY round 9's state: published at 39963682435 with the
    // window ending at 40494639566. Round 9 called it covered.
    {
        const u32 n = 6;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 5000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);   // published BEFORE winEnd
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42, kFragBoth,
              3000, 7, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 2, 1, OBS_KIND_TX_DOORBELL, 97, 0, 0, 0, 0, 3100, 7, 1,
              OBS_PKT_PARSED, false);
        v2Rec(buf, 3, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0,
              false);
        v2Rec(buf, 4, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 60, 0, 4000,
              7, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 5, 1, OBS_KIND_RX_DONE, 951, 951, 0x1f002000, 60, 0, 4500,
              0, 0, 0, false);
        const ObsBatchSpec spec = obsBatchSpecOf(1, 0, winStart, winEnd);
        ObsJoin j = obsJoin(buf, bytes, 1024, spec);
        check(j.hasCompletePair, "B: the pair is still there");
        check(!j.recordsCoverWindow,
              "B: but the snapshot does NOT cover the window");
        checkU64(j.coverState, OBS_COVER_TOO_LATE,
                 "B: the reason is that it was published too early");
        check(std::strcmp(j.coverWhy, "published-before-window-end") == 0,
              "B: and the reason token is stable");
    }

    // ---- case C: coverage holds, but a request is missing from the batch --
    {
        const u32 n = 4;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        // Only request 1; request 2 was declared but never appears.
        v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42, kFragBoth,
              3000, 7, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 2, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0,
              false);
        v2Rec(buf, 3, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 60, 0, 4000,
              7, 1, OBS_PKT_PARSED, false);
        const ObsBatchSpec spec = obsBatchSpecOf(2, 7, winStart, winEnd);
        ObsJoin j = obsJoin(buf, bytes, 1024, spec);
        check(j.hasCompletePair, "C: a pair exists");
        check(j.recordsCoverWindow, "C: the records cover the window");
        check(!j.controlledBatchComplete,
              "C: but the declared batch is NOT complete");
        checkU64(j.batchMissing, 1, "C: one declared request has no record");
        check(std::strcmp(j.batchWhy, "requests-missing") == 0,
              "C: and the reason names it");
    }

    // ---- case D: a request submitted inside the window but not completed --
    //
    // This is the "unfinished submit must not be hidden by a successful pair"
    // requirement. Request 2 is submitted and never completes.
    {
        const u32 n = 5;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42, kFragBoth,
              3000, 7, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 2, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0,
              false);
        v2Rec(buf, 3, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 60, 0, 4000,
              7, 1, OBS_PKT_PARSED, false);
        // Request 2: submitted, never completed.
        v2Rec(buf, 4, 1, OBS_KIND_TX_SUBMIT, 97, 97, 0x3ebc122e0ULL, 42, kFragBoth,
              5000, 7, 2, OBS_PKT_PARSED, false);
        const ObsBatchSpec spec = obsBatchSpecOf(2, 7, winStart, winEnd);
        ObsJoin j = obsJoin(buf, bytes, 1024, spec);
        check(j.hasCompletePair, "D: request 1 is a complete pair");
        checkU64(j.winUncompleted, 1,
                 "D: the unfinished submit is counted, not hidden");
        check(!j.controlledBatchComplete,
              "D: the batch is incomplete because request 2 never finished");
        check(std::strcmp(j.batchWhy, "requests-incomplete") == 0,
              "D: and the reason names it");
    }

    // ---- case E: an orphan completion is counted from raw records --------
    //
    // A completion inside the window whose submit appears NOWHERE in the
    // snapshot is a genuine orphan. A completion whose submit is simply
    // BEFORE the window is a legitimate pre-window in-flight item. Round 9
    // conflated them.
    {
        const u32 n = 4;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        // A submit BEFORE the window...
        v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 90, 90, 0xAAAA0, 42, 0, 1000,
              0, 0, 0, false);
        // ...whose completion lands INSIDE it.
        v2Rec(buf, 2, 1, OBS_KIND_TX_DONE, 90, 90, 0, 0, 0, 4000, 0, 0, 0,
              false);
        // A completion inside the window with no submit at all.
        v2Rec(buf, 3, 1, OBS_KIND_TX_DONE, 777, 777, 0, 0, 0, 5000, 0, 0, 0,
              false);
        const ObsBatchSpec spec = obsBatchSpecOf(0, 0, winStart, winEnd);
        ObsJoin j = obsJoin(buf, bytes, 1024, spec);
        checkU64(j.winPreWindowInFlight, 1,
                 "E: a pre-window submit completing inside is not an orphan");
        checkU64(j.winOrphanDone, 1,
                 "E: a completion with no submit anywhere IS an orphan");
    }

    // ---- case F: a snapshot that does not reach back to the window start --
    {
        const u32 n = 3;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        // Every record is already inside the window.
        v2Rec(buf, 0, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42, kFragBoth,
              3000, 7, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 1, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0,
              false);
        v2Rec(buf, 2, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 60, 0, 4000,
              7, 1, OBS_PKT_PARSED, false);
        const ObsBatchSpec spec = obsBatchSpecOf(1, 0, winStart, winEnd);
        ObsJoin j = obsJoin(buf, bytes, 1024, spec);
        check(!j.recordsCoverWindow,
              "F: a snapshot that starts inside the window does not cover it");
        checkU64(j.coverState, OBS_COVER_TOO_EARLY,
                 "F: the reason is that it does not reach back");
    }

    // ---- case G: an overflowed ring cannot claim coverage ----------------
    {
        const u32 n = 4;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, OBS_HDR_OVERFLOWED, 0, 1);
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42, kFragBoth,
              3000, 7, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 2, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0,
              false);
        v2Rec(buf, 3, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 60, 0, 4000,
              7, 1, OBS_PKT_PARSED, false);
        const ObsBatchSpec spec = obsBatchSpecOf(1, 0, winStart, winEnd);
        ObsJoin j = obsJoin(buf, bytes, 1024, spec);
        check(!j.recordsCoverWindow,
              "G: an overflowed ring cannot claim window coverage");
        checkU64(j.coverState, OBS_COVER_OVERFLOW, "G: the reason is overflow");
    }
}

// --- 5. business correlation: the join key is (token, reqId) -------------
static void testV2BusinessJoin() {
    const u64 winStart = 2000, winEnd = 8000;
    unsigned char buf[OBS_HDR_BYTES + 16 * OBS_REC_BYTES];

    // A two-segment request: both segments carry the SAME (token, reqId), the
    // doorbell carries it too, and the reply carries it back.
    {
        const u32 n = 7;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42,
              OBS_FLAG_FIRST_FRAG, 3000, 0xA1B2C3D4, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 2, 1, OBS_KIND_TX_SUBMIT, 97, 97, 0x3c9997510ULL, 14,
              OBS_FLAG_LAST_FRAG, 3010, 0xA1B2C3D4, 1, OBS_PKT_PARSED, false);
        /* The two segments above already carry FIRST and LAST separately,
         * which is exactly what a two-descriptor packet looks like. */
        v2Rec(buf, 3, 1, OBS_KIND_TX_DOORBELL, 98, 0, 0, 0, 0, 3100,
              0xA1B2C3D4, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 4, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0,
              false);
        v2Rec(buf, 5, 1, OBS_KIND_TX_DONE, 97, 97, 0, 0, 0, 3510, 0, 0, 0,
              false);
        v2Rec(buf, 6, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 60, 0, 4000,
              0xA1B2C3D4, 1, OBS_PKT_PARSED, false);
        const ObsBatchSpec spec = obsBatchSpecOf(1, 0xA1B2C3D4, winStart, winEnd);
        ObsJoin j = obsJoin(buf, bytes, 1024, spec);
        checkU64(j.bizCount, 1, "both segments fold into ONE business op");
        checkU64(j.biz[0].segCount, 2, "with two segments");
        checkU64(j.biz[0].segDone, 2, "both completed");
        check(j.biz[0].allSegDone, "all segments completed");
        check(j.biz[0].haveRx, "and the reply is attached");
        checkU64(j.biz[0].reqId, 1, "the request id round-trips");
        checkU64(j.biz[0].token, 0xA1B2C3D4, "the token round-trips");
        checkU64(j.biz[0].segAddr[0], 0x3c99974e0ULL,
                 "segment 0 keeps its own address");
        checkU64(j.biz[0].segAddr[1], 0x3c9997510ULL,
                 "segment 1 keeps its own address");
        checkU64(j.biz[0].segLen[0], 42, "segment 0 keeps its own length");
        checkU64(j.biz[0].segLen[1], 14, "segment 1 keeps its own length");
        check(j.controlledBatchComplete, "the single-request batch is complete");
    }

    // A reply that arrives WITHOUT the matching submit must not be paired.
    {
        const u32 n = 3;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        v2Rec(buf, 1, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 60, 0, 4000,
              0xBEEF, 5, OBS_PKT_PARSED, false);
        v2Rec(buf, 2, 1, OBS_KIND_RX_DONE, 951, 951, 0x1f002000, 60, 0, 4500,
              0, 0, 0, false);
        const ObsBatchSpec spec = obsBatchSpecOf(1, 0, winStart, winEnd);
        ObsJoin j = obsJoin(buf, bytes, 1024, spec);
        checkU64(j.bizCount, 1, "the lone reply forms an op");
        check(!j.biz[0].haveSubmit, "but it has no submit");
        check(!j.biz[0].allSegDone, "and cannot be all-segments-done");
        check(!j.controlledBatchComplete,
              "so the batch is not complete");
    }

    // An unparsed TX record (no business id) must block the batch claim
    // rather than being silently ignored.
    {
        const u32 n = 3;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42, 0,
              3000, 0, 0, OBS_PKT_TCP, false);   // IPv4/TCP: not parsed
        v2Rec(buf, 2, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0,
              false);
        const ObsBatchSpec spec = obsBatchSpecOf(1, 0, winStart, winEnd);
        ObsJoin j = obsJoin(buf, bytes, 1024, spec);
        // The record was positively identified as IPv4/TCP: not our
        // protocol, so it is NOT a blocker and NOT counted as unparsed.
        // (Round 10's first version counted every non-matching packet,
        // which made controlledBatchComplete unreachable on a live
        // interface where ordinary TCP traffic is constant.)
        checkU64(j.batchUnparsed, 0,
                 "an IPv4/TCP record is not a batch blocker");
        check(!j.controlledBatchComplete,
              "and blocks the controlled-batch claim");
        // Two reasons are true at once here (the request is incomplete AND a
        // record had no business id); the analyser reports the more specific
        // one. Assert the counter and the blocked verdict, which is what the
        // requirement actually is.
        check(j.batchWhy != nullptr && std::strlen(j.batchWhy) > 0,
              "and a reason is reported");
    }

    // A batch that was never declared is NOT a completed batch.
    {
        const u32 n = 2;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42, kFragBoth,
              3000, 7, 1, OBS_PKT_PARSED, false);
        const ObsBatchSpec spec = obsBatchSpecOf(0, 0, winStart, winEnd);
        ObsJoin j = obsJoin(buf, bytes, 1024, spec);
        check(!j.controlledBatchComplete,
              "an undeclared batch is not a completed batch");
        check(std::strcmp(j.batchWhy, "batch-not-declared") == 0,
              "and says so");
    }

    // A request OUTSIDE the declared range blocks the claim.
    {
        const u32 n = 5;
        const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
        v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42, kFragBoth,
              3000, 7, 1, OBS_PKT_PARSED, false);
        v2Rec(buf, 2, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0,
              false);
        v2Rec(buf, 3, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 60, 0, 4000,
              7, 1, OBS_PKT_PARSED, false);
        // Request 9 was never declared.
        v2Rec(buf, 4, 1, OBS_KIND_TX_SUBMIT, 97, 97, 0x3ebc122e0ULL, 42, kFragBoth,
              5000, 7, 9, OBS_PKT_PARSED, false);
        const ObsBatchSpec spec = obsBatchSpecOf(1, 7, winStart, winEnd);
        ObsJoin j = obsJoin(buf, bytes, 1024, spec);
        checkU64(j.batchUnexpected, 1, "an out-of-range request is counted");
        check(!j.controlledBatchComplete,
              "and blocks the controlled-batch claim");
        check(std::strcmp(j.batchWhy,
                          "requests-outside-the-declared-batch") == 0,
              "and the reason names it");
    }
}

// --- 6. the window subset must agree with the raw records ---------------
//
// This is the recomputation round 9 never did: take the raw record stream and
// independently derive how many submits and completions fall inside the
// window, then require the reported counters to equal that.
static void testV2WindowRecompute() {
    const u64 winStart = 2000, winEnd = 8000;
    unsigned char buf[OBS_HDR_BYTES + 16 * OBS_REC_BYTES];
    const u32 n = 10;
    const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
    v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
             0x1c860b3b0bbdULL, 0, 0, 1);
    // One record before the window so coverage can reach back.
    v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
          0, 0, 0, false);
    // 4 submits inside, 4 completions inside, 1 completion after the window.
    for (u32 i = 0; i < 4; i++) {
        v2Rec(buf, 1 + i, 1, OBS_KIND_TX_SUBMIT, 96 + i, 96 + i,
              0x3c9997000ULL + i * 0x10, 42, 0, 3000 + i * 100,
              7, 1 + i, OBS_PKT_PARSED, false);
    }
    for (u32 i = 0; i < 4; i++) {
        v2Rec(buf, 5 + i, 1, OBS_KIND_TX_DONE, 96 + i, 96 + i, 0, 0, 0,
              5000 + i * 100, 0, 0, 0, false);
    }
    v2Rec(buf, 9, 1, OBS_KIND_TX_DONE, 100, 100, 0, 0, 0, 9000, 0, 0, 0,
          false);   // after the window

    const ObsBatchSpec spec = obsBatchSpecOf(0, 0, winStart, winEnd);
        ObsJoin j = obsJoin(buf, bytes, 1024, spec);
    checkU64(j.submits, 4, "four submits in the raw records");
    checkU64(j.dones, 5, "five completions in the raw records");
    checkU64(j.winSubmits, 4, "four submits fall inside the window");
    checkU64(j.winDones, 4, "four completions fall inside the window");
    checkU64(j.winPaired, 4, "all four pair up inside the window");
    checkU64(j.winOrphanDone, 0, "none is an orphan");
    check(j.hasCompletePair, "there is at least one complete pair");
    check(j.recordsCoverWindow, "and the snapshot covers the window");
    // The counter must equal what the raw stream says, not be asserted.
    check(j.winPaired == j.winDones && j.winDones == j.winSubmits,
          "the window counters close arithmetically");
}

// ===========================================================================
// 7. ROUND 11: the batch predicate must reject assembled evidence
// ===========================================================================
//
// Every case below was ACCEPTED by round 10's predicate and must now be
// refused. Each one is expressed as a shape the driver could really produce,
// not as "two frozen copies differ": the records are individually well formed,
// the snapshot is structurally valid, and only the RELATION between records is
// wrong. That is the class of defect a summary-based check cannot see.
//
// The declaration (ObsBatchSpec) is always pinned to a token and a window
// BEFORE the records are read, because that is the whole point: the predicate
// has to be answerable against something fixed in advance.

// --- A. duplicate completion for one segment, none for another -----------
//
// Round 10 counted completions per OP: `segDone++` on any match, then
// `segDone == segCount`. Two completions for segment 96 and none for 97 made
// segDone 2 == segCount 2, so the batch passed -- while segment 97's DMA range
// had no completion evidence at all.
static void testV11CounterexampleA() {
    const u64 winStart = 2000, winEnd = 8000;
    unsigned char buf[OBS_HDR_BYTES + 16 * OBS_REC_BYTES];
    const u32 n = 6;
    const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
    v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
             0x1c860b3b0bbdULL, 0, 0, 1);
    v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
          0, 0, 0, false);
    // Two segments of one request: 96 is the first, 97 the last.
    v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3790a57b6ULL, 74,
          OBS_FLAG_FIRST_FRAG, 3000, 0xA3DBBA85, 1, OBS_PKT_PARSED, false);
    v2Rec(buf, 2, 1, OBS_KIND_TX_SUBMIT, 97, 97, 0x3790a5800ULL, 74,
          OBS_FLAG_LAST_FRAG, 3010, 0xA3DBBA85, 1, OBS_PKT_PARSED, false);
    // TWO completions for 96...
    v2Rec(buf, 3, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0, false);
    v2Rec(buf, 4, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3600, 0, 0, 0, false);
    // ...and NONE for 97. The RX record is present, so the old predicate saw
    // submit + "all segments done" + RX and called the batch complete.
    v2Rec(buf, 5, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 74, 0, 4000,
          0xA3DBBA85, 1, OBS_PKT_PARSED, false);

    const ObsBatchSpec spec = obsBatchSpecOf(1, 0xA3DBBA85, winStart, winEnd);
    ObsJoin j = obsJoin(buf, bytes, 1024, spec);

    checkU64(j.bizCount, 1, "A: one business op");
    checkU64(j.biz[0].segCount, 2, "A: two segments were submitted");
    checkU64(j.biz[0].segDoneCount[0], 2,
             "A: segment 96 has two completion records");
    checkU64(j.biz[0].segDoneCount[1], 0,
             "A: segment 97 has none");
    checkU64(j.biz[0].segDupDone, 1, "A: the duplicate is counted as a duplicate");
    checkU64(j.biz[0].segMissingDone, 1, "A: and the missing one is counted");
    check(!j.biz[0].allSegDone,
          "A: not all segments completed, despite done-records == segment-count");
    check(!j.controlledBatchComplete, "A: the batch is NOT complete");
    checkU64(j.batchDupDone, 1, "A: the blocking reason is a duplicate");
    check(std::strcmp(j.batchWhy, "duplicate-completions") == 0,
          "A: and the reason token names it");

    // The same fixture with the duplicate removed and 97 completed must pass,
    // otherwise the check above proves nothing about the duplicate.
    {
        unsigned char t[OBS_HDR_BYTES + 16 * OBS_REC_BYTES];
        std::memcpy(t, buf, bytes);
        // Turn record 4 (the duplicate completion) into 97's completion.
        v2Rec(t, 4, 1, OBS_KIND_TX_DONE, 97, 97, 0, 0, 0, 3600, 0, 0, 0,
              false);
        ObsJoin k = obsJoin(t, bytes, 1024, spec);
        check(k.biz[0].allSegDone,
              "A control: one completion per segment DOES satisfy allSegDone");
        check(k.controlledBatchComplete,
              "A control: and that batch is complete");
    }
}

// --- B. the real exchange happened AFTER the window ---------------------
//
// The window contains an unrelated TX/RX pair (no business id). The request
// this round declared was submitted after winEnd, completed after winEnd, and
// its reply arrived after winEnd. Round 10 checked the window only for the
// "first window operation" it happened to quote, and the batch predicate did
// not look at the window at all -- so the unrelated in-window pair plus the
// out-of-window real exchange added up to a pass.
static void testV11CounterexampleB() {
    const u64 winStart = 2000, winEnd = 8000;
    unsigned char buf[OBS_HDR_BYTES + 16 * OBS_REC_BYTES];
    const u32 n = 6;
    const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
    v2Header(buf, 1, n, 20000, 1, 0x2500, 0x10EC, 0x8127, 2,
             0x1c860b3b0bbdULL, 0, 0, 1);
    v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
          0, 0, 0, false);
    // Inside the window: an ordinary TX with NO business id, and its
    // completion. This is the unrelated pair that used to carry the claim.
    v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3c99974e0ULL, 42,
          kFragBoth, 3000, 0, 0, OBS_PKT_NO_MAGIC, false);
    v2Rec(buf, 2, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0, false);
    // AFTER the window: the real request, its completion and its reply.
    v2Rec(buf, 3, 1, OBS_KIND_TX_SUBMIT, 97, 97, 0x3790a57b6ULL, 74,
          kFragBoth, 9000, 0xA3DBBA85, 1, OBS_PKT_PARSED, false);
    v2Rec(buf, 4, 1, OBS_KIND_TX_DONE, 97, 97, 0, 0, 0, 9500, 0, 0, 0, false);
    v2Rec(buf, 5, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 74, 0, 10000,
          0xA3DBBA85, 1, OBS_PKT_PARSED, false);

    const ObsBatchSpec spec = obsBatchSpecOf(1, 0xA3DBBA85, winStart, winEnd);
    ObsJoin j = obsJoin(buf, bytes, 1024, spec);

    check(j.hasCompletePair, "B: an in-window pair does exist");
    checkU64(j.bizCount, 1, "B: exactly one business op is in the records");
    check(!j.biz[0].allStagesInWindow,
          "B: but its stages are not all inside the window");
    check(j.biz[0].stageOutsideWindow,
          "B: and the violation is a stage outside the window");
    check(!j.controlledBatchComplete,
          "B: so the batch is NOT complete");
    checkU64(j.batchOutsideWindow, 1, "B: the window violation is counted");
    check(std::strcmp(j.batchWhy, "exchange-outside-the-window") == 0,
          "B: and the reason token names it");

    // The same records with the window covering them must pass, so the
    // rejection above is attributable to the window and nothing else.
    {
        const ObsBatchSpec wide = obsBatchSpecOf(1, 0xA3DBBA85, 2000, 20000);
        ObsJoin k = obsJoin(buf, bytes, 1024, wide);
        check(k.biz[0].allStagesInWindow,
              "B control: with a window that contains them, the stages pass");
        check(k.controlledBatchComplete,
              "B control: and the batch is complete");
    }
}

// --- C. two runs spliced into one batch ---------------------------------
//
// Token A's request 1 and token B's request 2, declared as a batch of 2. Round
// 10 folded business ops by reqId alone, so this looked like a complete batch:
// both request ids present, each with a full TX/done/RX chain.
static void testV11CounterexampleC() {
    const u64 winStart = 2000, winEnd = 8000;
    unsigned char buf[OBS_HDR_BYTES + 16 * OBS_REC_BYTES];
    const u32 n = 8;
    const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
    v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
             0x1c860b3b0bbdULL, 0, 0, 1);
    v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
          0, 0, 0, false);
    // Run A: request 1.
    v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3790a57b6ULL, 74,
          kFragBoth, 3000, 0xAAAA0001, 1, OBS_PKT_PARSED, false);
    v2Rec(buf, 2, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0, false);
    v2Rec(buf, 3, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 74, 0, 4000,
          0xAAAA0001, 1, OBS_PKT_PARSED, false);
    // Run B: request 2, a DIFFERENT run token.
    v2Rec(buf, 4, 1, OBS_KIND_TX_SUBMIT, 97, 97, 0x3fc67a1b6ULL, 74,
          kFragBoth, 5000, 0xBBBB0002, 2, OBS_PKT_PARSED, false);
    v2Rec(buf, 5, 1, OBS_KIND_TX_DONE, 97, 97, 0, 0, 0, 5500, 0, 0, 0, false);
    v2Rec(buf, 6, 1, OBS_KIND_RX_DONE, 951, 951, 0x1f002000, 74, 0, 6000,
          0xBBBB0002, 2, OBS_PKT_PARSED, false);
    v2Rec(buf, 7, 1, OBS_KIND_RX_DONE, 952, 952, 0x1f003000, 60, 0, 6500,
          0, 0, 0, false);

    // Declared: batch of 2, pinned to run A.
    const ObsBatchSpec spec = obsBatchSpecOf(2, 0xAAAA0001, winStart, winEnd);
    ObsJoin j = obsJoin(buf, bytes, 1024, spec);

    checkU64(j.batchForeignToken, 2,
             "C: the other run's records are counted, not folded in");
    checkU64(j.bizCount, 1, "C: only one run's op survives the token filter");
    checkU64(j.batchMissing, 1, "C: request 2 of THIS run is missing");
    check(!j.controlledBatchComplete,
          "C: so the batch is NOT complete");
    check(std::strcmp(j.batchWhy, "records-from-another-run") == 0,
          "C: and the reason token names the foreign run");
    // The unparsed RX record (no business id) belongs to no run at all, so it
    // must not be miscounted as one. Two parsed records of run B is exact.
    checkU64(j.rxDone, 4, "C: all three RX records were seen");
    checkU64(j.rxParsed, 2, "C: only two of them carried a business id");

    // With no token declared, the records are seen to span two runs and the
    // verdict must refuse rather than pick one.
    {
        const ObsBatchSpec loose = obsBatchSpecOf(2, 0, winStart, winEnd);
        ObsJoin k = obsJoin(buf, bytes, 1024, loose);
        check(k.tokenAmbiguous,
              "C: an undeclared token across two runs is reported ambiguous");
        check(!k.controlledBatchComplete,
              "C: and cannot produce a complete batch");
        check(std::strcmp(k.batchWhy, "records-span-multiple-runs") == 0,
              "C: with a reason that says so");
    }

    // A snapshot containing only run A, declared as a batch of 2, is still
    // incomplete -- the point is not "fewer records is safer" but that the
    // declared count is what must be met.
    {
        const u32 m = 4;
        const u64 b2 = OBS_HDR_BYTES + (u64)m * OBS_REC_BYTES;
        unsigned char t[OBS_HDR_BYTES + 16 * OBS_REC_BYTES];
        v2Header(t, 1, m, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
                 0x1c860b3b0bbdULL, 0, 0, 1);
        v2Rec(t, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
              0, 0, 0, false);
        v2Rec(t, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3790a57b6ULL, 74,
              kFragBoth, 3000, 0xAAAA0001, 1, OBS_PKT_PARSED, false);
        v2Rec(t, 2, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0,
              false);
        v2Rec(t, 3, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 74, 0, 4000,
              0xAAAA0001, 1, OBS_PKT_PARSED, false);
        ObsJoin k = obsJoin(t, b2, 1024, spec);
        checkU64(k.batchComplete, 1, "C control: run A's request 1 is complete");
        checkU64(k.batchMissing, 1, "C control: but request 2 is still missing");
        check(!k.controlledBatchComplete, "C control: so the batch fails");
    }
}

// --- D. completion recorded before its own submit ----------------------
//
// A completion whose timestamp precedes the submit it is matched to is a
// stale record from an earlier lap of the ring that happens to share the
// cumulative index. Counting it as a completion would attribute a DMA range
// to an operation that had not started yet.
static void testV11CounterexampleOrder() {
    const u64 winStart = 2000, winEnd = 8000;
    unsigned char buf[OBS_HDR_BYTES + 16 * OBS_REC_BYTES];
    const u32 n = 5;
    const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
    v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
             0x1c860b3b0bbdULL, 0, 0, 1);
    v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
          0, 0, 0, false);
    // The completion appears in the log BEFORE the submit it matches.
    v2Rec(buf, 1, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3000, 0, 0, 0, false);
    v2Rec(buf, 2, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3790a57b6ULL, 74,
          kFragBoth, 4000, 0xA3DBBA85, 1, OBS_PKT_PARSED, false);
    v2Rec(buf, 3, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 4500, 0, 0, 0, false);
    v2Rec(buf, 4, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 74, 0, 5000,
          0xA3DBBA85, 1, OBS_PKT_PARSED, false);

    const ObsBatchSpec spec = obsBatchSpecOf(1, 0xA3DBBA85, winStart, winEnd);
    ObsJoin j = obsJoin(buf, bytes, 1024, spec);
    check(j.biz[0].segDoneBeforeSubmit,
          "D: a completion earlier than its submit is detected");
    check(!j.controlledBatchComplete, "D: and blocks the batch");
    checkU64(j.batchOrder, 1, "D: counted as an ordering violation");
}

// --- E. unknown length / TSO: the DMA range must not be guessed --------
//
// A TSO descriptor's length field is the MSS, not the number of bytes the
// device will write. Reporting a DMA range from it would be a guess. The
// driver sets kObsFlagLenUnknown precisely so a reader can refuse.
static void testV11UnknownLength() {
    const u64 winStart = 2000, winEnd = 8000;
    unsigned char buf[OBS_HDR_BYTES + 16 * OBS_REC_BYTES];
    const u32 n = 4;
    const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
    v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
             0x1c860b3b0bbdULL, 0, 0, 1);
    v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
          0, 0, 0, false);
    v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3790a57b6ULL, 1460,
          kFragBoth | OBS_FLAG_LEN_UNKNOWN | OBS_FLAG_TSO, 3000,
          0xA3DBBA85, 1, OBS_PKT_PARSED, false);
    v2Rec(buf, 2, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0, false);
    v2Rec(buf, 3, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 74, 0, 4000,
          0xA3DBBA85, 1, OBS_PKT_PARSED, false);

    const ObsBatchSpec spec = obsBatchSpecOf(1, 0xA3DBBA85, winStart, winEnd);
    ObsJoin j = obsJoin(buf, bytes, 1024, spec);
    check(j.biz[0].segLenUnknown, "E: the unknown length is detected");
    check(!j.biz[0].dmaRangeKnown, "E: so the DMA range is NOT known");
    check(!j.controlledBatchComplete, "E: and the batch cannot pass");
    checkU64(j.batchDmaUnknown, 1, "E: counted as an unknown DMA range");

    // A zero-length segment is the same failure by a different route.
    {
        unsigned char t[OBS_HDR_BYTES + 16 * OBS_REC_BYTES];
        std::memcpy(t, buf, bytes);
        v2Rec(t, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3790a57b6ULL, 0,
              kFragBoth, 3000, 0xA3DBBA85, 1, OBS_PKT_PARSED, false);
        ObsJoin k = obsJoin(t, bytes, 1024, spec);
        check(!k.controlledBatchComplete,
              "E: a zero-length segment also fails the batch");
    }
    // And a submitted segment with no address at all.
    {
        unsigned char t[OBS_HDR_BYTES + 16 * OBS_REC_BYTES];
        std::memcpy(t, buf, bytes);
        v2Rec(t, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0, 74,
              kFragBoth, 3000, 0xA3DBBA85, 1, OBS_PKT_PARSED, false);
        ObsJoin k = obsJoin(t, bytes, 1024, spec);
        check(k.biz[0].segAddrZero, "E: a zero address is detected");
        check(!k.controlledBatchComplete,
              "E: and blocks the batch");
    }
}

static void testV11BatchCounterexamples() {
    testV11CounterexampleA();
    testV11CounterexampleB();
    testV11CounterexampleC();
    testV11CounterexampleOrder();
    testV11UnknownLength();
}

// --- F. segment structure: a dropped trailing descriptor ---------------
//
// The strongest form of "missing segment": the log simply does not contain the
// last descriptor of the packet. Every segment it DOES contain completed, so a
// per-segment completion check alone would pass. The FIRST/LAST fragment flags
// are what make the omission visible.
static void testV11SegmentStructure() {
    const u64 winStart = 2000, winEnd = 8000;
    unsigned char buf[OBS_HDR_BYTES + 16 * OBS_REC_BYTES];
    const u32 n = 5;
    const u64 bytes = OBS_HDR_BYTES + (u64)n * OBS_REC_BYTES;
    v2Header(buf, 1, n, 9000, 1, 0x2500, 0x10EC, 0x8127, 2,
             0x1c860b3b0bbdULL, 0, 0, 1);
    v2Rec(buf, 0, 1, OBS_KIND_RX_DONE, 900, 900, 0x1f000000, 60, 0, 1500,
          0, 0, 0, false);
    // Only the FIRST fragment is present; the LAST was never logged.
    v2Rec(buf, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3790a57b6ULL, 74,
          OBS_FLAG_FIRST_FRAG, 3000, 0xA3DBBA85, 1, OBS_PKT_PARSED, false);
    v2Rec(buf, 2, 1, OBS_KIND_TX_DONE, 96, 96, 0, 0, 0, 3500, 0, 0, 0, false);
    v2Rec(buf, 3, 1, OBS_KIND_RX_DONE, 950, 950, 0x1f001000, 74, 0, 4000,
          0xA3DBBA85, 1, OBS_PKT_PARSED, false);
    v2Rec(buf, 4, 1, OBS_KIND_RX_DONE, 951, 951, 0x1f002000, 60, 0, 4200,
          0, 0, 0, false);

    const ObsBatchSpec spec = obsBatchSpecOf(1, 0xA3DBBA85, winStart, winEnd);
    ObsJoin j = obsJoin(buf, bytes, 1024, spec);
    checkU64(j.biz[0].segCount, 1, "F: only one segment is in the log");
    checkU64(j.biz[0].firstFragCount, 1, "F: it is marked first");
    checkU64(j.biz[0].lastFragCount, 0, "F: and nothing is marked last");
    check(!j.biz[0].fragStructureOk, "F: the packet structure is incomplete");
    check(j.biz[0].allSegDone,
          "F: yet every segment that IS present completed");
    check(!j.controlledBatchComplete,
          "F: the batch is still refused, because a segment is missing");
    checkU64(j.batchBadFrag, 1, "F: counted as a structural problem");

    // Two segments that both claim to be first is equally impossible.
    {
        unsigned char t[OBS_HDR_BYTES + 16 * OBS_REC_BYTES];
        std::memcpy(t, buf, bytes);
        v2Rec(t, 1, 1, OBS_KIND_TX_SUBMIT, 96, 96, 0x3790a57b6ULL, 74,
              kFragBoth, 3000, 0xA3DBBA85, 1, OBS_PKT_PARSED, false);
        ObsJoin k = obsJoin(t, bytes, 1024, spec);
        check(k.biz[0].fragStructureOk,
              "F control: one segment carrying both flags is a valid packet");
        check(k.controlledBatchComplete, "F control: and that batch passes");
    }
}


int main() {
    testIntervalContainment();
    testLiveness();
    testClassificationOrder();
    testCoalescing();
    testRecordingIgnoresMapLimit();
    testEnvelopeSurvivesFullSet();
    testRound6ArchiveContradiction();
    testAddressPlusLength();
    testClosePointerSemantics();
    testChipIdentity();
    testDescriptorDecoders();
    testSlotLifecycle();
    testRound6Replay();
    testWindowScanRound7Shape();
    testSlotReuseAndGenerations();
    testUnknownLengths();
    testPerPathCoverage();
    testRingBasis();
    testScanBounds();
    testCounterWrap();
    testPreWindowInFlight();
    testScanQuality();
    testV2HeaderGuard();
    testV2Seqlock();
    testV2Identity();
    testV2ThreeVerdicts();
    testV2BusinessJoin();
    testV2WindowRecompute();
    testV11BatchCounterexamples();
    testV11SegmentStructure();

    std::printf("\n%d passed, %d failed\n", gPass, gFail);
    if (gFail == 0) {
        std::printf("RESULT: ALL CHECKS PASS\n");
        return 0;
    }
    std::printf("RESULT: FAILURES\n");
    return 1;
}
