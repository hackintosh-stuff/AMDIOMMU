// evidence-gate-test.cpp -- the production success predicate, term by term.
//
// WHY THIS FILE EXISTS
// --------------------
// Round 11 computed seven evidence properties and PUBLISHED them, but the
// probe's own PASS-CANDIDATE verdict did not consume four of them. Publishing
// a property is not using it. Four concrete false passes came out of that:
//
//   1. `if (want.have && !idOk)` -- an UNKNOWN device identity skipped the
//      identity check entirely, so a snapshot that could not be attributed to
//      the target was treated as if it had been.
//   2. A run token of 0 was replaced by one inferred from the very records
//      being judged, which makes "these records are this run" true by
//      construction.
//   3. `bizWalkFail` was incremented on the early-return paths and then
//      OVERWRITTEN by a function-local counter at the end.
//   4. The verdict never read bizWalkCount/Ok/Fail at all, so a run whose
//      page-table walk failed every business range could still be stamped
//      PASS-CANDIDATE.
//
// The fix is structural: the conjunction lives in ONE function
// (amdobs::obsEvidenceGate), the production path calls it, and this test calls
// the SAME function with one counterexample per term.
//
// A test that re-implemented the predicate would prove nothing about the kext.
// That is the round-4 lesson: three implementations agreeing with each other
// and all three wrong.
//
// WHAT "ONE COUNTEREXAMPLE PER TERM" MEANS
// ----------------------------------------
// Start from an evidence struct where every term holds -- the gate must return
// nullptr. Then break exactly one term and require the gate to return that
// term's reason. If a term could be broken without the gate noticing, the
// property is decorative, which is precisely the round-11 defect.

#include "../probe/amd_iommu_dma_observe.hpp"

#include <cstdio>
#include <cstring>

// The wire constants live in namespace amdobs; the test spells them out so a
// reader can see which layer each name comes from.
using amdobs::u32;
using amdobs::u64;
using amdobs::OBS_HDR_BYTES;
using amdobs::OBS_REC_BYTES;
using amdobs::OBS_MAGIC;
using amdobs::OBS_VERSION;
using amdobs::OBS_CAPACITY;
using amdobs::OBS_KIND_TX_SUBMIT;
using amdobs::OBS_FLAG_FIRST_FRAG;
using amdobs::OBS_FLAG_LAST_FRAG;
using amdobs::OBS_PKT_PARSED;
using amdobs::OBS_HDR_OVERFLOWED;
using amdobs::OBS_HDR_LOST;

static int gPass = 0, gFail = 0;

static void check(bool cond, const char *what) {
    if (cond) {
        gPass++;
    } else {
        gFail++;
        std::printf("FAIL: %s\n", what);
    }
}

// The evidence of a run that satisfies every condition.
static amdobs::ObsEvidence goodEvidence() {
    amdobs::ObsEvidence e;
    e.identityKnown = true;
    e.declaredToken = 0xA3DBBA85;
    e.expectedBatch = 4;
    e.snapshotExported = true;
    e.snapshotHashStable = true;
    e.snapshotFresh = true;
    e.writerDropped = 0;
    e.publishLost = 0;
    e.readerHoles = 0;
    e.hdrFlags = 0;
    e.bizCapped = 0;
    e.hasCompletePair = true;
    e.recordsCoverWindow = true;
    e.controlledBatchComplete = true;
    e.tokenResolvedOnDeclared = true;
    e.bizWalkExpected = 8;
    e.bizWalkCount = 8;
    e.bizWalkOk = 8;
    e.bizWalkFail = 0;
    e.bizWalkCapped = 0;
    // ROUND 14: the RX posted-buffer set. A run whose eight business ranges are
    // mapped but whose ~1024 posted RX buffers are not is exactly the state
    // every round through 13 was in, so the baseline evidence must include a
    // covered set -- otherwise "all conditions hold" would describe a run that
    // never asked the RX question.
    e.rxSetPresent = true;
    e.rxSetComplete = true;
    e.rxSetRanges = 1030;
    e.rxSetWalked = 1030;
    e.rxSetOk = 1030;
    e.rxSetFail = 0;
    e.rxSetCapped = 0;
    e.rxSetGenStable = true;
    e.rxSetNoGap = true;
    e.rxSetNoLoss = true;
    e.windowRan = true;
    e.windowValid = true;
    e.eventLogOk = true;
    e.commandsOk = true;
    e.restoreOk = true;
    return e;
}

static void checkReason(const amdobs::ObsEvidence &e, const char *want,
                        const char *what) {
    const char *got = amdobs::obsEvidenceGate(e);
    if (want == nullptr) {
        if (got == nullptr) {
            gPass++;
        } else {
            gFail++;
            std::printf("FAIL: %s (gate refused with '%s', wanted pass)\n",
                        what, got);
        }
        return;
    }
    if (got && std::strcmp(got, want) == 0) {
        gPass++;
    } else {
        gFail++;
        std::printf("FAIL: %s (got '%s', want '%s')\n", what,
                    got ? got : "<pass>", want);
    }
}

// ---------------------------------------------------------------------------
// 0. the baseline must pass, or every counterexample below is meaningless
// ---------------------------------------------------------------------------
static void testBaselinePasses() {
    checkReason(goodEvidence(), nullptr,
                "0: evidence that satisfies every condition passes the gate");
    // And every reason token has a readable expansion: a stable token nobody
    // can read is only half a diagnostic.
    check(std::strcmp(amdobs::obsEvidenceGateText(nullptr),
                      "all evidence conditions hold") == 0,
          "0: the pass case has a readable text");
}

// ---------------------------------------------------------------------------
// 1. identity -- the round-11 `want.have && !idOk` hole
// ---------------------------------------------------------------------------
//
// Round 11's guard only fired when the probe HAD an independent identity. When
// it did not, the check was skipped and the run continued. Unknown is not
// "nothing to check": it is "cannot attribute the evidence to the target".
static void testIdentityUnknownIsRefused() {
    amdobs::ObsEvidence e = goodEvidence();
    e.identityKnown = false;
    checkReason(e, "identity-unknown",
                "1: an UNKNOWN device identity refuses the run (round-11 hole)");

    // The mismatch case, which round 11 did handle, must still be refused.
    // It is reported through the same term: the gate only needs to know that
    // the identity was not established.
    e = goodEvidence();
    e.identityKnown = false;   // the caller sets this false on a mismatch too
    checkReason(e, "identity-unknown", "1: a mismatched identity also refuses");
}

// ---------------------------------------------------------------------------
// 2. the run token -- declared, not inferred
// ---------------------------------------------------------------------------
//
// Round 11 fell back to "the single token seen in the records". That is
// circular: the token being checked is read out of the records the check is
// about. `tokenResolvedOnDeclared` is the property that makes the difference
// visible, and `strictToken` in ObsBatchSpec is what makes it impossible for
// the production path to infer one.
static void testTokenMustBeDeclared() {
    amdobs::ObsEvidence e = goodEvidence();
    e.declaredToken = 0;
    checkReason(e, "token-not-declared",
                "2: a token of 0 refuses the run");

    e = goodEvidence();
    e.tokenResolvedOnDeclared = false;   // the join used some other token
    checkReason(e, "token-not-resolved-on-declaration",
                "2: a join that did not use the declared token refuses the run");

    // The strict spec must not infer a token, and the permissive one must
    // record that it did.
    const amdobs::ObsBatchSpec strict =
        amdobs::obsBatchSpecStrict(4, 0, 1000, 2000);
    check(strict.strictToken, "2: the strict spec is marked strict");
    check(strict.runToken == 0, "2: the strict spec carries no token");

    // A tiny snapshot with one parsed record carrying token 0x77.
    unsigned char buf[OBS_HDR_BYTES + 2 * OBS_REC_BYTES];
    std::memset(buf, 0, sizeof(buf));
    {
        // Header: magic, version, recSize, capacity, head, ..., pubId, ...
        u32 v[20] = {0};
        v[0] = OBS_MAGIC; v[1] = OBS_VERSION; v[2] = OBS_REC_BYTES;
        v[3] = OBS_CAPACITY; v[4] = 2; v[7] = 1;      // head=2, pubId=1
        v[8] = 1; v[9] = 2; v[10] = 2;                // first,last,valid
        u64 tStart = 1000, tPub = 9000;
        std::memcpy(buf + 0, v, 80);
        std::memcpy(buf + 80, &tStart, 8);
        std::memcpy(buf + 88, &tPub, 8);
    }
    for (u32 i = 0; i < 2; i++) {
        unsigned char *r = buf + OBS_HDR_BYTES + (u64)i * OBS_REC_BYTES;
        const u32 ticket = 1 + i;
        u32 seq = ticket << 1;
        u32 kind = OBS_KIND_TX_SUBMIT;
        u32 cum = 100 + i, slot = 100 + i, gen = 0, batch = 0, o1 = 0, o2 = 0;
        u32 len = 74, flags = OBS_FLAG_FIRST_FRAG | OBS_FLAG_LAST_FRAG;
        u32 token = 0x77, req = 1, flow = 0, pkt = OBS_PKT_PARSED;
        u64 t = 1500 + i, addr = 0x10000000ULL + i * 0x1000;
        std::memcpy(r + 0, &t, 8);
        std::memcpy(r + 8, &addr, 8);
        std::memcpy(r + 16, &seq, 4);
        std::memcpy(r + 20, &kind, 4);
        std::memcpy(r + 24, &cum, 4);
        std::memcpy(r + 28, &slot, 4);
        std::memcpy(r + 32, &gen, 4);
        std::memcpy(r + 36, &batch, 4);
        std::memcpy(r + 40, &o1, 4);
        std::memcpy(r + 44, &o2, 4);
        std::memcpy(r + 48, &len, 4);
        std::memcpy(r + 52, &flags, 4);
        std::memcpy(r + 56, &token, 4);
        std::memcpy(r + 60, &req, 4);
        std::memcpy(r + 64, &flow, 4);
        std::memcpy(r + 68, &pkt, 4);
    }
    const u64 bytes = OBS_HDR_BYTES + 2 * OBS_REC_BYTES;

    // Strict: no token declared -> nothing resolved, nothing inferred.
    {
        amdobs::ObsJoin j;
        amdobs::obsJoinInto(j, buf, bytes, 1024,
                            amdobs::obsBatchSpecStrict(1, 0, 1000, 2000));
        check(!j.tokenResolved,
              "2: strict mode refuses to resolve a token it was not given");
        check(!j.inferredToken,
              "2: strict mode does not mark an inferred token");
        check(!j.controlledBatchComplete,
              "2: and the batch can never be complete");
    }
    // Permissive: the token is inferred and FLAGGED as inferred.
    {
        amdobs::ObsJoin j;
        amdobs::obsJoinInto(j, buf, bytes, 1024,
                            amdobs::obsBatchSpecOf(1, 0, 1000, 2000));
        check(j.tokenResolved, "2: permissive mode does resolve the token");
        check(j.inferredToken,
              "2: and marks it as INFERRED, so a reader can refuse it");
        check(j.joinToken == 0x77, "2: the inferred token is the one seen");
        check(!j.controlledBatchComplete,
              "2: an inferred token cannot complete the batch");
        check(std::strcmp(j.batchWhy, "run-token-was-inferred") == 0,
              "2: and the reason names the inference");
    }
    // Declared: the same records with the token supplied.
    {
        amdobs::ObsJoin j;
        amdobs::obsJoinInto(j, buf, bytes, 1024,
                            amdobs::obsBatchSpecStrict(1, 0x77, 1000, 2000));
        check(j.tokenResolved, "2: a declared token resolves");
        check(!j.inferredToken, "2: and is not marked inferred");
    }
}

// ---------------------------------------------------------------------------
// 3. snapshot export and stability
// ---------------------------------------------------------------------------
static void testSnapshotMustBeRecheckable() {
    amdobs::ObsEvidence e = goodEvidence();
    e.snapshotExported = false;
    checkReason(e, "snapshot-not-exported",
                "3: a snapshot that was not exported refuses the run");

    e = goodEvidence();
    e.snapshotHashStable = false;
    checkReason(e, "snapshot-unstable",
                "3: a snapshot that changed during the decode refuses the run");

    e = goodEvidence();
    e.snapshotFresh = false;
    checkReason(e, "snapshot-published-before-window-end",
                "3: a snapshot older than the window end refuses the run");
}

// ---------------------------------------------------------------------------
// 4. loss -- the round-11 "read dropped and never used it" hole
// ---------------------------------------------------------------------------
//
// Round 11 published `m2-b2-obs-dropped` and the analyser ignored it. A
// snapshot with dropped records then reported itself complete. Each loss
// channel is a separate term so the reason names which one.
static void testLossIsRefused() {
    amdobs::ObsEvidence e = goodEvidence();
    e.writerDropped = 1;
    checkReason(e, "records-dropped-by-writer",
                "4: one dropped record refuses the run");

    e = goodEvidence();
    e.publishLost = 1;
    checkReason(e, "records-lost-at-publish",
                "4: one hole found at publish refuses the run");

    e = goodEvidence();
    e.readerHoles = 1;
    checkReason(e, "records-unreadable",
                "4: one unreadable record refuses the run");

    e = goodEvidence();
    e.hdrFlags = OBS_HDR_OVERFLOWED;
    checkReason(e, "ring-overflowed",
                "4: an overflowed ring refuses the run");

    e = goodEvidence();
    e.hdrFlags = OBS_HDR_LOST;
    checkReason(e, "snapshot-flagged-lost",
                "4: a snapshot flagged as lossy refuses the run");

    e = goodEvidence();
    e.bizCapped = 1;
    checkReason(e, "business-ops-capped",
                "4: business operations beyond the cap refuse the run");
}

// ---------------------------------------------------------------------------
// 5. the three join verdicts stay independent
// ---------------------------------------------------------------------------
static void testJoinVerdictsAreIndependent() {
    amdobs::ObsEvidence e = goodEvidence();
    e.hasCompletePair = false;
    checkReason(e, "no-verifiable-pair", "5: no pair refuses the run");

    e = goodEvidence();
    e.recordsCoverWindow = false;
    checkReason(e, "records-do-not-cover-window",
                "5: a snapshot that does not cover the window refuses the run");

    e = goodEvidence();
    e.controlledBatchComplete = false;
    checkReason(e, "controlled-batch-incomplete",
                "5: an incomplete batch refuses the run");
}

// ---------------------------------------------------------------------------
// 6. page-table evidence -- the term round 11 never read
// ---------------------------------------------------------------------------
//
// This is the load-bearing case. Round 11 computed bizWalkCount/Ok/Fail and
// published them, but the PASS-CANDIDATE branch never looked. So a run whose
// every business range failed to walk was stamped PASS-CANDIDATE with the
// failure sitting in a diagnostic property next to it.
static void testPageTableEvidenceIsRequired() {
    // Every range failed.
    amdobs::ObsEvidence e = goodEvidence();
    e.bizWalkOk = 0;
    e.bizWalkFail = 8;
    checkReason(e, "page-table-evidence-failed",
                "6: a run whose walks all failed is REFUSED (round-11 hole)");

    // One range failed, the rest passed.
    e = goodEvidence();
    e.bizWalkOk = 7;
    e.bizWalkFail = 1;
    checkReason(e, "page-table-evidence-failed",
                "6: a single failed range refuses the whole run");

    // Not every expected range was walked at all.
    e = goodEvidence();
    e.bizWalkCount = 3;
    e.bizWalkOk = 3;
    checkReason(e, "page-table-ranges-missing",
                "6: a range that was never walked refuses the run");

    // Budget exhaustion is a degradation, not a pass.
    e = goodEvidence();
    e.bizWalkCapped = 1;
    checkReason(e, "page-table-budget-exceeded",
                "6: exceeding the export budget refuses the run");

    // Nothing declared at all.
    e = goodEvidence();
    e.bizWalkExpected = 0;
    e.bizWalkCount = 0;
    e.bizWalkOk = 0;
    checkReason(e, "no-business-ranges-declared",
                "6: no business range at all refuses the run");

    // Walked, no failures, but not everything proven covered.
    e = goodEvidence();
    e.bizWalkOk = 6;
    checkReason(e, "page-table-ranges-unproven",
                "6: a range walked but not proven covered refuses the run");
}

// ---------------------------------------------------------------------------
// 6b. the RX posted-buffer set (round 14)
// ---------------------------------------------------------------------------
//
// WHY THIS IS A SEPARATE BLOCK AND NOT PART OF SECTION 6
// ------------------------------------------------------
// Section 6 is about the EIGHT business ranges. This block is about the ~1024
// posted RX buffers plus everything re-armed during the window -- a different
// question with its own failure modes. Keeping them apart is what makes
// "the RX set is covered" a claim that had to be established rather than a
// consequence of the business walk passing.
//
// Every term gets its own counterexample, for the round-11 reason: a term that
// can be broken without the gate noticing is decorative.
static void testRxSet() {
    amdobs::ObsEvidence e;

    // The most important one: the state every round through 13 was in. The
    // business ranges are all mapped; the RX set was never read. This must
    // refuse, and it must say so distinctly rather than as "something failed".
    e = goodEvidence();
    e.rxSetPresent = false;
    checkReason(e, "rx-set-not-read",
                "6b: business ranges mapped but no RX set read is REFUSED");

    // A ring rebuild during the window means the baseline describes a ring that
    // no longer exists, so the set is about the wrong object.
    e = goodEvidence();
    e.rxSetGenStable = false;
    checkReason(e, "rx-ring-rebuilt-during-window",
                "6b: a ring rebuild during the window refuses the run");

    // The rearm ring lapped past the baseline: records between the baseline and
    // the oldest survivor are gone, so the union is a SUBSET.
    e = goodEvidence();
    e.rxSetNoGap = false;
    checkReason(e, "rx-rearm-log-lapped-baseline",
                "6b: a rearm log that lapped the baseline refuses the run");

    // A writer dropped a record: a buffer was re-armed with no record at all.
    e = goodEvidence();
    e.rxSetNoLoss = false;
    checkReason(e, "rx-rearm-records-lost",
                "6b: a lost rearm record refuses the run");

    // The union itself was incomplete for some other reason.
    e = goodEvidence();
    e.rxSetComplete = false;
    checkReason(e, "rx-set-incomplete",
                "6b: an incomplete set refuses the run");

    // An empty set is not "zero failures". A probe that read a publication with
    // no slots and no rearms has proven nothing.
    e = goodEvidence();
    e.rxSetRanges = 0;
    e.rxSetWalked = 0;
    e.rxSetOk = 0;
    checkReason(e, "rx-set-empty",
                "6b: an empty RX set refuses the run");

    // Ranges were dropped because the array was full.
    e = goodEvidence();
    e.rxSetCapped = 3;
    checkReason(e, "rx-set-budget-exceeded",
                "6b: exceeding the RX range budget refuses the run");

    // Fewer ranges were walked than the set contains.
    e = goodEvidence();
    e.rxSetWalked = 1000;
    e.rxSetOk = 1000;
    checkReason(e, "rx-set-ranges-missing",
                "6b: an RX range that was never walked refuses the run");

    // THE RESULT THIS ROUND EXISTS TO PRODUCE: a real mapping gap.
    e = goodEvidence();
    e.rxSetFail = 1;
    e.rxSetOk = 1029;
    checkReason(e, "rx-set-not-covered",
                "6b: one unmapped RX buffer refuses the run");

    // Walked, no explicit failure, but the counts do not add up to "all ok".
    e = goodEvidence();
    e.rxSetOk = 1000;
    checkReason(e, "rx-set-ranges-unproven",
                "6b: RX ranges walked but not all proven refuses the run");

    // And the positive case: a covered set passes this term.
    e = goodEvidence();
    checkReason(e, nullptr,
                "6b: a fully covered RX set does not block the gate");
}

// ---------------------------------------------------------------------------
// 7. run preconditions come first
// ---------------------------------------------------------------------------
//
// A reason that invalidates everything else must be reported first, so a
// capture with several problems is not labelled with the vaguest one.
static void testPreconditionsComeFirst() {
    amdobs::ObsEvidence e = goodEvidence();
    e.restoreOk = false;
    e.identityKnown = false;      // also broken
    e.bizWalkFail = 8;            // also broken
    checkReason(e, "restore-incomplete",
                "7: a restore failure is reported ahead of every other term");

    e = goodEvidence();
    e.commandsOk = false;
    e.bizWalkFail = 8;
    checkReason(e, "command-did-not-complete",
                "7: a failed command is reported ahead of the page-table term");

    e = goodEvidence();
    e.eventLogOk = false;
    checkReason(e, "event-log-not-running", "7: a dead event log refuses");

    e = goodEvidence();
    e.windowRan = false;
    checkReason(e, "window-not-executed", "7: a window that never ran refuses");

    e = goodEvidence();
    e.windowValid = false;
    checkReason(e, "window-invalid", "7: an invalid window refuses");

    e = goodEvidence();
    e.expectedBatch = 0;
    checkReason(e, "batch-not-declared", "7: an undeclared batch refuses");
}

// ---------------------------------------------------------------------------
// 8. every reason token has readable text
// ---------------------------------------------------------------------------
static void testEveryReasonHasText() {
    const char *reasons[] = {
        "restore-incomplete", "command-did-not-complete",
        "event-log-not-running", "window-not-executed", "window-invalid",
        "identity-unknown", "token-not-declared",
        "token-not-resolved-on-declaration", "batch-not-declared",
        "snapshot-not-exported", "snapshot-unstable",
        "snapshot-published-before-window-end", "records-dropped-by-writer",
        "records-lost-at-publish", "records-unreadable", "ring-overflowed",
        "snapshot-flagged-lost", "business-ops-capped", "no-verifiable-pair",
        "records-do-not-cover-window", "controlled-batch-incomplete",
        "no-business-ranges-declared", "page-table-budget-exceeded",
        "page-table-ranges-missing", "page-table-evidence-failed",
        "page-table-ranges-unproven",
        // ROUND 14: every RX-set token must have readable text too, or a
        // refusal would reach the operator as "unrecognised reason".
        "rx-set-not-read", "rx-ring-rebuilt-during-window",
        "rx-rearm-log-lapped-baseline", "rx-rearm-records-lost",
        "rx-set-incomplete", "rx-set-empty", "rx-set-budget-exceeded",
        "rx-set-ranges-missing", "rx-set-not-covered",
        "rx-set-ranges-unproven",
    };
    for (const char *r : reasons) {
        const char *txt = amdobs::obsEvidenceGateText(r);
        const bool ok = txt && std::strcmp(txt, "unrecognised reason") != 0;
        if (!ok) {
            gFail++;
            std::printf("FAIL: 8: reason '%s' has no readable text\n", r);
        } else {
            gPass++;
        }
    }
    // And an unknown token is reported as unknown rather than silently blank.
    check(std::strcmp(amdobs::obsEvidenceGateText("not-a-real-reason"),
                      "unrecognised reason") == 0,
          "8: an unknown token is reported as unrecognised");
}

// ---------------------------------------------------------------------------
// 9. the gate is the SAME function the probe calls
// ---------------------------------------------------------------------------
//
// A test can only be evidence if it exercises production code. This check is
// textual but it is checking a structural property: the probe's verdict branch
// must call obsEvidenceGate, and must not contain a hand-written conjunction of
// the evidence terms. Re-deriving the predicate in the probe is how the four
// holes appeared in the first place.
static void testGateIsCalledByProduction() {
    // The probe source is not available at runtime, so this is asserted by
    // tools/verify/gate-wiring.py, which reads the .cpp. Here we assert the
    // property the wiring depends on: that a single function decides, and that
    // breaking any one term changes its answer. That is what makes the wiring
    // meaningful -- if the gate returned nullptr for everything, wiring it up
    // would be worse than useless.
    unsigned refused = 0;
    amdobs::ObsEvidence e = goodEvidence();
    e.identityKnown = false;          if (amdobs::obsEvidenceGate(e)) refused++;
    e = goodEvidence(); e.declaredToken = 0;
    if (amdobs::obsEvidenceGate(e)) refused++;
    e = goodEvidence(); e.bizWalkFail = 1;
    if (amdobs::obsEvidenceGate(e)) refused++;
    e = goodEvidence(); e.writerDropped = 1;
    if (amdobs::obsEvidenceGate(e)) refused++;
    check(refused == 4,
          "9: every one of the four round-11 holes now changes the gate result");
}

int main() {
    std::printf("evidence-gate tests\n");
    std::printf("===================\n");
    testBaselinePasses();
    testIdentityUnknownIsRefused();
    testTokenMustBeDeclared();
    testSnapshotMustBeRecheckable();
    testLossIsRefused();
    testJoinVerdictsAreIndependent();
    testPageTableEvidenceIsRequired();
    testRxSet();
    testPreconditionsComeFirst();
    testEveryReasonHasText();
    testGateIsCalledByProduction();
    std::printf("\n%d passed, %d failed\n", gPass, gFail);
    if (gFail == 0) {
        std::printf("RESULT: ALL CHECKS PASS\n");
        return 0;
    }
    std::printf("RESULT: FAILURES\n");
    return 1;
}
