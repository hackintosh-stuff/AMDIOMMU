// AMDMapperProbeDma.cpp -- DMA observation: rings, segments, event log
//
// Part of the AMDMapperProbe kext. Split out of the original
// single-file AMDMapperProbe.cpp by tools/split-probe.py; the
// function bodies are unchanged and in their original order.

#include "AMDMapperProbe.hpp"
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOWorkLoop.h>

// IOPCIDevice.h itself triggers two -Werror-level warnings from within the SDK:
//   1. IOPCIDevice is marked __kpi_deprecated("Use PCIDriverKit")
//   2. Its internal setProperty overload is not marked override (-Winconsistent-missing-override)
//
// Both are **problems in Apple's own headers**, not defects in this project's code:
//   - PCIDriverKit is a userspace DriverKit framework and cannot implement an
//     IOMapper subclass; this project must be an in-kernel IOKit kext and can
//     only use IOPCIDevice.
//   - The override warning comes from SDK declarations; we cannot and should
//     not modify SDK headers.
//
// Therefore suppress only these two while including that header, without
// disabling them globally -- other genuine deprecation / override issues
// will still be reported as errors as usual.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Winconsistent-missing-override"
#include <IOKit/pci/IOPCIDevice.h>
#pragma clang diagnostic pop

#include <pexpert/pexpert.h>
#include <mach/kmod.h>
#include <mach/mach_time.h>
#include <kern/clock.h>
#include <libkern/OSByteOrder.h>

// The single implementation of page table encoding/decoding. Production code
// and the host regression tests **include the same file**, so the tests run
// exactly these branches rather than a separately written Python restatement.
// See tests/pte-core-test.cpp and docs/m2-2b-2-round5-result.md.
#include "amd_iommu_pte_core.hpp"

// The definition of OSPtr<T> depends on IOKIT_ENABLE_SHARED_PTR (SDK
// libkern/c++/OSPtr.h): defined = OSSharedPtr<T>; undefined = T*.
// The SDK default is undefined.
#if defined(IOKIT_ENABLE_SHARED_PTR)
    #define M1A_HAS_SHARED_PTR 1
#else
    #define M1A_HAS_SHARED_PTR 0
#endif

#include "AMDMapperProbeInternal.hpp"

// ===== AMDMapperProbeDma.cpp (original lines 3087..3116) =====
// ---- Round 7: read the close pointer / tail pointer by chip identity ----
//
// Round 6 "probed three candidate registers and took the first one that was
// non-zero and < 1024". That is not an identity criterion, it is a guess: any
// stale or unrelated register that happens to read a small number wins the
// election. The registers are in fact a deterministic function of how the chip
// is configured, and that configuration can be read from TxConfig(0x40) to
// reproduce the driver's branches exactly:
//
//   rtl812xIdentifyChip()      RTL812xLucyHardware.cpp:167
//     reg = TxConfig & 0x7c800000 ; ICVerID = TxConfig & 0x00700000
//     0x6C800000 + ICVerID 0 -> CFG_METHOD_41 ; 0x100000 -> 42
//   rtl812xx.cpp:17494-17507   HwSuppTxNoCloseVer (41/42 -> 6)
//   rtl812xx.cpp:17511-17525   MaxTxDescPtrMask (ver 6 -> 0x7FFFFFFF)
//   rtl812xx.cpp:17214-17232   rtl8125_setup_mqs_reg()
//     ver 6 -> HW_CLO_PTR0_8125BP = 0x0D34 / SW_TAIL_PTR0_8125BP = 0x0D30
//   RTL812xLucyHardware.cpp:1178 rtl812xGetHwCloPtr()
//     ver 3 -> RTL_R16, otherwise RTL_R32
bool org_example_AMDMapperProbe::m2b2ReadCloPtr(volatile UInt8 *bar,
                                                UInt32 *out) {
    if (!bar || !out) return false;
    const amdobs::CloPtrSpec spec =
        amdobs::cloPtrSpecFor(fM22b2Dma.noCloseVer);
    if (!spec.valid) return false;
    const UInt32 v = (spec.width == 2)
        ? (UInt32)(*(volatile UInt16 *)(bar + spec.reg))
        : *(volatile UInt32 *)(bar + spec.reg);
    // Both the width and the mask must hold, otherwise this sample is not
    // interpretable.
    if (!amdobs::cloPtrSampleValid(v, spec.width, spec.mask)) return false;
    *out = v;
    return true;
}

// ===== AMDMapperProbeDma.cpp (original lines 3118..3126) =====
bool org_example_AMDMapperProbe::m2b2ReadTailPtr(volatile UInt8 *bar,
                                                 UInt32 *out) {
    if (!bar || !out) return false;
    const amdobs::CloPtrSpec spec =
        amdobs::cloPtrSpecFor(fM22b2Dma.noCloseVer);
    if (!spec.valid) return false;
    *out = *(volatile UInt32 *)(bar + spec.tailReg);
    return true;
}

// ===== AMDMapperProbeDma.cpp (original lines 3128..3233) =====
// ---- Round 7: collect the (address, length) pairs from descriptors ----
//
// [Fundamental difference from round 6]
//   Round 6 called inIdentityRam() before inserting, with RAM_TOP fixed at
//   16 GiB. Descriptor addresses "at or above 16 GiB" -- exactly the class
//   this round investigates -- were therefore discarded before ever entering
//   the set. The set then "proved" faults were not in the device set, when
//   they could never have been in it.
//
//   Every non-zero address in a valid descriptor is recorded, wherever it
//   lies. The only exception is empty slots left by a registered fixed-TX
//   ring rebuild. Whether the memory may be read is decided independently by
//   readVerdict().
//
// [Round 8: the lifecycle is really wired in]
//   Round 7's version accepted the tailCum / cloCum arguments and then
//   `(void)`-ed them: as long as a close pointer was readable, every non-zero
//   address was labelled LIFE_INFLIGHT. In round 7's capture tail = clo =
//   0x6a, i.e. the queue was **already drained**, yet every historical address
//   was still reported in-flight.
//
//   Now each slot is judged by its cumulative index: txSlotCumulative() gives
//   the cumulative position the slot currently corresponds to, which is then
//   compared with the close pointer. A slot may already hold a later
//   generation's descriptor, so the lifecycle must be computed as "the
//   descriptor this slot holds now", not "the descriptor this slot once held".
void org_example_AMDMapperProbe::m2b2CollectTxSegments(const UInt8 *ring,
                                                       UInt32 count,
                                                       UInt32 tailCum,
                                                       UInt32 cloCum) {
    if (!ring) return;
    // One segment per descriptor at most; segment count never exceeds slot
    // count. Process in batches to avoid one oversized allocation.
    const UInt32 kBatch = 256;
    amdobs::Seg *segs = (amdobs::Seg *)IOMalloc(kBatch * sizeof(amdobs::Seg));
    if (!segs) {
        fM22b2Dma.unscanned += count;
        setProperty("m2-b2-dma-tx-collect", "SKIP-alloc-failed");
        return;
    }
    const UInt32 mask = fM22b2Dma.cloPtrMask
        ? fM22b2Dma.cloPtrMask : 0x7FFFFFFFu;
    UInt32 done = 0;
    UInt32 lifeCounts[4] = { 0, 0, 0, 0 };
    while (done < count) {
        const UInt32 n = ((count - done) < kBatch) ? (count - done) : kBatch;
        UInt32 used = 0;
        for (UInt32 k = 0; k < n; k++) {
            const UInt32 slot = done + k;
            const UInt8 *d = ring + (UInt64)slot * amdobs::TX_DESC_STRIDE;
            const UInt64 addr = amdobs::rd64(d + 8);
            if (addr == 0) continue;          // never programmed: not a DMA target
            const UInt32 opts1 = amdobs::rd32(d);
            // The fixed-object entry rebuild clears opts1 but retains the
            // old address. Such an empty slot is not a current DMA span.
            if (fR31Session && fM22b2Dma.txRingBasis ==
                    amdobs::RB_REGISTERED_FIXED_DMA_OBJECT &&
                !(opts1 & ~amdobs::TX_DESC_RINGEND)) continue;
            UInt32 len = opts1 & amdobs::TX_DESC_LENMASK;
            const bool tso =
                (opts1 & (amdobs::TX_DESC_LARGESEND | amdobs::TX_DESC_GSO4 |
                          amdobs::TX_DESC_GSO6)) != 0;
            // [Round 8] TSO's 16-bit field is the MSS, not a length; a zero
            // length cannot be expressed either. Both can only yield a
            // **bound**, which must be marked LEN_UNKNOWN so it cannot take
            // part in exact-coverage arguments. Round 7 simply treated 0x1000
            // as the true length.
            UInt32 flags = 0;
            if (tso) {
                flags |= amdobs::RANGE_LEN_UNKNOWN | amdobs::RANGE_FROM_TSO;
                if (len == 0) len = 0x1000;
            } else if (len == 0) {
                flags |= amdobs::RANGE_LEN_UNKNOWN;
                len = 0x1000;
            }
            segs[used].base = addr;
            segs[used].len = len;
            segs[used].flags = flags;
            segs[used].pad = 0;
            used++;
            // [Round 8] Per-slot lifecycle, not "close pointer present ->
            // label everything in-flight".
            const UInt32 life = amdobs::txSlotLifecycle(
                slot, tailCum, cloCum, 1024, mask, fM22b2Dma.haveCloPtr);
            if (life < 4) lifeCounts[life]++;
        }
        // insertSegments accepts a single lifecycle per batch. Take the
        // **most conservative** one: if any record is uncertain, the whole
        // batch is not claimed in-flight. Per-record counts are published
        // separately.
        UInt32 life;
        if (!fM22b2Dma.haveCloPtr) {
            life = amdobs::LIFE_SNAPSHOT;
        } else if (lifeCounts[amdobs::LIFE_SNAPSHOT] ||
                   lifeCounts[amdobs::LIFE_UNKNOWN]) {
            life = amdobs::LIFE_SNAPSHOT;
        } else if (lifeCounts[amdobs::LIFE_INFLIGHT] &&
                   !lifeCounts[amdobs::LIFE_COMPLETED]) {
            life = amdobs::LIFE_INFLIGHT;
        } else if (lifeCounts[amdobs::LIFE_COMPLETED] &&
                   !lifeCounts[amdobs::LIFE_INFLIGHT]) {
            life = amdobs::LIFE_COMPLETED;
        } else {
            // Mixed: both in-flight and returned records. Use snapshot to
            // mean "this batch cannot be summarized in one word" instead of
            // picking the flattering label.
            life = amdobs::LIFE_SNAPSHOT;
        }
        amdobs::insertSegments(fM22b2AddrSet, segs, used, amdobs::PURP_TX_BUF,
                               life, fM22b2Policy);
        done += n;
    }
    IOFree(segs, kBatch * sizeof(amdobs::Seg));

    // Per-class counts are published separately, making the "mixed" conclusion
    // externally checkable.
    setHexProperty(this, "m2-b2-dma-tx-life-inflight",
                   (UInt64)lifeCounts[amdobs::LIFE_INFLIGHT]);
    setHexProperty(this, "m2-b2-dma-tx-life-completed",
                   (UInt64)lifeCounts[amdobs::LIFE_COMPLETED]);
    setHexProperty(this, "m2-b2-dma-tx-life-snapshot",
                   (UInt64)lifeCounts[amdobs::LIFE_SNAPSHOT]);
    setHexProperty(this, "m2-b2-dma-tx-life-unknown",
                   (UInt64)lifeCounts[amdobs::LIFE_UNKNOWN]);
}

// ===== AMDMapperProbeDma.cpp (original lines 3235..3275) =====
void org_example_AMDMapperProbe::m2b2CollectRxSegments(const UInt8 *ring,
                                                       UInt32 count) {
    if (!ring) return;
    const UInt32 kBatch = 256;
    amdobs::Seg *segs = (amdobs::Seg *)IOMalloc(kBatch * sizeof(amdobs::Seg));
    if (!segs) {
        fM22b2Dma.unscanned += count;
        setProperty("m2-b2-dma-rx-collect", "SKIP-alloc-failed");
        return;
    }
    UInt32 done = 0;
    while (done < count) {
        const UInt32 n = ((count - done) < kBatch) ? (count - done) : kBatch;
        UInt32 used = 0;
        for (UInt32 k = 0; k < n; k++) {
            const UInt32 slot = done + k;
            const UInt8 *d = ring + (UInt64)slot * amdobs::RX_DESC_STRIDE;
            const UInt64 addr = amdobs::rd64(d + 8);
            if (addr == 0) continue;
            // For RX descriptors the low 16 bits of blen are the buffer
            // length; the driver always fills kRxBufferSize.
            const UInt32 blen = amdobs::rd32(d);
            UInt32 len = blen & 0xFFFF;
            UInt32 flags = 0;
            if (len == 0) {
                // The driver always fills kRxBufferSize; reading 0 means this
                // is not a valid descriptor. The address is still recorded (it
                // may be in use by the device), but the length can only be a
                // bound.
                len = 0x1000;
                flags |= amdobs::RANGE_LEN_UNKNOWN;
            }
            segs[used].base = addr;
            segs[used].len = len;
            segs[used].flags = flags;
            segs[used].pad = 0;
            used++;
        }
        amdobs::insertSegments(fM22b2AddrSet, segs, used, amdobs::PURP_RX_BUF,
                               amdobs::LIFE_SNAPSHOT, fM22b2Policy);
        done += n;
    }
    IOFree(segs, kBatch * sizeof(amdobs::Seg));
}

// ===== AMDMapperProbeDma.cpp (original lines 3277..3495) =====
// ---- Round 8: post-window descriptor lifecycle scan ----
//
// [Why a separate function is required, rather than reusing the pre-window
// capture]
//
//   The pre-window capture only knows "what was in the ring when the window
//   opened". It cannot answer this round's core question: **for the
//   descriptors submitted during the window, what are their addresses,
//   lengths, generations and completion states**.
//
//   The two cumulative pointers at the window edges give exactly this set:
//   [tailBefore, tailAfter) is every cumulative index submitted within the
//   window. Walking it one by one resolves each entry to a concrete slot and
//   generation.
//
// [Why it must be read after the window]
//   Completion state is determined by the close pointer at window end. A read
//   mid-window yields only an intermediate state.
//
// [Concurrency conditions and limitations] (listed honestly, not hidden in the
// implementation)
//   - The device may still be writing while we read the ring. But descriptors
//     outside [tailBefore, tailAfter) are not in our traversal range, and
//     descriptors inside it are not rewritten: the driver only rewrites a slot
//     when submitting a new descriptor, which would push the tail pointer past
//     it.
//   - The driver never clears the address field of completed descriptors, so
//     the bytes of completed window descriptors persist until that slot is
//     reused. That is what the `submits < ringSize` condition in
//     txWindowCoverageOf() is for.
//   - If window submissions reach the ring size, the earliest entries have
//     already been overwritten. They are counted in winOverwritten rather
//     than silently dropped.
void org_example_AMDMapperProbe::m2b2ScanTxWindowAfter(const UInt8 *ring,
                                                       UInt32 count) {
    fM22b2Dma.winSubmits = fM22b2Dma.winCompletes = 0;
    fM22b2Dma.winVisited = fM22b2Dma.winDecoded = 0;
    fM22b2Dma.winOverwritten = 0;
    fM22b2Dma.winInflight = fM22b2Dma.winCompleted = 0;
    fM22b2Dma.winCompletedInWindow = 0;
    fM22b2Dma.winLenUnknown = fM22b2Dma.winTsoSlots = 0;
    fM22b2Dma.winGenBefore = fM22b2Dma.winGenAfter = 0;
    fM22b2Dma.winCovReason = amdobs::TXCOV_NO_RING;
    fM22b2Dma.winRecordsLost = 0;
    fM22b2Dma.winExact = false;
    fM22b2Dma.winQualityName = "not-run";
    fM22b2Dma.haveFirstCompleted = false;
    fM22b2Dma.winFirstCompletedAddr = 0;
    fM22b2Dma.winFirstCompletedLen = 0;
    fM22b2Dma.winFirstCompletedSlot = 0;
    fM22b2Dma.winFirstCompletedGen = 0;
    fM22b2WinSet.clear();

    if (!ring || count == 0) {
        setProperty("m2-b2-dma-win-scan", "SKIP-no-ring");
        return;
    }
    if (!fM22b2Dma.haveTailPtr || !fM22b2Dma.haveCloPtr) {
        fM22b2Dma.winCovReason = amdobs::TXCOV_NO_POINTERS;
        setProperty("m2-b2-dma-win-scan", "SKIP-no-pointers");
        setProperty("m2-b2-dma-win-cov-reason",
                    amdobs::txCoverageReasonName(fM22b2Dma.winCovReason));
        setProperty("m2-b2-dma-win-quality", "pointers-unreadable");
        return;
    }

    const UInt32 mask = fM22b2Dma.cloPtrMask
        ? fM22b2Dma.cloPtrMask : 0x7FFFFFFFu;

    fM22b2Dma.tWinScanStart = m2b2NowNS();

    // [Round 9] Window records use **dedicated** storage capacity.
    //
    //   Round 8 pushed the handful of window descriptors into the same
    //   AddrSet (capacity 64) shared with thousands of historical RX/TX
    //   snapshots. The snapshots filled it first and the window records landed
    //   in dropped -- so "3 submissions within the window" could have zero
    //   entries in the set while dropped merely grew. Records of small
    //   controlled operations must be independent, otherwise they are always
    //   queued last.
    //
    //   Window records now go to fM22b2WinSet with capacity separate from the
    //   snapshot set, letting the analyser check both accounting invariants
    //   independently.
    const UInt32 kBatch = 256;
    amdobs::Seg *segs = (amdobs::Seg *)IOMalloc(kBatch * sizeof(amdobs::Seg));
    UInt32 used = 0;
    UInt32 recordsLost = 0;
    UInt32 lifeCounts[4] = { 0, 0, 0, 0 };

    const amdobs::TxWindowScan sc = amdobs::scanTxWindow(
        ring, count,
        fM22b2Dma.tailPtrBefore, fM22b2Dma.tailPtrAfter,
        fM22b2Dma.cloPtrBefore, fM22b2Dma.cloPtrAfter,
        mask, true,
        [&](const amdobs::TxWindowDesc &d) {
            if (d.addr != 0) {
                if (segs && used < kBatch) {
                    segs[used].base = d.addr;
                    segs[used].len = d.len;
                    segs[used].flags = d.flags | amdobs::RANGE_IN_WINDOW;
                    segs[used].pad = 0;
                    used++;
                } else {
                    // Storage exhausted: this descriptor **exists and is
                    // decodable**, but no record could be kept. It must be
                    // counted in recordsLost so coverage eligibility is
                    // withdrawn instead of silently vanishing.
                    recordsLost++;
                }
            }
            if (d.lifecycle < 4) lifeCounts[d.lifecycle]++;
        });

    // Window descriptors are recorded as "submitted within the window".
    // lifecycle takes the most conservative value.
    if (segs && used) {
        UInt32 life;
        if (lifeCounts[amdobs::LIFE_SNAPSHOT] ||
            lifeCounts[amdobs::LIFE_UNKNOWN]) {
            life = amdobs::LIFE_SNAPSHOT;
        } else if (sc.inflight && sc.completed) {
            life = amdobs::LIFE_SNAPSHOT;
        } else if (sc.completed && !sc.inflight) {
            life = amdobs::LIFE_COMPLETED;
        } else {
            life = amdobs::LIFE_INFLIGHT;
        }
        amdobs::insertSegments(fM22b2WinSet, segs, used,
                               amdobs::PURP_TX_BUF, life, fM22b2Policy);
    }
    if (segs) IOFree(segs, kBatch * sizeof(amdobs::Seg));

    fM22b2Dma.tWinScanEnd = m2b2NowNS();

    fM22b2Dma.winSubmits = sc.coverage.submits;
    fM22b2Dma.winCompletes = sc.coverage.completes;
    fM22b2Dma.winVisited = sc.visited;
    fM22b2Dma.winDecoded = sc.decoded;
    fM22b2Dma.winOverwritten = sc.overwritten;
    fM22b2Dma.winInflight = sc.inflight;
    fM22b2Dma.winCompleted = sc.completed;
    fM22b2Dma.winCompletedInWindow = sc.completedInWindow;
    fM22b2Dma.winLenUnknown = sc.lenUnknown;
    fM22b2Dma.winTsoSlots = sc.tsoSlots;
    fM22b2Dma.winGenBefore = sc.coverage.genBefore;
    fM22b2Dma.winGenAfter = sc.coverage.genAfter;
    fM22b2Dma.winCovReason = sc.coverage.reason;
    fM22b2Dma.winRecordsLost = recordsLost;
    if (sc.firstCompletedAddr != 0) {
        fM22b2Dma.haveFirstCompleted = true;
        fM22b2Dma.winFirstCompletedAddr = sc.firstCompletedAddr;
        fM22b2Dma.winFirstCompletedLen = sc.firstCompletedLen;
        fM22b2Dma.winFirstCompletedSlot = sc.firstCompletedSlot;
        fM22b2Dma.winFirstCompletedGen = sc.firstCompletedGen;
    }

    // [Round 9] Scan quality decides coverage eligibility.
    //
    //   Round 8 published the counters, but covered only looked at pointer
    //   arithmetic: an early scan stop, lost records, undecodable lengths --
    //   none affected tx-window-covered = yes. Now all of them withdraw
    //   eligibility -- "it was published" and "it was accounted" are two
    //   different things.
    const amdobs::TxWindowQuality q =
        amdobs::txWindowQualityOf(sc, recordsLost);
    fM22b2Dma.winExact = q.exact;
    fM22b2Dma.winQualityName = amdobs::txWindowQualityName(q);
    const bool eligible = sc.coverage.covered && q.exact;

    // Coverage of the TX buffer path holds only here, and only on this one
    // path.
    fM22b2Dma.pathCov.set(amdobs::PATH_TX_BUF,
                          eligible ? amdobs::COV_WINDOW
                                   : amdobs::COV_SNAPSHOT);
    fM22b2Dma.txWindowCovered = eligible;

    setProperty("m2-b2-dma-win-scan", "done");
    setProperty("m2-b2-dma-win-cov-reason",
                amdobs::txCoverageReasonName(sc.coverage.reason));
    setProperty("m2-b2-dma-win-quality", fM22b2Dma.winQualityName);
    setProperty("m2-b2-dma-win-exact", q.exact ? "yes" : "no");
    setHexProperty(this, "m2-b2-dma-win-records-lost",
                   (UInt64)recordsLost);
    setHexProperty(this, "m2-b2-dma-win-stop-reason",
                   (UInt64)sc.stopReason);
    setProperty("m2-b2-dma-win-stop-reason-name",
                amdobs::txScanStopName(sc.stopReason));
    setHexProperty(this, "m2-b2-dma-win-skipped",
                   (UInt64)sc.historicalSkipped);
    setHexProperty(this, "m2-b2-dma-win-prewin-completed",
                   (UInt64)sc.preWindowCompleted);
    setHexProperty(this, "m2-b2-dma-win-inflight-at-start",
                   (UInt64)sc.coverage.inFlightAtStart);
    setHexProperty(this, "m2-b2-dma-win-submits",
                   (UInt64)fM22b2Dma.winSubmits);
    setHexProperty(this, "m2-b2-dma-win-completes",
                   (UInt64)fM22b2Dma.winCompletes);
    setHexProperty(this, "m2-b2-dma-win-visited", (UInt64)sc.visited);
    setHexProperty(this, "m2-b2-dma-win-decoded", (UInt64)sc.decoded);
    setHexProperty(this, "m2-b2-dma-win-overwritten", (UInt64)sc.overwritten);
    setHexProperty(this, "m2-b2-dma-win-addr-zero", (UInt64)sc.addrZero);
    setHexProperty(this, "m2-b2-dma-win-inflight", (UInt64)sc.inflight);
    setHexProperty(this, "m2-b2-dma-win-completed", (UInt64)sc.completed);
    setHexProperty(this, "m2-b2-dma-win-completed-in-window",
                   (UInt64)sc.completedInWindow);
    setHexProperty(this, "m2-b2-dma-win-len-unknown", (UInt64)sc.lenUnknown);
    setHexProperty(this, "m2-b2-dma-win-tso", (UInt64)sc.tsoSlots);
    setHexProperty(this, "m2-b2-dma-win-gen-before", (UInt64)sc.coverage.genBefore);
    setHexProperty(this, "m2-b2-dma-win-gen-after", (UInt64)sc.coverage.genAfter);
    setHexProperty(this, "m2-b2-dma-t-win-scan-start", fM22b2Dma.tWinScanStart);
    setHexProperty(this, "m2-b2-dma-t-win-scan-end", fM22b2Dma.tWinScanEnd);
    setProperty("m2-b2-dma-tx-window-covered",
                eligible ? "yes" : "no");

    // Accounting for the window set (checked separately from the snapshot
    // set).
    setHexProperty(this, "m2-b2-winset-ranges",
                   (UInt64)fM22b2WinSet.n);
    setHexProperty(this, "m2-b2-winset-raw-offered",
                   (UInt64)fM22b2WinSet.rawOffered);
    setHexProperty(this, "m2-b2-winset-merged-total",
                   (UInt64)fM22b2WinSet.mergedTotal);
    setHexProperty(this, "m2-b2-winset-dropped",
                   (UInt64)fM22b2WinSet.droppedCount);
    setHexProperty(this, "m2-b2-winset-len-unknown",
                   (UInt64)fM22b2WinSet.savedLenUnknown);

    if (fM22b2Dma.haveFirstCompleted) {
        setHexProperty(this, "m2-b2-dma-win-1st-completed-addr",
                       fM22b2Dma.winFirstCompletedAddr);
        setHexProperty(this, "m2-b2-dma-win-1st-completed-len",
                       (UInt64)fM22b2Dma.winFirstCompletedLen);
        setHexProperty(this, "m2-b2-dma-win-1st-completed-slot",
                       (UInt64)fM22b2Dma.winFirstCompletedSlot);
        setHexProperty(this, "m2-b2-dma-win-1st-completed-gen",
                       (UInt64)fM22b2Dma.winFirstCompletedGen);
    }
}

// ===== AMDMapperProbeDma.cpp (original lines 4477..4601) =====
void org_example_AMDMapperProbe::m2b2PublishDmaDefaults() {
    setProperty("m2-b2-dma-layout-known",
                fM22b2Dma.layoutKnown ? "yes" : "no");
    setHexProperty(this, "m2-b2-dma-tx-slots", fM22b2Dma.txSlots);
    setHexProperty(this, "m2-b2-dma-tx-zeroaddr", fM22b2Dma.txAddrZero);
    setHexProperty(this, "m2-b2-dma-tx-done-with-addr",
                   fM22b2Dma.txDoneWithAddrBefore);
    setHexProperty(this, "m2-b2-dma-ranges", fM22b2Dma.ranges);
    setHexProperty(this, "m2-b2-dma-dropped", fM22b2Dma.dropped);
    setHexProperty(this, "m2-b2-dma-raw-offered", fM22b2Dma.rawOffered);
    setHexProperty(this, "m2-b2-dma-merged-total", fM22b2Dma.mergedTotal);
    setHexProperty(this, "m2-b2-dma-unscanned", fM22b2Dma.unscanned);
    setProperty("m2-b2-dma-envelope-valid",
                fM22b2Dma.envValid ? "yes" : "no");
    setHexProperty(this, "m2-b2-dma-envelope-lo", fM22b2Dma.envLo);
    setHexProperty(this, "m2-b2-dma-envelope-hi", fM22b2Dma.envHi);
    setProperty("m2-b2-dma-coverage",
                amdobs::coverageName(fM22b2Dma.coverage));
    setHexProperty(this, "m2-b2-dma-read-ok", fM22b2Dma.readOkCount);
    setHexProperty(this, "m2-b2-dma-read-outofmap",
                   fM22b2Dma.readOutOfMapCount);
    setHexProperty(this, "m2-b2-dma-read-notram",
                   fM22b2Dma.readNotRamCount);
    setHexProperty(this, "m2-b2-dma-cloptr-reg", fM22b2Dma.cloPtrReg);
    setHexProperty(this, "m2-b2-dma-cloptr-width", fM22b2Dma.cloPtrWidth);
    setHexProperty(this, "m2-b2-dma-cloptr-mask", fM22b2Dma.cloPtrMask);
    setHexProperty(this, "m2-b2-dma-cloptr-before", fM22b2Dma.cloPtrBefore);
    setHexProperty(this, "m2-b2-dma-cfgmethod", fM22b2Dma.cfgMethod);
    setHexProperty(this, "m2-b2-dma-noclosever", fM22b2Dma.noCloseVer);
    setProperty("m2-b2-dma-chip-known",
                fM22b2Dma.chipKnown ? "yes" : "no");
    setProperty("m2-b2-dma-tx-window-covered",
                fM22b2Dma.txWindowCovered ? "yes" : "no");
    setProperty("m2-b2-dma-cloptr-delta-valid", "no-observation-incomplete");
    setHexProperty(this, "m2-b2-dma-t-obs-before", fM22b2Dma.tObsBefore);
    setHexProperty(this, "m2-b2-dma-t-obs-after", fM22b2Dma.tObsAfter);
    setHexProperty(this, "m2-b2-dma-t-clo-before", fM22b2Dma.tCloBefore);

    // [Round 8] The SKIP path also publishes per-path coverage and window scan
    // fields, explicitly marked as not observed. Otherwise the analyser can
    // only report "field missing" when the fact is "the observation ran but did
    // not complete".
    setProperty("m2-b2-dma-cov-txring", "none");
    setProperty("m2-b2-dma-cov-rxring", "none");
    setProperty("m2-b2-dma-cov-txbuf", "none");
    setProperty("m2-b2-dma-cov-rxbuf", "none");
    setProperty("m2-b2-dma-cov-stat", "none");
    setProperty("m2-b2-dma-cov-weakest", "none");
    setProperty("m2-b2-dma-cov-all-window", "no");
    setProperty("m2-b2-dma-tx-ring-basis", "none");
    setProperty("m2-b2-dma-rx-ring-basis", "none");
    setHexProperty(this, "m2-b2-dma-tx-ring-decoded", 0);
    setHexProperty(this, "m2-b2-dma-rx-ring-ringend-at-last", 0);
    setHexProperty(this, "m2-b2-dma-len-unknown", 0);
    setProperty("m2-b2-dma-win-scan", "SKIP-observation-did-not-complete");
    setHexProperty(this, "m2-b2-dma-win-submits", 0);
    setHexProperty(this, "m2-b2-dma-win-completes", 0);
    setHexProperty(this, "m2-b2-dma-win-visited", 0);
    setHexProperty(this, "m2-b2-dma-win-decoded", 0);
    setHexProperty(this, "m2-b2-dma-win-overwritten", 0);
    setHexProperty(this, "m2-b2-dma-win-inflight", 0);
    setHexProperty(this, "m2-b2-dma-win-completed", 0);
    setHexProperty(this, "m2-b2-dma-win-completed-in-window", 0);
    setHexProperty(this, "m2-b2-dma-win-len-unknown", 0);
    setHexProperty(this, "m2-b2-dma-win-tso", 0);
    setHexProperty(this, "m2-b2-dma-win-gen-before", 0);
    setHexProperty(this, "m2-b2-dma-win-gen-after", 0);
    setProperty("m2-b2-dma-win-cov-reason", "not-observed");
    setHexProperty(this, "m2-b2-dma-tx-life-inflight", 0);
    setHexProperty(this, "m2-b2-dma-tx-life-completed", 0);
    setHexProperty(this, "m2-b2-dma-tx-life-snapshot", 0);
    setHexProperty(this, "m2-b2-dma-tx-life-unknown", 0);

    // [Round 9] The SKIP path must also publish window quality, boundary
    // positions and driver-log fields.
    //
    // Same reasoning as above: the analyser needs to distinguish "not
    // applicable" from "missing". Missing can only be reported as CANNOT
    // ANALYSE, which amounts to "I have no data" -- when the fact is "the
    // observation did not complete, and here is why".
    setProperty("m2-b2-dma-win-quality", "not-run");
    setProperty("m2-b2-dma-win-exact", "no");
    setHexProperty(this, "m2-b2-dma-win-records-lost", 0);
    setHexProperty(this, "m2-b2-dma-win-stop-reason", 0);
    setProperty("m2-b2-dma-win-stop-reason-name", "no-ring");
    setHexProperty(this, "m2-b2-dma-win-skipped", 0);
    setHexProperty(this, "m2-b2-dma-win-prewin-completed", 0);
    setHexProperty(this, "m2-b2-dma-win-inflight-at-start", 0);
    setHexProperty(this, "m2-b2-dma-win-addr-zero", 0);
    setProperty("m2-b2-dma-boundary-in-window", "no");
    setHexProperty(this, "m2-b2-winset-ranges", 0);
    setHexProperty(this, "m2-b2-winset-raw-offered", 0);
    setHexProperty(this, "m2-b2-winset-merged-total", 0);
    setHexProperty(this, "m2-b2-winset-dropped", 0);
    setHexProperty(this, "m2-b2-winset-len-unknown", 0);
    setProperty("m2-b2-obs", "SKIP-observation-did-not-complete");
    setProperty("m2-b2-obs-format", "absent");
    setProperty("m2-b2-obs-state", "absent");
    setProperty("m2-b2-obs-why", "not-read");
    setHexProperty(this, "m2-b2-obs-head", 0);
    setHexProperty(this, "m2-b2-obs-published", 0);
    setHexProperty(this, "m2-b2-obs-first", 0);
    setHexProperty(this, "m2-b2-obs-wrapped", 0);
    setHexProperty(this, "m2-b2-obs-bytes", 0);
    setHexProperty(this, "m2-b2-obs-records", 0);
    setHexProperty(this, "m2-b2-obs-t-start", 0);
    setHexProperty(this, "m2-b2-obs-t-published", 0);
    setHexProperty(this, "m2-b2-obs-ops", 0);
    setHexProperty(this, "m2-b2-obs-submits", 0);
    setHexProperty(this, "m2-b2-obs-dones", 0);
    setHexProperty(this, "m2-b2-obs-doorbells", 0);
    setHexProperty(this, "m2-b2-obs-rx-done", 0);
    setHexProperty(this, "m2-b2-obs-rx-addr-zero", 0);
    setHexProperty(this, "m2-b2-obs-stale", 0);
    setHexProperty(this, "m2-b2-obs-unmatched-done", 0);
    setHexProperty(this, "m2-b2-obs-uncompleted", 0);
    setHexProperty(this, "m2-b2-obs-overflow", 0);
    setProperty("m2-b2-obs-all-completed", "no");
    setHexProperty(this, "m2-b2-obs-win-submits", 0);
    setHexProperty(this, "m2-b2-obs-win-dones", 0);
    setHexProperty(this, "m2-b2-obs-win-paired", 0);
    setHexProperty(this, "m2-b2-obs-win-orphan-done", 0);
    setProperty("m2-b2-obs-window-complete", "no");
    setProperty("m2-b2-obs-source", "none");
    setHexProperty(this, "m2-b2-obs-first-submit-t", 0);
    setHexProperty(this, "m2-b2-obs-last-done-t", 0);
    setHexProperty(this, "m2-b2-obs-first-rx-addr", 0);
    setHexProperty(this, "m2-b2-obs-last-rx-addr", 0);
}

// ===== AMDMapperProbeDma.cpp (original lines 4603..5183) =====
void org_example_AMDMapperProbe::observeDeviceDma() {
    fM22b2Dma.ran = false;
    fM22b2Dma.barMapped = false;
    fM22b2Dma.barBase = 0;
    fM22b2Dma.barLen = 0;
    fM22b2Dma.haveTxRing = false;
    fM22b2Dma.txRingBase = 0;
    fM22b2Dma.haveRxRing = false;
    fM22b2Dma.rxRingBase = 0;
    fM22b2Dma.haveStat = false;
    fM22b2Dma.statBase = 0;
    fM22b2Dma.haveCounter = false;
    fM22b2Dma.counterAddr = 0;
    fM22b2Dma.txSlots = fM22b2Dma.txOwned = fM22b2Dma.txDone = 0;
    fM22b2Dma.txAddrZero = 0;
    fM22b2Dma.txTsoSlots = 0;
    fM22b2Dma.rxSlots = fM22b2Dma.rxOwned = fM22b2Dma.rxDone = 0;
    fM22b2Dma.rxAddrZero = 0;
    fM22b2Dma.txFirstAddr = fM22b2Dma.rxFirstAddr = 0;
    fM22b2Dma.ranges = fM22b2Dma.dropped = 0;
    fM22b2Dma.rawOffered = fM22b2Dma.mergedTotal = 0;
    fM22b2Dma.unscanned = 0;
    fM22b2Dma.txBufRanges = fM22b2Dma.rxBufRanges = 0;
    fM22b2Dma.envValid = false;
    fM22b2Dma.envLo = fM22b2Dma.envHi = 0;
    fM22b2Dma.readOkCount = 0;
    fM22b2Dma.readOutOfMapCount = 0;
    fM22b2Dma.readNotRamCount = 0;
    fM22b2Dma.coverage = amdobs::COV_NONE;
    fM22b2Dma.txDoneWithAddrBefore = 0;
    fM22b2Dma.txDoneWithAddrAfter = 0;
    fM22b2Dma.haveCloPtr = false;
    fM22b2Dma.cloPtrBefore = 0;
    fM22b2Dma.cloPtrAfter = 0;
    fM22b2Dma.cloPtrReg = 0;
    fM22b2Dma.cloPtrWidth = 0;
    fM22b2Dma.cloPtrMask = 0;
    fM22b2Dma.txConfigRaw = 0;
    fM22b2Dma.cfgMethod = 0;
    fM22b2Dma.noCloseVer = 0;
    fM22b2Dma.chipKnown = false;
    fM22b2Dma.haveCloDelta = false;
    fM22b2Dma.cloDelta = 0;
    fM22b2Dma.cloDeltaValid = false;
    fM22b2Dma.haveTailPtr = false;
    fM22b2Dma.tailPtrBefore = 0;
    fM22b2Dma.tailPtrAfter = 0;
    fM22b2Dma.txWindowCovered = false;
    fM22b2Dma.haveDoneDelta = false;
    fM22b2Dma.skipReason = nullptr;

    // Time boundaries: monotonic nanoseconds, easy to check item by item
    // against the window start/end.
    fM22b2Dma.tObsBefore = m2b2NowNS();

    setProperty("m2-b2-dma-obs", "started");

    // ---- 0. Physical layout policy ----
    //
    // [Round 7] Only the "may this be read" criterion is established here;
    // it does **not** participate in recording. The identity-mapping ceiling is
    // 16 GiB (M2-2b-2's coverage), not a RAM ceiling. Round 6 treated it as a
    // RAM ceiling and filtered records with it -- one of the errors this round
    // fixes.
    //
    // layoutKnown stays false: this round obtained no authoritative physical
    // layout matching **this boot**, so no address is dereferenced, but all are
    // recorded. That is the honest choice: rather read less memory than treat
    // a guessed layout as fact.
    fM22b2Policy = amdobs::defaultMapPolicy();
    fM22b2Policy.limit = M2B2_IDENTITY_LIMIT;
    fM22b2Policy.layoutKnown = false;
    fM22b2Dma.layoutKnown = false;
    fM22b2Dma.layoutSource = "none-per-boot-source-unavailable";
    setProperty("m2-b2-dma-layout-known", "no");
    setProperty("m2-b2-dma-layout-source",
                "no authoritative per-boot physical layout was captured");

    // ---- 1. Find the NIC's IOPCIDevice ----
    //
    // IOPCIDevice is marked __kpi_deprecated("Use PCIDriverKit") in the SDK,
    // and this project builds with -Werror, so the diagnostic must be
    // suppressed locally.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    IOPCIDevice *nic = nullptr;
    {
        IOService *svc = findNicServiceOnly();
        if (svc) {
            nic = OSDynamicCast(IOPCIDevice, svc);
            if (!nic) svc->release();
        }
    }
#pragma clang diagnostic pop
    if (!nic) {
        fM22b2Dma.skipReason = "no-nic-pcidevice";
        setProperty("m2-b2-dma-obs", "SKIP-no-nic-pcidevice");
        fM22b2Dma.tObsAfter = m2b2NowNS();
        m2b2PublishDmaDefaults();
        return;
    }

    // ---- 2. Get BAR2's physical range and map it read-only ----
    //
    // [v0.21.7 fix: must be fetched by config register, not by array index]
    // getDeviceMemoryWithIndex(2) is the 3rd element of the device memory
    // array, not BAR2; in testing it returned {0xfc860000,0x4000} while the
    // real BAR2 is {0xfc800000,0x40000}. The correct interface is
    // getDeviceMemoryWithRegister().
    IODeviceMemory *dm =
        nic->getDeviceMemoryWithRegister(kIOPCIConfigBaseAddress2);
    if (!dm) {
        nic->release();
        fM22b2Dma.skipReason = "no-bar2-device-memory";
        setProperty("m2-b2-dma-obs", "SKIP-no-bar2");
        fM22b2Dma.tObsAfter = m2b2NowNS();
        m2b2PublishDmaDefaults();
        return;
    }
    const IOPhysicalAddress barPhys = dm->getPhysicalAddress();
    const IOByteCount     barSize = dm->getLength();
    setHexProperty(this, "m2-b2-dma-bar-pa", (UInt64)barPhys);
    setHexProperty(this, "m2-b2-dma-bar-len", (UInt64)barSize);
    setProperty("m2-b2-dma-bar-src", "kIOPCIConfigBaseAddress2");

    if (barPhys == 0 || barSize == 0 || barSize > 0x1000000) {
        nic->release();
        fM22b2Dma.skipReason = "implausible-bar";
        setProperty("m2-b2-dma-obs", "SKIP-implausible-bar");
        fM22b2Dma.tObsAfter = m2b2NowNS();
        m2b2PublishDmaDefaults();
        return;
    }

    IOMemoryMap *barMap =
        nic->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress2,
                                         kIOMapInhibitCache | kIOMapReadOnly);
    if (!barMap) {
        nic->release();
        fM22b2Dma.skipReason = "bar-map-failed";
        setProperty("m2-b2-dma-obs", "SKIP-bar-map-failed");
        fM22b2Dma.tObsAfter = m2b2NowNS();
        m2b2PublishDmaDefaults();
        return;
    }
    volatile UInt8 *bar =
        (volatile UInt8 *)(uintptr_t)barMap->getVirtualAddress();
    fM22b2Dma.barMapped = true;
    fM22b2Dma.barBase = (UInt64)barPhys;
    fM22b2Dma.barLen = (UInt64)barSize;
    setProperty("m2-b2-dma-obs", "bar-mapped-readonly");

    // ---- 3. Chip identity: the close-pointer registers are derived from it,
    //      not elected ----
    //
    // Round 6's "take the first candidate register that is non-zero and
    // < 1024" is not an identity criterion. The registers are a deterministic
    // function of how the chip is configured, and that configuration can be
    // read from TxConfig(0x40) to reproduce the driver's branches exactly (see
    // the derivation comment in amd_iommu_dma_observe.hpp).
    {
        const UInt32 txConfig = *(volatile UInt32 *)(bar + amdobs::REG_TX_CONFIG);
        const amdobs::ChipId chip = amdobs::identifyChip(txConfig);
        const amdobs::CloPtrSpec spec = amdobs::cloPtrSpecFor(chip.noCloseVer);

        fM22b2Dma.txConfigRaw = txConfig;
        fM22b2Dma.cfgMethod = chip.cfgMethod;
        fM22b2Dma.noCloseVer = chip.noCloseVer;
        fM22b2Dma.chipKnown = chip.known;
        fM22b2Dma.cloPtrReg = spec.reg;
        fM22b2Dma.cloPtrWidth = spec.width;
        fM22b2Dma.cloPtrMask = spec.mask;

        setHexProperty(this, "m2-b2-dma-txconfig", (UInt64)txConfig);
        setHexProperty(this, "m2-b2-dma-cfgmethod", (UInt64)chip.cfgMethod);
        setHexProperty(this, "m2-b2-dma-noclosever", (UInt64)chip.noCloseVer);
        setProperty("m2-b2-dma-chip-known", chip.known ? "yes" : "NO");
        setHexProperty(this, "m2-b2-dma-cloptr-reg", (UInt64)spec.reg);
        setHexProperty(this, "m2-b2-dma-cloptr-width", (UInt64)spec.width);
        setHexProperty(this, "m2-b2-dma-cloptr-mask", (UInt64)spec.mask);
        setProperty("m2-b2-dma-cloptr-id-src",
                    chip.known ? "derived-from-TxConfig"
                               : "unknown-chip-no-register");
    }

    // ---- 4. Read the device's own DMA base registers ----
    //
    // These are addresses the driver wrote and the hardware accesses by. To
    // read them is to ask the device "which memory are you accessing now",
    // regardless of whether the driver goes through the mapper.
    m2b2ReadBar64(bar, amdobs::REG_TX_DESC_LOW, amdobs::REG_TX_DESC_HIGH,
                  &fM22b2Dma.txRingBase);
    fM22b2Dma.haveTxRing = (fM22b2Dma.txRingBase != 0);
    m2b2ReadBar64(bar, amdobs::REG_RX_DESC_LOW, amdobs::REG_RX_DESC_HIGH,
                  &fM22b2Dma.rxRingBase);
    fM22b2Dma.haveRxRing = (fM22b2Dma.rxRingBase != 0);
    m2b2ReadBar64(bar, amdobs::REG_COUNTER_LOW, amdobs::REG_COUNTER_HIGH,
                  &fM22b2Dma.counterAddr);
    fM22b2Dma.haveCounter = (fM22b2Dma.counterAddr != 0);

    // Close and tail pointers: read from the derived registers, with the
    // reading time recorded.
    {
        UInt32 v = 0;
        if (m2b2ReadCloPtr(bar, &v)) {
            fM22b2Dma.haveCloPtr = true;
            fM22b2Dma.cloPtrBefore = v;
            fM22b2Dma.tCloBefore = m2b2NowNS();
        }
        UInt32 t = 0;
        if (m2b2ReadTailPtr(bar, &t)) {
            fM22b2Dma.haveTailPtr = true;
            fM22b2Dma.tailPtrBefore = t;
            fM22b2Dma.tTailBefore = m2b2NowNS();
        }
        setHexProperty(this, "m2-b2-dma-cloptr-before",
                       (UInt64)fM22b2Dma.cloPtrBefore);
        setHexProperty(this, "m2-b2-dma-tailptr-before",
                       (UInt64)fM22b2Dma.tailPtrBefore);
        setProperty("m2-b2-dma-cloptr-usable",
                    fM22b2Dma.haveCloPtr ? "yes" : "no");
    }

    setHexProperty(this, "m2-b2-dma-tx-ring", fM22b2Dma.txRingBase);
    setHexProperty(this, "m2-b2-dma-rx-ring", fM22b2Dma.rxRingBase);
    setHexProperty(this, "m2-b2-dma-counter", fM22b2Dma.counterAddr);
    setProperty("m2-b2-dma-tx-ring-src",
                fM22b2Dma.haveTxRing ? "register" : "zero-not-programmed");
    setProperty("m2-b2-dma-rx-ring-src",
                fM22b2Dma.haveRxRing ? "register" : "zero-not-programmed");

    // ---- 5. Build the address sets ----
    //
    // [Round 7] All addresses are recorded unconditionally. Whether they may
    // be read is decided separately by readVerdict.
    //
    // [Round 9] Window records use a dedicated set; what is cleared here is
    // the snapshot set, and the window set is cleared at window scan time.
    // Their capacities are separate, so records of small controlled operations
    // are no longer dropped behind thousands of historical snapshots.
    amdobs::AddrSet &set = fM22b2AddrSet;
    set.clear();
    fM22b2WinSet.clear();

    const UInt64 kTxDescBytes = 1024ULL * amdobs::TX_DESC_STRIDE;   // 32 KiB
    const UInt64 kRxDescBytes = 1024ULL * amdobs::RX_DESC_STRIDE;   // 16 KiB
    const UInt64 kStatBytes   = 0x1000ULL;

    // The NIC reports bus addresses. Native fixed DMA now uses IOVAs, while
    // a CPU IOMemoryDescriptor still needs the registered buffer's real PA.
    // Keep the bus values in the observation set and resolve only CPU reads.
    UInt64 txReadPA = fM22b2Dma.txRingBase;
    UInt64 rxReadPA = fM22b2Dma.rxRingBase;
    const bool txBacking = !fR31Session ||
        r40FixedReadPA(r40fixed::kTxRing, fM22b2Dma.txRingBase, kTxDescBytes, &txReadPA);
    const bool rxBacking = !fR31Session ||
        r40FixedReadPA(r40fixed::kRxRing, fM22b2Dma.rxRingBase, kRxDescBytes, &rxReadPA);
    const auto txReadVerdict = txBacking ?
        amdobs::readVerdictDeviceReported(txReadPA, kTxDescBytes, fM22b2Policy) :
        amdobs::RD_UNVERIFIED;
    const auto rxReadVerdict = rxBacking ?
        amdobs::readVerdictDeviceReported(rxReadPA, kRxDescBytes, fM22b2Policy) :
        amdobs::RD_UNVERIFIED;
    setHexProperty(this, "m2-b2-dma-tx-ring-read-pa", txBacking ? txReadPA : 0);
    setHexProperty(this, "m2-b2-dma-rx-ring-read-pa", rxBacking ? rxReadPA : 0);

    // Ring and statistics-buffer addresses are registered **unconditionally**.
    // They are memory the device is certain to access.
    if (fM22b2Dma.haveTxRing) {
        set.insert(fM22b2Dma.txRingBase, kTxDescBytes, amdobs::PURP_TX_RING,
                   amdobs::LIFE_INFLIGHT, txReadVerdict);
    }
    if (fM22b2Dma.haveRxRing) {
        set.insert(fM22b2Dma.rxRingBase, kRxDescBytes, amdobs::PURP_RX_RING,
                   amdobs::LIFE_INFLIGHT, rxReadVerdict);
    }
    if (fM22b2Dma.haveCounter && (fM22b2Dma.counterAddr & ~0xFFFULL) != 0) {
        fM22b2Dma.statBase = fM22b2Dma.counterAddr & ~0xFFFULL;
        fM22b2Dma.haveStat = true;
        set.insert(fM22b2Dma.statBase, kStatBytes, amdobs::PURP_COUNTER_DUMP,
                   amdobs::LIFE_INFLIGHT,
                   amdobs::readVerdictDeviceReported(fM22b2Dma.statBase, kStatBytes,
                                       fM22b2Policy));
        setHexProperty(this, "m2-b2-dma-stat-base", fM22b2Dma.statBase);
    }

    // **Separate** criterion for mapping ring memory: readVerdict is used only
    // here, and only to decide whether to read the descriptors. Recording is
    // already complete; a failed read does not affect set membership.
    {
        const char *whyTx = nullptr;
        const bool txOk =
            fM22b2Dma.haveTxRing && txBacking &&
            amdobs::plausibleRingBase(txReadPA, kTxDescBytes,
                                      M2B2_IDENTITY_LIMIT, &whyTx) &&
            txReadVerdict == amdobs::RD_OK;
        const char *whyRx = nullptr;
        const bool rxOk =
            fM22b2Dma.haveRxRing && rxBacking &&
            amdobs::plausibleRingBase(rxReadPA, kRxDescBytes,
                                      M2B2_IDENTITY_LIMIT, &whyRx) &&
            rxReadVerdict == amdobs::RD_OK;
        setProperty("m2-b2-dma-tx-ring-trusted", txOk ? "yes" : "NO");
        setProperty("m2-b2-dma-rx-ring-trusted", rxOk ? "yes" : "NO");
        if (!txOk && fM22b2Dma.haveTxRing) {
            setProperty("m2-b2-dma-tx-ring-why",
                        whyTx ? whyTx : "not readable under current policy");
            // Ring address recorded, but its contents unreadable -> cannot
            // enumerate descriptors -> these slots are unscanned.
            fM22b2Dma.unscanned += 1024;
        }
        if (!rxOk && fM22b2Dma.haveRxRing) {
            setProperty("m2-b2-dma-rx-ring-why",
                        whyRx ? whyRx : "not readable under current policy");
            fM22b2Dma.unscanned += 1024;
        }
        setProperty("m2-b2-dma-trust",
                    (txOk && rxOk) ? "trusted"
                                   : "PARTIAL-ring-registers-not-readable");
        if (!txOk) fM22b2Dma.haveTxRing = false;
        if (!rxOk) fM22b2Dma.haveRxRing = false;
    }

    // ---- 5b. Grounds for reading ring memory: the fingerprint must be able
    //      to fail for real ----
    //
    // [Round 8] Round 7's admission condition was "the device register says it
    // uses this address". That proves only that the **device was programmed**
    // to use it -- not that this memory is still the driver's ring object, is
    // still alive, or that this PA maps to it. Reading a wrong PA panics, so
    // that reasoning was one step short.
    //
    // The unregistered general path can only judge by whether the contents
    // match a ring the driver would have constructed:
    //   - The RX ring's last descriptor carries RingEnd (written once at setup
    //     and never cleared) -- a structural fingerprint;
    //   - TX ring addresses are non-zero with length fields within 16 bits or
    //     carrying the TSO bit.
    // A page of random memory will not satisfy "RingEnd exactly in the last
    // slot". This is a check that can genuinely fail.
    //
    // When the general path's fingerprint fails, the address is kept but the
    // scan stops. Native fixed TX identity is already confirmed by the
    // registered object, its original PA and a live mapping; a rebuilt empty
    // ring does not depend on historical content fingerprints.
    {
        fM22b2Dma.txRingBasis = amdobs::RB_NONE;
        fM22b2Dma.rxRingBasis = amdobs::RB_NONE;
        fM22b2Dma.txRingFpOk = false;
        fM22b2Dma.rxRingFpOk = false;
        fM22b2Dma.txRingDecoded = 0;
        fM22b2Dma.rxRingRingEndAtLast = 0;
        setProperty("m2-b2-dma-tx-ring-basis", "none");
        setProperty("m2-b2-dma-rx-ring-basis", "none");
    }

    // ---- 6. Read the descriptor rings, collecting (address, length) in the
    //      actual formats ----
    //
    // This is the core step: a descriptor's addr field is the target of the
    // device's next DMA, and the length field gives the real size of that DMA
    // (no longer approximated as one page across the board).
    if (fM22b2Dma.haveTxRing) {
        IOMemoryDescriptor *ringMd =
            IOMemoryDescriptor::withPhysicalAddress(txReadPA,
                                                    kTxDescBytes,
                                                    kIODirectionIn);
        if (ringMd) {
            IOMemoryMap *rm = ringMd->map(kIOMapInhibitCache | kIOMapReadOnly);
            if (rm) {
                const UInt8 *rb =
                    (const UInt8 *)(uintptr_t)rm->getVirtualAddress();

                // Fingerprint: whether the contents really look like a
                // driver-constructed TX ring.
                const amdobs::TxRingFingerprint fp =
                    amdobs::txRingFingerprint(rb, 1024);
                const bool registeredTx = fR31Session && txBacking;
                fM22b2Dma.txRingDecoded = fp.decoded;
                fM22b2Dma.txRingFpOk = fp.ok;
                fM22b2Dma.txRingBasis = registeredTx
                    ? amdobs::RB_REGISTERED_FIXED_DMA_OBJECT
                    : (fp.ok ? amdobs::RB_FINGERPRINT : amdobs::RB_REGISTER_AND_MAP);
                setProperty("m2-b2-dma-tx-ring-basis",
                            amdobs::ringBasisName(fM22b2Dma.txRingBasis));
                setHexProperty(this, "m2-b2-dma-tx-ring-decoded",
                               (UInt64)fp.decoded);
                setHexProperty(this, "m2-b2-dma-tx-ring-badlen",
                               (UInt64)fp.badLen);
                setProperty("m2-b2-dma-tx-ring-fp",
                            fp.ok ? "ok" : "FAIL-content-mismatch");
                if (!fp.ok && !registeredTx) {
                    // A failed fingerprint still blocks an unregistered ring.
                    fM22b2Dma.unscanned += 1024;
                    rm->release();
                    ringMd->release();
                    fM22b2Dma.haveTxRing = false;
                    goto afterTxRing;
                }
                const amdobs::TxRingStats ts = amdobs::scanTxRing(rb, 1024);
                fM22b2Dma.txSlots = ts.slots;
                fM22b2Dma.txOwned = ts.owned;
                fM22b2Dma.txDone = ts.done;
                fM22b2Dma.txAddrZero = ts.addrZero;
                fM22b2Dma.txTsoSlots = ts.tsoSlots;
                fM22b2Dma.txFirstAddr = ts.firstAddr;
                fM22b2Dma.txDoneWithAddrBefore = ts.doneWithAddr;

                // Raw three-field export: to judge whether stride / ring base /
                // length field are right.
                for (UInt32 di = 0; di < 8; di++) {
                    const UInt8 *dd =
                        rb + (UInt64)di * amdobs::TX_DESC_STRIDE;
                    char k[56];
                    char v[128];
                    snprintf(k, sizeof(k), "m2-b2-dma-txdesc%u", di);
                    snprintf(v, sizeof(v),
                             "opts1=%08x opts2=%08x addr=%016llx len=0x%x",
                             amdobs::rd32(dd), amdobs::rd32(dd + 4),
                             (unsigned long long)amdobs::rd64(dd + 8),
                             amdobs::rd32(dd) & amdobs::TX_DESC_LENMASK);
                    setProperty(k, v);
                }

                m2b2CollectTxSegments(rb, 1024, fM22b2Dma.tailPtrBefore,
                                      fM22b2Dma.cloPtrBefore);
                rm->release();
            } else {
                setProperty("m2-b2-dma-tx-scan", "map-failed");
                fM22b2Dma.unscanned += 1024;
            }
            ringMd->release();
        } else {
            setProperty("m2-b2-dma-tx-scan", "md-failed");
            fM22b2Dma.unscanned += 1024;
        }
    }
afterTxRing:

    if (fM22b2Dma.haveRxRing) {
        IOMemoryDescriptor *ringMd =
            IOMemoryDescriptor::withPhysicalAddress(rxReadPA,
                                                    kRxDescBytes,
                                                    kIODirectionIn);
        if (ringMd) {
            IOMemoryMap *rm = ringMd->map(kIOMapInhibitCache | kIOMapReadOnly);
            if (rm) {
                const UInt8 *rb =
                    (const UInt8 *)(uintptr_t)rm->getVirtualAddress();

                // Fingerprint: the driver writes RingEnd into the last
                // descriptor at setup and never clears it afterwards. Its
                // presence at that position is the strongest currently
                // obtainable evidence that "this PA is the RX ring".
                const amdobs::RxRingFingerprint fp =
                    amdobs::rxRingFingerprint(rb, 1024);
                fM22b2Dma.rxRingRingEndAtLast = fp.ringEndAtLast;
                fM22b2Dma.rxRingFpOk = fp.ok;
                fM22b2Dma.rxRingBasis = fp.ok ? amdobs::RB_FINGERPRINT
                                              : amdobs::RB_REGISTER_AND_MAP;
                setProperty("m2-b2-dma-rx-ring-basis",
                            amdobs::ringBasisName(fM22b2Dma.rxRingBasis));
                setHexProperty(this, "m2-b2-dma-rx-ring-decoded",
                               (UInt64)fp.decoded);
                setHexProperty(this, "m2-b2-dma-rx-ring-ringend-at-last",
                               (UInt64)fp.ringEndAtLast);
                if (!fp.ok) {
                    setProperty("m2-b2-dma-rx-ring-fp", "FAIL-content-mismatch");
                    fM22b2Dma.unscanned += 1024;
                    rm->release();
                    ringMd->release();
                    fM22b2Dma.haveRxRing = false;
                    goto afterRxRing;
                }
                setProperty("m2-b2-dma-rx-ring-fp", "ok");

                const amdobs::RxRingStats rs = amdobs::scanRxRing(rb, 1024);
                fM22b2Dma.rxSlots = rs.slots;
                fM22b2Dma.rxOwned = rs.owned;
                fM22b2Dma.rxDone = rs.done;
                fM22b2Dma.rxAddrZero = rs.addrZero;
                fM22b2Dma.rxFirstAddr = rs.firstAddr;
                m2b2CollectRxSegments(rb, 1024);
                rm->release();
            } else {
                setProperty("m2-b2-dma-rx-scan", "map-failed");
                fM22b2Dma.unscanned += 1024;
            }
            ringMd->release();
        } else {
            setProperty("m2-b2-dma-rx-scan", "md-failed");
            fM22b2Dma.unscanned += 1024;
        }
    }
afterRxRing:

    fM22b2Dma.ranges = set.n;
    fM22b2Dma.dropped = set.droppedCount;
    fM22b2Dma.rawOffered = set.rawOffered;
    fM22b2Dma.mergedTotal = set.mergedTotal;
    fM22b2Dma.unscanned += set.unscanned;
    fM22b2Dma.envValid = set.envValid;
    fM22b2Dma.envLo = set.envLo;
    fM22b2Dma.envHi = set.envHi;

    // Read-permission statistics: record why each range is / is not readable.
    for (UInt32 i = 0; i < set.n; i++) {
        if (set.r[i].readable == amdobs::RD_OK) fM22b2Dma.readOkCount++;
        else if (set.r[i].readable == amdobs::RD_OUT_OF_MAP)
            fM22b2Dma.readOutOfMapCount++;
        else if (set.r[i].readable == amdobs::RD_NOT_RAM)
            fM22b2Dma.readNotRamCount++;
    }

    // Coverage: one snapshot. Window coverage awaits the tail-pointer delta
    // after the window ends.
    //
    // [Round 8] Per-path initialization. At this moment every path has only a
    // snapshot; whole-window coverage of the TX buffer path only becomes
    // claimable after m2b2ScanTxWindowAfter() runs post-window. Rings and the
    // statistics buffer **do not** gain whole-window coverage: we make no
    // window argument for them.
    fM22b2Dma.pathCov.clear();
    fM22b2Dma.pathCov.set(amdobs::PATH_TX_RING, amdobs::COV_SNAPSHOT);
    fM22b2Dma.pathCov.set(amdobs::PATH_RX_RING, amdobs::COV_SNAPSHOT);
    fM22b2Dma.pathCov.set(amdobs::PATH_TX_BUF, amdobs::COV_SNAPSHOT);
    fM22b2Dma.pathCov.set(amdobs::PATH_RX_BUF, amdobs::COV_SNAPSHOT);
    fM22b2Dma.pathCov.set(amdobs::PATH_STAT, amdobs::COV_SNAPSHOT);
    fM22b2Dma.coverage = amdobs::COV_SNAPSHOT;

    fM22b2Dma.tObsAfter = m2b2NowNS();

    // ---- 7. Publish the results ----
    setHexProperty(this, "m2-b2-dma-tx-slots", fM22b2Dma.txSlots);
    setHexProperty(this, "m2-b2-dma-tx-owned", fM22b2Dma.txOwned);
    setHexProperty(this, "m2-b2-dma-tx-done", fM22b2Dma.txDone);
    setHexProperty(this, "m2-b2-dma-tx-done-with-addr",
                   fM22b2Dma.txDoneWithAddrBefore);
    setHexProperty(this, "m2-b2-dma-tx-zeroaddr", fM22b2Dma.txAddrZero);
    setHexProperty(this, "m2-b2-dma-tx-tso", fM22b2Dma.txTsoSlots);
    setHexProperty(this, "m2-b2-dma-tx-firstaddr", fM22b2Dma.txFirstAddr);
    setHexProperty(this, "m2-b2-dma-rx-slots", fM22b2Dma.rxSlots);
    setHexProperty(this, "m2-b2-dma-rx-owned", fM22b2Dma.rxOwned);
    setHexProperty(this, "m2-b2-dma-rx-done", fM22b2Dma.rxDone);
    setHexProperty(this, "m2-b2-dma-rx-zeroaddr", fM22b2Dma.rxAddrZero);
    setHexProperty(this, "m2-b2-dma-rx-firstaddr", fM22b2Dma.rxFirstAddr);

    // The five counter classes are published separately and never mixed.
    setHexProperty(this, "m2-b2-dma-ranges", fM22b2Dma.ranges);
    setHexProperty(this, "m2-b2-dma-dropped", fM22b2Dma.dropped);
    setHexProperty(this, "m2-b2-dma-raw-offered", fM22b2Dma.rawOffered);
    setHexProperty(this, "m2-b2-dma-merged-total", fM22b2Dma.mergedTotal);
    setHexProperty(this, "m2-b2-dma-unscanned", fM22b2Dma.unscanned);
    setProperty("m2-b2-dma-envelope-valid",
                fM22b2Dma.envValid ? "yes" : "no");
    setHexProperty(this, "m2-b2-dma-envelope-lo", fM22b2Dma.envLo);
    setHexProperty(this, "m2-b2-dma-envelope-hi", fM22b2Dma.envHi);
    setProperty("m2-b2-dma-coverage",
                amdobs::coverageName(fM22b2Dma.coverage));

    setHexProperty(this, "m2-b2-dma-read-ok", fM22b2Dma.readOkCount);
    setHexProperty(this, "m2-b2-dma-read-outofmap",
                   fM22b2Dma.readOutOfMapCount);
    setHexProperty(this, "m2-b2-dma-read-notram", fM22b2Dma.readNotRamCount);

    setHexProperty(this, "m2-b2-dma-t-obs-before", fM22b2Dma.tObsBefore);
    setHexProperty(this, "m2-b2-dma-t-obs-after", fM22b2Dma.tObsAfter);
    setHexProperty(this, "m2-b2-dma-t-clo-before", fM22b2Dma.tCloBefore);

    // [Round 8] Per-path coverage state is published separately.
    // A single coverage value cannot express "TX complete, RX snapshot only",
    // and using the latter as the former is exactly where round 7
    // over-generalized.
    setProperty("m2-b2-dma-cov-txring",
                amdobs::coverageName(fM22b2Dma.pathCov.txRing));
    setProperty("m2-b2-dma-cov-rxring",
                amdobs::coverageName(fM22b2Dma.pathCov.rxRing));
    setProperty("m2-b2-dma-cov-txbuf",
                amdobs::coverageName(fM22b2Dma.pathCov.txBuf));
    setProperty("m2-b2-dma-cov-rxbuf",
                amdobs::coverageName(fM22b2Dma.pathCov.rxBuf));
    setProperty("m2-b2-dma-cov-stat",
                amdobs::coverageName(fM22b2Dma.pathCov.stat));
    setProperty("m2-b2-dma-cov-weakest",
                amdobs::coverageName(fM22b2Dma.pathCov.weakest()));
    setProperty("m2-b2-dma-cov-all-window",
                fM22b2Dma.pathCov.allWindow() ? "yes" : "no");

    // [Round 8] The grounds for reading ring memory are published item by item.
    setProperty("m2-b2-dma-tx-ring-basis",
                amdobs::ringBasisName(fM22b2Dma.txRingBasis));
    setProperty("m2-b2-dma-rx-ring-basis",
                amdobs::ringBasisName(fM22b2Dma.rxRingBasis));
    setHexProperty(this, "m2-b2-dma-tx-ring-decoded",
                   (UInt64)fM22b2Dma.txRingDecoded);
    setHexProperty(this, "m2-b2-dma-rx-ring-ringend-at-last",
                   (UInt64)fM22b2Dma.rxRingRingEndAtLast);
    // Number of ranges whose length could not be decoded: when non-zero, exact
    // coverage must not be claimed negatively.
    setHexProperty(this, "m2-b2-dma-len-unknown",
                   (UInt64)set.savedLenUnknown);

    // Range details (bounded count, to avoid a property explosion)
    for (UInt32 i = 0; i < set.n && i < 16; i++) {
        char k[56];
        snprintf(k, sizeof(k), "m2-b2-dma-range%u-base", i);
        setHexProperty(this, k, set.r[i].base);
        snprintf(k, sizeof(k), "m2-b2-dma-range%u-len", i);
        setHexProperty(this, k, set.r[i].len);
        snprintf(k, sizeof(k), "m2-b2-dma-range%u-purpose", i);
        setProperty(k, amdobs::purposeName(set.r[i].purpose));
        snprintf(k, sizeof(k), "m2-b2-dma-range%u-life", i);
        setProperty(k, amdobs::lifecycleName(set.r[i].lifecycle));
        snprintf(k, sizeof(k), "m2-b2-dma-range%u-read", i);
        setProperty(k, amdobs::readVerdictName(set.r[i].readable));
    }
    setHexProperty(this, "m2-b2-dma-range-listed",
                   (UInt64)((set.n < 16) ? set.n : 16));

    fM22b2Dma.ran = true;
    // "complete" means the observation ran. It does NOT mean the values are
    // usable; m2-b2-dma-trust carries that separate judgement.
    setProperty("m2-b2-dma-obs", "complete");

    barMap->release();
    nic->release();
}
