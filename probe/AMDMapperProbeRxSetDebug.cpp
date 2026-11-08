// AMDMapperProbeRxSet.cpp -- round 14: the RX posted-buffer SET.
//
// Part of the AMDMapperProbe kext. Added as its own translation unit rather
// than appended to AMDMapperProbePgt.cpp so that "did this round's code run?"
// is answerable from the binary (tools/build/build-probe.sh names its entry points).
//
// ===========================================================================
// WHAT THIS MODULE ANSWERS, AND WHY THE OLD ANSWER WAS NOT ENOUGH
// ===========================================================================
//
// Round 13 walked eight DMA ranges: the four controlled requests' TX buffers
// and the four RX buffers that carried their echoes. All eight were mapped.
//
// That is a statement about eight buffers. The RX ring holds 1024 posted
// page-sized buffers, and the driver re-posts them continuously, so during a
// three-second window the device can write into far more than eight buffers --
// including buffers that were already posted before the window opened and were
// replaced while it ran.
//
// The question M2-2b-2 has to answer for the RX direction is therefore a set
// question:
//
//     is EVERY RX buffer the device could write during the window mapped, and
//     mapped with write permission?
//
// This module builds that set and walks it:
//
//     S = { (addr, capacity) in the baseline slot table }
//       ∪ { (addr, capacity) from every rearm record with seq > watermark }
//
// The set is CONSERVATIVE: it is a superset of what the device can reach at any
// instant in [t_baseline, t_end], so a proof over S is a proof over the window.
// The argument is written out in probe/amd_iommu_rxset_core.hpp and the three
// conditions it depends on (no gap, no loss, no ring rebuild) are checked here
// rather than assumed.
//
// ===========================================================================
// WHERE THE TWO READS HAPPEN
// ===========================================================================
//
//   before the window : m2b2RxSetRead(true)  -- records the WATERMARK
//   after the window  : m2b2RxSetRead(false) -- the baseline + rearm log used
//   then              : m2b2BuildRxSet() + m2b2WalkRxSet()
//
// The watermark is read BEFORE the window and the set is built AFTER it. That
// ordering is the whole design: a rearm that happens during the window has a
// sequence number greater than the watermark, so it is required; a rearm that
// happened before the window does not, so it is already reflected in the
// baseline. Reading the watermark after the window would make every rearm
// look "already in the baseline" and the set would silently shrink to whatever
// the last capture happened to see.
//
// ===========================================================================
// WHY THE RAW BYTES ARE EXPORTED
// ===========================================================================
//
// The analyser must be able to rebuild S from the driver's own publication and
// compare it with what the probe walked. If the probe only published its
// conclusion, "the set was covered" would be a claim about the probe's own
// arithmetic. So the exact bytes the probe decoded are published as an OSData
// property and their sha256 alongside it, exactly as round 11 did for the
// observation log -- and for the same reason.

#include "AMDMapperProbe.hpp"
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOWorkLoop.h>

// IOPCIDevice.h itself triggers two -Werror-level warnings from within the SDK
// (see the same note in AMDMapperProbeObs.cpp). Suppress only these two, not
// globally.
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

#include "amd_iommu_pte_core.hpp"
#include "amd_iommu_bizwalk_core.hpp"
#include "amd_iommu_rxset_core.hpp"
#include "amd_iommu_sparse_core.hpp"

#include "AMDMapperProbeInternal.hpp"

// The driver's wire header is deliberately NOT included here. The blob is
// decoded through amd_iommu_rxset_core.hpp, which carries the offsets as
// numbers and asserts them against that header in the host test
// (tools/verify/rxpost-layout.py). Including the driver's header in the
// probe would make the probe depend on a file the driver build owns, and a
// drift between the two would then be a compile error in whichever tree was
// built second rather than a checked property.

// ===========================================================================
// One read of the driver's RX post publication.
// ===========================================================================
//
// WHY THE DECODE IS IN THE PROBE RATHER THAN IN THE CORE
// ------------------------------------------------------
// amd_iommu_rxset_core.hpp decodes the blob (decodeBlob/slotAt/rearmAt) so the
// host test can drive it. This function is the IOKit part: find the driver
// node, copy the property, hash it, export it. Keeping them separate is what
// lets the test cover the decode without a kernel.
bool org_maz1_AMDMapperProbe::m2b2RxSetRead(bool beforeWindow) {
    fM22b2Dma.rxsetPresent = false;
    fM22b2Dma.rxsetWhy = "not-read";
    fM22b2Dma.rxsetSetWhy = "not-built";
    fM22b2Dma.rxsetComplete = false;
    fM22b2Dma.rxsetRanges = 0;
    fM22b2Dma.rxsetWalked = 0;
    fM22b2Dma.rxsetOk = 0;
    fM22b2Dma.rxsetFail = 0;
    fM22b2Dma.rxsetFailCapped = 0;
    fM22b2Dma.rxsetFailCount = 0;
    fM22b2Dma.rxsetSampleCount = 0;
    fM22b2Dma.rxsetRawExported = false;
    fM22b2Dma.rxsetRawBytes = 0;
    fM22b2Dma.rxsetRawSha[0] = 0;
    fM22b2Dma.rxsetRawWhy = "not-exported";
    fM22b2Dma.rxsetMinAddr = 0;
    fM22b2Dma.rxsetMaxEnd = 0;
    fM22b2Dma.rxsetBytesTotal = 0;

    IOService *svc = findNicServiceOnly();
    if (!svc) {
        fM22b2Dma.rxsetWhy = "nic-not-found";
        return false;
    }

    const char *src = "unknown";
    IOService *obsSvc = m2b2FindObsService(svc, &src);

    OSObject *o = obsSvc ? obsSvc->copyProperty("rtl812x-rxpost") : nullptr;
    OSData *d = o ? OSDynamicCast(OSData, o) : nullptr;
    if (o && !d) o->release();
    if (!d) {
        fM22b2Dma.rxsetWhy = obsSvc ? "property-absent" : "no-obs-service";
        if (obsSvc != svc) obsSvc->release();
        svc->release();
        return false;
    }

    const UInt32 bytes = (UInt32)d->getLength();
    const UInt8 *base = (const UInt8 *)d->getBytesNoCopy();
    const amdrx::BlobHeader h = amdrx::decodeBlob(base, (amdobs::u64)bytes);
    if (!h.ok) {
        fM22b2Dma.rxsetWhy = h.why ? h.why : "header-rejected";
        d->release();
        if (obsSvc != svc) obsSvc->release();
        svc->release();
        return false;
    }

    // ---- identity: this publication must belong to THIS driver instance --
    //
    // The epoch is bound before the window (round 11). A publication whose
    // epoch differs came from a previous load of the driver, and its baseline
    // describes a ring that no longer exists.
    if (h.epoch != fM22b2Dma.epochBound) {
        fM22b2Dma.rxsetWhy = "epoch-mismatch";
        d->release();
        if (obsSvc != svc) obsSvc->release();
        svc->release();
        return false;
    }

    if (!beforeWindow) {
        setHexProperty(this, "m2-b2-rxset-t-published", h.tPublished);
        const bool throughEnd = fM22b2Dma.tWinEnd != 0 &&
                                h.tPublished >= fM22b2Dma.tWinEnd;
        setProperty("m2-b2-rxset-published-through-end",
                    throughEnd ? "yes" : "no");
        if (!throughEnd) {
            fM22b2Dma.rxsetWhy = "publication-before-window-end";
            d->release();
            if (obsSvc != svc) obsSvc->release();
            svc->release();
            return false;
        }
    }

    if (beforeWindow) {
        // The WATERMARK. Everything with a larger sequence number is produced
        // by the window (or by the capture interval around it).
        fM22b2Dma.rxsetWatermark = h.head;
        fM22b2Dma.rxsetPreRingGen = h.ringGen;
        fM22b2Dma.rxsetPreEpoch = h.epoch;
        d->release();
        if (obsSvc != svc) obsSvc->release();
        svc->release();
        setHexProperty(this, "m2-b2-rxset-watermark", (UInt64)h.head);
        setHexProperty(this, "m2-b2-rxset-pre-ring-gen", (UInt64)h.ringGen);
        setHexProperty(this, "m2-b2-rxset-pre-baseline-slots",
                       (UInt64)h.baselineSlots);
        setHexProperty(this, "m2-b2-rxset-pre-baseline-count",
                       (UInt64)h.baselineCount);
        setProperty("m2-b2-rxset-pre", "read");
        return true;
    }

    // ---- the AFTER read: this is the publication the set is built from ----
    //
    // Export the exact bytes first, so the analyser can rebuild the set from
    // them rather than from the probe's summary. The hash is computed twice --
    // before and after the decode below -- and a difference means the buffer
    // changed under us, which for a retained OSData should be impossible and is
    // therefore treated as a hard failure of the export rather than something
    // to work around.
    char shaBefore[65];
    amdobs::sha256::hashHex(base, (amdobs::u64)bytes, shaBefore);

    fM22b2Dma.rxsetHead = h.head;
    fM22b2Dma.rxsetRingGen = h.ringGen;
    fM22b2Dma.rxsetEpoch = h.epoch;
    fM22b2Dma.rxsetIfUnit = h.ifUnit;
    fM22b2Dma.rxsetVtdPath = h.vtdPath;
    fM22b2Dma.rxsetBaselineSlots = h.baselineSlots;
    fM22b2Dma.rxsetBaselineValid = h.baselineValid;
    fM22b2Dma.rxsetBaselineCapDesc = h.baselineCapDesc;
    fM22b2Dma.rxsetBaselineCapConst = h.baselineCapConst;
    fM22b2Dma.rxsetBaselineCapBad = h.baselineCapBad;
    fM22b2Dma.rxsetBaselineTorn = h.baselineTorn;
    fM22b2Dma.rxsetBaselineCount = h.baselineCount;
    fM22b2Dma.rxsetBaselineGenMoved = h.baselineGenMoved;

    // ---- build S from the two halves -------------------------------------
    //
    // The slot table and the rearm log are decoded here and handed to the
    // shared core, which is the SAME code the host test compiles. So "the
    // union is complete" is a property of one function rather than of this
    // call site.
    //
    // WHY THE DECODE ARRAYS ARE STATIC RATHER THAN IOMalloc'd
    // ------------------------------------------------------
    // 1024 slot records (32 B) + up to 4096 rearm records (40 B) is 192 KiB.
    // That is far past the kernel stack, and IOMalloc here would be a heap
    // allocation on a path that must not fail for a memory reason while
    // holding a 192 KiB transient. They are function-local `static` because
    // the probe is a singleton and this runs once per experiment on the
    // work-loop thread: no reentrancy, no concurrency, and no allocator.
    static amdrx::SlotRec sSlots[amdrx::RXB_SLOT_MAX];
    static amdrx::RearmRec sRearms[amdrx::RXB_REARM_MAX];
    if (h.slotCount > (UInt32)amdrx::RXB_SLOT_MAX ||
        h.rearmCount > (UInt32)amdrx::RXB_REARM_MAX) {
        fM22b2Dma.rxsetWhy = "more-records-than-the-core-accepts";
        d->release();
        if (obsSvc != svc) obsSvc->release();
        svc->release();
        return false;
    }
    {
        for (UInt32 i = 0; i < h.slotCount; i++)
            sSlots[i] = amdrx::slotAt(base, i);
        for (UInt32 i = 0; i < h.rearmCount; i++)
            sRearms[i] = amdrx::rearmAt(base, i);

        // A ring generation that moved between the two reads invalidates the
        // join: the baseline describes a different ring than the rearm log.
        if (h.ringGen != fM22b2Dma.rxsetPreRingGen) {
            fM22b2Dma.rxsetWhy = "ring-rebuilt-during-window";
            fM22b2Dma.rxsetSetWhy = "ring-rebuilt-during-window";
            fM22b2Dma.rxsetComplete = false;
            d->release();
            if (obsSvc != svc) obsSvc->release();
            svc->release();
            setProperty("m2-b2-rxset", "SKIP-ring-rebuilt");
            return false;
        }

        amdrx::SetResult res;
        amdrx::buildSet(sSlots, h.slotCount, sRearms, h.rearmCount,
                        fM22b2Dma.rxsetWatermark, h.head, h.rearmFirstSeq,
                        fM22b2Dma.rxsetList, M22b2DmaObs::kRxSetMaxRanges,
                        res);

        fM22b2Dma.rxsetRanges = res.ranges;
        fM22b2Dma.rxsetFromBaseline = res.fromBaseline;
        fM22b2Dma.rxsetFromRearm = res.fromRearm;
        fM22b2Dma.rxsetFromBoth = res.fromBoth;
        fM22b2Dma.rxsetCapped = res.capped;
        fM22b2Dma.rxsetSkippedZero = res.skippedZero;
        fM22b2Dma.rxsetSkippedBadCap = res.skippedBadCap;
        fM22b2Dma.rxsetRearmRequired = res.rearmRequired;
        fM22b2Dma.rxsetRearmUsed = res.rearmUsed;
        fM22b2Dma.rxsetRearmSeen = res.rearmSeen;
        fM22b2Dma.rxsetComplete = res.complete;
        fM22b2Dma.rxsetSetWhy = res.why;   // nullptr == complete
    }

    // ---- export the raw bytes -------------------------------------------
    {
        char shaAfter[65];
        amdobs::sha256::hashHex(base, (amdobs::u64)bytes, shaAfter);
        if (strcmp(shaBefore, shaAfter) != 0) {
            fM22b2Dma.rxsetRawWhy = "snapshot-changed-during-decode";
        } else {
            OSData *raw = OSData::withBytes(base, bytes);
            if (raw) {
                setProperty("m2-b2-rxset-raw", raw);
                raw->release();
                fM22b2Dma.rxsetRawExported = true;
                fM22b2Dma.rxsetRawBytes = bytes;
                fM22b2Dma.rxsetRawWhy = "ok";
                memcpy(fM22b2Dma.rxsetRawSha, shaAfter,
                       sizeof(fM22b2Dma.rxsetRawSha));
            } else {
                fM22b2Dma.rxsetRawWhy = "could-not-allocate-export";
            }
        }
    }

    d->release();
    if (obsSvc != svc) obsSvc->release();
    svc->release();

    fM22b2Dma.rxsetPresent = true;
    fM22b2Dma.rxsetWhy = "ok";
    return true;
}

// ===========================================================================
// Walk every range in S.
// ===========================================================================
//
// Reuses amdbw::walkRange() -- the SAME function that walks the business
// ranges -- so a defect in the walker shows up in both places rather than in
// one and not the other. The capacity is the range length, so "the device may
// write capacity bytes here" becomes "all capacity bytes are covered".
//
// The export is deliberately asymmetric:
//
//   * every FAILING range is exported in full (up to kRxSetDetailMax), because
//     a failure needs an address, a length, a source and a reason to act on;
//   * only a small SAMPLE of the passing ranges is exported with its full page
//     table path, because 1024 identical 4 KiB pages would be 1024 copies of
//     the same three PTEs. The sample is still re-checkable: the analyser
//     verifies the sampled paths against the raw PTEs and separately verifies
//     that the COUNTS add up (walked == ok + fail + capped).
void org_maz1_AMDMapperProbe::m2b2WalkRxSet(
        const volatile UInt64 *dte, UInt32 tgt,
        const volatile UInt64 *ptv, UInt64 ptBase, UInt64 ptBytes) {
    fM22b2Dma.rxsetWalked = 0;
    fM22b2Dma.rxsetOk = 0;
    fM22b2Dma.rxsetFail = 0;
    fM22b2Dma.rxsetFailCapped = 0;
    fM22b2Dma.rxsetFailCount = 0;
    fM22b2Dma.rxsetSampleCount = 0;
    fM22b2Dma.rxsetMinAddr = 0;
    fM22b2Dma.rxsetMaxEnd = 0;
    fM22b2Dma.rxsetBytesTotal = 0;

    if (!dte || !ptv || ptBase == 0 || ptBytes == 0) {
        setProperty("m2-b2-rxset-walk", "SKIP-no-page-table");
        return;
    }

    const UInt64 dteRaw = (UInt64)dte[tgt * 4 + 0];
    const UInt64 dteMode =
        (dteRaw >> M2B2_DEV_ENTRY_MODE_SHIFT) & M2B2_DEV_ENTRY_MODE_MASK;
    const UInt64 dteRootPA = dteRaw & M2B2_PTE_ADDR_MASK;
    const bool dteValid = (dteRaw & DTE_V) != 0;
    const bool dteTranslate = (dteRaw & DTE_TV) != 0 && dteMode != 0;
    const unsigned rootLevel =
        (dteMode == 3) ? amdpte::LEVEL_1G
                       : (dteMode == 4 ? amdpte::LEVEL_512G : 0);

    setHexProperty(this, "m2-b2-rxset-dte-raw", dteRaw);
    setHexProperty(this, "m2-b2-rxset-dte-root-pa", dteRootPA);
    setHexProperty(this, "m2-b2-rxset-root-level", (UInt64)rootLevel);

    if (!dteValid || !dteTranslate || rootLevel == 0) {
        // Every range in S is UNPROVEN, not "zero failures".
        fM22b2Dma.rxsetFail = fM22b2Dma.rxsetRanges;
        setProperty("m2-b2-rxset-walk", "SKIP-dte-not-translating");
        return;
    }

    const UInt64 ptEnd = ptBase + ptBytes;
    auto readEntry = [&](UInt64 tablePA, unsigned index) -> UInt64 {
        if (tablePA < ptBase || tablePA >= ptEnd) return 0;
        const UInt64 byteOff = tablePA - ptBase;
        if (byteOff + 8ULL * (UInt64)index + 8ULL > ptBytes) return 0;
        return (UInt64)ptv[byteOff / 8 + index];
    };

    for (UInt32 i = 0; i < fM22b2Dma.rxsetRanges; i++) {
        const amdrx::Range &rg = fM22b2Dma.rxsetList[i];

        amdbw::RangeResult r;
        // RX direction: the device WRITES, so the required bit is IW.
        amdbw::walkRange(readEntry, rootLevel, dteRootPA,
                         rg.addr, rg.capacity, /*isRx*/ true, r);

        fM22b2Dma.rxsetWalked++;
        fM22b2Dma.rxsetBytesTotal += rg.capacity;
        if (fM22b2Dma.rxsetMinAddr == 0 || rg.addr < fM22b2Dma.rxsetMinAddr)
            fM22b2Dma.rxsetMinAddr = rg.addr;
        const UInt64 end = rg.addr + rg.capacity;
        if (end > fM22b2Dma.rxsetMaxEnd) fM22b2Dma.rxsetMaxEnd = end;

        if (r.ok) {
            fM22b2Dma.rxsetOk++;
            // Keep a bounded sample WITH its path, so the analyser can verify
            // a real chain rather than only a counter.
            if (fM22b2Dma.rxsetSampleCount <
                M22b2DmaObs::kRxSetSampleMax) {
                const UInt32 s = fM22b2Dma.rxsetSampleCount;
                auto &d = fM22b2Dma.rxsetSample[s];
                d.addr = rg.addr;
                d.capacity = rg.capacity;
                d.source = rg.source;
                d.slot = rg.slot;
                d.ok = 1;
                d.permOk = r.permOk ? 1 : 0;
                d.leaves = (UInt8)(r.leafCount > 255 ? 255 : r.leafCount);
                d.reserved = 0;
                d.why = "ok";
                auto &sp = fM22b2Dma.rxsetSamplePath[s];
                sp.leafCount = d.leaves;
                if (r.leafCount > 0) {
                    const amdbw::Path &p0 = r.path[0];
                    sp.depth = (UInt8)(p0.depth > M22b2DmaObs::kBizWalkMaxLevels
                                           ? M22b2DmaObs::kBizWalkMaxLevels
                                           : p0.depth);
                    sp.leafPA = p0.leafPA;
                    sp.leafSize = p0.leafSize;
                    sp.leafLevel = p0.leafLevel;
                    for (UInt32 k = 0; k < sp.depth; k++) {
                        sp.tablePA[k] = p0.table[k];
                        sp.index[k] = p0.index[k];
                        sp.level[k] = p0.level[k];
                        sp.pte[k] = p0.pte[k];
                    }
                }
                fM22b2Dma.rxsetSampleCount++;
            }
        } else {
            fM22b2Dma.rxsetFail++;
            if (r.capped) fM22b2Dma.rxsetFailCapped++;
            if (fM22b2Dma.rxsetFailCount < M22b2DmaObs::kRxSetDetailMax) {
                auto &d =
                    fM22b2Dma.rxsetFailDetail[fM22b2Dma.rxsetFailCount];
                d.addr = rg.addr;
                d.capacity = rg.capacity;
                d.source = rg.source;
                d.slot = rg.slot;
                d.ok = 0;
                d.permOk = r.permOk ? 1 : 0;
                d.leaves = (UInt8)(r.leafCount > 255 ? 255 : r.leafCount);
                d.reserved = 0;
                d.why = r.why ? r.why : "walk-failed";
                fM22b2Dma.rxsetFailCount++;
            }
        }
    }

    setProperty("m2-b2-rxset-walk",
                fM22b2Dma.rxsetFail == 0 ? "all-covered"
                                         : "SOME-NOT-COVERED");
}

// ===========================================================================
// Publish the set and its result.
// ===========================================================================
//
// The counters are published separately from the per-range detail so that a
// reader can check the ARITHMETIC (walked == ok + fail, ranges == fromBaseline
// + fromRearm - fromBoth) without parsing 3072 property lines. That identity is
// what makes "all covered" a claim about the whole set rather than about the
// exported sample.
void org_maz1_AMDMapperProbe::m2b2PublishRxSet() {
    setProperty("m2-b2-rxset", fM22b2Dma.rxsetPresent ? "present"
                                                      : "SKIP-not-read");
    setProperty("m2-b2-rxset-why",
                fM22b2Dma.rxsetWhy ? fM22b2Dma.rxsetWhy : "unknown");
    setProperty("m2-b2-rxset-set-why",
                fM22b2Dma.rxsetSetWhy ? fM22b2Dma.rxsetSetWhy : "complete");
    setProperty("m2-b2-rxset-complete",
                fM22b2Dma.rxsetComplete ? "yes" : "no");

    setHexProperty(this, "m2-b2-rxset-watermark",
                   (UInt64)fM22b2Dma.rxsetWatermark);
    setHexProperty(this, "m2-b2-rxset-head", (UInt64)fM22b2Dma.rxsetHead);
    setHexProperty(this, "m2-b2-rxset-ring-gen", (UInt64)fM22b2Dma.rxsetRingGen);
    setHexProperty(this, "m2-b2-rxset-pre-ring-gen",
                   (UInt64)fM22b2Dma.rxsetPreRingGen);
    setHexProperty(this, "m2-b2-rxset-epoch", (UInt64)fM22b2Dma.rxsetEpoch);
    setHexProperty(this, "m2-b2-rxset-ifunit", (UInt64)fM22b2Dma.rxsetIfUnit);
    setHexProperty(this, "m2-b2-rxset-vtd-path", (UInt64)fM22b2Dma.rxsetVtdPath);

    setHexProperty(this, "m2-b2-rxset-baseline-slots",
                   (UInt64)fM22b2Dma.rxsetBaselineSlots);
    setHexProperty(this, "m2-b2-rxset-baseline-valid",
                   (UInt64)fM22b2Dma.rxsetBaselineValid);
    setHexProperty(this, "m2-b2-rxset-baseline-capdesc",
                   (UInt64)fM22b2Dma.rxsetBaselineCapDesc);
    setHexProperty(this, "m2-b2-rxset-baseline-capconst",
                   (UInt64)fM22b2Dma.rxsetBaselineCapConst);
    setHexProperty(this, "m2-b2-rxset-baseline-capbad",
                   (UInt64)fM22b2Dma.rxsetBaselineCapBad);
    setHexProperty(this, "m2-b2-rxset-baseline-torn",
                   (UInt64)fM22b2Dma.rxsetBaselineTorn);
    setHexProperty(this, "m2-b2-rxset-baseline-count",
                   (UInt64)fM22b2Dma.rxsetBaselineCount);
    setHexProperty(this, "m2-b2-rxset-baseline-genmoved",
                   (UInt64)fM22b2Dma.rxsetBaselineGenMoved);

    setHexProperty(this, "m2-b2-rxset-ranges", (UInt64)fM22b2Dma.rxsetRanges);
    setHexProperty(this, "m2-b2-rxset-from-baseline",
                   (UInt64)fM22b2Dma.rxsetFromBaseline);
    setHexProperty(this, "m2-b2-rxset-from-rearm",
                   (UInt64)fM22b2Dma.rxsetFromRearm);
    setHexProperty(this, "m2-b2-rxset-from-both",
                   (UInt64)fM22b2Dma.rxsetFromBoth);
    setHexProperty(this, "m2-b2-rxset-capped", (UInt64)fM22b2Dma.rxsetCapped);
    setHexProperty(this, "m2-b2-rxset-skip-zero",
                   (UInt64)fM22b2Dma.rxsetSkippedZero);
    setHexProperty(this, "m2-b2-rxset-skip-badcap",
                   (UInt64)fM22b2Dma.rxsetSkippedBadCap);
    setHexProperty(this, "m2-b2-rxset-rearm-required",
                   (UInt64)fM22b2Dma.rxsetRearmRequired);
    setHexProperty(this, "m2-b2-rxset-rearm-used",
                   (UInt64)fM22b2Dma.rxsetRearmUsed);
    setHexProperty(this, "m2-b2-rxset-rearm-seen",
                   (UInt64)fM22b2Dma.rxsetRearmSeen);

    setHexProperty(this, "m2-b2-rxset-walked", (UInt64)fM22b2Dma.rxsetWalked);
    setHexProperty(this, "m2-b2-rxset-ok", (UInt64)fM22b2Dma.rxsetOk);
    setHexProperty(this, "m2-b2-rxset-fail", (UInt64)fM22b2Dma.rxsetFail);
    setHexProperty(this, "m2-b2-rxset-fail-capped",
                   (UInt64)fM22b2Dma.rxsetFailCapped);
    setHexProperty(this, "m2-b2-rxset-min-addr", fM22b2Dma.rxsetMinAddr);
    setHexProperty(this, "m2-b2-rxset-max-end", fM22b2Dma.rxsetMaxEnd);
    setHexProperty(this, "m2-b2-rxset-bytes", fM22b2Dma.rxsetBytesTotal);
    setHexProperty(this, "m2-b2-rxset-samples",
                   (UInt64)fM22b2Dma.rxsetSampleCount);

    // ---- the raw bytes the set was built from ----
    setProperty("m2-b2-rxset-raw-why",
                fM22b2Dma.rxsetRawWhy ? fM22b2Dma.rxsetRawWhy : "unknown");
    setProperty("m2-b2-rxset-raw-sha256", fM22b2Dma.rxsetRawSha);
    setHexProperty(this, "m2-b2-rxset-raw-bytes",
                   (UInt64)fM22b2Dma.rxsetRawBytes);
    // THE STATUS STRING MUST NOT USE THE BLOB'S PROPERTY NAME.
    //
    // The first version published the OSData as `m2-b2-rxset-raw` (in
    // m2b2RxSetRead) and then the string "exported" under the SAME key here.
    // IOKit replaces the property, so the blob was destroyed a few statements
    // after it was created: the probe reported `raw = exported`, published a
    // correct sha256 of bytes that no longer existed anywhere, and the capture
    // script -- correctly -- refused with "the probe did not export
    // m2-b2-rxset-raw".
    //
    // The observation-log export has the same shape and does not collide
    // (`m2-b2-obs-snapshot-used` vs `m2-b2-obs-used`); this now matches it.
    setProperty("m2-b2-rxset-raw-state",
                fM22b2Dma.rxsetRawExported ? "exported" : "SKIP");

    // ---- the failing ranges, one property block each ----
    //
    // A failure must be actionable: which slot, which address, how long, where
    // it came from, and why the walk refused it. Anything less turns "the set
    // is not covered" into a number nobody can act on.
    for (UInt32 i = 0; i < fM22b2Dma.rxsetFailCount; i++) {
        const auto &d = fM22b2Dma.rxsetFailDetail[i];
        char k[64];
        snprintf(k, sizeof(k), "m2-b2-rxset-bad%u-addr", (unsigned)i);
        setHexProperty(this, k, d.addr);
        snprintf(k, sizeof(k), "m2-b2-rxset-bad%u-cap", (unsigned)i);
        setHexProperty(this, k, (UInt64)d.capacity);
        snprintf(k, sizeof(k), "m2-b2-rxset-bad%u-slot", (unsigned)i);
        setHexProperty(this, k, (UInt64)d.slot);
        snprintf(k, sizeof(k), "m2-b2-rxset-bad%u-source", (unsigned)i);
        setProperty(k, (d.source == amdrx::RX_SRC_BASELINE) ? "baseline"
                        : (d.source == amdrx::RX_SRC_REARM) ? "rearm"
                                                            : "both");
        snprintf(k, sizeof(k), "m2-b2-rxset-bad%u-leaves", (unsigned)i);
        setHexProperty(this, k, (UInt64)d.leaves);
        snprintf(k, sizeof(k), "m2-b2-rxset-bad%u-perm-ok", (unsigned)i);
        setProperty(k, d.permOk ? "yes" : "no");
        snprintf(k, sizeof(k), "m2-b2-rxset-bad%u-why", (unsigned)i);
        setProperty(k, d.why ? d.why : "unknown");
    }
    setHexProperty(this, "m2-b2-rxset-bad-count",
                   (UInt64)fM22b2Dma.rxsetFailCount);

    // ---- the sampled passing ranges, with their paths ----
    for (UInt32 i = 0; i < fM22b2Dma.rxsetSampleCount; i++) {
        const auto &d = fM22b2Dma.rxsetSample[i];
        const auto &sp = fM22b2Dma.rxsetSamplePath[i];
        char k[64];
        snprintf(k, sizeof(k), "m2-b2-rxset-s%u-addr", (unsigned)i);
        setHexProperty(this, k, d.addr);
        snprintf(k, sizeof(k), "m2-b2-rxset-s%u-cap", (unsigned)i);
        setHexProperty(this, k, (UInt64)d.capacity);
        snprintf(k, sizeof(k), "m2-b2-rxset-s%u-slot", (unsigned)i);
        setHexProperty(this, k, (UInt64)d.slot);
        snprintf(k, sizeof(k), "m2-b2-rxset-s%u-source", (unsigned)i);
        setProperty(k, (d.source == amdrx::RX_SRC_BASELINE) ? "baseline"
                        : (d.source == amdrx::RX_SRC_REARM) ? "rearm"
                                                            : "both");
        snprintf(k, sizeof(k), "m2-b2-rxset-s%u-leaves", (unsigned)i);
        setHexProperty(this, k, (UInt64)sp.leafCount);
        snprintf(k, sizeof(k), "m2-b2-rxset-s%u-depth", (unsigned)i);
        setHexProperty(this, k, (UInt64)sp.depth);
        snprintf(k, sizeof(k), "m2-b2-rxset-s%u-leaf-pa", (unsigned)i);
        setHexProperty(this, k, sp.leafPA);
        snprintf(k, sizeof(k), "m2-b2-rxset-s%u-leaf-size", (unsigned)i);
        setHexProperty(this, k, sp.leafSize);
        snprintf(k, sizeof(k), "m2-b2-rxset-s%u-leaf-level", (unsigned)i);
        setHexProperty(this, k, (UInt64)sp.leafLevel);
        for (UInt32 L = 0; L < sp.depth; L++) {
            snprintf(k, sizeof(k), "m2-b2-rxset-s%u-pte%u-table",
                     (unsigned)i, (unsigned)L);
            setHexProperty(this, k, sp.tablePA[L]);
            snprintf(k, sizeof(k), "m2-b2-rxset-s%u-pte%u-index",
                     (unsigned)i, (unsigned)L);
            setHexProperty(this, k, (UInt64)sp.index[L]);
            snprintf(k, sizeof(k), "m2-b2-rxset-s%u-pte%u-level",
                     (unsigned)i, (unsigned)L);
            setHexProperty(this, k, (UInt64)sp.level[L]);
            snprintf(k, sizeof(k), "m2-b2-rxset-s%u-pte%u",
                     (unsigned)i, (unsigned)L);
            setHexProperty(this, k, sp.pte[L]);
        }
    }
    setHexProperty(this, "m2-b2-rxset-sample-count",
                   (UInt64)fM22b2Dma.rxsetSampleCount);
}

// Round 15. No caller-supplied addresses reach the driver's posting path.
// Prepare obtains a stable allocation domain while the driver holds every
// object; authorize permits only entries from that immutable domain.
bool org_maz1_AMDMapperProbe::m2b2R15Call(UInt32 op) {
    // A native session has its own ring lifecycle; it never prepares,
    // authorizes or disarms the experimental pool.
    if (fR31Session || !fR15Service) return false;
    fR15Request.version = r15pool::kVersion;
    fR15Request.bytes = sizeof(fR15Request);
    fR15Request.op = op;
    const OSSymbol *sym = OSSymbol::withCString(r15pool::kFunctionName);
    if (!sym) return false;
    IOReturn kr = kIOReturnBusy;
    // Real RX poll/ISR exclusion is acquired by the driver. A work-loop gate
    // by itself cannot exclude pollInputPackets on its separate thread.
    for (UInt32 i = 0; i < 100; ++i) {
        ++fR15PoolRpcCalls;
        setHexProperty(this, "m2-3p-rx-pool-rpcs", fR15PoolRpcCalls);
        kr = fR15Service->callPlatformFunction(sym, false,
                                              &fR15Request, nullptr,
                                              nullptr, nullptr);
        if (kr != kIOReturnBusy) break;
        IOSleep(1);
    }
    sym->release();
    setHexProperty(this, "m2-b2-r15-last-op", op);
    setHexProperty(this, "m2-b2-r15-last-kr", (UInt64)(UInt32)kr);
    return kr == kIOReturnSuccess;
}

bool org_maz1_AMDMapperProbe::m2b2R15PrepareMap(
        volatile UInt64 *pt, UInt64 ptBase,
        UInt32 totalPages, UInt32 basePages) {
    IOService *nic = findNicServiceOnly();
    if (!nic) { setProperty("m2-b2-r15", "FAIL-no-nic"); return false; }
    const char *src = nullptr;
    IOService *obs = m2b2FindObsService(nic, &src); // returns +1, even fallback
    nic->release();
    fR15Service = obs;
    fR15Request.reserved = m2b2ReadDeclaredToken(); // ABI: businessToken
    if (!fR15Request.reserved) {
        setProperty("m2-b2-r15", "FAIL-business-token-absent"); return false;
    }
    if (fR31Session)
        return r34RxPrepareMap(pt, ptBase, totalPages, basePages);
    if (!m2b2R15Call(r15pool::kPrepare)) {
        setProperty("m2-b2-r15", "FAIL-prepare"); return false;
    }
    const r15pool::Snapshot &s = fR15Request.out;
    fR15Request.poolId = s.poolId;
    fR15Request.expectedGeneration = s.generation;
    const char *physicalStats[] = {"allocation-attempts", "allocation-failures",
        "prepare-failures", "attach-failures", "span-failures"};
    UInt32 physicalAttempts = 0;
    for (UInt32 i = 0; i < 5; i++) {
        char driverKey[96], probeKey[96];
        snprintf(driverKey, sizeof(driverKey), "rtl812x-r15-physical-%s", physicalStats[i]);
        snprintf(probeKey, sizeof(probeKey), "m2-b2-r15-physical-%s", physicalStats[i]);
        OSObject *obj = obs->copyProperty(driverKey);
        OSNumber *n = OSDynamicCast(OSNumber, obj);
        if (!n) {
            if (obj) obj->release();
            setProperty("m2-b2-r15", "FAIL-physical-allocation-stats"); return false;
        }
        UInt32 v = n->unsigned32BitValue();
        if (i == 0) physicalAttempts = v;
        setHexProperty(this, probeKey, v);
        obj->release();
    }
    if (physicalAttempts > r15pool::kExtraIOBufferAttempts ||
        s.allocationAttempts < physicalAttempts ||
        s.allocationAttempts - physicalAttempts > r15pool::kMaxAttempts) {
        setProperty("m2-b2-r15", "FAIL-allocation-budget"); return false;
    }
    setProperty("m2-b2-r15-allocation-policy", "bounded-mbuf4k-plus-owned-physical");
    if (s.reserved[0] != fR15Request.reserved ||
        s.version != r15pool::kVersion || s.bytes != sizeof(s) ||
        s.state != r15pool::kPrepared || s.vtdPath != 0 || !s.poolId ||
        !s.epoch || s.entryCount != r15pool::kMaxEntries ||
        s.spareCount != r15pool::kSpareCount || s.flags) {
        setProperty("m2-b2-r15", "FAIL-pool-manifest"); return false;
    }
    OSData *before = OSData::withBytes(&s, sizeof(s));
    if (!before) return false;
    setProperty("m2-b2-r15-pool-before-raw", before);
    before->release();
    char sha[65];
    amdobs::sha256::hashHex((const UInt8 *)&s, sizeof(s), sha);
    setProperty("m2-b2-r15-pool-before-sha256", sha);

    amdsparse::Arena arena = {pt, ptBase, totalPages, basePages,
        fM22b2Use3L ? 3u : 4u, ptBase, 0, 0, nullptr};
    auto read = [&](UInt64 pa, unsigned ix) -> UInt64 {
        volatile amdsparse::u64 *p = amdsparse::table(arena, pa);
        return p ? p[ix] : 0;
    };
    UInt64 maxEnd = 0;
    for (UInt32 i = 0; i < s.entryCount; ++i) {
        const r15pool::Entry &e = s.entries[i];
        if (e.id != i || e.capacity != s.bufferSize || e.capacity != 4096 ||
            (e.reserved != 0 && e.reserved != 2) ||
            (e.reserved == 2 && (!physicalAttempts || i < r15pool::kRingCount)) ||
            e.kind != (i < r15pool::kRingCount ? r15pool::kEntryRing
                                              : r15pool::kEntrySpare) ||
            !amdsparse::mapOwnedRange(arena, e.addr, e.capacity)) {
            setProperty("m2-b2-r15", "FAIL-owned-map");
            setProperty("m2-b2-r15-map-why", arena.why ? arena.why
                                                       : "invalid-entry");
            setHexProperty(this, "m2-b2-r15-map-bad-id", i);
            setHexProperty(this, "m2-b2-r15-map-bad-addr", e.addr);
            setHexProperty(this, "m2-b2-r15-map-bad-capacity", e.capacity);
            return false;
        }
        amdbw::RangeResult r;
        amdbw::walkRange(read, arena.rootLevel, ptBase,
                         e.addr, e.capacity, true, r);
        if (!r.ok) {
            setProperty("m2-b2-r15", "FAIL-owned-walk");
            setProperty("m2-b2-r15-map-why", r.why ? r.why : "walk");
            setHexProperty(this, "m2-b2-r15-map-bad-id", i);
            setHexProperty(this, "m2-b2-r15-map-bad-addr", e.addr);
            return false;
        }
        if (e.addr + e.capacity > maxEnd) maxEnd = e.addr + e.capacity;
    }
    OSSynchronizeIO();
    fR15MapTicks = mach_absolute_time();
    setHexProperty(this, "m2-b2-r15-map-time", m2b2NowNS());
    setHexProperty(this, "m2-b2-r15-map-max-end", maxEnd);
    setHexProperty(this, "m2-b2-r15-map-ranges", s.entryCount);
    setHexProperty(this, "m2-b2-r15-sparse-pages", arena.addedPages);
    setHexProperty(this, "m2-b2-r15-sparse-leaves", arena.addedLeaves);
    setHexProperty(this, "m2-b2-r15-pt-base", ptBase);
    setHexProperty(this, "m2-b2-r15-pt-used-pages", arena.next);
    const UInt32 rawBytes = arena.next * 4096u;
    OSData *raw = OSData::withBytes((const void *)pt, rawBytes);
    if (!raw) { setProperty("m2-b2-r15", "FAIL-table-export"); return false; }
    setProperty("m2-b2-r15-pt-raw", raw);
    amdobs::sha256::hashHex((const UInt8 *)raw->getBytesNoCopy(), rawBytes, sha);
    setProperty("m2-b2-r15-pt-sha256", sha);
    raw->release();
    // Existing window/log fields are mach ticks despite historical NS names.
    // This finite x86 experiment requires and verifies the common 1:1 clock;
    // do not import the userspace-only mach_timebase_info API into a kext.
    UInt64 oneSecondNS = 0;
    absolutetime_to_nanoseconds(1000000000ULL, &oneSecondNS);
    if (oneSecondNS != 1000000000ULL) {
        setProperty("m2-b2-r15", "FAIL-non-unit-timebase"); return false;
    }
    setHexProperty(this, "m2-b2-r15-timebase-numer", 1);
    setHexProperty(this, "m2-b2-r15-timebase-denom", 1);
    setProperty("m2-b2-r15-map-mode", "bootstrap-plus-owned-sparse4k");
    setProperty("m2-b2-r15-obs-scope",
                "declared-business-only; all-rxpost-and-pool-witnesses-retained");
    setProperty("m2-b2-map-limit-kind", "bootstrap-only-not-address-ceiling");
    setProperty("m2-b2-r15", "mapped-before-dte");
    return true;
}

bool org_maz1_AMDMapperProbe::m2b2R15Authorize() {
    if (fR31Session) return r34RxAuthorize();
    if (!fR15Service || !fR15MapTicks || !fR15InvTicks) return false;
    // Zero keeps the current cyclic RX session authorized until Disarm.
    // The finite path retains its 120-second setup/window/drain allowance.
    const UInt64 windowNS = fR31Session ? 0 : 120000000000ULL;
    UInt64 windowTicks = 0;
    nanoseconds_to_absolutetime(windowNS, &windowTicks);
    fR15Request.mapCompletedAt = fR15InvTicks;
    fR15Request.deadline = fR31Session ? 0 : mach_absolute_time() + windowTicks;
    setHexProperty(this, "m2-b2-r15-authorize-window-ns", windowNS);
    setHexProperty(this, "m2-b2-r15-authorize-deadline", fR15Request.deadline);
    fR15Request.replaceLimit = r15pool::kSpareCount;
    setHexProperty(this, "m2-b2-r15-inv-time", fR15InvTicks);
    const bool ok = m2b2R15Call(r15pool::kAuthorize);
    setProperty("m2-b2-r15-authorize", ok ? "done" : "FAIL");
    return ok;
}

void org_maz1_AMDMapperProbe::m2b2R15Finish() {
    if (fR31Session) return; // Native ResumePhysical follows register restore.
    if (!fR15Service || !fR15Request.poolId) return;
    if (!m2b2R15Call(r15pool::kDisarm)) {
        setProperty("m2-b2-r15-disarm", "FAIL"); return;
    }
    setProperty("m2-b2-r15-disarm", "copy-only-until-driver-stop");
    const r15pool::Snapshot &s = fR15Request.out;
    OSData *raw = OSData::withBytes(&s, sizeof(s));
    if (!raw) return;
    setProperty("m2-b2-r15-pool-raw", raw);
    char sha[65];
    amdobs::sha256::hashHex((const UInt8 *)&s, sizeof(s), sha);
    setProperty("m2-b2-r15-pool-sha256", sha);
    raw->release();
    setHexProperty(this, "m2-b2-r15-replacements", s.replacements);
    setHexProperty(this, "m2-b2-r15-completions", s.completions);
    setHexProperty(this, "m2-b2-r15-high-spares", s.highSpareCount);
    setHexProperty(this, "m2-b2-r15-allocation-attempts", s.allocationAttempts);
    setHexProperty(this, "m2-b2-r15-flags", s.flags);
    setProperty("m2-b2-r15", s.completions ? "replacement-used" : "no-new-buffer-completion");
}

void org_maz1_AMDMapperProbe::m2b2R15Release() {
    if (!fR15Service) return;
    if (fR31Session) {
        // Also unfreeze a Prepare-only ring when setup exits before install.
        // Installed mappings must have completed the ordinary drain first.
        if (!r34RxResumePhysical()) return;
        r34RxRelease();
        if (fR34Rx) return;
        fR15Service->release();
        fR15Service = nullptr;
        return;
    }
    // Also covers every early return before hardware is enabled. Revocation
    // never frees objects that can still be installed in RX descriptors.
    if (fR15Request.poolId &&
        fR15Request.out.state != r15pool::kDisarmed) m2b2R15Finish();
    fR15Service->release();
    fR15Service = nullptr;
}
