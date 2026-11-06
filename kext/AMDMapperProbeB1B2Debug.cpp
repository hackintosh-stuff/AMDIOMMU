// AMDMapperProbeB1B2.cpp -- M1 mapper self-tests (B1, B2, B2a, B2b)
//
// Part of the AMDMapperProbe kext. Split out of the original
// single-file AMDMapperProbe.cpp by tools/dev/split-probe.py; the
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

// ===== AMDMapperProbeB1B2.cpp (original lines 217..242) =====
// ------------------------------------------------------------------ B1 self-test

void org_maz1_AMDMapperProbe::runB1SelfTest() {
    if (!fTarget) {
        setProperty("m1b-selftest", "SKIP-no-target");
        return;
    }

    IOMapper *before = probeRawMapper(fTarget);
    if (before) {
        setProperty("m1b-selftest", "ABORT-pre-existing-mapper");
        return;
    }
    setProperty("m1b-before", "NULL-as-expected");

    fTarget->setProperty("iommu-parent", this);

    IOMapper *after = probeRawMapper(fTarget);
    if (after == this) {
        setProperty("m1b-selftest", "PASS-real-device-found-our-mapper");
    } else if (after) {
        setProperty("m1b-selftest", "FAIL-wrong-mapper");
    } else {
        setProperty("m1b-selftest", "FAIL-still-NULL");
    }
}

// ===== AMDMapperProbeB1B2.cpp (original lines 308..392) =====
// ---------------------------------------------------------------- B2-0 self-test

// Run a real IODMACommand flow using our own buffer and mapper.
//
// This reproduces exactly what RTL812xLucy does to its descriptor ring:
//     IODMACommand::withSpecification(..., mapper, NULL)
//     setMemoryDescriptor(md)   <- internally calls our iovmMapMemory
//
// No hardware is involved at any point: the buffer is ours, and the IOVA is
// never used by any device.
void org_maz1_AMDMapperProbe::runB2SelfTest() {
    const IOByteCount kBufSize = 16 * 4096;

    IOBufferMemoryDescriptor *bmd = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
        kernel_task,
        kIODirectionInOut | kIOMemoryPhysicallyContiguous,
        kBufSize,
        0xFFFFFFFFFFFFFF00ULL);
    if (!bmd) {
        setProperty("m1b2-alloc", "FAIL-buffer");
        return;
    }
    setProperty("m1b2-alloc", "OK");
    setHexProperty(this, "m1b2-bufsize", kBufSize);

    if (bmd->prepare() != kIOReturnSuccess) {
        setProperty("m1b2-prepare", "FAIL");
        bmd->release();
        return;
    }
    setProperty("m1b2-prepare", "OK");

    // Pass our mapper explicitly -- identical to how the Lucy driver uses it.
    IODMACommand *cmd = IODMACommand::withSpecification(
        kIODMACommandOutputHost64,
        64,             // numAddressBits
        0,              // maxSegmentSize
        IODMACommand::kMapped,
        0,              // maxTransferSize
        1,              // alignment
        this,           // mapper <- the key point: OUR mapper
        NULL);
    if (!cmd) {
        setProperty("m1b2-cmd", "FAIL-withSpecification");
        bmd->complete();
        bmd->release();
        return;
    }
    setProperty("m1b2-cmd", "OK");

    // This line triggers iovmMapMemory (via the multi-segment path inside
    // prepare). Note: B2-0 deliberately keeps the window **closed**, behaving
    // exactly like 0.4.0, so results from two deployments are directly
    // comparable and do not lose the baseline because the implementation
    // changed. The success path is observed by B2-a, which follows.
    // fProbeCallActive tells iovmMapMemory that the probe itself initiated
    // this call, so this (doomed-to-fail) call is not miscounted as a real
    // device call.
    fProbeCallActive = true;
    IOReturn ret = cmd->setMemoryDescriptor(bmd);
    fProbeCallActive = false;

    setHexProperty(this, "m1b2-setmd-ret", (uint64_t)(uint32_t)ret);
    setProperty("m1b2-setmd",
        (ret == kIOReturnSuccess) ? "SUCCESS" : "FAILED-as-expected");
    setHexProperty(this, "m1b2-mapcalls", fMapCalls);

    if (ret == kIOReturnSuccess) {
        IODMACommand::Segment64 seg;
        UInt64 offset = 0;
        UInt32 numSegs = 1;

        if (cmd->gen64IOVMSegments(&offset, &seg, &numSegs) == kIOReturnSuccess) {
            setProperty("m1b2-gen64", "OK");
            setHexProperty(this, "m1b2-seg0-iova", seg.fIOVMAddr);
            setHexProperty(this, "m1b2-seg0-len", seg.fLength);
        } else {
            setProperty("m1b2-gen64", "FAILED");
        }
        cmd->clearMemoryDescriptor();
    }

    cmd->release();
    bmd->complete();
    bmd->release();

    setProperty("m1b2-done", "yes");
}

// ===== AMDMapperProbeB1B2.cpp (original lines 394..487) =====
// ---------------------------------------------------------------- B2-a self-test
//
// Two comparison cases:
//   ok   -- physically contiguous 64 KiB; iovmMapMemory should return success
//           + identity mapping
//   frag -- fragmented 8 MiB; should return kIOReturnUnsupported and be counted
//
// Pass/fail is not judged via IOLog (which scrolls out of msgbuf); everything
// lands in IORegistry properties.

void org_maz1_AMDMapperProbe::runB2OneTest(
    const char *tag, bool wantContiguous, IOByteCount size) {

    IOOptionBits opts = kIODirectionInOut;
    if (wantContiguous) opts |= kIOMemoryPhysicallyContiguous;

    IOBufferMemoryDescriptor *bmd = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
        kernel_task, opts, size, 0xFFFFFFFFFFFFFF00ULL);
    if (!bmd) {
        setStrTagged(this, tag, "alloc", "FAIL");
        return;
    }
    setStrTagged(this, tag, "alloc", "OK");
    setHexTagged(this, tag, "size", size);

    if (bmd->prepare() != kIOReturnSuccess) {
        setStrTagged(this, tag, "prepare", "FAIL");
        bmd->release();
        return;
    }

    // First probe the buffer's actual physical layout independently, as the
    // comparison baseline.
    ProbeRun run = probeSegmentRun(bmd, 0, size);
    setHexTagged(this, tag, "segs", run.segCount);
    setHexTagged(this, tag, "firstpa", run.firstPA);
    setStrTagged(this, tag, "contig",
        run.error ? "ERROR" : (run.contiguous ? "yes" : "no"));

    IODMACommand *cmd = IODMACommand::withSpecification(
        kIODMACommandOutputHost64, 64, 0, IODMACommand::kMapped,
        0, 1, this, NULL);
    if (!cmd) {
        setStrTagged(this, tag, "cmd", "FAIL");
        bmd->complete();
        bmd->release();
        return;
    }

    uint32_t beforeOk     = fMapOkCalls;
    uint32_t beforeFrag   = fMapRejectFragCalls;
    uint32_t beforeOther  = fMapRejectOtherCalls;

    // Open the window, valid only for this cmd (double gate).
    fExpectedCmd = cmd;
    fMapWindowOpen = true;
    fProbeCallActive = true;
    IOReturn ret = cmd->setMemoryDescriptor(bmd);
    fProbeCallActive = false;
    fMapWindowOpen = false;
    fExpectedCmd = nullptr;

    setHexTagged(this, tag, "ret", (uint64_t)(uint32_t)ret);
    setHexTagged(this, tag, "okdelta",     fMapOkCalls         - beforeOk);
    setHexTagged(this, tag, "fragdelta",   fMapRejectFragCalls - beforeFrag);
    setHexTagged(this, tag, "otherdelta",  fMapRejectOtherCalls - beforeOther);

    if (ret == kIOReturnSuccess) {
        setStrTagged(this, tag, "result", "MAPPED");

        IODMACommand::Segment64 seg;
        UInt64 offset = 0;
        UInt32 numSegs = 1;
        if (cmd->gen64IOVMSegments(&offset, &seg, &numSegs) == kIOReturnSuccess) {
            setHexTagged(this, tag, "iova", seg.fIOVMAddr);
            setHexTagged(this, tag, "seg0len", seg.fLength);
            setHexTagged(this, tag, "nsegs", numSegs);
            // Identity-mapping verdict: the IOVA must equal the buffer's
            // physical start.
            setStrTagged(this, tag, "identity",
                (seg.fIOVMAddr == run.firstPA && seg.fLength == size)
                    ? "yes" : "NO");
        } else {
            setStrTagged(this, tag, "gen64", "FAILED");
        }

        cmd->clearMemoryDescriptor();   // → iovmUnmapMemory
        setHexTagged(this, tag, "unmapcalls", fUnmapCalls);
    } else if (ret == kIOReturnUnsupported) {
        setStrTagged(this, tag, "result", "REJECTED-unsupported");
    } else {
        setStrTagged(this, tag, "result", "FAILED-other");
    }

    cmd->release();
    bmd->complete();
    bmd->release();
}

// ===== AMDMapperProbeB1B2.cpp (original lines 489..521) =====
void org_maz1_AMDMapperProbe::runB2aSelfTest() {
    // B2-0 just ran once (window closed -> counted in rejectOther). Zero
    // B2-a's own counters first so the numbers reported below reflect only
    // B2-a's two comparison cases, not mixed with B2-0's observation calls.
    fMapOkCalls = fMapRejectFragCalls = fMapRejectOtherCalls = 0;
    fUnmapOkCalls = 0;

    // Comparison 1: physically contiguous, expected to succeed.
    runB2OneTest("m1b2a-ok", true, 16 * 4096);

    // Comparison 2: fragmented, expected to be rejected. An 8 MiB general
    // buffer is almost never physically contiguous.
    runB2OneTest("m1b2a-frag", false, 8 * 1024 * 1024);

    setHexProperty(this, "m1b2a-okcalls", fMapOkCalls);
    setHexProperty(this, "m1b2a-fragcalls", fMapRejectFragCalls);
    setHexProperty(this, "m1b2a-othercalls", fMapRejectOtherCalls);
    setHexProperty(this, "m1b2a-unmapok", fUnmapOkCalls);

    // Summary of the last successful mapping (also makes the fLast* four
    // members actually read)
    setHexProperty(this, "m1b2a-last-segs", fLastSegCount);
    setHexProperty(this, "m1b2a-last-pa", fLastFirstPA);
    setHexProperty(this, "m1b2a-last-len", fLastLength);
    setHexProperty(this, "m1b2a-last-off", fLastOffset);

    // Overall verdict: contiguous success + fragmented rejection -- PASS only
    // if both hold.
    if (fMapOkCalls > 0 && fMapRejectFragCalls > 0) {
        setProperty("m1b2a-selftest", "PASS-contig-mapped-frag-rejected");
    } else if (fMapOkCalls > 0) {
        setProperty("m1b2a-selftest", "PARTIAL-contig-mapped-frag-untested");
    } else {
        setProperty("m1b2a-selftest", "FAIL-no-successful-map");
    }
}

// ===== AMDMapperProbeB1B2.cpp (original lines 523..540) =====
// ------------------------------------------------------ B2-b mapping table operations
//
// Identity mappings need no page table, but we must **remember which ranges
// were mapped**, otherwise mapToPhysicalAddress cannot distinguish "what we
// mapped" from "what someone asked about", and unmap cannot validate its
// arguments.

org_maz1_AMDMapperProbe::MapEntry *
org_maz1_AMDMapperProbe::allocMapEntry() {
    for (int i = 0; i < kMaxActiveMaps; i++) {
        if (!fMaps[i].used) {
            fMaps[i].used = true;
            uint32_t n = usedMapEntries();
            if (n > fTablePeak) fTablePeak = n;
            return &fMaps[i];
        }
    }
    return nullptr;     // table full
}

// ===== AMDMapperProbeB1B2.cpp (original lines 542..554) =====
// Release by exact (pa,len) match. Under identity mapping pa is the IOVA, and
// on unmap the kernel passes back exactly the value we originally returned
// (IOMemoryDescriptor::dmaUnmap -> iovmUnmapMemory).
bool org_maz1_AMDMapperProbe::freeMapEntry(uint64_t pa, uint64_t len) {
    for (int i = 0; i < kMaxActiveMaps; i++) {
        if (fMaps[i].used && fMaps[i].pa == pa && fMaps[i].len == len) {
            fMaps[i].used = false;
            fMaps[i].pa = 0;
            fMaps[i].len = 0;
            return true;
        }
    }
    return false;
}

// ===== AMDMapperProbeB1B2.cpp (original lines 556..562) =====
uint32_t org_maz1_AMDMapperProbe::usedMapEntries() {
    uint32_t n = 0;
    for (int i = 0; i < kMaxActiveMaps; i++) {
        if (fMaps[i].used) n++;
    }
    return n;
}

// ===== AMDMapperProbeB1B2.cpp (original lines 564..573) =====
void org_maz1_AMDMapperProbe::publishB2bStats() {
    setHexProperty(this, "m1bb-realmapcalls", fRealMapCalls);
    setHexProperty(this, "m1bb-realmapok", fRealMapOk);
    setHexProperty(this, "m1bb-realfrag", fRealMapRejectFrag);
    setHexProperty(this, "m1bb-realnoslot", fRealMapRejectNoSlot);
    setHexProperty(this, "m1bb-realunmap", fRealUnmapCalls);
    setHexProperty(this, "m1bb-tablepeak", fTablePeak);
    setHexProperty(this, "m1bb-tableused", usedMapEntries());
    setHexProperty(this, "m1bb-publishhits", fPublishHits);
}

// ===== AMDMapperProbeB1B2.cpp (original lines 7407..7417) =====
// ------------------------------------------------------------- statistics property refresh

// Refresh only when the call count changes, avoiding a setProperty (which
// keeps allocating memory) on every mapping.
void org_maz1_AMDMapperProbe::publishMapStats(bool force) {
    if (!force && fMapCalls == fPublishedMapCalls) return;
    fPublishedMapCalls = fMapCalls;
    setHexProperty(this, "m1b2-mapcalls", fMapCalls);
    setHexProperty(this, "m1b2-unmapcalls", fUnmapCalls);
    setHexProperty(this, "m1b2-insertcalls", fInsertCalls);
    setHexProperty(this, "m1b2-physaddrcalls", fPhysAddrCalls);
}
