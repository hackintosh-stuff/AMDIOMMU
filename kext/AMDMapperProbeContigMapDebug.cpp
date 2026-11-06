// AMDMapperProbeContigMapDebug.cpp -- M1 B2-a: a physically contiguous buffer must
// map, a fragmented one must be rejected, and both verdicts come from count deltas.
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

// ===== split from AMDMapperProbe.cpp: original lines 394..487 =====
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

// ===== split from AMDMapperProbe.cpp: original lines 489..521 =====
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

