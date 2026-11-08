// AMDMapperProbeDmaContractDebug.cpp -- M1 B2: a real IODMACommand flow
// (withSpecification -> setMemoryDescriptor -> gen64IOVMSegments) through our mapper.
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

// ===== split from AMDMapperProbe.cpp: original lines 308..392 =====
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

