// AMDMapperProbeMapperBindingDebug.cpp -- M1 B1: the target NIC must report
// our mapper as its iommu-parent, and a pre-existing mapper must abort the run.
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

// ===== split from AMDMapperProbe.cpp: original lines 217..242 =====
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

