// AMDMapperProbeMapTableDebug.cpp -- M1 B2-b: the active mapping table
// (alloc/free/lookup by exact pa,len) and the statistics published from it.
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

// ===== split from AMDMapperProbe.cpp: original lines 523..540 =====
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

// ===== split from AMDMapperProbe.cpp: original lines 542..554 =====
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

// ===== split from AMDMapperProbe.cpp: original lines 556..562 =====
uint32_t org_maz1_AMDMapperProbe::usedMapEntries() {
    uint32_t n = 0;
    for (int i = 0; i < kMaxActiveMaps; i++) {
        if (fMaps[i].used) n++;
    }
    return n;
}

// ===== split from AMDMapperProbe.cpp: original lines 564..573 =====
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

// ===== split from AMDMapperProbe.cpp: original lines 7407..7417 =====
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
