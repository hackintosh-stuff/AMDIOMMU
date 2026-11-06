// AMDMapperProbeMmio.cpp -- M2-0/1/2a-1 MMIO read and write probes
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

// ===== AMDMapperProbeMmio.cpp (original lines 807..991) =====
// ------------------------------------------------- M2-0b: PCI config space read-only probe

// Why this step exists (after M2-0):
//
//   M2-0's conclusion was "IVRS's 0xFD380000 is correct; DSDT's _CRS
//   0xFEB80000 is a stale declaration". But all the evidence for that
//   conclusion lives on the Linux side:
//     - Linux source uses h->mmio_phys (init.c:1755), not _CRS
//     - Linux dmesg's `Using global IVHD EFR:0x0` corroborates that EFR comes
//       from an MMIO read
//   These prove 0xFD380000 is readable **under Linux**; they say nothing about
//   macOS.
//
//   The IOMMU's capability block carries its own BAR -- the hardware's current
//   authoritative value. Comparing it with IVRS's base allows an independent
//   verdict on the macOS side:
//     - BAR == 0xFD380000 -> agrees with IVRS; _CRS is indeed stale, and M2-1
//       may use that address
//     - BAR == 0xFEB80000 -> the reverse; _CRS is right and M2-0's conclusion
//       must be overturned
//     - BAR is a third value -> neither source is trustworthy, and M2-1 must
//       switch to the BAR
//
// Everything here is read-only. configRead8/16/32 only read PCI config space:
// no MMIO is touched, no register written, no device state changed.
//
// Known limitations:
//   configAccess() requires !isInactive() && reserved && parent, and is
//   rejected (returns 0xFFFFFFFF) if configProt forbids reads.
//   So this function must distinguish "read all ones" from "read rejected" --
//   both return 0xFFFFFFFF; whether the channel works is judged by whether
//   device-id / vendor-id can be read normally.
//
// On IOPCIDevice's deprecation warning:
//   The SDK marks IOPCIDevice __kpi_deprecated("Use PCIDriverKit"). That advice
//   does not apply to this project -- PCIDriverKit is a userspace DriverKit
//   framework and cannot implement an IOMapper subclass; this project must be
//   an in-kernel kext. We only use the **read-only** configRead8/16/32, whose
//   symbols are confirmed present in the running kernel's IOPCIFamily export
//   table. Therefore the warning is disabled only **inside this function**,
//   not globally.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
void org_maz1_AMDMapperProbe::runM20ConfigProbe() {
    setProperty("m2-stage", "0-config-probe-start");

    if (!fTarget) {
        setProperty("m2-config", "SKIP-no-target");
        return;
    }

    IOPCIDevice *pci = OSDynamicCast(IOPCIDevice, fTarget);
    if (!pci) {
        setProperty("m2-config", "FAIL-target-not-IOPCIDevice");
        return;
    }

    // ---- Step 1: verify the config space channel itself works ----
    //
    // vendor-id is at 0x00, device-id at 0x02. We already know both values
    // from IORegistry properties (0x1022 / 0x1481), so they serve as a
    // "channel self-check": if they do not read back, configRead was rejected
    // or returned garbage, and every subsequent BAR read is untrustworthy.
    UInt16 vid = pci->configRead16(0x00);
    UInt16 did = pci->configRead16(0x02);

    setHexProperty(this, "m2-cfg-vid", vid);
    setHexProperty(this, "m2-cfg-did", did);

    if (vid != 0x1022 || did != 0x1481) {
        // Channel is dead. Do not continue -- BAR reads would be garbage.
        setProperty("m2-config", "FAIL-channel-not-usable");
        setProperty("m2-config-note",
                    "vid/did mismatch => configRead blocked or inactive");
        return;
    }
    setProperty("m2-config", "channel-ok");

    // ---- Step 2: walk the capability list to find the AMD IOMMU capability ----
    //
    // CapID 0x0F = Secure Device (the ID the AMD IOMMU capability uses).
    // On the real machine, macOS's "Capability Offsets" lists
    // SecureCapability = 64 (0x40).
    //
    // We do not blindly trust that property; we walk the list ourselves -- so
    // this works even if the property is missing, and it verifies the
    // property's value against the list along the way.
    UInt16 status = pci->configRead16(0x06);
    bool capListSupported = (status & 0x0010) != 0;   // Status[4] = Capabilities List
    setProperty("m2-cfg-caplist", capListSupported ? "yes" : "no");

    if (!capListSupported) {
        setProperty("m2-config", "FAIL-no-capability-list");
        return;
    }

    UInt8 capPtr = (UInt8)(pci->configRead8(0x34) & 0xFC);  // low 2 bits reserved
    setHexProperty(this, "m2-cfg-cap0", capPtr);

    UInt8 iommuCap = 0;
    UInt8 walk = capPtr;
    // Walk at most 48 steps (PCI spec caps at 48 capabilities) and detect loops.
    for (int i = 0; i < 48 && walk >= 0x40; i++) {
        UInt16 hdr = pci->configRead16(walk);
        UInt8 capId = (UInt8)(hdr & 0xFF);
        UInt8 next  = (UInt8)((hdr >> 8) & 0xFC);

        if (capId == 0x0F) {        // Secure Device / AMD IOMMU
            iommuCap = walk;
            break;
        }
        if (next == 0 || next == walk) break;   // list end or self-loop
        walk = next;
    }

    if (!iommuCap) {
        setProperty("m2-config", "FAIL-no-iommu-capability");
        return;
    }

    setHexProperty(this, "m2-cfg-iommu-cap", iommuCap);
    setProperty("m2-config", "capability-found");

    // ---- Step 3: read the capability header and BAR ----
    //
    // AMD IOMMU capability structure (relative to the capability start):
    //   +0x00 u32 : CapID(8) | CapPtr(8) | CapHdr(16)
    //   +0x04 u64 : Base Address (bit0 = lock, must be masked)
    //   +0x0C u16 : PCI Segment Group
    //   +0x0E u16 : IOMMU Info
    //   +0x10 u32 : IOMMU Feature Reporting
    //   +0x14 u32 : IOMMU Attributes
    //   +0x18 u64 : EFR Image
    //   +0x20 u64 : EFR Image 2
    UInt32 capHdr = pci->configRead32(iommuCap);
    setHexProperty(this, "m2-cfg-caphdr", capHdr);

    UInt32 barLo = pci->configRead32((UInt8)(iommuCap + 0x04));
    UInt32 barHi = pci->configRead32((UInt8)(iommuCap + 0x08));

    setHexProperty(this, "m2-cfg-barlo-raw", barLo);
    setHexProperty(this, "m2-cfg-barhi-raw", barHi);

    // bit0 is the lock bit, not an address bit.
    UInt64 bar = ((UInt64)barHi << 32) | (UInt64)(barLo & ~1u);
    setHexProperty(this, "m2-cfg-bar", bar);

    UInt16 segGroup = pci->configRead16((UInt8)(iommuCap + 0x0C));
    UInt16 iommuInfo = pci->configRead16((UInt8)(iommuCap + 0x0E));
    setHexProperty(this, "m2-cfg-seggroup", segGroup);
    setHexProperty(this, "m2-cfg-iommuinfo", iommuInfo);

    UInt32 featRep = pci->configRead32((UInt8)(iommuCap + 0x10));
    setHexProperty(this, "m2-cfg-featrep", featRep);

    UInt32 attrs = pci->configRead32((UInt8)(iommuCap + 0x14));
    setHexProperty(this, "m2-cfg-attrs", attrs);

    // EFR Image: the hardware-side copy of the field in IVRS's 0x11 block.
    // If it equals IVRS's 0x058F77EF22294A5A, both derive from the same data.
    UInt32 efrLo = pci->configRead32((UInt8)(iommuCap + 0x18));
    UInt32 efrHi = pci->configRead32((UInt8)(iommuCap + 0x1C));
    UInt64 efr = ((UInt64)efrHi << 32) | (UInt64)efrLo;
    setHexProperty(this, "m2-cfg-efr", efr);

    // ---- Step 4: render the verdict ----
    //
    // The criterion is the BAR compared against the two candidate addresses.
    // That is this function's sole purpose.
    const UInt64 kIvrsBase = 0xFD380000ULL;   // written in both IVRS 0x10 and 0x11 blocks
    const UInt64 kCrsBase  = 0xFEB80000ULL;   // DSDT _CRS Memory32Fixed
    const UInt64 kEfrKnown = 0x058F77EF22294A5AULL;  // IVRS EFR field, measured value

    if (bar == kIvrsBase) {
        setProperty("m2-config-verdict", "BAR==IVRS(0xFD380000)");
        setProperty("m2-config-meaning", "IVRS correct, _CRS stale");
    } else if (bar == kCrsBase) {
        setProperty("m2-config-verdict", "BAR==_CRS(0xFEB80000)");
        setProperty("m2-config-meaning", "_CRS correct, IVRS stale!");
    } else if (bar == 0) {
        setProperty("m2-config-verdict", "BAR==0");
        setProperty("m2-config-meaning", "BAR not programmed / unreadable");
    } else {
        setProperty("m2-config-verdict", "BAR==third-value");
        setProperty("m2-config-meaning", "neither IVRS nor _CRS; trust BAR");
    }

    // EFR comparison: an independent second criterion.
    // If EFR matches IVRS, we read the capability structure at the right
    // place, and the BAR reading is trustworthy too. If not, the BAR reading
    // is in doubt.
    if (efr == kEfrKnown) {
        setProperty("m2-cfg-efr-match", "yes");
    } else {
        setProperty("m2-cfg-efr-match", "no");
    }

    setProperty("m2-stage", "1-config-probe-done");
}

// ===== AMDMapperProbeMmio.cpp (original lines 1022..1022) =====


// ===== AMDMapperProbeMmio.cpp (original lines 1116..1226) =====
void org_maz1_AMDMapperProbe::runM21MmioProbe() {
    setProperty("m2-m1-stage", "0-start");

    // ---- Gated: not executed by default ----
    if (!parseMmioBootArg()) {
        setProperty("m2-m1-gate", "closed");
        setProperty("m2-m1-stage", "1-skipped-no-bootarg");
        return;
    }
    setProperty("m2-m1-gate", "open");

    // ---- Build the physical address descriptor ----
    //
    // withPhysicalAddress describes a range of physical addresses. Here it
    // describes the IOMMU's MMIO window. It returns OSPtr, which under the SDK
    // default (IOKIT_ENABLE_SHARED_PTR undefined) is a bare pointer.
    IOMemoryDescriptor *md =
        IOMemoryDescriptor::withPhysicalAddress(
            (IOPhysicalAddress)M21_MMIO_BASE,
            (IOByteCount)M21_MMIO_LEN,
            kIODirectionNone);
    if (!md) {
        setProperty("m2-m1-stage", "2-FAIL-withPhysicalAddress-null");
        return;
    }
    setProperty("m2-m1-md", "created");

    // ---- Map into kernel space ----
    //
    // kIOMapInhibitCache is mandatory: MMIO registers must not be cached by
    // the CPU, otherwise reads return stale values and writes never land. This
    // is a correctness requirement, not an optimization. kIOMapReadOnly adds
    // another safety net: even a code bug cannot write through it.
    IOMemoryMap *map = md->map(kIOMapInhibitCache | kIOMapReadOnly | kIOMapAnywhere);
    if (!map) {
        setProperty("m2-m1-stage", "3-FAIL-map-null");
        md->release();
        return;
    }
    setProperty("m2-m1-map", "ok");

    IOVirtualAddress va = map->getVirtualAddress();
    if (!va) {
        setProperty("m2-m1-stage", "4-FAIL-no-virtual-address");
        map->release();
        md->release();
        return;
    }
    setHexProperty(this, "m2-m1-va", (UInt64)va);
    setHexProperty(this, "m2-m1-maplen", (UInt64)map->getLength());
    setProperty("m2-m1-stage", "5-mapped");

    volatile UInt8 *base = (volatile UInt8 *)va;

    // ---- Phase A: read EFR only -- the single criterion ----
    //
    // Only this one register is read. If the address is wrong, the worst
    // outcome is an unrelated 64-bit value; we stop immediately and do not
    // touch other offsets.
    UInt64 efr = mmioRead64(base, M21_OFF_EXT_FEAT);
    setHexProperty(this, "m2-m1-efr", efr);
    setHexProperty(this, "m2-m1-efr-expected", M21_EFR_EXPECTED);

    if (efr != M21_EFR_EXPECTED) {
        setProperty("m2-m1-verdict", "FAIL-efr-mismatch");
        setProperty("m2-m1-stage", "6-stopped-efr-mismatch");
        // Do not read other registers -- the address may be wrong; reading
        // more only adds risk.
        map->release();
        md->release();
        return;
    }

    // EFR matched -> address right, mapping right, MMIO readable.
    setProperty("m2-m1-verdict", "PASS-efr-match");
    setProperty("m2-m1-stage", "7-efr-verified");

    // ---- Phase B: EFR verified; read other read-only registers as extra
    //      intelligence ----
    //
    // These readings do not affect the criterion; they only provide a baseline
    // for M2-2:
    //   - DEV_TABLE non-zero means someone already configured a device table
    //     (should not happen)
    //   - CONTROL's IOMMU_EN bit set means the IOMMU is already running
    //     (danger signal)
    //   - STATUS's EVT_RUN and similar bits reflect whether the log is running
    UInt64 devTable = mmioRead64(base, M21_OFF_DEV_TABLE);
    UInt64 control  = mmioRead64(base, M21_OFF_CONTROL);
    UInt32 status   = mmioRead32(base, M21_OFF_STATUS);

    setHexProperty(this, "m2-m1-devicetable", devTable);
    setHexProperty(this, "m2-m1-control", control);
    setHexProperty(this, "m2-m1-status", (UInt64)status);

    // Critical safety check: the IOMMU must be off.
    // If CONTROL's bit0 (IOMMU_EN) is 1, someone else is using it, and M2-2
    // must never rashly take over.
    if (control & 0x1ULL) {
        setProperty("m2-m1-iommu-enabled", "YES-unexpected");
    } else {
        setProperty("m2-m1-iommu-enabled", "no-as-expected");
    }

    // DEV_TABLE == 0 means it was never programmed -- exactly the clean state
    // we expect.
    if (devTable == 0) {
        setProperty("m2-m1-devicetable-clean", "yes");
    } else {
        setProperty("m2-m1-devicetable-clean", "no");
    }

    setProperty("m2-m1-stage", "8-complete");

    // ---- Cleanup ----
    // Must unmap and release. Leaving the mapping mapped keeps this MMIO range
    // pinned in kernel virtual address space.
    map->release();
    md->release();
    setProperty("m2-m1-cleanup", "done");
}

// ===== AMDMapperProbeMmio.cpp (original lines 1228..1267) =====
// ------------------------------------------------- M2-2a-1: minimal MMIO write test

// Purpose: answer exactly one question -- **can this MMIO window be written?**
//
// No IOMMU enable, no device table allocation, no commands issued. Just one
// "write a value, read it back, restore the original".
//
// Why MMIO_DEV_TABLE_OFFSET (0x0000) is the target:
//   - It is the IOMMU's only register whose write has no immediate side
//     effect: the hardware only actually uses it once CONTROL_IOMMU_EN is set.
//   - The IOMMU is currently completely off (M2-1 measured every CONTROL
//     enable bit as 0), so writing it is pure storage, consumed by no hardware
//     logic.
//   - Its current value is 0x0 (measured in M2-1), so "restore the original"
//     means writing back 0; even a failed restore leaves an "unprogrammed"
//     clean state.
//
// Why not use the CONTROL register for the write test:
//   Writing CONTROL carries real risk -- any wrong bit could enable the IOMMU
//   or clear firmware presets. DEV_TABLE has no such risk.
//
// Choice of the test value (corrected after the first 0.10.0 measurement):
//   The first version wrote 0xDEADBEEF00000000 and compared the read-back
//   directly, yielding "FAIL-write-did-not-stick". The measurement read back
//   0x000DBEEF00000000 -- **only bits 63:52 were lost**, bits 51:0 fully
//   preserved.
//
//   That was not a failed write but the hardware masking reserved bits per
//   spec:
//     The AMD IOMMU's DEV_TABLE base register implements only bits 51:0
//     (Linux: `#define PM_ADDR_MASK 0x000ffffffffff000ULL`, and the entry
//     iommu_set_device_table() writes encodes only base + size).
//     Bits 63:52 are reserved read-as-zero; anything written there reads back 0.
//
//   So the criterion must be "read-back == written & implementation mask"; a
//   direct comparison is wrong. That was my error in designing the criterion,
//   not a hardware problem.
//
// Why that marker value is still used:
//   0xDEADBEEF00000000 sits in bits 63:32; bits 51:32 of it are reserved, but
//   bits 51:12 are real address bits and bits 11:0 are size-encoding bits --
//   enough to prove the write landed. A pattern occupying only bits 51:12
//   would be cleaner.
#define M22_OFF_DEV_TABLE   0x0000
// Use only bits 51:12 (address bits), avoiding the reserved and size-encoding
// bits.
#define M22_WRITE_PATTERN   0x000ABCDEF0000000ULL
// The hardware's implemented bit mask: the DEV_TABLE base register has only
// bits 51:0.
#define M22_IMPL_MASK       0x000FFFFFFFFFFFFFULL

// ===== AMDMapperProbeMmio.cpp (original lines 1269..1391) =====
void org_maz1_AMDMapperProbe::runM22aWriteProbe() {
    setProperty("m2-2a-stage", "0-start");

    // Gated: runs only for amdiommu=write.
    // Kept separate from mmio (read-only) because this is the first hardware
    // write -- a different risk level.
    if (!parseWriteBootArg()) {
        setProperty("m2-2a-gate", "closed");
        setProperty("m2-2a-stage", "1-skipped-no-bootarg");
        return;
    }
    setProperty("m2-2a-gate", "open");

    // ---- Map, writable this time ----
    //
    // Difference from M2-1: kIOMapReadOnly is dropped.
    // kIOMapInhibitCache is kept -- MMIO being non-cacheable is a correctness
    // requirement.
    IOMemoryDescriptor *md =
        IOMemoryDescriptor::withPhysicalAddress(
            (IOPhysicalAddress)M21_MMIO_BASE,
            (IOByteCount)M21_MMIO_LEN,
            kIODirectionNone);
    if (!md) {
        setProperty("m2-2a-stage", "2-FAIL-md-null");
        return;
    }

    IOMemoryMap *map = md->map(kIOMapInhibitCache | kIOMapAnywhere);
    if (!map) {
        setProperty("m2-2a-stage", "3-FAIL-map-null");
        md->release();
        return;
    }

    IOVirtualAddress va = map->getVirtualAddress();
    if (!va) {
        setProperty("m2-2a-stage", "4-FAIL-no-va");
        map->release();
        md->release();
        return;
    }
    setProperty("m2-2a-map", "ok-rw");

    volatile UInt8 *base = (volatile UInt8 *)va;

    // ---- Step 1: first confirm EFR still matches ----
    //
    // This is the "we mapped the right thing" self-check. M2-1 verified it
    // once; verify again here: if this mapping landed elsewhere, the writes
    // below would hit a wrong address. So identity must be reconfirmed before
    // writing.
    UInt64 efr = mmioRead64(base, M21_OFF_EXT_FEAT);
    setHexProperty(this, "m2-2a-efr", efr);
    if (efr != M21_EFR_EXPECTED) {
        setProperty("m2-2a-verdict", "FAIL-efr-mismatch-before-write");
        setProperty("m2-2a-stage", "5-aborted-identity-check");
        map->release();
        md->release();
        return;
    }
    setProperty("m2-2a-identity", "confirmed");

    // ---- Step 2: record the original value ----
    UInt64 orig = mmioRead64(base, M22_OFF_DEV_TABLE);
    setHexProperty(this, "m2-2a-devicetable-orig", orig);

    // ---- Step 3: write the marker value, read it back ----
    //
    // This is the project's **first hardware write**.
    mmioWrite64(base, M22_OFF_DEV_TABLE, M22_WRITE_PATTERN);
    UInt64 readback = mmioRead64(base, M22_OFF_DEV_TABLE);

    setHexProperty(this, "m2-2a-wrote", M22_WRITE_PATTERN);
    setHexProperty(this, "m2-2a-readback", readback);
    setHexProperty(this, "m2-2a-impl-mask", M22_IMPL_MASK);

    // Criterion: compare only the bits the hardware actually implements
    // (bits 51:0). The high bits are reserved read-as-zero -- written ones
    // necessarily read back 0. That is not a failure.
    UInt64 expected = M22_WRITE_PATTERN & M22_IMPL_MASK;
    setHexProperty(this, "m2-2a-expected", expected);

    bool writeOk = (readback == expected);
    if (writeOk) {
        setProperty("m2-2a-writable", "yes");
    } else {
        setProperty("m2-2a-writable", "no");
    }
    // ---- Step 4: restore the original value immediately ----
    //
    // Restore regardless of whether the previous step succeeded. This cleanup
    // is not optional.
    mmioWrite64(base, M22_OFF_DEV_TABLE, orig);
    UInt64 restored = mmioRead64(base, M22_OFF_DEV_TABLE);
    setHexProperty(this, "m2-2a-restored", restored);

    bool restoreOk = (restored == orig);
    setProperty("m2-2a-restore", restoreOk ? "ok" : "MISMATCH");

    // ---- Step 5: confirm the IOMMU is still off ----
    //
    // Writing DEV_TABLE must not change CONTROL. If it did, we wrote the wrong
    // offset -- a fact that must be known immediately.
    UInt64 ctl = mmioRead64(base, M21_OFF_CONTROL);
    setHexProperty(this, "m2-2a-control-after", ctl);
    if (ctl & 0x1ULL) {
        setProperty("m2-2a-iommu-enabled", "YES-unexpected");
    } else {
        setProperty("m2-2a-iommu-enabled", "no-as-expected");
    }

    // ---- Verdict ----
    if (writeOk && restoreOk) {
        setProperty("m2-2a-verdict", "PASS-mmio-writable");
        setProperty("m2-2a-stage", "6-complete");
    } else if (!writeOk) {
        setProperty("m2-2a-verdict", "FAIL-write-did-not-stick");
        setProperty("m2-2a-stage", "6-complete-write-failed");
    } else {
        setProperty("m2-2a-verdict", "FAIL-restore-mismatch");
        setProperty("m2-2a-stage", "6-complete-restore-failed");
    }

    map->release();
    md->release();
    setProperty("m2-2a-cleanup", "done");
}
