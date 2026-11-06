// AMDMapperProbeTable.cpp -- M2-2a-2/2a-3 device table, enable, cmd channel
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

// ===== AMDMapperProbeTable.cpp (original lines 1442..1662) =====

void org_maz1_AMDMapperProbe::runM22bTableProbe() {
    setProperty("m2-2b-stage", "0-start");

    if (!parseTableBootArg()) {
        setProperty("m2-2b-gate", "closed");
        setProperty("m2-2b-stage", "1-skipped-no-bootarg");
        return;
    }
    setProperty("m2-2b-gate", "open");

    // ---- Step 1: try to allocate physically contiguous memory ----
    //
    // withCapacity(capacity, direction, withContiguousMemory=true)
    // The third argument is the key: it demands the underlying memory be
    // physically contiguous.
    IOBufferMemoryDescriptor *buf = nullptr;
    UInt64 tableSize = 0;

    for (int attempt = 0; attempt < 2; attempt++) {
        UInt64 want = (attempt == 0) ? M22B_TABLE_SIZE_FULL : M22B_TABLE_SIZE_MIN;
        IOBufferMemoryDescriptor *b =
            IOBufferMemoryDescriptor::withCapacity(
                (vm_size_t)want, kIODirectionNone, true);
        if (b) {
            buf = b;
            tableSize = want;
            break;
        }
        // Record the failure and try a smaller size
        if (attempt == 0) setProperty("m2-2b-2mib", "FAILED");
    }

    if (!buf) {
        setProperty("m2-2b-verdict", "FAIL-no-contiguous-memory");
        setProperty("m2-2b-stage", "2-FAIL-alloc");
        return;
    }
    if (tableSize == M22B_TABLE_SIZE_FULL) {
        setProperty("m2-2b-2mib", "ok");
    }
    setHexProperty(this, "m2-2b-tablesize", tableSize);

    // ---- Step 2: take the physical address and confirm real contiguity ----
    //
    // withContiguousMemory=true should guarantee contiguity, but it must be
    // verified by measurement: take the physical addresses at offset 0 and of
    // the last DTE; their difference must equal (count-1)*32. If not, the
    // memory is not truly contiguous and must never be handed to the hardware.
    UInt32 dteCount = (UInt32)(tableSize / M22B_DTE_SIZE);
    setHexProperty(this, "m2-2b-dtecount", dteCount);

    IOByteCount segLen = 0;
    addr64_t paBase = buf->getPhysicalSegment(0, &segLen, kIOMemoryMapperNone);
    if (!paBase) {
        setProperty("m2-2b-verdict", "FAIL-no-physical-address");
        setProperty("m2-2b-stage", "3-FAIL-pa");
        buf->release();
        return;
    }
    setHexProperty(this, "m2-2b-pa", (UInt64)paBase);
    setHexProperty(this, "m2-2b-seglen", (UInt64)segLen);

    // The segment length must cover the whole table
    bool contiguous = ((UInt64)segLen >= tableSize);
    setProperty("m2-2b-contiguous", contiguous ? "yes" : "no");
    if (!contiguous) {
        setProperty("m2-2b-verdict", "FAIL-not-contiguous");
        setProperty("m2-2b-stage", "3-FAIL-seglen");
        buf->release();
        return;
    }

    // The base must be 4 KiB aligned (hardware requirement; the size encoding
    // is in units of 4 KiB)
    bool aligned = (((UInt64)paBase & 0xFFF) == 0);
    setProperty("m2-2b-aligned", aligned ? "yes" : "no");
    if (!aligned) {
        setProperty("m2-2b-verdict", "FAIL-not-page-aligned");
        setProperty("m2-2b-stage", "3-FAIL-align");
        buf->release();
        return;
    }

    // ---- Step 3: fill the table ----
    //
    // Every DTE is filled as "pass-through": V=1, TV=1, IR=1, IW=1, DOMID=0,
    // MODE=0, HOST_TRP=0. Matches Linux's set_dte_passthrough()
    // (iommu.c:2164-2173).
    //
    // Why DOMID 0: a pass-through domain needs no real domain isolation. Linux
    // uses identity_domain.id, but that value depends on its allocator. We use
    // 0 to mean "pass-through domain" -- clear semantics and no collision with
    // anyone (the IOMMU is off, so it is never consumed).
    volatile UInt64 *dte = (volatile UInt64 *)buf->getBytesNoCopy();
    if (!dte) {
        setProperty("m2-2b-verdict", "FAIL-no-virtual-address");
        setProperty("m2-2b-stage", "4-FAIL-va");
        buf->release();
        return;
    }

    const UInt64 passthrough0 = DTE_V | DTE_TV | DTE_IR | DTE_IW;
    const UInt64 passthrough1 = 0;   // DOMID = 0

    for (UInt32 i = 0; i < dteCount; i++) {
        dte[i * 4 + 0] = passthrough0;   // data[0]
        dte[i * 4 + 1] = passthrough1;   // data[1]
        dte[i * 4 + 2] = 0;              // data[2]
        dte[i * 4 + 3] = 0;              // data[3]
    }
    setProperty("m2-2b-filled", "yes");
    setHexProperty(this, "m2-2b-dte0", passthrough0);

    // Spot-check the first and last DTEs to confirm the writes landed
    UInt64 first0 = dte[0];
    UInt64 last0  = dte[(dteCount - 1) * 4];
    setHexProperty(this, "m2-2b-firstdte", first0);
    setHexProperty(this, "m2-2b-lastdte", last0);
    bool fillOk = (first0 == passthrough0 && last0 == passthrough0);
    setProperty("m2-2b-fillcheck", fillOk ? "ok" : "MISMATCH");

    // ---- Step 4: write MMIO_DEV_TABLE_OFFSET ----
    //
    // Encoding: entry = pa | ((size >> 12) - 1)
    //   Linux init.c:401-404:
    //     entry = iommu_virt_to_phys(dev_table);
    //     entry |= (dev_table_size >> 12) - 1;
    //
    // 2 MiB -> (0x200000>>12)-1 = 0x1FF
    // 4 KiB -> (0x1000>>12)-1 = 0x0
    UInt64 sizeCode = (tableSize >> 12) - 1;
    UInt64 entry = ((UInt64)paBase & ~0xFFFULL) | sizeCode;
    setHexProperty(this, "m2-2b-sizecode", sizeCode);
    setHexProperty(this, "m2-2b-entry", entry);

    // Map the MMIO (writable)
    IOMemoryDescriptor *md =
        IOMemoryDescriptor::withPhysicalAddress(
            (IOPhysicalAddress)M21_MMIO_BASE,
            (IOByteCount)M21_MMIO_LEN,
            kIODirectionNone);
    if (!md) {
        setProperty("m2-2b-verdict", "FAIL-mmio-md");
        setProperty("m2-2b-stage", "5-FAIL-mmio-md");
        buf->release();
        return;
    }

    IOMemoryMap *map = md->map(kIOMapInhibitCache | kIOMapAnywhere);
    if (!map) {
        setProperty("m2-2b-verdict", "FAIL-mmio-map");
        setProperty("m2-2b-stage", "5-FAIL-mmio-map");
        md->release();
        buf->release();
        return;
    }

    volatile UInt8 *base = (volatile UInt8 *)map->getVirtualAddress();

    // Re-verify identity before writing (same reasoning as M2-2a-1)
    UInt64 efr = mmioRead64(base, M21_OFF_EXT_FEAT);
    if (efr != M21_EFR_EXPECTED) {
        setProperty("m2-2b-verdict", "FAIL-efr-mismatch");
        setProperty("m2-2b-stage", "6-aborted-identity");
        map->release();
        md->release();
        buf->release();
        return;
    }
    setProperty("m2-2b-identity", "confirmed");

    UInt64 origEntry = mmioRead64(base, M21_OFF_DEV_TABLE);
    setHexProperty(this, "m2-2b-orig-entry", origEntry);

    mmioWrite64(base, M21_OFF_DEV_TABLE, entry);
    UInt64 readback = mmioRead64(base, M21_OFF_DEV_TABLE);
    setHexProperty(this, "m2-2b-readback", readback);

    // The criterion uses the mask (M2-2a-1's lesson: bits 63:52 are reserved)
    UInt64 expected = entry & 0x000FFFFFFFFFFFFFULL;
    setHexProperty(this, "m2-2b-expected", expected);
    bool tableOk = (readback == expected);
    setProperty("m2-2b-tableset", tableOk ? "yes" : "no");

    // ---- Step 5: confirm the IOMMU is still off ----
    //
    // This step's most important safety check: we wrote only DEV_TABLE and
    // must never have touched CONTROL.
    UInt64 ctl = mmioRead64(base, M21_OFF_CONTROL);
    setHexProperty(this, "m2-2b-control", ctl);
    if (ctl & 0x1ULL) {
        setProperty("m2-2b-iommu-enabled", "YES-unexpected");
    } else {
        setProperty("m2-2b-iommu-enabled", "no-as-expected");
    }

    // ---- Step 6: restore ----
    //
    // Because the IOMMU was never enabled, the hardware never reads this
    // table. But to keep "as found, so left", the register is restored to its
    // original value (0). The memory is held by buf and freed with
    // buf->release().
    mmioWrite64(base, M21_OFF_DEV_TABLE, origEntry);
    UInt64 restored = mmioRead64(base, M21_OFF_DEV_TABLE);
    setHexProperty(this, "m2-2b-restored", restored);
    setProperty("m2-2b-restore", (restored == origEntry) ? "ok" : "MISMATCH");

    // ---- Verdict ----
    if (fillOk && tableOk && (restored == origEntry)) {
        setProperty("m2-2b-verdict", "PASS-table-built");
        setProperty("m2-2b-stage", "7-complete");
    } else if (!fillOk) {
        setProperty("m2-2b-verdict", "FAIL-fill");
        setProperty("m2-2b-stage", "7-complete-fill-failed");
    } else if (!tableOk) {
        setProperty("m2-2b-verdict", "FAIL-table-register");
        setProperty("m2-2b-stage", "7-complete-register-failed");
    } else {
        setProperty("m2-2b-verdict", "FAIL-restore");
        setProperty("m2-2b-stage", "7-complete-restore-failed");
    }

    map->release();
    md->release();
    buf->release();
    setProperty("m2-2b-cleanup", "done");
}

// ===== AMDMapperProbeTable.cpp (original lines 1664..1701) =====
// ------------------------------------ M2-2a-3: short-window enable test (highest risk)

// ============================ What this step does ============================
//
// Walk the full Linux early_enable_iommu() enable sequence, but **disable
// immediately after an extremely short window**:
//
//   1. Build the device table (all pass-through, same as M2-2a-2)
//   2. Write MMIO_DEV_TABLE_OFFSET
//   3. Allocate the command buffer (8 KiB), write MMIO_CMD_BUF_OFFSET
//      (base | MMIO_CMD_SIZE_512)
//   4. Reset cmd head/tail to 0
//   5. Set CONTROL_CMDBUF_EN
//   6. Set CONTROL_IOMMU_EN          <- from this moment, all system DMA goes
//                                       through the device table
//   7. Immediately read MMIO_STATUS to confirm the IOMMU really came up
//   8. Immediately clear CONTROL_IOMMU_EN  <- window closes
//   9. Confirm the IOMMU is back in the off state
//
// Why a short window rather than a long-lived enable:
//   The enable action itself may crash immediately (wrong device table
//   address, wrong size encoding, command buffer not ready). If it crashes in
//   a short window, the configuration is fundamentally broken and there is no
//   need to risk a long run. Only if the short window passes does "long-term
//   running after enable" come into question.
//
// ============================ Why no event log ============================
//
// Linux's early_enable_iommu() sequence does **not** include
// enable_event_buffer(). The event log is opened separately in
// init_iommu_one_late(), after IOMMU enable. This round does not open one
// either: the event log only affects fault recording, not translation itself.
// One fewer thing done means one fewer place to go wrong.
//
// ============================ Key registers ============================
//
// MMIO_CMD_BUF_OFFSET (0x08)'s encoding is similar to DEV_TABLE's but
// **different**:
//   Linux: entry = phys(cmd_buf) | MMIO_CMD_SIZE_512
//   MMIO_CMD_SIZE_512 = 0x9ULL << 56      <- high bits! Not low
//   The command buffer is fixed at 512 entries x 16 B = 8 KiB
//
// This is easy to get wrong: DEV_TABLE's size encoding is in the low bits
// (bit 0..11), while CMD_BUF's size encoding is in bits 56..59. Get it wrong
// and the hardware cannot find the command buffer.
#define M23_OFF_CMD_BUF     0x0008

// ===== AMDMapperProbeTable.cpp (original lines 1706..1914) =====

void org_maz1_AMDMapperProbe::runM23EnableProbe() {
    setProperty("m2-3-stage", "0-start");

    if (!parseEnableBootArg()) {
        setProperty("m2-3-gate", "closed");
        setProperty("m2-3-stage", "1-skipped-no-bootarg");
        return;
    }
    setProperty("m2-3-gate", "open");

    // ---- Step 1: allocate the device table (2 MiB, all pass-through) ----
    IOBufferMemoryDescriptor *tbl =
        IOBufferMemoryDescriptor::withCapacity(
            (vm_size_t)M22B_TABLE_SIZE_FULL, kIODirectionNone, true);
    if (!tbl) {
        setProperty("m2-3-verdict", "FAIL-table-alloc");
        setProperty("m2-3-stage", "2-FAIL-table");
        return;
    }

    IOByteCount tblSegLen = 0;
    addr64_t tblPA = tbl->getPhysicalSegment(0, &tblSegLen, kIOMemoryMapperNone);
    if (!tblPA || (UInt64)tblSegLen < M22B_TABLE_SIZE_FULL ||
        ((UInt64)tblPA & 0xFFF)) {
        setProperty("m2-3-verdict", "FAIL-table-memory");
        setProperty("m2-3-stage", "2-FAIL-table-mem");
        tbl->release();
        return;
    }
    setHexProperty(this, "m2-3-tbl-pa", (UInt64)tblPA);

    // Fill all-pass-through DTEs
    volatile UInt64 *dte = (volatile UInt64 *)tbl->getBytesNoCopy();
    UInt32 dteCount = (UInt32)(M22B_TABLE_SIZE_FULL / M22B_DTE_SIZE);
    const UInt64 pt0 = DTE_V | DTE_TV | DTE_IR | DTE_IW;
    for (UInt32 i = 0; i < dteCount; i++) {
        dte[i * 4 + 0] = pt0;
        dte[i * 4 + 1] = 0;
        dte[i * 4 + 2] = 0;
        dte[i * 4 + 3] = 0;
    }
    setProperty("m2-3-table", "filled");

    // ---- Step 2: allocate the command buffer (8 KiB) ----
    IOBufferMemoryDescriptor *cmdbuf =
        IOBufferMemoryDescriptor::withCapacity(
            (vm_size_t)M23_CMD_BUF_SIZE, kIODirectionNone, true);
    if (!cmdbuf) {
        setProperty("m2-3-verdict", "FAIL-cmdbuf-alloc");
        setProperty("m2-3-stage", "3-FAIL-cmdbuf");
        tbl->release();
        return;
    }

    IOByteCount cmdSegLen = 0;
    addr64_t cmdPA = cmdbuf->getPhysicalSegment(0, &cmdSegLen, kIOMemoryMapperNone);
    if (!cmdPA || (UInt64)cmdSegLen < M23_CMD_BUF_SIZE) {
        setProperty("m2-3-verdict", "FAIL-cmdbuf-memory");
        setProperty("m2-3-stage", "3-FAIL-cmdbuf-mem");
        cmdbuf->release();
        tbl->release();
        return;
    }
    setHexProperty(this, "m2-3-cmd-pa", (UInt64)cmdPA);

    // Zero the command buffer (so leftover garbage is not executed as commands)
    {
        volatile UInt64 *cb = (volatile UInt64 *)cmdbuf->getBytesNoCopy();
        for (UInt32 i = 0; i < (M23_CMD_BUF_SIZE / 8); i++) cb[i] = 0;
    }
    setProperty("m2-3-cmdbuf", "zeroed");

    // ---- Step 3: map the MMIO ----
    IOMemoryDescriptor *md =
        IOMemoryDescriptor::withPhysicalAddress(
            (IOPhysicalAddress)M21_MMIO_BASE,
            (IOByteCount)M21_MMIO_LEN,
            kIODirectionNone);
    if (!md) {
        setProperty("m2-3-verdict", "FAIL-mmio-md");
        setProperty("m2-3-stage", "4-FAIL-md");
        cmdbuf->release();
        tbl->release();
        return;
    }

    IOMemoryMap *map = md->map(kIOMapInhibitCache | kIOMapAnywhere);
    if (!map) {
        setProperty("m2-3-verdict", "FAIL-mmio-map");
        setProperty("m2-3-stage", "4-FAIL-map");
        md->release();
        cmdbuf->release();
        tbl->release();
        return;
    }
    volatile UInt8 *base = (volatile UInt8 *)map->getVirtualAddress();

    // Re-verify identity before writing
    if (mmioRead64(base, M21_OFF_EXT_FEAT) != M21_EFR_EXPECTED) {
        setProperty("m2-3-verdict", "FAIL-efr-mismatch");
        setProperty("m2-3-stage", "5-aborted-identity");
        map->release(); md->release(); cmdbuf->release(); tbl->release();
        return;
    }
    setProperty("m2-3-identity", "confirmed");

    // ---- Step 4: record the original state for restoration ----
    UInt64 origDT    = mmioRead64(base, M21_OFF_DEV_TABLE);
    UInt64 origCmd   = mmioRead64(base, M23_OFF_CMD_BUF);
    UInt64 origCtrl  = mmioRead64(base, M21_OFF_CONTROL);
    setHexProperty(this, "m2-3-orig-devicetable", origDT);
    setHexProperty(this, "m2-3-orig-cmdbuf", origCmd);
    setHexProperty(this, "m2-3-orig-control", origCtrl);

    // Safety precondition: the IOMMU must be off on entry. If not, abort
    // immediately.
    if (origCtrl & M23_CTRL_IOMMU_EN) {
        setProperty("m2-3-verdict", "ABORT-already-enabled");
        setProperty("m2-3-stage", "6-aborted-pre-enabled");
        map->release(); md->release(); cmdbuf->release(); tbl->release();
        return;
    }

    // ---- Step 5: write the device table and command buffer registers ----
    UInt64 dtEntry = ((UInt64)tblPA & ~0xFFFULL) |
                     ((M22B_TABLE_SIZE_FULL >> 12) - 1);
    UInt64 cmdEntry = ((UInt64)cmdPA & ~0xFFFULL) | M23_CMD_SIZE_CODE;

    setHexProperty(this, "m2-3-devicetable-entry", dtEntry);
    setHexProperty(this, "m2-3-cmdbuf-entry", cmdEntry);

    mmioWrite64(base, M21_OFF_DEV_TABLE, dtEntry);
    mmioWrite64(base, M23_OFF_CMD_BUF, cmdEntry);
    setProperty("m2-3-regs", "written");

    // Reset cmd head/tail (Linux amd_iommu_reset_cmd_buffer)
    mmioWrite64(base, 0x2000, 0);   // MMIO_CMD_HEAD
    mmioWrite64(base, 0x2008, 0);   // MMIO_CMD_TAIL

    // ---- Step 6: enable the command buffer ----
    //
    // Use read-modify-write to preserve firmware preset bits
    // (COHERENT_EN/EPH_EN etc.).
    UInt64 ctrl = mmioRead64(base, M21_OFF_CONTROL);
    ctrl |= M23_CTRL_CMDBUF_EN;
    mmioWrite64(base, M21_OFF_CONTROL, ctrl);
    UInt64 ctrlAfterCmd = mmioRead64(base, M21_OFF_CONTROL);
    setHexProperty(this, "m2-3-control-after-cmdbuf", ctrlAfterCmd);
    setProperty("m2-3-cmdbuf-enabled",
        (ctrlAfterCmd & M23_CTRL_CMDBUF_EN) ? "yes" : "no");

    // ---- Step 7: enable the IOMMU -- window opens ----
    ctrl = mmioRead64(base, M21_OFF_CONTROL);
    ctrl |= M23_CTRL_IOMMU_EN;
    mmioWrite64(base, M21_OFF_CONTROL, ctrl);

    UInt64 ctrlEnabled = mmioRead64(base, M21_OFF_CONTROL);
    setHexProperty(this, "m2-3-control-enabled", ctrlEnabled);
    bool reallyEnabled = (ctrlEnabled & M23_CTRL_IOMMU_EN) != 0;
    setProperty("m2-3-enabled", reallyEnabled ? "yes" : "no");

    // Read the status register (read-only, no side effects)
    UInt32 status = mmioRead32(base, M21_OFF_STATUS);
    setHexProperty(this, "m2-3-status", (UInt64)status);

    // ---- Step 8: disable immediately -- window closes ----
    //
    // Whatever was read above, this step must execute.
    ctrl = mmioRead64(base, M21_OFF_CONTROL);
    ctrl &= ~M23_CTRL_IOMMU_EN;
    mmioWrite64(base, M21_OFF_CONTROL, ctrl);

    UInt64 ctrlDisabled = mmioRead64(base, M21_OFF_CONTROL);
    setHexProperty(this, "m2-3-control-disabled", ctrlDisabled);
    bool reallyDisabled = (ctrlDisabled & M23_CTRL_IOMMU_EN) == 0;
    setProperty("m2-3-disabled", reallyDisabled ? "yes" : "no");

    // ---- Step 9: restore all registers ----
    mmioWrite64(base, M21_OFF_DEV_TABLE, origDT);
    mmioWrite64(base, M23_OFF_CMD_BUF, origCmd);
    // The command-buffer enable bit is restored too (clear first, then write,
    // so the hardware no longer points at freed memory)
    ctrl = mmioRead64(base, M21_OFF_CONTROL);
    ctrl &= ~M23_CTRL_CMDBUF_EN;
    ctrl |= (origCtrl & M23_CTRL_CMDBUF_EN);
    mmioWrite64(base, M21_OFF_CONTROL, ctrl);

    UInt64 finalCtrl = mmioRead64(base, M21_OFF_CONTROL);
    setHexProperty(this, "m2-3-final-control", finalCtrl);
    setHexProperty(this, "m2-3-final-devicetable",
                   mmioRead64(base, M21_OFF_DEV_TABLE));
    setHexProperty(this, "m2-3-final-cmdbuf", mmioRead64(base, M23_OFF_CMD_BUF));

    // ---- Verdict ----
    if (reallyEnabled && reallyDisabled) {
        setProperty("m2-3-verdict", "PASS-enable-disable-window");
        setProperty("m2-3-stage", "7-complete");
    } else if (!reallyEnabled) {
        setProperty("m2-3-verdict", "FAIL-did-not-enable");
        setProperty("m2-3-stage", "7-complete-not-enabled");
    } else {
        setProperty("m2-3-verdict", "FAIL-could-not-disable");
        setProperty("m2-3-stage", "7-complete-still-enabled");
    }

    map->release();
    md->release();
    cmdbuf->release();
    tbl->release();
    setProperty("m2-3-cleanup", "done");
}

// ===== AMDMapperProbeTable.cpp (original lines 1965..2211) =====
void org_maz1_AMDMapperProbe::runM2b1CmdProbe() {
    setProperty("m2-b1-stage", "0-start");

    if (!parseCmdBootArg()) {
        setProperty("m2-b1-gate", "closed");
        setProperty("m2-b1-stage", "1-skipped-no-bootarg");
        return;
    }
    setProperty("m2-b1-gate", "open");

    // ---- Step 1: allocate the three memory blocks ----
    //   tbl     : 2 MiB device table (all pass-through)
    //   cmdbuf  : 8 KiB command buffer
    //   cwwb    : 4 KiB completion signal (cmd_sem)
    IOBufferMemoryDescriptor *tbl =
        IOBufferMemoryDescriptor::withCapacity(
            (vm_size_t)M22B_TABLE_SIZE_FULL, kIODirectionNone, true);
    IOBufferMemoryDescriptor *cmdbuf =
        IOBufferMemoryDescriptor::withCapacity(
            (vm_size_t)M23_CMD_BUF_SIZE, kIODirectionNone, true);
    IOBufferMemoryDescriptor *cwwb =
        IOBufferMemoryDescriptor::withCapacity(
            (vm_size_t)0x1000, kIODirectionNone, true);

    if (!tbl || !cmdbuf || !cwwb) {
        setProperty("m2-b1-verdict", "FAIL-alloc");
        setProperty("m2-b1-stage", "2-FAIL-alloc");
        if (tbl) tbl->release();
        if (cmdbuf) cmdbuf->release();
        if (cwwb) cwwb->release();
        return;
    }

    IOByteCount sl = 0;
    addr64_t tblPA = tbl->getPhysicalSegment(0, &sl, kIOMemoryMapperNone);
    bool memOk = tblPA && ((UInt64)sl >= M22B_TABLE_SIZE_FULL);

    addr64_t cmdPA = 0;
    addr64_t semPA = 0;
    if (memOk) {
        cmdPA = cmdbuf->getPhysicalSegment(0, &sl, kIOMemoryMapperNone);
        memOk = cmdPA && ((UInt64)sl >= M23_CMD_BUF_SIZE);
    }
    if (memOk) {
        semPA = cwwb->getPhysicalSegment(0, &sl, kIOMemoryMapperNone);
        memOk = semPA && ((UInt64)sl >= 0x1000);
    }

    if (!memOk) {
        setProperty("m2-b1-verdict", "FAIL-memory");
        setProperty("m2-b1-stage", "3-FAIL-mem");
        tbl->release();
        cmdbuf->release();
        cwwb->release();
        return;
    }

    setHexProperty(this, "m2-b1-tbl-pa", (UInt64)tblPA);
    setHexProperty(this, "m2-b1-cmd-pa", (UInt64)cmdPA);
    setHexProperty(this, "m2-b1-sem-pa", (UInt64)semPA);

    // All three must be 4 KiB aligned
    if (((UInt64)tblPA & 0xFFF) || ((UInt64)cmdPA & 0xFFF) ||
        ((UInt64)semPA & 0xFFF)) {
        setProperty("m2-b1-verdict", "FAIL-not-aligned");
        setProperty("m2-b1-stage", "3-FAIL-align");
        tbl->release(); cmdbuf->release(); cwwb->release();
        return;
    }

    // ---- Step 2: fill the table, zero the command buffer and cmd_sem ----
    volatile UInt64 *dte = (volatile UInt64 *)tbl->getBytesNoCopy();
    UInt32 dteCount = (UInt32)(M22B_TABLE_SIZE_FULL / M22B_DTE_SIZE);
    const UInt64 pt0 = DTE_V | DTE_TV | DTE_IR | DTE_IW;
    for (UInt32 i = 0; i < dteCount; i++) {
        dte[i * 4 + 0] = pt0;
        dte[i * 4 + 1] = 0;
        dte[i * 4 + 2] = 0;
        dte[i * 4 + 3] = 0;
    }

    volatile UInt32 *cmdBuf = (volatile UInt32 *)cmdbuf->getBytesNoCopy();
    for (UInt32 i = 0; i < (M23_CMD_BUF_SIZE / 4); i++) cmdBuf[i] = 0;

    volatile UInt64 *sem = (volatile UInt64 *)cwwb->getBytesNoCopy();
    *sem = 0;
    setProperty("m2-b1-mem", "prepared");

    // ---- Step 3: map the MMIO ----
    IOMemoryDescriptor *md =
        IOMemoryDescriptor::withPhysicalAddress(
            (IOPhysicalAddress)M21_MMIO_BASE,
            (IOByteCount)M21_MMIO_LEN, kIODirectionNone);
    if (!md) {
        setProperty("m2-b1-verdict", "FAIL-mmio-md");
        setProperty("m2-b1-stage", "4-FAIL-md");
        tbl->release(); cmdbuf->release(); cwwb->release();
        return;
    }
    IOMemoryMap *map = md->map(kIOMapInhibitCache | kIOMapAnywhere);
    if (!map) {
        setProperty("m2-b1-verdict", "FAIL-mmio-map");
        setProperty("m2-b1-stage", "4-FAIL-map");
        md->release();
        tbl->release(); cmdbuf->release(); cwwb->release();
        return;
    }
    volatile UInt8 *base = (volatile UInt8 *)map->getVirtualAddress();

    if (mmioRead64(base, M21_OFF_EXT_FEAT) != M21_EFR_EXPECTED) {
        setProperty("m2-b1-verdict", "FAIL-efr-mismatch");
        setProperty("m2-b1-stage", "5-aborted-identity");
        map->release(); md->release();
        tbl->release(); cmdbuf->release(); cwwb->release();
        return;
    }
    setProperty("m2-b1-identity", "confirmed");

    // ---- Step 4: record the original state ----
    UInt64 origDT   = mmioRead64(base, M21_OFF_DEV_TABLE);
    UInt64 origCmd  = mmioRead64(base, M23_OFF_CMD_BUF);
    UInt64 origCtrl = mmioRead64(base, M21_OFF_CONTROL);
    setHexProperty(this, "m2-b1-orig-control", origCtrl);

    if (origCtrl & M23_CTRL_IOMMU_EN) {
        setProperty("m2-b1-verdict", "ABORT-already-enabled");
        setProperty("m2-b1-stage", "6-aborted");
        map->release(); md->release();
        tbl->release(); cmdbuf->release(); cwwb->release();
        return;
    }

    // ---- Step 5: configure and enable ----
    UInt64 dtEntry  = ((UInt64)tblPA & ~0xFFFULL) |
                      ((M22B_TABLE_SIZE_FULL >> 12) - 1);
    UInt64 cmdEntry = ((UInt64)cmdPA & ~0xFFFULL) | M23_CMD_SIZE_CODE;

    mmioWrite64(base, M21_OFF_DEV_TABLE, dtEntry);
    mmioWrite64(base, M23_OFF_CMD_BUF, cmdEntry);
    mmioWrite64(base, M2B1_CMD_HEAD_OFFSET, 0);
    mmioWrite64(base, M2B1_CMD_TAIL_OFFSET, 0);

    UInt64 ctrl = mmioRead64(base, M21_OFF_CONTROL);
    ctrl |= M23_CTRL_CMDBUF_EN;
    mmioWrite64(base, M21_OFF_CONTROL, ctrl);

    ctrl = mmioRead64(base, M21_OFF_CONTROL);
    ctrl |= M23_CTRL_IOMMU_EN;
    mmioWrite64(base, M21_OFF_CONTROL, ctrl);

    UInt64 ctrlOn = mmioRead64(base, M21_OFF_CONTROL);
    setProperty("m2-b1-enabled",
        (ctrlOn & M23_CTRL_IOMMU_EN) ? "yes" : "no");
    setHexProperty(this, "m2-b1-control-on", ctrlOn);

    // ---- Step 6: issue one CMD_COMPL_WAIT ----
    //
    // Sequence number 1 (initial value 0; a change proves execution).
    const UInt32 kSeq = 1;
    UInt64 seq = (UInt64)kSeq;

    UInt32 d0 = (UInt32)((UInt64)semPA & 0xFFFFFFFF) | M2B1_CMD_STORE_MASK;
    UInt32 d1 = (UInt32)((UInt64)semPA >> 32) | (M2B1_CMD_COMPL_WAIT << 28);
    UInt32 d2 = (UInt32)(seq & 0xFFFFFFFF);
    UInt32 d3 = (UInt32)(seq >> 32);

    setHexProperty(this, "m2-b1-cmd-d0", d0);
    setHexProperty(this, "m2-b1-cmd-d1", d1);
    setHexProperty(this, "m2-b1-cmd-d2", d2);
    setHexProperty(this, "m2-b1-cmd-d3", d3);

    writeCmd(cmdBuf, 0, d0, d1, d2, d3);
    setProperty("m2-b1-cmd", "written");

    // Advance tail: the hardware fetches commands at tail.
    // Note Linux uses writel(tail, ...), where tail is a byte offset.
    UInt32 newTail = 16;   // one command is 16 bytes
    mmioWrite64(base, M2B1_CMD_TAIL_OFFSET, newTail);
    setHexProperty(this, "m2-b1-tail", newTail);

    // ---- Step 7: poll cmd_sem, waiting for the hardware to write back ----
    UInt32 loops = 0;
    UInt64 observed = 0;
    while (loops < M2B1_LOOP_TIMEOUT) {
        observed = *sem;
        if (observed != 0) break;
        loops++;
    }

    setHexProperty(this, "m2-b1-sem-value", observed);
    setHexProperty(this, "m2-b1-loops", loops);

    bool cmdWorked = (observed == seq);
    setProperty("m2-b1-cmd-executed", cmdWorked ? "yes" : "no");

    // Read head/tail to see how far the hardware has consumed
    UInt64 hwHead = mmioRead64(base, M2B1_CMD_HEAD_OFFSET);
    UInt64 hwTail = mmioRead64(base, M2B1_CMD_TAIL_OFFSET);
    setHexProperty(this, "m2-b1-hw-head", hwHead);
    setHexProperty(this, "m2-b1-hw-tail", hwTail);

    UInt32 status = mmioRead32(base, M21_OFF_STATUS);
    setHexProperty(this, "m2-b1-status", (UInt64)status);
    if (status & 0x1) {
        setProperty("m2-b1-evt-overflow", "YES");
    } else {
        setProperty("m2-b1-evt-overflow", "no");
    }

    // ---- Step 8: disable immediately and restore ----
    ctrl = mmioRead64(base, M21_OFF_CONTROL);
    ctrl &= ~M23_CTRL_IOMMU_EN;
    mmioWrite64(base, M21_OFF_CONTROL, ctrl);
    UInt64 ctrlOff = mmioRead64(base, M21_OFF_CONTROL);
    setProperty("m2-b1-disabled",
        (ctrlOff & M23_CTRL_IOMMU_EN) ? "no" : "yes");

    mmioWrite64(base, M21_OFF_DEV_TABLE, origDT);
    mmioWrite64(base, M23_OFF_CMD_BUF, origCmd);
    ctrl = mmioRead64(base, M21_OFF_CONTROL);
    ctrl &= ~M23_CTRL_CMDBUF_EN;
    ctrl |= (origCtrl & M23_CTRL_CMDBUF_EN);
    mmioWrite64(base, M21_OFF_CONTROL, ctrl);

    setHexProperty(this, "m2-b1-final-control",
                   mmioRead64(base, M21_OFF_CONTROL));
    setHexProperty(this, "m2-b1-final-devicetable",
                   mmioRead64(base, M21_OFF_DEV_TABLE));
    setHexProperty(this, "m2-b1-final-cmdbuf",
                   mmioRead64(base, M23_OFF_CMD_BUF));

    // ---- Verdict ----
    if (cmdWorked) {
        setProperty("m2-b1-verdict", "PASS-command-channel-works");
        setProperty("m2-b1-stage", "7-complete");
    } else {
        setProperty("m2-b1-verdict", "FAIL-no-completion");
        setProperty("m2-b1-stage", "7-complete-no-completion");
    }

    map->release();
    md->release();
    tbl->release();
    cmdbuf->release();
    cwwb->release();
    setProperty("m2-b1-cleanup", "done");
}
