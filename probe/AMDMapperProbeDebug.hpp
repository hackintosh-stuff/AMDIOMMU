// AMDMapperProbeDebug.hpp -- boot-arg parsers for the retired M2 experiment
// modes (arm/mmio/write/table/enable/cmd/pgt/pgt4k/pgthold/pgtsleep/pgt3l).
//
// Only included by the Debug build (AMD_MAPPER_PROBE_DEBUG=1); the production
// build's main switch accepts just amdiommu=passive / auto-attach. The legacy
// experiment modules live in probe/*Debug.cpp and are built by
// tools/build/build-probe-debug.sh.

#ifndef AMDMapperProbeDebug_hpp
#define AMDMapperProbeDebug_hpp

#include <pexpert/pexpert.h>
#include <libkern/libkern.h>

#if AMD_MAPPER_PROBE_DEBUG

// ---- parseM22b2Delay (original lines 5295..5308) ----
// Parses m2b2delay=<seconds> and returns milliseconds. Capped at 300 s to
// avoid hanging a timer that never fires.
static inline bool parseM22b2Delay(uint32_t *outMS) {
    char val[32];
    if (!PE_parse_boot_argn("m2b2delay", val, sizeof(val))) return false;
    int secs = 0;
    for (int i = 0; val[i] && i < 8; i++) {
        if (val[i] < '0' || val[i] > '9') return false;
        secs = secs * 10 + (val[i] - '0');
        if (secs > 300) return false;
    }
    if (secs <= 0) return false;
    *outMS = (uint32_t)secs * 1000;
    return true;
}

// ---- parseArmBootArg (original lines 7419..7437) ----
// ------------------------------------------------------------------ Lifecycle

// Parses amdiommu=arm from the boot arguments.
//
// Why a boot-arg instead of auto-detection:
//   Having an RTL8127 installed does not mean it should be let through. Once
//   let through, Lucy's descriptor ring mappings really pass through us; if
//   our implementation is defective the consequence is a non-working NIC or
//   even a panic. So this is an **explicit switch**: without `amdiommu=arm`
//   the behaviour is identical to 0.5.0, and the parameter can be removed at
//   any time to return to the safe state.
//
// PE_parse_boot_argn instead of querying the IORegistry: boot-args are parsed
// early by the kernel and are guaranteed to be available by the time our
// start() runs.
static inline bool parseArmBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    return strncmp(val, "arm", 3) == 0;
}

// ---- boot-arg parsers (original lines 7439..7583) ----
// Parses amdiommu=mmio -- the gate for M2-1 MMIO probing.
//
// Why a separate value instead of reusing "arm":
//   arm only affects B2-b (letting the NIC's mappings pass through us) and is
//   verified stable on this machine. mmio makes the code touch the IOMMU's
//   MMIO window for the first time -- a different kind of risk. The two must
//   be independently switchable so that on a problem mmio can be turned off
//   while arm is kept, isolating variables to the minimum.
//
// Note that PE_parse_boot_argn can only take one value, so amdiommu=arm and
// amdiommu=mmio cannot both be written. This round's usage:
//   amdiommu=mmio  -> run MMIO probing only, NIC not let through (safest)
//   amdiommu=arm   -> let the NIC through only, no MMIO (B2-b state)
static inline bool parseMmioBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    return strncmp(val, "mmio", 4) == 0;
}

// Parses amdiommu=write -- the gate for the M2-2a-1 minimal write test.
//
// Three escalating levels, each with a different risk, independently
// switchable:
//   amdiommu=arm    -> let the NIC through only (B2-b, verified stable)
//   amdiommu=mmio   -> read-only MMIO (M2-1, verified passing)
//   amdiommu=write  -> allow MMIO writes (M2-2a-1, new this round)
//
// Why an independent value instead of a sub-flag on mmio:
//   PE_parse_boot_argn takes one value at a time; separate values are
//   clearest, and on a problem the variable is isolated to the single
//   dimension "are writes allowed".
static inline bool parseWriteBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    return strncmp(val, "write", 5) == 0;
}

// Parses amdiommu=table -- the gate for M2-2a-2.
//
// Four escalating levels, increasing risk:
//   arm   -> let the NIC through (B2-b)
//   mmio  -> read-only MMIO (M2-1)
//   write -> single-register write test (M2-2a-1)
//   table -> build a device table and write the base register (M2-2a-2, this round)
static inline bool parseTableBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    return strncmp(val, "table", 5) == 0;
}

// Parses amdiommu=enable -- the gate for M2-2a-3.
//
// Five escalating levels, increasing risk:
//   arm    -> let the NIC through (B2-b)
//   mmio   -> read-only MMIO (M2-1)
//   write  -> single-register write test (M2-2a-1)
//   table  -> build the device table (M2-2a-2)
//   enable -> enable the IOMMU (M2-2a-3, this round, highest risk)
//
// Note on strncmp length: the full string length must be used, otherwise
// "enable" also matches "enableX". Here 6 = strlen("enable").
static inline bool parseEnableBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    return strncmp(val, "enable", 6) == 0;
}

// Parses amdiommu=cmd -- the gate for M2-2b-1 command channel verification.
//
// Six escalating levels:
//   arm -> mmio -> write -> table -> enable -> cmd
// Each level is an independently revertible switch, isolating variables to the
// minimum when something goes wrong.
static inline bool parseCmdBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    return strncmp(val, "cmd", 3) == 0;
}

// Parses amdiommu=pgt -- the gate for M2-2b-2.
//
// Seven escalating levels:
//   arm -> mmio -> write -> table -> enable -> cmd -> pgt
//
// This is the first step in M2 where the hardware **really translates DMA
// through a page table we built**. The previous six steps were all "configure
// registers" or "full pass-through"; the hardware never looked at a page table.
static inline bool parsePgtBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    // Note: strncmp(val, "pgt", 3) must be used so that "pgt4k" also
    // matches -- it is a pgt variant (4 KiB leaf mode) and the gate should
    // open for it too.
    return strncmp(val, "pgt", 3) == 0;
}

// Parses amdiommu=pgt4k -- the 4 KiB leaf page discrimination experiment.
//
// Must be stricter than parsePgtBootArg: a full 5-character comparison is
// used, otherwise "pgt" would also match.
static inline bool parsePgt4kBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    return strncmp(val, "pgt4k", 5) == 0;
}

// Parses amdiommu=pgthold -- a long observation mode that keeps translation
// active.
//
// Difference from the previous two modes: pgthold extends the observation
// window from 2 s to 20 s with the DTE pointing at the translation table the
// whole time. This allows observing from outside whether en2's RX/TX packet
// counters keep growing via netstat -- that is the direct evidence of whether
// the page table actually works.
static inline bool parsePgtHoldBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    return strncmp(val, "pgthold", 7) == 0;
}

// Parses amdiommu=pgtsleep -- a pure-sleep control (keeps pass-through, only
// performs the same long sleep).
static inline bool parsePgtSleepBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    return strncmp(val, "pgtsleep", 8) == 0;
}

// Parses amdiommu=pgt3l -- 3-level page table mode.
static inline bool parsePgt3lBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    return strncmp(val, "pgt3l", 5) == 0;
}

#endif /* AMD_MAPPER_PROBE_DEBUG */
#endif /* AMDMapperProbeDebug_hpp */
