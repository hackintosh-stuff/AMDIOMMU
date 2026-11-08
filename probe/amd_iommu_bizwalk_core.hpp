// amd_iommu_bizwalk_core.hpp -- walk EVERY byte of a business DMA range, not
// just the first page, and export every path that was used.
//
// ===========================================================================
// WHY THIS FILE EXISTS (round 12)
// ===========================================================================
//
// Round 11 walked `addr`, then separately looped "pages" to decide coverage.
// Three things were wrong with that, and all three are false-pass shapes:
//
//   1. The exported path was the FIRST page's path only. A 74-byte range that
//      starts 16 bytes before a leaf boundary crosses into a leaf whose path
//      was never exported, yet `covered` could still read yes because the
//      coverage loop walked a DIFFERENT leaf successfully. The analyser then
//      had raw PTEs for one leaf and a "covered" claim about two.
//
//   2. The coverage loop advanced by `pageSize` derived from the leaf it had
//      just decoded -- including when that decode had FAILED, where it fell
//      back to 4096 and could skip over a gap.
//
//   3. `count >= kBizWalkMaxSegs` returned without recording anything, so a
//      range that was never walked looked exactly like a range that passed.
//      "Only exported the first leaf but claimed the whole range" is the same
//      defect one level down: budget exhaustion has to be a RECORDED
//      degradation.
//
// The rule this file enforces:
//
//     a range is covered only when EVERY byte of [addr, addr+len) is covered
//     by a legal leaf, EVERY leaf used is exported in full (root to leaf), and
//     EVERY level of EVERY path carries the permission the direction needs.
//
// Anything else is `covered = false` with a stable `why` token, never a
// silent skip.
//
// ===========================================================================
// WHY IT IS A HEADER AND NOT INLINE IN THE PROBE
// ===========================================================================
// Same reason as amd_iommu_pte_core.hpp: the host regression test must compile
// the code the kext runs. A test that re-implements the walk proves nothing
// about the kext, and the round-4 history is exactly that failure -- three
// implementations agreeing with each other and all three wrong.
//
// It depends on amd_iommu_pte_core.hpp and nothing else: no IOKit, no libc,
// no allocation. The caller supplies a `readEntry(tablePA, index)` callback,
// which the kext points at its own page-table memory and the test points at a
// plain array.

#pragma once

#include "amd_iommu_pte_core.hpp"

namespace amdbw {

typedef unsigned long long u64;
typedef unsigned int       u32;

// How many distinct leaves one range may use. A 74-byte frame lands in one
// 2 MiB leaf; the bound exists so a pathological range (or a corrupted length)
// cannot make the export unbounded. Exceeding it is RECORDED, not ignored.
static const unsigned kMaxLeaves = 4;

// One exported path: the whole chain from the root to the leaf, every level.
//
// `table`/`index`/`level`/`pte` are what an independent decoder needs to
// re-derive the link itself rather than trusting the walker's conclusion.
struct Path {
    unsigned depth;                  // number of PTEs examined (>= 1)
    unsigned level[amdpte::LEVEL_MAX];
    u64      table[amdpte::LEVEL_MAX];
    unsigned index[amdpte::LEVEL_MAX];
    u64      pte[amdpte::LEVEL_MAX];
    u64      leafPA;                 // leaf base from the decoded PTE
    u64      leafSize;               // bytes this leaf maps
    unsigned leafLevel;              // level of the table holding the leaf
    u64      coversFrom;             // first byte of the range this leaf covers
    u64      coversBytes;            // how many bytes of the range it covers
    bool     permOk;                 // every level carries the direction's bit
};

struct RangeResult {
    bool     ok;            // the range is fully covered with the right perms
    bool     overflow;      // addr + len wrapped 64 bits
    bool     capped;        // more leaves than kMaxLeaves: DEGRADED, not ok
    bool     badStart;      // the first byte has no legal leaf
    unsigned leafCount;     // leaves exported
    unsigned leavesChecked;
    unsigned leavesBad;
    bool     covered;
    bool     permOk;
    u64      bytesCovered;  // bytes of [addr, addr+len) proven covered
    const char *why;        // stable token; nullptr when ok
    Path     path[kMaxLeaves];
};

static inline void rangeResultInit(RangeResult &r) {
    r.ok = false;
    r.overflow = false;
    r.capped = false;
    r.badStart = false;
    r.leafCount = 0;
    r.leavesChecked = 0;
    r.leavesBad = 0;
    r.covered = false;
    r.permOk = true;
    r.bytesCovered = 0;
    r.why = "not-walked";
    for (unsigned i = 0; i < kMaxLeaves; i++) {
        r.path[i].depth = 0;
        r.path[i].leafPA = 0;
        r.path[i].leafSize = 0;
        r.path[i].leafLevel = 0;
        r.path[i].coversFrom = 0;
        r.path[i].coversBytes = 0;
        r.path[i].permOk = false;
    }
}

// Walk one address. `readEntry` returns the 64-bit PTE at tablePA+index*8, and
// MUST return 0 for an address outside the memory it is allowed to read (0 has
// PR=0, so an out-of-bounds read decodes as "absent" rather than fabricating a
// leaf).
//
// `out` receives the full chain. Returns true only for a legal leaf.
template <typename ReadFn>
static inline bool walkOne(ReadFn readEntry, unsigned rootLevel, u64 rootPA,
                           u64 iova, Path &out) {
    out.depth = 0;
    out.leafPA = 0;
    out.leafSize = 0;
    out.leafLevel = 0;
    out.coversFrom = 0;
    out.coversBytes = 0;
    out.permOk = false;

    if (rootLevel < amdpte::LEVEL_4K || rootLevel > amdpte::LEVEL_MAX)
        return false;

    unsigned level = rootLevel;
    u64 tablePA = rootPA;

    while (out.depth < amdpte::LEVEL_MAX) {
        const unsigned ix = amdpte::indexAt(level, iova);
        const u64 pte = readEntry(tablePA, ix);

        out.level[out.depth] = level;
        out.table[out.depth] = tablePA;
        out.index[out.depth] = ix;
        out.pte[out.depth] = pte;
        out.depth++;

        const amdpte::DecodedPte d = amdpte::decodePte(pte, level);

        if (d.kind == amdpte::PTE_TABLE) {
            level = d.childLevel;
            tablePA = d.outPA;
            continue;
        }
        if (d.kind == amdpte::PTE_LEAF_DEFAULT ||
            d.kind == amdpte::PTE_LEAF_LARGE) {
            out.leafPA = d.outPA;
            out.leafSize = d.pageSize;
            out.leafLevel = level;
            return true;
        }
        // absent or illegal
        return false;
    }
    return false;
}

// Does every level of this path carry the bit the direction needs?
//
// TX (the device READS the buffer) -> IR
// RX (the device WRITES the buffer) -> IW
//
// Every DIRECTORY entry on the path is checked too: a directory without IR
// makes the leaf unreachable for a read even when the leaf itself has IR.
static inline bool pathPermOk(const Path &p, bool isRx) {
    if (p.depth == 0) return false;
    for (unsigned k = 0; k < p.depth; k++) {
        const u64 need = isRx ? amdpte::PTE_IW : amdpte::PTE_IR;
        if ((p.pte[k] & need) == 0) return false;
    }
    return true;
}

// Walk the WHOLE range [addr, addr+len).
//
// The loop advances by the leaf it just proved, so the number of iterations is
// the number of DISTINCT leaves the range touches -- not the number of 4 KiB
// pages, and never an unbounded scan.
template <typename ReadFn>
static inline void walkRange(ReadFn readEntry, unsigned rootLevel, u64 rootPA,
                             u64 addr, u32 len, bool isRx, RangeResult &r) {
    rangeResultInit(r);

    if (len == 0) { r.why = "zero-length"; return; }

    const u64 end = addr + (u64)len;
    if (end < addr) { r.overflow = true; r.why = "range-overflows"; return; }
    if (addr == 0) { r.why = "null-address"; return; }

    u64 cur = addr;
    while (cur < end) {
        if (r.leafCount >= kMaxLeaves) {
            // We have proven some prefix and cannot export the rest. Say so:
            // "covered" stays false and the caller must degrade.
            r.capped = true;
            r.why = "leaf-budget-exceeded";
            return;
        }
        Path &p = r.path[r.leafCount];
        r.leavesChecked++;

        if (!walkOne(readEntry, rootLevel, rootPA, cur, p)) {
            r.leavesBad++;
            if (r.leafCount == 0) {
                r.badStart = true;
                r.why = "start-not-a-legal-leaf";
            } else {
                r.why = "range-not-fully-covered";
            }
            return;
        }
        if (p.depth == 0) {          // defensive: walkOne cannot succeed with 0
            r.leavesBad++;
            r.why = "empty-path";
            return;
        }

        // Identity FIRST, then containment.
        //
        // The leaf's VIRTUAL span is fixed by the index that selected it, not
        // by its physical base, so "does the leaf contain `cur`" is only a
        // meaningful question once identity is assumed. A leaf pointing at a
        // different physical page still covers `cur`'s virtual range; testing
        // containment first would report the misleading reason
        // "leaf-does-not-contain-address" for what is really a non-identity
        // mapping. That is what the first version of this round did, and the
        // test caught it.
        //
        // The experiment maps each physical page to itself, so the translation
        // of `cur` must BE `cur`. A leaf that translates elsewhere is not
        // evidence about this address, whatever else is true of it.
        if ((p.leafPA | (cur & (p.leafSize - 1))) != cur) {
            r.leavesBad++;
            r.why = "not-an-identity-mapping";
            return;
        }

        // Defensive: after the identity check this cannot fail, but if the
        // leaf size and the page base ever disagree the loop must stop rather
        // than advance by a bogus amount.
        if (!(p.leafPA <= cur && cur < p.leafPA + p.leafSize)) {
            r.leavesBad++;
            r.why = "leaf-does-not-contain-address";
            return;
        }

        p.coversFrom = cur;
        p.coversBytes = 0;
        p.permOk = pathPermOk(p, isRx);
        if (!p.permOk) r.permOk = false;

        // How far this leaf carries us: to its end, or to the range end.
        const u64 leafEnd = p.leafPA + p.leafSize;
        const u64 stop = (leafEnd < end) ? leafEnd : end;
        if (stop <= cur) {           // defensive: never loop forever
            r.leavesBad++;
            r.why = "no-progress";
            return;
        }
        p.coversBytes = stop - cur;
        r.bytesCovered += p.coversBytes;
        r.leafCount++;

        cur = stop;
    }

    r.covered = (r.bytesCovered == (u64)len);
    if (!r.covered) { r.why = "range-not-fully-covered"; return; }
    if (!r.permOk)  { r.why = "permission-insufficient"; return; }
    r.ok = true;
    r.why = nullptr;
}

}  // namespace amdbw
