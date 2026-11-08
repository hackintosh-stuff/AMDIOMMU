// bizwalk-core-test.cpp -- the business-range walker, tested from the file the
// kext compiles.
//
// WHY THIS TEST EXISTS
// --------------------
// Round 11 walked the first page of a business range, then looped "pages" to
// decide coverage. Three false-pass shapes came out of that, and each one is a
// test case below:
//
//   A. a range that starts near a leaf boundary crosses into a leaf whose path
//      was never exported, while `covered` still read yes;
//   B. the coverage loop fell back to a 4096-byte step when a decode failed,
//      so it could skip over a gap;
//   C. a range beyond the export budget was skipped with no record at all, so
//      "only exported part of it" looked identical to "all of it passed".
//
// The walker now lives in probe/amd_iommu_bizwalk_core.hpp and BOTH the kext and
// this test compile it. A test that re-implemented the walk would prove nothing
// about the kext -- round 4's history is exactly three implementations agreeing
// with each other and all three wrong.
//
// The page table here is a real 4-level AMD-Vi table built with
// amd_iommu_pte_core.hpp (the same encoder the kext uses), not a mock.

#include "../probe/amd_iommu_bizwalk_core.hpp"

#include <cstdio>
#include <cstring>
#include <map>
#include <vector>

static int gPass = 0, gFail = 0;

static void check(bool cond, const char *what) {
    if (cond) {
        gPass++;
    } else {
        gFail++;
        std::printf("FAIL: %s\n", what);
    }
}

static void checkU64(unsigned long long got, unsigned long long want,
                     const char *what) {
    if (got == want) {
        gPass++;
    } else {
        gFail++;
        std::printf("FAIL: %s (got 0x%llx, want 0x%llx)\n", what, got, want);
    }
}

// ---------------------------------------------------------------------------
// A page table in a flat buffer, addressed by physical address exactly as the
// kext addresses its own allocated block.
// ---------------------------------------------------------------------------
static const unsigned kRootLevel = 4;
static const unsigned long long kRootPA = 0x10000000ULL;
static const unsigned long long kTableBytes = 0x10000ULL;

struct PageTable {
    std::vector<unsigned long long> words;   // 8 bytes each
    unsigned long long base;

    PageTable() : words(kTableBytes / 8, 0), base(kRootPA) {}

    // The kext's readEntry: out-of-range returns 0, which decodes as absent.
    unsigned long long read(unsigned long long tablePA, unsigned index) const {
        if (tablePA < base) return 0;
        const unsigned long long off = tablePA - base;
        if (off + 8ULL * index + 8ULL > kTableBytes) return 0;
        return words[off / 8 + index];
    }

    void write(unsigned long long tablePA, unsigned index,
               unsigned long long pte) {
        const unsigned long long off = tablePA - base;
        words[off / 8 + index] = pte;
    }

    // Allocate a fresh table page and return its PA.
    unsigned long long newTable(unsigned long long *cursor) {
        const unsigned long long pa = base + *cursor;
        *cursor += 4096;
        return pa;
    }
};

// Build a 4-level identity map for `addr` down to a 2 MiB leaf, returning the
// L2 table's PA so a caller can make several addresses share or not share it.
struct Built {
    unsigned long long root, l3, l2;
    bool ok;
};

static Built buildIdentity(PageTable &pt, unsigned long long cursor,
                           unsigned long long addr, bool perms) {
    Built b;
    b.root = pt.base;
    b.l3 = pt.base + cursor;        cursor += 4096;
    b.l2 = pt.base + cursor;
    b.ok = true;
    const amdpte::u64 permsBits = perms ? (amdpte::PTE_IR | amdpte::PTE_IW) : 0;
    pt.write(b.root, amdpte::indexAt(4, addr),
             amdpte::makeTablePde(3, b.l3, permsBits));
    pt.write(b.l3, amdpte::indexAt(3, addr),
             amdpte::makeTablePde(2, b.l2, permsBits));
    pt.write(b.l2, amdpte::indexAt(2, addr),
             amdpte::makeDefaultLeaf(2, addr & ~0x1FFFFFULL, permsBits));
    return b;
}

// ---------------------------------------------------------------------------
// 1. a range inside ONE leaf: the ordinary case
// ---------------------------------------------------------------------------
static void testSingleLeaf() {
    PageTable pt;
    const unsigned long long addr = 0x1F421F000ULL;   // inside a 2 MiB leaf
    buildIdentity(pt, 0x1000, addr, true);

    amdbw::RangeResult r;
    amdbw::walkRange([&](unsigned long long t, unsigned i) { return pt.read(t, i); },
                     kRootLevel, pt.base, addr, 74, false, r);
    check(r.ok, "a 74-byte range inside one leaf is covered");
    checkU64(r.leafCount, 1, "and uses exactly one leaf");
    checkU64(r.bytesCovered, 74, "and every byte is accounted for");
    check(r.permOk, "and the direction's permission is present at every level");
    check(r.path[0].depth == 3, "the exported path has three levels");
    checkU64(r.path[0].leafSize, 0x200000ULL, "the leaf is 2 MiB");
}

// ---------------------------------------------------------------------------
// A. a range that CROSSES a leaf boundary
// ---------------------------------------------------------------------------
//
// This is the case round 11 got wrong: it exported the first page's path and
// claimed the whole range. The walker must now export BOTH leaves, and each
// path must be complete (root to leaf).
static void testCrossesLeafBoundary() {
    PageTable pt;
    unsigned long long cursor = 0x1000;

    // Two adjacent 2 MiB leaves in the SAME L2 table.
    const unsigned long long leafA = 0x20000000ULL;      // 2 MiB aligned
    const unsigned long long leafB = leafA + 0x200000ULL;
    const unsigned long long l3 = pt.base + cursor; cursor += 4096;
    const unsigned long long l2 = pt.base + cursor; cursor += 4096;
    const amdpte::u64 perms = amdpte::PTE_IR | amdpte::PTE_IW;
    pt.write(pt.base, amdpte::indexAt(4, leafA),
             amdpte::makeTablePde(3, l3, perms));
    pt.write(l3, amdpte::indexAt(3, leafA),
             amdpte::makeTablePde(2, l2, perms));
    pt.write(l2, amdpte::indexAt(2, leafA),
             amdpte::makeDefaultLeaf(2, leafA, perms));
    pt.write(l2, amdpte::indexAt(2, leafB),
             amdpte::makeDefaultLeaf(2, leafB, perms));

    // Start 16 bytes before the boundary: 74 bytes straddles it.
    const unsigned long long addr = leafB - 16;
    amdbw::RangeResult r;
    amdbw::walkRange([&](unsigned long long t, unsigned i) { return pt.read(t, i); },
                     kRootLevel, pt.base, addr, 74, false, r);
    check(r.ok, "a range crossing a leaf boundary is covered when both leaves map");
    checkU64(r.leafCount, 2, "and BOTH leaves are exported");
    checkU64(r.path[0].coversBytes, 16, "the first leaf covers 16 bytes");
    checkU64(r.path[1].coversBytes, 58, "the second leaf covers the remaining 58");
    checkU64(r.bytesCovered, 74, "the two add up to the whole range");
    checkU64(r.path[0].leafPA, leafA, "the first exported leaf is the lower one");
    checkU64(r.path[1].leafPA, leafB, "the second exported leaf is the upper one");
    check(r.path[0].depth == 3 && r.path[1].depth == 3,
          "both paths are complete, not just the first");
}

// ---------------------------------------------------------------------------
// B. a range that crosses into an UNMAPPED leaf
// ---------------------------------------------------------------------------
//
// The first leaf maps; the second does not. The range is not covered, and the
// reason must be specific.
static void testCrossesIntoUnmapped() {
    PageTable pt;
    unsigned long long cursor = 0x1000;
    const unsigned long long leafA = 0x40000000ULL;
    const unsigned long long l3 = pt.base + cursor; cursor += 4096;
    const unsigned long long l2 = pt.base + cursor; cursor += 4096;
    const amdpte::u64 perms = amdpte::PTE_IR | amdpte::PTE_IW;
    pt.write(pt.base, amdpte::indexAt(4, leafA),
             amdpte::makeTablePde(3, l3, perms));
    pt.write(l3, amdpte::indexAt(3, leafA),
             amdpte::makeTablePde(2, l2, perms));
    pt.write(l2, amdpte::indexAt(2, leafA),
             amdpte::makeDefaultLeaf(2, leafA, perms));
    // leafA + 2 MiB deliberately left absent.

    const unsigned long long addr = leafA + 0x200000ULL - 16;
    amdbw::RangeResult r;
    amdbw::walkRange([&](unsigned long long t, unsigned i) { return pt.read(t, i); },
                     kRootLevel, pt.base, addr, 74, false, r);
    check(!r.ok, "a range crossing into an unmapped leaf is NOT covered");
    check(!r.covered, "and `covered` says so");
    check(r.why && std::strcmp(r.why, "range-not-fully-covered") == 0,
          "and the reason is the missing coverage, not something vague");
    checkU64(r.leafCount, 1, "only the mapped leaf is exported");
    checkU64(r.bytesCovered, 16, "and only its 16 bytes are claimed");
}

// ---------------------------------------------------------------------------
// C. the export budget is a RECORDED degradation
// ---------------------------------------------------------------------------
//
// A pathological length spans more leaves than the budget. Round 11 returned
// silently; the result must now be `capped`, not `ok`, and the reason must say
// so. This is the difference between "we proved part of it" and "we proved it".
static void testLeafBudgetIsRecorded() {
    PageTable pt;
    unsigned long long cursor = 0x1000;
    const unsigned long long base = 0x60000000ULL;
    const amdpte::u64 perms = amdpte::PTE_IR | amdpte::PTE_IW;
    const unsigned long long l3 = pt.base + cursor; cursor += 4096;
    pt.write(pt.base, amdpte::indexAt(4, base),
             amdpte::makeTablePde(3, l3, perms));
    // One L2 table per 1 GiB region is enough: map 8 consecutive 2 MiB leaves.
    const unsigned long long l2 = pt.base + cursor; cursor += 4096;
    pt.write(l3, amdpte::indexAt(3, base),
             amdpte::makeTablePde(2, l2, perms));
    for (unsigned i = 0; i < 8; i++) {
        const unsigned long long leaf = base + (unsigned long long)i * 0x200000ULL;
        pt.write(l2, amdpte::indexAt(2, leaf),
                 amdpte::makeDefaultLeaf(2, leaf, perms));
    }

    // 8 leaves' worth of bytes: more than kMaxLeaves.
    amdbw::RangeResult r;
    amdbw::walkRange([&](unsigned long long t, unsigned i) { return pt.read(t, i); },
                     kRootLevel, pt.base, base, 8u * 0x200000u, false, r);
    check(!r.ok, "a range beyond the leaf budget is NOT reported as covered");
    check(r.capped, "and the budget exhaustion is recorded");
    check(r.why && std::strcmp(r.why, "leaf-budget-exceeded") == 0,
          "with a reason that names the budget");
    checkU64(r.leafCount, amdbw::kMaxLeaves,
             "and it exports exactly as many leaves as it is allowed");
}

// ---------------------------------------------------------------------------
// D. permissions are checked at EVERY level, not just the leaf
// ---------------------------------------------------------------------------
static void testPermissionAtEveryLevel() {
    // TX needs IR on the leaf AND on both directory entries.
    struct Case { const char *name; bool dirPerms; bool leafPerms; bool isRx;
                  bool wantOk; };
    const Case cases[] = {
        {"TX, IR everywhere",            true,  true,  false, true},
        {"TX, leaf lacks IR",            true,  false, false, false},
        {"TX, directories lack IR",      false, true,  false, false},
        {"RX, IW everywhere",            true,  true,  true,  true},
        {"RX, leaf lacks IW",            true,  false, true,  false},
        {"RX, directories lack IW",      false, true,  true,  false},
    };
    for (const Case &c : cases) {
        PageTable pt;
        const unsigned long long addr = 0x30000000ULL + 0x1234;
        unsigned long long cursor = 0x1000;
        const unsigned long long l3 = pt.base + cursor; cursor += 4096;
        const unsigned long long l2 = pt.base + cursor; cursor += 4096;
        const amdpte::u64 dirBits = c.dirPerms
            ? (amdpte::PTE_IR | amdpte::PTE_IW) : 0u;
        const amdpte::u64 leafBits = c.leafPerms
            ? (amdpte::PTE_IR | amdpte::PTE_IW) : 0u;
        pt.write(pt.base, amdpte::indexAt(4, addr),
                 amdpte::makeTablePde(3, l3, dirBits));
        pt.write(l3, amdpte::indexAt(3, addr),
                 amdpte::makeTablePde(2, l2, dirBits));
        pt.write(l2, amdpte::indexAt(2, addr),
                 amdpte::makeDefaultLeaf(2, addr & ~0x1FFFFFULL, leafBits));

        amdbw::RangeResult r;
        amdbw::walkRange(
            [&](unsigned long long t, unsigned i) { return pt.read(t, i); },
            kRootLevel, pt.base, addr, 74, c.isRx, r);
        check(r.ok == c.wantOk, c.name);
        if (!c.wantOk && r.why) {
            check(std::strcmp(r.why, "permission-insufficient") == 0 ||
                  std::strcmp(r.why, "range-not-fully-covered") == 0,
                  "  the failure names a permission problem");
        }
    }
}

// ---------------------------------------------------------------------------
// E. overflow and null
// ---------------------------------------------------------------------------
static void testOverflowAndNull() {
    PageTable pt;
    buildIdentity(pt, 0x1000, 0x1F421F000ULL, true);

    amdbw::RangeResult r;
    amdbw::walkRange([&](unsigned long long t, unsigned i) { return pt.read(t, i); },
                     kRootLevel, pt.base, ~0ULL - 8, 74, false, r);
    check(!r.ok, "a range that wraps 64 bits is not covered");
    check(r.overflow, "and the overflow is recorded");

    amdbw::walkRange([&](unsigned long long t, unsigned i) { return pt.read(t, i); },
                     kRootLevel, pt.base, 0x1F421F000ULL, 0, false, r);
    check(!r.ok, "a zero-length range is not covered");

    amdbw::walkRange([&](unsigned long long t, unsigned i) { return pt.read(t, i); },
                     kRootLevel, pt.base, 0, 74, false, r);
    check(!r.ok, "a null address is not covered");
}

// ---------------------------------------------------------------------------
// F. an absent start is rejected with a specific reason
// ---------------------------------------------------------------------------
static void testAbsentStart() {
    PageTable pt;   // completely empty: every entry decodes as absent
    amdbw::RangeResult r;
    amdbw::walkRange([&](unsigned long long t, unsigned i) { return pt.read(t, i); },
                     kRootLevel, pt.base, 0x1F421F000ULL, 74, false, r);
    check(!r.ok, "an empty page table yields no coverage");
    check(r.badStart, "and the failure is attributed to the start");
    check(r.why && std::strcmp(r.why, "start-not-a-legal-leaf") == 0,
          "with the start-specific reason");
}

// ---------------------------------------------------------------------------
// G. a leaf that translates somewhere else is not evidence
// ---------------------------------------------------------------------------
static void testNonIdentityRejected() {
    PageTable pt;
    unsigned long long cursor = 0x1000;
    const unsigned long long addr = 0x1F421F000ULL;
    const amdpte::u64 perms = amdpte::PTE_IR | amdpte::PTE_IW;
    const unsigned long long l3 = pt.base + cursor; cursor += 4096;
    const unsigned long long l2 = pt.base + cursor; cursor += 4096;
    pt.write(pt.base, amdpte::indexAt(4, addr),
             amdpte::makeTablePde(3, l3, perms));
    pt.write(l3, amdpte::indexAt(3, addr),
             amdpte::makeTablePde(2, l2, perms));
    // Maps the SAME virtual address to a DIFFERENT physical leaf.
    pt.write(l2, amdpte::indexAt(2, addr),
             amdpte::makeDefaultLeaf(2, 0x80000000ULL, perms));

    amdbw::RangeResult r;
    amdbw::walkRange([&](unsigned long long t, unsigned i) { return pt.read(t, i); },
                     kRootLevel, pt.base, addr, 74, false, r);
    check(!r.ok, "a non-identity mapping is not evidence about the address");
    check(r.why && std::strcmp(r.why, "not-an-identity-mapping") == 0,
          "and the reason says so");
}

// ---------------------------------------------------------------------------
// H. every exported level is usable by an independent decoder
// ---------------------------------------------------------------------------
//
// The analyser re-derives the chain from the exported (table, index, level,
// pte) tuples. If the walker's export were self-consistent but not
// independently checkable, that would be a claim rather than evidence. So the
// test re-walks the exported chain itself, using ONLY those tuples.
static void testExportedChainIsSelfChecking() {
    PageTable pt;
    const unsigned long long addr = 0x3D8DD77B6ULL;
    buildIdentity(pt, 0x1000, addr, true);

    amdbw::RangeResult r;
    amdbw::walkRange([&](unsigned long long t, unsigned i) { return pt.read(t, i); },
                     kRootLevel, pt.base, addr, 74, false, r);
    check(r.ok, "the range is covered");
    if (!r.ok) return;

    const amdbw::Path &p = r.path[0];
    bool links = true;
    unsigned long long expectTable = pt.base;
    unsigned expectLevel = kRootLevel;
    for (unsigned L = 0; L < p.depth; L++) {
        if (p.table[L] != expectTable) links = false;
        if (p.level[L] != expectLevel) links = false;
        if (p.index[L] != amdpte::indexAt(expectLevel, addr)) links = false;
        const amdpte::DecodedPte d = amdpte::decodePte(p.pte[L], expectLevel);
        if (d.kind == amdpte::PTE_TABLE) {
            expectTable = d.outPA;
            expectLevel = d.childLevel;
        } else if (d.kind == amdpte::PTE_LEAF_DEFAULT ||
                   d.kind == amdpte::PTE_LEAF_LARGE) {
            if (L != p.depth - 1) links = false;
            if (d.outPA != p.leafPA || d.pageSize != p.leafSize) links = false;
            if (!(d.outPA <= addr && addr < d.outPA + d.pageSize)) links = false;
        } else {
            links = false;
        }
    }
    check(links, "the exported chain re-derives from its own raw PTEs");
}

int main() {
    std::printf("business-range walk core tests\n");
    std::printf("==============================\n");
    testSingleLeaf();
    testCrossesLeafBoundary();
    testCrossesIntoUnmapped();
    testLeafBudgetIsRecorded();
    testPermissionAtEveryLevel();
    testOverflowAndNull();
    testAbsentStart();
    testNonIdentityRejected();
    testExportedChainIsSelfChecking();
    std::printf("\n%d passed, %d failed\n", gPass, gFail);
    if (gFail == 0) {
        std::printf("RESULT: ALL CHECKS PASS\n");
        return 0;
    }
    std::printf("RESULT: FAILURES\n");
    return 1;
}
