// Host regression tests for the AMD-Vi page-table encoding core.
//
// These tests include probe/amd_iommu_pte_core.hpp -- THE SAME FILE the
// production kext includes -- and call its real functions. They are not a
// Python restatement of the logic: if a test here passes, the code that runs
// on the machine took the same branch.
//
// Build (host, not kernel):
//     clang++ -std=c++17 -O2 -Wall -Wextra -Werror -o pte-core-test \
//         tests/pte-core-test.cpp
//
// Expected values below are derived from:
//   * AMD IOMMU Spec 48882 Rev 3.10, section 2.2.3 (pp. 79-87) and Table 17
//   * Linux v6.6 drivers/iommu/amd/io_pgtable.c iommu_v1_map_pages()
//   * Linux v6.6 drivers/iommu/amd/amd_iommu_types.h PAGE_SIZE_* macros
// and are written out literally here, not computed by the code under test.

#include "../probe/amd_iommu_pte_core.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace amdpte;

static int g_pass = 0;
static int g_fail = 0;

static void check(bool cond, const char *what) {
    if (cond) {
        g_pass++;
    } else {
        g_fail++;
        std::printf("  FAIL: %s\n", what);
    }
}

static void checkEqU64(u64 got, u64 want, const char *what) {
    if (got == want) {
        g_pass++;
    } else {
        g_fail++;
        std::printf("  FAIL: %s (got 0x%llx, want 0x%llx)\n", what,
                    (unsigned long long)got, (unsigned long long)want);
    }
}

static void section(const char *name) {
    std::printf("\n%s\n%s\n", name, std::string(74, '-').c_str());
}

// ---------------------------------------------------------------------------
// A flat memory image standing in for the probe's contiguous page-table
// allocation: `pages` 4 KiB pages starting at PA 0x2fbc0000, exactly as the
// live machine reported (m2-b2-dump-root-pa = 0x2fbc0000, 19 pages).
// ---------------------------------------------------------------------------
struct TableImage {
    static const u64 kBasePA = 0x2fbc0000ULL;
    static const unsigned kPageSize = 0x1000;

    std::vector<u64> mem;   // kPageSize/8 qwords per page

    explicit TableImage(unsigned pages) : mem(pages * (kPageSize / 8), 0) {}

    u64 *page(unsigned idx) { return &mem[idx * (kPageSize / 8)]; }

    static u64 paOf(unsigned pageIdx) { return kBasePA + (u64)pageIdx * kPageSize; }

    static unsigned pageOf(u64 pa) { return (unsigned)((pa - kBasePA) / kPageSize); }

    u64 read(u64 tablePA, unsigned index) {
        return page(pageOf(tablePA))[index];
    }

    // Bounds-safe reader used by the walker: out-of-image reads return 0.
    bool inImage(u64 pa) const {
        return pa >= kBasePA && pa < kBasePA + mem.size() * 8;
    }
};

// Build the 4-level identity map the probe builds, with a selectable leaf
// encoding so the same builder can produce both the round-4 (wrong) and the
// corrected tables.
//
// Layout, matching the live export:
//   page 0      root  (level 4)
//   page 1..16  L3    (level 3, one per 1 GiB region)
//   page 17..   L2    (level 2, one per 1 GiB region; holds the 2 MiB leaves)
enum LeafMode {
    LEAF_ROUND4_BUG,   // NextLevel=7 + size bits (the shipped defect)
    LEAF_CORRECT       // NextLevel=0, default 2 MiB for a level-2 table
};

static const u64 kIdentityLimit = 0x400000000ULL;   // 16 GiB
static const u64 kTwoMiB = 0x200000ULL;
static const u64 kPerms = PTE_IR | PTE_IW;

static void buildIdentity2M(TableImage &t, LeafMode mode) {
    // page 0 = root(4); page 1 = L3(3); page 2..17 = L2(2), one per 1 GiB
    const unsigned rootPage = 0;
    const unsigned l3Page = 1;
    const unsigned l2Base = 2;

    // root[0] -> L3 table
    t.page(rootPage)[0] = makeTablePde(3, TableImage::paOf(l3Page), kPerms);

    for (unsigned gb = 0; gb < 16; gb++) {
        // L3[gb] -> L2 table for this 1 GiB
        t.page(l3Page)[gb] =
            makeTablePde(2, TableImage::paOf(l2Base + gb), kPerms);

        u64 *l2 = t.page(l2Base + gb);
        for (unsigned i = 0; i < 512; i++) {
            const u64 pa = ((u64)gb << 30) + ((u64)i << 21);
            if (mode == LEAF_ROUND4_BUG) {
                // The exact shipped expression: unconditional PAGE_SIZE_PTE
                // plus PM_LEVEL_ENC(7).
                l2[i] = makeLargeLeaf(pa, kTwoMiB, kPerms);
            } else {
                l2[i] = makeDefaultLeaf(2, pa, kPerms);
            }
        }
    }
}

// ---------------------------------------------------------------------------

static void test1_round4_leaf_rejected() {
    section("1. The round-4 exported leaf, placed at level 2, MUST be rejected");

    // The literal value the probe exported on the live machine:
    //   m2-b2-dump0-leaf = 0x70000003844ffe01
    const u64 shipped = 0x70000003844ffe01ULL;

    const DecodedPte d = decodePte(shipped, 2);
    check(d.kind == PTE_ILLEGAL, "shipped leaf decodes as ILLEGAL at level 2");
    checkEqU64(d.pageSize, kTwoMiB, "its size bits do decode to 2 MiB");
    if (d.reason) std::printf("  reason: %s\n", d.reason);

    // It must NOT be silently accepted as a valid 2 MiB leaf.
    check(d.kind != PTE_LEAF_LARGE, "not accepted as a legal enlarged leaf");
    check(d.kind != PTE_LEAF_DEFAULT, "not accepted as a default leaf");

    // And it is illegal at level 1 too. This is worth stating precisely,
    // because it is NOT the naive "NextLevel=7 is fine for a bigger page"
    // intuition: 2 MiB enlarged needs
    //     default(1) < 2 MiB < default(2)
    // i.e. 4 KiB < 2 MiB < 2 MiB, which is false. 2 MiB is exactly the level-2
    // default, so NextLevel=7 can never spell it. There is exactly one legal
    // encoding of a 2 MiB page and it is NextLevel=0 in a level-2 table.
    const DecodedPte d1 = decodePte(shipped, 1);
    check(d1.kind == PTE_ILLEGAL, "the same PTE is ALSO illegal at level 1");
    checkEqU64(d1.pageSize, kTwoMiB, "still decodes to a 2 MiB size field");

    // The only legal way to write 2 MiB:
    check(decodePte(makeDefaultLeaf(2, 0x384400000ULL, kPerms), 2).kind ==
              PTE_LEAF_DEFAULT,
          "NextLevel=0 in a level-2 table is the sole legal 2 MiB encoding");
}

static void test2_corrected_leaf_accepted() {
    section("2. The corrected leaf at level 2 passes as a default 2 MiB map");

    const u64 fixed = 0x7000000384400001ULL;
    const DecodedPte d = decodePte(fixed, 2);
    check(d.kind == PTE_LEAF_DEFAULT, "decodes as a default-size leaf");
    checkEqU64(d.pageSize, kTwoMiB, "page size is 2 MiB");
    checkEqU64(d.outPA, 0x384400000ULL, "output page base is 0x384400000");
    checkEqU64(d.pteCount, 1, "occupies exactly one PTE (no replication)");

    // The builder must produce exactly this value.
    checkEqU64(makeDefaultLeaf(2, 0x384400000ULL, kPerms), fixed,
               "makeDefaultLeaf(2, 0x384400000) == the corrected value");

    // And the old builder is the thing that produced the bad value.
    checkEqU64(makeLargeLeaf(0x384400000ULL, kTwoMiB, kPerms), 0x70000003844ffe01ULL,
               "makeLargeLeaf(2 MiB) reproduces the shipped bad value");

    // Linux takes the count==1 branch for 2 MiB, which has no PM_LEVEL_ENC.
    checkEqU64(pageSizePteCount(kTwoMiB), 1,
               "PAGE_SIZE_PTE_COUNT(2 MiB) == 1 -> Linux count==1 branch");
    checkEqU64(pageSizePteCount(1ULL << 30), 1,
               "PAGE_SIZE_PTE_COUNT(1 GiB) == 1 -> also a default leaf");
}

static void test3_level1_4k_leaf() {
    section("3. A level-1 default leaf is 4 KiB and stays correct");

    const u64 pte = makeDefaultLeaf(1, 0x12345000ULL, kPerms);
    const DecodedPte d = decodePte(pte, 1);
    check(d.kind == PTE_LEAF_DEFAULT, "decodes as default leaf");
    checkEqU64(d.pageSize, 0x1000, "page size is 4 KiB");
    checkEqU64(d.outPA, 0x12345000ULL, "output page base preserved");

    // NextLevel must be 0 -- a 4 KiB leaf written as level 7 would be wrong.
    checkEqU64(nextLevelOf(pte), 0, "NextLevel == 0");

    // PR and FC present, no NextLevel bits set anywhere.
    check((pte & PTE_PR) != 0, "PR set");
    check((pte & PTE_FC) != 0, "FC set on the leaf");
    checkEqU64(pte & 0xE00ULL, 0, "no NextLevel bits");

    // A 4 KiB leaf sitting in a level-2 table is NOT a 4 KiB map -- it is a
    // 2 MiB map. Getting this wrong is the whole class of bug.
    const DecodedPte d2 = decodePte(pte, 2);
    checkEqU64(d2.pageSize, kTwoMiB,
               "the same PTE in a level-2 table means 2 MiB, not 4 KiB");
}

static void test4_extended_size_count_gt_1() {
    section("4. A genuine count>1 enlarged size (offline only)");

    // Spec 48882 Rev 3.10 p. 81, Software Note, uses exactly this example:
    // "if the physical page is 32 Kbytes ... the PTE must be repeated 8 times".
    const u64 ps32K = 0x8000ULL;
    checkEqU64(pageSizePteCount(ps32K), 8,
               "PAGE_SIZE_PTE_COUNT(32 KiB) == 8, matching the spec example");
    checkEqU64(pageSizeLevel(ps32K), 1, "32 KiB belongs at level 1");

    const u64 leaf = makeLargeLeaf(0x10000000ULL, ps32K, kPerms);
    const DecodedPte d = decodePte(leaf, 1);
    check(d.kind == PTE_LEAF_LARGE, "decodes as enlarged leaf");
    checkEqU64(d.pageSize, ps32K, "page size is 32 KiB");
    checkEqU64(d.pteCount, 8, "replication count is 8");
    checkEqU64(d.outPA, 0x10000000ULL, "output base preserved");

    // A 4 MiB enlarged page at level 2 is legal (default 2 MiB, next level
    // 1 GiB) and needs 2 PTEs.
    const u64 ps4M = 0x400000ULL;
    checkEqU64(pageSizePteCount(ps4M), 2, "PAGE_SIZE_PTE_COUNT(4 MiB) == 2");
    const DecodedPte d4 = decodePte(makeLargeLeaf(0x80000000ULL, ps4M, kPerms), 2);
    check(d4.kind == PTE_LEAF_LARGE, "4 MiB at level 2 is legal");
    checkEqU64(d4.pteCount, 2, "needs 2 replicated PTEs");

    // But 2 MiB at level 2 is NOT legal as an enlarged page, and 1 GiB at
    // level 2 is not either (that is the next level's default).
    check(decodePte(makeLargeLeaf(0, kTwoMiB, kPerms), 2).kind == PTE_ILLEGAL,
          "2 MiB enlarged at level 2 rejected");
    check(decodePte(makeLargeLeaf(0, 1ULL << 30, kPerms), 2).kind == PTE_ILLEGAL,
          "1 GiB enlarged at level 2 rejected (use level 3)");
}

static void test5_boundaries() {
    section("5. Offsets, page boundaries, 2 MiB boundaries, end of range");

    TableImage t(19);
    buildIdentity2M(t, LEAF_CORRECT);

    auto read = [&](u64 pa, unsigned idx) -> u64 {
        if (!t.inImage(pa)) return 0;
        return t.read(pa, idx);
    };

    struct Case { u64 iova; const char *why; };
    const Case cases[] = {
        {0x0ULL,                "start of the map"},
        {0x1ULL,                "byte 1 (offset inside the first 2 MiB page)"},
        {0xFFFULL,              "last byte of the first 4 KiB"},
        {0x1000ULL,             "second 4 KiB inside the same 2 MiB page"},
        {0x1FFFFFULL,           "last byte of the first 2 MiB page"},
        {0x200000ULL,           "first byte of the second 2 MiB page"},
        {0x3FFFFFULL,           "last byte of the second 2 MiB page"},
        {0x40000000ULL,         "1 GiB boundary"},
        {0x100000000ULL,        "4 GiB boundary"},
        {0x200000000ULL,        "8 GiB boundary"},
        {0x3FFE00000ULL,        "last 2 MiB page of the map"},
        {0x3FFFFFFF0ULL,        "16 GiB minus 16"},
        {kIdentityLimit - 1,    "the very last byte below the 16 GiB limit"},
    };

    for (const Case &c : cases) {
        const WalkResult r = walkPageTable(read, 4, TableImage::kBasePA, c.iova);
        if (!r.ok) {
            g_fail++;
            std::printf("  FAIL: walk at 0x%llx (%s): %s\n",
                        (unsigned long long)c.iova, c.why,
                        r.reason ? r.reason : "?");
            continue;
        }
        if (r.outPA != c.iova) {
            g_fail++;
            std::printf("  FAIL: 0x%llx -> 0x%llx not identity (%s)\n",
                        (unsigned long long)c.iova,
                        (unsigned long long)r.outPA, c.why);
            continue;
        }
        g_pass++;
        checkEqU64(r.pageSize, kTwoMiB, "leaf page size is 2 MiB");
        checkEqU64(r.depth, 3, "walk depth is root->L3->L2");
    }

    // One past the limit: the table does not map it.
    const WalkResult over =
        walkPageTable(read, 4, TableImage::kBasePA, kIdentityLimit);
    check(!over.ok, "16 GiB itself is not mapped");

    // The page-table allocation is only 19 pages = 76 KiB, yet it maps
    // 16 GiB. Stating that distinction explicitly.
    check(t.mem.size() * 8 == 19 * 4096, "table image is 19 pages (76 KiB)");
    check(kIdentityLimit / kTwoMiB == 8192, "8192 leaf PTEs describe 16 GiB");
}

static void test6_bad_tables_never_report_ok() {
    section("6. Missing paths, illegal levels, incompatible sizes are never OK");

    // (a) absent root entry
    {
        TableImage t(19);
        buildIdentity2M(t, LEAF_CORRECT);
        t.page(0)[0] = 0;
        auto read = [&](u64 pa, unsigned idx) -> u64 {
            if (!t.inImage(pa)) return 0;
            return t.read(pa, idx);
        };
        const WalkResult r = walkPageTable(read, 4, TableImage::kBasePA, 0x1000);
        check(!r.ok, "absent root entry -> not ok");
        check(r.absent, "reported as absent");
    }

    // (b) absent intermediate entry
    {
        TableImage t(19);
        buildIdentity2M(t, LEAF_CORRECT);
        t.page(1)[3] = 0;   // L3 entry for the 3..4 GiB region
        auto read = [&](u64 pa, unsigned idx) -> u64 {
            if (!t.inImage(pa)) return 0;
            return t.read(pa, idx);
        };
        const WalkResult r =
            walkPageTable(read, 4, TableImage::kBasePA, 0xC0000000ULL);
        check(!r.ok, "absent L3 entry -> not ok");
        check(r.absent, "reported as absent");
    }

    // (c) level skipping: root points straight at an L2 table (NextLevel=2
    //     from a level-4 table)
    {
        TableImage t(19);
        buildIdentity2M(t, LEAF_CORRECT);
        t.page(0)[0] = makeTablePde(2, TableImage::paOf(2), kPerms);
        auto read = [&](u64 pa, unsigned idx) -> u64 {
            if (!t.inImage(pa)) return 0;
            return t.read(pa, idx);
        };
        const WalkResult r = walkPageTable(read, 4, TableImage::kBasePA, 0x1000);
        check(!r.ok, "level skipping -> not ok");
        check(r.illegal, "reported as illegal");
    }

    // (d) the shipped bad leaf inside a full table: the walk must report
    //     illegal, not a successful translation.
    {
        TableImage t(19);
        buildIdentity2M(t, LEAF_ROUND4_BUG);
        auto read = [&](u64 pa, unsigned idx) -> u64 {
            if (!t.inImage(pa)) return 0;
            return t.read(pa, idx);
        };
        const WalkResult r =
            walkPageTable(read, 4, TableImage::kBasePA, 0x384514000ULL);
        check(!r.ok, "round-4 table does NOT walk successfully");
        check(r.illegal, "reported as an illegal encoding");
        std::printf("  round-4 table, walk at 0x384514000 -> %s\n",
                    r.reason ? r.reason : "?");
    }

    // (e) the corrected table DOES walk successfully at the same address.
    {
        TableImage t(19);
        buildIdentity2M(t, LEAF_CORRECT);
        auto read = [&](u64 pa, unsigned idx) -> u64 {
            if (!t.inImage(pa)) return 0;
            return t.read(pa, idx);
        };
        const WalkResult r =
            walkPageTable(read, 4, TableImage::kBasePA, 0x384514000ULL);
        check(r.ok, "corrected table walks successfully at 0x384514000");
        checkEqU64(r.outPA, 0x384514000ULL, "identity translation");
        checkEqU64(r.pageSize, kTwoMiB, "2 MiB page");
    }

    // (f) root level out of range
    {
        TableImage t(19);
        buildIdentity2M(t, LEAF_CORRECT);
        auto read = [&](u64 pa, unsigned idx) -> u64 {
            if (!t.inImage(pa)) return 0;
            return t.read(pa, idx);
        };
        check(!walkPageTable(read, 0, TableImage::kBasePA, 0).ok,
              "root level 0 -> not ok");
        check(!walkPageTable(read, 7, TableImage::kBasePA, 0).ok,
              "root level 7 -> not ok");
    }
}

static void test7_encoding_matches_live_export() {
    section("7. Re-encode the live exported PDEs bit-for-bit");

    // Values read back from the running machine (evidence 20261031-165500):
    //   m2-b2-dump-root0 = 0x600000002fbc1601
    //   m2-b2-dump0-l2   = 0x600000002fbd0401
    //   m2-b2-dump0-leaf = 0x70000003844ffe01   <- the defect
    const u64 liveRoot0 = 0x600000002fbc1601ULL;
    const u64 liveL2 = 0x600000002fbd0401ULL;
    const u64 liveLeaf = 0x70000003844ffe01ULL;

    checkEqU64(makeTablePde(3, 0x2fbc1000ULL, kPerms), liveRoot0,
               "root[0] reproduces exactly");
    checkEqU64(makeTablePde(2, 0x2fbd0000ULL, kPerms), liveL2,
               "L2[0] reproduces exactly");

    // The PDEs decode correctly at their own levels -- the defect was ONLY
    // in the leaf, which is why a level-blind decoder passed them.
    check(decodePte(liveRoot0, 4).kind == PTE_TABLE, "root[0] is a table PDE");
    checkEqU64(decodePte(liveRoot0, 4).childLevel, 3, "root[0] -> level 3");
    check(decodePte(liveL2, 3).kind == PTE_TABLE, "L2[0] is a table PDE");
    checkEqU64(decodePte(liveL2, 3).childLevel, 2, "L2[0] -> level 2");

    // The leaf, at its true level, is illegal. It is illegal at EVERY level:
    // 2 MiB enlarged requires default(level) < 2 MiB < default(level+1), and
    // the only level where the lower bound holds is level 1 (4 KiB), where the
    // upper bound then fails because 2 MiB == default(2).
    check(decodePte(liveLeaf, 2).kind == PTE_ILLEGAL,
          "live leaf is illegal at level 2");
    check(decodePte(liveLeaf, 1).kind == PTE_ILLEGAL,
          "live leaf is illegal at level 1 too");

    // What it should have been.
    const u64 fixed = makeDefaultLeaf(2, liveLeaf & PM_ADDR_MASK & ~(kTwoMiB - 1),
                                      kPerms);
    checkEqU64(fixed, 0x7000000384400001ULL,
               "corrected leaf == 0x7000000384400001");
}

static void test8_spec_level_table() {
    section("8. Level numbering agrees with spec Table 15");

    checkEqU64(defaultPageSize(1), 0x1000ULL, "level 1 default = 4 KiB");
    checkEqU64(defaultPageSize(2), 0x200000ULL, "level 2 default = 2 MiB");
    checkEqU64(defaultPageSize(3), 1ULL << 30, "level 3 default = 1 GiB");
    checkEqU64(defaultPageSize(4), 1ULL << 39, "level 4 default = 512 GiB");

    // Index bit positions: level 1 uses VA bits 20:12, level 2 uses 29:21.
    checkEqU64(indexShift(1), 12, "level 1 index shift = 12");
    checkEqU64(indexShift(2), 21, "level 2 index shift = 21");
    checkEqU64(indexShift(3), 30, "level 3 index shift = 30");
    checkEqU64(indexShift(4), 39, "level 4 index shift = 39");

    // A Mode=4 DTE has a level-4 root.
    checkEqU64(levelOfDefaultPageSize(1ULL << 39), 4,
               "512 GiB <-> level 4 (Mode=4 root)");

    // NextLevel encoding of a PDE stored in a level-N table is N-1.
    checkEqU64(nextLevelOf(makeTablePde(3, 0, 0)), 3, "PDE -> level 3 encodes 3");
    checkEqU64(nextLevelOf(makeTablePde(2, 0, 0)), 2, "PDE -> level 2 encodes 2");
}

int main() {
    std::printf("AMD-Vi page-table encoding core -- host regression\n");
    std::printf("==================================================\n");
    std::printf("Testing probe/amd_iommu_pte_core.hpp (production code)\n");

    test1_round4_leaf_rejected();
    test2_corrected_leaf_accepted();
    test3_level1_4k_leaf();
    test4_extended_size_count_gt_1();
    test5_boundaries();
    test6_bad_tables_never_report_ok();
    test7_encoding_matches_live_export();
    test8_spec_level_table();

    std::printf("\n==================================================\n");
    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    if (g_fail) {
        std::printf("RESULT: FAIL\n");
        return 1;
    }
    std::printf("RESULT: ALL CHECKS PASS\n");
    return 0;
}
