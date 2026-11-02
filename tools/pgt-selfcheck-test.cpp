// pgt-selfcheck-test.cpp — 离线验证 M2-2b-2 页表构建与自检逻辑。
//
// 为什么需要这个测试：
//   探针里的「页表自检」如果永远返回 ok，那它就是一个假的保险丝。
//   这段代码在离线环境里复制探针的构建 + 走表逻辑，并**故意注入错误**，
//   确认自检能报 FAIL。只有注入错误时能失败，真实运行时报的 ok 才有意义。
//
// 编译（Mac 或任意带 clang 的机器）：
//   clang++ -std=c++17 -O1 -o pgt-selfcheck-test pgt-selfcheck-test.cpp
//
// 这个文件不参与 kext 构建，只是验证工具。

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

using UInt64 = uint64_t;
using UInt32 = uint32_t;
using UInt8  = uint8_t;

// ---- 与探针完全相同的常量 ----
#define M2B2_PAGE_MODE_4_LEVEL  4
#define M2B2_PTE_COUNT          512
#define M2B2_PAGE_SIZE          0x1000ULL
#define M2B2_LARGE_PAGE         0x200000ULL
#define M2B2_IDENTITY_LIMIT     0x400000000ULL
#define M2B2_LEAF_PAGES         (M2B2_IDENTITY_LIMIT / (1ULL << 30))   // 16
#define M2B2_L2_PAGES           1
#define M2B2_ROOT_PAGES         1
#define M2B2_TOTAL_PAGES        (M2B2_ROOT_PAGES + M2B2_L2_PAGES + M2B2_LEAF_PAGES)

#define M2B2_PTE_PR             (1ULL << 0)
#define M2B2_PTE_FC             (1ULL << 60)
#define M2B2_PTE_IR             (1ULL << 61)
#define M2B2_PTE_IW             (1ULL << 62)
#define M2B2_PTE_ADDR_MASK      0x000FFFFFFFFFF000ULL
#define M2B2_LEVEL_ENC(x)       (((UInt64)(x) << 9) & 0xE00ULL)
#define M2B2_LEVEL_7            7ULL

static inline UInt64 m2b2LargeLeaf(UInt64 pa) {
    UInt64 pte = (pa | (M2B2_LARGE_PAGE - 1)) &
                 ~(M2B2_LARGE_PAGE >> 1) &
                 M2B2_PTE_ADDR_MASK;
    return pte | M2B2_LEVEL_ENC(M2B2_LEVEL_7) |
           M2B2_PTE_PR | M2B2_PTE_FC | M2B2_PTE_IR | M2B2_PTE_IW;
}

static inline UInt64 m2b2TablePte(UInt64 level, UInt64 pa) {
    return (pa & M2B2_PTE_ADDR_MASK) | M2B2_LEVEL_ENC(level) |
           M2B2_PTE_PR | M2B2_PTE_FC | M2B2_PTE_IR | M2B2_PTE_IW;
}

// ---- 构建页表。mutation 用来注入错误 ----
enum Mutation {
    MUT_NONE = 0,
    MUT_BAD_LEAF_LEVEL,   // 叶子写成 NEXT_LEVEL=0（会被当成指向下一级表）
    MUT_LEAF_NOT_PRESENT, // 某个叶子 PR=0
    MUT_BAD_OA,           // 叶子输出地址算错（非恒等）
    MUT_L2_LEVEL,         // L2 项 NEXT_LEVEL 写错
    MUT_ROOT_MISSING,     // 根表项没写
    MUT_NO_SIZE_BIT,      // 叶子漏掉大页大小编码（bit20）
    MUT_NO_PERMS,         // 叶子缺 IR/IW 权限位
    MUT_L2_MISSING,       // L2 表项没写
    MUT_NO_FC,            // 叶子缺 FC（force-coherent）——真实踩过的坑
};

static void build(std::vector<UInt64> &pt, UInt64 ptPA, Mutation mut) {
    pt.assign(M2B2_TOTAL_PAGES * M2B2_PTE_COUNT, 0);

    UInt64 rootPageIdx = 0;
    UInt64 l2PageBase = rootPageIdx + M2B2_ROOT_PAGES;
    UInt64 leafPageBase = l2PageBase + M2B2_L2_PAGES;

    UInt64 rootPA = ptPA + rootPageIdx * M2B2_PAGE_SIZE;
    UInt64 l2PA = ptPA + l2PageBase * M2B2_PAGE_SIZE;
    (void)rootPA;

    UInt64 *root = &pt[rootPageIdx * M2B2_PTE_COUNT];
    UInt64 *l2 = &pt[l2PageBase * M2B2_PTE_COUNT];

    if (mut != MUT_ROOT_MISSING) {
        UInt64 lvl = (mut == MUT_L2_LEVEL) ? 5 : 3;
        root[0] = m2b2TablePte(lvl, l2PA);
    }

    for (UInt32 gb = 0; gb < M2B2_LEAF_PAGES; gb++) {
        UInt64 leafPageIdx = leafPageBase + gb;
        UInt64 leafPA = ptPA + leafPageIdx * M2B2_PAGE_SIZE;
        UInt64 lvl2 = (mut == MUT_L2_LEVEL) ? 4 : 2;
        l2[gb] = m2b2TablePte(lvl2, leafPA);
        // 抽样的 i2 值只有 0、1、15（见 kSamples）。要让 l2-missing 真的被
        // 走到，必须清掉一个**会被抽样**的项，而不是随便一个。
        if (mut == MUT_L2_MISSING && gb == 0) l2[gb] = 0;

        UInt64 *leaf = &pt[leafPageIdx * M2B2_PTE_COUNT];
        UInt64 base1G = (UInt64)gb << 30;
        for (UInt32 i = 0; i < M2B2_PTE_COUNT; i++) {
            UInt64 pa = base1G + ((UInt64)i << 21);
            UInt64 pte;
            switch (mut) {
            case MUT_BAD_LEAF_LEVEL:
                // 去掉 NEXT_LEVEL=7，改成 0
                pte = m2b2LargeLeaf(pa) & ~M2B2_LEVEL_ENC(M2B2_LEVEL_7);
                break;
            case MUT_NO_SIZE_BIT:
                // 漏掉大页编码：不 OR (2MiB-1)
                pte = ((pa & M2B2_PTE_ADDR_MASK) | M2B2_LEVEL_ENC(7) |
                       M2B2_PTE_PR | M2B2_PTE_IR | M2B2_PTE_IW);
                break;
            case MUT_BAD_OA:
                // 输出地址偏移 2 MiB
                pte = m2b2LargeLeaf(pa + M2B2_LARGE_PAGE);
                break;
            case MUT_NO_PERMS:
                pte = m2b2LargeLeaf(pa) & ~(M2B2_PTE_IR | M2B2_PTE_IW);
                break;
            case MUT_NO_FC:
                pte = m2b2LargeLeaf(pa) & ~M2B2_PTE_FC;
                break;
            case MUT_LEAF_NOT_PRESENT:
                // 抽样里的 i1：0x0 和 0x200000 → i1=0；0x1FFFFF/0x3FFFFF
                // → i1=0；0x40000000 → i1=0。所以清 i=0 才能被走到。
                pte = (i == 0) ? 0 : m2b2LargeLeaf(pa);
                break;
            default:
                pte = m2b2LargeLeaf(pa);
                break;
            }
            leaf[i] = pte;
        }
    }
}

// 与探针 m2b2PtePageSize 完全一致
static inline UInt64 ptePageSize(UInt64 pte) {
    UInt64 x = pte | 0xFFFULL;
    UInt32 i = 0;
    while (i < 63 && ((x >> i) & 1ULL)) i++;
    return 1ULL << (1 + i);
}

// ---- 走表自检：与探针第 4 步逻辑一致 ----
// 注意这里用**物理地址**访问页表，因为离线环境下 ptPA 就是缓冲的地址。
// 探针里用 (pa - ptPA) 偏移换算，语义等价。
static bool walk(const std::vector<UInt64> &pt, UInt64 ptPA,
                 UInt64 iova, UInt64 *outPA, const char **why) {
    UInt64 ptBytes = M2B2_TOTAL_PAGES * M2B2_PAGE_SIZE;
    const UInt64 *base = pt.data();

    UInt32 i3 = (UInt32)((iova >> 39) & 0x1FF);
    UInt32 i2 = (UInt32)((iova >> 30) & 0x1FF);
    UInt32 i1 = (UInt32)((iova >> 21) & 0x1FF);

    const UInt64 *root = base;
    UInt64 pte3 = root[i3];
    if (!(pte3 & M2B2_PTE_PR)) { *why = "root-not-present"; return false; }

    UInt64 lvl3 = (pte3 >> 9) & 0x7ULL;
    if (lvl3 != 3) { *why = "root-level-mismatch"; return false; }

    UInt64 pa2 = pte3 & M2B2_PTE_ADDR_MASK;
    if (pa2 < ptPA || pa2 >= ptPA + ptBytes) { *why = "root-oa-out-of-range"; return false; }
    const UInt64 *l2 = (const UInt64 *)((const UInt8 *)base + (pa2 - ptPA));

    UInt64 pte2 = l2[i2];
    if (!(pte2 & M2B2_PTE_PR)) { *why = "l2-not-present"; return false; }
    UInt64 lvl2 = (pte2 >> 9) & 0x7ULL;
    if (lvl2 != 2) { *why = "l2-level-mismatch"; return false; }

    UInt64 pa1 = pte2 & M2B2_PTE_ADDR_MASK;
    if (pa1 < ptPA || pa1 >= ptPA + ptBytes) { *why = "l2-oa-out-of-range"; return false; }
    const UInt64 *leaf = (const UInt64 *)((const UInt8 *)base + (pa1 - ptPA));

    UInt64 pte1 = leaf[i1];
    if (!(pte1 & M2B2_PTE_PR)) { *why = "leaf-not-present"; return false; }
    UInt64 lvl1 = (pte1 >> 9) & 0x7ULL;
    if (lvl1 != M2B2_LEVEL_7) { *why = "leaf-level-not-7"; return false; }

    // 大小编码必须是 2 MiB，否则硬件按 4 KiB 解释
    if (ptePageSize(pte1) != M2B2_LARGE_PAGE) {
        *why = "leaf-wrong-page-size"; return false;
    }

    // 权限位
    if ((pte1 & (M2B2_PTE_IR | M2B2_PTE_IW)) != (M2B2_PTE_IR | M2B2_PTE_IW)) {
        *why = "leaf-missing-perms"; return false;
    }

    // FC（force-coherent）必须置位，否则硬件走表可能读到陈旧 PTE
    if (!(pte1 & M2B2_PTE_FC)) {
        *why = "leaf-missing-fc"; return false;
    }

    // 大页：输出地址必须 2 MiB 对齐且等于 IOVA 的 2 MiB 基址
    UInt64 got = (pte1 & M2B2_PTE_ADDR_MASK) & ~(M2B2_LARGE_PAGE - 1);
    UInt64 want = iova & ~(M2B2_LARGE_PAGE - 1);
    if (got != want) { *why = "oa-mismatch-not-identity"; return false; }

    *outPA = got;
    return true;
}

static const UInt64 kSamples[] = {
    0x0ULL, 0x1000ULL, 0x1FFFFFULL, 0x200000ULL,
    0x3FFFFFULL,
    0x40000000ULL,
    0x100000000ULL,
    0x200000000ULL,
    0x3C0000000ULL,
    0x3FFE00000ULL,
    0x3FFFFFFF0ULL,
};

static int runCase(const char *name, Mutation mut, bool expectOk) {
    std::vector<UInt64> pt;
    // 模拟一块"物理内存"：ptPA 用缓冲地址本身
    build(pt, 0, mut);   // 先建，拿到真实地址后重建
    UInt64 ptPA = (UInt64)(uintptr_t)pt.data();
    build(pt, ptPA, mut);

    UInt32 bad = 0;
    const char *firstWhy = "-";
    UInt64 firstBad = 0;
    for (UInt64 iova : kSamples) {
        UInt64 outPA = 0;
        const char *why = "-";
        if (!walk(pt, ptPA, iova, &outPA, &why)) {
            if (bad == 0) { firstWhy = why; firstBad = iova; }
            bad++;
        }
    }

    bool ok = (bad == 0);
    bool pass = (ok == expectOk);

    printf("%-24s expect=%-4s got=%-4s bad=%u/%zu  %s\n",
           name, expectOk ? "ok" : "FAIL", ok ? "ok" : "FAIL",
           bad, sizeof(kSamples) / sizeof(kSamples[0]),
           pass ? "PASS" : "*** TEST ITSELF WRONG ***");
    if (bad) printf("    first bad: iova=0x%llx why=%s\n",
                    (unsigned long long)firstBad, firstWhy);
    return pass ? 0 : 1;
}

int main() {
    int fails = 0;
    printf("== 页表布局 ==\n");
    printf("leaf pages  = %llu\n", (unsigned long long)M2B2_LEAF_PAGES);
    printf("total pages = %llu (%llu bytes)\n",
           (unsigned long long)M2B2_TOTAL_PAGES,
           (unsigned long long)(M2B2_TOTAL_PAGES * M2B2_PAGE_SIZE));
    printf("\n== 用例 ==\n");

    fails += runCase("correct-table",       MUT_NONE,             true);
    fails += runCase("bad-leaf-level",      MUT_BAD_LEAF_LEVEL,   false);
    fails += runCase("leaf-not-present",    MUT_LEAF_NOT_PRESENT, false);
    fails += runCase("bad-output-address",  MUT_BAD_OA,           false);
    fails += runCase("l2-level-wrong",      MUT_L2_LEVEL,         false);
    fails += runCase("root-missing",        MUT_ROOT_MISSING,     false);
    fails += runCase("no-size-bit",         MUT_NO_SIZE_BIT,      false);
    fails += runCase("no-perms",            MUT_NO_PERMS,         false);
    fails += runCase("l2-missing",          MUT_L2_MISSING,       false);
    fails += runCase("no-fc",               MUT_NO_FC,            false);

    printf("\n%s\n", fails == 0
        ? "RESULT: PASS — 自检对正确表放行、对 9 种错误全部报错。"
        : "RESULT: FAIL — 自检没能区分正确与错误。");
    return fails == 0 ? 0 : 1;
}
