// Append leaf tables and a new L2 directory when the mapper crosses 1 GiB.
// The root, existing upper-level tables and existing leaf pages never move.
#pragma once
#include "amd_iommu_sparse_core.hpp"

namespace amdtable {
typedef amdpte::u64 u64;

// The root and L3 remain in the initial buffer. The 2 GiB mapper window uses
// two adjacent L3 entries, so locating their parent needs no page-bank lookup.
inline volatile u64 *leafDirectoryParent(amdsparse::Arena &rootArena, u64 iova) {
    if (rootArena.rootLevel != 3 && rootArena.rootLevel != 4) return nullptr;
    u64 pa = rootArena.rootPA;
    const u64 permissions = amdpte::PTE_IR | amdpte::PTE_IW;
    for (unsigned level = rootArena.rootLevel; level > 3; --level) {
        volatile u64 *parent = amdsparse::table(rootArena, pa);
        if (!parent) return nullptr;
        const u64 raw = parent[amdpte::indexAt(level, iova)];
        const amdpte::DecodedPte entry = amdpte::decodePte(raw, level);
        if (entry.kind != amdpte::PTE_TABLE || entry.childLevel != level - 1 ||
            (raw & permissions) != permissions) return nullptr;
        pa = entry.outPA;
    }
    return amdsparse::table(rootArena, pa);
}

struct PageTableGrowthPlan {
    volatile u64 *parentEntry;
    volatile u64 *directory;
    unsigned firstEntry, leafCount, tablePages;
};

// Each geometric increase stays within one L2 directory. The initial directory
// is in rootArena; the final increase adds a complete directory in a new block.
// Hold the mapper lock from planning through attachment and capacity commit.
inline bool planPageTableGrowth(amdsparse::Arena &rootArena, u64 firstIOVA,
                               unsigned leafCount, PageTableGrowthPlan &growth) {
    growth = {};
    const unsigned firstEntry = amdpte::indexAt(2, firstIOVA);
    if ((firstIOVA & 0x1fffffULL) || !leafCount || leafCount > 512 - firstEntry)
        return false;
    volatile u64 *parent = leafDirectoryParent(rootArena, firstIOVA);
    if (!parent) return false;
    volatile u64 *parentEntry = parent + amdpte::indexAt(3, firstIOVA);
    volatile u64 *directory = nullptr;
    const u64 raw = *parentEntry;
    if (raw) {
        const auto entry = amdpte::decodePte(raw, 3);
        const u64 permissions = amdpte::PTE_IR | amdpte::PTE_IW;
        if (entry.kind != amdpte::PTE_TABLE || entry.childLevel != 2 ||
                (raw & permissions) != permissions) return false;
        directory = amdsparse::table(rootArena, entry.outPA);
        if (!directory) return false;
        for (unsigned i = 0; i < leafCount; ++i)
            if (directory[firstEntry + i]) return false;
    }
    growth = {parentEntry, directory, firstEntry, leafCount,
              leafCount + (directory ? 0U : 1U)};
    return true;
}

// The caller allocates growth.tablePages and passes the first new leaf-pointer
// slot, not the start of the complete array. A new directory occupies the first
// page of the block; publish its L3 link only after every child PDE is prepared.
// After success, retain the block and confirm hardware synchronization before
// exposing the newly covered IOVA range.
inline bool attachPageTables(const PageTableGrowthPlan &growth,
                            volatile u64 *newTables, u64 newTablePA,
                            volatile u64 **newLeafPointers) {
    const unsigned directoryPages = growth.directory ? 0U : 1U;
    if (!growth.parentEntry || !newTables || !newLeafPointers || !newTablePA ||
            (newTablePA & 4095ULL) || !growth.leafCount || growth.firstEntry >= 512 ||
            growth.leafCount > 512 - growth.firstEntry ||
            growth.tablePages != growth.leafCount + directoryPages) return false;
    for (unsigned i = 0; i < growth.tablePages * 512; ++i) newTables[i] = 0;
    volatile u64 *directory = growth.directory ? growth.directory : newTables;
    const u64 permissions = amdpte::PTE_IR | amdpte::PTE_IW;
    for (unsigned i = 0; i < growth.leafCount; ++i) {
        const unsigned page = directoryPages + i;
        newLeafPointers[i] = newTables + page * 512;
        directory[growth.firstEntry + i] = amdpte::makeTablePde(
            1, newTablePA + (u64)page * 4096, permissions);
    }
    if (!growth.directory)
        *growth.parentEntry = amdpte::makeTablePde(2, newTablePA, permissions);
    return true;
}
}  // namespace amdtable
