// Append leaf tables and a new L2 directory when the mapper crosses 1 GiB.
// The root, existing upper-level tables and existing leaf pages never move.
#pragma once
#include "amd_iommu_sparse_core.hpp"

namespace amdtable {
typedef amdpte::u64 u64;

// Growth storage is physically contiguous within each block, not across the
// whole capacity increase. Bound each allocation to 64 KiB.
static constexpr unsigned kTableBlockPages = 16;

constexpr unsigned pageTableBlockCount(unsigned tablePages) {
    return (tablePages + kTableBlockPages - 1) / kTableBlockPages;
}

constexpr unsigned pageTableBlockPages(unsigned tablePages, unsigned blockIndex) {
    const unsigned firstPage = blockIndex * kTableBlockPages;
    const unsigned remaining = firstPage < tablePages ? tablePages - firstPage : 0;
    return remaining < kTableBlockPages ? remaining : kTableBlockPages;
}

struct PageTableBlock {
    volatile u64 *tables;
    u64 physicalBase;
    unsigned tablePages;
};

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
// is in rootArena; the final increase adds a complete directory and its leaves.
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

// Stage all bounded blocks before calling this helper, and pass the first new
// leaf-pointer slot, not the start of the complete array. A new directory uses
// logical page zero; its leaves may reside in any of the following blocks.
// Publish the L3 link only after every child PDE is prepared. After success,
// retain all blocks and confirm hardware synchronization before exposing the
// newly covered IOVA range. Every validation precedes the first PDE write.
inline bool attachPageTables(const PageTableGrowthPlan &growth,
                            const PageTableBlock *blocks, unsigned blockCount,
                            volatile u64 **newLeafPointers) {
    const unsigned directoryPages = growth.directory ? 0U : 1U;
    if (!growth.parentEntry || !blocks || !newLeafPointers ||
            !growth.leafCount || growth.firstEntry >= 512 ||
            growth.leafCount > 512 - growth.firstEntry ||
            growth.tablePages != growth.leafCount + directoryPages ||
            blockCount != pageTableBlockCount(growth.tablePages)) return false;
    for (unsigned i = 0; i < blockCount; ++i) {
        const auto &block = blocks[i];
        if (!block.tables || !block.physicalBase || (block.physicalBase & 4095ULL) ||
                block.tablePages != pageTableBlockPages(growth.tablePages, i)) return false;
    }
    for (unsigned i = 0; i < blockCount; ++i)
        for (unsigned entry = 0; entry < blocks[i].tablePages * 512; ++entry)
            blocks[i].tables[entry] = 0;
    volatile u64 *directory = growth.directory ? growth.directory : blocks[0].tables;
    const u64 permissions = amdpte::PTE_IR | amdpte::PTE_IW;
    for (unsigned i = 0; i < growth.leafCount; ++i) {
        const unsigned page = directoryPages + i;
        const auto &block = blocks[page / kTableBlockPages];
        const unsigned localPage = page % kTableBlockPages;
        newLeafPointers[i] = block.tables + localPage * 512;
        directory[growth.firstEntry + i] = amdpte::makeTablePde(
            1, block.physicalBase + (u64)localPage * 4096, permissions);
    }
    if (!growth.directory)
        *growth.parentEntry = amdpte::makeTablePde(2, blocks[0].physicalBase, permissions);
    return true;
}
}  // namespace amdtable
