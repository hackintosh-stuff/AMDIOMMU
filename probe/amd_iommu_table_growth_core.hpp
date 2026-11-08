// Append leaf tables to the mapper's fixed 1 GiB directory without moving
// the root, upper-level tables or any existing leaf table.
#pragma once
#include "amd_iommu_sparse_core.hpp"

namespace amdtable {
typedef amdpte::u64 u64;

// The root and both upper levels remain in the original contiguous buffer.
// Growth buffers contain only L1 tables, so locating L2 needs no page-bank map.
inline volatile u64 *leafDirectory(amdsparse::Arena &rootArena, u64 iova) {
    if (rootArena.rootLevel != 3 && rootArena.rootLevel != 4) return nullptr;
    u64 pa = rootArena.rootPA;
    const u64 permissions = amdpte::PTE_IR | amdpte::PTE_IW;
    for (unsigned level = rootArena.rootLevel; level > 2; --level) {
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

// firstLeaf is an L2 entry index. The mapper window begins on a 1 GiB boundary,
// so it is also an index into the complete leafPointers array. The caller owns
// the mapper lock and the new buffer. All refusal checks precede any write.
// After success, retain the buffer until domain teardown and confirm the
// required hardware synchronization before exposing the new capacity.
inline bool attachLeafTables(volatile u64 *directory,
                             unsigned firstLeaf, unsigned leafCount,
                             volatile u64 *newTables, u64 newTablePA,
                             volatile u64 **leafPointers) {
    if (!directory || !newTables || !leafPointers || !newTablePA ||
            (newTablePA & 4095ULL) || !leafCount || firstLeaf >= 512 ||
            leafCount > 512 - firstLeaf) return false;
    for (unsigned i = 0; i < leafCount; ++i)
        if (directory[firstLeaf + i]) return false;

    for (unsigned i = 0; i < leafCount * 512; ++i) newTables[i] = 0;
    const u64 permissions = amdpte::PTE_IR | amdpte::PTE_IW;
    for (unsigned i = 0; i < leafCount; ++i) {
        leafPointers[firstLeaf + i] = newTables + i * 512;
        directory[firstLeaf + i] = amdpte::makeTablePde(
            1, newTablePA + (u64)i * 4096, permissions);
    }
    return true;
}
}  // namespace amdtable
