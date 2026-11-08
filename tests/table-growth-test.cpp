// One live growth sequence using the production table-attachment helper.
// This checks table structure and translations, not hardware invalidation.
#include <cstdio>
#include <vector>

#include "../probe/amd_iommu_mapper_abi.hpp"
#include "../probe/amd_iommu_table_growth_core.hpp"
#include "../probe/amd_iommu_tx_core.hpp"

namespace {
using amdtable::u64;

bool check(bool ok, const char *what) {
    if (!ok) std::printf("FAIL %s\n", what);
    return ok;
}

struct TableBlock {
    u64 physicalBase;
    std::vector<u64> words;
    TableBlock(u64 pa, unsigned pages, u64 initial = 0)
        : physicalBase(pa), words(pages * 512, initial) {}
};

struct Mapping {
    unsigned page;
    u64 physical;
};

bool growAndTranslate() {
    const auto &initial = mapper_abi::kProfileLegacy;
    const auto &expanded = mapper_abi::kProfileRl10g;
    const auto &ceiling = mapper_abi::kProfileRl10gMax;
    const u64 permissions = amdpte::PTE_IR | amdpte::PTE_IW;
    TableBlock root(0x10000000ULL, initial.tablePages);
    amdsparse::Arena rootArena = {root.words.data(), root.physicalBase,
        initial.tablePages, 1, 4, root.physicalBase, 0, 0, nullptr};
    std::vector<volatile u64 *> leaves(initial.pages / 512);
    for (unsigned i = 0; i < leaves.size(); ++i) {
        leaves[i] = amdtx::prepareAt(rootArena,
            mapper_abi::kBase + (u64)i * 0x200000ULL, 512);
        if (!check(leaves[i] != nullptr, "initial leaf preparation")) return false;
    }
    volatile u64 *directory = amdtable::leafDirectory(rootArena, mapper_abi::kBase);
    if (!check(directory != nullptr, "locate the fixed L2 directory")) return false;

    std::vector<const TableBlock *> blocks{&root};
    auto readEntry = [&blocks](u64 pa, unsigned index) -> u64 {
        for (const TableBlock *block : blocks) {
            if (pa >= block->physicalBase &&
                    pa - block->physicalBase < block->words.size() * sizeof(u64))
                return block->words[(pa - block->physicalBase) / sizeof(u64) + index];
        }
        return 0;
    };
    const u64 rootPA = rootArena.rootPA;
    const u64 rootEntry = readEntry(rootPA, amdpte::indexAt(4, mapper_abi::kBase));
    const u64 upperPA = amdpte::decodePte(rootEntry, 4).outPA;
    const u64 upperEntry = readEntry(upperPA, amdpte::indexAt(3, mapper_abi::kBase));
    const u64 directoryPA = amdpte::decodePte(upperEntry, 3).outPA;
    auto hierarchyUnchanged = [&]() {
        return check(rootArena.rootPA == rootPA &&
            readEntry(rootPA, amdpte::indexAt(4, mapper_abi::kBase)) == rootEntry &&
            readEntry(upperPA, amdpte::indexAt(3, mapper_abi::kBase)) == upperEntry &&
            amdsparse::table(rootArena, directoryPA) == directory &&
            amdtable::leafDirectory(rootArena, mapper_abi::kBase) == directory,
            "root and both upper-level table addresses stay fixed");
    };
    std::vector<Mapping> mappings;
    auto mapPage = [&](unsigned page) {
        const u64 physical = 0x120000000ULL + (u64)page * 4096;
        leaves[page / 512][page % 512] = amdpte::makeDefaultLeaf(1, physical, permissions);
        mappings.push_back(Mapping{page, physical});
    };
    auto translationsMatch = [&]() {
        for (const Mapping &mapping : mappings) {
            const u64 offset = 0x59;
            const auto walk = amdpte::walkPageTable(readEntry, rootArena.rootLevel,
                rootPA, mapper_abi::kBase + (u64)mapping.page * 4096 + offset);
            if (!check(walk.ok && walk.outPA == mapping.physical + offset &&
                    walk.leafLevel == 1 && walk.pageSize == 4096 && walk.depth == 4,
                    "old and new IOVA translations match their physical pages"))
                return false;
        }
        return true;
    };
    auto tablesEmpty = [](const TableBlock &block) {
        for (u64 word : block.words) if (word) return false;
        return true;
    };
    unsigned tablePages = initial.tablePages;
    mapPage(0);
    mapPage(initial.pages / 2);
    mapPage(initial.pages - 1);
    if (!check(tablePages == 16, "only 16 table pages are allocated initially") ||
            !translationsMatch()) return false;

    const unsigned addedLeaves = (expanded.pages - initial.pages) / 512;
    TableBlock expandedTables(0x40000000ULL, addedLeaves, ~0ULL);
    leaves.resize(expanded.pages / 512);
    if (!check(amdtable::attachLeafTables(directory, initial.pages / 512, addedLeaves,
            expandedTables.words.data(), expandedTables.physicalBase, leaves.data()),
            "attach leaf tables for rl-10g") ||
            !check(tablesEmpty(expandedTables), "first growth clears every new leaf"))
        return false;
    blocks.push_back(&expandedTables);
    tablePages += addedLeaves;
    mapPage(initial.pages);
    mapPage(expanded.pages / 2);
    mapPage(expanded.pages - 1);
    if (!check(tablePages == 264, "first growth owns 264 table pages") ||
            !hierarchyUnchanged() || !translationsMatch()) return false;

    const unsigned ceilingLeaves = (ceiling.pages - expanded.pages) / 512;
    TableBlock ceilingTables(0x70000000ULL, ceilingLeaves, ~0ULL);
    leaves.resize(ceiling.pages / 512);
    if (!check(amdtable::attachLeafTables(directory, expanded.pages / 512, ceilingLeaves,
            ceilingTables.words.data(), ceilingTables.physicalBase, leaves.data()),
            "attach leaf tables for rl-10g-max") ||
            !check(tablesEmpty(ceilingTables), "second growth clears every new leaf"))
        return false;
    blocks.push_back(&ceilingTables);
    tablePages += ceilingLeaves;
    mapPage(expanded.pages);
    mapPage((expanded.pages + ceiling.pages) / 2);
    mapPage(ceiling.pages - 1);
    if (!check(tablePages == 520, "second growth owns 520 table pages") ||
            !hierarchyUnchanged() || !translationsMatch()) return false;

    for (const Mapping &mapping : mappings)
        leaves[mapping.page / 512][mapping.page % 512] = 0;
    for (volatile u64 *leaf : leaves)
        for (unsigned i = 0; i < 512; ++i)
            if (!check(leaf[i] == 0, "all leaf mappings can be cleared")) return false;
    for (const Mapping &mapping : mappings) {
        const auto walk = amdpte::walkPageTable(readEntry, rootArena.rootLevel,
            rootPA, mapper_abi::kBase + (u64)mapping.page * 4096);
        if (!check(walk.absent && !walk.ok, "cleared mappings no longer translate"))
            return false;
    }
    return hierarchyUnchanged();
}
}  // namespace

int main() {
    if (!growAndTranslate()) return 1;
    std::printf("TABLE_GROWTH_OK table_pages=16,264,520\n");
    return 0;
}
