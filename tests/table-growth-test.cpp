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
    const auto &ceiling = mapper_abi::kProfileDma32Max;
    auto capacity = mapper_abi::capacityForProfile(initial);
    constexpr unsigned expectedPages[] = {
        4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288};
    constexpr unsigned expectedTablePages[] = {16, 24, 40, 72, 136, 264, 520, 1033};
    constexpr unsigned expectedSegments[] = {1, 2, 3, 5, 9, 17, 33, 66};
    constexpr u64 tablePhysicalBases[] = {
        0x40000000ULL, 0x70000000ULL, 0x28000000ULL,
        0x54000000ULL, 0x90000000ULL, 0x08000000ULL, 0x06000000ULL};
    constexpr unsigned growthSteps = sizeof(tablePhysicalBases) / sizeof(tablePhysicalBases[0]);
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
    std::vector<const TableBlock *> blocks{&root};
    // Resolve every table PA through its allocation segment, including a new L2.
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
    volatile u64 *upper = amdtable::leafDirectoryParent(rootArena, mapper_abi::kBase);
    volatile u64 *directory = amdsparse::table(rootArena, directoryPA);
    if (!check(upper && directory, "locate the initial L3 and L2 tables")) return false;
    auto hierarchyUnchanged = [&]() {
        return check(rootArena.rootPA == rootPA &&
            readEntry(rootPA, amdpte::indexAt(4, mapper_abi::kBase)) == rootEntry &&
            readEntry(upperPA, amdpte::indexAt(3, mapper_abi::kBase)) == upperEntry &&
            amdsparse::table(rootArena, directoryPA) == directory &&
            amdtable::leafDirectoryParent(rootArena, mapper_abi::kBase) == upper,
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
    auto newLeavesEmpty = [&](unsigned firstLeaf, unsigned count) {
        for (unsigned i = 0; i < count; ++i)
            for (unsigned entry = 0; entry < 512; ++entry)
                if (leaves[firstLeaf + i][entry]) return false;
        return true;
    };
    unsigned tablePages = initial.tablePages;
    mapPage(0);
    mapPage(initial.pages / 2);
    mapPage(initial.pages - 1);
    if (!check(capacity.pages == expectedPages[0] && tablePages == expectedTablePages[0],
            "legacy capacity starts with only 16 allocated table pages") ||
            !translationsMatch()) return false;

    // Keep every host buffer stable. Blocks within a growth are separated and
    // descend in PA; the final growth lies below rootPA. Walking must resolve
    // each actual segment rather than add an offset to one physical base.
    std::vector<TableBlock> addedBlocks;
    addedBlocks.reserve(expectedSegments[growthSteps] - 1);
    for (unsigned step = 0; step < growthSteps; ++step) {
        mapper_abi::Capacity target{};
        if (!check(mapper_abi::nextCapacity(capacity, ceiling,
                mapper_abi::CapacityResource::iovaPages, target),
                "plan the next IOVA capacity increase") ||
                !check(target.records == initial.records &&
                    target.pages == expectedPages[step + 1],
                    "IOVA capacity doubles without growing record slots")) return false;
        const unsigned firstLeaf = capacity.pages / 512;
        const unsigned addedLeaves = (target.pages - capacity.pages) / 512;
        const u64 firstIOVA = mapper_abi::kBase + (u64)capacity.pages * 4096;
        const bool addsDirectory = firstIOVA == 0xc0000000ULL;
        amdtable::PageTableGrowthPlan growth{};
        if (!check(amdtable::planPageTableGrowth(rootArena, firstIOVA, addedLeaves, growth),
                "plan leaf storage and a directory when crossing 1 GiB") ||
                !check(growth.directory == (addsDirectory ? nullptr : directory) &&
                    growth.parentEntry == upper + amdpte::indexAt(3, firstIOVA) &&
                    growth.firstEntry == firstLeaf % 512 &&
                    growth.tablePages == addedLeaves + (addsDirectory ? 1U : 0U),
                    "growth plan counts the new directory separately from leaf pages"))
            return false;
        std::vector<u64> retainedDirectory;
        if (addsDirectory) {
            if (!check(growth.tablePages == 513 && *growth.parentEntry == 0,
                    "the 1 GiB to 2 GiB step prepares 513 pages under an empty L3 entry"))
                return false;
            for (unsigned entry = 0; entry < 512; ++entry)
                retainedDirectory.push_back(static_cast<u64>(directory[entry]));
        }
        const unsigned blockCount = amdtable::pageTableBlockCount(growth.tablePages);
        if (!check(blockCount == expectedSegments[step + 1] - expectedSegments[step],
                "block count follows the 64 KiB allocation bound")) return false;
        std::vector<amdtable::PageTableBlock> staged;
        staged.reserve(blockCount);
        for (unsigned i = 0; i < blockCount; ++i) {
            const unsigned pages = amdtable::pageTableBlockPages(growth.tablePages, i);
            if (!check(pages > 0 && pages <= 16,
                    "each table allocation is at most 16 pages")) return false;
            addedBlocks.emplace_back(tablePhysicalBases[step] - (u64)i * 0x20000ULL,
                                     pages, ~0ULL);
            TableBlock &block = addedBlocks.back();
            staged.push_back({block.words.data(), block.physicalBase, pages});
            blocks.push_back(&block);
        }
        leaves.resize(target.pages / 512);
        if (!check(amdtable::attachPageTables(growth, staged.data(), blockCount,
                leaves.data() + firstLeaf),
                "attach all staged table blocks for one capacity increase") ||
                !check(newLeavesEmpty(firstLeaf, addedLeaves), "growth clears every new leaf"))
            return false;
        if (addsDirectory) {
            const u64 newDirectoryPA = staged.front().physicalBase;
            const auto &lastBlock = staged.back();
            const u64 lastLeafPA = lastBlock.physicalBase +
                (u64)(lastBlock.tablePages - 1) * 4096;
            if (!check(readEntry(upperPA, 3) ==
                    amdpte::makeTablePde(2, newDirectoryPA, permissions) &&
                    readEntry(newDirectoryPA, 0) ==
                    amdpte::makeTablePde(1, newDirectoryPA + 4096, permissions) &&
                    readEntry(newDirectoryPA, 511) ==
                    amdpte::makeTablePde(1, lastLeafPA, permissions),
                    "L3[3] reaches the new L2 and leaves in different physical blocks"))
                return false;
            for (unsigned entry = 0; entry < 512; ++entry)
                if (!check(directory[entry] == retainedDirectory[entry],
                        "adding another directory leaves every old L2 entry untouched"))
                    return false;
        }
        tablePages += growth.tablePages;
        mapPage((capacity.pages + target.pages) / 2);
        // Map both sides of every physical-block boundary. The first block
        // loses one leaf position when it also owns the new L2 directory.
        unsigned mappedLeaves = 0;
        for (unsigned i = 0; i < blockCount; ++i) {
            const unsigned blockLeaves = staged[i].tablePages -
                ((addsDirectory && i == 0) ? 1U : 0U);
            mapPage((firstLeaf + mappedLeaves) * 512);
            mappedLeaves += blockLeaves;
            mapPage((firstLeaf + mappedLeaves) * 512 - 1);
        }
        if (!check(mappedLeaves == addedLeaves,
                "boundary mappings span every new leaf block")) return false;
        capacity = target;
        if (!check(tablePages == expectedTablePages[step + 1] &&
                blocks.size() == expectedSegments[step + 1],
                "table pages and physical segments follow their separate sequences") ||
                !hierarchyUnchanged() || !translationsMatch()) return false;
    }
    if (!check(mapper_abi::kBase + (u64)(capacity.pages - 1) * 4096 == 0xfffff000ULL &&
            mappings.back().page == capacity.pages - 1,
            "the last mapping covers the final 4 KiB page below 4 GiB")) return false;

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
    std::printf("TABLE_GROWTH_OK table_pages=16,24,40,72,136,264,520,1033 "
                "segments=1,2,3,5,9,17,33,66 max_block_pages=16\n");
    return 0;
}
