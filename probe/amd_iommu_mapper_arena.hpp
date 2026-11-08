// Metadata storage shared by the live mapper and its host capacity test.
// Allocation and ownership stay with the caller; page-table pages are separate.
#pragma once
#include <stddef.h>
#include "amd_iommu_mapper_abi.hpp"
#include "amd_iommu_tx_core.hpp"

class IOMemoryDescriptor;
class IODMACommand;

namespace amdmapper {
struct MappingArena {
    struct Mapping {
        IOMemoryDescriptor *memory;
        IODMACommand *command;
        mapper_abi::RecordHeader record;
    };
    void *arena;
    size_t arenaBytes;
    Mapping *mappings;
    amdtx::u64 *physicalByPage;
    uint16_t *slotByStartPage;
    amdtx::u64 *liveSlots;
    volatile amdtx::u64 **leaves;
    amdtx::RuntimeAllocator allocator;
    uint32_t records, pages;
};
static_assert(sizeof(MappingArena::Mapping) == mapper_abi::kMappingBytes,
              "mapping metadata must match arena size accounting");

// The caller supplies zeroed, suitably aligned storage of arenaBytesFor(capacity)
// bytes. Bind each array independently because its offset changes with capacity.
inline void bindArena(MappingArena &target, void *zeroedStorage,
                      const mapper_abi::Capacity &capacity,
                      uint32_t maxMapPages = mapper_abi::kMapPages) {
    const size_t recordWords = (capacity.records + 63) / 64;
    const size_t pageWords = (capacity.pages + 63) / 64;
    const size_t leafCount = capacity.pages / 512;
    target.arena = zeroedStorage;
    target.arenaBytes = static_cast<size_t>(mapper_abi::arenaBytesFor(capacity));
    target.records = capacity.records;
    target.pages = capacity.pages;
    auto *cursor = static_cast<uint8_t *>(zeroedStorage);
    target.mappings = reinterpret_cast<MappingArena::Mapping *>(cursor);
    cursor += static_cast<size_t>(capacity.records) * sizeof(MappingArena::Mapping);
    target.physicalByPage = reinterpret_cast<amdtx::u64 *>(cursor);
    cursor += static_cast<size_t>(capacity.pages) * sizeof(amdtx::u64);
    target.slotByStartPage = reinterpret_cast<uint16_t *>(cursor);
    cursor += static_cast<size_t>(capacity.pages) * sizeof(uint16_t);
    target.liveSlots = reinterpret_cast<amdtx::u64 *>(cursor);
    cursor += recordWords * sizeof(amdtx::u64);
    target.leaves = reinterpret_cast<volatile amdtx::u64 **>(cursor);
    cursor += leafCount * sizeof(volatile amdtx::u64 *);
    auto *used = reinterpret_cast<amdtx::u64 *>(cursor);
    cursor += pageWords * sizeof(amdtx::u64);
    auto *ever = reinterpret_cast<amdtx::u64 *>(cursor);
    target.allocator = amdtx::RuntimeAllocator{
        used, ever, capacity.pages, maxMapPages, 0, 0, 0};
}

inline void bindArena(MappingArena &target, void *zeroedStorage,
                      const mapper_abi::Profile &profile) {
    bindArena(target, zeroedStorage, mapper_abi::capacityForProfile(profile),
              profile.mapPages);
}

// Both arenas are bound, and target is at least as large as source. The live
// mapper holds its lock while copying and replacing these software pointers.
// New capacity remains zeroed; existing table pages are retained by address.
inline void copyArena(MappingArena &target, const MappingArena &source) {
    for (uint32_t i = 0; i < source.records; ++i)
        target.mappings[i] = source.mappings[i];
    for (uint32_t i = 0; i < source.pages; ++i) {
        target.physicalByPage[i] = source.physicalByPage[i];
        target.slotByStartPage[i] = source.slotByStartPage[i];
    }
    for (uint32_t i = 0; i < (source.records + 63) / 64; ++i)
        target.liveSlots[i] = source.liveSlots[i];
    for (uint32_t i = 0; i < source.pages / 512; ++i)
        target.leaves[i] = source.leaves[i];
    for (uint32_t i = 0; i < (source.pages + 63) / 64; ++i) {
        target.allocator.used[i] = source.allocator.used[i];
        target.allocator.ever[i] = source.allocator.ever[i];
    }
    target.allocator.maxMapPages = source.allocator.maxMapPages;
    target.allocator.livePages = source.allocator.livePages;
    target.allocator.peakPages = source.allocator.peakPages;
    target.allocator.reusedAllocations = source.allocator.reusedAllocations;
}
} // namespace amdmapper
