// Independently owned metadata stores shared by the live mapper and host test.
// Allocation and lifetime stay with the caller; hardware page tables are separate.
#pragma once
#include <stddef.h>
#include "amd_iommu_mapper_abi.hpp"
#include "amd_iommu_tx_core.hpp"

class IOMemoryDescriptor;
class IODMACommand;

namespace amdmapper {
struct RecordStorage {
    struct Mapping {
        IOMemoryDescriptor *memory;
        IODMACommand *command;
        mapper_abi::RecordHeader record;
    };
    void *recordMemory;
    size_t recordBytes;
    Mapping *mappings;
    amdtx::u64 *liveSlots;
    uint32_t records;
};
struct IovaPageStorage {
    void *pageMemory;
    size_t pageBytes;
    amdtx::u64 *physicalByPage;
    uint32_t *slotByStartPage; // slot + 1; zero means no mapping starts here
    volatile amdtx::u64 **leaves;
    amdtx::RuntimeAllocator allocator;
    uint32_t pages;
};
struct MappingStorage : RecordStorage, IovaPageStorage {
    size_t metadataBytes() const { return recordBytes + pageBytes; }
};
static_assert(sizeof(RecordStorage::Mapping) == mapper_abi::kMappingBytes,
              "mapping metadata must match record storage size accounting");

// The caller supplies zeroed storage with the corresponding byte count.
// Binding one resource leaves the other resource's pointers and counters alone.
inline void bindRecordStorage(RecordStorage &target, void *zeroedStorage,
                              uint32_t records) {
    target.recordMemory = zeroedStorage;
    target.recordBytes = static_cast<size_t>(mapper_abi::recordStorageBytesFor(records));
    target.records = records;
    auto *cursor = static_cast<uint8_t *>(zeroedStorage);
    target.mappings = reinterpret_cast<RecordStorage::Mapping *>(cursor);
    cursor += static_cast<size_t>(records) * sizeof(RecordStorage::Mapping);
    target.liveSlots = reinterpret_cast<amdtx::u64 *>(cursor);
}

inline void bindIovaPageStorage(IovaPageStorage &target, void *zeroedStorage,
                                uint32_t pages,
                                uint32_t maxMapPages = mapper_abi::kMapPages) {
    const size_t pageWords = (pages + 63) / 64;
    const size_t leafCount = pages / 512;
    target.pageMemory = zeroedStorage;
    target.pageBytes = static_cast<size_t>(mapper_abi::iovaPageStorageBytesFor(pages));
    target.pages = pages;
    auto *cursor = static_cast<uint8_t *>(zeroedStorage);
    target.physicalByPage = reinterpret_cast<amdtx::u64 *>(cursor);
    cursor += static_cast<size_t>(pages) * sizeof(amdtx::u64);
    target.slotByStartPage = reinterpret_cast<uint32_t *>(cursor);
    cursor += static_cast<size_t>(pages) * sizeof(uint32_t);
    target.leaves = reinterpret_cast<volatile amdtx::u64 **>(cursor);
    cursor += leafCount * sizeof(volatile amdtx::u64 *);
    auto *used = reinterpret_cast<amdtx::u64 *>(cursor);
    cursor += pageWords * sizeof(amdtx::u64);
    auto *ever = reinterpret_cast<amdtx::u64 *>(cursor);
    target.allocator = amdtx::RuntimeAllocator{
        used, ever, pages, maxMapPages, 0, 0, 0};
}

// Both stores are bound, and target is at least as large as source. The caller
// holds the mapper lock until the replacement store is adopted. New capacity
// stays zeroed; growth of either resource preserves the other allocation.
inline void copyRecordStorage(RecordStorage &target, const RecordStorage &source) {
    for (uint32_t i = 0; i < source.records; ++i)
        target.mappings[i] = source.mappings[i];
    for (uint32_t i = 0; i < (source.records + 63) / 64; ++i)
        target.liveSlots[i] = source.liveSlots[i];
}

inline void copyIovaPageStorage(IovaPageStorage &target, const IovaPageStorage &source) {
    for (uint32_t i = 0; i < source.pages; ++i) {
        target.physicalByPage[i] = source.physicalByPage[i];
        target.slotByStartPage[i] = source.slotByStartPage[i];
    }
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
