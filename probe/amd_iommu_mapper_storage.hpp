// Retained record and IOVA-page metadata chunks.
// Allocation and lifetime stay with the caller; hardware page tables are separate.
#pragma once
#include <stddef.h>
#include "amd_iommu_mapper_abi.hpp"
#include "amd_iommu_tx_core.hpp"

class IOMemoryDescriptor;
class IODMACommand;

namespace amdmapper {
// Initial legacy chunk plus seven record-capacity doublings to the DMA32 ceiling.
static constexpr uint32_t kMaxRecordChunks = 8;

struct RecordStorage;
struct RecordBitmap {
    const RecordStorage *storage;
    explicit operator bool() const { return storage != nullptr; }
    amdtx::u64 &operator[](unsigned word) const;
};

struct RecordChunk {
    struct Mapping {
        IOMemoryDescriptor *memory;
        IODMACommand *command;
        mapper_abi::RecordHeader record;
    };
    void *memory;
    size_t bytes;
    uint32_t firstRecord, records;
    Mapping *mappings;
    amdtx::u64 *liveSlots;
};

struct RecordStorage {
    using Mapping = RecordChunk::Mapping;
    RecordChunk recordChunks[kMaxRecordChunks];
    size_t recordBytes;
    RecordBitmap liveSlots;
    uint32_t records, recordChunkCount;

    // The caller supplies a global slot inside the allocated capacity.
    const RecordChunk &chunkAtRecord(uint32_t slot) const {
        for (uint32_t i = recordChunkCount; i > 1; --i)
            if (slot >= recordChunks[i - 1].firstRecord) return recordChunks[i - 1];
        return recordChunks[0];
    }
    Mapping &mappingAt(uint32_t slot) const {
        const auto &chunk = chunkAtRecord(slot);
        return chunk.mappings[slot - chunk.firstRecord];
    }
};

inline amdtx::u64 &RecordBitmap::operator[](unsigned word) const {
    const auto &chunk = storage->chunkAtRecord(word * 64);
    return chunk.liveSlots[word - chunk.firstRecord / 64];
}

// Initial legacy chunk plus seven IOVA-capacity doublings to the DMA32 ceiling.
static constexpr uint32_t kMaxIovaPageChunks = 8;

struct IovaPageStorage;
struct PageBitmap {
    const IovaPageStorage *storage;
    bool ever;
    explicit operator bool() const { return storage != nullptr; }
    amdtx::u64 &operator[](unsigned word) const;
};

struct IovaPageChunk {
    void *memory;
    size_t bytes;
    uint32_t firstPage, pages;
    amdtx::u64 *physicalByPage;
    uint32_t *slotByStartPage; // slot + 1; zero means no mapping starts here
    volatile amdtx::u64 **leaves;
    amdtx::u64 *used, *ever;
};

struct IovaPageStorage {
    IovaPageChunk chunks[kMaxIovaPageChunks];
    size_t pageBytes;
    amdtx::RuntimeAllocatorState<PageBitmap> allocator;
    uint32_t pages, pageChunkCount;

    // The caller supplies an index inside the allocated capacity. Chunks are
    // appended in IOVA order; at most eight descriptors need to be examined.
    const IovaPageChunk &chunkAtPage(uint32_t page) const {
        for (uint32_t i = pageChunkCount; i > 1; --i)
            if (page >= chunks[i - 1].firstPage) return chunks[i - 1];
        return chunks[0];
    }
    amdtx::u64 &physicalPage(uint32_t page) const {
        const auto &chunk = chunkAtPage(page);
        return chunk.physicalByPage[page - chunk.firstPage];
    }
    uint32_t &startPageOwner(uint32_t page) const {
        const auto &chunk = chunkAtPage(page);
        return chunk.slotByStartPage[page - chunk.firstPage];
    }
    volatile amdtx::u64 *&leafTable(uint32_t leafIndex) const {
        const auto &chunk = chunkAtPage(leafIndex * 512);
        return chunk.leaves[leafIndex - chunk.firstPage / 512];
    }
    // A mapping may cross metadata chunks even though its IOVA range is linear.
    void copyPhysicalPages(uint32_t firstPage, uint32_t count,
                           uint64_t *destination) const {
        for (uint32_t i = 0; i < count; ++i)
            destination[i] = physicalPage(firstPage + i);
    }
};

inline amdtx::u64 &PageBitmap::operator[](unsigned word) const {
    const auto &chunk = storage->chunkAtPage(word * 64);
    return (ever ? chunk.ever : chunk.used)[word - chunk.firstPage / 64];
}

struct MappingStorage : RecordStorage, IovaPageStorage {
    size_t metadataBytes() const { return recordBytes + pageBytes; }
};
static_assert(sizeof(RecordStorage::Mapping) == mapper_abi::kMappingBytes,
              "mapping metadata must match record storage size accounting");

// Bind the bitmap view once to the stable owning store. Append descriptors in
// place after initialization; copying this store would retain the old owner.
inline void initializeRecordStorage(RecordStorage &target) {
    target = {};
    target.liveSlots = RecordBitmap{&target};
}

// The caller supplies a zeroed chunk with the corresponding byte count.
inline void bindRecordChunk(RecordChunk &target, void *zeroedStorage,
                           uint32_t firstRecord, uint32_t records) {
    target.memory = zeroedStorage;
    target.bytes = static_cast<size_t>(mapper_abi::recordChunkBytesFor(records));
    target.firstRecord = firstRecord;
    target.records = records;
    auto *cursor = static_cast<uint8_t *>(zeroedStorage);
    target.mappings = reinterpret_cast<RecordChunk::Mapping *>(cursor);
    cursor += static_cast<size_t>(records) * sizeof(RecordChunk::Mapping);
    target.liveSlots = reinterpret_cast<amdtx::u64 *>(cursor);
}

// The caller owns a chunk starting at target.records and has checked the
// descriptor limit. Existing record allocations and slot numbers stay in place.
inline void appendRecordChunk(RecordStorage &target, const RecordChunk &chunk) {
    target.recordChunks[target.recordChunkCount++] = chunk;
    target.recordBytes += chunk.bytes;
    target.records += chunk.records;
}

// Bind the bitmap views once to the stable owning store. After initialization,
// append descriptors in place; copying this store would leave views bound to
// the previous owner. Both resource stores stay in place throughout growth.
inline void initializeIovaPageStorage(IovaPageStorage &target,
                                     uint32_t maxMapPages = mapper_abi::kMapPages) {
    target = {};
    target.allocator = amdtx::RuntimeAllocatorState<PageBitmap>{
        {&target, false}, {&target, true}, 0, maxMapPages, 0, 0, 0};
}

inline void bindIovaPageChunk(IovaPageChunk &target, void *zeroedStorage,
                             uint32_t firstPage, uint32_t pages) {
    const size_t pageWords = (pages + 63) / 64;
    const size_t leafCount = pages / 512;
    target.memory = zeroedStorage;
    target.bytes = static_cast<size_t>(mapper_abi::iovaPageChunkBytesFor(pages));
    target.firstPage = firstPage;
    target.pages = pages;
    auto *cursor = static_cast<uint8_t *>(zeroedStorage);
    target.physicalByPage = reinterpret_cast<amdtx::u64 *>(cursor);
    cursor += static_cast<size_t>(pages) * sizeof(amdtx::u64);
    target.slotByStartPage = reinterpret_cast<uint32_t *>(cursor);
    cursor += static_cast<size_t>(pages) * sizeof(uint32_t);
    target.leaves = reinterpret_cast<volatile amdtx::u64 **>(cursor);
    cursor += leafCount * sizeof(volatile amdtx::u64 *);
    target.used = reinterpret_cast<amdtx::u64 *>(cursor);
    cursor += pageWords * sizeof(amdtx::u64);
    target.ever = reinterpret_cast<amdtx::u64 *>(cursor);
}

// The caller owns a prepared chunk starting at target.pages and has checked the
// descriptor limit. Append only after any hardware growth fence has completed.
// Existing chunks and all allocator accounting remain in place.
inline void appendIovaPageChunk(IovaPageStorage &target, const IovaPageChunk &chunk) {
    target.chunks[target.pageChunkCount++] = chunk;
    target.pageBytes += chunk.bytes;
    target.pages += chunk.pages;
    target.allocator.poolPages = target.pages;
}

} // namespace amdmapper
