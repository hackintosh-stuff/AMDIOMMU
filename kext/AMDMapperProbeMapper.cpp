// R44: ordinary per-device IOMapper backend. All normal IODMACommand objects
// share one bounded allocator; there are no private driver roles or bindings.
#include "AMDMapperProbeInternal.hpp"
#include "amd_iommu_tx_core.hpp"
#include "amd_iommu_mapper_abi.hpp"
#include <IOKit/IOLocks.h>
#include <kern/debug.h>

// XNU's DMA-unmap caller can discard our error and unwire the descriptor.
// Once PTEs have been published, neither an error return nor retaining an
// IOMemoryDescriptor proves its backing pages remain wired. If retirement
// cannot be confirmed, fail-stop before returning control to that caller.
// Do not allocate, publish registry data, retry a failed ring, or drop the
// domain lock here. This is containment, not recovery or proof of device idle.
[[noreturn]] static void r70DMAFailStop(
    const char *reason, const r44mapper::RecordHeader &record) {
    panic("AMDMapperProbe: unsafe DMA retirement (%s), handle=%llu "
          "iova=0x%llx length=0x%llx state=0x%x",
          reason, (unsigned long long)record.handle,
          (unsigned long long)record.mapAddress,
          (unsigned long long)record.mapLength, (unsigned)record.state);
}

struct org_example_AMDMapperProbe::R44MapperState {
    struct Mapping {
        IOMemoryDescriptor *memory;
        IODMACommand *command;
        r44mapper::RecordHeader record;
    };
    IOLock *lock;
    volatile UInt64 *tables;
    // Root physical address of that table area; growth swaps both together.
    UInt64 tablePA;
    // One wired block holds every capacity-dependent array; its size comes
    // from the selected profile at prepare time. The legacy profile allocates
    // the same bytes the static ABI3 arrays used to occupy.
    void *arena;
    size_t arenaBytes;
    volatile UInt64 **leaves;
    amdtx::RuntimeAllocator allocator;
    // Both scratch buffers are per-domain and used only while lock is held.
    BoundedProbeLayout<r44mapper::kRuns> walkScratch;
    r44mapper::Record exportScratch;
    Mapping *mappings;
    // Expected PA from the descriptor walk, independent of the actual leaf PTE.
    UInt64 *physicalByPage;
    // Sole per-slot liveness state; accessed under the domain lock.
    amdtx::u64 *liveSlots;
    // Per-domain start index: zero means no mapping starts on this IOVA page.
    UInt16 *slotByStartPage;
    r44mapper::Snapshot snapshot;
    OSData *suspendLive, *suspendPT, *resumeLive, *resumePT;
    UInt64 nextHandle;
    // R48 observes successful caller address constraints outside the raw ABI.
    // Only snapshot publication writes registry properties, never the hot path.
    UInt64 map32Ok, mapHighPAOk, mappedHighPAPages;
    UInt32 minMapBits, maxMapBits;
    UInt32 records, pages;
    bool accepting;
    // R71-B: growth is one-shot and only legal in [prepared, first activation).
    // The state object itself is never replaced - a rebuild swaps the arena and
    // the page tables inside it - so the domain lock and every address a caller
    // already holds stay valid.
    bool grown;
    bool growthAttempted;
    UInt64 growthTime;
    const char *growthState;

    volatile UInt64 &leaf(unsigned page) { return leaves[page / 512][page % 512]; }

    // A naturally placed span fits the smallest AMD range command for its
    // length. Reserve only the requested pages. A failed first-fit search
    // does not modify the allocator, so fragmented pools keep their capacity.
    bool allocateRange(unsigned count, unsigned &base, unsigned required) {
        unsigned preferred = required; // caller supplied a nonzero power of two
        while (preferred < count) preferred <<= 1;
        if (preferred != required && amdtx::allocate(allocator, count, base, preferred))
            return true;
        return amdtx::allocate(allocator, count, base, required);
    }

    unsigned nextSlot(unsigned from, bool occupied) const {
        return amdtx::findNextBitmapPage(liveSlots, from, records, occupied);
    }
    bool slotLive(unsigned slot) const {
        return (liveSlots[slot / 64] & (1ULL << (slot % 64))) != 0;
    }
    void setSlotLive(unsigned slot, bool live) {
        const amdtx::u64 mask = 1ULL << (slot % 64);
        auto &word = liveSlots[slot / 64];
        if (live) word |= mask;
        else word &= ~mask;
    }

    void exportRecord(const r44mapper::RecordHeader &header, r44mapper::Record &out) const {
        out.header = header;
        const size_t used = header.pages * sizeof(out.physical[0]);
        memcpy(out.physical, physicalByPage + header.basePage, used);
        bzero(out.physical + header.pages, sizeof(out.physical) - used);
    }

    OSData *copyLiveRecords() {
        OSData *data = OSData::withCapacity((snapshot.liveCount ? snapshot.liveCount : 1) *
                                            sizeof(r44mapper::Record));
        if (!data) return nullptr;
        auto &row = exportScratch;
        for (unsigned i = nextSlot(0, true); i < records;
             i = nextSlot(i + 1, true)) {
            exportRecord(mappings[i].record, row);
            if (!data->appendBytes(&row, sizeof(row))) {
                data->release();
                return nullptr;
            }
        }
        return data;
    }

    void capturePowerBoundary(OSData *&live, OSData *&pt) {
        if (live) { live->release(); live = nullptr; }
        if (pt) { pt->release(); pt = nullptr; }
        live = copyLiveRecords();
        pt = OSData::withBytes((const void *)tables, (unsigned)snapshot.ptBytes);
    }
};

// R71-B: one carve order for both the prepared arena and a grown one. The
// arithmetic lives in the ABI header so tests/ can verify it without compiling
// the kext; it must match the carve below exactly.
bool org_example_AMDMapperProbe::r44BuildArena(
    R44MapperState *d, volatile UInt64 *tables, UInt64 tablePA, UInt32 tablePages,
    UInt32 rootLevel, const r44mapper::Profile &profile) {
    if (!d || d->arena || !tables || !tablePA || (tablePA & 4095ULL) ||
        (rootLevel != 3 && rootLevel != 4)) return false;
    // Capacity is decided before the tables are published: the caller must have
    // reserved this profile's page-table area, and the record count must fit the
    // UInt16 slot encoding used by slotByStartPage.
    if (!profile.records || profile.records > 0xffffU || !profile.pages ||
        (profile.pages % 512) || profile.tablePages < 11 ||
        tablePages < profile.tablePages) return false;
    const UInt32 leavesCount = profile.pages / 512;
    const UInt64 words = (profile.records + 63) / 64;
    const UInt64 pageWords = (profile.pages + 63) / 64;
    const UInt64 blockBytes = r44mapper::arenaBytesFor(profile);
    IOLog("AMDMapperProbe: arena profile=%s records=%u pages=%u tables=%u bytes=%llu\n",
          profile.name, profile.records, profile.pages, tablePages, blockBytes);
    if (!blockBytes || blockBytes > r44mapper::kMaxArenaBytes) return false;
    void *arena = IOMalloc((vm_size_t)blockBytes);
    if (!arena) return false;
    bzero(arena, (size_t)blockBytes);
    d->arena = arena;
    d->arenaBytes = (size_t)blockBytes;
    d->records = profile.records;
    d->pages = profile.pages;
    d->tables = tables;
    d->tablePA = tablePA;
    uint8_t *cursor = (uint8_t *)d->arena;
    d->mappings = (R44MapperState::Mapping *)cursor;
    cursor += (UInt64)profile.records * sizeof(R44MapperState::Mapping);
    d->physicalByPage = (UInt64 *)cursor;
    cursor += (UInt64)profile.pages * sizeof(UInt64);
    d->slotByStartPage = (UInt16 *)cursor;
    cursor += (UInt64)profile.pages * sizeof(UInt16);
    d->liveSlots = (amdtx::u64 *)cursor;
    cursor += words * sizeof(amdtx::u64);
    d->leaves = (volatile UInt64 **)cursor;
    cursor += (UInt64)leavesCount * sizeof(volatile UInt64 *);
    amdtx::u64 *used = (amdtx::u64 *)cursor;
    cursor += pageWords * sizeof(amdtx::u64);
    amdtx::u64 *ever = (amdtx::u64 *)cursor;
    d->allocator = amdtx::RuntimeAllocator{used, ever, profile.pages,
                                           profile.mapPages, 0, 0, 0};
    amdsparse::Arena arenaMap = {tables, tablePA, tablePages, 1, rootLevel,
                                 tablePA, 0, 0, nullptr};
    for (UInt32 i = 0; i < leavesCount; ++i) {
        d->leaves[i] = amdtx::prepareAt(arenaMap,
            r44mapper::kBase + (UInt64)i * 0x200000ULL, 512);
        if (!d->leaves[i]) {
            // Release only what this build allocated: the caller may still be
            // using the arena this build was meant to replace, so the lock, the
            // counters and the snapshot stay exactly as they were.
            IOFree(d->arena, d->arenaBytes);
            d->arena = nullptr;
            d->arenaBytes = 0;
            d->records = 0;
            d->pages = 0;
            d->tables = nullptr;
            d->tablePA = 0;
            d->mappings = nullptr;
            d->physicalByPage = nullptr;
            d->slotByStartPage = nullptr;
            d->liveSlots = nullptr;
            d->leaves = nullptr;
            bzero(&d->allocator, sizeof(d->allocator));
            return false;
        }
    }
    auto &s = d->snapshot;
    s.version = r44mapper::kVersion; s.bytes = sizeof(s);
    s.flags = r44mapper::kPrepared | r44mapper::kAccepting;
    s.capacityMaps = profile.records; s.capacityPages = profile.pages;
    s.maxMapPages = profile.mapPages; s.maxRuns = profile.runs;
    s.iovaBase = r44mapper::kBase; s.iovaBytes = profile.pages * 4096ULL;
    s.rootPA = tablePA; s.ptBytes = tablePages * 4096ULL;
    s.rootLevel = rootLevel; s.tablePages = tablePages;
    return true;
}

bool org_example_AMDMapperProbe::r44PrepareMappings(
    volatile UInt64 *tables, UInt64 tablePA, UInt32 tablePages, UInt32 rootLevel,
    const r44mapper::Profile &profile) {
    if (fR44Mapper) return false;
    auto *d = (R44MapperState *)IOMalloc(sizeof(R44MapperState));
    if (!d) return false;
    bzero(d, sizeof(*d));
    d->lock = IOLockAlloc();
    if (!d->lock) { IOFree(d, sizeof(*d)); return false; }
    if (!r44BuildArena(d, tables, tablePA, tablePages, rootLevel, profile)) {
        IOLockFree(d->lock);
        IOFree(d, sizeof(*d));
        return false;
    }
    d->accepting = true;
    d->growthState = "prepared";
    d->growthTime = 0;
    d->snapshot.preparedAt = mach_absolute_time();
    OSSynchronizeIO();
    fR44Mapper = d;
    return true;
}

// R71-B: the first real mapping request is the only moment the actual demand is
// known, and the only moment a rebuild is provably safe. The DTE still names a
// passthrough root and no PTE has been handed to the client, so the table area
// can be replaced without invalidating anything and without a rollback path that
// would have to undo published translations.
//
// A failed growth is not a failed mapping: the prepared arena stays installed and
// the capacity evidence records that the ceiling was needed but unavailable.
bool org_example_AMDMapperProbe::r44GrowBeforeFirstMap(R44MapperState *d) {
    if (!d || d->growthAttempted) return false;
    d->growthAttempted = true;
    // Normally unreachable: the caller only invokes this before activation.
    if (!r44GrowthOpen() || d->snapshot.liveCount) {
        d->growthState = "closed-live";
        return false;
    }
    const r44mapper::Profile *prepared = r44PreparedProfile();
    const r44mapper::Profile *target =
        r44mapper::profileForFirstMapGrowth(prepared, r44CeilingProfile());
    if (!target) {
        d->growthState = "not-needed";
        return false;
    }
    IOBufferMemoryDescriptor *tables = nullptr;
    UInt64 tablePA = 0;
    if (!r44AllocateTableArea(tables, (UInt64)target->tablePages * M2B2_PAGE_SIZE,
                              tablePA)) {
        d->growthState = "failed-tables";
        return false;
    }
    auto *fresh = (R44MapperState *)IOMalloc(sizeof(R44MapperState));
    if (!fresh) {
        tables->release();
        d->growthState = "failed-state";
        return false;
    }
    bzero(fresh, sizeof(*fresh));
    if (!r44BuildArena(fresh, (volatile UInt64 *)tables->getBytesNoCopy(), tablePA,
                       target->tablePages, M2B2_PAGE_MODE_4_LEVEL, *target)) {
        IOFree(fresh, sizeof(*fresh));
        tables->release();
        d->growthState = "failed-arena";
        return false;
    }
    // Adopt in one step. No field of d is cleared, so the lock, the counters and
    // the accumulated snapshot evidence survive the swap untouched.
    void *oldArena = d->arena;
    const size_t oldBytes = d->arenaBytes;
    d->arena = fresh->arena; d->arenaBytes = fresh->arenaBytes;
    d->mappings = fresh->mappings;
    d->physicalByPage = fresh->physicalByPage;
    d->slotByStartPage = fresh->slotByStartPage;
    d->liveSlots = fresh->liveSlots;
    d->leaves = fresh->leaves;
    d->allocator = fresh->allocator;
    d->records = fresh->records; d->pages = fresh->pages;
    d->tables = fresh->tables; d->tablePA = fresh->tablePA;
    d->snapshot.capacityMaps = fresh->snapshot.capacityMaps;
    d->snapshot.capacityPages = fresh->snapshot.capacityPages;
    d->snapshot.maxMapPages = fresh->snapshot.maxMapPages;
    d->snapshot.maxRuns = fresh->snapshot.maxRuns;
    d->snapshot.iovaBytes = fresh->snapshot.iovaBytes;
    d->snapshot.rootPA = fresh->snapshot.rootPA;
    d->snapshot.ptBytes = fresh->snapshot.ptBytes;
    d->snapshot.rootLevel = fresh->snapshot.rootLevel;
    d->snapshot.tablePages = fresh->snapshot.tablePages;
    fresh->arena = nullptr;   // ownership moved into d
    IOFree(fresh, sizeof(*fresh));
    // The domain is the platform's view of the same capacity; the DTE is written
    // from tablePA at first activation, which has not happened yet.
    r44AdoptGrownTables(tables, tablePA, target->tablePages, *target);
    if (oldArena) IOFree(oldArena, oldBytes);
    d->grown = true;
    d->growthState = "grown";
    d->growthTime = mach_absolute_time();
    IOLog("AMDMapperProbe: grew %s -> %s (records=%u pages=%u tables=%u)\n",
          prepared ? prepared->name : "unknown", target->name,
          target->records, target->pages, target->tablePages);
    // Publish the decision immediately: the raw snapshot is RPC-triggered, and a
    // capacity change must not be invisible until somebody asks for one.
    if (fNicDevice) {
        fNicDevice->setProperty("r44-profile", target->name);
        fNicDevice->setProperty("r44-capacity-grown", "yes");
        fNicDevice->setProperty("r44-profile-grown-from",
            prepared ? prepared->name : "unknown");
        // The length argument is required: a bare UInt64 selects the bool
        // overload and publishes "Yes" instead of the number.
        fNicDevice->setProperty("r44-table-bytes",
            (unsigned long long)((UInt64)target->tablePages * M2B2_PAGE_SIZE), 64);
        fNicDevice->setProperty("r44-map-window-bytes",
            (unsigned long long)((UInt64)target->pages * 4096ULL), 64);
        fNicDevice->setProperty("r44-profile-records", target->records, 32);
        fNicDevice->setProperty("r44-profile-pages", target->pages, 32);
    }
    setProperty("r44-capacity-grown", "yes");
    setProperty("r44-growth-state", d->growthState);
    return true;
}

bool org_example_AMDMapperProbe::r44QuiesceMappings() {
    auto *d = fR44Mapper;
    if (!d) return true;
    IOLockLock(d->lock);
    const bool drained = !d->snapshot.liveCount;
    if (drained) {
        d->accepting = false;
        d->snapshot.flags &= ~r44mapper::kAccepting;
    }
    IOLockUnlock(d->lock);
    return drained;
}

// TODO(R47-PM-HARDWARE): implemented from the existing lifetime/command
// contracts; real system sleep/resume validation is pending. R47 exercises
// normal networking only and does not trigger this transition for testing.
IOReturn org_example_AMDMapperProbe::r47PowerTransition(UInt32 operation) {
    auto *d = fR44Mapper;
    if (!d) return kIOReturnNotReady;
    // Lock order is Lucy command gate -> mapper lock. The backend never
    // calls into the driver. PTE edits, CWs, snapshots and PM share this lock.
    IOLockLock(d->lock);
    if (!r52PowerSupported()) {
        IOLockUnlock(d->lock);
        return kIOReturnUnsupported;
    }
    if ((operation == 1 && !d->accepting) ||
        (operation == 2 && d->accepting)) {
        IOLockUnlock(d->lock);
        return kIOReturnNotReady;
    }
    bool ok = false;
    if (operation == 1) {
        d->accepting = false;
        d->snapshot.flags &= ~r44mapper::kAccepting;
        if (d->resumeLive) { d->resumeLive->release(); d->resumeLive = nullptr; }
        if (d->resumePT) { d->resumePT->release(); d->resumePT = nullptr; }
        d->capturePowerBoundary(d->suspendLive, d->suspendPT);
        ok = r47SuspendAuto();
    } else if (operation == 2) {
        ok = r47ResumeAuto();
        if (ok) {
            // Exact retained records/PT are exported before any ordinary
            // mapping can run again. Allocation failure invalidates evidence,
            // but does not turn a successful hardware wake into a PM failure.
            d->capturePowerBoundary(d->resumeLive, d->resumePT);
            d->accepting = true;
            d->snapshot.flags |= r44mapper::kAccepting;
        }
    }
    if (!ok) d->snapshot.flags |= r44mapper::kFailed;
    IOLockUnlock(d->lock);
    return ok ? kIOReturnSuccess : kIOReturnIOError;
}

IOReturn org_example_AMDMapperProbe::r63SetRequesterDMA(bool park) {
    auto *m = fR44Mapper;
    if (!m) return kIOReturnNotReady;
    IOLockLock(m->lock);
    const IOReturn result = m->accepting ? r63SwitchRequesterDMA(park) : kIOReturnNotReady;
    if (result == kIOReturnIOError) {
        m->accepting = false;
        m->snapshot.flags |= r44mapper::kFailed;
        m->snapshot.flags &= ~r44mapper::kAccepting;
    }
    IOLockUnlock(m->lock);
    return result;
}

UInt32 org_example_AMDMapperProbe::r44LiveMappings() const {
    auto *d = fR44Mapper;
    if (!d) return 0;
    IOLockLock(d->lock);
    const UInt32 count = d->snapshot.liveCount;
    IOLockUnlock(d->lock);
    return count;
}

bool org_example_AMDMapperProbe::r44ReleaseMappings() {
    auto *d = fR44Mapper;
    if (!d) return true;
    // The platform closes admission and restores its hardware before release.
    IOLockLock(d->lock);
    const bool release = !d->accepting && !d->snapshot.liveCount;
    IOLockUnlock(d->lock);
    if (!release) return false;
    fR44Mapper = nullptr;
    if (d->suspendLive) d->suspendLive->release();
    if (d->suspendPT) d->suspendPT->release();
    if (d->resumeLive) d->resumeLive->release();
    if (d->resumePT) d->resumePT->release();
    if (d->arena) IOFree(d->arena, d->arenaBytes);
    IOLockFree(d->lock); IOFree(d, sizeof(*d));
    return true;
}

IOReturn org_example_AMDMapperProbe::r44MapMemory(
    IOMemoryDescriptor *memory, uint64_t descriptorOffset, uint64_t length,
    uint32_t mapOptions, const IODMAMapSpecification *mapSpecification,
    IODMACommand *dmaCommand, const IODMAMapPageList *pageList,
    uint64_t *mapAddress, uint64_t *mapLength) {
    if (mapAddress) *mapAddress = 0;
    if (mapLength) *mapLength = 0;
    auto *d = fR44Mapper;
    if (!d) return kIOReturnNotReady;
    IOLockLock(d->lock);
    auto &s = d->snapshot;
    ++s.mapCalls;
    IOReturn result = kIOReturnUnsupported;
    do {
        if (!d->accepting || fR63DMAParked) { result = kIOReturnNotReady; break; }
        if (!memory || !mapAddress || !mapLength || !length ||
            descriptorOffset > memory->getLength() ||
            length > memory->getLength() - descriptorOffset) {
            result = kIOReturnBadArgument; break;
        }
        // Publish the largest request actually seen so a capacity decision does
        // not have to guess what a third-party client asks for.
        if (length > fR69MaxLength) fR69MaxLength = length;
        if (length > (UInt64)d->allocator.maxMapPages * 4096ULL) {
            ++fR69RejectedLength; break;
        }
        if (mapOptions & (kIODMAMapFixedAddress | kIODMAMapIdentityMap |
                          kIODMAMapDeviceMemory)) {
            ++fR69RejectedOptions; break;
        }
        const UInt64 permissions =
            ((mapOptions & kIODMAMapReadAccess) ? amdpte::PTE_IR : 0) |
            ((mapOptions & kIODMAMapWriteAccess) ? amdpte::PTE_IW : 0);
        if (!permissions) { result = kIOReturnBadArgument; break; }
        const UInt64 alignment = (mapSpecification && mapSpecification->alignment)
            ? mapSpecification->alignment : 1;
        const unsigned bits = (mapSpecification && mapSpecification->numAddressBits)
            ? mapSpecification->numAddressBits : 64;
        if ((alignment & (alignment - 1)) || alignment > r44mapper::kBase ||
            bits > 64 || bits < 32) { ++fR69RejectedBits; break; }

        // Use the public wired-descriptor walk; the SDK deliberately makes
        // upl_page_info opaque. A pageList provides the first-offset check.
        ++s.walks;
        auto &layout = d->walkScratch;
        probeLayoutInto(layout, memory, descriptorOffset, length, r44mapper::kRuns);
        if (layout.pages > fR69MaxPages) fR69MaxPages = layout.pages;
        if (layout.runs > fR69MaxRuns) fR69MaxRuns = layout.runs;
        if (layout.error || !layout.runs || layout.totalBytes != length ||
            !layout.pages || layout.pages > d->allocator.maxMapPages) {
            ++fR69RejectedLayout; break;
        }
        if ((pageList && pageList->pageOffset != layout.firstOffset) ||
            (layout.firstOffset & (alignment - 1))) break;
        bool physicalValid = true;
        for (UInt32 i = 0; i < layout.runs; ++i) {
            const auto &run = layout.run[i];
            if (!run.pa || run.pa >= (1ULL << 52) ||
                run.bytes > (1ULL << 52) - run.pa) physicalValid = false;
        }
        if (!physicalValid) break;

        // R71-B: the first admissible mapping is the only point where the real
        // demand is known and a rebuild cannot disturb anything - no PTE has been
        // published and the DTE still names a passthrough root. Growth mutates d
        // in place, so every pointer above stays valid, including this one. The
        // call is a no-op unless the domain is still open for growth.
        r44GrowBeforeFirstMap(d);

        const unsigned slot = d->nextSlot(0, false);
        if (slot == d->records) {
            ++fR69RejectedRecords; result = kIOReturnNoResources; break;
        }
        const unsigned alignmentPages = alignment > 4096 ? (unsigned)(alignment / 4096) : 1;
        unsigned basePage = 0;
        if (!d->allocateRange(layout.pages, basePage, alignmentPages)) {
            ++fR69RejectedNoRange; result = kIOReturnNoResources; break;
        }
        const UInt64 address = r44mapper::kBase + basePage * 4096ULL + layout.firstOffset;
        const UInt64 returnedLength = layout.discontig
            ? layout.pages * 4096ULL - layout.firstOffset : length;
        // Check the complete returned IOVA span against this caller's actual
        // address width. Physical pages can remain anywhere below the PA limit;
        // a 32-bit DMA constraint applies to IOVA, not backing RAM.
        if (bits < 64 && (address >= (1ULL << bits) ||
                         returnedLength > (1ULL << bits) - address)) {
            amdtx::release(d->allocator, basePage, layout.pages); break;
        }
        bool empty = d->slotByStartPage[basePage] == 0;
        for (unsigned i = 0; i < layout.pages; ++i)
            if (d->leaf(basePage + i)) empty = false;
        if (!empty) {
            amdtx::release(d->allocator, basePage, layout.pages);
            d->accepting = false; s.flags |= r44mapper::kFailed;
            s.flags &= ~r44mapper::kAccepting;
            result = kIOReturnInternalError; break;
        }

        auto &mapping = d->mappings[slot];
        bzero(&mapping, sizeof(mapping));
        mapping.memory = memory; mapping.command = dmaCommand;
        d->setSlotLive(slot, true);
        auto &record = mapping.record;
        record.handle = ++d->nextHandle; record.firstPA = layout.run[0].pa;
        record.mapAddress = address; record.mapLength = returnedLength;
        record.descriptorOffset = descriptorOffset; record.length = length;
        record.recordIndex = slot; record.basePage = basePage;
        d->slotByStartPage[basePage] = static_cast<UInt16>(slot + 1);
        record.pages = layout.pages; record.runs = layout.runs; record.options = mapOptions;
        UInt32 highPages = 0;
        for (unsigned i = 0; i < layout.runs; ++i) {
            const auto &run = layout.run[i];
            for (unsigned j = 0; j < run.pageBytes / 4096U; ++j) {
                const unsigned localPage = (unsigned)(run.slot / 4096ULL) + j;
                const UInt64 physical = (run.pa & ~4095ULL) + j * 4096ULL;
                d->physicalByPage[basePage + localPage] = physical;
                if (physical >= (1ULL << 32)) ++highPages;
                d->leaf(basePage + localPage) = amdpte::makeDefaultLeaf(1, physical, permissions);
            }
        }
        OSSynchronizeIO();
        record.tPublish = mach_absolute_time(); record.state = r44mapper::kMapPublished;
        ++s.liveCount;
        if (s.liveCount > s.peakMaps) s.peakMaps = s.liveCount;
        if (layout.pages > s.maxObservedPages) s.maxObservedPages = layout.pages;
        if (layout.runs > s.maxObservedRuns) s.maxObservedRuns = layout.runs;
        // First map activates the DTE. Later maps need an INV/CW only when
        // the actual controller can cache non-present translations.
        bool skipped = false;
        const bool synchronized = r44Invalidate(false,
            r44mapper::kBase + record.basePage * 4096ULL,
            record.pages * 4096ULL, true, &skipped);
        if (!skipped) ++s.invalidates;
        if (!synchronized) {
            ++s.invalidateFailures;
            d->accepting = false; s.flags |= r44mapper::kFailed;
            s.flags &= ~r44mapper::kAccepting;
            d->exportRecord(record, s.lastMap);
            r70DMAFailStop("map invalidation unconfirmed", record);
        }
        record.tMapComplete = mach_absolute_time(); record.state |= r44mapper::kMapConfirmed;
        ++s.mapOk;
        // Mirror the counters the S3 measurement reads; published outside the
        // lock by r69PublishCapacity() only when they change.
        fR69MapOk = s.mapOk;
        // s.livePages/s.peakPages are only refreshed when a snapshot is
        // published, so read the allocator directly for the measurement.
        fR69LiveMaps = s.liveCount;
        fR69LivePages = d->allocator.livePages;
        fR69PeakMaps = s.peakMaps;
        fR69PeakPages = d->allocator.peakPages;
        if (bits == 32) ++d->map32Ok;
        if (highPages) ++d->mapHighPAOk;
        d->mappedHighPAPages += highPages;
        if (!d->minMapBits || bits < d->minMapBits) d->minMapBits = bits;
        if (bits > d->maxMapBits) d->maxMapBits = bits;
        if (descriptorOffset) ++s.offsetMaps;
        if (layout.discontig) ++s.fragmentedMaps;
        if (!s.firstMapAt) s.firstMapAt = record.tMapComplete;
        s.lastMapAt = record.tMapComplete;
        d->exportRecord(record, s.lastMap);
        *mapAddress = address; *mapLength = returnedLength;
        result = kIOReturnSuccess;
    } while (false);
    if (result != kIOReturnSuccess) ++s.mapRejected;
    IOLockUnlock(d->lock);
    r69PublishCapacity();
    return result;
}

// Capacity evidence for third-party clients. Called without the mapper lock so
// a property publication can never sit inside the DMA path's critical section.
void org_example_AMDMapperProbe::r69PublishCapacity() {
    const UInt64 rejects = (UInt64)fR69RejectedLength + fR69RejectedOptions +
        fR69RejectedLayout + fR69RejectedRecords + fR69RejectedNoRange +
        fR69RejectedBits;
    // Peak/max/reject changes are rare and must be published immediately. The
    // monotonic counters move on every map, so they are only republished once
    // 128 of them accumulate: this keeps the DMA path out of the registry for
    // all but one call in 128.
    const bool rareChange =
        fR69MaxLength != fR69PublishedMaxLength ||
        fR69MaxPages != fR69PublishedMaxPages ||
        fR69MaxRuns != fR69PublishedMaxRuns ||
        rejects != fR69PublishedRejects ||
        fR69PeakMaps != fR69PublishedPeakMaps ||
        fR69PeakPages != fR69PublishedPeakPages;
    const bool liveChange =
        fR69LiveMaps != fR69PublishedLiveMaps ||
        fR69LivePages != fR69PublishedLivePages ||
        fR69MapOk - fR69PublishedMapOk >= 128 ||
        fR69UnmapOk - fR69PublishedUnmapOk >= 128;
    if (!rareChange && !liveChange) return;
    fR69PublishedMaxLength = fR69MaxLength;
    fR69PublishedMaxPages = fR69MaxPages;
    fR69PublishedMaxRuns = fR69MaxRuns;
    fR69PublishedRejects = rejects;
    fR69PublishedMapOk = fR69MapOk;
    fR69PublishedUnmapOk = fR69UnmapOk;
    fR69PublishedLiveMaps = fR69LiveMaps;
    fR69PublishedLivePages = fR69LivePages;
    fR69PublishedPeakMaps = fR69PeakMaps;
    fR69PublishedPeakPages = fR69PeakPages;
    setProperty("r44-map-ok-live", fR69MapOk, 64);
    setProperty("r44-unmap-ok-live", fR69UnmapOk, 64);
    setProperty("r44-live-maps-live", fR69LiveMaps, 32);
    setProperty("r44-live-pages-live", fR69LivePages, 32);
    setProperty("r44-peak-maps-live", fR69PeakMaps, 32);
    setProperty("r44-peak-pages-live", fR69PeakPages, 32);
    setProperty("r69-max-map-length", fR69MaxLength, 64);
    setProperty("r69-max-map-pages", fR69MaxPages, 64);
    setProperty("r69-max-map-runs", fR69MaxRuns, 64);
    setProperty("r69-rejects-length", (unsigned long long)fR69RejectedLength, 32);
    setProperty("r69-rejects-options", (unsigned long long)fR69RejectedOptions, 32);
    setProperty("r69-rejects-layout", (unsigned long long)fR69RejectedLayout, 32);
    setProperty("r69-rejects-records", (unsigned long long)fR69RejectedRecords, 32);
    setProperty("r69-rejects-norange", (unsigned long long)fR69RejectedNoRange, 32);
    setProperty("r69-rejects-bits", (unsigned long long)fR69RejectedBits, 32);
}

IOReturn org_example_AMDMapperProbe::r44UnmapMemory(
    IOMemoryDescriptor *memory, IODMACommand *dmaCommand,
    uint64_t mapAddress, uint64_t mapLength) {
    auto *d = fR44Mapper;
    if (!d) return kIOReturnNotReady;
    IOLockLock(d->lock);
    auto &s = d->snapshot;
    ++s.unmapCalls;
    // Reject unrelated/invalid calls normally, even for a suspended or failed
    // domain. Only an exact owned live mapping can put backing RAM at risk.
    IOReturn result = d->accepting ? kIOReturnBadArgument : kIOReturnNotReady;
    do {
        if (mapAddress < r44mapper::kBase) break;
        const UInt64 page = (mapAddress - r44mapper::kBase) / 4096;
        if (page >= d->pages) break;
        const UInt16 owner = d->slotByStartPage[page];
        if (!owner || owner > d->records) break;
        const unsigned slot = owner - 1U;
        auto &mapping = d->mappings[slot];
        auto &record = mapping.record;
        if (!d->slotLive(slot) || record.basePage != page || record.mapAddress != mapAddress) break;
        if (mapping.memory != memory || mapping.command != dmaCommand ||
            record.mapLength != mapLength) break;
        // An earlier allocator failure may leave a record whose hardware
        // retirement already completed. Keep that safe leak closed, not fatal.
        if (record.state & r44mapper::kUnmapConfirmed) {
            result = kIOReturnInternalError; break;
        }
        if (!d->accepting)
            r70DMAFailStop("owned unmap while domain unavailable", record);
        if (record.state != (r44mapper::kMapPublished | r44mapper::kMapConfirmed))
            r70DMAFailStop("owned unmap with unretired state", record);
        for (unsigned i = 0; i < record.pages; ++i) d->leaf(record.basePage + i) = 0;
        OSSynchronizeIO();
        record.tClear = mach_absolute_time(); record.state |= r44mapper::kClearPublished;
        ++s.invalidates;
        if (!r44Invalidate(false, r44mapper::kBase + record.basePage * 4096ULL,
                           record.pages * 4096ULL)) {
            ++s.invalidateFailures;
            d->accepting = false; s.flags |= r44mapper::kFailed;
            s.flags &= ~r44mapper::kAccepting;
            d->exportRecord(record, s.lastUnmap);
            r70DMAFailStop("unmap invalidation unconfirmed", record);
        }
        record.tUnmapComplete = mach_absolute_time(); record.state |= r44mapper::kUnmapConfirmed;
        d->exportRecord(record, s.lastUnmap);
        // A cleared PTE alone is not retirement: pages become reusable only
        // after the INV_IOMMU_PAGES CompletionWait has returned successfully.
        if (!amdtx::release(d->allocator, record.basePage, record.pages)) {
            d->accepting = false; s.flags |= r44mapper::kFailed;
            s.flags &= ~r44mapper::kAccepting;
            result = kIOReturnInternalError; break;
        }
        d->slotByStartPage[page] = 0;
        --s.liveCount; ++s.unmapOk;
        fR69UnmapOk = s.unmapOk;
        fR69LiveMaps = s.liveCount;
        fR69LivePages = d->allocator.livePages;
        s.lastUnmapAt = record.tUnmapComplete;
        d->setSlotLive(slot, false);
        mapping.memory = nullptr; mapping.command = nullptr;
        result = kIOReturnSuccess;
    } while (false);
    if (result != kIOReturnSuccess) ++s.unmapRejected;
    IOLockUnlock(d->lock);
    return result;
}

bool org_example_AMDMapperProbe::r44Translate(uint64_t address, uint64_t *physical) const {
    auto *d = fR44Mapper;
    if (!d || !physical || address < r44mapper::kBase ||
        address - r44mapper::kBase >= (UInt64)d->pages * 4096ULL) return false;
    IOLockLock(d->lock);
    const auto decoded = amdpte::decodePte(d->leaf((unsigned)((address - r44mapper::kBase) / 4096)), 1);
    const bool present = decoded.kind == amdpte::PTE_LEAF_DEFAULT;
    if (present) *physical = decoded.outPA + (address & 4095ULL);
    IOLockUnlock(d->lock);
    return present;
}

void org_example_AMDMapperProbe::r44PublishMappings(OSDictionary **copy) {
    if (copy) *copy = nullptr;
    auto *d = fR44Mapper;
    if (!d) {
        r44PublishAuto();
        if (copy) *copy = dictionaryWithProperties();
        return;
    }
    IOLockLock(d->lock);
    auto &s = d->snapshot;
    s.livePages = d->allocator.livePages; s.peakPages = d->allocator.peakPages;
    s.reusedAllocations = d->allocator.reusedAllocations;
    ++s.snapshotSequence; s.snapshotTime = mach_absolute_time();
    OSData *summary = OSData::withBytes(&s, sizeof(s));
    OSData *active = d->copyLiveRecords();
    OSData *tables = OSData::withBytes((const void *)d->tables, (unsigned)s.ptBytes);
    if (summary && active && tables) {
        setProperty("r44-mapper-raw", summary);
        setProperty("r44-live-raw", active);
        setProperty("r44-pt-raw", tables);
        setProperty("r44-mapper-abi", r44mapper::kVersion, 32);
        setProperty("r44-live-maps", s.liveCount, 32);
        setProperty("r44-live-pages", s.livePages, 32);
        // S3 measurement: peaks since this domain was prepared, published with
        // the ordinary snapshot so a read never races the DMA path.
        setProperty("r44-peak-maps", s.peakMaps, 32);
        setProperty("r44-peak-pages", s.peakPages, 32);
        setProperty("r44-map-ok", s.mapOk, 64);
        setProperty("r44-unmap-ok", s.unmapOk, 64);
        setProperty("r44-map-rejected", s.mapRejected, 64);
        setProperty("r44-unmap-rejected", s.unmapRejected, 64);
        setProperty("r44-snapshot-sequence", s.snapshotSequence, 64);
        setProperty("r48-map32-ok", d->map32Ok, 64);
        setProperty("r48-map-high-pa-ok", d->mapHighPAOk, 64);
        setProperty("r48-mapped-high-pa-pages", d->mappedHighPAPages, 64);
        setProperty("r48-map-min-bits", d->minMapBits, 32);
        setProperty("r48-map-max-bits", d->maxMapBits, 32);
        // R71-B: growth state. Also published directly at the swap, because the
        // raw snapshot above is only produced when a reader asks for one.
        setProperty("r44-capacity-grown", d->grown ? "yes" : "no");
        setProperty("r44-growth-state", d->growthState ? d->growthState : "unknown");
        setProperty("r44-growth-time", d->growthTime, 64);
    }
    if (summary) summary->release();
    if (active) active->release();
    if (tables) tables->release();
    auto boundary = [this](const char *key, OSData *data) {
        if (data) setProperty(key, data);
        else removeProperty(key);
    };
    boundary("r47-suspend-live-raw", d->suspendLive);
    boundary("r47-suspend-pt-raw", d->suspendPT);
    boundary("r47-resume-live-raw", d->resumeLive);
    boundary("r47-resume-pt-raw", d->resumePT);
    setProperty("r47-pm-snapshots-valid",
        d->suspendLive && d->suspendPT && d->resumeLive && d->resumePT ? "yes" : "no");
    // Keep this domain's raw state, PTE bytes and hardware counters in one
    // snapshot. Hardware export takes only the controller lock after this lock.
    r44PublishAuto();
    if (copy) *copy = dictionaryWithProperties();
    IOLockUnlock(d->lock);
}
