// R44: ordinary per-device IOMapper backend. All normal IODMACommand objects
// share one bounded allocator; there are no private driver roles or bindings.
#include "AMDMapperProbeInternal.hpp"
#include "amd_iommu_tx_core.hpp"
#include "amd_iommu_mapper_abi.hpp"
#include <IOKit/IOLocks.h>

struct org_example_AMDMapperProbe::R44MapperState {
    struct Mapping {
        IOMemoryDescriptor *memory;
        IODMACommand *command;
        r44mapper::Record record;
    };
    IOLock *lock;
    volatile UInt64 *tables;
    volatile UInt64 *leaves[r44mapper::kPages / 512];
    amdtx::BoundedAllocator<r44mapper::kPages, r44mapper::kMapPages> allocator;
    Mapping mappings[r44mapper::kRecords];
    // Sole per-slot liveness state; accessed under the domain lock.
    amdtx::u64 liveSlots[(r44mapper::kRecords + 63) / 64];
    // Per-domain start index: zero means no mapping starts on this IOVA page.
    static_assert(r44mapper::kRecords <= 0xffffU, "slot + 1 must fit in UInt16");
    UInt16 slotByStartPage[r44mapper::kPages];
    r44mapper::Snapshot snapshot;
    OSData *suspendLive, *suspendPT, *resumeLive, *resumePT;
    UInt64 nextHandle;
    // R48 observes successful caller address constraints outside the raw ABI.
    // Only snapshot publication writes registry properties, never the hot path.
    UInt64 map32Ok, mapHighPAOk, mappedHighPAPages;
    UInt32 minMapBits, maxMapBits;
    bool accepting;

    volatile UInt64 &leaf(unsigned page) { return leaves[page / 512][page % 512]; }

    unsigned nextSlot(unsigned from, bool occupied) const {
        return amdtx::findNextBitmapPage(liveSlots, from, r44mapper::kRecords, occupied);
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

    void capturePowerBoundary(OSData *&live, OSData *&pt) {
        if (live) { live->release(); live = nullptr; }
        if (pt) { pt->release(); pt = nullptr; }
        live = OSData::withCapacity((snapshot.liveCount ? snapshot.liveCount : 1) *
                                    sizeof(r44mapper::Record));
        if (live) {
            for (unsigned i = nextSlot(0, true); i < r44mapper::kRecords;
                 i = nextSlot(i + 1, true)) {
                if (!live->appendBytes(&mappings[i].record, sizeof(r44mapper::Record))) {
                    live->release(); live = nullptr;
                    break;
                }
            }
        }
        pt = OSData::withBytes((const void *)tables, (unsigned)snapshot.ptBytes);
    }
};

bool org_example_AMDMapperProbe::r44PrepareMappings(
    volatile UInt64 *tables, UInt64 tablePA, UInt32 tablePages, UInt32 rootLevel) {
    if (fR44Mapper || !tables || !tablePA || (tablePA & 4095ULL) ||
        tablePages < 11 || (rootLevel != 3 && rootLevel != 4)) return false;
    auto *d = (R44MapperState *)IOMalloc(sizeof(R44MapperState));
    if (!d) return false;
    bzero(d, sizeof(*d));
    d->lock = IOLockAlloc();
    if (!d->lock) { IOFree(d, sizeof(*d)); return false; }
    d->tables = tables;
    amdsparse::Arena arena = {tables, tablePA, tablePages, 1, rootLevel,
                              tablePA, 0, 0, nullptr};
    for (unsigned i = 0; i < r44mapper::kPages / 512; ++i) {
        d->leaves[i] = amdtx::prepareAt(arena, r44mapper::kBase + i * 0x200000ULL, 512);
        if (!d->leaves[i]) {
            IOLockFree(d->lock); IOFree(d, sizeof(*d)); return false;
        }
    }
    auto &s = d->snapshot;
    s.version = r44mapper::kVersion; s.bytes = sizeof(s);
    s.flags = r44mapper::kPrepared | r44mapper::kAccepting;
    s.capacityMaps = r44mapper::kRecords; s.capacityPages = r44mapper::kPages;
    s.maxMapPages = r44mapper::kMapPages; s.maxRuns = r44mapper::kRuns;
    s.iovaBase = r44mapper::kBase; s.iovaBytes = r44mapper::kPages * 4096ULL;
    s.rootPA = tablePA; s.ptBytes = tablePages * 4096ULL;
    s.rootLevel = rootLevel; s.tablePages = tablePages;
    s.preparedAt = mach_absolute_time();
    d->accepting = true;
    OSSynchronizeIO();
    fR44Mapper = d;
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
        if (!d->accepting) { result = kIOReturnNotReady; break; }
        if (!memory || !mapAddress || !mapLength || !length ||
            descriptorOffset > memory->getLength() ||
            length > memory->getLength() - descriptorOffset) {
            result = kIOReturnBadArgument; break;
        }
        if (length > r44mapper::kMapPages * 4096ULL ||
            (mapOptions & (kIODMAMapFixedAddress | kIODMAMapIdentityMap |
                           kIODMAMapDeviceMemory))) break;
        const UInt64 permissions =
            ((mapOptions & kIODMAMapReadAccess) ? amdpte::PTE_IR : 0) |
            ((mapOptions & kIODMAMapWriteAccess) ? amdpte::PTE_IW : 0);
        if (!permissions) { result = kIOReturnBadArgument; break; }
        const UInt64 alignment = (mapSpecification && mapSpecification->alignment)
            ? mapSpecification->alignment : 1;
        const unsigned bits = (mapSpecification && mapSpecification->numAddressBits)
            ? mapSpecification->numAddressBits : 64;
        if ((alignment & (alignment - 1)) || alignment > r44mapper::kBase ||
            bits > 64 || bits < 32) break;

        // Use the public wired-descriptor walk; the SDK deliberately makes
        // upl_page_info opaque. A pageList provides the first-offset check.
        ++s.walks;
        const auto layout = probeLayout<r44mapper::kRuns>(
            memory, descriptorOffset, length, r44mapper::kRuns);
        if (layout.error || !layout.runs || layout.totalBytes != length ||
            !layout.pages || layout.pages > r44mapper::kMapPages) break;
        if ((pageList && pageList->pageOffset != layout.firstOffset) ||
            (layout.firstOffset & (alignment - 1))) break;
        bool physicalValid = true;
        for (UInt32 i = 0; i < layout.runs; ++i) {
            const auto &run = layout.run[i];
            if (!run.pa || run.pa >= (1ULL << 52) ||
                run.bytes > (1ULL << 52) - run.pa) physicalValid = false;
        }
        if (!physicalValid) break;

        const unsigned slot = d->nextSlot(0, false);
        if (slot == r44mapper::kRecords) { result = kIOReturnNoResources; break; }
        const unsigned alignmentPages = alignment > 4096 ? (unsigned)(alignment / 4096) : 1;
        unsigned basePage = 0;
        if (!amdtx::allocate(d->allocator, layout.pages, basePage, alignmentPages)) {
            result = kIOReturnNoResources; break;
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
                record.physical[localPage] = physical;
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
            s.lastMap = record;
            result = kIOReturnIOError; break;
        }
        record.tMapComplete = mach_absolute_time(); record.state |= r44mapper::kMapConfirmed;
        ++s.mapOk;
        if (bits == 32) ++d->map32Ok;
        if (highPages) ++d->mapHighPAOk;
        d->mappedHighPAPages += highPages;
        if (!d->minMapBits || bits < d->minMapBits) d->minMapBits = bits;
        if (bits > d->maxMapBits) d->maxMapBits = bits;
        if (descriptorOffset) ++s.offsetMaps;
        if (layout.discontig) ++s.fragmentedMaps;
        if (!s.firstMapAt) s.firstMapAt = record.tMapComplete;
        s.lastMapAt = record.tMapComplete; s.lastMap = record;
        *mapAddress = address; *mapLength = returnedLength;
        result = kIOReturnSuccess;
    } while (false);
    if (result != kIOReturnSuccess) ++s.mapRejected;
    IOLockUnlock(d->lock);
    return result;
}

IOReturn org_example_AMDMapperProbe::r44UnmapMemory(
    IOMemoryDescriptor *memory, IODMACommand *dmaCommand,
    uint64_t mapAddress, uint64_t mapLength) {
    auto *d = fR44Mapper;
    if (!d) return kIOReturnNotReady;
    IOLockLock(d->lock);
    auto &s = d->snapshot;
    ++s.unmapCalls;
    // Sleep retains live mappings. Reject before clearing a single PTE or
    // touching the command ring while the hardware is unavailable.
    if (!d->accepting) {
        ++s.unmapRejected;
        IOLockUnlock(d->lock);
        return kIOReturnNotReady;
    }
    IOReturn result = kIOReturnBadArgument;
    do {
        if (mapAddress < r44mapper::kBase) break;
        const UInt64 page = (mapAddress - r44mapper::kBase) / 4096;
        if (page >= r44mapper::kPages) break;
        const UInt16 owner = d->slotByStartPage[page];
        if (!owner || owner > r44mapper::kRecords) break;
        const unsigned slot = owner - 1U;
        auto &mapping = d->mappings[slot];
        auto &record = mapping.record;
        if (!d->slotLive(slot) || record.basePage != page || record.mapAddress != mapAddress) break;
        if (mapping.memory != memory || mapping.command != dmaCommand ||
            record.mapLength != mapLength ||
            record.state != (r44mapper::kMapPublished | r44mapper::kMapConfirmed)) break;
        for (unsigned i = 0; i < record.pages; ++i) d->leaf(record.basePage + i) = 0;
        OSSynchronizeIO();
        record.tClear = mach_absolute_time(); record.state |= r44mapper::kClearPublished;
        ++s.invalidates;
        if (!r44Invalidate(false, r44mapper::kBase + record.basePage * 4096ULL,
                           record.pages * 4096ULL)) {
            ++s.invalidateFailures;
            d->accepting = false; s.flags |= r44mapper::kFailed;
            s.flags &= ~r44mapper::kAccepting;
            s.lastUnmap = record;
            result = kIOReturnIOError; break;
        }
        record.tUnmapComplete = mach_absolute_time(); record.state |= r44mapper::kUnmapConfirmed;
        // A cleared PTE alone is not retirement: pages become reusable only
        // after the INV_IOMMU_PAGES CompletionWait has returned successfully.
        if (!amdtx::release(d->allocator, record.basePage, record.pages)) {
            d->accepting = false; s.flags |= r44mapper::kFailed;
            s.flags &= ~r44mapper::kAccepting;
            s.lastUnmap = record;
            result = kIOReturnInternalError; break;
        }
        d->slotByStartPage[page] = 0;
        --s.liveCount; ++s.unmapOk;
        s.lastUnmapAt = record.tUnmapComplete; s.lastUnmap = record;
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
        address - r44mapper::kBase >= r44mapper::kPages * 4096ULL) return false;
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
    OSData *active = OSData::withCapacity((s.liveCount ? s.liveCount : 1) * sizeof(r44mapper::Record));
    if (active) {
        for (unsigned i = d->nextSlot(0, true); i < r44mapper::kRecords;
             i = d->nextSlot(i + 1, true))
            active->appendBytes(&d->mappings[i].record, sizeof(r44mapper::Record));
    }
    OSData *tables = OSData::withBytes((const void *)d->tables, (unsigned)s.ptBytes);
    if (summary && active && tables) {
        setProperty("r44-mapper-raw", summary);
        setProperty("r44-live-raw", active);
        setProperty("r44-pt-raw", tables);
        setProperty("r44-mapper-abi", r44mapper::kVersion, 32);
        setProperty("r44-live-maps", s.liveCount, 32);
        setProperty("r44-live-pages", s.livePages, 32);
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
