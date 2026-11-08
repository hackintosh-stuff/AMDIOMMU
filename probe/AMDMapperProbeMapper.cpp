// R44: ordinary per-device IOMapper backend. All normal IODMACommand objects
// share one bounded allocator; there are no private driver roles or bindings.
#include "AMDMapperProbeInternal.hpp"
#include "amd_iommu_tx_core.hpp"
#include "amd_iommu_mapper_abi.hpp"
#include "amd_iommu_mapper_arena.hpp"
#include "amd_iommu_table_growth_core.hpp"
#include <IOKit/IOLocks.h>
#include <kern/debug.h>

// XNU's DMA-unmap caller can discard our error and unwire the descriptor.
// Once PTEs have been published, neither an error return nor retaining an
// IOMemoryDescriptor proves its backing pages remain wired. If retirement
// cannot be confirmed, fail-stop before returning control to that caller.
// Do not allocate, publish registry data, retry a failed ring, or drop the
// domain lock here. This is containment, not recovery or proof of device idle.
[[noreturn]] static void DMAFailStop(
    const char *reason, const mapper_abi::RecordHeader &record) {
    panic("AMDMapperProbe: unsafe DMA retirement (%s), handle=%llu "
          "iova=0x%llx length=0x%llx state=0x%x",
          reason, (unsigned long long)record.handle,
          (unsigned long long)record.mapAddress,
          (unsigned long long)record.mapLength, (unsigned)record.state);
}

struct org_maz1_AMDMapperProbe::MapperState : amdmapper::MappingArena {
    struct TableAllocation {
        IOBufferMemoryDescriptor *memory;
        mapper_abi::TableSegment segment;
    };
    // Initial 4096-page window plus six doublings to the 262144-page ceiling.
    // Record-slot growth does not allocate a page-table segment.
    static constexpr UInt32 kMaxTableAllocations = 7;
    IOLock *lock;
    volatile UInt64 *tables;
    UInt64 tablePA;
    TableAllocation tableAllocations[kMaxTableAllocations];
    UInt32 tableAllocationCount;
    // These scratch buffers and the state object stay in place across growth.
    BoundedProbeLayout<mapper_abi::kRuns> walkScratch;
    mapper_abi::Record exportScratch;
    mapper_abi::Snapshot snapshot;
    OSData *suspendLive, *suspendPT, *suspendPTSegments;
    OSData *resumeLive, *resumePT, *resumePTSegments;
    UInt64 nextHandle;
    UInt64 map32Ok, mapHighPAOk, mappedHighPAPages;
    UInt32 minMapBits, maxMapBits;
    bool accepting;
    UInt32 capacityGrowthCount;
    UInt32 recordGrowthCount, pageGrowthCount;
    UInt64 growthTime;
    const char *growthState;
    const char *growthFrom;
    const char *growthResource;
    UInt32 growthFromRecords, growthFromPages;

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

    void exportRecord(const mapper_abi::RecordHeader &header, mapper_abi::Record &out) const {
        out.header = header;
        const size_t used = header.pages * sizeof(out.physical[0]);
        memcpy(out.physical, physicalByPage + header.basePage, used);
        bzero(out.physical + header.pages, sizeof(out.physical) - used);
    }

    OSData *copyLiveRecords() {
        OSData *data = OSData::withCapacity((snapshot.liveCount ? snapshot.liveCount : 1) *
                                            sizeof(mapper_abi::Record));
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

    bool copyPageTables(OSData *&data, OSData *&segments) const {
        data = OSData::withCapacity((unsigned)snapshot.ptBytes);
        segments = OSData::withCapacity(tableAllocationCount *
                                       sizeof(mapper_abi::TableSegment));
        if (data && segments) {
            bool complete = true;
            for (UInt32 i = 0; i < tableAllocationCount; ++i) {
                const auto &allocation = tableAllocations[i];
                if (!data->appendBytes(allocation.memory->getBytesNoCopy(),
                                       (unsigned)allocation.segment.bytes) ||
                    !segments->appendBytes(&allocation.segment, sizeof(allocation.segment))) {
                    complete = false;
                    break;
                }
            }
            if (complete) return true;
        }
        if (data) { data->release(); data = nullptr; }
        if (segments) { segments->release(); segments = nullptr; }
        return false;
    }

    void capturePowerBoundary(OSData *&live, OSData *&pt, OSData *&segments) {
        if (live) { live->release(); live = nullptr; }
        if (pt) { pt->release(); pt = nullptr; }
        if (segments) { segments->release(); segments = nullptr; }
        live = copyLiveRecords();
        copyPageTables(pt, segments);
    }
};

// Only metadata moves during growth. The shared layout/copy helpers are also
// exercised by the host capacity test; the kernel owns allocation and lifetime.
static bool AllocateMapperArena(amdmapper::MappingArena &arena,
                                const mapper_abi::Capacity &capacity) {
    if (!capacity.records || capacity.records > 0xffffU ||
        !capacity.pages || (capacity.pages % 512)) return false;
    const UInt64 bytes = mapper_abi::arenaBytesFor(capacity);
    if (!bytes || bytes > mapper_abi::kMaxArenaBytes) return false;
    void *memory = IOMalloc((vm_size_t)bytes);
    if (!memory) return false;
    bzero(memory, (size_t)bytes);
    amdmapper::bindArena(arena, memory, capacity);
    return true;
}

bool org_maz1_AMDMapperProbe::PrepareMappings(
    IOBufferMemoryDescriptor *tables, UInt64 tablePA, UInt32 rootLevel,
    const mapper_abi::Profile &profile) {
    if (fMapper || !tables || !tablePA || (tablePA & 4095ULL) ||
        (rootLevel != 3 && rootLevel != 4) ||
        tables->getLength() < profile.tablePages * 4096ULL) return false;
    auto *d = (MapperState *)IOMalloc(sizeof(MapperState));
    if (!d) return false;
    bzero(d, sizeof(*d));
    d->lock = IOLockAlloc();
    if (!d->lock) { IOFree(d, sizeof(*d)); return false; }
    if (!AllocateMapperArena(*d, mapper_abi::capacityForProfile(profile))) {
        IOLockFree(d->lock);
        IOFree(d, sizeof(*d));
        return false;
    }
    d->tables = (volatile UInt64 *)tables->getBytesNoCopy();
    d->tablePA = tablePA;
    amdsparse::Arena rootArena = {d->tables, tablePA, profile.tablePages, 1,
                                  rootLevel, tablePA, 0, 0, nullptr};
    for (UInt32 i = 0; i < profile.pages / 512; ++i) {
        d->leaves[i] = amdtx::prepareAt(rootArena,
            mapper_abi::kBase + (UInt64)i * 0x200000ULL, 512);
        if (!d->leaves[i]) {
            IOFree(d->arena, d->arenaBytes);
            IOLockFree(d->lock);
            IOFree(d, sizeof(*d));
            return false;
        }
    }
    // Domain retains its root allocation; MapperState owns another reference
    // alongside the additional leaf allocations it will own after growth.
    tables->retain();
    d->tableAllocations[0] = {tables, {tablePA, 0, profile.tablePages * 4096ULL}};
    d->tableAllocationCount = 1;
    auto &snapshot = d->snapshot;
    snapshot.version = mapper_abi::kVersion;
    snapshot.bytes = sizeof(snapshot);
    snapshot.flags = mapper_abi::kPrepared | mapper_abi::kAccepting;
    snapshot.capacityMaps = profile.records;
    snapshot.capacityPages = profile.pages;
    snapshot.maxMapPages = profile.mapPages;
    snapshot.maxRuns = profile.runs;
    snapshot.iovaBase = mapper_abi::kBase;
    snapshot.iovaBytes = profile.pages * 4096ULL;
    snapshot.rootPA = tablePA;
    snapshot.ptBytes = profile.tablePages * 4096ULL;
    snapshot.rootLevel = rootLevel;
    snapshot.tablePages = profile.tablePages;
    snapshot.preparedAt = mach_absolute_time();
    d->accepting = true;
    d->growthState = "prepared";
    d->growthResource = "none";
    OSSynchronizeIO();
    fMapper = d;
    return true;
}

// Allocate and copy software metadata before linking any new hardware tables.
// The mapper lock keeps every live record and internal pointer stable until the
// new arena is adopted. Existing table allocations remain wired throughout.
bool org_maz1_AMDMapperProbe::TryGrowCapacity(
    MapperState *d, mapper_abi::CapacityResource resource) {
    const mapper_abi::Capacity current{d->records, d->pages};
    const mapper_abi::Profile *ceiling = CeilingProfile();
    mapper_abi::Capacity target{};
    if (!ceiling || !mapper_abi::nextCapacity(current, *ceiling, resource, target)) {
        d->growthState = "at-ceiling";
        return false;
    }
    amdmapper::MappingArena grown{};
    if (!AllocateMapperArena(grown, target)) {
        d->growthState = "failed-arena";
        return false;
    }
    amdmapper::copyArena(grown, *d);
    // Record-slot pressure only moves software metadata. Page-pool pressure
    // additionally extends the fixed-root tree with the required leaf tables.
    if (target.pages > current.pages) {
        const UInt32 firstLeaf = current.pages / 512;
        const UInt32 leafCount = (target.pages - current.pages) / 512;
        IOBufferMemoryDescriptor *newTables = nullptr;
        UInt64 newTablePA = 0;
        if (!AllocateTableArea(newTables, (UInt64)leafCount * 4096ULL, newTablePA)) {
            IOFree(grown.arena, grown.arenaBytes);
            d->growthState = "failed-tables";
            return false;
        }
        amdsparse::Arena rootArena = {d->tables, d->tablePA,
            (UInt32)(d->tableAllocations[0].segment.bytes / 4096), 1,
            d->snapshot.rootLevel, d->tablePA, 0, 0, nullptr};
        volatile UInt64 *directory = amdtable::leafDirectory(rootArena, mapper_abi::kBase);
        if (!amdtable::attachLeafTables(directory, firstLeaf, leafCount,
                (volatile UInt64 *)newTables->getBytesNoCopy(), newTablePA, grown.leaves)) {
            // The helper performs every check before the first PDE write.
            newTables->release();
            IOFree(grown.arena, grown.arenaBytes);
            d->growthState = "failed-page-tables";
            d->accepting = false;
            d->snapshot.flags |= mapper_abi::kFailed;
            d->snapshot.flags &= ~mapper_abi::kAccepting;
            return false;
        }
        // From this point hardware can reference the new allocation. Retain it
        // even if completion cannot be confirmed; no new IOVA is returned on failure.
        d->tableAllocations[d->tableAllocationCount++] = {newTables,
            {newTablePA, d->snapshot.ptBytes, (UInt64)leafCount * 4096ULL}};
        d->snapshot.ptBytes += (UInt64)leafCount * 4096ULL;
        d->snapshot.tablePages += leafCount;
        OSSynchronizeIO();
    }
    bool invalidated = false;
    const bool committed = CommitCapacityGrowth(target, d->snapshot.tablePages, invalidated);
    if (invalidated) ++d->snapshot.invalidates;
    if (!committed) {
        IOFree(grown.arena, grown.arenaBytes);
        if (invalidated) ++d->snapshot.invalidateFailures;
        d->growthState = "failed-synchronization";
        d->accepting = false;
        d->snapshot.flags |= mapper_abi::kFailed;
        d->snapshot.flags &= ~mapper_abi::kAccepting;
        return false;
    }
    void *oldArena = d->arena;
    const size_t oldBytes = d->arenaBytes;
    static_cast<amdmapper::MappingArena &>(*d) = grown;
    IOFree(oldArena, oldBytes);
    d->snapshot.capacityMaps = target.records;
    d->snapshot.capacityPages = target.pages;
    d->snapshot.iovaBytes = target.pages * 4096ULL;
    ++d->capacityGrowthCount;
    if (resource == mapper_abi::CapacityResource::recordSlots) {
        ++d->recordGrowthCount;
        d->growthResource = "records";
    } else {
        ++d->pageGrowthCount;
        d->growthResource = "iova-pages";
    }
    d->growthFrom = mapper_abi::profileNameForCapacity(current);
    d->growthFromRecords = current.records;
    d->growthFromPages = current.pages;
    d->growthState = "grown";
    d->growthTime = mach_absolute_time();
    IOLog("AMDMapperProbe: capacity grew for %s (records=%u -> %u pages=%u -> %u table-pages=%u)\n",
          d->growthResource, current.records, target.records, current.pages, target.pages,
          d->snapshot.tablePages);
    return true;
}

bool org_maz1_AMDMapperProbe::QuiesceMappings() {
    auto *d = fMapper;
    if (!d) return true;
    IOLockLock(d->lock);
    const bool drained = !d->snapshot.liveCount;
    if (drained) {
        d->accepting = false;
        d->snapshot.flags &= ~mapper_abi::kAccepting;
    }
    IOLockUnlock(d->lock);
    return drained;
}

// Compatibility entry point for a client that still drives PM through the
// private R47PowerTransition RPC. Since R72 the mapper also hears about system
// sleep/wake itself (registerSleepWakeInterest) and reconciles a lost controller
// from the DMA path, so PM no longer depends on this call. A client that does
// call it still gets the same admission/pairing contract.
IOReturn org_maz1_AMDMapperProbe::PowerTransition(UInt32 operation) {
    auto *d = fMapper;
    if (!d) return kIOReturnNotReady;
    // Lock order is Lucy command gate -> mapper lock. The backend never
    // calls into the driver. PTE edits, CWs, snapshots and PM share this lock.
    IOLockLock(d->lock);
    if (!PowerSupported()) {
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
        d->snapshot.flags &= ~mapper_abi::kAccepting;
        if (d->resumeLive) { d->resumeLive->release(); d->resumeLive = nullptr; }
        if (d->resumePT) { d->resumePT->release(); d->resumePT = nullptr; }
        if (d->resumePTSegments) { d->resumePTSegments->release(); d->resumePTSegments = nullptr; }
        d->capturePowerBoundary(d->suspendLive, d->suspendPT, d->suspendPTSegments);
        ok = SuspendAuto();
    } else if (operation == 2) {
        ok = ResumeAuto();
        if (ok) {
            // Exact retained records/PT are exported before any ordinary
            // mapping can run again. Allocation failure invalidates evidence,
            // but does not turn a successful hardware wake into a PM failure.
            d->capturePowerBoundary(d->resumeLive, d->resumePT, d->resumePTSegments);
            d->accepting = true;
            d->snapshot.flags |= mapper_abi::kAccepting;
            // Admission is open again, so the suspend record is consumed here
            // rather than inside ResumeAuto(), which no longer clears it.
            SetSuspendRequested(false);
        }
    }
    if (!ok) d->snapshot.flags |= mapper_abi::kFailed;
    IOLockUnlock(d->lock);
    return ok ? kIOReturnSuccess : kIOReturnIOError;
}

// R72: the sleep side, driven by the controller's sleep/wake interest rather
// than by a client RPC. Admission closes here and the boundary snapshots are
// taken; SuspendAuto() decides from the live-mapping count whether the
// translation hardware may actually be stopped.
bool org_maz1_AMDMapperProbe::SuspendDomain() {
    MapperState *state = fMapper;
    if (!state || !fController || !fDomain) return true; // nothing attached yet
    IOLockLock(state->lock);
    if (state->accepting) {
        state->accepting = false;
        state->snapshot.flags &= ~mapper_abi::kAccepting;
        if (state->resumeLive) { state->resumeLive->release(); state->resumeLive = nullptr; }
        if (state->resumePT) { state->resumePT->release(); state->resumePT = nullptr; }
        if (state->resumePTSegments) { state->resumePTSegments->release(); state->resumePTSegments = nullptr; }
        state->capturePowerBoundary(state->suspendLive, state->suspendPT, state->suspendPTSegments);
    }
    // Recorded before the transition is attempted: admission is closed either
    // way, so the DMA path may reopen it once the controller is proven usable
    // even if the suspend bookkeeping itself failed.
    SetSuspendRequested(true);
    const bool ok = SuspendAuto();
    IOLockUnlock(state->lock);
    return ok;
}

// R72: the wake side. Admission is reopened only after the register image and a
// complete domain flush have both been confirmed.
bool org_maz1_AMDMapperProbe::ResumeDomain() {
    MapperState *state = fMapper;
    if (!state || !fController || !fDomain) return true;
    IOLockLock(state->lock);
    bool ok = ResumeAuto();
    if (!ok) {
        // The PM bookkeeping alone must not strand admission: if the hardware
        // can still be proven operational, reopening is the safe outcome. A
        // controller that cannot confirm an invalidation keeps it closed.
        ok = EnsureControllerOperationalLocked(state, "resume") && ControllerReady();
    }
    if (ok) {
        state->capturePowerBoundary(state->resumeLive, state->resumePT, state->resumePTSegments);
        state->accepting = true;
        state->snapshot.flags |= mapper_abi::kAccepting;
        SetSuspendRequested(false);
    }
    IOLockUnlock(state->lock);
    return ok;
}

// R72: the boundary blobs are otherwise published only by R44Snapshot, so the
// cross-boundary hash comparison would need a snapshot nobody asks for while
// judging a wake. The pointers are swapped by capturePowerBoundary under the
// mapper lock, so they are retained here before the property writes can block.
void org_maz1_AMDMapperProbe::PublishPMBoundary() {
    MapperState *state = fMapper;
    if (!state) return;
    OSData *suspendLive, *suspendPT, *suspendSegments;
    OSData *resumeLive, *resumePT, *resumeSegments;
    IOLockLock(state->lock);
    suspendLive = state->suspendLive; suspendPT = state->suspendPT;
    suspendSegments = state->suspendPTSegments;
    resumeLive = state->resumeLive; resumePT = state->resumePT;
    resumeSegments = state->resumePTSegments;
    if (suspendLive) suspendLive->retain();
    if (suspendPT) suspendPT->retain();
    if (suspendSegments) suspendSegments->retain();
    if (resumeLive) resumeLive->retain();
    if (resumePT) resumePT->retain();
    if (resumeSegments) resumeSegments->retain();
    const bool valid = suspendLive && suspendPT && suspendSegments &&
        resumeLive && resumePT && resumeSegments;
    IOLockUnlock(state->lock);
    auto publish = [this](const char *key, OSData *data) {
        if (data) { setProperty(key, data); data->release(); }
        else removeProperty(key);
    };
    publish("pm-suspend-live-raw", suspendLive);
    publish("pm-suspend-pt-raw", suspendPT);
    publish("pm-suspend-pt-segments-raw", suspendSegments);
    publish("pm-resume-live-raw", resumeLive);
    publish("pm-resume-pt-raw", resumePT);
    publish("pm-resume-pt-segments-raw", resumeSegments);
    setProperty("pm-snapshots-valid", valid ? "yes" : "no");
}

IOReturn org_maz1_AMDMapperProbe::SetRequesterDMA(bool park) {
    auto *m = fMapper;
    if (!m) return kIOReturnNotReady;
    IOLockLock(m->lock);
    const IOReturn result = m->accepting ? SwitchRequesterDMA(park) : kIOReturnNotReady;
    if (result == kIOReturnIOError) {
        m->accepting = false;
        m->snapshot.flags |= mapper_abi::kFailed;
        m->snapshot.flags &= ~mapper_abi::kAccepting;
    }
    IOLockUnlock(m->lock);
    return result;
}

UInt32 org_maz1_AMDMapperProbe::LiveMappings() const {
    auto *d = fMapper;
    if (!d) return 0;
    IOLockLock(d->lock);
    const UInt32 count = d->snapshot.liveCount;
    IOLockUnlock(d->lock);
    return count;
}

bool org_maz1_AMDMapperProbe::ReleaseMappings() {
    auto *d = fMapper;
    if (!d) return true;
    // The platform closes admission and restores its hardware before release.
    IOLockLock(d->lock);
    const bool release = !d->accepting && !d->snapshot.liveCount;
    IOLockUnlock(d->lock);
    if (!release) return false;
    fMapper = nullptr;
    if (d->suspendLive) d->suspendLive->release();
    if (d->suspendPT) d->suspendPT->release();
    if (d->suspendPTSegments) d->suspendPTSegments->release();
    if (d->resumeLive) d->resumeLive->release();
    if (d->resumePT) d->resumePT->release();
    if (d->resumePTSegments) d->resumePTSegments->release();
    if (d->arena) IOFree(d->arena, d->arenaBytes);
    for (UInt32 i = 0; i < d->tableAllocationCount; ++i)
        d->tableAllocations[i].memory->release();
    IOLockFree(d->lock); IOFree(d, sizeof(*d));
    return true;
}

IOReturn org_maz1_AMDMapperProbe::MapMemory(
    IOMemoryDescriptor *memory, uint64_t descriptorOffset, uint64_t length,
    uint32_t mapOptions, const IODMAMapSpecification *mapSpecification,
    IODMACommand *dmaCommand, const IODMAMapPageList *pageList,
    uint64_t *mapAddress, uint64_t *mapLength) {
    if (mapAddress) *mapAddress = 0;
    if (mapLength) *mapLength = 0;
    auto *d = fMapper;
    if (!d) return kIOReturnNotReady;
    IOLockLock(d->lock);
    auto &s = d->snapshot;
    const UInt32 previousGrowthCount = d->capacityGrowthCount;
    const char *previousGrowthState = d->growthState;
    ++s.mapCalls;
    IOReturn result = kIOReturnUnsupported;
    do {
        // R72: admission closed by a system suspend is a restorable state, not a
        // refusal; a parked requester or a failed domain still is. The controller
        // check below runs before any PTE is published, so a wake that produced
        // no suspend notification is repaired instead of mapped around.
        const bool suspended = !d->accepting;
        if (suspended && (!SuspendRequested() || (s.flags & mapper_abi::kFailed))) {
            result = kIOReturnNotReady; break;
        }
        if (fDMAParked) { result = kIOReturnNotReady; break; }
        if (!EnsureControllerOperationalLocked(d, "map")) {
            ++fRejectedUnavailable; result = kIOReturnNotReady; break;
        }
        if (suspended) {
            d->accepting = true;
            s.flags |= mapper_abi::kAccepting;
            SetSuspendRequested(false);
        }
        if (!memory || !mapAddress || !mapLength || !length ||
            descriptorOffset > memory->getLength() ||
            length > memory->getLength() - descriptorOffset) {
            result = kIOReturnBadArgument; break;
        }
        // Publish the largest request actually seen so a capacity decision does
        // not have to guess what a third-party client asks for.
        if (length > fMaxLength) fMaxLength = length;
        if (length > (UInt64)d->allocator.maxMapPages * 4096ULL) {
            ++fRejectedLength; break;
        }
        if (mapOptions & (kIODMAMapFixedAddress | kIODMAMapIdentityMap |
                          kIODMAMapDeviceMemory)) {
            ++fRejectedOptions; break;
        }
        const UInt64 permissions =
            ((mapOptions & kIODMAMapReadAccess) ? amdpte::PTE_IR : 0) |
            ((mapOptions & kIODMAMapWriteAccess) ? amdpte::PTE_IW : 0);
        if (!permissions) { result = kIOReturnBadArgument; break; }
        const UInt64 alignment = (mapSpecification && mapSpecification->alignment)
            ? mapSpecification->alignment : 1;
        const unsigned bits = (mapSpecification && mapSpecification->numAddressBits)
            ? mapSpecification->numAddressBits : 64;
        if ((alignment & (alignment - 1)) || alignment > mapper_abi::kBase ||
            bits > 64 || bits < 32) { ++fRejectedBits; break; }

        // Use the public wired-descriptor walk; the SDK deliberately makes
        // upl_page_info opaque. A pageList provides the first-offset check.
        ++s.walks;
        auto &layout = d->walkScratch;
        probeLayoutInto(layout, memory, descriptorOffset, length, mapper_abi::kRuns);
        if (layout.pages > fMaxPages) fMaxPages = layout.pages;
        if (layout.runs > fMaxRuns) fMaxRuns = layout.runs;
        if (layout.error || !layout.runs || layout.totalBytes != length ||
            !layout.pages || layout.pages > d->allocator.maxMapPages) {
            ++fRejectedLayout; break;
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

        unsigned slot = d->nextSlot(0, false);
        while (slot == d->records &&
               TryGrowCapacity(d, mapper_abi::CapacityResource::recordSlots))
            slot = d->nextSlot(0, false);
        if (slot == d->records) {
            ++fRejectedRecords;
            result = d->accepting ? kIOReturnNoResources : kIOReturnIOError;
            break;
        }
        const unsigned alignmentPages = alignment > 4096 ? (unsigned)(alignment / 4096) : 1;
        unsigned basePage = 0;
        bool rangeAllocated = d->allocateRange(layout.pages, basePage, alignmentPages);
        while (!rangeAllocated &&
               TryGrowCapacity(d, mapper_abi::CapacityResource::iovaPages))
            rangeAllocated = d->allocateRange(layout.pages, basePage, alignmentPages);
        if (!rangeAllocated) {
            ++fRejectedNoRange;
            result = d->accepting ? kIOReturnNoResources : kIOReturnIOError;
            break;
        }
        const UInt64 address = mapper_abi::kBase + basePage * 4096ULL + layout.firstOffset;
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
            d->accepting = false; s.flags |= mapper_abi::kFailed;
            s.flags &= ~mapper_abi::kAccepting;
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
        record.tPublish = mach_absolute_time(); record.state = mapper_abi::kMapPublished;
        ++s.liveCount;
        // R72: the shared controller reads this to decide whether a suspend may
        // stop the translation hardware at all.
        NoteLiveMapping(true);
        if (s.liveCount > s.peakMaps) s.peakMaps = s.liveCount;
        if (layout.pages > s.maxObservedPages) s.maxObservedPages = layout.pages;
        if (layout.runs > s.maxObservedRuns) s.maxObservedRuns = layout.runs;
        // First map activates the DTE. Later maps need an INV/CW only when
        // the actual controller can cache non-present translations.
        bool skipped = false;
        const bool synchronized = Invalidate(false,
            mapper_abi::kBase + record.basePage * 4096ULL,
            record.pages * 4096ULL, true, &skipped);
        if (!skipped) ++s.invalidates;
        if (!synchronized) {
            ++s.invalidateFailures;
            d->accepting = false; s.flags |= mapper_abi::kFailed;
            s.flags &= ~mapper_abi::kAccepting;
            d->exportRecord(record, s.lastMap);
            DMAFailStop("map invalidation unconfirmed", record);
        }
        record.tMapComplete = mach_absolute_time(); record.state |= mapper_abi::kMapConfirmed;
        ++s.mapOk;
        // Mirror the counters the S3 measurement reads; published outside the
        // lock by PublishCapacity() only when they change.
        fMapOk = s.mapOk;
        // s.livePages/s.peakPages are only refreshed when a snapshot is
        // published, so read the allocator directly for the measurement.
        fLiveMaps = s.liveCount;
        fLivePages = d->allocator.livePages;
        fPeakMaps = s.peakMaps;
        fPeakPages = d->allocator.peakPages;
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
    const bool capacityChanged = previousGrowthCount != d->capacityGrowthCount ||
        previousGrowthState != d->growthState;
    IOLockUnlock(d->lock);
    PublishCapacity(capacityChanged);
    return result;
}

// Capacity evidence for third-party clients. Called without the mapper lock so
// a property publication can never sit inside the DMA path's critical section.
void org_maz1_AMDMapperProbe::PublishCapacity(bool capacityChanged) {
    if (capacityChanged && fMapper) {
        auto *d = fMapper;
        IOLockLock(d->lock);
        const mapper_abi::Capacity current{d->records, d->pages};
        const char *profileName = mapper_abi::profileNameForCapacity(current);
        const UInt32 growthCount = d->capacityGrowthCount;
        const UInt32 recordGrowthCount = d->recordGrowthCount;
        const UInt32 pageGrowthCount = d->pageGrowthCount;
        const UInt64 growthTime = d->growthTime;
        const char *growthState = d->growthState;
        const char *growthFrom = d->growthFrom;
        const char *growthResource = d->growthResource;
        const UInt32 growthFromRecords = d->growthFromRecords;
        const UInt32 growthFromPages = d->growthFromPages;
        const UInt64 tableBytes = d->snapshot.ptBytes;
        const UInt32 tablePages = d->snapshot.tablePages;
        const UInt64 arenaBytes = d->arenaBytes;
        IOLockUnlock(d->lock);
        // Registry writes can block, so publish the captured decision only after
        // releasing the mapper lock. Profiles and state names have static storage.
        auto publish = [&](IORegistryEntry *entry) {
            entry->setProperty("iommu-profile", profileName);
            entry->setProperty("iommu-profile-allocated", profileName);
            entry->setProperty("iommu-profile-records", current.records, 32);
            entry->setProperty("iommu-profile-pages", current.pages, 32);
            entry->setProperty("iommu-profile-table-pages", tablePages, 32);
            entry->setProperty("iommu-table-bytes", tableBytes, 64);
            entry->setProperty("mapper-arena-bytes", arenaBytes, 64);
            entry->setProperty("mapper-map-window-bytes", current.pages * 4096ULL, 64);
            entry->setProperty("iommu-capacity-grown", growthCount ? "yes" : "no");
            entry->setProperty("iommu-growth-count", growthCount, 32);
            entry->setProperty("iommu-record-growth-count", recordGrowthCount, 32);
            entry->setProperty("iommu-page-growth-count", pageGrowthCount, 32);
            entry->setProperty("iommu-growth-resource", growthResource);
            entry->setProperty("iommu-growth-from-records", growthFromRecords, 32);
            entry->setProperty("iommu-growth-from-pages", growthFromPages, 32);
            entry->setProperty("iommu-growth-state", growthState);
            entry->setProperty("iommu-growth-time", growthTime, 64);
            if (growthFrom) entry->setProperty("iommu-profile-grown-from", growthFrom);
        };
        publish(this);
        if (fNicDevice) publish(fNicDevice);
    }
    const UInt64 rejects = (UInt64)fRejectedLength + fRejectedOptions +
        fRejectedLayout + fRejectedRecords + fRejectedNoRange +
        fRejectedBits + fRejectedUnavailable;
    // Peak/max/reject changes are rare and must be published immediately. The
    // monotonic counters move on every map, so they are only republished once
    // 128 of them accumulate: this keeps the DMA path out of the registry for
    // all but one call in 128.
    const bool rareChange =
        fMaxLength != fPublishedMaxLength ||
        fMaxPages != fPublishedMaxPages ||
        fMaxRuns != fPublishedMaxRuns ||
        rejects != fPublishedRejects ||
        fPeakMaps != fPublishedPeakMaps ||
        fPeakPages != fPublishedPeakPages;
    const bool liveChange =
        fLiveMaps != fPublishedLiveMaps ||
        fLivePages != fPublishedLivePages ||
        fMapOk - fPublishedMapOk >= 128 ||
        fUnmapOk - fPublishedUnmapOk >= 128;
    if (!rareChange && !liveChange) return;
    fPublishedMaxLength = fMaxLength;
    fPublishedMaxPages = fMaxPages;
    fPublishedMaxRuns = fMaxRuns;
    fPublishedRejects = rejects;
    fPublishedMapOk = fMapOk;
    fPublishedUnmapOk = fUnmapOk;
    fPublishedLiveMaps = fLiveMaps;
    fPublishedLivePages = fLivePages;
    fPublishedPeakMaps = fPeakMaps;
    fPublishedPeakPages = fPeakPages;
    setProperty("mapper-map-ok-live", fMapOk, 64);
    setProperty("mapper-unmap-ok-live", fUnmapOk, 64);
    setProperty("mapper-live-maps-live", fLiveMaps, 32);
    setProperty("mapper-live-pages-live", fLivePages, 32);
    setProperty("mapper-peak-maps-live", fPeakMaps, 32);
    setProperty("mapper-peak-pages-live", fPeakPages, 32);
    setProperty("mapper-max-map-length", fMaxLength, 64);
    setProperty("mapper-max-map-pages", fMaxPages, 64);
    setProperty("mapper-max-map-runs", fMaxRuns, 64);
    setProperty("mapper-rejects-length", (unsigned long long)fRejectedLength, 32);
    setProperty("mapper-rejects-options", (unsigned long long)fRejectedOptions, 32);
    setProperty("mapper-rejects-layout", (unsigned long long)fRejectedLayout, 32);
    setProperty("mapper-rejects-records", (unsigned long long)fRejectedRecords, 32);
    setProperty("mapper-rejects-no-range", (unsigned long long)fRejectedNoRange, 32);
    setProperty("mapper-rejects-bits", (unsigned long long)fRejectedBits, 32);
    setProperty("mapper-rejects-unavailable",
                (unsigned long long)fRejectedUnavailable, 32);
}

IOReturn org_maz1_AMDMapperProbe::UnmapMemory(
    IOMemoryDescriptor *memory, IODMACommand *dmaCommand,
    uint64_t mapAddress, uint64_t mapLength) {
    auto *d = fMapper;
    if (!d) return kIOReturnNotReady;
    IOLockLock(d->lock);
    auto &s = d->snapshot;
    ++s.unmapCalls;
    // Reject unrelated/invalid calls normally, even for a suspended or failed
    // domain. Only an exact owned live mapping can put backing RAM at risk.
    IOReturn result = d->accepting ? kIOReturnBadArgument : kIOReturnNotReady;
    do {
        if (mapAddress < mapper_abi::kBase) break;
        const UInt64 page = (mapAddress - mapper_abi::kBase) / 4096;
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
        if (record.state & mapper_abi::kUnmapConfirmed) {
            result = kIOReturnInternalError; break;
        }
        // R72: an owned live mapping may only be retired against a controller
        // that is provably able to confirm the invalidation. A wake that
        // delivered no suspend notification is repaired here, before the PTE is
        // cleared; a controller that cannot be restored keeps the fail-stop,
        // because XNU unwires the descriptor even when this call fails.
        if (!EnsureControllerOperationalLocked(d, "unmap")) {
            DMAFailStop(ControllerReady() ? "owned unmap while domain unavailable"
                                          : "wake-restore-required", record);
        }
        if (record.state != (mapper_abi::kMapPublished | mapper_abi::kMapConfirmed))
            DMAFailStop("owned unmap with unretired state", record);
        for (unsigned i = 0; i < record.pages; ++i) d->leaf(record.basePage + i) = 0;
        OSSynchronizeIO();
        record.tClear = mach_absolute_time(); record.state |= mapper_abi::kClearPublished;
        ++s.invalidates;
        if (!Invalidate(false, mapper_abi::kBase + record.basePage * 4096ULL,
                           record.pages * 4096ULL)) {
            ++s.invalidateFailures;
            d->accepting = false; s.flags |= mapper_abi::kFailed;
            s.flags &= ~mapper_abi::kAccepting;
            d->exportRecord(record, s.lastUnmap);
            DMAFailStop("unmap invalidation unconfirmed", record);
        }
        record.tUnmapComplete = mach_absolute_time(); record.state |= mapper_abi::kUnmapConfirmed;
        d->exportRecord(record, s.lastUnmap);
        // A cleared PTE alone is not retirement: pages become reusable only
        // after the INV_IOMMU_PAGES CompletionWait has returned successfully.
        if (!amdtx::release(d->allocator, record.basePage, record.pages)) {
            d->accepting = false; s.flags |= mapper_abi::kFailed;
            s.flags &= ~mapper_abi::kAccepting;
            result = kIOReturnInternalError; break;
        }
        d->slotByStartPage[page] = 0;
        NoteLiveMapping(false);
        --s.liveCount; ++s.unmapOk;
        fUnmapOk = s.unmapOk;
        fLiveMaps = s.liveCount;
        fLivePages = d->allocator.livePages;
        s.lastUnmapAt = record.tUnmapComplete;
        d->setSlotLive(slot, false);
        mapping.memory = nullptr; mapping.command = nullptr;
        result = kIOReturnSuccess;
    } while (false);
    if (result != kIOReturnSuccess) ++s.unmapRejected;
    IOLockUnlock(d->lock);
    return result;
}

bool org_maz1_AMDMapperProbe::Translate(uint64_t address, uint64_t *physical) const {
    auto *d = fMapper;
    if (!d || !physical || address < mapper_abi::kBase ||
        address - mapper_abi::kBase >= (UInt64)d->pages * 4096ULL) return false;
    IOLockLock(d->lock);
    const auto decoded = amdpte::decodePte(d->leaf((unsigned)((address - mapper_abi::kBase) / 4096)), 1);
    const bool present = decoded.kind == amdpte::PTE_LEAF_DEFAULT;
    if (present) *physical = decoded.outPA + (address & 4095ULL);
    IOLockUnlock(d->lock);
    return present;
}

void org_maz1_AMDMapperProbe::PublishMappings(OSDictionary **copy) {
    if (copy) *copy = nullptr;
    auto *d = fMapper;
    if (!d) {
        PublishAuto();
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
    OSData *tables = nullptr, *segments = nullptr;
    d->copyPageTables(tables, segments);
    if (summary && active && tables && segments) {
        setProperty("mapper-state-raw", summary);
        setProperty("mapper-live-raw", active);
        setProperty("mapper-page-table-raw", tables);
        setProperty("mapper-page-table-segments-raw", segments);
        setProperty("mapper-abi-version", mapper_abi::kVersion, 32);
        setProperty("mapper-live-maps", s.liveCount, 32);
        setProperty("mapper-live-pages", s.livePages, 32);
        // S3 measurement: peaks since this domain was prepared, published with
        // the ordinary snapshot so a read never races the DMA path.
        setProperty("mapper-peak-maps", s.peakMaps, 32);
        setProperty("mapper-peak-pages", s.peakPages, 32);
        setProperty("mapper-map-ok", s.mapOk, 64);
        setProperty("mapper-unmap-ok", s.unmapOk, 64);
        setProperty("mapper-map-rejected", s.mapRejected, 64);
        setProperty("mapper-unmap-rejected", s.unmapRejected, 64);
        setProperty("mapper-snapshot-sequence", s.snapshotSequence, 64);
        setProperty("mapper-map-32bit-ok", d->map32Ok, 64);
        setProperty("mapper-map-high-pa-ok", d->mapHighPAOk, 64);
        setProperty("mapper-mapped-high-pa-pages", d->mappedHighPAPages, 64);
        setProperty("mapper-map-min-bits", d->minMapBits, 32);
        setProperty("mapper-map-max-bits", d->maxMapBits, 32);
        // Capacity decisions are also published after each growth attempt.
        setProperty("iommu-capacity-grown", d->capacityGrowthCount ? "yes" : "no");
        setProperty("iommu-growth-count", d->capacityGrowthCount, 32);
        setProperty("iommu-record-growth-count", d->recordGrowthCount, 32);
        setProperty("iommu-page-growth-count", d->pageGrowthCount, 32);
        setProperty("iommu-growth-resource", d->growthResource);
        setProperty("iommu-growth-from-records", d->growthFromRecords, 32);
        setProperty("iommu-growth-from-pages", d->growthFromPages, 32);
        setProperty("iommu-growth-state", d->growthState ? d->growthState : "unknown");
        setProperty("iommu-growth-time", d->growthTime, 64);
    }
    if (summary) summary->release();
    if (active) active->release();
    if (tables) tables->release();
    if (segments) segments->release();
    auto boundary = [this](const char *key, OSData *data) {
        if (data) setProperty(key, data);
        else removeProperty(key);
    };
    boundary("pm-suspend-live-raw", d->suspendLive);
    boundary("pm-suspend-pt-raw", d->suspendPT);
    boundary("pm-suspend-pt-segments-raw", d->suspendPTSegments);
    boundary("pm-resume-live-raw", d->resumeLive);
    boundary("pm-resume-pt-raw", d->resumePT);
    boundary("pm-resume-pt-segments-raw", d->resumePTSegments);
    setProperty("pm-snapshots-valid",
        d->suspendLive && d->suspendPT && d->suspendPTSegments &&
        d->resumeLive && d->resumePT && d->resumePTSegments ? "yes" : "no");
    // Keep this domain's raw state, PTE bytes and hardware counters in one
    // snapshot. Hardware export takes only the controller lock after this lock.
    PublishAuto();
    if (copy) *copy = dictionaryWithProperties();
    IOLockUnlock(d->lock);
}
