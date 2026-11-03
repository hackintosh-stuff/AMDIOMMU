// M2-3b: explicit same-device live TX mapping backend for NATIVE mbuf segments.
//
// Round16 proved that four *different* physical pages could be reached through
// the same non-identity IOVA and that retire-invalidation precedes reuse. Round
// 17 keeps that mechanism and removes the two things that were really a
// surrogate for it: the page-aligned staging copy (the descriptors now carry
// the real packet's own physical segments) and the cumulative coupling between
// "how many requests succeeded so far" and "how long a DMA owner must live"
// (every request's owner is now retired and released per packet).
//
// Round32: sixteen active records own variable-size mappings independently of a circular history
// of the last 32 completed retirements. History exhaustion never gates Map.
// The original command ring is reused using hardware HEAD and bounded waits;
// each mapping owner is released only after its own retire CompletionWait.
#include "AMDMapperProbeInternal.hpp"
#include "amd_iommu_tx_core.hpp"
#include "amd_iommu_bizwalk_core.hpp"
#include "../tools/lucy-obs/AMDAliveTxDomainNative.hpp"
#include "../tools/lucy-obs/RTL812xTxMapStd.hpp"
#include <IOKit/IOLocks.h>

// Round25: the original command buffer is reused circularly, with finite
// per-submit waits. Completed evidence is circular and never owns live state.

struct org_example_AMDMapperProbe::R17Domain {
    IOLock *lock;
    volatile UInt8 *mmio;
    volatile UInt64 *pt, *leaves;
    // The first L1 contains the bounded dynamic TX arena; RX uses four more.
    enum { kIovaL1Count = (amdtx::kRxFirstPage +
        r27rx::kCount * r27rx::kPagesPerSlot + 511) / 512 };
    volatile UInt64 *iovaL1[kIovaL1Count];
    UInt64 ptBase, ptBytes, handle, handleCounter;
    M2B2CmdCtx command;
    // Install precedes the caller's DTE invalidations. The domain owns this
    // cursor only after r17SyncCommand hands it over before opening admission.
    bool commandOwned;
    r17domain::Snapshot snapshot;
    bool installed, accepting;
    // Live DMA owners (0..amdtx::kSlots). Each accepted Map takes an active
    // record and the pages its layout needs. Confirmed Retire returns both.
    UInt32 liveOwner, maxLiveOwner, mapsOk, mapsRejected, retires;
    // slotLive is a bitmask of active metadata records; slotHandle[k] is the
    // generation handle owning record k. Handles are UInt64 (r17domain::Record::
    // handle) and are compared verbatim against Request::handle, so storing the
    // full width here is what keeps that comparison exact.
    UInt32 slotLive;
    amdtx::Allocator allocator;
    UInt64 slotHandle[amdtx::kSlots];
    // Metadata activity is distinct from allocator occupancy and page reuse.
    UInt32 slotsUsed, slotUses[amdtx::kSlots];
    r17domain::Record slotRecord[amdtx::kSlots]; // authoritative active mappings; never overwritten by history
    IOMemoryDescriptor *slotMemory[amdtx::kSlots];
    IODMACommand *slotCommand[amdtx::kSlots];
    // Round18: the same owner slot, entered through IOMapper virtuals instead of
    // the platform callback. Only one of the two entry paths may be armed.
    bool stdMode;
    void *stdMapper;
    // Round20: identity coverage of ordinary TX objects (kCover). `coverNext`
    // is the first table page this path may use after TX/RX preparation.
    // `rootLevel` is the live table's root.
    UInt32 rootLevel, coverNext, coverEnd;
    UInt32 coverCalls, coverChunks, coverPages, coverLeaves, coverPresent;
    UInt32 coverInvals, coverFails, coverUnconfirmed;
    const char *coverWhy;
    // ---- round 21: window edge accounting ----
    // gateSeq counts successful gate transitions; gateFails is the driver's own
    // refusal counter, gateFailCount counts calls that did not return success.
    UInt32 gateSeq, gateFails, gateFailCount, exitSamples;
    UInt32 coverInFlightAtExit;
    UInt64 tGateClose, tGateOpen, tTranslateOn, tTranslateOff;
    // ---- round 22: the submission barrier and the stop/restore boundaries ----
    // edgeSeq/tEdge/tSubmitDone/tDrainDone/tResume are copied from the driver's
    // own latches on every control call: they name when the event happened, not
    // when the probe looked. stop* describe the one stop attempt (label, result,
    // and the two quantities the result was decided on).
    UInt32 edgeSeq, enterEdgeSeq, exitEdgeSeq;
    UInt64 tEdge, tSubmitDone, tDrainDone, tResume;
    bool stopOk, detachOk, resumed;
    UInt32 stopMs, stopLastRing, stopLastFlight;
    UInt32 driverHeld, driverLive, driverMapped, driverRetired;
    const char *stopEdge, *stopFailReason;
    UInt64 tDetach;
    // Explicit "unconfirmed mapping modification" state. After invalidate() fails,
    // new cover requests are refused until explicit recovery (detach/retire). This
    // prevents using stale present bits from a failed attempt on subsequent chunks.
    bool coverUnconfirmedMap;
};

// The pool owns mbufs; these physical descriptors only describe those retained
// objects. A retained driver reference and kRelease keep the two lifetimes
// paired, including the pinned failure path.
struct org_example_AMDMapperProbe::R27RxDomain {
    IOService *driver;
    IOMemoryDescriptor *memory[r27rx::kCount];
    IODMACommand *command[r27rx::kCount];
    bool wired[r27rx::kCount], prepared[r27rx::kCount];
    bool held, installed, drained, released;
    r27rx::Request control;
    r27rx::BackendSnapshot snapshot;
};
struct org_example_AMDMapperProbe::R34RxDomain {
    IOService *driver;
    // Borrowed from Lucy between Bind and Unbind; Lucy releases the objects.
    IOMemoryDescriptor *memory[r34rx::kCount];
    IODMACommand *command[r34rx::kCount];
    bool prepared, installed, released, physicalResumed;
    // Private batch commits finish the hardware work before a standard
    // IOMapper callback consumes the confirmed result for its registered pair.
    bool preMapped[r34rx::kCount], preUnmapped[r34rx::kCount];
    UInt32 mapInvalidations, unmapInvalidations;
    UInt32 mapBatchCalls, unmapBatchCalls, mapBatchSlots, unmapBatchSlots, maxBatch;
    // One sparse arena serves bootstrap, IOVA tables and physical restore.
    // Initial RX identity leaves retire once all descriptors use IOVA. Fixed
    // NIC objects remain physical; stop adds each slot's current buffer back.
    UInt32 physicalNext, bootstrapPages, fixedPages, removedPages, restoreAddedPages;
    bool bootstrapRetired;
    UInt64 tBootstrapClear;
    r17domain::Command bootstrapRetireCommand;
    void *activePt;
    UInt32 activePtBytes;
    r34rx::PhysicalLayout physical;
    r34rx::Request control;
    r34rx::BackendSnapshot snapshot;
};
static_assert(r27rx::kIovaBase == amdtx::kBase + amdtx::kRxFirstPage * 4096ULL,
              "RX starts after the separate dynamic TX L1 table");
static_assert(amdtx::kPages <= amdtx::kRxFirstPage &&
              512 % r27rx::kPagesPerSlot == 0,
              "Each RX stripe stays within its own L1 table");

bool org_example_AMDMapperProbe::r17Prepare(volatile UInt64 *pt, UInt64 base,
                                           UInt32 pages) {
    if (fR17 || pages <= M2B2_IOVA_RESERVED_PAGES) return false;
    if (fR31Session && (!fR34Rx || fR34Rx->physicalNext < 2 ||
                       !fR34Rx->bootstrapPages)) return false;
    R17Domain *d = (R17Domain *)IOMalloc(sizeof(R17Domain));
    if (!d) return false;
    bzero(d, sizeof(*d));
    d->lock = IOLockAlloc();
    if (!d->lock) { IOFree(d,sizeof(*d)); return false; }
    fR17 = d;
    d->pt=pt; d->ptBase=base; d->ptBytes=pages*4096ULL;
    // Command space is checked against hardware HEAD on each submission.
    // Native sessions continue from the actual sparse bootstrap cursor. The
    // remaining arena is shared with physical restore instead of leaving most
    // free pages behind a fixed IOVA/cover partition. Legacy keeps its tail.
    static_assert(R17Domain::kIovaL1Count + 3 <= M2B2_IOVA_RESERVED_PAGES,
                  "IOVA arena includes L2, all L1s and two cover pages");
    amdsparse::Arena a={pt,base,pages,
        fR31Session ? fR34Rx->physicalNext : pages-M2B2_IOVA_RESERVED_PAGES,
        fM22b2Use3L?3u:4u,base,0,0,nullptr};
    d->rootLevel = a.rootLevel;
    for (UInt32 i = 0; i < R17Domain::kIovaL1Count; ++i) {
        d->iovaL1[i] = amdtx::prepareAt(a, amdtx::kBase + i * 0x200000ULL, 512);
        if (!d->iovaL1[i]) {
            setProperty("m2-3b-prepare", "FAIL-iova-conflict"); return false;
        }
    }
    d->leaves = d->iovaL1[0];
    // Whatever remains may be used by the round-20 cover path, never beyond.
    d->coverNext = a.next;
    d->coverEnd = a.pages;
    auto &s=d->snapshot;
    s.version=r17domain::kVersion; s.bytes=sizeof(s);
    s.iovaBase=amdtx::kBase; s.iovaBytes=amdtx::kPages*4096ULL;
    s.rootPA=base; s.rootLevel=a.rootLevel;
    s.leafPA=base+((uintptr_t)d->leaves-(uintptr_t)pt);
    s.ptBase=base; s.ptBytes=d->ptBytes;
    OSSynchronizeIO();
    setProperty("m2-3b-prepare","done");
    return true;
}

// Take a free active-record index; its index does not choose an IOVA address.
static const UInt32 kNoSlot = 0xffffffffu;
static UInt32 r17TakeSlot(UInt32 &liveMask) {
    for (UInt32 k = 0; k < amdtx::kSlots; ++k) {
        if (liveMask & (1u << k)) continue;
        liveMask |= (1u << k);
        return k;
    }
    return kNoSlot;
}

// Locate the exact mapped address in its independent active record.
static UInt32 r17SlotOf(const r17domain::Record *records, UInt32 live, UInt64 iova) {
    for (UInt32 k = 0; k < amdtx::kSlots; ++k)
        if ((live & (1u << k)) && records[k].segments[0].iova == iova) return k;
    return kNoSlot;
}

// Only confirmed retirements enter bounded evidence storage. Active state is
// never read from history: overwriting the oldest completion cannot lose a DMA owner.
static void r25Archive(r17domain::Snapshot &s, const r17domain::Record &w) {
    s.records[s.historyTotal % r17domain::kMaxRecords] = w;
    ++s.historyTotal;
    s.count = s.historyTotal < r17domain::kMaxRecords ? s.historyTotal : r17domain::kMaxRecords;
    s.historyStart = s.historyTotal - s.count;
}

static bool r17Invalidate(volatile UInt8 *base, M2B2CmdCtx &ctx,
                          r17domain::Command &record, const char *label) {
    // Full domain invalidation including PDE caches, followed by a real
    // CompletionWait STORE. No driver callback, sleeping, or workloop entry.
    const UInt64 addr=m2b2InvAddress();
    record.d[0]=0;
    record.d[1]=ctx.domid|((UInt32)M2B2_CMD_INV_IOMMU_PAGES<<28);
    record.d[2]=(UInt32)addr|M2B2_CMD_PDE_MASK;
    record.d[3]=(UInt32)(addr>>32);
    record.expected=ctx.completionSequence+1;
    // Space for the invalidation + CompletionWait is checked by m2b2Submit.
    const bool ok=m2b2Submit(base,&ctx,label,record.d[0],record.d[1],record.d[2],record.d[3]);
    record.observed=ctx.lastSem;
    record.tComplete=mach_absolute_time();
    return ok;
}

IOReturn org_example_AMDMapperProbe::r17Callback(void *context, UInt32 op,
                                               r17tx::Request *r) {
    auto *self=(org_example_AMDMapperProbe *)context;
    R17Domain *d=self?self->fR17:nullptr;
    if (!d || !r || r->version!=r17tx::kVersion || r->bytes!=sizeof(*r))
        return kIOReturnBadArgument;
    if (op==r17tx::kRetireAck) r->tRetire=0;
    IOLockLock(d->lock);
    auto &s=d->snapshot;
    IOReturn result=kIOReturnNotReady;
    if (r->bdf!=s.devid || !d->installed) goto out;
    if (op==r17tx::kRetireAck) {
        // complete() can hide an IOMapper unmap failure. Confirm this handle's
        // retirement from the backend's completed record before driver release.
        if (r->token!=self->fR15Request.reserved || !r->handle ||
            r->handle>d->handleCounter) {
            result=kIOReturnBadArgument; goto out;
        }
        for (UInt32 k=0;k<amdtx::kSlots;++k)
            if (d->slotHandle[k]==r->handle) goto out;
        for (UInt32 k=0;k<s.count && k<r17domain::kMaxRecords;++k) {
            const auto &w=s.records[(s.historyStart+k)%r17domain::kMaxRecords];
            if (w.handle!=r->handle) continue;
            if (w.status!=3 || !w.tClearPublish || w.tRetireInv<=w.tClearPublish ||
                w.tRetireInv!=w.retireCommand.tComplete ||
                !w.retireCommand.expected ||
                w.retireCommand.expected!=w.retireCommand.observed) {
                result=kIOReturnIOError; goto out;
            }
            r->tRetire=w.tRetireInv;
            result=kIOReturnSuccess; break;
        }
    } else if (op==r17tx::kMap) {
        // Round23: `d->handle` is no longer a single "the one live generation"
        // marker -- it records the most recently issued handle for Query, and
        // whether a slot is free is decided by the slot mask below.
        if (!d->accepting || r->handle ||
            r->token!=self->fR15Request.reserved ||
            r->reqId<1 || r->reqId>r17tx::kRequestLimit ||
            !r->count || r->count>r17tx::kMaxSegments) {
            d->mapsRejected++; result=kIOReturnBadArgument; goto out;
        }
        {
            // Reserve independent metadata and a variable-size IOVA extent.
            const UInt32 slot=r17TakeSlot(d->slotLive);
            if (slot!=kNoSlot) { d->slotsUsed|=1u<<slot; d->slotUses[slot]++; }
            if (slot==kNoSlot) { d->mapsRejected++; result=kIOReturnBusy; goto out; }
            amdtx::Segment input[amdtx::kSegments]={};
            amdtx::Plan plan;
            for (UInt32 i=0;i<r->count;++i) input[i]={r->physical[i].address,r->physical[i].length,0};
            if (!amdtx::plan(plan,input,r->count)) {
                d->slotLive&=~(1u<<slot);
                d->mapsRejected++; result=kIOReturnUnsupported; goto out;
            }
            if (!amdtx::allocate(d->allocator,plan.pages,plan.basePage)) {
                d->slotLive&=~(1u<<slot);
                d->mapsRejected++; result=kIOReturnBusy; goto out;
            }
            for (unsigned i=0;i<plan.count;++i)
                plan.segments[i].iova += (UInt64)plan.basePage*4096ULL;
            for (unsigned i=0;i<plan.pages;++i)
                if (d->leaves[plan.basePage+i]) {
                    amdtx::release(d->allocator,plan.basePage,plan.pages);
                    d->slotLive&=~(1u<<slot);
                    d->mapsRejected++; result=kIOReturnBusy; goto out;
                }
            for (unsigned i=0;i<plan.pages;++i)
                d->leaves[plan.basePage+i]=
                    amdpte::makeDefaultLeaf(1,plan.physical[i],
                                            amdpte::PTE_IR);
            OSSynchronizeIO();
            auto &w=d->slotRecord[slot];
            bzero(&w,sizeof(w));
            w.handle=++d->handleCounter; d->handle=w.handle; r->handle=w.handle;
            w.count=plan.count; w.pages=plan.pages; w.token=r->token; w.req=r->reqId;
            w.basePage=plan.basePage; w.recordIndex=slot;
            d->slotHandle[slot]=w.handle;
            for(unsigned i=0;i<plan.count;++i) {
                const auto &p=plan.segments[i];
                w.segments[i]={p.pa,p.bytes,p.iova};
                r->iova[i]={p.iova,p.bytes};
            }
            OSSynchronizeIO();
            w.tMapPublish=mach_absolute_time();
            for(unsigned i=0;i<plan.pages;++i) {
                w.mapPte[i]=d->leaves[plan.basePage+i];
                w.physical[i]=plan.physical[i];
            }
            // On timeout leave handle nonzero and pin ownership. The slot stays
            // taken for the same reason: its PTEs may still be live.
            if (!r17Invalidate(d->mmio,d->command,w.mapCommand,"r17-map-pages")) {
                w.status|=4; s.flags|=1; d->accepting=false;
                d->liveOwner++; s.active=1;
                if (d->maxLiveOwner<d->liveOwner) d->maxLiveOwner=d->liveOwner;
                d->mapsRejected++; result=kIOReturnIOError; goto out;
            }
            w.tMapInv=w.mapCommand.tComplete; r->tMap=w.tMapInv;
            w.status|=1; s.active=1;
            d->liveOwner++;
            if (d->maxLiveOwner<d->liveOwner) d->maxLiveOwner=d->liveOwner;
            d->mapsOk++;
            if (w.pages>s.maxMappedPages) s.maxMappedPages=w.pages;
            result=kIOReturnSuccess;
        }
    } else if (op==r17tx::kCover) {
        // Round20: identity coverage for a NON-selected packet's own physical
        // segments. It is deliberately allowed while a mapped generation owns
        // the owner slot: the device may prefetch later descriptors, and an
        // uncovered ordinary buffer would stall the whole queue (rounds 18/19).
        if (!d->installed) { result=kIOReturnNotReady; goto out; }
        // After invalidate() fails, refuse new cover until explicit recovery.
        if (d->coverUnconfirmedMap) {
            d->coverFails++; result=kIOReturnBusy; goto out;
        }
        if (!r->count || r->count>r17tx::kMaxSegments) {
            d->coverFails++; result=kIOReturnBadArgument; goto out;
        }
        {
            amdtx::Segment in[amdtx::kSegments]={};
            for (UInt32 i=0;i<r->count;++i)
                in[i]={r->physical[i].address,r->physical[i].length,0};
            amdsparse::Arena a={d->pt,d->ptBase,
                (unsigned)(d->ptBytes/4096ULL),d->coverNext,
                d->rootLevel,d->ptBase,0,0,nullptr};
            amdtx::CoverResult cr;
            if (!amdtx::coverIdentity(a,M2B2_IDENTITY_LIMIT,in,r->count,cr)) {
                d->coverFails++; d->coverWhy=a.why;
                result=kIOReturnNoResources; goto out;
            }
            d->coverNext=a.next;
            if (cr.pages || cr.chunks || cr.leaves) {
                // The entries exist only for the hardware after the domain
                // invalidation. If that is not confirmed the caller must not
                // submit, and this domain stops accepting new generations.
                r17domain::Command rec={};
                OSSynchronizeIO();
                if (!r17Invalidate(d->mmio,d->command,rec,"r20-cover-identity")) {
                    d->coverFails++; d->accepting=false; d->coverUnconfirmedMap=true;
                    result=kIOReturnIOError; goto out;
                }
                d->coverInvals++; d->coverUnconfirmedMap=false;
            }
            d->coverCalls++; d->coverChunks+=cr.chunks; d->coverPages+=cr.pages;
            d->coverLeaves+=cr.leaves; d->coverPresent+=cr.present;
            result=kIOReturnSuccess;
        }
        goto out;
    } else if (op==r17tx::kRetire) {
        // Round23: the generation is identified by its OWN handle, and the slot
        // to clear is the one that handle owns. Round 22 was correct only
        // because at most one mapping existed; with several live, "clear the
        // window" would unmap the other frames' PTEs as well -- and the device
        // would then fault on a descriptor it already owns.
        if (!r->handle || r->handle>d->handleCounter) {
            result=kIOReturnBadArgument; goto out;
        }
        {
            UInt32 slot=kNoSlot;
            for (UInt32 k=0; k<amdtx::kSlots; ++k)
                if ((d->slotLive&(1u<<k)) && d->slotHandle[k]==r->handle) { slot=k; break; }
            if (slot==kNoSlot) { result=kIOReturnBadArgument; goto out; }
            auto &w=d->slotRecord[slot];
            if (slot>=amdtx::kSlots || d->slotHandle[slot]!=r->handle ||
                !(d->slotLive&(1u<<slot)) || w.handle!=r->handle ||
                r17SlotOf(d->slotRecord,d->slotLive,w.segments[0].iova)!=slot || w.status!=1) {
                result=kIOReturnBadArgument; goto out;
            }
            const UInt32 base=w.basePage;
            for(unsigned i=0;i<w.pages;++i) d->leaves[base+i]=0;
            OSSynchronizeIO();
            if (!w.tClearPublish) w.tClearPublish=mach_absolute_time();
            for(unsigned i=0;i<w.pages;++i) w.clearPte[i]=d->leaves[base+i];
            // M2B2CmdCtx retains this label pointer until export. Keep a static
            // label; the record's handle/basePage identify the allocation.
            if (!r17Invalidate(d->mmio,d->command,w.retireCommand,"r32-retire-allocation")) {
                // Keep handle, slot and owner: this translation may still be
                // live, and freeing the allocation would let the next Map reuse
                // PTEs the device is still translating through.
                w.status|=8; s.flags|=2; d->accepting=false;
                result=kIOReturnIOError; goto out;
            }
            w.tRetireInv=w.retireCommand.tComplete; r->tRetire=w.tRetireInv;
            w.status|=2; s.active=(d->liveOwner>1)?1:0;
            amdtx::release(d->allocator,w.basePage,w.pages);
            r25Archive(s,w);
            d->slotLive&=~(1u<<slot);
            d->slotHandle[slot]=0;
            // Only clear the "most recent handle" marker when it IS this one:
            // retiring a frame that is not the newest must not hide the newest.
            if (d->handle==r->handle) d->handle=0;
            if (d->liveOwner) d->liveOwner--;
            d->retires++;
            result=kIOReturnSuccess;
        }
    }
out:
    IOLockUnlock(d->lock);
    return result;
}

// Round18: is the standard-interface mode requested for this boot? The only
// dependable channel in this project is the amdiommu= value (separate boot-args
// do not reach this kext), so the mode travels as an extra '.std' segment after
// the batch/token segments the round-17 parser already understands.
static bool r17ModeRequested(const char *mode, size_t length) {
    char val[128];
    val[0] = 0;
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) return false;
    const char *q = val;
    while ((q = strchr(q, '.')) != nullptr) {
        q++;
        if (strncmp(q, mode, length) == 0 && (q[length] == 0 || q[length] == '.')) return true;
    }
    return false;
}

bool org_example_AMDMapperProbe::r31SessionRequested() const {
    return r17ModeRequested("session", 7);
}

bool org_example_AMDMapperProbe::r17Activate(volatile UInt8 *base, void *command) {
    if (!fR17 || !fR15Service) return false;
    auto *d=fR17;
    d->mmio=base; d->command=*(M2B2CmdCtx *)command;
    d->commandOwned=false;
    d->snapshot.devid=d->command.devid; d->snapshot.domid=d->command.domid;
    const bool stdMode=r17ModeRequested("std", 3);
    const bool allTx=r17ModeRequested("alltx", 5);
    const bool rxStd=r17ModeRequested("rxstd", 5);
    if (fR31Session && (!stdMode || !allTx || !rxStd)) {
        setProperty("m2-3l-session-state", "failed");
        setProperty("m2-3l-session-error", "session-requires-std-alltx-rxstd");
        return false;
    }
    if (rxStd && (!stdMode || !allTx)) {
        setProperty("m2-3h-rx-state", "invalid-rxstd-requires-std-alltx");
        return false;
    }
    if (allTx && !stdMode) {
        setProperty("m2-3g-mode", "invalid-alltx-requires-std");
        return false;
    }
    d->stdMode=stdMode; d->stdMapper=stdMode?this:nullptr;
    r17tx::Configure c={};
    c.version=r17tx::kVersion; c.bytes=sizeof(c); c.op=r17tx::kInstall;
    c.bdf=d->command.devid; c.token=fR15Request.reserved;
    // Session admission lasts until explicit Disarm. The finite path keeps
    // its 120-second authorization covering the window and drain.
    c.deadline=fR31Session?0:mach_absolute_time()+120000000000ULL;
    setHexProperty(this,"m2-3l-tx-deadline",c.deadline);
    c.callback=&org_example_AMDMapperProbe::r17Callback; c.context=this; c.owner=this;
    c.mode=allTx?(UInt32)r17tx::kModeAllStandard:
        (stdMode?(UInt32)r17tx::kModeStandard:(UInt32)r17tx::kModeDirect);
    c.mapper=stdMode?(void *)this:nullptr;
    const OSSymbol *sym=OSSymbol::withCString(r17tx::kFunctionName);
    if (!sym) return false;
    // Install publishes the callback only after all state is initialized.
    d->installed=true; d->accepting=true;
    IOReturn kr=fR15Service->callPlatformFunction(sym,false,&c,nullptr,nullptr,nullptr);
    sym->release();
    if (kr!=kIOReturnSuccess) { d->installed=false; d->accepting=false; return false; }
    // ---- round 22: Install IS the first half of entering the window ----------
    //
    // Install closes the driver's admission word before it publishes the state,
    // so from this instant no packet is admitted (neither an ordinary one, whose
    // physical addresses are about to be re-resolved through a different table,
    // nor a selected one, whose 64 GiB IOVA is meaningless until the flip is
    // confirmed). Everything that is already inside outputStart holds a
    // reference and remains visible to the quiesce that follows.
    //
    // The DTE is still the passthrough entry here: nothing has been flipped yet.
    // r17StopSubmit() below is what waits for the old-mapping traffic to finish,
    // and the caller flips only after it returns.
    d->tTranslateOn=0;   // set when the caller confirms the invalidation
    d->enterEdgeSeq=0; d->exitEdgeSeq=0;
    setProperty("m2-3b-authorize","done");
    setProperty("m2-3c-mode",stdMode?"standard-iomapper":"direct-platform-call");
    setProperty("m2-3g-mode",allTx?"all-standard":
        (stdMode?"selected-standard":"selected-direct"));
    setHexProperty(this,"m2-3b-command-capacity",(UInt64)(M23_CMD_BUF_SIZE/16));
    return true;
}

// The driver timer retires mappings after the NIC ring is empty. Keep the DTE
// and command engine active until those owners and commands have completed.
bool org_example_AMDMapperProbe::r17BackendDrained() {
    R17Domain *d=fR17;
    if (!d) return true;
    IOLockLock(d->lock);
    const bool clean=!d->liveOwner && !d->slotLive && !d->allocator.livePages &&
        d->mapsOk==d->retires &&
        !d->command.failed && d->command.submits==d->command.completed &&
        !d->coverUnconfirmedMap && !d->snapshot.flags;
    IOLockUnlock(d->lock);
    return clean;
}

// Poll on the probe thread without holding Lucy's gate or the backend lock,
// allowing the driver timer to finish pending unmaps.
bool org_example_AMDMapperProbe::r17StopSubmit(UInt32 budgetMs, const char *edge) {
    R17Domain *d=fR17;
    if (!d || !d->installed) return true;
    UInt32 lastRing=0, lastFlight=0;
    bool done=false;
    d->stopOk=false; d->stopFailReason=nullptr;
    const UInt64 t0=mach_absolute_time();
    do {
        UInt32 occ=0, cover=0, flight=0, ring=0;
        if (!r17Gate(true,&occ,&cover,&flight,&ring)) {
            // The backend is unreachable (not "still busy"). That is a real
            // failure of the stop, not something to retry into a timeout.
            d->stopFailReason="backend-unreachable";
            break;
        }
        lastRing=ring; lastFlight=flight;
        if (!flight && !ring && !occ && !cover && !d->driverHeld &&
            !d->driverLive && d->driverMapped==d->driverRetired &&
            r17BackendDrained()) {
            done=true; break;
        }
        IOSleep(1);
    } while (m2b2ToMS(mach_absolute_time()-t0)<budgetMs);
    d->stopOk=done;
    d->stopMs=(UInt32)m2b2ToMS(mach_absolute_time()-t0);
    d->stopLastRing=lastRing;
    d->stopLastFlight=lastFlight;
    d->stopEdge=edge?edge:"?";
    if (!done && !d->stopFailReason) d->stopFailReason="still-owned-at-deadline";
    // Boundary records, named for the event they describe. The driver's latches
    // are the authority: they are stamped when the event happened, not when the
    // probe last looked, so a later poll cannot move them.
    char k[64];
    snprintf(k,sizeof(k),"m2-3e-%s-gate-close",edge);
    setHexProperty(this,k,d->tEdge);
    snprintf(k,sizeof(k),"m2-3e-%s-submit-done",edge);
    setHexProperty(this,k,d->tSubmitDone);
    snprintf(k,sizeof(k),"m2-3e-%s-drain-done",edge);
    setHexProperty(this,k,d->tDrainDone);
    snprintf(k,sizeof(k),"m2-3e-%s-drain",edge);
    setProperty(k,done?"drained":"TIMEOUT");
    snprintf(k,sizeof(k),"m2-3e-%s-drain-ms",edge);
    setHexProperty(this,k,(UInt64)d->stopMs);
    snprintf(k,sizeof(k),"m2-3e-%s-last-ring",edge);
    setHexProperty(this,k,(UInt64)lastRing);
    snprintf(k,sizeof(k),"m2-3e-%s-last-inflight",edge);
    setHexProperty(this,k,(UInt64)lastFlight);
    // tDrainDone above remains the driver's descriptor-drain latch. This is
    // the separate probe observation that software and backend owners are gone.
    snprintf(k,sizeof(k),"m2-3i-%s-retire-confirmed-time",edge);
    setHexProperty(this,k,done?m2b2NowNS():0);
    snprintf(k,sizeof(k),"m2-3i-%s-driver-live",edge);
    setHexProperty(this,k,d->driverLive);
    snprintf(k,sizeof(k),"m2-3i-%s-driver-held",edge);
    setHexProperty(this,k,d->driverHeld);
    snprintf(k,sizeof(k),"m2-3i-%s-driver-mapped",edge);
    setHexProperty(this,k,d->driverMapped);
    snprintf(k,sizeof(k),"m2-3i-%s-driver-retired",edge);
    setHexProperty(this,k,d->driverRetired);
    if (!done) {
        snprintf(k,sizeof(k),"m2-3e-%s-drain-why",edge);
        setProperty(k,d->stopFailReason?d->stopFailReason:"unknown");
    }
    return done;
}

// Round 22 enter, part 2. Called ONLY after the DTE was switched to the
// translation table AND both invalidations completed. The admission word has
// been closed since Install, so no descriptor was submitted against either
// table during the flip; opening it now is the first moment a controlled IOVA
// or an ordinary packet may be submitted again.
bool org_example_AMDMapperProbe::r17EnterComplete(UInt64 tInvComplete) {
    R17Domain *d=fR17;
    if (!d || !d->installed) return false;
    if (!d->stopOk) {
        // The caller must not get here without a successful stop, but if it
        // does, refusing is the only safe answer: the gate stays closed.
        setProperty("m2-3e-enter","REFUSED-no-successful-stop");
        return false;
    }
    UInt32 occ=0, cover=0, flight=0, ring=0;
    if (!r17Gate(false,&occ,&cover,&flight,&ring)) {
        setProperty("m2-3e-enter","FAIL-resume-refused-submissions-in-flight");
        return false;
    }
    d->tTranslateOn=tInvComplete;
    d->enterEdgeSeq++;
    setHexProperty(this,"m2-3e-t-translate-on",d->tTranslateOn);
    setHexProperty(this,"m2-3e-t-gate-open",d->tEdge);
    setProperty("m2-3e-enter","gate-open-after-dte-and-invalidations");
    return true;
}

// ---- round 22: window edges -------------------------------------------------
//
// Both edges talk to the driver through the same platform function that owns
// Install/Disarm/Detach, so they are serialized with it and cannot race the
// detach sequence. Neither of them touches the page table or the command ring:
// that is what makes them safe to call while an output thread is inside
// r17TxMap. Neither of them sleeps either -- see r17StopSubmit for where the
// waiting happens and why.

bool org_example_AMDMapperProbe::r17Gate(bool quiesce, UInt32 *outstanding,
                                         UInt32 *activeCover, UInt32 *inFlight,
                                         UInt32 *ringOwn) {
    R17Domain *d = fR17;
    if (outstanding) *outstanding = 0;
    if (activeCover) *activeCover = 0;
    if (inFlight) *inFlight = 0;
    if (ringOwn) *ringOwn = 0;
    if (!d || !d->installed || !fR15Service) return false;
    r17tx::Configure c = {};
    c.version = r17tx::kVersion; c.bytes = sizeof(c);
    c.op = quiesce ? (UInt32)r17tx::kQuiesce : (UInt32)r17tx::kResume;
    c.bdf = d->snapshot.devid; c.token = fR15Request.reserved;
    const OSSymbol *sym = OSSymbol::withCString(r17tx::kFunctionName);
    if (!sym) return false;
    const IOReturn kr =
        fR15Service->callPlatformFunction(sym, false, &c, nullptr, nullptr, nullptr);
    sym->release();
    if (outstanding) *outstanding = c.outstanding;
    if (activeCover) *activeCover = c.activeCover;
    if (inFlight) *inFlight = c.inFlight;
    if (ringOwn) *ringOwn = c.ringOwn;
    // The driver's latches, not a probe-side clock: these name when the event
    // happened. A failed call must not overwrite them with stale values.
    if (kr == kIOReturnSuccess) {
        d->driverHeld = c.held;
        d->driverLive = c.modeReserved;
        d->driverMapped = c.mapped;
        d->driverRetired = c.retired;
        d->edgeSeq = c.edgeSeq;
        d->tEdge = c.tEdge;
        d->tSubmitDone = c.tSubmitDone;
        d->tDrainDone = c.tDrainDone;
        d->tResume = c.tResume;
        d->gateFails = c.gateFails;
        if (quiesce) d->gateSeq++;
        else d->tGateOpen = c.tEdge;
    } else {
        d->gateFailCount++;
        return false;
    }
    return true;
}

void org_example_AMDMapperProbe::r17SampleExit(UInt32 stage) {
    R17Domain *d = fR17;
    if (!d || !d->installed || !fR15Service) return;
    if (stage != r20tx::kStageExit && stage != r20tx::kStageDrained) return;
    // Ask the driver for a sample at THIS stage explicitly. A bare kQuiesce
    // would sample at its own stage, which is exactly how the round-20 record
    // ended up describing the wrong moment.
    r17tx::Configure c = {};
    c.version = r17tx::kVersion; c.bytes = sizeof(c);
    c.op = r17tx::kSample;
    c.bdf = d->snapshot.devid; c.token = fR15Request.reserved;
    c.state = stage;                     // which step this sample belongs to
    const OSSymbol *sym = OSSymbol::withCString(r17tx::kFunctionName);
    if (!sym) return;
    const IOReturn kr =
        fR15Service->callPlatformFunction(sym, false, &c, nullptr, nullptr, nullptr);
    sym->release();
    if (kr == kIOReturnSuccess) d->exitSamples++;
}

// Round 22 exit, part 2: revoke the controlled admission and release the
// backend. Called ONLY after the device table was restored and read back.
bool org_example_AMDMapperProbe::r17Detach() {
    R17Domain *d = fR17;
    if (!d || !d->installed || !fR15Service) return true;
    const OSSymbol *sym=OSSymbol::withCString(r17tx::kFunctionName);
    if (!sym) return false;
    r17tx::Configure c={};
    c.version=r17tx::kVersion; c.bytes=sizeof(c); c.op=r17tx::kDisarm;
    c.bdf=d->snapshot.devid; c.token=fR15Request.reserved;
    IOReturn kr=kIOReturnBusy;
    for(unsigned i=0;i<100;++i) {
        kr=fR15Service->callPlatformFunction(sym,false,&c,nullptr,nullptr,nullptr);
        if (kr!=kIOReturnBusy) break;
        IOSleep(10);
    }
    bool ok=(kr==kIOReturnSuccess);
    if (ok) {
        c.op=r17tx::kDetach;
        kr=fR15Service->callPlatformFunction(sym,false,&c,nullptr,nullptr,nullptr);
        ok=(kr==kIOReturnSuccess);
    }
    sym->release();
    d->detachOk=ok; d->tDetach=mach_absolute_time();
    setHexProperty(this,"m2-3e-t-detach",d->tDetach);
    setProperty("m2-3e-exit-detach",ok?"detached":"REFUSED");
    if (ok) { d->installed=false; d->accepting=false; }
    return ok;
}

// Round 22 exit, part 3: ordinary output resumes. This is the LAST step and it
// is explicit: Disarm/Detach no longer open the admission word, so a failed or
// skipped hardware restore can never leave ordinary packets flowing against a
// table that is still installed while cover has been disabled.
bool org_example_AMDMapperProbe::r17ResumeOutput() {
    R17Domain *d=fR17;
    if (!d || !fR15Service) return false;
    if (d->installed) return false;   // detach is a precondition, not a default
    r17tx::Configure c={};
    c.version=r17tx::kVersion; c.bytes=sizeof(c);
    c.op=r17tx::kResume;
    c.bdf=d->snapshot.devid; c.token=fR15Request.reserved;
    const OSSymbol *sym=OSSymbol::withCString(r17tx::kFunctionName);
    if (!sym) return false;
    const IOReturn kr=
        fR15Service->callPlatformFunction(sym,false,&c,nullptr,nullptr,nullptr);
    sym->release();
    if (kr!=kIOReturnSuccess) {
        setProperty("m2-3e-after-exit","FAIL-resume-refused");
        return false;
    }
    d->tResume=c.tResume;
    d->resumed=true;
    setHexProperty(this,"m2-3e-t-resume",d->tResume);
    setProperty("m2-3e-after-exit","ordinary-output-resumed");
    return true;
}

bool org_example_AMDMapperProbe::r17Installed() const {
    return fR17 && fR17->installed;
}

void org_example_AMDMapperProbe::r17SetTranslateOff(UInt64 t) {
    if (fR17) fR17->tTranslateOff = t;
}

void org_example_AMDMapperProbe::r17SyncCommand(void *command) {
    // Round22: r17Activate() copies the command context at Install time. When
    // Install moved BEFORE the DTE flip (the whole point of this round), that
    // copy predated the two flip invalidations: the domain then appended its
    // own invalidations at the OLD slot index, over slots the hardware had
    // already consumed, and every CompletionWait timed out. The first selected
    // packet was mapped, refused, and its rollback unmap also failed, so the
    // backend was pinned -- with the net result that no controlled frame was
    // ever transmitted.
    //
    // Handing the caller's current cursors over *after* its own submissions is
    // what makes the two users of the same ring agree on where the head is.
    if (!fR17 || !command) return;
    IOLockLock(fR17->lock);
    fR17->command = *(M2B2CmdCtx *)command;
    fR17->commandOwned = true;
    IOLockUnlock(fR17->lock);
}

void org_example_AMDMapperProbe::r17PublishWindow() {
    R17Domain *d = fR17;
    if (!d) return;
    setHexProperty(this, "m2-3e-gate-seq",        (UInt64)d->gateSeq);
    setHexProperty(this, "m2-3e-gate-fails",      (UInt64)(d->gateFails + d->gateFailCount));
    setHexProperty(this, "m2-3e-exit-samples",    (UInt64)d->exitSamples);
    setHexProperty(this, "m2-3e-t-gate-open",     d->tGateOpen);
    setHexProperty(this, "m2-3e-t-translate-on",  d->tTranslateOn);
    setHexProperty(this, "m2-3e-t-translate-off", d->tTranslateOff);
    setHexProperty(this, "m2-3e-cover-inflight",  (UInt64)d->coverInFlightAtExit);
    setProperty("m2-3e-enter-stop", d->stopOk ? "drained" : "NOT-DRAINED");
}

// Round 22 exit/export. Split out of the old r17Finish so the ordering can be
// seen at the call site (AMDMapperProbePgt.cpp) instead of being implied by the
// side effects of one function:
//
//   r17StopSubmit("exit")  -- no new admission, submitters gone, ring drained
//   r17SampleExit(exit)    -- the forced exit record, taken at that step
//   <caller restores the DTE and reads it back>
//   r17Detach()            -- revoke controlled admission, clear the callback
//   r17ResumeOutput()      -- ordinary output may flow again
//
// Export is unconditional: a pinned run must still leave behind the live PTEs,
// the command words and the records that explain why it was pinned.
void org_example_AMDMapperProbe::r17Export(void *command) {
    R17Domain *d=fR17;
    if (!d) return;
    IOLockLock(d->lock);
    if (d->mmio && command) {
        // An entry invalidation can fail after Install but before SyncCommand.
        // In that case the caller still owns the newest cursor and failure;
        // copying the Install-time snapshot back would erase both of them.
        if (d->commandOwned) *(M2B2CmdCtx *)command=d->command;
        else d->command=*(M2B2CmdCtx *)command;
    }
    auto &s=d->snapshot;
    s.mapsTotal=d->mapsOk; s.retiresTotal=d->retires;
    s.commandCapacity=(UInt32)(M23_CMD_BUF_SIZE/16);
    s.commandSubmits=d->command.submits; s.commandCompleted=d->command.completed;
    s.commandWraps=d->command.wraps; s.commandPostWrapCompleted=d->command.postWrapCompleted;
    s.completionSequence=d->command.completionSequence;
    s.liveOwners=d->liveOwner; s.maxLiveOwners=d->maxLiveOwner; s.slotsUsed=d->slotsUsed;
    s.livePages=d->allocator.livePages; s.peakPages=d->allocator.peakPages;
    s.reusedAllocations=d->allocator.reusedAllocations;
    for (UInt32 k=0;k<amdtx::kSlots;++k) s.slotUses[k]=d->slotUses[k];
    OSData *domainRaw=OSData::withBytes(&d->snapshot,sizeof(d->snapshot));
    OSData *ptRaw=OSData::withBytes((const void *)d->pt,(unsigned)d->ptBytes);
    IOLockUnlock(d->lock);
    OSObject *driverRaw=fR15Service?fR15Service->copyProperty("rtl812x-txmap-raw"):nullptr;
    if (driverRaw) { setProperty("m2-3b-driver-raw",driverRaw); driverRaw->release(); }
    if (domainRaw) { setProperty("m2-3b-domain-raw",domainRaw); domainRaw->release(); }
    if (ptRaw) { setProperty("m2-3b-pt-raw",ptRaw); ptRaw->release(); }
    setHexProperty(this,"m2-3b-submits",(UInt64)d->command.submits);
    setHexProperty(this,"m2-3b-command-capacity",(UInt64)s.commandCapacity);
    setHexProperty(this,"m2-3b-command-completed",(UInt64)s.commandCompleted);
    setHexProperty(this,"m2-3b-command-wraps",(UInt64)s.commandWraps);
    setHexProperty(this,"m2-3b-command-post-wrap-completed",(UInt64)s.commandPostWrapCompleted);
    setHexProperty(this,"m2-3b-completion-sequence",s.completionSequence);
    setHexProperty(this,"m2-3b-history-total",(UInt64)s.historyTotal);
    setHexProperty(this,"m2-3b-history-start",(UInt64)s.historyStart);
    for (UInt32 k=0;k<amdtx::kSlots;++k) {
        char key[40]; snprintf(key,sizeof(key),"m2-3b-slot%u-uses",k);
        setHexProperty(this,key,(UInt64)d->slotUses[k]);
    }
    setHexProperty(this,"m2-3b-map-accepted",(UInt64)d->mapsOk);
    setHexProperty(this,"m2-3b-map-rejected",(UInt64)d->mapsRejected);
    setHexProperty(this,"m2-3b-retires",(UInt64)d->retires);
    setHexProperty(this,"m2-3b-live-owner-max",(UInt64)d->maxLiveOwner);
    setHexProperty(this,"m2-3b-owners-held",(UInt64)d->liveOwner);
    // These properties describe metadata records. Allocator page counts below
    // describe the independent IOVA extents and their reuse.
    setHexProperty(this,"m2-3b-slots-live",(UInt64)d->slotLive);
    setHexProperty(this,"m2-3b-slots-used",(UInt64)d->slotsUsed);
    setHexProperty(this,"m2-3b-slots-capacity",(UInt64)amdtx::kSlots);
    setHexProperty(this,"m2-3m-iova-pages",(UInt64)amdtx::kPages);
    setHexProperty(this,"m2-3m-live-pages",(UInt64)s.livePages);
    setHexProperty(this,"m2-3m-peak-pages",(UInt64)s.peakPages);
    setHexProperty(this,"m2-3m-max-mapped-pages",(UInt64)s.maxMappedPages);
    setHexProperty(this,"m2-3m-reused-allocations",(UInt64)s.reusedAllocations);
    setHexProperty(this,"m2-3b-records",(UInt64)d->snapshot.count);
    publishStdStats();
    r17PublishWindow();
    setProperty("m2-3c-mode", d->stdMode ? "standard-iomapper" : "direct-platform-call");
    setHexProperty(this,"m2-3c-held",(UInt64)d->liveOwner);
}
void org_example_AMDMapperProbe::r17Release() {
    if (!fR17 || fR17->installed) return;
    r27RxRelease();
    if (fR27Rx || fR34Rx) return; // RX owners cannot outlive this page table.
    IOLockFree(fR17->lock); IOFree(fR17,sizeof(*fR17)); fR17=nullptr;
}

// ================== Round18: standard IOMapper entry points ==================
//
// These are the SAME domain records, the SAME invalidations and the SAME owner
// slot as round 17. What changed is who asks: IODMACommand::prepare() reaches
// IOMemoryDescriptor::dmaMap() and that calls iovmMapMemory() on the mapper the
// driver explicitly handed to withSpecification(). Nothing here is called by
// the driver directly, and nothing here is a self-test.
//
// Accepted layout, and why it is bounded:
//   IODMACommand picks ONE of two contracts from what the mapper returns.
//     * mapLength == length  -> a single linear IOVA range; the command derives
//       every DMA address as mapAddress + (logical offset) and never builds
//       fMapSegments. This is the shape a translation backend wants when the
//       bytes keep their in-page offset: the IOVA start is not the page base.
//     * mapLength >  length  -> the command builds fDMAOffset / fMapOffset /
//       fPageOffset per physical run (reference/IODMACommand.xnu-…cpp:946..1047)
//       and gen64IOVMSegments() then answers from that table. NOTE: this branch
//       does NOT call iovmInsert() -- an earlier comment here claimed it did,
//       and round 19 corrects that. Round 18 counted insert-calls as if the
//       contract demanded them; they were always going to be zero.
//   Round 18 implemented the first contract only: one physically contiguous
//   run per call, every fragmented descriptor refused before any PTE was
//   written. Round 19 adds the second contract for bounded fragments: up to
//   amdtx::kSegments runs and amdtx::kMapPages allocation pages, laid out exactly the
//   way AppleVTD::spaceMapMemory does it (page-aligned slot per run, first
//   byte keeps its in-page offset, mapAddress = window base + firstPageOffset).

void org_example_AMDMapperProbe::publishStdStats() {
    setHexProperty(this, "m2-3c-map-calls",    (UInt64)fStdMapCalls);
    setHexProperty(this, "m2-3c-map-ok",       (UInt64)fStdMapOk);
    setHexProperty(this, "m2-3c-map-rejects",  (UInt64)fStdMapRejects);
    setHexProperty(this, "m2-3c-unmap-calls",  (UInt64)fStdUnmapCalls);
    setHexProperty(this, "m2-3c-unmap-ok",     (UInt64)fStdUnmapOk);
    setHexProperty(this, "m2-3c-page-runs",    (UInt64)fStdPageRuns);
    setHexProperty(this, "m2-3c-frag-rejects", (UInt64)fStdFragRejects);
    setHexProperty(this, "m2-3c-off-rejects",  (UInt64)fStdOffsetRejects);
    setHexProperty(this, "m2-3c-insert-calls", (UInt64)fStdInsertRejects);
    setHexProperty(this, "m2-3c-walk-calls",   (UInt64)fStdWalkCalls);
    setHexProperty(this, "m2-3c-runs",         (UInt64)fStdRuns);
    setHexProperty(this, "m2-3c-discontig",    (UInt64)fStdDiscontig);
    setHexProperty(this, "m2-3c-max-runs",     (UInt64)fStdMaxRuns);
    setHexProperty(this, "m2-3c-cap-rejects",  (UInt64)fStdCapRejects);
    // Round20: coverage of ordinary TX objects (kCover). `chunks` counts new
    // 2 MiB identity leaves, `leaves` new 4 KiB ones inside an existing table.
    if (fR17) {
        setHexProperty(this, "m2-3c-cover-calls",   (UInt64)fR17->coverCalls);
        setHexProperty(this, "m2-3c-cover-chunks",  (UInt64)fR17->coverChunks);
        setHexProperty(this, "m2-3c-cover-pages",   (UInt64)fR17->coverPages);
        setHexProperty(this, "m2-3c-cover-leaves",  (UInt64)fR17->coverLeaves);
        setHexProperty(this, "m2-3c-cover-present", (UInt64)fR17->coverPresent);
        setHexProperty(this, "m2-3c-cover-invals",  (UInt64)fR17->coverInvals);
        setHexProperty(this, "m2-3c-cover-fails",   (UInt64)fR17->coverFails);
        setHexProperty(this, "m2-3c-cover-unconf",  (UInt64)fR17->coverUnconfirmedMap);
        if (fR17->coverWhy) setProperty("m2-3c-cover-stop", fR17->coverWhy);
    }
}

static inline UInt64 r18LeafFor(UInt64 pa, UInt32 mapOptions) {
    const UInt64 perms = (mapOptions & (UInt64)kIODMAMapWriteAccess)
        ? (amdpte::PTE_IR | amdpte::PTE_IW) : amdpte::PTE_IR;
    return amdpte::makeDefaultLeaf(1, pa, perms);
}

bool org_example_AMDMapperProbe::r18StdReady() const {
    R17Domain *d = fR17;
    return d && d->installed && d->stdMode && d->stdMapper == (const void *)this;
}

bool org_example_AMDMapperProbe::r18StdOwnsAddress(uint64_t iova) const {
    if (!r18StdReady()) return false;
    return iova >= amdtx::kBase &&
           iova - amdtx::kBase < (UInt64)amdtx::kPages * 4096ULL;
}

bool org_example_AMDMapperProbe::r18StdTranslate(uint64_t iova,
                                                 uint64_t *outPA) const {
    R17Domain *d = fR17;
    if (!outPA || !d || !d->leaves || !r18StdOwnsAddress(iova)) return false;
    const unsigned ix = amdpte::indexAt(1, iova) - amdpte::indexAt(1, amdtx::kBase);
    if (ix >= amdtx::kPages) return false;
    const UInt64 raw = d->leaves[ix];
    if (!raw) return false;
    const auto dec = amdpte::decodePte(raw, 1);
    if (dec.kind != amdpte::PTE_LEAF_DEFAULT && dec.kind != amdpte::PTE_LEAF_LARGE)
        return false;
    *outPA = dec.outPA + (iova & 4095ULL);
    return true;
}

IOReturn org_example_AMDMapperProbe::r18StdMap(
    IOMemoryDescriptor *memory, uint64_t descriptorOffset, uint64_t length,
    uint32_t mapOptions, const IODMAMapSpecification *mapSpecification,
    IODMACommand *dmaCommand, const IODMAMapPageList *pageList,
    uint64_t *mapAddress, uint64_t *mapLength) {
    (void)mapSpecification;
    if (mapAddress) *mapAddress = 0;
    if (mapLength)  *mapLength  = 0;
    fStdMapCalls++;
    R17Domain *d = fR17;
    if (!d) { fStdMapRejects++; return kIOReturnNotReady; }
    IOReturn result = kIOReturnUnsupported;
    IOLockLock(d->lock);
    auto &s = d->snapshot;
    // pageList is deliberately NOT required: it is only an extra cross-check,
    // because its page array is opaque to a third-party kext (see below).
    if (!memory || !dmaCommand || !mapAddress || !mapLength || !length ||
        descriptorOffset) {
        fStdOffsetRejects++; fStdMapRejects++;
        goto out;
    }
    if (!d->installed || !d->stdMode || !d->accepting || d->stdMapper != (void *)this) {
        fStdMapRejects++; result = kIOReturnNotReady;
        goto out;
    }
    {
        // Unsupported mapping semantics: a fixed address or on-device memory
        // cannot be expressed by this backend and must not be half-honoured.
        if (mapOptions & (kIODMAMapFixedAddress | kIODMAMapPhysicallyContiguous)) {
            fStdOffsetRejects++; fStdMapRejects++;
            goto out;
        }
        // The page list itself is NOT readable from a third-party kext: the SDK
        // declares upl_page_info as `unsigned int opaque[2]` and only the in-tree
        // XNU build sees phys_addr. So the physical runs are obtained through the
        // public IOMemoryDescriptor walk (probeLayout), laid out exactly the way
        // AppleVTD does it (page-aligned slots, one per physical run), and the
        // framework's pageOffset is used only as an independent cross-check when
        // present. A fragmented frame costs one page-aligned slot per run, which
        // is what makes *mapLength exceed `length` and selects the command's
        // partial-mapping branch (fDMAOffset/fMapOffset/fPageOffset) -- that
        // branch does NOT call iovmInsert().
        ProbeLayout L = probeLayout(memory, descriptorOffset, length,
                                    (UInt32)amdtx::kSegments);
        if (L.error || !L.runs || L.totalBytes != length || !L.run[0].pa) {
            fStdFragRejects++; fStdMapRejects++;
            goto out;
        }
        if (L.pages > amdtx::kMapPages || L.runs > (UInt32)amdtx::kSegments) {
            // This mapping must fit the bounded per-allocation record.
            fStdCapRejects++; fStdMapRejects++;
            goto out;
        }
        const UInt32 off = L.firstOffset;
        if (pageList && (UInt64)pageList->pageOffset != (UInt64)off) {
            // The framework and the descriptor walk disagree about where the
            // first byte sits inside its page. Never resolve that silently.
            fStdOffsetRejects++; fStdMapRejects++;
            goto out;
        }
        // Metadata and IOVA pages are reserved independently.
        const UInt32 slot = r17TakeSlot(d->slotLive);
        if (slot != kNoSlot) { d->slotsUsed |= 1u << slot; d->slotUses[slot]++; }
        if (slot == kNoSlot) { fStdMapRejects++; result = kIOReturnBusy; goto out; }
        unsigned basePage = 0;
        if (!amdtx::allocate(d->allocator,L.pages,basePage)) {
            d->slotLive &= ~(1u << slot);
            fStdMapRejects++; result = kIOReturnBusy; goto out;
        }
        for (UInt32 i = 0; i < L.pages; i++) {
            if (d->leaves[basePage + i]) {
                amdtx::release(d->allocator,basePage,L.pages);
                d->slotLive &= ~(1u << slot);
                fStdMapRejects++; result = kIOReturnBusy; goto out;
            }
        }
        const UInt32 npages = L.pages;
        // One page-aligned slot per physical run, exactly the layout the command
        // recomputes from fMapSegments: slot i starts at L.run[i].slot and its
        // bytes sit at slot + align -- now shifted into this allocation.
        for (UInt32 i = 0; i < L.runs; i++) {
            L.run[i].slot += (UInt64)basePage * 4096ULL;
            for (UInt32 j = 0; j < L.run[i].pageBytes / 4096U; j++)
                d->leaves[L.run[i].slot / 4096U + j] =
                    r18LeafFor((L.run[i].pa & ~4095ULL) + (UInt64)j * 4096ULL,
                               mapOptions);
        }
        OSSynchronizeIO();
        auto &w = d->slotRecord[slot];
        bzero(&w,sizeof(w));
        w.handle = ++d->handleCounter; d->handle = w.handle;
        // The driver cannot see this return value (IOKit consumed it), so a
        // combined marker is published for it to read back:
        //   [63:32] cumulative issued handles, [31:0] this generation's handle.
        // Bounded history count saturates, so it cannot serve as a new-map mark.
        setProperty("m2-3c-map-mark",
            ((UInt64)d->handleCounter << 32) | (UInt64)(w.handle & 0xFFFFFFFFULL), 64);
        // The mapper never sees the packet, so it cannot stamp token/req: the
        // driver stamps its own handle and the two records are matched on it.
        w.count = L.runs; w.pages = npages; w.token = 0; w.req = 0;
        w.basePage = basePage; w.recordIndex = slot;
        d->slotMemory[slot] = memory; d->slotCommand[slot] = dmaCommand;
        for (UInt32 i = 0; i < L.runs; i++)
            w.segments[i] = { L.run[i].pa, L.run[i].bytes,
                              amdtx::kBase + L.run[i].slot + L.run[i].align };
        // Evidence is local to this allocation, never a copy of neighbours.
        for (UInt32 j = 0; j < npages; j++) w.mapPte[j] = d->leaves[basePage+j];
        for (UInt32 i = 0; i < L.runs; i++)
            for (UInt32 j = 0; j < L.run[i].pageBytes / 4096U; j++)
                w.physical[L.run[i].slot / 4096U - basePage + j] =
                    (L.run[i].pa & ~4095ULL) + (UInt64)j * 4096ULL;
        // The exact length IOKit will hand back to iovmUnmapMemory(): the
        // command stores fLocalMapperAllocLength from this return, so the unmap
        // MUST be checked against this value, not against the logical length.
        w.maplen = L.discontig
            ? (uint32_t)((UInt64)npages * 4096ULL - (UInt64)off) : (uint32_t)length;
        w.tMapPublish = mach_absolute_time();
        d->slotHandle[slot] = w.handle;
        if (!r17Invalidate(d->mmio, d->command, w.mapCommand, "r18-std-map-pages")) {
            // The PTEs are written and the invalidation is NOT confirmed: the
            // translation may still be live, so the slot stays taken and the
            // handle stays issued. No return-to-allocator, no reuse.
            w.status |= 4; s.flags |= 1; d->accepting = false;
            d->liveOwner++; s.active = 1;
            if (d->maxLiveOwner < d->liveOwner) d->maxLiveOwner = d->liveOwner;
            // Round22: name the failure. Without this the run only showed
            // map-calls=1/map-ok=0, which reads like "the mapper refused the
            // packet" instead of "the invalidation never completed".
            setProperty("m2-3c-map-stop", "invalidate-not-confirmed");
            fStdMapRejects++; result = kIOReturnIOError; goto out;
        }
        w.tMapInv = w.mapCommand.tComplete;
        w.status |= 1; s.active = 1;
        d->liveOwner++;
        if (d->maxLiveOwner < d->liveOwner) d->maxLiveOwner = d->liveOwner;
        d->mapsOk++; fStdMapOk++; fStdPageRuns++;
        if (npages>s.maxMappedPages) s.maxMappedPages=npages;
        fStdRuns += L.runs;
        if (L.runs > fStdMaxRuns) fStdMaxRuns = L.runs;
        if (L.discontig) fStdDiscontig++;
        *mapAddress = amdtx::kBase + basePage * 4096ULL + off;
        // One contiguous run keeps the linear contract (mapLength == length, the
        // bytes keep their in-page offset). A fragmented layout returns the
        // page-aligned window length (strictly > length), which is what selects
        // the command's partial-mapping branch; both are recorded in w.maplen.
        *mapLength  = w.maplen;
        result = kIOReturnSuccess;
    }
out:
    IOLockUnlock(d->lock);
    return result;
}

IOReturn org_example_AMDMapperProbe::r18StdUnmap(
    IOMemoryDescriptor *memory, IODMACommand *dmaCommand,
    uint64_t mapAddress, uint64_t mapLength) {
    R17Domain *d = fR17;
    if (!d) return kIOReturnNotReady;
    IOLockLock(d->lock);
    IOReturn result = kIOReturnBadArgument;
    auto &s = d->snapshot;
    // Round23: route the unmap by the address IOKit hands back, not by "the
    // newest generation". With several live mappings there is no such thing as
    // the current one, and clearing the wrong allocation would unmap another
    // frame's bytes while its descriptor is still owned by the device.
    const UInt32 slot = r17SlotOf(d->slotRecord,d->slotLive,mapAddress);
    if (slot >= amdtx::kSlots) {
        IOLockUnlock(d->lock);
        return kIOReturnBadArgument;
    }
    {
        const UInt64 h = d->slotHandle[slot];
        if (!(d->slotLive & (1u << slot)) || !h ||
            d->slotRecord[slot].handle!=h || d->slotRecord[slot].status!=1 ||
            d->slotMemory[slot]!=memory || d->slotCommand[slot]!=dmaCommand) {
            IOLockUnlock(d->lock);
            return kIOReturnBadArgument;
        }
        auto &w = d->slotRecord[slot];
        // Unmap exactly what was handed out. A mismatch means the framework and
        // this backend disagree about the mapping, which is never "close enough".
        // The length is the mapper's own contract (w.maplen), NOT the logical
        // frame length: a fragmented window is page-aligned per run and is
        // therefore larger than the frame.
        if (mapAddress != w.segments[0].iova ||
            mapLength != (uint64_t)w.maplen) {
            IOLockUnlock(d->lock);
            return kIOReturnBadArgument;
        }
        fStdUnmapCalls++;
        const UInt32 base = w.basePage;
        for (UInt32 i = 0; i < w.pages; i++) d->leaves[base + i] = 0;
        OSSynchronizeIO();
        if (!w.tClearPublish) w.tClearPublish = mach_absolute_time();
        for (UInt32 i = 0; i < w.pages; i++) w.clearPte[i] = d->leaves[base+i];
        if (!r17Invalidate(d->mmio, d->command, w.retireCommand, "r32-std-unmap-allocation")) {
            // Keep handle, slot and owner: the translation may still be live.
            w.status |= 8; s.flags |= 2; d->accepting = false;
            result = kIOReturnIOError; goto out;
        }
        w.tRetireInv = w.retireCommand.tComplete;
        w.status |= 2;
        amdtx::release(d->allocator,w.basePage,w.pages);
        r25Archive(s,w);
        d->slotLive &= ~(1u << slot);
        d->slotHandle[slot] = 0;
        d->slotMemory[slot] = nullptr; d->slotCommand[slot] = nullptr;
        if (d->handle == h) d->handle = 0;
        if (d->liveOwner) d->liveOwner--;
        s.active = (d->liveOwner > 0) ? 1 : 0;
        d->retires++; fStdUnmapOk++;
        result = kIOReturnSuccess;
    }
out:
    IOLockUnlock(d->lock);
    return result;
}

// Normal capacity exercise before the driver gate opens. These are genuine
// IOKit mappings, but no NIC descriptor references these private buffers.
// Keep their counts and two completed records separate from packet witnesses.
bool org_example_AMDMapperProbe::r32CapacityProbe() {
    R17Domain *d = fR17;
    if (!d || !r18StdReady() || !d->accepting || !d->commandOwned ||
        !d->stopOk || d->liveOwner || d->allocator.livePages ||
        d->snapshot.probeStart) return false;
    auto &s = d->snapshot;
    s.probeStart = mach_absolute_time();
    const UInt32 mapsBefore = d->mapsOk, retiresBefore = d->retires;
    IOBufferMemoryDescriptor *memory[8] = {};
    IODMACommand *commands[8] = {};
    bool wired[8] = {}, prepared[8] = {};
    UInt64 addresses[8] = {}, firstAddress = 0;
    bool ok = true;

    auto activeRecord = [&](UInt32 i) -> UInt32 {
        for (UInt32 k = 0; k < amdtx::kSlots; ++k)
            if ((d->slotLive & (1u << k)) && d->slotCommand[k] == commands[i])
                return k;
        return kNoSlot;
    };
    auto create = [&](UInt32 i, UInt32 pages) -> bool {
        const IOByteCount bytes = (IOByteCount)pages * 4096ULL;
        memory[i] = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
            kernel_task, kIODirectionInOut | kIOMemoryPhysicallyContiguous,
            bytes, 0xFFFFFFFFFFFFF000ULL);
        if (!memory[i] || memory[i]->prepare(kIODirectionInOut) != kIOReturnSuccess)
            return false;
        wired[i] = true;
        commands[i] = IODMACommand::withSpecification(
            kIODMACommandOutputHost64, 64, 0, IODMACommand::kMapped, 0, 1,
            this, nullptr);
        if (!commands[i] ||
            commands[i]->setMemoryDescriptor(memory[i], true) != kIOReturnSuccess)
            return false;
        prepared[i] = true;
        IODMACommand::Segment64 segment = {};
        UInt64 offset = 0; UInt32 count = 1;
        const UInt32 record = activeRecord(i);
        if (record == kNoSlot ||
            commands[i]->gen64IOVMSegments(&offset, &segment, &count) != kIOReturnSuccess ||
            count != 1 || offset != bytes || segment.fLength != bytes)
            return false;
        const auto &w = d->slotRecord[record];
        uint64_t pa = 0;
        if (segment.fIOVMAddr != w.segments[0].iova ||
            !r18StdTranslate(segment.fIOVMAddr, &pa) || pa != w.segments[0].pa ||
            !r18StdTranslate(segment.fIOVMAddr + bytes - 1, &pa) ||
            pa != w.segments[0].pa + bytes - 1) return false;
        addresses[i] = segment.fIOVMAddr;
        if (d->liveOwner > s.probePeakOwners) s.probePeakOwners = d->liveOwner;
        if (w.pages > s.probeMaxPages) s.probeMaxPages = w.pages;
        return true;
    };
    auto finish = [&](UInt32 i, r17domain::Record *evidence) -> bool {
        bool finished = true;
        UInt64 handle = 0;
        const UInt32 record = commands[i] ? activeRecord(i) : kNoSlot;
        if (record != kNoSlot) handle = d->slotRecord[record].handle;
        if (prepared[i]) {
            if (commands[i]->complete(false, true) != kIOReturnSuccess) finished = false;
            prepared[i] = false;
        }
        if (commands[i] && activeRecord(i) != kNoSlot) {
            // The backend still owns the pages. Keep the corresponding buffer
            // and command alive just as the existing TX failure path does.
            return false;
        }
        if (handle) {
            const auto &last = s.records[(s.historyTotal - 1) % r17domain::kMaxRecords];
            if (last.handle != handle || last.status != 3) finished = false;
            else if (evidence) *evidence = last;
        }
        if (commands[i]) {
            if (commands[i]->clearMemoryDescriptor(false) != kIOReturnSuccess) finished = false;
            commands[i]->release(); commands[i] = nullptr;
        }
        if (memory[i]) {
            if (wired[i] && memory[i]->complete(kIODirectionInOut) != kIOReturnSuccess)
                finished = false;
            memory[i]->release(); memory[i] = nullptr; wired[i] = false;
        }
        return finished;
    };

    for (UInt32 i = 0; i < 8 && ok; ++i) ok = create(i, i ? 1 : 8);
    firstAddress = addresses[0];
    for (UInt32 i = 0; i < 8; ++i)
        if (!finish(i, i ? nullptr : &s.probeFirst)) ok = false;
    if (ok) {
        ok = create(0, 8);
        s.probeReused = ok && addresses[0] == firstAddress;
        if (!finish(0, &s.probeReuse)) ok = false;
    }
    s.probeMaps = d->mapsOk - mapsBefore;
    s.probeUnmaps = d->retires - retiresBefore;
    s.probeEnd = mach_absolute_time();
    ok = ok && s.probeMaps == 9 && s.probeUnmaps == 9 &&
        s.probePeakOwners == 8 && s.probeMaxPages > 4 && s.probeReused &&
        !d->liveOwner && !d->allocator.livePages;
    s.probePassed = ok;
    if (!ok) { d->accepting = false; s.flags |= 4; }
    setProperty("m2-3m-capacity", ok ? "passed" : "failed");
    setHexProperty(this,"m2-3m-probe-maps",s.probeMaps);
    setHexProperty(this,"m2-3m-probe-unmaps",s.probeUnmaps);
    setHexProperty(this,"m2-3m-probe-peak-owners",s.probePeakOwners);
    setHexProperty(this,"m2-3m-probe-max-pages",s.probeMaxPages);
    return ok;
}

// ================= Round28: map-once standard cyclic RX mappings =================
// These callbacks run with the same R17 lock and command cursor as ordinary
// TX. No second command-ring cursor or shared TX slot is introduced.
bool org_example_AMDMapperProbe::r27RxRequested() const {
    return r17ModeRequested("rxstd", 5);
}

bool org_example_AMDMapperProbe::r27RxCandidate(
    IOMemoryDescriptor *memory, IODMACommand *command) const {
    const R27RxDomain *r = __atomic_load_n(&fR27Rx, __ATOMIC_ACQUIRE);
    if (!r) return false;
    for (UInt32 i = 0; i < r27rx::kCount; ++i)
        if ((memory && memory == __atomic_load_n(&r->memory[i], __ATOMIC_ACQUIRE)) ||
            (command && command == __atomic_load_n(&r->command[i], __ATOMIC_ACQUIRE)))
            return true;
    return false;
}

bool org_example_AMDMapperProbe::r27RxOwnsAddress(uint64_t iova) const {
    return (__atomic_load_n(&fR27Rx, __ATOMIC_ACQUIRE) ||
            __atomic_load_n(&fR34Rx, __ATOMIC_ACQUIRE)) && iova >= r27rx::kIovaBase &&
        iova - r27rx::kIovaBase < r27rx::kCount * r27rx::kPagesPerSlot * 4096ULL;
}

bool org_example_AMDMapperProbe::r27RxTranslate(uint64_t iova,
                                              uint64_t *outPA) const {
    R17Domain *d = fR17;
    if (!outPA || !d || !d->leaves || !r27RxOwnsAddress(iova)) return false;
    const UInt32 page = amdtx::kRxFirstPage + (UInt32)((iova - r27rx::kIovaBase) / 4096ULL);
    const volatile UInt64 *leaves = d->iovaL1[page / 512];
    if (!leaves) return false;
    const auto dec = amdpte::decodePte(leaves[page % 512], 1);
    if (dec.kind != amdpte::PTE_LEAF_DEFAULT) return false;
    *outPA = dec.outPA + (iova & 4095ULL);
    return true;
}

IOReturn org_example_AMDMapperProbe::r27RxMap(
    IOMemoryDescriptor *memory, uint64_t descriptorOffset, uint64_t length,
    uint32_t mapOptions, const IODMAMapSpecification *mapSpecification,
    IODMACommand *dmaCommand, const IODMAMapPageList *pageList,
    uint64_t *mapAddress, uint64_t *mapLength) {
    (void)mapSpecification;
    if (mapAddress) *mapAddress = 0;
    if (mapLength) *mapLength = 0;
    R17Domain *d = fR17;
    R27RxDomain *r = __atomic_load_n(&fR27Rx, __ATOMIC_ACQUIRE);
    if (!d || !r) return kIOReturnNotReady;
    IOLockLock(d->lock);
    auto &s = r->snapshot;
    s.mapCalls++;
    IOReturn result = kIOReturnBadArgument;
    UInt32 ix = r27rx::kCount;
    for (UInt32 i = 0; i < r27rx::kCount; ++i)
        if (memory && dmaCommand &&
            memory == __atomic_load_n(&r->memory[i], __ATOMIC_ACQUIRE) &&
            dmaCommand == __atomic_load_n(&r->command[i], __ATOMIC_ACQUIRE))
            { ix = i; break; }
    if (ix == r27rx::kCount || !mapAddress || !mapLength || descriptorOffset ||
        length != r27rx::kCapacity ||
        !(mapOptions & kIODMAMapWriteAccess) ||
        (mapOptions & (kIODMAMapFixedAddress | kIODMAMapPhysicallyContiguous)))
        goto out;
    if (!d->installed || !d->stdMode || !d->commandOwned ||
        !d->accepting || d->stdMapper != (void *)this || r->installed) {
        result = kIOReturnNotReady; goto out;
    }
    {
        auto &w = s.records[ix];
        if (w.flags != r27rx::kMapRegistered) goto out;
        ProbeLayout L = probeLayout(memory, 0, length, 1);
        if (L.error || L.runs != 1 || L.totalBytes != length ||
            L.run[0].pa != w.pa || !L.pages || L.pages > r27rx::kPagesPerSlot ||
            (pageList && pageList->pageOffset != L.firstOffset)) goto out;
        const UInt32 first = amdtx::kRxFirstPage + ix * r27rx::kPagesPerSlot;
        volatile UInt64 *table = d->iovaL1[first / 512];
        if (!table) { result = kIOReturnNotReady; goto out; }
        volatile UInt64 *leaves = table + first % 512;
        for (UInt32 j = 0; j < r27rx::kPagesPerSlot; ++j)
            if (leaves[j]) { result = kIOReturnBusy; goto out; }
        w.pages = L.pages; w.mapOptions = mapOptions;
        w.iova = r27rx::kIovaBase + ix * r27rx::kPagesPerSlot * 4096ULL + L.firstOffset;
        w.mapLength = length;
        // A physically contiguous 4096-byte object may straddle two pages.
        // Its standard mapLength stays 4096, not the reserved stripe length.
        for (UInt32 j = 0; j < w.pages; ++j)
            leaves[j] = amdpte::makeDefaultLeaf(1,
                (w.pa & ~4095ULL) + j * 4096ULL, amdpte::PTE_IR | amdpte::PTE_IW);
        OSSynchronizeIO();
        w.tMapPublish = mach_absolute_time();
        w.flags |= r27rx::kMapPublished;
        s.liveOwners++;
        for (UInt32 j = 0; j < r27rx::kPagesPerSlot; ++j)
            w.mapPte[j] = leaves[j];
        if (!r17Invalidate(d->mmio, d->command, w.mapCommand, "r27-rx-map")) {
            d->accepting = false; result = kIOReturnIOError; goto out;
        }
        w.tMapInv = w.mapCommand.tComplete;
        w.flags |= r27rx::kMapInvalidated;
        *mapAddress = w.iova; *mapLength = w.mapLength;
        s.mapOk++; result = kIOReturnSuccess;
    }
out:
    if (ix < r27rx::kCount) s.records[ix].mapResult = (UInt32)result;
    if (result != kIOReturnSuccess) { s.mapRejects++; s.flags |= r27rx::kBackendMapFailed; }
    IOLockUnlock(d->lock);
    return result;
}

IOReturn org_example_AMDMapperProbe::r27RxUnmap(
    IOMemoryDescriptor *memory, IODMACommand *dmaCommand,
    uint64_t mapAddress, uint64_t mapLength) {
    R17Domain *d = fR17;
    R27RxDomain *r = __atomic_load_n(&fR27Rx, __ATOMIC_ACQUIRE);
    if (!d || !r) return kIOReturnNotReady;
    IOLockLock(d->lock);
    auto &s = r->snapshot;
    s.unmapCalls++;
    IOReturn result = kIOReturnBadArgument;
    UInt32 ix = r27rx::kCount;
    for (UInt32 i = 0; i < r27rx::kCount; ++i)
        if (memory && dmaCommand &&
            memory == __atomic_load_n(&r->memory[i], __ATOMIC_ACQUIRE) &&
            dmaCommand == __atomic_load_n(&r->command[i], __ATOMIC_ACQUIRE))
            { ix = i; break; }
    if (ix == r27rx::kCount) goto out;
    // An installed batch can retire only after gated driver readback confirms
    // that every posted IOVA has been replaced by its original physical mbuf.
    if ((r->installed && !r->drained) || !d->installed || !d->commandOwned) {
        result = kIOReturnNotReady; goto out;
    }
    {
        auto &w = s.records[ix];
        if ((w.flags & (r27rx::kMapInvalidated | r27rx::kMapUnmapped)) !=
                r27rx::kMapInvalidated ||
            mapAddress != w.iova || mapLength != w.mapLength) goto out;
        const UInt32 first = amdtx::kRxFirstPage + ix * r27rx::kPagesPerSlot;
        volatile UInt64 *table = d->iovaL1[first / 512];
        if (!table) { result = kIOReturnNotReady; goto out; }
        volatile UInt64 *leaves = table + first % 512;
        for (UInt32 j = 0; j < r27rx::kPagesPerSlot; ++j) leaves[j] = 0;
        OSSynchronizeIO();
        w.tUnmapPublish = mach_absolute_time();
        for (UInt32 j = 0; j < r27rx::kPagesPerSlot; ++j)
            w.clearPte[j] = leaves[j];
        if (!r17Invalidate(d->mmio, d->command, w.unmapCommand, "r27-rx-unmap")) {
            d->accepting = false; result = kIOReturnIOError; goto out;
        }
        w.tUnmapInv = w.unmapCommand.tComplete;
        w.flags |= r27rx::kMapUnmapped;
        if (s.liveOwners) s.liveOwners--;
        s.unmapOk++; result = kIOReturnSuccess;
    }
out:
    if (ix < r27rx::kCount) s.records[ix].unmapResult = (UInt32)result;
    if (result != kIOReturnSuccess) s.flags |= r27rx::kBackendUnmapFailed;
    IOLockUnlock(d->lock);
    return result;
}

// IODMACommand prepare/complete are client-context operations. The existing
// probe is entered by a workloop timer, so open ONLY that gate while doing
// this work. Retain owner, timer and loop; restore the exact gate state on every
// return; Lucy's gate is held only by its short control operations.
class R27ClientContext {
    IOService *owner;
    R27ProbeTimer *timer;
    IOWorkLoop *loop;
    bool opened;
    R27ClientContext(const R27ClientContext &) = delete;
    R27ClientContext &operator=(const R27ClientContext &) = delete;
public:
    R27ClientContext(IOService *o, R27ProbeTimer *t)
        : owner(o), timer(t), loop(t ? t->getWorkLoop() : nullptr),
          opened(loop && loop->inGate()) {
        owner->retain();
        if (timer) timer->retain();
        if (loop) loop->retain();
        if (opened) timer->openClientGate();
    }
    ~R27ClientContext() {
        if (opened) timer->closeClientGate();
        if (loop) loop->release();
        if (timer) timer->release();
        owner->release();
    }
};

IOReturn org_example_AMDMapperProbe::r27RxControl(UInt32 op) {
    R27RxDomain *r = __atomic_load_n(&fR27Rx, __ATOMIC_ACQUIRE);
    if (!r || !r->driver) return kIOReturnNotReady;
    auto &c = r->control;
    c.version = r27rx::kVersion; c.bytes = sizeof(c); c.op = op;
    const OSSymbol *sym = OSSymbol::withCString(r27rx::kFunctionName);
    if (!sym) return kIOReturnNoMemory;
    IOReturn result = kIOReturnBusy;
    for (UInt32 attempt = 0; attempt < 100; ++attempt) {
        result = r->driver->callPlatformFunction(sym, false, &c, nullptr, nullptr, nullptr);
        if (result != kIOReturnBusy || op == r27rx::kDrain) break;
        IOSleep(1);
    }
    sym->release();
    setHexProperty(this, "m2-3h-rx-last-op", op);
    setHexProperty(this, "m2-3h-rx-last-kr", (UInt32)result);
    return result;
}

bool org_example_AMDMapperProbe::r27RxBegin() {
    if (!r27RxRequested()) return true;
    if (fR31Session) return r34RxBegin();
    if (__atomic_load_n(&fR27Rx, __ATOMIC_ACQUIRE) ||
        !r18StdReady() || !fR17->commandOwned || !fR15Service)
        return false;
    R27ClientContext client(this, fR31Session ? nullptr : fM22b2Timer);
    setProperty("m2-3h-rx-mode", "standard-nonidentity-cyclic1024");
    setProperty("m2-3h-rx-ready", "no");
    setProperty("m2-3h-rx-state", "preparing");
    R27RxDomain *r = (R27RxDomain *)IOMalloc(sizeof(R27RxDomain));
    if (!r) return false;
    bzero(r, sizeof(*r));
    r->driver = fR15Service; r->driver->retain();
    r->snapshot.version = r27rx::kVersion;
    r->snapshot.bytes = sizeof(r->snapshot);
    r->snapshot.count = r27rx::kCount;
    auto &c = r->control;
    c.poolId = fR15Request.poolId;
    c.expectedGeneration = fR15Request.expectedGeneration;
    c.mapCount = r27rx::kCount; c.replaceLimit = r27rx::kCount;
    c.businessToken = fR15Request.reserved;
    __atomic_store_n(&fR27Rx, r, __ATOMIC_RELEASE);
    // withPhysicalAddress does not retain the driver's mbuf. Hold that pool
    // before creating the FIRST MD, including partial-map failure cleanup.
    if (r27RxControl(r27rx::kHold) != kIOReturnSuccess) goto failed;
    r->held = true;
    for (UInt32 i = 0; i < r27rx::kCount; ++i) {
        auto &w = r->snapshot.records[i];
        const auto &e = fR15Request.out.entries[r15pool::kRingCount + i];
        w.pa = e.addr; w.entryId = e.id; w.capacity = e.capacity;
        w.mapResult = (UInt32)kIOReturnNotReady;
        w.unmapResult = (UInt32)kIOReturnNotReady;
        if (!w.pa || w.capacity != r27rx::kCapacity ||
            w.entryId != r15pool::kRingCount + i) goto failed;
        __atomic_store_n(&r->memory[i], IOMemoryDescriptor::withPhysicalAddress(
            (IOPhysicalAddress)w.pa, (IOByteCount)w.capacity, kIODirectionIn), __ATOMIC_RELEASE);
        if (!r->memory[i]) goto failed;
        if (r->memory[i]->prepare(kIODirectionIn) != kIOReturnSuccess) goto failed;
        r->wired[i] = true;
        __atomic_store_n(&r->command[i], IODMACommand::withSpecification(
            kIODMACommandOutputHost64, 64, 0, IODMACommand::kMapped, 0, 1,
            this, nullptr), __ATOMIC_RELEASE);
        if (!r->command[i]) goto failed;
        w.flags = r27rx::kMapRegistered;
        const IOReturn kr = r->command[i]->setMemoryDescriptor(r->memory[i], true);
        if (kr != kIOReturnSuccess) { w.mapResult = (UInt32)kr; goto failed; }
        r->prepared[i] = true;
        IODMACommand::Segment64 segment = {};
        UInt64 offset = 0; UInt32 count = 1;
        uint64_t walked = 0;
        if (r->command[i]->gen64IOVMSegments(&offset, &segment, &count) != kIOReturnSuccess ||
            count != 1 || offset != r27rx::kCapacity ||
            segment.fIOVMAddr != w.iova || segment.fLength != w.capacity ||
            w.iova == w.pa || !r27RxTranslate(w.iova, &walked) || walked != w.pa ||
            !r27RxTranslate(w.iova + w.capacity - 1, &walked) ||
            walked != w.pa + w.capacity - 1) goto failed;
        c.maps[i] = {w.pa, w.iova, w.tMapInv, w.entryId, w.capacity};
    }
    if (r27RxControl(r27rx::kInstall) != kIOReturnSuccess) goto failed;
    r->installed = true;
    // R15 Authorize must follow the LAST RX map invalidation, not just the
    // earlier DTE invalidation. Its finite translation-window bound gates swaps.
    fR15InvTicks = r->snapshot.records[r27rx::kCount - 1].tMapInv;
    r27RxExport();
    setProperty("m2-3h-rx-state", "installed-awaiting-authorize");
    return true;
failed:
    r->snapshot.flags |= r27rx::kBackendMapFailed;
    setProperty("m2-3h-rx-state", "FAIL-map-or-install");
    r27RxExport();
    // Pgt's recovery calls Finish before restoring the DTE. Never discard a
    // command whose mapper published PTEs, even if prepare returned failure.
    return false;
}

void org_example_AMDMapperProbe::r27RxReady() {
    if (fR34Rx) { r34RxReady(); return; }
    R27RxDomain *r = __atomic_load_n(&fR27Rx, __ATOMIC_ACQUIRE);
    if (!r || !r->installed) return;
    r->snapshot.ready = 1;
    r->snapshot.tReady = mach_absolute_time();
    r27RxExport();
    setProperty("m2-3h-rx-state", "ready");
    setProperty("m2-3h-rx-ready", "yes");
}

bool org_example_AMDMapperProbe::r27RxFinish(UInt32 budgetMs) {
    if (fR34Rx) return r34RxFinish(budgetMs);
    R27RxDomain *r = __atomic_load_n(&fR27Rx, __ATOMIC_ACQUIRE);
    if (!r || r->released) return true;
    R27ClientContext client(this, fR31Session ? nullptr : fM22b2Timer);
    setProperty("m2-3h-rx-ready", "no");
    if (r->held) {
        if (r27RxControl(r27rx::kDisarm) != kIOReturnSuccess) goto drainFailed;
        // This is the userspace tail barrier: successful Disarm guarantees no
        // cyclic repost. TX admission remains open until Finish succeeds.
        setProperty("m2-3h-rx-state", "draining");
        setHexProperty(this, "m2-3h-rx-drain-budget-ms", budgetMs);
        UInt64 budgetTicks = 0;
        nanoseconds_to_absolutetime((UInt64)budgetMs * 1000000ULL, &budgetTicks);
        const UInt64 deadline = mach_absolute_time() + budgetTicks;
        do {
            const IOReturn kr = r27RxControl(r27rx::kDrain);
            const auto &s = r->control.out;
            if (kr == kIOReturnSuccess && s.version == r27rx::kVersion &&
                s.bytes == sizeof(s) && s.poolId == r->control.poolId &&
                s.state == r27rx::kDrained && !s.pendingPosted && s.posted == s.completed) {
                // posted/completed count cycles; restored counts distinct
                // objects. Every object's last cycle must be complete and its
                // original ring buffer restored before any standard unmap.
                UInt32 distinct = 0;
                UInt64 posts = 0, completions = 0;
                for (UInt32 i = 0; i < r27rx::kCount; ++i) {
                    const auto &w = s.witnesses[i];
                    if (w.postCount != w.doneCount) goto drainFailed;
                    posts += w.postCount; completions += w.doneCount;
                    if (!w.postCount) continue;
                    ++distinct;
                    if (!(w.flags & r27rx::kWitnessRestored)) goto drainFailed;
                }
                if (s.restored != distinct || posts != s.posted ||
                    completions != s.completed) goto drainFailed;
                // A reset/address mismatch means the ring association proof
                // was lost. A payload-copy error does not prevent safe unmap.
                if (s.flags & (r27rx::kFlagAddressMismatch | r27rx::kFlagRingReset |
                               r27rx::kFlagStopped)) goto drainFailed;
                r->drained = true; break;
            }
            if (kr != kIOReturnSuccess && kr != kIOReturnBusy) goto drainFailed;
            IOSleep(10);
        } while (mach_absolute_time() < deadline);
        if (!r->drained) goto drainFailed;
    } else r->drained = true; // Hold/Install never succeeded: nothing was posted.
    r->snapshot.tDrained = mach_absolute_time();
    for (UInt32 i = 0; i < r27rx::kCount; ++i) {
        auto &w = r->snapshot.records[i];
        if ((w.flags & r27rx::kMapPublished) && !(w.flags & r27rx::kMapInvalidated))
            goto unmapFailed;
        if (r->prepared[i]) {
            // complete() invokes our iovmUnmapMemory. Never retry it after a
            // failed callback: XNU has already dropped its mapping bookkeeping.
            const IOReturn kr = r->command[i]->complete(true, false);
            r->prepared[i] = false;
            if (kr != kIOReturnSuccess || !(w.flags & r27rx::kMapUnmapped))
                goto unmapFailed;
        }
        if ((w.flags & r27rx::kMapPublished) && !(w.flags & r27rx::kMapUnmapped))
            goto unmapFailed;
        if (r->command[i]) {
            if (r->command[i]->clearMemoryDescriptor(false) != kIOReturnSuccess)
                goto unmapFailed;
            // Withdraw routing identity before release can make this address
            // available to a concurrently allocated ordinary TX command.
            IODMACommand *command = __atomic_exchange_n(&r->command[i], nullptr, __ATOMIC_ACQ_REL);
            command->release();
        }
        if (r->memory[i]) {
            if (r->wired[i]) {
                if (r->memory[i]->complete(kIODirectionIn) != kIOReturnSuccess)
                    goto unmapFailed;
                r->wired[i] = false;
            }
            IOMemoryDescriptor *memory = __atomic_exchange_n(&r->memory[i], nullptr, __ATOMIC_ACQ_REL);
            memory->release();
        }
        if (w.flags & r27rx::kMapRegistered) w.flags |= r27rx::kMapReleased;
    }
    if (r->snapshot.liveOwners) goto unmapFailed;
    if (r->held) {
        if (r27RxControl(r27rx::kRelease) != kIOReturnSuccess) {
            r->snapshot.flags |= r27rx::kBackendReleaseFailed;
            setProperty("m2-3h-rx-state", "PINNED-pool-release-refused");
            r27RxExport(); return false;
        }
        r->held = false;
    }
    r->released = true;
    setProperty("m2-3h-rx-state", "drained-and-unmapped");
    r27RxExport();
    return true;
drainFailed:
    r->snapshot.flags |= r27rx::kBackendDrainFailed;
    setProperty("m2-3h-rx-state", "PINNED-RX-not-drained");
    r27RxExport(); return false;
unmapFailed:
    r->snapshot.flags |= r27rx::kBackendUnmapFailed;
    setProperty("m2-3h-rx-state", "PINNED-RX-unmap-failed");
    r27RxExport(); return false;
}

// After RX retirement, keep TX open until the peer echoes the R29D marker
// that userspace sends after receiving every tail reply.
bool org_example_AMDMapperProbe::r29WaitTailDone(UInt32 budgetMs) {
    if (fR34Rx) return r34RxTailDone(budgetMs);
    R27RxDomain *r = __atomic_load_n(&fR27Rx, __ATOMIC_ACQUIRE);
    if (!r || !r->snapshot.ready) return true;
    R27ClientContext client(this, fR31Session ? nullptr : fM22b2Timer);
    setProperty("m2-3i-tail-state", "waiting");
    const UInt64 start = m2b2NowNS();
    do {
        const IOReturn kr = r27RxControl(r27rx::kSnapshot);
        const auto &s = r->control.out;
        if (kr != kIOReturnSuccess || s.version != r27rx::kVersion ||
            s.bytes != sizeof(s) || s.poolId != r->control.poolId ||
            s.businessToken != fR15Request.reserved ||
            s.state != r27rx::kReleased || s.flags || s.pendingPosted) {
            setProperty("m2-3i-tail-state", "PINNED-tail-snapshot");
            r27RxExport(); return false;
        }
        if (s.tailSeq && s.tailSeq <= r27rx::kTailMax) {
            setHexProperty(this, "m2-3i-tail-seq", s.tailSeq);
            // This is the probe's confirmation observation, in mach ticks
            // (m2b2NowNS has the same clock as the existing recovery stamps).
            setHexProperty(this, "m2-3i-tail-confirmed-time", m2b2NowNS());
            setProperty("m2-3i-tail-state", "confirmed");
            r27RxExport(); return true;
        }
        IOSleep(10);
    } while (m2b2ToMS(m2b2NowNS()-start) < budgetMs);
    setProperty("m2-3i-tail-state", "PINNED-tail-timeout");
    r27RxExport(); return false;
}

void org_example_AMDMapperProbe::r27RxExport() {
    if (fR34Rx) { r34RxExport(); return; }
    R27RxDomain *r = __atomic_load_n(&fR27Rx, __ATOMIC_ACQUIRE);
    if (!r) return;
    OSData *raw = OSData::withBytes(&r->snapshot, sizeof(r->snapshot));
    if (raw) { setProperty("m2-3h-rx-map-raw", raw); raw->release(); }
    raw = OSData::withBytes(&r->control.out, sizeof(r->control.out));
    if (raw) { setProperty("m2-3h-rx-raw", raw); raw->release(); }
    setHexProperty(this, "m2-3h-rx-version", r27rx::kVersion);
    setHexProperty(this, "m2-3h-rx-map-ok", r->snapshot.mapOk);
    setHexProperty(this, "m2-3h-rx-unmap-ok", r->snapshot.unmapOk);
    setHexProperty(this, "m2-3h-rx-live-owners", r->snapshot.liveOwners);
    setHexProperty(this, "m2-3h-rx-backend-flags", r->snapshot.flags);
    setHexProperty(this, "m2-3h-rx-posted", r->control.out.posted);
    setHexProperty(this, "m2-3h-rx-completed", r->control.out.completed);
    setHexProperty(this, "m2-3h-rx-restored", r->control.out.restored);
    setHexProperty(this, "m2-3h-rx-pending", r->control.out.pendingPosted);
    UInt64 distinct = 0, reused = 0, reuseCycles = 0, samples = 0;
    for (UInt32 i = 0; i < r27rx::kCount; ++i) {
        const auto &w = r->control.out.witnesses[i];
        if (w.postCount) ++distinct;
        if (w.reuseCount) ++reused;
        reuseCycles += w.reuseCount;
        samples += w.sampleCount;
    }
    setHexProperty(this, "m2-3h-rx-distinct-posted", distinct);
    setHexProperty(this, "m2-3h-rx-reused-objects", reused);
    setHexProperty(this, "m2-3h-rx-reuse-cycles", reuseCycles);
    setHexProperty(this, "m2-3h-rx-cycle-samples", samples);
    setHexProperty(this, "m2-3h-rx-flags", r->control.out.flags);
}

void org_example_AMDMapperProbe::r27RxRelease() {
    if (fR34Rx) { r34RxRelease(); return; }
    R27RxDomain *r = __atomic_load_n(&fR27Rx, __ATOMIC_ACQUIRE);
    if (!r || !r->released || r->held || r->snapshot.liveOwners) return;
    // Called only after the TX backend detached and the original DTE was
    // restored. The exported OSData owns a copy of all final RX evidence.
    for (UInt32 i = 0; i < r27rx::kCount; ++i)
        if (r->command[i] || r->memory[i]) return;
    r->driver->release();
    __atomic_store_n(&fR27Rx, (R27RxDomain *)nullptr, __ATOMIC_RELEASE);
    IOFree(r, sizeof(*r));
}

// ================= Round34: ordinary driver-owned receive mappings ================
// The fixed RX stripes are independent of the dynamic TX allocator. Lucy owns
// each MD/Cmd and mbuf; Bind routes its standard IOKit calls here. A completed
// slot can retire/remap while other slots keep processing DMA.
bool org_example_AMDMapperProbe::r34RxCandidate(
    IOMemoryDescriptor *memory, IODMACommand *command) const {
    const R34RxDomain *r = __atomic_load_n(&fR34Rx, __ATOMIC_ACQUIRE);
    if (!r) return false;
    for (UInt32 i = 0; i < r34rx::kCount; ++i)
        if ((memory && memory == __atomic_load_n(&r->memory[i], __ATOMIC_ACQUIRE)) ||
            (command && command == __atomic_load_n(&r->command[i], __ATOMIC_ACQUIRE)))
            return true;
    return false;
}

int org_example_AMDMapperProbe::r34RxCallback(void *context, r34rx::Binding *b) {
    if (!context) return kIOReturnBadArgument;
    return static_cast<org_example_AMDMapperProbe *>(context)->r34RxOperation(b);
}

IOReturn org_example_AMDMapperProbe::r34RxOperation(r34rx::Binding *b) {
    R17Domain *d = fR17;
    R34RxDomain *r = __atomic_load_n(&fR34Rx, __ATOMIC_ACQUIRE);
    if (!d || !r || !b || b->version != r34rx::kVersion ||
        b->bytes != sizeof(*b) || b->slot >= r34rx::kCount)
        return kIOReturnBadArgument;
    if (b->op == r34rx::kBatchMap || b->op == r34rx::kBatchUnmap)
        return r34RxBatch(b);
    IOLockLock(d->lock);
    auto &s = r->snapshot;
    auto &w = s.slots[b->slot].last;
    const bool live = (w.flags & r34rx::kMapPublished) &&
                      !(w.flags & r34rx::kMapUnmapped);
    IOReturn result = kIOReturnBadArgument;
    if (b->op == r34rx::kBind) {
        if (!b->memory || !b->command || r->memory[b->slot] ||
            r->command[b->slot] || r->released) goto done;
        __atomic_store_n(&r->memory[b->slot],
            static_cast<IOMemoryDescriptor *>(b->memory), __ATOMIC_RELEASE);
        __atomic_store_n(&r->command[b->slot],
            static_cast<IODMACommand *>(b->command), __ATOMIC_RELEASE);
        ++s.boundPairs;
        result = kIOReturnSuccess;
    } else if (b->op == r34rx::kRead) {
        b->out = w;
        result = kIOReturnSuccess;
    } else if (b->op == r34rx::kUnbind) {
        if (live || !r->memory[b->slot] || !r->command[b->slot]) goto done;
        __atomic_store_n(&r->memory[b->slot], (IOMemoryDescriptor *)nullptr,
                         __ATOMIC_RELEASE);
        __atomic_store_n(&r->command[b->slot], (IODMACommand *)nullptr,
                         __ATOMIC_RELEASE);
        --s.boundPairs;
        result = kIOReturnSuccess;
    } else if (b->op == r34rx::kRetireBootstrap) {
        // Lucy calls once, after all 1024 distinct slots publish their first
        // IOVA OWN and the current batch has finished. No physical RX remains.
        if (b->slot || b->length != r34rx::kCount || !b->pa ||
            !r->installed || r->released || r->bootstrapRetired ||
            !r->activePt || r->activePtBytes != d->ptBytes ||
            !d->installed || !d->commandOwned || s.coverCalls ||
            s.boundPairs != r34rx::kCount || s.liveOwners != r34rx::kCount)
            goto retireFailed;
        for (UInt32 slot = 0; slot < r34rx::kCount; ++slot)
            if (s.slots[slot].mapCount < 2 || r->preMapped[slot] ||
                r->preUnmapped[slot]) goto retireFailed;
        {
            amdsparse::Arena a = {d->pt, d->ptBase,
                (unsigned)(d->ptBytes / 4096ULL), d->coverNext,
                d->rootLevel, d->ptBase, 0, 0, nullptr};
            auto fixed = [&](UInt64 page) -> bool {
                for (UInt32 i = 0; i < r34rx::kPhysicalSpanCount; ++i) {
                    const auto &span = r->physical.spans[i];
                    if (page < span.pa + span.bytes && page + 4096ULL > span.pa)
                        return true;
                }
                return false;
            };
            unsigned removed = 0;
            for (UInt32 slot = 0; slot < r34rx::kCount; ++slot) {
                if (!amdsparse::unmapOwnedRange(a,
                        r->control.out.slots[slot].originalPA,
                        r34rx::kCapacity, fixed, removed)) {
                    d->accepting = false;
                    goto retireFailed;
                }
            }
            OSSynchronizeIO();
            r->tBootstrapClear = mach_absolute_time();
            if (r->tBootstrapClear < b->pa ||
                removed != r->bootstrapPages - r->fixedPages ||
                !r17Invalidate(d->mmio, d->command, r->bootstrapRetireCommand,
                               "r38-rx-bootstrap-retire")) {
                d->accepting = false;
                goto retireFailed;
            }
            // Preallocated during Prepare; take the active image before any
            // other mapper operation can modify the table under the same lock.
            for (UInt32 i = 0; i < r->activePtBytes / sizeof(UInt64); ++i)
                static_cast<UInt64 *>(r->activePt)[i] = d->pt[i];
            r->removedPages = removed;
            r->bootstrapRetired = true;
            result = kIOReturnSuccess;
            goto done;
        }
retireFailed:
        s.flags |= r34rx::kFlagUnmapFailed;
        result = kIOReturnIOError;
    } else if (b->op == r34rx::kCover) {
        ++s.coverCalls;
        if (live || !b->pa || b->length != r34rx::kCapacity ||
            !d->installed || !d->commandOwned) goto coverFailed;
        {
            // Stop returns the CURRENT native mbuf to physical DMA, which can
            // differ from the initial ring. Confirm its identity mapping
            // before Lucy writes physical OWN. Keep RX accounting separate.
            amdsparse::Arena a = {d->pt, d->ptBase,
                (unsigned)(d->ptBytes / 4096ULL), d->coverNext,
                d->rootLevel, d->ptBase, 0, 0, nullptr};
            const bool mapped = amdsparse::mapOwnedRange(a, b->pa, b->length);
            d->coverNext = a.next;
            if (!mapped) { d->accepting = false; goto coverFailed; }
            if (a.addedPages || a.addedLeaves) {
                r17domain::Command rec = {};
                OSSynchronizeIO();
                if (!r17Invalidate(d->mmio, d->command, rec,
                                   "r34-rx-physical-restore")) {
                    d->accepting = false;
                    goto coverFailed;
                }
            }
            r->restoreAddedPages += a.addedLeaves;
            ++s.coverOk;
            result = kIOReturnSuccess;
            goto done;
        }
coverFailed:
        ++s.coverFailed;
        s.flags |= r34rx::kFlagCoverFailed;
        result = kIOReturnIOError;
    }
done:
    IOLockUnlock(d->lock);
    return result;
}

// Only the native receive loop uses this private precommit operation. A
// successful standard map/unmap still returns after hardware invalidation;
// it merely consumes the result already confirmed for its own MD/Cmd pair.
IOReturn org_example_AMDMapperProbe::r34RxBatch(r34rx::Binding *b) {
    R17Domain *d = fR17;
    R34RxDomain *r = __atomic_load_n(&fR34Rx, __ATOMIC_ACQUIRE);
    if (!d || !r || !b || b->version != r34rx::kVersion ||
        b->bytes != sizeof(*b) || b->slot >= r34rx::kCount ||
        !b->length || b->length > r34rx::kBatchSize ||
        (b->op != r34rx::kBatchMap && b->op != r34rx::kBatchUnmap))
        return kIOReturnBadArgument;
    const bool mapping = b->op == r34rx::kBatchMap;
    const UInt32 count = (UInt32)b->length;
    const UInt32 batch = b->slot | (count << 16);
    // Cache only the compact physical layout, not sixteen ProbeLayout objects
    // on the kernel stack. The driver has already prepared these descriptors.
    UInt64 physical[r34rx::kBatchSize] = {};
    UInt32 pages[r34rx::kBatchSize] = {};
    UInt64 published = 0;
    r17domain::Command command = {};
    IOReturn result = kIOReturnBadArgument;
    IOLockLock(d->lock);
    auto &s = r->snapshot;
    if (!r->installed || r->released || !d->installed || !d->stdMode ||
        !d->commandOwned || !d->accepting || d->stdMapper != (void *)this) {
        result = kIOReturnNotReady; goto done;
    }
    // Validate the complete group before changing any leaf. Every member is
    // still owned by the driver and none has been re-published with OWN.
    for (UInt32 n = 0; n < count; ++n) {
        const UInt32 slot = (b->slot + n) & (r34rx::kCount - 1);
        const auto &w = s.slots[slot].last;
        if (!r->memory[slot] || !r->command[slot] ||
            r->preMapped[slot] || r->preUnmapped[slot]) goto done;
        const UInt32 first = amdtx::kRxFirstPage + slot * r34rx::kPagesPerSlot;
        volatile UInt64 *table = d->iovaL1[first / 512];
        if (!table) { result = kIOReturnNotReady; goto done; }
        volatile UInt64 *leaves = table + first % 512;
        if (mapping) {
            if ((w.flags & r34rx::kMapPublished) && !(w.flags & r34rx::kMapUnmapped))
                goto done;
            const ProbeLayout layout = probeLayout(r->memory[slot], 0, r34rx::kCapacity, 1);
            if (layout.error || layout.runs != 1 || layout.totalBytes != r34rx::kCapacity ||
                !layout.pages || layout.pages > r34rx::kPagesPerSlot) goto done;
            for (UInt32 j = 0; j < r34rx::kPagesPerSlot; ++j)
                if (leaves[j]) { result = kIOReturnBusy; goto done; }
            physical[n] = layout.run[0].pa;
            pages[n] = layout.pages;
        } else if ((w.flags & (r34rx::kMapInvalidated | r34rx::kMapUnmapped)) !=
                   r34rx::kMapInvalidated) goto done;
    }
    for (UInt32 n = 0; n < count; ++n) {
        const UInt32 slot = (b->slot + n) & (r34rx::kCount - 1);
        auto &entry = s.slots[slot];
        auto &w = entry.last;
        const UInt32 first = amdtx::kRxFirstPage + slot * r34rx::kPagesPerSlot;
        volatile UInt64 *leaves = d->iovaL1[first / 512] + first % 512;
        if (mapping) {
            bzero(&w, sizeof(w));
            w.generation = (UInt64)entry.mapCount + 1;
            w.memory = (UInt64)(uintptr_t)r->memory[slot];
            w.command = (UInt64)(uintptr_t)r->command[slot];
            w.pa = physical[n];
            w.iova = r34rx::kIovaBase + slot * r34rx::kPagesPerSlot * 4096ULL +
                     (w.pa & 4095ULL);
            w.mapLength = r34rx::kCapacity; w.slot = slot; w.pages = pages[n];
            w.mapOptions = kIODMAMapWriteAccess;
            w.mapResult = w.unmapResult = (UInt32)kIOReturnNotReady;
            w.mapBatch = batch;
            for (UInt32 j = 0; j < w.pages; ++j)
                leaves[j] = amdpte::makeDefaultLeaf(1,
                    (w.pa & ~4095ULL) + j * 4096ULL, amdpte::PTE_IR | amdpte::PTE_IW);
            w.flags = r34rx::kMapPublished;
            ++s.liveOwners;
            for (UInt32 j = 0; j < r34rx::kPagesPerSlot; ++j) w.mapPte[j] = leaves[j];
        } else {
            for (UInt32 j = 0; j < r34rx::kPagesPerSlot; ++j) leaves[j] = 0;
            for (UInt32 j = 0; j < r34rx::kPagesPerSlot; ++j) w.clearPte[j] = leaves[j];
            w.unmapBatch = batch;
        }
    }
    OSSynchronizeIO();
    published = mach_absolute_time();
    for (UInt32 n = 0; n < count; ++n) {
        auto &w = s.slots[(b->slot + n) & (r34rx::kCount - 1)].last;
        if (mapping) w.tMapPublish = published;
        else w.tUnmapPublish = published;
    }
    if (mapping) ++r->mapBatchCalls;
    else ++r->unmapBatchCalls;
    if (!r17Invalidate(d->mmio, d->command, command,
                      mapping ? "r36-rx-batch-map" : "r36-rx-batch-unmap")) {
        d->accepting = false; result = kIOReturnIOError; goto done;
    }
    for (UInt32 n = 0; n < count; ++n) {
        const UInt32 slot = (b->slot + n) & (r34rx::kCount - 1);
        auto &w = s.slots[slot].last;
        if (mapping) {
            w.mapCommand = command; w.tMapInv = command.tComplete;
            w.flags |= r34rx::kMapInvalidated;
            r->preMapped[slot] = true;
        } else {
            w.unmapCommand = command; w.tUnmapInv = command.tComplete;
            r->preUnmapped[slot] = true;
        }
    }
    if (mapping) { ++r->mapInvalidations; r->mapBatchSlots += count; }
    else { ++r->unmapInvalidations; r->unmapBatchSlots += count; }
    if (count > r->maxBatch) r->maxBatch = count;
    result = kIOReturnSuccess;
done:
    if (result != kIOReturnSuccess)
        s.flags |= mapping ? r34rx::kFlagMapFailed : r34rx::kFlagUnmapFailed;
    IOLockUnlock(d->lock);
    return result;
}

IOReturn org_example_AMDMapperProbe::r34RxMap(
    IOMemoryDescriptor *memory, uint64_t descriptorOffset, uint64_t length,
    uint32_t mapOptions, const IODMAMapSpecification *mapSpecification,
    IODMACommand *dmaCommand, const IODMAMapPageList *pageList,
    uint64_t *mapAddress, uint64_t *mapLength) {
    (void)mapSpecification;
    if (mapAddress) *mapAddress = 0;
    if (mapLength) *mapLength = 0;
    R17Domain *d = fR17;
    R34RxDomain *r = __atomic_load_n(&fR34Rx, __ATOMIC_ACQUIRE);
    if (!d || !r) return kIOReturnNotReady;
    IOLockLock(d->lock);
    auto &s = r->snapshot;
    ++s.mapCalls;
    UInt32 slot = r34rx::kCount;
    IOReturn result = kIOReturnBadArgument;
    for (UInt32 i = 0; i < r34rx::kCount; ++i)
        if (memory && dmaCommand && memory == r->memory[i] &&
            dmaCommand == r->command[i]) { slot = i; break; }
    if (slot == r34rx::kCount || !mapAddress || !mapLength || descriptorOffset ||
        length != r34rx::kCapacity || !(mapOptions & kIODMAMapWriteAccess) ||
        (mapOptions & (kIODMAMapFixedAddress | kIODMAMapPhysicallyContiguous)))
        goto done;
    if (!d->installed || !d->stdMode || !d->commandOwned || !d->accepting ||
        d->stdMapper != (void *)this || r->released) {
        result = kIOReturnNotReady; goto done;
    }
    {
        auto &entry = s.slots[slot];
        auto &w = entry.last;
        const ProbeLayout L = probeLayout(memory, 0, length, 1);
        if (L.error || L.runs != 1 || L.totalBytes != length ||
            !L.pages || L.pages > r34rx::kPagesPerSlot ||
            (pageList && pageList->pageOffset != L.firstOffset)) goto done;
        if (r->preMapped[slot]) {
            // The private batch already published and invalidated this exact
            // prepared MD. Success is synchronous, just as in the scalar path.
            if (r->preUnmapped[slot] ||
                (w.flags & (r34rx::kMapInvalidated | r34rx::kMapUnmapped)) !=
                    r34rx::kMapInvalidated ||
                w.memory != (UInt64)(uintptr_t)memory ||
                w.command != (UInt64)(uintptr_t)dmaCommand ||
                w.pa != L.run[0].pa || w.pages != L.pages || w.mapLength != length)
                goto done;
            r->preMapped[slot] = false;
            w.mapOptions = mapOptions;
            *mapAddress = w.iova; *mapLength = w.mapLength;
            ++entry.mapCount; ++s.mapOk;
            result = kIOReturnSuccess;
            goto done;
        }
        if ((w.flags & r34rx::kMapPublished) && !(w.flags & r34rx::kMapUnmapped))
            goto done;
        const UInt32 first = amdtx::kRxFirstPage + slot * r34rx::kPagesPerSlot;
        volatile UInt64 *table = d->iovaL1[first / 512];
        if (!table) { result = kIOReturnNotReady; goto done; }
        volatile UInt64 *leaves = table + first % 512;
        for (UInt32 j = 0; j < r34rx::kPagesPerSlot; ++j)
            if (leaves[j]) { result = kIOReturnBusy; goto done; }
        bzero(&w, sizeof(w));
        w.generation = (UInt64)entry.mapCount + 1;
        w.memory = (UInt64)(uintptr_t)memory;
        w.command = (UInt64)(uintptr_t)dmaCommand;
        w.pa = L.run[0].pa;
        w.iova = r34rx::kIovaBase + slot * r34rx::kPagesPerSlot * 4096ULL + L.firstOffset;
        w.mapLength = length; w.slot = slot; w.pages = L.pages;
        w.mapOptions = mapOptions;
        w.unmapResult = (UInt32)kIOReturnNotReady;
        for (UInt32 j = 0; j < w.pages; ++j)
            leaves[j] = amdpte::makeDefaultLeaf(1,
                (w.pa & ~4095ULL) + j * 4096ULL, amdpte::PTE_IR | amdpte::PTE_IW);
        OSSynchronizeIO();
        w.tMapPublish = mach_absolute_time();
        w.flags = r34rx::kMapPublished;
        ++s.liveOwners;
        for (UInt32 j = 0; j < r34rx::kPagesPerSlot; ++j) w.mapPte[j] = leaves[j];
        if (!r17Invalidate(d->mmio, d->command, w.mapCommand, "r34-rx-map")) {
            d->accepting = false; result = kIOReturnIOError; goto done;
        }
        ++r->mapInvalidations;
        w.tMapInv = w.mapCommand.tComplete;
        w.flags |= r34rx::kMapInvalidated;
        *mapAddress = w.iova; *mapLength = w.mapLength;
        ++entry.mapCount; ++s.mapOk;
        result = kIOReturnSuccess;
    }
done:
    if (slot < r34rx::kCount) s.slots[slot].last.mapResult = (UInt32)result;
    if (result != kIOReturnSuccess) { ++s.mapRejects; s.flags |= r34rx::kFlagMapFailed; }
    IOLockUnlock(d->lock);
    return result;
}

IOReturn org_example_AMDMapperProbe::r34RxUnmap(
    IOMemoryDescriptor *memory, IODMACommand *dmaCommand,
    uint64_t mapAddress, uint64_t mapLength) {
    R17Domain *d = fR17;
    R34RxDomain *r = __atomic_load_n(&fR34Rx, __ATOMIC_ACQUIRE);
    if (!d || !r) return kIOReturnNotReady;
    IOLockLock(d->lock);
    auto &s = r->snapshot;
    ++s.unmapCalls;
    UInt32 slot = r34rx::kCount;
    IOReturn result = kIOReturnBadArgument;
    for (UInt32 i = 0; i < r34rx::kCount; ++i)
        if (memory && dmaCommand && memory == r->memory[i] &&
            dmaCommand == r->command[i]) { slot = i; break; }
    if (slot == r34rx::kCount || !d->installed || !d->commandOwned) goto done;
    {
        auto &entry = s.slots[slot];
        auto &w = entry.last;
        if ((w.flags & (r34rx::kMapInvalidated | r34rx::kMapUnmapped)) !=
            r34rx::kMapInvalidated || mapAddress != w.iova || mapLength != w.mapLength ||
            r->preMapped[slot]) goto done;
        if (r->preUnmapped[slot]) {
            // The batch CW completed before the driver called Cmd.complete().
            // This call now releases the standard owner's accounting once.
            r->preUnmapped[slot] = false;
        } else {
            const UInt32 first = amdtx::kRxFirstPage + slot * r34rx::kPagesPerSlot;
            volatile UInt64 *table = d->iovaL1[first / 512];
            if (!table) { result = kIOReturnNotReady; goto done; }
            volatile UInt64 *leaves = table + first % 512;
            for (UInt32 j = 0; j < r34rx::kPagesPerSlot; ++j) leaves[j] = 0;
            OSSynchronizeIO();
            w.tUnmapPublish = mach_absolute_time();
            for (UInt32 j = 0; j < r34rx::kPagesPerSlot; ++j) w.clearPte[j] = leaves[j];
            if (!r17Invalidate(d->mmio, d->command, w.unmapCommand, "r34-rx-unmap")) {
                d->accepting = false; result = kIOReturnIOError; goto done;
            }
            ++r->unmapInvalidations;
            w.tUnmapInv = w.unmapCommand.tComplete;
        }
        w.flags |= r34rx::kMapUnmapped;
        w.unmapResult = kIOReturnSuccess;
        --s.liveOwners; ++s.unmapOk; ++entry.unmapCount;
        // Generation one was prepared before replacing physical ring entries.
        // Retain the first actual IOVA generation, then keep last authoritative.
        if (w.generation > 1 && entry.sampleCount < r34rx::kSamples)
            entry.samples[entry.sampleCount++] = w;
        result = kIOReturnSuccess;
    }
done:
    if (slot < r34rx::kCount) s.slots[slot].last.unmapResult = (UInt32)result;
    if (result != kIOReturnSuccess) s.flags |= r34rx::kFlagUnmapFailed;
    IOLockUnlock(d->lock);
    return result;
}

IOReturn org_example_AMDMapperProbe::r34RxControl(UInt32 op) {
    R34RxDomain *r = fR34Rx;
    if (!r || !r->driver) return kIOReturnNotReady;
    auto &c = r->control;
    c.version = r34rx::kVersion; c.bytes = sizeof(c); c.op = op;
    const OSSymbol *sym = OSSymbol::withCString(r34rx::kFunctionName);
    if (!sym) return kIOReturnNoMemory;
    IOReturn result = kIOReturnBusy;
    for (UInt32 attempt = 0; attempt < 100; ++attempt) {
        result = r->driver->callPlatformFunction(sym, false, &c, nullptr, nullptr, nullptr);
        if (result != kIOReturnBusy || op == r34rx::kDrain) break;
        IOSleep(1);
    }
    sym->release();
    setHexProperty(this, "m2-3h-rx-last-op", op);
    setHexProperty(this, "m2-3h-rx-last-kr", (UInt32)result);
    return result;
}

bool org_example_AMDMapperProbe::r34RxPrepareMap(
        volatile UInt64 *pt, UInt64 ptBase, UInt32 totalPages, UInt32 basePages) {
    if (!fR31Session || fR34Rx || fR27Rx || !fR15Service || !fR15Request.reserved)
        return false;
    R27ClientContext client(this, nullptr);
    R34RxDomain *r = (R34RxDomain *)IOMalloc(sizeof(R34RxDomain));
    if (!r) return false;
    bzero(r, sizeof(*r));
    r->activePtBytes = totalPages * 4096u;
    r->activePt = IOMalloc(r->activePtBytes);
    if (!r->activePt) { IOFree(r, sizeof(*r)); return false; }
    r->driver = fR15Service; r->driver->retain();
    r->snapshot.version = r34rx::kVersion;
    r->snapshot.bytes = sizeof(r->snapshot);
    r->snapshot.count = r34rx::kCount;
    r->control.businessToken = fR15Request.reserved;
    r->control.mapper = this; r->control.context = this;
    r->control.callback = &org_example_AMDMapperProbe::r34RxCallback;
    __atomic_store_n(&fR34Rx, r, __ATOMIC_RELEASE);
    setProperty("m2-3h-rx-mode", "native-ring-batch16");
    setProperty("m2-3h-rx-ready", "no");
    setProperty("m2-3h-rx-state", "preparing");
    if (r34RxControl(r34rx::kPrepare) != kIOReturnSuccess) {
        setProperty("m2-3h-rx-state", "FAIL-native-prepare"); return false;
    }
    const auto &s = r->control.out;
    r->prepared = true;
    r->control.ringId = s.ringId;
    if (s.version != r34rx::kVersion || s.bytes != sizeof(s) ||
        s.state != r34rx::kPrepared || s.flags || !s.ringId ||
        !r->control.expectedGeneration || s.slotCount != r34rx::kCount ||
        s.businessToken != fR15Request.reserved || s.maps || s.nativeActive) {
        setProperty("m2-3h-rx-state", "FAIL-native-ring-manifest"); return false;
    }
    setProperty("m2-3p-rx-source", "lucy-normal-ring");
    setHexProperty(this, "m2-3p-rx-ring-id", s.ringId);
    setHexProperty(this, "m2-3p-rx-ring-generation", r->control.expectedGeneration);
    setHexProperty(this, "m2-3p-rx-spares", 0);
    setHexProperty(this, "m2-3p-rx-pool-rpcs", fR15PoolRpcCalls);
    OSObject *layoutObject = r->driver->copyProperty("rtl812x-r37-physical-layout");
    OSData *layoutData = OSDynamicCast(OSData, layoutObject);
    const bool haveLayout = layoutData && layoutData->getLength() == sizeof(r->physical);
    if (haveLayout)
        memcpy(&r->physical, layoutData->getBytesNoCopy(), sizeof(r->physical));
    if (layoutObject) layoutObject->release();
    if (!haveLayout || r->physical.version != r34rx::kPhysicalLayoutVersion ||
        r->physical.bytes != sizeof(r->physical) ||
        r->physical.generation != r->control.expectedGeneration ||
        r->physical.count != r34rx::kPhysicalSpanCount) {
        setProperty("m2-3h-rx-state", "FAIL-native-physical-layout"); return false;
    }
    // Prepare holds the existing physical ring copy-only. It does not take
    // mbuf ownership, allocate spare buffers, or alter any NIC-owned address.
    // The root starts empty: fixed NIC DMA objects and the current RX buffers
    // receive only the 4 KiB leaves intersecting their actual spans.
    amdsparse::Arena arena = {pt, ptBase, totalPages, basePages,
        fM22b2Use3L ? 3u : 4u, ptBase, 0, 0, nullptr};
    auto read = [&](UInt64 pa, unsigned ix) -> UInt64 {
        volatile amdsparse::u64 *table = amdsparse::table(arena, pa);
        return table ? table[ix] : 0;
    };
    UInt32 mapped = 0, walked = 0;
    UInt64 maxEnd = 0;
    auto mapAndWalk = [&](UInt64 pa, UInt64 bytes) -> bool {
        if (!amdsparse::mapOwnedRange(arena, pa, bytes)) return false;
        // A descriptor ring exceeds the bounded business-range witness.
        // Walk every intersecting page directly, including both permissions.
        for (UInt64 page = pa & ~4095ULL; page < pa + bytes; page += 4096ULL) {
            amdbw::Path path;
            if (!amdbw::walkOne(read, arena.rootLevel, ptBase, page, path) ||
                path.leafSize != 4096 || path.leafPA != page ||
                !amdbw::pathPermOk(path, false) || !amdbw::pathPermOk(path, true)) {
                arena.why = "native-identity-not-4k-rw";
                return false;
            }
            ++walked;
        }
        return true;
    };
    for (UInt32 i = 0; i < r34rx::kPhysicalSpanCount; ++i) {
        const auto &span = r->physical.spans[i];
        if (!mapAndWalk(span.pa, span.bytes)) {
            setProperty("m2-3h-rx-state", "FAIL-native-fixed-dma-map");
            setProperty("m2-3p-rx-map-why", arena.why ? arena.why : "fixed-dma-span");
            setHexProperty(this, "m2-3r-physical-bad-span", i);
            return false;
        }
    }
    r->fixedPages = arena.addedLeaves;
    for (UInt32 slot = 0; slot < r34rx::kCount; ++slot) {
        const UInt64 pa = s.slots[slot].originalPA;
        if (!mapAndWalk(pa, r34rx::kCapacity)) {
            setProperty("m2-3h-rx-state", "FAIL-native-bootstrap-map");
            setProperty("m2-3p-rx-map-why", arena.why ? arena.why : "invalid-ring-span");
            setHexProperty(this, "m2-3p-rx-map-bad-slot", slot);
            return false;
        }
        ++mapped;
        if (pa + r34rx::kCapacity > maxEnd) maxEnd = pa + r34rx::kCapacity;
    }
    r->physicalNext = arena.next;
    r->bootstrapPages = arena.addedLeaves;
    OSSynchronizeIO();
    fR15MapTicks = mach_absolute_time();
    setHexProperty(this, "m2-3p-rx-bootstrap-map-time", fR15MapTicks);
    setHexProperty(this, "m2-3p-rx-bootstrap-ranges", mapped);
    setHexProperty(this, "m2-3p-rx-bootstrap-max-end", maxEnd);
    setHexProperty(this, "m2-3p-rx-sparse-pages", arena.addedPages);
    setHexProperty(this, "m2-3p-rx-sparse-leaves", arena.addedLeaves);
    setHexProperty(this, "m2-3p-rx-pt-used-pages", arena.next);
    // This is the native software self-check. The legacy Pgt sample list
    // assumes a flat RAM aperture and cannot describe an owned sparse table.
    setProperty("m2-b2-walk", "ok");
    setProperty("m2-b2-walk-basis", "owned-sparse-4k");
    setHexProperty(this, "m2-b2-walk-samples", walked);
    setHexProperty(this, "m2-b2-walk-checked", walked);
    setHexProperty(this, "m2-b2-walk-bad", 0);
    UInt64 oneSecondNS = 0;
    absolutetime_to_nanoseconds(1000000000ULL, &oneSecondNS);
    if (oneSecondNS != 1000000000ULL) {
        setProperty("m2-3h-rx-state", "FAIL-native-timebase"); return false;
    }
    setProperty("m2-b2-map-limit-kind", "owned-ranges-no-aperture");
    setProperty("m2-3h-rx-state", "native-ring-mapped-before-dte");
    r34RxExport();
    return true;
}

bool org_example_AMDMapperProbe::r34RxBegin() {
    R34RxDomain *r = fR34Rx;
    if (!r || r->installed || fR27Rx || !r18StdReady() || !fR17->commandOwned ||
        r->control.out.state != r34rx::kPrepared || !fR15MapTicks)
        return false;
    R27ClientContext client(this, nullptr);
    if (r34RxControl(r34rx::kInstall) != kIOReturnSuccess) {
        r->snapshot.flags |= r34rx::kFlagMapFailed;
        setProperty("m2-3h-rx-state", "FAIL-native-install");
        r34RxExport(); return false;
    }
    r->installed = true;
    // Install stamps this after the driver's 1024 initial prepares complete.
    fR15InvTicks = r->control.out.tInstalled;
    setProperty("m2-3h-rx-state", "installed-awaiting-authorize");
    r34RxExport();
    return true;
}

bool org_example_AMDMapperProbe::r34RxAuthorize() {
    R34RxDomain *r = fR34Rx;
    if (!r || !r->installed || !fR15InvTicks ||
        r->control.out.maps != r34rx::kCount || r->control.out.flags)
        return false;
    R27ClientContext client(this, nullptr);
    const bool ok = r34RxControl(r34rx::kAuthorize) == kIOReturnSuccess;
    setProperty("m2-3p-rx-authorize", ok ? "done" : "FAIL");
    setHexProperty(this, "m2-3p-rx-authorize-deadline", r->control.deadline);
    return ok;
}

bool org_example_AMDMapperProbe::r34RxResumePhysical() {
    R34RxDomain *r = fR34Rx;
    if (!r || r->physicalResumed) return true;
    if (!r->prepared) {
        // A refused Prepare has not frozen or borrowed the driver's ring.
        r->released = r->physicalResumed = true;
        return true;
    }
    if (r->snapshot.liveOwners || r->snapshot.boundPairs ||
        (!r->released && r->control.out.state != r34rx::kPrepared)) return false;
    R27ClientContext client(this, nullptr);
    // Lucy starts the physical ring once, then reports Busy until link and
    // actual RX/TX enable are restored. Wait outside its command gate before
    // Detach and ordinary output resume; do not restart it on every poll.
    const UInt64 start = m2b2NowNS();
    IOReturn result = kIOReturnBusy;
    do {
        result = r34RxControl(r34rx::kResumePhysical);
        if (result != kIOReturnBusy) break;
        IOSleep(10);
    } while (m2b2ToMS(m2b2NowNS() - start) < 5000);
    if (result != kIOReturnSuccess) {
        setProperty("m2-3p-rx-physical-resume", "FAIL"); return false;
    }
    r->physicalResumed = true;
    r->released = true; // A Prepare-only cancellation has no MD/Cmd to release.
    setProperty("m2-3p-rx-physical-resume", "done");
    r34RxExport();
    return true;
}

void org_example_AMDMapperProbe::r34RxReady() {
    R34RxDomain *r = fR34Rx;
    if (!r || !r->installed) return;
    r->snapshot.ready = 1;
    r->snapshot.tReady = mach_absolute_time();
    setHexProperty(this, "m2-3o-rx-ready-time", r->snapshot.tReady);
    setProperty("m2-3h-rx-state", "ready");
    setProperty("m2-3h-rx-ready", "yes");
    r34RxExport();
}

bool org_example_AMDMapperProbe::r34RxFinish(UInt32 budgetMs) {
    R34RxDomain *r = fR34Rx;
    if (!r || r->released) return true;
    // Before Install the unchanged physical ring is already safe for restore;
    // ResumePhysical will unfreeze it after the hardware state is restored.
    if (!r->installed && !r->snapshot.liveOwners && !r->snapshot.boundPairs)
        return true;
    R27ClientContext client(this, fR31Session ? nullptr : fM22b2Timer);
    setProperty("m2-3h-rx-ready", "no");
    if (r34RxControl(r34rx::kDisarm) != kIOReturnSuccess) goto failed;
    setProperty("m2-3h-rx-state", "draining");
    setHexProperty(this, "m2-3h-rx-drain-budget-ms", budgetMs);
    {
        const UInt64 start = m2b2NowNS();
        bool drained = false;
        do {
            const IOReturn kr = r34RxControl(r34rx::kDrain);
            const auto &s = r->control.out;
            if (kr == kIOReturnSuccess && s.version == r34rx::kVersion &&
                s.bytes == sizeof(s) && s.state == r34rx::kDrained && !s.flags &&
                !s.pendingPosted && s.posted == s.completed + s.stopRetired &&
                s.restored == r34rx::kCount && s.maps == s.unmaps &&
                !r->snapshot.liveOwners) { drained = true; break; }
            if (kr != kIOReturnSuccess && kr != kIOReturnBusy) break;
            IOSleep(10);
        } while (m2b2ToMS(m2b2NowNS() - start) < budgetMs);
        if (!drained) goto failed;
    }
    r->snapshot.tDrained = mach_absolute_time();
    if (r34RxControl(r34rx::kRelease) != kIOReturnSuccess ||
        r->snapshot.boundPairs || r->snapshot.liveOwners) goto failed;
    r->released = true;
    setProperty("m2-3h-rx-state", "drained-and-unmapped");
    r34RxExport();
    return true;
failed:
    setProperty("m2-3h-rx-state", "PINNED-native-RX-not-drained");
    r34RxExport();
    return false;
}

bool org_example_AMDMapperProbe::r34RxTailDone(UInt32 budgetMs) {
    R34RxDomain *r = fR34Rx;
    if (!r || !r->snapshot.ready) return true;
    R27ClientContext client(this, fR31Session ? nullptr : fM22b2Timer);
    setProperty("m2-3i-tail-state", "waiting");
    const UInt64 start = m2b2NowNS();
    do {
        const IOReturn kr = r34RxControl(r34rx::kSnapshot);
        const auto &s = r->control.out;
        if (kr != kIOReturnSuccess || s.state != r34rx::kReleased || s.flags ||
            s.pendingPosted || s.businessToken != fR15Request.reserved) break;
        if (s.tailSeq && s.tailSeq <= r34rx::kTailMax) {
            setHexProperty(this, "m2-3i-tail-seq", s.tailSeq);
            setHexProperty(this, "m2-3i-tail-confirmed-time", m2b2NowNS());
            setProperty("m2-3i-tail-state", "confirmed");
            r34RxExport(); return true;
        }
        IOSleep(10);
    } while (m2b2ToMS(m2b2NowNS() - start) < budgetMs);
    setProperty("m2-3i-tail-state", "PINNED-tail-timeout");
    r34RxExport(); return false;
}

void org_example_AMDMapperProbe::r34RxExport() {
    R34RxDomain *r = fR34Rx;
    if (!r) return;
    // Native bootstrap exists before the TX/page-table backend is prepared.
    OSData *activeRaw = nullptr, *retireRaw = nullptr;
    if (fR17) IOLockLock(fR17->lock);
    OSData *raw = OSData::withBytes(&r->snapshot, sizeof(r->snapshot));
    if (r->bootstrapRetired) {
        activeRaw = OSData::withBytes(r->activePt, r->activePtBytes);
        retireRaw = OSData::withBytes(&r->bootstrapRetireCommand,
                                     sizeof(r->bootstrapRetireCommand));
    }
    if (fR17) IOLockUnlock(fR17->lock);
    if (raw) { setProperty("m2-3o-rx-backend-raw", raw); raw->release(); }
    raw = OSData::withBytes(&r->control.out, sizeof(r->control.out));
    if (raw) { setProperty("m2-3o-rx-driver-raw", raw); raw->release(); }
    setHexProperty(this, "m2-3o-rx-version", r34rx::kVersion);
    setHexProperty(this, "m2-3h-rx-map-ok", r->snapshot.mapOk);
    setHexProperty(this, "m2-3h-rx-unmap-ok", r->snapshot.unmapOk);
    setHexProperty(this, "m2-3h-rx-live-owners", r->snapshot.liveOwners);
    setHexProperty(this, "m2-3h-rx-backend-flags", r->snapshot.flags);
    setHexProperty(this, "m2-3h-rx-posted", r->control.out.posted);
    setHexProperty(this, "m2-3h-rx-completed", r->control.out.completed);
    setHexProperty(this, "m2-3h-rx-stop-retired", r->control.out.stopRetired);
    setHexProperty(this, "m2-3h-rx-restored", r->control.out.restored);
    setHexProperty(this, "m2-3h-rx-pending", r->control.out.pendingPosted);
    setHexProperty(this, "m2-3h-rx-flags", r->control.out.flags);
    setHexProperty(this, "m2-3o-rx-replacements", r->control.out.replaced);
    setHexProperty(this, "m2-3o-rx-bound-pairs", r->snapshot.boundPairs);
    setHexProperty(this, "m2-3o-rx-physical-cover-ok", r->snapshot.coverOk);
    setHexProperty(this, "m2-3q-rx-map-invalidations", r->mapInvalidations);
    setHexProperty(this, "m2-3q-rx-unmap-invalidations", r->unmapInvalidations);
    setHexProperty(this, "m2-3q-rx-map-batch-calls", r->mapBatchCalls);
    setHexProperty(this, "m2-3q-rx-unmap-batch-calls", r->unmapBatchCalls);
    setHexProperty(this, "m2-3q-rx-map-batch-slots", r->mapBatchSlots);
    setHexProperty(this, "m2-3q-rx-unmap-batch-slots", r->unmapBatchSlots);
    setHexProperty(this, "m2-3q-rx-max-batch", r->maxBatch);
    raw = OSData::withBytes(&r->physical, sizeof(r->physical));
    if (raw) { setProperty("m2-3r-physical-layout", raw); raw->release(); }
    setProperty("m2-3r-physical-mode", "owned-sparse-4k");
    setHexProperty(this, "m2-3r-bootstrap-pages", r->bootstrapPages);
    setHexProperty(this, "m2-3r-restore-added-pages", r->restoreAddedPages);
    setHexProperty(this, "m2-3r-identity-pages",
                   r->bootstrapPages - r->removedPages + r->restoreAddedPages);
    if (fR17) setHexProperty(this, "m2-3r-pt-used-pages", fR17->coverNext);
    setProperty("m2-3s-rx-bootstrap-retired", r->bootstrapRetired ? "yes" : "no");
    setHexProperty(this, "m2-3s-fixed-pages", r->fixedPages);
    setHexProperty(this, "m2-3s-bootstrap-removed-pages", r->removedPages);
    setHexProperty(this, "m2-3s-bootstrap-clear-time", r->tBootstrapClear);
    setHexProperty(this, "m2-3s-bootstrap-retire-time", r->bootstrapRetireCommand.tComplete);
    if (activeRaw) { setProperty("m2-3s-rx-active-pt-raw", activeRaw); activeRaw->release(); }
    if (retireRaw) { setProperty("m2-3s-rx-bootstrap-retire-command", retireRaw); retireRaw->release(); }
}

void org_example_AMDMapperProbe::r34RxRelease() {
    R34RxDomain *r = fR34Rx;
    if (!r || !r->released || !r->physicalResumed ||
        r->snapshot.liveOwners || r->snapshot.boundPairs) return;
    // Lucy has completed/unbound its objects; final OSData copies own evidence.
    r->driver->release();
    __atomic_store_n(&fR34Rx, (R34RxDomain *)nullptr, __ATOMIC_RELEASE);
    IOFree(r->activePt, r->activePtBytes);
    IOFree(r, sizeof(*r));
}
