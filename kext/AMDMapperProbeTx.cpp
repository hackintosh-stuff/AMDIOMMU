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
// Round25: four active slots own mappings independently of a circular history
// of the last 32 completed retirements. History exhaustion never gates Map.
// The original command ring is reused using hardware HEAD and bounded waits;
// each mapping owner is released only after its own retire CompletionWait.
#include "AMDMapperProbeInternal.hpp"
#include "amd_iommu_tx_core.hpp"
#include "../tools/lucy-obs/AMDAliveTxDomainNative.hpp"
#include "../tools/lucy-obs/RTL812xTxMapStd.hpp"
#include <IOKit/IOLocks.h>

// Round25: the original command buffer is reused circularly, with finite
// per-submit waits. Completed evidence is circular and never owns live state.

struct org_example_AMDMapperProbe::R17Domain {
    IOLock *lock;
    volatile UInt8 *mmio;
    volatile UInt64 *pt, *leaves;
    UInt64 ptBase, ptBytes, handle, handleCounter;
    M2B2CmdCtx command;
    // Install precedes the caller's DTE invalidations. The domain owns this
    // cursor only after r17SyncCommand hands it over before opening admission.
    bool commandOwned;
    r17domain::Snapshot snapshot;
    bool installed, accepting;
    // Live DMA owners. Round23: a COUNT (0..amdtx::kSlots), not a flag. An
    // accepted Map takes one of the fixed window slots, a confirmed Retire gives
    // exactly that slot back; the other live mappings are untouched.
    UInt32 liveOwner, maxLiveOwner, mapsOk, mapsRejected, retires;
    // Round23: the fixed slots. slotLive is a bitmask; slotHandle[k] is the
    // generation handle owning slot k. Handles are UInt64 (r17domain::Record::
    // handle) and are compared verbatim against Request::handle, so storing the
    // full width here is what keeps that comparison exact.
    UInt32 slotLive;
    UInt64 slotHandle[amdtx::kSlots];
    // Round23: which stripes have ever been used, and how many times each was
    // handed out. The first proves the window is not leaked (only kSlots
    // distinct stripes may appear); the second shows reuse.
    UInt32 slotsUsed, slotUses[amdtx::kSlots];
    r17domain::Record slotRecord[amdtx::kSlots]; // authoritative active mappings; never overwritten by history
    // Round18: the same owner slot, entered through IOMapper virtuals instead of
    // the platform callback. Only one of the two entry paths may be armed.
    bool stdMode;
    void *stdMapper;
    // Round20: identity coverage of ordinary TX objects (kCover). `coverNext`
    // is the first table page this path may use; the 64 GiB window consumed two
    // of the four pages reserved for it. `rootLevel` is the live table's root.
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
    const char *stopEdge, *stopFailReason;
    UInt64 tDetach;
    // Explicit "unconfirmed mapping modification" state. After invalidate() fails,
    // new cover requests are refused until explicit recovery (detach/retire). This
    // prevents using stale present bits from a failed attempt on subsequent chunks.
    bool coverUnconfirmedMap;
};

bool org_example_AMDMapperProbe::r17Prepare(volatile UInt64 *pt, UInt64 base,
                                           UInt32 pages) {
    if (fR17 || pages < 5) return false;
    R17Domain *d = (R17Domain *)IOMalloc(sizeof(R17Domain));
    if (!d) return false;
    bzero(d, sizeof(*d));
    d->lock = IOLockAlloc();
    if (!d->lock) { IOFree(d,sizeof(*d)); return false; }
    fR17 = d;
    d->pt=pt; d->ptBase=base; d->ptBytes=pages*4096ULL;
    // Command space is checked against hardware HEAD on each submission.
    // RX sparse arena excludes the last four pages. These pages are exclusively
    // reserved for this IOVA subtree, initialized while root is inactive.
    amdsparse::Arena a={pt,base,pages,pages-4,
        fM22b2Use3L?3u:4u,base,0,0,nullptr};
    d->rootLevel = a.rootLevel;
    d->leaves=amdtx::prepare(a);
    if (!d->leaves) { setProperty("m2-3b-prepare","FAIL-iova-conflict"); return false; }
    // amdtx::prepare() consumes exactly two table pages from the reserved tail;
    // whatever is left may be used by the round-20 cover path, never beyond.
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

// Round23: take a free window slot, or kNoSlot. Called with d->lock held, so
// two Maps cannot be handed the same stripe.
static const UInt32 kNoSlot = 0xffffffffu;
static UInt32 r17TakeSlot(UInt32 &liveMask) {
    for (UInt32 k = 0; k < amdtx::kSlots; ++k) {
        if (liveMask & (1u << k)) continue;
        liveMask |= (1u << k);
        return k;
    }
    return kNoSlot;
}

// Which stripe does a generation's IOVA fall in? Every segment the plan produced
// starts inside [kBase + slot*4p*4096, kBase + (slot+1)*4p*4096), so the answer
// follows from the address alone. Returning kNoSlot for anything outside the
// window is what makes a bad handle a refusal instead of a wild clear.
static UInt32 r17SlotOf(UInt64 iova) {
    if (iova < amdtx::kBase) return kNoSlot;
    const UInt64 off = iova - amdtx::kBase;
    const UInt64 span = (UInt64)amdtx::kPages * 4096ULL;
    if (off >= span) return kNoSlot;
    return (UInt32)(off / ((UInt64)amdtx::kPagesPerSlot * 4096ULL));
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
    IOLockLock(d->lock);
    auto &s=d->snapshot;
    IOReturn result=kIOReturnNotReady;
    if (r->bdf!=s.devid || !d->installed) goto out;
    if (op==r17tx::kMap) {
        // Round23: `d->handle` is no longer a single "the one live generation"
        // marker -- it records the most recently issued handle for Query, and
        // whether a slot is free is decided by the slot mask below.
        if (!d->accepting || r->handle ||
            r->token!=self->fR15Request.reserved ||
            r->reqId<1 || r->reqId>r17tx::kRequestLimit ||
            !r->count || r->count>amdtx::kSegments) {
            d->mapsRejected++; result=kIOReturnBadArgument; goto out;
        }
        {
            // A slot is reserved BEFORE the geometry is planned, because the
            // plan needs to know which stripe it may use. A refused plan gives
            // the slot straight back, so a rejection never consumes one.
            const UInt32 slot=r17TakeSlot(d->slotLive);
            if (slot!=kNoSlot) { d->slotsUsed|=1u<<slot; d->slotUses[slot]++; }
            if (slot==kNoSlot) { d->mapsRejected++; result=kIOReturnBusy; goto out; }
            amdtx::Segment input[amdtx::kSegments]={};
            amdtx::Plan plan;
            for (UInt32 i=0;i<r->count;++i) input[i]={r->physical[i].address,r->physical[i].length,0};
            if (!amdtx::plan(plan,input,r->count,slot)) {
                d->slotLive&=~(1u<<slot);
                d->mapsRejected++; result=kIOReturnUnsupported; goto out;
            }
            // Admission depends only on a free active slot, never on history.
            // Only THIS stripe must be absent. Round 22 required the whole
            // window to be empty, which is exactly the restriction this round
            // removes: a page of another live mapping is not this one's to
            // check, and touching it would be the overlap bug.
            for (unsigned i=0;i<amdtx::kPagesPerSlot;++i)
                if (d->leaves[plan.basePage+i]) {
                    d->slotLive&=~(1u<<slot);
                    d->mapsRejected++; result=kIOReturnBusy; goto out;
                }
            for (unsigned i=0;i<plan.pages;++i)
                d->leaves[plan.basePage+i]=
                    amdpte::makeDefaultLeaf(1,plan.physical[plan.basePage+i],
                                            amdpte::PTE_IR);
            OSSynchronizeIO();
            auto &w=d->slotRecord[slot];
            bzero(&w,sizeof(w));
            w.handle=++d->handleCounter; d->handle=w.handle; r->handle=w.handle;
            w.count=plan.count; w.pages=plan.pages; w.token=r->token; w.req=r->reqId;
            d->slotHandle[slot]=w.handle;
            for(unsigned i=0;i<plan.count;++i) {
                const auto &p=plan.segments[i];
                w.segments[i]={p.pa,p.bytes,p.iova};
                r->iova[i]={p.iova,p.bytes};
            }
            OSSynchronizeIO();
            w.tMapPublish=mach_absolute_time();
            for(unsigned i=0;i<amdtx::kPages;++i) w.mapPte[i]=d->leaves[i];
            for(unsigned i=0;i<amdtx::kPages;++i) w.physical[i]=plan.physical[i];
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
        if (!r->count || r->count>amdtx::kSegments) {
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
                r17SlotOf(w.segments[0].iova)!=slot || w.status!=1) {
                result=kIOReturnBadArgument; goto out;
            }
            const UInt32 base=slot*amdtx::kPagesPerSlot;
            for(unsigned i=0;i<amdtx::kPagesPerSlot;++i) d->leaves[base+i]=0;
            OSSynchronizeIO();
            if (!w.tClearPublish) w.tClearPublish=mach_absolute_time();
            for(unsigned i=0;i<amdtx::kPages;++i) w.clearPte[i]=d->leaves[i];
            // Round23: name the slot in the label so a timeout says WHICH
            // generation's unmap did not complete.
            // M2B2CmdCtx retains this pointer in records/failReason until
            // export, so a stack-formatted label would already be dangling.
            static const char *const labels[amdtx::kSlots] = {
                "r17-retire-slot0", "r17-retire-slot1",
                "r17-retire-slot2", "r17-retire-slot3"
            };
            if (!r17Invalidate(d->mmio,d->command,w.retireCommand,labels[slot])) {
                // Keep handle, slot and owner: this translation may still be
                // live, and freeing the stripe would let the next Map reuse
                // PTEs the device is still translating through.
                w.status|=8; s.flags|=2; d->accepting=false;
                result=kIOReturnIOError; goto out;
            }
            w.tRetireInv=w.retireCommand.tComplete; r->tRetire=w.tRetireInv;
            w.status|=2; s.active=(d->liveOwner>1)?1:0;
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

bool org_example_AMDMapperProbe::r17Activate(volatile UInt8 *base, void *command) {
    if (!fR17 || !fR15Service) return false;
    auto *d=fR17;
    d->mmio=base; d->command=*(M2B2CmdCtx *)command;
    d->commandOwned=false;
    d->snapshot.devid=d->command.devid; d->snapshot.domid=d->command.domid;
    const bool stdMode=r17ModeRequested("std", 3);
    const bool allTx=r17ModeRequested("alltx", 5);
    if (allTx && !stdMode) {
        setProperty("m2-3g-mode", "invalid-alltx-requires-std");
        return false;
    }
    d->stdMode=stdMode; d->stdMapper=stdMode?this:nullptr;
    r17tx::Configure c={};
    c.version=r17tx::kVersion; c.bytes=sizeof(c); c.op=r17tx::kInstall;
    c.bdf=d->command.devid; c.token=fR15Request.reserved;
    // Covers the finite 60-second window and its drain. In all-TX mode the
    // token identifies this run; packet admission does not inspect that token.
    c.deadline=mach_absolute_time()+120000000000ULL;
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

// Round 22: stop admitting submissions and wait until both of these hold:
//
//   (a) no admitted submission is between the gate and its OWN bit, and
//   (b) the ring holds no descriptor the device still owns.
//
// (a) BEFORE (b) is the whole point. Round 21 closed a flag and read the ring,
// so a thread that had passed the flag but not yet written OWN was invisible:
// the drain could report "empty" and the DTE flip raced that thread. The
// barrier's reference count makes (a) a counted fact, and the ring only shrinks
// after a completion, so once both hold nothing can appear behind us.
//
// The wait happens HERE, on the probe's thread. kQuiesce itself never sleeps:
// the caller's other thread is the driver workloop, which is the context that
// reaps completed descriptors, so waiting there would wait for itself.
bool org_example_AMDMapperProbe::r17StopSubmit(UInt32 budgetMs, const char *edge) {
    R17Domain *d=fR17;
    if (!d || !d->installed) return true;
    UInt32 lastRing=0, lastFlight=0;
    bool done=false;
    UInt64 t0=mach_absolute_time();
    for (UInt32 i=0;i<budgetMs;i++) {
        UInt32 occ=0, cover=0, flight=0, ring=0;
        if (!r17Gate(true,&occ,&cover,&flight,&ring)) {
            // The backend is unreachable (not "still busy"). That is a real
            // failure of the stop, not something to retry into a timeout.
            d->stopFailReason="backend-unreachable";
            break;
        }
        lastRing=ring; lastFlight=flight;
        if (flight==0 && ring==0) {
            // Confirm with a second read. The word is closed and the reference
            // count is zero, so no submission can appear between the two reads;
            // this only guards against a completion that was mid-walk.
            IOSleep(2);
            UInt32 occ2=0, cover2=0, flight2=0, ring2=0;
            if (!r17Gate(true,&occ2,&cover2,&flight2,&ring2)) {
                d->stopFailReason="backend-unreachable";
                break;
            }
            if (flight2==0 && ring2==0) { done=true; lastRing=0; lastFlight=0; break; }
            lastRing=ring2; lastFlight=flight2;
        }
        IOSleep(1);
    }
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
    // Round23: the slots themselves. `slots-live` is the mask of window stripes
    // currently owned; `slots-used` counts every distinct slot ever handed out,
    // so "the same four stripes were reused" is checkable without trusting the
    // driver's own owner count.
    setHexProperty(this,"m2-3b-slots-live",(UInt64)d->slotLive);
    setHexProperty(this,"m2-3b-slots-used",(UInt64)d->slotsUsed);
    setHexProperty(this,"m2-3b-slots-capacity",(UInt64)amdtx::kSlots);
    setHexProperty(this,"m2-3b-records",(UInt64)d->snapshot.count);
    publishStdStats();
    r17PublishWindow();
    setProperty("m2-3c-mode", d->stdMode ? "standard-iomapper" : "direct-platform-call");
    setHexProperty(this,"m2-3c-held",(UInt64)d->liveOwner);
}
void org_example_AMDMapperProbe::r17Release() {
    if (!fR17 || fR17->installed) return;
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
//   amdtx::kSegments runs and amdtx::kPages window pages, laid out exactly the
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
        if (L.pages > amdtx::kPagesPerSlot || L.runs > (UInt32)amdtx::kSegments) {
            // Capacity: refused before a single PTE is written, so a window this
            // backend cannot express never becomes a half-built mapping. Round23
            // bounds this by ONE STRIPE, not the whole window: a mapping that
            // does not fit in its slot would collide with another live one.
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
        // Round23: take a stripe first (the layout below is relative to it), and
        // give it straight back on every path that refuses.
        const UInt32 slot = r17TakeSlot(d->slotLive);
        if (slot != kNoSlot) { d->slotsUsed |= 1u << slot; d->slotUses[slot]++; }
        if (slot == kNoSlot) { fStdMapRejects++; result = kIOReturnBusy; goto out; }
        const UInt32 basePage = slot * amdtx::kPagesPerSlot;
        // Only THIS stripe must be absent; the other live mappings own theirs.
        for (UInt32 i = 0; i < amdtx::kPagesPerSlot; i++) {
            if (d->leaves[basePage + i]) {
                d->slotLive &= ~(1u << slot);
                fStdMapRejects++; result = kIOReturnBusy; goto out;
            }
        }
        const UInt32 npages = L.pages;
        // One page-aligned slot per physical run, exactly the layout the command
        // recomputes from fMapSegments: slot i starts at L.run[i].slot and its
        // bytes sit at slot + align -- now shifted into this stripe.
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
        for (UInt32 i = 0; i < L.runs; i++)
            w.segments[i] = { L.run[i].pa, L.run[i].bytes,
                              amdtx::kBase + L.run[i].slot + L.run[i].align };
        // The record keeps the FULL window snapshot (all 16 pages), so the
        // analyzer sees a stable array and can tell its own stripe from the
        // other live ones; only the pages this stripe owns are non-zero here.
        for (UInt32 j = 0; j < amdtx::kPages; j++) {
            w.physical[j] = 0;
            w.mapPte[j]   = d->leaves[j];
        }
        for (UInt32 i = 0; i < L.runs; i++)
            for (UInt32 j = 0; j < L.run[i].pageBytes / 4096U; j++)
                w.physical[L.run[i].slot / 4096U + j] =
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
    (void)memory; (void)dmaCommand;
    R17Domain *d = fR17;
    if (!d) return kIOReturnNotReady;
    IOLockLock(d->lock);
    IOReturn result = kIOReturnBadArgument;
    auto &s = d->snapshot;
    // Round23: route the unmap by the address IOKit hands back, not by "the
    // newest generation". With several live mappings there is no such thing as
    // the current one, and clearing the wrong stripe would unmap another
    // frame's bytes while its descriptor is still owned by the device.
    const UInt32 slot = r17SlotOf(mapAddress);
    if (slot >= amdtx::kSlots) {
        IOLockUnlock(d->lock);
        return kIOReturnBadArgument;
    }
    {
        const UInt64 h = d->slotHandle[slot];
        if (!(d->slotLive & (1u << slot)) || !h ||
            d->slotRecord[slot].handle!=h || d->slotRecord[slot].status!=1) {
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
        const UInt32 base = slot * amdtx::kPagesPerSlot;
        for (UInt32 i = 0; i < amdtx::kPagesPerSlot; i++) d->leaves[base + i] = 0;
        OSSynchronizeIO();
        if (!w.tClearPublish) w.tClearPublish = mach_absolute_time();
        for (UInt32 i = 0; i < amdtx::kPages; i++) w.clearPte[i] = d->leaves[i];
        static const char *const labels[amdtx::kSlots] = {
            "r18-std-unmap-slot0", "r18-std-unmap-slot1",
            "r18-std-unmap-slot2", "r18-std-unmap-slot3"
        };
        if (!r17Invalidate(d->mmio, d->command, w.retireCommand, labels[slot])) {
            // Keep handle, slot and owner: the translation may still be live.
            w.status |= 8; s.flags |= 2; d->accepting = false;
            result = kIOReturnIOError; goto out;
        }
        w.tRetireInv = w.retireCommand.tComplete;
        w.status |= 2;
        r25Archive(s,w);
        d->slotLive &= ~(1u << slot);
        d->slotHandle[slot] = 0;
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
