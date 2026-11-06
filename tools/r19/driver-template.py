"""Round19 generator templates (standard IOMapper/IODMACommand TX path).

Loaded by tools/build/patch-lucy-obs.py, not by any kext. Every body below is
compiled into the real driver by text substitution, so the host test that
exercises these exact functions (tools/r19/test-driver.py) is testing the
driver's own code rather than a model of it.

ROUND 18 KEEPS EVERY ROUND-17 NAME (R17TxState, r17TxMap, ...) ON PURPOSE: the
patch anchors in apply-lucy-obs2.py, the call sites in outputStart/txInterrupt/
stop and the round-17 witness layout are shared, so the two paths differ only in
*who performs the map*:

    mode = kModeDirect    -> the platform callback maps the packet's physical
                             segments (round-17 behaviour, unchanged);
    mode = kModeStandard  -> the driver builds an IOMemoryDescriptor for the
                             packet and an IODMACommand on the probe's own
                             IOMapper, and IOKit itself calls iovmMapMemory()
                             from IODMACommand::prepare(). Retirement calls
                             complete(), which is what makes IOKit call
                             iovmUnmapMemory().

Two fixes ride along with round 19:

  * The retirement timer no longer calls txInterrupt() outside the driver's own
    exclusion protocol. It takes __POLLING exactly like interruptOccurred() and
    pollInputPackets() do, skips the harvest when the bit is already held, and
    releases it before any retire/invalidation work, which is what the round-17
    note "same workloop, therefore serialised" wrongly assumed away.
  * The rollback after a PUBLISHED map is one function with two endings
    (r17TxStdRollback): unmap confirmed -> release and clear the handle;
    unmap failed -> keep packet/objects/handle and park in kPending. Round 18
    ignored complete()'s failure and left stdHandle set, so a fully rolled-back
    generation looked like a live owner forever.

And the round-19 feature: the accepted input layout is a WHOLE MBUF CHAIN,
described one IOAddressRange per mbuf (IOMemoryDescriptor::withAddressRanges
for chains, withAddress unchanged for a single mbuf). The command may answer
with several DMA runs; each becomes one TX descriptor. Capacity beyond
r18std::kMbufs / kSegments is refused BEFORE prepare(), and a published map
that the command cannot express is rolled back, never half-submitted.
"""
# Round19 deliberately keeps the round-17 identifiers: the call sites inside
# outputStart/txInterrupt/stop, the HOOKS below and the witness layout are
# shared, so the generator needs to be told the names instead of deriving them.
STATE_NAME = 'R17TxState'
CONFIG_NAME = 'r17TxConfigure'
MEMBERS = r'''
    struct R17TxState;
    R17TxState *r17Tx;
    IOReturn r17TxConfigure(r17tx::Configure *c);
    bool r17TxMap(mbuf_t m, IOPhysicalSegment *segments, UInt32 &count);
    bool r17TxMapDirect(R17TxState *p, mbuf_t m, IOPhysicalSegment *segments,
                        UInt32 &count);
    bool r17TxMapStd(R17TxState *p, mbuf_t m, IOPhysicalSegment *segments,
                     UInt32 &count);
    bool r17TxStdRollback(R17TxState *p, mbuf_t m, IOReturn unmap);
    void r17TxRetire(R17TxState *p, UInt64 handle);
    UInt64 r17TxStdMark();
    void r17TxPosted(mbuf_t m);
    void r17TxComplete(UInt32 slot);
    void r17TxPublish();
    void r17TxTimer(IOTimerEventSource *timer);
    void r17TxStop();
'''
METHODS = r'''
#pragma mark --- round 17 native TX mapping, per-packet recycling ---
struct RTL8125::R17TxState {
    volatile UInt32 state;
    volatile bool enabled;
    /* Set by the completion path when it arrives before the witness of this
     * generation was recorded. Read by the commit step and by the timer. */
    volatile UInt32 doneSeen;
    UInt32 token, bdf, lastSlot;
    UInt64 deadline;
    r17tx::Callback callback;
    void *context;
    IOService *owner;
    IOTimerEventSource *timer;
    r17tx::Request request;
    /* The single live DMA owner: the real mbuf whose physical segments are
     * mapped. NULL whenever no mapping is live. Exactly one is ever held. */
    mbuf_t packet;
    UInt32 mapped, completed, retired, dropped, replaced, rejected;
    UInt32 held, maxHeld;
    UInt32 lastSig;             /* throttles the raw publication */
    /* Diagnostics: did the driver's own completion walk reach this generation? */
    UInt32 completeCalls, completeHits, lastSeenSlot;
    /* ---- round 19: standard mapper objects of the LIVE generation ----
     * They are created before prepare() and released only after complete()
     * confirmed the unmap. On a refused detach/retire they stay here, because
     * they are what keeps the mapping (and the mbuf) owned. */
    bool stdMode;
    IOMapper *stdMapper;
    IOMemoryDescriptor *stdMD;
    IODMACommand *stdCmd;
    /* True when THIS generation's descriptor was wired explicitly (multi-range
     * MD): complete() must be paired with that prepare before release. */
    bool stdWired;
    UInt32 stdHandle;
    UInt32 stdAccepts, stdRejects, stdUnsupported, stdUnmaps, stdPinned;
    UInt32 stdLastSig;
    r18std::Witness stdW;
    r18std::Snapshot stdSnap;
    r17tx::Witness current;
    r17tx::Snapshot snapshot;
};

IOReturn RTL8125::r17TxConfigure(r17tx::Configure *c)
{
    if (!c || c->version != r17tx::kVersion || c->bytes != sizeof(*c) ||
        c->op < r17tx::kInstall || c->op > r17tx::kDetach)
        return kIOReturnBadArgument;
    /* The platform entry is serialized by commandGate. State CAS also excludes
     * the output thread (not on this workloop). Completion never takes a lock. */
    if (c->op == r17tx::kInstall && !r17Tx) {
        if (useAppleVTD || !workLoop || !pciDevice || !c->callback ||
            !c->context || !c->owner || !c->token ||
            c->deadline <= mach_absolute_time()) return kIOReturnBadArgument;
        UInt32 bdf = ((UInt32)pciDevice->getBusNumber() << 8) |
                     ((UInt32)pciDevice->getDeviceNumber() << 3) |
                     pciDevice->getFunctionNumber();
        if (bdf != c->bdf) return kIOReturnBadArgument;
        /* Round19: the standard mode is only valid with a mapper object and a
         * callback (Install/Query/Detach still travel through the platform
         * function). Anything else is refused rather than downgraded. */
        if (c->mode != r17tx::kModeDirect && c->mode != r17tx::kModeStandard)
            return kIOReturnBadArgument;
        if (c->mode == r17tx::kModeStandard && !c->mapper)
            return kIOReturnBadArgument;
        R17TxState *p = (R17TxState *)IOMalloc(sizeof(R17TxState));
        if (!p) return kIOReturnNoMemory;
        bzero(p, sizeof(*p));
        p->stdMode = (c->mode == r17tx::kModeStandard);
        p->stdMapper = (IOMapper *)c->mapper;
        p->timer = IOTimerEventSource::timerEventSource(this,
            OSMemberFunctionCast(IOTimerEventSource::Action, this,
                                 &RTL8125::r17TxTimer));
        if (!p->timer || workLoop->addEventSource(p->timer) != kIOReturnSuccess) {
            if (p->timer) p->timer->release();
            IOFree(p, sizeof(*p));
            return kIOReturnNoResources;
        }
        /* No staging buffer and no per-generation DMA allocation here: the
         * descriptors carry the packet's own physical segments. The state
         * itself is permanent, so an output-thread pointer stays valid and no
         * second Install is possible after Detach. */
        p->token = c->token; p->bdf = bdf; p->deadline = c->deadline;
        p->context = c->context; p->callback = c->callback; p->owner = c->owner;
        p->owner->retain();
        p->enabled = true;
        __atomic_store_n(&r17Tx, p, __ATOMIC_RELEASE);
        p->timer->setTimeoutMS(10);
    } else if (c->op == r17tx::kInstall) return kIOReturnBusy;
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    if (!p) return kIOReturnNotReady;
    if (c->op == r17tx::kDisarm || c->op == r17tx::kDetach)
        __atomic_store_n(&p->enabled, false, __ATOMIC_RELEASE);
    UInt32 state = __atomic_load_n(&p->state, __ATOMIC_ACQUIRE);
    c->state = state;
    /* The handle is only safe to copy while no generation is being handed
     * over; Query is diagnostic, not a barrier. Raw witnesses carry handles. */
    c->handle = 0;
    /* Round19: in standard mode the mapping is created by IOKit inside
     * prepare(), so the driver never receives the probe's generation handle as
     * a return value. Query reads it back; with a single in-flight generation
     * and this call made immediately after a successful prepare(), the answer
     * can only be this generation's. A nonzero answer is also what tells a
     * failed prepare() "something was published, keep the mbuf". */
    if (c->op == r17tx::kQuery && p->stdMode)
        c->handle = (UInt64)__atomic_load_n(&p->stdHandle, __ATOMIC_ACQUIRE);
    c->mapped = __atomic_load_n(&p->mapped, __ATOMIC_RELAXED);
    c->completed = __atomic_load_n(&p->completed, __ATOMIC_RELAXED);
    c->retired = __atomic_load_n(&p->retired, __ATOMIC_RELAXED);
    c->dropped = __atomic_load_n(&p->dropped, __ATOMIC_RELAXED);
    c->held = __atomic_load_n(&p->held, __ATOMIC_RELAXED);
    c->maxHeld = __atomic_load_n(&p->maxHeld, __ATOMIC_RELAXED);
    c->evidenceUsed = c->retired;
    c->rejected = __atomic_load_n(&p->rejected, __ATOMIC_RELAXED);
    if (c->op == r17tx::kDisarm || c->op == r17tx::kDetach) {
        UInt32 expected = r17tx::kIdle;
        if (!__atomic_compare_exchange_n(&p->state, &expected,
            (UInt32)r17tx::kControl, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return kIOReturnBusy;
        if (c->op == r17tx::kDetach) {
            /* Only Idle is eligible, and Idle here is a per-packet fact: every
             * successful Retire already freed its own mbuf, so a live owner at
             * this point means a generation is genuinely outstanding. Never
             * free it to make Detach look clean. */
            if (p->packet || __atomic_load_n(&p->held, __ATOMIC_ACQUIRE) ||
                p->request.handle || p->stdHandle || p->stdCmd || p->stdMD) {
                __atomic_store_n(&p->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
                return kIOReturnBusy;
            }
            p->callback = NULL; p->context = NULL;
            if (p->owner) { p->owner->release(); p->owner = NULL; }
        }
        __atomic_store_n(&p->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
        c->state = r17tx::kIdle;
    }
    r17TxPublish();
    return kIOReturnSuccess;
}

/* true: the caller may submit m. false: consumed (freed or pinned), MUST skip.
 * Called only after the frame's length is known and before ANY OWN. */
bool RTL8125::r17TxMap(mbuf_t m, IOPhysicalSegment *segments, UInt32 &count)
{
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    if (!p || !segments || !count) return true;
    UInt32 token = 0, req = 0, flow = 0;
    UInt32 flags = obsParseBiz(m, (UInt32)mbuf_pkthdr_len(m), true,
                               &token, &req, &flow);
    if (!(flags & kObsPktParsed) || token != p->token ||
        req < 1 || req > r17tx::kMaxRequests)
        return true;
    UInt32 expected = r17tx::kIdle;
    if (!__atomic_compare_exchange_n(&p->state, &expected,
        (UInt32)r17tx::kMapping, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        /* A previous generation is still live: drop this one, never queue it
         * behind a mapping whose backing we do not own. */
        __atomic_fetch_add(&p->dropped, 1u, __ATOMIC_RELAXED);
        freePacket(m); return false;
    }
    const bool base = !useAppleVTD && __atomic_load_n(&p->enabled, __ATOMIC_ACQUIRE)
        && p->callback && mach_absolute_time() < p->deadline
        && p->packet == NULL && __atomic_load_n(&p->held, __ATOMIC_ACQUIRE) == 0
        && __atomic_load_n(&p->retired, __ATOMIC_RELAXED) < r17tx::kMaxRequests;
    if (!base) {
        __atomic_fetch_add(&p->rejected, 1u, __ATOMIC_RELAXED);
        freePacket(m);
        __atomic_store_n(&p->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
        return false;
    }
    bzero(&p->current, sizeof(p->current));
    p->current.cumulative = txTailPtr0;
    p->current.firstSlot = txNextDescIndex;
    bzero(&p->request, sizeof(p->request));
    p->request.version = r17tx::kVersion; p->request.bytes = sizeof(p->request);
    p->request.bdf = p->bdf; p->request.token = token; p->request.reqId = req;
    __atomic_store_n(&p->doneSeen, 0u, __ATOMIC_RELAXED);
    /* Exactly one mapper performs this map, chosen at Install time. */
    const bool ok = p->stdMode ? r17TxMapStd(p, m, segments, count)
                               : r17TxMapDirect(p, m, segments, count);
    if (!ok) return false;
    p->lastSlot = (txNextDescIndex + count - 1) & kTxDescMask;
    __atomic_fetch_add(&p->mapped, 1u, __ATOMIC_RELAXED);
    /* Published BEFORE the first OWN: the completion path may stamp this
     * generation as soon as the doorbell is rung, but it must not start the
     * retirement of a witness that has not been recorded yet (kPosting). */
    __atomic_store_n(&p->state, (UInt32)r17tx::kPosting, __ATOMIC_RELEASE);
    return true;
}

/* Round 17 path: the platform callback maps the packet's own physical segments.
 * Nothing is copied and numSegs is NOT flattened here. */
bool RTL8125::r17TxMapDirect(R17TxState *p, mbuf_t m,
                             IOPhysicalSegment *segments, UInt32 &count)
{
    bool valid = count <= r17tx::kMaxSegments;
    UInt64 total = 0, pages = 0;
    for (UInt32 i = 0; valid && i < count; i++) {
        UInt64 pa = segments[i].location, len = segments[i].length;
        valid = pa && len && len <= 0xffff && pa + len > pa;
        if (!valid) break;
        total += len; pages += ((pa & 4095) + len + 4095) / 4096;
        valid = total <= r17tx::kMaxBytes && pages <= r17tx::kMaxPages;
    }
    /* The mapped bytes must BE the whole frame: a partial mapping would let the
     * descriptor read unmapped memory past the last segment. */
    valid = valid && total == (UInt64)mbuf_pkthdr_len(m);
    if (!valid) {
        __atomic_fetch_add(&p->rejected, 1u, __ATOMIC_RELAXED);
        freePacket(m);
        __atomic_store_n(&p->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
        return false;
    }
    r17tx::Request &r = p->request;
    r.count = count;
    for (UInt32 i = 0; i < count; i++) {
        r.physical[i].address = segments[i].location;
        r.physical[i].length = segments[i].length;
    }
    IOReturn result = p->callback(p->context, r17tx::kMap, &r);
    valid = result == kIOReturnSuccess && r.handle && r.count == count && r.tMap;
    /* Same count/order/length and the SAME in-page offset: the packet's bytes
     * must land in the page at the position the descriptor expects. The IOVA
     * start address itself is free to differ from the physical one. */
    for (UInt32 i = 0; valid && i < count; i++) {
        UInt64 addr = r.iova[i].address, len = r.iova[i].length;
        valid = addr && addr != segments[i].location &&
            len == segments[i].length && addr + len > addr &&
            (addr & 4095) == (segments[i].location & 4095);
    }
    if (!valid) {
        __atomic_fetch_add(&p->rejected, 1u, __ATOMIC_RELAXED);
        if (r.handle) {
            /* The backend published a mapping and owes the invalidation. Keep
             * the mbuf with it; no descriptor has been given an OWN bit. */
            p->packet = m;
            __atomic_store_n(&p->held, 1u, __ATOMIC_RELEASE);
            __atomic_store_n(&p->maxHeld, 1u, __ATOMIC_RELEASE);
            __atomic_store_n(&p->state, (UInt32)r17tx::kPending, __ATOMIC_RELEASE);
        } else {
            freePacket(m);
            __atomic_store_n(&p->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
        }
        return false;
    }
    for (UInt32 i = 0; i < count; i++) segments[i].location = r.iova[i].address;
    p->packet = m;
    __atomic_store_n(&p->held, 1u, __ATOMIC_RELEASE);
    __atomic_store_n(&p->maxHeld, 1u, __ATOMIC_RELEASE);
    return true; /* the dispatcher publishes kPosting, not this helper */
}

/* Round 18 path: the packet is described by an IOMemoryDescriptor and mapped
 * through an IODMACommand built on the probe's own IOMapper. IOKit -- not this
 * function -- calls iovmMapMemory(); all this code does is describe, prepare,
 * read back what the framework decided, and decide whether that is usable.
 *
 * Bounded input layout: ONE mbuf holding the whole frame whose bytes form ONE
 * contiguous physical run (what every 74/162-byte frame in this experiment is).
 * A multi-mbuf frame is refused here, before prepare(), so no descriptor is
 * ever offered to the hardware for a packet this round cannot map. The mapper
 * independently refuses a fragmented page list, which is the same rule checked
 * from the other side. */
bool RTL8125::r17TxMapStd(R17TxState *p, mbuf_t m,
                          IOPhysicalSegment *segments, UInt32 &count)
{
    const UInt32 len = (UInt32)mbuf_pkthdr_len(m);
    r17tx::Request &r = p->request;
    bzero(&p->stdW, sizeof(p->stdW));
    p->stdW.version = r18std::kVersion;
    p->stdW.bytes = sizeof(p->stdW);
    p->stdW.req = r.reqId;
    p->stdW.token = r.token;
    p->stdW.tBegin = mach_absolute_time();
    __atomic_store_n(&p->stdHandle, 0u, __ATOMIC_RELEASE);
    /* Describe the REAL chain: one IOAddressRange per mbuf, in logical order,
     * each carrying its own length. Nothing is copied and nothing is
     * linearised -- which is the point of asking the standard command to do the
     * mapping at all. A single-mbuf frame keeps the round-18 call
     * (withAddress), so the already-proven path is byte-for-byte unchanged. */
    IOAddressRange ranges[r18std::kMbufs];
    UInt32 nrange = 0, sum = 0;
    bool fits = true;
    mbuf_t c = m;
    for (; c; c = mbuf_next(c)) {
        if (nrange == r18std::kMbufs) { fits = false; break; }
        const UInt32 l = (UInt32)mbuf_len(c);
        if (!l) { fits = false; break; }
        ranges[nrange].address = (IOVirtualAddress)(uintptr_t)mbuf_data(c);
        ranges[nrange].length = (IOByteCount)l;
        sum += l; nrange++;
    }
    p->stdW.mbufSegments = nrange;
    const bool layout = fits && c == NULL && nrange && len && len <= r17tx::kMaxBytes
        && sum == len;
    if (!layout) {
        p->stdW.flags |= r18std::kRefused;
        __atomic_fetch_add(&p->stdUnsupported, 1u, __ATOMIC_RELAXED);
        __atomic_fetch_add(&p->rejected, 1u, __ATOMIC_RELAXED);
        freePacket(m);
        __atomic_store_n(&p->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
        return false;
    }
    IOMemoryDescriptor *md = (nrange == 1)
        ? IOMemoryDescriptor::withAddress((void *)(uintptr_t)ranges[0].address,
                                          (IOByteCount)ranges[0].length,
                                          kIODirectionOut)
        : IOMemoryDescriptor::withAddressRanges(ranges, nrange, kIODirectionOut,
                                                kernel_task);
    /* kIOMemoryAutoPrepare (which withAddress() implies) is XNU_KERNEL_PRIVATE,
     * so a multi-range descriptor must be wired EXPLICITLY -- the withAddressRanges
     * documentation says exactly that for kernel_task memory. Without it the
     * mapper's getPhysicalSegment() panics ("IOGMD: not wired for the
     * IODMACommand"); complete() below is paired with this prepare(). */
    bool wired = false;
    if (md && nrange != 1) {
        const IOReturn wr = md->prepare(kIODirectionOut);
        if (wr != kIOReturnSuccess) {
            md->release();
            md = nullptr;
        }
        wired = (md != nullptr);
    }
    p->stdWired = wired;
    if (!md) {
        p->stdW.flags |= r18std::kRefused;
        __atomic_fetch_add(&p->stdRejects, 1u, __ATOMIC_RELAXED);
        __atomic_fetch_add(&p->rejected, 1u, __ATOMIC_RELAXED);
        freePacket(m);
        __atomic_store_n(&p->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
        return false;
    }
    IODMACommand *cmd = IODMACommand::withSpecification(
        kIODMACommandOutputHost64, 64, 0, IODMACommand::kMapped, 0, 1,
        p->stdMapper, NULL);
    if (!cmd) {
        md->release();
        p->stdW.flags |= r18std::kRefused;
        __atomic_fetch_add(&p->stdRejects, 1u, __ATOMIC_RELAXED);
        __atomic_fetch_add(&p->rejected, 1u, __ATOMIC_RELAXED);
        freePacket(m);
        __atomic_store_n(&p->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
        return false;
    }
    p->stdMD = md; p->stdCmd = cmd;
    p->stdW.memory = (UInt64)(uintptr_t)md;
    p->stdW.command = (UInt64)(uintptr_t)cmd;
    p->stdW.descriptorLength = len;
    /* The call that makes IOKit perform the map. autoPrepare is used because
     * the packet is already wired kernel memory owned by the stack; the mapper
     * itself never sleeps, so this path stays non-blocking. */
    const UInt64 mark0 = r17TxStdMark();
    IOReturn kr = cmd->setMemoryDescriptor(md, true);
    const UInt64 mark1 = r17TxStdMark();
    p->stdW.prepareResult = (UInt32)kr;
    p->stdW.tPrepared = mach_absolute_time();
    /* Did this prepare() publish a mapping? Only a growth of the probe's record
     * count proves it; the handle value alone would still be the previous
     * generation's. */
    p->stdHandle = ((mark1 >> 32) != (mark0 >> 32))
        ? (UInt32)(mark1 & 0xFFFFFFFFULL) : 0;
    p->stdW.handle = p->stdHandle; /* stamped into the witness, not inferred later */
    if (kr != kIOReturnSuccess) {
        if (p->stdHandle == 0) {
            /* Nothing was published: no translation exists, so nothing is kept. */
            cmd->clearMemoryDescriptor();
            p->stdCmd = nullptr; p->stdMD = nullptr;
            cmd->release(); md->release();
            p->stdW.flags |= r18std::kRefused;
            __atomic_fetch_add(&p->stdRejects, 1u, __ATOMIC_RELAXED);
            __atomic_fetch_add(&p->rejected, 1u, __ATOMIC_RELAXED);
            freePacket(m);
            __atomic_store_n(&p->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
            return false;
        }
        /* The mapper published a mapping and could not confirm its
         * invalidation. Keep the standard objects and the mbuf: this is a
         * pinned generation, never a recycled one. */
        p->stdW.flags |= r18std::kPinned;
        __atomic_fetch_add(&p->stdPinned, 1u, __ATOMIC_RELAXED);
        p->packet = m;
        __atomic_store_n(&p->held, 1u, __ATOMIC_RELEASE);
        __atomic_store_n(&p->maxHeld, 1u, __ATOMIC_RELEASE);
        __atomic_store_n(&p->state, (UInt32)r17tx::kPending, __ATOMIC_RELEASE);
        return false;
    }
    IODMACommand::Segment64 segs[r18std::kSegments] = {};
    UInt64 segOffset = 0;
    UInt32 segCount = r18std::kSegments;
    kr = cmd->gen64IOVMSegments(&segOffset, segs, &segCount);
    p->stdW.segmentResult = (UInt32)kr;
    p->stdW.tSegmented = mach_absolute_time();
    p->stdW.segCount = segCount;
    for (UInt32 i = 0; i < segCount && i < r18std::kSegments; i++) {
        p->stdW.segments[i].address = segs[i].fIOVMAddr;
        p->stdW.segments[i].length = segs[i].fLength;
    }
    /* Accept what the framework ACTUALLY produced: up to kSegments runs, no
     * zero entries, lengths summing to the frame, and every run non-identity.
     * The identity cross-check walks the descriptor at each run's own logical
     * start, so a fragment that the command mapped onto its physical address
     * is refused even when other fragments are translated. */
    bool ok = kr == kIOReturnSuccess && segCount >= 1 && segCount <= r18std::kSegments;
    UInt64 covered = 0;
    for (UInt32 i = 0; ok && i < segCount; i++) {
        covered += segs[i].fLength;
        IOPhysicalLength plen = 0;
        const IOPhysicalAddress pa = md->getPhysicalSegment(
            covered - segs[i].fLength, &plen, kIOMemoryMapperNone);
        ok = segs[i].fIOVMAddr && segs[i].fLength && covered <= (UInt64)len &&
             pa && segs[i].fIOVMAddr != (UInt64)pa && plen;
    }
    ok = ok && covered == (UInt64)len;
    if (!ok) {
        /* The mapping IS published, so it has to be taken down through the
         * same standard API before anything is released. The result decides
         * the outcome: one rollback path, two very different endings. */
        IOPhysicalLength plen0 = 0;
        const IOPhysicalAddress pa0 = md->getPhysicalSegment(
            0, &plen0, kIOMemoryMapperNone);
        if (kr == kIOReturnSuccess && pa0 && segs[0].fIOVMAddr == (UInt64)pa0)
            p->stdW.flags |= r18std::kIdentity;
        return r17TxStdRollback(p, m, cmd->complete(true, false));
    }
    p->stdW.mapAddress = segs[0].fIOVMAddr;
    /* Logical bytes covered by the mapping. The length IOKit hands back to
     * iovmUnmapMemory() is the mapper's own contract (strictly larger than
     * this whenever the layout is fragmented) and is recorded by the mapper,
     * not re-derived here. */
    p->stdW.mapLength = len;
    p->stdW.flags |= r18std::kMapped;
    r.count = segCount;
    r.tMap = p->stdW.tPrepared;
    for (UInt32 i = 0; i < segCount; i++) {
        r.iova[i].address = segs[i].fIOVMAddr;
        r.iova[i].length = segs[i].fLength;
        segments[i].location = segs[i].fIOVMAddr;
        segments[i].length = segs[i].fLength;
    }
    count = segCount;
    p->packet = m;
    __atomic_store_n(&p->held, 1u, __ATOMIC_RELEASE);
    __atomic_store_n(&p->maxHeld, 1u, __ATOMIC_RELEASE);
    __atomic_fetch_add(&p->stdAccepts, 1u, __ATOMIC_RELAXED);
    return true;
}

/* The single rollback exit for "the standard map was published, then found
 * unusable". Only the unmap result decides what happens next:
 *
 *   confirmed -> the translation is gone. Release this generation's descriptor,
 *     command and packet, clear the generation handle AND the owner state, so
 *     the next request (and Detach) proceeds. Round 18 got this wrong twice:
 *     it ignored complete()'s failure and left stdHandle set, which made a
 *     fully rolled-back generation look like a live owner forever.
 *
 *   not confirmed -> the translation may still be live. Keep packet, descriptor,
 *     command and handle, and park in kPending. Never retried through
 *     complete(): the archived XNU IOMemoryDescriptor::dmaUnmap clears its own
 *     mapping bookkeeping even when the mapper fails, so a second complete()
 *     would report success without unmapping anything. */
bool RTL8125::r17TxStdRollback(R17TxState *p, mbuf_t m, IOReturn unmap)
{
    p->stdW.completeResult = (UInt32)unmap;
    p->stdW.tCompleteBegin = p->stdW.tCompleteBegin ? p->stdW.tCompleteBegin
                                                    : mach_absolute_time();
    p->stdW.tCompleteEnd = mach_absolute_time();
    if (p->stdCmd) p->stdCmd->clearMemoryDescriptor();
    if (unmap == kIOReturnSuccess) {
        if (p->stdCmd) { p->stdCmd->release(); p->stdCmd = nullptr; }
        if (p->stdMD && p->stdWired) p->stdMD->complete(kIODirectionOut);
        if (p->stdMD) { p->stdMD->release(); p->stdMD = nullptr; }
        p->stdWired = false;
        p->stdW.flags |= r18std::kRefused;
        p->stdW.tFree = mach_absolute_time();
        __atomic_store_n(&p->stdHandle, 0u, __ATOMIC_RELEASE);
        __atomic_fetch_add(&p->stdUnsupported, 1u, __ATOMIC_RELAXED);
        __atomic_fetch_add(&p->rejected, 1u, __ATOMIC_RELAXED);
        freePacket(m);
        __atomic_store_n(&p->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
        return false;
    }
    p->stdW.flags |= r18std::kPinned;
    __atomic_fetch_add(&p->stdPinned, 1u, __ATOMIC_RELAXED);
    p->packet = m;
    __atomic_store_n(&p->held, 1u, __ATOMIC_RELEASE);
    __atomic_store_n(&p->maxHeld, 1u, __ATOMIC_RELEASE);
    __atomic_store_n(&p->state, (UInt32)r17tx::kPending, __ATOMIC_RELEASE);
    return false;
}

/* Commit step: the descriptor ring now carries this generation, so record it.
 * Runs on the output thread, immediately after the first DescOwn is set and
 * before the doorbell. */
void RTL8125::r17TxPosted(mbuf_t m)
{
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    if (!p || __atomic_load_n(&p->state, __ATOMIC_ACQUIRE) != r17tx::kPosting ||
        p->packet != m) return;
    p->current.tOwn = mach_absolute_time();
    p->current.lastSlot = p->lastSlot;
    if (p->stdMode) p->stdW.tCommit = p->current.tOwn;
    for (UInt32 i = 0; i < p->request.count; i++) {
        RtlTxDesc *d = &txDescArray[(p->current.firstSlot + i) & kTxDescMask];
        r17tx::Descriptor &out = p->current.descriptors[i];
        out.address = OSSwapLittleToHostInt64(d->addr);
        out.length = p->request.iova[i].length;
        out.opts1 = OSSwapLittleToHostInt32(d->opts1);
        out.opts2 = OSSwapLittleToHostInt32(d->opts2);
    }
    /* Submission/completion handoff. If the completion was already recorded
     * (doneSeen), this commit publishes kPending itself, so a very fast
     * completion cannot leave a generation that nobody will retire; otherwise
     * it publishes kSubmitted and the completion path (or the timer) moves it
     * to kPending afterwards. Either way the retire path only ever observes a
     * fully recorded witness. */
    if (__atomic_load_n(&p->doneSeen, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&p->state, (UInt32)r17tx::kPending, __ATOMIC_RELEASE);
        __atomic_fetch_add(&p->completed, 1u, __ATOMIC_RELAXED);
    } else {
        __atomic_store_n(&p->state, (UInt32)r17tx::kSubmitted, __ATOMIC_RELEASE);
    }
}

/* Completion: interrupt or polling context. Records the hardware completion and
 * moves the state; never invalidates, frees, or waits. */
void RTL8125::r17TxComplete(UInt32 slot)
{
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    if (!p) return;
    __atomic_fetch_add(&p->completeCalls, 1u, __ATOMIC_RELAXED);
    p->lastSeenSlot = slot;
    if (slot != p->lastSlot) return;
    UInt32 state = __atomic_load_n(&p->state, __ATOMIC_ACQUIRE);
    if (state != r17tx::kPosting && state != r17tx::kSubmitted) return;
    if (p->request.tDone) return;
    /* Real close-pointer completion only. */
    p->request.tDone = mach_absolute_time();
    p->current.doneClose = txClosePtr0;
    p->current.closeMask = linuxData.MaxTxDescPtrMask;
    __atomic_fetch_add(&p->completeHits, 1u, __ATOMIC_RELAXED);
    __atomic_store_n(&p->doneSeen, 1u, __ATOMIC_RELEASE);
    UInt32 expected = r17tx::kSubmitted;
    if (__atomic_compare_exchange_n(&p->state, &expected,
        (UInt32)r17tx::kPending, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        __atomic_fetch_add(&p->completed, 1u, __ATOMIC_RELAXED);
    /* If the state was still kPosting the CAS fails on purpose: the commit
     * step owns that transition and will see doneSeen. */
}

void RTL8125::r17TxPublish()
{
    R17TxState *p = r17Tx;
    if (!p) return;
    UInt32 retired = __atomic_load_n(&p->retired, __ATOMIC_RELAXED);
    UInt32 state = __atomic_load_n(&p->state, __ATOMIC_ACQUIRE);
    UInt32 dropped = __atomic_load_n(&p->dropped, __ATOMIC_RELAXED);
    UInt32 rejected = __atomic_load_n(&p->rejected, __ATOMIC_RELAXED);
    /* The snapshot is ~17 KB. Re-publishing it on every 10 ms tick for an
     * unchanged run would allocate continuously in the kernel for no evidence
     * gain, so publish only when something a reader can observe changed. The
     * Disarm/Detach entry point always ends with a publish, which is the one
     * the probe archives. */
    UInt32 sig = retired * 37u + state * 7u + dropped * 3u + rejected;
    if (p->lastSig && sig == p->lastSig) return;
    p->lastSig = sig;
    setProperty("rtl812x-txmap-mode", p->stdMode
        ? "native-mbuf-standard-iomapper-v1"
        : "native-mbuf-explicit-iova-v1");
    if (p->stdMode) {
        r18std::Snapshot &ss = p->stdSnap;
        ss.magic = r18std::kMagic; ss.version = r18std::kVersion;
        ss.bytes = sizeof(ss); ss.bdf = p->bdf; ss.token = p->token;
        ss.mode = 1;
        ss.accepts = __atomic_load_n(&p->stdAccepts, __ATOMIC_RELAXED);
        ss.rejects = __atomic_load_n(&p->stdRejects, __ATOMIC_RELAXED);
        ss.unsupported = __atomic_load_n(&p->stdUnsupported, __ATOMIC_RELAXED);
        ss.unmaps = __atomic_load_n(&p->stdUnmaps, __ATOMIC_RELAXED);
        ss.pinned = __atomic_load_n(&p->stdPinned, __ATOMIC_RELAXED);
        ss.maxHeld = __atomic_load_n(&p->maxHeld, __ATOMIC_RELAXED);
        ss.count = (ss.accepts > r18std::kMax) ? r18std::kMax : ss.accepts;
        ss.tPublished = mach_absolute_time();
        OSData *sd = OSData::withBytes(&ss, sizeof(ss));
        if (sd) { setProperty("rtl812x-txmap-std-raw", sd); sd->release(); }
    }
    setProperty("rtl812x-txmap-held", (UInt64)__atomic_load_n(&p->held, __ATOMIC_ACQUIRE), 32);
    setProperty("rtl812x-txmap-max-held", (UInt64)__atomic_load_n(&p->maxHeld, __ATOMIC_RELAXED), 32);
    setProperty("rtl812x-txmap-rejected", (UInt64)rejected, 32);
    p->snapshot.magic = 0x37315854; p->snapshot.version = r17tx::kVersion;
    p->snapshot.bytes = sizeof(p->snapshot); p->snapshot.bdf = p->bdf;
    p->snapshot.token = p->token;
    p->snapshot.dropped = dropped;
    p->snapshot.state = state;
    p->snapshot.retired = retired;
    p->snapshot.rejected = rejected;
    p->snapshot.maxHeld = __atomic_load_n(&p->maxHeld, __ATOMIC_RELAXED);
    p->snapshot.count = retired;
    /* Ring accounting: this is what tells "the device never completed it" from
     * "the driver's completion walk could not reach the slot". */
    p->snapshot.txNext = txNextDescIndex;
    p->snapshot.txDirty = txDirtyDescIndex;
    p->snapshot.txClose = txClosePtr0;
    p->snapshot.txFree = (UInt32)txNumFreeDesc;
    p->snapshot.txDescDone = txDescDoneCount;
    p->snapshot.completeCalls = __atomic_load_n(&p->completeCalls, __ATOMIC_RELAXED);
    p->snapshot.completeHits = __atomic_load_n(&p->completeHits, __ATOMIC_RELAXED);
    p->snapshot.lastSeenSlot = p->lastSeenSlot;
    p->snapshot.tPublished = mach_absolute_time();
    OSData *data = OSData::withBytes(&p->snapshot, sizeof(p->snapshot));
    if (data) { setProperty("rtl812x-txmap-raw", data); data->release(); }
}

/* Round19: read the probe's map marker, [63:32] = records issued, [31:0] =
 * generation handle. Comparing the record count across prepare() is what tells
 * "the mapper never published anything" from "it published and then failed":
 * a bare handle read is stale as soon as one earlier packet has mapped. */
UInt64 RTL8125::r17TxStdMark()
{
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    if (!p || !p->owner) return 0;
    OSObject *o = p->owner->copyProperty("m2-3c-map-mark");
    OSNumber *n = OSDynamicCast(OSNumber, o);
    UInt64 v = n ? n->unsigned64BitValue() : 0;
    if (o) o->release();
    return v;
}

/* Retirement: workloop timer context only. Order is fixed and observable:
 * confirmed completion -> retire (unmap + invalidate + CompletionWait)
 * -> release the standard objects -> free THIS packet's mbuf -> IOVA/handle
 * reusable. The caller holds NO driver exclusion when this runs. */
void RTL8125::r17TxRetire(R17TxState *p, UInt64 handle)
{
    IOReturn result;
    if (p->stdMode) {
        /* complete() is what makes IOKit call iovmUnmapMemory(); the driver
         * never invokes the mapper itself. Note the contract cost: complete()
         * drops the command's own bookkeeping even when the unmap fails, so a
         * failed unmap cannot be retried -- it is reported as pinned. */
        p->stdW.tCompleteBegin = mach_absolute_time();
        result = p->stdCmd ? p->stdCmd->complete(true, false) : kIOReturnNotReady;
        p->stdW.tCompleteEnd = mach_absolute_time();
        p->stdW.completeResult = (UInt32)result;
    } else {
        result = p->callback(p->context, r17tx::kRetire, &p->request);
    }
    if (result == kIOReturnSuccess) {
        mbuf_t done = p->packet;
        p->current.request = p->request;
        p->current.request.handle = handle;
        p->current.retired = 1;
        /* The device's own final words for this generation, read before the
         * slot can be reused (this runs in the retire tick). */
        for (UInt32 i = 0; i < p->request.count; i++)
            p->current.doneOpts1[i] = OSSwapLittleToHostInt32(
                txDescArray[(p->current.firstSlot + i) & kTxDescMask].opts1);
        p->request.handle = 0;
        p->packet = NULL;
        __atomic_store_n(&p->held, 0u, __ATOMIC_RELEASE);
        if (p->stdMode) {
            if (p->stdCmd) { p->stdCmd->clearMemoryDescriptor();
                             p->stdCmd->release(); p->stdCmd = nullptr; }
            if (p->stdMD && p->stdWired) p->stdMD->complete(kIODirectionOut);
            if (p->stdMD) { p->stdMD->release(); p->stdMD = nullptr; }
            p->stdWired = false;
        }
        /* Retire succeeded, so the mapping is gone and the IOVA is reusable.
         * The mbuf is released per packet here -- NOT held to Detach -- and
         * tFree is stamped after EVERY release of this generation. The witness
         * is copied into the snapshot only AFTER tFree, otherwise it would
         * record a zero free time and no order could be checked. */
        if (done) freePacket(done);
        p->current.tFree = mach_absolute_time();
        if (p->stdMode) {
            const UInt32 at = p->stdHandle;   /* generation index, before the reset */
            p->stdW.tFree = p->current.tFree;
            if (p->stdW.flags & r18std::kMapped) {
                p->stdW.flags |= r18std::kUnmapped;
                if (at && at <= r18std::kMax) p->stdSnap.witnesses[at - 1] = p->stdW;
                __atomic_fetch_add(&p->stdUnmaps, 1u, __ATOMIC_RELAXED);
            }
            __atomic_store_n(&p->stdHandle, 0u, __ATOMIC_RELEASE);
        }
        UInt32 n = __atomic_load_n(&p->retired, __ATOMIC_RELAXED);
        if (n < r17tx::kMaxRequests) p->snapshot.witnesses[n] = p->current;
        n++; __atomic_store_n(&p->retired, n, __ATOMIC_RELAXED);
        p->snapshot.count = n;
        __atomic_store_n(&p->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
    } else {
        /* The unmap/invalidation is not confirmed: keep handle, standard
         * objects and mbuf. A failed retire is never reported as recycled. */
        p->request.handle = handle;
        if (p->stdMode) {
            p->stdW.flags |= r18std::kPinned;
            __atomic_fetch_add(&p->stdPinned, 1u, __ATOMIC_RELAXED);
        }
        __atomic_store_n(&p->state, (UInt32)r17tx::kPending, __ATOMIC_RELEASE);
    }
}

void RTL8125::r17TxTimer(IOTimerEventSource *timer)
{
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    if (!p) return;
    UInt32 state = __atomic_load_n(&p->state, __ATOMIC_ACQUIRE);
    /* The driver reaps TX descriptors only from txInterrupt(), which this
     * driver calls from interruptOccurred() and pollInputPackets(). A serial
     * stationary experiment generates no inbound traffic, so without an active
     * harvest the completion of a mapped frame can sit unreaped indefinitely.
     *
     * ROUND 18 CORRECTION: "the timer is on the same workloop, therefore it is
     * serialised" was wrong. txInterrupt() itself takes no lock, and the two
     * real callers both enter it only while holding __POLLING -- the poll path
     * does not promise to run on this workloop. So this harvest uses the
     * driver's own exclusion: take __POLLING non-blocking, skip the tick when
     * somebody else holds it, and release it before any retire or IOMMU
     * invalidation wait. */
    if ((state == r17tx::kPosting || state == r17tx::kSubmitted) && p->packet &&
        !__atomic_load_n(&p->doneSeen, __ATOMIC_ACQUIRE)) {
        if (!test_and_set_bit(__POLLING, &stateFlags)) {
            txInterrupt();
            clear_bit(__POLLING, &stateFlags);
        }
        /* else: a poller or the interrupt handler owns the ring walk; this
         * tick deliberately does not enter it. */
    }
    state = __atomic_load_n(&p->state, __ATOMIC_ACQUIRE);
    if (state == r17tx::kSubmitted &&
        __atomic_load_n(&p->doneSeen, __ATOMIC_ACQUIRE)) {
        UInt32 expected = r17tx::kSubmitted;
        if (__atomic_compare_exchange_n(&p->state, &expected,
            (UInt32)r17tx::kPending, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            __atomic_fetch_add(&p->completed, 1u, __ATOMIC_RELAXED);
    }
    UInt32 expected = r17tx::kPending;
    if (__atomic_compare_exchange_n(&p->state, &expected,
        (UInt32)r17tx::kRetiring, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        r17TxRetire(p, p->request.handle);
    r17TxPublish();
    timer->setTimeoutMS(10);
}

void RTL8125::r17TxStop()
{
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    if (!p) return;
    __atomic_store_n(&p->enabled, false, __ATOMIC_RELEASE);
    p->timer->cancelTimeout();
    workLoop->removeEventSource(p->timer); p->timer->release(); p->timer = NULL;
    /* Stop is not close-pointer completion. Never release an outstanding DMA
     * owner or the callback owner here; the probe must Disarm/drain/Detach.
     * The state itself stays allocated so an output-thread pointer cannot
     * dangle. */
    IOLog("r17 TX stop: state=%u handle=%llu held=%u (nonidle retained fail-closed)\n",
          __atomic_load_n(&p->state, __ATOMIC_ACQUIRE),
          (unsigned long long)p->request.handle,
          __atomic_load_n(&p->held, __ATOMIC_RELAXED));
}
'''

HOOKS = (
    'if (!r17TxMap(m, txSegments, numSegs)) continue;',
    'r17TxComplete(txDirtyDescIndex);', 'r17TxPosted(m);',
    'r17TxStop();', 'r17Tx = NULL;',
    'functionName->isEqualTo(r17tx::kFunctionName)',
    'p->packet == m) ? NULL : m;')


def patch_cpp(text):
    def once(old, new):
        nonlocal text
        assert text.count(old) == 1, old
        text = text.replace(old, new, 1)
    once('        r15Pool = NULL;\n', '        r15Pool = NULL;\n        r17Tx = NULL;\n')
    stop = text.index('void RTL8125::stop(IOService *provider)')
    end = text.index('    if (workLoop)', stop)
    text = text[:end] + '    r17TxStop();\n' + text[end:]
    # Mapping happens after the real physical segments are known and before the
    # ring reservation / descriptor fill / first OWN of this packet.
    once('        OSAddAtomic(-numSegs, &txNumFreeDesc);',
         '        if (!r17TxMap(m, txSegments, numSegs)) continue;\n'
         '        OSAddAtomic(-numSegs, &txNumFreeDesc);')
    once('                txMbufArray[index] = m;',
         '                /* Selected mbuf belongs to the R17 slot, not the TX ring,\n'
         '                 * so the per-packet recycle path is its only owner. */\n'
         '                R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);\n'
         '                txMbufArray[index] = (p && p->packet == m) ? NULL : m;')
    once('        firstDesc->opts1 |= DescOwn;',
         '        firstDesc->opts1 |= DescOwn;\n        r17TxPosted(m);')
    once('        m = txMbufArray[txDirtyDescIndex];',
         '        r17TxComplete(txDirtyDescIndex);\n        m = txMbufArray[txDirtyDescIndex];')
    # struct must be defined before outputStart's ownership check
    start = text.index('struct RTL8125::R17TxState {')
    end = text.index('\n};', start) + 3
    struct = text[start:end]
    text = text[:start] + text[end:]
    pos = text.index('IOReturn RTL8125::outputStart(')
    text = text[:pos] + struct + '\n\n' + text[pos:]
    once('    if (!functionName || !functionName->isEqualTo(r15pool::kFunctionName))',
         '    if (functionName && functionName->isEqualTo(r17tx::kFunctionName)) {\n'
         '        if (!param1 || param2 || param3 || param4 || !commandGate)\n'
         '            return kIOReturnBadArgument;\n'
         '        return commandGate->runAction(\n'
         '            [](OSObject *o, void *c, void *, void *, void *) -> IOReturn {\n'
         '                return ((RTL8125 *)o)->r17TxConfigure((r17tx::Configure *)c);\n'
         '            }, param1);\n'
         '    }\n'
         '    if (!functionName || !functionName->isEqualTo(r15pool::kFunctionName))')
    return text
