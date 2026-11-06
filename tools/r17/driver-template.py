"""Round17 generator templates (native-mbuf TX mapping, per-packet recycling).

Loaded by tools/build/patch-lucy-obs.py, not by any kext. Every body below is
compiled into the real driver by text substitution, so the host test that
exercises these exact functions (tools/r17/test-driver.py) is testing the
driver's own code rather than a model of it.
"""
MEMBERS = r'''
    struct R17TxState;
    R17TxState *r17Tx;
    IOReturn r17TxConfigure(r17tx::Configure *c);
    bool r17TxMap(mbuf_t m, IOPhysicalSegment *segments, UInt32 count);
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
        R17TxState *p = (R17TxState *)IOMalloc(sizeof(R17TxState));
        if (!p) return kIOReturnNoMemory;
        bzero(p, sizeof(*p));
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
                p->request.handle) {
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
 * Called only after getPhysicalSegmentsWithCoalesce and before ANY OWN. The
 * segments handed in are the packet's REAL physical segments; nothing is
 * copied and numSegs is NOT flattened here. */
bool RTL8125::r17TxMap(mbuf_t m, IOPhysicalSegment *segments, UInt32 count)
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
    bool valid = !useAppleVTD && __atomic_load_n(&p->enabled, __ATOMIC_ACQUIRE)
        && p->callback && mach_absolute_time() < p->deadline
        && p->packet == NULL && __atomic_load_n(&p->held, __ATOMIC_ACQUIRE) == 0
        && __atomic_load_n(&p->retired, __ATOMIC_RELAXED) < r17tx::kMaxRequests
        && count <= r17tx::kMaxSegments;
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
    bzero(&p->current, sizeof(p->current));
    p->current.cumulative = txTailPtr0;
    p->current.firstSlot = txNextDescIndex;
    bzero(&p->request, sizeof(p->request));
    r17tx::Request &r = p->request;
    r.version = r17tx::kVersion; r.bytes = sizeof(r); r.bdf = p->bdf;
    r.token = token; r.reqId = req; r.count = count;
    for (UInt32 i = 0; i < count; i++) {
        r.physical[i].address = segments[i].location;
        r.physical[i].length = segments[i].length;
    }
    __atomic_store_n(&p->doneSeen, 0u, __ATOMIC_RELAXED);
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
    p->lastSlot = (txNextDescIndex + count - 1) & kTxDescMask;
    __atomic_fetch_add(&p->mapped, 1u, __ATOMIC_RELAXED);
    /* Published BEFORE the first OWN: the completion path may stamp this
     * generation as soon as the doorbell is rung, but it must not start the
     * retirement of a witness that has not been recorded yet (kPosting). */
    __atomic_store_n(&p->state, (UInt32)r17tx::kPosting, __ATOMIC_RELEASE);
    return true;
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
    setProperty("rtl812x-txmap-mode", "native-mbuf-explicit-iova-v1");
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

/* Retirement: workloop timer context only. Order is fixed and observable:
 * confirmed completion -> retire (clear PTE + invalidate + CompletionWait)
 * -> free THIS packet's mbuf -> the IOVA pages and the handle are reusable. */
void RTL8125::r17TxTimer(IOTimerEventSource *timer)
{
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    if (!p) return;
    UInt32 state = __atomic_load_n(&p->state, __ATOMIC_ACQUIRE);
    /* The driver reaps TX descriptors only from txInterrupt(), which this
     * driver calls from the interrupt handler and from the polled input path.
     * A serial stationary experiment generates no inbound traffic, so without
     * this the completion of a mapped frame can sit unreaped indefinitely and
     * the next request would be dropped for "previous generation still live".
     * The timer runs on the same workloop as those two callers, so calling
     * txInterrupt() here is the same serialised context, not a new race. It is
     * done only while this generation is actually outstanding. */
    if ((state == r17tx::kPosting || state == r17tx::kSubmitted) && p->packet &&
        !__atomic_load_n(&p->doneSeen, __ATOMIC_ACQUIRE))
        txInterrupt();
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
        (UInt32)r17tx::kRetiring, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        UInt64 handle = p->request.handle;
        IOReturn result = p->callback(p->context, r17tx::kRetire, &p->request);
        if (result == kIOReturnSuccess) {
            mbuf_t done = p->packet;
            p->current.request = p->request;
            p->current.request.handle = handle;
            p->current.retired = 1;
            /* The device's own final words for this generation, read before
             * the slot can be reused (this runs in the retire tick). */
            for (UInt32 i = 0; i < p->request.count; i++)
                p->current.doneOpts1[i] = OSSwapLittleToHostInt32(
                    txDescArray[(p->current.firstSlot + i) & kTxDescMask].opts1);
            p->request.handle = 0;
            p->packet = NULL;
            __atomic_store_n(&p->held, 0u, __ATOMIC_RELEASE);
            /* Retire succeeded, so the mapping is gone and the IOVA is
             * reusable. The mbuf is released per packet here -- NOT held to
             * Detach -- and tFree is stamped after the release. */
            if (done) freePacket(done);
            p->current.tFree = mach_absolute_time();
            UInt32 n = __atomic_load_n(&p->retired, __ATOMIC_RELAXED);
            if (n < r17tx::kMaxRequests) p->snapshot.witnesses[n] = p->current;
            n++; __atomic_store_n(&p->retired, n, __ATOMIC_RELAXED);
            p->snapshot.count = n;
            __atomic_store_n(&p->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
        } else {
            /* The invalidation is not confirmed: keep handle and mbuf. A
             * failed retire is never reported as a recycled request. */
            p->request.handle = handle;
            __atomic_store_n(&p->state, (UInt32)r17tx::kPending, __ATOMIC_RELEASE);
        }
    }
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
