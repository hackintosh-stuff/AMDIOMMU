"""Round16 generator templates. Loaded by apply-lucy-obs2, not a probe."""
MEMBERS = r'''
    struct R16TxState;
    R16TxState *r16Tx;
    IOReturn r16TxConfigure(r16tx::Configure *c);
    bool r16TxMap(mbuf_t m, IOPhysicalSegment *segments, UInt32 &count);
    void r16TxComplete(UInt32 slot);
    void r16TxPosted(mbuf_t m);
    void r16TxPublish();
    void r16TxTimer(IOTimerEventSource *timer);
    void r16TxStop();
'''
METHODS = r'''
#pragma mark --- round 16 explicit TX mapping ---
struct RTL8125::R16TxState {
    volatile UInt32 state;
    volatile bool enabled;
    UInt32 token, bdf, lastSlot;
    UInt64 deadline;
    r16tx::Callback callback;
    void *context;
    IOService *owner;
    IOTimerEventSource *timer;
    r16tx::Request request;
    mbuf_t packet, quarantine[4];
    UInt32 quarantineCount;
    IOBufferMemoryDescriptor *staging[4];
    UInt64 stagingPA[4];
    bool stagingPrepared[4];
    volatile UInt32 copiedBytes;
    UInt32 mapped, completed, retired, dropped;
    r16tx::Witness current;
    r16tx::Snapshot snapshot;
};

IOReturn RTL8125::r16TxConfigure(r16tx::Configure *c)
{
    if (!c || c->version != r16tx::kVersion || c->bytes != sizeof(*c) ||
        c->op < r16tx::kInstall || c->op > r16tx::kDetach)
        return kIOReturnBadArgument;
    /* platform entry is serialized by commandGate. State CAS also excludes
     * output thread (not on this workloop). Completion never takes a lock. */
    if (c->op == r16tx::kInstall && !r16Tx) {
        if (useAppleVTD || !workLoop || !pciDevice || !c->callback ||
            !c->context || !c->owner || !c->token ||
            c->deadline <= mach_absolute_time()) return kIOReturnBadArgument;
        UInt32 bdf = ((UInt32)pciDevice->getBusNumber() << 8) |
                     ((UInt32)pciDevice->getDeviceNumber() << 3) |
                     pciDevice->getFunctionNumber();
        if (bdf != c->bdf) return kIOReturnBadArgument;
        R16TxState *p = (R16TxState *)IOMalloc(sizeof(R16TxState));
        if (!p) return kIOReturnNoMemory;
        bzero(p, sizeof(*p));
        p->timer = IOTimerEventSource::timerEventSource(this,
            OSMemberFunctionCast(IOTimerEventSource::Action, this,
                                 &RTL8125::r16TxTimer));
        if (!p->timer || workLoop->addEventSource(p->timer) != kIOReturnSuccess) {
            if (p->timer) p->timer->release();
            IOFree(p, sizeof(*p));
            return kIOReturnNoResources;
        }
        /* Four normal, distinct page-aligned real TX DMA buffers. No high-PA
         * constraint and no output-thread allocation. Keep all until Detach. */
        bool stagingOK = true;
        for (UInt32 i = 0; i < 4 && stagingOK; i++) {
            p->staging[i] = IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task,
                kIODirectionOut | kIOMemoryPhysicallyContiguous |
                kIOMemoryHostPhysicallyContiguous | kIOMemoryMapperNone, 4096, 4096);
            if (!p->staging[i]) { stagingOK = false; break; }
            if (p->staging[i]->prepare() != kIOReturnSuccess) {
                stagingOK = false; break;
            }
            p->stagingPrepared[i] = true;
            IOByteCount span = 0;
            p->stagingPA[i] = p->staging[i]->getPhysicalSegment(0, &span,
                                                           kIOMemoryMapperNone);
            stagingOK = p->staging[i]->getBytesNoCopy() &&
                p->staging[i]->getLength() >= 4096 && span >= 4096 &&
                p->stagingPA[i] && !(p->stagingPA[i] & 4095) &&
                p->stagingPA[i] + 4096 > p->stagingPA[i];
            for (UInt32 j = 0; j < i; j++)
                if (p->stagingPA[j] == p->stagingPA[i]) stagingOK = false;
        }
        if (!stagingOK) {
            for (UInt32 i = 0; i < 4; i++) {
                /* No backend mapping exists here; failed complete still pins
                 * that descriptor rather than releasing an uncertain owner. */
                if (p->staging[i] && (!p->stagingPrepared[i] ||
                    p->staging[i]->complete() == kIOReturnSuccess))
                    p->staging[i]->release();
            }
            workLoop->removeEventSource(p->timer); p->timer->release();
            IOFree(p, sizeof(*p)); return kIOReturnNoResources;
        }
        /* Permanent state allocation avoids pointer lifetime races. No second
         * Install after Detach: one finite four-request experiment per start. */
        p->token = c->token; p->bdf = bdf; p->deadline = c->deadline;
        p->context = c->context; p->callback = c->callback; p->owner = c->owner;
        p->owner->retain();
        p->enabled = true;
        __atomic_store_n(&r16Tx, p, __ATOMIC_RELEASE);
        p->timer->setTimeoutMS(10);
    } else if (c->op == r16tx::kInstall) return kIOReturnBusy;
    R16TxState *p = __atomic_load_n(&r16Tx, __ATOMIC_ACQUIRE);
    if (!p) return kIOReturnNotReady;
    if (c->op == r16tx::kDisarm || c->op == r16tx::kDetach)
        __atomic_store_n(&p->enabled, false, __ATOMIC_RELEASE);
    UInt32 state = __atomic_load_n(&p->state, __ATOMIC_ACQUIRE);
    c->state = state;
    /* handle is only safe to copy while Idle/Submitted/Pending, never while
     * Map/Retire writes the request. Query is diagnostic, not a barrier. */
    c->handle = 0; // never race callback mutation; raw witnesses carry handles
    c->mapped = __atomic_load_n(&p->mapped, __ATOMIC_RELAXED);
    c->completed = __atomic_load_n(&p->completed, __ATOMIC_RELAXED);
    c->retired = __atomic_load_n(&p->retired, __ATOMIC_RELAXED);
    c->dropped = __atomic_load_n(&p->dropped, __ATOMIC_RELAXED);
    if (c->op == r16tx::kDisarm || c->op == r16tx::kDetach) {
        UInt32 expected = r16tx::kIdle;
        if (!__atomic_compare_exchange_n(&p->state, &expected,
            (UInt32)r16tx::kControl, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return kIOReturnBusy;
        if (c->op == r16tx::kDetach) {
            /* Only Idle is eligible: every live backend mapping has retired.
             * Complete all native buffers before freeing either owner. A failed
             * complete pins all remaining resources and owner; retry is safe. */
            for (UInt32 i = 0; i < 4; i++) {
                if (p->staging[i] && p->stagingPrepared[i]) {
                    IOReturn result = p->staging[i]->complete();
                    if (result != kIOReturnSuccess) {
                        __atomic_store_n(&p->state, (UInt32)r16tx::kIdle, __ATOMIC_RELEASE);
                        return result;
                    }
                    p->stagingPrepared[i] = false;
                }
            }
            for (UInt32 i = 0; i < 4; i++) {
                if (p->staging[i]) { p->staging[i]->release(); p->staging[i] = NULL; }
                if (i < p->quarantineCount) {
                    freePacket(p->quarantine[i]); p->quarantine[i] = NULL;
                    /* Actual DMA buffer AND original mbuf are both gone. */
                    p->snapshot.witnesses[i].tFree = mach_absolute_time();
                }
            }
            p->quarantineCount = 0;
            p->callback = NULL; p->context = NULL;
            if (p->owner) { p->owner->release(); p->owner = NULL; }
        }
        __atomic_store_n(&p->state, (UInt32)r16tx::kIdle, __ATOMIC_RELEASE);
        c->state = r16tx::kIdle;
    }
    r16TxPublish();
    return kIOReturnSuccess;
}

/* true: caller may submit m. false: consumed (free or pinned), MUST continue.
 * Called only after getPhysicalSegmentsWithCoalesce and before ANY OWN. */
bool RTL8125::r16TxMap(mbuf_t m, IOPhysicalSegment *segments, UInt32 &count)
{
    R16TxState *p = __atomic_load_n(&r16Tx, __ATOMIC_ACQUIRE);
    if (!p) return true;
    UInt32 token = 0, req = 0, flow = 0;
    UInt32 flags = obsParseBiz(m, (UInt32)mbuf_pkthdr_len(m), true,
                              &token, &req, &flow);
    if (!(flags & kObsPktParsed) || token != p->token || req < 1 || req > 4)
        return true;
    UInt32 expected = r16tx::kIdle;
    if (!__atomic_compare_exchange_n(&p->state, &expected,
        (UInt32)r16tx::kMapping, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        __atomic_fetch_add(&p->dropped, 1u, __ATOMIC_RELAXED);
        freePacket(m); return false;
    }
    bool valid = !useAppleVTD && __atomic_load_n(&p->enabled, __ATOMIC_ACQUIRE)
        && p->callback && mach_absolute_time() < p->deadline &&
        count && count <= r16tx::kMaxSegments && p->quarantineCount < 4;
    UInt64 total = 0, pages = 0;
    for (UInt32 i = 0; valid && i < count; i++) {
        UInt64 pa = segments[i].location, len = segments[i].length;
        valid = pa && len && len <= 0x3fff && pa + len > pa;
        if (!valid) break;
        total += len; pages += ((pa & 4095) + len + 4095) / 4096;
        valid = total <= r16tx::kMaxBytes && pages <= r16tx::kMaxPages;
    }
    valid = valid && total <= 4096 && total == (UInt64)mbuf_pkthdr_len(m);
    if (valid) {
        /* These are the real transmitted frame bytes, not a surrogate test
         * buffer: OWN descriptors point only to this page's mapped IOVA. */
        IOBufferMemoryDescriptor *staging = p->staging[p->quarantineCount];
        valid = staging && p->stagingPrepared[p->quarantineCount] &&
            mbuf_copydata(m, 0, (size_t)total, staging->getBytesNoCopy()) == 0;
    }
    if (!valid) {
        __atomic_fetch_add(&p->dropped, 1u, __ATOMIC_RELAXED);
        freePacket(m);
        __atomic_store_n(&p->state, (UInt32)r16tx::kIdle, __ATOMIC_RELEASE);
        return false;
    }
    /* UInt32& updates caller numSegs BEFORE every descriptor count/index/OWN.
     * Original cursor may have 1..8 segments; copy flattens at most one page. */
    count = 1;
    segments[0].location = p->stagingPA[p->quarantineCount];
    segments[0].length = total;
    __atomic_fetch_add(&p->copiedBytes, (UInt32)total, __ATOMIC_RELAXED);
    bzero(&p->current, sizeof(p->current));
    p->current.cumulative = txTailPtr0;
    p->current.firstSlot = txNextDescIndex;
    bzero(&p->request, sizeof(p->request));
    r16tx::Request &r = p->request;
    r.version = r16tx::kVersion; r.bytes = sizeof(r); r.bdf = p->bdf;
    r.token = token; r.reqId = req; r.count = count;
    for (UInt32 i = 0; i < count; i++) {
        r.physical[i].address = segments[i].location;
        r.physical[i].length = segments[i].length;
    }
    p->packet = m;
    IOReturn result = p->callback(p->context, r16tx::kMap, &r);
    valid = result == kIOReturnSuccess && r.handle && r.count == count && r.tMap;
    for (UInt32 i = 0; valid && i < count; i++) {
        UInt64 addr = r.iova[i].address, len = r.iova[i].length;
        valid = addr && addr != segments[i].location &&
            len == segments[i].length && addr + len > addr &&
            (addr & 4095) == (segments[i].location & 4095);
    }
    if (!valid) {
        __atomic_fetch_add(&p->dropped, 1u, __ATOMIC_RELAXED);
        if (r.handle) {
            /* Backend has cleanup obligation. No descriptor ever got OWN. */
            __atomic_store_n(&p->state, (UInt32)r16tx::kPending, __ATOMIC_RELEASE);
        } else {
            p->packet = NULL; freePacket(m);
            __atomic_store_n(&p->state, (UInt32)r16tx::kIdle, __ATOMIC_RELEASE);
        }
        return false;
    }
    for (UInt32 i = 0; i < count; i++) segments[i].location = r.iova[i].address;
    p->lastSlot = (txNextDescIndex + count - 1) & kTxDescMask;
    __atomic_fetch_add(&p->mapped, 1u, __ATOMIC_RELAXED);
    /* Published before first OWN; interrupt/polling sees all request fields. */
    __atomic_store_n(&p->state, (UInt32)r16tx::kSubmitted, __ATOMIC_RELEASE);
    return true;
}

void RTL8125::r16TxPosted(mbuf_t m)
{
    R16TxState *p = __atomic_load_n(&r16Tx, __ATOMIC_ACQUIRE);
    if (!p || __atomic_load_n(&p->state, __ATOMIC_ACQUIRE) != r16tx::kSubmitted ||
        p->packet != m) return;
    p->current.tOwn = mach_absolute_time();
    p->current.lastSlot = p->lastSlot;
    for (UInt32 i = 0; i < p->request.count; i++) {
        RtlTxDesc *d = &txDescArray[(p->current.firstSlot + i) & kTxDescMask];
        r16tx::Descriptor &out = p->current.descriptors[i];
        out.address = OSSwapLittleToHostInt64(d->addr);
        out.length = p->request.iova[i].length;
        out.opts1 = OSSwapLittleToHostInt32(d->opts1);
        out.opts2 = OSSwapLittleToHostInt32(d->opts2);
    }
}

void RTL8125::r16TxPublish()
{
    R16TxState *p = r16Tx;
    if (!p) return;
    setProperty("rtl812x-txmap-mode", "page-aligned-real-tx-staging-v1");
    setProperty("rtl812x-txmap-staging-page-bytes", (UInt64)4096, 32);
    setProperty("rtl812x-txmap-staging-count", (UInt64)4, 32);
    setProperty("rtl812x-txmap-staging-copy-bytes",
        (UInt64)__atomic_load_n(&p->copiedBytes, __ATOMIC_RELAXED), 32);
    p->snapshot.magic = 0x36315854; p->snapshot.version = r16tx::kVersion;
    p->snapshot.bytes = sizeof(p->snapshot); p->snapshot.bdf = p->bdf;
    p->snapshot.token = p->token;
    p->snapshot.dropped = __atomic_load_n(&p->dropped, __ATOMIC_RELAXED);
    p->snapshot.state = __atomic_load_n(&p->state, __ATOMIC_ACQUIRE);
    p->snapshot.tPublished = mach_absolute_time();
    OSData *data = OSData::withBytes(&p->snapshot, sizeof(p->snapshot));
    if (data) { setProperty("rtl812x-txmap-raw", data); data->release(); }
}

void RTL8125::r16TxComplete(UInt32 slot)
{
    R16TxState *p = __atomic_load_n(&r16Tx, __ATOMIC_ACQUIRE);
    if (!p || __atomic_load_n(&p->state, __ATOMIC_ACQUIRE) != r16tx::kSubmitted ||
        slot != p->lastSlot) return;
    /* Real close-pointer completion only. TX interrupt/polling already have
     * upstream __POLLING exclusion; no sleep/callback/invalidations/free here. */
    p->request.tDone = mach_absolute_time();
    p->current.doneClose = txClosePtr0;
    p->current.closeMask = linuxData.MaxTxDescPtrMask;
    __atomic_fetch_add(&p->completed, 1u, __ATOMIC_RELAXED);
    __atomic_store_n(&p->state, (UInt32)r16tx::kPending, __ATOMIC_RELEASE);
}

void RTL8125::r16TxTimer(IOTimerEventSource *timer)
{
    R16TxState *p = __atomic_load_n(&r16Tx, __ATOMIC_ACQUIRE);
    if (!p) return;
    UInt32 expected = r16tx::kPending;
    if (__atomic_compare_exchange_n(&p->state, &expected,
        (UInt32)r16tx::kRetiring, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        UInt64 handle = p->request.handle;
        IOReturn result = p->callback(p->context, r16tx::kRetire, &p->request);
        if (result == kIOReturnSuccess) {
            /* Short quarantine prevents immediate allocator PA recycling. */
            p->current.request = p->request;
            p->current.request.handle = handle;
            p->current.retired = 1;
            p->snapshot.witnesses[p->quarantineCount] = p->current;
            p->quarantine[p->quarantineCount++] = p->packet;
            p->snapshot.count = p->quarantineCount;
            p->packet = NULL;
            __atomic_fetch_add(&p->retired, 1u, __ATOMIC_RELAXED);
            p->request.handle = 0;
            __atomic_store_n(&p->state, (UInt32)r16tx::kIdle, __ATOMIC_RELEASE);
        } else {
            p->request.handle = handle; // failure cannot discard the obligation
            __atomic_store_n(&p->state, (UInt32)r16tx::kPending, __ATOMIC_RELEASE);
        }
    }
    r16TxPublish();
    timer->setTimeoutMS(10);
}

void RTL8125::r16TxStop()
{
    R16TxState *p = __atomic_load_n(&r16Tx, __ATOMIC_ACQUIRE);
    if (!p) return;
    __atomic_store_n(&p->enabled, false, __ATOMIC_RELEASE);
    p->timer->cancelTimeout();
    workLoop->removeEventSource(p->timer); p->timer->release(); p->timer = NULL;
    /* Stop is not close-pointer completion. Never release outstanding DMA or
     * callback owner. Probe must Disarm/drain/Detach before normal shutdown.
     * State itself remains allocated to avoid output pointer lifetime races. */
    IOLog("r16 TX stop: state=%u handle=%llu (nonidle retained fail-closed)\n",
          __atomic_load_n(&p->state, __ATOMIC_ACQUIRE), p->request.handle);
}
'''

def patch_cpp(text):
    def once(old, new):
        nonlocal text
        assert text.count(old) == 1, old
        text = text.replace(old, new, 1)
    once('        r15Pool = NULL;\n', '        r15Pool = NULL;\n        r16Tx = NULL;\n')
    stop = text.index('void RTL8125::stop(IOService *provider)')
    end = text.index('    if (workLoop)', stop)
    text = text[:end] + '    r16TxStop();\n' + text[end:]
    once('        OSAddAtomic(-numSegs, &txNumFreeDesc);',
         '        if (!r16TxMap(m, txSegments, numSegs)) continue;\n'
         '        OSAddAtomic(-numSegs, &txNumFreeDesc);')
    once('                txMbufArray[index] = m;',
         '                /* Selected mbuf belongs to R16 slot, not TX ring. */\n'
         '                R16TxState *p = __atomic_load_n(&r16Tx, __ATOMIC_ACQUIRE);\n'
         '                txMbufArray[index] = (p &&\n'
         '                    __atomic_load_n(&p->state, __ATOMIC_ACQUIRE) == r16tx::kSubmitted &&\n'
         '                    p->packet == m) ? NULL : m;')
    once('        firstDesc->opts1 |= DescOwn;',
         '        firstDesc->opts1 |= DescOwn;\n        r16TxPosted(m);')
    once('        m = txMbufArray[txDirtyDescIndex];',
         '        r16TxComplete(txDirtyDescIndex);\n        m = txMbufArray[txDirtyDescIndex];')
    # struct must be defined before outputStart's ownership check
    start = text.index('struct RTL8125::R16TxState {')
    end = text.index('\n};', start) + 3
    struct = text[start:end]
    text = text[:start] + text[end:]
    pos = text.index('IOReturn RTL8125::outputStart(')
    text = text[:pos] + struct + '\n\n' + text[pos:]
    once('    if (!functionName || !functionName->isEqualTo(r15pool::kFunctionName))',
         '    if (functionName && functionName->isEqualTo(r16tx::kFunctionName)) {\n'
         '        if (!param1 || param2 || param3 || param4 || !commandGate)\n'
         '            return kIOReturnBadArgument;\n'
         '        return commandGate->runAction(\n'
         '            [](OSObject *o, void *c, void *, void *, void *) -> IOReturn {\n'
         '                return ((RTL8125 *)o)->r16TxConfigure((r16tx::Configure *)c);\n'
         '            }, param1);\n'
         '    }\n'
         '    if (!functionName || !functionName->isEqualTo(r15pool::kFunctionName))')
    return text
