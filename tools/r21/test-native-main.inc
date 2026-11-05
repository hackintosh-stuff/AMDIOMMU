/* Round20 host tests for the ACTUAL generated driver methods.
 *
 * The round-17/18/19 cases are kept as-is because those paths must not
 * regress. Round 20 adds:
 *   * the paired md->complete() on BOTH pre-publish early exits of the
 *     multi-range standard path (command allocation failure, and
 *     setMemoryDescriptor failure with nothing published);
 *   * kCover: an ordinary packet is offered to the backend before any OWN,
 *     keeps its physical addresses, and is dropped if the backend refuses;
 *   * the blocked-ring record: first unfinished slot, ring address, and every
 *     outstanding descriptor.
 */

static int mapMode = 0;      /* 0 ok, 1 fail-no-handle, 2 fail-then-handle, 3 bad iova */
static int retireMode = 0;   /* 0 ok, 1 fail once, 2 fail always */
static int maps = 0, retires = 0, retireFails = 0;
static UInt64 handleSeq = 0;
/* Round 20: the backend also answers kCover for ordinary (non-selected) TX. */
static int coverMode = 0;    /* 0 ok, 1 refuse, 2 slow (checks concurrency) */
static int coverCalls = 0;
static UInt64 coverLastPa = 0;
static UInt32 coverLastCount = 0;
/* Round 21: the harness answers the two window-edge control ops itself, the
 * same way the real backend does, so the driver's gate logic is exercised
 * end-to-end instead of being simulated. */
static UInt32 harnessGate = 0;      /* the gate the "backend" reports */
static UInt32 harnessOutstanding = 0;
static UInt32 harnessGateCalls = 0, harnessGateFails = 0;
static int harnessQuiesceRefuse = 0;
static UInt32 lastSampleSeq = 0;

static IOReturn backend(void *, uint32_t op, r17tx::Request *r)
{
    if (op == r17tx::kCover) {
        coverCalls++;
        if (coverMode) return 95;
        if (r->count) { coverLastPa = r->physical[0].address;
                        coverLastCount = r->count; }
        return 0;
    }
    if (op == r17tx::kRetire) {
        retires++;
        if (retireMode == 1 && retireFails == 0) { retireFails++; return 88; }
        if (retireMode == 2) return 88;
        r->tRetire = mach_absolute_time();
        return 0;
    }
    if (op == r17tx::kRetireAck) {
        stdAckCalls++;
        auto record = stdConfirmedRetires.find(r->handle);
        if (!r->handle || r->bdf != 0x2500 || r->token != 7 ||
            record == stdConfirmedRetires.end()) return kIOReturnNotReady;
        r->tRetire = record->second;
        return kIOReturnSuccess;
    }
    maps++;
    if (mapMode == 1) return 99;
    UInt64 at = 0;
    for (UInt32 i = 0; i < r->count; i++) {
        UInt64 pa = r->physical[i].address, len = r->physical[i].length;
        UInt64 off = pa & 4095;
        r->iova[i].address = 0x1000000000ULL + at * 4096 + off;
        r->iova[i].length = len;
        at += (off + len + 4095) / 4096;
    }
    if (mapMode == 3) r->iova[0].address += 1;         /* offset broken */
    r->handle = ++handleSeq;
    r->tMap = mach_absolute_time();
    if (mapMode == 2) r->handle = 0;                    /* ambiguous failure */
    return mapMode == 2 ? 99 : 0;
}

/* The map call now updates the segment count in place (standard mode replaces
 * the packet's cursor segments with the single IOVA run the command returned). */
static bool mapCall(RTL8125 &d, mbuf_t m, IOPhysicalSegment *segs, UInt32 n,
                    UInt32 *outN = nullptr)
{
    UInt32 c = n;
    bool r = d.r17TxMap(m, segs, c);
    if (outN) *outN = c;
    return r;
}

/* Round 21: drive the real control op, so the gate logic under test is the
 * driver's own and the returned knobs are its real answers. */
static UInt32 harnessInFlight = 0, harnessRingOwn = 0, harnessEdgeSeq = 0;
static UInt64 harnessSubmitDone = 0, harnessDrainDone = 0;
static IOReturn gateCfg(RTL8125 &d, bool quiesce)
{
    r17tx::Configure c{};
    c.version = r17tx::kVersion; c.bytes = sizeof(c);
    c.op = quiesce ? (UInt32)r17tx::kQuiesce : (UInt32)r17tx::kResume;
    c.bdf = 0x2500; c.token = 7;
    const IOReturn kr = d.r17TxConfigure(&c);
    if (kr == 0) {
        harnessGate = c.quiesced;
        harnessOutstanding = c.outstanding;
        harnessInFlight = c.inFlight;
        harnessRingOwn = c.ringOwn;
        harnessEdgeSeq = c.edgeSeq;
        harnessSubmitDone = c.tSubmitDone;
        harnessDrainDone = c.tDrainDone;
        harnessGateCalls++;
    } else harnessGateFails++;
    return kr;
}

/* Round22: the probe never disarms/detaches without a preceding quiesce, and
 * the driver now REFUSES that order, so every cleanup in this file goes through
 * the same two calls the exit sequence makes. */
static IOReturn detachCfg(RTL8125 &d)
{
    assert(gateCfg(d, true) == 0);
    r17tx::Configure c{};
    c.version = r17tx::kVersion; c.bytes = sizeof(c);
    c.op = r17tx::kDetach;
    c.bdf = 0x2500; c.token = 7;
    return d.r17TxConfigure(&c);
}
static void installMode(RTL8125 &d, IOService &o, UInt32 mode, IOMapper *mapper,
                        UInt64 deadline = 100000000)
{
    /* Each fixture installs a fresh device domain. */
    IODMACommand::arena = {};
    d.r17Tx = nullptr;
    r17tx::Configure c{};
    c.version = r17tx::kVersion; c.bytes = sizeof(c); c.op = r17tx::kInstall;
    c.bdf = 0x2500; c.token = 7; c.deadline = deadline;
    c.callback = backend; c.context = &o; c.owner = &o;
    c.mode = mode; c.mapper = mapper;
    assert(!d.r17TxConfigure(&c));
    /* Round22: Install closes the admission word BEFORE publishing the state,
     * so nothing can be admitted between "the state exists" and "the gate is
     * shut". This is the half of the enter edge round 21 could not observe. */
    assert(d.r17Admit == 0x80000000u);
    /* Round 21: Install deliberately leaves the window gate CLOSED -- the probe
     * opens it in r17EnterComplete() once the DTE flip is confirmed. Every case
     * below exercises the mapping path, not the window edges, so it opens the
     * gate here with the same single call the probe makes. The gate tests
     * ((8)/(9)) close it again explicitly. */
    {
        r17tx::Configure g{};
        g.version = r17tx::kVersion; g.bytes = sizeof(g);
        g.op = r17tx::kResume;
        g.bdf = c.bdf; g.token = c.token;
        assert(!d.r17TxConfigure(&g));
    }
    assert(d.r17Admit == 0u);
    d.interface.signals = 0; // discard this fixture's initial Resume wake
    assert(o.refs == 2);
    /* Round23: there is no driver-wide generation state any more. What must be
     * true after Install is that EVERY generation slot is idle and no mbuf is
     * held -- which is the same fact, checked across the set. */
    for (UInt32 k = 0; k < r17tx::kSlots; k++)
        assert(d.r17Tx->gens[k].state == r17tx::kIdle);
    assert(d.r17Tx->held == 0 && d.r17Tx->maxHeld == 0);
}

static void install(RTL8125 &d, IOService &o)
{
    installMode(d, o, r17tx::kModeDirect, nullptr);
}

static r17tx::Configure control(unsigned op)
{
    r17tx::Configure c{};
    c.version = r17tx::kVersion; c.bytes = sizeof(c); c.op = op;
    return c;
}

/* Fill the descriptor slots exactly as outputStart's loop does, then commit.
 *
 * Round23: the generation to mark is the one that owns THIS mbuf. Round 22
 * could assume gens[0] because only one could be live; the multi-generation
 * cases below submit several of them in overlapping order, so the lookup uses
 * the same helper the driver does. */
static UInt32 genOfPacket(RTL8125 &d, mbuf_t m)
{
    for (UInt32 k = 0; k < r17tx::kSlots; k++)
        if (d.r17Tx->gens[k].packet == m) return k;
    return r17tx::kSlots;
}
static void submit(RTL8125 &d, mbuf_t m, IOPhysicalSegment *segs, UInt32 n)
{
    const UInt32 g = genOfPacket(d, m);
    if (g >= r17tx::kSlots) {
        printf("submit(): packet tok=%u req=%u len=%u is not held by any "
               "generation (states %u/%u/%u/%u, held=%u, maps=%d)\n",
               m->token, m->req, m->len,
               d.r17Tx->gens[0].state, d.r17Tx->gens[1].state,
               d.r17Tx->gens[2].state, d.r17Tx->gens[3].state,
               d.r17Tx->held, maps);
    }
    assert(g < r17tx::kSlots);
    UInt32 index = d.r17Tx->gens[g].current.firstSlot;
    d.txNextDescIndex = (index + n) & kTxDescMask;
    for (UInt32 i = 0; i < n; i++) {
        RtlTxDesc *desc = &d.txDescArray[index];
        UInt32 opts1 = (UInt32)segs[i].length | (i == 0 ? 0x10000000u : 0x80000000u);
        if (i == n - 1) opts1 |= 0x20000000u;
        desc->addr = segs[i].location;
        desc->opts1 = opts1;
        desc->opts2 = 0;
        index = (index + 1) & kTxDescMask;
    }
    d.txDescArray[d.r17Tx->gens[g].current.firstSlot].opts1 |= 0x80000000u;
    d.r17TxPosted(m);
}

static void retireTick(RTL8125 &d, IOTimerEventSource *t) { d.r17TxTimer(t); }

/* Round22: an ordinary (non-selected) packet that the map accepted is OWNed by
 * outputStart and then reported through r17TxPosted() -- that call is what ends
 * its admission reference. The harness has no output ring for these packets, so
 * the commit is emulated explicitly; leaving it out would leak a reference and
 * make every later quiesce report "still admitted". */
static void postOrdinary(RTL8125 &d, mbuf_t m)
{
    assert(d.r17TxRefs() > 0);
    d.r17TxPosted(m);
}

/* One whole accepted standard-mode generation, ending in a confirmed unmap. */
static void stdRoundTrip(RTL8125 &d, IOService &o, IOTimerEventSource &timer,
                         UInt32 req, UInt64 pa, UInt32 len)
{
    RTL8125::R17TxState *p = d.r17Tx;
    Mbuf m; m.token = 7; m.req = req; m.len = len; m.pa = pa;
    IOPhysicalSegment seg[1] = {{0, 0}};
    UInt32 n = 0;
    assert(mapCall(d, &m, seg, 1, &n));
    assert(n == 1);                                   /* one IOVA run */
    assert(p->gens[0].state == r17tx::kPosting);
    /* First-fit allocation places a lone mapping at the first arena page. */
    assert(seg[0].location == amdtx::kBase + (pa & 4095ULL));
    assert(seg[0].location != pa);                     /* non-identity */
    assert(p->gens[0].request.count == 1);
    assert(p->gens[0].stdHandle == stdLastHandle && p->gens[0].stdHandle);
    assert(p->gens[0].stdW.handle == p->gens[0].stdHandle);   /* stamped, never inferred */
    assert(p->gens[0].stdMD && p->gens[0].stdCmd);
    assert(p->gens[0].stdW.flags & r18std::kMapped);
    submit(d, &m, seg, 1);
    assert(p->gens[0].state == r17tx::kSubmitted);
    assert(p->gens[0].current.descriptors[0].address == seg[0].location);
    assert(p->gens[0].stdW.tCommit == p->gens[0].current.tOwn);
    d.r17TxComplete(p->gens[0].lastSlot);
    assert(p->gens[0].state == r17tx::kPending && m.frees == 0);
    const int unmapsBefore = stdUnmapCount;
    retireTick(d, &timer);
    assert(stdUnmapCount == unmapsBefore + 1);         /* complete() ran */
    assert(m.frees == 1);
    assert(!p->gens[0].stdMD && !p->gens[0].stdCmd);                   /* objects released */
    assert(p->gens[0].stdHandle == 0 && p->held == 0);
    assert(p->gens[0].state == r17tx::kIdle);
    assert(p->gens[0].stdW.flags & r18std::kUnmapped);
    (void)o;
}

int main(void)
{
    IOService owner;
    RTL8125 d;
    IOTimerEventSource timer;
    install(d, owner);
    RTL8125::R17TxState *p = d.r17Tx;

    /* ---- 1. native two-segment packet: count kept, offsets kept ------------- */
    {
        Mbuf m; m.token = 7; m.req = 1; m.len = 1514;
        IOPhysicalSegment seg[2] = {{0x35acb2bb6ULL, 1000}, {0x3defce000ULL, 514}};
        assert(mapCall(d, &m, seg, 2));
        assert(p->gens[0].state == r17tx::kPosting);
        assert(p->gens[0].request.count == 2);              /* NOT flattened to 1 */
        assert(seg[0].location == 0x1000000bb6ULL); /* offset preserved */
        assert(seg[1].location == amdtx::kBase + 0x1000ULL);   /* stripe 0, 2nd page */
        assert(p->held == 1 && p->maxHeld == 1 && p->gens[0].packet == &m);
        submit(d, &m, seg, 2);
        assert(p->gens[0].state == r17tx::kSubmitted);
        assert(p->gens[0].current.descriptors[0].address == seg[0].location);
        assert(p->gens[0].current.descriptors[1].length == 514);
        d.r17TxComplete(p->gens[0].lastSlot);
        assert(p->gens[0].state == r17tx::kPending && p->completed == 1);
        assert(m.frees == 0);
        retireTick(d, &timer);
        assert(m.frees == 1);
        assert(p->held == 0 && p->retired == 1);
        assert(p->snapshot.witnesses[0].tFree >= p->snapshot.witnesses[0].request.tRetire);
        assert(p->gens[0].state == r17tx::kIdle);
    }

    /* ---- 2. fast completion before the commit step ------------------------- */
    {
        UInt32 c0 = p->completed;
        Mbuf m; m.token = 7; m.req = 2; m.len = 74;
        IOPhysicalSegment seg[1] = {{0x3c57d63b6ULL, 74}};
        assert(mapCall(d, &m, seg, 1));
        d.r17TxComplete(p->gens[0].lastSlot);
        assert(p->gens[0].state == r17tx::kPosting);
        assert(p->gens[0].doneSeen == 1);
        assert(p->completed == c0);
        submit(d, &m, seg, 1);
        assert(p->gens[0].state == r17tx::kPending && p->completed == c0 + 1);
        retireTick(d, &timer);
        assert(m.frees == 1 && p->retired == 2 && p->held == 0);
    }

    /* ---- 3. retire failure keeps the owner and the handle ------------------ */
    {
        retireMode = 1;
        Mbuf m; m.token = 7; m.req = 3; m.len = 74;
        IOPhysicalSegment seg[1] = {{0x35f6651b6ULL, 74}};
        assert(mapCall(d, &m, seg, 1));
        UInt64 h = p->gens[0].request.handle;
        submit(d, &m, seg, 1);
        d.r17TxComplete(p->gens[0].lastSlot);
        retireTick(d, &timer);
        assert(p->gens[0].state == r17tx::kPending);
        assert(p->held == 1 && p->gens[0].packet == &m && m.frees == 0);
        assert(p->gens[0].request.handle == h);
        assert(p->retired == 2);
        retireTick(d, &timer);
        assert(p->gens[0].state == r17tx::kIdle && p->held == 0 && m.frees == 1);
        assert(p->retired == 3);
        retireMode = 0;
    }

    /* ---- 4. map refused with handle 0 frees the packet, no owner ----------- */
    {
        mapMode = 2;
        Mbuf m; m.token = 7; m.req = 4; m.len = 74;
        IOPhysicalSegment seg[1] = {{0x35e41000ULL, 74}};
        UInt32 before = p->rejected;
        assert(!mapCall(d, &m, seg, 1));
        assert(p->gens[0].state == r17tx::kIdle && p->held == 0 && m.frees == 1);
        assert(p->rejected == before + 1);
        mapMode = 0;
    }

    /* ---- 5. map refused but the backend kept a handle => pinned ------------ */
    {
        mapMode = 3;
        Mbuf m; m.token = 7; m.req = 5; m.len = 74;
        IOPhysicalSegment seg[1] = {{0x35e42000ULL, 74}};
        assert(!mapCall(d, &m, seg, 1));
        assert(p->gens[0].state == r17tx::kPending && p->held == 1 && m.frees == 0);
        mapMode = 0;
        retireTick(d, &timer);
        assert(p->held == 0 && m.frees == 1);
    }

    /* ---- 6. geometry/protocol refusals free and stay Idle ------------------- */
    {
        Mbuf m; m.token = 7; m.req = 6; m.len = 74;
        IOPhysicalSegment seg[1] = {{0x35e43000ULL, 74}};
        m.len = 100;
        assert(!mapCall(d, &m, seg, 1));
        assert(m.frees == 1 && p->gens[0].state == r17tx::kIdle && p->held == 0);
        Mbuf m2; m2.token = 8; m2.req = 7; m2.len = 74;
        IOPhysicalSegment s2[1] = {{0x35e44000ULL, 74}};
        assert(mapCall(d, &m2, s2, 1));
        assert(m2.frees == 0);
        postOrdinary(d, &m2);
        Mbuf m3; m3.token = 7; m3.req = r17tx::kRequestLimit + 1; m3.len = 74;
        assert(mapCall(d, &m3, s2, 1));
        postOrdinary(d, &m3);
    }

    /* ---- 7. per-packet recycling: bounded owners over many generations ----- */
    {
        UInt32 before = p->retired;
        for (UInt32 i = 0; i < 6 && before + i < r17tx::kMaxRequests; i++) {
            Mbuf *m = new Mbuf;
            m->token = 7; m->req = 8; m->len = 74;
            IOPhysicalSegment seg[1] = {{0x360000000ULL + i * 0x3000 + 0x1b6, 74}};
            assert(mapCall(d, m, seg, 1));
            assert(p->held == 1 && p->maxHeld == 1);
            submit(d, m, seg, 1);
            d.r17TxComplete(p->gens[0].lastSlot);
            assert(m->frees == 0);
            retireTick(d, &timer);
            assert(m->frees == 1 && p->held == 0);
        }
        assert(p->maxHeld == 1);
    }

    /* ---- 7b. Round25: history full does not gate mapping or retirement. ---- */
    {
        const UInt32 before = p->rejected;
        while (p->retired < 40) {
            Mbuf m; m.token = 7; m.req = p->retired + 1; m.len = 74;
            IOPhysicalSegment seg[1] = {{0x380000000ULL, 74}};
            const UInt32 seq = p->retired;
            assert(mapCall(d, &m, seg, 1));
            submit(d, &m, seg, 1);
            d.r17TxComplete(p->gens[0].lastSlot);
            retireTick(d, &timer);
            assert(m.frees == 1 && p->held == 0 && p->retired == seq + 1);
            assert(p->snapshot.witnesses[seq % 32].request.reqId == m.req);
        }
        assert(p->rejected == before);
        assert(p->snapshot.count == 32 && p->snapshot.historyStart == 8);
    }

    /* ---- 8. Detach while an owner is live must refuse, not free ------------ */
    {
        Mbuf m; m.token = 7; m.req = 9; m.len = 74;
        IOPhysicalSegment seg[1] = {{0x370000000ULL, 74}};
        assert(mapCall(d, &m, seg, 1));
        submit(d, &m, seg, 1);
        d.r17TxComplete(p->gens[0].lastSlot);
        auto c = control(r17tx::kDisarm);
        assert(gateCfg(d, true) == 0);          /* admission closed first */
        assert(d.r17TxConfigure(&c) == kIOReturnBusy);
        c.op = r17tx::kDetach;
        assert(d.r17TxConfigure(&c) == kIOReturnBusy);
        assert(m.frees == 0 && p->held == 1);
        retireTick(d, &timer);
        assert(m.frees == 1 && p->held == 0);
        c.op = r17tx::kDisarm;
        assert(!d.r17TxConfigure(&c));
    }
    /* ---- 9. Detach from Idle releases the owner, frees nothing extra ------- */
    {
        auto c = control(r17tx::kDetach);
        assert(!d.r17TxConfigure(&c));   /* admission is still closed from (8) */
        assert(owner.refs == 1);
        assert(p->gens[0].state == r17tx::kIdle && p->held == 0);
        assert(p->snapshot.count == (p->retired > 32 ? 32 : p->retired));
    }
    d.r17TxStop();

    /* ==================== round 19: timer harvest exclusion ================= */
    {
        IOService o2;
        RTL8125 d2;
        IOTimerEventSource t2;
        installMode(d2, o2, r17tx::kModeDirect, nullptr);
        RTL8125::R17TxState *q = d2.r17Tx;
        Mbuf m; m.token = 7; m.req = 11; m.len = 74;
        IOPhysicalSegment seg[1] = {{0x390000000ULL + 0x2b6, 74}};
        assert(mapCall(d2, &m, seg, 1));
        submit(d2, &m, seg, 1);              /* kSubmitted, no completion yet */
        assert(q->gens[0].state == r17tx::kSubmitted);
        const UInt32 c0 = d2.txInterruptCalls;
        /* (a) a poller holds the exclusion: the timer must NOT enter. */
        d2.stateFlags = 1u << __POLLING;
        retireTick(d2, &t2);
        assert(d2.txInterruptCalls == c0);            /* skipped, not queued */
        assert(d2.stateFlags & (1u << __POLLING));    /* still the poller's bit */
        /* (b) released: the harvest runs, and inside it the bit is held. */
        mock_clear_bit(__POLLING, &d2.stateFlags);
        harvestHeldPolling = 0;
        retireTick(d2, &t2);
        assert(d2.txInterruptCalls == c0 + 1);
        assert(harvestHeldPolling == 1);              /* entered WITH the bit */
        assert(!(d2.stateFlags & (1u << __POLLING))); /* released afterwards */
        /* the timer's own tick must not leave the generation stranded either */
        d2.r17TxComplete(q->gens[0].lastSlot);
        retireTick(d2, &t2);
        assert(m.frees == 1 && q->retired == 1 && q->held == 0);
        auto c = control(r17tx::kDetach);
        assert(gateCfg(d2, true) == 0);
        assert(!d2.r17TxConfigure(&c));
        d2.r17TxStop();
    }

    /* ==================== round 19: standard mapper path =================== */
    {
        IOService o3;
        RTL8125 s;
        IOTimerEventSource t3;
        IOMapper mapper;
        stdMode = kStdOk;
        installMode(s, o3, r17tx::kModeStandard, &mapper);
        RTL8125::R17TxState *q = s.r17Tx;
        assert(q->stdMode && q->stdMapper == &mapper);

        /* (1) full standard round trip: map via the command, then unmap via it */
        const int md0 = stdMdCreated, cmd0 = stdCmdCreated;
        stdRoundTrip(s, o3, t3, 12, 0x3c57d63b6ULL, 74);
        assert(stdMdCreated == md0 + 1 && stdCmdCreated == cmd0 + 1);
        assert(stdMdReleased == stdMdCreated && stdCmdReleased == stdCmdCreated);
        assert(q->stdAccepts == 1 && q->stdUnmaps == 1);
        assert(q->stdSnap.witnesses[0].flags & r18std::kMapped);
        assert(q->stdSnap.witnesses[0].memory != 0 && q->stdSnap.witnesses[0].command != 0);
        assert(q->stdSnap.witnesses[0].segCount == 1);
        assert(q->stdSnap.witnesses[0].mapAddress ==
               amdtx::kBase + (0x3c57d63b6ULL & 4095ULL));
        stdRoundTrip(s, o3, t3, 13, 0x35e41000ULL, 162);
        assert(q->stdAccepts == 2 && q->stdUnmaps == 2);

        /* (2) THE round-19 feature: a real two-mbuf chain is mapped as TWO
         * ranges, the command answers with TWO runs, both become descriptors,
         * and the whole chain is freed on retire. */
        {
            const int md0 = stdMdCreated, cmd0 = stdCmdCreated;
            Mbuf head; head.token = 7; head.req = 14; head.len = 42;
            head.pkthdr = 1514; head.pa = 0x3a4c1000ULL + 0x2b6;
            Mbuf tail; tail.token = 7; tail.req = 14; tail.len = 1472;
            tail.pa = 0x3d9e7000ULL + 0x130;
            head.next = &tail;
            IOPhysicalSegment seg[4] = {};
            UInt32 n = 0;
            assert(mapCall(s, &head, seg, 2, &n));
            assert(n == 2);                        /* one run per mbuf */
            assert(q->gens[0].state == r17tx::kPosting);
            assert(q->gens[0].stdW.mbufSegments == 2);     /* chain length recorded */
            assert(q->gens[0].stdW.segCount == 2);
            assert(q->gens[0].request.count == 2);
            assert(seg[0].location == amdtx::kBase + 0x2b6ULL);   /* stripe 0 */
            assert(seg[1].location == amdtx::kBase + 0x1000ULL + 0x130ULL);
            assert(seg[0].location != head.pa && seg[1].location != tail.pa);
            assert(q->gens[0].stdW.segments[1].length == 1472);
            assert(q->gens[0].stdMD && q->gens[0].stdCmd);
            submit(s, &head, seg, 2);
            assert(s.r17Tx->gens[0].current.descriptors[0].address == seg[0].location);
            assert(s.r17Tx->gens[0].current.descriptors[1].length == 1472);
            s.r17TxComplete(q->gens[0].lastSlot);
            const int unmapsBefore = stdUnmapCount;
            retireTick(s, &t3);
            assert(stdUnmapCount == unmapsBefore + 1);
            assert(head.frees == 1 && tail.frees == 1);   /* WHOLE chain freed */
            assert(!q->gens[0].stdMD && !q->gens[0].stdCmd && q->gens[0].stdHandle == 0);
            assert(q->held == 0 && q->gens[0].state == r17tx::kIdle);
            assert(q->stdSnap.witnesses[2].flags &
                   (r18std::kMapped | r18std::kUnmapped));
            assert(stdMdCreated == md0 + 1 && stdCmdCreated == cmd0 + 1);
            assert(stdMdReleased == stdMdCreated && stdCmdReleased == stdCmdCreated);
            /* the multi-range descriptor was wired AND unwired exactly once */
            assert(stdMdPrepared == 1 && stdMdCompleted == 1);
        }

        /* (2b) round 20: multi-range descriptor + command allocation failure.
         * The descriptor was wired explicitly, so this early exit owes its
         * complete() and must reset stdWired. */
        {
            const int md0 = stdMdCreated, mdRel0 = stdMdReleased;
            const int prep0 = stdMdPrepared, comp0 = stdMdCompleted;
            stdCmdAllocFails = 1;
            Mbuf head; head.token = 7; head.req = 19; head.len = 42;
            head.pkthdr = 1514; head.pa = 0x3a4c1000ULL + 0x2b6;
            Mbuf tail; tail.token = 7; tail.req = 19; tail.len = 1472;
            tail.pa = 0x3d9e7000ULL + 0x130;
            head.next = &tail;
            IOPhysicalSegment seg[4] = {};
            UInt32 before = q->stdRejects;
            assert(!mapCall(s, &head, seg, 2));
            stdCmdAllocFails = 0;
            assert(q->stdRejects == before + 1);
            assert(head.frees == 1 && tail.frees == 1);   /* whole chain freed */
            assert(q->held == 0 && q->gens[0].state == r17tx::kIdle);
            assert(!q->gens[0].stdMD && !q->gens[0].stdCmd && !q->gens[0].stdWired && q->gens[0].stdHandle == 0);
            assert(stdMdCreated == md0 + 1 && stdMdPrepared == prep0 + 1);
            assert(stdMdCompleted == comp0 + 1);          /* paired complete() */
            assert(stdMdReleased == mdRel0 + 1);
        }

        /* (2c) round 20: multi-range descriptor + setMemoryDescriptor failure
         * with no mapping published. Same obligation, different exit. */
        {
            const int md0 = stdMdCreated, mdRel0 = stdMdReleased;
            const int prep0 = stdMdPrepared, comp0 = stdMdCompleted;
            stdMode = kStdRefuseNoHandle;
            Mbuf head; head.token = 7; head.req = 20; head.len = 42;
            head.pkthdr = 1514; head.pa = 0x3a5c1000ULL + 0x2b6;
            Mbuf tail; tail.token = 7; tail.req = 20; tail.len = 1472;
            tail.pa = 0x3d9e7000ULL + 0x930;
            head.next = &tail;
            IOPhysicalSegment seg[4] = {};
            UInt32 before = q->stdRejects;
            assert(!mapCall(s, &head, seg, 2));
            stdMode = kStdOk;
            assert(q->stdRejects == before + 1);
            assert(head.frees == 1 && tail.frees == 1);
            assert(q->held == 0 && q->gens[0].state == r17tx::kIdle);
            assert(!q->gens[0].stdMD && !q->gens[0].stdCmd && !q->gens[0].stdWired && q->gens[0].stdHandle == 0);
            assert(stdMdCreated == md0 + 1 && stdMdPrepared == prep0 + 1);
            assert(stdMdCompleted == comp0 + 1);
            assert(stdMdReleased == mdRel0 + 1);
        }

        /* (2d) round 20: an ORDINARY packet keeps its PAs but is offered to
         * the backend for coverage before submission; a refusal drops it. */
        {
            const int cover0 = coverCalls, maps0 = maps;
            Mbuf m; m.token = 8; m.req = 1; m.len = 1514;
            IOPhysicalSegment seg[2] = {{0x400a66800ULL, 42},
                                        {0x400a67810ULL, 1472}};
            assert(mapCall(s, &m, seg, 2));      /* pass-through, still 2 PAs */
            assert(coverCalls == cover0 + 1);
            assert(coverLastPa == 0x400a66800ULL && coverLastCount == 2);
            assert(maps == maps0);               /* no mapping was published */
            assert(seg[0].location == 0x400a66800ULL);
            coverMode = 1;
            Mbuf m2; m2.token = 8; m2.req = 1; m2.len = 1514;
            IOPhysicalSegment seg2[2] = {{0x400a66800ULL, 42},
                                         {0x400a67810ULL, 1472}};
            assert(!mapCall(s, &m2, seg2, 2));
            coverMode = 0;
            assert(m2.frees == 1);
            assert(q->coverRejects == 1);
            assert(maps == maps0);
        }

        /* (2e) round 20: the blocked-ring record names the first unfinished
         * slot, the ring's own address and every outstanding descriptor. */
        {
            /* This stub's r17TxComplete does not advance txDirty (the real
             * txInterrupt does); align it so "outstanding" means what it says. */
            s.txDirtyDescIndex = s.txNextDescIndex;
            Mbuf m; m.token = 7; m.req = 23; m.len = 74;
            m.pa = 0x3aa00000ULL + 0x2b6;
            IOPhysicalSegment seg[1] = {{0, 0}};
            UInt32 n = 0;
            assert(mapCall(s, &m, seg, 1, &n) && n == 1);
            submit(s, &m, seg, 1);               /* outstanding, not completed */
            /* Round 21: the throttled publish no longer rewrites a window-edge
             * sample, and a fresh state's stage is already kStageThrottled, so
             * an explicit sample is what produces the record here. */
            s.r17TxSample(r20tx::kStageQuiesce);
            const r20tx::Block &b = q->blockSnap;
            assert(b.magic == r20tx::kMagic && b.bytes == sizeof(b));
            assert(b.txNext == s.txNextDescIndex && b.txDirty == s.txDirtyDescIndex);
            assert(b.outstanding == 1 && b.firstSlot == s.txDirtyDescIndex);
            assert(b.ringAddr == 0x3ff00000ULL && b.ringBytes == kTxDescSize);
            assert(b.slots[0].index == s.txDirtyDescIndex);
            assert(b.slots[0].addr == seg[0].location);
            assert(b.slots[0].flags & r20tx::kOwn);
            assert(b.slots[0].flags & r20tx::kSelected);
            assert(b.outAddr[0] == seg[0].location);
            s.r17TxComplete(q->gens[0].lastSlot);
            retireTick(s, &t3);
            assert(m.frees == 1 && q->held == 0 && q->gens[0].state == r17tx::kIdle);
        }

        /* (3) prepare fails with nothing published: free, stay Idle */
        {
            stdMode = kStdRefuseNoHandle;
            Mbuf m; m.token = 7; m.req = 15; m.len = 74; m.pa = 0x3a0000000ULL + 0x3b6;
            IOPhysicalSegment seg[1] = {{0, 0}};
            UInt32 before = q->stdRejects;
            assert(!mapCall(s, &m, seg, 1));
            assert(q->stdRejects == before + 1);
            assert(m.frees == 1 && q->held == 0 && q->gens[0].state == r17tx::kIdle);
            assert(!q->gens[0].stdCmd && !q->gens[0].stdMD);
            stdMode = kStdOk;
        }

        /* (4) the command's answer does not cover the frame (its runs are
         * truncated). The map IS published, so it is rolled back through the same API
         * (unmap confirmed here) and NOTHING is kept. */
        {
            stdMode = kStdTooMany;
            const int unmaps0 = stdUnmapCount, cmd2 = stdCmdCreated;
            Mbuf m; m.token = 7; m.req = 16; m.len = 1472; m.pa = 0x3b0000000ULL + 0x5d2;
            IOPhysicalSegment seg[1] = {{0, 0}};
            assert(!mapCall(s, &m, seg, 1));
            assert(stdUnmapCount == unmaps0 + 1);    /* no half-mapped command */
            assert(m.frees == 1 && q->held == 0 && q->gens[0].state == r17tx::kIdle);
            assert(stdCmdCreated == cmd2 + 1 && !q->gens[0].stdCmd && !q->gens[0].stdMD);
            assert(q->gens[0].stdHandle == 0);               /* generation really closed */
            stdMode = kStdOk;
        }

        /* (5) an identity result is NEVER accepted as a mapping */
        {
            stdMode = kStdIdentity;
            Mbuf m; m.token = 7; m.req = 17; m.len = 74; m.pa = 0x3c0000000ULL + 0x1b6;
            IOPhysicalSegment seg[1] = {{0, 0}};
            assert(!mapCall(s, &m, seg, 1));
            assert(m.frees == 1 && q->held == 0 && q->gens[0].state == r17tx::kIdle);
            assert(q->gens[0].stdW.flags & r18std::kIdentity);
            stdMode = kStdOk;
        }

        /* (6) unmap failure at retire pins the generation, never recycles it */
        {
            stdUnmapFails = 1;
            Mbuf m; m.token = 7; m.req = 18; m.len = 74; m.pa = 0x3d0000000ULL + 0x4a6;
            IOPhysicalSegment seg[1] = {{0, 0}};
            UInt32 n = 0;
            assert(mapCall(s, &m, seg, 1, &n) && n == 1);
            submit(s, &m, seg, 1);
            s.r17TxComplete(q->gens[0].lastSlot);
            UInt32 pinned0 = q->stdPinned;
            retireTick(s, &t3);
            assert(q->stdPinned == pinned0 + 1);
            assert(m.frees == 0 && q->held == 1 && q->gens[0].packet == &m);
            assert(q->gens[0].state == r17tx::kPending);
            assert(q->gens[0].stdCmd && q->gens[0].stdMD);            /* obligation preserved */
            auto c = control(r17tx::kDetach);
            assert(gateCfg(s, true) == 0);
            assert(s.r17TxConfigure(&c) == kIOReturnBusy);
            stdUnmapFails = 0;
        }
        s.r17TxStop();                                /* keeps the pinned owner */
    }

    /* (7) rollback after a PUBLISHED map: the unmap result decides the ending.
     * Round 18 ignored complete()'s failure and left stdHandle set, so this
     * group is what pins that behaviour down. */
    {
        IOService o4;
        RTL8125 r;
        IOTimerEventSource t4;
        IOMapper mapper4;
        installMode(r, o4, r17tx::kModeStandard, &mapper4);
        RTL8125::R17TxState *q4 = r.r17Tx;

        /* (7a) complete() succeeds: release everything, clear the handle, and
         * let Detach proceed. */
        stdMode = kStdIdentity;
        const int md1 = stdMdCreated, cmd3 = stdCmdCreated;
        Mbuf m1; m1.token = 7; m1.req = 21; m1.len = 74; m1.pa = 0x3e0000000ULL + 0x2c6;
        IOPhysicalSegment seg1[1] = {{0, 0}};
        assert(!mapCall(r, &m1, seg1, 1));
        assert(q4->gens[0].stdW.flags & r18std::kIdentity);
        assert(q4->gens[0].stdW.completeResult == 0);              /* unmap confirmed */
        assert(stdMdCreated == md1 + 1 && stdCmdCreated == cmd3 + 1);
        /* exactly one md/cmd is still held -- by case (6)'s pinned generation */
        assert(stdMdReleased == stdMdCreated - 1 && stdCmdReleased == stdCmdCreated - 1);
        assert(!q4->gens[0].stdCmd && !q4->gens[0].stdMD && q4->gens[0].stdHandle == 0);
        assert(m1.frees == 1 && q4->held == 0 && q4->gens[0].state == r17tx::kIdle);
        {
            auto c = control(r17tx::kDetach);
            assert(gateCfg(r, true) == 0);
            assert(!r.r17TxConfigure(&c));                 /* not Busy */
            assert(o4.refs == 1);                          /* owner released */
        }
        r.r17TxStop();
        stdMode = kStdOk;

        /* (7b) complete() fails: keep mbuf, objects and handle; park in
         * kPending and refuse Detach. Nothing is reported as recycled. */
        {
            IOService o5;
            RTL8125 z;
            IOTimerEventSource t5;
            IOMapper mapper5;
            installMode(z, o5, r17tx::kModeStandard, &mapper5);
            RTL8125::R17TxState *q5 = z.r17Tx;
            stdMode = kStdIdentity;
            stdUnmapFails = 1;
            Mbuf m2; m2.token = 7; m2.req = 22; m2.len = 74; m2.pa = 0x3f0000000ULL + 0x3d6;
            IOPhysicalSegment seg2[1] = {{0, 0}};
            assert(!mapCall(z, &m2, seg2, 1));
            assert(q5->gens[0].stdW.flags & r18std::kPinned);
            assert((int)q5->gens[0].stdW.completeResult != 0);
            assert(m2.frees == 0 && q5->gens[0].packet == &m2 && q5->held == 1);
            assert(q5->gens[0].stdCmd && q5->gens[0].stdMD && q5->gens[0].stdHandle != 0);
            assert(q5->gens[0].state == r17tx::kPending);
            auto c = control(r17tx::kDetach);
            assert(gateCfg(z, true) == 0);
            assert(z.r17TxConfigure(&c) == kIOReturnBusy);
            z.r17TxStop();
            stdMode = kStdOk;
            stdUnmapFails = 0;
        }
    }

    /* (8) round 21: the window GATE. While it is closed NEITHER an ordinary
     * packet nor a selected one may be submitted -- the selected one because
     * its 64 GiB IOVA is only meaningful once translation is in effect, the
     * ordinary one because its PAs are re-resolved through a table that is
     * being replaced. Both are dropped, never queued. */
    {
        IOService o8;
        RTL8125 r8;
        IOTimerEventSource t8;
        IOMapper mapper8;
        installMode(r8, o8, r17tx::kModeStandard, &mapper8);
        RTL8125::R17TxState *q8 = r8.r17Tx;

        const int rej0 = (int)q8->rejected;
        const int cover0 = coverCalls;
        const int maps0 = maps;
        assert(gateCfg(r8, true) == 0);          /* kQuiesce */
        assert(harnessGate == 1);

        Mbuf mo; mo.token = 8; mo.req = 1; mo.len = 74;
        IOPhysicalSegment so[1] = {{0x35e41000ULL, 74}};
        assert(!mapCall(r8, &mo, so, 1));
        assert(mo.frees == 1);
        assert((int)q8->rejected == rej0 + 1);
        assert(coverCalls == cover0);            /* no cover either */

        Mbuf ms; ms.token = 7; ms.req = 1; ms.len = 74;
        IOPhysicalSegment ss[1] = {{0x35e41000ULL, 74}};
        assert(!mapCall(r8, &ms, ss, 1));
        assert(ms.frees == 1);
        assert(maps == maps0);                   /* never reached the mapper */

        assert(gateCfg(r8, false) == 0);         /* kResume */
        assert(harnessGate == 0);
        Mbuf mo2; mo2.token = 8; mo2.req = 1; mo2.len = 74;
        IOPhysicalSegment so2[1] = {{0x35e41000ULL, 74}};
        assert(mapCall(r8, &mo2, so2, 1));
        assert(mo2.frees == 0);
        postOrdinary(r8, &mo2);
        r8.r17TxStop();
    }

    /* (10) round 21 REGRESSION: re-issuing kQuiesce must SUCCEED.
     * The first hardware run of this round failed every drain with
     * gate-fails=5/drain-ok=0 while reporting outstanding=0, because the
     * second quiesce returned Busy and the loop treated that as "cannot see the
     * ring". A drain loop that re-reads occupancy is the normal case, so
     * idempotence is the contract, not an optimisation. */
    {
        IOService o10;
        RTL8125 r10;
        IOTimerEventSource t10;
        IOMapper m10;
        installMode(r10, o10, r17tx::kModeStandard, &m10);
        RTL8125::R17TxState *q10 = r10.r17Tx;

        const UInt32 q0 = q10->windowQuiesce;   /* Install counted its own close */
        assert(gateCfg(r10, true) == 0);
        assert(harnessGate == 1);
        assert(q10->windowQuiesce == q0 + 1);
        /* the same request again, as a drain loop does it */
        assert(gateCfg(r10, true) == 0);
        assert(gateCfg(r10, true) == 0);
        assert(harnessGate == 1);
        assert(q10->windowQuiesce == q0 + 1);  /* only the first one counts */
        assert(gateCfg(r10, false) == 0);
        assert(harnessGate == 0);
        r10.r17TxStop();
    }

    /* (11) round 21 REGRESSION: the throttled publish must not overwrite a
     * window-edge sample.
     * The second hardware run produced stage=1 (quiesce) even though the exit
     * sample had been taken at stage 3, because r17TxPublish ran after r17Finish
     * and its signature check happened to pass. That made the record
     * indistinguishable from the round-20 bug it exists to fix. */
    {
        IOService o11;
        RTL8125 r11;
        IOTimerEventSource t11;
        IOMapper m11;
        installMode(r11, o11, r17tx::kModeStandard, &m11);
        RTL8125::R17TxState *q11 = r11.r17Tx;

        r11.r17TxSample(r20tx::kStageExit);
        const UInt32 seq = q11->blockSnap.sampleSeq;
        const UInt32 stage = q11->blockSnap.sampleStage;
        assert(stage == r20tx::kStageExit);
        /* the 10 ms tick, which must be a no-op here */
        r11.r17TxPublish();
        r11.r17TxPublish();
        assert(q11->blockSnap.sampleStage == stage);   /* NOT downgraded */
        assert(q11->blockSnap.sampleSeq == seq);       /* NOT re-sampled */

        /* a throttled sample may still fill an EMPTY record */
        r11.r17TxSample(r20tx::kStageThrottled);
        assert(q11->blockSnap.sampleStage == r20tx::kStageExit);
        r11.r17TxStop();
    }

    /* (12) round 21: kSample names its own stage and refuses an unknown one.
     * Reusing kQuiesce to force a sample is how "exit" got recorded as
     * "quiesce"; this op exists so the caller states which step it means. */
    {
        IOService o12;
        RTL8125 r12;
        IOTimerEventSource t12;
        IOMapper m12;
        installMode(r12, o12, r17tx::kModeStandard, &m12);
        RTL8125::R17TxState *q12 = r12.r17Tx;

        r17tx::Configure c{};
        c.version = r17tx::kVersion; c.bytes = sizeof(c);
        c.op = r17tx::kSample; c.state = r20tx::kStageExit;
        assert(!r12.r17TxConfigure(&c));
        assert(q12->blockSnap.sampleStage == r20tx::kStageExit);

        c.state = 99;                       /* not a valid stage */
        assert(r12.r17TxConfigure(&c) == kIOReturnBadArgument);
        assert(q12->blockSnap.sampleStage == r20tx::kStageExit);
        r12.r17TxStop();
    }
    /* (9) round 21: a window-edge sample is FORCED, not throttled. Round 20's
     * block came from the throttled path, whose signature ignores ring motion;
     * after Disarm restored Idle nothing changed, the publication was skipped,
     * and the archived sample was 9.014 s older than the window end. The exit
     * steps must always produce a fresh sample that names its own step. */
    {
        IOService o9;
        RTL8125 r9;
        IOTimerEventSource t9;
        IOMapper mapper9;
        installMode(r9, o9, r17tx::kModeStandard, &mapper9);
        RTL8125::R17TxState *q9 = r9.r17Tx;
        r9.r17TxSample(r20tx::kStageQuiesce);
        const UInt32 seq1 = q9->blockSnap.sampleSeq;
        const UInt32 st1 = q9->blockSnap.sampleStage;
        const UInt64 t1 = q9->blockSnap.tSample;
        r9.r17TxSample(r20tx::kStageExit);
        assert(q9->blockSnap.sampleStage == r20tx::kStageExit);
        assert(q9->blockSnap.sampleSeq > seq1);
        assert(q9->blockSnap.tSample >= t1);
        assert(st1 == r20tx::kStageQuiesce);
        assert(q9->blockSnap.quiesced ==
               __atomic_load_n(&q9->gate, __ATOMIC_ACQUIRE));
        lastSampleSeq = q9->blockSnap.sampleSeq;
        r9.r17TxStop();
    }
    /* ---- (13) round22: the two windows round 21 could not see --------------
     *
     * (a) "gate read succeeded" -> "coverActive++": in round 21 a Detach could
     *     clear callback/context in that gap. Admission is now the SAME atomic
     *     step that counts the reference, so there is no gap to clear.
     * (b) "cover returned" -> "OWN written": the ring is still empty there, so
     *     round 21's drain (which only looked at the ring) concluded "empty".
     *     The reference is held until OWN, so quiesce must NOT conclude here. */
    {
        IOService o13; RTL8125 r13; IOTimerEventSource t13; IOMapper m13;
        installMode(r13, o13, r17tx::kModeStandard, &m13);
        RTL8125::R17TxState *q13 = r13.r17Tx;

        Mbuf m; m.token = 8; m.req = 1; m.len = 74;
        IOPhysicalSegment seg[1] = {{0x35e41000ULL, 74}};
        assert(mapCall(r13, &m, seg, 1));      /* cover done, OWN not written */
        assert(r13.r17TxRefs() == 1);
        assert(r13.r17TxRingOwn() == 0);

        assert(gateCfg(r13, true) == 0);
        assert(harnessInFlight == 1);          /* (b): still admitted */
        assert(harnessRingOwn == 0);           /* the ring looks empty ... */
        assert(harnessDrainDone == 0);         /* ... and it is NOT drained */
        assert(harnessSubmitDone == 0);

        /* a new packet is refused BEFORE any cover call, which is the (a)
         * window: refusal and non-admission are the same atomic fact. */
        const int coverBefore = coverCalls, rejBefore = (int)q13->rejected;
        Mbuf m2; m2.token = 8; m2.req = 2; m2.len = 74;
        IOPhysicalSegment seg2[1] = {{0x35e42000ULL, 74}};
        assert(!mapCall(r13, &m2, seg2, 1));
        assert(m2.frees == 1 && coverCalls == coverBefore);
        assert((int)q13->rejected == rejBefore + 1);
        assert((int)q13->barrierFails == 1);

        /* write OWN: the reference leaves. This packet is ORDINARY (token 8),
         * so it never created a generation and its ring slot is not tracked by
         * the controlled path -- the fact under test is the admission
         * reference, which postOrdinary ends exactly as outputStart does. */
        postOrdinary(r13, &m);
        assert(r13.r17TxRefs() == 0);
        assert(gateCfg(r13, true) == 0);
        assert(harnessInFlight == 0);
        assert(harnessSubmitDone != 0);        /* submitters done */
        /* Nothing controlled owns a descriptor here, so the drain is complete
         * as soon as the count is: this case is about (b), the counted
         * admission, which is exactly what the earlier drainDone==0 proved. */
        assert(harnessRingOwn == 0);
        assert(harnessDrainDone != 0);
        const UInt64 submitDone = harnessSubmitDone;
        assert(gateCfg(r13, true) == 0);
        assert(harnessSubmitDone == submitDone);   /* latched, not re-stamped */
        r13.r17TxStop();
    }

    /* ---- (14) round22: kResume refuses while a submission is admitted ------ */
    {
        IOService o14; RTL8125 r14; IOTimerEventSource t14; IOMapper m14;
        installMode(r14, o14, r17tx::kModeStandard, &m14);
        Mbuf m; m.token = 8; m.req = 1; m.len = 74;
        IOPhysicalSegment seg[1] = {{0x35e41000ULL, 74}};
        assert(mapCall(r14, &m, seg, 1));
        assert(gateCfg(r14, true) == 0);
        /* reopening the window under an unaccounted submission would let the
         * probe restore the table while a descriptor is still on its way */
        assert(gateCfg(r14, false) == kIOReturnBusy);
        assert(harnessGate == 1);
        postOrdinary(r14, &m);        /* ordinary frame: ends its admission ref */
        assert(gateCfg(r14, false) == 0);
        assert(harnessGate == 0);
        r14.r17TxStop();
    }

    /* ---- (15) round22: Disarm/Detach never run without a closed word ------- */
    {
        IOService o15; RTL8125 r15; IOTimerEventSource t15; IOMapper m15;
        installMode(r15, o15, r17tx::kModeStandard, &m15);
        /* the word is OPEN here: a Disarm would race the output path */
        auto c = control(r17tx::kDisarm);
        assert(r15.r17TxConfigure(&c) == kIOReturnBusy);
        c.op = r17tx::kDetach;
        assert(r15.r17TxConfigure(&c) == kIOReturnBusy);
        assert(r15.r17Tx && r15.r17Tx->callback == backend);
        /* with the word closed it proceeds -- and it does NOT reopen it. That
         * is what keeps "restore failed, detach refused" from resuming output
         * against a table nobody covers any more. */
        assert(gateCfg(r15, true) == 0);
        auto d15 = control(r17tx::kDetach);
        assert(!r15.r17TxConfigure(&d15));
        assert(r15.r17TxRefs() == 0);
        assert(r15.r17Admit == 0x80000000u);   /* still closed after Detach */
        assert(gateCfg(r15, false) == 0);      /* only an explicit resume */
        assert(r15.r17Admit == 0u);
        r15.r17TxStop();
    }

    /* ---- (16) round22: the sampler never dereferences an mbuf -------------- */
    {
        IOService o16; RTL8125 r16; IOTimerEventSource t16; IOMapper m16;
        installMode(r16, o16, r17tx::kModeStandard, &m16);
        RTL8125::R17TxState *q16 = r16.r17Tx;
        /* four outstanding slots so the sampler walks them */
        r16.txNextDescIndex = (r16.txDirtyDescIndex + 4) & kTxDescMask;
        /* poison every mbuf pointer it could touch: any mbuf_data()/mbuf_len()
         * would dereference 0x1 and fault (ASAN catches it deterministically) */
        for (UInt32 i = 0; i < 16; i++)
            r16.txMbufArray[(r16.txDirtyDescIndex + i) & kTxDescMask] =
                (mbuf_t)(uintptr_t)0x1;
        const int d0 = mbufDataCalls, l0 = mbufLenCalls;
        r17tx::Configure c{};
        c.version = r17tx::kVersion; c.bytes = sizeof(c);
        c.op = r17tx::kSample; c.state = r20tx::kStageExit;
        assert(!r16.r17TxConfigure(&c));
        assert(mbufDataCalls == d0 && mbufLenCalls == l0);
        assert(q16->blockSnap.nslot >= 4);
        assert(q16->blockSnap.slots[0].flags & r20tx::kHasMbuf);
        assert(q16->blockSnap.slots[0].mbufData == 1);   /* value only */
        assert(q16->blockSnap.slots[0].mbufLen == 0);    /* never read */
        r16.r17TxStop();
    }
    /* ---- concurrent mappings use independent driver records ----------------
     *
     * This is the round's core claim, so it is asserted as a set of facts rather
     * than one happy path:
     *   (a) every live record holds its own mbuf,
     *       IOMemoryDescriptor and IODMACommand;
     *   (b) their dynamically allocated IOVA ranges do not overlap;
     *   (c) each completes and retires INDEPENDENTLY, in a different order from
     *       the one they were mapped in, and the others stay valid meanwhile;
     *   (d) a freed slot is reused by the next generation;
     *   (e) after the batch every owner is back to zero.
     */
    {
        IOService o17; RTL8125 r17; IOTimerEventSource t17; IOMapper m17;
        stdMode = kStdOk;
        installMode(r17, o17, r17tx::kModeStandard, &m17);
        RTL8125::R17TxState *q17 = r17.r17Tx;

        const UInt32 N = r17tx::kSlots;
        mbuf_t ms[N];
        IOPhysicalSegment seg[N][1];
        UInt64 iova[N];
        const int md0 = stdMdCreated, cmd0 = stdCmdCreated;
        for (UInt32 i = 0; i < N; i++) {
            ms[i] = new Mbuf;
            ms[i]->token = 7; ms[i]->req = 1; ms[i]->len = 74;
            ms[i]->pa = 0x500000000ULL + (UInt64)i * 0x9000ULL + 0x2b6;
            seg[i][0] = {0, 0};
            UInt32 n = 0;
            assert(mapCall(r17, ms[i], seg[i], 1, &n));
            assert(n == 1);
            iova[i] = seg[i][0].location;
            submit(r17, ms[i], seg[i], 1); // real outputStart posts before next dequeue
        }
        /* All sixteen live records hold distinct standard objects. */
        assert(q17->held == N);
        assert(q17->maxHeld == N);
        assert(stdMdCreated == md0 + (int)N && stdCmdCreated == cmd0 + (int)N);
        assert(r17.r17TxLiveGens() == N);
        for (UInt32 i = 0; i < N; i++) {
            assert(q17->gens[i].state == r17tx::kSubmitted);
            assert(q17->gens[i].packet == ms[i]);
            assert(q17->gens[i].stdMD && q17->gens[i].stdCmd);
            assert(q17->gens[i].stdHandle != 0);
        }
        /* These one-page requests occupy disjoint pages, without a fixed
         * per-record stripe or gaps reserved for their unused capacity. */
        for (UInt32 i = 0; i < N; i++) {
            const UInt64 off = iova[i] - amdtx::kBase;
            assert(off < (UInt64)amdtx::kPages * 4096ULL);
            assert(off / 4096ULL == i);
            for (UInt32 j = 0; j < i; j++) {
                const UInt64 oi = iova[i] - amdtx::kBase;
                const UInt64 oj = iova[j] - amdtx::kBase;
                assert(oi / 4096ULL != oj / 4096ULL);
            }
        }
        /* The next packet stays in the interface queue, never dequeued/freed.
         * The timer alone must wake output after retiring ONE slot. */
        Mbuf extra; extra.pa = 0x600000000ULL + 0x2b6;
        IOPhysicalSegment se[1] = {{0, 0}};
        bool queued = true;
        const UInt32 drop0 = q17->dropped;
        auto output = [&]() {
            if (r17.r17TxOutputReady() && queued) {
                queued = false;
                assert(mapCall(r17, &extra, se, 1));
                submit(r17, &extra, se, 1);
            }
        };
        output();
        assert(queued && !extra.frees && q17->outputWaiting == 1);
        assert(q17->outputWaits == 1 && q17->dropped == drop0);
        retireTick(r17, &t17); // no completion: no spurious dequeue
        assert(queued && r17.interface.signals == 0);
        r17.txClosePtr0 = q17->gens[0].lastSlot;
        r17.r17TxComplete(q17->gens[0].lastSlot);
        const int u0 = stdUnmapCount;
        retireTick(r17, &t17); // deliberately ignore first wake (lost-edge test)
        assert(queued && r17.interface.signals == 1 && stdUnmapCount == u0 + 1);
        r17.interface.output = output;
        retireTick(r17, &t17); // repeated level wake automatically resumes output
        assert(!queued && !extra.frees && q17->outputWaiting == 0);
        assert(q17->outputResumes == 1 && q17->outputWakes == 2);
        assert(q17->held == N && ms[0]->frees == 1);
        for (UInt32 i = 1; i < N; i++) {
            assert(q17->gens[i].packet == ms[i] && !ms[i]->frees);
            assert(q17->gens[i].state == r17tx::kSubmitted);
            assert(q17->gens[i].stdCmd && q17->gens[i].stdHandle);
            assert(seg[i][0].location == iova[i]);
        }
        r17.interface.output = nullptr;
        /* (c) INDEPENDENT retirement. Complete and retire ONE generation at a
         * time in reverse order, and after each step assert that the others are
         * exactly as they were before it. That is the property this round adds:
         * one request's unmap+free must not disturb another's mapping.
         *
         * r17TxComplete() stamps every generation whose last descriptor the
         * close pointer has passed, so the harness advances the close pointer to
         * exactly the generation being retired -- otherwise it would be testing
         * a driver that had already completed several at once, which is a
         * different (and also interesting) case covered by the batch below. */
        for (UInt32 i = 0; i < N; i++) assert(q17->gens[i].state == r17tx::kSubmitted);
        /* (c3) the batch is retired by the driver's own rule: every generation
         * that is ready is completed and retired on the next tick. */
        {
            const int unmap0 = stdUnmapCount;
            for (UInt32 i = 0; i < N; i++) {
                r17.txClosePtr0 = q17->gens[i].lastSlot;
                r17.r17TxComplete(q17->gens[i].lastSlot);
            }
            const int pending = (int)q17->held;
            assert(pending == (int)N);
            retireTick(r17, &t17);
            /* exactly one unmap per generation: not N+1 (double unmap), not
             * fewer (an orphaned mapping) */
            assert(stdUnmapCount == unmap0 + (int)N);
            for (UInt32 i = 0; i < N; i++) {
                assert(q17->gens[i].state == r17tx::kIdle);
                assert(q17->gens[i].packet == NULL);
                assert(q17->gens[i].stdMD == NULL && q17->gens[i].stdCmd == NULL);
                assert(q17->gens[i].stdHandle == 0);
                assert(ms[i]->frees == 1);      /* freed once, exactly */
            }
        }
        /* Every packet freed once, no queued/pending owner remains. */
        assert(extra.frees == 1 && !queued && q17->outputWaiting == 0);
        assert(q17->dropped == drop0);
        assert(q17->held == 0);
        assert(r17.r17TxLiveGens() == 0);
        for (UInt32 i = 0; i < N; i++) {
            assert(q17->gens[i].state == r17tx::kIdle);
            assert(ms[i]->frees == 1);
        }

        /* Freed pages are reusable: two more one-page mappings reuse pages
         * zero and one rather than leaking address space. */
        {
            Mbuf a; a.token = 7; a.req = 1; a.len = 74;
            a.pa = 0x700000000ULL + 0x3b6;
            IOPhysicalSegment sa[1] = {{0, 0}};
            UInt32 na = 0;
            assert(mapCall(r17, &a, sa, 1, &na));
            assert((sa[0].location - amdtx::kBase) /
                   4096ULL == 0);
            Mbuf b; b.token = 7; b.req = 1; b.len = 74;
            b.pa = 0x700010000ULL + 0x4b6;
            IOPhysicalSegment sb[1] = {{0, 0}};
            UInt32 nb = 0;
            assert(mapCall(r17, &b, sb, 1, &nb));
            assert((sb[0].location - amdtx::kBase) /
                   4096ULL == 1);
            assert(q17->held == 2);
            submit(r17, &a, sa, 1);
            submit(r17, &b, sb, 1);
            r17.r17TxComplete(q17->gens[0].lastSlot);
            r17.r17TxComplete(q17->gens[1].lastSlot);
            retireTick(r17, &t17);
            assert(a.frees == 1 && b.frees == 1 && q17->held == 0);
        }
        auto c17 = control(r17tx::kDetach);
        assert(gateCfg(r17, true) == 0);
        assert(!r17.r17TxConfigure(&c17));       /* every owner returned */
        r17.r17TxStop();
        stdMode = kStdOk;
    }

    /* All 512 monotonic requests with the current live-record capacity and
     * timer-only resume; history wrap does not disturb other live mappings. */
    {
        IOService owner; RTL8125 d; IOTimerEventSource timer; IOMapper mapper;
        stdMode = kStdOk;
        installMode(d, owner, r17tx::kModeStandard, &mapper);
        auto *p = d.r17Tx;
        const UInt32 N = r17tx::kSlots;
        Mbuf packets[512];
        UInt32 next = 0;
        auto output = [&]() {
            while (next < 512 && d.r17TxOutputReady()) {
                auto *m = &packets[next];
                m->req = ++next;
                m->pa = 0x800000000ULL + (UInt64)next * 0x3000 + 0x2b6;
                IOPhysicalSegment seg[1] = {{0, 0}};
                assert(mapCall(d, m, seg, 1));
                submit(d, m, seg, 1);
            }
        };
        d.interface.output = output;
        output();
        assert(next == N && p->held == N && p->outputWaiting);
        while (p->retired < 512) {
            UInt32 oldest = 512;
            for (UInt32 i = 0; i < N; i++)
                if (p->gens[i].packet && p->gens[i].request.reqId < oldest + 1)
                    oldest = p->gens[i].request.reqId - 1;
            assert(oldest < 512 && !packets[oldest].frees);
            const UInt32 g = genOfPacket(d, &packets[oldest]);
            d.r17TxComplete(p->gens[g].lastSlot);
            retireTick(d, &timer); // no external output call: wake must refill
            assert(packets[oldest].frees == 1);
            assert(p->retired == oldest + 1);
            assert(p->held <= N);
            assert(p->held == (next - p->retired));
            for (UInt32 i = 0; i < N; i++) {
                auto &live = p->gens[i];
                if (!live.packet) continue;
                assert(!live.packet->frees && live.stdMD && live.stdCmd);
                assert(live.stdHandle && live.state == r17tx::kSubmitted);
                assert(live.request.reqId == live.packet->req);
            }
        }
        d.interface.output = nullptr;
        assert(next == 512 && p->mapped == 512 && p->completed == 512);
        assert(p->retired == 512 && p->stdUnmaps == 512 && p->held == 0);
        assert(p->maxHeld == N && !p->dropped && !p->rejected);
        assert(p->outputWakes > 32 && p->outputResumes > 32);
        assert(p->snapshot.count == 32 && p->snapshot.historyStart == 480);
        assert(p->stdSnap.count == 32 && p->stdSnap.historyTotal == 512);
        assert(p->stdSnap.historyStart == 480);
        assert(p->stdHighReqAccepts == 480 && p->stdSnap.highReqAccepts == 480);
        for (UInt32 seq = 480; seq < 512; seq++) {
            const auto &w = p->snapshot.witnesses[seq % 32];
            const auto &s = p->stdSnap.witnesses[seq % 32];
            assert(w.request.reqId == seq + 1 && w.retired && w.tFree);
            assert(s.req == seq + 1 && (s.flags & r18std::kUnmapped));
        }
        for (const auto &m : packets) assert(m.frees == 1);
        assert(!gateCfg(d, true));
        auto detach = control(r17tx::kDetach);
        assert(!d.r17TxConfigure(&detach));
        d.r17TxStop();
        printf("round32: 512 monotonic requests, 32-history wrap, sixteen-owner auto-resume passed\n");
    }

    /* Ordinary frames fill all sixteen live standard-map records. The next
     * stays in the interface queue until retirement wakes output, and a
     * completed Detach followed by Resume restores ordinary output. No packet
     * token/req is needed for admission; the old selector is diagnostic only. */
    {
        IOService owner; RTL8125 d; IOTimerEventSource timer; IOMapper mapper;
        stdMode = kStdOk;
        d.r17Tx = nullptr;
        auto config = control(r17tx::kInstall);
        config.bdf = 0x2500; config.token = 7; config.deadline = 100000000;
        config.callback = backend; config.context = &owner; config.owner = &owner;
        config.mode = r17tx::kModeAllStandard; config.mapper = &mapper;
        d.enableTSO4 = true;
        assert(d.r17TxConfigure(&config) == kIOReturnBadArgument);
        assert(!d.r17Tx && owner.refs == 1 && d.r17Admit == 0);
        d.enableTSO4 = false; d.enableTSO6 = true;
        assert(d.r17TxConfigure(&config) == kIOReturnBadArgument);
        assert(!d.r17Tx && owner.refs == 1 && d.r17Admit == 0);
        d.enableTSO6 = false;
        installMode(d, owner, r17tx::kModeAllStandard, &mapper);
        auto *p = d.r17Tx;
        const UInt32 N = r17tx::kSlots, total = N + 1;
        Mbuf packets[total];
        const UInt32 lengths[5] = {1514, 1024, 60, 74, 256};
        for (UInt32 i = 0; i < total; i++) {
            packets[i].len = lengths[i % 5];
            packets[i].pa = 0x900000000ULL + (UInt64)i * 0x3000 + 0x2b6;
            packets[i].parsed = false;
        }
        packets[0].parsed = false; // ordinary UDP/TCP/ARP has no parsed IOB1 tag
        packets[1].token = 0;
        packets[2].req = 0;
        packets[3].req = r17tx::kRequestLimit + 1;
        packets[N].parsed = true;
        packets[N].req = 42;       // legacy-selected, still gets the internal sequence
        const int coverBefore = coverCalls;
        const int directBefore = maps;
        UInt32 next = 0;
        auto output = [&]() {
            while (next < total && d.r17TxOutputReady()) {
                auto *m = &packets[next++];
                IOPhysicalSegment seg[1] = {{m->pa, m->len}};
                assert(mapCall(d, m, seg, 1));
                const UInt32 k = genOfPacket(d, m);
                assert(k < r17tx::kSlots && seg[0].location != m->pa);
                assert(p->gens[k].request.token == 7);
                assert(p->gens[k].request.reqId == next);
                assert(p->gens[k].stdW.req == next && p->gens[k].stdW.token == 7);
                submit(d, m, seg, 1);
            }
        };
        d.interface.output = output;
        output();
        assert(next == N && p->held == N && p->outputWaiting);
        assert(p->mapped == N && p->unmarked == N && p->legacySelected == 0);
        assert(!packets[N].frees && genOfPacket(d, &packets[N]) == r17tx::kSlots);
        for (UInt32 i = 0; i < total; i++) {
            const UInt32 k = genOfPacket(d, &packets[i]);
            assert(k < r17tx::kSlots);
            d.r17TxComplete(p->gens[k].lastSlot);
            retireTick(d, &timer); // first retirement admits the queued frame
            assert(packets[i].frees == 1 && p->held <= r17tx::kSlots);
        }
        d.interface.output = nullptr;
        assert(next == total && p->mapAttempts == total && p->mapped == total);
        assert(p->unmarked == N && p->legacySelected == 1);
        assert(p->completed == total && p->retired == total && p->stdUnmaps == total);
        assert(p->held == 0 && p->maxHeld == N && !p->dropped && !p->rejected);
        assert(p->stdSnap.mode == r17tx::kModeAllStandard);
        assert(p->stdSnap.count == total && p->stdSnap.historyTotal == total);
        assert(coverCalls == coverBefore && maps == directBefore);
        for (UInt32 seq = 0; seq < total; seq++) {
            assert(p->snapshot.witnesses[seq].request.reqId == seq + 1);
            assert(p->stdSnap.witnesses[seq].req == seq + 1);
        }
        /* An expired window fails closed even for unmarked traffic. */
        p->deadline = mach_absolute_time();
        Mbuf late; late.parsed = false;
        IOPhysicalSegment lateSeg[1] = {{late.pa, late.len}};
        assert(!mapCall(d, &late, lateSeg, 1) && late.frees == 1);
        assert(p->mapAttempts == total + 1 && p->mapped == total && p->rejected == 1);
        assert(coverCalls == coverBefore && maps == directBefore);
        d.txDirtyDescIndex = d.txNextDescIndex;
        assert(!detachCfg(d));
        assert(!p->enabled && !p->callback && owner.refs == 1);
        assert(d.r17Admit == 0x80000000u); // Detach does not open the gate
        assert(!gateCfg(d, false));       // backend has now restored the DTE
        Mbuf after; after.parsed = false;
        IOPhysicalSegment afterSeg[1] = {{after.pa, after.len}};
        assert(d.r17TxOutputReady());
        assert(mapCall(d, &after, afterSeg, 1));
        assert(afterSeg[0].location == after.pa && !after.frees && !p->held);
        assert(p->mapAttempts == total + 1 && p->mapped == total && p->unmarked == N);
        postOrdinary(d, &after);
        d.freePacket(&after); // ordinary ring ownership, no mapping retirement
        assert(!d.r17TxRefs() && coverCalls == coverBefore && maps == directBefore);
        d.r17TxStop();
        printf("round32: ordinary all-standard TX, sixteen-owner resume, detach output passed\n");
    }

    /* Round29: an empty hardware ring is not an empty driver. The real
     * completion path still owns one generation until the timer completes the
     * standard command AND reads its backend-confirmed retirement record. */
    {
        IOService owner; RTL8125 d; IOTimerEventSource timer; IOMapper mapper;
        installMode(d, owner, r17tx::kModeAllStandard, &mapper);
        auto *p = d.r17Tx;
        Mbuf m; m.parsed = false;
        IOPhysicalSegment seg[1] = {{m.pa, m.len}};
        const int complete0 = stdCompleteCalls, ack0 = stdAckCalls;
        assert(mapCall(d, &m, seg, 1));
        auto *g = &p->gens[genOfPacket(d, &m)];
        const UInt64 handle = g->stdHandle;
        assert(handle && !g->request.handle); // ack must use the mapper stamp
        submit(d, &m, seg, 1);
        d.r17TxComplete(g->lastSlot);
        d.txDirtyDescIndex = d.txNextDescIndex;
        auto close = control(r17tx::kQuiesce);
        assert(!d.r17TxConfigure(&close));
        assert(!close.inFlight && !close.ringOwn && !close.activeCover);
        assert(close.held == 1 && close.modeReserved == 1);
        assert(close.mapped == 1 && close.completed == 1 && !close.retired);
        assert(g->state == r17tx::kPending && !g->stdCompleteAttempted);
        assert(!m.frees && stdCompleteCalls == complete0 && stdAckCalls == ack0);
        retireTick(d, &timer);
        assert(stdCompleteCalls == complete0 + 1 && stdAckCalls == ack0 + 1);
        assert(m.frees == 1 && p->retired == 1 && p->stdUnmaps == 1);
        assert(g->request.tRetire == stdConfirmedRetires.at(handle));
        assert(g->request.tRetire < m.freedAt && !g->stdMD && !g->stdCmd);
        assert(!d.r17TxConfigure(&close));
        assert(!close.held && !close.modeReserved && close.mapped == close.retired);
        assert(!detachCfg(d));
        d.r17TxStop();
    }

    printf("round29: ring drained before acknowledged timer retirement passed\n");

    /* Round31: zero deadline keeps real all-standard mapping active across
     * the old 120-second limit. Explicit stop still retires before Disarm. */
    {
        IOService owner; RTL8125 d; IOTimerEventSource timer; IOMapper mapper;
        installMode(d, owner, r17tx::kModeAllStandard, &mapper, 0);
        auto *p = d.r17Tx;
        const UInt64 started = mach_absolute_time();
        for (unsigned phase = 0; phase < 2; phase++) {
            if (phase) ticks += 125000000000ULL;
            Mbuf m; m.parsed = false;
            IOPhysicalSegment seg[1] = {{m.pa, m.len}};
            assert(mapCall(d, &m, seg, 1));
            const UInt32 k = genOfPacket(d, &m);
            assert(k < r17tx::kSlots && seg[0].location != m.pa);
            submit(d, &m, seg, 1);
            d.r17TxComplete(p->gens[k].lastSlot);
            retireTick(d, &timer);
            assert(m.frees == 1 && !p->held);
        }
        assert(mach_absolute_time() - started > 120000000000ULL);
        assert(!p->deadline && p->mapped == 2 && p->completed == 2);
        assert(p->retired == 2 && p->stdUnmaps == 2 && !p->rejected);
        assert(!d.r17TxLiveGens());
        d.txDirtyDescIndex = d.txNextDescIndex;
        assert(!gateCfg(d, true));
        auto stop = control(r17tx::kDisarm);
        assert(!d.r17TxConfigure(&stop) && !p->enabled);
        assert(!detachCfg(d) && owner.refs == 1 && !p->callback);
        assert(!gateCfg(d, false));
        d.r17TxStop();
    }
    printf("round31: active all-standard session beyond 120s, retire/Disarm/Detach passed\n");

    /* Round32: table transitions stop dequeue, preserving an ordinary queued
     * frame. Resume wakes it both inside the mapping session and after Detach.
     * Exercise the actual dequeue/admission/map/Posted methods used by the
     * generated outputStart rather than the old already-dequeued wrapper. */
    {
        IOService owner; RTL8125 d; IOTimerEventSource timer; IOMapper mapper;
        installMode(d, owner, r17tx::kModeAllStandard, &mapper, 0);
        auto *p = d.r17Tx;
        Mbuf mapped, ordinary;
        mapped.parsed = ordinary.parsed = false;
        auto output = [&]() {
            mbuf_t m = nullptr;
            while (d.r32TxDequeue(&d.interface, &m)) {
                RTL8125::R32TxAdmission admission(&d);
                assert(d.r17TxRefs() == 1);
                IOPhysicalSegment seg[1] = {{m->pa, m->len}};
                UInt32 count = 1;
                assert(d.r17TxMapAdmitted(m, seg, count));
                const UInt32 k = genOfPacket(d, m);
                admission.handoff();
                if (k < r17tx::kSlots) {
                    assert(seg[0].location != m->pa);
                    submit(d, m, seg, count);
                } else {
                    assert(seg[0].location == m->pa);
                    postOrdinary(d, m);
                    d.freePacket(m);
                }
            }
        };
        d.interface.output = output;
        assert(!gateCfg(d, true));
        d.interface.queued = &mapped;
        output();
        assert(d.interface.queued == &mapped && !d.interface.dequeues);
        assert(!mapped.frees && !d.r17TxRefs() && p->outputWaiting);
        assert(!p->mapAttempts && !p->rejected && !p->barrierFails);
        const unsigned wakes = d.interface.signals;
        assert(!gateCfg(d, false));
        assert(d.interface.signals == wakes + 1 && d.interface.dequeues == 1);
        assert(!d.interface.queued && !d.r17TxRefs() && p->mapped == 1);
        const UInt32 k = genOfPacket(d, &mapped);
        assert(k < r17tx::kSlots);
        d.r17TxComplete(p->gens[k].lastSlot);
        retireTick(d, &timer);
        assert(mapped.frees == 1 && !p->held && !IODMACommand::arena.livePages);
        d.txDirtyDescIndex = d.txNextDescIndex;
        assert(!gateCfg(d, true));
        d.interface.queued = &ordinary;
        output();
        assert(d.interface.queued == &ordinary && d.interface.dequeues == 1);
        assert(!ordinary.frees && !d.r17TxRefs());
        assert(!detachCfg(d) && !p->callback && !p->enabled);
        assert(!gateCfg(d, false));
        assert(d.interface.dequeues == 2 && !d.interface.queued && ordinary.frees == 1);
        assert(!d.r17TxRefs() && p->mapAttempts == 1 && p->mapped == 1);
        assert(!p->rejected && !p->barrierFails && !p->coverCalls && !p->coverRejects);
        d.interface.output = nullptr;
        d.r17TxStop();
    }
    printf("round32: queued TX survives quiesce, resumes mapped and detached, no rejection passed\n");

    printf("round21 window-edge tests: gate calls=%u fails=%u samples=%u\n",
           harnessGateCalls, harnessGateFails, lastSampleSeq);
    printf("round23 multi-generation TX tests: slots=%u\n", (unsigned)r17tx::kSlots);
    printf("round20 standard-mapper TX driver tests passed "
           "(direct maps=%d retires=%d; std accepts/prepares/unmaps=%d/%d/%d; "
           "cover calls=%d)\n",
           maps, retires, stdMode, stdPrepareCalls, stdUnmapCount, coverCalls);
    return 0;
}
