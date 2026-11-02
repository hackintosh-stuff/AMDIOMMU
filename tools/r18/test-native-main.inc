/* Round18 host tests for the ACTUAL generated driver methods.
 *
 * The round-17 cases are kept as-is (direct platform-call mode) because that
 * path must not regress. On top of them this covers what round 18 adds:
 *   * the standard path: packet -> IOMemoryDescriptor -> IODMACommand on the
 *     probe's mapper -> IOVA from gen64IOVMSegments -> descriptor -> complete();
 *   * the refusals: multi-mbuf frame, prepare failure with and without a
 *     published mapping, a command that cannot express one run, and an identity
 *     result (never accepted);
 *   * the timer harvest obeying the driver's own __POLLING exclusion.
 */

static int mapMode = 0;      /* 0 ok, 1 fail-no-handle, 2 fail-then-handle, 3 bad iova */
static int retireMode = 0;   /* 0 ok, 1 fail once, 2 fail always */
static int maps = 0, retires = 0, retireFails = 0;
static UInt64 handleSeq = 0;

static IOReturn backend(void *, uint32_t op, r17tx::Request *r)
{
    if (op == r17tx::kRetire) {
        retires++;
        if (retireMode == 1 && retireFails == 0) { retireFails++; return 88; }
        if (retireMode == 2) return 88;
        r->tRetire = mach_absolute_time();
        return 0;
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

static void installMode(RTL8125 &d, IOService &o, UInt32 mode, IOMapper *mapper)
{
    d.r17Tx = nullptr;
    r17tx::Configure c{};
    c.version = r17tx::kVersion; c.bytes = sizeof(c); c.op = r17tx::kInstall;
    c.bdf = 0x2500; c.token = 7; c.deadline = 100000000;
    c.callback = backend; c.context = &o; c.owner = &o;
    c.mode = mode; c.mapper = mapper;
    assert(!d.r17TxConfigure(&c));
    assert(o.refs == 2);
    assert(d.r17Tx->state == r17tx::kIdle);
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

/* Fill the descriptor slots exactly as outputStart's loop does, then commit. */
static void submit(RTL8125 &d, mbuf_t m, IOPhysicalSegment *segs, UInt32 n)
{
    UInt32 index = d.txNextDescIndex;
    d.txNextDescIndex = (d.txNextDescIndex + n) & kTxDescMask;
    for (UInt32 i = 0; i < n; i++) {
        RtlTxDesc *desc = &d.txDescArray[index];
        UInt32 opts1 = (UInt32)segs[i].length | (i == 0 ? 0x10000000u : 0x80000000u);
        if (i == n - 1) opts1 |= 0x20000000u;
        desc->addr = segs[i].location;
        desc->opts1 = opts1;
        desc->opts2 = 0;
        index = (index + 1) & kTxDescMask;
    }
    d.txDescArray[d.r17Tx->current.firstSlot].opts1 |= 0x80000000u;
    d.r17TxPosted(m);
}

static void retireTick(RTL8125 &d, IOTimerEventSource *t) { d.r17TxTimer(t); }

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
    assert(p->state == r17tx::kPosting);
    assert(seg[0].location == 0x1000000000ULL + (pa & 4095ULL));
    assert(seg[0].location != pa);                     /* non-identity */
    assert(p->request.count == 1);
    assert(p->request.physical[0].address == pa);      /* real packet PA */
    assert(p->stdHandle == stdLastHandle && p->stdHandle);
    assert(p->stdW.handle == p->stdHandle);   /* stamped, never inferred */
    assert(p->stdMD && p->stdCmd);
    assert(p->stdW.flags & r18std::kMapped);
    submit(d, &m, seg, 1);
    assert(p->state == r17tx::kSubmitted);
    assert(p->current.descriptors[0].address == seg[0].location);
    assert(p->stdW.tCommit == p->current.tOwn);
    d.r17TxComplete(p->lastSlot);
    assert(p->state == r17tx::kPending && m.frees == 0);
    const int unmapsBefore = stdUnmapCount;
    retireTick(d, &timer);
    assert(stdUnmapCount == unmapsBefore + 1);         /* complete() ran */
    assert(m.frees == 1);
    assert(!p->stdMD && !p->stdCmd);                   /* objects released */
    assert(p->stdHandle == 0 && p->held == 0);
    assert(p->state == r17tx::kIdle);
    assert(p->stdW.flags & r18std::kUnmapped);
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
        assert(p->state == r17tx::kPosting);
        assert(p->request.count == 2);              /* NOT flattened to 1 */
        assert(seg[0].location == 0x1000000bb6ULL); /* offset preserved */
        assert(seg[1].location == 0x1000001000ULL);
        assert(p->held == 1 && p->maxHeld == 1 && p->packet == &m);
        submit(d, &m, seg, 2);
        assert(p->state == r17tx::kSubmitted);
        assert(p->current.descriptors[0].address == seg[0].location);
        assert(p->current.descriptors[1].length == 514);
        d.r17TxComplete(p->lastSlot);
        assert(p->state == r17tx::kPending && p->completed == 1);
        assert(m.frees == 0);
        retireTick(d, &timer);
        assert(m.frees == 1);
        assert(p->held == 0 && p->retired == 1);
        assert(p->snapshot.witnesses[0].tFree >= p->snapshot.witnesses[0].request.tRetire);
        assert(p->state == r17tx::kIdle);
    }

    /* ---- 2. fast completion before the commit step ------------------------- */
    {
        UInt32 c0 = p->completed;
        Mbuf m; m.token = 7; m.req = 2; m.len = 74;
        IOPhysicalSegment seg[1] = {{0x3c57d63b6ULL, 74}};
        assert(mapCall(d, &m, seg, 1));
        d.r17TxComplete(p->lastSlot);
        assert(p->state == r17tx::kPosting);
        assert(p->doneSeen == 1);
        assert(p->completed == c0);
        submit(d, &m, seg, 1);
        assert(p->state == r17tx::kPending && p->completed == c0 + 1);
        retireTick(d, &timer);
        assert(m.frees == 1 && p->retired == 2 && p->held == 0);
    }

    /* ---- 3. retire failure keeps the owner and the handle ------------------ */
    {
        retireMode = 1;
        Mbuf m; m.token = 7; m.req = 3; m.len = 74;
        IOPhysicalSegment seg[1] = {{0x35f6651b6ULL, 74}};
        assert(mapCall(d, &m, seg, 1));
        UInt64 h = p->request.handle;
        submit(d, &m, seg, 1);
        d.r17TxComplete(p->lastSlot);
        retireTick(d, &timer);
        assert(p->state == r17tx::kPending);
        assert(p->held == 1 && p->packet == &m && m.frees == 0);
        assert(p->request.handle == h);
        assert(p->retired == 2);
        retireTick(d, &timer);
        assert(p->state == r17tx::kIdle && p->held == 0 && m.frees == 1);
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
        assert(p->state == r17tx::kIdle && p->held == 0 && m.frees == 1);
        assert(p->rejected == before + 1);
        mapMode = 0;
    }

    /* ---- 5. map refused but the backend kept a handle => pinned ------------ */
    {
        mapMode = 3;
        Mbuf m; m.token = 7; m.req = 5; m.len = 74;
        IOPhysicalSegment seg[1] = {{0x35e42000ULL, 74}};
        assert(!mapCall(d, &m, seg, 1));
        assert(p->state == r17tx::kPending && p->held == 1 && m.frees == 0);
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
        assert(m.frees == 1 && p->state == r17tx::kIdle && p->held == 0);
        Mbuf m2; m2.token = 8; m2.req = 7; m2.len = 74;
        IOPhysicalSegment s2[1] = {{0x35e44000ULL, 74}};
        assert(mapCall(d, &m2, s2, 1));
        assert(m2.frees == 0);
        Mbuf m3; m3.token = 7; m3.req = 33; m3.len = 74;
        assert(mapCall(d, &m3, s2, 1));
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
            d.r17TxComplete(p->lastSlot);
            assert(m->frees == 0);
            retireTick(d, &timer);
            assert(m->frees == 1 && p->held == 0);
        }
        assert(p->maxHeld == 1);
    }

    /* ---- 7b. evidence storage full: refuse and free, never grow the array -- */
    {
        UInt32 saved = p->retired, before = p->rejected;
        p->retired = r17tx::kMaxRequests;
        Mbuf m; m.token = 7; m.req = 10; m.len = 74;
        IOPhysicalSegment seg[1] = {{0x380000000ULL, 74}};
        assert(!mapCall(d, &m, seg, 1));
        assert(m.frees == 1 && p->state == r17tx::kIdle && p->held == 0);
        assert(p->rejected == before + 1);
        assert(p->retired == r17tx::kMaxRequests);
        p->retired = saved;
    }

    /* ---- 8. Detach while an owner is live must refuse, not free ------------ */
    {
        Mbuf m; m.token = 7; m.req = 9; m.len = 74;
        IOPhysicalSegment seg[1] = {{0x370000000ULL, 74}};
        assert(mapCall(d, &m, seg, 1));
        submit(d, &m, seg, 1);
        d.r17TxComplete(p->lastSlot);
        auto c = control(r17tx::kDisarm);
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
        assert(!d.r17TxConfigure(&c));
        assert(owner.refs == 1);
        assert(p->state == r17tx::kIdle && p->held == 0);
        assert(p->snapshot.count == 0 || p->snapshot.count == p->retired);
    }
    d.r17TxStop();

    /* ==================== round 18: timer harvest exclusion ================= */
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
        assert(q->state == r17tx::kSubmitted);
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
        d2.r17TxComplete(q->lastSlot);
        retireTick(d2, &t2);
        assert(m.frees == 1 && q->retired == 1 && q->held == 0);
        auto c = control(r17tx::kDetach);
        assert(!d2.r17TxConfigure(&c));
        d2.r17TxStop();
    }

    /* ==================== round 18: standard mapper path =================== */
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
               0x1000000000ULL + (0x3c57d63b6ULL & 4095ULL));
        stdRoundTrip(s, o3, t3, 13, 0x35e41000ULL, 162);
        assert(q->stdAccepts == 2 && q->stdUnmaps == 2);

        /* (2) unsupported layout: two mbufs. Refused BEFORE prepare(). */
        {
            int prep0 = stdPrepareCalls, cmd1 = stdCmdCreated;
            Mbuf head; head.token = 7; head.req = 14; head.len = 42;
            Mbuf tail; tail.token = 7; tail.req = 14; tail.len = 1472;
            head.next = &tail;
            IOPhysicalSegment seg[1] = {{0, 0}};
            UInt32 before = q->stdUnsupported;
            assert(!mapCall(s, &head, seg, 1));
            assert(q->stdUnsupported == before + 1);
            assert(stdPrepareCalls == prep0);        /* no command was prepared */
            assert(stdCmdCreated == cmd1);
            assert(head.frees == 1 && q->held == 0 && q->state == r17tx::kIdle);
        }

        /* (3) prepare fails with nothing published: free, stay Idle */
        {
            stdMode = kStdRefuseNoHandle;
            Mbuf m; m.token = 7; m.req = 15; m.len = 74; m.pa = 0x3a0000000ULL + 0x3b6;
            IOPhysicalSegment seg[1] = {{0, 0}};
            UInt32 before = q->stdRejects;
            assert(!mapCall(s, &m, seg, 1));
            assert(q->stdRejects == before + 1);
            assert(m.frees == 1 && q->held == 0 && q->state == r17tx::kIdle);
            assert(!q->stdCmd && !q->stdMD);
            stdMode = kStdOk;
        }

        /* (4) the command cannot express one run: unmap through the API, refuse */
        {
            stdMode = kStdTwoSegments;
            const int unmaps0 = stdUnmapCount, cmd2 = stdCmdCreated;
            Mbuf m; m.token = 7; m.req = 16; m.len = 1472; m.pa = 0x3b0000000ULL + 0x5d2;
            IOPhysicalSegment seg[1] = {{0, 0}};
            assert(!mapCall(s, &m, seg, 1));
            assert(stdUnmapCount == unmaps0 + 1);    /* no half-mapped command */
            assert(m.frees == 1 && q->held == 0 && q->state == r17tx::kIdle);
            assert(stdCmdCreated == cmd2 + 1 && !q->stdCmd && !q->stdMD);
            stdMode = kStdOk;
        }

        /* (5) an identity result is NEVER accepted as a mapping */
        {
            stdMode = kStdIdentity;
            Mbuf m; m.token = 7; m.req = 17; m.len = 74; m.pa = 0x3c0000000ULL + 0x1b6;
            IOPhysicalSegment seg[1] = {{0, 0}};
            assert(!mapCall(s, &m, seg, 1));
            assert(m.frees == 1 && q->held == 0 && q->state == r17tx::kIdle);
            assert(q->stdW.flags & r18std::kIdentity);
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
            s.r17TxComplete(q->lastSlot);
            UInt32 pinned0 = q->stdPinned;
            retireTick(s, &t3);
            assert(q->stdPinned == pinned0 + 1);
            assert(m.frees == 0 && q->held == 1 && q->packet == &m);
            assert(q->state == r17tx::kPending);
            assert(q->stdCmd && q->stdMD);            /* obligation preserved */
            auto c = control(r17tx::kDetach);
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
        assert(q4->stdW.flags & r18std::kIdentity);
        assert(q4->stdW.completeResult == 0);              /* unmap confirmed */
        assert(stdMdCreated == md1 + 1 && stdCmdCreated == cmd3 + 1);
        /* exactly one md/cmd is still held -- by case (6)'s pinned generation */
        assert(stdMdReleased == stdMdCreated - 1 && stdCmdReleased == stdCmdCreated - 1);
        assert(!q4->stdCmd && !q4->stdMD && q4->stdHandle == 0);
        assert(m1.frees == 1 && q4->held == 0 && q4->state == r17tx::kIdle);
        {
            auto c = control(r17tx::kDetach);
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
            assert(q5->stdW.flags & r18std::kPinned);
            assert((int)q5->stdW.completeResult != 0);
            assert(m2.frees == 0 && q5->packet == &m2 && q5->held == 1);
            assert(q5->stdCmd && q5->stdMD && q5->stdHandle != 0);
            assert(q5->state == r17tx::kPending);
            auto c = control(r17tx::kDetach);
            assert(z.r17TxConfigure(&c) == kIOReturnBusy);
            z.r17TxStop();
            stdMode = kStdOk;
            stdUnmapFails = 0;
        }
    }

    printf("round18 standard-mapper TX driver tests passed "
           "(direct maps=%d retires=%d; std accepts/prepares/unmaps=%d/%d/%d)\n",
           maps, retires, stdMode, stdPrepareCalls, stdUnmapCount);
    return 0;
}
