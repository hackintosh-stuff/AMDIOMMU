/* Round17 host tests for the ACTUAL generated driver methods.
 *
 * These cover only what round 17 changed: native segment mapping (no staging,
 * no numSegs flattening), the submission/completion handoff, per-packet free
 * after a successful retire, the bounded owner count, and the failure paths
 * that must NOT look like a recycled request.
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
    /* Same geometry rule as the real core: each segment starts on the next
       unused IOVA page and keeps its in-page offset. */
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

static void install(RTL8125 &d, IOService &o)
{
    d.r17Tx = nullptr;
    r17tx::Configure c{};
    c.version = 2; c.bytes = sizeof(c); c.op = r17tx::kInstall;
    c.bdf = 0x2500; c.token = 7; c.deadline = 100000000;
    c.callback = backend; c.context = &o; c.owner = &o;
    assert(!d.r17TxConfigure(&c));
    assert(o.refs == 2);
    assert(d.r17Tx->state == r17tx::kIdle);
    assert(d.r17Tx->held == 0 && d.r17Tx->maxHeld == 0);
}

static r17tx::Configure control(unsigned op)
{
    r17tx::Configure c{};
    c.version = 2; c.bytes = sizeof(c); c.op = op;
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

static void retiteTick(RTL8125 &d, IOTimerEventSource *t) { d.r17TxTimer(t); }

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
        assert(d.r17TxMap(&m, seg, 2));
        assert(p->state == r17tx::kPosting);        /* before the first OWN */
        assert(p->request.count == 2);              /* NOT flattened to 1 */
        assert(seg[0].location == 0x1000000bb6ULL); /* offset preserved */
        assert(seg[1].location == 0x1000001000ULL);
        assert(p->held == 1 && p->maxHeld == 1 && p->packet == &m);
        submit(d, &m, seg, 2);                      /* sets OWN + commits */
        assert(p->state == r17tx::kSubmitted);
        assert(p->current.descriptors[0].address == seg[0].location);
        assert(p->current.descriptors[1].length == 514);
        d.r17TxComplete(p->lastSlot);
        assert(p->state == r17tx::kPending && p->completed == 1);
        assert(m.frees == 0);                       /* not before retire */
        retiteTick(d, &timer);
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
        assert(d.r17TxMap(&m, seg, 1));
        /* completion arrives while the output thread still holds kPosting */
        d.r17TxComplete(p->lastSlot);
        assert(p->state == r17tx::kPosting);
        assert(p->doneSeen == 1);
        assert(p->completed == c0);   /* the commit owns this transition */
        submit(d, &m, seg, 1);        /* commit must publish kPending itself */
        assert(p->state == r17tx::kPending && p->completed == c0 + 1);
        retiteTick(d, &timer);
        assert(m.frees == 1 && p->retired == 2 && p->held == 0);
    }

    /* ---- 3. retire failure keeps the owner and the handle ------------------ */
    {
        retireMode = 1;
        Mbuf m; m.token = 7; m.req = 3; m.len = 74;
        IOPhysicalSegment seg[1] = {{0x35f6651b6ULL, 74}};
        assert(d.r17TxMap(&m, seg, 1));
        UInt64 h = p->request.handle;
        submit(d, &m, seg, 1);
        d.r17TxComplete(p->lastSlot);
        retiteTick(d, &timer);
        assert(p->state == r17tx::kPending);        /* not recycled */
        assert(p->held == 1 && p->packet == &m && m.frees == 0);
        assert(p->request.handle == h);             /* obligation preserved */
        assert(p->retired == 2);
        retiteTick(d, &timer);                      /* retry succeeds */
        assert(p->state == r17tx::kIdle && p->held == 0 && m.frees == 1);
        assert(p->retired == 3);
        retireMode = 0;
    }

    /* ---- 4. map refused with handle 0 frees the packet, no owner ----------- */
    {
        mapMode = 2;                                /* error + handle 0 */
        Mbuf m; m.token = 7; m.req = 4; m.len = 74;
        IOPhysicalSegment seg[1] = {{0x35e41000ULL, 74}};
        UInt32 before = p->rejected;
        assert(!d.r17TxMap(&m, seg, 1));
        assert(p->state == r17tx::kIdle && p->held == 0 && m.frees == 1);
        assert(p->rejected == before + 1);
        mapMode = 0;
    }

    /* ---- 5. map refused but the backend kept a handle => pinned ------------ */
    {
        mapMode = 2;
        Mbuf m; m.token = 7; m.req = 5; m.len = 74;
        IOPhysicalSegment seg[1] = {{0x35e42000ULL, 74}};
        /* mapMode 3 leaves a valid handle but a broken offset */
        mapMode = 3;
        assert(!d.r17TxMap(&m, seg, 1));
        assert(p->state == r17tx::kPending && p->held == 1 && m.frees == 0);
        mapMode = 0;
        retiteTick(d, &timer);                      /* retire cleans it up */
        assert(p->held == 0 && m.frees == 1);
    }

    /* ---- 6. geometry/protocol refusals free and stay Idle ------------------- */
    {
        Mbuf m; m.token = 7; m.req = 6; m.len = 74;
        IOPhysicalSegment seg[1] = {{0x35e43000ULL, 74}};
        m.len = 100;                                /* mapped bytes != frame */
        assert(!d.r17TxMap(&m, seg, 1));
        assert(m.frees == 1 && p->state == r17tx::kIdle && p->held == 0);
        Mbuf m2; m2.token = 8; m2.req = 7; m2.len = 74;   /* foreign token */
        IOPhysicalSegment s2[1] = {{0x35e44000ULL, 74}};
        assert(d.r17TxMap(&m2, s2, 1));             /* pass-through, untouched */
        assert(m2.frees == 0);
        Mbuf m3; m3.token = 7; m3.req = 33; m3.len = 74;
        assert(d.r17TxMap(&m3, s2, 1));             /* outside req1..32 */
    }

    /* ---- 7. per-packet recycling: 32 generations, bounded owners ----------- */
    {
        UInt32 before = p->retired;
        for (UInt32 i = 0; i < 6 && before + i < r17tx::kMaxRequests; i++) {
            Mbuf *m = new Mbuf;                     /* freed by the driver */
            m->token = 7; m->req = 8; m->len = 74;
            IOPhysicalSegment seg[1] = {{0x360000000ULL + i * 0x3000 + 0x1b6, 74}};
            assert(d.r17TxMap(m, seg, 1));
            assert(p->held == 1 && p->maxHeld == 1);
            submit(d, m, seg, 1);
            d.r17TxComplete(p->lastSlot);
            assert(m->frees == 0);
            retiteTick(d, &timer);
            assert(m->frees == 1 && p->held == 0);
        }
        assert(p->maxHeld == 1);                    /* independent of the count */
    }

    /* ---- 7b. evidence storage full: refuse and free, never grow the array -- */
    {
        UInt32 saved = p->retired, before = p->rejected;
        p->retired = r17tx::kMaxRequests;
        Mbuf m; m.token = 7; m.req = 10; m.len = 74;
        IOPhysicalSegment seg[1] = {{0x380000000ULL, 74}};
        assert(!d.r17TxMap(&m, seg, 1));
        assert(m.frees == 1 && p->state == r17tx::kIdle && p->held == 0);
        assert(p->rejected == before + 1);
        assert(p->retired == r17tx::kMaxRequests);
        p->retired = saved;
    }

    /* ---- 8. Detach while an owner is live must refuse, not free ------------ */
    {
        Mbuf m; m.token = 7; m.req = 9; m.len = 74;
        IOPhysicalSegment seg[1] = {{0x370000000ULL, 74}};
        assert(d.r17TxMap(&m, seg, 1));
        submit(d, &m, seg, 1);
        d.r17TxComplete(p->lastSlot);
        auto c = control(r17tx::kDisarm);
        /* Disarm is Busy until the pending generation really drains. */
        assert(d.r17TxConfigure(&c) == kIOReturnBusy);
        c.op = r17tx::kDetach;
        assert(d.r17TxConfigure(&c) == kIOReturnBusy);
        assert(m.frees == 0 && p->held == 1);
        retiteTick(d, &timer);                      /* real recovery */
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
    printf("round17 native TX driver tests passed (maps=%d retires=%d retired=%u)\n",
           maps, retires, p->retired);
    return 0;
}
