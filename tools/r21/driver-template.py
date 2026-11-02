"""Round20 generator templates (standard IOMapper/IODMACommand TX path).

Loaded by tools/apply-lucy-obs2.py, not by any kext. Every body below is
compiled into the real driver by text substitution, so the host test that
exercises these exact functions (tools/r20/test-driver.py) is testing the
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
    mode = kModeAllStandard -> the same standard path for every packet admitted
                              during the finite window. Packet token/req fields
                              are diagnostic only; req is an internal sequence.

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
    /* Round23: one generation record per window slot. Declared here because the
     * helpers below take it, and defined with R17TxState so a gen's state and
     * its objects are always travelled together. */
    struct R17Gen;
    /* ---- round 22: the submission barrier -------------------------------
     * ONE word, valid for the whole driver lifetime (not only while a window
     * is installed), because the race it closes exists BEFORE Install too: an
     * output thread that read "no backend" is already inside outputStart and
     * has not written its OWN bit yet.
     *
     *   bit 31      closed
     *   bits 0..30  admitted submissions that have not set OWN yet
     *
     * Admission is a CAS on this word, so "the gate is open" and "I am counted"
     * are one indivisible step; leaving is the matching decrement after OWN.
     * 0 is the normal state: open, nothing in flight. */
    volatile UInt32 r17Admit = 0;
    IOReturn r17TxConfigure(r17tx::Configure *c);
    bool r17TxEnter();
    void r17TxLeave();
    UInt32 r17TxRefs();
    UInt32 r17TxRingOwn();
    bool r17TxOutputReady();
    void r17TxWakeOutput();
    bool r17TxMap(mbuf_t m, IOPhysicalSegment *segments, UInt32 &count);
    bool r17TxMapAdmitted(mbuf_t m, IOPhysicalSegment *segments, UInt32 &count);
    bool r17TxMapDirect(R17TxState *p, R17Gen *g, mbuf_t m,
                        IOPhysicalSegment *segments, UInt32 &count);
    bool r17TxMapStd(R17TxState *p, R17Gen *g, mbuf_t m,
                     IOPhysicalSegment *segments, UInt32 &count);
    IOReturn r17TxStdComplete(R17TxState *p, R17Gen *g);
    bool r17TxStdRollback(R17TxState *p, R17Gen *g, mbuf_t m);
    bool r17TxCover(R17TxState *p, IOPhysicalSegment *segments, UInt32 count);
    void r17TxRetire(R17TxState *p, R17Gen *g, UInt64 handle);
    UInt64 r17TxStdMark();
    void r17TxPosted(mbuf_t m);
    void r17TxComplete(UInt32 slot);
    R17Gen *r17TxFindByPacket(R17TxState *p, mbuf_t m);
    R17Gen *r17txNewestLive(R17TxState *p);
    UInt32 r17TxLiveGens();
    void r17TxPublish();
    void r17TxPublishBlock();
    void r17TxSample(UInt32 stage);
    UInt32 r17TxOutstanding();
    IOReturn r17TxGate(bool quiesce);
    void r17TxReport(r17tx::Configure *c);
    void r17TxTimer(IOTimerEventSource *timer);
    void r17TxStop();
'''
METHODS = r'''
#pragma mark --- round 17 native TX mapping, per-packet recycling ---
/* ROUND 23: ONE RECORD PER LIVE REQUEST, NOT ONE PER DRIVER.
 *
 * Rounds 17..22 kept the mapping of "the generation" in R17TxState itself, which
 * was correct only because the driver never had two at once: Map refused while
 * `packet` was set, so there was exactly one packet, one IODMACommand, one
 * IOMemoryDescriptor and one witness. That single-owner assumption is embedded
 * in the code as "the" packet (`p->packet`), "the" handle (`p->stdHandle`) and
 * "the" slot (`p->lastSlot`), and every one of those becomes wrong the moment a
 * second frame is mapped before the first is retired -- which is what this round
 * asks for.
 *
 * So the per-request objects move into R17Gen, one entry per window slot, and
 * the driver keeps r17tx::kSlots of them. A generation is identified by its own
 * pointer from Map through Submit, Complete and Retire; nothing is inferred from
 * "the only one there can be".
 *
 * A gen's lifecycle is the same state machine as before, per slot:
 *   kIdle -> kMapping -> kPosting -> kSubmitted -> kPending -> kRetiring -> kIdle
 * so the completion handoff (doneSeen) and the "descriptors being recorded"
 * guard (kPosting) still hold -- now independently for each live request. */
struct RTL8125::R17Gen {
    volatile UInt32 state;
    volatile UInt32 doneSeen;
    UInt32 index;               /* gen slot, for witnesses and diagnostics */
    mbuf_t packet;              /* the one mbuf whose PHYSICAL bytes are mapped */
    UInt32 firstSlot, lastSlot; /* ring descriptors this generation occupies */
    IOMemoryDescriptor *stdMD;
    IODMACommand *stdCmd;
    bool stdWired;
    bool stdCompleteAttempted; /* complete() may discard failed unmap bookkeeping */
    IOReturn stdRetireResult;  /* API result plus per-handle backend confirmation */
    UInt64 stdHandle;           /* probe handle, 0 until one is published */
    r17tx::Request request;
    r17tx::Witness current;
    r18std::Witness stdW;
};
struct RTL8125::R17TxState {
    UInt32 token, bdf;
    UInt64 deadline;
    r17tx::Callback callback;
    void *context;
    IOService *owner;
    IOTimerEventSource *timer;
    bool enabled;
    /* Round23: the driver-level control word. Round 22 reused the generation
     * state for this (one field, two meanings) which was safe only while one
     * generation could exist. Now the control ops CAS THIS word and the live
     * generations are enumerated separately, so a Disarm can no longer mistake
     * "some generation is live" for "a control op is running". */
    volatile UInt32 ctrl;       /* kIdle or kControl; bzero()'d at Install */
    /* The live requests. A gen is claimed by an atomic CAS on its state, so two
     * output threads cannot share one; `inUse` is derived from the states, never
     * maintained separately (a second bookkeeping flag is a second thing to get
     * wrong -- round 22's `held`/`packet` pair had exactly that problem). */
    R17Gen gens[r17tx::kSlots];
    volatile UInt32 outputWaiting;
    UInt32 outputWaits, outputResumes, outputWakes;
    UInt32 mapped, completed, retired, dropped, replaced, rejected;
    UInt32 held, maxHeld;       /* live mbufs: counts, not a flag */
    UInt32 lastSig;             /* throttles the raw publication */
    /* Diagnostics: did the driver's own completion walk reach this generation? */
    UInt32 completeCalls, completeHits, lastSeenSlot;
    /* ---- round 19: standard mapper objects are per gen (see R17Gen) ---- */
    bool stdMode, allTx;
    IOMapper *stdMapper;
    UInt32 stdAccepts, stdRejects, stdUnsupported, stdUnmaps, stdPinned;
    UInt32 stdHighReqAccepts;
    /* Round26: attempts is also the internal request sequence in all mode.
     * Successful maps partition into the old selector's two outcomes. */
    UInt32 mapAttempts, unmarked, legacySelected;
    UInt32 stdLastSig;
    r18std::Snapshot stdSnap;
    /* Round25: absolute retirement record cursor. History writes at cursor%32;
     * it never bounds the cumulative counter or the four live generations. */
    UInt32 stdRecordCursor;
    /* ---- round 20: blocked-ring record and cover accounting ---- */
    r20tx::Block blockSnap;
    UInt32 coverCalls, coverRejects;
    /* ---- round 21/22: the translation window gate ----
     * gate mirrors the closed bit in r17Admit for reporting; the authoritative
     * state is the admission word, because only that word can be closed and
     * referenced in one atomic step. */
    volatile UInt32 gate;
    volatile UInt32 coverActive;
    UInt32 coverGen;
    UInt32 windowQuiesce, windowDrained, windowExit, windowResumed;
    UInt32 gateFails;   /* refused gate transitions, reported to the probe */
    UInt32 barrierFails;/* submissions refused because the word was closed */
    /* Round22 boundary stamps. LATCHED, not re-sampled: the first observation of
     * an event is the event, and a later poll must not move it. */
    UInt32 edgeSeq;
    UInt64 tEdge;       /* the most recent admission-word transition */
    UInt64 tGateClose;  /* the admission word became closed (this close) */
    UInt64 tSubmitDone; /* inFlight first reached 0 after that close */
    UInt64 tDrainDone;  /* inFlight==0 && ringOwn==0 first held after it */
    UInt64 tResume;     /* the word was opened again */
    volatile UInt32 blockPublish;
    UInt64 tQuiesce, tDrained, tExit, tResumed;
    r17tx::Snapshot snapshot;
};

IOReturn RTL8125::r17TxConfigure(r17tx::Configure *c)
{
    /* Round 21: an explicit whitelist, not a range. kQuiesce/kResume are 16/17
     * precisely so they cannot collide with 1..4, and a range test would then
     * have admitted every undefined value in between. */
    if (!c || c->version != r17tx::kVersion || c->bytes != sizeof(*c) ||
        !(c->op == r17tx::kInstall || c->op == r17tx::kDisarm ||
          c->op == r17tx::kQuery || c->op == r17tx::kDetach ||
          c->op == r17tx::kQuiesce || c->op == r17tx::kResume ||
          c->op == r17tx::kSample)) {
        return kIOReturnBadArgument;
    }
    /* The platform entry is serialized by commandGate. State CAS also excludes
     * the output thread (not on this workloop). Completion never takes a lock. */
    if (c->op == r17tx::kInstall && !r17Tx) {
        /* Every refusal names itself. Round 21's first hardware run reported
         * only "FAIL-install" on the probe side, which cannot distinguish a bad
         * deadline from a BDF mismatch from a missing mapper -- and the run
         * costs a reboot to repeat. */
        if (useAppleVTD || !workLoop || !pciDevice || !c->callback ||
            !c->context || !c->owner || !c->token ||
            c->deadline <= mach_absolute_time()) {
            IOLog("r17 install rejected: vtd=%d wl=%d pci=%d cb=%d ctx=%d "
                  "own=%d tok=%u dl=%llu now=%llu\n", (int)useAppleVTD,
                  workLoop != 0, pciDevice != 0, c->callback != 0,
                  c->context != 0, c->owner != 0, c->token,
                  (unsigned long long)c->deadline,
                  (unsigned long long)mach_absolute_time());
            return kIOReturnBadArgument;
        }
        UInt32 bdf = ((UInt32)pciDevice->getBusNumber() << 8) |
                     ((UInt32)pciDevice->getDeviceNumber() << 3) |
                     pciDevice->getFunctionNumber();
        if (bdf != c->bdf) {
            IOLog("r17 install rejected: bdf got %#x want %#x\n", bdf, c->bdf);
            return kIOReturnBadArgument;
        }
        /* Round19: the standard mode is only valid with a mapper object and a
         * callback (Install/Query/Detach still travel through the platform
         * function). Anything else is refused rather than downgraded. */
        if (c->mode != r17tx::kModeDirect && c->mode != r17tx::kModeStandard &&
            c->mode != r17tx::kModeAllStandard) {
            IOLog("r17 install rejected: mode %u\n", c->mode);
            return kIOReturnBadArgument;
        }
        if (c->mode != r17tx::kModeDirect && !c->mapper) {
            IOLog("r17 install rejected: standard mode without a mapper\n");
            return kIOReturnBadArgument;
        }
        /* Four pages per live slot do not support large TSO super-packets.
         * These fields feed getFeatures() during driver setup: changing them
         * here would not renegotiate the stack's advertised capabilities. The
         * all-TX run must start with both offloads already disabled. */
        if (c->mode == r17tx::kModeAllStandard && (enableTSO4 || enableTSO6)) {
            IOLog("r26 install rejected: all-standard requires TSO4=0 TSO6=0 "
                  "(got %d/%d)\n", (int)enableTSO4, (int)enableTSO6);
            return kIOReturnBadArgument;
        }
        R17TxState *p = (R17TxState *)IOMalloc(sizeof(R17TxState));
        if (!p) return kIOReturnNoMemory;
        bzero(p, sizeof(*p));
        p->stdMode = (c->mode != r17tx::kModeDirect);
        p->allTx = (c->mode == r17tx::kModeAllStandard);
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
        /* Round 21: a fresh state starts with its window gate CLOSED. The probe
         * opens it in r17EnterComplete() once the DTE flip is confirmed; until
         * then neither a selected frame (64 GiB IOVA) nor an ordinary one (PA
         * re-resolution) may be submitted.
         *
         * Round22: the gate is the ADMISSION WORD, and it is closed BEFORE the
         * state is published. A thread that read r17Tx==NULL and is already
         * inside outputStart holds a reference (taken before it looked at the
         * state at all), so closing the word here makes that thread part of the
         * drain the probe is about to wait for -- which is exactly the case
         * round 21 could not see. */
        __atomic_store_n(&p->gate, 1u, __ATOMIC_RELEASE);
        const UInt32 admitPrev =
            __atomic_fetch_or(&r17Admit, 0x80000000u, __ATOMIC_ACQ_REL);
        if (!(admitPrev & 0x80000000u)) {
            p->edgeSeq = 1;
            p->tGateClose = mach_absolute_time();
            p->tEdge = p->tGateClose;
            p->windowQuiesce = 1;
        }
        __atomic_store_n(&r17Tx, p, __ATOMIC_RELEASE);
        p->timer->setTimeoutMS(10);
    } else if (c->op == r17tx::kInstall) return kIOReturnBusy;
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    if (!p) return kIOReturnNotReady;
    /* Round 22: the window edges are plain control operations. They touch only
     * atomics and ring indices -- no sleep, no IOMMU command, no lock the
     * completion path needs -- so they are safe inside the command gate while
     * an output thread is inside r17TxMap. The WAIT for inFlight/ringOwn to
     * reach zero lives in the probe's own thread for exactly that reason: this
     * workloop reaps completed descriptors, so blocking it would wait for
     * itself. */
    /* Round21: an explicit, caller-named sample. Configure.state carries the
     * r20tx::kStage* value so the record says which window step it belongs to
     * instead of inheriting whatever step the last gate operation happened to
     * be. No state change, no ring touch beyond the value copy. */
    if (c->op == r17tx::kSample) {
        const UInt32 stage = c->state;
        if (stage != r20tx::kStageQuiesce && stage != r20tx::kStageDrained &&
            stage != r20tx::kStageExit && stage != r20tx::kStageResumed) {
            __atomic_fetch_add(&p->gateFails, 1u, __ATOMIC_RELAXED);
            return kIOReturnBadArgument;
        }
        r17TxSample(stage);
        r17TxReport(c);
        return kIOReturnSuccess;
    }
    if (c->op == r17tx::kQuiesce || c->op == r17tx::kResume) {
        const IOReturn kr = r17TxGate(c->op == r17tx::kQuiesce);
        /* Round23: there is no single driver state any more; the control word is
         * what a caller can still read here, and the live count says how many
         * mappings exist. */
        c->state = __atomic_load_n(&p->ctrl, __ATOMIC_ACQUIRE);
        r17TxReport(c);
        c->mapped = __atomic_load_n(&p->mapped, __ATOMIC_RELAXED);
        c->completed = __atomic_load_n(&p->completed, __ATOMIC_RELAXED);
        c->retired = __atomic_load_n(&p->retired, __ATOMIC_RELAXED);
        c->dropped = __atomic_load_n(&p->dropped, __ATOMIC_RELAXED);
        c->rejected = __atomic_load_n(&p->rejected, __ATOMIC_RELAXED);
        return kr;
    }
    /* Round22: `enabled` is NOT cleared here. A refused Disarm/Detach must
     * leave the controlled path exactly as it was -- clearing it on the way to
     * a refusal would silently disable the mapping while the window is still
     * open. It is cleared below, only after the CAS accepted the op. */
    UInt32 state = __atomic_load_n(&p->ctrl, __ATOMIC_ACQUIRE);
    c->state = state;
    /* Round23: Query reports the newest handle still live, for the same
     * diagnostic purpose as before, plus the number of live generations so a
     * caller can tell "nothing mapped" from "several mapped". */
    c->handle = 0;
    if (c->op == r17tx::kQuery) {
        c->maxHeld = r17TxLiveGens();
        if (p->stdMode) {
            for (UInt32 k = 0; k < r17tx::kSlots; k++) {
                const UInt64 h = __atomic_load_n(&p->gens[k].stdHandle,
                                                 __ATOMIC_ACQUIRE);
                if (h > c->handle) c->handle = h;
            }
        }
    }
    c->mapped = __atomic_load_n(&p->mapped, __ATOMIC_RELAXED);
    c->completed = __atomic_load_n(&p->completed, __ATOMIC_RELAXED);
    c->retired = __atomic_load_n(&p->retired, __ATOMIC_RELAXED);
    c->dropped = __atomic_load_n(&p->dropped, __ATOMIC_RELAXED);
    c->held = __atomic_load_n(&p->held, __ATOMIC_RELAXED);
    c->modeReserved = r17TxLiveGens();
    c->maxHeld = __atomic_load_n(&p->maxHeld, __ATOMIC_RELAXED);
    c->evidenceUsed = c->retired;
    c->rejected = __atomic_load_n(&p->rejected, __ATOMIC_RELAXED);
    if (c->op == r17tx::kDisarm || c->op == r17tx::kDetach) {
        /* Round22: a submission that was admitted is still between the gate and
         * its OWN bit, so it may yet call kCover (callback/context) and it still
         * needs `enabled`. Nothing may be torn down underneath it. The word must
         * ALSO be closed: Disarm/Detach without a preceding quiesce would be a
         * control operation racing the output path, and the probe never does
         * that -- making it a refusal here means a wrong order fails loudly
         * instead of silently opening or dropping traffic. */
        if (!(__atomic_load_n(&r17Admit, __ATOMIC_ACQUIRE) & 0x80000000u) ||
            r17TxRefs()) {
            __atomic_fetch_add(&p->gateFails, 1u, __ATOMIC_RELAXED);
            return kIOReturnBusy;
        }
        /* Round23: the control word is separate from the generation states, so
         * this CAS says "no other control op is running" and says nothing about
         * the mappings -- those are counted below. */
        UInt32 expected = r17tx::kIdle;
        if (!__atomic_compare_exchange_n(&p->ctrl, &expected,
            (UInt32)r17tx::kControl, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            /* Round 21: distinguish "a generation is genuinely live" from "the
             * gate is still closed". The probe retries on Busy, but it needs to
             * know which one it hit, and a closed gate must not be reported as a
             * pinned DMA owner. */
            if (__atomic_load_n(&p->gate, __ATOMIC_ACQUIRE))
                __atomic_fetch_add(&p->gateFails, 1u, __ATOMIC_RELAXED);
            return kIOReturnBusy;
        }
        /* A Disarm with mappings still live is refused for the same reason a
         * Detach is: the controlled path must not be switched off while a
         * descriptor the device owns still translates through it. */
        if (r17TxLiveGens() || __atomic_load_n(&p->held, __ATOMIC_ACQUIRE)) {
            __atomic_store_n(&p->ctrl, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
            return kIOReturnBusy;
        }
        /* The op was accepted: only now may the controlled path be switched
         * off. From here on a selected frame is refused by r17TxMap's `base`
         * test, which is what keeps a late 64 GiB IOVA out of a table that is
         * no longer installed. */
        __atomic_store_n(&p->enabled, false, __ATOMIC_RELEASE);
        if (c->op == r17tx::kDetach) {
            /* Round23: "Idle" now means EVERY generation is idle, which is the
             * same per-packet fact as before -- each successful Retire already
             * cleared its own slot -- checked across all of them instead of one
             * driver-wide field. A live generation at this point is genuinely
             * outstanding; never free it to make Detach look clean. */
            if (r17TxLiveGens() || __atomic_load_n(&p->held, __ATOMIC_ACQUIRE)) {
                __atomic_store_n(&p->ctrl, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
                return kIOReturnBusy;
            }
            /* Round22: re-check after taking the control word. An admission can
             * land between the check above and this CAS (the word could still be
             * open if the caller skipped the quiesce). Give it back and refuse
             * rather than detach underneath it. */
            if (r17TxRefs() ||
                __atomic_load_n(&p->coverActive, __ATOMIC_ACQUIRE)) {
                __atomic_store_n(&p->ctrl, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
                __atomic_fetch_add(&p->gateFails, 1u, __ATOMIC_RELAXED);
                return kIOReturnBusy;
            }
            p->callback = NULL; p->context = NULL;
            if (p->owner) { p->owner->release(); p->owner = NULL; }
        }
        __atomic_store_n(&p->ctrl, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
        c->state = r17tx::kIdle;
        /* Round22: Disarm/Detach do NOT open the admission word.
         *
         * Round 21 opened it here, so a successful Disarm resumed ordinary
         * output immediately -- and when the exit could not restore the device
         * table (drained=false, or a refused Detach), the run ended with
         * translation still installed, cover already disabled and ordinary TX
         * flowing again. That is exactly the failure this round removes: the
         * probe opens the word with an explicit kResume, only after the device
         * table has been restored and read back. */
        c->quiesced = __atomic_load_n(&p->gate, __ATOMIC_ACQUIRE);
    }
    r17TxPublish();
    return kIOReturnSuccess;
}

/* ---- round 22: the submission barrier ------------------------------------
 *
 * Admission and departure are the two halves of ONE contract, and the reason
 * they exist is that the probe must be able to say "no descriptor is between
 * outputStart and the hardware" without trusting thread scheduling:
 *
 *   r17TxEnter()  is called on every packet that reached the commit point,
 *                 BEFORE the backend is even looked at (so it also covers the
 *                 output thread that read "no backend" before Install);
 *   r17TxLeave()  is called after the OWN bit is set, or on every refusal.
 *
 * While an admission is outstanding, the probe's kQuiesce cannot conclude
 * "stopped", so the DTE flip cannot happen underneath it. The count is capped
 * at 2^31-1 which cannot be reached with a bounded output queue; a saturated
 * word refuses admission instead of wrapping into the closed bit. */
bool RTL8125::r17TxEnter()
{
    for (;;) {
        UInt32 v = __atomic_load_n(&r17Admit, __ATOMIC_ACQUIRE);
        if (v & 0x80000000u) return false;
        if ((v & 0x7fffffffu) == 0x7fffffffu) return false;
        if (__atomic_compare_exchange_n(&r17Admit, &v, v + 1u, false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return true;
    }
}
void RTL8125::r17TxLeave()
{
    __atomic_fetch_sub(&r17Admit, 1u, __ATOMIC_ACQ_REL);
}
UInt32 RTL8125::r17TxRefs()
{
    return __atomic_load_n(&r17Admit, __ATOMIC_ACQUIRE) & 0x7fffffffu;
}
/* The generation that owns this mbuf, or NULL. The mbuf pointer is the link
 * between the commit point (r17TxPosted) and the gen that mapped it: at that
 * instant the ring has not been walked, so the packet is still this
 * generation's and no other generation can hold the same pointer. */
RTL8125::R17Gen *RTL8125::r17TxFindByPacket(R17TxState *p, mbuf_t m)
{
    if (!p || !m) return NULL;
    for (UInt32 k = 0; k < r17tx::kSlots; k++) {
        if (__atomic_load_n(&p->gens[k].packet, __ATOMIC_ACQUIRE) == m)
            return &p->gens[k];
    }
    return NULL;
}
/* The newest live generation: highest index whose state is not Idle. Used only
 * for the single-generation ring sample, which is a diagnostic record. */
RTL8125::R17Gen *RTL8125::r17txNewestLive(R17TxState *p)
{
    if (!p) return NULL;
    for (UInt32 k = r17tx::kSlots; k > 0; k--) {
        R17Gen *g = &p->gens[k - 1];
        if (__atomic_load_n(&g->state, __ATOMIC_ACQUIRE) != r17tx::kIdle)
            return g;
    }
    return NULL;
}
/* Total descriptor occupancy, selected generation INCLUDED. This is the number
 * the probe drains to zero: the selected slots are descriptors the device owns
 * just like any other, and the page table they translate through is about to be
 * replaced. r17TxOutstanding() below answers a different question (ordinary
 * traffic only) and must not be used as the drain target. */
UInt32 RTL8125::r17TxRingOwn()
{
    return (txNextDescIndex - txDirtyDescIndex) & kTxDescMask;
}

/* true: the caller may submit m. false: consumed (freed or pinned), MUST skip.
 * Called only after the frame's length is known and before ANY OWN.
 *
 * Round22 splits this in two: this wrapper owns the admission reference, and
 * r17TxMapAdmitted() is the round-17..21 body unchanged. A `false` from the
 * body means the packet never reaches an OWN bit, so the reference is released
 * here; a `true` means outputStart will set OWN and call r17TxPosted(), which
 * releases it. There is no third exit from outputStart between those two
 * points (verified against the generated source by tools/r21/test-driver.py). */
/* The interface has ONE output thread. Test capacity BEFORE dequeue: the
 * interface queue remains the sole mbuf owner; no fifth packet reaches Map.
 * Publish waiting BEFORE scanning slots. Retirement may race either side of
 * the scan, but the timer repeats a level-triggered wake until output consumes
 * it, so a signal just before the output thread sleeps cannot be lost. */
bool RTL8125::r17TxOutputReady()
{
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    if (!p) return true;
    UInt32 was = __atomic_exchange_n(&p->outputWaiting, 1u, __ATOMIC_ACQ_REL);
    for (UInt32 k = 0; k < r17tx::kSlots; k++) {
        if (__atomic_load_n(&p->gens[k].state, __ATOMIC_ACQUIRE) == r17tx::kIdle) {
            __atomic_store_n(&p->outputWaiting, 0u, __ATOMIC_RELEASE);
            if (was) __atomic_fetch_add(&p->outputResumes, 1u, __ATOMIC_RELAXED);
            return true;
        }
    }
    if (!was) __atomic_fetch_add(&p->outputWaits, 1u, __ATOMIC_RELAXED);
    return false;
}

void RTL8125::r17TxWakeOutput()
{
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    if (!p) return;
    if (__atomic_load_n(&p->outputWaiting, __ATOMIC_ACQUIRE)) {
        for (UInt32 k = 0; k < r17tx::kSlots; k++) {
            if (__atomic_load_n(&p->gens[k].state, __ATOMIC_ACQUIRE) == r17tx::kIdle) {
                if (netif) {
                    __atomic_fetch_add(&p->outputWakes, 1u, __ATOMIC_RELAXED);
                    netif->signalOutputThread();
                }
                break;
            }
        }
    }
    setProperty("R24TxPending", (UInt64)__atomic_load_n(&p->outputWaiting, __ATOMIC_ACQUIRE), 32);
    setProperty("R24TxWaits", (UInt64)__atomic_load_n(&p->outputWaits, __ATOMIC_RELAXED), 32);
    setProperty("R24TxResumes", (UInt64)__atomic_load_n(&p->outputResumes, __ATOMIC_RELAXED), 32);
    setProperty("R24TxWakes", (UInt64)__atomic_load_n(&p->outputWakes, __ATOMIC_RELAXED), 32);
}

bool RTL8125::r17TxMap(mbuf_t m, IOPhysicalSegment *segments, UInt32 &count)
{
    if (!r17TxEnter()) {
        /* Gated: the window is being flipped. Dropping is the only safe answer
         * for BOTH kinds of packet -- an ordinary one relies on the identity
         * table being stable, a selected one carries a 64 GiB IOVA that is only
         * meaningful once translation is confirmed. The stack retransmits. */
        R17TxState *p0 = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
        if (p0) {
            __atomic_fetch_add(&p0->barrierFails, 1u, __ATOMIC_RELAXED);
            __atomic_fetch_add(&p0->rejected, 1u, __ATOMIC_RELAXED);
        }
        freePacket(m);
        return false;
    }
    const bool keep = r17TxMapAdmitted(m, segments, count);
    if (!keep) r17TxLeave();
    return keep;
}

bool RTL8125::r17TxMapAdmitted(mbuf_t m, IOPhysicalSegment *segments,
                               UInt32 &count)
{
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    if (!p) return true;
    /* allTx describes the completed run as well as the active one. Only a
     * fully detached backend restores ordinary output; Disarm/deadline alone
     * must never turn an active translated window into identity fallback.
     * Admission still stays closed until the probe restores the DTE and Resume
     * opens it, so this return cannot bypass the window-edge barrier. */
    if (p->allTx && !__atomic_load_n(&p->enabled, __ATOMIC_ACQUIRE) &&
        !p->callback) return true;
    if (!segments || !count) {
        if (!p->allTx) return true;
        __atomic_fetch_add(&p->mapAttempts, 1u, __ATOMIC_RELAXED);
        __atomic_fetch_add(&p->rejected, 1u, __ATOMIC_RELAXED);
        freePacket(m); return false;
    }
    UInt32 token = 0, req = 0, flow = 0;
    UInt32 flags = obsParseBiz(m, (UInt32)mbuf_pkthdr_len(m), true,
                               &token, &req, &flow);
    const bool legacySelected = (flags & kObsPktParsed) && token == p->token &&
        req >= 1 && req <= r17tx::kRequestLimit;
    if (!p->allTx && !legacySelected) {
        /* Round 22: there is no gate check here any more. Admission was decided
         * by r17TxEnter() and is held until r17TxPosted(), so a close that
         * happens NOW is covered by the reference: kQuiesce cannot conclude
         * "stopped" until this packet has set its OWN bit. Re-checking the word
         * would only turn a covered submission into a drop. */
        /* Round 20: a packet that is NOT selected keeps its physical addresses,
         * so its own pages must be covered by the device page table before any
         * descriptor owns it. Failure drops the packet; an address the device
         * cannot translate is never offered to hardware. */
        if (!r17TxCover(p, segments, count)) {
            __atomic_fetch_add(&p->rejected, 1u, __ATOMIC_RELAXED);
            freePacket(m); return false;
        }
        return true;
    }
    const UInt32 attempt =
        __atomic_fetch_add(&p->mapAttempts, 1u, __ATOMIC_RELAXED) + 1u;
    if (p->allTx) {
        token = p->token;
        req = attempt; /* internal, monotonic; no packet ID or 512 admission cap */
    }
    /* Round23: claim a free gen slot. The CAS is on that slot's own state, so
     * two output threads racing here take DIFFERENT slots or one is told Busy --
     * never the same one. Round 22 could express this as a single CAS on a
     * driver-wide state because there was only one slot to take. */
    R17Gen *g = NULL;
    for (UInt32 k = 0; k < r17tx::kSlots && !g; k++) {
        UInt32 idle = r17tx::kIdle;
        if (__atomic_compare_exchange_n(&p->gens[k].state, &idle,
                (UInt32)r17tx::kMapping, false, __ATOMIC_ACQ_REL,
                __ATOMIC_ACQUIRE))
            g = &p->gens[k];
    }
    if (!g) {
        /* Fail-closed invariant guard, NOT normal saturation handling:
         * outputStart's sole output thread checks r17TxOutputReady BEFORE
         * dequeue, and is the sole caller that claims gens. Timer/control only
         * release gens. Thus no slot can become busy between that check and
         * this claim. Saturation keeps the packet owned by the interface queue.
         * A future additional Map caller must supply its own queue protocol. */
        __atomic_fetch_add(&p->dropped, 1u, __ATOMIC_RELAXED);
        freePacket(m); return false;
    }
    /* Round 22: no gate term. The probe opens the admission word only after the
     * DTE flip and both invalidations completed, so a packet admitted here is
     * always admitted after translation is confirmed; a close that happens
     * after admission is exactly what the reference protects. */
    const bool base = !useAppleVTD && __atomic_load_n(&p->enabled, __ATOMIC_ACQUIRE)
        && p->callback && mach_absolute_time() < p->deadline;
    /* Round25: historical evidence capacity never gates live mapping owners. */
    if (!base) {
        __atomic_fetch_add(&p->rejected, 1u, __ATOMIC_RELAXED);
        freePacket(m);
        __atomic_store_n(&g->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
        return false;
    }
    g->index = (UInt32)(g - p->gens);
    bzero(&g->current, sizeof(g->current));
    g->current.cumulative = txTailPtr0;
    g->current.firstSlot = txNextDescIndex;
    g->packet = NULL; g->stdMD = NULL; g->stdCmd = NULL; g->stdWired = false;
    g->stdCompleteAttempted = false; g->stdRetireResult = kIOReturnNotReady;
    g->stdHandle = 0; g->lastSlot = 0;
    bzero(&g->request, sizeof(g->request));
    g->request.version = r17tx::kVersion; g->request.bytes = sizeof(g->request);
    g->request.bdf = p->bdf; g->request.token = token; g->request.reqId = req;
    __atomic_store_n(&g->doneSeen, 0u, __ATOMIC_RELAXED);
    /* Exactly one mapper performs this map, chosen at Install time. */
    const bool ok = p->stdMode ? r17TxMapStd(p, g, m, segments, count)
                               : r17TxMapDirect(p, g, m, segments, count);
    if (!ok) return false;
    g->lastSlot = (txNextDescIndex + count - 1) & kTxDescMask;
    __atomic_fetch_add(&p->mapped, 1u, __ATOMIC_RELAXED);
    __atomic_fetch_add(legacySelected ? &p->legacySelected : &p->unmarked,
                       1u, __ATOMIC_RELAXED);
    /* Published BEFORE the first OWN: the completion path may stamp this
     * generation as soon as the doorbell is rung, but it must not start the
     * retirement of a witness that has not been recorded yet (kPosting). */
    __atomic_store_n(&g->state, (UInt32)r17tx::kPosting, __ATOMIC_RELEASE);
    return true;
}

/* Round 17 path: the platform callback maps the packet's own physical segments.
 * Nothing is copied and numSegs is NOT flattened here. */
bool RTL8125::r17TxMapDirect(R17TxState *p, R17Gen *g, mbuf_t m,
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
        __atomic_store_n(&g->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
        return false;
    }
    r17tx::Request &r = g->request;
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
            g->packet = m;
            __atomic_fetch_add(&p->held, 1u, __ATOMIC_ACQ_REL);
            if (__atomic_load_n(&p->maxHeld, __ATOMIC_RELAXED) < p->held)
                __atomic_store_n(&p->maxHeld, p->held, __ATOMIC_RELEASE);
            __atomic_store_n(&g->state, (UInt32)r17tx::kPending, __ATOMIC_RELEASE);
        } else {
            freePacket(m);
            __atomic_store_n(&g->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
        }
        return false;
    }
    for (UInt32 i = 0; i < count; i++) segments[i].location = r.iova[i].address;
    g->packet = m;
    __atomic_fetch_add(&p->held, 1u, __ATOMIC_ACQ_REL);
    if (__atomic_load_n(&p->maxHeld, __ATOMIC_RELAXED) < p->held)
        __atomic_store_n(&p->maxHeld, p->held, __ATOMIC_RELEASE);
    return true; /* the dispatcher publishes kPosting, not this helper */
}

/* Round 20: cover the packet's OWN physical ranges in the device page table.
 *
 * The bootstrap table maps [0, 16 GiB) identity, but RAM does not end there:
 * the low MMIO hole pushes the top of RAM above 16 GiB, so an ordinary mbuf can
 * legitimately carry a PA the device cannot read. The device then faults on the
 * first data fetch and the TX queue stops -- which is what rounds 18/19 saw.
 *
 * The backend is asked to add identity coverage for exactly the 2 MiB chunks
 * that contain these segments (and to invalidate), before any OWN is set. The
 * descriptor addresses are NOT rewritten: this is still the ordinary identity
 * path. A backend failure returns false so the packet is dropped, never sent
 * with an uncovered address.
 */
bool RTL8125::r17TxCover(R17TxState *p, IOPhysicalSegment *segments, UInt32 count)
{
    if (!p || !segments || !count || !p->callback)
        return true;   /* no backend: this boot is not translated by us */
    /* Round 22: no gate read here. The caller holds an admission reference from
     * r17TxEnter(), which is what keeps the backend (callback/context) alive
     * across this call -- reading the word again would reintroduce exactly the
     * check-then-act window round 21 had between "gate was open" and
     * coverActive++. The counter below is a diagnostic, not the lifetime
     * mechanism. */
    __atomic_fetch_add(&p->coverActive, 1u, __ATOMIC_ACQ_REL);
    for (UInt32 at = 0; at < count; at += r17tx::kMaxSegments) {
        r17tx::Request r;
        bzero(&r, sizeof(r));
        r.version = r17tx::kVersion; r.bytes = sizeof(r); r.bdf = p->bdf;
        r.token = p->token;
        UInt32 n = 0;
        for (; n < r17tx::kMaxSegments && at + n < count; n++) {
            r.physical[n].address = segments[at + n].location;
            r.physical[n].length  = segments[at + n].length;
        }
        r.count = n;
        const IOReturn kr = p->callback(p->context, r17tx::kCover, &r);
        if (kr != kIOReturnSuccess) {
            __atomic_fetch_add(&p->coverRejects, 1u, __ATOMIC_RELAXED);
            __atomic_fetch_sub(&p->coverActive, 1u, __ATOMIC_ACQ_REL);
            return false;
        }
    }
    __atomic_fetch_add(&p->coverCalls, 1u, __ATOMIC_RELAXED);
    __atomic_fetch_sub(&p->coverActive, 1u, __ATOMIC_ACQ_REL);
    return true;
}

/* Round 18 path: the packet is described by an IOMemoryDescriptor and mapped
 * through an IODMACommand built on the probe's own IOMapper. IOKit -- not this
 * function -- calls iovmMapMemory(); all this code does is describe, prepare,
 * read back what the framework decided, and decide whether that is usable.
 *
 * The chain is bounded by kMbufs and the returned DMA runs by kSegments. The
 * mapper independently enforces the four-page capacity of a live slot before
 * it writes PTEs; kMaxBytes alone does not establish that a layout fits. */
bool RTL8125::r17TxMapStd(R17TxState *p, R17Gen *g, mbuf_t m,
                          IOPhysicalSegment *segments, UInt32 &count)
{
    const UInt32 len = (UInt32)mbuf_pkthdr_len(m);
    r17tx::Request &r = g->request;
    bzero(&g->stdW, sizeof(g->stdW));
    g->stdW.version = r18std::kVersion;
    g->stdW.bytes = sizeof(g->stdW);
    g->stdW.req = r.reqId;
    g->stdW.token = r.token;
    g->stdW.tBegin = mach_absolute_time();
    g->stdHandle = 0;
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
    g->stdW.mbufSegments = nrange;
    const bool layout = fits && c == NULL && nrange && len && len <= r17tx::kMaxBytes
        && sum == len;
    if (!layout) {
        g->stdW.flags |= r18std::kRefused;
        __atomic_fetch_add(&p->stdUnsupported, 1u, __ATOMIC_RELAXED);
        __atomic_fetch_add(&p->rejected, 1u, __ATOMIC_RELAXED);
        freePacket(m);
        __atomic_store_n(&g->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
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
    g->stdWired = wired;
    if (!md) {
        g->stdW.flags |= r18std::kRefused;
        __atomic_fetch_add(&p->stdRejects, 1u, __ATOMIC_RELAXED);
        __atomic_fetch_add(&p->rejected, 1u, __ATOMIC_RELAXED);
        freePacket(m);
        __atomic_store_n(&g->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
        return false;
    }
    IODMACommand *cmd = IODMACommand::withSpecification(
        kIODMACommandOutputHost64, 64, 0, IODMACommand::kMapped, 0, 1,
        p->stdMapper, NULL);
    if (!cmd) {
        /* Round 20: the multi-range descriptor was wired before the command
         * existed, so this early exit owes its complete() as well. One cleanup
         * shape for every pre-publish failure: release md, never leak wiring. */
        if (md && wired) md->complete(kIODirectionOut);
        g->stdWired = false;
        md->release();
        g->stdW.flags |= r18std::kRefused;
        __atomic_fetch_add(&p->stdRejects, 1u, __ATOMIC_RELAXED);
        __atomic_fetch_add(&p->rejected, 1u, __ATOMIC_RELAXED);
        freePacket(m);
        __atomic_store_n(&g->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
        return false;
    }
    g->stdMD = md; g->stdCmd = cmd;
    g->stdW.memory = (UInt64)(uintptr_t)md;
    g->stdW.command = (UInt64)(uintptr_t)cmd;
    g->stdW.descriptorLength = len;
    /* The call that makes IOKit perform the map. autoPrepare is used because
     * the packet is already wired kernel memory owned by the stack; the mapper
     * itself never sleeps, so this path stays non-blocking. */
    const UInt64 mark0 = r17TxStdMark();
    IOReturn kr = cmd->setMemoryDescriptor(md, true);
    const UInt64 mark1 = r17TxStdMark();
    g->stdW.prepareResult = (UInt32)kr;
    g->stdW.tPrepared = mach_absolute_time();
    /* Did this prepare() publish a mapping? Only a growth of the probe's record
     * count proves it; the handle value alone would still be the previous
     * generation's. */
    g->stdHandle = ((mark1 >> 32) != (mark0 >> 32))
        ? (UInt32)(mark1 & 0xFFFFFFFFULL) : 0;
    g->stdW.handle = (UInt32)g->stdHandle; /* stamped, not inferred later */
    if (kr != kIOReturnSuccess) {
        if (g->stdHandle == 0) {
            /* Nothing was published: no translation exists, so nothing is kept.
             * Round 20 pairs the explicit md->prepare() with complete() on this
             * path too (round 19 released the descriptor still wired). */
            cmd->clearMemoryDescriptor();
            g->stdCmd = nullptr; g->stdMD = nullptr;
            if (wired) md->complete(kIODirectionOut);
            g->stdWired = false;
            cmd->release(); md->release();
            g->stdW.flags |= r18std::kRefused;
            __atomic_fetch_add(&p->stdRejects, 1u, __ATOMIC_RELAXED);
            __atomic_fetch_add(&p->rejected, 1u, __ATOMIC_RELAXED);
            freePacket(m);
            __atomic_store_n(&g->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
            return false;
        }
        /* The mapper published a mapping and could not confirm its
         * invalidation. Keep the standard objects and the mbuf: this is a
         * pinned generation, never a recycled one. */
        g->stdW.flags |= r18std::kPinned;
        __atomic_fetch_add(&p->stdPinned, 1u, __ATOMIC_RELAXED);
        g->packet = m;
        __atomic_fetch_add(&p->held, 1u, __ATOMIC_ACQ_REL);
        if (__atomic_load_n(&p->maxHeld, __ATOMIC_RELAXED) < p->held)
            __atomic_store_n(&p->maxHeld, p->held, __ATOMIC_RELEASE);
        __atomic_store_n(&g->state, (UInt32)r17tx::kPending, __ATOMIC_RELEASE);
        return false;
    }
    IODMACommand::Segment64 segs[r18std::kSegments] = {};
    UInt64 segOffset = 0;
    UInt32 segCount = r18std::kSegments;
    kr = cmd->gen64IOVMSegments(&segOffset, segs, &segCount);
    g->stdW.segmentResult = (UInt32)kr;
    g->stdW.tSegmented = mach_absolute_time();
    g->stdW.segCount = segCount;
    for (UInt32 i = 0; i < segCount && i < r18std::kSegments; i++) {
        g->stdW.segments[i].address = segs[i].fIOVMAddr;
        g->stdW.segments[i].length = segs[i].fLength;
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
            g->stdW.flags |= r18std::kIdentity;
        return r17TxStdRollback(p, g, m);
    }
    g->stdW.mapAddress = segs[0].fIOVMAddr;
    /* Logical bytes covered by the mapping. The length IOKit hands back to
     * iovmUnmapMemory() is the mapper's own contract (strictly larger than
     * this whenever the layout is fragmented) and is recorded by the mapper,
     * not re-derived here. */
    g->stdW.mapLength = len;
    g->stdW.flags |= r18std::kMapped;
    r.count = segCount;
    r.tMap = g->stdW.tPrepared;
    for (UInt32 i = 0; i < segCount; i++) {
        r.iova[i].address = segs[i].fIOVMAddr;
        r.iova[i].length = segs[i].fLength;
        segments[i].location = segs[i].fIOVMAddr;
        segments[i].length = segs[i].fLength;
    }
    count = segCount;
    g->packet = m;
    __atomic_fetch_add(&p->held, 1u, __ATOMIC_ACQ_REL);
    if (__atomic_load_n(&p->maxHeld, __ATOMIC_RELAXED) < p->held)
        __atomic_store_n(&p->maxHeld, p->held, __ATOMIC_RELEASE);
    __atomic_fetch_add(&p->stdAccepts, 1u, __ATOMIC_RELAXED);
    if (r.reqId > r17tx::kMaxRequests)
        __atomic_fetch_add(&p->stdHighReqAccepts, 1u, __ATOMIC_RELAXED);
    return true;
}

/* Round29: complete() is still the only standard API that initiates unmap, but
 * its return value does not carry every mapper/CompletionWait failure. Query
 * the backend's confirmed record for THIS stamped handle before any release.
 * Never issue complete twice: the framework may already have discarded its
 * own mapping bookkeeping even when the backend retained the owner. */
IOReturn RTL8125::r17TxStdComplete(R17TxState *p, R17Gen *g)
{
    if (g->stdCompleteAttempted) return g->stdRetireResult;
    g->stdCompleteAttempted = true;
    g->stdW.tCompleteBegin = mach_absolute_time();
    const IOReturn result = g->stdCmd ? g->stdCmd->complete(true, false)
                                    : kIOReturnNotReady;
    g->stdW.tCompleteEnd = mach_absolute_time();
    g->stdW.completeResult = (UInt32)result; /* keep the actual framework result */
    g->stdRetireResult = result;
    if (result != kIOReturnSuccess) return result;
    r17tx::Request ack = g->request;
    /* Standard mode does not populate Request::handle. The mapper mark taken
     * around prepare() is the source of this generation's backend identity. */
    ack.handle = g->stdHandle;
    ack.tRetire = 0;
    if (!ack.handle || !p->callback) {
        g->stdRetireResult = kIOReturnNotReady;
        return g->stdRetireResult;
    }
    IOReturn confirmed = p->callback(p->context, r17tx::kRetireAck, &ack);
    if (confirmed == kIOReturnSuccess &&
        (ack.handle != g->stdHandle || !ack.tRetire))
        confirmed = kIOReturnIOError;
    if (confirmed == kIOReturnSuccess) g->request.tRetire = ack.tRetire;
    g->stdRetireResult = confirmed;
    return confirmed;
}

/* The single rollback exit for "the standard map was published, then found
 * unusable". Both API completion and backend confirmation decide the ending:
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
bool RTL8125::r17TxStdRollback(R17TxState *p, R17Gen *g, mbuf_t m)
{
    const IOReturn unmap = r17TxStdComplete(p, g);
    if (unmap == kIOReturnSuccess) {
        if (g->stdCmd) { g->stdCmd->clearMemoryDescriptor(false);
                         g->stdCmd->release(); g->stdCmd = nullptr; }
        if (g->stdMD && g->stdWired) g->stdMD->complete(kIODirectionOut);
        if (g->stdMD) { g->stdMD->release(); g->stdMD = nullptr; }
        g->stdWired = false;
        g->stdW.flags |= r18std::kRefused;
        g->stdW.tFree = mach_absolute_time();
        g->stdHandle = 0;
        __atomic_fetch_add(&p->stdUnsupported, 1u, __ATOMIC_RELAXED);
        __atomic_fetch_add(&p->rejected, 1u, __ATOMIC_RELAXED);
        freePacket(m);
        __atomic_store_n(&g->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
        return false;
    }
    g->stdW.flags |= r18std::kPinned;
    __atomic_fetch_add(&p->stdPinned, 1u, __ATOMIC_RELAXED);
    g->packet = m;
    __atomic_fetch_add(&p->held, 1u, __ATOMIC_ACQ_REL);
    if (__atomic_load_n(&p->maxHeld, __ATOMIC_RELAXED) < p->held)
        __atomic_store_n(&p->maxHeld, p->held, __ATOMIC_RELEASE);
    __atomic_store_n(&g->state, (UInt32)r17tx::kPending, __ATOMIC_RELEASE);
    return false;
}

/* Commit step: the descriptor ring now carries this generation, so record it.
 * Runs on the output thread, immediately after the first DescOwn is set and
 * before the doorbell. */
void RTL8125::r17TxPosted(mbuf_t m)
{
    /* Round22: this is the end of the admitted region -- the OWN bit of the
     * first descriptor was just set, so the descriptor now belongs to the
     * device and the ring occupancy (not this reference) is what keeps the
     * drain loop honest. Released BEFORE any early return: every admitted
     * packet reaches this call, and a leaked reference would make kQuiesce
     * unreachable forever. */
    r17TxLeave();
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    if (!p) return;
    /* Round23: find the generation THIS packet belongs to. Several are live at
     * once now, so "the state is kPosting" is no longer enough to identify one;
     * the mbuf pointer is the link between the commit point and the gen that
     * mapped it. */
    R17Gen *g = r17TxFindByPacket(p, m);
    if (!g || __atomic_load_n(&g->state, __ATOMIC_ACQUIRE) != r17tx::kPosting)
        return;
    g->current.tOwn = mach_absolute_time();
    g->current.lastSlot = g->lastSlot;
    if (p->stdMode) g->stdW.tCommit = g->current.tOwn;
    for (UInt32 i = 0; i < g->request.count; i++) {
        RtlTxDesc *d = &txDescArray[(g->current.firstSlot + i) & kTxDescMask];
        r17tx::Descriptor &out = g->current.descriptors[i];
        out.address = OSSwapLittleToHostInt64(d->addr);
        out.length = g->request.iova[i].length;
        out.opts1 = OSSwapLittleToHostInt32(d->opts1);
        out.opts2 = OSSwapLittleToHostInt32(d->opts2);
    }
    /* Submission/completion handoff, per generation. If the completion was
     * already recorded (doneSeen), this commit publishes kPending itself, so a
     * very fast completion cannot leave a generation that nobody will retire;
     * otherwise it publishes kSubmitted and the completion path (or the timer)
     * moves it to kPending afterwards. Either way the retire path only ever
     * observes a fully recorded witness. */
    if (__atomic_load_n(&g->doneSeen, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&g->state, (UInt32)r17tx::kPending, __ATOMIC_RELEASE);
        __atomic_fetch_add(&p->completed, 1u, __ATOMIC_RELAXED);
    } else {
        __atomic_store_n(&g->state, (UInt32)r17tx::kSubmitted, __ATOMIC_RELEASE);
    }
}

/* Completion: interrupt or polling context. Records the hardware completion and
 * moves the state; never invalidates, frees, or waits.
 *
 * Round23: the close pointer advances over several generations' descriptors in
 * one walk, so EVERY generation whose last slot was just passed must be stamped
 * -- not only the most recently mapped one. Round 22 compared against a single
 * `lastSlot` and silently ignored every other live generation's completion. */
void RTL8125::r17TxComplete(UInt32 slot)
{
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    if (!p) return;
    __atomic_fetch_add(&p->completeCalls, 1u, __ATOMIC_RELAXED);
    p->lastSeenSlot = slot;
    for (UInt32 k = 0; k < r17tx::kSlots; k++) {
        R17Gen *g = &p->gens[k];
        if (g->lastSlot != slot) continue;
        UInt32 state = __atomic_load_n(&g->state, __ATOMIC_ACQUIRE);
        if (state != r17tx::kPosting && state != r17tx::kSubmitted) continue;
        if (g->request.tDone) continue;
        /* Real close-pointer completion only. */
        g->request.tDone = mach_absolute_time();
        g->current.doneClose = txClosePtr0;
        g->current.closeMask = linuxData.MaxTxDescPtrMask;
        __atomic_fetch_add(&p->completeHits, 1u, __ATOMIC_RELAXED);
        __atomic_store_n(&g->doneSeen, 1u, __ATOMIC_RELEASE);
        UInt32 expected = r17tx::kSubmitted;
        if (__atomic_compare_exchange_n(&g->state, &expected,
            (UInt32)r17tx::kPending, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            __atomic_fetch_add(&p->completed, 1u, __ATOMIC_RELAXED);
        /* If the state was still kPosting the CAS fails on purpose: the commit
         * step owns that transition and will see doneSeen. */
    }
}

/* Ordinary descriptors the device still owns. The ring occupancy is
 * (txNext - txDirty) mod kNumTxDesc; the SELECTED generations occupy one ring
 * run each, and those are not "ordinary" traffic (the probe tracks them by
 * owner/handle instead). Everything else in the ring is an ordinary packet this
 * driver submitted and must keep translating correctly.
 *
 * Round23: sum over ALL live generations. Subtracting one generation's count
 * was right only while one could be live.
 *
 * This is a ring fact read without taking the driver's exclusion: the two
 * indices are independently published, so a concurrent harvest can only make
 * the answer look newer by one slot, never invent occupancy. It is used for a
 * bounded drain loop, and the loop re-reads the close pointer anyway, so a
 * racing read cannot turn a busy ring into "drained". */
UInt32 RTL8125::r17TxOutstanding()
{
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    UInt32 occ = (txNextDescIndex - txDirtyDescIndex) & kTxDescMask;
    if (!p) return occ;
    UInt32 sel = 0;
    for (UInt32 k = 0; k < r17tx::kSlots; k++) {
        R17Gen *g = &p->gens[k];
        const UInt32 state = __atomic_load_n(&g->state, __ATOMIC_ACQUIRE);
        if (state == r17tx::kIdle || state == r17tx::kMapping ||
            state == r17tx::kControl) continue;
        sel += __atomic_load_n(&g->request.count, __ATOMIC_ACQUIRE);
    }
    /* Selected slots still owned by hardware are a subset of the occupancy. */
    return occ > sel ? occ - sel : 0;
}

/* Round23: how many generations still hold an mbuf. The probe reads this as the
 * owner count; retirement is complete only when it reaches zero, which is what
 * makes "all owners returned" a checked fact rather than "no error was
 * reported". */
UInt32 RTL8125::r17TxLiveGens()
{
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    if (!p) return 0;
    UInt32 n = 0;
    for (UInt32 k = 0; k < r17tx::kSlots; k++) {
        const UInt32 state = __atomic_load_n(&p->gens[k].state, __ATOMIC_ACQUIRE);
        if (state != r17tx::kIdle && state != r17tx::kControl) n++;
    }
    return n;
}

/* Window gate. quiesce=true: CLOSE the admission word and report the facts the
 * probe needs in order to decide whether the window may be flipped:
 *
 *     inFlight  -- admitted submissions that have not set OWN yet
 *     ringOwn   -- total descriptor occupancy (selected slots included)
 *
 * It is IDEMPOTENT and it NEVER WAITS. The probe polls it from its own thread,
 * because the wait belongs there: this driver's workloop is what reaps
 * completed descriptors, so sleeping here to wait for a drain would wait for
 * itself. (Round 21 made the repeat a success for the same reason -- a repeat
 * is the same request re-asserted, not a state error.)
 *
 * quiesce=false: OPEN it again, and only from the exact "closed with no
 * reference" state. A resume with references still held would let the probe
 * restore the device table under a submission it has not accounted for.
 */
IOReturn RTL8125::r17TxGate(bool quiesce)
{
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    if (!p) return kIOReturnNotReady;
    if (!quiesce) {
        UInt32 expected = 0x80000000u;
        if (!__atomic_compare_exchange_n(&r17Admit, &expected, 0u, false,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            __atomic_fetch_add(&p->gateFails, 1u, __ATOMIC_RELAXED);
            return kIOReturnBusy;
        }
        p->windowResumed++;
        p->edgeSeq++;
        p->tEdge = mach_absolute_time();
        p->tResume = p->tEdge;
        __atomic_store_n(&p->gate, 0u, __ATOMIC_RELEASE);
        /* Round22: the resume does NOT take a block sample.
         *
         * It is a window edge, so round 21's rule ("only an edge may replace a
         * non-throttled record") let it overwrite the exit record -- and the
         * exit record is the one the analysis consumes (it is taken while the
         * device still owns nothing and the table is still installed). The
         * resume is recorded by tEdge/tResume, which is all it needs to say.
         * kStageResumed stays a valid explicit kSample stage. */
        return kIOReturnSuccess;
    }
    /* fetch_or so the reference count is preserved exactly; only the transition
     * stamps the edge and re-arms the two latches. */
    const UInt32 prev = __atomic_fetch_or(&r17Admit, 0x80000000u, __ATOMIC_ACQ_REL);
    if (!(prev & 0x80000000u)) {
        p->windowQuiesce++;
        p->edgeSeq++;
        p->tGateClose = mach_absolute_time();
        p->tEdge = p->tGateClose;
        p->tSubmitDone = 0;
        p->tDrainDone = 0;
        __atomic_store_n(&p->gate, 1u, __ATOMIC_RELEASE);
        r17TxSample(r20tx::kStageQuiesce);
    }
    /* Latch the two boundaries. "First observation" IS the definition: a later
     * poll must not move a boundary, which is what makes the record name the
     * event instead of the last time somebody looked.
     *
     * inFlight is checked first on purpose. txNextDescIndex is advanced inside
     * the admitted region, so a descriptor that is still between the gate and
     * its OWN bit is already counted by ringOwn; requiring inFlight==0 first
     * means the occupancy read cannot be made stale by a submission that is
     * still mid-commit. */
    if (!p->tSubmitDone && r17TxRefs() == 0)
        p->tSubmitDone = mach_absolute_time();
    if (!p->tDrainDone && r17TxRefs() == 0 && r17TxRingOwn() == 0) {
        p->tDrainDone = mach_absolute_time();
        p->windowDrained++;
    }
    return kIOReturnSuccess;
}

/* Shared read-out for every control op that reports the window. Values are
 * loaded once each into the caller's Configure; nothing here allocates. */
void RTL8125::r17TxReport(r17tx::Configure *c)
{
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    if (!p) return;
    c->quiesced = __atomic_load_n(&p->gate, __ATOMIC_ACQUIRE);
    c->inFlight = r17TxRefs();
    c->ringOwn = r17TxRingOwn();
    c->outstanding = r17TxOutstanding();
    c->activeCover = __atomic_load_n(&p->coverActive, __ATOMIC_ACQUIRE);
    c->held = __atomic_load_n(&p->held, __ATOMIC_ACQUIRE);
    c->modeReserved = r17TxLiveGens(); /* native v7: independent live-generation count */
    c->gateFails = __atomic_load_n(&p->gateFails, __ATOMIC_RELAXED);
    c->barrierFails = __atomic_load_n(&p->barrierFails, __ATOMIC_RELAXED);
    c->edgeSeq = p->edgeSeq;
    c->tEdge = p->tEdge;
    c->tSubmitDone = p->tSubmitDone;
    c->tDrainDone = p->tDrainDone;
    c->tResume = p->tResume;
}
/* Round 21: force a ring sample for a specific window step. Unlike
 * r17TxPublish's throttled path this always samples, so "the block was taken at
 * the exit" is a fact about the call site rather than an inference from a
 * signature.
 *
 * Round 22: the sample is a bounded VALUE COPY and nothing else. It runs inside
 * the command gate, so it must not allocate (the OSData publication moved to
 * r17TxPublishBlock, which only the timer calls) and it must not dereference an
 * mbuf (the poller may have reaped that slot -- see the mbuf note below).
 */
void RTL8125::r17TxSample(UInt32 stage)
{
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    if (!p) return;
    /* Round 21: the throttled 10 ms tick must not overwrite a window-edge
     * sample. The first hardware run of this round ended with sampleStage=0
     * even though the exit sample had been taken correctly, because the
     * publish that follows r17Finish re-sampled at stage 0 -- which makes the
     * record indistinguishable from the round-20 bug it exists to fix. Only
     * the window edges (and their own retries) may replace a non-throttled
     * record; throttled samples may only fill a throttled or empty one. */
    if (stage == r20tx::kStageThrottled) {
        const UInt32 prev = p->blockSnap.sampleStage;
        if (prev != r20tx::kStageThrottled) return;
    }
    /* The values are copied into a LOCAL block and published afterwards:
     * sampling must not leave a half-filled record visible, and the OSData
     * allocation below is outside whatever exclusion the caller holds. */
    r20tx::Block b;
    bzero(&b, sizeof(b));
    /* Round23: the record keeps describing ONE generation (the newest live one)
     * because its layout is pinned and consumed by the analyzer, but it now also
     * reports how many are live, so "the sample says one generation" can never
     * be mistaken for "only one exists". */
    R17Gen *g = r17txNewestLive(p);
    const UInt32 state = g ? __atomic_load_n(&g->state, __ATOMIC_ACQUIRE)
                           : (UInt32)r17tx::kIdle;
    b.magic = r20tx::kMagic; b.version = r20tx::kVersion;
    b.bytes = sizeof(b); b.bdf = p->bdf; b.token = p->token;
    b.state = state;
    b.txNext = txNextDescIndex; b.txDirty = txDirtyDescIndex;
    b.txClose = txClosePtr0; b.txTail = txTailPtr0;
    b.txFree = (UInt32)txNumFreeDesc; b.txDescDone = txDescDoneCount;
    b.completeCalls = __atomic_load_n(&p->completeCalls, __ATOMIC_RELAXED);
    b.completeHits = __atomic_load_n(&p->completeHits, __ATOMIC_RELAXED);
    b.lastSeenSlot = p->lastSeenSlot;
    b.firstSlot = txDirtyDescIndex;
    b.liveHandle = g ? (UInt32)g->stdHandle : 0;
    b.liveReq = g ? g->request.reqId : 0;
    b.liveCount = g ? g->request.count : 0;
    b.liveSegs = g ? g->request.count : 0;
    b.liveMbufs = g ? g->stdW.mbufSegments : 0;
    b.liveFlags = (g && (g->stdW.flags & r18std::kMapped)) ? 1u : 0u;
    if (g && (g->stdW.flags & r18std::kUnmapped)) b.liveFlags |= 2u;
    if (g && (g->stdW.flags & r18std::kPinned)) b.liveFlags |= 4u;
    b.outstanding = (txNextDescIndex - txDirtyDescIndex) & kTxDescMask;
    b.tSample = mach_absolute_time();
    b.ringAddr = txPhyAddr;
    b.ringBytes = (UInt32)kTxDescSize;
    b.ringDescSize = (UInt32)sizeof(RtlTxDesc);
    UInt32 at = 0;
    auto put = [&](UInt32 slot) {
        if (at >= r20tx::kSlots) return;
        RtlTxDesc *d = &txDescArray[slot];
        r20tx::Slot &o = b.slots[at++];
        o.index = slot;
        o.addr = OSSwapLittleToHostInt64(d->addr);
        o.opts1 = OSSwapLittleToHostInt32(d->opts1);
        o.opts2 = OSSwapLittleToHostInt32(d->opts2);
        /* Round23: a slot is "selected" if ANY live generation's descriptor run
         * covers it. Round 22 tested against the single generation; with several
         * live, testing one would mark the others' slots as ordinary traffic. */
        for (UInt32 k = 0; k < r17tx::kSlots; k++) {
            R17Gen *gk = &p->gens[k];
            if (__atomic_load_n(&gk->state, __ATOMIC_ACQUIRE) == r17tx::kIdle)
                continue;
            const UInt32 n = __atomic_load_n(&gk->request.count, __ATOMIC_ACQUIRE);
            if (n && ((slot - gk->current.firstSlot) & kTxDescMask) < n) {
                o.flags |= r20tx::kSelected;
                break;
            }
        }
        /* Round 22: the mbuf POINTER is copied, never dereferenced.
         *
         * Round 21 called mbuf_data()/mbuf_len() here. Those run on the probe's
         * thread while the poller can reap the very same slot and free the
         * mbuf, so the sample could read freed memory -- and it did so from a
         * control op that claims not to touch driver-owned objects. Only the
         * pointer value is recorded now; it is a correlation key against the
         * driver's own dump, never something to follow. mbufLen stays 0 for the
         * same reason: reading it needs the dereference that is the bug. */
        mbuf_t bm = txMbufArray[slot];
        if (bm) o.flags |= r20tx::kHasMbuf;
        o.mbufData = (UInt64)(uintptr_t)bm;
        o.mbufLen = 0;
        if (o.opts1 & DescOwn) o.flags |= r20tx::kOwn;
        if (o.opts1 & FirstFrag) o.flags |= r20tx::kFirst;
        if (o.opts1 & LastFrag) o.flags |= r20tx::kLast;
        if (slot == kTxLastDesc) o.flags |= r20tx::kRingEnd;
    };
    if (b.outstanding) {
        for (UInt32 i = 0; i < 8; i++)
            put((txDirtyDescIndex + i) & kTxDescMask);
        if (b.outstanding > 8)
            for (UInt32 i = b.outstanding - 8; i < b.outstanding; i++)
                put((txDirtyDescIndex + i) & kTxDescMask);
        const UInt32 n = b.outstanding < r20tx::kOutstanding
            ? b.outstanding : r20tx::kOutstanding;
        for (UInt32 i = 0; i < n; i++) {
            const UInt32 slot = (txDirtyDescIndex + i) & kTxDescMask;
            b.outAddr[i] = OSSwapLittleToHostInt64(txDescArray[slot].addr);
            b.outOpts1[i] = OSSwapLittleToHostInt32(txDescArray[slot].opts1);
        }
    }
    b.nslot = at;
    p->coverGen++;
    b.sampleStage = stage;
    b.sampleSeq = p->coverGen;
    b.quiesced = __atomic_load_n(&p->gate, __ATOMIC_ACQUIRE);
    b.activeCover = __atomic_load_n(&p->coverActive, __ATOMIC_ACQUIRE);
    b.coverCalls = __atomic_load_n(&p->coverCalls, __ATOMIC_RELAXED);
    b.coverRejects = __atomic_load_n(&p->coverRejects, __ATOMIC_RELAXED);
    p->blockSnap = b;
    /* Round 22: NO OSData allocation here.
     *
     * This function runs inside the driver's command gate (kSample/kQuiesce) or
     * in the 10 ms timer. Allocating a 2320-byte OSData and publishing it from
     * there is exactly the "allocation inside the protected region" the window
     * protocol is supposed to avoid. The record is copied into the state under
     * the gate and handed to r17TxPublishBlock(), which the TIMER runs -- a
     * context that holds no gate and can allocate.
     *
     * The flag is a value store, not a lock: a second forced sample before the
     * timer fires simply leaves the newer record available, which is the one
     * that matters (a later stage supersedes an earlier one, and the throttled
     * filter above already prevents a tick from replacing an edge record). */
    __atomic_store_n(&p->blockPublish, 1u, __ATOMIC_RELEASE);
}
/* Round22: publish the record r17TxSample copied. Called ONLY from the 10 ms
 * timer, i.e. outside the command gate, so the OSData allocation this needs is
 * not performed in a control-op/protected region. A separate function (instead
 * of a tail call in r17TxPublish) is deliberate: r17TxPublish returns early
 * when nothing observable changed, and a forced edge sample must still be
 * published in that case. */
void RTL8125::r17TxPublishBlock()
{
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    if (!p) return;
    if (!__atomic_exchange_n(&p->blockPublish, 0u, __ATOMIC_ACQ_REL)) return;
    OSData *bd = OSData::withBytes(&p->blockSnap, sizeof(p->blockSnap));
    if (bd) { setProperty("rtl812x-txmap-block-raw", bd); bd->release(); }
}

void RTL8125::r17TxPublish()
{
    R17TxState *p = r17Tx;
    if (!p) return;
    UInt32 retired = __atomic_load_n(&p->retired, __ATOMIC_RELAXED);
    /* Round23: the driver no longer has one state to publish, so the signature
     * uses the number of live generations plus the retirement counter. Both move
     * when anything observable about the set of mappings changes. */
    UInt32 live = r17TxLiveGens();
    UInt32 dropped = __atomic_load_n(&p->dropped, __ATOMIC_RELAXED);
    UInt32 rejected = __atomic_load_n(&p->rejected, __ATOMIC_RELAXED);
    /* The snapshot is ~17 KB. Re-publishing it on every 10 ms tick for an
     * unchanged run would allocate continuously in the kernel for no evidence
     * gain, so publish only when something a reader can observe changed. The
     * Disarm/Detach entry point always ends with a publish, which is the one
     * the probe archives. */
    UInt32 sig = retired * 37u + live * 7u + dropped * 3u + rejected;
    if (p->lastSig && sig == p->lastSig) return;
    p->lastSig = sig;
    /* Ring/cover motion is NOT part of the signature (round 20 shipped that
     * bug: a sample could be 9 s stale and still be reported as the exit one).
     * The throttled path therefore only ever produces kStageThrottled records;
     * the window edges call r17TxSample() directly and always publish. */
    r17TxSample(r20tx::kStageThrottled);
    setProperty("rtl812x-txmap-mode", p->stdMode
        ? "native-mbuf-standard-iomapper-v1"
        : "native-mbuf-explicit-iova-v1");
    setProperty("R26TxMode", p->allTx ? "all-standard" :
                (p->stdMode ? "selected-standard" : "selected-direct"));
    setProperty("R26TxMapped", (UInt64)__atomic_load_n(&p->mapped, __ATOMIC_RELAXED), 32);
    setProperty("R26TxUnmarked", (UInt64)__atomic_load_n(&p->unmarked, __ATOMIC_RELAXED), 32);
    setProperty("R26TxLegacySelected", (UInt64)__atomic_load_n(&p->legacySelected, __ATOMIC_RELAXED), 32);
    setProperty("R26TxAttempts", (UInt64)__atomic_load_n(&p->mapAttempts, __ATOMIC_RELAXED), 32);
    if (p->stdMode) {
        r18std::Snapshot &ss = p->stdSnap;
        ss.magic = r18std::kMagic; ss.version = r18std::kVersion;
        ss.bytes = sizeof(ss); ss.bdf = p->bdf; ss.token = p->token;
        ss.mode = p->allTx ? r17tx::kModeAllStandard : r17tx::kModeStandard;
        ss.accepts = __atomic_load_n(&p->stdAccepts, __ATOMIC_RELAXED);
        ss.rejects = __atomic_load_n(&p->stdRejects, __ATOMIC_RELAXED);
        ss.unsupported = __atomic_load_n(&p->stdUnsupported, __ATOMIC_RELAXED);
        ss.unmaps = __atomic_load_n(&p->stdUnmaps, __ATOMIC_RELAXED);
        ss.pinned = __atomic_load_n(&p->stdPinned, __ATOMIC_RELAXED);
        ss.maxHeld = __atomic_load_n(&p->maxHeld, __ATOMIC_RELAXED);
        ss.historyTotal = __atomic_load_n(&p->stdRecordCursor, __ATOMIC_ACQUIRE);
        ss.count = ss.historyTotal > r18std::kMax ? r18std::kMax : ss.historyTotal;
        ss.historyStart = ss.historyTotal - ss.count;
        ss.highReqAccepts = __atomic_load_n(&p->stdHighReqAccepts, __ATOMIC_RELAXED);
        ss.tPublished = mach_absolute_time();
        OSData *sd = OSData::withBytes(&ss, sizeof(ss));
        if (sd) { setProperty("rtl812x-txmap-std-raw", sd); sd->release(); }
    }
    setProperty("rtl812x-txmap-cover-calls",
                (UInt64)__atomic_load_n(&p->coverCalls, __ATOMIC_RELAXED), 32);
    setProperty("rtl812x-txmap-cover-rejects",
                (UInt64)__atomic_load_n(&p->coverRejects, __ATOMIC_RELAXED), 32);
    setProperty("rtl812x-txmap-held", (UInt64)__atomic_load_n(&p->held, __ATOMIC_ACQUIRE), 32);
    setProperty("rtl812x-txmap-max-held", (UInt64)__atomic_load_n(&p->maxHeld, __ATOMIC_RELAXED), 32);
    setProperty("rtl812x-txmap-rejected", (UInt64)rejected, 32);
    p->snapshot.magic = 0x37315854; p->snapshot.version = r17tx::kVersion;
    p->snapshot.bytes = sizeof(p->snapshot); p->snapshot.bdf = p->bdf;
    p->snapshot.token = p->token;
    p->snapshot.dropped = dropped;
    /* Round23: the snapshot describes a set of generations, not one state. The
     * field stays in the pinned layout; 0 (Idle) is the honest value once it
     * is no longer a per-driver fact. */
    p->snapshot.state = (UInt32)r17tx::kIdle;
    p->snapshot.retired = retired;
    p->snapshot.rejected = rejected;
    p->snapshot.maxHeld = __atomic_load_n(&p->maxHeld, __ATOMIC_RELAXED);
    p->snapshot.count = retired > r17tx::kMaxRequests ? r17tx::kMaxRequests : retired;
    p->snapshot.historyStart = retired - p->snapshot.count;
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
 * -> release the standard objects -> free THIS packet's mbuf -> slot reusable.
 * The caller holds NO driver exclusion when this runs.
 *
 * Round23: this is per GENERATION. Round 22 wrote into `p->current` and reset
 * the driver-wide `stdHandle`, which was unambiguous only while one generation
 * could be live; with several live it would overwrite another request's witness
 * and clear a handle it does not own. */
void RTL8125::r17TxRetire(R17TxState *p, R17Gen *g, UInt64 handle)
{
    IOReturn result;
    if (p->stdMode) {
        result = r17TxStdComplete(p, g);
    } else {
        result = p->callback(p->context, r17tx::kRetire, &g->request);
    }
    if (result == kIOReturnSuccess) {
        mbuf_t done = g->packet;
        g->current.request = g->request;
        g->current.request.handle = handle;
        g->current.retired = 1;
        /* The device's own final words for this generation, read before the
         * slot can be reused (this runs in the retire tick). */
        for (UInt32 i = 0; i < g->request.count; i++)
            g->current.doneOpts1[i] = OSSwapLittleToHostInt32(
                txDescArray[(g->current.firstSlot + i) & kTxDescMask].opts1);
        g->request.handle = 0;
        g->packet = NULL;
        __atomic_fetch_sub(&p->held, 1u, __ATOMIC_ACQ_REL);
        if (p->stdMode) {
            if (g->stdCmd) { g->stdCmd->clearMemoryDescriptor(false);
                             g->stdCmd->release(); g->stdCmd = nullptr; }
            if (g->stdMD && g->stdWired) g->stdMD->complete(kIODirectionOut);
            if (g->stdMD) { g->stdMD->release(); g->stdMD = nullptr; }
            g->stdWired = false;
        }
        /* Retire succeeded, so the mapping is gone and its window slot is
         * reusable. The mbuf is released per packet here -- NOT held to Detach
         * -- and tFree is stamped after EVERY release of this generation. The
         * witness is recorded only AFTER tFree, otherwise it would carry a zero
         * free time and no order could be checked. */
        if (done) freePacket(done);
        g->current.tFree = mach_absolute_time();
        if (p->stdMode) {
            g->stdW.tFree = g->current.tFree;
            if (g->stdW.flags & r18std::kMapped) {
                g->stdW.flags |= r18std::kUnmapped;
                /* Round23: append in RETIRE order. The round-19..22 code indexed
                 * by handle, which assumed handle order == retire order; with
                 * overlapping generations the OLDER one retires first, so
                 * indexing by handle would leave holes and overwrite witnesses. */
                const UInt32 at = __atomic_load_n(&p->stdRecordCursor,
                                                  __ATOMIC_RELAXED);
                p->stdSnap.witnesses[at % r18std::kMax] = g->stdW;
                __atomic_store_n(&p->stdRecordCursor, at + 1, __ATOMIC_RELEASE);
                p->stdSnap.historyTotal = at + 1;
                p->stdSnap.count = at + 1 > r18std::kMax ? r18std::kMax : at + 1;
                p->stdSnap.historyStart = at + 1 - p->stdSnap.count;
                __atomic_fetch_add(&p->stdUnmaps, 1u, __ATOMIC_RELAXED);
            }
            g->stdHandle = 0;
        }
        UInt32 n = __atomic_load_n(&p->retired, __ATOMIC_RELAXED);
        p->snapshot.witnesses[n % r17tx::kMaxRequests] = g->current;
        n++; __atomic_store_n(&p->retired, n, __ATOMIC_RELAXED);
        p->snapshot.count = n > r17tx::kMaxRequests ? r17tx::kMaxRequests : n;
        p->snapshot.historyStart = n - p->snapshot.count;
        /* The slot is free only AFTER the mapping is gone: this store is what
         * lets the next Map claim it, and it must not happen one instruction
         * earlier. */
        __atomic_store_n(&g->state, (UInt32)r17tx::kIdle, __ATOMIC_RELEASE);
    } else {
        /* The unmap/invalidation is not confirmed: keep handle, standard
         * objects and mbuf, and park THIS generation. A failed retire is never
         * reported as recycled, and the other live generations are untouched. */
        g->request.handle = handle;
        if (p->stdMode && !(g->stdW.flags & r18std::kPinned)) {
            g->stdW.flags |= r18std::kPinned;
            __atomic_fetch_add(&p->stdPinned, 1u, __ATOMIC_RELAXED);
        }
        __atomic_store_n(&g->state, (UInt32)r17tx::kPending, __ATOMIC_RELEASE);
    }
}

void RTL8125::r17TxTimer(IOTimerEventSource *timer)
{
    R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
    if (!p) return;
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
     * invalidation wait.
     *
     * Round23: the harvest is needed while ANY generation is still waiting for
     * its completion. */
    bool needHarvest = false;
    for (UInt32 k = 0; k < r17tx::kSlots; k++) {
        R17Gen *g = &p->gens[k];
        const UInt32 state = __atomic_load_n(&g->state, __ATOMIC_ACQUIRE);
        if ((state == r17tx::kPosting || state == r17tx::kSubmitted) &&
            !__atomic_load_n(&g->doneSeen, __ATOMIC_ACQUIRE)) {
            needHarvest = true;
            break;
        }
    }
    if (needHarvest) {
        if (!test_and_set_bit(__POLLING, &stateFlags)) {
            txInterrupt();
            clear_bit(__POLLING, &stateFlags);
        }
        /* else: a poller or the interrupt handler owns the ring walk; this
         * tick deliberately does not enter it. */
    }
    /* Retire every generation that is ready, oldest slot first. Each transition
     * is its own CAS, so a generation that is not ready is simply left alone. */
    for (UInt32 k = 0; k < r17tx::kSlots; k++) {
        R17Gen *g = &p->gens[k];
        UInt32 state = __atomic_load_n(&g->state, __ATOMIC_ACQUIRE);
        if (state == r17tx::kSubmitted &&
            __atomic_load_n(&g->doneSeen, __ATOMIC_ACQUIRE)) {
            UInt32 expected = r17tx::kSubmitted;
            if (__atomic_compare_exchange_n(&g->state, &expected,
                (UInt32)r17tx::kPending, false, __ATOMIC_ACQ_REL,
                __ATOMIC_ACQUIRE))
                __atomic_fetch_add(&p->completed, 1u, __ATOMIC_RELAXED);
        }
        /* A failed standard retirement is terminal for this generation. The
         * command may have dropped its mapping bookkeeping; re-entering it
         * cannot establish that the retained backend owner was unmapped. The
         * acquire load also covers pinned post-prepare rollback publication. */
        state = __atomic_load_n(&g->state, __ATOMIC_ACQUIRE);
        if (state != r17tx::kPending ||
            (p->stdMode && (g->stdW.flags & r18std::kPinned))) continue;
        UInt32 pending = r17tx::kPending;
        if (__atomic_compare_exchange_n(&g->state, &pending,
            (UInt32)r17tx::kRetiring, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            r17TxRetire(p, g, g->request.handle);
    }
    r17TxWakeOutput();
    r17TxPublish();
    r17TxPublishBlock();
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
    UInt32 live = 0;
    for (UInt32 k = 0; k < r17tx::kSlots; k++)
        if (__atomic_load_n(&p->gens[k].state, __ATOMIC_ACQUIRE) != r17tx::kIdle)
            live++;
    IOLog("r17 TX stop: live=%u handle=%llu held=%u (nonidle retained fail-closed)\n",
          live,
          (unsigned long long)(live ? p->gens[0].request.handle : 0),
          __atomic_load_n(&p->held, __ATOMIC_RELAXED));
}
'''

HOOKS = (
    'if (!r17TxMap(m, txSegments, numSegs)) continue;',
    'r17TxComplete(txDirtyDescIndex);', 'r17TxPosted(m);',
    'r17TxStop();', 'r17Tx = NULL;',
    'functionName->isEqualTo(r17tx::kFunctionName)',
    'txMbufArray[index] = (p && r17TxFindByPacket(p, m)) ? NULL : m;',
    'r17TxOutputReady() && interface->dequeueOutputPackets(',
    'result = (r17TxOutputReady() && (txNumFreeDesc > (kMaxSegs + 3)))')


def patch_cpp(text):
    def once(old, new):
        nonlocal text
        assert text.count(old) == 1, old
        text = text.replace(old, new, 1)
    once('        r15Pool = NULL;\n', '        r15Pool = NULL;\n        r17Tx = NULL;\n')
    stop = text.index('void RTL8125::stop(IOService *provider)')
    end = text.index('    if (workLoop)', stop)
    text = text[:end] + '    r17TxStop();\n' + text[end:]
    # Backpressure must precede dequeue (the queue still owns the fifth mbuf).
    once('(interface->dequeueOutputPackets(1, &m, NULL, NULL, NULL) == kIOReturnSuccess)',
         '(r17TxOutputReady() && interface->dequeueOutputPackets(1, &m, NULL, NULL, NULL) == kIOReturnSuccess)')
    # IOKit must see a resource stall, not success with packets still queued.
    # Recheck capacity at the tail as well: publishing the fourth packet may
    # have consumed the final slot even if the dequeue loop ended otherwise.
    once('    result = (txNumFreeDesc > (kMaxSegs + 3)) ? kIOReturnSuccess : kIOReturnNoResources;',
         '    result = (r17TxOutputReady() && (txNumFreeDesc > (kMaxSegs + 3))) ? kIOReturnSuccess : kIOReturnNoResources;')
    # Mapping happens after the real physical segments are known and before the
    # ring reservation / descriptor fill / first OWN of this packet.
    once('        OSAddAtomic(-numSegs, &txNumFreeDesc);',
         '        if (!r17TxMap(m, txSegments, numSegs)) continue;\n'
         '        OSAddAtomic(-numSegs, &txNumFreeDesc);')
    once('                txMbufArray[index] = m;',
         '                /* Round23: the mbuf belongs to a selected generation, so the\n'
         '                 * TX ring must not own it as well -- the per-packet recycle\n'
         '                 * path is its only owner. Several generations can be live, so\n'
         '                 * the test is "does ANY of them hold this mbuf". */\n'
         '                R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);\n'
         '                txMbufArray[index] = (p && r17TxFindByPacket(p, m)) ? NULL : m;')
    once('        firstDesc->opts1 |= DescOwn;',
         '        firstDesc->opts1 |= DescOwn;\n        r17TxPosted(m);')
    once('        m = txMbufArray[txDirtyDescIndex];',
         '        r17TxComplete(txDirtyDescIndex);\n        m = txMbufArray[txDirtyDescIndex];')
    # The struct definitions must come before outputStart's ownership check.
    #
    # Round23: R17TxState now CONTAINS an array of R17Gen by value, so the two
    # must move together -- slicing only R17TxState would leave its member type
    # undefined at the point of use. The block therefore starts at R17Gen (which
    # is the first of the pair in the template) and ends at the close of
    # R17TxState -- searching for the END from R17TxState's own start, because a
    # naive '\n};' search from R17Gen stops at R17Gen's own close and moves a
    # half-struct (that is exactly what happened on the first attempt).
    start = text.index('struct RTL8125::R17Gen {')
    end = text.index('\n};', text.index('struct RTL8125::R17TxState {')) + 3
    assert text.count('struct RTL8125::R17Gen {') == 1
    struct = text[start:end]
    assert 'struct RTL8125::R17TxState {' in struct and struct.rstrip().endswith('};')
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
