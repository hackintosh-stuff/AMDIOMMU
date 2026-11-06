"""Driver-owned RX mappings on Lucy's normal replacement path.

The ordinary non-VTD receive loop stays in use. Each ring slot owns one virtual
MD/command pair. Completion retires its mapping before replaceOrCopyPacket can
deliver the old mbuf; the replacement is mapped before the next OWN publication.
The existing ring is prepared directly without an R15 pool. Round36 batches
up to sixteen already completed slots, without waiting across poll calls.
Round37 exports the driver's actual TX/RX descriptor and tally spans so the
bootstrap table can map only these objects and the frozen RX buffers.
Round38 retires the RX bootstrap aliases once all slots have actually
published their first IOVA OWN, after completing the current batch.
Round39 stops the NIC before retiring the final mappings, without peer tail
traffic, and restarts the physical ring after the original IOMMU state returns.
Round40 also maps Lucy's existing descriptor rings and tally buffer through
three persistent standard DMA commands, using the same stopped-NIC transition.
Round42 posts every initial RX mapping while the NIC is stopped and retires
the bootstrap identity aliases before enabling any IOVA receive traffic.
Round43 stops before changing the DTE and resumes physical DMA only after
restoring the original IOMMU state. The translated lifetime needs no identity
aliases; Authorize captures the fully mapped IOVA table before enabling DMA.
The older RX4 path remains selectable from its original template.
"""
from pathlib import Path
import runpy

BASE = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'base/driver-template.py'))
HEADERS = BASE['HEADERS'] + ['RTL812xRxNative.hpp', 'RTL812xFixedDma.hpp']
MEMBERS = BASE['MEMBERS'] + r'''
    struct R34RxState;
    R34RxState *r34Rx = nullptr;
    static IOReturn r34RxAction(OSObject *, void *, void *, void *, void *);
    IOReturn r34RxControl(r34rx::Request *);
    bool r34RxBinding(UInt32, UInt32, r34rx::MapRecord *, UInt64 = 0);
    bool r34RxPrepareSlot(UInt32);
    bool r34RxFinishMapSlot(UInt32);
    bool r34RxMapSlot(UInt32);
    bool r34RxUnmapSlot(UInt32);
    bool r34RxRecordDone(UInt32, UInt64, UInt32, UInt32);
    bool r34RxComplete(UInt32, UInt64, UInt32, UInt32);
    bool r36RxBatchCall(UInt32, UInt32, UInt32);
    bool r36RxBeginBatch(UInt32, UInt32);
    bool r36RxPublish(UInt32, UInt64, UInt64, UInt64);
    bool r43RxCaptureActive();
    bool r42RxPostInitial();
    bool r39RxPaused() const;
    bool r39RxStop();
    IOReturn r39RxResume();
    UInt64 r40FixedRegister(UInt32);
    bool r40FixedBinding(UInt32, UInt32, r34rx::MapRecord * = nullptr, UInt64 = 0);
    bool r43StopBeforeDte();
    bool r40FixedInstall();
    IOReturn r40FixedActivate();
    bool r40FixedRetire();
    bool r40FixedRelease();
    bool r34RxRearm(UInt32, UInt32, UInt32, bool, UInt64 *);
    void r34RxPosted(UInt32, UInt64);
    bool r34RxCanReplace() const;
    mbuf_t r34RxCopy(mbuf_t, UInt32);
    bool r34RxObserve(UInt32, UInt32, UInt32);
    bool r34RxFree();
    void r34RxInvalidate();
    bool r34RxParse(mbuf_t, UInt32 *, UInt32 *);
'''

METHODS = r'''
#pragma mark --- driver-owned normal RX ring and replacement ---

struct RTL8125::R34RxState {
    r34rx::Snapshot snapshot;
    IOMapper *mapper;
    void *context;
    r34rx::Callback callback;
    IOMemoryDescriptor *memory[r34rx::kCount];
    IODMACommand *command[r34rx::kCount];
    IOAddressRange ranges[r34rx::kCount];
    bool bound[r34rx::kCount], wired[r34rx::kCount], mapped[r34rx::kCount];
    r34rx::Witness current[r34rx::kCount];
    UInt32 generation;
    UInt32 keepTx[kNumTxDesc], filtered[5];
    UInt64 tPrepared, tAuthorized, tPhysicalResumed;
    bool authorized, physicalResumed;
    UInt32 batchFirst, batchCount, batchQueued;
    UInt32 batches, batchSlots, maxBatch;
    UInt64 batchOld[r34rx::kBatchSize], batchWord[r34rx::kBatchSize];
    UInt32 firstIovaSlots;
    UInt64 tLastFirstIovaPost, tActiveReady;
    bool activeCaptureAttempted, activeCaptured;
    r34rx::StopRecord stop;
    bool hardwarePaused;
    r40fixed::DriverSnapshot fixed;
    IOMemoryDescriptor *fixedMemory[r40fixed::kCount];
    IODMACommand *fixedCommand[r40fixed::kCount];
    IOAddressRange fixedRanges[r40fixed::kCount];
    bool fixedBound[r40fixed::kCount], fixedWired[r40fixed::kCount];
    bool fixedMapped[r40fixed::kCount], entryRebuilding;
    UInt32 irqPending, irqMasked, irqArmed, irqExpected;
};

bool RTL8125::r34RxBinding(UInt32 op, UInt32 slot,
                         r34rx::MapRecord *out, UInt64 pa)
{
    R34RxState *p = r34Rx;
    if (!p || slot >= r34rx::kCount || !p->callback) return false;
    r34rx::Binding b = {};
    b.version = r34rx::kVersion; b.bytes = sizeof(b); b.op = op; b.slot = slot;
    b.memory = p->memory[slot]; b.command = p->command[slot];
    b.pa = pa; b.length = r34rx::kCapacity;
    const IOReturn kr = p->callback(p->context, &b);
    if (kr != kIOReturnSuccess) return false;
    if (out) *out = b.out;
    return true;
}

bool RTL8125::r34RxPrepareSlot(UInt32 slot)
{
    R34RxState *p = r34Rx;
    auto &s = p->snapshot;
    IOMemoryDescriptor *md = p->memory[slot];
    if (p->mapped[slot] || p->wired[slot]) return false;
    p->ranges[slot].address = (IOVirtualAddress)mbuf_datastart(rxBufArray[slot].mbuf);
    p->ranges[slot].length = r34rx::kCapacity;
    if (!md->initWithOptions(&p->ranges[slot], 1, 0, kernel_task,
            kIOMemoryTypeVirtual | kIODirectionIn | kIOMemoryAsReference, p->mapper) ||
        md->prepare(kIODirectionIn) != kIOReturnSuccess) {
        s.flags |= r34rx::kFlagMapFailed;
        return false;
    }
    p->wired[slot] = true;
    return true;
}

bool RTL8125::r34RxFinishMapSlot(UInt32 slot)
{
    R34RxState *p = r34Rx;
    auto &s = p->snapshot;
    auto &w = p->current[slot];
    IOMemoryDescriptor *md = p->memory[slot];
    IODMACommand *cmd = p->command[slot];
    if (!p->wired[slot] || p->mapped[slot]) return false;
    // A batch pre-map has already completed invalidation. The ordinary
    // callback claims that confirmed mapping; scalar calls map synchronously.
    if (cmd->setMemoryDescriptor(md, true) != kIOReturnSuccess) {
        s.flags |= r34rx::kFlagMapFailed;
        return false;
    }
    p->mapped[slot] = true;
    r34rx::MapRecord record = {};
    IODMACommand::Segment64 segment = {};
    UInt64 offset = 0;
    UInt32 count = 1;
    if (!r34RxBinding(r34rx::kRead, slot, &record) ||
        !(record.flags & r34rx::kMapInvalidated) ||
        cmd->gen64IOVMSegments(&offset, &segment, &count) != kIOReturnSuccess ||
        count != 1 || offset != r34rx::kCapacity ||
        segment.fLength != r34rx::kCapacity || segment.fIOVMAddr != record.iova ||
        record.iova == record.pa || !record.tMapInv) {
        s.flags |= r34rx::kFlagMapFailed;
        return false;
    }
    bzero(&w, sizeof(w));
    w.generation = record.generation; w.memory = record.memory;
    w.command = record.command; w.pa = record.pa; w.iova = record.iova;
    w.tMapInv = record.tMapInv; w.slot = slot;
    s.maps++; s.slots[slot].mapCount++;
    s.slots[slot].currentPA = record.pa;
    return true;
}

bool RTL8125::r34RxMapSlot(UInt32 slot)
{
    return r34RxPrepareSlot(slot) && r34RxFinishMapSlot(slot);
}

bool RTL8125::r34RxUnmapSlot(UInt32 slot)
{
    R34RxState *p = r34Rx;
    auto &s = p->snapshot;
    if (!p->mapped[slot]) return true;
    if (p->command[slot]->complete(true, false) != kIOReturnSuccess) {
        s.flags |= r34rx::kFlagUnmapFailed;
        return false;
    }
    r34rx::MapRecord record = {};
    if (!r34RxBinding(r34rx::kRead, slot, &record) ||
        !(record.flags & r34rx::kMapUnmapped) || !record.tUnmapInv ||
        p->command[slot]->clearMemoryDescriptor(false) != kIOReturnSuccess ||
        p->memory[slot]->complete(kIODirectionIn) != kIOReturnSuccess) {
        s.flags |= r34rx::kFlagUnmapFailed;
        return false;
    }
    p->mapped[slot] = false; p->wired[slot] = false;
    p->current[slot].tUnmapInv = record.tUnmapInv;
    p->current[slot].flags |= r34rx::kWitnessUnmapped;
    s.unmaps++; s.slots[slot].unmapCount++;
    return true;
}

bool RTL8125::r34RxCanReplace() const
{
    return r34Rx && (r34Rx->physicalResumed ||
        (r34Rx->snapshot.state == r34rx::kInstalled && r34Rx->authorized));
}

mbuf_t RTL8125::r34RxCopy(mbuf_t packet, UInt32 length)
{
    if (!r34Rx || !length || length > kRxBufferSize) return nullptr;
    mbuf_t copy = rxPool->getPacket(length, MBUF_DONTWAIT);
    if (copy && mbuf_trailingspace(copy) >= length) {
        mbuf_copy_pkthdr(copy, packet);
        mbuf_pkthdr_setheader(copy, nullptr);
        bcopy(mbuf_data(packet), mbuf_data(copy), length);
        return copy;
    }
    if (copy) mbuf_freem_list(copy);
    r34Rx->snapshot.flags |= r34rx::kFlagCopyFailed;
    return nullptr;
}

bool RTL8125::r34RxObserve(UInt32 kind, UInt32 slot, UInt32 token)
{
    R34RxState *p = __atomic_load_n(&r34Rx, __ATOMIC_ACQUIRE);
    if (!p) return true;
    bool keep = true;
    if (kind == kObsKindTxSubmit) {
        keep = token == p->snapshot.businessToken;
        if (slot < kNumTxDesc)
            __atomic_store_n(&p->keepTx[slot], keep ? 1u : 0u, __ATOMIC_RELEASE);
    } else if (kind == kObsKindTxDone) {
        keep = slot < kNumTxDesc &&
            __atomic_load_n(&p->keepTx[slot], __ATOMIC_ACQUIRE) != 0;
    } else if (kind == kObsKindRxDone || kind == kObsKindTxDoorbell) {
        keep = token == p->snapshot.businessToken;
    }
    if (!keep && kind < 5)
        __atomic_fetch_add(&p->filtered[kind], 1u, __ATOMIC_RELAXED);
    return keep;
}

bool RTL8125::r34RxRecordDone(UInt32 slot, UInt64 oldAddr,
                             UInt32 status, UInt32 length)
{
    R34RxState *p = r34Rx;
    auto &s = p->snapshot;
    auto &w = p->current[slot];
    if (w.tPost) {
        if (oldAddr != w.iova || rxBufArray[slot].phyAddr != w.iova ||
            !s.pendingPosted || w.tDone) {
            s.flags |= r34rx::kFlagAddressMismatch;
            return false;
        }
        w.tDone = mach_absolute_time(); w.doneLength = length; w.doneStatus = status;
        w.flags |= r34rx::kWitnessDone;
        if (status & RxRES) w.flags |= r34rx::kWitnessError;
        s.completed++; s.slots[slot].doneCount++; s.pendingPosted--;
    }
    return true;
}

bool RTL8125::r34RxComplete(UInt32 slot, UInt64 oldAddr,
                           UInt32 status, UInt32 length)
{
    R34RxState *p = r34Rx;
    if (!p || p->physicalResumed || p->snapshot.state == r34rx::kReleased)
        return true;
    if (p->snapshot.state == r34rx::kPrepared ||
        (p->snapshot.state == r34rx::kInstalled && !p->authorized)) return true;
    // BeginBatch already records completion and retires every selected slot.
    if (!p->mapped[slot]) return true;
    return r34RxRecordDone(slot, oldAddr, status, length) && r34RxUnmapSlot(slot);
}

bool RTL8125::r36RxBatchCall(UInt32 op, UInt32 first, UInt32 count)
{
    R34RxState *p = r34Rx;
    if (!p || !p->callback || !count || count > r34rx::kBatchSize ||
        first >= r34rx::kCount) return false;
    r34rx::Binding b = {};
    b.version = r34rx::kVersion; b.bytes = sizeof(b);
    b.op = op; b.slot = first; b.length = count;
    return p->callback(p->context, &b) == kIOReturnSuccess;
}

bool RTL8125::r36RxBeginBatch(UInt32 first, UInt32 budget)
{
    R34RxState *p = r34Rx;
    if (!p || p->physicalResumed || p->snapshot.state != r34rx::kInstalled ||
        !p->authorized) return true;
    if (p->batchCount) return first ==
        (p->batchFirst + p->batchQueued) % r34rx::kCount;
    const UInt32 limit = budget < r34rx::kBatchSize ? budget : r34rx::kBatchSize;
    UInt32 count = 0;
    while (count < limit) {
        const UInt32 slot = (first + count) % r34rx::kCount;
        if (OSSwapLittleToHostInt32(rxDescArray[slot].cmd.opts1) & DescOwn) break;
        ++count;
    }
    if (!count) return true;
    p->batchFirst = first; p->batchCount = count; p->batchQueued = 0;
    // OWN is clear for the whole selected chunk. Record completion before the
    // shared invalidation, then keep standard DMA completion synchronous.
    for (UInt32 n = 0; n < count; ++n) {
        const UInt32 slot = (first + n) % r34rx::kCount;
        const UInt32 status = OSSwapLittleToHostInt32(rxDescArray[slot].cmd.opts1);
        if (!p->mapped[slot] || !r34RxRecordDone(slot, rxBufArray[slot].phyAddr,
                                               status, status & 0x1fff)) return false;
    }
    if (!r36RxBatchCall(r34rx::kBatchUnmap, first, count)) {
        p->snapshot.flags |= r34rx::kFlagUnmapFailed; return false;
    }
    for (UInt32 n = 0; n < count; ++n)
        if (!r34RxUnmapSlot((first + n) % r34rx::kCount)) return false;
    return true;
}

bool RTL8125::r36RxPublish(UInt32 slot, UInt64 addr, UInt64 oldAddr, UInt64 word1)
{
    R34RxState *p = r34Rx;
    if (!p->batchCount) {
        rxDescArray[slot].buf.addr = OSSwapHostToLittleInt64(addr);
        wmb();
        rxDescArray[slot].buf.blen = OSSwapHostToLittleInt64(word1);
        r34RxPosted(slot, addr);
        rxpostRecordRearm(slot, addr, oldAddr, word1);
        return true;
    }
    const UInt32 n = p->batchQueued;
    if (n >= p->batchCount || slot != (p->batchFirst + n) % r34rx::kCount) {
        p->snapshot.flags |= r34rx::kFlagAddressMismatch; return false;
    }
    p->batchOld[n] = oldAddr; p->batchWord[n] = word1;
    if (++p->batchQueued != p->batchCount) return true;
    // Every new mbuf is wired, but none of these descriptors has OWN yet.
    // One confirmed map covers the chunk. Complete all ordinary DMA callbacks
    // before publishing the first descriptor back to the NIC.
    if (!r36RxBatchCall(r34rx::kBatchMap, p->batchFirst, p->batchCount)) {
        p->snapshot.flags |= r34rx::kFlagMapFailed; return false;
    }
    for (UInt32 i = 0; i < p->batchCount; ++i)
        if (!r34RxFinishMapSlot((p->batchFirst + i) % r34rx::kCount)) return false;
    for (UInt32 i = 0; i < p->batchCount; ++i) {
        const UInt32 current = (p->batchFirst + i) % r34rx::kCount;
        const UInt64 iova = p->current[current].iova;
        rxBufArray[current].phyAddr = iova;
        rxDescArray[current].buf.addr = OSSwapHostToLittleInt64(iova);
        wmb();
        rxDescArray[current].buf.blen = OSSwapHostToLittleInt64(p->batchWord[i]);
        r34RxPosted(current, iova);
        rxpostRecordRearm(current, iova, p->batchOld[i], p->batchWord[i]);
    }
    ++p->batches; p->batchSlots += p->batchCount;
    if (p->batchCount > p->maxBatch) p->maxBatch = p->batchCount;
    p->batchCount = p->batchQueued = 0;
    return true;
}

bool RTL8125::r43RxCaptureActive()
{
    R34RxState *p = r34Rx;
    if (p->activeCaptureAttempted) return p->activeCaptured;
    // Every initial IOVA OWN is already published, but hardware is still
    // stopped. The entry reset ended the old physical DMA before these
    // descriptors changed. No packet completion is inferred from that reset.
    if (p->physicalResumed || p->snapshot.state != r34rx::kInstalled ||
        p->firstIovaSlots != r34rx::kCount || !p->hardwarePaused ||
        !p->fixed.resetVerified || p->authorized || p->batchCount) {
        p->snapshot.flags |= r34rx::kFlagMapFailed;
        return false;
    }
    p->activeCaptureAttempted = true;
    r34rx::Binding b = {};
    b.version = r34rx::kVersion; b.bytes = sizeof(b);
    b.op = r34rx::kCaptureActive; b.slot = 0;
    b.pa = p->tLastFirstIovaPost; b.length = r34rx::kCount;
    if (p->callback(p->context, &b) != kIOReturnSuccess) {
        p->snapshot.flags |= r34rx::kFlagMapFailed;
        return false;
    }
    p->activeCaptured = true;
    p->tActiveReady = mach_absolute_time();
    return true;
}

bool RTL8125::r42RxPostInitial()
{
    R34RxState *p = r34Rx;
    auto &s = p->snapshot;
    if (!p->hardwarePaused || !p->fixed.resetVerified ||
        s.maps != r34rx::kCount || s.posted || s.pendingPosted) return false;
    for (UInt32 slot = 0; slot < r34rx::kCount; ++slot) {
        auto &w = p->current[slot];
        if (!p->mapped[slot] || !w.tMapInv || w.tPost || !w.iova) return false;
        const UInt64 oldAddr = OSSwapLittleToHostInt64(rxDescArray[slot].buf.addr);
        const UInt64 word = kRxBufferSize | DescOwn |
            (slot == kRxLastDesc ? RingEnd : 0);
        rxBufArray[slot].phyAddr = w.iova;
        rxDescArray[slot].buf.addr = OSSwapHostToLittleInt64(w.iova);
        wmb();
        rxDescArray[slot].buf.blen = OSSwapHostToLittleInt64(word);
        r34RxPosted(slot, w.iova);
        rxpostRecordRearm(slot, w.iova, oldAddr, word);
    }
    // The backend marks Install complete only after this RPC returns.
    // Authorize captures the active IOVA table before rtl812xEnable is called.
    return p->firstIovaSlots == r34rx::kCount;
}

bool RTL8125::r39RxPaused() const
{
    R34RxState *p = __atomic_load_n(&r34Rx, __ATOMIC_ACQUIRE);
    return p && __atomic_load_n(&p->hardwarePaused, __ATOMIC_ACQUIRE);
}

UInt64 RTL8125::r40FixedRegister(UInt32 kind)
{
    struct rtl8125_private *tp = &linuxData;
    const UInt32 low = kind == r40fixed::kTxRing ? TxDescStartAddrLow :
        kind == r40fixed::kRxRing ? RxDescAddrLow : CounterAddrLow;
    const UInt32 high = kind == r40fixed::kTxRing ? TxDescStartAddrHigh :
        kind == r40fixed::kRxRing ? RxDescAddrHigh : CounterAddrHigh;
    UInt64 address = ((UInt64)RTL_R32(tp, high) << 32) | RTL_R32(tp, low);
    if (kind == r40fixed::kTally) address &= ~(UInt64)(CounterReset | CounterDump);
    return address;
}

bool RTL8125::r40FixedBinding(UInt32 op, UInt32 kind,
                            r34rx::MapRecord *out, UInt64 time)
{
    R34RxState *p = r34Rx;
    if (!p || kind >= r40fixed::kCount || !p->callback) return false;
    r34rx::Binding b = {};
    b.version = r34rx::kVersion; b.bytes = sizeof(b); b.op = op; b.slot = kind;
    if (op == r40fixed::kEntered) {
        b.pa = time; b.length = r40fixed::kCount;
    } else {
        b.memory = p->fixedMemory[kind]; b.command = p->fixedCommand[kind];
        b.pa = p->fixed.objects[kind].pa; b.length = p->fixed.objects[kind].bytes;
    }
    if (p->callback(p->context, &b) != kIOReturnSuccess) return false;
    if (out) *out = b.out;
    return true;
}

bool RTL8125::r43StopBeforeDte()
{
    R34RxState *p = r34Rx;
    auto &f = p->fixed;
    auto &s = p->snapshot;
    if (f.entryCalls || s.state != r34rx::kPrepared || s.maps) return false;
    struct rtl8125_private *tp = &linuxData;
    ++f.entryCalls;
    f.tStopBegin = mach_absolute_time();
    f.commandBefore = RTL_R8(tp, ChipCmd);
    f.interruptMaskBefore = RTL_R32(tp, IMR0_8125);
    f.generationBefore = rxpostHdr ? rxpostHdr->ringGen : p->generation;
    for (UInt32 i = 0; i < r40fixed::kCount; ++i) {
        f.objects[i].registerBefore = r40FixedRegister(i);
        if (f.objects[i].registerBefore != f.objects[i].pa) return false;
    }
    // TX admission is still closed from the pre-DTE drain. Prepare kept all
    // RX mbufs unchanged, so this explicit rebuild preserves that manifest.
    __atomic_store_n(&p->hardwarePaused, true, __ATOMIC_RELEASE);
    timerSource->cancelTimeout();
    interruptSource->disable();
    netif->stopOutputThread();
    netif->flushOutputQueue();
    clear_mask((__LINK_UP_M | __POLL_MODE_M), &stateFlags);
    setLinkStatus(kIONetworkLinkValid);
    rtl8125_hw_reset(tp);
    f.commandStopped = RTL_R8(tp, ChipCmd);
    f.interruptMaskStopped = RTL_R32(tp, IMR0_8125);
    if ((f.commandStopped & (CmdReset | CmdTxEnb | CmdRxEnb)) ||
        f.interruptMaskStopped) return false;
    f.resetVerified = 1;
    f.tStopped = mach_absolute_time();
    p->entryRebuilding = true;
    clearRxTxRings();
    p->entryRebuilding = false;
    f.generationAfter = rxpostHdr ? rxpostHdr->ringGen : p->generation;
    rxpostCaptureBaseline();
    rxpostPublish();
    return true;
}

bool RTL8125::r40FixedInstall()
{
    R34RxState *p = r34Rx;
    auto &f = p->fixed;
    auto &s = p->snapshot;
    struct rtl8125_private *tp = &linuxData;
    if (s.state != r34rx::kPrepared || s.maps || !f.entryCalls ||
        !f.resetVerified || !p->hardwarePaused ||
        (RTL_R8(tp, ChipCmd) & (CmdReset | CmdTxEnb | CmdRxEnb)) ||
        RTL_R32(tp, IMR0_8125)) return false;

    // Mark ownership before allocating any pair. These virtual descriptors
    // describe the existing driver buffers; their original MD/Cmd stay owned
    // by Lucy and keep the physical allocation alive through final restart.
    s.state = r34rx::kInstalled;
    const IOVirtualAddress address[r40fixed::kCount] = {
        (IOVirtualAddress)txDescArray, (IOVirtualAddress)rxDescArray,
        (IOVirtualAddress)statData
    };
    for (UInt32 i = 0; i < r40fixed::kCount; ++i) {
        auto &o = f.objects[i];
        const UInt32 direction = i == r40fixed::kTally ? kIODirectionIn : kIODirectionInOut;
        p->fixedRanges[i].address = address[i]; p->fixedRanges[i].length = o.bytes;
        p->fixedMemory[i] = IOMemoryDescriptor::withOptions(&p->fixedRanges[i], 1, 0,
            kernel_task, kIOMemoryTypeVirtual | direction | kIOMemoryAsReference, p->mapper);
        p->fixedCommand[i] = IODMACommand::withSpecification(kIODMACommandOutputHost64,
            64, 0, IODMACommand::kMapped, 0, 1, p->mapper, nullptr);
        if (!p->fixedMemory[i] || !p->fixedCommand[i] ||
            !r40FixedBinding(r40fixed::kBind, i)) return false;
        p->fixedBound[i] = true;
        o.memory = (UInt64)(uintptr_t)p->fixedMemory[i];
        o.command = (UInt64)(uintptr_t)p->fixedCommand[i];
        if (p->fixedMemory[i]->prepare(direction) != kIOReturnSuccess) return false;
        p->fixedWired[i] = true;
        if (p->fixedCommand[i]->setMemoryDescriptor(p->fixedMemory[i], true) !=
            kIOReturnSuccess) return false;
        p->fixedMapped[i] = true;
        r34rx::MapRecord record = {};
        IODMACommand::Segment64 segment = {};
        UInt64 offset = 0; UInt32 count = 1;
        if (!r40FixedBinding(r40fixed::kRead, i, &record) ||
            !(record.flags & r40fixed::kMapInvalidated) || !record.tMapInv ||
            record.memory != o.memory || record.command != o.command || record.pa != o.pa ||
            p->fixedCommand[i]->gen64IOVMSegments(&offset, &segment, &count) != kIOReturnSuccess ||
            count != 1 || offset != o.bytes || segment.fLength != o.bytes ||
            segment.fIOVMAddr != record.iova || record.iova == o.pa ||
            record.iova != r40fixed::kIovaBase + i * r40fixed::kStride + (o.pa & 4095ULL))
            return false;
        o.iova = record.iova; o.mapOptions = record.mapOptions;
        ++o.mapCount; o.tMapReady = mach_absolute_time();
    }
    return true;
}

IOReturn RTL8125::r40FixedActivate()
{
    R34RxState *p = r34Rx;
    auto &f = p->fixed;
    if (f.tActive) return f.flags ? kIOReturnIOError : kIOReturnSuccess;
    struct rtl8125_private *tp = &linuxData;
    if (!f.tProgrammed) {
        if (!p->hardwarePaused || !f.resetVerified ||
            p->firstIovaSlots != r34rx::kCount ||
            (RTL_R8(tp, ChipCmd) & (CmdReset | CmdTxEnb | CmdRxEnb)) ||
            RTL_R32(tp, IMR0_8125) || !r43RxCaptureActive())
            return kIOReturnIOError;
        txPhyAddr = f.objects[r40fixed::kTxRing].iova;
        rxPhyAddr = f.objects[r40fixed::kRxRing].iova;
        statPhyAddr = f.objects[r40fixed::kTally].iova;
        txDescDoneCount = txDescDoneLast = 0;
        rtl812xEnable();
        for (UInt32 i = 0; i < r40fixed::kCount; ++i) {
            f.objects[i].registerActive = r40FixedRegister(i);
            if (f.objects[i].registerActive != f.objects[i].iova) return kIOReturnIOError;
        }
        f.tProgrammed = mach_absolute_time();
    }
    const UInt32 phy = RTL_R32(tp, PHYstatus);
    if (phy == 0xffffffffu || !(phy & LinkStatus)) return kIOReturnBusy;
    // PHY negotiation needs no network callback. Keep the prepared mappings
    // paused until link is up, so a link-down IRQ cannot clear this new ring.
    if (p->hardwarePaused) {
        // HwConfig enabled the NIC mask while the MSI event source was still
        // disabled. A pending link event must be acknowledged before arming
        // that source; the normal link-up HwConfig below restores the mask.
        p->irqPending = RTL_R32(tp, ISR0_8125);
        rtl8125_irq_mask_and_ack(tp);
        p->irqMasked = RTL_R32(tp, IMR0_8125);
        __atomic_store_n(&p->hardwarePaused, false, __ATOMIC_RELEASE);
        interruptSource->enable();
    }
    if (!test_bit(__LINK_UP, &stateFlags)) rtl812xCheckLinkStatus(tp);
    const UInt32 command = RTL_R8(tp, ChipCmd);
    if (!test_bit(__LINK_UP, &stateFlags) ||
        (command & (CmdReset | CmdTxEnb | CmdRxEnb)) != (CmdTxEnb | CmdRxEnb))
        return kIOReturnBusy;
    for (UInt32 i = 0; i < r40fixed::kCount; ++i) {
        f.objects[i].registerActive = r40FixedRegister(i);
        if (f.objects[i].registerActive != f.objects[i].iova) return kIOReturnIOError;
    }
    p->irqArmed = RTL_R32(tp, IMR0_8125);
    p->irqExpected = intrMask;
    f.tActive = mach_absolute_time();
    return r40FixedBinding(r40fixed::kEntered, 0, nullptr, f.tActive)
        ? kIOReturnSuccess : kIOReturnIOError;
}

bool RTL8125::r40FixedRetire()
{
    R34RxState *p = r34Rx;
    for (UInt32 i = 0; i < r40fixed::kCount; ++i) {
        if (!p->fixedMapped[i]) continue;
        auto &o = p->fixed.objects[i];
        if (p->fixedCommand[i]->complete(true, false) != kIOReturnSuccess) return false;
        r34rx::MapRecord record = {};
        const UInt32 direction = i == r40fixed::kTally ? kIODirectionIn : kIODirectionInOut;
        if (!r40FixedBinding(r40fixed::kRead, i, &record) ||
            !(record.flags & r40fixed::kMapUnmapped) || !record.tUnmapInv ||
            p->fixedCommand[i]->clearMemoryDescriptor(false) != kIOReturnSuccess ||
            p->fixedMemory[i]->complete(direction) != kIOReturnSuccess) return false;
        p->fixedMapped[i] = p->fixedWired[i] = false;
        ++o.unmapCount; o.tUnmapReady = mach_absolute_time();
    }
    txPhyAddr = p->fixed.objects[r40fixed::kTxRing].pa;
    rxPhyAddr = p->fixed.objects[r40fixed::kRxRing].pa;
    statPhyAddr = p->fixed.objects[r40fixed::kTally].pa;
    return true;
}

bool RTL8125::r40FixedRelease()
{
    R34RxState *p = r34Rx;
    for (UInt32 i = 0; i < r40fixed::kCount; ++i) {
        if (p->fixedMapped[i] || p->fixedWired[i]) return false;
        if (p->fixedBound[i] && !r40FixedBinding(r40fixed::kUnbind, i)) return false;
        p->fixedBound[i] = false;
        if (p->fixedCommand[i]) { p->fixedCommand[i]->release(); p->fixedCommand[i] = nullptr; }
        if (p->fixedMemory[i]) { p->fixedMemory[i]->release(); p->fixedMemory[i] = nullptr; }
    }
    return true;
}

bool RTL8125::r39RxStop()
{
    R34RxState *p = r34Rx;
    auto &s = p->snapshot;
    auto &stop = p->stop;
    if (s.state == r34rx::kDrained) return true;
    if (stop.stopCalls || p->batchCount || p->batchQueued) return false;
    struct rtl8125_private *tp = &linuxData;
    ++stop.stopCalls;
    stop.tStopBegin = mach_absolute_time();
    stop.commandBefore = RTL_R8(tp, ChipCmd);
    stop.interruptMaskBefore = RTL_R32(tp, IMR0_8125);
    stop.rxNextBefore = rxNextDescIndex;

    // The probe has already closed TX admission and drained its owners. Keep
    // this command-gate + POLLING exclusion through the final RX unmaps.
    // Paused entry points also exclude a queued timer, IRQ or poll callback.
    __atomic_store_n(&p->hardwarePaused, true, __ATOMIC_RELEASE);
    timerSource->cancelTimeout();
    interruptSource->disable();
    netif->stopOutputThread();
    netif->flushOutputQueue();
    clear_mask((__LINK_UP_M | __POLL_MODE_M), &stateFlags);
    setLinkStatus(kIONetworkLinkValid);
    rtl8125_hw_reset(tp);
    stop.commandStopped = RTL_R8(tp, ChipCmd);
    stop.interruptMaskStopped = RTL_R32(tp, IMR0_8125);
    if ((stop.commandStopped & (CmdReset | CmdTxEnb | CmdRxEnb)) ||
        stop.interruptMaskStopped) {
        s.flags |= r34rx::kFlagStopped;
        return false;
    }
    stop.resetVerified = 1;
    stop.tStopped = mach_absolute_time();

    for (UInt32 slot = 0; slot < r34rx::kCount; ++slot) {
        auto &d = s.slots[slot];
        auto &w = p->current[slot];
        const UInt64 oldAddr = OSSwapLittleToHostInt64(rxDescArray[slot].buf.addr);
        if (!r34RxUnmapSlot(slot)) return false;
        if (w.tUnmapInv > stop.tLastUnmap) stop.tLastUnmap = w.tUnmapInv;
        if (w.tPost && !w.tDone && !(w.flags & r34rx::kWitnessStopRetired)) {
            if (!s.pendingPosted) {
                s.flags |= r34rx::kFlagAddressMismatch;
                return false;
            }
            // No packet completion was observed for this final OWN. The NIC
            // stop, not a fabricated tDone, authorizes retirement of its DMA.
            w.flags |= r34rx::kWitnessStopRetired;
            ++s.stopRetired; ++d.stopRetired; --s.pendingPosted;
        }
        if (w.tPost) { d.last = w; w.reserved = 1; }
        const UInt64 pa = mbuf_data_to_physical(mbuf_datastart(rxBufArray[slot].mbuf));
        if (!pa) {
            s.flags |= r34rx::kFlagAddressMismatch;
            return false;
        }
        // DMA stays off until the original IOMMU state is restored. Preparing
        // the physical descriptors here does not need an experimental alias.
        d.currentPA = pa;
        rxBufArray[slot].phyAddr = pa;
        rxDescArray[slot].buf.addr = OSSwapHostToLittleInt64(pa);
        const UInt64 word1 = kRxBufferSize | DescOwn |
            (slot == kRxLastDesc ? RingEnd : 0u);
        wmb();
        rxDescArray[slot].buf.blen = OSSwapHostToLittleInt64(word1);
        if (!d.tPhysicalOwn) ++s.restored;
        d.tPhysicalOwn = mach_absolute_time();
        s.tLastRestore = d.tPhysicalOwn;
        rxpostRecordRearm(slot, pa, oldAddr, word1);
    }
    stop.stopRetired = s.stopRetired;
    stop.restored = s.restored;
    stop.tLastRestore = s.tLastRestore;
    if (!r40FixedRetire()) {
        p->fixed.flags |= r40fixed::kFlagUnmapFailed;
        s.flags |= r34rx::kFlagUnmapFailed;
        return false;
    }
    if (s.pendingPosted || s.posted != s.completed + s.stopRetired ||
        s.maps != s.unmaps || s.restored != r34rx::kCount) return false;
    s.state = r34rx::kDrained;
    return true;
}

IOReturn RTL8125::r39RxResume()
{
    R34RxState *p = r34Rx;
    auto &stop = p->stop;
    if (p->physicalResumed) return kIOReturnSuccess;
    // A Prepare-only cancellation never stopped the NIC or owned mappings.
    if (!stop.stopCalls && !p->fixed.entryCalls) {
        p->physicalResumed = true;
        p->tPhysicalResumed = mach_absolute_time();
        return kIOReturnSuccess;
    }
    if (stop.stopCalls ? !stop.resetVerified : !p->fixed.resetVerified)
        return kIOReturnNotReady;
    struct rtl8125_private *tp = &linuxData;
    if (!stop.tResumeBegin) {
        stop.tResumeBegin = mach_absolute_time();
        // The probe has confirmed the original IOMMU state. This also handles
        // an entry stop followed by cancellation before Install owns any DMA.
        // Use Lucy's existing rebuild/restart path after all owners are gone.
        clearRxTxRings();
        stop.rxNextAfter = rxNextDescIndex;
        txDescDoneCount = txDescDoneLast = 0;
        rtl812xEnable();
        __atomic_store_n(&p->hardwarePaused, false, __ATOMIC_RELEASE);
        interruptSource->enable();
    }
    // The enable path starts PHY negotiation. Poll outside this command gate
    // until the ordinary link-up path can enable DMA; never reset it again.
    const UInt32 phy = RTL_R32(tp, PHYstatus);
    if (phy != 0xffffffffu && (phy & LinkStatus) &&
        !test_bit(__LINK_UP, &stateFlags)) rtl812xCheckLinkStatus(tp);
    const UInt32 command = RTL_R8(tp, ChipCmd);
    if (!test_bit(__LINK_UP, &stateFlags) ||
        (command & (CmdReset | CmdTxEnb | CmdRxEnb)) != (CmdTxEnb | CmdRxEnb))
        return kIOReturnBusy;
    for (UInt32 i = 0; i < r40fixed::kCount; ++i) {
        auto &o = p->fixed.objects[i];
        o.registerPhysical = r40FixedRegister(i);
        if (o.registerPhysical != o.pa) return kIOReturnIOError;
    }
    p->physicalResumed = true;
    p->tPhysicalResumed = stop.tResumed = mach_absolute_time();
    return kIOReturnSuccess;
}

bool RTL8125::r34RxRearm(UInt32 slot, UInt32 token, UInt32 reqId,
                        bool replaced, UInt64 *addr)
{
    R34RxState *p = r34Rx;
    auto &s = p->snapshot;
    auto &d = s.slots[slot];
    auto &w = p->current[slot];
    if (p->physicalResumed || s.state == r34rx::kReleased) return true;
    if (s.state == r34rx::kPrepared ||
        (s.state == r34rx::kInstalled && !p->authorized)) return true;
    if (s.state != r34rx::kInstalled) return false;
    if (replaced) { s.replaced++; d.replaceCount++; }
    if (w.tPost && w.tDone && !w.reserved) {
        w.token = token; w.reqId = reqId; w.replaced = replaced ? 1u : 0u;
        d.last = w;
        if (!d.sampleCount) { d.samples[0] = w; d.sampleCount = 1; }
        w.reserved = 1; // do not relabel this DMA with later physical tail packets
    }
    if (p->batchCount) return r34RxPrepareSlot(slot);
    if (!r34RxMapSlot(slot)) return false;
    *addr = p->current[slot].iova;
    rxBufArray[slot].phyAddr = *addr;
    return true;
}

void RTL8125::r34RxPosted(UInt32 slot, UInt64 addr)
{
    R34RxState *p = r34Rx;
    auto &s = p->snapshot;
    auto &d = s.slots[slot];
    auto &w = p->current[slot];
    if (p->mapped[slot] && addr == w.iova && !w.tPost) {
        w.tPost = mach_absolute_time(); w.flags |= r34rx::kWitnessPosted;
        if (!d.postCount) {
            ++p->firstIovaSlots;
            p->tLastFirstIovaPost = w.tPost;
        }
        s.posted++; d.postCount++; s.pendingPosted++;
    }
}

IOReturn RTL8125::r34RxAction(OSObject *owner, void *arg0,
                            void *, void *, void *)
{
    auto *self = static_cast<RTL8125 *>(owner);
    if (self->useAppleVTD) return kIOReturnUnsupported;
    if (test_and_set_bit(__POLLING, &self->stateFlags)) return kIOReturnBusy;
    const IOReturn result = self->r34RxControl((r34rx::Request *)arg0);
    clear_bit(__POLLING, &self->stateFlags);
    return result;
}

IOReturn RTL8125::r34RxControl(r34rx::Request *request)
{
    if (!request || request->version != r34rx::kVersion ||
        request->bytes != sizeof(*request) || request->op < r34rx::kInstall ||
        request->op > r34rx::kStopBeforeDte) return kIOReturnBadArgument;
    if (!rxBufArray || !rxDescArray || !rxPool) return kIOReturnNotReady;
    if (request->op == r34rx::kPrepare) {
        if (r34Rx || r15Pool) return kIOReturnBusy;
        if (!netif || !test_bit(__ENABLED, &stateFlags) ||
            !test_bit(__LINK_UP, &stateFlags)) return kIOReturnNotReady;
        if (!request->businessToken || request->deadline) return kIOReturnBadArgument;
        auto *p = (R34RxState *)IOMallocZero(sizeof(R34RxState));
        if (!p) return kIOReturnNoMemory;
        auto &s = p->snapshot;
        s.version = r34rx::kVersion; s.bytes = sizeof(s); s.slotCount = r34rx::kCount;
        s.businessToken = request->businessToken;
        p->stop.version = r34rx::kStopVersion; p->stop.bytes = sizeof(p->stop);
        p->fixed.version = r40fixed::kVersion; p->fixed.bytes = sizeof(p->fixed);
        p->fixed.count = r40fixed::kCount;
        p->generation = rxpostHdr ?
            __atomic_load_n(&rxpostHdr->ringGen, __ATOMIC_RELAXED) : 1u;
        // These prepared, contiguous descriptors stay owned by Lucy for the
        // lifetime of this ring. Read their raw PA and match the address Lucy
        // programmed into the NIC; do not infer coverage from a RAM limit.
        r34rx::PhysicalLayout physical = {};
        physical.version = r34rx::kPhysicalLayoutVersion;
        physical.bytes = sizeof(physical);
        physical.generation = p->generation;
        physical.count = r34rx::kPhysicalSpanCount;
        IOMemoryDescriptor *physicalMemory[r34rx::kPhysicalSpanCount] = {
            txBufDesc, rxBufDesc, statBufDesc
        };
        const UInt64 physicalAddress[r34rx::kPhysicalSpanCount] = {
            txPhyAddr, rxPhyAddr, statPhyAddr
        };
        const UInt64 physicalLength[r34rx::kPhysicalSpanCount] = {
            kTxDescSize, kRxDescSize, sizeof(RtlStatData)
        };
        for (UInt32 i = 0; i < r34rx::kPhysicalSpanCount; ++i) {
            IOByteCount length = 0;
            const UInt64 pa = physicalMemory[i] ? physicalMemory[i]->getPhysicalSegment(
                0, &length, kIOMemoryMapperNone) : 0;
            if (!pa || pa != physicalAddress[i] || length < physicalLength[i]) {
                IOFree(p, sizeof(*p)); return kIOReturnNotAligned;
            }
            physical.spans[i].pa = pa;
            physical.spans[i].bytes = physicalLength[i];
            p->fixed.objects[i].kind = i;
            p->fixed.objects[i].pa = pa;
            p->fixed.objects[i].bytes = physicalLength[i];
        }
        for (UInt32 slot = 0; slot < r34rx::kCount; ++slot) {
            UInt64 pa = 0;
            if (!r15PhysicalSpan(rxBufArray[slot].mbuf, &pa) ||
                pa != rxBufArray[slot].phyAddr ||
                pa != OSSwapLittleToHostInt64(rxDescArray[slot].buf.addr)) {
                IOFree(p, sizeof(*p)); return kIOReturnNotAligned;
            }
            s.slots[slot].originalPA = pa;
            s.slots[slot].currentPA = pa;
        }
        OSData *physicalRaw = OSData::withBytes(&physical, sizeof(physical));
        if (!physicalRaw) { IOFree(p, sizeof(*p)); return kIOReturnNoMemory; }
        const bool physicalPublished = setProperty("rtl812x-r37-physical-layout", physicalRaw);
        physicalRaw->release();
        if (!physicalPublished) { IOFree(p, sizeof(*p)); return kIOReturnNoMemory; }
        for (UInt32 slot = 0; slot < kNumTxDesc; ++slot) p->keepTx[slot] = 1;
        p->tPrepared = mach_absolute_time();
        s.ringId = p->tPrepared ? p->tPrepared : 1;
        s.state = r34rx::kPrepared;
        // Borrow Lucy's existing ring. The receive hook keeps it copy-only
        // until the probe maps these exact spans and authorizes native RX.
        // No mbuf, spare pool, or ownership handoff is created here.
        request->expectedGeneration = p->generation;
        __atomic_store_n(&r34Rx, p, __ATOMIC_RELEASE);
    } else {
        if (!r34Rx) return kIOReturnNotReady;
        if (request->ringId != r34Rx->snapshot.ringId ||
            request->expectedGeneration != r34Rx->generation ||
            request->businessToken != r34Rx->snapshot.businessToken)
            return kIOReturnBadArgument;
    }
    auto *p = r34Rx;
    auto &s = p->snapshot;
    IOReturn controlResult = kIOReturnSuccess;
    if (request->op == r34rx::kStopBeforeDte) {
        if (s.state != r34rx::kPrepared || s.flags || request->deadline)
            return kIOReturnBadArgument;
        if (!r43StopBeforeDte()) {
            s.flags |= r34rx::kFlagStopped;
            controlResult = kIOReturnIOError;
        }
    } else if (request->op == r34rx::kInstall) {
        if (s.state != r34rx::kPrepared || s.flags || !request->mapper ||
            !request->context || !request->callback || request->deadline)
            return kIOReturnBadArgument;
        p->mapper = static_cast<IOMapper *>(request->mapper); p->mapper->retain();
        p->context = request->context; p->callback = request->callback;
        if (!r40FixedInstall()) {
            p->fixed.flags |= r40fixed::kFlagMapFailed;
            s.flags |= r34rx::kFlagMapFailed;
            return kIOReturnIOError;
        }
        for (UInt32 slot = 0; slot < r34rx::kCount; ++slot) {
            p->ranges[slot].address = (IOVirtualAddress)mbuf_datastart(rxBufArray[slot].mbuf);
            p->ranges[slot].length = r34rx::kCapacity;
            p->memory[slot] = IOMemoryDescriptor::withOptions(&p->ranges[slot], 1, 0,
                kernel_task, kIOMemoryTypeVirtual | kIODirectionIn | kIOMemoryAsReference,
                p->mapper);
            p->command[slot] = IODMACommand::withSpecification(kIODMACommandOutputHost64,
                64, 0, IODMACommand::kMapped, 0, 1, p->mapper, nullptr);
            if (!p->memory[slot] || !p->command[slot] ||
                !r34RxBinding(r34rx::kBind, slot, nullptr)) {
                s.flags |= r34rx::kFlagMapFailed; return kIOReturnNoMemory;
            }
            p->bound[slot] = true;
            if (!r34RxMapSlot(slot)) return kIOReturnIOError;
        }
        if (!r42RxPostInitial()) {
            s.flags |= r34rx::kFlagMapFailed; return kIOReturnIOError;
        }
        s.nativeActive = 1;
        s.tInstalled = mach_absolute_time();
    } else if (request->op == r34rx::kAuthorize) {
        if (s.state != r34rx::kInstalled || s.flags || !s.nativeActive ||
            s.maps != r34rx::kCount || !s.tInstalled || request->deadline)
            return kIOReturnBadArgument;
        controlResult = r40FixedActivate();
        if (controlResult == kIOReturnSuccess) {
            p->authorized = true;
            p->tAuthorized = mach_absolute_time();
        } else if (controlResult != kIOReturnBusy) {
            p->fixed.flags |= r40fixed::kFlagMapFailed;
            s.flags |= r34rx::kFlagMapFailed;
        }
    } else if (request->op == r34rx::kDisarm || request->op == r34rx::kDrain) {
        p->authorized = false;
        if (!s.tDisarmed) s.tDisarmed = mach_absolute_time();
        if (s.state != r34rx::kReleased && s.state != r34rx::kDrained) {
            s.state = r34rx::kDisarmed;
            // Disarm closes the callback window and stops DMA in this same
            // serialized RPC. A following Drain observes the drained state.
            if (!r39RxStop())
                controlResult = kIOReturnIOError;
        }
    } else if (request->op == r34rx::kRelease) {
        if (s.state != r34rx::kDrained || s.pendingPosted ||
            s.posted != s.completed + s.stopRetired)
            return kIOReturnBusy;
        for (UInt32 slot = 0; slot < r34rx::kCount; ++slot) {
            if (p->mapped[slot] || p->wired[slot] ||
                !r34RxBinding(r34rx::kUnbind, slot, nullptr)) return kIOReturnBusy;
            p->bound[slot] = false;
            if (p->command[slot]) { p->command[slot]->release(); p->command[slot] = nullptr; }
            if (p->memory[slot]) { p->memory[slot]->release(); p->memory[slot] = nullptr; }
        }
        if (!r40FixedRelease()) return kIOReturnBusy;
        p->mapper->release(); p->mapper = nullptr;
        p->context = nullptr; p->callback = nullptr;
        s.state = r34rx::kReleased; s.nativeActive = 0;
    } else if (request->op == r34rx::kResumePhysical) {
        if (s.state != r34rx::kReleased && s.state != r34rx::kPrepared)
            return kIOReturnBusy;
        // The caller has restored the original translation/register state.
        // A pre-DTE abort may also release a ring that was only prepared.
        s.state = r34rx::kReleased;
        controlResult = r39RxResume();
    }
    bcopy(&s, &request->out, sizeof(s));
    OSData *raw = OSData::withBytes(&s, sizeof(s));
    if (raw) { setProperty("rtl812x-r34-rx-native-raw", raw); raw->release(); }
    raw = OSData::withBytes(&p->stop, sizeof(p->stop));
    if (raw) { setProperty("rtl812x-r39-rx-stop-raw", raw); raw->release(); }
    raw = OSData::withBytes(&p->fixed, sizeof(p->fixed));
    if (raw) { setProperty("rtl812x-r40-fixed-dma-raw", raw); raw->release(); }
    setProperty("rtl812x-r41-irq-pending", p->irqPending, 32);
    setProperty("rtl812x-r41-irq-masked", p->irqMasked, 32);
    setProperty("rtl812x-r41-irq-armed", p->irqArmed, 32);
    setProperty("rtl812x-r41-irq-expected", p->irqExpected, 32);
    setProperty("rtl812x-r34-rx-mode", "native-ring-batch16");
    setProperty("rtl812x-r34-rx-state", s.state, 32);
    setProperty("rtl812x-r34-rx-maps", s.maps, 32);
    setProperty("rtl812x-r34-rx-unmaps", s.unmaps, 32);
    setProperty("rtl812x-r34-rx-replaced", s.replaced, 32);
    setProperty("rtl812x-r34-rx-flags", s.flags, 32);
    setProperty("rtl812x-r35-rx-source", "lucy-normal-ring");
    setProperty("rtl812x-r35-rx-experimental-pool", r15Pool ? 1u : 0u, 32);
    setProperty("rtl812x-r35-rx-spares", r15Pool ? r15Pool->snap.spareCount : 0u, 32);
    setProperty("rtl812x-r35-rx-ring-id", s.ringId, 64);
    setProperty("rtl812x-r35-rx-prepare-time", p->tPrepared, 64);
    setProperty("rtl812x-r35-rx-authorize-time", p->tAuthorized, 64);
    setProperty("rtl812x-r35-rx-resume-time", p->tPhysicalResumed, 64);
    setProperty("rtl812x-r35-obs-scope", "declared-business-only; native-rx-witnesses-retained");
    setProperty("rtl812x-r35-obs-business-token", s.businessToken, 32);
    UInt32 filtered = 0;
    for (UInt32 kind = 1; kind < 5; ++kind)
        filtered += __atomic_load_n(&p->filtered[kind], __ATOMIC_RELAXED);
    setProperty("rtl812x-r35-obs-filtered", filtered, 32);
    setProperty("rtl812x-r36-rx-batches", p->batches, 32);
    setProperty("rtl812x-r36-rx-batch-slots", p->batchSlots, 32);
    setProperty("rtl812x-r36-rx-max-batch", p->maxBatch, 32);
    setProperty("rtl812x-r36-rx-pending-batch", p->batchCount, 32);
    setProperty("rtl812x-r38-rx-first-iova-slots", p->firstIovaSlots, 32);
    setProperty("rtl812x-r38-rx-last-first-iova-time", p->tLastFirstIovaPost, 64);
    setProperty("rtl812x-r43-rx-active-ready-time", p->tActiveReady, 64);
    return controlResult;
}

void RTL8125::r34RxInvalidate()
{
    // This one stopped-NIC rebuild keeps the immutable Prepare mbufs/spans.
    // RX-post still bumps its real generation and publishes a fresh baseline.
    if (r34Rx && r34Rx->entryRebuilding && r34Rx->hardwarePaused &&
        r34Rx->snapshot.state == r34rx::kPrepared && !r34Rx->snapshot.maps)
        return;
    if (r34Rx && r34Rx->snapshot.state != r34rx::kReleased) {
        r34Rx->snapshot.flags |= r34rx::kFlagRingReset;
        r34Rx->authorized = false;
        r34Rx->snapshot.state = r34rx::kDisarmed;
    }
}

bool RTL8125::r34RxFree()
{
    if (!r34Rx) return true;
    for (UInt32 slot = 0; slot < r34rx::kCount; ++slot)
        if (r34Rx->mapped[slot] || r34Rx->wired[slot] || r34Rx->bound[slot]) return false;
    for (UInt32 i = 0; i < r40fixed::kCount; ++i)
        if (r34Rx->fixedMapped[i] || r34Rx->fixedWired[i] || r34Rx->fixedBound[i]) return false;
    IOFree(r34Rx, sizeof(*r34Rx)); r34Rx = nullptr;
    return true;
}

bool RTL8125::r34RxParse(mbuf_t packet, UInt32 *token, UInt32 *reqId)
{
    if (!r34Rx || !packet || !token || !reqId) return false;
    UInt8 h[54]; UInt32 have = 0;
    for (mbuf_t m = packet; m && have < sizeof(h); m = mbuf_next(m)) {
        const UInt32 length = (UInt32)mbuf_len(m);
        const UInt32 take = length < sizeof(h) - have ? length : sizeof(h) - have;
        if (take) bcopy(mbuf_data(m), h + have, take);
        have += take;
    }
    if (have != sizeof(h) || h[12] != 8 || h[13] || h[14] != 0x45 ||
        h[23] != 17 || (h[20] & 0x3f) || h[21]) return false;
    const UInt32 ipLength = ((UInt32)h[16] << 8) | h[17];
    const UInt32 udpLength = ((UInt32)h[38] << 8) | h[39];
    if (ipLength < 40 || udpLength < 20 || udpLength != ipLength - 20 ||
        ipLength + 14 > (UInt32)mbuf_pkthdr_len(packet)) return false;
    const UInt32 t = ((UInt32)h[46] << 24) | ((UInt32)h[47] << 16) |
                    ((UInt32)h[48] << 8) | h[49];
    const UInt32 r = ((UInt32)h[50] << 24) | ((UInt32)h[51] << 16) |
                    ((UInt32)h[52] << 8) | h[53];
    if (!t || !r) return false;
    auto &s = r34Rx->snapshot;
    if (h[42] == 'R' && h[43] == '2' && h[44] == '9' && h[45] == 'D') {
        if (ipLength == 40 && udpLength == 20 && s.state == r34rx::kReleased &&
            !s.flags && !s.pendingPosted && t == s.businessToken &&
            r <= r34rx::kTailMax && !s.tailSeq) s.tailSeq = r;
        return false;
    }
    if (h[42] != 'R' || h[43] != '2' || h[44] != '7' || h[45] != 'P') return false;
    *token = t; *reqId = r;
    return true;
}
'''


def pool_methods(text):
    text = BASE['pool_methods'](text)

    def once(old, new):
        nonlocal text
        assert text.count(old) == 1, 'round34 pool anchor: ' + old
        text = text.replace(old, new, 1)

    once('    if (functionName && functionName->isEqualTo(r27rx::kFunctionName)) {',
         '    if (functionName && functionName->isEqualTo(r34rx::kFunctionName)) {\n'
         '        if (!param1 || param2 || param3 || param4 || !commandGate)\n'
         '            return kIOReturnBadArgument;\n'
         '        return commandGate->runAction(r34RxAction, param1);\n'
         '    }\n'
         '    if (functionName && functionName->isEqualTo(r27rx::kFunctionName)) {')
    once('void RTL8125::r15PoolInvalidate()\n{\n',
         'void RTL8125::r15PoolInvalidate()\n{\n    r34RxInvalidate();\n')
    once('void RTL8125::r15PoolFree()\n{\n',
         'void RTL8125::r15PoolFree()\n{\n'
         '    if (!r34RxFree()) {\n'
         '        if (rxBufArray) for (UInt32 i = 0; i < r15pool::kRingCount; i++)\n'
         '            rxBufArray[i].mbuf = nullptr;\n'
         '        setProperty("rtl812x-r34-rx-stop", "PINNED-mappings-not-released");\n'
         '        return;\n'
         '    }\n')
    once('bool RTL8125::r15PoolObserve(UInt32 kind, UInt32 slot, UInt32 token)\n{\n',
         'bool RTL8125::r15PoolObserve(UInt32 kind, UInt32 slot, UInt32 token)\n{\n'
         '    if (__atomic_load_n(&r34Rx, __ATOMIC_ACQUIRE))\n'
         '        return r34RxObserve(kind, slot, token);\n')
    return text + '\n' + METHODS


def pause_entries(text):
    def once(old, new):
        nonlocal text
        assert text.count(old) == 1, 'round39 pause anchor: ' + old
        text = text.replace(old, new, 1)

    # Gate callbacks are serialized, but an already queued IRQ/timer and the
    # independent network poll path must also stay quiet until restart begins.
    for declaration in (
        'void RTL8125::interruptOccurred(OSObject *client, IOInterruptEventSource *src, int count)',
        'void RTL8125::rtl812xCheckLinkStatus(struct rtl8125_private *tp)',
        'void RTL8125::timerActionRTL8125(IOTimerEventSource *timer)',
        'void RTL8125::pollInputPackets(IONetworkInterface *interface, uint32_t maxCount, IOMbufQueue *pollQueue, void *context )',
    ):
        once(declaration + '\n{\n', declaration + '\n{\n'
             '    if (r39RxPaused()) return;\n')
    declaration = 'IOReturn RTL8125::setInputPacketPollingEnable(IONetworkInterface *interface, bool enabled)'
    once(declaration + '\n{\n', declaration + '\n{\n'
         '    if (r39RxPaused()) return kIOReturnSuccess;\n')
    return text


def pool_receive(text):
    return text.replace('        if (r15Pool) {',
        '        if (r34Rx && !r34RxCanReplace()) {\n'
        '            replaced = false;\n'
        '            newPkt = r34RxCopy(bufPkt, (UInt32)pktSize);\n'
        '        } else if (r15Pool) {', 1)


def rx_business(text):
    text = BASE['rx_business'](text)
    return text.replace('            r27RxParse(rxPacketHead, &r27RxToken, &r27RxReq);',
                        '            if (r34Rx) r34RxParse(rxPacketHead, &r27RxToken, &r27RxReq);\n'
                        '            else r27RxParse(rxPacketHead, &r27RxToken, &r27RxReq);', 1)


def rx_rearm(text):
    text = BASE['rx_rearm'](text)
    start = text.index('        r15PoolRearm(')
    # The original block includes descriptor publication and RX-post evidence.
    # Native batching moves both into Publish; history keeps the same block.
    old = text[start:]
    return text[:start] + (
        '        if (r34Rx) {\n'
        '            if (!r34RxRearm(rxNextDescIndex, r27RxToken, r27RxReq, replaced, &addr) ||\n'
        '                !r36RxPublish(rxNextDescIndex, addr, obsRxAddr, word1)) break;\n'
        '        } else {\n' + old + '        }\n')


def rx_decl(text):
    return BASE['rx_decl'](text)


def rx_capture(text):
    return BASE['rx_capture'](text) + (
        '        replaced = false;\n'
        '        if (r34Rx && !r36RxBeginBatch(rxNextDescIndex, maxCount - goodPkts)) break;\n'
        '        if (r34Rx && !r34RxComplete(rxNextDescIndex, obsRxAddr, descStatus1,\n'
        '                                      (UInt32)(descStatus1 & 0x1fff))) break;\n')
