"""Driver-owned RX mappings on Lucy's normal replacement path.

The ordinary non-VTD receive loop stays in use. Each ring slot owns one virtual
MD/command pair. Completion retires its mapping before replaceOrCopyPacket can
deliver the old mbuf; the replacement is mapped before the next OWN publication.
The older RX4 path remains selectable from its original template.
"""
from pathlib import Path
import runpy

BASE = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'r27/driver-template.py'))
HEADERS = BASE['HEADERS'] + ['RTL812xRxNative.hpp']
MEMBERS = BASE['MEMBERS'] + r'''
    struct R34RxState;
    R34RxState *r34Rx = nullptr;
    static IOReturn r34RxAction(OSObject *, void *, void *, void *, void *);
    IOReturn r34RxControl(r34rx::Request *);
    bool r34RxBinding(UInt32, UInt32, r34rx::MapRecord *, UInt64 = 0);
    bool r34RxMapSlot(UInt32);
    bool r34RxUnmapSlot(UInt32);
    bool r34RxComplete(UInt32, UInt64, UInt32, UInt32);
    bool r34RxRearm(UInt32, UInt32, UInt32, bool, UInt64 *);
    void r34RxPosted(UInt32, UInt64);
    bool r34RxCanReplace() const;
    bool r34RxOwnsRing() const;
    bool r34RxFree();
    void r34RxResumePhysical();
    void r34RxInvalidate();
    bool r34RxParse(mbuf_t, UInt32 *, UInt32 *);
'''

METHODS = r'''
#pragma mark --- round34 driver-owned normal RX replacement ---

struct RTL8125::R34RxState {
    r34rx::Snapshot snapshot;
    IOMapper *mapper;
    void *context;
    r34rx::Callback callback;
    IOMemoryDescriptor *memory[r34rx::kCount];
    IODMACommand *command[r34rx::kCount];
    IOAddressRange ranges[r34rx::kCount];
    bool bound[r34rx::kCount], wired[r34rx::kCount], mapped[r34rx::kCount];
    bool restorePending[r34rx::kCount];
    r34rx::Witness current[r34rx::kCount];
    bool ringOwned, physicalResumed;
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

bool RTL8125::r34RxMapSlot(UInt32 slot)
{
    R34RxState *p = r34Rx;
    auto &s = p->snapshot;
    auto &w = p->current[slot];
    IOMemoryDescriptor *md = p->memory[slot];
    IODMACommand *cmd = p->command[slot];
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
        (r34Rx->snapshot.state == r34rx::kInstalled && r15Pool &&
         r15Pool->snap.state == r15pool::kAuthorized));
}

bool RTL8125::r34RxOwnsRing() const
{
    return r34Rx && r34Rx->ringOwned;
}

bool RTL8125::r34RxComplete(UInt32 slot, UInt64 oldAddr,
                           UInt32 status, UInt32 length)
{
    R34RxState *p = r34Rx;
    if (!p || p->physicalResumed || p->snapshot.state == r34rx::kReleased)
        return true;
    if (p->snapshot.state == r34rx::kInstalled &&
        r15Pool->snap.state != r15pool::kAuthorized) return true;
    if (!p->mapped[slot]) return true;
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
    // Unmap BEFORE replaceOrCopyPacket can return the old mbuf to the stack.
    return r34RxUnmapSlot(slot);
}

bool RTL8125::r34RxRearm(UInt32 slot, UInt32 token, UInt32 reqId,
                        bool replaced, UInt64 *addr)
{
    R34RxState *p = r34Rx;
    auto &s = p->snapshot;
    auto &d = s.slots[slot];
    auto &w = p->current[slot];
    if (p->physicalResumed || s.state == r34rx::kReleased) return true;
    if (s.state == r34rx::kInstalled &&
        r15Pool->snap.state != r15pool::kAuthorized) return true;
    if (replaced) { s.replaced++; d.replaceCount++; }
    if (w.tPost && w.tDone && !w.reserved) {
        w.token = token; w.reqId = reqId; w.replaced = replaced ? 1u : 0u;
        d.last = w;
        if (!d.sampleCount) { d.samples[0] = w; d.sampleCount = 1; }
        w.reserved = 1; // do not relabel this DMA with later physical tail packets
    }
    if (s.state == r34rx::kInstalled) {
        if (!r34RxMapSlot(slot)) return false;
        *addr = p->current[slot].iova;
        rxBufArray[slot].phyAddr = *addr;
    } else if (!d.tPhysicalOwn) {
        // Replacement mbufs need not belong to the initial bootstrap set.
        // Add their current physical span before publishing physical OWN.
        const UInt64 pa = mbuf_data_to_physical(mbuf_datastart(rxBufArray[slot].mbuf));
        if (!pa || !r34RxBinding(r34rx::kCover, slot, nullptr, pa)) {
            s.flags |= r34rx::kFlagCoverFailed;
            return false;
        }
        d.currentPA = pa; *addr = pa; rxBufArray[slot].phyAddr = pa;
        p->restorePending[slot] = true;
    }
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
        s.posted++; d.postCount++; s.pendingPosted++;
    } else if (p->restorePending[slot] && addr == d.currentPA) {
        p->restorePending[slot] = false;
        d.tPhysicalOwn = mach_absolute_time();
        s.tLastRestore = d.tPhysicalOwn; s.restored++;
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
        request->op > r34rx::kRelease) return kIOReturnBadArgument;
    R15PoolState *pool = r15Pool;
    if (!pool || !rxBufArray || !rxDescArray || !rxPool) return kIOReturnNotReady;
    if (request->poolId != pool->snap.poolId ||
        request->expectedGeneration != pool->snap.generation) return kIOReturnBadArgument;
    if (request->op == r34rx::kInstall) {
        if (r34Rx || pool->rx27.version || pool->snap.state != r15pool::kPrepared ||
            pool->snap.flags || !request->mapper || !request->context || !request->callback ||
            !request->businessToken || request->businessToken != pool->snap.reserved[0])
            return kIOReturnBadArgument;
        r34Rx = (R34RxState *)IOMallocZero(sizeof(R34RxState));
        if (!r34Rx) return kIOReturnNoMemory;
        auto *p = r34Rx;
        auto &s = p->snapshot;
        p->mapper = static_cast<IOMapper *>(request->mapper); p->mapper->retain();
        p->context = request->context; p->callback = request->callback;
        s.version = r34rx::kVersion; s.bytes = sizeof(s); s.slotCount = r34rx::kCount;
        s.poolId = request->poolId; s.businessToken = request->businessToken;
        for (UInt32 slot = 0; slot < r34rx::kCount; ++slot) {
            s.slots[slot].originalPA = rxBufArray[slot].phyAddr;
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
        // These ring mbufs now follow Lucy's ordinary replace/copy ownership.
        // R15 keeps only its unused bootstrap spares and must never free a
        // ring mbuf which replaceOrCopyPacket has already delivered upstream.
        for (UInt32 slot = 0; slot < r34rx::kCount; ++slot) pool->mbufs[slot] = nullptr;
        p->ringOwned = true;
        s.state = r34rx::kInstalled; s.nativeActive = 1;
        s.tInstalled = mach_absolute_time();
    } else {
        if (!r34Rx) return kIOReturnNotReady;
        auto *p = r34Rx;
        auto &s = p->snapshot;
        if (request->op == r34rx::kDisarm || request->op == r34rx::kDrain) {
            __atomic_store_n(&pool->snap.state, (UInt32)r15pool::kDisarmed, __ATOMIC_RELEASE);
            if (!s.tDisarmed) s.tDisarmed = mach_absolute_time();
            if (s.state != r34rx::kReleased)
                s.state = (request->op == r34rx::kDrain && !s.pendingPosted &&
                    s.restored == r34rx::kCount) ? r34rx::kDrained : r34rx::kDisarmed;
        } else if (request->op == r34rx::kRelease) {
            if (s.state != r34rx::kDrained || s.pendingPosted || s.posted != s.completed)
                return kIOReturnBusy;
            for (UInt32 slot = 0; slot < r34rx::kCount; ++slot) {
                if (p->mapped[slot] || p->wired[slot] ||
                    !r34RxBinding(r34rx::kUnbind, slot, nullptr)) return kIOReturnBusy;
                p->bound[slot] = false;
                if (p->command[slot]) { p->command[slot]->release(); p->command[slot] = nullptr; }
                if (p->memory[slot]) { p->memory[slot]->release(); p->memory[slot] = nullptr; }
            }
            p->mapper->release(); p->mapper = nullptr;
            p->context = nullptr; p->callback = nullptr;
            s.state = r34rx::kReleased; s.nativeActive = 0;
        }
    }
    const auto &s = r34Rx->snapshot;
    bcopy(&s, &request->out, sizeof(s));
    OSData *raw = OSData::withBytes(&s, sizeof(s));
    if (raw) { setProperty("rtl812x-r34-rx-native-raw", raw); raw->release(); }
    setProperty("rtl812x-r34-rx-mode", "driver-owned-replacement");
    setProperty("rtl812x-r34-rx-state", s.state, 32);
    setProperty("rtl812x-r34-rx-maps", s.maps, 32);
    setProperty("rtl812x-r34-rx-unmaps", s.unmaps, 32);
    setProperty("rtl812x-r34-rx-replaced", s.replaced, 32);
    setProperty("rtl812x-r34-rx-flags", s.flags, 32);
    return kIOReturnSuccess;
}

void RTL8125::r34RxResumePhysical()
{
    // Probe calls R15 Finish only after restoring the original hardware state.
    // Until this point the restored physical ring remains copy-only for R29D.
    if (r34Rx && r34Rx->snapshot.state == r34rx::kReleased)
        r34Rx->physicalResumed = true;
}

void RTL8125::r34RxInvalidate()
{
    if (r34Rx && r34Rx->snapshot.state != r34rx::kReleased) {
        r34Rx->snapshot.flags |= r34rx::kFlagRingReset;
        r34Rx->snapshot.state = r34rx::kDisarmed;
    }
}

bool RTL8125::r34RxFree()
{
    if (!r34Rx) return true;
    for (UInt32 slot = 0; slot < r34rx::kCount; ++slot)
        if (r34Rx->mapped[slot] || r34Rx->wired[slot] || r34Rx->bound[slot]) return false;
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
    once('    } else if (request->op == r15pool::kDisarm) {\n',
         '    } else if (request->op == r15pool::kDisarm) {\n'
         '        r34RxResumePhysical();\n')
    once('void RTL8125::r15PoolInvalidate()\n{\n',
         'void RTL8125::r15PoolInvalidate()\n{\n    r34RxInvalidate();\n')
    once('    if (rxBufArray) for (UInt32 i = 0; i < r15pool::kRingCount; i++) {\n',
         '    const bool nativeRing = r34RxOwnsRing();\n'
         '    if (!r34RxFree()) {\n'
         '        if (rxBufArray) for (UInt32 i = 0; i < r15pool::kRingCount; i++)\n'
         '            rxBufArray[i].mbuf = nullptr;\n'
         '        setProperty("rtl812x-r34-rx-stop", "PINNED-mappings-not-released");\n'
         '        return;\n'
         '    }\n'
         '    if (rxBufArray && !nativeRing) for (UInt32 i = 0; i < r15pool::kRingCount; i++) {\n')
    return text + '\n' + METHODS


def pool_receive(text):
    return text.replace('if (r15Pool) {', 'if (r15Pool && !r34RxCanReplace()) {', 1)


def rx_business(text):
    text = BASE['rx_business'](text)
    return text.replace('            r27RxParse(rxPacketHead, &r27RxToken, &r27RxReq);',
                        '            if (r34Rx) r34RxParse(rxPacketHead, &r27RxToken, &r27RxReq);\n'
                        '            else r27RxParse(rxPacketHead, &r27RxToken, &r27RxReq);', 1)


def rx_rearm(text):
    text = BASE['rx_rearm'](text)
    start = text.index('        r15PoolRearm(')
    end = text.index('        desc->buf.addr =', start)
    old = text[start:end]
    text = text[:start] + (
        '        if (r34Rx) {\n'
        '            if (!r34RxRearm(rxNextDescIndex, r27RxToken, r27RxReq, replaced, &addr)) break;\n'
        '        } else {\n' + old + '        }\n') + text[end:]
    return text.replace('        r15PoolPosted(rxNextDescIndex, addr);',
        '        if (r34Rx) r34RxPosted(rxNextDescIndex, addr);\n'
        '        else r15PoolPosted(rxNextDescIndex, addr);', 1)


def rx_decl(text):
    return BASE['rx_decl'](text)


def rx_capture(text):
    return BASE['rx_capture'](text) + (
        '        replaced = false;\n'
        '        if (r34Rx && !r34RxComplete(rxNextDescIndex, obsRxAddr, descStatus1,\n'
        '                                      (UInt32)(descStatus1 & 0x1fff))) break;\n')
