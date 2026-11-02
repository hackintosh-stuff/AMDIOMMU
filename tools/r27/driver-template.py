"""Round27 finite RX mapping hooks layered on the round15 owned pool.

The probe prepares the standard commands outside Lucy's command gate.  Lucy
only installs already-invalidated IOVAs, posts each spare once, then restores
the original physical buffer at that descriptor's next hand-back.  No mapper
operation, allocation, or waiting is added to the receive interrupt.
"""

HEADERS = ['RTL812xRxMap.hpp', 'AMDAliveTxDomainNative.hpp']

MEMBERS = r'''
    static IOReturn r27RxAction(OSObject *, void *, void *, void *, void *);
    IOReturn r27RxControl(r27rx::Request *request);
    void r27RxRearm(UInt32 slot, UInt64 oldAddr, UInt32 status,
                   UInt32 length, UInt32 token, UInt32 reqId, UInt64 *addr);
    void r27RxPosted(UInt32 slot, UInt64 addr);
    bool r27RxActive();
    bool r27RxParse(mbuf_t packet, UInt32 *token, UInt32 *reqId);
'''

METHODS = r'''
#pragma mark --- round 27 one-shot standard-mapped receive spares ---

IOReturn RTL8125::r27RxAction(OSObject *owner, void *arg0,
                            void *, void *, void *)
{
    RTL8125 *self = (RTL8125 *)owner;
    if (self->useAppleVTD) return kIOReturnUnsupported;
    if (test_and_set_bit(__POLLING, &self->stateFlags)) return kIOReturnBusy;
    IOReturn result = self->r27RxControl((r27rx::Request *)arg0);
    clear_bit(__POLLING, &self->stateFlags);
    return result;
}

IOReturn RTL8125::r27RxControl(r27rx::Request *request)
{
    if (!request || request->version != r27rx::kVersion ||
        request->bytes != sizeof(*request) || request->op < r27rx::kInstall ||
        request->op > r27rx::kHold) return kIOReturnBadArgument;
    R15PoolState *p = r15Pool;
    if (!p || !rxBufArray || !rxDescArray) return kIOReturnNotReady;
    if (request->poolId != p->snap.poolId ||
        request->expectedGeneration != p->snap.generation)
        return kIOReturnBadArgument;
    r27rx::Snapshot &s = p->rx27;
    if (request->op == r27rx::kHold) {
        /* Physical memory descriptors do not retain their mbuf backing.  Take
         * this owner hold before the probe creates its FIRST standard command,
         * including the partial-map failure path which may never Install. */
        if (s.version || p->snap.state != r15pool::kPrepared || p->snap.flags ||
            p->snap.replacements || !request->businessToken ||
            request->businessToken != p->snap.reserved[0])
            return kIOReturnBadArgument;
        bzero(&s, sizeof(s));
        s.version = r27rx::kVersion; s.bytes = sizeof(s);
        s.state = r27rx::kHeld; s.generation = p->snap.generation;
        s.poolId = p->snap.poolId; s.businessToken = request->businessToken;
        p->rx27BindingsHeld = true;
    } else if (request->op == r27rx::kInstall) {
        /* Install only binds immutable, already-mapped spares.  R15 Authorize
         * still owns the bounded replacement window; no descriptor is changed
         * by this control call and no DMACommand is prepared under the gate. */
        const UInt64 now = mach_absolute_time();
        if (s.state != r27rx::kHeld || !p->rx27BindingsHeld ||
            p->snap.state != r15pool::kPrepared || p->snap.flags ||
            p->snap.replacements || request->mapCount != r27rx::kCount ||
            request->replaceLimit != r27rx::kCount ||
            !request->businessToken ||
            request->businessToken != p->snap.reserved[0])
            return kIOReturnBadArgument;
        for (UInt32 i = 0; i < r27rx::kCount; ++i) {
            const r27rx::Mapping &m = request->maps[i];
            const UInt32 id = r15pool::kRingCount + i;
            const r15pool::Entry &e = p->snap.entries[id];
            const UInt64 expected = r27rx::kIovaBase +
                (UInt64)i * r27rx::kPagesPerSlot * 4096ULL + (e.addr & 4095ULL);
            if (e.id != id || e.kind != r15pool::kEntrySpare ||
                m.entryId != id || m.pa != e.addr ||
                m.capacity != r27rx::kCapacity || e.capacity != m.capacity ||
                m.iova != expected || m.iova == m.pa || !m.tMapInv ||
                m.tMapInv < p->snap.tPrepared || m.tMapInv > now)
                return kIOReturnBadArgument;
        }
        bzero(&s, sizeof(s));
        s.version = r27rx::kVersion; s.bytes = sizeof(s);
        s.state = r27rx::kInstalled;
        s.generation = p->snap.generation; s.poolId = p->snap.poolId;
        s.mapCount = request->mapCount; s.businessToken = request->businessToken;
        s.tInstalled = now;
        bcopy(request->maps, s.maps, sizeof(s.maps));
    } else {
        if (!s.version) return kIOReturnNotReady;
        if (request->op == r27rx::kDisarm || request->op == r27rx::kDrain) {
            __atomic_store_n(&p->snap.state, (UInt32)r15pool::kDisarmed,
                             __ATOMIC_RELEASE);
            if (!s.tDisarmed) s.tDisarmed = mach_absolute_time();
            if (s.state != r27rx::kReleased)
                s.state = (request->op == r27rx::kDrain && !s.pendingPosted)
                    ? r27rx::kDrained : r27rx::kDisarmed;
        } else if (request->op == r27rx::kRelease) {
            /* This is the probe's acknowledgement of all 64 confirmed unmaps.
             * A clear pending count alone is insufficient: every live ring
             * association must again be its retained original physical object. */
            if (s.state != r27rx::kDrained || s.pendingPosted ||
                s.posted != s.restored) return kIOReturnBusy;
            for (UInt32 slot = 0; slot < r15pool::kRingCount; ++slot) {
                if (p->slotId[slot] != slot ||
                    rxBufArray[slot].mbuf != p->mbufs[slot] ||
                    rxBufArray[slot].phyAddr != p->snap.entries[slot].addr ||
                    OSSwapLittleToHostInt64(rxDescArray[slot].buf.addr) !=
                        p->snap.entries[slot].addr)
                    return kIOReturnBusy;
            }
            p->rx27BindingsHeld = false;
            s.state = r27rx::kReleased;
        }
    }
    bcopy(&s, &request->out, sizeof(s));
    setProperty("rtl812x-r27-rx-state", s.state, 32);
    setProperty("rtl812x-r27-rx-posted", s.posted, 32);
    setProperty("rtl812x-r27-rx-completed", s.completed, 32);
    setProperty("rtl812x-r27-rx-restored", s.restored, 32);
    setProperty("rtl812x-r27-rx-pending", s.pendingPosted, 32);
    setProperty("rtl812x-r27-rx-flags", s.flags, 32);
    return kIOReturnSuccess;
}

void RTL8125::r27RxRearm(UInt32 slot, UInt64 oldAddr, UInt32 status,
    UInt32 length, UInt32 token, UInt32 reqId, UInt64 *addr)
{
    R15PoolState *p = r15Pool;
    if (!p || !p->rx27.version || !addr || slot >= r15pool::kRingCount) return;
    r27rx::Snapshot &s = p->rx27;
    const UInt64 now = mach_absolute_time();
    const bool copyFailed = p->rx27CopyFailed;
    p->rx27CopyFailed = false;
    p->snap.rxCompletions++;
    const UInt32 id = p->slotId[slot];
    const bool spare = id >= r15pool::kRingCount && id < p->snap.entryCount;
    const UInt32 ix = spare ? id - r15pool::kRingCount : (UInt32)r27rx::kCount;
    const UInt64 expected = spare && ix < s.mapCount
        ? s.maps[ix].iova : p->snap.entries[slot].addr;
    const bool matches = id < p->snap.entryCount &&
        (spare || id == slot) && oldAddr == expected &&
        rxBufArray[slot].mbuf == p->mbufs[id] &&
        rxBufArray[slot].phyAddr == expected &&
        OSSwapLittleToHostInt64(rxDescArray[slot].buf.addr) == expected;
    if (!matches) {
        s.flags |= r27rx::kFlagAddressMismatch;
        p->snap.flags |= r15pool::kFlagAddressMismatch;
        s.state = r27rx::kDisarmed;
        __atomic_store_n(&p->snap.state, (UInt32)r15pool::kDisarmed,
                         __ATOMIC_RELEASE);
    }
    if (copyFailed) s.flags |= r27rx::kFlagCopyFailed;

    if (spare && ix < s.mapCount) {
        r27rx::Witness &w = s.witnesses[ix];
        /* The hardware has handed THIS descriptor back.  Restoration precedes
         * every authorization/deadline check, even for an error or failed copy.
         * No caller may leave an IOVA posted when translation is restored. */
        if (!w.tDone && w.tPost && w.slot == slot && w.entryId == id) {
            w.tDone = now; w.token = token; w.reqId = reqId;
            w.doneLength = length; w.doneStatus = status;
            w.flags |= r27rx::kWitnessDone;
            if (!matches || copyFailed || (status & RxRES))
                w.flags |= r27rx::kWitnessError;
            s.completed++;
            r15pool::Witness &old = p->snap.witnesses[ix];
            old.tDone = now; old.token = token; old.reqId = reqId;
            old.doneLength = length; old.doneStatus = status;
            old.flags = (w.flags & r27rx::kWitnessError)
                ? r15pool::kWitnessError : r15pool::kWitnessCompleted;
            p->snap.completions++;
        } else {
            s.flags |= r27rx::kFlagAddressMismatch;
            w.flags |= r27rx::kWitnessError;
            s.state = r27rx::kDisarmed;
            __atomic_store_n(&p->snap.state, (UInt32)r15pool::kDisarmed,
                             __ATOMIC_RELEASE);
        }
        p->slotId[slot] = slot;
        rxBufArray[slot].mbuf = p->mbufs[slot];
        rxBufArray[slot].phyAddr = p->snap.entries[slot].addr;
        *addr = p->snap.entries[slot].addr;
        /* slotWitness stays until r27RxPosted sees the physical OWN store. */
        return;
    }
    if (!matches) {
        p->slotId[slot] = slot;
        rxBufArray[slot].mbuf = p->mbufs[slot];
        rxBufArray[slot].phyAddr = p->snap.entries[slot].addr;
        *addr = p->snap.entries[slot].addr;
        return;
    }
    if (s.state != r27rx::kInstalled ||
        __atomic_load_n(&p->snap.state, __ATOMIC_ACQUIRE) != r15pool::kAuthorized)
        return;
    if (now > p->snap.deadline) {
        p->snap.flags |= r15pool::kFlagExpired;
        s.state = r27rx::kDisarmed;
        __atomic_store_n(&p->snap.state, (UInt32)r15pool::kDisarmed,
                         __ATOMIC_RELEASE);
        return;
    }
    if (copyFailed || (status & RxRES) ||
        p->snap.replacements >= p->snap.replaceLimit ||
        p->snap.replacements >= s.mapCount) return;
    const UInt32 n = p->snap.replacements;
    const UInt32 next = r15pool::kRingCount + n;
    const r27rx::Mapping &m = s.maps[n];
    r27rx::Witness &w = s.witnesses[n];
    w.originalPA = p->snap.entries[slot].addr;
    w.sparePA = m.pa; w.iova = m.iova;
    w.slot = slot; w.entryId = next;
    r15pool::Witness &old = p->snap.witnesses[n];
    old.oldAddr = oldAddr; old.newAddr = m.iova;
    old.slot = slot; old.capacity = m.capacity; old.entryId = next;
    p->slotId[slot] = next;
    p->slotWitness[slot] = n + 1;
    p->snap.replacements = n + 1;
    rxBufArray[slot].mbuf = p->mbufs[next];
    rxBufArray[slot].phyAddr = m.iova;
    *addr = m.iova;
}

void RTL8125::r27RxPosted(UInt32 slot, UInt64 addr)
{
    R15PoolState *p = r15Pool;
    if (!p || !p->rx27.version || slot >= r15pool::kRingCount) return;
    const UInt32 wi = p->slotWitness[slot];
    if (!wi || wi > p->rx27.mapCount) return;
    r27rx::Snapshot &s = p->rx27;
    r27rx::Witness &w = s.witnesses[wi - 1];
    /* The caller is after address -> barrier -> OWN.  Hardware may already
     * have cleared OWN by now, so re-reading OWN would lose a fast completion;
     * the ordered store site itself is the publication evidence. */
    if (!w.tPost && w.iova == addr && p->slotId[slot] == w.entryId) {
        w.tPost = mach_absolute_time();
        w.flags |= r27rx::kWitnessPosted;
        p->snap.witnesses[wi - 1].tPost = w.tPost;
        s.posted++; s.pendingPosted++;
    } else if (w.tDone && !w.tRestoreOwn && addr == w.originalPA &&
               p->slotId[slot] == slot) {
        w.tRestoreOwn = mach_absolute_time();
        w.flags |= r27rx::kWitnessRestored;
        s.restored++;
        if (s.pendingPosted) s.pendingPosted--;
        else s.flags |= r27rx::kFlagAddressMismatch;
        s.tLastRestore = w.tRestoreOwn;
        p->slotWitness[slot] = 0;
    }
}

bool RTL8125::r27RxActive()
{
    return r15Pool && r15Pool->rx27.version != 0;
}

bool RTL8125::r27RxParse(mbuf_t packet, UInt32 *token, UInt32 *reqId)
{
    /* Observe ordinary R27P UDP replies only.  These bytes never select a DMA
     * mapping: replacement and restoration cover non-business RX as well. */
    if (!r15Pool || !r15Pool->rx27.version || !packet || !token || !reqId)
        return false;
    UInt8 h[54]; UInt32 have = 0;
    for (mbuf_t m = packet; m && have < sizeof(h); m = mbuf_next(m)) {
        const UInt32 len = (UInt32)mbuf_len(m);
        const UInt32 take = len < sizeof(h) - have ? len : sizeof(h) - have;
        if (take) bcopy(mbuf_data(m), h + have, take);
        have += take;
    }
    if (have != sizeof(h) || h[12] != 0x08 || h[13] != 0x00 ||
        h[14] != 0x45 || h[23] != 17 || (h[20] & 0x3f) || h[21]) return false;
    const UInt32 ipLength = ((UInt32)h[16] << 8) | h[17];
    const UInt32 udpLength = ((UInt32)h[38] << 8) | h[39];
    if (ipLength < 40 || udpLength < 20 || udpLength != ipLength - 20 ||
        ipLength + 14 > (UInt32)mbuf_pkthdr_len(packet) ||
        h[42] != 'R' || h[43] != '2' || h[44] != '7' || h[45] != 'P') return false;
    const UInt32 t = ((UInt32)h[46] << 24) | ((UInt32)h[47] << 16) |
                     ((UInt32)h[48] << 8) | h[49];
    const UInt32 r = ((UInt32)h[50] << 24) | ((UInt32)h[51] << 16) |
                     ((UInt32)h[52] << 8) | h[53];
    if (!t || !r) return false;
    *token = t; *reqId = r;
    return true;
}
'''


def pool_methods(text):
    """Transform only shared R15 state/call sites; old wire types stay intact."""
    def once(old, new):
        nonlocal text
        if text.count(old) != 1:
            raise AssertionError('round27 pool anchor: ' + old)
        text = text.replace(old, new, 1)

    once('    UInt32 physicalFailures[4]; // allocation, prepare, attach, span\n',
         '    UInt32 physicalFailures[4]; // allocation, prepare, attach, span\n'
         '    r27rx::Snapshot rx27;\n'
         '    bool rx27BindingsHeld, rx27CopyFailed;\n')
    once('    if (!functionName || !functionName->isEqualTo(r15pool::kFunctionName))',
         '    if (functionName && functionName->isEqualTo(r27rx::kFunctionName)) {\n'
         '        if (!param1 || param2 || param3 || param4 || !commandGate)\n'
         '            return kIOReturnBadArgument;\n'
         '        return commandGate->runAction(r27RxAction, param1);\n'
         '    }\n'
         '    if (!functionName || !functionName->isEqualTo(r15pool::kFunctionName))')
    once('    r15Pool->snap.copyFailures++;\n',
         '    r15Pool->snap.copyFailures++;\n'
         '    if (r15Pool->rx27.version) r15Pool->rx27CopyFailed = true;\n')
    once('    if (!r15Pool || !length || length > kRxBufferSize) return NULL;\n',
         '    if (!r15Pool) return NULL;\n'
         '    if (!length || length > kRxBufferSize) {\n'
         '        r15Pool->snap.copyFailures++;\n'
         '        r15Pool->snap.flags |= r15pool::kFlagCopyFailed;\n'
         '        if (r15Pool->rx27.version) r15Pool->rx27CopyFailed = true;\n'
         '        return NULL;\n'
         '    }\n')
    once('    if (!r15Pool || slot >= r15pool::kRingCount) return;\n'
         '    R15PoolState *p = r15Pool;\n',
         '    if (!r15Pool || slot >= r15pool::kRingCount) return;\n'
         '    if (r15Pool->rx27.version) {\n'
         '        r27RxRearm(slot, oldAddr, status, length, token, reqId, addr);\n'
         '        return;\n'
         '    }\n'
         '    R15PoolState *p = r15Pool;\n')
    once('void RTL8125::r15PoolPosted(UInt32 slot, UInt64 addr)\n'
         '{\n'
         '    if (!r15Pool || slot >= r15pool::kRingCount) return;\n',
         'void RTL8125::r15PoolPosted(UInt32 slot, UInt64 addr)\n'
         '{\n'
         '    if (!r15Pool || slot >= r15pool::kRingCount) return;\n'
         '    if (r15Pool->rx27.version) { r27RxPosted(slot, addr); return; }\n')
    once('void RTL8125::r15PoolInvalidate()\n'
         '{\n'
         '    if (!r15Pool) return;\n',
         'void RTL8125::r15PoolInvalidate()\n'
         '{\n'
         '    if (!r15Pool) return;\n'
         '    if (r15Pool->rx27.version) {\n'
         '        r15Pool->rx27.flags |= r27rx::kFlagRingReset;\n'
         '        if (r15Pool->rx27.state != r27rx::kReleased)\n'
         '            r15Pool->rx27.state = r27rx::kDisarmed;\n'
         '    }\n')
    once('    for (UInt32 i = 0; i < r15Pool->snap.entryCount; i++)\n'
         '        r15ReleaseOwned(r15Pool->mbufs[i], r15Pool->regions[i]);\n',
         '    if (r15Pool->rx27BindingsHeld) {\n'
         '        /* Physical MDs do not retain mbufs.  Until confirmed unmaps\n'
         '         * are acknowledged, keep the sole owning pool even on stop. */\n'
         '        r15Pool->rx27.flags |= r27rx::kFlagStopped;\n'
         '        setProperty("rtl812x-r27-rx-stop", "PINNED-mappings-not-released");\n'
         '        return;\n'
         '    }\n'
         '    for (UInt32 i = 0; i < r15Pool->snap.entryCount; i++)\n'
         '        r15ReleaseOwned(r15Pool->mbufs[i], r15Pool->regions[i]);\n')
    return text + '\n' + METHODS


def rx_business(text):
    old = '            interface->enqueueInputPacket(rxPacketHead, pollQueue);'
    assert text.count(old) == 1
    return text.replace(old,
        '            /* Round27: independent ordinary-UDP observation, never a map selector. */\n'
        '            r27RxParse(rxPacketHead, &r27RxToken, &r27RxReq);\n\n' + old, 1)


def rx_rearm(text):
    old = '                       obsRxToken, obsRxReq, &addr);'
    assert text.count(old) == 1
    return text.replace(old,
        '                       r27RxActive() ? r27RxToken : obsRxToken,\n'
        '                       r27RxActive() ? r27RxReq : obsRxReq, &addr);', 1)


def rx_decl(text):
    return text + '    UInt32 r27RxToken = 0, r27RxReq = 0; // independent of IOB1 OBS\n'


def rx_capture(text):
    return text + '        r27RxToken = 0; r27RxReq = 0;\n'
