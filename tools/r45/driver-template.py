"""Ordinary mapped TX backpressure and bounded IPv4 TSO observations.

This layers onto R44's device IOMapper path. It keeps the existing packet
commands, TX ring, hardware completion and ordinary interface lifecycle.
"""

PUBLIC = '''    virtual IOReturn setProperties(OSObject *properties) override;
'''

MEMBERS = '''
    /* Round45: lifetime counters for the ordinary mapped TCP/TSO4 path. */
    struct R45TsoStats {
        UInt64 posted, completed, stopRetired;
        UInt64 postedBytes, completedBytes;
        UInt64 maxLength, maxSegments, maxMss;
        UInt64 mapFailures, commandWaits, snapshotSequence;
    } r45Tso;
    bool r45TxCommandReady();
    void r45Tso4PostedPacket(UInt32 command, UInt32 length,
                            UInt32 segments, UInt32 options2);
    void r45Tso4RetiredPacket(UInt32 command, UInt32 length, bool stopped);
    void r45PublishTSO();
    static IOReturn r45SnapshotAction(OSObject *, void *, void *, void *, void *);
'''

METHODS = r'''
/* Round45: this is a readiness check, not a new queue. The sole output
 * thread consumes commands; hardware completion returns them and already
 * signals that thread. commandWaits counts failed readiness checks. */
bool RTL8125::r45TxCommandReady()
{
    if (!useAppleVTD) return true;
    const bool ready = txMapInfo &&
        __atomic_load_n(&txMapInfo->txNumFreeMem, __ATOMIC_ACQUIRE) > 1;
    if (!ready && r44NormalMapped)
        __atomic_fetch_add(&r45Tso.commandWaits, 1ULL, __ATOMIC_RELAXED);
    return ready;
}

static void r45AtomicMax(UInt64 *value, UInt64 candidate)
{
    UInt64 old = __atomic_load_n(value, __ATOMIC_RELAXED);
    while (old < candidate &&
           !__atomic_compare_exchange_n(value, &old, candidate, false,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {}
}

void RTL8125::r45Tso4PostedPacket(UInt32 command, UInt32 length,
                                UInt32 segments, UInt32 options2)
{
    if (!r44NormalMapped || !(command & GiantSendv4)) return;
    /* Called only after the first descriptor's OWN bit is handed off. */
    __atomic_fetch_add(&r45Tso.postedBytes, (UInt64)length, __ATOMIC_RELAXED);
    r45AtomicMax(&r45Tso.maxLength, length);
    r45AtomicMax(&r45Tso.maxSegments, segments);
    r45AtomicMax(&r45Tso.maxMss, (options2 >> MSSShift_8125) & MSSMask);
    __atomic_fetch_add(&r45Tso.posted, 1ULL, __ATOMIC_RELEASE);
}

void RTL8125::r45Tso4RetiredPacket(UInt32 command, UInt32 length, bool stopped)
{
    if (!r44NormalMapped || !(command & GiantSendv4)) return;
    if (stopped) {
        /* Ring clear is reclamation, never evidence of hardware completion. */
        __atomic_fetch_add(&r45Tso.stopRetired, 1ULL, __ATOMIC_RELAXED);
    } else {
        __atomic_fetch_add(&r45Tso.completedBytes, (UInt64)length, __ATOMIC_RELAXED);
        __atomic_fetch_add(&r45Tso.completed, 1ULL, __ATOMIC_RELEASE);
    }
}

void RTL8125::r45PublishTSO()
{
    if (!r44NormalMapped) return;
    /* Snapshot/disable run on the existing command gate. Output counters
     * are individually atomic; accounting equality is checked after drain. */
#define R45_PROP(name, member) \
    setProperty("rtl812x-r45-" name, \
        __atomic_load_n(&r45Tso.member, __ATOMIC_ACQUIRE), 64)
    R45_PROP("tso4-posted", posted);
    R45_PROP("tso4-completed", completed);
    R45_PROP("tso4-stop-retired", stopRetired);
    R45_PROP("tso4-posted-bytes", postedBytes);
    R45_PROP("tso4-completed-bytes", completedBytes);
    R45_PROP("tso4-max-length", maxLength);
    R45_PROP("tso4-max-segments", maxSegments);
    R45_PROP("tso4-max-mss", maxMss);
    R45_PROP("map-failures", mapFailures);
    R45_PROP("command-waits", commandWaits);
#undef R45_PROP
    setProperty("rtl812x-r45-tso4-enabled", (UInt64)enableTSO4, 64);
    setProperty("rtl812x-r45-tso6-enabled", (UInt64)enableTSO6, 64);
    setProperty("rtl812x-r45-tx-free-commands", (UInt64)(txMapInfo ?
        __atomic_load_n(&txMapInfo->txNumFreeMem, __ATOMIC_ACQUIRE) : 0), 64);
    setProperty("rtl812x-r45-tx-free-descriptors",
        (UInt64)__atomic_load_n(&txNumFreeDesc, __ATOMIC_ACQUIRE), 64);
    setProperty("rtl812x-r45-snapshot-seq", ++r45Tso.snapshotSequence, 64);
}

IOReturn RTL8125::r45SnapshotAction(OSObject *owner, void *, void *, void *, void *)
{
    RTL8125 *me = OSDynamicCast(RTL8125, owner);
    if (!me || !me->r44NormalMapped) return kIOReturnNotReady;
    me->r45PublishTSO();
    return kIOReturnSuccess;
}

IOReturn RTL8125::setProperties(OSObject *properties)
{
    OSDictionary *dict = OSDynamicCast(OSDictionary, properties);
    OSObject *request = dict ? dict->getObject("R45Snapshot") : NULL;
    if (!request) return super::setProperties(properties);
    OSBoolean *value = OSDynamicCast(OSBoolean, request);
    if (!value || !value->isTrue()) return kIOReturnBadArgument;
    if (!commandGate || !r44NormalMapped) return kIOReturnNotReady;
    return commandGate->runAction(r45SnapshotAction);
}
'''

INIT_OLD = '        hasSensor = false;\n'
INIT_NEW = '        bzero(&r45Tso, sizeof(r45Tso));\n' + INIT_OLD

DEQUEUE_OLD = '    while ((txNumFreeDesc > (kMaxSegs + 3)) && (r32TxDequeue(interface, &m))) {'
DEQUEUE_NEW = '''    while ((txNumFreeDesc > (kMaxSegs + 3)) && r45TxCommandReady() &&
           (r32TxDequeue(interface, &m))) {'''

RESULT_OLD = '    result = (r17TxOutputReady() && (txNumFreeDesc > (kMaxSegs + 3))) ? kIOReturnSuccess : kIOReturnNoResources;'
RESULT_NEW = '''    result = (r17TxOutputReady() && r45TxCommandReady() &&
              (txNumFreeDesc > (kMaxSegs + 3))) ? kIOReturnSuccess : kIOReturnNoResources;'''

FAILED_OLD = '''        if (!numSegs) {
            DebugLog("getPhysicalSegmentsWithCoalesce() failed. Dropping packet.\\n");'''
FAILED_NEW = '''        if (!numSegs) {
            if (r44NormalMapped && useAppleVTD)
                __atomic_fetch_add(&r45Tso.mapFailures, 1ULL, __ATOMIC_RELAXED);
            DebugLog("getPhysicalSegmentsWithCoalesce() failed. Dropping packet.\\n");'''

POST_OLD = '''        firstDesc->opts1 |= DescOwn;
        admission.handoff();'''
POST_NEW = '''        firstDesc->opts1 |= DescOwn;
        r45Tso4PostedPacket(cmd, len, numSegs, opts2);
        admission.handoff();'''

COMPLETE_OLD = '''            if (useAppleVTD)
                txUnmapPacket();

            freePacket(m, kDelayFree);'''
COMPLETE_NEW = '''            if (useAppleVTD)
                txUnmapPacket();
            /* Only txInterrupt's hardware close pointer reaches this path. */
            r45Tso4RetiredPacket(
                OSSwapLittleToHostInt32(txDescArray[txDirtyDescIndex].opts1),
                (UInt32)mbuf_pkthdr_len(m), false);

            freePacket(m, kDelayFree);'''

DISABLE_OLD = '    r44PublishNormalDMA(false);\n'
DISABLE_NEW = DISABLE_OLD + '    r45PublishTSO();\n'

CLEAR_OLD = '''    for (i = 0; i < kNumTxDesc; i++) {
        txDescArray[i].opts1 = OSSwapHostToLittleInt32((i != kTxLastDesc) ? 0 : RingEnd);
        m = txMbufArray[i];
\x20\x20\x20\x20\x20\x20\x20\x20
        if (m) {
            freePacket(m);'''
CLEAR_NEW = '''    for (i = 0; i < kNumTxDesc; i++) {
        const UInt32 r45Command = OSSwapLittleToHostInt32(txDescArray[i].opts1);
        txDescArray[i].opts1 = OSSwapHostToLittleInt32((i != kTxLastDesc) ? 0 : RingEnd);
        m = txMbufArray[i];
\x20\x20\x20\x20\x20\x20\x20\x20
        if (m) {
            r45Tso4RetiredPacket(r45Command, (UInt32)mbuf_pkthdr_len(m), true);
            freePacket(m);'''

MAP_OLD = '''    if (packet && vector && maxSegs) {
        srcRange = txMapInfo->txSCRange;'''
MAP_NEW = '''    /* Output admission reserves capacity by leaving one command unused.
     * Never report source fragments as mapped output when commands run out. */
    if (!txMapInfo ||
        __atomic_load_n(&txMapInfo->txNumFreeMem, __ATOMIC_ACQUIRE) <= 1)
        return 0;
    if (packet && vector && maxSegs) {
        srcRange = txMapInfo->txSCRange;'''

MAP_BLOCK_OLD = '        if (txMapInfo->txNumFreeMem > 1) {\n'
MAP_BLOCK_NEW = '''        /* The sole output thread consumes commands; completion only adds
         * capacity, so the admission check above remains valid here. */
        {
'''

# Round45's IOResources mapper service can be started just after this driver's
# start(): IOKit matching for the two providers is not ordered. The single
# copyMapperForDevice() lookup must see iommu-parent, so wait for that
# publication with a hard bound while the PCI provider is still unopened.
WAIT_OLD = '    pciDevice->retain();\n\n    if (!pciDevice->open(this)) {'
WAIT_NEW = '''    pciDevice->retain();

    /* Round45: the per-device mapper is published by a separate IOResources
     * service. Wait only for that publication, with a hard bound, before the
     * one-shot lookup below; the nub stays unopened so the probe can still
     * attach. A missing mapper leaves the ordinary physical path unchanged. */
    for (UInt32 r45WaitMs = 0; r45WaitMs < 2000; ++r45WaitMs) {
        if (pciDevice->getProperty("iommu-parent")) break;
        IOSleep(1);
    }

    if (!pciDevice->open(this)) {'''


def patch(hpp, cpp, setup, vtd):
    def once(text, old, new, label):
        if text.count(old) != 1:
            raise SystemExit('refused: round45 %s anchor count %d' %
                             (label, text.count(old)))
        return text.replace(old, new, 1)

    hpp = once(hpp, '    virtual void free() override;\n',
               '    virtual void free() override;\n' + PUBLIC, 'snapshot override')
    hpp = once(hpp, '    bool hasSensor;\n', '    bool hasSensor;\n' + MEMBERS,
               'TSO counters')
    for old, new, label in (
        (INIT_OLD, INIT_NEW, 'initialization'),
        (DEQUEUE_OLD, DEQUEUE_NEW, 'command admission'),
        (RESULT_OLD, RESULT_NEW, 'command backpressure'),
        (FAILED_OLD, FAILED_NEW, 'mapping failures'),
        (POST_OLD, POST_NEW, 'actual TSO submission'),
        (COMPLETE_OLD, COMPLETE_NEW, 'hardware completion'),
        (DISABLE_OLD, DISABLE_NEW, 'disable snapshot'),
        (WAIT_OLD, WAIT_NEW, 'mapper publication wait'),
    ):
        cpp = once(cpp, old, new, label)
    anchor = '\n#pragma mark --- statistics update methods ---\n'
    cpp = once(cpp, anchor, '\n' + METHODS + anchor, 'TSO methods')
    setup = once(setup, CLEAR_OLD, CLEAR_NEW, 'stop reclamation')
    vtd = once(vtd, MAP_OLD, MAP_NEW, 'mapped command exhaustion')
    vtd = once(vtd, MAP_BLOCK_OLD, MAP_BLOCK_NEW, 'mapped command admission')
    return hpp, cpp, setup, vtd


def is_current(hpp, cpp, setup, vtd):
    import re
    norm = lambda s: re.sub(r'\s+', ' ', s).strip()
    for text, blocks in (
        (hpp, (PUBLIC, MEMBERS)),
        (cpp, (METHODS, INIT_NEW, DEQUEUE_NEW, RESULT_NEW, FAILED_NEW,
               POST_NEW, COMPLETE_NEW, DISABLE_NEW)),
        (setup, (CLEAR_NEW,)),
        (vtd, (MAP_NEW, MAP_BLOCK_NEW)),
    ):
        if any(norm(block) not in norm(text) for block in blocks):
            return False
    return True
