"""Join ordinary Lucy power callbacks to the persistent device mapper.

IONetworkingFamily disables the controller before its unusable power callback,
then re-enables it after the usable callback. Keep that resource lifecycle:
all TX retirement and RX remapping precedes suspend; mapper restore completes
before enable() can configure hardware or setLinkUp() can start DMA.

TODO(R47-PM-HARDWARE): real system sleep/resume is unavailable on this
platform. Keep the implementation for future validation; the current
round exercises ordinary networking without invoking PM transitions.
"""

MEMBERS = '''
    /* Round47: one ordinary sleep/wake cycle retains the existing DMA owners. */
    struct R47PowerStats {
        UInt64 sleepCount, wakeCount;
        UInt64 quiescedAt, suspendedAt, d3At;
        UInt64 d0At, restoredAt, enableAt, linkupAt;
        UInt64 enableBlockedCount, linkupBlockedCount;
        UInt32 sleepChipCmd, sleepStateFlags, wakeChipCmd;
        UInt32 sleepPmcsr, wakePmcsr;
        IOReturn lastError;
    } r47Power;
    bool r47PMBlocked;
    IOReturn r47MapperPower(bool waking);
    void r47PublishPM(const char *phase);
    static IOReturn r47SnapshotAction(OSObject *, void *, void *, void *, void *);
'''

METHODS = r'''
IOReturn RTL8125::r47MapperPower(bool waking)
{
    /* TODO(R47-PM-HARDWARE): validate real system sleep/resume once the
     * platform supports it. Ordinary startup and networking do not
     * call this method. */
    if (!r44NormalMapped || !mapper || !pciDevice) return kIOReturnNotReady;
    const OSSymbol *name = OSSymbol::withCString("R47PowerTransition");
    if (!name) return kIOReturnNoMemory;
    /* The mapper validates the same PCI nub that owns this driver's DMA.
     * A successful wake includes device/page invalidations and both CWs. */
    const IOReturn result = mapper->callPlatformFunction(name, false, pciDevice,
        (void *)(uintptr_t)(waking ? 2 : 1), NULL, NULL);
    name->release();
    return result;
}

void RTL8125::r47PublishPM(const char *phase)
{
    if (!r44NormalMapped) return;
    if (phase) setProperty("rtl812x-r47-pm-state", phase);
    setProperty("rtl812x-r47-pm-blocked", (UInt64)r47PMBlocked, 64);
#define R47_PROP(name, member) \
    setProperty("rtl812x-r47-" name, (UInt64)r47Power.member, 64)
    R47_PROP("sleep-count", sleepCount);
    R47_PROP("wake-count", wakeCount);
    R47_PROP("sleep-quiesced-at", quiescedAt);
    R47_PROP("sleep-suspended-at", suspendedAt);
    R47_PROP("sleep-d3-at", d3At);
    R47_PROP("wake-d0-at", d0At);
    R47_PROP("wake-restored-at", restoredAt);
    R47_PROP("wake-enable-at", enableAt);
    R47_PROP("wake-linkup-at", linkupAt);
    R47_PROP("enable-blocked-count", enableBlockedCount);
    R47_PROP("linkup-blocked-count", linkupBlockedCount);
    R47_PROP("sleep-chipcmd", sleepChipCmd);
    R47_PROP("sleep-state-flags", sleepStateFlags);
    R47_PROP("wake-chipcmd", wakeChipCmd);
    R47_PROP("sleep-pmcsr", sleepPmcsr);
    R47_PROP("wake-pmcsr", wakePmcsr);
#undef R47_PROP
    setProperty("rtl812x-r47-last-error", (UInt64)(UInt32)r47Power.lastError, 64);
}

IOReturn RTL8125::r47SnapshotAction(OSObject *owner, void *, void *, void *, void *)
{
    RTL8125 *me = OSDynamicCast(RTL8125, owner);
    if (!me || !me->r44NormalMapped) return kIOReturnNotReady;
    me->r46PublishTSO();
    me->r47PublishPM(NULL);
    return kIOReturnSuccess;
}
'''

INIT_OLD = '        bzero(&r46Tso, sizeof(r46Tso));\n'
INIT_NEW = '''        bzero(&r47Power, sizeof(r47Power));
        r47PMBlocked = false;
''' + INIT_OLD

READY_OLD = '    r44SelectNormalDMA();\n'
READY_NEW = READY_OLD + '    r47PublishPM("ready");\n'

RPC_OLD = '''    OSObject *request = dict ? dict->getObject("R46Snapshot") : NULL;
    const bool round46 = request != NULL;
    if (!request) request = dict ? dict->getObject("R45Snapshot") : NULL;'''
RPC_NEW = '''    OSObject *request = dict ? dict->getObject("R47Snapshot") : NULL;
    const bool round47 = request != NULL;
    if (!request) request = dict ? dict->getObject("R46Snapshot") : NULL;
    const bool round46 = request != NULL;
    if (!request) request = dict ? dict->getObject("R45Snapshot") : NULL;'''
ACTION_OLD = '    return commandGate->runAction(round46 ? r46SnapshotAction : r45SnapshotAction);'
ACTION_NEW = '''    return commandGate->runAction(round47 ? r47SnapshotAction :
        (round46 ? r46SnapshotAction : r45SnapshotAction));'''

ENABLE_OLD = '    DebugLog("enable() ===>\\n");\n'
ENABLE_NEW = ENABLE_OLD + '''
    /* PM errors still acknowledge IOKit's transition; they never authorize
     * this controller to touch DMA hardware before mapper restore succeeds. */
    if (r44NormalMapped && r47PMBlocked) {
        ++r47Power.enableBlockedCount;
        r47PublishPM("enable-blocked");
        return kIOReturnNotReady;
    }
'''
ENABLE_TIME_OLD = '    selectMedium(selectedMedium);\n    rtl812xEnable();\n'
ENABLE_TIME_NEW = '''    if (r44NormalMapped && r47Power.restoredAt && !r47Power.enableAt) {
        r47Power.enableAt = mach_absolute_time();
        r47PublishPM("enabled");
    }
''' + ENABLE_TIME_OLD

LINKUP_OLD = '''    /* Start hardware. */
    RTL_W8(tp, ChipCmd, CmdTxEnb | CmdRxEnb);
    /* enable() configures the chip; setLinkUp() actually starts DMA. */
    r44PublishNormalDMA(true);
'''
LINKUP_NEW = '''    /* Keep the final DMA-enable store behind the PM handshake as well. */
    if (r44NormalMapped && r47PMBlocked) {
        ++r47Power.linkupBlockedCount;
        r47PublishPM("linkup-blocked");
        return;
    }
''' + LINKUP_OLD + '''    if (r44NormalMapped && r47Power.restoredAt && !r47Power.linkupAt) {
        r47Power.wakeChipCmd = RTL_R8(tp, ChipCmd);
        r47Power.linkupAt = mach_absolute_time();
        r47PublishPM("link-up");
    }
'''

WAKE_OLD = '''IOReturn RTL8125::setPowerStateWakeAction(OSObject *owner, void *arg1, void *arg2, void *arg3, void *arg4)
{
    RTL8125 *ethCtlr = OSDynamicCast(RTL8125, owner);
    IOPCIDevice *dev;
    UInt16 val16;
    UInt8 offset;

    if (ethCtlr && ethCtlr->pciPMCtrlOffset) {
        dev = ethCtlr->pciDevice;
        offset = ethCtlr->pciPMCtrlOffset;

        val16 = dev->extendedConfigRead16(offset);

        val16 &= ~(kPCIPMCSPowerStateMask | kPCIPMCSPMEStatus | kPCIPMCSPMEEnable);
        val16 |= kPCIPMCSPowerStateD0;

        dev->extendedConfigWrite16(offset, val16);
    }
    return kIOReturnSuccess;
}
'''

WAKE_NEW = '''IOReturn RTL8125::setPowerStateWakeAction(OSObject *owner, void *arg1, void *arg2, void *arg3, void *arg4)
{
    RTL8125 *ethCtlr = OSDynamicCast(RTL8125, owner);
    IOPCIDevice *dev;
    UInt16 val16;
    UInt8 offset;

    if (!ethCtlr) return kIOReturnBadArgument;
    if (ethCtlr->r44NormalMapped) {
        ethCtlr->r47PMBlocked = true;
        if (!ethCtlr->pciDevice || !ethCtlr->pciPMCtrlOffset) {
            ethCtlr->r47Power.lastError = kIOReturnNotReady;
            ethCtlr->r47PublishPM("resume-failed");
            return kIOReturnNotReady;
        }
    }
    if (ethCtlr->pciPMCtrlOffset) {
        dev = ethCtlr->pciDevice;
        offset = ethCtlr->pciPMCtrlOffset;
        val16 = dev->extendedConfigRead16(offset);
        val16 &= ~(kPCIPMCSPowerStateMask | kPCIPMCSPMEStatus | kPCIPMCSPMEEnable);
        val16 |= kPCIPMCSPowerStateD0;
        dev->extendedConfigWrite16(offset, val16);

        if (ethCtlr->r44NormalMapped) {
            ethCtlr->r47Power.wakePmcsr = dev->extendedConfigRead16(offset);
            if ((ethCtlr->r47Power.wakePmcsr & kPCIPMCSPowerStateMask) !=
                    kPCIPMCSPowerStateD0) {
                ethCtlr->r47Power.lastError = kIOReturnIOError;
                ethCtlr->r47PublishPM("resume-failed");
                return kIOReturnIOError;
            }
            ethCtlr->r47Power.d0At = mach_absolute_time();
            const IOReturn result = ethCtlr->r47MapperPower(true);
            ethCtlr->r47Power.lastError = result;
            if (result != kIOReturnSuccess) {
                ethCtlr->r47PublishPM("resume-failed");
                return result;
            }
            ethCtlr->r47Power.restoredAt = mach_absolute_time();
            ++ethCtlr->r47Power.wakeCount;
            ethCtlr->r47PMBlocked = false;
            ethCtlr->r47PublishPM("restored");
        }
    }
    /* The family now performs its ordinary enable(), including hardware
     * setup. Do not call enable() here or rebuild its persistent DMA owners. */
    return kIOReturnSuccess;
}
'''

SLEEP_OLD = '''IOReturn RTL8125::setPowerStateSleepAction(OSObject *owner, void *arg1, void *arg2, void *arg3, void *arg4)
{
    RTL8125 *ethCtlr = OSDynamicCast(RTL8125, owner);
    IOPCIDevice *dev;
    UInt16 val16;
    UInt8 offset;

    if (ethCtlr && ethCtlr->pciPMCtrlOffset) {
        dev = ethCtlr->pciDevice;
        offset = ethCtlr->pciPMCtrlOffset;

        val16 = dev->extendedConfigRead16(offset);

        val16 &= ~(kPCIPMCSPowerStateMask | kPCIPMCSPMEStatus | kPCIPMCSPMEEnable);

        if (ethCtlr->linuxData.wol_enabled)
            val16 |= (kPCIPMCSPMEStatus | kPCIPMCSPMEEnable | kPCIPMCSPowerStateD3);
        else
            val16 |= kPCIPMCSPowerStateD3;

        dev->extendedConfigWrite16(offset, val16);
    }
    return kIOReturnSuccess;
}
'''

SLEEP_NEW = '''IOReturn RTL8125::setPowerStateSleepAction(OSObject *owner, void *arg1, void *arg2, void *arg3, void *arg4)
{
    RTL8125 *ethCtlr = OSDynamicCast(RTL8125, owner);
    IOPCIDevice *dev;
    UInt16 val16;
    UInt8 offset;

    if (!ethCtlr) return kIOReturnBadArgument;
    if (ethCtlr->r44NormalMapped) {
        ethCtlr->r47PMBlocked = true;
        ethCtlr->r47Power.quiescedAt = ethCtlr->r47Power.suspendedAt = 0;
        ethCtlr->r47Power.d3At = ethCtlr->r47Power.d0At = 0;
        ethCtlr->r47Power.restoredAt = ethCtlr->r47Power.enableAt = 0;
        ethCtlr->r47Power.linkupAt = 0;
        ethCtlr->r47Power.wakeChipCmd = 0;
        ethCtlr->r47Power.sleepPmcsr = ethCtlr->r47Power.wakePmcsr = 0;
        if (!ethCtlr->pciDevice || !ethCtlr->pciPMCtrlOffset) {
            ethCtlr->r47Power.lastError = kIOReturnNotReady;
            ethCtlr->r47PublishPM("suspend-failed");
            return kIOReturnNotReady;
        }
        /* IOEthernetInterface has already called disable(): hardware reset,
         * TX retirement and BOTH existing clearRxTxRings() calls are finished.
         * In particular RX remapping must precede mapper admission closing. */
        ethCtlr->r47Power.sleepStateFlags = ethCtlr->stateFlags;
        ethCtlr->r47Power.sleepChipCmd = RTL_R8(&ethCtlr->linuxData, ChipCmd);
        if ((ethCtlr->r47Power.sleepStateFlags & __ENABLED_M) ||
            (ethCtlr->r47Power.sleepChipCmd & (CmdTxEnb | CmdRxEnb | CmdReset))) {
            ethCtlr->r47Power.lastError = kIOReturnBusy;
            ethCtlr->r47PublishPM("suspend-failed");
            return kIOReturnBusy;
        }
        ethCtlr->r47Power.quiescedAt = mach_absolute_time();
        const IOReturn result = ethCtlr->r47MapperPower(false);
        ethCtlr->r47Power.lastError = result;
        if (result != kIOReturnSuccess) {
            ethCtlr->r47PublishPM("suspend-failed");
            return result;
        }
        ethCtlr->r47Power.suspendedAt = mach_absolute_time();
        ethCtlr->r47PublishPM("suspended");
    }
    if (ethCtlr->pciPMCtrlOffset) {
        dev = ethCtlr->pciDevice;
        offset = ethCtlr->pciPMCtrlOffset;
        val16 = dev->extendedConfigRead16(offset);
        val16 &= ~(kPCIPMCSPowerStateMask | kPCIPMCSPMEStatus | kPCIPMCSPMEEnable);
        if (ethCtlr->linuxData.wol_enabled)
            val16 |= (kPCIPMCSPMEStatus | kPCIPMCSPMEEnable | kPCIPMCSPowerStateD3);
        else
            val16 |= kPCIPMCSPowerStateD3;
        dev->extendedConfigWrite16(offset, val16);

        if (ethCtlr->r44NormalMapped) {
            ethCtlr->r47Power.sleepPmcsr = dev->extendedConfigRead16(offset);
            if ((ethCtlr->r47Power.sleepPmcsr & kPCIPMCSPowerStateMask) !=
                    kPCIPMCSPowerStateD3) {
                ethCtlr->r47Power.lastError = kIOReturnIOError;
                ethCtlr->r47PublishPM("suspend-failed");
                return kIOReturnIOError;
            }
            ethCtlr->r47Power.d3At = mach_absolute_time();
            ++ethCtlr->r47Power.sleepCount;
            ethCtlr->r47PublishPM("sleeping");
        }
    }
    return kIOReturnSuccess;
}
'''

PM_ACK_OLD = '    powerState = powerStateOrdinal;\n'
PM_ACK_NEW = '''    /* IOPMAckImplied reports synchronous callback completion, not an
     * IOReturn device error. R47 records failures and keeps enable/link-up
     * blocked until its synchronous mapper wake succeeds. */
''' + PM_ACK_OLD


def rewrite(text):
    """Final R45/R46 blocks after this layer, for inherited freshness checks."""
    for old, new in ((INIT_OLD, INIT_NEW), (READY_OLD, READY_NEW),
                     (RPC_OLD, RPC_NEW), (ACTION_OLD, ACTION_NEW),
                     (ENABLE_OLD, ENABLE_NEW),
                     (ENABLE_TIME_OLD, ENABLE_TIME_NEW),
                     (LINKUP_OLD, LINKUP_NEW), (PM_ACK_OLD, PM_ACK_NEW)):
        text = text.replace(old, new)
    return text


def patch(hpp, cpp, hardware):
    def once(text, old, new, name):
        if text.count(old) != 1:
            raise SystemExit('refused: round47 %s anchor count %d' %
                             (name, text.count(old)))
        return text.replace(old, new, 1)

    def method(text, old, new, name):
        import re
        signature = old.splitlines()[0]
        if text.count(signature) != 1:
            raise SystemExit('refused: round47 %s signature' % name)
        start = text.index(signature)
        end = text.index('\n}', start) + 2
        norm = lambda value: re.sub(r'\s+', ' ', value).strip()
        if norm(text[start:end]) != norm(old):
            raise SystemExit('refused: round47 %s pinned body' % name)
        return text[:start] + new.rstrip('\n') + text[end:]

    hpp = once(hpp, '    bool hasSensor;\n', '    bool hasSensor;\n' + MEMBERS,
               'power state members')
    for old, new, name in (
        (INIT_OLD, INIT_NEW, 'power state initialization'),
        (READY_OLD, READY_NEW, 'initial power publication'),
        (RPC_OLD, RPC_NEW, 'power snapshot request'),
        (ACTION_OLD, ACTION_NEW, 'power snapshot dispatch'),
        (ENABLE_OLD, ENABLE_NEW, 'ordinary enable guard'),
        (ENABLE_TIME_OLD, ENABLE_TIME_NEW, 'ordinary wake enable time'),
        (LINKUP_OLD, LINKUP_NEW, 'actual DMA enable guard'),
        (PM_ACK_OLD, PM_ACK_NEW, 'power acknowledgement contract'),
    ):
        cpp = once(cpp, old, new, name)
    anchor = '\n#pragma mark --- statistics update methods ---\n'
    cpp = once(cpp, anchor, '\n' + METHODS + anchor, 'power methods')
    hardware = method(hardware, SLEEP_OLD, SLEEP_NEW, 'ordinary sleep callback')
    hardware = method(hardware, WAKE_OLD, WAKE_NEW, 'ordinary wake callback')
    return hpp, cpp, hardware


def is_current(hpp, cpp, hardware):
    import re
    norm = lambda text: re.sub(r'\s+', ' ', text).strip()
    for text, blocks in (
        (hpp, (MEMBERS,)),
        (cpp, (METHODS, INIT_NEW, READY_NEW, RPC_NEW, ACTION_NEW, ENABLE_NEW,
               ENABLE_TIME_NEW, LINKUP_NEW, PM_ACK_NEW)),
        (hardware, (SLEEP_NEW, WAKE_NEW)),
    ):
        if any(norm(block) not in norm(text) for block in blocks):
            return False
    return True
