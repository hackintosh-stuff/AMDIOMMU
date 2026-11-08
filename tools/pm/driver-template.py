"""R66-2: join RTL8111's real power callbacks to its existing device mapper.

Input is the fixed R63 generated driver. No extra checkout is created.
The OS network family, not these callbacks, calls disable()/enable().
"""
MEMBERS = r'''
    // PM actions, timer actions and recovery run under the existing workloop gate.
    struct R66_2PowerStats {
        UInt64 sleeps, wakes, quiescedAt, suspendedAt, d3At, d0At;
        UInt64 restoredAt, enableAt, linkupAt, restarts;
        UInt32 sleepChip, sleepPmcsr, wakePmcsr;
        IOReturn error, restartError;
    } r66_2Power;
    bool r66_2PMBlocked, r66_2PMSuspended, r66_2Resetting;
    IOReturn r66_2MapperPower(UInt32 operation);
    void r66_2PublishPM(const char *phase);
'''
METHODS = r'''
IOReturn RTL8111::r66_2MapperPower(UInt32 operation)
{
    if (!r53NormalMapped || !mapper || !pciDevice) return kIOReturnNotReady;
    const OSSymbol *key = OSSymbol::withCString("RequestPowerTransition");
    if (!key) return kIOReturnNoMemory;
    const IOReturn result = mapper->callPlatformFunction(key, false, pciDevice,
        (void *)(uintptr_t)operation, NULL, NULL);
    key->release();
    return result;
}

void RTL8111::r66_2PublishPM(const char *phase)
{
    if (!r53NormalMapped) return;
    setProperty("rtl8111-r66_2-pm-hooks", UInt64(1), 64);
    if (phase) setProperty("rtl8111-r66_2-pm-state", phase);
    setProperty("rtl8111-r66_2-pm-blocked", UInt64(r66_2PMBlocked), 64);
#define R66_2_PROP(key, member) setProperty("rtl8111-r66_2-" key, UInt64(r66_2Power.member), 64)
    R66_2_PROP("sleep-count", sleeps);
    R66_2_PROP("wake-count", wakes);
    R66_2_PROP("sleep-quiesced-at", quiescedAt);
    R66_2_PROP("sleep-suspended-at", suspendedAt);
    R66_2_PROP("sleep-d3-at", d3At);
    R66_2_PROP("wake-d0-at", d0At);
    R66_2_PROP("wake-restored-at", restoredAt);
    R66_2_PROP("wake-enable-at", enableAt);
    R66_2_PROP("wake-linkup-at", linkupAt);
    R66_2_PROP("sleep-chipcmd", sleepChip);
    R66_2_PROP("sleep-pmcsr", sleepPmcsr);
    R66_2_PROP("wake-pmcsr", wakePmcsr);
    R66_2_PROP("restart-count", restarts);
#undef R66_2_PROP
    setProperty("rtl8111-r66_2-last-error", UInt64(UInt32(r66_2Power.error)), 64);
    setProperty("rtl8111-r66_2-restart-error", UInt64(UInt32(r66_2Power.restartError)), 64);
}
'''
SLEEP_PREFIX = r'''
    if (!ethCtlr) return kIOReturnBadArgument;
    if (ethCtlr->r53NormalMapped) {
        ethCtlr->r66_2PMBlocked = true;
        ethCtlr->r66_2Power.quiescedAt = ethCtlr->r66_2Power.suspendedAt = 0;
        ethCtlr->r66_2Power.d3At = ethCtlr->r66_2Power.d0At = 0;
        ethCtlr->r66_2Power.restoredAt = ethCtlr->r66_2Power.enableAt = 0;
        ethCtlr->r66_2Power.linkupAt = 0;
        if (!ethCtlr->pciDevice || !ethCtlr->pciPMCtrlOffset) {
            ethCtlr->r66_2Power.error = kIOReturnNotReady;
            ethCtlr->r66_2PublishPM("suspend-failed");
            return kIOReturnNotReady;
        }
        // IONetworkingFamily has completed disable(), TX retirement and RX rebuild.
        ethCtlr->r66_2Power.sleepChip = _OSReadInt8(ethCtlr->baseAddr, ChipCmd);
        if (ethCtlr->isEnabled ||
            (ethCtlr->r66_2Power.sleepChip & (CmdTxEnb | CmdRxEnb | CmdReset))) {
            ethCtlr->r66_2Power.error = kIOReturnBusy;
            ethCtlr->r66_2PublishPM("suspend-failed");
            return kIOReturnBusy;
        }
        ethCtlr->r66_2Power.quiescedAt = mach_absolute_time();
        const IOReturn result = ethCtlr->r66_2MapperPower(1);
        ethCtlr->r66_2Power.error = result;
        if (result != kIOReturnSuccess) {
            ethCtlr->r66_2PublishPM("suspend-failed");
            return result;
        }
        ethCtlr->r66_2PMSuspended = true;
        ethCtlr->r66_2Power.suspendedAt = mach_absolute_time();
    }
'''
SLEEP_AFTER_D3 = r'''
        if (ethCtlr->r53NormalMapped) {
            ethCtlr->r66_2Power.sleepPmcsr = dev->extendedConfigRead16(offset);
            if ((ethCtlr->r66_2Power.sleepPmcsr & kPCIPMCSPowerStateMask) != kPCIPMCSPowerStateD3) {
                ethCtlr->r66_2Power.error = kIOReturnIOError;
                ethCtlr->r66_2PublishPM("suspend-failed");
                return kIOReturnIOError;
            }
            ethCtlr->r66_2Power.d3At = mach_absolute_time();
            ++ethCtlr->r66_2Power.sleeps;
            ethCtlr->r66_2PublishPM("sleeping");
        }
'''
WAKE_PREFIX = r'''
    if (!ethCtlr) return kIOReturnBadArgument;
    if (ethCtlr->r53NormalMapped && ethCtlr->r66_2PMSuspended &&
        (!ethCtlr->pciDevice || !ethCtlr->pciPMCtrlOffset)) {
        ethCtlr->r66_2Power.error = kIOReturnNotReady;
        ethCtlr->r66_2PublishPM("resume-failed");
        return kIOReturnNotReady;
    }
'''
WAKE_AFTER_D0 = r'''
        // An initial D0 callback is not a completed system sleep. Do not call
        // the mapper or enable() on boot; only pair a real successful suspend.
        if (ethCtlr->r53NormalMapped && ethCtlr->r66_2PMSuspended) {
            ethCtlr->r66_2Power.wakePmcsr = dev->extendedConfigRead16(offset);
            if ((ethCtlr->r66_2Power.wakePmcsr & kPCIPMCSPowerStateMask) != kPCIPMCSPowerStateD0) {
                ethCtlr->r66_2Power.error = kIOReturnIOError;
                ethCtlr->r66_2PublishPM("resume-failed");
                return kIOReturnIOError;
            }
            ethCtlr->r66_2Power.d0At = mach_absolute_time();
            const IOReturn result = ethCtlr->r66_2MapperPower(2);
            ethCtlr->r66_2Power.error = result;
            if (result != kIOReturnSuccess) {
                ethCtlr->r66_2PublishPM("resume-failed");
                return result;
            }
            ethCtlr->r66_2Power.restoredAt = mach_absolute_time();
            ++ethCtlr->r66_2Power.wakes;
            ethCtlr->r66_2PMSuspended = false;
            ethCtlr->r66_2PMBlocked = false;
            ethCtlr->r66_2PublishPM("restored");
        }
'''
RESTART_PREFIX = r'''
    if (r53NormalMapped) {
        if (!isEnabled || r66_2PMBlocked || r66_2Resetting) return;
        r66_2Resetting = true;
        ++r66_2Power.restarts;
        // Reuse the accepted DMA stop/drain/rebuild/park path. The legacy
        // shortcut below leaves the MSI event source live while remapping RX.
        linkUp = false;
        setLinkStatus(kIONetworkLinkValid);
        IOReturn result = disable(netif);
        if (result == kIOReturnSuccess && !r66_2PMBlocked)
            result = enable(netif);
        if (result != kIOReturnSuccess) r66_2PMBlocked = true;
        r66_2Power.restartError = result;
        r66_2Resetting = false;
        r66_2PublishPM(result == kIOReturnSuccess ? "restart-complete" : "restart-failed");
        return;
    }
'''


def once(text, old, new, label):
    if text.count(old) != 1:
        raise ValueError('R66-2 %s: expected one source anchor, found %d' % (label, text.count(old)))
    return text.replace(old, new, 1)


def method(text, signature):
    start = text.index(signature)
    end = text.index('\n}', start) + 2
    return text[start:end]


def patch(hpp, cpp, hardware):
    """Return transformed source strings; this function does not write files."""
    if 'r66_2MapperPower' in cpp:
        raise ValueError('R66-2 input already transformed; verify the generated-file stamp instead')
    if 'r63RequesterDMA' not in cpp:
        raise ValueError('R66-2 requires the R63 mapped RTL8111 lifecycle')
    hpp = once(hpp, '    bool useAppleVTD;\n', '    bool useAppleVTD;\n' + MEMBERS, 'members')
    init = '        r53NormalMapped = r53ResourcesReady = false;\n'
    cpp = once(cpp, init, init + '''        bzero(&r66_2Power, sizeof(r66_2Power));
        r66_2PMBlocked = r66_2PMSuspended = r66_2Resetting = false;
''', 'init')
    cpp = once(cpp, '    r53ResourcesReady = true;\n',
               '    r53ResourcesReady = true;\n    r66_2PublishPM("ready");\n', 'capability')
    cpp = once(cpp, '    DebugLog("enable() ===>\\n");\n',
               '    DebugLog("enable() ===>\\n");\n    if (r53NormalMapped && r66_2PMBlocked) return kIOReturnNotReady;\n', 'enable gate')
    cpp = once(cpp, '    selectMedium(selectedMedium);\n    enableRTL8111();\n', '''    if (r53NormalMapped && r66_2Power.restoredAt && !r66_2Power.enableAt) {
        r66_2Power.enableAt = mach_absolute_time();
        r66_2PublishPM("enabled");
    }
    selectMedium(selectedMedium);
    enableRTL8111();
''', 'enable ordering')
    cpp = once(cpp, '    /* Enable receiver and transmitter. */\n', '''    if (r53NormalMapped && (!isEnabled || r66_2PMBlocked)) return;
    /* Enable receiver and transmitter. */
''', 'link admission')
    cpp = once(cpp, '    WriteReg8(ChipCmd, CmdTxEnb | CmdRxEnb);\n', '''    WriteReg8(ChipCmd, CmdTxEnb | CmdRxEnb);
    if (r53NormalMapped && r66_2Power.restoredAt && !r66_2Power.linkupAt) {
        r66_2Power.linkupAt = mach_absolute_time();
        r66_2PublishPM("link-up");
    }
''', 'link proof')
    cpp = once(cpp, 'void RTL8111::r53Snapshot()\n{\n',
               'void RTL8111::r53Snapshot()\n{\n    r66_2PublishPM(NULL);\n', 'snapshot PM fields')
    for signature in ('bool RTL8111::checkForDeadlock()',
                      'void RTL8111::timerActionRTL8111C(IOTimerEventSource *timer)',
                      'void RTL8111::timerActionRTL8111B(IOTimerEventSource *timer)'):
        result = 'false' if signature.startswith('bool') else ''
        guard = '    if (r53NormalMapped && (!isEnabled || r66_2PMBlocked)) return%s;\n' % (' ' + result if result else '')
        cpp = once(cpp, signature + '\n{\n', signature + '\n{\n' + guard, 'timer/reset admission')
    cpp += '\n' + METHODS
    hardware = once(hardware, 'void RTL8111::enableRTL8111()\n{\n',
                    'void RTL8111::enableRTL8111()\n{\n    if (r53NormalMapped && r66_2PMBlocked) return;\n', 'hardware admission')
    hardware = once(hardware, 'void RTL8111::restartRTL8111()\n{\n',
                    'void RTL8111::restartRTL8111()\n{\n' + RESTART_PREFIX, 'mapped restart')
    for name, prefix, suffix in (('Sleep', SLEEP_PREFIX, SLEEP_AFTER_D3), ('Wake', WAKE_PREFIX, WAKE_AFTER_D0)):
        sig = 'IOReturn RTL8111::setPowerState%sAction(' % name
        body = method(hardware, sig)
        new = once(body, '    if (ethCtlr && ethCtlr->pciPMCtrlOffset) {',
                   prefix + '\n    if (ethCtlr && ethCtlr->pciPMCtrlOffset) {', name + ' PM callback')
        new = once(new, '        dev->extendedConfigWrite16(offset, val16);',
                   '        dev->extendedConfigWrite16(offset, val16);\n' + suffix, name + ' PMCSR order')
        hardware = once(hardware, body, new, name + ' replacement')
    return hpp, cpp, hardware
