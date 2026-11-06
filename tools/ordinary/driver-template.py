"""Select Lucy's existing mapped DMA path for the device's actual IOMapper.

R44 uses the ordinary fixed resources, 64 RX groups and packet TX commands.
The legacy R17/R34 modules remain available, but are not installed in auto mode.
Diagnostics are published at startup and real enable/disable events only.
"""

MEMBERS = '''
    /* Round44: ordinary per-device IOMapper path; no experimental binding. */
    bool r44NormalMapped;
    UInt32 r44EnableCount;
    UInt32 r44DisableCount;
    void r44SelectNormalDMA();
    void r44PublishNormalDMA(bool enabled);
'''

METHODS = r'''
/* Round44: IOMapper::copyMapperForDevice supplied the mapper used by the
 * driver's existing MD/IODMACommand constructors. This selection also applies
 * on x86; the historical variable name does not imply an AppleVTD service. */
void RTL8125::r44SelectNormalDMA()
{
    if (mapper && !useAppleVTD) {
        IOLog("Device mapper present, using mapped DMA path.\n");
        useAppleVTD = true;
    }
    OSString *mode = mapper ? OSDynamicCast(OSString, mapper->getProperty("r44-mode")) : NULL;
    r44NormalMapped = mode && mode->isEqualTo("auto");
    setProperty("rtl812x-r44-mapper-found", (UInt64)(mapper != NULL), 64);
    setProperty("rtl812x-r44-mapped-dma", (UInt64)(mapper && useAppleVTD), 64);
    if (!r44NormalMapped) return;
    setProperty("rtl812x-r44-mode", "auto");
    setProperty("rtl812x-r44-enable-count", (UInt64)r44EnableCount, 64);
    setProperty("rtl812x-r44-disable-count", (UInt64)r44DisableCount, 64);
    setProperty("rtl812x-r44-rx-groups", (UInt64)kNumRxMemDesc, 64);
    setProperty("rtl812x-r44-rx-slots", (UInt64)kNumRxDesc, 64);
    setProperty("rtl812x-r44-fixed-mappings", (UInt64)3, 64);
}

void RTL8125::r44PublishNormalDMA(bool enabled)
{
    if (!r44NormalMapped) return;
    struct rtl8125_private *tp = &linuxData;
    const UInt32 command = RTL_R8(tp, ChipCmd);
    const UInt64 now = mach_absolute_time();
    if (enabled) {
        ++r44EnableCount;
        setProperty("rtl812x-r44-enable-time", now, 64);
        setProperty("rtl812x-r44-enable-command", (UInt64)command, 64);
    } else {
        ++r44DisableCount;
        setProperty("rtl812x-r44-disable-time", now, 64);
        setProperty("rtl812x-r44-disable-command", (UInt64)command, 64);
    }
    setProperty("rtl812x-r44-state", enabled ? "enabled" : "disabled");
    setProperty("rtl812x-r44-enable-count", (UInt64)r44EnableCount, 64);
    setProperty("rtl812x-r44-disable-count", (UInt64)r44DisableCount, 64);
    setProperty("rtl812x-r44-tx-iova", (UInt64)txPhyAddr, 64);
    setProperty("rtl812x-r44-rx-iova", (UInt64)rxPhyAddr, 64);
    setProperty("rtl812x-r44-tally-iova", (UInt64)statPhyAddr, 64);
    /* r40FixedRegister only reads the three MMIO base registers. Tally's
     * command bits are removed, leaving its actual device-visible address. */
    setProperty("rtl812x-r44-tx-register", r40FixedRegister(r40fixed::kTxRing), 64);
    setProperty("rtl812x-r44-rx-register", r40FixedRegister(r40fixed::kRxRing), 64);
    setProperty("rtl812x-r44-tally-register", r40FixedRegister(r40fixed::kTally), 64);
}
'''

SELECT_OLD = '''#if defined(__arm64__)
    /*
     * On Apple Silicon all PCIe/Thunderbolt DMA is translated by DART.
     * Raw physical addresses would fault, so the mapper-aware code path
     * (historically the AppleVTD path) is mandatory whenever the device
     * has a system mapper.
     */
    if (mapper && !useAppleVTD) {
        IOLog("DART mapper present, using mapped DMA path.\\n");
        useAppleVTD = true;
    }
#endif'''
SELECT_NEW = '''    /* Round44: use the actual device mapper on x86 as well as arm64. */
    r44SelectNormalDMA();'''

INIT_OLD = '        useAppleVTD = false;\n'
INIT_NEW = '''        useAppleVTD = false;
        r44NormalMapped = false;
        r44EnableCount = r44DisableCount = 0;
'''

RESET_OLD = '''    if (!rtl812xInit()) {
        IOLog("Failed to initialize chip.\\n");
        goto error_cfg;
    }
'''
RESET_NEW = RESET_OLD + '''    if (r44NormalMapped) {
        setProperty("rtl812x-r44-reset-done-time", mach_absolute_time(), 64);
        setProperty("rtl812x-r44-reset-command", (UInt64)RTL_R8(&linuxData, ChipCmd), 64);
    }
'''

READY_OLD = '''    if (!setupStatResources()) {
        IOLog("Error allocating Stat resources.\\n");
        goto error_dma3;
    }
'''
READY_NEW = READY_OLD + '''    if (r44NormalMapped)
        setProperty("rtl812x-r44-resources-ready-time", mach_absolute_time(), 64);
'''

ENABLE_OLD = '''    /* Start hardware. */
    RTL_W8(tp, ChipCmd, CmdTxEnb | CmdRxEnb);
'''
ENABLE_NEW = ENABLE_OLD + '''    /* enable() configures the chip; setLinkUp() actually starts DMA. */
    r44PublishNormalDMA(true);
'''

DISABLE_OLD = ('    rtl812xDisable();\n'
               '    \n'
               '    clearRxTxRings();\n')
DISABLE_NEW = DISABLE_OLD + '''    r44PublishNormalDMA(false);
'''

PREPARE_OLD = '''    if (txBufDesc->prepare() != kIOReturnSuccess) {'''
PREPARE_NEW = '''    if (r44NormalMapped)
        setProperty("rtl812x-r44-first-dma-prepare-time", mach_absolute_time(), 64);
''' + PREPARE_OLD

CLEAR_OLD = '''            if (md && (md->getTag() == kIOMemoryActive)) {
                md->complete();'''
CLEAR_NEW = '''            if (md && (md->getTag() == kIOMemoryActive)) {
                /* Match txUnmapPacket(): retire the DMA command before
                 * completing and reusing its descriptor on normal down/up. */
                txMapInfo->txDmaCmd[i]->clearMemoryDescriptor();
                md->complete();'''


def patch(hpp, cpp, setup):
    def once(text, old, new, label):
        if text.count(old) != 1:
            raise SystemExit('refused: round44 %s anchor count %d' %
                             (label, text.count(old)))
        return text.replace(old, new, 1)

    hpp = once(hpp, '    bool hasSensor;\n', '    bool hasSensor;\n' + MEMBERS,
               'normal mapped members')
    for old, new, label in (
        (INIT_OLD, INIT_NEW, 'initialization'),
        (SELECT_OLD, SELECT_NEW, 'mapper selection'),
        (RESET_OLD, RESET_NEW, 'initial reset'),
        (READY_OLD, READY_NEW, 'resources ready'),
        (ENABLE_OLD, ENABLE_NEW, 'hardware enable'),
        (DISABLE_OLD, DISABLE_NEW, 'interface disable'),
    ):
        cpp = once(cpp, old, new, label)
    anchor = '\n#pragma mark --- statistics update methods ---\n'
    cpp = once(cpp, anchor, '\n' + METHODS + anchor, 'normal DMA methods')
    setup = once(setup, PREPARE_OLD, PREPARE_NEW, 'first DMA prepare')
    setup = once(setup, CLEAR_OLD, CLEAR_NEW, 'normal TX ring clear')
    return hpp, cpp, setup


def is_current(hpp, cpp, setup):
    """Do not accept an earlier generated tree as the current normal path."""
    import re
    norm = lambda s: re.sub(r'\s+', ' ', s).strip()
    for text, blocks in ((hpp, (MEMBERS,)),
                         (cpp, (METHODS, INIT_NEW, SELECT_NEW, RESET_NEW,
                                READY_NEW, ENABLE_NEW, DISABLE_NEW)),
                         (setup, (PREPARE_NEW, CLEAR_NEW))):
        if any(norm(block) not in norm(text) for block in blocks):
            return False
    return True
