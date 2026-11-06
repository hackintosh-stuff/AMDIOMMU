#!/usr/bin/env python3
"""Adapt one pinned RTL8111 dependency input in place for the ordinary per-device mapper."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent

MEMBERS = r'''
    /* R53: observations of the normal driver path, without test DMA. */
    bool r53NormalMapped;
    bool r53ResourcesReady;
    UInt64 r53EnableCount, r53DisableCount, r53Tso6Count, r53SnapshotSerial;
    UInt64 r53RingDrainCount;
    const char *r53State;
    void r53SelectMapper();
    void r53Snapshot();
    static IOReturn r53SnapshotAction(OSObject *, void *, void *, void *, void *);
'''

METHODS = r'''
/* The upstream member name useAppleVTD denotes its mapped packet path.
 * Select it from the actual per-device mapper on x86, without service-name tests. */
void RTL8111::r53SelectMapper()
{
    useAppleVTD = mapper != NULL;
    OSString *mode = mapper ? OSDynamicCast(OSString, mapper->getProperty("r44-mode")) : NULL;
    r53NormalMapped = mode && mode->isEqualTo("auto");
    const UInt64 requester = (UInt64(pciDevice->getBusNumber()) << 8) |
        (UInt64(pciDevice->getDeviceNumber()) << 3) | pciDevice->getFunctionNumber();
    OSNumber *domain = mapper ? OSDynamicCast(OSNumber, mapper->getProperty("r44-domain-id")) : NULL;
    setProperty("rtl8111-r53-requester", requester, 64);
    setProperty("rtl8111-r53-mapper-id", mapper ? mapper->getRegistryEntryID() : 0, 64);
    setProperty("rtl8111-r53-domain-id", domain ? domain->unsigned64BitValue() : 0, 64);
    setProperty("rtl8111-r53-mapper-found", UInt64(mapper != NULL), 64);
    setProperty("rtl8111-r53-mapped-dma", UInt64(useAppleVTD), 64);
    setProperty("rtl8111-r53-mode", r53NormalMapped ? "auto" : (mapper ? "mapped" : "physical"));
    setProperty("rtl8111-r53-rx-groups", UInt64(kNumRxMemDesc), 64);
    setProperty("rtl8111-r53-rx-slots", UInt64(kNumRxDesc), 64);
    setProperty("rtl8111-r53-rx-pages-per-group", UInt64(kRxMemBatchSize), 64);
    setProperty("rtl8111-r53-fixed-mappings", UInt64(3), 64);
}

IOReturn RTL8111::setProperties(OSObject *properties)
{
    OSDictionary *dict = OSDynamicCast(OSDictionary, properties);
    if (dict && dict->getObject("R53Snapshot") == kOSBooleanTrue) {
        if (!commandGate || !r53ResourcesReady)
            return kIOReturnNotReady;
        return commandGate->runAction(r53SnapshotAction);
    }
    return super::setProperties(properties);
}

IOReturn RTL8111::r53SnapshotAction(OSObject *owner, void *, void *, void *, void *)
{
    RTL8111 *self = OSDynamicCast(RTL8111, owner);
    if (!self || !self->r53ResourcesReady)
        return kIOReturnNotReady;
    self->r53Snapshot();
    return kIOReturnSuccess;
}

void RTL8111::r53Snapshot()
{
    if (!r53ResourcesReady || !baseAddr)
        return;
    struct Live {
        UInt32 kind, index;
        UInt64 iova, length;
    };
    static_assert(sizeof(Live) == 24, "R53 live resource ABI");
    OSData *live = OSData::withCapacity((3 + kNumRxMemDesc) * sizeof(Live));
    OSData *rx = OSData::withCapacity(kNumRxDesc * sizeof(UInt64));
    if (!live || !rx) {
        if (live) live->release();
        if (rx) rx->release();
        return;
    }
    Live row = {1, 0, txPhyAddr, kTxDescSize};
    live->appendBytes(&row, sizeof(row));
    row = {2, 0, rxPhyAddr, kRxDescSize};
    live->appendBytes(&row, sizeof(row));
    row = {3, 0, statPhyAddr, sizeof(RtlStatData)};
    live->appendBytes(&row, sizeof(row));
    for (UInt32 i = 0; i < kNumRxDesc; ++i) {
        const UInt64 addr = OSSwapLittleToHostInt64(rxDescArray[i].buf.addr);
        rx->appendBytes(&addr, sizeof(addr));
        if ((i & kRxMemDescMask) == 0) {
            row = {4, i >> kRxMemBaseShift, addr, UInt64(kRxMemBatchSize) * PAGE_SIZE};
            live->appendBytes(&row, sizeof(row));
        }
    }
    setProperty("rtl8111-r53-live", live);
    setProperty("rtl8111-r53-rx-addresses", rx);
    live->release();
    rx->release();
    setProperty("rtl8111-r53-state", r53State);
    setProperty("rtl8111-r53-enable-count", r53EnableCount, 64);
    setProperty("rtl8111-r53-disable-count", r53DisableCount, 64);
    setProperty("rtl8111-r53-tso6-count", r53Tso6Count, 64);
    setProperty("rtl8111-r53-ring-drain-count", r53RingDrainCount, 64);
    setProperty("rtl8111-r53-tx-mapped-active",
        UInt64(useAppleVTD && txMapInfo ? kNumTxMemDesc - txMapInfo->txNumFreeMem : 0), 64);
    setProperty("rtl8111-r53-chip-command", UInt64(ReadReg8(ChipCmd)), 64);
    setProperty("rtl8111-r53-tx-iova", UInt64(txPhyAddr), 64);
    setProperty("rtl8111-r53-rx-iova", UInt64(rxPhyAddr), 64);
    setProperty("rtl8111-r53-tally-iova", UInt64(statPhyAddr), 64);
    setProperty("rtl8111-r53-tx-register",
        (UInt64(ReadReg32(TxDescStartAddrHigh)) << 32) | ReadReg32(TxDescStartAddrLow), 64);
    setProperty("rtl8111-r53-rx-register",
        (UInt64(ReadReg32(RxDescAddrHigh)) << 32) | ReadReg32(RxDescAddrLow), 64);
    /* CounterDump is a command bit, not part of the DMA address. */
    setProperty("rtl8111-r53-tally-register",
        (UInt64(ReadReg32(CounterAddrHigh)) << 32) |
        (ReadReg32(CounterAddrLow) & ~UInt32(0x3f)), 64);
    setProperty("rtl8111-r53-snapshot-serial", ++r53SnapshotSerial, 64);
}
'''


def once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit("RTL8111 pinned anchor %s: expected 1, got %d" % (label, count))
    return text.replace(old, new, 1)



def payload_commands(hpp, cpp, setup, vtd):
    """Use standard explicit DMA commands: MD legacy mapping requires gSystem."""
    hpp = once(hpp, "    IOMemoryDescriptor *txMemIO[kNumTxMemDesc];\n",
               "    IOMemoryDescriptor *txMemIO[kNumTxMemDesc];\n    IODMACommand *txDmaCmd[kNumTxMemDesc];\n",
               "TX command ownership")
    hpp = once(hpp, "    IOMemoryDescriptor *rxMemIO[kNumRxMemDesc];\n",
               "    IOMemoryDescriptor *rxMemIO[kNumRxMemDesc];\n    IODMACommand *rxDmaCmd[kNumRxMemDesc];\n",
               "RX command ownership")
    vtd = once(vtd, "    IOByteCount offset;\n    UInt64 word1;\n",
               """    IOByteCount offset;
    IODMACommand *dmaCmd = NULL;
    IODMACommand::Segment64 dmaSeg;
    UInt64 dmaOffset;
    UInt32 dmaCount;
    UInt64 word1;
""", "initial RX command locals")
    vtd = once(vtd, "        rxMapInfo->rxMemIO[i] = md;\n",
               """        rxMapInfo->rxMemIO[i] = md;
        dmaCmd = IODMACommand::withSpecification(kIODMACommandOutputHost64, 64,
            PAGE_SIZE, IODMACommand::kMapped, 0, 1, mapper, NULL);
        if (!dmaCmd)
            goto error_rx_desc;
        rxMapInfo->rxDmaCmd[i] = dmaCmd;
        if (dmaCmd->setMemoryDescriptor(md) != kIOReturnSuccess)
            goto error_rx_desc;
""", "initial RX explicit mapping")
    # Both initial setup and runtime refill previously called legacy MD
    # getPhysicalSegment(); on this XNU that path only maps with gSystem.
    physical = "            pa = md->getPhysicalSegment(offset, NULL);\n"
    if vtd.count(physical) != 2:
        raise SystemExit("unexpected native RX physical-address sites")
    initial = """            dmaOffset = offset;
            dmaCount = 1;
            if (dmaCmd->gen64IOVMSegments(&dmaOffset, &dmaSeg, &dmaCount) != kIOReturnSuccess ||
                dmaCount != 1 || dmaSeg.fLength != PAGE_SIZE || !dmaSeg.fIOVMAddr)
                goto error_rx_desc;
            pa = dmaSeg.fIOVMAddr;
"""
    vtd = vtd.replace(physical, initial, 1)
    cleanup = "            md = rxMapInfo->rxMemIO[i];\n"
    if vtd.count(cleanup) != 2:
        raise SystemExit("unexpected RX cleanup sites")
    vtd = vtd.replace(cleanup, """            if (rxMapInfo->rxDmaCmd[i]) {
                rxMapInfo->rxDmaCmd[i]->clearMemoryDescriptor();
                rxMapInfo->rxDmaCmd[i]->release();
                rxMapInfo->rxDmaCmd[i] = NULL;
            }
""" + cleanup)
    # setupRxMap cleans its own MD/command pairs. The caller must then unwind
    # its ring, pool and packet allocations on initial mapping failure.
    setup = once(setup, """    if (useAppleVTD)
        result = setupRxMap();
    else
        result = true;
""", """    if (useAppleVTD) {
        result = setupRxMap();
        if (!result)
            goto error_buf;
    } else {
        result = true;
    }
""", "initial RX mapping unwind")
    vtd = once(vtd, "        for (i = 0; i < kNumTxMemDesc; i++) {\n",
               """        for (i = 0; i < kNumTxMemDesc; i++) {
            if (txMapInfo->txDmaCmd[i]) {
                txMapInfo->txDmaCmd[i]->clearMemoryDescriptor();
                txMapInfo->txDmaCmd[i]->release();
                txMapInfo->txDmaCmd[i] = NULL;
            }
""", "TX free command before descriptor")
    vtd = once(vtd, "    IOMemoryDescriptor *md = NULL;\n",
               """    IOMemoryDescriptor *md = NULL;
    IODMACommand *dmaCmd = NULL;
    IODMACommand::Segment64 dmaSeg;
    UInt64 dmaOffset;
    UInt32 dmaCount;
""", "TX command locals")
    vtd = once(vtd, "            md->setTag(kIOMemoryActive);\n",
               """            md->setTag(kIOMemoryActive);
            dmaCmd = txMapInfo->txDmaCmd[saveMem];
            if (!dmaCmd) {
                dmaCmd = IODMACommand::withSpecification(kIODMACommandOutputHost64, 64,
                    PAGE_SIZE, IODMACommand::kMapped, 0, 1, mapper, NULL);
                if (!dmaCmd)
                    goto error_map;
                txMapInfo->txDmaCmd[saveMem] = dmaCmd;
            }
            if (dmaCmd->setMemoryDescriptor(md) != kIOReturnSuccess)
                goto error_map;
""", "TX explicit mapping")
    vtd = once(vtd, "                vector[i].location = md->getPhysicalSegment(offset, NULL) + srcRange[i].address;\n",
               """                dmaOffset = offset;
                dmaCount = 1;
                if (dmaCmd->gen64IOVMSegments(&dmaOffset, &dmaSeg, &dmaCount) != kIOReturnSuccess ||
                    dmaCount != 1 || dmaSeg.fLength != PAGE_SIZE || !dmaSeg.fIOVMAddr)
                    goto error_map;
                vector[i].location = dmaSeg.fIOVMAddr + srcRange[i].address;
""", "TX IOVA output")
    vtd = once(vtd, "error_map:\n    txMapInfo->txNextMem2Use = saveMem;\n",
               """error_map:
    if (dmaCmd)
        dmaCmd->clearMemoryDescriptor();
    if (md && md->getTag() == kIOMemoryActive) {
        md->complete();
        md->setTag(kIOMemoryInactive);
    }
    txMapInfo->txNextMem2Use = saveMem;
""", "TX error command before descriptor")
    vtd = once(vtd, """    IOMemoryDescriptor *md = txMapInfo->txMemIO[txMapInfo->txNextMem2Free];
\x20\x20\x20\x20
    md->complete();
""", """    IOMemoryDescriptor *md = txMapInfo->txMemIO[txMapInfo->txNextMem2Free];
    IODMACommand *dmaCmd = txMapInfo->txDmaCmd[txMapInfo->txNextMem2Free];
    dmaCmd->clearMemoryDescriptor();
    md->complete();
""", "TX completion command before descriptor")
    setup = once(setup, """            if (md && (md->getTag() == kIOMemoryActive)) {
                md->complete();
""", """            if (md && (md->getTag() == kIOMemoryActive)) {
                txMapInfo->txDmaCmd[i]->clearMemoryDescriptor();
                md->complete();
""", "TX down-up command before descriptor")
    vtd = once(vtd, """    IOPhysicalAddress pa;
    IOMemoryDescriptor *md;
    UInt64 length;
""", """    IOPhysicalAddress pa;
    IOMemoryDescriptor *md;
    IODMACommand *dmaCmd;
    IODMACommand::Segment64 dmaSeg;
    UInt64 dmaOffset;
    UInt32 dmaCount;
    UInt64 length;
""", "runtime RX command locals")
    vtd = once(vtd, """        md = rxMapInfo->rxMemIO[index >> kRxMemBaseShift];
        md->complete();
""", """        md = rxMapInfo->rxMemIO[index >> kRxMemBaseShift];
        dmaCmd = rxMapInfo->rxDmaCmd[index >> kRxMemBaseShift];
        dmaCmd->clearMemoryDescriptor();
        md->complete();
""", "runtime RX command before descriptor reuse")
    # rxMapBuffers() clears the batch command -- a synchronous unmap plus
    # invalidation -- before it maps the batch again. Under physical addressing
    # the re-map returns the same address, so an in-flight RX write was
    # harmless. Under IOVA the new pages are different, so a descriptor the NIC
    # has not retired yet would write to an unmapped IOVA and raise a real
    # IO_PAGE_FAULT. Stop RX DMA through the ordinary driver path first and wait
    # for the completions already in flight, then rewrite the ring.
    setup = once(setup, """void RTL8111::clearDescriptors()
{
    IOMemoryDescriptor *md;
    mbuf_t m;
    UInt64 word1;
    UInt32 lastIndex = kTxLastDesc;
    UInt32 i;
""", """void RTL8111::clearDescriptors()
{
    IOMemoryDescriptor *md;
    mbuf_t m;
    UInt64 word1;
    UInt32 lastIndex = kTxLastDesc;
    UInt32 i;

    /* R53: the ring rewrite below unmaps and remaps every RX batch to different
     * IOVAs. Descriptors still owned by the NIC would then point into
     * invalidated pages, so RX DMA must be stopped and drained first. This is
     * the driver's own disable path, not a test hook. */
    if (useAppleVTD) {
        UInt16 mask = ReadReg16(IntrMask);
        WriteReg16(IntrMask, 0);
        WriteReg8(ChipCmd, ReadReg8(ChipCmd) & ~(CmdRxEnb | CmdTxEnb));
        OSSynchronizeIO();
        setProperty("rtl8111-r53-drain-command", UInt64(ReadReg8(ChipCmd)), 64);
        IOSleep(20);
        WriteReg16(IntrStatus, ReadReg16(IntrStatus));
        WriteReg16(IntrMask, mask);
        ++r53RingDrainCount;
    }
""", "stop RX DMA before remap")
    prepared = """        if (md->prepare() != kIOReturnSuccess) {
            IOLog("Failed to prepare rx IOMemoryDescriptor.\\n");
            goto done;
        }
"""
    vtd = once(vtd, prepared, prepared + """        if (dmaCmd->setMemoryDescriptor(md) != kIOReturnSuccess) {
            IOLog("Failed to map rx DMA command.\\n");
            goto done;
        }
""", "runtime RX explicit mapping")
    vtd = once(vtd, physical, """            dmaOffset = offset;
            dmaCount = 1;
            if (dmaCmd->gen64IOVMSegments(&dmaOffset, &dmaSeg, &dmaCount) != kIOReturnSuccess ||
                dmaCount != 1 || dmaSeg.fLength != PAGE_SIZE || !dmaSeg.fIOVMAddr) {
                IOLog("Failed to generate rx IOVA.\\n");
                goto done;
            }
            pa = dmaSeg.fIOVMAddr;
""", "runtime RX IOVA output")
    # A runtime mapping failure cannot leave the NIC consuming retired IOVAs.
    begin = vtd.index("UInt16 RTL8111::rxMapBuffers(")
    end = vtd.index("UInt32 RTL8111::rxInterruptVTD(", begin)
    method = vtd[begin:end].replace("goto done;", "goto error_map;")
    method = once(method, "done:\n    return index;\n", """    goto done;
error_map:
    rtl8168_nic_reset(&linuxData);
    r53State = "map-failed";
    r53Snapshot();
done:
    return index;
""", "runtime RX mapping failure stops DMA")
    vtd = vtd[:begin] + method + vtd[end:]
    if "getPhysicalSegment(offset" in vtd:
        raise SystemExit("legacy packet DMA address lookup remains")
    return hpp, cpp, setup, vtd


def transform(files, version):
    """Transform verified upstream bytes, preserving their license headers."""
    out = dict(files)
    hpp = out["RealtekRTL8111.hpp"].decode("utf-8")
    cpp = out["RealtekRTL8111.cpp"].decode("utf-8")
    setup = out["RealtekRTL8111Setup.cpp"].decode("utf-8")
    vtd = out["RealtekRTL8111VTD.cpp"].decode("utf-8")
    hpp = once(hpp, "#include \"RealtekRxPool.hpp\"\n",
               "#include \"RealtekRxPool.hpp\"\n#include \"amd_iommu_device_policy.hpp\"\n#include <mach/mach_time.h>\n",
               "shared device policy")
    hpp = once(hpp, "public:\n", "public:\n    virtual IOReturn setProperties(OSObject *properties) override;\n",
               "snapshot declaration")
    hpp = once(hpp, "    bool useAppleVTD;\n", "    bool useAppleVTD;\n" + MEMBERS, "members")
    cpp = once(cpp, "        useAppleVTD = false;\n", """        useAppleVTD = false;
        mapper = NULL;
        r53NormalMapped = r53ResourcesReady = false;
        r53EnableCount = r53DisableCount = r53Tso6Count = r53SnapshotSerial = 0;
        r53RingDrainCount = 0;
        r53State = "initializing";
""", "initialization")
    cpp = once(cpp, "    pciDevice->retain();\n", """    pciDevice->retain();
    if (!amd_iommu_policy::waitForMapper(pciDevice))
        goto error_open;
""", "selected device readiness")
    cpp = once(cpp, "    getParams();\n", "    getParams();\n    r53SelectMapper();\n", "actual mapper selection")
    cpp = once(cpp, """    if (!initRTL8111()) {
        goto error_cfg;
    }
""", """    if (!initRTL8111()) {
        goto error_cfg;
    }
    if (r53NormalMapped) {
        /* initRTL8111 already performs exitOOB/hw_init/nic_reset.
         * Confirm DMA is stopped before the first ordinary mapping activates DTE. */
        const UInt32 command = ReadReg8(ChipCmd);
        setProperty("rtl8111-r53-reset-command", UInt64(command), 64);
        setProperty("rtl8111-r53-reset-done-time", mach_absolute_time(), 64);
        if (command & (CmdTxEnb | CmdRxEnb | CmdReset)) {
            IOLog("RTL8111: DMA still active after initial NIC reset.\\n");
            goto error_cfg;
        }
    }
""", "normal reset before first map")
    ready = """    if (!setupStatResources()) {
        IOLog("Error allocating Stat resources.\\n");
        goto error_dma3;
    }
"""
    cpp = once(cpp, ready, ready + """    r53ResourcesReady = true;
    r53State = "resources-ready";
    setProperty("rtl8111-r53-resources-ready-time", mach_absolute_time(), 64);
    r53Snapshot();
""", "resources ready")
    # All failed start paths must report failure; the upstream result still
    # contains super::start() success at this label.
    cpp = once(cpp, "error_open:\n    pciDevice->release();",
               "error_open:\n    result = false;\n    pciDevice->release();", "failed start result")
    cpp = once(cpp, "error_cfg:\n    pciDevice->close(this);",
               "error_cfg:\n    RELEASE(mapper);\n    pciDevice->close(this);", "failed start mapper release")
    stop = """    freeStatResources();
    freeRxResources();
    freeTxResources();
"""
    cpp = once(cpp, stop, """    r53ResourcesReady = false;
""" + stop + "    RELEASE(mapper);\n", "stop mapper lifetime")
    # free() also handles a partially started instance.
    cpp = once(cpp, "    RELEASE(pciDevice);\n\n    DebugLog(\"free() <===\\n\");",
               "    RELEASE(pciDevice);\n    RELEASE(mapper);\n\n    DebugLog(\"free() <===\\n\");",
               "free mapper lifetime")
    enabled = "    WriteReg8(ChipCmd, CmdTxEnb | CmdRxEnb);\n"
    cpp = once(cpp, enabled, enabled + """    ++r53EnableCount;
    r53State = "enabled";
    setProperty("rtl8111-r53-enable-command", UInt64(ReadReg8(ChipCmd)), 64);
    setProperty("rtl8111-r53-enable-time", mach_absolute_time(), 64);
    r53Snapshot();
""", "actual hardware enable")
    disabled = "    disableRTL8111();\n    \n    clearDescriptors();\n"
    cpp = once(cpp, disabled, disabled + """    ++r53DisableCount;
    r53State = "disabled";
    setProperty("rtl8111-r53-disable-command", UInt64(ReadReg8(ChipCmd)), 64);
    setProperty("rtl8111-r53-disable-time", mach_absolute_time(), 64);
    r53Snapshot();
""", "ordinary interface disable")
    tso = """void RTL8111::getTso6Command(UInt32 *cmd1, UInt32 *cmd2, UInt32 mssValue, mbuf_tso_request_flags_t tsoFlags)
{
"""
    cpp = once(cpp, tso, tso + "    ++r53Tso6Count;\n", "actual TSO6 observation")
    # The mapped packet descriptor pool has 256 entries, smaller than the
    # 512 hardware slots. Apply normal output backpressure before dequeue.
    cpp = once(cpp,
               "while ((txNumFreeDesc > (kMaxSegs + 3)) && (interface->dequeueOutputPackets",
               "while ((txNumFreeDesc > (kMaxSegs + 3)) && (!useAppleVTD || txMapInfo->txNumFreeMem > 1) && (interface->dequeueOutputPackets",
               "mapped TX pool backpressure")
    cpp = once(cpp,
               "result = (txNumFreeDesc > (kMaxSegs + 3)) ? kIOReturnSuccess : kIOReturnNoResources;",
               "result = (txNumFreeDesc > (kMaxSegs + 3) && (!useAppleVTD || txMapInfo->txNumFreeMem > 1)) ? kIOReturnSuccess : kIOReturnNoResources;",
               "mapped TX output stall")
    vtd = once(vtd, "    if (packet && vector && maxSegs) {\n",
               "    if (packet && vector && maxSegs && txMapInfo->txNumFreeMem > 1) {\n",
               "mapped TX requires a descriptor")
    cpp += "\n" + METHODS
    # getParams must not select another device's AppleVTD service; all mappings
    # below use the mapper copied for this PCI device.
    start = setup.index("    if (version_major >= Tahoe) {\n")
    end = setup.index("    versionString =", start)
    setup = setup[:start] + "    useAppleVTD = mapper != NULL;\n" + setup[end:]
    setup = once(setup, "    OSIterator *iterator;\n", "", "obsolete service lookup local")
    setup = once(setup, "    if (txBufDesc->prepare() != kIOReturnSuccess) {",
                 """    if (r53NormalMapped)
        setProperty("rtl8111-r53-first-dma-prepare-time", mach_absolute_time(), 64);
    if (txBufDesc->prepare() != kIOReturnSuccess) {""", "first ordinary DMA")
    setup = once(setup,
                 "statDescDmaCmd = IODMACommand::withSpecification(kIODMACommandOutputHost64, 64, 0, IODMACommand::kMapped, 0, 1);",
                 "statDescDmaCmd = IODMACommand::withSpecification(kIODMACommandOutputHost64, 64, 0, IODMACommand::kMapped, 0, 1, mapper, NULL);",
                 "tally actual mapper")
    # A fresh TX descriptor must use the same per-device mapper as its reused
    # initWithOptions() form. No gSystem mapper is installed in this project.
    vtd = once(vtd,
               "md = IOMemoryDescriptor::withAddressRanges(dstRange, segIndex, (kIOMemoryTypeVirtual | kIODirectionOut | kIOMemoryAsReference), kernel_task);",
               "md = IOMemoryDescriptor::withOptions(dstRange, segIndex, 0, kernel_task, (kIOMemoryTypeVirtual | kIODirectionOut | kIOMemoryAsReference), mapper);",
               "fresh TX actual mapper")
    vtd = once(vtd, """            rxDescArray[i].buf.blen = OSSwapHostToLittleInt64(word1);
            rxDescArray[i].buf.addr = OSSwapHostToLittleInt64(rxBufArray[i].phyAddr);
""", """            rxDescArray[n].buf.blen = OSSwapHostToLittleInt64(word1);
            rxDescArray[n].buf.addr = OSSwapHostToLittleInt64(pa);
""", "initial RX per-slot address")
    hpp, cpp, setup, vtd = payload_commands(hpp, cpp, setup, vtd)
    for name, text in (("RealtekRTL8111.hpp", hpp), ("RealtekRTL8111.cpp", cpp),
                       ("RealtekRTL8111Setup.cpp", setup), ("RealtekRTL8111VTD.cpp", vtd)):
        out[name] = text.encode("utf-8")
    out["Info.plist"] = versioned_plist(files["Info.plist"], version)
    return out


def versioned_plist(data, version):
    plist_text = data.decode("utf-8")
    for old, new in (("$" + "{EXECUTABLE_NAME}", "RealtekRTL8111"),
                     ("$" + "{PRODUCT_NAME:rfc1034identifier}", "RealtekRTL8111"),
                     ("$" + "{PRODUCT_NAME}", "RealtekRTL8111")):
        plist_text = plist_text.replace(old, new)
    info = plistlib.loads(plist_text.encode("utf-8"))
    info["CFBundleVersion"] = info["CFBundleShortVersionString"] = version
    info["IOKitPersonalities"]["RTL8111 PCIe Adapter"]["DriverVersion"] = version
    info["OSBundleLibraries"]["org.maz1.AMDMapperProbe"] = "0.61.0"
    return plistlib.dumps(info, sort_keys=False)


def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + bytes([0]) + data).hexdigest()


def digest(data):
    return hashlib.sha256(data).hexdigest()


# Accepted R53 implementation 49365e9 (includes mapped RX ring drain).
R53_GENERATOR = "0c54b0bb98f0ddac9fe40bccf6a882a8231eaaaa029eff9bc0defe3d4c6e4673"
R53_FILE_CATALOG = "6059e6a26ee4e56ebfcd85bee8343c2e1f2404a48489caf2009ad58924c5edd1"


def existing_updates(source, stamp, pin, fingerprint, policy):
    hashes = stamp.get("files", {})
    managed = {item["path"] for item in pin["files"]}
    managed.add("RealtekRTL8111/amd_iommu_device_policy.hpp")
    if stamp.get("upstream") != pin["commit"] or set(hashes) != managed:
        raise SystemExit("fixed RTL8111 input or managed file list differs")
    current = stamp.get("generator") == fingerprint and stamp.get("version") == pin["version"]
    if not current:
        catalog = digest(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode())
        if (stamp.get("version") != "3.0.53" or stamp.get("generator") != R53_GENERATOR or
                catalog != R53_FILE_CATALOG):
            raise SystemExit("unrecognized RTL8111 generated input; no files changed")
    for path, expected in hashes.items():
        if digest((source / path).read_bytes()) != expected:
            raise SystemExit("generated source changed: " + path)
    if current:
        return {}
    # R54 leaves the accepted C++ and other pinned inputs byte-for-byte intact.
    info = (source / "RealtekRTL8111/Info.plist").read_bytes()
    return {"amd_iommu_device_policy.hpp": policy,
            "Info.plist": versioned_plist(info, pin["version"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    driver = source / "RealtekRTL8111"
    pin_path = HERE / "rtl8111-source-pin.json"
    pin = json.loads(pin_path.read_text(encoding="utf-8"))
    policy = (ROOT / "kext/amd_iommu_device_policy.hpp").read_bytes()
    fingerprint = digest(Path(__file__).read_bytes() + pin_path.read_bytes() + policy)
    stamp_path = source / ".r53-generated.json"
    if stamp_path.exists():
        stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
        generated = existing_updates(source, stamp, pin, fingerprint, policy)
        if not generated:
            print("RTL8111 already current:", pin["version"], source)
            return
        hashes = dict(stamp["files"])
    else:
        originals = {}
        hashes = {}
        for item in pin["files"]:
            data = (source / item["path"]).read_bytes()
            if len(data) != item["bytes"] or git_blob(data) != item["git_blob"]:
                raise SystemExit("pinned source mismatch: " + item["path"])
            hashes[item["path"]] = digest(data)
            if item["path"].startswith("RealtekRTL8111/"):
                originals[Path(item["path"]).name] = data
        # Confirm the upstream reset is before the existing DMA allocation path.
        hardware = originals["RealtekRTL8111Hardware.cpp"].decode("utf-8")
        init = hardware.split("bool RTL8111::initRTL8111()", 1)[1].split("void RTL8111::enableRTL8111()", 1)[0]
        if "    exitOOB();\n    rtl8168_hw_init(tp);\n    rtl8168_nic_reset(tp);" not in init:
            raise SystemExit("upstream initial reset contract changed")
        generated = transform(originals, pin["version"])
        generated["amd_iommu_device_policy.hpp"] = policy
    for name, data in generated.items():
        target = driver / name
        if not target.exists() or target.read_bytes() != data:
            target.write_bytes(data)
        hashes["RealtekRTL8111/" + name] = digest(data)
    stamp_path.write_bytes((json.dumps({"upstream": pin["commit"], "generator": fingerprint,
                                       "version": pin["version"], "files": hashes},
                                      indent=2) + "\n").encode("utf-8"))
    print("RTL8111 generated:", pin["version"], source)


if __name__ == "__main__":
    main()
