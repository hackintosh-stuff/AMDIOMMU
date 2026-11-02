/* RTL812xEthernet.cpp -- RTL8125 driver class implementation.
*
* Copyright (c) 2020 Laura Müller <laura-mueller@uni-duesseldorf.de>
* All rights reserved.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License as published by the Free
* Software Foundation; either version 2 of the License, or (at your option)
* any later version.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
* more details.
*
* Driver for Realtek RTL8125 PCIe 2.5GB ethernet controllers.
*
* This driver is based on Realtek's r8125 Linux driver (9.003.04).
*/

#include "RTL812xLucy.hpp"

#pragma mark --- function prototypes ---

static inline void prepareTSO4(mbuf_t m, UInt32 *tcpOffset, UInt32 *mss);
static inline void prepareTSO6(mbuf_t m, UInt32 *tcpOffset, UInt32 *mss);

static inline u32 ether_crc(int length, unsigned char *data);


#pragma mark --- static data ---

static const char *speed10GName = "10 Gigabit";
static const char *speed5GName = "5 Gigabit";
static const char *speed25GName = "2.5 Gigabit";
static const char *speed1GName = "1 Gigabit";
static const char *speed100MName = "100 Megabit";
static const char *speed10MName = "10 Megabit";
static const char *duplexFullName = "full-duplex";
static const char *duplexHalfName = "half-duplex";
static const char *offFlowName = "no flow-control";
static const char *onFlowName = "flow-control";

static const char* eeeNames[kEEETypeCount] = {
    "",
    ", energy-efficient-ethernet"
};

#define _R(NAME,SNAME,MAC,RCR,MASK,JumFrameSz) \
    { .name = NAME, .speed_name = SNAME, .mcfg = MAC, .RCR_Cfg = RCR, .RxConfigMask = MASK, .jumbo_frame_sz = JumFrameSz }

const struct RtlChipInfo rtlChipInfo[NUM_CHIPS] {
    _R("RTL8125A rev. 1",
    "2.5",
    CFG_METHOD_2,
    Rx_Fetch_Number_8 | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
    0xff7e5880,
    Jumbo_Frame_9k),

    _R("RTL8125A rev. 2",
    "2.5",
    CFG_METHOD_3,
    Rx_Fetch_Number_8 | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
    0xff7e5880,
    Jumbo_Frame_9k),

    _R("RTL8125B rev. 1",
    "2.5",
    CFG_METHOD_4,
    Rx_Fetch_Number_8 | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
    0xff7e5880,
    Jumbo_Frame_9k),

    _R("RTL8125B rev. 2",
    "2.5",
    CFG_METHOD_5,
    Rx_Fetch_Number_8 | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
    0xff7e5880,
    Jumbo_Frame_9k),

    _R("RTL8168KB rev. 1",
    "2.5",
    CFG_METHOD_6,
    Rx_Fetch_Number_8 | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
    0xff7e5880,
    Jumbo_Frame_9k),

    _R("RTL8168KB rev. 2",
    "2.5",
    CFG_METHOD_7,
    Rx_Fetch_Number_8 | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
    0xff7e5880,
    Jumbo_Frame_9k),

    _R("RTL8125BP rev. 1",
    "2.5",
    CFG_METHOD_8,
    Rx_Fetch_Number_8 | Rx_Close_Multiple | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
    0xff7e5880,
    Jumbo_Frame_9k),

    _R("RTL8125BP rev. 2",
    "2.5",
    CFG_METHOD_9,
    Rx_Fetch_Number_8 | Rx_Close_Multiple | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
    0xff7e5880,
    Jumbo_Frame_9k),

    _R("RTL8125D rev. 1",
    "2.5",
    CFG_METHOD_10,
    Rx_Fetch_Number_8 | Rx_Close_Multiple | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
    0xff7e5880,
    Jumbo_Frame_9k),

    _R("RTL8125D rev. 2",
    "2.5",
    CFG_METHOD_11,
    Rx_Fetch_Number_8 | Rx_Close_Multiple | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
    0xff7e5880,
    Jumbo_Frame_9k),

    _R("RTL8125CP rev. 1",
    "2.5",
    CFG_METHOD_12,
    Rx_Fetch_Number_8 | Rx_Close_Multiple | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
    0xff7e5880,
    Jumbo_Frame_9k),

    _R("RTL8168KD rev. 1",
    "2.5",
    CFG_METHOD_13,
    Rx_Fetch_Number_8 | Rx_Close_Multiple | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_256 << RxCfgDMAShift),
    0xff7e5880,
    Jumbo_Frame_9k),
    
    _R("RTL8126A rev. 1",
    "5",
    CFG_METHOD_31,
    Rx_Fetch_Number_8 | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_512 << RxCfgDMAShift),
    0xff7e5880,
    Jumbo_Frame_9k),

    _R("RTL8126A rev. 2",
    "5",
    CFG_METHOD_32,
    Rx_Fetch_Number_8 | Rx_Close_Multiple | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_512 << RxCfgDMAShift),
    0xff7e5880,
    Jumbo_Frame_9k),

    _R("RTL8126A rev. 3",
    "5",
    CFG_METHOD_33,
    Rx_Fetch_Number_8 | Rx_Close_Multiple | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_512 << RxCfgDMAShift),
    0xff7e5880,
    Jumbo_Frame_9k),

    _R("RTL8127 rev. 1",
    "10",
    CFG_METHOD_41,
    Rx_Fetch_Number_8 | Rx_Close_Multiple | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_512 << RxCfgDMAShift),
    0xff7e5880,
    Jumbo_Frame_9k),

    _R("RTL8127 rev. 2",
    "10",
    CFG_METHOD_42,
    Rx_Fetch_Number_8 | Rx_Close_Multiple | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST_512 << RxCfgDMAShift),
    0xff7e5880,
    Jumbo_Frame_9k),

    _R("Unknown",
    "2.5",
    CFG_METHOD_DEFAULT,
    (RX_DMA_BURST_512 << RxCfgDMAShift),
    0xff7e5880,
    Jumbo_Frame_1k)
};
#undef _R

#pragma mark --- public methods ---

OSDefineMetaClassAndStructors(RTL8125, super)

/* IOService (or its superclass) methods. */

bool RTL8125::init(OSDictionary *properties)
{
    bool result;
    
    result = super::init(properties);
    
    if (result) {
        workLoop = NULL;
        commandGate = NULL;
        pciDevice = NULL;
        mediumDict = NULL;
        txQueue = NULL;
        interruptSource = NULL;
        timerSource = NULL;
        netif = NULL;
        netStats = NULL;
        etherStats = NULL;
        baseMap = NULL;
        rxPool = NULL;
        r15Pool = NULL;
        r17Tx = NULL;
        txMbufCursor = NULL;
        rxBufArrayMem = NULL;
        txBufArrayMem = NULL;
        statBufDesc = NULL;
        statPhyAddr = (IOPhysicalAddress64)NULL;
        statData = NULL;
        rxPacketHead = NULL;
        rxPacketTail = NULL;
        rxPacketSize = 0;

        /* Initialize state flags. */
        stateFlags = 0;
        
        mtu = ETH_DATA_LEN;
        powerState = 0;
        //speed = 0;
        //duplex = DUPLEX_FULL;
        //autoneg = AUTONEG_ENABLE;
        //flowCtl = kFlowControlOff;
        //eeeCap = 0;
        memset(&linuxData, 0, sizeof(struct rtl8125_private));
        linuxData.mmio_addr = NULL;
        linuxData.aspm = 0;
        //linuxData.configEEE = 0;
        //linuxData.s0MagicPacket = 0;
        //linuxData.hwoptimize = 0;
        linuxData.DASH = 0;
        pciDeviceData.vendor = 0;
        pciDeviceData.device = 0;
        pciDeviceData.subsystem_vendor = 0;
        pciDeviceData.subsystem_device = 0;
        linuxData.pci_dev = &pciDeviceData;
        rtlChipInfos = &rtlChipInfo[0];
        //pollInterval2500 = 0;
        wolCapable = false;
        enableTSO4 = false;
        enableTSO6 = false;
        useAppleVTD = false;
        hasSensor = false;
        pciPMCtrlOffset = 0;
        memset(fallBackMacAddr.bytes, 0, kIOEthernetAddressSize);
        nanoseconds_to_absolutetime(kStatDelayTime, &statDelay);
        nanoseconds_to_absolutetime(kTimerPeriod, &timerInterval);

#ifdef DEBUG_INTR
        lastRxIntrupts = lastTxIntrupts = lastTmrIntrupts = tmrInterrupts = 0;
#endif
    }
    
done:
    return result;
}

void RTL8125::free()
{
    UInt32 i;
    
    DebugLog("free() ===>\n");
    
    if (workLoop) {
        if (interruptSource) {
            workLoop->removeEventSource(interruptSource);
            RELEASE(interruptSource);
        }
        if (timerSource) {
            workLoop->removeEventSource(timerSource);
            RELEASE(timerSource);
        }
        workLoop->release();
        workLoop = NULL;
    }
    RELEASE(commandGate);
    RELEASE(txQueue);
    RELEASE(mediumDict);
    
    for (i = MIDX_AUTO; i < MIDX_COUNT; i++)
        mediumTable[i] = NULL;

    RELEASE(baseMap);
    linuxData.mmio_addr = NULL;
    
    RELEASE(pciDevice);
    freeTxResources();
    freeRxResources();
    freeStatResources();
    
    DebugLog("free() <===\n");
    
    super::free();
}

bool RTL8125::start(IOService *provider)
{
    bool result;
    
    result = super::start(provider);
    
    if (!result) {
        IOLog("IOEthernetController::start failed.\n");
        goto done;
    }
    clear_mask((__M_CAST_M | __PROMISC_M), &stateFlags);
    multicastFilter = 0;

    pciDevice = OSDynamicCast(IOPCIDevice, provider);
    
    if (!pciDevice) {
        IOLog("No provider.\n");
        goto done;
    }
    pciDevice->retain();
    
    if (!pciDevice->open(this)) {
        IOLog("Failed to open provider.\n");
        goto error_open;
    }
    mapper = IOMapper::copyMapperForDevice(pciDevice);

    getParams();

#if defined(__arm64__)
    /*
     * On Apple Silicon all PCIe/Thunderbolt DMA is translated by DART.
     * Raw physical addresses would fault, so the mapper-aware code path
     * (historically the AppleVTD path) is mandatory whenever the device
     * has a system mapper.
     */
    if (mapper && !useAppleVTD) {
        IOLog("DART mapper present, using mapped DMA path.\n");
        useAppleVTD = true;
    }
#endif
    
    if (!initPCIConfigSpace(pciDevice)) {
        goto error_cfg;
    }

    if (!rtl812xInit()) {
        IOLog("Failed to initialize chip.\n");
        goto error_cfg;
    }
    
    if (!setupMediumDict()) {
        IOLog("Failed to setup medium dictionary.\n");
        goto error_cfg;
    }
    commandGate = getCommandGate();
    
    if (!commandGate) {
        IOLog("getCommandGate() failed.\n");
        goto error_gate;
    }
    commandGate->retain();
    
    if (!setupTxResources()) {
        IOLog("Error allocating Tx resources.\n");
        goto error_dma1;
    }

    if (!setupRxResources()) {
        IOLog("Error allocating Rx resources.\n");
        goto error_dma2;
    }

    if (!setupStatResources()) {
        IOLog("Error allocating Stat resources.\n");
        goto error_dma3;
    }

    /* Round 10: allocate the observation log. A failure here is NOT fatal --
     * the NIC works fine without it, and refusing to start the interface
     * because a diagnostic buffer could not be allocated would be worse than
     * starting it with no diagnostics. obsInit() records the failure and
     * obsPublish() reports "unavailable" so the absence is visible. */
    if (!obsInit()) {
        IOLog("Observation log unavailable; continuing without it.\n");
    }

    /* Round 14: the RX posted-buffer tables. Allocated AFTER setupRxResources()
     * because the first baseline capture reads rxDescArray/rxBufArray, and
     * before attachInterface() is not required (the BSD unit is resolved at
     * publish time). Not fatal, for the same reason as above. */
    if (!rxpostInit()) {
        IOLog("RX post tables unavailable; continuing without them.\n");
    }

    if (!initEventSources(provider)) {
        IOLog("initEventSources() failed.\n");
        goto error_src;
    }
    
    result = attachInterface(reinterpret_cast<IONetworkInterface**>(&netif));

    if (!result) {
        IOLog("attachInterface() failed.\n");
        goto error_src;
    }
    pciDevice->close(this);
    result = true;
    
done:
    return result;

error_src:
    freeStatResources();

error_dma3:
    freeRxResources();

error_dma2:
    freeTxResources();
    
error_dma1:
    RELEASE(commandGate);
        
error_gate:
    RELEASE(mediumDict);

error_cfg:
    pciDevice->close(this);
    
error_open:
    pciDevice->release();
    pciDevice = NULL;
    goto done;
}

void RTL8125::stop(IOService *provider)
{
    UInt32 i;
    
    if (netif) {
        detachInterface(netif);
        netif = NULL;
    }
    r17TxStop();
    if (workLoop) {
        if (interruptSource) {
            workLoop->removeEventSource(interruptSource);
            RELEASE(interruptSource);
        }
        if (timerSource) {
            workLoop->removeEventSource(timerSource);
            RELEASE(timerSource);
        }
        workLoop->release();
        workLoop = NULL;
    }
    RELEASE(commandGate);
    RELEASE(txQueue);
    RELEASE(mediumDict);
    
    for (i = MIDX_AUTO; i < MIDX_COUNT; i++)
        mediumTable[i] = NULL;

    /* Round 10: publish a last snapshot, then release the log before the
     * rings it describes are torn down. Order matters: publishing after the
     * free would read a released buffer. */
    obsPublish();
    obsFree();

    /* Round 14: same ordering for the RX post tables -- the last publication
     * must describe the rings while they still exist. */
    rxpostCaptureBaseline();
    rxpostPublish();
    rxpostFree();

    freeStatResources();
    freeRxResources();
    freeTxResources();

    RELEASE(baseMap);
    linuxData.mmio_addr = NULL;

    RELEASE(pciDevice);
    
    super::stop(provider);
}

/* Power Management Support */
static IOPMPowerState powerStateArray[kPowerStateCount] =
{
    {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {1, kIOPMDeviceUsable, kIOPMPowerOn, kIOPMPowerOn, 0, 0, 0, 0, 0, 0, 0, 0}
};

IOReturn RTL8125::registerWithPolicyMaker(IOService *policyMaker)
{
    DebugLog("registerWithPolicyMaker() ===>\n");
    
    powerState = kPowerStateOn;
    
    DebugLog("registerWithPolicyMaker() <===\n");

    return policyMaker->registerPowerDriver(this, powerStateArray, kPowerStateCount);
}

IOReturn RTL8125::setPowerState(unsigned long powerStateOrdinal, IOService *policyMaker)
{
    IOReturn result = IOPMAckImplied;
    
    DebugLog("setPowerState() ===>\n");
        
    if (powerStateOrdinal == powerState) {
        DebugLog("Already in power state %lu.\n", powerStateOrdinal);
        goto done;
    }
    DebugLog("switching to power state %lu.\n", powerStateOrdinal);
    
    if (powerStateOrdinal == kPowerStateOff)
        commandGate->runAction(setPowerStateSleepAction);
    else
        commandGate->runAction(setPowerStateWakeAction);

    powerState = powerStateOrdinal;
    
done:
    DebugLog("setPowerState() <===\n");

    return result;
}

void RTL8125::systemWillShutdown(IOOptionBits specifier)
{
    struct rtl8125_private *tp = &linuxData;
    
    DebugLog("systemWillShutdown() ===>\n");
    
    if ((kIOMessageSystemWillPowerOff | kIOMessageSystemWillRestart) & specifier) {
        disable(netif);
        
        /* Restore the original MAC address. */
        rtl8125_rar_set(tp, (UInt8 *)&origMacAddr.bytes);
        rtl8125_set_bios_setting(tp);
    }
    
    DebugLog("systemWillShutdown() <===\n");

    /* Must call super shutdown or system will stall. */
    super::systemWillShutdown(specifier);
}

/* IONetworkController methods. */
IOReturn RTL8125::enable(IONetworkInterface *netif)
{
    const IONetworkMedium *selectedMedium;
    IOReturn result = kIOReturnError;
    
    DebugLog("enable() ===>\n");

    if (test_bit(__ENABLED, &stateFlags)) {
        DebugLog("Interface already enabled.\n");
        result = kIOReturnSuccess;
        goto done;
    }
    if (!pciDevice || pciDevice->isOpen()) {
        IOLog("Unable to open PCI device.\n");
        goto done;
    }
    pciDevice->open(this);
    
    selectedMedium = getSelectedMedium();
    
    if (!selectedMedium) {
        DebugLog("No medium selected. Falling back to autonegotiation.\n");
        selectedMedium = mediumTable[MIDX_AUTO];
    }
    selectMedium(selectedMedium);
    rtl812xEnable();
    
    /* We have to enable the interrupt because we are using a msi interrupt. */
    interruptSource->enable();

    rxPacketHead = rxPacketTail = NULL;
    rxPacketSize = 0;
    txDescDoneCount = txDescDoneLast = 0;
    deadlockWarn = 0;
    set_bit(__ENABLED, &stateFlags);
    clear_bit(__POLL_MODE, &stateFlags);

    result = kIOReturnSuccess;
    
    DebugLog("enable() <===\n");

done:
    return result;
}

IOReturn RTL8125::disable(IONetworkInterface *netif)
{
    UInt64 timeout;
    UInt64 delay;
    UInt64 now;
    UInt64 t;

    DebugLog("disable() ===>\n");
    
    if (!test_bit(__ENABLED, &stateFlags))
        goto done;
    
    netif->stopOutputThread();
    netif->flushOutputQueue();
    
    if (test_bit(__POLLING, &stateFlags)) {
        nanoseconds_to_absolutetime(5000, &delay);
        clock_get_uptime(&now);
        timeout = delay * 10;
        t = delay;

        while (test_bit(__POLLING, &stateFlags) && (t < timeout)) {
            clock_delay_until(now + t);
            t += delay;
        }
    }
    clear_mask((__ENABLED_M | __LINK_UP_M | __POLL_MODE_M | __POLLING_M), &stateFlags);

    timerSource->cancelTimeout();
    txDescDoneCount = txDescDoneLast = 0;

    /* Disable interrupt as we are using msi. */
    interruptSource->disable();

    rtl812xDisable();
    
    clearRxTxRings();
    
    if (pciDevice && pciDevice->isOpen())
        pciDevice->close(this);
        
    DebugLog("disable() <===\n");
    
done:
    return kIOReturnSuccess;
}

struct RTL8125::R17Gen {
    volatile UInt32 state;
    volatile UInt32 doneSeen;
    UInt32 index;               /* gen slot, for witnesses and diagnostics */
    mbuf_t packet;              /* the one mbuf whose PHYSICAL bytes are mapped */
    UInt32 firstSlot, lastSlot; /* ring descriptors this generation occupies */
    IOMemoryDescriptor *stdMD;
    IODMACommand *stdCmd;
    bool stdWired;
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

IOReturn RTL8125::outputStart(IONetworkInterface *interface, IOOptionBits options )
{
    IOPhysicalSegment txSegments[kMaxSegs];
    mbuf_t m;
    RtlTxDesc *desc, *firstDesc;
    IOReturn result = kIOReturnNoResources;
    UInt32 cmd;
    UInt32 opts2;
    UInt32 offloadFlags;
    UInt32 mss;
    UInt32 len;
    UInt32 tcpOff;
    UInt32 opts1;
    UInt32 vlanTag;
    UInt32 numSegs;
    UInt32 lastSeg;
    UInt32 index;
    UInt32 i;
    /* Round 10: business identifier of the packet currently being filled.
     * Extracted once per packet, then copied into every segment's record, so
     * a multi-segment packet cannot produce two records that disagree about
     * which request they belong to. */
    UInt32 obsPktToken = 0, obsPktReq = 0, obsPktFlow = 0, obsPktFlags = 0;
    
    //DebugLog("outputStart() ===>\n");
    
    if (!(test_mask((__ENABLED_M | __LINK_UP_M), &stateFlags)))  {
        DebugLog("Interface down. Dropping packets.\n");
        goto done;
    }
    while ((txNumFreeDesc > (kMaxSegs + 3)) && (r17TxOutputReady() && interface->dequeueOutputPackets(1, &m, NULL, NULL, NULL) == kIOReturnSuccess)) {
        cmd = 0;
        opts2 = 0;

        /* Get the packet length. */
        len = (UInt32)mbuf_pkthdr_len(m);

        if (mbuf_get_tso_requested(m, &offloadFlags, &mss)) {
            DebugLog("mbuf_get_tso_requested() failed. Dropping packet.\n");
            freePacket(m);
            continue;
        }
        if (offloadFlags & (MBUF_TSO_IPV4 | MBUF_TSO_IPV6)) {
            if (offloadFlags & MBUF_TSO_IPV4) {
                if ((len - kMacHdrLen) > mtu) {
                    /*
                     * Fix the pseudo header checksum, get the
                     * TCP header size and set paylen.
                     */
                    prepareTSO4(m, &tcpOff, &mss);
                    
                    cmd = (GiantSendv4 | (tcpOff << GTTCPHO_SHIFT));
                    opts2 = ((mss & MSSMask) << MSSShift_8125);
                } else {
                    /*
                     * There is no need for a TSO4 operation as the packet
                     * can be sent in one frame.
                     */
                    offloadFlags = kChecksumTCP;
                    opts2 = (TxIPCS_C | TxTCPCS_C);
                }
            } else {
                if ((len - kMacHdrLen) > mtu) {
                    /* The pseudoheader checksum has to be adjusted first. */
                    prepareTSO6(m, &tcpOff, &mss);
                    
                    cmd = (GiantSendv6 | (tcpOff << GTTCPHO_SHIFT));
                    opts2 = ((mss & MSSMask) << MSSShift_8125);
                } else {
                    /*
                     * There is no need for a TSO6 operation as the packet
                     * can be sent in one frame.
                     */
                    offloadFlags = kChecksumTCPIPv6;
                    opts2 = (TxTCPCS_C | TxIPV6F_C | (((kMacHdrLen + kIPv6HdrLen) & TCPHO_MAX) << TCPHO_SHIFT));
                }
            }
        } else {
            /* We use mss as a dummy here because it isn't needed anymore. */
            mbuf_get_csum_requested(m, &offloadFlags, &mss);
            
            if (offloadFlags & kChecksumTCP)
                opts2 = (TxIPCS_C | TxTCPCS_C);
            else if (offloadFlags & kChecksumTCPIPv6)
                opts2 = (TxTCPCS_C | TxIPV6F_C | (((kMacHdrLen + kIPv6HdrLen) & TCPHO_MAX) << TCPHO_SHIFT));
            else if (offloadFlags & kChecksumUDP)
                opts2 = (TxIPCS_C | TxUDPCS_C);
            else if (offloadFlags & kChecksumUDPIPv6)
                opts2 = (TxUDPCS_C | TxIPV6F_C | (((kMacHdrLen + kIPv6HdrLen) & TCPHO_MAX) << TCPHO_SHIFT));
            else if (offloadFlags & kChecksumIP)
                opts2 = TxIPCS_C;
        }
        /* Finally get the physical segments. */
        if (useAppleVTD)
            numSegs = txMapPacket(m, txSegments, kMaxSegs);
        else
            numSegs = txMbufCursor->getPhysicalSegmentsWithCoalesce(m, txSegments, kMaxSegs);

        /* Alloc required number of descriptors. As the descriptor
         * which has been freed last must be considered to be still
         * in use we never fill the ring completely but leave at
         * least one unused.
         */
        if (!numSegs) {
            DebugLog("getPhysicalSegmentsWithCoalesce() failed. Dropping packet.\n");
            freePacket(m);
            continue;
        }
        if (!r17TxMap(m, txSegments, numSegs)) continue;
        OSAddAtomic(-numSegs, &txNumFreeDesc);
        index = txNextDescIndex;
        txNextDescIndex = (txNextDescIndex + numSegs) & kTxDescMask;
        /* Round 10: remember where this packet starts in the cumulative index
         * space. txTailPtr0 is the driver's own submit counter, so
         * (txTailPtr0 + i) is the exact cumulative index of the i-th
         * descriptor of this packet -- the same number the hardware will
         * later report through the close pointer. */
        obsTxBatch = txTailPtr0;
        txTailPtr0 += numSegs;
        firstDesc = &txDescArray[index];
        lastSeg = numSegs - 1;

        /* Round 10: extract the business identifier ONCE for the whole
         * packet, while `m` is the mbuf we still hold. Every descriptor of
         * this packet then carries the same (token, reqId), so a multi-
         * segment packet cannot produce two records that disagree about
         * which request they belong to. */
        {
            UInt32 bizToken = 0, bizReq = 0, bizFlow = 0;
            obsPktFlags = obsParseBiz(m, (UInt32)mbuf_pkthdr_len(m), true,
                                      &bizToken, &bizReq, &bizFlow);
            obsPktToken = bizToken;
            obsPktReq = bizReq;
            obsPktFlow = bizFlow;
        }
        
        /* Next fill in the VLAN tag. */
        opts2 |= (getVlanTagDemand(m, &vlanTag)) ? (OSSwapInt16(vlanTag) | TxVlanTag) : 0;
        
        /* And finally fill in the descriptors. */
        for (i = 0; i < numSegs; i++) {
            desc = &txDescArray[index];
            opts1 = (((UInt32)txSegments[i].length) | cmd);
            opts1 |= (i == 0) ? FirstFrag : DescOwn;
            
            if (i == lastSeg) {
                opts1 |= LastFrag;
                /* Round23: the mbuf belongs to a selected generation, so the
                 * TX ring must not own it as well -- the per-packet recycle
                 * path is its only owner. Several generations can be live, so
                 * the test is "does ANY of them hold this mbuf". */
                R17TxState *p = __atomic_load_n(&r17Tx, __ATOMIC_ACQUIRE);
                txMbufArray[index] = (p && r17TxFindByPacket(p, m)) ? NULL : m;
            } else {
                txMbufArray[index] = NULL;
            }
            if (index == kTxLastDesc)
                opts1 |= RingEnd;
            
            desc->addr = OSSwapHostToLittleInt64(txSegments[i].location);
            desc->opts2 = OSSwapHostToLittleInt32(opts2);
            desc->opts1 = OSSwapHostToLittleInt32(opts1);

            /* Round 10: record the descriptor exactly as it was programmed.
             * `len` is the real segment length (txSegments[i].length), which
             * is the one thing a reader of the ring cannot recover when the
             * descriptor carries a TSO command bit. `flags` says whether that
             * happened, so the length is never silently a guess.
             *
             * The business identifier is the SAME for every segment of this
             * packet (extracted once, above), so the join key is stable
             * across segments. */
            {
                UInt32 oflags = 0;
                if (cmd & (GiantSendv4 | GiantSendv6 | LargeSend))
                    oflags |= kObsFlagLenUnknown | kObsFlagTso;
                if (i == 0)
                    oflags |= kObsFlagFirstFrag;
                if (i == lastSeg)
                    oflags |= kObsFlagLastFrag;
                if (index == kTxLastDesc)
                    oflags |= kObsFlagRingEnd;
                if (opts1 & DescOwn)
                    oflags |= kObsFlagDescOwn;
                obsWrite(kObsKindTxSubmit,
                         obsTxBatch + i,
                         index,
                         (obsTxBatch + i) / kNumTxDesc,
                         txSegments[i].location,
                         opts1, opts2,
                         (UInt32)txSegments[i].length,
                         oflags,
                         obsPktToken, obsPktReq, obsPktFlow, obsPktFlags);
            }
            
            //DebugLog("opts1=0x%x, opts2=0x%x, addr=0x%llx, len=0x%llx\n", opts1, opts2, txSegments[i].location, txSegments[i].length);
            ++index &= kTxDescMask;
        }
        firstDesc->opts1 |= DescOwn;
        r17TxPosted(m);
    }
    /* Ensure descriptor writes are visible to the device before the
     * doorbell MMIO write (required on arm64, implicit on x86).
     */
    wmb();

    /* Update tail pointer. */
    rtl812xDoorbell(&linuxData, txTailPtr0);

    /* Round 10: the doorbell is the moment the device is told the descriptors
     * exist. Recording it lets a reader separate "filled in" from "offered to
     * the device", which are two different claims. It carries the same
     * business id as the submits of the packet it releases. */
    obsWrite(kObsKindTxDoorbell, txTailPtr0, 0, 0, 0, 0, 0, 0, 0,
             obsPktToken, obsPktReq, obsPktFlow, obsPktFlags);

    result = (r17TxOutputReady() && (txNumFreeDesc > (kMaxSegs + 3))) ? kIOReturnSuccess : kIOReturnNoResources;
    
done:
    //DebugLog("outputStart() <===\n");
    
    return result;
}

void RTL8125::getPacketBufferConstraints(IOPacketBufferConstraints *constraints) const
{
    DebugLog("getPacketBufferConstraints() ===>\n");

    constraints->alignStart = kIOPacketBufferAlign1;
    constraints->alignLength = kIOPacketBufferAlign1;
    
    DebugLog("getPacketBufferConstraints() <===\n");
}

IOOutputQueue* RTL8125::createOutputQueue()
{
    DebugLog("createOutputQueue() ===>\n");
    
    DebugLog("createOutputQueue() <===\n");

    return IOBasicOutputQueue::withTarget(this);
}

const OSString* RTL8125::newVendorString() const
{
    DebugLog("newVendorString() ===>\n");
    
    DebugLog("newVendorString() <===\n");

    return OSString::withCString("Realtek");
}

const OSString* RTL8125::newModelString() const
{
    DebugLog("newModelString() ===>\n");
    DebugLog("newModelString() <===\n");
    
    return OSString::withCString(rtlChipInfo[linuxData.chipset].name);
}

bool RTL8125::configureInterface(IONetworkInterface *interface)
{
    char modelName[kNameLenght];
    IONetworkData *data;
    IOReturn error;
    bool result;

    DebugLog("configureInterface() ===>\n");

    result = super::configureInterface(interface);
    
    if (!result)
        goto done;
    
    /* Get the generic network statistics structure. */
    data = interface->getParameter(kIONetworkStatsKey);
    
    if (data) {
        netStats = (IONetworkStats *)data->getBuffer();
        
        if (!netStats) {
            IOLog("Error getting IONetworkStats\n.");
            result = false;
            goto done;
        }
    }
    /* Get the Ethernet statistics structure. */
    data = interface->getParameter(kIOEthernetStatsKey);
    
    if (data) {
        etherStats = (IOEthernetStats *)data->getBuffer();
        
        if (!etherStats) {
            IOLog("Error getting IOEthernetStats\n.");
            result = false;
            goto done;
        }
    }
    error = interface->configureOutputPullModel((kNumTxDesc/2), 0, 0, IONetworkInterface::kOutputPacketSchedulingModelNormal);
    
    if (error != kIOReturnSuccess) {
        IOLog("configureOutputPullModel() failed\n.");
        result = false;
        goto done;
    }
    error = interface->configureInputPacketPolling(kNumRxDesc, 0);
    
    if (error != kIOReturnSuccess) {
        IOLog("configureInputPacketPolling() failed\n.");
        result = false;
        goto done;
    }
    snprintf(modelName, kNameLenght, "Realtek %s PCIe %sGbit Ethernet", rtlChipInfo[linuxData.chipset].name, rtlChipInfo[linuxData.chipset].speed_name);
    setProperty("model", modelName);
    
    DebugLog("configureInterface() <===\n");

done:
    return result;
}

bool RTL8125::createWorkLoop()
{
    DebugLog("createWorkLoop() ===>\n");
    
    workLoop = IOWorkLoop::workLoop();
    
    DebugLog("createWorkLoop() <===\n");

    return workLoop ? true : false;
}

IOWorkLoop* RTL8125::getWorkLoop() const
{
    DebugLog("getWorkLoop() ===>\n");
    
    DebugLog("getWorkLoop() <===\n");

    return workLoop;
}

/* Methods inherited from IOEthernetController. */
IOReturn RTL8125::getHardwareAddress(IOEthernetAddress *addr)
{
    IOReturn result = kIOReturnError;
    
    DebugLog("getHardwareAddress() ===>\n");
    
    if (addr) {
        bcopy(&currMacAddr.bytes, addr->bytes, kIOEthernetAddressSize);
        result = kIOReturnSuccess;
    }
    
    DebugLog("getHardwareAddress() <===\n");

    return result;
}

IOReturn RTL8125::setPromiscuousMode(bool active)
{
    struct rtl8125_private *tp = &linuxData;
    UInt32 *filterAddr = (UInt32 *)&multicastFilter;
    UInt32 mcFilter[2];
    UInt32 rxMode;

    DebugLog("setPromiscuousMode() ===>\n");
    
    if (active) {
        DebugLog("Promiscuous mode enabled.\n");
        rxMode = (AcceptBroadcast | AcceptMulticast | AcceptMyPhys | AcceptAllPhys);
        mcFilter[1] = mcFilter[0] = 0xffffffff;
    } else {
        DebugLog("Promiscuous mode disabled.\n");
        rxMode = (AcceptBroadcast | AcceptMulticast | AcceptMyPhys);
        mcFilter[0] = *filterAddr++;
        mcFilter[1] = *filterAddr;
    }
    rxMode |= tp->rtl8125_rx_config | (RTL_R32(tp, RxConfig) & rtlChipInfos[tp->chipset].RxConfigMask);
    RTL_W32(tp, RxConfig, rxMode);
    RTL_W32(tp, MAR0, mcFilter[0]);
    RTL_W32(tp, MAR1, mcFilter[1]);

    if (active)
        set_bit(__PROMISC, &stateFlags);
    else
        clear_bit(__PROMISC, &stateFlags);

    DebugLog("setPromiscuousMode() <===\n");

    return kIOReturnSuccess;
}

IOReturn RTL8125::setMulticastMode(bool active)
{
    struct rtl8125_private *tp = &linuxData;
    UInt32 *filterAddr = (UInt32 *)&multicastFilter;
    UInt32 mcFilter[2];
    UInt32 rxMode;

    DebugLog("setMulticastMode() ===>\n");
    
    if (active) {
        rxMode = (AcceptBroadcast | AcceptMulticast | AcceptMyPhys);
        mcFilter[0] = *filterAddr++;
        mcFilter[1] = *filterAddr;
    } else{
        rxMode = (AcceptBroadcast | AcceptMyPhys);
        mcFilter[1] = mcFilter[0] = 0;
    }
    rxMode |= tp->rtl8125_rx_config | (RTL_R32(tp, RxConfig) & rtlChipInfos[tp->chipset].RxConfigMask);
    RTL_W32(tp, RxConfig, rxMode);
    RTL_W32(tp, MAR0, mcFilter[0]);
    RTL_W32(tp, MAR1, mcFilter[1]);
    
    if (active)
        set_bit(__M_CAST, &stateFlags);
    else
        clear_bit(__M_CAST, &stateFlags);

    DebugLog("setMulticastMode() <===\n");
    
    return kIOReturnSuccess;
}

IOReturn RTL8125::setMulticastList(IOEthernetAddress *addrs, UInt32 count)
{
    struct rtl8125_private *tp = &linuxData;
    UInt64 filter = 0;
    UInt32 *filterAddr = (UInt32 *)&multicastFilter;
    UInt32 i, bitNumber;
    
    DebugLog("setMulticastList() ===>\n");
    
    if (count <= kMCFilterLimit) {
        for (i = 0; i < count; i++, addrs++) {
            bitNumber = ether_crc(6, reinterpret_cast<unsigned char *>(addrs)) >> 26;
            filter |= (1 << (bitNumber & 0x3f));
        }
        multicastFilter = OSSwapInt64(filter);
    } else {
        multicastFilter = 0xffffffffffffffff;
    }
    RTL_W32(tp, MAR0, *filterAddr++);
    RTL_W32(tp, MAR1, *filterAddr);

    DebugLog("setMulticastList() <===\n");

    return kIOReturnSuccess;
}

IOReturn RTL8125::getChecksumSupport(UInt32 *checksumMask, UInt32 checksumFamily, bool isOutput)
{
    IOReturn result = kIOReturnUnsupported;

    DebugLog("getChecksumSupport() ===>\n");

    if ((checksumFamily == kChecksumFamilyTCPIP) && checksumMask) {
        if (isOutput) {
            *checksumMask = (kChecksumTCP | kChecksumUDP | kChecksumIP | kChecksumTCPIPv6 | kChecksumUDPIPv6);
        } else {
            *checksumMask = (kChecksumTCP | kChecksumUDP | kChecksumIP | kChecksumTCPIPv6 | kChecksumUDPIPv6);
        }
        result = kIOReturnSuccess;
    }
    DebugLog("getChecksumSupport() <===\n");

    return result;
}

UInt32 RTL8125::getFeatures() const
{
    UInt32 features = (kIONetworkFeatureMultiPages | kIONetworkFeatureHardwareVlan);
    
    DebugLog("getFeatures() ===>\n");
    
    if (enableTSO4)
        features |= kIONetworkFeatureTSOIPv4;
    
    if (enableTSO6)
        features |= kIONetworkFeatureTSOIPv6;
    
    DebugLog("getFeatures() <===\n");
    
    return features;
}

IOReturn RTL8125::setWakeOnMagicPacket(bool active)
{
    struct rtl8125_private *tp = &linuxData;
    IOReturn result = kIOReturnUnsupported;

    DebugLog("setWakeOnMagicPacket() ===>\n");

    if (tp->wol_opts && wolCapable) {
        tp->wol_enabled = (active) ? WOL_ENABLED : WOL_DISABLED;

        DebugLog("WakeOnMagicPacket %s.\n", active ? "enabled" : "disabled");

        result = kIOReturnSuccess;
    }
    
    DebugLog("setWakeOnMagicPacket() <===\n");

    return result;
}

IOReturn RTL8125::getPacketFilters(const OSSymbol *group, UInt32 *filters) const
{
    IOReturn result = kIOReturnSuccess;

    DebugLog("getPacketFilters() ===>\n");

    if ((group == gIOEthernetWakeOnLANFilterGroup) && wolCapable) {
        *filters = kIOEthernetWakeOnMagicPacket;
        DebugLog("kIOEthernetWakeOnMagicPacket added to filters.\n");
    } else {
        result = super::getPacketFilters(group, filters);
    }
    
    DebugLog("getPacketFilters() <===\n");

    return result;
}

IOReturn RTL8125::setHardwareAddress(const IOEthernetAddress *addr)
{
    IOReturn result = kIOReturnError;
    
    DebugLog("setHardwareAddress() ===>\n");
    
    if (addr) {
        bcopy(addr->bytes, &currMacAddr.bytes, kIOEthernetAddressSize);
        rtl8125_rar_set(&linuxData, (UInt8 *)&currMacAddr.bytes);
        result = kIOReturnSuccess;
    }
    
    DebugLog("setHardwareAddress() <===\n");
    
    return result;
}

IOReturn RTL8125::selectMedium(const IONetworkMedium *medium)
{
    struct rtl8125_private *tp = &linuxData;
    IOReturn result = kIOReturnSuccess;
    UInt32 index;
    
    DebugLog("selectMedium() ===>\n");
    
    if (medium) {
        index = medium->getIndex();
        
        rtl812xMedium2Adv(tp, index);
        setCurrentMedium(medium);
        setLinkDown();
    }
    DebugLog("selectMedium() <===\n");
    
done:
    return result;
}

#pragma mark --- jumbo frame support methods ---

IOReturn RTL8125::getMaxPacketSize(UInt32 * maxSize) const
{
    DebugLog("getMaxPacketSize() ===>\n");
        
    *maxSize = kMaxPacketSize;
    
    DebugLog("maxSize: %u, version_major: %u\n", *maxSize, version_major);

    DebugLog("getMaxPacketSize() <===\n");
    
    return kIOReturnSuccess;
}

IOReturn RTL8125::setMaxPacketSize(UInt32 maxSize)
{
    struct rtl8125_private *tp = &linuxData;
    IOReturn result = kIOReturnError;

    DebugLog("setMaxPacketSize() ===>\n");
    
    if (maxSize <= kMaxPacketSize) {
        mtu = maxSize - (VLAN_ETH_HLEN);
        DebugLog("maxSize: %u, mtu: %u\n", maxSize, mtu);
        
        /* Adjust maximum rx size. */
        tp->rms = mtu + VLAN_ETH_HLEN + ETH_FCS_LEN;
        
        rtl812xSetOffloadFeatures(mtu <= MSS_MAX);

        /* Force reinitialization. */
        setLinkDown();
        timerSource->cancelTimeout();
        
        tp->eee.tx_lpi_timer = mtu + ETH_HLEN + 0x20;
        rtl812xRestart();
        
        result = kIOReturnSuccess;
    }
    
    DebugLog("setMaxPacketSize() <===\n");
    
    return result;
}

#pragma mark --- common interrupt methods ---

void RTL8125::txInterrupt()
{
    struct rtl8125_private *tp = &linuxData;
    mbuf_t m;
    UInt32 nextClosePtr = rtl812xGetHwCloPtr(tp);
    UInt32 oldDirtyIndex = txDirtyDescIndex;
    UInt32 numDone;

    numDone = ((nextClosePtr - txClosePtr0) & tp->MaxTxDescPtrMask);

#ifdef DEBUG_INTR
    DebugLog("txInterrupt() numDone: %u.\n", numDone);
#endif  /* DEBUG_INTR */

    /* Round 10: record each descriptor the device handed back, with the same
     * cumulative index the submit record used. A reader can therefore join
     * submit and completion on (cumulative) alone, without assuming anything
     * about slot reuse. `txClosePtr0` is the driver's own completion counter,
     * read from the hardware close pointer, so this is the same number that
     * produced numDone.
     *
     * The completion does NOT carry a business id: the mbuf has already been
     * unmapped and handed back by the time the close pointer advances, so
     * there is nothing left to parse. The join to a request goes
     * submit -> (cumulative) -> done, which is exact. */
    {
        UInt32 doneCum = txClosePtr0;
        UInt32 doneLeft = numDone;
        UInt32 doneIdx = txDirtyDescIndex;
        while (doneLeft-- > 0) {
            obsWrite(kObsKindTxDone,
                     doneCum,
                     doneIdx,
                     doneCum / kNumTxDesc,
                     0, 0, 0, 0, 0, 0, 0, 0, 0);
            doneCum++;
            ++doneIdx &= kTxDescMask;
        }
    }

    txClosePtr0 = nextClosePtr;

    while (numDone-- > 0) {
        r17TxComplete(txDirtyDescIndex);
        m = txMbufArray[txDirtyDescIndex];
        txMbufArray[txDirtyDescIndex] = NULL;

        if (m) {
            if (useAppleVTD)
                txUnmapPacket();

            freePacket(m, kDelayFree);
        }
        txDescDoneCount++;
        OSIncrementAtomic(&txNumFreeDesc);
        ++txDirtyDescIndex &= kTxDescMask;
    }
    if (oldDirtyIndex != txDirtyDescIndex) {
        if (txNumFreeDesc > kTxQueueWakeTreshhold)
            netif->signalOutputThread();
        
        releaseFreePackets();
    }
}

UInt32 RTL8125::rxInterrupt(IONetworkInterface *interface, uint32_t maxCount, IOMbufQueue *pollQueue, void *context)
{
    RtlRxDesc *desc = &rxDescArray[rxNextDescIndex];
    mbuf_t bufPkt, newPkt;
    UInt64 addr;
    UInt64 word1;
    /* Round 10: descStatus2 and pktSize are read on the RxRES path, which
     * jumps to nextDesc before assigning them. They were uninitialised there
     * before round 9; the observation record would have made that visible as
     * garbage rather than harmless, so they are now initialised. */
    UInt32 descStatus1, descStatus2 = 0;
    SInt32 pktSize = 0;
    UInt32 goodPkts = 0;
    bool replaced;
    UInt64 obsRxAddr = 0;
    /* Round 10: the business id of the packet completed in this iteration,
     * captured before rxPacketHead is cleared. Reset at the top of every
     * iteration so a packet without a magic never inherits the previous
     * packet's identity. */
    UInt32 obsRxToken = 0, obsRxReq = 0, obsRxFlow = 0, obsRxPktFlags = 0;
    
    while (!((descStatus1 = OSSwapLittleToHostInt32(desc->cmd.opts1)) & DescOwn) && (goodPkts < maxCount)) {
        word1 = (rxNextDescIndex == kRxLastDesc) ? (kRxBufferSize | DescOwn | RingEnd) : (kRxBufferSize | DescOwn);
        addr = rxBufArray[rxNextDescIndex].phyAddr;
        /* Round 10: the address the DEVICE wrote into, captured before the
         * descriptor is re-programmed below. */
        obsRxAddr = addr;
        /* Reset the business capture so this iteration cannot inherit the
         * previous packet's identity. */
        obsRxToken = 0; obsRxReq = 0; obsRxFlow = 0; obsRxPktFlags = 0;

        /* Drop packets with receive errors. */
        if (unlikely(descStatus1 & RxRES)) {
            DebugLog("Rx error.\n");
            
            if (descStatus1 & (RxRWT | RxRUNT))
                etherStats->dot3StatsEntry.frameTooLongs++;

            if (descStatus1 & RxCRC)
                etherStats->dot3StatsEntry.fcsErrors++;

            discardPacketFragment();
            goto nextDesc;
        }
        
        descStatus2 = OSSwapLittleToHostInt32(desc->cmd.opts2);
        pktSize = (descStatus1 & 0x1fff);
        bufPkt = rxBufArray[rxNextDescIndex].mbuf;
        //DebugLog("rxInterrupt(): descStatus1=0x%x, descStatus2=0x%x, pktSize=%u\n", descStatus1, descStatus2, pktSize);
        
        if (r15Pool) {
            /* Pool mbufs NEVER escape to the stack. Delivery owns a copy. */
            replaced = false;
            newPkt = r15PoolCopy(bufPkt, (UInt32)pktSize);
        } else {
            newPkt = rxPool->replaceOrCopyPacket(&bufPkt, pktSize, &replaced);
        }
        
        if (unlikely(!newPkt)) {
            /*
             * Allocation of a new packet failed so that we must leave the
             * original packet in place.
             */
            DebugLog("replaceOrCopyPacket() failed.\n");
            etherStats->dot3RxExtraEntry.resourceErrors++;
            discardPacketFragment();
            goto nextDesc;
        }
handle_pkt:
        /* If the packet was replaced we have to update the descriptor's buffer address. */
        if (replaced) {
            if (unlikely(mbuf_next(bufPkt) != NULL)) {
                DebugLog("getPhysicalSegment() failed.\n");
                etherStats->dot3RxExtraEntry.resourceErrors++;
                discardPacketFragment();
                mbuf_freem_list(bufPkt);
                goto nextDesc;
            }
            rxBufArray[rxNextDescIndex].mbuf = bufPkt;
            addr = mbuf_data_to_physical(mbuf_datastart(bufPkt));
            rxBufArray[rxNextDescIndex].phyAddr = addr;
        }
        if (descStatus1 & LastFrag) {
            pktSize -= kIOEthernetCRCSize;
            
            if (rxPacketHead) {
                if (pktSize > 0) {
                    /* This is the last buffer of a jumbo frame. */
                    mbuf_setlen(newPkt, pktSize);

                    mbuf_setflags_mask(newPkt, 0, MBUF_PKTHDR);
                    mbuf_setnext(rxPacketTail, newPkt);
                    
                    rxPacketTail = newPkt;
                } else {
                    /*
                     * The last fragment consists only of the FCS or a part
                     * of it, so that we can drop it and adjust the packet
                     * length to exclude the FCS.
                     */
                    DebugLog("Packet size: %d. Dropping!\n", pktSize);
                    mbuf_free(newPkt);
                    mbuf_adjustlen(rxPacketTail, pktSize);
                }
                rxPacketSize += pktSize;
            } else {
                /*
                 * We've got a complete packet in one buffer.
                 * It can be enqueued directly.
                 */
                mbuf_setlen(newPkt, pktSize);

                rxPacketHead = newPkt;
                rxPacketSize = pktSize;
            }
            getChecksumResult(newPkt, descStatus1, descStatus2);
            
            /* Also get the VLAN tag if there is any. */
            if (descStatus2 & RxVlanTag)
                setVlanTag(rxPacketHead, OSSwapInt16(descStatus2 & 0xffff));
            
            mbuf_pkthdr_setlen(rxPacketHead, rxPacketSize);

            /* Round 10: parse the business id HERE, while rxPacketHead still
             * points at the completed packet. The echo carries the same
             * (token, reqId) the TX submit did, so the reply can be joined to
             * its request by value. Doing this at nextDesc would be too late:
             * rxPacketHead is cleared immediately below. */
            obsRxToken = 0; obsRxReq = 0; obsRxFlow = 0;
            obsRxPktFlags = obsParseBiz(rxPacketHead,
                                        (UInt32)mbuf_pkthdr_len(rxPacketHead),
                                        false, &obsRxToken, &obsRxReq,
                                        &obsRxFlow);

            interface->enqueueInputPacket(rxPacketHead, pollQueue);
            
            rxPacketHead = rxPacketTail = NULL;
            rxPacketSize = 0;
            
            goodPkts++;
        } else {
            mbuf_setlen(newPkt, pktSize);

            if (rxPacketHead) {
                /* We are in the middle of a jumbo frame. */
                mbuf_setflags_mask(newPkt, 0, MBUF_PKTHDR);
                mbuf_setnext(rxPacketTail, newPkt);
                
                rxPacketTail = newPkt;
                rxPacketSize += pktSize;
            } else {
                /* This is the first buffer of a jumbo frame. */
                rxPacketHead = rxPacketTail = newPkt;
                rxPacketSize = pktSize;
            }
        }

        /* Finally update the descriptor and get the next one to examine. */
    nextDesc:
        /* Round 10: record the descriptor the device filled for us. `addr` is
         * the buffer the device wrote into, captured before re-programming
         * (obsRxAddr). `pktSize` is what the device reported.
         *
         * The business identifier is parsed from the received mbuf here, at
         * the only point where the driver still holds it. For the echo reply
         * this yields the SAME (token, reqId) that the TX submit carried, so
         * the reply can be joined to its request without using time or
         * addresses. */
        {
            /* Use the values captured where the packet was complete. */
            obsWrite(kObsKindRxDone,
                     obsRxReaped,
                     rxNextDescIndex,
                     obsRxReaped / kNumRxDesc,
                     obsRxAddr,
                     (UInt32)(descStatus1 & 0xFFFFFFFFu),
                     descStatus2,
                     (UInt32)pktSize,
                     (descStatus1 & RxRES) ? kObsFlagRxError : 0,
                     obsRxToken, obsRxReq, obsRxFlow, obsRxPktFlags);
        }
        obsRxReaped++;

        r15PoolRearm(rxNextDescIndex, obsRxAddr, descStatus1,
                       (UInt32)(descStatus1 & 0x1fff),
                       obsRxToken, obsRxReq, &addr);
        desc->buf.addr = OSSwapHostToLittleInt64(addr);
        wmb();
        desc->buf.blen = OSSwapHostToLittleInt64(word1);
        r15PoolPosted(rxNextDescIndex, addr);

        /* Round 14: record the buffer being handed BACK to the hardware.
         *
         * WHY HERE AND NOT NEXT TO THE obsWrite() ABOVE
         * ---------------------------------------------
         * This is the only point where the FINAL values are known. `addr` is
         * what the descriptor is being re-programmed with (either the original
         * buffer when `replaced` is false, or the new one installed by
         * replaceOrCopyPacket), and `word1` is the length word actually being
         * written. The observation log's rx-done record describes the buffer
         * the device just FILLED, and its `len` is the received packet size --
         * recording that as the posted capacity is exactly the substitution
         * this round exists to remove.
         *
         * WHY IT IS WRITTEN ON THE `nextDesc` PATH RATHER THAN IN THE SUCCESS
         * BRANCH: the error paths (RxRES, replaceOrCopyPacket failure, a
         * multi-segment mbuf) all jump here and all re-program the descriptor.
         * A rearm that only recorded the success path would understate the set
         * precisely where the driver is recycling buffers fastest.
         *
         * `obsRxAddr` is the buffer the descriptor posted at the TOP of this
         * iteration, i.e. exactly what this rearm retires. `addr` is what it
         * installs -- the same value when `replaced` is false, and the new
         * mbuf's physical address when it is true. Recording both is what keeps
         * a buffer that was live at the baseline instant from falling out of
         * the set when the rearm lands during the baseline scan. */
        rxpostRecordRearm(rxNextDescIndex, addr, obsRxAddr, word1);

        ++rxNextDescIndex &= kRxDescMask;
        desc = &rxDescArray[rxNextDescIndex];
    }
    return goodPkts;
}

void RTL8125::rtl812xCheckLinkStatus(struct rtl8125_private *tp)
{
    UInt64 now;
    UInt32 status;
    
    status = RTL_R32(tp, PHYstatus);
    
    if ((status == 0xffffffff) || !(status & LinkStatus)) {
        rtl812xLinkDownPatch(tp);
        
        /* Stop watchdog and statistics updates. */
        timerSource->cancelTimeout();
        setLinkDown();
        
        clearRxTxRings();
    } else {
        /* Get EEE mode. */
        rtl812xGetEEEMode(tp);
        
        /* Get link speed, duplex and flow-control mode. */
        if (status & (TxFlowCtrl | RxFlowCtrl)) {
            tp->fcpause = rtl8125_fc_full;
        } else {
            tp->fcpause = rtl8125_fc_none;
        }
        if (status & _10000bpsF) {
            tp->speed = SPEED_10000;
            tp->duplex = DUPLEX_FULL;
        } else if (status & (_5000bpsF | _10000bpsL)) {
            tp->speed = SPEED_5000;
            tp->duplex = DUPLEX_FULL;
        } else if (status & (_2500bpsF | _5000bpsL)) {
            tp->speed = SPEED_2500;
            tp->duplex = DUPLEX_FULL;
        } else if (status & (_1000bpsF | _2500bpsL | _1000bpsL)) {
                tp->speed = SPEED_1000;
                tp->duplex = DUPLEX_FULL;
        } else if (status & _100bps) {
            tp->speed = SPEED_100;
            
            if (status & FullDup) {
                tp->duplex = DUPLEX_FULL;
            } else {
                tp->duplex = DUPLEX_HALF;
            }
        } else {
            tp->speed = SPEED_10;
            
            if (status & FullDup) {
                tp->duplex = DUPLEX_FULL;
            } else {
                tp->duplex = DUPLEX_HALF;
            }
        }
        rtl812xLinkOnPatch(tp);

        setLinkUp();
        clock_get_uptime(&now);
        timerSource->wakeAtTime(now + timerInterval);
    }
}
/*
void RTL8125::checkLinkStatus()
{
    struct rtl8125_private *tp = &linuxData;
    UInt64 now;
    UInt16 currLinkState;
    
    DebugLog("Link change interrupt: Check link status.\n");

    currLinkState = RTL_R16(tp, PHYstatus);
    
    if (currLinkState & LinkStatus) {
        // Get EEE mode.
        eeeMode = getEEEMode();
        
        // Get link speed, duplex and flow-control mode.
        if (currLinkState & (TxFlowCtrl | RxFlowCtrl)) {
            flowCtl = kFlowControlOn;
        } else {
            flowCtl = kFlowControlOff;
        }
        if (currLinkState & _10000bpsF) {
            speed = SPEED_10000;
            duplex = DUPLEX_FULL;
        } else if (currLinkState & (_5000bpsF | _10000bpsL)) {
            speed = SPEED_5000;
            duplex = DUPLEX_FULL;
        } else if (currLinkState & (_2500bpsF | _5000bpsL)) {
            speed = SPEED_2500;
            duplex = DUPLEX_FULL;
        } else if (currLinkState & _1000bpsF) {
                speed = SPEED_1000;
                duplex = DUPLEX_FULL;
        } else if (currLinkState & _100bps) {
            speed = SPEED_100;
            
            if (currLinkState & FullDup) {
                duplex = DUPLEX_FULL;
            } else {
                duplex = DUPLEX_HALF;
            }
        } else {
            speed = SPEED_10;
            
            if (currLinkState & FullDup) {
                duplex = DUPLEX_FULL;
            } else {
                duplex = DUPLEX_HALF;
            }
        }
        setupRTL8125();
        
        if (tp->mcfg == CFG_METHOD_2) {
            if (RTL_R16(tp, PHYstatus) & FullDup)
                RTL_W32(tp, TxConfig, (RTL_R32(tp, TxConfig) | (BIT_24 | BIT_25)) & ~BIT_19);
            else
                RTL_W32(tp, TxConfig, (RTL_R32(tp, TxConfig) | BIT_25) & ~(BIT_19 | BIT_24));
        }

        if ((tp->mcfg == CFG_METHOD_2 || tp->mcfg == CFG_METHOD_3 ||
             tp->mcfg == CFG_METHOD_4 || tp->mcfg == CFG_METHOD_5) &&
            (RTL_R16(tp, PHYstatus) & _10bps))
                rtl8125_enable_eee_plus(tp);

        setLinkUp();
        clock_get_uptime(&now);
        timerSource->wakeAtTime(now + timerInterval);

        rtl8125_mdio_write(tp, 0x1F, 0x0000);
        linuxData.phy_reg_anlpar = rtl8125_mdio_read(tp, MII_LPA);
    } else {
        tp->phy_reg_anlpar = 0;

        if (tp->mcfg == CFG_METHOD_2 ||
            tp->mcfg == CFG_METHOD_3 ||
            tp->mcfg == CFG_METHOD_4 ||
            tp->mcfg == CFG_METHOD_5)
                rtl8125_disable_eee_plus(tp);

        // Stop watchdog and statistics updates.
        timerSource->cancelTimeout();
        setLinkDown();
    }
}
*/
void RTL8125::interruptOccurred(OSObject *client, IOInterruptEventSource *src, int count)
{
    struct rtl8125_private *tp = &linuxData;
    UInt32 packets;
    UInt32 status;
    
    status = RTL_R32(tp, ISR0_8125);
    
    //DebugLog("interruptHandler: status = 0x%x.\n", status);

    /* hotplug/major error/no more work/shared irq */
    if ((status == 0xFFFFFFFF) || !status)
        goto done;
    
    RTL_W32(tp, IMR0_8125, 0x0000);
    RTL_W32(tp, ISR0_8125, (status & ~RxFIFOOver));

    if (!test_bit(__POLL_MODE, &stateFlags) &&
        !test_and_set_bit(__POLLING, &stateFlags)) {
        /* Rx interrupt */
        if (status & (RxOK | RxDescUnavail)) {
            packets = rxInterrupt(netif, kNumRxDesc, NULL, NULL);
            
            if (packets)
                netif->flushInputQueue();
            
            etherStats->dot3RxExtraEntry.interrupts++;
        }
        /* Tx interrupt */
        if (status & (TxOK | RxOK | PCSTimeout)) {
            txInterrupt();
            
            if (status & TxOK)
                etherStats->dot3TxExtraEntry.interrupts++;
        }
        if (status & (TxOK | RxOK)) {
            RTL_W32(tp, TIMER_INT0_8125, 0x5000);
            RTL_W32(tp, TCTR0_8125, 0x5000);
            intrMask = intrMaskTimer;
        } else if (status & PCSTimeout) {
            RTL_W32(tp, TIMER_INT0_8125, 0x0000);
            intrMask = intrMaskRxTx;
        }
#ifdef DEBUG_INTR
        if (status & PCSTimeout)
            tmrInterrupts++;
#endif
        
        clear_bit(__POLLING, &stateFlags);
    }
    if (status & LinkChg) {
        rtl812xCheckLinkStatus(tp);
        //checkLinkStatus();
        RTL_W32(tp, TIMER_INT0_8125, 0x000);
        intrMask = intrMaskRxTx;
    }
done:
    RTL_W32(tp, IMR0_8125, intrMask);
}

bool RTL8125::txHangCheck()
{
    struct rtl8125_private *tp = &linuxData;
    bool deadlock = false;
    
    if ((txDescDoneCount == txDescDoneLast) && (txNumFreeDesc < kNumTxDesc)) {
        if (++deadlockWarn == kTxCheckTreshhold) {
            /* Some members of the RTL8125 family seem to be prone to lose
             * transmitter rinterrupts. In order to avoid false positives
             * when trying to detect transmitter deadlocks, check the
             * transmitter ring once for completed descriptors before we
             * assume a deadlock.
             */
            DebugLog("Warning: Tx timeout, ISR0=0x%x, IMR0=0x%x, polling=%u.\n", RTL_R32(tp, ISR0_8125),
                     RTL_R32(tp, IMR0_8125), test_bit(__POLL_MODE, &stateFlags));
            etherStats->dot3TxExtraEntry.timeouts++;
            txInterrupt();
        } else if (deadlockWarn >= kTxDeadlockTreshhold) {
#ifdef DEBUG
            UInt32 i, index;
            
            for (i = 0; i < 10; i++) {
                index = ((txDirtyDescIndex - 1 + i) & kTxDescMask);
                IOLog("desc[%u]: opts1=0x%x, opts2=0x%x, addr=0x%llx.\n", index,
                      txDescArray[index].opts1, txDescArray[index].opts2, txDescArray[index].addr);
            }
#endif
            IOLog("Tx stalled? Resetting chipset. ISR0=0x%x, IMR0=0x%x.\n", RTL_R32(tp, ISR0_8125),
                  RTL_R32(tp, IMR0_8125));
            etherStats->dot3TxExtraEntry.resets++;
            rtl812xRestart();
            deadlock = true;
        }
    } else {
        deadlockWarn = 0;
    }
    return deadlock;
}

#pragma mark --- rx poll methods ---

IOReturn RTL8125::setInputPacketPollingEnable(IONetworkInterface *interface, bool enabled)
{
    //DebugLog("setInputPacketPollingEnable() ===>\n");

    if (test_bit(__ENABLED, &stateFlags)) {
        if (enabled) {
            set_bit(__POLL_MODE, &stateFlags);

            intrMask = intrMaskPoll;
        } else {
            clear_bit(__POLL_MODE, &stateFlags);

            intrMask = intrMaskRxTx;
        }
        RTL_W32(&linuxData, IMR0_8125, intrMask);
    }
    DebugLog("Input polling %s.\n", enabled ? "enabled" : "disabled");

    //DebugLog("setInputPacketPollingEnable() <===\n");
    
    return kIOReturnSuccess;
}

void RTL8125::pollInputPackets(IONetworkInterface *interface, uint32_t maxCount, IOMbufQueue *pollQueue, void *context )
{
    //DebugLog("pollInputPackets() ===>\n");
    
    if (test_bit(__POLL_MODE, &stateFlags) &&
        !test_and_set_bit(__POLLING, &stateFlags)) {

        if (useAppleVTD)
            rxInterruptVTD(interface, maxCount, pollQueue, context);
        else
            rxInterrupt(interface, maxCount, pollQueue, context);

        /* Finally cleanup the transmitter ring. */
        txInterrupt();
        
        clear_bit(__POLLING, &stateFlags);
    }
    //DebugLog("pollInputPackets() <===\n");
}

#pragma mark --- hardware specific methods ---

void RTL8125::getChecksumResult(mbuf_t m, UInt32 status1, UInt32 status2)
{
    mbuf_csum_performed_flags_t performed = 0;
    UInt32 value = 0;

    if ((status2 & RxV4F) && !(status1 & RxIPF))
        performed |= (MBUF_CSUM_DID_IP | MBUF_CSUM_IP_GOOD);

    if (((status1 & RxTCPT) && !(status1 & RxTCPF)) ||
        ((status1 & RxUDPT) && !(status1 & RxUDPF))) {
        performed |= (MBUF_CSUM_DID_DATA | MBUF_CSUM_PSEUDO_HDR);
        value = 0xffff; // fake a valid checksum value
    }
    if (performed)
        mbuf_set_csum_performed(m, performed, value);
}

void RTL8125::setLinkUp()
{
    struct rtl8125_private *tp = &linuxData;
    const char *speedName;
    const char *duplexName;
    const char *flowName;
    const char *eeeName;
    UInt64 mediumSpeed;
    UInt32 mediumIndex = MIDX_AUTO;
    UInt32 spd = tp->speed;
    UInt32 fc = tp->fcpause;
    bool eee;
    
    eee = tp->eee.eee_active;
    eeeName = eeeNames[kEEETypeNo];

    /* Get link speed, duplex and flow-control mode. */
    if (fc == rtl8125_fc_full) {
        flowName = onFlowName;
    } else {
        flowName = offFlowName;
    }
    if (spd == SPEED_10000) {
        mediumSpeed = kSpeed10000MBit;
        speedName = speed10GName;
        duplexName = duplexFullName;

        if (fc == rtl8125_fc_full) {
            if (eee) {
                mediumIndex = MIDX_10000FDFC_EEE;
                eeeName = eeeNames[kEEETypeYes];
            } else {
                mediumIndex = MIDX_10000FDFC;
                eeeName = eeeNames[kEEETypeNo];
            }
        } else {
            if (eee) {
                mediumIndex = MIDX_10000FD_EEE;
                eeeName = eeeNames[kEEETypeYes];
            } else {
                mediumIndex = MIDX_10000FD;
                eeeName = eeeNames[kEEETypeNo];
            }
        }
    } else if (spd == SPEED_5000) {
        mediumSpeed = kSpeed5000MBit;
        speedName = speed5GName;
        duplexName = duplexFullName;
       
        if (fc == rtl8125_fc_full) {
            if (eee) {
                mediumIndex = MIDX_5000FDFC_EEE;
                eeeName = eeeNames[kEEETypeYes];
            } else {
                mediumIndex = MIDX_5000FDFC;
                eeeName = eeeNames[kEEETypeNo];
            }
        } else {
            if (eee) {
                mediumIndex = MIDX_5000FD_EEE;
                eeeName = eeeNames[kEEETypeYes];
            } else {
                mediumIndex = MIDX_5000FD;
                eeeName = eeeNames[kEEETypeNo];
            }
        }
    } else if (spd == SPEED_2500) {
        mediumSpeed = kSpeed2500MBit;
        speedName = speed25GName;
        duplexName = duplexFullName;
       
        if (fc == rtl8125_fc_full) {
            if (eee) {
                mediumIndex = MIDX_2500FDFC_EEE;
                eeeName = eeeNames[kEEETypeYes];
            } else {
                mediumIndex = MIDX_2500FDFC;
                eeeName = eeeNames[kEEETypeNo];
            }
        } else {
            if (eee) {
                mediumIndex = MIDX_2500FD_EEE;
                eeeName = eeeNames[kEEETypeYes];
            } else {
                mediumIndex = MIDX_2500FD;
                eeeName = eeeNames[kEEETypeNo];
            }
        }
    } else if (spd == SPEED_1000) {
        mediumSpeed = kSpeed1000MBit;
        speedName = speed1GName;
        duplexName = duplexFullName;
       
        if (fc == rtl8125_fc_full) {
            if (eee) {
                mediumIndex = MIDX_1000FDFC_EEE;
                eeeName = eeeNames[kEEETypeYes];
            } else {
                mediumIndex = MIDX_1000FDFC;
            }
        } else {
            if (eee) {
                mediumIndex = MIDX_1000FD_EEE;
                eeeName = eeeNames[kEEETypeYes];
            } else {
                mediumIndex = MIDX_1000FD;
            }
        }
    } else if (spd == SPEED_100) {
        mediumSpeed = kSpeed100MBit;
        speedName = speed100MName;
        
        if (tp->duplex == DUPLEX_FULL) {
            duplexName = duplexFullName;
            
            if (fc == rtl8125_fc_full) {
                if (eee) {
                    mediumIndex =  MIDX_100FDFC_EEE;
                    eeeName = eeeNames[kEEETypeYes];
                } else {
                    mediumIndex = MIDX_100FDFC;
                }
            } else {
                if (eee) {
                    mediumIndex =  MIDX_100FD_EEE;
                    eeeName = eeeNames[kEEETypeYes];
                } else {
                    mediumIndex = MIDX_100FD;
                }
            }
        } else {
            mediumIndex = MIDX_100HD;
            duplexName = duplexHalfName;
        }
    } else {
        mediumSpeed = kSpeed10MBit;
        speedName = speed10MName;
        
        if (tp->duplex == DUPLEX_FULL) {
            mediumIndex = MIDX_10FD;
            duplexName = duplexFullName;
        } else {
            mediumIndex = MIDX_10HD;
            duplexName = duplexHalfName;
        }
    }
    rxPacketHead = rxPacketTail = NULL;
    rxPacketSize = 0;

    /* Start hardware. */
    RTL_W8(tp, ChipCmd, CmdTxEnb | CmdRxEnb);

    set_bit(__LINK_UP, &stateFlags);
    setLinkStatus(kIONetworkLinkValid | kIONetworkLinkActive, mediumTable[mediumIndex], mediumSpeed, NULL);

    /* Start output thread, statistics update and watchdog. Also
     * update poll params according to link speed.
     */
    bzero(&pollParms, sizeof(IONetworkPacketPollingParameters));
    
    if (spd == SPEED_10) {
        pollParms.lowThresholdPackets = 2;
        pollParms.highThresholdPackets = 8;
        pollParms.lowThresholdBytes = 0x400;
        pollParms.highThresholdBytes = 0x1800;
        pollParms.pollIntervalTime = 1000000;  /* 1ms */
    } else {
        pollParms.lowThresholdPackets = 10;
        pollParms.highThresholdPackets = 40;
        pollParms.lowThresholdBytes = 0x1000;
        pollParms.highThresholdBytes = 0x10000;
        
        if (spd == SPEED_10000)
            pollParms.pollIntervalTime = pollTime5G / 2;
        else if (spd == SPEED_5000)
            pollParms.pollIntervalTime = (mtu < 4076) ? pollTime5G : (pollTime5G + 10000);
        else if (spd == SPEED_2500)
            pollParms.pollIntervalTime = pollTime2G;
        else if (spd == SPEED_1000)
            pollParms.pollIntervalTime = 170000;   /* 170µs */
        else
            pollParms.pollIntervalTime = 1000000;  /* 1ms */
    }
    netif->setPacketPollingParameters(&pollParms, 0);
    DebugLog("pollIntervalTime: %lluµs\n", (pollParms.pollIntervalTime / 1000));

    netif->startOutputThread();

    IOLog("Link up on en%u, %s, %s, %s%s\n", netif->getUnitNumber(), speedName, duplexName, flowName, eeeName);
}

void RTL8125::setLinkDown()
{
    struct rtl8125_private *tp = &linuxData;
    
    deadlockWarn = 0;

    /* Stop output thread and flush output queue. */
    netif->stopOutputThread();
    netif->flushOutputQueue();

    /* Update link status. */
    clear_mask((__LINK_UP_M | __POLL_MODE_M), &stateFlags);
    setLinkStatus(kIONetworkLinkValid);

    rtl812xLinkDownPatch(tp);
    clearRxTxRings();

    /* Enable link change interrupt. */
    intrMask = intrMaskRxTx;
    RTL_W32(tp, IMR0_8125, intrMask);

    rtl812xSetPhyMedium(tp, tp->autoneg, tp->speed, tp->duplex, tp->advertising);
    
    IOLog("Link down on en%u\n", netif->getUnitNumber());
}

void RTL8125::timerActionRTL8125(IOTimerEventSource *timer)
{
    struct rtl8125_private *tp = &linuxData;
    UInt64 now;
    
    clock_get_uptime(&now);

#ifdef DEBUG_INTR
    UInt32 rxIntr = etherStats->dot3RxExtraEntry.interrupts - lastRxIntrupts;
    UInt32 txIntr = etherStats->dot3TxExtraEntry.interrupts - lastTxIntrupts;
    UInt32 tmrIntr = tmrInterrupts - lastTmrIntrupts;

    lastRxIntrupts = etherStats->dot3RxExtraEntry.interrupts;
    lastTxIntrupts = etherStats->dot3TxExtraEntry.interrupts;
    lastTmrIntrupts = tmrInterrupts;
    
    IOLog("rxIntr/s: %u, txIntr/s: %u, timerIntr/s: %u\n", rxIntr, txIntr, tmrIntr);
#endif
    
    if (!test_bit(__LINK_UP, &stateFlags))
        goto done;

    rtl812xDumpTallyCounter(tp);

    /* Round 14: refresh the RX posted-buffer baseline and publish it.
     *
     * WHY THE BASELINE IS RE-CAPTURED HERE AND NOT ONLY AT INIT
     * --------------------------------------------------------
     * The probe needs a baseline that is as close as possible to the moment
     * the window opens. A baseline captured at init() is minutes old by then,
     * and the ring has been re-posted many times. Re-capturing once a second
     * keeps the gap small; the rearm log covers whatever the gap still is,
     * which is why the two halves are joined on a watermark rather than on
     * time.
     *
     * WHY THIS IS SAFE ON THE WATCHDOG
     * --------------------------------
     * The watchdog is NOT assumed to be serialised with the RX path. The
     * capture only reads descriptor memory, the RX path only writes it, and
     * the read is a bounded retry pair -- see RTL812xRxPost.hpp. No lock is
     * taken here, so this cannot stall a packet path. */
    rxpostCaptureBaseline();
    rxpostPublish();

    /* Round 10: refresh the published observation log once per watchdog tick
     * (kTimerPeriod = 1 s). This is a PERIODIC refresh, not a barrier: the
     * snapshot a reader gets is the one that existed when it read the
     * property, and the header records tPublished so the reader can decide
     * for itself whether that snapshot covers the range it needs. Round 9
     * relied on "no more than a second old" and that is exactly what failed:
     * its snapshot was 0.53 s OLDER than the window end, so the window's last
     * half second was never in it. obsPublish() is a bounded memcpy plus one
     * property set; it does not touch the device.
     *
     * obsForcePublish lets a reader ask for a fresher snapshot than the last
     * tick produced, without that reader ever running the copy itself. */
    if (obsForcePublish) {
        obsForcePublish = false;
    }
    obsPublish();
    thread_call_enter_delayed(statCall, statDelay);

    /* Check for tx deadlock. */
    if (txHangCheck())
        goto done;
    
    timerSource->wakeAtTime(now +timerInterval);

done:
    txDescDoneLast = txDescDoneCount;
    
}

#pragma mark --- round 10 observation log (wire version 2) ---

/* Allocate the log. Returns false when the buffer could not be created, in
 * which case every obsWrite() is a no-op and obsPublish() says so. */
bool RTL8125::obsInit()
{
    obsRegion = NULL;
    obsHdr = NULL;
    obsRecs = NULL;
    obsTxBatch = 0;
    obsRxReaped = 0;
    obsWrapped = 0;
    obsDropped = 0;
    obsPubId = 0;
    obsBusDevFn = 0;
    obsVendorId = 0;
    obsDeviceId = 0;
    obsIfUnit = 0;
    obsMacHi = 0;
    obsMacLo = 0;

    /* Epoch: seconds since boot at the moment this instance allocated the
     * log. A reader compares it against the snapshot's own value, so a
     * snapshot taken before a driver reload cannot be mistaken for one taken
     * after it. */
    obsForcePublish = false;
    obsLock = 0;
    {
        UInt64 ns = mach_absolute_time();
        obsEpoch = (UInt32)(ns / 1000000000ULL);
    }

    /* Device identity, taken from the IOPCIDevice this driver was matched
     * against and from the MAC the hardware is actually using. A snapshot
     * whose identity does not match the device under test is refused by the
     * reader instead of being silently attributed to it. */
    if (pciDevice) {
        UInt32 vd = pciDevice->configRead32(0);
        obsVendorId = vd & 0xFFFFu;
        obsDeviceId = (vd >> 16) & 0xFFFFu;
        UInt8 bus = pciDevice->getBusNumber() & 0xFFu;
        UInt8 dev = pciDevice->getDeviceNumber() & 0x1Fu;
        UInt8 fn  = pciDevice->getFunctionNumber() & 0x7u;
        obsBusDevFn = ((UInt32)bus << 8) | ((UInt32)dev << 3) | (UInt32)fn;
    }
    /* 【为什么 ifUnit 不能在 obsInit() 里定】
     *
     *   start() 里的顺序是：
     *       setupStatResources()  ->  obsInit()  ->  initEventSources()
     *       ->  attachInterface(&netif)
     *
     *   也就是说 obsInit() 运行时 netif 还是 NULL，取到的是 unit 0。
     *   第一版实机验证就是这样失败的：驱动快照头部写着 ifUnit = 0，
     *   而探针从 IORegistry 独立读到的是 2，身份核对报
     *   interface-unit-mismatch，整轮降级。
     *
     *   所以 ifUnit 改为在 obsPublish() 里现取（那时 attachInterface 早已
     *   完成），并且不只信 netif：先试 netif，再退回读父节点的
     *   IOInterfaceUnit 属性。两者都没有就留 0 并让读者判为不匹配——
     *   绝不猜一个看起来合理的数字。
     */
    obsIfUnit = 0;
    {
        /* getHardwareAddress() returns currMacAddr, i.e. the address the
         * hardware is actually using -- not the EEPROM default. That is the
         * one an operator can compare against ifconfig. */
        IOEthernetAddress ea;
        bzero(&ea, sizeof(ea));
        if (getHardwareAddress(&ea) == kIOReturnSuccess) {
            obsPackMac(ea.bytes, &obsMacHi, &obsMacLo);
        }
    }

    obsRegion = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
        kernel_task,
        (kIODirectionOut | kIOMemoryPhysicallyContiguous |
         kIOMemoryHostPhysicallyContiguous),
        kObsRegionBytes,
        0xFFFFFFFFFFFFFF00ULL);

    if (!obsRegion) {
        IOLog("obsInit(): could not allocate the observation log.\n");
        return false;
    }
    if (obsRegion->prepare() != kIOReturnSuccess) {
        IOLog("obsInit(): prepare() failed.\n");
        obsRegion->release();
        obsRegion = NULL;
        return false;
    }
    obsHdr = (RtlObsHdr *)obsRegion->getBytesNoCopy();
    if (!obsHdr) {
        obsRegion->complete();
        obsRegion->release();
        obsRegion = NULL;
        return false;
    }
    bzero(obsHdr, (size_t)kObsRegionBytes);
    obsHdr->magic = kObsMagic;
    obsHdr->version = kObsVersion;
    obsHdr->recSize = kObsRecBytes;
    obsHdr->capacity = kObsCapacity;
    obsHdr->epoch = obsEpoch;
    obsHdr->tStart = mach_absolute_time();
    obsRecs = (RtlObsRec *)((UInt8 *)obsHdr + kObsHdrBytes);

    /* Publish once immediately, so a reader can tell "the log exists but is
     * empty" from "the log was never created". */
    obsPublish();
    return true;
}

void RTL8125::obsFree()
{
    if (obsRegion) {
        obsRegion->complete();
        obsRegion->release();
        obsRegion = NULL;
    }
    obsHdr = NULL;
    obsRecs = NULL;
}

/* Append one record.
 *
 * THE PROTOCOL (round 11 replaced round 10's; see RTL812xObsWrite.hpp)
 * --------------------------------------------------------------------
 * Round 10 claimed the slot with an unconditional atomic exchange and then
 * "re-checked ownership" before publishing. That re-check runs BEFORE the
 * last writer writes, so a writer whose slot was taken mid-body still
 * overwrites the new owner's fields and the new owner then stamps the
 * result. The surviving record is one writer's seq over two writers' bytes.
 * tools/r11/verify-write-protocol.py reproduces exactly that: 13 of 13 body
 * fields foreign.
 *
 * Round 11 holds a bounded spin lock across "claim ticket, claim slot, fill
 * body, publish", so the interleaving cannot occur rather than being detected
 * after the fact. The busy marker stays, because obsPublish() reads records
 * WITHOUT the lock (a ~37 KB memcpy under a spin lock would stall the output
 * thread) and needs a cheap "body in flight" signal.
 *
 * Everything here is bounded: kObsLockSpinMax retries, no sleeping, no
 * allocation. A writer that cannot take the lock increments `dropped`, which
 * reaches the published header, so a snapshot that lost records cannot
 * present itself as complete.
 */
void RTL8125::obsWrite(UInt32 kind, UInt32 cumulative, UInt32 slot, UInt32 gen,
                       UInt64 addr, UInt32 opts1, UInt32 opts2, UInt32 len,
                       UInt32 flags, UInt32 token, UInt32 reqId,
                       UInt32 flowHash, UInt32 pktFlags)
{
    if (!obsHdr || !obsRecs) return;
    /* Explicit opt-in scope BEFORE ticket claim: excluded load rows are not
     * dropped records or sequence holes. RXPOST and pool witnesses stay full. */
    if (!r15PoolObserve(kind, slot, token)) return;

    struct ObsFillCtx {
        UInt32 kind, cumulative, slot, gen;
        UInt64 addr;
        UInt32 opts1, opts2, len, flags, token, reqId, flowHash, pktFlags;
        UInt32 batch;
    } ctx;
    ctx.kind = kind;
    ctx.cumulative = cumulative;
    ctx.slot = slot;
    ctx.gen = gen;
    ctx.addr = addr;
    ctx.opts1 = opts1;
    ctx.opts2 = opts2;
    ctx.len = len;
    ctx.flags = flags;
    ctx.token = token;
    ctx.reqId = reqId;
    ctx.flowHash = flowHash;
    ctx.pktFlags = pktFlags;
    ctx.batch = obsTxBatch;

    const bool ok = obslog::writeRecord(
        &obsLock,
        (unsigned char *)obsHdr,
        (unsigned char *)obsRecs,
        kObsCapacityMask,
        [](unsigned char *rec, const ObsFillCtx &c) {
            RtlObsRec *r = (RtlObsRec *)rec;
            r->tMono = mach_absolute_time();
            r->addr = c.addr;
            r->kind = c.kind;
            r->cumulative = c.cumulative;
            r->slot = c.slot;
            r->gen = c.gen;
            r->batch = c.batch;
            r->opts1 = c.opts1;
            r->opts2 = c.opts2;
            r->len = c.len;
            r->flags = c.flags;
            r->token = c.token;
            r->reqId = c.reqId;
            r->flowHash = c.flowHash;
            r->pktFlags = c.pktFlags;
        },
        ctx,
        &obsDropped,
        &obsWrapped);

    if (!ok) {
        /* The loss is already in obsDropped, and obsPublish() copies it into
         * the published header's `dropped` field. Nothing else to do: a drop
         * must not be retried here, because the caller is on a packet path
         * that must not block. */
        IOLog("obsWrite(): dropped a record (lock bound exhausted).\n");
    }
}

/* Parse the business identifier out of a packet.
 *
 * Returns the kObsPkt* flags word. token/reqId/flowHash are set to 0 unless
 * kObsPktParsed is returned, so a caller can never see a half-decoded id.
 *
 * The parse is deliberately narrow: IPv4, IHL == 5, no fragmentation, no
 * VLAN, UDP, and the first four payload bytes equal kObsBizMagic. Anything
 * else is reported as "not parsed" with a reason. There is no fallback that
 * guesses an identifier from a length or a timestamp -- round 9 did exactly
 * that and it produced a claim that does not survive re-checking.
 */
UInt32 RTL8125::obsParseBiz(mbuf_t m, UInt32 len, bool isTx,
                            UInt32 *token, UInt32 *reqId, UInt32 *flowHash)
{
    *token = 0; *reqId = 0; *flowHash = 0;
    if (!m) return kObsPktShort;

    /* Bounded linearisation of the mbuf chain. Never more than
     * kObsBizScanMax bytes, never a copy into a variable-length buffer. */
    UInt8 buf[kObsBizScanMax];
    UInt32 have = 0;
    mbuf_t cur = m;
    while (cur && have < kObsBizScanMax) {
        const UInt32 segLen = (UInt32)mbuf_len(cur);
        const UInt8 *seg = (const UInt8 *)mbuf_data(cur);
        if (!seg) break;
        UInt32 take = segLen;
        if (take > kObsBizScanMax - have) take = kObsBizScanMax - have;
        memcpy(buf + have, seg, take);
        have += take;
        cur = mbuf_next(cur);
    }
    if (have < kObsBizHeaderBytes) return kObsPktShort;

    UInt32 flags = 0;
    UInt32 off = 12;                       /* after the two MACs */
    UInt16 etherType = ((UInt16)buf[off] << 8) | (UInt16)buf[off + 1];
    off += 2;
    if (etherType == 0x8100u || etherType == 0x88A8u) {
        /* VLAN tagged: the payload offset would depend on the tag stack, so
         * refuse rather than guess. */
        return kObsPktVlan;
    }
    if (etherType != 0x0800u) return kObsPktNotIpv4;

    if (have < off + 20u) return kObsPktShort;
    const UInt8 ihl = (UInt8)(buf[off] & 0x0Fu);
    const UInt16 fragField = ((UInt16)buf[off + 6] << 8) | (UInt16)buf[off + 7];
    const UInt8 proto = buf[off + 9];
    if (ihl != 5u) return kObsPktIpOptions;
    if ((fragField & 0x2000u) || (fragField & 0x1FFFu)) return kObsPktFragmented;
    if (proto != 17u) {
        /* TCP is explicitly out of scope: one write() is not one segment, so
         * an application-level id would need TCP sequence bookkeeping that
         * this driver does not have. */
        return (proto == 6u) ? kObsPktTcp : kObsPktNotUdp;
    }

    const UInt32 udpOff = off + 20u;
    if (have < udpOff + 8u) return kObsPktShort;
    const UInt16 udpLen = ((UInt16)buf[udpOff + 4] << 8) | (UInt16)buf[udpOff + 5];
    const UInt16 sport = ((UInt16)buf[udpOff] << 8) | (UInt16)buf[udpOff + 1];
    const UInt16 dport = ((UInt16)buf[udpOff + 2] << 8) | (UInt16)buf[udpOff + 3];

    const UInt32 payOff = udpOff + 8u;
    if (udpLen < 8u) return kObsPktTruncated;
    const UInt32 payLen = (UInt32)udpLen - 8u;
    if (payLen < 16u) return kObsPktShort;
    if (have < payOff + 16u) return kObsPktTruncated;

    const UInt32 magic = ((UInt32)buf[payOff] << 24) |
                         ((UInt32)buf[payOff + 1] << 16) |
                         ((UInt32)buf[payOff + 2] << 8) |
                         (UInt32)buf[payOff + 3];
    if (magic != kObsBizMagic) {
        (void)isTx;
        return kObsPktNoMagic;
    }
    const UInt32 t = ((UInt32)buf[payOff + 4] << 24) |
                      ((UInt32)buf[payOff + 5] << 16) |
                      ((UInt32)buf[payOff + 6] << 8) |
                      (UInt32)buf[payOff + 7];
    const UInt32 rq = ((UInt32)buf[payOff + 8] << 24) |
                       ((UInt32)buf[payOff + 9] << 16) |
                       ((UInt32)buf[payOff + 10] << 8) |
                       (UInt32)buf[payOff + 11];
    if (t == 0 || rq == 0) return kObsPktNoMagic;   /* 0 is never valid */

    /* Flow hash: ports plus the two IPv4 addresses, so two concurrent flows
     * with the same token are still distinguishable. */
    const UInt32 saddr = ((UInt32)buf[off + 12] << 24) |
                         ((UInt32)buf[off + 13] << 16) |
                         ((UInt32)buf[off + 14] << 8) |
                         (UInt32)buf[off + 15];
    const UInt32 daddr = ((UInt32)buf[off + 16] << 24) |
                         ((UInt32)buf[off + 17] << 16) |
                         ((UInt32)buf[off + 18] << 8) |
                         (UInt32)buf[off + 19];
    UInt32 h = 2166136261u;
    h = (h ^ (UInt32)sport) * 16777619u;
    h = (h ^ (UInt32)dport) * 16777619u;
    h = (h ^ saddr) * 16777619u;
    h = (h ^ daddr) * 16777619u;

    *token = t;
    *reqId = rq;
    *flowHash = h;
    flags |= kObsPktParsed;
    (void)len;
    return flags;
}

/* Publish one self-describing snapshot: header + records in ONE OSData.
 *
 * WHY ONE PROPERTY
 * ----------------
 * Round 9 published head/first/published/wrapped/t-published as five OSString
 * properties and the records as a sixth OSData property. Each individual
 * property write is atomic, but the six together are not, so a reader could
 * pair a header from publication N with records from publication N-1. Round
 * 9's own archive shows two different publications 87 s apart, and the report
 * used the later one as if it were the earlier one.
 *
 * Here the header travels WITH the records. There is one property to read, so
 * there is nothing to tear. `pubId` increments on every publish, so a reader
 * can also detect that two reads returned the same snapshot (or not).
 */
void RTL8125::obsPublish()
{
    if (!obsHdr || !obsRecs) {
        setProperty("rtl812x-obs-state", "unavailable");
        setProperty("rtl812x-obs-format", kObsFormat);
        return;
    }

    RtlObsHdr *snap = (RtlObsHdr *)obsSnap;
    RtlObsRec *snapRecs = (RtlObsRec *)(obsSnap + kObsHdrBytes);

    const UInt64 now = mach_absolute_time();
    /* head counts tickets ISSUED, and tickets start at 1, so the last
     * issued ticket is exactly head. */
    const UInt32 head = __atomic_load_n(&obsHdr->head, __ATOMIC_ACQUIRE);
    UInt32 n = (head < kObsPublishMax) ? head : kObsPublishMax;
    const UInt32 firstTicket = head - n + 1u;   /* ticket of the first copied */

    UInt32 copied = 0, lost = 0;
    UInt32 lastTicket = firstTicket;   /* overwritten by the last good copy */
    /* Round 11: the copy itself lives in RTL812xObsWrite.hpp, so the host test
     * exercises the same code the driver runs. The publisher deliberately does
     * NOT take the write lock: a ~37 KB memcpy under a spin lock would stall
     * every writer. It relies on the busy marker plus the double read, which
     * the locked writer makes reliable. */
    obslog::publishCopy((const unsigned char *)obsRecs,
                        kObsCapacityMask,
                        kObsCapacity,
                        firstTicket,
                        n,
                        (unsigned char *)snapRecs,
                        kObsRecBytes,
                        &copied,
                        &lost);
    if (n > 0) lastTicket = firstTicket + n - 1u;

    /* Resolve the BSD unit NOW, not in obsInit(): start() calls obsInit()
     * before attachInterface(), so netif is still NULL there. */
    {
        UInt32 unit = 0;
        bool have = false;
        if (netif) {
            unit = (UInt32)netif->getUnitNumber();
            have = true;
        }
        if (!have) {
            OSNumber *u = OSDynamicCast(OSNumber,
                                        copyProperty("IOInterfaceUnit"));
            if (u) {
                unit = (UInt32)u->unsigned32BitValue();
                have = true;
                u->release();
            }
        }
        if (have) obsIfUnit = unit;
    }

    obsPubId++;

    snap->magic       = kObsMagic;
    snap->version     = kObsVersion;
    snap->recSize     = kObsRecBytes;
    snap->capacity    = kObsCapacity;
    snap->head        = head;
    snap->wrapped     = obslog::readLoss(&obsWrapped);
    snap->dropped     = obslog::readLoss(&obsDropped);
    snap->pubId       = obsPubId;
    snap->firstTicket = firstTicket;
    snap->lastTicket  = lastTicket;
    snap->validCount  = n - lost;
    snap->lostCount   = lost;
    snap->epoch       = obsEpoch;
    snap->busDevFn    = obsBusDevFn;
    snap->vendorId    = obsVendorId;
    snap->deviceId    = obsDeviceId;
    snap->ifUnit      = obsIfUnit;
    snap->macHi       = obsMacHi;
    snap->macLo       = obsMacLo;
    snap->flags       = 0;
    if (head > kObsCapacity) snap->flags |= kObsHdrFlagOverflowed;
    if (lost)                snap->flags |= kObsHdrFlagLost;
    /* Round 12: a writer that never got a ticket leaves no hole in the ticket
     * range, so the reader cannot see it from the records. It MUST reach the
     * header, or a snapshot that lost records reports itself as complete. */
    if (snap->dropped != 0)  snap->flags |= kObsHdrFlagLost;
    if (head > n)            snap->flags |= kObsHdrFlagTruncated;
    snap->tStart      = obsHdr->tStart;
    snap->tPublished  = now;
    snap->reserved    = 0;

    const UInt32 bytes = kObsHdrBytes + n * kObsRecBytes;
    OSData *blob = OSData::withBytes(obsSnap, bytes);
    if (blob) {
        setProperty("rtl812x-obs-snapshot", blob);
        blob->release();
    }

    /* Non-authoritative convenience strings. A reader MUST use the header
     * inside rtl812x-obs-snapshot; these exist only so a human looking at
     * ioreg can see the state at a glance. They are deliberately named
     * differently from v1's so a v1 reader cannot mistake them for its own. */
    setProperty("rtl812x-obs-format", kObsFormat);
    setProperty("rtl812x-obs-state",
                (lost || obslog::readLoss(&obsDropped)) ? "degraded" : "ok");
    /* Round 11: publish the instance epoch as its own property as well as in
     * the snapshot header. A reader that needs to bind to "this driver
     * instance" BEFORE it reads a snapshot (because binding from the snapshot
     * it is about to judge would be circular) needs a channel that is not the
     * snapshot. The probe reads this one at step 15c, before the window. */
    {
        OSNumber *en = OSNumber::withNumber((unsigned long long)obsEpoch, 32);
        if (en) {
            setProperty("rtl812x-obs-epoch", en);
            en->release();
        }
    }
}

/* Publish on demand. Exposed so the probe's reader can ask for a fresh
 * snapshot instead of using whatever the last watchdog tick left behind.
 *
 * BOUNDED: this only sets a flag that the next watchdog tick honours. It does
 * NOT block, does NOT wait for the tick, and does NOT call obsPublish()
 * directly from another thread's context -- doing so would run a ~37 KiB
 * memcpy on the caller's thread while the output thread is writing records,
 * and would put an unbounded delay inside the probe's measurement window.
 * The reader is expected to poll the publication id with a bounded deadline
 * and to DEGRADE if a fresh-enough snapshot does not appear. */
void RTL8125::obsPublishNow()
{
    obsForcePublish = true;
}


#pragma mark --- round 14 RX posted-buffer set ---
/* Allocate the RX posted-buffer tables and capture the first baseline.
 *
 * A failure here is NOT fatal: the NIC works without it and refusing to start
 * the interface because a diagnostic buffer could not be allocated would be
 * worse. The header's `flags` carries NO_BASELINE so the absence is visible
 * instead of being read as "the set is empty".
 */
bool RTL8125::rxpostInit()
{
    rxpostRegion = NULL;
    rxpostHdr = NULL;
    rxpostSlots[0] = rxpostSlots[1] = NULL;
    rxpostRearms = NULL;
    rxpostLock = 0;
    rxpostWrapped = 0;
    rxpostDropped = 0;
    rxpostPubId = 0;

    /* The wire constants are duplicated in RTL812xRxPost.hpp so the host test
     * can compile without the driver's headers. Assert them against the real
     * enumerators here: a drift would silently decode DescOwn as a length. */
    static_assert(kRxPostSlots == kNumRxDesc,
                  "the slot table must be exactly one record per descriptor");
    static_assert(kRxPostDescOwn == (UInt32)DescOwn,
                  "kRxPostDescOwn must be the driver's DescOwn");
    static_assert(kRxPostRingEnd == (UInt32)RingEnd,
                  "kRxPostRingEnd must be the driver's RingEnd");
    /* THE TIE THAT WOULD HAVE CAUGHT THE PANIC.
     *
     * kRxPostRegionBytes is computed from kRxPostSlotTables, so changing that
     * constant moves the size and the offset together and the header's own
     * assertions still pass. This one compares the macro against the ARRAY THE
     * DRIVER ACTUALLY DECLARES. With `rxpostSlots[2]` and a macro saying 1, the
     * region came out one slot array short and the tail of the rearm ring fell
     * outside the mapping -- a page fault on write, minutes later. */
    static_assert(sizeof(rxpostSlots) / sizeof(rxpostSlots[0]) ==
                      kRxPostSlotTables,
                  "kRxPostSlotTables must equal the number of slot arrays "
                  "the driver declares");

    rxpostRegion = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
        kernel_task,
        (kIODirectionOut | kIOMemoryPhysicallyContiguous |
         kIOMemoryHostPhysicallyContiguous),
        (vm_size_t)kRxPostRegionBytes,
        0xFFFFFFFFFFFFFF00ULL);
    if (!rxpostRegion) {
        IOLog("rxpostInit(): could not allocate the RX post tables.\n");
        return false;
    }
    if (rxpostRegion->prepare() != kIOReturnSuccess) {
        IOLog("rxpostInit(): prepare() failed.\n");
        rxpostRegion->release();
        rxpostRegion = NULL;
        return false;
    }
    rxpostHdr = (rxpost::Hdr *)rxpostRegion->getBytesNoCopy();
    if (!rxpostHdr) {
        rxpostRegion->complete();
        rxpostRegion->release();
        rxpostRegion = NULL;
        return false;
    }
    bzero(rxpostHdr, (size_t)kRxPostRegionBytes);

    rxpostSlots[0] = (UInt8 *)rxpostHdr + kRxPostHdrBytes;
    rxpostSlots[1] = rxpostSlots[0] + (UInt64)kRxPostSlots * kRxPostSlotBytes;
    rxpostRearms   = rxpostSlots[1] + (UInt64)kRxPostSlots * kRxPostSlotBytes;

    /* THE RING MUST LIE ENTIRELY INSIDE THE ALLOCATION.
     *
     * Round 14's run 5 panicked here, ~242 s in: `kRxPostRegionBytes` was
     * `kRxPostSnapshotMax`, which counts ONE slot array, while the layout above
     * places the ring after TWO. The tail of the ring therefore fell outside the
     * IOBufferMemoryDescriptor's mapping, and the fault only appeared once the
     * ring filled far enough -- which is why it survived the experiment itself
     * and killed the machine minutes later.
     *
     * The static_asserts in RTL812xRxPost.hpp now tie the macro to this layout.
     * This second check is not redundant: it compares against the buffer the
     * allocator ACTUALLY returned. If IOBufferMemoryDescriptor rounds the size
     * DOWN, or a future edit sizes the macro from a different expression than
     * the one asserted, the compile-time check still passes and this one does
     * not. A diagnostic table is never worth a panic, so on a mismatch the
     * tables are abandoned rather than used. */
    {
        const UInt8 *base = (const UInt8 *)rxpostHdr;
        const UInt64 end  = (UInt64)(rxpostRearms - base) +
                            (UInt64)kRxPostRearmCap * kRxPostRearmBytes;
        const UInt64 have = (UInt64)kRxPostRegionBytes;
        if (end > have ||
            (UInt64)(rxpostRegion->getLength()) < have) {
            IOLog("rxpostInit(): ring end %llu exceeds region %llu (have %llu);"
                  " refusing to use the tables.\\n",
                  end, have, (UInt64)rxpostRegion->getLength());
            rxpostRegion->complete();
            rxpostRegion->release();
            rxpostRegion = NULL;
            rxpostHdr = NULL;
            rxpostSlots[0] = rxpostSlots[1] = NULL;
            rxpostRearms = NULL;
            return false;
        }
    }

    rxpostHdr->magic         = kRxPostMagic;
    rxpostHdr->version       = kRxPostVersion;
    rxpostHdr->recSizeSlot   = kRxPostSlotBytes;
    rxpostHdr->recSizeRearm  = kRxPostRearmBytes;
    rxpostHdr->slotCapacity  = kRxPostSlots;
    rxpostHdr->rearmCapacity = kRxPostRearmCap;
    rxpostHdr->rxBufferSize  = (UInt32)kRxBufferSize;
    rxpostHdr->ringGen       = 1;
    rxpostHdr->epoch         = obsEpoch;
    rxpostHdr->flags         = kRxPostHdrFlagNoBaseline;

    /* Capture once immediately, so a reader can tell "the tables exist but the
     * ring was not ready" from "the tables were never created". */
    rxpostCaptureBaseline();
    rxpostPublish();
    return true;
}

void RTL8125::rxpostFree()
{
    if (rxpostRegion) {
        rxpostRegion->complete();
        rxpostRegion->release();
        rxpostRegion = NULL;
    }
    rxpostHdr = NULL;
    rxpostSlots[0] = rxpostSlots[1] = NULL;
    rxpostRearms = NULL;
}

/* Bump the ring generation. Called from EVERY path that rewrites descriptor
 * addresses, because a baseline captured under the old generation describes
 * buffers that are no longer posted. A reader requires the generation to
 * match, so this turns "the ring was rebuilt" into an explicit invalidation
 * rather than a silent mis-join. */
void RTL8125::rxpostBumpGen()
{
    r15PoolInvalidate();
    if (!rxpostHdr) return;
    __atomic_fetch_add(&rxpostHdr->ringGen, 1u, __ATOMIC_RELAXED);
    /* The baseline is now known-stale. The next capture replaces it; until
     * then the header says so instead of describing the old ring. */
    __atomic_store_n(&rxpostHdr->baselineSlots, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->flags,
                     __atomic_load_n(&rxpostHdr->flags, __ATOMIC_RELAXED) |
                         kRxPostHdrFlagNoBaseline,
                     __ATOMIC_RELAXED);
}

/* Capture the baseline: every descriptor's posted address and capacity.
 *
 * WHY THE WATERMARK IS READ FIRST
 * -------------------------------
 * See RTL812xRxPost.hpp rule 1. Reading it after the scan would let a rearm
 * that happened DURING the scan be excluded from the required set while also
 * being invisible in the scan, and the address it replaced would then be in
 * neither half.
 *
 * WHY A BOUNDED RETRY PER SLOT
 * ----------------------------
 * The RX path writes `buf.addr` then `buf.blen`. A reader that takes `blen`,
 * then `addr`, then `blen` again and sees the same `blen` twice has either a
 * consistent pair or an `addr` that is NEWER than the length -- and "newer
 * address with an older length word" describes the buffer being posted right
 * now, which is conservative for a set that must be a superset. The retry
 * exists to catch the case where `blen` changed, and a pair that never
 * stabilises is counted (`baselineTorn`) rather than published as if it were
 * read cleanly.
 *
 * WHY IT IS SAFE TO CALL FROM THE WATCHDOG
 * ----------------------------------------
 * The watchdog is not assumed to be serialised with the RX path -- that
 * assumption is exactly what this round refuses to make. The scan only READS
 * descriptor memory, and the RX path only WRITES it, so there is no ordering
 * requirement beyond the bounded retry above. The two slot arrays mean a
 * publish that is copying one array cannot see a capture writing it.
 */
void RTL8125::rxpostCaptureBaseline()
{
    if (!rxpostHdr || !rxpostSlots[0] || !rxDescArray || !rxBufArray) return;

    /* Rule 1: the watermark BEFORE the scan. */
    const UInt32 headBefore =
        __atomic_load_n(&rxpostHdr->head, __ATOMIC_ACQUIRE);
    const UInt32 genBefore =
        __atomic_load_n(&rxpostHdr->ringGen, __ATOMIC_RELAXED);

    /* The capture always writes the array the publisher is NOT reading, then
     * flips `baselineActive`. That flip is the only cross-context write the
     * capture makes, so a publish that is copying one array can never see a
     * capture writing it. */
    const UInt32 useIdx =
        __atomic_load_n(&rxpostHdr->baselineActive, __ATOMIC_RELAXED) ^ 1u;
    UInt8 *dst = rxpostSlots[useIdx];

    UInt32 slots = 0, valid = 0, addrZero = 0, capDesc = 0, capConst = 0;
    UInt32 capBad = 0, torn = 0;

    for (UInt32 i = 0; i < kNumRxDesc; i++) {
        const UInt64 a0 = (UInt64)rxDescArray[i].buf.addr;
        const UInt64 b0 = (UInt64)rxDescArray[i].buf.blen;
        const UInt64 b1 = (UInt64)rxDescArray[i].buf.blen;
        const UInt64 a1 = (UInt64)rxDescArray[i].buf.addr;
        const UInt64 b2 = (UInt64)rxDescArray[i].buf.blen;

        UInt64 addr = a0;
        UInt64 blen = b0;
        UInt32 extra = 0;
        if (b1 != b0 || b2 != b0) {
            /* The length word moved under the read. Take the last pair and
             * say so: a torn pair is still a POSTED buffer (the device will be
             * told about it), so dropping it would understate the set. */
            extra |= kRxPostSlotTorn;
            torn++;
            addr = a1;
            blen = b2;
        }

        rxpost::fillSlotRec(dst + (UInt64)i * kRxPostSlotBytes,
                            i, addr, blen, genBefore,
                            (UInt32)kRxBufferSize, extra);

        const rxpost::SlotRec *r =
            (const rxpost::SlotRec *)(dst + (UInt64)i * kRxPostSlotBytes);
        slots++;
        if (r->flags & kRxPostSlotAddrZero) addrZero++; else valid++;
        if (r->flags & kRxPostSlotCapFromDesc) capDesc++;
        if (r->flags & kRxPostSlotCapFromConst) capConst++;
        if (r->flags & kRxPostSlotCapMismatch) capBad++;
    }

    /* Rule 3: if the ring was rebuilt while we scanned, the scan describes two
     * different rings. Throw it away rather than publish a mixture. */
    const UInt32 genAfter =
        __atomic_load_n(&rxpostHdr->ringGen, __ATOMIC_RELAXED);
    if (genAfter != genBefore) {
        __atomic_fetch_add(&rxpostHdr->baselineGenMoved, 1u, __ATOMIC_RELAXED);
        __atomic_store_n(&rxpostHdr->baselineSlots, 0u, __ATOMIC_RELAXED);
        __atomic_store_n(&rxpostHdr->flags,
                         __atomic_load_n(&rxpostHdr->flags, __ATOMIC_RELAXED) |
                             kRxPostHdrFlagNoBaseline,
                         __ATOMIC_RELAXED);
        return;
    }

    __atomic_store_n(&rxpostHdr->baselineSlots, slots, __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->baselineValid, valid, __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->baselineAddrZero, addrZero, __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->baselineCapDesc, capDesc, __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->baselineCapConst, capConst, __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->baselineCapBad, capBad, __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->baselineTorn, torn, __ATOMIC_RELAXED);
    __atomic_fetch_add(&rxpostHdr->baselineCount, 1u, __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->rearmFirstSeq,
                     rxpost::firstSeqFor(headBefore, kRxPostRearmCap),
                     __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->rearmSeqAtBaseline, (UInt32)headBefore,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->tBaseline, mach_absolute_time(),
                     __ATOMIC_RELAXED);

    /* Flip the published index, then clear the NO_BASELINE flag. Order
     * matters: a publisher that reads the new index must find a complete
     * array behind it, and it reads the flag after the index. */
    __atomic_store_n(&rxpostHdr->baselineActive, useIdx, __ATOMIC_RELAXED);
    __atomic_store_n(&rxpostHdr->flags,
                     __atomic_load_n(&rxpostHdr->flags, __ATOMIC_RELAXED) &
                         ~(UInt32)kRxPostHdrFlagNoBaseline,
                     __ATOMIC_RELAXED);
}

/* Record one rearm: the driver is handing `slot` back to the hardware with
 * `addr` and `blenRaw` as the FINAL descriptor words, retiring `oldAddr`.
 *
 * Called from the hand-back site, i.e. where the descriptor is actually
 * re-programmed, so the values recorded are the ones the device will use. The
 * observation log's rx-done record is NOT reused: its `len` is the received
 * packet size, and substituting that for the posted capacity is precisely the
 * defect this round exists to remove.
 *
 * WHY `oldAddr` IS A PARAMETER AND NOT READ HERE
 * ----------------------------------------------
 * The caller is the only one that knows which buffer is being retired: on the
 * `replaced` path the old buffer came from `replaceOrCopyPacket`, and on the
 * non-replaced path the buffer is unchanged (old == new). Reading it here from
 * the descriptor would give the address that is being INSTALLED, which is the
 * bug this field exists to prevent.
 */
void RTL8125::rxpostRecordRearm(UInt32 slot, UInt64 addr, UInt64 oldAddr,
                                UInt64 blenRaw)
{
    if (!rxpostHdr || !rxpostRearms) return;

    struct RxPostFillCtx {
        UInt32 slot;
        UInt64 addr;
        UInt64 oldAddr;
        UInt64 blenRaw;
        UInt64 tMono;
        UInt32 extra;
    } ctx;
    ctx.slot = slot;
    ctx.addr = addr;
    ctx.oldAddr = oldAddr;
    ctx.blenRaw = blenRaw;
    ctx.tMono = mach_absolute_time();
    ctx.extra = (oldAddr != addr) ? kRxPostRearmReplaced : 0u;

    obslog::writeRecordSized(
        &rxpostLock,
        (unsigned char *)rxpostHdr,
        (unsigned char *)rxpostRearms,
        kRxPostRearmMask,
        kRxPostRearmBytes,
        kRxPostRearmSeqWord,
        [](unsigned char *rec, const RxPostFillCtx &c) {
            rxpost::fillRearmRec(rec, c.slot, c.addr, c.oldAddr, c.blenRaw,
                                 c.tMono, c.extra);
        },
        ctx,
        &rxpostDropped,
        &rxpostWrapped);
}

/* Publish one self-describing blob: header, the slot array, the rearm ring. */
void RTL8125::rxpostPublish()
{
    if (!rxpostHdr || !rxpostSlots[0] || !rxpostRearms) {
        setProperty("rtl812x-rxpost-state", "unavailable");
        setProperty("rtl812x-rxpost-format", kRxPostFormat);
        return;
    }

    rxpost::Hdr *snap = (rxpost::Hdr *)rxpostSnap;
    const UInt32 head = __atomic_load_n(&rxpostHdr->head, __ATOMIC_ACQUIRE);
    const UInt32 watermark =
        __atomic_load_n(&rxpostHdr->rearmSeqAtBaseline, __ATOMIC_RELAXED);

    /* Publish the NEWEST records the budget allows, not merely the ones this
     * instance's own baseline needs.
     *
     * WHY: the probe takes its baseline BEFORE the window and reads the rearm
     * log AFTER it, so the records it requires start at ITS watermark, which is
     * older than any baseline this driver captures afterwards. Publishing only
     * "from my own watermark" would make the probe's older watermark
     * unrepresentable. Publishing the newest N lets the probe check the one
     * thing that matters -- whether the ring still holds records back to its
     * watermark -- instead of depending on when this instance last captured.
     */
    UInt32 want = head;

    /* Read the index AFTER the watermark and AFTER the head: the capture sets
     * the index last, so an index read here names an array that was complete
     * when it was flipped. */
    const UInt32 useIdx =
        __atomic_load_n(&rxpostHdr->baselineActive, __ATOMIC_RELAXED);
    const UInt8 *slotBase = rxpostSlots[useIdx & 1u];

    UInt32 published = 0;
    const UInt32 bytes = rxpost::publishCopy(
        slotBase, (const UInt8 *)rxpostRearms, head, want,
        kRxPostRearmCap, kRxPostRearmMask,
        (unsigned char *)snap, &published);

    UInt32 pubId = __atomic_load_n(&rxpostHdr->pubId, __ATOMIC_RELAXED) + 1u;
    __atomic_store_n(&rxpostHdr->pubId, pubId, __ATOMIC_RELAXED);

    /* Resolve the BSD unit now: rxpostInit() runs before attachInterface(). */
    if (netif) {
        __atomic_store_n(&rxpostHdr->ifUnit,
                         (UInt32)netif->getUnitNumber(), __ATOMIC_RELAXED);
    }

    snap->magic              = kRxPostMagic;
    snap->version            = kRxPostVersion;
    snap->recSizeSlot        = kRxPostSlotBytes;
    snap->recSizeRearm       = kRxPostRearmBytes;
    snap->head               = head;
    snap->wrapped            = obslog::readLoss(&rxpostWrapped);
    snap->dropped            = obslog::readLoss(&rxpostDropped);
    snap->slotCapacity       = kRxPostSlots;
    snap->rearmCapacity      = kRxPostRearmCap;
    snap->rearmFirstSeq      = published ? (head - published + 1u) : 0u;
    snap->ringGen            = __atomic_load_n(&rxpostHdr->ringGen,
                                               __ATOMIC_RELAXED);
    snap->baselineSlots      = __atomic_load_n(&rxpostHdr->baselineSlots,
                                               __ATOMIC_RELAXED);
    snap->baselineValid      = __atomic_load_n(&rxpostHdr->baselineValid,
                                               __ATOMIC_RELAXED);
    snap->baselineAddrZero   = __atomic_load_n(&rxpostHdr->baselineAddrZero,
                                               __ATOMIC_RELAXED);
    snap->baselineCapDesc    = __atomic_load_n(&rxpostHdr->baselineCapDesc,
                                               __ATOMIC_RELAXED);
    snap->baselineCapConst   = __atomic_load_n(&rxpostHdr->baselineCapConst,
                                               __ATOMIC_RELAXED);
    snap->baselineCapBad     = __atomic_load_n(&rxpostHdr->baselineCapBad,
                                               __ATOMIC_RELAXED);
    snap->baselineTorn       = __atomic_load_n(&rxpostHdr->baselineTorn,
                                               __ATOMIC_RELAXED);
    snap->baselineCount      = __atomic_load_n(&rxpostHdr->baselineCount,
                                               __ATOMIC_RELAXED);
    snap->baselineGenMoved   = __atomic_load_n(&rxpostHdr->baselineGenMoved,
                                               __ATOMIC_RELAXED);
    snap->pubId              = pubId;
    snap->epoch              = obsEpoch;
    snap->ifUnit             = __atomic_load_n(&rxpostHdr->ifUnit,
                                               __ATOMIC_RELAXED);
    snap->vtdPath            = __atomic_load_n(&rxpostHdr->vtdPath,
                                               __ATOMIC_RELAXED) & 1u;
    snap->rxBufferSize       = (UInt32)kRxBufferSize;
    snap->rearmRequired      = want;
    snap->rearmPublished     = published;
    snap->tBaseline          = __atomic_load_n(&rxpostHdr->tBaseline,
                                               __ATOMIC_RELAXED);
    snap->rearmSeqAtBaseline = watermark;
    snap->tPublished         = mach_absolute_time();

    snap->flags = 0;
    if (__atomic_load_n(&rxpostHdr->baselineSlots, __ATOMIC_RELAXED) == 0)
        snap->flags |= kRxPostHdrFlagNoBaseline;
    if (snap->dropped != 0 || snap->wrapped != 0)
        snap->flags |= kRxPostHdrFlagRearmLost;
    if (__atomic_load_n(&rxpostHdr->baselineGenMoved, __ATOMIC_RELAXED) != 0)
        snap->flags |= kRxPostHdrFlagGenMoved;
    /* A prefix is NOT a complete answer. Say so, in the header, where the
     * reader looks -- never only in a comment next to the copy loop. */
    if (published < want)
        snap->flags |= kRxPostHdrFlagTruncated;

    OSData *blob = OSData::withBytes(rxpostSnap, bytes);
    if (blob) {
        setProperty("rtl812x-rxpost", blob);
        blob->release();
    }
    setProperty("rtl812x-rxpost-format", kRxPostFormat);
    setProperty("rtl812x-rxpost-state",
                (snap->flags & (kRxPostHdrFlagRearmLost |
                                kRxPostHdrFlagNoBaseline |
                                kRxPostHdrFlagTruncated))
                    ? "degraded" : "ok");
}


#pragma mark --- round 15 finite owned receive allocation domain ---

struct RTL8125::R15PoolState {
    r15pool::Snapshot snap;
    mbuf_t mbufs[r15pool::kMaxEntries];
    IOBufferMemoryDescriptor *regions[r15pool::kMaxEntries];
    UInt32 slotId[r15pool::kRingCount];
    UInt32 slotWitness[r15pool::kRingCount]; // 0 = none, otherwise index + 1
    UInt32 keepTx[kNumTxDesc]; // atomic: output submit vs interrupt completion
    UInt32 filtered[5];       // atomic, separate from snapshot-copy memory
    UInt32 physicalAttempts;
    UInt32 physicalFailures[4]; // allocation, prepare, attach, span
};

/* Verify the WHOLE device-writable span, not merely the first physical byte.
 * A single mbuf is not a promise of physical contiguity. Walk every physical
 * page transition plus the final byte, and reject rather than guess. */
static bool r15PhysicalSpan(mbuf_t m, UInt64 *base)
{
    if (!m || mbuf_next(m) || !mbuf_datastart(m) ||
        mbuf_maxlen(m) < kRxBufferSize) return false;
    const UInt8 *start = (const UInt8 *)mbuf_datastart(m);
    const UInt64 pa = mbuf_data_to_physical((void *)start);
    if (!pa || pa + kRxBufferSize < pa) return false;
    for (UInt32 off = 0; off < kRxBufferSize; ) {
        if (mbuf_data_to_physical((void *)(start + off)) != pa + off)
            return false;
        UInt32 step = (UInt32)(PAGE_SIZE -
            ((uintptr_t)(start + off) & (PAGE_SIZE - 1)));
        off += step;
    }
    if (mbuf_data_to_physical((void *)(start + kRxBufferSize - 1)) !=
        pa + kRxBufferSize - 1) return false;
    *base = pa;
    return true;
}

/* The public attach API accepts an external buffer plus its free callback.
 * Its SDK prose recommends mbuf_alloccluster; this custom backing is verified
 * against this target's XNU m_clattach implementation, NOT claimed portable to
 * every kernel. The wrapper never escapes/copies its cluster reference. The
 * descriptor stays solely pool-owned; callback deliberately cannot release it.
 * On every rejection/teardown free the wrapper FIRST, then complete/release the
 * descriptor. Never feed this arbitrary VM buffer to mbuf_data_to_physical. */
static void r15ExternalFree(caddr_t, u_int, caddr_t) {}

static void r15ReleaseOwned(mbuf_t m, IOBufferMemoryDescriptor *region)
{
    if (m) mbuf_freem_list(m);
    if (region) {
        region->complete();
        region->release();
    }
}

IOReturn RTL8125::callPlatformFunction(const OSSymbol *functionName,
    bool waitForFunction, void *param1, void *param2, void *param3, void *param4)
{
    if (functionName && functionName->isEqualTo(r17tx::kFunctionName)) {
        if (!param1 || param2 || param3 || param4 || !commandGate)
            return kIOReturnBadArgument;
        return commandGate->runAction(
            [](OSObject *o, void *c, void *, void *, void *) -> IOReturn {
                return ((RTL8125 *)o)->r17TxConfigure((r17tx::Configure *)c);
            }, param1);
    }
    if (!functionName || !functionName->isEqualTo(r15pool::kFunctionName))
        return super::callPlatformFunction(functionName, waitForFunction,
                                           param1, param2, param3, param4);
    if (!param1 || param2 || param3 || param4 || !commandGate)
        return kIOReturnBadArgument;
    r15pool::Request *r = (r15pool::Request *)param1;
    if (r->version != r15pool::kVersion || r->bytes != sizeof(*r))
        return kIOReturnBadArgument;
    return commandGate->runAction(r15PoolAction, r);
}

IOReturn RTL8125::r15PoolAction(OSObject *owner, void *arg0,
                              void *, void *, void *)
{
    RTL8125 *self = (RTL8125 *)owner;
    /* Gate excludes workloop interrupt/reset; __POLLING ALSO excludes the
     * independent input polling thread. Never spin/wait on that thread. */
    if (self->useAppleVTD) return kIOReturnUnsupported;
    if (test_and_set_bit(__POLLING, &self->stateFlags)) return kIOReturnBusy;
    IOReturn result = self->r15PoolControl((r15pool::Request *)arg0);
    clear_bit(__POLLING, &self->stateFlags);
    return result;
}

IOReturn RTL8125::r15PoolControl(r15pool::Request *request)
{
    if (request->op < r15pool::kPrepare || request->op > r15pool::kDisarm)
        return kIOReturnBadArgument;
    if (request->op == r15pool::kPrepare && !r15Pool) {
        if (!rxBufArray || !rxDescArray || !rxPool || !netif ||
            !test_bit(__ENABLED, &stateFlags) ||
            !test_bit(__LINK_UP, &stateFlags)) return kIOReturnNotReady;
        R15PoolState *p = (R15PoolState *)IOMallocZero(sizeof(R15PoolState));
        if (!p) return kIOReturnNoMemory;
        p->snap.version = r15pool::kVersion;
        p->snap.bytes = sizeof(p->snap);
        p->snap.generation = rxpostHdr ?
            __atomic_load_n(&rxpostHdr->ringGen, __ATOMIC_RELAXED) : 1u;
        p->snap.epoch = obsEpoch;
        p->snap.mtu = mtu;
        p->snap.bufferSize = kRxBufferSize;
        p->snap.reserved[0] = request->reserved; // immutable scope token
        for (UInt32 i = 0; i < kNumTxDesc; i++) p->keepTx[i] = 1u;
        /* Ring objects are BORROWED until the single commit below. On failure
         * free only spares, never a buffer still installed in the live ring. */
        bool valid = true;
        for (UInt32 i = 0; i < r15pool::kRingCount; i++) {
            UInt64 pa = 0;
            if (!r15PhysicalSpan(rxBufArray[i].mbuf, &pa) ||
                pa != rxBufArray[i].phyAddr ||
                pa != OSSwapLittleToHostInt64(rxDescArray[i].buf.addr)) {
                valid = false; break;
            }
            for (UInt32 j = 0; j < i; j++) {
                UInt64 other = p->snap.entries[j].addr;
                if (pa < other + kRxBufferSize && other < pa + kRxBufferSize)
                    valid = false;
            }
            if (!valid) break;
            p->mbufs[i] = rxBufArray[i].mbuf;
            p->slotId[i] = i;
            p->snap.entries[i].addr = pa;
            p->snap.entries[i].capacity = kRxBufferSize;
            p->snap.entries[i].id = i;
            p->snap.entries[i].kind = r15pool::kEntryRing;
        }
        /* Bounded high-first selection, with NO exclusion of low addresses.
         * At most 64 candidates plus one being considered are held at once;
         * at most 512 mbuf + 64 ordinary-VM descriptor attempts are made.
         * Nothing allocated here is posted before mapping authorization.
         * Descriptor allocation may block: this is gated thread-context Prepare
         * before DTE switching, never interrupt level or an OS simple lock. */
        if (valid) for (UInt32 attempt = 0; attempt < r15pool::kMaxAttempts +
                       r15pool::kExtraIOBufferAttempts; attempt++) {
            mbuf_t m = NULL;
            IOBufferMemoryDescriptor *region = NULL;
            UInt64 pa = 0;
            p->snap.allocationAttempts++;
            if (attempt < r15pool::kMaxAttempts) {
                unsigned int chunks = 1;
                if (mbuf_allocpacket(MBUF_DONTWAIT, kRxBufferSize, &chunks, &m))
                    continue;
                if (!r15PhysicalSpan(m, &pa)) {
                    mbuf_freem_list(m); continue;
                }
            } else {
                p->physicalAttempts++;
                region = IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task,
                    kIODirectionInOut | kIOMemoryMapperNone,
                    kRxBufferSize, PAGE_SIZE);
                if (!region) { p->physicalFailures[0]++; continue; }
                if (region->prepare() != kIOReturnSuccess) {
                    p->physicalFailures[1]++; region->release(); continue;
                }
                IOByteCount span = 0;
                void *bytes = region->getBytesNoCopy();
                pa = region->getPhysicalSegment(0, &span, kIOMemoryMapperNone);
                if (!bytes || region->getLength() < kRxBufferSize || !pa ||
                    pa + kRxBufferSize < pa || span < kRxBufferSize) {
                    p->physicalFailures[3]++;
                    r15ReleaseOwned(NULL, region); continue;
                }
                if (mbuf_gethdr(MBUF_DONTWAIT, MBUF_TYPE_DATA, &m) ||
                    mbuf_attachcluster(MBUF_DONTWAIT, MBUF_TYPE_DATA, &m,
                        (caddr_t)bytes, r15ExternalFree, kRxBufferSize, NULL)) {
                    p->physicalFailures[2]++;
                    r15ReleaseOwned(m, region); continue;
                }
                if (!m || mbuf_next(m) || mbuf_datastart(m) != bytes ||
                    mbuf_maxlen(m) < kRxBufferSize) {
                    p->physicalFailures[3]++;
                    r15ReleaseOwned(m, region); continue;
                }
            }
            bool overlaps = false;
            UInt32 have = r15pool::kRingCount + p->snap.spareCount;
            for (UInt32 j = 0; j < have; j++) {
                UInt64 other = p->snap.entries[j].addr;
                if (pa < other + kRxBufferSize && other < pa + kRxBufferSize)
                    overlaps = true;
            }
            if (overlaps) { r15ReleaseOwned(m, region); continue; }
            UInt32 keep = have;
            if (p->snap.spareCount == r15pool::kSpareCount) {
                keep = r15pool::kRingCount;
                for (UInt32 j = keep + 1; j < r15pool::kMaxEntries; j++)
                    if (p->snap.entries[j].addr < p->snap.entries[keep].addr)
                        keep = j;
                if (pa <= p->snap.entries[keep].addr) {
                    r15ReleaseOwned(m, region); continue;
                }
                r15ReleaseOwned(p->mbufs[keep], p->regions[keep]);
            } else p->snap.spareCount++;
            mbuf_setdata(m, mbuf_datastart(m), 0);
            p->mbufs[keep] = m;
            p->regions[keep] = region;
            p->snap.entries[keep].reserved = region ?
                r15pool::kSourceIOBuffer : r15pool::kSourceMbuf;
            p->snap.entries[keep].addr = pa;
            p->snap.entries[keep].capacity = kRxBufferSize;
            p->snap.entries[keep].kind = r15pool::kEntrySpare;
        }
        if (!valid || p->snap.spareCount != r15pool::kSpareCount) {
            for (UInt32 i = r15pool::kRingCount; i < r15pool::kMaxEntries; i++)
                r15ReleaseOwned(p->mbufs[i], p->regions[i]);
            IOFree(p, sizeof(*p));
            return valid ? kIOReturnNoMemory : kIOReturnNotAligned;
        }
        /* Highest actual physical address is the first replacement. */
        for (UInt32 i = r15pool::kRingCount; i < r15pool::kMaxEntries; i++) {
            UInt32 high = i;
            for (UInt32 j = i + 1; j < r15pool::kMaxEntries; j++)
                if (p->snap.entries[j].addr > p->snap.entries[high].addr) high = j;
            r15pool::Entry e = p->snap.entries[i];
            p->snap.entries[i] = p->snap.entries[high];
            p->snap.entries[high] = e;
            mbuf_t m = p->mbufs[i]; p->mbufs[i] = p->mbufs[high];
            p->mbufs[high] = m;
            IOBufferMemoryDescriptor *region = p->regions[i];
            p->regions[i] = p->regions[high];
            p->regions[high] = region;
            p->snap.entries[i].id = i;
            if (p->snap.entries[i].addr >= 0x400000000ULL)
                p->snap.highSpareCount++;
        }
        p->snap.entryCount = r15pool::kMaxEntries;
        p->snap.tPrepared = mach_absolute_time();
        p->snap.poolId = p->snap.tPrepared ? p->snap.tPrepared : 1;
        p->snap.state = r15pool::kPrepared;
        /* TX output runs outside the command gate/RX guard. Publish the
         * fully initialized immutable token + TX slot table with release. */
        __atomic_store_n(&r15Pool, p, __ATOMIC_RELEASE);
    }
    if (!r15Pool) return kIOReturnNotReady;
    R15PoolState *p = r15Pool;
    if (request->op != r15pool::kPrepare &&
        (request->poolId != p->snap.poolId ||
         request->expectedGeneration != p->snap.generation))
        return kIOReturnBadArgument;
    if (request->op == r15pool::kAuthorize) {
        UInt64 now = mach_absolute_time(), maxWindow = 0;
        nanoseconds_to_absolutetime(10000000000ULL, &maxWindow);
        if (p->snap.state != r15pool::kPrepared || p->snap.flags ||
            !request->mapCompletedAt || request->mapCompletedAt < p->snap.tPrepared ||
            request->mapCompletedAt > now || request->deadline <= now ||
            request->deadline - now > maxWindow ||
            !request->replaceLimit || request->replaceLimit > r15pool::kSpareCount)
            return kIOReturnBadArgument;
        p->snap.mapCompletedAt = request->mapCompletedAt;
        p->snap.deadline = request->deadline;
        p->snap.replaceLimit = request->replaceLimit;
        p->snap.tAuthorized = now;
        p->snap.rxCompletions = 0;
        __atomic_store_n(&p->snap.state, (UInt32)r15pool::kAuthorized,
                         __ATOMIC_RELEASE);
    } else if (request->op == r15pool::kDisarm) {
        __atomic_store_n(&p->snap.state, (UInt32)r15pool::kDisarmed,
                         __ATOMIC_RELEASE);
    }
    setProperty("rtl812x-r15-physical-allocation-attempts", p->physicalAttempts, 32);
    setProperty("rtl812x-r15-physical-allocation-failures", p->physicalFailures[0], 32);
    setProperty("rtl812x-r15-physical-prepare-failures", p->physicalFailures[1], 32);
    setProperty("rtl812x-r15-physical-attach-failures", p->physicalFailures[2], 32);
    setProperty("rtl812x-r15-physical-span-failures", p->physicalFailures[3], 32);
    UInt32 totalFiltered = 0;
    for (UInt32 i = 1; i < 5; i++)
        totalFiltered += __atomic_load_n(&p->filtered[i], __ATOMIC_RELAXED);
    p->snap.reserved[1] = totalFiltered;
    if (p->snap.reserved[0]) {
        setProperty("rtl812x-r15-obs-scope",
            "declared-business-only; all-rxpost-and-pool-witnesses-retained");
        setProperty("rtl812x-r15-obs-business-token", p->snap.reserved[0], 32);
        setProperty("rtl812x-r15-obs-filtered-txsubmit",
            __atomic_load_n(&p->filtered[kObsKindTxSubmit], __ATOMIC_RELAXED), 32);
        setProperty("rtl812x-r15-obs-filtered-txdone",
            __atomic_load_n(&p->filtered[kObsKindTxDone], __ATOMIC_RELAXED), 32);
        setProperty("rtl812x-r15-obs-filtered-rxdone",
            __atomic_load_n(&p->filtered[kObsKindRxDone], __ATOMIC_RELAXED), 32);
        setProperty("rtl812x-r15-obs-filtered-doorbell",
            __atomic_load_n(&p->filtered[kObsKindTxDoorbell], __ATOMIC_RELAXED), 32);
    } else setProperty("rtl812x-r15-obs-scope", "all-observation-rows");
    bcopy(&p->snap, &request->out, sizeof(request->out));
    return kIOReturnSuccess;
}

bool RTL8125::r15PoolObserve(UInt32 kind, UInt32 slot, UInt32 token)
{
    R15PoolState *p = __atomic_load_n(&r15Pool, __ATOMIC_ACQUIRE);
    if (!p || !p->snap.reserved[0]) return true;
    bool keep = true;
    if (kind == kObsKindTxSubmit) {
        keep = token == p->snap.reserved[0];
        if (slot < kNumTxDesc)
            __atomic_store_n(&p->keepTx[slot], keep ? 1u : 0u, __ATOMIC_RELEASE);
    } else if (kind == kObsKindTxDone) {
        keep = slot < kNumTxDesc &&
            __atomic_load_n(&p->keepTx[slot], __ATOMIC_ACQUIRE) != 0;
    } else if (kind == kObsKindRxDone || kind == kObsKindTxDoorbell) {
        keep = token == p->snap.reserved[0];
    }
    if (!keep && kind < 5)
        __atomic_fetch_add(&p->filtered[kind], 1u, __ATOMIC_RELAXED);
    return keep;
}

mbuf_t RTL8125::r15PoolCopy(mbuf_t packet, UInt32 length)
{
    if (!r15Pool || !length || length > kRxBufferSize) return NULL;
    mbuf_t copy = rxPool->getPacket(length, MBUF_DONTWAIT);
    if (copy && mbuf_trailingspace(copy) >= length) {
        mbuf_copy_pkthdr(copy, packet);
        mbuf_pkthdr_setheader(copy, NULL);
        bcopy(mbuf_data(packet), mbuf_data(copy), length);
        return copy;
    }
    if (copy) mbuf_freem_list(copy);
    r15Pool->snap.copyFailures++;
    r15Pool->snap.flags |= r15pool::kFlagCopyFailed;
    return NULL;
}

void RTL8125::r15PoolRearm(UInt32 slot, UInt64 oldAddr, UInt32 status,
    UInt32 length, UInt32 token, UInt32 reqId, UInt64 *addr)
{
    if (!r15Pool || slot >= r15pool::kRingCount) return;
    R15PoolState *p = r15Pool;
    UInt64 now = mach_absolute_time();
    p->snap.rxCompletions++;
    UInt32 id = p->slotId[slot];
    if (id >= p->snap.entryCount || oldAddr != p->snap.entries[id].addr ||
        rxBufArray[slot].mbuf != p->mbufs[id] ||
        oldAddr != OSSwapLittleToHostInt64(rxDescArray[slot].buf.addr)) {
        p->snap.flags |= r15pool::kFlagAddressMismatch;
        __atomic_store_n(&p->snap.state, (UInt32)r15pool::kDisarmed,
                         __ATOMIC_RELEASE);
        /* Hard domain interlock: even a detected external association change
         * must not re-post an unexported address at nextDesc. Restore a known
         * retained object, never free/dereference the unexpected foreign one. */
        UInt32 canonical = id < p->snap.entryCount ? id : slot;
        p->slotId[slot] = canonical;
        rxBufArray[slot].mbuf = p->mbufs[canonical];
        rxBufArray[slot].phyAddr = p->snap.entries[canonical].addr;
        *addr = p->snap.entries[canonical].addr;
        return;
    }
    UInt32 wi = p->slotWitness[slot];
    if (wi && wi <= p->snap.replacements) {
        r15pool::Witness *w = &p->snap.witnesses[wi - 1];
        if (!w->tDone && w->tPost && w->newAddr == oldAddr) {
            w->tDone = now;
            w->token = token; w->reqId = reqId;
            w->doneLength = length; w->doneStatus = status;
            w->flags = (status & RxRES) ? r15pool::kWitnessError :
                                         r15pool::kWitnessCompleted;
            p->snap.completions++;
        }
    }
    if (__atomic_load_n(&p->snap.state, __ATOMIC_ACQUIRE) !=
        r15pool::kAuthorized) return;
    if (now > p->snap.deadline) {
        p->snap.flags |= r15pool::kFlagExpired;
        __atomic_store_n(&p->snap.state, (UInt32)r15pool::kDisarmed,
                         __ATOMIC_RELEASE);
        return;
    }
    if ((status & RxRES) || p->snap.replacements >= p->snap.replaceLimit)
        return;
    UInt32 n = p->snap.replacements;
    UInt32 next = r15pool::kRingCount + n;
    r15pool::Witness *w = &p->snap.witnesses[n];
    w->oldAddr = oldAddr; w->newAddr = p->snap.entries[next].addr;
    w->slot = slot; w->capacity = kRxBufferSize; w->entryId = next;
    p->slotId[slot] = next;
    p->slotWitness[slot] = n + 1;
    p->snap.replacements = n + 1;
    /* Retired original stays in mbufs[] and is NEVER freed or delivered. */
    rxBufArray[slot].mbuf = p->mbufs[next];
    rxBufArray[slot].phyAddr = w->newAddr;
    *addr = w->newAddr;
}

void RTL8125::r15PoolPosted(UInt32 slot, UInt64 addr)
{
    if (!r15Pool || slot >= r15pool::kRingCount) return;
    UInt32 wi = r15Pool->slotWitness[slot];
    if (wi && wi <= r15Pool->snap.replacements) {
        r15pool::Witness *w = &r15Pool->snap.witnesses[wi - 1];
        if (!w->tPost && w->newAddr == addr) w->tPost = mach_absolute_time();
    }
}

void RTL8125::r15PoolInvalidate()
{
    if (!r15Pool) return;
    __atomic_store_n(&r15Pool->snap.state, (UInt32)r15pool::kDisarmed,
                     __ATOMIC_RELEASE);
    __atomic_fetch_add(&r15Pool->snap.generation, 1u, __ATOMIC_RELAXED);
    __atomic_fetch_or(&r15Pool->snap.flags, (UInt32)r15pool::kFlagRingReset,
                      __ATOMIC_RELAXED);
}

void RTL8125::r15PoolFree()
{
    if (!r15Pool) return;
    /* Called from freeRxResources AFTER interface detach/RX shutdown, never
     * from Disarm. Ring entries are aliases, so null them before freeing the
     * single owning array to prevent the upstream cleanup freeing them twice. */
    if (rxBufArray) for (UInt32 i = 0; i < r15pool::kRingCount; i++) {
        rxBufArray[i].mbuf = NULL;
        rxBufArray[i].phyAddr = 0;
    }
    for (UInt32 i = 0; i < r15Pool->snap.entryCount; i++)
        r15ReleaseOwned(r15Pool->mbufs[i], r15Pool->regions[i]);
    IOFree(r15Pool, sizeof(*r15Pool));
    r15Pool = NULL;
}


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
        c->held = r17TxLiveGens();
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
        return r17TxStdRollback(p, g, m, cmd->complete(true, false));
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

/* The single rollback exit for "the standard map was published, then found
 * unusable". Only the unmap result decides what happens next:
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
bool RTL8125::r17TxStdRollback(R17TxState *p, R17Gen *g, mbuf_t m,
                               IOReturn unmap)
{
    g->stdW.completeResult = (UInt32)unmap;
    g->stdW.tCompleteBegin = g->stdW.tCompleteBegin ? g->stdW.tCompleteBegin
                                                    : mach_absolute_time();
    g->stdW.tCompleteEnd = mach_absolute_time();
    if (g->stdCmd) g->stdCmd->clearMemoryDescriptor();
    if (unmap == kIOReturnSuccess) {
        if (g->stdCmd) { g->stdCmd->release(); g->stdCmd = nullptr; }
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
        /* complete() is what makes IOKit call iovmUnmapMemory(); the driver
         * never invokes the mapper itself. Note the contract cost: complete()
         * drops the command's own bookkeeping even when the unmap fails, so a
         * failed unmap cannot be retried -- it is reported as pinned. */
        g->stdW.tCompleteBegin = mach_absolute_time();
        result = g->stdCmd ? g->stdCmd->complete(true, false) : kIOReturnNotReady;
        g->stdW.tCompleteEnd = mach_absolute_time();
        g->stdW.completeResult = (UInt32)result;
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
            if (g->stdCmd) { g->stdCmd->clearMemoryDescriptor();
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
        if (p->stdMode) {
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

#pragma mark --- statistics update methods ---

void RTL8125::rtl812xDumpTallyCounter(struct rtl8125_private *tp)
{
    UInt32 cmd;

    RTL_W32(tp, CounterAddrHigh, (statPhyAddr >> 32));
    cmd = statPhyAddr & 0x00000000ffffffff;
    RTL_W32(tp, CounterAddrLow, cmd);
    RTL_W32(tp, CounterAddrLow, cmd | CounterDump);
}

void RTL8125::runStatUpdateThread(thread_call_param_t param0)
{
    ((RTL8125 *) param0)->statUpdateThread();
}

void RTL8125::statUpdateThread()
{
    struct rtl8125_private *tp = &linuxData;
    UInt32 sgColl, mlColl;

    if (!(RTL_R32(tp, CounterAddrLow) & CounterDump)) {
        netStats->inputPackets = OSSwapLittleToHostInt64(statData->rxPackets) & 0x00000000ffffffff;
        netStats->inputErrors = OSSwapLittleToHostInt32(statData->rxErrors);
        netStats->outputPackets = OSSwapLittleToHostInt64(statData->txPackets) & 0x00000000ffffffff;
        netStats->outputErrors = OSSwapLittleToHostInt32(statData->txErrors);
        
        sgColl = OSSwapLittleToHostInt32(statData->txOneCollision);
        mlColl = OSSwapLittleToHostInt32(statData->txMultiCollision);
        netStats->collisions = sgColl + mlColl;
        
        etherStats->dot3StatsEntry.singleCollisionFrames = sgColl;
        etherStats->dot3StatsEntry.multipleCollisionFrames = mlColl;
        etherStats->dot3StatsEntry.alignmentErrors = OSSwapLittleToHostInt16(statData->alignErrors);
        etherStats->dot3StatsEntry.missedFrames = OSSwapLittleToHostInt16(statData->rxMissed);
        etherStats->dot3TxExtraEntry.underruns = OSSwapLittleToHostInt16(statData->txUnderun);
        
        etherStats->dot3RxExtraEntry.frameTooShorts = OSSwapLittleToHostInt32(statData->rxRunt);
        etherStats->dot3RxExtraEntry.overruns = OSSwapLittleToHostInt32(statData->rxMacMissed);
        etherStats->dot3RxExtraEntry.resourceErrors = OSSwapLittleToHostInt32(statData->rxMacError);
    }
}

UInt32 RTL8125::getTemperature()
{
    UInt32 value;
    
    if (hasSensor)
        commandGate->runAction(readThermalSensor, &value);
    else
        value = kInvalidTemp;
    
    return value;
}

void RTL8125::getHwStatistics(RtlStatData *hwStats)
{
    if (statData && hwStats) {
        hwStats->txPackets = OSSwapLittleToHostInt64(statData->txPackets);
        hwStats->rxPackets = OSSwapLittleToHostInt64(statData->rxPackets);
        hwStats->txErrors = OSSwapLittleToHostInt64(statData->txErrors);
        hwStats->rxErrors = OSSwapLittleToHostInt32(statData->rxErrors);
        hwStats->rxMissed = OSSwapLittleToHostInt16(statData->rxMissed);
        hwStats->alignErrors = OSSwapLittleToHostInt16(statData->alignErrors);
        hwStats->txOneCollision = OSSwapLittleToHostInt32(statData->txOneCollision);
        hwStats->txMultiCollision = OSSwapLittleToHostInt32(statData->txMultiCollision);
        hwStats->rxUnicast = OSSwapLittleToHostInt64(statData->rxUnicast);
        hwStats->rxBroadcast = OSSwapLittleToHostInt64(statData->rxBroadcast);
        hwStats->rxMulticast = OSSwapLittleToHostInt32(statData->rxMulticast);
        hwStats->txAborted = OSSwapLittleToHostInt16(statData->txAborted);
        hwStats->txUnderun = OSSwapLittleToHostInt16(statData->txUnderun);
        hwStats->txOctets = OSSwapLittleToHostInt64(statData->txOctets);
        hwStats->rxOctets = OSSwapLittleToHostInt64(statData->rxOctets);
        hwStats->rxMulticast64 = OSSwapLittleToHostInt64(statData->rxMulticast64);
        hwStats->txUnicast64 = OSSwapLittleToHostInt64(statData->txUnicast64);
        hwStats->txBroadcast64 = OSSwapLittleToHostInt64(statData->txBroadcast64);
        hwStats->txMulticast64 = OSSwapLittleToHostInt64(statData->txMulticast64);
        hwStats->txPauseOn = OSSwapLittleToHostInt32(statData->txPauseOn);
        hwStats->txPauseOff = OSSwapLittleToHostInt32(statData->txPauseOff);
        hwStats->txPauseAll = OSSwapLittleToHostInt32(statData->txPauseAll);
        hwStats->txDeferred = OSSwapLittleToHostInt32(statData->txDeferred);
        hwStats->txLateCollision = OSSwapLittleToHostInt32(statData->txLateCollision);
        hwStats->txAllCollision = OSSwapLittleToHostInt32(statData->txAllCollision);
        hwStats->txAborted32 = OSSwapLittleToHostInt32(statData->txAborted32);
        hwStats->alignErrors32 = OSSwapLittleToHostInt32(statData->alignErrors32);
        hwStats->rxFrame2Long = OSSwapLittleToHostInt32(statData->rxFrame2Long);
        hwStats->rxRunt = OSSwapLittleToHostInt32(statData->rxRunt);
        hwStats->rxPauseOn = OSSwapLittleToHostInt32(statData->rxPauseOn);
        hwStats->rxPauseOff = OSSwapLittleToHostInt32(statData->rxPauseOff);
        hwStats->rxPauseAll = OSSwapLittleToHostInt32(statData->rxPauseAll);
        hwStats->rxUnknownOpcode = OSSwapLittleToHostInt32(statData->rxUnknownOpcode);
        hwStats->rxMacError = OSSwapLittleToHostInt32(statData->rxMacError);
        hwStats->txUnderrun32 = OSSwapLittleToHostInt32(statData->txUnderrun32);
        hwStats->rxMacMissed = OSSwapLittleToHostInt32(statData->rxMacMissed);
        hwStats->rxTcamDropped = OSSwapLittleToHostInt32(statData->rxTcamDropped);
        hwStats->tdu = OSSwapLittleToHostInt32(statData->tdu);
        hwStats->rdu = OSSwapLittleToHostInt32(statData->rdu);
    }
}

#pragma mark --- miscellaneous functions ---

static inline void prepareTSO4(mbuf_t m, UInt32 *tcpOffset, UInt32 *mss)
{
    struct ip *iphdr;
    struct tcphdr *tcphdr;
    UInt16 *addr;
    int i = (int)mbuf_len(m);
    UInt32 csum32 = 6;
    UInt32 il;

    /*
     * VLAN packets have the L3 and L4 headers in the second mbuf.
     * The first one carries only the L2 header.
     */
    if (i == ETH_HLEN)
        iphdr = (struct ip *)mbuf_data(mbuf_next(m));
    else
        iphdr = (struct ip *)((UInt8 *)mbuf_data(m) + ETH_HLEN);

    addr = (UInt16 *)&iphdr->ip_src;
    
    for (i = 0; i < 4; i++) {
        csum32 += ntohs(*addr++);
        csum32 += (csum32 >> 16);
        csum32 &= 0xffff;
    }
    il = ((iphdr->ip_hl & 0x0f) << 2);
    tcphdr = (struct tcphdr *)((UInt8 *)iphdr + il);
    //DebugLog("IPv4 header length: %u\n", il);
    
    /* Fill in the pseudo header checksum for TSOv4. */
    tcphdr->th_sum = htons((UInt16)csum32);

    *tcpOffset = ETH_HLEN + il;
    
    if (*mss > MSS_MAX)
        *mss = MSS_MAX;
}

static inline void prepareTSO6(mbuf_t m, UInt32 *tcpOffset, UInt32 *mss)
{
    struct ip6_hdr *ip6Hdr;
    struct tcphdr *tcpHdr;
    int i = (int)mbuf_len(m);
    UInt32 csum32 = 6;
    
    /*
     * VLAN packets have the L3 and L4 headers in the second mbuf.
     * The first one carries only the L2 header.
     */
    if (i == ETH_HLEN)
        ip6Hdr = (struct ip6_hdr *)mbuf_data(mbuf_next(m));
    else
        ip6Hdr = (struct ip6_hdr *)((UInt8 *)mbuf_data(m) + ETH_HLEN);

    ip6Hdr->ip6_ctlun.ip6_un1.ip6_un1_plen = 0;

    for (i = 0; i < 16; i++) {
        csum32 += ntohs(ip6Hdr->ip6_src.__u6_addr.__u6_addr16[i]);
        csum32 += (csum32 >> 16);
        csum32 &= 0xffff;
    }
    tcpHdr = (struct tcphdr *)((UInt8 *)ip6Hdr + kIPv6HdrLen);
    
    /* Fill in the pseudo header checksum for TSOv6. */
    tcpHdr->th_sum = htons((UInt16)csum32);

    *tcpOffset = ETH_HLEN + kIPv6HdrLen;
    
    if (*mss > MSS_MAX)
        *mss = MSS_MAX;
}

static unsigned const ethernet_polynomial = 0x04c11db7U;

static inline u32 ether_crc(int length, unsigned char *data)
{
    int crc = -1;
    
    while(--length >= 0) {
        unsigned char current_octet = *data++;
        int bit;
        for (bit = 0; bit < 8; bit++, current_octet >>= 1) {
            crc = (crc << 1) ^
            ((crc < 0) ^ (current_octet & 1) ? ethernet_polynomial : 0);
        }
    }
    return crc;
}
