/* RTL812xEthernet.hpp -- RTL8125 driver class definition.
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

#ifndef RTL812xEthernet_hpp
#define RTL812xEthernet_hpp

#include "rtl812x_hw.h"
#include "rtl812xx.h"
#include "rtl812x_dash.h"
#include "RTL8125LucyRxPool.hpp"
/* Round 10: bounded submit/complete metadata log (v2). */
#include "RTL812xObsLog.hpp"
/* Round 11: the write/publish protocol, shared with the
 * host regression test (tests/obs-write-test.cpp). */
#include "RTL812xObsWrite.hpp"
/* Round 14: the RX posted-buffer set (baseline + rearm log),
 * shared with the host regression test
 * (tests/rxpost-test.cpp). */
#include "RTL812xRxPost.hpp"
#include "RTL812xRxPool.hpp"
#include "RTL812xTxMapNative.hpp"
#include "RTL812xTxMapStd.hpp"

#ifdef DEBUG
#define DebugLog(args...) IOLog(args)
#else
#define DebugLog(args...)
#endif

#define    RELEASE(x)    if(x){(x)->release();(x)=NULL;}

#define super IOEthernetController

enum
{
    MIDX_AUTO = 0,
    MIDX_10HD,
    MIDX_10FD,
    MIDX_100HD,
    MIDX_100FD,
    MIDX_100FDFC,
    MIDX_100FD_EEE,
    MIDX_100FDFC_EEE,
    MIDX_1000FD,
    MIDX_1000FDFC,
    MIDX_1000FD_EEE,
    MIDX_1000FDFC_EEE,
    MIDX_2500FD,
    MIDX_2500FDFC,
    MIDX_2500FD_EEE,
    MIDX_2500FDFC_EEE,
    MIDX_5000FD,
    MIDX_5000FDFC,
    MIDX_5000FD_EEE,
    MIDX_5000FDFC_EEE,
    MIDX_10000FD,
    MIDX_10000FDFC,
    MIDX_10000FD_EEE,
    MIDX_10000FDFC_EEE,
    MIDX_COUNT
};

#define MBit 1000000ULL

enum {
    kSpeed10000MBit = 10000*MBit,
    kSpeed5000MBit = 5000*MBit,
    kSpeed2500MBit = 2500*MBit,
    kSpeed1000MBit = 1000*MBit,
    kSpeed100MBit = 100*MBit,
    kSpeed10MBit = 10*MBit,
};

enum {
    kEEETypeNo = 0,
    kEEETypeYes = 1,
    kEEETypeCount
};

struct rtlMediumTable {
    IOMediumType    type;
    UInt64          spd;
    UInt32          idx;
    UInt32          speed;
    UInt32          duplex;
    UInt32          fc;
    UInt32          eee;
    UInt64          adv;
};

#define kMacHdrLen      14
#define kIPv4HdrLen     20
#define kIPv6HdrLen     40

enum RtlStateFlags {
    __ENABLED = 0,      /* driver is enabled */
    __LINK_UP = 1,      /* link is up */
    __PROMISC = 2,      /* promiscuous mode enabled */
    __M_CAST = 3,       /* multicast mode enabled */
    __POLL_MODE = 4,    /* poll mode is active */
    __POLLING = 5,      /* poll routine is polling */
};

enum RtlStateMask {
    __ENABLED_M = (1 << __ENABLED),
    __LINK_UP_M = (1 << __LINK_UP),
    __PROMISC_M = (1 << __PROMISC),
    __M_CAST_M = (1 << __M_CAST),
    __POLL_MODE_M = (1 << __POLL_MODE),
    __POLLING_M = (1 << __POLLING),
};

/* RTL8125's Rx descriptor. */
typedef union RtlRxDesc {
    struct {
        UInt32 opts1;
        UInt32 opts2;
        UInt64 addr;
    } cmd;
    struct {
        UInt64 blen;
        UInt64 addr;
    } buf;
} RtlRxDesc;

/* RTL8125's Tx descriptor. */
typedef struct RtlTxDesc {
    UInt32 opts1;
    UInt32 opts2;
    UInt64 addr;
#ifdef USE_NEW_TX_DESC
    UInt32 reserved0;
    UInt32 reserved1;
    UInt32 reserved2;
    UInt32 reserved3;
#endif  /* USE_NEW_TX_DESC */
} RtlTxDesc;

#define kTransmitQueueCapacity  1024

/* With up to 32 segments we should be on the save side. */
#define kMaxSegs 32

/* The number of descriptors must be a power of 2. */
#define kNumTxDesc    1024    /* Number of Tx descriptors */
#define kNumRxDesc    1024    /* Number of Rx descriptors */
#define kTxLastDesc    (kNumTxDesc - 1)
#define kRxLastDesc    (kNumRxDesc - 1)
#define kTxDescMask    (kNumTxDesc - 1)
#define kRxDescMask    (kNumRxDesc - 1)
#define kTxDescSize    (kNumTxDesc*sizeof(struct RtlTxDesc))
#define kRxDescSize    (kNumRxDesc*sizeof(union RtlRxDesc))
#define kRxBufArraySize (kNumRxDesc * sizeof(struct rtlRxBufferInfo))
#define kTxBufArraySize (kNumTxDesc * sizeof(mbuf_t))

/* Numbers of IOMemoryDescriptors and IORanges for tx */
#define kNumTxMemDesc       (kNumTxDesc / 2)
#define kTxMemDescMask      (kNumTxMemDesc - 1)
#define kNumTxRanges        (kNumTxDesc + kMaxSegs)
#define kTxRangeMask        kTxDescMask
#define kTxMapMemSize       sizeof(struct rtlTxMapInfo)

/* Numbers of IOMemoryDescriptors and batch size for rx */
#define kRxMemBaseShift 4
#define kNumRxMemDesc   (kNumRxDesc >> kRxMemBaseShift)
#define kRxMapMemSize   (sizeof(struct rtlRxMapInfo))
#define kRxMemBatchSize (kNumRxDesc / kNumRxMemDesc)
#define kRxMemDescMask  (kRxMemBatchSize - 1)
#define kRxMemBaseMask  ~kRxMemDescMask

/* This is the receive buffer size (must be large enough to hold a packet). */
#define kRxBufferSize   PAGE_SIZE

#define kMCFilterLimit  32
#define kMaxMtu 9000
#define kMaxPacketSize (kMaxMtu + ETH_HLEN + VLAN_HLEN + ETH_FCS_LEN)

/* statitics dump delay in ns. */
#define kStatDelayTime 1000000UL    /* 1ms */

/* RealtekRxPool capacities */
#define kRxPoolClstCap   100    /* mbufs with 4k cluster*/
#define kRxPoolMbufCap   50     /* mbufs without clusters */

/* Treshhold value to wake a stalled queue */
#define kTxQueueWakeTreshhold (kNumTxDesc / 10)

/* transmitter deadlock treshhold in seconds. */
#define kTxDeadlockTreshhold 6
#define kTxCheckTreshhold (kTxDeadlockTreshhold - 1)
#define kTimerPeriod    1000000000UL

/* MSS value position */
#define MSSShift_8125 18

/* This definitions should have been in IOPCIDevice.h. */
enum
{
    kIOPCIPMCapability = 2,
    kIOPCIPMControl = 4,
};

enum
{
    kIOPCIELinkCapability = 12,
    kIOPCIELinkControl = 16,
};

enum
{
    kIOPCIELinkCtlASPM = 0x0003,    /* ASPM Control */
    kIOPCIELinkCtlL0s = 0x0001,     /* L0s Enable */
    kIOPCIELinkCtlL1 = 0x0002,      /* L1 Enable */
    kIOPCIELinkCtlClkPM = 0x0004,   /* Clock PM Enable */
    kIOPCIELinkCtlCcc = 0x0040,     /* Common Clock Configuration */
    kIOPCIELinkCtlClkReqEn = 0x100, /* Enable clkreq */
};

enum
{
    kIOPCIELinkCapL0sSup = 0x00000400UL,
    kIOPCIELinkCapL1Sup = 0x00000800UL,
    kIOPCIELinkCapASPMCompl = 0x00400000UL,
};

enum
{
    kPowerStateOff = 0,
    kPowerStateOn,
    kPowerStateCount
};

#define kParamName "Driver Parameters"
#define kEnableL0sName "enableAspmL0s"
#define kEnableL1Name "enableAspmL1"
#define kEnableCSO6Name "enableCSO6"
#define kEnableTSO4Name "enableTSO4"
#define kEnableTSO6Name "enableTSO6"
#define kPollTime10GName "µsPollTime10G"
#define kPollTime5GName "µsPollTime5G"
#define kPollTime2GName "µsPollTime2G"
#define kDriverVersionName "Driver Version"
#define kFallbackName "fallbackMAC"
#define kNameLenght 64

extern const struct RTLChipInfo rtl_chip_info[];

/*
 * Indicates if a tx IOMemoryDescriptor is in the prepared
 * (active) or completed state (inactive).
 */
enum
{
    kIOMemoryInactive = 0,
    kIOMemoryActive = 1
};

typedef struct rtlTxMapInfo {
    UInt16 txNextMem2Use;
    UInt16 txNextMem2Free;
    SInt16 txNumFreeMem;
    IOMemoryDescriptor *txMemIO[kNumTxMemDesc];
    /*
     * Device addresses must come from a mapper-backed IODMACommand:
     * IOMemoryDescriptor::getPhysicalSegment() yields raw physical
     * addresses, which the DART rejects on Apple Silicon.
     */
    IODMACommand *txDmaCmd[kNumTxMemDesc];
    IOAddressRange txMemRange[kNumTxRanges];
    IOAddressRange txSCRange[kMaxSegs];
} rtlTxMapInfo;

typedef struct rtlRxMapInfo {
    IOMemoryDescriptor *rxMemIO[kNumRxMemDesc];
    IODMACommand *rxDmaCmd[kNumRxMemDesc];
    IOAddressRange rxMemRange[kNumRxDesc];
} rtlRxMapInfo;

typedef struct rtlRxBufferInfo {
    mbuf_t mbuf;
    IOPhysicalAddress64 phyAddr;
} rtlRxBufferInfo;



/**
 *  Known kernel versions
 */
enum KernelVersion {
    Tiger         = 8,
    Leopard       = 9,
    SnowLeopard   = 10,
    Lion          = 11,
    MountainLion  = 12,
    Mavericks     = 13,
    Yosemite      = 14,
    ElCapitan     = 15,
    Sierra        = 16,
    HighSierra    = 17,
    Mojave        = 18,
    Catalina      = 19,
    BigSur        = 20,
    Monterey      = 21,
    Ventura       = 22,
    Sonoma        = 23,
    Sequoia       = 24,
    Tahoe         = 25,
};

/**
 *  Kernel version major
 */
extern const int version_major;

class RTL8125 : public super
{
    
    OSDeclareDefaultStructors(RTL8125)
    
public:
    /* IOService (or its superclass) methods. */
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;
    virtual bool init(OSDictionary *properties) override;
    virtual void free() override;
    virtual IOReturn callPlatformFunction(const OSSymbol *functionName,
        bool waitForFunction, void *param1, void *param2,
        void *param3, void *param4) override;
    
    /* Power Management Support */
    virtual IOReturn registerWithPolicyMaker(IOService *policyMaker) override;
    virtual IOReturn setPowerState(unsigned long powerStateOrdinal, IOService *policyMaker ) override;
    virtual void systemWillShutdown(IOOptionBits specifier) override;

    /* IONetworkController methods. */
    virtual IOReturn enable(IONetworkInterface *netif) override;
    virtual IOReturn disable(IONetworkInterface *netif) override;
    
    virtual IOReturn outputStart(IONetworkInterface *interface, IOOptionBits options ) override;
    virtual IOReturn setInputPacketPollingEnable(IONetworkInterface *interface, bool enabled) override;
    virtual void pollInputPackets(IONetworkInterface *interface, uint32_t maxCount, IOMbufQueue *pollQueue, void *context) override;
    
    virtual void getPacketBufferConstraints(IOPacketBufferConstraints *constraints) const override;
    
    virtual IOOutputQueue* createOutputQueue() override;
    
    virtual const OSString* newVendorString() const override;
    virtual const OSString* newModelString() const override;
    
    virtual IOReturn selectMedium(const IONetworkMedium *medium) override;
    virtual bool configureInterface(IONetworkInterface *interface) override;
    
    virtual bool createWorkLoop() override;
    virtual IOWorkLoop* getWorkLoop() const override;
    
    /* Methods inherited from IOEthernetController. */
    virtual IOReturn getHardwareAddress(IOEthernetAddress *addr) override;
    virtual IOReturn setHardwareAddress(const IOEthernetAddress *addr) override;
    virtual IOReturn setPromiscuousMode(bool active) override;
    virtual IOReturn setMulticastMode(bool active) override;
    virtual IOReturn setMulticastList(IOEthernetAddress *addrs, UInt32 count) override;
    virtual IOReturn getChecksumSupport(UInt32 *checksumMask, UInt32 checksumFamily, bool isOutput) override;
    virtual IOReturn setWakeOnMagicPacket(bool active) override;
    virtual IOReturn getPacketFilters(const OSSymbol *group, UInt32 *filters) const override;
    
    virtual UInt32 getFeatures() const override;
    virtual IOReturn getMaxPacketSize(UInt32 * maxSize) const override;
    virtual IOReturn setMaxPacketSize(UInt32 maxSize) override;
    
    virtual IOReturn newUserClient(task_t task, void *securityID, UInt32 type, IOUserClient **handler) override;
    UInt32 getTemperature();
    void getHwStatistics(RtlStatData *hwStats);
    
private:
    bool initPCIConfigSpace(IOPCIDevice *provider);
    void setupASPM(IOPCIDevice *provider, bool allowL0s, bool allowL1);
    void getParams();
    bool setupMediumDict();
    bool initEventSources(IOService *provider);
    
    static IOReturn setPowerStateWakeAction(OSObject *owner, void *arg1, void *arg2, void *arg3, void *arg4);
    static IOReturn setPowerStateSleepAction(OSObject *owner, void *arg1, void *arg2, void *arg3, void *arg4);

    void interruptOccurred(OSObject *client, IOInterruptEventSource *src, int count);
    UInt32 rxInterrupt(IONetworkInterface *interface, uint32_t maxCount, IOMbufQueue *pollQueue, void *context);
    void txInterrupt();

    bool setupRxResources();
    bool setupTxResources();
    bool setupStatResources();
    void freeRxResources();
    void freeTxResources();
    void freeStatResources();
    
    static IOReturn refillAction(OSObject *owner, void *arg1, void *arg2, void *arg3, void *arg4);

    void clearRxTxRings();
    void discardPacketFragment();
    void rtl812xCheckLinkStatus(struct rtl8125_private *tp);
    void setLinkUp();
    void setLinkDown();
    bool txHangCheck();

    /* Hardware initialization methods. */
    bool rtl812xIdentifyChip(struct rtl8125_private *tp);
    bool rtl812xInit();
    void initMacAddr(struct rtl8125_private *tp);
    void rtl812xEnable();
    void rtl812xDisable();
    void rtl812xHwInit(struct rtl8125_private *tp);
    void rtl812xHwConfig(struct rtl8125_private *tp);
    void rtl812xSetMrrs(struct rtl8125_private *tp, UInt8 setting);
    void rtl812xSetOffloadFeatures(bool active);
    void rtl812xRestart();
    void rtl812xSetPhyMedium(struct rtl8125_private *tp, UInt8 autoneg, UInt32 speed, UInt8 duplex, UInt64 adv);
    void rtl812xMedium2Adv(struct rtl8125_private *tp, UInt32 index);
    void rtl812xGetEEEMode(struct rtl8125_private *tp);
    void rtl812xLinkDownPatch(struct rtl8125_private *tp);
    void rtl812xLinkOnPatch(struct rtl8125_private *tp);
    UInt32 rtl812xGetHwCloPtr(struct rtl8125_private *tp);
    void rtl812xDoorbell(struct rtl8125_private *tp, UInt32 txTailPtr);
    static IOReturn readThermalSensor(OSObject *owner, void *arg1, void *arg2, void *arg3, void *arg4);

    void rtl812xDumpTallyCounter(struct rtl8125_private *tp);
    static void runStatUpdateThread(thread_call_param_t param0);
    void statUpdateThread();

    /* Descriptor related methods. */
    void getChecksumResult(mbuf_t m, UInt32 status1, UInt32 status2);
    
    /* AppleVTD support methods*/
    bool setupRxMap();
    void freeRxMap();
    bool setupTxMap();
    void freeTxMap();

    void    interruptOccurredVTD(OSObject *client, IOInterruptEventSource *src, int count);
    UInt32  rxInterruptVTD(IONetworkInterface *interface, uint32_t maxCount,
                           IOMbufQueue *pollQueue, void *context);
    UInt32  txMapPacket(mbuf_t packet, IOPhysicalSegment *vector, UInt32 maxSegs);
    void    txUnmapPacket();
    UInt16  rxMapBuffers(UInt16 index, UInt16 count);

    /* Watchdog timer method. */
    void timerActionRTL8125(IOTimerEventSource *timer);

private:
    IOWorkLoop *workLoop;
    IOCommandGate *commandGate;
    IOPCIDevice *pciDevice;
    OSDictionary *mediumDict;
    IONetworkMedium *mediumTable[MIDX_COUNT];
    IOBasicOutputQueue *txQueue;
    
    IOInterruptEventSource *interruptSource;
    IOTimerEventSource *timerSource;
    IOEthernetInterface *netif;
    IOMemoryMap *baseMap;
    IOMapper *mapper;
    
    /* transmitter data */
    IOBufferMemoryDescriptor *txBufDesc;
    IOPhysicalAddress64 txPhyAddr;
    IODMACommand *txDescDmaCmd;
    struct RtlTxDesc *txDescArray;
    IOMbufNaturalMemoryCursor *txMbufCursor;
    mbuf_t *txMbufArray;
    void *txBufArrayMem;
    rtlTxMapInfo *txMapInfo;
    void *txMapMem;
    UInt64 txDescDoneCount;
    UInt64 txDescDoneLast;
    UInt32 txNextDescIndex;
    UInt32 txDirtyDescIndex;
    UInt32 txTailPtr0;
    UInt32 txClosePtr0;
    SInt32 txNumFreeDesc;

    /* receiver data */
    IOBufferMemoryDescriptor *rxBufDesc;
    IOPhysicalAddress64 rxPhyAddr;
    IODMACommand *rxDescDmaCmd;
    RtlRxDesc *rxDescArray;
    rtlRxBufferInfo *rxBufArray;
    void *rxBufArrayMem;
    void *rxMapMem;
    rtlRxMapInfo *rxMapInfo;
    RTL8125LucyRxPool *rxPool;
    UInt64 multicastFilter;
    mbuf_t rxPacketHead;
    mbuf_t rxPacketTail;
    SInt32 rxPacketSize;
    UInt16 rxNextDescIndex;
    UInt16 rxMapNextIndex;

    /* power management data */
    unsigned long powerState;
    IOByteCount pcieCapOffset;
    IOByteCount pciPMCtrlOffset;

    /* statistics data */
    UInt32 deadlockWarn;
    IONetworkStats *netStats;
    IOEthernetStats *etherStats;
    IOBufferMemoryDescriptor *statBufDesc;
    IOPhysicalAddress64 statPhyAddr;
    IODMACommand *statDescDmaCmd;
    thread_call_t statCall;
    struct RtlStatData *statData;

    UInt32 mtu;
    struct pci_dev pciDeviceData;
    struct rtl8125_private linuxData;
    const struct RtlChipInfo *rtlChipInfos;
    struct IOEthernetAddress currMacAddr;
    struct IOEthernetAddress origMacAddr;
    struct IOEthernetAddress fallBackMacAddr;
    IONetworkPacketPollingParameters pollParms;

    UInt32 intrMask;
    UInt32 intrMaskRxTx;
    UInt32 intrMaskTimer;
    UInt32 intrMaskPoll;

    /* poll intervals in ns */
    UInt64 pollTime10G;
    UInt64 pollTime5G;
    UInt64 pollTime2G;
    UInt64 statDelay;
    UInt64 timerInterval;

    /* flags */
    UInt32 stateFlags;
    
    bool wolCapable;
    bool enableTSO4;
    bool enableTSO6;
    bool useAppleVTD;
    bool hasSensor;

    /* Round 10: the submit/complete observation log (wire version 2).
     *
     * This is the driver's own live memory object. The probe never maps it by
     * physical address: obsPublish() copies a suffix of it into an IORegistry
     * property, so a reader receives bytes the driver copied out of an object
     * it still holds.
     *
     * `obsSnap` is the staging buffer for one publication: it holds the
     * header FOLLOWED BY the records, and is published as a single OSData.
     * That is what makes header and records one immutable snapshot instead
     * of six properties that can tear against each other.
     */
    IOBufferMemoryDescriptor *obsRegion;
    RtlObsHdr *obsHdr;
    RtlObsRec *obsRecs;
    /* Publication staging: kObsHdrBytes + kObsPublishMax records = 36,960 B.
     * A member, not a local: that is far past the kernel stack. */
    UInt8 obsSnap[kObsSnapshotMax];
    UInt32 obsTxBatch;      /* first cumulative index of the packet being sent */
    UInt32 obsRxReaped;     /* cumulative count of reaped RX descriptors */
    UInt32 obsWrapped;      /* slots overwritten before being published */
    UInt32 obsDropped;      /* writers that lost their slot to another writer */
    UInt32 obsPubId;        /* publication counter, starts at 1 */
    UInt32 obsEpoch;        /* driver-instance epoch, seconds since boot */
    UInt32 obsBusDevFn;     /* (bus<<8)|(dev<<3)|fn of the PCI function */
    UInt32 obsVendorId;
    UInt32 obsDeviceId;
    UInt32 obsIfUnit;       /* BSD unit: 2 for en2 */
    UInt32 obsMacHi;
    UInt32 obsMacLo;
    /* Set by obsPublishNow(); honoured by the next watchdog tick. */
    volatile bool obsForcePublish;
    /* Round 11: serialises obsWrite()'s claim/fill/publish sequence. See
     * RTL812xObsWrite.hpp -- round 10 preempted a slot that another writer was
     * still filling, which produced records whose body mixed two writers. */
    volatile unsigned int obsLock;

    bool     obsInit();
    void     obsFree();
    void     obsWrite(UInt32 kind, UInt32 cumulative, UInt32 slot, UInt32 gen,
                      UInt64 addr, UInt32 opts1, UInt32 opts2, UInt32 len,
                      UInt32 flags, UInt32 token, UInt32 reqId,
                      UInt32 flowHash, UInt32 pktFlags);
    void     obsPublish();
    void     obsPublishNow();
    UInt32   obsParseBiz(mbuf_t m, UInt32 len, bool isTx,
                         UInt32 *token, UInt32 *reqId, UInt32 *flowHash);

    /* ---- Round 14: the RX posted-buffer set ---------------------------
     *
     * `rxpostRegion` holds the header, BOTH slot arrays and the rearm ring.
     * The two slot arrays are what let a capture write while a publish copies:
     * the capture fills the INACTIVE one and flips `activeBaseline`, so a
     * publish never has to take the RX path's lock and a capture never has to
     * wait for a publish to finish.
     */
    IOBufferMemoryDescriptor *rxpostRegion;
    rxpost::Hdr *rxpostHdr;
    UInt8 *rxpostSlots[2];      /* the two slot arrays inside rxpostRegion */
    UInt8 *rxpostRearms;        /* the rearm ring inside rxpostRegion     */
    UInt8 rxpostSnap[kRxPostSnapshotMax];
    volatile unsigned int rxpostLock;   /* serialises rearm writers         */
    UInt32 rxpostWrapped;
    UInt32 rxpostDropped;
    UInt32 rxpostPubId;

    bool     rxpostInit();
    void     rxpostFree();
    void     rxpostCaptureBaseline();
    void     rxpostRecordRearm(UInt32 slot, UInt64 addr, UInt64 oldAddr,
                               UInt64 blenRaw);
    void     rxpostBumpGen();
    void     rxpostPublish();

    struct R15PoolState;
    R15PoolState *r15Pool;
    static IOReturn r15PoolAction(OSObject *, void *, void *, void *, void *);
    IOReturn r15PoolControl(r15pool::Request *request);
    mbuf_t r15PoolCopy(mbuf_t packet, UInt32 length);
    void r15PoolRearm(UInt32 slot, UInt64 oldAddr, UInt32 status,
                      UInt32 length, UInt32 token, UInt32 reqId, UInt64 *addr);
    void r15PoolPosted(UInt32 slot, UInt64 addr);
    void r15PoolInvalidate();
    void r15PoolFree();
    bool r15PoolObserve(UInt32 kind, UInt32 slot, UInt32 token);

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
    bool r17TxStdRollback(R17TxState *p, R17Gen *g, mbuf_t m, IOReturn unmap);
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
    
#ifdef DEBUG_INTR
    UInt32 tmrInterrupts;
    UInt32 lastRxIntrupts;
    UInt32 lastTxIntrupts;
    UInt32 lastTmrIntrupts;
#endif
};

#endif  /* RTL812xEthernet_hpp */
