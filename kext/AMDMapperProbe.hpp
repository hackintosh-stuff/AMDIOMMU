#pragma once
#include <IOKit/IOMapper.h>
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IODMACommand.h>
#include <kern/thread.h>

class IOPCIDevice;

#include "amd_iommu_mapper_abi.hpp"

// Pure-logic core for device DMA observation (range sets, fault
// classification, descriptor decoding). Included by the host regression tests
// from the same file; see tests/dma-observe-test.cpp.
#include "amd_iommu_dma_observe.hpp"

// Round 14: construction and decoding of the RX posted-buffer set. Also
// "the probe and the host regression compile the same file"; see
// tests/rxpost-test.cpp.
#include "amd_iommu_rxset_core.hpp"
#include "../tools/lucy-obs/RTL812xRxPool.hpp"
#include "../tools/lucy-obs/RTL812xRxMap.hpp"
#include "../tools/lucy-obs/RTL812xRxNative.hpp"
#include "../tools/lucy-obs/RTL812xFixedDma.hpp"
// Round17: native-mbuf TX mapping ABI (round16's RTL812xTxMap.hpp is kept as
// the archived staging ABI and is no longer included by the probe).
#include "../tools/lucy-obs/RTL812xTxMapNative.hpp"

class IOTimerEventSource;   // forward declaration, avoids mutual header inclusion
class R27ProbeTimer;
struct R47HardwareInfo;

// The M1-B probe (B1 + B2-0 + B2-a)
//
// B1: give the IOMA of a real but non-DMA device (pci1022,1481) an
//     iommu-parent, verifying copyMapperForDevice(realDevice) returns this
//     mapper.
//
// B2-0: use **our own** IOBufferMemoryDescriptor + our own mapper to run a
//       real IODMACommand flow once, recording the arguments iovmMapMemory
//       actually receives.
//
// B2-a: actually implement the "physically contiguous single segment" identity
//       mapping and observe the success path.
//       Key constraint: *mapLength must be **exactly equal to** length.
//       Returning more than length makes IODMACommand take the multi-segment
//       branch, and that branch has at IODMACommand.cpp:946
//           assert(mapArgs.fAllocLength > mapArgs.fLength);
//       An identity mapping cannot produce a longer range; taking that branch
//       panics. Returning exactly length gives fAllocLength == fLength and the
//       multi-segment branch is skipped entirely.
//
// Explicitly not done:
//   - gSystem is not published (fIsSystem stays false)
//   - fragmented buffers are not supported (the interface cannot express them;
//     see m1b-b2-0-result.md §6)
//   - no third-party driver is modified
class org_example_AMDMapperProbe : public IOMapper {
    OSDeclareDefaultStructors(org_example_AMDMapperProbe);

protected:
    bool initHardware(IOService *provider) override;
    void free() override;

public:
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    IOReturn setProperties(OSObject *properties) override;
    IOReturn callPlatformFunction(const OSSymbol *, bool,
        void *, void *, void *, void *) override;

    uint64_t getPageSize() const override;

    IOReturn iovmMapMemory(IOMemoryDescriptor *memory,
        uint64_t descriptorOffset,
        uint64_t length,
        uint32_t mapOptions,
        const IODMAMapSpecification *mapSpecification,
        IODMACommand *dmaCommand,
        const IODMAMapPageList *pageList,
        uint64_t *mapAddress,
        uint64_t *mapLength) override;

    IOReturn iovmUnmapMemory(IOMemoryDescriptor *memory,
        IODMACommand *dmaCommand,
        uint64_t mapAddress,
        uint64_t mapLength) override;

    IOReturn iovmInsert(uint32_t options,
        uint64_t mapAddress,
        uint64_t offset,
        uint64_t physicalAddress,
        uint64_t length) override;

    uint64_t mapToPhysicalAddress(uint64_t mappedAddress) override;

private:
    IOService *fTarget;          // B1 target (IOMA)
    // Round44: a persistent per-device mapper. Ordinary IODMACommand calls
    // use this backend without the experiment's registered object bindings.
    bool fR44Auto = false;
    // R52: the root owns the hardware; auto-device instances own one mapper.
    // fR52Owner is set before start() and must survive initHardware().
    static constexpr UInt32 kR52MaxDomains = 3;
    org_example_AMDMapperProbe *fR52Owner = nullptr;
    org_example_AMDMapperProbe *fR52Mappers[kR52MaxDomains] = {};
    IOLock *fR52AttachLock = nullptr;
    UInt64 fR52SnapshotSequence = 0;
    bool fR52Stopping = false;
    // R53 explicit segment-zero requester selection; an empty list keeps R52.
    bool fR53SelectionExplicit = false;
    UInt32 fR53Requesters[kR52MaxDomains] = {};
    UInt32 fR53RequesterCount = 0;
    bool r53ReadDeviceSelection();
    IOService *fR54Offers[kR52MaxDomains] = {};  // retained by selector index
    // R69: a selected third-party client that cannot call our claim handshake
    // (Apple's own Ethernet kexts call only IOMapper::copyMapperForDevice) gets
    // its iommu-parent at first publish instead of at claim. Off by default so
    // the R54..R67 claim protocol and its analysis stay the default behaviour.
    bool fR69AutoAttach = false;
    // Capacity evidence for third-party clients; published only on change.
    UInt64 fR69MaxLength = 0, fR69MaxPages = 0, fR69MaxRuns = 0;
    UInt64 fR69PublishedMaxLength = 0, fR69PublishedMaxPages = 0,
           fR69PublishedMaxRuns = 0, fR69PublishedRejects = 0;
    // Capacity measurement: the live counters are only in the snapshot blob,
    // which is republished on prepare/PM boundaries. Mirror the ones the S3
    // measurement needs and publish them when they change, so a read never
    // has to force a snapshot from user space.
    UInt64 fR69MapOk = 0, fR69UnmapOk = 0;
    UInt32 fR69LiveMaps = 0, fR69LivePages = 0,
           fR69PeakMaps = 0, fR69PeakPages = 0;
    UInt64 fR69PublishedMapOk = ~0ULL, fR69PublishedUnmapOk = ~0ULL;
    UInt32 fR69PublishedLiveMaps = ~0U, fR69PublishedLivePages = ~0U,
           fR69PublishedPeakMaps = ~0U, fR69PublishedPeakPages = ~0U;
    UInt32 fR69RejectedLength = 0, fR69RejectedOptions = 0,
           fR69RejectedLayout = 0, fR69RejectedRecords = 0,
           fR69RejectedNoRange = 0, fR69RejectedBits = 0;
    void r69PublishCapacity();
    // S1 capacity profile (docs/m2-3az-round69-capacity-model.md). The legacy
    // entry is the default and reproduces the accepted ABI3 arena exactly; a
    // domain may only be prepared after the profile's page-table area exists.
    // R71-B: capacity is no longer chosen per device at admission. Every domain
    // is prepared at the legacy arena and may grow once, at its first mapping,
    // to the ceiling in kProfileCeiling (see r44GrowBeforeFirstMap). The boot
    // argument now names that ceiling; a device's identity table entry only
    // decides how far a third-party client may grow.
    r44mapper::Profile fR44Profile = r44mapper::kProfileLegacy;
    bool fR44ProfileForced = false;
    bool r44SelectProfile();
    const r44mapper::Profile *r44ForcedProfile() const;
    // Admission ceiling for this device: the boot-arg profile when it parses,
    // otherwise the demand default. A forced value at or below the legacy arena
    // disables growth, which keeps the R67-2 compatibility mode available.
    const r44mapper::Profile *r44Ceiling(bool &forced) const;
    const r44mapper::Profile *r44ProfileForDevice(
        UInt32 vendor, UInt32 device, UInt32 classCode,
        r44mapper::ProfileSource *source = nullptr) const;
    struct R52Domain;
    R52Domain *fR52Domain = nullptr;
    void r52AttachExistingDevices();
    bool r52PrepareController(const R47HardwareInfo &);
    bool r52PrepareDomain(IOService *, UInt32, const r44mapper::Profile *,
                          r44mapper::ProfileSource);
    bool r52ReleaseDomain();
    void r52PublishDomains();
    bool r52PowerSupported() const;
    IOReturn r66SetSystemPM(bool armed);
    bool fR63DMAParked = false; // writes hold both the mapper and controller locks
    IOReturn r63SetRequesterDMA(bool park);
    IOReturn r63SwitchRequesterDMA(bool park);
    bool r52InvalidateLocked(bool, UInt64, UInt64, bool, bool *);
    struct R44Controller;
    R44Controller *fR44Controller = nullptr;
    struct R44MapperState;
    R44MapperState *fR44Mapper = nullptr;
    bool r44StartAuto();
    bool r44AttachAuto(IOService *, bool claim = false);
    bool r44StopAuto();
    bool r44Invalidate(bool invalidateDevice = false,
        UInt64 address = 0, UInt64 bytes = 0,
        bool newMapping = false, bool *skipped = nullptr);
    void r44PublishAuto();
    // TODO(R47-PM-HARDWARE): validate real system sleep/resume when the
    // platform supports it. Normal network operation does not invoke PM.
    // Called synchronously by Lucy's existing gated PM actions. The normal
    // network-family disable has retired TX and rebuilt RX before suspend.
    IOReturn r47PowerTransition(UInt32);
    bool r47SuspendAuto();
    bool r47ResumeAuto();
    bool r44PrepareMappings(volatile UInt64 *, UInt64, UInt32, UInt32,
                            const r44mapper::Profile &);
    // R71-B: shared by prepare and growth so the arena carve order exists once.
    // `d` is zeroed and owns nothing; on failure it still owns nothing.
    static bool r44BuildArena(R44MapperState *d, volatile UInt64 *tables,
                              UInt64 tablePA, UInt32 tablePages, UInt32 rootLevel,
                              const r44mapper::Profile &profile);
    // R71-B: called with the domain lock held, from the first admissible map.
    // Rebuilds the arena and page-table area at the admission ceiling while the
    // DTE still names a passthrough root, then adopts them in one step.
    bool r44GrowBeforeFirstMap(R44MapperState *d);
    // R52Domain is defined in AMDMapperProbeAuto.cpp, so the growth code (which
    // owns R44MapperState) asks the platform side through these accessors
    // instead of reaching into a type it cannot see.
    bool r44GrowthOpen() const;
    const r44mapper::Profile *r44PreparedProfile() const;
    const r44mapper::Profile *r44CeilingProfile() const;
    void r44AdoptGrownTables(IOBufferMemoryDescriptor *tables, UInt64 tablePA,
                             UInt32 tablePages, const r44mapper::Profile &target);
    // Same allocation the controller buffers use, so admission and growth cannot
    // diverge on alignment or contiguity requirements.
    bool r44AllocateTableArea(IOBufferMemoryDescriptor *&md, UInt64 bytes, UInt64 &pa);
    bool r44QuiesceMappings();
    bool r44ReleaseMappings();
    UInt32 r44LiveMappings() const;
    void r44PublishMappings(OSDictionary **copy = nullptr);
    IOReturn r44MapMemory(IOMemoryDescriptor *, uint64_t, uint64_t, uint32_t,
        const IODMAMapSpecification *, IODMACommand *, const IODMAMapPageList *,
        uint64_t *, uint64_t *);
    IOReturn r44UnmapMemory(IOMemoryDescriptor *, IODMACommand *, uint64_t, uint64_t);
    bool r44Translate(uint64_t, uint64_t *) const;

    // Round34: Lucy owns the standard objects and replaces the real RX mbufs.
    // This service owns only routing identities, PTEs and mapping evidence.
    struct R34RxDomain;
    R34RxDomain *fR34Rx = nullptr;

    // ---- B2 observation counters ----
    // iovmMapMemory may be called at high frequency; setProperty on every call
    // would keep allocating memory. Policy: record the first call, the last
    // call and the cumulative count, refreshing properties only when the count
    // changes.
    uint32_t fMapCalls;
    uint32_t fUnmapCalls;
    uint32_t fInsertCalls;
    uint32_t fPhysAddrCalls;
    uint32_t fPublishedMapCalls;

    // ---- B2-a verdict results ----
    uint32_t fMapOkCalls;          // physically contiguous, returned identity mapping successfully
    uint32_t fMapRejectFragCalls;  // not physically contiguous -> kIOReturnUnsupported
    uint32_t fMapRejectOtherCalls; // invalid arguments / window closed
    uint32_t fUnmapOkCalls;

    // Safety gate (for self-test): a real success may be returned only while
    // the probe's self-test is running. Besides "the window is open", it also
    // requires dmaCommand to be the very one the probe created -- so even if a
    // real device obtains this mapper in the future, it can never receive a
    // "looks-successful" mapping inside the self-test window.
    bool fMapWindowOpen;
    IODMACommand *fExpectedCmd;

    // The "this call came from the probe itself" flag, distinct from
    // fMapWindowOpen:
    //   fProbeCallActive  this setMemoryDescriptor was initiated by the probe
    //                     (B2-0 / B2-a)
    //   fMapWindowOpen    this call may return success (only B2-a's two
    //                     comparison cases open it)
    // B2-0 is "probe-initiated but window closed"; judged by the window alone
    // it would be miscounted as a "real device call" -- exactly the trap of the
    // first 0.6.0 deployment (m1bb-realmapcalls reported 1, actually B2-0's
    // 16 KiB buffer).
    bool fProbeCallActive;

    // ---- B2-b: real device support ----
    //
    // The fundamental difference from B2-a: B2-a maintains **one** active
    // mapping at a time (self-test is serial), while RTL812xLucy establishes
    // **three** mappings simultaneously in start():
    //   txBufDesc  (16 KiB)  setupTxResources()   -> txDescDmaCmd
    //   rxBufDesc  (16 KiB)  setupRxResources()   -> rxDescDmaCmd
    //   statBufDesc(~300 B)  setupStatResources() -> statDescDmaCmd
    // and if useAppleVTD is true it later maps packet buffers as well.
    // So this must become a mapping table; a single variable no longer works.
    //
    // Why a fixed array rather than dynamic allocation: iovmMapMemory may be
    // called in interrupt/gated context, where IOMalloc is not safe. 32 entries
    // are ample for current use; when full, return failure and count it (better
    // to reject than to allocate memory inside the kernel).
    enum { kMaxActiveMaps = 32 };

    struct MapEntry {
        uint64_t pa;        // physical address (under identity mapping also the IOVA)
        uint64_t len;
        bool     used;
    };
    MapEntry fMaps[kMaxActiveMaps];

    // Real-device gate: real devices receive mappings only when the boot-arg
    // `amdiommu=arm` is present. This is a second independent switch -- having
    // the card installed does not mean automatic admission; the boot argument
    // must be added explicitly.
    bool      fArmed;
    IOService *fNicDevice;      // B2-b target (the RTL8127 PCI device)

    // Boot sequencing (measured lesson of 0.6.0):
    //   The probe matches IOResources and start() runs extremely early. At that
    //   moment serviceMatching(IOPCIDevice) returns an empty set -- PCI
    //   enumeration is not complete, findNic() reported ABSENT-no-rtl8127,
    //   while pci10ec,8127 clearly existed on the same machine seconds later.
    //   B1 always succeeded because it uses the IOACPIPlane path; those nodes
    //   are established during the EFI phase.
    //   Hence findNic() now locates the device by IODeviceTree path first.
    //
    // The race (0.6.0 measured: success/failure/success across three reboots):
    //   Lucy reads iommu-parent once in start() without retrying. There is no
    //   ordering guarantee between the moment the probe sets the property and
    //   the moment Lucy reads it, so it worked only sometimes.
    //
    // Solution: switch to gIOFirstPublishNotification.
    //   Per the IOKit documentation (IOService.h:279):
    //     "When an IOService is published with registerService, the matching
    //      and probing process begins ... A list of matching dictionaries from
    //      the catalog **and installed publish notification requests** ...
    //      is constructed ... After probe, the driver is detached ...
    //      For each category, the highest scoring driver ... its start method
    //      called."
    //   i.e. publish notifications are delivered **before** probe/start. We
    //   attach the property the instant the device registers; Lucy is certain
    //   to read it when it later probes/starts.
    IONotifier *fPublishNotifier;
    uint32_t    fPublishHits;       // notification callback hit count
    bool        fLateAttach;        // whether the "notification missed it" fallback path was taken

    // ---- B2-b observation ----
    uint32_t fRealMapCalls;       // mapping requests with a non-probe cmd
    uint32_t fRealMapOk;          // of those, the successful ones
    uint32_t fRealMapRejectFrag;  // rejected for fragmentation
    uint32_t fRealMapRejectNoSlot;// table full
    uint32_t fRealUnmapCalls;
    uint32_t fTablePeak;          // peak table occupancy

    // Summary of the last successful mapping
    uint32_t fLastSegCount;
    uint64_t fLastFirstPA;
    uint64_t fLastLength;
    uint64_t fLastOffset;

    bool findTarget();
    bool findNic();
    bool armNic(IOService *nic);
    void installPublishNotifier();
    static bool publishHandler(void *target, void *refCon,
                               IOService *newService, IONotifier *notifier);
    void runB1SelfTest();
    struct R33DeviceDomain;
    bool fR31Session = false;
    volatile UInt32 fR31StopRequested = 0;
    volatile UInt32 fR31WorkerActive = 0;
    volatile UInt64 fR31StopRequestTime = 0;
    bool fR31SessionCompleted = false; // written/read by the worker only
    R33DeviceDomain *fR33Domain = nullptr;
    volatile UInt32 fR33TeardownState = 0; // 0 active, 1 queued/running, 2 finished
    UInt32 fR33InstallCount = 0;

    R27ProbeTimer *fM22b2Timer;   // one-shot timer (released in stop())
    uint32_t            fM22b2DelayMS; // delay in milliseconds (overridable by boot-arg)

    // How many raw events (16 bytes each) are kept per window for offline
    // decoding.
    //
    // [v0.20.0] Raised from 8 to 16. Round 4 kept only 8 while the window
    // actually held 14-17 events, so any "address distribution / flag
    // composition" conclusion covered less than half the events. 16 covers the
    // largest window observed so far (17) with margin.
    //
    // [v0.21.0] The window structs moved to members (see fM22b2WinPre /
    // fM22b2WinMain below) and no longer occupy runM22b2PageTableProbe()'s
    // stack, so this cap is no longer constrained by the __chkstk threshold.
public:
    static const unsigned kM22b2RawKeep = 16;

private:

    // Event window records.
    //
    // [Why this struct must exist]
    //   The old m2b2MeasureEvents() returned a single UInt32 and used 0 both
    //   for (a) genuinely no events in the window and (b) log overflow /
    //   incomplete entries / sampling failure. Opposite meanings merged into
    //   one value made every prior "0 faults" conclusion uninterpretable.
    //
    // Each window now records in full: monotonic start/end, measured duration,
    // HEAD/TAIL at both ends, STATUS at both ends, per-type counts, the devid
    // mismatch count, and raw event bytes. When valid=false, invalidReason
    // states the concrete reason, and that window **must not** be treated as
    // 0 events.
public:
    struct M22b2EventWindow {
        bool        valid;
        const char *invalidReason;
        uint64_t    tStart;
        uint64_t    tEnd;
        uint64_t    durMS;           // measured duration (not the nominal value)
        uint64_t    wallStart;       // wall-clock seconds, for aligning external netstat samples
        uint64_t    wallEnd;
        uint32_t    headStart;
        uint32_t    tailStart;
        uint32_t    headEnd;
        uint32_t    tailEnd;
        uint32_t    statusStart;
        uint32_t    statusEnd;
        uint32_t    entries;
        uint32_t    typeCount[16];
        uint32_t    devidMismatch;
        uint32_t    rawCount;
        // Whether retention was truncated by the cap. true means
        // entries > rawCount; raw is then a sample and cannot represent all
        // events.
        bool        rawTruncated;
        // Pre-existing backlog: entries already in [HEAD, TAIL) and unconsumed
        // at window start. These are events from **the previous window or the
        // switch process**, not new events of this window.
        uint32_t    preBacklog;
        uint32_t    raw[kM22b2RawKeep][4];
    };

private:

public:

    // Observation results (filled by observeDeviceDma(); step 17 classifies
    // faults with it)
    //
    // [Round 7 rewrite] Round 6's version of this struct had two semantic
    // errors, both fixed here:
    //
    //  (1) It called inIdentityRam() (RAM_TOP = 16 GiB) before collecting
    //      descriptor addresses, so **the very class of addresses this round
    //      investigates was discarded before entering the set**. The set then
    //      "proved" faults were not in the device set -- they never could have
    //      been. Now: recording and dereferencing are completely separated. All
    //      descriptor addresses are recorded; readVerdict only decides "may
    //      that memory be read", kept as metadata.
    //
    //  (2) The close-pointer delta was computed with ring modulo 1024. The
    //      hardware counter is a 31-bit cumulative value
    //      (MaxTxDescPtrMask = 0x7FFFFFFF); the correct answer to 1000 -> 2024
    //      is 1024, but ring modulo gives 0 -- reading "the device completed
    //      1024 descriptors" as "the device did nothing", precisely the
    //      direction that must never be confused.
    struct M22b2DmaObs {
        bool     ran;
        bool     barMapped;
        uint64_t barBase;      // BAR2's physical base
        uint64_t barLen;

        // ---- Round 10: the target device's independent identity ----
        //
        // [Why this group exists]
        //   Round 9 never checked "which device these driver records belong
        //   to". The records carry no vendor/device/BDF, and the probe never
        //   compared its own observations, so "the records belong to the target
        //   device" was an assumption.
        //
        //   This group is obtained by **the probe itself** from the device
        //   table and the IORegistry, independent of anything the driver
        //   publishes. The analyser compares it item by item with the snapshot
        //   header and rejects on any mismatch.
        //
        // [Why MAC and ifUnit too]
        //   The same machine may have two NICs of the same model (different
        //   BDFs, same vendor/device), and interface numbers may change after a
        //   driver reload. MAC + ifUnit are the checkable evidence that "this
        //   network interface is that PCI function", not "the number looks
        //   similar".
        bool     nicIdentityKnown;
        uint32_t devid;            // the device table's devid, which is the BDF
        uint32_t vendorId;
        uint32_t deviceId;
        uint32_t nicUnit;          // BSD unit（en2 -> 2）
        uint64_t nicMac;           // 48-bit MAC
        const char *nicBsdName;    // "en2"
        // The request count declared for round 10's controlled batch;
        // 0 means this round declared no batch.
        uint32_t expectedBatch;

        // ---- Round 11: this run's run-token declaration ----
        //
        // [Why it must be declared, not inferred from records]
        //   Round 10's batch criterion merged by reqId alone, with no token
        //   concept. So "token A's req1 + token B's req2" counted as one
        //   complete 2-request batch -- two different runs stitched into one.
        //
        //   This round's token is fixed here **before the evidence is read**
        //   (the load script and the boot-arg use the same value); records with
        //   a non-matching token are all counted in batchForeignToken.
        //   When undeclared (0), it degrades to "adopt only if the records
        //   contain exactly one token"; two or more yields tokenAmbiguous and a
        //   refusal to pass.
        uint32_t declaredToken;

        // ---- Round 11: this driver instance's binding ----
        //
        // Set by m2b2BindDriverInstance() before the window opens, read-only
        // afterwards. 0 means binding failed, in which case the batch criterion
        // refuses to pass (unknown is not a pass).
        uint32_t epochBound;

        // Device addresses read from registers
        bool     haveTxRing;
        uint64_t txRingBase;
        bool     haveRxRing;
        uint64_t rxRingBase;
        bool     haveStat;
        uint64_t statBase;
        bool     haveCounter;
        uint64_t counterAddr;

        // Descriptor scan results
        uint32_t txSlots;
        uint32_t txOwned;
        uint32_t txDone;
        uint32_t txAddrZero;
        uint32_t txTsoSlots;
        uint32_t rxSlots;
        uint32_t rxOwned;
        uint32_t rxDone;
        uint32_t rxAddrZero;
        uint64_t txFirstAddr;
        uint64_t rxFirstAddr;

        // Collected address ranges and **five counters that never mix** (round 7)
        //
        //   rawOffered   raw addresses taken from descriptors/registers
        //   mergedTotal  merged range count == savedCount + droppedCount
        //   savedCount   actually stored into the set
        //   droppedCount not stored due to the capacity cap (the envelope still
        //                covers them)
        //   unscanned    slots that could not be examined at all (ring mapping
        //                failure etc.)
        uint32_t ranges;          // == savedCount; keeps the old property name
        uint32_t dropped;         // == droppedCount
        uint32_t rawOffered;
        uint32_t mergedTotal;
        uint32_t unscanned;
        uint32_t txBufRanges;
        uint32_t rxBufRanges;

        // The envelope of all observed ranges (including those dropped at the
        // capacity cap).
        bool     envValid;
        uint64_t envLo;
        uint64_t envHi;

        // [Round 7] Physical layout and read permission
        //
        // The identity-mapping ceiling is **not** a RAM ceiling; this round no
        // longer filters records with it and uses it only to answer "may this
        // be read". Without an authoritative layout, layoutKnown = false: no
        // address is dereferenced, but all are recorded.
        bool     layoutKnown;
        const char *layoutSource;   // "probe" / "none"
        uint32_t readOkCount;
        uint32_t readOutOfMapCount;
        uint32_t readNotRamCount;

        // [Round 7] Coverage
        //
        // COV_NONE / COV_SNAPSHOT / COV_WINDOW. A snapshot supports only
        // **positive** attribution; "the device never used this address"
        // requires whole-window coverage.
        uint32_t coverage;

        // Device completion evidence.
        uint32_t txDoneWithAddrBefore;
        uint32_t txDoneWithAddrAfter;
        bool     haveDoneDelta;

        // [Round 7] Close pointer: identity is derived from the chip, no longer
        // "take the first non-zero candidate".
        bool     haveCloPtr;
        uint32_t cloPtrBefore;
        uint32_t cloPtrAfter;
        uint32_t cloPtrReg;      // derived from ChipId, not elected
        uint32_t cloPtrWidth;
        uint32_t cloPtrMask;     // MaxTxDescPtrMask
        uint32_t txConfigRaw;
        uint32_t cfgMethod;
        uint32_t noCloseVer;
        bool     chipKnown;
        bool     haveCloDelta;
        uint32_t cloDelta;       // masked delta, not ring modulo
        bool     cloDeltaValid;  // sample valid and the delta explainable

        // Ring tail pointer (cumulative submit count), used to judge window
        // coverage
        bool     haveTailPtr;
        uint32_t tailPtrBefore;
        uint32_t tailPtrAfter;
        bool     txWindowCovered;

        // ---- Round 8: window scan and generations ----
        //
        // Round 7's collector never called txSlotLifecycle(): it ignored its
        // own tailCum/cloCum arguments and, as long as a close pointer was
        // readable, labelled every non-zero TX address in-flight. In round 7's
        // capture tail = clo = 0x6a (the queue was already drained), yet every
        // historical address was still reported in-flight.
        //
        // Now scanTxWindow() walks by cumulative index over
        // [tailBefore, tailAfter), each entry carrying its own slot, generation,
        // address, length and completion state.
        uint32_t winSubmits;         // descriptors submitted within the window
        uint32_t winCompletes;       // descriptors handed back within the window
        uint32_t winVisited;         // cumulative indices actually visited
        uint32_t winDecoded;         // successfully decoded
        uint32_t winOverwritten;     // slots already reused (descriptor no longer in the ring)
        uint32_t winInflight;
        uint32_t winCompleted;
        uint32_t winCompletedInWindow;
        uint32_t winLenUnknown;      // length undecodable (TSO / zero length)
        uint32_t winTsoSlots;
        uint32_t winGenBefore;       // generation at window start
        uint32_t winGenAfter;        // generation at window end
        uint32_t winCovReason;       // TxCoverageReason
        // The first descriptor "completed within the window": lands the positive
        // completion delta on a concrete operation.
        bool     haveFirstCompleted;
        uint64_t winFirstCompletedAddr;
        uint32_t winFirstCompletedLen;
        uint32_t winFirstCompletedSlot;
        uint32_t winFirstCompletedGen;

        // ---- Round 8: per-path coverage ----
        //
        // Round 7 had a single coverage value used for all paths. TX has
        // whole-window coverage; RX / rings / the statistics buffer have only a
        // snapshot. Generalizing TX's verdict to the whole device is the same
        // over-generalization in a new place.
        amdobs::PathCoverage pathCov;

        // ---- Round 8: grounds for reading ring memory ----
        //
        // Device registers prove only "the device was programmed to use this
        // address"; they cannot prove this memory is still the driver's ring
        // object, still alive, and that this PA maps to it. A fingerprint must
        // genuinely be able to fail to count as a check.
        uint32_t txRingBasis;        // RingBasis
        uint32_t rxRingBasis;
        uint32_t txRingDecoded;      // descriptors decoded in the fingerprint
        uint32_t rxRingRingEndAtLast;
        bool     txRingFpOk;
        bool     rxRingFpOk;

        // [Round 7] Time boundaries: all monotonic nanoseconds, checkable item
        // by item
        uint64_t tObsBefore;      // observation before the window
        uint64_t tWinStart;
        uint64_t tWinEnd;
        uint64_t tObsAfter;       // observation after the window
        uint64_t tCloBefore;
        uint64_t tCloAfter;
        uint64_t tRecoveryStart;
        uint64_t tRecoveryEnd;

        // ---- Round 8: boundary moments (all on the same monotonic clock) ----
        uint64_t tTranslateOn;    // the DTE switching to translation takes effect
        uint64_t tTranslateOff;   // the DTE switched back to pass-through (before recovery starts)
        uint64_t tTailBefore;     // moment the tail pointer was read before the window
        uint64_t tTailAfter;      // moment the tail pointer was read after the window
        uint64_t tWinScanStart;   // post-window ring scan start
        uint64_t tWinScanEnd;     // post-window ring scan end

        // ---- Round 9: time-boundary reordering ----
        //
        // Round 8 recorded tTranslateOn at "the DTE was written". Writing the
        // DTE does not mean translation is effective: the invalidation commands
        // were not yet submitted and the TLB may still hold old entries. The
        // two moments are now published separately, with tTranslateOn taken
        // **after all invalidation commands complete**.
        //
        // Likewise, round 8's two CloPtr samples sandwiched the window from the
        // outside (span 3.00785 s > window 3.00018 s), so "completions happened
        // within the zero-event window" was never actually proven. The
        // post-sample now happens at the last moment **inside** the window, and
        // no register is read after the window closes.
        uint64_t tDteWritten;     // the DTE write completed
        uint64_t tInvComplete;    // both invalidation commands received completions
        // The main window's monotonic boundaries tWinStart / tWinEnd were
        // declared back in round 7 (above); this round uses them directly to
        // window-filter the driver log's pairings.
        uint64_t tCloAfterInWin;  // the in-window post-sample's start (= tCloAfter)
        bool     boundaryInWindow; // the post-sample really happened inside the window

        // ---- Round 11: the snapshot the probe actually used ----
        //
        // [What went wrong here in round 10]
        //   The probe did read a fresh snapshot (publication 27, tPublished
        //   41,305,180,913 ns, window end 40,843,902,421 ns -- coverage held).
        //   But the archive took a different copy from props.raw.txt, a dump of
        //   the whole IOService plane, whose driver node was already
        //   publication 71 from 43 seconds later. So "the runtime verdict" and
        //   "the archived input" were two different things, and the analyser
        //   verified the latter.
        //
        //   The fix is not to make the capture script more careful but to have
        //   **the probe itself** hand over, verbatim, the bytes that took part
        //   in the verdict: an OSData property m2-b2-obs-snapshot-used whose
        //   contents are exactly the bytes used for decoding, byte for byte.
        //   The capture script writes it to disk and the analyser verifies its
        //   hash equals the m2-b2-obs-used-sha256 the probe published alongside.
        //
        // [Why a separate hash is recorded too]
        //   The property is text; the blob is binary. Exporting only the blob
        //   proves nothing about its identity with the bytes used at verdict
        //   time. The probe hashes once before and once after decoding; a
        //   mismatch means the OSData changed in our hands (should not happen,
        //   but is detectable) -- the blob is then not published and the reason
        //   written out.
        bool     obsUsedExported;      // the blob was published
        uint32_t obsUsedBytes;         // published byte count
        bool     obsUsedHashStable;    // hashes before/after decoding agree
        char     obsUsedSha[65];       // hexadecimal sha256 (64 + NUL)
        const char *obsUsedWhy;        // why it was not published
        // Whether this snapshot is the one actively fetched to cover the
        // window. Combined with obsFetchTries it makes "the bounded refresh
        // worked" independently checkable.
        uint32_t obsUsedPubId;
        uint64_t obsUsedTPublished;
        bool     obsUsedIsFresh;       // tPublished >= tWinEnd

        // ---- Round 11: driver instance binding ----
        //
        // [Why binding is required and "merely requiring internal consistency"
        // is not enough]
        //   Round 10 had want.epoch = 0, and obsIdentityMatches() interprets 0
        //   as "don't check". The same card, the same MAC, the same BSD unit --
        //   a new instance created after a driver reload or controller reset
        //   would have its snapshot accepted as this instance's evidence.
        //
        //   The instance epoch is now fixed **before the window opens** (read
        //   from the driver node, or sampled and remembered by the probe), and
        //   the snapshot header's epoch must equal it afterwards. If it cannot
        //   be obtained, epochBinding = "unknown" is published and passing is
        //   refused -- unknown is not a pass.
        uint32_t obsEpochBound;        // this round's instance identity (0 = not bound)
        uint32_t obsEpochSeen;         // the epoch carried in the snapshot header
        const char *obsEpochBinding;   // "matched" / "mismatch" / "unknown"

        // ---- Round 10: the driver-side observation log (wire format v2) ----
        //
        // Ring reading sees only "bytes after the window": it cannot prove
        // those bytes belong to one generation, nor recover TSO segments' true
        // lengths. The driver now records metadata at its own submit/complete
        // points and publishes **header + records** as **one** OSData.
        //
        // [Why round 9's v1 was not enough]
        //   1. v1's seq is written only once at the end; a reader doing "read
        //      seq, read body, read seq again" sees **the previous** seq twice
        //      mid-write and judges a half-written state consistent. That is
        //      not a seqlock.
        //   2. v1 split head/first/published/wrapped/t-published into five
        //      OSStrings with the records as a sixth OSData; the six do not
        //      form one atomic publication.
        //   3. The snapshot's publication time 39963682435 ns preceded the
        //      window end 40494639566 ns by 530957131 ns; "covers the full
        //      window" did not hold.
        //   4. The records carried no business identity and could not be matched
        //      to client requests.
        bool     obsPresent;
        const char *obsWhy;        // why unavailable, or "ok"
        const char *obsIdentityWhy; // why the identity check failed, or "ok"
        uint32_t obsPubId;         // the publication ID adopted this round
        uint32_t obsEpoch;         // the driver instance's epoch
        uint32_t obsHead;
        uint32_t obsPublished;     // == the record count in the snapshot
        uint32_t obsFirst;         // firstTicket
        uint32_t obsWrapped;
        uint32_t obsDropped;
        uint32_t obsValidCount;
        uint32_t obsLostCount;
        uint32_t obsHdrFlags;
        uint32_t obsBusDevFn;
        uint32_t obsVendorId;
        uint32_t obsDeviceId;
        uint32_t obsIfUnit;
        uint64_t obsMac;           // 48-bit MAC
        uint64_t obsTStart;
        uint64_t obsTPublished;
        // Refresh attempts and whether the finally adopted one is "fresh"
        uint32_t obsFetchTries;    // how many bounded polls were made
        bool     obsFreshEnough;   // tPublished >= the window end
        // The submit -> completion pairing result
        uint32_t obsOps;
        uint32_t obsSubmits;
        uint32_t obsDones;
        uint32_t obsDoorbells;
        uint32_t obsRxDone;
        uint32_t obsRxAddrZero;
        uint32_t obsStale;
        uint32_t obsUnmatchedDone;
        uint32_t obsUncompleted;
        uint32_t obsOverflow;
        bool     obsAllCompleted;
        // ---- Pairings within the window ----
        uint32_t obsWinSubmits;
        uint32_t obsWinDones;
        uint32_t obsWinPaired;
        uint32_t obsWinOrphanDone;
        uint32_t obsWinPreWindowInFlight;
        uint32_t obsWinUncompleted;
        // ---- Round 10: three independent criteria ----
        //
        // These three must stay separate. "One successful pair exists" cannot
        // substitute for "the records cover the window", and neither can
        // substitute for "this controlled batch completed".
        bool     obsHasCompletePair;
        bool     obsRecordsCoverWindow;
        bool     obsControlledBatchComplete;
        uint32_t obsCoverState;
        const char *obsCoverName;
        // ---- Round 10: business correlation ----
        uint32_t obsBizOps;
        uint32_t obsBizCapped;
        uint32_t obsExpectedBatch;
        uint32_t obsBatchComplete;
        uint32_t obsBatchPartial;
        uint32_t obsBatchMissing;
        uint32_t obsBatchUnexpected;
        uint32_t obsBatchUnparsed;
        uint32_t obsTxParsed;
        uint32_t obsRxParsed;
        // ---- Round 11: batch-criterion bindings and blocking counters ----
        uint32_t obsDeclaredToken;      // the declared run token (0 = not declared)
        uint32_t obsJoinToken;          // the token actually used for joining
        bool     obsTokenResolved;      // the token came from the declaration or a unique inference
        bool     obsTokenAmbiguous;     // multiple tokens appear in the records
        // [Round 12] The token was **inferred** (not declared before reading the
        // records). An inferred token cannot support the batch criterion: it
        // makes "these records belong to this run" true by construction.
        bool     obsTokenInferred;
        uint32_t obsBatchForeignToken;  // records belonging to other runs
        uint32_t obsBatchOutsideWindow; // requests whose stages did not all fall within the window
        uint32_t obsBatchDupDone;       // requests with duplicated completions
        uint32_t obsBatchBadFrag;       // requests with incomplete segment structure
        uint32_t obsBatchDmaUnknown;    // requests whose DMA ranges could not be determined
        uint32_t obsBatchOrder;         // requests whose completion preceded submission
        const char *obsBatchWhy;
        // The first complete business operation (all TX segments + completion +
        // RX) in the controlled batch
        bool     obsHaveBizOp;
        uint32_t obsBizToken;
        uint32_t obsBizReqId;
        uint32_t obsBizSegCount;
        uint32_t obsBizSegDone;
        uint64_t obsBizTSubmitFirst;
        uint64_t obsBizTSubmitLast;
        uint64_t obsBizTDoorbell;
        uint64_t obsBizTDoneFirst;
        uint64_t obsBizTDoneLast;
        uint64_t obsBizRxAddr;
        uint32_t obsBizRxLen;
        uint64_t obsBizTRx;
        // All DMA segments of that operation (address/length/cumulative index)
        uint32_t obsBizSegCum[amdobs::OBS_MAX_SEGS];
        uint64_t obsBizSegAddr[amdobs::OBS_MAX_SEGS];
        uint32_t obsBizSegLen[amdobs::OBS_MAX_SEGS];
        uint32_t obsBizSegDoneCount[amdobs::OBS_MAX_SEGS];
        uint32_t obsBizSegMissingDone;
        uint32_t obsBizSegDupDone;
        bool     obsBizFragOk;
        bool     obsBizInWindow;
        uint64_t obsFirstSubmitT;
        uint64_t obsLastDoneT;
        uint64_t obsFirstRxAddr;
        uint64_t obsLastRxAddr;
        // The first completely paired controlled operation: submit -- address --
        // completion, all three here.
        bool     obsHaveFirstOp;
        uint32_t obsFirstOpCum;
        uint32_t obsFirstOpSlot;
        uint32_t obsFirstOpGen;
        uint64_t obsFirstOpAddr;
        uint32_t obsFirstOpLen;
        uint32_t obsFirstOpFlags;
        uint64_t obsFirstOpTSubmit;
        uint64_t obsFirstOpTCompl;

        // ---- Round 11: raw page table evidence for business addresses ----
        //
        // [Why round 10's evidence was not evidence]
        //   The report said "L4->L3->L2 identity leaves, the root table from
        //   the actual DTE", but the published samples were win0 (the first
        //   in-window operation with both submit and completion -- unrelated to
        //   business) and dma0..dma5 (a sample of in-use addresses such as the
        //   ring base and the statistics buffer). Not one of business request
        //   1's TX address 0x3790a57b6 or RX address 0x1f421f000 was among
        //   them. Attaching background operations' paths to the business chain
        //   mistakes "nearby" for "the same".
        //
        //   Now: for **every TX/RX segment of every controlled request**, the
        //   segment's [addr, addr+len) is walked, with the real table physical
        //   address, index, level and raw PTE exported level by level, and every
        //   byte of the range checked to be covered by legal leaves. The data
        //   source is the table this experiment built; the start point is the
        //   **actual DTE** read in this step.
        //
        // [Why a separate block rather than reusing dumpPath]
        //   dumpPath walks one address at a time and judges only "translates
        //   back to itself". Business ranges must judge coverage and
        //   permissions, per segment, so the field structure differs.
        uint32_t bizWalkCount;      // the (request, direction, segment) pairs actually walked
        uint32_t bizWalkOk;         // of those, ranges fully covered by legal leaves
        uint32_t bizWalkFail;       // the ones that did not hold
        // ---- Round 12: the range set's two "ledgers" ----
        //
        // [bizWalkExpected]
        //   The number of ranges that should have been walked, derived from the
        //   **raw business records** (each req's TX segments + RX segments under
        //   this run's token). It must equal bizWalkCount; otherwise some ranges
        //   were never walked at all -- round 11 judged only "whether the ones
        //   reached passed", and walking a few fewer could still be all green.
        //
        // [bizWalkCapped]
        //   The number of ranges explicitly downgraded for exceeding forensic
        //   capacity or budget. Round 11 returned directly on
        //   `count >= kBizWalkMaxSegs` -- no counting, no downgrade -- so "only
        //   a part was exported" would be read as "everything qualified".
        uint32_t bizWalkExpected;
        uint32_t bizWalkCapped;
        // How many distinct leaves are exported per segment at most. A 74-byte
        // packet normally lands in a single 2 MiB leaf; when it crosses leaves,
        // **every** leaf's complete path must be exported, otherwise the
        // analyser can check only the first leaf while seeing covered=yes.
        static const uint32_t kBizWalkMaxLeaves = 4;
        // Levels exported per path at most; AMD-Vi has at most 6 levels, so 6
        // is sufficient and fixed.
        static const uint32_t kBizWalkMaxLevels = 6;
        static const uint32_t kBizWalkMaxSegs = amdobs::OBS_MAX_SEGS * 8;
        // One path: every level from root to leaf.
        struct BizPath {
            uint8_t  depth;
            uint8_t  reserved[3];
            uint64_t leafPA;        // the hit leaf's base address
            uint64_t leafSize;
            uint32_t leafLevel;
            // Which part of the range this leaf covers: start + byte count.
            //
            // [Why both are needed]
            //   With byte counts alone, "the two leaves add up to exactly the
            //   whole range" cannot be checked -- an overlap or a gap still
            //   makes the total look right. The start makes each leaf's
            //   coverage addable segment by segment.
            uint64_t coversFrom;
            uint64_t coversBytes;
            uint64_t tablePA[kBizWalkMaxLevels];
            uint32_t index[kBizWalkMaxLevels];
            uint32_t level[kBizWalkMaxLevels];
            uint64_t pte[kBizWalkMaxLevels];
        };
        struct BizWalk {
            uint32_t reqId;
            uint8_t  isRx;          // 0 = TX (device reads), 1 = RX (device writes)
            uint8_t  segIndex;
            uint8_t  depth;         // the first leaf's level count (keeps the old property's meaning)
            uint8_t  covered;       // the range is fully covered
            uint8_t  permOk;        // this direction's permission bits suffice
            uint8_t  overflow;      // addr+len overflowed
            uint8_t  capped;        // leaf count exceeded kBizWalkMaxLeaves
            uint8_t  leafCount;     // the number of leaves actually exported
            uint64_t addr;
            uint32_t len;
            uint64_t leafPA;        // the first leaf's base (old property)
            uint64_t leafSize;
            uint32_t leafLevel;
            uint64_t rootPA;        // the walk's start point (from the actual DTE)
            uint32_t rootLevel;
            uint64_t dteRaw;        // the DTE the walk was based on
            uint32_t pagesChecked;  // leaves checked within the range
            uint32_t pagesBad;      // leaves not covered by a legal leaf
            const char *why;
            BizPath  path[kBizWalkMaxLeaves];
        };
        BizWalk bizWalk[kBizWalkMaxSegs];

        // ---- Round 14: the RX posted-buffer set ----
        //
        // [What round 13 lacked]
        //   The 8 ranges walked were the 8 buffers that "happened to carry the
        //   4 echoes". The full ring holds 1024 4 KiB buffers, re-posted
        //   repeatedly within the window. So what was proven was "the sample
        //   was mapped", not "every buffer the device can write is mapped".
        //
        // [This round's set]
        //     S = { (addr, capacity) from the baseline slot table }
        //       ∪ { (addr, capacity) of every re-post record with sequence
        //           number greater than the baseline watermark }
        //
        //   The baseline is collected by the driver on its own execution path
        //   and refreshed once per second; the probe reads it once **before the
        //   window**, recording the then-current post count (the watermark), and
        //   reads it a second time after the window, requiring every record
        //   "after the watermark" to be present. So any buffer still valid at
        //   window start and replaced later is either still in the final
        //   baseline or in the re-post records -- never missing from both.
        //
        // [Why the set lives in a member]
        //   3072 ranges x 24 bytes = 72 KiB. On runM22b2PageTableProbe()'s
        //   stack it would push the frame past the 4 KiB threshold, producing a
        //   ____chkstk_darwin weak reference and an outright kmutil rejection of
        //   the whole bundle (this project hit that three times).
        static const uint32_t kRxSetMaxRanges = 3072;
        static const uint32_t kRxSetDetailMax = 64;
        static const uint32_t kRxSetSampleMax = 8;

        struct RxSetDetail {
            uint64_t addr;
            uint32_t capacity;
            uint32_t source;      // amdrx::RX_SRC_*
            uint32_t slot;
            uint8_t  ok;
            uint8_t  permOk;
            uint8_t  leaves;
            uint8_t  reserved;
            const char *why;
        };

        bool     rxsetPresent;
        const char *rxsetWhy;         // why unavailable, or "ok"
        const char *rxsetSetWhy;      // the set construction's verdict token (nullptr = complete)

        // The two reads' identity and generation. All three must agree before
        // the two halves may be joined.
        uint32_t rxsetWatermark;      // the head read **before** the window
        uint32_t rxsetHead;           // the head read after the window
        uint32_t rxsetRingGen;
        uint32_t rxsetPreRingGen;
        uint32_t rxsetEpoch;
        uint32_t rxsetPreEpoch;
        uint32_t rxsetIfUnit;
        uint32_t rxsetVtdPath;

        // The driver's self-reported baseline statistics, compared item by item
        // against the probe's independent recomputation.
        uint32_t rxsetBaselineSlots;
        uint32_t rxsetBaselineValid;
        uint32_t rxsetBaselineCapDesc;
        uint32_t rxsetBaselineCapConst;
        uint32_t rxsetBaselineCapBad;
        uint32_t rxsetBaselineTorn;
        uint32_t rxsetBaselineCount;
        uint32_t rxsetBaselineGenMoved;

        // The set's own accounting.
        uint32_t rxsetRanges;
        uint32_t rxsetFromBaseline;
        uint32_t rxsetFromRearm;
        uint32_t rxsetFromBoth;
        uint32_t rxsetCapped;
        uint32_t rxsetSkippedZero;
        uint32_t rxsetSkippedBadCap;
        uint32_t rxsetRearmRequired;
        uint32_t rxsetRearmUsed;
        uint32_t rxsetRearmSeen;
        bool     rxsetComplete;

        // Walk results.
        uint32_t rxsetWalked;
        uint32_t rxsetOk;
        uint32_t rxsetFail;
        uint32_t rxsetFailCapped;
        uint64_t rxsetMinAddr;
        uint64_t rxsetMaxEnd;
        uint64_t rxsetBytesTotal;
        // The unmapped / unauthorized ranges, exported one by one (bounded;
        // overflow only counted).
        uint32_t rxsetFailCount;
        RxSetDetail rxsetFailDetail[kRxSetDetailMax];
        // For the passing part, only a sample is exported with full paths, to
        // avoid piling up page-table text per slot.
        uint32_t rxsetSampleCount;
        RxSetDetail rxsetSample[kRxSetSampleMax];
        // Sampled ranges' complete paths, in the same export form as the
        // business ranges.
        struct RxSamplePath {
            uint8_t  leafCount;
            uint8_t  depth;
            uint8_t  reserved[2];
            uint64_t leafPA;
            uint64_t leafSize;
            uint32_t leafLevel;
            uint64_t tablePA[kBizWalkMaxLevels];
            uint32_t index[kBizWalkMaxLevels];
            uint32_t level[kBizWalkMaxLevels];
            uint64_t pte[kBizWalkMaxLevels];
        };
        RxSamplePath rxsetSamplePath[kRxSetSampleMax];

        // The raw bytes the driver published (so the analyser can rebuild the
        // set independently).
        bool     rxsetRawExported;
        uint32_t rxsetRawBytes;
        char     rxsetRawSha[65];
        const char *rxsetRawWhy;

        // The range array. A member, not a local (see the stack frame note
        // above).
        amdrx::Range rxsetList[kRxSetMaxRanges];

        // ---- Round 9: window scan quality ----
        //
        // Round 8 published all the counters, but covered looked only at
        // pointer arithmetic: an early scan stop, lost records, undecodable
        // lengths -- none affected `tx-window-covered = yes`. Now all of them
        // withdraw eligibility instead of merely being displayed alongside.
        uint32_t winRecordsLost;
        bool     winExact;
        const char *winQualityName;

        // ---- Round 12: the evidence gate's actual verdict ----
        //
        // evidenceOk / evidenceWhy are amdobs::obsEvidenceGate()'s verdict over
        // **the same** evidence. The probe publishes it and the analyser
        // independently recomputes it; a mismatch means one side read the
        // evidence wrong. Note it is not a copy of the verdict string: the
        // verdict additionally layers window boundaries and ring-read
        // attribution, which are not part of "evidence eligibility".
        bool     evidenceOk;
        const char *evidenceWhy;

        const char *skipReason;
    };

    // Collect the addresses + lengths from descriptors into the set.
    //
    // The key difference from round 6: **no filtering by any ceiling**. All
    // non-zero addresses enter the set; whether that memory may be read is
    // decided separately by readVerdict() and recorded as metadata.
    //
    // [Round 8] This function now really uses tailCum/cloCum: it calls
    // scanTxWindow(), taking descriptors by cumulative index over
    // [tailCum, the post-window tail pointer), each with its own slot,
    // generation and lifecycle. Round 7's version ignored both arguments and
    // labelled every non-zero address in-flight.
    void m2b2CollectTxSegments(const UInt8 *ring, UInt32 count,
                               UInt32 tailCum, UInt32 cloCum);

    // [Round 10] Read the driver-side observation log (wire format v2).
    //
    // The fundamental difference from ring reading: what is read here is a copy
    // of memory the driver **still holds**. The driver writes records at its
    // submit/complete points and publishes **header + records** as **one**
    // OSData. The bytes the probe receives carry the driver's own cumulative
    // indices, so the "submit -- completion" pairing matches on the same number,
    // with no inference about slot reuse involved.
    //
    // Round 9's v1 had three structural defects, each fixed in v2 (see the
    // implementation's comments):
    //   1. seq written only once at the end; a reader cannot detect a
    //      half-written state;
    //   2. header and records in six properties, possibly from different
    //      publications;
    //   3. no business identity in the records, so they cannot be matched to
    //      client requests.
    void m2b2ReadDriverObs();

    // ---- Debug-only declarations: used only by kext/*Debug.cpp ----
public:


    // Round17: native-mbuf TX mapping. One live owner, evidence and command
    // budget bounded separately (see kext/AMDMapperProbeTx.cpp).
    struct R17Domain;
    R17Domain *fR17 = nullptr;
    bool r17Prepare(volatile UInt64 *, UInt64, UInt32);
    bool r17Activate(volatile UInt8 *, void *);
    void r17Export(void *);
    static IOReturn r17Callback(void *, UInt32, r17tx::Request *);
    void r17Release();
    // ---- round 21/22: the translation window edges ----
    //
    // The window is not "the period between two r17* calls"; it is the period
    // during which the device actually translates through this backend. Both
    // edges are ordered against the ORDINARY output path, which keeps running,
    // so both are built on the driver's submission barrier rather than on a
    // flag the probe sets and hopes nobody is inside:
    //
    //   enter: stop admission -> wait for admitted submitters to set OWN ->
    //          wait for the ring to hold nothing -> flip DTE + invalidate ->
    //          confirm -> open admission
    //   exit:  stop admission -> wait submitters -> drain the ring ->
    //          forced exit sample -> restore DTE + flush + read back ->
    //          detach -> resume ordinary output
    //
    // `r17Gate` is the single place that talks to the barrier; `r17StopSubmit`
    // is the only wait, and it runs on the probe's thread -- never inside the
    // driver's gate or workloop.
    bool r17Gate(bool quiesce, UInt32 *outstanding, UInt32 *activeCover,
                 UInt32 *inFlight = nullptr, UInt32 *ringOwn = nullptr);
    // Closes admission, then waits for submitters, descriptors, driver held/live
    // generations and backend owners to drain, with every retirement and command
    // completion confirmed. Polling does not hold the driver's gate or d->lock.
    bool r17StopSubmit(UInt32 budgetMs, const char *edge);
    bool r17BackendDrained();
    // Second half of the enter edge: only after the DTE flip and both domain
    // invalidations completed. `tInvComplete` is that completion time, which is
    // what "translation is in effect from here" means.
    bool r17EnterComplete(UInt64 tInvComplete);
    // Exit, after the caller restored the device table and read it back:
    // revoke controlled admission and release the backend, then (separately)
    // let ordinary output flow again. Neither opens admission implicitly.
    bool r17Detach();
    bool r17ResumeOutput();
    // Round22: the translation-off time is decided by AMDMapperProbePgt.cpp (it
    // is the register read-back), but the value belongs to the window record.
    // R17Domain is private to AMDMapperProbeTx.cpp, so it travels through here
    // instead of being written across translation units.
    void r17SetTranslateOff(UInt64);
    // Round22: the domain keeps its own copy of the command-ring cursors, which
    // it uses for every invalidation (map, unmap, cover). The caller must hand
    // it the CURRENT position after it has submitted commands on its own copy --
    // otherwise the domain appends at a stale slot and its CompletionWait never
    // arrives. This is exactly what moving Install before the DTE flip exposed.
    void r17SyncCommand(void *);
    // R17Domain is incomplete outside AMDMapperProbeTx.cpp; the window state is
    // read through this instead of by reaching into the struct.
    bool r17Installed() const;
    // Force the driver to sample the ring for a specific window step.
    void r17SampleExit(UInt32 stage);
    void r17PublishWindow();
    // Round18: the SAME domain, entered through the IOMapper virtuals that
    // IODMACommand calls, instead of through the platform callback. Bounded to
    // one physically contiguous page run per call (the layout a single-mbuf TX
    // packet has); everything else is refused before any PTE is written.
    bool r18StdReady() const;
    bool r32CapacityProbe();
    // True only for an address inside the domain's own bounded IOVA window, so
    // an unrelated mapper call can never be routed into (or counted as) this
    // path.
    bool r18StdOwnsAddress(uint64_t iova) const;
    // Real page-table translation for mapToPhysicalAddress(); false when the
    // entry is absent (never a fabricated identity result).
    bool r18StdTranslate(uint64_t iova, uint64_t *outPA) const;
    IOReturn r18StdMap(IOMemoryDescriptor *, uint64_t, uint64_t, uint32_t,
        const IODMAMapSpecification *, IODMACommand *, const IODMAMapPageList *,
        uint64_t *, uint64_t *);
    IOReturn r18StdUnmap(IOMemoryDescriptor *, IODMACommand *, uint64_t, uint64_t);
    // Published counters, so "the standard path ran" is never inferred from the
    // driver's own success string.
    uint32_t fStdMapCalls = 0, fStdMapOk = 0, fStdMapRejects = 0;
    uint32_t fStdUnmapCalls = 0, fStdUnmapOk = 0;
    uint32_t fStdPageRuns = 0, fStdFragRejects = 0, fStdOffsetRejects = 0;
    uint32_t fStdInsertRejects = 0, fStdWalkCalls = 0;
    /* round19: multi-run windows */
    uint32_t fStdRuns = 0, fStdDiscontig = 0, fStdMaxRuns = 0, fStdCapRejects = 0;
    void publishStdStats();

    // Round30: 1024 cyclic RX mappings. Commands are registered by BOTH object
    // identities before IOKit can call the mapper. They never consume TX slots.
    struct R27RxDomain;
    R27RxDomain *fR27Rx = nullptr;
    bool r27RxRequested() const;
    bool r27RxBegin();
    void r27RxReady();
    bool r27RxFinish(UInt32 budgetMs);
    bool r29WaitTailDone(UInt32 budgetMs);
    void r27RxExport();
    void r27RxRelease();
    IOReturn r27RxControl(UInt32 op);
    bool r27RxCandidate(IOMemoryDescriptor *, IODMACommand *) const;
    bool r27RxOwnsAddress(uint64_t) const;
    bool r27RxTranslate(uint64_t, uint64_t *) const;
    IOReturn r27RxMap(IOMemoryDescriptor *, uint64_t, uint64_t, uint32_t,
        const IODMAMapSpecification *, IODMACommand *, const IODMAMapPageList *,
        uint64_t *, uint64_t *);
    IOReturn r27RxUnmap(IOMemoryDescriptor *, IODMACommand *, uint64_t, uint64_t);
    bool r40FixedCandidate(IOMemoryDescriptor *, IODMACommand *) const;
    bool r40FixedOwnsAddress(uint64_t) const;
    bool r40FixedTranslate(uint64_t, uint64_t *) const;
    bool r40FixedReadPA(UInt32, UInt64, UInt64, UInt64 *) const;
    IOReturn r40FixedOperation(r34rx::Binding *);
    IOReturn r40FixedMap(IOMemoryDescriptor *, uint64_t, uint64_t, uint32_t,
        const IODMAMapSpecification *, IODMACommand *, const IODMAMapPageList *,
        uint64_t *, uint64_t *);
    IOReturn r40FixedUnmap(IOMemoryDescriptor *, IODMACommand *, uint64_t, uint64_t);
    bool r34RxPrepareMap(volatile UInt64 *, UInt64, UInt32, UInt32);
    bool r34RxStopBeforeDte();
    bool r34RxBegin();
    bool r34RxAuthorize();
    bool r34RxResumePhysical();
    bool r34RxFinish(UInt32 budgetMs);
    bool r34RxTailDone(UInt32 budgetMs);
    void r34RxReady();
    void r34RxExport();
    void r34RxRelease();
    IOReturn r34RxControl(UInt32 op);
    static int r34RxCallback(void *, r34rx::Binding *);
    IOReturn r34RxOperation(r34rx::Binding *);
    IOReturn r34RxBatch(r34rx::Binding *);
    bool r34RxCandidate(IOMemoryDescriptor *, IODMACommand *) const;
    IOReturn r34RxMap(IOMemoryDescriptor *, uint64_t, uint64_t, uint32_t,
        const IODMAMapSpecification *, IODMACommand *, const IODMAMapPageList *,
        uint64_t *, uint64_t *);
    IOReturn r34RxUnmap(IOMemoryDescriptor *, IODMACommand *, uint64_t, uint64_t);

    // Read-only lookup of the NIC service: **does not** set fNicDevice and does
    // not depend on fArmed.
    //
    // Why a separate function: M2-2b-2 needs the target device's BDF under
    // amdiommu=pgt, but then fArmed=false and fNicDevice is NULL. Reusing
    // findNic() directly would mutate state and couple to the arm flow; reusing
    // fNicDevice would yield NULL. The caller releases the returned value.
    IOService *findNicServiceOnly();
    void runB2SelfTest();
    void runB2aSelfTest();
    void runB2OneTest(const char *tag, bool wantContiguous, IOByteCount size);
    void publishMapStats(bool force);
    void publishB2bStats();

    // ---- M2-0b: PCI config space read-only probe ----
    //
    // Purpose: M2-0's conclusion was that IVRS's 0xFD380000 is correct and DSDT's
    // _CRS (0xFEB80000) is a stale declaration. But that conclusion rests on
    // Linux-side evidence and had no independent verification on macOS.
    //
    // The IOMMU's capability block (measured cap_ptr = 0x40) carries its own
    // MMIO BAR:
    //   cap_ptr + 0x00 : CapID(8) | CapPtr(8) | CapHdr(16)
    //   cap_ptr + 0x04 : BAR low  (bit0 is the lock bit; must be masked)
    //   cap_ptr + 0x08 : BAR high
    // This is the hardware's current, authoritative BAR value -- more
    // trustworthy than DSDT's static declaration.
    //
    // Everything is read-only: configRead8/16/32 only do PCI config reads; no
    // register is written.
    void runM20ConfigProbe();

    // ---- M2-1: read-only MMIO probing ----
    //
    // The project's first touch of MMIO. Triple protection:
    //   1. Gated by boot-arg `amdiommu=mmio`; not executed at all by default
    //   2. Read-only, mapped with kIOMapReadOnly
    //   3. Staged: first read only EFR, one register, compared against Linux's
    //      measured value; on mismatch stop immediately, touching no other
    //      offsets
    void runM21MmioProbe();

    // ---- M2-2a-1: minimal MMIO write test ----
    //
    // Answers exactly one question: can this MMIO window be written.
    // No IOMMU enable, no device table allocation, no commands.
    //
    // Approach: write a marker to the DEV_TABLE register -> read back ->
    // restore the original -> confirm CONTROL unchanged.
    // Gate: boot-arg `amdiommu=write`.
    //
    // Why DEV_TABLE is the target: it is the only register whose write has no
    // immediate side effect -- the hardware uses it only once
    // CONTROL_IOMMU_EN is set, and the IOMMU is currently completely off.
    // Its current value is 0, so even a failed restore leaves an "unprogrammed"
    // clean state.
    void runM22aWriteProbe();

    // ---- M2-2a-2: build the device table (no enable) ----
    //
    // Allocate physically contiguous memory -> fill all pass-through DTEs ->
    // write the DEV_TABLE base register -> confirm CONTROL unchanged ->
    // restore the original value.
    //
    // **The IOMMU is not enabled.** That is this step's core value: with the
    // IOMMU off the hardware never reads the table, so system behaviour must be
    // completely unchanged, separating "is the table right" from "is it stable
    // after enable" cleanly.
    //
    // Gate: boot-arg `amdiommu=table`.
    void runM22bTableProbe();

    // ---- M2-2a-3: short-window enable test (highest risk) ----
    //
    // Walk the full Linux early_enable_iommu() enable sequence, but **disable
    // immediately after an extremely short window**:
    //   build device table -> write DEV_TABLE -> allocate command buffer ->
    //   write CMD_BUF -> reset head/tail -> CMDBUF_EN -> **IOMMU_EN** ->
    //   read STATUS -> immediately clear IOMMU_EN -> confirm off -> restore all
    //   registers
    //
    // Gate: boot-arg `amdiommu=enable`.
    //
    // Why a short window: the enable action itself may crash immediately (wrong
    // address, wrong encoding, command buffer not ready). If it crashes in a
    // short window, the configuration is fundamentally broken and a long run
    // need not be risked.
    void runM23EnableProbe();

    // ---- M2-2b-1: command channel verification ----
    //
    // M2-2a-3 only "configured" the command buffer, never issuing a command.
    // This step issues one CMD_COMPL_WAIT and verifies three things:
    //   command format correct   -> the hardware can parse it (type in
    //                               data[1]'s bit28..31)
    //   tail advance correct     -> the hardware sees the new command
    //   cmd_sem address correct  -> the hardware can write back the completion
    //
    // Gate: boot-arg `amdiommu=cmd`.
    //
    // This is an entirely new component: three memory blocks (device table /
    // command buffer / completion signal) present simultaneously, and the first
    // time the hardware is truly driven to act. Still a short window.
    void runM2b1CmdProbe();

    // ---- M2-2b-2: 4-level identity page table + single-device DTE switch ----
    //
    // M2-2b-1 proved the command channel works. This step proves the **page
    // table mechanism**:
    //   build the 4-level page table -> fill identity mappings -> enable ->
    //   CMD_INV_ALL -> switch the target device's DTE from pass-through to
    //   translation -> INV_DEV_ENTRY + INV_IOMMU_PAGES -> confirm the hardware
    //   accepts it (no fault events) -> restore everything.
    //
    // Gate: boot-arg `amdiommu=pgt`.
    //
    // New observation means: **the event log**. With EVT_LOG_EN on, the IOMMU
    // writes its own IO_PAGE_FAULT / DEV_TAB_ERR into memory we designate -- a
    // capability none of the earlier steps had; before, the only indirect
    // measure was "did the system crash".
    //
    // [2026-10-31 key fix] This function **cannot** run directly in start().
    //
    // Measured: with the RTL8127 connected via an SFP+ fibre link and a manual
    // `ifconfig en2 up`, it did DMA (Ipkts rose from 0 to 157). But after any
    // reboot, en2 returned to `media: <unknown type>` with zero packets --
    // because the probe's start() runs **earlier** than Lucy configures the
    // NIC. So "0 faults after switching" still measures nothing.
    //
    // Solution: an IOTimerEventSource defers the whole probe until after start()
    // returns (default 20 s), by which time PCI enumeration, the NIC driver and
    // link negotiation are all complete. That neither blocks boot nor performs
    // the experiment in a window with real DMA.
    void runM22b2PageTableProbe();
    void finishM22b2PageTableProbe(R33DeviceDomain *, bool finishWindow);

    // Deferred scheduling: attach a one-shot timer at the end of start(); when
    // it fires, it calls runM22b2PageTableProbe(). Returning false means
    // scheduling failed (record the property and give up).
    bool scheduleM22b2();

    // Timer callback (static, matching IOTimerEventSource::Action's signature)
    static void m22b2TimerFired(OSObject *owner, IOTimerEventSource *sender);

    // Round33: setup transfers its hardware resources to the service and
    // returns. Explicit stop launches a separate worker for drain + restore.
    bool r31SessionRequested() const;
    static void r31SessionWorker(void *parameter, wait_result_t result);
    static void r33DomainStopWorker(void *parameter, wait_result_t result);
    void r33ScheduleDomainStop();
    bool r33DomainStopPending() const;
    void r31RequestStop();

    // Leaf page size mode:
    //   false = 2 MiB large pages (covering all 16 GiB)
    //   true  = 4 KiB small pages (covering all 16 GiB, to test whether the
    //           large-page encoding is accepted by the hardware)
    // Chosen by boot-arg `amdiommu=pgt4k`.
    bool                fM22b2Use4K;

    // Long observation mode keeping translation active (`amdiommu=pgthold`).
    // The observation window extends from 2 s to M2B2_HOLD_SECS seconds with
    // the DTE pointing at the translation table throughout, easing external
    // netstat observation of whether the device still transmits normally.
    bool                fM22b2Hold;

    // Pure-sleep control (`amdiommu=pgtsleep`): keeps the DTE pass-through and
    // only performs the same 20 s IOSleep, to decide whether "the counters
    // froze" was caused by translation or by a long sleep blocking the
    // workloop.
    bool                fM22b2SleepOnly;

    // Page table level mode (`amdiommu=pgt3l`):
    //   false = PAGE_MODE_4_LEVEL (each root entry covers 512 GiB)
    //   true  = PAGE_MODE_3_LEVEL (each root entry covers 1 GiB, matching the
    //           16 GiB RAM)
    bool                fM22b2Use3L;

    // Device DMA observation (v0.21.0).
    //
    // The only question round 5 failed to answer was "was that out-of-range
    // fault's address really in use by the device". The criterion then was
    // m1bb-realmapcalls, and it was 0 -- because RTL812xLucy bypasses the
    // mapper entirely when useAppleVTD is false, using bare physical addresses.
    // That counter could therefore exclude nothing.
    //
    // The approach now is to read the device directly: from BAR2 read the TX/RX
    // descriptor ring bases, the statistics buffer base and the CounterAddr
    // register, then collect the descriptors' addresses in the rings into a
    // range set. These are addresses the device will truly access, independent
    // of whether the driver goes through a mapper.
    //
    // Read-only: no device register is written; the driver's DMA path is not
    // altered.
    void observeDeviceDma();

    // Reads the TX ring read-only and returns the count of slots with DescOwn
    // cleared; -1 = unreadable. Called once before and once after the window;
    // the difference is the in-window completion record count.
    int m2b2ScanTxDone();
    // Two window instances. Placed in members rather than on the stack: 424
    // bytes each, 848 total -- exactly the part that pushed
    // runM22b2PageTableProbe()'s frame past the __chkstk threshold.
    M22b2EventWindow fM22b2WinPre;
    M22b2EventWindow fM22b2WinMain;
    M22b2DmaObs fM22b2Dma;

    // The observed device DMA range set.
    //
    // [Why a member and not the stack]
    //   AddrSet is now 64 ranges at 32 bytes each = 2048 bytes. Placing it in
    //   runM22b2PageTableProbe()'s frame would push the total frame past the
    //   compiler's __chkstk threshold (4 KiB), producing a **weak** reference to
    //   ____chkstk_darwin in the binary and an outright kmutil refusal:
    //   "Has weak references but does not test for them."
    //   Round 6 hit exactly this trap (when M2B2_RAW_KEEP rose from 8 to 32).
    //   As a member it occupies no stack and lets step 15b and step 17 share
    //   the same snapshot.
    amdobs::AddrSet fM22b2AddrSet;

    // [Round 9] The window records' **dedicated** capacity.
    //
    // Round 8 pushed the handful of window descriptors into the AddrSet
    // (capacity 64) shared with thousands of historical RX/TX snapshots. The
    // snapshots filled it first and the window records landed in dropped, so
    // "3 submissions within the window" could have zero entries in the set.
    // Records of small controlled operations must be independent, otherwise
    // they are always queued last.
    amdobs::AddrSet fM22b2WinSet;

    // [Round 9] Staging for submit/completion pairing.
    //
    // Why a member rather than a local: ObsJoin holds 64 ObsTxOps at ~56 bytes
    // each, about 3.6 KiB total. As a local of m2b2ReadDriverObs() it would push
    // that function's frame past 4 KiB, the compiler would insert __chkstk, the
    // binary would carry a **weak** reference to ____chkstk_darwin, and kmutil
    // would refuse outright:
    //   "Has weak references but does not test for them."
    // Round 6 hit the same trap when M2B2_RAW_KEEP rose from 8 to 32.
    amdobs::ObsJoin fM22b2ObsJoin;

    // Physical layout policy (identity-mapping ceiling + RAM holes + whether
    // the layout is known)
    amdobs::MapPolicy fM22b2Policy;

    // [Round 8] Post-window descriptor lifecycle scan.
    //
    // Difference from m2b2CollectTxSegments: the latter snapshots **before** the
    // window (knowing nothing of what happened inside), while this one, **after**
    // the window, attributes each cumulative index between the window edges.
    // Results go into fM22b2Dma's win* fields.
    void m2b2ScanTxWindowAfter(const UInt8 *ring, UInt32 count);

    void m2b2CollectRxSegments(const UInt8 *ring, UInt32 count);

    // [Round 10] Collect the target NIC's identity (BDF / vendor / device / BSD
    // unit / MAC).
    //
    // [Why collected independently]
    //   The driver records themselves do not know "which card I am". If the
    //   probe does not observe identity itself, "this DMA belongs to the target
    //   device" is merely an assumption. Round 9 was exactly that.
    //
    // [Why en2 is not hard-coded]
    //   Interface numbers change with driver load order. Fetched fresh from the
    //   IORegistry: IOInterfaceUnit gives the number, IOMACAddress gives the
    //   MAC, the parent node gives the BDF. Only the three together bind "the
    //   network interface" and "the PCI function" into one thing.
    void m2b2CaptureNicIdentity();

    // [Round 11] Collect raw page table evidence for every TX/RX segment of
    // every controlled request.
    //
    // [Why it must be called before recovery]
    //   The walk uses the page table memory built for this experiment. The
    //   recovery flow frees it (after confirming the hardware stopped), after
    //   which the pointer is invalid. So the collection point must be step 17b,
    //   overlapping the interval where the DTE switch is still in effect.
    //
    // [Why the start point must be the actual DTE]
    //   Round 10's analyser had a criterion "the root table comes from the DTE",
    //   but it judged a pass outright when m2-b2-dte-root did not exist -- and
    //   that property never existed. Here instead: the target device's entry is
    //   **read back** from dte[], its mode and root table address decoded, and
    //   that used as the walk's start; the raw DTE value is exported alongside,
    //   making "the start came from the DTE" independently checkable.
    //
    // The page tables are owned by R33DeviceDomain; the diagnostics borrow these
    // pointers only while the domain is valid. After hardware recovery and the
    // diagnostics, the domain releases the page tables uniformly; the walk
    // function keeps no borrowed pointers.
    void m2b2WalkBusinessRanges(const volatile UInt64 *dte, UInt32 tgt,
                                const volatile UInt64 *ptMem,
                                UInt64 ptBasePA, UInt64 ptBytes);

    // ---- Round 14: the RX posted-buffer set ----
    //
    // m2b2RxSetRead(): reads the driver's published rtl812x-rxpost once,
    //   decoding the baseline slot table, re-post records and watermark, and
    //   constructs set S on the spot. `beforeWindow` decides its role: the
    //   pre-window read only records the watermark (re-posts with later
    //   sequence numbers then belong to this window), while the post-window
    //   read is the one that constructs the set and exports the raw bytes.
    //   On false, rxsetWhy says why; it never returns an "empty set" pretending
    //   to be a result.
    //
    // m2b2WalkRxSet(): walks every range of S against the real page table,
    //   reusing amdbw::walkRange() -- **the same** core code as the business
    //   range walks.
    //
    // m2b2PublishRxSet(): publishes the counters, each failing range and the
    //   sampled paths.
    bool m2b2RxSetRead(bool beforeWindow);
    void m2b2WalkRxSet(const volatile UInt64 *dte, UInt32 tgt,
                       const volatile UInt64 *ptMem,
                       UInt64 ptBasePA, UInt64 ptBytes);
    void m2b2PublishRxSet();

    // Shared driver reference and token storage for the historical finite
    // path and native sessions. Sessions use the R34 control, never pool RPCs.
    // The finite path alone retains the R15 ring/spare allocation domain.
    IOService *fR15Service;
    r15pool::Request fR15Request;
    UInt32 fR15PoolRpcCalls;
    UInt64 fR15MapTicks;
    UInt64 fR15InvTicks;
    bool m2b2R15Call(UInt32 op);
    bool m2b2R15PrepareMap(volatile UInt64 *pt, UInt64 ptBase,
                           UInt32 totalPages, UInt32 basePages);
    bool m2b2R15Authorize();
    void m2b2R15Finish();
    void m2b2R15Release();
    struct R15Scope {
        org_example_AMDMapperProbe *self;
        bool transferred = false;
        ~R15Scope() { if (!transferred) self->m2b2R15Release(); }
    };

    // Round 10: the controlled batch's declared request count this round;
    // 0 = not declared.
    UInt32 m2b2ReadDeclaredBatch();

    // Round 11: this round's declared run token; 0 = not declared.
    //
    // The batch criterion must bind to "this one run". Merging by reqId alone
    // stitches two different runs' records into one complete batch -- see
    // counterexample C of ObsBatchSpec in amd_iommu_dma_observe.hpp.
    UInt32 m2b2ReadDeclaredToken();

    // Round 11: bind this driver instance's epoch before the window opens.
    //
    // [Why it must precede the window]
    //   Taking the epoch inside m2b2ReadDriverObs() (after the window) would
    //   let the object under test define the test's standard. The binding point
    //   must precede the evidence.
    //
    // If it cannot be obtained, epochBound stays 0 and the reader refuses to
    // pass -- unknown is not a pass.
    void m2b2BindDriverInstance();

    // Reads the close pointer (register and width derived from ChipId).
    // Returning false = unreadable.
    bool m2b2ReadCloPtr(volatile UInt8 *bar, UInt32 *out);
    bool m2b2ReadTailPtr(volatile UInt8 *bar, UInt32 *out);

    // Writes round 7's new observation fields as defaults.
    //
    // Why needed: observeDeviceDma() has several early-return paths. If they
    // return after writing only m2-b2-dma-obs, the independent analyser sees
    // "fields missing" and can only report CANNOT ANALYSE -- equivalent to "I
    // have no data", when the fact is "the observation ran but could not
    // continue". The two mean different things, and only one of them is honest.
    void m2b2PublishDmaDefaults();

    // Mapping table operations
    MapEntry *allocMapEntry();
    bool      freeMapEntry(uint64_t pa, uint64_t len);
    uint32_t  usedMapEntries();

};
