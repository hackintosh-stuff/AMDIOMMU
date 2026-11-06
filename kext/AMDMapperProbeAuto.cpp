// Persistent per-device hardware lifecycle for amdiommu=passive.
// The experiment's timer, Lucy bindings and measurement windows are not used.
#include "AMDMapperProbeInternal.hpp"
#include "AMDMapperProbeDiscovery.hpp"
#include "amd_iommu_mapper_abi.hpp"
#include "amd_iommu_device_policy.hpp"
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSCollectionIterator.h>
#include <kern/debug.h>

namespace {
// Ordering: per-device mapper lock -> shared controller lock. Attachment
// serializes the fixed device list independently; no controller path takes
// a mapper lock or invokes the network driver.
struct LockGuard {
    IOLock *lock;
    explicit LockGuard(IOLock *value) : lock(value) { IOLockLock(lock); }
    ~LockGuard() { IOLockUnlock(lock); }
};
// Mark each selected candidate before any preparation that can fail. Drivers
// see either a completed per-device mapper or an explicit startup failure.
struct AttachPolicy {
    IOService *device;
    bool mapped = false;
    explicit AttachPolicy(IOService *value) : device(value) {
        device->setProperty(amd_iommu_policy::kProperty,
                            amd_iommu_policy::kSelected);
    }
    ~AttachPolicy() {
        device->setProperty(amd_iommu_policy::kProperty, mapped ?
            amd_iommu_policy::kMapped : amd_iommu_policy::kFailed);
    }
};

inline bool IsHexDigit(char c) {
    return ((c >= '0') && (c <= '9')) ||
           ((c >= 'a') && (c <= 'f')) ||
           ((c >= 'A') && (c <= 'F'));
}

bool ParseRequester(const char *text, UInt32 &requester) {
    requester = 0;
    for (UInt32 i = 0; i < 4; ++i) {
        const char digit = text[i];
        UInt32 value;
        if (digit >= '0' && digit <= '9') value = digit - '0';
        else if (digit >= 'a' && digit <= 'f') value = digit - 'a' + 10;
        else if (digit >= 'A' && digit <= 'F') value = digit - 'A' + 10;
        else return false;
        requester = (requester << 4) | value;
    }
    return true;
}
// The page-table area is profile-driven: mapper_abi::Profile::tablePages.
constexpr UInt32 kMaxParts = 16;  // power-of-two split fits a 1 MiB range
static_assert(mapper_abi::kMapPages <= 512, "revisit exact range command bound");

// The caller has checked that address and bytes are page-aligned and inside the domain.
UInt32 PlanRange(UInt32 opcode, UInt64 address, UInt64 bytes,
                    M2B2CmdWords (&out)[kMaxParts], UInt64 &covered) {
    UInt32 count = 0;
    covered = 0;
    while (bytes) {
        if (count == kMaxParts) return 0;  // never publish a partial plan
        UInt64 span = 4096;
        while (span <= bytes / 2 && !(address & (2 * span - 1))) span *= 2;
        const UInt64 encoded = InvRangeAddress(address, span);
        out[count++] = {0, opcode, (UInt32)encoded, (UInt32)(encoded >> 32)};
        covered += (encoded & 1) ? (2ULL << __builtin_ctzll(~(encoded >> 12))) : 1;
        address += span;
        bytes -= span;
    }
    return count;
}
// PCI IOMMU capability, not EFR: Linux v6.6 IOMMU_CAP_NPCACHE.
constexpr UInt32 kNpCache = 1u << 26;
constexpr UInt64 kEnabled = M2B2_CTRL_IOMMU_EN |
    M2B2_CTRL_CMDBUF_EN | M2B2_CTRL_EVT_LOG_EN;

bool Allocate(IOBufferMemoryDescriptor *&md, UInt64 bytes, UInt64 &pa) {
    pa = 0;
    md = IOBufferMemoryDescriptor::withCapacity((IOByteCount)bytes,
                                               kIODirectionOut, true);
    if (!md) return false;
    IOByteCount span = 0;
    pa = md->getPhysicalSegment(0, &span, kIOMemoryMapperNone);
    if (!pa || (pa & 0xfff) || span < bytes) {
        md->release();
        md = nullptr;
        pa = 0;
        return false;
    }
    bzero(md->getBytesNoCopy(), (size_t)bytes);
    return true;
}
}

// R71-B: growth allocates a domain's page-table area through the same helper the
// controller buffers use, so admission and growth cannot diverge on the 4 KiB
// alignment or on the physical-contiguity requirement.
bool org_example_AMDMapperProbe::AllocateTableArea(
    IOBufferMemoryDescriptor *&md, UInt64 bytes, UInt64 &pa) {
    return Allocate(md, bytes, pa);
}


struct org_example_AMDMapperProbe::Domain {
    IOBufferMemoryDescriptor *tables;
    UInt64 tablePA, activeTime;
    UInt32 deviceID, domainID;
    UInt64 invDevCompleted, invPagesCompleted;
    UInt64 invFullCompleted, invRangeCompleted, invRangePages, invRangeCoveredPages;
    UInt64 mapInvalidationSkipped;
    UInt64 lastRangeAddress, lastRangeBytes, lastRangeSequence;
    UInt64 rangeDescriptors, splitBatches, splitAddress, splitBytes, splitSequence;
    UInt32 splitCount;
    M2B2CmdWords splitWords[kMaxParts];
    UInt32 lastRangeCommand[4];
    UInt64 lastInvDevSequence, lastInvPagesSequence;
    UInt64 parkCount, restoreCount, gateDevSequence, gatePagesSequence;
    // R65: per-requester participation in a coordinated shared-controller PM cycle.
    bool pmSuspendReady, pmResumeReady;
    // R66-2: retain this domain's PM evidence across later ordinary invalidations.
    UInt64 pmSuspends, pmResumes, pmSuspendSequence;
    UInt64 pmResumeDevSequence, pmResumePagesSequence;
    void recordPMResume() {
        ++pmResumes;
        pmResumeDevSequence = lastInvDevSequence;
        pmResumePagesSequence = lastInvPagesSequence;
    }
    UInt64 targetFaults;
    UInt32 lastEvent[4];
    // S2: the admission record for this domain. Shown per device so a refused
    // or legacy domain cannot be mistaken for a pool-sized one.
    const char *profileName;
    UInt32 profileRecords, profilePages, tablePages;
    // R71-B: the arena is prepared at profileName and may grow once, at the first
    // mapping, to this ceiling (nullptr before prepare finishes).
    const mapper_abi::Profile *ceilingProfile;
    const char *state;
    bool active;
};

struct org_example_AMDMapperProbe::Controller {
    IOBufferMemoryDescriptor *devices, *commands, *semaphore, *events;
    IOLock *lock;
    Domain *domains[kMaxDomains];
    UInt32 domainCount;
    IOMemoryDescriptor *mmioMemory;
    IOMemoryMap *mmioMap;
    volatile UInt8 *base;
    UInt64 devicePA, commandPA, semaphorePA, eventPA;
    UInt64 originalDT, originalCommand, originalEvent, originalControl;
    HardwareInfo hardware;
    UInt64 startupEfr;
    UInt64 readyTime;
    UInt64 eventEntries, targetFaults;
    UInt64 sleepControl, observedControl;
    UInt64 suspendTime, resumeTime, suspendSequence;
    UInt64 resumeDevSequence, resumePagesSequence;
    UInt64 suspendCount, resumeCount, powerFailures;
    UInt32 lastEvent[4];
    M2B2HeadCache headCache;
    M2B2CmdCtx command;
    const char *state;
    bool configured, ready, pinned, restored;
    bool eventOverflow, eventInvalid;
    bool suspended, powerFailed, resumeRegistersRestored;
    bool coordinatedPMArmed = false;

    // The driver has already stopped DMA. Stop the hardware producers before
    // changing their ring pointers or returning the controller to firmware.
    bool stopHardware() {
        UInt64 ctrl = mmioRead64(base, M2B2_OFF_CONTROL);
        ctrl &= ~(M2B2_CTRL_CMDBUF_EN | M2B2_CTRL_EVT_LOG_EN);
        mmioWrite64(base, M2B2_OFF_CONTROL, ctrl);
        UInt32 status = 0;
        for (UInt32 i = 0; i < M2B1_LOOP_TIMEOUT; ++i) {
            status = mmioRead32(base, M2B2_OFF_STATUS);
            if (!(status & (M2B2_STATUS_CMDBUF_RUN | M2B2_STATUS_EVT_RUN)))
                break;
        }
        ctrl = mmioRead64(base, M2B2_OFF_CONTROL) & ~M2B2_CTRL_IOMMU_EN;
        mmioWrite64(base, M2B2_OFF_CONTROL, ctrl);
        observedControl = mmioRead64(base, M2B2_OFF_CONTROL);
        return !(status & (M2B2_STATUS_CMDBUF_RUN | M2B2_STATUS_EVT_RUN)) &&
            !(observedControl & kEnabled);
    }

    // TAIL belongs to the event producer. Consume the final events after it
    // stops, before a resume resets the ring. Fault history stays cumulative.
    void collectEvents() {
        const UInt32 status = mmioRead32(base, M2B2_OFF_STATUS);
        if (status & M2B2_STATUS_EVT_OVERFLOW) eventOverflow = true;
        UInt64 head = mmioRead64(base, M2B2_OFF_EVT_HEAD);
        const UInt64 tail = mmioRead64(base, M2B2_OFF_EVT_TAIL);
        if (head >= M2B2_EVT_BUFFER_SIZE || tail >= M2B2_EVT_BUFFER_SIZE ||
            ((head | tail) & 15)) eventInvalid = true;
        else {
            const volatile UInt32 *entries =
                (volatile UInt32 *)events->getBytesNoCopy();
            while (head != tail) {
                const UInt32 entry = (UInt32)head / 4;
                const UInt32 type = entries[entry + 1] >> M2B2_EVENT_TYPE_SHIFT;
                if (!type) { eventInvalid = true; break; }
                for (UInt32 i = 0; i < 4; ++i) lastEvent[i] = entries[entry + i];
                ++eventEntries;
                for (UInt32 slot = 0; slot < kMaxDomains; ++slot) {
                    Domain *d = domains[slot];
                    if (!d || (lastEvent[0] & M2B2_EVENT_DEVID_MASK) != d->deviceID)
                        continue;
                    ++d->targetFaults;
                    ++targetFaults;
                    for (UInt32 i = 0; i < 4; ++i) d->lastEvent[i] = lastEvent[i];
                }
                head = (head + 16) % M2B2_EVT_BUFFER_SIZE;
            }
            mmioWrite64(base, M2B2_OFF_EVT_HEAD, head);
        }
    }

    bool powerFailure(const char *reason) {
        ready = false;
        suspended = true;
        powerFailed = true;
        state = reason;
        ++powerFailures;
        return false;
    }

    bool restore() {
        if (!configured) { restored = true; return true; }
        if (suspended || !stopHardware()) return false;
        mmioWrite64(base, M2B2_OFF_DEV_TABLE, originalDT);
        mmioWrite64(base, M2B2_OFF_CMD_BUF, originalCommand);
        mmioWrite64(base, M2B2_OFF_EVT_BUF, originalEvent);
        mmioWrite64(base, M2B2_OFF_CONTROL, originalControl);
        OSSynchronizeIO();
        observedControl = mmioRead64(base, M2B2_OFF_CONTROL);
        restored = mmioRead64(base, M2B2_OFF_DEV_TABLE) == originalDT &&
            mmioRead64(base, M2B2_OFF_CMD_BUF) == originalCommand &&
            mmioRead64(base, M2B2_OFF_EVT_BUF) == originalEvent &&
            observedControl == originalControl;
        if (restored) { configured = false; ready = false; }
        return restored;
    }

    void releaseBuffers() {
        if (mmioMap) mmioMap->release();
        if (mmioMemory) mmioMemory->release();
        if (events) events->release();
        if (semaphore) semaphore->release();
        if (commands) commands->release();
        if (devices) devices->release();
        if (lock) IOLockFree(lock);
    }
};


bool org_example_AMDMapperProbe::ReadDeviceSelection() {
    char selection[32] = {};
    fSelectionExplicit = PE_parse_boot_argn("amdiommu_devices", selection,
                                              sizeof(selection) - 1);
    fRequesterCount = 0;
    if (!fSelectionExplicit) {
        setProperty("device-selection", "default-rtl8127");
        return true;
    }
    // One to kMaxDomains four-hex-digit segment-zero requester IDs, no
    // saved BDFs. The third slot is reserved for a Mellanox adapter next to the
    // two RTL8127 ports; the selected-pair semantics are unchanged.
    // R70-S5f: values are written with a non-hex prefix (n3400) because the
    // kernel converts an all-digit boot-arg value into a 32-bit integer
    // inside the caller's buffer (observed: "3400" arrived as 0x0D48).
    // So: skip every non-hex byte before each ID, then parse four hex digits.
    const char *cursor = selection;
    while (true) {
        while (*cursor && !IsHexDigit(*cursor)) ++cursor;
        if (!*cursor) break;
        if (fRequesterCount == kMaxDomains) {
            setProperty("iommu-state", "failed-device-selection");
            return false;
        }
        UInt32 id = 0;
        if (!ParseRequester(cursor, id)) {
            setProperty("iommu-state", "failed-device-selection");
            return false;
        }
        for (UInt32 i = 0; i < fRequesterCount; ++i) {
            if (fRequesters[i] == id) {
                setProperty("iommu-state", "failed-device-selection");
                return false;
            }
        }
        fRequesters[fRequesterCount++] = id;
        cursor += 4;
    }
    if (!fRequesterCount) {
        setProperty("iommu-state", "failed-device-selection");
        return false;
    }
    setProperty("device-selection", selection);
    setProperty("device-selection-count", fRequesterCount, 32);
    return true;
}

// S1/R71-B: this selects the *ceiling* a domain may grow to, not the arena it is
// prepared with. Growth happens at the first mapping (GrowBeforeFirstMap), so
// the value published here says how far that growth may go.
bool org_example_AMDMapperProbe::SelectProfile() {
    char requested[24] = {};
    const bool named = PE_parse_boot_argn("amdiommu_profile", requested,
                                          sizeof(requested) - 1) != 0;
    bool forced = false;
    const mapper_abi::Profile *ceiling = Ceiling(forced);
    fProfile = *ceiling;
    fProfileForced = forced;
    if (named) setProperty("iommu-profile-request", requested);
    setProperty("iommu-profile-mode", forced ? "forced" : "first-map-growth");
    setProperty("iommu-profile", ceiling->name);
    setProperty("iommu-profile-ceiling", ceiling->name);
    setProperty("iommu-profile-records", ceiling->records, 32);
    setProperty("iommu-profile-pages", ceiling->pages, 32);
    setProperty("iommu-profile-table-pages", ceiling->tablePages, 32);
    // An unknown name must never widen the pool. It is reported as refused and
    // leaves the legacy ceiling in place, which also disables growth.
    return !named || mapper_abi::profileForName(requested) != nullptr;
}

// The ceiling is a per-instance decision: every attached device owns its own
// mapper instance and the boot argument is parsed again for each of them, so an
// override can never be lost to whichever instance ran first (R70-S3b).
const mapper_abi::Profile *org_example_AMDMapperProbe::Ceiling(bool &forced) const {
    forced = false;
    char requested[24] = {};
    if (!PE_parse_boot_argn("amdiommu_profile", requested, sizeof(requested) - 1))
        return &mapper_abi::kProfileRl10gMax;
    forced = true;
    if (const mapper_abi::Profile *picked = mapper_abi::profileForName(requested))
        return picked;
    return &mapper_abi::kProfileLegacy;
}

// Vendor/device IDs come from the device-tree properties OpenCore already
// publishes, so S2 never touches PCI config space before admission.
static bool pciIdProperty(IORegistryEntry *entry, const char *key, UInt32 &value) {
    OSData *data = OSDynamicCast(OSData, entry->getProperty(key));
    if (!data || data->getLength() < sizeof(UInt32)) return false;
    value = *(const UInt32 *)data->getBytesNoCopy();
    return true;
}

// The boot-arg override is parsed on every call. Each attached device gets its
// own mapper instance (see AttachAuto), so an admission decision must never
// depend on which instance happened to run SelectProfile first - R70-S3b
// showed a device admitted with the legacy arena while the controller instance
// reported the forced profile.
const mapper_abi::Profile *org_example_AMDMapperProbe::ForcedProfile() const {
    char requested[24] = {};
    if (!PE_parse_boot_argn("amdiommu_profile", requested, sizeof(requested) - 1))
        return nullptr;
    return mapper_abi::profileForName(requested);
}

// S2 admission input: which capacity does this device need *before* a domain
// exists? Pure decision helper: the caller reads the registry identity before
// it takes fAttachLock. Doing that lookup under the attach lock was observed
// to stall the boot on the first non-forced attach (R70-S6), so this function
// must never touch the registry itself.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
const mapper_abi::Profile *org_example_AMDMapperProbe::ProfileForDevice(
    UInt32 vendor, UInt32 device, UInt32 classCode,
    mapper_abi::ProfileSource *source) const {
    if (source) *source = mapper_abi::ProfileSource::legacy;
    if (const mapper_abi::Profile *forced = ForcedProfile()) {
        if (source) *source = mapper_abi::ProfileSource::bootArg;
        return forced;
    }
    if (!fAutoAttach) return &mapper_abi::kProfileLegacy;
    return mapper_abi::profileForDevice(vendor, device, true, classCode, source);
}
#pragma clang diagnostic pop

bool org_example_AMDMapperProbe::StartAuto() {
    IOLog("AMDMapperProbe: auto-start enter\n");
    setProperty("iommu-mode", "passive");
    setProperty("iommu-role", "controller");
    setProperty("snapshot-consistency", "per-domain");
    setProperty("iommu-max-domains", kMaxDomains, 32);
    setProperty("iommu-domain-count", 0ULL, 64);
    setProperty("iommu-state", "waiting-for-pci-publication");
    setProperty("iommu-controller-ready", "no");
    setProperty("iommu-system-mapper", "no");
    setProperty("iomapper-gsystem", IOMapper::gSystem ? "NONNULL" : "NULL-as-expected");
    if (!ReadDeviceSelection()) {
        return false;
    }
    // R69: Apple's own Ethernet kexts only ask IOMapper::copyMapperForDevice(),
    // so they can never call AMDIOMMUClaimRequesterV1. amdiommu=auto-attach is
    // the only switch: it publishes iommu-parent at first publish (before their
    // probe) for the selected requesters only. Plain amdiommu=passive keeps
    // the offer/claim protocol intact.
    setProperty("auto-attach", fAutoAttach ? "yes" : "no");
    SelectProfile();
    fAttachLock = IOLockAlloc();
    if (!fAttachLock) return false;
    installPublishNotifier();
    if (!fPublishNotifier) {
        setProperty("iommu-state", "failed-publish-notifier");
        IOLockFree(fAttachLock); fAttachLock = nullptr;
        return false;
    }
    // Offer explicit requesters to pre-open clients; keep eager attach for the default.
    // Replay published endpoints through the same path as the notification.
    AttachExistingDevices();
    PublishDomains();
    return true;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
bool org_example_AMDMapperProbe::AttachAuto(IOService *service, bool claim) {
    if (!fAuto || fOwner || !fAttachLock) return false;
    IOPCIDevice *nic = OSDynamicCast(IOPCIDevice, service);
    if (!nic) return false;
    // A config-space cycle on this device can stall the notification thread,
    // so take the identity from the registry properties instead.
    UInt32 vendorId = 0, deviceId = 0;
    pciIdProperty(nic, "vendor-id", vendorId);
    pciIdProperty(nic, "device-id", deviceId);
    const UInt16 vendor16 = (UInt16)(vendorId & 0xffffU);
    const UInt16 device16 = (UInt16)(deviceId & 0xffffU);
    const UInt32 requester = ((UInt32)nic->getBusNumber() << 8) |
        ((UInt32)nic->getDeviceNumber() << 3) | nic->getFunctionNumber();
    UInt32 match = 0;
    while (match < fRequesterCount && fRequesters[match] != requester) ++match;
    if (match == fRequesterCount) {
        // Only the legacy default and known unselected clients need model IDs.
        if (claim || vendor16 != 0x10ec) return false;
        if (device16 != 0x8127 && device16 != 0x8168) return false;
        if (fSelectionExplicit || device16 != 0x8127) {
            nic->setProperty(amd_iommu_policy::kProperty, amd_iommu_policy::kPassthrough);
            return false;
        }
    }
    // Registry identity and profile must be resolved before fAttachLock:
    // a device property lookup performed while the attach lock was held stalled
    // the boot as soon as the profile was derived per device (R70-S6). Only the
    // already-resolved profile is passed down from here.
    UInt32 classCode = 0;
    pciIdProperty(nic, "class-code", classCode);
    mapper_abi::ProfileSource profileSource = mapper_abi::ProfileSource::legacy;
    const mapper_abi::Profile *deviceProfile =
        ProfileForDevice(vendor16, device16, classCode, &profileSource);
    LockGuard attachment(fAttachLock);
    if (fStopping) return false;
    if (fSelectionExplicit) {
        IOService *&offered = fOffers[match];
        // A client that claims keeps the R54 ordering guarantees: the offer was
        // published before its PCI open and this call must match that record.
        if (!claim && !fAutoAttach) {
            if (offered) return offered == nic;  // first publish or replay
            if (nic->isOpen() || nic->getProperty("iommu-parent")) {
                setProperty("attach-failure", "already-open-or-bound");
                setProperty("attach-rejected-requester", requester, 32);
                nic->setProperty(amd_iommu_policy::kProperty, amd_iommu_policy::kFailed);
                return false;
            }
            if (!nic->setProperty(amd_iommu_policy::kProperty, amd_iommu_policy::kSelected) ||
                !nic->setProperty(amd_iommu_policy::kOffer, this)) {
                nic->setProperty(amd_iommu_policy::kProperty, amd_iommu_policy::kFailed);
                return false;
            }
            nic->retain();
            offered = nic;
            return true;  // no mapper, page table or translated DTE yet
        }
        if (claim) {
            if (offered != nic || nic->getProperty(amd_iommu_policy::kOffer) != this)
                return false;
            nic->removeProperty(amd_iommu_policy::kOffer);
        }
    }
    AttachPolicy policy(nic);
    ++fPublishHits;
    setProperty("publish-hits", (unsigned long long)fPublishHits, 64);
    UInt32 slot = kMaxDomains;
    for (UInt32 i = 0; i < kMaxDomains; ++i) {
        auto *mapper = fMappers[i];
        if (!mapper) { if (slot == kMaxDomains) slot = i; continue; }
        if (mapper->fNicDevice == nic) { policy.mapped = true; return true; }
        if (mapper->fDomain && mapper->fDomain->deviceID == requester) {
            setProperty("attach-failure", "duplicate-requester");
            return false;
        }
    }
    if (slot == kMaxDomains) {
        setProperty("attach-failure", "domain-capacity");
        return false;
    }
    if (nic->isOpen() || (claim && nic->getProperty("iommu-parent"))) {
        setProperty("attach-failure", "already-open-or-bound");
        setProperty("attach-rejected-requester", requester, 32);
        return false;
    }
    auto *mapper = new org_example_AMDMapperProbe;
    if (!mapper) return false;
    if (!mapper->init()) { mapper->release(); return false; }
    mapper->fOwner = this;
    mapper->setName("AMDMapperDevice");
    if (!mapper->attach(this)) { mapper->release(); return false; }
    if (!mapper->start(this)) {
        mapper->detach(this); mapper->release(); return false;
    }
    if (!mapper->PrepareDomain(nic, slot, deviceProfile, profileSource)) {
        setProperty("attach-failure", "device-prepare");
        setProperty("attach-rejected-requester", requester, 32);
        mapper->ReleaseDomain();
        mapper->stop(this);
        mapper->detach(this); mapper->release();
        return false;
    }
    fMappers[slot] = mapper;
    policy.mapped = true;
    mapper->registerService();
    return true;
}
#pragma clang diagnostic pop

bool org_example_AMDMapperProbe::PrepareController(const HardwareInfo &hardware) {
    if (fController) {
        LockGuard guard(fController->lock);
        const auto &found = fController->hardware;
        // This round deliberately owns one IVRS unit. The second requester
        // must resolve to that same unit; never reprogram its shared registers.
        return fController->ready && !fController->suspended &&
            !fController->command.failed &&
            found.mmioBase == hardware.mmioBase &&
            found.mmioBytes == hardware.mmioBytes &&
            found.iommuID == hardware.iommuID &&
            found.capabilityHeader == hardware.capabilityHeader;
    }
    auto *c = (Controller *)IOMalloc(sizeof(Controller));
    if (!c) return false;
    bzero(c, sizeof(*c));
    c->lock = IOLockAlloc();
    c->hardware = hardware;
    c->state = "preparing";
    fController = c;
    const char *failure = nullptr;
    if (!c->lock ||
        !Allocate(c->devices, M22B_TABLE_SIZE_FULL, c->devicePA) ||
        !Allocate(c->commands, M23_CMD_BUF_SIZE, c->commandPA) ||
        !Allocate(c->semaphore, M2B2_PAGE_SIZE, c->semaphorePA) ||
        !Allocate(c->events, M2B2_EVT_BUFFER_SIZE, c->eventPA)) {
        failure = "failed-dma-memory";
    }

    if (!failure) {
        // IVRS ownership and the matching PCI capability/BAR were checked
        // before allocating the backend. Map only the basic register window.
        c->mmioMemory = IOMemoryDescriptor::withPhysicalAddress(
            (IOPhysicalAddress)c->hardware.mmioBase,
            (IOByteCount)c->hardware.mmioBytes, kIODirectionNone);
        if (c->mmioMemory)
            c->mmioMap = c->mmioMemory->map(kIOMapInhibitCache | kIOMapAnywhere);
        if (!c->mmioMap) failure = "failed-mmio-map";
        else {
            c->base = (volatile UInt8 *)c->mmioMap->getVirtualAddress();
            if (c->hardware.pciEfrSupported)
                c->startupEfr = mmioRead64(c->base, M21_OFF_EXT_FEAT);
            setProperty("iommu-mmio-efr", (unsigned long long)c->startupEfr, 64);
            // Host four-level translation, INV_DEV/INV_PAGES and CW are the
            // basic path. Guest/PASID/performance EFR bits are not requirements.
            // If firmware supplies an EFR image, verify the same unit's actual
            // register instead of requiring this board's former fixed value.
            if ((c->hardware.pciEfrSupported && c->startupEfr == ~0ULL) ||
                (c->hardware.firmwareEfrPresent &&
                 (!c->hardware.pciEfrSupported ||
                  c->startupEfr != c->hardware.firmwareEfr))) {
                setProperty("iommu-efr-match", "no");
                failure = "failed-iommu-efr";
            } else {
                setProperty("iommu-efr-match", !c->hardware.pciEfrSupported ?
                    "not-reported" : (c->hardware.firmwareEfrPresent ?
                    "yes" : "firmware-absent"));
            }
        }
        setProperty("discovery-state", failure ? failure : "ready");
    }
    if (!failure) {
        c->originalDT = mmioRead64(c->base, M2B2_OFF_DEV_TABLE);
        c->originalCommand = mmioRead64(c->base, M2B2_OFF_CMD_BUF);
        c->originalEvent = mmioRead64(c->base, M2B2_OFF_EVT_BUF);
        c->originalControl = mmioRead64(c->base, M2B2_OFF_CONTROL);
        if (c->originalControl & kEnabled)
            failure = "failed-iommu-already-enabled";
    }
    if (failure) {
        setProperty("iommu-state", failure);
        c->releaseBuffers();
        fController = nullptr;
        IOFree(c, sizeof(*c));
        return false;
    }

    volatile UInt64 *dte = (volatile UInt64 *)c->devices->getBytesNoCopy();
    for (UInt32 i = 0; i < M22B_TABLE_SIZE_FULL / M22B_DTE_SIZE; ++i)
        dte[i * 4] = DTE_V | DTE_TV | DTE_IR | DTE_IW;
    c->command.buf = (volatile UInt32 *)c->commands->getBytesNoCopy();
    c->command.sem = (volatile UInt64 *)c->semaphore->getBytesNoCopy();
    c->command.semPA = c->semaphorePA;
    c->command.headCache = &c->headCache;
    c->command.pageMode = M2B2_PAGE_MODE_4_LEVEL;

    OSSynchronizeIO();
    c->configured = true;
    mmioWrite64(c->base, M2B2_OFF_DEV_TABLE,
        c->devicePA | ((M22B_TABLE_SIZE_FULL >> 12) - 1));
    mmioWrite64(c->base, M2B2_OFF_CMD_BUF, c->commandPA | M23_CMD_SIZE_CODE);
    mmioWrite64(c->base, M2B2_OFF_EVT_BUF, c->eventPA | M2B2_EVT_LEN_MASK);
    mmioWrite64(c->base, M2B2_OFF_CMD_HEAD, 0);
    mmioWrite64(c->base, M2B2_OFF_CMD_TAIL, 0);
    mmioWrite64(c->base, M2B2_OFF_EVT_HEAD, 0);
    mmioWrite64(c->base, M2B2_OFF_EVT_TAIL, 0);
    UInt64 control = c->originalControl | M2B2_CTRL_CMDBUF_EN;
    mmioWrite64(c->base, M2B2_OFF_CONTROL, control);
    control |= M2B2_CTRL_EVT_LOG_EN;
    mmioWrite64(c->base, M2B2_OFF_CONTROL, control);
    control |= M2B2_CTRL_IOMMU_EN;
    mmioWrite64(c->base, M2B2_OFF_CONTROL, control);
    if ((mmioRead64(c->base, M2B2_OFF_CONTROL) & kEnabled) != kEnabled) {
        c->state = "failed-controller-enable";
        setProperty("iommu-failure", c->state);
        if (c->restore()) {
            c->releaseBuffers();
            fController = nullptr;
            IOFree(c, sizeof(*c));
        } else if (!c->pinned) {
            c->pinned = true;
            retain();
        }
        return false;
    }

    c->ready = true;
    c->readyTime = mach_absolute_time();
    c->state = "ready-shared-controller";
    return true;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
bool org_example_AMDMapperProbe::PrepareDomain(
    IOService *service, UInt32 slot, const mapper_abi::Profile *requestedIn,
    mapper_abi::ProfileSource sourceIn) {
    IOPCIDevice *nic = OSDynamicCast(IOPCIDevice, service);
    if (!fOwner || !nic || slot >= kMaxDomains) return false;
    const mapper_abi::Profile *requested = requestedIn;
    HardwareInfo hardware{};
    if (!DiscoverHardware(this, nic, hardware)) return false;
    auto *d = (Domain *)IOMalloc(sizeof(Domain));
    if (!d) return false;
    bzero(d, sizeof(*d));
    fDomain = d;
    d->domainID = slot + 1;
    d->deviceID = ((UInt32)nic->getBusNumber() << 8) |
        ((UInt32)nic->getDeviceNumber() << 3) | nic->getFunctionNumber();
    d->state = "preparing";
    // R71-B: capacity is no longer guessed from identity before the client has
    // ever mapped. R70-S3 proved that refusing is NOT a safe passthrough for
    // Apple's client: with no iommu-parent its kMapped IODMACommand gets NULL and
    // IOSkywalk panics on 0xe00002be exactly like capacity exhaustion. So every
    // domain is prepared - at the legacy arena, the smallest one and the only one
    // that cannot fail for size - and may grow at its first mapping to the
    // ceiling this device is admitted for.
    mapper_abi::ProfileSource source = sourceIn;
    if (!requested) requested = &mapper_abi::kProfileLegacy;
    char requestedName[24] = {};
    const bool named = PE_parse_boot_argn("amdiommu_profile", requestedName,
                                          sizeof(requestedName) - 1) != 0;
    const bool unsupported =
        named && mapper_abi::profileForName(requestedName) == nullptr;
    bool forcedCeiling = false;
    const mapper_abi::Profile *ceiling = Ceiling(forcedCeiling);
    // The claim path is the verified R67-2 configuration: it keeps the arena it
    // was accepted with unless an operator raises the ceiling explicitly.
    if (!forcedCeiling && !(fOwner && fOwner->fAutoAttach))
        ceiling = &mapper_abi::kProfileLegacy;
    const mapper_abi::Profile *prepared = &mapper_abi::kProfileLegacy;
    const bool growth =
        mapper_abi::profileForFirstMapGrowth(prepared, ceiling) != nullptr;
    // Per-instance admission evidence: the device mapper is its own instance,
    // so record whether this instance saw the boot-arg override at all.
    nic->setProperty("iommu-attach-forced", ForcedProfile() ? "yes" : "no");
    nic->setProperty("iommu-attach-instance", getRegistryEntryID(), 64);
    nic->setProperty("iommu-profile-source",
        source == mapper_abi::ProfileSource::bootArg ? "boot-arg"
        : (source == mapper_abi::ProfileSource::idTable ? "id-table"
        : (source == mapper_abi::ProfileSource::classTable ? "class-table"
                                                          : "legacy-fallback")));
    // The identity table is advisory now: it sets the admission ceiling and
    // records what identity-based sizing would have picked. It cannot cost a real
    // client its arena any more, because the arena starts at legacy and grows
    // from demand.
    nic->setProperty("iommu-profile-suggested", requested->name);
    nic->setProperty("iommu-profile-prepared", prepared->name);
    nic->setProperty("iommu-profile-ceiling-source",
                     forcedCeiling ? "boot-arg" : "default");
    nic->setProperty("iommu-profile-ceiling",
                     unsupported ? "unsupported-name" : ceiling->name);
    nic->setProperty("iommu-growth-policy", growth ? "first-map" : "disabled");
    nic->setProperty("iommu-capacity-grown", "no");
    nic->setProperty("iommu-profile", prepared->name);
    const UInt64 preparedBytes = mapper_abi::arenaBytesFor(*prepared);
    const bool preparedOK = preparedBytes &&
        preparedBytes <= mapper_abi::kMaxArenaBytes &&
        prepared->tablePages >= prepared->pages / 512 + 2 &&
        AllocateTableArea(d->tables,
            (UInt64)prepared->tablePages * M2B2_PAGE_SIZE, d->tablePA) &&
        PrepareMappings((volatile UInt64 *)d->tables->getBytesNoCopy(),
            d->tablePA, prepared->tablePages, M2B2_PAGE_MODE_4_LEVEL, *prepared);
    if (!preparedOK) {
        nic->setProperty("admission", "refused-no-arena");
        IOLog("AMDMapperProbe: admission refused, the legacy arena did not prepare\n");
        if (fAutoAttach)
            panic("AMDMapperProbe: admission-refused: legacy arena did not prepare");
        if (d->tables) { d->tables->release(); d->tables = nullptr; }
        return false;
    }
    d->profileName = prepared->name;
    d->profileRecords = prepared->records;
    d->profilePages = prepared->pages;
    d->tablePages = prepared->tablePages;
    d->ceilingProfile = ceiling;
    const char *admission = growth
        ? (ceiling == &mapper_abi::kProfileRl10gMax
               ? "granted-rl-10g-max-on-demand" : "granted-rl-10g-on-demand")
        : "granted-native-legacy";
    nic->setProperty("admission", admission);
    IOLog("AMDMapperProbe: domain %u prepared %s, ceiling %s (growth %s)\n",
          slot, prepared->name, unsupported ? "unsupported-name" : ceiling->name,
          growth ? "first-map" : "disabled");
    if (!fOwner->PrepareController(hardware)) return false;
    Controller *c = fOwner->fController;
    fController = c;
    {
        LockGuard guard(c->lock);
        c->domains[slot] = d;
        ++c->domainCount;
        d->state = "ready-passthrough";
    }
    nic->retain(); fNicDevice = nic;
    setProperty("attach-requester-id", d->deviceID, 32);
    setProperty("mapper-entry-id", getRegistryEntryID(), 64);
    setProperty("owner-entry-id", fOwner->getRegistryEntryID(), 64);
    setProperty("device-entry-id", nic->getRegistryEntryID(), 64);
    setProperty("iommu-mmio-efr", c->startupEfr, 64);
    setProperty("iommu-efr-match", c->hardware.pciEfrSupported ?
        (c->hardware.firmwareEfrPresent ? "yes" : "firmware-absent") : "not-reported");
    // Identity and a complete domain snapshot precede copyMapperForDevice().
    // Only first map activates this endpoint's DTE, after the endpoint driver's reset.
    PublishMappings();
    if (!nic->setProperty("iommu-parent", this)) return false;
    setProperty("iommu-parent-policy", fOwner->fAutoAttach
        ? "set-at-first-publish-autoattach"
        : (fOwner->fSelectionExplicit
            ? "set-on-client-claim-before-pci-open" : "set-before-driver-start"));
    return true;
}
#pragma clang diagnostic pop

// R71-B: growth reads and updates the domain through these four calls. The
// domain struct is private to this file while the rebuild itself lives with
// MapperState, so neither translation unit needs the other's type.
bool org_example_AMDMapperProbe::GrowthOpen() const {
    Domain *d = fDomain;
    return d && !d->active;
}

const mapper_abi::Profile *org_example_AMDMapperProbe::PreparedProfile() const {
    Domain *d = fDomain;
    return d ? mapper_abi::profileForName(d->profileName) : nullptr;
}

const mapper_abi::Profile *org_example_AMDMapperProbe::CeilingProfile() const {
    Domain *d = fDomain;
    return d ? d->ceilingProfile : nullptr;
}

void org_example_AMDMapperProbe::AdoptGrownTables(
    IOBufferMemoryDescriptor *tables, UInt64 tablePA, UInt32 tablePages,
    const mapper_abi::Profile &target) {
    Domain *d = fDomain;
    if (!d) return;
    // The DTE is written from tablePA at first activation, which is still ahead:
    // nothing in the hardware refers to the area this call replaces.
    IOBufferMemoryDescriptor *old = d->tables;
    d->tables = tables;
    d->tablePA = tablePA;
    d->tablePages = tablePages;
    d->profileName = target.name;
    d->profileRecords = target.records;
    d->profilePages = target.pages;
    if (old) old->release();
}

bool org_example_AMDMapperProbe::ReleaseDomain() {
    Domain *d = fDomain;
    Controller *c = fController;
    if (!d) return QuiesceMappings() && ReleaseMappings();
    // Active roots are released only after the shared owner restored hardware.
    if (c && c->configured && d->active) return false;
    if (!QuiesceMappings() || !ReleaseMappings()) return false;
    if (c) {
        LockGuard guard(c->lock);
        for (UInt32 i = 0; i < kMaxDomains; ++i) {
            if (c->domains[i] != d) continue;
            c->domains[i] = nullptr; --c->domainCount;
        }
    }
    if (d->tables) d->tables->release();
    fDomain = nullptr; fController = nullptr;
    IOFree(d, sizeof(*d));
    return true;
}


bool org_example_AMDMapperProbe::Invalidate(
    bool invalidateDevice, UInt64 address, UInt64 bytes,
    bool newMapping, bool *skipped) {
    if (skipped) *skipped = false;
    Controller *c = fController;
    if (!c || !fDomain) return false;
    LockGuard guard(c->lock);
    return InvalidateLocked(invalidateDevice, address, bytes, newMapping, skipped);
}

bool org_example_AMDMapperProbe::InvalidateLocked(
    bool invalidateDevice, UInt64 address, UInt64 bytes,
    bool newMapping, bool *skipped) {
    // Both the caller's mapper lock and shared controller lock are held.
    // One queue cursor and CompletionWait sequence serve all device domains.
    if (skipped) *skipped = false;
    Controller *c = fController;
    Domain *d = fDomain;
    if (!c || !d || !c->ready || c->command.failed) return false;
    const bool full = !d->active || invalidateDevice || !bytes;
    const UInt64 windowBytes = (UInt64)d->profilePages * 4096ULL;
    if (!full && (((address | bytes) & 4095ULL) ||
        address < mapper_abi::kBase ||
        address - mapper_abi::kBase >= windowBytes ||
        bytes > windowBytes - (address - mapper_abi::kBase)))
        return false;
    OSSynchronizeIO();
    // Upper-level tables are prebuilt and ordinary maps fill only empty leaves.
    // Unmap still waits for invalidation before returning IOVA to the allocator.
    // With no non-present cache, a new mapping therefore needs no INV/CW.
    // First activation, explicit device flush and PM always retain their fence.
    if (newMapping && !full && !(c->hardware.capabilityHeader & kNpCache)) {
        ++d->mapInvalidationSkipped;
        if (skipped) *skipped = true;
        return true;
    }
    c->command.devid = d->deviceID;
    c->command.domid = d->domainID;
    c->command.rootPA = d->tablePA;
    if (!d->active || invalidateDevice) {
        volatile UInt64 *dte = (volatile UInt64 *)c->devices->getBytesNoCopy();
        dte[d->deviceID * 4 + 1] = d->domainID;
        dte[d->deviceID * 4] = (d->tablePA & M2B2_PTE_ADDR_MASK) |
            ((UInt64)M2B2_PAGE_MODE_4_LEVEL << M2B2_DEV_ENTRY_MODE_SHIFT) |
            DTE_V | DTE_TV | (fDMAParked ? 0 : (DTE_IR | DTE_IW));
        OSSynchronizeIO();
        if (!m2b2Submit(c->base, &c->command, "activate-device", d->deviceID,
                ((UInt32)M2B2_CMD_INV_DEV_ENTRY << 28), 0, 0)) {
            d->state = "failed-device-invalidation";
            return false;
        }
        ++d->invDevCompleted;
        d->lastInvDevSequence = c->command.completionSequence;
    }
    // First activation and power transitions still flush the complete domain
    // and PDE cache. Ordinary maps only edit leaves of the prebuilt IOVA tree.
    M2B2CmdWords cmd[kMaxParts];
    const UInt32 opcode = d->domainID | ((UInt32)M2B2_CMD_INV_IOMMU_PAGES << 28);
    UInt32 count = 1;
    UInt64 covered = 0;
    if (full) {
        const UInt64 encoded = m2b2InvAddress();
        cmd[0] = {0, opcode, (UInt32)encoded | M2B2_CMD_PDE_MASK, (UInt32)(encoded >> 32)};
    } else {
        count = PlanRange(opcode, address, bytes, cmd, covered);
    }
    if (!count || !m2b2SubmitBatch(c->base, &c->command, "invalidate-pages", cmd, count)) {
        d->state = "failed-page-invalidation";
        return false;
    }
    ++d->invPagesCompleted;
    d->lastInvPagesSequence = c->command.completionSequence;
    if (full) ++d->invFullCompleted;
    else {
        ++d->invRangeCompleted;
        d->invRangePages += bytes / 4096;
        d->invRangeCoveredPages += covered;
        d->rangeDescriptors += count;
        if (count > 1) {
            ++d->splitBatches;
            d->splitAddress = address; d->splitBytes = bytes;
            d->splitSequence = c->command.completionSequence; d->splitCount = count;
            memcpy(d->splitWords, cmd, count * sizeof(cmd[0]));
        }
        d->lastRangeAddress = address;
        d->lastRangeBytes = bytes;
        memcpy(d->lastRangeCommand, &cmd[count - 1], sizeof(cmd[0]));
        d->lastRangeSequence = c->command.completionSequence;
    }
    if (!d->active) {
        d->active = true;
        d->activeTime = mach_absolute_time();
        d->state = "active";
    }
    return true;
}


// Caller holds its mapper lock. A shared-controller lock serializes the DTE
// write and both fences with ordinary submissions from either requester.
IOReturn org_example_AMDMapperProbe::SwitchRequesterDMA(bool park) {
    auto *c = fController;
    auto *d = fDomain;
    if (!c || !d) return kIOReturnNotReady;
    LockGuard guard(c->lock);
    if (c->command.failed) return kIOReturnIOError;
    if (!c->ready || c->suspended) return kIOReturnNotReady;
    if (!d->active) return kIOReturnNotReady;
    if (fDMAParked == park) return kIOReturnSuccess; // active on first enable
    fDMAParked = park;
    if (!InvalidateLocked(true, 0, 0, false, nullptr)) {
        // Do not start DMA or release backing after an unconfirmed transition.
        // With a failed queue, a deny in table memory is not proof of eviction.
        fDMAParked = true;
        auto *dte = (volatile UInt64 *)c->devices->getBytesNoCopy();
        dte[d->deviceID * 4] &= ~(DTE_IR | DTE_IW);
        OSSynchronizeIO();
        d->state = "failed-requester-access";
        return kIOReturnIOError;
    }
    if (park) ++d->parkCount; else ++d->restoreCount;
    d->gateDevSequence = d->lastInvDevSequence;
    d->gatePagesSequence = d->lastInvPagesSequence;
    return kIOReturnSuccess;
}

IOReturn org_example_AMDMapperProbe::SetSystemPM(bool armed) {
    Controller *c = fController;
    if (!fAuto || fOwner || !c) return kIOReturnBadArgument;
    LockGuard guard(c->lock);
    if (armed) {
        if (!c->ready || c->suspended || c->powerFailed || c->domainCount != 2)
            return kIOReturnNotReady;
        UInt32 present = 0;
        for (UInt32 i = 0; i < kMaxDomains; ++i) {
            Domain *domain = c->domains[i];
            if (!domain) continue;
            ++present;
            if (!domain->active) return kIOReturnNotReady;
        }
        if (present != 2) return kIOReturnNotReady;
        c->coordinatedPMArmed = true;
    } else {
        if (c->suspended) return kIOReturnBusy;
        c->coordinatedPMArmed = false;
    }
    setProperty("pm-coordinated-armed", c->coordinatedPMArmed ? "yes" : "no");
    return kIOReturnSuccess;
}

bool org_example_AMDMapperProbe::PowerSupported() const {
    Controller *c = fController;
    if (!c || !fDomain) return false;
    LockGuard guard(c->lock);
    // Single-domain behavior remains unchanged. Two-domain PM is enabled
    // only by an explicit runtime arm after both NICs are fully initialized.
    if (c->domainCount == 1) return true;
    if (c->domainCount != 2 || !c->coordinatedPMArmed) return false;
    UInt32 present = 0;
    for (UInt32 i = 0; i < kMaxDomains; ++i) {
        Domain *domain = c->domains[i];
        if (!domain) continue;
        ++present;
        if (!domain->active) return false;
    }
    return present == 2;
}

// TODO(R47-PM-HARDWARE): validate the real suspend/resume sequence once this
// AMD platform can sleep reliably. R47 acceptance does not invoke this path.
bool org_example_AMDMapperProbe::SuspendAuto() {
    // The mapper lock is held and admission is closed. Lucy's PM gate has
    // already completed the network family's disable/clearRxTxRings path.
    Controller *c = fController;
    Domain *d = fDomain;
    if (!c || !d) return false;
    LockGuard guard(c->lock);
    if ((c->domainCount != 1 && c->domainCount != 2) ||
        !c->ready || c->suspended || c->powerFailed)
        return false;
    c->resumeRegistersRestored = false;
    c->sleepControl = mmioRead64(c->base, M2B2_OFF_CONTROL);
    if ((c->sleepControl & kEnabled) != kEnabled)
        return c->powerFailure("failed-pm-suspend-controller-not-enabled");
    if (c->domainCount == 2) {
        if (d->pmSuspendReady) return false;
        if (d->pmResumeReady) {
            bool allResumed = true;
            for (UInt32 i = 0; i < kMaxDomains; ++i)
                if (c->domains[i] && !c->domains[i]->pmResumeReady) allResumed = false;
            if (!allResumed) return false;
            for (UInt32 i = 0; i < kMaxDomains; ++i)
                if (c->domains[i]) c->domains[i]->pmResumeReady = false;
        }
        // Fence this requester's own DTE/domain before publishing readiness.
        // The final participant performs the single shared-controller stop.
        if (!InvalidateLocked(false, 0, 0, false, nullptr))
            return c->powerFailure("failed-pm-domain-suspend-fence");
        ++d->pmSuspends;
        d->pmSuspendSequence = c->command.completionSequence;
        d->pmSuspendReady = true;
        d->state = "pm-suspend-ready";
        bool allReady = true;
        for (UInt32 i = 0; i < kMaxDomains; ++i)
            if (c->domains[i] && !c->domains[i]->pmSuspendReady) allReady = false;
        if (!allReady) return true;
    } else {
        if (!InvalidateLocked(false, 0, 0, false, nullptr))
            return c->powerFailure("failed-pm-suspend-fence");
        ++d->pmSuspends;
        d->pmSuspendSequence = c->command.completionSequence;
    }
    c->suspendSequence = c->command.completionSequence;
    if (!c->stopHardware())
        return c->powerFailure("failed-pm-suspend-controller");
    c->collectEvents();
    c->ready = false;
    c->suspended = true;
    c->suspendTime = mach_absolute_time();
    ++c->suspendCount;
    c->state = "suspended";
    return true;
}

// TODO(R47-PM-HARDWARE): D0 readiness and retained BAR/MMIO across real system
// sleep need hardware validation; normal interface down/up is not this test.
bool org_example_AMDMapperProbe::ResumeAuto() {
    // The PCI parent and Lucy's D0 transition are complete, but its normal
    // enable has not run. All tables, DMA objects and mapping records survive.
    Controller *c = fController;
    Domain *d = fDomain;
    if (!c || !d) return false;
    LockGuard guard(c->lock);
    if ((c->domainCount != 1 && c->domainCount != 2) ||
        !c->suspended || c->powerFailed) {
        // The first requester restored the shared controller. Later requesters
        // only need to invalidate their own DTE/domain before reopening.
        if (c->domainCount == 2 && c->ready && !c->suspended &&
            !c->powerFailed && !d->pmResumeReady && c->resumeRegistersRestored &&
            c->suspendCount == c->resumeCount + 1) {
            // This is the second requester only after the first has restored
            // the engines. An incomplete suspend is NOT a restored controller.
            if (!InvalidateLocked(true, 0, 0, false, nullptr))
                return c->powerFailure("failed-pm-domain-resume-invalidation");
            d->recordPMResume();
            d->pmResumeReady = true;
            d->state = "pm-resume-ready";
            c->resumeDevSequence = d->lastInvDevSequence;
            c->resumePagesSequence = d->lastInvPagesSequence;
            bool allReady = true;
            for (UInt32 i = 0; i < kMaxDomains; ++i)
                if (c->domains[i] && !c->domains[i]->pmResumeReady) allReady = false;
            if (allReady) {
                c->resumeTime = mach_absolute_time();
                ++c->resumeCount;
                c->state = "ready-all-domains";
            }
            return true;
        }
        if (c->domainCount == 2 && !c->powerFailed)
            return c->powerFailure("failed-pm-resume-before-controller-restore");
        return false;
    }
    if (c->domainCount == 2) {
        for (UInt32 i = 0; i < kMaxDomains; ++i)
            if (c->domains[i] && !c->domains[i]->pmSuspendReady)
                return c->powerFailure("failed-pm-resume-incomplete-suspend-barrier");
    }
    if (c->hardware.pciEfrSupported &&
        mmioRead64(c->base, M21_OFF_EXT_FEAT) != c->startupEfr)
        return c->powerFailure("failed-pm-resume-identity");
    if (!c->stopHardware())
        return c->powerFailure("failed-pm-resume-stop");

    // Linux v6.6 init.c early_enable_iommu() reloads the device table and
    // stopped command/event rings on resume, then enables and invalidates.
    // Only the ring position restarts: sequence numbers and evidence counters
    // must remain monotonic, so an old semaphore value cannot complete a new CW.
    bzero(c->commands->getBytesNoCopy(), M23_CMD_BUF_SIZE);
    bzero(c->events->getBytesNoCopy(), M2B2_EVT_BUFFER_SIZE);
    c->headCache.valid = false; // no cached position survives a hardware ring reset
    c->command.idx = 0;
    c->command.tail = 0;
    OSSynchronizeIO();
    const UInt64 dt = c->devicePA | ((M22B_TABLE_SIZE_FULL >> 12) - 1);
    const UInt64 commands = c->commandPA | M23_CMD_SIZE_CODE;
    const UInt64 events = c->eventPA | M2B2_EVT_LEN_MASK;
    mmioWrite64(c->base, M2B2_OFF_DEV_TABLE, dt);
    mmioWrite64(c->base, M2B2_OFF_CMD_BUF, commands);
    mmioWrite64(c->base, M2B2_OFF_EVT_BUF, events);
    mmioWrite64(c->base, M2B2_OFF_CMD_HEAD, 0);
    mmioWrite64(c->base, M2B2_OFF_CMD_TAIL, 0);
    mmioWrite64(c->base, M2B2_OFF_EVT_HEAD, 0);
    mmioWrite64(c->base, M2B2_OFF_EVT_TAIL, 0);
    mmioWrite32(c->base, M2B2_OFF_STATUS, M2B2_STATUS_EVT_OVERFLOW);
    UInt64 control = c->sleepControl & ~kEnabled;
    mmioWrite64(c->base, M2B2_OFF_CONTROL, control | M2B2_CTRL_CMDBUF_EN);
    control |= M2B2_CTRL_CMDBUF_EN | M2B2_CTRL_EVT_LOG_EN;
    mmioWrite64(c->base, M2B2_OFF_CONTROL, control);
    control |= M2B2_CTRL_IOMMU_EN;
    mmioWrite64(c->base, M2B2_OFF_CONTROL, control);
    OSSynchronizeIO();
    c->observedControl = mmioRead64(c->base, M2B2_OFF_CONTROL);
    c->resumeRegistersRestored =
        mmioRead64(c->base, M2B2_OFF_DEV_TABLE) == dt &&
        mmioRead64(c->base, M2B2_OFF_CMD_BUF) == commands &&
        mmioRead64(c->base, M2B2_OFF_EVT_BUF) == events &&
        c->observedControl == c->sleepControl;
    if (!c->resumeRegistersRestored)
        return c->powerFailure("failed-pm-resume-registers");
    UInt32 status = 0;
    const UInt32 running = M2B2_STATUS_CMDBUF_RUN | M2B2_STATUS_EVT_RUN;
    for (UInt32 i = 0; i < M2B1_LOOP_TIMEOUT; ++i) {
        status = mmioRead32(c->base, M2B2_OFF_STATUS);
        if ((status & running) == running) break;
    }
    if ((status & running) != running)
        return c->powerFailure("failed-pm-resume-engines");

    c->ready = true;
    // Force the device-cache invalidation even though the DTE remains active
    // in retained memory. Do not overwrite the original startup timestamps.
    if (!InvalidateLocked(true, 0, 0, false, nullptr))
        return c->powerFailure("failed-pm-resume-invalidation");
    d->recordPMResume();
    c->resumeDevSequence = d->lastInvDevSequence;
    c->resumePagesSequence = d->lastInvPagesSequence;
    c->suspended = false;
    if (c->domainCount == 2) {
        d->pmResumeReady = true;
        d->state = "pm-resume-ready";
        for (UInt32 i = 0; i < kMaxDomains; ++i)
            if (c->domains[i]) c->domains[i]->pmSuspendReady = false;
        bool allReady = true;
        for (UInt32 i = 0; i < kMaxDomains; ++i)
            if (c->domains[i] && !c->domains[i]->pmResumeReady) allReady = false;
        if (allReady) {
            c->resumeTime = mach_absolute_time();
            ++c->resumeCount;
            c->state = "ready-all-domains";
        } else {
            c->state = "ready-awaiting-domain-resume";
        }
    } else {
        c->resumeTime = mach_absolute_time();
        ++c->resumeCount;
        c->state = "ready-shared-controller";
    }
    return true;
}

void org_example_AMDMapperProbe::PublishAuto() {
    Controller *c = fController;
    Domain *d = fDomain;
    if (!c || !d) return;
    LockGuard guard(c->lock);
    // The per-device snapshot holds its mapper lock. The shared lock also
    // serializes event HEAD consumption and queue counters across both NICs.
    if (c->configured && !c->suspended) {
        c->collectEvents();
        c->observedControl = mmioRead64(c->base, M2B2_OFF_CONTROL);
    }
    auto number = [this](const char *key, UInt64 value) {
        setProperty(key, (unsigned long long)value, 64);
    };
    setProperty("iommu-state", d->state ? d->state : "preparing");
    setProperty("iommu-controller-ready", c->ready ? "yes" : "no");
    setProperty("iommu-dte-active", d->active && c->configured ? "yes" : "no");
    setProperty("iommu-registers-restored", c->restored ? "yes" : "no");
    setProperty("iommu-event-overflow", c->eventOverflow ? "yes" : "no");
    setProperty("iommu-event-valid", c->eventInvalid ? "no" : "yes");
    setProperty("iommu-command-failed", c->command.failed ? "yes" : "no");
    setProperty("pm-controller-state", c->powerFailed ? "failed" :
                (c->suspended ? "suspended" : "awake"));
    UInt32 pmSuspendReady = 0, pmResumeReady = 0;
    for (UInt32 i = 0; i < kMaxDomains; ++i) {
        if (!c->domains[i]) continue;
        pmSuspendReady += c->domains[i]->pmSuspendReady ? 1 : 0;
        pmResumeReady += c->domains[i]->pmResumeReady ? 1 : 0;
    }
    number("pm-domain-suspend-count", d->pmSuspends);
    number("pm-domain-resume-count", d->pmResumes);
    number("pm-domain-suspend-sequence", d->pmSuspendSequence);
    number("pm-domain-resume-device-sequence", d->pmResumeDevSequence);
    number("pm-domain-resume-pages-sequence", d->pmResumePagesSequence);
    number("pm-domain-count", c->domainCount);
    setProperty("pm-coordinated-armed", c->coordinatedPMArmed ? "yes" : "no");
    number("pm-suspend-ready", pmSuspendReady);
    number("pm-resume-ready", pmResumeReady);
    setProperty("pm-resume-registers-restored",
                c->resumeRegistersRestored ? "yes" : "no");
    number("pm-controller-suspend-count", c->suspendCount);
    number("pm-controller-resume-count", c->resumeCount);
    number("pm-controller-failures", c->powerFailures);
    number("pm-controller-suspend-time", c->suspendTime);
    number("pm-controller-resume-time", c->resumeTime);
    number("pm-controller-suspend-sequence", c->suspendSequence);
    number("pm-controller-resume-device-invalidation-sequence", c->resumeDevSequence);
    number("pm-controller-resume-pages-invalidation-sequence", c->resumePagesSequence);
    setProperty("command-counters-scope", "controller");
    setProperty("pm-support-scope", c->domainCount > 1 ? "unsupported-shared" : "single-device");
    number("invalidation-completed-total", d->invDevCompleted + d->invPagesCompleted);
    number("iommu-device-id", d->deviceID);
    number("iommu-domain-id", d->domainID);
    number("iommu-root-pa", d->tablePA);
    number("iommu-table-pa", d->tablePA);
    number("iommu-table-bytes", (UInt64)d->tablePages * M2B2_PAGE_SIZE);
    setProperty("iommu-domain-profile", d->profileName ? d->profileName : "unknown");
    number("iommu-domain-profile-records", d->profileRecords);
    number("iommu-domain-profile-pages", d->profilePages);
    number("iommu-device-table-pa", c->devicePA);
    number("iommu-command-pa", c->commandPA);
    number("iommu-event-pa", c->eventPA);
    number("iommu-controller-ready-time", c->readyTime);
    number("iommu-dte-active-time", d->activeTime);
    setProperty("dma-parked", c->command.failed ? "unknown" : (fDMAParked ? "yes" : "no"));
    number("dma-park-count", d->parkCount);
    number("dma-restore-count", d->restoreCount);
    number("dma-last-device-sequence", d->gateDevSequence);
    number("dma-last-pages-sequence", d->gatePagesSequence);
    number("invalidation-device-completed", d->invDevCompleted);
    number("invalidation-pages-completed", d->invPagesCompleted);
    number("iommu-np-cache", (c->hardware.capabilityHeader & kNpCache) ? 1 : 0);
    number("invalidation-map-skipped", d->mapInvalidationSkipped);
    number("invalidation-full-completed", d->invFullCompleted);
    number("invalidation-range-completed", d->invRangeCompleted);
    number("invalidation-range-pages", d->invRangePages);
    number("invalidation-range-covered-pages", d->invRangeCoveredPages);
    number("invalidation-range-descriptors", d->rangeDescriptors);
    number("invalidation-split-batches", d->splitBatches);
    if (d->splitCount) {
        number("invalidation-split-address", d->splitAddress);
        number("invalidation-split-bytes", d->splitBytes);
        number("invalidation-split-sequence", d->splitSequence);
        setProperty("invalidation-split-commands", d->splitWords, d->splitCount * sizeof(d->splitWords[0]));
    }
    number("invalidation-last-range-address", d->lastRangeAddress);
    number("invalidation-last-range-bytes", d->lastRangeBytes);
    number("invalidation-last-range-sequence", d->lastRangeSequence);
    for (UInt32 i = 0; i < 4; ++i) {
        char key[32];
        snprintf(key, sizeof(key), "invalidation-last-range-command%u", i);
        number(key, d->lastRangeCommand[i]);
    }
    number("iommu-command-submits", c->command.submits);
    number("iommu-command-completed", c->command.completed);
    number("iommu-command-wraps", c->command.wraps);
    number("iommu-command-post-wrap-completed", c->command.postWrapCompleted);
    number("iommu-command-completion-sequence", c->command.completionSequence);
    number("iommu-event-entries", c->eventEntries);
    number("iommu-target-faults", d->targetFaults);
    for (UInt32 i = 0; i < 4; ++i) {
        char key[32];
        snprintf(key, sizeof(key), "iommu-last-event%u", i);
        number(key, d->lastEvent[i]);
    }
    // A snapshot taken while suspended must never probe powered-down MMIO.
    number("iommu-control-register", c->observedControl);
    if (c->devices) {
        const volatile UInt64 *dte =
            (volatile UInt64 *)c->devices->getBytesNoCopy();
        number("iommu-dte0", dte[d->deviceID * 4]);
        number("iommu-dte1", dte[d->deviceID * 4 + 1]);
    }
}


void org_example_AMDMapperProbe::PublishDomains() {
    if (fOwner || !fAttachLock) return;
    LockGuard attachment(fAttachLock);
    OSArray *domains = OSArray::withCapacity(kMaxDomains);
    if (!domains) return;
    for (UInt32 i = 0; i < kMaxDomains; ++i) {
        auto *mapper = fMappers[i];
        if (!mapper || !mapper->fDomain) continue;
        OSDictionary *properties = nullptr;
        mapper->PublishMappings(&properties);
        if (!properties) continue;
        domains->setObject(properties);
        // Retain the historical single-device inspection surface on the owner.
        // Tools explicitly consume every dictionary in snapshot-domains.
        if (domains->getCount() == 1) {
            OSCollectionIterator *keys = OSCollectionIterator::withCollection(properties);
            if (keys) {
                while (OSObject *object = keys->getNextObject()) {
                    OSString *key = OSDynamicCast(OSString, object);
                    if (!key) continue;
                    const char *name = key->getCStringNoCopy();
                    if (!strncmp(name, "iommu-", 6) || !strncmp(name, "mapper-", 7) ||
                        !strncmp(name, "pm-", 3))
                        setProperty(name, properties->getObject(name));
                }
                keys->release();
            }
        }
        properties->release();
    }
    setProperty("snapshot-domains", domains);
    setProperty("iommu-domain-count", domains->getCount(), 32);
    setProperty("snapshot-sequence", ++fSnapshotSequence, 64);
    setProperty("snapshot-time", mach_absolute_time(), 64);
    domains->release();
    Controller *c = fController;
    if (!c) return;
    LockGuard guard(c->lock);
    if (c->configured && !c->suspended) c->collectEvents();
    auto number = [this](const char *key, UInt64 value) {
        setProperty(key, (unsigned long long)value, 64);
    };
    number("iommu-controller-device-table-pa", c->devicePA);
    number("iommu-controller-command-pa", c->commandPA);
    number("iommu-controller-event-pa", c->eventPA);
    number("iommu-controller-command-submits", c->command.submits);
    number("iommu-controller-command-completed", c->command.completed);
    number("iommu-controller-command-completion-sequence", c->command.completionSequence);
    number("iommu-controller-command-wraps", c->command.wraps);
    number("iommu-controller-head-reads", c->headCache.reads);
    number("iommu-controller-cached-batches", c->headCache.cachedBatches);
    number("iommu-controller-event-entries", c->eventEntries);
    number("iommu-controller-target-faults", c->targetFaults);
    setProperty("iommu-controller-ready", c->ready ? "yes" : "no");
    setProperty("iommu-controller-command-failed", c->command.failed ? "yes" : "no");
    setProperty("iommu-controller-event-overflow", c->eventOverflow ? "yes" : "no");
    setProperty("iommu-controller-event-valid", c->eventInvalid ? "no" : "yes");
}

bool org_example_AMDMapperProbe::StopAuto() {
    if (fOwner) {
        // Device stop closes only that domain. Its root and mapper remain owned
        // by the controller service until all domains can be stopped together.
        // In particular, interface disable/enable never stops this controller.
        if (!QuiesceMappings()) {
            setProperty("device-stop-state", "retained-live-mappings");
            return false;
        }
        PublishMappings();
        setProperty("device-stop-state", "quiesced");
        return true;
    }
    if (!fAttachLock) return !fController;
    {
        LockGuard attachment(fAttachLock);
        Controller *c = fController;
        fStopping = true;
        for (auto *&device : fOffers) {
            if (!device) continue;
            if (device->getProperty(amd_iommu_policy::kOffer) == this) {
                device->setProperty(amd_iommu_policy::kProperty, amd_iommu_policy::kFailed);
                device->removeProperty(amd_iommu_policy::kOffer);
            }
            device->release();
            device = nullptr;
        }
        for (UInt32 i = 0; i < kMaxDomains; ++i) {
            auto *mapper = fMappers[i];
            if (!mapper || mapper->QuiesceMappings()) continue;
            setProperty("iommu-state", "retained-live-mappings");
            if (c && !c->pinned) { c->pinned = true; retain(); }
            return false;
        }
        if (c) {
            LockGuard guard(c->lock);
            if (!c->restore()) {
                c->state = "retained-hardware-stop-failed";
                setProperty("iommu-state", c->state);
                if (!c->pinned) { c->pinned = true; retain(); }
                return false;
            }
        }
        for (UInt32 i = 0; i < kMaxDomains; ++i) {
            auto *mapper = fMappers[i];
            if (!mapper) continue;
            mapper->stop(this);
            mapper->ReleaseDomain();
            mapper->fOwner = nullptr;
            mapper->detach(this);
            mapper->release();
            fMappers[i] = nullptr;
        }
        if (c) {
            const bool pinned = c->pinned;
            c->releaseBuffers();
            fController = nullptr;
            IOFree(c, sizeof(*c));
            if (pinned) release();
        }
    }
    setProperty("iommu-state", "stopped");
    return true;
}

void org_example_AMDMapperProbe::free() {
    // A pre-open claim pins the owner (and hence this lock) until it returns.
    if (fAttachLock) IOLockFree(fAttachLock);
    IOMapper::free();
}
