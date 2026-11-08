// Persistent per-device hardware lifecycle for amdiommu=passive.
// The experiment's timer, Lucy bindings and measurement windows are not used.
#include "AMDMapperProbeInternal.hpp"
#include "AMDMapperProbeDiscovery.hpp"
#include "amd_iommu_mapper_abi.hpp"
#include "amd_iommu_device_policy.hpp"
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSCollectionIterator.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/IOMessage.h>
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
// The initial table allocation follows the prepared profile. Later leaf
// allocations are tracked by the mapper and retained alongside the root.
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

// Reserve page-table storage with the controller buffers' alignment and
// physical-contiguity requirements.
bool org_maz1_AMDMapperProbe::AllocateTableArea(
    IOBufferMemoryDescriptor *&md, UInt64 bytes, UInt64 &pa) {
    return Allocate(md, bytes, pa);
}


struct org_maz1_AMDMapperProbe::Domain {
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
#if AMD_MAPPER_PM_TRACE
    // PM fault tracer: which fault, where it pointed, and the PM phase that was
    // live when it was observed. Only compiled into a trace build.
    UInt64 faultObservedTime;
    UInt64 faultIOVA;
    UInt32 faultType;
    UInt32 faultCount;
    const char *faultPhase;
#endif
    // R72: live mappings as this domain's mapper counts them, and the evidence
    // that a suspend closed admission (so a later DMA call may reopen it).
    UInt32 pmLiveMaps;
    bool pmSuspendRequested;
    bool pmParkedBySuspend;
    // S2: the admission record for this domain. Shown per device so a refused
    // or legacy domain cannot be mistaken for a pool-sized one.
    mapper_abi::Capacity capacity;
    UInt32 allocatedTablePages;
    // The profile limits growth; records and IOVA pages grow independently.
    // Growth appends leaf pages while retaining tables and tablePA as the root.
    const mapper_abi::Profile *ceilingProfile;
    const char *state;
    bool active;
};

struct org_maz1_AMDMapperProbe::Controller {
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
    // R72: self-driven PM evidence.
    UInt64 lazyRestores, retainedSuspends, resumeFailures, commandRecoveries;
    const char *pmReason;
#if AMD_MAPPER_PM_TRACE
    // PM fault tracer (trace build only). `phase` names the PM window a drain is
    // observing; the ring copy keeps what the producer wrote before the reset,
    // because S3 clears EVT_HEAD/TAIL and the normal walk cannot reach it.
    const char *pmPhase;
    UInt8 *traceRing;
    UInt64 traceTailAtSuspend;
    UInt64 traceDrains, traceRingFaults;
    bool traceHaveTail;
#endif

    // R72: is the register image this driver installed still in the controller?
    // A real S3 clears CONTROL and all three ring bases, so this is also the wake
    // detector for a wake that delivered no suspend notification. Kext-side only:
    // no lock, no allocation, four MMIO reads.
    bool signatureOK() {
        if (!configured || !base) return false;
        if ((mmioRead64(base, M2B2_OFF_CONTROL) & kEnabled) != kEnabled)
            return false;
        if (mmioRead64(base, M2B2_OFF_DEV_TABLE) !=
            (devicePA | ((M22B_TABLE_SIZE_FULL >> 12) - 1))) return false;
        if (mmioRead64(base, M2B2_OFF_CMD_BUF) !=
            (commandPA | M23_CMD_SIZE_CODE)) return false;
        if (mmioRead64(base, M2B2_OFF_EVT_BUF) !=
            (eventPA | M2B2_EVT_LEN_MASK)) return false;
        return true;
    }
    // A device left in D3 answers all-ones. Restoring is impossible there, and
    // silently treating it as "no change needed" would submit into a dead ring.
    bool responding() {
        if (!configured || !base) return false;
        return mmioRead64(base, M2B2_OFF_CONTROL) != ~((UInt64)0);
    }
    // The suspend side may touch the translation hardware only when nobody holds
    // a live mapping: with IOMMU_EN cleared a requester that is still DMAing
    // would address physical memory directly.
    bool allDmaQuiesced() const {
        for (UInt32 i = 0; i < kMaxDomains; ++i)
            if (domains[i] && domains[i]->pmLiveMaps) return false;
        return true;
    }

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
#if AMD_MAPPER_PM_TRACE
                    // The IOMMU does not timestamp an event, so this records when
                    // the drain saw it and which PM window was live at that time.
                    ++d->faultCount;
                    d->faultObservedTime = mach_absolute_time();
                    d->faultIOVA = (UInt64)lastEvent[2] | ((UInt64)lastEvent[3] << 32);
                    d->faultType = type;
                    d->faultPhase = pmPhase ? pmPhase : "unknown";
#endif
                }
                head = (head + 16) % M2B2_EVT_BUFFER_SIZE;
            }
            mmioWrite64(base, M2B2_OFF_EVT_HEAD, head);
        }
    }

#if AMD_MAPPER_PM_TRACE
    // S3 clears EVT_HEAD/TAIL, so the normal walk cannot reach what the producer
    // wrote after the last drain. The buffer contents survive in RAM, and the
    // producer writes forward from the tail observed before the transition, so a
    // zero type field marks the end of what it managed to publish.
    void scanPreResetRing() {
        if (!traceRing || !traceHaveTail) return;
        UInt64 cursor = traceTailAtSuspend;
        if (cursor >= M2B2_EVT_BUFFER_SIZE || (cursor & 15)) return;
        for (UInt32 n = 0; n < M2B2_EVT_BUFFER_SIZE / 16; ++n) {
            const UInt32 entry = (UInt32)cursor / 4;
            const UInt32 words[4] = {
                *(const UInt32 *)(traceRing + (entry + 0) * 4),
                *(const UInt32 *)(traceRing + (entry + 1) * 4),
                *(const UInt32 *)(traceRing + (entry + 2) * 4),
                *(const UInt32 *)(traceRing + (entry + 3) * 4)};
            const UInt32 type = words[1] >> M2B2_EVENT_TYPE_SHIFT;
            if (!type) break;
            ++eventEntries;
            for (UInt32 i = 0; i < 4; ++i) lastEvent[i] = words[i];
            for (UInt32 slot = 0; slot < kMaxDomains; ++slot) {
                Domain *d = domains[slot];
                if (!d || (lastEvent[0] & M2B2_EVENT_DEVID_MASK) != d->deviceID)
                    continue;
                ++d->targetFaults;
                ++targetFaults;
                ++traceRingFaults;
                ++d->faultCount;
                d->faultObservedTime = mach_absolute_time();
                d->faultIOVA = (UInt64)lastEvent[2] | ((UInt64)lastEvent[3] << 32);
                d->faultType = type;
                d->faultPhase = "pre-restore-ring";
                for (UInt32 i = 0; i < 4; ++i) d->lastEvent[i] = lastEvent[i];
            }
            cursor = (cursor + 16) % M2B2_EVT_BUFFER_SIZE;
        }
        traceHaveTail = false;
    }
#endif

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
#if AMD_MAPPER_PM_TRACE
        if (traceRing) {
            IOFree(traceRing, (size_t)M2B2_EVT_BUFFER_SIZE);
            traceRing = nullptr;
        }
#endif
        if (mmioMap) mmioMap->release();
        if (mmioMemory) mmioMemory->release();
        if (events) events->release();
        if (semaphore) semaphore->release();
        if (commands) commands->release();
        if (devices) devices->release();
        if (lock) IOLockFree(lock);
    }
};


bool org_maz1_AMDMapperProbe::ReadDeviceSelection() {
    char selection[128] = {};
    fSelectionExplicit = PE_parse_boot_argn("amdiommu_devices", selection,
                                              sizeof(selection) - 1);
    fRequesterCount = 0;
    if (!fSelectionExplicit) {
        return ReadDefaultDevices();
    }
    // One to kMaxDomains four-hex-digit segment-zero requester IDs, no
    // saved BDFs. Slots are allocated on demand; the capacity matches the
    // Info.plist default device list (16).
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

// Default selection from the Info.plist personality. The AMDMapperProbeDevices
// value uses the IOPCIMatch format: whitespace-separated "0xVVVVDDDD" words,
// each optionally followed by "&0xMMMMMMMM"; VVVV is the PCI vendor and DDDD
// the device. Comparison is (device << 16 | vendor) & mask == id & mask, the
// way IOPCIFamily evaluates IOPCIMatch. The personality dictionary becomes the
// instance property table at IOService::init, so the key is read with
// getProperty() -- no OSKext API needed.
bool org_maz1_AMDMapperProbe::ReadDefaultDevices() {
    fDefaultDeviceCount = 0;
    OSString *value = OSDynamicCast(OSString, getProperty("AMDMapperProbeDevices"));
    if (!value || !value->getCStringNoCopy()) {
        setProperty("device-selection", "plist-missing");
        return true;  // no default devices: every later publish is rejected
    }
    const char *cursor = value->getCStringNoCopy();
    while (*cursor) {
        while (*cursor == ' ' || *cursor == '\t') ++cursor;
        if (!*cursor) break;
        if (fDefaultDeviceCount == kMaxDefaultDevices) {
            setProperty("device-selection", "plist-too-many-entries");
            fDefaultDeviceCount = 0;
            return true;
        }
        if (cursor[0] != '0' || (cursor[1] != 'x' && cursor[1] != 'X')) {
            setProperty("device-selection", "plist-parse-failed");
            fDefaultDeviceCount = 0;
            return true;
        }
        cursor += 2;
        UInt64 id = 0;
        UInt32 digits = 0;
        while (IsHexDigit(*cursor) && digits < 8) {
            const char digit = *cursor++;
            const UInt32 nibble = digit <= '9' ? digit - '0'
                : (digit <= 'F' ? digit - 'A' + 10 : digit - 'a' + 10);
            id = (id << 4) | nibble;
            ++digits;
        }
        if (!digits) {
            setProperty("device-selection", "plist-parse-failed");
            fDefaultDeviceCount = 0;
            return true;
        }
        UInt32 mask = 0xffffffffU;
        if (*cursor == '&') {
            ++cursor;
            if (cursor[0] != '0' || (cursor[1] != 'x' && cursor[1] != 'X')) {
                setProperty("device-selection", "plist-parse-failed");
                fDefaultDeviceCount = 0;
                return true;
            }
            cursor += 2;
            UInt64 parsed = 0;
            digits = 0;
            while (IsHexDigit(*cursor) && digits < 8) {
                const char digit = *cursor++;
                const UInt32 nibble = digit <= '9' ? digit - '0'
                    : (digit <= 'F' ? digit - 'A' + 10 : digit - 'a' + 10);
                parsed = (parsed << 4) | nibble;
                ++digits;
            }
            if (!digits) {
                setProperty("device-selection", "plist-parse-failed");
                fDefaultDeviceCount = 0;
                return true;
            }
            mask = (UInt32)(parsed & 0xffffffffU);
        }
        if (*cursor && *cursor != ' ' && *cursor != '\t') {
            setProperty("device-selection", "plist-parse-failed");
            fDefaultDeviceCount = 0;
            return true;
        }
        fDefaultDevices[fDefaultDeviceCount].idMasked =
            (UInt32)(id & 0xffffffffU) & mask;
        fDefaultDevices[fDefaultDeviceCount].mask = mask;
        ++fDefaultDeviceCount;
    }
    setProperty("device-selection", value->getCStringNoCopy());
    setProperty("device-selection-count", fDefaultDeviceCount, 32);
    return true;
}

bool org_maz1_AMDMapperProbe::DefaultDeviceMatches(
    UInt16 vendor, UInt16 device) const {
    const UInt32 identity = ((UInt32)device << 16) | vendor;
    for (UInt32 i = 0; i < fDefaultDeviceCount; ++i)
        if ((identity & fDefaultDevices[i].mask) == fDefaultDevices[i].idMasked)
            return true;
    return false;
}

// Select the growth ceiling. Each domain starts with legacy storage and
// doubles the exhausted resource while retaining existing mappings.
bool org_maz1_AMDMapperProbe::SelectProfile() {
    char requested[24] = {};
    const bool named = PE_parse_boot_argn("amdiommu_profile", requested,
                                          sizeof(requested) - 1) != 0;
    bool forced = false;
    const mapper_abi::Profile *ceiling = Ceiling(forced);
    fProfile = *ceiling;
    fProfileForced = forced;
    if (named) setProperty("iommu-profile-request", requested);
    setProperty("iommu-profile-mode", forced ? "forced" : "capacity-demand");
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
const mapper_abi::Profile *org_maz1_AMDMapperProbe::Ceiling(bool &forced) const {
    forced = false;
    char requested[24] = {};
    if (!PE_parse_boot_argn("amdiommu_profile", requested, sizeof(requested) - 1))
        return &mapper_abi::kProfileDma32Max;
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
const mapper_abi::Profile *org_maz1_AMDMapperProbe::ForcedProfile() const {
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
const mapper_abi::Profile *org_maz1_AMDMapperProbe::ProfileForDevice(
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

bool org_maz1_AMDMapperProbe::StartAuto() {
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
    // R72: this instance is the controller, so it is the one that listens for a
    // real system sleep/wake. Registration is optional: without it the DMA path
    // still repairs a lost controller, it just learns about the loss later.
    RegisterSystemPM();
    // Offer explicit requesters to pre-open clients; keep eager attach for the default.
    // Replay published endpoints through the same path as the notification.
    AttachExistingDevices();
    PublishDomains();
    return true;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
bool org_maz1_AMDMapperProbe::AttachAuto(IOService *service, bool claim,
                                        bool allowOpen) {
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
        // Two sources, never mixed: amdiommu_devices is the only input when it
        // is present, and the Info.plist identity list (AMDMapperProbeDevices)
        // is consulted only when the boot argument is absent. In default mode
        // fRequesterCount is 0, so every device lands here and the table alone
        // decides; a claim (including the hook's attach verb) is accepted for a
        // table match, because the table is the selection in that mode.
        if (fSelectionExplicit) return false;
        if (!DefaultDeviceMatches(vendor16, device16)) return false;
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
        if (!fAutoAttach) {
            if (!claim) {
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
            if (offered != nic || nic->getProperty(amd_iommu_policy::kOffer) != this)
                return false;
            nic->removeProperty(amd_iommu_policy::kOffer);
        } else if (!claim) {
            // Auto-attach keeps an offer published as well. The mapper is still
            // attached right below at first publish, but a client that runs the
            // claim handshake before its PCI open must find the record it is
            // supposed to match; without it the handshake would answer
            // kIOReturnNotReady for a device that is already mapped.
            if (!offered) {
                if (!nic->setProperty(amd_iommu_policy::kOffer, this))
                    return false;
                nic->retain();
                offered = nic;
            } else if (offered != nic) {
                return false;
            }
        } else {
            // A claim in auto-attach mode usually arrives after the attachment,
            // so accept it while the offer still names this device and let the
            // lookup below turn it into a success. A device that failed to
            // prepare falls through to a second attempt, which is the only way
            // a client can retry without rebooting.
            //
            // allowOpen covers the remaining case: the hook fires before this
            // device's first publish notification, so there is no offer record
            // yet. Publish one now instead of refusing, so a pre-open claim
            // that runs later still finds the record it must match.
            if (!offered) {
                if (!nic->setProperty(amd_iommu_policy::kOffer, this))
                    return false;
                nic->retain();
                offered = nic;
            } else if (offered != nic) {
                return false;
            }
            nic->removeProperty(amd_iommu_policy::kOffer);
        }
    } else {
        // Default selection (no amdiommu_devices). The device is still attached
        // eagerly below, so this path keeps working without Lilu; the offer is
        // published on top of that so the copyMapperForDevice hook can reach the
        // controller through the device, and so a pre-open claim has a record to
        // validate against. fOffers[] is indexed by the boot-argument list, which
        // is empty here, so the property itself is the record.
        if (!claim) {
            if (!nic->getProperty(amd_iommu_policy::kOffer) &&
                !nic->setProperty(amd_iommu_policy::kOffer, this))
                return false;
        } else {
            OSObject *offer = nic->getProperty(amd_iommu_policy::kOffer);
            if (offer && offer != this) return false;
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
    // allowOpen: the copyMapperForDevice() hook calls us from inside the
    // client's start(), after its PCI open, so open is expected there. Being
    // bound to a mapper is still refused - that would be a second domain for a
    // device that already resolves DMA somewhere else.
    if ((!allowOpen && nic->isOpen()) ||
        (claim && nic->getProperty("iommu-parent"))) {
        setProperty("attach-failure", "already-open-or-bound");
        setProperty("attach-rejected-requester", requester, 32);
        return false;
    }
    auto *mapper = new org_maz1_AMDMapperProbe;
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

bool org_maz1_AMDMapperProbe::PrepareController(const HardwareInfo &hardware) {
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
#if AMD_MAPPER_PM_TRACE
    // One private copy of the event ring, so a fault written before the S3 reset
    // can still be read after it. Trace build only.
    c->traceRing = (UInt8 *)IOMalloc((vm_size_t)M2B2_EVT_BUFFER_SIZE);
    if (c->traceRing) bzero(c->traceRing, (size_t)M2B2_EVT_BUFFER_SIZE);
    c->pmPhase = "boot";
#endif

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
bool org_maz1_AMDMapperProbe::PrepareDomain(
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
    // Allocate legacy storage before publishing iommu-parent. The ceiling is
    // an allocation limit, not a reservation made for every attached device.
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
    const bool growth = prepared->records < ceiling->records ||
        prepared->pages < ceiling->pages;
    // Per-instance admission evidence: the device mapper is its own instance,
    // so record whether this instance saw the boot-arg override at all.
    nic->setProperty("iommu-attach-forced", ForcedProfile() ? "yes" : "no");
    nic->setProperty("iommu-attach-instance", getRegistryEntryID(), 64);
    nic->setProperty("iommu-profile-source",
        source == mapper_abi::ProfileSource::bootArg ? "boot-arg"
        : (source == mapper_abi::ProfileSource::idTable ? "id-table"
        : (source == mapper_abi::ProfileSource::classTable ? "class-table"
                                                          : "legacy-fallback")));
    // Record the identity-based suggestion separately from the actual ceiling
    // and current usable capacity.
    nic->setProperty("iommu-profile-suggested", requested->name);
    nic->setProperty("iommu-profile-prepared", prepared->name);
    nic->setProperty("iommu-profile-ceiling-source",
                     forcedCeiling ? "boot-arg" : "default");
    nic->setProperty("iommu-profile-ceiling",
                     unsupported ? "unsupported-name" : ceiling->name);
    nic->setProperty("iommu-growth-policy", growth ? "capacity-demand" : "disabled");
    nic->setProperty("iommu-capacity-grown", "no");
    nic->setProperty("iommu-profile", prepared->name);
    const UInt64 preparedBytes = mapper_abi::metadataBytesFor(*prepared);
    const bool preparedOK = preparedBytes &&
        preparedBytes <= mapper_abi::kMaxMetadataBytes &&
        prepared->tablePages >= prepared->pages / 512 + 2 &&
        AllocateTableArea(d->tables,
            (UInt64)prepared->tablePages * M2B2_PAGE_SIZE, d->tablePA) &&
        PrepareMappings(d->tables, d->tablePA, M2B2_PAGE_MODE_4_LEVEL, *prepared);
    if (!preparedOK) {
        nic->setProperty("admission", "refused-no-arena");
        IOLog("AMDMapperProbe: admission refused, initial capacity %s did not prepare\n",
              prepared->name);
        if (fAutoAttach)
            panic("AMDMapperProbe: admission-refused: initial capacity did not prepare");
        if (d->tables) { d->tables->release(); d->tables = nullptr; }
        return false;
    }
    d->capacity = mapper_abi::capacityForProfile(*prepared);
    d->allocatedTablePages = prepared->tablePages;
    d->ceilingProfile = ceiling;
    const char *admission = growth
        ? (ceiling == &mapper_abi::kProfileDma32Max
               ? "granted-dma32-max-on-demand"
               : (ceiling == &mapper_abi::kProfileRl10gMax
                      ? "granted-rl-10g-max-on-demand" : "granted-rl-10g-on-demand"))
        : "granted-native-legacy";
    nic->setProperty("admission", admission);
    IOLog("AMDMapperProbe: domain %u prepared %s, ceiling %s (growth %s)\n",
          slot, prepared->name, unsupported ? "unsupported-name" : ceiling->name,
          growth ? "capacity-demand" : "disabled");
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
    PublishCapacity(true);
    PublishMappings();
    if (!nic->setProperty("iommu-parent", this)) return false;
    setProperty("iommu-parent-policy", fOwner->fAutoAttach
        ? "set-at-first-publish-autoattach"
        : (fOwner->fSelectionExplicit
            ? "set-on-client-claim-before-pci-open" : "set-before-driver-start"));
    return true;
}
#pragma clang diagnostic pop

// MapperState is private to the mapper translation unit. The configured
// ceiling is shared without exposing either implementation structure.
const mapper_abi::Profile *org_maz1_AMDMapperProbe::CeilingProfile() const {
    Domain *d = fDomain;
    return d ? d->ceilingProfile : nullptr;
}

bool org_maz1_AMDMapperProbe::CommitCapacityGrowth(
    const mapper_abi::Capacity &target, UInt32 allocatedTablePages, bool &invalidated) {
    invalidated = false;
    Controller *c = fController;
    Domain *d = fDomain;
    if (!c || !d) return false;
    // Caller holds the mapper lock; retain the existing mapper -> controller order.
    LockGuard guard(c->lock);
    // Linked table memory remains owned even when synchronization fails.
    // A record-only increase leaves this count and the hardware tree unchanged.
    d->allocatedTablePages = allocatedTablePages;
    if (!c->ready || c->command.failed) return false;
    if (d->active && target.pages > d->capacity.pages) {
        invalidated = true;
        // New upper-level entries require a PDE-cache fence regardless of the
        // non-present leaf-cache capability. An active DTE stays untouched.
        if (!InvalidateLocked(false, 0, 0, false, nullptr)) return false;
    }
    d->capacity = target;
    return true;
}

bool org_maz1_AMDMapperProbe::ReleaseDomain() {
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


bool org_maz1_AMDMapperProbe::Invalidate(
    bool invalidateDevice, UInt64 address, UInt64 bytes,
    bool newMapping, bool *skipped) {
    if (skipped) *skipped = false;
    Controller *c = fController;
    if (!c || !fDomain) return false;
    LockGuard guard(c->lock);
    return InvalidateLocked(invalidateDevice, address, bytes, newMapping, skipped);
}

bool org_maz1_AMDMapperProbe::InvalidateLocked(
    bool invalidateDevice, UInt64 address, UInt64 bytes,
    bool newMapping, bool *skipped) {
    // Both the caller's mapper lock and shared controller lock are held.
    // One queue cursor and CompletionWait sequence serve all device domains.
    if (skipped) *skipped = false;
    Controller *c = fController;
    Domain *d = fDomain;
    if (!c || !d || !c->ready || c->command.failed) return false;
    const bool full = !d->active || invalidateDevice || !bytes;
    const UInt64 windowBytes = (UInt64)d->capacity.pages * 4096ULL;
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
IOReturn org_maz1_AMDMapperProbe::SwitchRequesterDMA(bool park) {
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

IOReturn org_maz1_AMDMapperProbe::SetSystemPM(bool armed) {
    Controller *c = fController;
    if (!fAuto || fOwner || !c) return kIOReturnBadArgument;
    LockGuard guard(c->lock);
    if (armed) {
        if (!c->ready || c->suspended || c->powerFailed)
            return kIOReturnNotReady;
        UInt32 present = 0;
        for (UInt32 i = 0; i < kMaxDomains; ++i) {
            Domain *domain = c->domains[i];
            if (!domain) continue;
            ++present;
            if (!domain->active) return kIOReturnNotReady;
        }
        // R72: a single domain needs no cross-requester barrier, so arming it is
        // legal. The published scope says which topology is in force instead of
        // refusing the request outright.
        if (!present || present != c->domainCount) return kIOReturnNotReady;
        c->coordinatedPMArmed = true;
    } else {
        if (c->suspended) return kIOReturnBusy;
        c->coordinatedPMArmed = false;
    }
    setProperty("pm-coordinated-armed", c->coordinatedPMArmed ? "yes" : "no");
    return kIOReturnSuccess;
}

bool org_maz1_AMDMapperProbe::PowerSupported() const {
    Controller *c = fController;
    if (!c || !fDomain) return false;
    LockGuard guard(c->lock);
    // A single requester needs no barrier. Two or more are enabled only by an
    // explicit runtime arm after every requester has been initialized, and the
    // barrier itself is written over kMaxDomains, so the count is not limited.
    if (!c->domainCount) return false;
    if (c->domainCount == 1) return true;
    if (!c->coordinatedPMArmed) return false;
    UInt32 present = 0;
    for (UInt32 i = 0; i < kMaxDomains; ++i) {
        Domain *domain = c->domains[i];
        if (!domain) continue;
        ++present;
        if (!domain->active) return false;
    }
    return present == c->domainCount;
}

// R72: suspend is reached from two triggers - the private RequestPowerTransition RPC
// and the self-driven system sleep notification. Both close admission, and both
// touch the translation hardware only when no requester still holds a live
// mapping. With IOMMU_EN cleared a client that is still DMAing would address
// physical memory directly, which is worse than a failed transition.
bool org_maz1_AMDMapperProbe::SuspendAuto() {
    Controller *c = fController;
    Domain *d = fDomain;
    if (!c || !d) return false;
    LockGuard guard(c->lock);
    if (!c->domainCount || !c->ready || c->suspended || c->powerFailed)
        return false;
    c->resumeRegistersRestored = false;
    c->sleepControl = mmioRead64(c->base, M2B2_OFF_CONTROL);
    if ((c->sleepControl & kEnabled) != kEnabled)
        return c->powerFailure("failed-pm-suspend-controller-not-enabled");
    if (c->domainCount > 1) {
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
        d->pmSuspendRequested = true;
        bool allReady = true;
        for (UInt32 i = 0; i < kMaxDomains; ++i)
            if (c->domains[i] && !c->domains[i]->pmSuspendReady) allReady = false;
        if (!allReady) return true;
    } else {
        if (!InvalidateLocked(false, 0, 0, false, nullptr))
            return c->powerFailure("failed-pm-suspend-fence");
        ++d->pmSuspends;
        d->pmSuspendSequence = c->command.completionSequence;
        d->pmSuspendRequested = true;
    }
    // R72/M7: revoking this requester's IR/IW and stopping the controller are
    // both gated on the mapper's own live-mapping count. That is a fact about
    // the requester, not an assumption about the system's PM callback order.
    if (c->allDmaQuiesced()) {
        if (d->active && !fDMAParked) {
            // Rewrite the DTE without IR/IW and fence it: a requester that keeps
            // cached translations would otherwise keep using a stale table image
            // once the controller is enabled again.
            fDMAParked = true;
            d->pmParkedBySuspend = true;
            if (!InvalidateLocked(true, 0, 0, false, nullptr)) {
                fDMAParked = false;
                d->pmParkedBySuspend = false;
                return c->powerFailure("failed-pm-suspend-requester");
            }
            ++d->parkCount;
        }
        c->suspendSequence = c->command.completionSequence;
        if (!c->stopHardware())
            return c->powerFailure("failed-pm-suspend-controller");
        c->collectEvents();
        c->state = "suspended";
        // Only a stopped controller is not ready. A retained suspend leaves the
        // engines programmed, and claiming otherwise would send every DMA call
        // the requester still makes during its own teardown through a full
        // restore: hundreds of invalidations, each with its own completion wait,
        // on the path that is trying to sleep.
        c->ready = false;
    } else {
        // Retained: the requester still owns mappings, so the image is left
        // programmed. Entering S3 resets it anyway and the wake path reprograms
        // it from scratch, so nothing is lost by not stopping it here.
        c->suspendSequence = c->command.completionSequence;
        ++c->retainedSuspends;
        c->pmReason = "suspend-retained-live-mappings";
        c->state = "suspended-retained";
    }
    c->suspended = true;
    c->suspendTime = mach_absolute_time();
    ++c->suspendCount;
    return true;
}

// R72: reinstall the controller's register image. The hardware decides: when the
// image is still present nothing is rewritten, so a spurious restore can never
// clear IOMMU_EN underneath a requester that is still using its translations.
bool org_maz1_AMDMapperProbe::RestoreHardwareAfterWake(MapperState *state) {
    Controller *c = fController;
    if (!c || !state || !c->configured) return false;
    if (c->signatureOK()) {
        // Retained suspend, or a transition that kept the image intact: only
        // readiness has to be re-established.
        c->observedControl = mmioRead64(c->base, M2B2_OFF_CONTROL);
        c->resumeRegistersRestored = true;
        c->ready = true;
        return true;
    }
    // A device left in D3 answers all-ones. Nothing can be restored there, and
    // submitting into that ring would never complete.
    if (!c->responding()) {
        c->pmReason = "failed-wake-controller-unresponsive";
        return false;
    }
    if (c->hardware.pciEfrSupported && c->startupEfr && c->startupEfr != ~0ULL &&
        mmioRead64(c->base, M21_OFF_EXT_FEAT) != c->startupEfr) {
        c->pmReason = "failed-wake-identity";
        return false;
    }
    // The image is known to be gone from here on, so stopping cannot make
    // anything worse: both engines already lost their program.
    if (!c->stopHardware()) {
        c->pmReason = "failed-wake-stop";
        return false;
    }
    // Linux v6.6 init.c early_enable_iommu() reloads the device table and the
    // stopped command/event rings, then enables and invalidates. Only the ring
    // position restarts: sequence numbers and evidence counters stay monotonic,
    // so an old semaphore value can never complete a new completion wait.
#if AMD_MAPPER_PM_TRACE
    // Keep what the producer wrote before the reset. S3 cleared HEAD/TAIL, so
    // this is the only chance to see a fault that landed during the requesters'
    // own teardown.
    if (c->traceRing && c->traceHaveTail) {
        memcpy(c->traceRing, c->events->getBytesNoCopy(), M2B2_EVT_BUFFER_SIZE);
        c->scanPreResetRing();
    }
#endif
    bzero(c->commands->getBytesNoCopy(), M23_CMD_BUF_SIZE);
    bzero(c->events->getBytesNoCopy(), M2B2_EVT_BUFFER_SIZE);
    c->headCache.valid = false; // no cached position survives a hardware ring reset
    c->command.idx = 0;
    c->command.tail = 0;
    c->command.domid = 0;
    c->command.devid = 0;
    c->command.rootPA = 0;
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
    // sleepControl is captured while the controller is enabled; originalControl
    // is the firmware value the first enable sequence started from. Without a
    // suspend record the second one is the only correct baseline.
    const UInt64 baseline = c->sleepControl ? c->sleepControl : c->originalControl;
    UInt64 control = baseline & ~kEnabled;
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
        (c->observedControl & kEnabled) == kEnabled;
    if (!c->resumeRegistersRestored) {
        c->pmReason = "failed-wake-registers";
        return false;
    }
    UInt32 status = 0;
    const UInt32 running = M2B2_STATUS_CMDBUF_RUN | M2B2_STATUS_EVT_RUN;
    for (UInt32 i = 0; i < M2B1_LOOP_TIMEOUT; ++i) {
        status = mmioRead32(c->base, M2B2_OFF_STATUS);
        if ((status & running) == running) break;
    }
    if ((status & running) != running) {
        c->pmReason = "failed-wake-engines";
        return false;
    }
    // Only now, with the image written back and both engines proven running, may
    // a ring abandoned mid-transition be reused. HEAD is never moved and the ring
    // is never grown: the consumer was reset by the power transition itself.
    if (c->command.failed) {
        c->command.failed = false;
        c->command.failReason = nullptr;
        ++c->commandRecoveries;
    }
    c->ready = true;
    return true;
}

// Both locks are held. Returns true with the controller ready and completely
// flushed, or false with pmReason naming the step that failed.
bool org_maz1_AMDMapperProbe::ReconcileControllerLocked(MapperState *state) {
    Controller *c = fController;
    Domain *d = fDomain;
    if (!c || !d || !state || !c->configured) return false;
    if (!RestoreHardwareAfterWake(state)) return false;
    if (!c->ready) return false;
    // The device and PDE caches did not survive, and the DTE write also restores
    // this requester's IR/IW when the suspend side revoked them.
    if (!InvalidateLocked(true, 0, 0, false, nullptr)) {
        c->pmReason = "failed-wake-invalidation";
        return false;
    }
    c->suspended = false;
    c->resumeTime = mach_absolute_time();
    c->resumeDevSequence = d->lastInvDevSequence;
    c->resumePagesSequence = d->lastInvPagesSequence;
    d->recordPMResume();
    d->pmResumeReady = true;
    // pmSuspendRequested is deliberately NOT cleared here. It is the flag that
    // lets MapMemory reopen an admission this transition closed; clearing it
    // while admission is still closed would make every later map return
    // kIOReturnNotReady until something else reopened the domain.
    d->state = "pm-resume-ready";
    return true;
}

// Every DMA entry point calls this with the mapper lock held. A wake that
// delivered no suspend notification is repaired here, before any PTE changes.
bool org_maz1_AMDMapperProbe::EnsureControllerOperationalLocked(
    MapperState *state, const char *where) {
    Controller *c = fController;
    if (!c || !state || !c->configured) return false;
    if (c->ready && c->signatureOK()) return true;
    LockGuard guard(c->lock);
    if (c->ready && c->signatureOK()) return true;
    if (!ReconcileControllerLocked(state)) {
        ++c->resumeFailures;
        if (!c->pmReason) c->pmReason = where;
        return false;
    }
    ++c->lazyRestores;
#if AMD_MAPPER_PM_TRACE
    // The requester reached the controller before the wake notification did.
    c->pmPhase = "post-restore-lazy";
    c->collectEvents();
    ++c->traceDrains;
#endif
    return true;
}

// R72: D0 readiness and the retained BAR/MMIO image are read back from the
// hardware, so this path no longer depends on a suspend having been observed.
bool org_maz1_AMDMapperProbe::ResumeAuto() {
    Controller *c = fController;
    Domain *d = fDomain;
    MapperState *state = fMapper;
    if (!c || !d || !state) return false;
    LockGuard guard(c->lock);
    if (!c->domainCount || !c->suspended || c->powerFailed) {
        // The first requester restored the shared controller. Later requesters
        // only need to invalidate their own DTE/domain before reopening.
        if (c->domainCount > 1 && c->ready && !c->suspended &&
            !c->powerFailed && !d->pmResumeReady && c->resumeRegistersRestored &&
            c->suspendCount == c->resumeCount + 1) {
            // This is the second requester only after the first has restored
            // the engines. An incomplete suspend is NOT a restored controller.
            if (!InvalidateLocked(true, 0, 0, false, nullptr))
                return c->powerFailure("failed-pm-domain-resume-invalidation");
            d->recordPMResume();
            d->pmResumeReady = true;
            // Every resume path has to consume this domain's suspend flag.
            // Leaving it set makes the next SuspendAuto() treat a fresh cycle as
            // a second suspend and report it as a suspend failure.
            d->pmSuspendReady = false;
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
        // R72: already awake. Either a lazy reconcile completed the resume before
        // this notification arrived, or the suspend was retained and the image
        // never left. Both are a completed resume, and both must be counted:
        // otherwise suspendCount stays one ahead of resumeCount for the rest of
        // the boot and the second-requester test above can never fire again.
        if (c->ready && !c->suspended && !c->powerFailed) {
            // A wake that produced no suspend notification can also leave the
            // image gone while an earlier DMA call already marked the controller
            // ready; repair that here instead of failing the whole domain.
            if (!c->signatureOK() && !ReconcileControllerLocked(state))
                return c->powerFailure(c->pmReason ? c->pmReason
                                                   : "failed-pm-resume-state");
            c->resumeRegistersRestored = true;
            // The lazy path already recorded this domain's resume; the retained
            // path has not, and recordPMResume() is per domain.
            if (!d->pmResumeReady) d->recordPMResume();
            d->pmResumeReady = true;
            d->pmSuspendReady = false;
            // pmSuspendRequested stays set until the caller that reopens
            // admission clears it, so a map cannot be refused for a domain that
            // is merely waiting to be reopened.
            d->state = "pm-resume-ready";
            c->resumeDevSequence = d->lastInvDevSequence;
            c->resumePagesSequence = d->lastInvPagesSequence;
            bool allReady = true;
            for (UInt32 i = 0; i < kMaxDomains; ++i)
                if (c->domains[i] && !c->domains[i]->pmResumeReady) allReady = false;
            if (allReady) {
                c->resumeTime = mach_absolute_time();
                // Count only a resume that answers a recorded suspend, so a
                // notification without one cannot inflate the cycle counter.
                if (c->suspendCount > c->resumeCount) ++c->resumeCount;
                c->state = c->domainCount > 1 ? "ready-all-domains"
                                              : "ready-shared-controller";
            } else {
                c->state = "ready-awaiting-domain-resume";
            }
            return true;
        }
        if (c->domainCount > 1 && !c->powerFailed)
            return c->powerFailure("failed-pm-resume-before-controller-restore");
        return false;
    }
    if (c->domainCount > 1) {
        for (UInt32 i = 0; i < kMaxDomains; ++i)
            if (c->domains[i] && !c->domains[i]->pmSuspendReady)
                return c->powerFailure("failed-pm-resume-incomplete-suspend-barrier");
    }
    // Undo the suspend side's own revocation before the reconciliation writes the
    // DTE again, so the restored image carries this requester's permissions.
    if (d->pmParkedBySuspend) {
        fDMAParked = false;
        d->pmParkedBySuspend = false;
        ++d->restoreCount;
    }
    if (!ReconcileControllerLocked(state))
        return c->powerFailure(c->pmReason ? c->pmReason : "failed-pm-resume");
    if (c->domainCount > 1) {
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

// R72: the sleep side. Runs on the PM thread, so allocation for the boundary
// snapshots is allowed here and deliberately kept out of the DMA path. The body
// lives in AMDMapperProbeMapper.cpp because MapperState is private to it; this
// translation unit only sequences the controller transitions.

// R72: the DMA path lives in AMDMapperProbeMapper.cpp, which cannot see Domain.
bool org_maz1_AMDMapperProbe::SuspendRequested() const {
    Domain *d = fDomain;
    return d && d->pmSuspendRequested;
}

void org_maz1_AMDMapperProbe::SetSuspendRequested(bool value) {
    Domain *d = fDomain;
    if (d) d->pmSuspendRequested = value;
}

void org_maz1_AMDMapperProbe::NoteLiveMapping(bool live) {
    Domain *d = fDomain;
    if (!d) return;
    if (live) ++d->pmLiveMaps;
    else if (d->pmLiveMaps) --d->pmLiveMaps;
}

bool org_maz1_AMDMapperProbe::ControllerReady() const {
    Controller *c = fController;
    return c && c->ready;
}

// The notifier lives on the controller instance; a device mapper reports the
// state of the instance that actually registered.
bool org_maz1_AMDMapperProbe::PMNotifierRegistered() const {
    if (fOwner) return fOwner->fSystemPMNotifier != nullptr;
    return fSystemPMNotifier != nullptr;
}

// R72: PM state is published at the transition, not only when a snapshot is
// requested, so a wake can be judged from the registry immediately. That includes
// the sequences and timestamps: RefreshSnapshot is the only other publisher, and
// nobody asks for one while judging a wake, so those keys would otherwise keep
// their prepare-time zeros and the transition's own completion waits would be
// invisible.
void org_maz1_AMDMapperProbe::PublishPMNow(const char *reason) {
    Controller *c = fController;
    Domain *d = fDomain;
    if (!c) return;
    UInt64 suspendCount, resumeCount, failures, lazy, retained, recoveries, resumes;
    UInt64 suspendTime, resumeTime, suspendSequence, resumeDevSeq, resumePagesSeq;
    UInt64 pmSuspends = 0, pmResumes = 0, pmSuspendSeq = 0;
    UInt64 pmDevSeq = 0, pmPagesSeq = 0;
    UInt32 liveMaps = 0, domainCount = 0, suspendReady = 0, resumeReady = 0;
    bool ready, suspended, restored, failed, armed;
    const char *state;
    {
        LockGuard guard(c->lock);
        suspendCount = c->suspendCount; resumeCount = c->resumeCount;
        failures = c->powerFailures; lazy = c->lazyRestores;
        retained = c->retainedSuspends; recoveries = c->commandRecoveries;
        resumes = c->resumeFailures;
        suspendTime = c->suspendTime; resumeTime = c->resumeTime;
        suspendSequence = c->suspendSequence;
        resumeDevSeq = c->resumeDevSequence; resumePagesSeq = c->resumePagesSequence;
        armed = c->coordinatedPMArmed;
        ready = c->ready; suspended = c->suspended;
        restored = c->resumeRegistersRestored; failed = c->powerFailed;
        state = c->state;
        domainCount = c->domainCount;
        for (UInt32 i = 0; i < kMaxDomains; ++i) {
            if (!c->domains[i]) continue;
            suspendReady += c->domains[i]->pmSuspendReady ? 1 : 0;
            resumeReady += c->domains[i]->pmResumeReady ? 1 : 0;
        }
        // Statistics only, and this runs on the PM thread: a live count read
        // without the mapper lock cannot put a PTE at risk.
        if (d) {
            pmSuspends = d->pmSuspends; pmResumes = d->pmResumes;
            pmSuspendSeq = d->pmSuspendSequence;
            pmDevSeq = d->pmResumeDevSequence; pmPagesSeq = d->pmResumePagesSequence;
            liveMaps = d->pmLiveMaps;
        }
    }
    // The reads above were taken under the controller lock; the property writes
    // may allocate and therefore happen outside it.
    setProperty("pm-controller-state", failed ? "failed" :
                (suspended ? "suspended" : "awake"));
    setProperty("iommu-controller-ready", ready ? "yes" : "no");
    setProperty("iommu-state", state ? state : "unknown");
    setProperty("pm-resume-registers-restored", restored ? "yes" : "no");
    setProperty("pm-controller-suspend-count", (unsigned long long)suspendCount, 64);
    setProperty("pm-controller-resume-count", (unsigned long long)resumeCount, 64);
    setProperty("pm-controller-failures", (unsigned long long)failures, 64);
    setProperty("pm-controller-suspend-time", (unsigned long long)suspendTime, 64);
    setProperty("pm-controller-resume-time", (unsigned long long)resumeTime, 64);
    setProperty("pm-controller-suspend-sequence",
                (unsigned long long)suspendSequence, 64);
    setProperty("pm-controller-resume-device-invalidation-sequence",
                (unsigned long long)resumeDevSeq, 64);
    setProperty("pm-controller-resume-pages-invalidation-sequence",
                (unsigned long long)resumePagesSeq, 64);
    setProperty("pm-domain-count", (unsigned long long)domainCount, 32);
    setProperty("pm-coordinated-armed", armed ? "yes" : "no");
    setProperty("pm-support-scope", domainCount > 1
        ? (armed ? "coordinated-armed" : "coordinated-unarmed") : "single-device");
    setProperty("pm-suspend-ready", (unsigned long long)suspendReady, 32);
    setProperty("pm-resume-ready", (unsigned long long)resumeReady, 32);
    setProperty("pm-domain-suspend-count", (unsigned long long)pmSuspends, 64);
    setProperty("pm-domain-resume-count", (unsigned long long)pmResumes, 64);
    setProperty("pm-domain-suspend-sequence", (unsigned long long)pmSuspendSeq, 64);
    setProperty("pm-domain-resume-device-sequence", (unsigned long long)pmDevSeq, 64);
    setProperty("pm-domain-resume-pages-sequence", (unsigned long long)pmPagesSeq, 64);
    setProperty("pm-domain-live-mappings", (unsigned long long)liveMaps, 32);
    setProperty("pm-lazy-restores", (unsigned long long)lazy, 64);
    setProperty("pm-suspend-retained", (unsigned long long)retained, 64);
    setProperty("pm-command-recoveries", (unsigned long long)recoveries, 64);
    setProperty("pm-resume-failures", (unsigned long long)resumes, 64);
    // Cross-boundary evidence: lives in AMDMapperProbeMapper.cpp because it has
    // to retain the blobs under the mapper lock.
    PublishPMBoundary();
    if (reason) setProperty("pm-last-transition", reason);
}

bool org_maz1_AMDMapperProbe::RegisterSystemPM() {
    if (fSystemPMNotifier) return true;
    char mode[16] = {};
    if (PE_parse_boot_argn("amdiommu_pm", mode, sizeof(mode) - 1) &&
        strcmp(mode, "off") == 0) {
        setProperty("pm-self-driven", "disabled-by-boot-arg");
        return false;
    }
    // registerSleepWakeInterest() registers a kIOGeneralInterest client with the
    // root domain. Delivering kIOMessageSystemWillSleep through that path requires
    // a response within the sleep timeout, so the handler returns success and
    // leaves the notification's returnValue at zero, which acknowledges at once.
    fSystemPMNotifier = registerSleepWakeInterest(sleepWakeHandler, this, nullptr);
    if (!fSystemPMNotifier) {
        setProperty("pm-self-driven", "failed-register");
        return false;
    }
    setProperty("pm-self-driven", "registered");
    return true;
}

void org_maz1_AMDMapperProbe::UnregisterSystemPM() {
    if (!fSystemPMNotifier) return;
    fSystemPMNotifier->disable();
    fSystemPMNotifier->release();
    fSystemPMNotifier = nullptr;
    setProperty("pm-self-driven", "unregistered");
}

IOReturn org_maz1_AMDMapperProbe::sleepWakeHandler(
    void *target, void *refCon, UInt32 messageType, IOService *provider,
    void *messageArgument, vm_size_t argSize) {
    (void)refCon; (void)provider; (void)messageArgument; (void)argSize;
    auto *self = static_cast<org_maz1_AMDMapperProbe *>(target);
    if (!self) return kIOReturnSuccess;
    switch (messageType) {
    case kIOMessageSystemWillSleep:
        self->SystemWillSleep();
        break;
    case kIOMessageSystemHasPoweredOn:
        self->SystemHasPoweredOn();
        break;
    default:
        break;
    }
    return kIOReturnSuccess;
}

void org_maz1_AMDMapperProbe::SystemWillSleep() {
    if (fOwner || !fAttachLock) return;
    uint32_t suspended = 0, failed = 0;
#if AMD_MAPPER_PM_TRACE
    // Baseline drain: everything the controller logged up to this point belongs
    // to ordinary operation. The tail is kept so a fault the producer writes
    // after this point can still be recovered from the ring copy taken at wake.
    if (fController && fController->configured && fController->traceRing) {
        Controller *c = fController;
        c->pmPhase = "pre-suspend";
        c->collectEvents();
        ++c->traceDrains;
        c->traceTailAtSuspend = mmioRead64(c->base, M2B2_OFF_EVT_TAIL);
        c->traceHaveTail = c->traceTailAtSuspend < M2B2_EVT_BUFFER_SIZE &&
            !(c->traceTailAtSuspend & 15);
    }
#endif
    {
        LockGuard attachment(fAttachLock);
        for (UInt32 i = 0; i < kMaxDomains; ++i) {
            auto *mapper = fMappers[i];
            if (!mapper || !mapper->fDomain) continue;
            if (mapper->SuspendDomain()) ++suspended; else ++failed;
        }
    }
    ++fSleepNotifications;
    setProperty("pm-sleep-notifications",
                (unsigned long long)fSleepNotifications, 64);
    setProperty("pm-last-suspend-domains", (unsigned long long)suspended, 32);
    setProperty("pm-last-suspend-failures", (unsigned long long)failed, 32);
#if AMD_MAPPER_PM_TRACE
    // What the transition itself produced, before the requesters tear down.
    if (fController && fController->configured && fController->traceRing) {
        fController->pmPhase = "post-suspend";
        fController->collectEvents();
        ++fController->traceDrains;
    }
#endif
    for (UInt32 i = 0; i < kMaxDomains; ++i) {
        auto *mapper = fMappers[i];
        if (mapper && mapper->fDomain) mapper->PublishPMNow("system-will-sleep");
    }
}

void org_maz1_AMDMapperProbe::SystemHasPoweredOn() {
    if (fOwner || !fAttachLock) return;
    uint32_t resumed = 0, failed = 0;
#if AMD_MAPPER_PM_TRACE
    // Only meaningful when the image survived; after a real S3 the pointers are
    // zero and the ring copy taken at restore covers the gap instead.
    if (fController && fController->configured && fController->traceRing &&
        fController->signatureOK()) {
        fController->pmPhase = "wake-entry";
        fController->collectEvents();
        ++fController->traceDrains;
    }
#endif
    {
        LockGuard attachment(fAttachLock);
        for (UInt32 i = 0; i < kMaxDomains; ++i) {
            auto *mapper = fMappers[i];
            if (!mapper || !mapper->fDomain) continue;
            if (mapper->ResumeDomain()) ++resumed; else ++failed;
        }
    }
    ++fWakeNotifications;
    setProperty("pm-wake-notifications", (unsigned long long)fWakeNotifications, 64);
    setProperty("pm-last-resume-domains", (unsigned long long)resumed, 32);
    setProperty("pm-last-resume-failures", (unsigned long long)failed, 32);
#if AMD_MAPPER_PM_TRACE
    // Anything the restored engines logged between enable and this point.
    if (fController && fController->configured && fController->traceRing) {
        fController->pmPhase = "post-resume";
        fController->collectEvents();
        ++fController->traceDrains;
    }
#endif
    for (UInt32 i = 0; i < kMaxDomains; ++i) {
        auto *mapper = fMappers[i];
        if (mapper && mapper->fDomain) mapper->PublishPMNow("system-has-powered-on");
    }
}

void org_maz1_AMDMapperProbe::PublishAuto() {
    Controller *c = fController;
    Domain *d = fDomain;
    if (!c || !d) return;
    LockGuard guard(c->lock);
    // The per-device snapshot holds its mapper lock. The shared lock also
    // serializes event HEAD consumption and queue counters across both NICs.
    if (c->configured && !c->suspended) {
#if AMD_MAPPER_PM_TRACE
        c->pmPhase = "awake";
#endif
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
    // R72: a single requester is a legal PM scope, and a two-requester controller
    // reports whether it is armed instead of declaring itself unsupported.
    setProperty("pm-support-scope", c->domainCount > 1
        ? (c->coordinatedPMArmed ? "coordinated-armed" : "coordinated-unarmed")
        : "single-device");
    setProperty("pm-self-driven", PMNotifierRegistered() ? "yes" : "no");
    setProperty("pm-last-reason", c->pmReason ? c->pmReason : "none");
    setProperty("pm-domain-suspend-requested", d->pmSuspendRequested ? "yes" : "no");
    setProperty("pm-domain-parked-by-suspend", d->pmParkedBySuspend ? "yes" : "no");
    number("pm-domain-live-mappings", d->pmLiveMaps);
    number("pm-lazy-restores", c->lazyRestores);
    number("pm-suspend-retained", c->retainedSuspends);
    number("pm-command-recoveries", c->commandRecoveries);
    number("pm-resume-failures", c->resumeFailures);
    number("invalidation-completed-total", d->invDevCompleted + d->invPagesCompleted);
    number("iommu-device-id", d->deviceID);
    number("iommu-domain-id", d->domainID);
    number("iommu-root-pa", d->tablePA);
    number("iommu-table-pa", d->tablePA);
    number("iommu-table-bytes", (UInt64)d->allocatedTablePages * M2B2_PAGE_SIZE);
    setProperty("iommu-domain-profile", mapper_abi::profileNameForCapacity(d->capacity));
    number("iommu-domain-profile-records", d->capacity.records);
    number("iommu-domain-profile-pages", d->capacity.pages);
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
#if AMD_MAPPER_PM_TRACE
    // Trace build only: when the drain saw the last fault, and in which PM
    // window. Compare iommu-fault-observed-time against pm-controller-suspend-time
    // and pm-controller-resume-time; "pre-restore-ring" means the fault was
    // written before the controller was reprogrammed.
    number("iommu-fault-count", d->faultCount);
    number("iommu-fault-type", d->faultType);
    number("iommu-fault-iova", d->faultIOVA);
    number("iommu-fault-observed-time", d->faultObservedTime);
    setProperty("iommu-fault-phase", d->faultPhase ? d->faultPhase : "none");
    number("iommu-fault-ring-recovered", c->traceRingFaults);
    number("iommu-trace-drains", c->traceDrains);
#endif
    // A snapshot taken while suspended must never probe powered-down MMIO.
    number("iommu-control-register", c->observedControl);
    if (c->devices) {
        const volatile UInt64 *dte =
            (volatile UInt64 *)c->devices->getBytesNoCopy();
        number("iommu-dte0", dte[d->deviceID * 4]);
        number("iommu-dte1", dte[d->deviceID * 4 + 1]);
    }
}


void org_maz1_AMDMapperProbe::PublishDomains() {
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

bool org_maz1_AMDMapperProbe::StopAuto() {
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
    // R72: detach from the root domain before taking the attach lock. disable()
    // waits for an in-flight handler, and those handlers take that same lock.
    UnregisterSystemPM();
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

void org_maz1_AMDMapperProbe::free() {
    // A pre-open claim pins the owner (and hence this lock) until it returns.
    if (fAttachLock) IOLockFree(fAttachLock);
    IOMapper::free();
}
