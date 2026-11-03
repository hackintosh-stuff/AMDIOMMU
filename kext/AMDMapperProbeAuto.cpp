// Persistent per-device hardware lifecycle for amdiommu=auto.
// The experiment's timer, Lucy bindings and measurement windows are not used.
#include "AMDMapperProbeInternal.hpp"
#include "AMDMapperProbeDiscovery.hpp"
#include "amd_iommu_mapper_abi.hpp"

namespace {
constexpr UInt32 kR44TablePages = 16;
constexpr UInt32 kR44Domain = 1;
// PCI IOMMU capability, not EFR: Linux v6.6 IOMMU_CAP_NPCACHE.
constexpr UInt32 kR51NpCache = 1u << 26;
constexpr UInt64 kR44Enabled = M2B2_CTRL_IOMMU_EN |
    M2B2_CTRL_CMDBUF_EN | M2B2_CTRL_EVT_LOG_EN;

bool r44Allocate(IOBufferMemoryDescriptor *&md, UInt64 bytes, UInt64 &pa) {
    md = IOBufferMemoryDescriptor::withCapacity((IOByteCount)bytes,
                                               kIODirectionOut, true);
    if (!md) return false;
    IOByteCount span = 0;
    pa = md->getPhysicalSegment(0, &span, kIOMemoryMapperNone);
    if (!pa || (pa & 0xfff) || span < bytes) return false;
    bzero(md->getBytesNoCopy(), (size_t)bytes);
    return true;
}
}

struct org_example_AMDMapperProbe::R44Controller {
    IOBufferMemoryDescriptor *tables, *devices, *commands, *semaphore, *events;
    IOMemoryDescriptor *mmioMemory;
    IOMemoryMap *mmioMap;
    volatile UInt8 *base;
    UInt64 tablePA, devicePA, commandPA, semaphorePA, eventPA;
    UInt64 originalDT, originalCommand, originalEvent, originalControl;
    R47HardwareInfo hardware;
    UInt64 startupEfr;
    UInt64 readyTime, activeTime;
    UInt64 invDevCompleted, invPagesCompleted;
    // R50 counters describe successfully completed ordinary invalidations.
    UInt64 invFullCompleted, invRangeCompleted, invRangePages;
    UInt64 mapInvalidationSkipped;
    UInt64 lastRangeAddress, lastRangeBytes, lastRangeSequence;
    UInt32 lastRangeCommand[4];
    UInt64 lastInvDevSequence, lastInvPagesSequence;
    UInt64 eventEntries, targetFaults;
    UInt64 sleepControl, observedControl;
    UInt64 suspendTime, resumeTime, suspendSequence;
    UInt64 resumeDevSequence, resumePagesSequence;
    UInt64 suspendCount, resumeCount, powerFailures;
    UInt32 lastEvent[4];
    UInt32 deviceID;
    M2B2CmdCtx command;
    const char *state;
    bool configured, ready, active, pinned, restored;
    bool eventOverflow, eventInvalid;
    bool suspended, powerFailed, resumeRegistersRestored;

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
            !(observedControl & kR44Enabled);
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
                if ((lastEvent[0] & M2B2_EVENT_DEVID_MASK) == deviceID)
                    ++targetFaults;
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
        if (restored) { configured = false; ready = false; active = false; }
        return restored;
    }

    void releaseBuffers() {
        if (mmioMap) mmioMap->release();
        if (mmioMemory) mmioMemory->release();
        if (events) events->release();
        if (semaphore) semaphore->release();
        if (commands) commands->release();
        if (devices) devices->release();
        if (tables) tables->release();
    }
};

bool org_example_AMDMapperProbe::r44StartAuto() {
    setProperty("r44-mode", "auto");
    setProperty("r44-state", "waiting-for-pci-publication");
    setProperty("r44-controller-ready", "no");
    setProperty("r44-dte-active", "no");
    setProperty("r44-system-mapper", "no");
    setProperty("m1b-gsystem", IOMapper::gSystem ? "NONNULL" : "NULL-as-expected");
    installPublishNotifier();
    if (!fPublishNotifier) {
        setProperty("r44-state", "failed-publish-notifier");
        return false;
    }

    // Existing unclaimed PCI services are also usable. An already attached
    // client is too late: Lucy only looks up its mapper once during start().
    if (!fNicDevice && !fR44Controller) {
        IOService *nic = findNicServiceOnly();
        if (nic) {
            setProperty("r44-start-nic", "found");
            setProperty("r44-start-nic-open", nic->isOpen() ? "yes" : "no");
            setProperty("r44-start-nic-client",
                        nic->getChildEntry(gIOServicePlane) ? "yes" : "no");
            r44AttachAuto(nic);
            nic->release();
        } else {
            setProperty("r44-start-nic", "absent");
        }
    }
    return true;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
bool org_example_AMDMapperProbe::r44AttachAuto(IOService *service) {
    if (!fR44Auto || fR44Controller) return fNicDevice == service;
    IOPCIDevice *nic = OSDynamicCast(IOPCIDevice, service);
    if (!nic || nic->configRead16(kIOPCIConfigVendorID) != 0x10ec ||
        nic->configRead16(kIOPCIConfigDeviceID) != 0x8127) return false;
    // The driver's single copyMapperForDevice() lookup runs before it opens
    // the PCI provider. A client attached to the nub but not yet started is
    // still safe to publish for: Round45's start() waits for this publication
    // with the nub unopened, so the lookup has not been missed. Only an open
    // provider means the driver already chose its DMA path. A publish
    // notification can replay an existing service when installed.
    if (nic->isOpen()) {
        setProperty("r44-state", "failed-too-late-open");
        return false;
    }

    R47HardwareInfo hardware{};
    if (!r47DiscoverHardware(this, nic, hardware)) {
        setProperty("r44-state", "failed-hardware-discovery");
        return false;
    }

    R44Controller *c = (R44Controller *)IOMalloc(sizeof(R44Controller));
    if (!c) { setProperty("r44-state", "failed-controller-memory"); return false; }
    bzero(c, sizeof(*c));
    fR44Controller = c;
    c->state = "preparing";
    c->hardware = hardware;
    c->deviceID = ((UInt32)nic->getBusNumber() << 8) |
        ((UInt32)nic->getDeviceNumber() << 3) | nic->getFunctionNumber();

    const char *failure = nullptr;
    if (!r44Allocate(c->tables, kR44TablePages * M2B2_PAGE_SIZE, c->tablePA) ||
        !r44Allocate(c->devices, M22B_TABLE_SIZE_FULL, c->devicePA) ||
        !r44Allocate(c->commands, M23_CMD_BUF_SIZE, c->commandPA) ||
        !r44Allocate(c->semaphore, M2B2_PAGE_SIZE, c->semaphorePA) ||
        !r44Allocate(c->events, M2B2_EVT_BUFFER_SIZE, c->eventPA)) {
        failure = "failed-dma-memory";
    } else if (!r44PrepareMappings((volatile UInt64 *)c->tables->getBytesNoCopy(),
                    c->tablePA, kR44TablePages, M2B2_PAGE_MODE_4_LEVEL)) {
        failure = "failed-mapper-prepare";
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
            setProperty("r47-mmio-efr", (unsigned long long)c->startupEfr, 64);
            // Host four-level translation, INV_DEV/INV_PAGES and CW are the
            // basic path. Guest/PASID/performance EFR bits are not requirements.
            // If firmware supplies an EFR image, verify the same unit's actual
            // register instead of requiring this board's former fixed value.
            if ((c->hardware.pciEfrSupported && c->startupEfr == ~0ULL) ||
                (c->hardware.firmwareEfrPresent &&
                 (!c->hardware.pciEfrSupported ||
                  c->startupEfr != c->hardware.firmwareEfr))) {
                setProperty("r47-efr-match", "no");
                failure = "failed-iommu-efr";
            } else {
                setProperty("r47-efr-match", !c->hardware.pciEfrSupported ?
                    "not-reported" : (c->hardware.firmwareEfrPresent ?
                    "yes" : "firmware-absent"));
            }
        }
        setProperty("r47-discovery-state", failure ? failure : "ready");
    }
    if (!failure) {
        c->originalDT = mmioRead64(c->base, M2B2_OFF_DEV_TABLE);
        c->originalCommand = mmioRead64(c->base, M2B2_OFF_CMD_BUF);
        c->originalEvent = mmioRead64(c->base, M2B2_OFF_EVT_BUF);
        c->originalControl = mmioRead64(c->base, M2B2_OFF_CONTROL);
        if (c->originalControl & kR44Enabled)
            failure = "failed-iommu-already-enabled";
    }
    if (failure) {
        setProperty("r44-state", failure);
        r44QuiesceMappings();
        r44ReleaseMappings();
        c->releaseBuffers();
        fR44Controller = nullptr;
        IOFree(c, sizeof(*c));
        return false;
    }

    volatile UInt64 *dte = (volatile UInt64 *)c->devices->getBytesNoCopy();
    for (UInt32 i = 0; i < M22B_TABLE_SIZE_FULL / M22B_DTE_SIZE; ++i)
        dte[i * 4] = DTE_V | DTE_TV | DTE_IR | DTE_IW;
    c->command.buf = (volatile UInt32 *)c->commands->getBytesNoCopy();
    c->command.sem = (volatile UInt64 *)c->semaphore->getBytesNoCopy();
    c->command.semPA = c->semaphorePA;
    c->command.devid = c->deviceID;
    c->command.domid = kR44Domain;
    c->command.rootPA = c->tablePA;
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
    if ((mmioRead64(c->base, M2B2_OFF_CONTROL) & kR44Enabled) != kR44Enabled) {
        c->state = "failed-controller-enable";
        setProperty("r44-failure", c->state);
        r44StopAuto();
        return false;
    }

    c->ready = true;
    c->readyTime = mach_absolute_time();
    c->state = "ready-passthrough";
    r44PublishMappings();
    // Publication is the final step: from here every ordinary mapping can
    // reach the prepared backend. First-map activation happens after Lucy's
    // rtl812xInit reset, before it receives the first descriptor-ring IOVA.
    nic->retain();
    fNicDevice = nic;
    nic->setProperty("iommu-parent", this);
    setProperty("r44-parent", "set-before-driver-start");
    return true;
}
#pragma clang diagnostic pop

bool org_example_AMDMapperProbe::r44Invalidate(
    bool invalidateDevice, UInt64 address, UInt64 bytes,
    bool newMapping, bool *skipped) {
    // The mapper lock serializes PTE publication, invalidation and IOVA reuse.
    // A map is usable only after the synchronization required by this IOMMU.
    if (skipped) *skipped = false;
    R44Controller *c = fR44Controller;
    if (!c || !c->ready || c->command.failed) return false;
    const bool full = !c->active || invalidateDevice || !bytes;
    if (!full && (((address | bytes) & 4095ULL) ||
        address < r44mapper::kBase ||
        address - r44mapper::kBase >= r44mapper::kPages * 4096ULL ||
        bytes > r44mapper::kPages * 4096ULL - (address - r44mapper::kBase)))
        return false;
    OSSynchronizeIO();
    // Upper-level tables are prebuilt and ordinary maps fill only empty leaves.
    // Unmap still waits for invalidation before returning IOVA to the allocator.
    // With no non-present cache, a new mapping therefore needs no INV/CW.
    // First activation, explicit device flush and PM always retain their fence.
    if (newMapping && !full && !(c->hardware.capabilityHeader & kR51NpCache)) {
        ++c->mapInvalidationSkipped;
        if (skipped) *skipped = true;
        return true;
    }
    if (!c->active || invalidateDevice) {
        volatile UInt64 *dte = (volatile UInt64 *)c->devices->getBytesNoCopy();
        dte[c->deviceID * 4 + 1] = kR44Domain;
        dte[c->deviceID * 4] = (c->tablePA & M2B2_PTE_ADDR_MASK) |
            ((UInt64)M2B2_PAGE_MODE_4_LEVEL << M2B2_DEV_ENTRY_MODE_SHIFT) |
            DTE_V | DTE_TV | DTE_IR | DTE_IW;
        OSSynchronizeIO();
        if (!m2b2Submit(c->base, &c->command, "r44-activate-device", c->deviceID,
                ((UInt32)M2B2_CMD_INV_DEV_ENTRY << 28), 0, 0)) {
            c->state = "failed-device-invalidation";
            return false;
        }
        ++c->invDevCompleted;
        c->lastInvDevSequence = c->command.completionSequence;
    }
    // First activation and power transitions still flush the complete domain
    // and PDE cache. Ordinary maps only edit leaves of the prebuilt IOVA tree.
    const UInt64 encoded = full ? m2b2InvAddress() : r50InvRangeAddress(address, bytes);
    const UInt32 d0 = 0;
    const UInt32 d1 = kR44Domain | ((UInt32)M2B2_CMD_INV_IOMMU_PAGES << 28);
    const UInt32 d2 = (UInt32)encoded | (full ? M2B2_CMD_PDE_MASK : 0);
    const UInt32 d3 = (UInt32)(encoded >> 32);
    if (!m2b2Submit(c->base, &c->command, "r44-invalidate-pages", d0, d1, d2, d3)) {
        c->state = "failed-page-invalidation";
        return false;
    }
    ++c->invPagesCompleted;
    c->lastInvPagesSequence = c->command.completionSequence;
    if (full) ++c->invFullCompleted;
    else {
        ++c->invRangeCompleted;
        c->invRangePages += bytes / 4096;
        c->lastRangeAddress = address;
        c->lastRangeBytes = bytes;
        c->lastRangeCommand[0] = d0; c->lastRangeCommand[1] = d1;
        c->lastRangeCommand[2] = d2; c->lastRangeCommand[3] = d3;
        c->lastRangeSequence = c->command.completionSequence;
    }
    if (!c->active) {
        c->active = true;
        c->activeTime = mach_absolute_time();
        c->state = "active";
    }
    return true;
}

// TODO(R47-PM-HARDWARE): validate the real suspend/resume sequence once this
// AMD platform can sleep reliably. R47 acceptance does not invoke this path.
bool org_example_AMDMapperProbe::r47SuspendAuto() {
    // The mapper lock is held and admission is closed. Lucy's PM gate has
    // already completed the network family's disable/clearRxTxRings path.
    R44Controller *c = fR44Controller;
    if (!c || !c->ready || c->suspended || c->powerFailed) return false;
    c->resumeRegistersRestored = false;
    c->sleepControl = mmioRead64(c->base, M2B2_OFF_CONTROL);
    if ((c->sleepControl & kR44Enabled) != kR44Enabled || !r44Invalidate())
        return c->powerFailure("failed-pm-suspend-fence");
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
bool org_example_AMDMapperProbe::r47ResumeAuto() {
    // The PCI parent and Lucy's D0 transition are complete, but its normal
    // enable has not run. All tables, DMA objects and mapping records survive.
    R44Controller *c = fR44Controller;
    if (!c || !c->suspended || c->powerFailed) return false;
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
    UInt64 control = c->sleepControl & ~kR44Enabled;
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
    if (!r44Invalidate(true))
        return c->powerFailure("failed-pm-resume-invalidation");
    c->resumeDevSequence = c->lastInvDevSequence;
    c->resumePagesSequence = c->lastInvPagesSequence;
    c->resumeTime = mach_absolute_time();
    ++c->resumeCount;
    c->suspended = false;
    c->state = c->active ? "active" : "ready-passthrough";
    return true;
}

void org_example_AMDMapperProbe::r44PublishAuto() {
    R44Controller *c = fR44Controller;
    if (!c) return;
    // Called while the generic mapper lock is held, or before publication /
    // after quiescing. The event producer owns TAIL; only advance consumed HEAD.
    if (c->configured && !c->suspended) {
        c->collectEvents();
        c->observedControl = mmioRead64(c->base, M2B2_OFF_CONTROL);
    }
    auto number = [this](const char *key, UInt64 value) {
        setProperty(key, (unsigned long long)value, 64);
    };
    setProperty("r44-state", c->state ? c->state : "preparing");
    setProperty("r44-controller-ready", c->ready ? "yes" : "no");
    setProperty("r44-dte-active", c->active ? "yes" : "no");
    setProperty("r44-registers-restored", c->restored ? "yes" : "no");
    setProperty("r44-event-overflow", c->eventOverflow ? "yes" : "no");
    setProperty("r44-event-valid", c->eventInvalid ? "no" : "yes");
    setProperty("r44-command-failed", c->command.failed ? "yes" : "no");
    setProperty("r47-pm-state", c->powerFailed ? "failed" :
                (c->suspended ? "suspended" : "awake"));
    setProperty("r47-resume-registers-restored",
                c->resumeRegistersRestored ? "yes" : "no");
    number("r47-suspend-count", c->suspendCount);
    number("r47-resume-count", c->resumeCount);
    number("r47-pm-failures", c->powerFailures);
    number("r47-suspend-at", c->suspendTime);
    number("r47-resume-at", c->resumeTime);
    number("r47-suspend-cw-sequence", c->suspendSequence);
    number("r47-resume-inv-dev-sequence", c->resumeDevSequence);
    number("r47-resume-inv-pages-sequence", c->resumePagesSequence);
    number("r44-target-devid", c->deviceID);
    number("r44-domain-id", kR44Domain);
    number("r44-root-pa", c->tablePA);
    number("r44-table-pa", c->tablePA);
    number("r44-table-bytes", kR44TablePages * M2B2_PAGE_SIZE);
    number("r44-device-table-pa", c->devicePA);
    number("r44-command-pa", c->commandPA);
    number("r44-event-pa", c->eventPA);
    number("r44-controller-ready-time", c->readyTime);
    number("r44-dte-active-time", c->activeTime);
    number("r44-inv-dev-completed", c->invDevCompleted);
    number("r44-inv-pages-completed", c->invPagesCompleted);
    number("r51-npcache", (c->hardware.capabilityHeader & kR51NpCache) ? 1 : 0);
    number("r51-map-invalidation-skipped", c->mapInvalidationSkipped);
    number("r50-inv-full-completed", c->invFullCompleted);
    number("r50-inv-range-completed", c->invRangeCompleted);
    number("r50-inv-range-pages", c->invRangePages);
    number("r50-last-range-address", c->lastRangeAddress);
    number("r50-last-range-bytes", c->lastRangeBytes);
    number("r50-last-range-sequence", c->lastRangeSequence);
    for (UInt32 i = 0; i < 4; ++i) {
        char key[32];
        snprintf(key, sizeof(key), "r50-last-range-command%u", i);
        number(key, c->lastRangeCommand[i]);
    }
    number("r44-cmd-submits", c->command.submits);
    number("r44-cmd-completed", c->command.completed);
    number("r44-cmd-wraps", c->command.wraps);
    number("r44-cmd-post-wrap", c->command.postWrapCompleted);
    number("r44-cmd-completion-sequence", c->command.completionSequence);
    number("r44-event-entries", c->eventEntries);
    number("r44-target-faults", c->targetFaults);
    for (UInt32 i = 0; i < 4; ++i) {
        char key[32];
        snprintf(key, sizeof(key), "r44-last-event%u", i);
        number(key, c->lastEvent[i]);
    }
    // A snapshot taken while suspended must never probe powered-down MMIO.
    number("r44-control", c->observedControl);
    if (c->devices) {
        const volatile UInt64 *dte =
            (volatile UInt64 *)c->devices->getBytesNoCopy();
        number("r44-dte0", dte[c->deviceID * 4]);
        number("r44-dte1", dte[c->deviceID * 4 + 1]);
    }
}

bool org_example_AMDMapperProbe::r44StopAuto() {
    R44Controller *c = fR44Controller;
    if (!c) return r44QuiesceMappings() && r44ReleaseMappings();
    if (!r44QuiesceMappings()) {
        c->state = "retained-live-mappings";
        r44PublishMappings();
        if (!c->pinned) { c->pinned = true; retain(); }
        return false;
    }
    r44PublishMappings();
    if (!c->restore()) {
        c->state = "retained-hardware-stop-failed";
        r44PublishAuto();
        if (!c->pinned) { c->pinned = true; retain(); }
        return false;
    }
    c->state = "stopped";
    r44PublishAuto();
    if (!r44ReleaseMappings()) return false;
    const bool pinned = c->pinned;
    c->releaseBuffers();
    fR44Controller = nullptr;
    IOFree(c, sizeof(*c));
    if (pinned) release();
    return true;
}
