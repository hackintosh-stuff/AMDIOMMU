// Persistent per-device hardware lifecycle for amdiommu=auto.
// The experiment's timer, Lucy bindings and measurement windows are not used.
#include "AMDMapperProbeInternal.hpp"

namespace {
constexpr UInt32 kR44TablePages = 16;
constexpr UInt32 kR44Domain = 1;
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
    UInt64 readyTime, activeTime;
    UInt64 invDevCompleted, invPagesCompleted;
    UInt64 eventEntries, targetFaults;
    UInt32 lastEvent[4];
    UInt32 deviceID;
    M2B2CmdCtx command;
    const char *state;
    bool configured, ready, active, pinned, restored;
    bool eventOverflow, eventInvalid;

    bool restore() {
        if (!configured) { restored = true; return true; }
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
        if ((status & (M2B2_STATUS_CMDBUF_RUN | M2B2_STATUS_EVT_RUN)) ||
            (mmioRead64(base, M2B2_OFF_CONTROL) & M2B2_CTRL_IOMMU_EN))
            return false;
        mmioWrite64(base, M2B2_OFF_DEV_TABLE, originalDT);
        mmioWrite64(base, M2B2_OFF_CMD_BUF, originalCommand);
        mmioWrite64(base, M2B2_OFF_EVT_BUF, originalEvent);
        mmioWrite64(base, M2B2_OFF_CONTROL, originalControl);
        OSSynchronizeIO();
        restored = mmioRead64(base, M2B2_OFF_DEV_TABLE) == originalDT &&
            mmioRead64(base, M2B2_OFF_CMD_BUF) == originalCommand &&
            mmioRead64(base, M2B2_OFF_EVT_BUF) == originalEvent &&
            mmioRead64(base, M2B2_OFF_CONTROL) == originalControl;
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
            r44AttachAuto(nic);
            nic->release();
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
    // Lucy closes the PCI provider after start() has allocated its resources,
    // so isOpen() alone would also admit an already running physical driver.
    // A publish notification can replay an existing service when installed.
    if (nic->isOpen() || nic->getChildEntry(gIOServicePlane)) {
        setProperty("r44-state", "failed-too-late");
        return false;
    }

    R44Controller *c = (R44Controller *)IOMalloc(sizeof(R44Controller));
    if (!c) { setProperty("r44-state", "failed-controller-memory"); return false; }
    bzero(c, sizeof(*c));
    fR44Controller = c;
    c->state = "preparing";
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
        // This first normal mode targets the same verified X570 IOMMU BAR as
        // R43. The EFR check protects the MMIO access before any register write.
        c->mmioMemory = IOMemoryDescriptor::withPhysicalAddress(
            (IOPhysicalAddress)M21_MMIO_BASE, (IOByteCount)M21_MMIO_LEN,
            kIODirectionNone);
        if (c->mmioMemory)
            c->mmioMap = c->mmioMemory->map(kIOMapInhibitCache | kIOMapAnywhere);
        if (!c->mmioMap) failure = "failed-mmio-map";
        else {
            c->base = (volatile UInt8 *)c->mmioMap->getVirtualAddress();
            if (mmioRead64(c->base, M21_OFF_EXT_FEAT) != M21_EFR_EXPECTED)
                failure = "failed-iommu-identity";
        }
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

bool org_example_AMDMapperProbe::r44Invalidate() {
    // The generic mapper's lock serializes PTE writes, command submission and
    // this first-map DTE installation. Failed completion never returns an IOVA.
    R44Controller *c = fR44Controller;
    if (!c || !c->ready || c->command.failed) return false;
    OSSynchronizeIO();
    if (!c->active) {
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
    }
    const UInt64 address = m2b2InvAddress();
    if (!m2b2Submit(c->base, &c->command, "r44-invalidate-pages", 0,
            kR44Domain | ((UInt32)M2B2_CMD_INV_IOMMU_PAGES << 28),
            (UInt32)address | M2B2_CMD_PDE_MASK, (UInt32)(address >> 32))) {
        c->state = "failed-page-invalidation";
        return false;
    }
    ++c->invPagesCompleted;
    if (!c->active) {
        c->active = true;
        c->activeTime = mach_absolute_time();
        c->state = "active";
    }
    return true;
}

void org_example_AMDMapperProbe::r44PublishAuto() {
    R44Controller *c = fR44Controller;
    if (!c) return;
    // Called while the generic mapper lock is held, or before publication /
    // after quiescing. The event producer owns TAIL; only advance consumed HEAD.
    if (c->configured) {
        const UInt32 status = mmioRead32(c->base, M2B2_OFF_STATUS);
        if (status & M2B2_STATUS_EVT_OVERFLOW) c->eventOverflow = true;
        UInt64 head = mmioRead64(c->base, M2B2_OFF_EVT_HEAD);
        const UInt64 tail = mmioRead64(c->base, M2B2_OFF_EVT_TAIL);
        if (head >= M2B2_EVT_BUFFER_SIZE || tail >= M2B2_EVT_BUFFER_SIZE ||
            ((head | tail) & 15)) c->eventInvalid = true;
        else {
            const volatile UInt32 *events =
                (volatile UInt32 *)c->events->getBytesNoCopy();
            while (head != tail) {
                const UInt32 entry = (UInt32)head / 4;
                const UInt32 type = events[entry + 1] >> M2B2_EVENT_TYPE_SHIFT;
                if (!type) { c->eventInvalid = true; break; }
                for (UInt32 i = 0; i < 4; ++i) c->lastEvent[i] = events[entry + i];
                ++c->eventEntries;
                if ((c->lastEvent[0] & M2B2_EVENT_DEVID_MASK) == c->deviceID)
                    ++c->targetFaults;
                head = (head + 16) % M2B2_EVT_BUFFER_SIZE;
            }
            mmioWrite64(c->base, M2B2_OFF_EVT_HEAD, head);
        }
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
    if (c->base) number("r44-control", mmioRead64(c->base, M2B2_OFF_CONTROL));
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
