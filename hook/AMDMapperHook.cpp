//
//  AMDMapperHook.cpp
//  AMDMapperHook
//
//  Lilu plugin. Routes IOMapper::copyMapperForDevice() so that a PCI device
//  selected through amdiommu_devices receives its iommu-parent at the moment a
//  client asks for a mapper, i.e. after that client's pciDevice->open().
//
//  Why this hook and not a patch of IOPCIFamily: copyMapperForDevice is an
//  exported symbol, and it is the point where every client states its need
//  (drivers call it from start(), including Apple's own mlx5 / AppleEthernetRL /
//  Aquantia clients). See docs/lilu-hook-design.md.
//
//  The hook never decides which devices are selected. It asks the probe, and the
//  probe answers from the boot-argument list only - so the selection semantics
//  stay in one place.
//

#include <Headers/kern_api.hpp>
#include <Headers/kern_patcher.hpp>
#include <Headers/kern_util.hpp>
#include <Headers/kern_version.hpp>
#include <Headers/plugin_start.hpp>

#include <IOKit/IOLib.h>
#include <IOKit/IOMapper.h>
#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>

// Lilu's disable list: -amdmhoff keeps this plugin from loading, which is the
// only way to turn the hook off now. Everything else about the hook is decided
// by the kext being present.
static const char *bootargOff[] {
	"-amdmhoff"
};

static const char *bootargDebug[] {
	"-amdmhdbg"
};

static const char *bootargBeta[] {
	"-amdmhbeta"
};

// Must match the mangled name of IOMapper::copyMapperForDevice(IOService *)
// exactly. 19 is the length of "copyMapperForDevice"; verified against
// `nm -m /System/Library/Kernels/kernel`.
static const char *kCopyMapperSymbol {"__ZN8IOMapper19copyMapperForDeviceEP9IOService"};
// IOService::open(IOService *, IOOptionBits, void *). This is the entry every
// client uses (pciDevice->open(this)); IOPCIDevice does not override it, and it
// is a real external symbol in the kernel image, so it can be routed with
// KernelPatcher::KernelID.
//
// IOPCIDevice::handleOpen() would be the more precise target - the device is
// still closed there too - but it lives in IOPCIFamily inside the Boot KC and
// KernelID only searches the kernel image (verified: the symbol exists in the KC
// as a defined T, yet routing it with KernelID fails). Routing open() costs one
// metaCast per open, which is not a hot path, and the hook filters for PCI.
static const char *kOpenSymbol {"__ZN9IOService4openEPS_jPv"};
// amd_iommu_device_policy::kClaim: the strict pre-open handshake. Valid here
// because the device is still closed at this point.
static const char *kClaimVerb {"AMDIOMMUClaimRequesterV1"};
// The probe publishes this class name and uses iommu-role to tell the
// controller apart from the per-device mapper instances of the same class.
static const char *kProbeClass {"org_maz1_AMDMapperProbe"};
// amd_iommu_device_policy::kAttach in the probe repository (probe/
// amd_iommu_device_policy.hpp). Kept as a literal because this plugin must not
// need the probe's headers: the two kexts are loaded independently.
static const char *kAttachVerb {"AMDIOMMUAttachRequesterV1"};
static const char *kMapperProperty {"iommu-parent"};
// amd_iommu_device_policy::kOffer: published by the probe on a selected device.
static const char *kOfferProperty {"amdiommu-requester-offer"};
static const char *kRoleProperty {"iommu-role"};
static const char *kControllerRole {"controller"};

// Armed by loading this kext: there is no arming boot argument. gInstalled only
// tracks whether the route was actually installed, so the routed body can bail
// out cheaply in the window before Lilu's patcher-load callback runs, and after
// a failed route. -amdmhoff (Lilu's disable list) is the way to not load at all.
static bool gInstalled {false};
// The open-path route (option D'). Tracked separately: it is the preferred one,
// while gInstalled covers the copyMapperForDevice fallback.
static bool gOpenInstalled {false};
static bool gSymbolFailed {false};

static mach_vm_address_t gOriginal {0};
static mach_vm_address_t gOpenOriginal {0};
static IOMapper *(*gCopyMapper)(IOService *) {nullptr};
static bool (*gServiceOpen)(IOService *, IOService *, IOOptionBits, void *) {nullptr};
static const OSSymbol *gClaimSymbol {nullptr};

// Open-path counters, kept apart from the copyMapperForDevice ones so the two
// routes can be told apart from ioreg.
static UInt32 gOpenRouted {0};
static UInt32 gOpenClaimOk {0};
static UInt32 gOpenClaimFail {0};

// Controller lookup result. Retained once found; the probe does not unload.
static IOService *gController {nullptr};
static const OSSymbol *gAttachSymbol {nullptr};

static UInt32 gRouted {0};
static UInt32 gAttachOk {0};
static UInt32 gAttachFail {0};
static UInt32 gLastRequester {0};

// Diagnostics for "the hook never acted" reports. Each of these publications
// happens at most once, so the arming path stays free of registry traffic
// after the first few calls.
static UInt32 gCalls {0};
static bool gLoggedCall {false};
static bool gLoggedNonPci {false};
static bool gLoggedNoController {false};
static char gFirstClass[64];
// Which channel produced the controller on the last call: offer / service / none.
static const char *gControllerChannel {"none"};
// Set once any channel has produced a controller, so hook-probe reflects reality
// even when the service-plane lookup alone (used at start time) came up empty.
static bool gControllerSeen {false};

// Breakdown of the last controller lookup, published once with the first skip.
static UInt32 gLookupNoMatching {0};
static UInt32 gLookupServices {0};
static UInt32 gLookupRoles {0};
static UInt32 gLookupControllers {0};
// The probe's IOService node normally starts after this plugin's node, so the
// hook-probe value published at start() is a snapshot taken too early. Refresh
// the published state once, at the first point where the controller is known.
static bool gProbeStateResolved {false};

// The plugin's own IORegistry node. Custom I/O Kit init is used only so that the
// state properties can be published once the node exists: pluginStart() runs
// before any personality is matched, so there is no instance to attach them to
// at that point.
class EXPORT AMDMapperHook : public IOService {
	OSDeclareDefaultStructors(AMDMapperHook)
public:
	IOService *probe(IOService *provider, SInt32 *score) override;
	bool start(IOService *provider) override;
	void stop(IOService *provider) override;
};

OSDefineMetaClassAndStructors(AMDMapperHook, IOService)

AMDMapperHook *ADDPR(selfInstance) = nullptr;

// The controller is the probe instance that owns the domains. Every attached
// device is a mapper instance of the same class, so the class name alone is not
// enough - iommu-role is what separates them, and it is published before the
// first device is attached.
//
// Deliberately not waitForMatchingService(): when the probe is absent that call
// blocks the caller's start() for as long as no service appears, which is
// exactly the failure mode this hook exists to remove.
static IOService *controllerService() {
	if (gController)
		return gController;

	OSDictionary *matching = IOService::serviceMatching(kProbeClass);
	gLookupServices = gLookupRoles = gLookupControllers = 0;
	gLookupNoMatching = matching ? 0 : 1;
	if (!matching)
		return nullptr;

	IOService *found = nullptr;
	OSIterator *iterator = IOService::getMatchingServices(matching);
	if (iterator) {
		while (OSObject *object = iterator->getNextObject()) {
			gLookupServices++;
			// getMatchingServices only yields services; the class checks below
			// go through metaCast by name for the same reason documented above.
			if (!object->metaCast("IOService"))
				continue;
			IOService *service = static_cast<IOService *>(object);

			OSObject *role = service->copyProperty(kRoleProperty);
			const bool isController = role && role->metaCast("OSString") &&
				static_cast<OSString *>(role)->isEqualTo(kControllerRole);
			if (role) {
				gLookupRoles++;
				role->release();
			}

			if (!isController)
				continue;

			service->retain();
			found = service;
			gLookupControllers++;
			break;
		}
		iterator->release();
	}
	matching->release();

	if (found)
		gController = found;
	return found;
}

// Class checks are done through metaCast(const char *), i.e. the OSMetaClass
// registry, and NOT through OSDynamicCast/safeMetaCast.
//
// OSDynamicCast(IOPCIDevice, ...) references __ZN11IOPCIDevice9metaClassE, an
// external data symbol that only IOPCIFamily can satisfy. In this plugin that
// reference was bound to an unusable address and the first dereference of it
// page-faulted:
//
//   panic(cpu 6 caller ...): Kernel trap at ...hookCopyMapperForDevice+0x30,
//   type = 14=page fault, CR2 = 0xffffff8055400000, caller
//   AppleUSBHostController::start.
//
// The offset is exactly `movq __got(IOPCIDevice::metaClass), %rax;
// movq (%rax), %rsi`. metaCast(const char *) resolves by name inside libkern
// and references no per-class data symbol at all.
static IOPCIDevice *asPciDevice(IOService *service) {
	if (!service || !service->metaCast("IOPCIDevice"))
		return nullptr;
	return static_cast<IOPCIDevice *>(service);
}

static IOMapper *asMapper(OSObject *object) {
	if (!object || !object->metaCast("IOMapper"))
		return nullptr;
	return static_cast<IOMapper *>(object);
}

// The controller for one device, taken from the offer the probe published on
// that device.
//
// This is better than searching the service plane: the probe sets
// amdiommu-requester-offer on a selected device before that device's driver
// starts (it is the same moment it sets amdiommu-dma-policy=selected), so the
// offer is already there on the very first copyMapperForDevice() call. Searching
// by class name returned nothing during exactly that window, and it would also
// have to re-implement the selection rule.
//
// The offer is the probe's own statement of "this device is selected", and the
// probe applies the selection rule in one place: amdiommu_devices when that boot
// argument is present, the Info.plist AMDMapperProbeDevices table when it is
// absent. The hook therefore inherits the same rule and never parses either
// list itself.
static IOService *controllerForDevice(IOService *device) {
	OSObject *offer = device->copyProperty(kOfferProperty);
	if (!offer)
		return nullptr;

	IOService *controller = nullptr;
	if (offer->metaCast("IOService"))
		controller = static_cast<IOService *>(offer);
	offer->release();
	return controller;
}

static UInt32 requesterOf(IOPCIDevice *pci) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	return ((UInt32)pci->getBusNumber() << 8) |
		((UInt32)pci->getDeviceNumber() << 3) | (UInt32)pci->getFunctionNumber();
#pragma clang diagnostic pop
}

static void publishCounters() {
	IOService *self = ADDPR(selfInstance);
	if (!self)
		return;

	self->setProperty("hook-routed", (unsigned long long)__atomic_load_n(&gRouted, __ATOMIC_RELAXED), 64);
	self->setProperty("hook-attach-ok", (unsigned long long)__atomic_load_n(&gAttachOk, __ATOMIC_RELAXED), 64);
	self->setProperty("hook-attach-fail", (unsigned long long)__atomic_load_n(&gAttachFail, __ATOMIC_RELAXED), 64);
	self->setProperty("hook-last-requester", __atomic_load_n(&gLastRequester, __ATOMIC_RELAXED), 32);
	self->setProperty("hook-controller", gControllerChannel);
	self->setProperty("hook-open-routed", (unsigned long long)__atomic_load_n(&gOpenRouted, __ATOMIC_RELAXED), 64);
	self->setProperty("hook-open-claim-ok", (unsigned long long)__atomic_load_n(&gOpenClaimOk, __ATOMIC_RELAXED), 64);
	self->setProperty("hook-open-claim-fail", (unsigned long long)__atomic_load_n(&gOpenClaimFail, __ATOMIC_RELAXED), 64);
}

// One-shot diagnostic publication: which device class reached the hook first,
// and why the first non-routed call was dropped. Called at most once per
// reason, so it cannot become per-call registry traffic.
static void publishCallState(const char *skip) {
	IOService *self = ADDPR(selfInstance);
	if (!self)
		return;

	self->setProperty("hook-calls", (unsigned long long)__atomic_load_n(&gCalls, __ATOMIC_RELAXED), 64);
	if (skip)
		self->setProperty("hook-first-skip", skip);
	// Always refreshed: these describe the lookup that just ran, so the newest
	// publication shows the newest state rather than the first-call snapshot.
	self->setProperty("hook-lookup-no-matching", gLookupNoMatching, 32);
	self->setProperty("hook-lookup-services", gLookupServices, 32);
	self->setProperty("hook-lookup-roles", gLookupRoles, 32);
	self->setProperty("hook-lookup-controllers", gLookupControllers, 32);
	self->setProperty("hook-controller", gControllerChannel);
	if (gFirstClass[0])
		self->setProperty("hook-first-device-class", gFirstClass);
}

static void publishState() {
	IOService *self = ADDPR(selfInstance);
	if (!self)
		return;

	// pending: this node started, Lilu has not run the patcher-load callback yet.
	// installed: the route is in place, so the hook is armed - loading the kext
	// is the only arming control there is. failed-symbol: routing failed and the
	// hook passes everything through.
	const char *state = "pending";
	if (gSymbolFailed)
		state = "failed-symbol";
	else if (gInstalled || gOpenInstalled)
		state = "installed";

	self->setProperty("hook-state", state);
	// Which route is live. hook-open=installed means the AppleVTD-equivalent
	// path (device claimed before its client can allocate); not-installed means
	// only the copyMapperForDevice fallback exists, which has the late window.
	self->setProperty("hook-open", gOpenInstalled ? "installed" : "not-installed");
	self->setProperty("hook-probe", (gControllerSeen || controllerService()) ? "found" : "absent");
	self->setProperty("hook-controller", gControllerChannel);
	publishCounters();
}

// The routed body. Three properties matter here:
//   - the original result wins, so anything that already resolves a mapper is
//     untouched (AppleVTD included);
//   - nothing is allocated, logged or locked unless the device is a PCI device
//     and the probe is present and armed;
//   - on success the property is re-read from the device, so the hook returns
//     exactly what copyMapperForDevice would have returned had the property
//     been published earlier - a +1 reference owned by the caller.
static IOMapper *hookCopyMapperForDevice(IOService *device) {
	IOMapper *mapper = gCopyMapper(device);
	if (mapper)
		return mapper;

	// Not armed yet (route not installed): one branch, no class check, no
	// registry traffic. Loading this kext is what arms it - there is no separate
	// boot argument; -amdmhoff is the Lilu-level disable that keeps the plugin
	// from loading at all.
	if (!gInstalled)
		return nullptr;

	const UInt32 calls = __atomic_add_fetch(&gCalls, 1, __ATOMIC_RELAXED);
	if (!gLoggedCall) {
		gLoggedCall = true;
		const char *cls = (device && device->getMetaClass()) ?
			device->getMetaClass()->getClassName() : "null";
		strlcpy(gFirstClass, cls, sizeof(gFirstClass));
		IOLog("AMDMapperHook: first call, device class %s\n", gFirstClass);
		publishCallState(nullptr);
	} else if (calls <= 64 && (calls & (calls - 1)) == 0) {
		// Milestones only (2, 4, 8, ... 64): enough to prove whether calls keep
		// arriving at all, without a registry write per call.
		publishCallState(nullptr);
	}

	IOPCIDevice *pci = asPciDevice(device);
	if (!pci) {
		if (!gLoggedNonPci) {
			gLoggedNonPci = true;
			IOLog("AMDMapperHook: %s is not an IOPCIDevice, skipping\n", gFirstClass);
			publishCallState("non-pci");
		}
		return nullptr;
	}

	// Only a call that actually resolves a controller updates the channel; a
	// call from a non-selected device (no offer) must not turn it into "none".
	IOService *controller = controllerForDevice(pci);
	if (controller) {
		gControllerChannel = "offer";
	} else {
		controller = controllerService();
		if (controller)
			gControllerChannel = "service";
	}
	if (!controller || !gAttachSymbol) {
		if (!gLoggedNoController) {
			gLoggedNoController = true;
			IOLog("AMDMapperHook: no probe controller for %s (symbol %s)\n",
				gFirstClass, gAttachSymbol ? "ok" : "missing");
			publishCallState("no-controller");
		}
		return nullptr;
	}
	gControllerSeen = true;

	// The controller instance of the probe starts after this plugin's node and
	// after Lilu's patcher-load callback, so hook-probe published there can lag.
	// Re-publish once, here, where the controller is known to exist, so the
	// value cannot stay "absent" for a device that did reach the probe.
	if (!gProbeStateResolved) {
		gProbeStateResolved = true;
		publishState();
	}

	__atomic_add_fetch(&gRouted, 1, __ATOMIC_RELAXED);
	__atomic_store_n(&gLastRequester, requesterOf(pci), __ATOMIC_RELAXED);

	const IOReturn result = controller->callPlatformFunction(gAttachSymbol, false, pci,
		nullptr, nullptr, nullptr);
	if (result != kIOReturnSuccess) {
		__atomic_add_fetch(&gAttachFail, 1, __ATOMIC_RELAXED);
		publishCounters();
		return nullptr;
	}

	OSObject *object = device->copyProperty(kMapperProperty);
	IOMapper *attached = asMapper(object);
	if (!attached) {
		// Never report a mapper we cannot hand over: the device would run
		// translated while its client believes it has none.
		if (object)
			object->release();
		__atomic_add_fetch(&gAttachFail, 1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&gAttachOk, 1, __ATOMIC_RELAXED);
	}

	publishCounters();
	return attached;
}

// Option D': claim the device at the entry of IOService::open().
//
// This is the AppleVTD-equivalent position: the original open() has not run yet,
// so the device is still closed and no client has received any resource. The
// domain therefore exists before the client can allocate a single DMA buffer,
// which is exactly what AppleVTD achieves from inside getResources(). Because the
// device is closed, the probe's strict claim verb applies and no guard has to be
// relaxed.
//
// Every exit returns the original function's result. A missing probe, a refused
// claim or a failed attach can only leave the device on its physical path; it
// must never be able to break open() for any device on the machine.
static bool hookServiceOpen(IOService *opened, IOService *client,
                            IOOptionBits options, void *arg) {
	// open() is system-wide: filter to PCI devices first. Selecting on the class
	// name keeps this independent of per-class data symbols (see asPciDevice).
	if (gOpenInstalled && gClaimSymbol && opened && opened->metaCast("IOPCIDevice")) {
		IOPCIDevice *device = static_cast<IOPCIDevice *>(opened);
		if (!device->getProperty(kMapperProperty)) {
			IOService *controller = controllerForDevice(device);
			if (controller) {
				const UInt32 count = __atomic_add_fetch(&gOpenRouted, 1, __ATOMIC_RELAXED);
				const IOReturn result = controller->callPlatformFunction(gClaimSymbol,
					false, device, nullptr, nullptr, nullptr);
				if (result == kIOReturnSuccess && device->getProperty(kMapperProperty))
					__atomic_add_fetch(&gOpenClaimOk, 1, __ATOMIC_RELAXED);
				else
					__atomic_add_fetch(&gOpenClaimFail, 1, __ATOMIC_RELAXED);
				// Opens are rare (once per driver attach, plus up/down), so
				// publish while the counts are small and stay quiet afterwards.
				if (count <= 8)
					publishCounters();
			}
		}
	}
	return gServiceOpen(opened, client, options, arg);
}

static void hookBoot() {
	// No arming boot argument: this function only runs when Lilu accepted the
	// plugin (so -amdmhoff, -amdmhdbg and the kernel range did not exclude it),
	// and the route below is the actual arming step.
	SYSLOG("amdmh", "bootstrap %s, arming on load", kextVersion);

	lilu.onPatcherLoadForce([](void *, KernelPatcher &patcher) {
		gAttachSymbol = OSSymbol::withCString(kAttachVerb);
		gClaimSymbol = OSSymbol::withCString(kClaimVerb);

		// Preferred route: the open path. Installed first and reported
		// separately, because a failure here does not have to take the fallback
		// down with it.
		KernelPatcher::RouteRequest openRequest(kOpenSymbol, hookServiceOpen, gOpenOriginal);
		if (patcher.routeMultiple(KernelPatcher::KernelID, &openRequest, 1) && gOpenOriginal) {
			gServiceOpen = reinterpret_cast<bool (*)(IOService *, IOService *, IOOptionBits, void *)>(gOpenOriginal);
			gOpenInstalled = true;
			SYSLOG("amdmh", "routed %s, original at 0x%llx", kOpenSymbol, gOpenOriginal);
		} else {
			SYSLOG("amdmh", "failed to route %s", kOpenSymbol);
		}

		// Fallback for devices that were opened before this callback ran, and for
		// builds where the handleOpen symbol cannot be solved. It keeps the late
		// window, so hook-open=installed is what callers should check.
		KernelPatcher::RouteRequest request(kCopyMapperSymbol, hookCopyMapperForDevice, gOriginal);
		if (!patcher.routeMultiple(KernelPatcher::KernelID, &request, 1) || !gOriginal) {
			SYSLOG("amdmh", "failed to route %s", kCopyMapperSymbol);
			if (!gOpenInstalled) {
				gSymbolFailed = true;
				publishState();
				return;
			}
			publishState();
			return;
		}

		gCopyMapper = reinterpret_cast<IOMapper *(*)(IOService *)>(gOriginal);
		gInstalled = true;
		SYSLOG("amdmh", "routed %s, original at 0x%llx", kCopyMapperSymbol, gOriginal);

		// The IOResources personality has already started by the time Lilu
		// reaches this callback, so the state published at start() predates the
		// installation and would still read "disabled". Publish again now that
		// the route exists; hook-probe is refreshed once more from the first
		// copyMapperForDevice() call, when the probe is certainly up.
		publishState();
	});
}

IOService *AMDMapperHook::probe(IOService *provider, SInt32 *score) {
	ADDPR(selfInstance) = this;
	setProperty("VersionInfo", kextVersion);
	return IOService::probe(provider, score);
}

bool AMDMapperHook::start(IOService *provider) {
	if (!IOService::start(provider)) {
		SYSLOG("amdmh", "failed to start the parent");
		return false;
	}

	ADDPR(selfInstance) = this;
	publishState();
	return true;
}

void AMDMapperHook::stop(IOService *provider) {
	ADDPR(selfInstance) = nullptr;
	IOService::stop(provider);
}

PluginConfiguration ADDPR(config) {
	xStringify(PRODUCT_NAME),
	parseModuleVersion(xStringify(MODULE_VERSION)),
	LiluAPI::AllowNormal,
	bootargOff,
	arrsize(bootargOff),
	bootargDebug,
	arrsize(bootargDebug),
	bootargBeta,
	arrsize(bootargBeta),
	KernelVersion::BigSur,
	KernelVersion::Tahoe,
	hookBoot
};
