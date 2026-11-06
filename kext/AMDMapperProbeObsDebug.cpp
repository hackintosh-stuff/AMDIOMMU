// AMDMapperProbeObs.cpp -- driver observation log (wire v2) reader
//
// Part of the AMDMapperProbe kext. Split out of the original
// single-file AMDMapperProbe.cpp by tools/split-probe.py; the
// function bodies are unchanged and in their original order.

#include "AMDMapperProbe.hpp"
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOWorkLoop.h>

// IOPCIDevice.h itself triggers two -Werror-level warnings from within the SDK:
//   1. IOPCIDevice is marked __kpi_deprecated("Use PCIDriverKit")
//   2. Its internal setProperty overload is not marked override (-Winconsistent-missing-override)
//
// Both are **problems in Apple's own headers**, not defects in this project's code:
//   - PCIDriverKit is a userspace DriverKit framework and cannot implement an
//     IOMapper subclass; this project must be an in-kernel IOKit kext and can
//     only use IOPCIDevice.
//   - The override warning comes from SDK declarations; we cannot and should
//     not modify SDK headers.
//
// Therefore suppress only these two while including that header, without
// disabling them globally -- other genuine deprecation / override issues
// will still be reported as errors as usual.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Winconsistent-missing-override"
#include <IOKit/pci/IOPCIDevice.h>
#pragma clang diagnostic pop

#include <pexpert/pexpert.h>
#include <mach/kmod.h>
#include <mach/mach_time.h>
#include <kern/clock.h>
#include <libkern/OSByteOrder.h>

// The single implementation of page table encoding/decoding. Production code
// and the host regression tests **include the same file**, so the tests run
// exactly these branches rather than a separately written Python restatement.
// See tests/pte-core-test.cpp and docs/m2-2b-2-round5-result.md.
#include "amd_iommu_pte_core.hpp"

// The definition of OSPtr<T> depends on IOKIT_ENABLE_SHARED_PTR (SDK
// libkern/c++/OSPtr.h): defined = OSSharedPtr<T>; undefined = T*.
// The SDK default is undefined.
#if defined(IOKIT_ENABLE_SHARED_PTR)
    #define M1A_HAS_SHARED_PTR 1
#else
    #define M1A_HAS_SHARED_PTR 0
#endif

#include "AMDMapperProbeInternal.hpp"

// ===== AMDMapperProbeObs.cpp (original lines 3497..3611) =====
// ===========================================================================
// Round 10: re-implementing m2b2ScanTxDone()
// ===========================================================================
//
// [Why this function was rewritten rather than "the original text recovered"]
//
//   When round 10 spliced the v2 reader into AMDMapperProbe.cpp, the end of
//   the spliced range was taken just before `m2b2PublishDmaDefaults()`, and
//   m2b2ScanTxDone() happened to sit between those two markers -- its
//   **definition** was replaced wholesale, leaving only the declaration in the
//   header and the call in step 16d. It surfaced at link time: kmutil reported
//
//     Failed to bind '__ZN26org_example_AMDMapperProbe14m2b2ScanTxDoneEv'
//     ... could not find a kext which exports this symbol
//
//   This is exactly the failure shape that kept recurring in round 9: it
//   compiles, installation "succeeds", set reconstruction fails, and the only
//   symptom is that the evidence contains nothing. This round fixes it as a
//   defect and writes "all driver symbols must resolve after linking" into the
//   deploy script.
//
// [What it does]
//
//   Reads the TX ring once and returns `doneWithAddr` -- the number of
//   descriptors that are both handed back (DescOwn cleared) and carry a
//   non-zero address.
//
//   This number is **not** completion evidence. DescOwn is not cleared by the
//   hardware on this chip, so this delta has been constantly 0 for four rounds
//   (done == zeroaddr). It is kept for exactly one purpose: to make "DescOwn
//   is not a completion signal" visible on every experiment instead of turning
//   into hearsay. The real completion evidence is the driver's own tx-done
//   records and the hardware close pointer.
//
// [Why two gates come first]
//
//   plausibleRingBase()          -- does the register's address look like a ring
//   readVerdictDeviceReported()  -- can this physical address be read safely
//
//   If either fails the function returns -1 and never "just tries to read".
//   Round 7's lesson: mapping in a device-reported address and reading it once
//   cost two panics.
// The declared batch size for this round.
//
// WHERE IT COMES FROM, AND WHY NOT FROM THE RECORDS
// -------------------------------------------------
// `controlledBatchComplete` answers "did every request THIS ROUND declared
// complete?". The declaration has to be made before the evidence is read,
// otherwise the check degenerates into "however many records I found is
// however many there were" -- which is circular and would pass on any input.
//
// So the number is written into the probe's IORegistry node by the deployment
// step (m2-b2-declared-batch), and read here. A missing property yields 0,
// which obsJoinInto() reports as "batch-not-declared" with
// controlledBatchComplete = false. Zero NEVER means "zero requests, all
// complete".
// The declaration is written onto the PROBE'S OWN node (this object), so it
// is read with copyProperty() on `this` -- no path lookup, and no dependence
// on where in the registry the probe happens to sit.
//
// ROUND 11: the SAME boot-arg also carries the run token, because a batch
// declaration without a token cannot tell two runs apart. See the
// counterexample in ObsBatchSpec: token A's req1 plus token B's req2 used to
// fold into one "complete" batch of 2.
//
//     amdiommu=pgt.batch4              -> 4 requests, token not declared
//     amdiommu=pgt.batch4.t0xa3dbba85  -> 4 requests, token 0xa3dbba85
//
// The token is parsed by the same bounded hex/dec scanner used for the count.
static inline bool m2b2ParseHexOrDec(const char **qp, UInt32 *out);

UInt32 org_example_AMDMapperProbe::m2b2ReadDeclaredBatch() {
    // WHERE THE DECLARATION ACTUALLY COMES FROM, AND TWO DEAD ENDS
    // ------------------------------------------------------------
    // Attempt 1: a personality key on our own IORegistry node. That does NOT
    // work -- IOKit publishes only a small fixed subset of the personality
    // dictionary onto the node (IOClass, IOProviderClass, IOMatchCategory,
    // ...), so an arbitrary key added to Info.plist never appears there. The
    // read silently returned 0 and the run reported "batch-not-declared".
    //
    // Attempt 2: `PE_parse_boot_argn("m2b2batch", ...)`. This project already
    // found (round 6, and again at parseM22b2Delay) that only `amdiommu=...`
    // is reliably delivered to this kext; separate trailing arguments are not
    // visible. So a second boot-arg is not a dependable channel either.
    //
    // Attempt 3 (this one): the count travels INSIDE the amdiommu= value,
    // which is the one argument that demonstrably arrives. The form is
    //
    //     amdiommu=pgt            -> no batch declared
    //     amdiommu=pgt.batch4     -> 4 requests declared
    //
    // Everything after a '.' is ours to define; the existing code only looks
    // for the exact tokens "pgt", "pgt4k" and "pgtsleep", so a suffix does not
    // disturb any of them (see parsePgtBootArg()).
    char val[128];
    val[0] = 0;
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        setProperty("m2-b2-declared-raw", "boot-arg-absent");
        return 0;
    }
    // Publish what the kernel actually delivered, so a mismatch between what
    // config.plist says and what this kext sees is visible instead of inferred.
    {
        char dbg[160];
        snprintf(dbg, sizeof(dbg), "amdiommu=%s", val);
        setProperty("m2-b2-declared-raw", dbg);
    }

    const char *dot = strchr(val, '.');
    if (!dot) return 0;
    const char *q = dot + 1;
    if (strncmp(q, "batch", 5) != 0) return 0;
    q += 5;

    UInt32 v = 0;
    if (!m2b2ParseHexOrDec(&q, &v)) return 0;
    return v;
}

// Bounded hex-or-decimal scanner shared by the batch count and the run token.
//
// Why one implementation: round 10 had this logic inline and a second copy
// would be a place for the two to drift. The scanner never reads past a
// non-digit and never overflows: it stops accumulating at 32 bits and leaves
// the rest for the caller's terminator check.
static inline bool m2b2ParseHexOrDec(const char **qp, UInt32 *out) {
    const char *q = *qp;
    UInt32 v = 0;
    bool any = false;
    if (q[0] == '0' && (q[1] == 'x' || q[1] == 'X')) {
        q += 2;
        while (*q) {
            UInt32 d;
            if (*q >= '0' && *q <= '9')      d = (UInt32)(*q - '0');
            else if (*q >= 'a' && *q <= 'f') d = (UInt32)(*q - 'a' + 10);
            else if (*q >= 'A' && *q <= 'F') d = (UInt32)(*q - 'A' + 10);
            else break;
            v = (v << 4) | d;
            any = true;
            q++;
        }
    } else {
        while (*q >= '0' && *q <= '9') {
            v = v * 10u + (UInt32)(*q - '0');
            any = true;
            q++;
        }
    }
    *qp = q;
    if (out) *out = v;
    return any;
}

// Read the run token out of the same amdiommu= value.
//
// Returns 0 when the value carries no token. Zero is never a valid token: the
// load generator starts at 1, and the driver refuses to publish a parsed
// record whose token is 0 (see obsParseBiz()). So "not declared" and
// "declared as 0" cannot be confused.
UInt32 org_example_AMDMapperProbe::m2b2ReadDeclaredToken() {
    char val[128];
    val[0] = 0;
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) return 0;
    const char *dot = strchr(val, '.');
    if (!dot) return 0;
    // Scan every '.key<value>' segment after the first, so the order of
    // batch and token in the boot-arg does not matter.
    const char *q = dot;
    while ((q = strchr(q, '.')) != nullptr) {
        q++;
        if (strncmp(q, "t0x", 3) == 0 || strncmp(q, "token", 5) == 0) {
            const char *r = q;
            if (strncmp(r, "token", 5) == 0) r += 5;
            else                              r += 1;   // skip the 't', keep 0x
            UInt32 v = 0;
            if (m2b2ParseHexOrDec(&r, &v) && v != 0) {
                char dbg[160];
                snprintf(dbg, sizeof(dbg), "declared token 0x%08x", v);
                setProperty("m2-b2-declared-token-raw", dbg);
                return v;
            }
        }
    }
    setProperty("m2-b2-declared-token-raw", "token-absent");
    return 0;
}

// ===========================================================================
// Round 11: binding this driver instance
// ===========================================================================
//
// [The problem to solve]
//
//   The snapshot header carries an epoch (the "seconds since boot" the driver
//   took in obsInit()). Round 10's reader wrote want.epoch = 0, and
//   obsIdentityMatches() interprets 0 as "don't check". So this entire
//   protection **never took effect**:
//
//     the same card, the same MAC, the same BSD unit -- a new instance
//     produced after a driver reload or controller reset would have its
//     snapshot accepted as evidence "of this instance".
//
// [How it is bound]
//
//   Prefer the instance identity the driver publishes itself. The driver
//   publishes `rtl812x-obs-epoch` on its node (same source as the snapshot
//   header). The probe reads it **before the window opens**, remembers it, and
//   afterwards requires the snapshot header's epoch to equal it.
//
//   When the driver publishes nothing, fall back: read one snapshot and use
//   its header epoch as the binding value, but **the source publication must
//   also be recorded**, and that publication must be the one from before the
//   window. The binding then still happens before the window -- it is not
//   copied out of the very snapshot being judged.
//
//   If neither path works, epochBound stays 0 and m2b2ReadDriverObs() refuses
//   to pass. This is not "one fewer check"; it is "this round has no standing
//   to conclude anything".
//
// [Why it is not bound inside m2b2ReadDriverObs()]
//   That step runs **after** the window. Taking the epoch there would let the
//   object under test define the test's own standard. The binding point must
//   precede the window -- that is why this is a separate function.
void org_example_AMDMapperProbe::m2b2BindDriverInstance() {
    fM22b2Dma.epochBound = 0;
    setProperty("m2-b2-epoch-bind", "not-attempted");

    IOService *svc = findNicServiceOnly();
    if (!svc) {
        setProperty("m2-b2-epoch-bind", "SKIP-no-nic");
        return;
    }
    const char *src = "unknown";
    IOService *obsSvc = m2b2FindObsService(svc, &src);
    if (!obsSvc) {
        svc->release();
        setProperty("m2-b2-epoch-bind", "SKIP-no-obs-node");
        return;
    }

    // Route 1: the driver publishes the instance epoch as its own property.
    {
        OSNumber *n = OSDynamicCast(OSNumber,
                                    obsSvc->copyProperty("rtl812x-obs-epoch"));
        if (n) {
            const UInt32 v = (UInt32)n->unsigned32BitValue();
            n->release();
            if (v != 0) {
                fM22b2Dma.epochBound = v;
                setProperty("m2-b2-epoch-bind", "driver-property");
                setHexProperty(this, "m2-b2-epoch-bound", (UInt64)v);
                if (obsSvc != svc) obsSvc->release();
                svc->release();
                return;
            }
        }
    }

    // Route 2: no published epoch property. Take it from the snapshot that
    // exists NOW -- which is before the window opens -- and record which
    // publication it came from, so the binding's provenance is auditable.
    {
        OSData *d = m2b2CopyObsSnapshot(obsSvc, nullptr);
        if (d) {
            const UInt32 bytes = (UInt32)d->getLength();
            const UInt8 *b = (const UInt8 *)d->getBytesNoCopy();
            const amdobs::ObsHeader h = amdobs::obsHeaderOk(b, bytes);
            if (h.ok && h.epoch != 0) {
                fM22b2Dma.epochBound = h.epoch;
                setProperty("m2-b2-epoch-bind", "pre-window-snapshot");
                setHexProperty(this, "m2-b2-epoch-bound", (UInt64)h.epoch);
                setHexProperty(this, "m2-b2-epoch-bind-pub-id",
                               (UInt64)h.pubId);
                setHexProperty(this, "m2-b2-epoch-bind-t-published",
                               h.tPublished);
            } else {
                setProperty("m2-b2-epoch-bind", "SKIP-unusable-snapshot");
                if (h.ok) setProperty("m2-b2-epoch-bind-why", "epoch-zero");
                else      setProperty("m2-b2-epoch-bind-why", h.why);
            }
            d->release();
        } else {
            setProperty("m2-b2-epoch-bind", "SKIP-no-snapshot");
        }
    }

    if (obsSvc != svc) obsSvc->release();
    svc->release();
}

// ===== AMDMapperProbeObs.cpp (original lines 3613..3641) =====
int org_example_AMDMapperProbe::m2b2ScanTxDone() {
    if (!fM22b2Dma.ran || !fM22b2Dma.haveTxRing) return -1;

    const UInt64 bytes = 1024ULL * amdobs::TX_DESC_STRIDE;
    const char *why = nullptr;
    if (!amdobs::plausibleRingBase(fM22b2Dma.txRingBase, bytes,
                                   M2B2_IDENTITY_LIMIT, &why) ||
        amdobs::readVerdictDeviceReported(fM22b2Dma.txRingBase, bytes,
                            fM22b2Policy) != amdobs::RD_OK) {
        return -1;
    }

    IOMemoryDescriptor *md =
        IOMemoryDescriptor::withPhysicalAddress(fM22b2Dma.txRingBase, bytes,
                                                kIODirectionIn);
    if (!md) return -1;

    int done = -1;
    IOMemoryMap *m = md->map(kIOMapInhibitCache | kIOMapReadOnly);
    if (m) {
        const UInt8 *rb = (const UInt8 *)(uintptr_t)m->getVirtualAddress();
        // doneWithAddr, NOT done: an unused slot has DescOwn clear and
        // would otherwise be counted as a completion.
        done = (int)amdobs::scanTxRing(rb, 1024).doneWithAddr;
        m->release();
    }
    md->release();
    return done;
}

// ===== AMDMapperProbeObs.cpp (original lines 3643..3886) =====
// ===========================================================================
// Round 10: collecting the target NIC's identity
// ===========================================================================
//
// [Why this step must exist separately]
//
//   Round 9's load was bound to en0's 192.168.50.204, while the target device
//   is 0x25:00.0 -> RTL8125 -> en2 (MAC 1c:86:0b:3b:0b:bd). en0 is a different
//   NIC (00:e0:4c:68:ab:03). So that round's archived "controlled TCP chain"
//   never passed through the observed device at all -- it proved another
//   NIC's DMA.
//
//   The root cause was not a mistyped address but **failing to bind "the
//   interface" and "the PCI function" into one thing**. The default route, a
//   source-address bind, even seeing one inet in ifconfig -- none of these
//   constitute evidence that "packets leave through this BDF".
//
//   So here four facts are collected in one pass and published:
//       DeviceId/BDF  <- this entry in the device table (resolved via kNicPaths)
//       vendor/device <- that IOPCIDevice's config space
//       MAC           <- that IOPCIDevice's IOMACAddress, or the driver
//                        instance's
//       BSD unit/name <- IOInterfaceUnit / BSD Name, and it must be a child
//                        node
//
//   The analyser compares this set item by item against the driver's snapshot
//   header. Any mismatch means the snapshot does not belong to this device and
//   the conclusion is downgraded -- never "it looks right, so accept it".
//
// [Why en2 is not hard-coded]
//   Interface numbers change with driver load order; hard-coding turns one
//   success into something irreproducible. It is fetched fresh every time and
//   the fetched values are published for the analyser to verify.
//
// [On IOPCIDevice's deprecation warning]
//   The SDK marks IOPCIDevice __kpi_deprecated("Use PCIDriverKit"). That advice
//   does not apply to this project -- PCIDriverKit is a userspace DriverKit
//   framework and cannot implement an IOMapper subclass; this project must be
//   an in-kernel kext. Only the **read-only** configRead16 and property reads
//   are used here. Therefore the warning is disabled only **inside this
//   function**, not globally (consistent with runM20ConfigProbe()).
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
void org_example_AMDMapperProbe::m2b2CaptureNicIdentity() {
    fM22b2Dma.nicIdentityKnown = false;
    fM22b2Dma.devid = 0;
    fM22b2Dma.vendorId = 0;
    fM22b2Dma.deviceId = 0;
    fM22b2Dma.nicUnit = 0;
    fM22b2Dma.nicMac = 0;
    fM22b2Dma.nicBsdName = "none";

    IOService *svc = findNicServiceOnly();
    if (!svc) {
        setProperty("m2-b2-nic-identity", "SKIP-no-nic");
        return;
    }

    bool haveBdf = false, haveVd = false, haveMac = false, haveUnit = false;

    // ---- BDF: taken from IOPCIDevice's own properties ----
    //
    // [Why not derived backwards via configRead]
    //   configRead can only read vendor/device; it cannot read "which
    //   bus/dev/fn number this function has". The IOPCIDevice "reg" property
    //   in the IORegistry is the (space, addr, len) triple, and addr's high
    //   bits are exactly bus/dev/fn. The property is more direct than the
    //   registers and harder to get wrong.
    IOPCIDevice *pci = OSDynamicCast(IOPCIDevice, svc);
    if (pci) {
        OSData *reg = OSDynamicCast(OSData, pci->copyProperty("reg"));
        if (reg && reg->getLength() >= 4) {
            const UInt8 *p = (const UInt8 *)reg->getBytesNoCopy();
            // [Why read only the first 4 bytes, rather than "find the word
            // that looks like a BDF"]
            //
            //   This board's `reg` property is 80 bytes:
            //
            //     00002500 00000000 00000000 00000000 00000000
            //     10002501 00000000 ...
            //     18002502 00000000 ...
            //
            //   This is OpenFirmware's
            //   `reg = <addr-hi addr-lo size-hi size-lo>` form: **the first
            //   32-bit big-endian word is (bus<<8)|(dev<<3)|fn**, i.e.
            //   0x2500 = 25:00.0; each subsequent 20-byte group is a BAR.
            //
            //   My first version took the 3rd word (p[8..11]) as the BDF, read
            //   0, while the driver snapshot correctly said 0x2500 -- identity
            //   checking then reported bdf-mismatch and the whole round
            //   downgraded to INDETERMINATE. **The parsing was wrong, not the
            //   device.**
            //
            //   Here the big-endian first word is taken directly, with a
            //   self-check against PCI's encoding constraints: bus is free,
            //   dev must be < 32, fn must be < 8.
            const UInt32 first = ((UInt32)p[0] << 24) | ((UInt32)p[1] << 16) |
                                 ((UInt32)p[2] << 8) | (UInt32)p[3];
            const UInt32 bus = (first >> 8) & 0xFFu;
            const UInt32 dev = (first >> 3) & 0x1Fu;
            const UInt32 fn  = first & 0x7u;
            const UInt32 bdf = (bus << 8) | (dev << 3) | fn;
            if (bdf == first) {          // the encoding must round-trip
                fM22b2Dma.devid = bdf;
                haveBdf = true;
            }
        }
        if (reg) reg->release();

        // vendor/device: prefer config space; fall back to properties.
        {
            const UInt16 v = pci->configRead16(0x00);
            const UInt16 d = pci->configRead16(0x02);
            if (v != 0xFFFFu && d != 0xFFFFu) {
                fM22b2Dma.vendorId = v;
                fM22b2Dma.deviceId = d;
                haveVd = true;
            }
        }
        if (!haveVd) {
            OSData *vid = OSDynamicCast(OSData, pci->copyProperty("vendor-id"));
            OSData *did = OSDynamicCast(OSData, pci->copyProperty("device-id"));
            if (vid && vid->getLength() >= 2 && did && did->getLength() >= 2) {
                const UInt8 *pv = (const UInt8 *)vid->getBytesNoCopy();
                const UInt8 *pd = (const UInt8 *)did->getBytesNoCopy();
                fM22b2Dma.vendorId = (UInt32)pv[0] | ((UInt32)pv[1] << 8);
                fM22b2Dma.deviceId = (UInt32)pd[0] | ((UInt32)pd[1] << 8);
                haveVd = true;
            }
            if (vid) vid->release();
            if (did) did->release();
        }

        // MAC: usually not on the IOPCIDevice; it is on the driver instance.
        // Looked for again in the child nodes below.
        OSData *mac = OSDynamicCast(OSData, pci->copyProperty("IOMACAddress"));
        if (mac && mac->getLength() >= 6) {
            const UInt8 *p = (const UInt8 *)mac->getBytesNoCopy();
            UInt64 m = 0;
            for (int i = 0; i < 6; i++) m = (m << 8) | (UInt64)p[i];
            fM22b2Dma.nicMac = m;
            haveMac = true;
        }
        if (mac) mac->release();
    }

    // ---- Driver instance: MAC + BSD unit ----
    //
    // Walk down from the IOPCIDevice to the driver's child node (RTL8125). It
    // carries IOMACAddress and IOInterfaceUnit, and below it hangs the
    // IOEthernetInterface (enN).
    {
        OSIterator *it = svc->getChildIterator(gIOServicePlane);
        if (it) {
            OSObject *o = nullptr;
            while ((o = it->getNextObject()) != nullptr) {
                IOService *child = OSDynamicCast(IOService, o);
                if (!child) continue;

                if (!haveMac) {
                    OSData *mac = OSDynamicCast(
                        OSData, child->copyProperty("IOMACAddress"));
                    if (mac && mac->getLength() >= 6) {
                        const UInt8 *p = (const UInt8 *)mac->getBytesNoCopy();
                        UInt64 m = 0;
                        for (int i = 0; i < 6; i++) m = (m << 8) | (UInt64)p[i];
                        fM22b2Dma.nicMac = m;
                        haveMac = true;
                    }
                    if (mac) mac->release();
                }

                // IOInterfaceUnit may hang on the driver node itself or on its
                // IOEthernetInterface child. Try both.
                if (!haveUnit) {
                    OSNumber *u = OSDynamicCast(
                        OSNumber, child->copyProperty("IOInterfaceUnit"));
                    if (u) {
                        fM22b2Dma.nicUnit = (UInt32)u->unsigned32BitValue();
                        haveUnit = true;
                        u->release();
                    }
                }

                // Then look further down for IOEthernetInterface (enN lives
                // at this level).
                OSIterator *it2 = child->getChildIterator(gIOServicePlane);
                if (it2) {
                    OSObject *o2 = nullptr;
                    while ((o2 = it2->getNextObject()) != nullptr) {
                        IOService *iface = OSDynamicCast(IOService, o2);
                        if (!iface) continue;
                        if (!haveUnit) {
                            OSNumber *u = OSDynamicCast(
                                OSNumber,
                                iface->copyProperty("IOInterfaceUnit"));
                            if (u) {
                                fM22b2Dma.nicUnit =
                                    (UInt32)u->unsigned32BitValue();
                                haveUnit = true;
                                u->release();
                            }
                        }
                        if (!haveMac) {
                            OSData *mac = OSDynamicCast(
                                OSData,
                                iface->copyProperty("IOMACAddress"));
                            if (mac && mac->getLength() >= 6) {
                                const UInt8 *p =
                                    (const UInt8 *)mac->getBytesNoCopy();
                                UInt64 m = 0;
                                for (int i = 0; i < 6; i++)
                                    m = (m << 8) | (UInt64)p[i];
                                fM22b2Dma.nicMac = m;
                                haveMac = true;
                            }
                            if (mac) mac->release();
                        }
                        // BSD Name is the enN; publish it directly for
                        // human verification.
                        OSString *bsd = OSDynamicCast(
                            OSString, iface->copyProperty("BSD Name"));
                        if (bsd) {
                            char buf[32];
                            const char *c = bsd->getCStringNoCopy();
                            if (c) {
                                UInt32 n = (UInt32)strlen(c);
                                if (n < sizeof(buf)) {
                                    memcpy(buf, c, n);
                                    buf[n] = 0;
                                    setProperty("m2-b2-nic-bsd", buf);
                                    fM22b2Dma.nicBsdName = "enN";
                                }
                            }
                            bsd->release();
                        }
                    }
                    it2->release();
                }
                break;   // the first driver child node suffices
            }
            it->release();
        }
    }

    svc->release();

    fM22b2Dma.nicIdentityKnown =
        (haveBdf && haveVd && haveMac && haveUnit);
    setProperty("m2-b2-nic-identity",
                fM22b2Dma.nicIdentityKnown ? "known" : "partial");
    setProperty("m2-b2-nic-has-bdf", haveBdf ? "yes" : "no");
    setProperty("m2-b2-nic-has-vd", haveVd ? "yes" : "no");
    setProperty("m2-b2-nic-has-mac", haveMac ? "yes" : "no");
    setProperty("m2-b2-nic-has-unit", haveUnit ? "yes" : "no");
    setHexProperty(this, "m2-b2-nic-bdf", (UInt64)fM22b2Dma.devid);
    setHexProperty(this, "m2-b2-nic-vendor", (UInt64)fM22b2Dma.vendorId);
    setHexProperty(this, "m2-b2-nic-device", (UInt64)fM22b2Dma.deviceId);
    setHexProperty(this, "m2-b2-nic-unit", (UInt64)fM22b2Dma.nicUnit);
    setHexProperty(this, "m2-b2-nic-mac", fM22b2Dma.nicMac);
}

// ===== AMDMapperProbeObs.cpp (original lines 4031..4474) =====
void org_example_AMDMapperProbe::m2b2ReadDriverObs() {
    fM22b2Dma.obsPresent = false;
    fM22b2Dma.obsWhy = "not-read";
    fM22b2Dma.obsIdentityWhy = "not-checked";
    fM22b2Dma.obsPubId = 0;
    fM22b2Dma.obsEpoch = 0;
    fM22b2Dma.obsHead = fM22b2Dma.obsPublished = 0;
    fM22b2Dma.obsFirst = fM22b2Dma.obsWrapped = fM22b2Dma.obsDropped = 0;
    fM22b2Dma.obsValidCount = fM22b2Dma.obsLostCount = 0;
    fM22b2Dma.obsHdrFlags = 0;
    fM22b2Dma.obsBusDevFn = fM22b2Dma.obsVendorId = 0;
    fM22b2Dma.obsDeviceId = fM22b2Dma.obsIfUnit = 0;
    fM22b2Dma.obsMac = 0;
    fM22b2Dma.obsTStart = fM22b2Dma.obsTPublished = 0;
    fM22b2Dma.obsFetchTries = 0;
    fM22b2Dma.obsFreshEnough = false;
    fM22b2Dma.obsOps = fM22b2Dma.obsSubmits = fM22b2Dma.obsDones = 0;
    fM22b2Dma.obsDoorbells = 0;
    fM22b2Dma.obsRxDone = fM22b2Dma.obsRxAddrZero = 0;
    fM22b2Dma.obsStale = fM22b2Dma.obsUnmatchedDone = 0;
    fM22b2Dma.obsUncompleted = fM22b2Dma.obsOverflow = 0;
    fM22b2Dma.obsAllCompleted = false;
    fM22b2Dma.obsWinSubmits = fM22b2Dma.obsWinDones = 0;
    fM22b2Dma.obsWinPaired = fM22b2Dma.obsWinOrphanDone = 0;
    fM22b2Dma.obsWinPreWindowInFlight = fM22b2Dma.obsWinUncompleted = 0;
    fM22b2Dma.obsHasCompletePair = false;
    fM22b2Dma.obsRecordsCoverWindow = false;
    fM22b2Dma.obsControlledBatchComplete = false;
    fM22b2Dma.obsCoverState = amdobs::OBS_COVER_NONE;
    fM22b2Dma.obsCoverName = "none";
    fM22b2Dma.obsBizOps = fM22b2Dma.obsBizCapped = 0;
    // DO NOT reset obsExpectedBatch here: it is the DECLARATION of how
    // many requests this round sent, set once in start() from the
    // boot-arg and only read afterwards. Clearing it in this per-read
    // reset silently turned "declared 4" into "not declared", which
    // made controlledBatchComplete unreachable: a run reported
    // batch-complete = 4 AND "records-without-a-business-id" at the
    // same time.
    fM22b2Dma.obsExpectedBatch = fM22b2Dma.expectedBatch;
    fM22b2Dma.obsBatchComplete = fM22b2Dma.obsBatchPartial = 0;
    fM22b2Dma.obsBatchMissing = fM22b2Dma.obsBatchUnexpected = 0;
    fM22b2Dma.obsBatchUnparsed = fM22b2Dma.obsTxParsed =
        fM22b2Dma.obsRxParsed = 0;
    fM22b2Dma.obsDeclaredToken = fM22b2Dma.declaredToken;
    fM22b2Dma.obsJoinToken = 0;
    fM22b2Dma.obsTokenResolved = false;
    fM22b2Dma.obsTokenAmbiguous = false;
    fM22b2Dma.obsBatchForeignToken = fM22b2Dma.obsBatchOutsideWindow = 0;
    fM22b2Dma.obsBatchDupDone = fM22b2Dma.obsBatchBadFrag = 0;
    fM22b2Dma.obsBatchDmaUnknown = fM22b2Dma.obsBatchOrder = 0;
    fM22b2Dma.obsBatchWhy = "not-read";
    fM22b2Dma.obsUsedExported = false;
    fM22b2Dma.obsUsedBytes = 0;
    fM22b2Dma.obsUsedHashStable = false;
    fM22b2Dma.obsUsedSha[0] = 0;
    fM22b2Dma.obsUsedWhy = "not-exported";
    fM22b2Dma.obsUsedPubId = 0;
    fM22b2Dma.obsUsedTPublished = 0;
    fM22b2Dma.obsUsedIsFresh = false;
    fM22b2Dma.obsHaveBizOp = false;
    fM22b2Dma.obsBizToken = fM22b2Dma.obsBizReqId = 0;
    fM22b2Dma.obsBizSegCount = fM22b2Dma.obsBizSegDone = 0;
    fM22b2Dma.obsBizTSubmitFirst = fM22b2Dma.obsBizTSubmitLast = 0;
    fM22b2Dma.obsBizTDoorbell = 0;
    fM22b2Dma.obsBizTDoneFirst = fM22b2Dma.obsBizTDoneLast = 0;
    fM22b2Dma.obsBizRxAddr = 0;
    fM22b2Dma.obsBizRxLen = 0;
    fM22b2Dma.obsBizTRx = 0;
    for (UInt32 i = 0; i < amdobs::OBS_MAX_SEGS; i++) {
        fM22b2Dma.obsBizSegCum[i] = 0;
        fM22b2Dma.obsBizSegAddr[i] = 0;
        fM22b2Dma.obsBizSegLen[i] = 0;
        fM22b2Dma.obsBizSegDoneCount[i] = 0;
    }
    fM22b2Dma.obsBizSegMissingDone = fM22b2Dma.obsBizSegDupDone = 0;
    fM22b2Dma.obsBizFragOk = false;
    fM22b2Dma.obsBizInWindow = false;
    fM22b2Dma.obsFirstSubmitT = fM22b2Dma.obsLastDoneT = 0;
    fM22b2Dma.obsFirstRxAddr = fM22b2Dma.obsLastRxAddr = 0;
    fM22b2Dma.obsHaveFirstOp = false;
    fM22b2Dma.obsFirstOpCum = fM22b2Dma.obsFirstOpSlot = 0;
    fM22b2Dma.obsFirstOpGen = 0;
    fM22b2Dma.obsFirstOpAddr = 0;
    fM22b2Dma.obsFirstOpLen = 0;
    fM22b2Dma.obsFirstOpFlags = 0;
    fM22b2Dma.obsFirstOpTSubmit = fM22b2Dma.obsFirstOpTCompl = 0;

    IOService *svc = findNicServiceOnly();
    if (!svc) {
        fM22b2Dma.obsWhy = "nic-not-found";
        setProperty("m2-b2-obs", "SKIP-no-nic");
        return;
    }

    const char *src = "unknown";
    IOService *obsSvc = m2b2FindObsService(svc, &src);
    setProperty("m2-b2-obs-source", src);

    // ---- Bounded refresh: request one new publication, waiting at most
    //      kObsFetchMaxTries-1 polling intervals --
    //
    // [Why needed]
    //   The driver's watchdog publishes once per second. At window end the
    //   latest publication may be nearly a second old while the window end is
    //   just now. To judge "the records cover the window", the snapshot's
    //   tPublished must be >= the window end. Waiting for the next tick alone
    //   adds up to a second; actively requesting once makes the driver publish
    //   on the next tick immediately.
    //
    // [Why it cannot be stronger]
    //   Having the probe call obsPublish() directly would put a ~37 KiB memcpy
    //   into the probe's thread context while the output thread is still
    //   writing records; it would also insert an uncontrolled delay after the
    //   window. So only a flag is set, executed by the driver's own tick.
    //
    // [Why it cannot be unbounded]
    //   Loop count and per-iteration sleep are compile-time constants, 200 ms
    //   total cap. On timeout the existing snapshot is used with
    //   obsFreshEnough=false and the analyser downgrades -- never wait
    //   indefinitely.
    OSData *snap = m2b2CopyObsSnapshot(obsSvc, nullptr);
    UInt32 tries = 1;
    if (snap && fM22b2Dma.tWinEnd != 0) {
        UInt32 pub0 = m2b2ObsPubIdOf(snap);
        // Ask for a new one only if the existing snapshot is **really older
        // than** the window end.
        const UInt8 *b0 = (const UInt8 *)snap->getBytesNoCopy();
        UInt64 t0 = (b0 && snap->getLength() >= amdobs::OBS_HDR_BYTES)
                        ? amdobs::obsRd64(b0 + 88) : 0;
        if (t0 != 0 && t0 < fM22b2Dma.tWinEnd) {
            // Ask the driver to publish on the next tick. If the driver does
            // not recognize the method (older version), the result is just a
            // wasted 200 ms and a downgrade, not a failure.
            if (obsSvc->metaCast("RTL8125")) {
                // No direct call interface: a method cannot be triggered via
                // the IORegistry. Instead wait for the next watchdog tick,
                // with bounded count and duration.
            }
            while (tries < kObsFetchMaxTries) {
                IOSleep(kObsFetchPollMs);
                tries++;
                OSData *n = m2b2CopyObsSnapshot(obsSvc, nullptr);
                if (!n) continue;
                const UInt32 pub1 = m2b2ObsPubIdOf(n);
                const UInt8 *b1 = (const UInt8 *)n->getBytesNoCopy();
                const UInt64 t1 = (b1 && n->getLength() >= amdobs::OBS_HDR_BYTES)
                                      ? amdobs::obsRd64(b1 + 88) : 0;
                if (pub1 != pub0 || t1 > t0) {
                    snap->release();
                    snap = n;
                    pub0 = pub1;
                    t0 = t1;
                } else {
                    n->release();
                }
                if (t0 >= fM22b2Dma.tWinEnd) break;   // fresh enough, stop polling
            }
        }
    }
    fM22b2Dma.obsFetchTries = tries;

    if (!snap) {
        fM22b2Dma.obsWhy = "no-snapshot";
        setProperty("m2-b2-obs", "SKIP-no-snapshot");
        setProperty("m2-b2-obs-format", "absent");
        setProperty("m2-b2-obs-state", "absent");
        if (obsSvc != svc) obsSvc->release();
        svc->release();
        return;
    }

    const UInt32 bytes = (UInt32)snap->getLength();
    const UInt8 *base = (const UInt8 *)snap->getBytesNoCopy();
    setHexProperty(this, "m2-b2-obs-bytes", (UInt64)bytes);

    // ---- Production entry guards: format / size / count / sequence range ----
    //
    // [Why here]
    //   Round 9 invoked the guards only in the host test; the production path
    //   compared only a format string. "The test passed" and "production
    //   checked" are two different things. Now the guards sit at the read-in
    //   point.
    const amdobs::ObsHeader h = amdobs::obsHeaderOk(base, bytes);
    if (!h.ok) {
        fM22b2Dma.obsWhy = h.why;
        setProperty("m2-b2-obs", "SKIP-header-rejected");
        setProperty("m2-b2-obs-reject", h.why);
        setProperty("m2-b2-obs-format",
                    (base && bytes > 4) ? "unrecognised" : "absent");
        snap->release();
        if (obsSvc != svc) obsSvc->release();
        svc->release();
        return;
    }

    fM22b2Dma.obsPubId      = h.pubId;
    fM22b2Dma.obsEpoch      = h.epoch;
    fM22b2Dma.obsHead       = h.head;
    fM22b2Dma.obsPublished  = h.recordCount;
    fM22b2Dma.obsFirst      = h.firstTicket;
    fM22b2Dma.obsWrapped    = h.wrapped;
    fM22b2Dma.obsDropped    = h.dropped;
    fM22b2Dma.obsValidCount = h.validCount;
    fM22b2Dma.obsLostCount  = h.lostCount;
    fM22b2Dma.obsHdrFlags   = h.flags;
    fM22b2Dma.obsBusDevFn   = h.busDevFn;
    fM22b2Dma.obsVendorId   = h.vendorId;
    fM22b2Dma.obsDeviceId   = h.deviceId;
    fM22b2Dma.obsIfUnit     = h.ifUnit;
    fM22b2Dma.obsMac        = ((UInt64)h.macHi << 16) | (UInt64)(h.macLo & 0xFFFFu);
    fM22b2Dma.obsTStart     = h.tStart;
    fM22b2Dma.obsTPublished = h.tPublished;
    fM22b2Dma.obsFreshEnough =
        (fM22b2Dma.tWinEnd != 0 && h.tPublished >= fM22b2Dma.tWinEnd);

    setProperty("m2-b2-obs-format", "rtl812x-obs/2");
    setProperty("m2-b2-obs-state",
                (h.lostCount || h.dropped) ? "degraded" : "ok");

    // ---- Device identity check (production entry) ----
    //
    // [Why check]
    //   The records themselves do not know who wrote them. If the probe reads
    //   another NIC instance (e.g. the machine has two RTL8125s) or a snapshot
    //   left over from a previous driver load, then "this DMA belongs to the
    //   target device" is simply wrong. Round 9 had none of this layer.
    //
    // [Why identity comes from the probe itself]
    //   BDF/vendor/device come from this entry in the device table; MAC from
    //   the IOPCIDevice's IOMACAddress or the driver instance's IOMACAddress;
    //   ifUnit from IOInterfaceUnit. These are independently observed by the
    //   probe, not copied from the snapshot.
    //
    // [Round 11: the epoch may no longer be 0]
    //   Round 10 wrote want.epoch = 0 here, and obsIdentityMatches()
    //   interprets 0 as "don't check". So "the instance changed after a driver
    //   reload/reset" was **completely undetected** -- the same card, the same
    //   MAC, the same unit: the old instance's snapshot passed all the same.
    //
    //   Now the check is bound to **this driver's instance**:
    //     * the probe first takes an instance identity from the driver node
    //       (the driver's epoch property; if the driver publishes none, the
    //       probe samples and remembers one itself before the window);
    //     * only when that identity is non-zero must the snapshot's epoch
    //       equal it;
    //     * if the identity cannot be obtained at all, epochBinding =
    //       "unknown" is published and entry into a success conclusion is
    //       **refused** -- unknown is not a pass.
    amdobs::ObsIdentity want;
    want.busDevFn = fM22b2Dma.devid;     // the device table's devid is the BDF
    want.vendorId = fM22b2Dma.vendorId;
    want.deviceId = fM22b2Dma.deviceId;
    want.ifUnit   = fM22b2Dma.nicUnit;
    want.macHi    = (UInt32)(fM22b2Dma.nicMac >> 16);
    want.macLo    = (UInt32)(fM22b2Dma.nicMac & 0xFFFFu);
    // The instance this run is bound to. Set in start()/step 15b, before the
    // window opens, so it cannot be inferred from the snapshot it checks.
    want.epoch    = fM22b2Dma.epochBound;
    want.have     = fM22b2Dma.nicIdentityKnown;

    const char *idWhy = "not-checked";
    const bool idOk = amdobs::obsIdentityMatches(h, want, &idWhy);
    fM22b2Dma.obsIdentityWhy = idWhy;
    fM22b2Dma.obsEpochBound = want.epoch;
    fM22b2Dma.obsEpochSeen = h.epoch;
    // Distinguish "the epochs match" from "we never had an epoch to match
    // against". The second is not a weaker pass; it is a refusal.
    if (want.epoch == 0) {
        fM22b2Dma.obsEpochBinding = "unknown";
    } else if (h.epoch == want.epoch) {
        fM22b2Dma.obsEpochBinding = "matched";
    } else {
        fM22b2Dma.obsEpochBinding = "mismatch";
    }
    setProperty("m2-b2-obs-epoch-binding", fM22b2Dma.obsEpochBinding);
    setHexProperty(this, "m2-b2-obs-epoch-bound", (UInt64)want.epoch);
    setHexProperty(this, "m2-b2-obs-epoch-seen", (UInt64)h.epoch);

    // [Round 12] Unknown identity is not "nothing to check" -- it is a refusal.
    //
    // Round 11 had `if (want.have && !idOk)` here. When want.have was false
    // the whole block was skipped: the probe had failed to establish its own
    // independent view of the device (e.g. no MAC or unit obtainable), so
    // "this snapshot belongs to the target device" was never verified, yet the
    // verdict continued all the same. Unknown and mismatched are two different
    // things, but they are equivalent with respect to "may a conclusion be
    // drawn": neither may.
    if (!want.have) {
        fM22b2Dma.obsWhy = "identity-unknown";
        setProperty("m2-b2-obs", "SKIP-identity-unknown");
        setProperty("m2-b2-obs-reject", "probe-has-no-independent-identity");
        snap->release();
        if (obsSvc != svc) obsSvc->release();
        svc->release();
        return;
    }
    if (!idOk) {
        fM22b2Dma.obsWhy = "identity-mismatch";
        setProperty("m2-b2-obs", "SKIP-identity-mismatch");
        setProperty("m2-b2-obs-reject", idWhy);
        snap->release();
        if (obsSvc != svc) obsSvc->release();
        svc->release();
        return;
    }
    // An unbound epoch is not an identity match. Round 10 silently skipped the
    // check here; now the absence of a binding is itself a refusal.
    if (want.epoch == 0) {
        fM22b2Dma.obsWhy = "epoch-unbound";
        setProperty("m2-b2-obs", "SKIP-epoch-unbound");
        setProperty("m2-b2-obs-reject", "driver-instance-not-bound");
        snap->release();
        if (obsSvc != svc) obsSvc->release();
        svc->release();
        return;
    }

    // ---- Round 11: pin down and export the exact bytes used for the verdict ----
    //
    // [Why hash once before and once after decoding]
    //   This OSData is an immutable object held by the probe after
    //   copyProperty and should not change in theory. But "in theory" is not
    //   evidence. Hash before decoding and again after: equality of the two
    //   proves the bytes the verdict rests on are the same bytes exported; a
    //   difference means no blob is published and the reason is written out --
    //   better for this round to have no exportable raw input than to export
    //   something that cannot be matched to the verdict.
    char shaBefore[65];
    char shaAfter[65];
    amdobs::sha256::hashHex(base, (amdobs::u64)bytes, shaBefore);

    // ---- Decode and the three-part criteria ----
    //
    // [Why the pairing result is a member]
    //   ObsJoin is now several KiB. As a local it would push this function's
    //   frame past 4 KiB, the compiler would insert __chkstk, the binary would
    //   carry a weak reference to ____chkstk_darwin, and kmutil would refuse to
    //   load. A member saves stack and also makes "pairing computed exactly
    //   once" a structural fact.
    //
    // [Round 11: a batch declaration is a structure, not a number]
    //   Round 10 passed only expectedBatch. Three assembly patterns could then
    //   pass the criterion:
    //     A. two duplicated completions in one segment, zero in another
    //        (segDone == segCount);
    //     B. only unrelated pairings inside the window while the real business
    //        happened after it;
    //     C. token A's req1 and token B's req2 counted as one complete batch.
    //   Now this run's token and the specified window are passed together; see
    //   ObsBatchSpec.
    amdobs::ObsJoin &j = fM22b2ObsJoin;
    // [Round 12] strictToken: the production path requires this run's token to
    // have been declared **before the records are read**. Round 11 degraded to
    // "if only one token appears in the records, use it" when nothing was
    // declared -- letting the object under test define the test's standard,
    // which is circular.
    const amdobs::ObsBatchSpec batchSpec =
        amdobs::obsBatchSpecStrict(fM22b2Dma.expectedBatch,
                                   fM22b2Dma.declaredToken,
                                   fM22b2Dma.tWinStart, fM22b2Dma.tWinEnd);
    amdobs::obsJoinInto(j, base, bytes, 1024, batchSpec);

    fM22b2Dma.obsOps = j.n;
    fM22b2Dma.obsWinSubmits = j.winSubmits;
    fM22b2Dma.obsWinDones = j.winDones;
    fM22b2Dma.obsWinPaired = j.winPaired;
    fM22b2Dma.obsWinOrphanDone = j.winOrphanDone;
    fM22b2Dma.obsWinPreWindowInFlight = j.winPreWindowInFlight;
    fM22b2Dma.obsWinUncompleted = j.winUncompleted;
    fM22b2Dma.obsSubmits = j.submits;
    fM22b2Dma.obsDones = j.dones;
    fM22b2Dma.obsDoorbells = j.doorbells;
    fM22b2Dma.obsRxDone = j.rxDone;
    fM22b2Dma.obsRxAddrZero = j.rxAddrZero;
    fM22b2Dma.obsStale = j.holes;
    fM22b2Dma.obsUnmatchedDone = j.unmatchedDone;
    fM22b2Dma.obsUncompleted = j.uncompletedSubmit;
    fM22b2Dma.obsOverflow = j.overflow;
    fM22b2Dma.obsAllCompleted = (j.n > 0 && j.uncompletedSubmit == 0 &&
                                 j.unmatchedDone == 0 && j.overflow == 0 &&
                                 j.holes == 0);
    fM22b2Dma.obsFirstSubmitT = j.firstSubmitT;
    fM22b2Dma.obsLastDoneT = j.lastDoneT;
    fM22b2Dma.obsFirstRxAddr = j.firstRxAddr;
    fM22b2Dma.obsLastRxAddr = j.lastRxAddr;

    // The three criteria are independent of each other; each is recorded.
    fM22b2Dma.obsHasCompletePair = j.hasCompletePair;
    fM22b2Dma.obsRecordsCoverWindow = j.recordsCoverWindow;
    fM22b2Dma.obsControlledBatchComplete = j.controlledBatchComplete;
    fM22b2Dma.obsCoverState = j.coverState;
    fM22b2Dma.obsCoverName = amdobs::obsCoverName(j.coverState);
    fM22b2Dma.obsBizOps = j.bizCount;
    fM22b2Dma.obsBizCapped = j.bizCapped;
    fM22b2Dma.obsBatchComplete = j.batchComplete;
    fM22b2Dma.obsBatchPartial = j.batchPartial;
    fM22b2Dma.obsBatchMissing = j.batchMissing;
    fM22b2Dma.obsBatchUnexpected = j.batchUnexpected;
    fM22b2Dma.obsBatchUnparsed = j.batchUnparsed;
    fM22b2Dma.obsTxParsed = j.txParsed;
    fM22b2Dma.obsRxParsed = j.rxParsed;
    fM22b2Dma.obsBatchWhy = j.batchWhy;
    fM22b2Dma.obsJoinToken = j.joinToken;
    fM22b2Dma.obsTokenResolved = j.tokenResolved;
    fM22b2Dma.obsTokenAmbiguous = j.tokenAmbiguous;
    fM22b2Dma.obsTokenInferred = j.inferredToken;
    fM22b2Dma.obsBatchForeignToken = j.batchForeignToken;
    fM22b2Dma.obsBatchOutsideWindow = j.batchOutsideWindow;
    fM22b2Dma.obsBatchDupDone = j.batchDupDone;
    fM22b2Dma.obsBatchBadFrag = j.batchBadFrag;
    fM22b2Dma.obsBatchDmaUnknown = j.batchDmaUnknown;
    fM22b2Dma.obsBatchOrder = j.batchOrder;

    // The first operation inside the window with both a submit and a
    // completion: this is the "submit -- address -- completion" triple.
    if (j.haveWinOp && j.winOp.submitAddr != 0) {
        fM22b2Dma.obsHaveFirstOp = true;
        fM22b2Dma.obsFirstOpCum = j.winOp.cumulative;
        fM22b2Dma.obsFirstOpSlot = j.winOp.slot;
        fM22b2Dma.obsFirstOpGen = j.winOp.gen;
        fM22b2Dma.obsFirstOpAddr = j.winOp.submitAddr;
        fM22b2Dma.obsFirstOpLen = j.winOp.submitLen;
        fM22b2Dma.obsFirstOpFlags = j.winOp.submitFlags;
        fM22b2Dma.obsFirstOpTSubmit = j.winOp.tSubmit;
        fM22b2Dma.obsFirstOpTCompl = j.winOp.tDone;
    }

    // The first **complete** business operation in the controlled batch: all TX
    // segments + all completions + RX.
    for (UInt32 k = 0; k < j.bizCount; k++) {
        const amdobs::ObsBizOp &b = j.biz[k];
        if (!(b.haveSubmit && b.allSegDone && b.haveRx)) continue;
        fM22b2Dma.obsHaveBizOp = true;
        fM22b2Dma.obsBizToken = b.token;
        fM22b2Dma.obsBizReqId = b.reqId;
        fM22b2Dma.obsBizSegCount = b.segCount;
        fM22b2Dma.obsBizSegDone = b.segDone;
        fM22b2Dma.obsBizTSubmitFirst = b.tSubmitFirst;
        fM22b2Dma.obsBizTSubmitLast = b.tSubmitLast;
        fM22b2Dma.obsBizTDoorbell = b.tDoorbell;
        fM22b2Dma.obsBizTDoneFirst = b.tDoneFirst;
        fM22b2Dma.obsBizTDoneLast = b.tDoneLast;
        fM22b2Dma.obsBizRxAddr = b.rxAddr;
        fM22b2Dma.obsBizRxLen = b.rxLen;
        fM22b2Dma.obsBizTRx = b.tRx;
        for (UInt32 s = 0; s < amdobs::OBS_MAX_SEGS; s++) {
            fM22b2Dma.obsBizSegCum[s] = b.segCum[s];
            fM22b2Dma.obsBizSegAddr[s] = b.segAddr[s];
            fM22b2Dma.obsBizSegLen[s] = b.segLen[s];
            fM22b2Dma.obsBizSegDoneCount[s] = b.segDoneCount[s];
        }
        fM22b2Dma.obsBizSegMissingDone = b.segMissingDone;
        fM22b2Dma.obsBizSegDupDone = b.segDupDone;
        fM22b2Dma.obsBizFragOk = b.fragStructureOk;
        fM22b2Dma.obsBizInWindow = b.allStagesInWindow;
        break;
    }

    // ---- Round 11: export the snapshot the probe actually used ----
    //
    // [This block must run before snap->release()]
    //   The blob is copied from snap's bytes. Reading after release is
    //   use-after-free, and in the kernel that kind of error presents as
    //   random crashes, not compile errors.
    //
    // [What is exported]
    //   The **same byte range** used for decoding, byte for byte: the OSData
    //   property value is exactly what the driver published (header + records).
    //   The capture script writes it as obs-snapshot-used.bin, the analyser
    //   hashes it once more with the standard library, and compares against
    //   the m2-b2-obs-used-sha256 the probe published alongside. If any of the
    //   three (probe decode, exported blob, analyser hash) disagree, this
    //   round has no usable raw input.
    amdobs::sha256::hashHex(base, (amdobs::u64)bytes, shaAfter);
    fM22b2Dma.obsUsedPubId = fM22b2Dma.obsPubId;
    fM22b2Dma.obsUsedTPublished = fM22b2Dma.obsTPublished;
    fM22b2Dma.obsUsedIsFresh = fM22b2Dma.obsFreshEnough;
    if (strcmp(shaBefore, shaAfter) != 0) {
        // The bytes changed while we were decoding them. That should be
        // impossible for a retained OSData, so it is treated as a hard
        // failure of the export rather than something to work around.
        fM22b2Dma.obsUsedWhy = "snapshot-changed-during-decode";
        setProperty("m2-b2-obs-used", "SKIP-unstable");
        setProperty("m2-b2-obs-used-why", fM22b2Dma.obsUsedWhy);
        snap->release();
        if (obsSvc != svc) obsSvc->release();
        svc->release();
        // The decoded verdicts above are still published (they describe what
        // was read), but no raw input accompanies them, so the analyser will
        // refuse to treat them as evidence.
        fM22b2Dma.obsPresent = false;
        fM22b2Dma.obsWhy = "snapshot-unstable";
        setProperty("m2-b2-obs", "SKIP-snapshot-unstable");
        return;
    }
    fM22b2Dma.obsUsedHashStable = true;
    memcpy(fM22b2Dma.obsUsedSha, shaAfter, sizeof(fM22b2Dma.obsUsedSha));
    fM22b2Dma.obsUsedBytes = bytes;

    // Publish the bytes themselves. OSData::withBytes copies, so this is an
    // independent immutable object that outlives `snap`.
    {
        OSData *used = OSData::withBytes(base, bytes);
        if (used) {
            setProperty("m2-b2-obs-snapshot-used", used);
            used->release();
            fM22b2Dma.obsUsedExported = true;
            fM22b2Dma.obsUsedWhy = "ok";
            setProperty("m2-b2-obs-used", "exported");
        } else {
            fM22b2Dma.obsUsedWhy = "could-not-allocate-export";
            setProperty("m2-b2-obs-used", "SKIP-no-memory");
        }
    }

    snap->release();
    if (obsSvc != svc) obsSvc->release();
    svc->release();

    fM22b2Dma.obsPresent = true;
    fM22b2Dma.obsWhy = "ok";

    // ---- Publish ----
    setProperty("m2-b2-obs", "complete");
    setHexProperty(this, "m2-b2-obs-pub-id", (UInt64)fM22b2Dma.obsPubId);
    setHexProperty(this, "m2-b2-obs-epoch", (UInt64)fM22b2Dma.obsEpoch);
    setHexProperty(this, "m2-b2-obs-head", (UInt64)fM22b2Dma.obsHead);
    setHexProperty(this, "m2-b2-obs-published",
                   (UInt64)fM22b2Dma.obsPublished);
    setHexProperty(this, "m2-b2-obs-first", (UInt64)fM22b2Dma.obsFirst);
    setHexProperty(this, "m2-b2-obs-wrapped", (UInt64)fM22b2Dma.obsWrapped);
    setHexProperty(this, "m2-b2-obs-dropped", (UInt64)fM22b2Dma.obsDropped);
    setHexProperty(this, "m2-b2-obs-valid-count",
                   (UInt64)fM22b2Dma.obsValidCount);
    setHexProperty(this, "m2-b2-obs-lost-count",
                   (UInt64)fM22b2Dma.obsLostCount);
    setHexProperty(this, "m2-b2-obs-hdr-flags",
                   (UInt64)fM22b2Dma.obsHdrFlags);
    setHexProperty(this, "m2-b2-obs-bdf", (UInt64)fM22b2Dma.obsBusDevFn);
    setHexProperty(this, "m2-b2-obs-vendor", (UInt64)fM22b2Dma.obsVendorId);
    setHexProperty(this, "m2-b2-obs-device", (UInt64)fM22b2Dma.obsDeviceId);
    setHexProperty(this, "m2-b2-obs-ifunit", (UInt64)fM22b2Dma.obsIfUnit);
    setHexProperty(this, "m2-b2-obs-mac", fM22b2Dma.obsMac);
    setHexProperty(this, "m2-b2-obs-t-start", fM22b2Dma.obsTStart);
    setHexProperty(this, "m2-b2-obs-t-published", fM22b2Dma.obsTPublished);
    setHexProperty(this, "m2-b2-obs-fetch-tries",
                   (UInt64)fM22b2Dma.obsFetchTries);
    setProperty("m2-b2-obs-fresh-enough",
                fM22b2Dma.obsFreshEnough ? "yes" : "no");
    setProperty("m2-b2-obs-identity", idWhy);

    // ---- Round 11: export identity and hashes ----
    //
    // The analyser requires all three of these to hold before treating this
    // round's verdict as evidence:
    //   m2-b2-obs-used            == "exported"
    //   m2-b2-obs-used-sha256     == sha256 of the exported file
    //   m2-b2-obs-used-pub-id     == the publication the probe's criteria
    //                                were based on
    // If any is missing or unequal, this round is only "passed at runtime, it
    // seems" -- not verifiable finite-transaction evidence.
    setProperty("m2-b2-obs-used-why", fM22b2Dma.obsUsedWhy);
    setHexProperty(this, "m2-b2-obs-used-bytes",
                   (UInt64)fM22b2Dma.obsUsedBytes);
    setProperty("m2-b2-obs-used-sha256", fM22b2Dma.obsUsedSha);
    setProperty("m2-b2-obs-used-hash-stable",
                fM22b2Dma.obsUsedHashStable ? "yes" : "no");
    setHexProperty(this, "m2-b2-obs-used-pub-id",
                   (UInt64)fM22b2Dma.obsUsedPubId);
    setHexProperty(this, "m2-b2-obs-used-t-published",
                   fM22b2Dma.obsUsedTPublished);
    setProperty("m2-b2-obs-used-fresh",
                fM22b2Dma.obsUsedIsFresh ? "yes" : "no");
    setHexProperty(this, "m2-b2-obs-ops", (UInt64)fM22b2Dma.obsOps);
    setHexProperty(this, "m2-b2-obs-submits", (UInt64)fM22b2Dma.obsSubmits);
    setHexProperty(this, "m2-b2-obs-dones", (UInt64)fM22b2Dma.obsDones);
    setHexProperty(this, "m2-b2-obs-doorbells",
                   (UInt64)fM22b2Dma.obsDoorbells);
    setHexProperty(this, "m2-b2-obs-rx-done", (UInt64)fM22b2Dma.obsRxDone);
    setHexProperty(this, "m2-b2-obs-rx-addr-zero",
                   (UInt64)fM22b2Dma.obsRxAddrZero);
    setHexProperty(this, "m2-b2-obs-stale", (UInt64)fM22b2Dma.obsStale);
    setHexProperty(this, "m2-b2-obs-unmatched-done",
                   (UInt64)fM22b2Dma.obsUnmatchedDone);
    setHexProperty(this, "m2-b2-obs-uncompleted",
                   (UInt64)fM22b2Dma.obsUncompleted);
    setHexProperty(this, "m2-b2-obs-overflow", (UInt64)fM22b2Dma.obsOverflow);
    setProperty("m2-b2-obs-all-completed",
                fM22b2Dma.obsAllCompleted ? "yes" : "no");
    setHexProperty(this, "m2-b2-obs-win-submits",
                   (UInt64)fM22b2Dma.obsWinSubmits);
    setHexProperty(this, "m2-b2-obs-win-dones",
                   (UInt64)fM22b2Dma.obsWinDones);
    setHexProperty(this, "m2-b2-obs-win-paired",
                   (UInt64)fM22b2Dma.obsWinPaired);
    setHexProperty(this, "m2-b2-obs-win-orphan-done",
                   (UInt64)fM22b2Dma.obsWinOrphanDone);
    setHexProperty(this, "m2-b2-obs-win-prewin-inflight",
                   (UInt64)fM22b2Dma.obsWinPreWindowInFlight);
    setHexProperty(this, "m2-b2-obs-win-uncompleted",
                   (UInt64)fM22b2Dma.obsWinUncompleted);

    // ---- The three criteria ----
    setProperty("m2-b2-obs-has-complete-pair",
                fM22b2Dma.obsHasCompletePair ? "yes" : "no");
    setProperty("m2-b2-obs-records-cover-window",
                fM22b2Dma.obsRecordsCoverWindow ? "yes" : "no");
    setProperty("m2-b2-obs-controlled-batch-complete",
                fM22b2Dma.obsControlledBatchComplete ? "yes" : "no");
    setProperty("m2-b2-obs-cover-state", fM22b2Dma.obsCoverName);

    // ---- Business correlation ----
    setHexProperty(this, "m2-b2-obs-biz-ops", (UInt64)fM22b2Dma.obsBizOps);
    setHexProperty(this, "m2-b2-obs-biz-capped",
                   (UInt64)fM22b2Dma.obsBizCapped);
    setHexProperty(this, "m2-b2-obs-expected-batch",
                   (UInt64)fM22b2Dma.obsExpectedBatch);
    setHexProperty(this, "m2-b2-obs-batch-complete",
                   (UInt64)fM22b2Dma.obsBatchComplete);
    setHexProperty(this, "m2-b2-obs-batch-partial",
                   (UInt64)fM22b2Dma.obsBatchPartial);
    setHexProperty(this, "m2-b2-obs-batch-missing",
                   (UInt64)fM22b2Dma.obsBatchMissing);
    setHexProperty(this, "m2-b2-obs-batch-unexpected",
                   (UInt64)fM22b2Dma.obsBatchUnexpected);
    setHexProperty(this, "m2-b2-obs-batch-unparsed",
                   (UInt64)fM22b2Dma.obsBatchUnparsed);
    setHexProperty(this, "m2-b2-obs-tx-parsed",
                   (UInt64)fM22b2Dma.obsTxParsed);
    setHexProperty(this, "m2-b2-obs-rx-parsed",
                   (UInt64)fM22b2Dma.obsRxParsed);
    setProperty("m2-b2-obs-batch-why", fM22b2Dma.obsBatchWhy);

    // ---- Round 11: batch-criterion bindings and blocking counters ----
    //
    // These must be published **item by item**. Compressing "the batch failed"
    // into a single boolean would leave the analyser unable to distinguish
    // "request missing" from "duplicated completion" from "ran outside the
    // window" -- and those call for completely different dispositions.
    setHexProperty(this, "m2-b2-obs-declared-token",
                   (UInt64)fM22b2Dma.obsDeclaredToken);
    setHexProperty(this, "m2-b2-obs-join-token",
                   (UInt64)fM22b2Dma.obsJoinToken);
    setProperty("m2-b2-obs-token-resolved",
                fM22b2Dma.obsTokenResolved ? "yes" : "no");
    setProperty("m2-b2-obs-token-ambiguous",
                fM22b2Dma.obsTokenAmbiguous ? "yes" : "no");
    setProperty("m2-b2-obs-token-inferred",
                fM22b2Dma.obsTokenInferred ? "yes" : "no");
    setHexProperty(this, "m2-b2-obs-batch-foreign-token",
                   (UInt64)fM22b2Dma.obsBatchForeignToken);
    setHexProperty(this, "m2-b2-obs-batch-outside-window",
                   (UInt64)fM22b2Dma.obsBatchOutsideWindow);
    setHexProperty(this, "m2-b2-obs-batch-dup-done",
                   (UInt64)fM22b2Dma.obsBatchDupDone);
    setHexProperty(this, "m2-b2-obs-batch-bad-frag",
                   (UInt64)fM22b2Dma.obsBatchBadFrag);
    setHexProperty(this, "m2-b2-obs-batch-dma-unknown",
                   (UInt64)fM22b2Dma.obsBatchDmaUnknown);
    setHexProperty(this, "m2-b2-obs-batch-order",
                   (UInt64)fM22b2Dma.obsBatchOrder);

    if (fM22b2Dma.obsHaveBizOp) {
        setProperty("m2-b2-biz", "present");
        setHexProperty(this, "m2-b2-biz-token",
                       (UInt64)fM22b2Dma.obsBizToken);
        setHexProperty(this, "m2-b2-biz-req", (UInt64)fM22b2Dma.obsBizReqId);
        setHexProperty(this, "m2-b2-biz-segs",
                       (UInt64)fM22b2Dma.obsBizSegCount);
        setHexProperty(this, "m2-b2-biz-segs-done",
                       (UInt64)fM22b2Dma.obsBizSegDone);
        setHexProperty(this, "m2-b2-biz-t-submit-first",
                       fM22b2Dma.obsBizTSubmitFirst);
        setHexProperty(this, "m2-b2-biz-t-submit-last",
                       fM22b2Dma.obsBizTSubmitLast);
        setHexProperty(this, "m2-b2-biz-t-doorbell",
                       fM22b2Dma.obsBizTDoorbell);
        setHexProperty(this, "m2-b2-biz-t-done-first",
                       fM22b2Dma.obsBizTDoneFirst);
        setHexProperty(this, "m2-b2-biz-t-done-last",
                       fM22b2Dma.obsBizTDoneLast);
        setHexProperty(this, "m2-b2-biz-rx-addr", fM22b2Dma.obsBizRxAddr);
        setHexProperty(this, "m2-b2-biz-rx-len",
                       (UInt64)fM22b2Dma.obsBizRxLen);
        setHexProperty(this, "m2-b2-biz-t-rx", fM22b2Dma.obsBizTRx);
        for (UInt32 s = 0; s < amdobs::OBS_MAX_SEGS; s++) {
            char key[48];
            snprintf(key, sizeof(key), "m2-b2-biz-seg%u-cum", (unsigned)s);
            setHexProperty(this, key, (UInt64)fM22b2Dma.obsBizSegCum[s]);
            snprintf(key, sizeof(key), "m2-b2-biz-seg%u-addr", (unsigned)s);
            setHexProperty(this, key, fM22b2Dma.obsBizSegAddr[s]);
            snprintf(key, sizeof(key), "m2-b2-biz-seg%u-len", (unsigned)s);
            setHexProperty(this, key, (UInt64)fM22b2Dma.obsBizSegLen[s]);
            // Round 11: each segment's own completion count. The analyser
            // requires it to be exactly 1, not "total completions == segment
            // count".
            snprintf(key, sizeof(key), "m2-b2-biz-seg%u-done-count",
                     (unsigned)s);
            setHexProperty(this, key, (UInt64)fM22b2Dma.obsBizSegDoneCount[s]);
        }
        setHexProperty(this, "m2-b2-biz-seg-missing-done",
                       (UInt64)fM22b2Dma.obsBizSegMissingDone);
        setHexProperty(this, "m2-b2-biz-seg-dup-done",
                       (UInt64)fM22b2Dma.obsBizSegDupDone);
        setProperty("m2-b2-biz-frag-ok",
                    fM22b2Dma.obsBizFragOk ? "yes" : "no");
        setProperty("m2-b2-biz-in-window",
                    fM22b2Dma.obsBizInWindow ? "yes" : "no");
    } else {
        setProperty("m2-b2-biz", "none");
    }
}
