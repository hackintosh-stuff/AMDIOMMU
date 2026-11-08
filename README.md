# AMDIOMMU — experimental AMD IOMMU driver

A kernel extension that gives macOS a working `IOMapper` on AMD platforms. Apple
ships no IOMMU driver for consumer AMD chipsets, so a device's DMA normally
bypasses the IOMMU entirely. This kext discovers the AMD IOMMU from the ACPI
IVRS table and PCI configuration, takes the controller over once its state and
feature registers agree, and gives the selected PCIe requesters a translation
domain. It then publishes itself, so a driver either claims it explicitly
(`amdiommu=passive`) or Apple's own Ethernet kexts find it through
`IOMapper::copyMapperForDevice()` (`amdiommu=auto-attach`). An optional companion,
[AMDMapperHook](#amdmapperhook-optional-companion), covers drivers that do
neither.

Status: experimental, 0.98.0. Verified board/CPU/device combinations are listed
in [COMPATIBILITY.md](COMPATIBILITY.md); building, deploying into OpenCore and
setting boot-args are covered below.

## Boot arguments

Two build variants exist and accept different boot-args:

- **Production** (default): `sh tools/build/build-probe.sh` → `build-m1a/AMDMapperProbe.kext`.
  Compiles the six production translation units only.
- **Debug**: `sh tools/build/build-probe-debug.sh` → `build-m1a-debug/AMDMapperProbe.kext`.
  Adds `probe/*Debug.cpp` and `-DAMD_MAPPER_PROBE_DEBUG=1`, restoring the retired
  M2 experiment modes. See "Retired M2 experiment modes" below.
- **Hook plugin**: `sh tools/build/build-hook.sh` → `build-hook/AMDMapperHook.kext`.
  The optional Lilu companion described below; needs the Lilu source tree and
  MacKernelSDK.

### Production build

| Argument | Values | Meaning |
|---|---|---|
| `amdiommu=<mode>` | `passive` | Auto-attach off: keeps the R54–R67 offer/claim handshake; clients must call `AMDIOMMUClaimRequesterV1`. |
| | `auto-attach` | Publishes `iommu-parent` at first publish for selected requesters, so Apple's own Ethernet kexts (which only call `IOMapper::copyMapperForDevice()`) get the mapper. The offer is published as well, so a client that does run the claim handshake gets a definite answer instead of `kIOReturnNotReady`. |
| | absent / any other value (incl. `off`) | Inert: no notifier, no device arm, no MMIO. `off` is not a recognised value — it simply matches no mode. |
| `amdiommu_devices=<ids>` | decimals prefixed with `n`, e.g. `n2200,n2201` or `n2300,n2301` | Selects PCI requesters (segment zero). **Prefix each ID with a non-hex character (`n`)**: kernel's `PE_parse_boot_argn` rewrites an all-digit value into a 32-bit integer in the caller's buffer (`3400` arrived as `0x0D48`). The parser skips non-hex bytes before reading four hex digits. Omit to fall back to the identity list in the kext's `Info.plist` (`AMDMapperProbeDevices`, see below). |
| `amdiommu_profile=<name>` | `dma32-max` | Default growth ceiling for auto-attach: 131072 records / 524288 pages (2 GiB), with every IOVA below 4 GiB. |
| | `rl-10g-max` | Ceiling at 65535 records / 262144 pages (1 GiB). |
| | `rl-10g` | Ceiling at 16384 records / 131072 pages (512 MiB). |
| | `native-legacy` | Ceiling at the accepted ABI3 window (1024 records / 16 MiB): growth is disabled. |
| | unknown name | Widen nothing: growth is disabled and `iommu-profile-ceiling` records `unsupported-name`. |
| `amdiommu_pm=off` | `off` | Do not register the self-driven sleep/wake interest. The DMA path still repairs a controller that lost its register image; the mapper simply learns about the loss later. Absent means registered. |

`amdiommu_profile` selects the **growth ceiling**. Each domain initially
allocates only `native-legacy` storage: 1024 records, a 16 MiB IOVA window and
16 page-table pages. Metadata occupies 176128 bytes and page tables occupy
65536 bytes: **241664 bytes, or about 0.230 MiB per prepared domain**. A higher
ceiling does not reserve its full storage at startup.

Record slots and IOVA pages grow independently. When a mapping runs out of
record slots, the mapper doubles only the record capacity. When it cannot
allocate an IOVA range, it doubles only the page capacity. Each increase stops
at that resource's configured ceiling, then retries the same request under the
mapper lock. The first mapping does not itself trigger growth. Existing mappings
can remain live throughout growth.

Growth copies the allocation records, physical-page index and allocation bitmaps
into a larger metadata arena. Existing leaf pointers are copied. A page-capacity
increase also allocates new leaf tables and, when extending beyond the first
1 GiB directory, a second L2 table. The new tables are linked through unused
PDEs; a record-capacity increase leaves the page tables untouched. The root and
all existing page-table pages remain at their original physical addresses, so
existing IOVAs keep the same translations. New table blocks need not be
physically adjacent to the original block.

When page capacity grows, an active domain completes a full domain invalidation
including the PDE cache before the added range becomes usable. This growth fence
is required even when the controller has no NP cache. Growing only the record
capacity needs no hardware invalidation. Ordinary maps keep their existing
NP-cache optimization when filling an already prepared leaf.

At the exhausted resource's ceiling, an allocation that cannot fit returns
`kIOReturnNoResources`.
Allocation failure leaves existing mappings and capacity in place. If hardware
synchronization fails, new mapping admission closes through the existing failed
domain state. Successful growth does not count as a capacity rejection.

The default auto-attach ceiling is `dma32-max`: 131072 records and 2 GiB of IOVA
space. Its window is `[0x80000000, 0x100000000)`, so 32-bit DMA clients can use
the whole window. A claim-based client keeps the `native-legacy` ceiling unless
explicitly overridden. Record capacity advances from 1024 through 2048, 4096,
8192, 16384, 32768 and 65536 to 131072. Explicit smaller profiles retain their
limits; for example, `rl-10g-max` caps the record count at 65535. IOVA capacity
follows its own sequence:

| IOVA capacity | IOVA pages | Allocated table pages | Table bytes | Table segments |
|---|---:|---:|---:|---:|
| 16 MiB | 4096 | 16 | 65536 | 1 |
| 32 MiB | 8192 | 24 | 98304 | 2 |
| 64 MiB | 16384 | 40 | 163840 | 3 |
| 128 MiB | 32768 | 72 | 294912 | 4 |
| 256 MiB | 65536 | 136 | 557056 | 5 |
| 512 MiB | 131072 | 264 | 1081344 | 6 |
| 1 GiB | 262144 | 520 | 2129920 | 7 |
| 2 GiB | 524288 | 1033 | 4231168 | 8 |

The 1 GiB to 2 GiB increase adds one L2 table and 512 leaf tables in a single
513-page block. The existing L3 table links this second directory through its
unused entry 3; entry 2 continues to serve the original 1 GiB range. The root
and DTE stay in place. The initial block retains five spare pages, so the
fully grown tree owns 1033 table pages with 1028 reachable pages. A
record-capacity increase adds no table segment. `rootPA` remains stable;
`ptBytes` and `tablePages` grow only with IOVA capacity. Snapshot ABI5 and its
physical segment descriptors remain unchanged.
[DEBUG.md](DEBUG.md) documents the format and a saved-snapshot inspector that
also reads ABI4 captures.

The internal start-page owner index uses 32 bits, allowing record counts above
65535. It occupies four bytes for every page of IOVA capacity; this space is
included in the reported metadata size. Exported record indexes and capacity
fields are also 32-bit, so this capacity increase needs no snapshot layout
change.

For example, a domain whose record capacity remains at 1024 and whose IOVA
capacity grows to 64 MiB uses 327680 metadata bytes and 163840 table bytes:
**491520 bytes, or 0.46875 MiB** in total. The complete `dma32-max` capacity uses
22175744 metadata bytes and 4231168 table bytes. The actual capacity follows
allocation pressure over the domain's lifetime; a later live-page count does
not determine how far it has already grown.

The named profiles describe ceilings. `iommu-profile` and
`iommu-profile-allocated` are display labels: they show a known profile only
when both current capacities match it exactly, and `dynamic` otherwise. Read
`iommu-profile-records` and `iommu-profile-pages` for the actual usable limits.

The identity table records what device-based sizing would have suggested.
These suggestions are separate from the default `dma32-max` ceiling or an
explicit profile selection. The configured ceiling limits growth; each
successful step allocates only the storage needed for that step.

| Derived from | Matches | Suggested ceiling |
|---|---|---|
| vendor/device table | `15b3:1015/1017/1019/101b/101d`, `10ec:8124-8127` | `rl-10g-max` |
| PCI class fallback | base class `0x02` (network) | `rl-10g-max` |
| PCI class fallback | base class `0x01` (storage) | `rl-10g` |
| otherwise | — | `native-legacy` |

The per-device profile suggestions, growth evidence and the full IORegistry
property surface — including why most properties are snapshots rather than live
counters — are documented in [DEBUG.md](DEBUG.md).

Current example (ConnectX-4 Lx). No profile argument is needed because
usable capacity now follows demand:

```
amdiommu=auto-attach amdiommu_devices=n2300,n2301
```

### Default device selection from Info.plist

When `amdiommu_devices` is omitted, the kext matches devices by identity against
the `AMDMapperProbeDevices` value inside its own `Info.plist` personality
(`IOKitPersonalities/AMDMapperProbe`). The value uses the **`IOPCIMatch`
format**: whitespace-separated `0xDDDDVVVV` words, each optionally followed by
`&0xMMMMMMMM`; `VVVV` is the PCI vendor, `DDDD` the device, compared as
`(device << 16 | vendor) & mask`. The personality dictionary becomes the driver
instance's property table, so the kext reads it with `getProperty()`.

The checked-in list is the verified adapter set:

- Mellanox CX4 Lx family driven by Apple's MLX5 client:
  `0x101515b3 0x101715b3 0x101915b3 0x101b15b3 0x101d15b3`
- Realtek range driven by Apple's Ethernet Realtek driver:
  `0x812410ec 0x812510ec 0x812610ec 0x812710ec`

Everything outside this list keeps physical (pass-through) DMA. The two sources
are never merged: when `amdiommu_devices` is present it is the only selection and
this table is ignored; when it is absent this table is the selection. A device
chosen either way is attached at first publish in both modes and also publishes
an offer, so a client that runs the claim handshake gets a definite answer even
when the mapper was already in place.

### Retired M2 experiment modes (Debug build only)

Available only with `AMD_MAPPER_PROBE_DEBUG=1`. The parsers live in
`probe/AMDMapperProbeDebug.hpp`; the implementations live in `probe/*Debug.cpp`.

| Argument | Values | Meaning |
|---|---|---|
| `amdiommu=<mode>` | `arm`, `mmio`, `write`, `table`, `enable`, `cmd` | Progressive M2 hardware-enablement gates (B2-b arming, MMIO read, MMIO write, device table, short enable window, command channel). Each is an independent, individually revertible switch. |
| | `pgt`, `pgt4k`, `pgthold`, `pgtsleep`, `pgt3l` | M2-2b-2 page-table translation experiments (4-level identity table, 4 KiB leaves, 20 s held-translation window, sleep-only control, 3-level table). `pgt` is a prefix match, so `pgt4k` also opens the main gate. |
| | `.batch<N>`, `.t0x<N>` / `.token<N>`, `.std`, `.alltx`, `.rxstd`, `.session` | Suffixes inside the same `amdiommu=` value, e.g. `amdiommu=pgt.batch512.t0x2a.std.alltx.rxstd.session`. The parser scans every `.key` segment; a separate trailing boot-arg is not a dependable channel on this kernel. |
| `m2b2delay=<seconds>` | 1–300 | Delay before the one-shot M2-2b-2 page-table probe (default 20000 ms). |

## Power management

The mapper handles system sleep and wake itself, so a real S3 reaches it without a
client RPC; `amdiommu_pm=off` turns that off and `R47PowerTransition` stays as a
compatibility entry for a client that drives PM itself. It stops the translation
hardware only when no requester still holds a live mapping, and repairs a
controller that lost its image from the DMA path.

Sleep/wake cycles have run with translation active, one domain and four at a time:
registers restored, no resume failures, no target faults. The published state is
`pm-self-driven`, `pm-controller-state`, the suspend/resume counts,
`pm-resume-registers-restored`, `pm-suspend-retained`, `pm-lazy-restores` and
`pm-resume-failures`. Acceptance criteria live in the requirements document.

## Compatibility

Which PCIe devices have actually run through this mapper, on which board and
CPU, and with which driver: see [COMPATIBILITY.md](COMPATIBILITY.md). That table
lists only combinations verified on hardware, and only where the endpoint is
driven by a driver shipped with macOS; unverified boards and third-party driver
stacks are out of scope.

## AMDMapperHook (optional companion)

The probe is enough for most setups. A few drivers, however, neither run its
claim handshake nor get a mapper from `auto-attach`; those devices would stay on
plain physical DMA even though they were selected. `AMDMapperHook.kext` is a
small optional add-on that closes that gap: it makes the mapper available to the
device before its driver starts, without changing the driver. It relies on Lilu,
so add both to OpenCore with Lilu first.

You only need the hook when the probe waits for a claim (`amdiommu=passive` with
an optional `amdiommu_devices` list). In `auto-attach` the mapper is already
published at boot, and the hook simply stands by. There is no boot argument to
turn it on: if the kext is loaded, it is active. To turn it off, disable its
`Kernel > Add` entry in OpenCore, or add `-amdmhoff`.

The hook does **not** widen the device list. Only requesters named by
`amdiommu_devices`, or by `AMDMapperProbeDevices` when that boot argument is
absent, are ever mapped; everything else is left on its physical path. In
IORegistry the `AMDMapperHook` node shows `hook-state=installed` when it is
ready, and the `hook-*` counters show whether it ever had to step in.

Build it with `sh tools/build/build-hook.sh`. The bundle is written to
`build-hook/AMDMapperHook.kext` and must be copied to the ESP (below) before a
reboot; building alone changes nothing on the machine.

## Install location (target machine)

The kext that actually runs is NOT installed in `/Library/Extensions` and is not
part of the auxiliary kernel collection. It is deployed into the **OpenCore
directory on the target machine's EFI system partition** and injected at boot:

- Bundles: `<EFI system partition>/EFI/OC/Kexts/AMDMapperProbe.kext` and, when
  the hook is used, `AMDMapperHook.kext` (plus `Lilu.kext`).
- Enabled via `Kernel > Add` (`BundlePath = AMDMapperProbe.kext`, then
  `AMDMapperHook.kext`) in the OC `config.plist` on the same partition. Lilu
  must appear before the hook.

Deploying a new build therefore means copying `build-m1a/AMDMapperProbe.kext`
(or the debug variant) over that bundle and rebooting; the partition number of
the EFI system partition varies, resolve it on the machine instead of hardcoding
it. `build-m1a/` and `build-m1a-debug/` are build outputs only; they are not
installed anywhere until copied to the ESP.
