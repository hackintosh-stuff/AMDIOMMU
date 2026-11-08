# AMDIOMMU — experimental AMD IOMMU driver

AMDIOMMU is a macOS kernel extension that provides DMA translation for selected
PCIe devices on AMD platforms. It supports automatic attachment for compatible
drivers and explicit integration by clients. The optional
[AMDMapperHook](#amdmapperhook-optional-companion) helps drivers that need the
mapper supplied before they start.

Mapping capacity grows on demand while existing mappings remain valid. The
mapper also handles system sleep and wake notifications.

Status: experimental, 0.98.0. See [COMPATIBILITY.md](COMPATIBILITY.md) for verified
board, CPU and device combinations.

## Build

| Variant | Command | Output |
|---|---|---|
| Production | `sh tools/build/build-probe.sh` | `build-m1a/AMDMapperProbe.kext` |
| Debug | `sh tools/build/build-probe-debug.sh` | `build-m1a-debug/AMDMapperProbe.kext` |
| Optional hook | `sh tools/build/build-hook.sh` | `build-hook/AMDMapperHook.kext` |

The production build is optimized; the Debug build keeps the retired experiment
modes at its own optimization level. The hook build needs the Lilu source tree
and MacKernelSDK. Build configuration and the Debug experiment modes are in
[DEBUG.md](DEBUG.md#release-build-configuration) and
[DEBUG.md](DEBUG.md#debug-build-experiment-modes).

## Configure

Enable automatic attachment with:

```text
amdiommu=auto-attach
```

With no explicit device list, the kext uses the adapter identities configured in
its `Info.plist`. To select particular requesters, supply their IDs with the `n`
prefix; for example:

```text
amdiommu=auto-attach amdiommu_devices=n2300,n2301
```

Use the requester IDs for the target machine. An explicit list replaces the
default selection. Devices outside the selection keep their existing DMA path.
The default list and selection format are described in
[DEBUG.md](DEBUG.md#device-selection).

| Setting | Purpose |
|---|---|
| `amdiommu=auto-attach` | Attach the mapper automatically to selected devices. |
| `amdiommu=passive` | Use explicit client integration or the optional hook. |
| `amdiommu_devices=<ids>` | Override the default device selection. |
| `amdiommu_profile=<name>` | Choose a capacity ceiling; normally omit it and use the default. |
| `amdiommu_pm=off` | Disable automatic sleep/wake notifications. |

Without a recognised `amdiommu` mode, the kext stays inactive. Auto-attach uses
`dma32-max` as its default ceiling and allocates capacity as needed. See the
[configuration reference](DEBUG.md#production-configuration) and
[profile reference](DEBUG.md#profile-ceilings) for accepted values and limits.

## Install through OpenCore

Deploy the built bundle into the target machine's EFI system partition:

- Copy `AMDMapperProbe.kext` to `<EFI system partition>/EFI/OC/Kexts/`.
- Enable its `Kernel > Add` entry in the OpenCore `config.plist` on that partition.
- When using the hook, also install `Lilu.kext` and `AMDMapperHook.kext`, with
  Lilu listed before the hook.
- Reboot to load the deployed build.

Locate the EFI system partition on the target machine; its partition number can
vary. The bundles in `build-m1a/`, `build-m1a-debug/` and `build-hook/` are build
outputs until copied to the ESP. This project uses OpenCore injection rather
than installation in `/Library/Extensions` or the auxiliary kernel collection.

## AMDMapperHook (optional companion)

Use `AMDMapperHook.kext` with `amdiommu=passive` when a selected driver needs the
mapper made available before startup. It relies on Lilu and leaves the driver
unchanged. In `auto-attach` mode the mapper is already available and the hook
stands by.

The hook uses the probe's device selection. It is active when loaded; disable
its OpenCore `Kernel > Add` entry or add `-amdmhoff` to turn it off. Diagnostic
properties are described in [DEBUG.md](DEBUG.md#hook-diagnostics).

## Compatibility

[COMPATIBILITY.md](COMPATIBILITY.md) lists board, CPU, adapter and driver
combinations verified on hardware. The matrix covers drivers shipped with
macOS; unverified boards and third-party driver stacks are out of scope.

## Diagnostics and implementation

[DEBUG.md](DEBUG.md) contains the configuration internals, capacity and memory
layout, synchronization rules, snapshot formats and IORegistry property
reference. Start with [Refresh and read](DEBUG.md#refresh-and-read) to capture
current state. Sleep/wake behavior is described under
[Power management](DEBUG.md#power-management).
