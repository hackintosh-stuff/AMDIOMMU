# AMDIOMMU — experimental AMD IOMMU driver

AMDIOMMU is a macOS kernel extension that provides DMA translation for selected
PCIe devices on AMD platforms. It supports automatic attachment for compatible
drivers and explicit integration by clients. The optional AMDMapperHook Lilu
plugin makes the mapper available before a selected driver starts; see
[Install and Configure](#install-and-configure) for the two supported setups.

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

## Install and Configure

Choose one of two setups. Each has its own set of kexts and `boot-args` value.

| Setup | Kexts in `EFI/OC/Kexts/` | `boot-args` | Use when |
|---|---|---|---|
| Probe + Hook | `Lilu.kext`, `AMDMapperHook.kext`, `AMDMapperProbe.kext` | `amdiommu=passive` | The driver needs the mapper before it starts and cannot be modified to claim it. |
| Probe only | `AMDMapperProbe.kext` | `amdiommu=auto-attach` | The driver obtains its mapper through `IOMapper::copyMapperForDevice()`. |

### Probe + Hook (`amdiommu=passive`)

`AMDMapperHook.kext` is a Lilu plugin for `amdiommu=passive`. It supplies the
mapper before driver startup for selected clients that do not perform the
offer/claim handshake themselves. It leaves the driver unchanged and uses the
probe's device selection; it does not add devices.
List `Lilu.kext` before `AMDMapperHook.kext` in `Kernel > Add`. The hook is
active when loaded; disable its `Kernel > Add` entry or add `-amdmhoff` to turn
it off. Diagnostic properties are described in
[DEBUG.md](DEBUG.md#hook-diagnostics).

### Probe only (`amdiommu=auto-attach`)

The probe publishes `iommu-parent` when each selected device first publishes, so
drivers that only call `IOMapper::copyMapperForDevice()` receive the mapper
without Lilu or the hook. An offer is published as well, so a claim-based client
gets a definite answer rather than `kIOReturnNotReady`.

### Deploy through OpenCore

- Copy the bundles for the chosen setup to `<EFI system partition>/EFI/OC/Kexts/`.
- Enable their `Kernel > Add` entries in the OpenCore `config.plist` on that partition.
- Set `boot-args` to the mode shown above, then reboot to load the deployed build.

Locate the EFI system partition on the target machine; its partition number can
vary. The bundles in `build-m1a/`, `build-m1a-debug/` and `build-hook/` are build
outputs until copied to the ESP. This project uses OpenCore injection rather
than installation in `/Library/Extensions` or the auxiliary kernel collection.

### Boot arguments

| Setting | Purpose |
|---|---|
| `amdiommu=passive` | Probe + Hook setup; auto-attach is off. |
| `amdiommu=auto-attach` | Probe-only setup; publish `iommu-parent` at first publish. |
| `amdiommu_devices=<ids>` | Override the default device selection. |
| `amdiommu_ceiling=<name>` | Choose a capacity ceiling; normally omit it and use the default. |
| `amdiommu_pm=off` | Disable automatic sleep/wake notifications. |
| `amdiommu_dbg=0xNN` | Select the IORegistry evidence groups to publish. Omitted or invalid means `0x00`; set `0xFF` for the full surface. |

With no explicit device list, the kext uses the adapter identities configured in
its `Info.plist`. To select particular requesters, supply their IDs with the `n`
prefix; for example:

```text
amdiommu=passive amdiommu_devices=n2300,n2301
```

Use the requester IDs for the target machine; the same selector works in either
mode. An explicit list replaces the default selection; devices outside the
selection keep their existing DMA path.
The default list and selection format are described in
[DEBUG.md](DEBUG.md#device-selection).

Without a recognised `amdiommu` mode, the kext stays inactive. Both production
modes use `dma32-max` as the default ceiling and allocate capacity as needed;
`amdiommu_ceiling=native-legacy` keeps a domain at its initial 16 MiB window.
See the [configuration reference](DEBUG.md#production-configuration) and
[profile reference](DEBUG.md#profile-ceilings) for accepted values and limits.

## Compatibility

[COMPATIBILITY.md](COMPATIBILITY.md) lists board, CPU, adapter and driver
combinations verified on hardware.

## Diagnostics and implementation

[DEBUG.md](DEBUG.md) contains the configuration internals, capacity and memory
layout, synchronization rules, snapshot formats and IORegistry property
reference. Start with [Refresh and read](DEBUG.md#refresh-and-read) to capture
current state. Sleep/wake behavior is described under
[Power management](DEBUG.md#power-management).
