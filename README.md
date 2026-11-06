# AMDIOMMU — experimental AMD IOMMU driver

A kernel extension that gives macOS a working `IOMapper` on AMD platforms. Apple
ships no IOMMU driver for consumer AMD chipsets, so a device's DMA normally
bypasses the IOMMU entirely. This kext discovers the AMD IOMMU from the ACPI
IVRS table and PCI configuration, takes the controller over once its state and
feature registers agree, and gives the selected PCIe requesters a translation
domain. It then publishes itself, so a driver either claims it explicitly
(`amdiommu=passive`) or Apple's own Ethernet kexts find it through
`IOMapper::copyMapperForDevice()` (`amdiommu=auto-attach`).

Status: experimental, 0.97.0. Verified board/CPU/device combinations are listed
in [COMPATIBILITY.md](COMPATIBILITY.md); building, deploying into OpenCore and
setting boot-args are covered below.

## Boot arguments

Two build variants exist and accept different boot-args:

- **Production** (default): `sh tools/build/probe.sh` → `build-m1a/AMDMapperProbe.kext`.
  Compiles the six production translation units only.
- **Debug**: `sh tools/build/probe-debug.sh` → `build-m1a-debug/AMDMapperProbe.kext`.
  Adds `kext/*Debug.cpp` and `-DAMD_MAPPER_PROBE_DEBUG=1`, restoring the retired
  M2 experiment modes. See "Retired M2 experiment modes" below.

### Production build

| Argument | Values | Meaning |
|---|---|---|
| `amdiommu=<mode>` | `passive` | Auto-attach off: keeps the R54–R67 offer/claim handshake; clients must call `AMDIOMMUClaimRequesterV1`. |
| | `auto-attach` | Publishes `iommu-parent` at first publish for selected requesters, so Apple's own Ethernet kexts (which only call `IOMapper::copyMapperForDevice()`) get the mapper. |
| | absent / any other value (incl. `off`) | Inert: no notifier, no device arm, no MMIO. `off` is not a recognised value — it simply matches no mode. |
| `amdiommu_devices=<ids>` | 1–16 four-hex-digit requester IDs, e.g. `n2200,n2201` or `n2300,n2301` | Selects PCI requesters (segment zero). **Prefix each ID with a non-hex character (`n`)**: this kernel's `PE_parse_boot_argn` rewrites an all-digit value into a 32-bit integer in the caller's buffer (`3400` arrived as `0x0D48`). The parser skips non-hex bytes before reading four hex digits. Omit to fall back to the identity list in the kext's `Info.plist` (`AMDMapperProbeDevices`, see below). |
| `amdiommu_profile=<name>` | `rl-10g-max` | Growth ceiling, and the default: 65535 records / 262144 pages (1 GiB), 516 table pages. |
| | `rl-10g` | Ceiling at 16384 records / 131072 pages (512 MiB), 260 table pages. |
| | `native-legacy` | Ceiling at the accepted ABI3 window (1024 records / 16 MiB): growth is disabled. |
| | unknown name | Widen nothing: growth is disabled and `r44-profile-ceiling=unsupported-name` is recorded. |

`amdiommu_profile` names the **ceiling**, not the arena a domain is prepared
with. Every domain is prepared at `native-legacy` and may grow **exactly once**,
at its first mapping, to that ceiling:

- the growth point is the first `iovmMapMemory` call that passes validation —
  before any PTE is published and while the DTE is still a passthrough entry, so
  nothing live has to be preserved or invalidated;
- after the first activation capacity is frozen for the reason R69 §6.3 gave for
  forbidding a runtime resize: a live domain must never change the meaning of an
  address a client is already using;
- a failed growth keeps the prepared arena and publishes `iommu-growth-state`; it
  never fails the mapping.

The per-device identity table did not go away, but it is advisory now: it is the
admission ceiling and the record of what identity-based sizing *would* have
chosen. A missing entry can no longer leave a real client with 16 MiB, because
the arena starts there and grows from actual demand.

| Derived from | Matches | Suggested ceiling |
|---|---|---|
| vendor/device table | `15b3:1015/1017/1019/101b/101d`, `10ec:8124-8127` | `rl-10g-max` |
| PCI class fallback | base class `0x02` (network) | `rl-10g-max` |
| PCI class fallback | base class `0x01` (storage) | `rl-10g` |
| otherwise | — | `native-legacy` |

The suggestion is published per device as `iommu-profile-suggested` with
`iommu-profile-source` = `boot-arg` \| `id-table` \| `class-table` \|
`legacy-fallback`. A claim-based client (Lucy, the board RTL8111) keeps the
accepted ABI3 arena: its ceiling stays `native-legacy` unless an operator raises
it explicitly. `amdiommu_autoattach` was removed — `amdiommu=auto-attach` is the
only switch.

Growth evidence, per device: `iommu-profile-prepared` (`native-legacy`),
`iommu-profile-ceiling`, `iommu-profile-ceiling-source` (`boot-arg` | `default`),
`iommu-growth-policy` (`first-map` | `disabled`), `iommu-capacity-grown`
(`no` | `yes` | `no-growth-failed`), `iommu-profile-grown-from`,
`mapper-map-window-bytes`, plus `iommu-growth-state`/`iommu-growth-time` in the mapper
snapshot (`iommu-growth-state` is `grown`, `not-needed`, `closed-live` or one of
the `failed-*` reasons).

Published properties no longer carry round prefixes. The release surface uses
semantic families: `iommu-*` (mode, state, controller/domain hardware evidence,
profile and growth), `discovery-*` (IVRS/PCI discovery facts), `mapper-*`
(per-device mapper statistics and raw dumps), `invalidation-*` (invalidation
counters), `pm-*` (suspend/resume), `dma-*` (DMA park gate), plus standalone
keys such as `probe-stage`, `publish-notifier`, `device-selection`,
`snapshot-domains` and `admission`.

Current example (ConnectX-4 Lx). No profile argument is needed because
the arena now follows demand:

```
amdiommu=auto-attach amdiommu_devices=n2300,n2301
```

### Default device selection from Info.plist

When `amdiommu_devices` is omitted, the kext matches devices by identity against
the `AMDMapperProbeDevices` value inside its own `Info.plist` personality
(`IOKitPersonalities/AMDMapperProbe`). The value uses the **`IOPCIMatch`
format**: whitespace-separated `0xVVVVDDDD` words, each optionally followed by
`&0xMMMMMMMM`; `VVVV` is the PCI vendor, `DDDD` the device, compared as
`(device << 16 | vendor) & mask`. The personality dictionary becomes the driver
instance's property table, so the kext reads it with `getProperty()`.

The checked-in list is the verified adapter set:

- Mellanox CX4 Lx family driven by Apple's MLX5 client:
  `0x101515b3 0x101715b3 0x101915b3 0x101b15b3 0x101d15b3`
- Realtek range driven by Apple's Ethernet Realtek driver:
  `0x812410ec 0x812510ec 0x812610ec 0x812710ec`

Everything outside this list keeps physical (pass-through) DMA. Identity
matching does not define offer slots, so `claim` is only honoured for
boot-arg-selected requesters; a plist-matched device attaches at first publish
in `auto-attach` mode and without a claim in `passive` mode, exactly like the
former hardcoded RTL8127 default.

### Retired M2 experiment modes (Debug build only)

Available only with `AMD_MAPPER_PROBE_DEBUG=1`. The parsers live in
`kext/AMDMapperProbeDebug.hpp`; the implementations live in `kext/*Debug.cpp`.

| Argument | Values | Meaning |
|---|---|---|
| `amdiommu=<mode>` | `arm`, `mmio`, `write`, `table`, `enable`, `cmd` | Progressive M2 hardware-enablement gates (B2-b arming, MMIO read, MMIO write, device table, short enable window, command channel). Each is an independent, individually revertible switch. |
| | `pgt`, `pgt4k`, `pgthold`, `pgtsleep`, `pgt3l` | M2-2b-2 page-table translation experiments (4-level identity table, 4 KiB leaves, 20 s held-translation window, sleep-only control, 3-level table). `pgt` is a prefix match, so `pgt4k` also opens the main gate. |
| | `.batch<N>`, `.t0x<N>` / `.token<N>`, `.std`, `.alltx`, `.rxstd`, `.session` | Suffixes inside the same `amdiommu=` value, e.g. `amdiommu=pgt.batch512.t0x2a.std.alltx.rxstd.session`. The parser scans every `.key` segment; a separate trailing boot-arg is not a dependable channel on this kernel. |
| `m2b2delay=<seconds>` | 1–300 | Delay before the one-shot M2-2b-2 page-table probe (default 20000 ms). |

## Compatibility

Which PCIe devices have actually run through this mapper, on which board and
CPU, and with which driver: see [COMPATIBILITY.md](COMPATIBILITY.md). That table
lists only combinations verified on hardware, and only where the endpoint is
driven by a driver shipped with macOS; unverified boards and third-party driver
stacks are out of scope.

## Install location (target machine)

The kext that actually runs is NOT installed in `/Library/Extensions` and is not
part of the auxiliary kernel collection. It is deployed into the **OpenCore
directory on the target machine's EFI system partition** and injected at boot:

- Bundle: `<EFI system partition>/EFI/OC/Kexts/AMDMapperProbe.kext`
- Enabled via `Kernel > Add` (`BundlePath = AMDMapperProbe.kext`) in the OC
  `config.plist` on the same partition.

Deploying a new build therefore means copying `build-m1a/AMDMapperProbe.kext`
(or the debug variant) over that bundle and rebooting; the partition number of
the EFI system partition varies, resolve it on the machine instead of hardcoding
it. `build-m1a/` and `build-m1a-debug/` are build outputs only; they are not
installed anywhere until copied to the ESP.

## Source and evidence policy

- `kext/`, `tools/` are canonical implementation and generator inputs. `include/`, `src/`, `tests/`, `fixtures/`, `reference/` contain existing modules, tests and reference inputs.
- `generated/round26/` is the historical generated Lucy inspection/reproducibility copy; do not edit it by hand.
- Runtime evidence, kext binaries, SDKs, upstream tarballs and full patch-package before/after snapshots are not committed.

Every future patch must name the full base commit and target this repository. Verify the expected working tree and use `git apply --check` before applying a patch. Never overwrite local changes or edit the baseline to force acceptance. Source identity in evidence is a Git commit hash, not a source snapshot. Logs, raw exports, binary identities and experiment results remain separate from provenance; repository commits do not constitute hardware validation.
