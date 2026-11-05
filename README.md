# AMDIOMMU — authoritative source repository

## Boot arguments

Two build variants exist and accept different boot-args:

- **Production** (default): `sh tools/build-m1a.sh` → `build-m1a/AMDMapperProbe.kext`.
  Compiles the six production translation units only.
- **Debug**: `sh tools/build-m1a-debug.sh` → `build-m1a-debug/AMDMapperProbe.kext`.
  Adds `kext/*Debug.cpp` and `-DAMD_MAPPER_PROBE_DEBUG=1`, restoring the retired
  M2 experiment modes. See "Retired M2 experiment modes" below.

### Production build

| Argument | Values | Meaning |
|---|---|---|
| `amdiommu=<mode>` | `auto` | Auto-attach off: keeps the R54–R67 offer/claim handshake; clients must call `AMDIOMMUClaimRequesterV1`. |
| | `auto-attach` | Publishes `iommu-parent` at first publish for selected requesters, so Apple's own Ethernet kexts (which only call `IOMapper::copyMapperForDevice()`) get the mapper. |
| | absent / any other value (incl. `off`) | Inert: no notifier, no device arm, no MMIO. `off` is not a recognised value — it simply matches no mode. |
| `amdiommu_devices=<ids>` | 1–3 four-hex-digit requester IDs, e.g. `n2200,n2201` or `n2300,n2301` | Selects PCI requesters (segment zero). **Prefix each ID with a non-hex character (`n`)**: this kernel's `PE_parse_boot_argn` rewrites an all-digit value into a 32-bit integer in the caller's buffer (`3400` arrived as `0x0D48`). The parser skips non-hex bytes before reading four hex digits. Omit for the legacy RTL8127 default. |
| `amdiommu_profile=<name>` | `native-legacy` | Accepted ABI3 window (1024 records / 16 MiB). Default. |
| | `rl-10g` | 16384 records / 131072 pages, 260 table pages. |
| | `rl-10g-max` | 65535 records / 262144 pages (1 GiB), 516 table pages. |
| | unknown name | Does **not** widen the arena: falls back to legacy and records `r44-profile=unsupported-name`. |

When omitted, `amdiommu_profile` is derived per device (`r44ProfileForDevice`);
a forced name applies to every attached device. `amdiommu_autoattach` was
removed — `amdiommu=auto-attach` is the only switch.

Current example (CX4 Lx on this machine):

```
amdiommu=auto-attach amdiommu_devices=n2300,n2301 amdiommu_profile=rl-10g-max
```

`serial=5`, `io=0xffffffff`, `debug=` and `-v` are XNU/OpenCore arguments, **not**
parsed by this kext.

### Retired M2 experiment modes (Debug build only)

Available only with `AMD_MAPPER_PROBE_DEBUG=1`. The parsers live in
`kext/AMDMapperProbeDebug.hpp`; the implementations live in `kext/*Debug.cpp`.

| Argument | Values | Meaning |
|---|---|---|
| `amdiommu=<mode>` | `arm`, `mmio`, `write`, `table`, `enable`, `cmd` | Progressive M2 hardware-enablement gates (B2-b arming, MMIO read, MMIO write, device table, short enable window, command channel). Each is an independent, individually revertible switch. |
| | `pgt`, `pgt4k`, `pgthold`, `pgtsleep`, `pgt3l` | M2-2b-2 page-table translation experiments (4-level identity table, 4 KiB leaves, 20 s held-translation window, sleep-only control, 3-level table). `pgt` is a prefix match, so `pgt4k` also opens the main gate. |
| | `.batch<N>`, `.t0x<N>` / `.token<N>`, `.std`, `.alltx`, `.rxstd`, `.session` | Suffixes inside the same `amdiommu=` value, e.g. `amdiommu=pgt.batch512.t0x2a.std.alltx.rxstd.session`. The parser scans every `.key` segment; a separate trailing boot-arg is not a dependable channel on this kernel. |
| `m2b2delay=<seconds>` | 1–300 | Delay before the one-shot M2-2b-2 page-table probe (default 20000 ms). |

## Source and evidence policy

- `kext/`, `tools/` are canonical implementation and generator inputs. `include/`, `src/`, `tests/`, `fixtures/`, `reference/` contain existing modules, tests and reference inputs.
- `generated/round26/` is the historical generated Lucy inspection/reproducibility copy; do not edit it by hand.
- Runtime evidence, kext binaries, SDKs, upstream tarballs and full patch-package before/after snapshots are not committed.

Every future patch must name the full base commit and target this repository. Verify the expected working tree and use `git apply --check` before applying a patch. Never overwrite local changes or edit the baseline to force acceptance. Source identity in evidence is a Git commit hash, not a source snapshot. Logs, raw exports, binary identities and experiment results remain separate from provenance; repository commits do not constitute hardware validation.
