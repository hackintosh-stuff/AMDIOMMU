# Reading IORegistry properties

`AMDMapperProbe` publishes its state as IORegistry properties on the controller
(`org_maz1_AMDMapperProbe`) and on each per-device mapper instance. Most of them
are **snapshots, not live counters**: `setProperty()` copies a value at one
moment, and the kernel-side state can change afterwards without changing what
`ioreg` shows. Refresh before drawing any conclusion from a value.

## Two kinds of property

| Kind | Examples | Published by | Freshness |
|---|---|---|---|
| Snapshot keys | `iommu-dte-active`, `iommu-state`, `mapper-map-ok`, `mapper-live-maps`, `pm-*` sequences, `invalidation-*` | `PublishMappings()` and `PublishAuto()` | Only at the moments listed below |
| `-live` keys | `mapper-map-ok-live`, `mapper-live-maps-live`, `mapper-live-pages-live`, `mapper-rejects-*` | `PublishCapacity()` | Approximate; throttled, and never contain hardware state |
| Hook keys | `hook-state`, `hook-open`, `hook-open-routed`, `hook-routed`, `hook-attach-ok`, `hook-last-requester` | `AMDMapperHook.kext` | Written when the event happens |

The hook is a separate kext and does not use the snapshot protocol. Its counters
can be read directly; the probe's cannot.

## Why the probe publishes on demand

The DMA path runs under the per-device mapper lock, once per map and unmap. It
only updates in-memory structures: `Domain::active` and `activeTime` are set at
the first mapping, `MapperState` counters are incremented, and a few values are
mirrored into `fMapOk` / `fLiveMaps` for the live publisher. Writing an
IORegistry property allocates objects and can block, so it must not happen in
that critical section.

A snapshot is also meant to be *one consistent picture*. `PublishMappings()`
holds the mapper lock while exporting the summary struct, the live mapping
records and the page-table bytes together; `PublishAuto()` then takes the shared
controller lock, consumes the IOMMU event log head and reads the control
register. Those reads have hardware side effects. Publishing each key whenever
its own value changes would both stall the DMA path and produce a set of values
from different instants. The controller declares this as
`snapshot-consistency = per-domain`.

Even the live publisher is throttled: it writes only when a peak/reject value
changes, the live map counts change, or 128 further map/unmap calls have
accumulated. It runs outside the lock, at the end of `MapMemory`. `UnmapMemory`
does not call it, so `-live` keys are not a substitute for a snapshot.

## When a snapshot is published

| Trigger | What is refreshed |
|---|---|
| A device is attached (`AttachAuto`, before `iommu-parent` is set) | That domain. `d->active` is still false, so `iommu-dte-active=no` and all map counters are zero |
| `setProperties({"R44Snapshot": true})` | Per-device instances publish their own snapshot; the controller publishes every domain |
| `setProperties({"R44All": true})` | Controller-level `PublishDomains()` |
| Sleep/wake transitions | `PublishPMNow()` and `PublishPMBoundary()`; without these, PM sequences and timestamps would keep their prepare-time zeros while a wake is being judged |
| Device quiesce / stop | A final snapshot |
| Capacity growth | Its own keys are written immediately, because a capacity change must not wait for a reader |

The attach-time snapshot is the usual source of confusion: a device may have
been doing translated DMA for a long time while `ioreg` still shows
`iommu-dte-active=no` and `mapper-map-ok=0`.

## Refresh and read

`tools/dev/probe-snapshot.c` sends `R44Snapshot` to every instance:

```sh
clang -framework IOKit -framework CoreFoundation \
    -o /tmp/probe-snapshot tools/dev/probe-snapshot.c
sudo /tmp/probe-snapshot

ioreg -w0 -l -p IOService -n AMDMapperDevice -r
ioreg -w0 -l -p IOService -n AMDMapperHook -r
```

The tool prints one line per instance with the result of `setProperties`. A
successful poke increments `mapper-snapshot-sequence`; compare that value before
and after if you need to prove a fresh snapshot landed. It changes nothing else
on the machine and does not require a reboot.

## Reading rules

- `iommu-dte-active=no` means "not active at the last publication", **not**
  "translation is off". The DTE is activated by the first map; refresh first.
- `mapper-map-ok=0` or zeroed `invalidation-*` / `pm-*` sequences are the same
  trap. Zero after a refresh is meaningful; zero before one is not.
- `mapper-live-maps` and `mapper-live-pages` are the ring/buffer set still
  mapped, not a leak indicator. Compare two snapshots: stable counts across
  interface down/up cycles mean the resources were rebuilt cleanly; a count that
  only grows with idle time is the thing to investigate.
- Read `mapper-state-raw`, `mapper-live-raw` and `mapper-page-table-raw` from the
  same snapshot. Their lengths and the ABI version are published alongside them.
- `iommu-event-overflow=no` and `iommu-event-valid=yes` describe the event log as
  of the last snapshot; a fault that happened just now may not be visible yet.
- Acceptance checks in tests and design notes that say
  "`iommu-dte-active=yes`" always mean **after a snapshot has been pulled**.

## Property families

Property names are grouped by meaning; no release property carries a round
prefix.

| Family | Covers |
|---|---|
| `iommu-*` | Mode, state, controller/domain hardware evidence, profile and growth |
| `discovery-*` | IVRS / PCI discovery facts |
| `mapper-*` | Per-device mapper statistics and raw dumps |
| `invalidation-*` | Invalidation counters |
| `pm-*` | Suspend/resume |
| `dma-*` | DMA park gate |

Standalone keys include `probe-stage`, `publish-notifier`, `device-selection`,
`snapshot-domains` and `admission`. `snapshot-domains` is the array of
per-domain dictionaries produced by a controller-level publication.

## Profile and growth evidence

`amdiommu_profile` selects the growth ceiling (see README for the values and the
one-shot growth rule). The decision and its outcome are published per device:

- `iommu-profile-suggested` carries the suggested ceiling; `iommu-profile-source`
  says where it came from: `boot-arg`, `id-table`, `class-table` or
  `legacy-fallback`. The vendor/device identity table is advisory — it is the
  admission ceiling and the record of what identity-based sizing would have
  chosen. A missing entry cannot leave a real client at 16 MiB, because every
  arena starts at `native-legacy` and grows from actual demand.
- A claim-based client (Lucy, the board RTL8111) keeps the accepted ABI3 arena:
  its ceiling stays `native-legacy` unless an operator raises it explicitly.
- `amdiommu_autoattach` no longer exists; `amdiommu=auto-attach` is the only
  switch for publishing `iommu-parent` at first publish.

| Growth evidence key | Values / meaning |
|---|---|
| `iommu-profile-prepared` | `native-legacy`, the arena every domain is prepared with |
| `iommu-profile-ceiling` | The selected ceiling |
| `iommu-profile-ceiling-source` | `boot-arg` \| `default` |
| `iommu-growth-policy` | `first-map` \| `disabled` |
| `iommu-capacity-grown` | `no` \| `yes` — written at attach, at the capacity swap and in the mapper snapshot |
| `iommu-profile-grown-from` | The profile the domain grew from |
| `mapper-map-window-bytes` | Size of the mapping window in bytes |
| `iommu-growth-state`, `iommu-growth-time` | Published with the mapper snapshot. State is `prepared`, `grown`, `not-needed`, `closed-live`, `failed-tables`, `failed-state`, `failed-arena` or `unknown` |

Capacity growth also writes `iommu-capacity-grown` and `iommu-growth-state`
directly at the swap, so those two do not depend on a snapshot request.

## Key reference

The keys most often needed when diagnosing:

| Key | Meaning |
|---|---|
| `iommu-mode`, `iommu-role` | Which variant and which object (`controller` / `device`) |
| `iommu-state` | `ready-passthrough` → `active` → `pm-resume-ready` |
| `iommu-dte-active`, `iommu-dte-active-time` | Whether the first map activated the DTE, and when |
| `iommu-parent-policy` | `set-at-first-publish-autoattach`, `set-on-client-claim-before-pci-open`, or `set-before-driver-start` — which path put the mapper in place |
| `device-selection`, `device-selection-count` | Which list is in force. `plist-missing`, `plist-parse-failed` and `plist-too-many-entries` all mean the selection is empty |
| `amdiommu-dma-policy` | `mapped` / `selected` / `passthrough` / `failed` on the PCI device |
| `mapper-map-ok`, `mapper-unmap-ok`, `mapper-map-rejected`, `mapper-unmap-rejected` | Aggregate mapping outcomes |
| `invalidation-device-completed`, `invalidation-full-completed` | Confirmed device/full invalidations |
| `pm-resume-ready`, `pm-resume-registers-restored`, `pm-snapshots-valid`, `pm-controller-failures` | Wake repair outcome |
| `snapshot-domains` | Array of per-domain dictionaries from the controller-level publication |
| `hook-open`, `hook-open-routed`, `hook-routed` | Whether the hook used the open-time claim path or its copyMapperForDevice fallback |

`device-selection` is worth checking first when nothing was mapped: an empty or
unparsable list is a deliberate no-device state, not a failure of the mapper.
