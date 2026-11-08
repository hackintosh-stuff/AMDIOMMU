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
records, page-table bytes and their physical segment descriptors together;
`PublishAuto()` then takes the shared
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
- Read `mapper-state-raw`, `mapper-live-raw`, `mapper-page-table-raw` and
  `mapper-page-table-segments-raw` from the same ABI5 snapshot. The segment
  descriptors are necessary to follow physical pointers between table blocks.
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

`amdiommu_profile` selects the growth ceiling (see README for the values).
Auto-attach defaults to `dma32-max`: 131072 records and 524288 IOVA pages
(2 GiB). The window is `[0x80000000, 0x100000000)`, entirely usable by 32-bit
DMA clients. Explicit `native-legacy`, `rl-10g` and `rl-10g-max` selections
retain their existing limits.

Allocated storage and usable capacity both start at `native-legacy`. A record-slot
allocation failure doubles only the record capacity; an IOVA allocation failure
doubles only the page capacity. Each resource is capped independently by the
selected ceiling, and the mapper retries the request after growth. A first
mapping that fits does not grow the domain.

- `iommu-profile-suggested` records the device-based suggestion;
  `iommu-profile-source` says where it came from: `boot-arg`, `id-table`,
  `class-table` or `legacy-fallback`. The configured ceiling is the growth limit;
  it is not a startup memory reservation.
- A claim-based client (Lucy, the board RTL8111) keeps the `native-legacy`
  ceiling unless an operator raises it explicitly.
- `amdiommu_autoattach` no longer exists; `amdiommu=auto-attach` is the switch
  for publishing `iommu-parent` at first publish.

| Growth evidence key | Values / meaning |
|---|---|
| `iommu-profile` | Display label on the device mapper / PCI device: a named profile when both capacities match it exactly, otherwise `dynamic` |
| `iommu-profile-prepared` | `native-legacy`, the initial usable capacity |
| `iommu-profile-allocated` | Display label for the currently allocated usable capacity; numeric records/pages are authoritative |
| `iommu-profile-ceiling` | Selected ceiling, or `unsupported-name` for an invalid request |
| `iommu-profile-ceiling-source` | `boot-arg` \| `default` |
| `iommu-profile-records`, `iommu-profile-pages` | Current usable limits |
| `iommu-profile-table-pages`, `iommu-table-bytes` | Actual allocated page-table size; includes added leaf tables and the second L2 directory |
| `mapper-record-storage-bytes` | Allocated bytes for mapping records and their liveness bitmap; changes only with record capacity |
| `mapper-page-storage-bytes` | Sum of allocated page-metadata chunk bytes: physical-page index, start-page owner index, leaf pointers and allocator bitmaps |
| `mapper-page-storage-chunks` | Number of retained page-metadata chunks; starts at one and increases once per successful page-capacity growth, up to eight |
| `mapper-arena-bytes` | Record allocation plus all page-metadata chunks, each rounded to 4 KiB; excludes page tables, fixed mapper state and its allocation descriptors |
| `iommu-growth-policy` | `capacity-demand` \| `disabled` |
| `iommu-capacity-grown` | Whether at least one capacity increase succeeded |
| `iommu-growth-count` | Total successful increases; the sum of record and page growth counts |
| `iommu-record-growth-count` | Successful increases of the record-slot capacity |
| `iommu-page-growth-count` | Successful increases of the IOVA page capacity |
| `iommu-growth-resource` | Resource changed by the most recent successful increase: `records`, `iova-pages`, or `none` before growth |
| `iommu-growth-from-records`, `iommu-growth-from-pages` | Numeric capacities before the most recent successful increase; zero before growth |
| `iommu-profile-grown-from` | Display label before the most recent successful increase; use the numeric growth-from fields to distinguish `dynamic` capacities |
| `mapper-map-window-bytes` | Current usable IOVA window in bytes |
| `iommu-growth-state` | `prepared`, `grown`, `at-ceiling`, `metadata-limit`, `failed-record-storage`, `failed-page-storage`, `failed-tables`, `failed-page-tables` or `failed-synchronization` |
| `iommu-growth-time` | Time of the most recent successful increase, or zero |

Capacity decisions are published on the mapper and PCI device after releasing
the mapper lock, so growth count, state and limits do not require a snapshot
request. The mapper snapshot also includes count, state and time. `at-ceiling`
means the resource needed by an allocation has reached its configured ceiling;
the other resource may still have room to grow. A freed slot or range may still
satisfy a later mapping. `metadata-limit` identifies the combined 64 MiB
metadata guard; `failed-record-storage` and `failed-page-storage` identify
which allocation could not be obtained.

`mapper-rejects-records` and `mapper-rejects-no-range` count requests that still
failed after growth/retry, not allocation pressure that growth resolved. Raw
snapshot `capacityMaps` / `capacityPages` describe usable limits. `rootPA` stays
fixed, while `ptBytes` / `tablePages` describe the current total of allocated table
blocks. Record-only growth keeps these table values and the segment count
unchanged, and requires no hardware invalidation. IOVA capacity grows from
16 to 32, 64, 128, 256, 512, 1024 and 2048 MiB; the corresponding allocated
table-page counts are 16, 24, 40, 72, 136, 264, 520 and 1033. The corresponding
segment counts are 1, 2, 3, 5, 9, 17, 33 and 66. Each page-table allocation is
limited to 16 pages (64 KiB), so one capacity increase can add multiple
segments. `iommu-page-growth-count` counts capacity increases; the segment
count describes the number of allocated blocks.

The last page-capacity increase adds 513 pages across 33 blocks: one L2
directory and 512 leaf tables. All blocks are allocated before any new PDE is
attached. Once the child tables are prepared, the new directory is linked
through the original L3 entry 3; the original L3 entry 2, its existing subtree
and the root PA stay intact.
At the 2 GiB ceiling there are 66 segments, 4231168 allocated table bytes
and 1028 reachable table pages. The `dma32-max` profile's 1028-page budget
describes construction in one contiguous block; incremental allocation owns
1033 pages because it retains the initial block's five spare pages. Registry
and snapshot table sizes report the actual 1033-page allocation.

Record growth copies records and their liveness bitmap into a replacement
allocation, releasing the old record allocation after commit. Page growth
appends metadata for only the added range; existing page indexes, owner indexes,
leaf-pointer arrays and bitmap storage keep their addresses and contents.
The record allocation stays in place during page growth. A single allocator
uses global IOVA-page indexes across all chunks, preserving live, peak and reuse
counts and allowing a mapping to cross a metadata-chunk boundary.

The initial metadata chunk covers 4096 IOVA pages; subsequent chunks cover
4096, 8192, 16384, 32768, 65536, 131072 and 262144 pages. The new chunk is
staged before attaching hardware tables and is appended to usable storage only
after capacity growth commits. Retained page-metadata chunks are released
with the mapper. The record allocation and every page chunk are independently
rounded to 4 KiB, so check `mapper-arena-bytes` against record bytes plus the
sum of all page chunks:

| Records / IOVA pages | Record storage bytes | Page metadata chunks | Page storage bytes | Total metadata bytes |
|---|---:|---:|---:|---:|
| 1024 / 4096 | 126976 | 1 | 53248 | 180224 |
| 1024 / 8192 | 126976 | 2 | 106496 | 233472 |
| 1024 / 16384 | 126976 | 3 | 208896 | 335872 |
| 131072 / 524288 | 15745024 | 8 | 6451200 | 22196224 |

`mapper-page-storage-chunks` is distinct from the page-table segment count.
With 128 MiB of IOVA capacity there are four metadata chunks and five table
segments; at 2 GiB there are eight metadata chunks and 66 table segments.

The internal start-page owner index is 32-bit, so the record capacity can pass
65535 without truncating an owner. It accounts for four bytes per IOVA page in
the page-storage allocation. Exported `recordIndex` and capacity fields are
32-bit as well; ABI5 and the Snapshot/Record byte layouts are unchanged.

New PDEs always require a full invalidation including the PDE cache on an active
domain, even when `iommu-np-cache` is zero. A page-capacity increase performs
this once, after attaching all its blocks and before exposing the added range.
Read `invalidation-full-completed` with the page-growth count when checking
this path; record growth does not add a full invalidation. Capacity is retained
after mappings are released, so use the growth counters and published capacity
instead of inferring the growth history from the current live-map or live-page
count.

## Segmented page-table snapshots

ABI5 retains a 4544-byte Snapshot and 2152-byte Record. The live-record layout is
unchanged; the version identifies the new page-table export convention:

| Export | Contents |
|---|---|
| `mapper-state-raw` | Snapshot; `ptBytes` is the sum of all allocated table-block sizes |
| `mapper-live-raw` | `liveCount` mapping records |
| `mapper-page-table-raw` | Complete table blocks concatenated in allocation order |
| `mapper-page-table-segments-raw` | One 24-byte little-endian `<QQQ` descriptor per block: physical base, byte offset in the concatenated blob, byte size |

To read a table at physical address `pa`, find its segment and read at
`offset + pa - physicalBase`. Subtracting `rootPA` from every table pointer is
only valid for the older contiguous ABI4 export. The four ABI5 blobs are captured
under the same mapper lock and belong to one `mapper-snapshot-sequence`.
An added segment can contain an L2 directory as well as leaf tables, so resolve
physical addresses through the segment descriptors at every level of the walk.
Blocks are listed in allocation order; their physical addresses need not be
adjacent or increasing. The descriptor's byte size gives each block's actual
allocation size, including a shorter final block when needed.

PM boundaries also retain their own `pm-suspend-pt-segments-raw` and
`pm-resume-pt-segments-raw` alongside the existing table/live blobs.
`pm-snapshots-valid=yes` requires both sets of segment descriptors. Decode a saved
boundary with its saved descriptors, not with the current domain's later layout.

After requesting a fresh snapshot with the helper described above, save and
inspect the registry export:

```sh
sudo /tmp/probe-snapshot
ioreg -a -l -w0 -r -c org_maz1_AMDMapperProbe > /tmp/mapper-snapshot.plist
python3 tools/dev/inspect-mapper-snapshot.py /tmp/mapper-snapshot.plist
```

The inspector reads ABI4 and ABI5, follows every reachable table through the
appropriate physical-address map and compares all present PTEs with the complete
live mapping set. Its JSON report gives each mapper's sequence, numeric
capacities, allocated bytes, segment count and verified IOVA pages. It also
reports `record_storage_bytes`, `page_storage_bytes`, `page_storage_chunks`,
`record_growth_count`, `page_growth_count`, `growth_resource`,
`grown_from_records` and `grown_from_pages`; these are `null` for older captures
that do not publish the corresponding properties. Use this snapshot check
alongside the normal traffic check. The old claim analyzer's fixed 16 MiB
capacity assertions remain scoped to its archived workload.

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
