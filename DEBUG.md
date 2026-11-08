# Implementation and debugging reference

Build, configuration examples and OpenCore installation are in
[README.md](README.md). This document describes implementation behavior,
configuration internals, capacity accounting and diagnostic evidence.

- [Production configuration](#production-configuration) and [device selection](#device-selection)
- [Profile and growth evidence](#profile-and-growth-evidence)
- [Runtime IOVA allocation](#runtime-iova-allocation)
- [IORegistry snapshots](#reading-ioregistry-properties)
- [Segmented page-table snapshots](#segmented-page-table-snapshots)
- [Production integration validation](#production-integration-validation)
- [Release build configuration](#release-build-configuration)
- [Power management](#power-management) and [hook diagnostics](#hook-diagnostics)
- [Debug build experiment modes](#debug-build-experiment-modes)

## Production configuration

The production kext discovers the AMD IOMMU through the ACPI IVRS table and PCI
configuration. It takes over the controller after the state and feature
registers agree, then prepares a translation domain for each selected requester.

| Argument | Values | Meaning |
|---|---|---|
| `amdiommu=<mode>` | `passive` | Auto-attach is off; explicit clients use the offer/claim handshake and call `AMDIOMMUClaimRequesterV1`. |
| | `auto-attach` | Publishes `iommu-parent` at first publish, so clients using `IOMapper::copyMapperForDevice()` get the mapper. The offer is also published, allowing claim-based clients to receive a definite answer rather than `kIOReturnNotReady`. |
| | absent / any other value, including `off` | Inert: no notifier, device arm or MMIO. `off` is not a recognised mode; it matches no mode. |
| `amdiommu_devices=<ids>` | Four hexadecimal requester-ID digits prefixed with `n`, for example `n2200,n2201` or `n2300,n2301` | Selects segment-zero requesters. If omitted, selection comes from `AMDMapperProbeDevices` in the kext's `Info.plist`. |
| `amdiommu_ceiling=<name>` | See [Profile ceilings](#profile-ceilings) | Selects the independent record and IOVA-page growth limits. |
| `amdiommu_pm=off` | `off` | Disables registration for self-driven sleep/wake notifications. DMA-path repair of a controller that lost its register image remains available. With the argument absent, notifications are registered. |

### Device selection

Prefix each requester ID with a non-hex character such as `n`.
`PE_parse_boot_argn` converts an all-digit boot-arg value into a 32-bit integer
inside the caller's buffer (`3400` arrived as `0x0D48`). `ReadDeviceSelection()`
skips non-hex bytes before parsing each four-digit hexadecimal ID.

When `amdiommu_devices` is absent, the kext reads `AMDMapperProbeDevices` from its
`Info.plist` personality (`IOKitPersonalities/AMDMapperProbe`). The value uses
`IOPCIMatch` format: whitespace-separated `0xDDDDVVVV` words, optionally followed
by `&0xMMMMMMMM`. `VVVV` is the PCI vendor and `DDDD` the device; comparison is
`((device << 16 | vendor) & mask) == (id & mask)`. The personality dictionary becomes
the instance property table, so the implementation reads it with `getProperty()`.

The checked-in adapter list is:

- Mellanox CX4 Lx family driven by Apple's MLX5 client:
  `0x101515b3 0x101715b3 0x101915b3 0x101b15b3 0x101d15b3`.
- Realtek range driven by Apple's Ethernet Realtek driver:
  `0x812410ec 0x812510ec 0x812610ec 0x812710ec`.

The two selection sources are never merged. An explicit `amdiommu_devices`
value is the sole selection; otherwise the identity list is used. Devices
outside the selected set retain physical pass-through DMA. Selected devices
publish an offer in both production modes, allowing a claim-based client to
receive a definite answer even when auto-attach has already supplied its mapper.

## Reading IORegistry properties

`AMDMapperProbe` publishes its state as IORegistry properties on the controller
(`org_maz1_AMDMapperProbe`) and on each per-device mapper instance. Most of them
are **snapshots, not live counters**: `setProperty()` copies a value at one
moment, and the kernel-side state can change afterwards without changing what
`ioreg` shows. Refresh before drawing any conclusion from a value.

### Two kinds of property

| Kind | Examples | Published by | Freshness |
|---|---|---|---|
| Snapshot keys | `iommu-dte-active`, `iommu-state`, `mapper-map-ok`, `mapper-live-maps`, `pm-*` sequences, `invalidation-*` | `PublishMappings()` and `PublishAuto()` | Only at the moments listed below |
| `-live` keys | `mapper-map-ok-live`, `mapper-live-maps-live`, `mapper-live-pages-live`, `mapper-rejects-*` | `PublishCapacity()` | Approximate; throttled, and never contain hardware state |
| Hook keys | `hook-state`, `hook-open`, `hook-open-routed`, `hook-routed`, `hook-attach-ok`, `hook-last-requester` | `AMDMapperHook.kext` | Written when the event happens |

The hook is a separate kext and does not use the snapshot protocol. Its counters
can be read directly; the probe's cannot.

### Why the probe publishes on demand

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

### When a snapshot is published

| Trigger | What is refreshed |
|---|---|
| A device is attached (`AttachAuto`, before `iommu-parent` is set) | That domain. `d->active` is still false, so `iommu-dte-active=no` and all map counters are zero |
| `setProperties({"RefreshSnapshot": true})` | Per-device instances publish their own snapshot; the controller publishes every domain |
| `setProperties({"R44All": true})` | Controller-level `PublishDomains()` |
| Sleep/wake transitions | `PublishPMNow()` and `PublishPMBoundary()`; without these, PM sequences and timestamps would keep their prepare-time zeros while a wake is being judged |
| Device quiesce / stop | A final snapshot |
| Capacity growth | Its own keys are written immediately, because a capacity change must not wait for a reader |

The attach-time snapshot is the usual source of confusion: a device may have
been doing translated DMA for a long time while `ioreg` still shows
`iommu-dte-active=no` and `mapper-map-ok=0`.

### Refresh and read

`tools/dev/probe-snapshot.c` sends `RefreshSnapshot` to every instance:

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

### Reading rules

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

### Property families

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

### Profile ceilings

`amdiommu_ceiling` selects the growth ceiling, not a startup reservation.

| Name | Record ceiling | IOVA-page ceiling | IOVA capacity | Selection |
|---|---:|---:|---|---|
| `dma32-max` | 131072 | 524288 | 2 GiB | Default for auto-attach |
| `rl-10g-max` | 65535 | 262144 | 1 GiB | Explicit smaller ceiling |
| `rl-10g` | 16384 | 131072 | 512 MiB | Explicit smaller ceiling |
| `native-legacy` | 1024 | 4096 | 16 MiB | Growth disabled; default for claim-based clients |

An unknown profile name disables growth and publishes
`iommu-profile-ceiling=unsupported-name`. The full `dma32-max` window is
`[0x80000000, 0x100000000)`, entirely usable by 32-bit DMA clients.

### Growth policy and profile suggestions

Allocated storage and usable capacity both start at `native-legacy`. A record-slot
allocation failure doubles only the record capacity; an IOVA allocation failure
doubles only the page capacity. Each resource is capped independently by the
selected ceiling, and the mapper retries the request under the mapper lock after
growth. A first mapping that fits does not grow the domain, and existing mappings
can remain live throughout growth. Record capacity advances from 1024 through
2048, 4096, 8192, 16384, 32768 and 65536 to 131072; an explicit smaller ceiling
clips the final increase.

At the exhausted resource's ceiling, a request that cannot fit returns
`kIOReturnNoResources`. Allocation failure retains the existing mappings and
capacity. If hardware synchronization fails, the existing failed-domain state
closes new mapping admission. Growth that satisfies the request is not a capacity
rejection.

- `iommu-profile-suggested` records the device-based suggestion;
  `iommu-profile-source` says where it came from: `boot-arg`, `id-table`,
  `class-table` or `legacy-fallback`. The configured ceiling is the growth limit;
  it is not a startup memory reservation.
- A claim-based client (Lucy, the board RTL8111) keeps the `native-legacy`
  ceiling unless an operator raises it explicitly.
- `amdiommu_autoattach` no longer exists; `amdiommu=auto-attach` is the switch
  for publishing `iommu-parent` at first publish.

The device identity table records the ceiling it would suggest independently of
the default `dma32-max` ceiling or an explicit operator selection:

| Derived from | Matches | Suggested ceiling |
|---|---|---|
| vendor/device table | `15b3:1015/1017/1019/101b/101d`, `10ec:8124-8127` | `rl-10g-max` |
| PCI class fallback | base class `0x02` (network) | `rl-10g-max` |
| PCI class fallback | base class `0x01` (storage) | `rl-10g` |
| otherwise | — | `native-legacy` |

### Growth properties

| Growth evidence key | Values / meaning |
|---|---|
| `iommu-profile` | Display label on the device mapper / PCI device: a named profile when both capacities match it exactly, otherwise `dynamic` |
| `iommu-profile-prepared` | `native-legacy`, the initial usable capacity |
| `iommu-profile-allocated` | Display label for the currently allocated usable capacity; numeric records/pages are authoritative |
| `iommu-profile-ceiling` | Selected ceiling, or `unsupported-name` for an invalid request |
| `iommu-profile-ceiling-source` | `boot-arg` \| `default` |
| `iommu-profile-records`, `iommu-profile-pages` | Current usable limits |
| `iommu-profile-table-pages`, `iommu-table-bytes` | Actual allocated page-table size; includes added leaf tables and the second L2 directory |
| `mapper-record-storage-bytes` | Sum of allocated record-metadata chunk bytes: mapping records and their liveness bitmaps |
| `mapper-record-storage-chunks` | Number of retained record-metadata chunks; starts at one and increases once per successful record-capacity growth, up to eight |
| `mapper-page-storage-bytes` | Sum of allocated page-metadata chunk bytes: physical-page index, start-page owner index, leaf pointers and allocator bitmaps |
| `mapper-page-storage-chunks` | Number of retained page-metadata chunks; starts at one and increases once per successful page-capacity growth, up to eight |
| `mapper-arena-bytes` | Sum of all record- and page-metadata chunks, each rounded to 4 KiB; excludes page tables, fixed mapper state and its allocation descriptors |
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
snapshot `capacityMaps` / `capacityPages` describe usable limits.

### Hardware page-table growth

`rootPA` stays fixed, while `ptBytes` / `tablePages` describe the current total of
allocated table blocks. Record-only growth keeps these values and the segment
count unchanged, and requires no hardware invalidation. IOVA capacity follows
this sequence:

| IOVA capacity | IOVA pages | Allocated table pages | Table bytes | Table segments |
|---|---:|---:|---:|---:|
| 16 MiB | 4096 | 16 | 65536 | 1 |
| 32 MiB | 8192 | 24 | 98304 | 2 |
| 64 MiB | 16384 | 40 | 163840 | 3 |
| 128 MiB | 32768 | 72 | 294912 | 5 |
| 256 MiB | 65536 | 136 | 557056 | 9 |
| 512 MiB | 131072 | 264 | 1081344 | 17 |
| 1 GiB | 262144 | 520 | 2129920 | 33 |
| 2 GiB | 524288 | 1033 | 4231168 | 66 |

Each page-table allocation contains at most 16 pages (64 KiB) of physically
contiguous storage. Blocks can be placed independently; a capacity increase
can add several segments. `iommu-page-growth-count` counts capacity increases,
whereas the segment count describes allocated blocks.

The last page-capacity increase adds 513 pages across 33 blocks: one L2
directory and 512 leaf tables. All blocks are allocated before any new PDE is
attached. Once the child tables are prepared, the new directory is linked
through the original L3 entry 3; the original L3 entry 2, its existing subtree
and the root PA stay intact. The DTE root remains unchanged.
At the 2 GiB ceiling there are 66 segments, 4231168 allocated table bytes
and 1028 reachable table pages. The `dma32-max` profile's 1028-page budget
describes construction in one contiguous block; incremental allocation owns
1033 pages because it retains the initial block's five spare pages. Registry
and snapshot table sizes report the actual 1033-page allocation.

### Metadata chunks and memory accounting

Record and page growth each append metadata for only the added range. Existing
mapping objects, record liveness bitmaps, page indexes, owner indexes,
leaf-pointer arrays and page bitmaps keep their addresses and contents. Neither
resource copies or replaces its existing chunks. Global record indexes and
liveness searches span all record chunks. A single allocator uses global
IOVA-page indexes across all page chunks, preserving live, peak and reuse counts
and allowing a mapping to cross a page-metadata chunk boundary.

The initial record chunk covers 1024 slots; subsequent chunks cover 1024, 2048,
4096, 8192, 16384, 32768 and 65536 slots, capped at the selected ceiling. Record
growth allocates and clears only the added chunk, then appends it after the
capacity decision commits. Existing page metadata, allocator state and hardware
tables stay in place. For the explicit 65535-record ceiling, the final chunk
covers 32767 slots.

The initial page chunk covers 4096 IOVA pages; subsequent chunks cover
4096, 8192, 16384, 32768, 65536, 131072 and 262144 pages. The new chunk is
staged before attaching hardware tables and is appended to usable storage only
after capacity growth commits. All retained metadata chunks are released with
the mapper. Every record and page chunk is independently rounded to 4 KiB, so
check `mapper-arena-bytes` against the sum of all chunks of both resources:

| Records / IOVA pages | Record chunks | Record storage bytes | Page chunks | Page storage bytes | Total metadata bytes |
|---|---:|---:|---:|---:|---:|
| 1024 / 4096 | 1 | 126976 | 1 | 53248 | 180224 |
| 2048 / 4096 | 2 | 253952 | 1 | 53248 | 307200 |
| 1024 / 8192 | 1 | 126976 | 2 | 106496 | 233472 |
| 1024 / 16384 | 1 | 126976 | 3 | 208896 | 335872 |
| 131072 / 524288 | 8 | 15765504 | 8 | 6451200 | 22216704 |

The initial domain uses 180224 metadata bytes and 65536 table bytes:
**245760 bytes, about 0.234 MiB**. A domain with 1024 records and a 64 MiB IOVA
window uses 335872 metadata bytes plus 163840 table bytes:
**499712 bytes, about 0.477 MiB**. Extending that window from 32 to 64 MiB
allocates only the new page chunk's 102400 metadata bytes. Record growth from
1024 to 2048 slots adds one 126976-byte chunk and retains the original chunk.
The complete `dma32-max` capacity uses 22216704 metadata bytes and 4231168 table
bytes.

These totals exclude fixed mapper state, which includes eight record-chunk
descriptors, eight page-chunk descriptors and 66 table-allocation descriptors
(the table descriptor array occupies 2112 bytes). Reported metadata bytes are
the sum of the independently rounded allocations, not the size of this fixed
state.

Starting from legacy capacity, `mapper-record-storage-chunks` equals one plus
the record-growth count, and `mapper-page-storage-chunks` equals one plus the
page-growth count. These describe independent software allocations and are
distinct from the page-table segment count. With 128 MiB of IOVA capacity there
are four page-metadata chunks and five table segments; at 2 GiB there are eight
page-metadata chunks and 66 table segments. Record growth adds no table segments.

The internal start-page owner index is 32-bit, so the record capacity can pass
65535 without truncating an owner. It accounts for four bytes per IOVA page in
the page-storage allocation. Exported `recordIndex` and capacity fields are
32-bit as well; ABI5 and the Snapshot/Record byte layouts are unchanged.

### Growth synchronization

New PDEs always require a full invalidation including the PDE cache on an active
domain, even when `iommu-np-cache` is zero. A page-capacity increase performs
this once, after attaching all its blocks and before exposing the added range.
Read `invalidation-full-completed` with the page-growth count when checking
this path; record growth does not add a full invalidation. Ordinary maps retain
the NP-cache optimization when filling an already prepared leaf. Capacity is retained
after mappings are released, so use the growth counters and published capacity
instead of inferring the growth history from the current live-map or live-page
count.

## Runtime IOVA allocation

The runtime allocator preserves first-fit placement, alignment and conflict
skip rules. `freePageSearchStart` is a conservative starting page: every page
before it is occupied, but the starting page itself may also be occupied. The
search skips only that known occupied prefix, so it still returns the same
lowest fitting range as a search from zero.

After a successful allocation, the start advances to the end of the allocated
range if that range begins at the first free page found. If alignment or a range
conflict skipped a lower free hole, the start remains at that first free page.
The allocator does not scan the occupied suffix after committing a range.
Failed allocations leave the start unchanged; successful release lowers it to
the released range's beginning when necessary. Initialization sets it to zero,
and appending page metadata retains it while extending `poolPages`. This also
keeps a free tail in an old chunk available for a mapping that spans new pages.

Once a range is selected, the allocator updates `used` and
`ever` with one mask per covered 64-bit bitmap word. The mask covers only the
requested pages in the first and last words; all intervening words are updated
as full words. Each bitmap view lookup resolves a global word through the
retained page-metadata chunks.

Release first checks every covered word to confirm that the whole range is
allocated. Only after that check passes does it clear the corresponding `used`
bits. It retains `ever` so later allocations still report reuse. `livePages`
changes by the requested page count, `peakPages` keeps its existing meaning,
and `reusedAllocations` increases once when any page in an allocation was used
before. The search start is internal allocator state; it adds no metadata
allocation, IORegistry property or snapshot ABI field. Capacity limits and the
append-only growth policy are unchanged.

A 256-page range covers four bitmap words when word-aligned, or five when it
starts within a word. This reduces repeated bitmap indexing and chunk lookup;
it is an operation-count change, not a measured throughput or latency result.
The compile-time `BoundedAllocator` retains its separate per-page implementation
as the reference for the existing host equivalence test.

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
reports `record_storage_bytes`, `record_storage_chunks`, `page_storage_bytes`,
`page_storage_chunks`, `record_growth_count`, `page_growth_count`, `growth_resource`,
`grown_from_records` and `grown_from_pages`; these are `null` for older captures
that do not publish the corresponding properties. Use this snapshot check
alongside the normal traffic check. The old claim analyzer's fixed 16 MiB
capacity assertions remain scoped to its archived workload.

## Production integration validation

Validate a complete candidate through the production build and its selected
attachment mode. Dynamic capacity is used by the existing mapper; it does not
require enabling the inactive `AMDIdentityMapper` scaffold or registering a
system-wide mapper. For the normal auto-attach configuration, keep the device
selection and capacity ceiling in place and run the following as one batch on
the same deployed build.

Run `tools/test.sh`, `tools/build/build-probe.sh` and `tools/verify/source.py`
once for the candidate. The host tests cover independent record/page growth,
retained metadata, large owners, cross-chunk ranges, the full table-growth
sequence and allocator equivalence. Reuse that evidence across the hardware
phases instead of rebuilding or rebooting for each scenario.

| Phase | Normal workload | Evidence |
|---|---|---|
| Attachment | Boot the candidate and inventory every selected requester and its driver/interface | Loaded build identity, active DTEs, fresh baseline snapshot |
| Per-link traffic | Send and receive on each connected test link, with one flow and with multiple flows | Completed transfers, interface-specific byte progress, fresh snapshot after each link's group |
| Concurrent traffic | Run both available links together, including simultaneous transmit and receive | Continued progress on both links, target fault and invalidation counters, snapshot while traffic is active |
| Mapping reuse | Stop and restart the normal traffic workload several times | Mapping/unmapping progress, retained capacity, consistent live PTEs |
| Link recovery | Bring each test interface down/up once when another management path is available, then repeat traffic | Link returns and data transfers complete with the same deployed mapper |
| Final state | Stop test traffic, allow the normal workload to settle, then capture again | All mapper snapshots validate, roots remain stable within the boot, no growing unreclaimed mapping set |

Bind traffic to the intended local interface/address and use controlled peers;
otherwise a passing transfer can exercise another NIC. An existing traffic tool
or a file transfer with source/destination hashes is sufficient. Record a missing
peer or disconnected link as unavailable and continue the other phases. A ping
is a reachability check, not a substitute for sustained send/receive work.

Request `RefreshSnapshot` at phase boundaries and inspect each capture with
`tools/dev/inspect-mapper-snapshot.py`. Compare fresh baseline and final counters
for each requester, including mapping rejections, invalidation failures and
target IOMMU events. Check the independent live-record/PTE comparison for every
mapper, not only the traffic-generating one. Do not require live-map counts to
return to zero while network drivers retain their normal DMA rings.

A passing batch supports integration for the tested attachment mode and device
combination. High capacity paths exercised only by the host tests remain marked
as host coverage; forcing a 2 GiB allocation, changing the initial capacity or
injecting failures is not required for this normal-workload decision. Active
hook routing and sleep/wake are separate capabilities: hook standby in
auto-attach does not validate routing, and an adapter/driver combination already
listed as unsuitable for sleep must not make this batch depend on S3. Keep those
coverage limits with the integration result rather than starting another
allocator micro-optimization cycle.

## Power management

The mapper handles system sleep and wake itself, so a real S3 reaches it without
a client RPC. `amdiommu_pm=off` disables those notifications;
`RequestPowerTransition` remains the compatibility entry for a client that drives PM
itself. Translation hardware stops only when no requester still holds a live
mapping. The DMA path repairs a controller that has lost its register image.

Sleep/wake cycles have run with translation active, with one domain and with
four: registers restored, no resume failures and no target faults. Published
state includes `pm-self-driven`, `pm-controller-state`, suspend/resume counts,
`pm-resume-registers-restored`, `pm-suspend-retained`, `pm-lazy-restores` and
`pm-resume-failures`. Refresh the snapshot before interpreting these values.
Acceptance criteria remain in the requirements document.

## Hook diagnostics

`AMDMapperHook.kext` supplies the mapper before driver startup when a selected
client neither performs the claim handshake nor obtains a mapper through
auto-attach. In `amdiommu=auto-attach`, the mapper is already published and the
hook stands by. Selection still comes from the probe's explicit requester list
or default identity list; the hook does not add devices.

The `AMDMapperHook` IORegistry node reports `hook-state=installed` when ready.
The `hook-*` counters indicate whether it intervened. `hook-open`,
`hook-open-routed` and `hook-routed` report use of the open-time claim and
`copyMapperForDevice` fallback paths. Hook properties are event-driven and can be read
directly, separately from the probe's on-demand snapshots. Loading and disabling
the companion are described in [README.md](README.md#amdmapperhook-optional-companion).

## Release build configuration

`tools/build/build-probe.sh` builds the deployable kext from the six production
translation units at `-O2 -g`, with `-Wall -Wextra -Werror`.
`tools/build/build-probe-debug.sh` sets `PROBE_DEBUG=1`: it keeps `-O0 -g` and
adds the retired `probe/*Debug.cpp` experiment modules plus
`-DAMD_MAPPER_PROBE_DEBUG=1`. Debug symbols stay in both variants so panic
traces and postmortem inspection remain usable; stripping them is a separate
decision.

`PROBE_OPT_LEVEL` overrides the optimization level for either variant, for
example `PROBE_OPT_LEVEL=-O0 sh tools/build/build-probe.sh`. It changes only the
compiler flag: the source list, feature set, bundle path and build record are
unchanged. This produces a production-feature `-O0` binary for a like-for-like
comparison with the optimized build. The Debug kext is not a valid
optimization-only control, because it adds experiment translation units and
accepts historical `amdiommu=` modes.

The build prints its optimization level, writes the bundle path to
`latest-m1a-build.txt` (or `latest-m1a-debug-build.txt`) and ad-hoc signs the
kext. Record the source commit and the SHA-256 of
`Contents/MacOS/AMDMapperProbe` for every deployed binary; the ESP copy and the
build output must match. The optimization level does not change capacity
mechanics, snapshot ABI5, device selection, the ceiling or the auto-attach path.

The optional Lilu plugin has its own entry, `tools/build/build-hook.sh`. Its
sources are `hook/AMDMapperHook.cpp` and `hook/Info.plist`, read from
`<repo>/hook` by default; the optional first argument still selects another
source directory. The output path `build-hook/AMDMapperHook.kext` and the
OpenCore installation steps in [README.md](README.md#build) are unchanged.

### Release validation and observations

Validate an optimized binary with the existing entries (`tools/test.sh`,
`tools/build/build-probe.sh`, `tools/verify/source.py`) and one full
[production integration batch](#production-integration-validation): one deploy,
one reboot, the same per-link single/multi-flow, concurrent, file-integrity,
start/stop, link-recovery and final short-traffic phases, with grouped
`RefreshSnapshot` captures read by the current ABI5 inspector. Fresh baseline and
final counters must show no new target faults, capacity rejections or
invalidation failures.

For an optimization comparison, keep the same links, directions, stream counts,
durations, tool and peer, and compare completed bytes, throughput and CPU
observations against the deployed `-O0` build of the same source. Report measured
values only and do not promise a speedup. The traffic tool or the peer can be the
bottleneck, and unchanged throughput does not by itself show an optimization was
ineffective. CPU samples are comparable only when both sides were collected
under the same conditions.

## Debug build experiment modes

The production build compiles the six production translation units. The Debug
build adds `probe/*Debug.cpp` and `-DAMD_MAPPER_PROBE_DEBUG=1`, restoring the
retired M2 experiment modes below. The parsers are in
`probe/AMDMapperProbeDebug.hpp`; implementations are in `probe/*Debug.cpp`.
Build commands and bundle paths are listed in [README.md](README.md#build).
Optimization levels are described in
[Release build configuration](#release-build-configuration).

| Argument | Values | Meaning |
|---|---|---|
| `amdiommu=<mode>` | `arm`, `mmio`, `write`, `table`, `enable`, `cmd` | Progressive M2 hardware-enablement gates: arming, MMIO read, MMIO write, device table, short enable window and command channel. Each is an independent, individually revertible switch. |
| | `pgt`, `pgt4k`, `pgthold`, `pgtsleep`, `pgt3l` | M2 page-table translation experiments: four-level identity table, 4 KiB leaves, a 20-second held-translation window, sleep-only control and a three-level table. `pgt` is a prefix match, so `pgt4k` also opens the main gate. |
| | `.batch<N>`, `.t0x<N>` / `.token<N>`, `.std`, `.alltx`, `.rxstd`, `.session` | Suffixes in the same `amdiommu=` value, for example `amdiommu=pgt.batch512.t0x2a.std.alltx.rxstd.session`. The parser scans each `.key` segment; a separate trailing boot-arg is not a dependable channel on this kernel. |
| `m2b2delay=<seconds>` | 1–300 | Delay before the one-shot page-table probe; default 20000 ms. |

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
