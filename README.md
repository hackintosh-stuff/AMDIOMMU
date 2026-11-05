# AMDIOMMU — authoritative source repository

## Round70 / capacity model: S1+S2 implemented, S3 measurement boot — BLOCKED (hang, no panic)

Base: `1fa228e` (R69 evidence archive). S1 `7aa457c` turns the ordinary
mapper's fixed arena into a profile-sized one (`native-legacy` keeps the
accepted ABI3 numbers byte for byte; `rl-10g` = 16384 records / 512 MiB;
`rl-10g-max` = 65535 records / 1 GiB for the measurement boot) and frees the
page-table area from `kR44TablePages`. S2 `eafb8ba` admits capacity per device
before the domain exists: only `10ec:8124–8127` on the auto-attach path takes a
pool-sized profile, everything else keeps ABI3; a refusal writes
`r69-admission=refused-*` on the device and leaves it on passthrough instead of
returning `NoResources` later. `1a3bd86` proves the runtime allocator is
indistinguishable from the compile-time one over 20,000 operations and pins the
arena arithmetic; `93cb810` adds the ceiling profile, the peak counters and
`tools/r70/measure.py`. Probe 0.78.0 builds clean; `R70_CAPACITY_OK`.

**Measured.** The first three measurement boots (0.78.0, then 0.79.0 twice)
panicked with the R69 signature
`"rl:34:0:0:0:tx: segment prepare error 0xe00002be"` at uptime
**52.0 / 61.8 / 63.2 s** and halted instead of rebooting, so each recovery
needed a manual power cycle into the Debian OCRESCUE environment. Live readback
21 s into the second boot gave the cause: the controller instance reported
`r44-profile=rl-10g-max`, the parent was published and both domains were built,
yet both `10ec:8127` devices carried `r69-admission=granted-native-legacy`.
`r44AttachAuto` gives every device its own mapper instance, and admission
consulted a member flag that instance never received, so the domains were built
with the legacy 16 MiB arena. Fix `afb6021` (0.80.0) resolves
`amdiommu_profile` on every admission and publishes `r44-attach-forced`; `5f7a7c5`
(0.81.0) publishes the capacity counters when they change; `e6b1bf7`/`31b66eb`
(0.82.0) read live IOVA pages from the allocator instead of the stale snapshot.

On the fixed build (`rl-10g-max`, 65535 records / 1 GiB, 516-page tables) both
domains reported `granted-rl-10g-max` with zero faults. A 2 GB single flow on
en4 (1 GbE, 18.5 s, ~930 Mb/s) produced peak **279 concurrent mappings and
4419 IOVA pages (~17.3 MiB)**, which alone exceeds the legacy 4096-page bound
and explains the three panics. After the SFP+ link came up, the same probe was
measured against a TrueNAS peer on en2: 1 GB in 0.927 s (~8.9 Gbps) and three
2 GB transfers at ~9.3 Gbps each gave peak **3267 concurrent mappings and
52,227 IOVA pages (~204 MiB)**, zero rejects and zero target faults. That makes
the 512 MiB profile only 2.5x on pages, so the Apple-RL default moved to
`rl-10g-max` (20x records, 5.0x pages) in `6b0643c`, with `rl-10g` retained as
the fallback step and `native-legacy` unchanged for Lucy/RTL8111. Not measured:
concurrent multi-flow 10 GbE, the AVB path, and sustained 10 GbE business.
Closure: probe ejected from the ESP, EFI and NVRAM back to `amdiommu=off`.

## Round69 / AppleEthernetRL on the AMD mapper — BLOCKED, panic preserved

Base: `bcb3d662f57ab8dbc330067ba7ac30f88925db88` (accepted R67-2). R69 adds
`tools/r69/` and three Probe-only commits (`2062018`, `bdc370d`, `4adf62e`);
no DMA mapper, page table, invalidation or NIC driver source was changed.

**Not accepted.** The interface analysis is sound and the publication
ordering was fixed: Apple's Ethernet kexts only call
`IOMapper::copyMapperForDevice()` and can never invoke the
`AMDIOMMUClaimRequesterV1` handshake, so `amdiommu=auto-attach` now builds the
domain and publishes `iommu-parent` at first publish
(`r44-parent=set-at-first-publish-autoattach`, `r52-domain-count=2`). Getting
the probe ahead of the client also required OpenCore `Kernel > Add`
injection: from the AuxKC it started ~14 s into boot, after
`AppleEthernetRL` had already cached a NULL mapper, and `r44-map-ok` stayed 0.

The blocker is a hard panic. Three boots died 57–78 s after start with
`"rl:34:0:0:0:tx: segment prepare error 0xe00002be"` at
`IOSkywalkPacketBufferPool.cpp:677`, raised from
`prepareMemorySegment` via `segmentConstructor` → `skmem_region_alloc` →
`pp_create` → `pp_alloc_packet_by_size` → `nx_netif_host_output` →
`dlil_output`. `0xe00002be` is `kIOReturnNoResources`, returned by
`r44MapMemory()` when the 1024 mapping records or the 16 MiB per-domain IOVA
pool are exhausted; a 10 GbE Skywalk packet pool reaches that within a minute.
`IOSkywalkFamily` treats the code as unrecoverable and panics, whereas
AppleVTD can always hand out an IOVA from a 48-bit space. This is a capacity
contract gap, not a transient fault.

Containment ran from the Debian rescue environment: the three panic reports
were copied out over a read-only APFS mount, then the OpenCore `Kernel > Add`
entry and the ESP kext copy were removed, and boot-args reduced to
`amdiommu=off`. The 15 SimpleAERL patches stay (unrelated). macOS is back up
with `amdiommu=off`, no probe loaded, and `AppleEthernetRL (1.0.0d1)` driving
both RTL8127 ports past the old threshold. `RTL812xLucy.kext` and
`AMDMapperProbe.kext` were moved out of `/Library/Extensions` to
`/Users/ling/r69-hold/`, so the accepted R67-2 topology is **not** restored by
this round.

Three design constraints carry into the next round: decide capacity
**before** claiming a device and fall back to passthrough instead of failing
at runtime; never return `kIOReturnNoResources` to a third-party client; and
measure the real RTL8127 Skywalk pool size before choosing an ABI4 capacity.

## Accepted Round67-2 / dual RTL8127 post-wake sustained traffic, one wake lineage

Base: `40fae03007b49dbc5b29418f71635d8d732b1665` (blocked R67 record). R67-2
adds only `tools/r67_2/`; no kext was rebuilt, deployed or re-signed — the
accepted Probe 0.74.0 and Lucy 1.1.241 binaries were adopted verbatim
(`adopt` preserves source-ref/expected-version/deployment from the R66-2
capture). The selector moved to the two 10ec:8127 devices: nic_a =
22:00.0/0x2200/en4 (down target), nic_b = 25:00.0/0x2500/en2; the board
RTL8111 is outside the selector and untouched.

**Accepted.** One documented selector boot; on that boot: the ordinary
96 MiB five-phase regression passed 4/4 (dual-Lucy independent domain trees,
8x128-page RX each, permissions 11→00→11, zero faults); one real system
sleep/wake completed (GPIO-503 wake, `system_sleep_wakes` 0/None→1, boottime
unchanged, controller suspend/resume once with zero failures, per-domain
fence CWs 12766…12771, retained live/PT hashes equal, both NICs back to
link-up, disarm clean); the 300 s four-stream sustained run then delivered
49.98 GB with every block dual-end SHA256-verified, reconnections 0, watchdog
restarts 0, faults 0; and the post-wake 96 MiB reciprocal down/up passed
4/4. The overall five-check analysis (wake origin, same restored domains,
persistent streams, post-wake down/up, continuous-to-lifecycle evidence
chain) is ok and the independent recompute is byte-identical. Two analyzer
fixes were made (`c7f284c` cross-process monotonic ordering replaced by
domain-counter ordering; `193bb18` finish reseals without stale analysis
outputs). Closure: next boot `amdiommu=off amdiommu_devices=2200,2500`,
SleepDisabled=1, finite jobs removed, peers exited, both NICs active, no
extra reboot. This proves the dual-RTL8127 scenario on one wake lineage
only; the RTL8111 sustained-load blocker from R67 stands, and no claim is
made beyond this topology.

## Round67 / sustained post-wake traffic — BLOCKED, failure evidence preserved

Base: `a4778b12411cca8d96ea2dae5bedf4d78afaf966` (accepted R66-2). R67 adds
only `tools/r67/`; no kext was rebuilt or replaced. `prepare` attached to the
accepted R66-2 wake boot without build/deploy/reboot/sleep (identities,
PM counts 1/1, armed=no, faults 0 verified; identity-start/provenance kept
the original binary provenance).

**Not accepted.** The 300 s four-stream sustained run tripped the zero-fault
gate: the RTL8111 TX-stall watchdog fired twice under sustained load and
although the R66-2 mapped-mode restart path completed both times
(`restart-count=2`, `restart-error=0`, `pm-state=restart-complete`), each
restart produced exactly one A-domain IOMMU target fault at `0x80004000`
(the fixed tally-mapping region; flags 0x20500001). Controller faults went
0 → 2. Peer B (Lucy) was flawless for the whole window — 5360 verified
blocks, 33.85 GB up + 11.11 GB down, no unverified data; peer A broke after
6 verified blocks (broken pipe, no auto-reconnect by design). Accounting
stayed clean: ~3.065M controller commands, A map/unmap 13581/13546 (delta 35
= persistent maps, no leak). The down/up lifecycle phase was not run. No
reboot, no selective rerun, no relaxed criterion; faults=2 remain recorded
live, both NICs active, PM disarmed, SleepDisabled=1 and next-boot
`amdiommu=off` untouched. The fix belongs to a driver-side round (tally
DMA timing inside the restart path); the sustained-load gap does not
invalidate the R66-2 PM cycle or the ordinary-phase results.

## Accepted Round66-2 / real dual-driver coordinated PM cycle

Base: `971198f2f4053057b9a5740f24a75c5add0cf470` (blocked R66 record). R66-2
unblocks the R66 failure: RealtekRTL8111 3.0.56 now carries real PM hooks
(sleep action fences the mapper via R47PowerTransition(1) after the ordinary
disable/TX reclaim/RX rebuild and only then enters D3; wake action does D0,
then R47PowerTransition(2), and only unblocks DMA start after success; the
initial D0 is not a fake wake and PM callbacks never call enable()). The
mapped-mode TX-watchdog restart reuses the disable/enable path with MSI
event quiescing and refuses to restart a down or PM-blocked interface. The
second domain's resume only commits its invalidations once the shared
controller is genuinely restored, per-domain PM fence sequences/counts are
exported so PM invalidations stay out of the ordinary map/unmap accounting,
and `tools/r66_2/pm.py` arms/captures/analyzes/disarms with participant
capability checks.

**Accepted.** Only AMDMapperProbe 0.74.0 (`D5282356-…`) and RealtekRTL8111
3.0.56 (`9DC6859E-…`) were rebuilt; Lucy 1.1.241 retained. After two
documented recovery boots (off, then auto — R66's powerFailed controller and
downed NICs cleared) the candidate boot passed the ordinary regression 4/4
with identical recompute: 12 transfers / 96 MiB dual hashes, A enable 1→1→2
and chip 12→0→12, both requesters 11→00→11, `r66_2-restart-count=0`, zero
faults. One controlled real sleep then ran inside that boot: armed,
`pmset sleepnow` 08:51:10, GPIO-503 wake 08:52:23 (`Total Sleep/Wakes since
boot :1`, boottime moved only by the ~1s post-wake RTC correction — the PM
analyzer now tolerates that drift and treats a pre-sleep missing counter as
0, commit `cf0a58a`, recomputed offline). PM analysis 4/4: controller
suspend/resume exactly once with zero failures and restored registers; the
completion chain B suspend 11571 < A suspend 11606 < A resume-dev 11607 <
11608 < B resume-dev 11609 < 11610; per-domain suspend/resume live-raw and
pt-raw hashes equal across the boundary; both drivers unblocked and back to
`link-up`; target faults zero throughout. `disarm` succeeded (armed=no).
SleepDisabled restored, finite job removed, next boot `amdiommu=off`, EFI
unmounted, no extra reboot. This is the first hardware-validated
dual-driver coordinated PM cycle; the sustained post-wake business for the
dual-RTL8127 topology was delivered separately in R67-2.

## Accepted Round68 / restore the ordinary dual-NIC lifecycle

Base: `a7d09010133560fd5f6a2779a3c45a4321a25994` (blocked R65 record).
Dual-domain system PM is paused: `r52PowerSupported()` returns false for two
domains, single-domain R47 behavior and the coordinated code are retained,
and `R65ArmSystemPM` is removed. Only AMDMapperProbe was rebuilt (0.72.0,
`70075D9F-4FFA-3810-9ED0-770046782296`); Lucy 1.1.241 and RTL8111 3.0.55
were retained. The runner reuses R64's five-phase flow with
`pm_boot_wake=False` — no enable-count or fault checks were relaxed.

**Accepted: all four mainline checks passed on the real Mac on the first auto
boot.** The R65 blocker is gone: A's enable-count is 1 → 1 → 2 with one
enable per ifup, chip-command 12 → 0 → 12, and controller/per-domain target
faults are zero in every phase (including 0x2700). Both requesters still
park and restore independently: A 11 → 00 → 11 (park CW 4730/4731,
restore 7522/7523), B 11 → 00 → 11 (park 9181/9182, restore 10611/10612).
The 96 MiB / 12-transfer reciprocal workload kept both down windows busy
with dual hashes, shared commands closed at 1167 → 7518 → 9158 → 10609 →
12190, exact range coverage held (A 32457/32457, B 37421/37421), the ring
cached 10975 of 11023 batches with 48 refreshes and 48 wraps, and map/unmap
closed at A 5421/5386 and B 6803/6792. Real system sleep/wake was validated
later by R66-2; ordinary down/up is not a sleep/wake test.

## Accepted Round64 / both NICs independently revoke and restore requester DMA access

Base: `e0f5ef93f8a665c9597c3989a9c8e92a34a9709d` (accepted R63). Only
RTL812xLucy was rebuilt (1.1.241, `6F935499-FCC0-3A8A-96E7-3CE0B1D647C8`);
AMDMapperProbe 0.70.0 (`27269764-…`) and RealtekRTL8111 3.0.55
(`DFBA1B95-…`) were retained. The Lucy client now calls the R63 requester
DMA lifecycle: restore after opening the PCI provider but before hardware
bring-up, park only after stopping hardware and `clearRxTxRings()`, with
failures blocking enable or returned from disable. The 8 x 128-page RX
groups, TX mappings and R47/R63 PM code are unchanged. Probe DTE, page
tables, command ring and invalidation core were not rebuilt or modified.

**Accepted: all four mainline checks passed on the real Mac on one planned
auto boot.** Five-phase readback: A 1/1 → 0/0 at its down snapshot
(park CW 3886/3887), back to 1/1 after up (restore CW 6848/6849); B stayed
1/1 through A's cycle, went 0/0 at its own down (park CW 8490/8491) and
back to 1/1 after up (restore CW 9973/9974). Each requester's park and
restore has its own new device and domain CompletionWait; the other domain
kept transferring through both down windows (96 MiB / 12 transfers, dual
hashes, zero target faults). Exact range coverage held (A 32692/32692,
B 35452/35452), the ring cached 10162 of 10206 batches with 44 refreshes
and 44 wraps, and map/unmap closed at A 5350/5315, B 5731/5720. Two offline
fixes were needed before acceptance: a Python 3.9 generator incompatibility
and an impossible analyzer expectation for cumulative transition counts;
the first failing analysis is preserved and R63 re-analysis still matches.
Deployed binary corresponds to `361b5c1`; later implementation commits
(`42d458d`, `1761255`) touch only the shared analyzer. PM remains
TODO(R47-PM-HARDWARE); ordinary interface down/up is not a sleep/wake test.

## Accepted Round63 / revoke one requester's DMA permission while its NIC is down

Base: `4309a75855f67957284ec71909378b72fa132a05` (accepted R62; deployed `833e7bd`).
R62 completed 11,291 batches in the measured window, refreshing the hardware
HEAD 48 times. Both NICs recovered, but both device-table entries kept
read and write permission even in their disabled snapshots.

The updated RTL8111 client now asks its own mapper to clear the DTE read
and write bits after stopping the NIC and rebuilding its RX rings. Keep
the live page tables, domain ID and mapping owners. Reject new maps while
parked; allow teardown of existing mappings. Before re-enabling the NIC,
restore the DTE permissions. Both operations must finish a device-entry
invalidation and a full-domain page invalidation before reporting success.
If the restore cannot be confirmed the client closes its PCI provider and
does not enable DMA. Lucy does not opt into the new callback.

Build AMDMapperProbe 0.70.0 and RealtekRTL8111 3.0.55; retain Lucy 1.1.240.
The existing 96 MiB two-device exercise now reads the DTE permission bits,
the two completion sequences for each transition, and the surviving domain's
traffic.

**Accepted: all four mainline checks passed on the real Mac (second auto boot;
the first died mid-first-upload as a boot-time link transient, run preserved).**
The deployed implementation is `afafc8b`; AMDMapperProbe 0.70.0
(`27269764-68AB-3C0F-A9B3-3B57BCE5280F`) and RealtekRTL8111 3.0.55
(`DFBA1B95-3F09-3070-A56F-E4CCCA3D2752`) were replaced, retaining Lucy
1.1.240 (`43C9BD33-…`). Five-phase `requesterAccess` readback: A went
ir/iw 1/1 → 0/0 at its down snapshot with parks=1, deviceCW/pagesCW
3799/3800; after up it returned to 1/1 with restores=1 and a fresh
4813/4814 completion pair. B stayed 1/1 with parks/restores=0 through both
its own down/up and A's. The 96 MiB reciprocal workload kept both down
windows busy, shared commands closed at 960 → 4812 → 6455 → 7953 → 9066,
exact coverage held (A 32837/32837, B 34234/34234), the ring cached 8069 of
8106 batches with 37 refreshes and 37 wraps, A ended 5637/5602 and B
3467/3456 map/unmap, and target faults stayed zero. PM remains
TODO(R47-PM-HARDWARE).

## Accepted Round62 / cache the shared command ring's observed HEAD

Base: `e4d61d84ae08e38ab79dce8330cc4f6aaca0b7fe` (accepted R61; deployed `e236625`). Its first auto boot
completed twelve transfers / 96 MiB. Both domains submitted real split
invalidations: 2,820 split batches cumulatively; 73,471 requested pages
matched 73,471 pages of encoded coverage. From before to b-after-up the
shared ring completed 11,194 batches and wrapped 50 times.

Use the last validated value read from the hardware HEAD register to
reserve an entire batch plus its CompletionWait. The serialized producer
cannot cross the reserved empty slot, so an old HEAD is conservative.
Refresh from hardware when the known space is insufficient. Invalidate
the cached position if the hardware ring is initialized again. Completion
and IOVA retirement still depend on the hardware semaphore.

Build only AMDMapperProbe 0.69.0; retain Lucy 1.1.240 and RTL8111 3.0.54.
The existing reciprocal test now reports successful cached reservations,
actual MMIO HEAD reads and wraps over the same five-phase workload.

**Accepted: all four mainline checks passed on the real Mac on the first auto
boot.** The deployed implementation is `833e7bd`; only AMDMapperProbe was
rebuilt (0.69.0, `776ECAFF-F168-3B5E-BA3F-D3280A2428A7`), retaining Lucy
1.1.240 (`43C9BD33-…`) and RealtekRTL8111 3.0.54 (`3089E621-…`). The
`before → b-after-up` ring window reported 11291 completed batches with
11243 cached and 48 refreshed (`11243 + 48 = 11291`), only 48 MMIO HEAD
reads and 48 wraps — both cache hits and real refreshes occurred while the
tail crossed the ring end. The 96 MiB reciprocal workload kept both down
windows busy, shared commands closed at 899 → 6956 → 8273 → 9749 → 12190,
exact coverage held at the last phase (A 32310/32310 with 884 split batches,
B 36866/36866 with 745), A ended 5608/5573 and B 6624/6613 map/unmap, and
target faults stayed zero. PM remains TODO(R47-PM-HARDWARE).

## Accepted Round61 / exact leaf invalidations with one completion per mapping

Base: `562559ac04a5d921691a0150868b6b037332b0df` (accepted R60). At its last snapshot the two domains
requested 74,628 pages of invalidation and the hardware command encodings
covered 83,414. These are requested address ranges, not cache miss counts.

Decompose each ordinary leaf range into contiguous aligned power-of-two blocks.
Reserve all the invalidation descriptors and one CompletionWait in the shared
ring before writing it. Publish the batch once and keep the IOVA owned until
that wait completes. Activation, full-domain flushes and the NPCache skip
keep their existing behavior. A per-domain witness records the actual words
of the last completed split batch for independent capture-side decoding.
Use the existing 96 MiB reciprocal NIC workload.

**Accepted: all four mainline checks passed on the real Mac on the first auto
boot.** The deployed implementation is `e236625`; only AMDMapperProbe was
rebuilt (0.68.0, `540C103D-3D5B-3D42-B75D-C5BB2DD92784`), retaining Lucy
1.1.240 (`43C9BD33-…`) and RealtekRTL8111 3.0.54 (`3089E621-…`). The split
path really ran: at the last phase both domains showed cumulative covered
pages equal to requested pages (A 35370/35370, B 38101/38101) with A at
5896 batches / 7606 descriptors / 1576 split batches and B at 5540 / 6858 /
1244. The per-domain witness exported a real split batch whose raw words
decode through the R50 decoder contiguously — A: request `0x80218000`, five
pages, segments 4 pages @`0x80218000` + 1 page @`0x8021c000`, completion
sequence 9054; B: request `0x80010000`, five pages, 4 pages + 1 page,
sequence 11337 — one CompletionWait per batch. The 96 MiB reciprocal
workload kept both down windows busy (`otherDeviceTrafficWhileTargetDown`),
the parallel payloads overlapped 141.266/127.795 ms, both NICs took exactly
one disable/enable cycle, A ended 5931/5896 and B 5551/5540 map/unmap, and
target faults stayed zero. PM remains TODO(R47-PM-HARDWARE).

## Accepted Round60 / aligned IOVA spans and reciprocal recovery

Base: `db18ba4b0e3f648980339ee182ad2d27be2205d5` (accepted R59; deployed `fdc6942`).
The R59 dual-NIC run used eight 512 KiB Lucy RX mappings. In the A-down
snapshot, the most recent hardware range command covered 64 pages for
a 16-page unmap. All eight Lucy RX groups in the final snapshot also
straddled a natural 128-page boundary.

Prefer a naturally aligned block for a multi-page ordinary DMA mapping.
If that block is unavailable, fall back to the existing allocator with the
caller's required alignment. Domain size, ABI3, page permissions and the
synchronous invalidation before IOVA reuse stay unchanged. Compare the
requested and encoded range in pages; these counts do not measure speed.

Build only AMDMapperProbe 0.67.0; retain Lucy 1.1.240 and RealtekRTL8111
3.0.54. The finite R60 auto run exercises both interface lifecycles using
the original two links: A down while B transfers, then B down while A
transfers, with traffic after each recovery (12 transfers / 96 MiB).

**Accepted: all four mainline checks passed on the real Mac (reciprocal
down/up).** The deployed implementation is `32edc71`; only AMDMapperProbe was
rebuilt (0.67.0, `BEB2CC99-EE9E-3DBE-AD58-C101D787D8F2`), retaining Lucy
1.1.240 (`43C9BD33-…`) and RealtekRTL8111 3.0.54 (`3089E621-…`). All RX groups
now sit naturally aligned — A 32/32 of 16 pages, B 8/8 of 128 pages — and the
ABI3 descriptor PAs still match the walked page tables
(`expectedLastPA == walkedLastPA`). The first auto run timed out in the initial parallel phase. The A peer verified
its upload; no A download receipt was recorded, and the cause is unresolved. The
second auto boot (`auto2`) completed 96 MiB across 12 transfers: A and B each
took exactly one disable/enable cycle, the other domain kept transferring
through both down windows (`otherDeviceTrafficWhileTargetDown`), the parallel
payloads overlapped 117.064/111.356 ms, shared commands closed at
819 → 7777 → 9426 → 11001 → 12419 with covered pages ≥ requested pages
(1573/1600 … 35664/39839), A ended 6317/6282 and B 6144/6133 map/unmap with
deltas equal to the persistent maps, and target faults stayed zero. PM remains
TODO(R47-PM-HARDWARE).

## Accepted Round59 / 512 KiB ordinary DMA mappings (ABI3)

Base: `63ca1bc0ced9c82f7b460559f8cd7917cdc8c0df` (R58 accepted). R58 deployed `3281ac6`;
its first 64 MiB auto run passed all four groups with zero target faults.
The two domains ended with 3738 and 5370 successful unmaps respectively.

R59 raises the per-request limit from 64 to 128 IOVA pages and physical
runs (up to 512 KiB for a page-aligned buffer). The domain still has
4096 IOVA pages and 1024 record slots. The wired descriptor walk uses
per-domain scratch under the mapper lock. ABI3 exports all expected PAs,
including the second half of a large mapping; ABI2 captures remain readable.

RTL812xLucy 1.1.240 uses eight 128-page receive mappings for its 1024
existing slots. The same 4 MiB receive pool formerly needed sixteen
64-page mappings. AMDMapperProbe 0.66.0 and Lucy are rebuilt together;
the installed RealtekRTL8111 3.0.54 is retained. The R59 hardware run
must show the eight full mappings and normal two-device business before
the larger mapping size is accepted. No throughput gain is claimed.

**Accepted: all four mainline checks passed on the real Mac on the first auto
boot.** The deployed implementation is `fdc6942`; both RTL812xLucy 1.1.240
(`43C9BD33-1BB2-3C6F-A339-A34DC3D0DAA9`) and AMDMapperProbe 0.66.0
(`9CB136EC-75FE-3553-8C12-F54694F60C00`) were replaced, retaining
RealtekRTL8111 3.0.54 (`3089E621-…`). Lucy now runs eight 128-page receive
mappings (524,288 bytes each, 1024 slots): the B domain held 11 persistent
maps (3 fixed + 8 RX) with 1037 pages, 11 tables and identity zero, and the
ABI3 descriptor PAs match the walked page tables through page 128
(`expectedLastPA == walkedLastPA == 15078797312`). A/en1/0x2700 domain 1 kept
its own 32×16 shape (35 maps/517 pages). Shared commands closed at
736 → 6871 → 8623 with A 3979/3944 and B 4686/4675 map/unmap, the 64 MiB load
overlapped 91.528 ms (upload) and 41.166 ms (download), B completed business
while A was down, A recovered after up, and target faults stayed zero. The
R53 off baseline was reused as historical context only; PM remains
TODO(R47-PM-HARDWARE).

## Accepted Round58 / compact storage for expected physical pages

Base: `231447265fb0d0283a5921a822a9f0760ac39d58`, the accepted R57 result. R57 deployed `c8cca04`;
its first 64 MiB auto run passed all four groups with zero target faults.

Store the expected physical addresses from the wired descriptor walk in
one 4096-entry array per domain, indexed by the allocated IOVA page.
A live record slot now holds only its 104-byte header. This replaces
1024 private 64-entry PA arrays (512 KiB) with a 32 KiB array: 480 KiB
less fixed mapper state per domain. Mapping capacity, the lowest-slot
rule and the completion-before-reuse contract do not change.

ABI2 still exports a full 616-byte record and a 1472-byte mapper snapshot.
Live records and the saved last-map/last-unmap records materialize their
PA slice before the backing pages can be reused; unused entries are zero.
Expected PAs remain independent of the hardware page tables. The existing
analyzer can compare the two directly. Build only AMDMapperProbe 0.65.0
and retain the two R54 clients.

**Accepted: all four mainline checks passed on the real Mac on the first auto
boot.** The deployed implementation is `3281ac6`; only AMDMapperProbe was
rebuilt (0.65.0, `593EF5F1-4DA6-34E5-9E29-8FB720E0CE3E`) and the deployment
listed it as the sole replaced bundle, retaining Lucy 1.1.239 (`3857B04F-…`)
and RealtekRTL8111 3.0.54 (`3089E621-…`). `abi.py --check-r49` passed and the
ABI2 exports stayed 1472-byte snapshots with 616-byte records. Both domains
again reported `set-on-client-claim-before-pci-open` with their own requester,
mapper and page-table root — A/en1/0x2700 domain 2 (35 maps/517 pages), B/en2/
0x2500 domain 1 (19 maps/1037 pages), the third candidate 0x2200 left
passthrough. The 64 MiB load overlapped 108.179 ms (upload) and 102.103 ms
(download), B completed business while A was down, A recovered after up,
shared commands closed at 616 → 7405 → 9112, A retired 3738 and B 5370
mappings with no rejected map/unmap or invalidation failure, and target
faults stayed zero. The accepted R53 off baseline was reused; PM remains
TODO(R47-PM-HARDWARE).

## Accepted Round57 / bitmap of live mapping-record slots

Base: `cc7bedff5abe77f2f2c97ab38bf223e7b3f49545` (accepted R56 record).
R56 deployed `0830a5a13f00973e3c08b0a8d886730bd9fa9471`. Its first auto
boot passed all four groups with 64 MiB, 10,353 successful maps, 10,299
successful unmaps and zero target faults. Only the Probe changed.

Ordinary map still chooses the lowest free record slot. It now finds that
slot in sixteen 64-bit words, instead of reading a live flag in each record.
This bitmap replaces the private per-record live flag. Unmap verifies the
bit for the slot found by R56's starting-page index; a failed invalidation
retains ownership. Both live-record exporters enumerate occupied slots in
the same ascending order as before. The IOVA allocator, record and snapshot
ABI, and invalidation-before-reuse contract are unchanged.

With the R56 before/A and before/B snapshot occupancies as input, one more
allocation selects slots 35 and 19 respectively. The old search reads 36 and
20 slot flags; both answers are in the first bitmap word. These are search
operation counts on captured layouts, not timing measurements.

**Accepted: all four mainline checks passed on the real Mac on the first auto
boot.** The deployed implementation is `c8cca04`; only AMDMapperProbe was
rebuilt (0.64.0, `4440B59A-9175-3FDC-AA36-E31725D649D6`) and the deployment
listed it as the sole replaced bundle, retaining Lucy 1.1.239 (`3857B04F-…`)
and RealtekRTL8111 3.0.54 (`3089E621-…`). Both domains again reported
`set-on-client-claim-before-pci-open` with their own requester, mapper and
page-table root — A/en1/0x2700 domain 1 (35 maps/517 pages), B/en2/0x2500
domain 2 (19 maps/1037 pages), the third candidate 0x2200 left passthrough.
The 64 MiB load overlapped 97.145 ms (upload) and 49.586 ms (download), B
completed business while A was down, A recovered after up, shared commands
closed at 636 → 7050 → 8794, A retired 4351 and B 4439 mappings with zero
target faults. Live exports stayed ascending and unique in slot order: A
occupied slots 0–34 and B 0–21 while handles grew to 4381/4443, showing
allocation, release and reuse on the same slots. The accepted R53 off
baseline was reused; PM remains TODO(R47-PM-HARDWARE).

## Accepted Round56 / indexed unmap by starting IOVA page

Base: `b339d0ec39a365b063d2d4e8774d5ebeebcd6fad` (R55 accepted record);
R55 deployed `54469ee61afa2143bc6c3848031ab2ad7d32730e`. Its first auto
boot passed the existing four groups: 8 transfers / 64 MiB, independent
pre-open claims, B completing business while A was down, and zero target
faults. The final snapshots recorded 4,664 and 5,167 successful unmaps.

R56 changes the record lookup in the ordinary mapper's unmap path. Each
domain indexes only the first page of a mapping with a 16-bit slot plus
one (8 KiB per domain). The exact IOVA including its offset, length,
descriptor, command, state and live owner are still checked. The owner
survives an invalidation failure and is removed only after completion and
successful allocator release. R55 first-fit allocation and ABI2 exports
are unchanged. This reduces record lookup work; no hardware timing or
throughput improvement has been measured.

Build only AMDMapperProbe **0.63.0** with `sh tools/build-m1a.sh`. Keep the
installed RTL812xLucy **1.1.239** and RealtekRTL8111 **3.0.54**. Use
`python3 -B tools/r56/run.py <command> ...` for the same finite workload.

**Accepted: all four mainline checks passed on the real Mac on the first auto
boot.** The deployed implementation is `0830a5a`; only AMDMapperProbe was
rebuilt (0.63.0, `4689E1F1-DCBF-3FA2-8CF4-22D74D105598`) and the deployment
listed it as the sole replaced bundle, retaining Lucy 1.1.239 (`3857B04F-…`)
and RealtekRTL8111 3.0.54 (`3089E621-…`). Both domains again reported
`set-on-client-claim-before-pci-open` with their own requester, mapper and
page-table root — A/en1/0x2700 domain 2 (35 maps/517 pages), B/en2/0x2500
domain 1 (19 maps/1037 pages), the third candidate 0x2200 left passthrough.
The 64 MiB load overlapped 107.315 ms (upload) and 80.947 ms (download), B
completed business while A was down, A recovered after up, shared commands
closed at 831 → 8423 → 10303, A retired 4425 and B 5874 mappings with no
rejected map/unmap or invalidation failure, and target faults stayed zero.
The accepted R53 off baseline was reused; PM remains TODO(R47-PM-HARDWARE).

## Accepted Round55 / word-wise first-fit IOVA allocation

Base: `30395d3572b36457b68dca2f37e9cdb027407017`, accepted R54 record.
The effective R54 deployment used `b882f091a50080969ccb69bb9748113cb3d3e0cb`.
Re-analysis of the original R54 auto5 capture reproduced the saved 4/4 result:
8 transfers, 64 MiB, independent per-device pre-open claims, and zero target
faults. R54 reused the accepted R53 32 MiB off baseline. Keep R54's final
RX snapshot pairing and settled initial lifecycle capture.

The allocator now searches its existing occupancy bitmap a word at a time.
It selects the same lowest aligned free run as the previous per-page scan.
No change to page-table publication, DMA permissions, returned address range,
the 16 MiB per-domain pool, ABI2, or synchronous unmap-before-reuse. No
instrumentation or new acceptance group is added to the runtime path.

Replaying a 1-page request on R54 auto5 before/B selected page 1037 in both
versions (1038 individual bit probes vs. 18 word probes). A 64-page request
on down/B still selected page 1101 (2777 vs. 28). These are static replay
counts, not kernel timing or network throughput measurements.

Build only AMDMapperProbe **0.62.0** with `sh tools/build-m1a.sh`. Reuse the
installed R54 clients: RTL812xLucy **1.1.239**, RealtekRTL8111 **3.0.54**.
They request Probe 0.61.0, within the new bundle's 0.53.0–0.62.0 compatibility
range. Use `python3 -B tools/r55/run.py <command> ...` for the existing
two-interface workload. The accepted R54 client binaries and fixed upstream
inputs do not need to be rebuilt.

**Accepted: all four mainline checks passed on the real Mac on the first auto
boot.** The deployed implementation is `54469ee`; only AMDMapperProbe was
rebuilt (0.62.0, `882258A2-0B10-3433-88D3-CC5696E7217E`) and the deployment
listed it as the sole replaced bundle, with RTL812xLucy 1.1.239
(`3857B04F-…`) and RealtekRTL8111 3.0.54 (`3089E621-…`) retained from R54.
Both domains again reported `set-on-client-claim-before-pci-open` with their own
requester, mapper and page-table root — A/en1/0x2700 domain 1 (35 maps/517
pages), B/en2/0x2500 domain 2 (19 maps/1037 pages), the third candidate 0x2200
left passthrough. The 64 MiB load overlapped 118.914 ms (upload) and 103.458 ms
(download), B completed traffic while A was down, A recovered after up, shared
commands closed at 901 → 8106 → 9835, and target faults stayed zero. The
accepted R53 off baseline was reused; PM remains TODO(R47-PM-HARDWARE).

## Accepted Round54 / explicit per-device requester claims

Base: `a798b47a9daaae98d5d4efe98285c1bfbee9da2d` (accepted R53 record).
The effective R53 run used `49365e9792b848af435493d5cf86ac49c802514c`.
Re-analysis of the original off and auto5 captures reproduced both saved
4/4 outputs exactly. Keep the RTL8111 stop/drain before a whole-ring
remap and the paired driver/mapper snapshot capture. Auto5 ran 64 MiB
and recorded zero target faults; auto3 had one real RX write fault.

An explicit `amdiommu_devices` match now offers the controller on the PCI
nub instead of binding solely on PCI publication or a Realtek model ID.
A cooperating client uses the shared `waitForMapper()` before PCI open
to claim its own nub. The controller validates the offer and existing IVRS
scope, then prepares the device mapper and publishes `iommu-parent`.
The driver still stops DMA before the first mapping activates its DTE.
Without an explicit list, the previous RTL8127 default remains available.
This neither installs a system mapper nor opts arbitrary PCI drivers in.

Use `sh tools/r54/build.sh <lucy-input> <rtl8111-input>` in the existing
checkout and `python3 -B tools/r54/run.py <command> ...` for the finite run.
The two original clients exercise the generic explicit-claim path.
The existing four checks include the actual per-domain parent phase
`set-on-client-claim-before-pci-open`; keep the R53 64 MiB load and
normal one-device down/up. Reuse the recorded R53 off baseline when the
endpoint and network configuration still match. Keep the same two-domain
limit, ABI2, NPCache policy and synchronous unmap. No PM expansion.

**Accepted on the real Mac with Probe 0.61.0, RTL812xLucy 1.1.239 and
RealtekRTL8111 3.0.54.** The deployed implementation is
`b882f09`, built once and deployed once per attempt; the deployment build log
is `runs/r54/r54-build.log`. All four mainline checks passed on the fifth auto
boot (`auto5`): both domains reported
`r44-parent = set-on-client-claim-before-pci-open` with their own requester
(0x2700 RTL8111 domain 2, 0x2500 RTL8125 domain 1), mapper IDs and page-table
roots, A holding 35 maps/517 pages and B 19/1037 with identity zero, the
third candidate 0x2200 left passthrough. The 64 MiB load overlapped 119.908 ms
(upload) and 102.100 ms (download), B completed traffic while A was down, A
recovered after up, shared commands closed at 618 → 7591 → 9266, and target
faults stayed zero. The off baseline is the accepted R53 one; no extra off boot
was taken. Four capture/lifecycle defects were fixed in this branch (join gate,
bounded window, single-pass publication, settled target lifecycle).

Target: Probe **0.61.0**, RTL812xLucy **1.1.239**, project RealtekRTL8111
**3.0.54**. PM remains TODO(R47-PM-HARDWARE) and was new binaries have been
built and the mixed-device workload has run on macOS.

## Accepted Round53 / mixed RTL8111 and RTL8127 device domains

Base: `2be76054f30e208d57658dc7efa3df79c9050f7c`, the accepted R52 result
documentation successor. Re-analysis of the original R52 off and auto
captures passed 4/4 each and exactly reproduced their saved JSON results.
R52 deployed `e69504d7d1e5a3e5bc2a897e4250905386891aa9`, including the real
`BSD Name` versus `IOBSDName` tool correction. Both domains retained
19 maps/1037 leaves/11 tables in three auto phases; 64 MiB completed with
130.091535 ms upload payload overlap and zero target faults. The report's
overlapping IOVA page counts are corrected here to 1037 / 973 / 1028 for
before / down / after-up. Consecutive translation examples use 4 KiB IOVA
steps (`0x80000000`, `0x80001000`, `0x80002000`, `0x80003000`).

**Accepted: all four mainline groups passed on the real Mac with Lucy 1.1.238 /
Probe 0.60.0 / RealtekRTL8111 3.0.53.** Implementation commits are the delivered
patch as `0391aa8`, plus two real fixes this round: `e44a501` stops NIC RX DMA
before the whole-batch IOVA remap (the first auto capture recorded one genuine
IO_PAGE_FAULT on requester `0x2700`), and `49365e9` judges the driver/mapper
snapshot pair by shape and retakes it when the two publications disagree. R53
adds an independent RealtekRTL8111 driver as a standard DMA client, sharing the
already accepted controller with one RTL8127. It does not publish a system
mapper or increase the existing per-domain capacity. The
`amdiommu_devices=HHHH,HHHH` boot argument selects the two actual segment-zero
PCI requesters. PCI nubs publish `amdiommu-dma-policy` so selected clients wait
for their own mapper and unselected clients continue on the physical path. With
no explicit selection, the prior two-RTL8127 behavior remains available.

Measured on the real machine: A = RTL8111 on `en1`, requester `0x2700`, domain 1,
mapper 4294968539, page-table root 813498368, 35 persistent maps / 517 pages;
B = RTL8125 on `en2`, requester `0x2500`, domain 2, mapper 4294968540, page-table
root 815857664, 19 maps / 1037 pages. The off baseline completed 32 MiB (4/4) and
the single auto workload completed 64 MiB in eight transfers (4/4), with real
payload overlap of 108.331 ms (upload) and 116.824 ms (download). B finished its
16 MiB inside the window in which A was down, A recovered after up, the shared
command submits/completed/completion-sequence closed in every phase, and target
faults were zero in all three phases.

The RTL8111 input is pinned to the official Mieze repository commit
`a3dad34ed4f1e72805ce42f6d506f6917fdf79a0`. Its virtual-descriptor physical-segment lookup assumes a global mapper,
so that lookup alone is insufficient with this project's `gSystem=false`.
The adaptation uses explicit `IODMACommand` objects with the device's
actual mapper for packet buffers as well as rings and tally memory,
gets descriptor IOVAs through `gen64IOVMSegments`, and clears each command
before completing or reusing its memory descriptor. It retains the
current 64-page/16 MiB bounds, stops NIC DMA before every whole-batch IOVA
remap and before the first DTE activation, and publishes a small per-instance
snapshot. Both drivers use the same controller/domain backend; descriptor,
packet and receive-buffer logic remains in the driver that owns it.

Use `tools/r53` with A=RTL8111 and B=RTL8125 in the explicit endpoint
configuration. The off baseline is 32 MiB. The auto workload is
64 MiB: concurrent normal traffic on both endpoints, B completing
traffic while A is down, then A recovering after up. Four mainline
analysis groups verify runtime identity, each driver's live DMA
resources and complete page table, interface-bound byte integrity,
and independent lifecycle with synchronous retirement and no faults.
The two driver resource shapes are deliberately allowed to differ.

Target versions: RTL812xLucy **1.1.238**, RealtekRTL8111 **3.0.53**
(project R53 build), AMDMapperProbe **0.60.0**.
Fetch the required pinned RTL8111 source files once into the fixed
input directory with `tools/r53/fetch-rtl8111.py`, then build both fixed
inputs with `sh tools/r53/build.sh <lucy-input> <rtl8111-input>`
(the Mac build log for this round is `runs/r53-build.log`, 2440 lines).
Do not clone/copy the project or create another worktree for this round.

Keep ABI2, the R51 NPCache policy, synchronous unmap and the R52 shared command
lock. Real system PM is still not implemented and dual-device PM is explicitly
unsupported in this stage; no PM, hot-plug or capacity-expansion test is added.
The down/up result is limited to "B completes business while A is down and A
recovers after up" and does not claim an existing TCP connection crossed the
transition uninterrupted.

## Accepted Round52 / two device domains on one controller

Base: `a75864596ba0e371685f029e7978d795fce1d39f`, the accepted Round51
result-documentation successor. The original R51 capture was re-analyzed:
all eleven checks passed and the complete result matched the saved analysis.
**Accepted: all four mainline groups passed on the real Mac with Lucy 1.1.237 /
Probe 0.59.0.** The deployed implementation is
`e69504d7d1e5a3e5bc2a897e4250905386891aa9`: the delivered patch committed
unchanged as `703d6a5`, plus one real tool fix because `tools/r52/common.py`
matched `IOBSDName` while `ioreg -a` publishes `BSD Name` (the first off
baseline failed on that selection before any traffic). The Mac build succeeded
on the first attempt and the deployment build log is `runs/r52-build.log`.
Two RTL8127 instances share one controller (single `r52-role=controller` entry,
identical shared command count 246 → 5975 → 8853): A/en2 requester 9472 domain
2 root PA 763428864, B/en4 requester 8704 domain 1 root PA 759562240. Both
domains held 19 maps/1037 leaves/11 tables with identity zero, and the same
IOVA `0x80000000` translated to A PA 763494400 and B PA 764108800 (1028 of
1037 live IOVA pages overlapping). The short off baseline moved 32 MiB and
passed 4/4; the single auto boot moved 64 MiB in eight streams with real
parallel payload overlap of 130.1 ms, B completing traffic while A was down and
A recovering after up, all with zero target faults. Dual-device PM is
Unsupported and real sleep/resume stays TODO(R47-PM-HARDWARE).

The controller owns the device table, command/event rings and completion
semaphore once. Each discovered RTL8127 has its own IOMapper instance,
requester, domain ID, page-table root, mapping records and low IOVA allocator.
Domain IOVA ranges may overlap; translation is selected by requester/DTE.
Command submission is serialized across domains. First activation remains
INV_DEV plus a full-domain fence; R51 NPCache-selected map invalidation and
synchronous range invalidation before unmap reuse remain per device.

The owner is identified by `r52-role=controller`; device mapper children by
`r52-role=device`. `R52Snapshot` publishes `r52-domains`, and shared command
counters use `r52-controller-*`. Lucy publishes the requester, actual mapper
registry ID and domain ID per instance. Tools select exact registry entries
and bind each IPv6 socket to its configured interface; neither PCI matching
order nor a fixed BSD interface number defines the two devices.

Build with `sh tools/r52/build.sh <existing-pinned-upstream-input>`, retaining
`--tx21 --rx34` and the ABI2 `--check-r49` layout contract.
Target versions: Lucy **1.1.237**, Probe **0.59.0**.
Use `tools/r52` and a concrete two-endpoint JSON configuration. A short off
baseline transfers 32 MiB. The auto run transfers 64 MiB: each endpoint in
normal operation, the surviving endpoint while the selected endpoint is
down, and the selected endpoint after it is up again. Four analysis groups
cover runtime identity, independent live translation, real traffic and
one-device down/up, and completed invalidations without target faults.
This proves business can complete in the other domain during the down
window; it does not claim an existing TCP connection crossed the transition
without interruption.

Keep the accepted 64-page/64-run maps, RX16x64, DMA32, IPv4/IPv6 TSO and
synchronous IOVA retirement. No throughput threshold, long stress matrix,
system mapper, alias support or multi-controller claim is added.
Real system PM remains `TODO(R47-PM-HARDWARE)`; dual-device PM is explicitly
unsupported in this stage and is not part of the ordinary down/up test.
Use the existing fixed Git checkouts and finite deployment/recovery workflow.

## Accepted Round51 / omit map invalidation when NPCache is absent

Base: `da99156d3e6b20694c88124afb75341f5f437545`, the accepted Round50 documentation successor.
Round50 was independently re-analyzed from its original capture: all eleven
ordinary checks passed and the result matched the saved analysis exactly.
Its actual implementation is `f17507ca33ca2d1e25d656f99cb91c250b52438c`.

**Accepted: eleven mainline checks passed on the real Mac with Lucy 1.1.236 /
Probe 0.58.0.** The deployed implementation is
`a41e5ac715b62e3bdf00d36e6614f13c6322052c`, built once, deployed once and
validated in one planned boot, one load run and one valid measurement (the
target was found powered off before the round and was powered on through
NanoKVM, which is not counted as the planned boot); the deployment build log is
`runs/r51-build.log`. The real capability header `0x190b640f` decoded to
NPCache=0 and the driver selected the same policy. Every phase completed
exactly one full-domain invalidation and `range = unmapOk` ranged ones, with
`skipped = mapOk - 1` (37625 at the end), `pageInvalidations = unmapOk + 1` and
`commandsCompleted = unmapOk + 2`; the R50-equivalent command count would have
been 75234, so 37625 INV/CW waits were avoided while every unmap stayed
synchronous and the last real range matched `lastUnmap`. Four phases still held
19 maps/1037 leaves/11 tables of one domain with 16 real 64-page RX groups,
1025 of 1037 live pages above 4 GiB, 32-bit requests with `map32ok == mapOk`
inside `[0x80000000, 0x81000000)`, 272 MiB of IPv6 traffic and TSO6 increments
2054/133, all with zero target faults.

Use the discovered IOMMU PCI capability header's NPCache bit26. Preserve the
first INV_DEV/full-domain activation, PTE publication barrier, synchronous
unmap range invalidation and IOVA release order. After activation, a new map
needs no INV/CW if the hardware cannot cache non-present entries: upper-level
tables were prebuilt, new IOVA leaves are empty, and prior unmap completion
precedes any reuse. NPCache-capable hardware retains the existing map fence.
See the pinned Linux v6.6 `domain_flush_np_cache()`, `amd_iommu_iotlb_sync_map()`
and `IOMMU_CAP_NPCACHE` definitions under `reference/linux-v6.6/`.

The map-only opt-in leaves unmap and PM callers unchanged. Skips never update
the last submitted range, command sequence or full/range completion counts.
The raw ABI2 is unchanged; `invalidates` still counts actual attempts.
`tMapComplete` records when the map is ready for the device, which need not
include a CW on NP-cache-free hardware. Snapshot properties `r51-npcache`
and `r51-map-invalidation-skipped` expose the policy and skipped map count.

With no PM, the current header `0x190b640f` decodes to NPCache=0:
`skip=mapOk-1`, `full=1`, `range=unmapOk`, and
`commandsCompleted=unmapOk+2`. The last real range then matches lastUnmap.
NPCache=1 retains the R50 relationship and zero skips. Capability is read at
runtime, never assumed from this observed value. This eliminates one INV/CW
per eligible map; throughput is recorded without an improvement threshold.

Use `tools/r51`, `runs/r51`, TCP9117, token `0x51c0de51`,
`org.example.round51load`, Lucy1.1.236 and Probe0.58.0.
Keep the same 272 MiB ordinary IPv6 workload and one interface down/up,
64-page maps, RX16x64, DMA32, ABI2, live/PT checks and eleven-check analyzer.
The shared analyzer's old accounting remains the default for prior rounds.
Do not add a workload matrix, emulate another controller, or trigger PM.
Real sleep/wake stays `TODO(R47-PM-HARDWARE)`.

Round50 report correction: its down-phase raw request is
`[0x8028c000,0x802cc000)` (256 KiB), while command `0x802bf001` covers
`[0x80280000,0x80300000)` (512 KiB). The original analysis is correct;
the report's transcribed endpoints do not require another hardware run.

## Accepted Round50 / ranged ordinary IOVA invalidation

Formal base: `23973d1652091ba0a671a4442e7a0fd3b2f87146`, the accepted Round49
result-documentation successor; tree `cb92cf1b010cc6c0bdba1bcfb75b1c06b140fc10`.
The deployed Round49 implementation is
`5daec3527784199bf80c649da0f56f369624555d`, with exactly the delivered candidate
tree and no implementation fixes. Its actual analyzer rerun passed 11/11
and reproduced both archived analysis files. Independent raw evidence review
confirmed 16 real 64-page/256 KiB RX groups, four phases of 19 maps/1037
leaves/11 tables, 1025 high physical pages, 272 MiB of IPv6 traffic, TSO6
completion increments 2052/136, 60610 completed commands over 236 wraps,
and zero target faults. The report records one build, one deployment, one
planned boot, one load and one valid measurement.

**Accepted: eleven mainline checks passed on the real Mac with Lucy 1.1.235 /
Probe 0.57.0, ordinary auto mode, MTU1500, TSO4 and TSO6 enabled.** The
deployed implementation is
`f17507ca33ca2d1e25d656f99cb91c250b52438c`, built once, deployed once and
validated in one planned boot, one load run and one valid measurement; the
deployment build log is `runs/r50-build.log`. Each phase completed exactly one
full-domain invalidation and `range = mapOk + unmapOk - 1` ranged ones (61174
at the end), with `full + range` equal to the 61175 completed page
invalidations and 61176 completed commands. The latest range always matched the
most recently completed mapper record; the observed command words decoded to
INV_IOMMU_PAGES, domain 1, PDE=0 and correct reserved bits, and the down-phase
64-page RX span encoded an aligned 512 KiB cover for its 256 KiB request. Both
traffic windows advanced the ranged counters. Four phases still held 19
maps/1037 leaves/11 tables of one domain with 16 real 64-page RX groups, 1025
of 1037 live pages above 4 GiB, 32-bit requests with `map32ok == mapOk` inside
`[0x80000000, 0x81000000)`, 272 MiB of IPv6 traffic and TSO6 increments
2054/135, all with zero target faults.

Ordinary map/unmap now supplies its complete allocated page range to
r44Invalidate. The prebuilt low-IOVA tree keeps its upper-level tables, so
ordinary edits invalidate the covered leaf translations with PDE=0. A
single-page request uses S=0; a multi-page request uses one aligned
power-of-two cover with S=1. The range comes from record.basePage/pages,
including physical-run padding and the first byte's page offset. First DTE
activation, explicit device invalidation and PM calls retain full-domain
PDE invalidation. The command ring, synchronous CompletionWait and IOVA
return/reuse order are unchanged.

This reduces the requested invalidation scope. It does not reduce the number
of completion waits or promise a throughput gain: the encoded cover can
include adjacent pages, and hardware may invalidate more than requested.
The encoding follows AMD 48882 section 2.4.3/Table36 and the existing pinned
reference/linux-v6.6/iommu.c build_inv_address contract.

Keep ABI2, the 64-page/64-run capacity, 16 MiB low IOVA pool, RX16x64,
fixed3/13pages, 19 steady/down mappings and 1037 leaves. Driver generation
is unchanged. The R50 build reuses --check-r49 because the ABI is unchanged.
Only existing Probe snapshot publication exposes range/full completion
counters, cumulative requested pages and the latest actual range command
words/sequence. No new DMA path or RPC is introduced.

Use tools/r50, runs/r50, TCP9116, token 0x50c0de50 and
org.example.round50load. Keep the eleven existing IVRS/DMA32/TCP/TSO checks;
extend the hardware-command check with range/full accounting and independent
command decoding against the most recently completed mapper record. Without
PM, full=1 and range=mapOk+unmapOk-1. Normal IPv6 transfers 128/128/8/8 MiB
and one interface down/up exercise the implementation. No extra workload
matrix, allocation target or performance threshold is required.

R49 deployment metadata retained two legacy capacity aliases at 32 despite
correct new fields and raw ABI2 capacity64. R50 sets both aliases to 64.
The R49 report's 1/2/4/5 sequence is the driver TSO sample sequence; its raw
mapper sequence is 2/3/4/5. Neither documentation issue changes acceptance.

R47 public ACPI discovery and PM implementation are retained. Real system
sleep/resume stays TODO(R47-PM-HARDWARE), outside acceptance. Do not trigger
sleep or an artificial awake controller stop/replay cycle. After successful
acceptance, remove the finite job, set only the next boot to off, unmount
EFI and confirm peer exit without a cleanup reboot.

Previous result and evidence are outside this source repository:
[Round49 result](<../../docs/m2-3ad-round49-result.md>) and
[evidence archive](<../../docs/evidence/r49-final-20261103.tgz>)
(SHA256 `7add839a6774d784d74d8d769a244090beac7e1ccfd013af60fbe9f2d459f1bc`).

## Accepted Round49 / larger ordinary DMA mappings and RX batches

Formal base: `e7074605b7077304d638f63440fe4467da918c8d`, the accepted Round48
result-documentation successor; tree `3adb7278e1250c2d95f258d90ebecf227c65f5b5`.
The deployed Round48 implementation is
`b98e74511073eb1eb487af12341b20c9d332d0e0`, with exactly the delivered
candidate tree. Its actual analyzer rerun passed 11/11 and reproduced both
archived analysis files. The driver and every successful mapper request used
32 bits; all captured IOVA spans stayed in the low pool. Each phase contained
1025 high physical pages among 1037 live pages. The four IPv6 streams carried
272 MiB, TSO6 added 2051/133 hardware completions, and the same domain retained
67 maps/1037 leaves/11 tables. Commands completed 72186 times over 281 wraps,
with zero target faults. The report records one build, one deployment, one
planned boot, one load and one valid measurement, with no implementation fix.

**Accepted: eleven mainline checks passed on the real Mac with Lucy 1.1.234 /
Probe 0.56.0, ordinary `amdiommu=auto`, MTU1500, TSO4 and TSO6 enabled.** The
deployed implementation is
`5daec3527784199bf80c649da0f56f369624555d`, built once, deployed once and
validated in one planned boot, one load run and one valid measurement; the
deployment build log is `runs/r49-build.log`. The 256 KiB ordinary maps were
real: 16 RX groups of 64 pages, `maxObservedPages = maxObservedRuns = 64`, and
all four phases held 19 maps/1037 leaves/11 reachable tables of one domain with
identity zero, including across one ordinary down/up that remapped every large
RX group. Steady and down snapshots kept 1025 of 1037 live pages above 4 GiB
with a maximum live PA of 16666193920, every successful request asked 32 bits
(`map32ok == mapOk`, 30314 at the end) and every captured span stayed inside
`[0x80000000, 0x81000000)`. The four IPv6 streams carried 272 MiB, TSO6 added
2052 and 136 hardware completions, 60610 commands completed over 236 wraps,
and target faults stayed zero.

The ordinary mapper now accepts up to 64 mapped pages and 64 physical runs
per request, covering an aligned 256 KiB buffer instead of the previous
32-page/128 KiB limit. Keep the low 16 MiB IOVA pool, 1024 mapping records,
32-bit ordinary driver requests and existing synchronous invalidation.
Legacy layout storage and explicit per-call budgets remain unchanged; only
the ordinary mapper uses the larger fixed-capacity layout.

Lucy's existing mapped RX path groups 64 pages per command, using 16 RX
groups for the same 1024 RX slots/4 MiB buffer total. Its existing setup,
remap, receive, clear and free methods derive their sizes from the same batch
macros. Normal RX traffic and interface down/up therefore exercise real
256 KiB IODMACommand maps. Fixed3 mappings remain 13 pages: steady and down
snapshots contain 19 live mappings and 1037 leaves in the same domain and
11 reachable tables. No extra test DMA path or snapshot RPC is added.

Ordinary raw observation moves to ABI2: 616-byte records and a 1472-byte
snapshot with complete 64-page physical lists. Historical ABI1 evidence is
still decoded for prior archives. Legacy experiment ABIs remain unchanged.
The R49 build uses --check-r49 for the new header layout; earlier check modes
retain their original meaning.

Use tools/r49, runs/r49, TCP9115, token 0x49c0de49 and
org.example.round49load. Keep the eleven IVRS/DMA32/TCP/TSO checks, with
whole-PT and lifecycle checks confirming 16 groups of 64 pages, 19 retained
mappings and RX remapping in both traffic windows. The four IPv6 streams
remain 128/128/8/8 MiB with one ordinary down/up. Physical run count depends
on actual page placement; hardware evidence need not contain exactly 64 runs.
Report actual high-PA coverage and throughput without allocation or speed gates.

R47 public IOACPIPlatformDevice discovery and PM implementation are retained.
Real sleep/resume stays TODO(R47-PM-HARDWARE), outside acceptance. Do not
trigger system sleep or an artificial awake controller stop/replay cycle.
After successful acceptance, remove the finite job, set only the next boot
to off, unmount EFI and confirm peer exit without a cleanup reboot.

Previous result and evidence are outside this source repository:
[Round48 result](<../../docs/m2-3ac-round48-result.md>) and
[evidence archive](<../../docs/evidence/r48-final-20261103.tgz>)
(SHA256 `0894e10c14c933b1079435d940cab6396adec2a15bdaa3134ba13cf33c31a283`).

## Accepted Round48 / ordinary 32-bit DMA constraints

Formal base: `123dea9ddb5f159535f1be5e42f01168203a0850`, the accepted Round47
result-documentation successor; tree `08c7c25a982c47769d66bebd4db67d59d077a9dc`.
The deployed Round47 implementation is
`0754d47b245ba2f641b0da194cdb6b1a11c03fb9`. The actual analyzer rerun passed
10/10 and exactly reproduced the archived JSON. Independent raw/PT/IVRS/TCP
verification confirmed 36 manifest hashes, four phases with 67 maps/1037
leaves/11 reachable tables, 272 MiB, TSO6 completion increments 2053 and 135,
67684 completed commands, 264 wraps and zero target faults. Preserve the
actual public `IOACPIPlatformDevice::getACPITableData` implementation that
fixed Round47's real SDK access and AuxKC symbol-binding failures.

**Accepted: eleven mainline checks passed on the real Mac with Lucy 1.1.233 /
Probe 0.55.0, ordinary `amdiommu=auto`, MTU1500, TSO4 and TSO6 enabled.** The
deployed implementation is
`b98e74511073eb1eb487af12341b20c9d332d0e0`, built once, deployed once and
validated in one planned boot, one load run and one valid measurement; the
deployment build log is `runs/r48-build.log`. The driver configured 32 address
bits, every successful mapper request asked for 32 bits (`min=max=32`,
`map32Ok == mapOk` per phase, 36126 at the end) and every live and last
map/unmap span stayed inside `[0x80000000, 0x81000000)` while the complete page
tables still mapped the recorded physical pages. High physical addresses were
actually covered: 1025 of 1037 live pages per phase sat above 4 GiB, with a
maximum live PA of 15189209088 and 210251 cumulative high-PA pages. The four
IPv6 TCP streams carried 272 MiB, TSO6 added 2051 and 133 hardware
completions, all four phases held 67 maps/1037 leaves/11 tables of one domain,
72186 commands completed over 281 wraps, and target faults stayed zero.

The ordinary mapper uses an independent 16 MiB IOVA pool at 0x80000000,
entirely below 4 GiB. Standard IODMACommand requests with 32 through 64 address
bits can use it; the whole returned span must fit the actual request. The
historical experimental allocator keeps its existing 64 GiB base. Physical
pages may remain above 4 GiB; this constrains device-visible IOVA, not RAM.

Lucy's ordinary TX-ring, RX-ring, tally, RX-group and packet-TX commands now
request 32 address bits in normal AMDIOMMU mode. Host64 output, gen64 segments,
NIC descriptors, physical allocation masks and DMA ownership remain intact.
Other mapper modes retain the original 64-bit request. ABI1 stays at 960-byte
snapshot/360-byte record, with 4096 IOVA pages, 1024 records and the existing
32-page/32-run per-map limits, fixed3 and RX64 resources.

Use tools/r48, runs/r48, TCP9114, token 0x48c0de48 and
org.example.round48load. The existing R47Snapshot publishes the new successful
request-width and high-PA counters; no new snapshot RPC is introduced. The
four IPv6 TCP streams remain 128/128/8/8 MiB, with one ordinary interface
down/up and complete before/pre-down/down/after-up mapper/live/PT captures.
Retain the ten existing checks and add a DMA32 check: every successful request
uses 32 bits, every live and last-map/unmap span fits the low pool, and the
complete page table maps those IOVAs to the recorded physical pages. Record
actual high-PA coverage; it is an observation, not a new allocation or rerun
gate. This validates constrained commands on the current RTL8127, without
claiming a separate 32-bit-only device has been tested.

R47 IVRS/PCI discovery and its PM implementation are retained. Real system
sleep/resume stays TODO(R47-PM-HARDWARE), outside the ordinary acceptance
gate. Do not trigger system sleep or an artificial awake controller cycle.
The normal interface down/up is not power-management evidence.

Build with `sh tools/r48/build.sh _scratch/lucy-upstream` using the same pinned
inputs and flags. Lucy requests Probe 0.55.0; Probe compatible version 0.53.0
and its IOACPIFamily dependency stay intact. After acceptance, remove the
finite job, set only the next boot to off, unmount EFI and confirm peer exit;
leave the current mapper active without a cleanup reboot.

The accepted previous result and archive are outside this source repository:
[Round47 result](<../../docs/m2-3ab-round47-result.md>) and
[evidence archive](<../../docs/evidence/r47-final-20261103.tgz>)
(SHA256 `27cb04f408d6a5c832dbdd3d0afaf663554b5ea9315e1b30737cff78f0bbe285`).

## Accepted Round47 / IVRS controller discovery

Formal base: `576c11adf03ce024bcf019d88cdc8b30781a19cc`, the accepted Round46
result-documentation successor; tree `8b79ac2fdafe40ee4d7686e3f0d82996d01760e5`.
The deployed Round46 implementation is
`9915c0f908bac8f2df2660fbace0fab80bf09c12`, with exactly the delivered candidate
tree. The analyzer rerun passed 9/9 and reproduced the archived JSON. An
independent raw/PT/TCP audit confirmed 272 MiB, TSO6 completion increments
2057 and 136, four snapshots with 67 maps/1037 leaves/11 reachable tables,
71204 completed commands, 278 wraps and zero target faults. The actual report
records one planned boot, one load and one valid measurement.

**Accepted: ten mainline checks passed on the real Mac with Lucy 1.1.232 /
Probe 0.54.0, ordinary `amdiommu=auto`, MTU1500 and both TSO modes enabled.**
The deployed implementation is
`0754d47b245ba2f641b0da194cdb6b1a11c03fb9`; two real blockers were fixed in
this branch before deployment: the platform expert's table lookup is protected,
and the derived accessor could not bind the unexported
`IOACPIPlatformExpert::metaClass`, so the actual IVRS is now read through
`IOACPIPlatformDevice::getACPITableData`. Real Mac compilation, strict
codesign, boot and hardware acceptance passed in one planned boot, one load run
and one valid measurement. The four IPv6 TCP streams carried 272 MiB; the two
traffic windows added 2053 and 135 real TSO6 hardware completions; all four
phases held 67 maps/1037 leaves/11 reachable tables of one domain, 67684
commands completed over 264 wraps, and target faults stayed zero. Discovery
resolved requester `0x2500` to unit 0 (`0000:00:00.2`), checked capability
`0x40`/header `0x190b640f`, confirmed the IVRS and PCI bases both at
`0xfd380000`, and observed firmware and runtime EFR `0x058f77ef22294a5a`.
The actual report records one planned boot, one load and one valid measurement.

The normal mapper now reads ACPI IVRS and reuses the existing topology parser
to resolve the current NIC's requester and owning IVHD unit. It locates the
unit's actual PCI nub and verifies the firmware register base against the
enabled Secure Device capability before mapping MMIO. Controller identity
uses runtime IVRS/PCI information and the observed EFR, replacing the fixed
MMIO address and fixed EFR equality in the ordinary startup path. This round
still serves the existing single NIC on PCI segment 0 with its plain requester
policy; it does not implement a system mapper or multi-device attachment.

Retain the ordinary mapper ABI1, 4096 IOVA pages, 1024 live records, per-map
32-page/32-run limits, RX64 groups and three fixed mappings. Probe's compatible
version remains 0.53.0; Lucy requests 0.54.0 for the new PM entry. The Probe
adds the IOACPIFamily dependency needed for the actual ACPI table API.

The driver also includes a gated IOMMU suspend/resume path. It coordinates
ordinary NIC disable and DMA stop with mapper freezing and controller stop;
resume restores the same tables and rings, completes invalidations, and only
then permits NIC enable. Existing live mappings and initial activation
identity remain available across this path. The runtime EFR is also the
same-controller reference for resume.

**TODO(R47-PM-HARDWARE): actual system sleep/resume is not validated on this
platform.** Do not trigger system sleep, a wake wait, or an artificial awake
IOMMU stop/replay cycle in this round. PM implementation and host validation
must not be reported as successful hardware power-management validation.
The TODO remains separate from the ordinary mainline acceptance result.

Use `tools/r47/build.sh` with the same pinned upstream inputs and generation
flags. Runtime entry points are deploy.py, peer.py, boot-load.sh, load.py,
capture.py, analyze.py and disarm-next.py under tools/r47. Use runs/r47,
TCP9113, userspace token 0x47c0de47 and org.example.round47load.
`R47Snapshot` collects ordinary counters and discovery evidence; the existing
TSO6 counters retain their `rtl812x-r46-` names.

The finite workload remains explicit AF_INET6 upload/download 128 MiB each,
ordinary interface down/up, then upload/download 8 MiB each. Select existing
local and peer IPv6 addresses; the tools do not create addresses or routes.
The four phases remain before/pre-down/down/after-up. Each phase captures the
complete mapper/live/PT evidence plus the actual IVRS bytes. The analyzer
retains the nine ordinary checks and adds one IVRS/PCI discovery check;
hardware PM is recorded separately as TODO and is not a required gate.

On success, remove the finite job, set only the next boot to `amdiommu=off`,
unmount EFI and confirm the peer exits. Keep the current ordinary mapper
active and do not append a cleanup reboot.

## Accepted Round46 / ordinary IPv6 TCP and hardware TSO

Formal base: `b7869df730b33107f16d277f4974b826df667c53`, the accepted Round45
result-documentation successor; tree `95d6528fb704c7bdcc67b511f4e264f21ef6dabe`.
The deployed implementation is `1a43d40039798e0ae21526c11c7151cfd289a834`.
The actual Round45 analyzer rerun passed 9/9 with JSON identical to the archive.
Independent raw and TCP verification confirmed 272 MiB, TSO4 hardware completion
increments 2071 and 132, four snapshots with 67 mappings/1037 IOVA leaves,
58754 completed commands and no target faults. Two planned boots and two load
attempts produced one valid measurement. The actual bounded pre-open mapper
wait and matching-boundary repair are included in this baseline.

**Accepted: nine ordinary mainline checks passed on the real Mac with Lucy
1.1.231 / Probe 0.53.0, `amdiommu=auto`, MTU1500 and both IPv4 and IPv6 TSO
enabled.** The deployed implementation is
`9915c0f908bac8f2df2660fbace0fab80bf09c12`; the delivered candidate applied
and built without any further fix. Real Mac compilation, strict codesign,
boot and hardware acceptance all passed in one planned boot, one load run and
one valid measurement. The two traffic windows added 2057 and 136 real TSO6
hardware completions over explicit AF_INET6 endpoints carrying 272 MiB,
while the enabled TSO4 path stayed closed without another IPv4 workload.

Exercise the ordinary IPv6 TCP path using the existing mapper, command pool,
descriptors and interface lifecycle. Keep the ordinary mapper ABI1 and
accepted resource capacities.

R46 reuses the actual TX post/retire methods and selects separate counters
from the descriptor's GiantSendv4/GiantSendv6 bits. Hardware close-pointer
completion and stop reclamation remain separate. `R46Snapshot` samples both
families through the existing command gate; the R45 fields and RPC stay usable.
Only TSO6 requires positive traffic increments during this round's two windows.
Both families must be drained at snapshots, with no stop-retired TSO packets
or mapping failures. The normal command-pool backpressure is unchanged.

The existing `prepareTSO6()` summed 16 words by indexing the source IPv6
address's eight-word array into its adjacent destination address. The new
template explicitly sums eight source and eight destination words, preserving
the checksum while removing the out-of-bounds access on the normal path.

The finite load uses explicit AF_INET6 sockets, existing local/peer numeric
IPv6 addresses, and TCP port 9112. Both endpoints record the real socket
addresses, ports and local scope IDs. The peer processes upload/download
128 MiB each, then upload/download 8 MiB each after ordinary interface down/up.
All 272 MiB are verified by deterministic content, SHA256 and peer receipts.
The four phases remain before/pre-down/down/after-up. IPv4 fallback is not
accepted as IPv6 evidence; scope IDs belong to each endpoint's own system.

Choose existing addresses on en2 and the actual peer, preferably the same LAN
ULA/global prefix, or scoped link-local addresses. The tools read address,
MTU, link and IPv6 route state and wait for the same address after interface
up. They do not install addresses or change routes. The prompt includes the
explicit address-selection step rather than inventing a peer IPv6 address.

Use the same Git checkout and pinned upstream with `tools/r46/build.sh`.
The generator remains --tx21/--rx34 and --check-r44 validates the unchanged
mapper ABI. Entry points under tools/r46 are deploy.py, peer.py, boot-load.sh,
load.py, capture.py, analyze.py and disarm-next.py. Use runs/r46, userspace
token 0x46c0de46 and org.example.round46load. Closure removes the finite job
and sets the next boot to off while the current ordinary mapper stays active.

Host validation covers actual generated dual-family TX methods, actual IPv6
header preparation, four real localhost IPv6 streams and analyzer contracts.
The default R45 analysis still exactly reproduces its accepted archive; real
Mac build, boot and hardware acceptance are now complete.

Result and archive are outside this source repository:
[Round46 result](<../../docs/m2-3aa-round46-result.md>) and
[evidence archive](<../../docs/evidence/r46-final-20261103.tgz>)
(SHA256 `939a82ca2f256ca13862d11b5352a7685348e855d84e2de0c908bc02125d7dfc`).
The finite job is removed, EFI is unmounted, the current mapper stays active
and the next boot is `amdiommu=off`; no extra reboot was issued.

## Accepted Round45 / ordinary IPv4 TCP and hardware TSO

Formal base: `035d1dd0f5e60afbc5f2715de3f425cb694d3f56`, the accepted Round44
result-documentation successor; tree `0e3d8dbb967fa6e2984297c3e952b2b4759151ac`.
The deployed Round44 implementation is `6c3e8ca7424dbfa0810ab0f4516ad4a5251e1092`.
Its actual analyzer rerun passed 9/9 and reproduced the archived JSON. An
independent raw walk confirmed all five snapshots: 67 live maps, 1024 RX plus
13 fixed IOVA leaves, no identity leaves, and the same device domain through
idle and ordinary interface down/up. There were three planned boots, four
load attempts and one valid measurement. The recorded 16094/16027 map/unmap
counts are boot totals; the valid phase1-to-pre-down interval adds 9830 each.

**Accepted: nine ordinary mainline checks passed on the real Mac with Lucy
1.1.230 / Probe 0.53.0, `amdiommu=auto`, MTU1500, IPv4 TSO enabled and IPv6
TSO disabled.** The deployed implementation is
`1a43d40039798e0ae21526c11c7151cfd289a834`, following the candidate
`6eebf25f56e86c2b10a66f16a07752248193b63a` plus three direct-cause fixes:
closing the IOResources/IOPCIDevice matching race with a bounded wait before
the driver's one-shot mapper lookup, and two generator-anchor corrections.
Real Mac compilation, codesign, boot and hardware acceptance all passed;
two planned boots, two load runs and one valid measurement.

The first boot lost the mapper to the driver start. IOKit does not order the
two providers' matching, so the driver now waits up to two seconds for
`iommu-parent` before opening the PCI nub, and the probe accepts an attached
but unopened nub. No check, threshold or ABI was changed for this fix.

Keep the accepted per-device mapper,
4096-page allocator, ordinary mapper ABI1 and fixed/RX resource lifetime.
The synchronous PCI nub lookup, compatible dependency `0.53.0`, IOResources
probe lookup and normalized analysis comparison from the actual R44 fixes
are part of this baseline.

Before dequeuing a packet, the normal output path now checks TX DMA command
availability as well as descriptor capacity. It leaves packets queued and
returns `kIOReturnNoResources` until the existing completion path returns
commands and wakes output. `txMapPacket()` returns zero on command exhaustion;
it can no longer report uninitialized output segments as a successful map.

Bounded lifetime counters observe actual `GiantSendv4` submissions after the
OWN store and completions consumed by the hardware close-pointer path. Ring
clear has a separate stop-retired count, so cleanup cannot masquerade as
hardware completion. `R45Snapshot=true` samples those counters under the
existing command gate; the TX hot path does not write registry properties.
Counters survive ordinary interface down/up. Snapshot collection waits up to
five seconds for posted/completed equality before recording each phase.

The finite TCP peer uses port 9111 and token `0x45c0de45` only for userspace
byte identity. Four transfers use deterministic position-sensitive payloads,
SHA256 and peer receipts:

| Stage | Upload | Download |
| --- | ---: | ---: |
| Before ordinary interface down/up | 128 MiB | 128 MiB |
| After ordinary interface up | 8 MiB | 8 MiB |

The total is 272 MiB. Snapshots are `before`, `pre-down`, `down`, `after-up`.
Both traffic intervals must show new TSO4 hardware completions and bytes,
with no mapping failures or stop-retired TSO packets. Throughput is recorded
without a line-rate threshold. TCP retransmission is normal protocol behavior;
the previous UDP no-retry condition and 125-second idle are not repeated.
Normal down still retains 64 RX groups and three fixed mappings in the same
domain. Complete live records and the whole PT remain the mapping authority.

Use the same checkout and pinned upstream input with `tools/r45/build.sh`.
The generator remains `--tx21 --rx34`, and `--check-r44` checks the unchanged
mapper ABI. Other entry points under `tools/r45` are `deploy.py`, `peer.py`,
`boot-load.sh`, `load.py`, `capture.py`, `analyze.py` and `disarm-next.py`.
Use `runs/r45` and the finite `org.example.round45load` job. Successful closure
sets only the next boot to off and removes the job; the current mapper stays
active. Keep source revisions in Git, without a round-specific repository copy.

The real run moved 285212672 bytes in four TCP transfers with both endpoints'
SHA256 and receipts verified; the two traffic windows added 2071 and 132 real
TSO4 hardware completions, with max-length 65226, max-segments 17 and max-mss
1448. All four phases kept one device domain and 67 complete live mappings
(64 RX groups + 3 fixed); command completion reached 58754 with 229 real
wraps and zero target faults. Observed throughput is reported without a
line-rate threshold.

Result and archive are outside this source repository:
[Round45 result](<../../docs/m2-3z-round45-result.md>) and
[evidence archive](<../../docs/evidence/r45-final-20261103.tgz>)
(SHA256 `9ad3f165a6e9652c3fe374d5e840e41098ae10e9d3936edb2bc63725144f7aaa`).
The finite job is removed, EFI is unmounted, the current mapper stays active
and the next boot is `amdiommu=off`; no extra reboot was issued.

## Accepted Round44 / attach the RTL8125 to an ordinary device IOMapper

Formal base: `102560a59bc448ddfd5600d5d958952e4875eb16`, the actual accepted
Round43 documentation successor; tree `078a46e38a9a1f15e6f97f2f6d304448936f3a81`.
The deployed Round43 implementation is `7d18caaa1ad5bcc9cae43cb85eb8761d6d05523a`,
tree `cf21535fb58c2b6bd8ed52459e0e3e5ed8c9b62a`, exactly the delivered candidate.
The actual analyzer rerun passed 14/14 and reproduced the archived JSON.
An independent raw walk confirmed 1024 RX + 13 fixed IOVA leaves, no identity
leaves, zero final leaves, and NIC stopped before the DTE write. The DTE write
was 31,745,105,654 ns; invalidation completed at 31,745,126,384 ns.

**Lucy 1.1.229 / Probe 0.53.0, `amdiommu=auto`. Accepted: nine ordinary
mainline checks passed on the real Mac.** The deployed implementation is
`6c3e8ca7424dbfa0810ab0f4516ad4a5251e1092`, on top of the base implementation
`9178196b51259ccb30960d330d62ff4b5cddd03c` and the dependency fix
`fb8c5da746f26d0ff30a18cdf8d18f7c9f0e42bd`; the later `418a0138…` and
`a0a29812…` only repair the capture and disarm tooling. This round connects the
ordinary driver path to a per-device mapper from its normal startup. It does
not install the legacy R17/R34 experimental session. `fIsSystem` remains false.

Two real blockers had to be fixed before a normal boot could work. `kmutil`
resolves a bundle dependency only inside the provider's compatible range, so
the driver must request `0.53.0` rather than `0.0.0`. The mapper then has to be
visible before the driver's single `copyMapperForDevice()` call: the publish
notification is delivered asynchronously and lost to the driver's `start()`, so
the probe now enumerates `IOPCIDevice` during its own `start()` and matches the
vendor and device config words — the nub is already published and still
unclaimed at that point, and it is named `ethernet`, not `pci10ec,8127`.

`AMDMapperProbeAuto.cpp` prepares a resident controller, an initially empty
IOVA domain and passthrough DTEs during the target PCI publication. It then
sets `iommu-parent` before Lucy calls `IOMapper::copyMapperForDevice()`. Lucy
selects its existing mapped DMA path on x86 as well as arm64. The target DTE
becomes translated at its first ordinary map, after the existing NIC reset and
before that map returns an IOVA. Each map/unmap completes INV/CW before an IOVA
is exposed or its pages become reusable.

`AMDMapperProbeMapper.cpp` accepts normal wired descriptors and DMA commands
without private role registration. The shared allocator has 4096 IOVA pages
(16 MiB), 1024 live records, and up to 32 pages/physical runs per mapping.
The 16-page PT arena contains 11 reachable tables. Normal Lucy owns 64 RX
groups of 16 pages, three fixed mappings and up to 512 packet TX commands.
The existing allocator implementation is reused; its legacy alias stays intact.

Normal `clearRxTxRings()` now clears an active TX command before completing its
descriptor, matching normal TX retirement. Interface down/up keeps the RX and
fixed resources: **67 live mappings after down is the correct result.** Only
actual descriptor resource teardown can reach zero. The resident controller
is not rebuilt across idle or interface transitions.

Evidence uses ordinary mapper ABI1 (960-byte summary, 360-byte live records),
the whole PT and minimal startup/enable/disable properties. `R44Snapshot=true`
exports the live set under the mapper lock; it does not control DMA ownership.
The normal workload remains 4096 requests, 125 s idle, another 4096 requests,
then ordinary interface down/up and three recovery probes. The nine checks in
`tools/r44/analyze.py` validate discovery/order, actual live PTEs, accounting,
byte integrity, persistent identity, fixed bases, retained mappings and faults.

Use the same Git checkout and pinned upstream input. Entry points:
`tools/r44/build.sh`, `deploy.py`, `boot-load.sh`, `load.py`, `capture.py`,
`analyze.py`, `disarm-next.py`; peer/protocol reuse `tools/r27/peer.py`.
Use `runs/r44`, token `0x44c0de44` only in userspace, and
`org.example.round44load`. Successful closure removes that finite job and sets
the next boot to `amdiommu=off`, while the current ordinary mapper stays active.
Host mainline validation is separate from the two that this round completed:
real Mac kext compilation and hardware acceptance both passed.

Result and archive are outside this source repository:
[Round44 result](<../../docs/m2-3y-round44-result.md>) and
[evidence archive](<../../docs/evidence/r44-final-20261103.tgz>)
(SHA256 `898e6ecb68b0d9a4301555427fbc5243c27cf6ec06d49823054d4000816fb418`).
The accepted run took three planned boots and four load runs; the first two
boots reported `failed-too-late` and the third boot's first load run failed
only in the capture lookup, so exactly one load run is the valid measurement.

## Accepted Round43 / an IOVA-only device domain from entry through stop

Base: `7af436acaad62a58acbdb4b788142145ec4c744f`, the accepted Round42
result-documentation successor (tree `a5f7f4a3aec7ad7b774c0f14e8e48f6e8700069f`).
The deployed implementation is `6931c8a6ee583482ce5bf373d1dfbee8f76cc954`,
whose tree exactly matches the delivered Round42 candidate. The original
capture was reanalyzed on the actual source: 14/14 passed, one planned boot
and one valid measurement, with JSON identical to the archived analysis.

Candidate: Lucy **1.1.228** / Probe **0.52.0**. TX native7/std5/domain4,
PhysicalLayout1, StopRecord1 and FixedDMA1 remain. Native RX advances to ABI5
with unchanged record sizes and explicit pre-DTE stop/active-snapshot ops.

Round42 already posts all initial RX IOVAs before enabling DMA. The remaining
physical bootstrap bridges the interval from the DTE switch to NIC stop.
Move that same verified NIC stop/reset to immediately after the existing TX
drain and before writing the DTE. The native root can then start without any
identity leaves; fixed and RX mappings are installed while the NIC is stopped.

Before enable, capture the real active IOVA tree after all initial OWN stores.
There is no bootstrap unmap or synthetic retirement command. Keep the accepted
IRQ handoff, first generation 1 and maps=posted. During exit, Disarm performs
the real NIC stop within its existing command gate; Drain confirms that state.
RX/fixed unmap and current-PA OWN preparation happen with DMA stopped. Restore
the original IOMMU state before enabling physical DMA again. No physical cover
mapping is needed, and the final experimental page table has no present leaf.

Keep the same normal 4096 + 125-second idle + 4096 workload, one explicit stop
and three ordinary probes after recovery. Update the existing 14 checks and
normal fixture for the new entry order, active IOVA snapshot and empty final
tree. Use the fixed checkout/upstream, `--tx 21 --rx 34`, `--check-r43`,
`runs/r43`, `org.example.round43load` and token `0x43c0de43`.
Host validation, real Mac compilation and hardware acceptance remain separate.

**Round43 hardware acceptance PASSED (14/14).** One planned boot and one valid
measurement. The entry stopped the NIC at 31,743,262,638 ns and read it back
stopped at 31,743,867,276 ns with `ChipCmd` 12 -> 0 and `IMR0` 32821 -> 0, then
wrote the device table at 31,745,105,654 ns and completed invalidation at
31,745,126,384 ns, so the stop strictly precedes the
DTE write and `stoppedBeforeDTE` is true. All 1024 initial IOVA OWN stores landed
afterwards (31,756,479,818 and 31,757,085,827 ns), the active tree was captured at
31,758,140,445 ns, driver active-ready followed at 31,758,140,595 ns, the fixed
registers were programmed at 31,780,744,635 ns and only then did hardware become
active at 32,171,479,859 ns and RX authorize at 32,171,493,419 ns.

`physical-mode` is `iova-only`: bootstrap pages, removed pages, restore-added
pages, physical cover calls and identity pages are all zero, and the final
experimental page table has **zero present leaves**. The active snapshot keeps
exactly 1024 RX IOVA leaves for the generation-1 buffers plus the three fixed
spans (txRing 889,716,736 / 32,768 B, rxRing 889,749,504 / 16,384 B, tally
15,107,784,704 / 192 B; 13 pages), and the fixed objects completed three standard
map/unmap pairs each.

RX counts are `maps = unmaps = posted = 10382` with `posted 10382 = completed
9358 + stopRetired 1024`, mapCount = postCount per slot, first generation 1, 2598
real replacements, 999 of 1024 slots differing between first and final retained
generation addresses and 1024 slots restored. Invalidations were 10370 each over
9346 batch calls and 9358 batch slots (`max-batch=5`, 24 saved cycles). TX retired
9319 with rejected 0, domain maps 9328 = 9319 + 9 capacity probes, the command
ring completed 39405/39405 through 153 wraps, business traffic completed 8192/8192
with 1047 ordinary probes and no peer tail packet across a 125.290027393 s idle
in one service-owned domain whose two observations share root/DT/command
`0x3a680000`/`0x3a800000`/`0x3aa00000` with `installs=1`.

Disarm stopped the NIC inside its own RPC (`stopCalls=1`, `rxNext` 142 -> 0,
`stopRetired` 1024, restored 1024), the original IOMMU state was restored before
the physical resume at 167,676,346,153 ns, owners/bindings/pending stayed zero,
device page faults stayed zero and 3/3 ordinary probes succeeded after exit.

Deployed implementation commit: `7d18caaa1ad5bcc9cae43cb85eb8761d6d05523a`. This
documentation update is not a deployed revision.

Round43 result and archive are outside this source repository:
[Round43 result](<../../docs/m2-3x-round43-result.md>) and
[evidence archive](<../../docs/evidence/r43-final-20261103.tgz>)
(SHA256 `c102e10e5cd38aa7657f9254faebfe2df63d6b4857c5ec288e994d3cf4feccee`).

The rearm observation ring stays capped at 4096 records, so
`rtl812x-rxpost-state` still reports `degraded` with a wrapped prefix while
`dropped` is zero; that is an observer capacity bound, not a traffic failure.

## Accepted Round42 / publish the entire RX IOVA ring before hardware enable

Base: `8efddec6ca4280b59fe991b87516903f8628bf23`, the accepted Round41
result-documentation successor (tree `4207a10f564eba051e0eeae197848566ac666317`).
Its deployed implementation is `ac436c3e8e3dbb625f71545b4ee913bd5d273f7e`,
whose tree exactly matches the delivered Round41 candidate. The original
capture was reanalyzed on the actual source: 14/14 passed, with one planned
boot and one valid measurement. The recomputed JSON matches the archived one.

Candidate: Lucy **1.1.227** / Probe **0.51.0**. Keep TX native7/std5/domain4,
native RX4, PhysicalLayout1, StopRecord1 and FixedDMA1. Keep the accepted
Round41 entry IRQ handoff and all three standard fixed DMA mappings.

Round41 left the prepared RX mappings unused until each slot's first physical
receive completed. Round42 uses the existing stopped-NIC entry window to
publish all 1024 prepared IOVAs directly into the ordinary RX ring. Each OWN
store has its real first-generation post witness. With the NIC still stopped,
retire every bootstrap identity leaf and confirm the existing INV/CW before
calling the ordinary hardware enable path. Hardware entry, RX authorization
and ready retain their actual later timestamps; they are not moved earlier.

The active snapshot therefore proves identity=0 before the first RX/TX
activation, without needing traffic to visit every RX slot. Initial mappings
now carry real RX work: maps=posted, per-slot mapCount=postCount and the first
retained generation is 1. Real completions and stop retirement stay separate,
with posted=completed+stopRetired. Final physical recovery and the current-RX
identity set keep the accepted Round41 behavior.

Keep the same normal 4096 + 125-second idle + 4096 workload, one local stop
and three ordinary probes after recovery. Strengthen the entry timing in the
existing RX checks and update the existing normal fixture; retain 14 checks.
Use the fixed checkout and upstream input, `--tx 21 --rx 34`, `--check-r42`,
`runs/r42`, `org.example.round42load` and token `0x42c0de42`.
Host validation, real Mac compilation and hardware acceptance remain separate.

**Round42 hardware acceptance PASSED (14/14).** One planned boot and one valid
measurement. All 1024 initial mappings were published with their real IOVA OWN
while the NIC was stopped (`initialMappingsPosted=1024`,
`unpostedInitialMappings=0`), the first post at 31,665,224,426 ns and the last
at 31,665,883,905 ns, then the bootstrap identity was cleared at 31,666,835,365
ns, its single INV/CW completed at 31,666,840,795 ns with expected = observed =
1049, the driver callback returned at 31,667,346,005 ns, and only then did the
hardware authorize at 32,111,651,558 ns, so
`bootstrapRetiredBeforeNICEnable` is true and the first packet already used IOVA.

The active page table holds **identity=0** with 1024 RX IOVA leaves mapping each
slot's generation-1 physical buffer, and all three fixed spans stayed at their
IOVA slots (txRing 879,222,784 / 32,768 B, rxRing 879,255,552 / 16,384 B, tally
15,120,543,744 / 192 B; 13 pages). Because the initial mappings now carry real
work, `maps = unmaps = posted = 10466` with no extra 1024 preparation term, and
`posted 10466 = completed 9442 + stopRetired 1024`; 2627 real replacements
occurred, 1006 of 1024 slots differed between first and final retained
generation addresses and all 1024 slots were restored.

RX invalidations were 10448 each over 9424 batch calls and 9442 batch slots
(`max-batch=5`, 36 saved cycles). TX retired 9364 with rejected 0, domain maps
9373 = 9364 + 9 capacity probes, the command ring completed 40676/40676 through
158 wraps, business traffic completed 8192/8192 with 1047 ordinary probes and no
peer tail packet across a 125.295904948 s idle in one service-owned domain whose
two observations share root/DT/command `0x39aa0000`/`0x39c00000`/`0x39e00000`
with `installs=1`. The local stop verified `ChipCmd` 12 -> 0 and `IMR0` 32821 ->
0 with `stopRetired` 1024, stop re-added 1024 current pages so the final
identity set is exactly 1024 pages (4,194,304 B), device page faults stayed
zero, and 3/3 ordinary probes succeeded after the physical resume.

Deployed implementation commit: `6931c8a6ee583482ce5bf373d1dfbee8f76cc954`.
This documentation update is not a deployed revision.

Round42 result and archive are outside this source repository:
[Round42 result](<../../docs/m2-3w-round42-result.md>) and
[evidence archive](<../../docs/evidence/r42-final-20261103.tgz>)
(SHA256 `65306b4890c9b7fc7ca990d0ee3acdc0f27a950d640f2c9849021f0dadeff065`).

The rearm observation ring remains capped at 4096 records, so
`rtl812x-rxpost-state` reports `degraded` with a wrapped prefix while `dropped`
stays zero; that is an observer capacity bound, not a traffic failure.

## Accepted Round41 / restore RX interrupt handling after fixed DMA entry

Base: `223ac39a05cbcc74d91bce2f98bfbd186ac315a7`, the recorded Round40 failure
successor (tree `971608bdda97ffd0bcf9af0cbfb265c061567431`). The deployed
Round40 implementation is `b64c87cd453e9bd67015b3d8054c4a0eb57bc42d`.
Its original capture was independently reanalyzed: 6 checks pass and 8 fail,
with the same JSON result. Raw RX descriptors prove 104 hardware completions
that the software never consumed after entry.

Candidate: Lucy **1.1.226** / Probe **0.50.0**. Keep all three fixed DMA IOVAs,
TX native7/std5/domain4, native RX4, PhysicalLayout1, StopRecord1 and FixedDMA1.
Repair the existing entry handoff by masking/acknowledging the NIC while its
system event source is still disabled, then enabling that source and using
the original link-up/HwConfig path to restore the interrupt mask and RX/TX.
Record the small pending/masked/armed/expected IRQ diagnostics with the existing
capture; no new binary ABI or periodic RX recovery path is needed.

Use the registered fixed-object identity when observing its TX ring. A normal
entry reset clears descriptor control words while leaving old address fields,
so the old used-ring fingerprint is not the authority for this already-owned
allocation. Keep its actual fingerprint counters and scan the registered ring.

Complete the same normal workload and full Round40 goal: 4096 requests,
125-second idle, another 4096, all RX slots taken over, active identity=0,
then one local stop and three ordinary probes after physical recovery.
The same 14 checks remain; there are no new test files or methods. Use the
fixed checkout/upstream directory, `--tx 21 --rx 34`, `--check-r41`, `runs/r41`,
`org.example.round41load` and token `0x41c0de41`.

**Round41 hardware acceptance PASSED (14/14).** One planned boot and one valid
measurement. The entry diagnostics read a pending `ISR` bit of 32, IMR 0 after
`rtl8125_irq_mask_and_ack`, and an armed mask of 32821 equal to the driver's
`intrMask`; software RX advanced for the whole run. These are the observed
handoff readbacks, not a trace of individual MSI delivery. Business traffic completed
8192/8192 with 1047 ordinary probes and no peer tail packet, across a
125.177099894 s idle in a single `service-owned` domain whose two observations
share root/DT/command `0x2d0a3000`/`0x2d200000`/`0x2d400000` with `installs=1`.

RX maps and unmaps were 10479 each (posted 9455 plus 1024 install-time
preparations) with `posted 9455 = completed 8431 + stopRetired 1024`, 2635 real
replacements, 1011 of 1024 slots differing between first and final retained
generation addresses and restored 1024. The fixed TX ring, RX ring and tally
kept their IOVA slots through three standard MD/command pairs each (13 physical
pages), all 1037 bootstrap pages including every initial RX alias were retired
after the last first-IOVA publication, so the active page table holds
**identity=0** plus 1024 RX IOVA leaves; the retirement command completed with
expected = observed = 5214, and stop re-added 1024 current-buffer pages so the
final identity set is exactly 1024 pages (4,194,304 B).

RX invalidations were 10457 each over 9433 batch calls and 9455 batch slots
(`max-batch=5`, 44 saved INV/CW cycles). TX retired 9378 with rejected 0, domain
maps 9387 = 9378 + 9 capacity probes, the command ring completed 40722/40722
through 159 wraps, the local stop verified `ChipCmd` 12 -> 0 and `IMR0` 32821 ->
0 with `stopRetired` 1024, and 3/3 ordinary probes succeeded after the physical
resume. Device page faults stayed zero.

Deployed implementation commit: `ac436c3e8e3dbb625f71545b4ee913bd5d273f7e`. This
documentation update is not a deployed revision.

Round41 result and archive are outside this source repository:
[Round41 result](<../../docs/m2-3v-round41-result.md>) and
[evidence archive](<../../docs/evidence/r41-final-20261103.tgz>)
(SHA256 `8e7497896b8b004a648c241dbcbdb6e367905716b38f41f0cea9cadbbb63a93b`).

One observability limit is recorded honestly: the rearm observation ring holds
4096 records while this run logged 10653, so `rtl812x-rxpost-state` reports
`degraded` with `wrapped=6557`, `dropped=0` and a truncated prefix. That is a
capacity bound of the observer, not a traffic failure; the published baseline
still covers all 1024 slots.

## Round40 (attempt failed) / fixed DMA descriptors via standard IOVA

Base: `db0d411e6e47d95a8e2209753debf88a4ff78595`, the accepted Round39
result-documentation successor. Preserve the deployed implementation
`f041f04a95bc6e5d2e037fad1d6e1ee6100f2b78` and its client address wait/rebind
fix `18e621845b8ecfda75cb156459f05cd4c0409924`. The original Round39 capture
was independently reanalyzed: 14/14 passed, with two planned boots and one
valid measurement. Native local stop, honest stopRetired accounting and
three ordinary probes after physical recovery are now hardware-verified.

Candidate: Lucy **1.1.225** / Probe **0.49.0**. Keep TX native7/std5/domain4,
native RX4, PhysicalLayout1 and StopRecord1. A separate FixedDMA1 record
connects the original physical spans, standard MD/command mappings and the
actual hardware-programmed addresses of the TX ring, RX ring and tally.

- Keep initial sparse physical bootstrap while the device still uses PA.
- With TX admission closed and drained, stop/rebuild the NIC once and map all
  three fixed DMA objects through driver-owned standard MD/command pairs.
- Use the unused IOVA gap between dynamic TX and RX for these fixed mappings;
  ordinary TX records and RX slot/map/batch counters remain independent.
- Program and read back the fixed IOVA bases through the existing hardware
  enable path, then open normal traffic. CPU ring observations still read the
  owned physical allocations and sample their baseline after the entry reset.
- Once every RX slot has posted its first IOVA OWN, retire the entire physical
  bootstrap, including fixed-object aliases. The active PT has no identity
  leaves: TX payloads, RX buffers, descriptor rings and tally all use IOVA.
- At the existing local stop, retire fixed mappings only after DMA is stopped,
  restore the driver's PA members, release fixed owners, restore IOMMU and
  restart ordinary physical traffic. The final identity set is current RX
  pages only; the three fixed IOVA spans have been unmapped.

Keep the established 4096 + 125-second idle + 4096 workload, one explicit
local stop and three post-exit probes. Reuse the accepted address-rebinding
behavior for startup probes because entry also resets the link. Keep the
same 14 checks and existing fixture methods; no additional failure matrix.
Use the same fixed checkout and upstream directory, `--tx 21 --rx 34`,
`--check-r40`, `runs/r40`, `org.example.round40load`, token `0x40c0de40`.
**Round40 hardware attempt FAILED: 6 checks passed, 8 failed.** One planned
boot, zero valid measurements. The Mac build and fixed-object mapping/readback
steps completed. TX ring 0x2e25e000/32768, RX ring 0x2e266000/16384 and tally
0x388e52000/192 map to their reserved IOVAs; all six map/unmap INV/CW records
and PA -> IOVA -> PA register readbacks agree.

Application traffic failed: 80 successful UDP send calls, zero replies and no
business/window packets at the peer; the client eventually reported errno 65.
Twenty pre-entry and three post-exit probes succeeded. Native RX posted,
completed and replaced stayed zero, so bootstrap retirement never occurred.

Independent raw inspection narrows this further: the active-window RX baseline
at 80.223163644 s contains 104 completed hardware descriptors in slots 0..103,
while the driver is still at slot 0 and all 71 rearm records predate entry.
The NIC did use the fixed IOVA RX ring; the software receive path did not
consume its completions. There are 116 completed standard TX mappings; the
independent TX timer can reap these without proving NIC IRQ recovery. Most of
the retained TX frames are 42 bytes, consistent with neighbor discovery retry,
but their Ethernet headers were not retained.

The focused next step is the entry IRQ handoff. R40 left the system event
source disabled while HwConfig enabled the device interrupt mask and the PHY
came up, then enabled the source without first masking and acknowledging the
pending device status. A lost/pending MSI is an inference from this order and
the raw RX evidence, not a directly captured ISR trace. Ordinary physical
traffic recovered on exit, and the system was disarmed after the attempt.

Failure evidence is outside this source repository:
[Round40 failure report](<../../docs/m2-3u-round40-result.md>) and
[evidence archive](<../../docs/evidence/r40-failure-20261103.tgz>)
(SHA256 `05a363f529fd99fe19d3f849e4bb213e994f059e742c1d9dd16c1282a8dba7ae`).

## Accepted Round39 / local NIC stop without peer drain packets

Base: `00b12033c60fb88f51618fde5e8b908014f072cf`, the accepted Round38
result-documentation successor. The deployed implementation is
`6910d03b298fc03550edda207a03be4fdd98263f`; retain its checker-only correction
`5bcb339c53c84fd262742e1091aa978502b2409c` for device-read-only TX IOVA leaves.
The original Round38 capture was independently reanalyzed: all 14 checks
passed, with the active identity set reduced to its 13 fixed DMA pages.

Candidate: Lucy **1.1.224** / Probe **0.48.0**. Native RX advances to ABI4
without changing its snapshot sizes; the former reserved counters now record
stop-retired descriptors separately from real completed receives. TX
native7/std5/domain4 and PhysicalLayout1 remain unchanged.

- Close TX admission and confirm all outstanding TX mappings retired first.
- Use Lucy's existing NIC reset/restart path under its normal exclusion,
  with actual ChipCmd and interrupt-mask readback before RX mappings retire.
- Reclaim all 1024 RX slots locally with the existing standard unmap and
  current-PA cover operations. Uncompleted OWN entries keep tDone=0 and count
  as stopRetired, so posted equals completed plus stopRetired.
- After original IOMMU state is restored, rebuild the physical rings and
  use the existing hardware/link startup path before reporting resume.
- Keep a compact 96-byte stop record. Preserve the Round38 active/final page
  table evidence and the same 14 normal checks, replacing the two peer-tail
  checks with local stop and ordinary-traffic recovery.

The normal workload stays 4096 + 125-second idle + 4096, followed by one
explicit stop. The client makes no network requests while waiting for stop;
it sends the existing three ordinary probes only after resume. No R28T/R29D
exchange is required by the native session. Legacy finite helpers remain
separate from this current path. Keep the same fixed checkout and upstream
input directory; do not create a source copy or worktree for the round.
Generator selection remains `--tx 21 --rx 34`, with `--check-r39`, `runs/r39`,
`org.example.round39load` and token `0x39c0de39`.

**Round39 hardware acceptance PASSED (14/14).** Two planned boots were needed
and one measurement is valid. The first boot completed the local stop and
resume (the client saw stopped and `resumed=1`) but its first post-exit probe
failed with `EADDRNOTAVAIL`, because configd withdrew and re-published en2's
manual address around the NIC reset while the client still held the pre-stop
socket. The client now waits up to 20 s for the declared address and rebinds a
fresh socket per probe; that is a tools-only change, the kexts were unchanged.

In the valid run the stop record shows `stopCalls=1`, `resetVerified=1`,
`ChipCmd` 12 -> 0, `IMR0` 32821 -> 0, `rxNext` 599 -> 0, `stopRetired=1024` and
`restored=1024`. TX admission closed and drained at 163,823,246,182 ns, the
registers read back stopped at 163,823,743,412 ns, the last unmap and physical
OWN followed at 163,837,864,436 and 163,837,870,206 ns, the resume began at
163,838,902,997 ns and completed at 164,277,231,944 ns after real link and
RX/TX enable, and the teardown ended at 164,278,501,125 ns. The peer log holds
no `peer_tail_*` record, the client sent nothing while waiting for stop, and
3/3 ordinary probes succeeded after resume.

Completion accounting is `posted 9670 = completed 8646 + stopRetired 1024`;
RX maps and unmaps were 10694 = 9670 + 1024 preparations, restored 1024, with
2610 real replacements and owners/boundPairs/pending/nativeActive zero. The
sparse page set kept 13 fixed pages, 1037 bootstrap pages, removed 1024 after
takeover, added 1024 at stop and ended at 1037 identity pages with the arena
cursor at 141. RX batch invalidations were 10679 each over 9655 calls and 9670
slots (`max-batch=3`, 30 saved cycles). TX retired 9248, domain maps 9257 =
9248 + 9 probes, the command ring completed 40900/40900 through 159 wraps, and
8192/8192 replies crossed 125.1780 s idle.

Deployed implementation commit: `f041f04a95bc6e5d2e037fad1d6e1ee6100f2b78`;
the client fix is `18e621845b8ecfda75cb156459f05cd4c0409924`. This
documentation update is not a deployed revision.

Round39 result and archive are outside this source repository:
[Round39 result](<../../docs/m2-3t-round39-result.md>) and
[evidence archive](<../../docs/evidence/r39-final-20261103.tgz>)
(SHA256 `6fd581d34d92f2a75c5d12be849b29e62ec96d0781f199717df28fa3f6d22fb6`).

## Accepted Round38 / retire initial RX physical bootstrap after IOVA takeover

Base: `fa65abf486a2b181ceae9ad8ea4c42ff7e911940`, the documentation successor
of the accepted Round37 implementation `bbeed6028f249ec842733b5fe685e87efc654110`.
Round37's original capture was independently reanalyzed: all 14 checks passed.
Its implementation tree exactly matches the prepared Round38 preimage.

Candidate: Lucy **1.1.223** / Probe **0.47.0**; TX domain4/native7/std5,
native RX ABI3 and the separate PhysicalLayout1 export keep their sizes.

- Install still prepares mappings without replacing NIC-owned physical
  addresses. Authorize still starts normal receive processing immediately.
- Count each slot's first actual IOVA OWN. After all 1024 distinct slots have
  switched, finish the current publish batch and request one bootstrap retire.
- Remove initial RX identity leaves except pages shared with the three fixed
  DMA objects. Keep intermediate tables and confirm one INV/CW through the
  existing domain lock and command producer. RX batch counts stay separate.
- Keep one immutable post-retirement active page-table image and the existing
  40-byte Command record. Active identity leaves must equal fixed DMA pages;
  the established TX/RX IOVA windows remain mapped during ordinary traffic.
- Stop uses existing current-buffer physical restore. The final identity set
  must equal fixed DMA plus current RX pages; original RX pages no longer
  remain solely because they belonged to the initial ring.

Keep the same 14-check normal workload, 8192 requests, 125-second idle and
single stop. Ready must not wait for all-slot takeover: traffic drives it.
No per-packet physical reference counting or table-page reclamation is added.
Use the fixed checkout and `_scratch/lucy-upstream`; generator selection
remains `--tx 21 --rx 34`. The build runner uses `--check-r38`, `runs/r38`
and `org.example.round38load` with token `0x38c0de38`.
Existing focused host checks, the generated receive-loop normal flow and the
production bootstrap/backend normal flow passed during preparation.
The accepted base and final patch application are checked separately.

**Round38 hardware acceptance PASSED (14/14).** One planned boot and one valid
measurement. All 1024 distinct slots published a first real IOVA OWN, the last
at 32,723,477,204 ns; the single retirement cleared 32,723,752,225 ns, its raw
40-byte command completed at 32,723,757,215 ns with expected = observed = 5118,
and the driver callback returned at 32,724,308,425 ns, all before the stop
request. The active snapshot keeps exactly 13 identity leaves for the three
fixed DMA spans, 1024 RX IOVA leaves covering every slot start and 21 TX IOVA
leaves inside the TX window, while 1024 initial RX identity leaves were removed
from a bootstrap of 1037 pages. Stop added 1024 current-buffer pages, so the
final identity set is 1037 pages (4,247,552 B) = 13 fixed + 1024 current RX,
with the arena cursor at 183 pages. RX logical maps/unmaps were 10763 each
(9739 posted plus 1024 preparations) with 10716 confirmed invalidations over
9692 batch calls and 9739 batch slots, `max-batch=10`, `pending-batch=0` and 94
saved INV/CW cycles; the separate bootstrap retirement and the 1024 restore
covers stay out of that identity. TX retired 10308 with rejected 0, domain maps
10317 = 10308 + 9 probes, the command ring completed 43094/43094 through 168
wraps, 8192/8192 replies crossed 125.1705 s idle, and 3/3 post-exit ordinary
probes succeeded.

The first analysis of this capture failed one check because the active-tree
walker demanded IW from every present leaf. The 21 TX IOVA leaves are
device-read-only by the established direction contract, so the checker now
allows the missing IW only inside the TX window and the fixture maps its TX leaf
read-only as well. That is a tool-only change: the deployed kext binaries are
unchanged, and a rebuild reproduced identical Lucy bytes with only the linker
assigned Probe UUID differing.

Deployed source commit: `6910d03b298fc03550edda207a03be4fdd98263f`; the
checker fix is `5bcb339c53c84fd262742e1091aa978502b2409c`. This documentation
update is not a deployed revision.

Round38 result and archive are outside this source repository:
[Round38 result](<../../docs/m2-3s-round38-result.md>) and
[evidence archive](<../../docs/evidence/r38-final-20261103.tgz>)
(SHA256 `acfc8230c13ed19403d9b724da478f69f5074e3d41ac0b3e3db4052e9245b545`).

## Accepted Round37 / owned sparse physical DMA mappings

Base: `11b7c10975f8fd021624f10bc23fa9863231f1ca`, the documentation successor
of the accepted Round36 implementation `70d638df5bb3a5b5c421079107abe17b61b2cd64`.
Round36's original capture was independently reanalyzed: all 14 checks passed.
Its implementation tree exactly matches the prepared Round37 preimage.

Candidate: Lucy **1.1.222** / Probe **0.46.0**; TX domain4/native7/std5 and
native RX ABI3 remain unchanged. A separate 64-byte PhysicalLayout records
Lucy's owned TX descriptor ring, RX descriptor ring and hardware statistics
buffer, with the ring generation and each actual physical span.

- Native sessions start with an empty root and add 4 KiB identity leaves only
  for those fixed DMA spans and the 1024 ordinary RX bootstrap buffers.
- Current buffers restored at stop receive only their required 4 KiB leaves;
  missing mappings are confirmed before physical OWN is published.
- Bootstrap, IOVA and restore tables use the existing arena's available space
  in sequence. TX standard mapping and RX batch16 behavior remain in place.
- The final raw page table is checked against the union of fixed DMA,
  original RX and restored RX page spans. Every remaining leaf must be a
  4 KiB identity leaf; no blanket 0..16 GiB identity map is built.

The existing 14-check normal run remains the acceptance workload. Bootstrap
mappings remain until domain teardown; active removal is a later change.
Restore cover invalidations are separate from RX map/unmap batch savings.
Use the fixed Git checkout and `_scratch/lucy-upstream`; generator selection
remains `--tx 21 --rx 34`. The build runner uses `--check-r37`, `runs/r37`
and `org.example.round37load` with token `0x37c0de37`.

**Round37 hardware acceptance PASSED (14/14).** One planned boot and one valid
measurement. `physical-mode` was `owned-sparse-4k`; the 64-byte
`r37-physical-layout.bin` reported version 1, count 3 and generation 2 with the
real spans txRing 663240704/32,768 B, rxRing 663273472/16,384 B and tally
15,042,269,184/192 B (13 fixed pages). Bootstrap covered 1037 pages (13 fixed
plus 1024 initial RX pages), the restore phase added 201 pages, and the final
page-table walk found exactly 1238 unique 4 KiB identity leaves (5,070,848 B)
matching the union of fixed DMA, original RX and current RX spans; the arena
cursor used only 136 pages. All 1024 restore covers succeeded with no failures
and no extra commands for already-covered slots. RX logical maps/unmaps were
10669 each (9645 posted plus 1024 preparations) with 10639 confirmed
invalidations over 9615 batch calls and 9645 batch slots, `max-batch=4`,
`pending-batch=0` and 60 saved INV/CW cycles. posted equalled completed at
9645, 2587 real replacements occurred, 861 of 1024 slots differed between first
and final retained generation addresses, all 1024 slots returned to their
current mbuf, and owners/boundPairs/pending were zero. TX retired 10278 with
rejected 0; domain maps 10287 = 10278 + 9 capacity probes; the command ring
completed 42056/42056 through 164 wraps. The setup worker exited before both
domain observations, which shared the same root/DT/command addresses across the
125.1111 s idle; R28T drained 1008/1008, R29D completed before TX close, and
3/3 post-exit ordinary probes succeeded.

Deployed source commit: `bbeed6028f249ec842733b5fe685e87efc654110`. This
documentation update is not a deployed revision.

Round37 result and archive are outside this source repository:
[Round37 result](<../../docs/m2-3r-round37-result.md>) and
[evidence archive](<../../docs/evidence/r37-final-20261103.tgz>)
(SHA256 `c1b23f591e3a6ff9955893167ac30a15bebeab93bc34cf4ef0cf8324a94defc8`).

## Accepted Round36 / RX invalidation batches

Base: `051c90050b195d5ae388018da4463e785c38e9ac`, the documentation successor
of the accepted Round35 implementation `e925368111fd92a567d348040a6026e63205ae70`.
Round35's original capture was independently reanalyzed: all 14 checks passed.

Candidate versions: Lucy **1.1.221** / Probe **0.45.0**. TX remains
domain4/native7/std5; native RX uses ABI3 with unchanged record sizes.

- Keep Lucy's ordinary RX ring and 1024 reusable MD/Cmd pairs.
- In each receive call, collect up to 16 adjacent completed slots, bounded by
  the current packet budget. Process partial batches immediately.
- Record completion, clear the batch's PTEs and confirm one invalidation before
  standard command completion and ordinary mbuf replacement/delivery.
- Prepare the current buffers, publish their PTEs and confirm one invalidation
  before standard map callbacks return and any new IOVA OWN is published.
- Keep install and drain on the established scalar paths. No batch is carried
  across receive calls or idle intervals.
- Preserve per-slot lifecycle evidence. A batch shares its confirmed command
  record; packed map/unmap group fields identify the first slot and width.
  Report actual invalidation counts, group widths and saved confirmation cycles.

The existing 14-check normal run remains the acceptance workload. Its RX
mapping evidence now accepts confirmed shared commands within one declared
batch and checks actual invalidation counts. Report savings against the same
run's logical map/unmap count; no fixed reduction percentage is required.

Use the same fixed Git checkout, upstream `_scratch/lucy-upstream` and SDK.
The native template family remains `--tx 21 --rx 34`; the build runner uses
`--check-r36`, `runs/r36` and `org.example.round36load` with token `0x36c0de36`.

**Round36 hardware acceptance PASSED (14/14).** One planned boot and one valid
measurement. The normal run really produced multi-slot batches: `max-batch=5`
on both the driver and backend sides, with `pending-batch=0` at the end. RX
logical maps and unmaps were 10654 each (9630 posted DMA plus 1024 install-time
preparations); confirmed invalidations were 10643 each, spread over 9619 batch
calls and 9630 batch slots, so the run saved 22 INV/CW cycles and the actual
invalidation total stayed below the logical call total. The mean batch width was
1.0011 because most receive calls had a single completed slot, and all 9630
batch slots still carry per-slot PTE, PA/IOVA, generation and
map/OWN/done/unmap ordering. posted equalled completed at 9630, 2599 real
replacements occurred, 962 of 1024 slots differed between first and final
retained generation addresses, all 1024 slots returned to their current mbuf,
and owners/boundPairs/pending were zero. TX retired 10264 with rejected 0;
domain maps 10273 = 10264 + 9 capacity probes; the command ring completed
41835/41835 through 163 wraps. The setup worker exited before both domain
observations, which shared the same root/DT/command addresses across the
125.1829 s idle; R28T drained 1008/1008, R29D completed before TX close, and
3/3 post-exit ordinary probes succeeded.

Deployed source commit: `70d638df5bb3a5b5c421079107abe17b61b2cd64`. This
documentation update is not a deployed revision.

Round36 result and archive are outside this source repository:
[Round36 result](<../../docs/m2-3q-round36-result.md>) and
[evidence archive](<../../docs/evidence/r36-final-20261103.tgz>)
(SHA256 `f9a997d3cd16cb4c11dbfec161cc7f3ef7698dcc5509f813d089486cf0432e1a`).

## Accepted Round35 / native RX bootstrap on Lucy's ordinary ring

Base: `18be5c49b911b351f7ec7fa5b52b23d46581666e`.
Candidate: Lucy **1.1.220** / Probe **0.44.0**. TX retains domain4/native7/std5;
native RX advances to ABI2 with an independent ring identity.

Round34 passed its normal hardware run and all 14 checks: 8192 replies,
125.201 s idle, 10578 RX map/unmap pairs, 9554 completed IOVA receives and
2669 real buffer replacements. Round35 removes the experimental R15 pool
from the service-owned native RX session:

- Native Prepare borrows the existing 1024 Lucy RX buffers and temporarily
  uses copy-only receive processing to keep their physical addresses stable.
  It allocates no replacement ring and no experimental spare buffers.
- The probe covers these current buffers for the initial physical DMA phase.
  Install creates the existing driver-owned MD/Cmd pairs; native Authorize
  then opens ordinary `replaceOrCopyPacket` and per-slot unmap/remap.
- Lucy owns its ordinary RX mbufs throughout. The session no longer transfers
  mbuf ownership through an experimental pool or calls that pool's control RPC.
- Stop retains the measured current-buffer physical restore, R28T/R29D and TX
  teardown. Only after hardware registers are restored does native ResumePhysical
  reopen ordinary physical RX replacement.
- The same 14-check normal run verifies the native ring identity, 1024 bootstrap
  ranges, zero experimental pool/spares/RPCs, real replacement and final release.

Use the fixed `repos/AMDIOMMU` checkout with a `round35-native-ring` Git branch.
On the Mac, reuse its existing checkout and MacKernelSDK. Prepare pristine files
from upstream `639144d1f284a9fee222a518691b01494f5e265d` in the reusable
`_scratch/lucy-upstream` directory, then run:

```sh
sh tools/r27/build.sh _scratch/lucy-upstream
```

The native generator family remains `--tx 21 --rx 34`; this round evolves that
implementation in place. Run defaults are `runs/r35` and `org.example.round35load`,
with token `0x35c0de35`. The compatible `R31Stop` RPC and service-owned domain
continue. Software checks reuse the existing focused cases.

**Round35 hardware acceptance PASSED (14/14).** One planned boot and one valid
measurement. Both sides report `lucy-normal-ring` with the same nonzero ring id
28726637338; the probe covered 1024 real bootstrap ranges and recorded zero
experimental pool RPCs and zero spares, while the driver reported
`experimental-pool=0` and `spares=0`. Native Prepare/Authorize ran on Lucy's
ordinary ring, `ResumePhysical` completed at 172749769439 ns between
translate-off and the driver's normal resume, and per-slot replacement resumed
from that instant. RX maps and unmaps were both 10652 = 9628 posted DMA plus
1024 install-time preparations; posted equalled completed at 9628, 2598 real
replacements occurred, 933 of 1024 slots differed between first and final
retained generation addresses, and all 1024 slots returned to their current
mbuf with owners/boundPairs/pending zero. TX retired 10295 with rejected 0;
domain maps 10304 = 10295 + 9 capacity probes; the command ring completed
41915/41915 through 163 wraps. The setup worker exited before both domain
observations, which shared the same root/DT/command addresses across the
125.1189 s idle; R28T drained 1008/1008, R29D completed before TX close, and
3/3 post-exit ordinary probes succeeded.

Deployed source commit: `e925368111fd92a567d348040a6026e63205ae70`. This
documentation update is not a deployed revision.

Round35 result and archive are outside this source repository:
[Round35 result](<../../docs/m2-3p-round35-result.md>) and
[evidence archive](<../../docs/evidence/r35-final-20261103.tgz>)
(SHA256 `3db51468bc095b4cee8194708c7e2760de54387b25d7ce607f971c0bd7192c55`).

This step retains the necessary physical identity coverage during entry and
restoration, and the existing synchronous per-slot RX invalidations. RX batch
mapping is the next separate performance step after normal-ring bootstrap passes.

## Historical Round34 / driver-owned RX streaming mappings

Base: `648e729c73a345cdee3899ca634ee32f057c8d78`.
Candidate: Lucy **1.1.219** / Probe **0.43.0**. TX retains domain4/native7/std5.

Round33 passed the normal hardware run and all 14 checks: setup returned before
both traffic phases, the same service-owned domain survived 125.159 s idle,
8192 replies completed, and a separate teardown worker restored all resources.
Round34 advances the receive-buffer data path:

- Lucy owns one reusable memory-descriptor/DMA-command pair per RX ring slot.
- Completion ends the old mapping before normal `replaceOrCopyPacket` processing.
  The current mbuf is then mapped again, and confirmed invalidation precedes OWN.
- Native replacement uses the driver's normal RX pool. The experimental R15
  object remains only for bootstrap; its ring mbuf ownership is transferred to
  Lucy and its spare-buffer cycling is no longer the active receive path.
- Stop restores each slot to its current mbuf's physical address, after ensuring
  identity coverage. The existing R28T/R29D, TX drain and register restore remain.
- The same normal 4096 + 125 s idle + 4096 run proves real replacement/remapping
  and final release. The protocol already carries full-MTU packets; no artificial
  replacement trigger or additional traffic matrix is required.

Keep the source in the fixed `repos/AMDIOMMU` checkout and use Git branches and
commits for rounds. On the Mac, reuse its existing checkout and MacKernelSDK.
Prepare pristine upstream files from `639144d1f284a9fee222a518691b01494f5e265d`
in the reusable `_scratch/lucy-upstream` directory, then run:

```sh
sh tools/r27/build.sh _scratch/lucy-upstream
```

Generation selects `--tx 21 --rx 34`. Run defaults are `runs/r34` and
`org.example.round34load`. The `R31Stop` RPC and service-owned domain continue.
The build uses focused existing checks; this round does not add unit tests or
expand failure-injection coverage.

**Round34 hardware acceptance PASSED (14/14).** One planned boot and one valid
measurement used token `0x34c0de34`. Lucy owned 1024 reusable MD/Cmd pairs; the
setup worker exited at 32,157,545,362 ns and both active-domain observations
report `installs=1` with the same root/DT/command addresses
`0x31880000`/`0x31a00000`/`0x31c00000` across the 125.2008 s idle. RX maps and
unmaps were both 10578 = 9554 posted DMA operations + 1024 install-time
preparations that never published an IOVA OWN; posted equalled completed at
9554, 2669 real replacements occurred, 976 of 1024 slots had different physical addresses in their first and final
retained generations, and all 1024 slots returned to their current mbuf's physical address
with owners/boundPairs/pending zero. TX retired 10382 with rejected 0; domain
maps 10391 = 10382 + 9 capacity probes; the command ring completed 41941/41941
through 163 wraps, the higher rate being the cost of per-slot streaming.
R28T drained 1024/1024, R29D completed before TX close, registers were restored
and 3/3 post-exit ordinary probes succeeded.

Deployed source commit: `09c1cff732cf953c9d7bfe652acbf6eb97a534fc`. This
documentation update is not a deployed revision.

Round34 result and archive are outside this source repository:
[Round34 result](<../../docs/m2-3o-round34-result.md>) and
[evidence archive](<../../docs/evidence/r34-final-20261103.tgz>)
(SHA256 `d418e94aebc262b64da4a392f67f12e7d6a0e6b050644bf0325f109b7bfa7e5a`).

This step uses per-slot streaming mappings, not upstream's 64-by-16 RX batch
optimization; bootstrap identity mappings still remain.

## Historical Round33 / service-owned device domain

Base: `fc0da752550e08c497fe8c105f4056655b68b8b9`.
Candidate: Lucy **1.1.218** / Probe **0.42.0**; domain4/native7/std5, RX4, pool2.

Round32 passed its hardware run and all 14 checks, including dynamic IOVA
allocation, sixteen live mappings, the wide-map capacity probe, zero TX
rejections and complete RX1024 recovery. Round33 moves the hardware domain's
lifetime out of the long-running measurement worker:

- The service owns the page tables, device table, command/event buffers,
  MMIO mappings, saved register state and retained pool/driver dependencies.
- The setup worker installs the domain and returns. Ordinary mapped DMA
  continues with the existing TX/RX paths while no setup worker is running.
- The existing `R31Stop` property schedules a separate teardown worker,
  which completes event sampling, RX/R29D/TX drain and hardware restoration
  before releasing the domain's resources.
- The normal 4096 + 125 s idle + 4096 load records active-domain observations
  before each phase. Both must show setup already finished and the same
  page-table, device-table and command-buffer addresses.

Keep using the fixed `repos/AMDIOMMU` checkout with Git branches and commits;
do not create a source directory or worktree for each round. Prepare pristine
files from upstream `639144d1f284a9fee222a518691b01494f5e265d` in the reusable
`_scratch/lucy-upstream` directory, retaining the existing MacKernelSDK:

```sh
sh tools/r27/build.sh _scratch/lucy-upstream
```

Generation selects `--tx 21 --rx 33`. Run defaults are `runs/r33` and
`org.example.round33load`. ABI layouts and the compatible stop RPC remain
unchanged.

**Round33 hardware acceptance PASSED (14/14).** One planned boot and one valid
measurement used token `0x33c0de33`. The setup worker exited at mach
31,810,054,080 ns, and both active-domain observations, taken before each
4096-request phase, report `setup_worker=0`, `installs=1` and the same
root/DT/command addresses `0x34a60000`/`0x34c00000`/`0x34e00000`; all 8192
replies crossed the 125.159 s idle. `R31Stop` scheduled a separate teardown
worker that began 10.5 us after the stop request, drained R28T 1024/1024,
completed R29D seq 1024 before closing TX, restored the registers and only then
released the domain. TX mapped/retired 10303 with rejected 0; domain maps were
10312 = 10303 + 9 capacity probes; the command ring completed 22675/22675
through 88 wraps; RX1024 mapped/unmapped 1024/1024 with 9368 completions in
four L1 tables; owners/pending/pinned/ring/livePages zero, no device page
fault, 3/3 post-exit ordinary probes.

Deployed source commit: `717cb625f5a560257dfd000e539966153fe93673`. This
documentation update is not a deployed revision.

Round33 result and archive are outside this source repository:
[Round33 result](<../../docs/m2-3n-round33-result.md>) and
[evidence archive](<../../docs/evidence/r33-final-20261103.tgz>)
(SHA256 `b9462912ac89ae17d17e08c81f0ce0237c81e823622b1063950828ff1704a0e9`).

This round retains the existing RX pool and bootstrap identity mappings.
The next functional step is Lucy-owned native RX command/buffer replacement
and remapping, using the persistent domain established here.

## Historical Round32 / dynamic IOVA mappings

Base: `561400ae756199035baa9b5593619835bd8471de`.
Candidate: Lucy **1.1.217** / Probe **0.41.0**; domain4/native7/std5, RX4, pool2.

Round31 completed its explicit-stop session and clean exit, but the unchanged
strict analyzer returned **13/14** because one TX frame was rejected. Rechecking
the raw capture found cover calls/rejects both zero. The source permits a
gate refusal after dequeue without increasing mapAttempts; the previous
legacy-cover diagnosis is therefore unsupported. Round32 acquires admission
before dequeuing and retains queued traffic while admission is closed.

The main new capability is variable-size DMA mapping:

- Allocate TX IOVA pages on demand from a bounded 256-page (1 MiB) arena,
  with 16 independent live mapping records and up to 32 pages per mapping.
- Keep each record's allocation separate from its record index and retain
  mapping-local PTE evidence. Backend physical layout supports up to 16 runs.
- Place RX1024 at 64 GiB + 2 MiB, separate from the TX arena. Five L1 tables
  cover the TX region and the four RX regions together.
- Before opening TX admission, use real IODMACommands to keep eight mappings
  live (one eight-page mapping and seven one-page mappings), retire them,
  then map eight pages again to prove reuse. These nine mappings remain in
  cumulative domain counters and have separate probe counts and retained
  evidence; they are capacity checks, not NIC DMA transfers.
- Reuse the Round31 explicit-stop session and its 4096 + 125 s idle + 4096
  ordinary network workload, R28T/R29D and normal recovery.

From this repository, use a fresh upstream tree at
`639144d1f284a9fee222a518691b01494f5e265d` and the existing MacKernelSDK,
prepared in the fixed `_scratch/lucy-upstream` directory:

```sh
sh tools/r27/build.sh _scratch/lucy-upstream
```

Generation selects `--tx 21 --rx 32`. Run defaults are `runs/r32` and
`org.example.round32load`; the compatible control helper remains
`tools/r31/session.py`, including the accepted registry-entry lookup fix.
Normal load submits the single stop request and supplies the drain tail.

**Round32 hardware acceptance PASSED (14/14).** One planned boot and one valid
measurement used token `0x32c0de32`. The capacity probe ran before gate-open:
9 maps and 9 confirmed unmaps, eight simultaneous owners, an eight-page mapping,
and an eight-page remap that reused base page 0. Domain maps were 10346 =
10337 network TX + 9 probe mappings; TX retired 10337 with rejected 0, RX1024
mapped/unmapped 1024/1024 with 9419 completions in four L1 tables at 64 GiB +
2 MiB, owners/pending/pinned/ring zero, no device page fault, 8192/8192 replies,
125.114 s idle, one explicit stop, R28T 1024/1024, R29D seq 1024 and 3/3
post-exit probes.

Deployed source commit: `d2ffc777b6b23b72fd5c1bfacd2519e5a67bca71`. This
documentation update is not a deployed revision.

Round32 result and archive are outside this source repository:
[Round32 result](<../../docs/m2-3m-round32-result.md>) and
[evidence archive](<../../docs/evidence/r32-final-20261103.tgz>)
(SHA256 `b1e69f05a51ea85f6cde96a6a76f00c2218debc8107d77607a8a465f46e388cd`).

## Historical Round31 / explicit-stop mapping session

Base: `d826cd3093d18625097f03b6a988a98637d622b1`.
Candidate: Lucy **1.1.216** / Probe **0.40.0**. The wire layouts stay
domain3/native7/std5, RX4 and pool2.

Round30 passed one planned boot and one valid measurement: all 1024 RX slots
mapped and restored, 9307 RX completions, 8192/8192 application replies and
10291/10291 confirmed TX retirements. Round31 gives the active mapping session
an explicit lifetime:

- Add `.session` to `.std.alltx.rxstd` to run on a dedicated kernel worker.
- Keep RX1024 and ordinary standard TX active until an explicit stop request;
  the session has no automatic 60-second window or 120-second TX/RX lease.
- Submit `R31Stop=true` through the service property interface. The request
  thread only records the stop; the worker performs the existing RX drain,
  R29D exchange, TX retirement and DTE/command-engine restoration.
- Keep the existing 8192 requests, split 4096 + 4096 around one 125-second
  idle period, then request stop and verify the same complete exit.

From this repository, use a fresh upstream tree at
`639144d1f284a9fee222a518691b01494f5e265d` with the existing MacKernelSDK:

```sh
sh tools/r27/build.sh _scratch/r31-upstream
```

Generation selects `--tx 21 --rx 31`. Run defaults are `runs/r31` and
`org.example.round31load`; compatibility entry points remain under `tools/r27`.
`python3 -B tools/r31/session.py status` reads the live state;
`sudo python3 -B tools/r31/session.py stop` requests the normal asynchronous exit.
The finite load requests this stop itself after its second half.

**Round31 session PASSED; strict 14-check acceptance NOT met (13/14).** Two boots
were made. The first exposed an RPC defect: the probe is an unregistered
IOService nub, so `IOServiceMatching` found nothing; the stop is now sent to the
registry entry found by walking the IOService plane (commit `9461218`, the
deployed source). The single valid measurement used token `0x31c0de31`:
4096 + 125.105 s idle + 4096, 8192/8192 replies, one stop request, R28T
1024/1024, R29D seq 1024, RX1024 map/unmap 1024/1024 with 9454 completions,
TX retired 10339, owners/pending/pinned/ring 0, and 3/3 post-exit probes.

The failing check is the pre-existing cumulative TX rule: `driver.rejected=1`.
Independent review found `R26TxAttempts == R26TxMapped == 10339`, but also
`coverCalls == coverRejects == 0` in both raw block and driver properties.
The earlier legacy-cover diagnosis was incorrect: the gate-refusal branch in
`r17TxMap()` increments rejected before a mapping attempt, after the frame has
already been dequeued. The counts identify this admission path; they do not
identify the specific packet or which transition it met. Application replies,
tails and final cleanup all completed. Keep the 13/14 result and incorporate
the dequeue/admission fix into the dynamic IOVA round, with no separate
cover-retest round. Deployed source: `9461218491846fd5432b31b166e596c5ee597642`.

Round31 result and archive are outside this source repository:
[Round31 result](<../../docs/m2-3l-round31-result.md>) and
[evidence archive](<../../docs/evidence/r31-final-20261103.tgz>)
(SHA256 `8e328133575032db8223ca1959531d4e99bc4be99e5979be681d5f752659ccf0`).

## Historical Round30 / full-ring cyclic RX1024

Base: `27664efbafdbea9e3f13141aff5c49d01c42a8b8`.
Candidate: Lucy **1.1.215** / Probe **0.39.0**; domain3/native7/std5, RX4, pool2.

Round29 passed its complete hardware measurement: 8192/8192 main replies,
64 RX mappings with 640 completions, 1024/1024 tails, the R29D echo, and
10284/10284 confirmed TX retirements with zero remaining owners. Deployment
involved two boots; the first had no running peer and was not a valid measurement.
See [Round29 result](../../docs/m2-3j-round29-result.md).

Round30 expands the same path to all 1024 RX ring slots:

- Retain and standard-map 1024 spare buffers, then reuse each mapping cyclically.
- Give RX an 8 MiB IOVA range across five L1 tables alongside the existing TX window.
- Restore every physical RX descriptor before confirmed unmap and buffer release.
- Keep four TX slots, 8192 main requests, bounded R28T tails and the R29D final echo.

Use a fresh upstream tree at `639144d1f284a9fee222a518691b01494f5e265d`
with the existing MacKernelSDK, then run from this repository:

```sh
sh tools/r27/build.sh _scratch/r30-upstream
```

The build runs focused software checks against generated `--tx 21 --rx 30`
source. RX4 sizes are Snapshot 311376, Request 344192 and BackendSnapshot 204864
bytes; pool2 sizes are Snapshot 114808 and Request 114856 bytes. Large kernel
control/evidence objects stay in heap or persistent storage. The normal analyzer
fixture covers 1024 associations, first four cycles per association and all five
L1 tables. Defaults are `runs/r30` and `org.example.round30load`; compatibility
entry points and evidence filenames under `tools/r27` remain in use.

**Round30 hardware acceptance PASSED.** The tested implementation was committed
before deployment as `874ea550e06bdf733398053dcd4e5165ada106d8` (tree
`09e425939dad870c6b930ded58cccfd2eba96c7a`), then built and deployed as Lucy
1.1.215 / Probe 0.39.0. One planned boot and one valid finite measurement used
token `0x30c0de30`.

- Application: 8192/8192 valid replies, bad 0, 512×16, no retransmission; R28T
  tails 1024/1024 and one R29D echo (seq 1024) before TX close.
- RX: 1024/1024 standard maps and confirmed unmaps over five L1 tables,
  1024 retained spares, 9307 posted/completed, 4096 retained first-four-cycle
  samples, restored 1024, pending 0, live owners 0.
- TX: driver/backend mapped and retired 10291/10291, held/live 0; owners,
  pending, pinned and ring 0; commands 22633 submitted and completed, 88 wraps;
  device page faults 0.
- After exit, three ordinary network probes succeeded; strict analyzer `ok=true`,
  13/13 checks; capture complete with no errors.

This documentation update is not a newly deployed or hardware-tested revision;
the deployed source commit remains `874ea55`. Next work is outside this round:
sleep/wake, multi-device or a general system mapper are not part of RX1024.

Round30 result and archive are outside this source repository:
[Round30 result](<../../docs/m2-3k-round30-result.md>) and
[evidence archive](<../../docs/evidence/r30-final-20261103.tgz>)
(SHA256 `f73fba0aeb668228fbe64bcea181eee6b4ed2b3b0bb48b4a2f486d00f62db857`).

## Historical Round29 / normal TX retirement and tail completion

Base: `feb014bd0172cbc0e897dab8332d7a2e1fcae948`.
Candidate: Lucy **1.1.214** / Probe **0.38.0**; domain3/native7/std5, RX3.

This round fixes the two observed Round28 exit failures while keeping RX64,
four TX slots and the existing 8192-request workload:

- Wait for the driver timer and backend retirement before restoring DTE/commands.
- Confirm each standard handle after complete(), before releasing its buffer.
- Finish the current tail batch and exchange one R29D echo before closing TX.

Use a fresh upstream tree at `639144d1f284a9fee222a518691b01494f5e265d`
with the existing MacKernelSDK, then run from this repository:

```sh
sh tools/r27/build.sh _scratch/r29-upstream
```

The build runs the current main-path checks against generated `--tx 21 --rx 29`
source. The normal analyzer fixture is selected; historical corruption matrices
remain available separately. Defaults are `runs/r29` and `org.example.round29load`.

**Round29 hardware acceptance PASSED.** The tested implementation was committed
before deployment as `2b77ec8d6c4e65eb27af130cfdf5596694202884` (tree
`e5780791aee8c5d60216e401c4d402ead1049dbb`), then built and deployed as Lucy
1.1.214 / Probe 0.38.0. The single valid finite measurement used token
`0x29d1a401`. Deployment involved two boots; the first had no running peer
and was excluded from the valid measurement.

- Application: 8192/8192 valid replies, bad 0, no retransmission; tail 1024/1024;
  one R29D echo (seq 1024) confirmed before TX close.
- RX: 64/64 standard maps and unmaps, 640 posted/completed and 64 restored,
  pending 0, live owners 0.
- TX: driver mapped/retired 10284/10284, live/held 0; backend owners/pending/
  pinned/ring 0; commands 20699 submitted and completed, 80 wraps; device page
  faults 0. Ordinary traffic resumed after exit and the network remained usable.
- Strict analyzer: `ok=true`, 13/13 checks; capture complete with no errors.

This documentation update is not a newly deployed or hardware-tested revision;
the deployed source commit remains `2b77ec8`. Next stage is RX1024: full
1024-slot RX takeover, not further RX64 defensive hardening.

Round29 result and archive are outside this source repository:
[Round29 result](<../../docs/m2-3j-round29-result.md>) and
[evidence archive](<../../docs/evidence/r29-final-20261103.tgz>)
(SHA256 `36b9618a39a499ce1dba08da114a1ec52272a5883f34ae8eb1688efac906f802`).

## Historical Round28 / cyclic64 RX implementation

Round28 evolves the existing Round27 entry points in place: 64 standard-mapped RX spares are reposted cyclically, then held/disarmed, drained, restored and unmapped alongside the established four-slot ordinary all-standard TX path. Expected versions: Lucy **1.1.213** / Probe **0.37.0**. Base commit: `ae92d3869a828b82e76eeb24c59ecd91a7cbe09a`.

**Round28 hardware acceptance FAILED.** The tested implementation was committed before deployment as `39c15efad4a3c224d000ec5ee044d2629df492c3` (tree `51dd758c12a016d17fb4ae147e3edd1f9f567d60`). Actual generated-source tests, Mac integrated checks and both kext builds passed; one finite hardware run used token `0x28b10c01`, with no second run.

- Main application traffic: 8192 sent / 8192 valid replies / bad0. RX: 64 maps/unmaps, 640 real completions/restored64, every spare completed10 times (reuse9), RX pending/live owners0.
- **Overall failure:** independent tail1024 sent / 1016 received; TX backend maps10255 / confirmed retires10251, backend owners4/live slots0xf, command submissions20638 / acknowledgments20637. Later driver retire counters and the cleanup string do not override authoritative backend ownership.
- An independent analyzer contract bug also exists: producer publishes `standard-nonidentity-cyclic-map-once` while analyzer expects `standard-nonidentity-cyclic64`. The original failing verdict remains unchanged; this mismatch is not the cause of the real TX closure failure.
- Next-boot containment only: EFI/NVRAM restored to `amdiommu=arm`, finite daemon removed, exact EFI unmounted. **Four current backend owners remain unresolved/retained.** No cleanup reboot, kext unload, forced free or counter reset was used. This is not a current clean DMA exit.
- Next gap: before command-engine shutdown, independently confirm software retirement plus backend owner/slot/command closure; require per-handle backend retirement acknowledgment before driver free/count/Idle, and add negative race tests. All1024 RX-slot takeover remains future work, after this safety gap.

Full result and source-free archive are outside this source repository: [Round28 result](<../../docs/m2-3i-round28-result.md>) and [evidence archive](<../../docs/evidence/r28-final-20261103.tgz>) (SHA256 `bb4f07b5395daa356fb15763f199869e10cbead9cc18ffb0a777f70c395e3a5f`). This documentation update is not a newly deployed or hardware-tested code revision.

- Main traffic: 8192 requests in 512 batches of 16; `R27P` application protocol retained.
- Drain traffic: separate `R28T` 200-byte tails, bounded to 4096; tails are not main requests or positive business witnesses.
- RX ABI2: Snapshot 19536 bytes, Request 21632 bytes, Witness 272 bytes, Cycle 40 bytes; first four cycle samples retained per spare. Backend snapshot remains 12864 bytes. TX domain3/native6/std5 and compatibility function/property names remain unchanged.
- Defaults use `runs/r28`; the finite launchd job is `org.example.round28load`. Capture retains compatibility filenames including `R27-EXPORTS.json`, with Round28 scope and expected versions. Evidence records Git source identity, not full-source snapshots.

On macOS with Python 3.9+ and C++17, obtain a fresh upstream tree at `639144d1f284a9fee222a518691b01494f5e265d`, supplying the existing MacKernelSDK dependency:

```sh
python3 -B tools/r27/check-local.py
sh tools/r27/build.sh _scratch/r28-upstream
```

The generator selection is **`--tx 21 --rx 28`** (`--rx28` and `--rx=28` also work). Compatibility selection `--rx 27` aliases the same current cyclic canonical template at `tools/r27/driver-template.py`; it does not regenerate the historical one-shot implementation. RX15 remains historical. Generate Round28 into its own isolated tree, never overwrite or derive it from `generated/round26`. Commit tested canonical source before any later authorized deployment; deployed checkout must match that commit and remain source-clean.

## Historical Round27

Round27 introduced the finite one-shot lifecycle for 64 standard-mapped RX spares with Lucy 1.1.212 / Probe 0.36.0 and RX ABI1, based on `ddf188b7381aac84461ed2dbeb962a8592f2be87`. Its results and exact deployed commit belong to the parent project's historical report. They are not a Round28 pass, nor does this README assert that historical hardware acceptance succeeded.

## Historical Round26 baseline

This repository became the authoritative source baseline at M2-3g / Round26. Round26 used Lucy 1.1.211 / Probe 0.35.0; domain3/native6/std5, mode2 ordinary all-standard TX. Single device, fixed four slots, finite translation window; not a general production IOMapper.

## Source and evidence policy

- `kext/`, `tools/` are canonical implementation and generator inputs. `include/`, `src/`, `tests/`, `fixtures/`, `reference/` contain existing modules, tests and reference inputs.
- `generated/round26/` is the historical generated Lucy inspection/reproducibility copy; do not edit it by hand.
- Runtime evidence, kext binaries, SDKs, upstream tarballs and full patch-package before/after snapshots are not committed.

Every future patch must name the full base commit and target this repository. Verify the expected working tree and use `git apply --check` before applying a patch. Never overwrite local changes or edit the baseline to force acceptance. Source identity in evidence is a Git commit hash, not a source snapshot. Logs, raw exports, binary identities and experiment results remain separate from provenance; repository commits do not constitute hardware validation.
