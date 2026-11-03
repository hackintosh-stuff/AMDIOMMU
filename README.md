# AMDIOMMU — authoritative source repository

## Current Round35 / native RX bootstrap on Lucy's ordinary ring

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
