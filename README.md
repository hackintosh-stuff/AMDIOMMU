# AMDIOMMU — authoritative source repository

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
**Round40 hardware attempt FAILED; the round is not accepted.** One planned
boot, zero valid measurements. The Mac SDK build, EFI deployment, entry
transition and exit path all completed as designed, and the three fixed
objects are provably correct: TX ring 0x2e25e000/32768, RX ring
0x2e266000/16384 and tally 0x388e52000/192 were mapped to 0x1000100000,
0x1000110000 and 0x1000120000 with every PTE pointing at the original PA and
carrying IR|IW, the six fixed map/unmap commands completed with
expected == observed, and the NIC registers read back PA before entry, IOVA
after activation and PA after exit.

Business traffic nevertheless stopped completely after the entry: the client
sent 80 frames and received none, the peer received zero business packets and
zero window probes, native RX recorded maps=1024 with posted=0 and
completed=0, so the bootstrap was never retired and active identity never
reached zero. The 20 pre-entry probes and the 3 post-exit probes succeeded, so
only the interval with the fixed IOVA entry was dead. Interface counters moved
by +117 out packets and +7 in packets, and the IOMMU reported no device page
faults. The exit path, which runs the same ring rebuild with translation off,
restored ordinary traffic, so the leading hypothesis is that the entry's NIC
reset under active translation does not re-arm the MAC's RX/TX descriptor
processing; the next step is to sample RCR/IMR0 and the rxpost baseline right
after activation before changing any ABI.

Nine of the fourteen checks failed (business integrity, session phase 2, local
stop record, TX totals, retained mappings, ordinary traffic, active page table,
and both RX lifecycle checks). The machine was disarmed and ordinary traffic
verified afterwards; the implementation commit is kept for diagnosis.

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
