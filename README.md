# AMDIOMMU — authoritative source repository

## Current Round30 / full-ring cyclic RX1024

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
