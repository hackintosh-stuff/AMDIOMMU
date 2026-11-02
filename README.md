# AMDIOMMU — authoritative source repository

## Round28 / cyclic64 RX implementation

Round28 evolves the existing Round27 entry points in place: 64 standard-mapped RX spares are reposted cyclically, then held/disarmed, drained, restored and unmapped alongside the established four-slot ordinary all-standard TX path. Expected versions: Lucy **1.1.213** / Probe **0.37.0**. Base commit: `ae92d3869a828b82e76eeb24c59ecd91a7cbe09a`.

This is software implementation and host-test scope, **not hardware acceptance**. macOS kext build, deployment and hardware validation remain separate; no successful Round28 hardware run is asserted here.

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
