# AMDIOMMU — Round26 source baseline

This repository is the authoritative source baseline starting at M2-3g / Round26 (2026-11-02). Commit source changes here; do not maintain a new independently edited source baseline in evidence archives or the parent working directory.

## Scope

- `kext/`, `tools/`: exact LF source inputs uploaded for the validated Round26 build (367 files), plus non-cache tool support files.
- `include/`, `src/`, `tests/`, `fixtures/`, `reference/`: existing project modules, tests and reference inputs.
- `generated/round26/`: exact generated Lucy C++/header used by the validated build, for source inspection and reproducibility comparison. The generator and templates remain canonical; do not edit the generated copy by hand.
- No runtime evidence, kext binaries, SDKs, upstream tarballs or full patch-package before/after snapshots are committed.

Round26: Lucy 1.1.211 / Probe 0.35.0; domain3/native6/std5, mode2 ordinary all-standard TX. Single device, fixed four slots, finite translation window; not a general production IOMapper.

## Reproduce

Use macOS, Python 3.9-compatible Python3 and the existing kernel SDK/toolchain. Obtain a **fresh** RTL812xLucy tree at upstream commit `639144d1f284a9fee222a518691b01494f5e265d` (https://github.com/Mieze/RTL812xLucy), supply its MacKernelSDK dependency, then run from this repository:

```sh
sh tools/r26/build.sh path/to/clean/RTL812xLucy
```

The path is relative to this repository. The build entry generates source, runs its focused ABI/protocol/ASan+UBSan/analyzer checks, and builds both kexts. Do not rerun injection on an already generated tree. Historical tool filenames do not imply that old hardware experiments should be rerun.

## Baseline policy

Every future patch must name the full **base commit** and target this repository. Verify the clean/expected working tree and run `git apply --check` before applying. Never silently overwrite local changes or edit the patch baseline to force acceptance. Commit the resulting source before deployment and record that commit in evidence metadata.

Evidence remains outside this repository. Source identity in evidence is a Git commit hash, not a source snapshot. Logs, raw exports, binary identities and experiment results remain separate from source provenance. Round26 original evidence/report live in the parent project's documentation tree. Repository commits do not themselves constitute hardware validation.
