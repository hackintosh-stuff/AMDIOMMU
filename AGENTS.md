# Repository conventions

## Documentation: state, not a log

`COMPATIBILITY.md` and the compatibility section of `README.md` are state
documents. They say what is true of this driver now, not what happened round by
round.

- **State only.** Each device row states facts that hold at the time of writing:
  link speed, throughput, mapper and domain state. Do not record "round N passed
  / round N failed". Once a defect is fixed its failure history is dropped,
  because the reader needs to know whether the combination works now.
- **Attribution decides inclusion.** A failure that follows the driver — a
  mapping pool exhausted, a capacity or lifetime contract violated, a panic that
  reproduces wherever that code path runs — must be recorded; it is a defect in
  this driver. A failure that follows one physical sample — the same hardware
  error under every driver, every firmware revision and every cold boot — is a
  property of that sample: it is not listed, and it must not be used to excuse a
  driver defect.
- **Fixed table shape.** Rows are PCIe devices with their hardware IDs; the
  column is the board + CPU combination; the cell is the driver and its state.
  Only drivers shipped with macOS are listed; third-party driver stacks are out
  of scope.
- **No version or commit pinning.** The header carries a date and the driver
  version only. Do not write `at commit <hash>` or round-specific report
  filenames into the body or the sources: the hash goes stale immediately, and
  the round names turn a state document back into a log.
- **Update by editing the cell.** When a state changes, edit that row. Do not
  append a chronological paragraph; if a basis is needed, state one present-tense
  observation.

## Source and evidence policy

- `kext/`, `tools/` are canonical implementation and generator inputs. `include/`, `src/`, `tests/` contain existing modules, tests and reference inputs.
- `reference/` holds the Apple xnu/IOPCIFamily and Linux v6.6 sources used to cross-check the implementation. They are kept locally but are not committed; the source comments cite them by file and line.
- `fixtures/` holds captured firmware tables used by the offline tests. It is also local-only: `tests/InspectorSmoke.py` runs its synthetic cases when the real IVRS blob is absent, so a fresh clone passes without it.
- Runtime evidence, kext binaries, SDKs, upstream tarballs and full patch-package before/after snapshots are not committed.

Every future patch must name the full base commit and target this repository. Verify the expected working tree and use `git apply --check` before applying a patch. Never overwrite local changes or edit the baseline to force acceptance. Source identity in evidence is a Git commit hash, not a source snapshot. Logs, raw exports, binary identities and experiment results remain separate from provenance; repository commits do not constitute hardware validation.

## Tool layout

`tools/` is organised by function, not by round. Entry points live at the top
level (`run.py`, `setup.py`, `efi-setup.py`, `measure.py`, `test.sh`); the run
chain sits in named directories (`base/`, `mixed/`, `dual/`, `dispatch/`,
`postwake/`, …), one directory per layer, with the same relative depth the
per-round directories used to have. `tools/build/` holds build entry points,
`tools/verify/` the offline gate, `tools/dev/` one-off analysis aids, and
`tools/templates/` the driver templates consumed by `tools/build/patch-lucy-obs.py`.

Round numbers survive only as protocol identities: the driver-template selector
(`--tx 16..21`, `--rx 15|27|…|34`) and the identifiers already present in
archived captures. They are not directory or file names any more.

## Verification entry points

```sh
sh tools/test.sh                       # offline gate; needs clang + SDK
python3 tools/run.py --help            # run-chain entry
sh tools/build/probe.sh                # production kext
sh tools/build/probe-debug.sh          # Debug variant, retired M2 modes
python3 tools/verify/source.py         # hygiene (LF, empty personalities, disabled start)
python3 tools/verify/rxpost-layout.py  # RX wire-format declarations must agree
```
