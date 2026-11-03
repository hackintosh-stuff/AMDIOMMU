#!/bin/sh
# Build the fixed checkout; SRC is the pinned upstream input tree.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
[ "$#" -eq 1 ] || { echo 'usage: sh tools/r49/build.sh <relative-upstream-source>' >&2; exit 2; }
SRC=$1
case "$SRC" in /*) echo 'SRC must be relative to the repository' >&2; exit 2;; esac
python3 -B - "$SRC" <<'PY'
from pathlib import Path
import sys
root = Path.cwd().resolve()
(root / sys.argv[1]).resolve().relative_to(root)
PY
python3 -B tools/apply-lucy-obs2.py "$SRC" --tx21 --rx34
# Round49 maps 64-page RX groups; check the full ABI2 record and decoder.
python3 -B tools/r21/abi.py --check-r49
sh tools/build-lucy.sh "$SRC"
sh tools/build-m1a.sh
printf '%s\n' 'Round49 built: RTL812xLucy 1.1.234; IPv4 TSO on / IPv6 TSO on; AMDMapperProbe 0.56.0; ordinary DMA32 / low IOVA pool; 16 RX groups of 64 pages; IVRS/PCI discovery; per-device IOMapper ABI2; finite TCP6 before/after normal down/up'
