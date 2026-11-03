#!/bin/sh
# Build the fixed checkout; SRC is the pinned upstream input tree.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
[ "$#" -eq 1 ] || { echo 'usage: sh tools/r48/build.sh <relative-upstream-source>' >&2; exit 2; }
SRC=$1
case "$SRC" in /*) echo 'SRC must be relative to the repository' >&2; exit 2;; esac
python3 -B - "$SRC" <<'PY'
from pathlib import Path
import sys
root = Path.cwd().resolve()
(root / sys.argv[1]).resolve().relative_to(root)
PY
python3 -B tools/apply-lucy-obs2.py "$SRC" --tx21 --rx34
# Round48 uses 32-bit command constraints and a low IOVA pool; ABI1 is unchanged.
python3 -B tools/r21/abi.py --check-r44
sh tools/build-lucy.sh "$SRC"
sh tools/build-m1a.sh
printf '%s\n' 'Round48 built: RTL812xLucy 1.1.233; IPv4 TSO on / IPv6 TSO on; AMDMapperProbe 0.55.0; ordinary DMA32 / low IOVA pool; IVRS/PCI discovery; per-device IOMapper ABI1; finite TCP6 before/after normal down/up'
