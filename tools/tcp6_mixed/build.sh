#!/bin/sh
# Build the fixed checkout; SRC is the pinned upstream input tree.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
[ "$#" -eq 1 ] || { echo 'usage: sh tools/tcp6_mixed/build.sh <relative-upstream-source>' >&2; exit 2; }
SRC=$1
case "$SRC" in /*) echo 'SRC must be relative to the repository' >&2; exit 2;; esac
python3 -B - "$SRC" <<'PY'
from pathlib import Path
import sys
root = Path.cwd().resolve()
(root / sys.argv[1]).resolve().relative_to(root)
PY
python3 -B tools/build/patch-lucy-obs.py "$SRC" --tx21 --rx34
# Round51 retains R49 ABI2 and its 64-page decoder/layout contract.
python3 -B tools/abi/abi.py --check-r49
sh tools/build/lucy.sh "$SRC"
sh tools/build/probe.sh
printf '%s\n' 'Round51 built: RTL812xLucy 1.1.236; IPv4 TSO on / IPv6 TSO on; AMDMapperProbe 0.58.0; ordinary DMA32 / low IOVA pool / NPCache-aware map invalidation; 16 RX groups of 64 pages; IVRS/PCI discovery; per-device IOMapper ABI2; finite TCP6 before/after normal down/up'
