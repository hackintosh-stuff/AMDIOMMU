#!/bin/sh
# Build the fixed checkout; SRC is the pinned upstream input tree.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
[ "$#" -eq 1 ] || { echo 'usage: sh tools/r52/build.sh <relative-upstream-source>' >&2; exit 2; }
SRC=$1
case "$SRC" in /*) echo 'SRC must be relative to the repository' >&2; exit 2;; esac
python3 -B - "$SRC" <<'PY'
from pathlib import Path
import sys
root = Path.cwd().resolve()
(root / sys.argv[1]).resolve().relative_to(root)
PY
python3 -B tools/build/patch-lucy-obs.py "$SRC" --tx21 --rx34
# Round52 keeps per-device ABI2 and its accepted 64-page decoder/layout contract.
python3 -B tools/r21/abi.py --check-r49
sh tools/build/lucy.sh "$SRC"
sh tools/build/probe.sh
printf '%s\n' 'Round52 built: RTL812xLucy 1.1.237; AMDMapperProbe 0.59.0; two RTL8127 device domains on one shared controller; independent ABI2 mapper/page tables/IOVA pools; DMA32 / RX16x64 / NPCache-aware map invalidation; IPv4+IPv6 TSO; finite per-interface TCP6 traffic and one-device down/up'
