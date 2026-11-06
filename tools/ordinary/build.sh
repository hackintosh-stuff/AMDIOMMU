#!/bin/sh
# Build the fixed checkout; SRC is the pinned upstream input tree.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
[ "$#" -eq 1 ] || { echo 'usage: sh tools/ordinary/build.sh <relative-upstream-source>' >&2; exit 2; }
SRC=$1
case "$SRC" in /*) echo 'SRC must be relative to the repository' >&2; exit 2;; esac
python3 -B - "$SRC" <<'PY'
from pathlib import Path
import sys
root = Path.cwd().resolve()
(root / sys.argv[1]).resolve().relative_to(root)
PY
python3 -B tools/build/patch-lucy-obs.py "$SRC" --tx21 --rx34
python3 -B tools/abi/abi.py --check-r44
sh tools/build/lucy.sh "$SRC"
sh tools/build/probe.sh
printf '%s\n' 'Round44 built: RTL812xLucy 1.1.229; AMDMapperProbe 0.53.0; ordinary per-device IOMapper ABI1; 4096 IOVA pages / 1024 records / 32 pages and runs per map; RX64 groups + fixed3 retained across normal down/up'
