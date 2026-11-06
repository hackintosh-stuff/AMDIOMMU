#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
[ "$#" -eq 1 ] || { echo 'usage: sh tools/r64/build.sh <relative-lucy-input>' >&2; exit 2; }
SRC=$1
case "$SRC" in /*) echo 'Lucy input must be relative to fixed repository' >&2; exit 2;; esac
python3 -B - "$SRC" <<'PY'
from pathlib import Path
import sys
root=Path.cwd().resolve()
(root/sys.argv[1]).resolve().relative_to(root)
PY
python3 -B tools/build/patch-lucy-obs.py "$SRC" --tx21 --rx34 --r59
python3 -B tools/r64/apply-lucy.py "$SRC"
python3 -B tools/r21/abi.py --check-r59
sh tools/build/lucy.sh --r64 "$SRC"
echo 'R64 built: RTL812xLucy 1.1.241; Probe 0.70.0 retained'
