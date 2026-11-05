#!/bin/sh
# Build the current checkout with its two fixed upstream input directories.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
[ "$#" -eq 2 ] || { echo 'usage: sh tools/r54/build.sh <relative-lucy-input> <relative-rtl8111-input>' >&2; exit 2; }
LUCY_SRC=$1
RTL_SRC=$2
python3 -B - "$LUCY_SRC" "$RTL_SRC" <<'PY'
from pathlib import Path
import sys
root = Path.cwd().resolve()
for value in sys.argv[1:]:
    path = Path(value)
    if path.is_absolute():
        raise SystemExit('upstream inputs must be relative to the fixed repository')
    (root / path).resolve().relative_to(root)
PY
python3 -B tools/apply-lucy-obs2.py "$LUCY_SRC" --tx21 --rx34
python3 -B tools/r21/abi.py --check-r49
sh tools/build-lucy.sh "$LUCY_SRC"
sh tools/build-m1a.sh
sh tools/r53/build-rtl8111.sh "$RTL_SRC" "$LUCY_SRC"
printf '%s\n' 'Round54 built: RTL812xLucy 1.1.239; RealtekRTL8111 3.0.54; AMDMapperProbe 0.61.0; explicit pre-open requester claims'
