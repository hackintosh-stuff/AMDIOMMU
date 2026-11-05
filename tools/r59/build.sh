#!/bin/sh
# The existing fixed Lucy input is upgraded in place. RTL8111 remains installed.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
[ "$#" -eq 1 ] || { echo 'usage: sh tools/r59/build.sh <relative-lucy-input>' >&2; exit 2; }
SRC=$1
python3 -B - "$SRC" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
if p.is_absolute():
    raise SystemExit('upstream input must be relative to the fixed repository')
p.resolve().relative_to(Path.cwd().resolve())
PY
python3 -B tools/apply-lucy-obs2.py "$SRC" --tx21 --rx34 --r59
python3 -B tools/r21/abi.py --check-r59
sh tools/build-lucy.sh --r59 "$SRC"
sh tools/build-m1a.sh
printf '%s\n' 'Round59 built: Probe 0.66.0 and Lucy 1.1.240 with 8 x 128-page RX groups; retain RealtekRTL8111 3.0.54'
