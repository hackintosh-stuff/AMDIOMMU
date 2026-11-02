#!/bin/sh
# Build the round25 probe and Lucy driver from a caller-selected upstream tree.
# Usage (on the Mac): sh tools/r25/build.sh /path/to/RTL812xLucy-<commit>
# The generator requires a pristine or already-current tree. No installation.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
SRC=${1:?path to the upstream RTL812xLucy source tree required}
SRC=$(CDPATH= cd -- "$SRC" && pwd)
cd "$ROOT"
python3 tools/apply-lucy-obs2.py "$SRC" --tx 21
sh tools/build-lucy.sh "$SRC"
sh tools/build-m1a.sh
printf '%s\n' 'Round25 build complete: RTL812xLucy 1.1.210 / AMDMapperProbe 0.34.0'
