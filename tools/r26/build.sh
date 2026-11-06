#!/bin/sh
# Run from the project root. SRC is a pristine pinned upstream tree, relative
# to that root, or a tree already generated from exactly these templates.
# Usage: sh tools/r26/build.sh RTL812xLucy-639144d1f284a9fee222a518691b01494f5e265d
# Builds only; does not install, load, change boot arguments, or reboot.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
SRC=${1:?relative path to pinned upstream RTL812xLucy source required}
python3 -B tools/build/patch-lucy-obs.py "$SRC" --tx 21
python3 -B tools/r26/check-local.py --source "$SRC/RTL812xLucy/RTL812xLucy.cpp"
sh tools/build/lucy.sh "$SRC"
sh tools/build/probe.sh
printf '%s\n' 'Round26 built: build-lucy/RTL812xLucy.kext (1.1.211), build-m1a/AMDMapperProbe.kext (0.35.0)'
