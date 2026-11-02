#!/bin/sh
# Run from repos/AMDIOMMU (or its exact Git checkout on the Mac).
# SRC is a project-relative pristine tree at the pinned upstream commit.
# Build only: no install, boot-argument write, kext load or reboot.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
SRC=${1:?relative path to pinned upstream RTL812xLucy source required}
case "$SRC" in /*) echo 'SRC must be relative to the repository' >&2; exit 2;; esac
python3 -B tools/apply-lucy-obs2.py "$SRC" --tx 21 --rx 28
python3 -B tools/r27/check-local.py --source "$SRC/RTL812xLucy/RTL812xLucy.cpp"
sh tools/build-lucy.sh "$SRC"
sh tools/build-m1a.sh
printf '%s\n' 'Round28 built: RTL812xLucy 1.1.213; AMDMapperProbe 0.37.0; TX native6/std5/domain3; RX cyclic64 v2'
