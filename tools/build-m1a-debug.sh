#!/bin/sh
# build-m1a-debug.sh -- build the probe WITH the retired M2 experiment
# subsystem (kext/*Debug.cpp) and the historical amdiommu=<mode> values.
#
# Output: build-m1a-debug/AMDMapperProbe.kext
# The production build (sh tools/build-m1a.sh) is unchanged and accepts
# only amdiommu=auto / auto-attach.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
PROBE_DEBUG=1 sh tools/build-m1a.sh "$@"
