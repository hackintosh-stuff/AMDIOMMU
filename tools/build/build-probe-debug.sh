#!/bin/sh
# build-m1a-debug.sh -- build the probe WITH the retired M2 experiment
# subsystem (probe/*Debug.cpp) and the historical amdiommu=<mode> values.
#
# Output: build-m1a-debug/AMDMapperProbe.kext
# This variant keeps -O0 and adds the retired experiment modules. The production
# build (sh tools/build/build-probe.sh) uses -O2 and accepts only
# amdiommu=passive / auto-attach; see DEBUG.md for the build configuration.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
PROBE_DEBUG=1 sh tools/build/build-probe.sh "$@"
