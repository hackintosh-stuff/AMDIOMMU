#!/bin/sh
# Build only the changed bundles using the original dependency input directories.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
[ "$#" -eq 2 ] || { echo 'usage: sh tools/r63/build.sh <rtl8111-input> <lucy-sdk-input>' >&2; exit 2; }
sh tools/build/probe.sh
sh tools/r53/build-rtl8111.sh --r63 "$1" "$2"
