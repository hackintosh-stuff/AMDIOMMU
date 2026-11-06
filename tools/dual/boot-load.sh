#!/bin/sh
# One finite mixed-device load; endpoint selection is explicit in the JSON.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../.." && pwd)
cd "$ROOT"
OUT=${1:?set the run directory}
CONFIG=${2:?set the endpoint JSON}
PYTHON=${PYTHON:-/usr/bin/python3}
exec "$PYTHON" "$HERE/load.py" "$OUT" --config "$CONFIG" --mode auto
