#!/bin/sh
# One finite run. Python validates the running boot, both instances and endpoints.
set -eu
HERE=$(CDPATH= cd "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd "$HERE/../.." && pwd)
cd "$PROJECT_ROOT"
OUT=${1:?provide the run output}
CONFIG=${2:?provide the endpoint config}
PYTHON=${PYTHON:-/usr/bin/python3}
exec "$PYTHON" "$HERE/load.py" "$OUT" --config "$CONFIG" --mode auto
