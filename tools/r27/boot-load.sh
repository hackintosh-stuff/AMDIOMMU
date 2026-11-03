#!/bin/sh
# Finite Round36 boot wait. Network configuration and offload flags are read-only.
set -eu
HERE=$(CDPATH= cd "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd "$HERE/../.." && pwd)
cd "$PROJECT_ROOT"
OUT=${1:-runs/r36}
PYTHON=${PYTHON:-/usr/bin/python3}
IFACE=${IFACE:-en2}
PEER=${PEER:-192.168.50.122}
PORT=${PORT:-9110}
WAIT=${WAIT:-120}
case "$WAIT" in ''|*[!0-9]*) echo 'WAIT must be an integer' >&2; exit 2;; esac
[ "$WAIT" -le 120 ] || { echo 'WAIT must be at most 120 seconds' >&2; exit 2; }
[ "$IFACE" = en2 ] || { echo 'round36 requires en2' >&2; exit 2; }

n=0
while [ "$n" -lt "$WAIT" ]; do
    state=$(/sbin/ifconfig "$IFACE" 2>/dev/null || true)
    if printf '%s\n' "$state" | /usr/bin/grep -q 'inet ' &&
       printf '%s\n' "$state" | /usr/bin/grep -q 'status: active'; then
        break
    fi
    n=$((n + 1))
    sleep 1
done

# Reuse the new deployment's read-only prechecks. The loaded-window mode is
# checked by load.py before the 8192 requests, after the probe publishes it.
"$PYTHON" - "$HERE/deploy.py" "$IFACE" <<'PY'
import importlib.util
from pathlib import Path
import plistlib
import subprocess
import sys
spec = importlib.util.spec_from_file_location('round36_deploy_checks', sys.argv[1])
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
checks.require_target_ready(subprocess.check_output(['ifconfig', sys.argv[2]], text=True))
info = plistlib.loads(Path('/Library/Extensions/RTL812xLucy.kext/Contents/Info.plist').read_bytes())
if info.get('CFBundleVersion') != checks.DRIVER_VERSION:
    raise SystemExit('round36-load: installed driver version is not 1.1.221')
checks.require_tso_off(info)
PY

got=$(/sbin/route -n get "$PEER" 2>/dev/null | /usr/bin/awk '/interface:/{print $2}')
if [ "$got" != "$IFACE" ]; then
    echo "round36-load: peer route uses ${got:-none}; en2 is required" >&2
    exit 3
fi
exec "$PYTHON" "$HERE/load.py" "$OUT" --iface "$IFACE" --peer "$PEER" --port "$PORT"
