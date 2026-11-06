#!/bin/sh
# Finite ordinary-mapper boot wait. Existing address/route/MTU are prerequisites.
set -eu
HERE=$(CDPATH= cd "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd "$HERE/../.." && pwd)
cd "$PROJECT_ROOT"
OUT=${1:-runs/r44}
PYTHON=${PYTHON:-/usr/bin/python3}
IFACE=${IFACE:-en2}
PEER=${PEER:-192.168.50.122}
PORT=${PORT:-9110}
WAIT=${WAIT:-120}
case "$WAIT" in ''|*[!0-9]*) echo 'WAIT must be an integer' >&2; exit 2;; esac
[ "$WAIT" -le 120 ] || { echo 'WAIT must be at most 120 seconds' >&2; exit 2; }
[ "$IFACE" = en2 ] || { echo 'round44 requires en2' >&2; exit 2; }

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

"$PYTHON" - "$HERE/deploy.py" "$IFACE" <<'PY'
import importlib.util
from pathlib import Path
import plistlib
import subprocess
import sys
spec = importlib.util.spec_from_file_location('_r44_boot_checks', sys.argv[1])
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
checks.require_target_ready(subprocess.check_output(['ifconfig', sys.argv[2]], text=True))
for bundle, version in (('RTL812xLucy', checks.DRIVER_VERSION),
                        ('AMDMapperProbe', checks.PROBE_VERSION)):
    path = Path('/Library/Extensions') / (bundle + '.kext/Contents/Info.plist')
    info = plistlib.loads(path.read_bytes())
    if info.get('CFBundleVersion') != version:
        raise SystemExit('round44-load: installed %s is not %s' % (bundle, version))
    if bundle == 'RTL812xLucy':
        checks.require_tso_off(info)
bootargs = subprocess.check_output(['sysctl', '-n', 'kern.bootargs'], text=True).split()
if [arg for arg in bootargs if arg.startswith('amdiommu=')] != ['amdiommu=auto']:
    raise SystemExit('round44-load: the running kernel must use amdiommu=auto')
PY

got=$(/sbin/route -n get "$PEER" 2>/dev/null | /usr/bin/awk '/interface:/{print $2}')
if [ "$got" != "$IFACE" ]; then
    echo "round44-load: peer route uses ${got:-none}; en2 is required" >&2
    exit 3
fi
exec "$PYTHON" "$HERE/load.py" "$OUT" --iface "$IFACE" --peer "$PEER" --port "$PORT"
