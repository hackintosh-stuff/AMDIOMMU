#!/bin/sh
# One finite IPv6 load using the existing en2 addresses and route.
set -eu
HERE=$(CDPATH= cd "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd "$HERE/../.." && pwd)
cd "$PROJECT_ROOT"
OUT=${1:-runs/r46}
PYTHON=${PYTHON:-/usr/bin/python3}
IFACE=${IFACE:-en2}
LOCAL6=${LOCAL6:?set the existing en2 IPv6 address}
PEER6=${PEER6:?set the existing peer IPv6 address}
PORT=${PORT:-9112}
WAIT=${WAIT:-120}
case "$WAIT" in ''|*[!0-9]*) echo 'WAIT must be an integer' >&2; exit 2;; esac
[ "$WAIT" -le 120 ] || { echo 'WAIT must be at most 120 seconds' >&2; exit 2; }
[ "$IFACE" = en2 ] || { echo 'round46 requires en2' >&2; exit 2; }

"$PYTHON" - "$HERE/deploy.py" "$LOCAL6" "$PEER6" "$WAIT" <<'PY'
import importlib.util
from pathlib import Path
import plistlib
import subprocess
import sys
sys.path.insert(0, str(Path(sys.argv[1]).parent))
spec = importlib.util.spec_from_file_location('_r46_boot_checks', sys.argv[1])
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
checks.NETWORK('en2', sys.argv[3], sys.argv[2], wait=int(sys.argv[4]))
for bundle, version in (('RTL812xLucy', checks.DRIVER_VERSION),
                        ('AMDMapperProbe', checks.PROBE_VERSION)):
    path = Path('/Library/Extensions') / (bundle + '.kext/Contents/Info.plist')
    info = plistlib.loads(path.read_bytes())
    if info.get('CFBundleVersion') != version:
        raise SystemExit('round46-load: installed %s is not %s' % (bundle, version))
    if bundle == 'RTL812xLucy':
        checks.require_offloads(info)
bootargs = subprocess.check_output(['sysctl', '-n', 'kern.bootargs'], text=True).split()
if [arg for arg in bootargs if arg.startswith('amdiommu=')] != ['amdiommu=auto']:
    raise SystemExit('round46-load: running kernel must use amdiommu=auto')
PY

exec "$PYTHON" "$HERE/load.py" "$OUT" --iface "$IFACE" --local "$LOCAL6" --peer "$PEER6" --port "$PORT"
