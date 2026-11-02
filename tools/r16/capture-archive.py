#!/usr/bin/env python3
"""Extract exact probe exports and refresh finite-run manifest, not a gate."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyze as X

NEW_EXPORTS = (
    ('m2-3a-domain-raw', 'r16-domain-raw.bin'),
    ('m2-3a-pt-raw', 'r16-pt-raw.bin'),
    ('m2-3a-driver-raw', 'r16-driver-raw.bin'))
OLD_EXPORTS = (
    ('m2-b2-obs-snapshot-used', 'm2-b2-obs-used-sha256', 'obs-snapshot-used.bin'),
    ('m2-b2-rxset-raw', 'm2-b2-rxset-raw-sha256', 'rxset-raw.bin'),
    ('m2-b2-r15-pool-before-raw', 'm2-b2-r15-pool-before-sha256', 'r15-pool-before-raw.bin'),
    ('m2-b2-r15-pool-raw', 'm2-b2-r15-pool-sha256', 'r15-pool-raw.bin'),
    ('m2-b2-r15-pt-raw', 'm2-b2-r15-pt-sha256', 'r15-pt-raw.bin'))


def archive(cap, iface):
    raw = (cap / 'props.raw.txt').read_text(encoding='utf-8', errors='replace')
    props = X.A.hexprops((cap / 'props.txt').read_text(encoding='utf-8', errors='replace'))
    X.need(props.get('m2-b2-r15-map-mode') == X.R.MODE, 'RX sparse ownership mode missing')
    for name in ('load.txt', 'client.log', 'peer.log', 'token.txt', 'batch.txt',
                 'system.txt', 'r16-version-confirmation.txt'):
        X.need((cap / name).is_file() and (cap / name).stat().st_size > 0,
               'missing current capture input: ' + name)
    token = int((cap / 'token.txt').read_text().strip(), 0)
    batch = int((cap / 'batch.txt').read_text().strip())
    X.need(token == props.get('m2-b2-obs-declared-token') and batch == 4 and
           props.get('m2-b2-obs-expected-batch') == batch, 'current token/batch mismatch')
    summary, blobs = {}, {}
    for key, sha_key, name in OLD_EXPORTS:
        blob = X.R.capture_blob(cap, raw, props, key, sha_key, name)
        blobs[name] = blob
        summary[name] = {'source': key, 'bytes': len(blob), 'sha256': hashlib.sha256(blob).hexdigest(),
                         'published_sha256_verified': True}
    for key, name in NEW_EXPORTS:
        blob = X.raw_export(cap, raw, key, name)
        blobs[name] = blob
        summary[name] = {'source': key, 'bytes': len(blob), 'sha256': hashlib.sha256(blob).hexdigest(),
                         'published_sha256_verified': False}
    # Fixed geometry only. An incomplete/failed run must still be archivable.
    domain, driver, pt = (blobs[k] for k in ('r16-domain-raw.bin', 'r16-driver-raw.bin', 'r16-pt-raw.bin'))
    X.need(len(domain) == X.DOMAIN_BYTES and struct.unpack_from('<2I', domain) == (1, len(domain)),
           'unknown domain export ABI')
    X.need(len(driver) == X.DRIVER_BYTES and struct.unpack_from('<3I', driver) == (0x36315854, 1, len(driver)),
           'unknown driver export ABI')
    X.need(len(pt) == struct.unpack_from('<Q', domain, 56)[0], 'final PT arena export size differs from ABI')
    for name, blob in blobs.items():
        (cap / name).write_bytes(blob)
    system = (cap / 'system.txt').read_text(encoding='utf-8', errors='replace')
    for bundle, env in (('AMDMapperProbe', 'EXPECTED_PROBE_VERSION'), ('RTL812xLucy', 'EXPECTED_DRIVER_VERSION')):
        want = os.environ.get(env)
        if want:
            match = re.search(r'^' + bundle + r'_version\s*:\s*(\S+)', system, re.M)
            X.need(match is not None and match.group(1) == want, bundle + ': installed version mismatch')
    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report = {'captured_utc': stamp, 'interface': iface, 'declared_token': token, 'batch': batch,
              'exports': summary, 'note': 'capture integrity only, no correctness/stability verdict; new raw exports have no producer-published digest'}
    (cap / 'R16-EXPORTS.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    lines = ['run_id : ' + cap.name, 'captured_utc : ' + stamp, 'interface : ' + iface,
             'Authoritative: probe-used OBS/RX + pool and final domain/PT/driver exports.',
             'Later driver node publications are cross-checks only.',
             'No flood; current clean4 payload bytes are logged in client and peer logs.',
             'New domain/PT/driver raw hashes below are archive-computed, NOT producer SHA claims.',
             'files (sha256, bytes, relative name):']
    for path in sorted(cap.rglob('*')):
        if path.is_file() and path != cap / 'MANIFEST.txt':
            data = path.read_bytes()
            lines.append('  %s  %10d  %s' % (hashlib.sha256(data).hexdigest(), len(data), path.relative_to(cap).as_posix()))
    (cap / 'MANIFEST.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return report


def main():
    if len(sys.argv) not in (2, 3):
        print('usage: capture-archive.py CAPTURE [IFACE]', file=sys.stderr)
        return 2
    try:
        result = archive(Path(sys.argv[1]), sys.argv[2] if len(sys.argv) == 3 else 'en2')
    except (OSError, ValueError, TypeError, struct.error) as exc:
        print('FAIL: ' + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
