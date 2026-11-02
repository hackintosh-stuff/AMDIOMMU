#!/usr/bin/env python3
"""Verify/extract Round15 capture exports and refresh manifest; never run gates."""
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location('r15_capture_decode', Path(__file__).with_name('analyze.py'))
R15 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R15)
EXPORTS = (
    ('m2-b2-r15-pool-before-raw', 'm2-b2-r15-pool-before-sha256', 'r15-pool-before-raw.bin'),
    ('m2-b2-r15-pool-raw', 'm2-b2-r15-pool-sha256', 'r15-pool-raw.bin'),
    ('m2-b2-r15-pt-raw', 'm2-b2-r15-pt-sha256', 'r15-pt-raw.bin'),
)


def archive(cap, iface):
    raw = (cap / 'props.raw.txt').read_text(encoding='utf-8', errors='replace')
    props = R15.A.hexprops((cap / 'props.txt').read_text(encoding='utf-8', errors='replace'))
    R15.need(props.get('m2-b2-r15-map-mode') == R15.MODE, 'Round15 sparse mode absent')
    R15.need(props.get('m2-b2-r15-obs-scope') ==
             'declared-business-only; all-rxpost-and-pool-witnesses-retained',
             'explicit finite-business OBS scope absent')
    for name in ('load.txt', 'client.log', 'flood-client.log', 'peer.log',
                 'token.txt', 'batch.txt', 'system.txt', 'r15-version-confirmation.txt'):
        R15.need((cap / name).is_file() and (cap / name).stat().st_size > 0,
                 'missing current capture input: ' + name)
    token = int((cap / 'token.txt').read_text().strip(), 0)
    batch = int((cap / 'batch.txt').read_text().strip())
    R15.need(token == props.get('m2-b2-obs-declared-token') and batch == 4 and
             batch == props.get('m2-b2-obs-expected-batch'),
             'load token/batch does not match the probe used snapshot')
    for key, sha_key, name in (
            ('m2-b2-obs-snapshot-used', 'm2-b2-obs-used-sha256', 'obs-snapshot-used.bin'),
            ('m2-b2-rxset-raw', 'm2-b2-rxset-raw-sha256', 'rxset-raw.bin')):
        R15.need((cap / name).is_file(), 'base capture did not extract ' + name)
        R15.capture_blob(cap, raw, props, key, sha_key, name)
    summary, blobs = {}, []
    for key, sha_key, name in EXPORTS:
        blob = R15.capture_blob(cap, raw, props, key, sha_key, name)
        blobs.append(blob)
        summary[name] = {'source': key, 'bytes': len(blob),
                         'sha256': hashlib.sha256(blob).hexdigest()}
    # Decode geometry, not correctness claims: a failed finite experiment is
    # still a legitimate archive. The analyzers decide its actual verdict.
    before, _, _ = R15.decode_pool(blobs[0])
    after, _, _ = R15.decode_pool(blobs[1])
    R15.need(len(blobs[2]) == props.get('m2-b2-r15-pt-used-pages', 0) * 4096,
             'raw table prefix disagrees with used-pages')
    for (_, _, name), blob in zip(EXPORTS, blobs):
        (cap / name).write_bytes(blob)
    system = (cap / 'system.txt').read_text(encoding='utf-8', errors='replace')
    for bundle, env in (('AMDMapperProbe', 'EXPECTED_PROBE_VERSION'),
                        ('RTL812xLucy', 'EXPECTED_DRIVER_VERSION')):
        want = os.environ.get(env)
        if want:
            match = re.search(r'^' + bundle + r'_version\s*:\s*(\S+)', system, re.M)
            R15.need(match is not None and match.group(1) == want,
                     bundle + ': installed version differs from ' + env)
    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report = {'captured_utc': stamp, 'interface': iface, 'exports': summary,
              'pool_ids': [before['poolId'], after['poolId']],
              'obs_scope': props['m2-b2-r15-obs-scope'],
              'declared_token': token, 'batch': batch,
              'note': 'capture integrity only; no correctness or stability verdict'}
    (cap / 'R15-EXPORTS.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    lines = ['run_id        : ' + cap.name, 'captured_utc  : ' + stamp,
             'interface     : ' + iface, '',
             'AUTHORITATIVE PROBE-EXPORTED BYTES:',
             '  obs-snapshot-used.bin, rxset-raw.bin, r15-pool-before-raw.bin,',
             '  r15-pool-raw.bin, r15-pt-raw.bin (all checked against published sha256)',
             'SCOPE: finite declared business; unfiltered RX post log and pool witnesses.',
             'LATER DRIVER SNAPSHOTS ARE NOT THE PROBE INPUTS.',
             'Load/client/flood/peer records belong to this Round15 run.', '',
             'files (sha256, size, relative name):']
    for path in sorted(cap.rglob('*')):
        if not path.is_file() or path == cap / 'MANIFEST.txt':
            continue
        data = path.read_bytes()
        lines.append('  %s  %10d  %s' %
                     (hashlib.sha256(data).hexdigest(), len(data), path.relative_to(cap).as_posix()))
    (cap / 'MANIFEST.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return report


def main():
    if len(sys.argv) not in (2, 3):
        print('usage: capture-archive.py CAPTURE [IFACE]', file=sys.stderr)
        return 2
    try:
        report = archive(Path(sys.argv[1]), sys.argv[2] if len(sys.argv) == 3 else 'en2')
    except (OSError, ValueError, TypeError) as exc:
        print('FAIL: ' + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
