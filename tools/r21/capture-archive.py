#!/usr/bin/env python3
"""Extract declared Round24/Round25 probe/driver exports and write the run manifest.

Integrity only: fixed ABI sizes, the token/batch declaration, and that every
input this capture needs is present. It is NOT a verdict -- that is
tools/r21/check-r24.py or check-r25.py's job, according to the batch.

The producer-digest verification for the OBS/RX/pool exports is reused from the
round-17 archive script (same ABI, same rules); only the round-18 additions
(domain3/native5/std4 for batch512, or the retained legacy batch16 ABI) are selected explicitly.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
# The archive uses TWO modules on purpose: `helpers` is the round-17 capture
# primitive library (A/R/need/raw_export) which never changed, while `analyze`
# is this round's own decoder whose ABI constants must match the exports being
# archived. Importing r17's `analyze` here is what silently validated round-21
# blobs against round-17 expectations.
# Two distinct modules, loaded under distinct names: the round-17 primitives
# (hex property extraction, blob capture) are unchanged and reused verbatim,
# while the DECODER must be this round's, because its ABI constants have to
# match the exports being archived. Importing one as the other is what let a
# round-21 export be validated against round-17 expectations.
def _load(name, path):
    """Load a module from an explicit path under an explicit name.

    Two modules called `analyze` exist (round-17 primitives, round-21 decoder);
    plain imports collide in sys.modules and whichever wins silently decides the
    ABI constants. Loading by path keeps them separate.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


helpers = _load('r17_capture_helpers', HERE.parent / 'r17' / 'analyze.py')
X = _load('r21_analyze', HERE / 'analyze.py')

# Batch declaration selects the ABI; never infer a new ABI from a blob alone.
BATCHES = (16, 512)


def validate_tx_abi(batch, domain, driver, std, block, pt):
    """Integrity/layout only; deliberately permits incomplete/pinned histories."""
    helpers.need(batch in BATCHES, 'unsupported declared batch')
    domain_version, domain_bytes, native_version, std_version = (
        (3, 80 + 32 * 720 + 72, 5, 4) if batch == 512 else
        (2, 80 + 32 * 720, X.DRIVER_VERSION, 3))
    helpers.need(len(domain) == domain_bytes and
                 struct.unpack_from('<2I', domain) == (domain_version, len(domain)),
                 'unknown domain export ABI for batch %d' % batch)
    dhead = struct.unpack_from('<4I', driver)
    helpers.need(len(driver) == X.DRIVER_HEADER + 32 * X.DRIVER_RECORD_BYTES and
                 dhead[:3] == (X.DRIVER_MAGIC, native_version, len(driver)) and dhead[3] <= 32,
                 'unknown driver export ABI for batch %d' % batch)
    helpers.need(len(std) == 72 + 32 * 304 and
                 struct.unpack_from('<2I', std) == (0x38315854, std_version),
                 'unknown std export ABI for batch %d' % batch)
    helpers.need(len(block) == 2320 and
                 struct.unpack_from('<3I', block) == (0x30325854, 2, 2320),
                 'unknown block export ABI')
    helpers.need(len(pt) == struct.unpack_from('<Q', domain, 56)[0],
                 'final PT arena export size differs from ABI')

NEW_EXPORTS = (
    ('m2-3b-domain-raw', 'r21-domain-raw.bin'),
    ('m2-3b-pt-raw', 'r21-pt-raw.bin'),
    ('m2-3b-driver-raw', 'r21-driver-raw.bin'),
    ('rtl812x-txmap-std-raw', 'r21-std-raw.bin'),
    ('rtl812x-txmap-block-raw', 'r21-block-raw.bin'))
OLD_EXPORTS = (
    ('m2-b2-obs-snapshot-used', 'm2-b2-obs-used-sha256', 'obs-snapshot-used.bin'),
    ('m2-b2-rxset-raw', 'm2-b2-rxset-raw-sha256', 'rxset-raw.bin'),
    ('m2-b2-r15-pool-before-raw', 'm2-b2-r15-pool-before-sha256', 'r15-pool-before-raw.bin'),
    ('m2-b2-r15-pool-raw', 'm2-b2-r15-pool-sha256', 'r15-pool-raw.bin'),
    ('m2-b2-r15-pt-raw', 'm2-b2-r15-pt-sha256', 'r15-pt-raw.bin'))


def archive(cap, iface):
    raw = (cap / 'props.raw.txt').read_text(encoding='utf-8', errors='replace')
    props = helpers.A.hexprops((cap / 'props.txt').read_text(encoding='utf-8', errors='replace'))
    helpers.need(props.get('m2-b2-r15-map-mode') == helpers.R.MODE,
           'RX sparse ownership mode missing')
    for name in ('load.txt', 'client.log', 'peer.log', 'token.txt', 'batch.txt',
                 'system.txt', 'r21-version-confirmation.txt'):
        helpers.need((cap / name).is_file() and (cap / name).stat().st_size > 0,
               'missing current capture input: ' + name)
    token = int((cap / 'token.txt').read_text().strip(), 0)
    batch = int((cap / 'batch.txt').read_text().strip())
    helpers.need(token == props.get('m2-b2-obs-declared-token') and
           batch in BATCHES and props.get('m2-b2-obs-expected-batch') == batch,
           'current token/batch mismatch')
    # A pinned run is archivable on purpose: the live PTEs, command words and
    # records of a refused detach are exactly what a failure needs to show. The
    # token records which outcome it was and the ANALYZER refuses pinned runs.
    cleanup = props.get('m2-3b-cleanup')
    helpers.need(cleanup in ('detached-after-restore-confirmed',
                             'no-window-installed',
                             'PINNED-outstanding-no-DTE-restore',
                             'PINNED-restore-incomplete',
                             'PINNED-detach-refused',
                             'PINNED-resume-refused'),
           'unknown TX cleanup token: %r' % (cleanup,))
    summary, blobs = {}, {}
    for key, sha_key, name in OLD_EXPORTS:
        blob = helpers.R.capture_blob(cap, raw, props, key, sha_key, name)
        blobs[name] = blob
        summary[name] = {'source': key, 'bytes': len(blob),
                         'sha256': hashlib.sha256(blob).hexdigest(),
                         'published_sha256_verified': True}
    for key, name in NEW_EXPORTS:
        blob = helpers.raw_export(cap, raw, key, name)
        blobs[name] = blob
        summary[name] = {'source': key, 'bytes': len(blob),
                         'sha256': hashlib.sha256(blob).hexdigest(),
                         'published_sha256_verified': False}
    domain, driver, pt, std = (blobs[k] for k in
                               ('r21-domain-raw.bin', 'r21-driver-raw.bin',
                                'r21-pt-raw.bin', 'r21-std-raw.bin'))
    validate_tx_abi(batch, domain, driver, std, blobs['r21-block-raw.bin'], pt)
    for name, blob in blobs.items():
        (cap / name).write_bytes(blob)
    system = (cap / 'system.txt').read_text(encoding='utf-8', errors='replace')
    for bundle, env in (('AMDMapperProbe', 'EXPECTED_PROBE_VERSION'),
                        ('RTL812xLucy', 'EXPECTED_DRIVER_VERSION')):
        want = os.environ.get(env)
        if want:
            match = re.search(r'^' + bundle + r'_version\s*:\s*(\S+)', system, re.M)
            helpers.need(match is not None and match.group(1) == want,
                   bundle + ': installed version mismatch')
    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report = {'captured_utc': stamp, 'interface': iface, 'declared_token': token,
              'batch': batch, 'cleanup': cleanup, 'exports': summary,
              'note': 'capture integrity only, no correctness/stability verdict; '
                      'new raw exports have no producer-published digest'}
    export_name = 'R25-EXPORTS.json' if batch == 512 else 'R21-EXPORTS.json'
    (cap / export_name).write_text(json.dumps(report, indent=2) + '\n',
                                          encoding='utf-8')
    lines = ['run_id : ' + cap.name, 'captured_utc : ' + stamp,
             'interface : ' + iface,
             'Authoritative: probe-used OBS/RX + pool and final domain/PT/driver/std exports.',
             'Later driver node publications are cross-checks only.',
             ('512 requests in 32 send16/receive groups; complete application logs, retained32 kernel history.'
              if batch == 512 else '16-request batch; payload bytes are in client/peer logs.'),
             'New domain/PT/driver/std raw hashes below are archive-computed, NOT producer SHA claims.',
             'files (sha256, bytes, relative name):']
    for path in sorted(cap.rglob('*')):
        if path.is_file() and path != cap / 'MANIFEST.txt':
            data = path.read_bytes()
            lines.append('  %s  %10d  %s' % (hashlib.sha256(data).hexdigest(), len(data),
                                             path.relative_to(cap).as_posix()))
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
