#!/usr/bin/env python3
"""Capture Round28 evidence after the finite load; no live peer or old ABI verifier.

All workspace paths are relative to the project. Missing evidence is recorded
in the manifest and returns 1 after saving the available failure diagnostics.
This is an archive operation, not a correctness or stability verdict.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[2]
VERSIONS = {'RTL812xLucy': '1.1.213', 'AMDMapperProbe': '0.37.0'}
ABI = {'native': 6, 'standard': 5, 'domain': 3, 'driver_mode': 2,
       'rx_driver': 2, 'rx_backend': 2}
EXPORTS = (
    ('probe', 'm2-3b-domain-raw', 'r21-domain-raw.bin'),
    ('probe', 'm2-3b-pt-raw', 'r21-pt-raw.bin'),
    ('probe', 'm2-3b-driver-raw', 'r21-driver-raw.bin'),
    ('driver', 'rtl812x-txmap-std-raw', 'r21-std-raw.bin'),
    ('driver', 'rtl812x-txmap-block-raw', 'r21-block-raw.bin'),
    ('probe', 'm2-3h-rx-raw', 'r27-rx-raw.bin'),
    ('probe', 'm2-3h-rx-map-raw', 'r27-rx-map-raw.bin'))
OPTIONAL_EXPORTS = (
    ('probe', 'm2-b2-obs-snapshot-used', 'obs-snapshot-used.bin', 'm2-b2-obs-used-sha256'),
    ('probe', 'm2-b2-rxset-raw', 'rxset-raw.bin', 'm2-b2-rxset-raw-sha256'),
    ('probe', 'm2-b2-r15-pool-before-raw', 'r15-pool-before-raw.bin', 'm2-b2-r15-pool-before-sha256'),
    ('probe', 'm2-b2-r15-pool-raw', 'r15-pool-raw.bin', 'm2-b2-r15-pool-sha256'),
    ('probe', 'm2-b2-r15-pt-raw', 'r15-pt-raw.bin', 'm2-b2-r15-pt-sha256'),
    ('driver', 'rtl812x-obs-snapshot', 'driver-snapshot-later.bin', None),
    ('driver', 'rtl812x-rxpost', 'rxset-driver-later.bin', None),
    ('driver', 'rtl812x-txmap-raw', 'r21-driver-raw2.bin', None))


def project_path(value):
    path = Path(value)
    if path.is_absolute():
        raise ValueError('workspace paths must be relative to the project: ' + value)
    path = (ROOT / path).resolve()
    path.relative_to(ROOT)
    return path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def property_text(text, key):
    found = re.search(r'"' + re.escape(key) + r'"\s*=\s*"([^"]*)"', text)
    return found.group(1) if found else None


def blob(text, key):
    found = re.findall(r'"' + re.escape(key) + r'"\s*=\s*<([0-9a-fA-F\s]*)>', text)
    values = [bytes.fromhex(value) for value in found]
    if not values:
        return None
    if any(value != values[0] for value in values[1:]):
        raise ValueError('ambiguous ioreg exports for ' + key)
    return values[0]


def command(args):
    try:
        result = subprocess.run(args, cwd=str(ROOT), capture_output=True, text=True,
                                errors='replace', timeout=30, check=False)
        detail = result.stdout
        if result.stderr:
            detail += '\n[stderr]\n' + result.stderr
        return result.returncode, detail
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc) + '\n'


def write_text(path, text):
    with path.open('w', encoding='utf-8', newline='\n') as stream:
        stream.write(text)


def collect_system(out, stamp):
    lines = ['date_utc : ' + stamp]
    for label, args in (
            ('kernel_release', ['uname', '-r']), ('kernel_version', ['uname', '-v']),
            ('kernel_arch', ['uname', '-m']), ('kern.uuid', ['sysctl', '-n', 'kern.uuid']),
            ('kern.boottime', ['sysctl', '-n', 'kern.boottime']), ('hostname', ['hostname'])):
        rc, text = command(args)
        lines.append('%s : %s' % (label, text.strip() if rc == 0 else '(unavailable)'))
    loaded_rc, loaded = command(['kmutil', 'showloaded', '--list-only'])
    identity = ['scope : r28', 'expected_abi : native6/std5/domain3 mode2',
                'captured_utc : ' + stamp, 'kmutil_returncode : %d' % loaded_rc,
                '# loaded kext identity (read-only)', loaded]
    installed = {}
    for name, expected in VERSIONS.items():
        bundle = Path('/Library/Extensions') / (name + '.kext')
        binary = bundle / 'Contents/MacOS' / name
        try:
            info = plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())
            digest = sha(binary.read_bytes())
            version = info.get('CFBundleVersion', '(missing)')
            uuid_rc, uuid_text = command(['xcrun', 'dwarfdump', '--uuid', str(binary)])
            match = re.search(r'UUID:\s*([0-9A-Fa-f-]+)\s*\(x86_64\)', uuid_text)
            uuid = match.group(1) if uuid_rc == 0 and match else '(unavailable)'
            signed_rc, signed = command(['codesign', '--verify', '--strict', str(bundle)])
            installed[name] = {'version': version, 'sha256': digest, 'uuid': uuid,
                               'expected_version': expected, 'codesign_returncode': signed_rc}
            for key, value in (('version', version), ('uuid', uuid), ('sha256', digest)):
                lines.append('%s_%s : %s' % (name, key, value))
            identity.extend(['%s_expected_version : %s' % (name, expected),
                             '%s_codesign_returncode : %d' % (name, signed_rc), signed])
            if name == 'RTL812xLucy':
                params = info.get('IOKitPersonalities', {}).get('RTL8125', {}).get('Driver Parameters', {})
                for key in ('enableTSO4', 'enableTSO6'):
                    value = params.get(key)
                    installed[name][key] = value
                    lines.append('%s_%s : %s' % (name, key, json.dumps(value)))
        except (OSError, ValueError, plistlib.InvalidFileException) as exc:
            installed[name] = {'error': str(exc), 'expected_version': expected}
            lines.append('%s_version : unavailable' % name)
            identity.append('%s_error : %s' % (name, exc))
    write_text(out / 'system.txt', '\n'.join(lines) + '\n')
    write_text(out / 'r27-version-confirmation.txt', '\n'.join(identity) + '\n')
    return installed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('out', help='new or empty project-relative capture directory')
    parser.add_argument('--load', default='runs/r28')
    parser.add_argument('--peer-log', default='runs/r28/peer.log')
    parser.add_argument('--iface', default='en2')
    args = parser.parse_args()
    out, load, peer_log = (project_path(value) for value in (args.out, args.load, args.peer_log))
    if out == load or (out.exists() and any(out.iterdir())):
        raise ValueError('capture output must be new or empty and separate from load input')
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    errors, warnings, exports = [], [], {}
    texts = {}
    for source, name, argv in (
            ('raw', 'props.raw.txt', ['ioreg', '-l', '-w0', '-p', 'IOService']),
            ('probe', 'props.txt', ['ioreg', '-l', '-w0', '-r', '-c', 'org_example_AMDMapperProbe']),
            ('driver', 'driver-obs.txt', ['ioreg', '-l', '-w0', '-r', '-c', 'RTL8125'])):
        rc, text = command(argv)
        texts[source] = text
        write_text(out / name, text)
        if rc or not text.strip():
            errors.append('ioreg capture failed: ' + name)
    copied = out / 'r27-load'
    copied.mkdir()
    # Fixed evidence allowlist: never archive arbitrary source snapshots from load.
    allowed_load = ('token.txt', 'batch.txt', 'requests.txt', 'load.txt', 'client.log',
                    'netstat-before.txt', 'netstat-after.txt', 'expected-version.json',
                    'source-ref.json', 'launchd.out', 'launchd.err', 'deployment.json')
    if load.is_dir():
        for name in allowed_load:
            path = load / name
            if path.is_file():
                shutil.copy2(path, copied / name)
    else:
        errors.append('load directory missing: ' + args.load)
    required = ('token.txt', 'batch.txt', 'requests.txt', 'load.txt', 'client.log',
                'netstat-before.txt', 'netstat-after.txt', 'expected-version.json', 'source-ref.json')
    for name in required + ('launchd.out', 'launchd.err', 'deployment.json'):
        source = load / name
        if source.is_file():
            shutil.copy2(source, out / name)
            if name in required and source.stat().st_size == 0:
                errors.append('empty current load input: ' + name)
        elif name in required:
            errors.append('missing current load input: ' + name)
    if peer_log.is_file() and peer_log.stat().st_size:
        shutil.copy2(peer_log, out / 'peer.log')
    else:
        errors.append('missing or empty peer log: ' + args.peer_log)
    token = batch = requests = None
    try:
        token = int((out / 'token.txt').read_text().strip(), 0)
        batch = int((out / 'batch.txt').read_text().strip())
        requests = int((out / 'requests.txt').read_text().strip())
        if not 0 < token < 0x80000000 or batch != 512 or requests != 8192:
            errors.append('r27 requires a nonzero low-half token, kernel batch512 and 8192 application requests')
    except (OSError, ValueError) as exc:
        errors.append('cannot read token/batch: ' + str(exc))
    all_specs = [entry + (None, True) for entry in EXPORTS] + [
        entry + (False,) for entry in OPTIONAL_EXPORTS]
    for source, key, name, digest_key, required_blob in all_specs:
        try:
            data = blob(texts[source], key)
            if data is None:
                if required_blob:
                    errors.append('missing required raw export: ' + key)
                continue
            expected_bytes = {'r27-rx-raw.bin': 19536, 'r27-rx-map-raw.bin': 12864}.get(name)
            if expected_bytes is not None and len(data) != expected_bytes:
                errors.append('Round28 export size mismatch: %s: %d != %d' %
                              (name, len(data), expected_bytes))
            (out / name).write_bytes(data)
            digest = sha(data)
            published = property_text(texts[source], digest_key) if digest_key else None
            verified = bool(published and published.lower() == digest)
            if digest_key and published and not verified:
                errors.append('producer digest mismatch: ' + key)
            if digest_key and not published:
                warnings.append('no producer digest for optional export: ' + key)
            exports[name] = {'source': key, 'bytes': len(data), 'sha256': digest,
                             'published_sha256_verified': verified}
        except ValueError as exc:
            errors.append(str(exc))
    installed = collect_system(out, stamp)
    network = []
    load_text = (out / 'load.txt').read_text(errors='replace') if (out / 'load.txt').exists() else ''
    peer = re.search(r'^load_peer\s*:\s*([^:\s]+):\d+', load_text, re.M)
    commands = [['ifconfig', args.iface], ['ifconfig', 'en3'],
                ['route', '-n', 'get', 'default'], ['netstat', '-rn', '-f', 'inet']]
    if peer:
        commands.append(['route', '-n', 'get', peer.group(1)])
    for argv in commands:
        rc, text = command(argv)
        network.extend(['$ ' + ' '.join(argv), 'returncode : %d' % rc, text])
    write_text(out / 'network.txt', '\n'.join(network) + '\n')
    rc, dmesg = command(['sudo', '-n', 'dmesg'])
    write_text(out / 'dmesg.txt', '\n'.join(dmesg.splitlines()[-600:]) + '\n')
    if rc:
        warnings.append('dmesg unavailable; read-only sudo -n returned %d' % rc)
    observed = {}
    for name, label, offset in (('r21-domain-raw.bin', 'domain', 0),
                                 ('r21-driver-raw.bin', 'native', 4),
                                 ('r21-std-raw.bin', 'standard', 4),
                                 ('r27-rx-raw.bin', 'rx_driver', 0),
                                 ('r27-rx-map-raw.bin', 'rx_backend', 0)):
        path = out / name
        if path.exists():
            data = path.read_bytes()
            observed[label] = struct.unpack_from('<I', data, offset)[0] if len(data) >= offset + 4 else None
    report = {
        'scope': 'r28', 'captured_utc': stamp, 'interface': args.iface,
        'load_source': args.load, 'peer_source': args.peer_log,
        'declared_token': token, 'token_scope': 'userspace-integrity-and-rx-observation-only',
        'batch': batch, 'application_requests': requests,
        'expected_abi': ABI, 'observed_abi': observed, 'installed': installed,
        'mode': property_text(texts['probe'], 'm2-3g-mode'),
        'rx_mode': property_text(texts['probe'], 'm2-3h-rx-mode'),
        'rx_state': property_text(texts['probe'], 'm2-3h-rx-state'),
        'cleanup': property_text(texts['probe'], 'm2-3b-cleanup'),
        'exports': exports, 'errors': errors, 'warnings': warnings,
        'capture_status': 'incomplete' if errors else 'complete',
        'note': 'archive only; native6/std5/domain3/rx2; internal TX map sequence is not '
                'the client request id; no old ABI verifier or OBS-ring-completeness '
                'requirement; later driver publications are cross-checks only'}
    write_text(out / 'R27-EXPORTS.json', json.dumps(report, indent=2) + '\n')
    lines = ['scope : r28', 'captured_utc : ' + stamp,
             'interface : ' + args.iface, 'expected_abi : native6/std5/domain3 mode2',
             'capture_status : ' + report['capture_status'],
             'No correctness verdict; hashes are computed from archived bytes.',
             'files (sha256, bytes, relative name):']
    for path in sorted(out.rglob('*')):
        if path.is_file() and path.name != 'MANIFEST.txt':
            data = path.read_bytes()
            lines.append('  %s  %10d  %s' % (sha(data), len(data), path.relative_to(out).as_posix()))
    write_text(out / 'MANIFEST.txt', '\n'.join(lines) + '\n')
    print('Round28 capture %s: %s' % (report['capture_status'], args.out))
    for error in errors:
        print('  INCOMPLETE: ' + error)
    return int(bool(errors))


if __name__ == '__main__':
    raise SystemExit(main())
