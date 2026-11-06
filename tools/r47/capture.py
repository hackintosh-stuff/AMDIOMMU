#!/usr/bin/env python3
"""Archive the ordinary IPv6 TCP/TSO run and installed binary identity."""
import argparse
import datetime
import json
import shutil
from common import PHASES, VERSIONS, module, project_path, sha, write_json

C = module('_r47_capture_helpers', 'tools/r27/capture.py')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('out')
    parser.add_argument('--load', default='runs/r47')
    parser.add_argument('--peer-log', default='runs/r47/peer.log')
    args = parser.parse_args()
    out, load, peer = (project_path(v) for v in (args.out, args.load, args.peer_log))
    if out == load or (out.exists() and any(out.iterdir())):
        raise ValueError('capture must be new or empty and separate from load')
    out.mkdir(parents=True, exist_ok=True)
    errors = []
    for name in ('token.txt', 'client.log', 'load.txt', 'source-ref.json',
                 'deployment.json', 'expected-version.json'):
        try:
            shutil.copyfile(load / name, out / name)
        except OSError as exc:
            errors.append(str(exc))
    for name in ('launchd.out', 'launchd.err'):
        if (load / name).exists():
            shutil.copyfile(load / name, out / name)
    if (load / 'snapshots').is_dir():
        shutil.copytree(load / 'snapshots', out / 'snapshots')
    for label in PHASES:
        if not (out / 'snapshots' / label / 'snapshot.json').is_file():
            errors.append('missing lifecycle snapshot: ' + label)
    try:
        shutil.copyfile(peer, out / 'peer.log')
    except OSError as exc:
        errors.append(str(exc))
    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    installed = C.collect_system(out, stamp, VERSIONS, 'r47', 'ordinary-device-mapper1')
    for name, command in (
            ('probe.txt', ['ioreg', '-l', '-w0', '-r', '-c', 'org_maz1_AMDMapperProbe']),
            ('driver.txt', ['ioreg', '-l', '-w0', '-r', '-c', 'RTL8125']),
            ('boot-args.txt', ['sysctl', '-n', 'kern.bootargs']),
            ('network.txt', ['ifconfig', 'en2']),
            ('dmesg.txt', ['sudo', '-n', 'dmesg'])):
        rc, text = C.command(command)
        C.write_text(out / name, text)
        if rc and name != 'dmesg.txt':
            errors.append('%s returned %d' % (name, rc))
    files = {p.relative_to(out).as_posix(): {'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())}
             for p in sorted(out.rglob('*')) if p.is_file()}
    write_json(out / 'manifest.json', {'scope': 'r47', 'captured_utc': stamp,
                                     'installed': installed, 'files': files, 'errors': errors})
    print(json.dumps({'capture': args.out, 'files': len(files), 'errors': errors}, indent=2))
    return int(bool(errors))


if __name__ == '__main__':
    raise SystemExit(main())
