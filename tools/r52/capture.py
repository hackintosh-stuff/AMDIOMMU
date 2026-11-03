#!/usr/bin/env python3
"""Archive only the selected R52 run, both receipts and installed identities."""
import argparse
import datetime
import json
import shutil
from common import OFF_PHASES, PHASES, VERSIONS, module, project_path, sha, write_json

C = module('_r52_capture_helpers', 'tools/r27/capture.py')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('out')
    parser.add_argument('--load', required=True)
    parser.add_argument('--peer-a-log', required=True)
    parser.add_argument('--peer-b-log', required=True)
    args = parser.parse_args()
    out, load = project_path(args.out), project_path(args.load)
    if out == load or (out.exists() and any(out.iterdir())):
        raise ValueError('capture must be new or empty, separate from load')
    run = json.loads((load / 'run.json').read_text(encoding='utf-8'))
    mode, errors = run['mode'], []
    out.mkdir(parents=True, exist_ok=True)
    required = ['token.txt', 'run.json', 'endpoints.json', 'client.log', 'load.txt', 'running-boot-args.txt']
    if mode == 'auto':
        required += ['source-ref.json', 'deployment.json', 'expected-version.json']
    for name in required:
        try:
            shutil.copyfile(load / name, out / name)
        except OSError as exc:
            errors.append(str(exc))
    for name in ('launchd.out', 'launchd.err'):
        if (load / name).exists():
            shutil.copyfile(load / name, out / name)
    if (load / 'snapshots').is_dir():
        shutil.copytree(load / 'snapshots', out / 'snapshots')
    for phase in PHASES if mode == 'auto' else OFF_PHASES:
        for relative in ('phase.json', 'a/snapshot.json', 'b/snapshot.json'):
            if not (out / 'snapshots' / phase / relative).is_file():
                errors.append('missing lifecycle snapshot: ' + phase + '/' + relative)
    for role, path in (('a', args.peer_a_log), ('b', args.peer_b_log)):
        try:
            shutil.copyfile(project_path(path), out / ('peer-' + role + '.log'))
        except OSError as exc:
            errors.append(str(exc))
    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    installed = C.collect_system(out, stamp, VERSIONS, 'r52', 'two-device-mapper-ABI2')
    commands = [('boot-args.txt', ['sysctl', '-n', 'kern.bootargs']),
                ('probe.txt', ['ioreg', '-l', '-w0', '-r', '-c', 'org_example_AMDMapperProbe']),
                ('driver.txt', ['ioreg', '-l', '-w0', '-r', '-c', 'RTL8125'])]
    commands += [('network-' + role + '.txt', ['ifconfig', endpoint['interface']])
                 for role, endpoint in run['roles'].items()]
    for name, argv in commands:
        status, text = C.command(argv)
        C.write_text(out / name, text)
        if status:
            errors.append('%s returned %d' % (name, status))
    _, text = C.command(['sudo', '-n', 'dmesg'])
    C.write_text(out / 'dmesg.txt', text)
    files = {p.relative_to(out).as_posix(): {'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())}
             for p in sorted(out.rglob('*')) if p.is_file()}
    write_json(out / 'manifest.json', {'scope': 'r52', 'mode': mode, 'captured_utc': stamp,
                                     'installed': installed, 'files': files, 'errors': errors})
    print(json.dumps({'capture': args.out, 'files': len(files), 'errors': errors}, indent=2))
    return int(bool(errors))


if __name__ == '__main__':
    raise SystemExit(main())
