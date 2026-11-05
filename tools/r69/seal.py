#!/usr/bin/env python3
"""Seal the Round69 evidence archive: run data plus source pins, no source tree."""
import hashlib
import json
import subprocess
import tarfile
from pathlib import Path

RUN = Path('/Users/ling/AMDIOMMU/runs/r69')
OUT = Path('/Users/ling/AMDIOMMU/r69-final-20261105.tgz')
BUILD = Path('/Users/ling/AMDIOMMU/r69-build.log')
ALLOWED = {'source-ref.json', 'closure.txt', 'pre', 'boot-a', 'panic'}


def main():
    entries = sorted(p for p in RUN.iterdir() if p.name in ALLOWED)
    missing = ALLOWED - {p.name for p in RUN.iterdir()}
    if missing:
        raise SystemExit('missing run members: %s' % sorted(missing))

    with tarfile.open(OUT, 'w:gz') as tar:
        for item in entries:
            tar.add(item, arcname=item.name)
        if BUILD.is_file():
            tar.add(BUILD, arcname='r69-build.log')

    digest = hashlib.sha256(OUT.read_bytes()).hexdigest()
    count = len(tarfile.open(OUT).getnames())
    print('archive: %s' % OUT)
    print('bytes  : %d' % OUT.stat().st_size)
    print('entries: %d' % count)
    print('sha256 : %s' % digest)

    (OUT.with_suffix('.tgz.sha256')).write_text(
        '%s  %s\n' % (digest, OUT.name))
    manifest = {
        'round': 69,
        'verdict': 'BLOCKED',
        'archive': OUT.name,
        'bytes': OUT.stat().st_size,
        'entries': count,
        'sha256': digest,
        'members': sorted(p.name for p in entries) + (
            ['r69-build.log'] if BUILD.is_file() else []),
    }
    (OUT.with_suffix('.tgz.manifest.json')).write_text(
        json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
