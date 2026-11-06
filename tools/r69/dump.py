#!/usr/bin/env python3
"""Print the probe's per-instance properties from one ioreg XML query."""
import plistlib
import subprocess
import sys

KEYS = (
    'r52-role', 'r52-requester', 'r44-state', 'r44-parent', 'r44-domain-id',
    'r44-live-maps', 'r44-live-pages', 'r44-map-ok', 'r44-map-rejected',
    'r44-unmap-ok', 'r44-dte-active', 'r44-target-faults',
    'r69-max-map-length', 'r69-max-map-pages', 'r69-max-map-runs',
    'r69-rejects-length', 'r69-rejects-options', 'r69-rejects-layout',
    'r69-rejects-records', 'r69-rejects-norange', 'r69-rejects-bits',
    'r44-controller-ready-time', 'r44-snapshot-sequence',
    'r52-controller-target-faults', 'r52-controller-ready',
    'r52-controller-cmd-submits', 'r52-domain-count', 'r69-autoattach',
)


def walk(node, out):
    if isinstance(node, dict):
        if node.get('IOClass') == 'org_maz1_AMDMapperProbe':
            out.append(node)
        for value in node.values():
            walk(value, out)
    elif isinstance(node, list):
        for value in node:
            walk(value, out)


def main():
    raw = subprocess.run(['ioreg', '-a', '-l', '-w0', '-c',
                          'org_maz1_AMDMapperProbe'],
                         capture_output=True).stdout
    tree = plistlib.loads(raw)
    found = []
    walk(tree, found)
    print('instances: %d' % len(found))
    for index, node in enumerate(found):
        print('--- [%d] %s' % (index, node.get('IORegistryEntryName', '?')))
        for key in KEYS:
            if key in node:
                print('    %-28s %s' % (key, node[key]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
