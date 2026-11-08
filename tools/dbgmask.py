#!/usr/bin/env python3
"""Read the amdiommu_dbg publication mask from a capture or kern.bootargs."""
import re
import subprocess

BASE = 0x01
SELECT = 0x02
ATTACH = 0x04
DISCOVERY = 0x08
MAPPING = 0x10
PM = 0x20
RAW = 0x40
DEBUG = 0x80
ALL = 0xFF
# A capture from a build older than the mask has neither the property nor the
# boot argument. Treat it as the historical full surface, not as 0x00.
LEGACY = ALL


def parse(value):
    if isinstance(value, int):
        return value if 0 <= value <= ALL else None
    if isinstance(value, bytes):
        value = value.decode('ascii', 'replace')
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r'\s*0x([0-9a-fA-F]{1,8})\s*', value)
    if not match:
        return None
    number = int(match.group(1), 16)
    return number if number <= ALL else None


def _nodes(tree):
    if isinstance(tree, list):
        for node in tree:
            yield from _nodes(node)
    elif isinstance(tree, dict):
        yield tree
        for child in tree.get('IORegistryEntryChildren', []):
            yield from _nodes(child)


def from_tree(tree):
    if tree is None:
        return None
    for node in _nodes(tree):
        value = parse(node.get('amdiommu-dbg'))
        if value is not None:
            return value
    return None


def from_bootargs():
    try:
        text = subprocess.check_output(
            ['sysctl', '-n', 'kern.bootargs'], text=True, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r'(?:^|\s)amdiommu_dbg=(0x[0-9a-fA-F]{1,8})(?=\s|$)', text)
    if not match:
        return None
    number = int(match.group(1), 16)
    return number if number <= ALL else None


def current(tree=None):
    value = from_tree(tree)
    if value is not None:
        return value
    value = from_bootargs()
    return LEGACY if value is None else value


def require(need, why, tree=None):
    mask = current(tree)
    missing = need & ~mask
    if missing:
        raise ValueError(
            '%s needs amdiommu_dbg=0x%02x (current=0x%02x); '
            'that evidence group is masked off' % (why, need, mask))
    return mask
