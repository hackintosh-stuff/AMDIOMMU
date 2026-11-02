#!/usr/bin/env python3
"""probe_sources.py -- read the WHOLE probe, across its modules.

WHY
---
Round 11 split kext/AMDMapperProbe.cpp into eight translation units plus a
shared header. Tools that want to assert something about "the probe's source"
used to open that one path. After the split that path holds only the entry
point, so such an assertion either fails or -- worse -- matches a fragment and
reports success.

This helper is the single place that knows the module list. Anything that
inspects the probe's text should use it rather than hard-coding a filename.
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MODULES = [
    'AMDMapperProbe.cpp',
    'AMDMapperProbeNic.cpp',
    'AMDMapperProbeB1B2.cpp',
    'AMDMapperProbeMmio.cpp',
    'AMDMapperProbeTable.cpp',
    'AMDMapperProbeDma.cpp',
    'AMDMapperProbeObs.cpp',
    'AMDMapperProbePgt.cpp',
    'AMDMapperProbeInternal.hpp',
]


def paths(root=None):
    """Every probe source file, in module order."""
    r = root or ROOT
    return [os.path.join(r, 'kext', m) for m in MODULES]


def text(root=None):
    """The concatenation of every probe source file.

    Concatenated, not searched file by file, because the question these tools
    ask is "does the probe contain X" -- a property of the probe as a whole.
    Which module X happens to live in is an implementation detail of the split.
    """
    out = []
    for p in paths(root):
        with open(p, encoding='utf-8') as f:
            out.append(f.read())
    return '\n'.join(out)


def missing(root=None):
    """Modules that are not present; empty means the tree is complete."""
    return [p for p in paths(root) if not os.path.exists(p)]
