#!/usr/bin/env python3
"""R45 uses the accepted ordinary mapper ABI and adds sampled TSO counters."""
import importlib.util
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[2]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


C = module('_r45_ordinary_common', 'tools/r44/common.py')
protocol = module('_r45_tcp_protocol', 'tools/r45/protocol.py')
PHASES = ('before', 'pre-down', 'down', 'after-up')
VERSIONS = {'RTL812xLucy': '1.1.230', 'AMDMapperProbe': '0.53.0'}
VERSION, SNAPSHOT_BYTES, RECORD_BYTES = C.VERSION, C.SNAPSHOT_BYTES, C.RECORD_BYTES
active, identity, read_snapshot = C.active, C.identity, C.read_snapshot
project_path, sha, write_json = C.project_path, C.sha, C.write_json
decode, load_helpers, session = C.decode, C.load_helpers, C.session


def sample_driver():
    session.set_boolean_property('R45Snapshot', service_class='RTL8125')
    return C.registry('RTL8125', 'rtl812x-r44-mapper-found')


def snapshot(parent, label):
    # TCP receipt completion can precede the final hardware TX interrupt.
    # Wait only for actual completion; no retransmission or synthetic retirement.
    deadline = time.monotonic() + 5
    while True:
        d = sample_driver()
        posted = d.get('rtl812x-r45-tso4-posted')
        completed = d.get('rtl812x-r45-tso4-completed')
        if posted is not None and posted == completed:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError('TSO packets did not complete before the lifecycle snapshot')
        time.sleep(.02)
    value = C.snapshot(parent, label, driver_prefixes=('rtl812x-r44-', 'rtl812x-r45-'))
    if not active(value):
        raise RuntimeError('ordinary device mapper is not active')
    return value
