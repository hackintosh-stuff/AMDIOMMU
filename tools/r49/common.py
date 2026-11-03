#!/usr/bin/env python3
"""R49 captures 64-page ordinary DMA32 mappings using mapper ABI2."""
from functools import partial
import importlib.util
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[2]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


C = module('_r49_ordinary_common', 'tools/r44/common.py')
protocol = module('_r49_tcp_protocol', 'tools/r49/protocol.py')
PHASES = ('before', 'pre-down', 'down', 'after-up')
VERSIONS = {'RTL812xLucy': '1.1.234', 'AMDMapperProbe': '0.56.0'}
VERSION, SNAPSHOT_BYTES, RECORD_BYTES = 2, 1472, 616
MAX_MAP_PAGES = MAX_RUNS = 64
RX_GROUPS, RX_GROUP_PAGES, PERSISTENT_MAPS = 16, 64, 19
active = partial(C.active, min_maps=PERSISTENT_MAPS)
identity = C.identity
read_snapshot = partial(C.read_snapshot, abi=VERSION)
project_path, sha, write_json = C.project_path, C.sha, C.write_json
decode = partial(C.decode, abi=VERSION)
load_helpers, session = C.load_helpers, C.session


def sample_driver():
    # The same command-gate action publishes both IPv4 and IPv6 counters.
    session.set_boolean_property('R47Snapshot', service_class='RTL8125')
    return C.registry('RTL8125', 'rtl812x-r44-mapper-found')


def snapshot(parent, label):
    # Drain real hardware completions before normal lifecycle observations.
    deadline = time.monotonic() + 5
    while True:
        d = sample_driver()
        prefixes = ('rtl812x-r45-tso4-', 'rtl812x-r46-tso6-')
        if all(d.get(p + 'posted') is not None and
               d[p + 'posted'] == d.get(p + 'completed') for p in prefixes):
            break
        if time.monotonic() >= deadline:
            raise RuntimeError('IPv4/IPv6 TSO did not complete before the lifecycle snapshot')
        time.sleep(.02)
    value = C.snapshot(parent, label,
                       driver_prefixes=('rtl812x-r44-', 'rtl812x-r45-', 'rtl812x-r46-', 'rtl812x-r47-', 'rtl812x-r48-'),
                       probe_prefixes=('r44-', 'r47-', 'r48-'),
                       extra_exports={'r47-ivrs-raw': 'ivrs.bin'}, abi=VERSION)
    if not active(value):
        raise RuntimeError('ordinary device mapper is not active')
    return value
