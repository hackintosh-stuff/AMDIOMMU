#!/usr/bin/env python3
"""R52 endpoint selection and per-instance ABI2 snapshots."""
import ctypes
import importlib.util
import json
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
PHASES = ('before', 'down', 'after-up')
OFF_PHASES = ('before', 'after')
VERSIONS = {'RTL812xLucy': '1.1.237', 'AMDMapperProbe': '0.59.0'}
BASE_COMMIT = 'a75864596ba0e371685f029e7978d795fce1d39f'
MAX_MAP_PAGES = MAX_RUNS = 64
RX_GROUPS, RX_GROUP_PAGES, PERSISTENT_MAPS = 16, 64, 19


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


C = module('_r52_abi2_helpers', 'tools/ordinary/common.py')
DBG = module('_amdiommu_dbgmask', 'tools/dbgmask.py')
protocol = module('_r52_tcp_protocol', 'tools/mixed/protocol.py')
project_path, sha, write_json = C.project_path, C.sha, C.write_json
# These exports also let the existing R44 page-table walker import normally.
active, identity = C.active, C.identity


def read_snapshot(path):
    return C.read_snapshot(path, abi=2)


def requester(text):
    match = re.fullmatch(r'(?:(0000):)?([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])', text)
    if not match:
        raise ValueError('BDF must be segment-zero hexadecimal bb:dd.f: ' + text)
    bus, device, function = (int(match[n], 16) for n in (2, 3, 4))
    if device >= 32:
        raise ValueError('PCI device number exceeds 31')
    return (bus << 8) | (device << 3) | function


def configuration(path):
    value = json.loads(path.read_text(encoding='utf-8'))
    devices = value['devices']
    if len(devices) != 2 or value['down_target'] not in devices:
        raise ValueError('select two devices and name exactly one down_target')
    selected = []
    for name, endpoint in devices.items():
        for key in ('interface', 'bdf', 'local_ipv6', 'peer_ipv6', 'port'):
            if key not in endpoint:
                raise ValueError(name + ': missing endpoint ' + key)
        if not re.fullmatch(r'en[0-9]+', endpoint['interface']):
            raise ValueError('an explicit existing Ethernet interface is required')
        if not isinstance(endpoint['port'], int) or not 0 < endpoint['port'] <= 65535:
            raise ValueError('invalid peer TCP port')
        endpoint['requester'] = requester(endpoint['bdf'])
        selected.append(endpoint)
    if (len({d['interface'] for d in selected}) != 2 or
            len({d['requester'] for d in selected}) != 2):
        raise ValueError('the two selected interfaces and requesters must differ')
    management = value.get('management', {})
    if management.get('interface') in {d['interface'] for d in selected}:
        raise ValueError('management must use a separate existing interface')
    return value


def roles(config):
    target = config['down_target']
    other = next(name for name in config['devices'] if name != target)
    return {role: dict(config['devices'][name], name=name)
            for role, name in (('a', target), ('b', other))}


def nodes(tree, parents=()):
    if isinstance(tree, list):
        for node in tree:
            yield from nodes(node, parents)
    elif isinstance(tree, dict):
        yield tree, parents
        for child in tree.get('IORegistryEntryChildren', []):
            yield from nodes(child, parents + (tree,))


def registry():
    tree = plistlib.loads(subprocess.check_output(
        ['ioreg', '-a', '-l', '-w0', '-p', 'IOService']))
    DBG.require(DBG.BASE, 'ioreg registry', tree)
    return tree


def bsd_name(node):
    """ioreg -a exposes the human-readable property key; accept both spellings."""
    return node.get('BSD Name') or node.get('IOBSDName')


def selected_drivers(tree, config):
    result = {}
    for role, endpoint in roles(config).items():
        matches = [(node, parents) for node, parents in nodes(tree)
                   if (node.get('IOObjectClass') == 'RTL8125' or
                       'rtl812x-r44-mapper-found' in node) and
                   any(bsd_name(child) == endpoint['interface']
                       for child, _ in nodes(node))]
        if len(matches) != 1:
            raise ValueError('expected one Lucy instance owning ' + endpoint['interface'])
        driver, parents = matches[0]
        pci = next((node for node in reversed(parents) if 'pcidebug' in node), None)
        # IOPCIConfigurator publishes decimal "%u:%u:%u" in pcidebug.
        # This also identifies the unmodified R51 driver in amdiommu=off.
        address = re.fullmatch(r'(\d+):(\d+):(\d+)', pci.get('pcidebug', '') if pci else '')
        if not address:
            raise ValueError('missing endpoint PCI ancestor for ' + endpoint['interface'])
        bus, device, function = map(int, address.groups())
        actual = (bus << 8) | (device << 3) | function
        if actual != endpoint['requester']:
            raise ValueError(endpoint['interface'] + ': configured BDF differs from its PCI ancestor')
        declared = driver.get('rtl812x-r52-requester', actual)
        if declared != actual:
            raise ValueError('Lucy requester differs from its PCI ancestor')
        result[role] = {'node': driver, 'binding': dict(endpoint,
                        driver_registry_id=driver['IORegistryEntryID'],
                        pci_registry_id=pci['IORegistryEntryID'], observed_requester=actual)}
    return result


def set_booleans(entries):
    """Publish one property on each listed exact registry entry in a single walk.

    Every publication is an independent RPC, so the caller's snapshot pair can
    only be coherent if the publications happen together. Walking the IOService
    plane once for the whole set keeps them milliseconds apart instead of
    seconds, and never matches a same-class entry by order.
    """
    if sys.platform != 'darwin':
        raise RuntimeError('IORegistry snapshot RPC requires macOS')
    if not entries:
        return
    wanted = {int(entry_id): name for entry_id, name in entries.items()}
    io = ctypes.CDLL('/System/Library/Frameworks/IOKit.framework/IOKit')
    cf = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
    port, ptr = ctypes.c_uint32, ctypes.c_void_p
    io.IORegistryGetRootEntry.argtypes, io.IORegistryGetRootEntry.restype = [port], port
    io.IORegistryEntryCreateIterator.argtypes = [port, ctypes.c_char_p, port, ctypes.POINTER(port)]
    io.IORegistryEntryCreateIterator.restype = port
    io.IOIteratorNext.argtypes, io.IOIteratorNext.restype = [port], port
    io.IORegistryEntryGetRegistryEntryID.argtypes = [port, ctypes.POINTER(ctypes.c_uint64)]
    io.IORegistryEntryGetRegistryEntryID.restype = port
    io.IORegistryEntrySetCFProperties.argtypes = [port, ptr]
    io.IORegistryEntrySetCFProperties.restype = port
    io.IOObjectRelease.argtypes, io.IOObjectRelease.restype = [port], port
    cf.CFStringCreateWithCString.argtypes = [ptr, ctypes.c_char_p, port]
    cf.CFStringCreateWithCString.restype = ptr
    cf.CFDictionaryCreate.argtypes = [ptr, ctypes.POINTER(ptr), ctypes.POINTER(ptr), ctypes.c_long, ptr, ptr]
    cf.CFDictionaryCreate.restype = ptr
    cf.CFRelease.argtypes, cf.CFRelease.restype = [ptr], None
    root, iterator = io.IORegistryGetRootEntry(0), port()
    keys, published = {}, set()
    try:
        if not root or io.IORegistryEntryCreateIterator(root, b'IOService', 1, ctypes.byref(iterator)):
            raise RuntimeError('cannot iterate IOService plane')
        while wanted:
            entry = io.IOIteratorNext(iterator)
            if not entry:
                raise RuntimeError('registry entry disappeared: %d' % sorted(wanted)[0])
            identity_value = ctypes.c_uint64()
            if (io.IORegistryEntryGetRegistryEntryID(entry, ctypes.byref(identity_value)) == 0 and
                    identity_value.value in wanted):
                name = wanted.pop(identity_value.value)
                key = keys.setdefault(name, cf.CFStringCreateWithCString(None, name.encode('ascii'), 0x08000100))
                if not key:
                    raise RuntimeError('cannot create snapshot property key')
                boolean = ptr.in_dll(cf, 'kCFBooleanTrue')
                properties = cf.CFDictionaryCreate(None, (ptr * 1)(key), (ptr * 1)(boolean.value), 1, None, None)
                if not properties:
                    raise RuntimeError('cannot create snapshot property dictionary')
                try:
                    status = io.IORegistryEntrySetCFProperties(entry, properties)
                    if status:
                        raise RuntimeError('%s on %d returned 0x%08x' % (name, identity_value.value, status))
                    published.add(identity_value.value)
                finally:
                    cf.CFRelease(properties)
            io.IOObjectRelease(entry)
    finally:
        for key in keys.values():
            if key:
                cf.CFRelease(key)
        if iterator.value:
            io.IOObjectRelease(iterator.value)
        if root:
            io.IOObjectRelease(root)


def set_boolean(entry_id, name):
    """Send a synchronous RPC to one exact retained registry entry, never first-match."""
    set_booleans({entry_id: name})


def scalars(node, prefixes):
    return {key: value for key, value in node.items()
            if key.startswith(prefixes) and isinstance(value, (str, int, bool))}


def snapshot(parent, label, config, mode):
    out = parent / label
    out.mkdir(parents=True, exist_ok=False)
    tree = registry()
    DBG.require(DBG.MAPPING | DBG.RAW, 'mapper snapshot', tree)
    drivers = selected_drivers(tree, config)
    if mode == 'auto':
        deadline = time.monotonic() + 5
        while True:
            for value in drivers.values():
                set_boolean(value['binding']['driver_registry_id'], 'R47Snapshot')
            tree = registry()
            drivers = selected_drivers(tree, config)
            if all(d['node'].get(p + 'posted') is not None and
                   d['node'][p + 'posted'] == d['node'].get(p + 'completed')
                   for d in drivers.values() for p in ('rtl812x-r45-tso4-', 'rtl812x-r46-tso6-')):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('TSO completion did not drain for the selected instances')
            time.sleep(.02)
    controller, domains = {}, []
    if mode == 'auto':
        owners = [node for node, _ in nodes(tree) if node.get('r52-role') == 'controller']
        if len(owners) != 1:
            raise ValueError('expected exactly one shared R52 controller')
        owner_id = owners[0]['IORegistryEntryID']
        set_boolean(owner_id, 'PublishAllDomains')  # Formerly R52Snapshot.
        tree = registry()
        owner = next(node for node, _ in nodes(tree) if node.get('IORegistryEntryID') == owner_id)
        controller = scalars(owner, ('r52-',))
        controller['registry_id'] = owner_id
        domains = owner['r52-domains']
        drivers = selected_drivers(tree, config)
    for role, selected in drivers.items():
        folder = out / role
        folder.mkdir()
        driver, binding = selected['node'], selected['binding']
        value = {'label': label, 'captured_ns': time.monotonic_ns(), 'binding': binding,
                 'driver': scalars(driver, ('rtl812x-',)), 'probe': {}, 'exports': {}}
        if mode == 'auto':
            matched = [p for p in domains if p.get('r52-requester') == binding['requester']]
            if len(matched) != 1:
                raise ValueError('missing/duplicate device domain for ' + binding['bdf'])
            probe = matched[0]
            if (driver.get('rtl812x-r52-mapper-id') != probe['r52-mapper-id'] or
                    driver.get('rtl812x-r52-domain-id') != probe['r44-domain-id']):
                raise ValueError('driver is bound to a different device mapper')
            value['probe'] = scalars(probe, ('r44-', 'r47-', 'r48-', 'r50-', 'r51-', 'r52-'))
            for key, name in C.EXPORTS.items():
                raw = probe[key]
                if not isinstance(raw, bytes):
                    raise ValueError('missing device raw snapshot ' + key)
                (folder / name).write_bytes(raw)
                value['exports'][name] = {'bytes': len(raw), 'sha256': sha(raw)}
        elif driver.get('rtl812x-r44-mapped-dma', 0):
            raise ValueError('off baseline unexpectedly uses mapped DMA')
        write_json(folder / 'snapshot.json', value)
    write_json(out / 'phase.json', {'label': label, 'mode': mode, 'controller': controller,
                                   'captured_ns': time.monotonic_ns()})


def boot_mode(mode):
    boot = subprocess.check_output(['sysctl', '-n', 'kern.bootargs'], text=True).split()
    if [arg for arg in boot if arg.startswith('amdiommu=')] != ['amdiommu=' + mode]:
        raise ValueError('running kernel must use amdiommu=' + mode)
    if mode == 'auto':
        for name, expected in VERSIONS.items():
            info = plistlib.loads((Path('/Library/Extensions') /
                                  (name + '.kext/Contents/Info.plist')).read_bytes())
            if info.get('CFBundleVersion') != expected:
                raise ValueError('installed %s must be %s' % (name, expected))
    return ' '.join(boot)
