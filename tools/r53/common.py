#!/usr/bin/env python3
"""Select the mixed RTL8111/RTL8125 endpoints and export their native DMA evidence."""
import json
import plistlib
import re
import struct
import subprocess
import time
from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[2]
BASE_COMMIT = '2be76054f30e208d57658dc7efa3df79c9050f7c'
VERSIONS = {'RTL812xLucy': '1.1.238', 'AMDMapperProbe': '0.60.0', 'RealtekRTL8111': '3.0.53'}
PHASES, OFF_PHASES = ('before', 'down', 'after-up'), ('before', 'after')
MAX_MAP_PAGES = MAX_RUNS = 64
RX_GROUPS, RX_GROUP_PAGES, PERSISTENT_MAPS = 16, 64, 19
PROFILES = {
    'RTL8111': {'vendor_id': 0x10ec, 'device_id': 0x8168, 'prefix': 'rtl8111-r53-',
                'identity_prefix': 'rtl8111-r53-', 'snapshot': 'R53Snapshot',
                'rx_groups': 32, 'rx_pages': 16, 'rx_slots': 512,
                'fixed': {'tx': 8192, 'rx': 8192, 'tally': 64}},
    'RTL8125': {'vendor_id': 0x10ec, 'device_id': 0x8127, 'prefix': 'rtl812x-r44-',
                'identity_prefix': 'rtl812x-r52-', 'snapshot': 'R47Snapshot',
                'rx_groups': 16, 'rx_pages': 64, 'rx_slots': 1024,
                'fixed': {'tx': 32768, 'rx': 16384, 'tally': 192}}
}
ACTIVE_CONFIG = None


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


C = module('_r53_existing_snapshot_helpers', 'tools/r52/common.py')
protocol = module('_r53_tcp_protocol', 'tools/r53/protocol.py')
project_path, sha, write_json = C.project_path, C.sha, C.write_json
nodes, registry, set_boolean = C.nodes, C.registry, C.set_boolean
active, identity = C.active, C.identity
C.VERSIONS = VERSIONS


def configuration(path):
    global ACTIVE_CONFIG
    config = C.configuration(path)
    classes = []
    for endpoint in config['devices'].values():
        kind = endpoint['driver_class']
        profile = PROFILES[kind]
        for key in ('vendor_id', 'device_id'):
            text = endpoint[key]
            if not isinstance(text, str) or not re.fullmatch(r'[0-9a-fA-F]{4}', text):
                raise ValueError(key + ' must be four hexadecimal digits')
            if int(text, 16) != profile[key]:
                raise ValueError('configured PCI identity differs from ' + kind)
            endpoint[key] = text.lower()
        classes.append(kind)
    if set(classes) != set(PROFILES) or config['devices'][config['down_target']]['driver_class'] != 'RTL8111':
        raise ValueError('select RTL8111 as down_target and one RTL8125 as the other endpoint')
    ACTIVE_CONFIG = config
    return config


roles = C.roles


def pci_number(node, name):
    value = node.get(name)
    if isinstance(value, bytes):
        return int.from_bytes(value, 'little')
    if isinstance(value, int):
        return value
    return None


def pci_requester(node):
    match = re.fullmatch(r'(\d+):(\d+):(\d+)', node.get('pcidebug', ''))
    if match:
        bus, device, function = map(int, match.groups())
        return (bus << 8) | (device << 3) | function
    return None


def selected_drivers(tree, config):
    selected = {}
    for role, endpoint in roles(config).items():
        profile, kind = PROFILES[endpoint['driver_class']], endpoint['driver_class']
        matches = [(node, parents) for node, parents in nodes(tree)
                   if (node.get('IOObjectClass') == kind or node.get('IOClass') == kind or
                       profile['prefix'] + 'mapper-found' in node) and
                   any(C.bsd_name(child) == endpoint['interface'] for child, _ in nodes(node))]
        if len(matches) != 1:
            raise ValueError('expected one ' + kind + ' owning ' + endpoint['interface'])
        driver, parents = matches[0]
        pci = next((node for node in reversed(parents) if 'pcidebug' in node), None)
        actual = pci_requester(pci) if pci else None
        if (actual != endpoint['requester'] or
                pci_number(pci, 'vendor-id') != profile['vendor_id'] or
                pci_number(pci, 'device-id') != profile['device_id']):
            raise ValueError(endpoint['interface'] + ': configured PCI identity differs from its ancestor')
        declared = driver.get(profile['identity_prefix'] + 'requester', actual)
        if declared != actual:
            raise ValueError(kind + ' requester differs from its PCI ancestor')
        selected[role] = {'node': driver, 'binding': dict(endpoint,
            driver_registry_id=driver['IORegistryEntryID'], pci_registry_id=pci['IORegistryEntryID'],
            observed_requester=actual, observed_vendor_id=pci_number(pci, 'vendor-id'),
            observed_device_id=pci_number(pci, 'device-id'),
            dma_policy=pci.get('amdiommu-dma-policy', 'unpublished'))}
    return selected


def selector(config):
    return ','.join('%04x' % row['requester'] for row in roles(config).values())


def validate_selector(boot, config):
    values = [arg.split('=', 1)[1] for arg in boot.split() if arg.startswith('amdiommu_devices=')]
    if len(values) != 1 or not re.fullmatch(r'[0-9a-fA-F]{4},[0-9a-fA-F]{4}', values[0]):
        raise ValueError('running kernel needs one explicit two-requester amdiommu_devices selector')
    if {int(value, 16) for value in values[0].split(',')} != {d['requester'] for d in roles(config).values()}:
        raise ValueError('running requester selector differs from endpoint configuration')


def boot_mode(mode):
    boot = C.boot_mode(mode)
    if mode == 'auto':
        if ACTIVE_CONFIG is None:
            raise ValueError('load endpoint configuration before checking the selector')
        validate_selector(boot, ACTIVE_CONFIG)
    return boot


def live_addresses(probe):
    """Decode the mapped IOVA of every live record a domain just published.

    The records travel as one opaque blob inside the domain dictionary, so the
    capture can join them to a driver snapshot without writing a file first.
    ABI2 records lead with handle, firstPA, mapAddress, so mapAddress is the
    third 64-bit word.
    """
    raw = probe.get('r44-live-raw')
    if not isinstance(raw, bytes):
        return None
    count = probe.get('r44-live-maps')
    if not isinstance(count, int) or count <= 0 or len(raw) != count * 616:
        return None
    return [{'mapAddress': struct.unpack_from('<Q', raw, index * 616 + 16)[0]}
            for index in range(count)]


def rx_groups_consistent(driver, rows):
    """Say whether a driver snapshot and that domain's mapper rows agree.

    rxInterruptVTD() rewrites one batch of IOVAs at a time. A driver snapshot
    and the mapper records taken at different instants then name different
    bases for the same group, which is exactly the state that would let a NIC
    write an IOVA the driver has already unmapped. The driver's own export
    names the IOVA each group occupies now, so every exported base must be a
    live mapping.
    """
    if not isinstance(driver.get('rtl8111-r53-live'), bytes) or not rows:
        return True
    live = [dict(zip(('kind', 'index', 'iova', 'length'), row))
            for row in struct.iter_unpack('<IIQQ', driver['rtl8111-r53-live'])]
    exported = {row['iova'] for row in live if row['kind'] == 4}
    if not exported:
        return True
    mapped = {row['mapAddress'] for row in rows}
    if not exported <= mapped:
        return False
    addresses = driver.get('rtl8111-r53-rx-addresses')
    if not isinstance(addresses, bytes) or len(addresses) != 512 * 8:
        return True
    slots = struct.unpack('<512Q', addresses)
    pages = PROFILES['RTL8111']['rx_pages']
    groups = {row['index'] for row in live if row['kind'] == 4}
    return all(slots[index * pages] in mapped for index in groups)


def snapshot(parent, label, config, mode):
    out = parent / label
    out.mkdir(parents=True, exist_ok=False)
    tree = registry()
    drivers = selected_drivers(tree, config)
    if mode == 'auto':
        deadline = time.monotonic() + 5
        while True:
            for value in drivers.values():
                profile = PROFILES[value['binding']['driver_class']]
                set_boolean(value['binding']['driver_registry_id'], profile['snapshot'])
            tree = registry()
            drivers = selected_drivers(tree, config)
            lucy = next(d['node'] for d in drivers.values() if d['binding']['driver_class'] == 'RTL8125')
            rtl8111 = next(d['node'] for d in drivers.values() if d['binding']['driver_class'] == 'RTL8111')
            if (rtl8111.get('rtl8111-r53-tx-mapped-active') == 0 and
                    all(lucy.get(p + 'posted') is not None and lucy[p + 'posted'] == lucy.get(p + 'completed')
                        for p in ('rtl812x-r45-tso4-', 'rtl812x-r46-tso6-'))):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('selected native TX mappings/TSO completions did not drain')
            time.sleep(.02)
        owners = [node for node, _ in nodes(tree) if node.get('r52-role') == 'controller']
        if len(owners) != 1:
            raise ValueError('expected one shared controller')
        owner_id = owners[0]['IORegistryEntryID']
        set_boolean(owner_id, 'R52Snapshot')
        tree = registry()
        owner = next(node for node, _ in nodes(tree) if node.get('IORegistryEntryID') == owner_id)
        controller = dict(C.scalars(owner, ('r52-', 'r53-')), registry_id=owner_id)
        domains = owner['r52-domains']
        # A batch remap between the driver snapshot above and this mapper
        # snapshot leaves a pair that describes two different rings. Re-take the
        # pair until it is self-consistent, bounded by the same deadline.
        for attempt in range(5):
            tree = registry()
            drivers = selected_drivers(tree, config)
            rtl8111 = next(d['node'] for d in drivers.values()
                           if d['binding']['driver_class'] == 'RTL8111')
            requester = next(d['binding']['requester'] for d in drivers.values()
                             if d['binding']['driver_class'] == 'RTL8111')
            probe = next((p for p in domains if p.get('r52-requester') == requester), None)
            if probe is None:
                break
            rows = live_addresses(probe)
            if rows is None or rx_groups_consistent(rtl8111, rows):
                break
            if attempt == 4 or time.monotonic() >= deadline:
                raise RuntimeError('RTL8111 driver and mapper snapshots describe different RX rings')
            for value in drivers.values():
                profile = PROFILES[value['binding']['driver_class']]
                set_boolean(value['binding']['driver_registry_id'], profile['snapshot'])
            time.sleep(.05)
    else:
        controller, domains = {}, []
    for role, selected in drivers.items():
        folder = out / role
        folder.mkdir()
        driver, binding = selected['node'], selected['binding']
        profile = PROFILES[binding['driver_class']]
        value = {'label': label, 'captured_ns': time.monotonic_ns(), 'binding': binding,
                 'driver': C.scalars(driver, ('rtl812x-', 'rtl8111-r53-')), 'probe': {}, 'exports': {}}
        if isinstance(driver.get('DriverVersion'), str):
            value['driver']['DriverVersion'] = driver['DriverVersion']
        exports = {}
        if mode == 'auto':
            matched = [p for p in domains if p.get('r52-requester') == binding['requester']]
            if len(matched) != 1 or binding['dma_policy'] != 'mapped':
                raise ValueError('selected endpoint has no unique mapped domain')
            probe = matched[0]
            prefix = profile['identity_prefix']
            if (driver.get(prefix + 'mapper-id') != probe['r52-mapper-id'] or
                    driver.get(prefix + 'domain-id') != probe['r44-domain-id']):
                raise ValueError('driver is bound to a different mapper')
            value['probe'] = C.scalars(probe, ('r44-', 'r47-', 'r48-', 'r50-', 'r51-', 'r52-', 'r53-'))
            exports.update({name: probe[key] for key, name in C.C.EXPORTS.items()})
            if binding['driver_class'] == 'RTL8111':
                exports.update({'driver-live.bin': driver['rtl8111-r53-live'],
                                'rx-addresses.bin': driver['rtl8111-r53-rx-addresses']})
        elif driver.get(profile['prefix'] + 'mapped-dma', 0):
            raise ValueError('off baseline unexpectedly uses mapped DMA')
        for name, raw in exports.items():
            if not isinstance(raw, bytes):
                raise ValueError('missing raw snapshot ' + name)
            (folder / name).write_bytes(raw)
            value['exports'][name] = {'bytes': len(raw), 'sha256': sha(raw)}
        write_json(folder / 'snapshot.json', value)
    selected_ids = {d['requester'] for d in roles(config).values()}
    unselected = [{'requester': pci_requester(node), 'policy': node.get('amdiommu-dma-policy', 'unpublished')}
                  for node, _ in nodes(tree)
                  if pci_requester(node) is not None and pci_requester(node) not in selected_ids and
                  pci_number(node, 'vendor-id') == 0x10ec and pci_number(node, 'device-id') in (0x8127, 0x8168)]
    write_json(out / 'phase.json', {'label': label, 'mode': mode, 'controller': controller,
                                   'unselected_candidates': unselected, 'captured_ns': time.monotonic_ns()})


def read_snapshot(path):
    metadata = json.loads((path / 'snapshot.json').read_text(encoding='utf-8'))
    if not metadata.get('probe'):
        return metadata  # off baseline has registry identity, without mapper/native raw files.
    value = C.read_snapshot(path)
    if value['binding']['driver_class'] == 'RTL8111':
        raw = (path / 'driver-live.bin').read_bytes()
        if len(raw) % 24:
            raise ValueError('RTL8111 live resource bytes differ from <IIQQ records')
        value['driver_live'] = [dict(zip(('kind', 'index', 'iova', 'length'), row))
                                for row in struct.iter_unpack('<IIQQ', raw)]
        raw = (path / 'rx-addresses.bin').read_bytes()
        if len(raw) != 512 * 8:
            raise ValueError('RTL8111 requires 512 captured RX descriptor addresses')
        value['rx_addresses'] = struct.unpack('<512Q', raw)
    return value
