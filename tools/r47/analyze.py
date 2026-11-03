#!/usr/bin/env python3
"""Accept IVRS/PCI discovery plus the established ordinary IPv6 TCP/TSO path.

The platform cannot sleep. PM implementation remains present but sleep/wake
validation is explicitly TODO and is not a gate for this round.
"""
import argparse
import json
import struct
from common import PHASES, VERSIONS, module, protocol as P, project_path, sha, write_json

BASE_COMMIT = '576c11adf03ce024bcf019d88cdc8b30781a19cc'
R46 = module('_r47_ordinary_analyzer', 'tools/r46/analyze.py')
need = R46.R45.need


def ivrs_units(raw):
    """Independently read the exported IVHD claims; never dereference MMIO."""
    need(len(raw) >= 48 and raw[:4] == b'IVRS', 'missing complete ACPI IVRS header')
    need(struct.unpack_from('<I', raw, 4)[0] == len(raw) and sum(raw) & 255 == 0,
         'IVRS declared length/checksum differs')
    units = []
    offset = 48
    while offset < len(raw):
        need(len(raw) - offset >= 6, 'truncated IVRS block')
        kind, flags, length, devid = struct.unpack_from('<BBHH', raw, offset)
        need(6 <= length <= len(raw) - offset, 'invalid IVRS block length')
        if kind in (0x10, 0x11, 0x40):
            header = 24 if kind == 0x10 else 40
            need(length >= header, 'truncated IVHD header')
            cap, base, segment, info = struct.unpack_from('<HQHH', raw, offset + 6)
            entry = {'kind': kind, 'offset': offset,
                     'devices': raw[offset + header:offset + length]}
            key = segment, devid
            matches = [value for value in units if value['key'] == key]
            if matches:
                unit = matches[0]
                need((unit['flags'], unit['cap'], unit['base'], unit['info']) ==
                     (flags, cap, base, info) and unit['blocks'][0]['devices'] == entry['devices'],
                     'duplicate IVHD descriptions disagree')
            else:
                unit = {'key': key, 'flags': flags, 'cap': cap, 'base': base,
                        'info': info, 'blocks': [], 'efr': None}
                units.append(unit)
            if kind != 0x10:
                efr = struct.unpack_from('<Q', raw, offset + 24)[0]
                need(unit['efr'] in (None, efr), 'duplicate IVHD EFR images disagree')
                unit['efr'] = efr
            unit['blocks'].append(entry)
        offset += length
    need(units, 'IVRS contains no IVHD unit')
    return units


def requester_claim(unit, requester):
    """Resolve this round's PCI requester from the captured device entries.

    Preserve the existing topology precedence: alias beats a direct entry,
    and any direct entry beats an all-devices fallback. R47's normal path
    requires a direct requester, so an applicable alias is reported to the
    caller and rejected there rather than treated as identity translation.
    """
    data, offset, pending, claims = unit['blocks'][0]['devices'], 0, None, []
    while offset < len(data):
        kind = data[offset]
        if kind == 0xf0:
            need(len(data) - offset >= 22, 'truncated HID entry')
            size = 22 + data[offset + 21]
        else:
            need(kind < 0x80, 'unsupported IVHD device-entry framing')
            size = 4 if kind < 0x40 else 8
        need(size <= len(data) - offset, 'truncated IVHD device entry')
        if kind != 0xf0:
            devid, setting = struct.unpack_from('<HB', data, offset + 1)
            if kind == 1:
                claims.append((0, requester, setting, False))
            elif kind in (2, 0x46) and devid == requester:
                claims.append((1, requester, setting, False))
            elif kind == 0x42 and devid == requester:
                claims.append((2, struct.unpack_from('<H', data, offset + 5)[0], setting, True))
            elif kind in (3, 0x43, 0x47):
                need(pending is None, 'nested IVHD range')
                alias = kind == 0x43
                used = struct.unpack_from('<H', data, offset + 5)[0] if alias else requester
                pending = devid, setting, alias, used
            elif kind == 4:
                need(pending is not None and devid >= pending[0], 'unpaired or reversed IVHD range')
                start, setting, alias, used = pending
                if start <= requester <= devid:
                    claims.append((2 if alias else 1, used, setting, alias))
                pending = None
            elif kind == 0x48:
                need(struct.unpack_from('<H', data, offset + 5)[0] != requester,
                     'requester identifies a special device, not the target PCI NIC')
        offset += size
    need(pending is None, 'unterminated IVHD range')
    if not claims:
        return None
    rank = max(claim[0] for claim in claims)
    best = set(claim[1:] for claim in claims if claim[0] == rank)
    need(len(best) == 1, 'ambiguous IVHD requester claims')
    return best.pop()


def discovery(cap):
    evidence = []
    for label in PHASES:
        path = cap / 'snapshots' / label
        value = json.loads((path / 'snapshot.json').read_text())
        raw = (path / 'ivrs.bin').read_bytes()
        need(value['exports']['ivrs.bin'] == {'bytes': len(raw), 'sha256': sha(raw)},
             label + ': IVRS raw export hash differs')
        p = value['probe']
        need(p['r47-discovery-state'] == 'ready' and
             p['r47-discovery-source'] == 'acpi-ivrs+pci', label + ': hardware was not discovered from IVRS/PCI')
        units = ivrs_units(raw)
        index = p['r47-ivrs-unit-index']
        need(p['r47-ivrs-bytes'] == len(raw) and p['r47-ivrs-unit-count'] == len(units) and
             0 <= index < len(units), label + ': discovered IVRS inventory differs')
        unit = units[index]
        segment, iommu = unit['key']
        requester = p['r47-requester-id']
        need(segment == p['r47-pci-segment'] == 0 and iommu == p['r47-iommu-id'] and
             requester == p['r44-target-devid'] and 0 <= requester <= 0xffff and
             len(unit['blocks']) == p['r47-ivrs-block-count'], label + ': selected PCI identities differ')
        claims = [(i, requester_claim(item, requester)) for i, item in enumerate(units)
                  if item['key'][0] == segment]
        claims = [(i, claim) for i, claim in claims if claim is not None]
        need(claims == [(index, (requester, p['r47-data-setting'], False))] and
             p['r47-resolved-id'] == requester and p['r47-requester-alias'] == 0,
             label + ': selected IVHD does not directly own the target requester')
        base, header = unit['base'], p['r47-cap-header']
        need(base > 0 and base & 0x3fff == 0 and
             base == p['r47-ivrs-mmio-base'] == p['r47-pci-mmio-base'] == p['r47-mmio-base'] and
             p['r47-mmio-bytes'] == 0x4000 and unit['cap'] == p['r47-cap-offset'] and
             0x40 <= unit['cap'] <= 0xf4 and unit['cap'] & 3 == 0 and
             header & 0xff == 0x0f and (header >> 16) & 7 == 3,
             label + ': IVRS/PCI capability/runtime MMIO identity differs')
        efr_present, efr_supported = unit['efr'] is not None and bool(raw[36] & 1), bool(header & (1 << 27))
        need(p['r47-ivrs-efr-present'] == int(efr_present) and
             p['r47-pci-efr-supported'] == int(efr_supported), label + ': EFR discovery metadata differs')
        if efr_present:
            need(p['r47-ivrs-efr'] == unit['efr'], label + ': firmware EFR image differs')
        if efr_supported:
            need(p['r47-mmio-efr'] != 0xffffffffffffffff, label + ': invalid runtime EFR readback')
            if efr_present:
                need(p['r47-mmio-efr'] == unit['efr'] and p['r47-efr-match'] == 'yes',
                     label + ': actual runtime EFR differs from the IVRS image')
            else:
                need(p['r47-efr-match'] == 'firmware-absent', label + ': missing firmware EFR was not identified')
        else:
            need(p['r47-efr-match'] == 'not-reported', label + ': unsupported EFR was not identified')
        evidence.append({'ivrsSHA256': sha(raw), 'ivrsBytes': len(raw), 'units': len(units),
                         'unitIndex': index, 'ivhdTypes': [block['kind'] for block in unit['blocks']],
                         'segment': segment, 'requester': requester, 'iommu': iommu,
                         'capOffset': unit['cap'], 'capHeader': header, 'mmioBase': base,
                         'mmioBytes': p['r47-mmio-bytes'], 'runtimeEFR': p['r47-mmio-efr'],
                         'firmwareEFR': unit['efr'], 'efrMatch': p['r47-efr-match']})
    need(all(row == evidence[0] for row in evidence), 'discovery identity changed across normal down/up')
    return dict(evidence[0], phases=list(PHASES), mmioSourcesAgree=True)


def analyze(cap, *, round_id=47, base_commit=BASE_COMMIT, versions=None,
            protocol=None, iova_base=0x1000000000, max_map_pages=32, max_runs=32,
            rx_groups=64, rx_group_pages=16):
    result = R46.R45.analyze(cap, round_id=round_id, base_commit=base_commit,
                             versions=VERSIONS if versions is None else versions,
                             protocol=P if protocol is None else protocol, tso_version=6,
                             tcp_record_check=R46.ipv6_transport, iova_base=iova_base,
                             max_map_pages=max_map_pages, max_runs=max_runs,
                             rx_groups=rx_groups, rx_group_pages=rx_group_pages)
    try:
        check = {'id': 'ivrs-pci-controller-discovery-and-requester-ownership',
                 'state': 'ok', 'detail': discovery(cap)}
    except (OSError, ValueError, KeyError, IndexError, TypeError, struct.error) as exc:
        check = {'id': 'ivrs-pci-controller-discovery-and-requester-ownership',
                 'state': 'FAIL', 'detail': str(exc)}
    result['scope'] = 'r%d-ivrs-pci-ordinary-ipv6-tcp-tso' % round_id
    result['checks'].append(check)
    result['ok'] = result['ok'] and check['state'] == 'ok'
    result['todo'] = [{'area': 'ordinary-system-sleep-wake', 'status': 'not-tested',
                       'implementation': 'retained', 'acceptance_gate': False,
                       'reason': 'This platform cannot sleep; no sleep or artificial controller power cycle was run.'}]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture')
    parser.add_argument('--json', dest='output')
    args = parser.parse_args()
    result = analyze(project_path(args.capture))
    if args.output:
        write_json(project_path(args.output), result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
