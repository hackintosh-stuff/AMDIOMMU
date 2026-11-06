#!/usr/bin/env python3
"""Accept real IPv6 TCP and TSO6 through the ordinary device IOMapper."""
import argparse
import ipaddress
import json
from common import VERSIONS, module, protocol as P, project_path, write_json

BASE_COMMIT = 'b7869df730b33107f16d277f4974b826df667c53'
R45 = module('_r46_ordinary_analyzer', 'tools/tcp4/analyze.py')


def ipv6_transport(client, peer):
    """Require recorded AF_INET6 endpoints and matching peer confirmations."""
    for side, row in (('client', client), ('peer', peer)):
        R45.need(row['family'] == 'IPv6', side + ': no actual IPv6 socket record')
        for which in ('local', 'peer'):
            endpoint = row[which]
            address = ipaddress.IPv6Address(endpoint['address'])
            R45.need(address.ipv4_mapped is None and not address.is_unspecified and
                     not address.is_multicast, side + ': ordinary IPv6 unicast is required')
            R45.need(isinstance(endpoint['port'], int) and 0 < endpoint['port'] <= 65535 and
                     isinstance(endpoint['scope_id'], int) and endpoint['scope_id'] >= 0,
                     side + ': IPv6 socket port/scope record is incomplete')
            R45.need(not address.is_link_local or endpoint['scope_id'] > 0,
                     side + ': link-local socket is missing its interface scope')
    # Link-local scope numbers belong to separate OS namespaces. Compare
    # wire-visible address/port across machines, and each saved receipt exactly.
    for mine, theirs in (('local', 'peer'), ('peer', 'local')):
        R45.need(all(client[mine][key] == peer[theirs][key] for key in ('address', 'port')),
                 'client/peer IPv6 socket endpoints do not describe the same connection')
    R45.need(client['peer_receipt_local'] == peer['local'] and
             client['peer_receipt_peer'] == peer['peer'],
             'saved peer receipt disagrees with the peer IPv6 socket record')
    return {'family': 'IPv6', 'client': {'local': client['local'], 'peer': client['peer']},
            'peer': {'local': peer['local'], 'peer': peer['peer']}}


def analyze(cap):
    return R45.analyze(cap, round_id=46, base_commit=BASE_COMMIT, versions=VERSIONS,
                       protocol=P, tso_version=6, tcp_record_check=ipv6_transport)


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
