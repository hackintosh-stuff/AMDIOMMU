#!/usr/bin/env python3
"""Focused additions: full payload/log proof, source budgets, truthful suffix coverage."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location('r15_proof_fixture', Path(__file__).with_name('test-analyze.py'))
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
A = F.A


def source2(f):
    for blob in (f[1], f[2]):
        struct.pack_into('<I', blob, 120 + 1024 * 24 + 20, 2)
        struct.pack_into('<I', blob, 80, 576)
    f[0]['m2-b2-r15-physical-allocation-attempts'] = 64


def truncated(f):
    # Actual fixed512 suffix with ten(s) of omitted pre-window tickets.
    first, count = 45, 512
    blob = bytearray(104 + count * 72)
    header = list(struct.unpack_from('<20I', f[5]))
    header[4], header[8], header[9], header[10], header[19] = 556, first, 556, count, 4
    struct.pack_into('<20I', blob, 0, *header)
    blob[80:104] = f[5][80:104]
    prefix, completion = f[5][104:176], f[5][176:248]
    for i in range(count):
        off = 104 + i * 72
        blob[off:off + 72] = completion if i == count - 1 else prefix
        struct.pack_into('<I', blob, off + 16, (first + i) * 2)
    f[5] = blob


class PayloadProofTest(unittest.TestCase):
    def fails(self, f, cid):
        result = A.analyze_payloads(*f)
        self.assertFalse(result['ok'])
        row = next(x for x in result['checks'] if x['id'] == cid)
        self.assertEqual(row['state'], 'fail', row)
        return result

    def test_full_payload_peer_and_mac_correlation_passes(self):
        result = A.analyze_payloads(*F.fixture())
        self.assertTrue(result['ok'], [c for c in result['checks'] if c['state'] == 'fail'])
        proof = result['details']['witnesses']['payload_log_proofs'][0]
        self.assertEqual(proof['payload_bytes'], 1024)
        self.assertEqual(proof['kernel_frame_bytes'], 1070)
        self.assertEqual(proof['peer_send_lines'], [2])

    def test_peer_clock_is_not_ordered_against_mac_clock(self):
        f = F.fixture()
        f[6]['peer.log'] = f[6]['peer.log'].replace(' t=1', ' t=99999999999999999')
        self.assertTrue(A.analyze_payloads(*f)['ok'])

    def test_missing_peer_send_or_wrong_length_rejected(self):
        for changed in ('peer_sent_missing', 'len=1023'):
            with self.subTest(changed=changed):
                f = F.fixture()
                f[6]['peer.log'] = f[6]['peer.log'].replace(
                    'peer_sent' if changed == 'peer_sent_missing' else 'len=1024', changed)
                self.fails(f, 'witness0-controlled-payload')

    def test_mac_full_payload_and_endpoint_checks(self):
        for old, new in (('len=1024 ', ''), ('payload_ok=1', 'payload_ok=0'),
                         ('from=192.168.50.122:9110', 'from=192.168.50.123:9110'),
                         ('t_ns=3002', 't_ns=2999')):
            with self.subTest(change=(old, new)):
                f = F.fixture()
                f[6]['flood-client.log'] = f[6]['flood-client.log'].replace(old, new)
                self.fails(f, 'witness0-controlled-payload')

    def test_wrong_peer_destination_or_ambiguous_send_rejected(self):
        for duplicate in (False, True):
            f = F.fixture()
            if duplicate:
                f[6]['peer.log'] += f[6]['peer.log'].splitlines()[1] + '\n'
            else:
                f[6]['peer.log'] = f[6]['peer.log'].replace('to=192.168.50.216:12345',
                                                          'to=192.168.50.216:12346')
            self.fails(f, 'witness0-controlled-payload')

    def test_obs_length_must_exclude_exactly_four_fcs_bytes(self):
        f = F.fixture()
        struct.pack_into('<I', f[5], 176 + 48, 1070)
        self.fails(f, 'witness0-later-completion')

    def test_raw_descriptor_length_must_match_latched_length(self):
        f = F.fixture()
        struct.pack_into('<I', f[2], 26232 + 60, 1071)
        self.fails(f, 'witness0-later-completion')

    def test_source2_and_split_576_budget_pass(self):
        f = F.fixture()
        source2(f)
        result = A.analyze_payloads(*f)
        self.assertTrue(result['ok'])
        policy = result['details']['allocation_policy']
        self.assertEqual(policy['native_attempts'], 512)
        self.assertEqual(policy['physical_attempts'], 64)
        self.assertEqual(policy['source_counts']['external_spare'], 1)

    def test_source_unknown_or_external_ring_rejected(self):
        for index, source in ((1024, 3), (0, 2)):
            f = F.fixture()
            for blob in (f[1], f[2]):
                struct.pack_into('<I', blob, 120 + index * 24 + 20, source)
            self.fails(f, 'pool-entry-sources')

    def test_source2_requires_positive_published_physical_counter(self):
        f = F.fixture()
        source2(f)
        del f[0]['m2-b2-r15-physical-allocation-attempts']
        self.fails(f, 'pool-physical-allocation-bound')

    def test_native_physical_and_total_bounds_are_separate(self):
        for total, physical, cid in ((513, 0, 'pool-native-allocation-bound'),
                                     (576, 65, 'pool-physical-allocation-bound'),
                                     (577, 64, 'pool-finite')):
            with self.subTest(total=total, physical=physical):
                f = F.fixture()
                for blob in (f[1], f[2]):
                    struct.pack_into('<I', blob, 80, total)
                f[0]['m2-b2-r15-physical-allocation-attempts'] = physical
                self.fails(f, cid)

    def test_missing_type2_count_only_explicit_empty_window_passes(self):
        f = F.fixture()
        del f[0]['m2-b2-win-type2-count']
        f[0].update({'m2-b2-win-new-entries': 0, 'm2-b2-win-entries': 0,
                     'm2-b2-win-raw-count': 0})
        self.assertTrue(A.analyze_payloads(*f)['ok'])

    def test_missing_type2_count_nonempty_or_partial_window_fails(self):
        for changed in ('new', 'entries', 'missing-new', 'nonfault-raw', 'fault-raw'):
            with self.subTest(changed=changed):
                f = F.fixture()
                del f[0]['m2-b2-win-type2-count']
                f[0].update({'m2-b2-win-new-entries': 0, 'm2-b2-win-entries': 0,
                             'm2-b2-win-raw-count': 0})
                if changed == 'new':
                    f[0]['m2-b2-win-new-entries'] = 1
                elif changed == 'entries':
                    f[0]['m2-b2-win-entries'] = 1
                elif changed == 'missing-new':
                    del f[0]['m2-b2-win-new-entries']
                else:
                    f[0]['m2-b2-win-raw-count'] = 1
                    event = 0x10100000 if changed == 'nonfault-raw' else 0x20100000
                    f[0]['m2-b2-win-raw0'] = '%08x%08x%08x%08x' % (
                        0x100, event, F.HIGH & 0xFFFFFFFF, F.HIGH >> 32)
                self.fails(f, 'fault-count-agrees')

    def test_defined_truncated_suffix_covering_window_passes(self):
        f = F.fixture()
        truncated(f)
        self.assertTrue(A.analyze_payloads(*f)['ok'])

    def test_truncated_suffix_that_starts_after_window_fails(self):
        f = F.fixture()
        truncated(f)
        for i in range(512):
            struct.pack_into('<Q', f[5], 104 + i * 72, 2000 if i < 511 else 3001)
        self.fails(f, 'obs-clean-and-current')

    def test_truncated_suffix_drop_wrap_loss_and_other_flags_fail(self):
        for offset, value in ((20, 1), (24, 1), (44, 1), (76, 5), (76, 6), (76, 12)):
            with self.subTest(offset=offset, value=value):
                f = F.fixture()
                truncated(f)
                struct.pack_into('<I', f[5], offset, value)
                self.fails(f, 'obs-clean-and-current')

    def test_truncated_suffix_missing_included_ticket_fails(self):
        f = F.fixture()
        truncated(f)
        struct.pack_into('<I', f[5], 104 + 100 * 72 + 16, (45 + 101) * 2)
        self.fails(f, 'obs-clean-and-current')


if __name__ == '__main__':
    unittest.main()
