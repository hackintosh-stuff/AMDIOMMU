#!/usr/bin/env python3
"""Focused synthetic Round15 raw-table/owned-pool/witness negatives only."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location('r15_analyze', Path(__file__).with_name('analyze.py'))
A = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A)
BASE, HIGH = 0x1000000, 0x4040D2000
PERMS = A.PR | A.IR | A.IW


def fixture():
    entries = [(0x200000 + i * 4096, 4096, i, 1, 0) for i in range(1024)]
    entries += [(HIGH + i * 4096, 4096, 1024 + i, 2, 0) for i in range(64)]
    token, flood = 0x12345678, 0x92345678
    witnesses = [(entries[0][0], HIGH, 1500, 3000, 0, 4096, 1024, 1, flood, 10001, 1070, 1070),
                 (entries[1][0], HIGH + 4096, 1600, 0, 1, 4096, 1025, 0, 0, 0, 0, 0)]
    before, after = bytearray(30328), bytearray(30328)
    def pool(blob, post):
        struct.pack_into('<4I5Q16I', blob, 0,
                         1, 30328, 2 if post else 1, 9, 123, 100,
                         500 if post else 0, 400 if post else 0, 10000,
                         7, 0, 1500, 4096, 1088, 64, 64, 64,
                         2 if post else 0, 1 if post else 0, 1200 if post else 0,
                         0, 0, 2, token, 4800 if post else 0)
        for i, e in enumerate(entries):
            struct.pack_into('<Q4I', blob, 120 + i * 24, *e)
        if post:
            for i, w in enumerate(witnesses):
                struct.pack_into('<4Q8I', blob, 26232 + i * 64, *w)
    pool(before, False)
    pool(after, True)
    tables = bytearray(4 * 4096)
    def pte(page, ix, raw):
        struct.pack_into('<Q', tables, page * 4096 + ix * 8, raw | PERMS)
    pte(0, 0, BASE + 4096 | 2 << 9)
    pte(1, 1, 0x200000)
    pte(1, 2, 0x400000)
    pte(0, HIGH >> 30, BASE + 8192 | 2 << 9)
    pte(2, (HIGH >> 21) & 511, BASE + 12288 | 1 << 9)
    for e in entries[1024:]:
        pte(3, (e[0] >> 12) & 511, e[0])
    rx = bytearray(160 + 1024 * 32 + 2 * 48)
    rh = [0x4F505852, 1, 32, 48, 2, 0, 0, 1024, 4096, 1, 9, 0,
          1024, 1024, 0, 1024, 0, 0, 0, 1, 0, 1, 7, 2, 0, 4096, 0, 0]
    struct.pack_into('<28I3Q2I', rx, 0, *rh, 2000, 0, 5000, 2, 2)
    for i, e in enumerate(entries[:1024]):
        addr = HIGH + i * 4096 if i < 2 else e[0]
        struct.pack_into('<QQ4I', rx, 160 + i * 32, addr, 4096 | 1 << 31, i, 4096, 5, 9)
    for i in range(2):
        struct.pack_into('<4Q4I', rx, 160 + 32768 + i * 48,
                         1800 + i * 100, HIGH + i * 4096, entries[i][0], 4096 | 1 << 31,
                         (i + 1) * 2, i, 4096, 0)
    obs = bytearray(104 + 2 * 72)
    oh = [0x324F4C52, 2, 72, 2048, 2, 0, 0, 1, 1, 2, 2, 0, 7, 0, 0, 0, 2, 0, 0, 0]
    struct.pack_into('<20I', obs, 0, *oh)
    struct.pack_into('<2Q', obs, 80, 100, 5000)
    struct.pack_into('<QQ14I', obs, 104, 500, 0x200000, 2, 1, 1, 0, 0, 0, 32, 0, 32, 0,
                     0, 0, 0, 0)
    struct.pack_into('<QQ14I', obs, 104 + 72, 3001, HIGH, 4, 3, 1, 0, 0, 0, 1070, 0, 1066, 0,
                     flood, 10001, 0, 1)
    props = {'m2-b2-r15-map-mode': A.MODE,
             'm2-b2-r15-obs-scope': 'declared-business-only; all-rxpost-and-pool-witnesses-retained',
             'm2-b2-r15-timebase-numer': 1,
             'm2-b2-r15-timebase-denom': 1, 'm2-b2-dma-t-win-start': 1000,
             'm2-b2-dma-t-win-end': 4000, 'm2-b2-r15-map-time': 200,
             'm2-b2-dma-t-dte-written': 300, 'm2-b2-r15-inv-time': 400,
             'm2-b2-rxset-watermark': 0, 'm2-b2-rxset-pre-ring-gen': 9,
             'm2-b2-r15-pt-used-pages': 4, 'm2-b2-r15-pt-base': BASE,
             'm2-b2-pt-root-pa': BASE, 'm2-b2-page-mode': 3,
             'm2-b2-rxset-dte-raw': BASE | 3 << 9 | 3 | A.IR | A.IW,
             'm2-b2-win-raw-count': 0, 'm2-b2-win-raw-truncated': 'no',
             'm2-b2-win-type2-count': 0,
             'm2-b2-rxset-dte-root-pa': BASE, 'm2-b2-rxset-root-level': 3,
             'm2-b2-obs-declared-token': token, 'm2-b2-obs-expected-batch': 4,
             'm2-b2-r15-flood-token': flood, 'm2-b2-r15-flood-req-first': 10001,
             'm2-b2-r15-flood-req-last': 11200}
    logs = {'peer.log': 'peer_start bind=192.168.50.122:9110 at=999999999\n'
                        'peer_sent token=0x92345678 req=10001 len=1024 to=192.168.50.216:12345 t=1\n',
            'flood-client.log': 'flood_bound 192.168.50.216:12345\n'
                'flood_recv token=0x92345678 req=10001 len=1024 payload_ok=1 '
                'from=192.168.50.122:9110 t_ns=3002\n',
            'client.log': ''}
    return [props, before, after, tables, rx, obs, logs]


class AnalyzerTest(unittest.TestCase):
    def fail_id(self, payloads, cid):
        result = A.analyze_payloads(*payloads)
        self.assertFalse(result['ok'])
        self.assertEqual(next(c for c in result['checks'] if c['id'] == cid)['state'], 'fail')

    def test_raw_high_pool_with_one_pending_witness_passes(self):
        result = A.analyze_payloads(*fixture())
        self.assertTrue(result['ok'], [c for c in result['checks'] if c['state'] != 'ok'])
        self.assertEqual(result['details']['witnesses']['pending'], 1)
        self.assertEqual(result['details']['above_16gib_controlled'], [0])

    def test_no_high_address_is_required_for_finite_run(self):
        f = fixture()
        low = 0xA00000
        def moved(addr):
            return low + addr - HIGH if HIGH <= addr < HIGH + 64 * 4096 else addr
        for blob in (f[1], f[2]):
            struct.pack_into('<I', blob, 84, 0)
            for i in range(1088):
                off = 120 + i * 24
                struct.pack_into('<Q', blob, off, moved(struct.unpack_from('<Q', blob, off)[0]))
            for i in range(2):
                off = 26232 + i * 64 + 8
                struct.pack_into('<Q', blob, off, moved(struct.unpack_from('<Q', blob, off)[0]))
        for i in range(1024):
            off = 160 + i * 32
            struct.pack_into('<Q', f[4], off, moved(struct.unpack_from('<Q', f[4], off)[0]))
        for i in range(2):
            struct.pack_into('<Q', f[4], 160 + 32768 + i * 48 + 8, low + i * 4096)
        struct.pack_into('<Q', f[5], 104 + 72 + 8, low)
        struct.pack_into('<Q', f[3], (HIGH >> 30) * 8, 0)
        struct.pack_into('<Q', f[3], 4096 + 5 * 8, low | PERMS)
        result = A.analyze_payloads(*f)
        self.assertTrue(result['ok'], [c for c in result['checks'] if c['state'] != 'ok'])
        self.assertEqual(result['details']['above_16gib_controlled'], [])

    def test_high_fault_is_classified_by_actual_mapping(self):
        f = fixture()
        f[0].update({'m2-b2-win-raw-count': 1, 'm2-b2-win-type2-count': 1,
                     'm2-b2-win-raw0': '%08x%08x%08x%08x' %
                     (0x100, 0x20100000, HIGH & 0xFFFFFFFF, HIGH >> 32)})
        result = A.analyze_payloads(*f)
        self.assertTrue(result['ok'])
        self.assertTrue(result['details']['faults'][0]['in_owned_pool'])
        bad = HIGH + 100 * 4096
        f[0]['m2-b2-win-raw0'] = ('%08x%08x%08x%08x' %
            (0x100, 0x20100000, bad & 0xFFFFFFFF, bad >> 32))
        self.fail_id(f, 'fault-actual-paths')

    def test_missing_second_page_of_full_capacity_rejected(self):
        t = A.Tables(fixture()[3], BASE, BASE, 3)
        with self.assertRaisesRegex(A.Refused, 'absent'):
            t.walk(HIGH + 63 * 4096 + 4000, 200)

    def test_missing_high_rx_leaf_fails_actual_walk(self):
        f = fixture()
        struct.pack_into('<Q', f[3], 3 * 4096 + ((HIGH >> 12) & 511) * 8, 0)
        self.fail_id(f, 'rxset-full-capacity-covered')

    def test_write_permission_missing_in_directory_rejected(self):
        f = fixture()
        off = (HIGH >> 30) * 8
        old = struct.unpack_from('<Q', f[3], off)[0]
        struct.pack_into('<Q', f[3], off, old & ~A.IW)
        self.fail_id(f, 'pool-before-full-capacity-covered')

    def test_unowned_high_neighbor_mapping_rejected(self):
        f = fixture()
        addr = HIGH - 4096
        struct.pack_into('<Q', f[3], 3 * 4096 + ((addr >> 12) & 511) * 8, addr | PERMS)
        self.fail_id(f, 'sparse-only-owned-high-pages')

    def test_retired_rx_address_not_in_owned_map_is_not_filtered(self):
        f = fixture()
        struct.pack_into('<Q', f[4], 160 + 32768 + 16, HIGH + 100 * 4096)
        self.fail_id(f, 'rxset-full-capacity-covered')

    def test_pool_manifest_change_rejected(self):
        f = fixture()
        struct.pack_into('<Q', f[2], 120, 0x800000)
        self.fail_id(f, 'pool-manifest-stable')

    def test_completion_before_post_rejected(self):
        f = fixture()
        struct.pack_into('<Q', f[2], 26232 + 24, 1400)
        self.fail_id(f, 'witness0-later-completion')

    def test_wrong_controlled_identity_does_not_count(self):
        f = fixture()
        struct.pack_into('<I', f[2], 26232 + 48, 0)
        self.fail_id(f, 'controlled-replacement-completed')

    def test_raw_posted_capacity_cannot_shrink_to_packet_length(self):
        f = fixture()
        struct.pack_into('<I', f[4], 160 + 20, 74)
        self.fail_id(f, 'rx-baseline-body')

    def test_missing_explicit_finite_obs_scope_rejected(self):
        f = fixture()
        del f[0]['m2-b2-r15-obs-scope']
        self.fail_id(f, 'finite-business-obs-scope')

    def test_scope_token_must_bind_prepared_and_after_pool(self):
        f = fixture()
        struct.pack_into('<I', f[2], 112, 0x87654321)
        self.fail_id(f, 'finite-business-obs-scope')

    def test_error_witness_cannot_count_as_completion(self):
        f = fixture()
        struct.pack_into('<I', f[2], 26232 + 44, 2)
        self.fail_id(f, 'controlled-replacement-completed')

    def test_raw_dte_root_must_match_arena_walk_root(self):
        f = fixture()
        f[0]['m2-b2-rxset-dte-raw'] += 4096
        self.fail_id(f, 'pt-root-dte-binding')

    def test_stale_rx_publication_rejected(self):
        f = fixture()
        struct.pack_into('<Q', f[4], 128, 3999)
        self.fail_id(f, 'rx-published-through-end')

    def test_invalidation_after_authorization_rejected(self):
        f = fixture()
        f[0]['m2-b2-r15-inv-time'] = 600
        struct.pack_into('<Q', f[2], 40, 600)
        self.fail_id(f, 'pool-visibility-timeline')

    def test_missing_suffix_completion_does_not_erase_latched_witness(self):
        f = fixture()
        # Keep a clean, current suffix row for an unrelated completion.
        struct.pack_into('<Q', f[5], 104 + 72 + 8, 0x500000)
        self.assertTrue(A.analyze_payloads(*f)['ok'])

    def test_timebase_conversion_is_not_implicitly_one(self):
        f = fixture()
        f[0]['m2-b2-r15-timebase-numer'] = 2
        for key in ('m2-b2-dma-t-win-start', 'm2-b2-dma-t-win-end',
                    'm2-b2-r15-map-time', 'm2-b2-dma-t-dte-written', 'm2-b2-r15-inv-time'):
            f[0][key] *= 2
        f[6]['flood-client.log'] = f[6]['flood-client.log'].replace('t_ns=3002', 't_ns=6002')
        self.assertTrue(A.analyze_payloads(*f)['ok'])


if __name__ == '__main__':
    unittest.main()
