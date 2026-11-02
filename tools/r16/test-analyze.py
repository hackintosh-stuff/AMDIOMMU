#!/usr/bin/env python3
"""Focused synthetic independent-byte mutations, NOT hardware pass claims."""
import copy
from pathlib import Path
import struct
import sys
import unittest
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyze as X
from protocol import payload, evidence


def fixture(offsets=(128, 128, 128, 128)):
    token, ptbase = 123, 0x100000
    p = {'m2-b2-obs-declared-token': token, 'm2-b2-dma-t-win-start': 100000000,
         'm2-b2-dma-t-win-end': 1000000000, 'm2-b2-r15-timebase-numer': 1,
         'm2-b2-r15-timebase-denom': 1, 'm2-b2-pt-root-pa': ptbase,
         'm2-b2-page-mode': 3, 'm2-b2-rxset-dte-raw': ptbase | X.IR | X.IW | (3 << 9) | 3,
         'm2-b2-rxset-dte-root-pa': ptbase, 'm2-b2-rxset-root-level': 3,
         'm2-b2-win-new-entries': 0,
         'm2-b2-win-entries': 0, 'm2-b2-win-raw-count': 0}
    domain = bytearray(X.DOMAIN_BYTES)
    driver = bytearray(X.DRIVER_BYTES)
    pt = bytearray(3 * 4096)
    struct.pack_into('<4I6Q4I', domain, 0, 1, X.DOMAIN_BYTES, 4, 0,
                     X.BASE, 65536, ptbase, ptbase + 8192, ptbase, len(pt), 3, 0x2500, 1, 0)
    struct.pack_into('<8IQ', driver, 0, 0x36315854, 1, X.DRIVER_BYTES, 4, 0x2500, token, 0, 0, 1100000000)
    for table, level, child in ((0, 3, ptbase + 4096), (4096, 2, ptbase + 8192)):
        index = X.BASE >> (9 * level + 3) & 511
        struct.pack_into('<Q', pt, table + index * 8, child | X.IR | X.IW | ((level - 1) << 9) | 1)
    obsrows = []
    def obs(kind, t, req=0, cumulative=0, addr=0, length=0, opts=0, flags=0):
        ticket = len(obsrows) + 1
        obsrows.append(struct.pack('<2Q14I', t, addr, ticket * 2, kind, cumulative,
                                   cumulative % 1024, cumulative // 1024, cumulative,
                                   opts, 0, length, flags, token if req else 0, req, 0, int(bool(req))))
    obs(3, 90)  # Real nonmagic prefix, not a fifth business transaction.
    client, peer = ['client_bound 127.0.0.1:10000'], [
        'peer_start bind=127.0.0.1:9110 token=0x0000007b',
        'peer_seed_recv len=1024 nonmagic=1 from=127.0.0.1:10001 t=1']
    for i in range(4):
        req, t, pa = i + 1, 150000000 + i * 200000000, 0x200000 + offsets[i] + i * 4096
        iova, opts = X.BASE + offsets[i], (1 << 31) | (1 << 29) | (1 << 28) | 74
        at = 80 + i * X.DOMAIN_RECORD_BYTES
        struct.pack_into('<5Q6I', domain, at, req, t, t+1, t+5, t+6, 1, 1, token, req, 3, 0)
        struct.pack_into('<3Q', domain, at+64, pa, 74, iova)
        struct.pack_into('<Q', domain, at+256, pa & -4096)
        struct.pack_into('<Q', domain, at+384, (pa & -4096) | X.FC | X.IR | 1)
        for j, delta in enumerate((1, 6)):
            seq = 2 * i + j + 1
            struct.pack_into('<4I3Q', domain, at + 640 + 40*j,
                             0, 1 | (3 << 28), 0xFFFFF003, 0x7FFFFFFF, seq, seq, t+delta)
        at = 40 + i * X.DRIVER_RECORD_BYTES
        struct.pack_into('<6I4Q', driver, at, 1, 312, 0x2500, token, req, 1, req, t+1, t+4, t+6)
        struct.pack_into('<2Q', driver, at+56, pa, 74)
        struct.pack_into('<2Q', driver, at+184, iova, 74)
        struct.pack_into('<2Q6I', driver, at+312, t+2, 1050000000, i, i, i, 1, i+1, 0xFFFF)
        struct.pack_into('<2Q2I', driver, at+352, iova, 74, opts, 0)
        obs(1, t+2, req, i, iova, 74, opts & ~(1 << 31), 4|8)
        obs(4, t+3, req)
        obs(2, t+4, cumulative=i)
        obs(3, t+7, req, addr=0x300000+i*4096, length=74)
        wire = evidence(payload(token, req))
        client.append('client_sent token=123 req=%d %s t_ns=%d' % (req, wire, t-1))
        client.append('client_recv token=123 req=%d %s payload_ok=1 from=127.0.0.1:9110 t_ns=%d' % (req, wire, t+8))
        peer.append('peer_recv token=123 req=%d %s payload_ok=1 from=127.0.0.1:10000 t=%d' % (req, wire, t+3))
        peer.append('peer_sent token=123 req=%d %s to=127.0.0.1:10000 t=%d' % (req, wire, t+4))
    peer.append('peer_stop received=4 bad=0 seed=1')
    hdr = struct.pack('<20I3Q', X.A.OBS_MAGIC, 2, 72, 4096, len(obsrows), 0, 0, 1,
                      1, len(obsrows), len(obsrows), 0, 1, 0x2500, 0x10ec, 0x8127, 2, 0, 0, 0, 1, 1100000000, 0)
    return [p, domain, pt, driver, hdr + b''.join(obsrows),
            {'client.log': '\n'.join(client), 'peer.log': '\n'.join(peer)}]


class Analyze(unittest.TestCase):
    def test_complete_and_walk(self):
        r = X.analyze_payloads(*fixture())
        self.assertTrue(r['ok'], r['checks'])
        self.assertEqual(len(r['details']['reuse']), 6)
        self.assertEqual(r['details']['requests'][0]['walk'][0]['pa'], 0x200080)

    def test_nonadjacent_exact_iova_reuse_counts(self):
        r = X.analyze_payloads(*fixture((128, 256, 128, 512)))
        self.assertTrue(r['ok'], r['checks'])
        self.assertEqual([(p['oldHandle'], p['newHandle']) for p in r['details']['reuse']], [(1, 3)])

    def test_same_iova_page_is_not_exact_iova_reuse(self):
        r = X.analyze_payloads(*fixture((2998, 2486, 950, 438)))
        self.assertFalse(r['ok'])
        self.assertEqual([c['id'] for c in r['checks'] if c['state'] == 'fail'],
                         ['real-same-iova-different-pa-content-reuse'])

    def test_serial_next_request_waits_150ms_after_echo(self):
        a = fixture()
        a[-1]['client.log'] = a[-1]['client.log'].replace('t_ns=349999999', 't_ns=299999999')
        result = X.analyze_payloads(*a)
        self.assertFalse(result['ok'])
        self.assertEqual([c['id'] for c in result['checks'] if c['state'] == 'fail'],
                         ['clean4-full-application-bytes'])

    def staging_metadata(self):
        return {'driverMode': 'page-aligned-real-tx-staging-v1',
                'installedDriverVersion': '1.1.201', 'loadedDriverVersion': '1.1.201',
                'installedDriverUUID': 'DRIVER', 'loadedDriverUUID': 'DRIVER',
                'installedProbeVersion': '0.26.0', 'loadedProbeVersion': '0.26.0',
                'installedProbeUUID': 'PROBE', 'loadedProbeUUID': 'PROBE'}

    def test_real_staging_mode_strict_success(self):
        result = X.analyze_payloads(*fixture((0, 0, 0, 0)), metadata=self.staging_metadata())
        self.assertTrue(result['ok'], result['checks'])

    def test_real_staging_mode_rejects_unaligned(self):
        result = X.analyze_payloads(*fixture(), metadata=self.staging_metadata())
        self.assertFalse(result['ok'])
        self.assertIn('real-tx-staging-aligned-distinct-backing',
                      [c['id'] for c in result['checks'] if c['state'] == 'fail'])

    def test_real_staging_mode_rejects_loaded_uuid_mismatch(self):
        meta = self.staging_metadata()
        meta['loadedDriverUUID'] = 'WRONG'
        result = X.analyze_payloads(*fixture((0, 0, 0, 0)), metadata=meta)
        self.assertFalse(result['ok'])

    def test_real_staging_binary_requires_explicit_mode(self):
        meta = self.staging_metadata()
        del meta['driverMode']
        result = X.analyze_payloads(*fixture((0, 0, 0, 0)), metadata=meta)
        self.assertFalse(result['ok'])

    def test_loaded_staging_binary_cannot_fall_back_to_legacy(self):
        meta = self.staging_metadata()
        meta['driverMode'] = None
        meta['installedDriverVersion'] = '1.1.200'
        result = X.analyze_payloads(*fixture((0, 0, 0, 0)), metadata=meta)
        self.assertFalse(result['ok'])
        self.assertIn('real-tx-staging-mode-and-binary-binding',
                      [c['id'] for c in result['checks'] if c['state'] == 'fail'])

    def fail_mutation(self, index, off, fmt, value):
        args = fixture()
        struct.pack_into(fmt, args[index], off, value)
        r = X.analyze_payloads(*args)
        self.assertFalse(r['ok'], r)

    def test_actual_map_pte_wrong_pa(self):
        self.fail_mutation(1, 80+384, '<Q', 0xBAD000 | X.FC | X.IR | 1)

    def test_actual_map_pte_unexpected_write(self):
        self.fail_mutation(1, 80+384, '<Q', 0x200000 | X.FC | X.IR | X.IW | 1)

    def test_actual_map_pte_missing_fault_control(self):
        self.fail_mutation(1, 80+384, '<Q', 0x200000 | X.IR | 1)

    def test_parent_pointer_outside_arena(self):
        args = fixture()
        index = X.BASE >> 30 & 511
        struct.pack_into('<Q', args[2], index*8, 0x999000 | X.IR | X.IW | 2 << 9 | 1)
        self.assertFalse(X.analyze_payloads(*args)['ok'])

    def test_retire_leaf_not_clear(self):
        self.fail_mutation(1, 80+512, '<Q', 1)

    def test_completion_store_wrong(self):
        self.fail_mutation(1, 80+640+24, '<Q', 99)

    def test_actual_descriptor_identity_fallback(self):
        self.fail_mutation(3, 40+352, '<Q', 0x200080)

    def test_free_before_invalidation(self):
        self.fail_mutation(3, 40+320, '<Q', 151)

    def test_close_pointer_did_not_advance(self):
        self.fail_mutation(3, 40+344, '<I', 0)

    def test_payload_claim_cannot_replace_bytes(self):
        args = fixture()
        args[5]['peer.log'] = args[5]['peer.log'].replace(payload(123, 2).hex(), payload(123, 1).hex())
        self.assertFalse(X.analyze_payloads(*args)['ok'])

    def test_extra_magic_request_refused(self):
        args = fixture()
        args[5]['peer.log'] += '\npeer_recv token=123 req=5 len=32 payload_ok=1'
        self.assertFalse(X.analyze_payloads(*args)['ok'])

    def test_fixed_abi_unknown_refused(self):
        args = fixture()
        struct.pack_into('<I', args[1], 0, 2)
        with self.assertRaises(X.Refused):
            X.analyze_payloads(*args)


if __name__ == '__main__':
    unittest.main()
