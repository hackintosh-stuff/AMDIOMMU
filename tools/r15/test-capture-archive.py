#!/usr/bin/env python3
"""Small fixture-only tests for capture extraction and refreshed manifest."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

C = load('capture_archive', 'capture-archive.py')
T = load('r15_fixture', 'test-analyze.py')


def populate(cap):
    p, before, after, pt, rx, obs, _logs = T.fixture()
    raw = []
    keys = C.EXPORTS + (
        ('m2-b2-rxset-raw', 'm2-b2-rxset-raw-sha256', 'rxset-raw.bin'),
        ('m2-b2-obs-snapshot-used', 'm2-b2-obs-used-sha256', 'obs-snapshot-used.bin'))
    for (key, sha, name), blob in zip(keys, (before, after, pt, rx, obs)):
        p[sha] = hashlib.sha256(blob).hexdigest()
        raw.append('"%s" = <%s>' % (key, bytes(blob).hex()))
        if name in ('rxset-raw.bin', 'obs-snapshot-used.bin'):
            (cap / name).write_bytes(blob)
    props = '\n'.join('"%s" = "%s"' % (k, hex(v) if isinstance(v, int) else v)
                      for k, v in p.items())
    (cap / 'props.txt').write_text(props, encoding='utf-8')
    (cap / 'props.raw.txt').write_text('\n'.join(raw), encoding='utf-8')
    for name in ('load.txt', 'client.log', 'flood-client.log', 'peer.log',
                 'r15-version-confirmation.txt'):
        (cap / name).write_text('current round15\n', encoding='utf-8')
    (cap / 'token.txt').write_text('0x12345678\n', encoding='utf-8')
    (cap / 'batch.txt').write_text('4\n', encoding='utf-8')
    (cap / 'system.txt').write_text('AMDMapperProbe_version : 0.21.15\nRTL812xLucy_version : 1.0.15\n', encoding='utf-8')
    (cap / 'r15-load').mkdir()
    (cap / 'r15-load' / 'flood-client.log').write_text('current flood\n', encoding='utf-8')
    return p


class CaptureArchiveTest(unittest.TestCase):
    def test_extracts_three_exact_blobs_and_refreshes_peer_load_manifest(self):
        with tempfile.TemporaryDirectory(prefix='r15-capture-test-') as td:
            cap = Path(td)
            populate(cap)
            report = C.archive(cap, 'en2')
            self.assertEqual(len(report['exports']), 3)
            for name, info in report['exports'].items():
                self.assertEqual(hashlib.sha256((cap / name).read_bytes()).hexdigest(), info['sha256'])
            manifest = (cap / 'MANIFEST.txt').read_text()
            self.assertIn('  peer.log', manifest)
            self.assertIn('  r15-load/flood-client.log', manifest)
            self.assertIn('finite declared business', manifest)

    def test_hash_mismatch_rejected_before_extracting_table(self):
        with tempfile.TemporaryDirectory(prefix='r15-capture-test-') as td:
            cap = Path(td)
            p = populate(cap)
            text = (cap / 'props.txt').read_text().replace(p['m2-b2-r15-pt-sha256'], '0' * 64)
            (cap / 'props.txt').write_text(text)
            with self.assertRaisesRegex(C.R15.Refused, 'sha256 mismatch'):
                C.archive(cap, 'en2')
            self.assertFalse((cap / 'r15-pt-raw.bin').exists())

    def test_wrong_load_token_rejected(self):
        with tempfile.TemporaryDirectory(prefix='r15-capture-test-') as td:
            cap = Path(td)
            populate(cap)
            (cap / 'token.txt').write_text('0x12345679\n')
            with self.assertRaisesRegex(C.R15.Refused, 'token/batch'):
                C.archive(cap, 'en2')

    def test_optional_expected_version_rejected_on_mismatch(self):
        with tempfile.TemporaryDirectory(prefix='r15-capture-test-') as td:
            cap = Path(td)
            populate(cap)
            with mock.patch.dict(C.os.environ, {'EXPECTED_PROBE_VERSION': 'wrong'}):
                with self.assertRaisesRegex(C.R15.Refused, 'installed version'):
                    C.archive(cap, 'en2')


if __name__ == '__main__':
    unittest.main()
