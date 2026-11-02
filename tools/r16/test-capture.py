#!/usr/bin/env python3
"""Archive-only fixed ABI/hash tests. No system commands/network operations."""
import hashlib
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


C, T = module('capture_r16', 'capture-archive.py'), module('test_r16', 'test-analyze.py')


class MemoryPath:
    """Archive API fixture with no filesystem writes or temporary directories."""
    def __init__(self, name='', tree=None):
        self.key, self.tree = name, {} if tree is None else tree
    def __truediv__(self, name):
        return MemoryPath(self.key + '/' + name, self.tree)
    def __lt__(self, other):
        return self.key < other.key
    def __eq__(self, other):
        return isinstance(other, MemoryPath) and self.key == other.key
    @property
    def name(self):
        return self.key.rsplit('/', 1)[-1]
    def exists(self):
        return self.key in self.tree
    is_file = exists
    def stat(self):
        return SimpleNamespace(st_size=len(self.read_bytes()))
    def read_bytes(self):
        return self.tree[self.key]
    def write_bytes(self, data):
        self.tree[self.key] = bytes(data)
    def read_text(self, encoding='utf-8', errors='strict'):
        return self.read_bytes().decode(encoding, errors)
    def write_text(self, text, encoding='utf-8'):
        self.write_bytes(text.encode(encoding))
    def rglob(self, pattern):
        return [MemoryPath(k, self.tree) for k in list(self.tree) if k.startswith(self.key + '/')]
    def relative_to(self, base):
        return MemoryPath(self.key[len(base.key)+1:], self.tree)
    def as_posix(self):
        return self.key


class Archive(unittest.TestCase):
    def make_capture(self, path):
        p, domain, pt, driver, obs, logs = T.fixture()
        p.update({'m2-b2-r15-map-mode': C.X.R.MODE, 'm2-b2-obs-expected-batch': 4})
        raw = []
        for (key, filename), blob in zip(C.NEW_EXPORTS, (domain, pt, driver)):
            raw.append('"%s" = <%s>' % (key, blob.hex()))
        for i, (key, sha_key, filename) in enumerate(C.OLD_EXPORTS):
            blob = obs if i == 0 else ('synthetic-export-%d' % i).encode()
            raw.append('"%s" = <%s>' % (key, blob.hex()))
            p[sha_key] = hashlib.sha256(blob).hexdigest()
        (path / 'props.raw.txt').write_text('\n'.join(raw), encoding='utf-8')
        (path / 'props.txt').write_text('\n'.join('"%s" = "%s"' %
            (k, hex(v) if isinstance(v, int) else v) for k, v in p.items()), encoding='utf-8')
        for name, content in dict(logs, **{'token.txt': '123', 'batch.txt': '4', 'system.txt': 'synthetic',
                                         'load.txt': 'synthetic', 'r16-version-confirmation.txt': 'synthetic'}).items():
            (path / name).write_text(content, encoding='utf-8')

    def test_fixed_geometry_and_manifests(self):
        path = MemoryPath('capture')
        self.make_capture(path)
        report = C.archive(path, 'en2')
        self.assertEqual(report['exports']['r16-driver-raw.bin']['bytes'], 2216)
        self.assertFalse(report['exports']['r16-driver-raw.bin']['published_sha256_verified'])
        self.assertTrue(report['exports']['obs-snapshot-used.bin']['published_sha256_verified'])
        self.assertIn('r16-domain-raw.bin', (path / 'MANIFEST.txt').read_text())
        (path / 'r16-domain-raw.bin').write_bytes(b'wrong')
        with self.assertRaises(C.X.Refused):
            C.archive(path, 'en2')


if __name__ == '__main__':
    unittest.main()
