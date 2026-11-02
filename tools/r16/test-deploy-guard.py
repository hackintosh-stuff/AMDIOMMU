#!/usr/bin/env python3
"""Pure tests of the actual deploy guard; never execute deployment/import side effects."""
import ast
import pathlib
import unittest

source = pathlib.Path(__file__).with_name('deploy.py')
node = next(n for n in ast.parse(source.read_text()).body
            if isinstance(n, ast.FunctionDef) and n.name == 'management_ready')
namespace = {}
exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), 'exec'), namespace)
ready = namespace['management_ready']
EN0 = 'inet 192.168.50.204 netmask 0xffffff00\nstatus: active\n'


class GuardTests(unittest.TestCase):
    def test_selected_en0(self):
        self.assertTrue(ready(EN0, 'gateway: 192.168.50.1\n  interface: en0\n'))

    def test_selected_en2_not_scoped_en0(self):
        self.assertFalse(ready(EN0, 'interface: en2\n'))
        self.assertFalse(ready(EN0, 'default 192.168.50.1 en0\ninterface: en2\n'))

    def test_absent_ambiguous_route(self):
        self.assertFalse(ready(EN0, ''))
        self.assertFalse(ready(EN0, 'interface: en0\ninterface: en2\n'))

    def test_address_and_link_required(self):
        self.assertFalse(ready(EN0.replace('.204 ', '.216 '), 'interface: en0\n'))
        self.assertFalse(ready(EN0.replace('active', 'inactive'), 'interface: en0\n'))


if __name__ == '__main__':
    unittest.main()
