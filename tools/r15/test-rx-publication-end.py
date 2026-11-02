#!/usr/bin/env python3
"""Focused RX publication-end regression; no capture/gate/history replay.

Execute the production check and finite-claim expressions extracted from main,
with a real wire-decoded RX header. Only the RX timestamp changes between cases.
"""
import ast
import contextlib
import importlib.util
import io
from pathlib import Path
import struct
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
ANALYZER = ROOT / 'tools' / 'analyze-round12.py'
CID = 'rxset-published-through-end'
SPEC = importlib.util.spec_from_file_location('analyzer12', ANALYZER)
A = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A)
TREE = ast.parse(ANALYZER.read_text(encoding='utf-8'))
MAIN = next(n for n in TREE.body if isinstance(n, ast.FunctionDef)
            and n.name == 'main')


def has_id(node):
    return any(isinstance(n, ast.Constant) and n.value == CID
               for n in ast.walk(node))


def assignment(name):
    return next(n.value for n in ast.walk(MAIN) if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name
                        for t in n.targets))


def evaluate(node, env):
    return eval(compile(ast.Expression(node), str(ANALYZER), 'eval'), env)


def wire_header(published):
    # Literal v1 geometry, independent of the analyzer's decoder constants.
    blob = bytearray(160 + 1024 * 32)
    struct.pack_into('<4I', blob, 0, 0x4F505852, 1, 32, 48)
    struct.pack_into('<I', blob, 28, 1024)
    struct.pack_into('<Q', blob, 112, 999999)  # decoy baseline timestamp
    struct.pack_into('<Q', blob, 128, published)
    rx = A.decode_rxpost(blob)
    assert rx['ok'], rx
    assert rx['hdr']['tPublished'] == published
    return rx['hdr']


class PublicationEndTest(unittest.TestCase):
    def setUp(self):
        A.RESULTS.clear()
        A.IDS.clear()
        A.STATE.clear()

    def check(self, published, end=2000, have_window=True, translation=True):
        calls = [n for n in ast.walk(MAIN) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name) and n.func.id == 'rec'
                 and len(n.args) > 1 and isinstance(n.args[1], ast.Constant)
                 and n.args[1].value == CID]
        self.assertEqual(len(calls), 1, 'production RX check must exist once')
        env = dict(rec=A.rec, h=wire_header(published), we=end,
                   have_window=have_window, is_translation=translation)
        with contextlib.redirect_stdout(io.StringIO()):
            evaluate(calls[0], env)
        return A.STATE[CID]

    def test_stale_rx_rejected_even_with_late_baseline_timestamp(self):
        self.assertEqual(self.check(1999), 'fail')
        self.assertIn('published=1999 end=2000', A.RESULTS[-1][-1])

    def test_exact_actual_end_accepted(self):
        self.assertEqual(self.check(2000), 'ok')

    def test_later_than_actual_end_accepted(self):
        self.assertEqual(self.check(2001), 'ok')

    def test_missing_or_invalid_actual_window_fails_closed(self):
        self.assertEqual(self.check(2001, end=None, have_window=False), 'fail')
        self.setUp()
        self.assertEqual(self.check(2001, have_window=False), 'fail')

    def test_control_is_not_a_translation_pass(self):
        self.assertEqual(self.check(1999, translation=False), 'na')

    def test_finite_rx_term_and_missing_diagnostics_require_check(self):
        term = assignment('rxset_ok')
        self.assertTrue(has_id(term))
        ids = {n.value for n in ast.walk(term) if isinstance(n, ast.Constant)
               and isinstance(n.value, str) and n.value.startswith('rxset-')}
        states = dict.fromkeys(ids, 'ok')
        self.assertTrue(evaluate(term, dict(is_translation=True, STATE=states)))
        for missing in ('fail', 'na', None):
            states[CID] = missing
            self.assertFalse(evaluate(term, dict(is_translation=True, STATE=states)))
        # Both textual and JSON missing-term diagnostics must name the new check.
        diagnostics = [n for n in ast.walk(MAIN) if isinstance(n, ast.ListComp)
                       and has_id(n)]
        self.assertEqual(len(diagnostics), 2)
        for diagnostic in diagnostics:
            self.assertIn(CID, evaluate(diagnostic, dict(STATE=states)))

    def test_vintage_and_bad_blob_keep_explicit_na_row(self):
        loops = [n for n in ast.walk(MAIN) if isinstance(n, ast.For)
                 and isinstance(n.target, ast.Name) and n.target.id == '_cid'
                 and has_id(n.iter)]
        self.assertEqual(len(loops), 2)


if __name__ == '__main__':
    unittest.main()
