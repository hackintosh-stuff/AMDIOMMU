#!/usr/bin/env python3
"""Focused local UDP protocol tests; no Mac/driver or external traffic required."""
import importlib.util
from pathlib import Path
import socket
import sys
import threading
import unittest
from unittest.mock import patch
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import protocol as P
import peer
import load


class Clean4(unittest.TestCase):
    def test_bytes(self):
        data = [P.payload(0x12345678, req) for req in P.REQUESTS]
        self.assertEqual({len(x) for x in data}, {32})
        self.assertEqual(len({x[12:] for x in data}), 4)
        self.assertIsNone(P.identify(P.SEED))
        for req, x in enumerate(data, 1):
            self.assertEqual(P.identify(x), (0x12345678, req))
        for token, req in ((0, 1), (0x80000000, 1), (1, 5)):
            with self.assertRaises(ValueError):
                P.payload(token, req)

    def test_load_clean4_exchange_with_full_echo(self):
        rows, result, client_rows = [], [], []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.1', 0))
            addr = server.getsockname()
            worker = threading.Thread(target=lambda: result.append(peer.serve(server, 123, 3, rows.append)))
            worker.start()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as seed:
                seed.settimeout(.2)
                seed.sendto(P.SEED, addr)
                self.assertEqual(seed.recvfrom(8192)[0], P.SEED)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                with patch.object(load, 'now', side_effect=time.monotonic_ns), patch.object(load.time, 'sleep') as spacing:
                    rc = load.exchange(client, '127.0.0.1', addr, 123, client_rows.append)
                    self.assertEqual([call.args for call in spacing.call_args_list], [(.15,)] * 3)
            worker.join(4)
            self.assertFalse(worker.is_alive())
        self.assertEqual((rc, result), (0, [0]))
        self.assertEqual(sum(r.startswith('client_sent ') for r in client_rows), 4)
        self.assertEqual(sum('payload_ok=1' in r for r in client_rows), 4)

    def test_peer_complete_bytes_and_order(self):
        rows, result = [], []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.1', 0))
            addr = server.getsockname()
            worker = threading.Thread(target=lambda: result.append(peer.serve(server, 123, 3, rows.append)))
            worker.start()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.bind(('127.0.0.1', 0))
                client.settimeout(.08)
                client.sendto(P.SEED, addr)
                self.assertEqual(client.recvfrom(8192)[0], P.SEED)
                wrong = P.payload(123, 1)[:-1] + b'X'
                client.sendto(wrong, addr)
                with self.assertRaises(socket.timeout):
                    client.recvfrom(8192)
                for req in P.REQUESTS:
                    data = P.payload(123, req)
                    client.sendto(data, addr)
                    self.assertEqual(client.recvfrom(8192)[0], data)
            worker.join(4)
            self.assertFalse(worker.is_alive())
        self.assertEqual(result, [1])  # bad full-padding packet cannot be hidden by later success.
        recv = [r for r in rows if r.startswith('peer_recv ')]
        self.assertEqual(len(recv), 5)
        self.assertIn('payload_ok=0', recv[0])
        self.assertIn('bad=1', rows[-1])


if __name__ == '__main__':
    unittest.main()
