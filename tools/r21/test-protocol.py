#!/usr/bin/env python3
"""Round25 deterministic load tests: full groups, no retries, no duplicate credit."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import protocol
import peer

spec = importlib.util.spec_from_file_location('round25_load', Path(__file__).with_name('load.py'))
load = importlib.util.module_from_spec(spec)
spec.loader.exec_module(load)


class Socket:
    def __init__(self, duplicate=False):
        self.queue = []
        self.events = []
        self.duplicate = duplicate
        self.sent = []

    def bind(self, addr):
        pass

    def settimeout(self, timeout):
        pass

    def getsockname(self):
        return ('127.0.0.1', 10000)

    def sendto(self, data, peer):
        ident = protocol.identify(data)
        if ident:
            self.sent.append(ident[1])
            self.events.append(('send', ident[1]))
        self.queue.append((data, peer))
        return len(data)

    def recvfrom(self, size):
        data, peer = self.queue.pop(0)
        ident = protocol.identify(data)
        if ident:
            self.events.append(('recv', ident[1]))
            if self.duplicate and ident[1] % 16 == 2:
                data = protocol.payload(7, ident[1] - 1)
        return data, peer


class ProtocolTests(unittest.TestCase):
    def test_scope_and_pattern(self):
        self.assertEqual(protocol.REQUESTS, tuple(range(1, 513)))
        self.assertEqual(len(protocol.bursts()), 32)
        original = [32, 1472, 120, 1472, 32, 1472, 120, 1472,
                    32, 120, 1472, 32, 120, 32, 120, 32]
        for group in protocol.bursts():
            self.assertEqual([protocol.length_of(r) for r in group], original)
            for req in group:
                data = protocol.payload(7, req)
                self.assertEqual(protocol.identify(data), (7, req))
                self.assertEqual(len(data), protocol.length_of(req))
        for req in (0, 513):
            with self.assertRaises(ValueError):
                protocol.payload(7, req)

    def exchange(self, duplicate=False):
        s = Socket(duplicate)
        logs = []
        with patch.object(load, 'now', return_value=100):
            rc = load.exchange(s, '127.0.0.1', ('127.0.0.2', 9110),
                               7, logs.append, load.OrdSeq())
        self.assertEqual(s.sent, list(protocol.REQUESTS))  # no retries
        for i in range(32):
            events = s.events[i * 32:(i + 1) * 32]
            self.assertEqual([e[0] for e in events], ['send'] * 16 + ['recv'] * 16)
        return rc, logs

    def test_all_512_send_all_then_receive(self):
        rc, logs = self.exchange()
        self.assertEqual(rc, 0)
        self.assertIn('client_summary sent=512 acked=512 bad=0', logs)

    def test_peer_full_512_and_reject_duplicate(self):
        class PeerSocket:
            def __init__(self, duplicate, reorder):
                self.incoming = [protocol.SEED]
                self.order = [req for group in protocol.bursts()
                              for req in (reversed(group) if reorder else group)]
                for req in self.order:
                    self.incoming.append(protocol.payload(7, req))
                    if duplicate and req == 32:
                        self.incoming.append(protocol.payload(7, req))
                self.echoes = []

            def getsockname(self):
                return ('127.0.0.2', 9110)

            def recvfrom(self, size):
                return self.incoming.pop(0), ('127.0.0.1', 10000)

            def sendto(self, data, addr):
                self.echoes.append(data)
                return len(data)

        for duplicate, reorder in ((False, False), (True, False), (False, True)):
            s = PeerSocket(duplicate, reorder)
            logs = []
            with patch.object(peer.select, 'select', return_value=([s], [], [])), \
                 patch.object(peer.time, 'monotonic', side_effect=lambda: 0 if s.incoming else 2):
                rc = peer.serve(s, 7, 1, logs.append)
            self.assertEqual(rc, int(duplicate))
            self.assertEqual(s.echoes, [protocol.SEED] +
                             [protocol.payload(7, req) for req in s.order])
            self.assertIn('peer_stop received=512 bad=%d seed=1' % int(duplicate), logs)

    def test_duplicates_never_count_as_success(self):
        rc, logs = self.exchange(duplicate=True)
        self.assertEqual(rc, 1)
        self.assertIn('client_summary sent=512 acked=480 bad=32', logs)


if __name__ == '__main__':
    unittest.main()
