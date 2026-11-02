#!/usr/bin/env python3
"""Round27 ordinary UDP: nonbusiness bytes, group reorder, no duplicate credit."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import protocol
import peer

spec = importlib.util.spec_from_file_location('round27_load', Path(__file__).with_name('load.py'))
load = importlib.util.module_from_spec(spec)
spec.loader.exec_module(load)


class Socket:
    def __init__(self, duplicate=False, reorder=False):
        self.queue = []
        self.events = []
        self.duplicate = duplicate
        self.reorder = reorder
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
        if (self.reorder and len(self.queue) == protocol.BURST and
                all(protocol.identify(data) for data, _ in self.queue)):
            self.queue.reverse()
        data, peer = self.queue.pop(0)
        ident = protocol.identify(data)
        if ident:
            self.events.append(('recv', ident[1]))
            if self.duplicate and ident[1] % 16 == 2:
                data = protocol.payload(7, ident[1] - 1)
        return data, peer


class ProtocolTests(unittest.TestCase):
    def test_scope_and_pattern(self):
        self.assertEqual(protocol.REQUESTS, tuple(range(1, 8193)))
        self.assertEqual(len(protocol.bursts()), 512)
        original = [32, 1472, 120, 1472, 32, 1472, 120, 1472,
                    32, 120, 1472, 32, 120, 32, 120, 32]
        for group in protocol.bursts():
            self.assertEqual([protocol.length_of(r) for r in group], original)
            for req in group:
                data = protocol.payload(7, req)
                self.assertEqual(data[:4], b'R27P')
                # The real obsParseBiz reads big-endian 0x31424F49 only at
                # payload offset zero; neither spelling selects r27 traffic.
                self.assertNotEqual(int.from_bytes(data[:4], 'big'), 0x31424F49)
                self.assertNotIn(b'IOB1', data)
                self.assertNotIn(bytes.fromhex('31424f49'), data)
                self.assertEqual(protocol.identify(data), (7, req))
                self.assertEqual(len(data), protocol.length_of(req))
        for data in [protocol.SEED] + [protocol.ordinary(seq) for seq in range(1, 88)]:
            self.assertNotEqual(int.from_bytes(data[:4], 'big'), 0x31424F49)
            self.assertNotIn(b'IOB1', data)
            self.assertNotIn(bytes.fromhex('31424f49'), data)
            self.assertIsNone(protocol.identify(data))
        for req in (0, 8193):
            with self.assertRaises(ValueError):
                protocol.payload(7, req)

    def exchange(self, duplicate=False, reorder=False):
        s = Socket(duplicate, reorder)
        logs = []
        with patch.object(load, 'now', return_value=100):
            rc = load.exchange(s, '127.0.0.1', ('127.0.0.2', 9110),
                               7, logs.append, load.OrdSeq())
        self.assertEqual(s.sent, list(protocol.REQUESTS))  # no retries
        for i in range(512):
            events = s.events[i * 32:(i + 1) * 32]
            self.assertEqual([e[0] for e in events], ['send'] * 16 + ['recv'] * 16)
        return rc, logs

    def test_all_8192_send_all_then_receive(self):
        rc, logs = self.exchange(reorder=True)
        self.assertEqual(rc, 0)
        self.assertIn('client_summary sent=8192 acked=8192 bad=0', logs)
        self.assertIn('client_recv_order req=1 answered=16', logs)

    def test_peer_full_8192_and_reject_duplicate(self):
        class PeerSocket:
            def __init__(self, duplicate):
                self.incoming = [protocol.SEED]
                # Every group arrives backwards; duplicates remain invalid
                # even inside a group where arbitrary order is permitted.
                for group in protocol.bursts():
                    for req in reversed(group):
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

        for duplicate in (False, True):
            s = PeerSocket(duplicate)
            logs = []
            with patch.object(peer.select, 'select', return_value=([s], [], [])), \
                 patch.object(peer.time, 'monotonic', side_effect=lambda: 0 if s.incoming else 2):
                rc = peer.serve(s, 7, 1, logs.append)
            self.assertEqual(rc, int(duplicate))
            self.assertEqual(s.echoes, [protocol.SEED] +
                             [protocol.payload(7, req) for group in protocol.bursts()
                              for req in reversed(group)])
            self.assertIn('peer_stop received=8192 bad=%d seed=1' % int(duplicate), logs)

    def test_tail_separate_bounded_and_byte_exact(self):
        for seq in (1, protocol.TAIL_MAX):
            data = protocol.tail(7, seq)
            self.assertEqual(len(data), 200)
            self.assertEqual(protocol.tail_identify(data), (7, seq))
            self.assertIsNone(protocol.identify(data))
            self.assertIsNone(protocol.ordinary_seq(data))
        for seq in (0, protocol.TAIL_MAX + 1):
            with self.assertRaises(ValueError):
                protocol.tail(7, seq)

    def test_last_tail_batch_finishes_before_done(self):
        s = Socket()
        logs, done = [], []
        send = s.sendto

        def record_send(data, addr):
            if protocol.tail_done_identify(data):
                self.assertEqual(s.queue, [])
                self.assertEqual(sum(line.startswith('client_tail_recv ') and
                                     'payload_ok=1' in line for line in logs), 16)
                done.append(data)
            return send(data, addr)

        released = '"m2-3h-rx-state" = "drained-and-unmapped"'
        with patch.object(load, 'now', return_value=100), \
             patch.object(load.time, 'monotonic', return_value=0), \
             patch.object(load.time, 'sleep'), \
             patch.object(load, 'command', side_effect=[released,
                          released + '\n"m2-3i-tail-state" = "waiting"']), \
             patch.object(s, 'sendto', side_effect=record_send):
            self.assertTrue(load.drain_tail(s, ('127.0.0.2', 9110), 7, logs.append))
        self.assertEqual(done, [protocol.tail_done(7, 16)])
        self.assertEqual(s.sent, [])  # no main workload ID or retry credit
        self.assertEqual(s.queue, [])
        self.assertIn('client_tail_summary sent=16 received=16 max=4096', logs)
        self.assertEqual(sum(line.startswith('client_tail_done_recv ') and
                             'payload_ok=1' in line for line in logs), 1)

    def test_tail_duplicate_fails_without_retransmission(self):
        class DuplicateTail(Socket):
            def recvfrom(self, size):
                data, addr = super().recvfrom(size)
                return protocol.tail(7, 1), addr
        s = DuplicateTail()
        logs = []
        with patch.object(load, 'now', return_value=100), \
             patch.object(load.time, 'monotonic', return_value=0):
            self.assertFalse(load.drain_tail(s, ('127.0.0.2', 9110), 7, logs.append))
        self.assertEqual(len(s.queue), 14)

    def test_duplicates_never_count_as_success(self):
        rc, logs = self.exchange(duplicate=True)
        self.assertEqual(rc, 1)
        self.assertIn('client_summary sent=8192 acked=7680 bad=512', logs)


if __name__ == '__main__':
    unittest.main()
