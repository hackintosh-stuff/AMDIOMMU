#!/usr/bin/env python3
"""Focused Round25 host checks; synthetic evidence is never a hardware result.

The C++ fixture includes the actual current export headers, so these tests do
not manufacture blobs using the decoder's own offset table. Its field semantics
follow r17StdMap/r17TxMapStd/r17TxRetire: domain packet metadata and native
handle/physical fields are zero in standard mode. Application logs
come from the real load.exchange/ord_probe and peer.serve with finite in-memory
socket doubles. The production analyzer and its real legacy decoding helpers
run unchanged against each temporary capture.
"""
import importlib.util
import itertools
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
R21 = ROOT / 'tools/r21'
sys.path.insert(0, str(R21))
import analyze as legacy
import load
import peer
import protocol

spec = importlib.util.spec_from_file_location('round25_analyzer', R21 / 'check-r25.py')
analyzer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analyzer)

TOKEN = 7
PEER = ('127.0.0.2', 9110)
ABI_CHECK = 'capture-ABI-domain3-native5-std4'
LOG_CHECK = 'full512-bytes-no-retry-no-duplicate-credit'
CMD_CHECK = 'original8192-command-ring-wraps-and-postwrap-completion'
HISTORY_CHECK = 'retained32-standard-handles-PTE-and-retirement-lifecycles'
EXIT_CHECK = 'zero-pending-owners-pins-ring-and-no-device-page-fault'

CPP = r'''
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
using IOReturn = int;
struct IOService;
#include "RTL812xTxMapNative.hpp"
#include "RTL812xTxMapStd.hpp"
#include "AMDAliveTxDomainNative.hpp"

static void save(const std::string &dir, const char *name, const void *p, size_t n) {
    FILE *f = std::fopen((dir + "/" + name).c_str(), "wb");
    if (!f || std::fwrite(p, 1, n, f) != n || std::fclose(f)) std::abort();
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    const std::string dir = argv[1], damage = argv[2];
    r17domain::Snapshot d{};
    r17tx::Snapshot g{};
    r18std::Snapshot s{};
    r20tx::Block b{};
    constexpr uint64_t base = 0x1000000000ULL, ptBase = 0x100000ULL;
    constexpr uint64_t perm = 1ULL | (1ULL << 61) | (1ULL << 62);
    uint64_t pt[3 * 512]{};
    pt[(base >> 30) & 511] = (ptBase + 4096) | perm | (2 << 9);
    pt[512 + ((base >> 21) & 511)] = (ptBase + 8192) | perm | (1 << 9);
    d.version = r17domain::kVersion; d.bytes = sizeof(d); d.count = 32;
    d.iovaBase = base; d.iovaBytes = 16 * 4096;
    d.rootPA = d.ptBase = ptBase; d.leafPA = ptBase + 8192;
    d.ptBytes = sizeof(pt); d.rootLevel = 3; d.devid = 0x0200; d.domid = 7;
    d.historyTotal = d.mapsTotal = d.retiresTotal = 512; d.historyStart = 480;
    d.commandCapacity = _COMMAND_RING_BYTES_ / 16;
    d.commandSubmits = d.commandCompleted = d.completionSequence = 1032;
    d.commandWraps = 4; d.commandPostWrapCompleted = 777;
    d.slotsUsed = 15; d.maxLiveOwners = 4;
    for (auto &uses : d.slotUses) uses = 128;
    g.magic = 0x37315854; g.version = r17tx::kVersion; g.bytes = sizeof(g);
    g.count = 32; g.bdf = d.devid; g.token = 7;
    g.retired = 512; g.maxHeld = 4; g.historyStart = 480; g.tPublished = 9025;
    s.magic = r18std::kMagic; s.version = r18std::kVersion; s.bytes = sizeof(s);
    s.count = 32; s.bdf = d.devid; s.token = 7;
    s.accepts = s.unmaps = s.historyTotal = 512;
    s.maxHeld = 4; s.mode = r17tx::kModeStandard;
    s.historyStart = 480; s.highReqAccepts = 480; s.tPublished = 9025;
    b.magic = r20tx::kMagic; b.version = r20tx::kVersion; b.bytes = sizeof(b);
    b.bdf = d.devid; b.token = 7; b.nslot = 16;
    b.txNext = b.txDirty = b.txClose = b.txTail = 64;
    b.tSample = 9025; b.ringAddr = 0x800000; b.ringDescSize = 16;
    b.ringBytes = 1024 * b.ringDescSize;
    b.sampleStage = r20tx::kStageExit; b.sampleSeq = 8; b.quiesced = 1;
    for (uint32_t i = 0; i < 32; ++i) {
        // These are retirement records, not necessarily the last 32 request
        // IDs. Keep request 480 instead of 481 to exercise that distinction.
        const uint32_t req = i == 0 ? 480 : 481 + i, pattern = (req - 1) % 16 + 1;
        const bool large = pattern == 2 || pattern == 4 || pattern == 6 || pattern == 8 || pattern == 11;
        const bool medium = pattern == 3 || pattern == 7 || pattern == 10 || pattern == 13 || pattern == 15;
        const uint32_t frame = (large ? 1472 : medium ? 120 : 32) + 42;
        const uint32_t n = large ? 2 : 1, page = (i % 4) * 4;
        // Four distinct stripes overlap; each group retires before reuse.
        const uint64_t t = 3000 + (i / 4) * 100 + (i % 4) * 3;
        const uint64_t commandBase = 969 + (i / 4) * 8;
        auto &w = d.records[i];
        // Each history may have its own physical ring permutation. Handles
        // must perform the join; equal array indices must not be assumed.
        auto &v = g.witnesses[(i * 5) % 32];
        auto &u = s.witnesses[(i * 9) % 32];
        // r17StdMap cannot see the packet: only its handle joins to stdW.
        w.handle = req; w.token = 0; w.req = 0; w.status = 3;
        w.count = w.pages = n; w.maplen = large ? 8192 - 256 : frame;
        w.tMapPublish = t + 1; w.tMapInv = t + 2;
        w.tClearPublish = t + 14; w.tRetireInv = t + 16;
        w.mapCommand = {{0, (3u << 28) | d.domid, 0xfffff003u, 0x7fffffffu},
                        commandBase + i % 4, commandBase + i % 4, t + 2};
        w.retireCommand = {{0, (3u << 28) | d.domid, 0xfffff003u, 0x7fffffffu},
                           commandBase + 4 + i % 4, commandBase + 4 + i % 4, t + 16};
        auto &r = v.request;
        r.version = r17tx::kVersion; r.bytes = sizeof(r); r.bdf = d.devid;
        // r17TxMapStd fills iova/tMap, not native handle or physical. Its
        // timer passes request.handle==0 to r17TxRetire in standard mode.
        r.token = 7; r.reqId = req; r.count = n; r.handle = 0;
        r.tMap = t + 3; r.tDone = t + 12;
        v.tOwn = t + 6; v.tFree = t + 20; v.retired = 1;
        v.cumulative = 2 * req; v.firstSlot = (2 * req) % 1024;
        v.lastSlot = (v.firstSlot + n - 1) % 1024;
        v.doneClose = v.cumulative + n; v.closeMask = 0xffff;
        u.version = r18std::kVersion; u.bytes = sizeof(u);
        u.req = req; u.token = 7; u.handle = req; u.segCount = n;
        u.flags = r18std::kMapped | r18std::kUnmapped;
        u.memory = 0x100000 + req * 64; u.command = 0x200000 + req * 64;
        u.mapLength = u.descriptorLength = frame; u.mbufSegments = n;
        u.tBegin = t; u.tPrepared = t + 3; u.tSegmented = t + 4;
        // r17TxPosted uses the exact tOwn stamp; the native Request carries
        // tDone, while the standard witness's tDone remains zero.
        u.tCommit = v.tOwn;
        u.tCompleteBegin = t + 13; u.tCompleteEnd = t + 17; u.tFree = t + 20;
        for (uint32_t j = 0; j < n; ++j) {
            const uint64_t off = j ? 512 : 256;
            const uint64_t pa = 0x10000000 + req * 0x10000 + j * 4096 + off;
            const uint64_t iova = base + (page + j) * 4096 + off;
            const uint64_t len = large ? (j ? frame - 96 : 96) : frame;
            w.segments[j] = {pa, len, iova};
            w.physical[page + j] = pa & ~4095ULL;
            w.mapPte[page + j] = (pa & ~4095ULL) | perm;
            r.iova[j] = {iova, len};
            v.descriptors[j] = {iova, len, 0x80000000u | (uint32_t)len, 0};
            v.doneOpts1[j] = v.descriptors[j].opts1;
            u.segments[j] = {iova, len};
        }
        u.mapAddress = u.segments[0].address;
    }
    if (damage == "capacity-bytes") d.commandCapacity = _COMMAND_RING_BYTES_;
    if (damage == "no-wrap") d.commandWraps = 0;
    if (damage == "no-postwrap") d.commandPostWrapCompleted = 0;
    if (damage == "unacknowledged") --d.commandCompleted;
    if (damage == "too-few-commands") d.commandSubmits = d.commandCompleted = d.completionSequence = 512;
    if (damage == "old-domain-version") --d.version;
    if (damage == "old-native-version") --g.version;
    if (damage == "old-std-version") --s.version;
    if (damage == "stale-history") d.historyStart = 448;
    if (damage == "bad-pte") d.records[0].mapPte[0] ^= 4096;
    if (damage == "uncleared-pte") pt[1024] = d.records[0].mapPte[0];
    if (damage == "bad-completion") ++d.records[0].retireCommand.observed;
    if (damage == "bad-command-opcode") d.records[0].retireCommand.d[1] ^= 1u << 28;
    if (damage == "bad-command-domain") d.records[0].retireCommand.d[1] ^= 1;
    if (damage == "bad-command-time") --d.records[0].retireCommand.tComplete;
    if (damage == "bad-handle") s.witnesses[0].handle = 999;
    if (damage == "not-unmapped") s.witnesses[0].flags = r18std::kMapped;
    if (damage == "pinned") s.pinned = 1;
    if (damage == "live-owner") d.liveOwners = 1;
    if (damage == "ring-outstanding") b.outstanding = 1;
    if (damage == "wrong-token") b.token = 8;
    if (damage == "wrong-device") b.bdf = 0x0300;
    save(dir, "r21-domain-raw.bin", &d, sizeof(d));
    save(dir, "r21-driver-raw.bin", &g, sizeof(g));
    save(dir, "r21-std-raw.bin", &s, sizeof(s));
    save(dir, "r21-block-raw.bin", &b, sizeof(b));
    save(dir, "r21-pt-raw.bin", pt, sizeof(pt));
}
'''


def properties():
    p = {'m2-3c-mode': 'standard-iomapper'}
    for key in ('m2-3c-map-calls', 'm2-3c-map-ok', 'm2-3c-unmap-ok',
                'm2-3b-map-accepted', 'm2-3b-retires'):
        p[key] = 512
    for key in ('m2-3c-insert-calls', 'm2-3c-map-rejects', 'm2-3b-map-rejected',
                'm2-3b-owners-held', 'm2-b2-win-entries', 'm2-b2-win-new-entries',
                'm2-b2-win-raw-count', 'm2-b2-win-pre-backlog',
                'm2-b2-win-devid-mismatch', 'm2-3c-cover-unconf',
                'm2-b2-win-head-start', 'm2-b2-win-tail-start',
                'm2-b2-win-head-end', 'm2-b2-win-tail-end',
                'm2-3e-enter-last-inflight', 'm2-3e-enter-last-ring',
                'm2-3e-exit-last-inflight', 'm2-3e-exit-last-ring'):
        p[key] = 0
    p.update({'m2-3b-command-capacity': 512, 'm2-3b-submits': 1032,
              'm2-3b-command-completed': 1032, 'm2-3b-command-wraps': 4,
              'm2-3b-command-post-wrap-completed': 777,
              'm2-3b-completion-sequence': 1032,
              'm2-b2-window-valid': 'yes', 'm2-b2-win-raw-truncated': 'no',
              'm2-b2-win-status-start': 8, 'm2-b2-win-status-end': 8,
              'm2-3e-enter': 'gate-open-after-dte-and-invalidations',
              'm2-3e-enter-drain': 'drained', 'm2-3e-exit-drain': 'drained',
              'm2-3e-translate-off': 'confirmed-by-register-readback',
              'm2-3e-exit-detach': 'detached',
              'm2-3e-after-exit': 'ordinary-output-resumed',
              'm2-3b-cleanup': 'detached-after-restore-confirmed'})
    enter = ('m2-3e-enter-gate-close', 'm2-3e-enter-submit-done',
             'm2-3e-enter-drain-done', 'm2-b2-dma-t-dte-written',
             'm2-3e-t-translate-on', 'm2-3e-t-gate-open')
    leave = ('m2-3e-exit-gate-close', 'm2-3e-exit-submit-done',
             'm2-3e-exit-drain-done', 'm2-3e-t-translate-off',
             'm2-3e-t-detach', 'm2-3e-t-resume')
    p.update(zip(enter, range(100, 160, 10)))
    p.update(zip(leave, range(9000, 9060, 10)))
    return ''.join('"%s" = "%s"\n' % (key, hex(value) if isinstance(value, int) else value)
                   for key, value in p.items())


class ClientSocket:
    def __init__(self, reorder):
        self.reorder = reorder
        self.queue, self.outgoing, self.group = [], [], []

    def bind(self, addr):
        pass

    def settimeout(self, timeout):
        pass

    def getsockname(self):
        return ('127.0.0.1', 10000)

    def sendto(self, data, addr):
        self.outgoing.append(data)
        if protocol.identify(data):
            self.group.append(data)
            if len(self.group) == protocol.BURST:
                self.queue.extend(reversed(self.group) if self.reorder else self.group)
                self.group = []
        else:
            self.queue.append(data)
        return len(data)

    def recvfrom(self, size):
        return self.queue.pop(0), PEER


def real_logs(client_reorder=False, peer_reorder=False):
    s, client_lines, peer_lines = ClientSocket(client_reorder), [], []
    seq = load.OrdSeq()
    with patch.object(load, 'now', return_value=50):
        assert load.ord_probe(s, PEER, seq.next(), client_lines.append, 'pre')
    with patch.object(load, 'now', side_effect=itertools.count(1000)):
        assert load.exchange(s, '127.0.0.1', PEER, TOKEN, client_lines.append, seq) == 0
    with patch.object(load, 'now', side_effect=itertools.count(9100)):
        for _ in range(3):
            assert load.ord_probe(s, PEER, seq.next(), client_lines.append, 'after-exit')
    client_lines.append('client_result OK')
    incoming = [protocol.SEED]
    at = 0
    while at < len(s.outgoing):
        if protocol.identify(s.outgoing[at]):
            group = s.outgoing[at:at + protocol.BURST]
            incoming.extend(group[5:] + group[:5] if peer_reorder else group)
            at += protocol.BURST
        else:
            incoming.append(s.outgoing[at])
            at += 1

    class PeerSocket:
        def getsockname(self):
            return PEER

        def recvfrom(self, size):
            return incoming.pop(0), ('127.0.0.1', 10000)

        def sendto(self, data, addr):
            return len(data)

    ps = PeerSocket()
    with patch.object(peer.select, 'select', return_value=([ps], [], [])), \
         patch.object(peer.time, 'monotonic', side_effect=lambda: 0 if incoming else 2), \
         patch.object(peer.time, 'monotonic_ns', side_effect=itertools.count(1)):
        assert peer.serve(ps, TOKEN, 1, peer_lines.append) == 0
    return '\n'.join(client_lines) + '\n', '\n'.join(peer_lines) + '\n'


class AnalyzerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='r25-analyzer-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.exe = cls.root / 'fixture'
        source = cls.root / 'fixture.cpp'
        producer = (ROOT / 'kext/AMDMapperProbeInternal.hpp').read_text()
        match = re.search(r'^#define\s+M23_CMD_BUF_SIZE\s+(\d+)', producer, re.M)
        assert match, 'actual command buffer size is not declared'
        source.write_text(CPP.replace('_COMMAND_RING_BYTES_', match[1]))
        compiler = shlex.split(os.environ['CXX']) if os.environ.get('CXX') else \
            [shutil.which('clang++') or shutil.which('c++')]
        if not compiler or not compiler[0]:
            raise RuntimeError('C++17 compiler required to test the real exported ABI')
        subprocess.run(compiler + ['-std=c++17', '-Wno-enum-compare', '-I', str(ROOT / 'tools/lucy-obs'),
                        str(source), '-o', str(cls.exe)], check=True)
        cls.baseline = cls.root / 'baseline'
        cls.baseline.mkdir()
        subprocess.run([str(cls.exe), str(cls.baseline), ''], check=True)
        client, peer_text = real_logs()
        (cls.baseline / 'client.log').write_text(client)
        (cls.baseline / 'peer.log').write_text(peer_text)
        (cls.baseline / 'props.txt').write_text(properties())
        (cls.baseline / 'props.raw.txt').write_text('')
        (cls.baseline / 'driver-obs.txt').write_text(
            '"rtl812x-txmap-mode" = "native-mbuf-standard-iomapper-v1"\n'
            '"R24TxWaits" = 96\n"R24TxResumes" = 96\n'
            '"R24TxWakes" = 96\n"R24TxPending" = 0\n')

    def setUp(self):
        self.capture = self.root / 'case'
        if self.capture.exists():
            shutil.rmtree(self.capture)
        shutil.copytree(self.baseline, self.capture)

    def expect(self, ok, failed_check=None):
        report = analyzer.check(self.capture)
        failures = {c['id']: c.get('detail', '') for c in report['checks'] if c['state'] != 'ok'}
        self.assertEqual(report['ok'], ok, failures)
        if failed_check:
            self.assertIn(failed_check, failures)
        return report

    def edit_log(self, name, transform):
        path = self.capture / name
        path.write_text('\n'.join(transform(path.read_text().splitlines())) + '\n')

    def test_real_header_abi_and_independent_history_permutations(self):
        self.assertEqual((self.capture / 'r21-domain-raw.bin').stat().st_size, analyzer.DOMAIN_BYTES)
        self.assertEqual((self.capture / 'r21-driver-raw.bin').stat().st_size, analyzer.DRIVER_BYTES)
        self.assertEqual((self.capture / 'r21-std-raw.bin').stat().st_size, analyzer.STD_BYTES)
        report = self.expect(True)
        cmd = next(c['detail'] for c in report['checks'] if c['id'] == CMD_CHECK)
        self.assertEqual((cmd['commandCapacity'], cmd['commandRingBytes']), (512, 8192))
        retained = next(c['detail'] for c in report['checks'] if c['id'] == HISTORY_CHECK)
        self.assertEqual(retained['nativeHandles'], [0])
        self.assertEqual(retained['peakRetainedLive'], 4)
        self.assertIn(480, retained['requests'])
        self.assertNotIn(481, retained['requests'])
        self.assertEqual((legacy.STD_VERSION, legacy.DRIVER_VERSION), (3, 4))

    def test_real_client_and_peer_allow_permutations_inside_each_burst(self):
        for client_order, peer_order in ((True, False), (False, True), (True, True)):
            with self.subTest(client_reorder=client_order, peer_reorder=peer_order):
                client, peer_text = real_logs(client_order, peer_order)
                (self.capture / 'client.log').write_text(client)
                (self.capture / 'peer.log').write_text(peer_text)
                self.expect(True)

    def test_duplicate_missing_corrupt_and_cross_group_echoes_fail(self):
        for damage in ('duplicate', 'missing', 'corrupt', 'cross-group', 'status-prefix'):
            with self.subTest(damage=damage):
                lines = (self.baseline / 'client.log').read_text().splitlines()
                ix = [i for i, line in enumerate(lines) if line.startswith('client_recv ')]
                if damage == 'duplicate':
                    lines[ix[1]] = lines[ix[0]]
                elif damage == 'missing':
                    del lines[ix[0]]
                elif damage == 'corrupt':
                    lines[ix[0]] = lines[ix[0]].replace('payload=', 'payload=00', 1)
                elif damage == 'cross-group':
                    lines[ix[0]], lines[ix[16]] = lines[ix[16]], lines[ix[0]]
                else:
                    lines[ix[0]] = lines[ix[0]].replace('payload_ok=1', 'payload_ok=10')
                (self.capture / 'client.log').write_text('\n'.join(lines) + '\n')
                self.expect(False, LOG_CHECK)

    def test_send_before_receive_and_burst_declarations_remain_required(self):
        for damage in ('early-receive', 'wrong-burst', 'hidden-timeout'):
            with self.subTest(damage=damage):
                lines = (self.baseline / 'client.log').read_text().splitlines()
                if damage == 'early-receive':
                    sent = next(i for i, line in enumerate(lines) if line.startswith('client_sent '))
                    recv = next(i for i, line in enumerate(lines) if line.startswith('client_recv '))
                    lines.insert(sent + 15, lines.pop(recv))
                elif damage == 'wrong-burst':
                    ix = next(i for i, line in enumerate(lines) if line.startswith('client_burst '))
                    lines[ix] = 'client_burst reqs=' + ','.join(map(str, range(2, 18)))
                else:
                    lines.append('client_timeout token=0x00000007 req=1')
                (self.capture / 'client.log').write_text('\n'.join(lines) + '\n')
                self.expect(False, LOG_CHECK)

    def test_peer_must_echo_the_request_it_just_validated(self):
        def wrong_pair(lines):
            ix = [i for i, line in enumerate(lines) if line.startswith('peer_sent ')]
            lines[ix[0]], lines[ix[1]] = lines[ix[1]], lines[ix[0]]
            return lines
        self.edit_log('peer.log', wrong_pair)
        self.expect(False, LOG_CHECK)

    def test_corrupted_raw_evidence_cannot_be_hidden_by_success_logs(self):
        cases = {
            'capacity-bytes': CMD_CHECK, 'no-wrap': CMD_CHECK,
            'no-postwrap': CMD_CHECK, 'unacknowledged': CMD_CHECK,
            'too-few-commands': CMD_CHECK,
            'old-domain-version': ABI_CHECK, 'old-native-version': ABI_CHECK,
            'old-std-version': ABI_CHECK, 'wrong-token': ABI_CHECK,
            'wrong-device': ABI_CHECK,
            'stale-history': HISTORY_CHECK, 'bad-pte': HISTORY_CHECK,
            'uncleared-pte': HISTORY_CHECK, 'bad-completion': HISTORY_CHECK,
            'bad-command-opcode': HISTORY_CHECK, 'bad-command-domain': HISTORY_CHECK,
            'bad-command-time': HISTORY_CHECK, 'bad-handle': HISTORY_CHECK,
            'not-unmapped': HISTORY_CHECK,
            'pinned': EXIT_CHECK, 'live-owner': EXIT_CHECK,
            'ring-outstanding': EXIT_CHECK,
        }
        for damage, check in cases.items():
            with self.subTest(damage=damage):
                subprocess.run([str(self.exe), str(self.capture), damage], check=True)
                self.expect(False, check)

    def test_command_scalar_must_match_the_same_exported_snapshot(self):
        path = self.capture / 'props.txt'
        path.write_text(path.read_text().replace('"m2-3b-command-capacity" = "0x200"',
                                                 '"m2-3b-command-capacity" = "0x2000"'))
        self.expect(False, CMD_CHECK)


if __name__ == '__main__':
    unittest.main(verbosity=2)
