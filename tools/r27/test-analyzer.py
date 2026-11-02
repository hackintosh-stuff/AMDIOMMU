#!/usr/bin/env python3
"""Focused Round27 analyzer fixture; synthetic evidence is not hardware evidence.

Actual C++ headers generate native6/std5/domain3 and both new RX snapshots.
Real Round27 client/peer code generates the 2048 ordinary application logs.
The positive fixture covers all 64 RX map/post/done/restore/unmap lifecycles,
including one matched business receive, and both aligned/unaligned RX pages.
Rejection cases cover missing restoration and corrupted RX command evidence.
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
R27 = ROOT / 'tools/r27'
sys.path.insert(0, str(R27))
import load
import peer
import protocol

spec = importlib.util.spec_from_file_location('round27_analyzer_tested', R27 / 'analyze.py')
analyzer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analyzer)
legacy = analyzer.A

TOKEN = 7
PEER = ('127.0.0.2', 9110)
ABI_CHECK = 'capture-ABI-domain3-native6-std5-rx1'
COUNTER_CHECK = 'all-TX-standard-mode2-cumulative-and-unmarked-no-cover'
LOG_CHECK = 'full2048-bytes-no-retry-no-duplicate-credit'
CMD_CHECK = 'original8192-command-ring-wraps-and-postwrap-completion'
HISTORY_CHECK = 'retained32-standard-handles-PTE-and-retirement-lifecycles'
EXIT_CHECK = 'zero-pending-owners-pins-ring-and-no-device-page-fault'
RX_MAP_CHECK = 'rx64-standard-mapping-PTE-and-confirmed-unmap'
RX_DONE_CHECK = 'rx64-real-DMA-restoration-and-application-correlation'

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
#include "RTL812xRxMap.hpp"
#include <cstddef>
static_assert(offsetof(r27rx::Snapshot, maps) == 80, "RX maps offset");
static_assert(offsetof(r27rx::Snapshot, witnesses) == 2128, "RX witnesses offset");
static_assert(offsetof(r27rx::BackendSnapshot, records) == 64, "RX backend records offset");
static_assert(offsetof(r27rx::MapRecord, mapPte) == 56, "RX map PTE offset");
static_assert(offsetof(r27rx::MapRecord, clearPte) == 72, "RX clear PTE offset");
static_assert(offsetof(r27rx::MapRecord, entryId) == 88, "RX scalar offset");
static_assert(offsetof(r27rx::MapRecord, mapCommand) == 120, "RX map command offset");
static_assert(offsetof(r27rx::MapRecord, unmapCommand) == 160, "RX unmap command offset");

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
    d.historyTotal = d.mapsTotal = d.retiresTotal = 2304; d.historyStart = 2272;
    d.commandCapacity = _COMMAND_RING_BYTES_ / 16;
    d.commandSubmits = d.commandCompleted = d.completionSequence = 4739;
    d.commandWraps = 18; d.commandPostWrapCompleted = 4484;
    d.slotsUsed = 15; d.maxLiveOwners = 4;
    for (auto &uses : d.slotUses) uses = 576;
    g.magic = 0x37315854; g.version = r17tx::kVersion; g.bytes = sizeof(g);
    g.count = 32; g.bdf = d.devid; g.token = 7;
    g.retired = 2304; g.maxHeld = 4; g.historyStart = 2272; g.tPublished = 9025;
    s.magic = r18std::kMagic; s.version = r18std::kVersion; s.bytes = sizeof(s);
    s.count = 32; s.bdf = d.devid; s.token = 7;
    s.accepts = s.unmaps = s.historyTotal = 2304;
    s.maxHeld = 4; s.mode = r17tx::kModeAllStandard;
    s.historyStart = 2272; s.highReqAccepts = 2272; s.tPublished = 9025;
    b.magic = r20tx::kMagic; b.version = r20tx::kVersion; b.bytes = sizeof(b);
    b.bdf = d.devid; b.token = 7; b.nslot = 16;
    b.txNext = b.txDirty = b.txClose = b.txTail = 64;
    b.tSample = 9025; b.ringAddr = 0x800000; b.ringDescSize = 16;
    b.ringBytes = 1024 * b.ringDescSize;
    b.sampleStage = r20tx::kStageExit; b.sampleSeq = 8; b.quiesced = 1;
    for (uint32_t i = 0; i < 32; ++i) {
        // These are retirement records, not necessarily the last 32 request
        // IDs. All retained internal IDs exceed the userspace range 1..2048.
        // Keep internal 2272 instead of 2273 to distinguish retirement order.
        const uint32_t req = i == 0 ? 2272 : 2273 + i, pattern = (req - 1) % 16 + 1;
        const bool large = pattern == 2 || pattern == 4 || pattern == 6 || pattern == 8 || pattern == 11;
        const bool medium = pattern == 3 || pattern == 7 || pattern == 10 || pattern == 13 || pattern == 15;
        const uint32_t frame = large ? 1514 : medium ? 162 : 96;
        const uint32_t n = large ? 2 : 1, page = (i % 4) * 4;
        // Four distinct stripes overlap; each group retires before reuse.
        const uint64_t t = 3000 + (i / 4) * 100 + (i % 4) * 3;
        const uint64_t commandBase = 4611 + (i / 4) * 8;
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
    r27rx::Snapshot rx{};
    r27rx::BackendSnapshot rb{};
    rx.version = r27rx::kVersion; rx.bytes = sizeof(rx);
    rx.state = r27rx::kReleased; rx.generation = 1; rx.poolId = 0x275200;
    rx.mapCount = rx.posted = rx.completed = rx.restored = r27rx::kCount;
    rx.businessToken = 7; rx.tInstalled = 400; rx.tDisarmed = 8800;
    rx.tLastRestore = 3483;
    rb.version = r27rx::kVersion; rb.bytes = sizeof(rb);
    rb.count = rb.mapCalls = rb.mapOk = rb.unmapCalls = rb.unmapOk = r27rx::kCount;
    rb.ready = 1; rb.tReady = 410; rb.tDrained = 8810;
    for (uint32_t i = 0; i < r27rx::kCount; ++i) {
        auto &r = rb.records[i];
        r.pa = 0x90000000ULL + i * 0x3000 + (i % 2 ? 128 : 0);
        r.iova = r27rx::kIovaBase + i * 8192 + (r.pa & 4095);
        r.entryId = 1024 + i; r.capacity = r.mapLength = r27rx::kCapacity;
        r.mapOptions = 0x2; // reference/IOMemoryDescriptor.sdk.h: kIODMAMapWriteAccess
        r.pages = (r.pa & 4095) ? 2 : 1;
        r.tMapPublish = 200 + i * 2; r.tMapInv = 201 + i * 2;
        r.tUnmapPublish = 8820 + i; r.tUnmapInv = 8900 + i;
        r.mapCommand = {{0, (3u << 28) | d.domid, 0xfffff003u, 0x7fffffffu},
                        1 + i, 1 + i, r.tMapInv};
        r.unmapCommand = {{0, (3u << 28) | d.domid, 0xfffff003u, 0x7fffffffu},
                          4676 + i, 4676 + i, r.tUnmapInv};
        r.flags = r27rx::kMapRegistered | r27rx::kMapPublished |
                  r27rx::kMapInvalidated | r27rx::kMapUnmapped | r27rx::kMapReleased;
        for (uint32_t j = 0; j < r.pages; ++j)
            r.mapPte[j] = ((r.pa & ~4095ULL) + j * 4096) | perm;
        rx.maps[i] = {r.pa, r.iova, r.tMapInv, r.entryId, r.capacity};
        auto &w = rx.witnesses[i];
        w.originalPA = 0xa0000000ULL + i * 8192;
        w.sparePA = r.pa; w.iova = r.iova; w.slot = i; w.entryId = r.entryId;
        w.flags = r27rx::kWitnessPosted | r27rx::kWitnessDone | r27rx::kWitnessRestored;
        w.tPost = 3000 + i; w.tDone = 3320 + i; w.tRestoreOwn = 3420 + i;
        // One actual business completion suffices. Other slots may receive
        // ordinary/background packets; no business selector controls mapping.
        w.token = i == 0 ? 7 : 0; w.reqId = i == 0 ? 1025 : 0;
        w.doneLength = i == 0 ? 78 : 246; // UDP bytes + Ethernet/IPv4/UDP/FCS
        w.doneStatus = w.doneLength; // hardware DescOwn is already clear
    }
    if (damage == "unrestored") rx.witnesses[63].flags &= ~r27rx::kWitnessRestored;
    save(dir, "r27-rx-raw.bin", &rx, sizeof(rx));
    save(dir, "r27-rx-map-raw.bin", &rb, sizeof(rb));
    save(dir, "r21-domain-raw.bin", &d, sizeof(d));
    save(dir, "r21-driver-raw.bin", &g, sizeof(g));
    save(dir, "r21-std-raw.bin", &s, sizeof(s));
    save(dir, "r21-block-raw.bin", &b, sizeof(b));
    save(dir, "r21-pt-raw.bin", pt, sizeof(pt));
}
'''


def properties():
    p = {'m2-3c-mode': 'standard-iomapper', 'm2-3g-mode': 'all-standard',
         'm2-3h-rx-mode': 'standard-nonidentity-one-shot',
         'm2-3h-rx-state': 'drained-and-unmapped', 'm2-3h-rx-ready': 'no',
         'm2-3h-rx-pending': 0, 'm2-3h-rx-live-owners': 0}
    for key in ('m2-3c-map-calls', 'm2-3c-map-ok', 'm2-3c-unmap-ok',
                'm2-3b-map-accepted', 'm2-3b-retires'):
        p[key] = 2304
    for key in ('m2-3c-insert-calls', 'm2-3c-map-rejects', 'm2-3b-map-rejected',
                'm2-3c-cover-calls', 'm2-3b-owners-held', 'm2-b2-win-entries', 'm2-b2-win-new-entries',
                'm2-b2-win-raw-count', 'm2-b2-win-pre-backlog',
                'm2-b2-win-devid-mismatch', 'm2-3c-cover-unconf',
                'm2-b2-win-head-start', 'm2-b2-win-tail-start',
                'm2-b2-win-head-end', 'm2-b2-win-tail-end',
                'm2-3e-enter-last-inflight', 'm2-3e-enter-last-ring',
                'm2-3e-exit-last-inflight', 'm2-3e-exit-last-ring'):
        p[key] = 0
    p.update({'m2-3b-command-capacity': 512, 'm2-3b-submits': 4739,
              'm2-3b-command-completed': 4739, 'm2-3b-command-wraps': 18,
              'm2-3b-command-post-wrap-completed': 4484,
              'm2-3b-completion-sequence': 4739,
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


def real_logs(client_reorder=True, peer_reorder=True):
    s, client_lines, peer_lines = ClientSocket(client_reorder), [], []
    seq = load.OrdSeq()
    with patch.object(load, 'now', return_value=50):
        for _ in range(20):
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
        cls.temp = tempfile.TemporaryDirectory(prefix='r27-analyzer-')
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
            '"R24TxWakes" = 96\n"R24TxPending" = 0\n'
            '"R26TxMode" = "all-standard"\n'
            '"R26TxMapped" = 2304\n"R26TxUnmarked" = 2304\n'
            '"R26TxLegacySelected" = 0\n"R26TxAttempts" = 2308\n'
            '"rtl812x-txmap-cover-calls" = 0\n')

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

    def test_rx64_full_lifecycle_with_actual_headers_and_real_logs(self):
        self.assertEqual((self.capture / 'r21-domain-raw.bin').stat().st_size, analyzer.DOMAIN_BYTES)
        self.assertEqual((self.capture / 'r21-driver-raw.bin').stat().st_size, analyzer.DRIVER_BYTES)
        self.assertEqual((self.capture / 'r21-std-raw.bin').stat().st_size, analyzer.STD_BYTES)
        self.assertEqual(protocol.MAGIC, b'R27P')
        self.assertNotIn(protocol.payload(TOKEN, 1)[:4], (b'IOB1', b'1BOI'))
        report = self.expect(True)
        self.assertEqual(len(report['checks']), 11)
        by_id = {c['id']: c.get('detail') for c in report['checks']}
        self.assertEqual(by_id[COUNTER_CHECK]['mode'], 2)
        self.assertEqual((by_id[COUNTER_CHECK]['Mapped'], by_id[COUNTER_CHECK]['Unmarked']), (2304, 2304))
        self.assertEqual((by_id[CMD_CHECK]['commandCapacity'], by_id[CMD_CHECK]['commandRingBytes']), (512, 8192))
        history = by_id[HISTORY_CHECK]
        self.assertEqual((history['historyTotal'], history['historyStart'], history['retained']), (2304, 2272, 32))
        self.assertTrue(all(req > 2048 for req in history['internalRequests']))
        self.assertEqual(history['nativeHandles'], [0])
        self.assertEqual(history['peakRetainedLive'], 4)
        self.assertEqual(by_id['ordinary-traffic-before-during-and-three-after'],
                         {'before': 20, 'during': 256, 'after': 3})
        self.assertEqual((self.capture / 'r27-rx-raw.bin').stat().st_size, 7248)
        self.assertEqual((self.capture / 'r27-rx-map-raw.bin').stat().st_size, 12864)
        self.assertEqual(by_id[RX_MAP_CHECK]['mapped'], 64)
        self.assertEqual(by_id[RX_MAP_CHECK]['unmapped'], 64)
        self.assertEqual(by_id[RX_MAP_CHECK]['writablePages'], 96)
        self.assertEqual(by_id[RX_DONE_CHECK]['restored'], 64)
        self.assertEqual(by_id[RX_DONE_CHECK]['applicationRequests'], [1025])
        # Scoped decoding must leave the historical module's ABI unchanged.
        self.assertEqual((legacy.STD_VERSION, legacy.DRIVER_VERSION), (3, 4))

    def test_corrupted_rx_command_evidence_is_rejected(self):
        path = self.capture / 'r27-rx-map-raw.bin'
        baseline = path.read_bytes()
        # Both directions: each word (including PDE), missing/mismatched CW,
        # zero/reversed/out-of-range/shared IDs and timestamp substitution.
        for command in (120, 160):
            for offset, fmt, value in (
                    (0, 'I', 1), (4, 'I', 7 | (3 << 28)),
                    (8, 'I', 0xfffff001), (12, 'I', 0),
                    (16, 'Q', 0), (24, 'Q', 0), (32, 'Q', 0),
                    (32, 'Q', 999)):
                # Domain word mutation must actually differ from the baseline.
                if offset == 4:
                    value ^= 1
                with self.subTest(command=command, offset=offset, value=value):
                    blob = bytearray(baseline)
                    analyzer.struct.pack_into('<' + fmt, blob, 64 + command + offset, value)
                    path.write_bytes(blob)
                    self.expect(False, RX_MAP_CHECK)
        for command, sequence in ((120, 4676), (160, 4740), (120, 4611), (160, 4677)):
            with self.subTest(command=command, sequence=sequence):
                blob = bytearray(baseline)
                analyzer.struct.pack_into('<2Q', blob, 64 + command + 16, sequence, sequence)
                path.write_bytes(blob)
                self.expect(False, RX_MAP_CHECK)

    def test_missing_rx_restoration_witness_is_rejected(self):
        subprocess.run([str(self.exe), str(self.capture), 'unrestored'], check=True)
        report = self.expect(False, RX_DONE_CHECK)
        by_id = {c['id']: c['state'] for c in report['checks']}
        self.assertEqual(by_id[RX_MAP_CHECK], 'ok')


if __name__ == '__main__':
    unittest.main(verbosity=2)
