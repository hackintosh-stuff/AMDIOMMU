#!/usr/bin/env python3
"""Focused Round40 analyzer fixture; synthetic evidence is not hardware evidence.

Actual C++ headers generate native7/std5/domain4 and both RX snapshots.
Current client/peer code generates the 8192 ordinary application logs.
The positive fixture covers all 1024 RX map/post/done/restore/unmap lifecycles,
including remapping, batch16, bootstrap retirement and local NIC stop without peer tail traffic.
Final uncompleted OWN records are explicitly stop-retired, never counted as DMA completions.
The same fixture maps the three fixed DMA objects through their actual headers,
with active IOVA readbacks, no active identity leaves and physical restart readbacks.
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
ABI_CHECK = 'capture-ABI-domain4-native7-std5-nativeRX4'
COUNTER_CHECK = 'all-TX-standard-mode2-cumulative-and-unmarked-no-cover'
LOG_CHECK = 'full8192-bytes-no-retry-no-duplicate-credit'
CMD_CHECK = 'original8192-command-ring-wraps-and-postwrap-completion'
HISTORY_CHECK = 'retained32-standard-handles-PTE-and-retirement-lifecycles'
EXIT_CHECK = 'zero-pending-owners-pins-ring-and-no-device-page-fault'
RX_MAP_CHECK = 'rx1024-driver-owned-MD-Cmd-repeated-mapping-and-unmap'
RX_DONE_CHECK = 'rx1024-native-replacement-DMA-and-current-buffer-restore'
SESSION_CHECK = 'service-owned-domain-after-setup-exit-125s-idle-stop-and-restore'
ALLOCATION_CHECK = 'dynamic-IOVA-wide-map-eight-live-and-confirmed-reuse'
STOP_CHECK = 'local-NIC-stop-before-RX-retirement'
AUTONOMOUS_CHECK = 'peer-independent-stop-and-physical-resume'
IDLE_NS = 125_000_000_000


def session_time(value):
    # Insert the same 125 s idle into the existing ordered synthetic timeline.
    return value + IDLE_NS if value >= 2152 else value

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
#include "RTL812xRxNative.hpp"
#include "RTL812xFixedDma.hpp"
#include "amd_iommu_sparse_core.hpp"
#include <cstddef>
static_assert(sizeof(r34rx::Snapshot) == 270432, "native RX driver snapshot");
static_assert(sizeof(r34rx::BackendSnapshot) == 475216, "native RX backend snapshot");
static_assert(offsetof(r34rx::Snapshot, slots) == 96, "native RX driver prefix");
static_assert(offsetof(r34rx::BackendSnapshot, slots) == 80, "native RX backend prefix");
static_assert(sizeof(r34rx::PhysicalLayout) == 64, "fixed physical DMA layout");
static_assert(sizeof(r34rx::StopRecord) == 96, "local NIC stop record");
static_assert(sizeof(r40fixed::DriverSnapshot) == 368, "fixed DMA driver snapshot");
static_assert(sizeof(r40fixed::BackendSnapshot) == 1376, "fixed DMA backend snapshot");

static uint64_t sessionTime(uint64_t value) {
    return value >= 2152 ? value + 125000000000ULL : value;
}
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
    amdsparse::u64 pt[32 * 512]{};
    pt[(base >> 30) & 511] = (ptBase + 4096) | perm | (2 << 9);
    for (uint32_t i = 0; i < 5; ++i)
        pt[512 + ((base >> 21) & 511) + i] = (ptBase + (2 + i) * 4096) | perm | (1 << 9);
    d.version = r17domain::kVersion; d.bytes = sizeof(d); d.count = 32;
    d.iovaBase = base; d.iovaBytes = 256 * 4096;
    d.rootPA = d.ptBase = ptBase; d.leafPA = ptBase + 8192;
    d.ptBytes = sizeof(pt); d.rootLevel = 3; d.devid = 0x0200; d.domid = 7;
    d.historyTotal = d.mapsTotal = d.retiresTotal = 10249; d.historyStart = 10217;
    d.commandCapacity = _COMMAND_RING_BYTES_ / 16;
    // Four normal ring passes use 63 full batches plus two 8-slot partials.
    // Install and final local-stop retirement remain scalar.
    constexpr uint32_t batchGroups = 4 * 65;
    constexpr uint32_t rxInvalidations = r34rx::kCount + batchGroups;
    d.commandSubmits = d.commandCompleted = d.completionSequence =
        2 * (10240 + 9) + 2 * rxInvalidations + 4 + 2 * r40fixed::kCount;
    d.commandWraps = d.commandSubmits * 2 / d.commandCapacity;
    d.commandPostWrapCompleted = d.commandCompleted - (d.commandCapacity / 2 - 1);
    d.slotsUsed = 65535; d.maxLiveOwners = 16;
    for (auto &uses : d.slotUses) uses = 640;
    for (uint32_t i = 0; i < 8; ++i) d.slotUses[i]++;
    d.slotUses[0]++;
    d.peakPages = 24; d.maxMappedPages = 8; d.reusedAllocations = 10000;
    d.probeMaps = d.probeUnmaps = 9; d.probePeakOwners = d.probeMaxPages = 8;
    d.probePassed = d.probeReused = 1; d.probeStart = 141; d.probeEnd = 159;
    auto capacityRecord = [&](r17domain::Record &w, uint64_t handle, uint64_t pa,
                              uint64_t mapTime, uint64_t doneTime, uint64_t sequence) {
        w.handle = handle; w.status = 3; w.count = 1; w.pages = 8; w.maplen = 8 * 4096;
        w.basePage = w.recordIndex = 0;
        w.tMapPublish = mapTime; w.tMapInv = mapTime + 1;
        w.tClearPublish = doneTime; w.tRetireInv = doneTime + 1;
        w.segments[0] = {pa, 8 * 4096, base};
        for (uint32_t i = 0; i < 8; ++i) {
            w.physical[i] = pa + i * 4096;
            w.mapPte[i] = w.physical[i] | perm;
        }
        w.mapCommand = {{0, (3u << 28) | d.domid, 0xfffff003u, 0x7fffffffu},
                        sequence, sequence, w.tMapInv};
        const uint64_t retired = handle == 1 ? 9 : 18;
        w.retireCommand = {{0, (3u << 28) | d.domid, 0xfffff003u, 0x7fffffffu},
                           retired, retired, w.tRetireInv};
    };
    capacityRecord(d.probeFirst, 1, 0x70000000, 142, 148, 1);
    capacityRecord(d.probeReuse, 9, 0x71000000, 151, 156, 17);
    g.magic = 0x37315854; g.version = r17tx::kVersion; g.bytes = sizeof(g);
    g.count = 32; g.bdf = d.devid; g.token = 7;
    g.retired = 10240; g.maxHeld = 16; g.historyStart = 10208; g.tPublished = 9025;
    s.magic = r18std::kMagic; s.version = r18std::kVersion; s.bytes = sizeof(s);
    s.count = 32; s.bdf = d.devid; s.token = 7;
    s.accepts = s.unmaps = s.historyTotal = 10240;
    s.maxHeld = 16; s.mode = r17tx::kModeAllStandard;
    s.historyStart = 10208; s.highReqAccepts = 10208; s.tPublished = 9025;
    b.magic = r20tx::kMagic; b.version = r20tx::kVersion; b.bytes = sizeof(b);
    b.bdf = d.devid; b.token = 7; b.nslot = 16;
    b.txNext = b.txDirty = b.txClose = b.txTail = 64;
    b.tSample = 9025; b.ringAddr = r40fixed::kIovaBase; b.ringDescSize = 16;
    b.ringBytes = 1024 * b.ringDescSize;
    b.sampleStage = r20tx::kStageExit; b.sampleSeq = 8; b.quiesced = 1;
    uint32_t nextPage = 0;
    for (uint32_t i = 0; i < 32; ++i) {
        // These are retirement records, not necessarily the last 32 request
        // IDs. All retained internal IDs exceed the userspace range 1..8192.
        // Keep internal 10208 instead of 10209 to distinguish retirement order.
        const uint32_t req = i == 0 ? 10208 : 10209 + i, pattern = (req - 1) % 16 + 1;
        const bool large = pattern == 2 || pattern == 4 || pattern == 6 || pattern == 8 || pattern == 11;
        const bool medium = pattern == 3 || pattern == 7 || pattern == 10 || pattern == 13 || pattern == 15;
        const uint32_t frame = large ? 1514 : medium ? 162 : 96;
        const uint32_t n = large ? 2 : 1;
        if (i % 16 == 0) nextPage = 0;
        const uint32_t page = nextPage;
        nextPage += n;
        // Sixteen variable-sized allocations coexist, retire, then are reused.
        const uint64_t t = 3000 + (i / 16) * 100 + i % 16;
        const uint64_t commandBase = 20419 + r34rx::kCount + 18 + (i / 16) * 32;
        auto &w = d.records[i];
        // Each history may have its own physical ring permutation. Handles
        // must perform the join; equal array indices must not be assumed.
        auto &v = g.witnesses[(i * 5) % 32];
        auto &u = s.witnesses[(i * 9) % 32];
        // r17StdMap cannot see the packet: only its handle joins to stdW.
        w.handle = req + 9; w.token = 0; w.req = 0; w.status = 3;
        w.basePage = page; w.recordIndex = i % 16;
        w.count = w.pages = n; w.maplen = large ? 8192 - 256 : frame;
        w.tMapPublish = t + 1; w.tMapInv = t + 2;
        w.tClearPublish = t + 44; w.tRetireInv = t + 46;
        w.mapCommand = {{0, (3u << 28) | d.domid, 0xfffff003u, 0x7fffffffu},
                        commandBase + i % 16, commandBase + i % 16, t + 2};
        w.retireCommand = {{0, (3u << 28) | d.domid, 0xfffff003u, 0x7fffffffu},
                           commandBase + 16 + i % 16, commandBase + 16 + i % 16, t + 46};
        auto &r = v.request;
        r.version = r17tx::kVersion; r.bytes = sizeof(r); r.bdf = d.devid;
        // r17TxMapStd fills iova/tMap, not native handle or physical. Its
        // timer passes request.handle==0 to r17TxRetire in standard mode.
        r.token = 7; r.reqId = req; r.count = n; r.handle = 0;
        r.tMap = t + 3; r.tDone = t + 42;
        v.tOwn = t + 6; v.tFree = t + 50; v.retired = 1;
        v.cumulative = 2 * req; v.firstSlot = (2 * req) % 1024;
        v.lastSlot = (v.firstSlot + n - 1) % 1024;
        v.doneClose = v.cumulative + n; v.closeMask = 0xffff;
        u.version = r18std::kVersion; u.bytes = sizeof(u);
        u.req = req; u.token = 7; u.handle = req + 9; u.segCount = n;
        u.flags = r18std::kMapped | r18std::kUnmapped;
        u.memory = 0x100000 + req * 64; u.command = 0x200000 + req * 64;
        u.mapLength = u.descriptorLength = frame; u.mbufSegments = n;
        u.tBegin = t; u.tPrepared = t + 3; u.tSegmented = t + 4;
        // r17TxPosted uses the exact tOwn stamp; the native Request carries
        // tDone, while the standard witness's tDone remains zero.
        u.tCommit = v.tOwn;
        u.tCompleteBegin = t + 43; u.tCompleteEnd = t + 47; u.tFree = t + 50;
        for (uint32_t j = 0; j < n; ++j) {
            const uint64_t off = j ? 512 : 256;
            const uint64_t pa = 0x10000000 + req * 0x10000 + j * 4096 + off;
            const uint64_t iova = base + (page + j) * 4096 + off;
            const uint64_t len = large ? (j ? frame - 96 : 96) : frame;
            w.segments[j] = {pa, len, iova};
            w.physical[j] = pa & ~4095ULL;
            w.mapPte[j] = (pa & ~4095ULL) | perm;
            r.iova[j] = {iova, len};
            v.descriptors[j] = {iova, len, 0x80000000u | (uint32_t)len, 0};
            v.doneOpts1[j] = v.descriptors[j].opts1;
            u.segments[j] = {iova, len};
        }
        u.mapAddress = u.segments[0].address;
    }
    r34rx::Snapshot rx{};
    r34rx::BackendSnapshot rb{};
    r34rx::StopRecord stop{};
    rx.version = r34rx::kVersion; rx.bytes = sizeof(rx);
    rx.state = r34rx::kReleased; rx.ringId = 0x355200;
    rx.slotCount = rx.restored = r34rx::kCount;
    rx.maps = rx.unmaps = 5 * r34rx::kCount;
    rx.posted = 4 * r34rx::kCount;
    rx.completed = 3 * r34rx::kCount; rx.stopRetired = r34rx::kCount;
    rx.replaced = 2 * r34rx::kCount;
    rx.businessToken = 7;
    rx.tInstalled = 400; rx.tDisarmed = 8800; rx.tLastRestore = 8868;
    rb.version = r34rx::kVersion; rb.bytes = sizeof(rb); rb.count = r34rx::kCount;
    rb.mapCalls = rb.mapOk = rb.unmapCalls = rb.unmapOk = rx.maps;
    rb.coverCalls = rb.coverOk = r34rx::kCount;
    rb.ready = 1; rb.tReady = 410; rb.tDrained = 8880;
    stop.version = r34rx::kStopVersion; stop.bytes = sizeof(stop);
    stop.stopCalls = stop.resetVerified = 1;
    stop.commandBefore = 0x0c; stop.interruptMaskBefore = 0xff;
    stop.rxNextBefore = 64; stop.stopRetired = stop.restored = r34rx::kCount;
    stop.tStopBegin = 8801; stop.tStopped = 8802;
    stop.tLastUnmap = 8867; stop.tLastRestore = rx.tLastRestore;
    stop.tResumeBegin = 9031; stop.tResumed = 9035;
    for (uint32_t i = 0; i < r34rx::kCount; ++i) {
        auto &bs = rb.slots[i]; auto &ds = rx.slots[i];
        bs.mapCount = bs.unmapCount = ds.mapCount = ds.unmapCount = 5;
        bs.sampleCount = ds.sampleCount = 1;
        ds.postCount = 4; ds.doneCount = 3; ds.stopRetired = 1; ds.replaceCount = 2;
        ds.originalPA = 0x80000000ULL + i * 8192;
        ds.tPhysicalOwn = 8805 + i / 16;
        for (uint32_t sample = 0; sample < 2; ++sample) {
            const bool first = sample == 0;
            auto &r = first ? bs.samples[0] : bs.last;
            auto &w = first ? ds.samples[0] : ds.last;
            r.generation = first ? 2 : 5;
            r.memory = 0xc00000 + i * 256; r.command = 0xd00000 + i * 256;
            r.pa = (first ? 0x90000000ULL : 0xa0000000ULL) + i * 0x3000 + (i % 2 ? 128 : 0);
            r.iova = r34rx::kIovaBase + i * 8192 + (r.pa & 4095);
            r.slot = i; r.mapLength = r34rx::kCapacity; r.mapOptions = 2;
            r.pages = (r.pa & 4095) ? 2 : 1;
            const uint32_t firstSlot = i < 1008 ? i / 16 * 16 : 1008 + (i - 1008) / 8 * 8;
            const uint32_t width = i < 1008 ? 16 : 8;
            const uint32_t group = i < 1008 ? i / 16 : 63 + (i - 1008) / 8;
            r.mapBatch = firstSlot | (width << 16);
            r.unmapBatch = first ? r.mapBatch : 0; // Final local-stop retirement is scalar.
            r.tMapPublish = first ? 1190 + i : 7000 + i;
            r.tMapInv = (first ? 1190 : 7000) + firstSlot + width;
            w.tPost = r.tMapInv + 1 + (i - firstSlot);
            w.tDone = first ? 1290 + i : 0;
            r.tUnmapPublish = first ? 1290 + firstSlot + width : 8803 + i / 16;
            r.tUnmapInv = r.tUnmapPublish + 1;
            const uint64_t mapSequence = first ? 1200 + 2 * group : 21700 + group;
            const uint64_t unmapSequence = first ? 1201 + 2 * group : 22000 + i;
            r.mapCommand = {{0, (3u << 28) | d.domid, 0xfffff003u, 0x7fffffffu},
                            mapSequence, mapSequence, r.tMapInv};
            r.unmapCommand = {{0, (3u << 28) | d.domid, 0xfffff003u, 0x7fffffffu},
                              unmapSequence, unmapSequence, r.tUnmapInv};
            r.flags = 7;
            for (uint32_t j = 0; j < r.pages; ++j)
                r.mapPte[j] = ((r.pa & ~4095ULL) + j * 4096) | perm;
            w.generation = r.generation; w.memory = r.memory; w.command = r.command;
            w.pa = r.pa; w.iova = r.iova; w.tMapInv = r.tMapInv; w.tUnmapInv = r.tUnmapInv;
            w.slot = i; w.flags = first ? 7 : 5 | r34rx::kWitnessStopRetired;
            w.token = first && i == 0 ? 7 : 0; w.reqId = first && i == 0 ? 1025 : 0;
            w.doneLength = first ? (i == 0 ? 78 : 1518) : 0;
            w.doneStatus = w.doneLength; w.replaced = first && i != 0;
        }
        ds.currentPA = ds.last.pa;
    }
    // Build and retire bootstrap with the production sparse helpers. Preserve
    // one active copy alongside the final current-RX physical tree.
    r34rx::PhysicalLayout physical{};
    physical.version = r34rx::kPhysicalLayoutVersion;
    physical.bytes = sizeof(physical); physical.generation = 2;
    physical.count = r34rx::kPhysicalSpanCount;
    physical.spans[0] = {0x800000, b.ringBytes};
    physical.spans[1] = {0x810000, 1024 * 16};
    physical.spans[2] = {0x820000, 64};
    amdsparse::Arena identity = {pt, ptBase, 32, 7, d.rootLevel, ptBase, 0, 0, nullptr};
    for (const auto &span : physical.spans)
        if (!amdsparse::mapOwnedRange(identity, span.pa, span.bytes)) std::abort();
    for (const auto &slot : rx.slots)
        if (!amdsparse::mapOwnedRange(identity, slot.originalPA, r34rx::kCapacity)) std::abort();
    if (identity.addedLeaves != 1033) std::abort();
    auto keepNone = [](amdsparse::u64) { return false; };
    unsigned removed = 0;
    for (const auto &span : physical.spans)
        if (!amdsparse::unmapOwnedRange(identity, span.pa, span.bytes,
                                       keepNone, removed)) std::abort();
    for (const auto &slot : rx.slots)
        if (!amdsparse::unmapOwnedRange(identity, slot.originalPA, r34rx::kCapacity,
                                       keepNone, removed)) std::abort();
    if (removed != 1033) std::abort();
    amdsparse::u64 activePt[32 * 512];
    std::memcpy(activePt, pt, sizeof(pt));
    r40fixed::DriverSnapshot fixedDriver{};
    r40fixed::BackendSnapshot fixedBackend{};
    fixedDriver.version = fixedBackend.version = r40fixed::kVersion;
    fixedDriver.bytes = sizeof(fixedDriver); fixedBackend.bytes = sizeof(fixedBackend);
    fixedDriver.count = fixedBackend.count = r40fixed::kCount;
    fixedDriver.entryCalls = fixedDriver.resetVerified = fixedBackend.entered = 1;
    fixedDriver.commandBefore = 0x0c; fixedDriver.interruptMaskBefore = 0xff;
    fixedDriver.generationBefore = physical.generation;
    fixedDriver.generationAfter = physical.generation + 1;
    fixedDriver.tStopBegin = 160; fixedDriver.tStopped = 161;
    fixedDriver.tProgrammed = 402;
    fixedDriver.tActive = fixedBackend.tEntered = 405;
    fixedBackend.mapCalls = fixedBackend.mapOk = fixedBackend.unmapCalls = fixedBackend.unmapOk = 3;
    for (uint32_t i = 0; i < r40fixed::kCount; ++i) {
        auto &w = fixedDriver.objects[i]; auto &r = fixedBackend.objects[i];
        w.memory = r.memory = 0xe00000 + i * 256;
        w.command = r.command = 0xf00000 + i * 256;
        w.pa = r.pa = physical.spans[i].pa;
        w.bytes = r.bytes = physical.spans[i].bytes;
        w.iova = r.iova = r40fixed::kIovaBase + i * r40fixed::kStride + (r.pa & 4095);
        w.registerBefore = w.registerPhysical = r.pa;
        w.registerActive = r.iova; w.kind = r.kind = i;
        w.mapOptions = r.mapOptions = i == r40fixed::kTally ? 2 : 3;
        w.mapCount = w.unmapCount = r.mapCalls = r.unmapCalls = 1;
        r.pages = ((r.pa & 4095) + r.bytes + 4095) / 4096; r.flags = 7;
        r.tMapPublish = 162 + 2 * i; r.tMapInv = r.tMapPublish + 1;
        w.tMapReady = r.tMapInv + 1;
        r.tUnmapPublish = 8871 + 2 * i; r.tUnmapInv = r.tUnmapPublish + 1;
        w.tUnmapReady = r.tUnmapInv + 1;
        const uint64_t mapSequence = 19 + i, unmapSequence = 23030 + i;
        r.mapCommand = {{0, (3u << 28) | d.domid, 0xfffff003u, 0x7fffffffu},
                        mapSequence, mapSequence, r.tMapInv};
        r.unmapCommand = {{0, (3u << 28) | d.domid, 0xfffff003u, 0x7fffffffu},
                          unmapSequence, unmapSequence, r.tUnmapInv};
        for (uint32_t j = 0; j < r.pages; ++j) {
            r.mapPte[j] = ((r.pa & ~4095ULL) + j * 4096) | perm;
            activePt[2 * 512 + 256 + i * 16 + j] = r.mapPte[j];
        }
    }
    // Earlier slots may already be on an unretained intermediate generation.
    // Active IOVAs need not equal the final retained first/last PA samples.
    for (uint32_t i = 0; i < r34rx::kCount; ++i) {
        const auto &w = rb.slots[i].samples[0];
        const uint64_t pa = w.tUnmapInv < 2241 ?
            0xb0000000ULL + i * 0x3000 + (w.pa & 4095) : w.pa;
        for (uint32_t j = 0; j < w.pages; ++j)
            activePt[(3 + i / 256) * 512 + (i % 256) * 2 + j] =
                ((pa & ~4095ULL) + j * 4096) | perm;
    }
    // One contemporaneous TX IOVA: the device only reads TX buffers, so the
    // standard TX path maps it read-only and the leaf carries IR without IW.
    activePt[2 * 512] = 0x70000000ULL | (perm & ~(1ULL << 62));
    r17domain::Command retire = {{0, (3u << 28) | d.domid, 0xfffff003u, 0x7fffffffu},
                                20000, 20000, 2242};
    identity.addedLeaves = 0;
    for (const auto &slot : rx.slots)
        if (!amdsparse::mapOwnedRange(identity, slot.currentPA, r34rx::kCapacity)) std::abort();
    if (identity.addedLeaves != 1536) std::abort();
    // Shift timestamp fields only; ABI, addresses, counters and protocol stay
    // identical. Both snapshots and real client logs include the idle gap.
#define SESSION_TIME(field) field = sessionTime(field)
    SESSION_TIME(g.tPublished); SESSION_TIME(s.tPublished); SESSION_TIME(b.tSample);
    for (auto &r : d.records) {
        SESSION_TIME(r.tMapPublish); SESSION_TIME(r.tMapInv);
        SESSION_TIME(r.tClearPublish); SESSION_TIME(r.tRetireInv);
        SESSION_TIME(r.mapCommand.tComplete); SESSION_TIME(r.retireCommand.tComplete);
    }
    for (auto &w : g.witnesses) {
        SESSION_TIME(w.request.tMap); SESSION_TIME(w.request.tDone);
        SESSION_TIME(w.tOwn); SESSION_TIME(w.tFree);
    }
    for (auto &w : s.witnesses) {
        SESSION_TIME(w.tBegin); SESSION_TIME(w.tPrepared); SESSION_TIME(w.tSegmented);
        SESSION_TIME(w.tCommit); SESSION_TIME(w.tDone); SESSION_TIME(w.tCompleteBegin);
        SESSION_TIME(w.tCompleteEnd); SESSION_TIME(w.tFree);
    }
    SESSION_TIME(rx.tInstalled); SESSION_TIME(rx.tDisarmed); SESSION_TIME(rx.tLastRestore);
    SESSION_TIME(rb.tReady); SESSION_TIME(rb.tDrained);
    SESSION_TIME(stop.tStopBegin); SESSION_TIME(stop.tStopped);
    SESSION_TIME(stop.tLastUnmap); SESSION_TIME(stop.tLastRestore);
    SESSION_TIME(stop.tResumeBegin); SESSION_TIME(stop.tResumed);
    SESSION_TIME(fixedDriver.tStopBegin); SESSION_TIME(fixedDriver.tStopped);
    SESSION_TIME(fixedDriver.tProgrammed); SESSION_TIME(fixedDriver.tActive);
    SESSION_TIME(fixedBackend.tEntered);
    for (uint32_t i = 0; i < r40fixed::kCount; ++i) {
        auto &w = fixedDriver.objects[i]; auto &r = fixedBackend.objects[i];
        SESSION_TIME(w.tMapReady); SESSION_TIME(w.tUnmapReady);
        SESSION_TIME(r.tMapPublish); SESSION_TIME(r.tMapInv);
        SESSION_TIME(r.tUnmapPublish); SESSION_TIME(r.tUnmapInv);
        SESSION_TIME(r.mapCommand.tComplete); SESSION_TIME(r.unmapCommand.tComplete);
    }
    SESSION_TIME(retire.tComplete);
    for (uint32_t i = 0; i < r34rx::kCount; ++i) {
        auto &ds = rx.slots[i]; auto &bs = rb.slots[i];
        SESSION_TIME(ds.tPhysicalOwn);
        for (uint32_t sample = 0; sample < 2; ++sample) {
            auto &w = sample ? ds.last : ds.samples[0];
            auto &r = sample ? bs.last : bs.samples[0];
            SESSION_TIME(w.tMapInv); SESSION_TIME(w.tPost);
            SESSION_TIME(w.tDone); SESSION_TIME(w.tUnmapInv);
            SESSION_TIME(r.tMapPublish); SESSION_TIME(r.tMapInv);
            SESSION_TIME(r.tUnmapPublish); SESSION_TIME(r.tUnmapInv);
            SESSION_TIME(r.mapCommand.tComplete); SESSION_TIME(r.unmapCommand.tComplete);
        }
    }
#undef SESSION_TIME
    if (damage == "unrestored") rx.slots[r34rx::kCount - 1].tPhysicalOwn = 0;
    save(dir, "r34-rx-driver.bin", &rx, sizeof(rx));
    save(dir, "r34-rx-backend.bin", &rb, sizeof(rb));
    save(dir, "r39-rx-stop.bin", &stop, sizeof(stop));
    save(dir, "r40-fixed-driver.bin", &fixedDriver, sizeof(fixedDriver));
    save(dir, "r40-fixed-backend.bin", &fixedBackend, sizeof(fixedBackend));
    save(dir, "r37-physical-layout.bin", &physical, sizeof(physical));
    save(dir, "r38-active-pt-raw.bin", activePt, sizeof(activePt));
    save(dir, "r38-bootstrap-retire-command.bin", &retire, sizeof(retire));
    save(dir, "r21-domain-raw.bin", &d, sizeof(d));
    save(dir, "r21-driver-raw.bin", &g, sizeof(g));
    save(dir, "r21-std-raw.bin", &s, sizeof(s));
    save(dir, "r21-block-raw.bin", &b, sizeof(b));
    save(dir, "r21-pt-raw.bin", pt, sizeof(pt));
}
'''


def properties():
    p = {'m2-3c-mode': 'standard-iomapper', 'm2-3g-mode': 'all-standard',
         'm2-3l-session-mode': 'explicit-stop', 'm2-3l-session-state': 'stopped',
         'm2-3l-session-start': 420, 'm2-3l-stop-request-time': session_time(8751),
         'm2-3l-session-end': session_time(9060),
         'm2-3n-domain-mode': 'service-owned', 'm2-3n-domain-state': 'stopped',
         'm2-3n-setup-worker-active': 0, 'm2-3n-setup-worker-exit-time': 430,
         'm2-3n-root-pa': 0x100000, 'm2-3n-dt-pa': 0x200000,
         'm2-3n-command-pa': 0x300000, 'm2-3n-install-count': 1,
         'm2-3n-teardown-start': session_time(8760),
         'm2-3n-teardown-end': session_time(9055),
         'm2-3l-tx-deadline': 0,
         'm2-3h-rx-mode': 'native-ring-batch16', 'm2-3o-rx-ready-time': 410,
         'm2-3p-rx-source': 'lucy-normal-ring', 'm2-3p-rx-bootstrap-ranges': 1024,
         'm2-3p-rx-ring-generation': 2,
         'm2-3p-rx-pool-rpcs': 0, 'm2-3p-rx-spares': 0, 'm2-3p-rx-ring-id': 0x355200,
         'm2-3p-rx-physical-resume': 'done',
         'm2-3r-physical-mode': 'owned-sparse-4k', 'm2-3r-bootstrap-pages': 1033,
         'm2-3r-restore-added-pages': 1536, 'm2-3r-identity-pages': 1536,
         'm2-3s-rx-bootstrap-retired': 'yes', 'm2-3s-fixed-pages': 9,
         'm2-3s-bootstrap-removed-pages': 1033,
         'm2-3s-bootstrap-clear-time': session_time(2241),
         'm2-3s-bootstrap-retire-time': session_time(2242),
         'm2-3q-rx-map-invalidations': 1284, 'm2-3q-rx-unmap-invalidations': 1284,
         'm2-3q-rx-map-batch-calls': 260, 'm2-3q-rx-unmap-batch-calls': 260,
         'm2-3q-rx-map-batch-slots': 4096, 'm2-3q-rx-unmap-batch-slots': 4096,
         'm2-3q-rx-max-batch': 16,
         'm2-3h-rx-state': 'drained-and-unmapped', 'm2-3h-rx-ready': 'no',
         'm2-b2-t-recovery-start': 8883, 'm2-3h-rx-pending': 0, 'm2-3h-rx-live-owners': 0,
         'm2-3h-rx-stop-retired': 1024, 'm2-3i-exit-retire-confirmed-time': 8792,
         'm2-3i-exit-driver-live': 0, 'm2-3i-exit-driver-held': 0,
         'm2-3i-exit-driver-mapped': 10240, 'm2-3i-exit-driver-retired': 10240,
         'm2-3b-slots-live': 0}
    for key in ('m2-3c-map-calls', 'm2-3c-map-ok', 'm2-3c-unmap-ok',
                'm2-3b-map-accepted', 'm2-3b-retires'):
        p[key] = 10249
    for key in ('m2-3c-insert-calls', 'm2-3c-map-rejects', 'm2-3b-map-rejected',
                'm2-3c-cover-calls', 'm2-3b-owners-held', 'm2-b2-win-entries', 'm2-b2-win-new-entries',
                'm2-b2-win-raw-count', 'm2-b2-win-pre-backlog',
                'm2-b2-win-devid-mismatch', 'm2-3c-cover-unconf',
                'm2-b2-win-head-start', 'm2-b2-win-tail-start',
                'm2-b2-win-head-end', 'm2-b2-win-tail-end',
                'm2-3e-enter-last-inflight', 'm2-3e-enter-last-ring',
                'm2-3e-exit-last-inflight', 'm2-3e-exit-last-ring'):
        p[key] = 0
    command_total = 2 * 10249 + 2 * 1284 + 4 + 2 * 3
    p.update({'m2-3b-command-capacity': 512, 'm2-3b-submits': command_total,
              'm2-3b-command-completed': command_total, 'm2-3b-command-wraps': command_total * 2 // 512,
              'm2-3b-command-post-wrap-completed': command_total - 255,
              'm2-3b-completion-sequence': command_total,
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
    p.update(zip(enter, (100, 110, 120, 130, 140, 406)))
    p.update(zip(leave, (8770, 8780, 8790, 9030, 9040, 9050)))
    for key in enter + leave + ('m2-b2-t-recovery-start',
                                'm2-3i-exit-retire-confirmed-time'):
        p[key] = session_time(p[key])
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
    steps, offset = itertools.count(), [0]

    def clock():
        return 1000 + next(steps) // 8 + offset[0]

    def sleep(seconds):
        offset[0] += round(seconds * 1e9)

    active = load.session.parse_status(properties())
    active.update({'session-state': 'active', 'domain-state': 'active'})
    with patch.object(load, 'now', side_effect=clock), \
         patch.object(load.time, 'sleep', side_effect=sleep), \
         patch.object(load.session, 'status', return_value=active):
        assert load.exchange(s, '127.0.0.1', PEER, TOKEN, client_lines.append, seq,
                             persistent_session=True) == 0
    with patch.object(load, 'now', side_effect=[session_time(8750), session_time(8752)]), \
         patch.object(load.session, 'stop') as stop:
        load.request_session_stop(client_lines.append)
        stop.assert_called_once_with()
    client_lines.append('client_session_stopped t_ns=%d' % session_time(9090))
    client_lines.append('client_stop_end stopped_ns=%d' % session_time(9090))
    client_lines.append('client_after_exit resumed=1 t_ns=%d' % session_time(9100))
    with patch.object(load, 'now', side_effect=itertools.count(session_time(9100))):
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
                        '-I', str(ROOT / 'kext'),
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
            '"R26TxMapped" = 10240\n"R26TxUnmarked" = 10240\n'
            '"R26TxLegacySelected" = 0\n"R26TxAttempts" = 10244\n'
            '"rtl812x-txmap-cover-calls" = 0\n'
            '"rtl812x-r35-rx-source" = "lucy-normal-ring"\n'
            '"rtl812x-r35-rx-experimental-pool" = 0\n'
            '"rtl812x-r35-rx-spares" = 0\n'
            '"rtl812x-r35-rx-ring-id" = 0x355200\n'
            '"rtl812x-r38-rx-first-iova-slots" = 1024\n'
            f'"rtl812x-r38-rx-last-first-iova-time" = {session_time(2222)}\n'
            '"rtl812x-r38-rx-bootstrap-retired" = 1\n'
            f'"rtl812x-r38-rx-bootstrap-retire-time" = {session_time(2243)}\n'
            f'"rtl812x-r35-rx-resume-time" = {session_time(9035)}\n')

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

    def test_rx1024_full_lifecycle_with_actual_headers_and_real_logs(self):
        self.assertEqual((self.capture / 'r21-domain-raw.bin').stat().st_size, analyzer.DOMAIN_BYTES)
        self.assertEqual((self.capture / 'r21-driver-raw.bin').stat().st_size, analyzer.DRIVER_BYTES)
        self.assertEqual((self.capture / 'r21-std-raw.bin').stat().st_size, analyzer.STD_BYTES)
        self.assertEqual(protocol.MAGIC, b'R27P')
        self.assertNotIn(protocol.payload(TOKEN, 1)[:4], (b'IOB1', b'1BOI'))
        report = self.expect(True)
        self.assertEqual(len(report['checks']), 14)
        by_id = {c['id']: c.get('detail') for c in report['checks']}
        lifecycle = by_id[SESSION_CHECK]
        self.assertEqual((lifecycle['mode'], lifecycle['activeObservations'],
                          lifecycle['domainInstalls']), ('service-owned', 2, 1))
        self.assertEqual((lifecycle['setupWorkerExited'], lifecycle['rootPA'],
                          lifecycle['deviceTablePA'], lifecycle['commandPA']),
                         (430, 0x100000, 0x200000, 0x300000))
        self.assertEqual(by_id[COUNTER_CHECK]['mode'], 2)
        self.assertEqual((by_id[COUNTER_CHECK]['Mapped'], by_id[COUNTER_CHECK]['Unmarked']), (10240, 10240))
        self.assertEqual((by_id[CMD_CHECK]['commandCapacity'], by_id[CMD_CHECK]['commandRingBytes']), (512, 8192))
        history = by_id[HISTORY_CHECK]
        self.assertEqual((history['historyTotal'], history['historyStart'], history['retained']), (10240, 10208, 32))
        self.assertTrue(all(req > 8192 for req in history['internalRequests']))
        self.assertEqual(history['nativeHandles'], [0])
        self.assertEqual(history['peakRetainedLive'], 16)
        self.assertEqual(history['domainHistoryTotal'], 10249)
        self.assertEqual(by_id[COUNTER_CHECK]['capacityProbeMaps'], 9)
        allocation = by_id[ALLOCATION_CHECK]
        self.assertEqual((allocation['probeMaps'], allocation['probeUnmaps']), (9, 9))
        self.assertEqual((allocation['probePeakOwners'], allocation['probePages']), (8, 8))
        self.assertEqual(allocation['firstBasePage'], allocation['reusedBasePage'])
        self.assertEqual((allocation['arenaPages'], allocation['recordCapacity'], allocation['livePages']),
                         (256, 16, 0))
        self.assertEqual(by_id['ordinary-traffic-before-during-and-three-after'],
                         {'before': 20, 'during': 1024, 'after': 3})
        self.assertEqual((self.capture / 'r34-rx-driver.bin').stat().st_size, analyzer.RX_DRIVER_BYTES)
        self.assertEqual((self.capture / 'r34-rx-backend.bin').stat().st_size, analyzer.RX_BACKEND_BYTES)
        self.assertEqual(by_id[RX_MAP_CHECK]['mapped'], 5120)
        self.assertEqual(by_id[RX_MAP_CHECK]['unmapped'], 5120)
        self.assertEqual((by_id[RX_MAP_CHECK]['mapBatchCalls'],
                          by_id[RX_MAP_CHECK]['unmapBatchCalls'],
                          by_id[RX_MAP_CHECK]['maxBatch']), (260, 260, 16))
        self.assertEqual(by_id[RX_MAP_CHECK]['invalidationCyclesSaved'], 7672)
        self.assertEqual(by_id[RX_MAP_CHECK]['writablePages'], 1536)
        self.assertEqual(by_id[RX_MAP_CHECK]['leafTables'], 4)
        self.assertEqual((self.capture / 'r37-physical-layout.bin').stat().st_size,
                         analyzer.PHYSICAL_LAYOUT_BYTES)
        self.assertEqual((by_id[RX_MAP_CHECK]['physicalMode'],
                          by_id[RX_MAP_CHECK]['physicalLayoutGeneration']), ('owned-sparse-4k', 2))
        self.assertEqual((by_id[RX_MAP_CHECK]['fixedPhysicalPages'],
                          by_id[RX_MAP_CHECK]['bootstrapPages'],
                          by_id[RX_MAP_CHECK]['restoreAddedPages'],
                          by_id[RX_MAP_CHECK]['identityPages']), (9, 1033, 1536, 1536))
        self.assertEqual((by_id[RX_MAP_CHECK]['bootstrapRemovedPages'],
                          by_id[RX_MAP_CHECK]['activeIdentityPages'],
                          by_id[RX_MAP_CHECK]['activeRxIovaPages']), (1033, 0, 1536))
        self.assertEqual(by_id[RX_MAP_CHECK]['bootstrapRetireCommand']['expected'], 20000)
        self.assertEqual(by_id[RX_MAP_CHECK]['bootstrapDriverDone'], session_time(2243))
        self.assertEqual(by_id[RX_MAP_CHECK]['identityBytes'], 1536 * 4096)
        fixed = by_id[RX_MAP_CHECK]['fixedDMA']
        self.assertEqual((fixed['mapped'], fixed['unmapped'], fixed['liveOwners'],
                          fixed['boundPairs'], fixed['iovaPages']), (3, 3, 0, 0, 9))
        self.assertEqual((fixed['generationBefore'], fixed['generationAfter']), (2, 3))
        self.assertEqual([obj['registerActive'] for obj in fixed['objects']],
                         [analyzer.FIXED_BASE + i * analyzer.FIXED_STRIDE for i in range(3)])
        self.assertTrue(all(obj['registerPhysical'] == obj['pa'] for obj in fixed['objects']))
        self.assertEqual((self.capture / 'r40-fixed-driver.bin').stat().st_size, analyzer.FIXED_DRIVER_BYTES)
        self.assertEqual((self.capture / 'r40-fixed-backend.bin').stat().st_size, analyzer.FIXED_BACKEND_BYTES)
        self.assertEqual((by_id[RX_MAP_CHECK]['source'], by_id[RX_MAP_CHECK]['ringId'],
                          by_id[RX_MAP_CHECK]['experimentalPoolRPCs'],
                          by_id[RX_MAP_CHECK]['experimentalSpares']),
                         ('lucy-normal-ring', 0x355200, 0, 0))
        self.assertEqual(by_id[RX_DONE_CHECK]['sampledCompletions'], 1024)
        self.assertEqual((by_id[RX_DONE_CHECK]['posted'], by_id[RX_DONE_CHECK]['completed'],
                          by_id[RX_DONE_CHECK]['stopRetired']), (4096, 3072, 1024))
        self.assertEqual((self.capture / 'r39-rx-stop.bin').stat().st_size, analyzer.STOP_BYTES)
        self.assertEqual((by_id[STOP_CHECK]['stopCalls'], by_id[STOP_CHECK]['resetVerified'],
                          by_id[STOP_CHECK]['stopRetired']), (1, 1, 1024))
        self.assertEqual((by_id[AUTONOMOUS_CHECK]['peerTailPackets'],
                          by_id[AUTONOMOUS_CHECK]['clientSendsDuringStop'],
                          by_id[AUTONOMOUS_CHECK]['ordinaryAfterExit']), (0, 0, 3))
        self.assertEqual(by_id[RX_DONE_CHECK]['restored'], 1024)
        self.assertEqual(by_id[RX_DONE_CHECK]['firstLastPADifferentSlots'], 1024)
        self.assertEqual(by_id[RX_DONE_CHECK]['applicationRequests'], [1025])
        self.assertEqual(by_id[SESSION_CHECK]['stopRequests'], 1)
        self.assertEqual(by_id[SESSION_CHECK]['requestsPerPhase'], 4096)
        self.assertGreaterEqual(by_id[SESSION_CHECK]['idleSeconds'], 125)
        self.assertGreater(by_id[SESSION_CHECK]['secondPhaseAfterSeconds'], 120)
        # Scoped decoding must leave the historical module's ABI unchanged.
        self.assertEqual((legacy.STD_VERSION, legacy.DRIVER_VERSION), (3, 4))

    def test_corrupted_rx_command_evidence_is_rejected(self):
        path = self.capture / 'r34-rx-backend.bin'
        baseline = path.read_bytes()
        # Both directions: each word (including PDE), missing/mismatched CW,
        # zero/reversed/out-of-range/shared IDs and timestamp substitution.
        for command in (144, 184):
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
                    analyzer.struct.pack_into('<' + fmt, blob, 96 + command + offset, value)
                    path.write_bytes(blob)
                    self.expect(False, RX_MAP_CHECK)
        domain, records = analyzer.decode_domain((self.capture / 'r21-domain-raw.bin').read_bytes())
        first_unmap = analyzer.struct.unpack_from('<Q', baseline, 96 + 184 + 16)[0]
        for command, sequence in ((144, first_unmap), (184, domain['completionSequence'] + 1),
                                  (144, records[0]['mapCommand']['expected']),
                                  (184, first_unmap + 1)):
            with self.subTest(command=command, sequence=sequence):
                blob = bytearray(baseline)
                analyzer.struct.pack_into('<2Q', blob, 96 + command + 16, sequence, sequence)
                path.write_bytes(blob)
                self.expect(False, RX_MAP_CHECK)

    def test_unmaps_must_complete_before_recovery(self):
        path = self.capture / 'props.txt'
        path.write_text(re.sub(r'("m2-b2-t-recovery-start" = )"[^"]+"', r'\1"0x22c4"', path.read_text()))
        self.expect(False, RX_MAP_CHECK)

    def test_cyclic_identity_counts_flags_and_order_corruption(self):
        path = self.capture / 'r34-rx-driver.bin'
        baseline = path.read_bytes()
        slot = analyzer.RX_DRIVER_HEADER
        first = slot + analyzer.RX_DRIVER_SLOT_BYTES - 2 * analyzer.RX_WITNESS_BYTES
        for offset, fmt, value in ((slot + 16, 'Q', 1), (slot + 32, 'I', 5),
                                   (slot + 36, 'I', 4), (slot + 44, 'I', 2),
                                   (slot + 48, 'I', 1), (first, 'Q', 1),
                                   (first + 48, 'Q', 1), (first + 56, 'Q', 1),
                                   (first + 76, 'I', 3), (first + 80, 'I', 8),
                                   (first + 84, 'I', 8193), (first + 96, 'I', 2)):
            with self.subTest(offset=offset):
                blob = bytearray(baseline)
                analyzer.struct.pack_into('<' + fmt, blob, offset, value)
                path.write_bytes(blob)
                self.expect(False)
        for offset, value in ((20, 256), (32, 64), (36, 64), (44, 1023)):
            with self.subTest(header=offset):
                blob = bytearray(baseline)
                analyzer.struct.pack_into('<I', blob, offset, value)
                path.write_bytes(blob)
                self.expect(False, RX_DONE_CHECK)

    def test_missing_or_corrupt_local_stop(self):
        path = self.capture / 'client.log'
        baseline = path.read_text()
        path.write_text(baseline.replace('client_stop_end ', 'missing_stop_end '))
        self.expect(False, AUTONOMOUS_CHECK)
        path.write_text(baseline)
        path = self.capture / 'r39-rx-stop.bin'
        blob = bytearray(path.read_bytes())
        analyzer.struct.pack_into('<I', blob, 20, 0x0c)
        path.write_bytes(blob)
        self.expect(False, STOP_CHECK)

    def test_missing_rx_restoration_witness_is_rejected(self):
        subprocess.run([str(self.exe), str(self.capture), 'unrestored'], check=True)
        report = self.expect(False, RX_DONE_CHECK)
        by_id = {c['id']: c['state'] for c in report['checks']}
        self.assertEqual(by_id[RX_MAP_CHECK], 'ok')


if __name__ == '__main__':
    unittest.main(verbosity=2)
