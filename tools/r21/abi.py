#!/usr/bin/env python3
"""Ask the C++ headers for the ABI numbers instead of retyping them.

Every round of this project has hard-coded at least one struct size or offset in
Python (Block bytes, Slot stride, Configure size, witness stride). When the C++
and the Python disagreed, the disagreement was invisible: the archive validated
its own constants against a blob it had extracted with those same constants, and
the analyzer did the same. Round 21 lost three hardware runs to exactly that,
first as "block blob: bad size", then as "unknown driver export ABI".

This script compiles a tiny program against the real headers and prints the
numbers as JSON. The callers import `abi()` and use it instead of literals; a
test then asserts the literals still match, so a header change fails the build
rather than the machine.

Usage:
    python3 tools/r21/abi.py            # print JSON
    python3 tools/r21/abi.py --check    # check current round25/26 decoder/header agreement
"""
import json
import os
import pathlib
import runpy
import shlex
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]

PROBE = r'''
#include <cstddef>
#include <cstdio>
/* These headers are written for the kernel: they expect IOReturn/IOService to
 * exist. The probe only needs the layouts, so provide the smallest possible
 * stand-ins rather than dragging in IOKit. */
using IOReturn = int;
struct IOService;
#include "RTL812xTxMapNative.hpp"
#include "RTL812xTxMapStd.hpp"
#include "AMDAliveTxDomainNative.hpp"
#include "RTL812xRxMap.hpp"
#include "RTL812xRxPool.hpp"
#include "RTL812xRxNative.hpp"
int main() {
    std::printf("{\n");
    std::printf("  \"domain_version\": %u,\n", r17domain::kVersion);
    std::printf("  \"domain_bytes\": %zu,\n", sizeof(r17domain::Snapshot));
    std::printf("  \"domain_record_bytes\": %zu,\n", sizeof(r17domain::Record));
    std::printf("  \"domain_records_offset\": %zu,\n", offsetof(r17domain::Snapshot, records));
    std::printf("  \"domain_tail_offset\": %zu,\n", offsetof(r17domain::Snapshot, historyTotal));
    std::printf("  \"domain_sequence_offset\": %zu,\n", offsetof(r17domain::Snapshot, completionSequence));
    std::printf("  \"domain_record_segments\": %zu,\n", sizeof(r17domain::Record{}.segments) / sizeof(r17domain::Segment));
    std::printf("  \"domain_record_pages\": %zu,\n", sizeof(r17domain::Record{}.physical) / sizeof(uint64_t));
    std::printf("  \"domain_record_basepage_offset\": %zu,\n", offsetof(r17domain::Record, basePage));
    std::printf("  \"domain_record_pte_offset\": %zu,\n", offsetof(r17domain::Record, mapPte));
    std::printf("  \"domain_allocator_offset\": %zu,\n", offsetof(r17domain::Snapshot, livePages));
    std::printf("  \"domain_probe_offset\": %zu,\n", offsetof(r17domain::Snapshot, probeFirst));
    std::printf("  \"native_history_start_offset\": %zu,\n", offsetof(r17tx::Snapshot, historyStart));
    std::printf("  \"std_history_total_offset\": %zu,\n", offsetof(r18std::Snapshot, historyTotal));
    std::printf("  \"request_limit\": %u, \"history_capacity\": %u, \"mapping_slots\": %u,\n", r17tx::kRequestLimit, r17tx::kMaxRequests, r17tx::kSlots);
    std::printf("  \"configure_bytes\": %zu,\n", sizeof(r17tx::Configure));
    std::printf("  \"request_bytes\": %zu,\n", sizeof(r17tx::Request));
    std::printf("  \"native_version\": %u,\n", (unsigned)r17tx::kVersion);
    std::printf("  \"retire_ack_op\": %u,\n", (unsigned)r17tx::kRetireAck);
    std::printf("  \"rx_version\": %u, \"rx_snapshot_bytes\": %zu, \"rx_request_bytes\": %zu,\n",
                r27rx::kVersion, sizeof(r27rx::Snapshot), sizeof(r27rx::Request));
    std::printf("  \"rx_tail_seq_offset\": %zu,\n", offsetof(r27rx::Snapshot, tailSeq));
    std::printf("  \"rx_count\": %u, \"rx_backend_bytes\": %zu,\n",
                r27rx::kCount, sizeof(r27rx::BackendSnapshot));
    std::printf("  \"rx_native_version\": %u, \"rx_native_count\": %u,\n",
                r34rx::kVersion, r34rx::kCount);
    std::printf("  \"rx_native_driver_bytes\": %zu, \"rx_native_backend_bytes\": %zu,\n",
                sizeof(r34rx::Snapshot), sizeof(r34rx::BackendSnapshot));
    std::printf("  \"rx_native_driver_header\": %zu, \"rx_native_driver_slot_bytes\": %zu,\n",
                offsetof(r34rx::Snapshot, slots), sizeof(r34rx::DriverSlot));
    std::printf("  \"rx_native_backend_header\": %zu, \"rx_native_backend_slot_bytes\": %zu,\n",
                offsetof(r34rx::BackendSnapshot, slots), sizeof(r34rx::BackendSlot));
    std::printf("  \"rx_native_witness_bytes\": %zu, \"rx_native_map_record_bytes\": %zu,\n",
                sizeof(r34rx::Witness), sizeof(r34rx::MapRecord));
    std::printf("  \"pool_version\": %u, \"pool_spares\": %u,\n",
                r15pool::kVersion, r15pool::kSpareCount);
    std::printf("  \"pool_snapshot_bytes\": %zu, \"pool_request_bytes\": %zu,\n",
                sizeof(r15pool::Snapshot), sizeof(r15pool::Request));
    std::printf("  \"kInstall\": %d, \"kDisarm\": %d, \"kQuery\": %d,\n",
                (int)r17tx::kInstall, (int)r17tx::kDisarm, (int)r17tx::kQuery);
    std::printf("  \"kDetach\": %d, \"kQuiesce\": %d, \"kResume\": %d,\n",
                (int)r17tx::kDetach, (int)r17tx::kQuiesce, (int)r17tx::kResume);
    std::printf("  \"kSample\": %d,\n", (int)r17tx::kSample);
    std::printf("  \"configure_off_deadline\": %zu,\n",
                offsetof(r17tx::Configure, deadline));
    std::printf("  \"configure_off_callback\": %zu,\n",
                offsetof(r17tx::Configure, callback));
    std::printf("  \"configure_off_mapper\": %zu,\n",
                offsetof(r17tx::Configure, mapper));
    std::printf("  \"configure_off_quiesced\": %zu,\n",
                offsetof(r17tx::Configure, quiesced));
    /* Round22 window barrier. These are what the enter/exit order is checked
     * against, so a silent layout change here would invalidate the evidence
     * rather than the build. */
    std::printf("  \"configure_off_inFlight\": %zu,\n",
                offsetof(r17tx::Configure, inFlight));
    std::printf("  \"configure_off_ringOwn\": %zu,\n",
                offsetof(r17tx::Configure, ringOwn));
    std::printf("  \"configure_off_edgeSeq\": %zu,\n",
                offsetof(r17tx::Configure, edgeSeq));
    std::printf("  \"configure_off_barrierFails\": %zu,\n",
                offsetof(r17tx::Configure, barrierFails));
    std::printf("  \"configure_off_tEdge\": %zu,\n",
                offsetof(r17tx::Configure, tEdge));
    std::printf("  \"configure_off_tSubmitDone\": %zu,\n",
                offsetof(r17tx::Configure, tSubmitDone));
    std::printf("  \"configure_off_tDrainDone\": %zu,\n",
                offsetof(r17tx::Configure, tDrainDone));
    std::printf("  \"configure_off_tResume\": %zu,\n",
                offsetof(r17tx::Configure, tResume));
    std::printf("  \"kMap\": %d, \"kRetire\": %d, \"kCover\": %d,\n",
                (int)r17tx::kMap, (int)r17tx::kRetire, (int)r17tx::kCover);
    std::printf("  \"std_version\": %u,\n", (unsigned)r18std::kVersion);
    std::printf("  \"std_segments\": %u,\n", (unsigned)r18std::kSegments);
    std::printf("  \"std_witness_bytes\": %zu,\n", sizeof(r18std::Witness));
    std::printf("  \"std_header_bytes\": %u,\n", (unsigned)r18std::kHeaderBytes);
    std::printf("  \"block_version\": %u,\n", (unsigned)r20tx::kVersion);
    std::printf("  \"block_bytes\": %zu,\n", sizeof(r20tx::Block));
    std::printf("  \"slot_bytes\": %zu,\n", sizeof(r20tx::Slot));
    std::printf("  \"block_slots\": %u,\n", (unsigned)r20tx::kSlots);
    std::printf("  \"block_outstanding\": %u,\n", (unsigned)r20tx::kOutstanding);
    std::printf("  \"off_tSample\": %zu,\n", offsetof(r20tx::Block, tSample));
    std::printf("  \"off_ringAddr\": %zu,\n", offsetof(r20tx::Block, ringAddr));
    std::printf("  \"off_sampleStage\": %zu,\n", offsetof(r20tx::Block, sampleStage));
    std::printf("  \"off_slots\": %zu,\n", offsetof(r20tx::Block, slots));
    std::printf("  \"off_outAddr\": %zu,\n", offsetof(r20tx::Block, outAddr));
    std::printf("  \"off_outOpts1\": %zu,\n", offsetof(r20tx::Block, outOpts1));
    std::printf("  \"kStageThrottled\": %d, \"kStageQuiesce\": %d,\n",
                (int)r20tx::kStageThrottled, (int)r20tx::kStageQuiesce);
    std::printf("  \"kStageDrained\": %d, \"kStageExit\": %d,\n",
                (int)r20tx::kStageDrained, (int)r20tx::kStageExit);
    std::printf("  \"kStageResumed\": %d\n", (int)r20tx::kStageResumed);
    std::printf("}\n");
    return 0;
}
'''


def abi():
    """Compile the probe against the real headers and return the numbers."""
    with tempfile.TemporaryDirectory() as tmp:
        src = pathlib.Path(tmp) / 'abi.cpp'
        src.write_text(PROBE, encoding='utf-8')
        exe = pathlib.Path(tmp) / 'abi'
        compiler = shlex.split(os.environ.get('CXX', ''))
        if not compiler:
            found = shutil.which('clang++') or shutil.which('g++')
            if not found:
                raise RuntimeError('C++ compiler required (CXX, clang++ or g++)')
            compiler = [found]
        subprocess.run(compiler + ['-std=c++17', '-Wno-enum-compare', '-I', str(ROOT / 'tools/lucy-obs'),
                        str(src), '-o', str(exe)], check=True)
        out = subprocess.check_output([str(exe)], text=True)
    return json.loads(out)


def check():
    """Check the current decoder; leave archived full-history versions alone."""
    sys.path.insert(0, str(HERE))
    import analyze as A
    want = abi()
    round26 = want['native_version'] == 6
    round29 = want['native_version'] == 7
    round32 = want['domain_version'] == 4
    decoder = (HERE.parent / 'r27/analyze.py' if round29 else
               HERE.parent / 'r26/analyze.py' if round26 else HERE / 'check-r25.py')
    current = runpy.run_path(str(decoder))
    bad = []
    pairs = [
        ('BLOCK_BYTES', want['block_bytes']),
        ('BLOCK_MAGIC', 0x30325854),
        ('BLOCK_OFF_TSAMPLE', want['off_tSample']),
        ('BLOCK_OFF_RINGADDR', want['off_ringAddr']),
        ('BLOCK_OFF_SAMPLESTAGE', want['off_sampleStage']),
        ('BLOCK_OFF_SLOTS', want['off_slots']),
        ('BLOCK_OFF_OUTADDR', want['off_outAddr']),
        ('BLOCK_OFF_OUTOPTS1', want['off_outOpts1']),
        ('BLOCK_STAGE_EXIT', want['kStageExit']),
        ('STD_SEGMENTS', want['std_segments']),
        ('STD_HEADER', want['std_header_bytes']),
        ('STD_RECORD_BYTES', want['std_witness_bytes']),
        ('STD_MAGIC', 0x38315854),
    ]
    for name, expect in pairs:
        got = getattr(A, name, None)
        if got != expect:
            bad.append('%s: analyze.py=%r headers=%r' % (name, got, expect))
    current_pairs = [
        ('DOMAIN_VERSION', want['domain_version']),
        ('DOMAIN_BYTES', want['domain_bytes']),
        ('DOMAIN_HEADER', want['domain_records_offset']),
        ('DOMAIN_RECORD_BYTES', want['domain_record_bytes']),
        ('DRIVER_VERSION', want['native_version']),
        ('STD_VERSION', want['std_version']),
        ('HISTORY_CAPACITY', want['history_capacity']),
    ]
    if round29:
        current_pairs += [('RX_VERSION', want['rx_native_version']),
                          ('RX_COUNT', want['rx_native_count']),
                          ('RX_DRIVER_BYTES', want['rx_native_driver_bytes']),
                          ('RX_BACKEND_BYTES', want['rx_native_backend_bytes']),
                          ('RX_DRIVER_HEADER', want['rx_native_driver_header']),
                          ('RX_DRIVER_SLOT_BYTES', want['rx_native_driver_slot_bytes']),
                          ('RX_BACKEND_HEADER', want['rx_native_backend_header']),
                          ('RX_BACKEND_SLOT_BYTES', want['rx_native_backend_slot_bytes']),
                          ('RX_WITNESS_BYTES', want['rx_native_witness_bytes']),
                          ('RX_MAP_RECORD_BYTES', want['rx_native_map_record_bytes'])]
    for name, expect in current_pairs:
        if current.get(name) != expect:
            bad.append('%s: %s=%r headers=%r' %
                       (name, decoder.name, current.get(name), expect))
    # Round22: the Configure layout is pinned HERE as well as in the header's
    # static_asserts. The header assert catches a layout change at compile time;
    # this list catches the other direction -- a deliberate ABI bump that left
    # the tooling behind. Changing either means updating both on purpose.
    pin = [('configure_bytes', 176), ('native_version', 7 if round29 else 6 if round26 else 5),
           ('request_limit', 512), ('mapping_slots', 16 if round32 else 4),
           ('configure_off_deadline', 24), ('configure_off_callback', 32),
           ('configure_off_mapper', 96), ('configure_off_quiesced', 112),
           ('configure_off_inFlight', 128), ('configure_off_ringOwn', 132),
           ('configure_off_edgeSeq', 136), ('configure_off_barrierFails', 140),
           ('configure_off_tEdge', 144), ('configure_off_tSubmitDone', 152),
           ('configure_off_tDrainDone', 160), ('configure_off_tResume', 168)]
    for name, expect in pin:
        got = want.get(name)
        if got != expect:
            bad.append('%s: headers=%r pinned=%r' % (name, got, expect))
    if bad:
        print('ABI MISMATCH:\n  ' + '\n  '.join(bad))
        return 1
    print('abi: current and shared record decoders match headers '
          '(%d fields); Configure/run dimensions match (%d)' %
          (len(pairs) + len(current_pairs), len(pin)))
    return 0


def check_r25():
    want = abi()
    pins = {'domain_version': 3, 'domain_bytes': 23192,
            'domain_record_bytes': 720, 'domain_records_offset': 80,
            'domain_tail_offset': 23120, 'domain_sequence_offset': 23184,
            'native_version': 5, 'std_version': 4,
            'native_history_start_offset': 44, 'std_history_total_offset': 52,
            'request_limit': 512, 'history_capacity': 32, 'mapping_slots': 4,
            'std_header_bytes': 72, 'std_witness_bytes': 304}
    bad = {k: (want.get(k), v) for k, v in pins.items() if want.get(k) != v}
    if bad:
        print('round25 ABI MISMATCH: ' + repr(bad))
        return 1
    print('round25 ABI: %d header-derived pins passed' % len(pins))
    return check()

def check_r26():
    want = abi()
    pins = {'domain_version': 3, 'domain_bytes': 23192,
            'domain_record_bytes': 720, 'domain_records_offset': 80,
            'domain_tail_offset': 23120, 'domain_sequence_offset': 23184,
            'native_version': 6, 'std_version': 5, 'configure_bytes': 176,
            'native_history_start_offset': 44, 'std_history_total_offset': 52,
            'history_capacity': 32, 'mapping_slots': 4,
            'std_header_bytes': 72, 'std_witness_bytes': 304}
    bad = {k: (want.get(k), v) for k, v in pins.items() if want.get(k) != v}
    if bad:
        print('round26 ABI MISMATCH: ' + repr(bad))
        return 1
    print('round26 ABI: %d header-derived pins passed' % len(pins))
    return check()


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ('--check-r32', '--check-r34', '--check-r35', '--check-r36'):
        want = abi()
        pins = {'domain_version': 4, 'domain_bytes': 44592,
                'domain_record_bytes': 1304, 'domain_records_offset': 80,
                'domain_tail_offset': 41808, 'domain_sequence_offset': 41920,
                'domain_record_segments': 16, 'domain_record_pages': 32,
                'domain_record_basepage_offset': 64, 'domain_record_pte_offset': 712,
                'domain_allocator_offset': 41928, 'domain_probe_offset': 41984,
                'native_version': 7, 'std_version': 5, 'configure_bytes': 176,
                'retire_ack_op': 4, 'history_capacity': 32, 'mapping_slots': 16,
                'rx_version': 4, 'rx_count': 1024, 'rx_snapshot_bytes': 311376,
                'rx_request_bytes': 344192, 'rx_backend_bytes': 204864,
                'rx_tail_seq_offset': 44, 'pool_version': 2, 'pool_spares': 1024,
                'pool_snapshot_bytes': 114808, 'pool_request_bytes': 114856}
        if sys.argv[1] in ('--check-r34', '--check-r35', '--check-r36'):
            pins.update({'rx_native_version': {'--check-r34': 1, '--check-r35': 2, '--check-r36': 3}[sys.argv[1]],
                         'rx_native_count': 1024,
                         'rx_native_driver_bytes': 270432, 'rx_native_backend_bytes': 475216,
                         'rx_native_driver_header': 96, 'rx_native_driver_slot_bytes': 264,
                         'rx_native_backend_header': 80, 'rx_native_backend_slot_bytes': 464,
                         'rx_native_witness_bytes': 104, 'rx_native_map_record_bytes': 224})
        bad = {k: (want.get(k), v) for k, v in pins.items() if want.get(k) != v}
        if bad:
            print('%s ABI MISMATCH: %r' % (sys.argv[1][8:], bad))
            return 1
        print('%s ABI: %d header-derived pins passed' % (sys.argv[1][8:], len(pins)))
        return check()
    if len(sys.argv) > 1 and sys.argv[1] == '--check-r30':
        want = abi()
        pins = {'domain_version': 3, 'native_version': 7, 'std_version': 5,
                'configure_bytes': 176, 'retire_ack_op': 4,
                'history_capacity': 32, 'mapping_slots': 4,
                'rx_version': 4, 'rx_count': 1024, 'rx_snapshot_bytes': 311376,
                'rx_request_bytes': 344192, 'rx_backend_bytes': 204864,
                'rx_tail_seq_offset': 44, 'pool_version': 2, 'pool_spares': 1024,
                'pool_snapshot_bytes': 114808, 'pool_request_bytes': 114856}
        bad = {k: (want.get(k), v) for k, v in pins.items() if want.get(k) != v}
        if bad:
            print('round30 ABI MISMATCH: ' + repr(bad))
            return 1
        print('round30 ABI: %d header-derived pins passed' % len(pins))
        return check()
    if len(sys.argv) > 1 and sys.argv[1] == '--check-r29':
        want = abi()
        pins = {'domain_version': 3, 'native_version': 7, 'std_version': 5,
                'configure_bytes': 176, 'retire_ack_op': 4,
                'history_capacity': 32, 'mapping_slots': 4,
                'rx_version': 3, 'rx_snapshot_bytes': 19536,
                'rx_request_bytes': 21632, 'rx_tail_seq_offset': 44}
        bad = {k: (want.get(k), v) for k, v in pins.items() if want.get(k) != v}
        if bad:
            print('round29 ABI MISMATCH: ' + repr(bad))
            return 1
        print('round29 ABI: %d header-derived pins passed' % len(pins))
        return check()
    if len(sys.argv) > 1 and sys.argv[1] == '--check-r26':
        return check_r26()
    if len(sys.argv) > 1 and sys.argv[1] == '--check-r25':
        return check_r25()
    if len(sys.argv) > 1 and sys.argv[1] == '--check':
        return check()
    print(json.dumps(abi(), indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
