#!/usr/bin/env python3
"""make-fixture.py -- build a synthetic round-11 capture to test the analyser.

WHY A SYNTHETIC CAPTURE IS LEGITIMATE HERE
------------------------------------------
The analyser must be exercised BEFORE a real run, because a bug found after a
reboot costs a reboot and the run. A synthetic capture is a fixture for testing
the ANALYSER, not evidence about the machine, and this script says so in the
files it writes so it cannot later be mistaken for a real run.

It is built to satisfy every check the analyser makes, so that:
  * a passing synthetic capture proves the analyser can pass (a suite that only
    ever rejects would "pass" on an analyser that rejects everything);
  * the negative suite can mutate it one property at a time.

WHAT IT CONTAINS
----------------
  props.txt              the probe's properties, including the exported
                         snapshot hash and the DTE it walked from
  props.raw.txt          contains m2-b2-obs-snapshot-used as an OSData hex blob
  obs-snapshot-used.bin  the same bytes, so the hash triple agrees
  client.log             one run, 4 requests, one token
  peer.log               the same 4 requests echoed, keyed by client port
  load.txt               the interface decision
  network.txt            the interface/MAC inventory
  system.txt             kernel and kext identity

The driver snapshot is a real wire-v2 blob (104-byte header + 72-byte records)
built with the same field layout the driver uses, so the analyser's decoder is
exercised rather than bypassed.
"""
import hashlib
import os
import struct
import sys

HDR_BYTES = 104
REC_BYTES = 72
MAGIC = 0x324F4C52

TOKEN = 0xA3DBBA85
BATCH = 4
BDF = 0x2500
VID = 0x10EC
DID = 0x8127
IFUNIT = 2
MAC = 0x1c860b3b0bbd
EPOCH = 42
PUBID = 27

# The window and the timestamps inside it.
WIN_START = 37_843_770_300
WIN_END = 40_843_902_421
T_PUBLISHED = 41_305_180_913

# Page table geometry, mirroring the probe's 4-level identity map.
ROOT_PA = 0x37205000
L3_PA = 0x37206000
L2_PA = 0x37215000
LEAF_PA = 0x382a00000
DTE_MODE = 4

KIND_TX_SUBMIT = 1
KIND_TX_DONE = 2
KIND_RX_DONE = 3
KIND_TX_DOORBELL = 4

PKT_PARSED = 1 << 0
FLAG_FIRST = 1 << 2
FLAG_LAST = 1 << 3


def sha(b):
    return hashlib.sha256(b).hexdigest()


def dte_raw():
    return (ROOT_PA & 0x000FFFFFFFFFF000) | (DTE_MODE << 9) | \
           (1 << 61) | (1 << 62) | 1 | 2


def pte_table(child_level, pa):
    return (pa & 0x000FFFFFFFFFF000) | (child_level << 9) | 1 | (1 << 61) | (1 << 62)


def pte_leaf(pa):
    # NextLevel 0 = the level's default page size (2 MiB at level 2).
    return (pa & 0x000FFFFFFFFFF000) | 1 | (1 << 60) | (1 << 61) | (1 << 62)


def walk_for(addr):
    """The (table, index, level, pte) chain this address takes."""
    i4 = (addr >> 39) & 0x1FF
    i3 = (addr >> 30) & 0x1FF
    i2 = (addr >> 21) & 0x1FF
    # The probe's table is built so L3[0] points at one L2 table covering
    # 1 GiB, and L2[i2] is a 2 MiB leaf.
    l3_ptes = {}
    l3_ptes[i3] = pte_table(2, L2_PA)
    return [
        (ROOT_PA, i4, 4, pte_table(3, L3_PA)),
        (L3_PA, i3, 3, l3_ptes[i3]),
        (L2_PA, i2, 2, pte_leaf((addr >> 21) << 21)),
    ]


def build_snapshot():
    """A wire-v2 snapshot with 4 requests, each one TX segment + done + RX."""
    recs = []

    def add(t, addr, kind, cum, slot, ln, flags, token, req, pkt):
        recs.append(dict(t=t, addr=addr, kind=kind, cum=cum, slot=slot,
                         ln=ln, flags=flags, token=token, req=req, pkt=pkt))

    # A pre-window record so the snapshot reaches back before WIN_START.
    add(WIN_START - 5_000_000, 0x1f000000, KIND_RX_DONE, 0x040, 0x040, 60,
        0, 0, 0, 0)

    base_cum = 0x068
    rx_cum = 0x04f
    tx_addrs = [0x3790a57b6, 0x3fc67a1b6, 0x3e50cedb6, 0x360c31bb6]
    rx_addrs = [0x1f421f000, 0x1f421e000, 0x1f4239000, 0x1f4238000]
    for i in range(BATCH):
        req = i + 1
        cum = base_cum + i
        ts = WIN_START + 780_000_000 + i * 250_000_000
        add(ts, tx_addrs[i], KIND_TX_SUBMIT, cum, cum, 74,
            FLAG_FIRST | FLAG_LAST, TOKEN, req, PKT_PARSED)
        add(ts + 2_000, 0, KIND_TX_DOORBELL, cum + 1, 0, 0, 0, TOKEN, req,
            PKT_PARSED)
        add(ts + 156_000, 0, KIND_TX_DONE, cum, cum, 0, 0, 0, 0, 0)
        add(ts + 960_000, rx_addrs[i], KIND_RX_DONE, rx_cum + i, rx_cum + i, 74,
            0, TOKEN, req, PKT_PARSED)

    # A trailing record so the snapshot is not exactly the business records.
    add(WIN_END + 1_000_000, 0x1f002000, KIND_RX_DONE, 0x060, 0x060, 60, 0, 0,
        0, 0)

    recs.sort(key=lambda r: r['t'])
    n = len(recs)
    first_ticket = 1
    head = first_ticket + n

    hdr = struct.pack(
        '<20IQQQ',
        MAGIC, 2, REC_BYTES, 4096,
        head, 0, 0, PUBID, first_ticket, first_ticket + n - 1,
        n, 0,                       # validCount, lostCount
        EPOCH, BDF, VID, DID, IFUNIT,
        (MAC >> 16) & 0xFFFFFFFF, MAC & 0xFFFF,
        0,                          # flags
        1000,                       # tStart
        T_PUBLISHED,
        0)

    body = b''
    for i, r in enumerate(recs):
        ticket = first_ticket + i
        body += struct.pack(
            '<QQIIIIIIIIIIIIII',
            r['t'], r['addr'], ticket << 1, r['kind'], r['cum'], r['slot'],
            r['cum'] // 1024, r['cum'],
            0, 0, r['ln'], r['flags'],
            r['token'], r['req'], 0x1234, r['pkt'])
    return hdr + body


def main():
    cap = sys.argv[1] if len(sys.argv) > 1 else 'fixture-r11'
    os.makedirs(cap, exist_ok=True)

    blob = build_snapshot()
    blob_sha = sha(blob)
    open(os.path.join(cap, 'obs-snapshot-used.bin'), 'wb').write(blob)

    # ---- props.raw.txt: the probe node plus the driver's property ----
    # ioreg's TEXT form, which is what the capture actually archives and what
    # the analyser parses: `"key" = "value"` and `"key" = <hex>`.
    raw_lines = ['+-o RTL8125  <class RTL8125>',
                 '  {',
                 '    "IOClass" = "RTL8125"',
                 '    "rtl812x-obs-snapshot" = <%s>' % blob.hex(),
                 '    "rtl812x-obs-epoch" = %d' % EPOCH,
                 '  }']

    # The probe's own node, with every property the analyser reads.
    props = []
    props.append(('m2-b2-mode', 'translation'))
    props.append(('m2-b2-obs-used', 'exported'))
    props.append(('m2-b2-obs-used-sha256', blob_sha))
    props.append(('m2-b2-obs-used-pub-id', '0x%x' % PUBID))
    props.append(('m2-b2-obs-used-t-published', '0x%x' % T_PUBLISHED))
    props.append(('m2-b2-obs-epoch-binding', 'matched'))
    props.append(('m2-b2-obs-epoch-bound', '0x%x' % EPOCH))
    props.append(('m2-b2-nic-bdf', '0x%x' % BDF))
    props.append(('m2-b2-nic-vendor', '0x%x' % VID))
    props.append(('m2-b2-nic-device', '0x%x' % DID))
    props.append(('m2-b2-nic-unit', '0x%x' % IFUNIT))
    props.append(('m2-b2-nic-mac', '0x%x' % MAC))
    props.append(('m2-b2-dma-t-win-start', '0x%x' % WIN_START))
    props.append(('m2-b2-dma-t-win-end', '0x%x' % WIN_END))
    props.append(('m2-b2-window-valid', 'yes'))
    # ---- ROUND 13: the raw event-log STATUS words and the ring pointers ----
    #
    # The production `m2b2SampleEvents()` refuses a window unless EVT_RUN is set
    # and EVT_OVERFLOW is clear at BOTH ends, and the analyser now recomputes
    # that from these words. A fixture without them cannot exercise the check,
    # and its baseline fails -- which is what round 12's fixture did the moment
    # the check was added.
    #
    # 0x1a = EVT_OVERFLOW(0) | EVT_INT(1) | EVT_RUN(3): log running, no
    # overflow. That is the value the real 20261101-014200 archive carries.
    props.append(('m2-b2-win-status-start', '0x1a'))
    props.append(('m2-b2-win-status-end', '0x1a'))
    # The ring is empty and never advanced, so head == tail == 0 at both ends
    # and the produced span is zero -- consistent with win-entries = 0.
    props.append(('m2-b2-win-head-start', '0x0'))
    props.append(('m2-b2-win-tail-start', '0x0'))
    props.append(('m2-b2-win-head-end', '0x0'))
    props.append(('m2-b2-win-tail-end', '0x0'))
    props.append(('m2-b2-win-entries', '0x0'))
    props.append(('m2-b2-map-limit', '0x400000000'))
    props.append(('m2-b2-obs-records-cover-window', 'yes'))
    props.append(('m2-b2-obs-controlled-batch-complete', 'yes'))
    # The header's own counters, mirrored. The analyser requires the probe's
    # view to agree with the header, so a fixture without these would fail its
    # own positive case.
    props.append(('m2-b2-obs-dropped', '0x0'))
    props.append(('m2-b2-obs-wrapped', '0x0'))
    props.append(('m2-b2-obs-lost-count', '0x0'))
    props.append(('m2-b2-obs-hdr-flags', '0x0'))
    props.append(('m2-b2-obs-expected-batch', '0x%x' % BATCH))
    props.append(('m2-b2-obs-declared-token', '0x%x' % TOKEN))
    props.append(('m2-b2-obs-join-token', '0x%x' % TOKEN))
    props.append(('m2-b2-obs-token-resolved', 'yes'))
    props.append(('m2-b2-obs-token-ambiguous', 'no'))
    props.append(('m2-b2-evt-log', 'enabled'))
    props.append(('m2-b2-evt-reset', 'done'))
    # ROUND 12: the fixture carries ONE raw event, so the negative suite's
    # event-status case has something to mutate. The round-11 archive has
    # win-raw-count = 0 (no faults), which left that case inapplicable there --
    # reported honestly as N/A, but a suite with a hole. The fixture fills it.
    #
    # Word layout: [0] devid + flags, [1] type in bits 31:28 and STATUS in bits
    # 27:16, [2]/[3] the fault address. The event is a decoy: type 1 (an IOMMU
    # event, NOT an IO_PAGE_FAULT) attributed to a DIFFERENT devid, with a
    # NON-ZERO status -- an event with status 0 is not a valid logged event, so
    # a fixture that used 0 would make the analyser's own status check fail on
    # the positive case. So the fault checks still see zero faults for the
    # target, the fixture stays a clean positive case, and a mutation that
    # zeroes the status is still detectable.
    props.append(('m2-b2-win-raw-count', '0x1'))
    props.append(('m2-b2-win-raw0',
                  '34000000' '11230000' '10001000' '00000000'))
    props.append(('m2-b2-win-raw-truncated', 'no'))
    props.append(('m2-b2-win-type2-count', '0x0'))

    # ---- ROUND 12: the command records -----------------------------------
    #
    # The analyser compares expected to observed for every command. A fixture
    # without these fields cannot exercise that check, and a suite that skips
    # it silently is a suite with a hole.
    props.append(('m2-b2-cmd-record-count', '0x3'))
    for i, (label, dwords) in enumerate((('inv-all', 1),
                                         ('inv-dev-entry', 2),
                                         ('inv-iommu-pages', 3))):
        props.append(('m2-b2-cmd%d-label' % i, label))
        props.append(('m2-b2-cmd%d-dwords' % i, '0x%x' % dwords))
        props.append(('m2-b2-cmd%d-expected' % i, '0x%x' % dwords))
        props.append(('m2-b2-cmd%d-observed' % i, '0x%x' % dwords))
        props.append(('m2-b2-cmd%d-loops' % i, '0x80'))
        props.append(('m2-b2-cmd%d-ok' % i, 'yes'))

    # ---- ROUND 12: the timeline ------------------------------------------
    #
    # DTE written -> invalidation complete = translation effective -> window
    # -> translation off -> recovery. The ordering checks are what catch
    # "the invalidation completion moved after the window".
    props.append(('m2-b2-dma-t-dte-written',
                  '0x%x' % (WIN_START - 3_000_000)))
    props.append(('m2-b2-dma-t-inv-complete',
                  '0x%x' % (WIN_START - 2_000_000)))
    props.append(('m2-b2-dma-t-translate-on',
                  '0x%x' % (WIN_START - 2_000_000)))
    props.append(('m2-b2-dma-t-translate-off',
                  '0x%x' % (WIN_END + 2_000_000)))
    props.append(('m2-b2-t-recovery-end',
                  '0x%x' % (WIN_END + 3_000_000)))
    props.append(('m2-b2-stage-inv-dev', 'yes'))
    props.append(('m2-b2-stage-inv-pages', 'yes'))
    props.append(('m2-b2-cmdbuf-stopped', 'yes'))
    props.append(('m2-b2-evtlog-stopped', 'yes'))
    props.append(('m2-b2-disabled', 'yes'))
    props.append(('m2-b2-regs-restored', 'yes'))
    props.append(('m2-b2-cleanup', 'done'))
    props.append(('m2-b2-bizwalk-dte-raw', '0x%x' % dte_raw()))
    props.append(('m2-b2-bizwalk-dte-mode', '0x%x' % DTE_MODE))
    props.append(('m2-b2-bizwalk-dte-root-pa', '0x%x' % ROOT_PA))
    props.append(('m2-b2-bizwalk-root-level', '0x4'))
    props.append(('m2-b2-bizwalk-dte-state', 'translation'))

    # Every business range, with the real chain for its address.
    idx = 0
    for i in range(BATCH):
        for direction, addr in (('tx', tx_addrs_for(i)),
                                ('rx', rx_addrs_for(i))):
            chain = walk_for(addr)
            props.append(('m2-b2-bw%d-req' % idx, '0x%x' % (i + 1)))
            props.append(('m2-b2-bw%d-dir' % idx, direction))
            props.append(('m2-b2-bw%d-seg' % idx, '0x0'))
            props.append(('m2-b2-bw%d-addr' % idx, '0x%x' % addr))
            props.append(('m2-b2-bw%d-len' % idx, '0x4a'))
            props.append(('m2-b2-bw%d-depth' % idx, '0x%x' % len(chain)))
            props.append(('m2-b2-bw%d-root-pa' % idx, '0x%x' % ROOT_PA))
            props.append(('m2-b2-bw%d-root-level' % idx, '0x4'))
            props.append(('m2-b2-bw%d-dte' % idx, '0x%x' % dte_raw()))
            leaf = chain[-1][3] & 0x000FFFFFFFFFF000
            props.append(('m2-b2-bw%d-leaf-pa' % idx, '0x%x' % leaf))
            props.append(('m2-b2-bw%d-leaf-size' % idx, '0x200000'))
            props.append(('m2-b2-bw%d-leaf-level' % idx, '0x2'))
            props.append(('m2-b2-bw%d-covered' % idx, 'yes'))
            props.append(('m2-b2-bw%d-perm-ok' % idx, 'yes'))
            props.append(('m2-b2-bw%d-pages' % idx, '0x1'))
            props.append(('m2-b2-bw%d-pages-bad' % idx, '0x0'))
            props.append(('m2-b2-bw%d-why' % idx, 'ok'))
            for L, (table, ix, lvl, pte) in enumerate(chain):
                props.append(('m2-b2-bw%d-pte%d-table' % (idx, L),
                              '0x%x' % table))
                props.append(('m2-b2-bw%d-pte%d-index' % (idx, L),
                              '0x%x' % ix))
                props.append(('m2-b2-bw%d-pte%d-level' % (idx, L),
                              '0x%x' % lvl))
                props.append(('m2-b2-bw%d-pte%d' % (idx, L), '0x%x' % pte))
            # ---- ROUND 12's PER-LEAF EXPORT, which round 13 now requires ----
            #
            # The round-12 probe publishes every leaf of a range as
            # `m2-b2-bwN-leafM-*`, and the analyser derives the path length by
            # counting `m2-b2-bwN-leafM-pteK`. A fixture that only had the
            # legacy `m2-b2-bwN-pteK` spelling made the analyser fall back to
            # the legacy branch, which is exactly why round 12's M3 mutation
            # (which zeroed `bwN-depth`) hit nothing: under the round-12 export
            # the depth is not a field the analyser reads at all.
            #
            # These ranges are 74 bytes inside a single 2 MiB leaf, so there is
            # exactly one leaf and it covers the whole range from `addr`.
            props.append(('m2-b2-bw%d-leaves' % idx, '0x1'))
            props.append(('m2-b2-bw%d-leaf0-pa' % idx, '0x%x' % leaf))
            props.append(('m2-b2-bw%d-leaf0-size' % idx, '0x200000'))
            props.append(('m2-b2-bw%d-leaf0-from' % idx, '0x%x' % addr))
            props.append(('m2-b2-bw%d-leaf0-bytes' % idx, '0x4a'))
            for L, (table, ix, lvl, pte) in enumerate(chain):
                props.append(('m2-b2-bw%d-leaf0-pte%d-table' % (idx, L),
                              '0x%x' % table))
                props.append(('m2-b2-bw%d-leaf0-pte%d-index' % (idx, L),
                              '0x%x' % ix))
                props.append(('m2-b2-bw%d-leaf0-pte%d-level' % (idx, L),
                              '0x%x' % lvl))
                props.append(('m2-b2-bw%d-leaf0-pte%d' % (idx, L),
                              '0x%x' % pte))
            idx += 1
    props.append(('m2-b2-bizwalk-count', '0x%x' % idx))
    props.append(('m2-b2-bizwalk-ok', '0x%x' % idx))
    props.append(('m2-b2-bizwalk-fail', '0x0'))
    props.append(('m2-b2-bizwalk-expected', '0x%x' % idx))
    props.append(('m2-b2-bizwalk-capped', '0x0'))
    props.append(('m2-b2-bizwalk', 'all-covered'))

    # ioreg's text form is `"key" = "value"` / `"key" = <hex>`, NOT an XML
    # plist. The analyser parses that form (it reads real ioreg output), so the
    # fixture has to be written in the same form or it tests a parser nobody
    # uses. Getting this wrong the first time produced a fixture that looked
    # plausible and had every property read as None.
    probe_node = ['    {',
                  '      "IOClass" = "org_maz1_AMDMapperProbe"']
    for k, v in props:
        probe_node.append('      "%s" = "%s"' % (k, v))
    # The exported snapshot itself, as an OSData hex blob. This is the whole
    # point of round 11: the probe publishes the exact bytes it decoded, so the
    # archive does not have to go looking for a later publication.
    probe_node.append('      "m2-b2-obs-snapshot-used" = <%s>' % blob.hex())
    probe_node.append('    }')

    # props.raw.txt contains BOTH nodes; props.txt only the probe's.
    open(os.path.join(cap, 'props.raw.txt'), 'w',
         encoding='utf-8').write('\n'.join(raw_lines + probe_node) + '\n')
    open(os.path.join(cap, 'props.txt'), 'w',
         encoding='utf-8').write('\n'.join(probe_node) + '\n')

    # ---- client.log ----
    port = 54321
    cl = ['client_start_ns 1000000',
          'client_iface en2',
          'client_peer 192.168.50.122:9110',
          'client_run_token 0x%08x' % TOKEN,
          'client_requests %d' % BATCH,
          'client_local 192.168.50.216',
          'client_route_interface en2',
          'client_route_gateway 192.168.50.1',
          'client_route_src 192.168.50.216',
          'client_bound 192.168.50.216:%d' % port]
    for i in range(BATCH):
        req = i + 1
        t = 2_000_000 + i * 250_000_000
        cl.append('client_sent token=0x%08x req=%d len=32 t_ns=%d'
                  % (TOKEN, req, t))
        cl.append('client_recv token=0x%08x req=%d t_ns=%d rtt_ns=120000'
                  % (TOKEN, req, t + 120_000))
    cl.append('client_summary sent=%d acked=%d bad=0 span_ns=900000000'
              % (BATCH, BATCH))
    cl.append('client_result OK')
    open(os.path.join(cap, 'client.log'), 'w',
         encoding='utf-8').write('\n'.join(cl) + '\n')

    # ---- peer.log ----
    pe = []
    for i in range(BATCH):
        req = i + 1
        head = struct.pack('>III', 0x31424F49, TOKEN, req) + b'\x00' * 20
        pe.append('peer_recv token=0x%08x req=%d len=32 from=192.168.50.216:%d t=%d'
                  % (TOKEN, req, port, 3_000_000 + i * 250_000_000))
        pe.append('RECV 32 bytes from 192.168.50.216:%d head=%s'
                  % (port, head[:12].hex()))
    open(os.path.join(cap, 'peer.log'), 'w',
         encoding='utf-8').write('\n'.join(pe) + '\n')

    # ---- load.txt ----
    open(os.path.join(cap, 'load.txt'), 'w', encoding='utf-8').write(
        'load_iface          : en2\n'
        'load_route_interface : en2\n'
        'load_mac            : 1c:86:0b:3b:0b:bd\n'
        'load_local          : 192.168.50.216\n'
        'load_run_token      : 0x%08x\n'
        'load_requests       : %d\n' % (TOKEN, BATCH))

    # ---- network.txt ----
    open(os.path.join(cap, 'network.txt'), 'w', encoding='utf-8').write(
        '# interface inventory\n'
        'en0: ether=00:e0:4c:68:ab:03 inet=192.168.50.204 status=active\n'
        'en1: ether=00:00:00:00:00:01 status=inactive\n'
        'en2: ether=1c:86:0b:3b:0b:bd inet=192.168.50.216 status=active\n')

    # ---- system.txt ----
    open(os.path.join(cap, 'system.txt'), 'w', encoding='utf-8').write(
        'kernel_release    : 25.6.0\n'
        'hw.tbfrequency    : 1000000000\n'
        'SYNTHETIC FIXTURE : this capture was GENERATED by '
        'tools/r11/make-fixture.py\n'
        '                    to test the analyser. It is NOT evidence about '
        'the machine.\n')

    print('fixture written to %s' % cap)
    print('  snapshot  %d B  sha256=%s' % (len(blob), blob_sha))
    print('  records   %d' % ((len(blob) - HDR_BYTES) // REC_BYTES))
    print('  SYNTHETIC -- not a real run')
    return 0


def tx_addrs_for(i):
    return [0x3790a57b6, 0x3fc67a1b6, 0x3e50cedb6, 0x360c31bb6][i]


def rx_addrs_for(i):
    return [0x1f421f000, 0x1f421e000, 0x1f4239000, 0x1f4238000][i]


if __name__ == '__main__':
    sys.exit(main())
