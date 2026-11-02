#!/usr/bin/env python3
"""make-control-fixture.py -- a capture shaped like a REAL control run.

WHY THE ROUND-11 FIXTURE WAS NOT A CONTROL CAPTURE
--------------------------------------------------
Round 11 tested control mode by taking a complete TRANSLATION fixture and
changing one property:

    prop_edit(text, 'm2-b2-mode', 'control')

That is not the shape the production control branch produces. Round 12 rewrote
it to have the "real missing-field shape", but got the shape wrong in BOTH
directions, which is worse than round 11 because it made the schema look
verified:

  * IT INVENTED A PROBE-USED SNAPSHOT. `m2-b2-obs-snapshot-used` cannot exist in
    control mode: the branch does `goto recover` right after its 20 s sleep, and
    `m2b2ReadDriverObs()` -- the only thing that publishes it -- is never
    reached. With the property removed the round-12 analyser exited 2 and wrote
    no analysis.json, i.e. it refused to judge a legitimate control capture.
    The fixture hid that by carrying the impossible field.

  * IT DELETED FIELDS THE CONTROL BRANCH REALLY PUBLISHES. Step 18 runs AFTER
    the `recover:` label, so a control run does publish the command records,
    `m2-b2-stage-inv-all` / `-inv-dev` / `-inv-pages`, `m2-b2-cmdbuf-stopped`,
    `m2-b2-regs-restored`, `m2-b2-cleanup`, `m2-b2-t-recovery-start` /
    `-t-recovery-end` and the evidence gate. Round 12's fixture dropped them, so
    the control schema asserted an absence that does not exist and the control
    verdict rested on the mode string alone.

WHAT THIS SCRIPT WRITES NOW
---------------------------
The field set is DERIVED FROM THE PRODUCTION SOURCE by tools/r13/control-shape.py
rather than written by hand. That script classifies every `setProperty` call in
`runM22b2PageTableProbe()` as:

    always           runs on both paths (before the branch, or after `recover:`)
    conditional      runs only when its guard holds
    translation_only inside the branch-to-label region the `goto` jumps over

This fixture writes every `always` property with a value consistent with a
SUCCESSFUL control run, and it writes the `conditional` properties whose
guards hold on a successful run. It writes NO translation-only property. It
writes no `m2-b2-obs-snapshot-used` and no `m2-b2-nic-*`, because the control
branch reaches neither.

`--shape <json>` lets the verifier supply the derivation so the fixture and the
schema are checked against the same source rather than against each other.

It is a SYNTHETIC fixture for testing the analyser. It says so in the files it
writes, so it can never be mistaken for a real run.
"""
import hashlib
import json
import os
import struct
import sys

HDR_BYTES = 104
REC_BYTES = 72
MAGIC = 0x324F4C52

# A real control run still knows WHICH DEVICE it watched: step 8 resolves the
# target BDF from the IOPCIDevice before the branch, and publishes
# m2-b2-target-devid / -tgt-bus / -tgt-dev / -tgt-fn. It does NOT publish
# m2-b2-nic-* (that is step 16c, after the `goto`).
BDF = 0x2500
BUS = (BDF >> 8) & 0xFF
DEV = (BDF >> 3) & 0x1F
FN = BDF & 0x7

# The control stage is a fixed 20 s IOSleep. A successful run measures close to
# that; the analyser requires 19 s .. 26 s, so the fixture must be inside it.
CTL_START = 12_000_000_000
CTL_END = CTL_START + 20_010_000_000

# The driver's own log exists in a control run -- it is published by the driver
# whether or not the probe is running an experiment. It is NOT the probe-used
# snapshot, and this fixture keeps them distinct on purpose.
DRV_EPOCH = 42


def sha(b):
    return hashlib.sha256(b).hexdigest()


def build_driver_snapshot():
    """The DRIVER's own log: ordinary traffic, no business records.

    A control run sends no controlled batch, so the driver's snapshot cannot
    contain one. This blob is written as `rtl812x-obs-snapshot` (the driver's
    property) and deliberately NOT as `m2-b2-obs-snapshot-used`, because the
    probe never decodes it in this branch.
    """
    recs = []
    for i in range(6):
        recs.append(dict(t=CTL_START + i * 1_000_000,
                         addr=0x1f000000 + i * 0x1000,
                         kind=3 if i % 2 == 0 else 1, cum=0x40 + i,
                         slot=0x40 + i, ln=60, flags=0, token=0, req=0,
                         pkt=0))

    n = len(recs)
    first_ticket = 1
    head = first_ticket + n
    hdr = struct.pack(
        '<20IQQQ',
        MAGIC, 2, REC_BYTES, 4096,
        head, 0, 0, 9, first_ticket, first_ticket + n - 1,
        n, 0,
        DRV_EPOCH, BDF, 0x10EC, 0x8127, 2,
        (0x1c860b3b0bbd >> 16) & 0xFFFFFFFF, 0x1c860b3b0bbd & 0xFFFF,
        0,
        1000,
        CTL_END + 1_000_000,
        0)

    body = b''
    for i, r in enumerate(recs):
        ticket = first_ticket + i
        body += struct.pack(
            '<QQIIIIIIIIIIIIII',
            r['t'], r['addr'], ticket << 1, r['kind'], r['cum'], r['slot'],
            r['cum'] // 1024, r['cum'],
            0, 0, r['ln'], r['flags'],
            r['token'], r['req'], 0, r['pkt'])
    return hdr + body


# ---------------------------------------------------------------------------
# The property set, keyed by the classification tools/r13/control-shape.py
# produces. Values are those of a SUCCESSFUL control run.
# ---------------------------------------------------------------------------
ALWAYS_VALUES = {
    # ---- published before the branch (shared setup) ----
    'm2-b2-cache-flush': '0x1',
    'm2-b2-cmd-pa': '0x1a2b3000',
    'm2-b2-control-on': '0x220000000406',
    'm2-b2-dt': '0x1a2b4000',
    'm2-b2-enabled': 'yes',
    'm2-b2-evt-log': 'enabled',
    'm2-b2-evt-pa': '0x1a2b5000',
    'm2-b2-identity': 'walk-ok',
    'm2-b2-inv-all': 'done',
    'm2-b2-l1-pages': '0x20',
    'm2-b2-l2-pages': '0x1',
    'm2-b2-leaf-mode': '2MiB',
    'm2-b2-leaf-pages': '0x10',
    'm2-b2-leaf-ptes': '0x10',
    'm2-b2-main-window-ran': 'no',
    'm2-b2-map-limit': '0x400000000',
    'm2-b2-orig-control': '0x220000000400',
    'm2-b2-pre-window-ran': 'no',
    'm2-b2-pt': 'built',
    'm2-b2-pt-bytes': '0x13000',
    'm2-b2-pt-l2-pa': '0x1a2b6000',
    'm2-b2-pt-pa': '0x1a2b5000',
    'm2-b2-pt-pages': '0x13',
    'm2-b2-pt-root-pa': '0x1a2b5000',
    'm2-b2-sem-pa': '0x1a2b7000',
    'm2-b2-stage': '19-control-preserved',
    'm2-b2-t-recovery-start': '0x%x' % (CTL_END + 1_000_000),
    'm2-b2-target-devid': '0x%x' % BDF,
    'm2-b2-tbl-pa': '0x1a2b4000',
    'm2-b2-tgt-hint': '0x2500',
    'm2-b2-tgt-source': 'IOPCIDevice-accessors',
    'm2-b2-verdict': 'CONTROL-sleep-only-no-dte-change',
    # The control branch's own statement about the DTE. Published INSIDE the
    # branch, so it is part of this mode's shape.
    'm2-b2-dte': 'NOT-switched-control',

    # ---- inside the branch: the control experiment itself ----
    'm2-b2-sleep-only': 'done',
    'm2-b2-window-secs': '0x14',
    'm2-b2-ctl-t-start': '0x%x' % CTL_START,
    'm2-b2-ctl-wall-start': '0x6ae698f7',
    'm2-b2-ctl-t-end': '0x%x' % CTL_END,
    'm2-b2-ctl-wall-end': '0x6ae6990b',
    'm2-b2-ctl-dur-ms': '0x%x' % ((CTL_END - CTL_START) // 1_000_000),
    'm2-b2-evt-window': 'none-in-sleep-only-branch',

    # ---- after `recover:` (step 18/19/20 run for BOTH paths) ----
    'm2-b2-mode': 'control-sleep-only',
}

# Conditional properties whose guard holds on a SUCCESSFUL control run.
# Anything not listed here is written as absent, which is the honest shape for
# a branch that did not take that guard.
CONDITIONAL_VALUES = {
    # step 11 succeeded, so `m2-b2-evt-reset` is "done" (not the FAIL string)
    'm2-b2-evt-reset': 'done',
    # step 12 succeeded
    'm2-b2-inv-all': 'done',
    # step 8 resolved the BDF from IOPCIDevice accessors
    'm2-b2-tgt-bus': '0x%x' % BUS,
    'm2-b2-tgt-dev': '0x%x' % DEV,
    'm2-b2-tgt-fn': '0x%x' % FN,
    'm2-b2-tgt-mismatch': 'none',
    # step 18.1b: the command records from steps 12 and 15
    'm2-b2-cmd-record-count': '0x2',
    'm2-b2-cmd0-label': 'inv-all',
    'm2-b2-cmd0-expected': '0x1',
    'm2-b2-cmd0-observed': '0x1',
    'm2-b2-cmd0-ok': 'yes',
    'm2-b2-cmd1-label': 'inv-dev-entry',
    'm2-b2-cmd1-expected': '0x2',
    'm2-b2-cmd1-observed': '0x2',
    'm2-b2-cmd1-ok': 'yes',
    # step 18.2 / 18.3: both stopped, so the timeout marker is absent
    'm2-b2-cmdbuf-stopped': 'yes',
    'm2-b2-evtlog-stopped': 'yes',
    'm2-b2-cmdbuf-stop-status': '0x220000000400',
    'm2-b2-evtlog-stop-status': '0x220000000400',
    'm2-b2-cmdbuf-stop-loops': '0x3',
    'm2-b2-evtlog-stop-loops': '0x3',
    # step 18.4
    'm2-b2-disabled': 'yes',
    'm2-b2-disabled-readback': '0x220000000400',
    # step 18.5: all three stopped, so the registers were restored
    'm2-b2-regs-restored': 'yes',
    'm2-b2-final-control': '0x220000000400',
    'm2-b2-orig-control-echo': '0x220000000400',
    # step 19: the per-gate status words. `inv-dev` / `inv-pages` are "no"
    # because the control branch never submits those two commands -- and the
    # control verdict does not depend on them (it depends on evt-reset,
    # inv-all and control-done). Publishing "no" is the honest value.
    'm2-b2-stage-evt-reset': 'yes',
    'm2-b2-stage-inv-all': 'yes',
    'm2-b2-stage-inv-dev': 'no',
    'm2-b2-stage-inv-pages': 'no',
    'm2-b2-stage-control-done': 'yes',
    'm2-b2-first-fail-stage': 'none',
    'm2-b2-t-recovery-end': '0x%x' % (CTL_END + 2_000_000),
    # step 20
    'm2-b2-cleanup': 'done',
    # The two "did this stage run" words are rewritten at the END of step 19 for
    # BOTH paths, so a control capture carries them.
    'm2-b2-pre-window-ran': 'no',
    'm2-b2-main-window-ran': 'no',
}

# The gate is only evaluated on the translation path (it is inside the
# `anyEvent`-less branch), so a control run publishes nothing here. Listed so
# the omission is deliberate rather than an oversight.
GATE_PROPERTIES = ('m2-b2-evidence-gate', 'm2-b2-evidence-gate-why',
                   'm2-b2-evidence-gate-text')


def main():
    cap = sys.argv[1] if len(sys.argv) > 1 else 'fixture-r13-control'
    shape_path = None
    if '--shape' in sys.argv:
        shape_path = sys.argv[sys.argv.index('--shape') + 1]
    os.makedirs(cap, exist_ok=True)

    blob = build_driver_snapshot()

    props = []
    for k in sorted(ALWAYS_VALUES):
        props.append((k, ALWAYS_VALUES[k]))
    for k in sorted(CONDITIONAL_VALUES):
        if k in ALWAYS_VALUES:
            continue
        props.append((k, CONDITIONAL_VALUES[k]))

    written = set(k for k, _ in props)

    if shape_path:
        # Cross-check the fixture against the derivation from the source. A
        # property classified `always` MUST be written; a `translation_only`
        # property MUST NOT be. This is what stops the fixture drifting from
        # the code the way round 12's did.
        shape = json.load(open(shape_path))
        missing = [p for p in shape['always'] if p not in written]
        forbidden = [p for p in shape['translation_only'] if p in written]
        if missing or forbidden:
            print('REFUSED: the fixture does not match the production shape',
                  file=sys.stderr)
            if missing:
                print('  always-published but missing: %s' % missing,
                      file=sys.stderr)
            if forbidden:
                print('  translation-only but written: %s' % forbidden,
                      file=sys.stderr)
            return 1

    probe_node = ['    {',
                  '      "IOClass" = "org_example_AMDMapperProbe"']
    for k, v in props:
        probe_node.append('      "%s" = "%s"' % (k, v))
    probe_node.append('    }')

    # The DRIVER node carries the driver's own snapshot. It is NOT the probe's.
    raw_lines = ['+-o RTL8125  <class RTL8125>',
                 '  {',
                 '    "IOClass" = "RTL8125"',
                 '    "rtl812x-obs-snapshot" = <%s>' % blob.hex(),
                 '    "rtl812x-obs-epoch" = %d' % DRV_EPOCH,
                 '    "rtl812x-obs-state" = "ok"',
                 '  }']
    open(os.path.join(cap, 'props.raw.txt'), 'w',
         encoding='utf-8').write('\n'.join(raw_lines + probe_node) + '\n')
    open(os.path.join(cap, 'props.txt'), 'w',
         encoding='utf-8').write('\n'.join(probe_node) + '\n')

    # A control run loads nothing, so the client and peer logs record that fact
    # rather than carrying a batch.
    open(os.path.join(cap, 'client.log'), 'w', encoding='utf-8').write(
        'client_start_ns 1000000\n'
        'client_iface en2\n'
        'client_result NOT-RUN control-branch\n')
    open(os.path.join(cap, 'peer.log'), 'w', encoding='utf-8').write(
        'peer_start_ns 1000000\n'
        'peer_result NOT-RUN control-branch\n')
    open(os.path.join(cap, 'load.txt'), 'w', encoding='utf-8').write(
        'load_iface          : en2\n'
        'load_route_interface : en2\n'
        'load_mac            : 1c:86:0b:3b:0b:bd\n'
        'load_local          : 192.168.50.216\n'
        'load_result         : NOT-RUN control-branch\n')
    open(os.path.join(cap, 'network.txt'), 'w', encoding='utf-8').write(
        '# interface inventory\n'
        'en0: ether=00:e0:4c:68:ab:03 inet=192.168.50.204 status=active\n'
        'en1: ether=00:00:00:00:00:01 status=inactive\n'
        'en2: ether=1c:86:0b:3b:0b:bd inet=192.168.50.216 status=active\n')
    open(os.path.join(cap, 'system.txt'), 'w', encoding='utf-8').write(
        'kernel_release    : 25.6.0\n'
        'hw.tbfrequency    : 1000000000\n'
        'SYNTHETIC FIXTURE : this capture was GENERATED by '
        'tools/r12/make-control-fixture.py\n'
        '                    to test the analyser\'s CONTROL schema. It is NOT '
        'evidence about the machine.\n'
        '                    Its field set is derived from '
        'runM22b2PageTableProbe() by\n'
        '                    tools/r13/control-shape.py: every property the '
        'control path\n'
        '                    publishes is present, and no translation-only '
        'property is.\n')

    print('control fixture written to %s' % cap)
    print('  driver snapshot %d B  sha256=%s' % (len(blob), sha(blob)))
    print('  mode control-sleep-only, %d probe properties' % len(props))
    print('  NO probe-used snapshot: the control branch never decodes one')
    print('  SYNTHETIC -- not a real run')
    return 0


if __name__ == '__main__':
    sys.exit(main())
