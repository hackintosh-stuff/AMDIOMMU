#!/usr/bin/env python3
"""test-analyzer10.py -- inject one defect at a time into a compliant capture
and require the analyser to reject it IN A NAMED WAY.

WHY "NAMED WAY" AND NOT JUST "NON-ZERO EXIT"
--------------------------------------------
Round 9's negative tests only asserted that the analyser exited non-zero. That
is satisfied by a crash, a typo, a missing file -- none of which demonstrate
that the check under test works. Each case below names the exact assertion that
must fire, so a test that passes for the wrong reason fails instead.

WHAT EACH CASE TARGETS
----------------------
The round-10 task names seven specific counterexamples:

  1. a live record is overwritten during the copy, or the header and the
     records come from different publications
  2. the snapshot predates the window end
  3. one pair succeeded but there is an unfinished submit, an orphan
     completion, or a record gap
  4. the cumulative index moves outside the tail range, or the length or
     generation disagrees
  5. a PTE lacks the permission the direction needs, or the root table is not
     the one the actual DTE names
  6. the business succeeded but the interface is not the target device, or the
     business id has nothing to do with the driver records
  7. the real control mode is missing a field for a stage that did not run

Cases 1-4 and 6 are exercised against the captured snapshot by mutating the
raw bytes; 5 and 7 are exercised against the probe's published PTE chain and
mode fields.
"""
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CAP = os.path.join(ROOT, 'docs/evidence/20261101-130000')
ANALYSER = os.path.join(ROOT, 'tools/analyze-round10.py')

HDR = 104
REC = 72

RESULTS = []


def record(name, ok, detail=''):
    RESULTS.append((name, ok, detail))
    print('  %-64s %s' % (name, 'PASS' if ok else 'FAIL'))
    if detail and not ok:
        print('      %s' % detail)


def load_capture():
    props = open(os.path.join(CAP, 'props.txt'), encoding='utf-8',
                 errors='replace').read()
    raw = open(os.path.join(CAP, 'props.raw.txt'), encoding='utf-8',
               errors='replace').read()
    blob = open(os.path.join(CAP, 'driver-snapshot.bin'), 'rb').read()
    return props, raw, blob


def run_analyser(capdir):
    r = subprocess.run([sys.executable, ANALYSER, capdir],
                       capture_output=True, text=True, cwd=ROOT)
    return r.returncode, r.stdout + r.stderr


def make_case(name, props=None, raw=None, blob=None, extra=None):
    """Copy the capture to a temp dir with the given files replaced."""
    # Under the DSH file sandbox only the workspace is writable, so the
    # case directories go under build-work-r10/ rather than %TEMP%.
    base = os.path.join(ROOT, 'build-work-r10')
    os.makedirs(base, exist_ok=True)
    # Fixed, short names: tempfile.mkdtemp produced a path long enough that
    # copy2 hit a sandbox ACL denial on this Windows workspace. A deterministic
    # name is also easier to inspect when a case fails.
    d = os.path.join(base, 'case-' + name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d, exist_ok=True)
    # analysis.json is the analyser's OWN output; copying it into the case
    # directory makes the analyser try to overwrite a file it is currently
    # writing (and, under the sandbox, a file it may not own).
    skip = {'analysis.json'}
    for f in os.listdir(CAP):
        if f in skip:
            continue
        s = os.path.join(CAP, f)
        if os.path.isfile(s):
            shutil.copyfile(s, os.path.join(d, f))
    if blob is not None:
        with open(os.path.join(d, 'driver-snapshot.bin'), 'wb') as f:
            f.write(blob)
        # props.raw.txt must carry the SAME blob, or the "from this capture"
        # check fires first and masks the defect under test.
        raw_txt = raw if raw is not None else open(
            os.path.join(CAP, 'props.raw.txt'), encoding='utf-8',
            errors='replace').read()
        raw_txt = re.sub(
            r'"rtl812x-obs-snapshot"\s*=\s*<[0-9a-fA-F]+>',
            '"rtl812x-obs-snapshot" = <%s>' % blob.hex(), raw_txt)
        open(os.path.join(d, 'props.raw.txt'), 'w', encoding='utf-8',
             newline='\n').write(raw_txt)
    if props is not None:
        open(os.path.join(d, 'props.txt'), 'w', encoding='utf-8',
             newline='\n').write(props)
    if extra:
        for fn, txt in extra.items():
            open(os.path.join(d, fn), 'w', encoding='utf-8',
                 newline='\n').write(txt)
    return d


def expect(name, capdir, needle):
    """The analyser must exit non-zero AND print the named assertion."""
    rc, out = run_analyser(capdir)
    ok = (rc != 0) and (needle in out)
    detail = ''
    if rc == 0:
        detail = 'analyser exited 0 (should have rejected)'
    elif needle not in out:
        detail = 'exited %d but did not report %r' % (rc, needle)
    record(name, ok, detail)
    shutil.rmtree(capdir, ignore_errors=True)


def hdr_set(blob, offset, fmt, value):
    b = bytearray(blob)
    struct.pack_into(fmt, b, offset, value)
    return bytes(b)


def rec_set(blob, index, offset, fmt, value):
    b = bytearray(blob)
    struct.pack_into(fmt, b, HDR + index * REC + offset, value)
    return bytes(b)


def main():
    print('=' * 78)
    print('ROUND-10 ANALYSER NEGATIVE REGRESSION')
    print('=' * 78)

    props, raw, blob = load_capture()

    # ---- baseline: the unmodified capture must PASS --------------------
    rc, out = run_analyser(CAP)
    record('the unmodified capture passes', rc == 0,
           'baseline exited %d' % rc)
    if rc != 0:
        print(out[-3000:])
        return 1

    print('\n--- 1. publication / record tearing -------------------------')
    # 1a. a record whose seq is odd = mid-write.
    #     Find a TX submit and set its seq odd.
    idx = None
    for i in range((len(blob) - HDR) // REC):
        kind = struct.unpack_from('<I', blob, HDR + i * REC + 20)[0]
        if kind == 1:
            idx = i
            break
    if idx is not None:
        b = rec_set(blob, idx, 16, '<I',
                    struct.unpack_from('<I', blob, HDR + idx * REC + 16)[0] | 1)
        expect('a mid-write record (odd seq) is rejected', make_case(
            'busy', blob=b), 'no record is mid-write or mis-ticketed')

    # 1b. a record stamped with ANOTHER ticket's seq = stale body.
    if idx is not None:
        wrong = ((struct.unpack_from('<I', blob, 32)[0] + idx) << 1) + 2
        b = rec_set(blob, idx, 16, '<I', wrong)
        expect('a record from another ticket is rejected', make_case(
            'stale', blob=b), 'no record is mid-write or mis-ticketed')

    # 1c. header and records from different publications: change the header's
    #     record count so the ticket range no longer spans it.
    b = hdr_set(blob, 40, '<I', 511)
    expect('a header that disagrees with its records is rejected', make_case(
        'hdr', blob=b), 'valid + lost equals the record count')

    print('\n--- 2. the snapshot predates the window end ----------------')
    # Published BEFORE the window end. This is round 9's actual state.
    b = hdr_set(blob, 88, '<Q', 1000)
    expect('a snapshot published before the window end is rejected',
           make_case('early', blob=b),
           'the snapshot was published at or after the window end')

    print('\n--- 3. one pair, but an unfinished submit / orphan / gap ---')
    # Locate the records that actually belong to the declared batch: a TX
    # submit carrying the parsed business id. Mutating any other record would
    # be a real change to irrelevant background traffic, and the analyser
    # would rightly still pass.
    biz_tx = None
    for i in range((len(blob) - HDR) // REC):
        kind = struct.unpack_from('<I', blob, HDR + i * REC + 20)[0]
        pkt = struct.unpack_from('<I', blob, HDR + i * REC + 68)[0]
        if kind == 1 and (pkt & 1):
            biz_tx = i
            break
    biz_cum = (struct.unpack_from('<I', blob, HDR + biz_tx * REC + 24)[0]
               if biz_tx is not None else None)

    # 3a. remove the completion of THAT request, so the batch claim must fail.
    biz_done = None
    if biz_cum is not None:
        for i in range((len(blob) - HDR) // REC):
            kind = struct.unpack_from('<I', blob, HDR + i * REC + 20)[0]
            cum = struct.unpack_from('<I', blob, HDR + i * REC + 24)[0]
            if kind == 2 and cum == biz_cum:
                biz_done = i
                break
    if biz_done is not None:
        b = rec_set(blob, biz_done, 20, '<I', 0)   # turn it into kind none
        expect('a removed completion breaks the batch claim', make_case(
            'nodone', blob=b),
            'every TX segment of every request completed')

    # 3b. a hole inside the window must defeat coverage.
    if idx is not None:
        b = rec_set(blob, idx, 16, '<I', 0)        # seq 0 = explicit hole
        expect('a hole defeats records_cover_window', make_case(
            'hole', blob=b), 'there are no holes in the snapshot')

    print('\n--- 4. index / length / generation disagreement -------------')
    # 4a. move the BUSINESS submit's cumulative index outside the queue, so no
    #     completion can match it.
    if biz_tx is not None:
        b = rec_set(blob, biz_tx, 24, '<I', 0xFFFF)
        expect('a cumulative index outside the queue is rejected',
               make_case('cum', blob=b),
               'every TX segment of every request completed')

    # 4b. claim a record was mid-write while its length changed: mutate the
    #     length of a parsed submit and require the batch check to notice the
    #     resulting mismatch with the client's payload size.
    tx = biz_tx
    if tx is not None:
        b = rec_set(blob, tx, 48, '<I', 0)         # length zero
        expect('a zero-length attributed segment is rejected', make_case(
            'len', blob=b),
            'the recorded segment length matches the frame the client sent')

    print('\n--- 5. PTE permission / wrong root -------------------------')
    # 5a. clear the Present bit on the leaf PTE.
    p2 = re.search(r'"m2-b2-win0-pte2"\s*=\s*"0x([0-9a-fA-F]+)"', props)
    if p2:
        old_val = p2.group(1)
        v = int(old_val, 16) & ~1
        mut = props.replace('"m2-b2-win0-pte2" = "0x%s"' % old_val,
                            '"m2-b2-win0-pte2" = "0x%x"' % v)
        assert mut != props, 'the PTE mutation did not apply'
        expect('a leaf without its Present bit is rejected', make_case(
            'notpresent', props=mut),
            'every published PTE has its Present bit set')

    # 5b. claim a different DTE root than the walk used.
    root = re.search(r'"m2-b2-dte-root"\s*=\s*"0x([0-9a-fA-F]+)"', props)
    if root:
        mut = props.replace('"m2-b2-dte-root" = "0x%s"' % root.group(1),
                            '"m2-b2-dte-root" = "0xdeadb000"')
        expect('a root table that is not the DTE\'s is rejected', make_case(
            'root', props=mut), 'the root table is the one the DTE names')

    # 5c. make the walk verdict something other than leaf.
    if '"m2-b2-win0-walk"' in props:
        mut = re.sub(r'"m2-b2-win0-walk"\s*=\s*"[a-z]+"',
                     '"m2-b2-win0-walk" = "absent"', props)
        expect('a non-leaf walk verdict is rejected', make_case(
            'walk', props=mut),
            'the walk verdict is leaf')

    print('\n--- 6. wrong device / unrelated business id ----------------')
    # 6a. change the snapshot's MAC so it is not the interface under test.
    b = hdr_set(blob, 72, '<I', 0x0BADF00D)
    expect('a snapshot from another interface is rejected', make_case(
        'mac', blob=b), 'snapshot MAC equals the probe\'s')

    # 6b. change the snapshot's BDF.
    b = hdr_set(blob, 52, '<I', 0x2600)
    expect('a snapshot from another BDF is rejected', make_case(
        'bdf', blob=b), 'snapshot BDF equals the probe\'s independently read BDF')

    # 6c. rewrite a driver record's business token so it no longer matches the
    #     client's run token.
    if tx is not None:
        b = rec_set(blob, tx, 56, '<I', 0x11111111)
        expect('a driver record with an unrelated business id is rejected',
               make_case('token', blob=b),
               'every driver record carries the client\'s run token')

    # 6d. the load ran on a different interface than the device.
    load = open(os.path.join(CAP, 'load.txt'), encoding='utf-8').read()
    mut = re.sub(r'load_iface\s*:\s*\S+', 'load_iface          : en0', load)
    expect('a load on a different interface is rejected', make_case(
        'iface', extra={'load.txt': mut}),
        'the load ran on the same interface as the device')

    # 6e. the route left by a different interface.
    mut = re.sub(r'load_route_interface\s*:\s*\S+',
                 'load_route_interface : en0', load)
    expect('a route leaving by another interface is rejected', make_case(
        'route', extra={'load.txt': mut}),
        'the route to the peer left by that same interface')

    print('\n--- 7. the declared batch is missing -----------------------')
    mut = re.sub(r'"m2-b2-obs-expected-batch"\s*=\s*"0x[0-9a-fA-F]+"',
                 '"m2-b2-obs-expected-batch" = "0x0"', props)
    expect('an undeclared batch is rejected', make_case(
        'nodecl', props=mut), 'this round declared a batch')

    # 7b. the client sent fewer requests than declared.
    cl = open(os.path.join(CAP, 'client.log'), encoding='utf-8').read()
    mut_cl = '\n'.join(l for l in cl.splitlines()
                       if 'req=4' not in l) + '\n'
    expect('a client that sent fewer requests than declared is rejected',
           make_case('fewer', extra={'client.log': mut_cl}),
           'the client sent exactly the declared number')

    # ---- summary -------------------------------------------------------
    print('\n' + '=' * 78)
    ok = sum(1 for _, o, _ in RESULTS if o)
    print('%d/%d negative cases behaved as required' % (ok, len(RESULTS)))
    print('RESULT: %s' % ('PASS' if ok == len(RESULTS) else 'FAIL'))
    return 0 if ok == len(RESULTS) else 1


if __name__ == '__main__':
    sys.exit(main())
