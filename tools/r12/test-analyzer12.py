#!/usr/bin/env python3
"""test-analyzer12.py -- negative suite for analyze-round12.py.

WHY THIS REPLACES ROUND 11'S SUITE
----------------------------------
Round 11's suite ran on a SYNTHETIC fixture. That is legitimate for exercising
the analyser, but it cannot tell you whether the analyser would have caught a
mutation of the REAL archive -- and eight mutations of the real archive still
scored 79/79.

WHAT "CAUGHT" MEANS -- AND WHAT ROUND 12 GOT WRONG
---------------------------------------------------
For every case, round 12 required:

  1. the run produces a STRUCTURED result (analysis.json);
  2. the named check id exists in it and has the expected state;
  3. the fixture bytes changed;
  4. every other newly failing check is declared in advance.

Round 13 (N6) adds the step that was missing and that let two cases score as
"caught" without testing anything:

  0. THE MUTATION MUST HAVE REACHED THE TARGET THE CHECK CONSUMES.

"the directory hash changed" is satisfied by editing a comment. Round 12's M3
case set `m2-b2-bwN-depth` to 0, which under the round-12 export is a field the
analyser never reads -- it derives the depth by counting the per-leaf
`m2-b2-bwN-leafM-pteK` properties. The case was scored as caught only because
the analyser was simultaneously failing for an unrelated reason. So each case
now re-reads the mutated input and asserts the SPECIFIC field or record the
check consumes has the new value, and a case that cannot do so is REFUSED.

THE CASES
---------
The eight round-11 survivors, plus the two round-13 counterexamples that the
round-12 analyser accepted:

    M1  seven of the eight walks deleted, leaving one
    M2  a walk's request id changed to 99
    M3  the per-leaf path removed (round 12 mutated an unread field)
    M4  a 74-byte range moved to start 16 bytes before a leaf end
    M5  dropped = 1
    M6  the event-log STATUS word at the window start zeroed   <- round 13
    M7  a command's completion value changed
    M8  the invalidation completion time moved after the window
    N1  the window STATUS words zeroed (the round-12 analyser ignored them)
    N2  the range address moved 16 bytes before its leaf, PTEs and leaf-from
        left alone (the round-12 analyser accepted it)
    N3  the window STATUS words deleted entirely
    N4  the leaf's `from` moved to disagree with the range cursor

A case that crashes, times out, or produces no JSON is a REFUSAL, not a pass.

Usage: python3 tools/r12/test-analyzer12.py <real-capture> [<fixture>]
"""
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
ANALYZER = os.path.join(ROOT, 'tools', 'analyze-round12.py')
WORK = os.path.join(ROOT, 'build-work-r13', 'cases')

HDR_BYTES = 104
REC_BYTES = 72

KIND_TX_SUBMIT = 1
KIND_TX_DONE = 2
KIND_RX_DONE = 3


def rmtree_force(path):
    """Remove a tree, clearing read-only bits first.

    WHY: this suite runs on Windows as well as on the Mac. A directory copied
    from the archive inherits whatever attributes the archive carried, and on
    Windows a read-only attribute makes `shutil.rmtree` fail with WinError 5 --
    which aborted the whole suite at the point where it should have been
    rebuilding its scratch directory. A cleanup failure must not be reported as
    a test failure.
    """
    def onerror(func, p, _exc):
        try:
            os.chmod(p, 0o777)
        except OSError:
            pass
        try:
            func(p)
        except OSError:
            pass

    if os.path.isdir(path):
        shutil.rmtree(path, onerror=onerror)


def sha_dir(d):
    h = hashlib.sha256()
    for name in sorted(os.listdir(d)):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            h.update(name.encode())
            h.update(open(p, 'rb').read())
    return h.hexdigest()


def prop_edit(text, key, value):
    pat = re.compile(r'("%s"\s*=\s*)"[^"]*"' % re.escape(key))
    if not pat.search(text):
        return None
    return pat.sub(lambda m: m.group(1) + '"%s"' % value, text, count=1)


def hexprop_edit(text, key, value):
    pat = re.compile(r'("%s"\s*=\s*)"0x[0-9a-fA-F]+"' % re.escape(key))
    if not pat.search(text):
        return None
    return pat.sub(lambda m: m.group(1) + '"0x%x"' % value, text, count=1)


def get_hexprop(text, key):
    m = re.search(r'"%s"\s*=\s*"0x([0-9a-fA-F]+)"' % re.escape(key), text)
    return int(m.group(1), 16) if m else None


def get_strprop(text, key):
    m = re.search(r'"%s"\s*=\s*"([^"]*)"' % re.escape(key), text)
    return m.group(1) if m else None


def del_prop(text, key):
    pat = re.compile(r'[ \t]*"%s"\s*=\s*"[^"]*"\n' % re.escape(key))
    if not pat.search(text):
        return None
    return pat.sub('', text, count=1)


class Case:
    def __init__(self, name, cid, want_state, allows=(), doc='',
                 needs_event=False, needs_snapshot=False):
        self.name = name
        self.cid = cid
        self.want_state = want_state
        self.allows = set(allows)
        self.doc = doc
        # A case may need evidence this input does not carry. Rather than skip
        # it silently, the suite reports it N/A for THAT input and runs it
        # against the other one. A skipped case is never counted as caught.
        self.needs_event = needs_event
        self.needs_snapshot = needs_snapshot


# ---------------------------------------------------------------------------
# THE MUTATIONS
# ---------------------------------------------------------------------------
CASES = [
    Case('M1-seven-of-eight-walks-deleted', 'pt-count', 'fail',
         allows={'the export matches the expected range set',
                 '=> the business DMA ranges have complete page-table evidence',
                 "the probe's ok/fail counters agree with the export size",
                 'every business range is fully covered by legal leaves',
                 'every range has the permission its direction needs'},
         doc='only one of the eight ranges is exported', needs_snapshot=True),

    Case('M2-walk-request-id-99', 'pt-count', 'fail',
         allows={'the export matches the expected range set',
                 '=> the business DMA ranges have complete page-table evidence'},
         doc='a walk claims request 99, which no record supports',
         needs_snapshot=True),

    # ROUND 13 (N5): round 12 zeroed `m2-b2-bwN-depth`, which the analyser does
    # not read. This removes the per-leaf path, which it does.
    Case('M3-per-leaf-path-removed', 'pt-covered', 'fail',
         allows={'every business range is fully covered by legal leaves',
                 '=> the business DMA ranges have complete page-table evidence',
                 "the probe's covered/perm-ok summaries agree with the "
                 'recomputation',
                 'every range has the permission its direction needs',
                 'the export matches the expected range set'},
         doc='a leaf path with no levels is not a path', needs_snapshot=True),

    Case('M4-range-crosses-leaf-without-evidence', 'pt-covered', 'fail',
         allows={'every business range is fully covered by legal leaves',
                 '=> the business DMA ranges have complete page-table evidence',
                 "the probe's covered/perm-ok summaries agree with the "
                 'recomputation',
                 'every range has the permission its direction needs',
                 'the export matches the expected range set'},
         doc='the 74-byte range starts 16 bytes before a leaf end and the next '
             'leaf has no evidence', needs_snapshot=True),

    Case('M5-dropped-1', 'loss-dropped', 'fail',
         allows={'no writer dropped a record',
                 "the probe's dropped/lost counters equal the header's",
                 'the exported blob matches the probe-published sha256',
                 'the archived file matches the probe-published sha256'},
         doc='a snapshot that lost a record cannot be complete',
         needs_snapshot=True),

    Case('M6-event-entry-status-zeroed', 'evt-entry-status', 'fail',
         allows={},
         doc='an event ENTRY whose status field is zero is not a valid entry',
         needs_event=True, needs_snapshot=True),

    Case('M7-command-completion-changed', 'cmd-expected-eq-observed', 'fail',
         doc='a command whose observed completion differs from its expected '
             'value did not complete', needs_snapshot=True),

    Case('M8-invalidation-after-window', 'tl-order', 'fail',
         allows={'the timeline is ordered',
                 'every business record falls inside the translation window'},
         doc='translation cannot have become effective after the window opened',
         needs_snapshot=True),

    # ---- ROUND 13: the two counterexamples the round-12 analyser ACCEPTED ----
    #
    # These are the cases that matter most, because they are the ones that
    # passed. Setting both window STATUS words to 0 in a copy of the passing
    # 20261101-014200 archive produced 97 ok / 0 failed and
    # "finite DMA translation evidence: YES".
    Case('N1-window-status-zeroed', 'win-status-run-start', 'fail',
         allows={'EVT_RUN was set at the window start',
                 'EVT_RUN was still set at the window end'},
         doc='zeroing the raw window STATUS words must not pass; the round-12 '
             'analyser never read them', needs_snapshot=True),

    Case('N2-window-status-deleted', 'win-status-present', 'fail',
         allows={'both window STATUS words were published',
                 # With the words gone, the two EVT_RUN terms cannot be
                 # established either. That is the same missing fact seen from
                 # two angles, not an independent side effect.
                 'EVT_RUN was set at the window start',
                 'EVT_RUN was still set at the window end',
                 'the event ring did not overflow at either end'},
         doc='a capture with no window STATUS words cannot establish that the '
             'event log was running', needs_snapshot=True),

    # The exact counterexample from the task: req 1 TX address moved 16 bytes
    # before its 2 MiB leaf, with the old PTE and the old leaf0-from kept, and
    # the snapshot + both OSData copies + the published sha256 all updated so
    # the only thing wrong is that no exported path covers the first 16 bytes.
    Case('N3-range-starts-before-its-leaf', 'pt-covered', 'fail',
         allows={'every business range is fully covered by legal leaves',
                 '=> the business DMA ranges have complete page-table evidence',
                 "the probe's covered/perm-ok summaries agree with the "
                 'recomputation',
                 'every range has the permission its direction needs',
                 'the export matches the expected range set',
                 'the exported blob matches the probe-published sha256',
                 'the archived file matches the probe-published sha256'},
         doc='the range begins before the leaf the export proves; round 12 '
             'derived the index from the export instead of the cursor',
         needs_snapshot=True),

    Case('N4-leaf-from-disagrees-with-cursor', 'pt-covered', 'fail',
         allows={'every business range is fully covered by legal leaves',
                 '=> the business DMA ranges have complete page-table evidence',
                 "the probe's covered/perm-ok summaries agree with the "
                 'recomputation',
                 'every range has the permission its direction needs',
                 'the export matches the expected range set'},
         doc='leafN-from must equal the cursor the walk has reached',
         needs_snapshot=True),
]


def run_analyzer(cap, outdir):
    r = subprocess.run([sys.executable, ANALYZER, cap, outdir],
                       capture_output=True, text=True)
    j = os.path.join(outdir, 'analysis.json')
    data = None
    if os.path.exists(j):
        data = json.load(open(j))
    return r, data


def states(data):
    return {c['id']: c['state'] for c in data['checks']}


def names(data):
    return {c['id']: c['name'] for c in data['checks']}


def find_biz_record(blob, req_id, kind):
    """Locate a record by its BUSINESS id, not by its index.

    WHY THIS MATTERS
    ----------------
    Round 11's suite removed "the first tx-done record", which was a
    BACKGROUND completion with cumulative index 0 -- not the business one. The
    case then failed to reproduce the intended situation, and the suite
    reported 14/15 for the wrong reason. Mutations must locate their target by
    the identity the check is about.
    """
    n = (len(blob) - HDR_BYTES) // REC_BYTES
    for i in range(n):
        off = HDR_BYTES + i * REC_BYTES
        k = struct.unpack_from('<I', blob, off + 20)[0]
        r = struct.unpack_from('<I', blob, off + 60)[0]
        if k == kind and r == req_id:
            return i, off
    return None, None


def rewrite_blob(d, blob, text):
    """Write the mutated snapshot and make BOTH OSData copies and the sha256
    agree with it, so a case is never caught merely by a hash mismatch.

    Round 12's M5 deliberately left the hash stale and DECLARED the hash check
    as an allowed cascade. That is fine for a loss mutation, but a geometric
    mutation must not be catchable by "the bytes changed": the point is that
    the PTEs no longer cover the range.
    """
    snap = os.path.join(d, 'obs-snapshot-used.bin')
    open(snap, 'wb').write(blob)
    new_sha = hashlib.sha256(blob).hexdigest()
    rawp = os.path.join(d, 'props.raw.txt')
    raw = open(rawp, encoding='utf-8', errors='replace').read()
    # Replace every OSData blob that is large enough to be the snapshot. The
    # probe node's `m2-b2-obs-snapshot-used` and the driver node's
    # `rtl812x-obs-snapshot` are both the same bytes in these captures.
    raw2, n = re.subn(r'<[0-9a-fA-F]{200,}>', '<' + blob.hex() + '>', raw)
    open(rawp, 'w', encoding='utf-8').write(raw2)
    text2 = re.sub(r'("m2-b2-obs-used-sha256"\s*=\s*)"[0-9a-f]*"',
                   lambda m: m.group(1) + '"%s"' % new_sha, text, count=1)
    return text2, new_sha, n


def mutate(case, d, text):
    """Apply this case's mutation.

    Returns (new_props_text, applied, verify) where `verify` is a callable that
    re-reads the mutated input and asserts the TARGET really changed. A case
    whose verify returns False is REFUSED, never counted as caught.
    """
    if case.name == 'M1-seven-of-eight-walks-deleted':
        out = text
        for i in range(1, 8):
            for suffix in ('req', 'dir', 'seg', 'addr', 'len', 'depth',
                           'leaf-pa', 'leaf-size', 'leaf-level', 'covered',
                           'perm-ok', 'pages', 'pages-bad', 'why',
                           'root-pa', 'root-level', 'dte', 'leaves'):
                out = del_prop(out, 'm2-b2-bw%d-%s' % (i, suffix)) or out
            for li in range(4):
                for s in ('pa', 'size', 'from', 'bytes'):
                    out = del_prop(out, 'm2-b2-bw%d-leaf%d-%s'
                                   % (i, li, s)) or out
                for L in range(6):
                    for s in ('table', 'index', 'level', ''):
                        key = 'm2-b2-bw%d-leaf%d-pte%d' % (i, li, L)
                        if s:
                            key += '-' + s
                        out = del_prop(out, key) or out
            for L in range(6):
                for s in ('table', 'index', 'level', ''):
                    key = 'm2-b2-bw%d-pte%d' % (i, L)
                    if s:
                        key += '-' + s
                    out = del_prop(out, key) or out
        if out == text:
            return None, False, None
        out = hexprop_edit(out, 'm2-b2-bizwalk-count', 1) or out

        def verify():
            t = open(os.path.join(d, 'props.txt'), encoding='utf-8').read()
            return (get_hexprop(t, 'm2-b2-bizwalk-count') == 1 and
                    get_hexprop(t, 'm2-b2-bw1-addr') is None and
                    get_hexprop(t, 'm2-b2-bw0-addr') is not None)
        return out, True, verify

    if case.name == 'M2-walk-request-id-99':
        v = get_hexprop(text, 'm2-b2-bw0-req')
        if v is None:
            return None, False, None
        out = hexprop_edit(text, 'm2-b2-bw0-req', 99)

        def verify():
            t = open(os.path.join(d, 'props.txt'), encoding='utf-8').read()
            return get_hexprop(t, 'm2-b2-bw0-req') == 99
        return out, True, verify

    if case.name == 'M3-per-leaf-path-removed':
        # ROUND 13 (N5): the analyser derives the depth by counting
        # `m2-b2-bwN-leafM-pteK`, so THAT is the input to break. Round 12 zeroed
        # `m2-b2-bwN-depth`, which nothing reads any more.
        out = text
        for L in range(6):
            for s in ('table', 'index', 'level', ''):
                key = 'm2-b2-bw0-leaf0-pte%d' % L
                if s:
                    key += '-' + s
                out = del_prop(out, key) or out
        if out == text:
            return None, False, None

        def verify():
            t = open(os.path.join(d, 'props.txt'), encoding='utf-8').read()
            return (get_hexprop(t, 'm2-b2-bw0-leaf0-pte0') is None and
                    get_hexprop(t, 'm2-b2-bw0-leaf0-pa') is not None and
                    # the LEGACY alias is untouched, so the case cannot be
                    # caught by "the whole export vanished"
                    get_hexprop(t, 'm2-b2-bw0-pte0') is not None)
        return out, True, verify

    if case.name == 'M4-range-crosses-leaf-without-evidence':
        leaf_pa = get_hexprop(text, 'm2-b2-bw0-leaf0-pa')
        leaf_size = get_hexprop(text, 'm2-b2-bw0-leaf0-size')
        if leaf_pa is None or leaf_size is None:
            leaf_pa = get_hexprop(text, 'm2-b2-bw0-leaf-pa')
            leaf_size = get_hexprop(text, 'm2-b2-bw0-leaf-size')
        if leaf_pa is None or leaf_size is None:
            return None, False, None
        new_addr = leaf_pa + leaf_size - 16
        out = hexprop_edit(text, 'm2-b2-bw0-addr', new_addr)

        def verify():
            t = open(os.path.join(d, 'props.txt'), encoding='utf-8').read()
            return get_hexprop(t, 'm2-b2-bw0-addr') == new_addr
        return out, True, verify

    if case.name == 'M5-dropped-1':
        snap = os.path.join(d, 'obs-snapshot-used.bin')
        if not os.path.exists(snap):
            return None, False, None
        blob = bytearray(open(snap, 'rb').read())
        before = bytes(blob)
        struct.pack_into('<I', blob, 24, 1)     # header.dropped
        if bytes(blob) == before:
            return None, False, None
        open(snap, 'wb').write(bytes(blob))
        rawp = os.path.join(d, 'props.raw.txt')
        raw = open(rawp, encoding='utf-8', errors='replace').read()
        raw = re.sub(r'("m2-b2-obs-snapshot-used"\s*=\s*)<[0-9a-fA-F]*>',
                     lambda m: m.group(1) + '<' + bytes(blob).hex() + '>',
                     raw, count=1)
        open(rawp, 'w', encoding='utf-8').write(raw)
        out = hexprop_edit(text, 'm2-b2-obs-dropped', 1)

        def verify():
            b = open(snap, 'rb').read()
            t = open(os.path.join(d, 'props.txt'), encoding='utf-8').read()
            return (struct.unpack_from('<I', b, 24)[0] == 1 and
                    get_hexprop(t, 'm2-b2-obs-dropped') == 1)
        return out, True, verify

    if case.name == 'M6-event-entry-status-zeroed':
        n_raw = get_hexprop(text, 'm2-b2-win-raw-count') or 0
        if n_raw == 0:
            return None, False, None
        v = get_strprop(text, 'm2-b2-win-raw0')
        if v is None or len(v) != 32:
            return None, False, None
        words = [v[j * 8:(j + 1) * 8] for j in range(4)]
        # Zero the status field (bits 27:16 of word 1) but keep the event type
        # (bits 31:28), so the record still decodes as the same event with an
        # impossible status.
        #
        # The width is 8 hex digits, not 16: each word is 32 bits and the
        # property is the concatenation of four of them. Formatting with %016x
        # produced a 40-character string, which is not a valid raw event -- the
        # analyser refused to decode it and the case then failed for the WRONG
        # reason. A mutation must produce a WELL-FORMED record with one
        # targeted field wrong, or it tests the decoder rather than the check.
        w1 = int(words[1], 16)
        w1 = (w1 & ~(0xFFF << 16)) & 0xFFFFFFFF
        words[1] = '%08x' % w1
        newv = ''.join(words)
        out = prop_edit(text, 'm2-b2-win-raw0', newv)

        def verify():
            t = open(os.path.join(d, 'props.txt'), encoding='utf-8').read()
            got = get_strprop(t, 'm2-b2-win-raw0')
            return (got == newv and len(got) == 32 and
                    ((int(got[8:16], 16) >> 16) & 0xFFF) == 0 and
                    ((int(got[8:16], 16) >> 28) & 0xF) != 0)
        return out, True, verify

    if case.name == 'M7-command-completion-changed':
        n = get_hexprop(text, 'm2-b2-cmd-record-count') or 0
        if n == 0:
            return None, False, None
        obs = get_hexprop(text, 'm2-b2-cmd1-observed')
        if obs is None:
            return None, False, None
        out = hexprop_edit(text, 'm2-b2-cmd1-observed', obs + 1)

        def verify():
            t = open(os.path.join(d, 'props.txt'), encoding='utf-8').read()
            return (get_hexprop(t, 'm2-b2-cmd1-observed') == obs + 1 and
                    get_hexprop(t, 'm2-b2-cmd1-expected') == obs)
        return out, True, verify

    if case.name == 'M8-invalidation-after-window':
        we = get_hexprop(text, 'm2-b2-dma-t-win-end')
        if we is None:
            return None, False, None
        out = hexprop_edit(text, 'm2-b2-dma-t-inv-complete', we + 1000)
        out = hexprop_edit(out, 'm2-b2-dma-t-translate-on', we + 1000)

        def verify():
            t = open(os.path.join(d, 'props.txt'), encoding='utf-8').read()
            return (get_hexprop(t, 'm2-b2-dma-t-inv-complete') == we + 1000 and
                    get_hexprop(t, 'm2-b2-dma-t-translate-on') == we + 1000)
        return out, True, verify

    if case.name == 'N1-window-status-zeroed':
        s = get_hexprop(text, 'm2-b2-win-status-start')
        e = get_hexprop(text, 'm2-b2-win-status-end')
        if s is None or e is None:
            return None, False, None
        out = hexprop_edit(text, 'm2-b2-win-status-start', 0)
        out = hexprop_edit(out, 'm2-b2-win-status-end', 0)

        def verify():
            t = open(os.path.join(d, 'props.txt'), encoding='utf-8').read()
            return (get_hexprop(t, 'm2-b2-win-status-start') == 0 and
                    get_hexprop(t, 'm2-b2-win-status-end') == 0 and
                    # the ORIGINAL words really did have EVT_RUN, so the
                    # mutation removed a fact rather than confirming an absence
                    bool(s & (1 << 3)) and bool(e & (1 << 3)))
        return out, True, verify

    if case.name == 'N2-window-status-deleted':
        out = del_prop(text, 'm2-b2-win-status-start')
        out = out and del_prop(out, 'm2-b2-win-status-end')

        def verify():
            t = open(os.path.join(d, 'props.txt'), encoding='utf-8').read()
            return (get_hexprop(t, 'm2-b2-win-status-start') is None and
                    get_hexprop(t, 'm2-b2-win-status-end') is None and
                    # the window's OTHER fields must survive, or the case
                    # would be caught by "the window vanished"
                    get_hexprop(t, 'm2-b2-dma-t-win-start') is not None)
        return out, True, verify

    if case.name == 'N3-range-starts-before-its-leaf':
        # The exact counterexample: req 1 TX, address moved 16 bytes before the
        # 2 MiB leaf base, len unchanged, PTE and leaf0-from left at the old
        # value, and the snapshot + hashes updated so nothing is caught by a
        # hash mismatch.
        snap = os.path.join(d, 'obs-snapshot-used.bin')
        if not os.path.exists(snap):
            return None, False, None
        blob = bytearray(open(snap, 'rb').read())
        idx, off = find_biz_record(blob, 1, KIND_TX_SUBMIT)
        if off is None:
            return None, False, None
        old_addr = struct.unpack_from('<Q', blob, off + 8)[0]
        leaf_pa = get_hexprop(text, 'm2-b2-bw0-leaf0-pa')
        if leaf_pa is None:
            leaf_pa = get_hexprop(text, 'm2-b2-bw0-leaf-pa')
        if leaf_pa is None:
            return None, False, None
        new_addr = leaf_pa - 16
        struct.pack_into('<Q', blob, off + 8, new_addr)
        blob = bytes(blob)
        text2, new_sha, nblob = rewrite_blob(d, blob, text)
        if nblob == 0:
            return None, False, None
        out = hexprop_edit(text2, 'm2-b2-bw0-addr', new_addr)

        def verify():
            b = open(os.path.join(d, 'obs-snapshot-used.bin'), 'rb').read()
            _i, o = find_biz_record(b, 1, KIND_TX_SUBMIT)
            t = open(os.path.join(d, 'props.txt'), encoding='utf-8').read()
            return (o is not None and
                    struct.unpack_from('<Q', b, o + 8)[0] == new_addr and
                    get_hexprop(t, 'm2-b2-bw0-addr') == new_addr and
                    # leaf0-from still names the OLD address: that is the
                    # defect, not an accident
                    get_hexprop(t, 'm2-b2-bw0-leaf0-from') == old_addr and
                    get_hexprop(t, 'm2-b2-bw0-leaf0-pa') == leaf_pa)
        return out, True, verify

    if case.name == 'N4-leaf-from-disagrees-with-cursor':
        # Move the exported `leaf0-from` one byte forward. The PTEs are
        # untouched and still cover the whole range, so only the
        # "the export's claim is the cursor" comparison can catch it.
        addr = get_hexprop(text, 'm2-b2-bw0-addr')
        frm = get_hexprop(text, 'm2-b2-bw0-leaf0-from')
        if addr is None or frm is None:
            return None, False, None
        out = hexprop_edit(text, 'm2-b2-bw0-leaf0-from', frm + 1)

        def verify():
            t = open(os.path.join(d, 'props.txt'), encoding='utf-8').read()
            return (get_hexprop(t, 'm2-b2-bw0-leaf0-from') == frm + 1 and
                    get_hexprop(t, 'm2-b2-bw0-addr') == addr and
                    get_hexprop(t, 'm2-b2-bw0-leaf0-pa') is not None)
        return out, True, verify

    return None, False, None


def run_suite(label, base):
    print()
    print('=' * 78)
    print('SUITE: %s' % label)
    print('baseline: %s' % base)
    print('=' * 78)

    bdir = os.path.join(WORK, label + '-baseline')
    r, data = run_analyzer(base, bdir)
    if data is None:
        print('REFUSED: the baseline produced no structured result.')
        print(r.stdout[-1200:])
        print(r.stderr[-1200:])
        return 0, len(CASES), ['baseline-refused'], []
    base_states = states(data)
    base_names = names(data)
    base_fail = [k for k, v in base_states.items() if v == 'fail']
    if base_fail:
        print('REFUSED: the baseline already fails:')
        for k in base_fail:
            print('  - %s (%s)' % (k, base_names.get(k)))
        return 0, len(CASES), ['baseline-fails'], []

    # A duplicate check id is a hard error in the analyser, but verify it here
    # too: the whole point of stable ids is that one result cannot overwrite
    # another.
    ids = [c['id'] for c in data['checks']]
    if len(ids) != len(set(ids)):
        print('REFUSED: the analyser emitted duplicate check ids')
        return 0, len(CASES), ['duplicate-ids'], []

    print('  baseline: %d checks, 0 failed, %d N/A'
          % (len(base_states),
             sum(1 for v in base_states.values() if v == 'na')))
    print()

    # What evidence does this input carry? A case that needs evidence the input
    # does not have is reported N/A for THIS input, never counted as caught.
    bt = open(os.path.join(base, 'props.txt'), encoding='utf-8',
              errors='replace').read()
    has_event = (get_hexprop(bt, 'm2-b2-win-raw-count') or 0) > 0
    has_snapshot = os.path.exists(os.path.join(base, 'obs-snapshot-used.bin'))

    ok_count = 0
    bad = []
    inapplicable = []
    for c in CASES:
        if c.needs_event and not has_event:
            print('  %-42s N/A: no raw event in this input (win-raw-count=0)'
                  % c.name)
            inapplicable.append(c.name)
            continue
        if c.needs_snapshot and not has_snapshot:
            print('  %-42s N/A: no probe-used snapshot in this input'
                  % c.name)
            inapplicable.append(c.name)
            continue

        d = os.path.join(WORK, label + '-' + c.name)
        shutil.copytree(base, d)
        props_path = os.path.join(d, 'props.txt')
        before = sha_dir(d)

        text = open(props_path, encoding='utf-8', errors='replace').read()
        new, applied, verify = mutate(c, d, text)
        if not applied or new is None or verify is None:
            print('  %-42s REFUSED: the mutation did not apply' % c.name)
            bad.append(c.name)
            continue
        if new != text:
            open(props_path, 'w', encoding='utf-8').write(new)

        # ROUND 13 (N6): THE TARGET, NOT THE DIRECTORY HASH.
        if not verify():
            print('  %-42s REFUSED: the mutation did not reach the field the '
                  'check consumes' % c.name)
            bad.append(c.name)
            continue
        after = sha_dir(d)
        if after == before:
            print('  %-42s REFUSED: the fixture bytes are unchanged' % c.name)
            bad.append(c.name)
            continue

        odir = os.path.join(WORK, label + '-' + c.name + '-out')
        r, data = run_analyzer(d, odir)
        if data is None:
            print('  %-42s REFUSED: no structured result (crash or bad input)'
                  % c.name)
            print('      stderr: %s' % r.stderr.strip()[:200])
            bad.append(c.name)
            continue

        st = states(data)
        nm = names(data)
        got = st.get(c.cid)
        if got != c.want_state:
            print('  %-42s NOT CAUGHT: %r is %r, wanted %r'
                  % (c.name, c.cid, got, c.want_state))
            bad.append(c.name)
            continue

        unexpected = [k for k, v in st.items()
                      if v == 'fail' and base_states.get(k) == 'ok'
                      and k != c.cid and k not in c.allows
                      and nm.get(k) not in c.allows]
        if unexpected:
            print('  %-42s CAUGHT but UNEXPLAINED side effects: %s'
                  % (c.name, [(k, nm.get(k)) for k in unexpected[:3]]))
            bad.append(c.name)
            continue

        declared = sorted(k for k in c.allows
                          if st.get(k) == 'fail' or
                          any(nm.get(x) == k and st.get(x) == 'fail'
                              for x in st))
        print('  %-42s CAUGHT  (%s -> %s)%s'
              % (c.name, c.cid, got,
                 '  [+%d declared cascade]' % len(declared) if declared else ''))
        ok_count += 1

    if inapplicable:
        print()
        print('  NOT APPLICABLE to this input: %s' % inapplicable)
        print('  These are reported, not counted as caught. The suite is only')
        print('  complete when every case runs against an input that carries')
        print('  the evidence it mutates.')
    return ok_count, len(CASES), bad, inapplicable


def main():
    if len(sys.argv) < 2:
        print('usage: test-analyzer12.py <real-capture> [<fixture>]')
        return 2
    real = sys.argv[1]
    fixture = sys.argv[2] if len(sys.argv) > 2 else None
    if not os.path.isdir(real):
        print('no such capture: %s' % real)
        return 2

    rmtree_force(WORK)
    os.makedirs(WORK)

    print('=' * 78)
    print('ROUND-12/13 ANALYSER NEGATIVE SUITE')
    print('=' * 78)
    print('  Each case mutates a COPY and requires a SPECIFIC check id to fail.')
    print('  A case that crashes or produces no JSON is a refusal, not a pass.')
    print('  A case whose mutation did not reach the field the check consumes')
    print('  is also a refusal -- that is the round-12 M3 defect.')

    results = {}
    results['real'] = run_suite('real', real)
    if fixture and os.path.isdir(fixture):
        results['fixture'] = run_suite('fixture', fixture)

    print()
    print('=' * 78)
    print('RESULT')
    print('=' * 78)
    total_ok = total_n = 0
    bad = []
    for label in ('real', 'fixture'):
        if label not in results:
            continue
        ok, n, b, na = results[label]
        total_ok += ok
        total_n += n
        bad += ['%s/%s' % (label, x) for x in b]
        print('  %-8s %d/%d caught, %d N/A%s'
              % (label, ok, n, len(na), '' if not b else '   problems: %s' % b))

    print()
    covered = set()
    for label in results:
        ok, n, b, na = results[label]
        covered.add('%s:%d/%d' % (label, ok, n))
    all_cases = all(results[label][0] + len(results[label][3]) == len(CASES)
                    for label in results)
    print('  per-input coverage: %s' % ', '.join(sorted(covered)))
    print('  every case is covered by the suite as a whole: %s'
          % ('YES' if all_cases else 'NO'))
    if 'real' in results and results['real'][3]:
        print('  on the REAL archive, %d case(s) are N/A because the capture'
              % len(results['real'][3]))
        print('  carries no evidence of that kind: %s' % results['real'][3])
        print('  They run on the fixture instead. Neither input alone can')
        print('  exercise every case; the union can, and the split is reported.')
    print('  RESULT: %s' % ('ALL CASES BEHAVE CORRECTLY' if not bad
                            else 'FAILURES: %s' % bad))
    return 0 if not bad else 1


if __name__ == '__main__':
    sys.exit(main())
