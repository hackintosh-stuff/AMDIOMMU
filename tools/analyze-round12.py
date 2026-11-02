#!/usr/bin/env python3
"""analyze-round12.py -- independently recompute the round-11/12 controlled chain.

WHAT "INDEPENDENT" MEANS HERE
-----------------------------
This script reads ONLY raw capture files. It does not use `m2-b2-verdict`,
`m2-b2-obs-*-complete`, `window-complete`, `bizwalk`, `covered`, `perm-ok` or
any other self-reported summary as the BASIS of a pass. Summaries are compared
AGAINST the recomputation, never used in place of it.

WHAT CHANGED FROM ROUND 11 (and why each change is a rejected false pass)
-------------------------------------------------------------------------
R1  Eight mutations of the REAL round-11 archive still scored 79/79:
      * seven of the eight walks deleted, leaving one
      * a walk's request id changed to 99
      * every walk depth set to 0
      * a 74-byte range moved to start 16 bytes before a leaf end, with no
        evidence for the next leaf
      * dropped = 1
      * an event's raw status word zeroed
      * a command's completion value changed
      * the invalidation completion time moved after the window
    Each of them is now a required negative case (tools/r12/test-analyzer12.py)
    and each fails on a SPECIFIC check, not on "something went wrong".

R2  `covered`/`perm-ok`/`bizwalk` were read as conclusions. They are now only
    cross-checked against a recomputation from the raw PTEs; the verdict comes
    from the recomputation.

R3  The walk covered the first page of a range. Round 12 walks the whole
    [addr, addr+len), requires every leaf it uses to be exported, and requires
    the exported leaves to account for every byte. A range whose second leaf is
    missing is NOT covered.

R4  `dropped`, `wrapped`, `lostCount` and the header flags were decoded and
    then ignored. They are now gate terms.

R5  Mode handling: `control-sleep-only` is a DIFFERENT experiment whose stages
    never execute. Round 11 reported those stages as N/A by appending a
    same-named record, which OVERWROTE the earlier result instead of adding an
    N/A. Now the mode is detected FIRST, each check has a stable unique id, and
    the applicable set is chosen by mode.

R6  The control fixture was a complete translation capture with one property
    changed, which is not what the production control branch produces. Round 12
    builds a control fixture that has the real missing-field shape.

ROUND 13 -- SIX DEFECTS THAT SURVIVED ROUND 12'S OWN SUITE
----------------------------------------------------------
N1  THE RAW WINDOW STATE WAS NEVER READ. `m2-b2-win-status-start` and
    `m2-b2-win-status-end` are the AMD-Vi event-log STATUS words sampled at the
    two ends of the measurement window, and `m2b2SampleEvents()` refuses the
    window when EVT_RUN is clear or EVT_OVERFLOW is set at either end. The
    analyser read neither: setting both to 0x0 in a copy of the passing
    20261101-014200 archive still produced 97 ok / 0 failed and
    "finite DMA translation evidence: YES". The `evt-status` check that DID
    exist looks at the status field inside an EVENT ENTRY, which is a different
    register and a different question -- and it is N/A whenever the window
    recorded no events, which is exactly this archive. The raw window state is
    now recomputed here from the two words, unconditionally, including for a
    zero-event window; the entry-level check keeps its own accurate name.

N2  `recompute_range()` USED THE EXPORTED `leafN-from` AND THE RUNNING CURSOR
    AS IF THEY WERE THE SAME THING. The index was derived from `leafN-from`,
    containment and identity were checked against `leafN-from`, and the covered
    byte count was advanced from `cur`. Nothing tied the two together, so a
    range whose first 16 bytes have no exported path still passed: move the
    business address of the first TX record from 0x3e0a17db6 to 0x3e09ffff0
    (16 bytes before the 2 MiB leaf base 0x3e0a00000), leave the old PTEs and
    `leaf0-from` in place, and the round-12 analyser reported
    "bw0 req=1 tx 0x3e09ffff0+74 OK leaves=1 bytes=74" -- a full pass for a
    range it had not proved. The cursor is now the only source of the index,
    the exported `leafN-from` must equal it, the decoded leaf must map the
    cursor to itself, and the step must be exactly what the leaf boundary and
    the range end imply.

N3  CONTROL MODE STILL NEEDED A PROBE-USED SNAPSHOT. The production control
    branch takes `goto recover` after its sleep, so `m2b2ReadDriverObs()` never
    runs and no `m2-b2-obs-snapshot-used` exists. The round-12 fixture
    synthesised one, and with it removed the analyser exited 2 without writing
    analysis.json -- a refusal to judge a legitimate control capture. The
    execution path is now chosen by mode BEFORE any snapshot is loaded or
    decoded, a control capture is judged from what the control branch really
    publishes, and the driver's own `rtl812x-obs-snapshot` is never substituted
    for the probe's.

N4  THE CONTROL FIXTURE DELETED FIELDS THE CONTROL BRANCH REALLY PUBLISHES.
    Step 19 runs on the `recover` path, so a control run DOES publish
    `m2-b2-stage-inv-all` / `-inv-dev` / `-inv-pages`, the command records from
    step 18.1b, `m2-b2-t-recovery-start` and the control stage's own timing.
    The round-12 fixture dropped them, which made the control schema assert an
    absence that does not exist and left the control verdict resting on the
    mode string alone.

N5  THE M3 MUTATION MISSED. It set `m2-b2-bwN-depth` to 0, but the round-12
    export publishes the per-leaf path as `m2-b2-bwN-leafM-pteK`, and the
    analyser derives the depth by counting those. The mutation therefore
    changed a field nothing read, and the case was scored as caught only
    because the analyser was simultaneously failing for an unrelated reason.
    It now removes the per-leaf path, which is the input the check actually
    consumes.

N6  A CASE COULD BE SCORED WITHOUT PROVING THE MUTATION REACHED ITS TARGET.
    "the directory hash changed" is satisfied by editing a comment. Every case
    now re-reads the mutated input and asserts that the SPECIFIC field or
    record the check consumes has the new value.

MODES
-----
`control-sleep-only` (the probe's own name for the control branch) and
`translation` are different experiments with different required fields. In
control mode the stages that do not execute are reported N/A, not PASS, and not
FAIL, and the script REFUSES to print "finite DMA translation evidence: YES".
In translation mode a missing required field is a REJECT: the schema says it
must be there.

Exit codes
----------
  0  every applicable check passed
  1  at least one applicable check failed
  2  the input is unusable (no snapshot to analyse, unreadable props) -- a
     refusal, not a verdict
"""
import hashlib
import json
import os
import re
import struct
import sys

HDR_BYTES = 104
REC_BYTES = 72
OBS_MAGIC = 0x324F4C52
OBS_VERSION = 2

KIND = {0: 'none', 1: 'tx-submit', 2: 'tx-done', 3: 'rx-done', 4: 'tx-doorbell'}
PKT_PARSED = 1 << 0
PKT_SHORT = 1 << 7
PKT_TRUNCATED = 1 << 8
HDR_OVERFLOWED = 1 << 0
HDR_LOST = 1 << 1
HDR_TRUNCATED = 1 << 2

# PTE permission bits (AMD-Vi spec Table 17).
PTE_PR = 1 << 0
PTE_FC = 1 << 60
PTE_IR = 1 << 61
PTE_IW = 1 << 62
PM_ADDR_MASK = 0x000FFFFFFFFFF000

# DTE bits.
DTE_V = 1 << 0
DTE_TV = 1 << 1
DTE_IR = 1 << 61
DTE_IW = 1 << 62
DTE_MODE_SHIFT = 9
DTE_MODE_MASK = 0x7

# AMD-Vi event-log STATUS bits and ring size, mirrored from
# kext/AMDMapperProbeInternal.hpp (M2B2_STATUS_* / M2B2_EVT_BUFFER_SIZE).
#
# ROUND 13 (N1): these are the bits `m2b2SampleEvents()` refuses a window on.
# They are re-derived here from the published raw words, so a capture whose
# window was not really valid cannot be accepted on the probe's own summary.
M2B2_STATUS_EVT_OVERFLOW = 1 << 0
M2B2_STATUS_EVT_RUN = 1 << 3
M2B2_EVT_BUFFER_SIZE = 8192

# DTE MODE equals the number of page-table levels, so it also names the LEVEL
# of the root table (AMD-Vi spec Table 15, 1-based). Mode 4 -> a level-4 root
# (512 GiB per entry), mode 3 -> a level-3 root (1 GiB per entry).
#
# Getting this wrong is not cosmetic: the first version mapped mode 4 -> level 3,
# which made every chain start at the wrong level and reported all eight
# business ranges as illegal.
LEVELS = {4: (4, 512 << 30), 3: (3, 1 << 30)}

# How many distinct leaves one range may use, mirroring amdbw::kMaxLeaves in
# kext/amd_iommu_bizwalk_core.hpp. A 74-byte frame lands in one 2 MiB leaf; the
# bound exists so a pathological length cannot make the export unbounded.
MAX_LEAVES = 4

# THE MODES THE PROBE CAN REPORT. The production branch's own string for the
# control experiment is `control-sleep-only`; round 11's analyser looked for
# `control` and therefore never recognised a real control capture.
MODE_TRANSLATION = 'translation'
MODE_CONTROL = 'control-sleep-only'
KNOWN_MODES = (MODE_TRANSLATION, MODE_CONTROL)

RESULTS = []      # (section, id, name, state, detail) state in ok/fail/na
IDS = {}          # id -> count, so a duplicate id is an error rather than a
                  # silent overwrite
STATE = {}        # id -> state, for the summary predicates below
MODE = 'unknown'


def rec(section, cid, name, ok, detail='', na=False):
    """Record one check.

    THE ID IS STABLE AND UNIQUE.
    ---------------------------
    Round 11 identified a check by its human-readable NAME and let a later
    `rec(..., na=True)` with the same name replace an earlier result. That is
    how the control-mode N/A rows silently overwrote real checks: the reader
    saw "N/A" where a check had actually run and failed.

    Now every check has an id that is unique within the run. Re-using one is a
    hard error, so an N/A can never mask an earlier verdict.
    """
    state = 'na' if na else ('ok' if ok else 'fail')
    if cid in IDS:
        raise SystemExit('REFUSED: check id %r used twice (the second use would'
                         ' overwrite the first result)' % cid)
    IDS[cid] = 1
    STATE[cid] = state
    RESULTS.append((section, cid, name, state, detail))
    mark = 'N/A ' if na else ('PASS' if ok else 'FAIL')
    line = '  %-56s %s' % (name, mark)
    if detail and not ok and not na:
        line += '   [%s]' % detail
    print(line)
    return ok


def section(title):
    print('\n%s' % title)
    print('-' * 78)


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def hexprops(txt):
    out = {}
    for m in re.finditer(r'"([A-Za-z0-9_.\-]+)"\s*=\s*"0x([0-9a-fA-F]+)"', txt):
        out[m.group(1)] = int(m.group(2), 16)
    for m in re.finditer(r'"([A-Za-z0-9_.\-]+)"\s*=\s*"([^"]*)"', txt):
        out.setdefault(m.group(1), m.group(2))
    return out


def decode_header(blob):
    f = struct.unpack('<20I', blob[:80])
    keys = ['magic', 'version', 'recSize', 'capacity', 'head', 'wrapped',
            'dropped', 'pubId', 'firstTicket', 'lastTicket', 'validCount',
            'lostCount', 'epoch', 'busDevFn', 'vendorId', 'deviceId',
            'ifUnit', 'macHi', 'macLo', 'flags']
    h = dict(zip(keys, f))
    h['tStart'] = struct.unpack('<Q', blob[80:88])[0]
    h['tPublished'] = struct.unpack('<Q', blob[88:96])[0]
    h['recordCount'] = (len(blob) - HDR_BYTES) // REC_BYTES
    return h


def decode_record(blob, index):
    off = HDR_BYTES + index * REC_BYTES
    v = struct.unpack_from('<QQIIIIIIIIIIIIII', blob, off)
    return dict(t=v[0], addr=v[1], seq=v[2], kind=v[3], cum=v[4], slot=v[5],
                gen=v[6], batch=v[7], opts1=v[8], opts2=v[9], len=v[10],
                flags=v[11], token=v[12], reqId=v[13], flow=v[14], pkt=v[15])


def valid_record(blob, h, index):
    r = decode_record(blob, index)
    if r['seq'] == 0 or (r['seq'] & 1):
        return None
    if (r['seq'] >> 1) != h['firstTicket'] + index:
        return None
    return r


def pte_decode(pte, level):
    """Independent AMD-Vi PTE decode. Returns (kind, outPA, pageSize, child)."""
    if not (pte & PTE_PR):
        return ('absent', 0, 0, 0)
    nl = (pte >> 9) & 0x7
    if nl == 7:
        # Enlarged page: size from the run of ones at bit 12+.
        x = pte | 0xFFF
        i = 0
        while i < 63 and ((x >> i) & 1):
            i += 1
        ps = 1 << (1 + i)
        default = 1 << (9 * level + 3)
        nxt = 1 << (9 * (level + 1) + 3) if level < 6 else 0
        if ps <= default or (nxt and ps >= nxt):
            return ('illegal', 0, ps, 0)
        return ('leaf-large', (pte & PM_ADDR_MASK) & ~(ps - 1), ps, 0)
    if nl == 0:
        return ('leaf-default', pte & PM_ADDR_MASK, 1 << (9 * level + 3), 0)
    if nl != level - 1:
        return ('illegal', 0, 0, nl)
    return ('table', pte & PM_ADDR_MASK, 0, nl)


# ---------------------------------------------------------------------------
# The per-range recomputation
# ---------------------------------------------------------------------------
#
# Given a range [addr, addr+len) and the exported leaves for it, decide from
# the RAW PTEs alone whether the range is fully covered. `P` supplies the
# properties.
#
# Returns (ok, why, info). `why` is a stable token so a test can assert on the
# reason rather than on "it failed".
def recompute_range(P, idx, addr, ln, direction, root_pa, root_level):
    prefix = 'm2-b2-bw%d' % idx
    info = {'leaves': 0, 'bytes': 0, 'paths': []}

    if ln == 0:
        return False, 'zero-length', info
    end = addr + ln
    if end > (1 << 64):
        return False, 'range-overflows', info
    if addr == 0:
        return False, 'null-address', info

    nleaves = P.get(prefix + '-leaves')
    if nleaves is None:
        # Round 11's archives have no per-leaf export. The range is still
        # checkable IF it fits in one leaf: treat the legacy single-path
        # properties as leaf 0 and require that the leaf covers the whole
        # range. A range that would need a second leaf then fails, which is
        # exactly the round-11 defect.
        nleaves = 1

    if nleaves == 0:
        return False, 'no-leaves-exported', info
    if nleaves > MAX_LEAVES:
        return False, 'leaf-budget-exceeded', info

    # THE CURSOR IS THE ONLY THING THAT ADVANCES.
    #
    # ROUND 13 (N2): round 12 advanced `cur` here but derived the index, the
    # containment test and the identity test from the EXPORTED `leafN-from`.
    # The two were never compared, so an export whose leaf does not contain the
    # first bytes of the range still passed -- the exported path was verified
    # against itself.
    #
    # Now `cur` is the sole source of truth: the index comes from `cur`, the
    # exported `leafN-from` must EQUAL `cur`, and the decoded leaf must map
    # `cur` to itself. A leaf that starts later than the range cannot be
    # silently used for the bytes before it.
    cur = addr
    covered = 0
    need_bit = PTE_IW if direction == 'rx' else PTE_IR
    for li in range(nleaves):
        if nleaves == 1 and P.get(prefix + '-leaf0-pa') is None:
            # legacy single-path spelling
            depth = P.get(prefix + '-depth') or 0
            t = lambda L: P.get(prefix + '-pte%d-table' % L)
            i = lambda L: P.get(prefix + '-pte%d-index' % L)
            lv = lambda L: P.get(prefix + '-pte%d-level' % L)
            pte = lambda L: P.get(prefix + '-pte%d' % L)
            leaf_pa = P.get(prefix + '-leaf-pa')
            leaf_size = P.get(prefix + '-leaf-size')
            covers_from = None       # the legacy export has no from/bytes
            covers_bytes = None
        else:
            depth = P.get(prefix + '-leaf%d-depth' % li)
            if depth is None:
                # The round-12 export always publishes the depth per leaf.
                # Without it the chain length is unknown and the path cannot
                # be re-derived.
                depth = 0
                for L in range(8):
                    if P.get(prefix + '-leaf%d-pte%d' % (li, L)) is None:
                        break
                    depth = L + 1
            t = lambda L, li=li: P.get(prefix + '-leaf%d-pte%d-table' % (li, L))
            i = lambda L, li=li: P.get(prefix + '-leaf%d-pte%d-index' % (li, L))
            lv = lambda L, li=li: P.get(prefix + '-leaf%d-pte%d-level' % (li, L))
            pte = lambda L, li=li: P.get(prefix + '-leaf%d-pte%d' % (li, L))
            leaf_pa = P.get(prefix + '-leaf%d-pa' % li)
            leaf_size = P.get(prefix + '-leaf%d-size' % li)
            covers_from = P.get(prefix + '-leaf%d-from' % li)
            covers_bytes = P.get(prefix + '-leaf%d-bytes' % li)

        # ---- depth 0 is a rejection, not a skip ---------------------------
        #
        # Round 11 accepted depth 0: the loop over levels simply did not run,
        # so the chain check passed vacuously. A path with no levels is not a
        # path.
        if depth == 0:
            return False, 'depth-zero', info

        # ---- the exported "this leaf starts here" must BE the cursor ------
        #
        # ROUND 13 (N2): this comparison did not exist. `covers_from` was read
        # from the export and used in place of `cur`, so an export that starts
        # 16 bytes late described a different range than the one being proved
        # and nothing noticed.
        if covers_from is not None and covers_from != cur:
            return False, 'leaf-from-does-not-match-cursor', info

        # ---- re-derive the chain from the raw PTEs ------------------------
        expect_table = root_pa
        lvl = root_level
        leaf_found = None
        for L in range(depth):
            tt, ii, ll, pp = t(L), i(L), lv(L), pte(L)
            if None in (tt, ii, ll, pp):
                return False, 'path-incomplete', info
            if tt != expect_table:
                return False, 'table-link-broken', info
            if ll != lvl:
                return False, 'level-mismatch', info
            # ROUND 13: the index is derived from the CURSOR, never from the
            # export's own claim about where the leaf begins.
            want_idx = (cur >> (9 * lvl + 3)) & 0x1FF
            if ii != want_idx:
                return False, 'index-mismatch', info
            kind, outpa, psize, child = pte_decode(pp, lvl)
            if kind == 'table':
                expect_table = outpa
                lvl = child
                continue
            if kind in ('leaf-default', 'leaf-large'):
                if L != depth - 1:
                    return False, 'leaf-not-last', info
                # ROUND 13: containment is tested against the CURSOR. Round 12
                # tested it against `covers_from`, i.e. against the export's
                # claim rather than against the range being proved.
                if not (outpa <= cur < outpa + psize):
                    return False, 'leaf-does-not-contain-address', info
                # Identity: this experiment maps each page to itself.
                if (outpa | (cur & (psize - 1))) != cur:
                    return False, 'not-an-identity-mapping', info
                leaf_found = (outpa, psize, L)
                break
            return False, 'no-legal-leaf', info

        if leaf_found is None:
            return False, 'no-legal-leaf', info
        outpa, psize, _L = leaf_found
        if leaf_pa is not None and leaf_pa != outpa:
            return False, 'leaf-pa-mismatch', info
        if leaf_size is not None and leaf_size != psize:
            return False, 'leaf-size-mismatch', info

        # ---- permissions at EVERY level -----------------------------------
        for L in range(depth):
            pp = pte(L)
            if pp is None or (pp & need_bit) == 0:
                return False, 'permission-insufficient', info

        # ---- how many bytes of the range this leaf carries ----------------
        #
        # ROUND 13: the step is bounded by BOTH the leaf's own end and the
        # range's end, and it must be positive. Round 12 computed the same
        # number but then compared it to `covers_bytes`, which the export
        # supplies -- so an export could describe a step the PTEs do not
        # support. The comparison is kept, because a disagreement means one of
        # the two is wrong and the analyser does not get to pick the
        # convenient one, but it is no longer the source of the value.
        stop = min(outpa + psize, end)
        if stop <= cur:
            return False, 'no-progress', info
        step = stop - cur
        if covers_bytes is not None and covers_bytes != step:
            return False, 'coverage-accounting-disagrees', info
        covered += step
        info['leaves'] += 1
        info['paths'].append((li, outpa, psize, step, depth))
        cur = stop
        if cur >= end:
            break

    info['bytes'] = covered
    if covered != ln:
        return False, 'range-not-fully-covered', info
    # The contiguous walk must end exactly at addr+len. Round 12 also checked
    # this, but `cur` and `covered` were advanced from different places, so the
    # check could hold while the bytes proved were not the bytes claimed.
    if cur != end:
        return False, 'range-not-fully-covered', info
    return True, 'ok', info


def write_result(cap, outdir, present, h, ws, we, results,
                 refused=None, extra=None):
    """Write analysis.json.

    Extracted so a REFUSAL can also produce a structured result. Round 12
    returned 2 with no JSON at all, which made "the analyser refused this input"
    indistinguishable from "the analyser crashed".
    """
    out = {
        'capture': cap,
        'mode': MODE,
        'refused': refused,
        'inputs': {k: {'bytes': v[0], 'sha256': v[1]}
                   for k, v in present.items()},
        'snapshot': h,
        'window': {'start': ws, 'end': we},
        'checks': [{'section': s, 'id': c, 'name': n, 'state': st,
                    'detail': d} for s, c, n, st, d in results],
    }
    if extra:
        out.update(extra)
    dest = outdir or cap
    os.makedirs(dest, exist_ok=True)
    path = os.path.join(dest, 'analysis.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=1)
    print('  wrote %s' % path)
    return out


# ---------------------------------------------------------------------------
# Round 14: the RX posted-buffer blob
# ---------------------------------------------------------------------------
#
# The layout is repeated from tools/lucy-obs/RTL812xRxPost.hpp rather than
# imported, because the analyser must be able to refuse a blob whose layout it
# does not recognise. tools/r14/check-rxpost-layout.py pins the three
# declarations (driver structs, probe offsets, this decoder's numbers) against
# each other, so a drift is caught there instead of producing plausible wrong
# ranges here.
RXPOST_HDR_BYTES = 160
RXPOST_SLOT_BYTES = 32
RXPOST_REARM_BYTES = 48
RXPOST_SLOT_MAX = 1024
RXSET_DETAIL_MAX = 64

RXPOST_FLAG_NO_BASELINE = 1 << 0
RXPOST_FLAG_REARM_LOST = 1 << 1
RXPOST_FLAG_GEN_MOVED = 1 << 2
RXPOST_FLAG_TRUNCATED = 1 << 3

RXPOST_SRC_BASELINE = 1
RXPOST_SRC_REARM = 2


def decode_rxpost(blob):
    """Decode the published RX post blob. Returns None or a dict with ok/why."""
    if not blob:
        return {'ok': False, 'why': 'no-blob'}
    if len(blob) < RXPOST_HDR_BYTES:
        return {'ok': False, 'why': 'shorter-than-a-header'}
    h = {}
    names = ['magic', 'version', 'recSizeSlot', 'recSizeRearm',
             'head', 'wrapped', 'dropped', 'slotCapacity', 'rearmCapacity',
             'rearmFirstSeq', 'ringGen', 'baselineActive',
             'baselineSlots', 'baselineValid', 'baselineAddrZero',
             'baselineCapDesc', 'baselineCapConst', 'baselineCapBad',
             'baselineTorn', 'baselineCount', 'baselineGenMoved',
             'pubId', 'epoch', 'ifUnit', 'vtdPath', 'rxBufferSize',
             'flags', 'pad0']
    vals = struct.unpack_from('<28I', blob, 0)
    h = dict(zip(names, vals))
    h['tBaseline'], h['rearmSeqAtBaseline'], h['tPublished'] = \
        struct.unpack_from('<3Q', blob, 112)
    h['rearmRequired'], h['rearmPublished'] = struct.unpack_from('<2I',
                                                                blob, 136)

    if h['magic'] != 0x4F505852:
        return {'ok': False, 'why': 'bad-magic'}
    if h['version'] != 1:
        return {'ok': False, 'why': 'unknown-version'}
    if h['recSizeSlot'] != RXPOST_SLOT_BYTES:
        return {'ok': False, 'why': 'slot-size-mismatch'}
    if h['recSizeRearm'] != RXPOST_REARM_BYTES:
        return {'ok': False, 'why': 'rearm-size-mismatch'}
    if h['slotCapacity'] != RXPOST_SLOT_MAX:
        return {'ok': False, 'why': 'slot-capacity-mismatch'}

    body = len(blob) - RXPOST_HDR_BYTES
    slot_bytes = RXPOST_SLOT_MAX * RXPOST_SLOT_BYTES
    if body < slot_bytes:
        return {'ok': False, 'why': 'body-shorter-than-the-slot-table'}
    rest = body - slot_bytes
    if rest % RXPOST_REARM_BYTES != 0:
        return {'ok': False, 'why': 'ragged-rearm-body'}
    n = rest // RXPOST_REARM_BYTES
    if n != h['rearmPublished']:
        return {'ok': False, 'why': 'rearm-count-disagrees-with-header'}

    slots = []
    base = RXPOST_HDR_BYTES
    for i in range(RXPOST_SLOT_MAX):
        off = base + i * RXPOST_SLOT_BYTES
        addr, blen = struct.unpack_from('<QQ', blob, off)
        slot, cap, flags, gen = struct.unpack_from('<4I', blob,
                                                   off + 16)
        slots.append({'addr': addr, 'blen': blen, 'slot': slot,
                      'capacity': cap, 'flags': flags, 'gen': gen})
    rearms = []
    rbase = base + slot_bytes
    for i in range(n):
        off = rbase + i * RXPOST_REARM_BYTES
        # THE FIELD ORDER IS THE DRIVER'S, NOT A GUESS.
        #
        # RearmRec is 48 bytes: tMono@0, addr@8, oldAddr@16, blenRaw@24,
        # then the protocol's seq@32 (the low half of word 4), slot@36,
        # capacity@40, flags@44.
        #
        # The first version of this decoder read seq@24 and capacity@32 --
        # i.e. it treated blenRaw as seq and seq as capacity. That produced a
        # set that disagreed with the probe by 125 ranges and looked like a
        # probe bug. It was not: the probe's core reads seq at byte 32, as
        # tools/r14/check-rxpost-layout.py asserts, and that check did not
        # cover THIS file. It does now.
        t, addr, old, blen = struct.unpack_from('<4Q', blob, off)
        seq, slot, cap, flags = struct.unpack_from('<4I', blob, off + 32)
        rearms.append({'t': t, 'addr': addr, 'oldAddr': old, 'blenRaw': blen,
                       'seq': seq, 'slot': slot, 'capacity': cap,
                       'flags': flags})

    return {'ok': True, 'why': None, 'hdr': h,
            'watermark': h['rearmSeqAtBaseline'],
            'slots': slots, 'rearms': rearms}


def rebuild_rx_set(rx):
    """Rebuild the union from the decoded blob, independently of the probe.

    The rules are the ones the design states, applied here rather than read
    from the probe's summary:

      * a slot with address 0 or capacity 0 is skipped (it posts nothing);
      * a rearm contributes BOTH its installed and its retired address, so a
        buffer replaced during the baseline scan cannot fall out of the set;
      * de-duplication is by (addr, capacity), not by slot and not by address
        alone -- a buffer re-posted at a different posted length is a different
        number of writable bytes.
    """
    out = {}
    stat = {'ranges': 0, 'fromBaseline': 0, 'fromRearm': 0, 'fromBoth': 0,
            'skippedZero': 0, 'capped': 0}

    def add(addr, cap, source, slot):
        if addr == 0 or cap == 0:
            stat['skippedZero'] += 1
            return
        key = (addr, cap)
        if key in out:
            if out[key]['source'] != source:
                out[key]['source'] = 'both'
            out[key]['slot'] = slot
            return
        out[key] = {'addr': addr, 'capacity': cap, 'source': source,
                    'slot': slot}
        # The contribution counters follow the SAME convention as the probe's
        # buildSet(): a range is counted once, against the half that introduced
        # it. A range first seen in the baseline and later re-armed is a
        # baseline contribution that also appears in both -- not two ranges.
        if source == 'baseline':
            stat['fromBaseline'] += 1
        else:
            stat['fromRearm'] += 1

    for s in rx['slots']:
        add(s['addr'], s['capacity'], 'baseline', s['slot'])
    for a in rx['rearms']:
        if a['seq'] == 0 or (a['seq'] & 1):
            continue                    # hole, or a body in flight
        add(a['addr'], a['capacity'], 'rearm', a['slot'])
        add(a['oldAddr'], a['capacity'], 'rearm', a['slot'])

    for v in out.values():
        if v['source'] == 'both':
            stat['fromBoth'] += 1
    stat['ranges'] = len(out)
    return out, stat


def main():
    global MODE
    cap = sys.argv[1] if len(sys.argv) > 1 else 'docs/evidence/20261101-140000'
    outdir = sys.argv[2] if len(sys.argv) > 2 else None

    print('=' * 78)
    print('ROUND-12 INDEPENDENT ANALYSIS')
    print('capture: %s' % cap)
    print('=' * 78)

    # ------------------------------------------------------------------
    section('0. INPUT IDENTITIES')
    # ------------------------------------------------------------------
    required = ['props.txt', 'props.raw.txt', 'client.log', 'peer.log',
                'load.txt', 'network.txt', 'system.txt']
    present = {}
    for f in required:
        p = os.path.join(cap, f)
        if os.path.exists(p):
            present[f] = (os.path.getsize(p), sha256(p))
            print('  %-22s %10d B  %s'
                  % (f, present[f][0], present[f][1][:32]))
        else:
            print('  %-22s MISSING' % f)
    rec('input', 'in-required', 'every required raw input is present',
        all(f in present for f in required),
        'missing: %s' % [f for f in required if f not in present])

    props = open(os.path.join(cap, 'props.txt'), encoding='utf-8',
                 errors='replace').read()
    P = hexprops(props)
    raw = open(os.path.join(cap, 'props.raw.txt'), encoding='utf-8',
               errors='replace').read()

    # ------------------------------------------------------------------
    section('1. MODE (detected FIRST, before any check is selected)')
    # ------------------------------------------------------------------
    #
    # WHY THIS COMES BEFORE EVERYTHING ELSE
    # -------------------------------------
    # The two experiments require different fields and support different
    # claims. Deciding which checks apply AFTER running them is how round 11's
    # control-mode N/A rows ended up overwriting real results: the check had
    # already been recorded, and a later same-named row replaced it.
    mode = P.get('m2-b2-mode')
    MODE = mode if mode else 'unknown'
    print('  mode = %r' % MODE)
    rec('mode', 'mode-known', 'the probe reported a mode this analyser knows',
        MODE in KNOWN_MODES, 'mode=%r (known: %s)' % (MODE, list(KNOWN_MODES)))

    is_control = (MODE == MODE_CONTROL)
    is_translation = (MODE == MODE_TRANSLATION)

    if is_control:
        print('\n  This is the CONTROL experiment. The stages that switch the')
        print('  DTE, invalidate and sample never execute, so they are N/A --')
        print('  not PASS and not FAIL. A control run can never satisfy the')
        print('  finite-transaction subgoal.')

    # ------------------------------------------------------------------
    section('2. THE SNAPSHOT THE PROBE ACTUALLY USED')
    # ------------------------------------------------------------------
    #
    # ROUND 13 (N3): THE PATH IS CHOSEN BY MODE *HERE*, BEFORE ANYTHING IS
    # LOADED OR DECODED.
    #
    # Round 12 loaded the probe's exported snapshot unconditionally and then
    # refused with exit 2 when it was absent. That is correct for a translation
    # capture -- refusing beats substituting a different snapshot, which is
    # round 10's failure mode -- but it is wrong for a control capture, because
    # the production control branch takes `goto recover` after its 20 s sleep
    # and therefore never calls m2b2ReadDriverObs(). A real control run has no
    # `m2-b2-obs-snapshot-used` and no `-obs-used-sha256`, by construction.
    #
    # The round-12 fixture hid this by synthesising a probe-used snapshot, so
    # the analyser was only ever tested against a control capture that carried
    # a field the production branch cannot produce. Removing it made the
    # analyser exit 2 without writing analysis.json -- a refusal to judge a
    # legitimate control capture.
    #
    # So: translation captures must export the snapshot they decoded, and a
    # missing one is still a refusal (exit 2). Control captures are judged from
    # what the control branch really publishes, and never from the driver's own
    # `rtl812x-obs-snapshot`, which is a DIFFERENT object published by a
    # different code path at a different time.
    m = re.search(r'"m2-b2-obs-snapshot-used"\s*=\s*<([0-9a-fA-F]+)>', raw)
    used_blob = bytes.fromhex(m.group(1)) if m else None
    used_path = os.path.join(cap, 'obs-snapshot-used.bin')
    used_file = open(used_path, 'rb').read() if os.path.exists(used_path) else None

    # The DRIVER's own snapshot. It exists in every capture, including control
    # ones, and it is NOT the probe-used snapshot. Kept separate on purpose:
    # conflating the two is exactly what round 10 did.
    drv_m = re.search(r'"rtl812x-obs-snapshot"\s*=\s*<([0-9a-fA-F]+)>', raw)
    driver_blob = bytes.fromhex(drv_m.group(1)) if drv_m else None
    print('  driver\'s own rtl812x-obs-snapshot   : %s'
          % (('%d B, NOT the probe-used one' % len(driver_blob))
             if driver_blob else 'ABSENT'))

    probe_sha = P.get('m2-b2-obs-used-sha256')
    probe_exported = P.get('m2-b2-obs-used') == 'exported'
    print('  probe exported the used snapshot : %s' % (P.get('m2-b2-obs-used')))
    print('  probe published sha256           : %s' % probe_sha)
    print('  extracted from props.raw.txt     : %s'
          % (sha256_bytes(used_blob)[:32] + '...' if used_blob else 'ABSENT'))
    print('  archived obs-snapshot-used.bin   : %s'
          % (sha256_bytes(used_file)[:32] + '...' if used_file else 'ABSENT'))

    ok_export = rec('snapshot', 'snap-exported',
                    'the probe exported the snapshot it decoded',
                    probe_exported and used_blob is not None,
                    'used=%s blob=%s' % (P.get('m2-b2-obs-used'),
                                         'present' if used_blob else 'absent'),
                    # R5: the control branch never decodes a driver snapshot,
                    # so "was one exported" is not applicable there. Calling it
                    # FAIL would report the absence of an experiment as a
                    # defect in it.
                    na=is_control)
    ok_sha_raw = rec('snapshot', 'snap-sha-raw',
                     'the exported blob matches the probe-published sha256',
                     bool(used_blob and probe_sha and
                          sha256_bytes(used_blob) == probe_sha),
                     'probe=%s computed=%s'
                     % (probe_sha,
                        sha256_bytes(used_blob) if used_blob else 'n/a'),
                     na=is_control)
    ok_sha_file = rec('snapshot', 'snap-sha-file',
                      'the archived file matches the probe-published sha256',
                      bool(used_file and probe_sha and
                           sha256_bytes(used_file) == probe_sha),
                      'probe=%s file=%s'
                      % (probe_sha,
                         sha256_bytes(used_file) if used_file else 'n/a'),
                      na=is_control)

    blob = used_file if used_file is not None else used_blob

    # A control capture MUST NOT carry a probe-used snapshot. If one is
    # present, either the capture is not a control run (the schema section
    # reports that) or something substituted one -- and the analyser will not
    # treat the driver's own blob as a stand-in either way.
    if is_control and blob is not None:
        rec('snapshot', 'snap-control-must-not-have-used',
            'a control capture carries no probe-used snapshot', False,
            'the control branch never calls m2b2ReadDriverObs(), so a capture '
            'labelled control that carries m2-b2-obs-snapshot-used is not a '
            'control run')

    if blob is None:
        if is_control:
            # THE CONTROL PATH. No snapshot is decoded because none exists;
            # every snapshot-header check below is N/A, and the control
            # branch's OWN evidence is verified in section 2c instead.
            print('\n  This is a CONTROL capture: the production branch never')
            print('  decodes a driver snapshot, so there is none to analyse.')
            print('  The checks that would need one are N/A -- and the driver\'s')
            print('  own rtl812x-obs-snapshot is NOT substituted for it.')
            h = None
        else:
            print('\n  REFUSED: no snapshot to analyse. Round 10\'s failure mode')
            print('  was analysing a different snapshot than the probe used; the')
            print('  answer is to refuse rather than substitute one.')
            #
            # ROUND 13: the refusal is STRUCTURED. Round 12 returned 2 after
            # printing to stdout and wrote no analysis.json at all, so a caller
            # could not distinguish "the analyser refused this input" from "the
            # analyser crashed" -- and the negative suite counted both as a
            # refusal, which is right, but a *person* reading the archive could
            # not tell either. Writing the partial result with an explicit
            # `refused` reason makes the refusal a machine-checkable fact.
            #
            # Exit code 2 still means "no verdict"; it does NOT mean the input
            # was rejected on its merits.
            rec('input', 'in-refused-no-snapshot',
                'a translation capture must export the snapshot it decoded',
                False,
                'm2-b2-obs-snapshot-used is absent and no '
                'obs-snapshot-used.bin was archived')
            # THE REFUSAL IS ALSO A SCHEMA VERDICT.
            #
            # The translation schema requires the probe-used snapshot (see
            # section 13's `required_fields`). A capture labelled translation
            # without one violates that schema, and saying so HERE -- rather
            # than only in a prose refusal -- is what lets a caller tell "this
            # input does not meet the translation schema" apart from "the
            # analyser crashed". `schema-fields` is recorded in section 13 on
            # the normal path, and section 13 is never reached when we return
            # below, so the id cannot be used twice.
            rec('schema', 'schema-fields',
                'every field the translation schema requires is present',
                False,
                'm2-b2-obs-snapshot-used / m2-b2-obs-used-sha256 are absent, '
                'so this capture cannot support a translation claim')
            # `ws`/`we` are read in section 6, which is AFTER this point, so
            # they are not bound yet. Read them directly rather than reordering:
            # the refusal must happen before anything decodes a snapshot.
            write_result(cap, outdir, present, None,
                         P.get('m2-b2-dma-t-win-start'),
                         P.get('m2-b2-dma-t-win-end'), RESULTS,
                         refused='no-probe-used-snapshot')
            return 2
    else:
        h = decode_header(blob)
        print('\n  decoded: pub=%d head=%d first=%d tPublished=%d records=%d'
              % (h['pubId'], h['head'], h['firstTicket'], h['tPublished'],
                 h['recordCount']))

    probe_pub = P.get('m2-b2-obs-used-pub-id')
    probe_tpub = P.get('m2-b2-obs-used-t-published')
    rec('snapshot', 'snap-pub-known',
        'the probe reported the publication it used',
        probe_pub is not None and probe_tpub is not None,
        na=is_control)
    rec('snapshot', 'snap-pub-is-blob', 'the blob IS that publication',
        h is not None and probe_pub == h['pubId'] and
        probe_tpub == h['tPublished'],
        'probe pub=%s t=%s blob pub=%s t=%s'
        % (probe_pub, probe_tpub,
           h['pubId'] if h else None, h['tPublished'] if h else None),
        na=is_control)

    # ------------------------------------------------------------------
    section('3. SNAPSHOT HEADER AND LOSS ACCOUNTING')
    # ------------------------------------------------------------------
    #
    # Every check in this section needs the probe-used blob. In control mode
    # there is none, so each is N/A -- recorded, not omitted, so every run
    # reports the same check ids and the denominator cannot shrink silently.
    if h is None:
        for cid, name in (
                ('hdr-magic', 'magic is RLO2 (wire v2)'),
                ('hdr-version', 'version is 2'),
                ('hdr-recsize', 'record size is 72'),
                ('hdr-whole', 'the body is a whole number of records'),
                ('hdr-valid-lost', 'valid + lost equals the record count'),
                ('hdr-tickets', 'the ticket range spans the record count'),
                ('hdr-pubid', 'publication id is non-zero'),
                ('loss-dropped', 'no writer dropped a record'),
                ('loss-lostcount', 'the publisher found no holes'),
                ('loss-overflowed', 'the ring did not overflow'),
                ('loss-flag', 'the snapshot is not flagged as lossy'),
                ('loss-probe-agrees',
                 "the probe's dropped/lost counters equal the header's"),
                ('loss-wrapped', 'no slot was overwritten before publication'),
                ('loss-wrapped-agrees',
                 "the probe's wrapped counter equals the header's")):
            rec('snapshot' if cid.startswith('hdr') else 'loss', cid, name,
                False, na=True)
        print('  (no probe-used snapshot in this mode: N/A, not PASS)')
    else:
        rec('snapshot', 'hdr-magic', 'magic is RLO2 (wire v2)',
            h['magic'] == OBS_MAGIC, '0x%x' % h['magic'])
        rec('snapshot', 'hdr-version', 'version is 2',
            h['version'] == OBS_VERSION)
        rec('snapshot', 'hdr-recsize', 'record size is 72',
            h['recSize'] == REC_BYTES)
        rec('snapshot', 'hdr-whole', 'the body is a whole number of records',
            (len(blob) - HDR_BYTES) % REC_BYTES == 0)
        rec('snapshot', 'hdr-valid-lost', 'valid + lost equals the record count',
            h['validCount'] + h['lostCount'] == h['recordCount'],
            '%d+%d vs %d' % (h['validCount'], h['lostCount'],
                             h['recordCount']))
        rec('snapshot', 'hdr-tickets', 'the ticket range spans the record count',
            h['recordCount'] == 0 or
            h['lastTicket'] - h['firstTicket'] + 1 == h['recordCount'])
        rec('snapshot', 'hdr-pubid', 'publication id is non-zero',
            h['pubId'] != 0)

        # ---- R5: loss is a gate term, not a decoration ------------------
        #
        # Round 11 decoded dropped/wrapped/lostCount/flags and then never used
        # them, so `dropped = 1` still produced a complete verdict. Each
        # channel is a separate check so a failure names the channel.
        #
        # ROUND 13 (N5 of the wrapped fix): `wrapped` is now a checked channel
        # too. Round 12 decoded it, printed it, and let the analyser ignore it
        # -- so a snapshot whose ring had wrapped past unpublished records was
        # accepted as complete. The production writer now counts it in one
        # place and the publisher copies that place; this is the reader side of
        # the same fact.
        print('  dropped=%d wrapped=%d lostCount=%d flags=0x%x'
              % (h['dropped'], h['wrapped'], h['lostCount'], h['flags']))
        rec('loss', 'loss-dropped', 'no writer dropped a record',
            h['dropped'] == 0, 'dropped=%d' % h['dropped'])
        rec('loss', 'loss-lostcount', 'the publisher found no holes',
            h['lostCount'] == 0, 'lostCount=%d' % h['lostCount'])
        rec('loss', 'loss-overflowed', 'the ring did not overflow',
            (h['flags'] & HDR_OVERFLOWED) == 0, 'flags=0x%x' % h['flags'])
        rec('loss', 'loss-flag', 'the snapshot is not flagged as lossy',
            (h['flags'] & HDR_LOST) == 0, 'flags=0x%x' % h['flags'])
        # The probe's own view of the same counters must agree with the header.
        rec('loss', 'loss-probe-agrees',
            'the probe\'s dropped/lost counters equal the header\'s',
            P.get('m2-b2-obs-dropped') == h['dropped'] and
            P.get('m2-b2-obs-lost-count') == h['lostCount'],
            'probe dropped=%s lost=%s' % (P.get('m2-b2-obs-dropped'),
                                          P.get('m2-b2-obs-lost-count')))
        # ROUND 13: `wrapped` must be zero AND the probe's mirror must agree
        # with the header. The round-12 defect was that the driver counted a
        # wrap in the shared writer but published an un-updated member, so the
        # header said 0 while the ring had wrapped. Two separate checks catch
        # the two halves: the header must say 0, and the probe must report the
        # same number the header does.
        rec('loss', 'loss-wrapped',
            'no slot was overwritten before publication',
            h['wrapped'] == 0, 'wrapped=%d' % h['wrapped'])
        rec('loss', 'loss-wrapped-agrees',
            'the probe\'s wrapped counter equals the header\'s',
            P.get('m2-b2-obs-wrapped') == h['wrapped'],
            'probe=%s header=%d' % (P.get('m2-b2-obs-wrapped'), h['wrapped']))


    # ------------------------------------------------------------------
    section('4. INSTANCE AND DEVICE IDENTITY')
    # ------------------------------------------------------------------
    #
    # ROUND 13 (N3): the identity checks that compare a value INSIDE the
    # snapshot header against the probe's independent view need a snapshot. In
    # control mode there is none, so those are N/A; the probe's own view of the
    # device, and the interface/load facts taken from the capture's text files,
    # are still verified -- a control run really does know which device it
    # watched, and saying so is not a translation claim.
    probe_bdf = P.get('m2-b2-nic-bdf')
    probe_mac = P.get('m2-b2-nic-mac')
    probe_unit = P.get('m2-b2-nic-unit')
    probe_vendor = P.get('m2-b2-nic-vendor')
    probe_device = P.get('m2-b2-nic-device')

    # R5: an UNKNOWN identity is a refusal. Round 11 only checked the fields
    # when the probe had them, so a capture with no identity passed.
    #
    # ROUND 13 (N3/N4): the control branch takes `goto recover` BEFORE step 16c,
    # so it never calls m2b2CaptureNicIdentity() and publishes NO `m2-b2-nic-*`
    # property at all. That is the branch's real shape, derived from the code by
    # tools/r13/control-shape.py -- not a defect and not a reason to invent the
    # fields in a fixture. So `id-known` is N/A in control mode, and the reason
    # is recorded rather than left to the reader.
    ident_known = all(v is not None for v in
                      (probe_bdf, probe_vendor, probe_device, probe_unit,
                       probe_mac))
    rec('identity', 'id-known', 'the probe established its own device identity',
        ident_known,
        'bdf=%s vendor=%s device=%s unit=%s mac=%s'
        % (probe_bdf, probe_vendor, probe_device, probe_unit, probe_mac),
        na=is_control)
    if is_control:
        print('  NOTE: the control branch never reaches m2b2CaptureNicIdentity(),')
        print('        so it publishes no m2-b2-nic-* property. The device it')
        print('        watched is still named by m2-b2-target-devid and')
        print('        m2-b2-tgt-bus/-dev/-fn, which are published before the')
        print('        branch; section 13 checks those instead.')

    if h is None:
        for cid, name in (
                ('id-bdf', "snapshot BDF equals the probe's independent BDF"),
                ('id-vendor', "snapshot vendor equals the probe's"),
                ('id-device', "snapshot device equals the probe's"),
                ('id-unit', "snapshot interface unit equals the probe's"),
                ('id-mac', "snapshot MAC equals the probe's"),
                ('id-epoch-match',
                 'the snapshot belongs to that instance')):
            rec('identity', cid, name, False, na=True)
        snap_mac = None
        binding = bound = None
    else:
        snap_mac = ((h['macHi'] & 0xFFFFFFFF) << 16) | (h['macLo'] & 0xFFFF)
        rec('identity', 'id-bdf',
            'snapshot BDF equals the probe\'s independent BDF',
            probe_bdf is not None and h['busDevFn'] == probe_bdf,
            'snap=0x%x probe=%s' % (h['busDevFn'], probe_bdf))
        rec('identity', 'id-vendor', 'snapshot vendor equals the probe\'s',
            probe_vendor is not None and h['vendorId'] == probe_vendor,
            'snap=0x%x probe=%s' % (h['vendorId'], probe_vendor))
        rec('identity', 'id-device', 'snapshot device equals the probe\'s',
            probe_device is not None and h['deviceId'] == probe_device,
            'snap=0x%x probe=%s' % (h['deviceId'], probe_device))
        rec('identity', 'id-unit', 'snapshot interface unit equals the probe\'s',
            probe_unit is not None and h['ifUnit'] == probe_unit,
            'snap=%s probe=%s' % (h['ifUnit'], probe_unit))
        rec('identity', 'id-mac', 'snapshot MAC equals the probe\'s',
            probe_mac is not None and snap_mac == probe_mac,
            'snap=0x%x probe=0x%x' % (snap_mac, probe_mac or 0))
        binding = P.get('m2-b2-obs-epoch-binding')
        bound = P.get('m2-b2-obs-epoch-bound')
        rec('identity', 'id-epoch-match',
            'the snapshot belongs to that instance',
            binding == 'matched' and bound == h['epoch'],
            'binding=%s bound=%s snap-epoch=%s'
            % (binding, bound, h['epoch']))

    # The binding is established BEFORE the snapshot is read, so it is checked
    # in both modes: a control run binds the instance too.
    #
    # ROUND 13 (N4): it does NOT. Step 15c (m2b2BindDriverInstance) is after the
    # control branch's `goto recover`, so a control capture has no epoch binding
    # at all. Asserting one here would demand a field the production branch
    # cannot produce -- the same error round 12 made with the snapshot.
    bound_any = P.get('m2-b2-obs-epoch-bound')
    rec('identity', 'id-epoch-bound',
        'the driver instance was bound before the window',
        bound_any not in (None, 0), 'epoch-bound=%s' % bound_any,
        na=is_control)


    net = open(os.path.join(cap, 'network.txt'), encoding='utf-8',
               errors='replace').read()
    net_mac = net_iface = None
    for line in net.splitlines():
        if 'ether=' in line and 'status=active' in line:
            mm = re.search(r'^(\w+):.*ether=([0-9a-f:]+)', line)
            if mm and (probe_mac is None or
                       int(mm.group(2).replace(':', ''), 16) == probe_mac):
                net_iface, net_mac = mm.group(1), mm.group(2)
    rec('identity', 'id-in-network',
        'the MAC belongs to the interface in network.txt',
        net_mac is not None and net_iface is not None,
        'iface=%s mac=%s' % (net_iface, net_mac))

    load = open(os.path.join(cap, 'load.txt'), encoding='utf-8',
                errors='replace').read()
    load_iface = re.search(r'load_iface\s*:\s*(\S+)', load)
    load_route = re.search(r'load_route_interface\s*:\s*(\S+)', load)
    rec('identity', 'id-load-iface',
        'the load ran on the same interface as the device',
        load_iface is not None and net_iface is not None and
        load_iface.group(1) == net_iface,
        'load=%s device=%s' % (load_iface and load_iface.group(1), net_iface))
    rec('identity', 'id-load-route',
        'the route to the peer left by that interface',
        load_route is not None and load_iface is not None and
        load_route.group(1) == load_iface.group(1),
        'route=%s' % (load_route and load_route.group(1)))

    # ------------------------------------------------------------------
    section('5. RECORD INTEGRITY')
    # ------------------------------------------------------------------
    holes = 0
    kinds = {}
    recs = []
    if h is not None:
        for i in range(h['recordCount']):
            r = valid_record(blob, h, i)
            if r is None:
                holes += 1
                continue
            kinds[r['kind']] = kinds.get(r['kind'], 0) + 1
            recs.append((i, r))
    if h is None:
        for cid, name in (
                ('rec-no-holes', 'no record is mid-write or mis-ticketed'),
                ('rec-submits', 'at least one TX submit is present'),
                ('rec-dones', 'at least one TX completion is present'),
                ('rec-rx', 'at least one RX record is present')):
            rec('records', cid, name, False, na=True)
        print('  (no probe-used snapshot in this mode: N/A, not PASS)')
    else:
        rec('records', 'rec-no-holes', 'no record is mid-write or mis-ticketed',
            holes == 0, '%d holes' % holes)
        print('  kinds: %s'
              % {KIND.get(k, k): v for k, v in sorted(kinds.items())})
        rec('records', 'rec-submits', 'at least one TX submit is present',
            kinds.get(1, 0) > 0)
        rec('records', 'rec-dones', 'at least one TX completion is present',
            kinds.get(2, 0) > 0,
            # A control run sends no controlled traffic, so there is no
            # completion to require. Ordinary background traffic may or may not
            # have one.
            na=is_control)
        rec('records', 'rec-rx', 'at least one RX record is present',
            kinds.get(3, 0) > 0)

    # ------------------------------------------------------------------
    section('6. THE WINDOW AND ITS VALIDITY')
    # ------------------------------------------------------------------
    ws = P.get('m2-b2-dma-t-win-start')
    we = P.get('m2-b2-dma-t-win-end')
    win_valid = P.get('m2-b2-window-valid')
    have_window = ws is not None and we is not None and we > ws
    if is_control:
        rec('window', 'win-bounds', 'the window bounds exist and are ordered',
            have_window, 'ws=%s we=%s' % (ws, we), na=not have_window)
    else:
        rec('window', 'win-bounds', 'the window bounds exist and are ordered',
            have_window, 'ws=%s we=%s' % (ws, we))
    if ws and we:
        print('  window = [%d, %d]  (%.6f s)' % (ws, we, (we - ws) / 1e9))
    rec('window', 'win-valid', 'the probe reported the window as valid',
        win_valid == 'yes', 'window-valid=%s (%s)'
        % (win_valid, P.get('m2-b2-window-invalid')),
        na=is_control)

    # ------------------------------------------------------------------
    section('6b. THE RAW WINDOW STATE, RECOMPUTED FROM THE STATUS WORDS')
    # ------------------------------------------------------------------
    #
    # ROUND 13 (N1): THIS SECTION DID NOT EXIST.
    #
    # `m2-b2-win-status-start` / `-end` are the AMD-Vi event-log STATUS register
    # sampled at the two ends of the measurement window, and
    # `m2b2SampleEvents()` refuses the window when EVT_RUN is clear or
    # EVT_OVERFLOW is set at either end. The round-12 analyser never read them:
    # zeroing both in a copy of the passing 20261101-014200 archive still gave
    # 97 ok / 0 failed and "finite DMA translation evidence: YES".
    #
    # The `evt-status` check that DID exist decodes the status field INSIDE an
    # event entry, which is a different register answering a different
    # question -- and it is N/A whenever the window recorded no events, which
    # is exactly what this archive does. So the hardware-side precondition had
    # no check at all.
    #
    # These checks run for EVERY translation capture, including one whose
    # window recorded zero events. "There was nothing to see" is a statement
    # about the window's CONTENTS; whether the log was running is a statement
    # about the window's VALIDITY, and it must hold either way.
    ws_s = P.get('m2-b2-win-status-start')
    ws_e = P.get('m2-b2-win-status-end')
    h_s = P.get('m2-b2-win-head-start')
    t_s = P.get('m2-b2-win-tail-start')
    h_e = P.get('m2-b2-win-head-end')
    t_e = P.get('m2-b2-win-tail-end')
    n_ent = P.get('m2-b2-win-entries')

    if is_control:
        # The control branch never opens a window, so it never samples STATUS.
        # Absence here is the branch's real shape, not a defect.
        for cid, name in (
                ('win-status-present', 'both window STATUS words were published'),
                ('win-status-run-start', 'EVT_RUN was set at the window start'),
                ('win-status-run-end', 'EVT_RUN was still set at the window end'),
                ('win-status-no-overflow', 'the event ring did not overflow at either end'),
                ('win-status-ptr-aligned', 'the head/tail words are aligned and in range'),
                ('win-status-head-stable', 'the consumer head did not move during the window'),
                ('win-status-span', 'the produced span agrees with the entry count')):
            rec('window', cid, name, False, na=True)
        print('\n  NOTE: the control branch takes `goto recover` before step 16,')
        print('  so it never samples the event log STATUS. These are N/A.')
    else:
        have_status = ws_s is not None and ws_e is not None
        rec('window', 'win-status-present',
            'both window STATUS words were published',
            have_status,
            'start=%s end=%s' % (ws_s, ws_e))

        # EVT_RUN (STATUS bit 3) must be set at BOTH ends. This is the exact
        # condition m2b2SampleEvents() refuses on, recomputed here from the
        # published word rather than read from `m2-b2-window-valid`.
        run_s = have_status and bool(ws_s & M2B2_STATUS_EVT_RUN)
        run_e = have_status and bool(ws_e & M2B2_STATUS_EVT_RUN)
        print('  STATUS start=0x%x end=0x%x  EVT_RUN start=%d end=%d'
              % (ws_s or 0, ws_e or 0, run_s, run_e))
        rec('window', 'win-status-run-start',
            'EVT_RUN was set at the window start', run_s,
            'STATUS=0x%x (bit 3 clear)' % (ws_s or 0))
        rec('window', 'win-status-run-end',
            'EVT_RUN was still set at the window end', run_e,
            'STATUS=0x%x (bit 3 clear)' % (ws_e or 0))

        # EVT_OVERFLOW (bit 0) must be clear at both ends. A ring that wrapped
        # inside the window cannot support "no fault occurred in the window".
        ovf = have_status and bool((ws_s | ws_e) & M2B2_STATUS_EVT_OVERFLOW)
        rec('window', 'win-status-no-overflow',
            'the event ring did not overflow at either end', not ovf,
            'start=0x%x end=0x%x' % (ws_s or 0, ws_e or 0))

        # Head/tail must be 16-byte aligned and inside the ring, at both ends.
        ptrs = [h_s, t_s, h_e, t_e]
        ptr_ok = (all(v is not None for v in ptrs) and
                  all((v & 0xF) == 0 and v < M2B2_EVT_BUFFER_SIZE for v in ptrs))
        rec('window', 'win-status-ptr-aligned',
            'the head/tail words are aligned and in range', ptr_ok,
            'head/tail start=%s/%s end=%s/%s (ring %d B)'
            % (h_s, t_s, h_e, t_e, M2B2_EVT_BUFFER_SIZE))

        # The consumer head is software-owned and must not move across the
        # window; `m2b2SampleEvents()` rejects `head-moved-unexpectedly`.
        head_ok = h_s is not None and h_e is not None and h_s == h_e
        rec('window', 'win-status-head-stable',
            'the consumer head did not move during the window', head_ok,
            'start=%s end=%s' % (h_s, h_e))

        # The produced span must account for exactly the entries the probe
        # counted. This is what ties the two STATUS samples to the records the
        # analyser actually decoded.
        span_ok = False
        if ptr_ok and n_ent is not None:
            span = (t_e + M2B2_EVT_BUFFER_SIZE - h_s) % M2B2_EVT_BUFFER_SIZE
            span_ok = (span % 16 == 0 and span // 16 == n_ent)
            print('  span=%d B -> %d entries, probe counted %d'
                  % (span, span // 16, n_ent))
        rec('window', 'win-status-span',
            'the produced span agrees with the entry count', span_ok,
            'head_start=%s tail_end=%s entries=%s' % (h_s, t_e, n_ent))

    # ROUND 13 (N3): every check in sections 7..12 needs the probe-used
    # snapshot. In control mode there is none by construction, so the block
    # is skipped and its ids are recorded as N/A below.
    #
    # The three verdicts are also defaulted here, so the summary cannot raise a
    # NameError in the one mode where they are genuinely undefined. A defaulted
    # False is the safe direction: it can only withhold a claim.
    paired, cover_ok, batch_ok = [], False, False
    declared = decl_token = token = 0
    faults = []          # decoded IO_PAGE_FAULTs; stays empty in control mode
    if h is not None:
        # ------------------------------------------------------------------
        section('7. VERDICT 1 -- has_complete_pair (recomputed)')
        # ------------------------------------------------------------------
        submits, dones = {}, {}
        for i, r in recs:
            if r['kind'] == 1:
                submits.setdefault(r['cum'], []).append((i, r))
            elif r['kind'] == 2:
                dones.setdefault(r['cum'], []).append((i, r))
        paired = sorted(set(submits) & set(dones))
        rec('pair', 'pair-exists',
            'at least one cumulative index has BOTH a submit and a done',
            len(paired) > 0, 'paired=%d' % len(paired),
            na=is_control)
        print('  paired cumulative indices: %s'
              % ', '.join('0x%x' % c for c in paired[:12]))

        # ------------------------------------------------------------------
        section('8. VERDICT 2 -- records_cover_window (recomputed)')
        # ------------------------------------------------------------------
        times = [r['t'] for _, r in recs]
        oldest = min(times) if times else 0
        cover_pub = rec('cover', 'cover-published',
                        'the snapshot was published at or after winEnd',
                        have_window and h['tPublished'] >= we,
                        'published=%d end=%s' % (h['tPublished'], we),
                        na=not have_window)
        cover_old = rec('cover', 'cover-oldest',
                        'the snapshot reaches back to or before winStart',
                        have_window and oldest != 0 and oldest <= ws,
                        'oldest=%d start=%s' % (oldest, ws), na=not have_window)
        cover_holes = rec('cover', 'cover-holes',
                          'there are no holes in the snapshot', holes == 0)
        cover_ovf = rec('cover', 'cover-overflow',
                        'the ring did not overflow past the window',
                        (h['flags'] & HDR_OVERFLOWED) == 0,
                        'flags=0x%x' % h['flags'])
        cover_ok = (cover_pub and cover_old and cover_holes and cover_ovf)
        rec('cover', 'cover-verdict', '=> records_cover_window', cover_ok,
            na=is_control)
        probe_cover = P.get('m2-b2-obs-records-cover-window')
        rec('cover', 'cover-agrees',
            'the probe\'s claim agrees with the recomputation',
            probe_cover == ('yes' if cover_ok else 'no'),
            'probe=%s recomputed=%s' % (probe_cover, cover_ok),
            na=is_control)

        # ------------------------------------------------------------------
        section('9. VERDICT 3 -- controlled_batch_complete (recomputed)')
        # ------------------------------------------------------------------
        declared = P.get('m2-b2-obs-expected-batch') or 0
        decl_token = P.get('m2-b2-obs-declared-token') or 0
        print('  declared batch = %d, declared token = 0x%08x'
              % (declared, decl_token))
        rec('batch', 'batch-declared', 'this round declared a batch', declared > 0,
            na=is_control)
        # R5: a token of 0 is a refusal, not "derive it from the records".
        rec('batch', 'batch-token-declared', 'this round declared a run token',
            decl_token != 0, 'declared-token=0x%x' % decl_token, na=is_control)
        rec('batch', 'batch-token-joined',
            'the records were joined on that DECLARED token',
            # R5: `token-inferred` is a round-12 field. A round-11 capture does not
            # carry it, and treating its absence as "not inferred" would be a
            # silent pass -- the exact shape this round exists to remove. So the
            # property is recomputed from what the capture DOES carry: the declared
            # token must be non-zero, the join must have resolved to exactly that
            # value, and there must be no ambiguity. If the explicit flag is
            # present it must also say "no".
            P.get('m2-b2-obs-token-resolved') == 'yes' and
            P.get('m2-b2-obs-token-ambiguous') == 'no' and
            (P.get('m2-b2-obs-token-inferred') in (None, 'no')) and
            decl_token != 0 and
            (P.get('m2-b2-obs-join-token') or 0) == decl_token,
            'join=0x%x declared=0x%x inferred=%s ambiguous=%s'
            % (P.get('m2-b2-obs-join-token') or 0, decl_token,
               P.get('m2-b2-obs-token-inferred'),
               P.get('m2-b2-obs-token-ambiguous')),
            na=is_control)

        cl = open(os.path.join(cap, 'client.log'), encoding='utf-8',
                  errors='replace').read()
        pe = open(os.path.join(cap, 'peer.log'), encoding='utf-8',
                  errors='replace').read()
        c_sent = [(int(a, 16), int(b)) for a, b in
                  re.findall(r'client_sent token=0x([0-9a-f]+) req=(\d+)', cl)]
        c_recv = [(int(a, 16), int(b)) for a, b in
                  re.findall(r'client_recv token=0x([0-9a-f]+) req=(\d+)', cl)]
        c_port = re.search(r'client_bound\s+\S+:(\d+)', cl)
        want_port = c_port.group(1) if c_port else None

        all_peer = []
        for a, b in re.findall(r'peer_recv token=0x([0-9a-f]+) req=(\d+)', pe):
            all_peer.append((int(a, 16), int(b), None))
        for _ip, port, head in re.findall(
                r'RECV \d+ bytes from (\S+):(\d+) head=([0-9a-f]{24})', pe):
            tok = int(head[8:16], 16)
            rid = int(head[16:24], 16)
            all_peer.append((tok, rid, port))

        c_tokens = set(t for t, _ in c_sent)
        if want_port is not None:
            p_recv = [(t, r) for (t, r, port) in all_peer
                      if t in c_tokens and port == want_port]
        else:
            p_recv = [(t, r) for (t, r, port) in all_peer if t in c_tokens]

        rec('batch', 'batch-client-sent', 'the client sent exactly the declared number',
            len(c_sent) == declared, '%d vs %d' % (len(c_sent), declared))
        rec('batch', 'batch-client-echo', 'the client received an echo for every send',
            len(c_recv) == len(c_sent) and sorted(c_recv) == sorted(c_sent),
            'sent=%d recv=%d' % (len(c_sent), len(c_recv)))
        rec('batch', 'batch-peer-same', 'the peer received exactly the same set',
            sorted(p_recv) == sorted(c_sent),
            'peer=%d client=%d' % (len(p_recv), len(c_sent)))
        tokens = set(t for t, _ in c_sent)
        rec('batch', 'batch-one-token', 'the client used exactly one run token',
            len(tokens) == 1, 'tokens=%s' % tokens, na=is_control)
        token = tokens.pop() if tokens else 0
        rec('batch', 'batch-token-matches',
            'that token is the one the probe declared',
            token == decl_token, 'client=0x%08x probe=0x%08x'
            % (token, decl_token))
        req_ids = sorted(r for _, r in c_sent)
        rec('batch', 'batch-ids', 'the request ids are exactly 1..declared',
            req_ids == list(range(1, declared + 1)), 'ids=%s' % req_ids)

        # Driver side, recomputed from raw records.
        tx_by_req, rx_by_req = {}, {}
        for i, r in recs:
            if not (r['pkt'] & PKT_PARSED):
                continue
            if r['kind'] == 1:
                tx_by_req.setdefault(r['reqId'], []).append((i, r))
            elif r['kind'] == 3:
                rx_by_req.setdefault(r['reqId'], []).append((i, r))
        print('  driver TX submits parsed : %s' % sorted(tx_by_req))
        print('  driver RX records parsed : %s' % sorted(rx_by_req))
        rec('batch', 'batch-driver-tx',
            'the driver parsed a TX submit for every declared request',
            sorted(tx_by_req) == list(range(1, declared + 1)),
            'tx=%s' % sorted(tx_by_req))
        rec('batch', 'batch-driver-rx',
            'the driver parsed an RX record for every declared request',
            sorted(rx_by_req) == list(range(1, declared + 1)),
            'rx=%s' % sorted(rx_by_req))
        rec('batch', 'batch-driver-token',
            'every driver record carries the client\'s run token',
            all(r['token'] == token for v in tx_by_req.values() for _, r in v) and
            all(r['token'] == token for v in rx_by_req.values() for _, r in v),
            'client token=0x%08x' % token)

        # Per-segment completion, not a count. Counterexample A applied to the real
        # evidence: each submitted cumulative index must have exactly one
        # completion, and no completion may precede its submit.
        seg_ok = True
        seg_report = {}
        order_ok = True
        for req, lst in sorted(tx_by_req.items()):
            rows = []
            for _i, r in lst:
                dl = dones.get(r['cum'], [])
                later = [d for _j, d in dl if d['t'] >= r['t']]
                rows.append((r['cum'], len(dl), len(later)))
                if len(later) != 1:
                    seg_ok = False
                if len(dl) != len(later):
                    order_ok = False
            seg_report[req] = rows
        rec('batch', 'batch-seg-once',
            'every TX segment of every request completed exactly once',
            seg_ok, str(seg_report))
        rec('batch', 'batch-seg-order', 'no completion precedes its own submission',
            order_ok)

        # ---- R5: the batch claim is BOUND to the declared token ---------------
        #
        # Round 11's analyser computed this conjunction from the client log and the
        # records, and never compared the client's token to the one the probe
        # declared. The token was checked as its own separate row, so a run whose
        # load used a DIFFERENT token than the probe had declared could still
        # recompute `controlled_batch_complete = True` while the probe (correctly)
        # refused.
        #
        # That is the same defect one level down: the probe was strict and the
        # analyser was not, so the analyser would have contradicted the production
        # verdict in the permissive direction. The token is part of the predicate,
        # not a row beside it.
        #
        # The 20261101-013600 run found this: the launchd job read round 11's token
        # file, the boot-arg declared a new one, and the analyser said "complete".
        batch_ok = (declared > 0 and decl_token != 0 and token == decl_token and
                    len(c_sent) == declared and
                    sorted(c_recv) == sorted(c_sent) and
                    sorted(p_recv) == sorted(c_sent) and
                    sorted(tx_by_req) == list(range(1, declared + 1)) and
                    sorted(rx_by_req) == list(range(1, declared + 1)) and
                    seg_ok and order_ok)
        rec('batch', 'batch-verdict', '=> controlled_batch_complete', batch_ok,
            na=is_control)
        probe_batch = P.get('m2-b2-obs-controlled-batch-complete')
        rec('batch', 'batch-agrees',
            'the probe\'s claim agrees with the recomputation',
            probe_batch == ('yes' if batch_ok else 'no'),
            'probe=%s recomputed=%s' % (probe_batch, batch_ok),
            na=is_control)

        # ------------------------------------------------------------------
        section('10. EVERY REQUEST\'S DMA RANGES, IN THE WINDOW')
        # ------------------------------------------------------------------
        req_stage = {}
        for req in sorted(tx_by_req):
            rows = []
            for _i, r in tx_by_req[req]:
                dl = dones.get(r['cum'], [])
                td = dl[0][1]['t'] if dl else None
                rows.append({'cum': r['cum'], 'slot': r['slot'],
                             'addr': r['addr'], 'len': r['len'],
                             't_submit': r['t'], 't_done': td,
                             'sub_in': have_window and ws <= r['t'] <= we,
                             'done_in': (td is not None and have_window and
                                         ws <= td <= we)})
            rxs = [{'cum': r['cum'], 'addr': r['addr'], 'len': r['len'],
                    't': r['t'], 'in': have_window and ws <= r['t'] <= we}
                   for _i, r in rx_by_req.get(req, [])]
            req_stage[req] = {'tx': rows, 'rx': rxs}
            for s in rows:
                print('    req %d TX cum=0x%03x addr=0x%-11x len=%3d '
                      't_submit=%d t_done=%s sub_in=%s done_in=%s'
                      % (req, s['cum'], s['addr'], s['len'], s['t_submit'],
                         s['t_done'], s['sub_in'], s['done_in']))
            for s in rxs:
                print('    req %d RX cum=0x%03x addr=0x%-11x len=%3d t=%d in=%s'
                      % (req, s['cum'], s['addr'], s['len'], s['t'], s['in']))

        all_sub_in = all(s['sub_in'] for v in req_stage.values() for s in v['tx'])
        all_done_in = all(s['done_in'] for v in req_stage.values()
                          for s in v['tx'])
        all_rx_in = all(s['in'] for v in req_stage.values() for s in v['rx'])
        rec('chain', 'chain-tx-in', 'every request\'s TX submits are inside the window',
            all_sub_in, na=is_control)
        rec('chain', 'chain-done-in',
            'every request\'s completions are inside the window', all_done_in,
            na=is_control)
        rec('chain', 'chain-rx-in', 'every request\'s RX records are inside the window',
            all_rx_in, na=is_control)

        cl_len = None
        for line in cl.splitlines():
            m2 = re.search(r'client_sent token=0x[0-9a-f]+ req=1 len=(\d+)', line)
            if m2:
                cl_len = int(m2.group(1))
                break
        frame_len = (cl_len + 8 + 20 + 14) if cl_len is not None else None
        all_lens = [s['len'] for v in req_stage.values() for s in v['tx']] + \
                   [s['len'] for v in req_stage.values() for s in v['rx']]
        rec('chain', 'chain-frame-len',
            'every recorded length is the frame the client sent',
            frame_len is not None and all(x == frame_len for x in all_lens),
            'client payload=%s frame=%s records=%s'
            % (cl_len, frame_len, sorted(set(all_lens))),
            # The control branch runs no load, so there is no client frame to
            # compare against.
            na=is_control)

        # ------------------------------------------------------------------
        section('11. RAW DTE -> EVERY BYTE OF EVERY BUSINESS RANGE')
        # ------------------------------------------------------------------
        #
        # The range set comes from the RAW BUSINESS RECORDS, not from the walk
        # export. Round 11 iterated over the exported walks, so a range that was
        # never walked simply was not examined -- seven of eight could be deleted
        # and the report still said 79/79.
        #
        # Here: build the expected set from (token, req, direction, segment, addr,
        # len) in the records, then require the export to match it EXACTLY -- no
        # missing, no duplicate, no extra, no wrong request.
        dte_raw = P.get('m2-b2-bizwalk-dte-raw')
        dte_state = P.get('m2-b2-bizwalk-dte-state')
        print('  DTE raw        = %s' % ('0x%x' % dte_raw if dte_raw else 'ABSENT'))
        print('  DTE state      = %s' % dte_state)

        if is_control:
            for cid, name in (
                    ('pt-dte', 'the probe exported the DTE it walked from'),
                    ('pt-dte-translating', 'the DTE is valid and switched to translation'),
                    ('pt-dte-perms', 'the DTE grants the device read and write'),
                    ('pt-expected', 'the expected range set is non-empty'),
                    ('pt-count', 'the export matches the expected range set'),
                    ('pt-covered', 'every business range is fully covered by legal leaves'),
                    ('pt-perm', 'every range has the permission its direction needs'),
                    ('pt-evidence', '=> the business DMA ranges have complete page-table evidence')):
                rec('pt', cid, name, False, na=True)
            print('\n  NOTE: the control branch never switches the DTE, so there is')
            print('  no page table to walk. These are N/A, not PASS.')
        elif dte_raw is None:
            rec('pt', 'pt-dte', 'the probe exported the DTE it walked from', False,
                'm2-b2-bizwalk-dte-raw absent')
            rec('pt', 'pt-evidence',
                '=> the business DMA ranges have complete page-table evidence',
                False)
        else:
            dte_valid = bool(dte_raw & DTE_V)
            dte_tv = bool(dte_raw & DTE_TV)
            dte_mode = (dte_raw >> DTE_MODE_SHIFT) & DTE_MODE_MASK
            dte_root = dte_raw & PM_ADDR_MASK
            dte_ir = bool(dte_raw & DTE_IR)
            dte_iw = bool(dte_raw & DTE_IW)
            print('  DTE V=%d TV=%d MODE=%d ROOT=0x%x IR=%d IW=%d'
                  % (dte_valid, dte_tv, dte_mode, dte_root, dte_ir, dte_iw))
            rec('pt', 'pt-dte', 'the probe exported the DTE it walked from', True)
            rec('pt', 'pt-dte-translating',
                'the DTE is valid and switched to translation',
                dte_valid and dte_tv and dte_mode in LEVELS,
                'V=%d TV=%d MODE=%d' % (dte_valid, dte_tv, dte_mode))
            rec('pt', 'pt-dte-perms', 'the DTE grants the device read and write',
                dte_ir and dte_iw, 'IR=%d IW=%d' % (dte_ir, dte_iw))
            root_level = LEVELS.get(dte_mode, (0, 0))[0]

            # ---- the expected set, from the raw records ----------------------
            expected = []
            for req in sorted(tx_by_req):
                for si, (_i, r) in enumerate(sorted(tx_by_req[req],
                                                    key=lambda x: x[1]['cum'])):
                    expected.append((req, 'tx', si, r['addr'], r['len']))
                for _i, r in sorted(rx_by_req.get(req, []),
                                    key=lambda x: x[1]['cum']):
                    expected.append((req, 'rx', 0, r['addr'], r['len']))
            rec('pt', 'pt-expected', 'the expected range set is non-empty',
                len(expected) > 0, 'expected=%d' % len(expected))
            print('  expected ranges (from raw records): %d' % len(expected))
            for (req, d, si, a, ln) in expected:
                print('    req %d %s seg %d addr=0x%x len=%d' % (req, d, si, a, ln))

            # ---- the exported set -------------------------------------------
            n = P.get('m2-b2-bizwalk-count') or 0
            exported = []
            for i in range(n):
                exported.append((P.get('m2-b2-bw%d-req' % i),
                                 P.get('m2-b2-bw%d-dir' % i),
                                 P.get('m2-b2-bw%d-seg' % i),
                                 P.get('m2-b2-bw%d-addr' % i),
                                 P.get('m2-b2-bw%d-len' % i), i))
            print('  exported ranges (from the walk): %d' % n)

            # R1: the export must MATCH the expected set exactly.
            exp_key = sorted((int(r), d, int(s), int(a), int(l))
                             for (r, d, s, a, l) in expected)
            got_key = sorted((int(r) if r is not None else -1, d or '?',
                              int(s) if s is not None else -1,
                              int(a) if a is not None else -1,
                              int(l) if l is not None else -1)
                             for (r, d, s, a, l, _i) in exported)
            missing = [k for k in exp_key if k not in got_key]
            extra = [k for k in got_key if k not in exp_key]
            dup = len(got_key) - len(set(got_key))
            rec('pt', 'pt-count', 'the export matches the expected range set',
                not missing and not extra and dup == 0 and n == len(expected),
                'missing=%s extra=%s dup=%d n=%d expected=%d'
                % (missing[:4], extra[:4], dup, n, len(expected)))

            # R1: the probe's own counters must agree with the export. Each is
            # checked separately and only when present, because a round-11 capture
            # has no `bizwalk-expected` at all -- and the analyser's expected set
            # is derived from the raw records anyway, which is the stronger claim.
            p_exp = P.get('m2-b2-bizwalk-expected')
            p_cnt = P.get('m2-b2-bizwalk-count')
            p_ok = P.get('m2-b2-bizwalk-ok')
            p_fail = P.get('m2-b2-bizwalk-fail')
            rec('pt', 'pt-probe-count',
                'the probe\'s bizwalk-count equals the number of exported ranges',
                p_cnt == n, 'probe=%s export=%d' % (p_cnt, n))
            rec('pt', 'pt-probe-expected',
                'the probe\'s bizwalk-expected equals the record-derived set',
                p_exp is None or p_exp == len(expected),
                'probe=%s records=%d' % (p_exp, len(expected)))
            rec('pt', 'pt-probe-ok',
                'the probe\'s ok/fail counters agree with the export size',
                p_ok is None or (p_ok + (p_fail or 0)) == n,
                'ok=%s fail=%s n=%d' % (p_ok, p_fail, n))

            # ---- recompute EVERY range from its raw PTEs --------------------
            all_ok = True
            reasons = {}
            details = []
            for (req, d, si, a, ln, i) in exported:
                root_pa = P.get('m2-b2-bw%d-root-pa' % i)
                if root_pa is None:
                    root_pa = dte_root
                root_lv = P.get('m2-b2-bw%d-root-level' % i) or root_level
                # The root the walk claims must be the one the DTE names. Round 10
                # asserted this against a property that was never published, so the
                # check always passed vacuously.
                if root_pa != dte_root:
                    all_ok = False
                    reasons['root-not-from-dte'] = reasons.get('root-not-from-dte', 0) + 1
                    details.append('bw%d root 0x%x != DTE 0x%x'
                                   % (i, root_pa, dte_root))
                    continue
                if root_lv != root_level:
                    all_ok = False
                    reasons['root-level-mismatch'] = reasons.get('root-level-mismatch', 0) + 1
                    details.append('bw%d root level %s != %s'
                                   % (i, root_lv, root_level))
                    continue
                ok, why, info = recompute_range(P, i, a, ln, d, root_pa, root_lv)
                if not ok:
                    all_ok = False
                    reasons[why] = reasons.get(why, 0) + 1
                    details.append('bw%d (req %s %s 0x%x+%d): %s'
                                   % (i, req, d, a, ln, why))
                else:
                    print('    bw%d req=%s %s 0x%x+%d OK  leaves=%d bytes=%d'
                          % (i, req, d, a, ln, info['leaves'], info['bytes']))

            if reasons:
                print('  failure reasons: %s' % reasons)
                for line in details[:8]:
                    print('    %s' % line)

            rec('pt', 'pt-covered',
                'every business range is fully covered by legal leaves', all_ok,
                str(reasons))
            # `covered` / `perm-ok` are CROSS-CHECKS only: the verdict above comes
            # from the raw PTEs.
            summary_agree = True
            for (req, d, si, a, ln, i) in exported:
                cov = P.get('m2-b2-bw%d-covered' % i)
                per = P.get('m2-b2-bw%d-perm-ok' % i)
                ok, why, info = recompute_range(P, i, a, ln, d,
                                                P.get('m2-b2-bw%d-root-pa' % i) or dte_root,
                                                P.get('m2-b2-bw%d-root-level' % i) or root_level)
                if cov is not None and (cov == 'yes') != ok:
                    summary_agree = False
                if per is not None and ok and per != 'yes':
                    summary_agree = False
            rec('pt', 'pt-summary-agrees',
                'the probe\'s covered/perm-ok summaries agree with the recomputation',
                summary_agree)
            rec('pt', 'pt-perm',
                'every range has the permission its direction needs', all_ok,
                str(reasons))
            rec('pt', 'pt-evidence',
                '=> the business DMA ranges have complete page-table evidence',
                all_ok and len(expected) > 0 and not missing and not extra)

        # ------------------------------------------------------------------
        section('12. EVENT LOG, COMMAND COMPLETION AND RECOVERY')
        # ------------------------------------------------------------------
        #
        # R1: these gates were too weak. The eight surviving mutations included
        # "an event's raw status word zeroed", "a command's completion value
        # changed" and "the invalidation completion moved after the window". None
        # of them was caught, because the checks only looked at the probe's own
        # stage strings.
        #
        # Now: the raw event words are decoded here, the command expected/observed
        # values are compared here, and the TIMELINE (DTE write, invalidation
        # completion, window, business, translation off, restore) is ordered here.
        evt_log = P.get('m2-b2-evt-log')
        rec('events', 'evt-enabled', 'the event log was enabled',
            evt_log == 'enabled', 'evt-log=%s' % evt_log, na=is_control)
        evt_reset = P.get('m2-b2-evt-reset')
        rec('events', 'evt-reset', 'the event log was reset before the window',
            evt_reset == 'done', 'evt-reset=%s' % evt_reset, na=is_control)

        n_raw = P.get('m2-b2-win-raw-count') or 0
        win_trunc = P.get('m2-b2-win-raw-truncated')
        print('  raw window events = %d (truncated=%s)' % (n_raw, win_trunc))
        rec('events', 'evt-not-truncated', 'the raw event window was not truncated',
            win_trunc == 'no', 'truncated=%s' % win_trunc, na=is_control)

        faults = []
        decoded_ok = True
        status_ok = True
        for i in range(n_raw):
            ev = P.get('m2-b2-win-raw%d' % i)
            if not ev or len(ev) != 32:
                decoded_ok = False
                continue
            w = [int(ev[j * 8:(j + 1) * 8], 16) for j in range(4)]
            # Event word layout: [0] devid+flags, [1] type in bits 31:28 plus the
            # status/error word, [2]/[3] the fault address.
            #
            # R1: the STATUS field must be non-zero. A raw event whose status word
            # is zero is not a valid logged event, and zeroing it used to change
            # nothing in the verdict.
            etype = (w[1] >> 28) & 0xF
            status = (w[1] >> 16) & 0xFFF
            if status == 0:
                status_ok = False
                print('    event %d has a ZERO status field (0x%016x)' % (i, w[1]))
            devid = w[0] & 0xFFFF
            if etype == 2:
                a = (w[2] | (w[3] << 32)) & 0xFFFFFFFFFFFFF000
                faults.append((devid, a))
                print('    IO_PAGE_FAULT devid=0x%04x addr=0x%x (%.4f GiB)'
                      % (devid, a, a / (1024.0 ** 3)))
        rec('events', 'evt-decoded', 'every raw event record decoded', decoded_ok,
            na=is_control)
        # ROUND 13 (N1): this check is about the STATUS FIELD INSIDE AN EVENT ENTRY,
        # which is a different register from the event-log STATUS sampled at the
        # window boundaries (section 6b). Round 12 called it `evt-status`, which
        # read like the hardware window check and let that check appear to exist.
        # It keeps its own accurate name, and section 6b now carries the real one.
        rec('events', 'evt-entry-status',
            'every raw event ENTRY carries a non-zero status field', status_ok,
            na=is_control)
        type2 = P.get('m2-b2-win-type2-count') or 0
        rec('events', 'evt-fault-count',
            'the decoded fault count matches the probe\'s counter',
            len(faults) == type2, 'decoded=%d probe=%s' % (len(faults), type2),
            na=is_control)
        rec('events', 'evt-devid', 'every faulting device id is the target device',
            all(d == (probe_bdf or d) for d, _ in faults), str(faults),
            na=is_control)
        limit = P.get('m2-b2-map-limit')
        if P.get('m2-b2-r15-map-mode') == 'bootstrap-plus-owned-sparse4k':
            # Round 15 keeps map-limit as the BOOTSTRAP limit, not a bound on
            # sparse owned pages. Address magnitude alone no longer judges a
            # fault's mapping: tools/r15/analyze.py must walk its actual path.
            rec('events', 'evt-limit',
                'the bootstrap limit is not a sparse-map coverage verdict',
                False, 'sparse coverage requires the exported raw-table walk',
                na=True)
        elif limit is not None:
            over = [a for _, a in faults if a >= limit]
            print('  identity map limit = 0x%x (%.4f GiB)'
                  % (limit, limit / (1024.0 ** 3)))
            rec('events', 'evt-limit', 'no fault lies at or above the identity map limit',
                len(over) == 0, 'over-limit: %s' % ['0x%x' % a for a in over],
                na=is_control)
        else:
            # A check that is conditional on a FIELD must still be recorded. A
            # missing row changes the denominator of the summary without saying so;
            # an N/A row is counted and printed.
            rec('events', 'evt-limit',
                'no fault lies at or above the identity map limit', False,
                'm2-b2-map-limit absent', na=True)

        # ---- command completion: expected vs observed ----------------------
        #
        # R1: the command records carry (label, dwords, expected, observed, loops,
        # ok). Round 11 only read the probe's stage strings. Comparing expected to
        # observed HERE is what catches a changed completion value.
        cmd_n = P.get('m2-b2-cmd-record-count') or 0
        cmd_ok = True
        cmd_lines = []
        for i in range(cmd_n):
            label = P.get('m2-b2-cmd%d-label' % i)
            exp = P.get('m2-b2-cmd%d-expected' % i)
            obs = P.get('m2-b2-cmd%d-observed' % i)
            okf = P.get('m2-b2-cmd%d-ok' % i)
            loops = P.get('m2-b2-cmd%d-loops' % i)
            cmd_lines.append('%s: expected=%s observed=%s ok=%s loops=%s'
                             % (label, exp, obs, okf, loops))
            if exp is None or obs is None or exp != obs:
                cmd_ok = False
            if okf != 'yes':
                cmd_ok = False
        print('  command records: %d' % cmd_n)
        for l in cmd_lines:
            print('    %s' % l)
        rec('cmd', 'cmd-records',
            'the command records carry expected and observed values',
            cmd_n > 0 and all(P.get('m2-b2-cmd%d-expected' % i) is not None and
                              P.get('m2-b2-cmd%d-observed' % i) is not None
                              for i in range(cmd_n)),
            'records=%d' % cmd_n, na=is_control)
        rec('cmd', 'cmd-expected-eq-observed',
            'every command\'s observed value equals its expected value',
            cmd_ok, '; '.join(cmd_lines[:4]), na=is_control)
        rec('cmd', 'cmd-inv-completed', 'the invalidation commands all completed',
            P.get('m2-b2-stage-inv-dev') == 'yes' and
            P.get('m2-b2-stage-inv-pages') == 'yes',
            'inv-dev=%s inv-pages=%s' % (P.get('m2-b2-stage-inv-dev'),
                                         P.get('m2-b2-stage-inv-pages')),
            na=is_control)
        rec('cmd', 'cmd-buffer-stopped', 'the command buffer was stopped before restore',
            P.get('m2-b2-cmdbuf-stopped') == 'yes',
            'stopped=%s' % P.get('m2-b2-cmdbuf-stopped'), na=is_control)
        rec('cmd', 'cmd-evtlog-stopped', 'the event log was stopped before restore',
            P.get('m2-b2-evtlog-stopped') == 'yes',
            'stopped=%s' % P.get('m2-b2-evtlog-stopped'), na=is_control)

        # ---- THE TIMELINE ---------------------------------------------------
        #
        # R1: "the invalidation completion moved after the window" survived. The
        # ordering below is what makes it fail.
        #
        #   tDteWritten <= tInvComplete = tTranslateOn <= tWinStart
        #   tWinEnd <= tTranslateOff <= tRecoveryEnd
        #   every business stage inside [tWinStart, tWinEnd]
        t_dte = P.get('m2-b2-dma-t-dte-written')
        t_inv = P.get('m2-b2-dma-t-inv-complete')
        t_on = P.get('m2-b2-dma-t-translate-on')
        t_off = P.get('m2-b2-dma-t-translate-off')
        t_rec = P.get('m2-b2-t-recovery-end')
        print('  tDteWritten=%s tInvComplete=%s tTranslateOn=%s' % (t_dte, t_inv, t_on))
        print('  tWinStart=%s tWinEnd=%s tTranslateOff=%s tRecoveryEnd=%s'
              % (ws, we, t_off, t_rec))

        have_timeline = all(v is not None for v in (t_dte, t_inv, t_on, t_off, ws, we))
        if is_control:
            rec('timeline', 'tl-fields', 'the timeline fields are present',
                have_timeline, na=True)
            rec('timeline', 'tl-order', 'the timeline is ordered', False, na=True)
            # The control branch has no translation window, so there is no window
            # for a business record to fall inside. Recorded as N/A rather than
            # omitted, so every run reports the same check ids.
            rec('timeline', 'tl-business-inside',
                'every business record falls inside the translation window',
                False, na=True)
        else:
            rec('timeline', 'tl-fields', 'the timeline fields are present',
                have_timeline,
                'dte=%s inv=%s on=%s off=%s ws=%s we=%s'
                % (t_dte, t_inv, t_on, t_off, ws, we))
            if have_timeline:
                order = []
                if not (t_dte <= t_inv):
                    order.append('DTE write (%d) after invalidation completion (%d)'
                                 % (t_dte, t_inv))
                if t_on != t_inv:
                    order.append('translate-on (%d) is not the invalidation '
                                 'completion (%d)' % (t_on, t_inv))
                # R1: this is the check the "moved after the window" mutation hits.
                if not (t_on <= ws):
                    order.append('translation became effective (%d) AFTER the '
                                 'window opened (%d)' % (t_on, ws))
                if not (we <= t_off):
                    order.append('translation was switched off (%d) BEFORE the '
                                 'window closed (%d)' % (t_off, we))
                if t_rec is not None and not (t_off <= t_rec):
                    order.append('recovery (%d) precedes translation-off (%d)'
                                 % (t_rec, t_off))
                for l in order:
                    print('    %s' % l)
                rec('timeline', 'tl-order', 'the timeline is ordered', not order,
                    '; '.join(order[:3]))
                # And every business stage must be inside the window, checked from
                # the raw records rather than from the probe's summary.
                inside = True
                for i, r in recs:
                    if not (r['pkt'] & PKT_PARSED):
                        continue
                    if not (t_on <= r['t'] <= t_off):
                        inside = False
                rec('timeline', 'tl-business-inside',
                    'every business record falls inside the translation window',
                    inside)
            else:
                rec('timeline', 'tl-order', 'the timeline is ordered', False,
                    'missing timeline fields')
                rec('timeline', 'tl-business-inside',
                    'every business record falls inside the translation window',
                    False, 'missing timeline fields')

        rec('recovery', 'rec-disabled', 'the IOMMU was disabled',
            P.get('m2-b2-disabled') == 'yes',
            'disabled=%s' % P.get('m2-b2-disabled'))
        rec('recovery', 'rec-regs', 'the original registers were restored',
            P.get('m2-b2-regs-restored') == 'yes',
            'restored=%s (abort=%s)'
            % (P.get('m2-b2-regs-restored'), P.get('m2-b2-restore-abort')))
        rec('recovery', 'rec-cleanup',
            'resources were released or explicitly retained',
            P.get('m2-b2-cleanup') in ('done',
                                       'REFUSED-hardware-not-proven-idle'),
            'cleanup=%s' % P.get('m2-b2-cleanup'))

    else:
        # A control capture has no probe-used snapshot, so none of the checks
        # above can run. Every id is still recorded -- as N/A -- so the
        # denominator of the summary does not silently shrink.
        for _cid in (
            'pair-exists',
            'cover-published',
            'cover-oldest',
            'cover-holes',
            'cover-overflow',
            'cover-verdict',
            'cover-agrees',
            'batch-declared',
            'batch-token-declared',
            'batch-token-joined',
            'batch-client-sent',
            'batch-client-echo',
            'batch-peer-same',
            'batch-one-token',
            'batch-token-matches',
            'batch-ids',
            'batch-driver-tx',
            'batch-driver-rx',
            'batch-driver-token',
            'batch-seg-once',
            'batch-seg-order',
            'batch-verdict',
            'batch-agrees',
            'chain-tx-in',
            'chain-done-in',
            'chain-rx-in',
            'chain-frame-len',
            'pt-dte',
            'pt-dte-translating',
            'pt-dte-perms',
            'pt-expected',
            'pt-count',
            'pt-probe-count',
            'pt-probe-expected',
            'pt-probe-ok',
            'pt-covered',
            'pt-summary-agrees',
            'pt-perm',
            'pt-evidence',
            'evt-enabled',
            'evt-reset',
            'evt-not-truncated',
            'evt-decoded',
            'evt-entry-status',
            'evt-fault-count',
            'evt-devid',
            'evt-limit',
            'cmd-records',
            'cmd-expected-eq-observed',
            'cmd-inv-completed',
            'cmd-buffer-stopped',
            'cmd-evtlog-stopped',
            'tl-fields',
            'tl-order',
            'tl-business-inside',
            'rec-disabled',
            'rec-regs',
            'rec-cleanup',
            ):
            rec('na', _cid, 'translation-only check: not applicable in this mode',
                False, na=True)
    # ------------------------------------------------------------------
    section('12b. THE RX POSTED-BUFFER SET (round 14)')
    # ------------------------------------------------------------------
    #
    # WHAT THIS SECTION IS FOR
    # ------------------------
    # Everything above is about the business exchange: eight DMA ranges for four
    # controlled requests. That proves those eight buffers are mapped. It says
    # nothing about the other ~1016 RX buffers the device can write, nor about
    # the ones it re-posts during the window.
    #
    # Round 14's probe builds the CONSERVATIVE SET
    #
    #     S = { (addr, cap) in the baseline slot table }
    #       ∪ { (addr, cap) and (oldAddr, cap) from every rearm record }
    #
    # and walks every range in it. This section rebuilds S from the driver's own
    # published blob -- not from the probe's summary -- and then checks the
    # probe's arithmetic against it.
    #
    # WHY THE REBUILD MATTERS
    # -----------------------
    # If this section only read `m2-b2-rxset-ok == m2-b2-rxset-ranges`, the
    # coverage claim would be the probe's own arithmetic checked against itself.
    # That is the round-12 defect one level up. The blob is decoded here from
    # the archived bytes, the set is rebuilt here, and the probe's counts must
    # match what this rebuild produces.
    rx_present = P.get('m2-b2-rxset') == 'present'
    # VINTAGE, NOT A DEFECT.
    #
    # A capture made by a probe built BEFORE round 14 cannot carry any rxset
    # property: the code that publishes them did not exist. Judging such a
    # capture as "the RX set failed" would be wrong in the same way round 12's
    # control schema was wrong -- it would report the absence of an experiment
    # as a failure of it, and it would silently change the verdict of every
    # archived run instead of tightening a check.
    #
    # So the vintage is detected from the property set (not from a version
    # string, which a probe could carry without the code) and those checks are
    # recorded as N/A. The report says so explicitly; N/A is never a pass.
    rxset_vintage = (P.get('m2-b2-rxset') is None and
                     P.get('m2-b2-rxset-why') is None and
                     P.get('m2-b2-rxset-raw') is None)
    rx_raw_prop = re.search(r'"m2-b2-rxset-raw"\s*=\s*<([0-9a-fA-F]+)>', raw)
    rx_raw_file_p = os.path.join(cap, 'rxset-raw.bin')
    rx_raw_file = (open(rx_raw_file_p, 'rb').read()
                   if os.path.exists(rx_raw_file_p) else None)
    rx_raw = bytes.fromhex(rx_raw_prop.group(1)) if rx_raw_prop else None

    print('  probe read the RX post tables : %s' % (P.get('m2-b2-rxset')))
    print('  probe reason                  : %s' % (P.get('m2-b2-rxset-why')))
    print('  set reason                    : %s'
          % (P.get('m2-b2-rxset-set-why')))
    print('  blob in props.raw.txt         : %s'
          % (('%d B' % len(rx_raw)) if rx_raw else 'ABSENT'))
    print('  archived rxset-raw.bin        : %s'
          % (('%d B' % len(rx_raw_file)) if rx_raw_file else 'ABSENT'))
    if rxset_vintage:
        print('  VINTAGE: this capture was made by a probe that has no RX post')
        print('           code at all (round 13 or earlier). The RX set checks')
        print('           are N/A here, NOT passed -- the question was never')
        print('           asked of this input.')

    rx = decode_rxpost(rx_raw_file or rx_raw)

    rec('rxset', 'rxset-present',
        'the probe read the driver RX post tables',
        rx_present or rxset_vintage,
        'm2-b2-rxset=%s why=%s' % (P.get('m2-b2-rxset'),
                                   P.get('m2-b2-rxset-why')),
        na=rxset_vintage or (not is_translation))

    # ---- the blob the probe used must be the blob archived ----
    rx_sha = P.get('m2-b2-rxset-raw-sha256')
    ok_rx_sha_raw = rec('rxset', 'rxset-sha-raw',
                        'the exported RX blob matches the probe sha256',
                        rx_raw is not None and rx_sha == sha256_bytes(rx_raw),
                        'probe=%s raw=%s'
                        % (rx_sha,
                           sha256_bytes(rx_raw) if rx_raw else 'absent'),
                        na=rxset_vintage or (not is_translation))
    ok_rx_sha_file = rec('rxset', 'rxset-sha-file',
                         'the archived RX blob matches the probe sha256',
                         rx_raw_file is not None and
                         rx_sha == sha256_bytes(rx_raw_file),
                         'probe=%s file=%s'
                         % (rx_sha,
                            sha256_bytes(rx_raw_file) if rx_raw_file
                            else 'absent'),
                         na=rxset_vintage or (not is_translation))
    rec('rxset', 'rxset-exported',
        'the probe exported the RX blob it built the set from',
        # The STATUS lives under `m2-b2-rxset-raw-state`; `m2-b2-rxset-raw`
        # holds the OSData itself. They were the same key in the first version,
        # and IOKit replaced the blob with the string -- see
        # tools/r14/verify-property-names.py.
        P.get('m2-b2-rxset-raw-state') == 'exported' and rx_raw is not None,
        'raw-state=%s raw=%s'
        % (P.get('m2-b2-rxset-raw-state'),
           'present' if rx_raw is not None else 'absent'),
        na=rxset_vintage or (not is_translation))

    if rxset_vintage and is_translation:
        # Everything else in this section depends on a blob that cannot exist
        # for this input. Recorded individually so the summary shows the shape
        # of what was NOT asked, rather than a single lumped N/A.
        for _cid in ('rxset-published-through-end',
                     'rxset-baseline-full', 'rxset-baseline-current',
                     'rxset-no-gen-move', 'rxset-no-gap', 'rxset-watermark-sane', 'rxset-no-loss',
                     'rxset-not-truncated', 'rxset-gen-stable',
                     'rxset-set-complete', 'rxset-ranges-agree',
                     'rxset-from-baseline-agree', 'rxset-from-rearm-agree',
                     'rxset-all-walked', 'rxset-arith-closes',
                     'rxset-all-covered', 'rxset-walk-dte',
                     'rxset-failures-enumerated', 'rxset-high-address-kept'):
            rec('rxset', _cid,
                'RX set check: the capture predates round 14', False,
                na=True)
        rx = None
    elif rx and rx['ok']:
        h = rx['hdr']
        print('  header: %d B, pub=%d head=%d gen=%d epoch=%d vtdPath=%d'
              % (len(rx_raw_file or rx_raw), h['pubId'], h['head'],
                 h['ringGen'], h['epoch'], h['vtdPath']))
        print('  baseline: slots=%d valid=%d zero=%d capDesc=%d capConst=%d '
              'capBad=%d torn=%d'
              % (h['baselineSlots'], h['baselineValid'],
                 h['baselineAddrZero'], h['baselineCapDesc'],
                 h['baselineCapConst'], h['baselineCapBad'],
                 h['baselineTorn']))
        print('  rearm: watermark=%d required=%d published=%d firstSeq=%d '
              'dropped=%d wrapped=%d'
              % (rx['watermark'], h['rearmRequired'], h['rearmPublished'],
                 h['rearmFirstSeq'], h['dropped'], h['wrapped']))

        # The RX publication is independent of the business snapshot. A clean
        # but stale RX suffix cannot prove the set through the actual DMA-window
        # end, even when that other snapshot was published late enough.
        rec('rxset', 'rxset-published-through-end',
            'the RX post snapshot was published at or after winEnd',
            have_window and h['tPublished'] >= we,
            'published=%d end=%s' % (h['tPublished'], we),
            na=not is_translation)

        # ---- the baseline must be COMPLETE, not partial ----
        #
        # A capture with fewer slot records than the ring has descriptors would
        # describe part of the ring. The count is compared with the header's own
        # capacity, so a truncated table is a refusal rather than a smaller set.
        rec('rxset', 'rxset-baseline-full',
            'the baseline covers every descriptor of the ring',
            h['baselineSlots'] == h['slotCapacity'] and h['slotCapacity'] > 0,
            'baselineSlots=%d slotCapacity=%d'
            % (h['baselineSlots'], h['slotCapacity']))

        # ---- the baseline must not have been invalidated ----
        rec('rxset', 'rxset-baseline-current',
            'no ring rebuild invalidated the baseline',
            (h['flags'] & RXPOST_FLAG_NO_BASELINE) == 0,
            'flags=0x%x' % h['flags'])
        rec('rxset', 'rxset-no-gen-move',
            'no capture saw the ring generation move',
            (h['flags'] & RXPOST_FLAG_GEN_MOVED) == 0,
            'flags=0x%x baselineGenMoved=%d'
            % (h['flags'], h['baselineGenMoved']))

        # ---- the rearm log must be gap-free ----
        #
        # THE GAP CHECK IS THE HEART OF THE SET ARGUMENT.
        #
        # `rearmFirstSeq` is the oldest ticket the ring still holds. If it is
        # greater than watermark+1, records between the baseline and the oldest
        # survivor are gone, so the union is a SUBSET of what the device could
        # write -- and "every range covered" would be a statement about the
        # wrong set.
        #
        # WHICH WATERMARK, AND WHY IT MATTERS
        # -----------------------------------
        # The header's `rearmSeqAtBaseline` is NOT stable: the driver re-captures
        # the baseline once a second on the watchdog, and each capture advances
        # that field. Reading it out of a blob published after the window
        # therefore gives the LATEST capture's watermark, not the one the probe
        # stamped before the window -- and since the latest capture is always at
        # or after the head, the check would pass trivially.
        #
        # The binding watermark is the one the PROBE stored on its pre-window
        # read and published as `m2-b2-rxset-watermark`. That is what the set was
        # actually joined on, so that is what this check uses. The header value
        # is reported alongside so the difference is visible rather than hidden.
        probe_wm = P.get('m2-b2-rxset-watermark')
        wm_used = probe_wm if probe_wm is not None else rx['watermark']
        wm_source = 'probe' if probe_wm is not None else 'header'
        first_seq = h['rearmFirstSeq']
        need_from = wm_used + 1
        gap_ok = (wm_used == 0) or (first_seq != 0 and first_seq <= need_from)
        rec('rxset', 'rxset-no-gap',
            'the rearm ring still holds every record after the watermark',
            gap_ok,
            'firstSeq=%d watermark=%d [%s] (need <= %d); header says %d'
            % (first_seq, wm_used, wm_source, need_from, rx['watermark']))
        # The probe's watermark must not be AHEAD of the head it published: that
        # would mean the set was joined on records that do not exist yet.
        rec('rxset', 'rxset-watermark-sane',
            'the joined watermark does not exceed the rearm head',
            wm_used <= h['head'],
            'watermark=%d head=%d' % (wm_used, h['head']))
        rec('rxset', 'rxset-no-loss',
            'no rearm record was dropped or displaced',
            h['dropped'] == 0 and h['wrapped'] == 0,
            'dropped=%d wrapped=%d' % (h['dropped'], h['wrapped']))
        rec('rxset', 'rxset-not-truncated',
            'the publication carries every record the watermark requires',
            (h['flags'] & RXPOST_FLAG_TRUNCATED) == 0 and
            h['rearmPublished'] >= h['rearmRequired'],
            'flags=0x%x published=%d required=%d'
            % (h['flags'], h['rearmPublished'], h['rearmRequired']))

        # ---- the ring generation must be the one seen before the window ----
        pre_gen = P.get('m2-b2-rxset-pre-ring-gen')
        rec('rxset', 'rxset-gen-stable',
            'the ring was not rebuilt between the two reads',
            pre_gen is not None and pre_gen == h['ringGen'],
            'pre=%s post=%s' % (pre_gen, h['ringGen']))

        # ---- REBUILD THE SET HERE, from the blob ----
        #
        # This is the independent part: the same union the probe built, built
        # again from the archived bytes, with the analyser's own de-duplication.
        # Every count the probe published is then compared with this rebuild.
        rebuilt, rstat = rebuild_rx_set(rx)
        print('  rebuilt set: %d ranges (%d baseline, %d rearm-only, '
              '%d both), %d zero-skipped, %d capped'
              % (rstat['ranges'], rstat['fromBaseline'], rstat['fromRearm'],
                 rstat['fromBoth'], rstat['skippedZero'], rstat['capped']))

        rec('rxset', 'rxset-set-complete',
            'the probe reported the set complete',
            P.get('m2-b2-rxset-complete') == 'yes',
            'm2-b2-rxset-complete=%s set-why=%s'
            % (P.get('m2-b2-rxset-complete'),
               P.get('m2-b2-rxset-set-why')))

        # The probe's counts must equal the rebuild. A disagreement means one of
        # the two is not describing the blob, and the coverage claim would be
        # about neither.
        probe_ranges = P.get('m2-b2-rxset-ranges')
        rec('rxset', 'rxset-ranges-agree',
            'the probe range count equals the independent rebuild',
            probe_ranges == rstat['ranges'],
            'probe=%s rebuild=%d' % (probe_ranges, rstat['ranges']))
        rec('rxset', 'rxset-from-baseline-agree',
            'the baseline contribution equals the rebuild',
            P.get('m2-b2-rxset-from-baseline') == rstat['fromBaseline'],
            'probe=%s rebuild=%d'
            % (P.get('m2-b2-rxset-from-baseline'), rstat['fromBaseline']))
        rec('rxset', 'rxset-from-rearm-agree',
            'the rearm contribution equals the rebuild',
            P.get('m2-b2-rxset-from-rearm') == rstat['fromRearm'],
            'probe=%s rebuild=%d'
            % (P.get('m2-b2-rxset-from-rearm'), rstat['fromRearm']))

        # ---- every range in the rebuilt set must have been WALKED ----
        #
        # The probe publishes `rxset-walked`. If it is smaller than the rebuilt
        # set, some ranges were never checked and "all covered" would be about
        # the subset that was.
        walked = P.get('m2-b2-rxset-walked')
        rec('rxset', 'rxset-all-walked',
            'the probe walked every range in the rebuilt set',
            walked == rstat['ranges'],
            'walked=%s rebuild=%d' % (walked, rstat['ranges']))

        # ---- the arithmetic must close ----
        ok_n = P.get('m2-b2-rxset-ok')
        fail_n = P.get('m2-b2-rxset-fail')
        cap_n = P.get('m2-b2-rxset-fail-capped')
        rec('rxset', 'rxset-arith-closes',
            'walked == ok + fail and capped is counted inside fail',
            (walked is not None and ok_n is not None and fail_n is not None
             and cap_n is not None
             and walked == ok_n + fail_n
             and cap_n <= fail_n),
            'walked=%s ok=%s fail=%s capped=%s'
            % (walked, ok_n, fail_n, cap_n))

        # ---- THE COVERAGE RESULT ----
        #
        # This is the round's actual answer. It is a separate check from the
        # arithmetic so that "the set was built correctly" and "the set is
        # mapped" cannot be confused with each other.
        rec('rxset', 'rxset-all-covered',
            'every RX range the device can write is mapped with write permission',
            (fail_n == 0 and cap_n == 0 and ok_n is not None
             and walked is not None and ok_n == walked and walked > 0),
            'ok=%s walked=%s fail=%s capped=%s'
            % (ok_n, walked, fail_n, cap_n))

        # ---- the walk must have used the experiment's own DTE ----
        rec('rxset', 'rxset-walk-dte',
            'the RX walk started from the DTE the experiment wrote',
            P.get('m2-b2-rxset-dte-raw') is not None and
            P.get('m2-b2-rxset-dte-root-pa') is not None and
            P.get('m2-b2-rxset-root-level') in (3, 4),
            'dte=%s root=%s level=%s'
            % (P.get('m2-b2-rxset-dte-raw'),
               P.get('m2-b2-rxset-dte-root-pa'),
               P.get('m2-b2-rxset-root-level')))

        # ---- the failing ranges must be enumerated ----
        #
        # A failure count with no addresses is not actionable, so the number of
        # exported detail blocks must equal the failure count (up to the export
        # cap, which the probe publishes separately).
        bad_count = P.get('m2-b2-rxset-bad-count')
        rec('rxset', 'rxset-failures-enumerated',
            'every failing range is exported with its address and reason',
            bad_count is not None and
            (fail_n == 0 or bad_count == min(fail_n, RXSET_DETAIL_MAX)),
            'fail=%s bad-count=%s (cap %d)'
            % (fail_n, bad_count, RXSET_DETAIL_MAX))

        # ---- high addresses must be reported, not filtered ----
        #
        # Legacy captures map a contiguous 16 GiB. Round 15 retains that
        # bootstrap and adds sparse actual-owned pages; being above 16 GiB alone
        # is therefore no longer evidence of a mapping gap. In either mode all
        # addresses must survive set reconstruction and reach the table walk.
        max_end = P.get('m2-b2-rxset-max-end')
        high = (max_end is not None and max_end > (16 << 30))
        rec('rxset', 'rxset-high-address-kept',
            'RX ranges above the 16 GiB bootstrap remain in the set',
            True,
            'max-end=%s%s' % (max_end, ' (ABOVE 16 GiB)' if high else ''),
            na=False)
        if high:
            print('  NOTE: the set reaches 0x%x, above the 16 GiB bootstrap.'
                  % max_end)
            print('        Coverage is decided by actual table walks, not height.')
    else:
        why = (rx['why'] if rx else 'no-blob')
        rec('rxset', 'rxset-blob-valid',
            'the archived RX blob decodes against the wire layout',
            False, 'decode failed: %s' % why, na=(not is_translation))
        for _cid in ('rxset-published-through-end',
                     'rxset-baseline-full', 'rxset-baseline-current',
                     'rxset-no-gen-move', 'rxset-no-gap', 'rxset-watermark-sane', 'rxset-no-loss',
                     'rxset-not-truncated', 'rxset-gen-stable',
                     'rxset-set-complete', 'rxset-ranges-agree',
                     'rxset-from-baseline-agree', 'rxset-from-rearm-agree',
                     'rxset-all-walked', 'rxset-arith-closes',
                     'rxset-all-covered', 'rxset-walk-dte',
                     'rxset-failures-enumerated',
                     'rxset-high-address-kept'):
            rec('rxset', _cid,
                'RX set check: not applicable (no decodable blob)', False,
                na=True)
    # ------------------------------------------------------------------
    section('13. MODE SCHEMA')
    # ------------------------------------------------------------------
    if is_translation:
        # Fields a TRANSLATION capture must carry for its claims to be
        # checkable at all. These are the ones whose absence made round 10's
        # analyser pass vacuously (it asserted against `m2-b2-dte-root`, which
        # was never published).
        required_fields = ['m2-b2-bizwalk-dte-raw', 'm2-b2-bizwalk-count',
                           'm2-b2-obs-used-sha256', 'm2-b2-obs-epoch-bound',
                           'm2-b2-obs-declared-token']
        missing = [k for k in required_fields if P.get(k) in (None, '')]
        rec('schema', 'schema-fields',
            'every field the translation schema requires is present',
            not missing, 'missing: %s' % missing)
        # Fields round 12 ADDED. A capture from an older probe cannot carry
        # them, and that is a fact about the capture's VINTAGE -- not a defect
        # in the analysis, and not something to paper over either.
        #
        # So it is reported as N/A (not applicable to this input) rather than
        # as PASS, and a companion check states what the analyser does instead.
        # N/A is the honest answer: the property was not verified from the
        # probe, it was recomputed from the raw records. Calling that a PASS
        # would claim the probe published something it never did.
        r12_fields = ['m2-b2-bizwalk-expected', 'm2-b2-obs-token-inferred']
        absent_r12 = [k for k in r12_fields if P.get(k) in (None, '')]
        rec('schema', 'schema-r12-fields',
            'the capture carries the fields round 12 added',
            not absent_r12,
            'absent: %s -- this capture predates round 12' % absent_r12,
            na=bool(absent_r12))
        rec('schema', 'schema-r12-recomputed',
            'the round-12 properties are recomputed from raw records here',
            True,
            'the range set is derived from the raw business records and the '
            'token binding from the declared token, so neither depends on a '
            'probe field that may be absent')
        rec('schema', 'schema-control-na',
            'the control-mode N/A rules do not apply to this capture', False,
            na=True)
    elif is_control:
        # THE CONTROL BRANCH'S REAL SHAPE.
        #
        # ROUND 13 (N4): round 12 wrote this list by hand and got it wrong in
        # BOTH directions.
        #
        #   * It asserted that `m2-b2-stage-inv-all` / `-inv-dev` / `-inv-pages`
        #     are absent. They are not: the control branch does `goto recover`,
        #     and step 18 -- which publishes them -- runs AFTER the label. So a
        #     real control capture carries them, and the round-12 fixture
        #     deleted them to satisfy a schema that was simply wrong.
        #   * It invented `m2-b2-obs-snapshot-used` in the fixture, a property
        #     the branch cannot produce, which hid the fact that the analyser
        #     refused a legitimate control capture.
        #
        # The lists below are derived from the source by
        # tools/r13/control-shape.py, and tools/r13/verify-control-shape.py
        # asserts that this block and that derivation agree. A hand-written
        # claim about the code is what failed; the check is against the code.
        #
        # Translation-only: the `goto recover` jumps over everything between the
        # branch and the label, plus the work the translation path does before
        # it (DTE switch, invalidation, window, snapshot decode, walk).
        must_be_absent = [
            'm2-b2-bizwalk-dte-raw', 'm2-b2-bizwalk-dte-mode',
            'm2-b2-bizwalk-dte-root-pa', 'm2-b2-bizwalk-dte-state',
            'm2-b2-bizwalk-root-level', 'm2-b2-bizwalk-count',
            'm2-b2-bizwalk-ok', 'm2-b2-bizwalk-fail',
            'm2-b2-bizwalk-expected', 'm2-b2-bizwalk-capped',
            'm2-b2-bizwalk-why', 'm2-b2-bizwalk',
            'm2-b2-bw0-addr', 'm2-b2-bw0-req',
            'm2-b2-dma-t-win-start', 'm2-b2-dma-t-win-end',
            'm2-b2-dma-t-translate-on', 'm2-b2-dma-t-inv-complete',
            'm2-b2-dma-t-dte-written',
            'm2-b2-window-valid', 'm2-b2-window-invalid',
            'm2-b2-win-status-start', 'm2-b2-win-status-end',
            'm2-b2-win-head-start', 'm2-b2-win-tail-end',
            'm2-b2-win-entries', 'm2-b2-win-raw-count',
            'm2-b2-obs-used', 'm2-b2-obs-used-sha256',
            'm2-b2-obs-used-pub-id', 'm2-b2-obs-used-t-published',
            'm2-b2-obs-declared-token', 'm2-b2-obs-join-token',
            'm2-b2-obs-token-resolved', 'm2-b2-obs-expected-batch',
            'm2-b2-obs-controlled-batch-complete',
            'm2-b2-obs-has-complete-pair', 'm2-b2-obs-records-cover-window',
            'm2-b2-obs-snapshot-used',
            'm2-b2-nic-bdf', 'm2-b2-nic-vendor', 'm2-b2-nic-device',
            'm2-b2-nic-unit', 'm2-b2-nic-mac',
            'm2-b2-page-mode',
            # The instance binding is step 15c, which is AFTER the control
            # branch's `goto recover`, so a control run never binds an epoch.
            'm2-b2-obs-epoch-bound', 'm2-b2-obs-epoch-binding',
        ]
        still_present = [k for k in must_be_absent if P.get(k) is not None]
        rec('schema', 'schema-control-shape',
            'the control capture lacks every translation-only field',
            not still_present,
            'present-but-impossible-in-control-mode: %s' % still_present)
        if still_present:
            print('  NOTE: the control branch jumps to `recover` before the DTE')
            print('        switch, the window, the snapshot decode and the walk,')
            print('        so a capture carrying those fields is NOT a control')
            print('        run. Relabelling a translation capture does not make')
            print('        it one, and accepting it would turn the control N/A')
            print('        set into a way of skipping checks.')

        # And the OTHER half, which round 12 never checked: a control capture
        # must carry the fields the control path DOES publish. Without this the
        # schema only rejects; it never requires, so an empty capture labelled
        # control would pass the shape test.
        #
        # `m2-b2-ctl-t-start` / `-t-end` are inside the branch; the rest are on
        # the shared or the recover path.
        must_be_present = [
            'm2-b2-mode', 'm2-b2-verdict', 'm2-b2-stage',
            'm2-b2-sleep-only', 'm2-b2-window-secs',
            'm2-b2-ctl-t-start', 'm2-b2-ctl-t-end', 'm2-b2-ctl-dur-ms',
            'm2-b2-target-devid', 'm2-b2-tgt-source',
            'm2-b2-evt-log', 'm2-b2-evt-reset',
            'm2-b2-inv-all', 'm2-b2-stage-evt-reset', 'm2-b2-stage-inv-all',
            'm2-b2-stage-inv-dev', 'm2-b2-stage-inv-pages',
            'm2-b2-stage-control-done',
            'm2-b2-disabled', 'm2-b2-regs-restored', 'm2-b2-cleanup',
            'm2-b2-cmdbuf-stopped', 'm2-b2-evtlog-stopped',
            'm2-b2-t-recovery-start', 'm2-b2-t-recovery-end',
        ]
        absent_required = [k for k in must_be_present if P.get(k) is None]
        rec('schema', 'schema-control-required',
            'the control capture carries every field the control path publishes',
            not absent_required,
            'missing: %s' % absent_required)

        # THE CONTROL VERDICT IS EARNED, NOT ASSERTED.
        #
        # Round 12 accepted control mode on the strength of the mode string.
        # The production branch already refuses to print CONTROL unless its
        # preconditions held (`evtResetOk && invAllOk && controlDone`), and
        # those three are published as `stage-evt-reset`, `stage-inv-all` and
        # `stage-control-done`. Recompute the conjunction here instead of
        # reading `m2-b2-verdict`.
        ctl_pre = (P.get('m2-b2-stage-evt-reset') == 'yes' and
                   P.get('m2-b2-stage-inv-all') == 'yes')
        ctl_done = P.get('m2-b2-stage-control-done') == 'yes'
        rec('schema', 'schema-control-preconditions',
            'the control run established its preconditions', ctl_pre,
            'evt-reset=%s inv-all=%s'
            % (P.get('m2-b2-stage-evt-reset'),
               P.get('m2-b2-stage-inv-all')))
        rec('schema', 'schema-control-completed',
            'the control stage itself completed', ctl_done,
            'stage-control-done=%s' % P.get('m2-b2-stage-control-done'))
        # The control stage is a fixed 20 s IOSleep and publishes its own
        # measured duration. A duration near zero means the sleep did not
        # happen; a duration far from 20 s means something else ran.
        dur = P.get('m2-b2-ctl-dur-ms')
        rec('schema', 'schema-control-duration',
            'the control stage ran for its declared 20 s',
            dur is not None and 19000 <= dur <= 26000,
            'ctl-dur-ms=%s (declared window-secs=%s)'
            % (dur, P.get('m2-b2-window-secs')))
        # And the two clock readings that bracket it must be ordered.
        t0 = P.get('m2-b2-ctl-t-start')
        t1 = P.get('m2-b2-ctl-t-end')
        rec('schema', 'schema-control-timing',
            'the control stage start precedes its end', 
            t0 is not None and t1 is not None and t1 > t0,
            't-start=%s t-end=%s' % (t0, t1))

        rec('schema', 'schema-control-na',
            'the translation-only checks are N/A in control mode', True,
            na=True)
        rec('schema', 'schema-fields',
            'the translation schema does not apply to this capture', False,
            na=True)
    else:
        rec('schema', 'schema-fields',
            'every field the translation schema requires is present', False,
            'mode is unknown, so no schema applies')
        rec('schema', 'schema-control-na',
            'the control-mode N/A rules do not apply to this capture', False,
            na=True)

    # ------------------------------------------------------------------
    section('SUMMARY')
    # ------------------------------------------------------------------
    sections = {}
    for sec, cid, name, state, detail in RESULTS:
        sections.setdefault(sec, [0, 0, 0])
        sections[sec][1] += 1
        if state == 'ok':
            sections[sec][0] += 1
        elif state == 'na':
            sections[sec][2] += 1
    n_ok = sum(1 for _s, _c, _n, st, _d in RESULTS if st == 'ok')
    n_fail = sum(1 for _s, _c, _n, st, _d in RESULTS if st == 'fail')
    n_na = sum(1 for _s, _c, _n, st, _d in RESULTS if st == 'na')
    for sec in sorted(sections):
        ok, tot, na = sections[sec]
        print('  %-12s %2d/%2d ok, %d N/A' % (sec, ok, tot, na))
    print()
    print('  TOTAL  %d ok, %d failed, %d N/A' % (n_ok, n_fail, n_na))
    print()
    print('  has_complete_pair        : %s' % ('YES' if paired else 'NO'))
    print('  records_cover_window     : %s' % ('YES' if cover_ok else 'NO'))
    print('  controlled_batch_complete: %s' % ('YES' if batch_ok else 'NO'))
    if is_control:
        print('  (all three are NO by construction: the control branch runs no')
        print('   batch, opens no window and reads no snapshot)')
    print()
    # Four separate statements, never collapsed into one.
    print('  business exchange succeeded      : %s'
          % ('YES' if batch_ok else 'NO'))
    print('  runtime input is re-checkable    : %s'
          % ('YES' if (ok_export and ok_sha_raw and ok_sha_file) else 'NO'))
    # R5: a control run must NEVER print YES here.
    #
    # ROUND 13 (N1): the finite claim now also requires the RECOMPUTED hardware
    # window state. Round 12's `finite` was `is_translation and batch_ok and
    # cover_ok and n_fail == 0`, which does cover a new failing check -- but the
    # window state had no check to fail. Naming the four window-state terms
    # explicitly means the claim cannot be made while any of them is unknown,
    # and it does not depend on `m2-b2-window-valid`, which is the probe's own
    # summary of the same facts.
    window_state_ok = (
        not is_translation or
        all(STATE.get(cid) == 'ok' for cid in
            ('win-status-present', 'win-status-run-start', 'win-status-run-end',
             'win-status-no-overflow', 'win-status-ptr-aligned',
             'win-status-head-stable', 'win-status-span')))

    # ROUND 14: the RX set is now part of the finite claim.
    #
    # WHY IT IS A SEPARATE TERM AND NOT JUST "n_fail == 0"
    # ---------------------------------------------------
    # `n_fail == 0` already catches a FAILED rxset check, but it cannot catch an
    # rxset check that was never recorded. Naming the terms means the claim
    # cannot be made while the RX set is unknown -- which is exactly the state
    # every round through 13 was in, and it was described as "RX coverage not
    # done" rather than being part of the verdict at all.
    rxset_ok = (
        not is_translation or
        all(STATE.get(cid) == 'ok' for cid in
            ('rxset-present', 'rxset-published-through-end',
             'rxset-baseline-full', 'rxset-baseline-current',
             'rxset-no-gap', 'rxset-watermark-sane', 'rxset-no-loss', 'rxset-not-truncated',
             'rxset-gen-stable', 'rxset-set-complete', 'rxset-ranges-agree',
             'rxset-all-walked', 'rxset-arith-closes', 'rxset-all-covered',
             'rxset-walk-dte')))
    finite = (is_translation and batch_ok and cover_ok and window_state_ok and
              rxset_ok and n_fail == 0)
    print('  finite DMA translation evidence  : %s'
          % ('YES' if finite else 'NO'))
    if is_translation and not window_state_ok:
        print('    (the hardware window state was not re-established: %s)'
              % [cid for cid in
                 ('win-status-present', 'win-status-run-start',
                  'win-status-run-end', 'win-status-no-overflow',
                  'win-status-ptr-aligned', 'win-status-head-stable',
                  'win-status-span')
                 if STATE.get(cid) != 'ok'])
    if is_translation and not rxset_ok:
        print('    (the RX posted-buffer set is not established: %s)'
              % [cid for cid in
                 ('rxset-present', 'rxset-published-through-end', 'rxset-baseline-full',
                  'rxset-baseline-current', 'rxset-no-gap', 'rxset-watermark-sane', 'rxset-no-loss',
                  'rxset-not-truncated', 'rxset-gen-stable',
                  'rxset-set-complete', 'rxset-ranges-agree',
                  'rxset-all-walked', 'rxset-arith-closes',
                  'rxset-all-covered', 'rxset-walk-dte')
                 if STATE.get(cid) != 'ok'])
    print('  M2-2b-2 overall                  : NOT CLAIMED BY THIS SCRIPT')
    print()
    if is_control:
        verdict = 'CONTROL (N/A is not a pass)'
        print('  RESULT: %s' % verdict)
    else:
        verdict = 'PASS' if n_fail == 0 else 'FAIL'
        print('  RESULT: %s' % verdict)

    write_result(cap, outdir, present, h, ws, we, RESULTS, extra={
        'snapshot_used': {
            'exported': bool(probe_exported),
            'probe_sha256': probe_sha,
            'blob_sha256': sha256_bytes(blob) if blob is not None else None,
            'matches_probe': bool(probe_sha and blob is not None and
                                  sha256_bytes(blob) == probe_sha),
        },
        'verdicts': {
            'has_complete_pair': bool(paired),
            'records_cover_window': cover_ok,
            'controlled_batch_complete': batch_ok,
        },
        'declared_batch': declared,
        'declared_token': decl_token,
        'run_token': token,
        'faults': [{'devid': d, 'addr': a} for d, a in faults],
        'finite_translation_evidence': bool(finite),
        # ROUND 14: WHICH TERM made the finite claim fail.
        #
        # Without this the JSON said only `false`, and every downstream reader
        # had to guess whether that was the window, the batch or the RX set.
        # Naming the terms is what lets the replay assert "the ONLY reason is
        # the RX set" instead of accepting any false as the same false.
        'finite_missing': ([]
                           if finite else
                           [cid for cid in
                            ('win-status-present', 'win-status-run-start',
                             'win-status-run-end', 'win-status-no-overflow',
                             'win-status-ptr-aligned', 'win-status-head-stable',
                             'win-status-span',
                             'rxset-present', 'rxset-published-through-end', 'rxset-baseline-full',
                             'rxset-baseline-current', 'rxset-no-gap',
                             'rxset-no-loss', 'rxset-not-truncated',
                             'rxset-gen-stable', 'rxset-set-complete',
                             'rxset-ranges-agree', 'rxset-all-walked',
                             'rxset-arith-closes', 'rxset-all-covered',
                             'rxset-walk-dte')
                            if STATE.get(cid) != 'ok']),
        'finite_terms': {
            'window_state': bool(window_state_ok),
            'rx_set': bool(rxset_ok),
            'business_batch': bool(batch_ok),
            'records_cover_window': bool(cover_ok),
            'has_complete_pair': bool(paired),
        },
    })

    return 0 if n_fail == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
