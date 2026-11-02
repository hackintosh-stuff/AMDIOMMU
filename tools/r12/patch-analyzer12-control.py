#!/usr/bin/env python3
"""patch-analyzer12-control.py -- make the control-mode N/A set complete.

WHY
---
The round-11 analyser treated a control capture as a translation capture that
had failed: every translation-only check reported FAIL, and the N/A rows it did
emit were appended by NAME, which overwrote the earlier result instead of adding
an N/A (the check id collision the round-12 analyser now refuses outright).

Round 12 detects the mode first. But detection alone is not enough: the checks
that depend on evidence the control branch never produces have to say N/A, or
the report claims the control experiment failed at things it never attempted.

This patch converts exactly those checks, and nothing else. The rule it
encodes: a check is N/A in control mode when the FIELD IT READS is absent BY
DESIGN in that branch -- not merely when the value is inconvenient.

Every substitution is anchored on the full call, so a mismatch fails loudly.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
TARGET = os.path.join(ROOT, 'tools', 'analyze-round12.py')

SUBS = [
    # ---- the snapshot: the control branch never decodes one --------------
    ("""                    'used=%s blob=%s' % (P.get('m2-b2-obs-used'),
                                         'present' if used_blob else 'absent'))""",
     """                    'used=%s blob=%s' % (P.get('m2-b2-obs-used'),
                                         'present' if used_blob else 'absent'),
                    # R5: the control branch never decodes a driver snapshot,
                    # so "was one exported" is not applicable there. Calling it
                    # FAIL would report the absence of an experiment as a
                    # defect in it.
                    na=is_control and not probe_exported)"""),

    ("""                     'probe=%s computed=%s'
                     % (probe_sha,
                        sha256_bytes(used_blob) if used_blob else 'n/a'))""",
     """                     'probe=%s computed=%s'
                     % (probe_sha,
                        sha256_bytes(used_blob) if used_blob else 'n/a'),
                     na=is_control and not probe_sha)"""),

    ("""                      'probe=%s file=%s'
                      % (probe_sha,
                         sha256_bytes(used_file) if used_file else 'n/a'))""",
     """                      'probe=%s file=%s'
                      % (probe_sha,
                         sha256_bytes(used_file) if used_file else 'n/a'),
                      na=is_control and not probe_sha)"""),

    ("""    rec('snapshot', 'snap-pub-known',
        'the probe reported the publication it used',
        probe_pub is not None and probe_tpub is not None)""",
     """    rec('snapshot', 'snap-pub-known',
        'the probe reported the publication it used',
        probe_pub is not None and probe_tpub is not None,
        na=is_control and probe_pub is None)"""),

    ("""        'probe pub=%s t=%s blob pub=%s t=%s'
        % (probe_pub, probe_tpub, h['pubId'], h['tPublished']))""",
     """        'probe pub=%s t=%s blob pub=%s t=%s'
        % (probe_pub, probe_tpub, h['pubId'], h['tPublished']),
        na=is_control and probe_pub is None)"""),

    # ---- record kinds: no business traffic in the control branch ---------
    ("""    rec('records', 'rec-dones', 'at least one TX completion is present',
        kinds.get(2, 0) > 0)""",
     """    rec('records', 'rec-dones', 'at least one TX completion is present',
        kinds.get(2, 0) > 0,
        # A control run sends no controlled traffic, so there is no completion
        # to require. Ordinary background traffic may or may not have one.
        na=is_control)"""),

    # ---- the three verdicts ----------------------------------------------
    ("""    rec('pair', 'pair-exists',
        'at least one cumulative index has BOTH a submit and a done',
        len(paired) > 0, 'paired=%d' % len(paired))""",
     """    rec('pair', 'pair-exists',
        'at least one cumulative index has BOTH a submit and a done',
        len(paired) > 0, 'paired=%d' % len(paired),
        na=is_control)"""),

    ("""    rec('cover', 'cover-verdict', '=> records_cover_window', cover_ok)""",
     """    rec('cover', 'cover-verdict', '=> records_cover_window', cover_ok,
        na=is_control)"""),

    ("""    rec('cover', 'cover-agrees',
        'the probe\\'s claim agrees with the recomputation',
        probe_cover == ('yes' if cover_ok else 'no'),
        'probe=%s recomputed=%s' % (probe_cover, cover_ok))""",
     """    rec('cover', 'cover-agrees',
        'the probe\\'s claim agrees with the recomputation',
        probe_cover == ('yes' if cover_ok else 'no'),
        'probe=%s recomputed=%s' % (probe_cover, cover_ok),
        na=is_control)"""),

    ("""    rec('batch', 'batch-declared', 'this round declared a batch', declared > 0)""",
     """    rec('batch', 'batch-declared', 'this round declared a batch', declared > 0,
        na=is_control)"""),

    ("""    rec('batch', 'batch-token-declared', 'this round declared a run token',
        decl_token != 0, 'declared-token=0x%x' % decl_token)""",
     """    rec('batch', 'batch-token-declared', 'this round declared a run token',
        decl_token != 0, 'declared-token=0x%x' % decl_token, na=is_control)"""),

    ("""        'join=0x%x declared=0x%x inferred=%s ambiguous=%s'
        % (P.get('m2-b2-obs-join-token') or 0, decl_token,
           P.get('m2-b2-obs-token-inferred'),
           P.get('m2-b2-obs-token-ambiguous')))""",
     """        'join=0x%x declared=0x%x inferred=%s ambiguous=%s'
        % (P.get('m2-b2-obs-join-token') or 0, decl_token,
           P.get('m2-b2-obs-token-inferred'),
           P.get('m2-b2-obs-token-ambiguous')),
        na=is_control)"""),

    ("""    rec('batch', 'batch-one-token', 'the client used exactly one run token',
        len(tokens) == 1, 'tokens=%s' % tokens)""",
     """    rec('batch', 'batch-one-token', 'the client used exactly one run token',
        len(tokens) == 1, 'tokens=%s' % tokens, na=is_control)"""),

    ("""    rec('batch', 'batch-verdict', '=> controlled_batch_complete', batch_ok)""",
     """    rec('batch', 'batch-verdict', '=> controlled_batch_complete', batch_ok,
        na=is_control)"""),

    ("""    rec('batch', 'batch-agrees',
        'the probe\\'s claim agrees with the recomputation',
        probe_batch == ('yes' if batch_ok else 'no'),
        'probe=%s recomputed=%s' % (probe_batch, batch_ok))""",
     """    rec('batch', 'batch-agrees',
        'the probe\\'s claim agrees with the recomputation',
        probe_batch == ('yes' if batch_ok else 'no'),
        'probe=%s recomputed=%s' % (probe_batch, batch_ok),
        na=is_control)"""),

    ("""    rec('chain', 'chain-frame-len',
        'every recorded length is the frame the client sent',
        frame_len is not None and all(x == frame_len for x in all_lens),
        'client payload=%s frame=%s records=%s'
        % (cl_len, frame_len, sorted(set(all_lens))))""",
     """    rec('chain', 'chain-frame-len',
        'every recorded length is the frame the client sent',
        frame_len is not None and all(x == frame_len for x in all_lens),
        'client payload=%s frame=%s records=%s'
        % (cl_len, frame_len, sorted(set(all_lens))),
        # The control branch runs no load, so there is no client frame to
        # compare against.
        na=is_control)"""),
]


def main():
    with open(TARGET, encoding='utf-8', newline='') as f:
        src = f.read()
    if '\r' in src:
        print('REFUSED: the target contains CR bytes')
        return 1

    applied = 0
    for old, new in SUBS:
        if old not in src:
            print('REFUSED: anchor not found:\n---\n%s\n---' % old[:200])
            return 1
        if src.count(old) != 1:
            print('REFUSED: anchor appears %d times:\n%s'
                  % (src.count(old), old[:120]))
            return 1
        src = src.replace(old, new, 1)
        applied += 1

    with open(TARGET, 'w', encoding='utf-8', newline='') as f:
        f.write(src)
    print('patched %d checks to report N/A in control mode' % applied)
    return 0


if __name__ == '__main__':
    sys.exit(main())
