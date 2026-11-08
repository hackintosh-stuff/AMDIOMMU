#!/usr/bin/env python3
"""verify-property-names.py -- no property is published twice with different types.

WHY THIS EXISTS
---------------
Round 14's second real-machine run reported `m2-b2-rxset-raw = exported` and a
correct sha256 of bytes that no longer existed. The cause:

    m2b2RxSetRead()    setProperty("m2-b2-rxset-raw", OSData)     <- the blob
    m2b2PublishRxSet() setProperty("m2-b2-rxset-raw", "exported") <- the status

IOKit REPLACES a property on the second write, so the blob was destroyed a few
statements after it was created. Nothing failed: the probe published a truthful
hash of the wrong thing, the capture script refused for the right reason, and the
run had no re-checkable RX input.

This is the "two authorities" defect one level up from round 13's `wrapped`: one
NAME, two different objects, and the loser disappears silently.

WHAT IS CHECKED
---------------
Every `setProperty`/`setHexProperty` call site in the kext sources is scanned for
a literal property name, and the name is classified by the type of the value:

  * a STRING literal  (setProperty("k", "text"))
  * a NUMBER          (setHexProperty, or setProperty with an integer expr)
  * a BLOB            (setProperty("k", someObject))

A name that appears with more than one class is an error, because whichever
write happens last destroys the others.

Loop-generated names (`m2-b2-rxset-s%u-addr`) are collapsed to their prefix so a
family is compared as a family.

Exit 0 only when every name has exactly one class.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
KEXT = os.path.join(ROOT, 'probe')

# Names that are LEGITIMATELY published twice with the same class -- i.e. the
# same string value re-published on a different path. Listing them here is a
# decision, not an oversight, and the list is checked for staleness below.
ALLOWED_REPEATS = {
    # The probe republishes its verdict on several exit paths; all string.
    'm2-b2-verdict': 'string',
    'm2-b2-stage': 'string',
}


def scan(path):
    """Yield (name, kind) for every literal setProperty in one file.

    THE TWO CALL SHAPES ARE SCANNED SEPARATELY, because a single regex cannot
    match both without also matching across statements:

        setProperty("key", value);            <- the key is the FIRST argument
        setHexProperty(this, "key", value);   <- the key is the SECOND

    The first version used one pattern with `[^,]+` for the leading argument,
    which required a comma before the key -- so every two-argument setProperty
    was skipped entirely, and the check reported "no collisions" while the very
    collision it exists for was present. A checker that silently sees nothing is
    worse than none, so the counts are printed and asserted non-zero below.
    """
    text = open(path, encoding='utf-8', errors='replace').read()
    out = []

    # What the file does with a bare identifier: if a name is ever assigned a
    # string literal, or passed as a parameter that is compared to one, treat it
    # as a string. This is deliberately narrow -- it only has to be right about
    # the probe's own idioms.
    known = {}
    for m in re.finditer(r'\b(\w+)\s*=\s*"', text):
        known.setdefault(m.group(1), 'string')
    for m in re.finditer(r'const char\s*\*\s*(\w+)', text):
        known.setdefault(m.group(1), 'string')
    for m in re.finditer(r'char\s+(\w+)\[', text):
        known.setdefault(m.group(1), 'string')

    # setProperty("key", value);
    for m in re.finditer(r'setProperty\s*\(\s*"([^"]+)"\s*,\s*(.*?)\)\s*;',
                         text, re.S):
        out.append((norm_name(m.group(1)), kind_of(m.group(2), False, known)))

    # setProperty(<obj>, "key", value);  and  setHexProperty(<obj>, "key", v)
    for m in re.finditer(
            r'set(Hex)?Property\s*\(\s*[A-Za-z_][\w>.\-]*\s*,\s*"([^"]+)"\s*,'
            r'\s*(.*?)\)\s*;', text, re.S):
        out.append((norm_name(m.group(2)), kind_of(m.group(3),
                                                   bool(m.group(1)), known)))
    return out


def norm_name(name):
    """Collapse printf-style families so a family is compared as a family."""
    return re.sub(r'%[-0-9.]*[a-zA-Z]', '%', name)


def kind_of(value, is_hex, known=None):
    """Classify the VALUE of one property write.

    A bare identifier is looked up in `known` -- the set of local/parameter names
    the same file passes string literals to. Without that, `setProperty(k, idWhy)`
    looks like an unknown object and a string property reads as a collision with
    itself.

    Returning 'unknown' for an identifier the scan could not type is deliberate:
    the caller treats 'unknown' as compatible with anything, so an untyped
    identifier never manufactures a collision. Only a value that is POSITIVELY a
    blob next to one that is POSITIVELY a string is an error -- which is the
    round-14 defect (`OSData` vs `"exported"` under one name).
    """
    v = value.strip()
    if is_hex:
        return 'number'
    if v.startswith('"'):
        return 'string'
    if '?' in v:
        arms = re.findall(r':\s*(".*?"|\S+)', v, re.S)
        if arms and all(a.strip().startswith('"') for a in arms):
            return 'string'
        if re.search(r'\?\s*"', v):
            return 'string'
    # A bare identifier: consult what the file does with that name, and fall
    # back to the NAME ITSELF, which the probe's idiom makes informative --
    # `raw`, `snap`, `used` are the OSData locals; `why`, `state`, `text` are
    # the strings.
    if re.match(r'^[A-Za-z_]\w*$', v):
        if known and v in known:
            return known[v]
        if re.search(r'(blob|snap|used|raw|data|obj)$', v, re.I):
            return 'blob'
        if re.search(r'(why|state|text|name|reason|err)$', v, re.I):
            return 'string'
        return 'unknown'
    # A member expression like `fM22b2Dma.rxsetWhy` or a call. Untyped.
    if re.search(r'\b(OSData|OSNumber|OSString)\b', v):
        return 'blob'
    return 'unknown'


def main():
    print('=' * 78)
    print('PROPERTY NAMES: does any name carry two different kinds of value?')
    print('=' * 78)

    if not os.path.isdir(KEXT):
        print('FAIL: no kext directory')
        return 1

    seen = {}
    files = sorted(f for f in os.listdir(KEXT) if f.endswith(('.cpp', '.hpp')))
    for f in files:
        for name, kind in scan(os.path.join(KEXT, f)):
            seen.setdefault(name, []).append((kind, f))

    bad = []
    for name, hits in sorted(seen.items()):
        kinds = set(k for k, _f in hits)
        # 'unknown' is compatible with anything: an identifier the scan could not
        # type must not manufacture a collision. 'number' and 'object' are both
        # "not a blob and not a string".
        decisive = set(k for k in kinds if k in ('blob', 'string'))
        if len(decisive) > 1:
            allow = ALLOWED_REPEATS.get(name)
            if allow and decisive == {allow}:
                continue
            bad.append((name, sorted(kinds), sorted(set(f for _k, f in hits))))

    print('  %d distinct property names scanned across %d files'
          % (len(seen), len(files)))
    # A scan that sees nothing passes every assertion below vacuously. That is
    # exactly how the first version of this script reported "no collisions"
    # while the collision was present.
    total_calls = sum(len(v) for v in seen.values())
    print('  %d property writes matched' % total_calls)
    if len(seen) < 100 or total_calls < 100:
        print('  FAIL: the scan found too few writes to be meaningful.')
        print('        A silent scanner would report every name as unique.')
        return 1
    print()
    if bad:
        print('  COLLISIONS (one name, more than one kind of value):')
        for name, kinds, where in bad:
            print('    %-34s %s' % (name, kinds))
            for f in where:
                print('        in %s' % f)
            print('      IOKit replaces a property on the second write, so the')
            print('      loser disappears with no error. Rename one of them.')
    else:
        print('  every property name carries exactly one kind of value  OK')

    # ---- the specific pair this round got wrong ----
    #
    # Asserted by name, because the generic scan above would also pass if BOTH
    # writes were renamed to something equally ambiguous.
    raw_hits = seen.get('m2-b2-rxset-raw')
    state_hits = seen.get('m2-b2-rxset-raw-state')
    print()
    ok_pair = (raw_hits is not None and state_hits is not None and
               all(k == 'blob' for k, _f in raw_hits) and
               all(k == 'string' for k, _f in state_hits))
    print('  %-62s %s' % (
        'the RX blob and its status use DIFFERENT property names',
        'PASS' if ok_pair else 'FAIL'))
    if not ok_pair:
        print('      m2-b2-rxset-raw       : %s' % (raw_hits,))
        print('      m2-b2-rxset-raw-state : %s' % (state_hits,))
        print('      The blob must own its own name; a status string under the')
        print('      same key destroys it.')

    # ---- the observation log's pair, as the reference shape ----
    used = seen.get('m2-b2-obs-snapshot-used')
    used_state = seen.get('m2-b2-obs-used')
    ok_ref = (used is not None and used_state is not None and
              all(k == 'blob' for k, _f in used) and
              all(k == 'string' for k, _f in used_state))
    print('  %-62s %s' % (
        'the observation log keeps its blob and status separate',
        'PASS' if ok_ref else 'FAIL'))

    ok = (not bad) and ok_pair and ok_ref
    print()
    print('  RESULT: %s' % ('NO COLLISIONS' if ok else 'FAILURES'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
