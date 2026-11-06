#!/usr/bin/env python3
"""splice-bizwalk.py -- replace m2b2WalkBusinessRanges() in the probe with the
round-12 body, without touching anything else in the file.

WHY A SPLICER AND NOT AN EDIT
-----------------------------
The function is ~340 lines and the replacement is ~330. A hand edit has to get
every brace right; a splice that anchors on the function's signature and on the
matching close brace at column 0 can assert its own result:

  * the anchor must appear EXACTLY once;
  * the replacement must end at file scope (next non-blank char is '}' or EOF);
  * the file must still contain every other function it had before.

If any assertion fails the script writes nothing and exits non-zero.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
TARGET = os.path.join(ROOT, 'kext', 'AMDMapperProbePgtDebug.cpp')
BODY = os.path.join(ROOT, 'build-work-r12', 'bizwalk-body.cpp.txt')

SIG = 'void org_maz1_AMDMapperProbe::m2b2WalkBusinessRanges('


def main():
    # newline='' EVERYWHERE.
    #
    # The first run of this script read the file as text and wrote it back with
    # the default newline translation, which on Windows turns every '\n' into
    # '\r\n'. The splice itself was correct, but the file then failed the
    # project's own LF-only source guard (tools/check_source.py), which is a
    # guard the kext build does NOT have -- so the damage would only have shown
    # up in the offline suite, after the file had been reviewed as "spliced
    # correctly". Reading and writing with newline='' keeps the bytes as they
    # were and makes the operation a splice rather than a rewrite.
    with open(TARGET, encoding='utf-8', newline='') as f:
        src = f.read()
    with open(BODY, encoding='utf-8', newline='') as f:
        body = f.read()

    if '\r' in src:
        print('REFUSED: the target already contains CR bytes; fix that first')
        return 1
    if '\r' in body:
        print('REFUSED: the replacement body contains CR bytes')
        return 1

    n = src.count(SIG)
    if n != 1:
        print('REFUSED: the signature appears %d times, expected 1' % n)
        return 1

    start = src.index(SIG)
    # Walk back to the start of the line so the replacement begins at column 0.
    line_start = src.rfind('\n', 0, start) + 1

    # Find the matching close brace of the function body.
    i = src.index('{', start)
    depth = 0
    end = None
    while i < len(src):
        c = src[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                end = i + 1
                break
        i += 1
    if end is None:
        print('REFUSED: unbalanced braces after the signature')
        return 1

    # The replacement must end at file scope: only whitespace may follow.
    rest = src[end:]
    if rest.strip() not in ('', '}'):
        print('REFUSED: %d bytes of real code follow the function; this is not'
              ' the last definition in the file' % len(rest.strip()))
        return 1

    before = src[:line_start]
    after = src[end:]

    # Every other method definition must survive.
    methods_before = set(re.findall(
        r'^\w[\w:<>\*\s]*org_maz1_AMDMapperProbe::(\w+)\s*\(', src,
        re.M))
    methods_after = set(re.findall(
        r'^\w[\w:<>\*\s]*org_maz1_AMDMapperProbe::(\w+)\s*\(',
        before + body + after, re.M))
    lost = methods_before - methods_after
    if lost:
        print('REFUSED: would lose method definitions: %s' % sorted(lost))
        return 1

    new = before + body + after
    if new == src:
        print('REFUSED: the splice produced identical bytes')
        return 1
    with open(TARGET, 'w', encoding='utf-8', newline='') as f:
        f.write(new)
    # A splice must not change the file's newline convention: the source guard
    # treats a CR byte as an error, and a silent rewrite to CRLF is exactly the
    # kind of "it looked fine" change that guard exists to catch.
    if '\r' in new:
        print('REFUSED: the splice introduced CR bytes; not written')
        return 1
    print('spliced m2b2WalkBusinessRanges(): %d -> %d bytes'
          % (end - line_start, len(body)))
    print('  methods before: %d, after: %d' % (len(methods_before),
                                               len(methods_after)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
