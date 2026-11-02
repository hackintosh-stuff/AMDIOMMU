"""Wrap the translation-only sections of analyze-round12.py in a mode guard.

ROUND 13 (N3). In control mode there is no probe-used snapshot, so sections
7..12 (the three join verdicts, the per-request window placement, the page-table
walk, the event log / command / timeline / recovery) cannot run. Round 12 ran
them anyway and crashed, or -- worse -- was only ever tested against a fixture
that carried a snapshot the production branch cannot produce.

Rather than 40 individual guards, the whole block is wrapped once and the
N/A rows are emitted from the check ids actually found inside it, so the list
cannot drift from the code.
"""
import re
import sys

PATH = sys.argv[1]
src = open(PATH, encoding='utf-8').read()
lines = src.split('\n')

start = None
end = None
for i, l in enumerate(lines):
    if start is None and "section('7. VERDICT 1" in l:
        start = i - 1          # include the preceding "# ---" comment line
    if "section('13. MODE SCHEMA')" in l:
        end = i - 1            # the "# ---" line before it
        break
if start is None or end is None:
    raise SystemExit('refused: could not locate the block')

block = lines[start:end]
text = '\n'.join(block)

ids = []
for m in re.finditer(r"rec\(\s*'[a-z0-9]+',\s*'([a-z0-9\-]+)'", text):
    if m.group(1) not in ids:
        ids.append(m.group(1))
if len(ids) < 20:
    raise SystemExit('refused: only found %d check ids; the anchor moved'
                     % len(ids))

indented = ['    ' + l if l.strip() else l for l in block]

na_lines = []
na_lines.append('')
na_lines.append('    # A control capture has no probe-used snapshot, so none of the')
na_lines.append('    # checks above can run. Every id is still recorded -- as N/A -- so')
na_lines.append('    # the denominator of the summary does not silently shrink.')
na_lines.append('    for _cid in (')
for cid in ids:
    na_lines.append("            '%s'," % cid)
na_lines.append('            ):')
na_lines.append('        rec(\'na\', _cid, \'translation-only check: not '
                'applicable in this mode\',')
na_lines.append('            False, na=True)')

new = lines[:start] + \
    ['    # ROUND 13 (N3): every check in sections 7..12 needs the probe-used',
     '    # snapshot. In control mode there is none by construction, so the block',
     '    # is skipped and its ids are recorded as N/A below.',
     '    if h is not None:'] + \
    indented + na_lines + lines[end:]

open(PATH, 'w', encoding='utf-8', newline='\n').write('\n'.join(new))
print('wrapped %d lines, %d check ids' % (len(block), len(ids)))
