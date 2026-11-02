#!/usr/bin/env python3
"""Read-only link check for the round16 report and README status section."""
from pathlib import Path
import json
import re
import sys
from urllib.parse import unquote

rows = []
for arg in sys.argv[1:]:
    source = Path(arg)
    lines = source.read_text(encoding='utf-8').splitlines()
    if source.name == 'README.md':
        lines = lines[:28]
    for line_number, line in enumerate(lines, 1):
        for match in re.finditer(r'\]\((?:<([^>]+)>|([^\s)]+))\)', line):
            target = match.group(1) or match.group(2)
            if re.match(r'^[a-zA-Z]+://', target) or target.startswith('#'):
                continue
            path, _, anchor = target.partition('#')
            resolved = source.parent / unquote(path)
            valid = resolved.exists()
            if valid and re.fullmatch(r'L\d+(?:-L\d+)?', anchor):
                last = int(anchor.split('-')[-1][1:])
                valid = resolved.is_file() and len(resolved.read_text(encoding='utf-8').splitlines()) >= last
            rows.append(dict(source=str(source), line=line_number, target=target, exists=valid))
errors = [row for row in rows if not row['exists']]
print(json.dumps(dict(checked=len(rows), errors=errors), indent=2))
raise SystemExit(bool(errors))
