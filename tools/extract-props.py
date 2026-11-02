#!/usr/bin/env python3
"""Extract selected m2-b2-* properties from an ioreg dump."""
import re
import sys

WANT = [
    "m2-b2-pa-va",
    "m2-b2-pa-va-mismatch",
    "m2-b2-pa-va-firstmism",
    "m2-b2-leafprobe-pte",
    "m2-b2-leafprobe-after-faults",
    "m2-b2-leafprobe-reversibility",
    "m2-b2-leafprobe-baseline",
    "m2-b2-leafprobe-faults",
    "m2-b2-leafprobe-iova",
    "m2-b2-evt-count2",
    "m2-b2-status",
    "m2-b2-pt-pa",
    "m2-b2-dte-after",
    "m2-b2-fault-addr-min",
    "m2-b2-fault-addr-max",
    "m2-b2-fault-walk-1stoa",
    "m2-b2-evt-flag-rw",
    "m2-b2-evt-flag-i",
    "m2-b2-verdict",
    "m2-b2-stage",
]


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "-"
    if path == "-":
        text = sys.stdin.read()
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()

    props = {}
    # Accept both `"key" = "value"` (raw ioreg) and `key" = "value"`
    # (what `grep -o 'key" = value'` leaves behind: the leading quote is
    # consumed by grep, so the key has no opening quote).
    pat = re.compile(r'"?\b(m2-b2-[a-z0-9-]+)"?\s*=\s*"?([^"\r\n]*)"?')
    for m in pat.finditer(text):
        props[m.group(1)] = m.group(2).strip()

    for k in WANT:
        print("%-34s %s" % (k, props.get(k, "<MISSING>")))


if __name__ == "__main__":
    main()
