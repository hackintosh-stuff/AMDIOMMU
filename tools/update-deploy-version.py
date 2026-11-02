#!/usr/bin/env python3
"""Update deploy-m2-2b2.sh for probe version 0.15.0."""
import sys

P = r"MSI_X570\amd-iommu\tools\deploy-m2-2b2.sh"

REPLACEMENTS = [
    (
        "# deploy-m2-2b2.sh — 部署探针 0.14.0（M2-2b-2：4 级恒等页表 + 单设备 DTE 切换）",
        "# deploy-m2-2b2.sh — 部署探针 0.15.0（M2-2b-2：4 级恒等页表 + 单设备 DTE 切换）",
    ),
    (
        '[ "$PB" = "0.14.0" ] || die "unexpected probe version: $PB (expected 0.14.0)"',
        '[ "$PB" = "0.15.0" ] || die "unexpected probe version: $PB (expected 0.15.0)"',
    ),
]


def main():
    with open(P, "r", encoding="utf-8") as f:
        s = f.read()

    for old, new in REPLACEMENTS:
        n = s.count(old)
        print("occurrences: %d  <- %s" % (n, old[:50]))
        if n != 1:
            print("REFUSING: expected exactly 1")
            return 1
        s = s.replace(old, new)

    with open(P, "w", encoding="utf-8", newline="\n") as f:
        f.write(s)

    left = s.count("0.14.0")
    print("remaining 0.14.0 occurrences: %d" % left)
    print("updated OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
