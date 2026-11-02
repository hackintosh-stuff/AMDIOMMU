#!/usr/bin/env python3
"""Bump the probe version from 0.17.0 to 0.18.0 across the three files that
must agree: the KMOD_EXPLICIT_DECL string, the Info.plist, and the deploy
script's version gate.

Written as a file rather than an inline -c because PowerShell strips the
backslash-escaped quotes and the script arrives mangled (AGENTS.md).
"""
import io

OLD = "0.17.0"
NEW = "0.18.0"

TARGETS = [
    "kext/AMDMapperProbe.cpp",
    "kext/AMDMapperProbe-Info.plist",
    "tools/deploy-m2-2b2.sh",
]


def main():
    for path in TARGETS:
        with io.open(path, encoding="utf-8", newline="") as f:
            text = f.read()
        n = text.count(OLD)
        if n == 0:
            print("  {:<34} no {!r} found".format(path, OLD))
            continue
        text = text.replace(OLD, NEW)
        with io.open(path, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        print("  {:<34} {} occurrence(s) -> {}".format(path, n, NEW))


if __name__ == "__main__":
    main()
