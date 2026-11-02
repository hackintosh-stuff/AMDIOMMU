#!/usr/bin/env python3
"""Bump the probe version 0.18.0 -> 0.19.0 across the files that must agree."""
import io

OLD = "0.18.0"
NEW = "0.19.0"

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
            print("  {:<34} no {!r}".format(path, OLD))
            continue
        text = text.replace(OLD, NEW)
        with io.open(path, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        print("  {:<34} {} -> {}".format(path, n, NEW))


if __name__ == "__main__":
    main()
