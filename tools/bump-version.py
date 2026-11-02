#!/usr/bin/env python3
"""Bump the probe version from 0.14.0 to 0.15.0 in both source and plist."""
import sys

CPP = r"MSI_X570\amd-iommu\kext\AMDMapperProbe.cpp"
PLIST = r"MSI_X570\amd-iommu\kext\AMDMapperProbe-Info.plist"

OLD = 'KMOD_EXPLICIT_DECL(org.example.AMDMapperProbe, "0.14.0", _start, _stop)'
NEW = 'KMOD_EXPLICIT_DECL(org.example.AMDMapperProbe, "0.15.0", _start, _stop)'

OLD_P = "<string>0.14.0</string>"
NEW_P = "<string>0.15.0</string>"


def main():
    with open(CPP, "r", encoding="utf-8") as f:
        s = f.read()
    n = s.count(OLD)
    print("cpp: KMOD version 0.14.0 occurrences = %d" % n)
    if n != 1:
        print("REFUSING: expected exactly 1")
        return 1
    s = s.replace(OLD, NEW)
    with open(CPP, "w", encoding="utf-8", newline="\n") as f:
        f.write(s)

    with open(PLIST, "r", encoding="utf-8") as f:
        t = f.read()
    m = t.count(OLD_P)
    print("plist: 0.14.0 occurrences = %d" % m)
    if m < 1:
        print("REFUSING: version string not found in plist")
        return 1
    t = t.replace(OLD_P, NEW_P)
    with open(PLIST, "w", encoding="utf-8", newline="\n") as f:
        f.write(t)

    print("bumped to 0.15.0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
