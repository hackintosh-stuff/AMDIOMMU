#!/usr/bin/env python3
"""Set the probe version everywhere at once."""
import sys

VERSION = sys.argv[1] if len(sys.argv) > 1 else "0.17.0"

CPP = r"MSI_X570\amd-iommu\kext\AMDMapperProbe.cpp"
PLIST = r"MSI_X570\amd-iommu\kext\AMDMapperProbe-Info.plist"
DEPLOY = r"MSI_X570\amd-iommu\tools\deploy-m2-2b2.sh"

# Any previous version string, so this works regardless of current value.
OLD_VERSIONS = ["0.14.0", "0.15.0", "0.16.0", "0.17.0", "0.18.0"]


def main():
    with open(CPP, "r", encoding="utf-8") as f:
        s = f.read()
    cur = None
    for v in OLD_VERSIONS:
        if ('AMDMapperProbe, "%s"' % v) in s:
            cur = v
            break
    if cur is None:
        print("REFUSING: cannot find current KMOD version in cpp")
        return 1
    old = 'AMDMapperProbe, "%s"' % cur
    new = 'AMDMapperProbe, "%s"' % VERSION
    s = s.replace(old, new)
    with open(CPP, "w", encoding="utf-8", newline="\n") as f:
        f.write(s)
    print("cpp     : %s -> %s" % (cur, VERSION))

    with open(PLIST, "r", encoding="utf-8") as f:
        t = f.read()
    for v in OLD_VERSIONS:
        t = t.replace("<string>%s</string>" % v, "<string>%s</string>" % VERSION)
    with open(PLIST, "w", encoding="utf-8", newline="\n") as f:
        f.write(t)
    print("plist   : set to %s" % VERSION)

    with open(DEPLOY, "r", encoding="utf-8") as f:
        d = f.read()
    for v in OLD_VERSIONS:
        d = d.replace(v, VERSION)
    with open(DEPLOY, "w", encoding="utf-8", newline="\n") as f:
        f.write(d)
    print("deploy  : set to %s" % VERSION)

    # Verify
    for path, label in ((CPP, "cpp"), (PLIST, "plist"), (DEPLOY, "deploy")):
        with open(path, "r", encoding="utf-8") as f:
            body = f.read()
        stale = [v for v in OLD_VERSIONS
                 if v != VERSION and v in body]
        print("%-7s stale versions remaining: %s" % (label, stale or "none"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
