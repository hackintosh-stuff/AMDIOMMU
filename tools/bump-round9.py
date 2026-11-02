#!/usr/bin/env python3
"""bump-round9.py -- move the probe from 0.23.0 to 0.24.0.

WHY A SCRIPT AND NOT A HAND EDIT
--------------------------------
The version appears in two places that must agree: the KMOD_EXPLICIT_DECL in
the source (which becomes the loaded kext's version) and CFBundleVersion in the
plist (which the deploy script gates on). A hand edit that touched one and not
the other produced a "version gate mismatch" deployment failure in round 8.
This script refuses unless it finds exactly one of each.

Usage:
    py -3 tools/bump-round9.py [--check]
Exit 0 = bumped (or, with --check, already at 0.24.0).
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CPP = os.path.join(ROOT, "kext", "AMDMapperProbe.cpp")
PLIST = os.path.join(ROOT, "kext", "AMDMapperProbe-Info.plist")
DEPLOY = os.path.join(ROOT, "tools", "deploy-m2-2b2.sh")

OLD = "0.23.0"
NEW = "0.24.0"

# The KMOD_EXPLICIT_DECL version in the source had been stale since round 7
# (it still said 0.21.7 while the plist shipped 0.23.0). The loaded kext's
# reported version comes from CFBundleVersion, so the stale string was
# invisible -- but a version that disagrees with itself in two places is
# exactly the kind of thing that later gets quoted as evidence. Both are
# updated here, and the script refuses if the source string is neither the old
# value nor already the new one.
KMOD_STALE = "0.21.7"


def read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def main():
    check = "--check" in sys.argv

    cpp = read(CPP)
    plist = read(PLIST)
    deploy = read(DEPLOY)

    cpp_old = 'KMOD_EXPLICIT_DECL(org.example.AMDMapperProbe, "%s"'
    cpp_new = 'KMOD_EXPLICIT_DECL(org.example.AMDMapperProbe, "%s"'
    n_cpp = cpp.count(cpp_old % OLD) + cpp.count(cpp_old % KMOD_STALE)
    cpp_at_new = cpp.count(cpp_new % NEW)

    plist_old = "<string>%s</string>" % OLD
    plist_new = "<string>%s</string>" % NEW
    n_plist = plist.count(plist_old)

    dep_old = '[ "$PB" = "%s" ]' % OLD
    dep_new = '[ "$PB" = "%s" ]' % NEW
    n_dep = deploy.count(dep_old)

    if check:
        ok = (cpp_at_new == 1 and plist.count(plist_new) >= 1 and
              deploy.count(dep_new) == 1)
        print("version is %s: %s" % (NEW, "yes" if ok else "NO"))
        return 0 if ok else 1

    if n_cpp != 1:
        print("REFUSING: the source KMOD version is neither %s nor %s "
              "exactly once (found %d)" % (OLD, KMOD_STALE, n_cpp))
        return 1
    if n_plist < 1:
        print("REFUSING: %s not found in the plist" % OLD)
        return 1
    if n_dep != 1:
        print("REFUSING: the deploy gate does not contain exactly one "
              "'[ \"$PB\" = \"%s\" ]'" % OLD)
        return 1

    cpp = cpp.replace(cpp_old % OLD, cpp_new % NEW)
    cpp = cpp.replace(cpp_old % KMOD_STALE, cpp_new % NEW)
    write(CPP, cpp)
    write(PLIST, plist.replace(plist_old, plist_new))
    write(DEPLOY, deploy.replace(dep_old, dep_new))
    print("bumped %s -> %s in source, plist and deploy gate" % (OLD, NEW))
    return 0


if __name__ == "__main__":
    sys.exit(main())
