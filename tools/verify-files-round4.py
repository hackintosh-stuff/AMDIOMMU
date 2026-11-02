#!/usr/bin/env python3
"""Verify every file touched in round 4 is LF-only and valid UTF-8."""
import sys

FILES = [
    "AGENTS.md",
    "MSI_X570/amd-iommu/README.md",
    "MSI_X570/amd-iommu/kext/AMDMapperProbe.cpp",
    "MSI_X570/amd-iommu/kext/AMDMapperProbe.hpp",
    "MSI_X570/amd-iommu/kext/AMDMapperProbe-Info.plist",
    "MSI_X570/amd-iommu/tools/deploy-m2-2b2.sh",
    "MSI_X570/amd-iommu/docs/m2-2b-2-round3-result.md",
    "MSI_X570/amd-iommu/docs/m2-2b-2-round4-result.md",
    "MSI_X570/amd-iommu/tools/analyze-round3.py",
    "MSI_X570/amd-iommu/tools/analyze-round4.py",
    "MSI_X570/amd-iommu/tools/model-event-ring-v0190.py",
    "MSI_X570/amd-iommu/tools/model-recovery-v0190.py",
    "MSI_X570/amd-iommu/tools/decode-exported-pagetable.py",
    "MSI_X570/amd-iommu/tools/rewrite-v0190-core.py",
    "MSI_X570/amd-iommu/tools/cast-cmd-types.py",
    "MSI_X570/amd-iommu/tools/bump-to-0190.py",
]


def main():
    problems = 0
    for path in FILES:
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except IOError as e:
            print("  MISSING  {:<58} {}".format(path, e))
            problems += 1
            continue

        cr = raw.count(b"\r")
        try:
            raw.decode("utf-8")
            utf8 = "ok"
        except UnicodeDecodeError as e:
            utf8 = "BAD"
            problems += 1

        status = []
        if cr:
            status.append("{} CR".format(cr))
            problems += 1
        if not raw.endswith(b"\n"):
            status.append("no-trailing-LF")

        print("  {:<58} {:>8} B  CR={}  {}  {}".format(
            path, len(raw), cr, utf8,
            ",".join(status) if status else "clean"))

    print()
    if problems:
        print("PROBLEMS: {}".format(problems))
        return 1
    print("ALL FILES: LF-only, valid UTF-8, zero problems")
    return 0


if __name__ == "__main__":
    sys.exit(main())
