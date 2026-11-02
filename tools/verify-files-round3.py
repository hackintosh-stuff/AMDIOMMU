#!/usr/bin/env python3
"""Verify every file touched in round 3 is LF-only and valid UTF-8.

The project requires LF line endings (AGENTS.md / earlier rounds). PowerShell
redirection and some editors silently write CRLF or GBK, so this is checked
after every write rather than assumed.
"""
import io
import sys

FILES = [
    "AGENTS.md",
    "MSI_X570/amd-iommu/README.md",
    "MSI_X570/amd-iommu/kext/AMDMapperProbe.cpp",
    "MSI_X570/amd-iommu/kext/AMDMapperProbe-Info.plist",
    "MSI_X570/amd-iommu/tools/deploy-m2-2b2.sh",
    "MSI_X570/amd-iommu/docs/m2-2b-2-round2-result.md",
    "MSI_X570/amd-iommu/docs/m2-2b-2-round3-result.md",
    "MSI_X570/amd-iommu/tools/decode-efr-v2.py",
    "MSI_X570/amd-iommu/tools/decode-ivhd-flags.py",
    "MSI_X570/amd-iommu/tools/verify-identity-exhaustive.py",
    "MSI_X570/amd-iommu/tools/audit-window-mismatch.py",
    "MSI_X570/amd-iommu/tools/verify-v0180-changes.py",
    "MSI_X570/amd-iommu/tools/analyze-round3.py",
    "MSI_X570/amd-iommu/tools/bump-to-0180.py",
]


def main():
    problems = 0
    for path in FILES:
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except IOError as e:
            print("  MISSING  {:<62} {}".format(path, e))
            problems += 1
            continue

        cr = raw.count(b"\r")
        try:
            raw.decode("utf-8")
            utf8 = "ok"
        except UnicodeDecodeError as e:
            utf8 = "BAD ({})".format(e)
            problems += 1

        status = []
        if cr:
            status.append("{} CR".format(cr))
            problems += 1
        if not raw.endswith(b"\n"):
            status.append("no-trailing-LF")

        print("  {:<62} {:>9} B  CR={}  utf8={}  {}".format(
            path, len(raw), cr, utf8, ",".join(status) if status else "clean"))

    print()
    if problems:
        print("PROBLEMS: {}".format(problems))
        return 1
    print("ALL FILES: LF-only, valid UTF-8, zero problems")
    return 0


if __name__ == "__main__":
    sys.exit(main())
