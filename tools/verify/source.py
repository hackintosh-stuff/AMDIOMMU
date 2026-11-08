#!/usr/bin/env python3
"""Source hygiene/guardrail regression checks, not a security proof."""
from pathlib import Path
import plistlib
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
errors = []
count = 0
readme = ROOT / "README.md"
if readme.exists():
    count += 1
    if b"\r" in readme.read_bytes():
        errors.append("CR byte: README.md")
for folder in ("include", "src", "tests", "probe", "tools", "docs"):
    for path in (ROOT / folder).rglob("*"):
        if path.is_file() and path.suffix in (".hpp", ".h", ".cpp", ".py", ".sh", ".md", ".plist"):
            count += 1
            if b"\r" in path.read_bytes():
                errors.append(f"CR byte: {path.relative_to(ROOT)}")
plist = plistlib.loads((ROOT / "probe/Info.plist").read_bytes())
if plist.get("IOKitPersonalities") != {}:
    errors.append("Scaffold must have empty IOKitPersonalities")
source = (ROOT / "probe/AMDIdentityMapper.cpp").read_text(encoding="utf-8")
# Strip comments before guard checks (not a complete C++ parser).
source = re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S)
if not re.search(r"::start\(IOService\s*\*\)\s*\{\s*return false;\s*\}", source):
    errors.append("Scaffold start must unconditionally return false")
for pattern in (r"IOMapper::start\s*\(", r"super::start\s*\(",
                r"registerService\s*\(", r"\bgSystem\b", r"setMapperRequired\s*\(",
                r"\bIOWrite\w*\s*\(", r"\biomap\w*\s*\("):
    if re.search(pattern, source):
        errors.append(f"Forbidden scaffold action: {pattern}")
# ---- the deployment-command guard, scoped correctly ---------------------
#
# WHAT WAS WRONG
# --------------
# This used to scan every tools/*.sh and reject any that mentioned sudo,
# kmutil, kextload, nvram, bless or reboot. But tools/ contains deploy-*.sh and
# capture-*.sh scripts whose WHOLE PURPOSE is to run those commands. So the
# check failed on a dozen legitimate files and tools/test.sh -- the offline
# entry point that calls this script -- could never pass. Round 10 worked around
# that by never running test.sh and reporting only the dma-observe binary's
# count, which is how a red hygiene gate stayed unnoticed.
#
# WHAT IT MEANS
# -------------
# The property actually worth enforcing is: an offline or capture script must
# not CHANGE the installed system. Two refinements make that checkable:
#
#   * a command counts as mutating only in its WRITING form. `nvram boot-args`
#     with no value is a read; `nvram boot-args=...` writes. `kmutil showloaded`
#     lists; `kmutil load`/`create` installs. Treating the read form as a
#     deployment command made every capture script "fail", which is the same
#     category error as failing a deploy script for deploying.
#
#   * deploy-*/install-* scripts are excluded by name: they exist to deploy.
#
# The rule now actually distinguishes the two, so it can be enforced without
# being switched off.
DEPLOY_PREFIX = re.compile(r"^(deploy|install|bootargs|set-|bump-|update-|patch-)")

# Mutating forms only. Each pattern requires the writing variant.
MUTATING = [
    # `nvram boot-args` (no '=') is a READ; `nvram boot-args=...` writes.
    # The negative lookahead is what separates them, and it matters: every
    # capture script legitimately reads the boot-args for the record.
    (re.compile(r"\bnvram\s+[A-Za-z0-9_.-]+\s*=(?!=)"), "nvram write"),
    (re.compile(r"\bkmutil\s+(load|unload|create|configure|inspect\s+-k)"), "kmutil install"),
    (re.compile(r"\bkextload\b"), "kextload"),
    (re.compile(r"\bkextutil\b"), "kextutil"),
    (re.compile(r"\bbless\b"), "bless"),
    (re.compile(r"\breboot\b"), "reboot"),
    (re.compile(r"\bshutdown\b"), "shutdown"),
]

# Commands that are only mutating when they are INVOKED, not when the word
# merely appears in output text.
#
# WHY THIS DISTINCTION EXISTS
# ---------------------------
# build-record.sh writes the sentence "written later, after a reboot" into the
# README it generates, and the guard rejected the script for it. That is the
# same category error as failing a capture script for reading `nvram`: the word
# is data, not an action.
#
# The rule: a mutating verb counts only in COMMAND POSITION -- at the start of a
# line, or after a separator that begins a new command (`;`, `&&`, `||`, `|`,
# `(`, `$(`), optionally preceded by a command prefix such as `sudo` or `exec`.
# A word inside a quoted string in the middle of an `echo` is not in command
# position.
COMMAND_VERBS = [
    (re.compile(r"(?:^|[;&|(]|\$\()\s*"
                r"(?:(?:sudo|exec|command|nohup|env)\s+)*"
                r"(?:/usr/sbin/|/sbin/)?reboot\b"), "reboot"),
    (re.compile(r"(?:^|[;&|(]|\$\()\s*"
                r"(?:(?:sudo|exec|command|nohup|env)\s+)*"
                r"(?:/usr/sbin/|/sbin/)?shutdown\b"), "shutdown"),
    (re.compile(r"(?:^|[;&|(]|\$\()\s*"
                r"(?:(?:sudo|exec|command|nohup|env)\s+)*"
                r"(?:/usr/bin/)?bless\b"), "bless"),
]

for path in sorted((ROOT / "tools").rglob("*.sh")):
    name = str(path.relative_to(ROOT / "tools"))
    if DEPLOY_PREFIX.match(path.name):
        # By definition: this script exists to deploy.
        continue
    # Strip full-line comments so prose about rebooting does not trip the rule.
    shell = "\n".join(ln for ln in path.read_text(encoding="utf-8").splitlines()
                      if not ln.lstrip().startswith("#"))
    for pat, what in MUTATING:
        # The three command verbs are checked by COMMAND_VERBS below, which is
        # stricter: they must be invoked, not merely mentioned.
        if what in ("reboot", "shutdown", "bless"):
            continue
        if pat.search(shell):
            errors.append(f"{name}: mutating command ({what}) in a script that "
                          f"must only read")
    for pat, what in COMMAND_VERBS:
        if pat.search(shell):
            errors.append(f"{name}: mutating command ({what}) is INVOKED in a "
                          f"script that must only read")
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print(f"Source guards: PASS ({count} files; LF, empty personalities, disabled start)")
