#!/usr/bin/env python3
"""Dump selected m2-b2-* properties from an ioreg capture.

Usage:
    py -3 tools/show-props.py docs/evidence/<stamp>/props.txt key1 key2 ...
    py -3 tools/show-props.py docs/evidence/<stamp>/props.txt          (default set)
"""
import io
import re
import sys

DEFAULT_KEYS = [
    # identity / configuration
    "m2-b2-verdict", "m2-b2-stage", "m2-b2-first-fail-stage",
    "m2-b2-first-fail-reason",
    "m2-b2-target-devid", "m2-b2-page-mode",
    "m2-b2-dump-root-pa", "m2-b2-dump-root-level", "m2-b2-dump-page-mode",
    "m2-b2-dump-pt-pages", "m2-b2-dump-count", "m2-b2-dump-leaf-encoding",
    "m2-b2-dump-map-limit", "m2-b2-map-limit", "m2-b2-leaf-mode",
    # windows
    "m2-b2-pre-window-ran", "m2-b2-pre-valid", "m2-b2-pre-entries",
    "m2-b2-pre-entries-count", "m2-b2-pre-backlog", "m2-b2-pre-dur-ms",
    "m2-b2-pre-wall-start", "m2-b2-pre-wall-end",
    "m2-b2-main-window-ran", "m2-b2-window-valid", "m2-b2-win-dur-ms",
    "m2-b2-win-wall-start", "m2-b2-win-wall-end",
    "m2-b2-win-entries", "m2-b2-win-new-entries", "m2-b2-win-pre-backlog",
    "m2-b2-win-raw-count", "m2-b2-win-raw-truncated",
    "m2-b2-win-head-start", "m2-b2-win-tail-start",
    "m2-b2-win-head-end", "m2-b2-win-tail-end",
    "m2-b2-win-status-start", "m2-b2-win-status-end",
    "m2-b2-win-dominant", "m2-b2-win-dominant-count",
    "m2-b2-win-devid-mismatch",
    # commands
    "m2-b2-cmd-submits", "m2-b2-cmd-completed", "m2-b2-cmd-record-count",
    "m2-b2-inv-domid", "m2-b2-inv",
    # faults
    "m2-b2-fault-inrange", "m2-b2-fault-outofrange",
    "m2-b2-fault-walk-present", "m2-b2-fault-walk-illegal",
    "m2-b2-fault-walk-absent",
    "m2-b2-fault-addr-min", "m2-b2-fault-addr-max",
    "m2-b2-flags-pr", "m2-b2-flags-pe", "m2-b2-flags-rz",
    "m2-b2-flags-read", "m2-b2-flags-write", "m2-b2-flags-interrupt",
    # software walk
    "m2-b2-walk", "m2-b2-walk-bad", "m2-b2-walk-checked",
    # recovery
    "m2-b2-disabled", "m2-b2-disabled-readback",
    "m2-b2-cmdbuf-stopped", "m2-b2-cmdbuf-stop-status",
    "m2-b2-cmdbuf-stop-loops",
    "m2-b2-evtlog-stopped", "m2-b2-evtlog-stop-status",
    "m2-b2-evtlog-stop-loops",
    "m2-b2-stop-control-write", "m2-b2-stop-control-readback",
    "m2-b2-orig-control", "m2-b2-final-control",
    "m2-b2-regs-restored", "m2-b2-cleanup",
]


def main():
    if len(sys.argv) < 2:
        print("usage: show-props.py <props.txt> [key ...]")
        return 2
    path = sys.argv[1]
    keys = sys.argv[2:] or DEFAULT_KEYS
    text = io.open(path, encoding="utf-8", errors="replace").read()

    width = max(len(k) for k in keys)
    missing = 0
    for k in keys:
        m = re.search(r'"' + re.escape(k) + r'"\s*=\s*"?([^"\n,}]+)', text)
        if m:
            print("%-*s %s" % (width, k, m.group(1).strip()))
        else:
            missing += 1
            print("%-*s <MISSING>" % (width, k))
    if missing:
        print("\n{} of {} keys missing".format(missing, len(keys)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
