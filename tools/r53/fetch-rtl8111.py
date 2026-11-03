#!/usr/bin/env python3
"""Fetch only the pinned RTL8111 build inputs into one fixed dependency directory."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request

HERE = Path(__file__).resolve().parent


def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + bytes([0]) + data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--proxy", help="Optional HTTP(S) proxy used for the pinned fetch")
    args = parser.parse_args()
    pin = json.loads((HERE / "rtl8111-source-pin.json").read_text(encoding="utf-8"))
    source = args.source.resolve()
    if (source / ".r53-generated.json").exists():
        raise SystemExit("already adapted: build this fixed input directory; do not fetch over generated files")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": args.proxy, "https": args.proxy})
    ) if args.proxy else urllib.request.build_opener()
    base = "https://raw.githubusercontent.com/Mieze/RTL8111_driver_for_OS_X/" + pin["commit"] + "/"
    for item in pin["files"]:
        dest = source / item["path"]
        if dest.exists():
            data = dest.read_bytes()
        else:
            data = opener.open(base + item["path"], timeout=60).read()
        if len(data) != item["bytes"] or git_blob(data) != item["git_blob"]:
            raise SystemExit("pinned source mismatch: " + item["path"])
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
    print("RTL8111 source verified:", pin["commit"], str(source))


if __name__ == "__main__":
    main()
