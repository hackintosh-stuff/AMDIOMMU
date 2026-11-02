#!/usr/bin/env python3
"""Enumerate the PCI MMIO windows the firmware actually assigned, and test
candidate DMA addresses against them.

WHY THIS EXISTS
---------------
Round 5 concluded that the single out-of-range IO_PAGE_FAULT at 0x405d1999c
"is MMIO because it is above 16 GiB". That was an inference from the RAM size,
not evidence about the address. Two things are needed instead:

  (a) the real set of assigned MMIO windows, and
  (b) an explicit statement of what remains unknown.

WHERE THE WINDOWS COME FROM
---------------------------
`assigned-addresses` uses the OpenFirmware 5-cell range encoding, and getting
that decode right from scratch is error-prone (a first attempt produced
garbage because the space-code field is not where the usual OF documentation
puts it). IOKit already decodes it: every IOPCIDevice carries an
`IODeviceMemory` property whose values are literal {"address"=N,"length"=N}
pairs. That is the authoritative decoded form, so this tool reads it instead
of re-deriving bit fields.

Usage:
    python3 pci-windows.py [address ...]

Exit code 0 always (it is a report, not a verdict); CONTAINS / NOT-IN-ANY-WINDOW
lines are meant to be grepped by callers.
"""
import re
import subprocess
import sys


def run(args):
    p = subprocess.run(args, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL)
    return p.stdout.decode("utf-8", "replace")


def split_devices(text):
    blocks = []
    cur = None
    for line in text.splitlines():
        if "+-o " in line:
            if cur is not None:
                blocks.append(cur)
            m = re.search(r"\+-o (\S+)", line)
            cur = {"name": m.group(1) if m else "?", "lines": []}
            continue
        if cur is not None:
            cur["lines"].append(line)
    if cur is not None:
        blocks.append(cur)
    return blocks


def props(block):
    """Collect `"key" = value` pairs from a node body (single-line values)."""
    out = {}
    for line in block["lines"]:
        m = re.match(r'\s*"([^"]+)"\s*=\s*(.*)$', line.strip())
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def parse_devicememory(val):
    """Parse `({"address"=N,"length"=N}, ...)` into [(addr, len), ...]."""
    out = []
    for m in re.finditer(r'\{"address"=(\d+)\s*,\s*"length"=(\d+)\}', val):
        out.append((int(m.group(1)), int(m.group(2))))
    return out


def main():
    addrs = []
    for a in sys.argv[1:]:
        try:
            addrs.append(int(a, 16) if a.lower().startswith("0x") else int(a))
        except ValueError:
            print("bad address: %s" % a)
            return 2

    text = run(["/usr/sbin/ioreg", "-r", "-c", "IOPCIDevice", "-w0", "-l"])
    devs = split_devices(text)
    print("PCI memory windows assigned by the firmware")
    print("=" * 78)
    print("source : ioreg -r -c IOPCIDevice -w0 -l")
    print("field  : IODeviceMemory (IOKit's decoded form of assigned-addresses)")
    print("devices: %d IOPCIDevice instances" % len(devs))
    print()

    wins = []
    for d in devs:
        p = props(d)
        if "IODeviceMemory" not in p:
            continue
        for addr, length in parse_devicememory(p["IODeviceMemory"]):
            if length == 0:
                continue
            wins.append({
                "dev": d["name"],
                "pcidebug": p.get("pcidebug", "?").strip('"'),
                "vendor": p.get("vendor-id", "?").strip("<>"),
                "device": p.get("device-id", "?").strip("<>"),
                "addr": addr, "len": length,
            })

    wins.sort(key=lambda w: w["addr"])
    hdr = "%-22s %-10s %-11s %-14s %-12s %s" % (
        "device", "pcidebug", "ids", "base", "size", "end")
    print(hdr)
    print("-" * len(hdr))
    for w in wins:
        print("%-22s %-10s %-11s 0x%012x 0x%010x 0x%012x" % (
            w["dev"][:22], w["pcidebug"][:10],
            (w["vendor"] + ":" + w["device"])[:11],
            w["addr"], w["len"], w["addr"] + w["len"]))
    print()
    print("windows: %d" % len(wins))
    if wins:
        lo = min(w["addr"] for w in wins)
        hi = max(w["addr"] + w["len"] for w in wins)
        print("span   : 0x%x .. 0x%x" % (lo, hi))
    print()

    if not addrs:
        return 0

    print("Address containment test")
    print("=" * 78)
    for a in addrs:
        hits = [w for w in wins if w["addr"] <= a < w["addr"] + w["len"]]
        print("0x%x  (%d bytes, %.3f GiB)" % (a, a, a / float(1 << 30)))
        if hits:
            for w in hits:
                print("  CONTAINS-BY-PCI-WINDOW %s (%s) 0x%x..0x%x size 0x%x"
                      % (w["dev"], w["pcidebug"], w["addr"],
                         w["addr"] + w["len"], w["len"]))
        else:
            print("  NOT-IN-ANY-PCI-WINDOW")
            print("  No assigned PCI memory window contains it. This rules")
            print("  out those windows; it does NOT make the address RAM.")
        print()

    print("What this test can and cannot conclude")
    print("-" * 78)
    print("  CONTAINS-BY-PCI-WINDOW  -> the address is inside a device's")
    print("                             assigned MMIO window; a DMA access to")
    print("                             it would be an MMIO access, not RAM.")
    print("  NOT-IN-ANY-PCI-WINDOW   -> not one of the windows listed above.")
    print("                             Neither RAM nor MMIO is established;")
    print("                             the remaining candidates (RAM above the")
    print("                             mapped limit, firmware-reserved range,")
    print("                             or a mis-programmed device address)")
    print("                             have to be separated by other evidence.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
