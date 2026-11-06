#!/usr/bin/env python3
"""Enumerate the PCI address windows the firmware actually assigned, and test
a candidate DMA address against them.

WHY THIS EXISTS
---------------
Round 5 concluded that the single out-of-range IO_PAGE_FAULT at 0x405d1999c
"is MMIO because it is above 16 GiB". That is an inference from the RAM size,
not evidence about the address. The only thing that can settle it is the
actual address map the firmware handed out.

This tool reads `assigned-addresses` and `reg` from every IOPCIDevice and
decodes the OpenFirmware 5-cell range format:

    cell0  phys_hi   bit31 relocatable, bits24:31 space (0=cfg 1=io
                     2=mem32 3=mem64), bits16:23 bus, 8:15 dev, 0:7 fn
    cell1  phys_mid
    cell2  phys_lo
    cell3  size_hi
    cell4  size_lo

It then reports every range containing the queried address, plus the full
list so the layout can be judged on its own terms.

It also tries to recover the EFI memory map if the device tree carries one,
because "how much RAM" (hw.memsize) says nothing about where the holes are.

Usage:
    python3 pci-bars.py [address ...]

Addresses accept 0x... or decimal. Exit code 0 always (it is a report, not a
verdict); it prints CONTAINS / NOT-IN-ANY-WINDOW lines that callers can grep.
"""
import re
import subprocess
import sys

IOREG = "/usr/sbin/ioreg"

SPACE = {0: "config", 1: "io", 2: "mem32", 3: "mem64"}


def run(args):
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, check=False)
    except OSError:
        return ""
    return p.stdout.decode("utf-8", "replace")


def hexdata(text):
    """Decode an ioreg '<00112233 ...>' property into bytes."""
    s = text.strip()
    if s.startswith("<") and s.endswith(">"):
        s = s[1:-1]
    s = re.sub(r"\s+", "", s)
    if len(s) % 2:
        return b""
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b""


def cells(data):
    out = []
    for i in range(0, len(data) - 3, 4):
        out.append((data[i] << 24) | (data[i + 1] << 16) |
                   (data[i + 2] << 8) | data[i + 3])
    return out


def parse_ranges(data):
    """Decode 5-cell OF ranges. Returns list of dicts."""
    out = []
    c = cells(data)
    for i in range(0, len(c) - 4, 5):
        hi, mid, lo, shi, slo = c[i:i + 5]
        space = (hi >> 24) & 0x3
        base = ((hi & 0x00FFFFFF) << 64) | (mid << 32) | lo
        size = (shi << 32) | slo
        out.append({
            "space": SPACE.get(space, "?%d" % space),
            "base": base,
            "size": size,
            "end": base + size,
        })
    return out


def split_devices(text):
    """Split `ioreg -c IOPCIDevice -w0 -l` output into per-device blocks.

    With -c IOPCIDevice only IOPCIDevice instances are printed, so each
    '+-o ' header starts a leaf block.
    """
    blocks = []
    cur = None
    for line in text.splitlines():
        if "+-o " in line:
            if cur is not None:
                blocks.append(cur)
            m = re.search(r"\+-o (\S+)\s+<class ([^,>]+)", line)
            cur = {
                "name": m.group(1) if m else "?",
                "class": m.group(2) if m else "?",
                "props": {},
            }
            continue
        if cur is None:
            continue
        m = re.match(r'\s*"([^"]+)"\s*=\s*(.*)$', line)
        if m:
            cur["props"][m.group(1)] = m.group(2).strip()
    if cur is not None:
        blocks.append(cur)
    return blocks


def strprop(p, key):
    v = p.get(key)
    if v is None:
        return ""
    m = re.match(r'"(.*)"$', v)
    return m.group(1) if m else v


def dataprop(p, key):
    v = p.get(key)
    if v is None or not v.startswith("<"):
        return b""
    return hexdata(v)


def main():
    addrs = []
    for a in sys.argv[1:]:
        try:
            addrs.append(int(a, 16) if a.lower().startswith("0x") else int(a))
        except ValueError:
            print("bad address: %s" % a)
            return 2

    print("PCI address windows actually assigned by the firmware")
    print("=" * 78)
    print("source: %s -r -c IOPCIDevice -w0 -l" % IOREG)
    print()

    devs = split_devices(run([IOREG, "-r", "-c", "IOPCIDevice", "-w0", "-l"]))
    print("IOPCIDevice instances: %d" % len(devs))
    print()

    ranges = []
    for d in devs:
        p = d["props"]
        name = strprop(p, "IOName") or d["name"]
        vendor = strprop(p, "vendor-id")
        device = strprop(p, "device-id")
        pcidebug = strprop(p, "pcidebug")
        for key in ("assigned-addresses", "reg"):
            for r in parse_ranges(dataprop(p, key)):
                if r["size"] == 0:
                    continue
                r["dev"] = d["name"]
                r["ioname"] = name
                r["ids"] = "%s:%s" % (vendor, device)
                r["pcidebug"] = pcidebug
                r["src"] = key
                ranges.append(r)

    print("Decoded non-empty address windows: %d" % len(ranges))
    print()
    hdr = "%-26s %-8s %-6s %-18s %-14s %s" % (
        "device", "ids", "src", "base", "size", "space")
    print(hdr)
    print("-" * len(hdr))
    for r in sorted(ranges, key=lambda x: x["base"]):
        print("%-26s %-8s %-6s 0x%016x 0x%012x %s" % (
            r["dev"][:26], r["ids"][:8], r["src"], r["base"],
            r["size"], r["space"]))
    print()

    if addrs:
        print("Address containment test")
        print("-" * 78)
        for a in addrs:
            hits = [r for r in ranges if r["base"] <= a < r["end"]]
            print("0x%x  (%d bytes, %.3f GiB)" % (a, a, a / float(1 << 30)))
            if hits:
                for r in hits:
                    print("  CONTAINS by %s (%s) window 0x%x..0x%x "
                          "size 0x%x src=%s"
                          % (r["dev"], r["ioname"], r["base"], r["end"],
                             r["size"], r["src"]))
            else:
                print("  NOT-IN-ANY-WINDOW: no PCI window above contains it.")
                print("  That does NOT make it RAM; it only rules out the")
                print("  windows listed here.")
            print()

    # ---- EFI memory map, if the device tree carries one ----
    print("Firmware memory map (if published in the device tree)")
    print("-" * 78)
    dt = run([IOREG, "-p", "IODeviceTree", "-w0", "-l"])
    found = False
    cur = None
    for line in dt.splitlines():
        if "+-o " in line:
            m = re.search(r"\+-o (\S+)", line)
            cur = m.group(1) if m else "?"
        m = re.match(r'\s*"([^"]*[Mm]em[^"]*[Mm]ap[^"]*)"\s*=\s*<(.*)>', line)
        if not m:
            m2 = re.match(r'\s*"([^"]*[Mm]ap[^"]*)"\s*=\s*<(.*)>', line)
            m = m2
        if m:
            found = True
            data = hexdata("<" + m.group(2) + ">")
            print("property %s under node %s, %d bytes"
                  % (m.group(1), cur, len(data)))
    if not found:
        print("no memory-map style property in the device tree.")
        print("The authoritative layout has to come from the firmware")
        print("itself (rescue USB: /proc/iomem and /sys/firmware/memmap/).")
    print()

    # ---- macOS view of installed RAM, for contrast only ----
    print("For contrast only (NOT an address layout)")
    print("-" * 78)
    print("hw.memsize : %s" % run(["/usr/sbin/sysctl", "-n",
                                    "hw.memsize"]).strip())
    print("hw.physmem : %s" % run(["/usr/sbin/sysctl", "-n",
                                    "hw.physmem"]).strip())
    print("Installed RAM says nothing about where the firmware put the")
    print("holes, so it cannot be used to classify a DMA address.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
