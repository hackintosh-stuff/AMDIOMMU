#!/usr/bin/env python3
"""Decode the two firmware-side memory-layout sources macOS actually exposes:

  1. the device-tree /memory node  -- its `reg` property is a list of
     (base, size) cell pairs describing the RAM the firmware hands to the OS.
  2. `sysctl -b machdep.memmap`    -- the raw EFI memory map descriptor array
     as the kernel retained it (EfiMemoryRange records, 40 bytes each).

Both are real address maps. Neither is the installed-RAM size.

Output is compact on purpose: `ioreg -l` on this machine is ~200 KB per
query and the interesting node is tiny.
"""
import re
import struct
import subprocess
import sys

EFI_TYPES = {
    0: "Reserved", 1: "LoaderCode", 2: "LoaderData", 3: "BootServicesCode",
    4: "BootServicesData", 5: "RuntimeServicesCode", 6: "RuntimeServicesData",
    7: "Conventional", 8: "Unusable", 9: "ACPIReclaim", 10: "ACPINVS",
    11: "MemoryMappedIO", 12: "MemoryMappedIOPortSpace", 13: "PalCode",
}


def sh(args):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return p.stdout


def dt_memory_node():
    """Print the /memory node's properties."""
    out = sh(["/usr/sbin/ioreg", "-p", "IODeviceTree", "-w0", "-l"])
    text = out.decode("utf-8", "replace")
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.search(r"\+-o memory\s+<class", line):
            start = i
            break
    if start is None:
        print("no /memory node")
        return
    # Node body runs until the next sibling at the same or shallower depth.
    base_indent = lines[start].index("+-o")
    body = []
    for line in lines[start + 1:]:
        if "+-o " in line:
            break
        body.append(line)
    print("device-tree /memory node")
    print("-" * 70)
    for line in body:
        s = line.strip()
        if not s.startswith('"'):
            continue
        m = re.match(r'"([^"]+)"\s*=\s*(.*)$', s)
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        if val.startswith("<") and val.endswith(">"):
            raw = val[1:-1].replace(" ", "")
            if len(raw) % 16 == 0 and len(raw) > 16:
                cells = [raw[i:i + 8] for i in range(0, len(raw), 8)]
                print("%-14s %d cells -> %d (base,size) pairs"
                      % (key, len(cells), len(cells) // 2))
                for j in range(0, len(cells) - 1, 2):
                    b = int(cells[j], 16)
                    sz = int(cells[j + 1], 16)
                    print("    base 0x%012x  size 0x%012x  end 0x%012x"
                          % (b, sz, b + sz))
            else:
                print("%-14s %s" % (key, val))
        else:
            print("%-14s %s" % (key, val[:70]))


def efi_memmap():
    raw = sh(["/usr/sbin/sysctl", "-b", "machdep.memmap"])
    print()
    print("EFI memory map as retained by the kernel (machdep.memmap)")
    print("-" * 70)
    print("raw length: %d bytes" % len(raw))
    if not raw:
        print("empty")
        return
    # EfiMemoryRange: u32 Type, u32 Pad, u64 PhysicalStart, u64 VirtualStart,
    #                 u64 NumberOfPages, u64 Attribute   == 40 bytes
    n = len(raw) // 40
    print("records: %d (40 bytes each)" % n)
    print()
    hdr = "%-4s %-22s %-14s %-14s %-14s %s" % (
        "type", "name", "start", "end", "size", "pages")
    print(hdr)
    print("-" * len(hdr))
    total_conv = 0
    for i in range(n):
        rec = raw[i * 40:(i + 1) * 40]
        t, pad, ps, vs, pages, attr = struct.unpack("<IIQQQQ", rec)
        size = pages * 4096
        name = EFI_TYPES.get(t, "?%d" % t)
        if t == 7:
            total_conv += size
        print("%-4d %-22s 0x%012x 0x%012x 0x%012x %d"
              % (t, name, ps, ps + size, size, pages))
    print()
    print("Conventional total: 0x%x (%d bytes, %.3f GiB)"
          % (total_conv, total_conv, total_conv / float(1 << 30)))
    print()
    print("NOTE: this is the EFI map, i.e. the address layout the firmware")
    print("published. A DMA address that falls in NO record above is outside")
    print("the memory the firmware described -- but that still does not say")
    print("what the address IS. Combine with the PCI window list.")


def main():
    dt_memory_node()
    efi_memmap()
    return 0


if __name__ == "__main__":
    sys.exit(main())
