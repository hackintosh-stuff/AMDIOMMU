#!/usr/bin/env python3
"""Decode the two IVHD blocks in the captured IVRS fixture.

Purpose: determine what iommu_init_flags() (Linux v6.6 init.c:2685-2710) would
do on THIS board, because that function is the one step of the canonical
enable sequence that our probe skips entirely.

iommu_init_flags() unconditionally enables CONTROL_COHERENT_EN (bit 10) and sets
the IOTLB invalidation timeout, then conditionally sets:
    HT_TUN_EN     (bit 1)  <- IVHD_FLAG_HT_TUN_EN_MASK
    PASSPW_EN     (bit 8)  <- IVHD_FLAG_PASSPW_EN_MASK
    RESPASSPW_EN  (bit 9)  <- IVHD_FLAG_RESPASSPW_EN_MASK
    ISOC_EN       (bit 11) <- IVHD_FLAG_ISOC_EN_MASK

The IOTLB invalidation timeout matters a great deal here: if it is left at the
firmware default and the IOMMU cannot complete an invalidation, the hardware
logs EVENT_TYPE_IOTLB_INV_TO (0x7) and the translation is never made valid.

IVHD common prefix (docs/ivrs-format.md:46): type u8 at 0, flags u8 at 1,
length u16 at 2, DeviceID u16 at 4.

Usage: decode-ivhd.py <IVRS-blob.bin>
The blob is the raw IVRS table, captured once per board; nothing is assumed
about which board it came from.
"""
import struct
import sys

# Linux v6.6 init.c:2687-2701, amd_iommu_types.h IVHD_FLAG_* masks
IVHD_FLAG_HT_TUN_EN_MASK = 0x01
IVHD_FLAG_PASSPW_EN_MASK = 0x02
IVHD_FLAG_RESPASSPW_EN_MASK = 0x04
IVHD_FLAG_ISOC_EN_MASK = 0x08
IVHD_FLAG_EFRSUP_MASK = 0x20

FLAG_NAMES = [
    (0x01, "HT_TUN_EN"),
    (0x02, "PASSPW_EN"),
    (0x04, "RESPASSPW_EN"),
    (0x08, "ISOC_EN"),
    (0x10, "COHERENT"),
    (0x20, "EFRSUP"),
    (0x40, "reserved6"),
    (0x80, "reserved7"),
]


def main(argv):
    if len(argv) != 2:
        print("usage: decode-ivhd.py <IVRS-blob.bin>", file=sys.stderr)
        return 2
    path = argv[1]
    try:
        with open(path, "rb") as f:
            blob = f.read()
    except OSError as exc:
        print("cannot read {}: {}".format(path, exc), file=sys.stderr)
        return 2

    total_len = struct.unpack_from("<I", blob, 4)[0]
    print("IVRS length = {} bytes".format(total_len))

    # IVRS fixed prefix is 48 bytes (docs/ivrs-format.md:45)
    off = 48
    blocks = []
    while off + 6 <= min(total_len, len(blob)):
        btype = blob[off]
        bflags = blob[off + 1]
        blen = struct.unpack_from("<H", blob, off + 2)[0]
        bdevid = struct.unpack_from("<H", blob, off + 4)[0]
        if blen < 6:
            print("malformed block at 0x{:X}: len={}".format(off, blen))
            break
        blocks.append((off, btype, bflags, blen, bdevid))
        off += blen

    print("blocks found: {}".format(len(blocks)))
    print()

    ivhd_flags = None
    for (o, t, fl, ln, devid) in blocks:
        print("block at 0x{:03X}: type=0x{:02X} flags=0x{:02X} len={} "
              "DeviceID={:04x}:{:02x}:{:02x}.{}".format(
                  o, t, fl, ln,
                  (devid >> 8) & 0xFF, (devid >> 3) & 0x1F, devid & 7,
                  devid & 7))
        names = [n for m, n in FLAG_NAMES if fl & m]
        print("  flags set: {}".format(", ".join(names) if names else "(none)"))
        if t in (0x10, 0x11, 0x40):
            if ivhd_flags is None:
                ivhd_flags = fl
            elif fl != ivhd_flags:
                print("  !! disagrees with the first IVHD block's flags")
            # For 0x11/0x40 the attributes word is at 20 (docs line 48)
            if t in (0x11, 0x40) and ln >= 24:
                attrs = struct.unpack_from("<I", blob, o + 20)[0]
                efr = struct.unpack_from("<Q", blob, o + 24)[0]
                print("  attributes = 0x{:08X}".format(attrs))
                print("  EFR image  = 0x{:016X}".format(efr))
        print()

    if ivhd_flags is None:
        print("no IVHD block found")
        return 1

    print("=" * 62)
    print("IVHD flags byte = 0x{:02X}".format(ivhd_flags))
    print()
    for mask, bit, name in [
        (IVHD_FLAG_HT_TUN_EN_MASK, 1, "CONTROL_HT_TUN_EN"),
        (IVHD_FLAG_PASSPW_EN_MASK, 8, "CONTROL_PASSPW_EN"),
        (IVHD_FLAG_RESPASSPW_EN_MASK, 9, "CONTROL_RESPASSPW_EN"),
        (IVHD_FLAG_ISOC_EN_MASK, 11, "CONTROL_ISOC_EN"),
    ]:
        on = bool(ivhd_flags & mask)
        print("  {:<20} (bit{:>2}) = {}".format(
            name, bit, "SET" if on else "cleared"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
