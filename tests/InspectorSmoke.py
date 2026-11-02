#!/usr/bin/env python3
"""CLI smoke tests using synthetic files in the caller's fresh test directory.

A captured real firmware table is additionally replayed if it is present, so a
parser regression that only shows up on genuine firmware is still caught. The
fixture is inert data: nothing here touches firmware, ACPI or hardware.
"""
from pathlib import Path
import struct
import subprocess
import sys

exe, output = sys.argv[1], Path(sys.argv[2])
fixtures = Path(sys.argv[3]) if len(sys.argv) > 3 else Path(__file__).resolve().parents[1] / "fixtures"
base = bytearray(48)
base[:4] = b"IVRS"
struct.pack_into("<I", base, 4, len(base))
base[8] = 2
base[9] = (-sum(base)) & 255
bad_checksum = bytearray(base)
bad_checksum[9] ^= 1
huge = bytearray(base)
struct.pack_into("<I", huge, 4, 0xffffffff)
cases = [
    ("valid-empty-table.bin", base, 0),
    ("truncated.bin", base[:-1], 3),
    ("checksum.bin", bad_checksum, 3),
    ("declared-huge.bin", huge, 3),
    ("empty.bin", b"", 3),
    ("trailing.bin", base + b"tail", 0),
]
for name, data, expected in cases:
    path = output / name
    path.write_bytes(data)
    p = subprocess.run([exe, str(path)], capture_output=True, text=True, timeout=10)
    if p.returncode != expected:
        raise RuntimeError(f"{name}: expected {expected}, got {p.returncode}: {p.stdout}{p.stderr}")
for args, expected in [(["--help"], 0), ([], 2), ([str(output / "nonexistent.bin")], 2)]:
    p = subprocess.run([exe] + args, capture_output=True, text=True, timeout=10)
    if p.returncode != expected:
        raise RuntimeError(f"args {args}: expected {expected}, got {p.returncode}: {p.stdout}{p.stderr}")

# Real firmware capture: MSI MPG X570 GAMING EDGE WIFI, read read-only from Linux
# sysfs on 2026-10-29. The expected values were cross-checked against an
# independent iasl disassembly and the kernel's live EFR word.
real = fixtures / "IVRS-msi-x570-gaming-edge-wifi-20261029.bin"
if real.is_file():
    data = real.read_bytes()
    if len(data) != 208:
        raise RuntimeError(f"{real.name}: expected 208 bytes, got {len(data)}")
    if sum(data) % 256 != 0:
        raise RuntimeError(f"{real.name}: ACPI checksum does not sum to zero")
    p = subprocess.run([exe, str(real)], capture_output=True, text=True, timeout=10)
    if p.returncode != 0:
        raise RuntimeError(f"{real.name}: expected acceptance, got {p.returncode}: {p.stdout}{p.stderr}")
    for token in ("tableBytes=208", "blocks=2", "IVHD=2", "IVMD=0",
                  "devices=16", "unknownBlocks=0", "unknownDevices=0"):
        if token not in p.stdout:
            raise RuntimeError(f"{real.name}: missing {token!r} in output:\n{p.stdout}")
    # A corrupted copy must be rejected, proving the acceptance came from real
    # validation rather than a lax path.
    corrupted = bytearray(data)
    corrupted[0x60] ^= 0xFF
    bad = output / "real-corrupted.bin"
    bad.write_bytes(corrupted)
    p = subprocess.run([exe, str(bad)], capture_output=True, text=True, timeout=10)
    if p.returncode != 3:
        raise RuntimeError(f"corrupted real table: expected 3, got {p.returncode}")
    # Truncating the real table must be caught, not partially accepted.
    short = output / "real-truncated.bin"
    short.write_bytes(data[:-1])
    p = subprocess.run([exe, str(short)], capture_output=True, text=True, timeout=10)
    if p.returncode != 3:
        raise RuntimeError(f"truncated real table: expected 3, got {p.returncode}")
    print("IVRS inspector smoke: 9 synthetic + 3 real-firmware cases, 0 failures")
else:
    print("IVRS inspector smoke: 9 cases, 0 failures (real firmware fixture absent)")
