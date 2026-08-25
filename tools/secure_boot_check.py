#!/usr/bin/env python3
"""Heuristically check whether a dumped ESP32 image hints at secure boot / flash crypto."""
import argparse
import struct
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description="Check secure boot / flash crypto on a flash dump")
    p.add_argument("image", help="path to flash dump")
    args = p.parse_args()

    data = Path(args.image).read_bytes()
    print(f"[+] File: {args.image}  size={len(data)} bytes")

    # Look for an ESP32 app image header (magic 0xE9) in the standard slots.
    for offset in (0x10000, 0x20000, 0x1000):
        if offset + 24 > len(data):
            continue
        if data[offset] != 0xE9:
            continue
        chip_id = struct.unpack("<I", data[offset + 19:offset + 23])[0]
        print(f"[+] App image header at 0x{offset:x}  chip_id=0x{chip_id:08x}")
        if chip_id == 0:
            print("[?] chip_id is 0 - image may be blank or encrypted")
        else:
            print(f"[i] Chip family = {chip_id >> 12 & 0xFF}")
        break
    else:
        print("[!] No ESP32 app image magic (0xE9) found in standard slots")

    print("\n[i] For ground truth run: espefuse.py --port <port> summary")
    print("    (requires physical access to the device)")


if __name__ == "__main__":
    main()
