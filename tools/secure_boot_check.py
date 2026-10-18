#!/usr/bin/env python3
"""Heuristically check whether a dumped ESP32 image hints at secure boot / flash crypto."""
import argparse
import struct
from pathlib import Path


# esp_chip_id_t from ESP-IDF (esp_image_format.h). Header layout is:
#   0 magic | 1 seg_count | 2 spi_mode | 3 spi_speed:size | 4-7 entry_addr
#   8 wp_pin | 9-11 spi_pin_drv | 12-13 chip_id | 14 min_chip_rev | 15 deprecated
#   16 hash_appended
CHIP_ID_OFFSET = 12
CHIP_ID_SIZE = 2

CHIP_NAMES = {
    0x0000: "ESP32",
    0x0002: "ESP32-S2",
    0x0005: "ESP32-C3",
    0x0006: "ESP32-C6",
    0x0009: "ESP32-S3",
    0x000C: "ESP32-H2",
    0x000D: "ESP32-P4",
    0x0012: "ESP32-C2",
}


def describe_chip(chip_id: int) -> str:
    name = CHIP_NAMES.get(chip_id)
    return name if name else f"unknown (0x{chip_id:04x})"


def main():
    p = argparse.ArgumentParser(description="Check secure boot / flash crypto on a flash dump")
    p.add_argument("image", help="path to flash dump")
    args = p.parse_args()

    data = Path(args.image).read_bytes()
    print(f"[+] File: {args.image}  size={len(data)} bytes")

    found = False
    # Search the standard app slots rather than only three fixed offsets, so a
    # custom partition layout still gets found.
    for offset in (0x10000, 0x20000, 0x1000):
        if offset + 24 > len(data):
            continue
        if data[offset] != 0xE9:
            continue

        chip_id = struct.unpack(
            "<H", data[offset + CHIP_ID_OFFSET:offset + CHIP_ID_OFFSET + CHIP_ID_SIZE]
        )[0]
        min_rev = data[offset + 14]
        hash_appended = bool(data[offset + 16])
        seg_count = data[offset + 1]

        print(f"[+] App image header at 0x{offset:x}")
        print(f"    segments      = {seg_count}")
        print(f"    chip_id       = 0x{chip_id:04x}  ({describe_chip(chip_id)})")
        print(f"    min_chip_rev  = {min_rev}")
        print(f"    hash_appended = {hash_appended}")

        if chip_id == 0x0000:
            print("[?] ESP32 with chip_id 0 - this is normal for the original ESP32,")
            print("    but a blank or encrypted image also reports 0. Treat as inconclusive.")
        if not hash_appended:
            print("[!] No SHA256 appended - image is unsigned. Secure boot would reject it.")
        found = True
        break

    if not found:
        print("[!] No ESP32 app image magic (0xE9) found in standard slots")

    print("\n[i] For ground truth run: espefuse.py --port <port> summary")
    print("    (requires physical access to the device)")


if __name__ == "__main__":
    main()