#!/usr/bin/env python3
"""Quick-look at a dumped flash image: strings, chip ID, partition markers."""
import argparse
import re
from pathlib import Path


ESP32_MAGIC = b"\xe9\x00"  # first 2 bytes of any valid ESP32 image
NVS_MAGIC = b"NVS"
PARTITION_MAGIC = b"\xaa\x50"


def main():
    p = argparse.ArgumentParser(description="Inspect a dumped ESP32 flash image")
    p.add_argument("image", help="path to .bin flash dump")
    p.add_argument("--strings", action="store_true",
                   help="dump printable strings (>=6 chars)")
    p.add_argument("--min-len", type=int, default=6)
    args = p.parse_args()

    data = Path(args.image).read_bytes()
    print(f"[+] File: {args.image}  size={len(data)} bytes")

    if data[:2] == ESP32_MAGIC:
        print("[+] Looks like a valid ESP32 image (magic 0xE9)")
    else:
        print("[?] No ESP32 magic byte at offset 0")

    if NVS_MAGIC in data:
        print("[+] NVS partition found")
    if PARTITION_MAGIC in data:
        print("[+] Partition table found")

    if args.strings:
        print(f"[+] Extracting strings (min length {args.min_len}):")
        for s in re.findall(rb"[\x20-\x7e]{%d,}" % args.min_len, data):
            print(s.decode("ascii", "replace"))


if __name__ == "__main__":
    main()
