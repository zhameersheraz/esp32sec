#!/usr/bin/env python3
"""Read and pretty-print the ESP32 partition table from a flash dump."""
import argparse
import struct
import sys
from pathlib import Path


# https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/storage/partition_table.html
TYPES = {0x00: "app", 0x01: "data"}
SUBTYPES_APP = {0x00: "factory", 0x10: "ota_0", 0x11: "ota_1", 0x20: "test"}
SUBTYPES_DATA = {
    0x00: "ota", 0x01: "phy", 0x02: "nvs", 0x03: "coredump",
    0x04: "nvs_keys", 0x05: "efuse", 0x06: "undefined", 0x80: "esphttpd",
    0x81: "fat", 0x82: "spiffs",
}
ENTRY_SIZE = 32  # bytes per partition entry


def main():
    p = argparse.ArgumentParser(description="Read ESP32 partition table")
    p.add_argument("image", help="path to flash dump")
    p.add_argument("--offset", type=lambda x: int(x, 0), default=0x8000,
                   help="partition table offset (default 0x8000)")
    args = p.parse_args()

    data = Path(args.image).read_bytes()
    if args.offset + ENTRY_SIZE > len(data):
        sys.exit(f"[-] Image too small for offset 0x{args.offset:x}")

    print(f"[+] Partition table at 0x{args.offset:x}")
    print(f"{'name':<16} {'type':<10} {'subtype':<12} {'offset':<12} {'size':<12} {'end'}")
    print("-" * 74)

    for i in range(128):
        off = args.offset + i * ENTRY_SIZE
        if off + ENTRY_SIZE > len(data):
            break
        chunk = data[off:off + ENTRY_SIZE]
        if chunk[:2] != b"\xaa\x50":
            break
        ptype, psub = struct.unpack("<BB", chunk[2:4])
        offset = struct.unpack("<I", chunk[4:8])[0]
        size = struct.unpack("<I", chunk[8:12])[0]
        name = chunk[16:32].rstrip(b"\x00").decode("ascii", "replace")
        if ptype == 0xFF and psub == 0xFF:
            print(f"{'(end marker)':<16}")
            break
        type_str = TYPES.get(ptype, f"0x{ptype:02x}")
        if ptype == 0:
            sub_str = SUBTYPES_APP.get(psub, f"0x{psub:02x}")
        else:
            sub_str = SUBTYPES_DATA.get(psub, f"0x{psub:02x}")
        print(f"{name:<16} {type_str:<10} {sub_str:<12} "
              f"0x{offset:08x}   0x{size:08x}   0x{offset + size:08x}")


if __name__ == "__main__":
    main()
