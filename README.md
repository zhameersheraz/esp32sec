# esp32sec

ESP32 security toolkit. Firmware analysis, UART sniffing, partition parsing, and
security posture checks for ESP32/ESP8266 hardware.

## Tools

| Tool                          | What it does                                                |
| ----------------------------- | ----------------------------------------------------------- |
| `tools/flash_dump.py`         | Dump flash over UART via esptool                            |
| `tools/uart_sniffer.py`       | Capture boot/runtime UART output                            |
| `tools/firmware_inspect.py`   | Quick-look at a flash image: strings, magic, NVS markers   |
| `tools/partition_table.py`    | Read and pretty-print the partition table from a dump       |
| `tools/secure_boot_check.py`  | Heuristic check for secure boot / flash crypto state        |

## Install

    pip install -r requirements.txt

## Quick start

    # 1. dump the flash
    sudo python3 tools/flash_dump.py --port /dev/ttyUSB0 --output flash.bin

    # 2. inspect it
    python3 tools/firmware_inspect.py flash.bin --strings

    # 3. read the partition table
    python3 tools/partition_table.py flash.bin

    # 4. sniff live UART during boot
    sudo python3 tools/uart_sniffer.py --port /dev/ttyUSB0 --baud 74880

## Docs

- Live site: https://zhameersheraz.github.io/esp32sec/

## Legal

Only test against devices you own or have explicit written permission to test.
The author is not responsible for misuse.
