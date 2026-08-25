# esp32sec

ESP32 security toolkit. Flash dumping, UART sniffing, firmware analysis.

- tools/     individual scripts
- docs/      hardware setup
- examples/  usage walkthroughs

Requirements: Python 3.10+, esptool.py, USB-to-UART bridge.

Quick start:
  pip install -r requirements.txt
  sudo python3 tools/flash_dump.py --port /dev/ttyUSB0

Only test on devices you own.
