#!/usr/bin/env python3
"""Capture raw UART output from an ESP32 (boot logs, debug prints)."""
import argparse
import serial


def main():
    p = argparse.ArgumentParser(description="Sniff ESP32 UART output")
    p.add_argument("--port", default="/dev/ttyUSB0")
    p.add_argument("--baud", type=int, default=74880,
                   help="ESP32 boot ROM uses 74880; runtime is usually 115200")
    p.add_argument("--output", default="uart_capture.log")
    p.add_argument("--seconds", type=int, default=0,
                   help="stop after N seconds (0 = until Ctrl+C)")
    args = p.parse_args()

    print(f"[+] Opening {args.port} @ {args.baud} baud -> {args.output}")
    print("[+] Press Ctrl+C to stop.")
    with serial.Serial(args.port, args.baud, timeout=1) as ser, \
         open(args.output, "wb") as out:
        import time
        start = time.time()
        try:
            while True:
                chunk = ser.read(4096)
                if chunk:
                    out.write(chunk)
                    out.flush()
                if args.seconds and (time.time() - start) >= args.seconds:
                    break
        except KeyboardInterrupt:
            pass
    print(f"[+] Saved to {args.output}")


if __name__ == "__main__":
    main()
