#!/usr/bin/env python3
import argparse, subprocess, sys
def main():
    p = argparse.ArgumentParser(description="Dump ESP32 flash")
    p.add_argument("--port", default="/dev/ttyUSB0")
    p.add_argument("--baud", type=int, default=115200)
    p.add_argument("--output", default="flash_dump.bin")
    p.add_argument("--size", default="4MB")
    a = p.parse_args()
    cmd = ["esptool.py", "--port", a.port, "--baud", str(a.baud), "read_flash", "0x0", a.size, a.output]
    print("[+] " + " ".join(cmd))
    try:
        subprocess.run(cmd, check=True)
        print("[+] Wrote " + a.output)
    except FileNotFoundError:
        sys.exit("esptool.py not found. pip install esptool")
    except subprocess.CalledProcessError as e:
        sys.exit("esptool failed: " + str(e))
if __name__ == "__main__":
    main()
