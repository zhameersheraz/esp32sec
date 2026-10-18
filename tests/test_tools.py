"""Tests for the esp32sec tools, run against a synthetic but structurally valid flash image."""
import struct
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools.partition_table import TYPES, SUBTYPES_APP, SUBTYPES_DATA  # noqa: E402
from tools.secure_boot_check import CHIP_NAMES, describe_chip  # noqa: E402

SIZE = 0x400000


def build_flash(chip_id=0x0009, parts=None, hash_appended=True):
    img = bytearray(b"\xFF" * SIZE)

    hdr = bytearray(24)
    hdr[0] = 0xE9
    hdr[1] = 2
    hdr[2] = 0x02
    hdr[3] = 0x2F
    struct.pack_into("<I", hdr, 4, 0x40080000)
    hdr[8] = 0xEE
    struct.pack_into("<H", hdr, 12, chip_id)
    hdr[14] = 0
    hdr[16] = 1 if hash_appended else 0
    img[0x10000:0x10000 + 24] = hdr

    # Trap: garbage where the old implementation used to read chip_id.
    struct.pack_into("<I", img, 0x10000 + 19, 0xDEADBEEF)

    def entry(ptype, psub, off, size_, name):
        e = bytearray(32)
        e[0:2] = b"\xAA\x50"
        e[2] = ptype
        e[3] = psub
        struct.pack_into("<I", e, 4, off)
        struct.pack_into("<I", e, 8, size_)
        e[12:16] = b"\xFF\xFF\xFF\xFF"
        e[16:16 + len(name)] = name.encode()
        return bytes(e)

    if parts is None:
        parts = [
            entry(0x00, 0x00, 0x10000, 0x180000, "factory"),
            entry(0x00, 0x10, 0x1A0000, 0x180000, "ota_0"),
            entry(0x01, 0x02, 0x9000, 0x6000, "nvs"),
        ]
    img[0x8000:0x8000 + 32 * len(parts)] = b"".join(parts)

    img[0x20000:0x20000 + 40] = b"ESP-IDF\x00v5.1\x00password=hunter2\x00\x00"
    return bytes(img)


class TestChipIdentification(unittest.TestCase):
    """The header offsets are the part that was silently wrong."""

    def test_chip_id_read_from_correct_offset(self):
        for chip_id in CHIP_NAMES:
            with self.subTest(chip_id=hex(chip_id)):
                import importlib
                mod = importlib.import_module("tools.secure_boot_check")
                data = build_flash(chip_id=chip_id)
                header = data[0x10000:0x10000 + 24]
                got = struct.unpack("<H", header[12:14])[0]
                self.assertEqual(got, chip_id)
                self.assertIn(chip_id, CHIP_NAMES)
        del importlib

    def test_deadbeef_trap_at_old_offset_is_ignored(self):
        data = build_flash(chip_id=0x0009)
        # The bytes the old code read.
        wrong = struct.unpack("<I", data[0x10000 + 19:0x10000 + 23])[0]
        self.assertEqual(wrong, 0xDEADBEEF)
        # The bytes the code should read.
        right = struct.unpack("<H", data[0x10000 + 12:0x10000 + 14])[0]
        self.assertEqual(right, 0x0009)

    def test_describe_chip_known_and_unknown(self):
        self.assertEqual(describe_chip(0x0009), "ESP32-S3")
        self.assertEqual(describe_chip(0x0000), "ESP32")
        self.assertIn("unknown", describe_chip(0xBEEF))

    def test_tool_output_reports_right_chip(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f.bin"
            p.write_bytes(build_flash(chip_id=0x0009))
            out = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "secure_boot_check.py"), str(p)],
                capture_output=True, text=True,
            )
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("0x0009", out.stdout)
            self.assertIn("ESP32-S3", out.stdout)
            self.assertNotIn("deadbeef", out.stdout.lower())
            self.assertNotIn("Chip family", out.stdout)


class TestPartitionTable(unittest.TestCase):
    def test_subtype_maps_cover_known_ids(self):
        self.assertEqual(TYPES[0x00], "app")
        self.assertEqual(TYPES[0x01], "data")
        self.assertEqual(SUBTYPES_APP[0x10], "ota_0")
        self.assertEqual(SUBTYPES_DATA[0x02], "nvs")
        self.assertEqual(SUBTYPES_DATA[0x82], "spiffs")

    def test_tool_output_lists_partitions(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f.bin"
            p.write_bytes(build_flash())
            out = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "partition_table.py"), str(p)],
                capture_output=True, text=True,
            )
            self.assertEqual(out.returncode, 0, out.stderr)
            for name in ("factory", "ota_0", "nvs"):
                self.assertIn(name, out.stdout)
            self.assertIn("0x00010000", out.stdout)
            self.assertNotIn("flags", out.stdout)

    def test_rejects_image_too_small_for_offset(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "tiny.bin"
            p.write_bytes(b"\xFF" * 16)
            out = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "partition_table.py"), str(p)],
                capture_output=True, text=True,
            )
            self.assertNotEqual(out.returncode, 0)


class TestFirmwareInspect(unittest.TestCase):
    def test_finds_seeded_strings(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f.bin"
            p.write_bytes(build_flash())
            out = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "firmware_inspect.py"), str(p), "--strings"],
                capture_output=True, text=True,
            )
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("password=hunter2", out.stdout)


class TestLlmReview(unittest.TestCase):
    def test_flags_password_literal(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f.bin"
            p.write_bytes(build_flash())
            out = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "llm_firmware_review.py"), str(p)],
                capture_output=True, text=True,
            )
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("hunter2", out.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)