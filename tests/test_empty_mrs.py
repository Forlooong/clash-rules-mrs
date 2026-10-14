import hashlib
import os
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

import zstandard

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from audit_sources import decode_mrs
from empty_mrs import EMPTY_DOMAIN_RAW, encode_empty_mrs, verify_empty_mrs


class EmptyMrsTests(unittest.TestCase):
    def test_encoding_is_nonempty_but_has_no_domain_or_terminal(self):
        data = encode_empty_mrs()
        self.assertGreater(len(data), 0)
        self.assertEqual(data, encode_empty_mrs())
        parsed = decode_mrs(data)
        self.assertEqual(parsed["count"], 0)
        self.assertEqual(parsed["domains"], [])
        self.assertEqual(parsed["fingerprint"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(verify_empty_mrs(data)["terminal_bits"], 0)

    def test_zero_bytes_and_terminal_or_count_tampering_are_rejected(self):
        for bad in (b"", b"not zstd", encode_empty_mrs()[:-1], encode_empty_mrs() + b"extra",
                    zstandard.ZstdCompressor().compress(EMPTY_DOMAIN_RAW[:-1]),
                    zstandard.ZstdCompressor().compress(EMPTY_DOMAIN_RAW + b"extra")):
            with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                verify_empty_mrs(bad)
        for offset in (5, 30):  # MRS rule count and terminal bitmap.
            raw = bytearray(EMPTY_DOMAIN_RAW)
            raw[offset:offset + 8] = struct.pack(">Q", 1)
            with self.assertRaises(ValueError):
                verify_empty_mrs(zstandard.ZstdCompressor().compress(raw))

    def test_other_behaviors_are_not_silently_substituted(self):
        for behavior in ("ipcidr", "classical", None):
            with self.assertRaises(ValueError):
                encode_empty_mrs(behavior)

    def test_core_command_is_resolved_from_path_when_not_in_current_directory(self):
        with patch("empty_mrs.shutil.which", return_value="/verified/bin/mihomo") as locate, \
                patch("empty_mrs.subprocess.check_output", side_effect=RuntimeError("stop before runtime")) as execute:
            with self.assertRaisesRegex(RuntimeError, "stop before runtime"):
                verify_empty_mrs(encode_empty_mrs(), "test-mihomo-on-path-only")
        locate.assert_called_once_with("test-mihomo-on-path-only")
        self.assertEqual(execute.call_args.args[0], ["/verified/bin/mihomo", "-v"])

    def test_pinned_core_loads_zero_count_provider_and_matches_no_sample(self):
        configured = os.environ.get("MIHOMO_BIN")
        bundled = ROOT / ".tools/mihomo-windows-amd64-compatible.exe"
        core = Path(configured) if configured else bundled if os.name == "nt" else None
        if core is None or not core.is_file():
            self.skipTest("Set MIHOMO_BIN to pinned Mihomo v1.19.32 for full-provider verification")
        report = verify_empty_mrs(encode_empty_mrs(), str(core))
        self.assertTrue(report["provider_loaded"])
        self.assertEqual(report["rule_count"], 0)
        self.assertFalse(report["runtime_match"])
        self.assertGreaterEqual(report["nonmatching_cases"], 10)
        self.assertIn("rejects count zero", report["converter"])


if __name__ == "__main__":
    unittest.main()
