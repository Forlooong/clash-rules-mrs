import importlib.util
import tempfile
import unittest
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "scripts/build-personal.py"
spec = importlib.util.spec_from_file_location("personal", path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class Personal(unittest.TestCase):
    def test_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "direct.yaml"
            p.write_text("payload:\n  - ''\n")
            self.assertEqual(mod.load(p), [])

    def test_mapping(self):
        result = mod.split(["DOMAIN,Example.com", "DOMAIN-SUFFIX,example.net",
                            "IP-CIDR,192.0.2.1/24", "IP-CIDR6,2001:db8::/32",
                            "IP-CIDR,192.0.2.0/24,no-resolve", "DOMAIN-KEYWORD,abc"])
        self.assertEqual(result["domain"], ["full:example.com", "+.example.net"])
        self.assertEqual(result["ipcidr"], ["192.0.2.0/24", "2001:db8::/32"])
        self.assertEqual(result["classical"], ["IP-CIDR,192.0.2.0/24,no-resolve", "DOMAIN-KEYWORD,abc"])

    def test_invalid(self):
        for rule in ("DOMAIN,", "IP-CIDR,invalid", "IP-CIDR6,192.0.2.0/24"):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                mod.split([rule])
