import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from runtime import snapshot as s

spec = importlib.util.spec_from_file_location("four_sources", Path(__file__).resolve().parents[1] / "scripts/four_sources.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)

def fixture():
    inline = {"schema_version": 1, "build_id": "rules-test", "sections": {n: [] for n in s.SECTIONS}}
    raw = json.dumps(inline).encode()
    providers = {n: {"path": s.PROVIDERS[n][0], "behavior": s.PROVIDERS[n][1], "format": "mrs"}
                 for n in s.BASE + ["acl-unban-domain", "services-proxy"]}
    files = {p["path"]: {"size": 1, "sha256": hashlib.sha256(b"x").hexdigest()} for p in providers.values()}
    files["inline-rules.json"] = {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    m = {"schema_version": 1, "build_id": "rules-test", "tag": "rules-test", "fake_ip_pool": "198.18.0.0/16",
         "providers": providers, "files": files}
    return m, inline, raw

class SnapshotTests(unittest.TestCase):
    def test_regex_commas_and_no_resolve(self):
        rule = r"DOMAIN-REGEX,^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$"
        self.assertEqual(b.parse_rule(rule), ("inline", rule))
        m, inline, _ = fixture()
        inline["sections"]["private"] = [rule]
        inline["sections"]["personal_proxy"] = ["IP-CIDR,192.0.2.0/24,no-resolve"]
        doc = s.assemble({}, m, inline)
        self.assertIn(rule + ",DIRECT", doc["rules"])
        self.assertIn("IP-CIDR,192.0.2.0/24,节点选择,no-resolve", doc["rules"])
        self.assertLess(doc["rules"].index("RULE-SET,acl-unban-domain,DIRECT"),
                        doc["rules"].index("RULE-SET,reject,REJECT"))
        self.assertEqual({p["format"] for p in doc["rule-providers"].values()}, {"mrs"})

    def test_fake_ip_subtraction_and_personal_conflict(self):
        import ipaddress
        self.assertEqual([str(x) for x in b.subtract(ipaddress.ip_network("198.18.0.0/15"))], ["198.19.0.0/16"])
        self.assertEqual(b.subtract(ipaddress.ip_network("198.18.1.0/24")), [])
        other = ipaddress.ip_network("192.0.2.0/24")
        self.assertEqual([str(x) for x in b.subtract(ipaddress.ip_network("192.0.2.0/23"), other)], ["192.0.3.0/24"])
        builder = b.Builder("rules-test", "mihomo")
        with self.assertRaises(ValueError):
            builder.add("ipcidr", "198.18.0.0/16", "personal-direct-ipcidr", "test", personal=True)

    def test_domain_coverage_preserves_exact_semantics(self):
        result, covered = b.prune_domains(["example.com", "a.example.com", "example.com", "similar-example.com"])
        self.assertEqual(result, ["a.example.com", "example.com", "similar-example.com"])
        result, _ = b.prune_domains(["+.example.com", "example.com", "+.a.example.com", "otherexample.com"])
        self.assertEqual(result, ["+.example.com", "otherexample.com"])

    def test_schema_and_rule_injection(self):
        m, inline, _ = fixture()
        for key, value in (("tag", "../main"), ("fake_ip_pool", "192.0.2.0/24")):
            bad = copy.deepcopy(m); bad[key] = value
            with self.assertRaises(ValueError):
                s.validate_manifest(bad)
        inline["sections"]["proxy"] = ["DOMAIN-KEYWORD,abc,DIRECT"]
        with self.assertRaises(ValueError):
            s.validate_inline(m, inline)
        m["providers"]["google"]["path"] = "../credential.json"
        with self.assertRaises(ValueError):
            s.validate_manifest(m)

    def test_hash_failure_does_not_replace_active_snapshot(self):
        m, inline, raw = fixture()
        manifest = json.dumps(m).encode()
        candidate = json.dumps({"build_id": m["build_id"], "manifest_sha256": hashlib.sha256(manifest).hexdigest()}).encode()
        def fake_download(url, maximum, deadline):
            if url.endswith("candidate.json"): return candidate
            if url.endswith("build-manifest.json"): return manifest
            if url.endswith("inline-rules.json"): return raw
            return b"y"  # Wrong checksum, same length.
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            s.atomic(state / "active.json", {"build_id": "rules-old"})
            with patch.object(s, "load_active", return_value=({**m, "build_id": "rules-old"}, inline)), \
                    patch.object(s, "download", side_effect=fake_download), self.assertRaises(ValueError):
                s.refresh(state)
            self.assertEqual(s.read_json(state / "active.json"), {"build_id": "rules-old"})
            self.assertFalse((state / "rules-test").exists())

    def test_success_only_stages_until_enabled(self):
        m, inline, raw = fixture()
        manifest = json.dumps(m).encode()
        candidate = json.dumps({"build_id": m["build_id"], "manifest_sha256": hashlib.sha256(manifest).hexdigest()}).encode()
        def fake_download(url, maximum, deadline):
            if url.endswith("candidate.json"): return candidate
            if url.endswith("build-manifest.json"): return manifest
            if url.endswith("inline-rules.json"): return raw
            return b"x"
        with tempfile.TemporaryDirectory() as directory, patch.object(s, "download", side_effect=fake_download):
            state = Path(directory)
            self.assertEqual(s.refresh(state), "rules-test")
            self.assertFalse((state / "active.json").exists())
            (state / "activation.enabled").touch()
            s.refresh(state)
            self.assertEqual(s.load_active(state)[0]["build_id"], "rules-test")

    def test_network_failure_keeps_active(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            s.atomic(state / "active.json", {"build_id": "rules-old"})
            with patch.object(s, "download", side_effect=TimeoutError), self.assertRaises(TimeoutError):
                s.refresh(state)
            self.assertEqual(s.read_json(state / "active.json")["build_id"], "rules-old")

if __name__ == "__main__":
    unittest.main()
