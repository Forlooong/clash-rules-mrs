import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from build_balanced import BalancedBuilder
from publish_snapshot import verify_audit
from runtime import snapshot


class BalancedTests(unittest.TestCase):
    def test_shared_roots_and_tlds_are_excluded_but_business_subdomains_remain(self):
        b = BalancedBuilder("rules-test", "unused", ROOT / "balanced-out")
        for value in ("+.amazonaws.cn", "+.cloudfront.cn", "+.cn", "+.baidu", "time.amazonaws.cn", "+.tenant.cloudfront.cn"):
            b.add("domain", value, "cn-domain", "fixture")
        self.assertEqual(b.domains["cn-domain"], ["time.amazonaws.cn", "+.tenant.cloudfront.cn"])
        self.assertEqual(len(b.exclusions), 4)
        b.add("domain", "+.amazonaws.cn", "personal-direct-domain", "personal/direct", personal=True)
        self.assertEqual(b.domains["personal-direct-domain"], ["+.amazonaws.cn"])

    @patch("publish_snapshot.verify_source_audit")
    def test_complete_audit_artifacts_are_bound_not_just_input_inventory(self, verify_source):
        sources = {name: {"commit": "a" * 40} for name in ("loyal", "acl", "meta")}
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            report = directory / "selected-exclusions.json"
            report.write_bytes(b"[]")
            proof = {"status": "passed", "sources": sources,
                     "files": {report.name: {"size": 2, "sha256": hashlib.sha256(b"[]").hexdigest()}}}
            raw = json.dumps(proof).encode()
            (directory / "artifact-manifest.json").write_bytes(raw)
            manifest = {"sources": sources, "audit": {"manifest_sha256": hashlib.sha256(raw).hexdigest()}}
            verify_audit(directory, manifest)
            verify_source.assert_called_once_with(directory.resolve(), sources)
            report.write_bytes(b"{}")
            with self.assertRaisesRegex(ValueError, "changed"):
                verify_audit(directory, manifest)
            report.write_bytes(b"[]")
            (directory / "unbound-source.tar.gz").write_bytes(b"extra")
            with self.assertRaisesRegex(ValueError, "inventory"):
                verify_audit(directory, manifest)

    def test_failed_full_audit_is_not_a_publishable_runtime_snapshot(self):
        providers = {name: {"path": snapshot.V2_PROVIDERS[name][0], "behavior": snapshot.V2_PROVIDERS[name][1], "format": "mrs"}
                     for name in snapshot.V2_REQUIRED}
        files = {p["path"]: {"size": 1, "sha256": "a" * 64} for p in providers.values()}
        files["inline-rules.json"] = {"size": 1, "sha256": "a" * 64}
        manifest = {"schema_version": 2, "policy_version": "balanced-v2", "build_id": "rules-test", "tag": "rules-test",
                    "fake_ip_pool": "198.18.0.0/16", "providers": providers, "files": files,
                    "audit": {"status": "failed", "manifest_sha256": "a" * 64}}
        with self.assertRaisesRegex(ValueError, "audit"):
            snapshot.validate_manifest(manifest)
        manifest["audit"]["status"] = "passed"
        inline = {"schema_version": 2, "build_id": "rules-test", "sections": {n: [] for n in snapshot.V2_SECTIONS}}
        original = {"tun": {"enable": True}, "dns": {"fake-ip-range": "198.18.0.0/16", "nameserver": ["system"]}}
        doc = snapshot.assemble(copy.deepcopy(original), manifest, inline)
        self.assertEqual(doc["tun"], original["tun"])
        self.assertEqual(doc["dns"], original["dns"])
        self.assertIn("RULE-SET,cn-ipcidr,DIRECT", doc["rules"])
        self.assertNotIn("RULE-SET,cn-ipcidr,DIRECT,no-resolve", doc["rules"])
        self.assertFalse(any("REJECT" in r for r in doc["rules"]))


if __name__ == "__main__":
    unittest.main()
