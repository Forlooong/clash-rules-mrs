import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import zstandard

spec = importlib.util.spec_from_file_location("audit_sources", Path(__file__).resolve().parents[1] / "scripts/audit_sources.py")
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class AuditTests(unittest.TestCase):
    def test_suffix_exact_and_subdomain_only_remain_distinct(self):
        self.assertNotEqual(a.domain_tokens(["x.example"]), a.domain_tokens(["+.x.example"]))
        self.assertNotEqual(a.domain_tokens([".x.example"]), a.domain_tokens(["+.x.example"]))
        self.assertEqual(a.domain_tokens(["+.example", "x.example", "+.x.example"]), [".example", "example"])
        self.assertEqual(a.domain_tokens(["x.example", ".x.example"]), a.domain_tokens(["+.x.example"]))
        self.assertNotEqual(a.domain_tokens(["*.example"]), a.domain_tokens(["+.example"]))

    def test_ip_projection_compares_coverage_not_prefix_count(self):
        self.assertEqual(a.ip_intervals(["192.0.2.0/25", "192.0.2.128/25"]), a.ip_intervals(["192.0.2.0/24"]))
        self.assertNotEqual(a.ip_intervals(["192.0.2.0/24"]), a.ip_intervals(["192.0.2.0/25"]))

    def test_classical_literal_stars_are_retained_inline_without_domain_wildcard_reinterpretation(self):
        rules = [("DOMAIN-SUFFIX", "cdn*.i-scmp.com"), ("DOMAIN-SUFFIX", "*2.bahamut.com.tw"),
                 ("DOMAIN", "*.literal.example"), ("DOMAIN-SUFFIX", "*.suffix.example"),
                 ("DOMAIN", "exact.example"), ("DOMAIN-PATTERN", "*.pattern.example")]
        projection = a.project(rules)
        self.assertEqual(projection["domain"], a.fingerprint(a.domain_tokens(["exact.example", "*.pattern.example"])))
        self.assertEqual(projection["inline"], a.fingerprint(sorted(rules[:4])))
        self.assertEqual(projection["inline_count"], 4)
        self.assertEqual(projection["domain_generator_input_count"], 5)
        self.assertIsNone(a.domain_mrs_value("DOMAIN", "*.literal.example"))
        self.assertEqual(a.domain_mrs_value("DOMAIN-PATTERN", "*.pattern.example"), "*.pattern.example")
        with self.assertRaises(ValueError):
            a.parse_predicate("UNKNOWN-DOMAIN,cdn*.example")

    def test_classical_literal_star_has_explicit_preservation_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = a.Audit(Path(directory))
            audit.file("acl", "Clash/Ruleset/Star.list", b"DOMAIN-SUFFIX,cdn*.example\n", "100644")
            result = audit.finish({}, "fixture")
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["risk_counts"]["classical_domain_not_mrs_representable"], 1)
            self.assertEqual(result["domain_projection_version"], a.DOMAIN_PROJECTION_VERSION)
            with a.gzip.open(Path(directory) / "rules.jsonl.gz", "rt", encoding="utf-8") as stream:
                row = json.loads(stream.readline())
            self.assertEqual(row["value"], "cdn*.example")
            self.assertIn("preserved_not_representable", row["reason"])

    def test_yaml_line_numbers_regex_commas_and_unknown_type(self):
        data = b"# comment\npayload:\n  - DOMAIN,example.com\n  - 'DOMAIN-REGEX,^x{1,3}\\.example$'\n"
        rules = list(a.text_rules("acl", "Clash/Providers/sample.yaml", data))
        self.assertEqual(rules[0], (3, "DOMAIN", "example.com"))
        self.assertEqual(rules[1], (4, "DOMAIN-REGEX", r"^x{1,3}\.example$"))
        with self.assertRaises(ValueError):
            a.parse_predicate("NEW-RULE,value")
        self.assertEqual(a.parse_predicate("URL-REGEX,^https:"), ("URL-REGEX", "^https:"))

    def test_mihomo_ip_aliases_bare_cidr_and_empty_payload(self):
        self.assertEqual(a.parse_predicate("IP-CIDR,2001:db8::/32"), ("IP-CIDR6", "2001:db8::/32"))
        self.assertEqual(a.parse_predicate("192.0.2.0/24"), ("IP-CIDR", "192.0.2.0/24"))
        self.assertEqual(list(a.text_rules("acl", "Clash/empty.yaml", b"payload:\n # disabled\n")), [])

    def test_unknown_line_is_recorded_without_skipping_the_rest(self):
        errors = []
        rows = list(a.text_rules("acl", "Clash/test.list", b"NEW-RULE,test\nDOMAIN,example.com\n",
                                 on_error=lambda line, error: errors.append((line, str(error)))))
        self.assertEqual(rows, [(1, "UNPARSED", "NEW-RULE,test"), (2, "DOMAIN", "example.com")])
        self.assertEqual(errors[0][0], 1)

    def test_independent_same_name_difference_is_not_a_conversion_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = a.Audit(Path(directory))
            audit.file("acl", "Clash/Providers/Ruleset/A.yaml", b"payload:\n - DOMAIN,one.example\n", "100644")
            audit.file("acl", "Clash/Ruleset/A.list", b"DOMAIN,two.example\n", "100644")
            audit.verify_projections()
            result = audit.finish({}, "fixture")
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["independent_table_differences"], 1)

    def test_tree_hash_detects_missing_blob(self):
        entry = ("file", "100644", a.git_hash("blob", b"hello\n"))
        expected = a.git_hash("tree", b"100644 file\0" + bytes.fromhex(entry[2]))
        self.assertEqual(a.root_tree([entry]), expected)
        self.assertNotEqual(a.root_tree([entry, ("sub/next", "100644", entry[2])]), expected)
        with self.assertRaises(ValueError):
            a.root_tree([entry, entry])

    def test_keyword_only_acl_source_is_empty_projection_not_missing_source(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = a.Audit(Path(directory))
            audit.file("acl", "Clash/Ruleset/A.list", b"DOMAIN-KEYWORD,example\n", "100644")
            audit.by_file[("acl", "Clash/mrs/A_domain.mrs")] = {
                "classification": "mrs", "behavior": "domain", "sha256": "fixture",
                "fingerprint": a.fingerprint(a.domain_tokens(["domain-keyword,example"]))}
            audit.verify_projections()
            result = audit.finish({}, "fixture")
            self.assertEqual(result["projection_mismatches"], 1)
            self.assertEqual(audit.projections[0]["right"], "Clash/Ruleset/A.list")
            self.assertIn("projection differs", audit.errors[0]["error"])

    def test_truncated_mrs_and_unknown_versions_fail(self):
        for data in (b"MRS\x02", b"MRS\x01\x01" + struct.pack(">q", -1)):
            with self.assertRaises(ValueError):
                a.decode_mrs(zstandard.ZstdCompressor().compress(data))

    def test_projection_mismatch_blocks_even_unused_file(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = a.Audit(Path(directory))
            audit.file("meta", "geo/geosite/foo.list", b"+.example.com\n", "100644")
            audit.file("meta", "geo/geosite/foo.yaml", b"payload:\n - other.example\n", "100644")
            audit.verify_projections()
            result = audit.finish({}, "fixture")
            self.assertEqual(result["status"], "failed")
            self.assertGreater(result["projection_mismatches"], 0)

    def test_other_client_rules_are_explicit_not_silently_translated(self):
        rows = list(a.text_rules("acl", "Acl/test.acl", b"[bypass_all]\n[proxy_list]\n(^|\\.)example.com$\n"))
        self.assertEqual(rows[-1][1], "ACL-PREDICATE")
        with self.assertRaises(ValueError):
            list(a.text_rules("acl", "Acl/test.acl", b"[unknown]\nexample\n"))


class RepairOverlayTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repair_dir = self.root / "repairs"
        self.repair_dir.mkdir()
        self.sources = {"meta": {"repository": a.REPOS["meta"], "commit": "c" * 40}}
        self.mrs_path = "geo/geoip/example.mrs"
        self.text_path = "geo/geoip/example.list"
        self.original = b"broken original compressed MRS"
        self.text = b"192.0.2.0/24\n"
        self.fixed = self.ip_mrs("192.0.2.0/24")
        self.files = {self.mrs_path: self.original, self.text_path: self.text}
        self.row = {"source": "meta", "path": self.mrs_path, "original_sha256": a.sha(self.original),
                    "canonical_path": self.text_path, "canonical_sha256": a.sha(self.text),
                    "fixed_path": "fixed/meta/" + self.mrs_path, "fixed_sha256": a.sha(self.fixed),
                    "behavior": "ipcidr"}
        self.manifest = {"schema_version": 1, "status": "repaired", "sources": self.sources, "repairs": [self.row]}
        self.write_overlay()

    @staticmethod
    def ip_mrs(cidr):
        ranges = a.ip_intervals([cidr])
        pack = lambda value: struct.pack(">q", value)
        raw = b"MRS\x01\x01" + pack(1) + pack(0) + b"\x01" + pack(len(ranges))
        for family, first, last in ranges:
            for value in (first, last):
                raw += ((value | (0xffff << 32)) if family == 4 else value).to_bytes(16, "big")
        return zstandard.ZstdCompressor().compress(raw)

    def write_overlay(self):
        target = self.repair_dir / self.row["fixed_path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.fixed)
        (self.repair_dir / "manifest.json").write_text(json.dumps(self.manifest), encoding="utf-8")

    def archive(self):
        path = self.root / "source.tar.gz"
        entries = []
        with tarfile.open(path, "w:gz") as stream:
            for name, data in self.files.items():
                item = tarfile.TarInfo("upstream-root/" + name)
                item.size, item.mode = len(data), 0o644
                stream.addfile(item, io.BytesIO(data))
                entries.append((name, "100644", a.git_hash("blob", data)))
        return path, {**self.sources["meta"], "tree_sha": a.root_tree(entries), "archive_sha256": a.sha(path.read_bytes())}

    def run_audit(self, overlay=True, output="effective"):
        archive, meta = self.archive()
        repairs = a.RepairOverlay(self.repair_dir, self.sources) if overlay else None
        audit = a.Audit(self.root / output, repairs=repairs)
        verified = audit.archive("meta", archive, meta)
        audit.verify_projections()
        result = audit.finish({"meta": verified}, "fixture-core")
        return audit, result, meta

    def test_repair_proves_original_tree_and_effective_projection_separately(self):
        _, original, _ = self.run_audit(overlay=False, output="original")
        self.assertEqual(original["status"], "failed")
        original_report = (self.root / "original/manifest.json").read_bytes()
        overlay_bytes = (self.repair_dir / self.row["fixed_path"]).read_bytes()
        audit, result, meta = self.run_audit()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["evaluation_scope"], "upstream-with-verified-repairs")
        self.assertEqual(result["repair_overlay"]["verified"], 1)
        self.assertEqual(result["sources"]["meta"]["tree_sha_verified"], meta["tree_sha"])
        self.assertEqual(result["sources"]["meta"]["tree_verification_scope"], "original_upstream_archive")
        entry = audit.by_file[("meta", self.mrs_path)]
        self.assertEqual(entry["sha256"], entry["original_sha256"])
        self.assertEqual(entry["original_sha256"], a.sha(self.original))
        self.assertEqual(entry["effective_sha256"], a.sha(self.fixed))
        self.assertTrue(entry["repair"]["canonical_projection_verified"])
        self.assertEqual(audit.projections[0]["left_sha256"], a.sha(self.fixed))
        self.assertEqual(audit.projections[0]["left_original_sha256"], a.sha(self.original))
        self.assertEqual((self.root / "original/manifest.json").read_bytes(), original_report)
        self.assertEqual((self.repair_dir / self.row["fixed_path"]).read_bytes(), overlay_bytes)

    def test_valid_binary_with_wrong_semantics_still_fails_full_projection(self):
        self.fixed = self.ip_mrs("198.51.100.0/24")
        self.row["fixed_sha256"] = a.sha(self.fixed)
        self.write_overlay()
        audit, result, _ = self.run_audit()
        self.assertEqual(result["status"], "failed")
        self.assertGreater(result["projection_mismatches"], 0)
        self.assertEqual(result["repair_overlay"]["verified"], 0)
        self.assertTrue(any("still differs" in row["error"] for row in audit.errors))

    def test_meta_geo_lite_paths_are_registered_and_match_their_canonical_text(self):
        for path, behavior in (("geo-lite/geosite/proxymedia.mrs", "domain"),
                               ("geo-lite/geoip/cn.mrs", "ipcidr")):
            self.row.update(path=path, canonical_path=path[:-4] + ".list", behavior=behavior)
            self.write_overlay()
            overlay = a.RepairOverlay(self.repair_dir, self.sources)
            self.assertIn(("meta", path), overlay.entries)
            self.assertEqual(a.canonical_mrs_input("meta", path, behavior, {}), path[:-4] + ".list")
        with self.assertRaisesRegex(ValueError, "behavior differs"):
            a.canonical_mrs_input("meta", "geo-lite/geosite/proxymedia.mrs", "ipcidr", {})
        with self.assertRaisesRegex(ValueError, "registered derived"):
            a.canonical_mrs_input("meta", "geo-unregistered/geosite/proxymedia.mrs", "domain", {})

    def test_incomplete_or_failed_repair_manifest_is_rejected(self):
        for status in (None, "building", "failed", "passed"):
            if status is None:
                self.manifest.pop("status", None)
            else:
                self.manifest["status"] = status
            self.write_overlay()
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, "status=repaired"):
                a.RepairOverlay(self.repair_dir, self.sources)

    def test_missing_overlay_target_and_duplicate_registration_cannot_pass(self):
        self.row["path"] = "geo/geoip/absent.mrs"
        self.write_overlay()
        audit, result, _ = self.run_audit()
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("exactly one" in row["error"] for row in audit.errors))
        self.manifest["repairs"].append(dict(self.row))
        self.write_overlay()
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            a.RepairOverlay(self.repair_dir, self.sources)

    def test_text_and_unknown_files_are_never_repaired_or_ignored(self):
        self.row["path"] = self.text_path
        self.write_overlay()
        with self.assertRaisesRegex(ValueError, "Only pinned derived"):
            a.RepairOverlay(self.repair_dir, self.sources)
        self.row["path"] = self.mrs_path
        self.write_overlay()
        self.files["unknown.extension"] = b"not a registered artifact"
        _, result, _ = self.run_audit()
        self.assertEqual(result["status"], "failed")

    def test_corrupted_canonical_text_blocks_even_if_its_new_hash_is_registered(self):
        # Use ACL classical syntax so an unknown predicate is recorded and the
        # valid later line is still audited; overlay cannot waive the parse error.
        sources = {"acl": {"repository": a.REPOS["acl"], "commit": "d" * 40}}
        self.sources = sources
        self.text_path, self.mrs_path = "Clash/Ruleset/Example.list", "Clash/mrs/Example_ip.mrs"
        self.text = b"NEW-RULE,unknown\nIP-CIDR,192.0.2.0/24\n"
        self.files = {self.mrs_path: self.original, self.text_path: self.text}
        self.row.update(source="acl", path=self.mrs_path, canonical_path=self.text_path,
                        canonical_sha256=a.sha(self.text), fixed_path="fixed/acl/" + self.mrs_path)
        self.manifest["sources"] = sources
        self.write_overlay()
        entries = [(name, "100644", a.git_hash("blob", data)) for name, data in self.files.items()]
        meta = {**sources["acl"], "tree_sha": a.root_tree(entries)}
        archive = self.root / "acl.tar.gz"
        with tarfile.open(archive, "w:gz") as stream:
            for name, data in self.files.items():
                item = tarfile.TarInfo("root/" + name)
                item.size, item.mode = len(data), 0o644
                stream.addfile(item, io.BytesIO(data))
        audit = a.Audit(self.root / "effective", repairs=a.RepairOverlay(self.repair_dir, sources))
        verified = audit.archive("acl", archive, meta)
        audit.verify_projections()
        result = audit.finish({"acl": verified}, "fixture")
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("canonical text" in entry["error"] for entry in audit.errors))

    def test_all_hashes_and_source_pin_are_mandatory(self):
        self.row["fixed_sha256"] = "0" * 64
        self.write_overlay()
        with self.assertRaisesRegex(ValueError, "artifact hash"):
            a.RepairOverlay(self.repair_dir, self.sources)
        self.row["fixed_sha256"] = a.sha(self.fixed)
        self.row["canonical_sha256"] = "0" * 64
        self.write_overlay()
        _, result, _ = self.run_audit(output="bad-canonical")
        self.assertEqual(result["status"], "failed")
        self.row["canonical_sha256"] = a.sha(self.text)
        self.row["original_sha256"] = "0" * 64
        self.write_overlay()
        _, result, _ = self.run_audit(output="bad-original")
        self.assertEqual(result["status"], "failed")
        with self.assertRaisesRegex(ValueError, "source revision"):
            a.RepairOverlay(self.repair_dir, {"meta": {"repository": a.REPOS["meta"], "commit": "e" * 40}})

    def test_original_git_tree_mismatch_is_not_hidden_by_good_repair(self):
        archive, meta = self.archive()
        meta["tree_sha"] = "0" * 40
        audit = a.Audit(self.root / "effective", repairs=a.RepairOverlay(self.repair_dir, self.sources))
        with self.assertRaisesRegex(ValueError, "Git tree mismatch") as failure:
            audit.archive("meta", archive, meta)
        audit.error("meta", "", failure.exception)
        audit.verify_projections()
        result = audit.finish({}, "fixture")
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("fully visited" in row["error"] for row in audit.errors))

    def test_execution_hash_is_captured_before_finish_and_existing_reports_are_protected(self):
        audit = a.Audit(self.root / "original")
        captured = audit.auditor_sha256
        with patch.object(a, "AUDITOR_SHA256", "later-edit"):
            result = audit.finish({}, "fixture-core")
        self.assertEqual(result["auditor_sha256"], captured)
        self.assertEqual(result["core_version"], "fixture-core")
        sources_path = self.root / "sources.json"
        sources_path.write_text(json.dumps(self.sources), encoding="utf-8")
        before = (self.root / "original/manifest.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "fresh output"):
            a.main(["--sources", str(sources_path), "--mihomo", "unused",
                    "--output", str(self.root / "original"), "--repairs", str(self.repair_dir)])
        self.assertEqual((self.root / "original/manifest.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
