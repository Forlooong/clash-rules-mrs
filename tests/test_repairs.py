import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("repair_sources", SCRIPTS / "repair_sources.py")
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class RepairTests(unittest.TestCase):
    def write_original_fixture(self, directory):
        files = [
            {"source": "loyal", "path": "direct.txt", "sha256": "1" * 64, "classification": "rules"},
            {"source": "meta", "path": "geo/geosite/a.list", "sha256": "2" * 64, "classification": "rules"},
            {"source": "acl", "path": "Clash/Ruleset/A.list", "sha256": "3" * 64,
             "classification": "rules", "projection": {"domain_generator_input_count": 1}},
            {"source": "acl", "path": "Clash/mrs/A_domain.mrs", "sha256": "4" * 64, "classification": "mrs"},
        ] + [{"source": "acl", "path": p, "sha256": h, "classification": "non_rule_metadata_or_tool"}
             for p, h in r.ACL_GENERATORS.items()]
        sources = {name: {"repository": repo, "commit": "a" * 40, "tree_sha": "b" * 40,
                          "tree_sha_verified": "b" * 40, "files": sum(x["source"] == name for x in files)}
                   for name, repo in r.audit.REPOS.items()}
        manifest = {"status": "failed", "sources": sources, "files": files}
        summary = {"status": "failed", "sources": sources, "files": len(files), "errors": 1}
        errors = [{"source": "acl", "path": "Clash/mrs/A_domain.mrs", "sha256": "4" * 64,
                   "error": "domain projection differs from Clash/Ruleset/A.list"}]
        comparisons = [{"source": "acl", "left": "Clash/mrs/A_domain.mrs", "right": "Clash/Ruleset/A.list",
                        "projection": "domain", "relation": "binary_representable_projection",
                        "left_sha256": "4" * 64, "right_sha256": "3" * 64, "required_equal": True, "equal": False}]
        for name, data in (("manifest.json", manifest), ("summary.json", summary),
                           ("errors.json", errors), ("projection-report.json", comparisons)):
            r.audit.write_json(Path(directory) / name, data)
        return sources

    def test_domain_dsl_is_projected_and_keyword_regex_preserved(self):
        raw = (b"DOMAIN,one.example\nDOMAIN-SUFFIX,two.example\n"
               b"DOMAIN-KEYWORD,brand\nDOMAIN-REGEX,^a{1,3}\\.example$\n"
               b"IP-CIDR,192.0.2.0/24,no-resolve\n")
        values, inline = r.domain_projection("acl", "Clash/Ruleset/A.list", raw)
        self.assertEqual(values, ["+.two.example", "one.example"])
        self.assertEqual([row["type"] for row in inline], ["DOMAIN-KEYWORD", "DOMAIN-REGEX"])
        self.assertFalse(any("," in value for value in values))

    def test_keyword_only_has_empty_domain_projection(self):
        values, inline = r.domain_projection("acl", "Clash/Ruleset/Whatsapp.list", b"DOMAIN-KEYWORD,whatsapp\n")
        self.assertEqual(values, [])
        self.assertEqual(inline[0]["value"], "whatsapp")

    def test_classical_asterisks_stay_inline_instead_of_changing_semantics(self):
        values, inline = r.domain_projection("acl", "Clash/Ruleset/A.list",
                                            b"DOMAIN-SUFFIX,cdn*.example\nDOMAIN,*.exact.example\nDOMAIN-SUFFIX,normal.example\n")
        self.assertEqual(values, ["+.normal.example"])
        self.assertEqual(len(inline), 2)

    def test_unknown_rule_cannot_be_repaired_away(self):
        with self.assertRaisesRegex(ValueError, "Unknown classical"):
            r.domain_projection("acl", "Clash/Ruleset/A.list", b"NEW-RULE,thing\n")

    def test_canonical_is_actual_last_generator_writer_even_keyword_only(self):
        inventory = {
            ("acl", "Clash/Providers/A.yaml"): {"projection": {"domain_generator_input_count": 4}},
            ("acl", "Clash/Providers/Ruleset/A.yaml"): {"projection": {"domain_generator_input_count": 3}},
            ("acl", "Clash/Ruleset/A.list"): {"projection": {"domain_generator_input_count": 1}},
        }
        self.assertEqual(r.canonical_acl("Clash/mrs/A_domain.mrs", inventory), "Clash/Ruleset/A.list")

    def test_arbitrary_binary_difference_is_not_a_known_conversion_bug(self):
        with patch.object(r.audit, "decode_mrs", return_value={"behavior": "domain", "domains": ["wrong.example"], "fingerprint": "bad"}):
            with self.assertRaisesRegex(ValueError, "confirmed literal"):
                r.validate_broken_domain(b"fixture", "expected")
        with patch.object(r.audit, "decode_mrs", return_value={"behavior": "domain", "domains": ["domain-suffix,example"], "fingerprint": "bad"}):
            result = r.validate_broken_domain(b"fixture", "expected")
            self.assertEqual(result["original_decoded_count"], 1)

    def test_identical_projection_is_not_rewritten(self):
        with patch.object(r.audit, "decode_mrs", return_value={"behavior": "domain", "domains": ["domain,example"], "fingerprint": "same"}):
            with self.assertRaises(ValueError):
                r.validate_broken_domain(b"fixture", "same")

    def test_new_snapshot_with_reviewed_generator_and_same_defect_is_pinned_per_run(self):
        with tempfile.TemporaryDirectory() as directory:
            sources = self.write_original_fixture(directory)
            _, _, requests = r.validated_requests(directory, sources)
            self.assertEqual(len(requests), 1)
            self.assertEqual(requests[0]["canonical_path"], "Clash/Ruleset/A.list")

    def test_changed_generator_is_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            sources = self.write_original_fixture(directory)
            path = Path(directory) / "manifest.json"
            manifest = r.read_json(path)
            manifest["files"][-1]["sha256"] = "9" * 64
            r.audit.write_json(path, manifest)
            with self.assertRaisesRegex(ValueError, "generator/source mapping changed"):
                r.validated_requests(directory, sources)

    def test_tampered_original_error_hash_is_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            sources = self.write_original_fixture(directory)
            path = Path(directory) / "errors.json"
            errors = r.read_json(path)
            errors[0]["sha256"] = "9" * 64
            r.audit.write_json(path, errors)
            with self.assertRaisesRegex(ValueError, "original MRS inventory"):
                r.validated_requests(directory, sources)

    def test_unknown_failure_reason_is_not_repaired(self):
        with tempfile.TemporaryDirectory() as directory:
            sources = self.write_original_fixture(directory)
            path = Path(directory) / "errors.json"
            errors = r.read_json(path)
            errors[0]["error"] = "an unreviewed new conversion fault"
            r.audit.write_json(path, errors)
            with self.assertRaisesRegex(ValueError, "Unknown ACL conversion failure"):
                r.validated_requests(directory, sources)


if __name__ == "__main__":
    unittest.main()
