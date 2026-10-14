"""Meaningful boundary/uncertainty checks using real compressed MRS payloads."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

import zstandard

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("report_changes", ROOT / "scripts/report_changes.py")
changes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(changes)
from runtime import snapshot


def mrs(behavior, values):
    """Small MRS v1 fixtures with real header, LOUDS tree and Zstandard frame."""
    pack = lambda value: struct.pack(">q", value)
    body = b"MRS\x01" + bytes([0 if behavior == "domain" else 1]) + pack(len(values)) + pack(0) + b"\x01"
    if behavior == "ipcidr":
        intervals = changes.ip_intervals(values)
        body += pack(len(intervals))
        for family, first, last in intervals:
            for value in (first, last):
                if family == 4:
                    value |= 0xffff << 32
                body += value.to_bytes(16, "big")
    else:
        root = {}
        for value in values:
            expanded = [value[2:], value[1:]] if value.startswith("+.") else [value]
            for token in expanded:
                node = root
                for label in token[::-1].encode():
                    node = node.setdefault(label, {})
                node[None] = True
        nodes, labels, leaves, bitmap = [root], bytearray(), [], []
        for node in nodes:
            leaves.append(None in node)
            for label in sorted(key for key in node if key is not None):
                labels.append(label)
                nodes.append(node[label])
                bitmap.append(False)
            bitmap.append(True)

        def words(bits):
            output = [0] * max(1, (len(bits) + 63) // 64)
            for index, bit in enumerate(bits):
                if bit:
                    output[index // 64] |= 1 << (index % 64)
            return pack(len(output)) + b"".join(struct.pack(">Q", item) for item in output)

        body += words(leaves) + words(bitmap) + pack(len(labels)) + bytes(labels)
    return zstandard.ZstdCompressor().compress(body)


def fixture(version, tag):
    names = (snapshot.V2_REQUIRED if version == 2 else
             set(snapshot.BASE) | {"acl-unban-domain", "services-proxy"})
    registry = snapshot.V2_PROVIDERS if version == 2 else snapshot.PROVIDERS
    providers = {name: {"path": registry[name][0], "behavior": registry[name][1], "format": "mrs"}
                 for name in names}
    domains = {name: ["unused-" + name + ".invalid"] for name, p in providers.items() if p["behavior"] == "domain"}
    ips = {name: ["203.0.113.0/24"] for name, p in providers.items() if p["behavior"] == "ipcidr"}
    inline = {"schema_version": version, "build_id": tag,
              "sections": {s: [] for s in (snapshot.V2_SECTIONS if version == 2 else snapshot.SECTIONS)}}
    manifest = {"schema_version": version, "build_id": tag, "tag": tag,
                "fake_ip_pool": "198.18.0.0/16", "providers": providers}
    if version == 2:
        manifest.update(policy_version="balanced-v2", audit={"status": "passed", "manifest_sha256": "a" * 64})
    return manifest, inline, domains, ips


def save(folder, manifest, inline, domains, ips):
    files = {"inline-rules.json": json.dumps(inline).encode()}
    for name, provider in manifest["providers"].items():
        files[provider["path"]] = mrs(provider["behavior"], (domains if provider["behavior"] == "domain" else ips)[name])
    manifest["files"] = {name: {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in files.items()}
    for name, data in files.items():
        target = folder / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    (folder / "build-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


class ChangesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.old = fixture(1, "rules-rebuilt-v1")
        self.new = fixture(2, "rules-candidate-v2")

    def compare(self):
        save(self.folder, *self.old)
        return changes.compare_snapshots(self.folder, *self.new)

    def actions(self, report, row):
        return (report["rules"]["old"][row[1]]["policy"], report["rules"]["new"][row[2]]["policy"])

    def test_real_mrs_decode_and_suffix_child_boundary_expose_narrowing(self):
        self.old[2]["direct"] = ["+.example.test"]
        self.new[2]["cn-domain"] = ["example.test"]
        report = self.compare()
        rows = {row[0]: row for row in report["domain_witnesses"]["rows"]}
        self.assertEqual(self.actions(report, rows["example.test"]), ("DIRECT", "DIRECT"))
        child = rows["mrs-audit-boundary.example.test"]
        self.assertEqual(self.actions(report, child), ("DIRECT", changes.GROUP))
        self.assertTrue(child[3] and child[4])  # Earlier IP predicates need connection context.
        self.assertFalse(report["baseline"]["is_actual_online_version"])
        raw = (self.folder / "build-manifest.json").read_bytes()
        self.assertEqual(report["baseline"]["manifest_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(report["baseline"]["tag"], "rules-rebuilt-v1")
        self.assertIn("reject", report["providers"]["removed"])

    def test_subdomains_only_do_not_gain_the_apex(self):
        self.old[2]["direct"] = [".example.test"]
        self.new[2]["cn-domain"] = ["+.example.test"]
        report = self.compare()
        rows = {row[0]: row for row in report["domain_witnesses"]["rows"]}
        self.assertEqual(self.actions(report, rows["example.test"]), (changes.GROUP, "DIRECT"))
        self.assertEqual(self.actions(report, rows["mrs-audit-boundary.example.test"]), ("DIRECT", "DIRECT"))

    def test_inline_keyword_and_supported_regex_take_the_first_hostname_hit(self):
        self.old[2]["direct"] = ["+.cn.test", "api12.cn.test", "forceproxy.cn.test"]
        self.new[2]["cn-domain"] = ["+.cn.test"]
        self.new[1]["sections"]["personal_proxy"] = ["DOMAIN-KEYWORD,forceproxy"]
        self.new[1]["sections"]["services"] = [r"DOMAIN-REGEX,^API[0-9]+\.CN\.TEST$"]
        report = self.compare()
        rows = {row[0]: row for row in report["domain_witnesses"]["rows"]}
        for host in ("api12.cn.test", "forceproxy.cn.test"):
            self.assertEqual(self.actions(report, rows[host]), ("DIRECT", changes.GROUP))
        selected = report["rules"]["new"][rows["api12.cn.test"][2]]
        self.assertEqual(selected["type"], "DOMAIN-REGEX")

    def test_complex_regex_and_removed_process_advertising_are_explicit(self):
        self.old[1]["sections"]["applications"] = ["PROCESS-NAME,example.exe"]
        self.new[1]["sections"]["personal_proxy"] = [r"DOMAIN-REGEX,^(?=api)api\.test$"]
        report = self.compare()
        self.assertEqual(report["rules"]["removed_process_routes"][0]["value"], "example.exe")
        self.assertTrue(report["rules"]["removed_advertising_routes"])
        self.assertTrue(any("Complex regex" in item["reason"] and item["can_preempt_witness"]
                            for item in report["uncertainties"]["new"]))
        self.assertFalse(report["gate"]["change_count_requires_approval"])

    def test_unknown_types_and_missing_compiled_indices_block_the_report(self):
        self.new[1]["sections"]["personal_direct"] = ["FUTURE-RULE,value"]
        with self.assertRaisesRegex(ValueError, "Unknown"):
            self.compare()
        self.new[1]["sections"]["personal_direct"] = []
        self.new[2].pop("cn-domain")
        with self.assertRaisesRegex(ValueError, "complete comparison index"):
            self.compare()

    def test_unapproved_upstream_process_rule_is_a_concrete_v2_gate(self):
        self.new[1]["sections"]["direct"] = ["PROCESS-NAME,browser.exe"]
        with self.assertRaisesRegex(ValueError, "Unapproved upstream"):
            self.compare()

    def test_personal_connection_predicates_remain_supported_and_uncertain(self):
        self.new[1]["sections"]["personal_direct"] = ["PROCESS-NAME,personal.exe", "DST-PORT,443", "NETWORK,tcp"]
        report = self.compare()
        indices = {r["index"] for r in report["rules"]["new"] if r["section"] == "personal_direct"}
        uncertainties = {r["rule_index"] for r in report["uncertainties"]["new"] if r["can_preempt_witness"]}
        self.assertTrue(indices <= uncertainties)
        self.assertEqual(len(indices), 3)

    def test_long_domain_still_gets_a_valid_short_child_boundary(self):
        host = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 59])
        self.assertEqual(len(host), 251)
        self.old[2]["direct"] = ["+." + host]
        self.new[2]["cn-domain"] = [host]
        report = self.compare()
        rows = {row[0]: row for row in report["domain_witnesses"]["rows"]}
        self.assertEqual(self.actions(report, rows["a." + host]), ("DIRECT", changes.GROUP))

    def test_ip_range_difference_is_by_address_coverage_not_prefix_count(self):
        self.old[3]["cncidr"] = ["192.0.2.0/24"]
        self.new[3]["cn-ipcidr"] = ["192.0.2.128/25"]
        report = self.compare()
        removed = report["ip_coverage"]["policies"]["DIRECT"]["removed"]
        self.assertEqual(removed["intervals"], [[4, "192.0.2.0", "192.0.2.127"]])
        self.assertEqual(removed["address_count"], "128")

    def test_baseline_corruption_blocks_real_decoder_input(self):
        save(self.folder, *self.old)
        target = self.folder / self.old[0]["providers"]["direct"]["path"]
        target.write_bytes(target.read_bytes() + b"corrupt")
        with self.assertRaisesRegex(ValueError, "hash/size"):
            changes.compare_snapshots(self.folder, *self.new)

    def test_both_ordered_chains_match_production_assembler(self):
        for fixture_data in (self.old, self.new):
            manifest, inline, domains, ips = fixture_data
            save(self.folder, *fixture_data)
            actual = changes._chain(manifest, inline)
            self.assertEqual([r["rule"] for r in actual], snapshot.assemble({}, manifest, inline)["rules"])


if __name__ == "__main__":
    unittest.main()
