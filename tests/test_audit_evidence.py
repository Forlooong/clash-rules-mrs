import copy
import io
import json
from pathlib import Path
import shutil
import struct
import sys
import tarfile
import tempfile
import unittest

import zstandard

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import audit_sources as audit
from verify_audit_evidence import verify_source_audit

CORE = "Mihomo Meta v1.19.32 test core"


class AuditEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output, self.cache = self.root / "audit", self.root / "cache"
        self.cache.mkdir()
        self.sources = {name: {"repository": repository, "commit": "a" * 40}
                        for name, repository in audit.REPOS.items()}
        self.canonical = "geo/geoip/test.list"
        self.binary = "geo/geoip/test.mrs"
        self.text = b"192.0.2.0/24\n"
        self.blobs = {"loyal": {"direct.txt": b"payload:\n - example.com\n"},
                      "acl": {"README.md": b"upstream metadata\n"}, "meta": {}}
        self.blobs["meta"].update({self.canonical: self.text, self.binary: b"broken original"})
        self.archives = {}
        for name, blobs in self.blobs.items():
            path = self.cache / (name + "-" + self.sources[name]["commit"] + ".tar.gz")
            entries = []
            with tarfile.open(path, "w:gz") as stream:
                for relative, content in blobs.items():
                    member = tarfile.TarInfo("upstream/" + relative)
                    member.size, member.mode = len(content), 0o644
                    stream.addfile(member, io.BytesIO(content))
                    entries.append((relative, "100644", audit.git_hash("blob", content)))
            self.archives[name] = path, {**self.sources[name], "tree_sha": audit.root_tree(entries),
                "archive_sha256": audit.sha(path.read_bytes()), "archive_bytes": path.stat().st_size}
        self.run_audit(self.output / "original")
        self.repairs = self.output / "repairs"
        self.repairs.mkdir()
        interval = audit.ip_intervals(["192.0.2.0/24"])[0]
        pack = lambda value: struct.pack(">q", value)
        body = b"MRS\x01\x01" + pack(1) + pack(0) + b"\x01" + pack(1)
        for value in interval[1:]:
            body += (value | (0xffff << 32)).to_bytes(16, "big")
        fixed = zstandard.ZstdCompressor().compress(body)
        expected = audit.fingerprint([interval])
        self.row = {"source": "meta", "path": self.binary, "original_sha256": audit.sha(b"broken original"),
                    "canonical_path": self.canonical, "canonical_sha256": audit.sha(self.text),
                    "fixed_path": "fixed/meta/" + self.binary, "fixed_sha256": audit.sha(fixed),
                    "behavior": "ipcidr", "retained_classical_path": "canonical/meta/" + self.canonical,
                    "retained_inline_count": 0, "expected_fingerprint": expected,
                    "core_decode_fingerprint": expected, "roundtrip_fingerprint": expected}
        for relative, content in ((self.row["fixed_path"], fixed), (self.row["retained_classical_path"], self.text)):
            path = self.repairs / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        original = self.output / "original"
        self.repair_manifest = {"schema_version": 1, "status": "repaired", "sources": self.sources,
            "repairs": [self.row], "full_audit_status": "failed",
            "original_audit_manifest_sha256": audit.sha((original / "manifest.json").read_bytes()),
            "original_errors_sha256": audit.sha((original / "errors.json").read_bytes())}
        self.write_json(self.repairs / "manifest.json", self.repair_manifest)
        self.run_audit(self.output, audit.RepairOverlay(self.repairs, self.sources))

    @staticmethod
    def write_json(path, value):
        path.write_text(json.dumps(value), encoding="utf-8")

    def run_audit(self, output, overlay=None):
        instance = audit.Audit(output, repairs=overlay)
        sources = {name: instance.archive(name, path, metadata)
                   for name, (path, metadata) in self.archives.items()}
        instance.verify_projections()
        return instance.finish(sources, CORE)

    def verify(self, **kwargs):
        return verify_source_audit(self.output, self.sources, archive_dir=self.cache, **kwargs)

    def mutate_json(self, relative, mutate):
        path = self.output / relative
        document = json.loads(path.read_bytes())
        mutate(document)
        self.write_json(path, document)

    def test_complete_repair_evidence_is_read_only_and_publishable_from_archives(self):
        before = {p.relative_to(self.output): audit.sha(p.read_bytes())
                  for p in self.output.rglob("*") if p.is_file()}
        result = self.verify()
        self.assertEqual(result["repair_overlay"]["verified"], 1)
        self.assertEqual(before, {p.relative_to(self.output): audit.sha(p.read_bytes())
                                 for p in self.output.rglob("*") if p.is_file()})
        with self.assertRaisesRegex(ValueError, "Missing"):
            verify_source_audit(self.output, self.sources)
        shutil.copytree(self.cache, self.output / "upstream")
        self.assertEqual(verify_source_audit(self.output, self.sources)["status"], "passed")

    def test_changed_or_missing_fixed_file_cannot_receive_fresh_artifact_hash(self):
        target = self.repairs / self.row["fixed_path"]
        target.write_bytes(b"changed after successful audit")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.verify()
        target.unlink()
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.verify()

    def test_external_repair_directory_is_not_accepted(self):
        self.repairs.rename(self.root / "external-repairs")
        with self.assertRaisesRegex(ValueError, "Missing"):
            self.verify()

    def test_changed_manifest_cannot_rebind_fixed_hash(self):
        self.repair_manifest["unreviewed_change"] = True
        self.write_json(self.repairs / "manifest.json", self.repair_manifest)
        with self.assertRaisesRegex(ValueError, "manifest differs"):
            self.verify()

    def test_retained_classical_bytes_must_match_original_text(self):
        (self.repairs / self.row["retained_classical_path"]).write_bytes(b"198.51.100.0/24\n")
        with self.assertRaisesRegex(ValueError, "canonical text changed"):
            self.verify()

    def test_untouched_original_audit_remains_bound(self):
        (self.output / "original/errors.json").write_text("[]", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "untouched original"):
            self.verify()

    def test_source_archive_corruption_and_selected_input_mismatch_block(self):
        changed = copy.deepcopy(self.sources)
        changed["meta"]["files"] = {self.canonical: {"size": len(self.text), "sha256": "b" * 64}}
        with self.assertRaisesRegex(ValueError, "Selected input differs"):
            verify_source_audit(self.output, changed, archive_dir=self.cache)
        self.archives["loyal"][0].write_bytes(b"archive changed after audit")
        with self.assertRaisesRegex(ValueError, "archive changed"):
            self.verify()

    def test_failed_effective_summary_or_projection_never_passes(self):
        self.mutate_json("summary.json", lambda doc: doc.update(status="failed"))
        with self.assertRaisesRegex(ValueError, "failed effective"):
            self.verify()
        self.mutate_json("summary.json", lambda doc: doc.update(status="passed"))
        self.mutate_json("projection-report.json", lambda rows: rows[0].update(equal=False))
        with self.assertRaisesRegex(ValueError, "projection gate"):
            self.verify()

    def test_every_registered_repair_must_be_verified_once(self):
        for relative in ("manifest.json", "summary.json"):
            self.mutate_json(relative, lambda doc: doc["repair_overlay"].update(verified=0))
        with self.assertRaisesRegex(ValueError, "completed effective"):
            self.verify()

    def test_unregistered_fixed_artifact_blocks(self):
        (self.repairs / "fixed/extra.mrs").write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "unregistered fixed"):
            self.verify()

    def test_passed_original_scope_needs_no_repairs(self):
        self.blobs["meta"].pop(self.binary)
        # Use a separate three-source original audit with metadata only; archive
        # hash/tree evidence is still mandatory even without a repair overlay.
        for name in self.archives:
            path, metadata = self.archives[name]
            if name == "meta":
                with tarfile.open(path, "w:gz") as stream:
                    content = self.text
                    member = tarfile.TarInfo("upstream/" + self.canonical)
                    member.size, member.mode = len(content), 0o644
                    stream.addfile(member, io.BytesIO(content))
                metadata.update(tree_sha=audit.root_tree([(self.canonical, "100644", audit.git_hash("blob", content))]),
                                archive_sha256=audit.sha(path.read_bytes()), archive_bytes=path.stat().st_size)
        plain = self.root / "plain"
        self.assertEqual(self.run_audit(plain)["status"], "passed")
        self.assertEqual(verify_source_audit(plain, self.sources, archive_dir=self.cache)["status"], "passed")


if __name__ == "__main__":
    unittest.main()
