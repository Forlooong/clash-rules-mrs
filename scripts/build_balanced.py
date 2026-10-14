#!/usr/bin/env python3
"""Build the opt-in balanced v2 channel; a complete-source audit is a release gate."""
import argparse
import hashlib
import gzip
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import time

import yaml

from four_sources import Builder, ROOT, POOL, REPOS, conflicts, get, prune_domains, write_json
from runtime.snapshot import V2_PROVIDERS, V2_REQUIRED, V2_SECTIONS, assemble, validate_manifest, verify

SERVICES = ("google", "youtube", "telegram", "netflix", "github", "openai")


def digest(path):
    data = Path(path).read_bytes()
    return {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class BalancedBuilder(Builder):
    def __init__(self, build_id, mihomo, output, sources=None, baseline=None):
        super().__init__(build_id, mihomo)
        self.out = Path(output).resolve()
        self.inline = {s: [] for s in V2_SECTIONS}
        self.fixed_sources = sources
        self.baseline = Path(baseline) if baseline else ROOT / "out"
        self.exclusions = []
        self.shared = json.loads((ROOT / "scripts/shared-platform-roots.json").read_text(encoding="utf-8"))

    def pin(self):
        if self.fixed_sources:
            self.sources = json.loads(Path(self.fixed_sources).read_text(encoding="utf-8"))
            for name, (repo, ref) in REPOS.items():
                info = self.sources[name]
                if info["repository"] != repo or info["ref"] != ref:
                    raise ValueError("Source repository/ref mismatch: " + name)
                if len(info["commit"]) != 40 or any(c not in "0123456789abcdef" for c in info["commit"]):
                    raise ValueError("Unpinned source: " + name)
            self.sources["personal"] = {"repository": "Forlooong/clash-rules-mrs", "commit":
                subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(), "files": {}}
        else:
            super().pin()

    def fetch(self, source, path):
        recorded = self.sources[source].get("files", {}).get(path)
        cached = self.raw / source / path
        if recorded and cached.exists() and digest(cached)["sha256"] == recorded["sha256"]:
            return cached.read_text(encoding="utf-8-sig")
        return super().fetch(source, path)

    def add(self, kind, value, target, source, original=None, personal=False, policy=None, rank=None):
        if not personal and kind == "domain" and value.startswith("+."):
            root = value[2:]
            if "." not in root and target != "private-domain":
                self.exclusions.append({"rule": value, "source": source, "target": target,
                                        "reason": "No automatic top-level suffix routing, including brand TLDs; use explicit business domains or IP fallback"})
                self.stats[source]["input"] += 1
                self.stats[source]["excluded_top_level"] += 1
                return
            if root in self.shared["roots"]:
                self.exclusions.append({"rule": value, "source": source, "target": target,
                                        "reason": self.shared["reason"]})
                self.stats[source]["input"] += 1
                self.stats[source]["excluded_shared_platform"] += 1
                return
        if target.startswith("personal-direct") or target == "personal_direct":
            policy, rank = "DIRECT", 2
        elif target.startswith("personal-proxy") or target == "personal_proxy":
            policy, rank = "节点选择", 3
        elif target.startswith("private"):
            policy, rank = "DIRECT", 4
        elif target == "telegram-ipcidr":
            policy, rank = "节点选择", 6
        elif target.startswith("cn-") or target == "direct":
            policy, rank = "DIRECT", 7 if kind != "ipcidr" else 8
        else:
            policy, rank = "节点选择", 5
        super().add(kind, value, target, source, original, personal, policy, rank)

    def collect(self):
        self.pin()
        for name, target, inline in [("private", "private-domain", "private"),
                                     ("geolocation-cn", "cn-domain", "direct")]:
            self.classical(self.fetch("meta", "geo/geosite/classical/" + name + ".list"),
                           "meta/geosite/" + name, target, inline)
        for name in SERVICES:
            self.classical(self.fetch("meta", "geo/geosite/classical/" + name + ".list"),
                           "meta/geosite/" + name, "services-proxy", "services")
        for name in ("private", "cn", "telegram"):
            for raw in self.fetch("meta", "geo/geoip/" + name + ".list").splitlines():
                if raw.strip() and not raw.startswith("#"):
                    self.add("ipcidr", raw.strip(), name + "-ipcidr", "meta/geoip/" + name)
        for direction in ("direct", "proxy"):
            path = ROOT / "personal" / (direction + ".yaml")
            self.sources["personal"]["files"][path.relative_to(ROOT).as_posix()] = digest(path)
            self.classical(path.read_text(encoding="utf-8"), "personal/" + direction,
                           "personal-" + direction + "-domain", "personal_" + direction,
                           "personal-" + direction + "-ipcidr", personal=True)
        # The runtime carries only inputs actually consumed; complete upstream inventories
        # and every excluded rule live in the separate audit attachment.
        self.out.mkdir(parents=True, exist_ok=True)
        write_json(self.out / "sources.json", self.sources)

    def emit(self, audit_dir):
        from runtime.dns import assemble_dns, dns_limitations
        from audit_sources import decode_mrs, domain_tokens, fingerprint, ip_intervals
        from report_changes import compare_snapshots
        from verify_audit_evidence import verify_source_audit
        audit_dir = Path(audit_dir).resolve()
        audit = verify_source_audit(audit_dir, self.sources, archive_dir=ROOT / ".cache/audit")
        audit_raw = (audit_dir / "manifest.json").read_bytes()
        if json.loads(audit_raw) != audit:
            raise ValueError("Source audit changed during build verification")
        if audit.get("status") != "passed":
            raise ValueError("Full upstream audit has not passed")
        for source in REPOS:
            if audit["sources"][source]["commit"] != self.sources[source]["commit"]:
                raise ValueError("Audit belongs to another source revision: " + source)
        providers, coverage, domain_index, ip_index = {}, {}, {}, {}
        for name in sorted(set(self.domains) | set(self.ips)):
            behavior = V2_PROVIDERS[name][1]
            original = self.domains[name] if behavior == "domain" else self.ips[name]
            if behavior == "domain":
                values, covered = prune_domains(original)
            else:
                values, covered = [], []
                for version in (4, 6):
                    nets = [ipaddress.ip_network(x) for x in original if ipaddress.ip_network(x).version == version]
                    values.extend(str(n) for n in ipaddress.collapse_addresses(nets))
            coverage[name] = {"input": len(original), "exact_duplicates": len(original) - len(set(original)),
                              "covered_domains": len(covered), "output": len(values)}
            if not values:
                continue
            if behavior == "domain":
                domain_index[name] = values
            else:
                ip_index[name] = values
            rel = V2_PROVIDERS[name][0]
            output = self.out / rel
            output.parent.mkdir(parents=True, exist_ok=True)
            temp = self.raw / ("convert-v2-" + name + ".yaml")
            temp.write_text(yaml.safe_dump({"payload": values}), encoding="utf-8")
            subprocess.run([self.mihomo, "convert-ruleset", behavior, "yaml", str(temp), str(output)], check=True)
            decoded = decode_mrs(output.read_bytes())
            projection = domain_tokens(values) if behavior == "domain" else ip_intervals(values)
            if decoded["behavior"] != behavior or decoded["fingerprint"] != fingerprint(projection):
                raise ValueError("Compiled MRS changed the selected rule semantics: " + name)
            providers[name] = {"path": rel, "behavior": behavior, "format": "mrs"}
        if not V2_REQUIRED <= set(providers):
            raise ValueError("A required v2 collection is empty")
        inline = {"schema_version": 2, "build_id": self.build_id,
                  "domain_index": domain_index,
                  "sections": {s: list(dict.fromkeys(v)) for s, v in self.inline.items()}}
        write_json(self.out / "inline-rules.json", inline)
        limitations = dns_limitations(inline) + [
            {"provider": n, "reason": "Personal IP routing has no domain predicate; DNS follows the domain policy, not this IP exception"}
            for n in providers if n.startswith("personal-") and n.endswith("-ipcidr")]
        build_report = {"sources": self.stats, "providers": coverage,
                    "shared_platform_exclusions": len(self.exclusions),
                    "audit_scope": audit.get("evaluation_scope", "original"),
                    "repair_overlay": audit.get("repair_overlay"),
                    "dns_limitations": limitations}
        shutil.copy2(ROOT / "NOTICE.md", self.out / "NOTICE.md")
        # Detailed provenance/conflicts are never downloaded by subscription consumers.
        write_json(audit_dir / "selected-rules.json", self.records)
        write_json(audit_dir / "selected-conflicts.json", conflicts(self.records))
        write_json(audit_dir / "selected-cidr-transformations.json", self.cidrs)
        write_json(audit_dir / "selected-exclusions.json", self.exclusions)
        change_report = compare_snapshots(self.baseline,
            {"schema_version": 2, "policy_version": "balanced-v2", "build_id": self.build_id, "providers": providers},
            inline, domain_index, ip_index)
        with gzip.open(audit_dir / "routing-changes.json.gz", "wt", encoding="utf-8") as stream:
            json.dump(change_report, stream, ensure_ascii=False, separators=(",", ":"))
        build_report["migration_comparison"] = {"baseline": change_report["baseline"],
            **{k: v for k, v in change_report["domain_witnesses"].items() if k not in {"rows", "columns"}}}
        notice_dir = audit_dir / "licenses"
        notice_dir.mkdir(exist_ok=True)
        for source, (repo, _) in REPOS.items():
            if source == "acl":
                (notice_dir / "acl-README.md").write_text(self.fetch(source, "README.md"), encoding="utf-8")
                (notice_dir / "acl-LICENSE").write_bytes(get("https://creativecommons.org/licenses/by-sa/4.0/legalcode.txt"))
            else:
                commit = json.loads(get(f"https://api.github.com/repos/{repo}/commits/master", True))["sha"]
                for rel in ("LICENSE", "README.md"):
                    (notice_dir / (source + "-" + rel)).write_bytes(get(f"https://raw.githubusercontent.com/{repo}/{commit}/{rel}"))
                write_json(notice_dir / (source + "-source.json"), {"repository": repo, "commit": commit})
        # License/source reads may add provenance. Bind the same finalized map
        # in runtime metadata, detailed evidence and the build manifest.
        write_json(self.out / "sources.json", self.sources)
        write_json(audit_dir / "selected-sources.json", self.sources)
        # Full corresponding source is a separate release asset, including pinned raw
        # inputs even if production branches are force-pushed by their generators.
        with tarfile.open(audit_dir / "selected-source.tar.gz", "w:gz") as archive:
            for source, info in self.sources.items():
                for rel, expected_input in info.get("files", {}).items():
                    path = ROOT / rel if source == "personal" else self.raw / source / rel
                    if not path.is_file() or digest(path) != expected_input:
                        raise ValueError("Recorded source input is missing or changed: " + source + "/" + rel)
                    archive.add(path, arcname="inputs/" + source + "/" + rel)
            for folder in ("scripts", "runtime", "tests", "personal"):
                for path in sorted((ROOT / folder).rglob("*.py" if folder != "personal" else "*.yaml")):
                    archive.add(path, arcname="builder/" + path.relative_to(ROOT).as_posix())
            for rel in ("README.md", "NOTICE.md", "LICENSE"):
                archive.add(ROOT / rel, arcname="builder/" + rel)
            archive.add(ROOT / "scripts/shared-platform-roots.json", arcname="builder/scripts/shared-platform-roots.json")
            archive.add(notice_dir, arcname="licenses")
        upstream_dir = audit_dir / "upstream"
        upstream_dir.mkdir(exist_ok=True)
        for source in REPOS:
            proof = audit["sources"][source]
            archive_name = source + "-" + proof["commit"] + ".tar.gz"
            cached = ROOT / ".cache/audit" / archive_name
            if digest(cached)["sha256"] != proof["archive_sha256"]:
                raise ValueError("Upstream source archive changed after audit: " + source)
            shutil.copy2(cached, upstream_dir / archive_name)
        # Bind every report and source archive after they have been finalized.
        # The source audit manifest alone cannot attest to derived reports.
        artifact_manifest = {"schema_version": 1, "status": audit["status"], "sources": audit["sources"],
                             "source_manifest_sha256": hashlib.sha256(audit_raw).hexdigest(),
                             "files": {p.relative_to(audit_dir).as_posix(): digest(p) for p in sorted(audit_dir.rglob("*"))
                                       if p.is_file() and p != audit_dir / "artifact-manifest.json"}}
        write_json(audit_dir / "artifact-manifest.json", artifact_manifest)
        audit_hash = digest(audit_dir / "artifact-manifest.json")["sha256"]
        build_report["audit_manifest_sha256"] = audit_hash
        write_json(self.out / "build-report.json", build_report)
        # Whitelist emitted runtime paths so stale files cannot enter a new snapshot.
        expected = {p["path"] for p in providers.values()} | {"inline-rules.json", "build-report.json", "sources.json", "NOTICE.md"}
        unexpected = {p.relative_to(self.out).as_posix() for p in self.out.rglob("*") if p.is_file()} - expected - {"build-manifest.json"}
        if unexpected:
            raise ValueError("Output directory contains stale/unexpected artifacts: " + repr(sorted(unexpected)))
        manifest = {"schema_version": 2, "policy_version": "balanced-v2", "build_id": self.build_id, "tag": self.build_id,
                    "created_at": int(time.time()), "core_version": subprocess.check_output([self.mihomo, "-v"], text=True).strip(),
                    "fake_ip_pool": str(POOL), "sources": self.sources, "providers": providers,
                    "files": {rel: digest(self.out / rel) for rel in sorted(expected)},
                    "audit": {"status": "passed", "manifest_sha256": audit_hash, "manifest_name": "artifact-manifest.json",
                              "scope": audit.get("evaluation_scope", "original"), "repair_overlay": audit.get("repair_overlay"),
                              "release_asset": "audit-" + self.build_id + ".tar.gz"},
                    "counts": {s: c["input"] for s, c in self.stats.items()},
                    "provider_counts": {n: c["output"] for n, c in coverage.items()},
                    "distribution_license": "GPL-3.0; audited ACL originals retain CC-BY-SA-4.0"}
        validate_manifest(manifest)
        write_json(self.out / "build-manifest.json", manifest)
        verify(self.out, manifest)
        doc = {"mixed-port": 0, "mode": "rule", "tun": {"enable": False},
               "dns": {"enable": True, "enhanced-mode": "fake-ip", "fake-ip-range": str(POOL)},
               "proxies": [{"name": "validation-node", "type": "socks5", "server": "127.0.0.1", "port": 9}],
               "proxy-groups": [{"name": "节点选择", "type": "select", "proxies": ["validation-node"]}]}
        doc = assemble_dns(assemble(doc, manifest, inline, self.out), manifest, inline)
        smoke = self.raw / "balanced-smoke.yaml"
        smoke.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), encoding="utf-8")
        subprocess.run([self.mihomo, "-t", "-d", str(ROOT), "-f", str(smoke)], check=True)
        return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-id", default=os.environ.get("BUILD_ID", "rules-local-v2"))
    parser.add_argument("--mihomo", default=os.environ.get("MIHOMO", "mihomo"))
    parser.add_argument("--output", default=str(ROOT / "balanced-out"))
    parser.add_argument("--sources", help="Reuse immutable production commits and verified cached inputs")
    parser.add_argument("--audit", default=str(ROOT / "audit"))
    parser.add_argument("--baseline", default=str(ROOT / "out"), help="Explicit v1 rebuilt snapshot used for the migration report")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    builder = BalancedBuilder(args.build_id, args.mihomo, args.output, args.sources, args.baseline)
    builder.collect()
    if not args.prepare_only:
        builder.emit(args.audit)


if __name__ == "__main__":
    main()
