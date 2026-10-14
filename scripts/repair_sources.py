#!/usr/bin/env python3
"""Repair the confirmed upstream MRS conversion defects in a separate overlay.

The original archives and failed audit remain unchanged. Every run uses its own
immutable snapshot, with the reviewed generator source mapping pinned by hash.
The overlay must subsequently pass audit_sources.py --repairs in full.
"""
import argparse
import collections
import difflib
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile

import audit_sources as audit


ACL_GENERATORS = {
    ".github/workflows/update.yml": "b02aebb2dae7abf1ccd560f2337c73e61a133d29cfbbadb2e144e32662c13fec",
    "scripts/gfwlist_parser.py": "57cca2bd593c896057bddcf5726d3add729c360d7b3ec93e281fc4cb734f3347",
}
EMPTY_META_PATHS = {
    "geo-lite/geosite/proxymedia.mrs",
    "geo/geosite/category-entertainment-cn@cn.mrs",
    "geo/geosite/category-games-cn@cn.mrs",
    "geo/geosite/category-speedtest@ads.mrs",
    "geo/geosite/epicgames@cn.mrs",
    "geo/geosite/mihoyo-cn@cn.mrs",
    "geo/geosite/mihoyo@cn.mrs",
    "geo/geosite/okaapps@cn.mrs",
    "geo/geosite/ookla-speedtest@ads.mrs",
    "geo/geosite/speedtest@ads.mrs",
}
CLASSICAL_DOMAIN_PREFIXES = ("domain,", "domain-suffix,", "domain-keyword,", "domain-regex,")


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def normalize_sources(sources):
    sources = sources.get("sources", sources)
    return {name: {"repository": sources[name]["repository"], "commit": sources[name]["commit"]}
            for name in audit.REPOS}


def domain_projection(source, path, raw):
    """Keep keyword/regex rules in their classical source, never as literal domains."""
    values, retained, seen = [], [], set()
    for line, kind, value in audit.text_rules(source, path, raw):
        domain = audit.domain_mrs_value(kind, value)
        if domain is not None:
            values.append(domain)
        elif kind not in {"IP-CIDR", "IP-CIDR6"} and (kind, value) not in seen:
            retained.append({"line": line, "type": kind, "value": value})
            seen.add((kind, value))
    return sorted(set(values)), retained


def canonical_acl(path, inventory):
    name = PurePosixPath(path).stem.removesuffix("_domain")
    candidates = [f"Clash/Providers/{name}.yaml", f"Clash/Providers/Ruleset/{name}.yaml",
                  f"Clash/Ruleset/{name}.list"]
    candidates = [candidate for candidate in candidates if ("acl", candidate) in inventory
                  and inventory[("acl", candidate)].get("projection", {}).get("domain_generator_input_count", 0)]
    if not candidates:
        raise ValueError("No canonical ACL generator input: " + path)
    # The fixed upstream update.yml converts these globs in this order. Last wins.
    return candidates[-1]


def validated_requests(audit_dir, sources):
    audit_dir = Path(audit_dir)
    manifest, summary = (read_json(audit_dir / name) for name in ("manifest.json", "summary.json"))
    errors, comparisons = (read_json(audit_dir / name) for name in ("errors.json", "projection-report.json"))
    sources = normalize_sources(sources)
    for name, spec in sources.items():
        original = manifest.get("sources", {}).get(name, {})
        if spec["repository"] != audit.REPOS[name] or any(original.get(k) != v for k, v in spec.items()):
            raise ValueError("Repair source snapshot differs from original audit: " + name)
        if original.get("tree_sha") != original.get("tree_sha_verified") or not original.get("tree_sha"):
            raise ValueError("Original complete-tree verification is missing: " + name)
    if summary.get("sources") != manifest["sources"] or summary.get("errors") != len(errors):
        raise ValueError("Original audit summary is inconsistent")
    inventory = {(item["source"], item["path"]): item for item in manifest["files"]}
    if len(inventory) != len(manifest["files"]) or summary.get("files") != len(inventory):
        raise ValueError("Original audit inventory is inconsistent")
    for name in sources:
        if sum(key[0] == name for key in inventory) != manifest["sources"][name]["files"]:
            raise ValueError("Original audit omitted a source directory: " + name)
    if any(item.get("parse_errors", 0) for item in inventory.values()):
        raise ValueError("Text parsing defects cannot be repaired by the MRS repair stage")
    if not errors:
        if manifest.get("status") != "passed" or summary.get("status") != "passed":
            raise ValueError("Error-free original audit did not pass")
        return manifest, inventory, []
    if manifest.get("status") != "failed" or summary.get("status") != "failed":
        raise ValueError("The failed original audit must remain failed")
    if len({(e["source"], e["path"]) for e in errors}) != len(errors):
        raise ValueError("Multiple failures in one file require review before repair")
    if any(error["source"] == "acl" for error in errors):
        for path, expected in ACL_GENERATORS.items():
            if inventory.get(("acl", path), {}).get("sha256") != expected:
                raise ValueError("ACL generator/source mapping changed and requires review: " + path)
    failed_comparisons = {(p["source"], p["left"]): p for p in comparisons
                          if p.get("required_equal") and not p.get("equal")}
    requests = []
    for error in errors:
        source, path = error["source"], error["path"]
        key = (source, path)
        entry = inventory.get(key)
        if not entry or error.get("sha256") != entry.get("sha256") or not path.endswith(".mrs"):
            raise ValueError("Defect does not match its original MRS inventory: " + str(key))
        if source == "acl" and path.startswith("Clash/mrs/") and path.endswith("_domain.mrs"):
            canonical = canonical_acl(path, inventory)
            comparison = failed_comparisons.get(key, {})
            if (error["error"] != "domain projection differs from " + canonical
                    or comparison.get("right") != canonical or comparison.get("projection") != "domain"
                    or comparison.get("relation") != "binary_representable_projection"
                    or comparison.get("left_sha256") != entry["sha256"]
                    or comparison.get("right_sha256") != inventory[(source, canonical)]["sha256"]):
                raise ValueError("Unknown ACL conversion failure: " + path)
            category = "classical_prefixes_written_as_literal_domain"
        elif source == "meta" and path in EMPTY_META_PATHS:
            if (entry.get("bytes") != 0 or entry["sha256"] != audit.sha(b"")
                    or error["error"] != "Truncated/invalid MRS length"):
                raise ValueError("Unknown Meta MRS failure: " + path)
            canonical, category = path[:-4] + ".list", "invalid_zero_byte_empty_set"
        else:
            raise ValueError("Unknown/new MRS defect requires review: " + path)
        canonical_entry = inventory.get((source, canonical), {})
        if canonical_entry.get("classification") != "rules" or canonical_entry.get("parse_errors", 0):
            raise ValueError("Canonical source is absent or invalid: " + canonical)
        requests.append({"source": source, "path": path, "original_sha256": entry["sha256"],
                         "canonical_path": canonical, "canonical_sha256": canonical_entry["sha256"],
                         "behavior": "domain", "defect": category})
    if len(failed_comparisons) != sum(r["source"] == "acl" for r in requests):
        raise ValueError("Unknown additional failed projection")
    return manifest, inventory, sorted(requests, key=lambda item: (item["source"], item["path"]))


def verified_archive_blobs(name, source, original, paths, cache, offline):
    archive_path, metadata = audit.cached_archive(name, source, Path(cache), offline)
    if any(metadata[k] != original[k] for k in ("commit", "repository", "archive_sha256", "tree_sha")):
        raise ValueError("Repair archive differs from original audit: " + name)
    blobs, tree = {}, []
    with tarfile.open(archive_path, "r|gz") as archive:
        for member in archive:
            if member.isdir():
                continue
            path = "/".join(PurePosixPath(member.name).parts[1:])
            if not member.isfile() or ".." in PurePosixPath(path).parts or not path:
                raise ValueError("Unsupported repair archive member")
            raw = archive.extractfile(member).read()
            mode = "100755" if member.mode & 0o111 else "100644"
            tree.append((path, mode, audit.git_hash("blob", raw)))
            if path in paths:
                blobs[path] = raw
    if audit.root_tree(tree) != original["tree_sha_verified"] or len(tree) != original["files"]:
        raise ValueError("Repair archive complete-tree verification failed: " + name)
    if set(blobs) != set(paths):
        raise ValueError("Canonical repair source is absent from archive")
    return blobs


def validate_broken_domain(raw, expected):
    original = audit.decode_mrs(raw)
    values = original.get("domains", [])
    if (original["behavior"] != "domain" or not values
            or not all(value.lower().startswith(CLASSICAL_DOMAIN_PREFIXES) for value in values)
            or original["fingerprint"] == expected):
        raise ValueError("MRS does not contain the confirmed literal classical-prefix defect")
    return {"original_decoded_count": len(values), "original_literal_examples": values[:3]}


def compile_and_verify(values, mihomo, fixed_path):
    expected = audit.fingerprint(audit.domain_tokens(values))
    fixed_path = Path(fixed_path)
    fixed_path.parent.mkdir(parents=True, exist_ok=True)
    if not values:
        from empty_mrs import encode_empty_mrs, verify_empty_mrs
        raw = encode_empty_mrs("domain")
        if audit.decode_mrs(raw)["fingerprint"] != expected:
            raise ValueError("Empty MRS encoder changed empty-set semantics")
        evidence = verify_empty_mrs(raw, mihomo)
        fixed_path.write_bytes(raw)
        return {"expected_fingerprint": expected, "core_decode_fingerprint": expected,
                "roundtrip_fingerprint": None, "empty_set_verification": evidence,
                "verification_method": "real_provider_empty_set_regression",
                "converter_limitation": "Mihomo convert-ruleset refuses count=0; provider regression verifies the empty set."}
    with tempfile.TemporaryDirectory(prefix="repair-mrs-") as directory:
        text, dumped = Path(directory) / "source.txt", Path(directory) / "roundtrip.txt"
        text.write_text("\n".join(values) + "\n", encoding="utf-8")
        subprocess.run([mihomo, "convert-ruleset", "domain", "text", str(text), str(fixed_path)],
                       check=True, capture_output=True, timeout=60)
        decoded = audit.decode_mrs(fixed_path.read_bytes())
        subprocess.run([mihomo, "convert-ruleset", "domain", "mrs", str(fixed_path), str(dumped)],
                       check=True, capture_output=True, timeout=60)
        roundtrip = audit.fingerprint(audit.domain_tokens(dumped.read_text(encoding="utf-8").splitlines()))
        if decoded["fingerprint"] != expected or roundtrip != expected:
            raise ValueError("Repaired MRS changed canonical source semantics")
    return {"expected_fingerprint": expected, "core_decode_fingerprint": decoded["fingerprint"],
            "roundtrip_fingerprint": roundtrip, "verification_method": "real_core_compile_and_decompile"}


def write_upstream_proposal(output, generator):
    original = generator.decode("utf-8")
    replacements = {
        "return rule_type in ('DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX')":
            "# Keyword/regex rules remain in the original classical ruleset.\n    return rule_type in ('DOMAIN', 'DOMAIN-SUFFIX')",
        'domain_yaml += f"  - {rule_type},{d}\\n"':
            'if "*" in d:  # Classical literal asterisks are not domain-provider wildcards.\n                continue\n            domain_value = f"+.{d}" if rule_type == "DOMAIN-SUFFIX" else d\n            domain_yaml += f"  - {domain_value}\\n"',
        'domain_text += f"{rule_type},{d}\\n"':
            'if "*" in d:  # Preserve unsupported predicates in the classical source.\n                continue\n            domain_value = f"+.{d}" if rule_type == "DOMAIN-SUFFIX" else d\n            domain_text += f"{domain_value}\\n"',
    }
    revised = original
    for old, new in replacements.items():
        if revised.count(old) != 1:
            raise ValueError("Reviewed upstream generator patch no longer applies uniquely")
        revised = revised.replace(old, new)
    compile(revised, "ACL4SSR/scripts/gfwlist_parser.py", "exec")
    patch = "".join(difflib.unified_diff(original.splitlines(keepends=True), revised.splitlines(keepends=True),
                                       fromfile="a/scripts/gfwlist_parser.py", tofile="b/scripts/gfwlist_parser.py"))
    (output / "ACL4SSR-domain-projection.patch").write_text(patch, encoding="utf-8")
    (output / "UPSTREAM-FIX.md").write_text(
        "# Upstream repair proposal (not sent)\n\n"
        "The attached minimal ACL4SSR patch emits bare exact domains and +.suffix predicates for the domain converter. "
        "DOMAIN-KEYWORD, DOMAIN-REGEX and classical domain rules containing literal asterisks remain in the original "
        "classical tables because domain MRS cannot preserve their matching semantics. "
        "Consumers that need those predicates must continue to load the classical source.\n\n"
        "The patch addresses nonempty domain projection generation. Before publishing an upstream release, remove stale "
        "generated outputs and handle empty projections deliberately: Mihomo 1.19.32 convert-ruleset rejects count=0. "
        "A keyword-only source such as Whatsapp needs a structurally valid empty MRS plus its classical rules, or an explicit "
        "provider manifest that omits the empty domain artifact. This local overlay supplies a verified empty MRS.\n\n"
        "Meta zero-byte MRS files must also be replaced by a valid empty-set serialization when their canonical domain "
        "projection is empty. A zero-byte file is not a valid MRS header. No placeholder domain is an acceptable fix.\n\n"
        "No upstream issue, pull request, release, or deployment was created by this repair.\n", encoding="utf-8")


def repair_all(audit_dir, sources, mihomo, output, cache=Path(".cache/audit"), offline=False):
    audit_dir, output = Path(audit_dir).resolve(), Path(output).resolve()
    if output == audit_dir or audit_dir.is_relative_to(output) or output.is_relative_to(audit_dir):
        raise ValueError("Repairs must be a separate sibling of the original failed audit")
    if output.exists() and any(output.iterdir()):
        raise ValueError("Repair output must be empty to prevent stale repaired artifacts")
    original, inventory, requests = validated_requests(audit_dir, sources)
    sources = normalize_sources(sources)
    mihomo = str(Path(mihomo).resolve()) if Path(mihomo).exists() else str(mihomo)
    version = subprocess.check_output([mihomo, "-v"], text=True).strip()
    if " v1.19.32 " not in version:
        raise ValueError("Repair verification requires the reviewed Mihomo v1.19.32 core")
    output.mkdir(parents=True, exist_ok=True)
    manifest = {"schema_version": 1, "status": "failed", "full_audit_status": original["status"],
                "original_audit_manifest_sha256": audit.sha((audit_dir / "manifest.json").read_bytes()),
                "original_errors_sha256": audit.sha((audit_dir / "errors.json").read_bytes()),
                "mihomo": version, "sources": sources, "repairs": [],
                "reviewed_acl_generators": ACL_GENERATORS,
                "publication": "not_authorized_by_repair; complete effective audit is required"}
    try:
        blobs = {}
        for name in ("acl", "meta"):
            paths = {r[field] for r in requests if r["source"] == name for field in ("path", "canonical_path")}
            if paths:
                if name == "acl":
                    paths.update(ACL_GENERATORS)
                blobs[name] = verified_archive_blobs(name, sources[name], original["sources"][name], paths, cache, offline)
                if name == "acl" and any(audit.sha(blobs[name][path]) != expected for path, expected in ACL_GENERATORS.items()):
                    raise ValueError("Archived ACL generator/source mapping changed")
        for request in requests:
            source, path, canonical = (request[k] for k in ("source", "path", "canonical_path"))
            broken, text = blobs[source][path], blobs[source][canonical]
            if audit.sha(broken) != request["original_sha256"] or audit.sha(text) != request["canonical_sha256"]:
                raise ValueError("Repair inputs do not match original audit hashes")
            values, retained = domain_projection(source, canonical, text)
            expected = audit.fingerprint(audit.domain_tokens(values))
            original_projection = inventory[(source, canonical)]["projection"]["domain"]
            correction = None
            if expected != original_projection:
                literal_wildcards = [item for item in retained if item["type"] in {"DOMAIN", "DOMAIN-SUFFIX"} and "*" in item["value"]]
                old_values = values + [("+." if item["type"] == "DOMAIN-SUFFIX" else "") + item["value"] for item in literal_wildcards]
                if not literal_wildcards or audit.fingerprint(audit.domain_tokens(old_values)) != original_projection:
                    raise ValueError("Canonical source projection differs from the original audit")
                correction = "Classical literal-asterisk predicates are preserved inline; they are not domain-provider wildcards."
            defect_evidence = validate_broken_domain(broken, expected) if source == "acl" else {}
            if source == "meta" and (values or broken):
                raise ValueError("A Meta zero-byte repair is allowed only for an actually empty canonical set")
            fixed_path = "fixed/" + source + "/" + path
            retained_path = "canonical/" + source + "/" + canonical
            target = output / fixed_path
            proof = compile_and_verify(values, mihomo, target)
            retained_file = output / retained_path
            retained_file.parent.mkdir(parents=True, exist_ok=True)
            retained_file.write_bytes(text)
            record = {**request, "fixed_path": fixed_path, "fixed_sha256": audit.sha(target.read_bytes()),
                      "retained_classical_path": retained_path, "retained_inline_count": len(retained),
                      "retained_inline_rules": retained, "original_audit_projection_fingerprint": original_projection,
                      "projection_definition_correction": correction, **proof, **defect_evidence}
            manifest["repairs"].append(record)
            if len(manifest["repairs"]) % 25 == 0:
                print(f"Rebuilt and verified {len(manifest['repairs'])}/{len(requests)} MRS files", flush=True)
        manifest["status"] = "repaired"
        manifest["counts"] = dict(collections.Counter(record["defect"] for record in manifest["repairs"]))
        if "acl" in blobs:
            write_upstream_proposal(output, blobs["acl"]["scripts/gfwlist_parser.py"])
    except Exception as error:
        manifest["status"] = "failed"
        manifest["error"] = str(error)
        raise
    finally:
        audit.write_json(output / "manifest.json", manifest)
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--sources", required=True, type=Path)
    parser.add_argument("--mihomo", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cache", type=Path, default=Path(".cache/audit"))
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args(argv)
    result = repair_all(args.audit, read_json(args.sources), args.mihomo, args.output, args.cache, args.offline)
    print(json.dumps({"status": result["status"], "repaired": len(result["repairs"]),
                      "original_audit_status": result["full_audit_status"]}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
