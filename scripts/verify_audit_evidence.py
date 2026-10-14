"""Read-only pre-build/publish verification of complete-source audit evidence.

This is a continuity check, not another full audit. Immutable upstream archive
hashes bind the original tree verification; every repair is checked against that
original inventory and the effective audit before artifacts may be re-hashed.
"""
import hashlib
import json
from pathlib import Path
import re

from audit_sources import (REPOS, RepairOverlay, canonical_mrs_input, decode_mrs,
                           project, repair_path, sha, text_rules)


def _file(root, relative):
    relative = repair_path(relative)
    root = Path(root).absolute()
    path = root / relative
    if any(part.is_symlink() for part in (path, *path.parents) if part != root.parent):
        raise ValueError("Audit evidence cannot be a symlink: " + str(path))
    if not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError("Missing or unsafe audit evidence: " + str(path))
    return path


def _read(root, relative):
    raw = _file(root, relative).read_bytes()
    return json.loads(raw), raw


def _digest(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def _inventory(document, sources, *, effective):
    if set(document.get("sources", {})) != set(REPOS):
        raise ValueError("Audit must cover every approved upstream source")
    inventory = {}
    counts = {name: 0 for name in REPOS}
    for entry in document.get("files", []):
        key = entry.get("source"), repair_path(entry.get("path"))
        if key[0] not in REPOS or key in inventory:
            raise ValueError("Duplicate or unknown audit inventory entry")
        if not re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", "")):
            raise ValueError("Invalid original audit file hash: " + key[1])
        if entry.get("original_sha256", entry["sha256"]) != entry["sha256"]:
            raise ValueError("Audit replaced the original upstream file identity")
        if effective and (entry.get("parse_errors", 0) or entry.get("classification") == "failed"):
            raise ValueError("Effective audit contains an invalid file: " + key[1])
        inventory[key] = entry
        counts[key[0]] += 1
    for name, repository in REPOS.items():
        actual, expected = document["sources"][name], sources.get(name, {})
        if (actual.get("repository") != repository or
                any(actual.get(field) != expected.get(field) for field in ("repository", "commit")) or
                not re.fullmatch(r"[0-9a-f]{40}", actual.get("commit", ""))):
            raise ValueError("Audit source revision differs: " + name)
        if (not re.fullmatch(r"[0-9a-f]{40}", actual.get("tree_sha", "")) or
                actual.get("tree_sha_verified") != actual["tree_sha"] or
                actual.get("tree_verification_scope", None if effective else "original_upstream_archive") != "original_upstream_archive" or
                counts[name] != actual.get("files") or not counts[name]):
            raise ValueError("Incomplete original Git tree evidence: " + name)
        # Selected inputs cannot merely claim the same source commit while using
        # a different cached byte stream. Personal inputs have no upstream tree.
        for path, spec in expected.get("files", {}).items():
            entry = inventory.get((name, path), {})
            if (entry.get("sha256") != spec.get("sha256") or
                    entry.get("bytes") != spec.get("size")):
                raise ValueError("Selected input differs from audited upstream: " + name + "/" + path)
    return inventory


def _effective_reports(directory, document, inventory):
    summary, _ = _read(directory, "summary.json")
    errors, _ = _read(directory, "errors.json")
    projections, _ = _read(directory, "projection-report.json")
    for relative in ("rules.jsonl.gz", "risks.jsonl.gz", "exclusions.json"):
        _file(directory, relative)
    if (document.get("schema_version") != 1 or document.get("status") != "passed" or
            summary.get("status") != "passed" or errors != [] or
            summary.get("errors") != 0 or summary.get("files") != len(inventory) or
            summary.get("sources") != document["sources"]):
        raise ValueError("Incomplete or failed effective source audit")
    if (not isinstance(projections, list) or
            any(item.get("required_equal") and item.get("equal") is not True for item in projections) or
            summary.get("projection_mismatches") != 0 or
            summary.get("projection_comparisons") != len(projections)):
        raise ValueError("Effective projection gate did not pass")
    for field in ("evaluation_scope", "auditor_sha256", "core_version", "repair_overlay"):
        if summary.get(field) != document.get(field):
            raise ValueError("Effective audit summary differs: " + field)
    if (not re.fullmatch(r"[0-9a-f]{64}", document.get("auditor_sha256", "")) or
            " v1.19.32 " not in document.get("core_version", "")):
        raise ValueError("Missing reviewed audit implementation/core evidence")
    for item in projections:
        for side in ("left", "right"):
            entry = inventory.get((item.get("source"), item.get(side)), {})
            if item.get(side + "_sha256") != entry.get("effective_sha256", entry.get("sha256")):
                raise ValueError("Projection evidence differs from effective inventory")


def _repairs(directory, sources, document, inventory):
    repair_dir = directory / "repairs"
    _file(repair_dir, "manifest.json")  # Reject missing/external/symlink overlays.
    overlay = RepairOverlay(repair_dir, sources)
    copy, copied_raw = _read(directory, "repair-manifest.json")
    if copied_raw != overlay.raw:
        raise ValueError("Archived repair manifest differs from effective audit input")
    proof = document.get("repair_overlay", {})
    count = len(overlay.entries)
    if (proof.get("manifest_sha256") != overlay.manifest_sha256 or
            any(proof.get(field) != count for field in ("registered", "applied", "verified")) or
            proof.get("tree_verification_scope") != "original_upstream_archive_only"):
        raise ValueError("Repair overlay differs from completed effective audit")
    original_dir = directory / "original"
    original, original_raw = _read(original_dir, "manifest.json")
    original_errors, original_errors_raw = _read(original_dir, "errors.json")
    if (sha(original_raw) != copy.get("original_audit_manifest_sha256") or
            sha(original_errors_raw) != copy.get("original_errors_sha256") or
            original.get("status") != copy.get("full_audit_status") or
            original.get("evaluation_scope", "original") != "original" or original.get("repair_overlay")):
        raise ValueError("Repair evidence no longer binds the untouched original audit")
    old = _inventory(original, sources, effective=False)
    source_fields = ("repository", "commit", "tree_sha", "archive_sha256", "archive_bytes", "files", "tree_sha_verified")
    if set(old) != set(inventory) or any(original["sources"][name].get(field) != document["sources"][name].get(field)
                                       for name in REPOS for field in source_fields):
        raise ValueError("Effective audit changed the original source inventory")
    if (any(item.get("parse_errors", 0) for item in old.values()) or
            {(item.get("source"), item.get("path")) for item in original_errors} != set(overlay.entries) or
            len(original_errors) != count or
            original.get("status") != ("failed" if count else "passed")):
        raise ValueError("Original audit errors are not exactly the registered MRS repairs")
    for key, current in inventory.items():
        previous = old[key]
        if previous.get("repair") or previous.get("effective_sha256", previous["sha256"]) != previous["sha256"]:
            raise ValueError("Original audit already contains a replacement: " + key[1])
        if any(current.get(field) != previous.get(field) for field in ("sha256", "bytes", "git_mode")):
            raise ValueError("Effective audit changed original upstream bytes: " + key[1])
        repaired = key in overlay.entries
        if bool(current.get("repair")) != repaired:
            raise ValueError("Unregistered or missing effective repair: " + key[1])
        if not repaired and current.get("effective_sha256") != current["sha256"]:
            raise ValueError("Unregistered effective file replacement: " + key[1])
    expected_fixed = set()
    for key, row in overlay.entries.items():
        source, path = key
        current, original_entry = inventory[key], old[key]
        canonical = canonical_mrs_input(source, path, row["behavior"], inventory)
        canonical_entry = inventory.get((source, canonical), {})
        repair = current["repair"]
        if (canonical != row["canonical_path"] or original_entry["sha256"] != row["original_sha256"] or
                canonical_entry.get("sha256") != row["canonical_sha256"] or
                canonical_entry.get("classification") != "rules" or canonical_entry.get("parse_errors", 0) or
                current.get("effective_sha256") != row["fixed_sha256"] or
                repair.get("manifest_sha256") != overlay.manifest_sha256 or
                repair.get("source_commit") != sources[source]["commit"] or
                repair.get("canonical_projection_verified") is not True or
                any(repair.get(field) != value for field, value in row.items())):
            raise ValueError("Repair row differs from audited original/effective evidence: " + path)
        retained_path = row.get("retained_classical_path")
        retained = _file(repair_dir, retained_path).read_bytes()
        if sha(retained) != row["canonical_sha256"]:
            raise ValueError("Retained canonical text changed after audit: " + path)
        predicates = list(text_rules(source, canonical, retained))
        projection = project([(kind, value) for _, kind, value in predicates])
        expected = projection[row["behavior"]]
        decoded = decode_mrs(overlay.fixed_bytes(row))
        if (projection != canonical_entry.get("projection") or
                decoded["behavior"] != row["behavior"] or decoded["fingerprint"] != expected or
                current.get("fingerprint") != expected or repair.get("verified_fingerprint") != expected or
                row.get("retained_inline_count") != projection["inline_count"]):
            raise ValueError("Repaired MRS no longer represents the retained canonical text: " + path)
        for field in ("expected_fingerprint", "core_decode_fingerprint", "roundtrip_fingerprint"):
            if row.get(field) is not None and row[field] != expected:
                raise ValueError("Repair core proof fingerprint differs: " + path)
        expected_fixed.add(row["fixed_path"])
    actual_fixed = {p.relative_to(repair_dir).as_posix() for p in (repair_dir / "fixed").rglob("*") if p.is_file()}
    if actual_fixed != expected_fixed:
        raise ValueError("Repair directory contains missing or unregistered fixed artifacts")


def verify_source_audit(audit_dir, sources, archive_dir=None):
    """Return a verified effective manifest without changing any evidence.

    Before build, pass the immutable archive cache as ``archive_dir``. Publication
    omits it, requiring the corresponding source archives inside ``audit/upstream``.
    Repair artifacts always have to be archived under ``audit/repairs``.
    """
    directory = Path(audit_dir).absolute()
    document, _ = _read(directory, "manifest.json")
    inventory = _inventory(document, sources, effective=True)
    _effective_reports(directory, document, inventory)
    archive_root = Path(archive_dir) if archive_dir is not None else directory / "upstream"
    for name, spec in document["sources"].items():
        archive = _file(archive_root, name + "-" + spec["commit"] + ".tar.gz")
        checksum, size = _digest(archive)
        if checksum != spec.get("archive_sha256") or size != spec.get("archive_bytes"):
            raise ValueError("Original source archive changed after audit: " + name)
    scope = document.get("evaluation_scope")
    if scope == "upstream-with-verified-repairs":
        _repairs(directory, sources, document, inventory)
    elif scope == "original":
        if document.get("repair_overlay") or any(item.get("repair") or
                item.get("effective_sha256") != item["sha256"] for item in inventory.values()):
            raise ValueError("Original-scope audit contains effective replacements")
    else:
        raise ValueError("Unknown complete-source audit scope")
    return document
