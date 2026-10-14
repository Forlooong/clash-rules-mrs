#!/usr/bin/env python3
"""Publish a verified immutable tag/release; only then expose candidate pointer."""
import base64
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import tarfile
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from runtime.snapshot import REPO, verify, download
from four_sources import guard
from verify_audit_evidence import verify_source_audit

def run(*args, cwd=None, env=None):
    return subprocess.check_output(args, cwd=cwd, env=env, text=True).strip()

def verify_audit(audit, manifest):
    audit = Path(audit).resolve()
    raw = (audit / "artifact-manifest.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest["audit"]["manifest_sha256"]:
        raise ValueError("Audit manifest differs from build gate")
    proof = json.loads(raw)
    if proof.get("status") != "passed":
        raise ValueError("Incomplete or failed upstream audit")
    actual = {p.relative_to(audit).as_posix() for p in audit.rglob("*") if p.is_file()} - {"artifact-manifest.json"}
    if actual != set(proof["files"]):
        raise ValueError("Audit artifact inventory changed after build")
    for rel, expected in proof["files"].items():
        path = (audit / rel).resolve()
        if not path.is_relative_to(audit):
            raise ValueError("Unsafe audit artifact path")
        data = path.read_bytes()
        if len(data) != expected["size"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
            raise ValueError("Audit artifact changed after build: " + rel)
    for name in ("loyal", "acl", "meta"):
        if proof["sources"][name]["commit"] != manifest["sources"][name]["commit"]:
            raise ValueError("Audit revisions differ")
    verify_source_audit(audit, manifest["sources"])
    return proof

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(ROOT / "out"))
    parser.add_argument("--audit", default=str(ROOT / "audit"))
    args = parser.parse_args()
    out = Path(args.out).resolve()
    manifest_raw = (out / "build-manifest.json").read_bytes()
    manifest = json.loads(manifest_raw)
    verify(out, manifest)
    version = manifest["schema_version"]
    candidate_name = "candidate-v2.json" if version == 2 else "candidate.json"
    audit_asset = None
    if version == 2:
        audit = Path(args.audit).resolve()
        verify_audit(audit, manifest)
        audit_asset = out.parent / ("audit-" + manifest["tag"] + ".tar.gz")
        with tarfile.open(audit_asset, "w:gz") as archive:
            for path in sorted(audit.rglob("*")):
                if path.is_file():
                    archive.add(path, arcname="audit/" + path.relative_to(audit).as_posix())
    previous = None
    try:
        previous_pointer = json.loads(download(REPO + "release/" + candidate_name, 4096, time.monotonic() + 30))
        raw = download(REPO + previous_pointer["build_id"] + "/build-manifest.json", 2 * 1024 * 1024,
                       time.monotonic() + 30)
        if hashlib.sha256(raw).hexdigest() != previous_pointer["manifest_sha256"]:
            raise ValueError("Previous candidate checksum mismatch")
        previous = json.loads(raw)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
    if os.environ.get("ALLOW_COUNT_CHANGE") != "true":
        guard(manifest, previous)
    tag = manifest["tag"]
    env = dict(os.environ)
    token = env["GH_TOKEN"]
    # Credential only in child environment, never command arguments or Git files.
    env["GIT_CONFIG_COUNT"] = "1"
    env["GIT_CONFIG_KEY_0"] = "http.https://github.com/.extraheader"
    env["GIT_CONFIG_VALUE_0"] = "AUTHORIZATION: basic " + base64.b64encode(("x-access-token:" + token).encode()).decode()
    git_dir = out / ".git"
    if git_dir.exists():
        raise ValueError("Artifact directory already has a Git repository")
    run("git", "init", cwd=out)
    run("git", "config", "user.name", "github-actions[bot]", cwd=out)
    run("git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com", cwd=out)
    run("git", "add", ".", cwd=out)
    run("git", "commit", "-m", "Verified rule snapshot " + tag, cwd=out)
    run("git", "remote", "add", "origin", "https://github.com/Forlooong/clash-rules-mrs.git", cwd=out)
    existing = run("git", "ls-remote", "--tags", "origin", "refs/tags/" + tag, cwd=out, env=env)
    if existing:
        raise ValueError("Refusing to overwrite immutable tag")
    run("git", "push", "origin", "HEAD:refs/tags/" + tag, cwd=out, env=env)
    deadline = time.monotonic() + 120
    remote = download(REPO + tag + "/build-manifest.json", 2 * 1024 * 1024, deadline)
    if remote != manifest_raw:
        raise ValueError("Published manifest differs")
    for rel, expected in manifest["files"].items():
        data = download(REPO + tag + "/" + rel, expected["size"], deadline)
        if hashlib.sha256(data).hexdigest() != expected["sha256"]:
            raise ValueError("Published file differs: " + rel)
    paths = [out / "build-manifest.json"] + [out / rel for rel in manifest["files"]]
    if audit_asset:
        paths.append(audit_asset)
    names = [p.name for p in paths]
    if len(names) != len(set(names)):
        raise ValueError("Release asset names collide")
    run("gh", "release", "create", tag, "--repo", "Forlooong/clash-rules-mrs",
        "--verify-tag", "--title", ("Balanced v2 MRS " if version == 2 else "Four-source MRS ") + tag,
        "--notes", "Immutable rules; pinned sources and hashes included. V2 full audit and corresponding source are separate assets.",
        *[str(p) for p in paths], env=env)
    # Asset digest where available, otherwise fetch asset and verify content hash.
    assets = json.loads(run("gh", "api", "repos/Forlooong/clash-rules-mrs/releases/tags/" + tag, env=env))["assets"]
    by_name = {a["name"]: a for a in assets}
    for p in paths:
        asset = by_name[p.name]
        sha = hashlib.sha256(p.read_bytes()).hexdigest()
        if asset["size"] != p.stat().st_size:
            raise ValueError("Release asset size mismatch")
        if asset.get("digest"):
            if asset["digest"] != "sha256:" + sha:
                raise ValueError("Release asset checksum mismatch")
        else:
            data = download(asset["browser_download_url"], p.stat().st_size, time.monotonic() + 120)
            if hashlib.sha256(data).hexdigest() != sha:
                raise ValueError("Release asset differs")
    candidate = {"schema_version": version, "build_id": tag,
                 "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest()}
    if version == 2:
        candidate["policy_version"] = manifest["policy_version"]
    (ROOT / "compat-out").mkdir(exist_ok=True)
    (ROOT / "compat-out" / candidate_name).write_text(json.dumps(candidate) + "\n", encoding="utf-8")
    candidate_dir = ROOT / "candidate-out"
    candidate_dir.mkdir(exist_ok=True)
    (candidate_dir / candidate_name).write_text(json.dumps(candidate) + "\n", encoding="utf-8")
    print("Verified candidate:", tag)

if __name__ == "__main__":
    main()
