#!/usr/bin/env python3
"""Publish a verified immutable tag/release; only then expose candidate pointer."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from runtime.snapshot import REPO, verify, download
from four_sources import guard

def run(*args, cwd=None, env=None):
    return subprocess.check_output(args, cwd=cwd, env=env, text=True).strip()

def main():
    out = ROOT / "out"
    manifest_raw = (out / "build-manifest.json").read_bytes()
    manifest = json.loads(manifest_raw)
    verify(out, manifest)
    previous = None
    try:
        previous_pointer = json.loads(download(REPO + "release/candidate.json", 4096, time.monotonic() + 30))
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
    names = [p.name for p in paths]
    if len(names) != len(set(names)):
        raise ValueError("Release asset names collide")
    run("gh", "release", "create", tag, "--repo", "Forlooong/clash-rules-mrs",
        "--verify-tag", "--title", "Four-source MRS " + tag,
        "--notes", "Immutable four-source rules; source versions, hashes and attribution included.",
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
    candidate = {"schema_version": 1, "build_id": tag,
                 "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest()}
    (ROOT / "compat-out/candidate.json").write_text(json.dumps(candidate) + "\n", encoding="utf-8")
    candidate_dir = ROOT / "candidate-out"
    candidate_dir.mkdir(exist_ok=True)
    (candidate_dir / "candidate.json").write_text(json.dumps(candidate) + "\n", encoding="utf-8")
    print("Verified candidate:", tag)

if __name__ == "__main__":
    main()
