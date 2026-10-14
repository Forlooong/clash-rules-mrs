#!/usr/bin/env python3
"""Build immutable MRS snapshots from pinned public text sources."""
import argparse
import collections
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from runtime.snapshot import BASE, SECTIONS, PROVIDERS, assemble, validate_manifest

POOL = ipaddress.ip_network("198.18.0.0/16")
REPOS = {"loyal": ("Loyalsoldier/clash-rules", "release"),
         "acl": ("ACL4SSR/ACL4SSR", "master"),
         "meta": ("MetaCubeX/meta-rules-dat", "meta")}
DOMAIN = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$")
INLINE_TYPES = {"DOMAIN-KEYWORD", "DOMAIN-REGEX", "PROCESS-NAME", "PROCESS-PATH",
                "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX", "DST-PORT", "SRC-PORT",
                "NETWORK", "SRC-IP-CIDR", "SRC-IP-CIDR6", "UID", "IP-ASN"}

def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

def get(url, api=False):
    headers = {"User-Agent": "Forlooong-MRS-builder"}
    if api and os.environ.get("GH_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GH_TOKEN"]
    for attempt in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as r:
                data = r.read(64 * 1024 * 1024 + 1)
                if len(data) > 64 * 1024 * 1024:
                    raise ValueError("source exceeds size limit")
                return data
        except Exception:
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)

def subtract(network, pool=POOL):
    if network.version != pool.version or not network.overlaps(pool):
        return [network]
    if network.subnet_of(pool):
        return []
    return list(network.address_exclude(pool))

def parse_rule(rule):
    kind, sep, value = rule.partition(",")
    kind, value = kind.strip().upper(), value.strip()
    if not sep or not value or "\n" in rule or "\r" in rule:
        raise ValueError("Malformed rule: " + repr(rule))
    if kind in ("DOMAIN", "DOMAIN-SUFFIX"):
        value = value.lower()
        if not DOMAIN.fullmatch(value):
            raise ValueError("Invalid domain: " + repr(rule))
        return "domain", ("+." if kind == "DOMAIN-SUFFIX" else "") + value
    if kind in ("IP-CIDR", "IP-CIDR6"):
        parts = value.split(",")
        if len(parts) > 2 or len(parts) == 2 and parts[1].strip() != "no-resolve":
            raise ValueError("Invalid IP options: " + rule)
        net = ipaddress.ip_network(parts[0], strict=False)
        if kind == "IP-CIDR" and net.version != 4 or kind == "IP-CIDR6" and net.version != 6:
            raise ValueError("Wrong IP family: " + rule)
        if len(parts) == 2:
            return "inline", kind + "," + str(net) + ",no-resolve"
        return "ipcidr", str(net)
    if kind not in INLINE_TYPES:
        raise ValueError("Unsupported rule type: " + kind)
    # Regex payload may contain commas (e.g. {0,61}); never split it again.
    return "inline", kind + "," + value

def prune_domains(values):
    unique = set(values)
    suffixes = {s[2:] for s in unique if s.startswith("+.")}
    result, covered = [], []
    for value in sorted(unique):
        if value.startswith("*.") or value.startswith(".") and not value.startswith("+."):
            result.append(value)
            continue
        host = value[2:] if value.startswith("+.") else value
        parts = host.split(".")
        ancestors = [".".join(parts[i:]) for i in range(len(parts))]
        if any(a in suffixes and not (value == "+." + a) for a in ancestors):
            covered.append(value)
        else:
            result.append(value)
    return result, covered

class Builder:
    def __init__(self, build_id, mihomo):
        self.build_id, self.mihomo = build_id, mihomo
        self.domains = collections.defaultdict(list)
        self.ips = collections.defaultdict(list)
        self.inline = {s: [] for s in SECTIONS}
        self.records, self.cidrs, self.sources = [], [], {}
        self.stats = collections.defaultdict(collections.Counter)
        self.raw = ROOT / "raw"
        self.out = ROOT / "out"
        self.offline = False

    def fetch(self, source, path):
        repo, _ = REPOS[source]
        target = self.raw / source / path
        recorded = self.sources.get(source, {}).get("files", {}).get(path)
        if self.offline and recorded and target.exists():
            data = target.read_bytes()
            if hashlib.sha256(data).hexdigest() != recorded["sha256"]:
                raise ValueError("Cached input checksum differs: " + path)
        else:
            data = get(f"https://raw.githubusercontent.com/{repo}/{self.sources[source]['commit']}/{path}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        self.sources[source]["files"][path] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        return data.decode("utf-8-sig")

    def pin(self):
        if self.offline:
            self.sources = json.loads((self.out / "sources.json").read_text(encoding="utf-8"))
            return
        for name, (repo, ref) in REPOS.items():
            commit = json.loads(get(f"https://api.github.com/repos/{repo}/commits/{ref}", True))["sha"]
            self.sources[name] = {"repository": repo, "ref": ref, "commit": commit, "files": {}}
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        self.sources["personal"] = {"repository": "Forlooong/clash-rules-mrs", "commit": commit, "files": {}}

    def add(self, kind, value, target, source, original=None, personal=False, policy=None, rank=None):
        self.stats[source]["input"] += 1
        if kind == "domain":
            self.domains[target].append(value)
        elif kind == "ipcidr":
            net = ipaddress.ip_network(value, strict=False)
            if personal and net.version == POOL.version and net.overlaps(POOL):
                raise ValueError("Personal rule overlaps Fake-IP: " + value)
            remaining = subtract(net)
            self.ips[target].extend(str(n) for n in remaining)
            if value != str(net) or remaining != [net] or net.is_private:
                self.cidrs.append({"source": source, "original": original or value,
                                   "normalized": str(net), "remaining": [str(n) for n in remaining],
                                   "private": net.is_private})
        else:
            if value.startswith(("IP-CIDR,", "IP-CIDR6,")):
                net = ipaddress.ip_network(value.split(",")[1], strict=False)
                if net.version == POOL.version and net.overlaps(POOL):
                    if personal:
                        raise ValueError("Personal inline IP overlaps Fake-IP")
                    for n in subtract(net):
                        self.inline[target].append(value.split(",")[0] + "," + str(n) + ",no-resolve")
                    self.cidrs.append({"source": source, "original": original or value,
                                       "normalized": str(net), "remaining": [str(n) for n in subtract(net)]})
                else:
                    self.inline[target].append(value)
            else:
                self.inline[target].append(value)
        self.stats[source][kind] += 1
        if policy is None:
            policy, rank = policy_for(target)
        self.records.append({"rule": value, "kind": kind, "source": source,
                             "target": target, "policy": policy, "rank": rank})

    def classical(self, text, source, domain, inline, ip=None, exclude_ip=False, personal=False):
        if re.search(r"(?m)^payload:\s*$", text):
            doc = yaml.safe_load(text)
            if not isinstance(doc, dict) or set(doc) != {"payload"} or not isinstance(doc["payload"], list):
                raise ValueError("Expected YAML payload list")
            rules = doc["payload"]
        else:
            rules = text.splitlines()
        meaningful = 0
        for raw in rules:
            if not isinstance(raw, str):
                raise ValueError("Non-string payload")
            raw = raw.strip()
            if not raw or raw.startswith(("#", ";", "//")):
                continue
            meaningful += 1
            kind, value = parse_rule(raw)
            if raw.startswith(("IP-CIDR,", "IP-CIDR6,")) and exclude_ip:
                self.stats[source]["input"] += 1
                self.stats[source]["excluded_ip"] += 1
                continue
            if raw.startswith(("IP-CIDR,", "IP-CIDR6,")) and not personal:
                kind, value = "ipcidr", raw.partition(",")[2].split(",")[0].strip()
            if kind == "ipcidr" and ip is None:
                raise ValueError("Unexpected IP in " + source)
            self.add(kind, value, domain if kind == "domain" else ip if kind == "ipcidr" else inline,
                     source, raw, personal)
        if not personal and not meaningful:
            raise ValueError("Empty required source: " + source)

    def collect(self):
        self.pin()
        for name in BASE:
            text = self.fetch("loyal", name + ".txt")
            values = yaml.safe_load(text)["payload"]
            if not values:
                raise ValueError("Empty required source: " + name)
            for value in values:
                self.add("ipcidr" if name.endswith("cidr") else "domain", value.strip(),
                         name, "loyal/" + name)
        text = self.fetch("loyal", "applications.txt")
        self.classical(text, "loyal/applications", "private", "applications")
        acl = [("LocalAreaNetwork", "private", "private", "lancidr", False),
               ("UnBan", "acl-unban-domain", "private", None, False),
               ("BanAD", "reject", "reject", None, False),
               ("ChinaDomain", "direct", "direct", "acl-direct-ipcidr", False),
               ("ProxyGFWlist", "proxy", "proxy", None, True)]
        for file, domain, inline, ip, exclude in acl:
            text = self.fetch("acl", "Clash/" + file + ".list")
            self.classical(text, "acl/" + file, domain, inline, ip, exclude)
        geo = [("private", "private", "private"), ("category-ads-all", "reject", "reject"),
               ("geolocation-!cn", "proxy", "proxy"), ("google", "google", "services"),
               *[(name, "services-proxy", "services") for name in
                 ("telegram", "netflix", "github", "openai", "youtube")]]
        for name, domain, inline in geo:
            text = self.fetch("meta", "geo/geosite/classical/" + name + ".list")
            self.classical(text, "meta/geosite/" + name, domain, inline)
        text = self.fetch("meta", "geo-lite/geosite/classical/cn.list")
        self.classical(text, "meta/geosite/cn-lite", "direct", "direct")
        for name, target in (("private", "lancidr"), ("cn", "cncidr"), ("telegram", "telegramcidr")):
            for line in self.fetch("meta", "geo/geoip/" + name + ".list").splitlines():
                if line.strip() and not line.startswith("#"):
                    self.add("ipcidr", line.strip(), target, "meta/geoip/" + name)
        for direction in ("direct", "proxy"):
            path = ROOT / "personal" / (direction + ".yaml")
            self.sources["personal"]["files"][str(path.relative_to(ROOT)).replace("\\", "/")] = {
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            self.classical(path.read_text(encoding="utf-8"), "personal/" + direction,
                           "personal-" + direction + "-domain", "personal_" + direction,
                           "personal-" + direction + "-ipcidr", personal=True)

    def emit(self):
        self.out.mkdir(exist_ok=True)
        providers, files, coverage = {}, {}, {}
        for name in sorted(set(self.domains) | set(self.ips)):
            behavior = "domain" if name in self.domains else "ipcidr"
            original = self.domains[name] if behavior == "domain" else self.ips[name]
            if behavior == "domain":
                values, covered = prune_domains(original)
            else:
                values, covered = [], []
                for version in (4, 6):
                    nets = [ipaddress.ip_network(x) for x in original if ipaddress.ip_network(x).version == version]
                    values.extend(str(x) for x in ipaddress.collapse_addresses(nets))
            coverage[name] = {"input": len(original), "exact_duplicates": len(original) - len(set(original)),
                              "covered_domains": covered, "output": len(values)}
            if not values:
                continue
            rel = PROVIDERS[name][0]
            output = self.out / rel
            output.parent.mkdir(parents=True, exist_ok=True)
            temp = self.raw / ("convert-" + name + ".yaml")
            temp.write_text(yaml.safe_dump({"payload": values}), encoding="utf-8")
            subprocess.run([self.mihomo, "convert-ruleset", behavior, "yaml", str(temp), str(output)], check=True)
            providers[name] = {"path": rel, "behavior": behavior, "format": "mrs"}
        for section in self.inline:
            self.inline[section] = list(dict.fromkeys(self.inline[section]))
        inline = {"schema_version": 1, "build_id": self.build_id, "sections": self.inline}
        write_json(self.out / "inline-rules.json", inline)
        write_json(self.out / "build-report.json", {"sources": self.stats, "providers": coverage})
        write_json(self.out / "cidr-report.json", self.cidrs)
        write_json(self.out / "conflict-report.json", conflicts(self.records))
        write_json(self.out / "sources.json", self.sources)
        license_dir = self.out / "licenses"
        license_dir.mkdir(exist_ok=True)
        shutil.copy2(ROOT / "NOTICE.md", license_dir / "NOTICE.md")
        for source in REPOS:
            # All original attribution/dependency notices retained at pinned refs.
            if source in ("meta", "loyal"):
                repo = REPOS[source][0]
                sha = json.loads(get(f"https://api.github.com/repos/{repo}/commits/master", True))["sha"]
                self.sources[source]["notice_commit"] = sha
                text = get(f"https://raw.githubusercontent.com/{repo}/{sha}/README.md").decode("utf-8")
                (license_dir / (source + "-LICENSE")).write_bytes(get(f"https://raw.githubusercontent.com/{repo}/{sha}/LICENSE"))
            else:
                text = self.fetch(source, "README.md")
            (license_dir / (source + "-README.md")).write_text(text, encoding="utf-8")
        (license_dir / "acl-LICENSE").write_bytes(get("https://creativecommons.org/licenses/by-sa/4.0/legalcode.txt"))
        write_json(self.out / "sources.json", self.sources)
        # Retain source even when upstream rewrites its release branch.
        with tarfile.open(self.out / "source-archive.tar.gz", "w:gz") as archive:
            for source, info in self.sources.items():
                for rel in info["files"]:
                    path = ROOT / rel if source == "personal" else self.raw / source / rel
                    arc = "builder/" + rel if source == "personal" else "builder/raw/" + source + "/" + rel
                    archive.add(path, arcname=arc)
            for rel in ("scripts/four_sources.py", "runtime/snapshot.py", "runtime/__init__.py",
                        "README.md", "NOTICE.md", "LICENSE"):
                archive.add(ROOT / rel, arcname="builder/" + rel)
            archive.add(self.out / "sources.json", arcname="builder/out/sources.json")
            archive.add(license_dir, arcname="licenses")
        version = subprocess.check_output([self.mihomo, "-v"], text=True).strip()
        for p in self.out.rglob("*"):
            if p.is_file() and p.name != "build-manifest.json":
                data = p.read_bytes()
                files[p.relative_to(self.out).as_posix()] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        manifest = {"schema_version": 1, "build_id": self.build_id, "tag": self.build_id,
                    "created_at": int(time.time()), "core_version": version,
                    "fake_ip_pool": str(POOL), "sources": self.sources,
                    "providers": providers, "files": files,
                    "counts": {source: counts["input"] for source, counts in self.stats.items()},
                    "provider_counts": {n: c["output"] for n, c in coverage.items()}}
        manifest["distribution_license"] = "GPL-3.0; ACL-only collections retain CC-BY-SA-4.0"
        validate_manifest(manifest)
        write_json(self.out / "build-manifest.json", manifest)
        config = {"mixed-port": 0, "mode": "rule", "proxies": [],
                  "proxy-groups": [{"name": "节点选择", "type": "select", "proxies": ["DIRECT"]}]}
        assemble(config, manifest, inline, local_dir=self.out)
        smoke = self.raw / "snapshot-smoke.yaml"
        smoke.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")
        subprocess.run([self.mihomo, "-t", "-d", str(ROOT), "-f", str(smoke)], check=True)
        return manifest

def policy_for(target):
    if target.startswith("personal-direct") or target == "personal_direct":
        return "DIRECT", 2
    if target.startswith("personal-proxy") or target == "personal_proxy":
        return "节点选择", 3
    groups = {"private": ("DIRECT", 4), "lancidr": ("DIRECT", 4),
              "acl-unban-domain": ("DIRECT", 5), "reject": ("REJECT", 6),
              "applications": ("DIRECT", 7), "icloud": ("DIRECT", 7), "apple": ("DIRECT", 7),
              "google": ("节点选择", 8), "services": ("节点选择", 8),
              "services-proxy": ("节点选择", 8), "telegramcidr": ("节点选择", 8),
              "proxy": ("节点选择", 9), "direct": ("DIRECT", 10),
              "acl-direct-ipcidr": ("DIRECT", 10), "cncidr": ("DIRECT", 12)}
    return groups.get(target, ("节点选择", 11))

def conflicts(records):
    index = collections.defaultdict(list)
    for r in records:
        if r["kind"] == "domain":
            index[r["rule"]].append(r)
    result = []
    seen = set()
    origins = {}
    def origin(row):
        key = row["source"] + "/" + row["target"]
        origins[key] = {k: row[k] for k in ("source", "target", "policy", "rank")}
        return key
    for rule, rows in index.items():
        host = rule[2:] if rule.startswith("+.") else rule
        parts = host.split(".")
        matches = rows + [r for i in range(len(parts)) for r in index.get("+." + ".".join(parts[i:]), [])
                          if r not in rows]
        policies = {r["policy"] for r in matches}
        key = (rule, tuple(sorted(policies)))
        if len(policies) > 1 and key not in seen:
            seen.add(key)
            ordered = sorted(matches, key=lambda r: r["rank"])
            result.append({"rule": rule, "winner": origin(ordered[0]),
                           "matches": [{"origin": origin(r), "rule": r["rule"]} for r in ordered]})
    return {"origins": origins, "domain_conflicts": result,
            "limitations": "Keyword/regex/process/IP intersections require core regressions; not exhaustive."}

def guard(manifest, previous):
    if not previous:
        return
    if previous.get("schema_version") != manifest.get("schema_version"):
        raise ValueError("Cannot compare counts across schema channels")
    for field in ("counts", "provider_counts"):
        for name, count in manifest[field].items():
            old = previous.get(field, {}).get(name)
            if old and abs(count - old) / old > .20:
                raise ValueError("Count changed over 20%: " + name)
    for name, p in manifest["providers"].items():
        old = previous.get("files", {}).get(p["path"])
        new = manifest["files"][p["path"]]
        if old and new["size"] > old["size"] * 2:
            raise ValueError("Artifact more than doubled: " + name)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-id", default=os.environ.get("BUILD_ID", "rules-local"))
    parser.add_argument("--mihomo", default=os.environ.get("MIHOMO", "mihomo"))
    parser.add_argument("--offline", action="store_true", help="Recompile previously pinned, hash-verified local inputs")
    args = parser.parse_args()
    b = Builder(args.build_id, args.mihomo)
    b.offline = args.offline
    b.collect()
    b.emit()

if __name__ == "__main__":
    main()
