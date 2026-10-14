#!/usr/bin/env python3
"""Audit complete, pinned upstream trees without deploying their rules.

Requires PyYAML and zstandard (tested with 0.24.0; 0.25.0 is also supported). MRS v1 decoding follows Mihomo's
rules/provider/mrs_reader.go, component/{trie/domain_set,cidr/ipcidr_set}_bin.go
at v1.19.32; --mihomo cross-checks the decoder against the real core.
An upstream projection mismatch is a failed audit, including in unused tables.
"""
import argparse
import collections
import functools
import gzip
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess
import tarfile
import tempfile
import time
import urllib.request

import yaml
import zstandard

REPOS = {"loyal": "Loyalsoldier/clash-rules", "acl": "ACL4SSR/ACL4SSR",
         "meta": "MetaCubeX/meta-rules-dat"}
VERSION = 1
CLASSICAL = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX",
             "IP-CIDR", "IP-CIDR6", "IP-ASN", "PROCESS-NAME", "PROCESS-PATH",
             "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX", "NETWORK", "DST-PORT",
             "SRC-PORT", "SRC-IP-CIDR", "SRC-IP-CIDR6", "UID"}
NON_MIHOMO = {"URL-REGEX", "USER-AGENT"}
ACL_SECTIONS = {"proxy_all", "bypass_all", "proxy_list", "bypass_list", "outbound_block_list"}
PUBLIC_CLOUD = {"amazonaws.com", "cloudfront.net", "azure.com", "azureedge.net",
                "cloudflare.com", "cloudflare.net", "akamai.net", "akamaized.net",
                "akamaihd.net", "akadns.net", "fastly.net", "aliyuncs.com",
                "myqcloud.com", "myhuaweicloud.com", "hwclouds.com"}
METADATA_EXTENSIONS = {".md", ".py", ".sh", ".ini", ".conf", ".bak", ".url",
                       ".crx", ".xpi", ".yml"}
YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
META_MRS_ROOTS = ("geo/geosite/", "geo/geoip/", "geo-lite/geosite/", "geo-lite/geoip/", "asn/")
DOMAIN_PROJECTION_VERSION = "mihomo-v1.19.32-classical-literal-star-v1"
DOMAIN_PROJECTION_SOURCES = [
    "https://github.com/MetaCubeX/mihomo/blob/v1.19.32/rules/common/domain.go",
    "https://github.com/MetaCubeX/mihomo/blob/v1.19.32/rules/common/domain_suffix.go",
    "https://github.com/MetaCubeX/mihomo/blob/v1.19.32/component/trie/domain.go",
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


# Capture the implementation actually loaded at process/module startup. A later
# source edit must not be presented as the implementation of this running audit.
AUDITOR_SHA256 = sha(Path(__file__).read_bytes())


def git_hash(kind, data):
    return hashlib.sha1(kind.encode() + b" " + str(len(data)).encode() + b"\0" + data).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def jsonline(stream, value):
    stream.write(json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n")


def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "clash-rules-mrs-audit"})
    with urllib.request.urlopen(req, timeout=60) as response:
        return json.load(response)


def cached_archive(name, spec, cache, offline):
    repo, commit = spec.get("repository"), spec.get("commit", "")
    if repo != REPOS[name] or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Expected approved repository and immutable SHA: " + name)
    cache.mkdir(parents=True, exist_ok=True)
    path = cache / (name + "-" + commit + ".tar.gz")
    meta_path = path.with_suffix(path.suffix + ".json")
    if path.exists() and meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("commit") != commit or meta.get("repository") != repo or sha(path.read_bytes()) != meta.get("archive_sha256"):
            raise ValueError("Cached archive integrity failure: " + name)
        return path, meta
    if offline:
        raise ValueError("Missing verified offline archive: " + str(path))
    tree = fetch_json(f"https://api.github.com/repos/{repo}/git/commits/{commit}")["tree"]["sha"]
    temporary = path.with_suffix(".partial")
    try:
        req = urllib.request.Request(f"https://codeload.github.com/{repo}/tar.gz/{commit}",
                                     headers={"User-Agent": "clash-rules-mrs-audit"})
        with urllib.request.urlopen(req, timeout=90) as response, temporary.open("wb") as target:
            digest = hashlib.sha256()
            total = 0
            while block := response.read(1024 * 1024):
                total += len(block)
                if total > 512 * 1024 * 1024:
                    raise ValueError("Archive exceeds audit size limit")
                digest.update(block)
                target.write(block)
        meta = {"repository": repo, "commit": commit, "tree_sha": tree,
                "archive_sha256": digest.hexdigest(), "archive_bytes": total}
        os.replace(temporary, path)
        write_json(meta_path, meta)
        return path, meta
    finally:
        temporary.unlink(missing_ok=True)


def root_tree(entries):
    """Reconstruct a Git tree from every archive blob, proving no directory was omitted."""
    directories = collections.defaultdict(dict)
    for path, mode, oid in entries:
        parts = path.split("/")
        parent = "/".join(parts[:-1])
        if parts[-1] in directories[parent]:
            raise ValueError("Duplicate archive path: " + path)
        directories[parent][parts[-1]] = (mode, oid)
        for index in range(len(parts) - 1):
            directories["/".join(parts[:index])].setdefault(parts[index], ("40000", None))
    for directory in sorted(directories, key=lambda x: (x.count("/"), len(x)), reverse=True):
        rows = directories[directory]
        raw = bytearray()
        for name, (mode, oid) in sorted(rows.items(), key=lambda item: (item[0] + ("/" if item[1][0] == "40000" else "")).encode()):
            if oid is None:
                raise ValueError("Incomplete archive directory: " + directory + "/" + name)
            raw.extend(mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(oid))
        oid = git_hash("tree", raw)
        if directory:
            parent, _, name = directory.rpartition("/")
            directories[parent][name] = ("40000", oid)
        else:
            return oid
    raise ValueError("Empty source archive")


def domain_tokens(values):
    """Canonical exact/subdomain-only union, retaining single-label wildcard semantics."""
    tokens = set()
    for value in values:
        value = value.lower()
        if value.startswith("+."):
            tokens.update((value[2:], value[1:]))
        else:
            tokens.add(value)
    suffixes = {x[1:] for x in tokens if x.startswith(".") and "*" not in x}
    result = []
    for token in tokens:
        host = token.lstrip(".")
        parts = host.split(".")
        if any(".".join(parts[i:]) in suffixes for i in range(1, len(parts))):
            continue
        result.append(token)
    return sorted(result)


def ip_intervals(values):
    ranges = []
    for value in values:
        if isinstance(value, tuple):
            ranges.append(value)
        else:
            net = network(value)
            ranges.append((net.version, int(net.network_address), int(net.broadcast_address)))
    result = []
    for version, begin, end in sorted(set(ranges)):
        if result and result[-1][0] == version and begin <= result[-1][2] + 1:
            old = result[-1]
            result[-1] = (version, old[1], max(old[2], end))
        else:
            result.append((version, begin, end))
    return result


def fingerprint(values):
    return sha("\n".join(str(value) for value in values).encode())


@functools.lru_cache(maxsize=131072)
def network(value):
    return ipaddress.ip_network(value, strict=False)


def domain_mrs_value(kind, value):
    """Exact v1.19.32 representation boundary, not a general exclusion fallback.

    Classical DOMAIN/SUFFIX compare literal strings, including '*' characters.
    Domain MRS instead treats a whole-label '*' as a wildcard and rejects a
    partial-label '*'. Neither conversion preserves the classical predicate.
    Keep these exact predicates in the untouched classical source/inline proof.
    DOMAIN-PATTERN already uses the domain-trie grammar and is not reinterpreted.
    """
    if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
        if "*" in value:
            return None
        return "+." + value if kind == "DOMAIN-SUFFIX" else value
    if kind == "DOMAIN-PATTERN":
        return value
    return None


def project(rules):
    domains, ips, other = [], [], []
    domain_generator_count = 0
    for kind, value in rules:
        if kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX"}:
            # ACL's generator writes a domain projection even for keyword/regex-only
            # tables, although those predicates cannot be represented in domain MRS.
            domain_generator_count += 1
        domain = domain_mrs_value(kind, value)
        if domain is not None:
            domains.append(domain)
        elif kind in ("IP-CIDR", "IP-CIDR6"):
            ips.append(value.split(",")[0])
        else:
            other.append((kind, value))
    ds, ip = domain_tokens(domains), ip_intervals(ips)
    return {"domain": fingerprint(ds), "ipcidr": fingerprint(ip),
            "inline": fingerprint(sorted(set(other))), "domain_count": len(ds),
            "ip_range_count": len(ip), "inline_count": len(set(other)),
            "domain_generator_input_count": domain_generator_count}


def parse_predicate(raw, behavior="classical"):
    raw = raw.strip()
    if behavior == "ipcidr":
        net = network(raw)
        return ("IP-CIDR6" if net.version == 6 else "IP-CIDR"), str(net)
    if behavior == "domain":
        if not raw or any(char.isspace() for char in raw) or "/" in raw or "," in raw:
            raise ValueError("Invalid domain-only predicate: " + raw)
        return "DOMAIN-PATTERN", raw.lower()
    kind, sep, value = raw.partition(",")
    kind, value = kind.strip().upper(), value.strip()
    if not sep:
        # ACL publishes both classical and bare CIDR payloads; CIDR syntax is unambiguous.
        try:
            net = network(raw)
        except ValueError:
            pass
        else:
            return ("IP-CIDR6" if net.version == 6 else "IP-CIDR"), str(net)
    if not sep or not value or kind not in CLASSICAL | NON_MIHOMO:
        raise ValueError("Unknown classical predicate: " + raw)
    if kind in ("DOMAIN", "DOMAIN-SUFFIX"):
        if any(char.isspace() for char in value) or "," in value or "/" in value:
            raise ValueError("Invalid classical domain: " + raw)
        value = value.lower()
    elif kind in ("IP-CIDR", "IP-CIDR6"):
        fields = value.split(",")
        if len(fields) > 2 or len(fields) == 2 and fields[1].strip() != "no-resolve":
            raise ValueError("Unknown CIDR option: " + raw)
        net = network(fields[0])
        # Mihomo treats IP-CIDR/IP-CIDR6 as aliases and parses the address itself.
        kind = "IP-CIDR6" if net.version == 6 else "IP-CIDR"
        value = str(net) + (",no-resolve" if len(fields) == 2 else "")
    return kind, value


def behavior_for(source, path):
    if source == "meta":
        if path.startswith("asn/") or "/geoip/" in "/" + path:
            return "classical" if "/classical/" in path else "ipcidr"
        return "classical" if "/classical/" in path else "domain"
    if source == "loyal":
        if path == "applications.txt":
            return "classical"
        return "ipcidr" if path.endswith("cidr.txt") else "domain"
    if path == "Acl/china_ip_list.txt":
        return "ipcidr"
    return "classical"


def text_rules(source, path, data, on_error=None):
    """Yield (physical line, normalized type, normalized value) for all rule text."""
    text = data.decode("utf-8-sig")
    behavior = behavior_for(source, path)
    def predicate(raw, line):
        try:
            return parse_predicate(raw, behavior)
        except ValueError as error:
            if on_error is None:
                raise
            on_error(line, error)
            return "UNPARSED", raw
    if path.endswith(".acl"):
        section = None
        for number, raw in enumerate(text.splitlines(), 1):
            raw = raw.strip()
            if not raw or raw.startswith(("#", ";", "//")):
                continue
            if raw.startswith("["):
                section = raw.strip("[]")
                if section not in ACL_SECTIONS:
                    raise ValueError("Unknown ACL section: " + raw)
                yield number, "ACL-SECTION", section
            else:
                if section is None:
                    raise ValueError("ACL predicate without section")
                # ACL regex grammar is a different engine, kept opaque and excluded.
                yield number, "ACL-PREDICATE", section + ":" + raw
        return
    if path.endswith(".rule"):
        for number, raw in enumerate(text.splitlines(), 1):
            raw = raw.strip()
            if not raw or raw.startswith(("#", ";", "//")):
                continue
            parts = raw.rsplit(None, 1)
            if len(parts) == 2 and parts[1] in {"remoteproxy", "localproxy", "direct", "reject"}:
                yield number, "LEGACY-PROXY-RULE", raw
            elif len(parts) == 2 and not any(c.isspace() for c in parts[0]):
                try:
                    ipaddress.ip_address(parts[1])
                except ValueError:
                    if on_error is None:
                        raise ValueError("Unknown legacy .rule grammar: " + raw)
                    on_error(number, "Unknown legacy .rule grammar: " + raw)
                    yield number, "UNPARSED", raw
                else:
                    yield number, "LEGACY-HOST-OVERRIDE", raw
            else:
                if on_error is None:
                    raise ValueError("Unknown legacy .rule grammar: " + raw)
                on_error(number, "Unknown legacy .rule grammar: " + raw)
                yield number, "UNPARSED", raw
        return
    if path.endswith(".yaml") or re.search(r"(?m)^payload:\s*$", text):
        node = yaml.compose(text, Loader=YAML_LOADER)
        if not isinstance(node, yaml.MappingNode):
            raise ValueError("Expected payload mapping")
        payload = [(k, v) for k, v in node.value if k.value == "payload"]
        if len(payload) != 1 or len(node.value) != 1:
            raise ValueError("Unexpected rule YAML structure")
        if isinstance(payload[0][1], yaml.ScalarNode) and payload[0][1].tag == "tag:yaml.org,2002:null":
            return
        if not isinstance(payload[0][1], yaml.SequenceNode):
            raise ValueError("Unexpected rule YAML payload type")
        for item in payload[0][1].value:
            if not isinstance(item, yaml.ScalarNode) or item.tag != "tag:yaml.org,2002:str":
                raise ValueError("Non-string YAML predicate")
            if not item.value.strip():
                continue
            kind, value = predicate(item.value, item.start_mark.line + 1)
            yield item.start_mark.line + 1, kind, value
    else:
        for number, raw in enumerate(text.splitlines(), 1):
            raw = raw.strip()
            if not raw or raw.startswith(("#", ";", "//")):
                continue
            kind, value = predicate(raw, number)
            yield number, kind, value


class BinaryReader:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def take(self, size):
        if size < 0 or self.offset + size > len(self.data):
            raise ValueError("Truncated/invalid MRS length")
        data = self.data[self.offset:self.offset + size]
        self.offset += size
        return data

    def length(self):
        value = struct.unpack(">q", self.take(8))[0]
        if value < 0:
            raise ValueError("Negative MRS length")
        return value


def decode_mrs(data):
    with zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)) as stream:
        raw = stream.read(128 * 1024 * 1024 + 1)
    if len(raw) > 128 * 1024 * 1024:
        raise ValueError("Oversized MRS")
    reader = BinaryReader(raw)
    if reader.take(4) != b"MRS\x01":
        raise ValueError("Unknown MRS version")
    behavior = reader.take(1)[0]
    count = reader.length()
    reader.take(reader.length())
    if reader.take(1) != b"\x01":
        raise ValueError("Unknown MRS set version")
    if behavior == 1:
        ranges = []
        for _ in range(reader.length()):
            first, last = (ipaddress.IPv6Address(reader.take(16)) for _ in range(2))
            first, last = first.ipv4_mapped or first, last.ipv4_mapped or last
            if first.version != last.version or int(first) > int(last):
                raise ValueError("Invalid MRS IP interval")
            ranges.append((first.version, int(first), int(last)))
        result = {"behavior": "ipcidr", "fingerprint": fingerprint(ip_intervals(ranges)),
                  "count": count, "intervals": ranges}
    elif behavior == 0:
        def words():
            length = reader.length()
            if length == 0 or length > (len(reader.data) - reader.offset) // 8:
                raise ValueError("Empty/oversized MRS bitmap")
            return struct.unpack(">" + "Q" * length, reader.take(length * 8))
        leaves, bitmap = words(), words()
        labels = reader.take(reader.length())
        # LOUDS labels are breadth-first. Each zero creates one child; each one ends a node.
        starts, edges = [0], 0
        for index in range(len(labels) + len(labels) + 2):
            if index // 64 >= len(bitmap):
                break
            if bitmap[index // 64] >> (index % 64) & 1:
                starts.append(edges)
                if len(starts) == len(labels) + 2:
                    break
            else:
                edges += 1
        if edges != len(labels) or len(starts) != len(labels) + 2:
            raise ValueError("Invalid MRS domain trie")
        keys, stack = [], [(0, b"")]
        while stack:
            node, key = stack.pop()
            if node // 64 < len(leaves) and leaves[node // 64] >> (node % 64) & 1:
                keys.append(key.removesuffix(b"+").decode("utf-8")[::-1])
            for edge in range(starts[node], starts[node + 1]):
                stack.append((edge + 1, key + labels[edge:edge + 1]))
        result = {"behavior": "domain", "fingerprint": fingerprint(domain_tokens(keys)),
                  "count": count, "domains": keys}
    else:
        raise ValueError("Unsupported MRS behavior: " + str(behavior))
    if reader.offset != len(raw):
        raise ValueError("Unexpected trailing MRS data")
    return result


def core_cross_check(mihomo):
    version = subprocess.check_output([mihomo, "-v"], text=True).strip()
    if not re.search(r"\bv1\.19\.32\b", version):
        raise ValueError("Audit projection semantics require pinned Mihomo v1.19.32")
    samples = {"domain": ["exact.example", ".only.example", "+.both.example", "*.wild.example",
                          "child.both.example", "+.child.both.example"],
               "ipcidr": ["192.0.2.0/25", "192.0.2.128/25", "2001:db8::/32"]}
    with tempfile.TemporaryDirectory(prefix="mrs-audit-core-") as directory:
        for behavior, rules in samples.items():
            source, target, dumped = (Path(directory) / n for n in ("input.txt", "output.mrs", "dump.txt"))
            source.write_text("\n".join(rules), encoding="utf-8")
            subprocess.run([mihomo, "convert-ruleset", behavior, "text", str(source), str(target)], check=True, capture_output=True)
            decoded = decode_mrs(target.read_bytes())
            expected = fingerprint(domain_tokens(rules) if behavior == "domain" else ip_intervals(rules))
            if decoded["fingerprint"] != expected:
                raise ValueError("MRS decoder failed real-core " + behavior + " cross-check")
            subprocess.run([mihomo, "convert-ruleset", behavior, "mrs", str(target), str(dumped)], check=True, capture_output=True)
            values = dumped.read_text(encoding="utf-8").splitlines()
            if fingerprint(domain_tokens(values) if behavior == "domain" else ip_intervals(values)) != expected:
                raise ValueError("MRS core round-trip changed fixture semantics")
        # The fixed core rejects partial-label '*' in domain collections. A
        # converter may log and skip them, so prove the resulting effective set
        # contains only the valid control rather than trusting the exit code.
        source.write_text("safe.example\ncdn*.i-scmp.com\n+.*2.bahamut.com.tw\n", encoding="utf-8")
        subprocess.run([mihomo, "convert-ruleset", "domain", "text", str(source), str(target)], check=True, capture_output=True)
        if decode_mrs(target.read_bytes())["fingerprint"] != fingerprint(domain_tokens(["safe.example"])):
            raise ValueError("Pinned core partial-wildcard representation boundary changed")
        config = Path(directory) / "aliases.yaml"
        config.write_text("mixed-port: 0\nmode: rule\nrules:\n  - IP-CIDR,2001:db8::/32,DIRECT\n"
                          "  - IP-CIDR6,192.0.2.0/24,DIRECT\n"
                          "  - DOMAIN-SUFFIX,cdn*.i-scmp.com,DIRECT\n"
                          "  - DOMAIN,*.wild.example,DIRECT\n  - MATCH,DIRECT\n", encoding="utf-8")
        subprocess.run([mihomo, "-t", "-d", directory, "-f", str(config)], check=True, capture_output=True)
    return version


def classify(source, path):
    suffix = PurePosixPath(path).suffix.lower()
    if suffix == ".mrs":
        return "mrs"
    if source == "meta":
        if suffix not in {".list", ".yaml"}:
            raise ValueError("Unknown Meta archive file: " + path)
        return "rules"
    if source == "loyal":
        if suffix != ".txt":
            raise ValueError("Unknown Loyal release file: " + path)
        return "rules"
    if suffix in {".list", ".yaml", ".acl", ".rule"} or path == "Acl/china_ip_list.txt":
        return "rules"
    if suffix in METADATA_EXTENSIONS or path in {"LICENCE", "LICENSE"} or path.startswith("Tool/"):
        return "non_rule_metadata_or_tool"
    raise ValueError("Unknown archive file classification: " + path)


def policy_hint(source, path):
    name = PurePosixPath(path).stem.lower()
    if name in {"reject", "category-ads-all"} or name.startswith(("banad", "banprogram", "baneasy")):
        return "reject"
    if name in {"direct", "cn", "geolocation-cn", "chinadomain", "unban", "googlecn"}:
        return "direct"
    if name in {"proxy", "geolocation-!cn", "proxygfwlist", "proxylite", "gfw", "greatfire", "tld-not-cn"}:
        return "proxy"
    return None


def repair_path(value):
    """Portable archive/overlay path, never an absolute or alternate-stream path."""
    if (not isinstance(value, str) or not value or "\\" in value or ":" in value or
            any(c in value for c in "\r\n\0") or value.startswith("/") or
            any(part in {"", ".", ".."} for part in value.split("/"))):
        raise ValueError("Unsafe repair path: " + repr(value))
    return value


def canonical_mrs_input(source, path, behavior, by_file):
    """Select the same upstream generator input used by strict projections."""
    if source == "meta" and path.startswith(META_MRS_ROOTS):
        expected = behavior_for(source, path)
        if expected not in {"domain", "ipcidr"} or behavior != expected:
            raise ValueError("Repair behavior differs from Meta derived path")
        return path[:-4] + ".list"
    if source == "acl" and path.startswith("Clash/"):
        name = PurePosixPath(path).stem
        suffix = "_domain" if behavior == "domain" else "_ip"
        if not name.endswith(suffix):
            raise ValueError("Repair behavior differs from ACL derived basename")
        base = name[:-len(suffix)]
        candidates = [f"Clash/Providers/{base}.yaml", f"Clash/Providers/Ruleset/{base}.yaml", f"Clash/Ruleset/{base}.list"]
        count_key = "domain_generator_input_count" if behavior == "domain" else "ip_range_count"
        existing = [p for p in candidates if (source, p) in by_file and
                    by_file[(source, p)].get("projection", {}).get(count_key, 0) > 0]
        if existing:
            return existing[-1]
        raise ValueError("Repair has no canonical ACL generator input")
    raise ValueError("Repair target is not a registered derived MRS path")


class RepairOverlay:
    """Read-only, hash-pinned replacement of derived binaries, never source text."""
    def __init__(self, directory, sources):
        self.directory = Path(directory).resolve()
        manifest_path = self.directory / "manifest.json"
        if manifest_path.is_symlink():
            raise ValueError("Repair manifest cannot be a symlink")
        self.raw = manifest_path.read_bytes()
        self.manifest = json.loads(self.raw)
        self.manifest_sha256 = sha(self.raw)
        if self.manifest.get("schema_version") != 1 or type(self.manifest.get("schema_version")) is not int:
            raise ValueError("Unknown repair manifest schema")
        if self.manifest.get("status") != "repaired":
            raise ValueError("Repair manifest must have completed status=repaired")
        pins = self.manifest.get("sources")
        if not isinstance(pins, dict) or not pins or not set(pins) <= set(REPOS):
            raise ValueError("Repair manifest requires approved pinned sources")
        for source, spec in pins.items():
            expected = sources.get(source, {})
            if (not isinstance(spec, dict) or spec.get("repository") != REPOS[source] or
                    not re.fullmatch(r"[0-9a-f]{40}", spec.get("commit", "")) or
                    any(spec.get(k) != expected.get(k) for k in ("repository", "commit"))):
                raise ValueError("Repair source revision mismatch: " + source)
        rows = self.manifest.get("repairs")
        if not isinstance(rows, list):
            raise ValueError("Repair manifest requires an explicit repairs list")
        self.entries, self.hits, self.archives, self.started_archives = {}, collections.Counter(), set(), set()
        fixed_paths = set()
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("Malformed repair registration")
            source, path = row.get("source"), repair_path(row.get("path"))
            if source not in pins or not path.endswith(".mrs") or row.get("behavior") not in {"domain", "ipcidr"}:
                raise ValueError("Only pinned derived .mrs files may be repaired")
            if not ((source == "meta" and path.startswith(META_MRS_ROOTS)) or
                    (source == "acl" and path.startswith("Clash/"))):
                raise ValueError("Repair target is not a registered derived MRS path")
            canonical = repair_path(row.get("canonical_path"))
            if not canonical.endswith((".list", ".yaml")) or classify(source, canonical) != "rules":
                raise ValueError("Repair canonical input must be original rule text")
            fixed = repair_path(row.get("fixed_path"))
            if not fixed.endswith(".mrs") or fixed in fixed_paths or (source, path) in self.entries:
                raise ValueError("Duplicate or non-MRS repair registration")
            for field in ("original_sha256", "canonical_sha256", "fixed_sha256"):
                if not re.fullmatch(r"[0-9a-f]{64}", row.get(field, "")):
                    raise ValueError("Invalid repair hash: " + field)
            for field in ("expected_fingerprint", "core_decode_fingerprint", "roundtrip_fingerprint"):
                if field in row and row[field] is not None and not re.fullmatch(r"[0-9a-f]{64}", row[field]):
                    raise ValueError("Invalid repair projection proof: " + field)
            self.entries[(source, path)] = dict(row)
            fixed_paths.add(fixed)
            # Verify every registered file, even if its upstream path never appears.
            self.fixed_bytes(row)

    def fixed_bytes(self, row):
        path = self.directory / row["fixed_path"]
        if any(p.is_symlink() for p in [path, *path.parents] if p != self.directory.parent):
            raise ValueError("Repair artifact cannot be a symlink")
        if self.directory not in path.resolve().parents:
            raise ValueError("Repair artifact escaped its directory")
        data = path.read_bytes()
        if sha(data) != row["fixed_sha256"]:
            raise ValueError("Repair artifact hash mismatch: " + row["fixed_path"])
        return data

    def archive(self, source, meta):
        if source not in self.manifest["sources"]:
            return
        spec = self.manifest["sources"][source]
        if any(meta.get(k) != spec[k] for k in ("repository", "commit")):
            raise ValueError("Repair overlay does not match original archive revision: " + source)
        self.started_archives.add(source)

    def apply(self, source, path, data, mode):
        row = self.entries.get((source, path))
        if row is None:
            return data, None
        self.hits[(source, path)] += 1
        if self.hits[(source, path)] != 1:
            raise ValueError("Repair registration matched more than once")
        if source not in self.started_archives or mode not in {"100644", "100755"}:
            raise ValueError("Repair requires the registered original regular archive blob")
        if sha(data) != row["original_sha256"]:
            raise ValueError("Repair original blob hash mismatch: " + path)
        fixed = self.fixed_bytes(row)
        return fixed, {**row, "manifest_sha256": self.manifest_sha256,
                       "source_commit": self.manifest["sources"][source]["commit"],
                       "canonical_projection_verified": False}

    def verify(self, audit):
        for source in set(self.manifest["sources"]) - self.archives:
            audit.error(source, "", "Repair source archive was not fully visited")
        for (source, path), row in self.entries.items():
            try:
                if source not in self.archives:
                    raise ValueError("Original archive Git tree was not verified for repair")
                if self.hits[(source, path)] != 1:
                    raise ValueError("Repair registration did not match exactly one original blob")
                entry = audit.by_file.get((source, path), {})
                if entry.get("classification") != "mrs" or not entry.get("repair"):
                    raise ValueError("Repair binary failed effective-file validation")
                if entry.get("behavior") != row["behavior"]:
                    raise ValueError("Repair binary behavior mismatch")
                canonical = canonical_mrs_input(source, path, row["behavior"], audit.by_file)
                if canonical != row["canonical_path"]:
                    raise ValueError("Repair canonical path differs from the upstream generator input")
                original = audit.by_file.get((source, canonical), {})
                if (original.get("classification") != "rules" or original.get("parse_errors", 0) or
                        original.get("sha256") != row["canonical_sha256"]):
                    raise ValueError("Repair canonical text is missing, changed or invalid")
                expected = original["projection"][row["behavior"]]
                if entry["fingerprint"] != expected:
                    raise ValueError("Repair semantic projection still differs from canonical text")
                for field in ("expected_fingerprint", "core_decode_fingerprint", "roundtrip_fingerprint"):
                    if row.get(field) is not None and row[field] != expected:
                        raise ValueError("Repair projection proof disagrees with audited text: " + field)
                if "retained_inline_count" in row and row["retained_inline_count"] != original["projection"]["inline_count"]:
                    raise ValueError("Repair retained inline count differs from untouched canonical text")
                entry["repair"]["canonical_projection_verified"] = True
                entry["repair"]["verified_fingerprint"] = expected
            except (ValueError, KeyError, TypeError) as error:
                audit.error(source, path, error)

    def summary(self, audit):
        verified = sum(bool(item.get("repair", {}).get("canonical_projection_verified")) for item in audit.inventory)
        return {"manifest_sha256": self.manifest_sha256, "registered": len(self.entries),
                "applied": sum(self.hits.values()), "verified": verified,
                "tree_verification_scope": "original_upstream_archive_only"}


class Audit:
    def __init__(self, output, consumed_inputs=(), repairs=None):
        self.output = output
        output.mkdir(parents=True, exist_ok=True)
        self.inventory, self.errors, self.projections = [], [], []
        self.by_file, self.mrs_cache, self.file_index = {}, {}, {}
        self.consumed_inputs = set(consumed_inputs)
        self.repairs = repairs
        self.auditor_sha256 = AUDITOR_SHA256
        self._repair_verified = False
        self.counts, self.exclusions, self.risk_counts = collections.Counter(), collections.Counter(), collections.Counter()
        self.domains = collections.defaultdict(dict)
        self.rule_stream = gzip.open(output / "rules.jsonl.gz", "wt", encoding="utf-8", compresslevel=4)
        self.risk_stream = gzip.open(output / "risks.jsonl.gz", "wt", encoding="utf-8", compresslevel=4)

    def error(self, source, path, error):
        entry = self.file_index.get((source, path), {})
        self.errors.append({"source": source, "path": path, "error": str(error),
                            "sha256": entry.get("sha256"),
                            "consumed_by_existing_builder": (source, path) in self.consumed_inputs})

    def risk(self, kind, **fields):
        self.risk_counts[kind] += 1
        jsonline(self.risk_stream, dict(kind=kind, **fields))

    def predicate(self, source, path, line, kind, value):
        non_mihomo = kind in NON_MIHOMO or kind.startswith(("ACL-", "LEGACY-"))
        reason = "different_rule_engine_not_imported" if non_mihomo else "audit_reference_not_automatically_deployed"
        if kind == "UNPARSED":
            reason = "unknown_semantics_blocks_audit"
        if kind in {"DOMAIN", "DOMAIN-SUFFIX"} and "*" in value:
            reason = "classical_literal_star_preserved_not_representable_as_domain_mrs"
            self.risk("classical_domain_not_mrs_representable", source=source, path=path, line=line,
                      type=kind, value=value, projection_version=DOMAIN_PROJECTION_VERSION,
                      disposition="preserved_in_untouched_classical_source")
        if kind in {"PROCESS-NAME", "PROCESS-PATH", "DOMAIN-KEYWORD"}:
            reason = "broad_predicate_requires_explicit_local_selection"
            self.risk("broad_predicate", source=source, path=path, line=line, type=kind, value=value)
        if source == "meta" and path.startswith("asn/"):
            reason = "global_asn_inventory_not_a_routing_policy"
        self.exclusions[reason] += 1
        self.counts["rules"] += 1
        self.counts[source + "/rules"] += 1
        self.counts["type/" + kind] += 1
        jsonline(self.rule_stream, {"source": source, "path": path, "line": line,
                                   "type": kind, "value": value, "disposition": "reference_only", "reason": reason})
        if kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-PATTERN"}:
            domain = ("+." + value) if kind == "DOMAIN-SUFFIX" else value
            host = domain.removeprefix("+.").lstrip(".")
            if domain.startswith(("+.", ".")) and (host in PUBLIC_CLOUD or "." not in host):
                self.risk("broad_domain_suffix", source=source, path=path, line=line, value=domain)
            hint = policy_hint(source, path)
            if hint:
                self.domains[domain].setdefault(hint, {"source": source, "path": path, "line": line})
        if non_mihomo:
            self.counts["explicit_non_mihomo_predicates"] += 1

    def file(self, source, path, data, mode):
        original_sha = sha(data)
        entry = {"source": source, "path": path, "bytes": len(data), "sha256": original_sha,
                 "original_sha256": original_sha, "effective_sha256": original_sha, "git_mode": mode}
        self.inventory.append(entry)
        self.file_index[(source, path)] = entry
        entry["consumed_by_existing_builder"] = (source, path) in self.consumed_inputs
        try:
            if self.repairs:
                data, proof = self.repairs.apply(source, path, data, mode)
                if proof:
                    entry.update(effective_sha256=sha(data), effective_bytes=len(data), repair=proof)
            category = entry["classification"] = classify(source, path)
            if category == "non_rule_metadata_or_tool":
                entry["reason"] = "repository_documentation_build_config_or_other_client_tool"
                self.exclusions[entry["reason"]] += 1
                return
            if category == "mrs":
                key = entry["effective_sha256"]
                if key not in self.mrs_cache:
                    decoded = decode_mrs(data)
                    self.mrs_cache[key] = {k: v for k, v in decoded.items() if k not in {"domains", "intervals"}}
                entry.update(self.mrs_cache[key])
                self.counts["mrs_files_decoded"] += 1
            else:
                rules = []
                before_errors = len(self.errors)
                def parse_error(line, error):
                    self.error(source, path, "line " + str(line) + ": " + str(error))
                for line, kind, value in text_rules(source, path, data, on_error=parse_error):
                    self.predicate(source, path, line, kind, value)
                    rules.append((kind, value))
                entry["rule_count"] = len(rules)
                entry["projection"] = project(rules)
                entry["parse_errors"] = len(self.errors) - before_errors
                self.counts["text_files_parsed"] += 1
            self.by_file[(source, path)] = entry
        except (OSError, ValueError, UnicodeError, yaml.YAMLError, struct.error, zstandard.ZstdError) as error:
            entry["classification"] = "failed"
            self.error(source, path, error)

    def archive(self, source, path, meta):
        if self.repairs:
            self.repairs.archive(source, meta)
        entries, seen, root = [], set(), None
        with tarfile.open(path, "r|gz") as archive:
            for member in archive:
                parts = PurePosixPath(member.name).parts
                if not parts or ".." in parts or PurePosixPath(member.name).is_absolute():
                    raise ValueError("Unsafe archive path")
                root = root or parts[0]
                if parts[0] != root:
                    raise ValueError("Multiple archive roots")
                if member.isdir():
                    continue
                rel = "/".join(parts[1:])
                if not rel or rel in seen:
                    raise ValueError("Duplicate/empty archive member")
                seen.add(rel)
                if member.issym():
                    data, mode = member.linkname.encode(), "120000"
                elif member.isfile():
                    data = archive.extractfile(member).read()
                    mode = "100755" if member.mode & 0o111 else "100644"
                else:
                    raise ValueError("Unsupported archive member type: " + rel)
                entries.append((rel, mode, git_hash("blob", data)))
                self.file(source, rel, data, mode)
                if len(seen) % 25000 == 0:
                    print(source + ": " + str(len(seen)) + " files audited", flush=True)
        actual = root_tree(entries)
        if actual != meta["tree_sha"]:
            raise ValueError("Complete Git tree mismatch: " + source + " expected " + meta["tree_sha"] + " got " + actual)
        if self.repairs and source in self.repairs.manifest["sources"]:
            self.repairs.archives.add(source)
        return {**meta, "files": len(entries), "tree_sha_verified": actual,
                "tree_verification_scope": "original_upstream_archive"}

    def compare(self, source, left_path, right_path, projection, relation, required=True):
        left = self.by_file.get((source, left_path))
        right = self.by_file.get((source, right_path))
        if not left or not right:
            self.error(source, left_path, "Missing required projection counterpart: " + right_path)
            return
        lhs = left.get("fingerprint") if left["classification"] == "mrs" else left["projection"][projection]
        rhs = right.get("fingerprint") if right["classification"] == "mrs" else right["projection"][projection]
        matches = lhs == rhs
        self.projections.append({"source": source, "left": left_path, "right": right_path,
                                 "left_sha256": left.get("effective_sha256", left["sha256"]),
                                 "right_sha256": right.get("effective_sha256", right["sha256"]),
                                 "left_original_sha256": left["sha256"], "right_original_sha256": right["sha256"],
                                 "projection": projection, "relation": relation, "equal": matches,
                                 "required_equal": required})
        if not matches and required:
            self.error(source, left_path, projection + " projection differs from " + right_path)
        elif not matches:
            self.risk("independently_maintained_tables_differ", source=source, left=left_path,
                      right=right_path, projection=projection)

    def verify_projections(self):
        for (source, path), item in list(self.by_file.items()):
            if source == "meta":
                if path.endswith(".yaml"):
                    self.compare(source, path, path[:-5] + ".list", "inline", "same_text_representation")
                    for field in ("domain", "ipcidr"):
                        self.compare(source, path, path[:-5] + ".list", field, "same_text_representation")
                elif path.endswith(".mrs"):
                    self.compare(source, path, path[:-4] + ".list", item["behavior"], "binary_projection")
                elif "/classical/" in path and path.endswith(".list"):
                    behavior = "ipcidr" if "/geoip/" in "/" + path else "domain"
                    self.compare(source, path, path.replace("/classical/", "/"), behavior, "classical_representable_projection")
            elif source == "acl" and path.endswith(".mrs"):
                name = PurePosixPath(path).stem
                if not name.endswith(("_domain", "_ip")):
                    self.error(source, path, "Unknown ACL MRS naming/projection convention")
                    continue
                base = name.rsplit("_", 1)[0]
                candidates = [f"Clash/Providers/{base}.yaml", f"Clash/Providers/Ruleset/{base}.yaml", f"Clash/Ruleset/{base}.list"]
                count_key = "domain_generator_input_count" if item["behavior"] == "domain" else "ip_range_count"
                existing = [candidate for candidate in candidates if (source, candidate) in self.by_file
                            and self.by_file[(source, candidate)]["projection"][count_key] > 0]
                if not existing:
                    self.error(source, path, "Missing ACL MRS original text")
                if existing:
                    # Upstream update.yml converts Providers, then Providers/Ruleset,
                    # then Ruleset; the last nonempty source overwrites this basename.
                    self.compare(source, path, existing[-1], item["behavior"], "binary_representable_projection")
            elif source == "acl" and path.startswith("Clash/Providers/") and path.endswith(".yaml"):
                name = PurePosixPath(path).stem
                # Independently maintained top-level lists are not assumed equivalent.
                candidate = "Clash/Ruleset/" + name + ".list"
                if (source, candidate) in self.by_file:
                    for field in ("domain", "ipcidr", "inline"):
                        self.compare(source, path, candidate, field, "independently_maintained_same_name", required=False)
        if self.repairs:
            self.repairs.verify(self)
            self._repair_verified = True

    def conflicts(self):
        for domain, origin in self.domains.items():
            policies = dict(origin)
            host = domain.removeprefix("+.").lstrip(".")
            parts = host.split(".")
            for index in range(len(parts)):
                suffix = "+." + ".".join(parts[index:])
                for policy, where in self.domains.get(suffix, {}).items():
                    policies.setdefault(policy, where)
            if len(policies) > 1:
                self.risk("opposing_upstream_classifications", domain=domain, policy_hints=policies,
                          interpretation="upstream overlap, not a proven runtime failure")

    def finish(self, sources, core):
        if self.repairs and not self._repair_verified:
            self.error("audit", "", "Effective repair projection verification did not complete")
            self.repairs.verify(self)
        self.rule_stream.close()
        self.risk_stream.close()
        execution = {"auditor_sha256": self.auditor_sha256, "core_version": core,
                     "evaluation_scope": "upstream-with-verified-repairs" if self.repairs else "original",
                     "domain_projection_version": DOMAIN_PROJECTION_VERSION,
                     "domain_projection_sources": DOMAIN_PROJECTION_SOURCES}
        if self.repairs:
            execution["repair_overlay"] = self.repairs.summary(self)
            (self.output / "repair-manifest.json").write_bytes(self.repairs.raw)
        write_json(self.output / "manifest.json", {"schema_version": VERSION,
                   "status": "failed" if self.errors else "passed", "sources": sources, "files": self.inventory, **execution})
        write_json(self.output / "projection-report.json", self.projections)
        write_json(self.output / "exclusions.json", dict(self.exclusions))
        write_json(self.output / "errors.json", self.errors)
        result = {"schema_version": VERSION, "status": "failed" if self.errors else "passed",
                  **execution,
                  "mihomo": core, "counts": dict(self.counts), "risk_counts": dict(self.risk_counts),
                  "files": len(self.inventory), "projection_comparisons": len(self.projections),
                  "projection_mismatches": sum(not p["equal"] and p["required_equal"] for p in self.projections),
                  "independent_table_differences": sum(not p["equal"] and not p["required_equal"] for p in self.projections),
                  "errors": len(self.errors), "sources": sources,
                  "limitations": ["Static audit does not prove endpoint reachability or absence of DNS leaks.",
                                  "All upstream rules are references; deployment selection is a separate manifest.",
                                  "ACL and legacy client predicates are preserved and explicitly excluded, not translated.",
                                  "Keyword/regex/process intersections are flagged, not claimed exhaustively solved."]}
        write_json(self.output / "summary.json", result)
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", required=True, type=Path)
    parser.add_argument("--mihomo", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cache", type=Path, default=Path(".cache/audit"))
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--repairs", type=Path, help="Read-only registered derived-MRS repair overlay")
    args = parser.parse_args(argv)
    sources = json.loads(args.sources.read_text(encoding="utf-8-sig"))
    if "sources" in sources:
        sources = sources["sources"]
    consumed = {(source, path) for source, spec in sources.items() for path in spec.get("files", {})}
    overlay = None
    if args.repairs:
        output, repair_dir = args.output.resolve(), args.repairs.resolve()
        if output == repair_dir or repair_dir in output.parents:
            raise ValueError("Repaired audit output must not modify its repair input directory")
        if output.exists() and any(not p.is_dir() or p.name not in {"original", "repairs"} for p in output.iterdir()):
            raise ValueError("Repaired audit requires fresh output; existing original/repairs subdirectories may be retained")
        overlay = RepairOverlay(args.repairs, sources)
    audit, verified, core = Audit(args.output, consumed, repairs=overlay), {}, "not verified"
    try:
        core = core_cross_check(str(Path(args.mihomo).resolve()) if Path(args.mihomo).exists() else args.mihomo)
        for name in REPOS:
            print("Auditing complete pinned tree: " + name, flush=True)
            archive, meta = cached_archive(name, sources[name], args.cache, args.offline)
            verified[name] = audit.archive(name, archive, meta)
        audit.verify_projections()
        audit.conflicts()
    except Exception as error:
        audit.error("audit", "", error)
    result = audit.finish(verified, core)
    print(json.dumps({k: result[k] for k in ("status", "files", "projection_comparisons", "projection_mismatches", "errors")}), flush=True)
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
