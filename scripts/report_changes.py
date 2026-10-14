"""Compare a rebuilt v1 policy with v2, without claiming an online traffic replay.

Every MRS in the baseline is hash checked and decoded by the full-source auditor.
Domain rows describe the first hostname predicate (or the eventual MATCH), not
the final connection policy: IP, process, port and unproved regex predicates can
intervene. Exact/suffix partitions get boundary witnesses; arbitrary regex and
keyword languages are deliberately not described as exhaustively enumerated.
"""
import collections
import hashlib
import ipaddress
import itertools
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from audit_sources import decode_mrs, ip_intervals, parse_predicate
from runtime import snapshot

GROUP = "节点选择"
DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX"}
CONTEXT_TYPES = {"IP-CIDR", "IP-CIDR6", "IP-ASN", "PROCESS-NAME", "PROCESS-PATH",
                 "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX", "NETWORK", "DST-PORT",
                 "SRC-PORT", "SRC-IP-CIDR", "SRC-IP-CIDR6", "UID"}


def _chain(manifest, inline):
    """Mirror the public assembler's ordered predicates; fail on unknown input."""
    version = manifest.get("schema_version")
    if version not in (1, 2) or type(version) is not int:
        raise ValueError("Unknown snapshot schema in change comparison")
    if version == 2 and manifest.get("policy_version") != "balanced-v2":
        raise ValueError("Unknown v2 policy in change comparison")
    if inline.get("schema_version") != version or inline.get("build_id") != manifest.get("build_id"):
        raise ValueError("Inline identity differs in change comparison")
    registry = snapshot.V2_PROVIDERS if version == 2 else snapshot.PROVIDERS
    required = snapshot.V2_REQUIRED if version == 2 else set(snapshot.BASE) | {"acl-unban-domain", "services-proxy"}
    providers = manifest["providers"]
    if not required <= set(providers) <= set(registry):
        raise ValueError("Missing or unknown provider in change comparison")
    for name, provider in providers.items():
        path, behavior = registry[name]
        if provider != {"path": path, "behavior": behavior, "format": "mrs"}:
            raise ValueError("Unknown provider contract: " + name)
    expected = snapshot.V2_SECTIONS if version == 2 else snapshot.SECTIONS
    if set(inline.get("sections", {})) != set(expected):
        raise ValueError("Unknown inline section in change comparison")
    rules = []

    def add(kind, value, action, *, no_resolve=False, section=None):
        text = kind + ("," + value if value else "") + "," + action
        if no_resolve:
            text += ",no-resolve"
        rules.append({"index": len(rules), "rule": text, "type": kind,
                      "value": value, "policy": action, "no_resolve": no_resolve,
                      "section": section})

    def provider(name, action):
        if name in providers:
            resolve = name.startswith("personal-") or (version == 2 and name == "cn-ipcidr")
            add("RULE-SET", name, action, no_resolve=providers[name]["behavior"] == "ipcidr" and not resolve)

    def section(name, action):
        for raw in inline["sections"][name]:
            if not isinstance(raw, str) or "\n" in raw or "\r" in raw:
                raise ValueError("Malformed inline rule in change comparison")
            kind, value = parse_predicate(raw)
            if kind not in DOMAIN_TYPES | CONTEXT_TYPES:
                raise ValueError("Unknown inline rule type: " + kind)
            if version == 2 and not name.startswith("personal_") and kind not in DOMAIN_TYPES:
                raise ValueError("Unapproved upstream connection predicate in v2: " + raw)
            no_resolve = kind in {"IP-CIDR", "IP-CIDR6"} and value.endswith(",no-resolve")
            if no_resolve:
                value = value[:-11]
            add(kind, value, action, no_resolve=no_resolve, section=name)

    add("DOMAIN", "localhost", "DIRECT")
    add("IP-CIDR", "127.0.0.0/8", "DIRECT", no_resolve=True)
    add("IP-CIDR6", "::1/128", "DIRECT", no_resolve=True)
    for direction, action in (("direct", "DIRECT"), ("proxy", GROUP)):
        for behavior in ("domain", "ipcidr"):
            provider("personal-" + direction + "-" + behavior, action)
        section("personal_" + direction, action)
    if version == 2:
        provider("private-domain", "DIRECT")
        provider("private-ipcidr", "DIRECT")
        section("private", "DIRECT")
        provider("services-proxy", GROUP)
        section("services", GROUP)
        provider("telegram-ipcidr", GROUP)
        provider("cn-domain", "DIRECT")
        section("direct", "DIRECT")
        provider("cn-ipcidr", "DIRECT")
    else:
        provider("private", "DIRECT")
        provider("lancidr", "DIRECT")
        section("private", "DIRECT")
        provider("acl-unban-domain", "DIRECT")
        provider("reject", "REJECT")
        section("reject", "REJECT")
        section("applications", "DIRECT")
        provider("icloud", "DIRECT")
        provider("apple", "DIRECT")
        provider("google", GROUP)
        provider("services-proxy", GROUP)
        section("services", GROUP)
        provider("telegramcidr", GROUP)
        provider("proxy", GROUP)
        section("proxy", GROUP)
        provider("direct", "DIRECT")
        section("direct", "DIRECT")
        provider("acl-direct-ipcidr", "DIRECT")
        for name in ("gfw", "greatfire", "tld-not-cn"):
            provider(name, GROUP)
        provider("cncidr", "DIRECT")
    add("MATCH", "", GROUP)
    return rules


def _regex(value):
    # Mihomo 1.19.32 uses case-insensitive regexp2. Evaluate only a small ASCII
    # subset shared with Python, leaving engine-specific constructs unresolved;
    # nested quantified groups could also cause Python backtracking blow-ups.
    if (not value.isascii() or "(?" in value or
            re.search(r"\\(?![dDsSwW.\-\\^$*+?{}\[\]()|/])", value) or
            re.search(r"\)[*+?{]", value)):
        return None
    try:
        return re.compile(value, re.ASCII | re.IGNORECASE)
    except re.error:
        return None


class DomainChain:
    def __init__(self, rules, providers, domain_index):
        self.rules, self.exact, self.suffix = rules, {}, {}
        self.extra, self.uncertainties, self.anchors = [], [], set()
        self.pattern_witnesses = set()
        for rule in rules:
            kind, value, index = rule["type"], rule["value"], rule["index"]
            if kind == "RULE-SET":
                if providers[value]["behavior"] == "domain":
                    for domain in domain_index[value]:
                        self.add(domain, index)
                else:
                    self.uncertain(rule, "IP rule needs destination address/resolution context")
            elif kind == "DOMAIN":
                self.add(value, index)
            elif kind == "DOMAIN-SUFFIX":
                self.add("+." + value, index)
            elif kind == "DOMAIN-KEYWORD":
                self.extra.append((index, "keyword", value.lower()))
                self.uncertain(rule, "Keyword evaluated on every witness; its infinite language is not exhaustively witnessed", contextual=False)
                if re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*", value.lower()):
                    self.pattern_witnesses.add(value.lower() + ".keyword-witness.invalid")
            elif kind == "DOMAIN-REGEX":
                compiled = _regex(value)
                if compiled is None:
                    self.uncertain(rule, "Complex regex equivalence/matching is not proved by this static evaluator")
                else:
                    self.extra.append((index, "regex", compiled))
                    self.uncertain(rule, "Case-insensitive ASCII subset evaluated with Python; arbitrary Mihomo regexp2 language coverage is not proved", contextual=False)
            elif kind in CONTEXT_TYPES:
                self.uncertain(rule, "Connection-only predicate needs IP/process/port/network/UID context")
            elif kind != "MATCH":
                raise ValueError("Unknown routing predicate: " + kind)
        self.extra.sort(key=lambda entry: entry[0])
        unresolved = [u["rule_index"] for u in self.uncertainties if u["can_preempt_witness"]]
        self.first_unresolved = min(unresolved, default=len(rules))

    def uncertain(self, rule, reason, contextual=True):
        self.uncertainties.append({"rule_index": rule["index"], "reason": reason,
                                   "can_preempt_witness": contextual})

    def add(self, value, index):
        if (not isinstance(value, str) or not value or
                any(c in value for c in ",\r\n /\\")):
            raise ValueError("Malformed domain index predicate: " + repr(value))
        value = value.lower().rstrip(".")
        inclusive = value.startswith("+.")
        subdomains = value.startswith(".")
        host = value[2:] if inclusive else value[1:] if subdomains else value
        if not host or "+" in host:
            raise ValueError("Unknown domain matcher syntax: " + value)
        if "*" in host:
            # MRS wildcards match a single label. Other wildcard forms are
            # retained as uncertainty rather than silently approximated.
            if any("*" in part and part != "*" for part in host.split(".")) or inclusive or subdomains:
                self.uncertain(self.rules[index], "Unsupported domain wildcard pattern: " + value)
                return
            pattern = re.compile("^" + r"\.".join("[^.]+" if p == "*" else re.escape(p) for p in host.split(".")) + "$")
            self.extra.append((index, "regex", pattern))
            witness = host.replace("*", "mrs-wildcard-witness")
            self.pattern_witnesses.update((witness, "mrs-child." + witness))
            self.uncertain(self.rules[index], "Wildcard evaluated on witnesses; wildcard/regex intersections are not exhaustively proved", contextual=False)
            return
        self.anchors.add(host)
        if inclusive or not subdomains:
            self.exact.setdefault(host, index)
        if inclusive or subdomains:
            self.suffix.setdefault(host, index)

    def match(self, hostname):
        best = self.exact.get(hostname, len(self.rules) - 1)
        parts = hostname.split(".")
        for index in range(1, len(parts)):
            best = min(best, self.suffix.get(".".join(parts[index:]), best))
        for index, kind, predicate in self.extra:
            if index >= best:
                break
            if (predicate in hostname) if kind == "keyword" else predicate.search(hostname) is not None:
                best = index
        return best, self.first_unresolved < best


def _subtract(left, right):
    """Subtract normalized closed intervals in linear time."""
    result, cursor = [], 0
    for family, first, last in left:
        while cursor < len(right) and (right[cursor][0] < family or
                                      right[cursor][0] == family and right[cursor][2] < first):
            cursor += 1
        index, start = cursor, first
        while index < len(right) and right[index][0] == family and right[index][1] <= last:
            _, low, high = right[index]
            if low > start:
                result.append((family, start, min(low - 1, last)))
            start = max(start, high + 1)
            if start > last:
                break
            index += 1
        if start <= last:
            result.append((family, start, last))
    return result


def _range_summary(intervals):
    rows = [[family, str(ipaddress.ip_address(first) if family == 4 else ipaddress.IPv6Address(first)),
             str(ipaddress.ip_address(last) if family == 4 else ipaddress.IPv6Address(last))]
            for family, first, last in intervals]
    return {"intervals": rows, "interval_count": len(rows),
            "address_count": str(sum(last - first + 1 for _, first, last in intervals))}


def _coverage_diff(old, new):
    return {"removed": _range_summary(_subtract(old, new)),
            "added": _range_summary(_subtract(new, old))}


def _inventory(manifest, domains, ips, rules):
    usage = {r["value"]: r for r in rules if r["type"] == "RULE-SET"}
    return [{"name": name, **provider, "rule_index": usage[name]["index"],
             "policy": usage[name]["policy"],
             "predicate_count": len(domains[name]) if name in domains else len(ips[name])}
            for name, provider in sorted(manifest["providers"].items())]


def _child_witness(host, anchors, fresh_label):
    if len(fresh_label) + len(host) + 1 <= 253:
        return fresh_label + "." + host
    # A long but valid name can still have a one-character child even when the
    # descriptive default label does not fit. If every possible short child is
    # an existing anchor, those exact witnesses already cover that partition.
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    for length in range(1, min(63, 252 - len(host)) + 1):
        for letters in itertools.product(alphabet, repeat=length):
            candidate = "".join(letters) + "." + host
            if candidate not in anchors:
                return candidate
    return None


def compare_snapshots(previous_dir, manifest, inline, domain_index, ip_index):
    """Return a serializable, gated comparison; new manifest may be pre-audit.

    domain_index and ip_index contain the exact normalized values sent to MRS
    conversion, keyed by every corresponding new provider. The caller may gzip
    this report in the separate audit directory before final artifact hashing.
    """
    directory = Path(previous_dir)
    raw_manifest = (directory / "build-manifest.json").read_bytes()
    previous = json.loads(raw_manifest)
    if previous.get("schema_version") != 1 or manifest.get("schema_version") != 2:
        raise ValueError("This baseline must be an explicit rebuilt v1 to v2 policy comparison")
    old_inline = json.loads((directory / "inline-rules.json").read_bytes())
    old_rules, new_rules = _chain(previous, old_inline), _chain(manifest, inline)
    snapshot.verify(directory, previous)
    # Verify the comparison's baseline chain against the production assembler.
    if [r["rule"] for r in old_rules] != snapshot.assemble({}, previous, old_inline)["rules"]:
        raise ValueError("Change evaluator differs from the production v1 rule chain")
    old_domains, old_ips = {}, {}
    for name, provider in previous["providers"].items():
        decoded = decode_mrs((directory / provider["path"]).read_bytes())
        if decoded["behavior"] != provider["behavior"]:
            raise ValueError("Baseline MRS behavior mismatch: " + name)
        if decoded["behavior"] == "domain":
            old_domains[name] = decoded["domains"]
        else:
            old_ips[name] = ip_intervals(decoded["intervals"])
    expected_domains = {n for n, p in manifest["providers"].items() if p["behavior"] == "domain"}
    expected_ips = set(manifest["providers"]) - expected_domains
    if set(domain_index) != expected_domains or set(ip_index) != expected_ips:
        raise ValueError("Every compiled provider must have exactly one complete comparison index")
    new_ips = {}
    pool = ipaddress.ip_network("198.18.0.0/16")
    for name, values in ip_index.items():
        parsed = [ipaddress.ip_network(v, strict=True) for v in values]
        if not parsed or any(p.version == 4 and p.overlaps(pool) for p in parsed):
            raise ValueError("Empty or Fake-IP-overlapping v2 IP collection: " + name)
        new_ips[name] = ip_intervals([str(p) for p in parsed])
    if any(not isinstance(values, list) or not values for values in domain_index.values()):
        raise ValueError("Empty or malformed v2 domain collection")
    old = DomainChain(old_rules, previous["providers"], old_domains)
    new = DomainChain(new_rules, manifest["providers"], domain_index)
    anchors = old.anchors | new.anchors
    label = "mrs-audit-boundary"
    # Use a fresh label globally, so an explicit child in either snapshot cannot
    # hide the general subdomain partition of its ancestor.
    while any(label in host.split(".") for host in anchors):
        label += "x"
    witnesses = anchors | old.pattern_witnesses | new.pattern_witnesses
    witnesses.update(child for host in anchors if (child := _child_witness(host, anchors, label)) is not None)
    rows, transitions = [], collections.Counter()
    changed_policy = uncertain_rows = 0
    for hostname in sorted(witnesses):
        before, old_uncertain = old.match(hostname)
        after, new_uncertain = new.match(hostname)
        lhs, rhs = old_rules[before], new_rules[after]
        if lhs["rule"] != rhs["rule"]:
            rows.append([hostname, before, after, old_uncertain, new_uncertain])
            transitions[(lhs["policy"], rhs["policy"])] += 1
            changed_policy += lhs["policy"] != rhs["policy"]
            uncertain_rows += old_uncertain or new_uncertain
    old_inventory = _inventory(previous, old_domains, old_ips, old_rules)
    new_inventory = _inventory(manifest, domain_index, new_ips, new_rules)
    old_names, new_names = set(previous["providers"]), set(manifest["providers"])
    old_text, new_text = [r["rule"] for r in old_rules], [r["rule"] for r in new_rules]
    old_policy_ips, new_policy_ips = collections.defaultdict(list), collections.defaultdict(list)
    for rules, ips, destination in ((old_rules, old_ips, old_policy_ips), (new_rules, new_ips, new_policy_ips)):
        for rule in rules:
            if rule["type"] == "RULE-SET" and rule["value"] in ips:
                destination[rule["policy"]].extend(ips[rule["value"]])
            elif rule["type"] in {"IP-CIDR", "IP-CIDR6"}:
                destination[rule["policy"]].extend(ip_intervals([rule["value"]]))
    return {
        "schema_version": 1, "status": "passed",
        "comparison_kind": "rebuilt_v1_to_v2_policy_comparison",
        "baseline": {"tag": previous["build_id"], "manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
                     "schema_version": 1, "is_actual_online_version": False,
                     "description": "Current production-branch inputs rebuilt with the v1 policy; not an observation of the active client/server."},
        "candidate": {"tag": manifest["build_id"], "schema_version": 2, "policy_version": manifest["policy_version"]},
        "gate": {"all_inputs_parsed": True, "v2_order_and_provider_contract_checked": True,
                 "change_count_requires_approval": False},
        "providers": {"old": old_inventory, "new": new_inventory,
                      "added": sorted(new_names - old_names), "removed": sorted(old_names - new_names)},
        "rules": {"old": old_rules, "new": new_rules,
                  "added": [r for r in new_rules if r["rule"] not in old_text],
                  "removed": [r for r in old_rules if r["rule"] not in new_text],
                  "moved": [{"rule": text, "old_index": old_text.index(text), "new_index": index}
                            for index, text in enumerate(new_text) if text in old_text and old_text.index(text) != index],
                  "removed_advertising_routes": [r for r in old_rules if r["policy"] == "REJECT" and r["rule"] not in new_text],
                  "removed_process_routes": [r for r in old_rules if r["type"].startswith("PROCESS-") and r["rule"] not in new_text]},
        "domain_witnesses": {
            "scope": "First hostname predicate or eventual MATCH, conditional on all earlier connection-only/unproved predicates not matching.",
            "anchor_count": len(anchors), "tested_count": len(witnesses), "changed_first_match_count": len(rows),
            "changed_policy_count": changed_policy, "conditional_change_count": uncertain_rows,
            "columns": ["hostname", "old_rule_index", "new_rule_index", "old_conditional", "new_conditional"],
            "rows": rows, "transitions": [{"old": a, "new": b, "count": count}
                                          for (a, b), count in sorted(transitions.items())]},
        "ip_coverage": {
            "scope": "Set coverage by provider/policy, not effective first-match routing or a claim about domain DNS answers.",
            "interval_columns": ["address_family", "first_inclusive", "last_inclusive"],
            "providers": {name: _coverage_diff(old_ips.get(name, []), new_ips.get(name, []))
                          for name in sorted(set(old_ips) | set(new_ips))},
            "policies": {action: _coverage_diff(ip_intervals(old_policy_ips[action]), ip_intervals(new_policy_ips[action]))
                         for action in sorted(set(old_policy_ips) | set(new_policy_ips))}},
        "uncertainties": {"old": old.uncertainties, "new": new.uncertainties},
        "limitations": [
            "Exact and suffix anchors plus fresh child boundaries cover hostname-only literal partitions; rows are concrete witnesses, not counts of affected real websites.",
            "Keyword, wildcard and regex combinations have additional unenumerated domains. Mihomo 1.19.32 uses case-insensitive regexp2; only a restricted shared ASCII subset is evaluated here, with complex constructs explicitly unresolved.",
            "IP, process, port, network and UID context is not supplied. Even a precise hostname hit does not prove the complete connection action.",
            "DNS resolver selection, network reachability, TLS and online client state require separate full-configuration core and deployment checks."]}
