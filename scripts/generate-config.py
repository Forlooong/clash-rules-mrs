#!/usr/bin/env python3
"""Generated providers always point at files in the release output."""
import json
from pathlib import Path
import yaml

out = Path("out")
providers = {}
rules = []


def add(name, rel, behavior, fmt):
    if not (out / rel).is_file():
        raise RuntimeError(f"Missing expected release artifact: {rel}")
    providers[name] = {
        "type": "http", "behavior": behavior, "format": fmt,
        "url": "https://raw.githubusercontent.com/Forlooong/clash-rules-mrs/release/" + rel,
        "path": "./ruleset/forlooong/" + rel, "interval": 43200,
        "proxy": "节点选择",
    }


for name in "reject icloud apple google proxy direct private gfw greatfire tld-not-cn".split():
    add(name, "loyalsoldier/" + name + ".mrs", "domain", "mrs")
for name in "telegramcidr cncidr lancidr".split():
    add(name, "loyalsoldier/" + name + ".mrs", "ipcidr", "mrs")
add("applications", "loyalsoldier/applications.yaml", "classical", "yaml")
for direction, policy in (("direct", "DIRECT"), ("proxy", "节点选择")):
    for behavior in ("domain", "ipcidr", "classical"):
        ext = "yaml" if behavior == "classical" else "mrs"
        name = "personal-" + direction + "-" + behavior
        rel = "personal/" + name + "." + ext
        if (out / rel).is_file():
            add(name, rel, behavior, ext)
            rules.append("RULE-SET," + name + "," + policy)

(out / "clash-snippet.yaml").write_text(
    "# Merge into the existing YAML; insert personal rules before other rules, keep original MATCH.\n"
    + yaml.safe_dump({"rule-providers": providers, "rules": rules}, allow_unicode=True, sort_keys=False),
    encoding="utf-8")
checks = {}
for name, p in providers.items():
    rel = p["url"].split("/release/")[1]
    checks[name] = {"type": "file", "behavior": p["behavior"], "format": p["format"], "path": "./out/" + rel}
smoke = {"mixed-port": 7897, "mode": "rule", "rule-providers": checks,
         "rules": ["RULE-SET," + name + ",DIRECT" for name in checks] + ["MATCH,DIRECT"]}
(out / "smoke.yaml").write_text(yaml.safe_dump(smoke, allow_unicode=True, sort_keys=False), encoding="utf-8")
(out / "manifest.json").write_text(json.dumps({k: v["url"] for k, v in providers.items()}, indent=2) + "\n")
