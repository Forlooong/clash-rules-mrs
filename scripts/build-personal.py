#!/usr/bin/env python3
"""Preserve classical fallback when a private rule cannot be converted to MRS."""
import ipaddress
import json
import re
import subprocess
from pathlib import Path
import yaml

DOMAIN = re.compile(r"^(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*$")


def load(path):
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or set(doc) != {"payload"} or not isinstance(doc["payload"], list):
        raise ValueError(f"{path}: expected only YAML payload list")
    items = []
    for item in doc["payload"]:
        if not isinstance(item, str):
            raise ValueError(f"{path}: a payload item must be string")
        item = item.strip()
        if item and item not in items:
            items.append(item)
    return items


def split(items):
    groups = {"domain": [], "ipcidr": [], "classical": []}
    for rule in items:
        fields = [x.strip() for x in rule.split(",")]
        if len(fields) < 2 or not fields[0] or not fields[1]:
            raise ValueError(f"Malformed rule: {rule!r}")
        kind, value = fields[0].upper(), fields[1]
        if kind in ("DOMAIN", "DOMAIN-SUFFIX") and len(fields) == 2:
            if not DOMAIN.fullmatch(value):
                raise ValueError(f"Invalid domain: {rule!r}")
            groups["domain"].append(("full:" if kind == "DOMAIN" else "+.") + value.lower())
        elif kind in ("IP-CIDR", "IP-CIDR6") and len(fields) == 2:
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid IP range: {rule!r}") from exc
            if (kind == "IP-CIDR" and net.version != 4) or (kind == "IP-CIDR6" and net.version != 6):
                raise ValueError(f"Wrong IP family: {rule!r}")
            groups["ipcidr"].append(str(net))
        else:
            # Keep original no-resolve and other non-MRS predicates untouched.
            groups["classical"].append(rule)
    return {key: list(dict.fromkeys(val)) for key, val in groups.items()}


def build():
    dest = Path("out/personal")
    dest.mkdir(parents=True, exist_ok=True)
    report = {}
    for direction in ("direct", "proxy"):
        groups = split(load(Path("personal") / (direction + ".yaml")))
        report[direction] = {name: len(values) for name, values in groups.items()}
        for kind in ("domain", "ipcidr"):
            output = dest / ("personal-" + direction + "-" + kind + ".mrs")
            if not groups[kind]:
                output.unlink(missing_ok=True)
                continue
            temp = dest / (".build-" + direction + "-" + kind + ".yaml")
            try:
                temp.write_text(yaml.safe_dump({"payload": groups[kind]}), encoding="utf-8")
                subprocess.run(["mihomo", "convert-ruleset", kind, "yaml", str(temp), str(output)], check=True)
                if not output.is_file() or not output.stat().st_size:
                    raise RuntimeError(f"Bad MRS output: {output}")
            finally:
                temp.unlink(missing_ok=True)
        fallback = dest / ("personal-" + direction + "-classical.yaml")
        if groups["classical"]:
            fallback.write_text(yaml.safe_dump({"payload": groups["classical"]}), encoding="utf-8")
        else:
            fallback.unlink(missing_ok=True)
        print(direction, report[direction])
    (dest / "build-report.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    build()
