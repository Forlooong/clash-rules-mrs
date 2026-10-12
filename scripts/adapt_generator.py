#!/usr/bin/env python3
"""Apply a guarded, credential-free patch to the existing production generator."""
import argparse
import ast
from pathlib import Path

def adapt(source):
    tree = ast.parse(source)
    function = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "make_config"), None)
    if not function:
        raise ValueError("Expected production make_config function")
    if "from snapshot import" in source:
        raise ValueError("Generator already adapted; compare rather than patch twice")
    lines = source.splitlines(keepends=True)
    body = "".join(lines[function.lineno - 1:function.end_lineno])
    if body.count("snippet = load_rules()") != 1 or body.count("return {") != 1:
        raise ValueError("Production generator changed; manual review required")
    body = body.replace("    snippet = load_rules()", """    state_dir = BASE / 'snapshot-state'
    active = load_active(state_dir) if (state_dir / 'active.json').exists() else None
    snippet = load_rules() if active is None else {'rule-providers': {}, 'rules': []}""")
    body = body.replace("    return {", "    doc = {")
    body += "\n    return assemble(doc, *active) if active else doc\n"
    lines[function.lineno - 1:function.end_lineno] = [body]
    output = "from snapshot import load_active, assemble\n" + "".join(lines)
    ast.parse(output)
    return output

def main():
    p = argparse.ArgumentParser()
    p.add_argument("input")
    p.add_argument("output")
    args = p.parse_args()
    source = Path(args.input).read_text(encoding="utf-8-sig")
    Path(args.output).write_text(adapt(source), encoding="utf-8")

if __name__ == "__main__":
    main()
