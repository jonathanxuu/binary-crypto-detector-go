#!/usr/bin/env python3
"""Generate detector knowledge and YARA rules from catalog/*.json."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog"


def load_catalog():
    entries = []
    for path in sorted(CATALOG.glob("*.json")):
        if path.name == "official-discovered.json":
            continue
        data = json.loads(path.read_text())
        for algorithm in data.get("algorithms", []):
            item = dict(algorithm)
            item["library"] = data["library"]
            item["source"] = data.get("source", "catalog")
            entries.append(item)
    return entries


def load_official_discovered():
    path = CATALOG / "official-discovered.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    return data.get("algorithms", [])


def generate_knowledge(entries, discovered):
    rules = {}
    for item in entries:
        rules[item["rule"]] = {
            "library": item["library"],
            "algorithm": item["algorithm"],
            "purpose": item.get("purpose", ""),
            "required_evidence": item.get("required_evidence", 1),
            "evidence": item.get("evidence", []),
            "imports": item.get("imports", []),
            "symbols": item.get("symbols", []),
            "status": "curated",
            "source": item.get("source", "project catalog"),
            "status": "curated",
            "source": item.get("source", "project catalog"),
        }
    for index, item in enumerate(discovered):
        imports = item.get("imports", [])
        if not imports:
            continue
        known_imports = {
            marker.lstrip("_")
            for existing in rules.values()
            for marker in existing.get("imports", [])
        }
        if any(marker.lstrip("_") in known_imports for marker in imports):
            continue
        rule = item.get("rule", f"Auto_{index:05d}")
        if rule in rules:
            continue
        rules[rule] = {
            "library": item.get("library", "unknown"),
            "algorithm": item.get("algorithm", "unknown"),
            "purpose": item.get("purpose", ""),
            "required_evidence": 1,
            "evidence": imports,
            "imports": imports,
            "status": "official-discovered",
            "source": item.get("source", "official library discovery"),
            "status": "official-discovered",
            "source": item.get("source", "official library discovery"),
        }
    output = {"rules": dict(sorted(rules.items())), "discovered_algorithms": discovered}
    (ROOT / "knowledge.json").write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n")


def yara_quote(value):
    return json.dumps(value, ensure_ascii=False)


def generate_yara(entries):
    blocks = []
    for item in entries:
        strings = item.get("yara_strings", [])
        if not strings:
            continue
        lines = [f"rule {item['rule']}", "{", "    meta:", f'        library = {yara_quote(item["library"])}', f'        algorithm = {yara_quote(item["algorithm"])}', "    strings:"]
        for index, value in enumerate(strings):
            lines.append(f"        ${chr(97 + index)} = {yara_quote(value)} ascii wide")
        lines.extend(["    condition:", "        1 of them", "}"])
        blocks.append("\n".join(lines))
    (ROOT / "rules" / "crypto.yar").write_text("\n\n".join(blocks) + "\n")


def main():
    entries = load_catalog()
    discovered = load_official_discovered()
    generate_knowledge(entries, discovered)
    generate_yara(entries)
    print(f"generated {len(entries)} curated algorithms and {len(discovered)} official discoveries")


if __name__ == "__main__":
    main()
