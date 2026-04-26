#!/usr/bin/env python3
"""Generate CVE recipe pages from a local GitHub Advisory Database checkout.

Usage:
  python scripts/generate_cve_recipes_from_ghad.py \
    --advisory-root /path/to/advisory-database/advisories/github-reviewed \
    --output-root content/prompt-library/cve/generated
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path

SEVERITIES = {"high", "critical"}


def slugify(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-")[:48] or "advisory"


def iter_json_files(root: Path):
    yield from root.rglob("*.json")


def has_fix(affected: list[dict]) -> bool:
    for item in affected:
        for rng in item.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return True
    return False


def first_fixed_versions(affected: list[dict]) -> list[str]:
    out: list[str] = []
    for item in affected:
        for rng in item.get("ranges", []):
            for event in rng.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    out.append(fixed)
    return sorted(set(out))


def affected_ranges(affected: list[dict]) -> list[str]:
    out: list[str] = []
    for item in affected:
        pkg = item.get("package", {})
        pkg_name = pkg.get("name", "unknown-package")
        ecosystem = pkg.get("ecosystem", "unknown")
        versions = item.get("versions", [])
        if versions:
            out.append(f"- **{pkg_name} ({ecosystem})**: {', '.join(versions[:8])}")
            continue
        for rng in item.get("ranges", []):
            pieces = []
            for event in rng.get("events", []):
                if "introduced" in event:
                    pieces.append(f">= {event['introduced']}")
                if "fixed" in event:
                    pieces.append(f"< {event['fixed']}")
            if pieces:
                out.append(f"- **{pkg_name} ({ecosystem})**: {' and '.join(pieces)}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--advisory-root", required=True, type=Path)
    ap.add_argument("--output-root", required=True, type=Path)
    ap.add_argument("--author", default="Codex")
    ap.add_argument("--team", default="Security")
    args = ap.parse_args()

    args.output_root.mkdir(parents=True, exist_ok=True)

    generated = 0
    skipped = 0
    today = dt.date.today().isoformat()

    for file_path in iter_json_files(args.advisory_root):
        try:
            doc = json.loads(file_path.read_text(encoding="utf-8"))
        except Exception:
            skipped += 1
            continue

        sev = (doc.get("database_specific", {}).get("severity") or "").lower()
        if sev not in SEVERITIES:
            continue

        aliases = doc.get("aliases", [])
        cves = [a for a in aliases if a.startswith("CVE-")]
        if not cves:
            continue

        affected = doc.get("affected", [])
        if not has_fix(affected):
            continue

        cve = cves[0]
        summary = (doc.get("summary") or "").strip() or f"{cve} security advisory"
        details = (doc.get("details") or "").strip().replace("\n\n", "\n")
        if len(details) > 600:
            details = details[:600].rsplit(" ", 1)[0] + "…"

        ecosystem = "unknown"
        for item in affected:
            eco = item.get("package", {}).get("ecosystem")
            if eco:
                ecosystem = eco.lower()
                break

        fixed_versions = first_fixed_versions(affected)
        fixed_str = ", ".join(fixed_versions[:5]) if fixed_versions else "see advisory"
        slug = slugify(summary)
        out_name = f"{cve.lower()}-{slug}.md"
        out_path = args.output_root / out_name

        disclosed = doc.get("published", "")[:10] or today
        intro = details or summary

        lines = [
            "---",
            f'title: "{cve} — {summary.replace("\"", "\\\"")}"',
            f'linkTitle: "{cve}"',
            f'description: "{summary.replace("\"", "\\\"")}"',
            'tool: "general"',
            f'author: "{args.author}"',
            f'team: "{args.team}"',
            'maturity: "draft"',
            'model: "GPT-5.3-Codex"',
            'tags: ["cve", "generated", "github-advisory"]',
            f'weight: {1000 + generated}',
            f'date: {today}',
            f'cve: "{cve}"',
            f'aliases: ["{summary.replace("\"", "\\\"")}"]',
            'kev: false',
            f'severity: "{sev}"',
            f'ecosystem: "{ecosystem}"',
            f'disclosed: "{disclosed}"',
            "---",
            "",
            intro,
            "",
            "## Affected versions",
            "",
            *affected_ranges(affected)[:10],
            "",
            "## Remediation strategy",
            "",
            f"Upgrade to a patched release. Minimum observed patched version(s): `{fixed_str}`.",
            "",
            "## The prompt",
            "",
            "~~~markdown",
            f"You are remediating {cve}.",
            "",
            "1) Detect vulnerable versions in dependency manifests and lock files.",
            f"2) Upgrade to patched versions (minimum: {fixed_str}).",
            "3) Run tests and dependency scans.",
            "4) If no safe upgrade path exists, produce TRIAGE.md with blockers.",
            "~~~",
            "",
        ]

        out_path.write_text("\n".join(lines), encoding="utf-8")
        generated += 1

    print(f"generated={generated} skipped={skipped} output={args.output_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
