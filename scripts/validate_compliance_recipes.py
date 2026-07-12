#!/usr/bin/env python3
"""Validate compliance catalog coverage, provenance, routing, and generated recipes."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import sync_compliance_recipes as syncer


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_HEADINGS = {
    "## Section index",
    "## Framework basis",
    "## When to use it",
    "## Inputs",
    "## The prompt",
    "## Output contract",
    "## Verification",
    "## Guardrails",
    "## Routing examples",
    "## Related recipes",
    "## References",
}
OFFICIAL_HOST_SUFFIXES = {
    "aicpa-cima.com",
    "baseline.openssf.org",
    "cisecurity.org",
    "cisa.gov",
    "cloudsecurityalliance.org",
    "defense.gov",
    "dfs.ny.gov",
    "europa.eu",
    "fbi.gov",
    "fda.gov",
    "fedramp.gov",
    "ftc.gov",
    "github.com",
    "hhs.gov",
    "iec.ch",
    "isaca.org",
    "iso.org",
    "nerc.com",
    "nist.gov",
    "owasp.org",
    "owaspsamm.org",
    "pcaobus.org",
    "pcisecuritystandards.org",
    "sec.gov",
    "slsa.dev",
}
SUMMARY_ONLY_PUBLISHERS = {
    "AICPA",
    "Center for Internet Security",
    "Cloud Security Alliance",
    "IEC",
    "ISACA",
    "ISO/IEC",
    "PCI Security Standards Council",
}


def parse_front_matter(text: str) -> dict[str, Any]:
    """Parse deterministic JSON-valued YAML emitted by the generator."""
    if not text.startswith("---\n"):
        raise ValueError("missing front matter")
    front_matter, _ = text[4:].split("\n---\n", 1)
    values: dict[str, Any] = {}
    for line in front_matter.splitlines():
        key, raw_value = line.split(":", 1)
        values[key] = json.loads(raw_value.strip())
    return values


def host_is_official(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return any(host == suffix or host.endswith(f".{suffix}") for suffix in OFFICIAL_HOST_SUFFIXES)


def validate() -> tuple[list[str], dict[str, Any]]:
    catalog = syncer.load_catalog()
    frameworks = catalog.get("frameworks", [])
    errors = syncer.catalog_errors(catalog)

    try:
        reviewed_on = date.fromisoformat(catalog["reviewed_on"])
    except (KeyError, TypeError, ValueError):
        errors.append("catalog reviewed_on must be an ISO date")
        reviewed_on = None
    if reviewed_on and reviewed_on > date.today():
        errors.append("catalog reviewed_on cannot be in the future")

    for framework in frameworks:
        framework_id = framework.get("framework_id", "<unknown>")
        positives = {value.casefold() for value in framework.get("routing_positive", [])}
        negatives = {
            value.casefold() for value in framework.get("routing_hard_negative", [])
        }
        if positives & negatives:
            errors.append(f"{framework_id}: positive and hard-negative routing overlap")
        if len(positives) != len(framework.get("routing_positive", [])):
            errors.append(f"{framework_id}: duplicate routing positive")
        if len(negatives) != len(framework.get("routing_hard_negative", [])):
            errors.append(f"{framework_id}: duplicate routing hard negative")
        for source in framework.get("official_sources", []):
            if not host_is_official(source):
                errors.append(f"{framework_id}: source host is not allowlisted: {source}")
        if framework.get("publisher") in SUMMARY_ONLY_PUBLISHERS:
            if framework.get("license_boundary") != "summary-only":
                errors.append(
                    f"{framework_id}: licensed publisher must use summary-only boundary"
                )

    errors.extend(syncer.sync(check=True))

    expected_names = {item["file_name"] for item in frameworks}
    actual_names = {
        path.name
        for path in syncer.OUTPUT_DIR.glob("*.md")
        if path.name != "_index.md"
    }
    if actual_names != expected_names:
        errors.append("recipe file set does not exactly match the 39-framework catalog")

    for framework in frameworks:
        path = syncer.OUTPUT_DIR / framework["file_name"]
        if not path.exists():
            continue
        content = path.read_text(encoding="utf-8")
        try:
            metadata = parse_front_matter(content)
        except (ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{framework['framework_id']}: invalid front matter: {exc}")
            continue
        exact_metadata = {
            "facets": framework["facets"],
            "framework_id": framework["framework_id"],
            "framework_status": framework["status"],
            "framework_version": framework["version"],
            "industry": framework["industries"],
            "industries": framework["industries"],
            "jurisdiction": framework["jurisdictions"],
            "jurisdictions": framework["jurisdictions"],
            "license_boundary": framework["license_boundary"],
            "official_sources": framework["official_sources"],
            "recipe_id": framework["recipe_id"],
            "routing_hard_negative": framework["routing_hard_negative"],
            "routing_positive": framework["routing_positive"],
            "source_reviewed": catalog["reviewed_on"],
        }
        for key, expected in exact_metadata.items():
            if metadata.get(key) != expected:
                errors.append(
                    f"{framework['framework_id']}: front matter {key} is stale"
                )
        headings = {
            line.strip() for line in content.splitlines() if line.startswith("## ")
        }
        missing_headings = REQUIRED_HEADINGS - headings
        if missing_headings:
            errors.append(
                f"{framework['framework_id']}: missing headings "
                + ", ".join(sorted(missing_headings))
            )
        for step in range(6):
            if f"## Step {step}" not in content:
                errors.append(f"{framework['framework_id']}: missing prompt Step {step}")
        required_phrases = (
            "does not certify compliance",
            "not certification, attestation, audit opinion, or legal advice",
            "Do not paste, paraphrase at length, or reconstruct licensed controls",
            "Route here:",
            "Hard negatives",
        )
        for phrase in required_phrases:
            if phrase not in content:
                errors.append(f"{framework['framework_id']}: missing guardrail: {phrase}")
        for source in framework["official_sources"]:
            if source not in content:
                errors.append(f"{framework['framework_id']}: source missing from recipe")

    index_path = syncer.OUTPUT_DIR / "_index.md"
    if not index_path.exists():
        errors.append("missing compliance section index")
    else:
        index = index_path.read_text(encoding="utf-8")
        if f"**{len(frameworks)} framework recipes**" not in index:
            errors.append("section index framework total is stale")
        for framework in frameworks:
            expected_link = f"./{Path(framework['file_name']).stem}/"
            if expected_link not in index:
                errors.append(
                    f"{framework['framework_id']}: missing from compliance section index"
                )

    metrics = {
        "frameworks": len(frameworks),
        "recipes": len(actual_names),
        "official_sources": sum(
            len(item.get("official_sources", [])) for item in frameworks
        ),
        "jurisdictions": len(
            {value for item in frameworks for value in item.get("jurisdictions", [])}
        ),
        "industries": len(
            {value for item in frameworks for value in item.get("industries", [])}
        ),
        "categories": dict(sorted(Counter(item["category"] for item in frameworks).items())),
        "statuses": dict(sorted(Counter(item["status"] for item in frameworks).items())),
        "license_boundaries": dict(
            sorted(Counter(item["license_boundary"] for item in frameworks).items())
        ),
        "reviewed_on": catalog.get("reviewed_on"),
    }
    return errors, metrics


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print machine-readable output")
    args = parser.parse_args()
    errors, metrics = validate()
    if args.json:
        print(json.dumps({"valid": not errors, "errors": errors, **metrics}, indent=2))
    else:
        for error in errors:
            print(f"ERROR: {error}")
        print(
            "Compliance coverage: "
            f"{metrics['recipes']}/{metrics['frameworks']} recipes, "
            f"{metrics['official_sources']} official sources, "
            f"{metrics['jurisdictions']} jurisdictions, "
            f"{metrics['industries']} industries"
        )
        print(f"Status coverage: {json.dumps(metrics['statuses'], sort_keys=True)}")
        print(f"Source review date: {metrics['reviewed_on']}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
