#!/usr/bin/env python3
"""Validate the structured and generated code-hygiene recipe catalog."""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from sync_code_hygiene_recipes import (
    CATALOG_PATH,
    CONTENT_ROOT,
    REPO_ROOT,
    ROUTING_PATH,
    SOURCES_PATH,
    expected_outputs,
    load_json,
    recipe_id,
    recipe_path,
    references_for,
)


EXPECTED_FAMILY_COUNTS = {
    "cross-language": 16,
    "javascript-typescript": 5,
    "python": 5,
    "jvm": 7,
    "dotnet": 4,
    "go": 4,
    "rust": 4,
    "c-cpp": 5,
    "ruby": 2,
    "php": 2,
    "swift": 2,
    "dart-flutter": 2,
    "shell-powershell": 4,
    "data": 3,
    "platform": 7,
}
REQUIRED_HEADINGS = [
    "## When to use it",
    "## Inputs",
    "## The prompt",
    "## Output contract",
    "## Verification",
    "## Guardrails",
    "## Related recipes",
    "## References",
]
REQUIRED_RECORD_FIELDS = ["family", "slug", "title", "goal", "tags", "detect", "fix", "verify", "stop"]


def fail(failures: list[str], message: str) -> None:
    failures.append(message)


def quality_score(markdown: str) -> int:
    lower = markdown.lower()
    score = 20
    if "## inputs" in lower:
        score += 10
    if "## when to use" in lower:
        score += 10
    if "## output contract" in lower:
        score += 15
    if "## verification" in lower:
        score += 15
    if "## guardrails" in lower:
        score += 15
    if "## related" in lower:
        score += 10
    if 'facets: ["code-hygiene", "audit", "remediation"]' in markdown:
        score += 5
    return min(score, 100)


def tokens(value: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9][a-z0-9+.-]+", value.lower())
        if token not in {"and", "the", "with", "from", "into", "without", "repository", "existing"}
    }


def rank_records(query: str, records: list[dict[str, Any]]) -> list[str]:
    query_tokens = tokens(query)
    scored: list[tuple[int, str]] = []
    for record in records:
        title_tokens = tokens(record["title"])
        haystack = " ".join(
            [record["title"], record["slug"], record["goal"], " ".join(record["tags"]), *record["detect"]]
        )
        haystack_tokens = tokens(haystack)
        score = len(query_tokens & haystack_tokens) + 3 * len(query_tokens & title_tokens)
        if record["slug"] in query.lower().replace(" ", "-"):
            score += 10
        scored.append((score, recipe_id(record)))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [item[1] for item in scored]


def validate_catalog(catalog: dict[str, Any], sources: dict[str, Any], failures: list[str]) -> None:
    records = catalog.get("records")
    families = catalog.get("families")
    if catalog.get("schema_version") != 1:
        fail(failures, "catalog schema_version must be 1")
    if not isinstance(records, list):
        fail(failures, "catalog records must be an array")
        return
    if not isinstance(families, dict):
        fail(failures, "catalog families must be an object")
        return
    if len(records) != catalog.get("expected_recipe_count") or len(records) != 72:
        fail(failures, f"catalog must contain exactly 72 records; found {len(records)}")

    actual_family_counts = Counter(record.get("family") for record in records)
    if dict(actual_family_counts) != EXPECTED_FAMILY_COUNTS:
        fail(failures, f"family counts differ: {dict(actual_family_counts)}")
    if set(families) != set(EXPECTED_FAMILY_COUNTS):
        fail(failures, "family definitions do not match the required taxonomy")

    source_rows = sources.get("sources")
    if sources.get("schema_version") != 1 or not isinstance(source_rows, list):
        fail(failures, "sources registry must be schema version 1 with a sources array")
        return
    source_ids = [source.get("id") for source in source_rows]
    if len(source_ids) != len(set(source_ids)):
        fail(failures, "source IDs must be unique")
    for source in source_rows:
        if not str(source.get("url", "")).startswith("https://"):
            fail(failures, f"source {source.get('id')} must use HTTPS")
        if not source.get("owner") or source.get("kind") not in {
            "standard",
            "official-docs",
            "official-guidance",
            "first-party-tool",
        }:
            fail(failures, f"source {source.get('id')} is not classified as a primary source")

    ids: list[str] = []
    slugs: list[str] = []
    paths: list[Path] = []
    tailored_contracts: list[tuple[str, str, str, str]] = []
    for index, record in enumerate(records):
        prefix = f"record[{index}]"
        for field in REQUIRED_RECORD_FIELDS:
            if record.get(field) in (None, "", []):
                fail(failures, f"{prefix} is missing {field}")
        family = record.get("family")
        if family not in families:
            fail(failures, f"{prefix} uses unknown family {family!r}")
            continue
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", str(record.get("slug", ""))):
            fail(failures, f"{prefix} has an invalid slug")
        if not isinstance(record.get("tags"), list) or len(record["tags"]) < 3:
            fail(failures, f"{prefix} needs at least three routing tags")
        if not isinstance(record.get("detect"), list) or len(record["detect"]) < 2:
            fail(failures, f"{prefix} needs at least two tailored detection signals")
        for field in ("fix", "verify", "stop"):
            if len(str(record.get(field, ""))) < 45:
                fail(failures, f"{prefix} {field} is too generic")
        current_id = recipe_id(record)
        if not re.fullmatch(r"code-hygiene\.[a-z0-9-]+\.[a-z0-9-]+", current_id):
            fail(failures, f"{prefix} has an invalid derived recipe_id")
        ids.append(current_id)
        slugs.append(record["slug"])
        paths.append(recipe_path(record))
        tailored_contracts.append(
            (" ".join(record["detect"]), record["fix"], record["verify"], record["stop"])
        )
        try:
            refs = references_for(record, families, sources)
        except KeyError as error:
            fail(failures, f"{prefix} references unknown source {error.args[0]}")
            refs = []
        if not refs:
            fail(failures, f"{prefix} has no official references")

    if len(ids) != len(set(ids)):
        fail(failures, "recipe_id values must be unique")
    if len(slugs) != len(set(slugs)):
        fail(failures, "recipe slugs must be globally unique")
    if len(paths) != len(set(paths)):
        fail(failures, "recipe paths must be unique")
    if len(tailored_contracts) != len(set(tailored_contracts)):
        fail(failures, "tailored detection/fix/verification/stop contracts must be unique")


def validate_generated(catalog: dict[str, Any], sources: dict[str, Any], failures: list[str]) -> None:
    outputs = expected_outputs(catalog, sources)
    for path, expected in outputs.items():
        if not path.exists():
            fail(failures, f"missing generated output {path.relative_to(REPO_ROOT)}")
            continue
        actual = path.read_text(encoding="utf-8")
        if actual != expected:
            fail(failures, f"stale generated output {path.relative_to(REPO_ROOT)}")

    expected_recipe_paths = {recipe_path(record).resolve() for record in catalog["records"]}
    actual_recipe_paths = {
        path.resolve() for path in CONTENT_ROOT.rglob("*.md") if path.name != "_index.md"
    }
    missing = expected_recipe_paths - actual_recipe_paths
    extra = actual_recipe_paths - expected_recipe_paths
    for path in sorted(missing):
        fail(failures, f"missing generated recipe {path.relative_to(REPO_ROOT)}")
    for path in sorted(extra):
        fail(failures, f"unexpected recipe outside catalog {path.relative_to(REPO_ROOT)}")

    for record in catalog["records"]:
        path = recipe_path(record)
        if not path.exists():
            continue
        markdown = path.read_text(encoding="utf-8")
        for heading in REQUIRED_HEADINGS:
            if heading not in markdown:
                fail(failures, f"{path.relative_to(REPO_ROOT)} is missing {heading}")
        expected_id = f"recipe_id: {json.dumps(recipe_id(record))}"
        if expected_id not in markdown:
            fail(failures, f"{path.relative_to(REPO_ROOT)} is missing stable recipe_id")
        if 'facets: ["code-hygiene", "audit", "remediation"]' not in markdown:
            fail(failures, f"{path.relative_to(REPO_ROOT)} is missing explicit facets")
        score = quality_score(markdown)
        if score < 85:
            fail(failures, f"{path.relative_to(REPO_ROOT)} quality score is {score}; minimum is 85")
        if "Start read-only" not in markdown or "explicitly authorizes a fix" not in markdown:
            fail(failures, f"{path.relative_to(REPO_ROOT)} lacks the read-only mutation gate")


def validate_routing(catalog: dict[str, Any], failures: list[str]) -> None:
    if not ROUTING_PATH.exists():
        fail(failures, "routing-fixtures.json is missing")
        return
    routing = load_json(ROUTING_PATH)
    cases = routing.get("positive_cases")
    negatives = routing.get("hard_negative_cases")
    if not isinstance(cases, list) or len(cases) != 144:
        fail(failures, "routing fixtures must contain exactly 144 positive cases")
        return
    if routing.get("positive_case_count") != len(cases):
        fail(failures, "routing fixture count metadata is stale")
    case_ids = [case.get("id") for case in cases]
    queries = [case.get("query") for case in cases]
    if len(case_ids) != len(set(case_ids)) or len(queries) != len(set(queries)):
        fail(failures, "routing fixture IDs and queries must be unique")
    if not isinstance(negatives, list) or len(negatives) < 6:
        fail(failures, "routing fixtures need hard negatives for existing security recipe families")

    records = catalog["records"]
    expected_ids = {recipe_id(record) for record in records}
    covered: Counter[str] = Counter()
    top3_hits = 0
    for case in cases:
        expected = case.get("expected_recipe_id")
        if expected not in expected_ids:
            fail(failures, f"routing case {case.get('id')} has unknown expected recipe")
            continue
        covered[expected] += 1
        if expected in rank_records(str(case.get("query", "")), records)[:3]:
            top3_hits += 1
    if set(covered) != expected_ids or any(count != 2 for count in covered.values()):
        fail(failures, "every recipe must have exactly two positive routing fixtures")
    accuracy = top3_hits / len(cases)
    if accuracy < 0.98:
        fail(failures, f"catalog routing top-3 accuracy is {accuracy:.3f}; minimum is 0.98")


def main() -> int:
    failures: list[str] = []
    catalog = load_json(CATALOG_PATH)
    sources = load_json(SOURCES_PATH)
    validate_catalog(catalog, sources, failures)
    validate_generated(catalog, sources, failures)
    validate_routing(catalog, failures)
    if failures:
        print("Code-hygiene catalog validation failed:", file=sys.stderr)
        for message in failures:
            print(f"- {message}", file=sys.stderr)
        return 1
    print(
        "Code-hygiene catalog validated: "
        f"{len(catalog['records'])} recipes, {len(catalog['families'])} families, "
        "144 positive routes, 6 hard negatives, all quality scores >=85."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
