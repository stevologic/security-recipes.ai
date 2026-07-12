#!/usr/bin/env python3
"""Generate the compliance recipe library from its reviewed framework catalog."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "data" / "compliance-frameworks" / "catalog.json"
OUTPUT_DIR = (
    ROOT / "content" / "prompt-library" / "general" / "compliance-standards"
)
EXPECTED_FRAMEWORK_COUNT = 39

CATEGORY_LABELS = {
    "ai-governance": "AI governance",
    "assurance": "Assurance and governance",
    "cloud-assurance": "Cloud assurance",
    "critical-infrastructure": "Critical infrastructure",
    "government": "Government and public sector",
    "privacy": "Privacy",
    "product-security": "Product and software security",
    "regulated-industries": "Regulated industries",
    "security-programs": "Security programs",
}

ALLOWED_STATUSES = {
    "draft-update",
    "final",
    "phased-implementation",
    "revision-in-progress",
}
ALLOWED_LICENSE_BOUNDARIES = {
    "official-text",
    "open-attribution",
    "public-domain",
    "summary-only",
}


def load_catalog(path: Path = CATALOG_PATH) -> dict[str, Any]:
    """Load the structured catalog without performing network access."""
    return json.loads(path.read_text(encoding="utf-8"))


def yaml_scalar(value: Any) -> str:
    """Return JSON syntax, which is also valid YAML front matter syntax."""
    return json.dumps(value, ensure_ascii=False)


def bullet_list(values: list[str]) -> str:
    return "\n".join(f"- {value}" for value in values)


def numbered_list(values: list[str]) -> str:
    return "\n".join(f"{index}. {value}" for index, value in enumerate(values, 1))


def related_frameworks(
    framework: dict[str, Any], all_frameworks: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Choose deterministic, relevant links without requiring a hand-kept graph."""
    same_category = [
        item
        for item in all_frameworks
        if item["framework_id"] != framework["framework_id"]
        and item["category"] == framework["category"]
    ]
    shared_facets = [
        item
        for item in all_frameworks
        if item["framework_id"] != framework["framework_id"]
        and item not in same_category
        and set(item["facets"]) & set(framework["facets"])
    ]
    return (same_category + shared_facets)[:3]


def license_instruction(framework: dict[str, Any]) -> str:
    boundary = framework["license_boundary"]
    if boundary == "summary-only":
        return (
            "This recipe intentionally summarizes domains and evidence needs. Do not "
            "reproduce licensed control text; use an organization-supplied licensed "
            "copy for requirement-level work."
        )
    if boundary == "open-attribution":
        return (
            "Use the official version and preserve its attribution and license terms. "
            "Do not substitute memory for the selected published text."
        )
    if boundary == "public-domain":
        return (
            "Use the official publication as the authority and preserve its version "
            "and update identifiers in every finding."
        )
    return (
        "Use the linked official legal or regulatory text and current implementing "
        "guidance; do not replace applicability analysis with this summary."
    )


def status_instruction(framework: dict[str, Any]) -> str:
    status = framework["status"]
    if status == "draft-update":
        return (
            "A draft update exists. Treat only the identified final version as "
            "normative unless the user explicitly requests a draft gap preview."
        )
    if status == "revision-in-progress":
        return (
            "The authority is revising or transitioning this framework. Confirm the "
            "effective source set and dates before making a current-state claim."
        )
    if status == "phased-implementation":
        return (
            "Implementation is phased. Determine which duties and dates apply to the "
            "organization before evaluating evidence."
        )
    return "The cataloged version is final; still verify scope and any later official updates."


def render_front_matter(
    framework: dict[str, Any], reviewed_on: str, weight: int
) -> str:
    tags = list(
        dict.fromkeys(
            [
                "compliance",
                framework["framework_id"],
                framework["category"],
                *framework["facets"],
                *framework["industries"][:2],
            ]
        )
    )
    fields = [
        ("title", framework["title"]),
        ("linkTitle", framework["short_title"]),
        ("description", framework["applicability"]),
        ("recipe_id", framework["recipe_id"]),
        ("framework_id", framework["framework_id"]),
        ("framework", framework["short_title"]),
        ("framework_version", framework["version"]),
        ("framework_status", framework["status"]),
        ("source_reviewed", reviewed_on),
        ("jurisdiction", framework["jurisdictions"]),
        ("jurisdictions", framework["jurisdictions"]),
        ("industry", framework["industries"]),
        ("industries", framework["industries"]),
        ("facets", framework["facets"]),
        ("official_sources", framework["official_sources"]),
        ("routing_positive", framework["routing_positive"]),
        ("routing_hard_negative", framework["routing_hard_negative"]),
        ("license_boundary", framework["license_boundary"]),
        ("tool", "Compliance evidence review"),
        ("author", "Security Recipes"),
        ("team", "GRC and Security Engineering"),
        ("maturity", "stable"),
        ("model", "gpt-5-codex"),
        ("tags", tags),
        ("weight", weight),
        ("date", reviewed_on),
        ("severity", "info"),
    ]
    body = "\n".join(f"{key}: {yaml_scalar(value)}" for key, value in fields)
    return f"---\n{body}\n---"


def render_recipe(
    framework: dict[str, Any],
    all_frameworks: list[dict[str, Any]],
    reviewed_on: str,
    weight: int,
) -> str:
    related = related_frameworks(framework, all_frameworks)
    related_lines = "\n".join(
        f"- [{item['short_title']}](../{Path(item['file_name']).stem}/)"
        for item in related
    )
    references = "\n".join(
        f"{index}. [{framework['publisher']} official source {index}]({url})"
        for index, url in enumerate(framework["official_sources"], 1)
    )
    evidence_rows = "\n".join(
        f"- {domain}: begin with {example}."
        for domain, example in zip(
            framework["evidence_domains"], framework["evidence_examples"], strict=True
        )
    )
    output_name = Path(framework["file_name"]).stem.upper().replace("-", "_")
    return f"""{render_front_matter(framework, reviewed_on, weight)}

# {framework['title']}

Use this recipe to produce a source-aware evidence-readiness assessment for **{framework['short_title']}**. It creates an auditable gap record; it does not certify compliance, provide legal advice, or replace an assessor, regulator, or certification body.

## Section index

- [Framework basis](#framework-basis)
- [When to use it](#when-to-use-it)
- [Inputs](#inputs)
- [The prompt](#the-prompt)
- [Output contract](#output-contract)
- [Verification](#verification)
- [Guardrails](#guardrails)
- [Routing examples](#routing-examples)
- [References](#references)

## Framework basis

- **Publisher:** {framework['publisher']}
- **Version:** {framework['version']}
- **Status:** `{framework['status']}`
- **Sources reviewed:** {reviewed_on}
- **Jurisdictions:** {', '.join(framework['jurisdictions'])}
- **Industries:** {', '.join(framework['industries'])}
- **License boundary:** `{framework['license_boundary']}`

{framework['applicability']}

{status_instruction(framework)}

{license_instruction(framework)}

## When to use it

Use this recipe when the organization has established that {framework['short_title']} is applicable or wants a readiness assessment against it. Use the routing positives below to distinguish this recipe from adjacent frameworks. If applicability, the effective version, or the authoritative requirement set is unresolved, stop at a scoped intake and record the decision owner.

## Inputs

- The business purpose, legal entities, products, services, systems, and locations in scope.
- The organization's role, applicability decision, selected profile, level, baseline, or control set where the framework requires one.
- The official publication URLs above and, for licensed material, an authorized organization-supplied copy.
- Evidence from the complete review period, including populations—not only hand-picked examples.
- Named owners, inherited/shared responsibilities, exceptions, compensating measures, and accepted risks.
- Read-only access by default. Redacted exports are acceptable when provenance and coverage remain testable.

Evidence domains for this framework:

{evidence_rows}

## The prompt

```markdown
You are a compliance evidence-readiness analyst. Evaluate the supplied scope against {framework['short_title']} ({framework['version']}). The catalog status is {framework['status']} and the source review date is {reviewed_on}.

Never claim certification or legal compliance. Never invent applicability, evidence, control operation, sampling results, or requirement text. Separate observed facts, organization assertions, and analyst inferences. Treat missing or inaccessible evidence as unknown, not as failure, unless the authoritative assessment method says otherwise.

## Step 0 — Lock authority, version, and scope

1. Record the exact official source, version, publication/update identifier, and effective date used.
2. Record the organization, role, jurisdiction, industry, system/product boundary, review period, and decision owner.
3. Confirm any selected level, profile, baseline, overlay, assessment type, or licensed requirement set.
4. {status_instruction(framework)}
5. {license_instruction(framework)}
6. Stop and request a decision when applicability or the authoritative requirement set cannot be established.

## Step 1 — Build the applicability map

For every supplied requirement identifier or official outcome in scope, record: applicability, rationale, responsible owner, implementation location, inherited/shared responsibility, evidence expected, and any dependency. Use only identifiers present in the authoritative source supplied for this engagement. Do not reconstruct licensed text.

## Step 2 — Collect evidence by framework domain

Review these domains without treating the labels as substitutes for authoritative requirements:

{numbered_list(framework['evidence_domains'])}

Start with these likely artifacts, then validate provenance and coverage:

{numbered_list(framework['evidence_examples'])}

For every artifact record: artifact ID, source system, owner, collection time, review period, access path, integrity/provenance note, population covered, and requirement/outcome links. Prefer system exports and immutable records over screenshots or narrative attestations.

## Step 3 — Test design and operation

For each applicable item, evaluate design, implementation, and operating evidence separately. Check whether evidence is authentic, complete, current for the review period, population-representative, and directly linked to the scoped system. Where sampling is permitted, state the population, method, sample size, selections, exceptions, and limitations; do not imply statistical assurance without a justified method.

## Step 4 — Classify gaps without overstating them

Use only: supported, partially supported, unsupported, not applicable with rationale, or not assessed. Record gaps as evidence-readiness findings—not declarations of legal noncompliance. Each finding must include the affected requirement/outcome, observed fact, missing or weak evidence, risk, owner, corrective action, due date, dependencies, retest method, and confidence.

## Step 5 — Produce the evidence bundle

Return one Markdown file named {output_name}.md with:

1. Executive summary and explicit assurance limitations.
2. Authority/version/status and scope/applicability record.
3. Coverage totals by status and evidence domain.
4. Requirement/outcome-to-evidence matrix with artifact provenance.
5. Findings ordered by risk and evidence impact.
6. A 30/60/90-day remediation and evidence-collection plan.
7. Open questions, unavailable sources, conflicts, and decisions required.
8. Official references with access/review date.

Before finalizing, verify that every conclusion is traceable to an artifact or clearly labeled assertion/inference, all denominators reconcile, all unavailable evidence is visible, licensed text is not reproduced, and no sentence claims certification or legal approval.
```

## Output contract

The response must contain one evidence matrix row per scoped authoritative item or outcome. At minimum include `item_id`, `applicability`, `owner`, `implementation`, `artifact_ids`, `test_method`, `coverage_period`, `status`, `gap`, and `confidence`. Every artifact ID must resolve to the artifact register, and every total must reconcile to the matrix.

## Verification

- Confirm the official source, version, status, and review date in both the executive summary and matrix metadata.
- Reconcile applicable, not applicable, and not assessed counts to the complete supplied scope.
- Trace each supported assertion to provenance-bearing evidence covering the stated period and population.
- Independently reperform a risk-based sample of mappings and document all exceptions.
- Verify findings distinguish control/design weakness from missing evidence and unknown scope.
- Have the accountable owner and, where required, qualified counsel or an authorized assessor review conclusions.

## Guardrails

- This is an evidence-readiness workflow, not certification, attestation, audit opinion, or legal advice.
- Do not infer that a voluntary framework is mandatory or that one framework proves another.
- Do not paste, paraphrase at length, or reconstruct licensed controls. Use source summaries and organization-supplied licensed material.
- Do not expose secrets, personal data, regulated data, or full production exports in the report.
- Do not modify systems, close findings, accept risk, or submit regulatory reports without explicit owner authorization.
- If versions conflict, preserve both citations, label the conflict, and escalate rather than choosing silently.

## Routing examples

Route here:

{bullet_list(framework['routing_positive'])}

Hard negatives—route elsewhere or clarify:

{bullet_list(framework['routing_hard_negative'])}

## Related recipes

{related_lines}

## References

{references}
"""


def render_index(frameworks: list[dict[str, Any]], reviewed_on: str) -> str:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for framework in frameworks:
        grouped[framework["category"]].append(framework)

    sections: list[str] = []
    for category in sorted(grouped, key=lambda value: CATEGORY_LABELS[value]):
        rows = [
            f"| [{item['short_title']}](./{Path(item['file_name']).stem}/) "
            f"| {item['version']} | `{item['status']}` | "
            f"{', '.join(item['jurisdictions'])} |"
            for item in grouped[category]
        ]
        sections.append(
            f"## {CATEGORY_LABELS[category]} ({len(rows)})\n\n"
            "| Framework | Version | Status | Jurisdiction |\n"
            "|---|---|---|---|\n"
            + "\n".join(rows)
        )

    section_index = "\n".join(
        f"- [{CATEGORY_LABELS[key]}](#{CATEGORY_LABELS[key].lower().replace(' ', '-').replace('&', '')}-{len(grouped[key])})"
        for key in sorted(grouped, key=lambda value: CATEGORY_LABELS[value])
    )
    joined_sections = "\n\n".join(sections)
    return f"""---
title: "Compliance standards"
linkTitle: "Compliance standards"
description: "A source-backed library of {len(frameworks)} compliance and assurance evidence recipes."
weight: 10
date: "{reviewed_on}"
---

# Compliance standards

This library contains **{len(frameworks)} framework recipes**, generated from a reviewed structured catalog. Each recipe separates framework applicability from evidence readiness, identifies its exact version and status, and links to official sources. It never treats a recipe as certification or legal advice.

Catalog sources were reviewed on **{reviewed_on}**. Draft, phased, and revision-in-progress entries are labeled; users must confirm official changes before relying on an assessment.

## Section index

{section_index}

{joined_sections}
"""


def catalog_errors(catalog: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    frameworks = catalog.get("frameworks", [])
    if len(frameworks) != EXPECTED_FRAMEWORK_COUNT:
        errors.append(
            f"expected {EXPECTED_FRAMEWORK_COUNT} frameworks, found {len(frameworks)}"
        )
    if catalog.get("framework_count") != len(frameworks):
        errors.append("framework_count does not match frameworks length")

    required = {
        "applicability",
        "category",
        "evidence_domains",
        "evidence_examples",
        "facets",
        "file_name",
        "framework_id",
        "industries",
        "jurisdictions",
        "license_boundary",
        "official_sources",
        "publisher",
        "recipe_id",
        "routing_hard_negative",
        "routing_positive",
        "short_title",
        "status",
        "title",
        "version",
    }
    unique_fields = ("framework_id", "recipe_id", "file_name")
    for field in unique_fields:
        values = [item.get(field) for item in frameworks]
        if len(values) != len(set(values)):
            errors.append(f"duplicate {field}")

    for framework in frameworks:
        missing = sorted(required - framework.keys())
        if missing:
            errors.append(
                f"{framework.get('framework_id', '<unknown>')}: missing {', '.join(missing)}"
            )
            continue
        framework_id = framework["framework_id"]
        if framework["status"] not in ALLOWED_STATUSES:
            errors.append(f"{framework_id}: unsupported status")
        if framework["license_boundary"] not in ALLOWED_LICENSE_BOUNDARIES:
            errors.append(f"{framework_id}: unsupported license boundary")
        if framework["category"] not in CATEGORY_LABELS:
            errors.append(f"{framework_id}: unsupported category")
        if not {"audit", "compliance"}.issubset(framework["facets"]):
            errors.append(f"{framework_id}: facets must contain audit and compliance")
        if len(framework["evidence_domains"]) != 4:
            errors.append(f"{framework_id}: expected four evidence domains")
        if len(framework["evidence_examples"]) != 4:
            errors.append(f"{framework_id}: expected four evidence examples")
        if len(framework["routing_positive"]) < 3:
            errors.append(f"{framework_id}: needs at least three routing positives")
        if len(framework["routing_hard_negative"]) < 2:
            errors.append(f"{framework_id}: needs at least two hard negatives")
        if not framework["file_name"].endswith(".md"):
            errors.append(f"{framework_id}: file_name must end in .md")
        if not framework["official_sources"]:
            errors.append(f"{framework_id}: no official source")
        for url in framework["official_sources"]:
            if not url.startswith("https://"):
                errors.append(f"{framework_id}: non-HTTPS source {url}")
    return errors


def expected_outputs(catalog: dict[str, Any]) -> dict[str, str]:
    frameworks = catalog["frameworks"]
    reviewed_on = catalog["reviewed_on"]
    outputs = {
        framework["file_name"]: render_recipe(
            framework, frameworks, reviewed_on, 100 + index * 10
        )
        for index, framework in enumerate(frameworks, 1)
    }
    outputs["_index.md"] = render_index(frameworks, reviewed_on)
    return outputs


def sync(check: bool = False) -> list[str]:
    catalog = load_catalog()
    errors = catalog_errors(catalog)
    if errors:
        return errors

    expected = expected_outputs(catalog)
    expected_names = set(expected)
    actual_names = {path.name for path in OUTPUT_DIR.glob("*.md")}

    if check:
        for name, content in expected.items():
            path = OUTPUT_DIR / name
            if not path.exists():
                errors.append(f"missing generated recipe: {name}")
            elif path.read_text(encoding="utf-8") != content:
                errors.append(f"generated recipe is stale: {name}")
        for name in sorted(actual_names - expected_names):
            errors.append(f"unexpected compliance recipe: {name}")
        return errors

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, content in expected.items():
        (OUTPUT_DIR / name).write_text(content, encoding="utf-8", newline="\n")
    for name in sorted(actual_names - expected_names):
        (OUTPUT_DIR / name).unlink()
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="fail if generated recipes are stale"
    )
    args = parser.parse_args()
    errors = sync(check=args.check)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    action = "verified" if args.check else "generated"
    print(f"Compliance catalog {action}: {EXPECTED_FRAMEWORK_COUNT} framework recipes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
