#!/usr/bin/env python3
"""Evaluate recipe retrieval against a golden finding-routing set."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import Any


STOP_WORDS = {"a", "an", "and", "for", "in", "of", "on", "or", "the", "to", "with"}


def tokenize(value: str) -> list[str]:
    terms = [term for term in re.split(r"\s+", value.lower().strip()) if term and term not in STOP_WORDS]
    return list(dict.fromkeys(terms))


def count_term(haystack: str, term: str) -> int:
    """Count a query term without matching it inside a larger word."""

    suffix = r"(?:s)?" if term.isalpha() and len(term) > 3 and not term.endswith("s") else ""
    pattern = rf"(?<![a-z0-9]){re.escape(term)}{suffix}(?![a-z0-9])"
    return len(re.findall(pattern, haystack))


def normalise_path(path: str) -> str:
    if not path:
        return "/"
    parsed = path.strip()
    if parsed.startswith("http://") or parsed.startswith("https://"):
        parts = parsed.split("/", 3)
        parsed = "/" + parts[3] if len(parts) > 3 else "/"
    if not parsed.startswith("/"):
        parsed = "/" + parsed
    return parsed if parsed.endswith("/") else parsed + "/"


def searchable_text(doc: dict[str, Any]) -> str:
    title = str(doc.get("title", ""))
    slug = str(doc.get("slug", ""))
    path = str(doc.get("path", ""))
    return " ".join(
        [
            title,
            str(doc.get("summary", "")),
            str(doc.get("content", ""))[:8000],
            " ".join(str(tag) for tag in doc.get("tags", []) or []),
            slug,
            path,
        ]
    ).lower()


def score_doc(query: str, doc: dict[str, Any], term_weights: dict[str, float] | None = None) -> float:
    terms = tokenize(query)
    title = str(doc.get("title", ""))
    slug = str(doc.get("slug", ""))
    path = str(doc.get("path", ""))
    haystack = searchable_text(doc)
    weights = term_weights or {}

    score = 0.0
    for term in terms:
        hits = count_term(haystack, term)
        if not hits:
            continue
        weight = weights.get(term, 1.0)
        score += weight * (1.0 + math.log1p(hits))
        if count_term(title.lower(), term):
            score += weight * 1.5
        if count_term(slug.lower(), term):
            score += weight
        if count_term(path.lower(), term):
            score += weight

    identifiers = set(re.findall(r"\b(?:cve-\d{4}-\d+|ghsa-[a-z0-9-]+)\b", query.lower()))
    for identifier in identifiers:
        if identifier in title.lower() or identifier in slug.lower() or identifier in path.lower():
            score += 50.0
    return score


def rank(query: str, docs: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    terms = tokenize(query)
    corpus = [searchable_text(doc) for doc in docs]
    term_weights = {}
    for term in terms:
        document_frequency = sum(1 for text in corpus if count_term(text, term))
        term_weights[term] = 1.0 + math.log((len(docs) + 1) / (document_frequency + 1))

    scored = [(score_doc(query, doc, term_weights), doc) for doc in docs]
    scored = [item for item in scored if item[0] > 0]
    scored.sort(key=lambda item: item[0], reverse=True)
    return [
        {
            "rank": idx + 1,
            "score": round(score, 4),
            "title": doc.get("title"),
            "path": normalise_path(str(doc.get("path", ""))),
            "slug": doc.get("slug"),
        }
        for idx, (score, doc) in enumerate(scored[:limit])
    ]


def evaluate(index_path: Path, golden_path: Path, limit: int) -> dict[str, Any]:
    docs = json.loads(index_path.read_text(encoding="utf-8"))
    golden = json.loads(golden_path.read_text(encoding="utf-8"))
    if not isinstance(docs, list) or not docs:
        raise ValueError("index must be a non-empty JSON array")
    cases = golden.get("cases", [])
    if not isinstance(cases, list) or not cases:
        raise ValueError("golden file must contain non-empty cases")

    results = []
    top1_hits = 0
    top3_hits = 0
    for case in cases:
        expected = {normalise_path(path) for path in case["expected_paths"]}
        ranked = rank(case["query"], docs, limit)
        ranked_paths = [item["path"] for item in ranked]
        top1 = bool(ranked_paths[:1] and ranked_paths[0] in expected)
        top3 = any(path in expected for path in ranked_paths[:3])
        top1_hits += int(top1)
        top3_hits += int(top3)
        results.append(
            {
                "id": case["id"],
                "top1": top1,
                "top3": top3,
                "expected_paths": sorted(expected),
                "results": ranked[:3],
            }
        )

    total = len(cases)
    return {
        "golden_name": golden.get("name"),
        "golden_version": golden.get("version"),
        "case_count": total,
        "top1_accuracy": round(top1_hits / total, 4),
        "top3_accuracy": round(top3_hits / total, 4),
        "minimum_top1_accuracy": golden.get("minimum_top1_accuracy", 0),
        "minimum_top3_accuracy": golden.get("minimum_top3_accuracy", 0),
        "cases": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", default="public/recipes-index.json")
    parser.add_argument("--golden", default="data/evaluations/recipe-routing-golden.json")
    parser.add_argument("--limit", type=int, default=8)
    parser.add_argument("--output")
    parser.add_argument("--enforce-thresholds", action="store_true")
    args = parser.parse_args()

    report = evaluate(Path(args.index), Path(args.golden), args.limit)
    rendered = json.dumps(report, indent=2)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)

    if args.enforce_thresholds and (
        report["top1_accuracy"] < report["minimum_top1_accuracy"]
        or report["top3_accuracy"] < report["minimum_top3_accuracy"]
    ):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
