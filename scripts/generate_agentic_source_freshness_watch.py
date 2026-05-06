#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic source freshness watch.

The watch proves that SecurityRecipes treats external guidance as a
maintained dependency. It scans selected source-backed packs, collects
their standards references, checks review cadence, verifies primary
publisher coverage, and emits an MCP-readable evidence artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any


PACK_SCHEMA_VERSION = "1.0"
DEFAULT_PROFILE = Path("data/assurance/agentic-source-freshness-profile.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-source-freshness-watch.json")
DATE_RE = re.compile(r"^(\d{4})(?:-(\d{2}))?(?:-(\d{2}))?")


class SourceFreshnessError(RuntimeError):
    """Raised when the source freshness watch cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SourceFreshnessError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise SourceFreshnessError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SourceFreshnessError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise SourceFreshnessError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SourceFreshnessError(f"{label} must be an object")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def normalize_path(path: Path) -> str:
    return path.as_posix()


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def parse_source_date(raw: Any) -> date | None:
    text = str(raw or "").strip()
    if not text:
        return None
    match = DATE_RE.match(text)
    if not match:
        return None
    year = int(match.group(1))
    month = int(match.group(2) or 1)
    day = int(match.group(3) or 1)
    try:
        return date(year, month, day)
    except ValueError:
        return None


def date_text(value: date | None) -> str | None:
    return value.isoformat() if value else None


def publisher_family(publisher: Any) -> str:
    text = str(publisher or "").lower()
    if "owasp" in text:
        return "OWASP"
    if "model context protocol" in text:
        return "Model Context Protocol"
    if "nist" in text or "caisi" in text:
        return "NIST"
    if "openai" in text:
        return "OpenAI"
    if "anthropic" in text:
        return "Anthropic"
    if "microsoft" in text:
        return "Microsoft"
    if "cisa" in text or "cybersecurity and infrastructure security agency" in text:
        return "CISA"
    if "cloud security alliance" in text:
        return "Cloud Security Alliance"
    if "a2a" in text or "agent2agent" in text:
        return "A2A"
    if "linux foundation" in text:
        return "Linux Foundation"
    return str(publisher or "Unknown").strip() or "Unknown"


def source_class_family(source_class: Any) -> str:
    text = str(source_class or "").lower()
    if "protocol" in text:
        return "protocol"
    if "frontier_lab" in text or "frontier" in text:
        return "frontier_lab"
    if "government" in text:
        return "government"
    if "industry" in text:
        return "industry"
    if "incident" in text:
        return "incident"
    return text or "unknown"


def get_nested_list(payload: dict[str, Any], dotted_path: str) -> list[Any]:
    node: Any = payload
    for part in dotted_path.split("."):
        if not isinstance(node, dict):
            return []
        node = node.get(part)
    return node if isinstance(node, list) else []


def source_title(source: dict[str, Any]) -> str:
    return str(source.get("name") or source.get("title") or source.get("id") or "untitled")


def source_reason(source: dict[str, Any]) -> str:
    return str(source.get("why_it_matters") or source.get("coverage") or source.get("commercial_reason") or "")


def source_key(source: dict[str, Any]) -> str:
    url = str(source.get("url") or "").strip().lower()
    if url:
        return f"url::{url}"
    return f"id::{str(source.get('id') or source_title(source)).strip().lower()}"


def freshness_class(published: date | None, as_of: date) -> str:
    if not published:
        return "undated_review_required"
    age = (as_of - published).days
    if age <= 120:
        return "recent_signal"
    if age <= 365:
        return "current_reference"
    return "standing_reference"


def review_decision(reviewed: date | None, cadence_days: int, as_of: date, source_count: int, missing: bool) -> tuple[str, list[str]]:
    blockers: list[str] = []
    if missing:
        return "blocked_by_missing_source", ["watched source file is missing"]
    if source_count <= 0:
        return "blocked_by_missing_source", ["no references found under configured reference_paths"]
    if not reviewed:
        return "review_due", ["watched source has no last_reviewed or generated_at date"]

    due_at = reviewed + timedelta(days=cadence_days)
    if as_of <= due_at:
        return "current", blockers
    if as_of <= due_at + timedelta(days=cadence_days):
        return "review_due", [f"review due after {due_at.isoformat()}"]
    return "stale_or_missing", [f"review stale after {due_at.isoformat()}"]


def validate_profile(profile: dict[str, Any], repo_root: Path) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 100, failures, "profile intent must explain freshness goal")

    contract = as_dict(profile.get("freshness_contract"), "freshness_contract")
    require(
        contract.get("default_state") == "not_enterprise_ready_until_primary_sources_and_dependent_packs_are_current",
        failures,
        "freshness_contract.default_state must fail closed",
    )
    require(parse_source_date(contract.get("as_of")) is not None, failures, "freshness_contract.as_of must be a date")
    require(len(as_list(contract.get("required_publishers"), "freshness_contract.required_publishers")) >= 6, failures, "required_publishers must cover primary source families")
    require(len(as_list(contract.get("required_source_classes"), "freshness_contract.required_source_classes")) >= 4, failures, "required_source_classes must cover source classes")
    require(len(as_list(contract.get("review_lanes"), "freshness_contract.review_lanes")) >= 4, failures, "review_lanes must cover protocol, lab, government, and industry sources")

    watched = as_list(profile.get("watched_sources"), "watched_sources")
    require(len(watched) >= int(contract.get("minimum_watch_sources") or 0), failures, "watched source count below minimum")
    watched_ids: set[str] = set()
    for idx, source in enumerate(watched):
        item = as_dict(source, f"watched_sources[{idx}]")
        source_id = str(item.get("id", "")).strip()
        require(bool(source_id), failures, f"watched_sources[{idx}].id is required")
        require(source_id not in watched_ids, failures, f"{source_id}: duplicate watched source id")
        watched_ids.add(source_id)
        path = str(item.get("path", "")).strip()
        require(bool(path), failures, f"{source_id}: path is required")
        require(resolve(repo_root, Path(path)).exists(), failures, f"{source_id}: watched path does not exist: {path}")
        require(len(as_list(item.get("reference_paths"), f"{source_id}.reference_paths")) >= 1, failures, f"{source_id}: reference_paths are required")
        require(int(item.get("review_cadence_days") or 0) >= 7, failures, f"{source_id}: review_cadence_days must be at least seven")
        require(len(str(item.get("why", ""))) >= 50, failures, f"{source_id}: why must be specific")

    watchlist = as_list(profile.get("primary_watchlist"), "primary_watchlist")
    require(len(watchlist) >= int(contract.get("minimum_primary_watchlist_items") or 0), failures, "primary watchlist below minimum")
    for idx, item in enumerate(watchlist):
        watch = as_dict(item, f"primary_watchlist[{idx}]")
        require(str(watch.get("url", "")).startswith("https://"), failures, f"primary_watchlist[{idx}].url must be https")
        require(str(watch.get("publisher_family", "")).strip(), failures, f"primary_watchlist[{idx}].publisher_family is required")
        require(len(str(watch.get("commercial_reason", ""))) >= 50, failures, f"primary_watchlist[{idx}].commercial_reason must be specific")

    buyer_views = as_list(profile.get("buyer_views"), "buyer_views")
    require(len(buyer_views) >= 3, failures, "buyer_views must cover procurement, platform, and acquisition")
    return failures


def collect_watch_sources(
    profile: dict[str, Any],
    repo_root: Path,
    as_of: date,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[str, Path], dict[str, Path], list[str]]:
    failures: list[str] = []
    watch_rows: list[dict[str, Any]] = []
    source_catalog: dict[str, dict[str, Any]] = {}
    source_paths: dict[str, Path] = {}
    source_refs: dict[str, Path] = {}

    for watched in as_list(profile.get("watched_sources"), "watched_sources"):
        item = as_dict(watched, "watched_source")
        source_id = str(item.get("id"))
        path_ref = Path(str(item.get("path")))
        path = resolve(repo_root, path_ref)
        source_paths[source_id] = path
        source_refs[source_id] = path_ref
        missing = not path.exists()
        payload: dict[str, Any] = {}
        references: list[dict[str, Any]] = []

        if not missing:
            payload = load_json(path)
            for ref_path in as_list(item.get("reference_paths"), f"{source_id}.reference_paths"):
                for raw in get_nested_list(payload, str(ref_path)):
                    if isinstance(raw, dict):
                        references.append(raw)

        reviewed = parse_source_date(payload.get("last_reviewed") or payload.get("generated_at"))
        cadence = int(item.get("review_cadence_days") or 30)
        decision, blockers = review_decision(reviewed, cadence, as_of, len(references), missing)
        due_at = reviewed + timedelta(days=cadence) if reviewed else None

        for source in references:
            key = source_key(source)
            published = parse_source_date(source.get("published"))
            entry = source_catalog.setdefault(
                key,
                {
                    "id": source.get("id"),
                    "name": source_title(source),
                    "publisher": source.get("publisher") or "Unknown",
                    "publisher_family": publisher_family(source.get("publisher")),
                    "published": source.get("published") or None,
                    "published_date": date_text(published),
                    "source_class": source.get("source_class") or "unknown",
                    "source_class_family": source_class_family(source.get("source_class")),
                    "url": source.get("url") or None,
                    "why_it_matters": source_reason(source),
                    "referenced_by": [],
                    "freshness_class": freshness_class(published, as_of),
                    "published_age_days": (as_of - published).days if published else None,
                },
            )
            entry["referenced_by"].append(
                {
                    "watched_source_id": source_id,
                    "watched_source_title": item.get("title"),
                    "path": normalize_path(path_ref),
                }
            )

        watch_rows.append(
            {
                "blockers": blockers,
                "business_criticality": item.get("business_criticality"),
                "decision": decision,
                "id": source_id,
                "last_reviewed": date_text(reviewed),
                "path": normalize_path(path_ref),
                "reference_count": len(references),
                "reference_paths": item.get("reference_paths", []),
                "review_cadence_days": cadence,
                "review_due_at": date_text(due_at),
                "title": item.get("title"),
                "why": item.get("why"),
            }
        )

    return watch_rows, source_catalog, source_paths, source_refs, failures


def primary_watchlist_coverage(profile: dict[str, Any], source_catalog: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    by_url: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for source in source_catalog.values():
        url = str(source.get("url") or "").strip().lower()
        if url:
            by_url[url].append(source)

    rows: list[dict[str, Any]] = []
    for item in as_list(profile.get("primary_watchlist"), "primary_watchlist"):
        watch = as_dict(item, "primary_watchlist_item")
        url = str(watch.get("url") or "").strip().lower()
        matches = by_url.get(url, [])
        rows.append(
            {
                "commercial_reason": watch.get("commercial_reason"),
                "found": bool(matches),
                "id": watch.get("id"),
                "publisher_family": watch.get("publisher_family"),
                "review_cadence_days": watch.get("review_cadence_days"),
                "source_ids": [source.get("id") for source in matches],
                "title": watch.get("title"),
                "url": watch.get("url"),
                "watched_source_ids": sorted(
                    {
                        ref.get("watched_source_id")
                        for source in matches
                        for ref in source.get("referenced_by", [])
                        if isinstance(ref, dict)
                    }
                ),
            }
        )
    return rows


def validate_coverage(
    profile: dict[str, Any],
    watch_rows: list[dict[str, Any]],
    source_catalog: dict[str, dict[str, Any]],
    primary_coverage: list[dict[str, Any]],
) -> list[str]:
    failures: list[str] = []
    contract = as_dict(profile.get("freshness_contract"), "freshness_contract")
    source_count = len(source_catalog)
    require(source_count >= int(contract.get("minimum_unique_source_references") or 0), failures, "unique source reference count below minimum")

    due_count = sum(1 for row in watch_rows if row.get("decision") != "current")
    require(due_count <= int(contract.get("maximum_due_watch_sources") or 0), failures, "one or more watched source packs are due or blocked")

    publisher_families = {str(source.get("publisher_family")) for source in source_catalog.values()}
    for publisher in as_list(contract.get("required_publishers"), "freshness_contract.required_publishers"):
        require(str(publisher) in publisher_families, failures, f"missing required publisher family: {publisher}")

    class_families = {str(source.get("source_class_family")) for source in source_catalog.values()}
    class_names = {str(source.get("source_class")) for source in source_catalog.values()}
    for required in as_list(contract.get("required_source_classes"), "freshness_contract.required_source_classes"):
        required_text = str(required)
        require(
            required_text in class_names or source_class_family(required_text) in class_families,
            failures,
            f"missing required source class: {required_text}",
        )

    missing_primary = [row.get("id") for row in primary_coverage if not row.get("found")]
    require(not missing_primary, failures, f"primary watchlist sources are not referenced: {missing_primary}")
    return failures


def source_artifacts(
    profile_path: Path,
    profile_ref: Path,
    source_paths: dict[str, Path],
    source_refs: dict[str, Path],
) -> dict[str, Any]:
    artifacts = {
        "agentic_source_freshness_profile": {
            "path": normalize_path(profile_ref),
            "sha256": sha256_file(profile_path),
        }
    }
    for source_id, path in sorted(source_paths.items()):
        if path.exists():
            artifacts[source_id] = {
                "path": normalize_path(source_refs[source_id]),
                "sha256": sha256_file(path),
            }
    return artifacts


def build_summary(
    watch_rows: list[dict[str, Any]],
    source_catalog: dict[str, dict[str, Any]],
    primary_coverage: list[dict[str, Any]],
    failures: list[str],
) -> dict[str, Any]:
    decisions = Counter(str(row.get("decision")) for row in watch_rows)
    publishers = Counter(str(source.get("publisher_family")) for source in source_catalog.values())
    classes = Counter(str(source.get("source_class")) for source in source_catalog.values())
    freshness = Counter(str(source.get("freshness_class")) for source in source_catalog.values())
    newest = sorted(
        [source for source in source_catalog.values() if source.get("published_date")],
        key=lambda source: str(source.get("published_date")),
        reverse=True,
    )
    return {
        "failure_count": len(failures),
        "freshness_class_counts": dict(sorted(freshness.items())),
        "newest_sources": [
            {
                "id": source.get("id"),
                "name": source.get("name"),
                "published": source.get("published"),
                "publisher_family": source.get("publisher_family"),
                "url": source.get("url"),
            }
            for source in newest[:8]
        ],
        "primary_watchlist_covered_count": sum(1 for row in primary_coverage if row.get("found")),
        "primary_watchlist_count": len(primary_coverage),
        "publisher_family_counts": dict(sorted(publishers.items())),
        "source_class_counts": dict(sorted(classes.items())),
        "status": "source_freshness_ready" if not failures else "needs_freshness_review",
        "unique_source_reference_count": len(source_catalog),
        "watch_decision_counts": dict(sorted(decisions.items())),
        "watch_source_count": len(watch_rows),
    }


def build_pack(
    *,
    profile: dict[str, Any],
    profile_path: Path,
    profile_ref: Path,
    repo_root: Path,
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    contract = as_dict(profile.get("freshness_contract"), "freshness_contract")
    as_of = parse_source_date(generated_at or contract.get("as_of") or profile.get("last_reviewed"))
    if as_of is None:
        raise SourceFreshnessError("freshness as_of date is invalid")

    watch_rows, source_catalog, source_paths, source_refs, collect_failures = collect_watch_sources(profile, repo_root, as_of)
    primary_coverage = primary_watchlist_coverage(profile, source_catalog)
    failures = [*failures, *collect_failures, *validate_coverage(profile, watch_rows, source_catalog, primary_coverage)]
    source_rows = sorted(
        source_catalog.values(),
        key=lambda source: (str(source.get("publisher_family")), str(source.get("name")), str(source.get("url"))),
    )

    return {
        "buyer_views": profile.get("buyer_views", []),
        "commercialization_path": profile.get("commercialization_path", {}),
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "failures": failures,
        "freshness_contract": profile.get("freshness_contract", {}),
        "freshness_summary": build_summary(watch_rows, source_catalog, primary_coverage, failures),
        "generated_at": generated_at or str(contract.get("as_of") or profile.get("last_reviewed")),
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "primary_watchlist_coverage": primary_coverage,
        "schema_version": PACK_SCHEMA_VERSION,
        "selected_feature": {
            "id": "agentic-source-freshness-watch",
            "implementation": [
                "Source freshness profile under data/assurance.",
                "Deterministic generator under scripts.",
                "Generated evidence pack under data/evidence.",
                "Human-readable docs page under security-remediation.",
                "MCP exposure through recipes_agentic_source_freshness_watch."
            ],
            "reason": "The product already has many generated evidence packs; the next enterprise-grade proof point is showing that current source guidance and dependent packs are monitored as maintained dependencies."
        },
        "source_artifacts": source_artifacts(profile_path, profile_ref, source_paths, source_refs),
        "source_catalog": source_rows,
        "watch_sources": sorted(watch_rows, key=lambda row: str(row.get("id"))),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in source freshness watch is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    profile_path = resolve(repo_root, args.profile)
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(profile_path)
        failures = validate_profile(profile, repo_root)
        pack = build_pack(
            profile=profile,
            profile_path=profile_path,
            profile_ref=args.profile,
            repo_root=repo_root,
            generated_at=args.generated_at,
            failures=failures,
        )
    except SourceFreshnessError as exc:
        print(f"agentic source freshness watch generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(pack)
    if args.check:
        if pack.get("failures"):
            print("agentic source freshness watch validation failed:", file=sys.stderr)
            for failure in pack.get("failures", []):
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_agentic_source_freshness_watch.py", file=sys.stderr)
            return 1
        if current_text != next_text:
            print(f"{output_path} is stale; run scripts/generate_agentic_source_freshness_watch.py", file=sys.stderr)
            return 1
        print(f"Validated agentic source freshness watch: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")
    if pack.get("failures"):
        print("Generated agentic source freshness watch with validation failures:", file=sys.stderr)
        for failure in pack.get("failures", []):
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated agentic source freshness watch: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
