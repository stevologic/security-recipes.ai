#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic threat radar.

The threat radar is the market-facing bridge between current agentic AI
security guidance and the product capabilities in this repo. It maps
source-backed threat signals to SecurityRecipes controls, MCP tools,
evidence artifacts, buyer triggers, and recommended roadmap moves.

The output is deterministic by default so CI can run with --check and
fail when the checked-in radar drifts from source intelligence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


RADAR_SCHEMA_VERSION = "1.0"
DEFAULT_SOURCES = Path("data/intelligence/agentic-threat-radar-sources.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-threat-radar.json")

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]+$")
VALID_PRIORITIES = {"critical", "high", "medium", "watch"}
VALID_HORIZONS = {"now", "next", "monitor"}
VALID_CONFIDENCE = {"high", "medium", "watch"}
VALID_STATUS = {"implemented", "recommended_next", "planned", "watch"}
SCORE_KEYS = {
    "market_urgency",
    "enterprise_control_value",
    "mcp_monetization_fit",
    "defensibility",
    "ease_of_adoption",
}
PRIORITY_FACTOR = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.55,
    "watch": 0.35,
}
HORIZON_FACTOR = {
    "now": 1.0,
    "next": 0.7,
    "monitor": 0.4,
}


class AgenticThreatRadarError(RuntimeError):
    """Raised when the threat radar cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AgenticThreatRadarError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise AgenticThreatRadarError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AgenticThreatRadarError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise AgenticThreatRadarError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgenticThreatRadarError(f"{label} must be an object")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def normalize_path(path: Path) -> str:
    return path.as_posix()


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def source_refs_by_id(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(source.get("id")): source
        for source in as_list(registry.get("source_references"), "source_references")
        if isinstance(source, dict) and source.get("id")
    }


def capabilities_by_id(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(capability.get("id")): capability
        for capability in as_list(registry.get("product_capabilities"), "product_capabilities")
        if isinstance(capability, dict) and capability.get("id")
    }


def score_signal(signal: dict[str, Any]) -> int:
    scores = signal.get("scores") if isinstance(signal.get("scores"), dict) else {}
    score_values = [
        int(scores.get(key) or 0)
        for key in SCORE_KEYS
    ]
    quality_score = (sum(score_values) / (len(SCORE_KEYS) * 5)) * 60
    priority_score = PRIORITY_FACTOR.get(str(signal.get("priority")), 0) * 25
    horizon_score = HORIZON_FACTOR.get(str(signal.get("horizon")), 0) * 15
    return min(100, round(quality_score + priority_score + horizon_score))


def output_path_allowed(path: str, output_ref: Path) -> bool:
    return Path(path).as_posix() == output_ref.as_posix()


def validate_registry(registry: dict[str, Any], repo_root: Path, output_ref: Path) -> list[str]:
    failures: list[str] = []
    require(registry.get("schema_version") == RADAR_SCHEMA_VERSION, failures, "registry schema_version must be 1.0")
    require(len(str(registry.get("intent", ""))) >= 80, failures, "registry intent must explain the product goal")

    source_refs = as_list(registry.get("source_references"), "source_references")
    require(len(source_refs) >= 10, failures, "source_references must include at least ten current references")
    source_ids: set[str] = set()
    source_classes: set[str] = set()
    for idx, source in enumerate(source_refs):
        label = f"source_references[{idx}]"
        if not isinstance(source, dict):
            failures.append(f"{label} must be an object")
            continue
        source_id = str(source.get("id", "")).strip()
        require(bool(ID_RE.match(source_id)), failures, f"{label}.id must be kebab-case")
        require(source_id not in source_ids, failures, f"{label}.id duplicates {source_id}")
        source_ids.add(source_id)
        source_classes.add(str(source.get("source_class", "")).strip())
        require(str(source.get("url", "")).startswith("https://"), failures, f"{source_id}: url must be https")
        require(str(source.get("publisher", "")).strip(), failures, f"{source_id}: publisher is required")
        require(str(source.get("published", "")).strip(), failures, f"{source_id}: published is required")
        require(len(str(source.get("why_it_matters", ""))) >= 40, failures, f"{source_id}: why_it_matters must be specific")

    require("industry_standard" in source_classes, failures, "source_references must include industry standards")
    require("government_framework" in source_classes, failures, "source_references must include government frameworks")
    require("frontier_lab_guidance" in source_classes, failures, "source_references must include frontier lab guidance")
    require("protocol_specification" in source_classes, failures, "source_references must include protocol specifications")

    capabilities = as_list(registry.get("product_capabilities"), "product_capabilities")
    require(len(capabilities) >= 8, failures, "product_capabilities must include the current product surface")
    capability_ids: set[str] = set()
    for idx, capability in enumerate(capabilities):
        label = f"product_capabilities[{idx}]"
        if not isinstance(capability, dict):
            failures.append(f"{label} must be an object")
            continue
        capability_id = str(capability.get("id", "")).strip()
        require(bool(ID_RE.match(capability_id)), failures, f"{label}.id must be kebab-case")
        require(capability_id not in capability_ids, failures, f"{label}.id duplicates {capability_id}")
        capability_ids.add(capability_id)
        require(str(capability.get("status")) in VALID_STATUS, failures, f"{capability_id}: status is invalid")
        require(len(str(capability.get("buyer_value", ""))) >= 40, failures, f"{capability_id}: buyer_value must be specific")
        require(bool(as_list(capability.get("evidence_paths"), f"{label}.evidence_paths")), failures, f"{capability_id}: evidence_paths are required")
        for raw_path in capability.get("evidence_paths", []) or []:
            path = str(raw_path)
            if output_path_allowed(path, output_ref):
                continue
            require((repo_root / path).exists(), failures, f"{capability_id}: evidence path does not exist: {path}")

    signals = as_list(registry.get("threat_signals"), "threat_signals")
    require(len(signals) >= 8, failures, "threat_signals must include at least eight threat signals")
    signal_ids: set[str] = set()
    covered_capabilities: set[str] = set()
    critical_count = 0
    for idx, signal in enumerate(signals):
        label = f"threat_signals[{idx}]"
        if not isinstance(signal, dict):
            failures.append(f"{label} must be an object")
            continue
        signal_id = str(signal.get("id", "")).strip()
        priority = str(signal.get("priority", "")).strip()
        source_list = [str(item) for item in as_list(signal.get("source_ids"), f"{label}.source_ids")]
        capability_list = [str(item) for item in as_list(signal.get("mapped_capability_ids"), f"{label}.mapped_capability_ids")]
        scores = signal.get("scores") if isinstance(signal.get("scores"), dict) else {}

        require(bool(ID_RE.match(signal_id)), failures, f"{label}.id must be kebab-case")
        require(signal_id not in signal_ids, failures, f"{label}.id duplicates {signal_id}")
        signal_ids.add(signal_id)
        require(priority in VALID_PRIORITIES, failures, f"{signal_id}: priority is invalid")
        require(str(signal.get("horizon")) in VALID_HORIZONS, failures, f"{signal_id}: horizon is invalid")
        require(str(signal.get("confidence")) in VALID_CONFIDENCE, failures, f"{signal_id}: confidence is invalid")
        require(len(str(signal.get("trend", ""))) >= 80, failures, f"{signal_id}: trend must be specific")
        require(len(str(signal.get("enterprise_risk", ""))) >= 60, failures, f"{signal_id}: enterprise_risk must be specific")
        require(len(str(signal.get("buyer_trigger", ""))) >= 40, failures, f"{signal_id}: buyer_trigger must be specific")
        require(len(str(signal.get("roadmap_action", ""))) >= 40, failures, f"{signal_id}: roadmap_action must be specific")
        require(len(as_list(signal.get("control_objectives"), f"{label}.control_objectives")) >= 3, failures, f"{signal_id}: at least three control objectives are required")
        require(len(source_list) >= 3, failures, f"{signal_id}: at least three source references are required")
        require(len(capability_list) >= 3, failures, f"{signal_id}: at least three mapped capabilities are required")
        for source_id in source_list:
            require(source_id in source_ids, failures, f"{signal_id}: references unknown source {source_id}")
        for capability_id in capability_list:
            require(capability_id in capability_ids, failures, f"{signal_id}: references unknown capability {capability_id}")
            covered_capabilities.add(capability_id)
        require(set(scores.keys()) == SCORE_KEYS, failures, f"{signal_id}: scores must include {sorted(SCORE_KEYS)}")
        for key in SCORE_KEYS:
            value = scores.get(key)
            require(isinstance(value, int) and 1 <= value <= 5, failures, f"{signal_id}: score {key} must be 1-5")
        if priority == "critical":
            critical_count += 1

    require(critical_count >= 3, failures, "threat_signals must include at least three critical signals")
    missing_capability_coverage = sorted(capability_ids - covered_capabilities)
    require(not missing_capability_coverage, failures, f"threat_signals do not cover capabilities: {missing_capability_coverage}")

    feature_backlog = as_list(registry.get("feature_backlog"), "feature_backlog")
    require(len(feature_backlog) >= 3, failures, "feature_backlog must include at least three recommended features")
    backlog_ids: set[str] = set()
    for idx, feature in enumerate(feature_backlog):
        label = f"feature_backlog[{idx}]"
        if not isinstance(feature, dict):
            failures.append(f"{label} must be an object")
            continue
        feature_id = str(feature.get("id", "")).strip()
        require(bool(ID_RE.match(feature_id)), failures, f"{label}.id must be kebab-case")
        require(feature_id not in backlog_ids, failures, f"{label}.id duplicates {feature_id}")
        backlog_ids.add(feature_id)
        require(str(feature.get("status")) in VALID_STATUS, failures, f"{feature_id}: status is invalid")
        require(len(str(feature.get("why", ""))) >= 50, failures, f"{feature_id}: why must be specific")
        for signal_id in as_list(feature.get("related_signal_ids"), f"{label}.related_signal_ids"):
            require(str(signal_id) in signal_ids, failures, f"{feature_id}: references unknown signal {signal_id}")

    return failures


def source_preview(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": source.get("id"),
        "name": source.get("name"),
        "published": source.get("published"),
        "publisher": source.get("publisher"),
        "source_class": source.get("source_class"),
        "url": source.get("url"),
    }


def capability_preview(capability: dict[str, Any]) -> dict[str, Any]:
    return {
        "buyer_value": capability.get("buyer_value"),
        "evidence_paths": capability.get("evidence_paths", []),
        "id": capability.get("id"),
        "mcp_tools": capability.get("mcp_tools", []),
        "status": capability.get("status"),
        "title": capability.get("title"),
    }


def build_path_evidence(registry: dict[str, Any], repo_root: Path, output_ref: Path) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for capability in registry.get("product_capabilities", []) or []:
        if not isinstance(capability, dict):
            continue
        for raw_path in capability.get("evidence_paths", []) or []:
            path = str(raw_path)
            if output_path_allowed(path, output_ref):
                continue
            resolved = repo_root / path
            if not resolved.exists() or not resolved.is_file():
                continue
            rows[path] = {
                "path": path,
                "sha256": sha256_file(resolved),
            }
    return [rows[path] for path in sorted(rows)]


def build_signal_rows(registry: dict[str, Any]) -> list[dict[str, Any]]:
    sources = source_refs_by_id(registry)
    capabilities = capabilities_by_id(registry)
    rows: list[dict[str, Any]] = []
    for signal in as_list(registry.get("threat_signals"), "threat_signals"):
        if not isinstance(signal, dict):
            continue
        row = {
            "buyer_trigger": signal.get("buyer_trigger"),
            "capabilities": [
                capability_preview(capabilities[capability_id])
                for capability_id in signal.get("mapped_capability_ids", [])
                if capability_id in capabilities
            ],
            "confidence": signal.get("confidence"),
            "control_objectives": signal.get("control_objectives", []),
            "enterprise_risk": signal.get("enterprise_risk"),
            "horizon": signal.get("horizon"),
            "id": signal.get("id"),
            "mapped_capability_ids": signal.get("mapped_capability_ids", []),
            "priority": signal.get("priority"),
            "roadmap_action": signal.get("roadmap_action"),
            "scores": signal.get("scores", {}),
            "source_ids": signal.get("source_ids", []),
            "sources": [
                source_preview(sources[source_id])
                for source_id in signal.get("source_ids", [])
                if source_id in sources
            ],
            "strategic_score": score_signal(signal),
            "title": signal.get("title"),
            "trend": signal.get("trend"),
        }
        rows.append(row)
    return sorted(rows, key=lambda row: (-int(row.get("strategic_score") or 0), str(row.get("id"))))


def build_capability_coverage(signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    coverage: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for signal in signals:
        for capability_id in signal.get("mapped_capability_ids", []) or []:
            coverage[str(capability_id)].append(signal)

    rows: list[dict[str, Any]] = []
    for capability_id in sorted(coverage):
        capability_signals = coverage[capability_id]
        rows.append(
            {
                "capability_id": capability_id,
                "critical_or_high_signal_count": sum(
                    1
                    for signal in capability_signals
                    if signal.get("priority") in {"critical", "high"}
                ),
                "max_strategic_score": max(int(signal.get("strategic_score") or 0) for signal in capability_signals),
                "signal_count": len(capability_signals),
                "signal_ids": [signal.get("id") for signal in capability_signals],
            }
        )
    return rows


def build_feature_recommendations(registry: dict[str, Any], signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    signals_by_id = {str(signal.get("id")): signal for signal in signals}
    rows: list[dict[str, Any]] = []
    for feature in as_list(registry.get("feature_backlog"), "feature_backlog"):
        if not isinstance(feature, dict):
            continue
        related = [
            signals_by_id[str(signal_id)]
            for signal_id in feature.get("related_signal_ids", []) or []
            if str(signal_id) in signals_by_id
        ]
        rows.append(
            {
                "id": feature.get("id"),
                "related_signal_ids": feature.get("related_signal_ids", []),
                "status": feature.get("status"),
                "supporting_signal_count": len(related),
                "supporting_signal_max_score": max([int(signal.get("strategic_score") or 0) for signal in related] or [0]),
                "supporting_signal_priority_counts": dict(
                    sorted(Counter(str(signal.get("priority")) for signal in related).items())
                ),
                "title": feature.get("title"),
                "why": feature.get("why"),
            }
        )
    return sorted(rows, key=lambda row: (-int(row.get("supporting_signal_max_score") or 0), str(row.get("id"))))


def build_summary(registry: dict[str, Any], signals: list[dict[str, Any]]) -> dict[str, Any]:
    priorities = Counter(str(signal.get("priority")) for signal in signals)
    horizons = Counter(str(signal.get("horizon")) for signal in signals)
    confidence = Counter(str(signal.get("confidence")) for signal in signals)
    source_classes = Counter(str(source.get("source_class")) for source in registry.get("source_references", []) if isinstance(source, dict))
    implemented_capabilities = [
        capability
        for capability in registry.get("product_capabilities", []) or []
        if isinstance(capability, dict) and capability.get("status") == "implemented"
    ]

    return {
        "confidence_counts": dict(sorted(confidence.items())),
        "critical_or_high_signal_count": sum(priorities[key] for key in ("critical", "high")),
        "feature_backlog_count": len(registry.get("feature_backlog", []) or []),
        "horizon_counts": dict(sorted(horizons.items())),
        "implemented_capability_count": len(implemented_capabilities),
        "priority_counts": dict(sorted(priorities.items())),
        "signal_count": len(signals),
        "source_class_counts": dict(sorted(source_classes.items())),
        "source_reference_count": len(registry.get("source_references", []) or []),
        "top_signals": [
            {
                "id": signal.get("id"),
                "priority": signal.get("priority"),
                "strategic_score": signal.get("strategic_score"),
                "title": signal.get("title"),
            }
            for signal in signals[:5]
        ],
    }


def build_pack(
    *,
    registry: dict[str, Any],
    sources_path: Path,
    sources_ref: Path,
    output_ref: Path,
    repo_root: Path,
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    signals = build_signal_rows(registry)
    capability_rows = [capability_preview(capability) for capability in registry.get("product_capabilities", []) if isinstance(capability, dict)]

    return {
        "acquisition_story": {
            "category_claim": "SecurityRecipes is the secure context and control evidence layer for agentic AI, not only a static recipe catalog.",
            "defensibility": [
                "Open knowledge attracts practitioners and creates distribution.",
                "Generated evidence packs create machine-readable trust that buyers and MCP clients can consume.",
                "Runtime evaluators move policy from prose to enforceable decisions.",
                "Threat radar keeps the product roadmap anchored to current standards and frontier-lab guidance."
            ],
            "likely_acquirer_fit": [
                "Frontier AI labs that need secure MCP and agent governance primitives.",
                "Security platforms that need agentic remediation and AI control-plane evidence.",
                "Cloud and developer platforms that need trustworthy agent enablement for enterprise buyers."
            ],
            "monetization_path": "Keep the knowledge base open, then sell hosted MCP policy, context signing, connector intake, runtime decision logs, eval replay, and trust-center exports."
        },
        "capability_coverage": build_capability_coverage(signals),
        "enterprise_adoption_packet": {
            "board_level_claim": "SecurityRecipes tracks current agentic AI risk and maps it to enforceable secure-context, MCP, identity, evidence, and eval controls.",
            "default_questions_answered": [
                "Which agentic AI risks are most urgent right now?",
                "Which sources support each risk signal?",
                "Which SecurityRecipes controls already address the signal?",
                "Which MCP tools expose the evidence?",
                "Which product investments should come next?"
            ],
            "recommended_first_use": "Attach this radar to AI platform strategy reviews, MCP server intake, quarterly threat-model updates, procurement security reviews, and acquisition diligence.",
            "sales_motion": "Lead with public threat intelligence and open recipes, then sell the hosted control plane that keeps customer-specific context, connector evidence, policy decisions, and eval replay current."
        },
        "failures": failures,
        "feature_backlog": build_feature_recommendations(registry, signals),
        "generated_at": generated_at or str(registry.get("last_reviewed", "")),
        "intent": registry.get("intent"),
        "path_evidence": build_path_evidence(registry, repo_root, output_ref),
        "positioning": registry.get("positioning", {}),
        "product_capabilities": capability_rows,
        "schema_version": RADAR_SCHEMA_VERSION,
        "selected_feature": {
            "id": "agentic-threat-radar",
            "implementation": [
                "Source registry under data/intelligence.",
                "Deterministic generator under scripts.",
                "Generated evidence pack under data/evidence.",
                "Human-readable docs page under security-remediation.",
                "MCP tool exposure through recipes_agentic_threat_radar."
            ],
            "reason": "It increases credibility by proving SecurityRecipes can translate fast-moving AI security guidance into current, productized, MCP-readable control evidence."
        },
        "source_artifacts": {
            "agentic_threat_radar_sources": {
                "path": normalize_path(sources_ref),
                "sha256": sha256_file(sources_path),
            }
        },
        "source_references": registry.get("source_references", []),
        "threat_radar_summary": build_summary(registry, signals),
        "threat_signals": signals,
    }


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in threat radar is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    sources_path = resolve(repo_root, args.sources)
    output_path = resolve(repo_root, args.output)

    try:
        registry = load_json(sources_path)
        failures = validate_registry(registry, repo_root, args.output)
        pack = build_pack(
            registry=registry,
            sources_path=sources_path,
            sources_ref=args.sources,
            output_ref=args.output,
            repo_root=repo_root,
            generated_at=args.generated_at,
            failures=failures,
        )
    except AgenticThreatRadarError as exc:
        print(f"agentic threat radar generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(pack)

    if args.check:
        if failures:
            print("agentic threat radar validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run this script without --check", file=sys.stderr)
            return 1
        if current_text != next_text:
            print(
                f"{output_path} is stale; run scripts/generate_agentic_threat_radar.py",
                file=sys.stderr,
            )
            return 1
        print(f"Validated agentic threat radar: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")

    if failures:
        print("Generated agentic threat radar with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated agentic threat radar: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
