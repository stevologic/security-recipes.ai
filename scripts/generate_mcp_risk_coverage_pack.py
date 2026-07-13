#!/usr/bin/env python3
"""Generate the SecurityRecipes MCP and agentic-skill risk coverage pack.

The pack maps current MCP and agentic-skill risk frameworks into the
repo's generated evidence surface. It is intentionally deterministic so
CI can prove the coverage packet is not stale after evidence, content,
or standards updates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


PACK_SCHEMA_VERSION = "1.0"
DEFAULT_PROFILE = Path("data/assurance/mcp-risk-coverage-profile.json")
DEFAULT_OUTPUT = Path("data/evidence/mcp-risk-coverage-pack.json")
VALID_STATUS = {"implemented", "planned", "watch"}
VALID_RISK_TIERS = {"critical", "high", "medium", "low"}


class MCPRiskCoverageError(RuntimeError):
    """Raised when the MCP risk coverage pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise MCPRiskCoverageError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise MCPRiskCoverageError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise MCPRiskCoverageError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MCPRiskCoverageError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise MCPRiskCoverageError(f"{label} must be a list")
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


def capability_by_id(profile: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(capability.get("id")): capability
        for capability in profile.get("capabilities", [])
        if isinstance(capability, dict) and capability.get("id")
    }


def source_by_id(profile: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(source.get("id")): source
        for source in profile.get("source_references", [])
        if isinstance(source, dict) and source.get("id")
    }


def risk_rows(profile: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for standard in as_list(profile.get("standards"), "standards"):
        standard_item = as_dict(standard, "standard")
        standard_id = str(standard_item.get("id"))
        source_ids = [str(source_id) for source_id in standard_item.get("source_ids", [])]
        for risk in as_list(standard_item.get("risks"), f"{standard_id}.risks"):
            risk_item = dict(as_dict(risk, "risk"))
            risk_item["standard_id"] = standard_id
            risk_item["standard_title"] = standard_item.get("title")
            risk_item["source_ids"] = source_ids
            rows.append(risk_item)
    return rows


def validate_profile(profile: dict[str, Any], repo_root: Path) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must describe the coverage goal")

    contract = as_dict(profile.get("coverage_contract"), "coverage_contract")
    require(
        contract.get("default_state") == "not_coverage_ready_until_each_mcp_and_skill_risk_maps_to_generated_evidence",
        failures,
        "coverage_contract.default_state must fail closed",
    )

    sources = as_list(profile.get("source_references"), "source_references")
    minimum_sources = int(contract.get("minimum_source_references") or 0)
    require(len(sources) >= minimum_sources, failures, "source reference count is below minimum")
    source_ids: set[str] = set()
    for idx, source in enumerate(sources):
        item = as_dict(source, f"source_references[{idx}]")
        source_id = str(item.get("id", "")).strip()
        require(bool(source_id), failures, f"source_references[{idx}].id is required")
        require(source_id not in source_ids, failures, f"{source_id}: duplicate source id")
        source_ids.add(source_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{source_id}: url must be https")
        require(str(item.get("publisher", "")).strip(), failures, f"{source_id}: publisher is required")
        require(len(str(item.get("why_it_matters", ""))) >= 70, failures, f"{source_id}: why_it_matters must be specific")

    capabilities = as_list(profile.get("capabilities"), "capabilities")
    minimum_capabilities = int(contract.get("minimum_capabilities") or 0)
    require(len(capabilities) >= minimum_capabilities, failures, "capability count is below minimum")
    capability_ids: set[str] = set()
    for idx, capability in enumerate(capabilities):
        item = as_dict(capability, f"capabilities[{idx}]")
        capability_id = str(item.get("id", "")).strip()
        require(bool(capability_id), failures, f"capabilities[{idx}].id is required")
        require(capability_id not in capability_ids, failures, f"{capability_id}: duplicate capability id")
        capability_ids.add(capability_id)
        require(str(item.get("status")) in VALID_STATUS, failures, f"{capability_id}: status is invalid")
        require(len(str(item.get("commercial_value", ""))) >= 70, failures, f"{capability_id}: commercial_value must be specific")
        paths = as_list(item.get("evidence_paths"), f"{capability_id}.evidence_paths")
        require(bool(paths), failures, f"{capability_id}: evidence_paths are required")
        for raw_path in paths:
            path = Path(str(raw_path))
            require(resolve(repo_root, path).exists(), failures, f"{capability_id}: evidence path does not exist: {path}")
        require(bool(as_list(item.get("mcp_tools"), f"{capability_id}.mcp_tools")), failures, f"{capability_id}: mcp_tools are required")

    for capability_id in as_list(contract.get("required_capability_ids"), "coverage_contract.required_capability_ids"):
        require(str(capability_id) in capability_ids, failures, f"required capability is missing: {capability_id}")

    standards = as_list(profile.get("standards"), "standards")
    standard_ids: set[str] = set()
    risk_ids: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards[{idx}].id is required")
        require(standard_id not in standard_ids, failures, f"{standard_id}: duplicate standard id")
        standard_ids.add(standard_id)
        require(str(item.get("title", "")).strip(), failures, f"{standard_id}: title is required")
        for source_id in as_list(item.get("source_ids"), f"{standard_id}.source_ids"):
            require(str(source_id) in source_ids, failures, f"{standard_id}: unknown source_id {source_id}")
        risks = as_list(item.get("risks"), f"{standard_id}.risks")
        require(len(risks) >= 10, failures, f"{standard_id}: at least ten risks are required")
        for risk_idx, risk in enumerate(risks):
            risk_item = as_dict(risk, f"{standard_id}.risks[{risk_idx}]")
            risk_id = str(risk_item.get("id", "")).strip()
            require(bool(risk_id), failures, f"{standard_id}.risks[{risk_idx}].id is required")
            require(risk_id not in risk_ids, failures, f"{risk_id}: duplicate risk id")
            risk_ids.add(risk_id)
            require(str(risk_item.get("risk_tier")) in VALID_RISK_TIERS, failures, f"{risk_id}: risk_tier is invalid")
            required_capabilities = as_list(risk_item.get("required_capability_ids"), f"{risk_id}.required_capability_ids")
            require(len(required_capabilities) >= 3, failures, f"{risk_id}: at least three capabilities are required")
            for capability_id in required_capabilities:
                require(str(capability_id) in capability_ids, failures, f"{risk_id}: unknown capability {capability_id}")
            require(len(str(risk_item.get("primary_attack_path", ""))) >= 70, failures, f"{risk_id}: primary_attack_path must be specific")
            require(len(str(risk_item.get("diligence_question", ""))) >= 60, failures, f"{risk_id}: diligence_question must be specific")
            require(len(str(risk_item.get("evidence_expectation", ""))) >= 80, failures, f"{risk_id}: evidence_expectation must be specific")

    minimum_risks = int(contract.get("minimum_risks") or 0)
    require(len(risk_ids) >= minimum_risks, failures, "risk count is below minimum")

    buyer_views = as_list(profile.get("buyer_views"), "buyer_views")
    require(len(buyer_views) >= 3, failures, "buyer views must include platform, skill governance, and diligence views")
    for idx, buyer_view in enumerate(buyer_views):
        item = as_dict(buyer_view, f"buyer_views[{idx}]")
        for standard_id in as_list(item.get("standard_ids"), f"buyer_views[{idx}].standard_ids"):
            require(str(standard_id) in standard_ids, failures, f"{item.get('id', idx)}: unknown standard id {standard_id}")
        require(len(str(item.get("answer_contract", ""))) >= 70, failures, f"{item.get('id', idx)}: answer_contract must be specific")

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
        "commercial_value": capability.get("commercial_value"),
        "evidence_paths": capability.get("evidence_paths", []),
        "id": capability.get("id"),
        "mcp_tools": capability.get("mcp_tools", []),
        "status": capability.get("status"),
        "title": capability.get("title"),
    }


def build_risk_coverage(profile: dict[str, Any]) -> list[dict[str, Any]]:
    capabilities = capability_by_id(profile)
    sources = source_by_id(profile)
    rows: list[dict[str, Any]] = []
    for risk in risk_rows(profile):
        capability_ids = [str(capability_id) for capability_id in risk.get("required_capability_ids", [])]
        mapped_capabilities = [
            capability_preview(capabilities[capability_id])
            for capability_id in capability_ids
            if capability_id in capabilities
        ]
        source_ids = [str(source_id) for source_id in risk.get("source_ids", [])]
        evidence_paths = sorted(
            {
                str(path)
                for capability in mapped_capabilities
                for path in capability.get("evidence_paths", [])
            }
        )
        mcp_tools = sorted(
            {
                str(tool)
                for capability in mapped_capabilities
                for tool in capability.get("mcp_tools", [])
            }
        )
        ready = len(mapped_capabilities) == len(capability_ids) and all(
            str(capability.get("status")) == "implemented"
            for capability in mapped_capabilities
        )
        rows.append(
            {
                "capabilities": mapped_capabilities,
                "commercialization_hook": risk.get("commercialization_hook"),
                "coverage_status": "covered" if ready else "needs_attention",
                "diligence_question": risk.get("diligence_question"),
                "evidence_expectation": risk.get("evidence_expectation"),
                "evidence_paths": evidence_paths,
                "id": risk.get("id"),
                "mcp_tools": mcp_tools,
                "primary_attack_path": risk.get("primary_attack_path"),
                "required_capability_ids": capability_ids,
                "risk_tier": risk.get("risk_tier"),
                "source_ids": source_ids,
                "sources": [
                    source_preview(sources[source_id])
                    for source_id in source_ids
                    if source_id in sources
                ],
                "standard_id": risk.get("standard_id"),
                "standard_title": risk.get("standard_title"),
                "title": risk.get("title"),
            }
        )
    return rows


def build_standards(profile: dict[str, Any], risks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sources = source_by_id(profile)
    risks_by_standard: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for risk in risks:
        risks_by_standard[str(risk.get("standard_id"))].append(risk)

    rows: list[dict[str, Any]] = []
    for standard in as_list(profile.get("standards"), "standards"):
        item = as_dict(standard, "standard")
        standard_id = str(item.get("id"))
        standard_risks = risks_by_standard.get(standard_id, [])
        covered = [risk for risk in standard_risks if risk.get("coverage_status") == "covered"]
        mcp_tools = sorted({str(tool) for risk in standard_risks for tool in risk.get("mcp_tools", [])})
        capability_ids = sorted(
            {
                str(capability_id)
                for risk in standard_risks
                for capability_id in risk.get("required_capability_ids", [])
            }
        )
        rows.append(
            {
                "capability_count": len(capability_ids),
                "coverage_score": round((len(covered) / max(len(standard_risks), 1)) * 100, 2),
                "id": standard_id,
                "mcp_tools": mcp_tools,
                "risk_count": len(standard_risks),
                "risk_ids": [risk.get("id") for risk in standard_risks],
                "source_ids": item.get("source_ids", []),
                "sources": [
                    source_preview(sources[str(source_id)])
                    for source_id in item.get("source_ids", [])
                    if str(source_id) in sources
                ],
                "status": "covered" if len(covered) == len(standard_risks) else "needs_attention",
                "title": item.get("title"),
            }
        )
    return rows


def build_capability_coverage(profile: dict[str, Any], risks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    capabilities = capability_by_id(profile)
    coverage: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for risk in risks:
        for capability_id in risk.get("required_capability_ids", []):
            coverage[str(capability_id)].append(risk)

    rows: list[dict[str, Any]] = []
    for capability_id in sorted(capabilities):
        mapped_risks = coverage.get(capability_id, [])
        rows.append(
            {
                "capability": capability_preview(capabilities[capability_id]),
                "capability_id": capability_id,
                "risk_count": len(mapped_risks),
                "risk_ids": [str(risk.get("id")) for risk in mapped_risks],
                "standard_count": len({str(risk.get("standard_id")) for risk in mapped_risks}),
                "status": "mapped" if mapped_risks else "unmapped",
            }
        )
    return rows


def build_buyer_views(profile: dict[str, Any], standards: list[dict[str, Any]]) -> list[dict[str, Any]]:
    standards_by_id = {str(standard.get("id")): standard for standard in standards}
    rows: list[dict[str, Any]] = []
    for view in as_list(profile.get("buyer_views"), "buyer_views"):
        item = as_dict(view, "buyer_view")
        selected = [
            standards_by_id[str(standard_id)]
            for standard_id in item.get("standard_ids", [])
            if str(standard_id) in standards_by_id
        ]
        rows.append(
            {
                "answer_contract": item.get("answer_contract"),
                "id": item.get("id"),
                "question": item.get("question"),
                "standards": selected,
                "standard_ids": item.get("standard_ids", []),
                "title": item.get("title"),
            }
        )
    return rows


def source_artifacts(profile_path: Path, profile_ref: Path, repo_root: Path, profile: dict[str, Any]) -> dict[str, Any]:
    artifacts: dict[str, dict[str, Any]] = {}
    for capability in profile.get("capabilities", []) or []:
        if not isinstance(capability, dict):
            continue
        for raw_path in capability.get("evidence_paths", []) or []:
            ref = Path(str(raw_path))
            path = resolve(repo_root, ref)
            if path.exists() and path.is_file():
                artifacts[normalize_path(ref)] = {
                    "path": normalize_path(ref),
                    "sha256": sha256_file(path),
                }
    return {
        "capability_evidence": [artifacts[path] for path in sorted(artifacts)],
        "mcp_risk_coverage_profile": {
            "path": normalize_path(profile_ref),
            "sha256": sha256_file(profile_path),
        },
    }


def build_summary(
    profile: dict[str, Any],
    risks: list[dict[str, Any]],
    standards: list[dict[str, Any]],
    coverage: list[dict[str, Any]],
    failures: list[str],
) -> dict[str, Any]:
    risk_status = Counter(str(risk.get("coverage_status")) for risk in risks)
    risk_tiers = Counter(str(risk.get("risk_tier")) for risk in risks)
    standard_status = Counter(str(standard.get("status")) for standard in standards)
    source_classes = Counter(str(source.get("source_class")) for source in profile.get("source_references", []) if isinstance(source, dict))
    mcp_tools = sorted({str(tool) for risk in risks for tool in risk.get("mcp_tools", [])})
    mapped_capabilities = [row for row in coverage if row.get("status") == "mapped"]
    return {
        "capability_count": len(coverage),
        "covered_risk_count": risk_status.get("covered", 0),
        "critical_or_high_risk_count": risk_tiers.get("critical", 0) + risk_tiers.get("high", 0),
        "distinct_mcp_tool_count": len(mcp_tools),
        "failure_count": len(failures),
        "mapped_capability_count": len(mapped_capabilities),
        "risk_count": len(risks),
        "risk_status_counts": dict(sorted(risk_status.items())),
        "risk_tier_counts": dict(sorted(risk_tiers.items())),
        "source_class_counts": dict(sorted(source_classes.items())),
        "source_reference_count": len(profile.get("source_references", []) or []),
        "standard_count": len(standards),
        "standard_status_counts": dict(sorted(standard_status.items())),
        "status": "mcp_and_skill_risk_coverage_ready" if not failures and risk_status.get("needs_attention", 0) == 0 else "needs_attention_before_enterprise_review",
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
    risks = build_risk_coverage(profile)
    standards = build_standards(profile, risks)
    coverage = build_capability_coverage(profile, risks)
    return {
        "buyer_views": build_buyer_views(profile, standards),
        "capability_coverage": coverage,
        "commercialization_path": profile.get("commercialization_path", {}),
        "coverage_contract": profile.get("coverage_contract", {}),
        "enterprise_adoption_packet": {
            "board_level_claim": "SecurityRecipes maps current MCP and agentic-skill risks to generated evidence, MCP tools, and hosted enforcement paths.",
            "default_questions_answered": [
                "Which OWASP MCP risks are covered?",
                "Which OWASP Agentic Skills risks are covered?",
                "Which generated evidence paths prove each risk treatment?",
                "Which MCP tools expose the evidence?",
                "Which coverage areas create hosted enterprise product wedges?"
            ],
            "recommended_first_use": "Attach this pack to MCP server intake, agent-skill approval, AI platform architecture review, procurement security review, and acquisition diligence.",
            "sales_motion": "Lead with open MCP and skill risk coverage, then sell hosted connector drift monitoring, skill scanning, policy enforcement, run receipts, and trust-center exports."
        },
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "mcp_risk_coverage_pack_id": "security-recipes.mcp-and-agentic-skill-risk-coverage.v1",
        "positioning": profile.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "OWASP MCP Top 10 is still in beta and may change as community review completes.",
                "treatment": "Regenerate the pack when OWASP publishes final or revised MCP guidance, and keep source URLs in the profile current."
            },
            {
                "risk": "Generated evidence proves reference controls, not live customer enforcement.",
                "treatment": "Bind the same risk map to customer MCP gateway logs, skill registries, identity-provider records, approval systems, and signed run receipts."
            },
            {
                "risk": "Skill registries and agent hosts can introduce new behavior package formats faster than standards stabilize.",
                "treatment": "Treat capability coverage as a minimum baseline and add platform-specific adapters in the hosted layer."
            }
        ],
        "risk_coverage": risks,
        "risk_coverage_summary": build_summary(profile, risks, standards, coverage, failures),
        "schema_version": PACK_SCHEMA_VERSION,
        "source_artifacts": source_artifacts(profile_path, profile_ref, repo_root, profile),
        "source_references": profile.get("source_references", []),
        "standards": standards,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in MCP risk coverage pack is stale.")
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
    except MCPRiskCoverageError as exc:
        print(f"MCP risk coverage generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if failures:
            print("MCP risk coverage validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_mcp_risk_coverage_pack.py", file=sys.stderr)
            return 1
        if current != rendered:
            print(f"{output_path} is stale; run scripts/generate_mcp_risk_coverage_pack.py", file=sys.stderr)
            return 1
        print(f"Validated MCP risk coverage pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if failures:
        print("Generated MCP risk coverage pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated MCP risk coverage pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
