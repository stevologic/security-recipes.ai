#!/usr/bin/env python3
"""Generate the SecurityRecipes Agentic AIVSS Risk Scoring Pack.

The pack is an AIVSS-aligned severity and remediation-priority layer for
agentic AI, MCP, A2A, skill, identity, context, and runtime risks. It
uses deterministic source-controlled evidence so CI and MCP tools can
reproduce the same decisions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.0"
DEFAULT_PROFILE = Path("data/assurance/agentic-aivss-risk-scoring-profile.json")
DEFAULT_POSTURE_SNAPSHOT = Path("data/evidence/agentic-posture-snapshot.json")
DEFAULT_EXPOSURE_GRAPH = Path("data/evidence/agentic-exposure-graph.json")
DEFAULT_TOOL_RISK_CONTRACT = Path("data/evidence/mcp-tool-risk-contract.json")
DEFAULT_CONTEXT_POISONING_GUARD = Path("data/evidence/context-poisoning-guard-pack.json")
DEFAULT_SKILL_SUPPLY_CHAIN = Path("data/evidence/agent-skill-supply-chain-pack.json")
DEFAULT_APP_INTAKE_PACK = Path("data/evidence/agentic-app-intake-pack.json")
DEFAULT_INCIDENT_RESPONSE_PACK = Path("data/evidence/agentic-incident-response-pack.json")
DEFAULT_STANDARDS_CROSSWALK = Path("data/evidence/agentic-standards-crosswalk.json")
DEFAULT_MCP_RISK_COVERAGE = Path("data/evidence/mcp-risk-coverage-pack.json")
DEFAULT_APPROVAL_RECEIPT_PACK = Path("data/evidence/agentic-approval-receipt-pack.json")
DEFAULT_ACTION_RUNTIME_PACK = Path("data/evidence/agentic-action-runtime-pack.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-aivss-risk-scoring-pack.json")


class AivssPackError(RuntimeError):
    """Raised when the AIVSS scoring pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AivssPackError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise AivssPackError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AivssPackError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AivssPackError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise AivssPackError(f"{label} must be a list")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def normalize_path(path: Path) -> str:
    return path.as_posix()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def validate_profile(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must explain the scoring goal")

    contract = as_dict(profile.get("scoring_contract"), "scoring_contract")
    require(contract.get("default_decision") == "hold_for_agentic_risk_review", failures, "default_decision must fail closed")
    score_bands = as_list(contract.get("score_bands"), "scoring_contract.score_bands")
    require(len(score_bands) >= 4, failures, "score_bands must include critical, high, medium, and low")
    dimensions = as_list(contract.get("dimensions"), "scoring_contract.dimensions")
    total = 0.0
    dimension_ids: set[str] = set()
    for idx, dimension in enumerate(dimensions):
        item = as_dict(dimension, f"dimensions[{idx}]")
        dimension_id = str(item.get("id", "")).strip()
        require(bool(dimension_id), failures, f"dimensions[{idx}].id is required")
        require(dimension_id not in dimension_ids, failures, f"{dimension_id}: duplicate dimension id")
        dimension_ids.add(dimension_id)
        max_score = float(item.get("max_score") or 0)
        require(max_score > 0, failures, f"{dimension_id}: max_score must be positive")
        require(len(str(item.get("question", ""))) >= 40, failures, f"{dimension_id}: question must be specific")
        total += max_score
    require(abs(total - 10.0) < 0.001, failures, "dimension max scores must sum to 10.0")

    references = as_list(profile.get("source_references"), "source_references")
    require(len(references) >= 6, failures, "source_references must include current AIVSS, OWASP, NIST, and MCP sources")
    for idx, source in enumerate(references):
        item = as_dict(source, f"source_references[{idx}]")
        require(str(item.get("url", "")).startswith("https://"), failures, f"{item.get('id')}: url must be https")
        require(len(str(item.get("why_it_matters", ""))) >= 50, failures, f"{item.get('id')}: why_it_matters must be specific")

    scenarios = as_list(profile.get("risk_scenarios"), "risk_scenarios")
    require(len(scenarios) >= 8, failures, "risk_scenarios must cover the core agentic risk set")
    scenario_ids: set[str] = set()
    for idx, scenario in enumerate(scenarios):
        item = as_dict(scenario, f"risk_scenarios[{idx}]")
        scenario_id = str(item.get("id", "")).strip()
        require(bool(scenario_id), failures, f"risk_scenarios[{idx}].id is required")
        require(scenario_id not in scenario_ids, failures, f"{scenario_id}: duplicate scenario id")
        scenario_ids.add(scenario_id)
        vector = as_dict(item.get("aivss_vector"), f"{scenario_id}.aivss_vector")
        for dimension_id in dimension_ids:
            require(dimension_id in vector, failures, f"{scenario_id}: missing vector dimension {dimension_id}")
        require(len(as_list(item.get("recommended_controls"), f"{scenario_id}.recommended_controls")) >= 3, failures, f"{scenario_id}: recommended_controls must be actionable")
        require(str(item.get("hosted_mcp_wedge", "")).strip(), failures, f"{scenario_id}: hosted_mcp_wedge is required")

    buyer_views = as_list(profile.get("buyer_views"), "buyer_views")
    require(len(buyer_views) >= 3, failures, "buyer_views must include security, runtime, and diligence views")
    return failures


def source_failures(payload: dict[str, Any], label: str) -> list[str]:
    failures = payload.get("failures")
    if isinstance(failures, list) and failures:
        return [f"{label}: {failure}" for failure in failures]
    summary_failures: list[str] = []
    for key, value in payload.items():
        if isinstance(value, dict) and key.endswith("_summary"):
            count = int(value.get("failure_count") or 0)
            if count:
                summary_failures.append(f"{label}.{key}: failure_count={count}")
    return summary_failures


def source_artifacts(repo_root: Path, refs: dict[str, Path]) -> dict[str, dict[str, str]]:
    artifacts: dict[str, dict[str, str]] = {}
    for key, ref in sorted(refs.items()):
        path = resolve(repo_root, ref)
        artifacts[key] = {
            "path": normalize_path(ref),
            "sha256": sha256_file(path),
        }
    return artifacts


def get_int(payload: dict[str, Any], *keys: str) -> int:
    current: Any = payload
    for key in keys:
        if not isinstance(current, dict):
            return 0
        current = current.get(key)
    try:
        return int(current or 0)
    except (TypeError, ValueError):
        return 0


def evidence_signal_summary(sources: dict[str, dict[str, Any]]) -> dict[str, Any]:
    posture = sources["agentic_posture_snapshot"]
    posture_risks = posture.get("risk_factor_summary") if isinstance(posture.get("risk_factor_summary"), dict) else {}
    skill_summary = sources["agent_skill_supply_chain_pack"].get("skill_supply_chain_summary", {})
    top_risk_skills = posture_risks.get("top_risk_skills")
    if not isinstance(top_risk_skills, list):
        top_risk_skills = skill_summary.get("top_risk_skills") if isinstance(skill_summary, dict) else []
    if not isinstance(top_risk_skills, list):
        top_risk_skills = []

    exposure_paths = sources["agentic_exposure_graph"].get("exposure_paths", [])
    high_exposure_paths = [
        path
        for path in exposure_paths
        if isinstance(path, dict) and int(path.get("score") or 0) >= 75
    ]
    critical_or_high_skills = [
        skill
        for skill in top_risk_skills
        if isinstance(skill, dict) and str(skill.get("risk_tier", "")).lower() in {"critical", "high"}
    ]

    return {
        "actionable_context_poisoning_findings": int(posture_risks.get("actionable_context_poisoning_findings") or get_int(sources["context_poisoning_guard_pack"], "guard_summary", "actionable_finding_count")),
        "critical_or_high_skill_count": len(critical_or_high_skills),
        "high_exposure_path_count": int(posture_risks.get("high_exposure_path_count") or len(high_exposure_paths)),
        "lethal_combination_workflow_count": int(posture_risks.get("lethal_combination_workflow_count") or get_int(sources["mcp_tool_risk_contract"], "tool_risk_summary", "lethal_combination_workflow_count")),
        "pilot_connector_count": int(posture_risks.get("pilot_connector_count") or 0),
        "posture_decision": posture.get("posture_summary", {}).get("decision"),
        "posture_score": posture.get("posture_summary", {}).get("posture_score"),
        "runtime_action_class_count": get_int(sources["agentic_action_runtime_pack"], "action_runtime_summary", "action_class_count"),
        "top_risk_skill_count": len(top_risk_skills),
        "workflow_count": posture.get("posture_summary", {}).get("workflow_count"),
        "xpia_sensitive_workflows": posture_risks.get("xpia_sensitive_workflows", []),
    }


def band_for_score(score: float, bands: list[dict[str, Any]]) -> dict[str, Any]:
    sorted_bands = sorted(bands, key=lambda band: float(band.get("minimum_score") or 0), reverse=True)
    for band in sorted_bands:
        if score >= float(band.get("minimum_score") or 0):
            return band
    return sorted_bands[-1]


def dimension_caps(profile: dict[str, Any]) -> dict[str, float]:
    return {
        str(dimension.get("id")): float(dimension.get("max_score") or 0)
        for dimension in profile.get("scoring_contract", {}).get("dimensions", [])
        if isinstance(dimension, dict)
    }


def adjusted_vector(
    scenario_id: str,
    vector: dict[str, Any],
    caps: dict[str, float],
    signals: dict[str, Any],
) -> dict[str, float]:
    adjusted = {key: float(vector.get(key) or 0) for key in caps}

    def bump(key: str, amount: float) -> None:
        adjusted[key] = min(caps[key], round(adjusted[key] + amount, 2))

    high_paths = int(signals.get("high_exposure_path_count") or 0)
    lethal = int(signals.get("lethal_combination_workflow_count") or 0)
    poisoning = int(signals.get("actionable_context_poisoning_findings") or 0)
    risky_skills = int(signals.get("critical_or_high_skill_count") or 0)
    pilot_connectors = int(signals.get("pilot_connector_count") or 0)

    if scenario_id == "agent_goal_hijack_context_poisoning" and poisoning:
        bump("context_data_sensitivity", min(0.25, poisoning * 0.05))
        bump("exploit_maturity", 0.1)
    if scenario_id == "mcp_tool_misuse_lethal_session" and lethal:
        bump("authority_impact", min(0.2, lethal * 0.08))
        bump("tool_reachability", 0.1)
    if scenario_id == "identity_privilege_abuse" and high_paths:
        bump("authority_impact", min(0.15, high_paths * 0.01))
        bump("business_materiality", 0.05)
    if scenario_id == "agentic_supply_chain_skill_compromise" and risky_skills:
        bump("exploit_maturity", 0.1)
        bump("tool_reachability", 0.1)
    if scenario_id == "unexpected_code_execution" and risky_skills:
        bump("authority_impact", 0.1)
        bump("exploit_maturity", 0.05)
    if scenario_id == "insecure_inter_agent_handoff" and high_paths:
        bump("context_data_sensitivity", 0.05)
        bump("tool_reachability", 0.05)
    if scenario_id == "cascading_failure_runaway_agent" and high_paths:
        bump("autonomy_exposure", 0.05)
        bump("business_materiality", 0.05)
    if scenario_id == "human_agent_trust_exploitation" and high_paths:
        bump("authority_impact", 0.05)
    if scenario_id == "rogue_agent_shadow_mcp" and pilot_connectors:
        bump("tool_reachability", min(0.2, pilot_connectors * 0.04))
        bump("business_materiality", 0.05)

    return adjusted


def score_rows(profile: dict[str, Any], sources: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    signals = evidence_signal_summary(sources)
    caps = dimension_caps(profile)
    bands = profile.get("scoring_contract", {}).get("score_bands", [])
    rows: list[dict[str, Any]] = []
    for scenario in profile.get("risk_scenarios", []):
        if not isinstance(scenario, dict):
            continue
        scenario_id = str(scenario.get("id"))
        vector = adjusted_vector(scenario_id, as_dict(scenario.get("aivss_vector"), f"{scenario_id}.aivss_vector"), caps, signals)
        score = round(sum(vector.values()), 2)
        band = band_for_score(score, bands)
        evidence_keys = [str(item) for item in scenario.get("evidence_keys", [])]
        rows.append(
            {
                "aivss_score": score,
                "aivss_vector": vector,
                "business_materiality": vector.get("business_materiality"),
                "evidence_keys": evidence_keys,
                "hosted_mcp_wedge": scenario.get("hosted_mcp_wedge"),
                "owner": scenario.get("owner"),
                "owasp_agentic_ids": scenario.get("owasp_agentic_ids", []),
                "owasp_mcp_ids": scenario.get("owasp_mcp_ids", []),
                "recommended_controls": scenario.get("recommended_controls", []),
                "remediation_sla": band.get("remediation_sla"),
                "runtime_default_decision": band.get("runtime_default_decision"),
                "scenario_id": scenario_id,
                "severity": band.get("band"),
                "source_signal_summary": signals,
                "title": scenario.get("title"),
            }
        )
    return sorted(rows, key=lambda row: (-float(row.get("aivss_score") or 0), str(row.get("scenario_id"))))


def build_summary(rows: list[dict[str, Any]], failures: list[str]) -> dict[str, Any]:
    severities = Counter(str(row.get("severity")) for row in rows)
    runtime_decisions = Counter(str(row.get("runtime_default_decision")) for row in rows)
    return {
        "critical_or_high_count": severities.get("critical", 0) + severities.get("high", 0),
        "failure_count": len(failures),
        "highest_score": max((float(row.get("aivss_score") or 0) for row in rows), default=0),
        "risk_score_count": len(rows),
        "runtime_decision_counts": dict(sorted(runtime_decisions.items())),
        "severity_counts": dict(sorted(severities.items())),
        "status": "agentic_aivss_ready" if not failures else "needs_agentic_aivss_review",
    }


def build_remediation_queue(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    queue = []
    for row in rows:
        if row.get("severity") not in {"critical", "high"}:
            continue
        controls = row.get("recommended_controls") if isinstance(row.get("recommended_controls"), list) else []
        queue.append(
            {
                "aivss_score": row.get("aivss_score"),
                "first_control": controls[0] if controls else None,
                "owner": row.get("owner"),
                "remediation_sla": row.get("remediation_sla"),
                "runtime_default_decision": row.get("runtime_default_decision"),
                "scenario_id": row.get("scenario_id"),
                "severity": row.get("severity"),
                "title": row.get("title"),
            }
        )
    return queue


def build_pack(
    *,
    profile: dict[str, Any],
    sources: dict[str, dict[str, Any]],
    refs: dict[str, Path],
    repo_root: Path,
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    rows = score_rows(profile, sources)
    return {
        "buyer_views": profile.get("buyer_views", []),
        "commercialization_path": {
            "open_layer": "Publish a deterministic AIVSS-aligned risk score for the open secure-context and MCP evidence packs.",
            "team_layer": "Let teams fork the profile, tune scenario vectors, and bind the score to their own agent identities, MCP servers, tools, and telemetry.",
            "enterprise_layer": "Sell hosted AIVSS drift scoring with live MCP gateway logs, skill registries, Agent Cards, approval receipts, and customer-private context sources.",
            "acquirer_value": "A frontier lab, AI coding platform, or security vendor gets a quantitative severity layer that can attach to every agent action, MCP tool, and trust-center export."
        },
        "decision_contract": profile.get("scoring_contract", {}),
        "evidence_signal_summary": evidence_signal_summary(sources),
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "hosted_mcp_wedges": [
            {
                "scenario_id": row.get("scenario_id"),
                "severity": row.get("severity"),
                "wedge": row.get("hosted_mcp_wedge"),
            }
            for row in rows
        ],
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "remediation_queue": build_remediation_queue(rows),
        "risk_scores": rows,
        "schema_version": SCHEMA_VERSION,
        "severity_summary": build_summary(rows, failures),
        "source_artifacts": source_artifacts(repo_root, refs),
        "source_references": profile.get("source_references", []),
    }


def validate_pack(pack: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(pack.get("schema_version") == SCHEMA_VERSION, failures, "pack schema_version must be 1.0")
    rows = as_list(pack.get("risk_scores"), "risk_scores")
    require(len(rows) >= 8, failures, "risk_scores must include at least eight scenarios")
    for row in rows:
        item = as_dict(row, "risk_score row")
        score = float(item.get("aivss_score") or -1)
        require(0 <= score <= 10, failures, f"{item.get('scenario_id')}: aivss_score must be between 0 and 10")
        require(item.get("severity") in {"critical", "high", "medium", "low"}, failures, f"{item.get('scenario_id')}: invalid severity")
        require(str(item.get("runtime_default_decision", "")).strip(), failures, f"{item.get('scenario_id')}: runtime_default_decision is required")
    return failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--posture-snapshot", type=Path, default=DEFAULT_POSTURE_SNAPSHOT)
    parser.add_argument("--exposure-graph", type=Path, default=DEFAULT_EXPOSURE_GRAPH)
    parser.add_argument("--tool-risk-contract", type=Path, default=DEFAULT_TOOL_RISK_CONTRACT)
    parser.add_argument("--context-poisoning-guard", type=Path, default=DEFAULT_CONTEXT_POISONING_GUARD)
    parser.add_argument("--skill-supply-chain", type=Path, default=DEFAULT_SKILL_SUPPLY_CHAIN)
    parser.add_argument("--app-intake-pack", type=Path, default=DEFAULT_APP_INTAKE_PACK)
    parser.add_argument("--incident-response-pack", type=Path, default=DEFAULT_INCIDENT_RESPONSE_PACK)
    parser.add_argument("--standards-crosswalk", type=Path, default=DEFAULT_STANDARDS_CROSSWALK)
    parser.add_argument("--mcp-risk-coverage", type=Path, default=DEFAULT_MCP_RISK_COVERAGE)
    parser.add_argument("--approval-receipt-pack", type=Path, default=DEFAULT_APPROVAL_RECEIPT_PACK)
    parser.add_argument("--action-runtime-pack", type=Path, default=DEFAULT_ACTION_RUNTIME_PACK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in AIVSS pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    refs = {
        "agent_skill_supply_chain_pack": args.skill_supply_chain,
        "agentic_action_runtime_pack": args.action_runtime_pack,
        "agentic_aivss_risk_scoring_profile": args.profile,
        "agentic_app_intake_pack": args.app_intake_pack,
        "agentic_exposure_graph": args.exposure_graph,
        "agentic_incident_response_pack": args.incident_response_pack,
        "agentic_posture_snapshot": args.posture_snapshot,
        "agentic_standards_crosswalk": args.standards_crosswalk,
        "agentic_approval_receipt_pack": args.approval_receipt_pack,
        "context_poisoning_guard_pack": args.context_poisoning_guard,
        "mcp_risk_coverage_pack": args.mcp_risk_coverage,
        "mcp_tool_risk_contract": args.tool_risk_contract,
    }
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(resolve(repo_root, args.profile))
        failures = validate_profile(profile)
        sources = {key: load_json(resolve(repo_root, ref)) for key, ref in refs.items() if key != "agentic_aivss_risk_scoring_profile"}
        for key, payload in sources.items():
            require(payload.get("schema_version") == SCHEMA_VERSION, failures, f"{key} schema_version must be 1.0")
            failures.extend(source_failures(payload, key))
        pack = build_pack(
            profile=profile,
            sources=sources,
            refs=refs,
            repo_root=repo_root,
            generated_at=args.generated_at,
            failures=failures,
        )
        failures.extend(validate_pack(pack))
        pack["failures"] = failures
        pack["severity_summary"]["failure_count"] = len(failures)
        pack["severity_summary"]["status"] = "agentic_aivss_ready" if not failures else "needs_agentic_aivss_review"
    except AivssPackError as exc:
        print(f"agentic AIVSS risk scoring pack generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if failures:
            print("agentic AIVSS risk scoring pack validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_agentic_aivss_risk_scoring_pack.py", file=sys.stderr)
            return 1
        if current != rendered:
            print(f"{output_path} is stale; run scripts/generate_agentic_aivss_risk_scoring_pack.py", file=sys.stderr)
            return 1
        print(f"Validated agentic AIVSS risk scoring pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")

    if failures:
        print("Generated agentic AIVSS risk scoring pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated agentic AIVSS risk scoring pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
