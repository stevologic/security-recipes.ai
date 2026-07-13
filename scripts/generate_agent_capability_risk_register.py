#!/usr/bin/env python3
"""Generate the SecurityRecipes agent capability risk register.

The readiness scorecard answers whether a workflow can scale. This
register answers the prior enterprise question: how much inherent agentic
capability risk does the workflow create, and which controls reduce the
residual risk before MCP access expands?

The output is deterministic by default so CI can run with --check and
fail when the checked-in risk register drifts from source controls.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


DEFAULT_MODEL = Path("data/assurance/agent-capability-risk-model.json")
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_POLICY = Path("data/policy/mcp-gateway-policy.json")
DEFAULT_CONNECTOR_TRUST_PACK = Path("data/evidence/mcp-connector-trust-pack.json")
DEFAULT_RED_TEAM_DRILL_PACK = Path("data/evidence/agentic-red-team-drill-pack.json")
DEFAULT_READINESS_SCORECARD = Path("data/evidence/agentic-readiness-scorecard.json")
DEFAULT_OUTPUT = Path("data/evidence/agent-capability-risk-register.json")

REQUIRED_FACTORS = {
    "access_permissions",
    "ai_autonomy",
    "impact_radius",
    "system_criticality",
}
VALID_TIERS = {"low", "medium", "high"}


class CapabilityRiskError(RuntimeError):
    """Raised when the capability risk register cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CapabilityRiskError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise CapabilityRiskError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise CapabilityRiskError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise CapabilityRiskError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CapabilityRiskError(f"{label} must be an object")
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


def index_by(rows: list[Any], key: str, label: str) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for row in rows:
        item = as_dict(row, label)
        item_key = str(item.get(key, "")).strip()
        if item_key:
            output[item_key] = item
    return output


def validate_model(model: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(model.get("schema_version") == "1.0", failures, "risk model schema_version must be 1.0")
    require(len(str(model.get("intent", ""))) >= 80, failures, "risk model intent must explain the product goal")

    standards = as_list(model.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 5, failures, "standards_alignment must include at least five references")
    standard_ids: set[str] = set()
    for idx, standard in enumerate(standards):
        label = f"standards_alignment[{idx}]"
        if not isinstance(standard, dict):
            failures.append(f"{label} must be an object")
            continue
        standard_id = str(standard.get("id", "")).strip()
        require(bool(standard_id), failures, f"{label}.id is required")
        require(standard_id not in standard_ids, failures, f"{label}.id duplicates {standard_id}")
        standard_ids.add(standard_id)
        require(str(standard.get("url", "")).startswith("https://"), failures, f"{label}.url must be https")

    factors = as_list(model.get("factor_model"), "factor_model")
    factor_ids: set[str] = set()
    for idx, factor in enumerate(factors):
        label = f"factor_model[{idx}]"
        if not isinstance(factor, dict):
            failures.append(f"{label} must be an object")
            continue
        factor_id = str(factor.get("id", "")).strip()
        factor_ids.add(factor_id)
        require(factor_id in REQUIRED_FACTORS, failures, f"{label}.id is unknown: {factor_id}")
        require(str(factor.get("question", "")).strip(), failures, f"{factor_id}.question is required")
        levels = as_list(factor.get("levels"), f"{factor_id}.levels")
        require(len(levels) >= 3, failures, f"{factor_id}.levels must include at least three levels")
        for level in levels:
            if not isinstance(level, dict):
                failures.append(f"{factor_id}.levels entries must be objects")
                continue
            require(str(level.get("id", "")).strip(), failures, f"{factor_id}.level.id is required")
            require(int(level.get("points", 0)) > 0, failures, f"{factor_id}.{level.get('id')}.points must be positive")
    require(REQUIRED_FACTORS.issubset(factor_ids), failures, "risk model is missing required CSA-style factors")

    tiers = as_list(model.get("risk_tiers"), "risk_tiers")
    tier_ids = {str(tier.get("id")) for tier in tiers if isinstance(tier, dict)}
    require(VALID_TIERS.issubset(tier_ids), failures, "risk_tiers must include low, medium, and high")
    for tier in tiers:
        if not isinstance(tier, dict):
            failures.append("risk_tiers entries must be objects")
            continue
        require(int(tier.get("min_score", -1)) >= 0, failures, f"{tier.get('id')}.min_score is invalid")
        require(int(tier.get("max_score", -1)) >= int(tier.get("min_score", 0)), failures, f"{tier.get('id')}.max_score is invalid")
        require(str(tier.get("decision", "")).strip(), failures, f"{tier.get('id')}.decision is required")

    credit_model = as_dict(model.get("control_credit_model"), "control_credit_model")
    require(int(credit_model.get("max_credit", 0)) > 0, failures, "control_credit_model.max_credit must be positive")
    require(bool(as_list(credit_model.get("credits"), "control_credit_model.credits")), failures, "control credits are required")
    return failures


def source_hash_failures(
    *,
    manifest_path: Path,
    policy_pack: dict[str, Any],
    connector_trust_pack: dict[str, Any],
    red_team_drill_pack: dict[str, Any],
    readiness_scorecard: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    manifest_hash = sha256_file(manifest_path)

    policy_source = policy_pack.get("source_manifest") if isinstance(policy_pack.get("source_manifest"), dict) else {}
    require(policy_source.get("sha256") == manifest_hash, failures, "gateway policy source_manifest.sha256 does not match workflow manifest")

    for label, artifact in [
        ("connector trust pack", connector_trust_pack),
        ("red-team drill pack", red_team_drill_pack),
        ("readiness scorecard", readiness_scorecard),
    ]:
        source = artifact.get("source_artifacts") if isinstance(artifact.get("source_artifacts"), dict) else {}
        source_manifest = source.get("workflow_manifest") if isinstance(source.get("workflow_manifest"), dict) else {}
        require(source_manifest.get("sha256") == manifest_hash, failures, f"{label} workflow_manifest.sha256 does not match workflow manifest")

    require(policy_pack.get("decision_contract", {}).get("default_decision") == "deny", failures, "gateway policy must default to deny")
    require(connector_trust_pack.get("connector_trust_summary", {}).get("failure_count") == 0, failures, "connector trust pack must have zero failures")
    require(red_team_drill_pack.get("red_team_summary", {}).get("failure_count") == 0, failures, "red-team drill pack must have zero failures")
    require(readiness_scorecard.get("readiness_summary", {}).get("failure_count") == 0, failures, "readiness scorecard must have zero failures")
    return failures


def factor_points(model: dict[str, Any]) -> dict[str, dict[str, int]]:
    output: dict[str, dict[str, int]] = {}
    for factor in model.get("factor_model", []) or []:
        if not isinstance(factor, dict):
            continue
        factor_id = str(factor.get("id"))
        output[factor_id] = {
            str(level.get("id")): int(level.get("points", 0))
            for level in factor.get("levels", []) or []
            if isinstance(level, dict)
        }
    return output


def workflow_text(workflow: dict[str, Any]) -> str:
    parts = [
        workflow.get("id"),
        workflow.get("title"),
        workflow.get("public_path"),
        " ".join(str(item) for item in workflow.get("eligible_findings", []) or []),
        " ".join(str(item) for item in workflow.get("kill_signals", []) or []),
    ]
    for context in workflow.get("mcp_context", []) or []:
        if isinstance(context, dict):
            parts.extend([context.get("namespace"), context.get("access"), context.get("purpose")])
    return " ".join(str(part or "") for part in parts).lower()


def factor_result(points: dict[str, dict[str, int]], factor_id: str, title: str, level: str, evidence: str) -> dict[str, Any]:
    return {
        "evidence": evidence,
        "factor_id": factor_id,
        "level": level,
        "points": points.get(factor_id, {}).get(level, 0),
        "title": title,
    }


def classify_system_criticality(workflow: dict[str, Any], points: dict[str, dict[str, int]]) -> dict[str, Any]:
    text = workflow_text(workflow)
    workflow_id = str(workflow.get("id", ""))
    if workflow_id in {"crypto-payment-security", "defi-blockchain-security"} or any(
        token in text for token in ["wallet", "multisig", "signer", "oracle", "bridge", "chain", "governance", "payment"]
    ):
        return factor_result(points, "system_criticality", "System Criticality", "critical", "Financial, chain, signing, or irreversible consequence domain.")
    if workflow_id in {"sensitive-data-remediation", "vulnerable-dependency-remediation", "base-image-remediation", "artifact-cache-quarantine"} or any(
        token in text for token in ["pii", "phi", "pci", "secret", "supply-chain", "cache", "registry", "base image", "container"]
    ):
        return factor_result(points, "system_criticality", "System Criticality", "high", "Privacy, supply-chain, fleet, artifact, or security-control workflow.")
    if workflow.get("status") == "active":
        return factor_result(points, "system_criticality", "System Criticality", "medium", "Active security workflow with bounded application impact.")
    return factor_result(points, "system_criticality", "System Criticality", "low", "Draft or low-consequence workflow.")


def classify_ai_autonomy(workflow: dict[str, Any], points: dict[str, dict[str, int]]) -> dict[str, Any]:
    contexts = [item for item in workflow.get("mcp_context", []) or [] if isinstance(item, dict)]
    access_modes = {str(item.get("access")) for item in contexts}
    agent_count = len(workflow.get("default_agents", []) or [])
    if "approval_required" in access_modes or str(workflow.get("id")) in {"crypto-payment-security", "defi-blockchain-security"}:
        return factor_result(points, "ai_autonomy", "AI Autonomy", "high_autonomy_or_approval_path", "Workflow includes approval-required or high-consequence agent paths.")
    if agent_count >= 5 or workflow.get("maturity_stage") in {"walk", "run"}:
        return factor_result(points, "ai_autonomy", "AI Autonomy", "multi_agentic_remediation", "Workflow supports repeatable delegated remediation across several agent hosts.")
    if workflow.get("status") == "active":
        return factor_result(points, "ai_autonomy", "AI Autonomy", "bounded_agentic_pr", "Agent can create scoped remediation output with mandatory review.")
    return factor_result(points, "ai_autonomy", "AI Autonomy", "supervised_assist", "Agent remains in supervised assist mode.")


def classify_access_permissions(workflow: dict[str, Any], points: dict[str, dict[str, int]]) -> dict[str, Any]:
    access_modes = {
        str(context.get("access"))
        for context in workflow.get("mcp_context", []) or []
        if isinstance(context, dict)
    }
    workflow_id = str(workflow.get("id"))
    if "approval_required" in access_modes or workflow_id in {"crypto-payment-security", "defi-blockchain-security"}:
        return factor_result(points, "access_permissions", "Access Permissions", "approval_or_irreversible_action", "Workflow domain or namespace can involve approval-required or hard-to-reverse operations.")
    if "write_branch" in access_modes and ("write_ticket" in access_modes or any(mode.startswith("write") and mode != "write_branch" for mode in access_modes)):
        return factor_result(points, "access_permissions", "Access Permissions", "branch_and_ticket_write", "Workflow can write scoped branches and operational evidence or tickets.")
    if any(mode.startswith("write") for mode in access_modes):
        return factor_result(points, "access_permissions", "Access Permissions", "scoped_branch_write", "Workflow can write inside scoped remediation boundaries.")
    return factor_result(points, "access_permissions", "Access Permissions", "read_only", "Workflow requests read-only MCP access.")


def classify_impact_radius(workflow: dict[str, Any], points: dict[str, dict[str, int]]) -> dict[str, Any]:
    workflow_id = str(workflow.get("id"))
    scope = workflow.get("scope") if isinstance(workflow.get("scope"), dict) else {}
    max_files = int(scope.get("max_changed_files") or 0)
    max_lines = int(scope.get("max_diff_lines") or 0)
    if workflow_id in {"crypto-payment-security", "defi-blockchain-security"}:
        return factor_result(points, "impact_radius", "Impact Radius", "financial_or_irreversible", "A bad action can affect payments, wallet controls, chain state, or governance outcomes.")
    if workflow_id in {"sensitive-data-remediation", "vulnerable-dependency-remediation", "base-image-remediation", "artifact-cache-quarantine"}:
        return factor_result(points, "impact_radius", "Impact Radius", "fleet_or_tenant", "Workflow can affect tenant data, supply-chain artifacts, container fleets, or shared remediation paths.")
    if max_files and max_files <= 3 and max_lines and max_lines <= 100:
        return factor_result(points, "impact_radius", "Impact Radius", "single_repo", "Workflow is constrained to a narrow file set.")
    return factor_result(points, "impact_radius", "Impact Radius", "service_or_team", "Workflow impact is bounded to a service or team review boundary.")


def workflow_policy_by_id(policy_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return index_by(policy_pack.get("workflow_policies", []), "workflow_id", "policy_pack.workflow_policies")


def readiness_by_workflow(scorecard: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return index_by(scorecard.get("workflow_readiness", []), "workflow_id", "readiness_scorecard.workflow_readiness")


def red_team_by_workflow(red_team_drill_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return index_by(red_team_drill_pack.get("workflow_drills", []), "workflow_id", "red_team_drill_pack.workflow_drills")


def connector_by_namespace(connector_trust_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return index_by(connector_trust_pack.get("connectors", []), "namespace", "connector_trust_pack.connectors")


def build_control_credits(
    *,
    workflow: dict[str, Any],
    policy: dict[str, Any] | None,
    readiness: dict[str, Any] | None,
    red_team: dict[str, Any] | None,
    connectors_by_namespace: dict[str, dict[str, Any]],
    model: dict[str, Any],
) -> tuple[int, list[dict[str, Any]], dict[str, Any]]:
    credits: list[dict[str, Any]] = []
    contexts = [item for item in workflow.get("mcp_context", []) or [] if isinstance(item, dict)]
    namespaces = [str(item.get("namespace")) for item in contexts if item.get("namespace")]
    connectors = [connectors_by_namespace.get(namespace) for namespace in namespaces]
    registered_count = sum(1 for connector in connectors if connector)
    production_count = sum(1 for connector in connectors if connector and connector.get("status") == "production")
    connector_count = len(namespaces)
    production_percent = round((100.0 * production_count / connector_count), 2) if connector_count else 100
    if production_percent == int(production_percent):
        production_percent = int(production_percent)

    readiness_score = int((readiness or {}).get("score") or 0)
    readiness_decision = str((readiness or {}).get("decision") or "")
    if readiness_decision == "scale_ready" and readiness_score >= 90:
        credits.append({"id": "readiness_scale_ready", "points": 16, "evidence": f"readiness={readiness_decision}, score={readiness_score}"})
    elif readiness_decision == "pilot_guarded" and readiness_score >= 78:
        credits.append({"id": "readiness_pilot_guarded", "points": 12, "evidence": f"readiness={readiness_decision}, score={readiness_score}"})

    if policy and policy.get("default_decision") == "deny":
        credits.append({"id": "default_deny_gateway", "points": 6, "evidence": "workflow gateway policy defaults to deny"})

    if connector_count and production_count == connector_count:
        credits.append({"id": "connector_production_coverage", "points": 8, "evidence": "all workflow MCP namespaces are production connectors"})
    elif connector_count and registered_count == connector_count:
        credits.append({"id": "connector_registered_coverage", "points": 4, "evidence": "all workflow MCP namespaces are registered; at least one remains pilot"})

    drill_count = int((red_team or {}).get("drill_count") or len((red_team or {}).get("drills", []) or []))
    if drill_count >= 5:
        credits.append({"id": "red_team_coverage", "points": 8, "evidence": f"{drill_count} generated adversarial drills"})

    runtime = policy.get("runtime_controls") if policy and isinstance(policy.get("runtime_controls"), dict) else {}
    if runtime.get("session_disablement_required") is True and workflow.get("kill_signals"):
        credits.append({"id": "runtime_kill_signal", "points": 4, "evidence": "session disablement and workflow kill signals are declared"})

    max_credit = int(model.get("control_credit_model", {}).get("max_credit") or 42)
    credit_points = min(max_credit, sum(int(item.get("points") or 0) for item in credits))
    connector_summary = {
        "connector_count": connector_count,
        "missing_namespaces": [
            namespace
            for namespace, connector in zip(namespaces, connectors)
            if connector is None
        ],
        "namespaces": namespaces,
        "production_connector_count": production_count,
        "production_connector_percent": production_percent,
        "registered_connector_count": registered_count,
    }
    return credit_points, credits, connector_summary


def risk_tier_for(model: dict[str, Any], residual_score: int) -> dict[str, Any]:
    for tier in model.get("risk_tiers", []) or []:
        if not isinstance(tier, dict):
            continue
        if int(tier.get("min_score", 0)) <= residual_score <= int(tier.get("max_score", 0)):
            return tier
    return {
        "decision": "security_architecture_review",
        "id": "high",
        "meaning": "Requires security architecture review before expansion.",
    }


def required_guardrails(tier_id: str) -> list[str]:
    base = [
        "Default-deny MCP gateway policy",
        "Human review before merge or operational closure",
        "Per-run audit evidence and run receipt",
        "Generated pack drift checks before promotion",
    ]
    if tier_id == "medium":
        return base + [
            "Bounded rollout cohort",
            "Workflow-owner approval for expansion",
            "Red-team drill replay on connector or model changes",
            "Context retrieval and egress boundary checks",
        ]
    if tier_id == "high":
        return base + [
            "Security architecture review before expansion",
            "Typed human approval record for privileged or irreversible actions",
            "Dry-run, simulator, or canary proof before production effect",
            "Per-run identity revocation and session kill switch",
            "Quarterly capability-risk recertification",
        ]
    return base


def next_actions(row: dict[str, Any]) -> list[str]:
    actions: list[str] = []
    tier_id = str(row.get("risk_tier"))
    pilot_namespaces = [
        connector.get("namespace")
        for connector in row.get("connector_statuses", [])
        if isinstance(connector, dict) and connector.get("status") == "pilot"
    ]
    if row.get("source_failure_count"):
        actions.append("Regenerate stale evidence before accepting the capability-risk decision.")
    if tier_id == "high":
        actions.append("Run security architecture review before expanding this workflow.")
    elif tier_id == "medium":
        actions.append("Keep expansion behind a guarded rollout cohort and workflow-owner approval.")
    else:
        actions.append("Continue standard MCP gateway audit and drift checks.")
    if pilot_namespaces:
        actions.append(f"Graduate or explicitly accept pilot MCP namespaces: {', '.join(str(item) for item in pilot_namespaces)}.")
    if any(dimension.get("level") == "approval_or_irreversible_action" for dimension in row.get("capability_dimensions", [])):
        actions.append("Require typed approval receipts for privileged or irreversible operations.")
    return actions


def build_workflow_rows(
    *,
    model: dict[str, Any],
    manifest: dict[str, Any],
    policy_pack: dict[str, Any],
    connector_trust_pack: dict[str, Any],
    red_team_drill_pack: dict[str, Any],
    readiness_scorecard: dict[str, Any],
    source_failures: list[str],
) -> list[dict[str, Any]]:
    points = factor_points(model)
    policies = workflow_policy_by_id(policy_pack)
    readiness_rows = readiness_by_workflow(readiness_scorecard)
    red_team_rows = red_team_by_workflow(red_team_drill_pack)
    connectors = connector_by_namespace(connector_trust_pack)
    rows: list[dict[str, Any]] = []

    for workflow in as_list(manifest.get("workflows"), "manifest.workflows"):
        if not isinstance(workflow, dict):
            continue
        workflow_id = str(workflow.get("id"))
        policy = policies.get(workflow_id)
        readiness = readiness_rows.get(workflow_id)
        red_team = red_team_rows.get(workflow_id)
        dimensions = [
            classify_system_criticality(workflow, points),
            classify_ai_autonomy(workflow, points),
            classify_access_permissions(workflow, points),
            classify_impact_radius(workflow, points),
        ]
        raw_score = sum(int(item.get("points") or 0) for item in dimensions)
        control_credit, credits, connector_summary = build_control_credits(
            workflow=workflow,
            policy=policy,
            readiness=readiness,
            red_team=red_team,
            connectors_by_namespace=connectors,
            model=model,
        )
        residual_score = max(0, raw_score - control_credit)
        tier = risk_tier_for(model, residual_score)
        contexts = [item for item in workflow.get("mcp_context", []) or [] if isinstance(item, dict)]
        connector_statuses = [
            {
                "access": context.get("access"),
                "namespace": context.get("namespace"),
                "status": connectors.get(str(context.get("namespace")), {}).get("status"),
                "trust_tier": (
                    connectors.get(str(context.get("namespace")), {}).get("trust_tier", {}).get("id")
                    if isinstance(connectors.get(str(context.get("namespace")), {}).get("trust_tier"), dict)
                    else connectors.get(str(context.get("namespace")), {}).get("trust_tier")
                ),
            }
            for context in contexts
        ]
        row = {
            "capability_dimensions": dimensions,
            "connector_coverage": connector_summary,
            "connector_statuses": connector_statuses,
            "control_credit": control_credit,
            "control_credits": credits,
            "decision": tier.get("decision"),
            "maturity_stage": workflow.get("maturity_stage"),
            "mcp_namespaces": connector_summary.get("namespaces", []),
            "owner": workflow.get("owner", {}),
            "public_path": workflow.get("public_path"),
            "raw_capability_score": raw_score,
            "readiness_decision": (readiness or {}).get("decision"),
            "readiness_score": (readiness or {}).get("score"),
            "red_team_drill_count": int((red_team or {}).get("drill_count") or len((red_team or {}).get("drills", []) or [])),
            "required_guardrails": required_guardrails(str(tier.get("id"))),
            "residual_risk_score": residual_score,
            "risk_tier": tier.get("id"),
            "risk_tier_meaning": tier.get("meaning"),
            "source_failure_count": len(source_failures),
            "status": workflow.get("status"),
            "title": workflow.get("title"),
            "workflow_id": workflow_id,
        }
        row["next_actions"] = next_actions(row)
        rows.append(row)

    return sorted(rows, key=lambda row: (-int(row.get("residual_risk_score") or 0), str(row.get("workflow_id"))))


def build_register(
    *,
    model: dict[str, Any],
    manifest: dict[str, Any],
    policy_pack: dict[str, Any],
    connector_trust_pack: dict[str, Any],
    red_team_drill_pack: dict[str, Any],
    readiness_scorecard: dict[str, Any],
    model_path: Path,
    manifest_path: Path,
    policy_path: Path,
    connector_trust_pack_path: Path,
    red_team_drill_pack_path: Path,
    readiness_scorecard_path: Path,
    model_ref: Path,
    manifest_ref: Path,
    policy_ref: Path,
    connector_trust_pack_ref: Path,
    red_team_drill_pack_ref: Path,
    readiness_scorecard_ref: Path,
    generated_at: str | None,
    failures: list[str],
    source_failures: list[str],
) -> dict[str, Any]:
    workflow_rows = build_workflow_rows(
        model=model,
        manifest=manifest,
        policy_pack=policy_pack,
        connector_trust_pack=connector_trust_pack,
        red_team_drill_pack=red_team_drill_pack,
        readiness_scorecard=readiness_scorecard,
        source_failures=source_failures,
    )
    tier_counts = Counter(str(row.get("risk_tier")) for row in workflow_rows)
    decision_counts = Counter(str(row.get("decision")) for row in workflow_rows)
    raw_scores = [int(row.get("raw_capability_score") or 0) for row in workflow_rows]
    residual_scores = [int(row.get("residual_risk_score") or 0) for row in workflow_rows]
    credit_scores = [int(row.get("control_credit") or 0) for row in workflow_rows]

    def average(values: list[int]) -> float | int:
        if not values:
            return 0
        score = round(sum(values) / len(values), 2)
        return int(score) if score == int(score) else score

    return {
        "capability_risk_summary": {
            "active_workflow_count": sum(1 for row in workflow_rows if row.get("status") == "active"),
            "average_control_credit": average(credit_scores),
            "average_raw_capability_score": average(raw_scores),
            "average_residual_risk_score": average(residual_scores),
            "decision_counts": dict(sorted(decision_counts.items())),
            "failure_count": len(failures),
            "high_risk_workflow_count": int(tier_counts.get("high", 0)),
            "risk_tier_counts": dict(sorted(tier_counts.items())),
            "source_failure_count": len(source_failures),
            "top_risk_workflows": [
                {
                    "decision": row.get("decision"),
                    "residual_risk_score": row.get("residual_risk_score"),
                    "risk_tier": row.get("risk_tier"),
                    "title": row.get("title"),
                    "workflow_id": row.get("workflow_id"),
                }
                for row in workflow_rows[:5]
            ],
            "workflow_count": len(workflow_rows),
        },
        "control_credit_model": model.get("control_credit_model"),
        "enterprise_adoption_packet": model.get("enterprise_adoption_packet"),
        "factor_model": model.get("factor_model", []),
        "failures": failures,
        "generated_at": generated_at or str(model.get("last_reviewed", "")),
        "intent": model.get("intent"),
        "positioning": model.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "Capability scoring is a reference decision surface, not proof of customer runtime enforcement.",
                "treatment": "Bind risk decisions to customer MCP gateway logs, identity issuance, approval receipts, and runtime kill evidence before production expansion.",
            },
            {
                "risk": "A low residual score can become stale after workflow, connector, model, prompt, or policy drift.",
                "treatment": "Run this generator in CI and require recertification when source hashes or capability dimensions change.",
            },
            {
                "risk": "Critical financial or signing domains need domain-specific simulation beyond generic agent controls.",
                "treatment": "Keep live signer, wallet, payment, and chain actions outside autonomous execution unless dry-run, simulator, dual approval, and kill-switch evidence are present.",
            },
        ],
        "risk_tiers": model.get("risk_tiers", []),
        "schema_version": "1.0",
        "source_artifacts": {
            "agent_capability_risk_model": {
                "path": normalize_path(model_ref),
                "sha256": sha256_file(model_path),
            },
            "agentic_readiness_scorecard": {
                "path": normalize_path(readiness_scorecard_ref),
                "sha256": sha256_file(readiness_scorecard_path),
            },
            "agentic_red_team_drill_pack": {
                "path": normalize_path(red_team_drill_pack_ref),
                "sha256": sha256_file(red_team_drill_pack_path),
            },
            "connector_trust_pack": {
                "path": normalize_path(connector_trust_pack_ref),
                "sha256": sha256_file(connector_trust_pack_path),
            },
            "gateway_policy_pack": {
                "path": normalize_path(policy_ref),
                "sha256": sha256_file(policy_path),
            },
            "workflow_manifest": {
                "path": normalize_path(manifest_ref),
                "sha256": sha256_file(manifest_path),
            },
        },
        "standards_alignment": model.get("standards_alignment", []),
        "workflow_capability_risks": workflow_rows,
    }


def validate_register(register: dict[str, Any], manifest: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(register.get("schema_version") == "1.0", failures, "register schema_version must be 1.0")
    rows = as_list(register.get("workflow_capability_risks"), "workflow_capability_risks")
    summary = as_dict(register.get("capability_risk_summary"), "capability_risk_summary")
    manifest_workflow_count = len(as_list(manifest.get("workflows"), "manifest.workflows"))
    require(summary.get("workflow_count") == len(rows), failures, "capability_risk_summary.workflow_count is stale")
    require(len(rows) == manifest_workflow_count, failures, "risk register workflow count must match manifest")
    for row in rows:
        item = as_dict(row, "workflow_capability_risks row")
        workflow_id = str(item.get("workflow_id"))
        dimensions = as_list(item.get("capability_dimensions"), f"{workflow_id}.capability_dimensions")
        require({str(dimension.get("factor_id")) for dimension in dimensions if isinstance(dimension, dict)} == REQUIRED_FACTORS, failures, f"{workflow_id}: capability dimensions are incomplete")
        raw_score = int(item.get("raw_capability_score", -1))
        control_credit = int(item.get("control_credit", -1))
        residual_score = int(item.get("residual_risk_score", -1))
        require(raw_score == sum(int(dimension.get("points", 0)) for dimension in dimensions if isinstance(dimension, dict)), failures, f"{workflow_id}: raw score is stale")
        require(residual_score == max(0, raw_score - control_credit), failures, f"{workflow_id}: residual score is stale")
        require(item.get("risk_tier") in VALID_TIERS, failures, f"{workflow_id}: unknown risk tier")
        require(bool(item.get("required_guardrails")), failures, f"{workflow_id}: required guardrails are missing")
        require(bool(item.get("next_actions")), failures, f"{workflow_id}: next actions are missing")
    return failures


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--connector-trust-pack", type=Path, default=DEFAULT_CONNECTOR_TRUST_PACK)
    parser.add_argument("--red-team-drill-pack", type=Path, default=DEFAULT_RED_TEAM_DRILL_PACK)
    parser.add_argument("--readiness-scorecard", type=Path, default=DEFAULT_READINESS_SCORECARD)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in capability risk register is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    model_path = resolve(repo_root, args.model)
    manifest_path = resolve(repo_root, args.manifest)
    policy_path = resolve(repo_root, args.policy)
    connector_trust_pack_path = resolve(repo_root, args.connector_trust_pack)
    red_team_drill_pack_path = resolve(repo_root, args.red_team_drill_pack)
    readiness_scorecard_path = resolve(repo_root, args.readiness_scorecard)
    output_path = resolve(repo_root, args.output)

    try:
        model = load_json(model_path)
        manifest = load_json(manifest_path)
        policy_pack = load_json(policy_path)
        connector_trust_pack = load_json(connector_trust_pack_path)
        red_team_drill_pack = load_json(red_team_drill_pack_path)
        readiness_scorecard = load_json(readiness_scorecard_path)
        failures = validate_model(model)
        source_failures = source_hash_failures(
            manifest_path=manifest_path,
            policy_pack=policy_pack,
            connector_trust_pack=connector_trust_pack,
            red_team_drill_pack=red_team_drill_pack,
            readiness_scorecard=readiness_scorecard,
        )
        failures.extend(source_failures)
        register = build_register(
            model=model,
            manifest=manifest,
            policy_pack=policy_pack,
            connector_trust_pack=connector_trust_pack,
            red_team_drill_pack=red_team_drill_pack,
            readiness_scorecard=readiness_scorecard,
            model_path=model_path,
            manifest_path=manifest_path,
            policy_path=policy_path,
            connector_trust_pack_path=connector_trust_pack_path,
            red_team_drill_pack_path=red_team_drill_pack_path,
            readiness_scorecard_path=readiness_scorecard_path,
            model_ref=args.model,
            manifest_ref=args.manifest,
            policy_ref=args.policy,
            connector_trust_pack_ref=args.connector_trust_pack,
            red_team_drill_pack_ref=args.red_team_drill_pack,
            readiness_scorecard_ref=args.readiness_scorecard,
            generated_at=args.generated_at,
            failures=failures,
            source_failures=source_failures,
        )
        failures.extend(validate_register(register, manifest))
        register["failures"] = failures
        register["capability_risk_summary"]["failure_count"] = len(failures)
    except CapabilityRiskError as exc:
        print(f"agent capability risk register generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(register)

    if args.check:
        if failures:
            print("agent capability risk register validation failed:", file=sys.stderr)
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
                f"{output_path} is stale; run scripts/generate_agent_capability_risk_register.py",
                file=sys.stderr,
            )
            return 1
        print(f"Validated agent capability risk register: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")

    if failures:
        print("Generated agent capability risk register with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated agent capability risk register: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
