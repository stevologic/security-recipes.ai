#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic posture snapshot.

The snapshot is the enterprise posture surface for the secure context
layer. It joins existing generated packs into one inspectable view for
AI platform review, MCP promotion, procurement security, and acquisition
diligence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.0"
DEFAULT_MODEL = Path("data/assurance/agentic-posture-model.json")
DEFAULT_WORKFLOW_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_SYSTEM_BOM = Path("data/evidence/agentic-system-bom.json")
DEFAULT_IDENTITY_LEDGER = Path("data/evidence/agent-identity-delegation-ledger.json")
DEFAULT_CONNECTOR_TRUST_PACK = Path("data/evidence/mcp-connector-trust-pack.json")
DEFAULT_AUTHORIZATION_PACK = Path("data/evidence/mcp-authorization-conformance-pack.json")
DEFAULT_TOOL_RISK_CONTRACT = Path("data/evidence/mcp-tool-risk-contract.json")
DEFAULT_SECURE_CONTEXT_TRUST_PACK = Path("data/evidence/secure-context-trust-pack.json")
DEFAULT_CONTEXT_POISONING_GUARD_PACK = Path("data/evidence/context-poisoning-guard-pack.json")
DEFAULT_CONTEXT_EGRESS_BOUNDARY_PACK = Path("data/evidence/context-egress-boundary-pack.json")
DEFAULT_HANDOFF_BOUNDARY_PACK = Path("data/evidence/agent-handoff-boundary-pack.json")
DEFAULT_A2A_AGENT_CARD_TRUST_PROFILE = Path("data/evidence/a2a-agent-card-trust-profile.json")
DEFAULT_SKILL_SUPPLY_CHAIN_PACK = Path("data/evidence/agent-skill-supply-chain-pack.json")
DEFAULT_TELEMETRY_CONTRACT = Path("data/evidence/agentic-telemetry-contract.json")
DEFAULT_RUN_RECEIPT_PACK = Path("data/evidence/agentic-run-receipt-pack.json")
DEFAULT_EXPOSURE_GRAPH = Path("data/evidence/agentic-exposure-graph.json")
DEFAULT_READINESS_SCORECARD = Path("data/evidence/agentic-readiness-scorecard.json")
DEFAULT_STANDARDS_CROSSWALK = Path("data/evidence/agentic-standards-crosswalk.json")
DEFAULT_ENTERPRISE_TRUST_CENTER_EXPORT = Path("data/evidence/enterprise-trust-center-export.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-posture-snapshot.json")


class PostureSnapshotError(RuntimeError):
    """Raised when the posture snapshot cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PostureSnapshotError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise PostureSnapshotError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise PostureSnapshotError(f"{path} root must be an object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise PostureSnapshotError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PostureSnapshotError(f"{label} must be an object")
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


def index_by(rows: list[Any], key: str) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict) and row.get(key):
            output[str(row[key])] = row
    return output


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


def validate_model(model: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(model.get("schema_version") == SCHEMA_VERSION, failures, "posture model schema_version must be 1.0")
    require(len(str(model.get("intent", ""))) >= 120, failures, "posture model intent must explain the enterprise goal")

    dimensions = as_list(model.get("posture_dimensions"), "posture_dimensions")
    weight_sum = 0
    dimension_ids: set[str] = set()
    for idx, dimension in enumerate(dimensions):
        item = as_dict(dimension, f"posture_dimensions[{idx}]")
        dimension_id = str(item.get("id", "")).strip()
        require(bool(dimension_id), failures, f"posture_dimensions[{idx}].id is required")
        require(dimension_id not in dimension_ids, failures, f"{dimension_id}: duplicate dimension id")
        dimension_ids.add(dimension_id)
        weight = int(item.get("weight") or 0)
        require(weight > 0, failures, f"{dimension_id}: weight must be positive")
        weight_sum += weight
        require(len(str(item.get("question", ""))) >= 50, failures, f"{dimension_id}: question must be specific")
    require(weight_sum == 100, failures, "posture dimension weights must sum to 100")

    contract = as_dict(model.get("decision_contract"), "decision_contract")
    require(contract.get("default_decision") == "hold_for_posture_review", failures, "default_decision must fail closed")
    require(len(as_list(contract.get("required_source_packs"), "required_source_packs")) >= 12, failures, "required_source_packs is incomplete")
    require(len(as_list(model.get("risk_factors"), "risk_factors")) >= 5, failures, "risk_factors must include current agentic posture risks")
    require(len(as_list(model.get("standards_alignment"), "standards_alignment")) >= 6, failures, "standards_alignment must include current references")
    return failures


def score_dimension(dimension_id: str, title: str, weight: int, percent: int, findings: list[str]) -> dict[str, Any]:
    percent = max(0, min(100, percent))
    earned = round(weight * percent / 100, 2)
    if earned == int(earned):
        earned = int(earned)
    return {
        "dimension_id": dimension_id,
        "earned": earned,
        "findings": findings,
        "max": weight,
        "percent": percent,
        "title": title,
    }


def component_counts(system_bom: dict[str, Any]) -> dict[str, int]:
    components = system_bom.get("components") if isinstance(system_bom.get("components"), dict) else {}
    return {
        str(key): len(value)
        for key, value in sorted(components.items())
        if isinstance(value, list)
    }


def max_exposure_by_workflow(exposure_graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for path in exposure_graph.get("exposure_paths", []) or []:
        if not isinstance(path, dict) or not path.get("workflow_id"):
            continue
        workflow_id = str(path.get("workflow_id"))
        current = rows.get(workflow_id)
        if current is None or int(path.get("score") or 0) > int(current.get("score") or 0):
            rows[workflow_id] = path
    return rows


def paths_by_workflow(exposure_graph: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for path in exposure_graph.get("exposure_paths", []) or []:
        if isinstance(path, dict) and path.get("workflow_id"):
            rows[str(path["workflow_id"])].append(path)
    return rows


def source_artifacts(repo_root: Path, refs: dict[str, Path]) -> dict[str, dict[str, str]]:
    artifacts: dict[str, dict[str, str]] = {}
    for key, ref in sorted(refs.items()):
        path = resolve(repo_root, ref)
        artifacts[key] = {
            "path": normalize_path(ref),
            "sha256": sha256_file(path),
        }
    return artifacts


def risk_factor_summary(sources: dict[str, dict[str, Any]]) -> dict[str, Any]:
    exposure = sources["agentic_exposure_graph"]
    tool_risk = sources["mcp_tool_risk_contract"]
    poisoning = sources["context_poisoning_guard_pack"]
    connector_trust = sources["mcp_connector_trust_pack"]
    skill_pack = sources["agent_skill_supply_chain_pack"]
    readiness = sources["agentic_readiness_scorecard"]

    high_exposure = [
        path
        for path in exposure.get("exposure_paths", []) or []
        if isinstance(path, dict) and int(path.get("score") or 0) >= 75
    ]
    xpia_sensitive = sorted(
        {
            str(path.get("workflow_id"))
            for path in high_exposure
            if path.get("path_class_id") in {"tenant_sensitive_context_path", "high_impact_authority_path"}
        }
    )
    actionable_findings = int(poisoning.get("guard_summary", {}).get("actionable_finding_count") or 0)
    pilot_connectors = [
        str(connector.get("namespace"))
        for connector in connector_trust.get("connectors", []) or []
        if isinstance(connector, dict) and connector.get("status") == "pilot"
    ]
    top_risk_skills = skill_pack.get("skill_supply_chain_summary", {}).get("top_risk_skills", [])
    return {
        "actionable_context_poisoning_findings": actionable_findings,
        "high_exposure_path_count": len(high_exposure),
        "lethal_combination_workflow_count": int(tool_risk.get("tool_risk_summary", {}).get("lethal_combination_workflow_count") or 0),
        "pilot_connector_count": len(pilot_connectors),
        "pilot_connectors": sorted(pilot_connectors),
        "pilot_guarded_workflow_count": int(readiness.get("readiness_summary", {}).get("pilot_guarded_workflow_count") or 0),
        "scale_ready_workflow_count": int(readiness.get("readiness_summary", {}).get("scale_ready_workflow_count") or 0),
        "top_risk_skill_count": len(top_risk_skills or []),
        "top_risk_skills": top_risk_skills or [],
        "xpia_sensitive_workflows": xpia_sensitive,
    }


def build_dimension_scores(
    model: dict[str, Any],
    sources: dict[str, dict[str, Any]],
    failures: list[str],
) -> list[dict[str, Any]]:
    dimensions = {str(item.get("id")): item for item in model.get("posture_dimensions", []) if isinstance(item, dict)}
    summary = risk_factor_summary(sources)
    counts = component_counts(sources["agentic_system_bom"])

    rows = []
    rows.append(
        score_dimension(
            "asset_inventory",
            str(dimensions["asset_inventory"]["title"]),
            int(dimensions["asset_inventory"]["weight"]),
            100 if not source_failures(sources["agentic_system_bom"], "agentic-system-bom") and counts.get("workflows", 0) > 0 else 55,
            [
                f"{counts.get('workflows', 0)} workflows",
                f"{counts.get('agent_identities', 0)} agent identities",
                f"{counts.get('mcp_connectors', 0)} MCP connectors",
            ],
        )
    )

    auth_summary = sources["mcp_authorization_conformance_pack"].get("authorization_summary", {})
    identity_summary = sources["agent_identity_delegation_ledger"].get("identity_summary", {})
    identity_percent = 100
    if int(auth_summary.get("failure_count") or 0) or source_failures(sources["agent_identity_delegation_ledger"], "agent-identity-delegation-ledger"):
        identity_percent = 60
    rows.append(
        score_dimension(
            "identity_authority",
            str(dimensions["identity_authority"]["title"]),
            int(dimensions["identity_authority"]["weight"]),
            identity_percent,
            [
                f"{identity_summary.get('identity_count', 0)} non-human identities",
                f"{auth_summary.get('connector_count', 0)} authorization profiles",
                "short-lived identity and token-passthrough controls are represented",
            ],
        )
    )

    lethal = int(sources["mcp_tool_risk_contract"].get("tool_risk_summary", {}).get("lethal_combination_workflow_count") or 0)
    connector_failures = int(sources["mcp_connector_trust_pack"].get("connector_trust_summary", {}).get("failure_count") or 0)
    rows.append(
        score_dimension(
            "mcp_tool_surface",
            str(dimensions["mcp_tool_surface"]["title"]),
            int(dimensions["mcp_tool_surface"]["weight"]),
            max(70, 100 - lethal * 10 - connector_failures * 20),
            [
                f"{sources['mcp_connector_trust_pack'].get('connector_trust_summary', {}).get('connector_count', 0)} registered MCP connectors",
                f"{lethal} lethal session-combination workflows",
                f"{connector_failures} connector-trust failures",
            ],
        )
    )

    actionable = int(summary["actionable_context_poisoning_findings"])
    context_failures = int(sources["secure_context_trust_pack"].get("context_trust_summary", {}).get("failure_count") or 0)
    rows.append(
        score_dimension(
            "context_integrity",
            str(dimensions["context_integrity"]["title"]),
            int(dimensions["context_integrity"]["weight"]),
            max(62, 100 - min(18, actionable // 3) - context_failures * 20),
            [
                f"{sources['secure_context_trust_pack'].get('context_trust_summary', {}).get('context_source_count', 0)} registered context sources",
                f"{actionable} actionable poisoning findings currently routed for review",
                f"{sources['context_egress_boundary_pack'].get('egress_boundary_summary', {}).get('prohibited_data_class_count', 0)} prohibited egress data classes",
            ],
        )
    )

    handoff_failures = int(sources["agent_handoff_boundary_pack"].get("handoff_boundary_summary", {}).get("failure_count") or 0)
    a2a_failures = int(sources["a2a_agent_card_trust_profile"].get("agent_card_trust_summary", {}).get("failure_count") or 0)
    skill_failures = int(sources["agent_skill_supply_chain_pack"].get("skill_supply_chain_summary", {}).get("failure_count") or 0)
    rows.append(
        score_dimension(
            "inter_agent_boundary",
            str(dimensions["inter_agent_boundary"]["title"]),
            int(dimensions["inter_agent_boundary"]["weight"]),
            max(55, 100 - (handoff_failures + a2a_failures + skill_failures) * 20),
            [
                f"{sources['agent_handoff_boundary_pack'].get('handoff_boundary_summary', {}).get('profile_count', 0)} handoff profiles",
                f"{sources['a2a_agent_card_trust_profile'].get('agent_card_trust_summary', {}).get('intake_profile_count', 0)} A2A intake profiles",
                f"{sources['agent_skill_supply_chain_pack'].get('skill_supply_chain_summary', {}).get('skill_count', 0)} skill profiles",
            ],
        )
    )

    telemetry_failures = int(sources["agentic_telemetry_contract"].get("telemetry_summary", {}).get("failure_count") or 0)
    readiness_failures = int(sources["agentic_readiness_scorecard"].get("readiness_summary", {}).get("failure_count") or 0)
    receipt_failures = len(sources["agentic_run_receipt_pack"].get("failures", []) or [])
    rows.append(
        score_dimension(
            "runtime_guardrails",
            str(dimensions["runtime_guardrails"]["title"]),
            int(dimensions["runtime_guardrails"]["weight"]),
            max(58, 100 - (telemetry_failures + readiness_failures + receipt_failures) * 18),
            [
                f"{sources['agentic_telemetry_contract'].get('telemetry_summary', {}).get('signal_class_count', 0)} telemetry signal classes",
                f"{sources['agentic_readiness_scorecard'].get('readiness_summary', {}).get('scale_ready_workflow_count', 0)} scale-ready workflows",
                "run receipts link identity, context, tools, egress, approval, and verifier evidence",
            ],
        )
    )

    high_exposure = int(summary["high_exposure_path_count"])
    exposure_failures = int(sources["agentic_exposure_graph"].get("exposure_graph_summary", {}).get("failure_count") or 0)
    rows.append(
        score_dimension(
            "exposure_management",
            str(dimensions["exposure_management"]["title"]),
            int(dimensions["exposure_management"]["weight"]),
            max(66, 100 - min(24, high_exposure // 2) - exposure_failures * 20),
            [
                f"{sources['agentic_exposure_graph'].get('exposure_graph_summary', {}).get('total_path_count', 0)} exposure paths",
                f"{high_exposure} paths score at or above 75",
                f"{len(summary['xpia_sensitive_workflows'])} workflows combine high exposure with XPIA-sensitive path classes",
            ],
        )
    )

    standards_summary = sources["agentic_standards_crosswalk"].get("crosswalk_summary", {})
    standards_failures = int(standards_summary.get("failure_count") or 0)
    rows.append(
        score_dimension(
            "standards_diligence",
            str(dimensions["standards_diligence"]["title"]),
            int(dimensions["standards_diligence"]["weight"]),
            max(60, 100 - standards_failures * 20),
            [
                f"{standards_summary.get('standard_count', 0)} mapped standards",
                f"{standards_summary.get('control_count', 0)} mapped controls",
                "trust-center export is available for buyer review",
            ],
        )
    )
    return rows


def posture_decision(score: int, failures: list[str], model: dict[str, Any], summary: dict[str, Any]) -> str:
    if failures:
        return "hold_for_posture_review"
    thresholds = model.get("decision_contract", {}).get("score_thresholds", {})
    if (
        score >= int(thresholds.get("enterprise_foundation_ready", 88))
        and int(summary.get("lethal_combination_workflow_count") or 0) == 0
    ):
        return "enterprise_foundation_ready"
    if score >= int(thresholds.get("guarded_enterprise_pilot", 74)):
        return "guarded_enterprise_pilot"
    return "hold_for_posture_review"


def workflow_posture_rows(sources: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    readiness_by_workflow = index_by(sources["agentic_readiness_scorecard"].get("workflow_readiness", []) or [], "workflow_id")
    tool_risk_by_workflow = index_by(sources["mcp_tool_risk_contract"].get("workflow_tool_risk", []) or [], "workflow_id")
    handoff_by_workflow = index_by(sources["agent_handoff_boundary_pack"].get("workflow_handoff_map", []) or [], "workflow_id")
    telemetry_by_workflow = index_by(sources["agentic_telemetry_contract"].get("workflow_telemetry_contracts", []) or [], "workflow_id")
    context_by_workflow = index_by(sources["secure_context_trust_pack"].get("workflow_context_map", []) or [], "workflow_id")
    egress_by_workflow = index_by(sources["context_egress_boundary_pack"].get("workflow_egress_map", []) or [], "workflow_id")
    auth_by_workflow = index_by(sources["mcp_authorization_conformance_pack"].get("workflow_authorization_map", []) or [], "workflow_id")
    max_exposure = max_exposure_by_workflow(sources["agentic_exposure_graph"])
    exposure_rows = paths_by_workflow(sources["agentic_exposure_graph"])

    rows: list[dict[str, Any]] = []
    for workflow_id in sorted(readiness_by_workflow):
        readiness = readiness_by_workflow[workflow_id]
        max_path = max_exposure.get(workflow_id, {})
        max_score = int(max_path.get("score") or 0)
        readiness_score = int(readiness.get("score") or 0)
        telemetry = telemetry_by_workflow.get(workflow_id, {})
        handoff = handoff_by_workflow.get(workflow_id, {})
        tool_risk = tool_risk_by_workflow.get(workflow_id, {})
        context = context_by_workflow.get(workflow_id, {})
        egress = egress_by_workflow.get(workflow_id, {})
        auth = auth_by_workflow.get(workflow_id, {})
        exposure_credit = max(0, 100 - max(0, max_score - 50))
        telemetry_credit = 100 if telemetry.get("decision") == "telemetry_ready" else 65
        context_credit = 100 if context.get("freshness_state") == "declared_current" else 70
        posture_score = round(
            readiness_score * 0.48
            + exposure_credit * 0.22
            + telemetry_credit * 0.12
            + context_credit * 0.10
            + (100 if handoff else 75) * 0.08
        )
        high_paths = [
            path
            for path in exposure_rows.get(workflow_id, [])
            if int(path.get("score") or 0) >= 75
        ]
        next_actions = list(readiness.get("next_actions", []) or [])
        if max_score >= 80:
            next_actions.append("Run posture architecture review for the highest-scoring exposure path before broad rollout.")
        if tool_risk.get("lethal_combination_possible"):
            next_actions.append("Split or block sessions that combine private data, untrusted content, and exfiltration-capable tools.")
        if telemetry.get("decision") != "telemetry_ready":
            next_actions.append("Complete telemetry contract coverage before production expansion.")

        decision = "scale_with_posture_monitoring"
        if max_score >= 80 or tool_risk.get("lethal_combination_possible"):
            decision = "architecture_review"
        elif readiness.get("decision") != "scale_ready" or high_paths:
            decision = "guarded_pilot"

        rows.append(
            {
                "agent_classes": telemetry.get("agent_classes", []) or readiness.get("agent_classes", []),
                "authorization_policy_hash": auth.get("authorization_policy_hash"),
                "context_package_hash": context.get("context_package_hash"),
                "egress_policy_hash": egress.get("egress_policy_hash") or telemetry.get("egress_policy_hash"),
                "highest_exposure_path": {
                    "decision": max_path.get("decision"),
                    "mcp_namespace": max_path.get("mcp_namespace"),
                    "path_class_id": max_path.get("path_class_id"),
                    "path_id": max_path.get("path_id"),
                    "risk_tier": max_path.get("risk_tier"),
                    "score": max_score,
                },
                "maturity_stage": readiness.get("maturity_stage"),
                "mcp_namespaces": readiness.get("mcp_namespaces", []),
                "next_actions": next_actions,
                "owner": readiness.get("owner", {}),
                "posture_decision": decision,
                "posture_score": posture_score,
                "public_path": readiness.get("public_path"),
                "readiness_decision": readiness.get("decision"),
                "readiness_score": readiness_score,
                "runtime_evidence": {
                    "handoff_default_decision": handoff.get("default_decision"),
                    "receipt_id": telemetry.get("receipt_id"),
                    "telemetry_decision": telemetry.get("decision"),
                },
                "session_combination": {
                    "aggregate_risk_factors": tool_risk.get("aggregate_risk_factors", {}),
                    "lethal_combination_possible": bool(tool_risk.get("lethal_combination_possible")),
                    "recommended_session_default": tool_risk.get("recommended_session_default"),
                },
                "status": readiness.get("status"),
                "title": readiness.get("title"),
                "workflow_id": workflow_id,
            }
        )
    return rows


def posture_findings(summary: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    if summary.get("high_exposure_path_count"):
        findings.append(
            {
                "id": "review-high-exposure-paths",
                "priority": "high",
                "title": "Review high-scoring exposure paths",
                "detail": "High exposure paths should be reviewed before broad rollout because they combine agent identity, context, MCP namespace, and workflow maturity into material operating risk.",
                "count": summary.get("high_exposure_path_count"),
            }
        )
    if summary.get("pilot_connector_count"):
        findings.append(
            {
                "id": "graduate-pilot-connectors",
                "priority": "medium",
                "title": "Graduate or constrain pilot MCP connectors",
                "detail": "Pilot MCP connectors should remain behind guarded rollout until promotion evidence and runtime audit behavior are stable.",
                "count": summary.get("pilot_connector_count"),
            }
        )
    if summary.get("actionable_context_poisoning_findings"):
        findings.append(
            {
                "id": "triage-context-poisoning-findings",
                "priority": "medium",
                "title": "Triage actionable context-poisoning findings",
                "detail": "Actionable findings should be dispositioned so retrieved context remains evidence rather than a hidden instruction channel.",
                "count": summary.get("actionable_context_poisoning_findings"),
            }
        )
    if summary.get("top_risk_skill_count"):
        findings.append(
            {
                "id": "review-top-risk-skills",
                "priority": "medium",
                "title": "Review highest-risk agent skills",
                "detail": "Agent skills are part of the execution layer and should stay pinned, scanned, permissioned, and sandboxed before reuse.",
                "count": summary.get("top_risk_skill_count"),
            }
        )
    return findings


def build_snapshot(
    *,
    model: dict[str, Any],
    sources: dict[str, dict[str, Any]],
    refs: dict[str, Path],
    repo_root: Path,
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    dimensions = build_dimension_scores(model, sources, failures)
    total_score = round(sum(float(row.get("earned", 0)) for row in dimensions))
    summary = risk_factor_summary(sources)
    decision = posture_decision(total_score, failures, model, summary)
    workflow_rows = workflow_posture_rows(sources)
    decision_counts = Counter(str(row.get("posture_decision")) for row in workflow_rows)

    return {
        "buyer_views": [
            {
                "id": "ai-platform-quarterly-review",
                "question": "Which agentic workflows can scale, which remain guarded, and which exposure paths need architecture review?",
                "uses": [
                    "posture_summary",
                    "workflow_posture",
                    "risk_factor_summary",
                    "source_artifacts",
                ],
            },
            {
                "id": "procurement-security-review",
                "question": "Which evidence proves SecurityRecipes has inventory, identity, MCP, context, telemetry, and standards controls?",
                "uses": [
                    "posture_dimensions",
                    "standards_alignment",
                    "enterprise_adoption_packet",
                    "source_artifacts",
                ],
            },
            {
                "id": "acquisition-diligence-review",
                "question": "What becomes the enterprise product surface beyond the open knowledge base?",
                "uses": [
                    "commercialization_path",
                    "selected_feature",
                    "workflow_posture",
                    "risk_factor_summary",
                ],
            },
        ],
        "commercialization_path": {
            "acquirer_value": "A frontier lab, AI coding platform, or security vendor gets a posture-management layer that can wrap MCP gateways, agent hosts, and secure-context retrieval with buyer-readable evidence.",
            "enterprise_layer": "Hosted posture snapshots with live MCP gateway logs, IAM issuance events, A2A card diffs, private context registries, red-team replay, and trust-center API exports.",
            "open_layer": "Open generated posture snapshot from SecurityRecipes reference controls and evidence packs.",
            "team_layer": "Customer-private overlays for tenant agents, internal MCP servers, agent skills, source-host permissions, approvals, and telemetry retention.",
        },
        "decision_contract": model.get("decision_contract", {}),
        "enterprise_adoption_packet": model.get("enterprise_adoption_packet", {}),
        "failures": failures,
        "generated_at": generated_at or str(model.get("last_reviewed", "")),
        "intent": model.get("intent"),
        "positioning": model.get("positioning", {}),
        "posture_dimensions": dimensions,
        "posture_findings": posture_findings(summary),
        "posture_summary": {
            "decision": decision,
            "dimension_count": len(dimensions),
            "failure_count": len(failures),
            "posture_score": total_score,
            "risk_factor_count": len(model.get("risk_factors", []) or []),
            "workflow_count": len(workflow_rows),
            "workflow_decision_counts": dict(sorted(decision_counts.items())),
        },
        "residual_risks": [
            {
                "risk": "The snapshot proves source-controlled reference posture, not live customer runtime enforcement.",
                "treatment": "Bind hosted deployments to MCP gateway logs, IAM token issuance, A2A card fetches, agent host traces, approval records, and sealed run receipts.",
            },
            {
                "risk": "Posture can drift when model, tool, connector, skill, Agent Card, prompt, policy, or context sources change.",
                "treatment": "Regenerate the snapshot in CI and alert on posture deltas for every control-plane or source-pack change.",
            },
            {
                "risk": "High posture scores do not remove the need for human review on high-impact actions.",
                "treatment": "Keep approval-required namespaces, high-autonomy XPIA paths, and irreversible operations behind explicit typed approvals and kill signals.",
            },
        ],
        "risk_factor_summary": summary,
        "risk_factors": model.get("risk_factors", []),
        "schema_version": SCHEMA_VERSION,
        "selected_feature": {
            "id": "agentic-posture-snapshot",
            "implementation": [
                "Posture source model under data/assurance.",
                "Deterministic generator under scripts.",
                "Generated posture artifact under data/evidence.",
                "Runtime posture evaluator for MCP tool exposure.",
                "Human-readable docs page and MCP tool exposure.",
            ],
            "reason": "Enterprise buyers are moving from agent pilots to posture management: they need one evidence surface for agent inventory, XPIA exposure, MCP/A2A trust, identity, context, guardrails, and runtime proof.",
        },
        "source_artifacts": source_artifacts(repo_root, refs),
        "standards_alignment": model.get("standards_alignment", []),
        "workflow_posture": workflow_rows,
    }


def validate_snapshot(snapshot: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(snapshot.get("schema_version") == SCHEMA_VERSION, failures, "snapshot schema_version must be 1.0")
    summary = as_dict(snapshot.get("posture_summary"), "posture_summary")
    workflows = as_list(snapshot.get("workflow_posture"), "workflow_posture")
    dimensions = as_list(snapshot.get("posture_dimensions"), "posture_dimensions")
    require(summary.get("workflow_count") == len(workflows), failures, "posture_summary.workflow_count is stale")
    require(summary.get("dimension_count") == len(dimensions), failures, "posture_summary.dimension_count is stale")
    require(0 <= int(summary.get("posture_score") or -1) <= 100, failures, "posture_score must be between 0 and 100")
    for row in workflows:
        item = as_dict(row, "workflow_posture row")
        require(item.get("workflow_id"), failures, "workflow_posture rows require workflow_id")
        require(item.get("posture_decision") in {"scale_with_posture_monitoring", "guarded_pilot", "architecture_review"}, failures, f"{item.get('workflow_id')}: invalid posture_decision")
        require(0 <= int(item.get("posture_score") or -1) <= 100, failures, f"{item.get('workflow_id')}: posture_score must be between 0 and 100")
    return failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--workflow-manifest", type=Path, default=DEFAULT_WORKFLOW_MANIFEST)
    parser.add_argument("--system-bom", type=Path, default=DEFAULT_SYSTEM_BOM)
    parser.add_argument("--identity-ledger", type=Path, default=DEFAULT_IDENTITY_LEDGER)
    parser.add_argument("--connector-trust-pack", type=Path, default=DEFAULT_CONNECTOR_TRUST_PACK)
    parser.add_argument("--authorization-pack", type=Path, default=DEFAULT_AUTHORIZATION_PACK)
    parser.add_argument("--tool-risk-contract", type=Path, default=DEFAULT_TOOL_RISK_CONTRACT)
    parser.add_argument("--secure-context-trust-pack", type=Path, default=DEFAULT_SECURE_CONTEXT_TRUST_PACK)
    parser.add_argument("--context-poisoning-guard-pack", type=Path, default=DEFAULT_CONTEXT_POISONING_GUARD_PACK)
    parser.add_argument("--context-egress-boundary-pack", type=Path, default=DEFAULT_CONTEXT_EGRESS_BOUNDARY_PACK)
    parser.add_argument("--handoff-boundary-pack", type=Path, default=DEFAULT_HANDOFF_BOUNDARY_PACK)
    parser.add_argument("--a2a-agent-card-trust-profile", type=Path, default=DEFAULT_A2A_AGENT_CARD_TRUST_PROFILE)
    parser.add_argument("--skill-supply-chain-pack", type=Path, default=DEFAULT_SKILL_SUPPLY_CHAIN_PACK)
    parser.add_argument("--telemetry-contract", type=Path, default=DEFAULT_TELEMETRY_CONTRACT)
    parser.add_argument("--run-receipt-pack", type=Path, default=DEFAULT_RUN_RECEIPT_PACK)
    parser.add_argument("--exposure-graph", type=Path, default=DEFAULT_EXPOSURE_GRAPH)
    parser.add_argument("--readiness-scorecard", type=Path, default=DEFAULT_READINESS_SCORECARD)
    parser.add_argument("--standards-crosswalk", type=Path, default=DEFAULT_STANDARDS_CROSSWALK)
    parser.add_argument("--enterprise-trust-center-export", type=Path, default=DEFAULT_ENTERPRISE_TRUST_CENTER_EXPORT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in posture snapshot is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    refs = {
        "agent_handoff_boundary_pack": args.handoff_boundary_pack,
        "agent_identity_delegation_ledger": args.identity_ledger,
        "agent_skill_supply_chain_pack": args.skill_supply_chain_pack,
        "agentic_exposure_graph": args.exposure_graph,
        "agentic_posture_model": args.model,
        "agentic_readiness_scorecard": args.readiness_scorecard,
        "agentic_run_receipt_pack": args.run_receipt_pack,
        "agentic_standards_crosswalk": args.standards_crosswalk,
        "agentic_system_bom": args.system_bom,
        "agentic_telemetry_contract": args.telemetry_contract,
        "a2a_agent_card_trust_profile": args.a2a_agent_card_trust_profile,
        "context_egress_boundary_pack": args.context_egress_boundary_pack,
        "context_poisoning_guard_pack": args.context_poisoning_guard_pack,
        "enterprise_trust_center_export": args.enterprise_trust_center_export,
        "mcp_authorization_conformance_pack": args.authorization_pack,
        "mcp_connector_trust_pack": args.connector_trust_pack,
        "mcp_tool_risk_contract": args.tool_risk_contract,
        "secure_context_trust_pack": args.secure_context_trust_pack,
        "workflow_manifest": args.workflow_manifest,
    }
    output_path = resolve(repo_root, args.output)

    try:
        model = load_json(resolve(repo_root, args.model))
        sources = {
            key: load_json(resolve(repo_root, ref))
            for key, ref in refs.items()
            if key != "agentic_posture_model"
        }
        failures = validate_model(model)
        for key, payload in sources.items():
            require(payload.get("schema_version") == SCHEMA_VERSION, failures, f"{key} schema_version must be 1.0")
            failures.extend(source_failures(payload, key))
        snapshot = build_snapshot(
            model=model,
            sources=sources,
            refs=refs,
            repo_root=repo_root,
            generated_at=args.generated_at,
            failures=failures,
        )
        failures.extend(validate_snapshot(snapshot))
        snapshot["failures"] = failures
        snapshot["posture_summary"]["failure_count"] = len(failures)
    except PostureSnapshotError as exc:
        print(f"agentic posture snapshot generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(snapshot)
    if args.check:
        if failures:
            print("agentic posture snapshot validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_agentic_posture_snapshot.py", file=sys.stderr)
            return 1
        if current != rendered:
            print(f"{output_path} is stale; run scripts/generate_agentic_posture_snapshot.py", file=sys.stderr)
            return 1
        print(f"Validated agentic posture snapshot: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")

    if failures:
        print("Generated agentic posture snapshot with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated agentic posture snapshot: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
