#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic readiness scorecard.

The assurance pack explains the control story. The red-team drill pack
tests hostile inputs. The identity ledger and connector trust pack
declare runtime authority. This script joins those artifacts into the
enterprise decision surface an AI platform team needs before expanding a
workflow: scale, pilot, gate, or block.

The output is deterministic by default so CI can run with --check and
fail when the checked-in scorecard drifts from source controls.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


DEFAULT_MODEL = Path("data/assurance/agentic-readiness-model.json")
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_POLICY = Path("data/policy/mcp-gateway-policy.json")
DEFAULT_CONNECTOR_TRUST_PACK = Path("data/evidence/mcp-connector-trust-pack.json")
DEFAULT_IDENTITY_LEDGER = Path("data/evidence/agent-identity-delegation-ledger.json")
DEFAULT_RED_TEAM_DRILL_PACK = Path("data/evidence/agentic-red-team-drill-pack.json")
DEFAULT_ASSURANCE_PACK = Path("data/evidence/agentic-assurance-pack.json")
DEFAULT_REPORT = Path("data/evidence/workflow-control-plane-report.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-readiness-scorecard.json")

MATURITY_POINTS = {
    "run": 12,
    "walk": 10,
    "crawl": 7,
    "draft": 2,
    "retired": 0,
}


class ReadinessScorecardError(RuntimeError):
    """Raised when the readiness scorecard cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReadinessScorecardError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ReadinessScorecardError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ReadinessScorecardError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReadinessScorecardError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReadinessScorecardError(f"{label} must be an object")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def sha256_file(path: Path) -> str:
    # Hash canonical UTF-8 text so evidence hashes are stable across
    # Windows CRLF and GitHub Actions Ubuntu LF checkouts.
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
    require(model.get("schema_version") == "1.0", failures, "readiness model schema_version must be 1.0")
    require(len(str(model.get("intent", ""))) >= 80, failures, "readiness model intent must explain product goal")

    dimensions = as_list(model.get("score_dimensions"), "score_dimensions")
    dimension_ids: set[str] = set()
    weight_sum = 0
    for idx, dimension in enumerate(dimensions):
        label = f"score_dimensions[{idx}]"
        if not isinstance(dimension, dict):
            failures.append(f"{label} must be an object")
            continue
        dimension_id = str(dimension.get("id", "")).strip()
        require(bool(dimension_id), failures, f"{label}.id is required")
        require(dimension_id not in dimension_ids, failures, f"{label}.id duplicates {dimension_id}")
        dimension_ids.add(dimension_id)
        weight = int(dimension.get("weight", 0))
        require(weight > 0, failures, f"{label}.weight must be positive")
        weight_sum += weight
    require(weight_sum == 100, failures, "score dimension weights must sum to 100")

    required_dimensions = {
        "adversarial_eval",
        "connector_trust",
        "control_plane",
        "evidence_chain",
        "gateway_policy",
        "identity_delegation",
        "maturity_signal",
    }
    require(required_dimensions.issubset(dimension_ids), failures, "readiness model is missing required dimensions")

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

    contract = as_dict(model.get("decision_contract"), "decision_contract")
    for key in ["scale_ready", "pilot_guarded", "manual_gate", "blocked"]:
        require(key in contract, failures, f"decision_contract.{key} is required")

    minimum = as_dict(model.get("minimum_contract"), "minimum_contract")
    require(bool(minimum.get("critical_denied_actions")), failures, "minimum_contract.critical_denied_actions is required")
    require(bool(minimum.get("required_gate_phases")), failures, "minimum_contract.required_gate_phases is required")
    return failures


def source_hash_failures(
    *,
    manifest_path: Path,
    policy_pack: dict[str, Any],
    connector_trust_pack: dict[str, Any],
    identity_ledger: dict[str, Any],
    red_team_drill_pack: dict[str, Any],
    assurance_pack: dict[str, Any],
    report: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    manifest_hash = sha256_file(manifest_path)

    policy_source = policy_pack.get("source_manifest") if isinstance(policy_pack.get("source_manifest"), dict) else {}
    require(policy_source.get("sha256") == manifest_hash, failures, "gateway policy source_manifest.sha256 does not match workflow manifest")

    for label, artifact in [
        ("connector trust pack", connector_trust_pack),
        ("identity ledger", identity_ledger),
        ("red-team drill pack", red_team_drill_pack),
        ("assurance pack", assurance_pack),
    ]:
        source = artifact.get("source_artifacts") if isinstance(artifact.get("source_artifacts"), dict) else {}
        source_manifest = source.get("workflow_manifest") if isinstance(source.get("workflow_manifest"), dict) else {}
        require(source_manifest.get("sha256") == manifest_hash, failures, f"{label} workflow_manifest.sha256 does not match workflow manifest")

    require(report.get("failure_count") == 0, failures, "workflow control-plane report must have zero failures")
    require(policy_pack.get("decision_contract", {}).get("default_decision") == "deny", failures, "gateway policy must default to deny")
    require(connector_trust_pack.get("connector_trust_summary", {}).get("failure_count") == 0, failures, "connector trust pack must have zero failures")
    require(red_team_drill_pack.get("red_team_summary", {}).get("failure_count") == 0, failures, "red-team drill pack must have zero failures")
    require(assurance_pack.get("assurance_summary", {}).get("failure_count") == 0, failures, "assurance pack must have zero failures")
    require(not identity_ledger.get("failures"), failures, "identity ledger must have zero failures")
    return failures


def check(checks: list[dict[str, Any]], check_id: str, title: str, earned: int, points: int, evidence: str) -> None:
    checks.append(
        {
            "earned": earned,
            "evidence": evidence,
            "id": check_id,
            "passed": earned == points,
            "points": points,
            "title": title,
        }
    )


def score_control_plane(workflow: dict[str, Any], required: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    owner = workflow.get("owner") if isinstance(workflow.get("owner"), dict) else {}
    reviewer_pools = owner.get("reviewer_pools") if isinstance(owner.get("reviewer_pools"), list) else []
    gates = workflow.get("gates") if isinstance(workflow.get("gates"), dict) else {}
    required_phases = {str(item) for item in required.get("required_gate_phases", [])}
    evidence = workflow.get("evidence") if isinstance(workflow.get("evidence"), list) else []
    kpis = workflow.get("kpis") if isinstance(workflow.get("kpis"), list) else []
    kill_signals = workflow.get("kill_signals") if isinstance(workflow.get("kill_signals"), list) else []

    check(checks, "owner_and_reviewers", "Owner and reviewer pools declared", 4 if owner.get("accountable_team") and reviewer_pools else 0, 4, "workflow.owner")
    check(checks, "active_status", "Workflow is active", 2 if workflow.get("status") == "active" else 0, 2, "workflow.status")
    check(checks, "required_gate_phases", "All required gate phases exist", 5 if required_phases.issubset(set(gates)) else 0, 5, "workflow.gates")
    check(checks, "evidence_contract", "Minimum evidence records declared", 3 if len(evidence) >= int(required.get("minimum_evidence_records", 3)) else 0, 3, "workflow.evidence")
    check(checks, "kpi_contract", "Minimum KPI records declared", 2 if len(kpis) >= int(required.get("minimum_kpis", 3)) else 0, 2, "workflow.kpis")
    check(checks, "kill_signals", "Kill signals declared", 2 if kill_signals else 0, 2, "workflow.kill_signals")
    return sum(int(item["earned"]) for item in checks), checks


def score_gateway_policy(workflow: dict[str, Any], policy: dict[str, Any] | None) -> tuple[int, list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    if not policy:
        check(checks, "policy_exists", "Workflow policy exists", 0, 3, "gateway_policy.workflow_policies")
        check(checks, "default_deny", "Default decision is deny", 0, 3, "gateway_policy.default_decision")
        check(checks, "denied_by_default", "Tool access denied by default", 0, 2, "gateway_policy.tool_access")
        check(checks, "namespace_alignment", "Policy namespaces match workflow namespaces", 0, 3, "gateway_policy.allowed_mcp_scopes")
        check(checks, "branch_scope", "Branch and ticket writes are scoped", 0, 2, "gateway_policy.dispatch")
        check(checks, "session_disablement", "Session disablement required", 0, 2, "gateway_policy.runtime_controls")
        return 0, checks

    tool_access = policy.get("tool_access") if isinstance(policy.get("tool_access"), dict) else {}
    scopes = tool_access.get("allowed_mcp_scopes") if isinstance(tool_access.get("allowed_mcp_scopes"), list) else []
    workflow_namespaces = {str(item.get("namespace")) for item in workflow.get("mcp_context", []) if isinstance(item, dict)}
    policy_namespaces = {str(item.get("namespace")) for item in scopes if isinstance(item, dict)}
    has_write = any(str(item.get("access", "")).startswith("write") for item in scopes if isinstance(item, dict))
    dispatch = policy.get("dispatch") if isinstance(policy.get("dispatch"), dict) else {}
    runtime = policy.get("runtime_controls") if isinstance(policy.get("runtime_controls"), dict) else {}

    check(checks, "policy_exists", "Workflow policy exists", 3, 3, "gateway_policy.workflow_policies")
    check(checks, "default_deny", "Default decision is deny", 3 if policy.get("default_decision") == "deny" else 0, 3, "gateway_policy.default_decision")
    check(checks, "denied_by_default", "Tool access denied by default", 2 if tool_access.get("denied_by_default") is True else 0, 2, "gateway_policy.tool_access.denied_by_default")
    check(checks, "namespace_alignment", "Policy namespaces match workflow namespaces", 3 if workflow_namespaces == policy_namespaces else 0, 3, "gateway_policy.allowed_mcp_scopes")
    branch_scoped = (not has_write) or bool(dispatch.get("required_branch_prefix") or dispatch.get("required_pr_label"))
    check(checks, "branch_scope", "Branch and ticket writes are scoped", 2 if branch_scoped else 0, 2, "gateway_policy.dispatch")
    check(checks, "session_disablement", "Session disablement required", 2 if runtime.get("session_disablement_required") is True else 0, 2, "gateway_policy.runtime_controls")
    return sum(int(item["earned"]) for item in checks), checks


def score_identity_delegation(
    workflow: dict[str, Any],
    policy: dict[str, Any] | None,
    identities: list[dict[str, Any]],
    required: dict[str, Any],
) -> tuple[int, list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    default_agents = {str(agent) for agent in workflow.get("default_agents", [])}
    identity_agents = {str(identity.get("agent_class")) for identity in identities}
    critical_denies = set(str(item) for item in required.get("critical_denied_actions", []))
    all_denies_present = all(
        critical_denies.issubset(
            {
                str(action)
                for action in (
                    identity.get("explicit_denies", {}).get("actions", [])
                    if isinstance(identity.get("explicit_denies"), dict)
                    else []
                )
            }
        )
        for identity in identities
    )
    all_runtime = all(
        identity.get("runtime_contract", {}).get("session_disablement_required") is True
        for identity in identities
        if isinstance(identity.get("runtime_contract"), dict)
    )
    no_static = all(
        "no shared static tokens" in str(identity.get("identity_controls", {}).get("credential_storage", "")).lower()
        for identity in identities
        if isinstance(identity.get("identity_controls"), dict)
    )
    approval_required = []
    if policy and isinstance(policy.get("tool_access"), dict):
        approval_required = [
            str(item)
            for item in policy["tool_access"].get("requires_human_approval_for", [])
        ]
    approval_reflected = all(
        set(approval_required).issubset(
            set(identity.get("delegated_authority", {}).get("approval_required_namespaces", []))
        )
        for identity in identities
        if isinstance(identity.get("delegated_authority"), dict)
    )
    kill_text = " ".join(str(item).lower() for item in workflow.get("kill_signals", []))
    needs_high_control = bool(approval_required) or any(token in kill_text for token in ["signer", "wallet", "multisig"])
    high_control_aligned = (not needs_high_control) or all(identity.get("risk_tier") == "high-control" for identity in identities)

    check(checks, "identity_coverage", "Identity exists for every default agent", 5 if default_agents and default_agents == identity_agents else 0, 5, "identity_ledger.agent_identities")
    check(checks, "critical_denies", "Critical denied actions present", 3 if identities and all_denies_present else 0, 3, "identity_ledger.explicit_denies")
    check(checks, "runtime_revocation", "Runtime revocation required", 2 if identities and all_runtime else 0, 2, "identity_ledger.runtime_contract")
    check(checks, "no_static_credentials", "No shared static credential model", 2 if identities and no_static else 0, 2, "identity_ledger.identity_controls")
    check(checks, "approval_reflected", "Approval-required namespaces reflected", 2 if approval_reflected else 0, 2, "identity_ledger.delegated_authority")
    check(checks, "high_control_alignment", "High-control workflows use high-control identities", 1 if high_control_aligned else 0, 1, "identity_ledger.risk_tier")
    return sum(int(item["earned"]) for item in checks), checks


def score_connector_trust(workflow: dict[str, Any], connectors_by_namespace: dict[str, dict[str, Any]]) -> tuple[int, list[dict[str, Any]], list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    namespaces = [str(item.get("namespace")) for item in workflow.get("mcp_context", []) if isinstance(item, dict)]
    connectors = [connectors_by_namespace.get(namespace) for namespace in namespaces]
    present = [connector for connector in connectors if connector]
    statuses = [str(connector.get("status")) for connector in present if isinstance(connector, dict)]
    production_percent = round(100.0 * statuses.count("production") / len(namespaces), 2) if namespaces else 100.0
    if production_percent == int(production_percent):
        production_percent = int(production_percent)
    all_production = bool(namespaces) and len(present) == len(namespaces) and all(status == "production" for status in statuses)
    any_pilot = any(status == "pilot" for status in statuses)
    trust_tiers = [
        connector.get("trust_tier", {}).get("id")
        for connector in present
        if isinstance(connector, dict) and isinstance(connector.get("trust_tier"), dict)
    ]
    recognized_tiers = all(str(tier).startswith("tier_") for tier in trust_tiers)
    scoped_write_ok = True
    for context in workflow.get("mcp_context", []):
        if not isinstance(context, dict):
            continue
        access = str(context.get("access"))
        connector = connectors_by_namespace.get(str(context.get("namespace")))
        tier_id = ""
        if connector and isinstance(connector.get("trust_tier"), dict):
            tier_id = str(connector["trust_tier"].get("id", ""))
        if access == "write_branch" and tier_id != "tier_2_scoped_write":
            scoped_write_ok = False
        if access == "approval_required" and tier_id != "tier_3_approval_required":
            scoped_write_ok = False

    production_points = 4 if all_production else 2 if any_pilot and len(present) == len(namespaces) else 0
    check(checks, "connector_registration", "All namespaces are registered", 5 if len(present) == len(namespaces) else 0, 5, "connector_trust_pack.connectors")
    check(checks, "production_status", "Connectors are production ready", production_points, 4, "connector_trust_pack.status")
    check(checks, "trust_tiers", "Trust tiers are assigned", 3 if recognized_tiers else 0, 3, "connector_trust_pack.trust_tier")
    check(checks, "write_tier_alignment", "Write and approval access match trust tier", 2 if scoped_write_ok else 0, 2, "connector_trust_pack.access_modes")

    connector_rows = [
        {
            "namespace": namespace,
            "production_ready": bool(connectors_by_namespace.get(namespace, {}).get("status") == "production"),
            "status": connectors_by_namespace.get(namespace, {}).get("status"),
            "trust_tier": (
                connectors_by_namespace.get(namespace, {}).get("trust_tier", {}).get("id")
                if isinstance(connectors_by_namespace.get(namespace, {}).get("trust_tier"), dict)
                else connectors_by_namespace.get(namespace, {}).get("trust_tier")
            ),
        }
        for namespace in namespaces
    ]
    return sum(int(item["earned"]) for item in checks), checks, connector_rows


def score_adversarial_eval(workflow_drill: dict[str, Any] | None, required: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    drills = workflow_drill.get("drills", []) if isinstance(workflow_drill, dict) and isinstance(workflow_drill.get("drills"), list) else []
    drill_count = len(drills)
    minimum = int(required.get("minimum_red_team_drills", 5))
    severities = {str(drill.get("severity")) for drill in drills if isinstance(drill, dict)}
    attack_families = {str(drill.get("attack_family")) for drill in drills if isinstance(drill, dict)}
    matched_namespace_count = sum(
        1
        for drill in drills
        if isinstance(drill, dict) and drill.get("matched_namespaces")
    )

    check(checks, "drill_row_exists", "Workflow has red-team row", 4 if workflow_drill else 0, 4, "red_team_drill_pack.workflow_drills")
    check(checks, "minimum_drills", "Minimum drill count met", 4 if drill_count >= minimum else 0, 4, "red_team_drill_pack.drills")
    check(checks, "high_severity_coverage", "High or critical scenarios present", 2 if severities.intersection({"high", "critical"}) else 0, 2, "red_team_drill_pack.severity")
    check(checks, "attack_family_coverage", "Multiple attack families covered", 2 if len(attack_families) >= 5 else 0, 2, "red_team_drill_pack.attack_family")
    check(checks, "namespace_exercise", "Drills exercise MCP namespaces", 2 if matched_namespace_count >= minimum else 0, 2, "red_team_drill_pack.matched_namespaces")
    return sum(int(item["earned"]) for item in checks), checks


def score_evidence_chain(
    workflow: dict[str, Any],
    assurance_workflow: dict[str, Any] | None,
    assurance_pack: dict[str, Any],
    source_failures: list[str],
) -> tuple[int, list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    evidence = workflow.get("evidence") if isinstance(workflow.get("evidence"), list) else []
    external_count = int(assurance_pack.get("assurance_summary", {}).get("external_evidence_artifact_count", 0))
    source_artifacts = assurance_pack.get("source_artifacts") if isinstance(assurance_pack.get("source_artifacts"), dict) else {}

    check(checks, "assurance_row_exists", "Workflow appears in assurance pack", 3 if assurance_workflow else 0, 3, "assurance_pack.workflow_assurance")
    check(checks, "workflow_evidence", "Workflow evidence records are named", 3 if len(evidence) >= 3 else 0, 3, "workflow.evidence")
    check(checks, "source_hash_alignment", "Source artifact hashes align", 4 if not source_failures and source_artifacts else 0, 4, "source_artifacts")
    check(checks, "external_evidence_named", "External runtime evidence is named", 2 if external_count >= 3 else 0, 2, "assurance_pack.external_evidence_artifact_count")
    return sum(int(item["earned"]) for item in checks), checks


def score_maturity_signal(workflow: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    stage = str(workflow.get("maturity_stage", ""))
    earned = MATURITY_POINTS.get(stage, 0)
    check(checks, "maturity_stage", "Maturity stage supports expansion", earned, 12, "workflow.maturity_stage")
    return earned, checks


def dimension_result(dimension_id: str, title: str, weight: int, earned: int, checks: list[dict[str, Any]]) -> dict[str, Any]:
    percent: int | float = round((100.0 * earned / weight) if weight else 0.0, 2)
    if float(percent).is_integer():
        percent = int(percent)
    return {
        "checks": checks,
        "dimension_id": dimension_id,
        "earned": earned,
        "max": weight,
        "percent": percent,
        "title": title,
    }


def identity_by_workflow(identity_ledger: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    output: dict[str, list[dict[str, Any]]] = {}
    for identity in identity_ledger.get("agent_identities", []):
        if not isinstance(identity, dict):
            continue
        workflow_id = str(identity.get("workflow_id", "")).strip()
        if workflow_id:
            output.setdefault(workflow_id, []).append(identity)
    return output


def build_blockers(
    *,
    workflow: dict[str, Any],
    policy: dict[str, Any] | None,
    identities: list[dict[str, Any]],
    connector_rows: list[dict[str, Any]],
    workflow_drill: dict[str, Any] | None,
    required: dict[str, Any],
    source_failures: list[str],
) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    if source_failures:
        blockers.append({"id": "source_hash_drift", "title": "Source hash drift", "detail": "; ".join(source_failures)})
    if not policy or policy.get("default_decision") != "deny":
        blockers.append({"id": "gateway_not_default_deny", "title": "Gateway not default deny", "detail": "Gateway policy must default to deny."})

    default_agents = {str(agent) for agent in workflow.get("default_agents", [])}
    identity_agents = {str(identity.get("agent_class")) for identity in identities}
    missing_agents = sorted(default_agents - identity_agents)
    if missing_agents:
        blockers.append({"id": "missing_identity_contract", "title": "Missing agent identity contract", "detail": f"Missing identities for: {', '.join(missing_agents)}"})

    missing_namespaces = sorted(str(row.get("namespace")) for row in connector_rows if not row.get("status"))
    if missing_namespaces:
        blockers.append({"id": "missing_connector_registration", "title": "Missing connector registration", "detail": f"Missing namespaces: {', '.join(missing_namespaces)}"})

    drill_count = int(workflow_drill.get("drill_count", 0)) if isinstance(workflow_drill, dict) else 0
    minimum_drills = int(required.get("minimum_red_team_drills", 5))
    if drill_count < minimum_drills:
        blockers.append({"id": "missing_red_team_coverage", "title": "Missing red-team coverage", "detail": f"{drill_count} drills present; {minimum_drills} required."})

    runtime = policy.get("runtime_controls") if policy and isinstance(policy.get("runtime_controls"), dict) else {}
    if not workflow.get("kill_signals") or runtime.get("session_disablement_required") is not True:
        blockers.append({"id": "missing_runtime_kill_signal", "title": "Missing runtime kill signal", "detail": "Workflow kill signals and gateway session disablement are both required."})

    return blockers


def decide(
    *,
    score: int,
    workflow: dict[str, Any],
    connector_rows: list[dict[str, Any]],
    blockers: list[dict[str, Any]],
    decision_contract: dict[str, Any],
) -> str:
    if blockers:
        return "blocked"

    stage = str(workflow.get("maturity_stage", ""))
    scale = decision_contract.get("scale_ready", {})
    all_connectors_production = all(row.get("production_ready") for row in connector_rows)
    if (
        score >= int(scale.get("minimum_score", 90))
        and stage in set(scale.get("allowed_maturity_stages", []))
        and (not scale.get("requires_all_connectors_production", True) or all_connectors_production)
    ):
        return "scale_ready"

    pilot = decision_contract.get("pilot_guarded", {})
    if score >= int(pilot.get("minimum_score", 78)):
        return "pilot_guarded"

    return "manual_gate"


def next_actions(decision: str, workflow: dict[str, Any], connector_rows: list[dict[str, Any]], blockers: list[dict[str, Any]]) -> list[str]:
    if blockers:
        return [f"Resolve blocker: {blocker['title']}" for blocker in blockers]

    actions: list[str] = []
    stage = str(workflow.get("maturity_stage", ""))
    pilot_connectors = [str(row.get("namespace")) for row in connector_rows if row.get("status") == "pilot"]
    if decision == "scale_ready":
        actions.append("Expand through the normal change-management cohort with MCP gateway audit enabled.")
        actions.append("Track reviewer burden, regression rate, and red-team replay results during expansion.")
        return actions

    if stage == "crawl":
        actions.append("Keep the workflow in a bounded pilot until pilot exit metrics justify walk-stage promotion.")
    if pilot_connectors:
        actions.append(f"Graduate pilot MCP connectors before broad rollout: {', '.join(pilot_connectors)}.")
    if decision == "manual_gate":
        actions.append("Require program-owner approval before any agent run.")
    if not actions:
        actions.append("Keep scoped approvals in place and review the lowest scoring dimension before expansion.")
    return actions


def build_scorecard(
    *,
    model: dict[str, Any],
    manifest: dict[str, Any],
    policy_pack: dict[str, Any],
    connector_trust_pack: dict[str, Any],
    identity_ledger: dict[str, Any],
    red_team_drill_pack: dict[str, Any],
    assurance_pack: dict[str, Any],
    report: dict[str, Any],
    source_failures: list[str],
    model_path: Path,
    manifest_path: Path,
    policy_path: Path,
    connector_trust_pack_path: Path,
    identity_ledger_path: Path,
    red_team_drill_pack_path: Path,
    assurance_pack_path: Path,
    report_path: Path,
    model_ref: Path,
    manifest_ref: Path,
    policy_ref: Path,
    connector_trust_pack_ref: Path,
    identity_ledger_ref: Path,
    red_team_drill_pack_ref: Path,
    assurance_pack_ref: Path,
    report_ref: Path,
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    required = as_dict(model.get("minimum_contract"), "minimum_contract")
    decision_contract = as_dict(model.get("decision_contract"), "decision_contract")
    dimensions = {str(item.get("id")): item for item in model.get("score_dimensions", []) if isinstance(item, dict)}

    policies = index_by(policy_pack.get("workflow_policies", []), "workflow_id", "policy_pack.workflow_policy")
    connectors = index_by(connector_trust_pack.get("connectors", []), "namespace", "connector_trust_pack.connector")
    identities = identity_by_workflow(identity_ledger)
    workflow_drills = index_by(red_team_drill_pack.get("workflow_drills", []), "workflow_id", "red_team_drill_pack.workflow_drills")
    assurance_workflows = index_by(assurance_pack.get("workflow_assurance", []), "workflow_id", "assurance_pack.workflow_assurance")

    workflow_rows: list[dict[str, Any]] = []
    for workflow in as_list(manifest.get("workflows"), "manifest.workflows"):
        if not isinstance(workflow, dict):
            continue
        workflow_id = str(workflow.get("id"))
        policy = policies.get(workflow_id)
        workflow_identities = identities.get(workflow_id, [])
        workflow_drill = workflow_drills.get(workflow_id)
        assurance_workflow = assurance_workflows.get(workflow_id)

        control_score, control_checks = score_control_plane(workflow, required)
        gateway_score, gateway_checks = score_gateway_policy(workflow, policy)
        identity_score, identity_checks = score_identity_delegation(workflow, policy, workflow_identities, required)
        connector_score, connector_checks, connector_rows = score_connector_trust(workflow, connectors)
        red_team_score, red_team_checks = score_adversarial_eval(workflow_drill, required)
        evidence_score, evidence_checks = score_evidence_chain(workflow, assurance_workflow, assurance_pack, source_failures)
        maturity_score, maturity_checks = score_maturity_signal(workflow)

        dimension_scores = [
            dimension_result("control_plane", str(dimensions["control_plane"].get("title")), 18, control_score, control_checks),
            dimension_result("gateway_policy", str(dimensions["gateway_policy"].get("title")), 15, gateway_score, gateway_checks),
            dimension_result("identity_delegation", str(dimensions["identity_delegation"].get("title")), 15, identity_score, identity_checks),
            dimension_result("connector_trust", str(dimensions["connector_trust"].get("title")), 14, connector_score, connector_checks),
            dimension_result("adversarial_eval", str(dimensions["adversarial_eval"].get("title")), 14, red_team_score, red_team_checks),
            dimension_result("evidence_chain", str(dimensions["evidence_chain"].get("title")), 12, evidence_score, evidence_checks),
            dimension_result("maturity_signal", str(dimensions["maturity_signal"].get("title")), 12, maturity_score, maturity_checks),
        ]
        total_score = sum(int(item["earned"]) for item in dimension_scores)
        blockers = build_blockers(
            workflow=workflow,
            policy=policy,
            identities=workflow_identities,
            connector_rows=connector_rows,
            workflow_drill=workflow_drill,
            required=required,
            source_failures=source_failures,
        )
        decision = decide(
            score=total_score,
            workflow=workflow,
            connector_rows=connector_rows,
            blockers=blockers,
            decision_contract=decision_contract,
        )
        owner = workflow.get("owner") if isinstance(workflow.get("owner"), dict) else {}
        workflow_rows.append(
            {
                "blockers": blockers,
                "connector_statuses": connector_rows,
                "decision": decision,
                "dimension_scores": dimension_scores,
                "identity_count": len(workflow_identities),
                "maturity_stage": workflow.get("maturity_stage"),
                "mcp_namespaces": [str(row.get("namespace")) for row in connector_rows],
                "next_actions": next_actions(decision, workflow, connector_rows, blockers),
                "owner": {
                    "accountable_team": owner.get("accountable_team"),
                    "escalation": owner.get("escalation"),
                    "reviewer_pools": owner.get("reviewer_pools", []),
                },
                "public_path": workflow.get("public_path"),
                "red_team_drill_count": int(workflow_drill.get("drill_count", 0)) if workflow_drill else 0,
                "score": total_score,
                "status": workflow.get("status"),
                "title": workflow.get("title"),
                "workflow_id": workflow_id,
            }
        )

    decision_counts = Counter(str(row.get("decision")) for row in workflow_rows)
    scores = [int(row.get("score", 0)) for row in workflow_rows]
    average_score = round(sum(scores) / len(scores), 2) if scores else 0
    if average_score == int(average_score):
        average_score = int(average_score)
    pilot_connector_workflows = [
        str(row.get("workflow_id"))
        for row in workflow_rows
        if any(connector.get("status") == "pilot" for connector in row.get("connector_statuses", []))
    ]

    return {
        "decision_contract": decision_contract,
        "enterprise_adoption_packet": model.get("enterprise_adoption_packet"),
        "failures": failures,
        "generated_at": generated_at or str(model.get("last_reviewed", "")),
        "intent": model.get("intent"),
        "positioning": model.get("positioning", {}),
        "readiness_summary": {
            "active_workflow_count": sum(1 for row in workflow_rows if row.get("status") == "active"),
            "average_score": average_score,
            "blocked_workflow_count": int(decision_counts.get("blocked", 0)),
            "decision_counts": dict(sorted(decision_counts.items())),
            "failure_count": len(failures),
            "manual_gate_workflow_count": int(decision_counts.get("manual_gate", 0)),
            "pilot_connector_workflows": pilot_connector_workflows,
            "pilot_guarded_workflow_count": int(decision_counts.get("pilot_guarded", 0)),
            "scale_ready_workflow_count": int(decision_counts.get("scale_ready", 0)),
            "source_failure_count": len(source_failures),
            "workflow_count": len(workflow_rows),
        },
        "residual_risks": [
            {
                "risk": "The scorecard proves readiness of the reference operating model, not live customer enforcement.",
                "treatment": "Bind the scorecard to runtime MCP gateway logs, source-host review events, and customer IAM controls before production expansion.",
            },
            {
                "risk": "Scores can be high while pilot connectors still depend on customer-specific hardening.",
                "treatment": "Treat pilot connector workflows as pilot_guarded until connector owners provide production evidence and promotion approval.",
            },
            {
                "risk": "A scale decision can become stale after model, agent host, MCP connector, or workflow changes.",
                "treatment": "Run the generator in CI and require scorecard review during workflow maturity changes and connector promotions.",
            },
        ],
        "scale_plan": {
            "next_30_days": [
                "Use scale_ready workflows as the first enterprise expansion cohort.",
                "Keep pilot_guarded workflows behind explicit rollout cohorts and reviewer capacity limits.",
                "Attach the scorecard to AI platform intake and procurement-security review.",
            ],
            "next_90_days": [
                "Promote pilot MCP connectors that repeatedly pass red-team drills and runtime audit review.",
                "Add customer runtime telemetry ingestion so score decisions include live enforcement evidence.",
                "Expose readiness deltas in hosted MCP and trust-center surfaces.",
            ],
        },
        "schema_version": "1.0",
        "score_dimensions": model.get("score_dimensions", []),
        "source_artifacts": {
            "agent_identity_delegation_ledger": {
                "path": normalize_path(identity_ledger_ref),
                "sha256": sha256_file(identity_ledger_path),
            },
            "agentic_assurance_pack": {
                "path": normalize_path(assurance_pack_ref),
                "sha256": sha256_file(assurance_pack_path),
            },
            "agentic_readiness_model": {
                "path": normalize_path(model_ref),
                "sha256": sha256_file(model_path),
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
            "workflow_control_plane_report": {
                "path": normalize_path(report_ref),
                "sha256": sha256_file(report_path),
            },
            "workflow_manifest": {
                "path": normalize_path(manifest_ref),
                "sha256": sha256_file(manifest_path),
            },
        },
        "standards_alignment": model.get("standards_alignment", []),
        "workflow_readiness": workflow_rows,
    }


def validate_scorecard(scorecard: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(scorecard.get("schema_version") == "1.0", failures, "scorecard schema_version must be 1.0")
    rows = as_list(scorecard.get("workflow_readiness"), "workflow_readiness")
    summary = as_dict(scorecard.get("readiness_summary"), "readiness_summary")
    require(summary.get("workflow_count") == len(rows), failures, "readiness_summary.workflow_count is stale")
    for row in rows:
        item = as_dict(row, "workflow_readiness row")
        score = int(item.get("score", -1))
        require(0 <= score <= 100, failures, f"{item.get('workflow_id')}: score must be between 0 and 100")
        dimensions = as_list(item.get("dimension_scores"), f"{item.get('workflow_id')}: dimension_scores")
        require(sum(int(dimension.get("earned", 0)) for dimension in dimensions if isinstance(dimension, dict)) == score, failures, f"{item.get('workflow_id')}: dimension score sum is stale")
        require(item.get("decision") in {"scale_ready", "pilot_guarded", "manual_gate", "blocked"}, failures, f"{item.get('workflow_id')}: unknown decision")
        if item.get("decision") == "scale_ready":
            require(item.get("maturity_stage") in {"walk", "run"}, failures, f"{item.get('workflow_id')}: scale_ready requires walk or run maturity")
            require(all(connector.get("production_ready") for connector in item.get("connector_statuses", [])), failures, f"{item.get('workflow_id')}: scale_ready requires production connectors")
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
    parser.add_argument("--identity-ledger", type=Path, default=DEFAULT_IDENTITY_LEDGER)
    parser.add_argument("--red-team-drill-pack", type=Path, default=DEFAULT_RED_TEAM_DRILL_PACK)
    parser.add_argument("--assurance-pack", type=Path, default=DEFAULT_ASSURANCE_PACK)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in readiness scorecard is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    model_path = resolve(repo_root, args.model)
    manifest_path = resolve(repo_root, args.manifest)
    policy_path = resolve(repo_root, args.policy)
    connector_trust_pack_path = resolve(repo_root, args.connector_trust_pack)
    identity_ledger_path = resolve(repo_root, args.identity_ledger)
    red_team_drill_pack_path = resolve(repo_root, args.red_team_drill_pack)
    assurance_pack_path = resolve(repo_root, args.assurance_pack)
    report_path = resolve(repo_root, args.report)
    output_path = resolve(repo_root, args.output)

    try:
        model = load_json(model_path)
        manifest = load_json(manifest_path)
        policy_pack = load_json(policy_path)
        connector_trust_pack = load_json(connector_trust_pack_path)
        identity_ledger = load_json(identity_ledger_path)
        red_team_drill_pack = load_json(red_team_drill_pack_path)
        assurance_pack = load_json(assurance_pack_path)
        report = load_json(report_path)

        failures = validate_model(model)
        source_failures = source_hash_failures(
            manifest_path=manifest_path,
            policy_pack=policy_pack,
            connector_trust_pack=connector_trust_pack,
            identity_ledger=identity_ledger,
            red_team_drill_pack=red_team_drill_pack,
            assurance_pack=assurance_pack,
            report=report,
        )
        failures.extend(source_failures)
        scorecard = build_scorecard(
            model=model,
            manifest=manifest,
            policy_pack=policy_pack,
            connector_trust_pack=connector_trust_pack,
            identity_ledger=identity_ledger,
            red_team_drill_pack=red_team_drill_pack,
            assurance_pack=assurance_pack,
            report=report,
            source_failures=source_failures,
            model_path=model_path,
            manifest_path=manifest_path,
            policy_path=policy_path,
            connector_trust_pack_path=connector_trust_pack_path,
            identity_ledger_path=identity_ledger_path,
            red_team_drill_pack_path=red_team_drill_pack_path,
            assurance_pack_path=assurance_pack_path,
            report_path=report_path,
            model_ref=args.model,
            manifest_ref=args.manifest,
            policy_ref=args.policy,
            connector_trust_pack_ref=args.connector_trust_pack,
            identity_ledger_ref=args.identity_ledger,
            red_team_drill_pack_ref=args.red_team_drill_pack,
            assurance_pack_ref=args.assurance_pack,
            report_ref=args.report,
            generated_at=args.generated_at,
            failures=failures,
        )
        failures.extend(validate_scorecard(scorecard))
        scorecard["failures"] = failures
        scorecard["readiness_summary"]["failure_count"] = len(failures)
    except ReadinessScorecardError as exc:
        print(f"agentic readiness scorecard generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(scorecard)

    if args.check:
        if failures:
            print("agentic readiness scorecard validation failed:", file=sys.stderr)
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
                f"{output_path} is stale; run scripts/generate_agentic_readiness_scorecard.py",
                file=sys.stderr,
            )
            return 1
        print(f"Validated agentic readiness scorecard: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")

    if failures:
        print("Generated agentic readiness scorecard with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated agentic readiness scorecard: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
