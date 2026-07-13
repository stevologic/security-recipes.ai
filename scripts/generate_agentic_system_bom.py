#!/usr/bin/env python3
"""Generate the SecurityRecipes Agentic System Bill of Materials.

The assurance pack includes an AI/Agent BOM seed. This generator turns
the seed into a full inspectability artifact by joining the workflow
manifest, gateway policy, connector trust pack, identity ledger,
red-team drills, readiness scorecard, assurance pack, and source BOM
profile.

The output is deterministic by default so CI can run with --check and
fail when the checked-in BOM drifts from source controls.
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


BOM_SCHEMA_VERSION = "1.0"
DEFAULT_PROFILE = Path("data/assurance/agentic-system-bom-profile.json")
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_POLICY = Path("data/policy/mcp-gateway-policy.json")
DEFAULT_CONNECTOR_TRUST_PACK = Path("data/evidence/mcp-connector-trust-pack.json")
DEFAULT_IDENTITY_LEDGER = Path("data/evidence/agent-identity-delegation-ledger.json")
DEFAULT_RED_TEAM_DRILL_PACK = Path("data/evidence/agentic-red-team-drill-pack.json")
DEFAULT_READINESS_SCORECARD = Path("data/evidence/agentic-readiness-scorecard.json")
DEFAULT_ASSURANCE_PACK = Path("data/evidence/agentic-assurance-pack.json")
DEFAULT_REPORT = Path("data/evidence/workflow-control-plane-report.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-system-bom.json")

WORKFLOW_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]+$")
REQUIRED_COMPONENT_TYPES = {
    "workflows",
    "agent_classes",
    "agent_identities",
    "mcp_connectors",
    "policy_components",
    "evidence_artifacts",
    "knowledge_sources",
    "evaluation_drills",
}
REQUIRED_DRIFT_TRIGGERS = {
    "agent_changed",
    "mcp_server_changed",
    "tool_changed",
    "model_changed",
    "knowledge_changed",
    "memory_changed",
    "policy_changed",
    "workflow_changed",
    "connector_trust_changed",
    "identity_contract_changed",
    "red_team_scenario_changed",
    "readiness_model_changed",
}


class AgenticSystemBOMError(RuntimeError):
    """Raised when the Agentic System BOM cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AgenticSystemBOMError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise AgenticSystemBOMError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AgenticSystemBOMError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise AgenticSystemBOMError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgenticSystemBOMError(f"{label} must be an object")
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


def first_nonempty(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def workflow_by_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for workflow in as_list(manifest.get("workflows"), "manifest.workflows"):
        item = as_dict(workflow, "manifest.workflow")
        workflow_id = str(item.get("id", "")).strip()
        if workflow_id:
            output[workflow_id] = item
    return output


def policy_by_workflow_id(policy_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for policy in as_list(policy_pack.get("workflow_policies"), "policy_pack.workflow_policies"):
        item = as_dict(policy, "policy_pack.workflow_policy")
        workflow_id = str(item.get("workflow_id", "")).strip()
        if workflow_id:
            output[workflow_id] = item
    return output


def connector_by_namespace(connector_trust_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for connector in as_list(connector_trust_pack.get("connectors"), "connector_trust_pack.connectors"):
        item = as_dict(connector, "connector_trust_pack.connector")
        namespace = str(item.get("namespace", "")).strip()
        if namespace:
            output[namespace] = item
    return output


def identity_by_workflow_agent(identity_ledger: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    output: dict[tuple[str, str], dict[str, Any]] = {}
    for identity in as_list(identity_ledger.get("agent_identities"), "identity_ledger.agent_identities"):
        item = as_dict(identity, "identity_ledger.agent_identity")
        workflow_id = str(item.get("workflow_id", "")).strip()
        agent_class = str(item.get("agent_class", "")).strip()
        if workflow_id and agent_class:
            output[(workflow_id, agent_class)] = item
    return output


def red_team_by_workflow(red_team_drill_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for workflow in as_list(red_team_drill_pack.get("workflow_drills"), "red_team_drill_pack.workflow_drills"):
        item = as_dict(workflow, "red_team_drill_pack.workflow_drill")
        workflow_id = str(item.get("workflow_id", "")).strip()
        if workflow_id:
            output[workflow_id] = item
    return output


def readiness_by_workflow(scorecard: dict[str, Any]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for workflow in as_list(scorecard.get("workflow_readiness"), "scorecard.workflow_readiness"):
        item = as_dict(workflow, "scorecard.workflow_readiness row")
        workflow_id = str(item.get("workflow_id", "")).strip()
        if workflow_id:
            output[workflow_id] = item
    return output


def assurance_by_workflow(assurance_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for workflow in as_list(assurance_pack.get("workflow_assurance"), "assurance_pack.workflow_assurance"):
        item = as_dict(workflow, "assurance_pack.workflow_assurance row")
        workflow_id = str(item.get("workflow_id", "")).strip()
        if workflow_id:
            output[workflow_id] = item
    return output


def allowed_scope_by_namespace(policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    tool_access = policy.get("tool_access") if isinstance(policy.get("tool_access"), dict) else {}
    output: dict[str, dict[str, Any]] = {}
    for scope in tool_access.get("allowed_mcp_scopes", []) or []:
        if not isinstance(scope, dict):
            continue
        namespace = str(scope.get("namespace", "")).strip()
        if namespace:
            output[namespace] = scope
    return output


def validate_profile(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == "1.0", failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 80, failures, "profile intent must explain the BOM product goal")

    standards = as_list(profile.get("standards_alignment"), "profile.standards_alignment")
    require(len(standards) >= 6, failures, "profile must include at least six standards references")
    standard_ids: set[str] = set()
    for idx, standard in enumerate(standards):
        label = f"profile.standards_alignment[{idx}]"
        item = as_dict(standard, label)
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"{label}.id is required")
        require(standard_id not in standard_ids, failures, f"{label}.id duplicates {standard_id}")
        standard_ids.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{label}.url must be https")

    contract = as_dict(profile.get("component_contract"), "profile.component_contract")
    component_types = {str(item) for item in as_list(contract.get("required_component_types"), "component_contract.required_component_types")}
    missing_types = sorted(REQUIRED_COMPONENT_TYPES - component_types)
    require(not missing_types, failures, f"component_contract missing component types: {missing_types}")

    trigger_ids = {
        str(item.get("id"))
        for item in as_list(profile.get("drift_triggers"), "profile.drift_triggers")
        if isinstance(item, dict) and item.get("id")
    }
    declared_triggers = {str(item) for item in as_list(contract.get("required_drift_triggers"), "component_contract.required_drift_triggers")}
    missing_declared = sorted(REQUIRED_DRIFT_TRIGGERS - declared_triggers)
    missing_records = sorted(declared_triggers - trigger_ids)
    require(not missing_declared, failures, f"component_contract missing drift triggers: {missing_declared}")
    require(not missing_records, failures, f"profile.drift_triggers missing records: {missing_records}")

    return failures


def source_hash_failures(
    *,
    manifest_path: Path,
    policy_path: Path,
    connector_trust_pack_path: Path,
    identity_ledger_path: Path,
    red_team_drill_pack_path: Path,
    readiness_scorecard_path: Path,
    assurance_pack_path: Path,
    report_path: Path,
    policy_pack: dict[str, Any],
    connector_trust_pack: dict[str, Any],
    identity_ledger: dict[str, Any],
    red_team_drill_pack: dict[str, Any],
    readiness_scorecard: dict[str, Any],
    assurance_pack: dict[str, Any],
    report: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    manifest_hash = sha256_file(manifest_path)
    policy_hash = sha256_file(policy_path)
    connector_hash = sha256_file(connector_trust_pack_path)
    identity_hash = sha256_file(identity_ledger_path)
    red_team_hash = sha256_file(red_team_drill_pack_path)
    readiness_hash = sha256_file(readiness_scorecard_path)
    assurance_hash = sha256_file(assurance_pack_path)
    report_hash = sha256_file(report_path)

    def check_source(pack: dict[str, Any], key: str, expected_hash: str, label: str) -> None:
        source = pack.get("source_artifacts", {}).get(key) if isinstance(pack.get("source_artifacts"), dict) else None
        if source is None:
            failures.append(f"{label} missing source_artifacts.{key}")
            return
        if source.get("sha256") != expected_hash:
            failures.append(f"{label} source_artifacts.{key}.sha256 is stale")

    policy_source = as_dict(policy_pack.get("source_manifest"), "policy_pack.source_manifest")
    require(policy_source.get("sha256") == manifest_hash, failures, "gateway policy source_manifest.sha256 is stale")

    check_source(connector_trust_pack, "workflow_manifest", manifest_hash, "connector trust pack")
    check_source(connector_trust_pack, "gateway_policy_pack", policy_hash, "connector trust pack")
    check_source(identity_ledger, "workflow_manifest", manifest_hash, "identity ledger")
    check_source(identity_ledger, "gateway_policy_pack", policy_hash, "identity ledger")
    check_source(identity_ledger, "workflow_control_plane_report", report_hash, "identity ledger")
    check_source(red_team_drill_pack, "workflow_manifest", manifest_hash, "red-team drill pack")
    check_source(red_team_drill_pack, "gateway_policy_pack", policy_hash, "red-team drill pack")
    check_source(red_team_drill_pack, "connector_trust_pack", connector_hash, "red-team drill pack")
    check_source(red_team_drill_pack, "agent_identity_delegation_ledger", identity_hash, "red-team drill pack")
    check_source(assurance_pack, "workflow_manifest", manifest_hash, "assurance pack")
    check_source(assurance_pack, "gateway_policy_pack", policy_hash, "assurance pack")
    check_source(assurance_pack, "workflow_control_plane_report", report_hash, "assurance pack")
    check_source(readiness_scorecard, "workflow_manifest", manifest_hash, "readiness scorecard")
    check_source(readiness_scorecard, "gateway_policy_pack", policy_hash, "readiness scorecard")
    check_source(readiness_scorecard, "connector_trust_pack", connector_hash, "readiness scorecard")
    check_source(readiness_scorecard, "agent_identity_delegation_ledger", identity_hash, "readiness scorecard")
    check_source(readiness_scorecard, "agentic_red_team_drill_pack", red_team_hash, "readiness scorecard")
    check_source(readiness_scorecard, "agentic_assurance_pack", assurance_hash, "readiness scorecard")
    check_source(readiness_scorecard, "workflow_control_plane_report", report_hash, "readiness scorecard")

    require(report.get("failure_count") == 0, failures, "workflow control-plane report has failures")
    require(connector_trust_pack.get("connector_trust_summary", {}).get("failure_count") == 0, failures, "connector trust pack has failures")
    require(identity_ledger.get("failures") == [], failures, "identity ledger has failures")
    require(red_team_drill_pack.get("red_team_summary", {}).get("failure_count") == 0, failures, "red-team drill pack has failures")
    require(assurance_pack.get("assurance_summary", {}).get("failure_count") == 0, failures, "assurance pack has failures")
    require(readiness_scorecard.get("readiness_summary", {}).get("failure_count") == 0, failures, "readiness scorecard has failures")

    return failures


def build_agent_class_components(manifest: dict[str, Any], identities: dict[tuple[str, str], dict[str, Any]]) -> list[dict[str, Any]]:
    workflows = workflow_by_id(manifest)
    workflows_by_agent: dict[str, list[str]] = defaultdict(list)
    for workflow_id, workflow in workflows.items():
        for agent in workflow.get("default_agents", []) or []:
            workflows_by_agent[str(agent)].append(workflow_id)

    components: list[dict[str, Any]] = []
    for agent_class in sorted(workflows_by_agent):
        identity_count = sum(1 for workflow_id in workflows_by_agent[agent_class] if (workflow_id, agent_class) in identities)
        components.append(
            {
                "agent_class": agent_class,
                "component_id": f"agent-class::{agent_class}",
                "component_type": "agent_classes",
                "drift_triggers": [
                    "agent_changed",
                    "model_changed",
                    "memory_changed",
                ],
                "identity_count": identity_count,
                "model_binding": {
                    "binding": "host-managed",
                    "required_control": "Rerun prompt regression, red-team drills, readiness scoring, and BOM generation before treating a model or host upgrade as production-ready.",
                },
                "workflow_count": len(workflows_by_agent[agent_class]),
                "workflow_ids": sorted(workflows_by_agent[agent_class]),
            }
        )
    return components


def build_identity_components(identity_ledger: dict[str, Any]) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for identity in as_list(identity_ledger.get("agent_identities"), "identity_ledger.agent_identities"):
        item = as_dict(identity, "identity_ledger.agent_identity")
        authority = item.get("delegated_authority") if isinstance(item.get("delegated_authority"), dict) else {}
        components.append(
            {
                "agent_class": item.get("agent_class"),
                "component_id": item.get("identity_id"),
                "component_type": "agent_identities",
                "explicit_denies": item.get("explicit_denies", {}).get("actions", []),
                "mcp_namespaces": [
                    scope.get("namespace")
                    for scope in authority.get("mcp_scopes", []) or []
                    if isinstance(scope, dict) and scope.get("namespace")
                ],
                "owner": item.get("owner"),
                "risk_tier": item.get("risk_tier"),
                "runtime_contract": item.get("runtime_contract"),
                "status": item.get("status"),
                "workflow_id": item.get("workflow_id"),
                "workflow_title": item.get("workflow_title"),
            }
        )
    return sorted(components, key=lambda row: str(row.get("component_id")))


def build_connector_components(connector_trust_pack: dict[str, Any]) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for connector in as_list(connector_trust_pack.get("connectors"), "connector_trust_pack.connectors"):
        item = as_dict(connector, "connector_trust_pack.connector")
        tier = item.get("trust_tier") if isinstance(item.get("trust_tier"), dict) else {}
        components.append(
            {
                "access_modes": item.get("access_modes", []),
                "component_id": f"mcp-connector::{item.get('namespace')}",
                "component_type": "mcp_connectors",
                "connector_id": item.get("connector_id"),
                "data_classes": item.get("data_classes", []),
                "deployment_model": item.get("deployment_model"),
                "drift_triggers": [
                    "mcp_server_changed",
                    "tool_changed",
                    "connector_trust_changed",
                ],
                "evidence_record_count": len(item.get("evidence_records", []) or []),
                "namespace": item.get("namespace"),
                "owner": item.get("owner"),
                "required_controls": item.get("required_controls", []),
                "status": item.get("status"),
                "title": item.get("title"),
                "transport": item.get("transport"),
                "trust_tier": tier,
            }
        )
    return sorted(components, key=lambda row: str(row.get("namespace")))


def build_policy_components(policy_pack: dict[str, Any], manifest: dict[str, Any]) -> list[dict[str, Any]]:
    decision_contract = policy_pack.get("decision_contract") if isinstance(policy_pack.get("decision_contract"), dict) else {}
    return [
        {
            "component_id": "policy::workflow-control-plane",
            "component_type": "policy_components",
            "drift_triggers": ["workflow_changed", "knowledge_changed"],
            "last_reviewed": manifest.get("last_reviewed"),
            "path": "data/control-plane/workflow-manifests.json",
            "purpose": "Declares workflow scope, owners, gates, evidence, KPIs, MCP context, and kill signals.",
            "workflow_count": len(manifest.get("workflows", []) or []),
        },
        {
            "component_id": "policy::mcp-gateway",
            "component_type": "policy_components",
            "default_decision": decision_contract.get("default_decision"),
            "decisions": [item.get("decision") for item in decision_contract.get("decisions", []) if isinstance(item, dict)],
            "drift_triggers": ["policy_changed", "tool_changed", "workflow_changed"],
            "path": "data/policy/mcp-gateway-policy.json",
            "purpose": "Turns workflow declarations into default-deny MCP runtime decisions.",
            "required_runtime_attributes": decision_contract.get("required_runtime_attributes", []),
        },
        {
            "component_id": "policy::agent-identity-delegation",
            "component_type": "policy_components",
            "drift_triggers": ["identity_contract_changed", "agent_changed"],
            "path": "data/evidence/agent-identity-delegation-ledger.json",
            "purpose": "Binds agent classes to non-human identity, delegated authority, explicit denies, and runtime revocation.",
        },
        {
            "component_id": "policy::readiness-promotion-gate",
            "component_type": "policy_components",
            "drift_triggers": ["readiness_model_changed", "connector_trust_changed", "red_team_scenario_changed"],
            "path": "data/evidence/agentic-readiness-scorecard.json",
            "purpose": "Produces scale, pilot, manual gate, or blocked workflow decisions from generated evidence.",
        },
    ]


def build_knowledge_sources() -> list[dict[str, Any]]:
    return [
        {
            "component_id": "knowledge::recipes",
            "component_type": "knowledge_sources",
            "drift_triggers": ["knowledge_changed"],
            "path": "content/recipes",
            "purpose": "Reusable prompts and instructions consumed by agent hosts and workflow operators.",
        },
        {
            "component_id": "knowledge::security-remediation-docs",
            "component_type": "knowledge_sources",
            "drift_triggers": ["knowledge_changed", "workflow_changed"],
            "path": "content/security-remediation",
            "purpose": "Human-readable operating model for agentic remediation workflows and program controls.",
        },
        {
            "component_id": "knowledge::control-plane-data",
            "component_type": "knowledge_sources",
            "drift_triggers": ["workflow_changed", "policy_changed"],
            "path": "data/control-plane",
            "purpose": "Machine-readable workflow manifests consumed by generators, MCP tools, and CI validation.",
        },
        {
            "component_id": "knowledge::assurance-data",
            "component_type": "knowledge_sources",
            "drift_triggers": ["knowledge_changed", "red_team_scenario_changed", "readiness_model_changed"],
            "path": "data/assurance",
            "purpose": "Source maps for assurance, red-team, readiness, and Agentic System BOM generation.",
        },
    ]


def build_evidence_artifacts(
    *,
    profile_ref: Path,
    manifest_ref: Path,
    policy_ref: Path,
    connector_trust_pack_ref: Path,
    identity_ledger_ref: Path,
    red_team_drill_pack_ref: Path,
    readiness_scorecard_ref: Path,
    assurance_pack_ref: Path,
    report_ref: Path,
    profile_path: Path,
    manifest_path: Path,
    policy_path: Path,
    connector_trust_pack_path: Path,
    identity_ledger_path: Path,
    red_team_drill_pack_path: Path,
    readiness_scorecard_path: Path,
    assurance_pack_path: Path,
    report_path: Path,
) -> list[dict[str, Any]]:
    artifacts = [
        ("agentic-system-bom-profile", "Agentic System BOM profile", profile_ref, profile_path, "source_profile"),
        ("workflow-manifest", "Workflow control-plane manifest", manifest_ref, manifest_path, "source_control"),
        ("mcp-gateway-policy-pack", "MCP gateway policy pack", policy_ref, policy_path, "generated_policy"),
        ("mcp-connector-trust-pack", "MCP connector trust pack", connector_trust_pack_ref, connector_trust_pack_path, "generated_evidence"),
        ("agent-identity-delegation-ledger", "Agent identity delegation ledger", identity_ledger_ref, identity_ledger_path, "generated_evidence"),
        ("agentic-red-team-drill-pack", "Agentic red-team drill pack", red_team_drill_pack_ref, red_team_drill_pack_path, "generated_evidence"),
        ("agentic-readiness-scorecard", "Agentic readiness scorecard", readiness_scorecard_ref, readiness_scorecard_path, "generated_evidence"),
        ("agentic-assurance-pack", "Agentic assurance pack", assurance_pack_ref, assurance_pack_path, "generated_evidence"),
        ("workflow-control-plane-report", "Workflow control-plane validation report", report_ref, report_path, "generated_evidence"),
    ]
    return [
        {
            "artifact_class": artifact_class,
            "component_id": f"evidence::{artifact_id}",
            "component_type": "evidence_artifacts",
            "path": normalize_path(artifact_ref),
            "sha256": sha256_file(artifact_path),
            "title": title,
        }
        for artifact_id, title, artifact_ref, artifact_path, artifact_class in artifacts
    ]


def build_evaluation_drills(red_team_drill_pack: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for workflow in as_list(red_team_drill_pack.get("workflow_drills"), "red_team_drill_pack.workflow_drills"):
        workflow_item = as_dict(workflow, "red_team_drill_pack.workflow_drill")
        for drill in workflow_item.get("drills", []) or []:
            if not isinstance(drill, dict):
                continue
            rows.append(
                {
                    "attack_family": drill.get("attack_family"),
                    "component_id": f"evaluation-drill::{drill.get('drill_id')}",
                    "component_type": "evaluation_drills",
                    "drill_id": drill.get("drill_id"),
                    "expected_policy_decisions": drill.get("expected_policy_decisions", []),
                    "scenario_id": drill.get("scenario_id"),
                    "severity": drill.get("severity"),
                    "workflow_id": workflow_item.get("workflow_id"),
                }
            )
    return sorted(rows, key=lambda row: str(row.get("component_id")))


def build_workflow_bom(
    *,
    manifest: dict[str, Any],
    policy_pack: dict[str, Any],
    connector_trust_pack: dict[str, Any],
    identity_ledger: dict[str, Any],
    red_team_drill_pack: dict[str, Any],
    readiness_scorecard: dict[str, Any],
    assurance_pack: dict[str, Any],
) -> list[dict[str, Any]]:
    workflows = workflow_by_id(manifest)
    policies = policy_by_workflow_id(policy_pack)
    connectors = connector_by_namespace(connector_trust_pack)
    identities = identity_by_workflow_agent(identity_ledger)
    red_team = red_team_by_workflow(red_team_drill_pack)
    readiness = readiness_by_workflow(readiness_scorecard)
    assurance = assurance_by_workflow(assurance_pack)

    rows: list[dict[str, Any]] = []
    for workflow_id in sorted(workflows):
        workflow = workflows[workflow_id]
        policy = policies.get(workflow_id, {})
        scopes = allowed_scope_by_namespace(policy)
        default_agents = [str(agent) for agent in workflow.get("default_agents", []) or []]
        missing_identity_agents = [
            agent
            for agent in default_agents
            if (workflow_id, agent) not in identities
        ]
        namespace_rows: list[dict[str, Any]] = []
        for context in workflow.get("mcp_context", []) or []:
            if not isinstance(context, dict):
                continue
            namespace = str(context.get("namespace", "")).strip()
            connector = connectors.get(namespace, {})
            trust_tier = connector.get("trust_tier") if isinstance(connector.get("trust_tier"), dict) else {}
            scope = scopes.get(namespace, {})
            namespace_rows.append(
                {
                    "access": context.get("access"),
                    "connector_id": connector.get("connector_id"),
                    "decision": scope.get("decision"),
                    "namespace": namespace,
                    "production_ready": connector.get("status") == "production",
                    "purpose": context.get("purpose"),
                    "status": connector.get("status"),
                    "trust_tier": trust_tier.get("id"),
                }
            )

        workflow_red_team = red_team.get(workflow_id, {})
        workflow_readiness = readiness.get(workflow_id, {})
        workflow_assurance = assurance.get(workflow_id, {})
        rows.append(
            {
                "agent_classes": default_agents,
                "agent_identity_ids": [
                    identities[(workflow_id, agent)].get("identity_id")
                    for agent in default_agents
                    if (workflow_id, agent) in identities
                ],
                "applicable_control_ids": workflow_assurance.get("applicable_control_ids", []),
                "component_id": f"workflow::{workflow_id}",
                "component_type": "workflows",
                "content_path": workflow.get("content_path"),
                "drift_triggers": [
                    "workflow_changed",
                    "policy_changed",
                    "agent_changed",
                    "mcp_server_changed",
                    "tool_changed",
                ],
                "evidence_record_count": len(workflow.get("evidence", []) or []),
                "gate_phases": sorted((workflow.get("gates") or {}).keys()) if isinstance(workflow.get("gates"), dict) else [],
                "kpi_count": len(workflow.get("kpis", []) or []),
                "maturity_stage": workflow.get("maturity_stage"),
                "mcp_namespaces": namespace_rows,
                "missing_identity_agents": missing_identity_agents,
                "owner": workflow.get("owner"),
                "policy_decisions": sorted(
                    {
                        str(scope.get("decision"))
                        for scope in scopes.values()
                        if isinstance(scope, dict) and scope.get("decision")
                    }
                ),
                "public_path": workflow.get("public_path"),
                "readiness_decision": workflow_readiness.get("decision"),
                "readiness_score": workflow_readiness.get("score"),
                "red_team_drill_count": int(first_nonempty(workflow_red_team.get("drill_count"), len(workflow_red_team.get("drills", []) or []), 0)),
                "status": workflow.get("status"),
                "title": workflow.get("title"),
                "workflow_id": workflow_id,
            }
        )
    return rows


def build_bom(
    *,
    profile: dict[str, Any],
    manifest: dict[str, Any],
    policy_pack: dict[str, Any],
    connector_trust_pack: dict[str, Any],
    identity_ledger: dict[str, Any],
    red_team_drill_pack: dict[str, Any],
    readiness_scorecard: dict[str, Any],
    assurance_pack: dict[str, Any],
    report: dict[str, Any],
    profile_path: Path,
    manifest_path: Path,
    policy_path: Path,
    connector_trust_pack_path: Path,
    identity_ledger_path: Path,
    red_team_drill_pack_path: Path,
    readiness_scorecard_path: Path,
    assurance_pack_path: Path,
    report_path: Path,
    profile_ref: Path,
    manifest_ref: Path,
    policy_ref: Path,
    connector_trust_pack_ref: Path,
    identity_ledger_ref: Path,
    red_team_drill_pack_ref: Path,
    readiness_scorecard_ref: Path,
    assurance_pack_ref: Path,
    report_ref: Path,
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    identities = identity_by_workflow_agent(identity_ledger)
    workflow_rows = build_workflow_bom(
        manifest=manifest,
        policy_pack=policy_pack,
        connector_trust_pack=connector_trust_pack,
        identity_ledger=identity_ledger,
        red_team_drill_pack=red_team_drill_pack,
        readiness_scorecard=readiness_scorecard,
        assurance_pack=assurance_pack,
    )
    agent_class_components = build_agent_class_components(manifest, identities)
    identity_components = build_identity_components(identity_ledger)
    connector_components = build_connector_components(connector_trust_pack)
    policy_components = build_policy_components(policy_pack, manifest)
    knowledge_sources = build_knowledge_sources()
    evidence_artifacts = build_evidence_artifacts(
        profile_ref=profile_ref,
        manifest_ref=manifest_ref,
        policy_ref=policy_ref,
        connector_trust_pack_ref=connector_trust_pack_ref,
        identity_ledger_ref=identity_ledger_ref,
        red_team_drill_pack_ref=red_team_drill_pack_ref,
        readiness_scorecard_ref=readiness_scorecard_ref,
        assurance_pack_ref=assurance_pack_ref,
        report_ref=report_ref,
        profile_path=profile_path,
        manifest_path=manifest_path,
        policy_path=policy_path,
        connector_trust_pack_path=connector_trust_pack_path,
        identity_ledger_path=identity_ledger_path,
        red_team_drill_pack_path=red_team_drill_pack_path,
        readiness_scorecard_path=readiness_scorecard_path,
        assurance_pack_path=assurance_pack_path,
        report_path=report_path,
    )
    evaluation_drills = build_evaluation_drills(red_team_drill_pack)

    active_workflows = [workflow for workflow in workflow_rows if workflow.get("status") == "active"]
    namespace_count = len(
        {
            namespace.get("namespace")
            for workflow in workflow_rows
            for namespace in workflow.get("mcp_namespaces", [])
            if isinstance(namespace, dict) and namespace.get("namespace")
        }
    )
    missing_identity_rows = [
        {
            "workflow_id": workflow.get("workflow_id"),
            "missing_identity_agents": workflow.get("missing_identity_agents", []),
        }
        for workflow in workflow_rows
        if workflow.get("missing_identity_agents")
    ]
    readiness_counts = Counter(str(workflow.get("readiness_decision")) for workflow in workflow_rows if workflow.get("readiness_decision"))

    components = {
        "agent_classes": agent_class_components,
        "agent_identities": identity_components,
        "evaluation_drills": evaluation_drills,
        "evidence_artifacts": evidence_artifacts,
        "knowledge_sources": knowledge_sources,
        "mcp_connectors": connector_components,
        "policy_components": policy_components,
        "workflows": workflow_rows,
    }
    component_counts = {key: len(value) for key, value in components.items()}

    return {
        "bom_format": "security-recipes-agentic-system-bom",
        "bom_id": "security-recipes-agentic-system-bom",
        "bom_summary": {
            "active_workflow_count": len(active_workflows),
            "agent_class_count": len(agent_class_components),
            "agent_identity_count": len(identity_components),
            "component_counts": component_counts,
            "connector_count": len(connector_components),
            "drift_trigger_count": len(profile.get("drift_triggers", []) or []),
            "evaluation_drill_count": len(evaluation_drills),
            "failure_count": len(failures),
            "mcp_namespace_count": namespace_count,
            "missing_identity_workflow_count": len(missing_identity_rows),
            "readiness_decision_counts": dict(sorted(readiness_counts.items())),
            "source_failure_count": sum(1 for failure in failures if "sha256" in failure or "source_artifacts" in failure),
            "workflow_count": len(workflow_rows),
        },
        "change_control_contract": {
            "ci_commands": [
                "python3 scripts/generate_agentic_system_bom.py",
                "python3 scripts/generate_agentic_system_bom.py --check",
            ],
            "manual_review_required_for": [
                "model_changed",
                "memory_changed",
                "policy_changed",
                "identity_contract_changed",
                "connector_trust_changed",
                "mcp_server_changed",
            ],
            "regeneration_rule": "Regenerate this BOM whenever any source artifact hash, drift trigger, workflow scope, agent identity, connector trust record, red-team scenario, or readiness model changes.",
        },
        "components": components,
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "missing_identity_workflows": missing_identity_rows,
        "positioning": profile.get("positioning", {}),
        "schema_version": BOM_SCHEMA_VERSION,
        "source_artifacts": {
            "agent_identity_delegation_ledger": {
                "path": normalize_path(identity_ledger_ref),
                "sha256": sha256_file(identity_ledger_path),
            },
            "agentic_assurance_pack": {
                "path": normalize_path(assurance_pack_ref),
                "sha256": sha256_file(assurance_pack_path),
            },
            "agentic_readiness_scorecard": {
                "path": normalize_path(readiness_scorecard_ref),
                "sha256": sha256_file(readiness_scorecard_path),
            },
            "agentic_red_team_drill_pack": {
                "path": normalize_path(red_team_drill_pack_ref),
                "sha256": sha256_file(red_team_drill_pack_path),
            },
            "agentic_system_bom_profile": {
                "path": normalize_path(profile_ref),
                "sha256": sha256_file(profile_path),
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
        "standards_alignment": profile.get("standards_alignment", []),
        "update_triggers": profile.get("drift_triggers", []),
    }


def validate_bom(bom: dict[str, Any], profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(bom.get("schema_version") == BOM_SCHEMA_VERSION, failures, "BOM schema_version must be 1.0")
    components = as_dict(bom.get("components"), "bom.components")
    required_types = {
        str(item)
        for item in as_dict(profile.get("component_contract"), "profile.component_contract").get("required_component_types", [])
    }
    for component_type in sorted(required_types):
        require(component_type in components, failures, f"BOM components missing {component_type}")
        require(bool(components.get(component_type)), failures, f"BOM component list is empty: {component_type}")

    summary = as_dict(bom.get("bom_summary"), "bom.bom_summary")
    require(summary.get("workflow_count") == len(components.get("workflows", [])), failures, "bom_summary.workflow_count is stale")
    require(summary.get("agent_identity_count") == len(components.get("agent_identities", [])), failures, "bom_summary.agent_identity_count is stale")
    require(summary.get("connector_count") == len(components.get("mcp_connectors", [])), failures, "bom_summary.connector_count is stale")
    require(summary.get("evaluation_drill_count") == len(components.get("evaluation_drills", [])), failures, "bom_summary.evaluation_drill_count is stale")

    contract = as_dict(profile.get("component_contract"), "profile.component_contract")
    min_drills = int(contract.get("minimum_red_team_drills_per_active_workflow", 5))
    for workflow in components.get("workflows", []):
        if not isinstance(workflow, dict):
            failures.append("workflow BOM row must be an object")
            continue
        workflow_id = str(workflow.get("workflow_id", ""))
        require(bool(WORKFLOW_ID_RE.match(workflow_id)), failures, f"{workflow_id}: workflow_id must be kebab-case")
        if workflow.get("status") == "active":
            require(int(workflow.get("red_team_drill_count") or 0) >= min_drills, failures, f"{workflow_id}: insufficient red-team drill coverage")
        require(not workflow.get("missing_identity_agents"), failures, f"{workflow_id}: missing identity agents {workflow.get('missing_identity_agents')}")
        for namespace in workflow.get("mcp_namespaces", []) or []:
            if not isinstance(namespace, dict):
                failures.append(f"{workflow_id}: mcp namespace row must be an object")
                continue
            require(bool(namespace.get("connector_id")), failures, f"{workflow_id}: namespace missing connector registration: {namespace.get('namespace')}")
            require(bool(namespace.get("decision")), failures, f"{workflow_id}: namespace missing gateway decision: {namespace.get('namespace')}")

    trigger_ids = {
        str(trigger.get("id"))
        for trigger in bom.get("update_triggers", []) or []
        if isinstance(trigger, dict) and trigger.get("id")
    }
    missing_triggers = sorted(REQUIRED_DRIFT_TRIGGERS - trigger_ids)
    require(not missing_triggers, failures, f"BOM missing update triggers: {missing_triggers}")

    return failures


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--connector-trust-pack", type=Path, default=DEFAULT_CONNECTOR_TRUST_PACK)
    parser.add_argument("--identity-ledger", type=Path, default=DEFAULT_IDENTITY_LEDGER)
    parser.add_argument("--red-team-drill-pack", type=Path, default=DEFAULT_RED_TEAM_DRILL_PACK)
    parser.add_argument("--readiness-scorecard", type=Path, default=DEFAULT_READINESS_SCORECARD)
    parser.add_argument("--assurance-pack", type=Path, default=DEFAULT_ASSURANCE_PACK)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in Agentic System BOM is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    profile_path = resolve(repo_root, args.profile)
    manifest_path = resolve(repo_root, args.manifest)
    policy_path = resolve(repo_root, args.policy)
    connector_trust_pack_path = resolve(repo_root, args.connector_trust_pack)
    identity_ledger_path = resolve(repo_root, args.identity_ledger)
    red_team_drill_pack_path = resolve(repo_root, args.red_team_drill_pack)
    readiness_scorecard_path = resolve(repo_root, args.readiness_scorecard)
    assurance_pack_path = resolve(repo_root, args.assurance_pack)
    report_path = resolve(repo_root, args.report)
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(profile_path)
        manifest = load_json(manifest_path)
        policy_pack = load_json(policy_path)
        connector_trust_pack = load_json(connector_trust_pack_path)
        identity_ledger = load_json(identity_ledger_path)
        red_team_drill_pack = load_json(red_team_drill_pack_path)
        readiness_scorecard = load_json(readiness_scorecard_path)
        assurance_pack = load_json(assurance_pack_path)
        report = load_json(report_path)

        failures = validate_profile(profile)
        failures.extend(
            source_hash_failures(
                manifest_path=manifest_path,
                policy_path=policy_path,
                connector_trust_pack_path=connector_trust_pack_path,
                identity_ledger_path=identity_ledger_path,
                red_team_drill_pack_path=red_team_drill_pack_path,
                readiness_scorecard_path=readiness_scorecard_path,
                assurance_pack_path=assurance_pack_path,
                report_path=report_path,
                policy_pack=policy_pack,
                connector_trust_pack=connector_trust_pack,
                identity_ledger=identity_ledger,
                red_team_drill_pack=red_team_drill_pack,
                readiness_scorecard=readiness_scorecard,
                assurance_pack=assurance_pack,
                report=report,
            )
        )
        bom = build_bom(
            profile=profile,
            manifest=manifest,
            policy_pack=policy_pack,
            connector_trust_pack=connector_trust_pack,
            identity_ledger=identity_ledger,
            red_team_drill_pack=red_team_drill_pack,
            readiness_scorecard=readiness_scorecard,
            assurance_pack=assurance_pack,
            report=report,
            profile_path=profile_path,
            manifest_path=manifest_path,
            policy_path=policy_path,
            connector_trust_pack_path=connector_trust_pack_path,
            identity_ledger_path=identity_ledger_path,
            red_team_drill_pack_path=red_team_drill_pack_path,
            readiness_scorecard_path=readiness_scorecard_path,
            assurance_pack_path=assurance_pack_path,
            report_path=report_path,
            profile_ref=args.profile,
            manifest_ref=args.manifest,
            policy_ref=args.policy,
            connector_trust_pack_ref=args.connector_trust_pack,
            identity_ledger_ref=args.identity_ledger,
            red_team_drill_pack_ref=args.red_team_drill_pack,
            readiness_scorecard_ref=args.readiness_scorecard,
            assurance_pack_ref=args.assurance_pack,
            report_ref=args.report,
            generated_at=args.generated_at,
            failures=failures,
        )
        failures.extend(validate_bom(bom, profile))
        bom["failures"] = failures
        bom["bom_summary"]["failure_count"] = len(failures)
        bom["bom_summary"]["source_failure_count"] = sum(
            1
            for failure in failures
            if "sha256" in failure or "source_artifacts" in failure
        )
    except AgenticSystemBOMError as exc:
        print(f"agentic system BOM generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(bom)

    if args.check:
        if failures:
            print("agentic system BOM validation failed:", file=sys.stderr)
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
                f"{output_path} is stale; run scripts/generate_agentic_system_bom.py",
                file=sys.stderr,
            )
            return 1
        print(f"Validated agentic system BOM: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")

    if failures:
        print("Generated agentic system BOM with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated agentic system BOM: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
