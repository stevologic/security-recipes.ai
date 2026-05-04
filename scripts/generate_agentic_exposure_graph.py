#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic exposure graph.

The exposure graph is the enterprise visibility layer for the secure
context thesis. It joins workflows, context sources, MCP namespaces,
non-human identities, authorization decisions, egress boundaries,
readiness, capability risk, and run receipts into risk-ranked paths that
buyers and platform teams can inspect before expanding agentic AI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


PACK_SCHEMA_VERSION = "1.0"
DEFAULT_PROFILE = Path("data/assurance/agentic-exposure-graph-profile.json")
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_GATEWAY_POLICY = Path("data/policy/mcp-gateway-policy.json")
DEFAULT_CONTEXT_TRUST_PACK = Path("data/evidence/secure-context-trust-pack.json")
DEFAULT_AUTHORIZATION_PACK = Path("data/evidence/mcp-authorization-conformance-pack.json")
DEFAULT_CONNECTOR_TRUST_PACK = Path("data/evidence/mcp-connector-trust-pack.json")
DEFAULT_IDENTITY_LEDGER = Path("data/evidence/agent-identity-delegation-ledger.json")
DEFAULT_EGRESS_BOUNDARY_PACK = Path("data/evidence/context-egress-boundary-pack.json")
DEFAULT_READINESS_SCORECARD = Path("data/evidence/agentic-readiness-scorecard.json")
DEFAULT_CAPABILITY_RISK_REGISTER = Path("data/evidence/agent-capability-risk-register.json")
DEFAULT_RUN_RECEIPT_PACK = Path("data/evidence/agentic-run-receipt-pack.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-exposure-graph.json")

REQUIRED_SOURCE_PACKS = {
    "agent_capability_risk_register",
    "agent_identity_ledger",
    "agentic_readiness_scorecard",
    "agentic_run_receipt_pack",
    "context_egress_boundary_pack",
    "gateway_policy",
    "mcp_authorization_conformance",
    "mcp_connector_trust_pack",
    "secure_context_trust_pack",
    "workflow_manifest",
}
REQUIRED_PATH_CLASSES = {
    "approval_required_tool_path",
    "context_to_read_tool",
    "context_to_write_tool",
    "high_impact_authority_path",
    "tenant_sensitive_context_path",
}
WRITE_ACCESS_MODES = {"approval_required", "write", "write_branch", "write_ticket"}
APPROVAL_ACCESS_MODES = {"approval_required"}
HIGH_IMPACT_HINTS = {
    "chain",
    "deploy",
    "funds",
    "governance",
    "identity",
    "payment",
    "production",
    "quarantine",
    "registry",
    "signer",
    "wallet",
}


class ExposureGraphError(RuntimeError):
    """Raised when the exposure graph cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ExposureGraphError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ExposureGraphError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ExposureGraphError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ExposureGraphError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ExposureGraphError(f"{label} must be a list")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def normalize_path(path: Path) -> str:
    return path.as_posix()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


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


def rows_by_workflow(pack: dict[str, Any], field: str, label: str) -> dict[str, dict[str, Any]]:
    return index_by(as_list(pack.get(field), f"{label}.{field}"), "workflow_id", label)


def source_failures(payloads: dict[str, dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for label, payload in payloads.items():
        rows = payload.get("failures")
        if isinstance(rows, list):
            failures.extend([f"{label}: {item}" for item in rows])
    return failures


def validate_profile(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 100, failures, "profile intent must explain the product goal")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 7, failures, "standards_alignment must include current agentic AI, MCP, and identity references")
    standard_ids: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in standard_ids, failures, f"{standard_id}: duplicate standard id")
        standard_ids.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 50, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(profile.get("graph_contract"), "graph_contract")
    require(
        contract.get("default_state") == "untrusted_until_exposure_path_is_graph_bound_and_policy_checked",
        failures,
        "graph_contract.default_state must fail closed",
    )
    required_sources = {str(item) for item in as_list(contract.get("required_source_packs"), "graph_contract.required_source_packs")}
    missing_sources = sorted(REQUIRED_SOURCE_PACKS - required_sources)
    require(not missing_sources, failures, f"graph_contract missing source packs: {missing_sources}")
    require(
        len(as_list(contract.get("required_runtime_fields"), "graph_contract.required_runtime_fields"))
        >= int(contract.get("minimum_runtime_fields") or 0),
        failures,
        "graph_contract runtime fields below minimum",
    )
    require(
        len(as_list(contract.get("risk_score_thresholds"), "graph_contract.risk_score_thresholds")) >= 4,
        failures,
        "graph_contract must include risk score thresholds",
    )

    classes = as_list(profile.get("path_classes"), "path_classes")
    class_ids = {str(as_dict(row, "path_class").get("id")) for row in classes}
    require(REQUIRED_PATH_CLASSES.issubset(class_ids), failures, "profile must define all required path classes")
    require(
        len(classes) >= int(contract.get("minimum_path_classes") or 0),
        failures,
        "path_classes below graph minimum",
    )
    for path_class in classes:
        item = as_dict(path_class, "path_class")
        class_id = str(item.get("id", "")).strip()
        require(len(str(item.get("question", ""))) >= 40, failures, f"{class_id}: question must be specific")
        require(len(as_list(item.get("risk_drivers"), f"{class_id}.risk_drivers")) >= 3, failures, f"{class_id}: risk_drivers are required")
    return failures


def validate_sources(source_payloads: dict[str, dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    require(source_payloads["workflow_manifest"].get("schema_version") == "1.0", failures, "workflow manifest schema_version must be 1.0")
    for key, payload in source_payloads.items():
        if key == "workflow_manifest":
            continue
        require(payload.get("schema_version") == "1.0", failures, f"{key} schema_version must be 1.0")
    failures.extend(source_failures(source_payloads))

    workflows = set(workflow_by_id(source_payloads["workflow_manifest"]))
    workflow_sources = {
        "gateway_policy": set(rows_by_workflow(source_payloads["gateway_policy"], "workflow_policies", "gateway_policy")),
        "secure_context_trust_pack": set(rows_by_workflow(source_payloads["secure_context_trust_pack"], "workflow_context_map", "context_trust")),
        "mcp_authorization_conformance": set(rows_by_workflow(source_payloads["mcp_authorization_conformance"], "workflow_authorization_map", "authorization")),
        "context_egress_boundary_pack": set(rows_by_workflow(source_payloads["context_egress_boundary_pack"], "workflow_egress_map", "egress")),
        "agentic_readiness_scorecard": set(rows_by_workflow(source_payloads["agentic_readiness_scorecard"], "workflow_readiness", "readiness")),
        "agent_capability_risk_register": set(rows_by_workflow(source_payloads["agent_capability_risk_register"], "workflow_capability_risks", "capability_risk")),
        "agentic_run_receipt_pack": set(rows_by_workflow(source_payloads["agentic_run_receipt_pack"], "workflow_receipt_templates", "run_receipts")),
    }
    for label, source_workflows in workflow_sources.items():
        require(workflows == source_workflows, failures, f"{label} workflows must match workflow manifest")
    return failures


def workflow_by_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return index_by(as_list(manifest.get("workflows"), "manifest.workflows"), "id", "workflow")


def connector_by_namespace(connector_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return index_by(as_list(connector_pack.get("connectors"), "connector_pack.connectors"), "namespace", "connector")


def identity_by_workflow(identity_ledger: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    output: dict[str, list[dict[str, Any]]] = {}
    for identity in as_list(identity_ledger.get("agent_identities"), "identity_ledger.agent_identities"):
        item = as_dict(identity, "identity")
        workflow_id = str(item.get("workflow_id", "")).strip()
        if workflow_id:
            output.setdefault(workflow_id, []).append(item)
    return output


def namespace_scope_by_identity(identity: dict[str, Any]) -> dict[str, dict[str, Any]]:
    delegated = identity.get("delegated_authority") if isinstance(identity.get("delegated_authority"), dict) else {}
    scopes = delegated.get("mcp_scopes") if isinstance(delegated, dict) else []
    return {
        str(scope.get("namespace")): scope
        for scope in scopes
        if isinstance(scope, dict) and scope.get("namespace")
    }


def source_artifacts(paths: dict[str, Path], refs: dict[str, Path]) -> dict[str, dict[str, str]]:
    return {
        key: {
            "path": normalize_path(refs[key]),
            "sha256": sha256_file(paths[key]),
        }
        for key in sorted(paths)
    }


def workflow_node(workflow: dict[str, Any], readiness: dict[str, Any] | None, risk: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "id": f"workflow::{workflow.get('id')}",
        "label": workflow.get("title"),
        "node_type": "workflow",
        "properties": {
            "maturity_stage": workflow.get("maturity_stage"),
            "owner": workflow.get("owner"),
            "public_path": workflow.get("public_path"),
            "readiness_decision": readiness.get("decision") if readiness else None,
            "readiness_score": readiness.get("score") if readiness else None,
            "residual_risk_score": risk.get("residual_risk_score") if risk else None,
            "risk_tier": risk.get("risk_tier") if risk else None,
            "status": workflow.get("status"),
            "workflow_id": workflow.get("id"),
        },
    }


def identity_node(identity: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"identity::{identity.get('identity_id')}",
        "label": identity.get("identity_id"),
        "node_type": "agent_identity",
        "properties": {
            "agent_class": identity.get("agent_class"),
            "delegated_by": identity.get("delegation_model", {}).get("delegated_by") if isinstance(identity.get("delegation_model"), dict) else None,
            "risk_tier": identity.get("risk_tier"),
            "workflow_id": identity.get("workflow_id"),
        },
    }


def namespace_node(namespace: str, connector: dict[str, Any] | None) -> dict[str, Any]:
    connector = connector or {}
    return {
        "id": f"mcp_namespace::{namespace}",
        "label": connector.get("title") or namespace,
        "node_type": "mcp_namespace",
        "properties": {
            "access_modes": connector.get("access_modes", []),
            "connector_id": connector.get("connector_id"),
            "deployment_model": connector.get("deployment_model"),
            "namespace": namespace,
            "status": connector.get("status"),
            "transport": connector.get("transport"),
            "trust_tier": connector.get("trust_tier", {}),
        },
    }


def context_node(source: dict[str, Any]) -> dict[str, Any]:
    source_id = source.get("source_id") or source.get("id")
    return {
        "id": f"context_source::{source_id}",
        "label": source.get("title"),
        "node_type": "context_source",
        "properties": {
            "exposure": source.get("exposure"),
            "kind": source.get("kind"),
            "root": source.get("root"),
            "trust_tier": source.get("trust_tier"),
        },
    }


def evidence_node(pack_id: str, artifact: dict[str, str]) -> dict[str, Any]:
    return {
        "id": f"evidence_pack::{pack_id}",
        "label": pack_id.replace("_", " ").title(),
        "node_type": "evidence_pack",
        "properties": artifact,
    }


def edge(edge_id: str, source: str, target: str, edge_type: str, properties: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "edge_type": edge_type,
        "id": edge_id,
        "properties": properties or {},
        "source": source,
        "target": target,
    }


def access_weight(access: str) -> int:
    return {
        "read": 4,
        "write_branch": 14,
        "write_ticket": 16,
        "write": 18,
        "approval_required": 22,
    }.get(access, 8)


def connector_weight(connector: dict[str, Any] | None) -> int:
    if not connector:
        return 18
    status = str(connector.get("status", "")).lower()
    if status == "production":
        return 0
    if status == "pilot":
        return 10
    return 16


def maturity_weight(maturity: str | None) -> int:
    return {"crawl": 6, "walk": 2, "run": 0}.get(str(maturity or "").lower(), 5)


def readiness_credit(readiness: dict[str, Any] | None) -> int:
    if not readiness:
        return 0
    decision = str(readiness.get("decision", ""))
    if decision == "scale_ready":
        return 10
    if decision == "pilot_guarded":
        return 6
    return 0


def egress_weight(namespace: str, egress_row: dict[str, Any] | None) -> tuple[int, dict[str, Any] | None]:
    if not egress_row:
        return 10, None
    for policy in egress_row.get("namespace_policies", []) or []:
        if not isinstance(policy, dict) or str(policy.get("namespace")) != namespace:
            continue
        weight = 0
        if policy.get("tenant_id_required"):
            weight += 5
        if policy.get("human_approval_required"):
            weight += 8
        if str(policy.get("sensitivity")) == "tenant_sensitive":
            weight += 4
        return weight, policy
    return 6, None


def path_class(access: str, namespace: str, risk: dict[str, Any] | None, egress_policy: dict[str, Any] | None) -> str:
    haystack = f"{namespace} {risk.get('title') if risk else ''}".lower()
    if access in APPROVAL_ACCESS_MODES:
        return "approval_required_tool_path"
    if risk and str(risk.get("risk_tier")) == "high" and any(hint in haystack for hint in HIGH_IMPACT_HINTS):
        return "high_impact_authority_path"
    if egress_policy and str(egress_policy.get("sensitivity")) == "tenant_sensitive":
        return "tenant_sensitive_context_path"
    if access in WRITE_ACCESS_MODES:
        return "context_to_write_tool"
    return "context_to_read_tool"


def path_decision(score: int, access: str, connector: dict[str, Any] | None, risk: dict[str, Any] | None) -> str:
    if access in APPROVAL_ACCESS_MODES:
        return "architecture_review"
    if risk and str(risk.get("risk_tier")) == "high" and score >= 60:
        return "architecture_review"
    if score >= 70:
        return "architecture_review"
    if score >= 55 or (connector and str(connector.get("status")) == "pilot"):
        return "hold_for_owner_review"
    if score >= 35:
        return "guarded_rollout"
    return "standard_monitoring"


def exposure_path(
    *,
    workflow: dict[str, Any],
    identity: dict[str, Any],
    scope: dict[str, Any],
    context_row: dict[str, Any] | None,
    auth_row: dict[str, Any] | None,
    connector: dict[str, Any] | None,
    egress_row: dict[str, Any] | None,
    readiness: dict[str, Any] | None,
    risk: dict[str, Any] | None,
    receipt: dict[str, Any] | None,
) -> dict[str, Any]:
    workflow_id = str(workflow.get("id"))
    namespace = str(scope.get("namespace"))
    access = str(scope.get("access") or "read")
    egress_add, egress_policy = egress_weight(namespace, egress_row)
    raw_risk_score = int(risk.get("residual_risk_score") or 0) if risk else 20
    score = max(
        0,
        min(
            100,
            raw_risk_score
            + access_weight(access)
            + connector_weight(connector)
            + maturity_weight(workflow.get("maturity_stage"))
            + egress_add
            - readiness_credit(readiness),
        ),
    )
    path_class_id = path_class(access, namespace, risk, egress_policy)
    decision = path_decision(score, access, connector, risk)
    auth_namespaces = {
        str(item.get("namespace")): item
        for item in (auth_row.get("namespaces", []) if auth_row else [])
        if isinstance(item, dict) and item.get("namespace")
    }
    auth_scope = auth_namespaces.get(namespace, {})

    return {
        "access": access,
        "agent_class": identity.get("agent_class"),
        "authorization_decision": auth_scope.get("authorization_decision"),
        "connector_id": connector.get("connector_id") if connector else None,
        "connector_status": connector.get("status") if connector else "missing",
        "context_package_hash": context_row.get("context_package_hash") if context_row else None,
        "context_source_ids": context_row.get("source_ids", []) if context_row else [],
        "decision": decision,
        "egress_policy_hash": egress_row.get("egress_policy_hash") if egress_row else None,
        "egress_sensitivity": egress_policy.get("sensitivity") if egress_policy else None,
        "identity_id": identity.get("identity_id"),
        "maturity_stage": workflow.get("maturity_stage"),
        "mcp_namespace": namespace,
        "path_class_id": path_class_id,
        "path_id": f"exposure::{workflow_id}::{identity.get('agent_class')}::{namespace}",
        "receipt_id": receipt.get("receipt_id") if receipt else None,
        "readiness_decision": readiness.get("decision") if readiness else None,
        "readiness_score": readiness.get("score") if readiness else None,
        "risk_tier": risk.get("risk_tier") if risk else None,
        "score": score,
        "source_artifact_refs": [
            "data/control-plane/workflow-manifests.json",
            "data/policy/mcp-gateway-policy.json",
            "data/evidence/secure-context-trust-pack.json",
            "data/evidence/mcp-authorization-conformance-pack.json",
            "data/evidence/mcp-connector-trust-pack.json",
            "data/evidence/agent-identity-delegation-ledger.json",
            "data/evidence/context-egress-boundary-pack.json",
            "data/evidence/agent-capability-risk-register.json",
            "data/evidence/agentic-run-receipt-pack.json",
        ],
        "title": f"{identity.get('agent_class')} -> {namespace}",
        "workflow_id": workflow_id,
        "workflow_title": workflow.get("title"),
    }


def build_graph(
    *,
    source_payloads: dict[str, dict[str, Any]],
    source_paths: dict[str, Path],
    source_refs: dict[str, Path],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    manifest = source_payloads["workflow_manifest"]
    connectors = connector_by_namespace(source_payloads["mcp_connector_trust_pack"])
    workflows = workflow_by_id(manifest)
    identities = identity_by_workflow(source_payloads["agent_identity_ledger"])
    policies = rows_by_workflow(source_payloads["gateway_policy"], "workflow_policies", "gateway_policy")
    context_rows = rows_by_workflow(source_payloads["secure_context_trust_pack"], "workflow_context_map", "context_trust")
    auth_rows = rows_by_workflow(source_payloads["mcp_authorization_conformance"], "workflow_authorization_map", "authorization")
    egress_rows = rows_by_workflow(source_payloads["context_egress_boundary_pack"], "workflow_egress_map", "egress")
    readiness_rows = rows_by_workflow(source_payloads["agentic_readiness_scorecard"], "workflow_readiness", "readiness")
    risk_rows = rows_by_workflow(source_payloads["agent_capability_risk_register"], "workflow_capability_risks", "risk")
    receipt_rows = rows_by_workflow(source_payloads["agentic_run_receipt_pack"], "workflow_receipt_templates", "receipt")

    nodes_by_id: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    exposure_paths: list[dict[str, Any]] = []

    for workflow_id, workflow in workflows.items():
        nodes_by_id[f"workflow::{workflow_id}"] = workflow_node(workflow, readiness_rows.get(workflow_id), risk_rows.get(workflow_id))
        for identity in identities.get(workflow_id, []):
            identity_id = str(identity.get("identity_id"))
            nodes_by_id[f"identity::{identity_id}"] = identity_node(identity)
            edges.append(
                edge(
                    f"edge::{workflow_id}::{identity_id}",
                    f"workflow::{workflow_id}",
                    f"identity::{identity_id}",
                    "uses_identity",
                    {"agent_class": identity.get("agent_class")},
                )
            )

        context_row = context_rows.get(workflow_id, {})
        for source_id in context_row.get("source_ids", []) or []:
            edges.append(
                edge(
                    f"edge::{workflow_id}::context::{source_id}",
                    f"workflow::{workflow_id}",
                    f"context_source::{source_id}",
                    "retrieves_context",
                    {"context_package_hash": context_row.get("context_package_hash")},
                )
            )

        for namespace in {str(scope.get("namespace")) for scope in policies.get(workflow_id, {}).get("tool_access", {}).get("allowed_mcp_scopes", []) if isinstance(scope, dict) and scope.get("namespace")}:
            nodes_by_id[f"mcp_namespace::{namespace}"] = namespace_node(namespace, connectors.get(namespace))
            edges.append(
                edge(
                    f"edge::{workflow_id}::namespace::{namespace}",
                    f"workflow::{workflow_id}",
                    f"mcp_namespace::{namespace}",
                    "requests_mcp_namespace",
                    {"authorization_policy_hash": auth_rows.get(workflow_id, {}).get("authorization_policy_hash")},
                )
            )

        for identity in identities.get(workflow_id, []):
            for namespace, scope in namespace_scope_by_identity(identity).items():
                nodes_by_id[f"mcp_namespace::{namespace}"] = namespace_node(namespace, connectors.get(namespace))
                edges.append(
                    edge(
                        f"edge::{identity.get('identity_id')}::scope::{namespace}",
                        f"identity::{identity.get('identity_id')}",
                        f"mcp_namespace::{namespace}",
                        "delegates_mcp_scope",
                        {"access": scope.get("access"), "decision": scope.get("decision")},
                    )
                )
                exposure_paths.append(
                    exposure_path(
                        workflow=workflow,
                        identity=identity,
                        scope=scope,
                        context_row=context_rows.get(workflow_id),
                        auth_row=auth_rows.get(workflow_id),
                        connector=connectors.get(namespace),
                        egress_row=egress_rows.get(workflow_id),
                        readiness=readiness_rows.get(workflow_id),
                        risk=risk_rows.get(workflow_id),
                        receipt=receipt_rows.get(workflow_id),
                    )
                )

        for pack_id, artifact in source_artifacts(source_paths, source_refs).items():
            if pack_id == "profile":
                continue
            edges.append(
                edge(
                    f"edge::{workflow_id}::evidence::{pack_id}",
                    f"workflow::{workflow_id}",
                    f"evidence_pack::{pack_id}",
                    "requires_evidence_pack",
                    {"path": artifact.get("path"), "sha256": artifact.get("sha256")},
                )
            )

    for source in as_list(source_payloads["secure_context_trust_pack"].get("context_sources"), "context_sources"):
        item = as_dict(source, "context_source")
        source_id = item.get("source_id") or item.get("id")
        nodes_by_id[f"context_source::{source_id}"] = context_node(item)

    artifacts = source_artifacts(source_paths, source_refs)
    for pack_id, artifact in artifacts.items():
        if pack_id != "profile":
            nodes_by_id[f"evidence_pack::{pack_id}"] = evidence_node(pack_id, artifact)

    nodes = sorted(nodes_by_id.values(), key=lambda row: str(row.get("id")))
    edges = sorted(edges, key=lambda row: str(row.get("id")))
    exposure_paths = sorted(exposure_paths, key=lambda row: (-int(row.get("score") or 0), str(row.get("path_id"))))
    return nodes, edges, exposure_paths


def graph_summary(nodes: list[dict[str, Any]], edges: list[dict[str, Any]], paths: list[dict[str, Any]], failures: list[str]) -> dict[str, Any]:
    node_counts = Counter(str(node.get("node_type")) for node in nodes)
    edge_counts = Counter(str(item.get("edge_type")) for item in edges)
    decision_counts = Counter(str(path.get("decision")) for path in paths)
    class_counts = Counter(str(path.get("path_class_id")) for path in paths)
    high_paths = [
        {
            "access": path.get("access"),
            "agent_class": path.get("agent_class"),
            "decision": path.get("decision"),
            "identity_id": path.get("identity_id"),
            "mcp_namespace": path.get("mcp_namespace"),
            "path_class_id": path.get("path_class_id"),
            "path_id": path.get("path_id"),
            "risk_tier": path.get("risk_tier"),
            "score": path.get("score"),
            "workflow_id": path.get("workflow_id"),
            "workflow_title": path.get("workflow_title"),
        }
        for path in paths[:8]
    ]
    return {
        "decision_counts": dict(sorted(decision_counts.items())),
        "distinct_agent_identity_count": node_counts.get("agent_identity", 0),
        "distinct_context_source_count": node_counts.get("context_source", 0),
        "distinct_mcp_namespace_count": node_counts.get("mcp_namespace", 0),
        "edge_counts": dict(sorted(edge_counts.items())),
        "failure_count": len(failures),
        "highest_exposure_paths": high_paths,
        "node_counts": dict(sorted(node_counts.items())),
        "path_class_counts": dict(sorted(class_counts.items())),
        "total_edge_count": len(edges),
        "total_node_count": len(nodes),
        "total_path_count": len(paths),
        "workflow_count": node_counts.get("workflow", 0),
    }


def build_pack(
    *,
    profile: dict[str, Any],
    source_payloads: dict[str, dict[str, Any]],
    source_paths: dict[str, Path],
    source_refs: dict[str, Path],
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    nodes, edges, paths = build_graph(
        source_payloads=source_payloads,
        source_paths=source_paths,
        source_refs=source_refs,
    )
    return {
        "commercialization_path": profile.get("commercialization_path", {}),
        "edges": edges,
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "exposure_graph_summary": graph_summary(nodes, edges, paths, failures),
        "exposure_paths": paths,
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "graph_contract": profile.get("graph_contract", {}),
        "intent": profile.get("intent"),
        "nodes": nodes,
        "path_classes": profile.get("path_classes", []),
        "positioning": profile.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "The graph proves source-controlled reference exposure, not live customer runtime behavior.",
                "treatment": "Bind hosted deployments to MCP gateway logs, IAM issuance events, approval records, source-host reviews, tenant context registries, and sealed run receipts."
            },
            {
                "risk": "Risk scores can become stale after model, prompt, connector, workflow, identity, policy, or context drift.",
                "treatment": "Regenerate the graph in CI and run hosted path-diff alerts after every control-plane, context, connector, or evidence-pack change."
            },
            {
                "risk": "A graph-visible path can still fail if the enforcing runtime ignores policy or allows token passthrough.",
                "treatment": "Treat graph output as a diligence and review surface; require MCP gateway, OAuth audience binding, short-lived identity, and egress enforcement at runtime."
            }
        ],
        "schema_version": PACK_SCHEMA_VERSION,
        "selected_feature": {
            "id": "agentic-exposure-graph",
            "implementation": [
                "Exposure graph source profile under data/assurance.",
                "Deterministic generator under scripts.",
                "Generated graph evidence under data/evidence.",
                "Human-readable docs page under security-remediation.",
                "MCP exposure through recipes_agentic_exposure_graph.",
                "CI refresh and validation before the Hugo build."
            ],
            "reason": "Agentic security is becoming an exposure-management problem: enterprises need to see how context, identities, MCP tools, authorization, egress, and evidence combine into action paths."
        },
        "source_artifacts": source_artifacts(source_paths, source_refs),
        "standards_alignment": profile.get("standards_alignment", []),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--gateway-policy", type=Path, default=DEFAULT_GATEWAY_POLICY)
    parser.add_argument("--context-trust-pack", type=Path, default=DEFAULT_CONTEXT_TRUST_PACK)
    parser.add_argument("--authorization-pack", type=Path, default=DEFAULT_AUTHORIZATION_PACK)
    parser.add_argument("--connector-trust-pack", type=Path, default=DEFAULT_CONNECTOR_TRUST_PACK)
    parser.add_argument("--identity-ledger", type=Path, default=DEFAULT_IDENTITY_LEDGER)
    parser.add_argument("--egress-boundary-pack", type=Path, default=DEFAULT_EGRESS_BOUNDARY_PACK)
    parser.add_argument("--readiness-scorecard", type=Path, default=DEFAULT_READINESS_SCORECARD)
    parser.add_argument("--capability-risk-register", type=Path, default=DEFAULT_CAPABILITY_RISK_REGISTER)
    parser.add_argument("--run-receipt-pack", type=Path, default=DEFAULT_RUN_RECEIPT_PACK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in exposure graph is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    refs = {
        "agent_capability_risk_register": args.capability_risk_register,
        "agent_identity_ledger": args.identity_ledger,
        "agentic_readiness_scorecard": args.readiness_scorecard,
        "agentic_run_receipt_pack": args.run_receipt_pack,
        "context_egress_boundary_pack": args.egress_boundary_pack,
        "gateway_policy": args.gateway_policy,
        "mcp_authorization_conformance": args.authorization_pack,
        "mcp_connector_trust_pack": args.connector_trust_pack,
        "profile": args.profile,
        "secure_context_trust_pack": args.context_trust_pack,
        "workflow_manifest": args.manifest,
    }
    paths = {key: resolve(repo_root, path) for key, path in refs.items()}
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(paths["profile"])
        source_payloads = {
            key: load_json(path)
            for key, path in paths.items()
            if key != "profile"
        }
        failures = validate_profile(profile)
        failures.extend(validate_sources(source_payloads))
        pack = build_pack(
            profile=profile,
            source_payloads=source_payloads,
            source_paths=paths,
            source_refs=refs,
            generated_at=args.generated_at,
            failures=failures,
        )
    except ExposureGraphError as exc:
        print(f"agentic exposure graph generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if failures:
            print("agentic exposure graph validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run this script without --check", file=sys.stderr)
            return 1
        if current_text != rendered:
            print(f"{output_path} is stale; run scripts/generate_agentic_exposure_graph.py", file=sys.stderr)
            return 1
        print(f"Validated agentic exposure graph: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if failures:
        print("Generated agentic exposure graph with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated agentic exposure graph: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
