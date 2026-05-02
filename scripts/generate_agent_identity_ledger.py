#!/usr/bin/env python3
"""Generate the SecurityRecipes agent identity and delegation ledger.

The workflow manifest says which work is approved. The MCP gateway
policy says which tools and paths are allowed. This ledger translates
those controls into the non-human identity view an enterprise IAM,
AI-platform, or audit team will ask for: which agent identity may act,
on whose authority, through which MCP namespaces, with which human
review and runtime kill controls.

The output is deterministic by default so CI can run with --check and
fail when the checked-in ledger drifts from source controls.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


LEDGER_SCHEMA_VERSION = "1.0"
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_POLICY = Path("data/policy/mcp-gateway-policy.json")
DEFAULT_REPORT = Path("data/evidence/workflow-control-plane-report.json")
DEFAULT_OUTPUT = Path("data/evidence/agent-identity-delegation-ledger.json")

WORKFLOW_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]+$")

ACCESS_ACTIONS = {
    "approval_required": "stage_approval_required_action",
    "read": "read_context",
    "write_branch": "write_remediation_branch",
    "write_ticket": "write_triage_ticket",
}

EXPLICIT_DENIED_ACTIONS = [
    "access_signing_material",
    "change_ci_or_deployment_configuration",
    "delegate_to_unapproved_agent",
    "deploy_or_release",
    "merge_pull_request",
    "modify_agent_policy_without_manual_review",
    "persist_memory_outside_run",
    "publish_package_or_image",
    "push_to_default_branch",
    "read_secret_store",
]

REQUIRED_RUNTIME_ATTRIBUTES = {
    "agent_id",
    "branch_name",
    "changed_paths",
    "diff_line_count",
    "gate_phase",
    "run_id",
    "tool_access_mode",
    "tool_namespace",
    "workflow_id",
}


class LedgerGenerationError(RuntimeError):
    """Raised when the identity ledger cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise LedgerGenerationError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise LedgerGenerationError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise LedgerGenerationError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise LedgerGenerationError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LedgerGenerationError(f"{label} must be an object")
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


def workflow_by_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    workflows = as_list(manifest.get("workflows"), "manifest.workflows")
    output: dict[str, dict[str, Any]] = {}
    for workflow in workflows:
        item = as_dict(workflow, "manifest.workflow")
        workflow_id = str(item.get("id", "")).strip()
        if workflow_id:
            output[workflow_id] = item
    return output


def policy_by_workflow_id(policy_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    policies = as_list(policy_pack.get("workflow_policies"), "policy_pack.workflow_policies")
    output: dict[str, dict[str, Any]] = {}
    for policy in policies:
        item = as_dict(policy, "policy_pack.workflow_policy")
        workflow_id = str(item.get("workflow_id", "")).strip()
        if workflow_id:
            output[workflow_id] = item
    return output


def validate_source_contract(
    *,
    manifest: dict[str, Any],
    policy_pack: dict[str, Any],
    report: dict[str, Any],
    manifest_path: Path,
) -> list[str]:
    failures: list[str] = []

    require(manifest.get("schema_version") == "1.0", failures, "manifest schema_version must be 1.0")
    require(policy_pack.get("schema_version") == "1.0", failures, "policy pack schema_version must be 1.0")
    require(report.get("failure_count") == 0, failures, "control-plane report must have zero failures")

    defaults = as_dict(manifest.get("workflow_defaults"), "manifest.workflow_defaults")
    require(defaults.get("human_review_required") is True, failures, "workflow defaults must require human review")
    require(str(defaults.get("branch_prefix", "")).strip(), failures, "workflow defaults need branch_prefix")
    require(str(defaults.get("required_pr_label", "")).strip(), failures, "workflow defaults need required_pr_label")

    decision_contract = as_dict(policy_pack.get("decision_contract"), "policy_pack.decision_contract")
    require(decision_contract.get("default_decision") == "deny", failures, "gateway policy must default to deny")
    runtime_attributes = set(as_list(decision_contract.get("required_runtime_attributes"), "decision_contract.required_runtime_attributes"))
    missing_runtime = sorted(REQUIRED_RUNTIME_ATTRIBUTES - {str(item) for item in runtime_attributes})
    require(not missing_runtime, failures, f"gateway policy missing runtime attributes: {missing_runtime}")

    policy_source = as_dict(policy_pack.get("source_manifest"), "policy_pack.source_manifest")
    require(
        policy_source.get("sha256") == sha256_file(manifest_path),
        failures,
        "gateway policy source_manifest.sha256 does not match workflow manifest",
    )

    workflows = workflow_by_id(manifest)
    policies = policy_by_workflow_id(policy_pack)
    require(set(workflows) == set(policies), failures, "policy workflow IDs must match manifest workflow IDs")

    for workflow_id, workflow in workflows.items():
        require(bool(WORKFLOW_ID_RE.match(workflow_id)), failures, f"{workflow_id}: id must be kebab-case")
        policy = policies.get(workflow_id, {})
        require(policy.get("default_decision") == "deny", failures, f"{workflow_id}: default decision must be deny")

        owner = as_dict(workflow.get("owner"), f"{workflow_id}: owner")
        reviewer_pools = as_list(owner.get("reviewer_pools"), f"{workflow_id}: owner.reviewer_pools")
        require(bool(owner.get("accountable_team")), failures, f"{workflow_id}: accountable team is required")
        require(bool(reviewer_pools), failures, f"{workflow_id}: reviewer pools are required")

        default_agents = [str(agent) for agent in as_list(workflow.get("default_agents"), f"{workflow_id}: default_agents")]
        policy_identity = as_dict(policy.get("identity"), f"{workflow_id}: policy.identity")
        require(
            sorted(default_agents) == sorted([str(agent) for agent in policy_identity.get("allowed_agents", [])]),
            failures,
            f"{workflow_id}: policy identity allowed_agents must match manifest default_agents",
        )

        context = as_list(workflow.get("mcp_context"), f"{workflow_id}: mcp_context")
        workflow_namespaces = {str(item.get("namespace")) for item in context if isinstance(item, dict)}
        require("*" not in "".join(sorted(workflow_namespaces)), failures, f"{workflow_id}: namespaces must not use wildcards")

        tool_access = as_dict(policy.get("tool_access"), f"{workflow_id}: policy.tool_access")
        scopes = as_list(tool_access.get("allowed_mcp_scopes"), f"{workflow_id}: allowed_mcp_scopes")
        policy_namespaces = {str(scope.get("namespace")) for scope in scopes if isinstance(scope, dict)}
        require(policy_namespaces == workflow_namespaces, failures, f"{workflow_id}: policy namespaces must match manifest")
        require(tool_access.get("denied_by_default") is True, failures, f"{workflow_id}: tool access must be denied by default")

        scope = as_dict(workflow.get("scope"), f"{workflow_id}: scope")
        require(bool(scope.get("allowed_paths")), failures, f"{workflow_id}: allowed_paths are required")
        require(bool(scope.get("forbidden_paths")), failures, f"{workflow_id}: forbidden_paths are required")

        evidence = as_list(workflow.get("evidence"), f"{workflow_id}: evidence")
        require(len(evidence) >= 3, failures, f"{workflow_id}: at least three evidence records are required")
        require(bool(workflow.get("kill_signals")), failures, f"{workflow_id}: kill signals are required")

        if any(str(scope_item.get("access")) == "write_branch" for scope_item in scopes if isinstance(scope_item, dict)):
            dispatch = as_dict(policy.get("dispatch"), f"{workflow_id}: policy.dispatch")
            require(str(dispatch.get("required_branch_prefix", "")).strip(), failures, f"{workflow_id}: branch writes need a prefix")
            require(str(dispatch.get("required_pr_label", "")).strip(), failures, f"{workflow_id}: branch writes need a PR label")

        approval_namespaces = [
            str(scope_item.get("namespace"))
            for scope_item in scopes
            if isinstance(scope_item, dict) and scope_item.get("decision") == "hold_for_approval"
        ]
        if approval_namespaces:
            require(bool(reviewer_pools), failures, f"{workflow_id}: approval-required namespaces need reviewer pools")
            require(
                sorted(approval_namespaces) == sorted([str(item) for item in tool_access.get("requires_human_approval_for", [])]),
                failures,
                f"{workflow_id}: approval-required namespace list is stale",
            )

    return failures


def identity_id(workflow_id: str, agent_class: str) -> str:
    return f"sr-agent::{workflow_id}::{agent_class}"


def risk_tier(workflow: dict[str, Any], policy: dict[str, Any]) -> str:
    maturity = str(workflow.get("maturity_stage", ""))
    scopes = as_list(
        as_dict(policy.get("tool_access"), f"{workflow.get('id')}: policy.tool_access").get("allowed_mcp_scopes"),
        f"{workflow.get('id')}: allowed_mcp_scopes",
    )
    has_approval_required = any(
        isinstance(scope, dict) and scope.get("decision") == "hold_for_approval"
        for scope in scopes
    )
    kill_text = " ".join([str(item).lower() for item in workflow.get("kill_signals", [])])
    if has_approval_required or "signer" in kill_text or "multisig" in kill_text or "wallet" in kill_text:
        return "high-control"
    if maturity == "crawl":
        return "elevated"
    return "standard"


def build_repository_scope(policy: dict[str, Any]) -> dict[str, Any]:
    change_scope = as_dict(policy.get("change_scope"), f"{policy.get('workflow_id')}: change_scope")
    dispatch = as_dict(policy.get("dispatch"), f"{policy.get('workflow_id')}: dispatch")
    return {
        "allowed_paths": change_scope.get("allowed_paths", []),
        "branch_prefix": dispatch.get("required_branch_prefix"),
        "forbidden_paths": change_scope.get("forbidden_paths", []),
        "max_changed_files": change_scope.get("max_changed_files"),
        "max_diff_lines": change_scope.get("max_diff_lines"),
        "required_pr_label": dispatch.get("required_pr_label"),
    }


def build_identity_record(
    *,
    agent_class: str,
    workflow: dict[str, Any],
    policy: dict[str, Any],
    defaults: dict[str, Any],
    runtime_attributes: list[str],
) -> dict[str, Any]:
    workflow_id = str(workflow.get("id"))
    owner = as_dict(workflow.get("owner"), f"{workflow_id}: owner")
    tool_access = as_dict(policy.get("tool_access"), f"{workflow_id}: policy.tool_access")
    scopes = [
        {
            "access": scope.get("access"),
            "decision": scope.get("decision"),
            "namespace": scope.get("namespace"),
            "purpose": scope.get("purpose"),
            "scope_id": scope.get("scope_id"),
        }
        for scope in as_list(tool_access.get("allowed_mcp_scopes"), f"{workflow_id}: allowed_mcp_scopes")
        if isinstance(scope, dict)
    ]
    actions = sorted({ACCESS_ACTIONS.get(str(scope.get("access")), str(scope.get("access"))) for scope in scopes})
    approval_namespaces = [
        str(scope.get("namespace"))
        for scope in scopes
        if scope.get("decision") == "hold_for_approval"
    ]

    return {
        "agent_class": agent_class,
        "delegated_authority": {
            "actions": actions,
            "approval_required_namespaces": approval_namespaces,
            "eligible_findings": workflow.get("eligible_findings", []),
            "mcp_scopes": scopes,
            "repository_scope": build_repository_scope(policy),
        },
        "delegation_model": {
            "accountable_team": owner.get("accountable_team"),
            "acts_for": "security-remediation-orchestrator",
            "delegated_by": owner.get("accountable_team"),
            "escalation": owner.get("escalation"),
            "human_review_required": defaults.get("human_review_required", True),
            "reviewer_pools": owner.get("reviewer_pools", []),
        },
        "evidence_contract": policy.get("evidence_contract"),
        "explicit_denies": {
            "actions": EXPLICIT_DENIED_ACTIONS,
            "default_decision": policy.get("default_decision"),
            "manual_review_required_for": defaults.get("manual_review_required_for", []),
        },
        "identity_controls": {
            "credential_model": "short-lived workload identity per workflow, agent class, and run",
            "credential_storage": "no shared static tokens; no model-visible secrets",
            "delegation_chain": [
                "accountable_team",
                "workflow_id",
                "agent_class",
                "run_id",
                "human_approval_record",
            ],
            "token_rules": [
                "issue tokens just in time",
                "bind tokens to workflow_id and run_id",
                "deny token passthrough to downstream tools",
                "expire tokens when the run ends or a kill signal fires",
            ],
        },
        "identity_id": identity_id(workflow_id, agent_class),
        "kpi_contract": policy.get("kpi_contract", []),
        "maturity_stage": workflow.get("maturity_stage"),
        "owner": {
            "accountable_team": owner.get("accountable_team"),
            "escalation": owner.get("escalation"),
            "reviewer_pools": owner.get("reviewer_pools", []),
        },
        "public_path": workflow.get("public_path"),
        "risk_tier": risk_tier(workflow, policy),
        "runtime_contract": {
            "egress_default": policy.get("runtime_controls", {}).get("egress_default"),
            "kill_signals": policy.get("runtime_controls", {}).get("kill_signals", []),
            "required_runtime_attributes": runtime_attributes,
            "session_disablement_required": policy.get("runtime_controls", {}).get("session_disablement_required"),
        },
        "source_content_path": workflow.get("content_path"),
        "status": workflow.get("status"),
        "workflow_id": workflow_id,
        "workflow_title": workflow.get("title"),
    }


def build_delegation_graph(identity_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    graph = []
    for record in identity_records:
        authority = as_dict(record.get("delegated_authority"), f"{record.get('identity_id')}: delegated_authority")
        owner = as_dict(record.get("owner"), f"{record.get('identity_id')}: owner")
        graph.append(
            {
                "agent_class": record.get("agent_class"),
                "delegated_by": owner.get("accountable_team"),
                "identity_id": record.get("identity_id"),
                "may_access_namespaces": [
                    scope.get("namespace")
                    for scope in authority.get("mcp_scopes", [])
                    if isinstance(scope, dict)
                ],
                "may_write": [
                    scope.get("namespace")
                    for scope in authority.get("mcp_scopes", [])
                    if isinstance(scope, dict) and str(scope.get("access", "")).startswith("write")
                ],
                "must_be_reviewed_by": owner.get("reviewer_pools", []),
                "workflow_id": record.get("workflow_id"),
            }
        )
    return graph


def validate_ledger(ledger: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(ledger.get("schema_version") == LEDGER_SCHEMA_VERSION, failures, "ledger schema_version is invalid")
    summary = as_dict(ledger.get("identity_summary"), "identity_summary")
    require(summary.get("default_decision") == "deny", failures, "ledger must default to deny")
    require(summary.get("human_review_required") is True, failures, "ledger must require human review")

    identities = as_list(ledger.get("agent_identities"), "agent_identities")
    seen: set[str] = set()
    for identity in identities:
        record = as_dict(identity, "agent_identity")
        identity_key = str(record.get("identity_id", "")).strip()
        require(bool(identity_key), failures, "agent identity is missing identity_id")
        require(identity_key not in seen, failures, f"duplicate identity_id: {identity_key}")
        seen.add(identity_key)

        owner = as_dict(record.get("owner"), f"{identity_key}: owner")
        require(bool(owner.get("accountable_team")), failures, f"{identity_key}: accountable team is required")
        require(bool(owner.get("reviewer_pools")), failures, f"{identity_key}: reviewer pools are required")

        evidence = as_dict(record.get("evidence_contract"), f"{identity_key}: evidence_contract")
        required_records = as_list(evidence.get("required_records"), f"{identity_key}: evidence_contract.required_records")
        require(len(required_records) >= 3, failures, f"{identity_key}: at least three evidence records are required")

        explicit_denies = as_dict(record.get("explicit_denies"), f"{identity_key}: explicit_denies")
        denied_actions = set(as_list(explicit_denies.get("actions"), f"{identity_key}: denied actions"))
        require({"merge_pull_request", "deploy_or_release", "read_secret_store"}.issubset(denied_actions), failures, f"{identity_key}: critical denied actions are missing")

        runtime = as_dict(record.get("runtime_contract"), f"{identity_key}: runtime_contract")
        require(runtime.get("session_disablement_required") is True, failures, f"{identity_key}: session disablement is required")
        runtime_attributes = {str(item) for item in as_list(runtime.get("required_runtime_attributes"), f"{identity_key}: runtime attributes")}
        missing_runtime = sorted(REQUIRED_RUNTIME_ATTRIBUTES - runtime_attributes)
        require(not missing_runtime, failures, f"{identity_key}: missing runtime attributes: {missing_runtime}")

        authority = as_dict(record.get("delegated_authority"), f"{identity_key}: delegated_authority")
        scopes = as_list(authority.get("mcp_scopes"), f"{identity_key}: mcp_scopes")
        namespaces = [str(scope.get("namespace")) for scope in scopes if isinstance(scope, dict)]
        require(all("*" not in namespace for namespace in namespaces), failures, f"{identity_key}: wildcard namespace is not allowed")
        if "write_remediation_branch" in set(authority.get("actions", [])):
            repo_scope = as_dict(authority.get("repository_scope"), f"{identity_key}: repository_scope")
            require(str(repo_scope.get("branch_prefix", "")).strip(), failures, f"{identity_key}: branch prefix is required")
            require(str(repo_scope.get("required_pr_label", "")).strip(), failures, f"{identity_key}: PR label is required")

    require(summary.get("identity_count") == len(identities), failures, "identity_summary.identity_count is stale")
    return failures


def build_ledger(
    *,
    manifest: dict[str, Any],
    policy_pack: dict[str, Any],
    report: dict[str, Any],
    manifest_path: Path,
    policy_path: Path,
    report_path: Path,
    manifest_ref: Path,
    policy_ref: Path,
    report_ref: Path,
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    defaults = as_dict(manifest.get("workflow_defaults"), "workflow_defaults")
    workflows = workflow_by_id(manifest)
    policies = policy_by_workflow_id(policy_pack)
    runtime_attributes = [
        str(item)
        for item in as_list(
            as_dict(policy_pack.get("decision_contract"), "decision_contract").get("required_runtime_attributes"),
            "decision_contract.required_runtime_attributes",
        )
    ]

    identity_records: list[dict[str, Any]] = []
    for workflow_id in sorted(workflows):
        workflow = workflows[workflow_id]
        policy = policies.get(workflow_id, {})
        for agent_class in sorted([str(agent) for agent in workflow.get("default_agents", [])]):
            identity_records.append(
                build_identity_record(
                    agent_class=agent_class,
                    workflow=workflow,
                    policy=policy,
                    defaults=defaults,
                    runtime_attributes=runtime_attributes,
                )
            )

    unique_namespaces = sorted(
        {
            str(scope.get("namespace"))
            for record in identity_records
            for scope in record.get("delegated_authority", {}).get("mcp_scopes", [])
            if isinstance(scope, dict) and scope.get("namespace")
        }
    )
    agent_classes = sorted({str(record.get("agent_class")) for record in identity_records})
    approval_workflows = sorted(
        {
            str(record.get("workflow_id"))
            for record in identity_records
            if record.get("delegated_authority", {}).get("approval_required_namespaces")
        }
    )

    ledger = {
        "agent_identities": identity_records,
        "delegation_graph": build_delegation_graph(identity_records),
        "enterprise_iam_contract": {
            "audit_events": [
                "identity_issued",
                "tool_call_decision",
                "branch_write",
                "human_approval_recorded",
                "evidence_record_attached",
                "kill_signal_triggered",
                "identity_revoked",
            ],
            "delegation_chain_required_fields": [
                "accountable_team",
                "workflow_id",
                "agent_class",
                "run_id",
                "tool_namespace",
                "human_approval_record",
            ],
            "identity_granularity": "one non-human identity per workflow, agent class, and runtime run",
            "issuance_requirements": [
                "service principal or workload identity is unique to the workflow and agent class",
                "runtime token is bound to workflow_id, agent_class, and run_id",
                "tool calls are evaluated by the MCP gateway policy before execution",
                "human approval is required before merge, release, deployment, or approval-required MCP scopes",
            ],
            "token_rules": [
                "no shared long-lived credentials",
                "no token passthrough from user session to downstream MCP tools",
                "expire identity at run completion",
                "revoke identity when a runtime kill signal fires",
            ],
        },
        "failures": failures,
        "generated_at": generated_at or str(manifest.get("last_reviewed", "")),
        "identity_summary": {
            "active_identity_count": sum(1 for record in identity_records if record.get("status") == "active"),
            "agent_classes": agent_classes,
            "approval_required_workflow_count": len(approval_workflows),
            "approval_required_workflows": approval_workflows,
            "default_decision": policy_pack.get("decision_contract", {}).get("default_decision"),
            "high_control_identity_count": sum(1 for record in identity_records if record.get("risk_tier") == "high-control"),
            "human_review_required": defaults.get("human_review_required", True),
            "identity_count": len(identity_records),
            "mcp_namespace_count": len(unique_namespaces),
            "mcp_namespaces": unique_namespaces,
            "workflow_count": len(workflows),
        },
        "intent": "Give enterprises a machine-readable non-human identity and delegation ledger for agentic remediation: who an agent acts for, which tools it may call, which writes are allowed, which actions are denied, and what evidence proves the delegation stayed in scope.",
        "ledger_id": "security-recipes-agent-identity-delegation-ledger",
        "positioning": {
            "buyer": "AI Platform, IAM, Security Engineering, GRC, and acquisition diligence teams",
            "category": "Agentic AI non-human identity governance",
            "enterprise_promise": "Agentic remediation identities can be reviewed, issued, scoped, audited, and revoked without relying on prompt text.",
            "why_now": "Agentic systems now act through tools, MCP connectors, and delegated permissions. Identity and privilege governance has to move from human-only IAM to runtime-scoped agent identities.",
        },
        "residual_risks": [
            {
                "risk": "The ledger defines approved delegation, but the deploying enterprise still has to enforce it in IAM and the MCP gateway.",
                "treatment": "Bind runtime credentials to workflow_id, agent_class, and run_id; deny tool calls without a matching ledger identity.",
            },
            {
                "risk": "Human approval records are external to this repository.",
                "treatment": "Export source-host review events and change-management approvals into the same evidence retention window.",
            },
            {
                "risk": "Compromised downstream MCP servers can still misrepresent tool results.",
                "treatment": "Pair identity scoping with server attestation, response logging, and kill signals on unexpected tool outputs.",
            },
        ],
        "schema_version": LEDGER_SCHEMA_VERSION,
        "source_artifacts": {
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
        "standards_alignment": [
            {
                "id": "owasp-agentic-top-10-2026",
                "name": "OWASP Top 10 for Agentic Applications 2026",
                "url": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
                "coverage": "ASI02 tool misuse, ASI03 identity and privilege abuse, ASI04 supply chain, and ASI10 rogue agents.",
            },
            {
                "id": "mcp-authorization",
                "name": "Model Context Protocol Authorization",
                "url": "https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization",
                "coverage": "HTTP transport authorization, resource-owner consent, and restricted MCP server access.",
            },
            {
                "id": "mcp-security-best-practices",
                "name": "Model Context Protocol Security Best Practices",
                "url": "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices",
                "coverage": "Confused-deputy prevention, token-passthrough avoidance, scope minimization, and session safety.",
            },
            {
                "id": "nist-ai-rmf-1.0",
                "name": "NIST AI Risk Management Framework 1.0",
                "url": "https://www.nist.gov/itl/ai-risk-management-framework",
                "coverage": "Governed, mapped, measured, and managed AI system risk.",
            },
            {
                "id": "cisa-secure-by-design",
                "name": "CISA Secure by Design",
                "url": "https://www.cisa.gov/securebydesign",
                "coverage": "Secure defaults, transparency, executive ownership, and measurable security outcomes.",
            },
        ],
    }
    ledger["failures"].extend(validate_ledger(ledger))
    return ledger


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in ledger is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    manifest_path = resolve(repo_root, args.manifest)
    policy_path = resolve(repo_root, args.policy)
    report_path = resolve(repo_root, args.report)
    output_path = resolve(repo_root, args.output)

    try:
        manifest = load_json(manifest_path)
        policy_pack = load_json(policy_path)
        report = load_json(report_path)
        failures = validate_source_contract(
            manifest=manifest,
            policy_pack=policy_pack,
            report=report,
            manifest_path=manifest_path,
        )
        ledger = build_ledger(
            manifest=manifest,
            policy_pack=policy_pack,
            report=report,
            manifest_path=manifest_path,
            policy_path=policy_path,
            report_path=report_path,
            manifest_ref=args.manifest,
            policy_ref=args.policy,
            report_ref=args.report,
            generated_at=args.generated_at,
            failures=failures,
        )
    except LedgerGenerationError as exc:
        print(f"agent identity ledger generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(ledger)

    if args.check:
        if ledger.get("failures"):
            print("agent identity ledger validation failed:", file=sys.stderr)
            for failure in ledger["failures"]:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run this script without --check", file=sys.stderr)
            return 1
        if current_text != next_text:
            print(
                f"{output_path} is stale; run scripts/generate_agent_identity_ledger.py",
                file=sys.stderr,
            )
            return 1
        print(f"Validated agent identity delegation ledger: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")

    if ledger.get("failures"):
        print("Generated agent identity delegation ledger with validation failures:", file=sys.stderr)
        for failure in ledger["failures"]:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated agent identity delegation ledger: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
