#!/usr/bin/env python3
"""Generate the SecurityRecipes MCP gateway policy pack.

The workflow control-plane manifest names what a remediation workflow is
allowed to do. This generator turns that manifest into a smaller,
enforcer-friendly JSON contract that an MCP gateway, agent host, CI
admission check, or policy sidecar can load without scraping docs.

The output is deterministic by default so CI can run with --check and fail
when the checked-in policy pack drifts from the workflow manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


POLICY_SCHEMA_VERSION = "1.0"
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_OUTPUT = Path("data/policy/mcp-gateway-policy.json")

ACCESS_DECISIONS = {
    "read": "allow",
    "write_branch": "allow_scoped_branch",
    "write_ticket": "allow_scoped_ticket",
    "approval_required": "hold_for_approval",
}


class PolicyGenerationError(RuntimeError):
    """Raised when the policy pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyGenerationError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise PolicyGenerationError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise PolicyGenerationError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise PolicyGenerationError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyGenerationError(f"{label} must be an object")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def normalize_path(path: Path) -> str:
    return path.as_posix()


def build_tool_scope(workflow_id: str, context: dict[str, Any]) -> dict[str, Any]:
    namespace = str(context.get("namespace", "")).strip()
    access = str(context.get("access", "")).strip()
    if not namespace or not access:
        raise PolicyGenerationError(f"{workflow_id}: every MCP context needs namespace and access")

    decision = ACCESS_DECISIONS.get(access)
    if not decision:
        raise PolicyGenerationError(f"{workflow_id}: unsupported MCP access mode {access!r}")

    return {
        "access": access,
        "decision": decision,
        "namespace": namespace,
        "purpose": str(context.get("purpose", "")).strip(),
        "scope_id": f"{workflow_id}:{namespace}:{access}",
    }


def build_gate_contract(workflow_id: str, workflow: dict[str, Any], phases: list[str]) -> list[dict[str, Any]]:
    gates = as_dict(workflow.get("gates"), f"{workflow_id}: gates")
    contract: list[dict[str, Any]] = []
    for phase in phases:
        rules = as_list(gates.get(phase), f"{workflow_id}: gates.{phase}")
        contract.append(
            {
                "phase": phase,
                "rule_count": len(rules),
                "rules": rules,
            }
        )
    return contract


def build_workflow_policy(
    workflow: dict[str, Any],
    defaults: dict[str, Any],
    phases: list[str],
) -> dict[str, Any]:
    workflow_id = str(workflow.get("id", "")).strip()
    if not workflow_id:
        raise PolicyGenerationError("workflow is missing id")

    owner = as_dict(workflow.get("owner"), f"{workflow_id}: owner")
    scope = as_dict(workflow.get("scope"), f"{workflow_id}: scope")
    mcp_context = as_list(workflow.get("mcp_context"), f"{workflow_id}: mcp_context")
    tool_scopes = [
        build_tool_scope(workflow_id, as_dict(context, f"{workflow_id}: mcp_context item"))
        for context in mcp_context
    ]

    evidence = as_list(workflow.get("evidence"), f"{workflow_id}: evidence")
    kpis = as_list(workflow.get("kpis"), f"{workflow_id}: kpis")
    kill_signals = as_list(workflow.get("kill_signals"), f"{workflow_id}: kill_signals")

    return {
        "change_scope": {
            "allowed_paths": as_list(scope.get("allowed_paths"), f"{workflow_id}: scope.allowed_paths"),
            "forbidden_paths": as_list(scope.get("forbidden_paths"), f"{workflow_id}: scope.forbidden_paths"),
            "max_changed_files": scope.get("max_changed_files"),
            "max_diff_lines": scope.get("max_diff_lines"),
        },
        "default_decision": "deny",
        "dispatch": {
            "automation_first": as_list(workflow.get("automation_first"), f"{workflow_id}: automation_first"),
            "eligible_findings": as_list(workflow.get("eligible_findings"), f"{workflow_id}: eligible_findings"),
            "max_open_prs_per_repo": defaults.get("max_open_prs_per_repo"),
            "required_branch_prefix": defaults.get("branch_prefix"),
            "required_pr_label": defaults.get("required_pr_label"),
        },
        "evidence_contract": {
            "required_records": [
                {
                    "evidence_owner": item.get("evidence_owner"),
                    "id": item.get("id"),
                    "retention": item.get("retention"),
                    "source": item.get("source"),
                }
                for item in evidence
                if isinstance(item, dict)
            ],
            "retention_days_default": defaults.get("evidence_retention_days"),
        },
        "gate_contract": build_gate_contract(workflow_id, workflow, phases),
        "identity": {
            "accountable_team": owner.get("accountable_team"),
            "allowed_agents": as_list(workflow.get("default_agents"), f"{workflow_id}: default_agents"),
            "escalation": owner.get("escalation"),
            "reviewer_pools": owner.get("reviewer_pools", []),
        },
        "kpi_contract": [
            {
                "id": item.get("id"),
                "target": item.get("target"),
            }
            for item in kpis
            if isinstance(item, dict)
        ],
        "maturity_stage": workflow.get("maturity_stage"),
        "public_path": workflow.get("public_path"),
        "runtime_controls": {
            "egress_default": "deny_except_declared_mcp_context",
            "kill_signals": kill_signals,
            "session_disablement_required": True,
        },
        "source_content_path": workflow.get("content_path"),
        "status": workflow.get("status"),
        "title": workflow.get("title"),
        "tool_access": {
            "allowed_mcp_scopes": tool_scopes,
            "denied_by_default": True,
            "requires_human_approval_for": [
                scope["namespace"]
                for scope in tool_scopes
                if scope.get("decision") == "hold_for_approval"
            ],
        },
        "workflow_id": workflow_id,
    }


def build_policy_pack(
    manifest: dict[str, Any],
    manifest_ref: str,
    manifest_sha256: str,
    generated_at: str | None,
) -> dict[str, Any]:
    defaults = as_dict(manifest.get("workflow_defaults", {}), "workflow_defaults")
    phases = [str(phase) for phase in as_list(manifest.get("required_gate_phases"), "required_gate_phases")]
    workflows = [
        build_workflow_policy(as_dict(workflow, "workflow"), defaults, phases)
        for workflow in as_list(manifest.get("workflows"), "workflows")
    ]

    unique_namespaces = sorted(
        {
            scope["namespace"]
            for workflow in workflows
            for scope in workflow["tool_access"]["allowed_mcp_scopes"]
        }
    )
    unique_decisions = sorted(
        {
            scope["decision"]
            for workflow in workflows
            for scope in workflow["tool_access"]["allowed_mcp_scopes"]
        }
    )

    return {
        "decision_contract": {
            "decisions": [
                {
                    "decision": "allow",
                    "meaning": "Read-only context access inside the declared namespace.",
                },
                {
                    "decision": "allow_scoped_branch",
                    "meaning": "Write only to the workflow branch prefix and declared file scope.",
                },
                {
                    "decision": "allow_scoped_ticket",
                    "meaning": "Write only workflow evidence or triage notes to declared ticket systems.",
                },
                {
                    "decision": "hold_for_approval",
                    "meaning": "Pause and require a typed human approval record before continuing.",
                },
                {
                    "decision": "deny",
                    "meaning": "Fail closed for undeclared workflows, tools, paths, hosts, or gates.",
                },
                {
                    "decision": "kill_session",
                    "meaning": "Disable the active agent session when a runtime kill signal fires.",
                },
            ],
            "default_decision": "deny",
            "required_runtime_attributes": [
                "workflow_id",
                "agent_id",
                "run_id",
                "tool_namespace",
                "tool_access_mode",
                "branch_name",
                "changed_paths",
                "diff_line_count",
                "gate_phase",
                "human_approval_record",
            ],
        },
        "generated_at": generated_at or str(manifest.get("last_reviewed", "")),
        "global_defaults": {
            "default_change_window": defaults.get("default_change_window"),
            "evidence_retention_days": defaults.get("evidence_retention_days"),
            "human_review_required": defaults.get("human_review_required", True),
            "manual_review_required_for": defaults.get("manual_review_required_for", []),
            "max_open_prs_per_repo": defaults.get("max_open_prs_per_repo"),
            "required_pr_label": defaults.get("required_pr_label"),
            "required_remediation_branch_prefix": defaults.get("branch_prefix"),
        },
        "intent": (
            "Convert SecurityRecipes workflow manifests into an enforceable MCP gateway policy pack "
            "for scoped tool access, reviewer-gated writes, runtime session disablement, and audit evidence."
        ),
        "policy_id": "security-recipes-mcp-gateway-policy-pack",
        "policy_summary": {
            "active_workflow_count": sum(1 for workflow in workflows if workflow.get("status") == "active"),
            "mcp_namespace_count": len(unique_namespaces),
            "policy_decisions": unique_decisions + ["deny", "kill_session"],
            "workflow_count": len(workflows),
        },
        "schema_version": POLICY_SCHEMA_VERSION,
        "source_manifest": {
            "last_reviewed": manifest.get("last_reviewed"),
            "path": manifest_ref,
            "schema_version": manifest.get("schema_version"),
            "sha256": manifest_sha256,
        },
        "standards_alignment": manifest.get("standards_alignment", []),
        "workflow_policies": workflows,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in policy pack is stale.")
    return parser.parse_args()


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    manifest_path = resolve(repo_root, args.manifest)
    output_path = resolve(repo_root, args.output)

    try:
        manifest = load_json(manifest_path)
        # Hash decoded text so Git's platform-specific working-tree line endings
        # cannot change the policy identity. Downstream generators use the same
        # canonical UTF-8 text hash when validating source_artifacts.
        manifest_sha = hashlib.sha256(
            manifest_path.read_text(encoding="utf-8").encode("utf-8")
        ).hexdigest()
        policy_pack = build_policy_pack(
            manifest=manifest,
            manifest_ref=normalize_path(args.manifest),
            manifest_sha256=manifest_sha,
            generated_at=args.generated_at,
        )
    except PolicyGenerationError as exc:
        print(f"mcp gateway policy generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(policy_pack)

    if args.check:
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run this script without --check", file=sys.stderr)
            return 1
        if current_text != next_text:
            print(
                f"{output_path} is stale; run scripts/generate_mcp_gateway_policy.py",
                file=sys.stderr,
            )
            return 1
        print(f"Validated MCP gateway policy pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")
    print(f"Generated MCP gateway policy pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
