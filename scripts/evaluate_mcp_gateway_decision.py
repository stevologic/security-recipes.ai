#!/usr/bin/env python3
"""Evaluate one MCP gateway runtime decision against the policy pack.

The generator creates the policy contract. This evaluator is the small,
deterministic decision function an MCP gateway, CI admission check, or
agent host can call before a tool invocation. It intentionally returns a
structured decision instead of raising on normal policy failures so it
can be used directly in audit logs and run transcripts.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from pathlib import Path
from typing import Any


DEFAULT_POLICY = Path("data/policy/mcp-gateway-policy.json")
VALID_DECISIONS = {
    "allow",
    "allow_scoped_branch",
    "allow_scoped_ticket",
    "hold_for_approval",
    "deny",
    "kill_session",
}


class GatewayDecisionError(RuntimeError):
    """Raised when a policy or runtime request cannot be parsed."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise GatewayDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise GatewayDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise GatewayDecisionError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def normalize_path(path: Any) -> str:
    value = str(path).replace("\\", "/").strip()
    while value.startswith("./"):
        value = value[2:]
    return value.lstrip("/")


def normalize_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def matches_pattern(path: str, pattern: str) -> bool:
    path = normalize_path(path)
    pattern = normalize_path(pattern)
    if not path or not pattern:
        return False

    if fnmatch.fnmatchcase(path, pattern):
        return True

    if pattern.startswith("**/") and fnmatch.fnmatchcase(path, pattern[3:]):
        return True

    if pattern.endswith("/**"):
        prefix = pattern[:-3].rstrip("/")
        return path == prefix or path.startswith(prefix + "/")

    return False


def matches_any(path: str, patterns: list[Any]) -> bool:
    return any(matches_pattern(path, str(pattern)) for pattern in patterns)


def approval_satisfied(record: Any) -> bool:
    if record is True:
        return True
    if record in (None, False, "", [], {}):
        return False
    if isinstance(record, dict):
        status = str(record.get("status") or record.get("decision") or "").lower()
        return status in {"approved", "approve", "allow", "allowed", "accepted", "true"}
    if isinstance(record, str):
        value = record.strip()
        if not value:
            return False
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return value.lower() in {"approved", "approve", "allow", "allowed", "accepted", "true"}
        return approval_satisfied(parsed)
    return False


def derive_agent_class(agent_id: str, allowed_agents: list[Any], explicit: Any = None) -> str:
    if explicit:
        return str(explicit).strip().lower()

    normalized_agent_id = normalize_token(agent_id)
    for agent in allowed_agents:
        candidate = str(agent).strip().lower()
        if normalize_token(candidate) and normalize_token(candidate) in normalized_agent_id:
            return candidate

    if "::" in agent_id:
        return agent_id.rsplit("::", 1)[-1].strip().lower()
    return agent_id.strip().lower()


def decision_result(
    *,
    decision: str,
    reason: str,
    request: dict[str, Any],
    policy_pack: dict[str, Any],
    policy: dict[str, Any] | None = None,
    scope: dict[str, Any] | None = None,
    violations: list[str] | None = None,
    approval_required: bool = False,
    approval_present: bool = False,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise GatewayDecisionError(f"unknown decision {decision!r}")

    matched_policy = None
    if policy is not None:
        matched_policy = {
            "maturity_stage": policy.get("maturity_stage"),
            "public_path": policy.get("public_path"),
            "status": policy.get("status"),
            "title": policy.get("title"),
            "workflow_id": policy.get("workflow_id"),
        }

    return {
        "allowed": decision in {"allow", "allow_scoped_branch", "allow_scoped_ticket"},
        "approval_present": approval_present,
        "approval_required": approval_required,
        "decision": decision,
        "evidence": {
            "observed_runtime_attributes": sorted(k for k, v in request.items() if v not in (None, "", [], {})),
            "policy_generated_at": policy_pack.get("generated_at"),
            "policy_id": policy_pack.get("policy_id"),
            "required_pr_label": (policy or {}).get("dispatch", {}).get("required_pr_label") if policy else None,
            "source_manifest_sha256": (policy_pack.get("source_manifest") or {}).get("sha256"),
        },
        "matched_policy": matched_policy,
        "matched_scope": scope,
        "reason": reason,
        "request": {
            "agent_class": request.get("agent_class"),
            "agent_id": request.get("agent_id"),
            "branch_name": request.get("branch_name"),
            "changed_paths": request.get("changed_paths") or [],
            "diff_line_count": request.get("diff_line_count"),
            "gate_phase": request.get("gate_phase"),
            "run_id": request.get("run_id"),
            "tool_access_mode": request.get("tool_access_mode"),
            "tool_namespace": request.get("tool_namespace"),
            "workflow_id": request.get("workflow_id"),
        },
        "violations": violations or [],
    }


def policy_by_workflow_id(policy_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    policies = policy_pack.get("workflow_policies")
    if not isinstance(policies, list):
        raise GatewayDecisionError("policy pack is missing workflow_policies")
    return {
        str(policy.get("workflow_id")): policy
        for policy in policies
        if isinstance(policy, dict) and policy.get("workflow_id")
    }


def evaluate_policy_decision(policy_pack: dict[str, Any], runtime_request: dict[str, Any]) -> dict[str, Any]:
    """Return a structured runtime decision for one requested tool call."""
    if not isinstance(policy_pack, dict):
        raise GatewayDecisionError("policy_pack must be an object")
    if not isinstance(runtime_request, dict):
        raise GatewayDecisionError("runtime_request must be an object")

    request = dict(runtime_request)
    request["changed_paths"] = [normalize_path(path) for path in as_list(request.get("changed_paths")) if str(path).strip()]
    request["diff_line_count"] = int(request.get("diff_line_count") or 0)

    workflow_id = str(request.get("workflow_id") or "").strip()
    if not workflow_id:
        return decision_result(
            decision="deny",
            reason="workflow_id is required",
            request=request,
            policy_pack=policy_pack,
            violations=["missing workflow_id"],
        )

    policies = policy_by_workflow_id(policy_pack)
    policy = policies.get(workflow_id)
    if policy is None:
        return decision_result(
            decision="deny",
            reason="workflow_id is not declared in the gateway policy pack",
            request=request,
            policy_pack=policy_pack,
            violations=[f"unknown workflow_id: {workflow_id}"],
        )

    kill_signal = str(request.get("runtime_kill_signal") or request.get("triggered_kill_signal") or "").strip()
    if kill_signal:
        known_signals = [str(signal) for signal in (policy.get("runtime_controls") or {}).get("kill_signals", [])]
        return decision_result(
            decision="kill_session",
            reason="runtime kill signal fired",
            request=request,
            policy_pack=policy_pack,
            policy=policy,
            violations=[] if kill_signal in known_signals else [f"unregistered kill signal: {kill_signal}"],
        )

    violations: list[str] = []
    if policy_pack.get("decision_contract", {}).get("default_decision") != "deny":
        violations.append("policy pack default_decision is not deny")
    if policy.get("default_decision") != "deny":
        violations.append("workflow policy default_decision is not deny")
    if policy.get("status") != "active":
        violations.append(f"workflow status is {policy.get('status')!r}, not active")

    required = ["agent_id", "run_id", "tool_namespace", "tool_access_mode", "gate_phase"]
    for key in required:
        if not str(request.get(key) or "").strip():
            violations.append(f"{key} is required")

    gate_phase = str(request.get("gate_phase") or "").strip()
    gate_phases = {str(item.get("phase")) for item in policy.get("gate_contract", []) if isinstance(item, dict)}
    if gate_phase and gate_phase not in gate_phases:
        violations.append(f"gate_phase {gate_phase!r} is not declared for workflow")

    allowed_agents = [str(agent).lower() for agent in (policy.get("identity") or {}).get("allowed_agents", [])]
    agent_class = derive_agent_class(str(request.get("agent_id") or ""), allowed_agents, request.get("agent_class"))
    request["agent_class"] = agent_class
    if agent_class not in allowed_agents:
        violations.append(f"agent_class {agent_class!r} is not allowed for workflow")

    namespace = str(request.get("tool_namespace") or "").strip()
    access_mode = str(request.get("tool_access_mode") or "").strip()
    scopes = (policy.get("tool_access") or {}).get("allowed_mcp_scopes") or []
    matched_scope = next(
        (
            scope
            for scope in scopes
            if isinstance(scope, dict)
            and str(scope.get("namespace")) == namespace
            and str(scope.get("access")) == access_mode
        ),
        None,
    )
    if matched_scope is None:
        violations.append(f"tool scope {namespace}:{access_mode} is not allowed")

    if violations:
        return decision_result(
            decision="deny",
            reason="runtime request failed gateway policy checks",
            request=request,
            policy_pack=policy_pack,
            policy=policy,
            scope=matched_scope,
            violations=violations,
        )

    change_class = str(request.get("change_class") or "").strip()
    manual_classes = [str(item) for item in (policy_pack.get("global_defaults") or {}).get("manual_review_required_for", [])]
    approval_present = approval_satisfied(request.get("human_approval_record"))
    if change_class and change_class in manual_classes and not approval_present:
        return decision_result(
            decision="hold_for_approval",
            reason="change class requires a typed human approval record",
            request=request,
            policy_pack=policy_pack,
            policy=policy,
            scope=matched_scope,
            approval_required=True,
            approval_present=False,
        )

    scope_decision = str(matched_scope.get("decision"))
    if scope_decision == "hold_for_approval" and not approval_present:
        return decision_result(
            decision="hold_for_approval",
            reason="tool scope requires a typed human approval record",
            request=request,
            policy_pack=policy_pack,
            policy=policy,
            scope=matched_scope,
            approval_required=True,
            approval_present=False,
        )

    if scope_decision == "allow_scoped_branch":
        branch_name = str(request.get("branch_name") or "").strip()
        changed_paths = request.get("changed_paths") or []
        change_scope = policy.get("change_scope") or {}
        branch_prefix = str((policy.get("dispatch") or {}).get("required_branch_prefix") or "")
        if not branch_name.startswith(branch_prefix):
            violations.append(f"branch_name must start with {branch_prefix!r}")
        if not changed_paths:
            violations.append("changed_paths are required for write_branch access")
        if len(changed_paths) > int(change_scope.get("max_changed_files") or 0):
            violations.append("changed_paths exceeds max_changed_files")
        if request["diff_line_count"] > int(change_scope.get("max_diff_lines") or 0):
            violations.append("diff_line_count exceeds max_diff_lines")

        forbidden = [path for path in changed_paths if matches_any(path, change_scope.get("forbidden_paths") or [])]
        if forbidden:
            violations.append(f"changed_paths hit forbidden paths: {forbidden}")

        outside = [path for path in changed_paths if not matches_any(path, change_scope.get("allowed_paths") or [])]
        if outside:
            violations.append(f"changed_paths outside allowed paths: {outside}")

        if violations:
            return decision_result(
                decision="deny",
                reason="scoped branch write failed path, branch, or diff limits",
                request=request,
                policy_pack=policy_pack,
                policy=policy,
                scope=matched_scope,
                violations=violations,
                approval_present=approval_present,
            )

    if scope_decision == "hold_for_approval" and approval_present:
        return decision_result(
            decision="allow",
            reason="approval-required tool scope has a typed approval record",
            request=request,
            policy_pack=policy_pack,
            policy=policy,
            scope=matched_scope,
            approval_required=True,
            approval_present=True,
        )

    return decision_result(
        decision=scope_decision,
        reason="runtime request satisfies gateway policy",
        request=request,
        policy_pack=policy_pack,
        policy=policy,
        scope=matched_scope,
        approval_required=scope_decision == "hold_for_approval",
        approval_present=approval_present,
    )


def request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.request:
        payload = load_json(args.request)
    else:
        payload = {}

    overrides = {
        "agent_class": args.agent_class,
        "agent_id": args.agent_id,
        "branch_name": args.branch_name,
        "change_class": args.change_class,
        "diff_line_count": args.diff_line_count,
        "gate_phase": args.gate_phase,
        "human_approval_record": args.human_approval_record,
        "run_id": args.run_id,
        "runtime_kill_signal": args.runtime_kill_signal,
        "tool_access_mode": args.tool_access_mode,
        "tool_namespace": args.tool_namespace,
        "workflow_id": args.workflow_id,
    }
    for key, value in overrides.items():
        if value not in (None, ""):
            payload[key] = value
    if args.changed_path:
        payload["changed_paths"] = args.changed_path
    return payload


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY, help="Path to mcp-gateway-policy.json")
    parser.add_argument("--request", type=Path, help="JSON file containing runtime request attributes")
    parser.add_argument("--workflow-id")
    parser.add_argument("--agent-id")
    parser.add_argument("--agent-class")
    parser.add_argument("--run-id")
    parser.add_argument("--tool-namespace")
    parser.add_argument("--tool-access-mode")
    parser.add_argument("--branch-name", default="")
    parser.add_argument("--changed-path", action="append", default=[])
    parser.add_argument("--diff-line-count", type=int, default=0)
    parser.add_argument("--gate-phase")
    parser.add_argument("--human-approval-record")
    parser.add_argument("--runtime-kill-signal")
    parser.add_argument("--change-class")
    parser.add_argument("--expect-decision", choices=sorted(VALID_DECISIONS))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    policy_pack = load_json(args.policy)
    request = request_from_args(args)
    decision = evaluate_policy_decision(policy_pack, request)
    print(json.dumps(decision, indent=2, sort_keys=True))
    if args.expect_decision and decision.get("decision") != args.expect_decision:
        print(
            f"expected decision {args.expect_decision!r}, got {decision.get('decision')!r}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
