#!/usr/bin/env python3
"""Evaluate one agentic runtime action decision.

The evaluator is deterministic. It checks the generated action runtime
pack, workflow action matrix, runtime evidence, high-impact flags,
authorization state, egress and handoff outcomes, approval evidence, and
kill signals before returning allow, hold, deny, or kill.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_PACK = Path("data/evidence/agentic-action-runtime-pack.json")

ALLOW_DECISIONS = {"allow_bounded_action"}
VALID_DECISIONS = {
    *ALLOW_DECISIONS,
    "hold_for_action_evidence",
    "hold_for_human_approval",
    "deny_unregistered_action",
    "deny_unapproved_high_impact_action",
    "kill_session_on_runtime_action_signal",
}
HIGH_RISK_TIERS = {"high", "critical"}
CRITICAL_ACTION_CLASSES = {"credential_or_secret_access", "funds_or_irreversible_transaction"}


class ActionRuntimeDecisionError(RuntimeError):
    """Raised when the action pack or request is invalid."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ActionRuntimeDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ActionRuntimeDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ActionRuntimeDecisionError(f"{path} root must be a JSON object")
    return payload


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def lower_set(values: Any) -> set[str]:
    return {str(item).strip().lower() for item in as_list(values) if str(item).strip()}


def action_classes_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("id")): row
        for row in as_list(pack.get("action_classes"))
        if isinstance(row, dict) and row.get("id")
    }


def workflows_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("workflow_id")): row
        for row in as_list(pack.get("workflow_action_matrix"))
        if isinstance(row, dict) and row.get("workflow_id")
    }


def has_approval(record: Any) -> bool:
    approval = as_dict(record)
    if not approval:
        return False
    status = str(approval.get("status") or approval.get("decision") or "").strip().lower()
    return bool(approval.get("approval_id") or approval.get("id")) and status in {"approved", "allow", "granted"}


def is_negative_decision(value: str | None) -> bool:
    decision = str(value or "").strip().lower()
    return decision.startswith("deny") or decision.startswith("kill") or "_deny" in decision or "_kill" in decision


def is_kill_decision(value: str | None) -> bool:
    decision = str(value or "").strip().lower()
    return decision.startswith("kill") or "_kill" in decision


def normalize_request(runtime_request: dict[str, Any]) -> dict[str, Any]:
    request = dict(runtime_request)
    for key in [
        "changed_paths",
        "data_classes",
        "indicators",
        "mcp_namespaces",
        "requested_capabilities",
    ]:
        request[key] = [str(item) for item in as_list(request.get(key)) if str(item).strip()]
    for key in [
        "affects_prod",
        "affects_many_tenants",
        "can_delete_data",
        "can_deploy",
        "can_modify_identity",
        "can_move_funds",
        "contains_secret",
        "external_side_effect",
        "identity_used_after_revocation",
        "persistent_memory_write",
        "repeated_denied_action",
        "skill_or_tool_install",
        "token_passthrough",
        "writes_public_corpus",
    ]:
        request[key] = as_bool(request.get(key))
    return request


def evidence_missing(action_class: dict[str, Any] | None, request: dict[str, Any]) -> list[str]:
    required = {
        "workflow_id",
        "action_class",
        "run_id",
        "agent_id",
        "identity_id",
        "tenant_id",
        "correlation_id",
        "intent_summary",
        "policy_pack_hash",
        "authorization_decision",
        "receipt_id",
    }
    if action_class:
        required.update(str(field) for field in as_list(action_class.get("required_evidence")))

    missing: list[str] = []
    for field in sorted(required):
        if field == "approval_id":
            if not has_approval(request.get("human_approval_record")):
                missing.append(field)
            continue
        if not request.get(field):
            missing.append(field)
    return missing


def matched_kill_reasons(pack: dict[str, Any], request: dict[str, Any]) -> list[str]:
    policy = as_dict(pack.get("runtime_policy"))
    kill_indicators = lower_set(policy.get("kill_signal_indicators"))
    indicators = lower_set(request.get("indicators"))
    reasons: list[str] = []

    if request.get("runtime_kill_signal"):
        reasons.append(f"runtime_kill_signal: {request['runtime_kill_signal']}")
    for indicator in sorted(kill_indicators & indicators):
        reasons.append(f"kill indicator: {indicator}")
    if request.get("contains_secret"):
        reasons.append("secret, token, or regulated payload was observed in the action envelope")
    if request.get("token_passthrough"):
        reasons.append("raw token passthrough was observed")
    if request.get("identity_used_after_revocation"):
        reasons.append("delegated identity was used after revocation")
    if request.get("repeated_denied_action"):
        reasons.append("agent repeated an action after a deny or hold decision")
    if request.get("external_side_effect") and request.get("contains_secret"):
        reasons.append("secret-bearing action has an external side effect")

    for field in ["authorization_decision", "egress_decision", "handoff_decision", "telemetry_decision", "catastrophic_risk_decision"]:
        if is_kill_decision(request.get(field)):
            reasons.append(f"{field} returned a kill decision")
    return reasons


def high_impact_without_approval(action_class: dict[str, Any] | None, request: dict[str, Any]) -> bool:
    risk_tier = str((action_class or {}).get("risk_tier", "")).lower()
    if risk_tier not in HIGH_RISK_TIERS:
        return False
    if not has_approval(request.get("human_approval_record")):
        return True
    if risk_tier == "critical" and not request.get("risk_acceptance_id"):
        return True
    return False


def critical_side_effect_requested(action_class_id: str, request: dict[str, Any]) -> bool:
    return (
        action_class_id in CRITICAL_ACTION_CLASSES
        or request.get("can_move_funds")
        or request.get("can_modify_identity")
        or request.get("can_delete_data")
        or request.get("writes_public_corpus")
        or (request.get("affects_prod") and request.get("external_side_effect"))
    )


def decision_result(
    *,
    decision: str,
    pack: dict[str, Any],
    request: dict[str, Any],
    action_class: dict[str, Any] | None,
    workflow: dict[str, Any] | None,
    reason: str,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise ActionRuntimeDecisionError(f"unknown decision {decision!r}")
    return {
        "allowed": decision in ALLOW_DECISIONS,
        "action_class": {
            "default_decision": action_class.get("default_decision") if action_class else None,
            "id": action_class.get("id") if action_class else request.get("action_class"),
            "risk_tier": action_class.get("risk_tier") if action_class else None,
            "title": action_class.get("title") if action_class else None,
        },
        "decision": decision,
        "evidence": {
            "observed_runtime_attributes": sorted(k for k, v in request.items() if v not in (None, "", [], {}, False)),
            "required_evidence": action_class.get("required_evidence", []) if action_class else [],
            "source_artifacts": pack.get("source_artifacts", {}),
        },
        "pack_generated_at": pack.get("generated_at"),
        "reason": reason,
        "request": {
            "action_class": request.get("action_class"),
            "agent_id": request.get("agent_id"),
            "correlation_id": request.get("correlation_id"),
            "identity_id": request.get("identity_id"),
            "run_id": request.get("run_id"),
            "tenant_id": request.get("tenant_id"),
            "workflow_id": request.get("workflow_id"),
        },
        "violations": violations or [],
        "workflow": {
            "action_class_ids": workflow.get("action_class_ids", []) if workflow else [],
            "decision_floor": workflow.get("decision_floor") if workflow else None,
            "title": workflow.get("title") if workflow else None,
            "workflow_id": workflow.get("workflow_id") if workflow else request.get("workflow_id"),
        },
    }


def evaluate_agentic_action_runtime_decision(
    pack: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured runtime action decision."""
    if not isinstance(pack, dict):
        raise ActionRuntimeDecisionError("pack must be an object")
    if not isinstance(runtime_request, dict):
        raise ActionRuntimeDecisionError("runtime_request must be an object")

    request = normalize_request(runtime_request)
    action_class_id = str(request.get("action_class") or "").strip()
    workflow_id = str(request.get("workflow_id") or "").strip()
    actions = action_classes_by_id(pack)
    workflows = workflows_by_id(pack)
    action_class = actions.get(action_class_id)
    workflow = workflows.get(workflow_id)

    if not action_class:
        return decision_result(
            decision="hold_for_action_evidence",
            pack=pack,
            request=request,
            action_class=None,
            workflow=workflow,
            reason="action class is not registered in the generated action runtime pack",
            violations=[f"unknown action_class: {action_class_id}"],
        )
    if not workflow:
        return decision_result(
            decision="hold_for_action_evidence",
            pack=pack,
            request=request,
            action_class=action_class,
            workflow=None,
            reason="workflow is not registered in the generated action matrix",
            violations=[f"unknown workflow_id: {workflow_id}"],
        )

    kill_reasons = matched_kill_reasons(pack, request)
    if kill_reasons:
        return decision_result(
            decision="kill_session_on_runtime_action_signal",
            pack=pack,
            request=request,
            action_class=action_class,
            workflow=workflow,
            reason="runtime kill-class action signal was observed",
            violations=kill_reasons,
        )

    if action_class_id not in set(workflow.get("action_class_ids", [])):
        return decision_result(
            decision="deny_unregistered_action",
            pack=pack,
            request=request,
            action_class=action_class,
            workflow=workflow,
            reason="action class is not registered for this workflow",
            violations=[f"{action_class_id} is outside workflow {workflow_id}"],
        )

    negative_decisions = [
        field
        for field in ["authorization_decision", "egress_decision", "handoff_decision", "telemetry_decision", "catastrophic_risk_decision"]
        if is_negative_decision(request.get(field))
    ]
    if negative_decisions:
        return decision_result(
            decision="deny_unapproved_high_impact_action",
            pack=pack,
            request=request,
            action_class=action_class,
            workflow=workflow,
            reason="linked policy, authorization, egress, handoff, telemetry, or catastrophic-risk decision denied the action",
            violations=[f"{field}={request.get(field)}" for field in negative_decisions],
        )

    missing = evidence_missing(action_class, request)
    missing_without_approval = [field for field in missing if field not in {"approval_id", "risk_acceptance_id"}]
    if missing_without_approval:
        return decision_result(
            decision="hold_for_action_evidence",
            pack=pack,
            request=request,
            action_class=action_class,
            workflow=workflow,
            reason="required action evidence is missing",
            violations=[f"missing {field}" for field in missing_without_approval],
        )

    if high_impact_without_approval(action_class, request):
        decision = "deny_unapproved_high_impact_action" if critical_side_effect_requested(action_class_id, request) else "hold_for_human_approval"
        return decision_result(
            decision=decision,
            pack=pack,
            request=request,
            action_class=action_class,
            workflow=workflow,
            reason="high-impact action requires linked approval and risk evidence before execution",
            violations=[f"missing {field}" for field in missing if field in {"approval_id", "risk_acceptance_id"}],
        )

    if request.get("affects_prod") or request.get("can_deploy"):
        if not has_approval(request.get("human_approval_record")):
            return decision_result(
                decision="hold_for_human_approval",
                pack=pack,
                request=request,
                action_class=action_class,
                workflow=workflow,
                reason="production-affecting action requires a linked approval",
                violations=["missing approval_id"],
            )

    return decision_result(
        decision="allow_bounded_action",
        pack=pack,
        request=request,
        action_class=action_class,
        workflow=workflow,
        reason="action is registered for the workflow and required evidence is present",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--runtime-request", type=Path, help="JSON file containing the runtime action request.")
    parser.add_argument("--workflow-id")
    parser.add_argument("--action-class")
    parser.add_argument("--run-id")
    parser.add_argument("--agent-id")
    parser.add_argument("--identity-id")
    parser.add_argument("--tenant-id")
    parser.add_argument("--correlation-id")
    parser.add_argument("--intent-summary")
    parser.add_argument("--policy-pack-hash")
    parser.add_argument("--context-package-hash")
    parser.add_argument("--authorization-decision")
    parser.add_argument("--egress-decision")
    parser.add_argument("--handoff-decision")
    parser.add_argument("--telemetry-decision")
    parser.add_argument("--catastrophic-risk-decision")
    parser.add_argument("--receipt-id")
    parser.add_argument("--telemetry-event-id")
    parser.add_argument("--approval-id")
    parser.add_argument("--approval-status")
    parser.add_argument("--risk-acceptance-id")
    parser.add_argument("--runtime-kill-signal")
    parser.add_argument("--indicator", action="append", default=[])
    parser.add_argument("--mcp-namespace", action="append", default=[])
    parser.add_argument("--requested-capability", action="append", default=[])
    parser.add_argument("--changed-path", action="append", default=[])
    parser.add_argument("--data-class", action="append", default=[])
    parser.add_argument("--affects-prod", action="store_true")
    parser.add_argument("--affects-many-tenants", action="store_true")
    parser.add_argument("--can-delete-data", action="store_true")
    parser.add_argument("--can-deploy", action="store_true")
    parser.add_argument("--can-modify-identity", action="store_true")
    parser.add_argument("--can-move-funds", action="store_true")
    parser.add_argument("--contains-secret", action="store_true")
    parser.add_argument("--external-side-effect", action="store_true")
    parser.add_argument("--identity-used-after-revocation", action="store_true")
    parser.add_argument("--persistent-memory-write", action="store_true")
    parser.add_argument("--repeated-denied-action", action="store_true")
    parser.add_argument("--skill-or-tool-install", action="store_true")
    parser.add_argument("--token-passthrough", action="store_true")
    parser.add_argument("--writes-public-corpus", action="store_true")
    parser.add_argument("--expect-decision")
    return parser.parse_args()


def request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.runtime_request:
        return load_json(args.runtime_request)
    request: dict[str, Any] = {
        "action_class": args.action_class,
        "affects_many_tenants": args.affects_many_tenants,
        "affects_prod": args.affects_prod,
        "agent_id": args.agent_id,
        "authorization_decision": args.authorization_decision,
        "can_delete_data": args.can_delete_data,
        "can_deploy": args.can_deploy,
        "can_modify_identity": args.can_modify_identity,
        "can_move_funds": args.can_move_funds,
        "catastrophic_risk_decision": args.catastrophic_risk_decision,
        "changed_paths": args.changed_path,
        "contains_secret": args.contains_secret,
        "context_package_hash": args.context_package_hash,
        "correlation_id": args.correlation_id,
        "data_classes": args.data_class,
        "egress_decision": args.egress_decision,
        "external_side_effect": args.external_side_effect,
        "handoff_decision": args.handoff_decision,
        "identity_id": args.identity_id,
        "identity_used_after_revocation": args.identity_used_after_revocation,
        "indicators": args.indicator,
        "intent_summary": args.intent_summary,
        "mcp_namespaces": args.mcp_namespace,
        "persistent_memory_write": args.persistent_memory_write,
        "policy_pack_hash": args.policy_pack_hash,
        "receipt_id": args.receipt_id,
        "repeated_denied_action": args.repeated_denied_action,
        "requested_capabilities": args.requested_capability,
        "risk_acceptance_id": args.risk_acceptance_id,
        "run_id": args.run_id,
        "runtime_kill_signal": args.runtime_kill_signal,
        "skill_or_tool_install": args.skill_or_tool_install,
        "telemetry_decision": args.telemetry_decision,
        "telemetry_event_id": args.telemetry_event_id,
        "tenant_id": args.tenant_id,
        "token_passthrough": args.token_passthrough,
        "workflow_id": args.workflow_id,
        "writes_public_corpus": args.writes_public_corpus,
    }
    if args.approval_id or args.approval_status:
        request["human_approval_record"] = {
            "approval_id": args.approval_id,
            "status": args.approval_status,
        }
    return request


def main() -> int:
    args = parse_args()
    try:
        pack = load_json(args.pack)
        result = evaluate_agentic_action_runtime_decision(pack, request_from_args(args))
    except ActionRuntimeDecisionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(result, indent=2, sort_keys=True))
    if args.expect_decision and result.get("decision") != args.expect_decision:
        print(
            f"expected decision {args.expect_decision!r}, got {result.get('decision')!r}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
