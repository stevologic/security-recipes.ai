#!/usr/bin/env python3
"""Evaluate one agentic approval receipt decision.

The evaluator is deterministic. It verifies that an approval receipt is
registered for the workflow and action class, unexpired, scope-bound,
role-complete, separated from the requesting identity, and linked to risk
acceptance when required.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_PACK = Path("data/evidence/agentic-approval-receipt-pack.json")

ALLOW_DECISIONS = {"allow_scope_bound_approval"}
VALID_DECISIONS = {
    *ALLOW_DECISIONS,
    "hold_for_second_approver",
    "hold_for_risk_acceptance",
    "deny_scope_mismatch",
    "deny_expired_or_untrusted_approval",
    "deny_unregistered_approval_profile",
    "kill_session_on_approval_bypass_signal",
}
NEGATIVE_PREFIXES = ("deny", "kill")


class ApprovalReceiptDecisionError(RuntimeError):
    """Raised when the approval receipt pack or request is invalid."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ApprovalReceiptDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ApprovalReceiptDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ApprovalReceiptDecisionError(f"{path} root must be a JSON object")
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


def parse_time(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def now_from_request(request: dict[str, Any]) -> datetime:
    return parse_time(request.get("now")) or datetime.now(timezone.utc)


def normalize_request(runtime_request: dict[str, Any]) -> dict[str, Any]:
    request = dict(runtime_request)
    approval = as_dict(request.get("approval_receipt"))
    for key, value in approval.items():
        request.setdefault(key, value)

    for list_key in ["approver_ids", "approver_roles", "indicators"]:
        request[list_key] = [str(item).strip() for item in as_list(request.get(list_key)) if str(item).strip()]

    for key in [
        "approval_after_execution",
        "approval_bypass_signal",
        "approval_reused_across_run",
        "contains_secret",
        "cross_tenant_approval_reuse",
        "requester_self_approved",
        "token_passthrough",
    ]:
        request[key] = as_bool(request.get(key))
    return request


def workflow_action_requirement(pack: dict[str, Any], request: dict[str, Any]) -> dict[str, Any] | None:
    workflow_id = str(request.get("workflow_id") or "").strip()
    action_class = str(request.get("action_class") or "").strip()
    for row in as_list(pack.get("workflow_approval_matrix")):
        if not isinstance(row, dict) or str(row.get("workflow_id")) != workflow_id:
            continue
        for action in as_list(row.get("action_approval_requirements")):
            if isinstance(action, dict) and str(action.get("action_class_id")) == action_class:
                return action if action.get("approval_profile_id") else None
    return None


def find_profile(pack: dict[str, Any], request: dict[str, Any]) -> dict[str, Any] | None:
    profile_id = str(request.get("approval_profile_id") or "").strip()
    action_class = str(request.get("action_class") or "").strip()
    for profile in as_list(pack.get("approval_profiles")):
        if not isinstance(profile, dict):
            continue
        if profile_id and str(profile.get("id")) == profile_id:
            return profile
        if action_class and action_class in {str(item) for item in as_list(profile.get("action_class_ids"))}:
            return profile
    return None


def trusted_status(pack: dict[str, Any], request: dict[str, Any]) -> bool:
    statuses = {
        str(item).lower()
        for item in as_dict(pack.get("runtime_policy")).get("trusted_status_values", ["approved"])
    }
    return str(request.get("approval_status") or "").strip().lower() in statuses


def trusted_source(pack: dict[str, Any], request: dict[str, Any]) -> bool:
    source = str(request.get("approval_source") or "").strip()
    if not source:
        return True
    trusted = {
        str(item)
        for item in as_dict(pack.get("runtime_policy")).get("trusted_sources", [])
    }
    untrusted = {
        str(item)
        for item in as_dict(pack.get("runtime_policy")).get("untrusted_sources", [])
    }
    return source in trusted and source not in untrusted


def role_requirements_met(profile: dict[str, Any], request: dict[str, Any]) -> bool:
    required_roles = {str(item) for item in as_list(profile.get("required_roles"))}
    approver_roles = {str(item) for item in as_list(request.get("approver_roles"))}
    if not required_roles:
        return True
    if str(profile.get("role_policy")) == "all_required":
        return required_roles.issubset(approver_roles)
    return bool(required_roles & approver_roles)


def is_negative_decision(value: Any) -> bool:
    decision = str(value or "").strip().lower()
    return decision.startswith(NEGATIVE_PREFIXES) or "_deny" in decision or "_kill" in decision


def kill_reasons(pack: dict[str, Any], profile: dict[str, Any] | None, request: dict[str, Any]) -> list[str]:
    policy = as_dict(pack.get("runtime_policy"))
    kill_indicators = {str(item).strip().lower() for item in as_list(policy.get("kill_signal_indicators"))}
    indicators = {str(item).strip().lower() for item in as_list(request.get("indicators"))}
    reasons: list[str] = []
    for indicator in sorted(kill_indicators & indicators):
        reasons.append(f"kill indicator: {indicator}")
    if request.get("approval_bypass_signal"):
        reasons.append("approval bypass signal was observed")
    if request.get("approval_after_execution"):
        reasons.append("approval was issued after execution began")
    if request.get("approval_reused_across_run"):
        reasons.append("approval was reused across a different run")
    if request.get("cross_tenant_approval_reuse"):
        reasons.append("approval was reused across tenant boundaries")
    if request.get("contains_secret"):
        reasons.append("secret, token, or regulated payload appeared in approval evidence")
    if request.get("token_passthrough"):
        reasons.append("raw token passthrough appeared in approval evidence")
    if profile and profile.get("requires_separation_of_duties"):
        requester = str(request.get("requester_id") or request.get("identity_id") or "").strip()
        approvers = {str(item) for item in as_list(request.get("approver_ids"))}
        if request.get("requester_self_approved") or (requester and requester in approvers):
            reasons.append("requester identity appears in approver set")
    if is_negative_decision(request.get("authorization_decision")) and str(request.get("authorization_decision", "")).startswith("kill"):
        reasons.append("authorization decision returned a kill state")
    return reasons


def missing_required_fields(pack: dict[str, Any], request: dict[str, Any]) -> list[str]:
    required = {
        str(field)
        for field in as_dict(pack.get("approval_contract")).get("required_runtime_fields", [])
    }
    missing: list[str] = []
    for field in sorted(required):
        value = request.get(field)
        if field in {"approver_ids", "approver_roles"}:
            if not as_list(value):
                missing.append(field)
        elif value in (None, "", [], {}):
            missing.append(field)
    return missing


def decision_result(
    *,
    decision: str,
    pack: dict[str, Any],
    profile: dict[str, Any] | None,
    request: dict[str, Any],
    reason: str,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise ApprovalReceiptDecisionError(f"unknown decision {decision!r}")
    return {
        "allowed": decision in ALLOW_DECISIONS,
        "approval_profile": {
            "approval_profile_id": profile.get("id") if profile else request.get("approval_profile_id"),
            "max_ttl_minutes": profile.get("max_ttl_minutes") if profile else None,
            "minimum_approvers": profile.get("minimum_approvers") if profile else None,
            "required_roles": profile.get("required_roles", []) if profile else [],
            "requires_risk_acceptance": profile.get("requires_risk_acceptance") if profile else None,
            "risk_tier": profile.get("risk_tier") if profile else None,
        },
        "decision": decision,
        "evidence": {
            "observed_runtime_attributes": sorted(k for k, v in request.items() if v not in (None, "", [], {}, False)),
            "source_artifacts": pack.get("source_artifacts", {}),
        },
        "pack_generated_at": pack.get("generated_at"),
        "reason": reason,
        "request": {
            "action_class": request.get("action_class"),
            "approval_id": request.get("approval_id"),
            "approval_status": request.get("approval_status"),
            "approval_type": request.get("approval_type"),
            "correlation_id": request.get("correlation_id"),
            "identity_id": request.get("identity_id"),
            "receipt_id": request.get("receipt_id"),
            "requested_scope_hash": request.get("requested_scope_hash"),
            "approved_scope_hash": request.get("approved_scope_hash"),
            "run_id": request.get("run_id"),
            "tenant_id": request.get("tenant_id"),
            "workflow_id": request.get("workflow_id"),
        },
        "violations": violations or [],
    }


def evaluate_agentic_approval_receipt_decision(
    pack: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured approval receipt decision."""
    if not isinstance(pack, dict):
        raise ApprovalReceiptDecisionError("pack must be an object")
    if not isinstance(runtime_request, dict):
        raise ApprovalReceiptDecisionError("runtime_request must be an object")

    request = normalize_request(runtime_request)
    profile = find_profile(pack, request)
    requirement = workflow_action_requirement(pack, request)
    requested_profile_id = str(request.get("approval_profile_id") or "").strip()
    expected_profile_id = str(as_dict(requirement).get("approval_profile_id") or "").strip()

    if requirement and not requested_profile_id:
        profile = find_profile(
            pack,
            {
                **request,
                "approval_profile_id": expected_profile_id,
            },
        )

    reasons = kill_reasons(pack, profile, request)
    if reasons:
        return decision_result(
            decision="kill_session_on_approval_bypass_signal",
            pack=pack,
            profile=profile,
            request=request,
            reason="runtime approval bypass or kill signal was observed",
            violations=reasons,
        )

    if profile is None or requirement is None:
        return decision_result(
            decision="deny_unregistered_approval_profile",
            pack=pack,
            profile=profile,
            request=request,
            reason="workflow and action class do not map to a registered approval profile",
            violations=[
                f"workflow_id={request.get('workflow_id')}",
                f"action_class={request.get('action_class')}",
            ],
        )

    if (
        (requested_profile_id and requested_profile_id != expected_profile_id)
        or str(profile.get("id") or "").strip() != expected_profile_id
    ):
        return decision_result(
            decision="deny_unregistered_approval_profile",
            pack=pack,
            profile=profile,
            request=request,
            reason="approval profile does not match the workflow and action class mapping",
            violations=[
                f"expected_profile_id={expected_profile_id}",
                f"requested_profile_id={requested_profile_id or profile.get('id')}",
            ],
        )

    missing = missing_required_fields(pack, request)
    if missing:
        return decision_result(
            decision="deny_expired_or_untrusted_approval",
            pack=pack,
            profile=profile,
            request=request,
            reason="approval receipt is missing required runtime fields",
            violations=[f"missing {field}" for field in missing],
        )

    if not trusted_status(pack, request) or not trusted_source(pack, request):
        return decision_result(
            decision="deny_expired_or_untrusted_approval",
            pack=pack,
            profile=profile,
            request=request,
            reason="approval status or source is not trusted",
            violations=[
                f"approval_status={request.get('approval_status')}",
                f"approval_source={request.get('approval_source')}",
            ],
        )

    issued_at = parse_time(request.get("issued_at"))
    expires_at = parse_time(request.get("expires_at"))
    now = now_from_request(request)
    if issued_at is None or expires_at is None or expires_at <= now or expires_at <= issued_at:
        return decision_result(
            decision="deny_expired_or_untrusted_approval",
            pack=pack,
            profile=profile,
            request=request,
            reason="approval receipt is expired or has malformed time bounds",
            violations=[f"issued_at={request.get('issued_at')}", f"expires_at={request.get('expires_at')}"],
        )

    if request.get("requested_scope_hash") != request.get("approved_scope_hash"):
        return decision_result(
            decision="deny_scope_mismatch",
            pack=pack,
            profile=profile,
            request=request,
            reason="approved scope hash does not match requested scope hash",
            violations=[
                f"requested_scope_hash={request.get('requested_scope_hash')}",
                f"approved_scope_hash={request.get('approved_scope_hash')}",
            ],
        )

    if len(as_list(request.get("approver_ids"))) < int(profile.get("minimum_approvers") or 1):
        return decision_result(
            decision="hold_for_second_approver",
            pack=pack,
            profile=profile,
            request=request,
            reason="approval receipt lacks the required approver count",
            violations=[f"minimum_approvers={profile.get('minimum_approvers')}"],
        )

    if not role_requirements_met(profile, request):
        return decision_result(
            decision="hold_for_second_approver",
            pack=pack,
            profile=profile,
            request=request,
            reason="approval receipt lacks required approver roles",
            violations=[
                f"required_roles={profile.get('required_roles', [])}",
                f"approver_roles={request.get('approver_roles', [])}",
            ],
        )

    if profile.get("requires_risk_acceptance") and not request.get("risk_acceptance_id"):
        return decision_result(
            decision="hold_for_risk_acceptance",
            pack=pack,
            profile=profile,
            request=request,
            reason="approval profile requires risk acceptance evidence",
            violations=["missing risk_acceptance_id"],
        )

    return decision_result(
        decision="allow_scope_bound_approval",
        pack=pack,
        profile=profile,
        request=request,
        reason="approval receipt is registered, scope-bound, unexpired, role-complete, and linked to run evidence",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--runtime-request", type=Path, help="JSON file containing the runtime approval request.")
    parser.add_argument("--workflow-id")
    parser.add_argument("--action-class")
    parser.add_argument("--approval-profile-id")
    parser.add_argument("--run-id")
    parser.add_argument("--agent-id")
    parser.add_argument("--identity-id")
    parser.add_argument("--tenant-id")
    parser.add_argument("--correlation-id")
    parser.add_argument("--approval-id")
    parser.add_argument("--approval-type")
    parser.add_argument("--approval-status", default="approved")
    parser.add_argument("--approval-source", default="source_host_review")
    parser.add_argument("--approver-id", action="append", default=[])
    parser.add_argument("--approver-role", action="append", default=[])
    parser.add_argument("--requester-id")
    parser.add_argument("--requested-scope-hash")
    parser.add_argument("--approved-scope-hash")
    parser.add_argument("--issued-at")
    parser.add_argument("--expires-at")
    parser.add_argument("--receipt-id")
    parser.add_argument("--policy-pack-hash")
    parser.add_argument("--risk-acceptance-id")
    parser.add_argument("--authorization-decision")
    parser.add_argument("--now")
    parser.add_argument("--indicator", action="append", default=[])
    parser.add_argument("--approval-after-execution", action="store_true")
    parser.add_argument("--approval-bypass-signal", action="store_true")
    parser.add_argument("--approval-reused-across-run", action="store_true")
    parser.add_argument("--contains-secret", action="store_true")
    parser.add_argument("--cross-tenant-approval-reuse", action="store_true")
    parser.add_argument("--requester-self-approved", action="store_true")
    parser.add_argument("--token-passthrough", action="store_true")
    parser.add_argument("--expect-decision")
    return parser.parse_args()


def request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.runtime_request:
        return load_json(args.runtime_request)
    return {
        "action_class": args.action_class,
        "agent_id": args.agent_id,
        "approval_after_execution": args.approval_after_execution,
        "approval_bypass_signal": args.approval_bypass_signal,
        "approval_id": args.approval_id,
        "approval_profile_id": args.approval_profile_id,
        "approval_reused_across_run": args.approval_reused_across_run,
        "approval_source": args.approval_source,
        "approval_status": args.approval_status,
        "approval_type": args.approval_type,
        "approved_scope_hash": args.approved_scope_hash,
        "approver_ids": args.approver_id,
        "approver_roles": args.approver_role,
        "authorization_decision": args.authorization_decision,
        "contains_secret": args.contains_secret,
        "correlation_id": args.correlation_id,
        "cross_tenant_approval_reuse": args.cross_tenant_approval_reuse,
        "expires_at": args.expires_at,
        "identity_id": args.identity_id,
        "indicators": args.indicator,
        "issued_at": args.issued_at,
        "now": args.now,
        "policy_pack_hash": args.policy_pack_hash,
        "receipt_id": args.receipt_id,
        "requested_scope_hash": args.requested_scope_hash,
        "requester_id": args.requester_id,
        "requester_self_approved": args.requester_self_approved,
        "risk_acceptance_id": args.risk_acceptance_id,
        "run_id": args.run_id,
        "tenant_id": args.tenant_id,
        "token_passthrough": args.token_passthrough,
        "workflow_id": args.workflow_id,
    }


def main() -> int:
    args = parse_args()
    try:
        pack = load_json(args.pack)
        result = evaluate_agentic_approval_receipt_decision(pack, request_from_args(args))
    except ApprovalReceiptDecisionError as exc:
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
