#!/usr/bin/env python3
"""Evaluate one agentic entitlement decision.

The evaluator is deterministic. It checks whether a non-human agent
identity still has an active, unexpired, reviewed entitlement for a
specific workflow, MCP namespace, and access mode before a gateway or
agent host forwards the request. MCP 2026-07-28 Security Best Practices
name Scope Minimization as a first-class attack: a server that exposes
every scope in scopes_supported and a client that requests them all
mints an omnibus token. Stolen files:*, db:*, or admin:* grants enable
lateral access and privilege chaining without a further elevation
prompt. This evaluator kills those omnibus token scopes and holds a
full-catalog initial grant that was not down-scoped for a targeted
WWW-Authenticate challenge. Unspecified token-scope evidence stays on
the prior path so existing CLI and CI admission checks remain valid.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_PACK = Path("data/evidence/agentic-entitlement-review-pack.json")

ALLOW_DECISIONS = {"allow_active_entitlement"}
VALID_DECISIONS = {
    *ALLOW_DECISIONS,
    "hold_for_access_review",
    "hold_for_step_up_authorization",
    "deny_unregistered_entitlement",
    "deny_expired_or_missing_lease",
    "kill_session_on_entitlement_signal",
}
NEGATIVE_PREFIXES = ("deny", "kill")
OMNIBUS_TOKEN_SCOPES = {
    "*",
    "all",
    "full-access",
    "files:*",
    "db:*",
    "admin:*",
}
OMNIBUS_TOKEN_SCOPE_PREFIXES = ("files:", "db:", "admin:")


class EntitlementDecisionError(RuntimeError):
    """Raised when the entitlement pack or request is invalid."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise EntitlementDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise EntitlementDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise EntitlementDecisionError(f"{path} root must be a JSON object")
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


def entitlements(pack: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in as_list(pack.get("entitlements")) if isinstance(row, dict)]


def find_entitlement(pack: dict[str, Any], request: dict[str, Any]) -> dict[str, Any] | None:
    entitlement_id = str(request.get("entitlement_id") or "").strip()
    if entitlement_id:
        for entitlement in entitlements(pack):
            if str(entitlement.get("entitlement_id")) == entitlement_id:
                return entitlement

    identity_id = str(request.get("identity_id") or "").strip()
    workflow_id = str(request.get("workflow_id") or "").strip()
    namespace = str(request.get("namespace") or "").strip()
    requested_access_mode = str(request.get("requested_access_mode") or "").strip()
    for entitlement in entitlements(pack):
        if (
            str(entitlement.get("identity_id")) == identity_id
            and str(entitlement.get("workflow_id")) == workflow_id
            and str(entitlement.get("namespace")) == namespace
            and str(entitlement.get("access_mode")) == requested_access_mode
        ):
            return entitlement
    return None


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


def has_approval(record: Any) -> bool:
    approval = as_dict(record)
    if not approval:
        return False
    status = str(approval.get("status") or approval.get("decision") or "").strip().lower()
    return bool(approval.get("approval_id") or approval.get("id")) and status in {"approved", "allow", "granted"}


def is_allowed_authorization(value: Any, pack: dict[str, Any]) -> bool:
    decision = str(value or "").strip().lower()
    prefixes = [
        str(prefix).lower()
        for prefix in as_dict(pack.get("runtime_policy")).get("authorization_allow_prefixes", ["allow"])
    ]
    return bool(decision) and any(decision.startswith(prefix) for prefix in prefixes)


def is_negative_decision(value: Any) -> bool:
    decision = str(value or "").strip().lower()
    return decision.startswith(NEGATIVE_PREFIXES) or "_deny" in decision or "_kill" in decision


def normalize_request(runtime_request: dict[str, Any]) -> dict[str, Any]:
    request = dict(runtime_request)
    for key in [
        "contains_secret",
        "cross_tenant_entitlement",
        "downscoped_grant",
        "identity_used_after_revocation",
        "initial_grant",
        "repeated_denied_entitlement",
        "scope_escalation",
        "token_passthrough",
    ]:
        request[key] = as_bool(request.get(key))
    request["indicators"] = [str(item).strip().lower() for item in as_list(request.get("indicators")) if str(item).strip()]
    for key in ("token_scopes", "requested_scopes", "scopes_supported", "scope_challenge"):
        request[key] = normalize_scopes(request.get(key))
    return request


def normalize_scopes(value: Any) -> list[str]:
    return [str(item).strip() for item in as_list(value) if str(item).strip()]


def is_omnibus_token_scope(scope: str) -> bool:
    text = scope.strip().lower()
    if text in OMNIBUS_TOKEN_SCOPES:
        return True
    return any(text.startswith(prefix) and text.endswith("*") for prefix in OMNIBUS_TOKEN_SCOPE_PREFIXES)


def omnibus_token_scope_kill_violations(request: dict[str, Any]) -> list[str]:
    """Return kill reasons for wildcard or omnibus token scopes.

    Unspecified token_scopes stay on the prior path. Named MCP Scope
    Minimization grants such as files:*, db:*, admin:*, *, all, and
    full-access are kill signals because a stolen token then enables
    lateral data access and privilege chaining without a further
    elevation prompt.
    """
    return [
        f"omnibus token scope {scope}"
        for scope in request.get("token_scopes") or []
        if is_omnibus_token_scope(str(scope))
    ]


def full_catalog_initial_grant_hold_violations(request: dict[str, Any]) -> list[str]:
    """Return holds for a full-catalog initial grant that was not down-scoped.

    MCP servers should emit a targeted WWW-Authenticate scope challenge
    instead of minting every scopes_supported value up front. Unspecified
    requested_scopes or scopes_supported stay on the prior path. A
    down-scoped grant, a non-initial grant, or a targeted scope_challenge
    does not take this hold.
    """
    requested = {scope.lower() for scope in request.get("requested_scopes") or []}
    supported = {scope.lower() for scope in request.get("scopes_supported") or []}
    if not requested or not supported:
        return []
    if not request.get("initial_grant"):
        return []
    if request.get("downscoped_grant"):
        return []
    if request.get("scope_challenge"):
        return []
    if requested < supported:
        return []
    return [
        "initial grant requested the full scopes_supported catalog without a down-scoped grant; "
        "hold for a targeted WWW-Authenticate scope challenge"
    ]


def kill_reasons(pack: dict[str, Any], request: dict[str, Any]) -> list[str]:
    policy = as_dict(pack.get("runtime_policy"))
    kill_indicators = {str(item).strip().lower() for item in as_list(policy.get("kill_signal_indicators"))}
    indicators = set(request.get("indicators") or [])
    reasons: list[str] = []
    for indicator in sorted(kill_indicators & indicators):
        reasons.append(f"kill indicator: {indicator}")
    if str(request.get("lease_status", "")).lower() == "revoked":
        reasons.append("entitlement lease is revoked")
    if request.get("contains_secret"):
        reasons.append("secret, token, or regulated payload was observed in the entitlement envelope")
    if request.get("token_passthrough"):
        reasons.append("raw token passthrough was observed")
    if request.get("identity_used_after_revocation"):
        reasons.append("identity was used after revocation")
    if request.get("scope_escalation"):
        reasons.append("scope escalation was requested outside the lease")
    if request.get("cross_tenant_entitlement"):
        reasons.append("cross-tenant entitlement was requested")
    if request.get("repeated_denied_entitlement"):
        reasons.append("agent repeated an entitlement request after denial")
    if is_negative_decision(request.get("authorization_decision")) and str(request.get("authorization_decision", "")).lower().startswith("kill"):
        reasons.append("authorization decision returned a kill state")
    reasons.extend(omnibus_token_scope_kill_violations(request))
    return reasons


def missing_runtime_evidence(pack: dict[str, Any], entitlement: dict[str, Any] | None, request: dict[str, Any]) -> list[str]:
    required = {
        str(field)
        for field in as_dict(pack.get("review_contract")).get("required_runtime_fields", [])
    }
    if entitlement:
        required.update(str(field) for field in as_list(entitlement.get("required_evidence")))
    missing: list[str] = []
    for field in sorted(required):
        if field == "human_approval_record":
            if not has_approval(request.get("human_approval_record")):
                missing.append(field)
            continue
        if field == "agent_class":
            if entitlement and entitlement.get("agent_class"):
                continue
        if field == "entitlement_id":
            if entitlement and entitlement.get("entitlement_id"):
                continue
        if not request.get(field):
            missing.append(field)
    return missing


def decision_result(
    *,
    decision: str,
    pack: dict[str, Any],
    request: dict[str, Any],
    entitlement: dict[str, Any] | None,
    reason: str,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise EntitlementDecisionError(f"unknown decision {decision!r}")
    return {
        "allowed": decision in ALLOW_DECISIONS,
        "decision": decision,
        "entitlement": {
            "access_mode": entitlement.get("access_mode") if entitlement else None,
            "entitlement_id": entitlement.get("entitlement_id") if entitlement else request.get("entitlement_id"),
            "identity_id": entitlement.get("identity_id") if entitlement else request.get("identity_id"),
            "namespace": entitlement.get("namespace") if entitlement else request.get("namespace"),
            "requires_human_approval": entitlement.get("requires_human_approval") if entitlement else None,
            "risk_tier": entitlement.get("risk_tier") if entitlement else None,
            "tier_id": entitlement.get("tier_id") if entitlement else None,
            "workflow_id": entitlement.get("workflow_id") if entitlement else request.get("workflow_id"),
        },
        "evidence": {
            "observed_runtime_attributes": sorted(k for k, v in request.items() if v not in (None, "", [], {}, False)),
            "required_evidence": entitlement.get("required_evidence", []) if entitlement else [],
            "source_artifacts": pack.get("source_artifacts", {}),
        },
        "pack_generated_at": pack.get("generated_at"),
        "reason": reason,
        "request": {
            "authorization_decision": request.get("authorization_decision"),
            "downscoped_grant": request.get("downscoped_grant"),
            "identity_id": request.get("identity_id"),
            "initial_grant": request.get("initial_grant"),
            "lease_id": request.get("lease_id"),
            "lease_status": request.get("lease_status"),
            "namespace": request.get("namespace"),
            "requested_access_mode": request.get("requested_access_mode"),
            "requested_scopes": request.get("requested_scopes", []),
            "review_status": request.get("review_status"),
            "run_id": request.get("run_id"),
            "scope_challenge": request.get("scope_challenge", []),
            "scopes_supported": request.get("scopes_supported", []),
            "tenant_id": request.get("tenant_id"),
            "token_scopes": request.get("token_scopes", []),
            "workflow_id": request.get("workflow_id"),
        },
        "violations": violations or [],
    }


def evaluate_agentic_entitlement_decision(
    pack: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured agentic entitlement decision."""
    if not isinstance(pack, dict):
        raise EntitlementDecisionError("pack must be an object")
    if not isinstance(runtime_request, dict):
        raise EntitlementDecisionError("runtime_request must be an object")

    request = normalize_request(runtime_request)
    entitlement = find_entitlement(pack, request)

    reasons = kill_reasons(pack, request)
    if reasons:
        return decision_result(
            decision="kill_session_on_entitlement_signal",
            pack=pack,
            request=request,
            entitlement=entitlement,
            reason="runtime entitlement kill signal was observed",
            violations=reasons,
        )

    if entitlement is None:
        return decision_result(
            decision="deny_unregistered_entitlement",
            pack=pack,
            request=request,
            entitlement=None,
            reason="identity, workflow, namespace, or requested access mode is not registered",
            violations=[
                f"identity_id={request.get('identity_id')}",
                f"workflow_id={request.get('workflow_id')}",
                f"namespace={request.get('namespace')}",
                f"requested_access_mode={request.get('requested_access_mode')}",
            ],
        )

    lease_status = str(request.get("lease_status") or "").strip().lower()
    expires_at = parse_time(request.get("lease_expires_at"))
    if lease_status in {"", "missing", "expired"} or not request.get("lease_id") or expires_at is None:
        return decision_result(
            decision="deny_expired_or_missing_lease",
            pack=pack,
            request=request,
            entitlement=entitlement,
            reason="entitlement lease is missing, expired, or malformed",
            violations=["missing or expired lease_id/lease_expires_at"],
        )
    if expires_at <= now_from_request(request):
        return decision_result(
            decision="deny_expired_or_missing_lease",
            pack=pack,
            request=request,
            entitlement=entitlement,
            reason="entitlement lease expired before the request time",
            violations=[f"lease_expires_at={request.get('lease_expires_at')}"],
        )

    if not is_allowed_authorization(request.get("authorization_decision"), pack):
        return decision_result(
            decision="hold_for_step_up_authorization",
            pack=pack,
            request=request,
            entitlement=entitlement,
            reason="authorization decision is missing or does not allow this entitlement",
            violations=[f"authorization_decision={request.get('authorization_decision')}"],
        )

    review_status = str(request.get("review_status") or "").strip().lower()
    if review_status in {"due", "overdue", "suspended", ""}:
        return decision_result(
            decision="hold_for_access_review",
            pack=pack,
            request=request,
            entitlement=entitlement,
            reason="entitlement access review is not current",
            violations=[f"review_status={review_status or 'missing'}"],
        )

    missing = missing_runtime_evidence(pack, entitlement, request)
    missing_without_approval = [field for field in missing if field not in {"human_approval_record", "risk_acceptance_id"}]
    if missing_without_approval:
        return decision_result(
            decision="hold_for_access_review",
            pack=pack,
            request=request,
            entitlement=entitlement,
            reason="required entitlement evidence is missing",
            violations=[f"missing {field}" for field in missing_without_approval],
        )

    if entitlement.get("requires_human_approval") and not has_approval(request.get("human_approval_record")):
        return decision_result(
            decision="hold_for_access_review",
            pack=pack,
            request=request,
            entitlement=entitlement,
            reason="privileged entitlement requires a linked human approval",
            violations=["missing human_approval_record"],
        )

    if entitlement.get("risk_tier") in {"high", "critical"} and not request.get("risk_acceptance_id"):
        return decision_result(
            decision="hold_for_step_up_authorization",
            pack=pack,
            request=request,
            entitlement=entitlement,
            reason="high-risk entitlement requires risk acceptance evidence",
            violations=["missing risk_acceptance_id"],
        )

    catalog_holds = full_catalog_initial_grant_hold_violations(request)
    if catalog_holds:
        return decision_result(
            decision="hold_for_step_up_authorization",
            pack=pack,
            request=request,
            entitlement=entitlement,
            reason="initial grant requested the full MCP scopes_supported catalog without a down-scoped grant",
            violations=catalog_holds,
        )

    return decision_result(
        decision="allow_active_entitlement",
        pack=pack,
        request=request,
        entitlement=entitlement,
        reason="entitlement is registered, leased, reviewed, authorized, and free of kill signals",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--runtime-request", type=Path, help="JSON file containing the runtime entitlement request.")
    parser.add_argument("--identity-id")
    parser.add_argument("--workflow-id")
    parser.add_argument("--agent-class")
    parser.add_argument("--namespace")
    parser.add_argument("--requested-access-mode")
    parser.add_argument("--entitlement-id")
    parser.add_argument("--lease-id")
    parser.add_argument("--lease-status", default="active")
    parser.add_argument("--lease-expires-at")
    parser.add_argument("--review-status", default="current")
    parser.add_argument("--authorization-decision")
    parser.add_argument("--run-id")
    parser.add_argument("--tenant-id")
    parser.add_argument("--correlation-id")
    parser.add_argument("--receipt-id")
    parser.add_argument("--policy-pack-hash")
    parser.add_argument("--risk-acceptance-id")
    parser.add_argument("--approval-id")
    parser.add_argument("--approval-status")
    parser.add_argument("--now")
    parser.add_argument("--indicator", action="append", default=[])
    parser.add_argument("--token-scope", action="append", default=[], dest="token_scopes")
    parser.add_argument("--requested-scope", action="append", default=[], dest="requested_scopes")
    parser.add_argument("--scopes-supported", action="append", default=[], dest="scopes_supported")
    parser.add_argument("--scope-challenge", action="append", default=[], dest="scope_challenge")
    parser.add_argument("--contains-secret", action="store_true")
    parser.add_argument("--cross-tenant-entitlement", action="store_true")
    parser.add_argument("--downscoped-grant", action="store_true")
    parser.add_argument("--identity-used-after-revocation", action="store_true")
    parser.add_argument("--initial-grant", action="store_true")
    parser.add_argument("--repeated-denied-entitlement", action="store_true")
    parser.add_argument("--scope-escalation", action="store_true")
    parser.add_argument("--token-passthrough", action="store_true")
    parser.add_argument("--expect-decision")
    return parser.parse_args()


def request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.runtime_request:
        return load_json(args.runtime_request)
    request: dict[str, Any] = {
        "agent_class": args.agent_class,
        "authorization_decision": args.authorization_decision,
        "contains_secret": args.contains_secret,
        "correlation_id": args.correlation_id,
        "cross_tenant_entitlement": args.cross_tenant_entitlement,
        "downscoped_grant": args.downscoped_grant,
        "entitlement_id": args.entitlement_id,
        "identity_id": args.identity_id,
        "identity_used_after_revocation": args.identity_used_after_revocation,
        "indicators": args.indicator,
        "initial_grant": args.initial_grant,
        "lease_expires_at": args.lease_expires_at,
        "lease_id": args.lease_id,
        "lease_status": args.lease_status,
        "namespace": args.namespace,
        "now": args.now,
        "policy_pack_hash": args.policy_pack_hash,
        "receipt_id": args.receipt_id,
        "repeated_denied_entitlement": args.repeated_denied_entitlement,
        "requested_access_mode": args.requested_access_mode,
        "requested_scopes": args.requested_scopes,
        "review_status": args.review_status,
        "risk_acceptance_id": args.risk_acceptance_id,
        "run_id": args.run_id,
        "scope_challenge": args.scope_challenge,
        "scope_escalation": args.scope_escalation,
        "scopes_supported": args.scopes_supported,
        "tenant_id": args.tenant_id,
        "token_passthrough": args.token_passthrough,
        "token_scopes": args.token_scopes,
        "workflow_id": args.workflow_id,
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
        result = evaluate_agentic_entitlement_decision(pack, request_from_args(args))
    except EntitlementDecisionError as exc:
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
