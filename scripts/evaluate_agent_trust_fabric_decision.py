#!/usr/bin/env python3
"""Evaluate one Agent Trust Fabric runtime decision.

The evaluator is deterministic. It turns identity, context, scope,
egress, telemetry, receipt, source freshness, approval, and containment
signals into an allow, hold, deny, or kill verdict.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_PACK = Path("data/evidence/agent-trust-fabric-pack.json")

ALLOW_DECISIONS = {"allow_trusted_agent_context"}
VALID_DECISIONS = {
    *ALLOW_DECISIONS,
    "hold_for_trust_evidence",
    "hold_for_step_up",
    "deny_untrusted_agent",
    "kill_session_on_agent_trust_break",
}
TRUST_TIER_ORDER = {"intern": 0, "apprentice": 1, "operator": 2, "principal": 3}


class AgentTrustFabricDecisionError(RuntimeError):
    """Raised when the trust fabric pack or request is invalid."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AgentTrustFabricDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise AgentTrustFabricDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AgentTrustFabricDecisionError(f"{path} root must be a JSON object")
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


def workflows_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("workflow_id")): row
        for row in as_list(pack.get("workflow_trust_matrix"))
        if isinstance(row, dict) and row.get("workflow_id")
    }


def dimensions_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("id")): row
        for row in as_list(pack.get("trust_dimensions"))
        if isinstance(row, dict) and row.get("id")
    }


def tiers_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("id")): row
        for row in as_list(pack.get("trust_tiers"))
        if isinstance(row, dict) and row.get("id")
    }


def has_approval(record: Any) -> bool:
    approval = as_dict(record)
    if not approval:
        return False
    status = str(approval.get("status") or approval.get("decision") or "").strip().lower()
    return bool(approval.get("approval_id") or approval.get("id")) and status in {"approved", "allow", "granted"}


def decision_state(value: Any) -> str:
    return str(value or "").strip().lower()


def is_negative_decision(value: Any) -> bool:
    decision = decision_state(value)
    return decision.startswith("deny") or decision.startswith("kill") or "_deny" in decision or "_kill" in decision


def is_hold_decision(value: Any) -> bool:
    decision = decision_state(value)
    return decision.startswith("hold") or "_hold" in decision or "review_due" in decision or "stale" in decision


def normalize_request(runtime_request: dict[str, Any]) -> dict[str, Any]:
    request = dict(runtime_request)
    for key in ["indicators", "mcp_namespaces", "requested_actions", "data_classes"]:
        request[key] = [str(item) for item in as_list(request.get(key)) if str(item).strip()]
    for key in [
        "context_poisoning_signal",
        "cross_tenant_context_access",
        "external_side_effect",
        "high_impact_action",
        "identity_used_after_revocation",
        "missing_trace_context",
        "prompt_injection_signal",
        "repeated_denied_action",
        "scope_escalation",
        "secret_egress",
        "telemetry_redaction_failure",
        "token_passthrough",
        "untrusted_context",
    ]:
        request[key] = as_bool(request.get(key))
    return request


def required_fields(pack: dict[str, Any]) -> set[str]:
    contract = as_dict(pack.get("trust_contract"))
    return {str(field) for field in as_list(contract.get("required_runtime_fields")) if str(field).strip()}


def missing_required_fields(pack: dict[str, Any], request: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    for field in sorted(required_fields(pack)):
        if field == "approval_id":
            if not has_approval(request.get("human_approval_record")):
                missing.append(field)
            continue
        if not request.get(field):
            missing.append(field)
    return missing


def matched_kill_reasons(pack: dict[str, Any], request: dict[str, Any]) -> list[str]:
    contract = as_dict(pack.get("trust_contract"))
    configured = lower_set(contract.get("kill_signals"))
    indicators = lower_set(request.get("indicators"))
    reasons: list[str] = []

    for indicator in sorted(configured & indicators):
        reasons.append(f"kill indicator: {indicator}")
    if request.get("runtime_kill_signal"):
        reasons.append(f"runtime_kill_signal: {request['runtime_kill_signal']}")
    if request.get("token_passthrough"):
        reasons.append("token passthrough was observed")
    if request.get("identity_used_after_revocation"):
        reasons.append("agent identity was used after revocation")
    if request.get("secret_egress"):
        reasons.append("secret egress was observed")
    if request.get("cross_tenant_context_access"):
        reasons.append("cross-tenant context access was observed")
    if request.get("telemetry_redaction_failure"):
        reasons.append("telemetry redaction failure was observed")
    if request.get("repeated_denied_action"):
        reasons.append("agent repeated an action after a hold or deny")
    if request.get("prompt_injection_signal") and request.get("external_side_effect"):
        reasons.append("prompt-injection signal combined with external side effect")
    if request.get("untrusted_context") and request.get("high_impact_action"):
        reasons.append("untrusted context combined with high-impact autonomy")

    for field in ["authorization_decision", "egress_decision", "action_runtime_decision", "telemetry_decision", "soc_decision"]:
        if decision_state(request.get(field)).startswith("kill") or "_kill" in decision_state(request.get(field)):
            reasons.append(f"{field} returned a kill decision")
    return reasons


def score_dimensions(pack: dict[str, Any], request: dict[str, Any], missing: list[str]) -> tuple[int, list[dict[str, Any]]]:
    dimensions = dimensions_by_id(pack)
    score = 100
    rows: list[dict[str, Any]] = []
    missing_count = len(missing)

    penalties_by_dimension = {
        "identity": 0,
        "context": 0,
        "scope": 0,
        "behavior": 0,
        "data-boundary": 0,
        "containment": 0,
    }

    if missing_count:
        penalties_by_dimension["behavior"] += min(20, missing_count * 3)
    if request.get("identity_used_after_revocation") or is_negative_decision(request.get("authorization_decision")):
        penalties_by_dimension["identity"] += 35
    if request.get("untrusted_context") or request.get("context_poisoning_signal") or is_hold_decision(request.get("source_freshness_decision")):
        penalties_by_dimension["context"] += 20
    if request.get("scope_escalation") or is_hold_decision(request.get("authorization_decision")) or is_hold_decision(request.get("action_runtime_decision")):
        penalties_by_dimension["scope"] += 16
    if request.get("missing_trace_context") or is_hold_decision(request.get("telemetry_decision")):
        penalties_by_dimension["behavior"] += 14
    if request.get("secret_egress") or request.get("cross_tenant_context_access") or is_negative_decision(request.get("egress_decision")):
        penalties_by_dimension["data-boundary"] += 30
    if is_negative_decision(request.get("soc_decision")) or request.get("runtime_kill_signal"):
        penalties_by_dimension["containment"] += 25

    for dimension_id, dimension in dimensions.items():
        weight = int(dimension.get("weight") or 0)
        penalty = min(weight, penalties_by_dimension.get(dimension_id, 0))
        score -= penalty
        rows.append(
            {
                "dimension_id": dimension_id,
                "max_points": weight,
                "observed_penalty": penalty,
                "score": max(weight - penalty, 0),
                "title": dimension.get("title"),
            }
        )

    return max(min(score, 100), 0), rows


def requested_tier_allowed(pack: dict[str, Any], workflow: dict[str, Any] | None, request: dict[str, Any], score: int) -> tuple[bool, list[str]]:
    tiers = tiers_by_id(pack)
    requested = str(request.get("requested_trust_tier") or "").strip() or "intern"
    default = str((workflow or {}).get("default_trust_tier") or "intern")
    requested_rank = TRUST_TIER_ORDER.get(requested, -1)
    default_rank = TRUST_TIER_ORDER.get(default, -1)
    tier = tiers.get(requested)
    reasons: list[str] = []

    if requested_rank < 0:
        return False, [f"unknown requested_trust_tier: {requested}"]
    if tier and score < int(tier.get("minimum_score") or 0):
        reasons.append(f"score {score} below tier minimum {tier.get('minimum_score')} for {requested}")
    if requested_rank > default_rank and not has_approval(request.get("human_approval_record")):
        reasons.append(f"requested tier {requested} exceeds workflow default {default} without approval")
    if requested in {"operator", "principal"} and not has_approval(request.get("human_approval_record")):
        reasons.append(f"{requested} tier requires linked approval")
    if requested == "principal" and not request.get("risk_acceptance_id"):
        reasons.append("principal tier requires separate risk_acceptance_id")
    return not reasons, reasons


def decision_result(
    *,
    decision: str,
    pack: dict[str, Any],
    request: dict[str, Any],
    workflow: dict[str, Any] | None,
    score: int,
    dimensions: list[dict[str, Any]],
    reason: str,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise AgentTrustFabricDecisionError(f"unknown decision {decision!r}")
    return {
        "allowed": decision in ALLOW_DECISIONS,
        "decision": decision,
        "dimension_scores": dimensions,
        "evidence": {
            "observed_runtime_attributes": sorted(k for k, v in request.items() if v not in (None, "", [], {}, False)),
            "required_runtime_fields": sorted(required_fields(pack)),
            "source_artifacts": pack.get("source_artifacts", {}),
        },
        "pack_generated_at": pack.get("generated_at"),
        "reason": reason,
        "request": {
            "agent_id": request.get("agent_id"),
            "correlation_id": request.get("correlation_id"),
            "identity_id": request.get("identity_id"),
            "requested_trust_tier": request.get("requested_trust_tier"),
            "run_id": request.get("run_id"),
            "tenant_id": request.get("tenant_id"),
            "trust_event_id": request.get("trust_event_id"),
            "workflow_id": request.get("workflow_id"),
        },
        "trust_score": score,
        "violations": violations or [],
        "workflow": {
            "default_trust_tier": workflow.get("default_trust_tier") if workflow else None,
            "risk_flags": workflow.get("risk_flags", []) if workflow else [],
            "title": workflow.get("title") if workflow else None,
            "workflow_id": workflow.get("workflow_id") if workflow else request.get("workflow_id"),
        },
    }


def evaluate_agent_trust_fabric_decision(pack: dict[str, Any], runtime_request: dict[str, Any]) -> dict[str, Any]:
    """Return an Agent Trust Fabric allow, hold, deny, or kill decision."""
    if not isinstance(pack, dict):
        raise AgentTrustFabricDecisionError("pack must be an object")
    if not isinstance(runtime_request, dict):
        raise AgentTrustFabricDecisionError("runtime_request must be an object")

    request = normalize_request(runtime_request)
    workflows = workflows_by_id(pack)
    workflow = workflows.get(str(request.get("workflow_id") or ""))
    missing = missing_required_fields(pack, request)
    score, dimensions = score_dimensions(pack, request, missing)
    thresholds = as_dict(as_dict(pack.get("trust_contract")).get("score_thresholds"))

    kill_reasons = matched_kill_reasons(pack, request)
    if kill_reasons:
        return decision_result(
            decision="kill_session_on_agent_trust_break",
            pack=pack,
            request=request,
            workflow=workflow,
            score=score,
            dimensions=dimensions,
            reason="runtime kill-class trust signal was observed",
            violations=kill_reasons,
        )

    if workflow is None:
        return decision_result(
            decision="deny_untrusted_agent",
            pack=pack,
            request=request,
            workflow=None,
            score=min(score, 49),
            dimensions=dimensions,
            reason="workflow is not registered in the generated Agent Trust Fabric matrix",
            violations=[f"unknown workflow_id: {request.get('workflow_id')}"],
        )

    if missing:
        return decision_result(
            decision="hold_for_trust_evidence",
            pack=pack,
            request=request,
            workflow=workflow,
            score=score,
            dimensions=dimensions,
            reason="required trust-fabric runtime evidence is missing",
            violations=[f"missing {field}" for field in missing],
        )

    tier_ok, tier_reasons = requested_tier_allowed(pack, workflow, request, score)
    if not tier_ok:
        return decision_result(
            decision="hold_for_step_up",
            pack=pack,
            request=request,
            workflow=workflow,
            score=score,
            dimensions=dimensions,
            reason="requested trust tier requires step-up approval or stronger evidence",
            violations=tier_reasons,
        )

    negative = [
        field
        for field in ["authorization_decision", "egress_decision", "action_runtime_decision", "telemetry_decision", "soc_decision"]
        if is_negative_decision(request.get(field))
    ]
    if negative:
        return decision_result(
            decision="deny_untrusted_agent",
            pack=pack,
            request=request,
            workflow=workflow,
            score=score,
            dimensions=dimensions,
            reason="linked policy, authorization, egress, telemetry, action, or SOC decision denied trust",
            violations=[f"{field}={request.get(field)}" for field in negative],
        )

    holds = [
        field
        for field in ["authorization_decision", "egress_decision", "action_runtime_decision", "telemetry_decision", "source_freshness_decision"]
        if is_hold_decision(request.get(field))
    ]
    if holds:
        return decision_result(
            decision="hold_for_step_up",
            pack=pack,
            request=request,
            workflow=workflow,
            score=score,
            dimensions=dimensions,
            reason="linked control asked for review or step-up before trusting the agent",
            violations=[f"{field}={request.get(field)}" for field in holds],
        )

    deny_threshold = int(thresholds.get("deny_untrusted_agent") or 50)
    hold_threshold = int(thresholds.get("hold_for_step_up") or 70)
    allow_threshold = int(thresholds.get("allow_trusted_agent_context") or 85)
    if score < deny_threshold:
        decision = "deny_untrusted_agent"
    elif score < hold_threshold:
        decision = "hold_for_trust_evidence"
    elif score < allow_threshold:
        decision = "hold_for_step_up"
    else:
        decision = "allow_trusted_agent_context"

    return decision_result(
        decision=decision,
        pack=pack,
        request=request,
        workflow=workflow,
        score=score,
        dimensions=dimensions,
        reason="trust-fabric score and required runtime evidence were evaluated",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--runtime-request", type=Path, help="JSON file containing the runtime trust request.")
    parser.add_argument("--workflow-id")
    parser.add_argument("--run-id")
    parser.add_argument("--agent-id")
    parser.add_argument("--identity-id")
    parser.add_argument("--tenant-id")
    parser.add_argument("--correlation-id")
    parser.add_argument("--trust-event-id")
    parser.add_argument("--requested-trust-tier", default="operator")
    parser.add_argument("--intent-summary")
    parser.add_argument("--context-package-hash")
    parser.add_argument("--policy-pack-hash")
    parser.add_argument("--authorization-decision")
    parser.add_argument("--egress-decision")
    parser.add_argument("--action-runtime-decision")
    parser.add_argument("--telemetry-decision")
    parser.add_argument("--soc-decision")
    parser.add_argument("--telemetry-event-id")
    parser.add_argument("--receipt-id")
    parser.add_argument("--source-freshness-decision")
    parser.add_argument("--approval-id")
    parser.add_argument("--approval-status")
    parser.add_argument("--risk-acceptance-id")
    parser.add_argument("--runtime-kill-signal")
    parser.add_argument("--indicator", action="append", default=[])
    parser.add_argument("--mcp-namespace", action="append", default=[])
    parser.add_argument("--requested-action", action="append", default=[])
    parser.add_argument("--data-class", action="append", default=[])
    parser.add_argument("--context-poisoning-signal", action="store_true")
    parser.add_argument("--cross-tenant-context-access", action="store_true")
    parser.add_argument("--external-side-effect", action="store_true")
    parser.add_argument("--high-impact-action", action="store_true")
    parser.add_argument("--identity-used-after-revocation", action="store_true")
    parser.add_argument("--missing-trace-context", action="store_true")
    parser.add_argument("--prompt-injection-signal", action="store_true")
    parser.add_argument("--repeated-denied-action", action="store_true")
    parser.add_argument("--scope-escalation", action="store_true")
    parser.add_argument("--secret-egress", action="store_true")
    parser.add_argument("--telemetry-redaction-failure", action="store_true")
    parser.add_argument("--token-passthrough", action="store_true")
    parser.add_argument("--untrusted-context", action="store_true")
    parser.add_argument("--expect-decision")
    return parser.parse_args()


def request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.runtime_request:
        return load_json(args.runtime_request)
    request: dict[str, Any] = {
        "action_runtime_decision": args.action_runtime_decision,
        "agent_id": args.agent_id,
        "authorization_decision": args.authorization_decision,
        "context_package_hash": args.context_package_hash,
        "context_poisoning_signal": args.context_poisoning_signal,
        "correlation_id": args.correlation_id,
        "cross_tenant_context_access": args.cross_tenant_context_access,
        "data_classes": args.data_class,
        "egress_decision": args.egress_decision,
        "external_side_effect": args.external_side_effect,
        "high_impact_action": args.high_impact_action,
        "identity_id": args.identity_id,
        "identity_used_after_revocation": args.identity_used_after_revocation,
        "indicators": args.indicator,
        "intent_summary": args.intent_summary,
        "mcp_namespaces": args.mcp_namespace,
        "missing_trace_context": args.missing_trace_context,
        "policy_pack_hash": args.policy_pack_hash,
        "prompt_injection_signal": args.prompt_injection_signal,
        "receipt_id": args.receipt_id,
        "repeated_denied_action": args.repeated_denied_action,
        "requested_actions": args.requested_action,
        "requested_trust_tier": args.requested_trust_tier,
        "risk_acceptance_id": args.risk_acceptance_id,
        "run_id": args.run_id,
        "runtime_kill_signal": args.runtime_kill_signal,
        "scope_escalation": args.scope_escalation,
        "secret_egress": args.secret_egress,
        "soc_decision": args.soc_decision,
        "source_freshness_decision": args.source_freshness_decision,
        "telemetry_decision": args.telemetry_decision,
        "telemetry_event_id": args.telemetry_event_id,
        "telemetry_redaction_failure": args.telemetry_redaction_failure,
        "tenant_id": args.tenant_id,
        "token_passthrough": args.token_passthrough,
        "trust_event_id": args.trust_event_id,
        "untrusted_context": args.untrusted_context,
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
        result = evaluate_agent_trust_fabric_decision(pack, request_from_args(args))
    except AgentTrustFabricDecisionError as exc:
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
