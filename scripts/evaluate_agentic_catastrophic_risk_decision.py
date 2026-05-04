#!/usr/bin/env python3
"""Evaluate one catastrophic-risk runtime decision.

The evaluator is deterministic. It does not infer whether a high-impact
agent action is acceptable; it checks the generated catastrophic-risk
annex for high-impact action classes, required evidence, approval state,
kill signals, and severe-risk flags before allowing a workflow to proceed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_ANNEX = Path("data/evidence/agentic-catastrophic-risk-annex.json")
ALLOW_DECISIONS = {
    "allow_bounded_agent_action",
    "allow_reviewed_high_impact_action",
}
VALID_DECISIONS = {
    *ALLOW_DECISIONS,
    "hold_for_catastrophic_risk_review",
    "deny_unbounded_autonomy",
    "kill_session_on_catastrophic_signal",
}


class CatastrophicRiskDecisionError(RuntimeError):
    """Raised when the annex or runtime request cannot be parsed."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CatastrophicRiskDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise CatastrophicRiskDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise CatastrophicRiskDecisionError(f"{path} root must be a JSON object")
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
    return {str(item).strip() for item in as_list(values) if str(item).strip()}


def approval_present(value: Any) -> bool:
    record = as_dict(value)
    if not record:
        return False
    status = str(record.get("status") or record.get("decision") or "").lower()
    return bool(record.get("approval_id") or record.get("id")) and status in {"approved", "allow", "granted"}


def scenarios_for_request(annex: dict[str, Any], request: dict[str, Any]) -> list[dict[str, Any]]:
    action_class = str(request.get("action_class") or "").strip()
    flags = {key for key, value in request.items() if as_bool(value)}
    matched: list[dict[str, Any]] = []
    for scenario in as_list(annex.get("catastrophic_scenarios")):
        if not isinstance(scenario, dict):
            continue
        triggers = lower_set(scenario.get("trigger_action_classes"))
        if action_class and action_class in triggers:
            matched.append(scenario)
            continue
        scenario_id = str(scenario.get("id") or "")
        if scenario_id == "private-context-exfiltration" and {"handles_secrets", "handles_unredacted_pii", "writes_public_corpus"} & flags:
            matched.append(scenario)
        elif scenario_id == "irreversible-financial-or-critical-action" and {"can_move_funds", "can_delete_data"} & flags:
            matched.append(scenario)
        elif scenario_id == "loss-of-human-oversight" and {"can_deploy", "can_modify_identity", "affects_prod"} & flags:
            matched.append(scenario)
        elif scenario_id == "uncontrolled-system-behavior" and int(request.get("observed_loop_count") or 0) > int(request.get("max_loop_count") or 3):
            matched.append(scenario)
    return matched


def scenario_preview(scenario: dict[str, Any]) -> dict[str, Any]:
    return {
        "default_decision": scenario.get("default_decision"),
        "id": scenario.get("id"),
        "impact_domain": scenario.get("impact_domain"),
        "promotion_gate": scenario.get("promotion_gate"),
        "status": scenario.get("status"),
        "title": scenario.get("title"),
    }


def decision_result(
    *,
    annex: dict[str, Any],
    decision: str,
    reason: str,
    request: dict[str, Any],
    matched_scenarios: list[dict[str, Any]] | None = None,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise CatastrophicRiskDecisionError(f"unknown decision {decision!r}")
    return {
        "allowed": decision in ALLOW_DECISIONS,
        "annex_generated_at": annex.get("generated_at"),
        "decision": decision,
        "evidence": {
            "observed_runtime_attributes": sorted(k for k, v in request.items() if v not in (None, "", [], {}, False)),
            "required_high_impact_fields": annex.get("runtime_decision_contract", {}).get("required_high_impact_fields", []),
            "source_artifacts": annex.get("source_artifacts"),
        },
        "matched_scenarios": [scenario_preview(scenario) for scenario in matched_scenarios or []],
        "reason": reason,
        "request": {
            "action_class": request.get("action_class"),
            "agent_id": request.get("agent_id"),
            "authorization_decision": request.get("authorization_decision"),
            "correlation_id": request.get("correlation_id"),
            "egress_decision": request.get("egress_decision"),
            "handoff_decision": request.get("handoff_decision"),
            "identity_id": request.get("identity_id"),
            "impact_domain": request.get("impact_domain"),
            "readiness_decision": request.get("readiness_decision"),
            "receipt_id": request.get("receipt_id"),
            "residual_risk_tier": request.get("residual_risk_tier"),
            "risk_acceptance_id": request.get("risk_acceptance_id"),
            "run_id": request.get("run_id"),
            "tenant_id": request.get("tenant_id"),
            "workflow_id": request.get("workflow_id"),
        },
        "violations": violations or [],
    }


def evaluate_agentic_catastrophic_risk_decision(
    annex: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured runtime decision for one high-impact action."""
    if not isinstance(annex, dict):
        raise CatastrophicRiskDecisionError("annex must be an object")
    if not isinstance(runtime_request, dict):
        raise CatastrophicRiskDecisionError("runtime_request must be an object")

    request = dict(runtime_request)
    request["action_class"] = str(request.get("action_class") or "").strip()
    request["authorization_decision"] = str(request.get("authorization_decision") or "").strip()
    request["egress_decision"] = str(request.get("egress_decision") or "").strip()
    request["handoff_decision"] = str(request.get("handoff_decision") or "").strip()
    request["readiness_decision"] = str(request.get("readiness_decision") or "").strip()
    request["residual_risk_tier"] = str(request.get("residual_risk_tier") or "").strip().lower()
    request["runtime_kill_signal"] = str(request.get("runtime_kill_signal") or "").strip()

    for key in annex.get("runtime_decision_contract", {}).get("catastrophic_flags", []) or []:
        request[str(key)] = as_bool(request.get(str(key)))

    try:
        request["observed_loop_count"] = int(request.get("observed_loop_count") or 0)
    except (TypeError, ValueError):
        request["observed_loop_count"] = 0
    try:
        request["max_loop_count"] = int(request.get("max_loop_count") or 3)
    except (TypeError, ValueError):
        request["max_loop_count"] = 3

    matched = scenarios_for_request(annex, request)
    contract = annex.get("runtime_decision_contract", {}) if isinstance(annex.get("runtime_decision_contract"), dict) else {}
    high_impact_actions = lower_set(contract.get("high_impact_action_classes"))
    catastrophic_flags = lower_set(contract.get("catastrophic_flags"))
    active_flags = sorted(flag for flag in catastrophic_flags if as_bool(request.get(flag)))
    is_high_impact = request["action_class"] in high_impact_actions or bool(active_flags)

    if request["runtime_kill_signal"]:
        return decision_result(
            annex=annex,
            decision="kill_session_on_catastrophic_signal",
            reason="runtime kill signal was raised before the action",
            request=request,
            matched_scenarios=matched,
            violations=[f"runtime_kill_signal: {request['runtime_kill_signal']}"],
        )

    if request["observed_loop_count"] > request["max_loop_count"]:
        return decision_result(
            annex=annex,
            decision="kill_session_on_catastrophic_signal",
            reason="agent exceeded the configured tool-loop threshold",
            request=request,
            matched_scenarios=matched,
            violations=[f"observed_loop_count={request['observed_loop_count']} exceeds max_loop_count={request['max_loop_count']}"],
        )

    if request.get("handles_secrets") and request.get("external_side_effect"):
        return decision_result(
            annex=annex,
            decision="kill_session_on_catastrophic_signal",
            reason="request combines secret handling with an external side effect",
            request=request,
            matched_scenarios=matched,
            violations=["handles_secrets=true", "external_side_effect=true"],
        )

    if not is_high_impact:
        missing_low = [
            field
            for field in ["workflow_id", "run_id", "identity_id"]
            if not request.get(field)
        ]
        if missing_low:
            return decision_result(
                annex=annex,
                decision="hold_for_catastrophic_risk_review",
                reason="bounded action is missing baseline runtime evidence",
                request=request,
                matched_scenarios=matched,
                violations=[f"missing {field}" for field in missing_low],
            )
        return decision_result(
            annex=annex,
            decision="allow_bounded_agent_action",
            reason="request does not match high-impact action classes or severe flags",
            request=request,
            matched_scenarios=matched,
        )

    high_risk_without_acceptance = (
        request["residual_risk_tier"] in {"high", "critical", "catastrophic"}
        and not request.get("risk_acceptance_id")
    )
    irreversible_without_approval = any(
        as_bool(request.get(flag))
        for flag in ["can_move_funds", "can_delete_data", "can_modify_identity"]
    ) and not approval_present(request.get("human_approval_record"))
    if high_risk_without_acceptance or irreversible_without_approval:
        violations: list[str] = []
        if high_risk_without_acceptance:
            violations.append("high residual risk requires risk_acceptance_id")
        if irreversible_without_approval:
            violations.append("irreversible action requires approved human_approval_record")
        return decision_result(
            annex=annex,
            decision="deny_unbounded_autonomy",
            reason="high-impact action lacks residual-risk acceptance or approval",
            request=request,
            matched_scenarios=matched,
            violations=violations,
        )

    required = [str(field) for field in contract.get("required_high_impact_fields", []) or []]
    missing = []
    for field in required:
        if field == "human_approval_record":
            if not approval_present(request.get("human_approval_record")):
                missing.append(field)
        elif not request.get(field):
            missing.append(field)

    if missing:
        return decision_result(
            annex=annex,
            decision="hold_for_catastrophic_risk_review",
            reason="high-impact action is missing required evidence",
            request=request,
            matched_scenarios=matched,
            violations=[f"missing {field}" for field in missing],
        )

    return decision_result(
        annex=annex,
        decision="allow_reviewed_high_impact_action",
        reason="high-impact action has approval, risk acceptance, identity, policy, authorization, and receipt evidence",
        request=request,
        matched_scenarios=matched,
    )


def parse_kv(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("expected KEY=VALUE")
    key, raw = value.split("=", 1)
    key = key.strip()
    if not key:
        raise argparse.ArgumentTypeError("key must not be empty")
    return key, raw


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--annex", type=Path, default=DEFAULT_ANNEX)
    parser.add_argument("--workflow-id", required=True)
    parser.add_argument("--action-class", required=True)
    parser.add_argument("--agent-id")
    parser.add_argument("--run-id")
    parser.add_argument("--identity-id")
    parser.add_argument("--tenant-id")
    parser.add_argument("--impact-domain")
    parser.add_argument("--policy-pack-hash")
    parser.add_argument("--authorization-decision")
    parser.add_argument("--context-package-hash")
    parser.add_argument("--egress-decision")
    parser.add_argument("--handoff-decision")
    parser.add_argument("--readiness-decision")
    parser.add_argument("--risk-acceptance-id")
    parser.add_argument("--receipt-id")
    parser.add_argument("--correlation-id")
    parser.add_argument("--residual-risk-tier")
    parser.add_argument("--runtime-kill-signal")
    parser.add_argument("--observed-loop-count", type=int, default=0)
    parser.add_argument("--max-loop-count", type=int, default=3)
    parser.add_argument("--approval-id")
    parser.add_argument("--approval-status", default="approved")
    parser.add_argument("--flag", action="append", type=parse_kv, default=[], help="Runtime boolean flag as KEY=VALUE.")
    parser.add_argument("--expect-decision")
    parser.add_argument("--json", action="store_true", help="Print the full JSON decision.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        annex = load_json(args.annex)
        request: dict[str, Any] = {
            "action_class": args.action_class,
            "agent_id": args.agent_id,
            "authorization_decision": args.authorization_decision,
            "context_package_hash": args.context_package_hash,
            "correlation_id": args.correlation_id,
            "egress_decision": args.egress_decision,
            "handoff_decision": args.handoff_decision,
            "identity_id": args.identity_id,
            "impact_domain": args.impact_domain,
            "max_loop_count": args.max_loop_count,
            "observed_loop_count": args.observed_loop_count,
            "policy_pack_hash": args.policy_pack_hash,
            "readiness_decision": args.readiness_decision,
            "receipt_id": args.receipt_id,
            "residual_risk_tier": args.residual_risk_tier,
            "risk_acceptance_id": args.risk_acceptance_id,
            "run_id": args.run_id,
            "runtime_kill_signal": args.runtime_kill_signal,
            "tenant_id": args.tenant_id,
            "workflow_id": args.workflow_id,
        }
        if args.approval_id:
            request["human_approval_record"] = {
                "approval_id": args.approval_id,
                "status": args.approval_status,
            }
        for key, value in args.flag:
            request[key] = value
        decision = evaluate_agentic_catastrophic_risk_decision(annex, request)
    except CatastrophicRiskDecisionError as exc:
        print(f"catastrophic-risk decision failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(decision, indent=2, sort_keys=True))
    else:
        print(
            f"{decision['decision']}: {decision['reason']} "
            f"(allowed={str(decision['allowed']).lower()})"
        )

    if args.expect_decision and decision.get("decision") != args.expect_decision:
        print(
            f"expected {args.expect_decision}, got {decision.get('decision')}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
