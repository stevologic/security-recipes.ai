#!/usr/bin/env python3
"""Evaluate one critical-infrastructure secure-context runtime decision."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_PACK = Path("data/evidence/critical-infrastructure-secure-context-pack.json")
ALLOW_DECISIONS = {
    "allow_ci_read_only_context",
    "allow_ci_supervised_action",
}
VALID_DECISIONS = {
    *ALLOW_DECISIONS,
    "hold_for_ci_safety_case",
    "deny_untrusted_ci_context",
    "kill_session_on_ci_hazard_signal",
}


class CriticalInfrastructureDecisionError(RuntimeError):
    """Raised when the pack or runtime request cannot be parsed."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CriticalInfrastructureDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise CriticalInfrastructureDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise CriticalInfrastructureDecisionError(f"{path} root must be a JSON object")
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


def lower_set(value: Any) -> set[str]:
    return {str(item).strip() for item in as_list(value) if str(item).strip()}


def sector_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = pack.get("sector_profiles")
    if not isinstance(rows, list):
        return {}
    return {
        str(row.get("id")): row
        for row in rows
        if isinstance(row, dict) and row.get("id")
    }


def approval_present(value: Any) -> bool:
    record = as_dict(value)
    status = str(record.get("status") or record.get("decision") or "").lower()
    return bool(record.get("approval_id") or record.get("id")) and status in {"approved", "allow", "granted"}


def starts_allow(value: Any) -> bool:
    return str(value or "").strip().startswith("allow")


def result(
    *,
    pack: dict[str, Any],
    decision: str,
    reason: str,
    request: dict[str, Any],
    sector: dict[str, Any] | None = None,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise CriticalInfrastructureDecisionError(f"unknown decision {decision!r}")
    return {
        "allowed": decision in ALLOW_DECISIONS,
        "critical_infrastructure_pack_generated_at": pack.get("generated_at"),
        "decision": decision,
        "evidence": {
            "required_runtime_evidence": pack.get("readiness_contract", {}).get("required_runtime_evidence", []),
            "source_artifacts": pack.get("source_artifacts"),
        },
        "reason": reason,
        "request": {
            "action_class": request.get("action_class"),
            "agent_id": request.get("agent_id"),
            "authorization_decision": request.get("authorization_decision"),
            "catastrophic_risk_decision": request.get("catastrophic_risk_decision"),
            "ci_safety_case_id": request.get("ci_safety_case_id"),
            "context_package_hash": request.get("context_package_hash"),
            "egress_decision": request.get("egress_decision"),
            "identity_id": request.get("identity_id"),
            "operator_approval_id": request.get("operator_approval_id"),
            "receipt_id": request.get("receipt_id"),
            "run_id": request.get("run_id"),
            "sector_id": request.get("sector_id"),
            "tenant_id": request.get("tenant_id"),
            "workflow_id": request.get("workflow_id"),
        },
        "sector": {
            "default_decision": sector.get("default_decision"),
            "id": sector.get("id"),
            "readiness_status": sector.get("readiness_status"),
            "title": sector.get("title"),
        } if sector else None,
        "violations": violations or [],
    }


def evaluate_critical_infrastructure_context_decision(
    pack: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a deterministic decision for one CI secure-context event."""
    if not isinstance(pack, dict):
        raise CriticalInfrastructureDecisionError("pack must be an object")
    if not isinstance(runtime_request, dict):
        raise CriticalInfrastructureDecisionError("runtime_request must be an object")

    request = dict(runtime_request)
    request["sector_id"] = str(request.get("sector_id") or "").strip()
    request["action_class"] = str(request.get("action_class") or "").strip()
    request["authorization_decision"] = str(request.get("authorization_decision") or "").strip()
    request["egress_decision"] = str(request.get("egress_decision") or "").strip()
    request["catastrophic_risk_decision"] = str(request.get("catastrophic_risk_decision") or "").strip()

    contract = pack.get("readiness_contract") if isinstance(pack.get("readiness_contract"), dict) else {}
    for flag in as_list(contract.get("hazard_flags")):
        request[str(flag)] = as_bool(request.get(str(flag)))

    sectors = sector_by_id(pack)
    sector = sectors.get(request["sector_id"])
    high_impact_actions = lower_set(contract.get("high_impact_action_classes"))
    baseline_actions = lower_set(contract.get("baseline_allowed_action_classes"))
    active_hazards = sorted(
        str(flag)
        for flag in as_list(contract.get("hazard_flags"))
        if as_bool(request.get(str(flag)))
    )
    high_impact = request["action_class"] in high_impact_actions
    baseline = request["action_class"] in baseline_actions

    if request.get("runtime_kill_signal"):
        return result(
            pack=pack,
            decision="kill_session_on_ci_hazard_signal",
            reason="runtime kill signal was raised before the critical-infrastructure action",
            request=request,
            sector=sector,
            violations=[f"runtime_kill_signal: {request.get('runtime_kill_signal')}"],
        )

    kill_hazards = {
        "token_passthrough",
        "shadow_mcp_server",
        "unsafe_local_mcp_launch",
        "raw_secret_access",
    }
    if kill_hazards.intersection(active_hazards):
        return result(
            pack=pack,
            decision="kill_session_on_ci_hazard_signal",
            reason="critical-infrastructure hazard signal requires immediate session termination",
            request=request,
            sector=sector,
            violations=sorted(kill_hazards.intersection(active_hazards)),
        )

    if request.get("untrusted_context") or not request.get("context_package_hash"):
        return result(
            pack=pack,
            decision="deny_untrusted_ci_context",
            reason="critical-infrastructure context is untrusted or missing a package hash",
            request=request,
            sector=sector,
            violations=["untrusted_context=true" if request.get("untrusted_context") else "missing context_package_hash"],
        )

    if not sector:
        return result(
            pack=pack,
            decision="hold_for_ci_safety_case",
            reason="sector profile is not registered in the critical-infrastructure pack",
            request=request,
            violations=["unknown sector_id"],
        )

    baseline_missing = [
        field
        for field in ["workflow_id", "run_id", "agent_id", "identity_id", "tenant_id"]
        if not request.get(field)
    ]
    if baseline_missing:
        return result(
            pack=pack,
            decision="hold_for_ci_safety_case",
            reason="runtime request is missing baseline identity or run evidence",
            request=request,
            sector=sector,
            violations=[f"missing {field}" for field in baseline_missing],
        )

    if not starts_allow(request["authorization_decision"]) or not starts_allow(request["egress_decision"]):
        return result(
            pack=pack,
            decision="hold_for_ci_safety_case",
            reason="MCP authorization and context egress must both allow before CI context can proceed",
            request=request,
            sector=sector,
            violations=[
                f"authorization_decision={request['authorization_decision'] or 'missing'}",
                f"egress_decision={request['egress_decision'] or 'missing'}",
            ],
        )

    prohibited = lower_set(sector.get("prohibited_without_safety_case"))
    severe_sector_hazards = {
        "affects_ot_or_ics",
        "patient_safety_impact",
        "emergency_services_impact",
        "funds_or_market_impact",
        "public_service_disruption",
        "cross_sector_dependency",
    }
    sector_hazard_active = bool(severe_sector_hazards.intersection(active_hazards))

    if baseline and not high_impact and not sector_hazard_active:
        return result(
            pack=pack,
            decision="allow_ci_read_only_context",
            reason="read-only or evidence-only critical-infrastructure context has required identity, authorization, egress, and context hash evidence",
            request=request,
            sector=sector,
        )

    requires_safety_case = high_impact or request["action_class"] in prohibited or sector_hazard_active
    if requires_safety_case:
        missing = []
        if not request.get("ci_safety_case_id"):
            missing.append("ci_safety_case_id")
        if not request.get("operator_approval_id"):
            missing.append("operator_approval_id")
        if not request.get("risk_acceptance_id"):
            missing.append("risk_acceptance_id")
        if not request.get("receipt_id"):
            missing.append("receipt_id")
        if not approval_present(request.get("human_approval_record")):
            missing.append("human_approval_record")
        if not starts_allow(request["catastrophic_risk_decision"]):
            missing.append("allowing catastrophic_risk_decision")
        if missing:
            return result(
                pack=pack,
                decision="hold_for_ci_safety_case",
                reason="critical-infrastructure action requires operator approval, safety case, risk acceptance, receipt, and severe-risk clearance",
                request=request,
                sector=sector,
                violations=[f"missing {field}" for field in missing],
            )

        return result(
            pack=pack,
            decision="allow_ci_supervised_action",
            reason="supervised critical-infrastructure action has sector safety-case evidence, operator approval, risk acceptance, receipt, authorization, egress, and severe-risk clearance",
            request=request,
            sector=sector,
        )

    return result(
        pack=pack,
        decision="hold_for_ci_safety_case",
        reason="action class is not part of the baseline read-only lane and needs operator review",
        request=request,
        sector=sector,
        violations=[f"unclassified action_class={request['action_class'] or 'missing'}"],
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
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--sector-id", required=True)
    parser.add_argument("--workflow-id", required=True)
    parser.add_argument("--action-class", required=True)
    parser.add_argument("--agent-id")
    parser.add_argument("--run-id")
    parser.add_argument("--identity-id")
    parser.add_argument("--tenant-id")
    parser.add_argument("--context-package-hash")
    parser.add_argument("--policy-pack-hash")
    parser.add_argument("--authorization-decision")
    parser.add_argument("--egress-decision")
    parser.add_argument("--catastrophic-risk-decision")
    parser.add_argument("--operator-approval-id")
    parser.add_argument("--ci-safety-case-id")
    parser.add_argument("--risk-acceptance-id")
    parser.add_argument("--receipt-id")
    parser.add_argument("--telemetry-trace-id")
    parser.add_argument("--runtime-kill-signal")
    parser.add_argument("--approval-id")
    parser.add_argument("--approval-status", default="approved")
    parser.add_argument("--flag", action="append", type=parse_kv, default=[], help="Runtime boolean flag as KEY=VALUE.")
    parser.add_argument("--expect-decision")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        pack = load_json(args.pack)
        request: dict[str, Any] = {
            "action_class": args.action_class,
            "agent_id": args.agent_id,
            "authorization_decision": args.authorization_decision,
            "catastrophic_risk_decision": args.catastrophic_risk_decision,
            "ci_safety_case_id": args.ci_safety_case_id,
            "context_package_hash": args.context_package_hash,
            "egress_decision": args.egress_decision,
            "identity_id": args.identity_id,
            "operator_approval_id": args.operator_approval_id,
            "policy_pack_hash": args.policy_pack_hash,
            "receipt_id": args.receipt_id,
            "risk_acceptance_id": args.risk_acceptance_id,
            "run_id": args.run_id,
            "runtime_kill_signal": args.runtime_kill_signal,
            "sector_id": args.sector_id,
            "telemetry_trace_id": args.telemetry_trace_id,
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
        decision = evaluate_critical_infrastructure_context_decision(pack, request)
    except CriticalInfrastructureDecisionError as exc:
        print(f"critical-infrastructure context decision failed: {exc}", file=sys.stderr)
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
