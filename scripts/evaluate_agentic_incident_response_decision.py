#!/usr/bin/env python3
"""Evaluate one agentic incident response decision.

The evaluator is deterministic. It checks the generated incident
response pack, runtime evidence, severity signals, data movement,
authorization state, and containment status before deciding whether to
monitor, triage, hold for forensics, contain, or kill the session.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_PACK = Path("data/evidence/agentic-incident-response-pack.json")

ALLOW_DECISIONS = {"monitor_no_incident", "triage_and_monitor"}
VALID_DECISIONS = {
    *ALLOW_DECISIONS,
    "hold_for_forensics",
    "contain_and_open_war_room",
    "kill_session_and_escalate_board",
}
SEVERITY_ORDER = {"sev3": 1, "sev2": 2, "sev1": 3, "sev0": 4}
KILL_DATA_CLASSES = {"api_key", "credential", "customer_data", "pci", "phi", "secret", "token"}
KILL_SIGNALS = {
    "credential_exfiltration",
    "cross_tenant_context",
    "funds_movement",
    "identity_after_revocation",
    "production_write_without_approval",
    "raw_token_passthrough",
    "secret_handoff",
}


class AgenticIncidentResponseError(RuntimeError):
    """Raised when the incident response pack or request is invalid."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AgenticIncidentResponseError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise AgenticIncidentResponseError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AgenticIncidentResponseError(f"{path} root must be a JSON object")
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


def incident_classes_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("id")): row
        for row in as_list(pack.get("incident_classes"))
        if isinstance(row, dict) and row.get("id")
    }


def workflows_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("workflow_id")): row
        for row in as_list(pack.get("workflow_response_matrix"))
        if isinstance(row, dict) and row.get("workflow_id")
    }


def response_phase_ids(pack: dict[str, Any]) -> list[str]:
    return [
        str(row.get("id"))
        for row in as_list(pack.get("response_phases"))
        if isinstance(row, dict) and row.get("id")
    ]


def has_approval(record: Any) -> bool:
    approval = as_dict(record)
    if not approval:
        return False
    status = str(approval.get("status") or approval.get("decision") or "").lower()
    return bool(approval.get("approval_id") or approval.get("id")) and status in {"approved", "allow", "granted"}


def severity_from_request(request: dict[str, Any], incident_class: dict[str, Any] | None) -> str:
    severity = str(request.get("severity_signal") or "").strip().lower()
    if severity not in SEVERITY_ORDER:
        severity = str((incident_class or {}).get("default_severity") or "sev3").lower()
    if severity not in SEVERITY_ORDER:
        severity = "sev3"
    return severity


def required_fields(pack: dict[str, Any]) -> list[str]:
    contract = as_dict(pack.get("incident_contract"))
    return [str(field) for field in as_list(contract.get("required_runtime_fields"))]


def evidence_missing(pack: dict[str, Any], request: dict[str, Any]) -> list[str]:
    baseline = [
        "incident_id",
        "workflow_id",
        "run_id",
        "agent_id",
        "identity_id",
        "tenant_id",
        "correlation_id",
        "incident_class_id",
        "receipt_id",
    ]
    required = set(baseline)
    if severity_from_request(request, incident_classes_by_id(pack).get(str(request.get("incident_class_id")))) in {"sev0", "sev1"}:
        required.update(
            {
                "authorization_decisions",
                "containment_action_ids",
                "context_source_hashes",
                "mcp_namespaces",
                "source_event_ids",
            }
        )
    return [field for field in sorted(required) if not request.get(field)]


def normalize_request(runtime_request: dict[str, Any]) -> dict[str, Any]:
    request = dict(runtime_request)
    for key in [
        "affected_data_classes",
        "authorization_decisions",
        "containment_action_ids",
        "context_source_hashes",
        "context_source_ids",
        "egress_decisions",
        "handoff_decisions",
        "indicators",
        "mcp_namespaces",
        "replay_case_ids",
        "source_event_ids",
    ]:
        request[key] = [str(item) for item in as_list(request.get(key)) if str(item).strip()]
    request["externalized_context"] = as_bool(request.get("externalized_context"))
    request["production_write"] = as_bool(request.get("production_write"))
    request["token_passthrough"] = as_bool(request.get("token_passthrough"))
    request["identity_used_after_revocation"] = as_bool(request.get("identity_used_after_revocation"))
    request["customer_impact_confirmed"] = as_bool(request.get("customer_impact_confirmed"))
    request["runtime_kill_signal"] = str(request.get("runtime_kill_signal") or "").strip()
    return request


def matched_kill_reasons(request: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    indicators = lower_set(request.get("indicators"))
    data_classes = lower_set(request.get("affected_data_classes"))
    authorization_decisions = lower_set(request.get("authorization_decisions"))
    egress_decisions = lower_set(request.get("egress_decisions"))
    handoff_decisions = lower_set(request.get("handoff_decisions"))

    if request.get("runtime_kill_signal"):
        reasons.append(f"runtime_kill_signal: {request['runtime_kill_signal']}")
    if KILL_SIGNALS & indicators:
        reasons.extend(f"kill indicator: {item}" for item in sorted(KILL_SIGNALS & indicators))
    if request.get("token_passthrough"):
        reasons.append("raw MCP or provider token passthrough was observed")
    if request.get("identity_used_after_revocation"):
        reasons.append("delegated identity was used after revocation")
    if request.get("externalized_context") and data_classes & KILL_DATA_CLASSES:
        reasons.append("sensitive context left the approved boundary")
    if request.get("production_write") and not has_approval(request.get("human_approval_record")):
        reasons.append("production write lacks linked human approval")
    if any(decision.startswith("deny") or decision.startswith("kill") for decision in authorization_decisions | egress_decisions | handoff_decisions):
        reasons.append("linked authorization, egress, or handoff decision denied or killed the action")
    return reasons


def decision_result(
    *,
    decision: str,
    pack: dict[str, Any],
    request: dict[str, Any],
    incident_class: dict[str, Any] | None,
    workflow: dict[str, Any] | None,
    reason: str,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise AgenticIncidentResponseError(f"unknown decision {decision!r}")
    return {
        "allowed": decision in ALLOW_DECISIONS,
        "decision": decision,
        "evidence": {
            "observed_runtime_attributes": sorted(k for k, v in request.items() if v not in (None, "", [], {}, False)),
            "required_runtime_fields": required_fields(pack),
            "source_artifacts": pack.get("source_artifacts", {}),
        },
        "incident_class": {
            "default_decision": incident_class.get("default_decision") if incident_class else None,
            "default_severity": incident_class.get("default_severity") if incident_class else None,
            "id": incident_class.get("id") if incident_class else request.get("incident_class_id"),
            "title": incident_class.get("title") if incident_class else None,
        },
        "pack_generated_at": pack.get("generated_at"),
        "reason": reason,
        "request": {
            "agent_id": request.get("agent_id"),
            "correlation_id": request.get("correlation_id"),
            "customer_impact_state": request.get("customer_impact_state"),
            "identity_id": request.get("identity_id"),
            "incident_class_id": request.get("incident_class_id"),
            "incident_id": request.get("incident_id"),
            "run_id": request.get("run_id"),
            "severity_signal": severity_from_request(request, incident_class),
            "tenant_id": request.get("tenant_id"),
            "workflow_id": request.get("workflow_id"),
        },
        "response_phase_ids": response_phase_ids(pack),
        "violations": violations or [],
        "workflow": {
            "default_response_decision": workflow.get("default_response_decision") if workflow else None,
            "readiness_decision": workflow.get("readiness_decision") if workflow else None,
            "risk_tier": workflow.get("risk_tier") if workflow else None,
            "severity_floor": workflow.get("severity_floor") if workflow else None,
            "title": workflow.get("title") if workflow else None,
            "workflow_id": workflow.get("workflow_id") if workflow else request.get("workflow_id"),
        },
    }


def evaluate_agentic_incident_response_decision(
    pack: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured incident response decision."""
    if not isinstance(pack, dict):
        raise AgenticIncidentResponseError("pack must be an object")
    if not isinstance(runtime_request, dict):
        raise AgenticIncidentResponseError("runtime_request must be an object")

    request = normalize_request(runtime_request)
    class_id = str(request.get("incident_class_id") or "").strip()
    workflow_id = str(request.get("workflow_id") or "").strip()
    classes = incident_classes_by_id(pack)
    workflows = workflows_by_id(pack)
    incident_class = classes.get(class_id)
    workflow = workflows.get(workflow_id)

    if not incident_class:
        return decision_result(
            decision="hold_for_forensics",
            pack=pack,
            request=request,
            incident_class=None,
            workflow=workflow,
            reason="incident class is not registered in the generated response pack",
            violations=[f"unknown incident_class_id: {class_id}"],
        )
    if not workflow:
        return decision_result(
            decision="hold_for_forensics",
            pack=pack,
            request=request,
            incident_class=incident_class,
            workflow=None,
            reason="workflow is not registered in the generated response matrix",
            violations=[f"unknown workflow_id: {workflow_id}"],
        )

    kill_reasons = matched_kill_reasons(request)
    if kill_reasons:
        return decision_result(
            decision="kill_session_and_escalate_board",
            pack=pack,
            request=request,
            incident_class=incident_class,
            workflow=workflow,
            reason="kill-class incident signal was observed",
            violations=kill_reasons,
        )

    missing = evidence_missing(pack, request)
    if missing:
        return decision_result(
            decision="hold_for_forensics",
            pack=pack,
            request=request,
            incident_class=incident_class,
            workflow=workflow,
            reason="required incident evidence is missing",
            violations=[f"missing {field}" for field in missing],
        )

    severity = severity_from_request(request, incident_class)
    if severity == "sev0":
        return decision_result(
            decision="kill_session_and_escalate_board",
            pack=pack,
            request=request,
            incident_class=incident_class,
            workflow=workflow,
            reason="sev0 agentic incident requires session kill and executive escalation",
        )
    if severity == "sev1" or request.get("customer_impact_confirmed"):
        return decision_result(
            decision="contain_and_open_war_room",
            pack=pack,
            request=request,
            incident_class=incident_class,
            workflow=workflow,
            reason="probable material agentic incident requires containment and coordinated response",
        )
    if severity == "sev2" or not request.get("replay_case_ids"):
        return decision_result(
            decision="hold_for_forensics",
            pack=pack,
            request=request,
            incident_class=incident_class,
            workflow=workflow,
            reason="incident evidence must be preserved and replay cases must be attached before closure",
            violations=[] if request.get("replay_case_ids") else ["missing replay_case_ids"],
        )

    if lower_set(request.get("indicators")):
        return decision_result(
            decision="triage_and_monitor",
            pack=pack,
            request=request,
            incident_class=incident_class,
            workflow=workflow,
            reason="low-severity suspicious signal has complete evidence and no external side effect",
        )

    return decision_result(
        decision="monitor_no_incident",
        pack=pack,
        request=request,
        incident_class=incident_class,
        workflow=workflow,
        reason="no incident indicators or material evidence gaps were observed",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--runtime-request", type=Path, help="JSON file containing the runtime incident request.")
    parser.add_argument("--incident-id")
    parser.add_argument("--workflow-id")
    parser.add_argument("--run-id")
    parser.add_argument("--agent-id")
    parser.add_argument("--identity-id")
    parser.add_argument("--tenant-id")
    parser.add_argument("--correlation-id")
    parser.add_argument("--incident-class-id")
    parser.add_argument("--severity-signal")
    parser.add_argument("--source-event-id", action="append", default=[])
    parser.add_argument("--receipt-id")
    parser.add_argument("--context-source-id", action="append", default=[])
    parser.add_argument("--context-source-hash", action="append", default=[])
    parser.add_argument("--mcp-namespace", action="append", default=[])
    parser.add_argument("--authorization-decision", action="append", default=[])
    parser.add_argument("--egress-decision", action="append", default=[])
    parser.add_argument("--handoff-decision", action="append", default=[])
    parser.add_argument("--affected-data-class", action="append", default=[])
    parser.add_argument("--indicator", action="append", default=[])
    parser.add_argument("--containment-action-id", action="append", default=[])
    parser.add_argument("--replay-case-id", action="append", default=[])
    parser.add_argument("--customer-impact-state")
    parser.add_argument("--externalized-context", action="store_true")
    parser.add_argument("--production-write", action="store_true")
    parser.add_argument("--token-passthrough", action="store_true")
    parser.add_argument("--identity-used-after-revocation", action="store_true")
    parser.add_argument("--customer-impact-confirmed", action="store_true")
    parser.add_argument("--runtime-kill-signal")
    parser.add_argument("--approval-id")
    parser.add_argument("--approval-status")
    parser.add_argument("--expect-decision")
    return parser.parse_args()


def request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.runtime_request:
        return load_json(args.runtime_request)
    request: dict[str, Any] = {
        "affected_data_classes": args.affected_data_class,
        "agent_id": args.agent_id,
        "authorization_decisions": args.authorization_decision,
        "containment_action_ids": args.containment_action_id,
        "context_source_hashes": args.context_source_hash,
        "context_source_ids": args.context_source_id,
        "correlation_id": args.correlation_id,
        "customer_impact_confirmed": args.customer_impact_confirmed,
        "customer_impact_state": args.customer_impact_state,
        "egress_decisions": args.egress_decision,
        "externalized_context": args.externalized_context,
        "handoff_decisions": args.handoff_decision,
        "identity_id": args.identity_id,
        "identity_used_after_revocation": args.identity_used_after_revocation,
        "incident_class_id": args.incident_class_id,
        "incident_id": args.incident_id,
        "indicators": args.indicator,
        "mcp_namespaces": args.mcp_namespace,
        "production_write": args.production_write,
        "receipt_id": args.receipt_id,
        "replay_case_ids": args.replay_case_id,
        "run_id": args.run_id,
        "runtime_kill_signal": args.runtime_kill_signal,
        "severity_signal": args.severity_signal,
        "source_event_ids": args.source_event_id,
        "tenant_id": args.tenant_id,
        "token_passthrough": args.token_passthrough,
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
        result = evaluate_agentic_incident_response_decision(pack, request_from_args(args))
    except AgenticIncidentResponseError as exc:
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
