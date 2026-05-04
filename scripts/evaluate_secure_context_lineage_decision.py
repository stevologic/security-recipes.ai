#!/usr/bin/env python3
"""Evaluate one secure-context lineage decision.

This is the runtime policy function for deciding whether context can be
trusted or reused after it has crossed retrieval, attestation, poisoning
scan, model route, egress, handoff, telemetry, and receipt boundaries.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_LEDGER = Path("data/evidence/secure-context-lineage-ledger.json")
ALLOW_DECISION = "allow_lineage_bound_context"
HOLD_EVIDENCE_DECISION = "hold_for_lineage_evidence"
HOLD_POISONING_DECISION = "hold_for_poisoning_review"
HOLD_REUSE_DECISION = "hold_for_reuse_review"
DENY_UNBOUND_DECISION = "deny_unbound_context_lineage"
DENY_CROSS_TENANT_DECISION = "deny_cross_tenant_lineage_reuse"
KILL_DECISION = "kill_session_on_lineage_break"

VALID_DECISIONS = {
    ALLOW_DECISION,
    HOLD_EVIDENCE_DECISION,
    HOLD_POISONING_DECISION,
    HOLD_REUSE_DECISION,
    DENY_UNBOUND_DECISION,
    DENY_CROSS_TENANT_DECISION,
    KILL_DECISION,
}


class SecureContextLineageDecisionError(RuntimeError):
    """Raised when lineage evaluation cannot run."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SecureContextLineageDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise SecureContextLineageDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SecureContextLineageDecisionError(f"{path} root must be a JSON object")
    return payload


def normalize(value: Any) -> str:
    return str(value or "").strip()


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def workflows_by_id(ledger: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = ledger.get("workflow_lineage")
    if not isinstance(rows, list):
        raise SecureContextLineageDecisionError("ledger is missing workflow_lineage")
    return {
        str(row.get("workflow_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("workflow_id")
    }


def sources_by_id(ledger: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = ledger.get("source_lineage")
    if not isinstance(rows, list):
        raise SecureContextLineageDecisionError("ledger is missing source_lineage")
    return {
        str(row.get("source_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("source_id")
    }


def allowed_reuse_classes(ledger: dict[str, Any]) -> dict[str, str]:
    reuse_policy = ledger.get("reuse_policy") if isinstance(ledger.get("reuse_policy"), dict) else {}
    classes = reuse_policy.get("allowed_reuse_classes") if isinstance(reuse_policy, dict) else []
    return {
        str(item.get("id")): str(item.get("default_decision"))
        for item in classes
        if isinstance(item, dict) and item.get("id")
    }


def decision_result(
    *,
    decision: str,
    reason: str,
    ledger: dict[str, Any],
    request: dict[str, Any],
    workflow: dict[str, Any] | None = None,
    sources: list[dict[str, Any]] | None = None,
    missing_evidence: list[str] | None = None,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise SecureContextLineageDecisionError(f"unknown lineage decision {decision!r}")
    return {
        "allowed": decision == ALLOW_DECISION,
        "decision": decision,
        "evidence": {
            "context_package_hash": workflow.get("context_package_hash") if workflow else None,
            "egress_policy_hash": workflow.get("egress_policy_hash") if workflow else None,
            "generated_at": ledger.get("generated_at"),
            "lineage_summary": ledger.get("lineage_summary"),
            "observed_runtime_attributes": sorted(k for k, v in request.items() if v not in (None, "", [], {})),
            "receipt_id": workflow.get("receipt_id") if workflow else None,
            "route_hash": workflow.get("route_hash") if workflow else None,
            "source_artifacts": ledger.get("source_artifacts"),
            "source_hashes": workflow.get("source_hashes") if workflow else {},
        },
        "matched_sources": [
            {
                "decision": source.get("decision"),
                "poisoning_decision": source.get("poisoning", {}).get("decision") if isinstance(source.get("poisoning"), dict) else None,
                "source_hash": source.get("source_hash"),
                "source_id": source.get("source_id"),
                "trust_tier": source.get("trust_tier"),
            }
            for source in (sources or [])
        ],
        "matched_workflow": {
            "approved_reuse_classes": workflow.get("approved_reuse_classes", []) if workflow else [],
            "context_package_hash": workflow.get("context_package_hash") if workflow else None,
            "decision": workflow.get("decision") if workflow else None,
            "receipt_id": workflow.get("receipt_id") if workflow else None,
            "workflow_id": workflow.get("workflow_id") if workflow else request.get("workflow_id"),
        },
        "missing_evidence": missing_evidence or [],
        "reason": reason,
        "request": {
            "agent_id": request.get("agent_id"),
            "context_package_hash": request.get("context_package_hash"),
            "correlation_id": request.get("correlation_id"),
            "destination_class": request.get("destination_class"),
            "reuse_class": request.get("reuse_class"),
            "run_id": request.get("run_id"),
            "source_ids": request.get("source_ids", []),
            "target_tenant_id": request.get("target_tenant_id"),
            "tenant_id": request.get("tenant_id"),
            "workflow_id": request.get("workflow_id"),
        },
        "violations": violations or [],
    }


def has_bad_decision(value: str, prefix: str) -> bool:
    return value.startswith(prefix) or f"_{prefix}_" in value


def evaluate_secure_context_lineage_decision(
    ledger: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured lineage decision for one runtime context request."""
    if not isinstance(ledger, dict):
        raise SecureContextLineageDecisionError("ledger must be an object")
    if not isinstance(runtime_request, dict):
        raise SecureContextLineageDecisionError("runtime_request must be an object")

    request = dict(runtime_request)
    request["workflow_id"] = normalize(request.get("workflow_id"))
    request["run_id"] = normalize(request.get("run_id"))
    request["agent_id"] = normalize(request.get("agent_id"))
    request["tenant_id"] = normalize(request.get("tenant_id"))
    request["target_tenant_id"] = normalize(request.get("target_tenant_id"))
    request["reuse_class"] = normalize(request.get("reuse_class") or "same_run_context_replay")
    request["source_ids"] = [normalize(source_id) for source_id in as_list(request.get("source_ids")) if normalize(source_id)]
    request["source_hashes"] = [normalize(source_hash) for source_hash in as_list(request.get("source_hashes")) if normalize(source_hash)]

    workflows = workflows_by_id(ledger)
    source_index = sources_by_id(ledger)
    workflow = workflows.get(request["workflow_id"])
    matched_sources = [source_index[source_id] for source_id in request["source_ids"] if source_id in source_index]

    kill_flags = [
        "contains_secret",
        "token_passthrough",
        "prohibited_data_class",
        "context_hash_mismatch",
        "identity_used_after_revocation",
    ]
    if request.get("runtime_kill_signal") or any(bool(request.get(flag)) for flag in kill_flags):
        return decision_result(
            decision=KILL_DECISION,
            reason="runtime request contains a lineage break or kill signal",
            ledger=ledger,
            request=request,
            workflow=workflow,
            sources=matched_sources,
            violations=[flag for flag in kill_flags if request.get(flag)] + ([str(request.get("runtime_kill_signal"))] if request.get("runtime_kill_signal") else []),
        )

    if workflow is None:
        return decision_result(
            decision=DENY_UNBOUND_DECISION,
            reason="workflow is not registered in the secure context lineage ledger",
            ledger=ledger,
            request=request,
            sources=matched_sources,
            violations=["unregistered workflow_id"],
        )

    unknown_sources = sorted(set(request["source_ids"]) - set(source_index))
    if unknown_sources:
        return decision_result(
            decision=DENY_UNBOUND_DECISION,
            reason="runtime request references unregistered context sources",
            ledger=ledger,
            request=request,
            workflow=workflow,
            sources=matched_sources,
            violations=[f"unregistered source_id: {source_id}" for source_id in unknown_sources],
        )

    workflow_source_ids = {str(source_id) for source_id in workflow.get("source_ids", []) or []}
    if request["source_ids"]:
        unapproved = sorted(set(request["source_ids"]) - workflow_source_ids)
        if unapproved:
            return decision_result(
                decision=DENY_UNBOUND_DECISION,
                reason="source is registered but not approved for this workflow lineage envelope",
                ledger=ledger,
                request=request,
                workflow=workflow,
                sources=matched_sources,
                violations=[f"source_id not approved for workflow: {source_id}" for source_id in unapproved],
            )

    reuse_defaults = allowed_reuse_classes(ledger)
    if request["reuse_class"] not in reuse_defaults:
        return decision_result(
            decision=HOLD_REUSE_DECISION,
            reason="reuse_class is not declared in the lineage reuse policy",
            ledger=ledger,
            request=request,
            workflow=workflow,
            sources=matched_sources,
            violations=[f"unknown reuse_class: {request['reuse_class']}"],
        )

    if request["reuse_class"] == "cross_tenant_context_reuse" or (
        request["target_tenant_id"] and request["tenant_id"] and request["target_tenant_id"] != request["tenant_id"]
    ):
        return decision_result(
            decision=DENY_CROSS_TENANT_DECISION,
            reason="tenant-bound context cannot be reused across tenant, account, workspace, or public-corpus boundaries",
            ledger=ledger,
            request=request,
            workflow=workflow,
            sources=matched_sources,
            violations=["cross-tenant lineage reuse"],
        )

    if request["reuse_class"] not in {str(item) for item in workflow.get("approved_reuse_classes", []) or []}:
        return decision_result(
            decision=HOLD_REUSE_DECISION,
            reason="reuse_class is declared but not approved for this workflow lineage envelope",
            ledger=ledger,
            request=request,
            workflow=workflow,
            sources=matched_sources,
            violations=[f"reuse_class not approved for workflow: {request['reuse_class']}"],
        )

    if request.get("context_package_hash") and request.get("context_package_hash") != workflow.get("context_package_hash"):
        return decision_result(
            decision=HOLD_EVIDENCE_DECISION,
            reason="context_package_hash does not match the generated workflow lineage envelope",
            ledger=ledger,
            request=request,
            workflow=workflow,
            sources=matched_sources,
            violations=["context_package_hash mismatch"],
        )

    supplied_hashes = set(request["source_hashes"])
    expected_hashes = {str(value) for value in (workflow.get("source_hashes") or {}).values() if value}
    if supplied_hashes and not supplied_hashes.issubset(expected_hashes):
        return decision_result(
            decision=HOLD_EVIDENCE_DECISION,
            reason="one or more supplied source_hashes do not match the workflow lineage source hashes",
            ledger=ledger,
            request=request,
            workflow=workflow,
            sources=matched_sources,
            violations=["source_hash mismatch"],
        )

    runtime_decisions = {
        "context_retrieval_decision": normalize(request.get("context_retrieval_decision")),
        "attestation_decision": normalize(request.get("attestation_decision")),
        "model_route_decision": normalize(request.get("model_route_decision")),
        "egress_decision": normalize(request.get("egress_decision")),
        "handoff_decision": normalize(request.get("handoff_decision")),
        "telemetry_decision": normalize(request.get("telemetry_decision")),
    }
    for key, value in runtime_decisions.items():
        if not value:
            continue
        if has_bad_decision(value, "kill"):
            return decision_result(
                decision=KILL_DECISION,
                reason=f"{key} reports a kill decision",
                ledger=ledger,
                request=request,
                workflow=workflow,
                sources=matched_sources,
                violations=[f"{key}: {value}"],
            )
        if has_bad_decision(value, "deny"):
            return decision_result(
                decision=DENY_UNBOUND_DECISION,
                reason=f"{key} reports a deny decision",
                ledger=ledger,
                request=request,
                workflow=workflow,
                sources=matched_sources,
                violations=[f"{key}: {value}"],
            )
        if has_bad_decision(value, "hold"):
            return decision_result(
                decision=HOLD_EVIDENCE_DECISION,
                reason=f"{key} reports a hold decision",
                ledger=ledger,
                request=request,
                workflow=workflow,
                sources=matched_sources,
                violations=[f"{key}: {value}"],
            )

    poisoning_state = normalize(request.get("poisoning_scan_state")).lower()
    if poisoning_state in {"block_until_removed", "actionable_findings", "actionable_context_poisoning_risk", "runtime_instruction_override"}:
        return decision_result(
            decision=KILL_DECISION,
            reason="runtime poisoning scan reports an actionable lineage break",
            ledger=ledger,
            request=request,
            workflow=workflow,
            sources=matched_sources,
            violations=[f"poisoning_scan_state: {poisoning_state}"],
        )

    if workflow.get("decision") == KILL_DECISION:
        return decision_result(
            decision=KILL_DECISION,
            reason="generated workflow lineage envelope is in kill state",
            ledger=ledger,
            request=request,
            workflow=workflow,
            sources=matched_sources,
        )

    if workflow.get("decision") in {HOLD_EVIDENCE_DECISION, HOLD_POISONING_DECISION}:
        required_runtime_override = poisoning_state in {"clean", "allow_with_adversarial_examples", "documented_adversarial_examples_only"}
        if not required_runtime_override:
            return decision_result(
                decision=str(workflow.get("decision")),
                reason="generated workflow lineage envelope requires runtime scan or evidence override",
                ledger=ledger,
                request=request,
                workflow=workflow,
                sources=matched_sources,
                missing_evidence=["poisoning_scan_state=clean or documented_adversarial_examples_only"],
            )

    required_fields = [
        "workflow_id",
        "run_id",
        "agent_id",
        "tenant_id",
        "correlation_id",
        "trace_id",
        "context_package_hash",
        "context_retrieval_decision",
        "attestation_decision",
        "poisoning_scan_state",
        "model_route_id",
        "model_route_decision",
        "egress_decision",
        "handoff_decision",
        "telemetry_event_id",
        "telemetry_decision",
        "receipt_id",
    ]
    missing = [field for field in required_fields if not request.get(field)]
    if not request["source_ids"]:
        missing.append("source_ids")
    if not request["source_hashes"]:
        missing.append("source_hashes")
    if request.get("receipt_id") and workflow.get("receipt_id") and request.get("receipt_id") != workflow.get("receipt_id"):
        missing.append("receipt_id matching workflow lineage envelope")
    if missing:
        return decision_result(
            decision=HOLD_EVIDENCE_DECISION,
            reason="runtime request is missing required lineage evidence",
            ledger=ledger,
            request=request,
            workflow=workflow,
            sources=matched_sources,
            missing_evidence=sorted(set(missing)),
        )

    return decision_result(
        decision=ALLOW_DECISION,
        reason="runtime request satisfies secure context lineage policy",
        ledger=ledger,
        request=request,
        workflow=workflow,
        sources=matched_sources,
    )


def request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.request:
        payload = load_json(args.request)
    else:
        payload = {}
    updates = {
        "agent_id": args.agent_id,
        "attestation_decision": args.attestation_decision,
        "context_package_hash": args.context_package_hash,
        "context_retrieval_decision": args.context_retrieval_decision,
        "correlation_id": args.correlation_id,
        "destination_class": args.destination_class,
        "egress_decision": args.egress_decision,
        "handoff_decision": args.handoff_decision,
        "model_route_decision": args.model_route_decision,
        "model_route_id": args.model_route_id,
        "poisoning_scan_state": args.poisoning_scan_state,
        "receipt_id": args.receipt_id,
        "reuse_class": args.reuse_class,
        "run_id": args.run_id,
        "target_tenant_id": args.target_tenant_id,
        "telemetry_decision": args.telemetry_decision,
        "telemetry_event_id": args.telemetry_event_id,
        "tenant_id": args.tenant_id,
        "trace_id": args.trace_id,
        "workflow_id": args.workflow_id,
    }
    for key, value in updates.items():
        if value not in (None, ""):
            payload[key] = value
    if args.source_ids:
        payload["source_ids"] = args.source_ids
    if args.source_hashes:
        payload["source_hashes"] = args.source_hashes
    for flag in [
        "contains_secret",
        "context_hash_mismatch",
        "identity_used_after_revocation",
        "prohibited_data_class",
        "token_passthrough",
    ]:
        if getattr(args, flag):
            payload[flag] = True
    if args.runtime_kill_signal:
        payload["runtime_kill_signal"] = args.runtime_kill_signal
    return payload


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--request", type=Path, help="JSON file containing runtime lineage request attributes")
    parser.add_argument("--workflow-id", required=True)
    parser.add_argument("--source-id", dest="source_ids", action="append")
    parser.add_argument("--source-hash", dest="source_hashes", action="append")
    parser.add_argument("--agent-id")
    parser.add_argument("--run-id")
    parser.add_argument("--tenant-id")
    parser.add_argument("--target-tenant-id")
    parser.add_argument("--correlation-id")
    parser.add_argument("--trace-id")
    parser.add_argument("--context-package-hash")
    parser.add_argument("--context-retrieval-decision")
    parser.add_argument("--attestation-decision")
    parser.add_argument("--poisoning-scan-state")
    parser.add_argument("--model-route-decision")
    parser.add_argument("--model-route-id")
    parser.add_argument("--egress-decision")
    parser.add_argument("--handoff-decision")
    parser.add_argument("--telemetry-event-id")
    parser.add_argument("--telemetry-decision")
    parser.add_argument("--receipt-id")
    parser.add_argument("--reuse-class", default="same_run_context_replay")
    parser.add_argument("--destination-class")
    parser.add_argument("--contains-secret", action="store_true")
    parser.add_argument("--context-hash-mismatch", action="store_true")
    parser.add_argument("--identity-used-after-revocation", action="store_true")
    parser.add_argument("--prohibited-data-class", action="store_true")
    parser.add_argument("--token-passthrough", action="store_true")
    parser.add_argument("--runtime-kill-signal")
    parser.add_argument("--expect-decision", choices=sorted(VALID_DECISIONS))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        ledger = load_json(args.ledger)
        request = request_from_args(args)
        decision = evaluate_secure_context_lineage_decision(ledger, request)
    except SecureContextLineageDecisionError as exc:
        print(f"secure context lineage evaluation failed: {exc}", file=sys.stderr)
        return 1

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
