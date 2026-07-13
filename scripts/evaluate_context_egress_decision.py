#!/usr/bin/env python3
"""Evaluate one secure-context egress decision.

The context egress boundary pack declares data classes, destination
classes, workflow namespace mappings, source egress policy, and
kill-session rules. This evaluator is the deterministic policy function
an MCP gateway, agent host, CI admission check, or audit replay can call
before context is sent to a model provider, remote MCP server, telemetry
sink, public corpus, webhook, or another tenant boundary.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_EGRESS_PACK = Path("data/evidence/context-egress-boundary-pack.json")
VALID_DECISIONS = {
    "allow_public_egress_with_citation",
    "allow_tenant_bound_egress",
    "hold_for_redaction_or_dpa",
    "deny_unapproved_workflow_egress",
    "deny_untrusted_destination",
    "deny_unclassified_egress",
    "kill_session_on_secret_egress",
}
ALLOW_DECISIONS = {
    "allow_public_egress_with_citation",
    "allow_tenant_bound_egress",
}


class ContextEgressDecisionError(RuntimeError):
    """Raised when the egress pack or runtime request cannot be parsed."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ContextEgressDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ContextEgressDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ContextEgressDecisionError(f"{path} root must be a JSON object")
    return payload


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def policies_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    policies = pack.get("data_class_policies")
    if not isinstance(policies, list):
        raise ContextEgressDecisionError("egress pack is missing data_class_policies")
    return {
        str(policy.get("id")): policy
        for policy in policies
        if isinstance(policy, dict) and policy.get("id")
    }


def destinations_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    destinations = pack.get("destination_classes")
    if not isinstance(destinations, list):
        raise ContextEgressDecisionError("egress pack is missing destination_classes")
    return {
        str(destination.get("id")): destination
        for destination in destinations
        if isinstance(destination, dict) and destination.get("id")
    }


def workflows_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    workflows = pack.get("workflow_egress_map")
    if not isinstance(workflows, list):
        raise ContextEgressDecisionError("egress pack is missing workflow_egress_map")
    return {
        str(workflow.get("workflow_id")): workflow
        for workflow in workflows
        if isinstance(workflow, dict) and workflow.get("workflow_id")
    }


def sources_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    sources = pack.get("source_egress_map")
    if not isinstance(sources, list):
        raise ContextEgressDecisionError("egress pack is missing source_egress_map")
    return {
        str(source.get("source_id")): source
        for source in sources
        if isinstance(source, dict) and source.get("source_id")
    }


def namespace_policy(workflow: dict[str, Any] | None, namespace: str) -> dict[str, Any] | None:
    if workflow is None or not namespace:
        return None
    for row in workflow.get("namespace_policies", []) or []:
        if isinstance(row, dict) and str(row.get("namespace")) == namespace:
            return row
    return None


def destination_preview(destination: dict[str, Any] | None) -> dict[str, Any] | None:
    if destination is None:
        return None
    return {
        "category": destination.get("category"),
        "external_processor": destination.get("external_processor"),
        "id": destination.get("id"),
        "requires_dpa": destination.get("requires_dpa"),
        "requires_residency_match": destination.get("requires_residency_match"),
        "requires_zero_data_retention": destination.get("requires_zero_data_retention"),
        "title": destination.get("title"),
        "trusted": destination.get("trusted"),
    }


def policy_preview(policy: dict[str, Any] | None) -> dict[str, Any] | None:
    if policy is None:
        return None
    return {
        "allowed_destination_classes": policy.get("allowed_destination_classes", []),
        "default_decision": policy.get("default_decision"),
        "hold_destination_classes": policy.get("hold_destination_classes", []),
        "id": policy.get("id"),
        "prohibited_destination_classes": policy.get("prohibited_destination_classes", []),
        "redaction_required_before_external": policy.get("redaction_required_before_external"),
        "sensitivity": policy.get("sensitivity"),
        "tenant_id_required": policy.get("tenant_id_required"),
        "title": policy.get("title"),
    }


def source_preview(source: dict[str, Any] | None) -> dict[str, Any] | None:
    if source is None:
        return None
    return {
        "data_class": source.get("data_class"),
        "default_decision": source.get("default_decision"),
        "exposure": source.get("exposure"),
        "root": source.get("root"),
        "sensitivity": source.get("sensitivity"),
        "source_hash": source.get("source_hash"),
        "source_id": source.get("source_id"),
        "title": source.get("title"),
        "trust_tier": source.get("trust_tier"),
    }


def workflow_preview(workflow: dict[str, Any] | None) -> dict[str, Any] | None:
    if workflow is None:
        return None
    return {
        "egress_policy_hash": workflow.get("egress_policy_hash"),
        "namespace_count": len(workflow.get("namespace_policies", []) or []),
        "status": workflow.get("status"),
        "title": workflow.get("title"),
        "workflow_id": workflow.get("workflow_id"),
    }


def decision_result(
    *,
    decision: str,
    reason: str,
    request: dict[str, Any],
    pack: dict[str, Any],
    policy: dict[str, Any] | None = None,
    destination: dict[str, Any] | None = None,
    source: dict[str, Any] | None = None,
    workflow: dict[str, Any] | None = None,
    namespace: dict[str, Any] | None = None,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise ContextEgressDecisionError(f"unknown decision {decision!r}")

    return {
        "allowed": decision in ALLOW_DECISIONS,
        "decision": decision,
        "evidence": {
            "egress_pack_generated_at": pack.get("generated_at"),
            "egress_policy_hash": workflow.get("egress_policy_hash") if workflow else None,
            "observed_runtime_attributes": sorted(k for k, v in request.items() if v not in (None, "", [], {})),
            "required_controls": policy.get("required_controls", []) if policy else [],
            "source_artifacts": pack.get("source_artifacts"),
            "source_hash": source.get("source_hash") if source else None,
        },
        "matched_data_class_policy": policy_preview(policy),
        "matched_destination": destination_preview(destination),
        "matched_namespace_policy": namespace,
        "matched_source": source_preview(source),
        "matched_workflow": workflow_preview(workflow),
        "reason": reason,
        "request": {
            "contains_secret": request.get("contains_secret"),
            "contains_unredacted_pii": request.get("contains_unredacted_pii"),
            "data_class": request.get("data_class"),
            "destination_class": request.get("destination_class"),
            "destination_trust_tier": request.get("destination_trust_tier"),
            "dpa_in_place": request.get("dpa_in_place"),
            "egress_path": request.get("egress_path"),
            "mcp_namespace": request.get("mcp_namespace"),
            "residency_region": request.get("residency_region"),
            "required_region": request.get("required_region"),
            "source_id": request.get("source_id"),
            "tenant_id": request.get("tenant_id"),
            "workflow_id": request.get("workflow_id"),
            "zero_data_retention": request.get("zero_data_retention"),
        },
        "violations": violations or [],
    }


def evaluate_context_egress_decision(
    egress_pack: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured runtime decision for one context egress request."""
    if not isinstance(egress_pack, dict):
        raise ContextEgressDecisionError("egress_pack must be an object")
    if not isinstance(runtime_request, dict):
        raise ContextEgressDecisionError("runtime_request must be an object")

    request = dict(runtime_request)
    for key in [
        "workflow_id",
        "source_id",
        "mcp_namespace",
        "data_class",
        "destination_class",
        "tenant_id",
        "destination_trust_tier",
        "residency_region",
        "required_region",
        "egress_path",
    ]:
        request[key] = str(request.get(key) or "").strip()
    for key in [
        "contains_secret",
        "contains_unredacted_pii",
        "dpa_in_place",
        "zero_data_retention",
    ]:
        request[key] = as_bool(request.get(key))

    policies = policies_by_id(egress_pack)
    destinations = destinations_by_id(egress_pack)
    workflows = workflows_by_id(egress_pack)
    sources = sources_by_id(egress_pack)
    prohibited = {
        str(item)
        for item in (
            egress_pack.get("egress_decision_contract", {}).get("prohibited_data_classes", [])
            if isinstance(egress_pack.get("egress_decision_contract"), dict)
            else []
        )
    }

    violations: list[str] = []
    workflow = workflows.get(request["workflow_id"]) if request["workflow_id"] else None
    source = sources.get(request["source_id"]) if request["source_id"] else None
    namespace = namespace_policy(workflow, request["mcp_namespace"])

    policy = policies.get(request["data_class"]) if request["data_class"] else None
    if policy is None and namespace and namespace.get("data_class"):
        policy = policies.get(str(namespace.get("data_class")))
        request["data_class"] = str(namespace.get("data_class"))
    if policy is None and source and source.get("data_class"):
        policy = policies.get(str(source.get("data_class")))
        request["data_class"] = str(source.get("data_class"))

    destination = destinations.get(request["destination_class"]) if request["destination_class"] else None

    if request["contains_secret"] or request["data_class"] in prohibited:
        violations.append("secret or prohibited data class attempted to leave context boundary")
        return decision_result(
            decision="kill_session_on_secret_egress",
            reason="secret or prohibited context egress attempt",
            request=request,
            pack=egress_pack,
            policy=policy,
            destination=destination,
            source=source,
            workflow=workflow,
            namespace=namespace,
            violations=violations,
        )

    if not request["workflow_id"]:
        violations.append("workflow_id is required")
    if not request["data_class"]:
        violations.append("data_class is required or must be inferable from source_id/mcp_namespace")
    if not request["destination_class"]:
        violations.append("destination_class is required")
    if not request["workflow_id"] or not request["data_class"] or not request["destination_class"]:
        return decision_result(
            decision="deny_unclassified_egress",
            reason="missing required egress attributes",
            request=request,
            pack=egress_pack,
            policy=policy,
            destination=destination,
            source=source,
            workflow=workflow,
            namespace=namespace,
            violations=violations,
        )

    if workflow is None:
        violations.append(f"workflow_id is not registered: {request['workflow_id']}")
        return decision_result(
            decision="deny_unapproved_workflow_egress",
            reason="workflow is not approved for context egress",
            request=request,
            pack=egress_pack,
            policy=policy,
            destination=destination,
            source=source,
            workflow=workflow,
            namespace=namespace,
            violations=violations,
        )

    if request["mcp_namespace"] and namespace is None:
        violations.append(f"mcp_namespace is not approved for workflow: {request['mcp_namespace']}")
        return decision_result(
            decision="deny_unapproved_workflow_egress",
            reason="namespace is not in the workflow egress map",
            request=request,
            pack=egress_pack,
            policy=policy,
            destination=destination,
            source=source,
            workflow=workflow,
            namespace=namespace,
            violations=violations,
        )

    if policy is None:
        violations.append(f"data_class is not registered: {request['data_class']}")
        return decision_result(
            decision="deny_unclassified_egress",
            reason="data class is not mapped to reviewed egress policy",
            request=request,
            pack=egress_pack,
            destination=destination,
            source=source,
            workflow=workflow,
            namespace=namespace,
            violations=violations,
        )

    if destination is None:
        violations.append(f"destination_class is not registered: {request['destination_class']}")
        return decision_result(
            decision="deny_untrusted_destination",
            reason="destination class is unknown",
            request=request,
            pack=egress_pack,
            policy=policy,
            source=source,
            workflow=workflow,
            namespace=namespace,
            violations=violations,
        )

    if not destination.get("trusted"):
        violations.append(f"destination is untrusted: {request['destination_class']}")
        return decision_result(
            decision="deny_untrusted_destination",
            reason="destination is explicitly untrusted",
            request=request,
            pack=egress_pack,
            policy=policy,
            destination=destination,
            source=source,
            workflow=workflow,
            namespace=namespace,
            violations=violations,
        )

    if request["source_id"] and source is None:
        violations.append(f"source_id is not registered: {request['source_id']}")
        return decision_result(
            decision="deny_unclassified_egress",
            reason="source is not mapped to the egress boundary",
            request=request,
            pack=egress_pack,
            policy=policy,
            destination=destination,
            workflow=workflow,
            namespace=namespace,
            violations=violations,
        )

    if source and str(source.get("sensitivity")) == "prohibited":
        violations.append("registered source is prohibited context")
        return decision_result(
            decision="kill_session_on_secret_egress",
            reason="prohibited source attempted egress",
            request=request,
            pack=egress_pack,
            policy=policy,
            destination=destination,
            source=source,
            workflow=workflow,
            namespace=namespace,
            violations=violations,
        )

    destination_id = request["destination_class"]
    allowed = {str(item) for item in policy.get("allowed_destination_classes", [])}
    hold = {str(item) for item in policy.get("hold_destination_classes", [])}
    prohibited_destinations = {str(item) for item in policy.get("prohibited_destination_classes", [])}

    if destination_id in prohibited_destinations:
        violations.append(f"destination is prohibited for data_class: {destination_id}")
        return decision_result(
            decision="deny_untrusted_destination",
            reason="destination is prohibited for data class",
            request=request,
            pack=egress_pack,
            policy=policy,
            destination=destination,
            source=source,
            workflow=workflow,
            namespace=namespace,
            violations=violations,
        )

    if destination_id not in allowed:
        if destination_id in hold:
            violations.append(f"destination requires additional review for data_class: {destination_id}")
            return decision_result(
                decision="hold_for_redaction_or_dpa",
                reason="destination is conditionally held for this data class",
                request=request,
                pack=egress_pack,
                policy=policy,
                destination=destination,
                source=source,
                workflow=workflow,
                namespace=namespace,
                violations=violations,
            )
        violations.append(f"destination is not allowed for data_class: {destination_id}")
        return decision_result(
            decision="deny_untrusted_destination",
            reason="destination is not allowed for data class",
            request=request,
            pack=egress_pack,
            policy=policy,
            destination=destination,
            source=source,
            workflow=workflow,
            namespace=namespace,
            violations=violations,
        )

    if policy.get("tenant_id_required") and not request["tenant_id"]:
        violations.append("tenant_id is required for tenant-bound egress")

    if request["contains_unredacted_pii"] and policy.get("redaction_required_before_external") and destination.get("external_processor"):
        violations.append("unredacted PII cannot leave to an external processor")

    if policy.get("human_approval_required") and not request.get("human_approval_record"):
        violations.append("human_approval_record is required for this data class")

    if destination.get("external_processor"):
        if destination.get("requires_dpa") and not request["dpa_in_place"]:
            violations.append("dpa_in_place is required for external processor egress")
        if destination.get("requires_zero_data_retention") and not request["zero_data_retention"]:
            violations.append("zero_data_retention is required for this destination")

    if destination.get("requires_residency_match") and request["required_region"]:
        if not request["residency_region"]:
            violations.append("residency_region is required when required_region is set")
        elif request["residency_region"].lower() != request["required_region"].lower():
            violations.append(
                f"residency_region {request['residency_region']!r} does not match required_region {request['required_region']!r}"
            )

    if violations:
        return decision_result(
            decision="hold_for_redaction_or_dpa",
            reason="egress request is missing required boundary evidence",
            request=request,
            pack=egress_pack,
            policy=policy,
            destination=destination,
            source=source,
            workflow=workflow,
            namespace=namespace,
            violations=violations,
        )

    decision = str(policy.get("default_decision") or "deny_unclassified_egress")
    if decision == "hold_for_redaction_or_dpa":
        decision = "allow_tenant_bound_egress"
    return decision_result(
        decision=decision,
        reason="egress request satisfies data-class and destination controls",
        request=request,
        pack=egress_pack,
        policy=policy,
        destination=destination,
        source=source,
        workflow=workflow,
        namespace=namespace,
        violations=[],
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, default=DEFAULT_EGRESS_PACK)
    parser.add_argument("--workflow-id", required=True)
    parser.add_argument("--destination-class", required=True)
    parser.add_argument("--data-class")
    parser.add_argument("--source-id")
    parser.add_argument("--mcp-namespace")
    parser.add_argument("--tenant-id")
    parser.add_argument("--destination-trust-tier")
    parser.add_argument("--contains-secret", action="store_true")
    parser.add_argument("--contains-unredacted-pii", action="store_true")
    parser.add_argument("--dpa-in-place", action="store_true")
    parser.add_argument("--zero-data-retention", action="store_true")
    parser.add_argument("--residency-region")
    parser.add_argument("--required-region")
    parser.add_argument("--human-approval-record")
    parser.add_argument("--egress-path")
    parser.add_argument("--expect-decision")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        pack = load_json(args.pack)
        approval = None
        if args.human_approval_record:
            approval = json.loads(args.human_approval_record)
        decision = evaluate_context_egress_decision(
            pack,
            {
                "contains_secret": args.contains_secret,
                "contains_unredacted_pii": args.contains_unredacted_pii,
                "data_class": args.data_class,
                "destination_class": args.destination_class,
                "destination_trust_tier": args.destination_trust_tier,
                "dpa_in_place": args.dpa_in_place,
                "egress_path": args.egress_path,
                "human_approval_record": approval,
                "mcp_namespace": args.mcp_namespace,
                "residency_region": args.residency_region,
                "required_region": args.required_region,
                "source_id": args.source_id,
                "tenant_id": args.tenant_id,
                "workflow_id": args.workflow_id,
                "zero_data_retention": args.zero_data_retention,
            },
        )
    except (ContextEgressDecisionError, json.JSONDecodeError) as exc:
        print(f"context egress decision failed: {exc}", file=sys.stderr)
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
