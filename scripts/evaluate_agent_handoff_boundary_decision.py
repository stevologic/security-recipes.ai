#!/usr/bin/env python3
"""Evaluate one agent handoff boundary decision.

The evaluator is intentionally deterministic. It does not ask a model
whether a handoff "sounds safe"; it checks the generated handoff pack
for the workflow, protocol, payload fields, data classes, target trust
tier, authentication evidence, and approval record expected before
context crosses an agent or protocol boundary.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_HANDOFF_PACK = Path("data/evidence/agent-handoff-boundary-pack.json")

ALLOW_DECISIONS = {
    "allow_metadata_handoff",
    "allow_cited_evidence_handoff",
    "allow_approved_handoff",
}
VALID_DECISIONS = {
    *ALLOW_DECISIONS,
    "hold_for_redaction_or_approval",
    "deny_untrusted_agent_handoff",
    "deny_unregistered_handoff",
    "kill_session_on_secret_handoff",
}
TRUSTED_TARGET_TIERS = {"first_party", "approved_vendor", "tenant_controlled"}
AUTHN_SCHEMES = {"oauth2", "openid_connect", "mutual_tls", "api_key", "signed_agent_card"}


class AgentHandoffBoundaryError(RuntimeError):
    """Raised when the handoff pack or runtime request cannot be parsed."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AgentHandoffBoundaryError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise AgentHandoffBoundaryError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AgentHandoffBoundaryError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def profiles_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(profile.get("profile_id")): profile
        for profile in as_list(pack.get("handoff_profiles"))
        if isinstance(profile, dict) and profile.get("profile_id")
    }


def workflows_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(workflow.get("workflow_id")): workflow
        for workflow in as_list(pack.get("workflow_handoff_map"))
        if isinstance(workflow, dict) and workflow.get("workflow_id")
    }


def protocol_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(protocol.get("protocol_id")): protocol
        for protocol in as_list(pack.get("protocol_surfaces"))
        if isinstance(protocol, dict) and protocol.get("protocol_id")
    }


def lower_set(values: Any) -> set[str]:
    return {str(item).strip() for item in as_list(values) if str(item).strip()}


def has_approval(value: Any) -> bool:
    record = as_dict(value)
    if not record:
        return False
    status = str(record.get("status") or record.get("decision") or "").lower()
    return bool(record.get("approval_id") or record.get("id")) and status in {"approved", "allow", "granted"}


def decision_result(
    *,
    decision: str,
    reason: str,
    runtime_request: dict[str, Any],
    violations: list[str] | None = None,
    matched_profile: dict[str, Any] | None = None,
    matched_workflow: dict[str, Any] | None = None,
    matched_protocol: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise AgentHandoffBoundaryError(f"unknown decision {decision!r}")
    return {
        "allowed": decision in ALLOW_DECISIONS,
        "decision": decision,
        "matched_profile": {
            "profile_id": matched_profile.get("profile_id") if matched_profile else None,
            "risk_tier": matched_profile.get("risk_tier") if matched_profile else None,
            "title": matched_profile.get("title") if matched_profile else None,
        },
        "matched_protocol": {
            "protocol_id": matched_protocol.get("protocol_id") if matched_protocol else runtime_request.get("protocol"),
            "title": matched_protocol.get("title") if matched_protocol else None,
        },
        "matched_workflow": {
            "title": matched_workflow.get("title") if matched_workflow else None,
            "workflow_id": matched_workflow.get("workflow_id") if matched_workflow else runtime_request.get("workflow_id"),
        },
        "reason": reason,
        "runtime_request": {
            "correlation_id": runtime_request.get("correlation_id"),
            "data_classes": as_list(runtime_request.get("data_classes")),
            "handoff_profile_id": runtime_request.get("handoff_profile_id"),
            "payload_fields": as_list(runtime_request.get("payload_fields")),
            "protocol": runtime_request.get("protocol"),
            "requested_capabilities": as_list(runtime_request.get("requested_capabilities")),
            "run_id": runtime_request.get("run_id"),
            "target_agent_class": runtime_request.get("target_agent_class"),
            "target_trust_tier": runtime_request.get("target_trust_tier"),
            "workflow_id": runtime_request.get("workflow_id"),
        },
        "violations": violations or [],
    }


def evaluate_agent_handoff_boundary_decision(
    handoff_pack: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured handoff boundary decision."""
    if not isinstance(handoff_pack, dict):
        raise AgentHandoffBoundaryError("handoff_pack must be an object")
    if not isinstance(runtime_request, dict):
        raise AgentHandoffBoundaryError("runtime_request must be an object")

    if runtime_request.get("runtime_kill_signal"):
        return decision_result(
            decision="kill_session_on_secret_handoff",
            reason="runtime kill signal was raised before handoff",
            runtime_request=runtime_request,
            violations=[str(runtime_request.get("runtime_kill_signal"))],
        )

    workflow_id = str(runtime_request.get("workflow_id") or "").strip()
    profile_id = str(runtime_request.get("handoff_profile_id") or "").strip()
    protocol_id = str(runtime_request.get("protocol") or "").strip()
    workflow = workflows_by_id(handoff_pack).get(workflow_id)
    profile = profiles_by_id(handoff_pack).get(profile_id)
    protocol = protocol_by_id(handoff_pack).get(protocol_id)

    if not workflow:
        return decision_result(
            decision="deny_unregistered_handoff",
            reason="workflow is not registered for handoff decisions",
            runtime_request=runtime_request,
            violations=[f"unknown workflow_id: {workflow_id}"],
        )
    if not profile:
        return decision_result(
            decision="deny_unregistered_handoff",
            reason="handoff profile is not registered",
            runtime_request=runtime_request,
            matched_workflow=workflow,
            violations=[f"unknown handoff_profile_id: {profile_id}"],
        )
    if not protocol:
        return decision_result(
            decision="deny_unregistered_handoff",
            reason="protocol surface is not registered",
            runtime_request=runtime_request,
            matched_profile=profile,
            matched_workflow=workflow,
            violations=[f"unknown protocol: {protocol_id}"],
        )

    allowed_protocols = lower_set(profile.get("allowed_protocols"))
    if protocol_id not in allowed_protocols:
        return decision_result(
            decision="deny_untrusted_agent_handoff",
            reason="handoff profile does not allow this protocol",
            runtime_request=runtime_request,
            matched_profile=profile,
            matched_protocol=protocol,
            matched_workflow=workflow,
            violations=[f"{profile_id} does not allow {protocol_id}"],
        )

    payload_fields = lower_set(runtime_request.get("payload_fields"))
    data_classes = lower_set(runtime_request.get("data_classes"))
    capabilities = lower_set(runtime_request.get("requested_capabilities"))
    contract = as_dict(handoff_pack.get("decision_contract"))
    prohibited_fields = lower_set(contract.get("prohibited_payload_fields"))
    prohibited_data = lower_set(contract.get("prohibited_data_classes"))
    sensitive_data = lower_set(contract.get("sensitive_data_classes"))
    high_impact = lower_set(contract.get("high_impact_capabilities"))
    profile_allowed_fields = lower_set(profile.get("allowed_payload_fields"))
    profile_required_fields = lower_set(profile.get("required_payload_fields"))
    profile_allowed_data = lower_set(profile.get("allowed_data_classes"))

    forbidden_payload = sorted((payload_fields & prohibited_fields) | (data_classes & prohibited_data))
    if runtime_request.get("contains_secret") or forbidden_payload:
        return decision_result(
            decision="kill_session_on_secret_handoff",
            reason="handoff attempted to move prohibited context or credential material",
            runtime_request=runtime_request,
            matched_profile=profile,
            matched_protocol=protocol,
            matched_workflow=workflow,
            violations=[f"prohibited item present: {item}" for item in forbidden_payload] or ["contains_secret=true"],
        )

    disallowed_fields = sorted(payload_fields - profile_allowed_fields)
    if disallowed_fields:
        return decision_result(
            decision="kill_session_on_secret_handoff",
            reason="handoff payload contains fields outside the profile boundary",
            runtime_request=runtime_request,
            matched_profile=profile,
            matched_protocol=protocol,
            matched_workflow=workflow,
            violations=[f"field is not allowed by profile: {field}" for field in disallowed_fields],
        )

    missing_required = sorted(profile_required_fields - payload_fields)
    if missing_required:
        return decision_result(
            decision="hold_for_redaction_or_approval",
            reason="handoff payload is missing required evidence fields",
            runtime_request=runtime_request,
            matched_profile=profile,
            matched_protocol=protocol,
            matched_workflow=workflow,
            violations=[f"missing required field: {field}" for field in missing_required],
        )

    unapproved_data = sorted(data_classes - profile_allowed_data)
    if unapproved_data:
        return decision_result(
            decision="hold_for_redaction_or_approval",
            reason="handoff includes data classes that require redaction or a narrower profile",
            runtime_request=runtime_request,
            matched_profile=profile,
            matched_protocol=protocol,
            matched_workflow=workflow,
            violations=[f"data class is not allowed by profile: {item}" for item in unapproved_data],
        )

    target_trust_tier = str(runtime_request.get("target_trust_tier") or "").strip()
    allowed_target_tiers = lower_set(protocol.get("allowed_target_trust_tiers"))
    if target_trust_tier not in TRUSTED_TARGET_TIERS or target_trust_tier not in allowed_target_tiers:
        return decision_result(
            decision="deny_untrusted_agent_handoff",
            reason="target agent trust tier is not approved for this protocol",
            runtime_request=runtime_request,
            matched_profile=profile,
            matched_protocol=protocol,
            matched_workflow=workflow,
            violations=[f"untrusted target_trust_tier: {target_trust_tier or '<missing>'}"],
        )

    if protocol_id == "a2a_task_delegation":
        schemes = lower_set(runtime_request.get("authentication_schemes"))
        if not (schemes & AUTHN_SCHEMES):
            return decision_result(
                decision="hold_for_redaction_or_approval",
                reason="A2A handoff is missing supported HTTP-layer authentication evidence",
                runtime_request=runtime_request,
                matched_profile=profile,
                matched_protocol=protocol,
                matched_workflow=workflow,
                violations=["missing oauth2, openid_connect, mutual_tls, api_key, or signed_agent_card"],
            )
        if target_trust_tier != "first_party" and not runtime_request.get("agent_card_signed"):
            return decision_result(
                decision="hold_for_redaction_or_approval",
                reason="non-first-party A2A target requires signed Agent Card evidence",
                runtime_request=runtime_request,
                matched_profile=profile,
                matched_protocol=protocol,
                matched_workflow=workflow,
                violations=["agent_card_signed=false"],
            )

    if protocol_id == "mcp_tool_call":
        resource_indicator = str(runtime_request.get("resource_indicator") or "").strip()
        token_audience = str(runtime_request.get("token_audience") or "").strip()
        if not resource_indicator or not token_audience or resource_indicator != token_audience:
            return decision_result(
                decision="hold_for_redaction_or_approval",
                reason="MCP handoff requires matching resource indicator and token audience evidence",
                runtime_request=runtime_request,
                matched_profile=profile,
                matched_protocol=protocol,
                matched_workflow=workflow,
                violations=["resource_indicator and token_audience must be present and equal"],
            )

    approval_required = bool(capabilities & high_impact) or profile.get("risk_tier") == "high" or bool(data_classes & sensitive_data)
    approved = has_approval(runtime_request.get("human_approval_record"))
    if approval_required and not approved:
        return decision_result(
            decision="hold_for_redaction_or_approval",
            reason="handoff requires explicit approval before high-impact or sensitive context crosses the boundary",
            runtime_request=runtime_request,
            matched_profile=profile,
            matched_protocol=protocol,
            matched_workflow=workflow,
            violations=["missing approved human_approval_record"],
        )

    if profile_id == "metadata-only":
        decision = "allow_metadata_handoff"
    elif profile_id == "cited-evidence":
        decision = "allow_cited_evidence_handoff"
    else:
        decision = "allow_approved_handoff"

    return decision_result(
        decision=decision,
        reason="handoff request satisfies profile, protocol, trust, data, and approval requirements",
        runtime_request=runtime_request,
        matched_profile=profile,
        matched_protocol=protocol,
        matched_workflow=workflow,
    )


def parse_key_value(values: list[str]) -> dict[str, str]:
    output: dict[str, str] = {}
    for value in values:
        key, separator, item = value.partition("=")
        if not separator:
            raise AgentHandoffBoundaryError(f"expected KEY=VALUE, got {value!r}")
        output[key.strip()] = item.strip()
    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff-pack", type=Path, default=DEFAULT_HANDOFF_PACK)
    parser.add_argument("--workflow-id", required=True)
    parser.add_argument("--handoff-profile-id", required=True)
    parser.add_argument("--protocol", required=True)
    parser.add_argument("--target-agent-class", default=None)
    parser.add_argument("--source-agent-id", default=None)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--correlation-id", default=None)
    parser.add_argument("--target-trust-tier", default="first_party")
    parser.add_argument("--payload-field", action="append", default=[])
    parser.add_argument("--data-class", action="append", default=[])
    parser.add_argument("--requested-capability", action="append", default=[])
    parser.add_argument("--authentication-scheme", action="append", default=[])
    parser.add_argument("--agent-card-signed", action="store_true")
    parser.add_argument("--contains-secret", action="store_true")
    parser.add_argument("--resource-indicator", default=None)
    parser.add_argument("--token-audience", default=None)
    parser.add_argument("--approval", action="append", default=[], help="Approval field as KEY=VALUE.")
    parser.add_argument("--runtime-kill-signal", default=None)
    parser.add_argument("--expect-decision", default=None)
    parser.add_argument("--json", action="store_true", help="Print full JSON decision.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        pack = load_json(args.handoff_pack)
        request = {
            "agent_card_signed": args.agent_card_signed,
            "authentication_schemes": args.authentication_scheme,
            "contains_secret": args.contains_secret,
            "correlation_id": args.correlation_id,
            "data_classes": args.data_class,
            "handoff_profile_id": args.handoff_profile_id,
            "human_approval_record": parse_key_value(args.approval),
            "payload_fields": args.payload_field,
            "protocol": args.protocol,
            "requested_capabilities": args.requested_capability,
            "resource_indicator": args.resource_indicator,
            "run_id": args.run_id,
            "runtime_kill_signal": args.runtime_kill_signal,
            "source_agent_id": args.source_agent_id,
            "target_agent_class": args.target_agent_class,
            "target_trust_tier": args.target_trust_tier,
            "token_audience": args.token_audience,
            "workflow_id": args.workflow_id,
        }
        decision = evaluate_agent_handoff_boundary_decision(pack, request)
    except AgentHandoffBoundaryError as exc:
        print(f"agent handoff boundary error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(decision, indent=2, sort_keys=True))
    else:
        print(decision["decision"])
        for violation in decision.get("violations", []):
            print(f"- {violation}")

    if args.expect_decision:
        if decision["decision"] != args.expect_decision:
            print(
                f"expected decision {args.expect_decision!r}, got {decision['decision']!r}",
                file=sys.stderr,
            )
            return 1
        return 0
    return 0 if decision["decision"] in ALLOW_DECISIONS or decision["decision"].startswith("hold_") else 2


if __name__ == "__main__":
    raise SystemExit(main())
