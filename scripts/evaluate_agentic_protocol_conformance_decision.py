#!/usr/bin/env python3
"""Evaluate one agentic protocol conformance decision.

This deterministic evaluator gives an agent host, MCP gateway, or A2A
gateway a fail-closed decision before protocol-mediated context, tool
authority, or remote-agent delegation proceeds.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_PACK = Path("data/evidence/agentic-protocol-conformance-pack.json")
ALLOW_DECISIONS = {"allow_with_protocol_receipt"}
VALID_DECISIONS = {
    *ALLOW_DECISIONS,
    "hold_for_protocol_evidence",
    "hold_for_protocol_drift_review",
    "deny_unbound_protocol_authority",
    "deny_untrusted_protocol_surface",
    "kill_session_on_protocol_violation",
}
HTTP_TRANSPORTS = {"http", "streamable-http", "sse", "https"}


class ProtocolConformanceDecisionError(RuntimeError):
    """Raised when the pack or runtime request cannot be parsed."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ProtocolConformanceDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ProtocolConformanceDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ProtocolConformanceDecisionError(f"{path} root must be a JSON object")
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


def protocols_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(protocol.get("id")): protocol
        for protocol in as_list(pack.get("protocol_profiles"))
        if isinstance(protocol, dict) and protocol.get("id")
    }


def checks_by_id(protocol: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(check.get("id")): check
        for check in as_list(protocol.get("conformance_checks"))
        if isinstance(check, dict) and check.get("id")
    }


def has_approval(value: Any) -> bool:
    record = as_dict(value)
    if not record:
        return False
    status = str(record.get("status") or record.get("decision") or "").lower()
    return bool(record.get("approval_id") or record.get("id")) and status in {"approved", "allow", "granted"}


def normalize_request(runtime_request: dict[str, Any]) -> dict[str, Any]:
    request = dict(runtime_request)
    for key in [
        "protocol_id",
        "workflow_id",
        "agent_id",
        "run_id",
        "transport",
        "protocol_version_observed",
        "handoff_profile_id",
        "consent_record_id",
        "session_id",
        "correlation_id",
        "gateway_policy_hash",
    ]:
        request[key] = str(request.get(key) or "").strip()
    for key in [
        "a2a_version_header",
        "agent_card_present",
        "agent_card_signed",
        "client_metadata_reviewed",
        "contains_secret",
        "extended_card_authenticated",
        "external_egress",
        "https_transport",
        "open_world_tool",
        "pkce_verified",
        "private_data_access",
        "provider_identity_verified",
        "resource_indicator_present",
        "runtime_kill_signal",
        "schema_drift_detected",
        "token_audience_bound",
        "token_passthrough",
        "tool_annotations_trusted",
        "tool_output_schema_validated",
        "tool_surface_pinned",
        "untrusted_content_seen",
    ]:
        request[key] = as_bool(request.get(key))
    request["data_classes"] = [str(item).strip() for item in as_list(request.get("data_classes")) if str(item).strip()]
    request["human_approval_record"] = as_dict(request.get("human_approval_record"))
    return request


def decision_result(
    *,
    decision: str,
    reason: str,
    pack: dict[str, Any],
    request: dict[str, Any],
    matched_protocol: dict[str, Any] | None = None,
    matched_checks: list[dict[str, Any]] | None = None,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise ProtocolConformanceDecisionError(f"unknown decision {decision!r}")
    return {
        "allowed": decision in ALLOW_DECISIONS,
        "decision": decision,
        "evidence": {
            "protocol_conformance_pack_generated_at": pack.get("generated_at"),
            "protocol_conformance_summary": pack.get("protocol_conformance_summary"),
            "source_artifacts": pack.get("source_artifacts"),
        },
        "matched_checks": matched_checks or [],
        "matched_protocol": {
            "effective_decision": matched_protocol.get("effective_decision") if matched_protocol else None,
            "id": matched_protocol.get("id") if matched_protocol else request.get("protocol_id"),
            "readiness_score": matched_protocol.get("readiness_score") if matched_protocol else None,
            "title": matched_protocol.get("title") if matched_protocol else None,
        },
        "reason": reason,
        "runtime_request": {
            "agent_id": request.get("agent_id"),
            "correlation_id": request.get("correlation_id"),
            "data_classes": request.get("data_classes", []),
            "protocol_id": request.get("protocol_id"),
            "protocol_version_observed": request.get("protocol_version_observed"),
            "run_id": request.get("run_id"),
            "session_id": request.get("session_id"),
            "transport": request.get("transport"),
            "workflow_id": request.get("workflow_id"),
        },
        "violations": violations or [],
    }


def selected_checks(protocol: dict[str, Any], check_ids: list[str]) -> list[dict[str, Any]]:
    by_id = checks_by_id(protocol)
    if not check_ids:
        return list(by_id.values())
    return [by_id[check_id] for check_id in check_ids if check_id in by_id]


def evaluate_agentic_protocol_conformance_decision(
    conformance_pack: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured conformance decision for one protocol boundary."""
    if not isinstance(conformance_pack, dict):
        raise ProtocolConformanceDecisionError("conformance_pack must be an object")
    if not isinstance(runtime_request, dict):
        raise ProtocolConformanceDecisionError("runtime_request must be an object")

    request = normalize_request(runtime_request)
    protocols = protocols_by_id(conformance_pack)
    protocol = protocols.get(request["protocol_id"])
    if request["runtime_kill_signal"] or request["contains_secret"] or request["token_passthrough"]:
        return decision_result(
            decision="kill_session_on_protocol_violation",
            reason="runtime kill signal, secret movement, or token passthrough crossed a protocol boundary",
            pack=conformance_pack,
            request=request,
            matched_protocol=protocol,
            violations=[
                flag
                for flag in ["runtime_kill_signal", "contains_secret", "token_passthrough"]
                if request.get(flag)
            ],
        )

    if protocol is None:
        return decision_result(
            decision="hold_for_protocol_evidence",
            reason="protocol profile is not registered in the conformance pack",
            pack=conformance_pack,
            request=request,
            violations=[f"unknown protocol_id: {request['protocol_id'] or '<missing>'}"],
        )

    if str(protocol.get("effective_decision")) != "ready_for_enterprise_conformance":
        return decision_result(
            decision="hold_for_protocol_evidence",
            reason="protocol profile still has evidence gaps",
            pack=conformance_pack,
            request=request,
            matched_protocol=protocol,
            matched_checks=selected_checks(protocol, []),
            violations=[
                f"{gap.get('check_id')}: {gap.get('fail_closed_decision')}"
                for gap in protocol.get("status_gaps", []) or []
                if isinstance(gap, dict)
            ],
        )

    protocol_id = request["protocol_id"]
    transport = request["transport"].lower()
    if protocol_id.startswith("mcp-authorization") and transport in HTTP_TRANSPORTS:
        violations = []
        if not request["resource_indicator_present"]:
            violations.append("resource_indicator_present=false")
        if not request["token_audience_bound"]:
            violations.append("token_audience_bound=false")
        if not request["pkce_verified"]:
            violations.append("pkce_verified=false")
        if violations:
            return decision_result(
                decision="deny_unbound_protocol_authority",
                reason="MCP authorization evidence is not bound to the protected resource",
                pack=conformance_pack,
                request=request,
                matched_protocol=protocol,
                matched_checks=selected_checks(protocol, ["mcp-protected-resource-metadata"]),
                violations=violations,
            )
        if request.get("client_metadata_reviewed") is False:
            return decision_result(
                decision="hold_for_protocol_evidence",
                reason="MCP client metadata has not been reviewed for production consent",
                pack=conformance_pack,
                request=request,
                matched_protocol=protocol,
                matched_checks=selected_checks(protocol, ["mcp-client-metadata-review"]),
                violations=["client_metadata_reviewed=false"],
            )

    if protocol_id == "mcp-tooling-safety":
        if request["schema_drift_detected"] or not request["tool_surface_pinned"]:
            return decision_result(
                decision="hold_for_protocol_drift_review",
                reason="MCP tool surface drift or missing baseline requires review",
                pack=conformance_pack,
                request=request,
                matched_protocol=protocol,
                matched_checks=selected_checks(protocol, ["mcp-tool-surface-pinning"]),
                violations=[
                    flag
                    for flag in ["schema_drift_detected", "tool_surface_pinned=false"]
                    if flag == "schema_drift_detected" and request["schema_drift_detected"]
                    or flag == "tool_surface_pinned=false" and not request["tool_surface_pinned"]
                ],
            )
        if not request["tool_annotations_trusted"]:
            return decision_result(
                decision="hold_for_protocol_drift_review",
                reason="tool annotations are not trusted enough to drive policy",
                pack=conformance_pack,
                request=request,
                matched_protocol=protocol,
                matched_checks=selected_checks(protocol, ["mcp-trusted-tool-annotations"]),
                violations=["tool_annotations_trusted=false"],
            )
        if request["private_data_access"] and request["open_world_tool"] and request["external_egress"]:
            return decision_result(
                decision="deny_untrusted_protocol_surface",
                reason="private data, untrusted content, and external send are present in the same protocol path",
                pack=conformance_pack,
                request=request,
                matched_protocol=protocol,
                matched_checks=selected_checks(protocol, ["mcp-private-untrusted-exfiltration-triangle"]),
                violations=["private_data_access+open_world_tool+external_egress"],
            )

    if protocol_id == "a2a-agent-discovery":
        violations = []
        if not request["https_transport"]:
            violations.append("https_transport=false")
        if not request["agent_card_present"]:
            violations.append("agent_card_present=false")
        if not request["provider_identity_verified"]:
            violations.append("provider_identity_verified=false")
        if request["protocol_version_observed"] and not request["a2a_version_header"]:
            violations.append("a2a_version_header=false")
        if violations:
            return decision_result(
                decision="hold_for_protocol_evidence",
                reason="A2A Agent Card or transport evidence is incomplete",
                pack=conformance_pack,
                request=request,
                matched_protocol=protocol,
                matched_checks=selected_checks(protocol, ["a2a-public-agent-card-intake", "a2a-version-and-transport-proof"]),
                violations=violations,
            )
        if request["external_egress"] and not request["extended_card_authenticated"]:
            return decision_result(
                decision="deny_untrusted_protocol_surface",
                reason="remote-agent delegation needs authenticated extended-card evidence",
                pack=conformance_pack,
                request=request,
                matched_protocol=protocol,
                matched_checks=selected_checks(protocol, ["a2a-authenticated-extended-card"]),
                violations=["extended_card_authenticated=false"],
            )

    if protocol_id == "agentic-identity-and-handoff":
        if request["untrusted_content_seen"] and request["external_egress"] and not has_approval(request.get("human_approval_record")):
            return decision_result(
                decision="deny_untrusted_protocol_surface",
                reason="untrusted protocol input reached an egress or delegation sink without approval",
                pack=conformance_pack,
                request=request,
                matched_protocol=protocol,
                matched_checks=selected_checks(protocol, ["prompt-injection-source-sink-boundary"]),
                violations=["untrusted_content_seen+external_egress without approval"],
            )
        missing_identity = [
            key
            for key in ["workflow_id", "agent_id", "run_id", "session_id", "correlation_id"]
            if not request.get(key)
        ]
        if missing_identity:
            return decision_result(
                decision="hold_for_protocol_evidence",
                reason="protocol use is missing identity, session, run, or correlation evidence",
                pack=conformance_pack,
                request=request,
                matched_protocol=protocol,
                matched_checks=selected_checks(protocol, ["agent-identity-bound-to-protocol"]),
                violations=[f"{key}=<missing>" for key in missing_identity],
            )

    return decision_result(
        decision="allow_with_protocol_receipt",
        reason="protocol boundary satisfies generated conformance policy",
        pack=conformance_pack,
        request=request,
        matched_protocol=protocol,
        matched_checks=selected_checks(protocol, []),
    )


def parse_key_value(values: list[str]) -> dict[str, str]:
    output: dict[str, str] = {}
    for value in values:
        key, separator, item = value.partition("=")
        if not separator:
            raise ProtocolConformanceDecisionError(f"expected KEY=VALUE, got {value!r}")
        output[key.strip()] = item.strip()
    return output


def request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.request:
        payload = load_json(args.request)
    else:
        payload = {}
    for key in [
        "protocol_id",
        "workflow_id",
        "agent_id",
        "run_id",
        "transport",
        "protocol_version_observed",
        "handoff_profile_id",
        "consent_record_id",
        "session_id",
        "correlation_id",
        "gateway_policy_hash",
    ]:
        value = getattr(args, key)
        if value not in (None, ""):
            payload[key] = value
    for flag in [
        "a2a_version_header",
        "agent_card_present",
        "agent_card_signed",
        "client_metadata_reviewed",
        "contains_secret",
        "extended_card_authenticated",
        "external_egress",
        "https_transport",
        "open_world_tool",
        "pkce_verified",
        "private_data_access",
        "provider_identity_verified",
        "resource_indicator_present",
        "runtime_kill_signal",
        "schema_drift_detected",
        "token_audience_bound",
        "token_passthrough",
        "tool_annotations_trusted",
        "tool_output_schema_validated",
        "tool_surface_pinned",
        "untrusted_content_seen",
    ]:
        if getattr(args, flag):
            payload[flag] = True
    if args.data_class:
        payload["data_classes"] = args.data_class
    if args.approval:
        payload["human_approval_record"] = parse_key_value(args.approval)
    return payload


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--request", type=Path)
    parser.add_argument("--protocol-id", dest="protocol_id", required=False)
    parser.add_argument("--workflow-id", dest="workflow_id")
    parser.add_argument("--agent-id", dest="agent_id")
    parser.add_argument("--run-id", dest="run_id")
    parser.add_argument("--transport", default="streamable-http")
    parser.add_argument("--protocol-version-observed", dest="protocol_version_observed")
    parser.add_argument("--handoff-profile-id", dest="handoff_profile_id")
    parser.add_argument("--consent-record-id", dest="consent_record_id")
    parser.add_argument("--session-id", dest="session_id")
    parser.add_argument("--correlation-id", dest="correlation_id")
    parser.add_argument("--gateway-policy-hash", dest="gateway_policy_hash")
    parser.add_argument("--data-class", dest="data_class", action="append", default=[])
    parser.add_argument("--approval", action="append", default=[], help="Approval field as KEY=VALUE.")
    parser.add_argument("--a2a-version-header", dest="a2a_version_header", action="store_true")
    parser.add_argument("--agent-card-present", dest="agent_card_present", action="store_true")
    parser.add_argument("--agent-card-signed", dest="agent_card_signed", action="store_true")
    parser.add_argument("--client-metadata-reviewed", dest="client_metadata_reviewed", action="store_true")
    parser.add_argument("--contains-secret", dest="contains_secret", action="store_true")
    parser.add_argument("--extended-card-authenticated", dest="extended_card_authenticated", action="store_true")
    parser.add_argument("--external-egress", dest="external_egress", action="store_true")
    parser.add_argument("--https-transport", dest="https_transport", action="store_true")
    parser.add_argument("--open-world-tool", dest="open_world_tool", action="store_true")
    parser.add_argument("--pkce-verified", dest="pkce_verified", action="store_true")
    parser.add_argument("--private-data-access", dest="private_data_access", action="store_true")
    parser.add_argument("--provider-identity-verified", dest="provider_identity_verified", action="store_true")
    parser.add_argument("--resource-indicator-present", dest="resource_indicator_present", action="store_true")
    parser.add_argument("--runtime-kill-signal", dest="runtime_kill_signal", action="store_true")
    parser.add_argument("--schema-drift-detected", dest="schema_drift_detected", action="store_true")
    parser.add_argument("--token-audience-bound", dest="token_audience_bound", action="store_true")
    parser.add_argument("--token-passthrough", dest="token_passthrough", action="store_true")
    parser.add_argument("--tool-annotations-trusted", dest="tool_annotations_trusted", action="store_true")
    parser.add_argument("--tool-output-schema-validated", dest="tool_output_schema_validated", action="store_true")
    parser.add_argument("--tool-surface-pinned", dest="tool_surface_pinned", action="store_true")
    parser.add_argument("--untrusted-content-seen", dest="untrusted_content_seen", action="store_true")
    parser.add_argument("--expect-decision", choices=sorted(VALID_DECISIONS))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        pack = load_json(args.pack)
        request = request_from_args(args)
        decision = evaluate_agentic_protocol_conformance_decision(pack, request)
    except (ProtocolConformanceDecisionError, json.JSONDecodeError) as exc:
        print(f"agentic protocol conformance decision failed: {exc}", file=sys.stderr)
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
