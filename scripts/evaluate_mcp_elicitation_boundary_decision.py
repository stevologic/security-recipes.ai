#!/usr/bin/env python3
"""Evaluate one MCP elicitation boundary decision.

This deterministic evaluator gives an MCP client, gateway, or agent host
a fail-closed decision before a server asks the user for form input or
directs the user to an external URL.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DEFAULT_PACK = Path("data/evidence/mcp-elicitation-boundary-pack.json")
ALLOW_DECISIONS = {"allow_elicitation_with_receipt"}
VALID_DECISIONS = {
    *ALLOW_DECISIONS,
    "hold_for_elicitation_evidence",
    "deny_sensitive_form_elicitation",
    "deny_untrusted_elicitation_url",
    "deny_token_or_secret_transit",
    "kill_session_on_elicitation_abuse",
}
SENSITIVE_FIELD_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|private[_-]?key|seed[_-]?phrase|card[_-]?number|cvv|session[_-]?cookie)",
    re.IGNORECASE,
)


class MCPElicitationBoundaryDecisionError(RuntimeError):
    """Raised when the pack or runtime request cannot be parsed."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise MCPElicitationBoundaryDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise MCPElicitationBoundaryDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise MCPElicitationBoundaryDecisionError(f"{path} root must be a JSON object")
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


def profiles_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(profile.get("id")): profile
        for profile in as_list(pack.get("elicitation_profiles"))
        if isinstance(profile, dict) and profile.get("id")
    }


def workflows_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(workflow.get("workflow_id")): workflow
        for workflow in as_list(pack.get("workflow_elicitation_map"))
        if isinstance(workflow, dict) and workflow.get("workflow_id")
    }


def has_approval(value: Any) -> bool:
    record = as_dict(value)
    if not record:
        return False
    status = str(record.get("status") or record.get("decision") or "").lower()
    return bool(record.get("approval_id") or record.get("id")) and status in {"approved", "allow", "granted"}


def infer_url_fields(request: dict[str, Any]) -> None:
    raw_url = str(request.get("url") or "").strip()
    parsed = urlparse(raw_url)
    if raw_url and not request.get("url_domain"):
        request["url_domain"] = parsed.hostname or ""
    if raw_url and "https_url" not in request:
        request["https_url"] = parsed.scheme == "https"


def normalize_request(runtime_request: dict[str, Any]) -> dict[str, Any]:
    request = dict(runtime_request)
    for key in [
        "workflow_id",
        "agent_id",
        "run_id",
        "connector_id",
        "namespace",
        "server_id",
        "elicitation_profile_id",
        "elicitation_id",
        "mode",
        "url",
        "url_domain",
        "user_id",
        "session_id",
        "correlation_id",
        "gateway_policy_hash",
        "authorization_pack_hash",
        "response_action",
    ]:
        request[key] = str(request.get(key) or "").strip()
    for key in [
        "client_supports_mode",
        "completion_notification_bound",
        "credential_requested",
        "form_contains_clickable_url",
        "https_url",
        "phishing_or_open_redirect_signal",
        "preauthenticated_url",
        "runtime_kill_signal",
        "sensitive_information_requested",
        "server_identity_displayed",
        "token_or_secret_transit",
        "url_allowlisted",
        "url_contains_sensitive_data",
        "url_opened_without_consent",
        "url_prefetched",
        "untrusted_content_seen",
        "user_can_decline",
        "user_can_review",
        "user_consent_recorded",
    ]:
        request[key] = as_bool(request.get(key))
    request["requested_data_classes"] = [
        str(item).strip()
        for item in as_list(request.get("requested_data_classes"))
        if str(item).strip()
    ]
    request["response_schema_fields"] = [
        str(item).strip()
        for item in as_list(request.get("response_schema_fields"))
        if str(item).strip()
    ]
    request["human_approval_record"] = as_dict(request.get("human_approval_record"))
    infer_url_fields(request)
    return request


def decision_result(
    *,
    decision: str,
    reason: str,
    pack: dict[str, Any],
    request: dict[str, Any],
    profile: dict[str, Any] | None = None,
    workflow: dict[str, Any] | None = None,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise MCPElicitationBoundaryDecisionError(f"unknown decision {decision!r}")
    return {
        "allowed": decision in ALLOW_DECISIONS,
        "decision": decision,
        "evidence": {
            "elicitation_boundary_pack_generated_at": pack.get("generated_at"),
            "elicitation_boundary_summary": pack.get("elicitation_boundary_summary"),
            "required_receipt_fields": pack.get("runtime_evidence_contract", {}).get("required_receipt_fields", []),
            "source_artifacts": pack.get("source_artifacts"),
        },
        "matched_profile": {
            "computed_decision": profile.get("computed_decision") if profile else None,
            "id": profile.get("id") if profile else request.get("elicitation_profile_id"),
            "mode": profile.get("mode") if profile else request.get("mode"),
            "risk_tier": profile.get("risk_tier") if profile else None,
            "title": profile.get("title") if profile else None,
        },
        "matched_workflow": {
            "allowed_profile_ids": workflow.get("allowed_profile_ids", []) if workflow else [],
            "approval_required_for": workflow.get("approval_required_for", []) if workflow else [],
            "workflow_id": workflow.get("workflow_id") if workflow else request.get("workflow_id"),
        },
        "reason": reason,
        "runtime_request": {
            "agent_id": request.get("agent_id"),
            "connector_id": request.get("connector_id"),
            "correlation_id": request.get("correlation_id"),
            "elicitation_id": request.get("elicitation_id"),
            "elicitation_profile_id": request.get("elicitation_profile_id"),
            "mode": request.get("mode"),
            "namespace": request.get("namespace"),
            "requested_data_classes": request.get("requested_data_classes", []),
            "response_action": request.get("response_action"),
            "run_id": request.get("run_id"),
            "server_id": request.get("server_id"),
            "session_id": request.get("session_id"),
            "url_domain": request.get("url_domain"),
            "user_id": request.get("user_id"),
            "workflow_id": request.get("workflow_id"),
        },
        "violations": violations or [],
    }


def missing_identity_fields(request: dict[str, Any]) -> list[str]:
    return [
        key
        for key in ["workflow_id", "agent_id", "run_id", "server_id", "elicitation_id", "mode", "session_id", "correlation_id"]
        if not request.get(key)
    ]


def missing_profile_required_fields(profile: dict[str, Any], request: dict[str, Any]) -> list[str]:
    missing = []
    for key in profile.get("required_runtime_attributes", []) or []:
        key = str(key)
        if key == "human_approval_record":
            if not has_approval(request.get("human_approval_record")):
                missing.append(key)
        elif not request.get(key):
            missing.append(key)
    return sorted(set(missing))


def profile_sensitive_classes(pack: dict[str, Any], profile: dict[str, Any] | None) -> set[str]:
    contract = pack.get("boundary_contract") if isinstance(pack.get("boundary_contract"), dict) else {}
    sensitive = {str(item) for item in contract.get("sensitive_data_classes", []) or []}
    if profile:
        sensitive.update(str(item) for item in profile.get("prohibited_data_classes", []) or [])
    return sensitive


def form_has_sensitive_fields(request: dict[str, Any]) -> bool:
    return any(SENSITIVE_FIELD_RE.search(field) for field in request.get("response_schema_fields", []))


def evaluate_mcp_elicitation_boundary_decision(
    elicitation_pack: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured decision for one MCP elicitation request."""
    if not isinstance(elicitation_pack, dict):
        raise MCPElicitationBoundaryDecisionError("elicitation_pack must be an object")
    if not isinstance(runtime_request, dict):
        raise MCPElicitationBoundaryDecisionError("runtime_request must be an object")

    request = normalize_request(runtime_request)
    profiles = profiles_by_id(elicitation_pack)
    workflows = workflows_by_id(elicitation_pack)
    profile = profiles.get(request["elicitation_profile_id"])
    workflow = workflows.get(request["workflow_id"]) if request["workflow_id"] else None

    if request["runtime_kill_signal"] or request["url_opened_without_consent"]:
        return decision_result(
            decision="kill_session_on_elicitation_abuse",
            reason="runtime kill signal or URL navigation without consent crossed the elicitation boundary",
            pack=elicitation_pack,
            request=request,
            profile=profile,
            workflow=workflow,
            violations=[
                flag
                for flag in ["runtime_kill_signal", "url_opened_without_consent"]
                if request.get(flag)
            ],
        )

    if request["token_or_secret_transit"]:
        return decision_result(
            decision="deny_token_or_secret_transit",
            reason="credentials or tokens would transit the MCP client, LLM context, or an intermediate server",
            pack=elicitation_pack,
            request=request,
            profile=profile,
            workflow=workflow,
            violations=["token_or_secret_transit=true"],
        )

    if profile is None:
        return decision_result(
            decision="hold_for_elicitation_evidence",
            reason="elicitation profile is not registered in the boundary pack",
            pack=elicitation_pack,
            request=request,
            workflow=workflow,
            violations=[f"unknown elicitation_profile_id: {request['elicitation_profile_id'] or '<missing>'}"],
        )

    mode = request["mode"] or str(profile.get("mode") or "")
    if mode != str(profile.get("mode")):
        return decision_result(
            decision="hold_for_elicitation_evidence",
            reason="runtime elicitation mode does not match the registered profile",
            pack=elicitation_pack,
            request=request,
            profile=profile,
            workflow=workflow,
            violations=[f"mode {mode!r} does not match profile mode {profile.get('mode')!r}"],
        )

    if not request["client_supports_mode"]:
        return decision_result(
            decision="hold_for_elicitation_evidence",
            reason="client did not declare support for the requested elicitation mode",
            pack=elicitation_pack,
            request=request,
            profile=profile,
            workflow=workflow,
            violations=["client_supports_mode=false"],
        )

    if workflow and request["elicitation_profile_id"] not in set(workflow.get("allowed_profile_ids", []) or []):
        return decision_result(
            decision="hold_for_elicitation_evidence",
            reason="workflow is not approved for this elicitation profile",
            pack=elicitation_pack,
            request=request,
            profile=profile,
            workflow=workflow,
            violations=[f"profile {request['elicitation_profile_id']!r} is not allowed for workflow {request['workflow_id']!r}"],
        )

    sensitive_classes = profile_sensitive_classes(elicitation_pack, profile)
    requested_classes = {str(item) for item in request.get("requested_data_classes", [])}
    if mode == "form":
        violations = []
        if request["sensitive_information_requested"] or request["credential_requested"]:
            violations.append("sensitive_information_or_credential_requested=true")
        if requested_classes & sensitive_classes:
            violations.append(f"sensitive_data_classes={sorted(requested_classes & sensitive_classes)}")
        if form_has_sensitive_fields(request):
            violations.append("response_schema_fields contain secret-like fields")
        if request["form_contains_clickable_url"]:
            violations.append("form_contains_clickable_url=true")
        if violations:
            return decision_result(
                decision="deny_sensitive_form_elicitation",
                reason="form-mode elicitation is requesting sensitive data or unsafe URL content",
                pack=elicitation_pack,
                request=request,
                profile=profile,
                workflow=workflow,
                violations=violations,
            )

    if mode == "url":
        allowed_domains = {str(item).lower() for item in profile.get("allowed_url_domains", []) or []}
        url_domain = str(request.get("url_domain") or "").lower()
        violations = []
        if not request.get("url"):
            violations.append("url=<missing>")
        if not request["https_url"]:
            violations.append("https_url=false")
        if request["preauthenticated_url"]:
            violations.append("preauthenticated_url=true")
        if request["url_contains_sensitive_data"]:
            violations.append("url_contains_sensitive_data=true")
        if request["url_prefetched"]:
            violations.append("url_prefetched=true")
        if request["phishing_or_open_redirect_signal"]:
            violations.append("phishing_or_open_redirect_signal=true")
        if not request["url_allowlisted"] or (allowed_domains and url_domain not in allowed_domains):
            violations.append(f"url_domain {url_domain or '<missing>'!r} is not allowlisted")
        if request["untrusted_content_seen"] and not has_approval(request.get("human_approval_record")):
            violations.append("untrusted_content_seen without approved human record")
        if violations:
            return decision_result(
                decision="deny_untrusted_elicitation_url",
                reason="URL-mode elicitation failed safe URL, domain, consent, or prompt-injection controls",
                pack=elicitation_pack,
                request=request,
                profile=profile,
                workflow=workflow,
                violations=violations,
            )

    missing = missing_identity_fields(request)
    if missing:
        return decision_result(
            decision="hold_for_elicitation_evidence",
            reason="elicitation request is missing identity, run, session, or correlation evidence",
            pack=elicitation_pack,
            request=request,
            profile=profile,
            workflow=workflow,
            violations=[f"{key}=<missing>" for key in missing],
        )

    missing_profile_fields = missing_profile_required_fields(profile, request)
    if missing_profile_fields:
        return decision_result(
            decision="hold_for_elicitation_evidence",
            reason="elicitation request is missing profile-required runtime evidence",
            pack=elicitation_pack,
            request=request,
            profile=profile,
            workflow=workflow,
            violations=[f"{key}=<missing>" for key in missing_profile_fields],
        )

    if not request["server_identity_displayed"] or not request["user_can_decline"]:
        return decision_result(
            decision="hold_for_elicitation_evidence",
            reason="user-facing identity or decline/cancel evidence is missing",
            pack=elicitation_pack,
            request=request,
            profile=profile,
            workflow=workflow,
            violations=[
                flag
                for flag in ["server_identity_displayed=false", "user_can_decline=false"]
                if flag == "server_identity_displayed=false" and not request["server_identity_displayed"]
                or flag == "user_can_decline=false" and not request["user_can_decline"]
            ],
        )

    if mode == "form" and not request["user_can_review"]:
        return decision_result(
            decision="hold_for_elicitation_evidence",
            reason="form-mode response review evidence is missing",
            pack=elicitation_pack,
            request=request,
            profile=profile,
            workflow=workflow,
            violations=["user_can_review=false"],
        )

    if mode == "url" and (not request["user_consent_recorded"] or not request["completion_notification_bound"]):
        return decision_result(
            decision="hold_for_elicitation_evidence",
            reason="URL-mode consent or completion binding evidence is missing",
            pack=elicitation_pack,
            request=request,
            profile=profile,
            workflow=workflow,
            violations=[
                flag
                for flag in ["user_consent_recorded=false", "completion_notification_bound=false"]
                if flag == "user_consent_recorded=false" and not request["user_consent_recorded"]
                or flag == "completion_notification_bound=false" and not request["completion_notification_bound"]
            ],
        )

    computed_decision = str(profile.get("computed_decision") or profile.get("default_decision") or "")
    if computed_decision in {"hold_for_elicitation_evidence", "deny_sensitive_form_elicitation", "deny_untrusted_elicitation_url"}:
        return decision_result(
            decision=computed_decision,
            reason="registered elicitation profile is not configured for automatic allow",
            pack=elicitation_pack,
            request=request,
            profile=profile,
            workflow=workflow,
            violations=profile.get("control_gaps", []),
        )

    return decision_result(
        decision="allow_elicitation_with_receipt",
        reason="elicitation request satisfies mode, data, URL, identity, consent, and receipt controls",
        pack=elicitation_pack,
        request=request,
        profile=profile,
        workflow=workflow,
    )


def parse_key_value(values: list[str]) -> dict[str, str]:
    output: dict[str, str] = {}
    for value in values:
        key, separator, item = value.partition("=")
        if not separator:
            raise MCPElicitationBoundaryDecisionError(f"expected KEY=VALUE, got {value!r}")
        output[key.strip()] = item.strip()
    return output


def request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.request:
        payload = load_json(args.request)
    else:
        payload = {}
    for key in [
        "workflow_id",
        "agent_id",
        "run_id",
        "connector_id",
        "namespace",
        "server_id",
        "elicitation_profile_id",
        "elicitation_id",
        "mode",
        "url",
        "url_domain",
        "user_id",
        "session_id",
        "correlation_id",
        "gateway_policy_hash",
        "authorization_pack_hash",
        "response_action",
    ]:
        value = getattr(args, key)
        if value not in (None, ""):
            payload[key] = value
    if args.data_class:
        payload["requested_data_classes"] = args.data_class
    if args.schema_field:
        payload["response_schema_fields"] = args.schema_field
    for flag in [
        "client_supports_mode",
        "completion_notification_bound",
        "credential_requested",
        "form_contains_clickable_url",
        "https_url",
        "phishing_or_open_redirect_signal",
        "preauthenticated_url",
        "runtime_kill_signal",
        "sensitive_information_requested",
        "server_identity_displayed",
        "token_or_secret_transit",
        "url_allowlisted",
        "url_contains_sensitive_data",
        "url_opened_without_consent",
        "url_prefetched",
        "untrusted_content_seen",
        "user_can_decline",
        "user_can_review",
        "user_consent_recorded",
    ]:
        if getattr(args, flag):
            payload[flag] = True
    if args.approval:
        payload["human_approval_record"] = parse_key_value(args.approval)
    return payload


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--request", type=Path)
    parser.add_argument("--workflow-id", dest="workflow_id")
    parser.add_argument("--agent-id", dest="agent_id")
    parser.add_argument("--run-id", dest="run_id")
    parser.add_argument("--connector-id", dest="connector_id")
    parser.add_argument("--namespace")
    parser.add_argument("--server-id", dest="server_id")
    parser.add_argument("--elicitation-profile-id", dest="elicitation_profile_id")
    parser.add_argument("--elicitation-id", dest="elicitation_id")
    parser.add_argument("--mode", choices=["form", "url"])
    parser.add_argument("--url")
    parser.add_argument("--url-domain", dest="url_domain")
    parser.add_argument("--user-id", dest="user_id")
    parser.add_argument("--session-id", dest="session_id")
    parser.add_argument("--correlation-id", dest="correlation_id")
    parser.add_argument("--gateway-policy-hash", dest="gateway_policy_hash")
    parser.add_argument("--authorization-pack-hash", dest="authorization_pack_hash")
    parser.add_argument("--response-action", dest="response_action")
    parser.add_argument("--data-class", dest="data_class", action="append", default=[])
    parser.add_argument("--schema-field", dest="schema_field", action="append", default=[])
    parser.add_argument("--approval", action="append", default=[], help="Approval field as KEY=VALUE.")
    parser.add_argument("--client-supports-mode", dest="client_supports_mode", action="store_true")
    parser.add_argument("--completion-notification-bound", dest="completion_notification_bound", action="store_true")
    parser.add_argument("--credential-requested", dest="credential_requested", action="store_true")
    parser.add_argument("--form-contains-clickable-url", dest="form_contains_clickable_url", action="store_true")
    parser.add_argument("--https-url", dest="https_url", action="store_true")
    parser.add_argument("--phishing-or-open-redirect-signal", dest="phishing_or_open_redirect_signal", action="store_true")
    parser.add_argument("--preauthenticated-url", dest="preauthenticated_url", action="store_true")
    parser.add_argument("--runtime-kill-signal", dest="runtime_kill_signal", action="store_true")
    parser.add_argument("--sensitive-information-requested", dest="sensitive_information_requested", action="store_true")
    parser.add_argument("--server-identity-displayed", dest="server_identity_displayed", action="store_true")
    parser.add_argument("--token-or-secret-transit", dest="token_or_secret_transit", action="store_true")
    parser.add_argument("--url-allowlisted", dest="url_allowlisted", action="store_true")
    parser.add_argument("--url-contains-sensitive-data", dest="url_contains_sensitive_data", action="store_true")
    parser.add_argument("--url-opened-without-consent", dest="url_opened_without_consent", action="store_true")
    parser.add_argument("--url-prefetched", dest="url_prefetched", action="store_true")
    parser.add_argument("--untrusted-content-seen", dest="untrusted_content_seen", action="store_true")
    parser.add_argument("--user-can-decline", dest="user_can_decline", action="store_true")
    parser.add_argument("--user-can-review", dest="user_can_review", action="store_true")
    parser.add_argument("--user-consent-recorded", dest="user_consent_recorded", action="store_true")
    parser.add_argument("--expect-decision", choices=sorted(VALID_DECISIONS))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        pack = load_json(args.pack)
        request = request_from_args(args)
        decision = evaluate_mcp_elicitation_boundary_decision(pack, request)
    except (MCPElicitationBoundaryDecisionError, json.JSONDecodeError) as exc:
        print(f"MCP elicitation boundary decision failed: {exc}", file=sys.stderr)
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
