#!/usr/bin/env python3
"""Evaluate one agentic app launch or expansion decision."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DEFAULT_PACK = Path("data/evidence/agentic-app-intake-pack.json")
ALLOW_DECISIONS = {"approve_reference_launch", "approve_guarded_pilot"}
VALID_DECISIONS = {
    "approve_reference_launch",
    "approve_guarded_pilot",
    "hold_for_agentic_app_security_review",
    "deny_until_controls_exist",
    "kill_session_on_launch_signal",
}
SECRET_DATA_CLASSES = {
    "api_secret",
    "browser_password",
    "live_signing_material",
    "private_key",
    "production_credential",
    "raw_access_token",
    "seed_phrase",
}
HIGH_IMPACT_TERMS = {
    "live_funds_movement",
    "production_deployment",
    "identity_or_policy_admin",
    "credential_or_secret_access",
    "external_customer_communication",
    "persistent_memory_write",
}
KILL_SIGNALS = {
    "secret_or_signer_material_requested",
    "raw_token_passthrough",
    "private_network_or_metadata_ip_egress",
    "autonomous_live_funds_or_production_deploy",
    "unregistered_agent_host",
    "tool_or_skill_changed_after_approval",
    "approval_bypass_attempt",
    "unsafe_mcp_icon_uri",
}

# MCP 2026-07-28 Icons: consumers MUST treat icon metadata and bytes as
# untrusted, MUST use HTTPS or data: URIs, MUST reject javascript:, file:,
# ftp:, ws:, and local app schemes, MUST fetch without credentials, and MUST
# treat SVG as potentially executable. Unspecified icons stay on the prior
# allow path so existing CLI and CI admission checks remain valid.
MCP_ICON_LIST_KEYS = ("icons", "mcp_icons", "icon_uris")
MCP_ICON_SRC_KEYS = ("icon_src", "icon_uri", "iconUrl")
MCP_ICON_SERVER_ORIGIN_KEYS = ("mcp_server_origin", "icon_server_origin")
MCP_ALLOWED_ICON_SCHEMES = {"https", "data"}
MCP_ALLOWED_DATA_ICON_MIMES = {"image/png", "image/jpeg", "image/jpg", "image/webp"}
MCP_SVG_ICON_MIMES = {"image/svg+xml"}


class AppIntakeDecisionError(RuntimeError):
    """Raised when an app intake decision cannot be evaluated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AppIntakeDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise AppIntakeDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AppIntakeDecisionError(f"{path} root must be an object")
    return payload


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def approval_present(value: Any) -> bool:
    if not isinstance(value, dict) or not value:
        return False
    if value.get("id") or value.get("approval_id") or value.get("change_id"):
        return str(value.get("decision", "approved")).strip().lower() in {"approved", "accept", "accepted", "allow"}
    return False


def two_key_present(value: Any) -> bool:
    if not isinstance(value, dict) or not value:
        return False
    approvers = value.get("approvers")
    if isinstance(approvers, list) and len([item for item in approvers if item]) >= 2:
        return True
    return as_bool(value.get("two_key_review"))


def first_present(request: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = request.get(key)
        if value not in (None, "", [], {}):
            return str(value).strip()
    return ""


def collect_mcp_icon_records(request: dict[str, Any]) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(src: str, mime_type: str) -> None:
        src = src.strip()
        mime_type = mime_type.strip()
        if not src:
            return
        key = (src, mime_type)
        if key in seen:
            return
        seen.add(key)
        records.append({"mimeType": mime_type, "src": src})

    for key in MCP_ICON_LIST_KEYS:
        for item in as_list(request.get(key)):
            if isinstance(item, dict):
                add(
                    str(item.get("src") or item.get("uri") or item.get("url") or ""),
                    str(item.get("mimeType") or item.get("mime_type") or ""),
                )
            else:
                add(str(item), "")
    default_mime = str(request.get("icon_mime_type") or request.get("icon_mimeType") or "").strip()
    for key in MCP_ICON_SRC_KEYS:
        for item in as_list(request.get(key)):
            add(str(item), default_mime)
    return records


def normalize_https_origin(value: str) -> str | None:
    parsed = urlparse(value.strip())
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    host = parsed.hostname.lower()
    port = parsed.port
    if port in (None, 443):
        return f"https://{host}"
    return f"https://{host}:{port}"


def data_icon_mime_type(src: str) -> str:
    parsed = urlparse(src)
    if parsed.scheme.lower() != "data":
        return ""
    header = src[5:].split(",", 1)[0]
    mime = header.split(";", 1)[0].strip().lower()
    return mime


def icon_is_svg(src: str, mime_type: str) -> bool:
    declared = mime_type.strip().lower()
    if declared in MCP_SVG_ICON_MIMES:
        return True
    if data_icon_mime_type(src) in MCP_SVG_ICON_MIMES:
        return True
    parsed = urlparse(src)
    path = parsed.path.lower()
    return path.endswith(".svg") or path.endswith(".svgz")


def mcp_icon_uri_violations(request: dict[str, Any]) -> list[str]:
    """Return intake violations for MCP 2026-07-28 icon security rules.

    Unspecified icon metadata stays on the prior allow path. Observed icon
    URIs, credentialed fetches, or unsandboxed SVG must fail closed.
    """
    records = collect_mcp_icon_records(request)
    credentialed = (
        as_bool(request.get("icon_fetch_with_credentials"))
        or as_bool(request.get("icon_fetch_with_cookies"))
        or as_bool(request.get("icon_fetch_with_authorization"))
    )
    svg_unsandboxed = as_bool(request.get("icon_svg_unsandboxed"))
    svg_sandboxed = as_bool(request.get("icon_svg_sandboxed"))
    svg_disallowed = as_bool(request.get("icon_svg_disallowed"))
    redirect_unsafe = as_bool(request.get("icon_redirect_cross_origin")) or as_bool(
        request.get("icon_redirect_scheme_change")
    )
    if (
        not records
        and not credentialed
        and not svg_unsandboxed
        and not redirect_unsafe
    ):
        return []

    violations: list[str] = []
    if credentialed:
        violations.append(
            "MCP icon fetch includes cookies, Authorization headers, or client credentials"
        )
    if redirect_unsafe:
        violations.append(
            "MCP icon redirect changes scheme or crosses origin; clients MUST reject unsafe redirects"
        )

    server_origin = first_present(request, MCP_ICON_SERVER_ORIGIN_KEYS)
    normalized_server = normalize_https_origin(server_origin) if server_origin else None
    svg_seen = svg_unsandboxed

    for record in records:
        src = record["src"]
        mime_type = record["mimeType"]
        parsed = urlparse(src)
        scheme = parsed.scheme.lower()
        if not scheme:
            violations.append(f"MCP icon URI {src!r} is missing a scheme; clients MUST use HTTPS or data:")
            continue
        if scheme not in MCP_ALLOWED_ICON_SCHEMES:
            violations.append(
                f"MCP icon URI {src!r} uses unsafe scheme {scheme}:; "
                "clients MUST reject javascript:, file:, ftp:, ws:, and local app schemes"
            )
            continue
        if scheme == "data":
            mime = data_icon_mime_type(src)
            if mime in MCP_SVG_ICON_MIMES:
                svg_seen = True
            elif mime not in MCP_ALLOWED_DATA_ICON_MIMES:
                violations.append(
                    f"MCP data: icon URI {src!r} is not an allowlisted image type"
                )
            continue
        if parsed.username is not None or parsed.password is not None:
            violations.append(f"MCP icon URI {src!r} includes userinfo credentials")
            continue
        if not parsed.hostname:
            violations.append(f"MCP icon URI {src!r} is missing a host")
            continue
        icon_origin = normalize_https_origin(f"https://{parsed.netloc}")
        if icon_origin is None:
            violations.append(f"MCP icon URI {src!r} is not a valid HTTPS origin")
            continue
        if normalized_server and icon_origin != normalized_server:
            violations.append(
                f"MCP icon URI {src!r} is not same-origin with MCP server {normalized_server}"
            )
        if icon_is_svg(src, mime_type):
            svg_seen = True

    if svg_seen and svg_unsandboxed:
        violations.append(
            "MCP SVG icon is unsandboxed; SVG MAY contain executable JavaScript"
        )
    elif svg_seen and not (svg_sandboxed or svg_disallowed):
        violations.append(
            "MCP SVG icon is not sandboxed or disallowed; treat SVG as potentially executable"
        )
    return violations


def normalize_request(runtime_request: dict[str, Any]) -> dict[str, Any]:
    request = dict(runtime_request)
    for key in [
        "app_id",
        "owner",
        "business_purpose",
        "autonomy_level",
        "deployment_environment",
        "indirect_prompt_injection_risk",
        "telemetry_decision",
        "egress_decision",
        "authorization_decision",
        "runtime_kill_signal",
        "icon_mime_type",
        "mcp_server_origin",
        "icon_server_origin",
    ]:
        request[key] = str(request.get(key) or "").strip()
    for key in [
        "external_write",
        "production_write",
        "destructive_or_irreversible",
        "a2a_or_remote_agent",
        "untrusted_input",
        "startup_or_package_install",
        "icon_fetch_with_credentials",
        "icon_fetch_with_cookies",
        "icon_fetch_with_authorization",
        "icon_svg_unsandboxed",
        "icon_svg_sandboxed",
        "icon_svg_disallowed",
        "icon_redirect_cross_origin",
        "icon_redirect_scheme_change",
    ]:
        request[key] = as_bool(request.get(key))
    memory = request.get("memory_persistence")
    if isinstance(memory, bool):
        request["memory_persistence"] = "persistent" if memory else "none"
    else:
        request["memory_persistence"] = str(memory or "").strip()
    for key in ["data_classes", "mcp_namespaces", "mcp_access_modes", "control_evidence", "requested_high_impact_actions"]:
        request[key] = [str(item) for item in as_list(request.get(key)) if str(item).strip()]
    if request.get("icon_uris") is not None:
        request["icon_uris"] = [str(item) for item in as_list(request.get("icon_uris")) if str(item).strip()]
    if request.get("icons") is not None and not isinstance(request.get("icons"), list):
        request["icons"] = as_list(request.get("icons"))
    if request.get("mcp_icons") is not None and not isinstance(request.get("mcp_icons"), list):
        request["mcp_icons"] = as_list(request.get("mcp_icons"))
    request["human_approval_record"] = request.get("human_approval_record") if isinstance(request.get("human_approval_record"), dict) else {}
    return request


def apps_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("app_id")): row
        for row in as_list(pack.get("app_intake_profiles"))
        if isinstance(row, dict) and row.get("app_id")
    }


def app_preview(app: dict[str, Any] | None) -> dict[str, Any] | None:
    if app is None:
        return None
    return {
        "app_id": app.get("app_id"),
        "autonomy_level": app.get("autonomy_level"),
        "decision": app.get("decision"),
        "external_write": app.get("external_write"),
        "indirect_prompt_injection_risk": app.get("indirect_prompt_injection_risk"),
        "lethal_secret_or_signer_path": app.get("lethal_secret_or_signer_path"),
        "mcp_namespaces": app.get("mcp_namespaces", []),
        "missing_control_evidence": app.get("missing_control_evidence", []),
        "production_write": app.get("production_write"),
        "residual_risk_score": app.get("residual_risk_score"),
        "risk_tier": app.get("risk_tier"),
        "title": app.get("title"),
    }


def result(
    *,
    decision: str,
    reason: str,
    request: dict[str, Any],
    pack: dict[str, Any],
    app: dict[str, Any] | None = None,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise AppIntakeDecisionError(f"unknown decision {decision!r}")
    return {
        "allowed": decision in ALLOW_DECISIONS,
        "decision": decision,
        "evidence": {
            "app_intake_generated_at": pack.get("generated_at"),
            "app_intake_summary": pack.get("app_intake_summary"),
            "source_artifacts": pack.get("source_artifacts"),
        },
        "matched_app": app_preview(app),
        "reason": reason,
        "request": {
            "app_id": request.get("app_id"),
            "autonomy_level": request.get("autonomy_level"),
            "data_classes": request.get("data_classes", []),
            "deployment_environment": request.get("deployment_environment"),
            "egress_decision": request.get("egress_decision"),
            "external_write": request.get("external_write"),
            "indirect_prompt_injection_risk": request.get("indirect_prompt_injection_risk"),
            "mcp_namespaces": request.get("mcp_namespaces", []),
            "owner": request.get("owner"),
            "production_write": request.get("production_write"),
            "telemetry_decision": request.get("telemetry_decision"),
        },
        "violations": violations or [],
    }


def merged_request(app: dict[str, Any] | None, request: dict[str, Any]) -> dict[str, Any]:
    merged = dict(app or {})
    for key, value in dict(request).items():
        if value not in (None, "", [], {}):
            merged[key] = value
    return normalize_request(merged)


def has_secret_or_signer(request: dict[str, Any]) -> bool:
    return bool({str(item) for item in request.get("data_classes", [])} & SECRET_DATA_CLASSES)


def high_impact_actions(request: dict[str, Any]) -> set[str]:
    actions = {str(item) for item in request.get("requested_high_impact_actions", [])}
    if request.get("production_write"):
        actions.add("production_deployment")
    if request.get("destructive_or_irreversible"):
        actions.add("live_funds_movement")
    if has_secret_or_signer(request):
        actions.add("credential_or_secret_access")
    if request.get("external_write"):
        actions.add("external_customer_communication")
    if str(request.get("memory_persistence") or "") not in {"", "none", "append_only_receipts"}:
        actions.add("persistent_memory_write")
    return actions & HIGH_IMPACT_TERMS


def evaluate_agentic_app_intake_decision(app_intake_pack: dict[str, Any], runtime_request: dict[str, Any]) -> dict[str, Any]:
    """Return a deterministic launch decision for one agentic application."""
    if not isinstance(app_intake_pack, dict):
        raise AppIntakeDecisionError("app_intake_pack must be an object")
    if not isinstance(runtime_request, dict):
        raise AppIntakeDecisionError("runtime_request must be an object")

    raw_request = dict(runtime_request)
    request_app_id = str(raw_request.get("app_id") or "").strip()
    app = apps_by_id(app_intake_pack).get(request_app_id) if request_app_id else None
    if app is None and request_app_id:
        normalized = normalize_request(raw_request)
        return result(
            decision="hold_for_agentic_app_security_review",
            reason="app_id is not registered in the intake pack",
            request=normalized,
            pack=app_intake_pack,
            violations=[f"unregistered app_id: {request_app_id}"],
        )

    request = merged_request(app, raw_request)
    signal = str(request.get("runtime_kill_signal") or "")
    if signal:
        return result(
            decision="kill_session_on_launch_signal",
            reason="runtime kill signal was raised before launch or expansion",
            request=request,
            pack=app_intake_pack,
            app=app,
            violations=[signal],
        )

    if has_secret_or_signer(request) and (
        request.get("external_write") or request.get("production_write") or request.get("destructive_or_irreversible")
    ):
        return result(
            decision="kill_session_on_launch_signal",
            reason="request combines secret or signer access with external, production, or irreversible authority",
            request=request,
            pack=app_intake_pack,
            app=app,
            violations=["secret_or_signer_material_requested"],
        )

    violations: list[str] = []
    if not request.get("owner"):
        violations.append("owner is required")
    if not request.get("business_purpose"):
        violations.append("business_purpose is required")
    if request.get("autonomy_level") in {"autonomous", "multi_agent_coordinator"} and request.get("indirect_prompt_injection_risk") == "high" and not approval_present(request.get("human_approval_record")):
        violations.append("high autonomy plus high XPIA risk requires human approval")
    if request.get("external_write") and request.get("egress_decision") not in {"allow_public_egress_with_citation", "allow_approved_processor_egress", "allow_internal_boundary"}:
        violations.append("external write requires an allow egress decision")
    if request.get("production_write") and request.get("authorization_decision") != "allow_authorized_mcp_request":
        violations.append("production write requires allow_authorized_mcp_request")
    if request.get("telemetry_decision") and request.get("telemetry_decision") != "telemetry_ready":
        violations.append("telemetry decision is not telemetry_ready")
    if high_impact_actions(request) and not two_key_present(request.get("human_approval_record")):
        violations.append("high-impact actions require two-key approval evidence")

    profile_namespaces = {str(item) for item in app.get("mcp_namespaces", [])} if app else set()
    requested_namespaces = {str(item) for item in request.get("mcp_namespaces", [])}
    if app and requested_namespaces and not requested_namespaces.issubset(profile_namespaces):
        violations.append("requested MCP namespaces are outside the registered app profile")

    declared_evidence = {str(item) for item in app.get("control_evidence", [])} if app else set()
    runtime_evidence = {str(item) for item in request.get("control_evidence", [])}
    missing_from_request = declared_evidence - runtime_evidence if runtime_evidence else set()
    if raw_request.get("deployment_environment") in {"production", "production_candidate"} and missing_from_request:
        violations.append("production expansion request omits registered control evidence: " + ", ".join(sorted(missing_from_request)))

    icon_violations = mcp_icon_uri_violations(request)
    violations.extend(icon_violations)

    if violations:
        registered_decision = str(app.get("decision")) if app else "hold_for_agentic_app_security_review"
        if icon_violations or registered_decision == "deny_until_controls_exist":
            decision = "deny_until_controls_exist"
            reason = (
                "MCP icon metadata violates 2026-07-28 URI, credential, or SVG rules"
                if icon_violations
                else "runtime launch request does not satisfy the app intake controls"
            )
        else:
            decision = "hold_for_agentic_app_security_review"
            reason = "runtime launch request does not satisfy the app intake controls"
        return result(
            decision=decision,
            reason=reason,
            request=request,
            pack=app_intake_pack,
            app=app,
            violations=violations,
        )

    if app is None:
        return result(
            decision="hold_for_agentic_app_security_review",
            reason="no registered app profile was supplied",
            request=request,
            pack=app_intake_pack,
            violations=["app_id is required"],
        )

    registered_decision = str(app.get("decision") or "")
    if registered_decision not in VALID_DECISIONS:
        return result(
            decision="hold_for_agentic_app_security_review",
            reason="registered app profile has an unknown decision",
            request=request,
            pack=app_intake_pack,
            app=app,
            violations=[f"unknown decision: {registered_decision}"],
        )

    return result(
        decision=registered_decision,
        reason="runtime request satisfies the registered app intake profile",
        request=request,
        pack=app_intake_pack,
        app=app,
    )


def request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.request:
        payload = load_json(args.request)
    else:
        payload = {}
    for key in [
        "app_id",
        "owner",
        "business_purpose",
        "autonomy_level",
        "deployment_environment",
        "indirect_prompt_injection_risk",
        "telemetry_decision",
        "egress_decision",
        "authorization_decision",
        "runtime_kill_signal",
        "mcp_server_origin",
    ]:
        value = getattr(args, key)
        if value not in (None, ""):
            payload[key] = value
    for key in [
        "external_write",
        "production_write",
        "destructive_or_irreversible",
        "memory_persistence",
        "a2a_or_remote_agent",
        "untrusted_input",
        "startup_or_package_install",
        "icon_fetch_with_credentials",
        "icon_svg_unsandboxed",
        "icon_svg_sandboxed",
        "icon_svg_disallowed",
    ]:
        if getattr(args, key):
            payload[key] = True
    for key in ["data_classes", "mcp_namespaces", "mcp_access_modes", "control_evidence", "requested_high_impact_actions"]:
        value = getattr(args, key)
        if value:
            payload[key] = value
    if args.icon_src:
        payload["icon_uris"] = list(args.icon_src)
    if args.human_approval_id:
        payload["human_approval_record"] = {
            "approvers": args.approver or [],
            "decision": "approved",
            "id": args.human_approval_id,
            "two_key_review": bool(args.two_key_review),
        }
    return payload


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--request", type=Path)
    parser.add_argument("--app-id", dest="app_id")
    parser.add_argument("--owner")
    parser.add_argument("--business-purpose", dest="business_purpose")
    parser.add_argument("--autonomy-level", dest="autonomy_level")
    parser.add_argument("--deployment-environment", dest="deployment_environment")
    parser.add_argument("--data-class", dest="data_classes", action="append")
    parser.add_argument("--mcp-namespace", dest="mcp_namespaces", action="append")
    parser.add_argument("--mcp-access-mode", dest="mcp_access_modes", action="append")
    parser.add_argument("--control-evidence", action="append")
    parser.add_argument("--requested-high-impact-action", dest="requested_high_impact_actions", action="append")
    parser.add_argument("--indirect-prompt-injection-risk", dest="indirect_prompt_injection_risk")
    parser.add_argument("--telemetry-decision", dest="telemetry_decision")
    parser.add_argument("--egress-decision", dest="egress_decision")
    parser.add_argument("--authorization-decision", dest="authorization_decision")
    parser.add_argument("--external-write", action="store_true")
    parser.add_argument("--production-write", action="store_true")
    parser.add_argument("--destructive-or-irreversible", action="store_true")
    parser.add_argument("--memory-persistence", action="store_true")
    parser.add_argument("--a2a-or-remote-agent", action="store_true")
    parser.add_argument("--untrusted-input", action="store_true")
    parser.add_argument("--startup-or-package-install", action="store_true")
    parser.add_argument("--human-approval-id")
    parser.add_argument("--approver", action="append")
    parser.add_argument("--two-key-review", action="store_true")
    parser.add_argument("--runtime-kill-signal")
    parser.add_argument(
        "--icon-src",
        action="append",
        dest="icon_src",
        help="MCP icon src URI to evaluate against 2026-07-28 icon security rules",
    )
    parser.add_argument("--mcp-server-origin", dest="mcp_server_origin")
    parser.add_argument("--icon-fetch-with-credentials", action="store_true")
    parser.add_argument("--icon-svg-unsandboxed", action="store_true")
    parser.add_argument("--icon-svg-sandboxed", action="store_true")
    parser.add_argument("--icon-svg-disallowed", action="store_true")
    parser.add_argument("--expect-decision", choices=sorted(VALID_DECISIONS))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        pack = load_json(args.pack)
        request = request_from_args(args)
        decision = evaluate_agentic_app_intake_decision(pack, request)
    except AppIntakeDecisionError as exc:
        print(f"agentic app intake decision failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(decision, indent=2, sort_keys=True))
    if args.expect_decision and decision.get("decision") != args.expect_decision:
        print(f"expected decision {args.expect_decision!r}, got {decision.get('decision')!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
