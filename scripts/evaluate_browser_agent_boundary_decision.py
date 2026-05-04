#!/usr/bin/env python3
"""Evaluate one browser-agent workspace boundary decision.

The evaluator is deterministic. It checks a generated browser-agent
boundary pack, the declared workspace class, task profile, runtime
evidence, controls, browser authority signals, and kill indicators
before returning allow, hold, deny, or kill.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_PACK = Path("data/evidence/browser-agent-boundary-pack.json")

ALLOW_DECISIONS = {"allow_isolated_browser_task"}
VALID_DECISIONS = {
    *ALLOW_DECISIONS,
    "hold_for_user_confirmation",
    "hold_for_browser_workspace_review",
    "deny_ambient_browser_authority",
    "kill_session_on_browser_agent_signal",
}
UNTRUSTED_CONTENT_LEVELS = {
    "public_web",
    "email",
    "document",
    "shared_drive",
    "support_ticket",
    "github_private_with_user_token",
}


class BrowserAgentBoundaryDecisionError(RuntimeError):
    """Raised when the pack or runtime request is invalid."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BrowserAgentBoundaryDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise BrowserAgentBoundaryDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise BrowserAgentBoundaryDecisionError(f"{path} root must be a JSON object")
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


def normalize_request(runtime_request: dict[str, Any]) -> dict[str, Any]:
    request = dict(runtime_request)
    for key in ["action_classes", "controls", "data_classes", "indicators"]:
        request[key] = [str(item) for item in as_list(request.get(key)) if str(item).strip()]
    for key in [
        "admin_console_write",
        "ambient_cookies_available",
        "contains_secret",
        "cross_origin_egress",
        "dom_credential_visible",
        "downloads_file",
        "executes_code",
        "external_side_effect",
        "hidden_instruction_detected",
        "localhost_access",
        "localhost_probe",
        "local_storage_token",
        "payment_or_purchase",
        "persistent_memory_write",
        "prompt_injection_signal",
        "sends_external_message",
        "uses_personal_profile",
    ]:
        request[key] = as_bool(request.get(key))
    return request


def workspaces_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("id")): row
        for row in as_list(pack.get("workspace_classes"))
        if isinstance(row, dict) and row.get("id")
    }


def tasks_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("id")): row
        for row in as_list(pack.get("task_profiles"))
        if isinstance(row, dict) and row.get("id")
    }


def has_approval(record: Any, approval_state: str | None = None) -> bool:
    if str(approval_state or "").strip().lower() in {"approved", "confirmed", "allow", "granted"}:
        return True
    approval = as_dict(record)
    if not approval:
        return False
    status = str(approval.get("status") or approval.get("decision") or "").strip().lower()
    return bool(approval.get("approval_id") or approval.get("id")) and status in {"approved", "confirmed", "allow", "granted"}


def missing_runtime_attributes(pack: dict[str, Any], request: dict[str, Any]) -> list[str]:
    required = set(pack.get("boundary_contract", {}).get("required_runtime_attributes", []) or [])
    missing: list[str] = []
    for field in sorted(required):
        if field == "approval_state":
            if not request.get(field) and not has_approval(request.get("human_approval_record")):
                missing.append(field)
            continue
        if field in {"action_classes", "data_classes"}:
            if not request.get(field):
                missing.append(field)
            continue
        if not request.get(field):
            missing.append(field)
    return missing


def matched_kill_reasons(pack: dict[str, Any], request: dict[str, Any]) -> list[str]:
    contract = as_dict(pack.get("boundary_contract"))
    configured = lower_set(contract.get("kill_signal_indicators"))
    indicators = lower_set(request.get("indicators"))
    reasons: list[str] = []

    if request.get("runtime_kill_signal"):
        reasons.append(f"runtime_kill_signal: {request['runtime_kill_signal']}")
    for indicator in sorted(configured & indicators):
        reasons.append(f"kill indicator: {indicator}")
    if request.get("contains_secret") and (request.get("cross_origin_egress") or request.get("external_side_effect") or request.get("sends_external_message")):
        reasons.append("secret-bearing browser context is crossing an origin or external delivery boundary")
    if request.get("dom_credential_visible") or request.get("local_storage_token"):
        reasons.append("credential or token is visible to browser DOM, local storage, or model context")
    if request.get("prompt_injection_signal") and (
        request.get("external_side_effect")
        or request.get("sends_external_message")
        or request.get("admin_console_write")
        or request.get("payment_or_purchase")
        or request.get("localhost_access")
        or request.get("persistent_memory_write")
    ):
        reasons.append("prompt-injection signal is paired with a dangerous browser sink")
    if request.get("hidden_instruction_detected") and (request.get("external_side_effect") or request.get("sends_external_message")):
        reasons.append("hidden instruction is attempting an external browser action")
    if request.get("downloads_file") and request.get("executes_code"):
        reasons.append("browser agent attempted download-and-execute behavior")
    if request.get("localhost_probe"):
        reasons.append("browser agent attempted localhost or loopback probing")
    if request.get("admin_console_write"):
        reasons.append("browser agent attempted an admin-console write")
    if request.get("payment_or_purchase"):
        reasons.append("browser agent attempted a payment, purchase, or irreversible transaction")
    return reasons


def ambient_authority_reasons(workspace: dict[str, Any] | None, request: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    workspace_id = str((workspace or {}).get("id") or request.get("workspace_class_id") or "")
    if workspace_id == "logged-in-personal-browser":
        reasons.append("workspace class is a logged-in personal browser")
    if request.get("uses_personal_profile"):
        reasons.append("browser agent is using a personal or shared browser profile")
    if request.get("ambient_cookies_available") and "dedicated_agent_profile" not in set(request.get("controls", [])):
        reasons.append("ambient cookies are available without a dedicated agent profile")
    if str(request.get("auth_state") or "").strip().lower() in {"personal_session", "ambient_user_session", "password_manager"}:
        reasons.append("auth_state implies ambient user authority")
    return reasons


def controls_missing(workspace: dict[str, Any], task: dict[str, Any], request: dict[str, Any]) -> list[str]:
    required = {str(item) for item in workspace.get("required_controls", []) or []}
    required.update(str(item) for item in task.get("required_controls", []) or [])
    observed = {str(item) for item in request.get("controls", []) or []}
    return sorted(required - observed)


def action_violations(workspace: dict[str, Any], task: dict[str, Any], request: dict[str, Any]) -> list[str]:
    allowed = {str(item) for item in workspace.get("allowed_action_classes", []) or []}
    allowed.update(str(item) for item in task.get("allowed_action_classes", []) or [])
    requested = {str(item) for item in request.get("action_classes", []) or []}
    return sorted(requested - allowed)


def decision_result(
    *,
    decision: str,
    pack: dict[str, Any],
    request: dict[str, Any],
    workspace: dict[str, Any] | None,
    task: dict[str, Any] | None,
    reason: str,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise BrowserAgentBoundaryDecisionError(f"unknown decision {decision!r}")
    return {
        "allowed": decision in ALLOW_DECISIONS,
        "decision": decision,
        "evidence": {
            "observed_runtime_attributes": sorted(k for k, v in request.items() if v not in (None, "", [], {}, False)),
            "source_artifacts": pack.get("source_artifacts", {}),
        },
        "pack_generated_at": pack.get("generated_at"),
        "reason": reason,
        "request": {
            "agent_id": request.get("agent_id"),
            "run_id": request.get("run_id"),
            "session_id": request.get("session_id"),
            "target_origin": request.get("target_origin"),
            "task_profile_id": request.get("task_profile_id"),
            "tenant_id": request.get("tenant_id"),
            "workspace_class_id": request.get("workspace_class_id"),
        },
        "task_profile": {
            "default_decision": task.get("default_decision") if task else None,
            "effective_decision": task.get("effective_decision") if task else None,
            "id": task.get("id") if task else request.get("task_profile_id"),
            "title": task.get("title") if task else None,
        },
        "violations": violations or [],
        "workspace_class": {
            "effective_decision": workspace.get("effective_decision") if workspace else None,
            "id": workspace.get("id") if workspace else request.get("workspace_class_id"),
            "residual_risk_score": workspace.get("residual_risk_score") if workspace else None,
            "risk_tier": workspace.get("risk_tier") if workspace else None,
            "title": workspace.get("title") if workspace else None,
        },
    }


def evaluate_browser_agent_boundary_decision(pack: dict[str, Any], runtime_request: dict[str, Any]) -> dict[str, Any]:
    """Return a structured browser-agent boundary decision."""
    if not isinstance(pack, dict):
        raise BrowserAgentBoundaryDecisionError("pack must be an object")
    if not isinstance(runtime_request, dict):
        raise BrowserAgentBoundaryDecisionError("runtime_request must be an object")

    request = normalize_request(runtime_request)
    workspace = workspaces_by_id(pack).get(str(request.get("workspace_class_id") or "").strip())
    task = tasks_by_id(pack).get(str(request.get("task_profile_id") or "").strip())

    if not workspace:
        return decision_result(
            decision="hold_for_browser_workspace_review",
            pack=pack,
            request=request,
            workspace=None,
            task=task,
            reason="workspace class is not registered in the browser-agent boundary pack",
            violations=[f"unknown workspace_class_id: {request.get('workspace_class_id')}"],
        )
    if not task:
        return decision_result(
            decision="hold_for_browser_workspace_review",
            pack=pack,
            request=request,
            workspace=workspace,
            task=None,
            reason="task profile is not registered in the browser-agent boundary pack",
            violations=[f"unknown task_profile_id: {request.get('task_profile_id')}"],
        )

    kill_reasons = matched_kill_reasons(pack, request)
    if kill_reasons:
        return decision_result(
            decision="kill_session_on_browser_agent_signal",
            pack=pack,
            request=request,
            workspace=workspace,
            task=task,
            reason="browser-agent kill signal was observed",
            violations=kill_reasons,
        )

    ambient = ambient_authority_reasons(workspace, request)
    if ambient:
        return decision_result(
            decision="deny_ambient_browser_authority",
            pack=pack,
            request=request,
            workspace=workspace,
            task=task,
            reason="browser agent would inherit ambient user authority",
            violations=ambient,
        )

    allowed_workspace_ids = {str(item) for item in task.get("allowed_workspace_class_ids", []) or []}
    if str(workspace.get("id")) not in allowed_workspace_ids:
        return decision_result(
            decision="hold_for_browser_workspace_review",
            pack=pack,
            request=request,
            workspace=workspace,
            task=task,
            reason="task profile is not approved for this browser workspace class",
            violations=[f"{workspace.get('id')} is outside task {task.get('id')}"],
        )

    content_level = str(request.get("content_trust_level") or "").strip()
    allowed_content = {str(item) for item in workspace.get("allowed_content_trust_levels", []) or []}
    if content_level and allowed_content and content_level not in allowed_content:
        return decision_result(
            decision="hold_for_browser_workspace_review",
            pack=pack,
            request=request,
            workspace=workspace,
            task=task,
            reason="content trust level is outside the approved workspace boundary",
            violations=[f"content_trust_level={content_level} not in {sorted(allowed_content)}"],
        )

    invalid_actions = action_violations(workspace, task, request)
    if invalid_actions:
        return decision_result(
            decision="hold_for_browser_workspace_review",
            pack=pack,
            request=request,
            workspace=workspace,
            task=task,
            reason="requested browser action is outside the workspace or task profile",
            violations=[f"unapproved action_class: {action}" for action in invalid_actions],
        )

    missing_controls = controls_missing(workspace, task, request)
    if missing_controls:
        return decision_result(
            decision="hold_for_browser_workspace_review",
            pack=pack,
            request=request,
            workspace=workspace,
            task=task,
            reason="required browser-agent boundary controls are missing",
            violations=[f"missing control: {control}" for control in missing_controls],
        )

    missing_evidence = missing_runtime_attributes(pack, request)
    if missing_evidence:
        return decision_result(
            decision="hold_for_browser_workspace_review",
            pack=pack,
            request=request,
            workspace=workspace,
            task=task,
            reason="required browser-agent runtime evidence is missing",
            violations=[f"missing {field}" for field in missing_evidence],
        )

    needs_confirmation = (
        request.get("external_side_effect")
        or request.get("sends_external_message")
        or any(action in {"fill_form", "create_issue", "create_ticket", "post_handoff", "draft_reply"} for action in request.get("action_classes", []))
        or content_level in UNTRUSTED_CONTENT_LEVELS
        or str(task.get("effective_decision")) == "hold_for_user_confirmation"
        or str(workspace.get("effective_decision")) == "hold_for_user_confirmation"
    )
    if needs_confirmation and not has_approval(request.get("human_approval_record"), request.get("approval_state")):
        return decision_result(
            decision="hold_for_user_confirmation",
            pack=pack,
            request=request,
            workspace=workspace,
            task=task,
            reason="browser task needs explicit user confirmation before proceeding",
            violations=["missing approved human confirmation"],
        )

    if str(task.get("effective_decision")).startswith("deny") or str(workspace.get("effective_decision")).startswith("deny"):
        return decision_result(
            decision="deny_ambient_browser_authority",
            pack=pack,
            request=request,
            workspace=workspace,
            task=task,
            reason="registered boundary defaults to deny for this browser authority class",
        )

    if int(workspace.get("residual_risk_score") or 0) <= 25 and str(task.get("effective_decision")) == "allow_isolated_browser_task":
        return decision_result(
            decision="allow_isolated_browser_task",
            pack=pack,
            request=request,
            workspace=workspace,
            task=task,
            reason="browser task is isolated, registered, policy-bound, and evidence-complete",
        )

    return decision_result(
        decision="hold_for_user_confirmation",
        pack=pack,
        request=request,
        workspace=workspace,
        task=task,
        reason="browser task is registered and evidence-complete but still requires explicit confirmation by policy",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--runtime-request", type=Path, help="JSON file containing the browser-agent runtime request.")
    parser.add_argument("--workspace-class-id")
    parser.add_argument("--task-profile-id")
    parser.add_argument("--session-id")
    parser.add_argument("--run-id")
    parser.add_argument("--agent-id")
    parser.add_argument("--tenant-id")
    parser.add_argument("--user-intent")
    parser.add_argument("--target-origin")
    parser.add_argument("--content-trust-level")
    parser.add_argument("--auth-state")
    parser.add_argument("--isolation-mode")
    parser.add_argument("--network-egress-policy")
    parser.add_argument("--browser-storage-policy")
    parser.add_argument("--approval-state")
    parser.add_argument("--telemetry-event-id")
    parser.add_argument("--receipt-id")
    parser.add_argument("--runtime-kill-signal")
    parser.add_argument("--action-class", action="append", default=[])
    parser.add_argument("--control", action="append", default=[])
    parser.add_argument("--data-class", action="append", default=[])
    parser.add_argument("--indicator", action="append", default=[])
    parser.add_argument("--human-approval-id")
    parser.add_argument("--human-approval-status")
    parser.add_argument("--admin-console-write", action="store_true")
    parser.add_argument("--ambient-cookies-available", action="store_true")
    parser.add_argument("--contains-secret", action="store_true")
    parser.add_argument("--cross-origin-egress", action="store_true")
    parser.add_argument("--dom-credential-visible", action="store_true")
    parser.add_argument("--downloads-file", action="store_true")
    parser.add_argument("--executes-code", action="store_true")
    parser.add_argument("--external-side-effect", action="store_true")
    parser.add_argument("--hidden-instruction-detected", action="store_true")
    parser.add_argument("--localhost-access", action="store_true")
    parser.add_argument("--localhost-probe", action="store_true")
    parser.add_argument("--local-storage-token", action="store_true")
    parser.add_argument("--payment-or-purchase", action="store_true")
    parser.add_argument("--persistent-memory-write", action="store_true")
    parser.add_argument("--prompt-injection-signal", action="store_true")
    parser.add_argument("--sends-external-message", action="store_true")
    parser.add_argument("--uses-personal-profile", action="store_true")
    parser.add_argument("--expect-decision")
    return parser.parse_args()


def request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.runtime_request:
        return load_json(args.runtime_request)
    request: dict[str, Any] = {
        "action_classes": args.action_class,
        "admin_console_write": args.admin_console_write,
        "agent_id": args.agent_id,
        "ambient_cookies_available": args.ambient_cookies_available,
        "approval_state": args.approval_state,
        "auth_state": args.auth_state,
        "browser_storage_policy": args.browser_storage_policy,
        "contains_secret": args.contains_secret,
        "content_trust_level": args.content_trust_level,
        "controls": args.control,
        "cross_origin_egress": args.cross_origin_egress,
        "data_classes": args.data_class,
        "dom_credential_visible": args.dom_credential_visible,
        "downloads_file": args.downloads_file,
        "executes_code": args.executes_code,
        "external_side_effect": args.external_side_effect,
        "hidden_instruction_detected": args.hidden_instruction_detected,
        "indicators": args.indicator,
        "isolation_mode": args.isolation_mode,
        "localhost_access": args.localhost_access,
        "localhost_probe": args.localhost_probe,
        "local_storage_token": args.local_storage_token,
        "network_egress_policy": args.network_egress_policy,
        "payment_or_purchase": args.payment_or_purchase,
        "persistent_memory_write": args.persistent_memory_write,
        "prompt_injection_signal": args.prompt_injection_signal,
        "receipt_id": args.receipt_id,
        "run_id": args.run_id,
        "runtime_kill_signal": args.runtime_kill_signal,
        "sends_external_message": args.sends_external_message,
        "session_id": args.session_id,
        "target_origin": args.target_origin,
        "task_profile_id": args.task_profile_id,
        "telemetry_event_id": args.telemetry_event_id,
        "tenant_id": args.tenant_id,
        "user_intent": args.user_intent,
        "uses_personal_profile": args.uses_personal_profile,
        "workspace_class_id": args.workspace_class_id,
    }
    if args.human_approval_id or args.human_approval_status:
        request["human_approval_record"] = {
            "approval_id": args.human_approval_id,
            "status": args.human_approval_status,
        }
    return request


def main() -> int:
    args = parse_args()
    try:
        pack = load_json(args.pack)
        result = evaluate_browser_agent_boundary_decision(pack, request_from_args(args))
    except BrowserAgentBoundaryDecisionError as exc:
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
