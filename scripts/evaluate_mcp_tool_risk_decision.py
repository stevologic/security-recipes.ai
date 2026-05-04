#!/usr/bin/env python3
"""Evaluate one MCP tool call against the generated tool-risk contract."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_PACK = Path("data/evidence/mcp-tool-risk-contract.json")
ALLOW_DECISION = "allow_tool_call"
CONFIRM_DECISION = "allow_with_confirmation"
HOLD_DECISION = "hold_for_tool_risk_review"
DENY_ANNOTATION_DECISION = "deny_annotation_contradiction"
DENY_SESSION_DECISION = "deny_session_exfiltration_path"
DENY_SCOPE_DECISION = "deny_scope_drift"
KILL_DECISION = "kill_session_on_tool_risk_signal"
VALID_DECISIONS = {
    ALLOW_DECISION,
    CONFIRM_DECISION,
    HOLD_DECISION,
    DENY_ANNOTATION_DECISION,
    DENY_SESSION_DECISION,
    DENY_SCOPE_DECISION,
    KILL_DECISION,
}
WRITE_ACCESS_MODES = {"write_branch", "write_ticket", "approval_required"}
KILL_MARKERS = {
    "raw_secret_in_tool_argument",
    "raw_secret_in_tool_result",
    "credential_or_signer_scope_requested",
    "tool_list_changed_after_approval",
    "unapproved_external_destination",
    "private_network_or_metadata_ip_destination",
    "approval_bypass_attempt",
}


class MCPToolRiskDecisionError(RuntimeError):
    """Raised when a tool-risk decision cannot be evaluated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise MCPToolRiskDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise MCPToolRiskDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise MCPToolRiskDecisionError(f"{path} root must be an object")
    return payload


def as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def normalize_runtime_request(runtime_request: dict[str, Any]) -> dict[str, Any]:
    request = dict(runtime_request)
    for key in [
        "workflow_id",
        "agent_id",
        "run_id",
        "connector_id",
        "namespace",
        "tool_name",
        "requested_access_mode",
        "gate_phase",
        "annotation_source",
        "session_id",
        "correlation_id",
        "policy_pack_hash",
        "authorization_pack_hash",
        "runtime_kill_signal",
    ]:
        request[key] = str(request.get(key) or "").strip()
    for key in [
        "server_trusted",
        "session_reads_private_data",
        "session_sees_untrusted_content",
        "session_can_exfiltrate",
        "contains_secret",
        "tool_list_changed_after_approval",
        "private_network_destination",
    ]:
        request[key] = as_bool(request.get(key))
    approval = request.get("human_approval_record")
    request["human_approval_record"] = approval if isinstance(approval, dict) else {}
    annotations = request.get("annotations")
    request["annotations"] = annotations if isinstance(annotations, dict) else {}
    request["changed_paths"] = [str(path) for path in as_list(request.get("changed_paths")) if str(path).strip()]
    return request


def profiles_by_namespace(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("namespace")): row
        for row in as_list(pack.get("tool_profiles"))
        if isinstance(row, dict) and row.get("namespace")
    }


def profiles_by_connector(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("connector_id")): row
        for row in as_list(pack.get("tool_profiles"))
        if isinstance(row, dict) and row.get("connector_id")
    }


def workflows_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("workflow_id")): row
        for row in as_list(pack.get("workflow_tool_risk"))
        if isinstance(row, dict) and row.get("workflow_id")
    }


def namespace_in_workflow(workflow: dict[str, Any] | None, namespace: str) -> bool:
    if not workflow or not namespace:
        return True
    return any(
        isinstance(row, dict) and str(row.get("namespace")) == namespace
        for row in workflow.get("namespaces", []) or []
    )


def access_mode_in_profile(profile: dict[str, Any] | None, requested_access_mode: str) -> bool:
    if not profile or not requested_access_mode:
        return True
    modes = {str(mode) for mode in profile.get("access_modes", []) or []}
    return requested_access_mode in modes


def annotation_defaults(pack: dict[str, Any]) -> dict[str, bool]:
    defaults = pack.get("evaluator_contract", {}).get("annotation_defaults")
    if isinstance(defaults, dict):
        return {str(key): as_bool(value) for key, value in defaults.items()}
    return {
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
        "readOnlyHint": False,
    }


def normalize_annotations(pack: dict[str, Any], annotations: dict[str, Any], profile: dict[str, Any] | None) -> dict[str, bool]:
    output = annotation_defaults(pack)
    suggested = profile.get("suggested_annotations") if profile and isinstance(profile.get("suggested_annotations"), dict) else {}
    for key, value in suggested.items():
        if key in output:
            output[key] = as_bool(value)
    for key, value in annotations.items():
        if key in output:
            output[key] = as_bool(value)
    return output


def approval_present(record: dict[str, Any]) -> bool:
    if not record:
        return False
    if record.get("id") or record.get("approval_id") or record.get("ticket_id"):
        return str(record.get("decision", "approved")).lower() in {"approved", "accept", "accepted", "allow"}
    return False


def decision_result(
    *,
    decision: str,
    reason: str,
    pack: dict[str, Any],
    request: dict[str, Any],
    profile: dict[str, Any] | None = None,
    workflow: dict[str, Any] | None = None,
    annotations: dict[str, bool] | None = None,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise MCPToolRiskDecisionError(f"unknown decision {decision!r}")
    return {
        "allowed": decision in {ALLOW_DECISION, CONFIRM_DECISION},
        "annotations": annotations or {},
        "decision": decision,
        "evidence": {
            "source_artifacts": pack.get("source_artifacts"),
            "tool_risk_contract_generated_at": pack.get("generated_at"),
            "tool_risk_summary": pack.get("tool_risk_summary"),
        },
        "matched_tool_profile": profile,
        "matched_workflow": workflow,
        "reason": reason,
        "request": {
            "agent_id": request.get("agent_id"),
            "annotation_source": request.get("annotation_source"),
            "connector_id": request.get("connector_id"),
            "correlation_id": request.get("correlation_id"),
            "gate_phase": request.get("gate_phase"),
            "namespace": request.get("namespace"),
            "requested_access_mode": request.get("requested_access_mode"),
            "run_id": request.get("run_id"),
            "server_trusted": request.get("server_trusted"),
            "session_id": request.get("session_id"),
            "tool_name": request.get("tool_name"),
            "workflow_id": request.get("workflow_id"),
        },
        "violations": violations or [],
    }


def runtime_kill_violations(request: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    signal = request.get("runtime_kill_signal")
    if signal:
        violations.append(str(signal))
    if request.get("contains_secret"):
        violations.append("raw_secret_in_tool_argument")
    if request.get("tool_list_changed_after_approval"):
        violations.append("tool_list_changed_after_approval")
    if request.get("private_network_destination"):
        violations.append("private_network_or_metadata_ip_destination")
    return [violation for violation in violations if violation in KILL_MARKERS or violation]


def evaluate_mcp_tool_risk_decision(tool_risk_pack: dict[str, Any], runtime_request: dict[str, Any]) -> dict[str, Any]:
    """Return a deterministic tool-risk decision for one MCP tool call."""
    if not isinstance(tool_risk_pack, dict):
        raise MCPToolRiskDecisionError("tool_risk_pack must be an object")
    if not isinstance(runtime_request, dict):
        raise MCPToolRiskDecisionError("runtime_request must be an object")

    request = normalize_runtime_request(runtime_request)
    profile = None
    if request["namespace"]:
        profile = profiles_by_namespace(tool_risk_pack).get(request["namespace"])
    if profile is None and request["connector_id"]:
        profile = profiles_by_connector(tool_risk_pack).get(request["connector_id"])
    workflow = workflows_by_id(tool_risk_pack).get(request["workflow_id"]) if request["workflow_id"] else None
    annotations = normalize_annotations(tool_risk_pack, request["annotations"], profile)

    kill_violations = runtime_kill_violations(request)
    if kill_violations:
        return decision_result(
            decision=KILL_DECISION,
            reason="runtime kill signal or secret-bearing tool path was observed",
            pack=tool_risk_pack,
            request=request,
            profile=profile,
            workflow=workflow,
            annotations=annotations,
            violations=kill_violations,
        )

    violations: list[str] = []
    if profile is None:
        violations.append("connector_id or namespace is not registered in the tool-risk contract")
        return decision_result(
            decision=HOLD_DECISION,
            reason="tool profile is not registered",
            pack=tool_risk_pack,
            request=request,
            workflow=workflow,
            annotations=annotations,
            violations=violations,
        )

    if request["workflow_id"] and workflow is None:
        violations.append(f"workflow_id is not registered: {request['workflow_id']}")
    if workflow and not namespace_in_workflow(workflow, str(profile.get("namespace"))):
        violations.append(f"namespace {profile.get('namespace')!r} is not approved for workflow {request['workflow_id']!r}")
    if not access_mode_in_profile(profile, request["requested_access_mode"]):
        violations.append(
            f"requested_access_mode {request['requested_access_mode']!r} is outside connector access modes {profile.get('access_modes', [])}"
        )
    if violations:
        return decision_result(
            decision=DENY_SCOPE_DECISION,
            reason="tool call is outside the workflow or connector scope",
            pack=tool_risk_pack,
            request=request,
            profile=profile,
            workflow=workflow,
            annotations=annotations,
            violations=violations,
        )

    requested_mode = request["requested_access_mode"]
    if annotations.get("readOnlyHint") and requested_mode and requested_mode != "read":
        return decision_result(
            decision=DENY_ANNOTATION_DECISION,
            reason="tool declares readOnlyHint=true while runtime request asks for a non-read access mode",
            pack=tool_risk_pack,
            request=request,
            profile=profile,
            workflow=workflow,
            annotations=annotations,
            violations=["readOnlyHint contradicts requested_access_mode"],
        )
    if annotations.get("readOnlyHint") and annotations.get("destructiveHint"):
        return decision_result(
            decision=DENY_ANNOTATION_DECISION,
            reason="tool annotations are contradictory",
            pack=tool_risk_pack,
            request=request,
            profile=profile,
            workflow=workflow,
            annotations=annotations,
            violations=["readOnlyHint=true and destructiveHint=true"],
        )

    factors = profile.get("risk_factors") if isinstance(profile.get("risk_factors"), dict) else {}
    server_trusted = bool(request["server_trusted"] or profile.get("trusted_server"))
    sensitive_tool = bool(
        factors.get("reads_private_data")
        or factors.get("can_exfiltrate")
        or factors.get("writes_state")
        or factors.get("destructive_action_potential")
    )
    if sensitive_tool and not server_trusted:
        return decision_result(
            decision=HOLD_DECISION,
            reason="sensitive tool annotations are not trusted enough to drive an allow decision",
            pack=tool_risk_pack,
            request=request,
            profile=profile,
            workflow=workflow,
            annotations=annotations,
            violations=["trusted_server=false for sensitive tool profile"],
        )

    reads_private = bool(request["session_reads_private_data"] or factors.get("reads_private_data"))
    sees_untrusted = bool(
        request["session_sees_untrusted_content"]
        or factors.get("sees_untrusted_content")
        or annotations.get("openWorldHint")
    )
    can_exfiltrate = bool(
        request["session_can_exfiltrate"]
        or factors.get("can_exfiltrate")
        or requested_mode in WRITE_ACCESS_MODES
    )
    has_approval = approval_present(request["human_approval_record"])
    if reads_private and sees_untrusted and can_exfiltrate and not has_approval:
        return decision_result(
            decision=DENY_SESSION_DECISION,
            reason="session combines private data, untrusted content, and external or state-changing capability without approval",
            pack=tool_risk_pack,
            request=request,
            profile=profile,
            workflow=workflow,
            annotations=annotations,
            violations=["private_data + untrusted_content + exfiltration_capability"],
        )

    if (
        factors.get("requires_human_approval")
        or factors.get("destructive_action_potential")
        or annotations.get("destructiveHint")
        or not annotations.get("idempotentHint")
        or requested_mode in WRITE_ACCESS_MODES
    ):
        if has_approval:
            return decision_result(
                decision=CONFIRM_DECISION,
                reason="tool is sensitive but has an explicit human approval record",
                pack=tool_risk_pack,
                request=request,
                profile=profile,
                workflow=workflow,
                annotations=annotations,
            )
        return decision_result(
            decision=HOLD_DECISION,
            reason="tool is state-changing, destructive, non-idempotent, or approval-required",
            pack=tool_risk_pack,
            request=request,
            profile=profile,
            workflow=workflow,
            annotations=annotations,
            violations=["human approval record required"],
        )

    return decision_result(
        decision=ALLOW_DECISION,
        reason="tool call satisfies registered profile, trusted annotations, workflow scope, and session-combination policy",
        pack=tool_risk_pack,
        request=request,
        profile=profile,
        workflow=workflow,
        annotations=annotations,
    )


def parse_bool_arg(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "y", "on"}:
        return True
    if lowered in {"0", "false", "no", "n", "off"}:
        return False
    raise argparse.ArgumentTypeError("boolean values must be true or false")


def request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    payload: dict[str, Any]
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
        "tool_name",
        "requested_access_mode",
        "gate_phase",
        "annotation_source",
        "session_id",
        "correlation_id",
        "policy_pack_hash",
        "authorization_pack_hash",
        "runtime_kill_signal",
    ]:
        value = getattr(args, key)
        if value not in (None, ""):
            payload[key] = value
    annotations = dict(payload.get("annotations") or {}) if isinstance(payload.get("annotations"), dict) else {}
    for cli_key, annotation_key in [
        ("read_only_hint", "readOnlyHint"),
        ("destructive_hint", "destructiveHint"),
        ("idempotent_hint", "idempotentHint"),
        ("open_world_hint", "openWorldHint"),
    ]:
        value = getattr(args, cli_key)
        if value is not None:
            annotations[annotation_key] = value
    if annotations:
        payload["annotations"] = annotations
    for key in [
        "server_trusted",
        "session_reads_private_data",
        "session_sees_untrusted_content",
        "session_can_exfiltrate",
        "contains_secret",
        "tool_list_changed_after_approval",
        "private_network_destination",
    ]:
        if getattr(args, key):
            payload[key] = True
    if args.human_approval_id:
        payload["human_approval_record"] = {
            "decision": "approved",
            "id": args.human_approval_id,
        }
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
    parser.add_argument("--tool-name", dest="tool_name")
    parser.add_argument("--requested-access-mode", dest="requested_access_mode")
    parser.add_argument("--gate-phase", dest="gate_phase")
    parser.add_argument("--annotation-source", dest="annotation_source")
    parser.add_argument("--session-id", dest="session_id")
    parser.add_argument("--correlation-id", dest="correlation_id")
    parser.add_argument("--policy-pack-hash", dest="policy_pack_hash")
    parser.add_argument("--authorization-pack-hash", dest="authorization_pack_hash")
    parser.add_argument("--read-only-hint", dest="read_only_hint", type=parse_bool_arg)
    parser.add_argument("--destructive-hint", dest="destructive_hint", type=parse_bool_arg)
    parser.add_argument("--idempotent-hint", dest="idempotent_hint", type=parse_bool_arg)
    parser.add_argument("--open-world-hint", dest="open_world_hint", type=parse_bool_arg)
    parser.add_argument("--server-trusted", action="store_true")
    parser.add_argument("--session-reads-private-data", action="store_true")
    parser.add_argument("--session-sees-untrusted-content", action="store_true")
    parser.add_argument("--session-can-exfiltrate", action="store_true")
    parser.add_argument("--contains-secret", action="store_true")
    parser.add_argument("--tool-list-changed-after-approval", action="store_true")
    parser.add_argument("--private-network-destination", action="store_true")
    parser.add_argument("--human-approval-id")
    parser.add_argument("--runtime-kill-signal")
    parser.add_argument("--expect-decision", choices=sorted(VALID_DECISIONS))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        pack = load_json(args.pack)
        request = request_from_args(args)
        decision = evaluate_mcp_tool_risk_decision(pack, request)
    except (MCPToolRiskDecisionError, json.JSONDecodeError) as exc:
        print(f"MCP tool-risk decision failed: {exc}", file=sys.stderr)
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
