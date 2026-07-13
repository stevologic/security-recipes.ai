#!/usr/bin/env python3
"""Evaluate a live MCP tool surface against the pinned drift baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_PACK = Path("data/evidence/mcp-tool-surface-drift-pack.json")
ALLOW_PINNED_DECISION = "allow_pinned_tool_surface"
ALLOW_REVIEWED_DECISION = "allow_reviewed_tool_surface"
HOLD_DECISION = "hold_for_tool_surface_review"
DENY_REGRESSION_DECISION = "deny_tool_surface_regression"
DENY_UNREGISTERED_DECISION = "deny_unregistered_tool_surface"
KILL_DECISION = "kill_session_on_tool_surface_signal"
VALID_DECISIONS = {
    ALLOW_PINNED_DECISION,
    ALLOW_REVIEWED_DECISION,
    HOLD_DECISION,
    DENY_REGRESSION_DECISION,
    DENY_UNREGISTERED_DECISION,
    KILL_DECISION,
}
HIGH_IMPACT_ADDED_FLAGS = {
    "command",
    "delete",
    "deploy",
    "external_send",
    "funds_movement",
    "metadata_ip",
    "private_network",
    "production_credential",
    "publish",
    "shell",
    "signer",
    "token",
    "webhook",
}


class MCPToolSurfaceDriftDecisionError(RuntimeError):
    """Raised when a tool-surface drift decision cannot be evaluated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise MCPToolSurfaceDriftDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise MCPToolSurfaceDriftDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise MCPToolSurfaceDriftDecisionError(f"{path} root must be an object")
    return payload


def stable_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def text_hash(value: str) -> str:
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


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


def normalize_bool_map(value: dict[str, Any]) -> dict[str, bool]:
    return dict(sorted((str(key), as_bool(item)) for key, item in value.items()))


def surfaces_by_key(pack: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (str(surface.get("namespace")), str(surface.get("tool_name"))): surface
        for surface in as_list(pack.get("tool_surfaces"))
        if isinstance(surface, dict) and surface.get("namespace") and surface.get("tool_name")
    }


def surfaces_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(surface.get("id")): surface
        for surface in as_list(pack.get("tool_surfaces"))
        if isinstance(surface, dict) and surface.get("id")
    }


def approval_present(record: dict[str, Any]) -> bool:
    if not record:
        return False
    if record.get("id") or record.get("approval_id") or record.get("ticket_id"):
        return str(record.get("decision", "approved")).lower() in {"approved", "accept", "accepted", "allow"}
    return False


def parse_json_value(value: str | None, label: str) -> Any:
    if value is None:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(f"{label} must be valid JSON: {exc}") from exc


def normalize_runtime_request(runtime_request: dict[str, Any]) -> dict[str, Any]:
    request = dict(runtime_request)
    for key in [
        "surface_id",
        "workflow_id",
        "namespace",
        "tool_name",
        "requested_access_mode",
        "description_sha256",
        "input_schema_sha256",
        "output_schema_sha256",
        "annotations_sha256",
        "surface_hash",
        "session_id",
        "run_id",
        "agent_id",
        "tenant_id",
        "correlation_id",
        "runtime_kill_signal",
    ]:
        request[key] = str(request.get(key) or "").strip()
    for key in [
        "capability_expansion",
        "data_class_expansion",
        "external_system_expansion",
        "server_trust_downgrade",
        "tool_list_changed_after_approval",
        "tool_removed",
        "contains_secret",
        "private_network_destination",
        "approval_bypass_signal",
        "hidden_instruction_signal",
        "annotation_relaxes_controls",
    ]:
        request[key] = as_bool(request.get(key))
    approval = request.get("human_approval_record")
    request["human_approval_record"] = approval if isinstance(approval, dict) else {}
    request["added_capability_flags"] = [
        str(flag).strip()
        for flag in as_list(request.get("added_capability_flags"))
        if str(flag).strip()
    ]
    return request


def observed_hashes(request: dict[str, Any]) -> dict[str, str]:
    return {
        key: str(request.get(key) or "").strip()
        for key in [
            "description_sha256",
            "input_schema_sha256",
            "output_schema_sha256",
            "annotations_sha256",
            "surface_hash",
        ]
        if str(request.get(key) or "").strip()
    }


def drift_violations(surface: dict[str, Any], request: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    for key in [
        "description_sha256",
        "input_schema_sha256",
        "output_schema_sha256",
        "annotations_sha256",
        "surface_hash",
    ]:
        observed = str(request.get(key) or "").strip()
        if observed and observed != str(surface.get(key) or "").strip():
            violations.append(f"{key} drift")
    for key in [
        "server_trust_downgrade",
        "tool_list_changed_after_approval",
        "tool_removed",
        "data_class_expansion",
        "external_system_expansion",
        "annotation_relaxes_controls",
    ]:
        if request.get(key):
            violations.append(key)
    return violations


def kill_violations(request: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    if request.get("runtime_kill_signal"):
        violations.append(str(request.get("runtime_kill_signal")))
    for key in [
        "capability_expansion",
        "contains_secret",
        "private_network_destination",
        "approval_bypass_signal",
        "hidden_instruction_signal",
    ]:
        if request.get(key):
            violations.append(key)
    added_flags = {str(flag).lower() for flag in request.get("added_capability_flags", [])}
    high_impact = sorted(added_flags & HIGH_IMPACT_ADDED_FLAGS)
    for flag in high_impact:
        violations.append(f"added high-impact capability: {flag}")
    return violations


def decision_result(
    *,
    decision: str,
    reason: str,
    pack: dict[str, Any],
    request: dict[str, Any],
    surface: dict[str, Any] | None = None,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise MCPToolSurfaceDriftDecisionError(f"unknown decision {decision!r}")
    return {
        "allowed": decision in {ALLOW_PINNED_DECISION, ALLOW_REVIEWED_DECISION},
        "decision": decision,
        "evidence": {
            "drift_pack_generated_at": pack.get("generated_at"),
            "source_artifacts": pack.get("source_artifacts"),
            "tool_surface_summary": pack.get("tool_surface_summary"),
        },
        "matched_tool_surface": surface,
        "observed_hashes": observed_hashes(request),
        "reason": reason,
        "request": {
            "agent_id": request.get("agent_id"),
            "correlation_id": request.get("correlation_id"),
            "namespace": request.get("namespace"),
            "requested_access_mode": request.get("requested_access_mode"),
            "run_id": request.get("run_id"),
            "session_id": request.get("session_id"),
            "surface_id": request.get("surface_id"),
            "tenant_id": request.get("tenant_id"),
            "tool_name": request.get("tool_name"),
            "workflow_id": request.get("workflow_id"),
        },
        "violations": violations or [],
    }


def evaluate_mcp_tool_surface_drift_decision(drift_pack: dict[str, Any], runtime_request: dict[str, Any]) -> dict[str, Any]:
    """Return a deterministic drift decision for one live MCP tool surface."""
    if not isinstance(drift_pack, dict):
        raise MCPToolSurfaceDriftDecisionError("drift_pack must be an object")
    if not isinstance(runtime_request, dict):
        raise MCPToolSurfaceDriftDecisionError("runtime_request must be an object")

    request = normalize_runtime_request(runtime_request)
    surface = None
    if request["surface_id"]:
        surface = surfaces_by_id(drift_pack).get(request["surface_id"])
    if surface is None and request["namespace"] and request["tool_name"]:
        surface = surfaces_by_key(drift_pack).get((request["namespace"], request["tool_name"]))

    kills = kill_violations(request)
    if kills:
        return decision_result(
            decision=KILL_DECISION,
            reason="tool surface showed a kill-session drift signal",
            pack=drift_pack,
            request=request,
            surface=surface,
            violations=kills,
        )

    if surface is None:
        return decision_result(
            decision=DENY_UNREGISTERED_DECISION,
            reason="tool surface is not registered in the drift baseline",
            pack=drift_pack,
            request=request,
            violations=["namespace/tool_name or surface_id is not registered"],
        )

    regressions: list[str] = []
    if request["workflow_id"] and request["workflow_id"] not in set(surface.get("allowed_workflow_ids", []) or []):
        regressions.append(f"workflow_id {request['workflow_id']!r} is not allowed for this tool surface")
    if request["requested_access_mode"] and request["requested_access_mode"] != str(surface.get("access_mode")):
        regressions.append(
            f"requested_access_mode {request['requested_access_mode']!r} does not match baseline {surface.get('access_mode')!r}"
        )
    observed_annotations = runtime_request.get("annotations")
    if isinstance(observed_annotations, dict):
        normalized = normalize_bool_map(observed_annotations)
        if normalized.get("readOnlyHint") and str(surface.get("access_mode")) != "read":
            regressions.append("observed readOnlyHint=true for a non-read baseline")
        if normalized.get("destructiveHint") is False and surface.get("high_impact_surface"):
            regressions.append("observed destructiveHint=false for a high-impact baseline")
    if regressions:
        return decision_result(
            decision=DENY_REGRESSION_DECISION,
            reason="live tool surface regressed from workflow, access, or annotation boundaries",
            pack=drift_pack,
            request=request,
            surface=surface,
            violations=regressions,
        )

    drift = drift_violations(surface, request)
    has_observed_hash = bool(observed_hashes(request))
    has_approval = approval_present(request["human_approval_record"])

    if not has_observed_hash:
        return decision_result(
            decision=HOLD_DECISION,
            reason="live tool surface did not provide enough hashes to compare against the baseline",
            pack=drift_pack,
            request=request,
            surface=surface,
            violations=["missing observed tool-surface hashes"],
        )

    if str(surface.get("source_kind")) != "registered_connector" and not has_approval:
        return decision_result(
            decision=HOLD_DECISION,
            reason="candidate or denied connector surface is fingerprinted but not production-allowed by default",
            pack=drift_pack,
            request=request,
            surface=surface,
            violations=["source_kind is not registered_connector"],
        )

    if drift:
        if has_approval:
            return decision_result(
                decision=ALLOW_REVIEWED_DECISION,
                reason="tool-surface drift is present but tied to a human review record",
                pack=drift_pack,
                request=request,
                surface=surface,
                violations=drift,
            )
        return decision_result(
            decision=HOLD_DECISION,
            reason="live tool surface changed from the pinned baseline and needs review",
            pack=drift_pack,
            request=request,
            surface=surface,
            violations=drift,
        )

    return decision_result(
        decision=ALLOW_PINNED_DECISION,
        reason="live tool surface matches the pinned baseline",
        pack=drift_pack,
        request=request,
        surface=surface,
    )


def request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    payload: dict[str, Any]
    if args.request:
        payload = load_json(args.request)
    else:
        payload = {}
    for key in [
        "surface_id",
        "workflow_id",
        "namespace",
        "tool_name",
        "requested_access_mode",
        "description_sha256",
        "input_schema_sha256",
        "output_schema_sha256",
        "annotations_sha256",
        "surface_hash",
        "session_id",
        "run_id",
        "agent_id",
        "tenant_id",
        "correlation_id",
        "runtime_kill_signal",
    ]:
        value = getattr(args, key)
        if value not in (None, ""):
            payload[key] = value

    if args.description is not None:
        payload["description_sha256"] = text_hash(args.description)
    if args.input_schema_json is not None:
        payload["input_schema_sha256"] = stable_hash(parse_json_value(args.input_schema_json, "input schema"))
    if args.output_schema_json is not None:
        payload["output_schema_sha256"] = stable_hash(parse_json_value(args.output_schema_json, "output schema"))
    if args.annotations_json is not None:
        annotations = parse_json_value(args.annotations_json, "annotations")
        if not isinstance(annotations, dict):
            raise argparse.ArgumentTypeError("annotations must be a JSON object")
        payload["annotations"] = annotations
        payload["annotations_sha256"] = stable_hash(normalize_bool_map(annotations))

    for key in [
        "capability_expansion",
        "data_class_expansion",
        "external_system_expansion",
        "server_trust_downgrade",
        "tool_list_changed_after_approval",
        "tool_removed",
        "contains_secret",
        "private_network_destination",
        "approval_bypass_signal",
        "hidden_instruction_signal",
        "annotation_relaxes_controls",
    ]:
        if getattr(args, key):
            payload[key] = True

    if args.added_capability_flag:
        payload["added_capability_flags"] = args.added_capability_flag
    if args.human_approval_id:
        payload["human_approval_record"] = {
            "decision": "approved",
            "id": args.human_approval_id,
        }
    return payload


def apply_baseline_hashes(pack: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    surface = None
    if request.get("surface_id"):
        surface = surfaces_by_id(pack).get(str(request.get("surface_id")))
    if surface is None and request.get("namespace") and request.get("tool_name"):
        surface = surfaces_by_key(pack).get((str(request.get("namespace")), str(request.get("tool_name"))))
    if not surface:
        return request
    next_request = dict(request)
    for key in [
        "description_sha256",
        "input_schema_sha256",
        "output_schema_sha256",
        "annotations_sha256",
        "surface_hash",
    ]:
        next_request.setdefault(key, surface.get(key))
    return next_request


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--request", type=Path)
    parser.add_argument("--surface-id", dest="surface_id")
    parser.add_argument("--workflow-id", dest="workflow_id")
    parser.add_argument("--namespace")
    parser.add_argument("--tool-name", dest="tool_name")
    parser.add_argument("--requested-access-mode", dest="requested_access_mode")
    parser.add_argument("--description")
    parser.add_argument("--description-sha256", dest="description_sha256")
    parser.add_argument("--input-schema-json", dest="input_schema_json")
    parser.add_argument("--input-schema-sha256", dest="input_schema_sha256")
    parser.add_argument("--output-schema-json", dest="output_schema_json")
    parser.add_argument("--output-schema-sha256", dest="output_schema_sha256")
    parser.add_argument("--annotations-json", dest="annotations_json")
    parser.add_argument("--annotations-sha256", dest="annotations_sha256")
    parser.add_argument("--surface-hash", dest="surface_hash")
    parser.add_argument("--session-id", dest="session_id")
    parser.add_argument("--run-id", dest="run_id")
    parser.add_argument("--agent-id", dest="agent_id")
    parser.add_argument("--tenant-id", dest="tenant_id")
    parser.add_argument("--correlation-id", dest="correlation_id")
    parser.add_argument("--runtime-kill-signal", dest="runtime_kill_signal")
    parser.add_argument("--added-capability-flag", action="append", default=[])
    parser.add_argument("--human-approval-id")
    parser.add_argument("--use-baseline-hashes", action="store_true")
    parser.add_argument("--capability-expansion", action="store_true")
    parser.add_argument("--data-class-expansion", action="store_true")
    parser.add_argument("--external-system-expansion", action="store_true")
    parser.add_argument("--server-trust-downgrade", action="store_true")
    parser.add_argument("--tool-list-changed-after-approval", action="store_true")
    parser.add_argument("--tool-removed", action="store_true")
    parser.add_argument("--contains-secret", action="store_true")
    parser.add_argument("--private-network-destination", action="store_true")
    parser.add_argument("--approval-bypass-signal", action="store_true")
    parser.add_argument("--hidden-instruction-signal", action="store_true")
    parser.add_argument("--annotation-relaxes-controls", action="store_true")
    parser.add_argument("--expect-decision", choices=sorted(VALID_DECISIONS))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        pack = load_json(args.pack)
        request = request_from_args(args)
        if args.use_baseline_hashes:
            request = apply_baseline_hashes(pack, request)
        decision = evaluate_mcp_tool_surface_drift_decision(pack, request)
    except (MCPToolSurfaceDriftDecisionError, argparse.ArgumentTypeError, json.JSONDecodeError) as exc:
        print(f"MCP tool-surface drift decision failed: {exc}", file=sys.stderr)
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
