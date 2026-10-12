#!/usr/bin/env python3
"""Evaluate one agentic telemetry event against the generated contract.

MCP 2026-07-28 removed protocol-level sessions and Mcp-Session-Id.
OpenTelemetry recommends mcp.session.id only when a request is part of
a session. This evaluator allows 2026-07-28 tool spans that carry
jsonrpc.request.id, mcp.method.name, and mcp.protocol.version without
mcp.session.id. Legacy 2025-11-25 traces still require a session id so
stored receipts stay evaluable. A present traceparent must be valid
W3C Trace Context. Unspecified protocol-version evidence stays on the
prior required-session path.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


DEFAULT_PACK = Path("data/evidence/agentic-telemetry-contract.json")
READY_DECISION = "telemetry_ready"
HOLD_TRACE_DECISION = "hold_for_trace_completion"
HOLD_WORKFLOW_DECISION = "hold_for_unregistered_workflow"
DENY_RAW_DECISION = "deny_raw_sensitive_telemetry"
KILL_SECRET_DECISION = "kill_session_on_secret_telemetry"
CURRENT_MCP_PROTOCOL_VERSION = "2026-07-28"
SESSION_ID_ATTRIBUTE = "mcp.session.id"
TRACEPARENT_ATTRIBUTE = "traceparent"
W3C_TRACEPARENT_RE = re.compile(
    r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$"
)


class TelemetryEvaluationError(RuntimeError):
    """Raised when telemetry evaluation cannot run."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TelemetryEvaluationError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise TelemetryEvaluationError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise TelemetryEvaluationError(f"{path} root must be an object")
    return payload


def contract_by_workflow(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = pack.get("workflow_telemetry_contracts", [])
    if not isinstance(rows, list):
        return {}
    return {
        str(row.get("workflow_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("workflow_id")
    }


def signal_class_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = pack.get("signal_classes", [])
    if not isinstance(rows, list):
        return {}
    return {
        str(row.get("id")): row
        for row in rows
        if isinstance(row, dict) and row.get("id")
    }


def normalize_attributes(attributes: dict[str, Any] | None) -> dict[str, str]:
    output: dict[str, str] = {}
    for key, value in (attributes or {}).items():
        if value is None:
            continue
        output[str(key)] = str(value)
    return output


def event_class_to_signal_id(pack: dict[str, Any], event_class: str) -> str | None:
    for signal_id, signal in signal_class_by_id(pack).items():
        if str(signal.get("event_class")) == event_class or signal_id == event_class:
            return signal_id
    return None


def protocol_version_requires_session_id(protocol_version: str) -> bool:
    """Return True when mcp.session.id stays on the prior required path."""
    return str(protocol_version or "").strip() != CURRENT_MCP_PROTOCOL_VERSION


def is_valid_w3c_traceparent(value: str) -> bool:
    match = W3C_TRACEPARENT_RE.fullmatch(str(value or "").strip())
    if not match:
        return False
    version, trace_id, parent_id, _flags = match.groups()
    if version == "ff":
        return False
    if set(trace_id) == {"0"} or set(parent_id) == {"0"}:
        return False
    return True


def required_attributes_for_event(
    pack: dict[str, Any],
    workflow_contract: dict[str, Any],
    event_class: str,
    attributes: dict[str, str] | None = None,
) -> list[str]:
    signal_id = event_class_to_signal_id(pack, event_class)
    signal = signal_class_by_id(pack).get(signal_id or "", {})
    common = {
        "service.name",
        "deployment.environment",
        "trace_id",
        "span_id",
        "workflow_id",
        "run_id",
        "agent_id",
        "identity_id",
        "correlation_id",
        "receipt_id",
        "telemetry.redaction_state",
    }
    base = [
        str(item)
        for item in pack.get("telemetry_contract", {}).get("required_trace_attributes", [])
        if str(item) in common
    ]
    workflow_required = [
        str(item)
        for item in workflow_contract.get("required_attributes", [])
        if str(item) in common
    ]
    signal_required = [str(item) for item in signal.get("required_attributes", [])]
    required = sorted({*base, *workflow_required, *signal_required})
    attrs = attributes or {}
    if not protocol_version_requires_session_id(attrs.get("mcp.protocol.version", "")):
        required = [item for item in required if item != SESSION_ID_ATTRIBUTE]
    return required


def has_prohibited_field(pack: dict[str, Any], attributes: dict[str, str]) -> list[str]:
    prohibited = {str(item).lower() for item in pack.get("telemetry_contract", {}).get("prohibited_telemetry_fields", [])}
    found: list[str] = []
    for key, value in attributes.items():
        low_key = key.lower()
        low_value = value.lower()
        if low_key in prohibited:
            found.append(key)
            continue
        if any(marker in low_value for marker in ["bearer ", "-----begin private key-----", "seed phrase", "sk_live_", "xoxb-"]):
            found.append(key)
    return sorted(set(found))


def evaluate_agentic_telemetry_event(pack: dict[str, Any], runtime_event: dict[str, Any]) -> dict[str, Any]:
    workflow_id = str(runtime_event.get("workflow_id", "")).strip()
    event_class = str(runtime_event.get("event_class", "")).strip()
    attributes = normalize_attributes(runtime_event.get("attributes") if isinstance(runtime_event.get("attributes"), dict) else {})
    workflow_contract = contract_by_workflow(pack).get(workflow_id)
    signal_id = event_class_to_signal_id(pack, event_class)

    if not workflow_contract:
        return {
            "decision": HOLD_WORKFLOW_DECISION,
            "missing_attributes": [],
            "notes": ["Workflow is not registered in the telemetry contract."],
            "prohibited_fields": [],
            "signal_class_id": signal_id,
            "workflow_id": workflow_id,
        }

    prohibited_fields = has_prohibited_field(pack, attributes)
    if runtime_event.get("contains_secret") or prohibited_fields:
        return {
            "decision": KILL_SECRET_DECISION,
            "missing_attributes": [],
            "notes": ["Prohibited secret, token, key, PII, or cross-tenant telemetry appeared in the event."],
            "prohibited_fields": prohibited_fields,
            "signal_class_id": signal_id,
            "workflow_id": workflow_id,
        }

    argument_capture = str(runtime_event.get("argument_capture", "absent"))
    result_capture = str(runtime_event.get("result_capture", "absent"))
    redaction_state = attributes.get("telemetry.redaction_state", "")
    raw_capture = argument_capture == "raw" or result_capture == "raw"
    if raw_capture and redaction_state not in {"redacted", "hashed", "metadata_only"}:
        return {
            "decision": DENY_RAW_DECISION,
            "missing_attributes": ["telemetry.redaction_state"],
            "notes": ["Raw sensitive payload capture requires an explicit redacted, hashed, or metadata_only state."],
            "prohibited_fields": [],
            "signal_class_id": signal_id,
            "workflow_id": workflow_id,
        }

    required = required_attributes_for_event(pack, workflow_contract, event_class, attributes)
    missing = [attr for attr in required if attr not in attributes or attributes.get(attr) == ""]
    if not signal_id:
        missing.append("registered_event_class")

    if missing:
        return {
            "decision": HOLD_TRACE_DECISION,
            "missing_attributes": sorted(set(missing)),
            "notes": ["Telemetry event is not reconstructable enough to trust yet."],
            "prohibited_fields": [],
            "signal_class_id": signal_id,
            "workflow_id": workflow_id,
        }

    if TRACEPARENT_ATTRIBUTE in attributes and not is_valid_w3c_traceparent(
        attributes.get(TRACEPARENT_ATTRIBUTE, "")
    ):
        return {
            "decision": HOLD_TRACE_DECISION,
            "missing_attributes": [],
            "notes": [
                "Present traceparent is not a valid W3C Trace Context header; hold for trace completion."
            ],
            "prohibited_fields": [],
            "signal_class_id": signal_id,
            "workflow_id": workflow_id,
        }

    notes = ["Telemetry event satisfies the generated trace contract and redaction baseline."]
    protocol_version = attributes.get("mcp.protocol.version", "")
    if not protocol_version_requires_session_id(protocol_version):
        if SESSION_ID_ATTRIBUTE in attributes:
            notes.append(
                "mcp.session.id is host-session correlation, not authentication, on MCP 2026-07-28."
            )
        else:
            notes.append(
                "MCP 2026-07-28 request identity uses jsonrpc.request.id, mcp.method.name, "
                "and mcp.protocol.version; mcp.session.id is not required."
            )

    return {
        "decision": READY_DECISION,
        "missing_attributes": [],
        "notes": notes,
        "prohibited_fields": [],
        "signal_class_id": signal_id,
        "workflow_id": workflow_id,
    }


def parse_attribute(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("--attribute values must use key=value")
    key, val = value.split("=", 1)
    key = key.strip()
    if not key:
        raise argparse.ArgumentTypeError("--attribute key cannot be empty")
    return key, val


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--workflow-id", required=True)
    parser.add_argument("--event-class", required=True, help="Signal id or event_class, e.g. mcp.tools.call")
    parser.add_argument("--attribute", action="append", type=parse_attribute, default=[], help="Runtime attribute in key=value form.")
    parser.add_argument("--argument-capture", choices=["absent", "metadata_only", "redacted", "hashed", "raw"], default="absent")
    parser.add_argument("--result-capture", choices=["absent", "metadata_only", "redacted", "hashed", "raw"], default="absent")
    parser.add_argument("--contains-secret", action="store_true")
    parser.add_argument("--expect-decision")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        pack = load_json(args.pack)
        decision = evaluate_agentic_telemetry_event(
            pack,
            {
                "argument_capture": args.argument_capture,
                "attributes": dict(args.attribute),
                "contains_secret": args.contains_secret,
                "event_class": args.event_class,
                "result_capture": args.result_capture,
                "workflow_id": args.workflow_id,
            },
        )
    except TelemetryEvaluationError as exc:
        print(f"agentic telemetry evaluation failed: {exc}", file=sys.stderr)
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
