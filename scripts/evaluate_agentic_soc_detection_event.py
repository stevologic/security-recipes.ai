#!/usr/bin/env python3
"""Evaluate one agentic AI or MCP telemetry event against the SOC pack."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_PACK = Path("data/evidence/agentic-soc-detection-pack.json")
NO_ALERT_DECISION = "soc_no_alert"
HOLD_TRACE_DECISION = "soc_hold_for_trace_completion"
HOLD_WORKFLOW_DECISION = "soc_hold_for_unregistered_workflow"
KILL_DECISION = "soc_critical_kill_session"


class SocDetectionEvaluationError(RuntimeError):
    """Raised when SOC detection evaluation cannot run."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SocDetectionEvaluationError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise SocDetectionEvaluationError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SocDetectionEvaluationError(f"{path} root must be an object")
    return payload


def normalize_attributes(attributes: dict[str, Any] | None) -> dict[str, str]:
    output: dict[str, str] = {}
    for key, value in (attributes or {}).items():
        if value is None:
            continue
        output[str(key)] = str(value)
    return output


def workflow_overlay_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = pack.get("workflow_detection_overlays", [])
    if not isinstance(rows, list):
        return {}
    return {
        str(row.get("workflow_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("workflow_id")
    }


def detection_rules(pack: dict[str, Any]) -> list[dict[str, Any]]:
    rows = pack.get("detection_rules", [])
    if not isinstance(rows, list):
        return []
    return sorted(
        [row for row in rows if isinstance(row, dict)],
        key=lambda row: (-int(row.get("severity_score") or 0), str(row.get("id"))),
    )


def get_field(runtime_event: dict[str, Any], attributes: dict[str, str], field: str) -> str:
    if field in runtime_event and runtime_event.get(field) is not None:
        return str(runtime_event.get(field))
    return attributes.get(field, "")


def truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def as_number(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def list_value(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def condition_matches(condition: dict[str, Any], runtime_event: dict[str, Any], attributes: dict[str, str]) -> bool:
    field = str(condition.get("field", ""))
    operator = str(condition.get("operator", ""))
    actual = get_field(runtime_event, attributes, field)
    value = condition.get("value")

    if operator == "bool_true":
        return truthy(actual)
    if operator == "equals":
        return actual == str(value)
    if operator == "not_equals":
        return actual != str(value)
    if operator == "not_equals_field":
        return actual != get_field(runtime_event, attributes, str(value))
    if operator == "in":
        return actual in set(list_value(value))
    if operator == "contains_any":
        lowered = actual.lower()
        return any(str(item).lower() in lowered for item in list_value(value))
    if operator == "greater_equal":
        actual_number = as_number(actual)
        expected_number = as_number(str(value))
        return actual_number is not None and expected_number is not None and actual_number >= expected_number
    return False


def rule_matches(rule: dict[str, Any], runtime_event: dict[str, Any], attributes: dict[str, str]) -> bool:
    event_class = str(runtime_event.get("event_class", "")).strip()
    event_classes = {str(item) for item in rule.get("event_classes", [])}
    if event_classes and event_class not in event_classes:
        return False

    all_conditions = [
        condition
        for condition in rule.get("all_match_conditions", [])
        if isinstance(condition, dict)
    ]
    any_conditions = [
        condition
        for condition in rule.get("any_match_conditions", [])
        if isinstance(condition, dict)
    ]
    return all(condition_matches(condition, runtime_event, attributes) for condition in all_conditions) and (
        not any_conditions or any(condition_matches(condition, runtime_event, attributes) for condition in any_conditions)
    )


def has_prohibited_field(attributes: dict[str, str]) -> list[str]:
    prohibited_names = {
        "api_key",
        "authorization_header",
        "cross_tenant_context",
        "customer_secret",
        "private_key",
        "raw_access_token",
        "seed_phrase",
        "unredacted_pii",
    }
    markers = [
        "bearer ",
        "-----begin private key-----",
        "seed phrase",
        "sk_live_",
        "xoxb-",
        "ghp_",
        "aws_secret_access_key",
    ]
    found: list[str] = []
    for key, value in attributes.items():
        low_key = key.lower()
        low_value = value.lower()
        if low_key in prohibited_names:
            found.append(key)
            continue
        if any(marker in low_value for marker in markers):
            found.append(key)
    return sorted(set(found))


def missing_attributes_for_rule(
    pack: dict[str, Any],
    rule: dict[str, Any],
    runtime_event: dict[str, Any],
    attributes: dict[str, str],
) -> list[str]:
    required = {
        *[str(item) for item in pack.get("detection_contract", {}).get("required_common_attributes", [])],
        *[str(item) for item in rule.get("required_attributes", [])],
    }
    return sorted(
        attr
        for attr in required
        if not get_field(runtime_event, attributes, attr)
    )


def common_missing_attributes(pack: dict[str, Any], runtime_event: dict[str, Any], attributes: dict[str, str]) -> list[str]:
    return sorted(
        str(attr)
        for attr in pack.get("detection_contract", {}).get("required_common_attributes", [])
        if not get_field(runtime_event, attributes, str(attr))
    )


def evaluate_agentic_soc_detection_event(pack: dict[str, Any], runtime_event: dict[str, Any]) -> dict[str, Any]:
    workflow_id = str(runtime_event.get("workflow_id", "")).strip()
    event_class = str(runtime_event.get("event_class", "")).strip()
    attributes = normalize_attributes(runtime_event.get("attributes") if isinstance(runtime_event.get("attributes"), dict) else {})
    workflow_overlay = workflow_overlay_by_id(pack).get(workflow_id)

    if not workflow_overlay:
        return {
            "available": True,
            "decision": HOLD_WORKFLOW_DECISION,
            "event_class": event_class,
            "matched_rule": None,
            "missing_attributes": [],
            "notes": ["Workflow is not registered in the SOC detection pack."],
            "prohibited_fields": [],
            "workflow_id": workflow_id,
        }

    prohibited = has_prohibited_field(attributes)
    if runtime_event.get("contains_secret") or prohibited:
        return {
            "available": True,
            "decision": KILL_DECISION,
            "event_class": event_class,
            "matched_rule": {
                "id": "secret-or-cross-tenant-telemetry",
                "title": "Secret or cross-tenant data emitted into telemetry",
            },
            "missing_attributes": common_missing_attributes(pack, runtime_event, attributes),
            "notes": ["Prohibited secret, token, key, PII, or cross-tenant telemetry appeared in the event."],
            "prohibited_fields": prohibited,
            "workflow_id": workflow_id,
        }

    event_class_known = False
    for rule in detection_rules(pack):
        if event_class in {str(item) for item in rule.get("event_classes", [])}:
            event_class_known = True
        if not rule_matches(rule, runtime_event, attributes):
            continue
        return {
            "available": True,
            "decision": rule.get("decision"),
            "event_class": event_class,
            "matched_rule": {
                "id": rule.get("id"),
                "severity": rule.get("severity"),
                "title": rule.get("title"),
            },
            "missing_attributes": missing_attributes_for_rule(pack, rule, runtime_event, attributes),
            "notes": [rule.get("response_playbook", "SOC response playbook is not defined.")],
            "prohibited_fields": [],
            "workflow_id": workflow_id,
        }

    missing = common_missing_attributes(pack, runtime_event, attributes)
    if event_class_known and missing:
        return {
            "available": True,
            "decision": HOLD_TRACE_DECISION,
            "event_class": event_class,
            "matched_rule": None,
            "missing_attributes": missing,
            "notes": ["Telemetry event is not complete enough for SOC-grade detection confidence."],
            "prohibited_fields": [],
            "workflow_id": workflow_id,
        }

    return {
        "available": True,
        "decision": NO_ALERT_DECISION,
        "event_class": event_class,
        "matched_rule": None,
        "missing_attributes": [],
        "notes": ["No SOC detection rule matched this event."],
        "prohibited_fields": [],
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
    parser.add_argument("--event-class", required=True)
    parser.add_argument("--attribute", action="append", type=parse_attribute, default=[], help="Runtime attribute in key=value form.")
    parser.add_argument("--contains-secret", action="store_true")
    parser.add_argument("--expect-decision")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        pack = load_json(args.pack)
        decision = evaluate_agentic_soc_detection_event(
            pack,
            {
                "attributes": dict(args.attribute),
                "contains_secret": args.contains_secret,
                "event_class": args.event_class,
                "workflow_id": args.workflow_id,
            },
        )
    except SocDetectionEvaluationError as exc:
        print(f"agentic SOC detection evaluation failed: {exc}", file=sys.stderr)
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
