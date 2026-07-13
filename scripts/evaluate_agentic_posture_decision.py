#!/usr/bin/env python3
"""Evaluate one runtime event against the agentic posture snapshot."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_SNAPSHOT = Path("data/evidence/agentic-posture-snapshot.json")
ALLOW_DECISION = "allow_with_posture_monitoring"
GUARDED_DECISION = "guarded_execution_required"
HOLD_ARCH_DECISION = "hold_for_architecture_review"
HOLD_XPIA_DECISION = "hold_for_xpia_human_review"
HOLD_WORKFLOW_DECISION = "hold_for_unregistered_workflow"
KILL_DECISION = "kill_session_on_posture_signal"


class PostureEvaluationError(RuntimeError):
    """Raised when posture evaluation cannot run."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PostureEvaluationError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise PostureEvaluationError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise PostureEvaluationError(f"{path} root must be an object")
    return payload


def workflow_by_id(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = snapshot.get("workflow_posture", [])
    if not isinstance(rows, list):
        return {}
    return {
        str(row.get("workflow_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("workflow_id")
    }


def normalize(value: Any) -> str:
    return str(value or "").strip()


def high_or_critical(value: str) -> bool:
    return value.lower() in {"high", "critical"}


def evaluate_agentic_posture_decision(snapshot: dict[str, Any], runtime_event: dict[str, Any]) -> dict[str, Any]:
    workflow_id = normalize(runtime_event.get("workflow_id"))
    workflow = workflow_by_id(snapshot).get(workflow_id)
    namespace = normalize(runtime_event.get("mcp_namespace") or runtime_event.get("namespace"))
    risk_factor = normalize(runtime_event.get("risk_factor"))
    autonomy_level = normalize(runtime_event.get("autonomy_level") or "bounded")
    xpia_risk = normalize(runtime_event.get("indirect_prompt_injection_risk") or "unknown")
    connector_status = normalize(runtime_event.get("connector_status"))
    human_approval_present = bool(runtime_event.get("human_approval_present"))
    contains_secret = bool(runtime_event.get("contains_secret"))
    session_exfiltration_path = bool(runtime_event.get("session_exfiltration_path"))
    unregistered_agent = bool(runtime_event.get("unregistered_agent"))

    if contains_secret or risk_factor in {"secret_egress", "prohibited_context"}:
        return {
            "decision": KILL_DECISION,
            "notes": ["Secret, token, prohibited context, or raw credential material appeared in the posture event."],
            "workflow_id": workflow_id,
            "mcp_namespace": namespace,
        }

    if not workflow:
        return {
            "decision": HOLD_WORKFLOW_DECISION,
            "notes": ["Workflow is not registered in the posture snapshot."],
            "workflow_id": workflow_id,
            "mcp_namespace": namespace,
        }

    if unregistered_agent:
        return {
            "decision": KILL_DECISION,
            "notes": ["Unregistered agent attempted to use a governed posture path."],
            "workflow_id": workflow_id,
            "mcp_namespace": namespace,
        }

    if session_exfiltration_path:
        return {
            "decision": KILL_DECISION,
            "notes": ["Runtime session combines private context, untrusted content, and exfiltration-capable tool access."],
            "workflow_id": workflow_id,
            "mcp_namespace": namespace,
        }

    if high_or_critical(xpia_risk) and autonomy_level in {"high", "autonomous"} and not human_approval_present:
        return {
            "decision": HOLD_XPIA_DECISION,
            "notes": ["High-autonomy agent with high indirect prompt-injection exposure requires human approval before action."],
            "workflow_id": workflow_id,
            "mcp_namespace": namespace,
        }

    highest_path = workflow.get("highest_exposure_path") if isinstance(workflow.get("highest_exposure_path"), dict) else {}
    if workflow.get("posture_decision") == "architecture_review" or int(highest_path.get("score") or 0) >= 80:
        return {
            "decision": HOLD_ARCH_DECISION,
            "highest_exposure_path": highest_path,
            "notes": ["Workflow is currently routed to architecture review by the generated posture snapshot."],
            "workflow_id": workflow_id,
            "mcp_namespace": namespace,
        }

    namespaces = {str(item) for item in workflow.get("mcp_namespaces", []) or []}
    if namespace and namespace not in namespaces:
        return {
            "decision": GUARDED_DECISION,
            "notes": ["Requested MCP namespace is not part of the workflow posture map."],
            "workflow_id": workflow_id,
            "mcp_namespace": namespace,
        }

    if connector_status == "pilot" or workflow.get("posture_decision") == "guarded_pilot":
        return {
            "decision": GUARDED_DECISION,
            "notes": ["Workflow or connector remains in guarded pilot posture."],
            "workflow_id": workflow_id,
            "mcp_namespace": namespace,
        }

    return {
        "decision": ALLOW_DECISION,
        "notes": ["Workflow posture allows execution with monitoring, citations, telemetry, and existing MCP gateway policy."],
        "workflow_id": workflow_id,
        "mcp_namespace": namespace,
        "posture_score": workflow.get("posture_score"),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--workflow-id", required=True)
    parser.add_argument("--agent-id")
    parser.add_argument("--namespace", "--mcp-namespace", dest="namespace")
    parser.add_argument("--risk-factor")
    parser.add_argument("--autonomy-level", choices=["bounded", "assisted", "high", "autonomous"], default="bounded")
    parser.add_argument("--indirect-prompt-injection-risk", choices=["unknown", "low", "medium", "high", "critical"], default="unknown")
    parser.add_argument("--connector-status", choices=["", "pilot", "production"], default="")
    parser.add_argument("--human-approval-present", action="store_true")
    parser.add_argument("--contains-secret", action="store_true")
    parser.add_argument("--session-exfiltration-path", action="store_true")
    parser.add_argument("--unregistered-agent", action="store_true")
    parser.add_argument("--expect-decision")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        snapshot = load_json(args.snapshot)
        decision = evaluate_agentic_posture_decision(
            snapshot,
            {
                "agent_id": args.agent_id,
                "autonomy_level": args.autonomy_level,
                "connector_status": args.connector_status,
                "contains_secret": args.contains_secret,
                "human_approval_present": args.human_approval_present,
                "indirect_prompt_injection_risk": args.indirect_prompt_injection_risk,
                "mcp_namespace": args.namespace,
                "risk_factor": args.risk_factor,
                "session_exfiltration_path": args.session_exfiltration_path,
                "unregistered_agent": args.unregistered_agent,
                "workflow_id": args.workflow_id,
            },
        )
    except PostureEvaluationError as exc:
        print(f"agentic posture evaluation failed: {exc}", file=sys.stderr)
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
