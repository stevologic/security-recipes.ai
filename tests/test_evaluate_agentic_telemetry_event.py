from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agentic_telemetry_event import (
    evaluate_agentic_telemetry_event,
    is_valid_traceparent,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "agentic-telemetry-contract.json"
VALID_TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"


def _mcp_tool_event(**overrides: object) -> dict[str, object]:
    attributes: dict[str, object] = {
        "service.name": "security-recipes-mcp",
        "deployment.environment": "production",
        "trace_id": "trace-ci",
        "span_id": "span-ci",
        "workflow_id": "vulnerable-dependency-remediation",
        "run_id": "run-ci",
        "agent_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "identity_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "correlation_id": "ci-correlation",
        "receipt_id": "sr-run-receipt::vulnerable-dependency-remediation",
        "telemetry.redaction_state": "metadata_only",
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": "repo.contents.patch",
        "mcp.protocol.version": "2026-07-28",
        "mcp.method.name": "tools/call",
        "jsonrpc.request.id": "req-ci",
        "network.transport": "tcp",
        "policy.decision": "allow",
        "authorization.decision": "allow_authorized_mcp_request",
    }
    event: dict[str, object] = {
        "argument_capture": "absent",
        "attributes": attributes,
        "contains_secret": False,
        "event_class": "mcp.tools.call",
        "result_capture": "absent",
        "workflow_id": "vulnerable-dependency-remediation",
    }
    if "attributes" in overrides and isinstance(overrides["attributes"], dict):
        attributes.update(overrides["attributes"])
        overrides = {key: value for key, value in overrides.items() if key != "attributes"}
    event.update(overrides)
    return event


class AgenticTelemetryRequestIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_current_spec_tool_span_is_ready_without_session_id(self) -> None:
        result = evaluate_agentic_telemetry_event(self.pack, _mcp_tool_event())
        self.assertEqual(result["decision"], "telemetry_ready")
        self.assertEqual(result["missing_attributes"], [])

    def test_prior_revision_still_requires_session_id(self) -> None:
        result = evaluate_agentic_telemetry_event(
            self.pack,
            _mcp_tool_event(attributes={"mcp.protocol.version": "2025-11-25"}),
        )
        self.assertEqual(result["decision"], "hold_for_trace_completion")
        self.assertIn("mcp.session.id", result["missing_attributes"])

    def test_current_spec_holds_without_request_id(self) -> None:
        result = evaluate_agentic_telemetry_event(
            self.pack,
            _mcp_tool_event(attributes={"jsonrpc.request.id": ""}),
        )
        self.assertEqual(result["decision"], "hold_for_trace_completion")
        self.assertIn("jsonrpc.request.id", result["missing_attributes"])
        self.assertNotIn("mcp.session.id", result["missing_attributes"])

    def test_valid_traceparent_is_optional_and_accepted(self) -> None:
        result = evaluate_agentic_telemetry_event(
            self.pack,
            _mcp_tool_event(attributes={"traceparent": VALID_TRACEPARENT}),
        )
        self.assertEqual(result["decision"], "telemetry_ready")
        self.assertTrue(is_valid_traceparent(VALID_TRACEPARENT))

    def test_malformed_traceparent_is_held(self) -> None:
        result = evaluate_agentic_telemetry_event(
            self.pack,
            _mcp_tool_event(attributes={"traceparent": "not-a-traceparent"}),
        )
        self.assertEqual(result["decision"], "hold_for_trace_completion")
        self.assertIn("traceparent", result["missing_attributes"])

    def test_all_zero_trace_id_is_rejected(self) -> None:
        self.assertFalse(
            is_valid_traceparent("00-" + ("0" * 32) + "-00f067aa0ba902b7-01")
        )


if __name__ == "__main__":
    unittest.main()
