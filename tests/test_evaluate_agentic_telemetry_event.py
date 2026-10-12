from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agentic_telemetry_event import (
    evaluate_agentic_telemetry_event,
    is_valid_w3c_traceparent,
    protocol_version_requires_session_id,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "agentic-telemetry-contract.json"
VALID_TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


def _mcp_tool_event(**overrides: object) -> dict[str, object]:
    attributes = {
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
    attribute_overrides = overrides.pop("attributes", None)
    if isinstance(attribute_overrides, dict):
        attributes.update({str(key): str(value) for key, value in attribute_overrides.items()})
        for key, value in list(attributes.items()):
            if value == "":
                attributes.pop(key)
    event: dict[str, object] = {
        "workflow_id": "vulnerable-dependency-remediation",
        "event_class": "mcp.tools.call",
        "attributes": attributes,
    }
    event.update(overrides)
    return event


class AgenticTelemetryRequestIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_current_spec_without_session_id_is_ready(self) -> None:
        result = evaluate_agentic_telemetry_event(self.pack, _mcp_tool_event())
        self.assertEqual(result["decision"], "telemetry_ready")
        self.assertEqual(result["missing_attributes"], [])
        self.assertTrue(any("mcp.session.id is not required" in note for note in result["notes"]))

    def test_current_spec_with_session_id_treats_it_as_correlation(self) -> None:
        result = evaluate_agentic_telemetry_event(
            self.pack,
            _mcp_tool_event(attributes={"mcp.session.id": "session-ci"}),
        )
        self.assertEqual(result["decision"], "telemetry_ready")
        self.assertTrue(any("host-session correlation" in note for note in result["notes"]))

    def test_legacy_protocol_without_session_id_is_held(self) -> None:
        result = evaluate_agentic_telemetry_event(
            self.pack,
            _mcp_tool_event(attributes={"mcp.protocol.version": "2025-11-25"}),
        )
        self.assertEqual(result["decision"], "hold_for_trace_completion")
        self.assertIn("mcp.session.id", result["missing_attributes"])

    def test_unspecified_protocol_version_stays_on_the_required_session_path(self) -> None:
        result = evaluate_agentic_telemetry_event(
            self.pack,
            _mcp_tool_event(attributes={"mcp.protocol.version": ""}),
        )
        self.assertEqual(result["decision"], "hold_for_trace_completion")
        self.assertIn("mcp.session.id", result["missing_attributes"])
        self.assertTrue(protocol_version_requires_session_id(""))

    def test_current_spec_missing_request_id_is_held(self) -> None:
        result = evaluate_agentic_telemetry_event(
            self.pack,
            _mcp_tool_event(attributes={"jsonrpc.request.id": ""}),
        )
        self.assertEqual(result["decision"], "hold_for_trace_completion")
        self.assertIn("jsonrpc.request.id", result["missing_attributes"])

    def test_invalid_traceparent_is_held(self) -> None:
        result = evaluate_agentic_telemetry_event(
            self.pack,
            _mcp_tool_event(attributes={"traceparent": "not-a-traceparent"}),
        )
        self.assertEqual(result["decision"], "hold_for_trace_completion")
        self.assertTrue(any("W3C Trace Context" in note for note in result["notes"]))

    def test_valid_traceparent_stays_ready(self) -> None:
        result = evaluate_agentic_telemetry_event(
            self.pack,
            _mcp_tool_event(attributes={"traceparent": VALID_TRACEPARENT}),
        )
        self.assertEqual(result["decision"], "telemetry_ready")
        self.assertTrue(is_valid_w3c_traceparent(VALID_TRACEPARENT))

    def test_all_zero_trace_id_is_not_valid_traceparent(self) -> None:
        self.assertFalse(
            is_valid_w3c_traceparent("00-00000000000000000000000000000000-00f067aa0ba902b7-01")
        )


if __name__ == "__main__":
    unittest.main()
