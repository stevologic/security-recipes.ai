from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_mcp_gateway_decision import evaluate_policy_decision


REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = REPO_ROOT / "data" / "policy" / "mcp-gateway-policy.json"


def _bounded_read(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "vulnerable-dependency-remediation",
        "agent_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "agent_class": "codex",
        "run_id": "run-acs",
        "tool_namespace": "advisories.vulnerability",
        "tool_access_mode": "read",
        "gate_phase": "tool_call",
    }
    request.update(overrides)
    return request


class MCPGatewayAcsFailOpenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))

    def test_bounded_read_is_allowed_when_guardian_evidence_is_unspecified(self) -> None:
        result = evaluate_policy_decision(self.policy, _bounded_read())
        self.assertEqual(result["decision"], "allow")
        self.assertTrue(result["allowed"])

    def test_timeout_with_fail_open_posture_kills_the_session(self) -> None:
        result = evaluate_policy_decision(
            self.policy,
            _bounded_read(
                guardian_decision_status="timeout",
                on_decision_failure="proceed",
            ),
        )
        self.assertEqual(result["decision"], "kill_session")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("fail-open" in item for item in result["violations"]))

    def test_transport_failure_defaults_to_acs_fail_open_and_kills(self) -> None:
        result = evaluate_policy_decision(
            self.policy,
            _bounded_read(guardian_decision_status="transport_failure"),
        )
        self.assertEqual(result["decision"], "kill_session")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("transport_failure" in item for item in result["violations"]))

    def test_error_without_decision_and_fail_closed_posture_denies(self) -> None:
        result = evaluate_policy_decision(
            self.policy,
            _bounded_read(
                guardian_decision_status="error_without_decision",
                on_decision_failure="deny",
            ),
        )
        self.assertEqual(result["decision"], "deny")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("on_decision_failure=deny" in item for item in result["violations"]))


if __name__ == "__main__":
    unittest.main()
