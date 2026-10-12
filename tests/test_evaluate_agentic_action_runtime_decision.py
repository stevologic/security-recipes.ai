from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agentic_action_runtime_decision import (
    evaluate_agentic_action_runtime_decision,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "agentic-action-runtime-pack.json"


def _bounded_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "vulnerable-dependency-remediation",
        "action_class": "repo_branch_write",
        "run_id": "run-action",
        "agent_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "identity_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "tenant_id": "tenant-demo",
        "correlation_id": "corr-action",
        "intent_summary": "Patch dependency lockfiles on a scoped remediation branch",
        "policy_pack_hash": "sha256:policy",
        "authorization_decision": "allow_authorized_mcp_request",
        "receipt_id": "receipt-action",
    }
    request.update(overrides)
    return request


class AgenticActionRuntimeStateHandleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_bounded_repo_write_is_allowed_when_state_handle_is_unspecified(self) -> None:
        result = evaluate_agentic_action_runtime_decision(self.pack, _bounded_request())
        self.assertEqual(result["decision"], "allow_bounded_action")
        self.assertTrue(result["allowed"])

    def test_unbound_state_handle_kills_the_session(self) -> None:
        result = evaluate_agentic_action_runtime_decision(
            self.pack,
            _bounded_request(state_handle_unbound=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_runtime_action_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("principal binding" in item for item in result["violations"])
        )

    def test_guessable_state_handle_kills_the_session(self) -> None:
        result = evaluate_agentic_action_runtime_decision(
            self.pack,
            _bounded_request(state_handle_guessable=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_runtime_action_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("predictable or sequential" in item for item in result["violations"])
        )

    def test_principal_mismatched_state_handle_kills_the_session(self) -> None:
        result = evaluate_agentic_action_runtime_decision(
            self.pack,
            _bounded_request(state_handle_principal_mismatch=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_runtime_action_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("verified token subject" in item for item in result["violations"])
        )


if __name__ == "__main__":
    unittest.main()
