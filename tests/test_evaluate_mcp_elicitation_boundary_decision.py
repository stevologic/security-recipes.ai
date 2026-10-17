from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_mcp_elicitation_boundary_decision import (
    evaluate_mcp_elicitation_boundary_decision,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "mcp-elicitation-boundary-pack.json"
TASK_ID = "786512e2-9e0d-44bd-8f29-789f320fe840"


def _url_oauth(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "mcp-connector-intake-scanner",
        "agent_id": "sr-agent::mcp-connector-intake::codex",
        "run_id": "run-123",
        "connector_id": "github",
        "namespace": "github.oauth",
        "server_id": "mcp-server::github",
        "elicitation_profile_id": "profile-third-party-oauth-url",
        "input_request_id": "github_oauth",
        "request_state": "opaque-aead-state",
        "mode": "url",
        "url": "https://github.com/login/oauth/authorize",
        "url_domain": "github.com",
        "user_id": "user-123",
        "session_id": "session-123",
        "correlation_id": "corr-123",
        "authorization_pack_hash": "auth-pack-sha256",
        "client_supports_mode": True,
        "server_identity_displayed": True,
        "user_can_decline": True,
        "user_consent_recorded": True,
        "request_state_echoed_exactly": True,
        "request_state_integrity_validated": True,
        "retry_request_bound": True,
        "https_url": True,
        "url_allowlisted": True,
    }
    request.update(overrides)
    return request


def _task_bound_url_oauth(**overrides: object) -> dict[str, object]:
    request = _url_oauth(
        delivery="tasks_get",
        task_id=TASK_ID,
        task_status="input_required",
        tasks_extension_declared=True,
        task_id_entropy_validated=True,
        task_request_authenticated=True,
        tasks_update_fulfillment=True,
    )
    request.pop("retry_request_bound", None)
    request.update(overrides)
    return request


class MCPElicitationTasksExtensionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_synchronous_url_oauth_still_allows(self) -> None:
        result = evaluate_mcp_elicitation_boundary_decision(self.pack, _url_oauth())
        self.assertEqual(result["decision"], "allow_elicitation_with_receipt")
        self.assertTrue(result["allowed"])

    def test_task_bound_url_oauth_allows(self) -> None:
        result = evaluate_mcp_elicitation_boundary_decision(self.pack, _task_bound_url_oauth())
        self.assertEqual(result["decision"], "allow_elicitation_with_receipt")
        self.assertTrue(result["allowed"])

    def test_undeclared_tasks_extension_is_killed(self) -> None:
        result = evaluate_mcp_elicitation_boundary_decision(
            self.pack,
            _task_bound_url_oauth(tasks_extension_declared=False, result_type="task"),
        )
        self.assertEqual(result["decision"], "kill_session_on_elicitation_abuse")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("io.modelcontextprotocol/tasks" in item for item in result["violations"]))

    def test_guessable_task_id_is_killed(self) -> None:
        result = evaluate_mcp_elicitation_boundary_decision(
            self.pack,
            _task_bound_url_oauth(task_id="1", task_id_entropy_validated=False),
        )
        self.assertEqual(result["decision"], "kill_session_on_elicitation_abuse")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("guessable" in item for item in result["violations"]))

    def test_higher_trust_task_channel_is_killed(self) -> None:
        result = evaluate_mcp_elicitation_boundary_decision(
            self.pack,
            _task_bound_url_oauth(task_higher_trust_channel=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_elicitation_abuse")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("higher-trust" in item for item in result["violations"]))

    def test_missing_tasks_update_fulfillment_is_held(self) -> None:
        result = evaluate_mcp_elicitation_boundary_decision(
            self.pack,
            _task_bound_url_oauth(tasks_update_fulfillment=False, retry_request_bound=True),
        )
        self.assertEqual(result["decision"], "hold_for_elicitation_evidence")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("tasks/update" in item for item in result["violations"]))

    def test_unauthenticated_task_request_is_held(self) -> None:
        result = evaluate_mcp_elicitation_boundary_decision(
            self.pack,
            _task_bound_url_oauth(task_request_authenticated=False),
        )
        self.assertEqual(result["decision"], "hold_for_elicitation_evidence")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("task_request_authenticated=false" in item for item in result["violations"]))

    def test_secret_form_on_task_channel_is_still_denied(self) -> None:
        result = evaluate_mcp_elicitation_boundary_decision(
            self.pack,
            {
                "workflow_id": "mcp-gateway-policy",
                "agent_id": "sr-agent::gateway::codex",
                "run_id": "run-124",
                "server_id": "mcp-server::unknown",
                "elicitation_profile_id": "profile-credential-form-prohibited",
                "input_request_id": "api_key_form",
                "request_state": "opaque-aead-state",
                "mode": "form",
                "requested_data_classes": ["api_key"],
                "response_schema_fields": ["api_key"],
                "session_id": "session-124",
                "correlation_id": "corr-124",
                "delivery": "tasks_get",
                "task_id": TASK_ID,
                "task_status": "input_required",
                "client_supports_mode": True,
                "server_identity_displayed": True,
                "user_can_decline": True,
                "user_can_review": True,
                "tasks_extension_declared": True,
                "task_id_entropy_validated": True,
                "task_request_authenticated": True,
                "tasks_update_fulfillment": True,
            },
        )
        self.assertEqual(result["decision"], "deny_sensitive_form_elicitation")
        self.assertFalse(result["allowed"])

    def test_unspecified_task_evidence_stays_on_allow_path(self) -> None:
        result = evaluate_mcp_elicitation_boundary_decision(self.pack, _url_oauth())
        self.assertEqual(result["decision"], "allow_elicitation_with_receipt")
        self.assertTrue(result["allowed"])
        self.assertFalse(result["runtime_request"]["task_id_present"])


if __name__ == "__main__":
    unittest.main()
