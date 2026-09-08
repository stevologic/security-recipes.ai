from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_mcp_elicitation_boundary_decision import (
    evaluate_mcp_elicitation_boundary_decision,
    is_task_bound_elicitation,
    task_id_looks_guessable,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "mcp-elicitation-boundary-pack.json"
UNGUESSABLE_TASK_ID = "8f3c9e2a1b4d80c65e4a3210abcdef12"


def _url_oauth_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "mcp-connector-intake-scanner",
        "agent_id": "sr-agent::mcp-connector-intake::codex",
        "run_id": "run-ci",
        "connector_id": "github",
        "namespace": "github.oauth",
        "server_id": "mcp-server::github",
        "elicitation_profile_id": "profile-third-party-oauth-url",
        "input_request_id": "github_oauth",
        "request_state": "opaque-aead-state",
        "mode": "url",
        "url": "https://github.com/login/oauth/authorize",
        "url_domain": "github.com",
        "user_id": "user-ci",
        "session_id": "session-ci",
        "correlation_id": "corr-ci",
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


def _task_oauth_request(**overrides: object) -> dict[str, object]:
    request = _url_oauth_request(
        delivery="tasks_get",
        task_id=UNGUESSABLE_TASK_ID,
        task_status="input_required",
        result_type="task",
        tasks_extension_declared=True,
        task_id_unguessable=True,
        task_request_authorized=True,
        tasks_update_used=True,
    )
    request.update(overrides)
    return request


class MCPElicitationTaskChannelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_synchronous_url_oauth_still_allows(self) -> None:
        result = evaluate_mcp_elicitation_boundary_decision(self.pack, _url_oauth_request())
        self.assertEqual(result["decision"], "allow_elicitation_with_receipt")
        self.assertTrue(result["allowed"])

    def test_task_bound_url_oauth_allows_with_same_trust_model(self) -> None:
        result = evaluate_mcp_elicitation_boundary_decision(self.pack, _task_oauth_request())
        self.assertEqual(result["decision"], "allow_elicitation_with_receipt")
        self.assertTrue(result["allowed"])
        self.assertTrue(result["runtime_request"]["task_id_present"])
        self.assertEqual(result["runtime_request"]["delivery"], "tasks_get")

    def test_undeclared_tasks_extension_kills_session(self) -> None:
        result = evaluate_mcp_elicitation_boundary_decision(
            self.pack,
            _task_oauth_request(tasks_extension_declared=False),
        )
        self.assertEqual(result["decision"], "kill_session_on_elicitation_abuse")
        self.assertFalse(result["allowed"])
        self.assertIn("tasks_extension_declared=false", result["violations"])

    def test_guessable_task_id_kills_session(self) -> None:
        result = evaluate_mcp_elicitation_boundary_decision(
            self.pack,
            _task_oauth_request(task_id="1", task_id_unguessable=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_elicitation_abuse")
        self.assertTrue(
            any("guessable" in item for item in result["violations"]),
        )

    def test_higher_trust_task_channel_kills_session(self) -> None:
        result = evaluate_mcp_elicitation_boundary_decision(
            self.pack,
            _task_oauth_request(task_treated_as_higher_trust=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_elicitation_abuse")
        self.assertIn("task_treated_as_higher_trust=true", result["violations"])

    def test_secret_form_on_a_task_is_still_denied(self) -> None:
        result = evaluate_mcp_elicitation_boundary_decision(
            self.pack,
            {
                "workflow_id": "mcp-gateway-policy",
                "agent_id": "sr-agent::gateway::codex",
                "run_id": "run-secret",
                "server_id": "mcp-server::unknown",
                "elicitation_profile_id": "profile-credential-form-prohibited",
                "input_request_id": "api_key_form",
                "request_state": "opaque-aead-state",
                "mode": "form",
                "requested_data_classes": ["api_key"],
                "response_schema_fields": ["api_key"],
                "session_id": "session-secret",
                "correlation_id": "corr-secret",
                "client_supports_mode": True,
                "server_identity_displayed": True,
                "user_can_decline": True,
                "user_can_review": True,
                "delivery": "tasks_get",
                "task_id": UNGUESSABLE_TASK_ID,
                "tasks_extension_declared": True,
                "task_id_unguessable": True,
                "task_request_authorized": True,
                "tasks_update_used": True,
            },
        )
        self.assertEqual(result["decision"], "deny_sensitive_form_elicitation")
        self.assertFalse(result["allowed"])

    def test_missing_task_auth_binding_holds(self) -> None:
        result = evaluate_mcp_elicitation_boundary_decision(
            self.pack,
            _task_oauth_request(task_request_authorized=False),
        )
        self.assertEqual(result["decision"], "hold_for_elicitation_evidence")
        self.assertIn("task_request_authorized=false", result["violations"])

    def test_retrying_original_method_for_task_input_holds(self) -> None:
        result = evaluate_mcp_elicitation_boundary_decision(
            self.pack,
            _task_oauth_request(original_method_retried_for_task_input=True),
        )
        self.assertEqual(result["decision"], "hold_for_elicitation_evidence")
        self.assertIn("original_method_retried_for_task_input=true", result["violations"])

    def test_task_id_entropy_helper(self) -> None:
        self.assertTrue(task_id_looks_guessable("1"))
        self.assertTrue(task_id_looks_guessable("task-12"))
        self.assertFalse(task_id_looks_guessable(UNGUESSABLE_TASK_ID))
        self.assertTrue(is_task_bound_elicitation({"delivery": "tasks_get"}))
        self.assertFalse(is_task_bound_elicitation({"delivery": "input_required_result"}))


if __name__ == "__main__":
    unittest.main()
