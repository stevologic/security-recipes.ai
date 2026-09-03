from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_mcp_tool_risk_decision import (
    evaluate_mcp_tool_risk_decision,
    insecure_tool_list_cache_violations,
    private_cache_reuse_violations,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "mcp-tool-risk-contract.json"


def _write_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "vulnerable-dependency-remediation",
        "namespace": "repo.contents",
        "tool_name": "repo.contents.patch",
        "requested_access_mode": "write_branch",
        "agent_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "run_id": "ci-allow",
        "session_id": "session-ci",
        "correlation_id": "corr-ci",
        "server_trusted": True,
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": True,
        },
        "human_approval_record": {"decision": "approved", "id": "approval-ci"},
    }
    request.update(overrides)
    return request


class ToolListCacheScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_unspecified_cache_evidence_keeps_prior_allow_path(self) -> None:
        result = evaluate_mcp_tool_risk_decision(self.pack, _write_request())
        self.assertEqual(result["decision"], "allow_with_confirmation")
        self.assertTrue(result["allowed"])

    def test_public_cache_of_user_specific_tools_list_is_denied(self) -> None:
        result = evaluate_mcp_tool_risk_decision(
            self.pack,
            _write_request(
                tools_list_from_cache=True,
                tools_list_cache_scope="public",
                tools_list_result_type="complete",
                tools_list_user_specific=True,
            ),
        )
        self.assertEqual(result["decision"], "deny_insecure_tool_list_cache")
        self.assertFalse(result["allowed"])
        self.assertIn(
            "public_tool_list_cache_contains_user_specific_data",
            result["violations"],
        )

    def test_public_cache_of_identical_tools_list_may_proceed(self) -> None:
        result = evaluate_mcp_tool_risk_decision(
            self.pack,
            _write_request(
                tools_list_from_cache=True,
                tools_list_cache_scope="public",
                tools_list_result_type="complete",
                tools_list_user_specific=False,
            ),
        )
        self.assertEqual(result["decision"], "allow_with_confirmation")
        self.assertTrue(result["allowed"])

    def test_private_cache_reused_across_tokens_is_killed(self) -> None:
        result = evaluate_mcp_tool_risk_decision(
            self.pack,
            _write_request(
                tools_list_from_cache=True,
                tools_list_cache_scope="private",
                tools_list_result_type="complete",
                tools_list_cache_shared_across_authorization_contexts=True,
            ),
        )
        self.assertEqual(result["decision"], "kill_session_on_tool_risk_signal")
        self.assertFalse(result["allowed"])
        self.assertIn(
            "private_tool_list_cache_shared_across_authorization_contexts",
            result["violations"],
        )

    def test_cached_input_required_tools_list_is_denied(self) -> None:
        result = evaluate_mcp_tool_risk_decision(
            self.pack,
            _write_request(
                tools_list_from_cache=True,
                tools_list_cache_scope="private",
                tools_list_result_type="input_required",
            ),
        )
        self.assertEqual(result["decision"], "deny_insecure_tool_list_cache")
        self.assertIn("cached_input_required_tools_list", result["violations"])

    def test_cache_scope_used_as_access_control_is_denied(self) -> None:
        result = evaluate_mcp_tool_risk_decision(
            self.pack,
            _write_request(tools_list_cache_used_as_access_control=True),
        )
        self.assertEqual(result["decision"], "deny_insecure_tool_list_cache")
        self.assertIn("cache_scope_used_as_access_control", result["violations"])

    def test_mixed_page_cache_scope_is_denied(self) -> None:
        result = evaluate_mcp_tool_risk_decision(
            self.pack,
            _write_request(
                tools_list_from_cache=True,
                tools_list_cache_scope="private",
                tools_list_result_type="complete",
                tools_list_mixed_page_cache_scope=True,
            ),
        )
        self.assertEqual(result["decision"], "deny_insecure_tool_list_cache")
        self.assertIn("mixed_page_cache_scope", result["violations"])

    def test_cached_complete_list_without_cache_scope_holds(self) -> None:
        result = evaluate_mcp_tool_risk_decision(
            self.pack,
            _write_request(
                tools_list_from_cache=True,
                tools_list_result_type="complete",
            ),
        )
        self.assertEqual(result["decision"], "hold_for_tool_risk_review")
        self.assertIn(
            "complete_tools_list_cache_missing_cache_scope",
            result["violations"],
        )

    def test_helpers_encode_caching_security_table(self) -> None:
        self.assertEqual(private_cache_reuse_violations({}), [])
        self.assertEqual(
            private_cache_reuse_violations(
                {
                    "tools_list_from_cache": True,
                    "tools_list_cache_scope": "private",
                    "tools_list_cache_shared_across_authorization_contexts": True,
                }
            ),
            ["private_tool_list_cache_shared_across_authorization_contexts"],
        )
        self.assertEqual(insecure_tool_list_cache_violations({}), [])
        self.assertIn(
            "public_tool_list_cache_contains_user_specific_data",
            insecure_tool_list_cache_violations(
                {
                    "tools_list_from_cache": True,
                    "tools_list_cache_scope": "public",
                    "tools_list_user_specific": True,
                }
            ),
        )


if __name__ == "__main__":
    unittest.main()
