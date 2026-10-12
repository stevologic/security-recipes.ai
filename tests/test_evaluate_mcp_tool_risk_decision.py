from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_mcp_tool_risk_decision import (
    evaluate_mcp_tool_risk_decision,
    tools_list_cache_deny_violations,
    tools_list_cache_hold_violations,
    tools_list_cache_kill_violations,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "mcp-tool-risk-contract.json"


def _approved_write(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "vulnerable-dependency-remediation",
        "namespace": "repo.contents",
        "tool_name": "repo.contents.patch",
        "requested_access_mode": "write_branch",
        "agent_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "run_id": "run-ci",
        "session_id": "session-ci",
        "correlation_id": "corr-ci",
        "server_trusted": True,
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": True,
        },
        "human_approval_record": {
            "decision": "approved",
            "id": "approval-ci",
        },
    }
    request.update(overrides)
    return request


class MCPToolListCacheScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_unspecified_cache_stays_on_the_confirmation_path(self) -> None:
        result = evaluate_mcp_tool_risk_decision(self.pack, _approved_write())
        self.assertEqual(result["decision"], "allow_with_confirmation")
        self.assertTrue(result["allowed"])

    def test_public_identical_complete_list_stays_on_the_confirmation_path(self) -> None:
        result = evaluate_mcp_tool_risk_decision(
            self.pack,
            _approved_write(
                tools_list_cached=True,
                tools_list_result_type="complete",
                tools_list_cache_scope="public",
            ),
        )
        self.assertEqual(result["decision"], "allow_with_confirmation")
        self.assertTrue(result["allowed"])

    def test_private_same_authorization_cache_stays_on_the_confirmation_path(self) -> None:
        result = evaluate_mcp_tool_risk_decision(
            self.pack,
            _approved_write(
                tools_list_cached=True,
                tools_list_result_type="complete",
                tools_list_cache_scope="private",
            ),
        )
        self.assertEqual(result["decision"], "allow_with_confirmation")
        self.assertTrue(result["allowed"])

    def test_public_user_specific_cache_is_denied(self) -> None:
        result = evaluate_mcp_tool_risk_decision(
            self.pack,
            _approved_write(
                tools_list_cached=True,
                tools_list_result_type="complete",
                tools_list_cache_scope="public",
                tools_list_user_specific=True,
            ),
        )
        self.assertEqual(result["decision"], "deny_insecure_tool_list_cache")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("user-specific" in item for item in result["violations"]))

    def test_cache_used_as_access_control_is_denied(self) -> None:
        result = evaluate_mcp_tool_risk_decision(
            self.pack,
            _approved_write(
                tools_list_cached=True,
                tools_list_result_type="complete",
                tools_list_cache_scope="public",
                tools_list_cache_used_as_access_control=True,
            ),
        )
        self.assertEqual(result["decision"], "deny_insecure_tool_list_cache")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("access control" in item for item in result["violations"]))

    def test_mixed_page_cache_scope_is_denied(self) -> None:
        result = evaluate_mcp_tool_risk_decision(
            self.pack,
            _approved_write(
                tools_list_cached=True,
                tools_list_result_type="complete",
                tools_list_cache_scope="private",
                tools_list_cache_mixed_page_scope=True,
            ),
        )
        self.assertEqual(result["decision"], "deny_insecure_tool_list_cache")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("mixed cacheScope" in item for item in result["violations"]))

    def test_cached_input_required_result_is_denied(self) -> None:
        result = evaluate_mcp_tool_risk_decision(
            self.pack,
            _approved_write(
                tools_list_cached=True,
                tools_list_result_type="input_required",
                tools_list_cache_scope="private",
            ),
        )
        self.assertEqual(result["decision"], "deny_insecure_tool_list_cache")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("input_required" in item for item in result["violations"]))

    def test_cached_complete_list_missing_cache_scope_is_held(self) -> None:
        result = evaluate_mcp_tool_risk_decision(
            self.pack,
            _approved_write(tools_list_cached=True, tools_list_result_type="complete"),
        )
        self.assertEqual(result["decision"], "hold_for_tool_risk_review")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("omitted cacheScope" in item for item in result["violations"]))

    def test_private_cache_reused_across_authorization_kills(self) -> None:
        result = evaluate_mcp_tool_risk_decision(
            self.pack,
            _approved_write(
                tools_list_cached=True,
                tools_list_result_type="complete",
                tools_list_cache_scope="private",
                tools_list_private_cache_reused_across_authorization=True,
            ),
        )
        self.assertEqual(result["decision"], "kill_session_on_tool_risk_signal")
        self.assertFalse(result["allowed"])
        self.assertIn(
            "private_tools_list_cache_reused_across_authorization",
            result["violations"],
        )

    def test_public_cache_reuse_across_authorization_is_not_a_kill(self) -> None:
        result = evaluate_mcp_tool_risk_decision(
            self.pack,
            _approved_write(
                tools_list_cached=True,
                tools_list_result_type="complete",
                tools_list_cache_scope="public",
                tools_list_private_cache_reused_across_authorization=True,
            ),
        )
        self.assertEqual(result["decision"], "allow_with_confirmation")
        self.assertTrue(result["allowed"])
        self.assertEqual(tools_list_cache_kill_violations(_approved_write()), [])

    def test_unspecified_cache_helpers_return_no_violations(self) -> None:
        request = _approved_write()
        self.assertEqual(tools_list_cache_kill_violations(request), [])
        self.assertEqual(tools_list_cache_deny_violations(request), [])
        self.assertEqual(tools_list_cache_hold_violations(request), [])


if __name__ == "__main__":
    unittest.main()
