from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_mcp_stdio_launch_decision import (
    dual_era_discover_decision,
    evaluate_mcp_stdio_launch_decision,
    proxy_spawn_kill_reason,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "mcp-stdio-launch-boundary-pack.json"


def _allow_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "launch_id": "security-recipes-local-stdio",
        "command": "python",
        "args": ["mcp_server.py"],
        "sandboxed": True,
        "network_egress": "allowlist",
        "env_keys": ["RECIPES_MCP_TRANSPORT"],
        "client_era": "dual-era",
        "discover_probe_policy": "probe-first",
    }
    request.update(overrides)
    return request


class MCPStdioDiscoverAndProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_dual_era_probe_first_allows_pinned_launch(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(self.pack, _allow_request())
        self.assertEqual(result["decision"], "allow_pinned_sandboxed_stdio_launch")
        self.assertTrue(result["allowed"])

    def test_unspecified_era_keeps_prior_allow_path(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack,
            _allow_request(client_era=None, discover_probe_policy=None),
        )
        self.assertEqual(result["decision"], "allow_pinned_sandboxed_stdio_launch")

    def test_dual_era_skip_probe_holds_for_owner_review(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack,
            _allow_request(discover_probe_policy="skip"),
        )
        self.assertEqual(result["decision"], "hold_for_owner_review")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("discover_probe_policy=skip" in item for item in result["violations"])
        )

    def test_dual_era_missing_probe_policy_holds(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack,
            _allow_request(discover_probe_policy=None),
        )
        self.assertEqual(result["decision"], "hold_for_owner_review")

    def test_modern_error_initialize_fallback_kills_session(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack,
            _allow_request(
                discover_probe_result="modern-error",
                legacy_initialize_fallback=True,
            ),
        )
        self.assertEqual(result["decision"], "kill_session_on_secret_or_privilege_request")
        self.assertIn("legacy_initialize_fallback=true", result["violations"])

    def test_discover_result_initialize_fallback_kills_session(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack,
            _allow_request(
                discover_probe_result="discover-result",
                legacy_initialize_fallback=True,
            ),
        )
        self.assertEqual(result["decision"], "kill_session_on_secret_or_privilege_request")

    def test_legacy_timeout_fallback_may_proceed(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack,
            _allow_request(
                discover_probe_result="other-error-or-timeout",
                legacy_initialize_fallback=True,
            ),
        )
        self.assertEqual(result["decision"], "allow_pinned_sandboxed_stdio_launch")

    def test_fallback_keyed_to_single_error_code_holds(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack,
            _allow_request(discover_fallback_keyed_to_single_error_code=True),
        )
        self.assertEqual(result["decision"], "hold_for_owner_review")
        self.assertIn("discover_fallback_keyed_to_single_error_code=true", result["violations"])

    def test_server_info_security_decision_holds(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack,
            _allow_request(treats_server_info_as_security_decision=True),
        )
        self.assertEqual(result["decision"], "hold_for_owner_review")
        self.assertIn("treats_server_info_as_security_decision=true", result["violations"])

    def test_unbound_proxy_token_kills_session(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack,
            _allow_request(proxy_spawn_architecture=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_secret_or_privilege_request")
        self.assertIn("proxy_spawn_architecture=true", result["violations"])

    def test_unregistered_proxy_spawn_kills_instead_of_deny(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack,
            _allow_request(launch_id="not-a-registered-launch", proxy_spawn_architecture=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_secret_or_privilege_request")

    def test_bound_proxy_without_extra_child_sandbox_holds(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack,
            _allow_request(
                proxy_spawn_architecture=True,
                proxy_token_binds_to_registered_launch=True,
            ),
        )
        self.assertEqual(result["decision"], "hold_for_owner_review")
        self.assertIn("proxy_child_sandboxed=false", result["violations"])
        self.assertIn("proxy_spawn_logged=false", result["violations"])

    def test_bound_sandboxed_logged_proxy_allows_pinned_launch(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack,
            _allow_request(
                proxy_spawn_architecture=True,
                proxy_token_binds_to_registered_launch=True,
                proxy_child_sandboxed=True,
                proxy_spawn_logged=True,
            ),
        )
        self.assertEqual(result["decision"], "allow_pinned_sandboxed_stdio_launch")

    def test_helpers_encode_spec_tables(self) -> None:
        self.assertIsNone(proxy_spawn_kill_reason({"proxy_spawn_architecture": False}, {"launch_id": "x"}))
        self.assertEqual(
            proxy_spawn_kill_reason({"proxy_spawn_architecture": True}, None),
            "proxy architecture attempted to spawn an unregistered STDIO command",
        )
        self.assertIsNone(
            dual_era_discover_decision({"client_era": "modern", "discover_probe_policy": "skip"})
        )
        kill = dual_era_discover_decision(
            {
                "client_era": "dual-era",
                "discover_probe_policy": "probe-first",
                "discover_probe_result": "modern_error",
                "legacy_initialize_fallback": True,
            }
        )
        self.assertIsNotNone(kill)
        self.assertEqual(kill[0], "kill_session_on_secret_or_privilege_request")


if __name__ == "__main__":
    unittest.main()
