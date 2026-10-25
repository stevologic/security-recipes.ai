from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_mcp_stdio_launch_decision import evaluate_mcp_stdio_launch_decision


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "mcp-stdio-launch-boundary-pack.json"
ALLOWED_LAUNCH = "security-recipes-local-stdio"


def _allowed_direct(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "launch_id": ALLOWED_LAUNCH,
        "command": "python",
        "args": ["mcp_server.py"],
        "sandboxed": True,
        "network_egress": "allowlist",
        "env_keys": ["RECIPES_MCP_TRANSPORT"],
        "launch_architecture": "direct",
    }
    request.update(overrides)
    return request


class MCPStdioDiscoverAndProxySpawnTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_direct_pinned_launch_still_allows(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(self.pack, _allowed_direct())
        self.assertEqual(result["decision"], "allow_pinned_sandboxed_stdio_launch")
        self.assertTrue(result["allowed"])

    def test_modern_only_client_does_not_require_discover_probe(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack, _allowed_direct(client_era="modern_only")
        )
        self.assertEqual(result["decision"], "allow_pinned_sandboxed_stdio_launch")
        self.assertTrue(result["allowed"])

    def test_dual_era_client_without_probe_is_held(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack, _allowed_direct(client_era="dual_era")
        )
        self.assertEqual(result["decision"], "hold_for_discover_probe")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("server/discover" in item for item in result["violations"]))

    def test_dual_era_client_with_probe_is_allowed(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack,
            _allowed_direct(client_era="dual_era", stdio_discover_probe=True),
        )
        self.assertEqual(result["decision"], "allow_pinned_sandboxed_stdio_launch")
        self.assertTrue(result["allowed"])

    def test_discover_method_counts_as_probe_evidence(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack,
            _allowed_direct(client_era="dual_era", discover_method="server/discover"),
        )
        self.assertEqual(result["decision"], "allow_pinned_sandboxed_stdio_launch")
        self.assertTrue(result["allowed"])

    def test_initialize_fallback_after_discover_result_is_held(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack,
            _allowed_direct(
                client_era="dual_era",
                stdio_discover_probe=True,
                discover_result_type="complete",
                initialize_fallback=True,
            ),
        )
        self.assertEqual(result["decision"], "hold_for_discover_probe")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("initialize fallback" in item for item in result["violations"]))

    def test_initialize_fallback_after_unsupported_version_error_is_held(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack,
            _allowed_direct(
                client_era="dual_era",
                discover_method="server/discover",
                discover_error="UnsupportedProtocolVersionError",
                initialize_fallback=True,
            ),
        )
        self.assertEqual(result["decision"], "hold_for_discover_probe")
        self.assertFalse(result["allowed"])

    def test_proxy_spawn_without_extra_controls_is_denied(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack, _allowed_direct(launch_architecture="proxy")
        )
        self.assertEqual(result["decision"], "deny_unrestricted_proxy_spawn")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("additional authorization" in item for item in result["violations"]))
        self.assertTrue(any("not logged" in item for item in result["violations"]))

    def test_unsandboxed_proxy_spawn_is_denied_not_held(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack,
            _allowed_direct(launch_architecture="proxy", sandboxed=False),
        )
        self.assertEqual(result["decision"], "deny_unrestricted_proxy_spawn")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("not sandboxed" in item for item in result["violations"]))

    def test_proxy_spawn_with_extra_controls_is_allowed(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack,
            _allowed_direct(
                launch_architecture="proxy",
                proxy_spawn_authorized=True,
                stdio_spawn_logged=True,
            ),
        )
        self.assertEqual(result["decision"], "allow_pinned_sandboxed_stdio_launch")
        self.assertTrue(result["allowed"])

    def test_direct_stdio_does_not_inherit_proxy_spawn_deny(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack, _allowed_direct(launch_architecture="direct")
        )
        self.assertEqual(result["decision"], "allow_pinned_sandboxed_stdio_launch")
        self.assertTrue(result["allowed"])

    def test_unspecified_isolation_kind_stays_on_prior_allow_path(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(self.pack, _allowed_direct())
        self.assertEqual(result["decision"], "allow_pinned_sandboxed_stdio_launch")
        self.assertTrue(result["allowed"])

    def test_container_isolation_kind_is_allowed(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack, _allowed_direct(isolation_kind="container")
        )
        self.assertEqual(result["decision"], "allow_pinned_sandboxed_stdio_launch")
        self.assertTrue(result["allowed"])

    def test_cooperative_filesystem_allowlist_is_denied(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack, _allowed_direct(isolation_kind="cooperative_allowlist")
        )
        self.assertEqual(result["decision"], "deny_cooperative_filesystem_boundary")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("cooperative" in item for item in result["violations"]))

    def test_mcp_roots_are_not_access_control(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack, _allowed_direct(isolation_kind="mcp_roots")
        )
        self.assertEqual(result["decision"], "deny_cooperative_filesystem_boundary")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("MCP Roots" in item for item in result["violations"]))

    def test_bare_chroot_is_not_a_process_sandbox(self) -> None:
        result = evaluate_mcp_stdio_launch_decision(
            self.pack, _allowed_direct(isolation_kind="chroot")
        )
        self.assertEqual(result["decision"], "deny_cooperative_filesystem_boundary")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("chroot" in item for item in result["violations"]))


if __name__ == "__main__":
    unittest.main()
