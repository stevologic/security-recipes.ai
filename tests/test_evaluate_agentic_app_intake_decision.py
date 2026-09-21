from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agentic_app_intake_decision import (
    evaluate_agentic_app_intake_decision,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "agentic-app-intake-pack.json"


def _pilot_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "app_id": "repository-remediation-agent-host",
        "deployment_environment": "enterprise_pilot",
        "egress_decision": "allow_internal_boundary",
        "authorization_decision": "allow_authorized_mcp_request",
        "telemetry_decision": "telemetry_ready",
        "human_approval_record": {
            "id": "approval-ci",
            "decision": "approved",
            "approvers": ["product-security", "service-owner"],
            "two_key_review": True,
        },
    }
    request.update(overrides)
    return request


class AgenticAppIntakeMcpIconTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_unspecified_icons_stay_on_the_prior_allow_path(self) -> None:
        result = evaluate_agentic_app_intake_decision(self.pack, _pilot_request())
        self.assertEqual(result["decision"], "approve_guarded_pilot")
        self.assertTrue(result["allowed"])

    def test_same_origin_https_png_icon_is_allowed(self) -> None:
        result = evaluate_agentic_app_intake_decision(
            self.pack,
            _pilot_request(
                mcp_icon_src="https://mcp.example.com/icons/tool.png",
                mcp_server_origin="https://mcp.example.com",
                mcp_icon_mime_type="image/png",
            ),
        )
        self.assertEqual(result["decision"], "approve_guarded_pilot")
        self.assertTrue(result["allowed"])
        self.assertEqual(result["violations"], [])

    def test_javascript_icon_uri_kills_the_session(self) -> None:
        result = evaluate_agentic_app_intake_decision(
            self.pack,
            _pilot_request(mcp_icon_src="javascript:void(0)"),
        )
        self.assertEqual(result["decision"], "kill_session_on_launch_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("unsafe scheme" in item for item in result["violations"]))

    def test_file_icon_uri_kills_the_session(self) -> None:
        result = evaluate_agentic_app_intake_decision(
            self.pack,
            _pilot_request(mcp_icon_src="file:///tmp/icon.png"),
        )
        self.assertEqual(result["decision"], "kill_session_on_launch_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("unsafe scheme" in item for item in result["violations"]))

    def test_credentialed_icon_fetch_kills_the_session(self) -> None:
        result = evaluate_agentic_app_intake_decision(
            self.pack,
            _pilot_request(
                mcp_icon_src="https://mcp.example.com/icons/tool.png",
                mcp_server_origin="https://mcp.example.com",
                mcp_icon_mime_type="image/png",
                mcp_icon_fetch_with_credentials=True,
            ),
        )
        self.assertEqual(result["decision"], "kill_session_on_launch_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("without credentials" in item for item in result["violations"]))

    def test_cross_origin_icon_is_held(self) -> None:
        result = evaluate_agentic_app_intake_decision(
            self.pack,
            _pilot_request(
                mcp_icon_src="https://cdn.untrusted.example/icons/tool.png",
                mcp_server_origin="https://mcp.example.com",
                mcp_icon_mime_type="image/png",
            ),
        )
        self.assertEqual(result["decision"], "hold_for_agentic_app_security_review")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("not the MCP server origin" in item for item in result["violations"]))

    def test_unsandboxed_svg_icon_is_held(self) -> None:
        result = evaluate_agentic_app_intake_decision(
            self.pack,
            _pilot_request(
                mcp_icon_src="https://mcp.example.com/icons/tool.svg",
                mcp_server_origin="https://mcp.example.com",
                mcp_icon_mime_type="image/svg+xml",
                mcp_icon_svg_unsandboxed=True,
            ),
        )
        self.assertEqual(result["decision"], "hold_for_agentic_app_security_review")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("SVG" in item for item in result["violations"]))


if __name__ == "__main__":
    unittest.main()
