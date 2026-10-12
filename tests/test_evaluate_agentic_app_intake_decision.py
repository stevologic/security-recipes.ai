from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agentic_app_intake_decision import (
    evaluate_agentic_app_intake_decision,
    mcp_icon_uri_violations,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "agentic-app-intake-pack.json"


def _guarded_pilot(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "app_id": "repository-remediation-agent-host",
        "deployment_environment": "enterprise_pilot",
        "egress_decision": "allow_internal_boundary",
        "authorization_decision": "allow_authorized_mcp_request",
        "telemetry_decision": "telemetry_ready",
        "human_approval_record": {
            "approvers": ["product-security", "service-owner"],
            "decision": "approved",
            "id": "approval-ci",
            "two_key_review": True,
        },
    }
    request.update(overrides)
    return request


class MCPIconUriSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_unspecified_icons_stay_on_the_guarded_pilot_path(self) -> None:
        result = evaluate_agentic_app_intake_decision(self.pack, _guarded_pilot())
        self.assertEqual(result["decision"], "approve_guarded_pilot")
        self.assertTrue(result["allowed"])

    def test_https_png_icon_stays_on_the_allow_path(self) -> None:
        result = evaluate_agentic_app_intake_decision(
            self.pack,
            _guarded_pilot(
                icon_src="https://mcp.security-recipes.ai/icons/app.png",
                mcp_server_origin="https://mcp.security-recipes.ai",
            ),
        )
        self.assertEqual(result["decision"], "approve_guarded_pilot")
        self.assertTrue(result["allowed"])

    def test_data_png_icon_stays_on_the_allow_path(self) -> None:
        result = evaluate_agentic_app_intake_decision(
            self.pack,
            _guarded_pilot(icon_src="data:image/png;base64,iVBORw0KGgo="),
        )
        self.assertEqual(result["decision"], "approve_guarded_pilot")
        self.assertTrue(result["allowed"])

    def test_sandboxed_svg_https_icon_stays_on_the_allow_path(self) -> None:
        result = evaluate_agentic_app_intake_decision(
            self.pack,
            _guarded_pilot(
                icons=[{"src": "https://mcp.security-recipes.ai/icons/app.svg", "mimeType": "image/svg+xml"}],
                mcp_server_origin="https://mcp.security-recipes.ai",
                icon_svg_sandboxed=True,
            ),
        )
        self.assertEqual(result["decision"], "approve_guarded_pilot")
        self.assertTrue(result["allowed"])

    def test_javascript_icon_denies_instead_of_guarded_pilot(self) -> None:
        result = evaluate_agentic_app_intake_decision(
            self.pack,
            _guarded_pilot(icon_src="javascript:alert(1)"),
        )
        self.assertEqual(result["decision"], "deny_until_controls_exist")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("javascript" in item for item in result["violations"]))

    def test_file_icon_denies(self) -> None:
        result = evaluate_agentic_app_intake_decision(
            self.pack,
            _guarded_pilot(icon_src="file:///etc/passwd"),
        )
        self.assertEqual(result["decision"], "deny_until_controls_exist")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("file:" in item for item in result["violations"]))

    def test_ftp_and_ws_icons_deny(self) -> None:
        for src in ("ftp://icons.example/app.png", "ws://icons.example/app"):
            with self.subTest(src=src):
                result = evaluate_agentic_app_intake_decision(self.pack, _guarded_pilot(icon_src=src))
                self.assertEqual(result["decision"], "deny_until_controls_exist")
                self.assertFalse(result["allowed"])

    def test_http_icon_denies_because_spec_requires_https_or_data(self) -> None:
        result = evaluate_agentic_app_intake_decision(
            self.pack,
            _guarded_pilot(icon_src="http://mcp.security-recipes.ai/icons/app.png"),
        )
        self.assertEqual(result["decision"], "deny_until_controls_exist")
        self.assertFalse(result["allowed"])

    def test_credentialed_icon_fetch_denies(self) -> None:
        result = evaluate_agentic_app_intake_decision(
            self.pack,
            _guarded_pilot(
                icon_src="https://mcp.security-recipes.ai/icons/app.png",
                mcp_server_origin="https://mcp.security-recipes.ai",
                icon_fetch_with_credentials=True,
            ),
        )
        self.assertEqual(result["decision"], "deny_until_controls_exist")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("credentials" in item for item in result["violations"]))

    def test_userinfo_in_icon_uri_denies(self) -> None:
        result = evaluate_agentic_app_intake_decision(
            self.pack,
            _guarded_pilot(icon_src="https://user:token@mcp.security-recipes.ai/icons/app.png"),
        )
        self.assertEqual(result["decision"], "deny_until_controls_exist")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("userinfo" in item for item in result["violations"]))

    def test_unsandboxed_svg_denies(self) -> None:
        result = evaluate_agentic_app_intake_decision(
            self.pack,
            _guarded_pilot(
                icon_src="https://mcp.security-recipes.ai/icons/app.svg",
                mcp_server_origin="https://mcp.security-recipes.ai",
                icon_svg_unsandboxed=True,
            ),
        )
        self.assertEqual(result["decision"], "deny_until_controls_exist")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("SVG" in item for item in result["violations"]))

    def test_svg_without_sandbox_or_disallow_denies(self) -> None:
        result = evaluate_agentic_app_intake_decision(
            self.pack,
            _guarded_pilot(
                icons=[{"src": "https://mcp.security-recipes.ai/icons/app.svg", "mimeType": "image/svg+xml"}],
                mcp_server_origin="https://mcp.security-recipes.ai",
            ),
        )
        self.assertEqual(result["decision"], "deny_until_controls_exist")
        self.assertFalse(result["allowed"])

    def test_cross_origin_icon_denies_when_server_origin_is_known(self) -> None:
        result = evaluate_agentic_app_intake_decision(
            self.pack,
            _guarded_pilot(
                icon_src="https://tracker.example/pixel.png",
                mcp_server_origin="https://mcp.security-recipes.ai",
            ),
        )
        self.assertEqual(result["decision"], "deny_until_controls_exist")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("same-origin" in item for item in result["violations"]))

    def test_data_html_icon_is_not_an_allowlisted_image_type(self) -> None:
        violations = mcp_icon_uri_violations({"icon_src": "data:text/html,<h1>x</h1>"})
        self.assertTrue(any("allowlisted image type" in item for item in violations))


if __name__ == "__main__":
    unittest.main()
