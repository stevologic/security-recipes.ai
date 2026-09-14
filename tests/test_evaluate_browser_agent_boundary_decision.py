from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_browser_agent_boundary_decision import (
    evaluate_browser_agent_boundary_decision,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "browser-agent-boundary-pack.json"


def _public_research_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workspace_class_id": "public-research-browser",
        "task_profile_id": "public-security-research",
        "session_id": "browser-ci-public",
        "run_id": "run-public",
        "agent_id": "sr-browser-agent",
        "tenant_id": "tenant-demo",
        "user_intent": "Collect cited public AI security references",
        "target_origin": "https://www.nist.gov",
        "content_trust_level": "standards_body",
        "auth_state": "logged_out",
        "isolation_mode": "dedicated_agent_profile",
        "action_classes": ["navigate", "read_page", "summarize", "copy_draft"],
        "data_classes": ["public_security_guidance"],
        "network_egress_policy": "origin_allowlist",
        "browser_storage_policy": "ephemeral_or_scoped_storage",
        "approval_state": "approved",
        "telemetry_event_id": "telemetry-public",
        "receipt_id": "receipt-public",
        "controls": [
            "dedicated_agent_profile",
            "ephemeral_or_scoped_storage",
            "logged_out_by_default",
            "origin_allowlist",
            "metadata_only_telemetry",
            "run_receipt",
        ],
    }
    request.update(overrides)
    return request


class BrowserAgentOriginSetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_isolated_public_research_is_allowed_when_origin_set_evidence_is_unspecified(self) -> None:
        result = evaluate_browser_agent_boundary_decision(self.pack, _public_research_request())
        self.assertEqual(result["decision"], "allow_isolated_browser_task")
        self.assertTrue(result["allowed"])

    def test_ungated_origin_expansion_kills_the_session(self) -> None:
        result = evaluate_browser_agent_boundary_decision(
            self.pack,
            _public_research_request(ungated_origin_expansion=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_browser_agent_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("gating function" in item for item in result["violations"]))

    def test_consume_outside_read_origin_set_kills_the_session(self) -> None:
        result = evaluate_browser_agent_boundary_decision(
            self.pack,
            _public_research_request(consume_outside_read_origin_set=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_browser_agent_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("gated read set" in item for item in result["violations"]))

    def test_actuate_outside_write_origin_set_kills_the_session(self) -> None:
        result = evaluate_browser_agent_boundary_decision(
            self.pack,
            _public_research_request(actuate_outside_write_origin_set=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_browser_agent_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("read-writable set" in item for item in result["violations"]))

    def test_cross_origin_read_to_write_leak_kills_the_session(self) -> None:
        result = evaluate_browser_agent_boundary_decision(
            self.pack,
            _public_research_request(cross_origin_read_to_write_leak=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_browser_agent_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("read-only origin" in item for item in result["violations"]))


if __name__ == "__main__":
    unittest.main()
