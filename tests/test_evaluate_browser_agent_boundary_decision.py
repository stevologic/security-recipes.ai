from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_browser_agent_boundary_decision import (
    evaluate_browser_agent_boundary_decision,
    origin_set_kill_violations,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "browser-agent-boundary-pack.json"


def _public_research(**overrides: object) -> dict[str, object]:
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

    def test_unspecified_origin_set_evidence_stays_on_the_allow_path(self) -> None:
        result = evaluate_browser_agent_boundary_decision(self.pack, _public_research())
        self.assertEqual(result["decision"], "allow_isolated_browser_task")
        self.assertTrue(result["allowed"])
        self.assertEqual(origin_set_kill_violations(_public_research()), [])

    def test_gated_task_relevant_origin_sets_stay_on_the_allow_path(self) -> None:
        result = evaluate_browser_agent_boundary_decision(
            self.pack,
            _public_research(
                origin_gating_isolated=True,
                origin_read_set=["https://csrc.nist.gov"],
                origin_write_set=["https://www.nist.gov"],
                consumed_origins=["https://csrc.nist.gov", "https://www.nist.gov"],
                actuated_origins=["https://www.nist.gov"],
            ),
        )
        self.assertEqual(result["decision"], "allow_isolated_browser_task")
        self.assertTrue(result["allowed"])

    def test_ungated_origin_expansion_kills(self) -> None:
        result = evaluate_browser_agent_boundary_decision(
            self.pack,
            _public_research(origin_expansion_ungated=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_browser_agent_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("ungated" in item for item in result["violations"]))

    def test_consumption_outside_gated_read_set_kills(self) -> None:
        result = evaluate_browser_agent_boundary_decision(
            self.pack,
            _public_research(
                origin_read_set=["https://www.nist.gov"],
                origin_write_set=["https://www.nist.gov"],
                consumed_origins=["https://mail.example.internal"],
            ),
        )
        self.assertEqual(result["decision"], "kill_session_on_browser_agent_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("mail.example.internal" in item for item in result["violations"]))

    def test_actuation_outside_gated_write_set_kills(self) -> None:
        result = evaluate_browser_agent_boundary_decision(
            self.pack,
            _public_research(
                origin_read_set=["https://www.nist.gov"],
                origin_write_set=["https://www.nist.gov"],
                actuated_origins=["https://payments.example"],
            ),
        )
        self.assertEqual(result["decision"], "kill_session_on_browser_agent_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("payments.example" in item for item in result["violations"]))

    def test_iframe_content_outside_read_set_kills(self) -> None:
        result = evaluate_browser_agent_boundary_decision(
            self.pack,
            _public_research(iframe_content_outside_read_set=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_browser_agent_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("iframe" in item for item in result["violations"]))

    def test_read_to_write_origin_data_flow_kills(self) -> None:
        result = evaluate_browser_agent_boundary_decision(
            self.pack,
            _public_research(read_to_write_data_flow=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_browser_agent_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("read-only origin" in item for item in result["violations"]))

    def test_gating_function_not_isolated_kills(self) -> None:
        result = evaluate_browser_agent_boundary_decision(
            self.pack,
            _public_research(origin_gating_isolated=False),
        )
        self.assertEqual(result["decision"], "kill_session_on_browser_agent_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("not isolated" in item for item in result["violations"]))

    def test_prompt_injection_plus_external_send_still_kills(self) -> None:
        result = evaluate_browser_agent_boundary_decision(
            self.pack,
            _public_research(
                prompt_injection_signal=True,
                sends_external_message=True,
            ),
        )
        self.assertEqual(result["decision"], "kill_session_on_browser_agent_signal")
        self.assertFalse(result["allowed"])
