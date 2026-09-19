from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agent_handoff_boundary_decision import (
    evaluate_agent_handoff_boundary_decision,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "agent-handoff-boundary-pack.json"


def _metadata_a2a(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "vulnerable-dependency-remediation",
        "handoff_profile_id": "metadata-only",
        "protocol": "a2a_task_delegation",
        "target_trust_tier": "approved_vendor",
        "agent_card_signed": True,
        "authentication_schemes": ["oauth2"],
        "a2a_version": "1.0",
        "payload_fields": [
            "task_summary",
            "workflow_id",
            "source_ids",
            "source_hashes",
            "correlation_id",
        ],
        "data_classes": ["curated_security_guidance"],
    }
    request.update(overrides)
    return request


class AgentHandoffA2AVersionAndAuthRequiredTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_metadata_a2a_handoff_is_allowed_with_version_1_0(self) -> None:
        result = evaluate_agent_handoff_boundary_decision(self.pack, _metadata_a2a())
        self.assertEqual(result["decision"], "allow_metadata_handoff")
        self.assertTrue(result["allowed"])

    def test_patch_version_1_0_0_is_treated_as_major_minor_1_0(self) -> None:
        result = evaluate_agent_handoff_boundary_decision(
            self.pack,
            _metadata_a2a(a2a_version="1.0.0"),
        )
        self.assertEqual(result["decision"], "allow_metadata_handoff")
        self.assertTrue(result["allowed"])

    def test_missing_a2a_version_holds_because_empty_header_is_0_3(self) -> None:
        result = evaluate_agent_handoff_boundary_decision(
            self.pack,
            _metadata_a2a(a2a_version=""),
        )
        self.assertEqual(result["decision"], "hold_for_redaction_or_approval")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("empty A2A-Version is 0.3" in item for item in result["violations"]))

    def test_unsupported_a2a_version_is_denied(self) -> None:
        result = evaluate_agent_handoff_boundary_decision(
            self.pack,
            _metadata_a2a(a2a_version="0.3"),
        )
        self.assertEqual(result["decision"], "deny_untrusted_agent_handoff")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("unsupported a2a_version: 0.3" in item for item in result["violations"]))

    def test_auth_required_without_out_of_band_channel_holds(self) -> None:
        result = evaluate_agent_handoff_boundary_decision(
            self.pack,
            _metadata_a2a(task_state="auth_required"),
        )
        self.assertEqual(result["decision"], "hold_for_redaction_or_approval")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("out-of-band credential_channel" in item for item in result["violations"])
        )

    def test_auth_required_with_https_channel_is_allowed(self) -> None:
        result = evaluate_agent_handoff_boundary_decision(
            self.pack,
            _metadata_a2a(task_state="TASK_STATE_AUTH_REQUIRED", credential_channel="https"),
        )
        self.assertEqual(result["decision"], "allow_metadata_handoff")
        self.assertTrue(result["allowed"])

    def test_auth_required_in_band_credential_kills_the_session(self) -> None:
        result = evaluate_agent_handoff_boundary_decision(
            self.pack,
            _metadata_a2a(
                task_state="auth_required",
                credential_channel="https",
                in_band_credential=True,
            ),
        )
        self.assertEqual(result["decision"], "kill_session_on_secret_handoff")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("in_band_credential=true" in item for item in result["violations"]))

    def test_unspecified_task_state_stays_on_the_prior_allow_path(self) -> None:
        result = evaluate_agent_handoff_boundary_decision(self.pack, _metadata_a2a())
        self.assertEqual(result["decision"], "allow_metadata_handoff")
        self.assertTrue(result["allowed"])


if __name__ == "__main__":
    unittest.main()
