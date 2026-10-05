from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agent_handoff_boundary_decision import (
    evaluate_agent_handoff_boundary_decision,
)
from scripts.generate_agent_handoff_boundary_pack import validate_model


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "agent-handoff-boundary-pack.json"
MODEL_PATH = REPO_ROOT / "data" / "assurance" / "agent-handoff-boundary-model.json"
WORKFLOW_PAGE = REPO_ROOT / "content" / "security-remediation" / "agent-handoff-boundary" / "_index.md"

METADATA_FIELDS = [
    "task_summary",
    "workflow_id",
    "source_ids",
    "source_hashes",
    "correlation_id",
]


def _a2a_metadata_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "vulnerable-dependency-remediation",
        "handoff_profile_id": "metadata-only",
        "protocol": "a2a_task_delegation",
        "target_trust_tier": "approved_vendor",
        "agent_card_signed": True,
        "authentication_schemes": ["oauth2"],
        "a2a_version": "1.0",
        "payload_fields": list(METADATA_FIELDS),
        "data_classes": ["curated_security_guidance"],
    }
    request.update(overrides)
    return request


def _mcp_metadata_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "vulnerable-dependency-remediation",
        "handoff_profile_id": "metadata-only",
        "protocol": "mcp_tool_call",
        "target_trust_tier": "approved_vendor",
        "resource_indicator": "https://mcp.example/resource",
        "token_audience": "https://mcp.example/resource",
        "payload_fields": list(METADATA_FIELDS),
        "data_classes": ["curated_security_guidance"],
    }
    request.update(overrides)
    return request


class AgentHandoffBoundaryA2AVersionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))
        cls.model = json.loads(MODEL_PATH.read_text(encoding="utf-8"))
        cls.page = WORKFLOW_PAGE.read_text(encoding="utf-8")

    def test_model_and_page_record_a2a_1_0_without_claiming_human_review(self) -> None:
        alignment = {
            str(item.get("id")): item
            for item in self.model.get("standards_alignment", [])
            if isinstance(item, dict)
        }
        spec = alignment["a2a-protocol-1-0-0"]
        self.assertEqual(spec["url"], "https://a2a-protocol.org/v1.0.0/specification/")
        self.assertIn("A2A-Version", spec["coverage"])
        self.assertIn("TASK_STATE_AUTH_REQUIRED", spec["coverage"])
        self.assertEqual(self.model["last_reviewed"], "2026-10-05")
        self.assertEqual(validate_model(self.model), [])

        a2a = next(
            item
            for item in self.model["protocol_surfaces"]
            if item.get("id") == "a2a_task_delegation"
        )
        self.assertIn("a2a_version_header", a2a["required_controls"])
        self.assertIn("in_task_auth_out_of_band", a2a["required_controls"])

        self.assertIn("https://a2a-protocol.org/v1.0.0/specification/", self.page)
        self.assertIn("A2A-Version", self.page)
        self.assertIn("TASK_STATE_AUTH_REQUIRED", self.page)
        self.assertIn("does not claim human review", self.page)
        self.assertIn("lastmod: 2026-10-05", self.page)

    def test_a2a_metadata_handoff_with_version_1_0_is_allowed(self) -> None:
        result = evaluate_agent_handoff_boundary_decision(
            self.pack, _a2a_metadata_request()
        )
        self.assertEqual(result["decision"], "allow_metadata_handoff")
        self.assertTrue(result["allowed"])

    def test_patch_version_1_0_0_is_treated_as_1_0(self) -> None:
        result = evaluate_agent_handoff_boundary_decision(
            self.pack, _a2a_metadata_request(a2a_version="1.0.0")
        )
        self.assertEqual(result["decision"], "allow_metadata_handoff")
        self.assertTrue(result["allowed"])

    def test_missing_a2a_version_is_held_as_legacy_0_3(self) -> None:
        result = evaluate_agent_handoff_boundary_decision(
            self.pack, _a2a_metadata_request(a2a_version="")
        )
        self.assertEqual(result["decision"], "hold_for_redaction_or_approval")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("0.3" in item for item in result["violations"]))

    def test_explicit_0_3_version_is_held(self) -> None:
        result = evaluate_agent_handoff_boundary_decision(
            self.pack, _a2a_metadata_request(a2a_version="0.3")
        )
        self.assertEqual(result["decision"], "hold_for_redaction_or_approval")
        self.assertFalse(result["allowed"])

    def test_unsupported_a2a_version_is_denied(self) -> None:
        result = evaluate_agent_handoff_boundary_decision(
            self.pack, _a2a_metadata_request(a2a_version="0.5")
        )
        self.assertEqual(result["decision"], "deny_untrusted_agent_handoff")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("0.5" in item for item in result["violations"]))

    def test_auth_required_without_out_of_band_channel_is_held(self) -> None:
        result = evaluate_agent_handoff_boundary_decision(
            self.pack,
            _a2a_metadata_request(task_state="TASK_STATE_AUTH_REQUIRED"),
        )
        self.assertEqual(result["decision"], "hold_for_redaction_or_approval")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("out-of-band credential channel" in item for item in result["violations"])
        )

    def test_auth_required_with_out_of_band_channel_is_allowed(self) -> None:
        result = evaluate_agent_handoff_boundary_decision(
            self.pack,
            _a2a_metadata_request(
                task_state="TASK_STATE_AUTH_REQUIRED",
                credential_channel="out_of_band",
            ),
        )
        self.assertEqual(result["decision"], "allow_metadata_handoff")
        self.assertTrue(result["allowed"])

    def test_credentials_in_a2a_message_kill_the_session(self) -> None:
        result = evaluate_agent_handoff_boundary_decision(
            self.pack,
            _a2a_metadata_request(
                task_state="TASK_STATE_AUTH_REQUIRED",
                credentials_in_a2a_message=True,
            ),
        )
        self.assertEqual(result["decision"], "kill_session_on_secret_handoff")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("A2A message" in item for item in result["violations"]))

    def test_unspecified_task_state_stays_on_the_prior_allow_path(self) -> None:
        result = evaluate_agent_handoff_boundary_decision(
            self.pack, _a2a_metadata_request()
        )
        self.assertEqual(result["decision"], "allow_metadata_handoff")
        self.assertIsNone(result["runtime_request"].get("task_state"))

    def test_mcp_handoff_does_not_require_a2a_version(self) -> None:
        result = evaluate_agent_handoff_boundary_decision(
            self.pack, _mcp_metadata_request()
        )
        self.assertEqual(result["decision"], "allow_metadata_handoff")
        self.assertTrue(result["allowed"])


if __name__ == "__main__":
    unittest.main()
