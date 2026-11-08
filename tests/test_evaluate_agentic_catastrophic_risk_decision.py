from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agentic_catastrophic_risk_decision import (
    evaluate_agentic_catastrophic_risk_decision,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
ANNEX_PATH = REPO_ROOT / "data" / "evidence" / "agentic-catastrophic-risk-annex.json"


def _reviewed_high_impact_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "base-image-remediation",
        "action_class": "production_deployment",
        "run_id": "run-123",
        "identity_id": "sr-agent::base-image-remediation::codex",
        "policy_pack_hash": "policy-hash",
        "authorization_decision": "allow_authorized_mcp_request",
        "risk_acceptance_id": "risk-accept-123",
        "receipt_id": "receipt-123",
        "affects_prod": True,
        "human_approval_record": {
            "approval_id": "approval-123",
            "status": "approved",
        },
    }
    request.update(overrides)
    return request


def _bounded_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "base-image-remediation",
        "action_class": "repo_branch_write",
        "run_id": "run-bounded",
        "identity_id": "sr-agent::base-image-remediation::codex",
    }
    request.update(overrides)
    return request


class AgenticCatastrophicRiskIdentityTenetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.annex = json.loads(ANNEX_PATH.read_text(encoding="utf-8"))

    def test_reviewed_high_impact_action_is_allowed_when_identity_tenets_are_unspecified(self) -> None:
        result = evaluate_agentic_catastrophic_risk_decision(
            self.annex,
            _reviewed_high_impact_request(),
        )
        self.assertEqual(result["decision"], "allow_reviewed_high_impact_action")
        self.assertTrue(result["allowed"])

    def test_bounded_action_is_allowed_when_unsigned_mandate_is_unspecified(self) -> None:
        result = evaluate_agentic_catastrophic_risk_decision(
            self.annex,
            _bounded_request(),
        )
        self.assertEqual(result["decision"], "allow_bounded_agent_action")
        self.assertTrue(result["allowed"])

    def test_bounded_action_with_unsigned_mandate_stays_on_the_allow_path(self) -> None:
        result = evaluate_agentic_catastrophic_risk_decision(
            self.annex,
            _bounded_request(unsigned_mandate=True),
        )
        self.assertEqual(result["decision"], "allow_bounded_agent_action")
        self.assertTrue(result["allowed"])

    def test_unattenuated_subagent_delegation_is_denied(self) -> None:
        result = evaluate_agentic_catastrophic_risk_decision(
            self.annex,
            _reviewed_high_impact_request(unattenuated_subagent_delegation=True),
        )
        self.assertEqual(result["decision"], "deny_unbounded_autonomy")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("more authority than the parent" in item for item in result["violations"])
        )

    def test_standing_privilege_is_denied(self) -> None:
        result = evaluate_agentic_catastrophic_risk_decision(
            self.annex,
            _reviewed_high_impact_request(standing_privilege=True),
        )
        self.assertEqual(result["decision"], "deny_unbounded_autonomy")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("standing privilege" in item for item in result["violations"])
        )

    def test_model_driven_access_grant_is_denied(self) -> None:
        result = evaluate_agentic_catastrophic_risk_decision(
            self.annex,
            _reviewed_high_impact_request(model_driven_access_grant=True),
        )
        self.assertEqual(result["decision"], "deny_unbounded_autonomy")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("reasoning model" in item for item in result["violations"])
        )

    def test_agent_writable_evidence_kills_the_session(self) -> None:
        result = evaluate_agentic_catastrophic_risk_decision(
            self.annex,
            _reviewed_high_impact_request(agent_writable_evidence=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_catastrophic_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("evidence logs" in item for item in result["violations"])
        )

    def test_unsigned_high_impact_mandate_is_held(self) -> None:
        result = evaluate_agentic_catastrophic_risk_decision(
            self.annex,
            _reviewed_high_impact_request(unsigned_mandate=True),
        )
        self.assertEqual(result["decision"], "hold_for_catastrophic_risk_review")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("unsigned mandate" in item for item in result["violations"])
        )

    def test_nist_identity_source_is_present(self) -> None:
        source_ids = {
            str(row.get("id"))
            for row in self.annex.get("standards_alignment", [])
            if isinstance(row, dict)
        }
        self.assertIn("nist-agentic-identity-foundation-2026", source_ids)
        self.assertIn("nist-nccoe-agentic-identity-comments-2026", source_ids)
        self.assertIn("nist-agentic-identity-design-tenets-2026", source_ids)


if __name__ == "__main__":
    unittest.main()
