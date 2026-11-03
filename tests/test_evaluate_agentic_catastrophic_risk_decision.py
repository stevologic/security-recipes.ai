from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agentic_catastrophic_risk_decision import (
    evaluate_agentic_catastrophic_risk_decision,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
ANNEX_PATH = REPO_ROOT / "data" / "evidence" / "agentic-catastrophic-risk-annex.json"


def _reviewed_high_impact(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "base-image-remediation",
        "action_class": "production_deployment",
        "run_id": "run-123",
        "agent_id": "sr-agent::base-image-remediation::codex",
        "identity_id": "sr-agent::base-image-remediation::codex",
        "tenant_id": "tenant-demo",
        "policy_pack_hash": "policy-hash",
        "authorization_decision": "allow_authorized_mcp_request",
        "context_package_hash": "context-hash",
        "egress_decision": "allow_internal_context",
        "handoff_decision": "allow_handoff",
        "readiness_decision": "ready",
        "risk_acceptance_id": "risk-accept-123",
        "receipt_id": "receipt-123",
        "correlation_id": "corr-123",
        "affects_prod": True,
        "human_approval_record": {
            "approval_id": "approval-123",
            "status": "approved",
        },
    }
    request.update(overrides)
    return request


class AgenticCatastrophicRiskIdentityTenetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.annex = json.loads(ANNEX_PATH.read_text(encoding="utf-8"))

    def test_reviewed_high_impact_action_is_allowed_when_identity_tenets_are_unspecified(self) -> None:
        result = evaluate_agentic_catastrophic_risk_decision(
            self.annex, _reviewed_high_impact()
        )
        self.assertEqual(result["decision"], "allow_reviewed_high_impact_action")
        self.assertTrue(result["allowed"])

    def test_unattenuated_subagent_delegation_is_denied(self) -> None:
        result = evaluate_agentic_catastrophic_risk_decision(
            self.annex,
            _reviewed_high_impact(unattenuated_subagent_delegation=True),
        )
        self.assertEqual(result["decision"], "deny_unbounded_autonomy")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("unattenuated sub-agent" in item for item in result["violations"])
        )

    def test_standing_privilege_is_denied(self) -> None:
        result = evaluate_agentic_catastrophic_risk_decision(
            self.annex,
            _reviewed_high_impact(standing_privilege=True),
        )
        self.assertEqual(result["decision"], "deny_unbounded_autonomy")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("standing privilege" in item for item in result["violations"])
        )

    def test_model_driven_access_grant_is_denied(self) -> None:
        result = evaluate_agentic_catastrophic_risk_decision(
            self.annex,
            _reviewed_high_impact(model_driven_access_grant=True),
        )
        self.assertEqual(result["decision"], "deny_unbounded_autonomy")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("separated deterministic policy engine" in item for item in result["violations"])
        )

    def test_agent_writable_evidence_kills_the_session(self) -> None:
        result = evaluate_agentic_catastrophic_risk_decision(
            self.annex,
            _reviewed_high_impact(agent_writable_evidence=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_catastrophic_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("agent-writable evidence" in item for item in result["violations"])
        )

    def test_unsigned_mandate_holds_high_impact_action(self) -> None:
        result = evaluate_agentic_catastrophic_risk_decision(
            self.annex,
            _reviewed_high_impact(unsigned_mandate=True),
        )
        self.assertEqual(result["decision"], "hold_for_catastrophic_risk_review")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("unsigned mandate" in item for item in result["violations"])
        )

    def test_nist_identity_design_tenets_source_is_present(self) -> None:
        source_ids = {
            str(row.get("id"))
            for row in self.annex.get("standards_alignment", [])
            if isinstance(row, dict)
        }
        self.assertIn("nist-agentic-identity-foundation-2026", source_ids)
        self.assertIn("nist-agentic-identity-design-tenets-2026", source_ids)


if __name__ == "__main__":
    unittest.main()
