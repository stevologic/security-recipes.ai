from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agent_trust_fabric_decision import (
    evaluate_agent_trust_fabric_decision,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "agent-trust-fabric-pack.json"


def _trusted_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "vulnerable-dependency-remediation",
        "run_id": "run-trust",
        "agent_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "identity_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "tenant_id": "tenant-demo",
        "correlation_id": "corr-trust",
        "trust_event_id": "trust-evt-1",
        "requested_trust_tier": "operator",
        "intent_summary": "Patch dependency lockfiles on a scoped remediation branch",
        "context_package_hash": "sha256:context",
        "policy_pack_hash": "sha256:policy",
        "authorization_decision": "allow_authorized_mcp_request",
        "egress_decision": "allow_internal_context",
        "action_runtime_decision": "allow_bounded_action",
        "telemetry_decision": "telemetry_ready",
        "soc_decision": "no_alert",
        "telemetry_event_id": "trace-1",
        "receipt_id": "receipt-1",
        "source_freshness_decision": "current",
        "human_approval_record": {
            "approval_id": "approval-1",
            "status": "approved",
        },
    }
    request.update(overrides)
    return request


class AgentTrustFabricIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_trusted_scoped_run_is_allowed(self) -> None:
        result = evaluate_agent_trust_fabric_decision(self.pack, _trusted_request())
        self.assertEqual(result["decision"], "allow_trusted_agent_context")
        self.assertTrue(result["allowed"])

    def test_shared_human_credential_kills_the_session(self) -> None:
        result = evaluate_agent_trust_fabric_decision(
            self.pack,
            _trusted_request(shared_human_credential=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_agent_trust_break")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("shared human credential" in item for item in result["violations"])
        )

    def test_local_user_account_impersonation_kills_the_session(self) -> None:
        result = evaluate_agent_trust_fabric_decision(
            self.pack,
            _trusted_request(local_user_account_impersonation=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_agent_trust_break")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("local user account" in item for item in result["violations"])
        )

    def test_long_lived_static_credential_is_denied(self) -> None:
        result = evaluate_agent_trust_fabric_decision(
            self.pack,
            _trusted_request(long_lived_static_credential=True),
        )
        self.assertEqual(result["decision"], "deny_untrusted_agent")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("long-lived static" in item for item in result["violations"])
        )

    def test_shared_human_credential_indicator_matches_kill_signal(self) -> None:
        result = evaluate_agent_trust_fabric_decision(
            self.pack,
            _trusted_request(indicators=["shared_human_credential"]),
        )
        self.assertEqual(result["decision"], "kill_session_on_agent_trust_break")

    def test_nist_identity_source_is_present(self) -> None:
        source_ids = {
            str(row.get("id"))
            for row in self.pack.get("source_references", [])
            if isinstance(row, dict)
        }
        self.assertIn("nist-agentic-identity-foundation-2026", source_ids)


if __name__ == "__main__":
    unittest.main()
