from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agentic_entitlement_decision import (
    evaluate_agentic_entitlement_decision,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "agentic-entitlement-review-pack.json"


def _active_write(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "identity_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "workflow_id": "vulnerable-dependency-remediation",
        "agent_class": "codex",
        "namespace": "repo.contents",
        "requested_access_mode": "write_branch",
        "lease_id": "lease-ci",
        "lease_status": "active",
        "lease_expires_at": "2099-01-01T00:00:00Z",
        "review_status": "current",
        "authorization_decision": "allow_authorized_mcp_request",
        "run_id": "run-entitlement",
        "tenant_id": "tenant-ci",
        "correlation_id": "corr-entitlement",
        "receipt_id": "receipt-entitlement",
        "policy_pack_hash": "sha256:policy",
    }
    request.update(overrides)
    return request


class AgenticEntitlementScopeMinimizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_active_write_is_allowed_when_scope_evidence_is_unspecified(self) -> None:
        result = evaluate_agentic_entitlement_decision(self.pack, _active_write())
        self.assertEqual(result["decision"], "allow_active_entitlement")
        self.assertTrue(result["allowed"])

    def test_baseline_granted_scope_stays_on_the_allow_path(self) -> None:
        result = evaluate_agentic_entitlement_decision(
            self.pack,
            _active_write(granted_scopes=["mcp:tools-basic"]),
        )
        self.assertEqual(result["decision"], "allow_active_entitlement")
        self.assertTrue(result["allowed"])

    def test_omnibus_files_scope_kills_the_session(self) -> None:
        result = evaluate_agentic_entitlement_decision(
            self.pack,
            _active_write(granted_scopes=["files:*"]),
        )
        self.assertEqual(result["decision"], "kill_session_on_entitlement_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("files:*" in item for item in result["violations"]))

    def test_omnibus_admin_scope_kills_even_when_mixed_with_baseline(self) -> None:
        result = evaluate_agentic_entitlement_decision(
            self.pack,
            _active_write(granted_scopes=["mcp:tools-basic", "admin:*"]),
        )
        self.assertEqual(result["decision"], "kill_session_on_entitlement_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("admin:*" in item for item in result["violations"]))

    def test_full_scopes_supported_initial_grant_holds_for_step_up(self) -> None:
        result = evaluate_agentic_entitlement_decision(
            self.pack,
            _active_write(requested_all_scopes_supported=True),
        )
        self.assertEqual(result["decision"], "hold_for_step_up_authorization")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("requested_all_scopes_supported" in item for item in result["violations"])
        )

    def test_full_catalog_request_with_down_scoped_grant_is_allowed(self) -> None:
        result = evaluate_agentic_entitlement_decision(
            self.pack,
            _active_write(
                requested_all_scopes_supported=True,
                granted_scopes=["mcp:tools-basic"],
            ),
        )
        self.assertEqual(result["decision"], "allow_active_entitlement")
        self.assertTrue(result["allowed"])

    def test_full_catalog_request_with_omnibus_grant_kills(self) -> None:
        result = evaluate_agentic_entitlement_decision(
            self.pack,
            _active_write(
                requested_all_scopes_supported=True,
                granted_scopes=["db:*"],
            ),
        )
        self.assertEqual(result["decision"], "kill_session_on_entitlement_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("db:*" in item for item in result["violations"]))


if __name__ == "__main__":
    unittest.main()
