from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agentic_entitlement_decision import (
    evaluate_agentic_entitlement_decision,
    full_catalog_initial_grant_hold_violations,
    omnibus_token_scope_kill_violations,
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
        "run_id": "run-ci",
        "tenant_id": "tenant-ci",
        "correlation_id": "corr-ci",
        "receipt_id": "receipt-ci",
        "policy_pack_hash": "sha256:policy",
    }
    request.update(overrides)
    return request


class AgenticEntitlementScopeMinimizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_unspecified_token_scopes_stay_on_the_allow_path(self) -> None:
        result = evaluate_agentic_entitlement_decision(self.pack, _active_write())
        self.assertEqual(result["decision"], "allow_active_entitlement")
        self.assertTrue(result["allowed"])
        self.assertEqual(omnibus_token_scope_kill_violations(_active_write()), [])
        self.assertEqual(full_catalog_initial_grant_hold_violations(_active_write()), [])

    def test_least_privilege_token_scopes_stay_on_the_allow_path(self) -> None:
        result = evaluate_agentic_entitlement_decision(
            self.pack,
            _active_write(token_scopes=["repo.contents:write_branch"]),
        )
        self.assertEqual(result["decision"], "allow_active_entitlement")
        self.assertTrue(result["allowed"])

    def test_omnibus_files_db_admin_token_scopes_kill(self) -> None:
        result = evaluate_agentic_entitlement_decision(
            self.pack,
            _active_write(token_scopes=["files:*", "db:*", "admin:*"]),
        )
        self.assertEqual(result["decision"], "kill_session_on_entitlement_signal")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("files:*" in item for item in result["violations"]))
        self.assertTrue(any("db:*" in item for item in result["violations"]))
        self.assertTrue(any("admin:*" in item for item in result["violations"]))

    def test_wildcard_and_full_access_token_scopes_kill(self) -> None:
        for scope in ("*", "all", "full-access"):
            with self.subTest(scope=scope):
                result = evaluate_agentic_entitlement_decision(
                    self.pack,
                    _active_write(token_scopes=[scope]),
                )
                self.assertEqual(result["decision"], "kill_session_on_entitlement_signal")
                self.assertFalse(result["allowed"])
                self.assertTrue(any(scope in item for item in result["violations"]))

    def test_full_catalog_initial_grant_without_downscope_is_held(self) -> None:
        result = evaluate_agentic_entitlement_decision(
            self.pack,
            _active_write(
                initial_grant=True,
                requested_scopes=[
                    "mcp:tools-basic",
                    "repo.contents:write_branch",
                    "files:read",
                ],
                scopes_supported=[
                    "mcp:tools-basic",
                    "repo.contents:write_branch",
                    "files:read",
                ],
            ),
        )
        self.assertEqual(result["decision"], "hold_for_step_up_authorization")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("full scopes_supported catalog" in item for item in result["violations"]))

    def test_downscoped_full_catalog_request_stays_on_the_allow_path(self) -> None:
        result = evaluate_agentic_entitlement_decision(
            self.pack,
            _active_write(
                initial_grant=True,
                downscoped_grant=True,
                requested_scopes=[
                    "mcp:tools-basic",
                    "repo.contents:write_branch",
                    "files:read",
                ],
                scopes_supported=[
                    "mcp:tools-basic",
                    "repo.contents:write_branch",
                    "files:read",
                ],
                token_scopes=["mcp:tools-basic"],
            ),
        )
        self.assertEqual(result["decision"], "allow_active_entitlement")
        self.assertTrue(result["allowed"])

    def test_targeted_scope_challenge_stays_on_the_allow_path(self) -> None:
        result = evaluate_agentic_entitlement_decision(
            self.pack,
            _active_write(
                initial_grant=True,
                requested_scopes=[
                    "mcp:tools-basic",
                    "repo.contents:write_branch",
                ],
                scopes_supported=[
                    "mcp:tools-basic",
                    "repo.contents:write_branch",
                ],
                scope_challenge=["repo.contents:write_branch"],
                token_scopes=["repo.contents:write_branch"],
            ),
        )
        self.assertEqual(result["decision"], "allow_active_entitlement")
        self.assertTrue(result["allowed"])

    def test_unspecified_catalog_helpers_return_no_violations(self) -> None:
        request = _active_write()
        self.assertEqual(omnibus_token_scope_kill_violations(request), [])
        self.assertEqual(full_catalog_initial_grant_hold_violations(request), [])


if __name__ == "__main__":
    unittest.main()
