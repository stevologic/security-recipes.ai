from __future__ import annotations

import unittest

from scripts.generate_agent_identity_ledger import (
    ENTERPRISE_IAM_TOKEN_RULES,
    IDENTITY_TOKEN_RULES,
    missing_token_rule_markers,
    validate_ledger,
)


class AgentIdentityLedgerTokenProtectionTests(unittest.TestCase):
    def test_identity_token_rules_cover_ir8587_markers(self) -> None:
        self.assertEqual(missing_token_rule_markers(IDENTITY_TOKEN_RULES, "identity"), [])
        self.assertEqual(
            missing_token_rule_markers(ENTERPRISE_IAM_TOKEN_RULES, "enterprise"),
            [],
        )

    def test_missing_sender_constraint_is_reported(self) -> None:
        stale = [
            "issue tokens just in time",
            "bind tokens to workflow_id and run_id",
            "deny token passthrough to downstream tools",
            "expire tokens when the run ends or a kill signal fires",
        ]
        missing = missing_token_rule_markers(stale, "stale")
        self.assertIn("sender-constrained", missing)
        self.assertIn("one hour", missing)
        self.assertIn("audience", missing)
        self.assertIn("never write tokens to logs", missing)
        self.assertIn("reject expired", missing)

    def test_validate_ledger_requires_ir8587_alignment(self) -> None:
        ledger = {
            "schema_version": "1.0",
            "identity_summary": {
                "default_decision": "deny",
                "human_review_required": True,
                "identity_count": 0,
            },
            "agent_identities": [],
            "enterprise_iam_contract": {"token_rules": list(ENTERPRISE_IAM_TOKEN_RULES)},
            "standards_alignment": [],
        }
        failures = validate_ledger(ledger)
        self.assertTrue(any("nist-ir-8587" in item for item in failures))
