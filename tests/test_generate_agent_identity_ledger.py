from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from scripts.generate_agent_identity_ledger import (
    ENTERPRISE_TOKEN_RULES,
    IDENTITY_TOKEN_RULES,
    validate_ledger,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
LEDGER_PATH = REPO_ROOT / "data" / "evidence" / "agent-identity-delegation-ledger.json"
WORKFLOW_PAGE = REPO_ROOT / "content" / "security-remediation" / "agent-identity-ledger" / "_index.md"


class AgentIdentityLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.page = WORKFLOW_PAGE.read_text(encoding="utf-8")

    def test_checked_in_ledger_includes_ir8587_token_controls(self) -> None:
        alignment = {
            str(item.get("id")): item
            for item in self.ledger.get("standards_alignment", [])
            if isinstance(item, dict)
        }
        ir8587 = alignment["nist-ir-8587"]
        self.assertEqual(ir8587["url"], "https://csrc.nist.gov/pubs/ir/8587/final")
        self.assertIn("short-lived", ir8587["coverage"])
        self.assertEqual(
            alignment["mcp-authorization"]["url"],
            "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization",
        )

        identity = self.ledger["agent_identities"][0]
        self.assertEqual(identity["identity_controls"]["token_rules"], IDENTITY_TOKEN_RULES)
        self.assertEqual(self.ledger["enterprise_iam_contract"]["token_rules"], ENTERPRISE_TOKEN_RULES)
        self.assertIn("token_rejected_expired", self.ledger["enterprise_iam_contract"]["audit_events"])
        self.assertIn("token_exposure_detected", self.ledger["enterprise_iam_contract"]["audit_events"])
        self.assertEqual(validate_ledger(self.ledger), [])

    def test_workflow_page_records_ir8587_without_claiming_human_review(self) -> None:
        self.assertIn("https://csrc.nist.gov/pubs/ir/8587/final", self.page)
        self.assertIn("sender-constrained", self.page)
        self.assertIn("one hour", self.page)
        self.assertIn("does not claim human review", self.page)
        self.assertIn("lastmod: 2026-10-02", self.page)

    def test_missing_sender_constraint_rule_fails_validation(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        identity = ledger["agent_identities"][0]
        identity["identity_controls"]["token_rules"] = [
            rule
            for rule in identity["identity_controls"]["token_rules"]
            if "sender-constrained" not in rule
        ]
        failures = validate_ledger(ledger)
        self.assertTrue(any("missing token rules" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main()
