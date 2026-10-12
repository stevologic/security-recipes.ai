from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PIN = "1e6e9a9c4dc9f766c49a421ea268f247d1113287"


class MaintenanceConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = json.loads((ROOT / ".github/maintenance.json").read_text())
        cls.workflow = (ROOT / ".github/workflows/maintenance-plan.yml").read_text()

    def test_consumer_has_no_mutation_or_advisory_ai_authority(self) -> None:
        self.assertEqual(self.policy["repository"], "stevologic/security-recipes.ai")
        self.assertEqual(self.policy["mode"], "dry-run")
        self.assertEqual(self.policy["automation"], {
            "merge": False, "close": False, "delete": False, "deploy": False,
        })
        self.assertEqual(self.policy["ai"]["provider"], "xai")
        self.assertIs(self.policy["ai"]["enabled"], False)
        self.assertNotIn("ai-key:", self.workflow)
        self.assertNotIn("ai-model:", self.workflow)
        self.assertNotIn("secrets.", self.workflow)
        self.assertNotIn("maintenance-operations", self.workflow)

    def test_pinned_caller_has_only_read_permissions(self) -> None:
        permissions = self.workflow.split("permissions:\n", 1)[1].split("\nconcurrency:", 1)[0]
        actual = dict(re.findall(r"(?m)^  ([\w-]+): (\w+)$", permissions))
        self.assertEqual(actual, dict.fromkeys(
            ("contents", "issues", "pull-requests", "checks", "actions"), "read",
        ))
        references = re.findall(r"(?m)^\s*uses:\s*([^#\s]+)", self.workflow)
        self.assertIn("stevologic/oss-deps-explorer/actions/maintenance@" + PIN, references)
        for reference in references:
            self.assertRegex(reference, r"^[^@\s]+@[0-9a-f]{40}$")
        self.assertIn("persist-credentials: false", self.workflow)
        self.assertNotIn("pull_request_target:", self.workflow)

    def test_existing_custom_pipelines_and_active_work_remain_reserved(self) -> None:
        reserved = {entry.split(":", 1)[0] for entry in self.policy["custom_jobs"]}
        existing = {path.name for path in (ROOT / ".github/workflows").glob("*.yml")}
        self.assertEqual(reserved, existing - {"maintenance-plan.yml"})
        self.assertIn("automation/*", self.policy["protected_patterns"])
        self.assertEqual(self.policy["default_branch"], "main")
        self.assertEqual(self.policy["integration_branch"], "development")
        self.assertEqual(self.policy["required_checks"], ["build"])
        # String IDs would silently miss REST pull-request numbers in the
        # shared contract's hold check. Completed reservations may be removed.
        self.assertTrue(all(isinstance(number, int) and number > 0
                            for number in self.policy["locked_prs"]))

    def test_inventory_cost_is_bounded_without_replacing_security_cadence(self) -> None:
        self.assertIn("cron: '7 15 * * 1'", self.workflow)
        self.assertIn("timeout-minutes: 15", self.workflow)
        self.assertIn("retention-days: 7", self.workflow)
        self.assertEqual(self.policy["cadences"]["tooling"], "monthly")
        self.assertEqual(self.policy["cadences"]["major_review"], "quarterly")
        self.assertIn("advisory-driven", self.policy["cadences"]["security"])


if __name__ == "__main__":
    unittest.main()
