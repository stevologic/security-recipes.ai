from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "leftover-review.yml"


class LeftoverReviewWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_runs_daily_and_can_be_dispatched(self) -> None:
        self.assertIn('cron: "17 13 * * *"', self.workflow)
        self.assertIn("workflow_dispatch:", self.workflow)
        self.assertIn("group: leftover-review", self.workflow)
        self.assertIn("cancel-in-progress: false", self.workflow)

    def test_reviews_up_to_100_leftover_gold_mediums_and_lows_after_highs(self) -> None:
        for required in (
            "scripts/pick_leftover_review_queue.py",
            "up to 100 leftover-gold medium and low",
            "drains leftover-gold criticals and highs first",
            "data/cve/leftover-review-state.json",
            "never invent +1 versions",
            "live GHAD 404",
            "set lastmod to today's UTC date (the review",
        ):
            self.assertIn(required, self.workflow)

    def test_uses_a_guarded_labeled_pull_request(self) -> None:
        for delivery_rule in (
            "automation/leftover-review-",
            "automation:leftover-review",
            "gh pr merge --auto --squash <pr-number>",
            "Never push directly to main or merge directly",
            "never force-push",
        ):
            self.assertIn(delivery_rule, self.workflow)

    def test_missing_or_unusable_openai_key_is_a_safe_noop(self) -> None:
        self.assertIn("secrets.OPENAI_API_KEY", self.workflow)
        self.assertIn("daily leftover review is inactive", self.workflow)
        self.assertIn("if: steps.auth.outputs.configured == 'true'", self.workflow)
        self.assertIn("scripts/check_openai_credentials.py", self.workflow)
        self.assertIn("if: steps.openai.outputs.usable == 'true'", self.workflow)

    def test_empty_queue_skips_codex(self) -> None:
        self.assertIn("steps.queue.outputs.selected != '0'", self.workflow)

    def test_actions_are_pinned_to_full_commit_shas(self) -> None:
        references = re.findall(r"(?m)^\s*uses:\s*([^#\s]+)", self.workflow)
        self.assertEqual(len(references), 2)
        for reference in references:
            with self.subTest(reference=reference):
                self.assertRegex(reference, r"^[^@\s]+@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
