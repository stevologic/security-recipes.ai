from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "content-refresh.yml"


class ContentRefreshWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_runs_daily_and_can_be_dispatched(self) -> None:
        self.assertIn('cron: "47 11 * * *"', self.workflow)
        self.assertIn("workflow_dispatch:", self.workflow)
        self.assertIn("group: content-refresh", self.workflow)
        self.assertIn("cancel-in-progress: false", self.workflow)

    def test_covers_all_reviewed_non_cve_content_surfaces(self) -> None:
        for required_scope in (
            "content/security-remediation/",
            "data/remediation_suite/",
            "data/assurance/",
            "non-CVE recipes under content/recipes/",
        ):
            self.assertIn(required_scope, self.workflow)
        for excluded_scope in (
            "content/recipes/cve/",
            "data/cve/",
            "static/api/cve-catalog/",
        ):
            self.assertIn(excluded_scope, self.workflow)

    def test_requires_research_substantive_edits_and_validation(self) -> None:
        for guardrail in (
            "primary/official sources",
            "at most one high-confidence, coherent opportunity",
            "date-only freshness edits",
            "Do not claim human review",
            "python scripts/run_checks.py",
            "creating a branch, issue, or PR",
        ):
            self.assertIn(guardrail, self.workflow)

    def test_uses_a_guarded_labeled_pull_request(self) -> None:
        for delivery_rule in (
            "automation/content-refresh-<topic>",
            "automation:content-refresh",
            "gh pr merge --auto --squash <pr-number>",
            "Never push directly to main or merge directly",
            "never force-push",
        ):
            self.assertIn(delivery_rule, self.workflow)

    def test_missing_or_unusable_openai_key_is_a_safe_noop(self) -> None:
        self.assertIn("secrets.OPENAI_API_KEY", self.workflow)
        self.assertIn("daily content refresh is inactive", self.workflow)
        self.assertIn("if: steps.auth.outputs.configured == 'true'", self.workflow)
        self.assertIn("scripts/check_openai_credentials.py", self.workflow)
        self.assertIn("if: steps.openai.outputs.usable == 'true'", self.workflow)


if __name__ == "__main__":
    unittest.main()
