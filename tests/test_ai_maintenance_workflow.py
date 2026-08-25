from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ai-maintenance.yml"
PROMPT = ROOT / ".github" / "prompts" / "ai-maintenance.md"


class AiMaintenanceWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.prompt = PROMPT.read_text(encoding="utf-8")

    def test_triggers_only_on_failed_automation_workflow_runs(self) -> None:
        self.assertIn("workflow_run:", self.workflow)
        self.assertNotRegex(self.workflow, r"(?m)^\s+(push|pull_request|pull_request_target):")
        self.assertIn("github.event.workflow_run.conclusion == 'failure'", self.workflow)
        for watched in (
            "- Build",
            "- CVE catalog sync",
            "- Content refresh",
            "- Leftover review",
            "- Production watchdog",
            "- CVE catalog validation",
            "- Automation shepherd",
            "- AI issue maintenance",
        ):
            with self.subTest(watched=watched):
                self.assertIn(watched, self.workflow)
        for branch_guard in (
            "github.event.workflow_run.head_branch == 'main'",
            "startsWith(github.event.workflow_run.head_branch, 'automation/')",
            "startsWith(github.event.workflow_run.head_branch, 'dependabot/')",
        ):
            with self.subTest(branch_guard=branch_guard):
                self.assertIn(branch_guard, self.workflow)

    def test_missing_or_unusable_api_key_disables_ai_repair_gracefully(self) -> None:
        self.assertIn("XAI_API_KEY: ${{ secrets.XAI_API_KEY }}", self.workflow)
        self.assertNotIn("OPENAI_API_KEY", self.workflow)
        self.assertIn("configured=false", self.workflow)
        self.assertIn(
            "AI maintenance is inactive until the repository secret is added",
            self.workflow,
        )
        self.assertIn("scripts/check_xai_credentials.py", self.workflow)
        self.assertIn("if: steps.xai.outputs.usable == 'true'", self.workflow)
        self.assertGreaterEqual(
            self.workflow.count("if: steps.auth.outputs.configured == 'true'"),
            2,
        )

    def test_repair_prompt_routes_delivery_through_the_shepherd(self) -> None:
        self.assertIn("automation/ai-fix-", self.prompt)
        self.assertIn("gh pr merge --auto --squash", self.prompt)
        self.assertIn("never merge directly", self.prompt)
        self.assertIn("automation:production-health", self.prompt)
        self.assertIn("never force-push", self.prompt)
        self.assertIn("never weaken or skip checks", self.prompt)
        self.assertIn("FAILED_WORKFLOW_RUN_ID", self.prompt)
        self.assertIn(
            "scripts/run_grok_agent.py --prompt-file .github/prompts/ai-maintenance.md",
            self.workflow,
        )

    def test_each_failed_run_gets_its_own_repair_slot(self) -> None:
        # A shared concurrency group let GitHub cancel queued investigations
        # when several workflows completed at once, dropping real failures.
        self.assertIn(
            "group: ai-maintenance-${{ github.event.workflow_run.id || github.run_id }}",
            self.workflow,
        )
        self.assertIn("cancel-in-progress: false", self.workflow)

    def test_workflow_permissions_stay_scoped_to_the_repair_job(self) -> None:
        self.assertIn("permissions: {}", self.workflow)
        job_section = self.workflow.split("jobs:", 1)[1]
        self.assertRegex(job_section, r"(?m)^\s{6}contents: write\s*$")
        self.assertRegex(job_section, r"(?m)^\s{6}pull-requests: write\s*$")

    def test_actions_are_pinned_to_full_commit_shas(self) -> None:
        references = re.findall(r"(?m)^\s*uses:\s*([^#\s]+)", self.workflow)

        self.assertEqual(len(references), 1)
        for reference in references:
            with self.subTest(reference=reference):
                self.assertRegex(reference, r"^[^@\s]+@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
