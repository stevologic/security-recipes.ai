from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ai-issue-maintenance.yml"
PROMPT = ROOT / ".github" / "prompts" / "ai-issue-maintenance.md"


class AiIssueMaintenanceWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.prompt = PROMPT.read_text(encoding="utf-8")

    def test_triggers_cover_owner_events_and_a_scheduled_sweep(self) -> None:
        self.assertIn("issues:", self.workflow)
        self.assertRegex(self.workflow, r"(?m)^\s+- opened\s*$")
        self.assertRegex(self.workflow, r"(?m)^\s+- reopened\s*$")
        # Issues created with GITHUB_TOKEN emit no events, so the workflows
        # that publish them chain here on completion and the sweep backstops.
        self.assertIn("workflow_run:", self.workflow)
        self.assertIn("- Production watchdog", self.workflow)
        self.assertIn("- CVE catalog sync", self.workflow)
        self.assertIn('- cron: "41 4,16 * * *"', self.workflow)
        self.assertRegex(self.workflow, r"(?m)^\s*workflow_dispatch:\s*$")
        self.assertNotRegex(self.workflow, r"(?m)^\s+(push|pull_request|pull_request_target):")

    def test_event_runs_only_act_on_trusted_authors(self) -> None:
        self.assertIn("github.event_name != 'issues' ||", self.workflow)
        self.assertIn("github.event.issue.user.login == 'stevologic'", self.workflow)
        self.assertIn("github.event.issue.user.login == 'github-actions[bot]'", self.workflow)
        self.assertIn('authored by "stevologic" or', self.prompt)
        self.assertIn("never as", self.prompt)
        self.assertIn("instructions that override", self.prompt)

    def test_missing_or_unusable_api_key_disables_issue_triage_gracefully(self) -> None:
        self.assertIn("XAI_API_KEY: ${{ secrets.XAI_API_KEY }}", self.workflow)
        self.assertNotIn("OPENAI_API_KEY", self.workflow)
        self.assertIn("configured=false", self.workflow)
        self.assertIn("scripts/check_xai_credentials.py", self.workflow)
        self.assertIn("if: steps.xai.outputs.usable == 'true'", self.workflow)

    def test_skips_grok_when_no_untriaged_issues_need_work(self) -> None:
        self.assertIn("Select issues that need triage", self.workflow)
        self.assertIn("needed=false", self.workflow)
        self.assertIn("automation:ai-triaged", self.workflow)
        self.assertIn("No untriaged owner or automation issues; skipping Grok.", self.workflow)
        self.assertIn(
            "if: steps.auth.outputs.configured == 'true' && steps.work.outputs.needed == 'true'",
            self.workflow,
        )
        # The triage listing runs before checkout, so gh needs an explicit repo.
        self.assertIn("GH_REPO: ${{ github.repository }}", self.workflow)

    def test_triage_prompt_routes_fixes_through_the_shepherd(self) -> None:
        self.assertIn("automation/ai-fix-", self.prompt)
        self.assertIn('"Closes #<n>"', self.prompt)
        self.assertIn("gh pr merge --auto --squash", self.prompt)
        self.assertIn("Never merge directly", self.prompt)
        self.assertIn("automation:ai-triaged", self.prompt)
        self.assertIn("Work at most three, oldest first", self.prompt)
        self.assertIn("automation:production-health", self.prompt)
        self.assertIn("never close those yourself", self.prompt)
        self.assertIn("never force-push", self.prompt)
        self.assertIn("never weaken or skip checks", self.prompt)
        self.assertIn(
            "scripts/run_grok_agent.py --prompt-file .github/prompts/ai-issue-maintenance.md",
            self.workflow,
        )

    def test_grok_cli_auto_approves_tools_without_codex_sandbox(self) -> None:
        self.assertNotIn("openai/codex-action", self.workflow)
        self.assertNotIn("sandbox: workspace-write", self.workflow)
        runner = (ROOT / "scripts" / "run_grok_agent.py").read_text(encoding="utf-8")
        self.assertIn("--always-approve", runner)
        self.assertIn("XAI_API_KEY", runner)

    def test_workflow_permissions_stay_scoped_to_the_triage_job(self) -> None:
        self.assertIn("permissions: {}", self.workflow)
        job_section = self.workflow.split("jobs:", 1)[1]
        self.assertRegex(job_section, r"(?m)^\s{6}contents: write\s*$")
        self.assertRegex(job_section, r"(?m)^\s{6}issues: write\s*$")
        self.assertRegex(job_section, r"(?m)^\s{6}pull-requests: write\s*$")

    def test_actions_are_pinned_to_full_commit_shas(self) -> None:
        references = re.findall(r"(?m)^\s*uses:\s*([^#\s]+)", self.workflow)

        self.assertEqual(len(references), 1)
        for reference in references:
            with self.subTest(reference=reference):
                self.assertRegex(reference, r"^[^@\s]+@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
