from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "karen-qa-or-data-only.yml"
AUTOMATION_DOC = ROOT / ".github" / "AUTOMATION.md"


class KarenQaOrDataOnlyWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.automation = AUTOMATION_DOC.read_text(encoding="utf-8")

    def test_uses_pull_request_target_without_running_pr_code(self) -> None:
        self.assertRegex(self.workflow, r"(?m)^on:\s*\n\s+pull_request_target:")
        self.assertNotRegex(self.workflow, r"(?m)^\s+pull_request:\s*$")
        self.assertIn("ref: ${{ github.event.repository.default_branch }}", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)
        self.assertNotIn("github.event.pull_request.head.sha", self.workflow)
        self.assertNotIn("ref: ${{ github.sha }}", self.workflow)
        self.assertIn("Never checkout", self.workflow)
        self.assertIn("never checks", self.workflow)
        self.assertIn("out or runs pull-request code", self.workflow)
        self.assertIn("pulls/${PR_NUMBER}/files", self.workflow)
        self.assertNotIn("git diff", self.workflow)
        self.assertNotIn("git show", self.workflow)

    def test_job_name_is_the_required_check_context(self) -> None:
        self.assertRegex(
            self.workflow,
            r"(?ms)^\s{2}karen-qa-or-data-only:\s*.*?^\s{4}name: karen-qa-or-data-only\s*$",
        )
        self.assertIn('context="karen-qa-or-data-only"', self.workflow)
        self.assertNotIn('context="karen-qa"', self.workflow)
        self.assertNotIn("context=karen-qa\n", self.workflow)
        self.assertIn("never emits", self.workflow)
        self.assertIn("the `karen-qa` context", self.workflow)
        self.assertIn("Author does not matter", self.workflow)
        self.assertIn("cannot", self.workflow)
        self.assertIn("exempt itself", self.workflow)

    def test_posts_status_on_the_exact_live_head(self) -> None:
        self.assertIn("repos/${GITHUB_REPOSITORY}/statuses/${HEAD_SHA}", self.workflow)
        self.assertIn("statuses: write", self.workflow)
        self.assertIn("LIVE_HEAD", self.workflow)
        self.assertIn("commits/${HEAD_SHA}/statuses", self.workflow)
        self.assertIn("commits/${HEAD_SHA}/check-runs", self.workflow)
        self.assertIn("needs karen-qa on ${HEAD_SHA} from Karen QA app", self.workflow)
        self.assertIn("check_run", self.workflow)
        self.assertIn("github.event.check_run.name == 'karen-qa'", self.workflow)

    def test_actions_are_pinned_and_permissions_are_minimal(self) -> None:
        self.assertRegex(self.workflow, r"(?m)^permissions:\s*\{\}\s*$")
        references = re.findall(r"(?m)^\s*uses:\s*([^#\s]+)", self.workflow)
        self.assertEqual(len(references), 1)
        self.assertRegex(references[0], r"^actions/checkout@[0-9a-f]{40}$")
        self.assertNotIn("setup-python", self.workflow)
        self.assertNotIn("pip install", self.workflow)
        self.assertNotIn("npm ", self.workflow)
        self.assertNotIn("secrets.", self.workflow)

    def test_documents_the_ruleset_change_without_applying_it(self) -> None:
        self.assertIn("Ruleset change", self.workflow)
        self.assertIn("replace that pin with", self.workflow)
        self.assertIn("`karen-qa-or-data-only`", self.automation)
        self.assertIn("replace the required `karen-qa` check", self.automation)
        self.assertIn("Do not change the ruleset", self.automation)
        self.assertIn("from this pull request", self.automation)
        self.assertNotIn("gh api --method PUT", self.workflow)
        self.assertNotIn("/rulesets/", self.workflow)


if __name__ == "__main__":
    unittest.main()
