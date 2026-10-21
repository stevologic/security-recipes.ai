from __future__ import annotations

import re
import unittest
from pathlib import Path

from scripts.karen_qa_or_data_only import GITHUB_ACTIONS_APP_ID, KAREN_QA_APP_ID


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

    def test_job_name_is_the_required_check_and_creates_a_check_run(self) -> None:
        self.assertRegex(
            self.workflow,
            r"(?ms)^\s{2}karen-qa-or-data-only:\s*.*?^\s{4}name: karen-qa-or-data-only\s*$",
        )
        self.assertIn('name: $name', self.workflow)
        self.assertIn('"karen-qa-or-data-only"', self.workflow)
        self.assertIn("repos/${GITHUB_REPOSITORY}/check-runs", self.workflow)
        self.assertIn("--method POST", self.workflow)
        self.assertIn("Create karen-qa-or-data-only check run on the exact head", self.workflow)
        self.assertNotIn("/statuses/", self.workflow)
        self.assertNotIn("statuses: write", self.workflow)
        self.assertIn("checks: write", self.workflow)
        self.assertNotIn('context="karen-qa"', self.workflow)
        self.assertIn("never emits", self.workflow)
        self.assertIn("the `karen-qa` context", self.workflow)
        self.assertIn("cannot", self.workflow)
        self.assertIn("exempt itself", self.workflow)
        self.assertNotIn("Author does not matter", self.workflow)

    def test_check_run_is_not_a_spoofable_commit_status(self) -> None:
        self.assertNotRegex(self.workflow, r"(?m)^  status:\s*$")
        self.assertIn("github.event.check_run.name == 'karen-qa'", self.workflow)
        self.assertIn(f"github.event.check_run.app.id == {KAREN_QA_APP_ID}", self.workflow)
        self.assertIn(f"KAREN_QA_APP_ID: \"{KAREN_QA_APP_ID}\"", self.workflow)
        self.assertIn(f"integration {GITHUB_ACTIONS_APP_ID}", self.workflow)
        self.assertIn("plain commit status cannot satisfy", self.workflow)
        self.assertIn("needs karen-qa on ${HEAD_SHA} from Karen QA app", self.workflow)

    def test_reads_head_and_files_consistently_and_rechecks_head(self) -> None:
        self.assertIn("Read the head SHA, then the file list, then re-check that the head is unchanged.", self.workflow)
        self.assertIn("Re-check that the head is unchanged before creating the check run.", self.workflow)
        self.assertIn("pr-after-files.json", self.workflow)
        self.assertIn("OBSERVED_HEAD", self.workflow)
        self.assertIn("LIVE_HEAD", self.workflow)
        self.assertIn("changed_files", self.workflow)
        self.assertIn("pulls/${PR_NUMBER}/commits", self.workflow)
        self.assertIn("git/trees/${HEAD_TREE_SHA}?recursive=1", self.workflow)
        self.assertIn("git/trees/${BASE_TREE_SHA}?recursive=1", self.workflow)
        self.assertIn("--observed-head-sha", self.workflow)
        self.assertIn("--author-type", self.workflow)
        self.assertIn("--commits-json", self.workflow)
        self.assertIn("--head-tree-json", self.workflow)
        self.assertIn("commits/${HEAD_SHA}/check-runs", self.workflow)

    def test_actions_are_pinned_and_permissions_are_minimal(self) -> None:
        self.assertRegex(self.workflow, r"(?m)^permissions:\s*\{\}\s*$")
        references = re.findall(r"(?m)^\s*uses:\s*([^#\s]+)", self.workflow)
        self.assertEqual(len(references), 1)
        self.assertRegex(references[0], r"^actions/checkout@[0-9a-f]{40}$")
        self.assertNotIn("setup-python", self.workflow)
        self.assertNotIn("pip install", self.workflow)
        self.assertNotIn("npm ", self.workflow)
        self.assertNotIn("secrets.", self.workflow)

    def test_documents_the_ruleset_change_and_integration_pin(self) -> None:
        self.assertIn("Ruleset change", self.workflow)
        self.assertIn("replace that pin with", self.workflow)
        self.assertIn("`karen-qa-or-data-only`", self.automation)
        self.assertIn("replace the required `karen-qa` check", self.automation)
        self.assertIn(str(KAREN_QA_APP_ID), self.automation)
        self.assertIn(str(GITHUB_ACTIONS_APP_ID), self.automation)
        self.assertIn("integration_id", self.automation)
        self.assertIn("Do not change the ruleset", self.automation)
        self.assertIn("from this pull request", self.automation)
        self.assertIn("CVE catalog data", self.automation)
        self.assertNotIn("Author does not matter", self.automation)
        self.assertNotIn("explicit CVE pipeline", self.automation)
        self.assertNotIn("gh api --method PUT", self.workflow)
        self.assertNotIn("/rulesets/", self.workflow)


if __name__ == "__main__":
    unittest.main()
