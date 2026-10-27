from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from scripts.karen_qa_or_data_only import (
    CVE_CATALOG_SYNC_BRANCH,
    GITHUB_ACTIONS_APP_ID,
    GITHUB_ACTIONS_BOT_ID,
    KAREN_QA_OR_DATA_ONLY_WORKFLOW,
    KAREN_QA_USER_ID,
    KAREN_QA_USER_LOGIN,
    MAIN_GATE_RULESET,
    REPOSITORY_ID,
    REQUIRED_CHECK_NAME,
    SYNC_BRANCH_RULESET,
)


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / KAREN_QA_OR_DATA_ONLY_WORKFLOW
AUTOMATION_DOC = ROOT / ".github" / "AUTOMATION.md"
MAIN_RULESET_PATH = ROOT / MAIN_GATE_RULESET
SYNC_RULESET_PATH = ROOT / SYNC_BRANCH_RULESET


class KarenQaOrDataOnlyWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.automation = AUTOMATION_DOC.read_text(encoding="utf-8")
        cls.main_ruleset = json.loads(MAIN_RULESET_PATH.read_text(encoding="utf-8"))
        cls.sync_ruleset = json.loads(SYNC_RULESET_PATH.read_text(encoding="utf-8"))

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

    def test_job_name_is_the_required_workflow_job_and_does_not_post_a_check_run(self) -> None:
        self.assertRegex(
            self.workflow,
            r"(?ms)^\s{2}karen-qa-or-data-only:\s*.*?^\s{4}name: karen-qa-or-data-only\s*$",
        )
        self.assertNotIn("repos/${GITHUB_REPOSITORY}/check-runs", self.workflow)
        self.assertNotIn("--method POST", self.workflow)
        self.assertNotIn("Create karen-qa-or-data-only check run on the exact head", self.workflow)
        self.assertNotIn("/statuses/", self.workflow)
        self.assertNotIn("statuses: write", self.workflow)
        self.assertNotIn("checks: write", self.workflow)
        self.assertNotIn('context="karen-qa"', self.workflow)
        self.assertIn("never emits", self.workflow)
        self.assertIn("the `karen-qa` context", self.workflow)
        self.assertIn("never posts a check run", self.workflow)
        self.assertIn("cannot", self.workflow)
        self.assertIn("exempt itself", self.workflow)
        self.assertNotIn("Author does not matter", self.workflow)

    def test_gate_depends_on_required_workflow_identity_not_actions_app_15368(self) -> None:
        self.assertIn("ruleset `workflows` rule", self.workflow)
        self.assertIn("identity a PR cannot forge", self.workflow)
        self.assertIn("Do not pin a required status check", self.workflow)
        self.assertIn("integration 15368", self.workflow)
        self.assertIn("that name is spoofable", self.workflow)
        self.assertNotIn("github.event.check_run.app.id == 5400051", self.workflow)
        self.assertNotIn("KAREN_QA_APP_ID", self.workflow)
        self.assertNotIn("5400051", self.workflow)
        required = self.main_ruleset["rules"]
        self.assertEqual(len(required), 1)
        self.assertEqual(required[0]["type"], "workflows")
        workflow_pin = required[0]["parameters"]["workflows"][0]
        self.assertEqual(workflow_pin["path"], str(KAREN_QA_OR_DATA_ONLY_WORKFLOW))
        self.assertEqual(workflow_pin["ref"], "refs/heads/main")
        self.assertEqual(workflow_pin["repository_id"], REPOSITORY_ID)
        checks = [
            rule
            for rule in required
            if rule.get("type") == "required_status_checks"
        ]
        self.assertEqual(checks, [])

    def test_accepts_karen_qa_status_from_stevologic_bot_user(self) -> None:
        self.assertRegex(self.workflow, r"(?m)^  status:\s*$")
        self.assertIn("github.event.context == 'karen-qa'", self.workflow)
        self.assertIn(f"github.event.sender.id == {KAREN_QA_USER_ID}", self.workflow)
        self.assertIn(f'KAREN_QA_USER_ID: "{KAREN_QA_USER_ID}"', self.workflow)
        self.assertIn(f'KAREN_QA_USER_LOGIN: "{KAREN_QA_USER_LOGIN}"', self.workflow)
        self.assertIn("commits/${HEAD_SHA}/statuses", self.workflow)
        self.assertIn("--statuses-json", self.workflow)
        self.assertNotIn("commits/${HEAD_SHA}/check-runs", self.workflow)
        self.assertNotIn("github.event.check_run.name == 'karen-qa'", self.workflow)
        self.assertIn(f"from ${{KAREN_QA_USER_LOGIN}} (${{KAREN_QA_USER_ID}})", self.workflow)

    def test_verifies_pr_author_and_actor_login_or_id(self) -> None:
        self.assertIn("--author-login", self.workflow)
        self.assertIn("--author-type", self.workflow)
        self.assertIn("--author-id", self.workflow)
        self.assertIn("--actor-login", self.workflow)
        self.assertIn("--actor-id", self.workflow)
        self.assertIn("--event-name", self.workflow)
        self.assertIn("ACTOR_LOGIN: ${{ github.actor }}", self.workflow)
        self.assertIn("ACTOR_ID: ${{ github.actor_id }}", self.workflow)
        self.assertIn(".user.id", self.workflow)
        self.assertNotIn("git author name", self.workflow.lower())

    def test_reads_head_and_files_consistently_and_rechecks_head(self) -> None:
        self.assertIn("Read the head SHA, then the file list, then re-check that the head is unchanged.", self.workflow)
        self.assertIn("pr-after-files.json", self.workflow)
        self.assertIn("OBSERVED_HEAD", self.workflow)
        self.assertIn("changed_files", self.workflow)
        self.assertIn("pulls/${PR_NUMBER}/commits", self.workflow)
        self.assertIn("git/trees/${HEAD_TREE_SHA}?recursive=1", self.workflow)
        self.assertIn("git/trees/${BASE_TREE_SHA}?recursive=1", self.workflow)
        self.assertIn("--observed-head-sha", self.workflow)

    def test_actions_are_pinned_and_permissions_are_minimal(self) -> None:
        self.assertRegex(self.workflow, r"(?m)^permissions:\s*\{\}\s*$")
        references = re.findall(r"(?m)^\s*uses:\s*([^#\s]+)", self.workflow)
        self.assertEqual(len(references), 1)
        self.assertRegex(references[0], r"^actions/checkout@[0-9a-f]{40}$")
        self.assertNotIn("setup-python", self.workflow)
        self.assertNotIn("pip install", self.workflow)
        self.assertNotIn("npm ", self.workflow)
        self.assertNotIn("secrets.", self.workflow)

    def test_documents_required_workflow_and_sync_branch_rulesets(self) -> None:
        self.assertIn("`karen-qa-or-data-only`", self.automation)
        self.assertIn("required workflow", self.automation)
        self.assertIn(str(KAREN_QA_OR_DATA_ONLY_WORKFLOW), self.automation)
        self.assertIn(str(KAREN_QA_USER_ID), self.automation)
        self.assertIn(KAREN_QA_USER_LOGIN, self.automation)
        self.assertIn(str(GITHUB_ACTIONS_BOT_ID), self.automation)
        self.assertIn("login/id", self.automation)
        self.assertIn("not a free-text git author", self.automation)
        self.assertIn("data/evidence/*.json", self.automation)
        self.assertIn("mcp_server.py", self.automation)
        self.assertIn(str(MAIN_GATE_RULESET), self.automation)
        self.assertIn(str(SYNC_BRANCH_RULESET), self.automation)
        self.assertIn(CVE_CATALOG_SYNC_BRANCH, self.automation)
        self.assertIn("Do not change live", self.automation)
        self.assertIn("rulesets from this pull request", self.automation)
        self.assertIn("from this pull request", self.automation)
        self.assertIn("CVE catalog data", self.automation)
        self.assertNotIn("Author does not matter", self.automation)
        self.assertNotIn("explicit CVE pipeline", self.automation)
        self.assertNotIn("pin `15368` so a plain commit status cannot satisfy", self.automation)
        self.assertNotIn("gh api --method PUT", self.workflow)
        self.assertNotIn("repos/${GITHUB_REPOSITORY}/rulesets", self.workflow)
        self.assertIn("5400051` is not a trusted", self.automation)
        self.assertNotIn("5400051", self.workflow)


class RulesetDefinitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.main_ruleset = json.loads(MAIN_RULESET_PATH.read_text(encoding="utf-8"))
        cls.sync_ruleset = json.loads(SYNC_RULESET_PATH.read_text(encoding="utf-8"))

    def test_main_gate_ruleset_requires_the_trusted_workflow_file(self) -> None:
        self.assertEqual(self.main_ruleset["name"], REQUIRED_CHECK_NAME)
        self.assertEqual(self.main_ruleset["target"], "branch")
        self.assertIn("refs/heads/main", self.main_ruleset["conditions"]["ref_name"]["include"])
        rules = self.main_ruleset["rules"]
        self.assertEqual([rule["type"] for rule in rules], ["workflows"])
        pin = rules[0]["parameters"]["workflows"][0]
        self.assertEqual(pin["path"], ".github/workflows/karen-qa-or-data-only.yml")
        self.assertEqual(pin["ref"], "refs/heads/main")
        self.assertEqual(pin["repository_id"], 1217516378)
        serialized = json.dumps(self.main_ruleset)
        self.assertNotIn('"integration_id": 15368', serialized)
        self.assertNotIn("required_status_checks", serialized)

    def test_sync_branch_ruleset_restricts_catalog_sync_branch(self) -> None:
        self.assertEqual(self.sync_ruleset["target"], "branch")
        self.assertIn(
            f"refs/heads/{CVE_CATALOG_SYNC_BRANCH}",
            self.sync_ruleset["conditions"]["ref_name"]["include"],
        )
        rule_types = {rule["type"] for rule in self.sync_ruleset["rules"]}
        self.assertTrue({"creation", "update", "deletion"}.issubset(rule_types))
        bypass = self.sync_ruleset["bypass_actors"]
        self.assertEqual(len(bypass), 1)
        self.assertEqual(bypass[0]["actor_id"], GITHUB_ACTIONS_APP_ID)
        self.assertEqual(bypass[0]["actor_type"], "Integration")
        self.assertEqual(bypass[0]["bypass_mode"], "always")


if __name__ == "__main__":
    unittest.main()
