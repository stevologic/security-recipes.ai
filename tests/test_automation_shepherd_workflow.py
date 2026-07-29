from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "automation-shepherd.yml"


class AutomationShepherdWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_runs_twice_hourly_and_can_be_dispatched(self) -> None:
        self.assertIn('- cron: "7,37 * * * *"', self.workflow)
        self.assertRegex(self.workflow, r"(?m)^\s*workflow_dispatch:\s*$")
        self.assertNotRegex(self.workflow, r"(?m)^\s+(push|pull_request|pull_request_target):")

    def test_reconciles_unbuilt_main_revisions_without_retry_storms(self) -> None:
        reconcile = self.workflow.split("- name: Reconcile the main branch Build", 1)[1]
        reconcile = reconcile.split("- name: Shepherd auto-merge pull requests", 1)[0]

        self.assertIn('.path == ".github/workflows/build.yml"', reconcile)
        self.assertIn("gh workflow run build.yml", reconcile)
        self.assertIn('--field "expected_sha=${MAIN_SHA}"', reconcile)
        self.assertIn('[ "$TOTAL_RUNS" -ge 2 ]', reconcile)
        self.assertIn("leaving it to AI maintenance", reconcile)

    def test_shepherds_only_same_repo_auto_merge_prs(self) -> None:
        shepherd = self.workflow.split("- name: Shepherd auto-merge pull requests", 1)[1]

        self.assertIn("select(.isCrossRepository == false)", shepherd)
        self.assertIn("select(.autoMergeRequest != null)", shepherd)
        self.assertIn('SYNC_BRANCH="automation/cve-catalog-sync"', shepherd)
        self.assertIn("the catalog sync manages its own delivery", shepherd)
        self.assertIn("pulls/${PR_NUMBER}/update-branch", shepherd)
        self.assertIn("expected_head_sha=${HEAD_SHA}", shepherd)
        self.assertIn('[ "$MERGE_STATE" = "DIRTY" ]', shepherd)

    def test_dispatches_validation_only_when_the_build_context_is_absent(self) -> None:
        shepherd = self.workflow.split("- name: Shepherd auto-merge pull requests", 1)[1]

        self.assertIn('select(.name == "build")', shepherd)
        self.assertIn('select(.context == "build")', shepherd)
        self.assertIn("gh workflow run cve-catalog-validate.yml", shepherd)
        self.assertIn('--field "expected_sha=${HEAD_SHA}"', shepherd)
        self.assertIn('--field "pr_number=${PR_NUMBER}"', shepherd)
        self.assertIn('--field "expected_branch=${HEAD_BRANCH}"', shepherd)
        self.assertIn("PENDING_VALIDATIONS", shepherd)
        self.assertLess(
            shepherd.index("PENDING_VALIDATIONS"),
            shepherd.index("gh workflow run cve-catalog-validate.yml"),
        )

    def test_never_merges_directly_or_checks_out_code(self) -> None:
        self.assertNotIn("pulls/${PR_NUMBER}/merge", self.workflow)
        self.assertNotIn("gh pr merge", self.workflow)
        self.assertNotIn("actions/checkout", self.workflow)
        self.assertNotIn("git push", self.workflow)

    def test_actions_are_pinned_to_full_commit_shas(self) -> None:
        references = re.findall(r"(?m)^\s*uses:\s*([^#\s]+)", self.workflow)

        self.assertEqual(references, [])


if __name__ == "__main__":
    unittest.main()
