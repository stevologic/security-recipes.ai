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

    def test_has_a_half_hourly_clock_and_can_be_dispatched(self) -> None:
        self.assertIn('cron: "7,37 * * * *"', self.workflow)
        self.assertRegex(self.workflow, r"(?m)^\s*workflow_dispatch:\s*$")
        self.assertNotRegex(self.workflow, r"(?m)^\s+(push|pull_request|pull_request_target):")
        self.assertIn("group: automation-shepherd", self.workflow)
        self.assertIn("cancel-in-progress: false", self.workflow)
        self.assertNotIn("gh workflow run automation-shepherd.yml", self.workflow)

    def test_chains_off_build_and_validation_completions(self) -> None:
        # GITHUB_TOKEN-dispatched completions do not emit workflow_run, so the
        # schedule and explicit kicks close that hole. workflow_run still
        # covers human- and Dependabot-triggered completions.
        self.assertIn("workflow_run:", self.workflow)
        self.assertIn("- Build", self.workflow)
        self.assertIn("- CVE catalog validation", self.workflow)
        self.assertIn("GITHUB_TOKEN itself dispatched do not emit", self.workflow)
        self.assertIn("workflow_run events", self.workflow)

    def test_reconciles_unbuilt_main_revisions_without_retry_storms(self) -> None:
        reconcile = self.workflow.split("- name: Reconcile the main branch Build", 1)[1]
        reconcile = reconcile.split("- name: Shepherd auto-merge pull requests", 1)[0]

        self.assertIn('.path == ".github/workflows/build.yml"', reconcile)
        self.assertIn("gh workflow run build.yml", reconcile)
        self.assertIn('--field "expected_sha=${MAIN_SHA}"', reconcile)
        self.assertIn('[ "$TOTAL_RUNS" -ge 2 ]', reconcile)
        self.assertIn("leaving it to AI maintenance", reconcile)

    def test_reconciles_unbuilt_development_revisions(self) -> None:
        reconcile = self.workflow.split(
            "- name: Reconcile the development branch Build", 1
        )[1]
        reconcile = reconcile.split("- name: Shepherd auto-merge pull requests", 1)[0]

        self.assertIn("git/ref/heads/development", reconcile)
        self.assertIn('.head_branch == "development"', reconcile)
        self.assertIn("--ref development", reconcile)
        self.assertIn('--field "expected_sha=${DEV_SHA}"', reconcile)

    def test_shepherds_only_same_repo_auto_merge_prs(self) -> None:
        shepherd = self.workflow.split("- name: Shepherd auto-merge pull requests", 1)[1]

        self.assertIn("select(.isCrossRepository == false)", shepherd)
        self.assertIn("select(.autoMergeRequest != null)", shepherd)
        self.assertIn('SYNC_BRANCH="automation/cve-catalog-sync"', shepherd)
        self.assertIn("the catalog sync manages its own delivery", shepherd)
        self.assertIn("pulls/${PR_NUMBER}/update-branch", shepherd)
        self.assertIn("expected_head_sha=${HEAD_SHA}", shepherd)
        self.assertIn('[ "$MERGE_STATE" = "DIRTY" ]', shepherd)
        # A token update-branch emits no events, so the same pass must adopt
        # the new head and continue to the validation logic.
        self.assertIn('HEAD_SHA="$UPDATED_SHA"', shepherd)
        self.assertLess(
            shepherd.index('HEAD_SHA="$UPDATED_SHA"'),
            shepherd.index("gh workflow run cve-catalog-validate.yml"),
        )

    def test_dispatches_validation_only_when_the_build_context_is_absent(self) -> None:
        shepherd = self.workflow.split("- name: Shepherd auto-merge pull requests", 1)[1]

        self.assertIn('select(.name == "build")', shepherd)
        self.assertIn('select(.context == "build")', shepherd)
        self.assertIn("gh workflow run cve-catalog-validate.yml", shepherd)
        self.assertIn('--field "expected_sha=${HEAD_SHA}"', shepherd)
        self.assertIn('--field "pr_number=${PR_NUMBER}"', shepherd)
        self.assertIn('--field "expected_branch=${HEAD_BRANCH}"', shepherd)
        self.assertNotIn("PENDING_REQUESTS", shepherd)
        self.assertNotIn("cve-catalog-validate-request.yml", shepherd)
        self.assertIn("PENDING_VALIDATIONS", shepherd)
        self.assertIn("--workflow cve-catalog-validate.yml", shepherd)
        self.assertIn(r'endswith(\"@ ${HEAD_SHA}\")', shepherd)
        self.assertLess(
            shepherd.index("PENDING_VALIDATIONS"),
            shepherd.index("gh workflow run cve-catalog-validate.yml"),
        )

    def test_never_merges_directly_or_checks_out_code(self) -> None:
        self.assertNotIn("pulls/${PR_NUMBER}/merge", self.workflow)
        self.assertNotIn("gh pr merge", self.workflow)
        self.assertNotIn("actions/checkout", self.workflow)
        self.assertNotIn("git push", self.workflow)
        # Without a checkout there is no git directory, so every gh command
        # needs an explicit repository context.
        self.assertEqual(
            self.workflow.count("GH_REPO: ${{ github.repository }}"),
            4,
        )

    def test_drains_dirty_or_stale_content_refresh_prs(self) -> None:
        drain = self.workflow.split(
            "- name: Drain stale content-refresh pull requests", 1
        )[1]
        drain = drain.split("- name: Shepherd auto-merge pull requests", 1)[0]

        self.assertIn('--label "automation:content-refresh"', drain)
        self.assertIn("[ \"$MERGE_STATE\" != \"DIRTY\" ]", drain)
        self.assertIn("[ \"$AGE_DAYS\" -lt 5 ]", drain)
        self.assertIn("gh pr comment", drain)
        self.assertIn("re-derive the change from current sources", drain)
        self.assertIn("gh pr close", drain)
        self.assertIn('SYNC_BRANCH="automation/cve-catalog-sync"', drain)
        self.assertNotIn("gh workflow run automation-shepherd.yml", drain)

    def test_actions_are_pinned_to_full_commit_shas(self) -> None:
        references = re.findall(r"(?m)^\s*uses:\s*([^#\s]+)", self.workflow)

        self.assertEqual(references, [])


if __name__ == "__main__":
    unittest.main()
