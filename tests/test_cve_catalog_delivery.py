from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.cve_catalog_delivery import (
    FALLBACK_LABEL,
    can_reuse_in_run_validation,
    classify_merge_error,
    classify_pr_state,
    is_alert_action,
    main as delivery_main,
    policy_for_catalog_pr,
    self_merge_gate,
    validation_ref,
)


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "cve-catalog-sync.yml"
AUTOMATION = ROOT / ".github" / "AUTOMATION.md"

SHA = "0a7e0100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
OTHER = "cccccccccccccccccccccccccccccccccccccccc"


def pr_payload(
    *,
    state: str = "open",
    merged: bool = False,
    head_sha: str = SHA,
    head_branch: str = "automation/cve-catalog-sync",
    base_branch: str = "main",
    repo: str = "stevologic/security-recipes.ai",
) -> dict[str, object]:
    return {
        "state": state,
        "merged": merged,
        "head": {"sha": head_sha, "ref": head_branch, "repo": {"full_name": repo}},
        "base": {"ref": base_branch},
    }


class CveCatalogDeliveryTests(unittest.TestCase):
    def test_data_only_policy_skips_karen_qa_and_allows_token_merge(self) -> None:
        policy = policy_for_catalog_pr(data_only=True, sha_matches=True, app_configured=False)
        self.assertTrue(policy.skip_karen_qa)
        self.assertTrue(policy.attach_build_check_on_pr_head)
        self.assertTrue(policy.protection_fallback)
        self.assertTrue(policy.merge_with_workflow_token)
        self.assertEqual(policy.action, "validate_and_merge")
        self.assertFalse(is_alert_action(policy.action))

    def test_data_only_with_app_still_skips_karen_qa(self) -> None:
        policy = policy_for_catalog_pr(data_only=True, sha_matches=True, app_configured=True)
        self.assertTrue(policy.skip_karen_qa)
        self.assertFalse(policy.attach_build_check_on_pr_head)
        self.assertTrue(policy.protection_fallback)

    def test_non_data_only_fails_closed(self) -> None:
        policy = policy_for_catalog_pr(data_only=False, sha_matches=True, app_configured=False)
        self.assertEqual(policy.action, "fail_closed_not_data_only")
        self.assertFalse(policy.skip_karen_qa)
        self.assertFalse(policy.protection_fallback)
        self.assertTrue(is_alert_action(policy.action))
        self.assertIn("karen-qa and real workflow checks", policy.message)

    def test_sha_mismatch_fails_closed(self) -> None:
        policy = policy_for_catalog_pr(data_only=True, sha_matches=False, app_configured=False)
        self.assertEqual(policy.action, "fail_closed_sha_mismatch")
        self.assertTrue(is_alert_action(policy.action))

    def test_already_merged_pr_is_idempotent_success(self) -> None:
        action = classify_pr_state(
            state="closed",
            merged=True,
            head_repository="stevologic/security-recipes.ai",
            head_branch="automation/cve-catalog-sync",
            head_sha=SHA,
            base_branch="main",
            expected_repository="stevologic/security-recipes.ai",
            expected_branch="automation/cve-catalog-sync",
            expected_sha=SHA,
            expected_base="main",
        )
        self.assertEqual(action, "already_merged")
        self.assertFalse(is_alert_action(action))

    def test_merged_at_a_different_head_is_still_idempotent(self) -> None:
        action = classify_pr_state(
            state="closed",
            merged=True,
            head_repository="stevologic/security-recipes.ai",
            head_branch="automation/cve-catalog-sync",
            head_sha=OTHER,
            base_branch="main",
            expected_repository="stevologic/security-recipes.ai",
            expected_branch="automation/cve-catalog-sync",
            expected_sha=SHA,
            expected_base="main",
        )
        self.assertEqual(action, "already_merged")

    def test_moved_head_retries_instead_of_alerting(self) -> None:
        action = classify_pr_state(
            state="open",
            merged=False,
            head_repository="stevologic/security-recipes.ai",
            head_branch="automation/cve-catalog-sync",
            head_sha=OTHER,
            base_branch="main",
            expected_repository="stevologic/security-recipes.ai",
            expected_branch="automation/cve-catalog-sync",
            expected_sha=SHA,
            expected_base="main",
        )
        self.assertEqual(action, "head_moved")
        self.assertFalse(is_alert_action(action))

    def test_existing_open_pr_at_expected_sha_is_current(self) -> None:
        action = classify_pr_state(
            state="open",
            merged=False,
            head_repository="stevologic/security-recipes.ai",
            head_branch="automation/cve-catalog-sync",
            head_sha=SHA,
            base_branch="main",
            expected_repository="stevologic/security-recipes.ai",
            expected_branch="automation/cve-catalog-sync",
            expected_sha=SHA,
            expected_base="main",
        )
        self.assertEqual(action, "current")

    def test_identity_change_fails_closed(self) -> None:
        action = classify_pr_state(
            state="open",
            merged=False,
            head_repository="evil/fork",
            head_branch="automation/cve-catalog-sync",
            head_sha=SHA,
            base_branch="main",
            expected_repository="stevologic/security-recipes.ai",
            expected_branch="automation/cve-catalog-sync",
            expected_sha=SHA,
            expected_base="main",
        )
        self.assertEqual(action, "identity_changed")
        self.assertTrue(is_alert_action(action))

    def test_revalidated_sha_reuses_only_this_run_validation(self) -> None:
        self.assertTrue(
            can_reuse_in_run_validation(
                in_run_validation_passed=True,
                validated_sha=SHA,
                expected_sha=SHA,
            )
        )
        self.assertFalse(
            can_reuse_in_run_validation(
                in_run_validation_passed=True,
                validated_sha=SHA,
                expected_sha=OTHER,
            )
        )
        self.assertFalse(
            can_reuse_in_run_validation(
                in_run_validation_passed=False,
                validated_sha=SHA,
                expected_sha=SHA,
            )
        )

    def test_author_only_match_with_non_data_path_fails_closed(self) -> None:
        gate = self_merge_gate(
            data_only=False,
            sha_matches=True,
            in_run_validation_passed=True,
            validated_sha=SHA,
            head_branch="automation/cve-catalog-sync",
            head_sha=SHA,
            pushed_sha=SHA,
            sync_branch="automation/cve-catalog-sync",
            author="github-actions[bot]",
        )
        self.assertFalse(gate.allowed)
        self.assertFalse(gate.used_author)
        self.assertEqual(gate.action, "fail_closed_not_data_only")
        self.assertTrue(is_alert_action(gate.action))
        self.assertIn("author identity is ignored", gate.message)

    def test_self_merge_requires_in_run_validation_and_pushed_sha(self) -> None:
        allowed = self_merge_gate(
            data_only=True,
            sha_matches=True,
            in_run_validation_passed=True,
            validated_sha=SHA,
            head_branch="automation/cve-catalog-sync",
            head_sha=SHA,
            pushed_sha=SHA,
            sync_branch="automation/cve-catalog-sync",
            author="github-actions[bot]",
        )
        self.assertTrue(allowed.allowed)
        self.assertFalse(allowed.used_author)
        missing_validation = self_merge_gate(
            data_only=True,
            sha_matches=True,
            in_run_validation_passed=False,
            validated_sha="",
            head_branch="automation/cve-catalog-sync",
            head_sha=SHA,
            pushed_sha=SHA,
            sync_branch="automation/cve-catalog-sync",
            author="github-actions[bot]",
        )
        self.assertFalse(missing_validation.allowed)
        self.assertEqual(missing_validation.action, "fail_closed_missing_in_run_validation")
        moved = self_merge_gate(
            data_only=True,
            sha_matches=True,
            in_run_validation_passed=True,
            validated_sha=SHA,
            head_branch="automation/cve-catalog-sync",
            head_sha=OTHER,
            pushed_sha=SHA,
            sync_branch="automation/cve-catalog-sync",
            author="github-actions[bot]",
        )
        self.assertFalse(moved.allowed)
        self.assertEqual(moved.action, "fail_closed_head_mismatch")

    def test_data_only_without_app_dispatches_validation_on_pr_head(self) -> None:
        self.assertEqual(
            validation_ref(
                data_only=True,
                app_configured=False,
                default_branch="main",
                pr_branch="automation/cve-catalog-sync",
            ),
            "automation/cve-catalog-sync",
        )
        self.assertEqual(
            validation_ref(
                data_only=True,
                app_configured=True,
                default_branch="main",
                pr_branch="automation/cve-catalog-sync",
            ),
            "main",
        )

    def test_protection_block_on_data_only_is_fallback_not_alert(self) -> None:
        action = classify_merge_error(
            data_only=True,
            error_text="Required status check 'build' is expected and failed rule violations",
        )
        self.assertEqual(action, "protection_fallback")
        self.assertFalse(is_alert_action(action))
        karen = classify_merge_error(
            data_only=True,
            error_text="Required status check karen-qa is expected",
        )
        self.assertEqual(karen, "protection_fallback")
        self.assertFalse(is_alert_action(karen))

    def test_protection_block_on_non_data_only_fails_closed(self) -> None:
        action = classify_merge_error(
            data_only=False,
            error_text="Required status check 'build' is expected; required checks must come from real workflow runs",
        )
        self.assertEqual(action, "fail_closed_real_checks")
        self.assertTrue(is_alert_action(action))
        karen = classify_merge_error(data_only=False, error_text="needs karen-qa")
        self.assertEqual(karen, "wait_karen_qa")
        self.assertFalse(is_alert_action(karen))

    def test_unexpected_merge_error_alerts(self) -> None:
        action = classify_merge_error(data_only=True, error_text="HTTP 500 boom")
        self.assertEqual(action, "fail_unexpected")
        self.assertTrue(is_alert_action(action))

    def test_pr_state_cli_reads_json_file_for_existing_and_merged_prs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "pr.json"
            path.write_text(json.dumps(pr_payload(merged=True, state="closed")), encoding="utf-8")
            self.assertEqual(
                delivery_main(
                    [
                        "pr-state",
                        "--pr-json-file",
                        str(path),
                        "--expected-repository",
                        "stevologic/security-recipes.ai",
                        "--expected-branch",
                        "automation/cve-catalog-sync",
                        "--expected-sha",
                        SHA,
                        "--expected-base",
                        "main",
                    ]
                ),
                0,
            )

    def test_workflow_wires_fallback_label_concurrency_and_build_dispatch_on_pr_head(
        self,
    ) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(FALLBACK_LABEL, workflow)
        self.assertIn("group: cve-catalog-sync", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("scripts/cve_catalog_data_paths.py", workflow)
        self.assertIn("scripts/cve_catalog_delivery.py", workflow)
        self.assertIn('--ref "$VALIDATION_REF"', workflow)
        self.assertIn("self-merge-gate", workflow)
        self.assertIn("reuse-in-run-validation", workflow)
        self.assertIn("Never gate self-merge on github-actions[bot]", workflow)
        self.assertNotIn("reuse-build-check", workflow)
        self.assertIn("protection_fallback=true", workflow)
        self.assertIn("data/cve/enrichment-carryover.json", workflow)
        automation = AUTOMATION.read_text(encoding="utf-8")
        self.assertIn("data-only", automation)
        self.assertIn("enrichment-carryover.json", automation)


if __name__ == "__main__":
    unittest.main()
