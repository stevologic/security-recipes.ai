from __future__ import annotations

import re
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from tests.cve_sync_harness import (
    FALLBACK_LABEL,
    HarnessResult,
    load_workflow,
    run_merge_job,
    step_named,
)
from tests.cve_sync_mutants.mutants import MUTANTS


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SECRET_KEY = "TEST-APP-PRIVATE-KEY-DO-NOT-ECHO"
SECRET_TOKEN = "TEST-APP-TOKEN-DO-NOT-ECHO"
GITHUB_TOKEN = "github-token"


class CveSyncMergeHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = load_workflow()

    def assert_no_secret_echo(self, result: HarnessResult) -> None:
        blob = result.stdout + result.stderr + result.github_output
        self.assertNotIn(SECRET_KEY, blob)
        self.assertNotIn(SECRET_TOKEN, blob)
        self.assertNotIn('echo "$APP_TOKEN"', self.workflow)
        self.assertNotIn('echo "$GH_TOKEN"', self.workflow)
        self.assertNotIn('echo "$APP_PRIVATE_KEY"', self.workflow)

    def test_missing_app_run1_dispatches_validate_skips_merge_and_labels(self) -> None:
        result = run_merge_job(self.workflow)
        self.assertEqual(
            result.stage,
            "delivery",
            f"missing App run 1 expected to reach delivery, stopped at {result.stage}",
        )
        self.assertEqual(result.detect_outputs.get("app_configured"), "false")
        self.assertEqual(result.detect_outputs.get("credential_status"), "missing")
        self.assertTrue(
            result.dispatched_validate,
            "missing App run 1 must dispatch cve-catalog-validate.yml so build attaches",
        )
        self.assertEqual(
            result.merge_calls,
            [],
            f"missing App must not call the merge API, got {result.merge_calls!r}",
        )
        self.assertIn(FALLBACK_LABEL, result.labels_added)
        self.assertEqual(result.outputs.get("protection_fallback"), "true")
        self.assertIn("GitHub App is not configured", result.stdout)
        self.assertIn(
            "Required build check is attached by dispatching cve-catalog-validate.yml",
            result.stdout,
            "missing App run 1 must emit the report_protection_fallback notice, "
            "not only the require-step notice",
        )
        self.assertIn("merge was not attempted without the App", result.stdout)
        self.assertIn("18147261", result.stdout)
        self.assertNotIn("::error::", result.stdout)
        self.assertEqual(
            result.returncode,
            0,
            "missing App run 1 expected exit 0 after validate dispatch and skipped merge, "
            f"got {result.returncode}: {result.stdout}\n{result.stderr}",
        )
        self.assertEqual(result.dispatch_ref, "automation/cve-catalog-sync")
        self.assertRegex(result.dispatch_expected_sha, SHA_RE)
        self.assertEqual(result.dispatch_expected_sha, result.head_sha)
        self.assert_no_secret_echo(result)

    def test_missing_app_validate_dispatch_pins_exact_sha_on_pr_branch(self) -> None:
        result = run_merge_job(self.workflow)
        self.assertTrue(
            result.dispatched_validate,
            "validate dispatch must run so the exact-SHA field can be inspected",
        )
        self.assertEqual(
            result.dispatch_ref,
            "automation/cve-catalog-sync",
            f"validate dispatch --ref actual={result.dispatch_ref!r} expected=automation/cve-catalog-sync",
        )
        self.assertNotEqual(result.dispatch_ref, "main")
        self.assertTrue(result.workflow_runs, "validate workflow run was not recorded")
        fields = result.workflow_runs[0].get("fields") or {}
        self.assertIn(
            "expected_sha",
            fields,
            f"validate dispatch omitted expected_sha; fields={fields!r}",
        )
        self.assertRegex(
            result.dispatch_expected_sha,
            SHA_RE,
            f"validate dispatch expected_sha actual={result.dispatch_expected_sha!r} expected=40-char SHA",
        )
        self.assertEqual(fields.get("expected_sha"), result.head_sha)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_app_expected_sha_falls_back_to_sync_head(self) -> None:
        result = run_merge_job(self.workflow)
        delivery = step_named(self.workflow, "Reconcile, validate, and merge exact catalog revision")
        env = delivery.get("env")
        self.assertIsInstance(env, dict)
        expr = str(env.get("EXPECTED_SHA") or "")
        self.assertIn("needs.sync.outputs.head_sha", expr)
        self.assertIn("||", expr)
        self.assertEqual(result.expected_sha, result.head_sha)
        self.assertRegex(result.expected_sha, SHA_RE)
        self.assertTrue(result.dispatched_validate)
        self.assertEqual(result.dispatch_expected_sha, result.head_sha)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_app_run2_escalates_after_dispatch(self) -> None:
        labeled_at = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        result = run_merge_job(
            self.workflow,
            labels=[FALLBACK_LABEL],
            labeled_at=labeled_at,
        )
        self.assertEqual(result.stage, "delivery")
        self.assertTrue(
            result.dispatched_validate,
            "run 2 must still dispatch cve-catalog-validate.yml before escalating",
        )
        self.assertEqual(result.merge_calls, [])
        self.assertEqual(
            result.returncode,
            1,
            "missing App run 2 expected exit 1 after dispatch+escalation, "
            f"got {result.returncode}: {result.stdout}\n{result.stderr}",
        )
        self.assertIn("2 consecutive", result.stdout)
        self.assertIn("::error::", result.stdout)
        self.assertEqual(result.outputs.get("protection_fallback"), "true")
        self.assert_no_secret_echo(result)

    def test_missing_app_24h_escalates_after_dispatch(self) -> None:
        labeled_at = (datetime.now(timezone.utc) - timedelta(hours=24, minutes=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        result = run_merge_job(self.workflow, labeled_at=labeled_at)
        self.assertTrue(
            result.dispatched_validate,
            "24h escalation must still dispatch cve-catalog-validate.yml first",
        )
        self.assertEqual(result.merge_calls, [])
        self.assertEqual(
            result.returncode,
            1,
            "missing App 24h expected exit 1 after dispatch+escalation, "
            f"got {result.returncode}: {result.stdout}\n{result.stderr}",
        )
        self.assertIn("older than 24h", result.stdout)
        self.assertEqual(result.outputs.get("protection_fallback"), "true")

    def test_missing_app_does_not_escalate_at_23h59m(self) -> None:
        labeled_at = (datetime.now(timezone.utc) - timedelta(hours=23, minutes=59)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        result = run_merge_job(self.workflow, labeled_at=labeled_at)
        self.assertTrue(result.dispatched_validate)
        self.assertEqual(result.merge_calls, [])
        self.assertEqual(
            result.returncode,
            0,
            "missing App at 23h59m expected exit 0, "
            f"got {result.returncode}: {result.stdout}\n{result.stderr}",
        )
        self.assertNotIn("older than 24h", result.stdout)
        self.assertEqual(result.outputs.get("protection_fallback"), "true")

    def test_id_only_credentials_fail_closed_before_delivery(self) -> None:
        result = run_merge_job(self.workflow, app_id="12345")
        self.assertEqual(result.stage, "require")
        self.assertEqual(result.detect_outputs.get("app_configured"), "false")
        self.assertEqual(result.detect_outputs.get("credential_status"), "incomplete")
        self.assertEqual(
            result.returncode,
            1,
            "ID-only credentials expected exit 1 before delivery, "
            f"got {result.returncode}: {result.stdout}\n{result.stderr}",
        )
        self.assertFalse(result.dispatched_validate)
        self.assertEqual(result.merge_calls, [])
        self.assertIn("incomplete", result.stdout)
        self.assertIn("::error::", result.stdout)
        self.assertNotIn("merge was not attempted without the App", result.stdout)

    def test_key_only_credentials_fail_closed_before_delivery(self) -> None:
        result = run_merge_job(self.workflow, app_private_key=SECRET_KEY)
        self.assertEqual(result.stage, "require")
        self.assertEqual(result.detect_outputs.get("app_configured"), "false")
        self.assertEqual(result.detect_outputs.get("credential_status"), "incomplete")
        self.assertEqual(
            result.returncode,
            1,
            "KEY-only credentials expected exit 1 before delivery, "
            f"got {result.returncode}: {result.stdout}\n{result.stderr}",
        )
        self.assertFalse(result.dispatched_validate)
        self.assertEqual(result.merge_calls, [])
        self.assertIn("incomplete", result.stdout)
        self.assertIn("::error::", result.stdout)
        self.assert_no_secret_echo(result)

    def test_incomplete_credentials_fail_closed_before_delivery(self) -> None:
        id_only = run_merge_job(self.workflow, app_id="12345")
        key_only = run_merge_job(self.workflow, app_private_key=SECRET_KEY)
        for label, result in (("id-only", id_only), ("key-only", key_only)):
            with self.subTest(credentials=label):
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(result.stage, "require")
                self.assertFalse(result.dispatched_validate)
                self.assertEqual(result.detect_outputs.get("credential_status"), "incomplete")

    def test_configured_app_uses_app_token_and_can_merge(self) -> None:
        result = run_merge_job(
            self.workflow,
            app_id="12345",
            app_private_key=SECRET_KEY,
            app_token=SECRET_TOKEN,
        )
        self.assertEqual(result.detect_outputs.get("app_configured"), "true")
        self.assertEqual(
            result.returncode,
            0,
            "configured App expected exit 0 after merge, "
            f"got {result.returncode}: {result.stdout}\n{result.stderr}",
        )
        self.assertTrue(result.dispatched_validate)
        self.assertEqual(result.dispatch_token, SECRET_TOKEN)
        self.assertEqual(len(result.merge_calls), 1)
        self.assertEqual(result.merge_calls[0].get("token"), SECRET_TOKEN)
        self.assertNotEqual(result.merge_calls[0].get("token"), GITHUB_TOKEN)
        self.assertNotIn(FALLBACK_LABEL, result.labels_added)
        self.assertNotEqual(result.outputs.get("protection_fallback"), "true")
        self.assert_no_secret_echo(result)

    def test_configured_app_empty_token_fails_closed(self) -> None:
        result = run_merge_job(
            self.workflow,
            app_id="12345",
            app_private_key=SECRET_KEY,
            app_token="",
        )
        self.assertEqual(result.detect_outputs.get("app_configured"), "true")
        self.assertEqual(
            result.returncode,
            1,
            "configured App with empty APP_TOKEN expected exit 1, "
            f"got {result.returncode}: {result.stdout}\n{result.stderr}",
        )
        self.assertFalse(result.dispatched_validate)
        self.assertEqual(result.merge_calls, [])
        self.assertIn("no App token was minted", result.stdout)
        self.assertIn("::error::", result.stdout)

    def test_merge_job_actions_permission_is_write(self) -> None:
        merge = yaml.safe_load(self.workflow)["jobs"]["merge"]
        self.assertEqual(merge["permissions"]["actions"], "write")
        self.assertNotEqual(merge["permissions"]["actions"], "read")

    def test_disk_mutants_are_not_vacuous(self) -> None:
        for mutant_id, relative, old, new in MUTANTS:
            with self.subTest(mutant=mutant_id):
                text = (Path(__file__).resolve().parents[1] / relative).read_text(
                    encoding="utf-8"
                )
                self.assertIn(old, text, f"{mutant_id} old text missing from {relative}")
                self.assertEqual(text.count(old), 1, f"{mutant_id} old text is not unique")
                self.assertNotEqual(old, new, f"{mutant_id} replacement is identical")


if __name__ == "__main__":
    unittest.main()
