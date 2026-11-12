from __future__ import annotations

import re
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from tests.cve_sync_harness import (
    DELIVERY_STEP,
    DETECT_STEP,
    FALLBACK_LABEL,
    REQUIRE_STEP,
    HarnessResult,
    apply_step_outputs,
    build_expression_context,
    load_workflow,
    render_github_value,
    rendered_step_env,
    run_merge_job,
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
        self.assertEqual(result.dispatch_token, GITHUB_TOKEN)
        self.assert_no_secret_echo(result)

    def test_missing_app_delivery_uses_github_token_not_app_token(self) -> None:
        result = run_merge_job(self.workflow)
        self.assertTrue(
            result.dispatched_validate,
            "missing App delivery must reach validate dispatch so GH_TOKEN can be inspected",
        )
        self.assertEqual(
            result.dispatch_token,
            GITHUB_TOKEN,
            f"missing App dispatch token actual={result.dispatch_token!r} "
            f"expected={GITHUB_TOKEN!r}",
        )
        self.assertNotEqual(result.dispatch_token, "")
        self.assertNotEqual(result.dispatch_token, SECRET_TOKEN)
        tokens = [str(call.get("gh_token") or "") for call in result.gh_calls]
        self.assertTrue(tokens, "missing App delivery must call gh")
        self.assertTrue(
            all(token == GITHUB_TOKEN for token in tokens),
            f"missing App gh calls must use github.token, got {tokens!r}",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_app_delivery_pr_number_comes_from_sync(self) -> None:
        result = run_merge_job(self.workflow, pr_number=475)
        self.assertTrue(
            result.dispatched_validate,
            "missing App delivery must dispatch so PR_NUMBER can be inspected",
        )
        fields = result.workflow_runs[0].get("fields") or {}
        self.assertEqual(
            fields.get("pr_number"),
            "475",
            f"validate dispatch pr_number actual={fields.get('pr_number')!r} expected='475'",
        )
        self.assertNotEqual(fields.get("pr_number"), result.head_sha)
        blobs = [
            " ".join(str(part) for part in call.get("argv") or [])
            for call in result.gh_calls
        ]
        self.assertTrue(
            any("pulls/475" in blob for blob in blobs),
            f"delivery must target PR 475, got {blobs!r}",
        )
        self.assertFalse(
            any(f"pulls/{result.head_sha}" in blob for blob in blobs),
            "delivery must not treat the sync head SHA as PR_NUMBER, "
            f"got {blobs!r}",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

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
        # App-commit is skipped, so its output is empty. Dispatch must still
        # carry the sync head SHA from the EXPECTED_SHA || fallback.
        result = run_merge_job(self.workflow)
        self.assertEqual(result.detect_outputs.get("app_configured"), "false")
        self.assertTrue(
            result.dispatched_validate,
            "missing App with empty app-commit output must still dispatch validate",
        )
        self.assertRegex(
            result.dispatch_expected_sha,
            SHA_RE,
            "validate dispatch expected_sha must be the 40-char sync head, "
            f"got {result.dispatch_expected_sha!r}",
        )
        self.assertEqual(
            result.dispatch_expected_sha,
            result.head_sha,
            "empty app-commit output must fall back to the sync head SHA on dispatch",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_app_skips_mint_and_attribute(self) -> None:
        result = run_merge_job(self.workflow)
        self.assertEqual(result.detect_outputs.get("app_configured"), "false")
        self.assertEqual(
            result.mint_calls,
            [],
            f"mint step must not run without the App, got {result.mint_calls!r}",
        )
        self.assertEqual(
            result.attribute_calls,
            [],
            f"attribute step must not run without the App, got {result.attribute_calls!r}",
        )
        self.assertTrue(result.dispatched_validate)
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
        self.assertTrue(result.mint_calls, "configured App must mint an App token")
        self.assertTrue(result.attribute_calls, "configured App must attribute the catalog revision")
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


class CveSyncHarnessEnvRenderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = load_workflow()
        self.ctx = build_expression_context(
            self.workflow,
            app_id="12345",
            app_private_key=SECRET_KEY,
            github_token=GITHUB_TOKEN,
            auto_merge_enabled="true",
            pr_number=475,
            head_sha="a" * 40,
        )
        self.plumbing = {"PATH": "/bin"}

    def test_unknown_expression_fails_loudly(self) -> None:
        with self.assertRaises(AssertionError) as cm:
            render_github_value("${{ secrets.NOT_A_REAL_SECRET }}", self.ctx)
        self.assertIn("unresolved GitHub expression", str(cm.exception))

    def test_unsupported_function_expression_fails_loudly(self) -> None:
        with self.assertRaises(AssertionError) as cm:
            render_github_value("${{ fromJSON(secrets.FOO) }}", self.ctx)
        self.assertIn("unresolved GitHub expression", str(cm.exception))

    def test_or_expr_uses_first_nonempty(self) -> None:
        self.assertEqual(
            render_github_value(
                "${{ steps.app-commit.outputs.head_sha || needs.sync.outputs.head_sha }}",
                self.ctx,
            ),
            "a" * 40,
        )

    def test_detect_env_comes_from_yaml_vars_and_secrets(self) -> None:
        env = rendered_step_env(self.workflow, DETECT_STEP, self.ctx, self.plumbing)
        self.assertEqual(env["APP_ID"], "12345")
        self.assertEqual(env["APP_PRIVATE_KEY"], SECRET_KEY)
        self.assertNotIn("CREDENTIAL_STATUS", env)
        self.assertNotIn("APP_CONFIGURED", env)
        self.assertNotIn("GH_TOKEN", env)

    def test_require_env_comes_from_detect_outputs(self) -> None:
        apply_step_outputs(
            self.ctx, "automation-auth", {"credential_status": "incomplete"}
        )
        env = rendered_step_env(self.workflow, REQUIRE_STEP, self.ctx, self.plumbing)
        self.assertEqual(env["CREDENTIAL_STATUS"], "incomplete")

    def test_delivery_env_comes_from_yaml_contexts(self) -> None:
        apply_step_outputs(
            self.ctx, "automation-auth", {"app_configured": "false"}
        )
        env = rendered_step_env(self.workflow, DELIVERY_STEP, self.ctx, self.plumbing)
        self.assertEqual(env["APP_CONFIGURED"], "false")
        self.assertEqual(env["AUTO_MERGE_ENABLED"], "true")
        self.assertEqual(env["BRANCH"], "automation/cve-catalog-sync")
        self.assertEqual(env["EXPECTED_SHA"], "a" * 40)
        self.assertEqual(env["GITHUB_DEFAULT_BRANCH"], "main")
        self.assertEqual(env["APP_TOKEN"], "")
        self.assertEqual(env["GH_TOKEN"], GITHUB_TOKEN)
        self.assertEqual(env["PR_NUMBER"], "475")
        self.assertNotIn("APP_ID", env)

    def test_rendered_step_env_rejects_non_plumbing_keys(self) -> None:
        with self.assertRaises(AssertionError) as cm:
            rendered_step_env(
                self.workflow,
                DETECT_STEP,
                self.ctx,
                {"PATH": "/bin", "GH_TOKEN": "injected"},
            )
        self.assertIn("non-plumbing", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
