from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "cve-catalog-sync.yml"


class CveSyncWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    def step(self, name: str) -> str:
        match = re.search(
            rf"(?ms)^\s{{6}}- name: {re.escape(name)}\s*$"
            rf"(.*?)(?=^\s{{6}}- name: |\Z)",
            self.workflow,
        )
        self.assertIsNotNone(match, f"workflow step not found: {name}")
        return match.group(0)

    def test_runs_on_a_daily_schedule(self) -> None:
        cron_match = re.search(
            r'(?m)^\s*- cron:\s*["\']([^"\']+)["\']\s*$', self.workflow
        )
        self.assertIsNotNone(cron_match, "scheduled cron trigger is missing")
        self.assertEqual(cron_match.group(1), "23 9 * * *")

    def test_overlapping_syncs_share_a_non_canceling_concurrency_group(self) -> None:
        self.assertRegex(
            self.workflow,
            r"(?ms)^concurrency:\s*\n\s*group:\s*cve-catalog-sync\s*\n\s*cancel-in-progress:\s*false\s*$",
        )

    def test_manual_priority_input_is_plumbed_into_the_bounded_sync(self) -> None:
        dispatch = self.workflow.split("permissions:", 1)[0]
        sync_step = self.step(
            "Synchronize and optionally enrich exact rolling ten-year catalog"
        )

        self.assertRegex(dispatch, r"(?m)^\s{6}priority_cve_ids:\s*$")
        self.assertIn("comma or space separated", dispatch)
        self.assertIn("PRIORITY_CVE_IDS: ${{ inputs.priority_cve_ids || '' }}", sync_step)
        self.assertIn('--priority-cve-ids "$PRIORITY_CVE_IDS"', sync_step)
        self.assertIn("CVE_ENRICHMENT_LIMIT", self.workflow)
        self.assertIn("CVE_ENRICH_MODEL: ${{ vars.CVE_ENRICH_MODEL }}", self.workflow)
        self.assertNotIn("|| 'grok-4.7'", self.workflow)
        self.assertNotIn("|| \"grok-4.7\"", self.workflow)
        self.assertIn("OPENAI_DAYBREAK_PROGRAM: ${{ vars.OPENAI_DAYBREAK_PROGRAM || '' }}", self.workflow)
        self.assertNotIn("OPENAI_ENRICHMENT_LIMIT", self.workflow)
        self.assertNotIn("OPENAI_MODEL", self.workflow)
        self.assertNotIn("XAI_ENRICHMENT_LIMIT", self.workflow)
        self.assertNotIn("XAI_MODEL", self.workflow)

    def test_openai_secret_is_optional_and_never_printed(self) -> None:
        sync_step = self.step(
            "Synchronize and optionally enrich exact rolling ten-year catalog"
        )
        self.assertIn(
            "OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}", sync_step
        )
        self.assertIn(
            "XAI_API_KEY: ${{ secrets.XAI_API_KEY }}", sync_step
        )
        self.assertEqual(
            self.workflow.count("OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}"), 2
        )
        self.assertEqual(
            self.workflow.count("XAI_API_KEY: ${{ secrets.XAI_API_KEY }}"), 2
        )
        self.assertNotIn("OPENAI_API_KEY", self.workflow.split("jobs:", 1)[0])
        self.assertNotIn("XAI_API_KEY", self.workflow.split("jobs:", 1)[0])
        self.assertIn(
            "New enrichment requests skipped; valid cached enrichments retained",
            self.workflow,
        )
        self.assertNotRegex(self.workflow, r"\bsk-[A-Za-z0-9_-]{12,}")
        self.assertNotIn('echo "$OPENAI_API_KEY"', self.workflow)
        self.assertNotIn("print(os.environ['OPENAI_API_KEY'])", self.workflow)
        self.assertNotIn('print(os.environ["OPENAI_API_KEY"])', self.workflow)
        self.assertNotIn('echo "$OPENAI_DAYBREAK_PROGRAM"', self.workflow)

    def test_daybreak_probe_input_skips_the_catalog_sync(self) -> None:
        dispatch = self.workflow.split("permissions:", 1)[0]
        probe_step = self.step("Probe configured enrichment provider")
        self.assertRegex(dispatch, r"(?m)^\s{6}daybreak_probe:\s*$")
        self.assertIn("type: boolean", dispatch)
        self.assertIn(
            "if: github.event_name == 'workflow_dispatch' && inputs.daybreak_probe",
            self.workflow,
        )
        self.assertIn(
            "if: github.event_name != 'workflow_dispatch' || !inputs.daybreak_probe",
            self.workflow,
        )
        self.assertIn("python scripts/probe_openai_daybreak.py", probe_step)
        self.assertIn("XAI_API_KEY: ${{ secrets.XAI_API_KEY }}", probe_step)
        self.assertIn("OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}", probe_step)
        self.assertNotIn("scripts/sync_cve_catalog.py", probe_step)
        self.assertIn("- name: Checkout selected branch", self.workflow)
        self.assertNotIn(
            "ref: ${{ github.event.repository.default_branch }}",
            self.step("Checkout selected branch"),
        )
        self.assertLess(
            self.workflow.index("daybreak-probe:"),
            self.workflow.index("\n  sync:"),
        )

    def test_nvd_api_key_is_optional_and_never_printed(self) -> None:
        sync_step = self.step(
            "Synchronize and optionally enrich exact rolling ten-year catalog"
        )
        self.assertIn("NVD_API_KEY: ${{ secrets.NVD_API_KEY }}", sync_step)
        self.assertEqual(
            self.workflow.count("NVD_API_KEY: ${{ secrets.NVD_API_KEY }}"), 1
        )
        self.assertNotIn("NVD_API_KEY", self.workflow.split("steps:", 1)[0])
        self.assertNotIn("if: ${{ secrets.NVD_API_KEY", self.workflow)
        self.assertNotIn("if: secrets.NVD_API_KEY", self.workflow)
        self.assertNotIn('echo "$NVD_API_KEY"', self.workflow)
        self.assertNotIn("print(os.environ['NVD_API_KEY'])", self.workflow)
        self.assertNotIn('print(os.environ["NVD_API_KEY"])', self.workflow)

    def test_dependencies_are_installed_before_unit_tests(self) -> None:
        install = "python -m pip install -r requirements-dev.txt"
        unit_tests = "python -m unittest"
        self.assertIn(install, self.workflow)
        self.assertIn(unit_tests, self.workflow)
        self.assertLess(self.workflow.index(install), self.workflow.index(unit_tests))

    def test_open_automation_pr_state_is_restored_before_sync(self) -> None:
        restore_step = self.step("Restore unmerged automation enrichment state")
        sync_step = self.step(
            "Synchronize and optionally enrich exact rolling ten-year catalog"
        )

        self.assertIn(
            "if: github.event_name == 'schedule' || github.ref_name == github.event.repository.default_branch",
            restore_step,
        )
        self.assertIn('gh pr list --head "$BRANCH"', restore_step)
        self.assertIn("--json number,isCrossRepository", restore_step)
        self.assertIn("select(.isCrossRepository == false)", restore_step)
        self.assertIn(
            'git fetch --depth=1 --no-tags origin "+refs/heads/$BRANCH:$STATE_REF"',
            restore_step,
        )
        self.assertIn("data/cve/ai-enrichments.json", restore_step)
        self.assertIn("data/cve/ai-generated-recipes.json", restore_step)
        self.assertIn("data/cve/enrichment-carryover.json", restore_step)
        self.assertIn("GeneratedRecipeManager", restore_step)
        self.assertIn("manager.managed_existing_paths()", restore_step)
        self.assertIn(
            "^content/recipes/cve/ai-enrichment-cve-[0-9]{4}-[0-9]{4,}\\.md$",
            restore_step,
        )
        self.assertIn("Preserving human-owned generated-name collision", restore_step)
        self.assertIn("cve-human-collisions.txt", restore_step)
        self.assertIn("restore_generated_recipe_manifest", restore_step)
        self.assertNotIn("restored generated-recipe manifest has invalid entries", restore_step)
        self.assertNotIn("del entries[cve]", restore_step)
        self.assertLess(
            self.workflow.index("Restore unmerged automation enrichment state"),
            self.workflow.index("Synchronize and optionally enrich exact rolling ten-year catalog"),
        )
        self.assertGreater(len(sync_step), 0)

    def test_nvd_cache_is_restored_and_saved_even_after_failure(self) -> None:
        restore_step = self.step("Restore verified NVD feed cache")
        save_step = self.step("Save verified and partial NVD feed cache")

        restore_action = re.search(
            r"uses: actions/cache/restore@([0-9a-f]{40}) # (v\d+\.\d+\.\d+)",
            restore_step,
        )
        save_action = re.search(
            r"uses: actions/cache/save@([0-9a-f]{40}) # (v\d+\.\d+\.\d+)",
            save_step,
        )
        self.assertIsNotNone(restore_action)
        self.assertIsNotNone(save_action)
        self.assertEqual(restore_action.groups(), save_action.groups())
        self.assertIn("path: tmp/nvd-cve-feeds", restore_step)
        self.assertRegex(save_step, r"(?m)^\s*if:\s*always\(\)\s*$")
        self.assertIn("path: tmp/nvd-cve-feeds", save_step)
        self.assertIn("${{ github.run_attempt }}", restore_step)
        self.assertIn("${{ github.run_attempt }}", save_step)

    def test_ai_cache_and_generated_recipes_are_included_in_catalog_commit(self) -> None:
        commit_step = self.step("Open or refresh catalog pull request")
        self.assertIn("github.event_name == 'schedule'", commit_step)
        self.assertIn(
            "github.ref_name == github.event.repository.default_branch",
            commit_step,
        )
        for path in (
            "static/api/cve-catalog",
            "data/cve/ai-enrichments.json",
            "data/cve/ai-generated-recipes.json",
            "data/cve/enrichment-carryover.json",
            ":(glob)content/recipes/cve/*.md",
        ):
            with self.subTest(path=path):
                self.assertIn(path, commit_step)
        self.assertNotIn("data/evidence", commit_step)
        self.assertNotIn("data/context/secure-context-release-pack.json", commit_step)
        self.assertNotIn("data/policy/mcp-gateway-policy.json", commit_step)
        self.assertNotIn("scripts/generated-output-ownership.json", commit_step)
        self.assertNotRegex(commit_step, r"(?m)^\s+content/recipes/cve\s*\\?\s*$")
        self.assertIn("--json number,isCrossRepository", commit_step)
        self.assertIn("select(.isCrossRepository == false)", commit_step)

    def test_behavior_changing_outputs_open_a_separate_karen_qa_pr(self) -> None:
        generated_step = self.step("Open generated-output review pull request")
        commit_step = self.step("Open or refresh catalog pull request")
        delivery_step = self.step(
            "Reconcile, validate, and merge exact catalog revision"
        )
        self.assertLess(
            self.workflow.index("Open or refresh catalog pull request"),
            self.workflow.index("Open generated-output review pull request"),
        )
        for path in (
            "data/evidence",
            "data/context/secure-context-release-pack.json",
            "data/policy/mcp-gateway-policy.json",
            "scripts/generated-output-ownership.json",
        ):
            with self.subTest(path=path):
                self.assertIn(path, generated_step)
                self.assertNotIn(path, commit_step)
        self.assertIn("automation/cve-generated-outputs", generated_step)
        self.assertIn("needs karen-qa", generated_step)
        self.assertIn("never self-merged", generated_step)
        self.assertIn("No behaviour-changing generator outputs changed.", generated_step)
        self.assertIn("continue-on-error: true", generated_step)
        self.assertNotIn("pulls/${PR_NUMBER}/merge", generated_step)
        self.assertNotIn("self-merge-gate", generated_step)
        self.assertIn("pulls/${PR_NUMBER}/merge", delivery_step)
        alert_step = self.step("Alert generated-output review PR failure")
        self.assertIn("always() && steps.generated-output-pr.outcome == 'failure'", alert_step)
        self.assertIn("::error::", alert_step)
        self.assertIn("generated-output-review --step-failed true", alert_step)
        self.assertIn("real alert", alert_step)
        self.assertIn("CVE catalog PR is unaffected", alert_step)
        self.assertNotIn("::warning::", alert_step)
        self.assertLess(
            self.workflow.index("Alert generated-output review PR failure"),
            self.workflow.index("\n  merge:"),
        )
        self.assertGreater(
            self.workflow.index("Reconcile, validate, and merge exact catalog revision"),
            self.workflow.index("\n  merge:"),
        )

    def test_recipe_derived_evidence_is_regenerated_before_validation_and_commit(self) -> None:
        generator_step = self.step("Refresh deterministic recipe-derived evidence")
        self.assertIn("python scripts/run_generator_pipeline.py --write", generator_step)
        self.assertLess(
            self.workflow.index("Refresh deterministic recipe-derived evidence"),
            self.workflow.index("Validate every catalog record and shard"),
        )
        self.assertLess(
            self.workflow.index("Refresh deterministic recipe-derived evidence"),
            self.workflow.index("Open or refresh catalog pull request"),
        )

    def test_manual_runs_upload_enrichment_results(self) -> None:
        artifact_step = self.step("Upload manual enrichment results")

        self.assertRegex(
            artifact_step,
            r"uses: actions/upload-artifact@[0-9a-f]{40} # v\d+\.\d+\.\d+",
        )
        self.assertIn("data/cve/ai-generated-recipes.json", artifact_step)
        self.assertIn("content/recipes/cve/ai-enrichment-cve-*.md", artifact_step)

    def test_catalog_unit_step_runs_the_intended_modules(self) -> None:
        unit_step = self.step("Run catalog unit tests")
        expected_modules = (
            "tests.test_cve_ai_enrichment",
            "tests.test_cve_ai_recipe",
            "tests.test_cve_catalog_data_paths",
            "tests.test_cve_catalog_delivery",
            "tests.test_sync_cve_catalog",
            "tests.test_cve_recipe_catalog",
            "tests.test_cve_sync_workflow",
        )
        for module in expected_modules:
            with self.subTest(module=module):
                self.assertIn(module, unit_step)

    def test_baseline_snapshot_preserves_start_year_index_dates(self) -> None:
        preserve_step = self.step("Preserve baseline catalog manifest")

        self.assertIn("write_baseline_snapshot", preserve_step)
        self.assertIn("scripts.check_cve_catalog_update", preserve_step)
        self.assertIn("static/api/cve-catalog", preserve_step)
        self.assertIn("cve-baseline-manifest.json", preserve_step)
        self.assertLess(
            self.workflow.index("Preserve baseline catalog manifest"),
            self.workflow.index("Synchronize and optionally enrich"),
        )

    def test_sync_writes_structured_health_report_before_safety_gate(self) -> None:
        sync_step = self.step(
            "Synchronize and optionally enrich exact rolling ten-year catalog"
        )
        safety_step = self.step("Quarantine suspicious catalog deltas")

        self.assertIn("--run-report", sync_step)
        self.assertIn("cve-sync-report.json", sync_step)
        self.assertIn("scripts/check_cve_catalog_update.py", safety_step)
        self.assertIn("--fail-on-anomaly", safety_step)
        self.assertRegex(safety_step, r"(?m)^\s*continue-on-error:\s*true\s*$")
        self.assertLess(
            self.workflow.index("Synchronize and optionally enrich"),
            self.workflow.index("Quarantine suspicious catalog deltas"),
        )

    def test_exact_sha_delivery_catches_up_revalidates_and_merges_safely(self) -> None:
        auth_step = self.step("Detect GitHub App automation credentials")
        token_step = self.step("Mint CVE automation GitHub App token")
        commit_step = self.step("Open or refresh catalog pull request")
        delivery_step = self.step(
            "Reconcile, validate, and merge exact catalog revision"
        )
        fail_step = self.step("Fail quarantined catalog refresh")

        self.assertIn("CVE_SYNC_APP_ID", auth_step)
        self.assertIn("CVE_SYNC_APP_KEY", auth_step)
        self.assertNotIn("CVE_AUTOMATION_APP", self.workflow)
        self.assertIn("post-merge Build will be used", auth_step)
        self.assertIn("GitHub App is not configured", auth_step)
        self.assertIn("actions/create-github-app-token@", token_step)
        self.assertIn("app-id: ${{ vars.CVE_SYNC_APP_ID }}", token_step)
        self.assertNotIn("client-id:", token_step)
        self.assertIn("GH_TOKEN: ${{ github.token }}", commit_step)
        self.assertNotIn("steps.app-token.outputs.token", commit_step)
        app_first_token = "steps.app-token.outputs.token || github.token"
        self.assertIn("MAX_DELIVERY_ATTEMPTS=5", delivery_step)
        self.assertIn(
            "gh workflow run cve-catalog-validate.yml", delivery_step
        )
        self.assertIn("--workflow cve-catalog-validate.yml", delivery_step)
        self.assertIn("--event workflow_dispatch", delivery_step)
        self.assertIn(
            "CVE catalog validation ${request_id} @ ${EXPECTED_SHA}",
            delivery_step,
        )
        self.assertIn('--ref "$GITHUB_DEFAULT_BRANCH"', delivery_step)
        self.assertNotIn('--ref "$BRANCH"', delivery_step)
        self.assertIn("expected_sha=$EXPECTED_SHA", delivery_step)
        self.assertIn("pr_number=$PR_NUMBER", delivery_step)
        self.assertIn("pulls/${PR_NUMBER}/update-branch", delivery_step)
        self.assertIn("expected_head_sha=$EXPECTED_SHA", delivery_step)
        self.assertIn("compare/${base_sha}...${expected_sha}", delivery_step)
        self.assertIn("length == 2 and index($old) != null", delivery_step)
        self.assertIn(
            "compare/${requested_base_sha}...${new_sha}", delivery_step
        )
        self.assertIn("Main advanced during exact-SHA validation", delivery_step)
        self.assertIn("dispatch_and_wait_for_validation", delivery_step)
        self.assertIn("scripts/cve_catalog_data_paths.py", delivery_step)
        self.assertIn("scripts/cve_catalog_delivery.py", delivery_step)
        self.assertIn("--pr-json-file", delivery_step)
        self.assertIn("evaluate_catalog_diff", delivery_step)
        self.assertIn("DATA_ONLY", delivery_step)
        self.assertIn("report_protection_fallback", delivery_step)
        self.assertIn("protection_fallback=true", delivery_step)
        self.assertIn("automation:protection-fallback", delivery_step)
        self.assertIn("fallback-escalation", delivery_step)
        self.assertIn('--app-configured "$APP_CONFIGURED"', delivery_step)
        self.assertIn("2 consecutive runs or 24h", delivery_step)
        self.assertIn("--labeled-at", delivery_step)
        self.assertIn("issues/${PR_NUMBER}/events", delivery_step)
        self.assertNotIn("--created-at", delivery_step)
        self.assertIn("fail-closed-wrong-sha", delivery_step)
        self.assertIn(
            "Catalog protection-fallback escalated after 2 consecutive runs or 24h",
            delivery_step,
        )
        for checkpoint in (
            "before_validation",
            "after_validation",
            "after_merge_attempt",
        ):
            with self.subTest(checkpoint=checkpoint):
                self.assertIn(
                    f"fail-closed-wrong-sha --checkpoint {checkpoint} --pr-state",
                    delivery_step,
                )
        self.assertEqual(delivery_step.count("fail-closed-wrong-sha --checkpoint"), 3)
        self.assertRegex(
            delivery_step,
            r"protection-fallback escalated[\s\S]{0,200}exit 1",
        )
        self.assertIn("Data-only catalog PR skips karen-qa and the GitHub App check.", delivery_step)
        self.assertIn('--ref "$VALIDATION_REF"', delivery_step)
        self.assertIn("reuse-in-run-validation", delivery_step)
        self.assertIn("self-merge-gate", delivery_step)
        self.assertIn("Never gate self-merge on github-actions[bot]", delivery_step)
        self.assertNotIn("reuse-build-check", delivery_step)
        self.assertIn("pulls/${PR_NUMBER}/merge", delivery_step)
        self.assertIn('sha=$EXPECTED_SHA', delivery_step)
        self.assertIn("AUTO_MERGE_ENABLED", delivery_step)
        self.assertIn("APP_CONFIGURED", delivery_step)
        self.assertIn(f"GH_TOKEN: ${{{{ {app_first_token} }}}}", delivery_step)
        self.assertIn("dispatch_main_build_after_merge", delivery_step)
        self.assertIn(
            "GitHub App merge authentication will emit the normal push-triggered Build",
            delivery_step,
        )
        self.assertIn("gh workflow run build.yml", delivery_step)
        self.assertIn('--field "expected_sha=$merge_commit_sha"', delivery_step)
        self.assertIn('--field "request_id=$request_id"', delivery_step)
        self.assertIn(
            'git/ref/heads/${GITHUB_DEFAULT_BRANCH}', delivery_step
        )
        self.assertIn(
            '"$current_main_sha" != "$merge_commit_sha"', delivery_step
        )
        self.assertIn("gh_api_with_retry()", delivery_step)
        self.assertNotIn("publish_required_merge_statuses", delivery_step)
        self.assertNotIn("/statuses/", self.workflow)
        self.assertNotIn("statuses: write", self.workflow)
        self.assertIn("rules/branches/${GITHUB_DEFAULT_BRANCH}", delivery_step)
        self.assertIn("require_karen_qa_from_app", delivery_step)
        self.assertIn("report_waiting_on_karen_qa", delivery_step)
        self.assertIn("waiting on karen-qa from the Karen QA app on ${expected_sha}", delivery_step)
        self.assertIn(
            '::warning::Catalog PR #${PR_NUMBER} is waiting on karen-qa from the Karen QA app on ${expected_sha}.',
            delivery_step,
        )
        self.assertIn('report_waiting_on_karen_qa "$EXPECTED_SHA"', delivery_step)
        self.assertIn("waiting_on_karen_qa=true", delivery_step)
        self.assertIn("does not post karen-qa", delivery_step)
        self.assertIn("Leaving catalog PR #${PR_NUMBER} open until karen-qa lands.", delivery_step)
        self.assertIn("needs karen-qa on ${expected_sha} from Karen QA app", delivery_step)
        self.assertNotIn("::error::needs karen-qa on ${EXPECTED_SHA}", delivery_step)
        self.assertIn(
            "required checks must come from real workflow runs on ${EXPECTED_SHA}",
            delivery_step,
        )
        self.assertNotIn("FOREIGN_REQUIRED_PINS", delivery_step)
        self.assertNotIn("retarget", delivery_step)
        self.assertNotIn("unpin", delivery_step)
        self.assertNotIn('context=karen-qa', delivery_step)
        self.assertIn("fail_closed_real_checks", delivery_step)
        self.assertIn("merge-error", delivery_step)
        self.assertNotIn("gh api --retry", delivery_step)
        self.assertNotIn("--retry-delay", delivery_step)
        self.assertEqual(delivery_step.count("dispatch_main_build_after_merge"), 5)
        self.assertNotIn("--auto", delivery_step)
        self.assertNotIn("--admin", delivery_step)
        self.assertNotIn("git checkout", delivery_step)
        self.assertLess(
            delivery_step.index("pulls/${PR_NUMBER}/update-branch"),
            delivery_step.rindex(
                'dispatch_and_wait_for_validation "$DELIVERY_ATTEMPT"'
            ),
        )
        self.assertLess(
            delivery_step.rindex(
                'dispatch_and_wait_for_validation "$DELIVERY_ATTEMPT"'
            ),
            delivery_step.index("pulls/${PR_NUMBER}/merge"),
        )
        self.assertIn("steps.safety.outputs.safe_to_merge != 'true'", fail_step)
        fallback_step = self.step("Explain catalog PR protection fallback")
        self.assertIn(
            "steps.catalog-delivery.outputs.protection_fallback == 'true'",
            fallback_step,
        )
        self.assertIn("automation:protection-fallback", fallback_step)
        self.assertIn("::notice::", fallback_step)
        self.assertNotIn("::error::", fallback_step)
        waiting_step = self.step("Explain catalog PR is waiting on karen-qa")
        self.assertIn(
            "steps.catalog-delivery.outputs.waiting_on_karen_qa == 'true'",
            waiting_step,
        )
        self.assertIn(
            '::warning::Catalog PR #${PR_NUMBER} is waiting on karen-qa from the Karen QA app on ${EXPECTED_SHA}.',
            waiting_step,
        )
        self.assertIn("GITHUB_STEP_SUMMARY", waiting_step)
        self.assertIn(r"never posts \`karen-qa\`", waiting_step)
        self.assertIn("HTTP 405", waiting_step)
        summarize_step = self.step("Summarize catalog refresh")
        self.assertIn("not retrievable", summarize_step)
        self.assertIn("::warning::NVD lastMod catch-up skipped", summarize_step)
        self.assertIn("GITHUB_STEP_SUMMARY", summarize_step)
        self.assertIn(
            "NVD lastMod catch-up skipped; catalog kept the annual-feed watermark",
            summarize_step,
        )

    def test_sync_job_timeout_documents_fetch_deadline_headroom(self) -> None:
        self.assertIn("timeout-minutes: 150", self.workflow)
        self.assertIn("5 min/page", self.workflow)
        self.assertIn("11.3 min measured", self.workflow)
        self.assertIn("CVE catalog sync budget", self.workflow)
        automation = (ROOT / ".github" / "AUTOMATION.md").read_text(encoding="utf-8")
        self.assertIn("## CVE catalog sync budget", automation)
        self.assertIn("15.5 min/URL", automation)
        self.assertIn("300s", automation)
        self.assertIn("successful catch-up pages", automation)
        self.assertIn("39623444175", automation)
        self.assertIn("11.3 min", automation)
        self.assertIn("20.7 min headroom", automation)
        self.assertIn("NVD_API_MAX_PAGES = 15", automation)
        self.assertIn("FETCH_DEADLINE_SECONDS", automation)
        self.assertIn("FETCH_READ_CHUNK_SIZE", automation)
        self.assertIn("15-page", self.workflow)

    def test_merge_job_is_the_only_cve_sync_environment_consumer(self) -> None:
        merge_idx = self.workflow.index("\n  merge:")
        sync_idx = self.workflow.index("\n  sync:")
        self.assertLess(sync_idx, merge_idx)
        merge_job = self.workflow[merge_idx:]
        sync_job = self.workflow[sync_idx:merge_idx]
        env_name = "cve-sync"
        job_environments = re.findall(r"(?m)^    environment:\s*(\S+)\s*$", self.workflow)
        self.assertEqual(job_environments, [env_name])
        self.assertRegex(merge_job, rf"(?m)^    environment:\s*{re.escape(env_name)}\s*$")
        self.assertNotRegex(sync_job, r"(?m)^    environment:\s*")
        self.assertNotIn("CVE_SYNC_APP_ID", sync_job)
        self.assertNotIn("CVE_SYNC_APP_KEY", sync_job)
        self.assertIn("CVE_SYNC_APP_ID", merge_job)
        self.assertIn("CVE_SYNC_APP_KEY", merge_job)
        self.assertIn("needs: sync", merge_job)
        self.assertIn("needs.sync.outputs.changed == 'true'", merge_job)
        self.assertIn("needs.sync.outputs.safe_to_merge == 'true'", merge_job)
        self.assertIn("needs.sync.result == 'success'", merge_job)
        self.assertIn("app-id: ${{ vars.CVE_SYNC_APP_ID }}", merge_job)
        self.assertIn("secrets.CVE_SYNC_APP_KEY", merge_job)
        generated_step = self.step("Open generated-output review pull request")
        self.assertIn("GH_TOKEN: ${{ github.token }}", generated_step)
        self.assertNotIn("steps.app-token.outputs.token", generated_step)
        automation = (ROOT / ".github" / "AUTOMATION.md").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        banned = "environment:" + f" {env_name}"
        skip_dirs = {".git", "node_modules", "public", ".venv", "__pycache__"}
        leaked: list[str] = []
        for path in ROOT.rglob("*"):
            if not path.is_file() or any(part in skip_dirs for part in path.parts):
                continue
            if path.resolve() == WORKFLOW_PATH.resolve():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if banned in text:
                leaked.append(str(path.relative_to(ROOT)))
        self.assertEqual(leaked, [], f"{banned} leaked outside the merge job")
        self.assertIn("CVE_SYNC_APP_ID", automation)
        self.assertIn("CVE_SYNC_APP_KEY", automation)
        self.assertIn("CVE_SYNC_APP_ID", readme)
        self.assertIn("CVE_SYNC_APP_KEY", readme)
        self.assertNotIn("CVE_AUTOMATION_APP", automation)
        self.assertNotIn("CVE_AUTOMATION_APP", readme)

    def test_enrichment_health_issue_is_upserted_and_closed_on_recovery(self) -> None:
        health_step = self.step("Reconcile enrichment health issue")

        self.assertIn("automation:cve-enrichment-health", health_step)
        self.assertIn("gh issue create", health_step)
        self.assertIn("gh issue edit", health_step)
        self.assertIn("gh issue close", health_step)
        self.assertIn("Provider error", health_step)

    def test_every_action_reference_is_immutable(self) -> None:
        references = re.findall(r"(?m)^\s*uses:\s*([^#\s]+)", self.workflow)

        self.assertGreaterEqual(len(references), 7)
        for reference in references:
            with self.subTest(reference=reference):
                self.assertRegex(reference, r"^[^@\s]+@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
