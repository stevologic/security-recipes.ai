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

    def test_manual_priority_input_is_plumbed_into_the_bounded_sync(self) -> None:
        dispatch = self.workflow.split("permissions:", 1)[0]
        sync_step = self.step(
            "Synchronize and optionally enrich exact rolling ten-year catalog"
        )

        self.assertRegex(dispatch, r"(?m)^\s{6}priority_cve_ids:\s*$")
        self.assertIn("comma or space separated", dispatch)
        self.assertIn("PRIORITY_CVE_IDS: ${{ inputs.priority_cve_ids || '' }}", sync_step)
        self.assertIn('--priority-cve-ids "$PRIORITY_CVE_IDS"', sync_step)
        self.assertIn("OPENAI_ENRICHMENT_LIMIT", self.workflow)

    def test_openai_secret_is_optional_and_never_printed(self) -> None:
        sync_step = self.step(
            "Synchronize and optionally enrich exact rolling ten-year catalog"
        )
        self.assertIn(
            "OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}", sync_step
        )
        self.assertEqual(
            self.workflow.count("OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}"), 1
        )
        self.assertNotIn("OPENAI_API_KEY", self.workflow.split("steps:", 1)[0])
        self.assertIn(
            "New OpenAI requests skipped; valid cached enrichments retained",
            self.workflow,
        )
        self.assertNotRegex(self.workflow, r"\bsk-[A-Za-z0-9_-]{12,}")
        self.assertNotIn('echo "$OPENAI_API_KEY"', self.workflow)
        self.assertNotIn("print(os.environ['OPENAI_API_KEY'])", self.workflow)
        self.assertNotIn('print(os.environ["OPENAI_API_KEY"])', self.workflow)

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
        self.assertIn('git fetch --no-tags origin "+refs/heads/$BRANCH:$STATE_REF"', restore_step)
        self.assertIn("data/cve/ai-enrichments.json", restore_step)
        self.assertIn("data/cve/ai-generated-recipes.json", restore_step)
        self.assertIn("GeneratedRecipeManager", restore_step)
        self.assertIn("manager.managed_existing_paths()", restore_step)
        self.assertIn(
            "^content/recipes/cve/ai-enrichment-cve-[0-9]{4}-[0-9]{4,}\\.md$",
            restore_step,
        )
        self.assertIn("Preserving human-owned generated-name collision", restore_step)
        self.assertIn("cve-human-collisions.txt", restore_step)
        self.assertIn("del entries[cve]", restore_step)
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
            "content/recipes/cve",
            "data/evidence",
            "data/context/secure-context-release-pack.json",
            "data/policy/mcp-gateway-policy.json",
            "scripts/generated-output-ownership.json",
        ):
            with self.subTest(path=path):
                self.assertIn(path, commit_step)
        self.assertIn("--json number,isCrossRepository", commit_step)
        self.assertIn("select(.isCrossRepository == false)", commit_step)

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
            "tests.test_sync_cve_catalog",
            "tests.test_cve_recipe_catalog",
            "tests.test_cve_sync_workflow",
        )
        for module in expected_modules:
            with self.subTest(module=module):
                self.assertIn(module, unit_step)

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

        self.assertIn("CVE_AUTOMATION_APP_CLIENT_ID", auth_step)
        self.assertIn("CVE_AUTOMATION_APP_PRIVATE_KEY", auth_step)
        self.assertIn("post-merge Build will be used", auth_step)
        self.assertIn("actions/create-github-app-token@", token_step)
        app_first_token = "steps.app-token.outputs.token || github.token"
        self.assertIn(f"GH_TOKEN: ${{{{ {app_first_token} }}}}", commit_step)
        self.assertIn("MAX_DELIVERY_ATTEMPTS=5", delivery_step)
        self.assertIn("gh workflow run cve-catalog-validate.yml", delivery_step)
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
        self.assertNotIn("gh api --retry", delivery_step)
        self.assertNotIn("--retry-delay", delivery_step)
        self.assertEqual(delivery_step.count("dispatch_main_build_after_merge"), 4)
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

    def test_enrichment_health_issue_is_upserted_and_closed_on_recovery(self) -> None:
        health_step = self.step("Reconcile enrichment health issue")

        self.assertIn("automation:cve-enrichment-health", health_step)
        self.assertIn("gh issue create", health_step)
        self.assertIn("gh issue edit", health_step)
        self.assertIn("gh issue close", health_step)

    def test_every_action_reference_is_immutable(self) -> None:
        references = re.findall(r"(?m)^\s*uses:\s*([^#\s]+)", self.workflow)

        self.assertGreaterEqual(len(references), 7)
        for reference in references:
            with self.subTest(reference=reference):
                self.assertRegex(reference, r"^[^@\s]+@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
