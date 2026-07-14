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

        self.assertIn("uses: actions/cache/restore@v4", restore_step)
        self.assertIn("path: tmp/nvd-cve-feeds", restore_step)
        self.assertIn("uses: actions/cache/save@v4", save_step)
        self.assertRegex(save_step, r"(?m)^\s*if:\s*always\(\)\s*$")
        self.assertIn("path: tmp/nvd-cve-feeds", save_step)
        self.assertIn("${{ github.run_attempt }}", restore_step)
        self.assertIn("${{ github.run_attempt }}", save_step)

    def test_ai_cache_and_generated_recipes_are_included_in_catalog_commit(self) -> None:
        commit_step = self.step("Open or refresh catalog pull request")
        self.assertIn(
            "if: github.event_name == 'schedule' || github.ref_name == github.event.repository.default_branch",
            commit_step,
        )
        self.assertIn(
            "git add -A -- static/api/cve-catalog data/cve/ai-enrichments.json "
            "data/cve/ai-generated-recipes.json content/recipes/cve",
            commit_step,
        )
        self.assertIn("--json number,isCrossRepository", commit_step)
        self.assertIn("select(.isCrossRepository == false)", commit_step)

    def test_manual_runs_upload_enrichment_results(self) -> None:
        artifact_step = self.step("Upload manual enrichment results")

        self.assertIn("uses: actions/upload-artifact@v4", artifact_step)
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


if __name__ == "__main__":
    unittest.main()
