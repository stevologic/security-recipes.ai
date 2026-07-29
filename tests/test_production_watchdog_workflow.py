from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "production-watchdog.yml"
PROBE = ROOT / "scripts" / "check_production_health.py"


class ProductionWatchdogWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.probe = PROBE.read_text(encoding="utf-8")

    def test_runs_twice_hourly_and_can_be_dispatched(self) -> None:
        self.assertIn('- cron: "17,47 * * * *"', self.workflow)
        self.assertRegex(self.workflow, r"(?m)^\s*workflow_dispatch:\s*$")

    def test_probe_covers_site_catalog_revision_and_tls_script(self) -> None:
        self.assertIn("scripts/check_production_health.py", self.workflow)
        self.assertIn("--base-url", self.workflow)
        self.assertIn("--expected-revision", self.workflow)
        self.assertIn("--expected-commit-time", self.workflow)
        self.assertIn("PRODUCTION_BASE_URL", self.workflow)
        self.assertIn(
            "context.minimum_version = ssl.TLSVersion.TLSv1_2",
            self.probe,
        )

    def test_catalog_freshness_allows_normal_deployment_lag(self) -> None:
        self.assertIn(
            "WATCHDOG_MAX_CATALOG_AGE_HOURS: ${{ vars.WATCHDOG_MAX_CATALOG_AGE_HOURS || '72' }}",
            self.workflow,
        )
        self.assertIn(
            "WATCHDOG_REVISION_GRACE_MINUTES: ${{ vars.WATCHDOG_REVISION_GRACE_MINUTES || '1440' }}",
            self.workflow,
        )

    def test_health_issue_is_updated_and_closed_on_recovery(self) -> None:
        self.assertIn("automation:production-health", self.workflow)
        self.assertIn("gh issue create", self.workflow)
        self.assertIn("gh issue edit", self.workflow)
        self.assertIn("gh issue close", self.workflow)
        self.assertIn("steps.production.outputs.healthy", self.workflow)

    def test_unhealthy_probe_fails_only_after_issue_reconciliation(self) -> None:
        reconcile = self.workflow.index("Upsert or recover production health issue")
        failure = self.workflow.index("Fail unhealthy watchdog run")

        self.assertLess(reconcile, failure)
        self.assertIn("continue-on-error: true", self.workflow)

    def test_unhealthy_runs_self_heal_missing_builds_and_stale_catalogs(self) -> None:
        revision_heal = self.workflow.split("- name: Self-heal an unbuilt main revision", 1)[1]
        catalog_heal = revision_heal.split("- name: Self-heal a stale CVE catalog", 1)[1]
        revision_heal = revision_heal.split("- name: Self-heal a stale CVE catalog", 1)[0]

        self.assertRegex(self.workflow, r"(?m)^\s{2}actions: write\s*$")
        for heal_step in (revision_heal, catalog_heal):
            self.assertIn(
                "if: always() && steps.production.outputs.healthy != 'true'",
                heal_step,
            )
            self.assertIn("production-health.json", heal_step)

        self.assertIn('select(.name == "revision" and .ok == false)', revision_heal)
        self.assertIn("gh workflow run build.yml", revision_heal)
        self.assertIn('--field "expected_sha=${MAIN_SHA}"', revision_heal)
        self.assertIn('.path == ".github/workflows/build.yml"', revision_heal)
        self.assertIn('[ "$TOTAL_RUNS" -ge 2 ]', revision_heal)

        self.assertIn('select(.name == "catalog" and .ok == false)', catalog_heal)
        self.assertIn("gh workflow run cve-catalog-sync.yml", catalog_heal)
        self.assertIn("six-hour heal cooldown", catalog_heal)
        self.assertIn("21600", catalog_heal)

        self.assertLess(
            self.workflow.index("Upsert or recover production health issue"),
            self.workflow.index("Self-heal an unbuilt main revision"),
        )
        self.assertLess(
            self.workflow.index("Self-heal a stale CVE catalog"),
            self.workflow.index("Fail unhealthy watchdog run"),
        )

    def test_actions_are_pinned_to_full_commit_shas(self) -> None:
        references = re.findall(r"(?m)^\s*uses:\s*([^#\s]+)", self.workflow)

        self.assertEqual(len(references), 2)
        for reference in references:
            with self.subTest(reference=reference):
                self.assertRegex(reference, r"^[^@\s]+@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
