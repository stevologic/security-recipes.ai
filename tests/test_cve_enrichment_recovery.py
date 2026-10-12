from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts import check_cve_catalog_update as guard
from scripts import cve_ai_enrichment as enrichment
from tests.test_cve_ai_enrichment import model_output, record
from tests.test_cve_automation_health import manifest, sync_report


ROOT = Path(__file__).resolve().parents[1]


class EnrichmentRecoveryTests(unittest.TestCase):
    def report(self, **metrics: object) -> dict[str, object]:
        candidate = manifest()
        candidate["scope"] = {
            "published_start": "2016-07-17", "published_end": "2026-07-17",
        }
        run = sync_report(selected=5, generated=5)
        run.update({
            "scope": copy.deepcopy(candidate["scope"]),
            "totals": copy.deepcopy(candidate["totals"]), "dry_run": False,
        })
        run["ai_enrichment"].update(metrics)
        return guard.build_report(candidate, candidate, run)

    def reconcile(self, report: dict[str, object], *, incident: bool = True) -> list[str]:
        workflow = (ROOT / ".github/workflows/cve-catalog-sync.yml").read_text()
        step = re.search(
            r"(?ms)^      - name: Reconcile enrichment health issue\n"
            r"(.*?)(?=^      - name: |\Z)", workflow,
        ).group(0)
        shell = textwrap.dedent(step.split("run: |\n", 1)[1])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commands = root / "commands"
            cli = root / "gh"
            cli.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$COMMAND_LOG"\n'
                'if [ "$1 $2" = "issue list" ]; then printf "%s" "$TEST_ISSUE"; fi\n'
            )
            cli.chmod(0o755)
            (root / "python").symlink_to(sys.executable)
            (root / "cve-safety-report.json").write_text(json.dumps(report))
            outputs = root / "outputs"
            guard._write_github_output(outputs, report)
            values = dict(line.split("=", 1) for line in outputs.read_text().splitlines())
            env = {
                "PATH": f"{root}{os.pathsep}{os.defpath}", "RUNNER_TEMP": str(root),
                "COMMAND_LOG": str(commands), "TEST_ISSUE": "349" if incident else "",
                "ENRICHMENT_HEALTHY": values["enrichment_healthy"],
                "ENRICHMENT_RECOVERY_READY": values["enrichment_recovery_ready"],
                "GITHUB_SERVER_URL": "https://github.invalid",
                "GITHUB_REPOSITORY": "fixture/security-recipes", "GITHUB_RUN_ID": "1",
            }
            subprocess.run(["bash", "-e", "-o", "pipefail", "-c", shell],
                           env=env, check=True, capture_output=True, text=True)
            return commands.read_text().splitlines()

    def test_existing_incident_survives_zero_limit_with_pending_work(self) -> None:
        report = self.report(selected=0, generated=0, eligible=500)
        self.assertTrue(report["enrichment"]["healthy"])
        self.assertFalse(report["enrichment"]["recovery"]["ready"])
        commands = self.reconcile(report)
        self.assertFalse(any(line.startswith(("issue close", "issue comment", "issue edit"))
                             for line in commands))

    def test_real_nonzero_recovery_closes_existing_incident(self) -> None:
        report = self.report()
        self.assertEqual(report["enrichment"]["recovery"]["reason"],
                         "healthy-nonzero-enrichment")
        commands = self.reconcile(report)
        self.assertTrue(any(line.startswith("issue comment 349") for line in commands))
        self.assertTrue(any(line.startswith("issue close 349") for line in commands))

    def test_one_warning_preserves_nonzero_recovery_and_two_hold_it(self) -> None:
        warning = self.report(generated=4)
        self.assertTrue(warning["enrichment"]["recovery"]["ready"])
        self.assertEqual(len(warning["enrichment"]["warnings"]), 1)
        alert = self.report(generated=3)
        self.assertFalse(alert["enrichment"]["healthy"])
        self.assertFalse(alert["enrichment"]["recovery"]["ready"])

    def test_fresh_cache_scan_proves_resolved_backlog_without_model_calls(self) -> None:
        source = record()
        entry = enrichment.build_enrichment_entry(
            source, model_output(), model="fixture-model", retrieved_source_urls=[],
            generated_at=datetime(2026, 7, 14, tzinfo=timezone.utc),
        )
        with tempfile.TemporaryDirectory() as temporary:
            cache = enrichment.EnrichmentCache(Path(temporary) / "cache.json",
                                               {str(source["cve"]): entry})
            cache.select_candidates([source], limit=0,
                                    as_of=datetime(2026, 7, 15, tzinfo=timezone.utc))
        self.assertEqual(cache.stats["cached"], 1)
        self.assertEqual(cache.stats["eligible"], 0)
        report = self.report(**cache.stats)
        self.assertEqual(report["enrichment"]["recovery"],
                         {"ready": True, "reason": "verified-empty-backlog"})
        self.assertTrue(any(line.startswith("issue close 349")
                            for line in self.reconcile(report)))

    def test_due_cached_work_is_not_an_empty_backlog(self) -> None:
        report = self.report(selected=0, generated=0, eligible=1, cached=500,
                             refresh_due=1)
        self.assertTrue(report["enrichment"]["healthy"])
        self.assertFalse(report["enrichment"]["recovery"]["ready"])

    def test_missing_or_invalid_counts_cannot_prove_recovery(self) -> None:
        for value in (None, True, -1, "0", 0.0):
            with self.subTest(value=value):
                report = self.report(selected=0, generated=0, eligible=value)
                self.assertTrue(report["enrichment"]["healthy"])
                self.assertFalse(report["enrichment"]["recovery"]["ready"])

    def test_inconsistent_counts_cannot_prove_recovery(self) -> None:
        for metrics in ({"generated": 6}, {"eligible": 4},
                        {"selected": 0, "generated": 0, "eligible": 0, "refresh_due": 1}):
            with self.subTest(metrics=metrics):
                self.assertFalse(self.report(**metrics)["enrichment"]["recovery"]["ready"])

    def test_partial_missing_dry_or_mismatched_scan_cannot_prove_recovery(self) -> None:
        candidate = manifest()
        candidate["scope"] = {"published_start": "2016-07-17", "published_end": "2026-07-17"}
        for change in ({}, {"dry_run": True}, {"totals": {}}, {"scope": {}},
                       {"totals": {"catalog_records": 10}}, {"dry_run": None}):
            with self.subTest(change=change):
                run = sync_report(selected=0, generated=0)
                run.update({"dry_run": False, "scope": copy.deepcopy(candidate["scope"]),
                            "totals": copy.deepcopy(candidate["totals"])})
                if not change:
                    run.pop("dry_run")
                else:
                    run.update(change)
                report = guard.build_report(candidate, candidate, run)
                self.assertTrue(report["enrichment"]["healthy"])
                self.assertFalse(report["enrichment"]["recovery"]["ready"])

    def test_quarantine_cannot_close_even_with_nonzero_healthy_enrichment(self) -> None:
        candidate = manifest(records=0)
        report = guard.build_report(manifest(), candidate, sync_report(selected=5, generated=5))
        self.assertTrue(report["enrichment"]["healthy"])
        self.assertFalse(report["enrichment"]["recovery"]["ready"])

    def test_healthy_noop_without_incident_creates_no_issue(self) -> None:
        commands = self.reconcile(self.report(selected=0, generated=0), incident=False)
        self.assertFalse(any(line.startswith(("issue create", "issue edit", "issue close"))
                             for line in commands))

    def test_unhealthy_run_retains_existing_issue_upsert(self) -> None:
        commands = self.reconcile(self.report(generated=0))
        self.assertTrue(any(line.startswith("issue edit 349") for line in commands))
        self.assertFalse(any(line.startswith("issue close") for line in commands))

    def test_missing_recovery_output_fails_closed(self) -> None:
        report = self.report()
        report["enrichment"].pop("recovery")
        self.assertFalse(any(line.startswith("issue close") for line in self.reconcile(report)))


if __name__ == "__main__":
    unittest.main()
