from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from scripts import check_cve_catalog_update as catalog_guard
from scripts import check_production_health as production


def manifest(
    *,
    records: int = 100_000,
    in_scope_kev: int = 1_000,
    kev_records: int = 1_600,
    updated_at: str = "2026-07-17T09:00:00Z",
) -> dict[str, Any]:
    return {
        "catalog_updated_at": updated_at,
        "totals": {
            "catalog_records": records,
            "in_scope_kev": in_scope_kev,
            "shards": 500,
            "markdown_drafts": 1_000,
            "markdown_pages": 1_010,
        },
        "by_publication_year": {
            "2025": {"total": 40_000},
            "2026": {"total": 35_000},
        },
        "sources": {
            "cisa_kev": {
                "catalog_records": kev_records,
                "date_released": updated_at,
            },
            "nvd": {
                "feeds": [
                    {
                        "year": 2025,
                        "accepted_records": 41_000,
                        "metadata": {"lastModifiedDate": updated_at},
                    },
                    {
                        "year": 2026,
                        "accepted_records": 36_000,
                        "metadata": {"lastModifiedDate": updated_at},
                    },
                ]
            },
        },
    }


def sync_report(
    *,
    api_enabled: bool = True,
    selected: int = 20,
    generated: int = 20,
    failed: int = 0,
    deleted: int = 0,
) -> dict[str, Any]:
    return {
        "ai_enrichment": {
            "api_enabled": api_enabled,
            "eligible": 500,
            "cached": 100,
            "selected": selected,
            "generated": generated,
            "failed": failed,
        },
        "generated_recipes": {"deleted": deleted},
    }


class CatalogUpdateGuardTests(unittest.TestCase):
    def test_small_expected_changes_remain_mergeable(self) -> None:
        baseline = manifest()
        candidate = manifest(records=99_900, in_scope_kev=990, kev_records=1_590)

        report = catalog_guard.build_report(
            baseline, candidate, sync_report(generated=19, failed=1)
        )

        self.assertTrue(report["safe_to_merge"])
        self.assertEqual(report["anomalies"], [])
        self.assertTrue(report["enrichment"]["healthy"])
        self.assertEqual(report["enrichment"]["metrics"]["failed"], 1)
        self.assertIn("1 enrichment request", report["enrichment"]["warnings"][0])

    def test_large_source_regression_is_quarantined(self) -> None:
        baseline = manifest()
        candidate = manifest(
            records=70_000,
            in_scope_kev=0,
            kev_records=0,
            updated_at="2026-07-16T09:00:00Z",
        )
        candidate["by_publication_year"].pop("2025")
        candidate["sources"]["nvd"]["feeds"] = [
            {
                "year": 2026,
                "accepted_records": 20_000,
                "metadata": {"lastModifiedDate": "2026-07-16T09:00:00Z"},
            }
        ]
        candidate["totals"]["shards"] = 300
        candidate["totals"]["markdown_drafts"] = 800

        report = catalog_guard.build_report(
            baseline, candidate, sync_report(deleted=50)
        )
        codes = {finding["code"] for finding in report["anomalies"]}

        self.assertFalse(report["safe_to_merge"])
        self.assertIn("catalog-implausibly-small", codes)
        self.assertIn("catalog-timestamp-regressed", codes)
        self.assertIn("publication-years-missing", codes)
        self.assertIn("in-scope-kev-empty", codes)
        self.assertIn("kev-feed-empty", codes)
        self.assertIn("kev-source-timestamp-regressed", codes)
        self.assertIn("nvd-feeds-missing", codes)
        self.assertIn("nvd-source-timestamp-regressed", codes)
        self.assertIn("shards-drop", codes)
        self.assertIn("markdown-drafts-drop", codes)
        self.assertIn("generated-recipe-deletion-spike", codes)

    def test_enrichment_outage_alerts_without_blocking_source_catalog(self) -> None:
        report = catalog_guard.build_report(
            manifest(),
            manifest(),
            sync_report(selected=20, generated=0, failed=3),
        )

        self.assertTrue(report["safe_to_merge"])
        self.assertFalse(report["enrichment"]["healthy"])
        self.assertGreaterEqual(len(report["enrichment"]["alerts"]), 2)

    def test_missing_openai_key_is_explicitly_unhealthy(self) -> None:
        health = catalog_guard.enrichment_health(
            sync_report(api_enabled=False, selected=0, generated=0)
        )

        self.assertFalse(health["healthy"])
        self.assertIn("OPENAI_API_KEY", health["alerts"][0])

    def test_cli_writes_fail_closed_github_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            baseline = root / "baseline.json"
            candidate = root / "candidate.json"
            run = root / "run.json"
            report = root / "report.json"
            markdown = root / "report.md"
            output = root / "github-output.txt"
            baseline.write_text('{"not": "a manifest"}\n', encoding="utf-8")
            candidate.write_text('{"not": "a manifest"}\n', encoding="utf-8")
            run.write_text('{"ai_enrichment": {}}\n', encoding="utf-8")

            result = catalog_guard.main(
                [
                    "--baseline",
                    str(baseline),
                    "--candidate",
                    str(candidate),
                    "--sync-report",
                    str(run),
                    "--report",
                    str(report),
                    "--markdown",
                    str(markdown),
                    "--github-output",
                    str(output),
                    "--fail-on-anomaly",
                ]
            )

            self.assertEqual(result, 1)
            self.assertIn("safe_to_merge=false", output.read_text(encoding="utf-8"))
            self.assertTrue(report.exists())


class FakeResponse:
    def __init__(self, url: str, payload: bytes, content_type: str) -> None:
        self.status = 200
        self.url = url
        self.payload = payload
        self.headers = {"Content-Type": content_type}

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def getcode(self) -> int:
        return self.status

    def geturl(self) -> str:
        return self.url

    def read(self, _: int = -1) -> bytes:
        return self.payload


class ProductionHealthTests(unittest.TestCase):
    NOW = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
    SHA = "a" * 40

    def opener(
        self,
        catalog_updated_at: str = "2026-07-17T09:00:00Z",
        revision: str | None = None,
    ):
        revision_value = revision or self.SHA

        def open_request(request: Any, *, timeout: float) -> FakeResponse:
            self.assertGreater(timeout, 0)
            url = request.full_url
            if url.endswith("/api/cve-catalog/manifest.json"):
                payload = (
                    '{"catalog_updated_at":"'
                    + catalog_updated_at
                    + '","totals":{"catalog_records":100000}}'
                ).encode()
                return FakeResponse(url, payload, "application/json")
            if url.endswith("/.well-known/deploy-revision"):
                return FakeResponse(url, revision_value.encode(), "text/plain")
            return FakeResponse(
                url, b"<!doctype html><html>security recipes</html>", "text/html"
            )

        return open_request

    def certificate(self, *_: object, **__: object) -> datetime:
        return self.NOW + timedelta(days=90)

    def test_healthy_site_catalog_revision_and_tls(self) -> None:
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(),
            certificate_expiry=self.certificate,
        )

        self.assertTrue(report["healthy"])
        self.assertEqual(report["failure_count"], 0)
        self.assertEqual(report["warning_count"], 0)
        self.assertEqual(
            {check["name"] for check in report["checks"]},
            {"homepage", "catalog", "revision", "tls"},
        )

    def test_recent_main_revision_gets_deployment_grace_warning(self) -> None:
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(minutes=10),
            now=self.NOW,
            opener=self.opener(revision="b" * 40),
            certificate_expiry=self.certificate,
        )

        self.assertTrue(report["healthy"])
        self.assertEqual(report["warning_count"], 1)

    def test_stale_catalog_and_stuck_revision_fail(self) -> None:
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(
                catalog_updated_at="2026-07-15T00:00:00Z",
                revision="b" * 40,
            ),
            certificate_expiry=self.certificate,
        )

        self.assertFalse(report["healthy"])
        self.assertEqual(report["failure_count"], 2)
        failed = {check["name"] for check in report["checks"] if not check["ok"]}
        self.assertEqual(failed, {"catalog", "revision"})


if __name__ == "__main__":
    unittest.main()
