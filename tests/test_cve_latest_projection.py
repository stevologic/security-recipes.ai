from __future__ import annotations

import copy
import gzip
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import yaml

from scripts.cve_latest_projection import (
    project_directory, project_latest, project_runtime, render_latest, utc_timestamp,
)

NOW = utc_timestamp("2026-10-25T12:00:00Z")
MANIFEST = {"schema_version": 2, "shard_set_sha256": "a" * 64,
            "catalog_updated_at": "2026-10-25T07:00:22Z"}


def record(cve="CVE-2026-1000", published="2026-10-25", **extra):
    return {"cve": cve, "published": published, "severity": "high", "score": 8.1,
            "title": "Source-backed title", "kev": False, **extra}


class FakeCatalog:
    def __init__(self, records, manifest=None):
        self.records = records
        self.manifest = manifest or copy.deepcopy(MANIFEST)
        self.searches = 0

    def info(self):
        return {"manifest": copy.deepcopy(self.manifest)}

    def active_revision(self):
        return self.manifest["shard_set_sha256"]

    def search_page(self, query, *, limit, expected_revision):
        assert query == "" and limit == 100 and expected_revision == self.active_revision()
        self.searches += 1
        return copy.deepcopy(self.records), len(self.records)


class LatestProjectionTests(unittest.TestCase):
    def test_mixed_records_preserve_source_dates_and_history(self):
        records = [record(), record("CVE-2026-1001", "2026-10-22"),
                   record("CVE-2026-1002", "2026-10-24"), record("CVE-2026-1003", "2026-10-26")]
        original = copy.deepcopy(records)
        result = project_latest(MANIFEST, records, NOW)
        self.assertEqual([x["cve"] for x in result["records"]], ["CVE-2026-1000", "CVE-2026-1002"])
        self.assertEqual(result["source_updated_at"], MANIFEST["catalog_updated_at"])
        self.assertEqual(result["records"][0]["published"], "2026-10-25")
        self.assertEqual(records, original)

    def test_stale_only_and_aggregator_failure_withhold_instead_of_relabel(self):
        stale = {**MANIFEST, "catalog_updated_at": "2026-10-16T17:15:48Z"}
        catalog = FakeCatalog([record()], stale)
        self.assertEqual(project_runtime(catalog, NOW)["status"], "stale")
        self.assertEqual(catalog.searches, 0)
        result = project_latest(MANIFEST, [record(published="2026-10-16")], NOW)
        self.assertEqual(result["status"], "empty")
        rendered = render_latest(result)
        self.assertIn("Fresh CVE updates are unavailable", rendered)
        self.assertIn("historical CVE catalog", rendered)
        self.assertNotIn("CVE-2026-1000", rendered)

    def test_exact_time_boundaries(self):
        published = record(published="2026-10-23")
        boundary = utc_timestamp("2026-10-26T00:00:00Z")
        source = {**MANIFEST, "catalog_updated_at": "2026-10-25T12:00:00Z"}
        self.assertEqual(project_latest(source, [published], boundary - timedelta(microseconds=1))["status"], "ready")
        self.assertEqual(project_latest(source, [published], boundary)["status"], "empty")
        source_boundary = utc_timestamp("2026-10-26T19:00:22Z")
        self.assertEqual(project_latest(MANIFEST, [record(published="2026-10-26")], source_boundary)["status"], "stale")
        self.assertEqual(project_latest(MANIFEST, [record(published="2026-10-26")], source_boundary - timedelta(microseconds=1))["status"], "ready")

    def test_future_or_missing_source_time_fails_closed(self):
        for value in (None, "bad", "2026-10-26T00:00:00Z", "2026-10-25"):
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                project_latest({**MANIFEST, "catalog_updated_at": value}, [record()], NOW)

    def test_idempotent_concurrent_readers_never_mutate_catalog(self):
        catalog = FakeCatalog([record()])
        original = copy.deepcopy(catalog.records)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: project_runtime(catalog, NOW), range(32)))
        self.assertTrue(all(result == results[0] for result in results))
        self.assertEqual(catalog.records, original)

    def test_concurrent_catalog_cutover_is_rejected(self):
        catalog = FakeCatalog([record()])
        original = catalog.search_page

        def swapped(*args, **kwargs):
            result = original(*args, **kwargs)
            catalog.manifest["shard_set_sha256"] = "b" * 64
            return result

        catalog.search_page = swapped
        with self.assertRaisesRegex(ValueError, "catalog changed"):
            project_runtime(catalog, NOW)

    def test_html_is_escaped_bounded_and_accessible(self):
        records = [record(f"CVE-2026-{1000+i}", title='<script>alert("x")</script>') for i in range(30)]
        result = project_latest(MANIFEST, records, NOW)
        self.assertEqual(len(result["records"]), 10)
        rendered = render_latest(result)
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn('aria-hidden="true" inert', rendered)
        self.assertIn('aria-label="Pause latest CVE ticker"', rendered)

    def test_runtime_candidate_bound_preserves_full_projection_order(self):
        records = [record(f"CVE-2026-{1000+i}", score=4 + i % 7,
                          severity="critical" if i % 3 == 0 else "medium") for i in range(150)]
        bounded = sorted(records, key=lambda row: (row["published"], row["cve"]), reverse=True)[:100]
        self.assertEqual(project_latest(MANIFEST, records, NOW),
                         project_latest(MANIFEST, bounded, NOW))

    def test_directory_snapshot_integrity_and_history_preservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "indexes").mkdir()
            blob = gzip.compress(json.dumps({"schema_version": 2, "year": 2026,
                                              "records": [record(), record(published="2026-10-16")]}).encode())
            partition = root / "indexes/2026.json.gz"
            partition.write_bytes(blob)
            manifest = {**MANIFEST, "complete_index": {"partitions": [{"year": 2026,
                        "path": "indexes/2026.json.gz", "sha256": hashlib.sha256(blob).hexdigest()}]}}
            manifest_file = root / "manifest.json"
            manifest_file.write_text(json.dumps(manifest))
            before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
            result = project_directory(root, NOW)
            self.assertEqual(result["status"], "ready")
            self.assertEqual({p: p.read_bytes() for p in before}, before)
            original = Path.read_bytes

            def read_and_swap(path):
                value = original(path)
                if path == partition:
                    manifest_file.write_text(json.dumps({**manifest, "shard_set_sha256": "b" * 64}))
                return value

            with patch.object(Path, "read_bytes", read_and_swap), self.assertRaisesRegex(ValueError, "catalog changed"):
                project_directory(root, NOW)

    def test_prune_command_reports_stale_without_changing_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            catalog = root / "catalog"
            catalog.mkdir()
            manifest = json.dumps({**MANIFEST, "catalog_updated_at": "2026-10-16T17:15:48Z"})
            (catalog / "manifest.json").write_text(manifest)
            historical = catalog / "historical.json"
            historical.write_text(json.dumps(record()))
            command = [sys.executable, "scripts/prune_cve_latest.py", "--catalog", str(catalog),
                       "--output", str(root / "output"), "--as-of", NOW.isoformat()]
            first = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(first.returncode, 1)
            report = (root / "output/latest.json").read_bytes()
            second = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(second.returncode, 1)
            self.assertEqual((root / "output/latest.json").read_bytes(), report)
            self.assertEqual((catalog / "manifest.json").read_text(), manifest)
            self.assertTrue(historical.exists())

    def test_independent_workflow_has_no_mutation_or_dispatch_authority(self):
        source = Path(".github/workflows/cve-latest-prune.yml").read_text()
        workflow = yaml.load(source, Loader=yaml.BaseLoader)
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertEqual(len(workflow["on"]["schedule"]), 1)
        self.assertNotIn("needs", workflow["jobs"]["prune"])
        self.assertNotRegex(source, r"workflow_run|gh workflow|git push|pull-requests:|XAI_API_KEY|NVD_API_KEY")
        nginx = Path("docker/nginx/default.conf").read_text()
        self.assertIn('proxy_pass $latest_api/api/cve-latest?format=html;', nginx)
        self.assertIn('ssi on;', nginx)
        self.assertIn('add_header Cache-Control "no-store";', nginx)
        template = Path("_includes/layouts/home-static.html").read_text()
        self.assertIn('<!--# include virtual="/_fragments/cve-latest" -->', template)
        self.assertNotIn('for item in latestReviewedCves', template)
