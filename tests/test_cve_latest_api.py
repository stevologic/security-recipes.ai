from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import patch

import mcp_server
from scripts.cve_latest_projection import project_latest
from tests.test_cve_latest_projection import FakeCatalog, MANIFEST, NOW, record
from tests.test_cve_recipe_catalog import public_search_request


class LatestAPITests(unittest.TestCase):
    def test_website_and_mcp_use_same_source_revision_and_records(self):
        catalog = FakeCatalog([record()])
        with patch.object(mcp_server, "cve_catalog", catalog), patch.object(mcp_server, "datetime") as clock:
            clock.now.return_value = NOW
            api = asyncio.run(mcp_server.cve_latest_projection(public_search_request("")))
            tool = asyncio.run(mcp_server.recipes_cve_catalog_info())
        self.assertEqual(json.loads(api.body), tool["latest_projection"])
        self.assertEqual(api.headers["Cache-Control"], "no-store")

    def test_stale_website_and_mcp_preserve_original_dates_and_history(self):
        catalog = FakeCatalog([record()], {**MANIFEST, "catalog_updated_at": "2026-10-16T17:15:48Z"})
        with patch.object(mcp_server, "cve_catalog", catalog), patch.object(mcp_server, "datetime") as clock:
            clock.now.return_value = NOW
            api = asyncio.run(mcp_server.cve_latest_projection(public_search_request("format=html")))
            tool = asyncio.run(mcp_server.recipes_cve_catalog_info())
        self.assertIn(b"Fresh CVE updates are unavailable", api.body)
        self.assertEqual(tool["latest_projection"]["records"], [])
        self.assertEqual(catalog.records, [record()])

    def test_unavailable_backend_never_returns_stale_cards(self):
        with patch.object(mcp_server, "project_runtime", side_effect=ValueError("bad snapshot")):
            response = asyncio.run(mcp_server.cve_latest_projection(public_search_request("")))
        self.assertEqual(response.status_code, 503)
        self.assertEqual(json.loads(response.body)["records"], [])

    def test_mcp_info_cannot_mix_a_and_b_snapshots(self):
        catalog = FakeCatalog([record()])
        changed = {**project_latest(MANIFEST, [record()], NOW), "source_revision": "b" * 64}
        with patch.object(mcp_server, "cve_catalog", catalog), patch.object(mcp_server, "project_runtime", return_value=changed):
            tool = asyncio.run(mcp_server.recipes_cve_catalog_info())
        self.assertEqual(tool["latest_projection"]["status"], "unavailable")
        self.assertEqual(tool["manifest"]["shard_set_sha256"], "a" * 64)

    def test_request_time_projection_expires_without_redeployment(self):
        first = project_latest(MANIFEST, [record()], NOW)
        from datetime import timedelta
        later = project_latest(MANIFEST, [record()], NOW + timedelta(days=4))
        self.assertEqual(first["status"], "ready")
        self.assertEqual(later["status"], "stale")
        self.assertEqual(first["source_revision"], later["source_revision"])
