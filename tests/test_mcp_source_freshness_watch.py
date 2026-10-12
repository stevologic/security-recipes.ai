from __future__ import annotations

import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

from mcp_server import AgenticSourceFreshnessWatch


class MCPSourceFreshnessWatchTests(unittest.TestCase):
    def test_serves_live_decisions_against_today_not_frozen_current(self) -> None:
        pack = {
            "buyer_views": [],
            "commercialization_path": {},
            "enterprise_adoption_packet": {},
            "failures": [],
            "freshness_contract": {"maximum_due_watch_sources": 0, "as_of": "2026-05-04"},
            "freshness_summary": {
                "status": "source_freshness_ready",
                "watch_decision_counts": {"current": 1},
            },
            "generated_at": "2026-05-04",
            "primary_watchlist_coverage": [],
            "schema_version": "1.0",
            "source_artifacts": {},
            "source_catalog": [],
            "watch_sources": [
                {
                    "blockers": [],
                    "decision": "current",
                    "id": "mcp-spec",
                    "last_reviewed": "2026-08-01",
                    "path": "data/assurance/example.json",
                    "reference_count": 4,
                    "review_cadence_days": 30,
                    "review_due_at": "2026-08-31",
                    "title": "MCP spec",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "watch.json"
            path.write_text(json.dumps(pack), encoding="utf-8")
            watch = AgenticSourceFreshnessWatch(str(path))
            with patch("mcp_server.today_utc", return_value=date(2026, 9, 27)):
                payload = watch.get()

        self.assertTrue(payload["available"])
        self.assertEqual(payload["evaluated_as_of"], "2026-09-27")
        self.assertEqual(payload["watch_sources"][0]["decision"], "review_due")
        self.assertEqual(
            payload["freshness_summary"]["status"],
            "needs_freshness_review",
        )
        self.assertNotEqual(payload["freshness_summary"]["status"], "source_freshness_ready")


if __name__ == "__main__":
    unittest.main()
