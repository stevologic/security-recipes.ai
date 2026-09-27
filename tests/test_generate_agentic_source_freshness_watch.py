from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

from scripts.generate_agentic_source_freshness_watch import (
    DUE_WATCH_FAILURE,
    evaluate_pack_as_of,
    resolve_as_of,
    review_decision,
    structural_failures,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "generate_agentic_source_freshness_watch.py"
PROFILE = ROOT / "data" / "assurance" / "agentic-source-freshness-profile.json"


class SourceFreshnessAsOfTests(unittest.TestCase):
    CONTRACT = {"as_of": "2026-05-04"}

    def test_as_of_defaults_to_today_and_uses_contract_only_as_a_floor(self) -> None:
        self.assertEqual(
            resolve_as_of(None, self.CONTRACT, today=date(2026, 9, 27)),
            date(2026, 9, 27),
        )
        self.assertEqual(
            resolve_as_of("2026-09-27", self.CONTRACT, today=date(2026, 1, 1)),
            date(2026, 9, 27),
        )
        self.assertEqual(
            resolve_as_of("2026-04-01", self.CONTRACT, today=date(2026, 9, 27)),
            date(2026, 5, 4),
        )
        self.assertNotEqual(
            resolve_as_of(None, self.CONTRACT, today=date(2026, 9, 27)),
            date(2026, 5, 4),
        )

    def test_pinned_as_of_marks_overdue_sources_review_due(self) -> None:
        decision, blockers = review_decision(
            date(2026, 8, 1),
            30,
            date(2026, 9, 27),
            3,
            False,
        )
        current, _ = review_decision(
            date(2026, 8, 1),
            30,
            date(2026, 8, 15),
            3,
            False,
        )
        self.assertEqual(decision, "review_due")
        self.assertTrue(blockers)
        self.assertEqual(current, "current")

    def test_due_watch_failures_are_editorial_and_not_structural(self) -> None:
        failures = [DUE_WATCH_FAILURE, "profile schema_version must be 1.0"]
        self.assertEqual(
            structural_failures(failures),
            ["profile schema_version must be 1.0"],
        )

    def test_written_pack_omits_editorial_due_failures(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "watch.json"
            generate = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--repo-root",
                    str(ROOT),
                    "--profile",
                    str(PROFILE),
                    "--output",
                    str(output),
                    "--as-of",
                    "2026-09-27",
                    "--generated-at",
                    "2026-09-27",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(generate.returncode, 0, generate.stderr)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertNotIn(DUE_WATCH_FAILURE, payload.get("failures") or [])
            self.assertEqual(payload["freshness_summary"]["status"], "source_freshness_ready")
            self.assertIn("review_due", payload["freshness_summary"]["watch_decision_counts"])

    def test_evaluate_pack_as_of_cannot_freeze_at_current(self) -> None:
        pack = {
            "failures": [],
            "freshness_contract": {"maximum_due_watch_sources": 0},
            "primary_watchlist_coverage": [],
            "source_catalog": [],
            "watch_sources": [
                {
                    "id": "mcp-spec",
                    "decision": "current",
                    "last_reviewed": "2026-08-01",
                    "path": "data/assurance/example.json",
                    "reference_count": 4,
                    "review_cadence_days": 30,
                    "review_due_at": "2026-08-31",
                }
            ],
        }
        frozen = evaluate_pack_as_of(pack, date(2026, 5, 4))
        live = evaluate_pack_as_of(pack, date(2026, 9, 27))
        self.assertEqual(frozen["watch_sources"][0]["decision"], "current")
        self.assertEqual(live["watch_sources"][0]["decision"], "review_due")
        self.assertEqual(live["evaluated_as_of"], "2026-09-27")
        self.assertIn(DUE_WATCH_FAILURE, live["failures"])
        self.assertEqual(live["freshness_summary"]["status"], "needs_freshness_review")

    def test_check_uses_the_same_pinned_as_of_as_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "watch.json"
            generate = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--repo-root",
                    str(ROOT),
                    "--profile",
                    str(PROFILE),
                    "--output",
                    str(output),
                    "--as-of",
                    "2026-05-04",
                    "--generated-at",
                    "2026-05-04",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(generate.returncode, 0, generate.stderr)
            check = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--repo-root",
                    str(ROOT),
                    "--profile",
                    str(PROFILE),
                    "--output",
                    str(output),
                    "--as-of",
                    "2026-05-04",
                    "--generated-at",
                    "2026-05-04",
                    "--check",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(check.returncode, 0, check.stderr)
            mismatched = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--repo-root",
                    str(ROOT),
                    "--profile",
                    str(PROFILE),
                    "--output",
                    str(output),
                    "--as-of",
                    "2026-09-27",
                    "--generated-at",
                    "2026-05-04",
                    "--check",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(mismatched.returncode, 1)
            inferred = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--repo-root",
                    str(ROOT),
                    "--profile",
                    str(PROFILE),
                    "--output",
                    str(output),
                    "--check",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(inferred.returncode, 0, inferred.stderr)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["generated_at"], "2026-05-04")


if __name__ == "__main__":
    unittest.main()
