from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.pick_leftover_review_queue import build_queue, inventory_leftover_pages


ROOT = Path(__file__).resolve().parents[1]


def _write_recipe(directory: Path, name: str, *, cve: str, severity: str, title: str, body: str) -> None:
    (directory / name).write_text(
        "\n".join(
            [
                "---",
                f'title: "{title}"',
                f'severity: "{severity}"',
                f'cve: "{cve}"',
                'ghsa: "GHSA-1111-2222-3333"',
                'ecosystem: "python/pip"',
                "---",
                "",
                body,
                "",
            ]
        ),
        encoding="utf-8",
    )


class LeftoverReviewQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cve_dir = self.root / "cve"
        self.cve_dir.mkdir()
        self.state_path = self.root / "leftover-review-state.json"
        self.state_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "daily_limit": 100,
                    "severity_order": ["critical", "high", "medium", "low"],
                    "reviewed_cves": ["CVE-2026-00001"],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_queue_drains_highs_before_mediums_and_respects_the_daily_limit(self) -> None:
        _write_recipe(
            self.cve_dir,
            "already-reviewed.md",
            cve="CVE-2026-00001",
            severity="high",
            title="CVE-2026-00001: reviewed leftover",
            body="GHAD first_patched is 1.0.1.",
        )
        _write_recipe(
            self.cve_dir,
            "skip-family.md",
            cve="CVE-2026-00002",
            severity="high",
            title="CVE-2026-00002: Linux leftover dump",
            body="Linux kernel leftover. GHAD first_patched is null.",
        )
        _write_recipe(
            self.cve_dir,
            "qnap-skip.md",
            cve="CVE-2026-00003",
            severity="high",
            title="CVE-2026-00003: QNAP leftover dump",
            body="QNAP leftover. GHAD first_patched is null.",
        )
        _write_recipe(
            self.cve_dir,
            "medium.md",
            cve="CVE-2026-00004",
            severity="medium",
            title="CVE-2026-00004: Docling leftover dump",
            body="GHAD first_patched is 2.91.0.",
        )
        _write_recipe(
            self.cve_dir,
            "high-b.md",
            cve="CVE-2026-00006",
            severity="high",
            title="CVE-2026-00006: Traefik leftover dump",
            body="GHAD first_patched is 3.7.3.",
        )
        _write_recipe(
            self.cve_dir,
            "high-a.md",
            cve="CVE-2026-00005",
            severity="high",
            title="CVE-2026-00005: PyJWT leftover dump",
            body="GHAD first_patched is 2.12.0.",
        )
        _write_recipe(
            self.cve_dir,
            "no-claim.md",
            cve="CVE-2026-00007",
            severity="low",
            title="CVE-2026-00007: leftover without claims",
            body="No advisory floor claim is present.",
        )

        queue = build_queue(cve_dir=self.cve_dir, state_path=self.state_path, limit=2)
        self.assertEqual([row["cve"] for row in queue["selected"]], ["CVE-2026-00005", "CVE-2026-00006"])
        self.assertEqual(queue["remaining"], {"critical": 0, "high": 2, "medium": 1, "low": 0})
        self.assertEqual(queue["selected_total"], 2)

        medium_queue = build_queue(cve_dir=self.cve_dir, state_path=self.state_path, limit=10)
        self.assertEqual(
            [row["cve"] for row in medium_queue["selected"]],
            ["CVE-2026-00005", "CVE-2026-00006", "CVE-2026-00004"],
        )

    def test_tracked_state_excludes_already_reviewed_leftover_gold(self) -> None:
        _write_recipe(
            self.cve_dir,
            "open.md",
            cve="CVE-2026-00008",
            severity="medium",
            title="CVE-2026-00008: leftover dump",
            body="GHAD first_patched is 1.2.3.",
        )
        rows = inventory_leftover_pages(self.cve_dir, {"CVE-2026-00008"})
        self.assertEqual(rows, [])

    def test_repository_state_file_declares_a_100_page_daily_limit(self) -> None:
        state = json.loads((ROOT / "data" / "cve" / "leftover-review-state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["daily_limit"], 100)
        self.assertEqual(state["severity_order"], ["critical", "high", "medium", "low"])
        self.assertIn("CVE-2026-46520", state["reviewed_cves"])
        self.assertGreaterEqual(len(state["reviewed_cves"]), 100)


if __name__ == "__main__":
    unittest.main()
