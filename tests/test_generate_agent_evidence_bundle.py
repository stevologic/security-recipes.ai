from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.generate_agent_evidence_bundle import build_manifest, load_events


class EvidenceBundleTests(unittest.TestCase):
    def test_canonical_receipt_events_are_normalized_and_complete(self) -> None:
        payload = [
            {
                "run_id": "run-1",
                "workflow_id": "vulnerable-dependencies",
                "event_class": "run_closed",
                "closed_at": "2026-07-10T12:00:00-07:00",
                "final_state": "completed",
            },
            {
                "run_id": "run-1",
                "workflow_id": "vulnerable-dependencies",
                "event_class": "human_approval",
                "approved_at": "2026-07-10T18:00:00Z",
                "approver": "reviewer@example.test",
            },
            {
                "run_id": "run-1",
                "workflow_id": "vulnerable-dependencies",
                "event_class": "verifier_result",
                "completed_at": "2026-07-10T18:30:00+00:00",
                "result": "passed",
            },
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "events.json"
            source.write_text(json.dumps(payload), encoding="utf-8")

            events = load_events(source)
            manifest = build_manifest("test-program", "2026-Q3", source, events)

        self.assertEqual(
            [event["event_class"] for event in events],
            ["human_approval", "verifier_result", "run_closed"],
        )
        self.assertEqual(events[-1]["timestamp"], "2026-07-10T19:00:00Z")
        self.assertEqual(events[-1]["closed_at"], "2026-07-10T19:00:00Z")
        self.assertEqual(manifest["control_gaps"], [])
        self.assertEqual(manifest["workflows"], {"vulnerable-dependencies": 3})
        run = manifest["runs"][0]
        self.assertEqual(run["outcome"], "completed")
        self.assertTrue(run["has_terminal_event"])
        self.assertTrue(run["has_review_decision"])
        self.assertTrue(run["has_verification"])
        self.assertEqual(run["reviewers"], ["reviewer@example.test"])

    def test_legacy_jsonl_aliases_remain_supported(self) -> None:
        payload = [
            {
                "run_id": "legacy-1",
                "workflow": "sast-findings",
                "event_type": "tests_passed",
                "timestamp": "2026-07-10T10:00:00Z",
            },
            {
                "run_id": "legacy-1",
                "workflow": "sast-findings",
                "event_type": "review_approved",
                "timestamp": "2026-07-10T10:01:00Z",
                "actor": "legacy-reviewer",
            },
            {
                "run_id": "legacy-1",
                "workflow": "sast-findings",
                "event_type": "pr_opened",
                "timestamp": "2026-07-10T10:02:00Z",
            },
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "events.jsonl"
            source.write_text("\n".join(json.dumps(event) for event in payload), encoding="utf-8")
            events = load_events(source)
            manifest = build_manifest("test-program", "legacy", source, events)

        self.assertEqual(events[0]["event_class"], "tests_passed")
        self.assertEqual(events[0]["workflow_id"], "sast-findings")
        self.assertEqual(manifest["control_gaps"], [])
        self.assertEqual(manifest["runs"][0]["workflow_id"], "sast-findings")

    def test_conflicting_aliases_and_missing_timestamp_are_rejected(self) -> None:
        cases = [
            {
                "run_id": "bad-alias",
                "event_class": "run_closed",
                "event_type": "run_failed",
                "timestamp": "2026-07-10T10:00:00Z",
            },
            {
                "run_id": "missing-time",
                "event_class": "run_closed",
            },
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            for index, payload in enumerate(cases):
                source = Path(tmpdir) / f"bad-{index}.json"
                source.write_text(json.dumps([payload]), encoding="utf-8")
                with self.subTest(payload=payload), self.assertRaisesRegex(ValueError, rf"event 1"):
                    load_events(source)


if __name__ == "__main__":
    unittest.main()
