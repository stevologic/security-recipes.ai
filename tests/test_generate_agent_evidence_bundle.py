from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.generate_agent_evidence_bundle import (
    BUNDLE_FILENAMES,
    BUNDLE_SCHEMA,
    build_manifest,
    load_events,
    write_bundle,
)


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
                "workflow_id": "sast-findings",
                "event_class": "run_closed",
                "event_type": "run_failed",
                "timestamp": "2026-07-10T10:00:00Z",
            },
            {
                "run_id": "missing-time",
                "workflow_id": "sast-findings",
                "event_class": "run_closed",
            },
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            for index, payload in enumerate(cases):
                source = Path(tmpdir) / f"bad-{index}.json"
                source.write_text(json.dumps([payload]), encoding="utf-8")
                with self.subTest(payload=payload), self.assertRaisesRegex(ValueError, rf"event 1"):
                    load_events(source)

    def test_missing_or_mixed_workflow_ownership_is_rejected(self) -> None:
        cases = {
            "missing": [
                {
                    "run_id": "run-missing",
                    "event_class": "run_closed",
                    "timestamp": "2026-07-10T10:00:00Z",
                }
            ],
            "mixed": [
                {
                    "run_id": "run-mixed",
                    "workflow_id": "sast-findings",
                    "event_class": "tests_passed",
                    "timestamp": "2026-07-10T10:00:00Z",
                },
                {
                    "run_id": "run-mixed",
                    "workflow_id": "vulnerable-dependencies",
                    "event_class": "run_closed",
                    "timestamp": "2026-07-10T10:01:00Z",
                },
            ],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            for label, payload in cases.items():
                source = Path(tmpdir) / f"{label}.json"
                source.write_text(json.dumps(payload), encoding="utf-8")
                expected = "workflow_id" if label == "missing" else "mixes workflow IDs"
                with self.subTest(label=label), self.assertRaisesRegex(ValueError, expected):
                    load_events(source)

    def test_transactional_bundle_replaces_extras_and_cleans_only_stale_siblings(self) -> None:
        payload = [
            {
                "run_id": "run-1",
                "workflow_id": "sast-findings",
                "event_class": "run_closed",
                "timestamp": "2026-07-10T10:00:00Z",
            }
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            parent = Path(tmpdir)
            source = parent / "events.json"
            source.write_text(json.dumps(payload), encoding="utf-8")
            events = load_events(source)
            manifest = build_manifest("test-program", "2026-Q3", source, events)

            output = parent / "bundle"
            output.mkdir()
            (output / "manifest.json").write_text(
                json.dumps({"schema": BUNDLE_SCHEMA}),
                encoding="utf-8",
            )
            (output / "obsolete.json").write_text("{}", encoding="utf-8")
            (output / "obsolete").mkdir()
            (output / "obsolete" / "nested.txt").write_text("old", encoding="utf-8")

            stale_stage = parent / ".bundle.stage-abandoned"
            stale_stage.mkdir()
            (stale_stage / "events.normalized.json").write_text("[]", encoding="utf-8")
            stale_backup = parent / ".bundle.backup-abandoned"
            stale_backup.mkdir()
            (stale_backup / "manifest.json").write_text(
                json.dumps({"schema": BUNDLE_SCHEMA}),
                encoding="utf-8",
            )
            (stale_backup / "old-extra.txt").write_text("old", encoding="utf-8")
            unowned_stage = parent / ".bundle.stage-operator-owned"
            unowned_stage.mkdir()
            (unowned_stage / "operator-note.txt").write_text("keep", encoding="utf-8")
            unowned_backup = parent / ".bundle.backup-operator-owned"
            unowned_backup.mkdir()
            (unowned_backup / "manifest.json").write_text("{}", encoding="utf-8")
            unrelated = parent / ".other.stage-abandoned"
            unrelated.mkdir()

            old = time.time() - (2 * 24 * 60 * 60)
            for path in (
                stale_stage,
                stale_backup,
                unowned_stage,
                unowned_backup,
                unrelated,
            ):
                os.utime(path, (old, old))

            write_bundle(output, events, manifest)

            self.assertEqual({path.name for path in output.iterdir()}, set(BUNDLE_FILENAMES))
            self.assertFalse(stale_stage.exists())
            self.assertFalse(stale_backup.exists())
            self.assertTrue(unowned_stage.exists())
            self.assertTrue(unowned_backup.exists())
            self.assertTrue(unrelated.exists())
            written_manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(written_manifest["owned_files"], list(BUNDLE_FILENAMES))

    def test_failed_publish_restores_prior_bundle_and_cleans_transaction_artifacts(self) -> None:
        payload = [
            {
                "run_id": "run-1",
                "workflow_id": "sast-findings",
                "event_class": "run_closed",
                "timestamp": "2026-07-10T10:00:00Z",
            }
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            parent = Path(tmpdir)
            source = parent / "events.json"
            source.write_text(json.dumps(payload), encoding="utf-8")
            events = load_events(source)
            manifest = build_manifest("test-program", "2026-Q3", source, events)
            output = parent / "bundle"
            output.mkdir()
            (output / "manifest.json").write_text(
                json.dumps({"schema": BUNDLE_SCHEMA}),
                encoding="utf-8",
            )
            (output / "prior.txt").write_text("preserve on rollback", encoding="utf-8")

            real_replace = os.replace
            failed = False

            def fail_stage_publish(source_path: str | Path, destination_path: str | Path) -> None:
                nonlocal failed
                source_candidate = Path(source_path)
                destination_candidate = Path(destination_path)
                if (
                    not failed
                    and source_candidate.name.startswith(".bundle.stage-")
                    and destination_candidate == output
                ):
                    failed = True
                    raise OSError("injected publish failure")
                real_replace(source_path, destination_path)

            with patch(
                "scripts.generate_agent_evidence_bundle.os.replace",
                side_effect=fail_stage_publish,
            ):
                with self.assertRaisesRegex(OSError, "injected publish failure"):
                    write_bundle(output, events, manifest)

            self.assertEqual((output / "prior.txt").read_text(encoding="utf-8"), "preserve on rollback")
            self.assertFalse(any(parent.glob(".bundle.stage-*")))
            self.assertFalse(any(parent.glob(".bundle.backup-*")))
            self.assertFalse((parent / ".bundle.lock").exists())


if __name__ == "__main__":
    unittest.main()
