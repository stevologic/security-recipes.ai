from __future__ import annotations

import copy
import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from scripts import cve_ai_enrichment as enrichment
from scripts import enhance_cve_catalog as worker
from scripts import sync_cve_catalog as sync
from scripts.cve_catalog_release import _target_lock, CatalogReleaseError
from scripts.check_cve_catalog_update import enrichment_health
from tests.test_cve_ai_enrichment import cached_enrichment
from tests.test_cve_latest_projection import NOW
from tests.test_sync_cve_catalog import normalize, nvd_record, write_catalog_fixture


class ThreeStageTests(unittest.TestCase):
    def test_source_and_ai_writer_lock_excludes_concurrent_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "catalog"
            with _target_lock(target):
                with self.assertRaises(CatalogReleaseError):
                    with _target_lock(target):
                        self.fail("two writers acquired the catalog")
    def fixture(self):
        temp = tempfile.TemporaryDirectory(prefix="test-three-stage-", dir=sync.ROOT)
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        output, content, _ = write_catalog_fixture(root, [normalize(nvd_record("CVE-2024-1234"))])
        return output, content, root / "enrichments.json", root / "generated.json"

    def test_missing_provider_keeps_baseline_unchanged(self):
        output, content, cache, generated = self.fixture()
        before = {p: p.read_bytes() for p in output.rglob("*") if p.is_file()}
        with patch.object(sync, "cache_feed", side_effect=AssertionError("source stage invoked")):
            report = worker.enhance_snapshot(output, content, cache, generated, limit=20, client=None)
        self.assertGreater(report["ai_enrichment"]["selected"], 0)
        self.assertFalse(report["ai_enrichment"]["api_enabled"])
        self.assertFalse(cache.exists())
        self.assertEqual({p: p.read_bytes() for p in before}, before)

    def test_provider_failure_preserves_last_good_snapshot(self):
        output, content, cache, generated = self.fixture()
        before = (output / "manifest.json").read_bytes()

        class Failed:
            def enrich(self, source):
                raise enrichment.EnrichmentError("simulated outage")

        report = worker.enhance_snapshot(output, content, cache, generated, limit=20, client=Failed())
        self.assertEqual(report["ai_enrichment"]["failed"], 1)
        self.assertEqual((output / "manifest.json").read_bytes(), before)
        self.assertFalse(cache.exists())

    def test_success_preserves_facts_and_does_not_recharge_unchanged_records(self):
        output, content, cache, generated = self.fixture()
        before = json.loads((output / "manifest.json").read_bytes())
        calls = []

        class Success:
            def enrich(self, source):
                calls.append(copy.deepcopy(source))
                return cached_enrichment(source, generated_at=NOW)

        first = worker.enhance_snapshot(output, content, cache, generated, limit=20, client=Success())
        self.assertEqual(first["ai_enrichment"]["generated"], 1)
        after = json.loads((output / "manifest.json").read_bytes())
        for field in ("sources", "scope", "catalog_updated_at"):
            self.assertEqual(before[field], after[field])
        self.assertEqual(before["totals"]["catalog_records"], after["totals"]["catalog_records"])
        last_good = (output / "manifest.json").read_bytes()
        second = worker.enhance_snapshot(output, content, cache, generated, limit=20, client=Success())
        self.assertEqual(second["ai_enrichment"]["selected"], 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual((output / "manifest.json").read_bytes(), last_good)

    def test_source_change_during_provider_call_cannot_be_overwritten(self):
        output, content, cache, generated = self.fixture()
        target = output / "manifest.json"
        newer = json.loads(target.read_bytes())
        newer["catalog_updated_at"] = "2026-10-25T13:00:00Z"

        class Raced:
            def enrich(self, source):
                target.write_text(json.dumps(newer))
                return cached_enrichment(source, generated_at=NOW)

        with self.assertRaisesRegex(ValueError, "source snapshot changed"):
            worker.enhance_snapshot(output, content, cache, generated, limit=20, client=Raced())
        self.assertEqual(json.loads(target.read_bytes()), newer)
        self.assertFalse(cache.exists())

    def test_separate_stage_clocks_keys_and_shared_writer_lock(self):
        source = yaml.load(Path(".github/workflows/cve-catalog-sync.yml").read_text(), Loader=yaml.BaseLoader)
        ai = yaml.load(Path(".github/workflows/cve-ai-enhancement.yml").read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(source["concurrency"]["group"], "cve-catalog-${{ inputs.stage == 'enhancement' && 'enhancement' || 'source' }}")
        self.assertNotEqual(source["on"]["schedule"], ai["on"]["schedule"])
        stage = next(s for s in source["jobs"]["sync"]["steps"] if s.get("id") == "synchronize")
        self.assertIn("--disable-ai-enrichment", stage["run"])
        self.assertIn("inputs.stage == 'enhancement'", stage["env"]["XAI_API_KEY"])
        self.assertIn("inputs.stage != 'enhancement'", stage["env"]["NVD_API_KEY"])
        self.assertIn("scripts/enhance_cve_catalog.py", stage["run"])
        self.assertNotIn("workflow_run", ai["on"])
        enqueue = ai["jobs"]["enqueue"]["steps"][0]
        self.assertEqual(enqueue["env"]["ENRICHMENT_LIMIT"], "${{ vars.XAI_ENRICHMENT_LIMIT || '20' }}")
        self.assertIn('--field "ai_enrichment_limit=$ENRICHMENT_LIMIT"', enqueue["run"])
        open_step = next(s for s in source["jobs"]["sync"]["steps"] if s.get("id") == "catalog-pr")
        delivery = next(s for s in source["jobs"]["sync"]["steps"] if s.get("id") == "catalog-delivery")
        self.assertIn('CREATE_FLAGS+=(--draft)', open_step["run"])
        self.assertIn('git push origin "HEAD:$BRANCH"\nelif git fetch', open_step["run"])
        self.assertIn("inputs.stage != 'enhancement'", delivery["env"]["AUTO_MERGE_ENABLED"])
        self.assertIn("not an automatic rebase", delivery["run"])
        self.assertFalse(enrichment_health({"stage": "source"})["healthy"])
        self.assertTrue(enrichment_health({"stage": "source"})["deferred"])

    def test_old_ai_base_cannot_reach_publication_and_source_does_not_wait(self):
        workflow = yaml.load(Path(".github/workflows/cve-catalog-sync.yml").read_text(), Loader=yaml.BaseLoader)
        step = next(s for s in workflow["jobs"]["sync"]["steps"] if s.get("id") == "catalog-pr")
        preflight = step["run"].split('          if [ -z', 1)[0]
        # YAML strips indentation, so split at the actual first status query.
        preflight = preflight.split('if [ -z "$(git status', 1)[0]
        harness = 'git() { echo "$BASE_SHA"; }; gh() { echo "$CURRENT_SHA"; };\n'
        for stage, current, allowed in (("enhancement", "a" * 40, True),
                                        ("enhancement", "b" * 40, False),
                                        ("source", "b" * 40, True)):
            with self.subTest(stage=stage, current=current), tempfile.TemporaryDirectory() as directory:
                env = {**os.environ, "BASE_SHA": "a" * 40, "CURRENT_SHA": current,
                       "GITHUB_REPOSITORY": "test/test", "GITHUB_DEFAULT_BRANCH": "main",
                       "GITHUB_OUTPUT": str(Path(directory) / "output")}
                script = harness + preflight.replace("${{ inputs.stage }}", stage) + '\necho PUBLICATION_ALLOWED\n'
                result = subprocess.run(["bash", "-eu", "-c", script], env=env, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual("PUBLICATION_ALLOWED" in result.stdout, allowed)
                if not allowed:
                    self.assertIn("changed=false", Path(env["GITHUB_OUTPUT"]).read_text())

    def test_offline_and_disabled_ai_never_construct_a_provider_client(self):
        report = {"ai_enrichment": {"selected": 0, "generated": 0, "failed": 0}}
        for flag in ("--offline", "--dry-run", "--disable-ai-enrichment"):
            args = sync.parse_args([flag])
            with self.subTest(flag=flag), patch.dict(os.environ, {"XAI_API_KEY": "test-placeholder"}), \
                    patch.object(sync, "parse_args", return_value=args), \
                    patch.object(sync, "XAIEnricher") as client, \
                    patch.object(worker, "enhance_snapshot", return_value=report) as enhance, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(worker._main(), 0)
                client.assert_not_called()
                self.assertIsNone(enhance.call_args.kwargs["client"])


if __name__ == "__main__":
    unittest.main()
