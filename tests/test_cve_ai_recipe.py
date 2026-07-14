from __future__ import annotations

import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path

from scripts import cve_ai_enrichment as enrichment
from scripts import cve_ai_recipe as recipe
from scripts import validate_cve_catalog as validator


SOURCE_URL = "https://vendor.example.test/security/CVE-2026-1234?view=advisory&lang=en"


def source_record(cve: str = "CVE-2026-1234") -> dict[str, object]:
    return {
        "cve": cve,
        "title": "Acme [Widget] *Parser* security vulnerability",
        "summary": "Acme Widget Parser accepts malformed untrusted records.",
        "published": "2026-07-10",
        "last_modified": "2026-07-13T01:02:03Z",
        "status": "Analyzed",
        "source_identifier": "security@acme.example",
        "severity": "high",
        "score": 8.1,
        "cvss_version": "3.1",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "cwes": ["CWE-20"],
        "products": [
            {
                "vendor": "acme",
                "product": "widget_parser",
                "version": "*",
                "version_start_including": "2.0.0",
                "version_start_excluding": "",
                "version_end_including": "",
                "version_end_excluding": "2.4.1",
            }
        ],
        "product_match_count": 1,
        "products_truncated": False,
        "references": [{"url": SOURCE_URL, "tags": ["Vendor Advisory"]}],
        "kev": False,
        "kev_details": None,
        "ecosystem": "software/application",
        "archetype": "generic",
        "archetypes": ["generic"],
        "recipe_kind": "composed",
        "markdown": [],
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve}",
    }


def enrichment_entry(record: dict[str, object], *, risk_suffix: str = "") -> dict[str, object]:
    claims = [
        {
            "kind": "affected_product",
            "claim": "Acme [Widget] *Parser* is the affected product.",
            "source_url": SOURCE_URL,
        },
        {
            "kind": "affected_version",
            "claim": "Versions 2.0.0 through 2.4.0 are affected.",
            "source_url": SOURCE_URL,
        },
        {
            "kind": "fixed_version",
            "claim": "Version 2.4.1 is the first fixed release.",
            "source_url": SOURCE_URL,
        },
        {
            "kind": "exposure",
            "claim": "Exposure requires untrusted records to reach the enabled parser.",
            "source_url": SOURCE_URL,
        },
        {
            "kind": "remediation",
            "claim": "Update Acme Widget Parser to fixed release 2.4.1.",
            "source_url": SOURCE_URL,
        },
        {
            "kind": "verification",
            "claim": "Confirm the deployed parser reports version 2.4.1 or later.",
            "source_url": SOURCE_URL,
        },
    ]
    return {
        "schema_version": enrichment.ENRICHMENT_SCHEMA_VERSION,
        "prompt_version": enrichment.PROMPT_VERSION,
        "model": "gpt-test",
        "generated_at": "2026-07-14T18:00:00Z",
        "source_fingerprint": enrichment.source_fingerprint(record),
        "gaps": enrichment.completeness_gaps(record),
        "status": "complete",
        "business_risk": (
            "Successful exploitation could alter [important] records & audit history." + risk_suffix
        ),
        "exposure_conditions": ["Untrusted records reach the enabled parser."],
        "remediation_steps": ["Model-authored operational prose must not be copied as a vetted step."],
        "verification_steps": ["Model-authored verification prose remains claim evidence only."],
        "uncertainty": ["Confirm whether dormant parser deployments still exist."],
        "recipe_specificity": "specific",
        "claim_evidence": claims,
        "source_urls": [SOURCE_URL],
        "retrieved_source_urls": [SOURCE_URL],
    }


def archetypes_payload() -> dict[str, object]:
    return {
        "archetypes": {
            "generic": {
                "containment_steps": ["Restrict the [parser] to trusted callers while rollout proceeds."],
                "watch_for": ["Bundled *copies* outside the primary inventory."],
                "rollback_steps": ["Restore captured configuration; retain containment if exposure returns."],
                "stop_conditions": ["Stop if scope is unknown or verification would require live secrets."],
            }
        }
    }


class CVEAIRecipeRenderingTests(unittest.TestCase):
    def test_builds_direct_root_development_draft_with_claim_sources_and_vetted_steps(self) -> None:
        record = source_record()
        entry = enrichment_entry(record)
        self.assertTrue(enrichment.recipe_ready(entry, record))

        draft = recipe.build_recipe_draft(record, entry, archetypes_payload())

        self.assertIsNotNone(draft)
        assert draft is not None
        self.assertEqual(draft.path, "ai-enrichment-cve-2026-1234.md")
        self.assertEqual(draft.metadata["maturity"], "development")
        self.assertEqual(draft.sha256, hashlib.sha256(draft.content.encode("utf-8")).hexdigest())
        self.assertIn('maturity: "development"', draft.content)
        self.assertIn('cve: "CVE-2026-1234"', draft.content)
        self.assertIn('severity: "high"', draft.content)
        self.assertIn('ecosystem: "software/application"', draft.content)
        self.assertIn('disclosed: "2026-07-10"', draft.content)
        self.assertIn('known_as: ["Acme [Widget] *Parser* security vulnerability"]', draft.content)
        self.assertIn(
            'description: "AI-assisted, evidence-gated remediation draft for CVE-2026-1234; security review required."',
            draft.content,
        )
        self.assertIn("AI-assisted, non-authoritative development draft", draft.content)
        self.assertIn("does not grant mutation or production authority", draft.content)
        for section in (
            "## Affected product and versions",
            "## Indicator of exposure",
            "## Remediation strategy",
            "## Verification",
        ):
            self.assertIn(section, draft.content)
        for label in (
            "Affected product",
            "Affected version",
            "Fixed version",
            "Exposure condition",
            "Remediation",
            "Verification",
        ):
            self.assertIn(f"**{label}:**", draft.content)
        self.assertEqual(draft.content.count("  - Evidence:"), 6)
        self.assertIn(r"Acme \[Widget\] \*Parser\*", draft.content)
        self.assertIn("view=advisory&amp;lang=en", draft.content)
        self.assertIn(r"Restrict the \[parser\]", draft.content)
        self.assertIn(r"Bundled \*copies\*", draft.content)
        self.assertIn("## Vetted rollback", draft.content)
        self.assertIn("## Stop and triage", draft.content)
        self.assertNotIn("Model-authored operational prose", draft.content)

    def test_only_canonical_trusted_advisory_urls_can_become_links(self) -> None:
        record = source_record()
        poisoned_source = SOURCE_URL + "#)https://evil.example/from-fragment"
        entry = enrichment_entry(record)
        entry["source_urls"] = [poisoned_source]
        entry["retrieved_source_urls"] = [poisoned_source]
        for claim in entry["claim_evidence"]:
            claim["source_url"] = poisoned_source
            if claim["kind"] == "remediation":
                claim["claim"] += " Download https://evil.example/payload."
        self.assertTrue(enrichment.recipe_ready(entry, record))

        draft = recipe.build_recipe_draft(record, entry, archetypes_payload())

        self.assertIsNotNone(draft)
        assert draft is not None
        hrefs = re.findall(r'href="([^"]+)"', draft.content)
        self.assertGreater(len(hrefs), 0)
        self.assertEqual(set(hrefs), {SOURCE_URL.replace("&", "&amp;")})
        self.assertNotIn("https://evil.example", draft.content)
        self.assertIn(r"https\:\/\/evil\.example\/payload", draft.content)

    def test_generated_frontmatter_passes_catalog_markdown_validation(self) -> None:
        record = source_record()
        draft = recipe.build_recipe_draft(record, enrichment_entry(record), archetypes_payload())
        self.assertIsNotNone(draft)
        assert draft is not None
        parent = validator.ROOT / "content" / "recipes" / "cve"
        with tempfile.TemporaryDirectory(prefix=".test-ai-recipe-", dir=parent) as tmpdir:
            content_dir = Path(tmpdir)
            (content_dir / draft.path).write_text(draft.content, encoding="utf-8")
            failures: list[str] = []
            counts, inventory = validator.validate_markdown_recipes(content_dir, failures)

        self.assertEqual(failures, [])
        self.assertEqual(counts["cve"], 1)
        self.assertEqual(next(iter(inventory.values()))["identity"], record["cve"])

    def test_fails_closed_when_evidence_human_markdown_or_archetype_context_blocks_draft(self) -> None:
        record = source_record()
        entry = enrichment_entry(record)
        entry["recipe_specificity"] = "not_specific"
        self.assertIsNone(recipe.build_recipe_draft(record, entry, archetypes_payload()))

        record = source_record()
        entry = enrichment_entry(record)
        record["ai_enrichment"] = entry
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            manager = recipe.GeneratedRecipeManager(root / "content", root / "manifest.json")
            record["human_markdown"] = True
            self.assertIsNone(manager.consider(record, archetypes=archetypes_payload()))
            self.assertEqual(manager.stats["skipped_human_markdown"], 1)

            record["human_markdown"] = False
            self.assertIsNone(manager.consider(record, archetypes={"archetypes": {}}))
            self.assertEqual(manager.stats["skipped_invalid_context"], 1)

        for recipe_kind, markdown in (
            ("markdown-draft", []),
            ("composed", [{"path": "content/recipes/cve/human.md"}]),
        ):
            record = source_record()
            record["ai_enrichment"] = enrichment_entry(record)
            record["recipe_kind"] = recipe_kind
            record["markdown"] = markdown
            with tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                manager = recipe.GeneratedRecipeManager(root / "content", root / "manifest.json")
                self.assertIsNone(manager.consider(record, archetypes=archetypes_payload()))
                self.assertEqual(manager.stats["skipped_human_markdown"], 1)


class GeneratedRecipeManagerTests(unittest.TestCase):
    def test_create_update_and_matching_ownership_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            content = root / "content"
            manifest = root / "owned.json"
            record = source_record()
            record["human_markdown"] = False
            record["ai_enrichment"] = enrichment_entry(record)

            manager = recipe.GeneratedRecipeManager(content, manifest)
            first = manager.consider(record, archetypes=archetypes_payload())
            self.assertIsNotNone(first)
            stats = manager.reconcile()
            self.assertEqual(stats["created"], 1)
            self.assertTrue(stats["manifest_changed"])
            assert first is not None
            target = content / first.path
            self.assertEqual(target.read_text(encoding="utf-8"), first.content)

            payload = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], 1)
            self.assertEqual(payload["generator"], recipe.GENERATOR_ID)
            self.assertEqual(payload["entries"][first.cve]["path"], first.path)
            self.assertEqual(payload["entries"][first.cve]["sha256"], first.sha256)

            reloaded = recipe.GeneratedRecipeManager(content, manifest)
            self.assertEqual(reloaded.managed_existing_paths(), {first.path})
            updated_entry = enrichment_entry(record)
            updated_entry["claim_evidence"][-1]["claim"] += " Confirm build metadata."
            record["ai_enrichment"] = updated_entry
            second = reloaded.consider(record, archetypes=archetypes_payload())
            self.assertIsNotNone(second)
            update_stats = reloaded.reconcile()
            self.assertEqual(update_stats["updated"], 1)
            assert second is not None
            self.assertEqual(target.read_text(encoding="utf-8"), second.content)

            unchanged = recipe.GeneratedRecipeManager(content, manifest)
            record["ai_enrichment"] = updated_entry
            unchanged.consider(record, archetypes=archetypes_payload())
            unchanged_stats = unchanged.reconcile()
            self.assertEqual(unchanged_stats["unchanged"], 1)
            self.assertFalse(unchanged_stats["manifest_changed"])

    def test_never_overwrites_unowned_or_edited_managed_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            content = root / "content"
            content.mkdir()
            manifest = root / "owned.json"
            record = source_record()
            record["human_markdown"] = False
            record["ai_enrichment"] = enrichment_entry(record)
            target = content / recipe.filename_for_cve(record["cve"])
            human = '---\nmaturity: "stable"\n---\nHuman recipe.\n'
            target.write_text(human, encoding="utf-8")

            unowned = recipe.GeneratedRecipeManager(content, manifest)
            self.assertIsNone(
                unowned.consider(record, archetypes=archetypes_payload())
            )
            stats = unowned.reconcile()
            self.assertEqual(stats["skipped_path_conflict"], 1)
            self.assertEqual(target.read_text(encoding="utf-8"), human)
            self.assertNotIn(str(record["cve"]), json.loads(manifest.read_text())["entries"])

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            content = root / "content"
            manifest = root / "owned.json"
            record = source_record()
            record["human_markdown"] = False
            record["ai_enrichment"] = enrichment_entry(record)
            owner = recipe.GeneratedRecipeManager(content, manifest)
            draft = owner.consider(record, archetypes=archetypes_payload())
            owner.reconcile()
            assert draft is not None
            target = content / draft.path
            edited = draft.content + "\nHuman review note.\n"
            target.write_text(edited, encoding="utf-8")

            manager = recipe.GeneratedRecipeManager(content, manifest)
            self.assertEqual(manager.managed_existing_paths(), set())
            record["ai_enrichment"] = enrichment_entry(record, risk_suffix=" New output.")
            manager.consider(record, archetypes=archetypes_payload())
            stats = manager.reconcile()
            self.assertEqual(stats["preserved_edited"], 1)
            self.assertEqual(target.read_text(encoding="utf-8"), edited)
            self.assertNotIn(
                str(record["cve"]), json.loads(manifest.read_text())["entries"]
            )

            target.write_text(draft.content, encoding="utf-8")
            relinquished = recipe.GeneratedRecipeManager(content, manifest)
            self.assertEqual(relinquished.managed_existing_paths(), set())
            relinquished.consider(record, archetypes=archetypes_payload())
            relinquished_stats = relinquished.reconcile()
            self.assertEqual(relinquished_stats["skipped_path_conflict"], 1)
            self.assertEqual(target.read_text(encoding="utf-8"), draft.content)

    def test_path_appearing_after_consider_aborts_before_catalog_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            content = root / "content"
            manifest = root / "owned.json"
            record = source_record()
            record["human_markdown"] = False
            record["ai_enrichment"] = enrichment_entry(record)
            manager = recipe.GeneratedRecipeManager(content, manifest)
            draft = manager.consider(record, archetypes=archetypes_payload())
            assert draft is not None
            content.mkdir(parents=True, exist_ok=True)
            target = content / draft.path
            human = "Human-owned file created after inventory.\n"
            target.write_text(human, encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "appeared after preflight"):
                manager.reconcile()

            self.assertEqual(target.read_text(encoding="utf-8"), human)
            self.assertFalse(manifest.exists())

    def test_full_run_purges_only_matching_owned_orphans(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            content = root / "content"
            manifest = root / "owned.json"
            record = source_record()
            record["human_markdown"] = False
            record["ai_enrichment"] = enrichment_entry(record)
            owner = recipe.GeneratedRecipeManager(content, manifest)
            draft = owner.consider(record, archetypes=archetypes_payload())
            owner.reconcile()
            assert draft is not None

            purge = recipe.GeneratedRecipeManager(content, manifest)
            stats = purge.reconcile()
            self.assertEqual(stats["deleted"], 1)
            self.assertFalse((content / draft.path).exists())
            self.assertEqual(json.loads(manifest.read_text())["entries"], {})

    def test_matching_sidecar_hash_without_generator_marker_is_not_owned_or_purged(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            content = root / "content"
            content.mkdir()
            manifest = root / "owned.json"
            filename = "ai-enrichment-cve-2026-1234.md"
            target = content / filename
            human = b'---\nmaturity: "development"\n---\nHuman-authored development draft.\n'
            target.write_bytes(human)
            digest = hashlib.sha256(human).hexdigest()
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "generator": recipe.GENERATOR_ID,
                        "entries": {
                            "CVE-2026-1234": {
                                "path": filename,
                                "sha256": digest,
                                "source_fingerprint": "b" * 64,
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            manager = recipe.GeneratedRecipeManager(content, manifest)
            self.assertEqual(manager.managed_existing_paths(), set())
            stats = manager.reconcile()
            self.assertEqual(stats["preserved_edited"], 1)
            self.assertEqual(target.read_bytes(), human)
            self.assertEqual(json.loads(manifest.read_text())["entries"], {})

    def test_partial_and_dry_run_do_not_purge_or_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            content = root / "content"
            manifest = root / "owned.json"
            record = source_record()
            record["human_markdown"] = False
            record["ai_enrichment"] = enrichment_entry(record)
            owner = recipe.GeneratedRecipeManager(content, manifest)
            draft = owner.consider(record, archetypes=archetypes_payload())
            owner.reconcile()
            assert draft is not None
            before_manifest = manifest.read_bytes()
            before_content = (content / draft.path).read_bytes()

            partial = recipe.GeneratedRecipeManager(content, manifest, partial=True)
            partial_stats = partial.reconcile()
            self.assertEqual(partial_stats["orphan_purge_skipped"], 1)
            self.assertEqual(manifest.read_bytes(), before_manifest)
            self.assertEqual((content / draft.path).read_bytes(), before_content)

            dry = recipe.GeneratedRecipeManager(content, manifest, dry_run=True)
            dry_stats = dry.reconcile()
            self.assertEqual(dry_stats["deleted"], 1)
            self.assertTrue(dry_stats["manifest_changed"])
            self.assertEqual(manifest.read_bytes(), before_manifest)
            self.assertEqual((content / draft.path).read_bytes(), before_content)

    def test_partial_run_relinquishes_an_edited_orphan(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            content = root / "content"
            manifest = root / "manifest.json"
            record = source_record()
            record["human_markdown"] = False
            record["ai_enrichment"] = enrichment_entry(record)
            owner = recipe.GeneratedRecipeManager(content, manifest)
            draft = owner.consider(record, archetypes=archetypes_payload())
            owner.reconcile()
            assert draft is not None
            target = content / draft.path
            edited = draft.content + "\nHuman edit.\n"
            target.write_text(edited, encoding="utf-8")

            partial = recipe.GeneratedRecipeManager(content, manifest, partial=True)
            stats = partial.reconcile()

            self.assertEqual(stats["preserved_edited"], 1)
            self.assertEqual(stats["orphan_purge_skipped"], 0)
            self.assertEqual(target.read_text(encoding="utf-8"), edited)
            self.assertEqual(json.loads(manifest.read_text())["entries"], {})

    def test_manifest_rejects_noncanonical_or_traversal_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            manifest = root / "owned.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "generator": recipe.GENERATOR_ID,
                        "entries": {
                            "CVE-2026-1234": {
                                "path": "../ai-enrichment-cve-2026-1234.md",
                                "sha256": "a" * 64,
                                "source_fingerprint": "b" * 64,
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unsafe path"):
                recipe.GeneratedRecipeManager(root / "content", manifest)


if __name__ == "__main__":
    unittest.main()
