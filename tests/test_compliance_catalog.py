from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import sync_compliance_recipes as syncer  # noqa: E402
import validate_compliance_recipes as validator  # noqa: E402


class ComplianceCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = syncer.load_catalog()
        cls.frameworks = cls.catalog["frameworks"]
        cls.by_id = {item["framework_id"]: item for item in cls.frameworks}

    def test_catalog_has_exactly_39_unique_frameworks(self) -> None:
        self.assertEqual(39, self.catalog["framework_count"])
        self.assertEqual(39, len(self.frameworks))
        for field in ("framework_id", "recipe_id", "file_name"):
            values = [item[field] for item in self.frameworks]
            self.assertEqual(len(values), len(set(values)), field)

    def test_catalog_has_broad_compliance_coverage(self) -> None:
        categories = {item["category"] for item in self.frameworks}
        self.assertEqual(set(syncer.CATEGORY_LABELS), categories)
        jurisdictions = {
            value for item in self.frameworks for value in item["jurisdictions"]
        }
        industries = {value for item in self.frameworks for value in item["industries"]}
        self.assertGreaterEqual(len(jurisdictions), 9)
        self.assertGreaterEqual(len(industries), 35)

    def test_time_sensitive_versions_and_statuses_are_precise(self) -> None:
        expected = {
            "cjis-security-policy": ("6.1 (June 25, 2026)", "final"),
            "eu-ai-act": (
                "Regulation (EU) 2024/1689; phased implementation",
                "phased-implementation",
            ),
            "fda-medical-device-cybersecurity": (
                "Final Guidance, February 2026",
                "final",
            ),
            "nist-ai-rmf": ("1.0; revision in progress", "revision-in-progress"),
            "nist-privacy-framework": (
                "1.0 final; 1.1 Initial Public Draft",
                "draft-update",
            ),
            "pci-dss": ("4.0.1", "final"),
            "slsa": ("1.2", "final"),
        }
        for framework_id, (version, status) in expected.items():
            with self.subTest(framework_id=framework_id):
                self.assertEqual(version, self.by_id[framework_id]["version"])
                self.assertEqual(status, self.by_id[framework_id]["status"])

    def test_every_framework_has_source_evidence_and_routing_metadata(self) -> None:
        for item in self.frameworks:
            with self.subTest(framework_id=item["framework_id"]):
                self.assertEqual(4, len(item["evidence_domains"]))
                self.assertEqual(4, len(item["evidence_examples"]))
                self.assertGreaterEqual(len(item["routing_positive"]), 3)
                self.assertGreaterEqual(len(item["routing_hard_negative"]), 2)
                self.assertTrue(item["official_sources"])
                self.assertTrue(
                    all(url.startswith("https://") for url in item["official_sources"])
                )
                self.assertIn("audit", item["facets"])
                self.assertIn("compliance", item["facets"])

    def test_licensed_publishers_use_summary_only_boundary(self) -> None:
        for item in self.frameworks:
            if item["publisher"] in validator.SUMMARY_ONLY_PUBLISHERS:
                with self.subTest(framework_id=item["framework_id"]):
                    self.assertEqual("summary-only", item["license_boundary"])
                    content = (syncer.OUTPUT_DIR / item["file_name"]).read_text(
                        encoding="utf-8"
                    )
                    self.assertIn(
                        "Do not paste, paraphrase at length, or reconstruct licensed controls",
                        content,
                    )

    def test_generated_library_is_exact_and_current(self) -> None:
        self.assertEqual([], syncer.sync(check=True))
        recipe_files = {
            path.name
            for path in syncer.OUTPUT_DIR.glob("*.md")
            if path.name != "_index.md"
        }
        self.assertEqual({item["file_name"] for item in self.frameworks}, recipe_files)

    def test_generated_search_descriptions_are_specific_and_bounded(self) -> None:
        descriptions = set()
        for item in self.frameworks:
            with self.subTest(framework_id=item["framework_id"]):
                description = syncer.meta_description(item)
                content = (syncer.OUTPUT_DIR / item["file_name"]).read_text(
                    encoding="utf-8"
                )
                metadata = validator.parse_front_matter(content)

                self.assertEqual(description, metadata["description"])
                self.assertNotEqual(item["applicability"], description)
                self.assertTrue(
                    description.startswith(
                        f"Assess {item['short_title']} evidence readiness:"
                    )
                )
                self.assertGreaterEqual(len(description), 100)
                self.assertLessEqual(len(description), syncer.META_DESCRIPTION_LIMIT)
                self.assertRegex(description, r"[.!?]$")
                for phrase in (
                    "verify applicability",
                    "official requirements",
                    "artifacts",
                    "record gaps",
                    "plan remediation",
                ):
                    self.assertIn(phrase, description)
                descriptions.add(description)

        self.assertEqual(len(self.frameworks), len(descriptions))

    def test_each_recipe_has_stable_metadata_and_quality_sections(self) -> None:
        for item in self.frameworks:
            with self.subTest(framework_id=item["framework_id"]):
                content = (syncer.OUTPUT_DIR / item["file_name"]).read_text(
                    encoding="utf-8"
                )
                metadata = validator.parse_front_matter(content)
                self.assertEqual(item["recipe_id"], metadata["recipe_id"])
                self.assertEqual(item["version"], metadata["framework_version"])
                self.assertEqual(item["status"], metadata["framework_status"])
                self.assertEqual(item["jurisdictions"], metadata["jurisdiction"])
                self.assertEqual(item["jurisdictions"], metadata["jurisdictions"])
                self.assertEqual(item["industries"], metadata["industry"])
                self.assertEqual(item["industries"], metadata["industries"])
                self.assertEqual(item["facets"], metadata["facets"])
                for heading in validator.REQUIRED_HEADINGS:
                    self.assertIn(heading, content)
                for step in range(6):
                    self.assertIn(f"## Step {step}", content)

    def test_full_validator_reports_complete_coverage(self) -> None:
        errors, metrics = validator.validate()
        self.assertEqual([], errors)
        self.assertEqual(39, metrics["frameworks"])
        self.assertEqual(39, metrics["recipes"])
        self.assertGreaterEqual(metrics["official_sources"], 39)
        self.assertEqual("2026-07-12", metrics["reviewed_on"])

    def test_catalog_is_valid_json_and_deterministically_serializable(self) -> None:
        reparsed = json.loads(syncer.CATALOG_PATH.read_text(encoding="utf-8"))
        self.assertEqual(self.catalog, reparsed)
        self.assertEqual(syncer.expected_outputs(self.catalog), syncer.expected_outputs(reparsed))


if __name__ == "__main__":
    unittest.main()
