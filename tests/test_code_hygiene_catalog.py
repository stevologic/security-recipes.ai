from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

from scripts import sync_code_hygiene_recipes as sync_catalog


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "code-hygiene"
CONTENT = ROOT / "content" / "recipes" / "general" / "code-hygiene"
REQUIRED_HEADINGS = {
    "## When to use it",
    "## Inputs",
    "## The prompt",
    "## Output contract",
    "## Verification",
    "## Guardrails",
    "## Related recipes",
    "## References",
}


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class CodeHygieneCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = read_json(DATA / "catalog.json")
        cls.sources = read_json(DATA / "sources.json")
        cls.routing = read_json(DATA / "routing-fixtures.json")

    def test_catalog_has_exact_unique_coverage(self) -> None:
        records = self.catalog["records"]
        self.assertEqual(len(records), 72)
        self.assertEqual(self.catalog["expected_recipe_count"], 72)
        self.assertEqual(len(self.catalog["families"]), 15)
        ids = [f"code-hygiene.{record['family']}.{record['slug']}" for record in records]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len({record["slug"] for record in records}), 72)
        self.assertEqual(
            Counter(record["family"] for record in records),
            Counter(
                {
                    "cross-language": 16,
                    "javascript-typescript": 5,
                    "python": 5,
                    "jvm": 7,
                    "dotnet": 4,
                    "go": 4,
                    "rust": 4,
                    "c-cpp": 5,
                    "ruby": 2,
                    "php": 2,
                    "swift": 2,
                    "dart-flutter": 2,
                    "shell-powershell": 4,
                    "data": 3,
                    "platform": 7,
                }
            ),
        )

    def test_every_record_has_tailored_contract(self) -> None:
        contracts = set()
        for record in self.catalog["records"]:
            self.assertGreaterEqual(len(record["tags"]), 3)
            self.assertGreaterEqual(len(record["detect"]), 2)
            self.assertGreaterEqual(len(record["fix"]), 45)
            self.assertGreaterEqual(len(record["verify"]), 45)
            self.assertGreaterEqual(len(record["stop"]), 45)
            contracts.add((tuple(record["detect"]), record["fix"], record["verify"], record["stop"]))
        self.assertEqual(len(contracts), 72)

    def test_generated_markdown_is_complete_and_agent_ready(self) -> None:
        recipe_files = sorted(path for path in CONTENT.rglob("*.md") if path.name != "_index.md")
        self.assertEqual(len(recipe_files), 72)
        for path in recipe_files:
            markdown = path.read_text(encoding="utf-8")
            for heading in REQUIRED_HEADINGS:
                self.assertIn(heading, markdown, str(path))
            self.assertIn('recipe_id: "code-hygiene.', markdown)
            self.assertIn('facets: ["code-hygiene", "audit", "remediation"]', markdown)
            self.assertIn("Start read-only", markdown)
            self.assertIn("explicitly authorizes a fix", markdown)
            self.assertIn("https://", markdown)

    def test_family_indexes_explain_selection_and_are_not_thin(self) -> None:
        for key, family in self.catalog["families"].items():
            path = CONTENT / key / "_index.md"
            markdown = path.read_text(encoding="utf-8")
            family_records = [
                record for record in self.catalog["records"] if record["family"] == key
            ]

            self.assertIn(f"## Choose a focused {family['title']} recipe", markdown)
            self.assertIn("## How to use this collection", markdown)
            self.assertIn("## Full recipe list", markdown)
            for record in family_records:
                with self.subTest(family=key, recipe=record["slug"]):
                    self.assertIn(record["title"], markdown)
                    self.assertIn(record["goal"], markdown)
                    self.assertIn(sync_catalog.recipe_url(record).rstrip("/"), markdown)

            body = markdown.split("---", maxsplit=2)[-1]
            words = re.findall(r"\b[\w'-]+\b", body)
            self.assertGreaterEqual(len(words), 180, str(path))

    def test_source_registry_is_primary_and_https(self) -> None:
        sources = self.sources["sources"]
        self.assertGreaterEqual(len(sources), 50)
        self.assertEqual(len({source["id"] for source in sources}), len(sources))
        for source in sources:
            self.assertTrue(source["url"].startswith("https://"))
            self.assertIn(
                source["kind"],
                {"standard", "official-docs", "official-guidance", "first-party-tool"},
            )
            self.assertTrue(source["owner"])

    def test_routing_fixtures_cover_every_recipe_and_hard_negatives(self) -> None:
        positives = self.routing["positive_cases"]
        self.assertEqual(len(positives), 144)
        self.assertEqual(self.routing["positive_case_count"], 144)
        covered = Counter(case["expected_recipe_id"] for case in positives)
        expected = {
            f"code-hygiene.{record['family']}.{record['slug']}" for record in self.catalog["records"]
        }
        self.assertEqual(set(covered), expected)
        self.assertTrue(all(count == 2 for count in covered.values()))
        self.assertGreaterEqual(len(self.routing["hard_negative_cases"]), 6)

    def test_generated_outputs_are_in_sync_and_validate(self) -> None:
        for script, extra in [
            ("scripts/sync_code_hygiene_recipes.py", ["--check"]),
            ("scripts/validate_code_hygiene_recipes.py", []),
        ]:
            result = subprocess.run(
                [sys.executable, script, *extra],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_sync_detects_and_removes_orphaned_recipe_and_family_index(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            temp = Path(temp_dir)
            content = temp / "code-hygiene"
            routing = temp / "routing-fixtures.json"
            with (
                mock.patch.object(sync_catalog, "CONTENT_ROOT", content),
                mock.patch.object(sync_catalog, "ROUTING_PATH", routing),
            ):
                sync_catalog.sync(check=False)
                orphan_recipe = content / "retired" / "orphan.md"
                orphan_index = content / "retired" / "_index.md"
                orphan_recipe.parent.mkdir(parents=True)
                orphan_recipe.write_text(sync_catalog.GENERATED_MARKER + "\n", encoding="utf-8")
                orphan_index.write_text(sync_catalog.GENERATED_MARKER + "\n", encoding="utf-8")

                stale = sync_catalog.sync(check=True)
                self.assertIn(str(orphan_recipe.relative_to(ROOT)), stale)
                self.assertIn(str(orphan_index.relative_to(ROOT)), stale)
                self.assertTrue(orphan_recipe.exists())

                sync_catalog.sync(check=False)
                self.assertFalse(orphan_recipe.exists())
                self.assertFalse(orphan_index.exists())
                self.assertFalse(orphan_recipe.parent.exists())


if __name__ == "__main__":
    unittest.main()
