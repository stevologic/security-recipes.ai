from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "search-indexing.yml"
LLMS = ROOT / "static" / "llms.txt"


class SearchIndexingWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_runs_daily_on_main_pushes_and_by_hand(self) -> None:
        self.assertIn('- cron: "53 7 * * *"', self.workflow)
        self.assertIn("push:", self.workflow)
        self.assertRegex(self.workflow, r"(?m)^\s*workflow_dispatch:\s*$")
        self.assertNotRegex(self.workflow, r"(?m)^\s+(pull_request|pull_request_target):")

    def test_submits_the_live_sitemap_with_a_deployed_key(self) -> None:
        self.assertIn("api.indexnow.org/indexnow", self.workflow)
        self.assertIn("sitemap.xml", self.workflow)
        # The submission must verify the key file is actually deployed before
        # claiming ownership of the host.
        self.assertIn('fetch(f"https://{host}/{key}.txt")', self.workflow)
        self.assertIn("skipping submission", self.workflow)
        self.assertIn("urls[start:start + 10000]", self.workflow)

    def test_the_public_key_file_matches_the_workflow_key(self) -> None:
        match = re.search(r"INDEXNOW_KEY: ([0-9a-f]{32})", self.workflow)
        self.assertIsNotNone(match)
        assert match is not None
        key = match.group(1)
        key_file = ROOT / "static" / f"{key}.txt"
        self.assertTrue(key_file.exists(), "the IndexNow key file must ship in static/")
        self.assertEqual(key_file.read_text(encoding="utf-8").strip(), key)

    def test_needs_no_secrets_permissions_or_checkout(self) -> None:
        self.assertIn("permissions: {}", self.workflow)
        self.assertNotIn("secrets.", self.workflow)
        self.assertNotIn("actions/checkout", self.workflow)

    def test_llms_txt_advertises_the_machine_surfaces(self) -> None:
        text = LLMS.read_text(encoding="utf-8")
        for surface in (
            "https://security-recipes.ai/mcp",
            "https://security-recipes.ai/api/recipes.json",
            "https://security-recipes.ai/api/cve-catalog/manifest.json",
            "https://security-recipes.ai/cve-database/",
            "https://security-recipes.ai/security-remediation/",
        ):
            with self.subTest(surface=surface):
                self.assertIn(surface, text)


if __name__ == "__main__":
    unittest.main()
