from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "cve-catalog-validate.yml"


class CveCatalogValidationWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_only_accepts_explicit_dispatch_with_exact_sha_input(self) -> None:
        self.assertRegex(
            self.workflow, r"(?m)^on:\s*\n\s+workflow_dispatch:"
        )
        self.assertNotRegex(
            self.workflow, r"(?m)^\s+(push|pull_request|schedule):"
        )
        self.assertIn("expected_sha:", self.workflow)
        self.assertIn("request_id:", self.workflow)

    def test_emits_the_existing_required_build_context(self) -> None:
        self.assertRegex(
            self.workflow,
            r"(?ms)^\s{2}validate:\s*.*?^\s{4}name: build\s*$",
        )
        self.assertIn("matches the required context emitted by build.yml", self.workflow)

    def test_checkout_and_event_must_match_requested_sha(self) -> None:
        self.assertIn("ref: ${{ inputs.expected_sha }}", self.workflow)
        self.assertIn('ACTUAL_SHA="$(git rev-parse HEAD)"', self.workflow)
        self.assertIn('"$GITHUB_SHA" != "$EXPECTED_SHA"', self.workflow)

    def test_validation_is_build_equivalent(self) -> None:
        expected_commands = (
            "python3 scripts/run_checks.py",
            "python3 scripts/validate_cve_catalog.py",
            "npm run build",
            "npm run check:performance",
            "docker compose config",
            "docker compose build",
        )
        for command in expected_commands:
            with self.subTest(command=command):
                self.assertIn(command, self.workflow)

    def test_actions_are_pinned_to_full_commit_shas(self) -> None:
        references = re.findall(r"(?m)^\s*uses:\s*([^#\s]+)", self.workflow)

        self.assertEqual(len(references), 3)
        for reference in references:
            with self.subTest(reference=reference):
                self.assertRegex(reference, r"^[^@\s]+@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
