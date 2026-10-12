from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.generate_context_poisoning_guard_pack import (
    RULE_PATTERNS,
    finding_disposition,
    scan_file,
    source_decision,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = REPO_ROOT / "data" / "assurance" / "context-poisoning-guard-profile.json"
WORKFLOW_PAGE = (
    REPO_ROOT / "content" / "security-remediation" / "context-poisoning-guard" / "_index.md"
)
TAG_BLOCK = "\U000E0048\U000E0069\U000E0064\U000E0064\U000E0065\U000E006E"
THREE_VARIATION_SELECTORS = "\uFE00\uFE01\uFE02"
SINGLE_EMOJI_MODIFIER = "\u2764\uFE0F"


class ContextPoisoningUnicodeSmugglingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        cls.page = WORKFLOW_PAGE.read_text(encoding="utf-8")
        cls.rules = {
            str(rule.get("id")): rule
            for rule in cls.profile.get("scanner_rules", [])
            if isinstance(rule, dict) and rule.get("id")
        }

    def test_profile_records_llm01_and_unicode_smuggling_rule(self) -> None:
        alignment = {
            str(item.get("id")): item
            for item in self.profile.get("standards_alignment", [])
            if isinstance(item, dict)
        }
        llm01 = alignment["owasp-llm01-2026"]
        self.assertEqual(
            llm01["url"],
            "https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/final/LLM01_PromptInjection.md",
        )
        self.assertIn("tag-block", llm01["coverage"])
        self.assertIn("U+E0000", llm01["coverage"])

        rule = self.rules["invisible-unicode-smuggling"]
        self.assertEqual(rule["severity"], "high")
        self.assertEqual(rule["risk_family"], "hidden_instruction")
        self.assertIn("U+E0000", rule["description"])
        self.assertIn("variation selectors", rule["description"])

    def test_workflow_page_records_llm01_without_claiming_human_review(self) -> None:
        self.assertIn(
            "https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/final/LLM01_PromptInjection.md",
            self.page,
        )
        self.assertIn("U+E0000", self.page)
        self.assertIn("invisible-unicode-smuggling", self.page)
        self.assertIn("does not\nclaim human review of the pack", self.page)
        self.assertIn("lastmod: 2026-10-04", self.page)

    def test_tag_block_and_variation_selector_runs_match(self) -> None:
        pattern = RULE_PATTERNS["invisible-unicode-smuggling"]
        self.assertIsNotNone(pattern.search(f"benign text {TAG_BLOCK} still looks clean"))
        self.assertIsNotNone(
            pattern.search(f"benign text {THREE_VARIATION_SELECTORS} still looks clean")
        )
        self.assertIsNone(pattern.search(f"heart {SINGLE_EMOJI_MODIFIER} stays visible"))
        self.assertIsNone(pattern.search("plain retrieved context with no hidden channel"))
        self.assertIsNone(RULE_PATTERNS["zero-width-control"].search(TAG_BLOCK))

    def test_scan_file_holds_tag_block_and_allows_emoji_modifier(self) -> None:
        source = {"id": "fixture-context"}
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_root = Path(tmpdir)
            poisoned = repo_root / "retrieved.md"
            poisoned.write_text(
                f"A registered source that still looks clean {TAG_BLOCK}.\n",
                encoding="utf-8",
            )
            findings = scan_file(
                path=poisoned,
                source=source,
                repo_root=repo_root,
                profile=self.profile,
                rules=self.rules,
            )
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule_id"], "invisible-unicode-smuggling")
            self.assertEqual(findings[0]["severity"], "high")
            self.assertTrue(findings[0]["actionable"])
            self.assertEqual(source_decision(findings), "hold_for_context_review")

            clean = repo_root / "emoji.md"
            clean.write_text(f"Approved note with a heart {SINGLE_EMOJI_MODIFIER}.\n", encoding="utf-8")
            clean_findings = scan_file(
                path=clean,
                source=source,
                repo_root=repo_root,
                profile=self.profile,
                rules=self.rules,
            )
            self.assertEqual(clean_findings, [])
            self.assertEqual(source_decision(clean_findings), "pass")

    def test_documented_adversarial_example_is_not_actionable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_root = Path(tmpdir)
            path = repo_root / "content" / "security-remediation" / "context-poisoning-guard" / "_index.md"
            path.parent.mkdir(parents=True, exist_ok=True)
            line = f"Documented tag-block example {TAG_BLOCK}"
            path.write_text(line + "\n", encoding="utf-8")
            disposition, actionable = finding_disposition(
                path=path,
                repo_root=repo_root,
                line=line,
                match_start=line.index(TAG_BLOCK),
                profile=self.profile,
            )
            self.assertEqual(disposition, "documented_adversarial_example")
            self.assertFalse(actionable)


if __name__ == "__main__":
    unittest.main()
