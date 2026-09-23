from __future__ import annotations

import unittest

from scripts.generate_context_poisoning_guard_pack import RULE_PATTERNS


class InvisibleUnicodeSmugglingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pattern = RULE_PATTERNS["invisible-unicode-smuggling"]

    def test_tag_block_character_matches(self) -> None:
        # U+E0041 is TAG LATIN CAPITAL LETTER A, a tag-block code point.
        line = "reviewed context " + "\U000E0041" + " continues"
        self.assertIsNotNone(self.pattern.search(line))

    def test_language_tag_matches(self) -> None:
        line = "prefix" + "\U000E0001" + "suffix"
        self.assertIsNotNone(self.pattern.search(line))

    def test_variation_selector_run_matches(self) -> None:
        line = "visible text" + "\uFE00\uFE01\uFE02" + "more text"
        self.assertIsNotNone(self.pattern.search(line))

    def test_single_emoji_variation_selector_does_not_match(self) -> None:
        line = "status: done\uFE0F"
        self.assertIsNone(self.pattern.search(line))

    def test_clean_text_does_not_match(self) -> None:
        self.assertIsNone(self.pattern.search("Return only approved context with citations."))

    def test_zero_width_rule_still_covers_llm01_zero_width_set(self) -> None:
        pattern = RULE_PATTERNS["zero-width-control"]
        for char in ("\u200b", "\u200c", "\u200d", "\u2060"):
            with self.subTest(codepoint=f"U+{ord(char):04X}"):
                self.assertIsNotNone(pattern.search(f"text{char}text"))


if __name__ == "__main__":
    unittest.main()
