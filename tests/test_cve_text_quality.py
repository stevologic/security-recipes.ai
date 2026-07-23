from __future__ import annotations

import unittest

from scripts.cve_text_quality import catalog_text_has_artifact, clean_catalog_text


class CveTextQualityTests(unittest.TestCase):
    def test_repairs_known_upstream_encoding_artifacts(self) -> None:
        samples = (
            ("vendor\u00e2\u0080\u0099s advisory", "vendor’s advisory"),
            ("vendor\u00e2\u20ac\u2122s advisory", "vendor’s advisory"),
            ("versions 1\u00e2\u20ac\u201c3", "versions 1–3"),
            ("release\u00e2\u20ac\u201dnotes", "release—notes"),
            ("Intel\u00e2\u201e\u00a2 product", "Intel™ product"),
            ("men\u00c3\u00ba", "menú"),
            ("product\u00c3\u201a\u00c2 name", "product name"),
            ("product\u00c2 name", "product name"),
            ("application\u00ef\u00bf\u00bds cache", "application's cache"),
            ("SAP\ufffdPlatform", "SAP Platform"),
            ("Cisco IM &amp;P&nbsp;Service", "Cisco IM &P Service"),
        )
        for source, expected in samples:
            with self.subTest(source=repr(source)):
                self.assertEqual(clean_catalog_text(source), expected)
                self.assertTrue(catalog_text_has_artifact(source))

    def test_preserves_correct_unicode(self) -> None:
        samples = (
            "München — “already quoted” ™ 😀 Ângela",
            "Thanh Toán",
            "Trân Minh-Quân",
            "Château",
        )
        for source in samples:
            with self.subTest(source=source):
                self.assertEqual(clean_catalog_text(source), source)
                self.assertFalse(catalog_text_has_artifact(source))


if __name__ == "__main__":
    unittest.main()
