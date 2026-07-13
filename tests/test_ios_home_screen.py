from __future__ import annotations

import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS_HEAD = REPO_ROOT / "_includes" / "partials" / "head-common.njk"
HOME_LAYOUT = REPO_ROOT / "_includes" / "layouts" / "home-static.html"
CUSTOM_CSS = REPO_ROOT / "assets" / "css" / "custom.css"
MANIFEST = REPO_ROOT / "static" / "site.webmanifest"
SEO = REPO_ROOT / "lib" / "seo.js"


class IosHomeScreenTests(unittest.TestCase):
    def test_every_page_requests_an_opaque_black_ios_status_bar(self) -> None:
        expected_status = '<meta name="apple-mobile-web-app-status-bar-style" content="black">'
        expected_theme = '<meta name="theme-color" content="#000000">'

        for path in (DOCS_HEAD, HOME_LAYOUT):
            source = path.read_text(encoding="utf-8")
            self.assertEqual(1, source.count(expected_status), path)
            self.assertEqual(1, source.count(expected_theme), path)
            self.assertNotIn("black-translucent", source, path)

    def test_manifest_uses_black_launch_and_theme_surfaces(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual("standalone", manifest["display"])
        self.assertEqual("#000000", manifest["theme_color"])
        self.assertEqual("#000000", manifest["background_color"])

    def test_home_and_docs_define_a_black_root_canvas(self) -> None:
        self.assertIn("background-color: #000;", HOME_LAYOUT.read_text(encoding="utf-8"))
        self.assertIn("background-color: #000 !important;", CUSTOM_CSS.read_text(encoding="utf-8"))

    def test_seo_metadata_cannot_override_the_installed_theme(self) -> None:
        self.assertNotIn('name="theme-color"', SEO.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
