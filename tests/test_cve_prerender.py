from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from scripts import materialize_cve_pages as prerender


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_BASE_URL = "https://security-recipes.example/"


def contract_fixture(cve_id: str, canonical_url: str) -> str:
    structured_data = {
        "@context": "https://schema.org",
        "@type": "Article",
        "additionalType": "https://schema.org/TechArticle",
        "url": canonical_url,
        "mainEntityOfPage": {"@id": f"{canonical_url}#webpage"},
        "dateModified": "2026-07-21T12:00:00Z",
    }
    return (
        "<!doctype html><html><head>"
        '<meta name="robots" content="index,follow">'
        f'<link rel="canonical" href="{canonical_url}">'
        '<script type="application/ld+json">'
        f"{json.dumps(structured_data, separators=(',', ':'))}"
        "</script></head><body>"
        f"<h1>{cve_id}</h1>"
        '<time datetime="2026-07-21T12:00:00Z">2026-07-21</time>'
        "</body></html>"
    )


class CvePrerenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.output_root = Path(cls.temp_dir.name)
        cls.qualified_ids = prerender.load_search_indexable_cve_ids()
        cls.rendered_ids = prerender.materialize_cve_pages(
            cls.output_root,
            public_base_url=PUBLIC_BASE_URL,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()

    def test_every_qualified_canonical_cve_sitemap_identity_is_materialized(self) -> None:
        historical_ids = set(self.qualified_ids) & set(
            prerender.mcp_server._CVE_STATIC_CANONICAL_ROUTES
        )
        self.assertEqual(
            set(self.rendered_ids),
            set(self.qualified_ids) - historical_ids,
        )
        self.assertTrue(self.rendered_ids)

        for cve_id in self.rendered_ids:
            with self.subTest(cve_id=cve_id):
                document_path = self.output_root / "cve" / cve_id / "index.html"
                self.assertTrue(document_path.is_file())
                prerender.validate_landing_page_contract(
                    document_path.read_text(encoding="utf-8"),
                    cve_id=cve_id,
                    canonical_url=f"{PUBLIC_BASE_URL}cve/{cve_id}/",
                    require_remediation_summary=True,
                )

    def test_runtime_contract_requires_data_first_sections_and_visible_freshness(self) -> None:
        cve_id = self.rendered_ids[0]
        canonical_url = f"{PUBLIC_BASE_URL}cve/{cve_id}/"
        document = (self.output_root / "cve" / cve_id / "index.html").read_text(
            encoding="utf-8"
        )

        for broken_document, message in (
            (
                document.replace('id="remediation-summary-heading"', "", 1),
                "remediation data sections",
            ),
            (
                document.replace('id="cite-record-heading"', "", 1),
                "remediation data sections",
            ),
            (
                document.replace("<time", "<span").replace("</time>", "</span>"),
                "dateModified is not visible",
            ),
            (
                re.sub(r',?"dateModified":"[^"]+"', "", document),
                "dateModified is required",
            ),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    prerender.validate_landing_page_contract(
                        broken_document,
                        cve_id=cve_id,
                        canonical_url=canonical_url,
                        require_remediation_summary=True,
                    )

    def test_nonqualified_and_historical_records_are_not_materialized(self) -> None:
        actual_ids = {
            child.name
            for child in (self.output_root / "cve").iterdir()
            if child.is_dir()
            and prerender.CVE_LIKE_OUTPUT_DIRECTORY.fullmatch(child.name)
        }
        self.assertEqual(actual_ids, set(self.rendered_ids))
        self.assertFalse(
            (self.output_root / "cve" / "CVE-2024-9999" / "index.html").exists()
        )
        for cve_id in prerender.mcp_server._CVE_STATIC_CANONICAL_ROUTES:
            self.assertNotIn(cve_id, actual_ids)

    def test_build_verifier_requires_physical_sitemap_destinations(self) -> None:
        sitemap_root = self.output_root / "sitemaps"
        sitemap_root.mkdir(parents=True, exist_ok=True)
        cve_rows = "".join(
            f"<url><loc>{PUBLIC_BASE_URL}cve/{cve_id}/</loc></url>"
            for cve_id in self.rendered_ids
        )
        (sitemap_root / "cves-qualified.xml").write_text(
            '<?xml version="1.0" encoding="utf-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            f"{cve_rows}</urlset>",
            encoding="utf-8",
        )

        historical_rows: list[str] = []
        for cve_id in set(self.qualified_ids) & set(
            prerender.mcp_server._CVE_STATIC_CANONICAL_ROUTES
        ):
            route = prerender.mcp_server._CVE_STATIC_CANONICAL_ROUTES[cve_id]
            canonical_url = f"{PUBLIC_BASE_URL.rstrip('/')}{route}"
            historical_rows.append(f"<url><loc>{canonical_url}</loc></url>")
            destination = prerender._route_output_path(self.output_root, route)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(
                contract_fixture(cve_id, canonical_url),
                encoding="utf-8",
            )
        (sitemap_root / "pages.xml").write_text(
            '<?xml version="1.0" encoding="utf-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            f"{''.join(historical_rows)}</urlset>",
            encoding="utf-8",
        )

        prerender.verify_materialized_build(
            self.output_root,
            public_base_url=PUBLIC_BASE_URL,
            search_indexable_ids=self.qualified_ids,
        )

        missing = self.output_root / "cve" / self.rendered_ids[0] / "index.html"
        original = missing.read_bytes()
        try:
            missing.unlink()
            with self.assertRaisesRegex(ValueError, "physical document|identity mismatch"):
                prerender.verify_materialized_build(
                    self.output_root,
                    public_base_url=PUBLIC_BASE_URL,
                    search_indexable_ids=self.qualified_ids,
                )
        finally:
            missing.write_bytes(original)

        rogue = self.output_root / "cve" / "cVe-2024-9999"
        rogue.mkdir()
        try:
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                prerender.verify_materialized_build(
                    self.output_root,
                    public_base_url=PUBLIC_BASE_URL,
                    search_indexable_ids=self.qualified_ids,
                )
        finally:
            rogue.rmdir()

    def test_build_and_nginx_wire_static_first_with_runtime_fallback(self) -> None:
        package = (ROOT / "package.json").read_text(encoding="utf-8")
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        mcp_dockerfile = (ROOT / "Dockerfile.mcp-server").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        nginx = (ROOT / "docker" / "nginx" / "default.conf").read_text(
            encoding="utf-8"
        )

        self.assertIn("node scripts/check_build_prerequisites.js", package)
        self.assertIn("python scripts/materialize_cve_pages.py", package)
        self.assertIn("COPY mcp_server.py ./", dockerfile)
        self.assertIn("scripts/materialize_cve_pages.py", dockerfile)
        self.assertIn("scripts/cve_text_quality.py", dockerfile)
        self.assertIn(
            "COPY scripts/cve_text_quality.py /app/scripts/cve_text_quality.py",
            mcp_dockerfile,
        )
        package_copy = "COPY package.json package-lock.json ./"
        requirements_copy = "COPY requirements-mcp-server.txt ./"
        self.assertIn(package_copy, dockerfile)
        self.assertIn(requirements_copy, dockerfile)
        self.assertLess(dockerfile.index(package_copy), dockerfile.index("npm ci"))
        self.assertLess(dockerfile.index("npm ci"), dockerfile.index(requirements_copy))
        self.assertIn("Python `>= 3.10`", readme)
        self.assertIn("python -m pip install -r requirements-mcp-server.txt", readme)
        self.assertIn("try_files $uri/index.html @cve_landing_runtime;", nginx)
        self.assertIn(
            'location ~ "^/cve/CVE-[0-9]{4}-[0-9]{4,}/$"',
            nginx,
        )
        self.assertIn(
            'location ~* "^/cve/CVE-[0-9]{4}-[0-9]{4,}/$"',
            nginx,
        )
        self.assertIn("error_page 418 = @cve_landing_runtime;", nginx)
        self.assertIn("location @cve_landing_runtime", nginx)
        self.assertIn("proxy_pass $cve_landing_api$uri;", nginx)


if __name__ == "__main__":
    unittest.main()
