from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from starlette.requests import Request

import mcp_server


ROOT = Path(__file__).resolve().parents[1]


def sample_recipe(cve: str = "CVE-2024-3400") -> dict[str, object]:
    return {
        "found": True,
        "cve": cve,
        "source_record": {
            "cve": cve,
            "title": 'Widget </title><script>alert("title")</script> command injection',
            "summary": "Unauthenticated input reaches a privileged command boundary <unsafe>.",
            "severity": "critical",
            "score": 9.8,
            "cvss_version": "3.1",
            "published": "2024-04-12",
            "last_modified": "2026-07-17T07:02:25Z",
            "kev": True,
            "ecosystem": "operating-system",
            "cwes": ["CWE-77", "CWE-78"],
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "products": [
                {"vendor": "Example Vendor", "product": "Widget", "version": "1.2.3"},
                {"vendor": "Example Vendor", "product": "Widget", "version": "1.2.4"},
            ],
            "product_match_count": 9,
            "references": [
                {
                    "url": f"https://vendor.example.test/advisories/{cve}",
                    "tags": ["Vendor Advisory"],
                },
                {"url": "javascript:alert(1)", "tags": ["Unsafe"]},
            ],
        },
        "composed_recipe": {
            "title": "Command, code, expression, and template injection",
            "exposure_checks": ["Trace <untrusted> values to process execution."],
            "remediation_steps": ["Use structured argument APIs without a shell."],
            "product_specific_override": [
                {
                    "cve": cve,
                    "maturity": "stable",
                    "title": f"{cve} reviewed recipe",
                    "path": f"content/recipes/cve/{cve.lower()}-reviewed.md",
                }
            ],
        },
        "agentic_change_plan": {
            "catalog_provenance": {"catalog_updated_at": "2026-07-17T07:02:25Z"}
        },
    }


def request_for(cve_id: str) -> Request:
    path = f"/cve/{cve_id}/"
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "root_path": "",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("mcp-server", 80),
            "path_params": {"cve_id": cve_id},
        }
    )


class CveLandingRenderTests(unittest.TestCase):
    def test_server_render_is_indexable_specific_bounded_and_safely_escaped(self) -> None:
        page = mcp_server._render_cve_landing_page(
            sample_recipe(),
            "https://security-recipes.example/base/",
        )

        self.assertLess(len(page.encode("utf-8")), 100_000)
        self.assertIn(
            '<link rel="canonical" '
            'href="https://security-recipes.example/base/cve/CVE-2024-3400/">',
            page,
        )
        self.assertIn(
            '<meta name="robots" '
            'content="index,follow,max-image-preview:large,max-snippet:-1,max-video-preview:-1">',
            page,
        )
        self.assertIn('data-cve-initial-id="CVE-2024-3400"', page)
        self.assertIn('data-cve-catalog-base="/api/cve-catalog/"', page)
        self.assertIn('data-site-signal-background="true"', page)
        self.assertIn('class="sr-docs-body sr-cve-detail-page"', page)
        self.assertIn('class="content cve-catalog cve-landing sr-cve-detail-content"', page)
        self.assertIn('<link rel="stylesheet" href="/css/cve-detail.css">', page)
        self.assertIn('<script src="/js/signal-background.js" defer></script>', page)
        self.assertIn('<meta name="theme-color" content="#020405">', page)
        self.assertIn("Complete CVE record and remediation plan", page)
        self.assertIn("Matched remediation archetype", page)
        self.assertIn("Explicitly reviewed curated workflows load", page)
        self.assertIn("Example Vendor / Widget / 1.2.3", page)
        self.assertIn('href="/recipes/cve/cve-2024-3400-reviewed/"', page)
        self.assertNotIn('javascript:alert(1)', page)
        self.assertNotIn('</title><script>alert("title")</script>', page)
        self.assertIn(
            "Widget &lt;/title&gt;&lt;script&gt;alert(&quot;title&quot;)&lt;/script&gt;",
            page,
        )

        match = re.search(
            r'<script type="application/ld\+json">(.*?)</script>',
            page,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match)
        assert match is not None
        self.assertNotIn("<", match.group(1))
        structured = json.loads(match.group(1))
        self.assertEqual(structured["identifier"], "CVE-2024-3400")
        self.assertEqual(
            structured["url"],
            "https://security-recipes.example/base/cve/CVE-2024-3400/",
        )
        self.assertEqual(structured["about"]["identifier"], "CVE-2024-3400")

    def test_renderer_rejects_mismatched_catalog_identity(self) -> None:
        recipe = sample_recipe()
        source = recipe["source_record"]
        assert isinstance(source, dict)
        source["cve"] = "CVE-2024-3401"
        with self.assertRaisesRegex(ValueError, "identities do not match"):
            mcp_server._render_cve_landing_page(recipe)

    def test_error_page_keeps_the_canonical_cve_theme(self) -> None:
        page = mcp_server._render_cve_landing_error(
            "CVE-2024-9999",
            "The record is unavailable.",
        )

        self.assertIn('data-site-signal-background="true"', page)
        self.assertIn('class="sr-docs-body sr-cve-detail-page"', page)
        self.assertIn('<link rel="stylesheet" href="/css/cve-detail.css">', page)
        self.assertIn('<script src="/js/signal-background.js" defer></script>', page)

    def test_public_base_url_rejects_credentials_and_non_http_schemes(self) -> None:
        self.assertEqual(
            mcp_server._cve_landing_public_base_url("javascript:alert(1)"),
            "https://security-recipes.ai",
        )
        self.assertEqual(
            mcp_server._cve_landing_public_base_url("https://user:pass@example.test/base"),
            "https://security-recipes.ai",
        )
        self.assertEqual(
            mcp_server._cve_landing_safe_https_url("https://[malformed"),
            "",
        )


class CveLandingRouteTests(unittest.IsolatedAsyncioTestCase):
    async def test_route_uses_a_worker_thread_and_returns_cacheable_html(self) -> None:
        lookup = AsyncMock(return_value=sample_recipe())
        with patch.object(mcp_server.asyncio, "to_thread", lookup):
            response = await mcp_server.cve_landing_page(request_for("CVE-2024-3400"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], mcp_server._CVE_LANDING_CACHE_CONTROL)
        self.assertIn("index, follow", response.headers["x-robots-tag"])
        self.assertIn("nosniff", response.headers["x-content-type-options"])
        self.assertIn(b'data-cve-initial-id="CVE-2024-3400"', response.body)
        lookup.assert_awaited_once_with(
            mcp_server._bounded_cve_landing_lookup,
            "CVE-2024-3400",
        )

    async def test_missing_record_is_a_nonindexable_404(self) -> None:
        lookup = AsyncMock(
            return_value={"found": False, "cve": "CVE-2024-9999"}
        )
        with patch.object(mcp_server.asyncio, "to_thread", lookup):
            response = await mcp_server.cve_landing_page(request_for("CVE-2024-9999"))

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(
            response.headers["x-robots-tag"],
            "noindex, nofollow, noarchive",
        )

    async def test_lowercase_identifier_redirects_to_the_absolute_canonical_route(self) -> None:
        with patch.dict(
            "os.environ",
            {"RECIPES_PUBLIC_SITE_BASE_URL": "https://security-recipes.example/"},
        ):
            response = await mcp_server.cve_landing_page(request_for("cve-2024-3400"))

        self.assertEqual(response.status_code, 308)
        self.assertEqual(
            response.headers["location"],
            "https://security-recipes.example/cve/CVE-2024-3400/",
        )

    async def test_invalid_identifier_is_a_nonindexable_404_without_lookup(self) -> None:
        lookup = AsyncMock()
        with patch.object(mcp_server.asyncio, "to_thread", lookup):
            response = await mcp_server.cve_landing_page(request_for("CVE-2024-bad"))

        self.assertEqual(response.status_code, 404)
        self.assertIn("noindex", response.headers["x-robots-tag"])
        lookup.assert_not_awaited()


class CveLandingProxyContractTests(unittest.TestCase):
    def test_fastmcp_registers_the_canonical_get_route(self) -> None:
        routes = {
            route.path: set(route.methods or [])
            for route in mcp_server.mcp._additional_http_routes
        }
        self.assertIn("/cve/{cve_id}/", routes)
        self.assertIn("GET", routes["/cve/{cve_id}/"])

    def test_nginx_proxies_only_canonical_cve_shapes_without_credentials(self) -> None:
        nginx = (ROOT / "docker" / "nginx" / "default.conf").read_text(encoding="utf-8")
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

        self.assertIn(
            'location ~* "^/cve/CVE-[0-9]{4}-[0-9]{4,}/$"',
            nginx,
        )
        self.assertIn("proxy_pass $cve_landing_api$request_uri;", nginx)
        self.assertIn('proxy_set_header Authorization "";', nginx)
        self.assertIn('proxy_set_header Cookie "";', nginx)
        self.assertIn(
            'RECIPES_PUBLIC_SITE_BASE_URL: '
            '"${SECURITY_RECIPES_BASE_URL:-https://security-recipes.ai/}"',
            compose,
        )


if __name__ == "__main__":
    unittest.main()
