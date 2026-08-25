from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from scripts import check_cve_catalog_update as catalog_guard
from scripts import check_production_health as production


def manifest(
    *,
    records: int = 100_000,
    in_scope_kev: int = 1_000,
    kev_records: int = 1_600,
    updated_at: str = "2026-07-17T09:00:00Z",
) -> dict[str, Any]:
    return {
        "catalog_updated_at": updated_at,
        "totals": {
            "catalog_records": records,
            "in_scope_kev": in_scope_kev,
            "shards": 500,
            "markdown_drafts": 1_000,
            "markdown_pages": 1_010,
        },
        "by_publication_year": {
            "2025": {"total": 40_000},
            "2026": {"total": 35_000},
        },
        "sources": {
            "cisa_kev": {
                "catalog_records": kev_records,
                "date_released": updated_at,
            },
            "nvd": {
                "feeds": [
                    {
                        "year": 2025,
                        "accepted_records": 41_000,
                        "metadata": {"lastModifiedDate": updated_at},
                    },
                    {
                        "year": 2026,
                        "accepted_records": 36_000,
                        "metadata": {"lastModifiedDate": updated_at},
                    },
                ]
            },
        },
    }


def sync_report(
    *,
    api_enabled: bool = True,
    selected: int = 20,
    generated: int = 20,
    failed: int = 0,
    deleted: int = 0,
    provider_error: str | None = None,
) -> dict[str, Any]:
    enrichment = {
        "api_enabled": api_enabled,
        "eligible": 500,
        "cached": 100,
        "selected": selected,
        "generated": generated,
        "failed": failed,
    }
    if provider_error:
        enrichment["provider_error"] = provider_error
    return {
        "ai_enrichment": enrichment,
        "generated_recipes": {"deleted": deleted},
    }


class CatalogUpdateGuardTests(unittest.TestCase):
    def test_small_expected_changes_remain_mergeable(self) -> None:
        baseline = manifest()
        candidate = manifest(records=99_900, in_scope_kev=990, kev_records=1_590)

        report = catalog_guard.build_report(
            baseline, candidate, sync_report(generated=19, failed=1)
        )

        self.assertTrue(report["safe_to_merge"])
        self.assertEqual(report["anomalies"], [])
        self.assertTrue(report["enrichment"]["healthy"])
        self.assertEqual(report["enrichment"]["metrics"]["failed"], 1)
        self.assertIn("1 enrichment request", report["enrichment"]["warnings"][0])

    def test_large_source_regression_is_quarantined(self) -> None:
        baseline = manifest()
        candidate = manifest(
            records=70_000,
            in_scope_kev=0,
            kev_records=0,
            updated_at="2026-07-16T09:00:00Z",
        )
        candidate["by_publication_year"].pop("2025")
        candidate["sources"]["nvd"]["feeds"] = [
            {
                "year": 2026,
                "accepted_records": 20_000,
                "metadata": {"lastModifiedDate": "2026-07-16T09:00:00Z"},
            }
        ]
        candidate["totals"]["shards"] = 300
        candidate["totals"]["markdown_drafts"] = 800

        report = catalog_guard.build_report(
            baseline, candidate, sync_report(deleted=50)
        )
        codes = {finding["code"] for finding in report["anomalies"]}

        self.assertFalse(report["safe_to_merge"])
        self.assertIn("catalog-implausibly-small", codes)
        self.assertIn("catalog-timestamp-regressed", codes)
        self.assertIn("publication-years-missing", codes)
        self.assertIn("in-scope-kev-empty", codes)
        self.assertIn("kev-feed-empty", codes)
        self.assertIn("kev-source-timestamp-regressed", codes)
        self.assertIn("nvd-feeds-missing", codes)
        self.assertIn("nvd-source-timestamp-regressed", codes)
        self.assertIn("shards-drop", codes)
        self.assertIn("markdown-drafts-drop", codes)
        self.assertIn("generated-recipe-deletion-spike", codes)

    def test_enrichment_outage_alerts_without_blocking_source_catalog(self) -> None:
        report = catalog_guard.build_report(
            manifest(),
            manifest(),
            sync_report(selected=20, generated=0, failed=3),
        )

        self.assertTrue(report["safe_to_merge"])
        self.assertFalse(report["enrichment"]["healthy"])
        self.assertGreaterEqual(len(report["enrichment"]["alerts"]), 2)

    def test_missing_xai_key_is_explicitly_unhealthy(self) -> None:
        health = catalog_guard.enrichment_health(
            sync_report(api_enabled=False, selected=0, generated=0)
        )

        self.assertFalse(health["healthy"])
        self.assertIn("XAI_API_KEY", health["alerts"][0])

    def test_exhausted_quota_is_explicit_and_does_not_blame_the_time_budget(self) -> None:
        health = catalog_guard.enrichment_health(
            sync_report(
                selected=20,
                generated=0,
                failed=1,
                provider_error="insufficient_quota",
            )
        )

        self.assertFalse(health["healthy"])
        self.assertEqual(health["metrics"]["provider_error"], "insufficient_quota")
        self.assertTrue(
            any("credits are exhausted" in alert for alert in health["alerts"])
        )
        self.assertTrue(
            any("provider became unavailable" in alert for alert in health["alerts"])
        )
        self.assertFalse(
            any("time budget" in alert for alert in health["alerts"])
        )

    def test_cli_writes_fail_closed_github_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            baseline = root / "baseline.json"
            candidate = root / "candidate.json"
            run = root / "run.json"
            report = root / "report.json"
            markdown = root / "report.md"
            output = root / "github-output.txt"
            baseline.write_text('{"not": "a manifest"}\n', encoding="utf-8")
            candidate.write_text('{"not": "a manifest"}\n', encoding="utf-8")
            run.write_text('{"ai_enrichment": {}}\n', encoding="utf-8")

            result = catalog_guard.main(
                [
                    "--baseline",
                    str(baseline),
                    "--candidate",
                    str(candidate),
                    "--sync-report",
                    str(run),
                    "--report",
                    str(report),
                    "--markdown",
                    str(markdown),
                    "--github-output",
                    str(output),
                    "--fail-on-anomaly",
                ]
            )

            self.assertEqual(result, 1)
            self.assertIn("safe_to_merge=false", output.read_text(encoding="utf-8"))
            self.assertTrue(report.exists())


class FakeResponse:
    def __init__(
        self,
        url: str,
        payload: bytes,
        content_type: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status = 200
        self.url = url
        self.payload = payload
        self.headers = {"Content-Type": content_type, **(headers or {})}

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def getcode(self) -> int:
        return self.status

    def geturl(self) -> str:
        return self.url

    def read(self, _: int = -1) -> bytes:
        return self.payload


class ProductionHealthTests(unittest.TestCase):
    NOW = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
    SHA = "a" * 40

    def opener(
        self,
        catalog_updated_at: str = "2026-07-17T09:00:00Z",
        revision: str | None = None,
        *,
        cve_html: bytes | None = None,
        sitemap_xml: bytes | None = None,
        robots_txt: bytes | None = None,
        search_indexable_json: bytes | None = None,
        pages_sitemap_xml: bytes | None = None,
        cve_sitemap_xml: bytes | None = None,
        cve_sitemap_year: str = "2024",
        excluded_cve_html: bytes | None = None,
        traffic_x_robots_tag: str = "noindex, nofollow, noarchive",
        www_final_url: str = "https://security-recipes.ai/",
        content_overrides: dict[str, bytes] | None = None,
        googlebot_overrides: dict[str, bytes] | None = None,
    ):
        revision_value = revision or self.SHA
        cve_id = production.DEFAULT_CVE_PROBE_ID
        cve_url = f"https://security-recipes.ai/cve/{cve_id}/"
        excluded_cve_id = production.DEFAULT_EXCLUDED_CVE_PROBE_ID
        excluded_cve_url = f"https://security-recipes.ai/cve/{excluded_cve_id}/"
        default_cve_html = f"""<!doctype html><html><head>
<title>{cve_id}: PAN-OS command injection</title>
<meta name="description" content="Fix {cve_id} with source-backed PAN-OS remediation guidance.">
<meta name="robots" content="index,follow,max-image-preview:large">
<link rel="canonical" href="{cve_url}">
<link rel="stylesheet" href="/css/cve-detail.css">
<script type="application/ld+json">{{"@context":"https://schema.org","@type":"Article","additionalType":"https://schema.org/TechArticle"}}</script>
</head><body class="sr-docs-body sr-cve-detail-page" data-cve-detail-page="true">
<nav class="sr-breadcrumbs" aria-label="Breadcrumb"><a href="/cve-database/">CVE Database</a></nav>
<h1 class="sr-page-title">{cve_id}: PAN-OS command injection</h1>
<div data-cve-initial-id="{cve_id}"></div></body></html>""".encode()
        default_excluded_cve_html = f"""<!doctype html><html><head>
<title>{excluded_cve_id}: Windows shortcut vulnerability</title>
<meta content="noindex,follow" name="robots">
<link rel="canonical" href="{excluded_cve_url}">
</head><body><div data-cve-initial-id="{excluded_cve_id}"></div></body></html>""".encode()
        default_sitemap = f"""<?xml version="1.0" encoding="utf-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://security-recipes.ai/sitemaps/pages.xml</loc></sitemap>
  <sitemap><loc>https://security-recipes.ai/sitemaps/cves-{cve_sitemap_year}.xml</loc></sitemap>
</sitemapindex>""".encode()
        default_pages_sitemap = b"""<?xml version="1.0" encoding="utf-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://security-recipes.ai/</loc></url>
  <url><loc>https://security-recipes.ai/recipes/cve/cve-2017-18342-pyyaml/</loc></url>
</urlset>"""
        default_cve_sitemap = f"""<?xml version="1.0" encoding="utf-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>{cve_url}</loc></url>
</urlset>""".encode()
        default_allowlist = json.dumps(
            {
                "records": [
                    {
                        "cve": "CVE-2017-18342",
                        "published": "2018-06-27",
                        "qualification": "stable_markdown",
                    },
                    {
                        "cve": cve_id,
                        "published": "2024-04-12",
                        "qualification": "stable_markdown",
                    },
                ]
            }
        ).encode()
        default_robots = b"""User-agent: *
Allow: /
Disallow: /search/
Sitemap: https://security-recipes.ai/sitemap.xml
"""
        integrity_pages = {
            "https://security-recipes.ai/": (
                b'<!doctype html><html><body><h1 class="hero-title">'
                b"Search CVEs. Remediate vulnerabilities with AI agents</h1></body></html>"
            ),
            "https://security-recipes.ai/cve-database/": (
                b"<!doctype html><html><head>"
                b"<title>CVE Database | Security Recipes</title>"
                b'<meta name="description" content="Search a synchronized NVD and CISA '
                b"KEV CVE database with sourced facts, affected-version evidence, "
                b'canonical advisories, and bounded AI remediation.">'
                b'<meta name="robots" content="index,follow,max-image-preview:large">'
                b'<link rel="canonical" href="https://security-recipes.ai/'
                b'cve-database/">'
                b'<script type="application/ld+json">{"@context":"https://schema.org",'
                b'"@graph":[{"@type":"Dataset"}]}</script>'
                b'</head><body><h1 id="cve-database-heading">CVE Database</h1>'
                b'<script type="application/json" data-cve-qualified-routes>'
                b'{"qualified":{"CVE-2026-14956":"/cve/CVE-2026-14956/"},'
                b'"historical":{}}</script></body></html>'
            ),
            "https://security-recipes.ai/agentic-security/": (
                b"<!doctype html><html><head>"
                b"<title>AI Agent Security: How to Secure AI Agent Systems</title>"
                b'<meta name="description" content="Secure AI agent systems against '
                b"prompt injection, tool abuse, excessive permissions, unsafe memory, "
                b'connector risk, and weak incident response.">'
                b'<meta name="robots" content="index,follow,max-image-preview:large">'
                b'<link rel="canonical" href="https://security-recipes.ai/'
                b'agentic-security/">'
                b'<script type="application/ld+json">{"@context":"https://schema.org",'
                b'"@graph":[{"@type":"CollectionPage"}]}</script>'
                b'</head><body><h1 class="sr-page-title">'
                b"AI Agent Security: How to Secure AI Agent Systems</h1></body></html>"
            ),
            "https://security-recipes.ai/codex/": (
                b'<!doctype html><html><body><h1 class="sr-page-title">'
                b"Codex Vulnerability Remediation</h1></body></html>"
            ),
            "https://security-recipes.ai/automation/": (
                b'<!doctype html><html><body><h1 class="sr-page-title">'
                b"Automated Vulnerability Remediation Without AI Agents</h1></body></html>"
            ),
            "https://security-recipes.ai/security-remediation/": (
                b"<!doctype html><html><head>"
                b"<title>How to Remediate Vulnerabilities with AI Agents</title>"
                b'<meta name="description" content="Learn how to remediate software '
                b"vulnerabilities with AI coding agents using scoped playbooks, source "
                b'evidence, tests, rollback, and human review.">'
                b'<meta name="robots" content="index,follow,max-image-preview:large">'
                b'<link rel="canonical" href="https://security-recipes.ai/'
                b'security-remediation/">'
                b'<script type="application/ld+json">{"@context":"https://schema.org",'
                b'"@graph":[{"@type":"HowTo"}]}</script>'
                b'</head><body><h1 class="sr-page-title">'
                b"How to Remediate Vulnerabilities with AI Agents</h1></body></html>"
            ),
            "https://security-recipes.ai/agents/": (
                b"<!doctype html><html><head>"
                b"<title>AI Coding Agents for Vulnerability Remediation | "
                b"Security Recipes</title>"
                b'<meta name="description" content="Compare Codex, Claude Code, Cursor, '
                b"Copilot, Devin, Shiba Studio, Hermes, and OpenClaw for AI vulnerability "
                b'remediation with bounded instructions and review gates.">'
                b'<meta name="robots" content="index,follow,max-image-preview:large">'
                b'<link rel="canonical" href="https://security-recipes.ai/agents/">'
                b'</head><body><h1 class="sr-page-title">'
                b"AI Coding Agents for Vulnerability Remediation</h1></body></html>"
            ),
        }
        integrity_pages.update(content_overrides or {})
        googlebot_pages = dict(integrity_pages)
        googlebot_pages.update(googlebot_overrides or {})

        def open_request(request: Any, *, timeout: float) -> FakeResponse:
            self.assertGreater(timeout, 0)
            url = request.full_url
            if url == "https://www.security-recipes.ai/":
                return FakeResponse(
                    www_final_url,
                    b"<!doctype html><html>security recipes</html>",
                    "text/html; charset=utf-8",
                )
            if url.endswith("/api/cve-catalog/manifest.json"):
                payload = (
                    '{"catalog_updated_at":"'
                    + catalog_updated_at
                    + '","totals":{"catalog_records":100000}}'
                ).encode()
                return FakeResponse(url, payload, "application/json")
            if url.endswith("/api/cve-catalog/search-indexable.json"):
                return FakeResponse(
                    url,
                    search_indexable_json
                    if search_indexable_json is not None
                    else default_allowlist,
                    "application/json",
                )
            if url.endswith("/.well-known/deploy-revision"):
                return FakeResponse(url, revision_value.encode(), "text/plain")
            if url.endswith("/robots.txt"):
                return FakeResponse(
                    url,
                    robots_txt if robots_txt is not None else default_robots,
                    "text/plain; charset=utf-8",
                )
            if url.endswith("/sitemap.xml"):
                return FakeResponse(
                    url,
                    sitemap_xml if sitemap_xml is not None else default_sitemap,
                    "application/xml",
                )
            if url.endswith("/sitemaps/pages.xml"):
                return FakeResponse(
                    url,
                    pages_sitemap_xml
                    if pages_sitemap_xml is not None
                    else default_pages_sitemap,
                    "application/xml",
                )
            if url.endswith(f"/sitemaps/cves-{cve_sitemap_year}.xml"):
                return FakeResponse(
                    url,
                    cve_sitemap_xml
                    if cve_sitemap_xml is not None
                    else default_cve_sitemap,
                    "application/xml",
                )
            if url == cve_url:
                return FakeResponse(
                    url,
                    cve_html if cve_html is not None else default_cve_html,
                    "text/html; charset=utf-8",
                )
            if url == excluded_cve_url:
                return FakeResponse(
                    url,
                    excluded_cve_html
                    if excluded_cve_html is not None
                    else default_excluded_cve_html,
                    "text/html; charset=utf-8",
                )
            if url.endswith("/traffic/"):
                headers = (
                    {"X-Robots-Tag": traffic_x_robots_tag}
                    if traffic_x_robots_tag
                    else {}
                )
                return FakeResponse(
                    url,
                    b"<!doctype html><html>traffic</html>",
                    "text/html; charset=utf-8",
                    headers,
                )
            selected_pages = (
                googlebot_pages
                if request.get_header("User-agent") == production.GOOGLEBOT_USER_AGENT
                else integrity_pages
            )
            if url in selected_pages:
                return FakeResponse(
                    url,
                    selected_pages[url],
                    "text/html; charset=utf-8",
                )
            return FakeResponse(
                url, b"<!doctype html><html>security recipes</html>", "text/html"
            )

        return open_request

    def certificate(self, *_: object, **__: object) -> datetime:
        return self.NOW + timedelta(days=90)

    def test_healthy_site_catalog_revision_and_tls(self) -> None:
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(),
            certificate_expiry=self.certificate,
        )

        self.assertTrue(report["healthy"])
        self.assertEqual(report["failure_count"], 0)
        self.assertEqual(report["warning_count"], 0)
        self.assertEqual(
            {check["name"] for check in report["checks"]},
            {
                "homepage",
                "content_integrity",
                "canonical_host",
                "robots",
                "catalog",
                "sitemap",
                "cve_landing",
                "excluded_cve",
                "traffic_noindex",
                "revision",
                "tls",
            },
        )
        self.assertEqual(report["cve_probe_id"], production.DEFAULT_CVE_PROBE_ID)

    def test_recent_main_revision_gets_deployment_grace_warning(self) -> None:
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(minutes=10),
            now=self.NOW,
            opener=self.opener(revision="b" * 40),
            certificate_expiry=self.certificate,
        )

        self.assertTrue(report["healthy"])
        self.assertEqual(report["warning_count"], 1)

    def test_stale_catalog_and_stuck_revision_fail(self) -> None:
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(
                catalog_updated_at="2026-07-15T00:00:00Z",
                revision="b" * 40,
            ),
            certificate_expiry=self.certificate,
        )

        self.assertFalse(report["healthy"])
        self.assertEqual(report["failure_count"], 2)
        failed = {check["name"] for check in report["checks"] if not check["ok"]}
        self.assertEqual(failed, {"catalog", "revision"})

    def test_non_indexable_cve_and_invalid_sitemap_fail_explicitly(self) -> None:
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(
                cve_html=b'<html><meta name="robots" content="noindex"></html>',
                sitemap_xml=b'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"/>',
            ),
            certificate_expiry=self.certificate,
        )

        self.assertFalse(report["healthy"])
        failed = {check["name"] for check in report["checks"] if not check["ok"]}
        self.assertEqual(failed, {"sitemap", "cve_landing"})

    def test_old_generic_cve_renderer_fails_the_theme_contract(self) -> None:
        cve_id = production.DEFAULT_CVE_PROBE_ID
        cve_url = f"https://security-recipes.ai/cve/{cve_id}/"
        generic_page = f"""<!doctype html><html><head>
<title>{cve_id}: PAN-OS command injection</title>
<meta name="description" content="PAN-OS vulnerability record.">
<meta name="robots" content="index,follow,max-image-preview:large">
<link rel="canonical" href="{cve_url}">
<script type="application/ld+json">{{"@context":"https://schema.org","@type":"Article","additionalType":"https://schema.org/TechArticle"}}</script>
</head><body><h1>{cve_id}: PAN-OS command injection</h1>
<div data-cve-initial-id="{cve_id}"></div></body></html>""".encode()
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(cve_html=generic_page),
            certificate_expiry=self.certificate,
        )

        failed = [check for check in report["checks"] if not check["ok"]]
        self.assertEqual([check["name"] for check in failed], ["cve_landing"])
        self.assertIn("CVE detail stylesheet", failed[0]["message"])
        self.assertIn("site-themed CVE body", failed[0]["message"])
        self.assertIn("CVE database breadcrumb", failed[0]["message"])
        self.assertIn("query-specific primary heading", failed[0]["message"])

    def test_www_must_resolve_over_https_and_consolidate_to_apex(self) -> None:
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(www_final_url="https://www.security-recipes.ai/"),
            certificate_expiry=self.certificate,
        )

        self.assertFalse(report["healthy"])
        failed = {check["name"] for check in report["checks"] if not check["ok"]}
        self.assertEqual(failed, {"canonical_host"})

    def test_robots_must_expose_noindex_routes_and_canonical_sitemap(self) -> None:
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(
                robots_txt=b"""User-agent: *
Disallow:
Disallow: /traffic/
"""
            ),
            certificate_expiry=self.certificate,
        )

        failed = [check for check in report["checks"] if not check["ok"]]
        self.assertEqual([check["name"] for check in failed], ["robots"])
        self.assertIn("blank Disallow", failed[0]["message"])

    def test_sitemap_membership_must_match_qualified_allowlist(self) -> None:
        excluded_url = (
            "https://security-recipes.ai/cve/"
            f"{production.DEFAULT_EXCLUDED_CVE_PROBE_ID}/"
        )
        bad_child = f"""<?xml version="1.0" encoding="utf-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>{excluded_url}</loc></url>
</urlset>""".encode()
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(cve_sitemap_xml=bad_child),
            certificate_expiry=self.certificate,
        )

        failed = [check for check in report["checks"] if not check["ok"]]
        self.assertEqual([check["name"] for check in failed], ["sitemap"])
        self.assertIn("unqualified record", failed[0]["message"])

    def test_sitemap_partition_uses_publication_year_not_cve_id_year(self) -> None:
        cve_id = production.DEFAULT_CVE_PROBE_ID
        allowlist = json.dumps(
            {
                "records": [
                    {
                        "cve": "CVE-2017-18342",
                        "published": "2018-06-27",
                        "qualification": "stable_markdown",
                    },
                    {
                        "cve": cve_id,
                        "published": "2023-12-31",
                        "qualification": "stable_markdown",
                    },
                ]
            }
        ).encode()
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(
                search_indexable_json=allowlist,
                cve_sitemap_year="2023",
            ),
            certificate_expiry=self.certificate,
        )

        sitemap = next(check for check in report["checks"] if check["name"] == "sitemap")
        self.assertTrue(sitemap["ok"], sitemap["message"])

    def test_each_cve_sitemap_is_bounded_below_fifty_thousand_urls(self) -> None:
        cve_url = (
            "https://security-recipes.ai/cve/"
            f"{production.DEFAULT_CVE_PROBE_ID}/"
        )
        oversized_child = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            + f"<url><loc>{cve_url}</loc></url>" * 49_001
            + "</urlset>"
        ).encode()
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(cve_sitemap_xml=oversized_child),
            certificate_expiry=self.certificate,
        )

        failed = [check for check in report["checks"] if not check["ok"]]
        self.assertEqual([check["name"] for check in failed], ["sitemap"])
        self.assertIn("49,001 URLs", failed[0]["message"])

    def test_excluded_cve_and_traffic_dashboard_must_send_noindex(self) -> None:
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(
                excluded_cve_html=b"<html><head></head><body>generic CVE</body></html>",
                traffic_x_robots_tag="nofollow",
            ),
            certificate_expiry=self.certificate,
        )

        failed = {check["name"] for check in report["checks"] if not check["ok"]}
        self.assertEqual(failed, {"excluded_cve", "traffic_noindex"})

    def test_tls_expiry_covers_apex_and_www_names(self) -> None:
        hostnames: list[str] = []

        def certificate(hostname: str, *_: object, **__: object) -> datetime:
            hostnames.append(hostname)
            return self.NOW + timedelta(days=90)

        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(),
            certificate_expiry=certificate,
        )

        self.assertTrue(report["healthy"])
        self.assertEqual(hostnames, ["security-recipes.ai", "www.security-recipes.ai"])

    def test_search_spam_visible_to_googlebot_fails_content_integrity(self) -> None:
        codex_url = "https://security-recipes.ai/codex/"
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(
                googlebot_overrides={
                    codex_url: (
                        b'<!doctype html><html><body><h1 class="sr-page-title">'
                        b"Codex Vulnerability Remediation</h1><p>NADIMTOGEL</p>"
                        b"</body></html>"
                    )
                }
            ),
            certificate_expiry=self.certificate,
        )

        failed = [check for check in report["checks"] if not check["ok"]]
        self.assertEqual([check["name"] for check in failed], ["content_integrity"])
        self.assertIn("known search-spam signature", failed[0]["message"])

    def test_old_generic_remediation_page_fails_content_integrity(self) -> None:
        remediation_url = "https://security-recipes.ai/security-remediation/"
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(
                content_overrides={
                    remediation_url: (
                        b"<!doctype html><html><head>"
                        b"<title>Remediation Playbooks | Security Recipes</title>"
                        b'</head><body><h1 class="sr-page-title">'
                        b"Remediation Playbooks</h1></body></html>"
                    )
                }
            ),
            certificate_expiry=self.certificate,
        )

        failed = [check for check in report["checks"] if not check["ok"]]
        self.assertEqual([check["name"] for check in failed], ["content_integrity"])
        self.assertIn("AI remediation guide", failed[0]["message"])
        self.assertIn("expected primary heading", failed[0]["message"])

    def test_remediation_page_must_include_howto_search_contract(self) -> None:
        remediation_url = "https://security-recipes.ai/security-remediation/"
        page_without_howto = (
            b"<!doctype html><html><head>"
            b"<title>How to Remediate Vulnerabilities with AI Agents</title>"
            b'<meta name="description" content="Learn how to remediate software '
            b"vulnerabilities with AI coding agents using scoped playbooks, source "
            b'evidence, tests, rollback, and human review.">'
            b'<meta name="robots" content="index,follow,max-image-preview:large">'
            b'<link rel="canonical" href="https://security-recipes.ai/'
            b'security-remediation/">'
            b'</head><body><h1 class="sr-page-title">'
            b"How to Remediate Vulnerabilities with AI Agents</h1></body></html>"
        )
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(
                content_overrides={remediation_url: page_without_howto}
            ),
            certificate_expiry=self.certificate,
        )

        failed = [check for check in report["checks"] if not check["ok"]]
        self.assertEqual([check["name"] for check in failed], ["content_integrity"])
        self.assertIn("HowTo structured data", failed[0]["message"])

    def test_missing_agent_security_hub_fails_content_integrity(self) -> None:
        agentic_url = "https://security-recipes.ai/agentic-security/"
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(
                content_overrides={
                    agentic_url: (
                        b"<!doctype html><html><head><title>Not Found</title></head>"
                        b'<body><h1 class="sr-page-title">Page not found</h1></body></html>'
                    )
                }
            ),
            certificate_expiry=self.certificate,
        )

        failed = [check for check in report["checks"] if not check["ok"]]
        self.assertEqual([check["name"] for check in failed], ["content_integrity"])
        self.assertIn("AI agent security guide", failed[0]["message"])
        self.assertIn("expected primary heading", failed[0]["message"])

    def test_cve_database_must_keep_dataset_and_qualified_links(self) -> None:
        database_url = "https://security-recipes.ai/cve-database/"
        page_without_dataset = (
            b"<!doctype html><html><head>"
            b"<title>CVE Database | Security Recipes</title>"
            b'<meta name="description" content="Search a synchronized NVD and CISA '
            b"KEV CVE database with sourced facts, affected-version evidence, "
            b'canonical advisories, and bounded AI remediation.">'
            b'<meta name="robots" content="index,follow,max-image-preview:large">'
            b'<link rel="canonical" href="https://security-recipes.ai/cve-database/">'
            b'</head><body><h1 id="cve-database-heading">CVE Database</h1></body></html>'
        )
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(
                content_overrides={database_url: page_without_dataset}
            ),
            certificate_expiry=self.certificate,
        )

        failed = [check for check in report["checks"] if not check["ok"]]
        self.assertEqual([check["name"] for check in failed], ["content_integrity"])
        self.assertIn("Dataset structured data", failed[0]["message"])

    def test_cve_database_must_keep_evidence_qualified_links(self) -> None:
        database_url = "https://security-recipes.ai/cve-database/"
        page_without_qualified_links = (
            b"<!doctype html><html><head>"
            b"<title>CVE Database | Security Recipes</title>"
            b'<meta name="description" content="Search a synchronized NVD and CISA '
            b"KEV CVE database with sourced facts, affected-version evidence, "
            b'canonical advisories, and bounded AI remediation.">'
            b'<meta name="robots" content="index,follow,max-image-preview:large">'
            b'<link rel="canonical" href="https://security-recipes.ai/cve-database/">'
            b'<script type="application/ld+json">{"@context":"https://schema.org",'
            b'"@graph":[{"@type":"Dataset"}]}</script>'
            b'</head><body><h1 id="cve-database-heading">CVE Database</h1>'
            b'<a href="/cve/CVE-2026-14956/">CVE-2026-14956</a></body></html>'
        )
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(
                content_overrides={database_url: page_without_qualified_links}
            ),
            certificate_expiry=self.certificate,
        )

        failed = [check for check in report["checks"] if not check["ok"]]
        self.assertEqual([check["name"] for check in failed], ["content_integrity"])
        self.assertIn("evidence-qualified CVE route payload", failed[0]["message"])

    def test_old_generic_agents_page_fails_content_integrity(self) -> None:
        agents_url = "https://security-recipes.ai/agents/"
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(
                content_overrides={
                    agents_url: (
                        b"<!doctype html><html><head>"
                        b"<title>Agent Setup | Security Recipes</title>"
                        b'</head><body><h1 class="sr-page-title">'
                        b"Agent Setup</h1></body></html>"
                    )
                }
            ),
            certificate_expiry=self.certificate,
        )

        failed = [check for check in report["checks"] if not check["ok"]]
        self.assertEqual([check["name"] for check in failed], ["content_integrity"])
        self.assertIn("AI agent comparison", failed[0]["message"])
        self.assertIn("expected primary heading", failed[0]["message"])

    def test_cve_database_watchdog_contract_matches_source_description(self) -> None:
        source = (
            Path(__file__).resolve().parents[1]
            / "content"
            / "cve-database"
            / "_index.md"
        ).read_text(encoding="utf-8")
        probe = next(
            item
            for item in production.CONTENT_INTEGRITY_PROBES
            if item[0] == "CVE database"
        )
        required = dict(probe[3])
        description_lines = source.split("description: >", 1)[1].split("keywords:", 1)[0]
        description = " ".join(
            line.strip() for line in description_lines.splitlines() if line.strip()
        )

        self.assertRegex(
            f'<meta name="description" content="{description}">',
            required["database meta description"],
        )

    def test_agents_watchdog_contract_matches_source_title(self) -> None:
        source = (
            Path(__file__).resolve().parents[1] / "content" / "agents" / "_index.md"
        ).read_text(encoding="utf-8")
        title = next(
            line.removeprefix("title:").strip()
            for line in source.splitlines()
            if line.startswith("title:")
        )
        probe = next(
            item
            for item in production.CONTENT_INTEGRITY_PROBES
            if item[0] == "AI agent comparison"
        )
        required = dict(probe[3])
        description_lines = source.split("description: >", 1)[1].split("---", 1)[0]
        description = " ".join(
            line.strip() for line in description_lines.splitlines() if line.strip()
        )

        self.assertRegex(f'<h1 class="sr-page-title">{title}</h1>', probe[2])
        self.assertRegex(
            f"<title>{title} | Security Recipes</title>",
            required["query-specific page title"],
        )
        self.assertRegex(
            f'<meta name="description" content="{description}">',
            required["agent-comparison meta description"],
        )

    def test_clean_googlebot_variant_still_fails_cloaking_parity(self) -> None:
        automation_url = "https://security-recipes.ai/automation/"
        report = production.run_probes(
            base_url="https://security-recipes.ai",
            expected_revision=self.SHA,
            expected_commit_time=self.NOW - timedelta(hours=2),
            now=self.NOW,
            opener=self.opener(
                googlebot_overrides={
                    automation_url: (
                        b'<!doctype html><html><body><h1 class="sr-page-title">'
                        b"Automated Vulnerability Remediation Without AI Agents</h1>"
                        b"<!-- bot-only variant --></body></html>"
                    )
                }
            ),
            certificate_expiry=self.certificate,
        )

        failed = [check for check in report["checks"] if not check["ok"]]
        self.assertEqual([check["name"] for check in failed], ["content_integrity"])
        self.assertIn("differs between", failed[0]["message"])


if __name__ == "__main__":
    unittest.main()
