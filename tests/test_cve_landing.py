from __future__ import annotations

import json
import re
import unittest
from copy import deepcopy
from html import unescape
from pathlib import Path
from unittest.mock import AsyncMock, patch

from starlette.requests import Request

import mcp_server


ROOT = Path(__file__).resolve().parents[1]
STATIC_REVIEWED_ROUTES = {
    "CVE-2014-0160": "/recipes/cve/cve-2014-0160-heartbleed/",
    "CVE-2014-6271": "/recipes/cve/cve-2014-6271-shellshock/",
    "CVE-2017-18342": "/recipes/cve/cve-2017-18342-pyyaml/",
}


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
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "published": "2024-04-12",
            "last_modified": "2026-07-17T07:02:25Z",
            "kev": True,
            "kev_details": {
                "vendor_project": "Example Vendor",
                "product": "Widget",
                "vulnerability_name": "Example Widget Command Injection Vulnerability",
                "date_added": "2024-04-12",
                "due_date": "2024-04-19",
                "known_ransomware_campaign_use": "Known",
                "required_action": (
                    "Apply mitigations per vendor instructions or discontinue use "
                    "of the product if mitigations are unavailable."
                ),
                "source": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            },
            "ecosystem": "operating-system",
            "cwes": ["CWE-77", "CWE-78"],
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "products": [
                {"vendor": "Example Vendor", "product": "Widget", "version": "1.2.3"},
                {"vendor": "Example Vendor", "product": "Widget", "version": "1.2.4"},
            ],
            "product_match_count": 9,
            "source_identifier": "security@example.test",
            "status": "Analyzed",
            "quality": "curated",
            "recipe_kind": "markdown-override",
            "references": [
                {
                    "url": f"https://vendor.example.test/advisories/{cve}",
                    "tags": ["Vendor Advisory"],
                },
                {"url": "javascript:alert(1)", "tags": ["Unsafe"]},
            ],
            "ai_enrichment": {
                "status": "complete",
                "business_risk": "Successful exploitation can expose protected records.",
                "exposure_conditions": ["The affected endpoint is reachable by untrusted users."],
                "remediation_steps": [
                    "Upgrade Widget to the vendor-fixed release 2.0.0 after change approval."
                ],
                "verification_steps": ["Confirm the deployed version and run the regression suite."],
                "uncertainty": ["The catalog cannot establish the live deployment version."],
                "claim_evidence": [
                    {
                        "kind": "fixed_version",
                        "claim": "The vendor identifies 2.0.0 as fixed.",
                        "source_url": f"https://vendor.example.test/advisories/{cve}",
                    },
                    {
                        "kind": "unsafe",
                        "claim": "Unsafe citations are never linked.",
                        "source_url": "javascript:alert(2)",
                    },
                ],
                "source_urls": [
                    f"https://vendor.example.test/advisories/{cve}",
                    "javascript:alert(3)",
                ],
                "model": "test-model",
                "generated_at": "2026-07-17T07:03:00",
                "prompt_version": "2026-07-test",
                "recipe_specificity": "specific",
                "source_fingerprint": "a" * 64,
                "gaps": ["live_deployment_state"],
            },
        },
        "composed_recipe": {
            "archetype_id": "command_code_injection",
            "primary_archetype_id": "command_code_injection",
            "title": "Command, code, expression, and template injection",
            "exposure_checks": ["Trace <untrusted> values to process execution."],
            "containment_steps": ["Restrict the affected route until patching is complete."],
            "remediation_steps": ["Use structured argument APIs without a shell."],
            "verification_steps": ["Run inert command-boundary regression tests."],
            "rollback_steps": ["Restore the recorded prior artifact if health checks fail."],
            "stop_conditions": ["Stop when repository ownership is unclear."],
            "watch_for": ["Alternate encodings and indirect execution wrappers."],
            "required_output": "Return a reviewed patch or a TRIAGE.md blocker record.",
            "product_specific_override": [
                {
                    "cve": cve,
                    "maturity": "stable",
                    "title": f"{cve} reviewed recipe",
                    "path": f"content/recipes/cve/{cve.lower()}-reviewed.md",
                    "content_markdown": """# Reviewed product workflow

Use the **fixed release** and preserve evidence.

<script>window.evil = true</script>

[Unsafe link](javascript:alert(4))
[Vendor evidence](https://vendor.example.test/fixed)
[Related CVE]({{< relref \"/recipes/cve/cve-2023-22515-related\" >}})
![Tracking pixel](https://attacker.example.test/pixel.png)
""",
                }
            ],
        },
        "safety_boundary": "Guidance does not grant production mutation authority.",
        "agentic_change_plan": {
            "catalog_provenance": {
                "catalog_updated_at": "2026-07-17T07:02:25Z",
                "source_shard": {"path": "shards/2024/0003.jsonl.gz"},
            },
            "objective": "Produce one <reviewer-ready> change or stop for triage.",
            "authoritative_recipe": {
                "mutation_authority": "The catalog does not grant <write> authority."
            },
            "target_hints": {"file_globs": ["**/composer.json", "<unsafe-glob>"]},
            "fixed_version_policy": {
                "when_unknown": "Do not invent a fixed version; write TRIAGE.md."
            },
            "actions": [
                {
                    "id": "command_injection.<discover>",
                    "phase": "discover",
                    "operation": "inspect",
                    "archetype_title": "Command <injection>",
                    "target_kinds": ["dependency_manifest", "lockfile"],
                    "instructions": ["Inspect <paths> without running exploit input."],
                    "required_evidence": ["Record resolved <component> identity."],
                    "mutates_files": False,
                    "approval_gate": "none",
                    "required_output": "affected-surface-inventory",
                    "on_failure": "triage",
                }
            ],
        },
    }


def generic_recipe(cve: str = "CVE-2024-3400") -> dict[str, object]:
    recipe = sample_recipe(cve)
    source_record = recipe["source_record"]
    assert isinstance(source_record, dict)
    source_record.pop("ai_enrichment", None)
    source_record.pop("has_markdown", None)
    source_record["quality"] = "metadata-backed"
    source_record["recipe_kind"] = "composed"
    source_record["markdown"] = []
    composed = recipe["composed_recipe"]
    assert isinstance(composed, dict)
    composed["product_specific_override"] = []
    return recipe


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


def legacy_request_for(slug: str) -> Request:
    path = f"/recipes/cve/{slug}/"
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
            "path_params": {"slug": slug},
        }
    )


class CveLandingRenderTests(unittest.TestCase):
    def test_search_indexability_gate_has_cross_language_policy_parity(self) -> None:
        cases = (
            ({"recipe_kind": "markdown-override"}, True, "stable recipe kind"),
            ({"markdown": [{"maturity": "stable"}]}, True, "stable Markdown entry"),
            ({"has_markdown": True}, True, "explicit stable Markdown flag"),
            ({"ai_enrichment": {"status": "complete"}}, False, "unqualified complete AI"),
            (
                {
                    "quality": "curated",
                    "recipe_kind": "composed",
                    "markdown": [],
                },
                False,
                "generic record",
            ),
            (
                {"ai_enrichment": {"status": "insufficient_evidence"}},
                False,
                "incomplete AI",
            ),
            ({"ai_enrichment": ["complete"]}, False, "malformed AI"),
        )
        for source_record, expected, label in cases:
            with self.subTest(label=label):
                self.assertEqual(
                    mcp_server._cve_landing_is_search_indexable(source_record),
                    expected,
                )
        source_record = {
            "cve": "CVE-2024-3400",
            "ai_enrichment": {"status": "complete"},
        }
        with patch.object(mcp_server.cve_catalog, "is_search_indexable", return_value=True):
            self.assertTrue(mcp_server._cve_landing_is_search_indexable(source_record))

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
        self.assertIn('data-cve-id="CVE-2024-3400"', page)
        self.assertIn('data-site-signal-background="true"', page)
        self.assertIn('class="sr-docs-body sr-cve-detail-page"', page)
        self.assertIn(
            'class="content cve-catalog cve-landing sr-cve-detail-content"',
            page,
        )
        self.assertIn('<link rel="stylesheet" href="/css/cve-detail.css">', page)
        self.assertIn('<script src="/js/signal-background.js" defer></script>', page)
        self.assertIn('<link rel="stylesheet" href="/css/cve-catalog.css">', page)
        self.assertNotIn("cve-record-loader", page)
        self.assertNotIn('<script src="/js/cve-catalog.js"', page)
        self.assertNotIn("complete-record", page)
        self.assertNotIn("<details", page)
        self.assertIn('<meta name="theme-color" content="#020405">', page)
        self.assertIn('<meta property="og:image:type" content="image/png">', page)
        self.assertIn('<meta property="og:image:width" content="1727">', page)
        self.assertNotIn('property="article:published_time"', page)
        self.assertIn(
            'property="article:modified_time" content="2026-07-17T07:02:25Z"',
            page,
        )
        self.assertIn("<dt>CVE published</dt><dd>2024-04-12</dd>", page)
        self.assertIn("<dt>Source updated</dt><dd>2026-07-17T07:02:25Z</dd>", page)
        self.assertIn('/images/cve-database-social.png', page)
        self.assertIn('<a href="/cve-database/" aria-current="page">CVE Database</a>', page)
        self.assertIn('<a href="/cve-database/">CVE Database</a>', page)

        self.assertNotIn('href="/recipes/?view=cve"', page)
        self.assertNotIn('href="/recipes/cve/"', page)
        title_match = re.search(r"<title>(.*?)</title>", page)
        self.assertIsNotNone(title_match)
        assert title_match is not None
        self.assertLessEqual(len(unescape(title_match.group(1))), 70)
        self.assertNotIn("alert", unescape(title_match.group(1)))
        self.assertNotIn("\u2026", unescape(title_match.group(1)))
        description_match = re.search(
            r'<meta name="description" content="([^"]+)">',
            page,
        )
        self.assertIsNotNone(description_match)
        assert description_match is not None
        description = unescape(description_match.group(1))
        self.assertLessEqual(len(description), 165)
        self.assertIn("Use the fixed release and preserve evidence", description)
        self.assertNotIn("Upgrade Widget", description)
        self.assertNotIn("\u2026", description)
        self.assertNotIn("alert", description)
        h1_match = re.search(r'<h1 class="sr-page-title">(.*?)</h1>', page)
        self.assertIsNotNone(h1_match)
        assert h1_match is not None
        self.assertEqual(
            unescape(h1_match.group(1)),
            unescape(title_match.group(1)),
        )
        for heading_id, label in (
            ("overview-heading", "Overview"),
            ("products-heading", "Affected products and version ranges"),
            ("detection-triage-heading", "Detection and triage"),
            ("remediation-authority-heading", "Remediation authority"),
            ("use-ai-heading", "Use AI to implement and verify"),
            ("sources-heading", "Sources, provenance, and citation"),
        ):
            with self.subTest(heading_id=heading_id):
                self.assertEqual(page.count(f'id="{heading_id}"'), 1)
                self.assertIn(label, page)
        self.assertEqual(page.count("data-remediation-authority="), 1)
        self.assertIn('data-remediation-authority="stable-reviewed"', page)
        self.assertIn("Stable reviewed recipe", page)
        self.assertIn("Use the fixed release and preserve evidence", page)
        self.assertIn("sole remediation authority", page)
        self.assertIn("9 NVD CPE configuration matches", page)
        self.assertIn(
            '<time datetime="2026-07-17T07:02:25Z">2026-07-17</time>',
            page,
        )
        self.assertIn("Known exploited", page)
        self.assertIn("2024-04-19", page)
        self.assertIn("Known ransomware use", page)
        self.assertNotIn("Apply mitigations per vendor instructions", page)
        self.assertIn("Read-only exposure checks", page)
        self.assertIn("Trace &lt;untrusted&gt; values to process execution", page)
        self.assertIn("Detection signals and verification", page)
        self.assertIn("Alternate encodings and indirect execution wrappers", page)
        self.assertIn("Stop when repository ownership is unclear", page)
        self.assertIn("Return a reviewed patch or a TRIAGE.md blocker record", page)

        self.assertIn("<strong>Inspect:</strong>", page)
        self.assertIn("<strong>Change:</strong>", page)
        self.assertIn("<strong>Approval:</strong>", page)
        self.assertIn("<strong>Test:</strong>", page)
        self.assertIn("<strong>Rollback:</strong>", page)
        self.assertIn("Copyable agent prompt", page)
        self.assertIn("Implement and verify remediation for CVE-2024-3400", page)
        self.assertIn("do not apply it yet", page)
        self.assertIn("does not grant write or production authority", page)
        self.assertIn(
            "use the approved system-image, package, configuration, or failover "
            "recovery procedure",
            page,
        )
        self.assertIn("Never automatically downgrade into an affected version", page)
        self.assertNotIn("Restore the recorded prior artifact", page)
        self.assertNotIn("&lt;unsafe-glob&gt;", page)
        self.assertIn("Example Vendor / Widget", page)
        self.assertIn("NVD CPE exact-version criterion: 1.2.3.", page)
        self.assertIn("derived from NVD CPE configuration matches", page)
        self.assertIn("not vendor-authored affected-version statements", page)
        self.assertIn(
            'href="https://github.com/stevologic/security-recipes.ai/blob/main/'
            'content/recipes/cve/cve-2024-3400-reviewed.md"',
            page,
        )
        self.assertNotIn("attacker.example.test", page)
        self.assertNotIn("javascript:", page)
        self.assertNotIn("<script>window.evil", page)
        self.assertNotIn("window.evil", page)
        self.assertNotIn('</title><script>alert("title")</script>', page)
        self.assertIn(
            "Widget &lt;/title&gt;&lt;script&gt;alert(&quot;title&quot;)&lt;/script&gt;",
            page,
        )
        self.assertNotIn("Successful exploitation can expose protected records", page)
        self.assertNotIn("Source-specific exposure conditions", page)
        self.assertIn('<h3 id="cite-record-heading">Citation</h3>', page)
        self.assertIn(
            'href="https://security-recipes.example/base/cve/CVE-2024-3400/"',
            page,
        )
        self.assertIn(
            'href="/api/cve-catalog/shards/2024/0003.jsonl.gz"',
            page,
        )
        self.assertIn('href="#remediation-authority-heading"', page)
        self.assertIn('href="#detection-triage-heading"', page)
        self.assertIn('href="#sources-heading"', page)

        match = re.search(
            r'<script type="application/ld\+json">(.*?)</script>',
            page,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match)
        assert match is not None
        self.assertNotIn("<", match.group(1))
        structured = json.loads(match.group(1))
        graph = structured["@graph"]
        by_type = {node["@type"]: node for node in graph}
        self.assertEqual(
            set(by_type),
            {
                "Organization",
                "WebSite",
                "WebPage",
                "Article",
                "BreadcrumbList",
                "DefinedTerm",
            },
        )
        article = by_type["Article"]
        self.assertEqual(article["additionalType"], "https://schema.org/TechArticle")
        self.assertEqual(article["identifier"], "CVE-2024-3400")
        self.assertEqual(
            article["url"],
            "https://security-recipes.example/base/cve/CVE-2024-3400/",
        )
        self.assertNotIn("datePublished", article)
        self.assertEqual(article["dateModified"], "2026-07-17T07:02:25Z")
        self.assertNotIn("datePublished", by_type["WebPage"])
        self.assertEqual(
            by_type["WebPage"]["dateModified"],
            "2026-07-17T07:02:25Z",
        )
        self.assertEqual(article["image"]["width"], 1727)
        self.assertEqual(
            article["citation"],
            [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
                "https://www.cve.org/CVERecord?id=CVE-2024-3400",
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                "?field_cve=CVE-2024-3400",
            ],
        )
        self.assertIn("CISA KEV", article["keywords"])
        self.assertEqual(by_type["DefinedTerm"]["termCode"], "CVE-2024-3400")
        self.assertEqual(
            [item["name"] for item in by_type["BreadcrumbList"]["itemListElement"]],
            ["Home", "CVE Database", "CVE-2024-3400"],
        )

    def test_static_workflow_and_agent_plan_cap_repeated_machine_fields(self) -> None:
        recipe = sample_recipe()
        composed = recipe["composed_recipe"]
        plan = recipe["agentic_change_plan"]
        assert isinstance(composed, dict)
        assert isinstance(plan, dict)

        field_limits = {
            "exposure_checks": 2,
            "containment_steps": 1,
            "remediation_steps": 2,
            "verification_steps": 2,
            "rollback_steps": 1,
            "stop_conditions": 2,
        }
        for field_name in (*field_limits, "watch_for"):
            composed[field_name] = [
                f"{field_name} visible candidate {index}" for index in range(12)
            ]

        raw_actions = plan["actions"]
        assert isinstance(raw_actions, list)
        base_action = raw_actions[0]
        assert isinstance(base_action, dict)
        phases = (
            "discover",
            "assess",
            "mitigate",
            "remediate",
            "verify",
            "rollback",
            "triage",
        )
        plan["actions"] = [
            {
                **base_action,
                "phase": phase,
                "archetype_title": f"Archetype {archetype_index}",
                "instructions": [
                    f"Instruction {phase}.{archetype_index}.{item}"
                    for item in range(8)
                ],
                "required_evidence": [
                    f"Evidence {phase}.{archetype_index}.{item}"
                    for item in range(6)
                ],
            }
            for phase in phases
            for archetype_index in range(3)
        ]

        workflow_html = mcp_server._cve_landing_workflow_html(
            "CVE-2024-3400",
            composed,
            recipe["safety_boundary"],
        )
        agent_html = mcp_server._cve_landing_agentic_plan_html(plan)

        self.assertEqual(
            workflow_html.count("<li>"),
            sum(field_limits.values()),
        )
        self.assertNotIn("watch_for visible candidate", workflow_html)
        self.assertNotIn('class="cve-catalog__agent-action"', agent_html)
        for phase in phases:
            self.assertNotIn(f"{phase.title()} —", agent_html)
        for archetype_index in range(3):
            self.assertNotIn(f"Archetype {archetype_index}", agent_html)
        self.assertNotIn("Instruction discover.0.0", agent_html)
        self.assertNotIn("Evidence discover.0.0", agent_html)
        self.assertNotIn("&lt;unsafe-glob&gt;", agent_html)
        self.assertNotIn("<details", agent_html)
        self.assertIn("<strong>Objective:</strong>", agent_html)
        self.assertIn("<strong>Mutation authority:</strong>", agent_html)
        self.assertIn('href="#sources-heading"', workflow_html)
        self.assertIn('href="#use-ai-heading"', agent_html)

        agent_text = unescape(re.sub(r"<[^>]+>", " ", agent_html))
        agent_words = re.findall(r"[A-Za-z0-9][A-Za-z0-9'-]*", agent_text)
        self.assertLessEqual(len(agent_words), 80)

        plain_summary = unescape(
            re.sub(r"<[^>]+>", " ", workflow_html + agent_html)
        )
        summary_words = re.findall(r"[A-Za-z0-9][A-Za-z0-9'-]*", plain_summary)
        self.assertLessEqual(len(summary_words), 500)

    def test_related_cves_render_without_playbook_promotion(self) -> None:
        recipe = sample_recipe()
        # Ignore a legacy supplemental field if an older caller still supplies it.
        recipe["matched_playbook"] = {
            "id": "recipe-recommender",
            "title": "Recipe Recommender",
            "page": "/security-remediation/recipe-recommender/",
            "summary": "Classify the owned finding before choosing a remediation workflow.",
        }
        recipe["related_cves"] = [
            {
                "cve": "CVE-2024-3400",
                "title": "The current record must be excluded",
                "severity": "critical",
                "score": 9.8,
                "published": "2024-04-12",
                "qualification": "stable_markdown",
            },
            {
                "cve": "CVE-2021-44228",
                "title": "Log4j <script>related</script> injection",
                "severity": "critical",
                "score": 10.0,
                "published": "2021-12-10",
                "qualification": "recipe_ready_ai",
                "href": "javascript:alert(1)",
                "relationship": {
                    "type": "same_primary_product",
                    "vendor": "Apache <script>",
                    "product": "Log4j",
                },
            },
            {
                "cve": "CVE-2017-18342",
                "title": "PyYAML unsafe deserialization",
                "severity": "critical",
                "score": 9.8,
                "published": "2018-06-26",
                "qualification": "stable_markdown",
                "relationship": {
                    "type": "same_specific_cwe",
                    "cwe": "CWE-502",
                },
            },
            {
                "cve": "not-a-cve",
                "title": "javascript:alert(1)",
            },
            {
                "cve": "CVE-2025-99999",
                "title": "Unqualified guidance must fail closed",
                "severity": "high",
                "score": 8.1,
                "published": "2025-01-01",
                "qualification": "",
            },
            {
                "cve": "CVE-2025-99998",
                "title": "Generic evidence must fail closed",
                "severity": "high",
                "score": 8.1,
                "published": "2025-01-01",
                "qualification": "recipe_ready_ai",
                "relationship": {
                    "type": "same_specific_cwe",
                    "cwe": "CWE-20",
                },
            },
            {
                "cve": "CVE-2025-99997",
                "title": "Untyped evidence must fail closed",
                "severity": "high",
                "score": 8.1,
                "published": "2025-01-01",
                "qualification": "recipe_ready_ai",
                "relationship": {
                    "type": "same_vendor_guess",
                    "value": "unreviewed",
                },
            },
        ]

        page = mcp_server._render_cve_landing_page(
            recipe,
            "https://security-recipes.example/base/",
        )

        self.assertIn('<h2 id="resources-heading">Related CVEs</h2>', page)
        self.assertNotIn('href="/security-remediation/recipe-recommender/"', page)
        self.assertNotIn("Recipe Recommender", page)
        self.assertNotIn("Choose an AI remediation playbook", page)
        self.assertNotIn("<strong>Playbook:</strong>", page)
        self.assertIn("<strong>Related:</strong>", page)
        self.assertIn('href="/cve/CVE-2021-44228/"', page)
        self.assertIn(
            'href="/recipes/cve/cve-2017-18342-pyyaml/"',
            page,
        )
        self.assertNotIn('href="/cve/CVE-2017-18342/"', page)
        self.assertIn(
            "CVE-2017-18342: PyYAML Default load Resolves Arbitrary Tags",
            page,
        )
        self.assertNotIn("The current record must be excluded", page)
        self.assertIn("Log4j &lt;script&gt;related&lt;/script&gt; injection", page)
        self.assertIn(
            "same primary product: Apache &lt;script&gt; / Log4j",
            page,
        )
        self.assertIn("shared specific weakness: CWE-502", page)
        self.assertNotIn("javascript:alert(1)", page)
        self.assertNotIn("Unqualified guidance must fail closed", page)
        self.assertNotIn("Generic evidence must fail closed", page)
        self.assertNotIn("Untyped evidence must fail closed", page)
        self.assertIn('href="#resources-heading"', page)

        match = re.search(
            r'<script type="application/ld\+json">(.*?)</script>',
            page,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match)
        assert match is not None
        structured = json.loads(match.group(1))
        webpage = next(
            node for node in structured["@graph"] if node.get("@type") == "WebPage"
        )
        self.assertEqual(
            webpage["relatedLink"],
            [
                "https://security-recipes.example/base/cve/CVE-2021-44228/",
                "https://security-recipes.example/base/recipes/cve/cve-2017-18342-pyyaml/",
            ],
        )

    def test_related_record_boundary_is_bounded_canonical_and_evidence_gated(
        self,
    ) -> None:
        related = [
            {
                "cve": f"CVE-2026-{30000 + index}",
                "title": f"Related record {index}",
                "severity": "high",
                "score": 8.0,
                "published": "2026-01-01",
                "qualification": "recipe_ready_ai",
                "href": "javascript:alert(1)",
                "relationship": {
                    "type": "same_remediation_pattern",
                    "archetype": "command_code_injection",
                },
            }
            for index in range(7)
        ]
        related.insert(
            0,
            {
                "cve": "CVE-2026-39998",
                "title": "Missing typed evidence",
                "severity": "high",
                "score": 8.0,
                "published": "2026-01-01",
                "qualification": "recipe_ready_ai",
            },
        )
        related.insert(
            1,
            {
                "cve": "CVE-2026-39999",
                "title": "Evidence with an unexpected field",
                "severity": "high",
                "score": 8.0,
                "published": "2026-01-01",
                "qualification": "recipe_ready_ai",
                "relationship": {
                    "type": "same_specific_cwe",
                    "cwe": "CWE-89",
                    "unreviewed": "must fail closed",
                },
            },
        )
        related.insert(
            2,
            {
                "cve": "CVE-2026-39997",
                "title": "Non-string evidence type",
                "severity": "high",
                "score": 8.0,
                "published": "2026-01-01",
                "qualification": "recipe_ready_ai",
                "relationship": {"type": []},
            },
        )

        records = mcp_server._cve_landing_related_records(
            "CVE-2026-14956",
            related,
            limit=99,
        )

        self.assertEqual(len(records), 6)
        self.assertEqual(
            [record["href"] for record in records],
            [f"/cve/CVE-2026-{30000 + index}/" for index in range(6)],
        )
        self.assertTrue(
            all(
                record["relationship"]["type"] == "same_remediation_pattern"
                for record in records
            )
        )
        self.assertNotIn("javascript:", json.dumps(records))
        self.assertNotIn("39998", json.dumps(records))
        self.assertNotIn("39999", json.dumps(records))
        self.assertNotIn("39997", json.dumps(records))

    def test_contextual_helpers_use_static_canonicals(self) -> None:
        for cve_id, route in STATIC_REVIEWED_ROUTES.items():
            with self.subTest(cve_id=cve_id):
                self.assertEqual(mcp_server._cve_landing_related_href(cve_id), route)
                self.assertEqual(
                    mcp_server._cve_landing_content_href(
                        f"/recipes/cve/{cve_id.lower()}-legacy/"
                    ),
                    route,
                )
        self.assertEqual(
            mcp_server._cve_landing_related_href("CVE-2024-3400"),
            "/cve/CVE-2024-3400/",
        )
        self.assertEqual(mcp_server._cve_landing_related_href("invalid"), "")

    def test_citation_download_rejects_a_non_catalog_shard_path(self) -> None:
        recipe = sample_recipe()
        agentic_plan = recipe["agentic_change_plan"]
        assert isinstance(agentic_plan, dict)
        provenance = agentic_plan["catalog_provenance"]
        assert isinstance(provenance, dict)
        provenance["source_shard"] = {"path": "../../private.jsonl.gz"}

        page = mcp_server._render_cve_landing_page(recipe)

        self.assertIn('<h3 id="cite-record-heading">Citation</h3>', page)
        self.assertNotIn("../../private.jsonl.gz", page)
        self.assertNotIn("Download the machine-readable source shard", page)

    def test_reviewed_relrefs_use_slash_canonical_content_routes(self) -> None:
        rendered = mcp_server._cve_landing_markdown(
            "[Threat model]({{< relref \"/fundamentals/threat-model#scope\" >}})\n\n"
            "[Already canonical]({{< relref \"/security-remediation/\" >}})\n\n"
            "[Machine feed]({{< relref \"/api/example.json?v=1\" >}})\n\n"
            "[Ordinary endpoint](/mcp)"
        )

        self.assertIn('href="/fundamentals/threat-model/#scope"', rendered)
        self.assertIn('href="/security-remediation/"', rendered)
        self.assertIn('href="/api/example.json?v=1"', rendered)
        self.assertIn('href="/mcp"', rendered)
        self.assertNotIn('href="/mcp/"', rendered)

    def test_reviewed_markdown_decodes_entities_once_and_keeps_raw_html_inert(self) -> None:
        rendered = mcp_server._cve_landing_markdown(
            "Compare `3 > 2` & keep AT&amp;T readable.\n\n"
            "<script>window.evil = true</script>"
        )

        self.assertIn("<code>3 &gt; 2</code> &amp; keep AT&amp;T readable", rendered)
        self.assertNotIn("&amp;gt;", rendered)
        self.assertNotIn("&amp;amp;T", rendered)
        self.assertIn("&lt;script&gt;window.evil = true&lt;/script&gt;", rendered)
        self.assertNotIn("<script>window.evil", rendered)

    def test_source_entities_and_truncated_summaries_render_as_complete_text(self) -> None:
        self.assertEqual(
            mcp_server._cve_landing_text("Cisco IM &amp;P&nbsp;Service"),
            "Cisco IM &P Service",
        )
        summary = (
            "The first complete source sentence explains the affected product. "
            "The second complete sentence records the supported fix. "
            "This final source fragment was cut during catalog normalization\u2026"
        )
        self.assertEqual(
            mcp_server._cve_landing_summary_text(summary),
            "The first complete source sentence explains the affected product. "
            "The second complete sentence records the supported fix.",
        )

    def test_generic_page_is_accessible_but_nonindexable(self) -> None:
        with patch.object(mcp_server.cve_catalog, "is_search_indexable", return_value=False):
            page = mcp_server._render_cve_landing_page(
                generic_recipe(),
                "https://security-recipes.example/",
            )

        self.assertIn(
            '<link rel="canonical" '
            'href="https://security-recipes.example/cve/CVE-2024-3400/">',
            page,
        )
        self.assertIn('<meta name="robots" content="noindex,follow">', page)
        self.assertIn('<meta name="googlebot" content="noindex,follow">', page)
        self.assertIn('data-cve-id="CVE-2024-3400"', page)
        self.assertIn('data-remediation-authority="bounded-fallback"', page)
        self.assertIn('<h2 id="detection-triage-heading">Detection and triage</h2>', page)
        self.assertIn("Read-only exposure checks", page)
        self.assertIn("Stop and triage", page)

    def test_ai_detection_and_triage_details_are_flat_source_linked_and_complete(self) -> None:
        recipe = sample_recipe()
        composed = recipe["composed_recipe"]
        source = recipe["source_record"]
        assert isinstance(composed, dict)
        assert isinstance(source, dict)
        composed["product_specific_override"] = []
        source["recipe_kind"] = "composed"
        enrichment = source["ai_enrichment"]
        assert isinstance(enrichment, dict)
        remediation_steps = enrichment["remediation_steps"]
        verification_steps = enrichment["verification_steps"]
        assert isinstance(remediation_steps, list)
        assert isinstance(verification_steps, list)
        remediation_steps.extend(
            [
                "Second reviewed remediation step.",
                "Third reviewed remediation step.",
                "Fourth reviewed remediation step.",
            ]
        )
        verification_steps.extend(
            [
                "Second source-linked verification step.",
                "Third source-linked verification step.",
            ]
        )

        with patch.object(
            mcp_server.cve_catalog,
            "search_qualification",
            return_value="recipe_ready_ai",
        ):
            page = mcp_server._render_cve_landing_page(recipe)

        self.assertIn('data-remediation-authority="complete-ai-enrichment"', page)
        self.assertIn('<h2 id="detection-triage-heading">Detection and triage</h2>', page)
        self.assertIn("AI evidence status", page)
        self.assertIn("passed the recipe-ready evidence gate", page)
        self.assertIn("Successful exploitation can expose protected records", page)
        self.assertIn("Source-specific exposure conditions", page)
        self.assertIn("affected endpoint is reachable by untrusted users", page)
        self.assertIn("catalog cannot establish the live deployment version", page)
        self.assertIn("Evidence-linked AI claims", page)
        self.assertIn("The vendor identifies 2.0.0 as fixed", page)
        self.assertIn("Fourth reviewed remediation step", page)
        self.assertIn("Third source-linked verification step", page)
        self.assertNotIn("<details", page)

    def test_stable_markdown_page_is_indexable_without_ai_enrichment(self) -> None:
        recipe = generic_recipe()
        source_record = recipe["source_record"]
        assert isinstance(source_record, dict)
        source_record["recipe_kind"] = "markdown-override"

        page = mcp_server._render_cve_landing_page(recipe)

        self.assertIn(
            '<meta name="robots" '
            'content="index,follow,max-image-preview:large,max-snippet:-1,max-video-preview:-1">',
            page,
        )

    def test_complete_but_nonspecific_ai_is_a_provenanced_bounded_fallback(self) -> None:
        recipe = mcp_server._bounded_cve_landing_lookup("CVE-2010-5330")
        source = recipe["source_record"]
        assert isinstance(source, dict)
        enrichment = source["ai_enrichment"]
        assert isinstance(enrichment, dict)
        self.assertEqual(enrichment.get("status"), "complete")
        self.assertEqual(enrichment.get("recipe_specificity"), "not_specific")
        self.assertEqual(mcp_server._cve_landing_search_qualification(source), "")

        page = mcp_server._render_cve_landing_page(recipe)

        self.assertIn('data-remediation-authority="bounded-fallback"', page)
        self.assertNotIn('data-remediation-authority="complete-ai-enrichment"', page)
        self.assertIn("Non-authoritative AI evaluation", page)
        self.assertIn(
            "did not establish a product-specific remediation recipe",
            page,
        )
        self.assertIn("model gpt-5.6-luna", page)
        self.assertIn("generated 2026-07-29", page)
        self.assertIn("Use it only to inform triage", page)

    def test_human_review_blocked_ai_names_the_non_authoritative_reason(self) -> None:
        recipe = generic_recipe("CVE-2099-99001")
        source = recipe["source_record"]
        assert isinstance(source, dict)
        source["ai_enrichment"] = deepcopy(
            sample_recipe()["source_record"]["ai_enrichment"]
        )
        source["recipe_kind"] = "markdown-draft"
        source["markdown"] = [
            {
                "cve": "CVE-2099-99001",
                "maturity": "development",
                "ai_enrichment_review_status": "human-reviewed-development-draft",
            }
        ]

        with patch.object(mcp_server.cve_catalog, "is_search_indexable", return_value=True):
            page = mcp_server._render_cve_landing_page(recipe)

        self.assertIn('data-remediation-authority="bounded-fallback"', page)
        self.assertNotIn('data-remediation-authority="complete-ai-enrichment"', page)
        self.assertIn("Non-authoritative AI evaluation", page)
        self.assertIn(
            "development-stage human review explicitly withholds",
            page,
        )
        self.assertIn("model test-model", page)
        self.assertIn("generated 2026-07-17", page)

    def test_structured_affected_data_renders_ranges_and_status_transitions(self) -> None:
        recipe = sample_recipe("CVE-2026-14956")
        source = recipe["source_record"]
        assert isinstance(source, dict)
        source["affected_data"] = [
            {
                "vendor": "Bricksforge <vendor>",
                "product": "Bricksforge",
                "default_status": "unaffected",
                "source": "security@wordfence.com",
                "platforms": ["WordPress"],
                "versions": [
                    {
                        "version": "0",
                        "less_than_or_equal": "3.1.8.6",
                        "less_than": "",
                        "version_type": "semver",
                        "status": "affected",
                        "changes": [
                            {"at": "3.1.8.7", "status": "unaffected"},
                        ],
                    }
                ],
                "version_count": 1,
                "versions_truncated": False,
            }
        ]
        source["affected_data_count"] = 1
        source["affected_data_stored"] = 1
        source["affected_data_truncated"] = False

        page = mcp_server._render_cve_landing_page(recipe)

        self.assertIn("Affected products and version ranges", page)
        self.assertIn("Bricksforge &lt;vendor&gt; / Bricksforge", page)
        self.assertIn("Affected: versions 0 through 3.1.8.6 inclusive (semver).", page)
        self.assertIn("Source status changes to unaffected at 3.1.8.7.", page)
        self.assertIn("Platforms: WordPress.", page)
        self.assertIn("Affected-status source: security@wordfence.com.", page)
        self.assertNotIn("derived from NVD CPE configuration matches", page)
        self.assertNotIn("No browser-safe affected-product rows", page)

    def test_reviewed_version_evidence_replaces_the_contradictory_empty_state(self) -> None:
        recipe = mcp_server.cve_catalog.get_recipe("CVE-2026-14956")

        page = mcp_server._render_cve_landing_page(recipe)

        self.assertIn('data-remediation-authority="stable-reviewed"', page)
        self.assertIn(
            '<meta name="description" content="Critical, unauthenticated Bricksforge '
            "privilege escalation (CVSS 9.8). Check public User Registration forms. "
            'Upgrade WordPress sites to Bricksforge 3.1.8.7 or later.">',
            page,
        )
        self.assertIn("Upgrade WordPress sites to Bricksforge 3.1.8.7 or later", page)
        self.assertNotIn("No browser-safe affected-product rows", page)
        self.assertEqual(page.count('id="remediation-authority-heading"'), 1)
        self.assertEqual(page.count('id="use-ai-heading"'), 1)
        self.assertNotIn("<details", page)

    def test_reviewed_version_evidence_fills_an_empty_product_table(self) -> None:
        """Cover the empty-products branch without assuming upstream stays empty.

        NVD can start publishing affected-product rows for any CVE at any time
        (CVE-2026-14956 gained one), which legitimately replaces this fallback
        with a real table. Drive the branch from the record so the rendering
        rule stays covered either way.
        """
        recipe = deepcopy(mcp_server.cve_catalog.get_recipe("CVE-2026-14956"))
        # products_html is structured affected_data OR the CPE product rows, so
        # both have to be empty to reach the fallback.
        recipe["source_record"]["products"] = []
        recipe["source_record"]["product_match_count"] = 0
        recipe["source_record"]["affected_data"] = []
        recipe["source_record"]["affected_data_count"] = 0

        page = mcp_server._render_cve_landing_page(recipe)

        self.assertIn(
            "The stable reviewed recipe contains product-specific version evidence "
            "and upgrade guidance.",
            page,
        )
        self.assertNotIn("No browser-safe affected-product rows", page)

    def test_populated_products_replace_the_reviewed_evidence_fallback(self) -> None:
        recipe = deepcopy(mcp_server.cve_catalog.get_recipe("CVE-2026-14956"))
        recipe["source_record"]["products"] = [
            {
                "vendor": "bricksforge",
                "product": "bricksforge",
                "version": "*",
                "version_start_including": "",
                "version_start_excluding": "",
                "version_end_including": "",
                "version_end_excluding": "3.1.8.7",
            }
        ]
        recipe["source_record"]["product_match_count"] = 1

        page = mcp_server._render_cve_landing_page(recipe)

        self.assertIn("bricksforge", page.lower())
        self.assertNotIn(
            "The stable reviewed recipe contains product-specific version evidence",
            page,
        )
        self.assertNotIn("No browser-safe affected-product rows", page)

    def test_real_reviewed_cve_omits_unrelated_qualified_records(self) -> None:
        recipe = mcp_server._bounded_cve_landing_lookup("CVE-2026-14956")

        page = mcp_server._render_cve_landing_page(recipe)

        self.assertNotIn("related_cves", recipe)
        self.assertNotIn("Related CVEs with qualified remediation guidance", page)

    def test_cpe_fallback_renders_all_bounds_deduplicates_and_marks_provenance(self) -> None:
        recipe = generic_recipe("CVE-2025-12345")
        source = recipe["source_record"]
        assert isinstance(source, dict)
        source.pop("affected_data", None)
        bounded_product = {
            "vendor": "Example <Vendor>",
            "product": "Bounded Widget",
            "version": "*",
            "version_start_including": "2.0.0",
            "version_start_excluding": "1.9.9",
            "version_end_including": "2.4.0",
            "version_end_excluding": "2.4.1",
        }
        source["products"] = [
            bounded_product,
            dict(bounded_product),
            {
                "vendor": "Example Vendor",
                "product": "Exact Widget",
                "version": "3.7.2",
            },
            {
                "vendor": "Example Vendor",
                "product": "Unbounded Widget",
                "version": "-",
            },
        ]
        source["product_match_count"] = 7

        page = mcp_server._render_cve_landing_page(recipe)
        products_match = re.search(
            r'<section class="cve-catalog__detail-section" '
            r'aria-labelledby="products-heading">(.*?)</section>',
            page,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(products_match)
        assert products_match is not None
        products_html = products_match.group(1)

        self.assertEqual(products_html.count("Example &lt;Vendor&gt; / Bounded Widget"), 1)
        self.assertIn(
            "NVD CPE configured version bounds: &gt;= 2.0.0 and &gt; 1.9.9 "
            "and &lt;= 2.4.0 and &lt; 2.4.1.",
            products_html,
        )
        self.assertIn("NVD CPE exact-version criterion: 3.7.2.", products_html)
        self.assertNotIn("NVD CPE exact-version criterion: *", products_html)
        self.assertIn(
            "This NVD CPE match has no exact or bounded version; do not read it "
            "as proof that every version is affected.",
            products_html,
        )
        self.assertIn("derived from NVD CPE configuration matches", products_html)
        self.assertIn("not vendor-authored affected-version statements", products_html)
        self.assertIn("Confirm the exact affected and fixed versions", products_html)
        self.assertIn(
            "Showing 3 representative product identities from 7 NVD CPE "
            "configuration matches.",
            products_html,
        )

    def test_placeholder_products_and_versions_fall_back_to_cpe_identity(self) -> None:
        recipe = generic_recipe("CVE-2099-99002")
        source = recipe["source_record"]
        assert isinstance(source, dict)
        source["affected_data"] = [
            {
                "vendor": "n/a",
                "product": "unknown",
                "default_status": "affected",
                "versions": [
                    {
                        "version": "unspecified",
                        "less_than": "n/a",
                        "status": "affected",
                    }
                ],
            }
        ]
        source["products"] = [
            {
                "vendor": "Acme",
                "product": "WidgetOS",
                "version": "*",
                "version_start_including": "1.0.0",
                "version_end_excluding": "2.0.0",
            }
        ]
        source["product_match_count"] = 1

        page = mcp_server._render_cve_landing_page(recipe)
        products_match = re.search(
            r'aria-labelledby="products-heading">(.*?)</section>',
            page,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(products_match)
        assert products_match is not None
        products_text = unescape(re.sub(r"<[^>]+>", " ", products_match.group(1)))

        self.assertIn("Acme / WidgetOS", products_text)
        self.assertIn(">= 1.0.0 and < 2.0.0", products_text)
        self.assertIn("derived from NVD CPE configuration matches", products_text)
        self.assertNotRegex(
            products_text,
            r"(?i)\b(?:n/a|unknown|unspecified)\b",
        )
        self.assertIn("Inventory every owned instance of Acme / WidgetOS", page)
        self.assertNotIn("Inventory every owned instance of n/a", page)

    def test_incomplete_ai_enrichment_is_not_rendered(self) -> None:
        recipe = sample_recipe()
        source = recipe["source_record"]
        assert isinstance(source, dict)
        enrichment = source["ai_enrichment"]
        assert isinstance(enrichment, dict)
        enrichment["status"] = "insufficient_evidence"
        enrichment["business_risk"] = "UNVERIFIED SENTINEL CLAIM"

        page = mcp_server._render_cve_landing_page(recipe)

        self.assertNotIn("AI-assisted evidence synthesis", page)
        self.assertNotIn("UNVERIFIED SENTINEL CLAIM", page)

    def test_ai_enrichment_flattens_markdown_citations_but_keeps_structured_sources(self) -> None:
        recipe = mcp_server._bounded_cve_landing_lookup("CVE-2025-64446")

        page = mcp_server._render_cve_landing_page(recipe)

        self.assertIn('data-remediation-authority="complete-ai-enrichment"', page)
        self.assertIn("Complete source-linked AI enrichment", page)
        self.assertIn("Upgrade FortiWeb 7.0 deployments to 7.0.12 or later", page)
        self.assertIn("<strong>Verify</strong>", page)
        self.assertIn(
            'href="https://fortiguard.fortinet.com/psirt/FG-IR-25-910"',
            page,
        )
        self.assertNotIn("](", page)
        self.assertNotIn("utm_source=openai", page)

    def test_ai_handoff_uses_deployment_aware_non_downgrade_recovery(self) -> None:
        fixtures = (
            (
                {"ecosystem": "javascript/npm"},
                ["@tanstack / react-router"],
                "captured lockfile, package, image, and data backup",
            ),
            (
                {"ecosystem": "operating-system"},
                ["paloaltonetworks / pan-os"],
                "vendor recovery, configuration-backup, or HA failover procedure",
            ),
            (
                {"ecosystem": "software/application"},
                ["Atlassian / Jira Server"],
                "application, database, configuration, or deployment-artifact recovery",
            ),
        )
        for source, products, expected in fixtures:
            with self.subTest(source=source, products=products):
                recovery = mcp_server._cve_landing_recovery_guidance(source, products)
                self.assertIn(expected, recovery)
                self.assertIn(
                    "Never automatically downgrade into an affected version",
                    recovery,
                )
                self.assertIn("if no known-safe recovery target exists", recovery)

        recipe = generic_recipe("CVE-2099-99003")
        source = recipe["source_record"]
        composed = recipe["composed_recipe"]
        assert isinstance(source, dict)
        assert isinstance(composed, dict)
        source["ecosystem"] = "javascript/npm"
        source["products"] = [
            {"vendor": "@tanstack", "product": "react-router", "version": "*"}
        ]
        composed["rollback_steps"] = [
            "ROLL BACK TO AN UNVERIFIED PRIOR RELEASE SENTINEL"
        ]

        page = mcp_server._render_cve_landing_page(recipe)

        self.assertIn("captured lockfile, package, image, and data backup", page)
        self.assertIn("Never automatically downgrade into an affected version", page)
        self.assertNotIn("UNVERIFIED PRIOR RELEASE SENTINEL", page)
        self.assertNotIn("vendor recovery, configuration-backup", page)

    def test_primary_references_filter_raw_nvd_links_and_match_schema(self) -> None:
        recipe = sample_recipe()
        composed = recipe["composed_recipe"]
        source = recipe["source_record"]
        assert isinstance(composed, dict)
        assert isinstance(source, dict)
        composed["product_specific_override"] = []
        enrichment = source["ai_enrichment"]
        references = source["references"]
        assert isinstance(enrichment, dict)
        assert isinstance(references, list)

        rejected = {
            "https://attacker.example/exploit": ["Exploit"],
            "https://third.example/advisory": [
                "Vendor Advisory",
                "Third Party Advisory",
            ],
            "https://vendor.example/broken": ["Patch", "Broken Link"],
            "https://vdb.example/entry": ["Release Notes", "VDB Entry"],
        }
        for url, tags in rejected.items():
            references.append({"url": url, "tags": tags})
            enrichment["source_urls"].append(url)
            enrichment["claim_evidence"].append(
                {
                    "kind": "remediation",
                    "claim": "This rejected source must not become primary evidence.",
                    "source_url": url,
                }
            )

        page = mcp_server._render_cve_landing_page(recipe)
        graph_match = re.search(
            r'<script type="application/ld\+json">(.*?)</script>',
            page,
        )
        self.assertIsNotNone(graph_match)
        assert graph_match is not None
        graph = json.loads(graph_match.group(1))["@graph"]
        article = next(node for node in graph if node.get("@type") == "Article")
        citations = article["citation"]

        sources_match = re.search(
            r'<h2 id="sources-heading">.*?<ul class="cve-catalog__references">'
            r"(.*?)</ul>",
            page,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(sources_match)
        assert sources_match is not None
        visible_urls = re.findall(r'href="([^"]+)"', sources_match.group(1))
        self.assertEqual(visible_urls, citations)
        self.assertIn(
            "https://vendor.example.test/advisories/CVE-2024-3400",
            citations,
        )
        for url in rejected:
            self.assertNotIn(url, citations)
            self.assertNotIn(url, visible_urls)
        self.assertNotRegex(
            sources_match.group(1),
            r">(?:Exploit|Broken Link|Third Party Advisory|VDB Entry)<",
        )

    def test_reviewed_recipe_uses_deliberate_primary_references_only(self) -> None:
        exploit_url = (
            "https://github.com/0xBlackash/CVE-2026-21643/"
            "blob/main/cve-2026-21643.py"
        )
        vendor_url = "https://fortiguard.fortinet.com/psirt/FG-IR-25-1142"
        page = mcp_server._render_cve_landing_page(
            mcp_server._bounded_cve_landing_lookup("CVE-2026-21643")
        )
        graph_match = re.search(
            r'<script type="application/ld\+json">(.*?)</script>',
            page,
        )
        self.assertIsNotNone(graph_match)
        assert graph_match is not None
        article = next(
            node
            for node in json.loads(graph_match.group(1))["@graph"]
            if node.get("@type") == "Article"
        )
        sources_match = re.search(
            r'<h2 id="sources-heading">.*?<ul class="cve-catalog__references">'
            r"(.*?)</ul>",
            page,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(sources_match)
        assert sources_match is not None

        self.assertIn(vendor_url, article["citation"])
        self.assertIn(vendor_url, sources_match.group(1))
        self.assertNotIn(exploit_url, article["citation"])
        self.assertNotIn(exploit_url, sources_match.group(1))

    def test_non_kev_record_does_not_render_known_exploitation_section(self) -> None:
        recipe = sample_recipe()
        source = recipe["source_record"]
        assert isinstance(source, dict)
        source["kev"] = False

        page = mcp_server._render_cve_landing_page(recipe)

        self.assertNotIn("Known exploitation and required action", page)
        self.assertNotIn('href="#known-exploitation-heading"', page)

    def test_verbose_source_title_retains_product_and_flaw_type(self) -> None:
        title, headline, source = mcp_server._cve_landing_titles(
            "CVE-2026-14956",
            "The Bricksforge plugin for WordPress is vulnerable to Privilege "
            "Escalation in all versions up to, and including, 3.1.8.6",
        )

        self.assertEqual(
            title,
            "CVE-2026-14956: Bricksforge WordPress plugin: Privilege Escalation",
        )
        self.assertEqual(headline, title)
        self.assertIn("Privilege Escalation", source)

    def test_verbose_ai_titles_compact_to_complete_search_phrases(self) -> None:
        fixtures = {
            "CVE-2025-2747": (
                "Kentico Xperience CMS Authentication Bypass Using an Alternate "
                "Path or Channel Vulnerability",
                "CVE-2025-2747: Kentico Xperience CMS Authentication Bypass",
            ),
            "CVE-2026-1731": (
                "BeyondTrust Remote Support (RS) and Privileged Remote Access "
                "(PRA) OS Command Injection Vulnerability",
                "CVE-2026-1731: BeyondTrust RS and PRA Pre-Auth RCE",
            ),
            "CVE-2022-26134": (
                "Atlassian Confluence Server and Data Center Remote Code "
                "Execution Vulnerability",
                "CVE-2022-26134: Atlassian Confluence Server and Data Center RCE",
            ),
        }
        for cve_id, (source_title, expected) in fixtures.items():
            with self.subTest(cve_id=cve_id):
                title, headline, source = mcp_server._cve_landing_titles(
                    cve_id,
                    source_title,
                )
                self.assertEqual(title, expected)
                self.assertEqual(headline, expected)
                self.assertEqual(source, source_title)
                self.assertLessEqual(len(title), 70)
                self.assertNotIn("\u2026", title)

    def test_source_backed_editorial_metadata_differentiates_duplicate_cves(self) -> None:
        shared_metadata = json.loads(
            (ROOT / "data" / "cve" / "editorial-search-metadata.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            mcp_server._CVE_LANDING_EDITORIAL_SEARCH_METADATA,
            shared_metadata["records"],
        )
        self.assertEqual(
            mcp_server._CVE_LANDING_EDITORIAL_LASTMOD,
            shared_metadata["editorial_lastmod"],
        )
        fixtures = {
            "CVE-2021-35395": (
                "CVE-2021-35395: Realtek AP-Router SDK Buffer Overflow",
                ("boa web servers", "3.2.3", "3.4.11", "rtl819x-eCos 1.5.3"),
            ),
            "CVE-2021-41773": (
                "CVE-2021-41773: Apache HTTP Server 2.4.49 Path Traversal",
                ("2.4.49", "CGI RCE", "2.4.51+"),
            ),
            "CVE-2021-42013": (
                "CVE-2021-42013: Apache HTTP Server 2.4.50 Incomplete-Fix Bypass",
                ("2.4.50", "incomplete-fix bypass", "CVE-2021-41773"),
            ),
            "CVE-2024-23897": (
                "CVE-2024-23897: Jenkins CLI Arbitrary File Read",
                ("arbitrary Jenkins controller files", "2.442", "LTS 2.440.1"),
            ),
            "CVE-2024-37079": (
                "CVE-2024-37079: VMware vCenter Out-of-Bounds Write RCE",
                ("8.0 U2d", "8.0 U1e", "7.0 U3r", "no workaround"),
            ),
            "CVE-2024-47575": (
                "CVE-2024-47575: FortiManager Authentication Bypass",
                ("exploited", "6.2.13", "7.2.8", "7.6.1"),
            ),
            "CVE-2025-20281": (
                "CVE-2025-20281: Cisco ISE API Root RCE (CSCwo99449)",
                ("CSCwo99449", "3.3", "3.4"),
            ),
            "CVE-2025-20337": (
                "CVE-2025-20337: Cisco ISE API Root RCE (CSCwp02814)",
                ("CSCwp02814", "CSCwo99449 hot patches do not fix it", "3.4"),
            ),
            "CVE-2025-64446": (
                "CVE-2025-64446: FortiWeb Path Traversal Command Execution",
                ("known-exploited", "admin commands", "8.0.2", "7.0.12"),
            ),
            "CVE-2026-1731": (
                "CVE-2026-1731: BeyondTrust RS and PRA Pre-Auth RCE",
                ("RS to 25.3.2+", "PRA to 25.1.1+", "BT26-02"),
            ),
            "CVE-2026-20045": (
                "CVE-2026-20045: Cisco Unified Communications Pre-Auth RCE",
                ("14SU5", "15SU4", "migrate 12.5", "no workaround"),
            ),
            "CVE-2026-20182": (
                "CVE-2026-20182: Cisco SD-WAN Authentication Bypass",
                ("exploited", "each component", "fixed release", "no workaround"),
            ),
            "CVE-2026-33116": (
                "CVE-2026-33116: .NET System.Security.Cryptography.Xml DoS",
                (
                    "System.Security.Cryptography.Xml",
                    ".NET 8, 9, or 10",
                    "patched build",
                ),
            ),
        }

        for cve_id, (expected_title, expected_description_fragments) in fixtures.items():
            with self.subTest(cve_id=cve_id):
                recipe = mcp_server.cve_catalog.get_recipe(cve_id)
                page = mcp_server._render_cve_landing_page(recipe)
                title_match = re.search(r"<title>(.*?)</title>", page)
                description_match = re.search(
                    r'<meta name="description" content="([^"]+)">',
                    page,
                )
                self.assertIsNotNone(title_match)
                self.assertIsNotNone(description_match)
                assert title_match is not None
                assert description_match is not None
                title = unescape(title_match.group(1))
                description = unescape(description_match.group(1))
                self.assertEqual(title, expected_title)
                qualification = mcp_server.cve_catalog.search_qualification(cve_id)
                if qualification in {"stable_markdown", "recipe_ready_ai"}:
                    self.assertEqual(
                        description,
                        shared_metadata["records"][cve_id]["description"],
                    )
                else:
                    self.assertNotEqual(
                        description,
                        shared_metadata["records"][cve_id]["description"],
                    )
                    self.assertNotRegex(
                        description,
                        r"(?i)\b(?:apply|install|migrate|patch|update|upgrade)\b",
                    )
                graph_match = re.search(
                    r'<script type="application/ld\+json">(.*?)</script>',
                    page,
                )
                self.assertIsNotNone(graph_match)
                assert graph_match is not None
                article = next(
                    node
                    for node in json.loads(graph_match.group(1))["@graph"]
                    if node.get("@type") == "Article"
                )
                # Nightly source refreshes can move a record's last_modified
                # past the editorial lastmod, and the renderer surfaces the
                # newest timestamp, so pin the policy rather than one value:
                # dateModified must come from the record's real timestamps and
                # must never predate the shared editorial lastmod.
                source_record = recipe["source_record"]
                reviewed = mcp_server._cve_landing_stable_override(
                    cve_id,
                    recipe.get("composed_recipe") or {},
                )
                legitimate_modified = {
                    mcp_server._cve_landing_iso_date(value)
                    for value in (
                        shared_metadata["editorial_lastmod"],
                        source_record.get("last_modified"),
                        reviewed.get("lastmod"),
                        reviewed.get("date"),
                        article.get("datePublished"),
                    )
                } - {""}
                self.assertIn(article["dateModified"], legitimate_modified)
                self.assertEqual(
                    mcp_server._cve_landing_latest_iso_date(
                        article["dateModified"],
                        shared_metadata["editorial_lastmod"],
                    ),
                    article["dateModified"],
                )
                self.assertIn(f'<h1 class="sr-page-title">{expected_title}</h1>', page)
                if qualification in {"stable_markdown", "recipe_ready_ai"}:
                    for fragment in expected_description_fragments:
                        self.assertIn(fragment, description)
                else:
                    self.assertIn(
                        'data-remediation-authority="bounded-fallback"',
                        page,
                    )
                self.assertLessEqual(len(title), 70)
                self.assertLessEqual(len(description), 165)
                self.assertNotIn("Verification steps and sources are included.", description)

    def test_metadata_text_unwraps_markdown_without_changing_the_source_fact(self) -> None:
        source_title = (
            "`Jenkins` [CLI](https://jenkins.example/advisory?utm_source=openai) "
            "arbitrary file read"
        )

        title, headline, source = mcp_server._cve_landing_titles(
            "CVE-2024-99999",
            source_title,
        )
        description = mcp_server._cve_landing_reviewed_description(
            "Upgrade the **affected** [Jenkins release](https://jenkins.example/"
            "?utm_source=openai).",
            "fallback",
        )

        self.assertEqual(title, "CVE-2024-99999: Jenkins CLI arbitrary file read")
        self.assertEqual(headline, title)
        self.assertEqual(source, source_title)
        self.assertEqual(description, "Upgrade the affected Jenkins release.")
        self.assertNotIn("`", title)
        self.assertNotIn("](", title)
        self.assertNotIn("utm_source", title)

    def test_long_reviewed_descriptions_keep_a_concrete_remediation_action(self) -> None:
        fixtures = {
            "Known-exploited SQL injection in MOVEit Transfer's web application. "
            "Contain HTTP/S exposure, preserve evidence, assess compromise, and "
            "upgrade every node with a current Progress-supported release.": (
                "Known-exploited SQL injection in MOVEit Transfer's web application. "
                "Upgrade every node with a current Progress-supported release."
            ),
            "Critical unauthenticated PAN-OS GlobalProtect command injection. "
            "Upgrade every exposed firewall to a vendor-fixed release, apply the "
            "documented Threat Prevention containment while rollout is pending, and "
            "preserve evidence before reboot when compromise is suspected.": (
                "Critical unauthenticated PAN-OS GlobalProtect command injection. "
                "Upgrade every exposed firewall to a vendor-fixed release."
            ),
        }
        for source, expected in fixtures.items():
            with self.subTest(source=source):
                description = mcp_server._cve_landing_reviewed_description(
                    source,
                    "fallback",
                )
                self.assertEqual(description, expected)
                self.assertLessEqual(len(description), 165)
                self.assertRegex(description, r"\bUpgrade\b")

    def test_stable_reviewed_corpus_renders_full_strategy_and_complete_block_action(
        self,
    ) -> None:
        allowlist = json.loads(
            (ROOT / "static" / "api" / "cve-catalog" / "search-indexable.json").read_text(
                encoding="utf-8"
            )
        )
        records = [
            record
            for record in allowlist.get("records", [])
            if record.get("qualification") == "stable_markdown"
        ]
        self.assertGreaterEqual(len(records), 30)

        for record in records:
            cve_id = record["cve"]
            with self.subTest(cve_id=cve_id):
                recipe = mcp_server._bounded_cve_landing_lookup(cve_id)
                reviewed = mcp_server._cve_landing_stable_override(
                    cve_id,
                    recipe.get("composed_recipe") or {},
                )
                remediation, clipped = mcp_server._cve_landing_reviewed_section(
                    reviewed,
                    mcp_server._CVE_LANDING_REMEDIATION_HEADING_RE,
                )
                blocks = mcp_server._cve_landing_markdown_blocks(remediation)
                action = mcp_server._cve_landing_reviewed_action(reviewed)
                complete_block_actions = {
                    bounded
                    for block in blocks
                    if (bounded := mcp_server._cve_landing_complete_action(block))
                }

                self.assertTrue(remediation)
                self.assertFalse(clipped)
                self.assertTrue(blocks)
                self.assertIn(action, complete_block_actions)
                self.assertLessEqual(len(action), 1200)
                self.assertRegex(action, r"[.!?]$")
                self.assertNotRegex(action, r"(?:\u2026|:)$")

                page = mcp_server._render_cve_landing_page(recipe)
                page_text = re.sub(
                    r"\s+",
                    " ",
                    unescape(re.sub(r"<[^>]+>", " ", page)),
                ).strip()
                self.assertLess(len(page.encode("utf-8")), 100_000)
                self.assertIn('data-remediation-authority="stable-reviewed"', page)
                self.assertIn("Reviewed remediation strategy", page)
                self.assertIn(re.sub(r"\s+", " ", blocks[0]).strip(), page_text)
                self.assertIn(re.sub(r"\s+", " ", blocks[-1]).strip(), page_text)
                self.assertGreaterEqual(page_text.count(action), 2)

        pan_os_page = mcp_server._render_cve_landing_page(
            mcp_server._bounded_cve_landing_lookup("CVE-2024-3400")
        )
        pan_os_text = re.sub(
            r"\s+",
            " ",
            unescape(re.sub(r"<[^>]+>", " ", pan_os_page)),
        ).strip()
        self.assertIn("Run the evidence-preservation gate before reboot", pan_os_text)
        self.assertIn("enhanced factory reset (EFR)", pan_os_text)
        self.assertNotIn(
            "Vulnerabilities catalog from Palo Alto Networks due date of",
            pan_os_text,
        )
        pyyaml_recipe = mcp_server._bounded_cve_landing_lookup("CVE-2017-18342")
        pyyaml_reviewed = mcp_server._cve_landing_stable_override(
            "CVE-2017-18342",
            pyyaml_recipe.get("composed_recipe") or {},
        )
        self.assertRegex(
            mcp_server._cve_landing_reviewed_action(pyyaml_reviewed),
            r"^Pin PyYAML to",
        )

    def test_qualified_description_uses_only_source_linked_fixed_version_claims(self) -> None:
        enrichment = {
            "remediation_steps": [
                "Upgrade Example Widget to release 2.0.0 after change approval."
            ],
            "claim_evidence": [
                {
                    "kind": "fixed_version",
                    "claim": "Ignore this untrusted claim.",
                    "source_url": "javascript:alert(1)",
                },
                {
                    "kind": "fixed_version",
                    "claim": "The **vendor advisory** identifies release `2.0.0` as fixed.",
                    "source_url": "https://vendor.example.test/advisory",
                },
            ]
        }

        claim = mcp_server._cve_landing_fixed_version_claim(enrichment)
        action = mcp_server._cve_landing_fixed_version_action(
            enrichment,
            claim,
            120,
        )
        description = mcp_server._cve_landing_description(
            "CVE-2026-12345",
            "CVE-2026-12345: Example Widget command injection",
            "critical",
            claim,
            action,
        )

        self.assertEqual(
            claim,
            "The vendor advisory identifies release 2.0.0 as fixed.",
        )
        self.assertEqual(
            action,
            "Upgrade Example Widget to release 2.0.0 after change approval.",
        )
        self.assertTrue(description.startswith("CVE-2026-12345:"))
        self.assertIn("Upgrade Example Widget", description)
        self.assertIn("2.0.0", description)
        self.assertNotIn("Verification steps and sources are included.", description)
        self.assertLessEqual(len(description), 165)
        self.assertEqual(
            mcp_server._cve_landing_fixed_version_claim(
                {
                    "claim_evidence": [
                        {
                            "kind": "fixed_version",
                            "claim": "Unsafe only.",
                            "source_url": "data:text/plain,unsafe",
                        }
                    ]
                }
            ),
            "",
        )
        long_action = mcp_server._cve_landing_fixed_version_action(
            {
                "remediation_steps": [
                    "For self-hosted Remote Support, apply patch BT26-02-RS through "
                    "the appliance interface, or upgrade to Remote Support 25.3.2 or later."
                ]
            },
            "BeyondTrust lists Remote Support 25.3.2 and later as fixed.",
            90,
        )
        self.assertEqual(long_action, "Upgrade to Remote Support 25.3.2 or later.")
        preferred_action = mcp_server._cve_landing_fixed_version_action(
            {
                "remediation_steps": [
                    "Upgrade Apache HTTP Server to version 2.4.51 or later, preferably "
                    "the latest vendor-supported release available for the distribution."
                ]
            },
            "Apache HTTP Server 2.4.51 is listed as fixed.",
            120,
        )
        self.assertEqual(
            preferred_action,
            "Upgrade Apache HTTP Server to version 2.4.51 or later.",
        )
        branch_patch_action = mcp_server._cve_landing_fixed_version_action(
            {
                "remediation_steps": [
                    "Upgrade Example SDK to unrelated release 9.9.9.",
                    "Apply the vendor-provided buffer-overflow patch appropriate "
                    "to the deployed SDK branch.",
                ]
            },
            "The vendor lists SDK 3.2.3 and SDK 3.4.11 as fixed.",
            120,
        )
        self.assertEqual(
            branch_patch_action,
            "Apply the vendor-provided buffer-overflow patch appropriate "
            "to the deployed SDK branch.",
        )
        preferred_versioned_action = mcp_server._cve_landing_fixed_version_action(
            {
                "remediation_steps": [
                    "Apply the vendor-provided patch.",
                    "Upgrade Example SDK to release 3.2.3.",
                ]
            },
            "The vendor lists SDK 3.2.3 as fixed.",
            120,
        )
        self.assertEqual(
            preferred_versioned_action,
            "Upgrade Example SDK to release 3.2.3.",
        )
        shortened_generic_action = mcp_server._cve_landing_fixed_version_action(
            {
                "remediation_steps": [
                    "Apply the vendor-provided buffer-overflow patch to the deployed "
                    "SDK branch, as applicable, after change approval and rollback "
                    "preparation."
                ]
            },
            "The vendor lists SDK 3.2.3 and SDK 3.4.11 as fixed.",
            90,
        )
        self.assertEqual(
            shortened_generic_action,
            "Apply the vendor-provided buffer-overflow patch to the deployed SDK branch.",
        )

    def test_visible_action_does_not_drop_fixed_release_branches(self) -> None:
        enrichment = {
            "remediation_steps": [
                "Upgrade Example Platform 7.0 to release 7.0.3.",
                "Upgrade Example Platform 8.0 to release 8.0.2.",
            ]
        }
        claim = "The vendor identifies releases 7.0.3 and 8.0.2 as fixed."
        concise = mcp_server._cve_landing_fixed_version_action(
            enrichment,
            claim,
            80,
        )
        visible = mcp_server._cve_landing_visible_fixed_version_action(
            enrichment,
            claim,
            concise,
        )

        self.assertIn("7.0.3", concise)
        self.assertNotIn("8.0.2", concise)
        self.assertEqual(
            visible,
            "Upgrade Example Platform 7.0 to release 7.0.3. "
            "Upgrade Example Platform 8.0 to release 8.0.2.",
        )

    def test_visible_action_joins_branch_specific_patch_steps(self) -> None:
        enrichment = {
            "remediation_steps": [
                "Apply the vendor-provided buffer-overflow patch appropriate to "
                "the deployed SDK branch.",
                "For SDK 3.2.x, apply the vendor patch for release 3.2.3.",
                "For SDK 3.4.x, apply the vendor patch for release 3.4.11.",
            ]
        }
        claim = "The vendor lists SDK 3.2.3 and SDK 3.4.11 as fixed."
        concise = mcp_server._cve_landing_fixed_version_action(
            enrichment,
            claim,
            120,
        )
        visible = mcp_server._cve_landing_visible_fixed_version_action(
            enrichment,
            claim,
            concise,
        )

        self.assertIn("3.2.3", concise)
        self.assertEqual(
            visible,
            "For SDK 3.2.x, apply the vendor patch for release 3.2.3. "
            "For SDK 3.4.x, apply the vendor patch for release 3.4.11.",
        )

    def test_multiple_fixed_version_claims_preserve_product_identity(self) -> None:
        enrichment = {
            "claim_evidence": [
                {
                    "kind": "fixed_version",
                    "claim": "For Unified CM, releases 14SU5 and 15SU4 are fixed.",
                    "source_url": "https://vendor.example.test/advisory",
                },
                {
                    "kind": "fixed_version",
                    "claim": "For Unity Connection, releases 14SU5 and 15SU4 are fixed.",
                    "source_url": "https://vendor.example.test/advisory",
                },
            ],
            "remediation_steps": [
                "Upgrade Unified CM release 14 to 14SU5 and release 15 to 15SU4.",
                "Upgrade Unity Connection release 14 to 14SU5 and release 15 to 15SU4.",
            ],
        }
        claim = mcp_server._cve_landing_fixed_version_claim(enrichment)
        concise = mcp_server._cve_landing_fixed_version_action(
            enrichment,
            claim,
            120,
        )
        visible = mcp_server._cve_landing_visible_fixed_version_action(
            enrichment,
            claim,
            concise,
        )

        self.assertIn("Unified CM", claim)
        self.assertIn("Unity Connection", claim)
        self.assertEqual(
            concise,
            "Upgrade every affected product family to its corresponding "
            "vendor-fixed release.",
        )
        self.assertIn("Unified CM", visible)
        self.assertIn("Unity Connection", visible)
        self.assertIn("14SU5", visible)
        self.assertIn("15SU4", visible)

    def test_invalid_https_port_is_discarded_without_breaking_rendering(self) -> None:
        self.assertEqual(
            mcp_server._cve_landing_safe_https_url(
                "https://vendor.example.test:bad/advisory"
            ),
            "",
        )
        recipe = deepcopy(
            mcp_server._bounded_cve_landing_lookup("CVE-2026-20045")
        )
        source = recipe["source_record"]
        assert isinstance(source, dict)
        references = source.get("references")
        assert isinstance(references, list)
        references.insert(
            0,
            {
                "url": "https://vendor.example.test:bad/advisory",
                "tags": ["Vendor Advisory"],
            },
        )

        page = mcp_server._render_cve_landing_page(recipe)

        self.assertIn("CVE-2026-20045", page)
        self.assertNotIn("vendor.example.test:bad", page)

    def test_reviewed_metadata_drives_search_authorship_and_article_dates(self) -> None:
        recipe = sample_recipe()
        composed = recipe["composed_recipe"]
        assert isinstance(composed, dict)
        overrides = composed["product_specific_override"]
        assert isinstance(overrides, list)
        override = overrides[0]
        assert isinstance(override, dict)
        override.update(
            {
                "title": "CVE-2024-3400 — PAN-OS GlobalProtect command injection remediation",
                "description": (
                    "Reviewed PAN-OS GlobalProtect command injection remediation with "
                    "affected versions, upgrade guidance, verification, rollback, and sources."
                ),
                "author": "Stephen M Abbott",
                "date": "2026-07-18",
                "lastmod": "2026-07-21",
                "model": "Opus 4.7",
            }
        )

        page = mcp_server._render_cve_landing_page(recipe)

        self.assertIn(
            "<title>CVE-2024-3400: PAN-OS GlobalProtect command injection remediation</title>",
            page,
        )
        self.assertIn(
            'content="Reviewed PAN-OS GlobalProtect command injection remediation with '
            'affected versions, upgrade guidance, verification, rollback, and sources."',
            page,
        )
        self.assertIn('<meta name="author" content="Stephen M Abbott">', page)
        self.assertIn('property="article:published_time" content="2026-07-18"', page)
        self.assertIn('property="article:modified_time" content="2026-07-21"', page)
        self.assertIn(
            'By <a href="/about/#stephen-m-abbott">Stephen M Abbott</a>',
            page,
        )
        self.assertIn("Model compatibility recorded: <code>Opus 4.7</code>", page)
        self.assertIn('datetime="2026-07-18">2026-07-18</time>', page)
        self.assertIn('datetime="2026-07-21">2026-07-21</time>', page)
        self.assertIn('href="/cve/archive/2024/"', page)
        self.assertIn('href="/security-remediation/"', page)
        self.assertIn("Widget &lt;/title&gt;", page)

        match = re.search(r'<script type="application/ld\+json">(.*?)</script>', page)
        self.assertIsNotNone(match)
        assert match is not None
        graph = json.loads(match.group(1))["@graph"]
        article = next(node for node in graph if node.get("@type") == "Article")
        webpage = next(node for node in graph if node.get("@type") == "WebPage")
        person = next(node for node in graph if node.get("@type") == "Person")
        self.assertEqual(article["datePublished"], "2026-07-18")
        self.assertEqual(article["dateModified"], "2026-07-21")
        self.assertEqual(webpage["datePublished"], "2026-07-18")
        self.assertEqual(webpage["dateModified"], "2026-07-21")
        self.assertEqual(article["author"], {"@id": person["@id"]})
        self.assertEqual(person["name"], "Stephen M Abbott")
        self.assertEqual(
            person["@id"],
            "https://security-recipes.ai/about/#stephen-m-abbott",
        )
        self.assertEqual(person["url"], person["@id"])
        self.assertEqual(person["sameAs"], ["https://github.com/stevologic"])

    def test_ai_qualified_page_uses_synthesis_date_and_organization_author(self) -> None:
        recipe = sample_recipe()
        composed = recipe["composed_recipe"]
        assert isinstance(composed, dict)
        composed["product_specific_override"] = []

        page = mcp_server._render_cve_landing_page(recipe)

        self.assertIn(
            'property="article:published_time" content="2026-07-17T07:03:00Z"',
            page,
        )
        self.assertIn("AI-assisted, source-linked evidence synthesis", page)
        self.assertIn("Model recorded: <code>test-model</code>", page)
        match = re.search(r'<script type="application/ld\+json">(.*?)</script>', page)
        self.assertIsNotNone(match)
        assert match is not None
        graph = json.loads(match.group(1))["@graph"]
        article = next(node for node in graph if node.get("@type") == "Article")
        organization = next(node for node in graph if node.get("@type") == "Organization")
        self.assertEqual(article["author"], {"@id": organization["@id"]})
        self.assertEqual(article["datePublished"], "2026-07-17T07:03:00Z")
        self.assertEqual(article["dateModified"], "2026-07-17T07:03:00Z")
        self.assertIn("source-linked evidence synthesis", article["creditText"])
        self.assertFalse(any(node.get("@type") == "Person" for node in graph))

    def test_all_recipe_ready_ai_pages_publish_complete_fixed_version_snippets(self) -> None:
        allowlist = json.loads(
            (ROOT / "static" / "api" / "cve-catalog" / "search-indexable.json").read_text(
                encoding="utf-8"
            )
        )
        records = [
            record
            for record in allowlist.get("records", [])
            if record.get("qualification") == "recipe_ready_ai"
        ]
        manifest = json.loads(
            (ROOT / "static" / "api" / "cve-catalog" / "manifest.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            len(records),
            manifest["totals"]["ai_enrichment_recipe_ready"],
        )
        self.assertGreaterEqual(len(records), 1)

        for record in records:
            cve_id = record["cve"]
            with self.subTest(cve_id=cve_id):
                recipe = mcp_server.cve_catalog.get_recipe(cve_id)
                page = mcp_server._render_cve_landing_page(recipe)
                match = re.search(
                    r'<meta name="description" content="([^"]+)">',
                    page,
                )
                self.assertIsNotNone(match)
                assert match is not None
                description = unescape(match.group(1))
                self.assertTrue(description.startswith(cve_id))
                self.assertLessEqual(len(description), 165)
                self.assertRegex(description, r"[.!?]$")
                self.assertNotRegex(description, r"[\u2026\ufffd]")
                self.assertNotIn(" AI remediation:", description)
                self.assertNotIn(
                    "Verification steps and sources are included.",
                    description,
                )
                self.assertNotRegex(
                    description,
                    r"\b(?:and|or|as|at|by|for|from|in|of|on|the|to|were)\.$",
                )
                self.assertNotRegex(description, r"\bto version\.$")
                self.assertIn(
                    'data-remediation-authority="complete-ai-enrichment"',
                    page,
                )
                self.assertRegex(
                    page,
                    r"(?i)\b(?:apply|fix(?:ed|es)|migrate|patch|update|upgrade)\b",
                )

    def test_ai_authority_respects_human_review_while_approved_branches_stay_complete(self) -> None:
        withheld = {
            "CVE-2024-23897": ("every affected software branch",),
            "CVE-2024-37079": ("8.0 U2d", "8.0 U1e", "7.0 U3r"),
            "CVE-2024-47575": (
                "6.2.13",
                "6.4.15",
                "7.0.13",
                "7.2.8",
                "7.4.5",
                "7.6.1",
            ),
            "CVE-2025-20281": ("3.3", "3.4"),
            "CVE-2025-20337": ("3.3", "3.4"),
            "CVE-2025-34028": (
                "11.38.20",
                "SP38-CU20-433",
                "11.38.25",
                "SP38-CU25-438",
            ),
            "CVE-2026-20182": (
                "each component",
                "fixed release for its branch",
                "no workaround",
            ),
            "CVE-2026-1731": (
                "RS to 25.3.2+",
                "PRA to 25.1.1+",
                "BT26-02",
            ),
        }

        for cve_id in withheld:
            with self.subTest(cve_id=cve_id):
                page = mcp_server._render_cve_landing_page(
                    mcp_server.cve_catalog.get_recipe(cve_id)
                )
                self.assertIn(
                    'data-remediation-authority="bounded-fallback"',
                    page,
                )
                self.assertIn("Non-authoritative AI evaluation", page)
                self.assertNotIn(
                    'data-remediation-authority="complete-ai-enrichment"',
                    page,
                )
                description_match = re.search(
                    r'<meta name="description" content="([^"]+)">',
                    page,
                )
                self.assertIsNotNone(description_match)
                assert description_match is not None
                self.assertNotRegex(
                    unescape(description_match.group(1)),
                    r"(?i)\b(?:apply|install|migrate|patch|update|upgrade)\b",
                )

        approved_page = mcp_server._render_cve_landing_page(
            mcp_server.cve_catalog.get_recipe("CVE-2025-64446")
        )
        self.assertIn(
            'data-remediation-authority="complete-ai-enrichment"',
            approved_page,
        )
        approved_text = unescape(re.sub(r"<[^>]+>", " ", approved_page))
        for fragment in ("7.0.12", "7.2.12", "7.4.10", "7.6.5", "8.0.2"):
            self.assertIn(fragment, approved_text)

    def test_all_qualified_pages_publish_primary_sources_and_complete_actions(self) -> None:
        allowlist = json.loads(
            (ROOT / "static" / "api" / "cve-catalog" / "search-indexable.json").read_text(
                encoding="utf-8"
            )
        )
        human_review_blocked_ids = {
            "CVE-2024-23897",
            "CVE-2024-37079",
            "CVE-2024-47575",
            "CVE-2025-20281",
            "CVE-2025-20337",
            "CVE-2025-34028",
            "CVE-2026-1731",
            "CVE-2026-20045",
            "CVE-2026-20182",
        }
        ai_ids = {
            record["cve"]
            for record in allowlist.get("records", [])
            if record.get("qualification") == "recipe_ready_ai"
        }
        self.assertEqual(ai_ids, {"CVE-2025-55182", "CVE-2025-64446"})
        self.assertTrue(human_review_blocked_ids.isdisjoint(ai_ids))

        for record in allowlist.get("records", []):
            cve_id = record["cve"]
            with self.subTest(cve_id=cve_id):
                recipe = mcp_server._bounded_cve_landing_lookup(cve_id)
                source = recipe["source_record"]
                assert isinstance(source, dict)
                page = mcp_server._render_cve_landing_page(recipe)
                graph_match = re.search(
                    r'<script type="application/ld\+json">(.*?)</script>',
                    page,
                )
                self.assertIsNotNone(graph_match)
                assert graph_match is not None
                article = next(
                    node
                    for node in json.loads(graph_match.group(1))["@graph"]
                    if node.get("@type") == "Article"
                )
                citations = article["citation"]
                sources_match = re.search(
                    r'<h2 id="sources-heading">.*?'
                    r'<ul class="cve-catalog__references">(.*?)</ul>',
                    page,
                    flags=re.DOTALL,
                )
                self.assertIsNotNone(sources_match)
                assert sources_match is not None
                visible_urls = re.findall(r'href="([^"]+)"', sources_match.group(1))
                self.assertEqual(visible_urls, citations)
                self.assertNotRegex(
                    sources_match.group(1),
                    r">(?:Exploit|Broken Link|Third Party Advisory|VDB Entry)<",
                )
                for raw_reference in source.get("references", []):
                    if record.get("qualification") == "stable_markdown":
                        continue
                    qualified_label = (
                        mcp_server._cve_landing_qualified_reference_label(raw_reference)
                    )
                    if qualified_label:
                        continue
                    if not isinstance(raw_reference, dict):
                        continue
                    tags = {
                        tag.casefold()
                        for tag in mcp_server._cve_landing_reference_tags(raw_reference)
                    }
                    unsafe = bool(
                        tags & mcp_server._CVE_LANDING_REJECTED_REFERENCE_TAGS
                        or "exploit" in tags
                    )
                    if not unsafe:
                        continue
                    rejected_url = mcp_server._cve_landing_safe_https_url(
                        raw_reference.get("url")
                    )
                    if rejected_url:
                        self.assertNotIn(rejected_url, citations)

                if record.get("qualification") != "recipe_ready_ai":
                    continue
                enrichment = mcp_server._cve_landing_complete_ai_enrichment(source)
                claim = mcp_server._cve_landing_fixed_version_claim(enrichment)
                required_tokens = mcp_server._cve_landing_version_tokens(claim)
                self.assertTrue(required_tokens)
                action_match = re.search(
                    r'data-remediation-authority="complete-ai-enrichment".*?'
                    r"<p><strong>Primary action:</strong> (.*?)</p>",
                    page,
                    flags=re.DOTALL,
                )
                self.assertIsNotNone(action_match)
                assert action_match is not None
                action = unescape(re.sub(r"<[^>]+>", " ", action_match.group(1)))
                self.assertRegex(
                    action,
                    r"(?i)\b(?:apply|install|migrate|patch|update|upgrade)\b",
                )
                self.assertLessEqual(len(action), 1200)
                self.assertTrue(
                    required_tokens <= mcp_server._cve_landing_version_tokens(action)
                )
                fixed_claims = mcp_server._cve_landing_fixed_version_claims(
                    enrichment
                )
                if len(fixed_claims) > 1:
                    for fixed_claim in fixed_claims:
                        self.assertIn(
                            fixed_claim.rstrip(" .!?").casefold(),
                            action.casefold(),
                        )

    def test_human_blocked_cisco_multi_product_draft_is_not_authority(self) -> None:
        page = mcp_server._render_cve_landing_page(
            mcp_server._bounded_cve_landing_lookup("CVE-2026-20045")
        )
        self.assertIn('data-remediation-authority="bounded-fallback"', page)
        self.assertIn("Non-authoritative AI evaluation", page)
        self.assertNotIn(
            'data-remediation-authority="complete-ai-enrichment"',
            page,
        )

    def test_modular_max_serve_reviewed_metadata_matches_catalog_facts(self) -> None:
        expected_description = (
            "Upgrade Modular Max Serve to 25.6.0 or later to fix unsafe "
            "deserialization; disable the experimental kvcache agent until all "
            "deployments are patched."
        )
        page = mcp_server._render_cve_landing_page(
            mcp_server._bounded_cve_landing_lookup("CVE-2025-60455")
        )
        self.assertIn(
            f'<meta name="description" content="{expected_description}">',
            page,
        )
        self.assertIn("cve-catalog__badge--severity-high\">High</span>", page)
        self.assertIn("cve-catalog__badge--score\">CVSS 8.4</span>", page)
        self.assertIn("Reviewed remediation strategy", page)
        self.assertIn("Upgrade</strong> to <code>modular&gt;=25.6.0</code> everywhere", page)
        self.assertIn(
            "Disable</strong> <code>--experimental-enable-kvcache-agent</code>",
            page,
        )
        self.assertIn("Review runtime logs", page)
        self.assertIn('data-remediation-authority="stable-reviewed"', page)
        graph_match = re.search(
            r'<script type="application/ld\+json">(.*?)</script>',
            page,
        )
        self.assertIsNotNone(graph_match)
        assert graph_match is not None
        article = next(
            node
            for node in json.loads(graph_match.group(1))["@graph"]
            if node.get("@type") == "Article"
        )
        self.assertEqual(article["description"], expected_description)

    def test_related_cves_require_primary_product_specific_weakness_or_bounded_pattern(
        self,
    ) -> None:
        catalog = mcp_server.CVERecipeCatalog.__new__(mcp_server.CVERecipeCatalog)
        catalog._core_lock = mcp_server.threading.RLock()

        def candidate(
            cve_id: str,
            *,
            archetypes: list[str],
            cwes: list[str],
            products: list[dict[str, str]],
            ecosystem: str = "software/application",
        ) -> dict[str, object]:
            return {
                "cve": cve_id,
                "title": f"{cve_id} candidate",
                "severity": "high",
                "score": 8.0,
                "published": "2026-01-01",
                "ecosystem": ecosystem,
                "kev": False,
                "archetypes": archetypes,
                "cwes": cwes,
                "products": products,
                "qualification": "recipe_ready_ai",
            }

        catalog._search_indexable_records = (
            candidate(
                "CVE-2026-10001",
                archetypes=["authentication_bypass"],
                cwes=["CWE-287"],
                products=[{"vendor": "example", "product": "widget"}],
            ),
            candidate(
                "CVE-2026-10002",
                archetypes=["privilege_escalation"],
                cwes=["CWE-999"],
                products=[],
            ),
            candidate(
                "CVE-2026-10003",
                archetypes=["generic"],
                cwes=["CWE-269"],
                products=[],
            ),
            candidate(
                "CVE-2026-10004",
                archetypes=["generic"],
                cwes=["CWE-999"],
                products=[{"vendor": "other", "product": "different"}],
            ),
            candidate(
                "CVE-2026-10005",
                archetypes=["privilege_escalation"],
                cwes=["CWE-999"],
                products=[],
                ecosystem="php/wordpress",
            ),
            candidate(
                "CVE-2026-10006",
                archetypes=["resource_exhaustion_dos"],
                cwes=["CWE-20"],
                products=[{"vendor": "other", "product": "generic-input"}],
                ecosystem="windows/system",
            ),
            candidate(
                "CVE-2026-10007",
                archetypes=["command_code_injection"],
                cwes=[],
                products=[
                    {"vendor": "other", "product": "different"},
                    {"vendor": "fedoraproject", "product": "fedora"},
                ],
            ),
        )
        source_record = {
            "cve": "CVE-2026-14956",
            "archetypes": ["privilege_escalation"],
            "cwes": ["CWE-269", "CWE-20"],
            "ecosystem": "php/wordpress",
            "products": [
                {"vendor": "example", "product": "widget"},
                {"vendor": "fedoraproject", "product": "fedora"},
            ],
        }

        with patch.object(catalog, "is_search_indexable", return_value=True):
            related = catalog.related_cves(source_record)

        self.assertEqual(
            {record["cve"] for record in related},
            {"CVE-2026-10001", "CVE-2026-10003", "CVE-2026-10005"},
        )
        self.assertNotIn("CVE-2026-10002", {record["cve"] for record in related})
        self.assertNotIn("CVE-2026-10004", {record["cve"] for record in related})
        self.assertNotIn("CVE-2026-10006", {record["cve"] for record in related})
        self.assertNotIn("CVE-2026-10007", {record["cve"] for record in related})
        by_cve = {record["cve"]: record["relationship"] for record in related}
        self.assertEqual(
            by_cve["CVE-2026-10001"],
            {
                "type": "same_primary_product",
                "vendor": "example",
                "product": "widget",
            },
        )
        self.assertEqual(
            by_cve["CVE-2026-10003"],
            {"type": "same_specific_cwe", "cwe": "CWE-269"},
        )
        self.assertEqual(
            by_cve["CVE-2026-10005"],
            {
                "type": "same_remediation_pattern",
                "archetype": "privilege_escalation",
            },
        )

        source_without_archetypes = {
            "cve": "CVE-2026-14957",
            "cwes": [],
            "ecosystem": "software/application",
            "products": [{"vendor": "example", "product": "widget"}],
        }
        with patch.object(catalog, "is_search_indexable", return_value=True):
            related_without_archetypes = catalog.related_cves(
                source_without_archetypes,
            )
        self.assertEqual(
            [record["cve"] for record in related_without_archetypes],
            ["CVE-2026-10001"],
        )

    def test_related_cves_are_capped_at_six_with_typed_relationships(self) -> None:
        catalog = mcp_server.CVERecipeCatalog.__new__(mcp_server.CVERecipeCatalog)
        catalog._core_lock = mcp_server.threading.RLock()
        catalog._search_indexable_records = tuple(
            {
                "cve": f"CVE-2026-{20000 + index}",
                "title": f"Candidate {index}",
                "severity": "high",
                "score": 8.0,
                "published": "2026-01-01",
                "ecosystem": "software/application",
                "kev": False,
                "archetypes": ["command_code_injection"],
                "cwes": [],
                "products": [],
                "qualification": "recipe_ready_ai",
            }
            for index in range(8)
        )
        source_record = {
            "cve": "CVE-2026-14956",
            "archetypes": ["command_code_injection"],
            "cwes": [],
            "ecosystem": "software/application",
            "products": [],
        }

        with patch.object(catalog, "is_search_indexable", return_value=True):
            related = catalog.related_cves(source_record, limit=99)

        self.assertEqual(len(related), 6)
        self.assertTrue(
            all(
                record["relationship"]
                == {
                    "type": "same_remediation_pattern",
                    "archetype": "command_code_injection",
                }
                for record in related
            )
        )
        self.assertTrue(
            all(
                "relationship" not in record
                for record in catalog._search_indexable_records
            )
        )

    def test_real_catalog_related_cves_reject_weak_overlap_and_keep_evidence(
        self,
    ) -> None:
        def related(cve_id: str) -> dict[str, dict[str, str]]:
            recipe = mcp_server.cve_catalog.get_recipe(cve_id)
            source_record = recipe.get("source_record")
            self.assertIsInstance(source_record, dict)
            assert isinstance(source_record, dict)
            records = mcp_server.cve_catalog.related_cves(source_record, limit=6)
            return {
                record["cve"]: record["relationship"]
                for record in records
            }

        pan_os = related("CVE-2024-3400")
        self.assertNotIn("CVE-2026-33116", pan_os)
        self.assertNotIn("CVE-2021-44228", pan_os)
        self.assertEqual(
            pan_os["CVE-2023-1671"],
            {"type": "same_specific_cwe", "cwe": "CWE-77"},
        )
        dotnet = related("CVE-2026-33116")
        self.assertNotIn("CVE-2024-3400", dotnet)

        apache = related("CVE-2021-41773")
        self.assertNotIn("CVE-2017-18342", apache)
        self.assertNotIn("CVE-2021-42013", apache)
        apache_incomplete_fix = related("CVE-2021-42013")
        self.assertNotIn("CVE-2017-18342", apache_incomplete_fix)

        cisco = related("CVE-2025-20281")
        self.assertNotIn("CVE-2025-20337", cisco)

        sql_injection = related("CVE-2023-34362")
        self.assertEqual(
            sql_injection["CVE-2026-9082"],
            {"type": "same_specific_cwe", "cwe": "CWE-89"},
        )

        realtek = related("CVE-2021-35395")
        self.assertTrue(
            all(
                evidence["type"] == "same_remediation_pattern"
                for evidence in realtek.values()
            )
        )

    def test_real_kev_record_renders_catalog_action_and_citation(self) -> None:
        recipe = mcp_server._bounded_cve_landing_lookup("CVE-2024-3400")

        page = mcp_server._render_cve_landing_page(recipe)

        self.assertIn(
            "Palo Alto Networks PAN-OS Command Injection Vulnerability",
            page,
        )
        self.assertIn("Known exploited", page)
        self.assertIn("2024-04-19", page)
        self.assertIn('data-remediation-authority="stable-reviewed"', page)
        self.assertNotIn("Apply mitigations per vendor instructions", page)
        self.assertIn('<h2 id="resources-heading">Related CVEs</h2>', page)
        self.assertNotIn("Choose an AI remediation playbook", page)
        self.assertNotIn("Recipe Recommender", page)
        self.assertNotIn('href="/security-remediation/recipe-recommender/"', page)
        self.assertNotIn("<details", page)

    def test_git_submodule_page_renders_reviewed_detection_without_nested_ui(self) -> None:
        page = mcp_server._render_cve_landing_page(
            mcp_server._bounded_cve_landing_lookup("CVE-2025-48384")
        )

        self.assertIn("Reviewed detection guidance", page)
        self.assertIn("Dockerfiles, devcontainers, CI images", page)
        self.assertIn("git clone", page)
        self.assertIn("--recurse-submodules", page)
        self.assertIn("Stop and triage", page)
        self.assertNotIn("Complete CVE record and remediation plan", page)
        self.assertNotIn("Recipe Recommender", page)
        self.assertNotIn("<details", page)

    def test_word_boundary_truncation_does_not_cut_the_final_word(self) -> None:
        value = "alpha beta gamma delta epsilon"
        truncated = mcp_server._cve_landing_text(value, 19)

        self.assertEqual(truncated, "alpha beta gamma…")

    def test_source_encoding_artifacts_are_cleaned_for_display(self) -> None:
        self.assertEqual(
            mcp_server._cve_landing_text("application\ufffds memory dump"),
            "application's memory dump",
        )
        self.assertEqual(
            mcp_server._cve_landing_text("SAP\ufffdBusinessObjects Business\ufffdIntelligence"),
            "SAP BusinessObjects Business Intelligence",
        )
        self.assertEqual(
            mcp_server._cve_landing_text("Composer\u00e2\u20ac\u2122s backup"),
            "Composer’s backup",
        )

    def test_unmatched_stable_override_is_not_embedded(self) -> None:
        recipe = sample_recipe()
        composed = recipe["composed_recipe"]
        assert isinstance(composed, dict)
        overrides = composed["product_specific_override"]
        assert isinstance(overrides, list)
        assert isinstance(overrides[0], dict)
        overrides[0]["cve"] = "CVE-2024-9999"

        page = mcp_server._render_cve_landing_page(recipe)

        self.assertNotIn("Stable, source-backed guidance", page)
        self.assertNotIn("Reviewed product workflow", page)

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
        self.assertIn('href="/cve-database/"', page)

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
        self.assertEqual(
            mcp_server._cve_landing_safe_https_url(
                "https://vendor.example/advisory?lang=en&utm_source=openai&utm_medium=ai"
            ),
            "https://vendor.example/advisory?lang=en",
        )

    def test_bounded_lookup_adds_related_cves_without_playbook_lookup(self) -> None:
        recipe = sample_recipe()
        related = [
            {
                "cve": "CVE-2021-44228",
                "title": "Related injection CVE",
                "severity": "critical",
                "score": 10.0,
                "published": "2021-12-10",
                "qualification": "stable_markdown",
            }
        ]
        with (
            patch.object(mcp_server.cve_catalog, "get_recipe", return_value=recipe),
            patch.object(
                mcp_server.cve_catalog,
                "related_cves",
                return_value=related,
            ) as related_lookup,
            patch.object(
                mcp_server.playbook_registry,
                "get_playbook",
                side_effect=AssertionError("CVE pages must not query playbook recommendations"),
            ) as playbook_lookup,
        ):
            result = mcp_server._bounded_cve_landing_lookup("CVE-2024-3400")

        source_record = recipe["source_record"]
        assert isinstance(source_record, dict)
        related_lookup.assert_called_once_with(source_record, limit=6)
        playbook_lookup.assert_not_called()
        self.assertEqual(result["related_cves"], related)
        self.assertNotIn("matched_playbook", result)

    def test_bounded_lookup_supplemental_context_fails_soft(self) -> None:
        recipe = sample_recipe()
        with (
            patch.object(mcp_server.cve_catalog, "get_recipe", return_value=recipe),
            patch.object(
                mcp_server.cve_catalog,
                "related_cves",
                side_effect=ValueError("bad qualified index"),
            ),
        ):
            result = mcp_server._bounded_cve_landing_lookup("CVE-2024-3400")

        self.assertNotIn("related_cves", result)
        self.assertNotIn("matched_playbook", result)

    def test_bounded_lookup_does_not_enrich_a_missing_record(self) -> None:
        missing = {"found": False, "cve": "CVE-2024-9999"}
        with (
            patch.object(mcp_server.cve_catalog, "get_recipe", return_value=missing),
            patch.object(mcp_server.cve_catalog, "related_cves") as related_lookup,
            patch.object(mcp_server.playbook_registry, "get_playbook") as playbook_lookup,
        ):
            result = mcp_server._bounded_cve_landing_lookup("CVE-2024-9999")

        self.assertIs(result, missing)
        related_lookup.assert_not_called()
        playbook_lookup.assert_not_called()


class CveLandingRouteTests(unittest.IsolatedAsyncioTestCase):
    async def test_route_uses_a_worker_thread_and_returns_cacheable_html(self) -> None:
        lookup = AsyncMock(return_value=sample_recipe())
        with patch.object(mcp_server.asyncio, "to_thread", lookup):
            response = await mcp_server.cve_landing_page(request_for("CVE-2024-3400"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], mcp_server._CVE_LANDING_CACHE_CONTROL)
        self.assertIn("index, follow", response.headers["x-robots-tag"])
        self.assertIn("nosniff", response.headers["x-content-type-options"])
        self.assertIn(b'data-cve-id="CVE-2024-3400"', response.body)
        self.assertIn(b'id="remediation-authority-heading"', response.body)
        self.assertIn(b'id="use-ai-heading"', response.body)
        lookup.assert_awaited_once_with(
            mcp_server._bounded_cve_landing_lookup,
            "CVE-2024-3400",
        )

    async def test_generic_record_is_cacheable_but_noindex_follow(self) -> None:
        lookup = AsyncMock(return_value=generic_recipe())
        with (
            patch.object(mcp_server.asyncio, "to_thread", lookup),
            patch.object(mcp_server.cve_catalog, "is_search_indexable", return_value=False),
        ):
            response = await mcp_server.cve_landing_page(request_for("CVE-2024-3400"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers["cache-control"],
            mcp_server._CVE_LANDING_CACHE_CONTROL,
        )
        self.assertEqual(response.headers["x-robots-tag"], "noindex, follow")
        self.assertIn(b'<meta name="robots" content="noindex,follow">', response.body)

    async def test_busy_and_catalog_load_failures_are_retryable_503s(self) -> None:
        for error in (
            mcp_server._CVELandingBusyError("busy"),
            TimeoutError("timed out"),
            OSError("catalog unavailable"),
        ):
            with self.subTest(error=type(error).__name__):
                lookup = AsyncMock(side_effect=error)
                with patch.object(mcp_server.asyncio, "to_thread", lookup):
                    response = await mcp_server.cve_landing_page(
                        request_for("CVE-2024-3400")
                    )

                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.headers["cache-control"], "no-store")
                self.assertIn("noindex", response.headers["x-robots-tag"])
                self.assertEqual(
                    response.headers["retry-after"],
                    str(mcp_server._CVE_LANDING_RETRY_AFTER_SECONDS),
                )

    async def test_render_identity_failure_is_a_retryable_503(self) -> None:
        lookup = AsyncMock(return_value=sample_recipe())
        with (
            patch.object(mcp_server.asyncio, "to_thread", lookup),
            patch.object(
                mcp_server,
                "_render_cve_landing_page",
                side_effect=ValueError("identity mismatch"),
            ),
        ):
            response = await mcp_server.cve_landing_page(request_for("CVE-2024-3400"))

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertIn("noindex", response.headers["x-robots-tag"])
        self.assertEqual(
            response.headers["retry-after"],
            str(mcp_server._CVE_LANDING_RETRY_AFTER_SECONDS),
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

    async def test_static_reviewed_cves_redirect_before_runtime_lookup(self) -> None:
        lookup = AsyncMock()
        with (
            patch.dict(
                "os.environ",
                {"RECIPES_PUBLIC_SITE_BASE_URL": "https://security-recipes.example/"},
            ),
            patch.object(mcp_server.asyncio, "to_thread", lookup),
        ):
            for cve_id, static_route in STATIC_REVIEWED_ROUTES.items():
                with self.subTest(cve_id=cve_id):
                    response = await mcp_server.cve_landing_page(
                        request_for(cve_id.lower())
                    )
                    self.assertEqual(response.status_code, 308)
                    self.assertEqual(
                        response.headers["location"],
                        f"https://security-recipes.example{static_route}",
                    )
                    self.assertEqual(
                        response.headers["x-robots-tag"],
                        "noindex, follow",
                    )
        lookup.assert_not_awaited()

    async def test_legacy_reviewed_recipe_redirects_to_canonical_cve(self) -> None:
        with patch.dict(
            "os.environ",
            {"RECIPES_PUBLIC_SITE_BASE_URL": "https://security-recipes.example/"},
        ):
            response = await mcp_server.legacy_cve_recipe_redirect(
                legacy_request_for("cve-2024-3400-pan-os-command-injection")
            )

        self.assertEqual(response.status_code, 308)
        self.assertEqual(
            response.headers["location"],
            "https://security-recipes.example/cve/CVE-2024-3400/",
        )
        self.assertEqual(response.headers["x-robots-tag"], "noindex, follow")

    async def test_legacy_static_reviewed_slugs_keep_their_static_canonicals(self) -> None:
        with patch.dict(
            "os.environ",
            {"RECIPES_PUBLIC_SITE_BASE_URL": "https://security-recipes.example/"},
        ):
            for cve_id, static_route in STATIC_REVIEWED_ROUTES.items():
                slug = static_route.removeprefix("/recipes/cve/").rstrip("/")
                with self.subTest(cve_id=cve_id):
                    response = await mcp_server.legacy_cve_recipe_redirect(
                        legacy_request_for(slug)
                    )
                    self.assertEqual(response.status_code, 308)
                    self.assertEqual(
                        response.headers["location"],
                        f"https://security-recipes.example{static_route}",
                    )

    async def test_invalid_legacy_recipe_slug_is_a_nonindexable_404(self) -> None:
        response = await mcp_server.legacy_cve_recipe_redirect(
            legacy_request_for("not-a-cve-recipe")
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertIn("noindex", response.headers["x-robots-tag"])

    async def test_invalid_identifier_is_a_nonindexable_404_without_lookup(self) -> None:
        lookup = AsyncMock()
        with patch.object(mcp_server.asyncio, "to_thread", lookup):
            response = await mcp_server.cve_landing_page(request_for("CVE-2024-bad"))

        self.assertEqual(response.status_code, 404)
        self.assertIn("noindex", response.headers["x-robots-tag"])
        lookup.assert_not_awaited()


class CveLandingProxyContractTests(unittest.TestCase):
    def test_fastmcp_registers_canonical_and_legacy_get_routes(self) -> None:
        routes = {
            route.path: set(route.methods or [])
            for route in mcp_server.mcp._additional_http_routes
        }
        self.assertIn("/cve/{cve_id}/", routes)
        self.assertIn("GET", routes["/cve/{cve_id}/"])
        self.assertIn("/recipes/cve/{slug}/", routes)
        self.assertIn("GET", routes["/recipes/cve/{slug}/"])

    def test_nginx_proxies_only_canonical_cve_shapes_without_credentials(self) -> None:
        nginx = (ROOT / "docker" / "nginx" / "default.conf").read_text(encoding="utf-8")
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

        self.assertIn(
            'location ~* "^/cve/CVE-[0-9]{4}-[0-9]{4,}/$"',
            nginx,
        )
        self.assertIn('proxy_cache_key "$scheme|$host|$uri";', nginx)
        self.assertNotIn('$scheme|$host|$request_uri', nginx)
        self.assertIn("proxy_cache_lock on;", nginx)
        self.assertIn("proxy_cache_lock_timeout 5s;", nginx)
        self.assertIn("proxy_cache_lock_age 5s;", nginx)
        self.assertIn("proxy_connect_timeout 3s;", nginx)
        self.assertIn("proxy_pass $cve_landing_api$uri;", nginx)
        self.assertIn('proxy_set_header Authorization "";', nginx)
        self.assertIn('proxy_set_header Cookie "";', nginx)
        self.assertIn(
            'RECIPES_PUBLIC_SITE_BASE_URL: '
            '"${SECURITY_RECIPES_BASE_URL:-https://security-recipes.ai/}"',
            compose,
        )


if __name__ == "__main__":
    unittest.main()
