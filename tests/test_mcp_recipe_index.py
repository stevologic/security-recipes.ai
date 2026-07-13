from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from mcp_server import RecipeIndex, ServerConfig


def run(coro):
    return asyncio.run(coro)


class RecipeIndexTests(unittest.TestCase):
    def test_normalizes_agent_recipe_feed(self) -> None:
        payload = {
            "api_version": "2026-06-10",
            "recipes": [
                {
                    "slug": "cve-2025-55182-react-server-components-rce",
                    "title": "React Server Components RCE",
                    "url": "https://example.test/recipes/cve-2025-55182/",
                    "path": "/recipes/cve-2025-55182/",
                    "source_file": "recipes/cve/cve-2025-55182-react-server-components-rce.md",
                    "category": {"slug": "cve", "label": "CVE"},
                    "agent": "general",
                    "severity": "critical",
                    "ecosystem": "npm",
                    "cve": "CVE-2025-55182",
                    "tags": ["react", "rsc"],
                    "facets": ["remediation", "risk", "code-hygiene"],
                    "quality": {"score": 90, "tier": "world-class", "signals": ["output-contract"]},
                    "summary": "Patch React Server Components remote code execution.",
                    "content_text": "Use the CVE recipe to patch React Server Components RCE safely.",
                }
            ],
        }

        docs = RecipeIndex._normalize_payload(payload)

        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]["content"], payload["recipes"][0]["content_text"])
        self.assertEqual(docs[0]["section"], "recipes")
        self.assertEqual(docs[0]["category"]["slug"], "cve")
        self.assertEqual(docs[0]["facets"], ["remediation", "risk", "code-hygiene"])
        self.assertEqual(docs[0]["quality"]["score"], 90)

    def test_file_backed_agent_feed_can_search_list_and_get(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            index_path = Path(tmpdir) / "recipes.json"
            index_path.write_text(
                json.dumps(
                    {
                        "recipes": [
                            {
                                "slug": "cve-2025-55182-react-server-components-rce",
                                "title": "React Server Components RCE",
                                "url": "https://example.test/recipes/cve-2025-55182/",
                                "path": "/recipes/cve-2025-55182/",
                                "source_file": "recipes/cve/cve-2025-55182-react-server-components-rce.md",
                                "category": {"slug": "cve", "label": "CVE"},
                                "agent": "general",
                                "severity": "critical",
                                "ecosystem": "npm",
                                "cve": "CVE-2025-55182",
                                "tags": ["react", "rsc"],
                                "facets": ["remediation", "risk", "code-hygiene"],
                                "quality": {"score": 90, "tier": "world-class", "signals": ["verification"]},
                                "summary": "Patch React Server Components remote code execution.",
                                "content_text": "Patch React Server Components and verify the npm test suite.",
                            },
                            {
                                "slug": "sast-finding-triage-and-fix",
                                "title": "SAST Finding Triage and Fix",
                                "url": "https://example.test/recipes/sast-finding-triage-and-fix/",
                                "path": "/recipes/sast-finding-triage-and-fix/",
                                "source_file": "recipes/general/sast-finding-triage-and-fix.md",
                                "category": {"slug": "general", "label": "General"},
                                "agent": "general",
                                "severity": "unspecified",
                                "tags": ["sast"],
                                "facets": ["remediation", "audit", "code-hygiene"],
                                "quality": {"score": 70, "tier": "strong", "signals": ["output-contract"]},
                                "summary": "Triage one static-analysis finding.",
                                "content_text": "Bound the agent to one SAST finding and one reviewed patch.",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            cfg = ServerConfig(
                source_index_url=index_path.as_uri(),
                allowed_source_hosts=[],
                max_results_default=10,
                max_results_cap=10,
            )
            index = RecipeIndex(cfg)

            refresh = run(index.refresh(force=True))
            cve_results = run(index.list_docs(section="cve"))
            strong_audit_results = run(index.list_docs(facets=["audit"], min_quality=70))
            search_results = run(index.search("react npm rce", section="cve"))
            quality_search_results = run(index.search("finding patch", facets=["code-hygiene"], min_quality=80))
            recipe = run(index.get_doc("/recipes/cve-2025-55182/"))
            quality_report = run(index.quality_report(facet="audit", limit=5))

        self.assertEqual(refresh["status"], "refreshed")
        self.assertEqual(refresh["doc_count"], 2)
        self.assertEqual(len(cve_results), 1)
        self.assertEqual(len(strong_audit_results), 1)
        self.assertEqual(strong_audit_results[0]["slug"], "sast-finding-triage-and-fix")
        self.assertEqual(cve_results[0]["cve"], "CVE-2025-55182")
        self.assertEqual(search_results[0]["slug"], "cve-2025-55182-react-server-components-rce")
        self.assertEqual(quality_search_results[0]["quality"]["tier"], "world-class")
        self.assertIsNotNone(recipe)
        self.assertEqual(recipe["title"], "React Server Components RCE")
        self.assertEqual(quality_report["recipe_count"], 1)
        self.assertEqual(quality_report["tier_counts"]["strong"], 1)
        self.assertEqual(quality_report["gaps"][0]["slug"], "sast-finding-triage-and-fix")
        self.assertIn("verification", quality_report["gaps"][0]["missing_quality_signals"])

    def test_normalizes_legacy_recipe_index_array(self) -> None:
        payload = [
            {
                "slug": "secure-context-firewall",
                "title": "Secure Context Firewall",
                "url": "https://example.test/security-remediation/secure-context-firewall/",
                "path": "/security-remediation/secure-context-firewall/",
                "section": "security-remediation",
                "agent": "general",
                "severity": "unspecified",
                "tags": ["mcp"],
                "summary": "Control what context reaches an agent.",
                "content": "Use policy boundaries to limit context egress and poisoning.",
            }
        ]

        docs = RecipeIndex._normalize_payload(payload)

        self.assertEqual(docs[0]["slug"], "secure-context-firewall")
        self.assertEqual(docs[0]["content"], payload[0]["content"])
        self.assertEqual(docs[0]["section"], "security-remediation")


if __name__ == "__main__":
    unittest.main()
