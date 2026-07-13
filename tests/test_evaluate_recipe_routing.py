from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.evaluate_recipe_routing import evaluate, rank


ROOT = Path(__file__).resolve().parents[1]


class RecipeRoutingTests(unittest.TestCase):
    def test_checked_in_golden_paths_resolve_to_content_pages(self) -> None:
        golden = json.loads((ROOT / "data/evaluations/recipe-routing-golden.json").read_text(encoding="utf-8"))
        content_urls = set()
        for path in (ROOT / "content").rglob("*.md"):
            relative = path.relative_to(ROOT / "content").as_posix()[:-3]
            if relative.endswith("/_index"):
                relative = relative[: -len("/_index")]
            content_urls.add(f"/{relative.strip('/')}/")
        expected = {path for case in golden["cases"] for path in case["expected_paths"]}
        self.assertEqual(set(), expected - content_urls)

    def test_evaluate_rejects_dangling_golden_path(self) -> None:
        docs = [{"title": "One", "slug": "one", "path": "/recipes/one/", "content": "one"}]
        golden = {
            "name": "test",
            "version": "1",
            "cases": [{"id": "dangling", "query": "one", "expected_paths": ["/recipes/gone/"]}],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            index_path = Path(temp_dir) / "index.json"
            golden_path = Path(temp_dir) / "golden.json"
            index_path.write_text(json.dumps(docs), encoding="utf-8")
            golden_path.write_text(json.dumps(golden), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "absent from the recipe index"):
                evaluate(index_path, golden_path, 3)

    def test_exact_cve_identifier_outranks_generic_rce_text(self) -> None:
        docs = [
            {
                "title": "CVE-2021-44228 Log4Shell",
                "slug": "cve-2021-44228-log4shell",
                "path": "/recipes/cve/cve-2021-44228-log4shell/",
                "content": "Patch log4j-core and disable unsafe JNDI lookups.",
            },
            {
                "title": "Generic remote code execution response",
                "slug": "generic-rce",
                "path": "/recipes/general/generic-rce/",
                "content": "Remote code execution in a Maven service. " * 20,
            },
        ]

        results = rank("CVE-2021-44228 Maven remote code execution", docs, 2)

        self.assertEqual(results[0]["path"], docs[0]["path"])

    def test_gate_query_matches_gatekeeping_not_gateway_substrings(self) -> None:
        docs = [
            {
                "title": "Gatekeeping Patterns",
                "slug": "gatekeeping",
                "path": "/security-remediation/gatekeeping/",
                "content": "Admission gates, pre-merge gates, runtime gates, and agentic remediation controls.",
            },
            {
                "title": "Payment gateways",
                "slug": "payment-gateways",
                "path": "/recipes/general/payment-gateways/",
                "content": "gateway gateways gateway gateways " * 20,
            },
        ]

        results = rank("admission gate pre merge gate runtime gate for agentic remediation", docs, 2)

        self.assertEqual(results[0]["path"], docs[0]["path"])


if __name__ == "__main__":
    unittest.main()
