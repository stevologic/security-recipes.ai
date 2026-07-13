from __future__ import annotations

import unittest

from scripts.evaluate_recipe_routing import rank


class RecipeRoutingTests(unittest.TestCase):
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
