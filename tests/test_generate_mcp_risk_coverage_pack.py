from __future__ import annotations

import unittest
from pathlib import Path

from scripts.generate_mcp_risk_coverage_pack import DEFAULT_PROFILE, build_risk_coverage, load_json


REPO_ROOT = Path(__file__).resolve().parents[1]


class McpRiskCoverageAliasTests(unittest.TestCase):
    def test_mcp06_aliases_pass_through_from_profile(self) -> None:
        profile = load_json(REPO_ROOT / DEFAULT_PROFILE)
        rows = {str(row.get("id")): row for row in build_risk_coverage(profile)}
        self.assertIn("MCP06", rows)
        self.assertEqual(
            rows["MCP06"].get("aliases"),
            ["Prompt Injection via Contextual Payloads"],
        )


if __name__ == "__main__":
    unittest.main()
