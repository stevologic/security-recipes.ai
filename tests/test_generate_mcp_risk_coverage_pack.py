from __future__ import annotations

import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = REPO_ROOT / "data" / "assurance" / "mcp-risk-coverage-profile.json"
WORKFLOW_PAGE = (
    REPO_ROOT / "content" / "security-remediation" / "mcp-risk-coverage" / "_index.md"
)
Q3_URL = (
    "https://genai.owasp.org/2026/10/08/genai-and-agentic-ai-exploit-roundup-q3-2026/"
)


def _profile() -> dict[str, object]:
    return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))


def _risk(profile: dict[str, object], risk_id: str) -> dict[str, object]:
    for standard in profile["standards"]:
        for risk in standard["risks"]:
            if risk["id"] == risk_id:
                return risk
    raise AssertionError(f"missing risk {risk_id}")


class MCPRiskCoverageDeadbugzTests(unittest.TestCase):
    def test_profile_records_q3_deadbugz_without_claiming_human_review(self) -> None:
        profile = _profile()
        self.assertEqual(profile["last_reviewed"], "2026-11-12")
        sources = {
            str(item.get("id")): item
            for item in profile["source_references"]
            if isinstance(item, dict)
        }
        q3 = sources["owasp-genai-exploit-roundup-q3-2026"]
        self.assertEqual(q3["url"], Q3_URL)
        self.assertEqual(q3["published"], "2026-10-08")
        self.assertIn("Deadbugz", q3["why_it_matters"])
        mcp_sources = next(
            standard["source_ids"]
            for standard in profile["standards"]
            if standard["id"] == "owasp-mcp-top-10-2025"
        )
        self.assertIn("owasp-genai-exploit-roundup-q3-2026", mcp_sources)

    def test_mcp03_requires_post_approval_metadata_reapproval(self) -> None:
        mcp03 = _risk(_profile(), "MCP03")
        self.assertIn("already-approved MCP server", mcp03["primary_attack_path"])
        self.assertIn("mutates tool metadata", mcp03["primary_attack_path"])
        self.assertIn("re-approval", mcp03["evidence_expectation"])
        self.assertIn("first benign calls", mcp03["evidence_expectation"])

    def test_mcp01_and_mcp04_cover_confused_deputy_secret_harvest(self) -> None:
        profile = _profile()
        mcp01 = _risk(profile, "MCP01")
        mcp04 = _risk(profile, "MCP04")
        self.assertIn("mcp-tool-surface-drift-pack", mcp01["required_capability_ids"])
        self.assertIn("confused deputy", mcp01["primary_attack_path"])
        self.assertIn("mcp-tool-surface-drift-pack", mcp04["required_capability_ids"])
        self.assertIn("mutate tool metadata after approval", mcp04["primary_attack_path"])

    def test_workflow_page_records_q3_without_claiming_human_review(self) -> None:
        page = WORKFLOW_PAGE.read_text(encoding="utf-8")
        self.assertIn(Q3_URL, page)
        self.assertIn("Deadbugz", page)
        self.assertIn("does not claim human review of the pack", page)
        self.assertIn("lastmod: 2026-11-12", page)


if __name__ == "__main__":
    unittest.main()
