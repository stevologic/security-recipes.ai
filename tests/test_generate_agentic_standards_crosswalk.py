from __future__ import annotations

import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = REPO_ROOT / "data" / "assurance" / "agentic-standards-crosswalk.json"
WORKFLOW_PAGE = (
    REPO_ROOT
    / "content"
    / "security-remediation"
    / "agentic-standards-crosswalk"
    / "_index.md"
)
PLAYBOOKS_PATH = REPO_ROOT / "data" / "remediation_suite" / "playbooks.json"


class StandardsCrosswalkIdentityTenetsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        cls.page = WORKFLOW_PAGE.read_text(encoding="utf-8")
        cls.playbooks = json.loads(PLAYBOOKS_PATH.read_text(encoding="utf-8"))

    def test_profile_records_nist_identity_design_tenets(self) -> None:
        source_ids = {
            str(row.get("id"))
            for row in self.profile.get("source_references", [])
            if isinstance(row, dict)
        }
        self.assertIn("nist-agentic-identity-foundation-2026", source_ids)
        self.assertIn("nist-nccoe-agentic-identity-comments-2026", source_ids)
        self.assertIn("nist-agentic-identity-design-tenets-2026", source_ids)
        self.assertEqual(self.profile.get("last_reviewed"), "2026-11-06")

        tenets = next(
            row
            for row in self.profile["source_references"]
            if row.get("id") == "nist-agentic-identity-design-tenets-2026"
        )
        self.assertEqual(
            tenets["url"],
            "https://www.nist.gov/blogs/cybersecurity-insights/design-tenets-agent-identity-management-systems",
        )
        self.assertEqual(tenets["published"], "2026-10-27")
        self.assertIn("attenuated sub-agent delegation", tenets["why_it_matters"])
        self.assertIn("zero standing privilege", tenets["why_it_matters"])
        self.assertIn("independent append-only evidence", tenets["why_it_matters"])

    def test_nist_identity_controls_cover_tenets_not_just_unique_credentials(self) -> None:
        nist = next(
            row
            for row in self.profile["standards"]
            if row.get("id") == "nist-agentic-ai-risk-management"
        )
        controls = {str(row.get("id")): row for row in nist["controls"]}
        self.assertIn("nist-agentic-identity-design-tenets-2026", nist["source_ids"])
        self.assertGreaterEqual(nist["minimum_required_controls"], 8)

        identity = controls["NIST-AGENT-01"]
        self.assertIn("distinct from humans and service accounts", identity["objective"])

        attenuation = controls["NIST-AGENT-06"]
        self.assertIn("agent-trust-fabric", attenuation["required_capability_ids"])
        self.assertIn("cannot claim more authority than the parent", attenuation["objective"])
        self.assertIn("standing privilege", attenuation["diligence_question"])

        mandates = controls["NIST-AGENT-07"]
        self.assertIn("signed mandate", mandates["diligence_question"])
        self.assertIn("reasoning model cannot expand permissions", mandates["diligence_question"])

        evidence = controls["NIST-AGENT-08"]
        self.assertIn("agent-independent append-only", evidence["objective"])
        self.assertIn("consent-fatigue", evidence["objective"])

    def test_workflow_and_playbook_record_tenets_without_claiming_human_review(self) -> None:
        self.assertIn("lastmod: 2026-11-06", self.page)
        self.assertIn("does not claim human review of the pack", self.page)
        self.assertIn(
            "https://www.nist.gov/blogs/cybersecurity-insights/design-tenets-agent-identity-management-systems",
            self.page,
        )
        self.assertIn("attenuated sub-agent delegation", self.page)
        playbook = next(
            row
            for row in self.playbooks["playbooks"]
            if row.get("id") == "agentic-standards-crosswalk"
        )
        decision = next(phase for phase in playbook["phases"] if phase.get("label") == "Decision")
        self.assertIn("unattenuated", decision["detail"])
        self.assertIn("standing privilege", decision["detail"])
        self.assertIn("write their own evidence", decision["detail"])


if __name__ == "__main__":
    unittest.main()
