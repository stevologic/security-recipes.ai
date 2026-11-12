from __future__ import annotations

import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = REPO_ROOT / "data" / "assurance" / "agentic-standards-crosswalk.json"


class StandardsCrosswalkIdentityTenetsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))

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


if __name__ == "__main__":
    unittest.main()
