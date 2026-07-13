from __future__ import annotations

import json
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any

from scripts import validate_cve_catalog as validator


ROOT = Path(__file__).resolve().parents[1]
ARCHETYPES_PATH = ROOT / "data" / "cve" / "remediation-archetypes.json"


def load_archetypes() -> dict[str, Any]:
    return json.loads(ARCHETYPES_PATH.read_text(encoding="utf-8"))


class CVEAgenticContractTests(unittest.TestCase):
    def validate(self, payload: dict[str, Any]) -> tuple[set[str], list[str]]:
        failures: list[str] = []
        valid = validator.valid_archetype_contracts(payload, failures)
        return valid, failures

    def test_every_archetype_has_a_complete_unique_deterministic_workflow(self) -> None:
        payload = load_archetypes()

        valid, failures = self.validate(payload)

        self.assertEqual(failures, [])
        self.assertEqual(valid, set(payload["archetypes"]))
        action_ids: list[str] = []
        for archetype_id, archetype in payload["archetypes"].items():
            actions = archetype["agentic_actions"]
            self.assertEqual(
                [action["phase"] for action in actions],
                list(validator.AGENTIC_ACTION_ORDER),
            )
            for action in actions:
                self.assertEqual(action["id"], f"{archetype_id}.{action['phase']}")
                self.assertTrue(archetype[action["source_field"]])
                action_ids.append(action["id"])
        self.assertEqual(len(action_ids), 19 * 7)
        self.assertEqual(len(action_ids), len(set(action_ids)))

    def test_contract_requires_safe_version_evidence_and_rollback(self) -> None:
        payload = load_archetypes()
        version_policy = payload["agentic_contract"]["fixed_version_policy"]
        self.assertTrue(version_policy["require_source_record"])
        self.assertIn("Do not invent", version_policy["when_unknown"])
        self.assertIn("TRIAGE.md", version_policy["when_unknown"])

        broken = deepcopy(payload)
        broken["archetypes"]["generic"]["rollback_steps"] = []
        valid, failures = self.validate(broken)

        self.assertNotIn("generic", valid)
        self.assertIn("rollback_steps", "\n".join(failures))

    def test_contract_rejects_phase_drift_and_duplicate_or_unknown_targets(self) -> None:
        payload = load_archetypes()
        broken = deepcopy(payload)
        actions = broken["archetypes"]["ssrf"]["agentic_actions"]
        actions[2]["source_field"] = "remediation_steps"
        actions[3]["target_kinds"] = ["source_code", "source_code"]
        actions[4]["target_kinds"] = ["network_probe"]

        valid, failures = self.validate(broken)
        failure_text = "\n".join(failures)

        self.assertNotIn("ssrf", valid)
        self.assertIn("containment_steps", failure_text)
        self.assertIn("target_kinds are invalid", failure_text)

    def test_vendor_controlled_ecosystems_never_target_source_edits(self) -> None:
        payload = load_archetypes()
        for ecosystem in validator.VENDOR_CONTROLLED_ECOSYSTEMS:
            targets = payload["ecosystem_target_hints"][ecosystem]["target_kinds"]
            self.assertNotIn("source_code", targets, ecosystem)

        broken = deepcopy(payload)
        broken["ecosystem_target_hints"]["hardware/firmware"]["target_kinds"].append(
            "source_code"
        )
        _, failures = self.validate(broken)
        self.assertIn("vendor-controlled source", "\n".join(failures))

    def test_contract_rejects_unsafe_unknown_version_policy(self) -> None:
        payload = load_archetypes()
        payload["agentic_contract"]["fixed_version_policy"]["when_unknown"] = (
            "Select a likely version and continue."
        )

        valid, failures = self.validate(payload)

        self.assertEqual(valid, set())
        self.assertIn("forbid invented versions", "\n".join(failures))

    def test_every_action_has_an_effective_target_in_every_ecosystem(self) -> None:
        payload = load_archetypes()
        broken = deepcopy(payload)
        broken["archetypes"]["generic"]["agentic_actions"][0]["target_kinds"] = [
            "source_code"
        ]

        valid, failures = self.validate(broken)

        self.assertNotIn("generic", valid)
        self.assertIn("no effective target for ecosystem", "\n".join(failures))

    def test_external_sources_are_untrusted_evidence_not_instructions(self) -> None:
        payload = load_archetypes()
        boundaries = " ".join(payload["agentic_contract"]["safety_boundaries"]).lower()

        self.assertIn("untrusted evidence", boundaries)
        self.assertIn("embedded commands", boundaries)


if __name__ == "__main__":
    unittest.main()
