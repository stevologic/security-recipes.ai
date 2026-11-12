"""Live-YAML mutant-anchor uniqueness; not part of the behavioural ControlTests set."""

from __future__ import annotations

import unittest
from pathlib import Path

from tests.exact_sha_build_status_mutants import SH, VA, edits_for, known_mutant_ids


ROOT = Path(__file__).resolve().parents[1]
SHEPHERD_WORKFLOW = ROOT / ".github" / "workflows" / "automation-shepherd.yml"
VALIDATE_WORKFLOW = ROOT / ".github" / "workflows" / "cve-catalog-validate.yml"


class ExactShaBuildStatusUniquenessTests(unittest.TestCase):
    def test_mutant_anchors_are_unique_in_live_yaml(self) -> None:
        files = {
            SH: SHEPHERD_WORKFLOW.read_text(encoding="utf-8"),
            VA: VALIDATE_WORKFLOW.read_text(encoding="utf-8"),
        }
        for mutant_id in known_mutant_ids():
            for rel, old, _new in edits_for(mutant_id):
                with self.subTest(mutant_id=mutant_id, rel=rel):
                    self.assertEqual(files[rel].count(old), 1, mutant_id)


if __name__ == "__main__":
    unittest.main()
