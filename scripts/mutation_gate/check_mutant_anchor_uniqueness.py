#!/usr/bin/env python3
"""Live-YAML mutant-anchor uniqueness.

Not loaded by CI ``unittest discover -s tests -p test_*.py``. Run explicitly:

    python scripts/mutation_gate/check_mutant_anchor_uniqueness.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.exact_sha_build_status_mutants import DELIVERY, SH, SYNC, VA, edits_for, known_mutant_ids


FILES = {
    SH: ROOT / SH,
    VA: ROOT / VA,
    SYNC: ROOT / SYNC,
    DELIVERY: ROOT / DELIVERY,
}


class MutantAnchorUniquenessTests(unittest.TestCase):
    def test_mutant_anchors_are_unique_in_live_files(self) -> None:
        files = {rel: path.read_text(encoding="utf-8") for rel, path in FILES.items()}
        for mutant_id in known_mutant_ids():
            for rel, old, _new in edits_for(mutant_id):
                with self.subTest(mutant_id=mutant_id, rel=rel):
                    self.assertEqual(files[rel].count(old), 1, mutant_id)


if __name__ == "__main__":
    unittest.main()
