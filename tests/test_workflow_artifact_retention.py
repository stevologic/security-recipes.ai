from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", "node_modules", "public", ".venv", "__pycache__"}
MAX_RETENTION_DAYS = 3
UPLOAD_ARTIFACT_RE = re.compile(
    r"(?m)^\s+uses:\s+actions/upload-artifact@[0-9a-f]{40}"
)
STEP_START_RE = re.compile(r"(?m)^(?= {6}- (?:name|uses):)")
RETENTION_RE = re.compile(r"(?m)^\s+retention-days:\s+(\d+)\s*$")


def iter_yaml_files() -> list[Path]:
    files: list[Path] = []
    for pattern in ("**/*.yml", "**/*.yaml"):
        for path in ROOT.glob(pattern):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            files.append(path)
    return sorted(set(files))


class WorkflowArtifactRetentionTests(unittest.TestCase):
    def test_every_upload_artifact_step_sets_retention_days_of_3_or_less(self) -> None:
        offenders: list[str] = []
        found = 0
        for path in iter_yaml_files():
            text = path.read_text(encoding="utf-8")
            for step in STEP_START_RE.split(text):
                if not UPLOAD_ARTIFACT_RE.search(step):
                    continue
                found += 1
                match = RETENTION_RE.search(step)
                if match is None or int(match.group(1)) > MAX_RETENTION_DAYS:
                    value = match.group(1) if match else "missing"
                    offenders.append(
                        f"{path.relative_to(ROOT)} retention-days={value}"
                    )

        self.assertGreaterEqual(found, 1)
        self.assertEqual(
            offenders,
            [],
            "every actions/upload-artifact step must set retention-days to "
            f"{MAX_RETENTION_DAYS} or less: {offenders}",
        )


if __name__ == "__main__":
    unittest.main()
