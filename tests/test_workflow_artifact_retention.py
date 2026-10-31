from __future__ import annotations

import re
import unittest
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SKIP_DIRS = {".git", "node_modules", "public", ".venv", "__pycache__"}
MAX_RETENTION_DAYS = 3
UPLOAD_ARTIFACT_RE = re.compile(r"^actions/upload-artifact@\S+")
RUN_CHECKS = ROOT / "scripts" / "run_checks.py"


def iter_action_yaml_files() -> list[Path]:
    files: list[Path] = []
    if WORKFLOWS.is_dir():
        files.extend(WORKFLOWS.glob("*.yml"))
        files.extend(WORKFLOWS.glob("*.yaml"))
    for pattern in ("**/action.yml", "**/action.yaml", "**/*.yml", "**/*.yaml"):
        for path in ROOT.glob(pattern):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            files.append(path)
    return sorted({path for path in files if path.is_file()})


def iter_job_or_composite_steps(document: Any) -> Iterator[tuple[str, dict[str, Any]]]:
    if not isinstance(document, dict):
        return
    jobs = document.get("jobs")
    if isinstance(jobs, dict):
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps")
            if not isinstance(steps, list):
                continue
            for index, step in enumerate(steps):
                if isinstance(step, dict):
                    yield f"jobs.{job_id}.steps[{index}]", step
    runs = document.get("runs")
    if isinstance(runs, dict):
        steps = runs.get("steps")
        if isinstance(steps, list):
            for index, step in enumerate(steps):
                if isinstance(step, dict):
                    yield f"runs.steps[{index}]", step


def upload_artifact_uses(step: dict[str, Any]) -> str | None:
    uses = step.get("uses")
    if not isinstance(uses, str):
        return None
    uses = uses.strip()
    if UPLOAD_ARTIFACT_RE.match(uses):
        return uses
    return None


def retention_days_value(step: dict[str, Any]) -> int | None:
    with_block = step.get("with")
    if not isinstance(with_block, dict) or "retention-days" not in with_block:
        return None
    raw = with_block["retention-days"]
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def retention_offenders(document: Any, source: str) -> list[str]:
    offenders: list[str] = []
    for location, step in iter_job_or_composite_steps(document):
        if upload_artifact_uses(step) is None:
            continue
        days = retention_days_value(step)
        if days is None or days > MAX_RETENTION_DAYS:
            value = "missing" if days is None else str(days)
            offenders.append(f"{source} {location} retention-days={value}")
    return offenders


def _must_parse(path: Path) -> bool:
    if path.name in {"action.yml", "action.yaml"}:
        return True
    try:
        return path.parent == WORKFLOWS
    except ValueError:
        return False


def scan_path_for_offenders(path: Path) -> tuple[int, list[str]]:
    text = path.read_text(encoding="utf-8")
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError:
        if _must_parse(path):
            raise
        return 0, []
    found = 0
    offenders: list[str] = []
    rel = str(path.relative_to(ROOT))
    for _location, step in iter_job_or_composite_steps(document):
        if upload_artifact_uses(step) is None:
            continue
        found += 1
        days = retention_days_value(step)
        if days is None or days > MAX_RETENTION_DAYS:
            value = "missing" if days is None else str(days)
            offenders.append(f"{rel} retention-days={value}")
    return found, offenders


class WorkflowArtifactRetentionTests(unittest.TestCase):
    def test_scan_covers_root_actions_and_github_workflows(self) -> None:
        files = {str(path.relative_to(ROOT)) for path in iter_action_yaml_files()}
        self.assertIn("actions/security-health/action.yml", files)
        self.assertTrue(any(name.startswith(".github/workflows/") for name in files))
        self.assertTrue(any(name.endswith("action.yml") or name.endswith("action.yaml") for name in files))

    def test_run_checks_discovers_tests_as_a_package(self) -> None:
        source = RUN_CHECKS.read_text(encoding="utf-8")
        self.assertIn('"-s", "tests"', source)
        self.assertIn('"-t", "."', source)

    def test_every_upload_artifact_step_sets_retention_days_of_3_or_less(self) -> None:
        offenders: list[str] = []
        found = 0
        for path in iter_action_yaml_files():
            try:
                file_found, file_offenders = scan_path_for_offenders(path)
            except yaml.YAMLError as exc:
                self.fail(f"{path.relative_to(ROOT)} is not valid YAML: {exc}")
            found += file_found
            offenders.extend(file_offenders)

        self.assertGreaterEqual(found, 1)
        self.assertEqual(
            offenders,
            [],
            "every actions/upload-artifact step must set retention-days to "
            f"{MAX_RETENTION_DAYS} or less: {offenders}",
        )

    def test_version_tag_without_retention_is_an_offender(self) -> None:
        document = yaml.safe_load(
            """
            jobs:
              build:
                steps:
                  - uses: actions/upload-artifact@v4
                    with:
                      name: mutant
            """
        )
        self.assertEqual(
            retention_offenders(document, "mutant.yml"),
            ["mutant.yml jobs.build.steps[0] retention-days=missing"],
        )

    def test_composite_action_retention_over_limit_is_an_offender(self) -> None:
        document = yaml.safe_load(
            """
            runs:
              using: composite
              steps:
                - uses: actions/upload-artifact@v4
                  with:
                    name: mutant
                    retention-days: 4
            """
        )
        self.assertEqual(
            retention_offenders(document, "actions/x/action.yml"),
            ["actions/x/action.yml runs.steps[0] retention-days=4"],
        )


if __name__ == "__main__":
    unittest.main()
