from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.security_recipes_remediation import cli
from tools.security_recipes_remediation.playbooks import (
    IGNORED_DIRECTORY_NAMES,
    PlaybookError,
    expand_file_patterns,
    inspect_workspace,
    load_playbook_registry,
    playbook_by_id,
    record_evidence,
    start_run,
    validate_playbook_registry,
    verify_run,
)


class PlaybookRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_playbook_registry()

    def test_registry_has_75_complete_unique_profiles(self) -> None:
        registry = validate_playbook_registry(copy.deepcopy(self.registry))
        playbooks = registry["playbooks"]
        self.assertEqual(len(playbooks), 75)
        self.assertEqual(len({item["id"] for item in playbooks}), 75)
        for playbook in playbooks:
            command = playbook["python"]["command"]
            self.assertIn(" playbook start ", f" {command} ")
            self.assertIn(f"--playbook {playbook['id']}", command)

    def test_brace_patterns_expand_to_real_alternatives(self) -> None:
        expanded = expand_file_patterns(["**/wallet*.{js,ts,py,go}"])
        self.assertEqual(
            expanded,
            ["**/wallet*.js", "**/wallet*.ts", "**/wallet*.py", "**/wallet*.go"],
        )

    def test_invalid_registry_profile_is_rejected(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["playbooks"][0]["file_patterns"] = ["../secrets/**"]
        with self.assertRaisesRegex(PlaybookError, "parent directories"):
            validate_playbook_registry(registry)

    def test_anchored_registry_patterns_are_not_pruned(self) -> None:
        for playbook in self.registry["playbooks"]:
            for pattern in expand_file_patterns(playbook["file_patterns"]):
                first_segment = pattern.split("/", 1)[0]
                if not any(marker in first_segment for marker in "*?["):
                    self.assertNotIn(first_segment, IGNORED_DIRECTORY_NAMES, f"{playbook['id']}: {pattern}")


class PlaybookLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_playbook_registry()

    def test_bounded_inspection_selects_patterns_and_skips_links_and_large_files(self) -> None:
        playbook = playbook_by_id(self.registry, "crypto-payments")
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
            workspace = Path(directory)
            (workspace / "src").mkdir()
            (workspace / "src" / "wallet_service.py").write_text("def validate():\n    return True\n", encoding="utf-8")
            (workspace / "src" / "wallet_notes.txt").write_text("not selected", encoding="utf-8")
            (workspace / "src" / "payment_large.py").write_bytes(b"x" * 65)
            (workspace / "config" / "nested").mkdir(parents=True)
            (workspace / "config" / "direct.json").write_text("{}", encoding="utf-8")
            (workspace / "config" / "nested" / "deep.json").write_text("{}", encoding="utf-8")
            (workspace / "app" / "config" / "nested").mkdir(parents=True)
            (workspace / "app" / "config" / "direct.json").write_text("{}", encoding="utf-8")
            (workspace / "app" / "config" / "nested" / "deep.json").write_text("{}", encoding="utf-8")
            (workspace / ".git").mkdir()
            (workspace / ".git" / "wallet_hidden.py").write_text("hidden", encoding="utf-8")

            outside = Path(outside_directory) / "wallet_external.py"
            outside.write_text("external", encoding="utf-8")
            link = workspace / "src" / "wallet_link.py"
            link_created = False
            try:
                link.symlink_to(outside)
                link_created = True
            except (NotImplementedError, OSError):
                pass

            inspection = inspect_workspace(
                playbook=playbook,
                workspace=workspace,
                max_files=10,
                max_file_bytes=64,
                max_total_bytes=256,
                max_entries=100,
            )
            paths = {item["path"] for item in inspection["files"]}
            self.assertEqual(
                paths,
                {
                    "src/wallet_service.py",
                    "config/direct.json",
                    "config/nested/deep.json",
                    "app/config/direct.json",
                    "app/config/nested/deep.json",
                },
            )
            self.assertEqual(inspection["summary"]["matched_file_count"], 5)
            self.assertEqual(inspection["summary"]["skipped_counts"]["file_size_limit"], 1)
            self.assertEqual(inspection["summary"]["skipped_counts"]["ignored_directory"], 1)
            if link_created:
                self.assertEqual(inspection["summary"]["skipped_counts"]["link_file"], 1)

    def test_explicit_public_and_prior_run_patterns_are_reachable(self) -> None:
        playbook = playbook_by_id(self.registry, "recipe-recommender")
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "public" / "api").mkdir(parents=True)
            (workspace / "public" / "api" / "recipes.json").write_text("[]", encoding="utf-8")
            (workspace / "public" / "cve" / "shards").mkdir(parents=True)
            for index in range(250):
                (workspace / "public" / "cve" / "shards" / f"CVE-{index}.json").write_text("{}", encoding="utf-8")
            (workspace / ".security-recipes" / "runs" / "prior" / "nested").mkdir(parents=True)
            (workspace / ".security-recipes" / "runs" / "run.json").write_text("{}", encoding="utf-8")
            nested = workspace / ".security-recipes" / "runs" / "prior" / "nested" / "evidence.json"
            nested.write_text("{}", encoding="utf-8")

            inspection = inspect_workspace(playbook=playbook, workspace=workspace)
            paths = {item["path"] for item in inspection["files"]}
            self.assertIn("public/api/recipes.json", paths)
            self.assertIn(".security-recipes/runs/run.json", paths)
            self.assertIn(".security-recipes/runs/prior/nested/evidence.json", paths)
            self.assertFalse(inspection["summary"]["truncated"])
            self.assertLess(inspection["summary"]["visited_entry_count"], 20)
            self.assertEqual(inspection["summary"]["skipped_counts"]["unselected_directory"], 1)

    def test_globstar_zero_directory_form_matches_direct_config_children(self) -> None:
        playbook = copy.deepcopy(playbook_by_id(self.registry, "crypto-payments"))
        playbook["file_patterns"] = ["**/config/**/*"]
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "config").mkdir()
            (workspace / "config" / "root.json").write_text("{}", encoding="utf-8")
            (workspace / "app" / "config" / "nested").mkdir(parents=True)
            (workspace / "app" / "config" / "direct.json").write_text("{}", encoding="utf-8")
            (workspace / "app" / "config" / "nested" / "deep.json").write_text("{}", encoding="utf-8")
            inspection = inspect_workspace(playbook=playbook, workspace=workspace)
            self.assertEqual(
                {item["path"] for item in inspection["files"]},
                {"config/root.json", "app/config/direct.json", "app/config/nested/deep.json"},
            )

    def test_start_record_verify_and_tamper_detection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            finding = workspace / "finding.json"
            finding.write_text('{"id":"CVE-TEST","severity":"high"}', encoding="utf-8")
            (workspace / "Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")
            evidence_file = workspace / "evidence" / "scan.json"
            evidence_file.parent.mkdir()
            evidence_file.write_text('{"result":"clean"}', encoding="utf-8")
            run_dir = workspace / ".security-recipes" / "runs" / "base-images"

            started = start_run(
                registry=self.registry,
                playbook_id="base-images",
                workspace=workspace,
                finding="finding.json",
                run_dir=run_dir,
            )
            self.assertEqual(set(started["artifacts"]), {"run.json", "PLAN.md", "AGENT_TASK.md", "evidence.json"})
            self.assertEqual({path.name for path in run_dir.iterdir()}, set(started["artifacts"]))

            incomplete = verify_run(run_dir=run_dir, registry=self.registry)
            self.assertTrue(incomplete["valid"])
            self.assertFalse(incomplete["complete"])

            requirements = playbook_by_id(self.registry, "base-images")["evidence"]
            item = record_evidence(
                run_dir=run_dir,
                evidence_file=evidence_file,
                kind="scanner",
                requirements=requirements,
                label="post-remediation scan",
            )
            self.assertEqual(item["path"], "evidence/scan.json")
            self.assertNotIn("content", item)
            self.assertEqual(len(item["sha256"]), 64)

            complete = verify_run(run_dir=run_dir, registry=self.registry)
            self.assertTrue(complete["valid"])
            self.assertTrue(complete["complete"])
            self.assertEqual(complete["verified_evidence_count"], 1)

            evidence_file.write_text('{"result":"tampered"}', encoding="utf-8")
            tampered = verify_run(run_dir=run_dir, registry=self.registry)
            self.assertFalse(tampered["valid"])
            self.assertTrue(any("hash or size" in issue for issue in tampered["issues"]))

    def test_profile_tamper_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "finding.json").write_text("{}", encoding="utf-8")
            run_dir = workspace / "run"
            start_run(
                registry=self.registry,
                playbook_id="base-images",
                workspace=workspace,
                finding="finding.json",
                run_dir=run_dir,
            )
            changed_registry = copy.deepcopy(self.registry)
            playbook_by_id(changed_registry, "base-images")["summary"] += " changed"
            result = verify_run(run_dir=run_dir, registry=changed_registry)
            self.assertFalse(result["valid"])
            self.assertIn("playbook profile hash does not match the current registry", result["issues"])

    def test_traversal_and_symlink_inputs_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
            workspace = Path(directory)
            outside_root = Path(outside_directory)
            (workspace / "finding.json").write_text("{}", encoding="utf-8")
            outside_finding = outside_root / "finding.json"
            outside_finding.write_text("{}", encoding="utf-8")

            with self.assertRaisesRegex(PlaybookError, "outside workspace"):
                start_run(
                    registry=self.registry,
                    playbook_id="base-images",
                    workspace=workspace,
                    finding=outside_finding,
                    run_dir=workspace / "run-outside-finding",
                )
            with self.assertRaisesRegex(PlaybookError, "child of the workspace"):
                start_run(
                    registry=self.registry,
                    playbook_id="base-images",
                    workspace=workspace,
                    finding="finding.json",
                    run_dir=outside_root / "run",
                )

            link = workspace / "linked-finding.json"
            try:
                link.symlink_to(outside_finding)
            except (NotImplementedError, OSError):
                link = None
            if link is not None:
                with self.assertRaisesRegex(PlaybookError, "symlink|outside workspace"):
                    start_run(
                        registry=self.registry,
                        playbook_id="base-images",
                        workspace=workspace,
                        finding=link,
                        run_dir=workspace / "run-linked-finding",
                    )

            run_dir = workspace / "run"
            start_run(
                registry=self.registry,
                playbook_id="base-images",
                workspace=workspace,
                finding="finding.json",
                run_dir=run_dir,
            )
            outside_evidence = outside_root / "evidence.txt"
            outside_evidence.write_text("external", encoding="utf-8")
            with self.assertRaisesRegex(PlaybookError, "outside workspace"):
                record_evidence(run_dir=run_dir, evidence_file=outside_evidence, kind="test")


class PlaybookCliTests(unittest.TestCase):
    @staticmethod
    def _run_cli(arguments: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = cli.main(arguments)
        return status, stdout.getvalue(), stderr.getvalue()

    def test_nested_cli_lifecycle_and_exit_codes(self) -> None:
        status, output, error = self._run_cli(["playbook", "list", "--category", "core-remediation"])
        self.assertEqual(status, 0, error)
        self.assertEqual(json.loads(output)["count"], 8)

        status, output, error = self._run_cli(["playbook", "describe", "--playbook", "base-images"])
        self.assertEqual(status, 0, error)
        self.assertEqual(json.loads(output)["id"], "base-images")

        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            finding = workspace / "finding.json"
            finding.write_text("{}", encoding="utf-8")
            evidence_file = workspace / "scan.json"
            evidence_file.write_text('{"clean":true}', encoding="utf-8")
            run_dir = workspace / "run"

            status, output, error = self._run_cli(
                [
                    "playbook",
                    "start",
                    "--playbook",
                    "base-images",
                    "--workspace",
                    str(workspace),
                    "--finding",
                    str(finding),
                    "--run-dir",
                    str(run_dir),
                ]
            )
            self.assertEqual(status, 0, error)
            self.assertEqual(json.loads(output)["playbook_id"], "base-images")

            status, output, error = self._run_cli(["playbook", "verify", "--run-dir", str(run_dir)])
            self.assertEqual(status, 3, error)
            self.assertTrue(json.loads(output)["valid"])

            requirements = playbook_by_id(load_playbook_registry(), "base-images")["evidence"]
            record_arguments = [
                "playbook",
                "record",
                "--run-dir",
                str(run_dir),
                "--file",
                str(evidence_file),
                "--kind",
                "scanner",
            ]
            for requirement in requirements:
                record_arguments.extend(["--requirement", requirement])
            status, output, error = self._run_cli(record_arguments)
            self.assertEqual(status, 0, error)
            self.assertEqual(json.loads(output)["requirements"], requirements)

            status, output, error = self._run_cli(["playbook", "verify", "--run-dir", str(run_dir)])
            self.assertEqual(status, 0, error)
            self.assertTrue(json.loads(output)["complete"])

            evidence_file.write_text("tampered", encoding="utf-8")
            status, output, error = self._run_cli(["playbook", "verify", "--run-dir", str(run_dir)])
            self.assertEqual(status, 2, error)
            self.assertFalse(json.loads(output)["valid"])


class RestoredScriptSmokeTests(unittest.TestCase):
    def test_every_restored_evaluator_and_generator_compiles_and_has_help(self) -> None:
        evaluator_exclusions = {"evaluate_cve_intelligence_intake.py", "evaluate_recipe_routing.py"}
        generator_exclusions = {"generate_agent_evidence_bundle.py", "generate_zero_day_recipes.py"}
        evaluators = sorted(
            path for path in (REPO_ROOT / "scripts").glob("evaluate_*.py") if path.name not in evaluator_exclusions
        )
        generators = sorted(
            path for path in (REPO_ROOT / "scripts").glob("generate_*.py") if path.name not in generator_exclusions
        )
        self.assertEqual(len(evaluators), 33)
        self.assertEqual(len(generators), 56)
        self.assertFalse((REPO_ROOT / "scripts" / "generate_cve_recipes_from_ghad.py").exists())

        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        for script in [*evaluators, *generators]:
            with self.subTest(script=script.name):
                source = script.read_text(encoding="utf-8-sig")
                compile(source, str(script), "exec")
                completed = subprocess.run(
                    [sys.executable, str(script), "--help"],
                    cwd=REPO_ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("usage:", completed.stdout.lower())

if __name__ == "__main__":
    unittest.main()
