from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
SHEPHERD_WORKFLOW = ROOT / ".github" / "workflows" / "automation-shepherd.yml"
VALIDATE_WORKFLOW = ROOT / ".github" / "workflows" / "cve-catalog-validate.yml"
FIXTURES = ROOT / "tests" / "fixtures" / "exact_sha_build_status"
MUTANTS_ROOT = FIXTURES / "mutants"
GH_STUB = FIXTURES / "gh_stub.py"
MANIFEST = FIXTURES / "mutants.json"

HEAD_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
MAIN_SHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
OTHER_SHA = "cccccccccccccccccccccccccccccccccccccccc"
PR_NUMBER = "480"
PR_BRANCH = "automation/content-refresh-ir-si-monitor-isolation"


@dataclass(frozen=True)
class WorkflowPaths:
    shepherd: Path
    validate: Path


CONTROL = WorkflowPaths(shepherd=SHEPHERD_WORKFLOW, validate=VALIDATE_WORKFLOW)


@dataclass
class CommandResult:
    completed: subprocess.CompletedProcess[str]
    calls: list[dict[str, Any]]


def step_run(workflow_path: Path, job_id: str, step_name: str) -> str:
    document = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    jobs = document.get("jobs") if isinstance(document, dict) else None
    if not isinstance(jobs, dict):
        raise AssertionError(f"{workflow_path}: missing jobs")
    job = jobs.get(job_id)
    if not isinstance(job, dict):
        raise AssertionError(f"{workflow_path}: missing job {job_id}")
    for step in job.get("steps") or []:
        if isinstance(step, dict) and step.get("name") == step_name:
            run = step.get("run")
            if not isinstance(run, str) or not run.strip():
                raise AssertionError(f"{workflow_path}: {job_id}/{step_name} has no run script")
            return run
    raise AssertionError(f"{workflow_path}: missing step {job_id}/{step_name}")


def catalog_pr(*, head_sha: str = HEAD_SHA) -> dict[str, Any]:
    return {
        "number": int(PR_NUMBER),
        "isCrossRepository": False,
        "autoMergeRequest": {"enabledAt": "2026-11-11T19:06:16Z"},
        "mergeStateStatus": "CLEAN",
        "headRefName": PR_BRANCH,
        "headRefOid": head_sha,
    }


def default_scenario(**overrides: Any) -> dict[str, Any]:
    scenario = {
        "pr_list": [catalog_pr()],
        "run_list": [],
        "check_runs_by_sha": {HEAD_SHA: {"check_runs": []}},
        "combined_status_by_sha": {HEAD_SHA: {"statuses": []}},
        "workflow_run_exit": 0,
        "status_post_exit": 0,
    }
    scenario.update(overrides)
    return scenario


def run_bash(
    script: str,
    *,
    env: dict[str, str],
    extra_path: Path,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, encoding="utf-8") as handle:
        handle.write(script)
        script_path = Path(handle.name)
    try:
        full_env = os.environ.copy()
        full_env.update(env)
        full_env["PATH"] = str(extra_path) + os.pathsep + full_env.get("PATH", "")
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script_path)],
            cwd=cwd or ROOT,
            env=full_env,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    finally:
        script_path.unlink(missing_ok=True)


def run_with_gh_stub(
    script: str,
    *,
    scenario: dict[str, Any],
    env: dict[str, str],
    cwd: Path | None = None,
) -> CommandResult:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        stub_dir = tmp_path / "bin"
        stub_dir.mkdir()
        stub_path = stub_dir / "gh"
        shutil.copy(GH_STUB, stub_path)
        stub_path.chmod(stub_path.stat().st_mode | stat.S_IEXEC)
        log_path = tmp_path / "gh-log.json"
        scenario_path = tmp_path / "scenario.json"
        log_path.write_text("[]\n", encoding="utf-8")
        scenario_path.write_text(json.dumps(scenario, indent=2) + "\n", encoding="utf-8")
        merged_env = {
            "GH_STUB_LOG": str(log_path),
            "GH_STUB_SCENARIO": str(scenario_path),
            "GH_TOKEN": "stub-token-not-for-echo",
            "GH_REPO": "stevologic/security-recipes.ai",
            "GITHUB_REPOSITORY": "stevologic/security-recipes.ai",
            "GITHUB_DEFAULT_BRANCH": "main",
            "GITHUB_RUN_ID": "111",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_SHA": MAIN_SHA,
        }
        merged_env.update(env)
        completed = run_bash(script, env=merged_env, extra_path=stub_dir, cwd=cwd)
        calls = json.loads(log_path.read_text(encoding="utf-8"))
        if not isinstance(calls, list):
            raise AssertionError("gh stub log is not a list")
        return CommandResult(completed=completed, calls=calls)


def workflow_run_calls(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [call for call in calls if call.get("positionals", [None])[0] == "workflow" and "run" in call.get("positionals", [])]


def status_post_calls(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    posted = []
    for call in calls:
        if call.get("positionals", [None])[0] != "api":
            continue
        if call.get("method") != "POST":
            continue
        path = next((item for item in call.get("positionals", []) if "/statuses/" in str(item)), "")
        if path:
            posted.append(call)
    return posted


def status_post_sha(call: dict[str, Any]) -> str:
    path = next(item for item in call.get("positionals", []) if "/statuses/" in str(item))
    return str(path).rsplit("/statuses/", 1)[1]


def assert_dispatch_carries_pr_head_sha(paths: WorkflowPaths) -> None:
    script = step_run(paths.shepherd, "shepherd", "Shepherd auto-merge pull requests")
    result = run_with_gh_stub(script, scenario=default_scenario(), env={})
    if result.completed.returncode != 0:
        raise AssertionError(
            "shepherd dispatch step failed:\n"
            f"{result.completed.stdout}\n{result.completed.stderr}"
        )
    dispatched = workflow_run_calls(result.calls)
    if len(dispatched) != 1:
        raise AssertionError(f"expected one validation dispatch, got {dispatched!r}")
    argv = dispatched[0]["argv"]
    if "cve-catalog-validate.yml" not in argv:
        raise AssertionError(f"dispatch targeted the wrong workflow: {argv!r}")
    if "--ref" not in argv or argv[argv.index("--ref") + 1] != "main":
        raise AssertionError(f"workflow code must come from the default branch: {argv!r}")
    fields = dispatched[0]["fields"]
    if fields.get("expected_sha") != HEAD_SHA:
        raise AssertionError(f"dispatch did not carry the PR head SHA: {fields!r}")
    if fields.get("pr_number") != PR_NUMBER:
        raise AssertionError(f"dispatch did not carry the PR number: {fields!r}")
    if fields.get("expected_branch") != PR_BRANCH:
        raise AssertionError(f"dispatch did not carry the PR branch: {fields!r}")


def assert_status_posted_to_head_sha_not_main(paths: WorkflowPaths) -> None:
    script = step_run(paths.validate, "publish-build-status", "Publish the build status on the validated SHA")
    result = run_with_gh_stub(
        script,
        scenario=default_scenario(),
        env={
            "EXPECTED_SHA": HEAD_SHA,
            "VALIDATE_RESULT": "success",
            "GITHUB_SHA": MAIN_SHA,
        },
    )
    if result.completed.returncode != 0:
        raise AssertionError(
            "publish step failed:\n"
            f"{result.completed.stdout}\n{result.completed.stderr}"
        )
    posted = status_post_calls(result.calls)
    if len(posted) != 1:
        raise AssertionError(f"expected one status post, got {posted!r}")
    sha = status_post_sha(posted[0])
    if sha != HEAD_SHA:
        raise AssertionError(f"status posted to {sha}, expected PR head {HEAD_SHA}")
    if MAIN_SHA in json.dumps(posted[0]["argv"]):
        raise AssertionError(f"status post mentioned main SHA {MAIN_SHA}: {posted[0]['argv']!r}")
    if posted[0]["fields"].get("context") != "build":
        raise AssertionError(f"posted context {posted[0]['fields']!r}, expected build")
    if posted[0]["fields"].get("state") != "success":
        raise AssertionError(f"posted state {posted[0]['fields']!r}, expected success")


def assert_dedupe_skips_in_flight_heads(paths: WorkflowPaths) -> None:
    script = step_run(paths.shepherd, "shepherd", "Shepherd auto-merge pull requests")
    result = run_with_gh_stub(
        script,
        scenario=default_scenario(
            run_list=[
                {
                    "displayTitle": f"CVE catalog validation shepherd-99-1-{PR_NUMBER} @ {HEAD_SHA}",
                    "status": "in_progress",
                }
            ]
        ),
        env={},
    )
    if result.completed.returncode != 0:
        raise AssertionError(
            "shepherd dedupe step failed:\n"
            f"{result.completed.stdout}\n{result.completed.stderr}"
        )
    dispatched = workflow_run_calls(result.calls)
    if dispatched:
        raise AssertionError(f"in-flight head was re-dispatched: {dispatched!r}")
    combined = result.completed.stdout + result.completed.stderr
    if "already running" not in combined:
        raise AssertionError(f"expected in-flight skip message, got:\n{combined}")


def assert_publish_missing_sha_fails_closed(paths: WorkflowPaths) -> None:
    script = step_run(paths.validate, "publish-build-status", "Publish the build status on the validated SHA")
    result = run_with_gh_stub(
        script,
        scenario=default_scenario(),
        env={
            "EXPECTED_SHA": "",
            "VALIDATE_RESULT": "success",
            "GITHUB_SHA": MAIN_SHA,
        },
    )
    if result.completed.returncode == 0:
        raise AssertionError("publish must fail closed on a missing SHA")
    posted = status_post_calls(result.calls)
    if posted:
        raise AssertionError(f"missing SHA still posted a status: {posted!r}")


def assert_shepherd_missing_sha_fails_closed(paths: WorkflowPaths) -> None:
    script = step_run(paths.shepherd, "shepherd", "Shepherd auto-merge pull requests")
    result = run_with_gh_stub(
        script,
        scenario=default_scenario(pr_list=[catalog_pr(head_sha="")]),
        env={},
    )
    if result.completed.returncode != 0:
        raise AssertionError(
            "shepherd should skip a bad SHA without aborting the rest of the pass:\n"
            f"{result.completed.stdout}\n{result.completed.stderr}"
        )
    dispatched = workflow_run_calls(result.calls)
    if dispatched:
        raise AssertionError(f"missing SHA still dispatched validation: {dispatched!r}")
    combined = result.completed.stdout + result.completed.stderr
    if "missing or invalid head SHA" not in combined:
        raise AssertionError(f"expected fail-closed error, got:\n{combined}")


def assert_validate_reject_missing_sha(paths: WorkflowPaths) -> None:
    script = step_run(paths.validate, "validate", "Reject a missing or invalid exact SHA")
    result = run_with_gh_stub(script, scenario=default_scenario(), env={"EXPECTED_SHA": ""})
    if result.completed.returncode == 0:
        raise AssertionError("validate must fail closed on a missing SHA before checkout")


def assert_wrong_context_is_not_build(paths: WorkflowPaths) -> None:
    # Used as a mutant-killing probe: control posts context=build.
    assert_status_posted_to_head_sha_not_main(paths)


BEHAVIORS: dict[str, Callable[[WorkflowPaths], None]] = {
    "test_dispatch_carries_pr_head_sha": assert_dispatch_carries_pr_head_sha,
    "test_status_is_posted_to_head_sha_not_main": assert_status_posted_to_head_sha_not_main,
    "test_dedupe_skips_in_flight_heads": assert_dedupe_skips_in_flight_heads,
    "test_publish_missing_sha_fails_closed": assert_publish_missing_sha_fails_closed,
    "test_shepherd_missing_sha_fails_closed": assert_shepherd_missing_sha_fails_closed,
    "test_validate_reject_missing_sha": assert_validate_reject_missing_sha,
    "test_status_uses_build_context": assert_wrong_context_is_not_build,
}


class ExactShaBuildStatusControlTests(unittest.TestCase):
    def test_dispatch_carries_pr_head_sha(self) -> None:
        assert_dispatch_carries_pr_head_sha(CONTROL)

    def test_status_is_posted_to_head_sha_not_main(self) -> None:
        assert_status_posted_to_head_sha_not_main(CONTROL)

    def test_dedupe_skips_in_flight_heads(self) -> None:
        assert_dedupe_skips_in_flight_heads(CONTROL)

    def test_publish_missing_sha_fails_closed(self) -> None:
        assert_publish_missing_sha_fails_closed(CONTROL)

    def test_shepherd_missing_sha_fails_closed(self) -> None:
        assert_shepherd_missing_sha_fails_closed(CONTROL)

    def test_validate_reject_missing_sha(self) -> None:
        assert_validate_reject_missing_sha(CONTROL)

    def test_failed_validation_posts_failure_on_the_head_sha(self) -> None:
        script = step_run(
            CONTROL.validate,
            "publish-build-status",
            "Publish the build status on the validated SHA",
        )
        result = run_with_gh_stub(
            script,
            scenario=default_scenario(),
            env={
                "EXPECTED_SHA": HEAD_SHA,
                "VALIDATE_RESULT": "failure",
                "GITHUB_SHA": MAIN_SHA,
            },
        )
        self.assertEqual(result.completed.returncode, 0, result.completed.stderr)
        posted = status_post_calls(result.calls)
        self.assertEqual(len(posted), 1)
        self.assertEqual(status_post_sha(posted[0]), HEAD_SHA)
        self.assertEqual(posted[0]["fields"].get("state"), "failure")
        self.assertEqual(posted[0]["fields"].get("context"), "build")

    def test_prove_step_fails_closed_when_checkout_does_not_match(self) -> None:
        script = step_run(
            CONTROL.validate,
            "validate",
            "Prove validation is attached to the requested revision",
        )
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "harness@example.test"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Harness"], cwd=repo, check=True)
            (repo / "README").write_text("fixture\n", encoding="utf-8")
            subprocess.run(["git", "add", "README"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "fixture"], cwd=repo, check=True, capture_output=True)
            actual = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repo,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            matched = run_bash(
                script,
                env={"EXPECTED_SHA": actual},
                extra_path=Path("/usr/bin"),
                cwd=repo,
            )
            self.assertEqual(matched.returncode, 0, matched.stderr)
            mismatched = run_bash(
                script,
                env={"EXPECTED_SHA": OTHER_SHA},
                extra_path=Path("/usr/bin"),
                cwd=repo,
            )
            self.assertNotEqual(mismatched.returncode, 0)
            missing = run_bash(
                script,
                env={"EXPECTED_SHA": ""},
                extra_path=Path("/usr/bin"),
                cwd=repo,
            )
            self.assertNotEqual(missing.returncode, 0)


class ExactShaBuildStatusMutantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        if not isinstance(cls.manifest, list) or not cls.manifest:
            raise AssertionError(f"{MANIFEST} must list on-disk mutants")

    def test_control_is_green_before_mutants_are_judged(self) -> None:
        for name, behavior in BEHAVIORS.items():
            with self.subTest(control=name):
                behavior(CONTROL)

    def test_each_on_disk_mutant_is_killed_by_its_named_test(self) -> None:
        rows = []
        for mutant in self.manifest:
            mutant_id = mutant["id"]
            killing_name = mutant["killing_test"]
            behavior = BEHAVIORS[killing_name]
            mutated = WorkflowPaths(
                shepherd=MUTANTS_ROOT / mutant_id / "automation-shepherd.yml",
                validate=MUTANTS_ROOT / mutant_id / "cve-catalog-validate.yml",
            )
            self.assertTrue(mutated.shepherd.is_file(), mutated.shepherd)
            self.assertTrue(mutated.validate.is_file(), mutated.validate)
            with self.subTest(mutant=mutant_id, killing_test=killing_name):
                try:
                    behavior(mutated)
                except AssertionError as killed:
                    rows.append(
                        {
                            "id": mutant_id,
                            "file": mutant["file"],
                            "killing_test": killing_name,
                            "expected": mutant["expected"],
                            "actual": str(killed),
                        }
                    )
                    continue
                self.fail(
                    f"{mutant_id} survived {killing_name}; expected {mutant['expected']}"
                )
        self.assertEqual(len(rows), len(self.manifest), rows)

    def test_mutants_are_surgical_edits_of_the_real_workflow_files(self) -> None:
        for mutant in self.manifest:
            mutant_id = mutant["id"]
            relative = mutant["file"].split(":", 1)[0]
            original = ROOT / relative
            mutated = MUTANTS_ROOT / mutant_id / Path(relative).name
            original_text = original.read_text(encoding="utf-8")
            mutated_text = mutated.read_text(encoding="utf-8")
            self.assertNotEqual(original_text, mutated_text, mutant_id)
            sibling = (
                MUTANTS_ROOT / mutant_id / "cve-catalog-validate.yml"
                if relative.endswith("automation-shepherd.yml")
                else MUTANTS_ROOT / mutant_id / "automation-shepherd.yml"
            )
            control_sibling = (
                VALIDATE_WORKFLOW if sibling.name == "cve-catalog-validate.yml" else SHEPHERD_WORKFLOW
            )
            self.assertEqual(
                sibling.read_text(encoding="utf-8"),
                control_sibling.read_text(encoding="utf-8"),
                f"{mutant_id} must leave the unmutated workflow identical to control",
            )


if __name__ == "__main__":
    unittest.main()
