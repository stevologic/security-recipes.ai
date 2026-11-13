from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from tests.exact_sha_build_status_mutants import (
    EQUIVALENT_MUTANTS,
    apply_edits,
)


ROOT = Path(__file__).resolve().parents[1]
SHEPHERD_WORKFLOW = ROOT / ".github" / "workflows" / "automation-shepherd.yml"
VALIDATE_WORKFLOW = ROOT / ".github" / "workflows" / "cve-catalog-validate.yml"
SYNC_WORKFLOW = ROOT / ".github" / "workflows" / "cve-catalog-sync.yml"
FIXTURES = ROOT / "tests" / "fixtures" / "exact_sha_build_status"
GH_STUB = FIXTURES / "gh_stub.py"

HEAD_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
MAIN_SHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
OTHER_SHA = "cccccccccccccccccccccccccccccccccccccccc"
FORTY_ONE_SHA = HEAD_SHA + "a"
PR_NUMBER = "480"
SYNC_BRANCH = "automation/cve-catalog-sync"
CONTENT_BRANCH = "automation/content-refresh-ir-si-monitor-isolation"
DEPENDABOT_BRANCH = "dependabot/npm_and_yarn/main/npm-minor-and-patch-3ce9b7b435"
SUBSTRING_BRANCH = "fix/hold-cve-catalog-sync-notes"
TRUSTED_REF = "refs/heads/main"
TRUSTED_ACTOR = "github-actions[bot]"
APP_SLUG = "qa-cve-sync"
APP_ACTOR = f"{APP_SLUG}[bot]"
REPO_FULL_NAME = "stevologic/security-recipes.ai"
LOOKALIKE_REFS = (
    "refs/heads/main-x",
    "refs/heads/mainline",
    "refs/heads/x/main",
    "refs/tags/main",
)
LOOKALIKE_APP_ACTORS = (
    f"{APP_SLUG}-x[bot]",
    f"x{APP_SLUG}[bot]",
    f"{APP_SLUG}b",
    f"{APP_ACTOR} ",
    f"{APP_ACTOR}\u200b",
    "dependabot[bot]",
    "QA-CVE-SYNC[bot]",
    "Qa-Cve-Sync[bot]",
)
REGEX_WILDCARD_SLUG = ".*"
DOT_SLUG = "sync.app"
DOT_SLUG_ACTOR = "syncXapp[bot]"
DELIVERY_SCRIPT = ROOT / "scripts" / "cve_catalog_delivery.py"
GITHUB_ACTIONS_TOKEN = "ghs_github_actions"
SYNC_DELIVERY_JOB = "merge"
SYNC_DELIVERY_STEP = "Reconcile, validate, and merge exact catalog revision"
INVALID_FORMAT_SLUGS = (
    "x.sync-app",
    "sync-app.",
    "sync.app",
    "Sync-App",
    "sync_app",
    "sync app",
    "sync/app",
    ".sync-app",
    "sync-app!",
)
LOOKALIKE_BRANCHES = (
    "automation/cve-catalog-sync-2",
    "automation/cve-catalog-sync/x",
    "x/automation/cve-catalog-sync",
    "Automation/CVE-Catalog-Sync",
    "automation/cve-catalog-sync ",
    " automation/cve-catalog-sync",
    "automation/cve\u2010catalog\u2010sync",
    "automation/cve-catalog-sync\u200b",
    "refs/heads/automation/cve-catalog-sync",
    CONTENT_BRANCH,
    DEPENDABOT_BRANCH,
    SUBSTRING_BRANCH,
    "automation/",
)
IN_FLIGHT_STATUSES = ("queued", "in_progress", "pending", "waiting", "requested")
EXPR_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
UNSET = object()


@dataclass(frozen=True)
class WorkflowPaths:
    shepherd: Path
    validate: Path
    sync: Path
    delivery: Path


CONTROL = WorkflowPaths(
    shepherd=SHEPHERD_WORKFLOW,
    validate=VALIDATE_WORKFLOW,
    sync=SYNC_WORKFLOW,
    delivery=DELIVERY_SCRIPT,
)

_SCRATCH: tempfile.TemporaryDirectory[str] | None = None
_SCRATCH_FILES: dict[str, str] = {}
_SCRATCH_LOCK = threading.Lock()
_SCRATCH_SOURCES = (
    ("automation-shepherd.yml", SHEPHERD_WORKFLOW),
    ("cve-catalog-validate.yml", VALIDATE_WORKFLOW),
    ("cve-catalog-sync.yml", SYNC_WORKFLOW),
    ("cve_catalog_delivery.py", DELIVERY_SCRIPT),
)


def _ensure_scratch() -> Path:
    global _SCRATCH
    if _SCRATCH is None:
        _SCRATCH = tempfile.TemporaryDirectory(prefix="exact-sha-mutant-scratch-")
        dest = Path(_SCRATCH.name)
        for name, src in _SCRATCH_SOURCES:
            text = src.read_text(encoding="utf-8")
            (dest / name).write_text(text, encoding="utf-8")
            _SCRATCH_FILES[name] = text
    return Path(_SCRATCH.name)


def _reset_scratch() -> Path:
    dest = _ensure_scratch()
    for name, text in _SCRATCH_FILES.items():
        (dest / name).write_text(text, encoding="utf-8")
    return dest


@dataclass
class CommandResult:
    completed: subprocess.CompletedProcess[str]
    calls: list[dict[str, Any]]


@contextmanager
def mutant_paths(mutant_id: str) -> Iterator[WorkflowPaths]:
    with _SCRATCH_LOCK:
        dest = _reset_scratch()
        apply_edits(dest, mutant_id)
        try:
            yield WorkflowPaths(
                shepherd=dest / "automation-shepherd.yml",
                validate=dest / "cve-catalog-validate.yml",
                sync=dest / "cve-catalog-sync.yml",
                delivery=dest / "cve_catalog_delivery.py",
            )
        finally:
            _reset_scratch()


def lookup_context(expr: str, context: dict[str, Any]) -> str:
    current: Any = context
    for part in expr.split("."):
        if not isinstance(current, dict) or part not in current:
            return ""
        current = current[part]
    if current is None:
        return ""
    return str(current)


def render_expression(template: str, context: dict[str, Any]) -> str:
    def replace(match: re.Match[str]) -> str:
        expr = match.group(1).strip()
        if "||" in expr:
            left, right = expr.split("||", 1)
            value = lookup_context(left.strip(), context)
            if value:
                return value
            return right.strip().strip("'\"")
        return lookup_context(expr, context)

    return EXPR_RE.sub(replace, template)


def jobs_document(path: Path) -> dict[str, Any]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    jobs = document.get("jobs") if isinstance(document, dict) else None
    if not isinstance(jobs, dict):
        raise AssertionError(f"{path}: missing jobs")
    return jobs


def named_step(path: Path, job_id: str, step_name: str) -> dict[str, Any]:
    job = jobs_document(path).get(job_id)
    if not isinstance(job, dict):
        raise AssertionError(f"{path}: missing job {job_id}")
    for step in job.get("steps") or []:
        if isinstance(step, dict) and step.get("name") == step_name:
            return step
    raise AssertionError(f"{path}: missing step {job_id}/{step_name}")


def rendered_step_env(step: dict[str, Any], context: dict[str, Any]) -> dict[str, str]:
    raw = step.get("env") or {}
    if not isinstance(raw, dict):
        return {}
    return {str(key): render_expression(str(value), context) for key, value in raw.items()}


def gha_context(
    *,
    expected_sha: str = HEAD_SHA,
    validate_result: str = "success",
    expected_branch: str = SYNC_BRANCH,
    pr_number: str = PR_NUMBER,
    ref: str = TRUSTED_REF,
    actor: str = TRUSTED_ACTOR,
    app_slug: str | None = None,
) -> dict[str, Any]:
    variables: dict[str, Any] = {}
    if app_slug:
        variables["CVE_SYNC_APP_SLUG"] = app_slug
    return {
        "inputs": {
            "expected_sha": expected_sha,
            "request_id": f"shepherd-111-1-{pr_number}",
            "pr_number": pr_number,
            "expected_branch": expected_branch,
        },
        "needs": {"validate": {"result": validate_result}},
        "vars": variables,
        "github": {
            "sha": MAIN_SHA,
            "token": "stub-token-not-for-echo",
            "repository": REPO_FULL_NAME,
            "run_id": "111",
            "run_attempt": "1",
            "ref": ref,
            "actor": actor,
            "workflow_ref": f"{REPO_FULL_NAME}/.github/workflows/cve-catalog-validate.yml@{ref}",
            "event": {"repository": {"default_branch": "main"}},
        },
    }


def platform_env(context: dict[str, Any]) -> dict[str, str]:
    github = context["github"]
    return {
        "GITHUB_SHA": str(github["sha"]),
        "GITHUB_REPOSITORY": str(github["repository"]),
        "GITHUB_RUN_ID": str(github["run_id"]),
        "GITHUB_RUN_ATTEMPT": str(github["run_attempt"]),
        "GITHUB_SERVER_URL": "https://github.com",
    }


def catalog_pr(
    *,
    head_sha: str = HEAD_SHA,
    branch: str = SYNC_BRANCH,
    number: str = PR_NUMBER,
    is_cross_repository: bool = False,
) -> dict[str, Any]:
    return {
        "number": int(number),
        "isCrossRepository": is_cross_repository,
        "autoMergeRequest": {"enabledAt": "2026-11-11T19:06:16Z"},
        "mergeStateStatus": "CLEAN",
        "headRefName": branch,
        "headRefOid": head_sha,
    }


def live_pull(
    *,
    head_sha: str = HEAD_SHA,
    branch: str = SYNC_BRANCH,
    state: str = "open",
    repo: Any = UNSET,
    base: str = "main",
) -> dict[str, Any]:
    head: dict[str, Any] = {"sha": head_sha, "ref": branch}
    if repo is UNSET:
        head["repo"] = {"full_name": REPO_FULL_NAME}
    else:
        head["repo"] = repo
    return {
        "state": state,
        "head": head,
        "base": {"ref": base},
    }


def default_scenario(**overrides: Any) -> dict[str, Any]:
    scenario = {
        "pr_list": [catalog_pr()],
        "run_list": [],
        "check_runs_by_sha": {HEAD_SHA: {"check_runs": []}},
        "combined_status_by_sha": {HEAD_SHA: {"statuses": []}},
        "repo": {"default_branch": "main"},
        "pull": live_pull(),
        "pull_number": PR_NUMBER,
        "workflow_run_exit": 0,
        "status_post_exit": 0,
        "status_post_failures": 0,
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
            timeout=30,
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
        sleep_stub = stub_dir / "sleep"
        sleep_stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        sleep_stub.chmod(sleep_stub.stat().st_mode | stat.S_IEXEC)
        log_path = tmp_path / "gh-log.json"
        scenario_path = tmp_path / "scenario.json"
        log_path.write_text("[]\n", encoding="utf-8")
        scenario_path.write_text(json.dumps(scenario, indent=2) + "\n", encoding="utf-8")
        merged_env = {
            "GH_STUB_LOG": str(log_path),
            "GH_STUB_SCENARIO": str(scenario_path),
        }
        merged_env.update(env)
        completed = run_bash(script, env=merged_env, extra_path=stub_dir, cwd=cwd)
        calls = json.loads(log_path.read_text(encoding="utf-8"))
        if not isinstance(calls, list):
            raise AssertionError("gh stub log is not a list")
        return CommandResult(completed=completed, calls=calls)


def run_named_step(
    paths: WorkflowPaths,
    which: str,
    job_id: str,
    step_name: str,
    *,
    context: dict[str, Any],
    scenario: dict[str, Any],
    cwd: Path | None = None,
) -> CommandResult:
    workflow = paths.validate if which == "validate" else paths.shepherd
    step = named_step(workflow, job_id, step_name)
    run = step.get("run")
    if not isinstance(run, str) or not run.strip():
        raise AssertionError(f"{workflow}: {job_id}/{step_name} has no run script")
    env = platform_env(context)
    env.update(rendered_step_env(step, context))
    return run_with_gh_stub(run, scenario=scenario, env=env, cwd=cwd)


def workflow_run_calls(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        call
        for call in calls
        if call.get("positionals", [None])[0] == "workflow" and "run" in call.get("positionals", [])
    ]


def dispatched_shas(calls: list[dict[str, Any]]) -> list[str]:
    return [call["fields"].get("expected_sha", "") for call in workflow_run_calls(calls)]


def status_post_calls(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    posted = []
    for call in calls:
        if call.get("method") != "POST":
            continue
        if any("/statuses/" in str(item) for item in call.get("positionals", [])):
            posted.append(call)
    return posted


def status_post_sha(call: dict[str, Any]) -> str:
    path = next(item for item in call.get("positionals", []) if "/statuses/" in str(item))
    return str(path).rsplit("/statuses/", 1)[1]


def inflight_run(status: str, sha: str = HEAD_SHA) -> dict[str, str]:
    return {
        "displayTitle": f"CVE catalog validation shepherd-99-1-{PR_NUMBER} @ {sha}",
        "status": status,
    }


def run_shepherd(paths: WorkflowPaths, scenario: dict[str, Any]) -> CommandResult:
    return run_named_step(
        paths,
        "shepherd",
        "shepherd",
        "Shepherd auto-merge pull requests",
        context=gha_context(),
        scenario=scenario,
    )


def run_publish(
    paths: WorkflowPaths,
    *,
    validate_result: str = "success",
    expected_sha: str = HEAD_SHA,
    expected_branch: str = SYNC_BRANCH,
    dispatch_ref: str = TRUSTED_REF,
    dispatch_actor: str = TRUSTED_ACTOR,
    app_slug: str | None = None,
    scenario: dict[str, Any] | None = None,
) -> CommandResult:
    context = gha_context(
        expected_sha=expected_sha,
        validate_result=validate_result,
        expected_branch=expected_branch,
        ref=dispatch_ref,
        actor=dispatch_actor,
        app_slug=app_slug,
    )
    return run_named_step(
        paths,
        "validate",
        "publish-build-status",
        "Publish the build status on the validated SHA",
        context=context,
        scenario=scenario or default_scenario(pull=live_pull(head_sha=expected_sha, branch=expected_branch)),
    )


def pull_get_paths(calls: list[dict[str, Any]]) -> list[str]:
    return [
        str(item)
        for call in calls
        for item in call.get("positionals", [])
        if "/pulls/" in str(item)
    ]


def assert_dispatch_carries_pr_head_sha(paths: WorkflowPaths) -> None:
    result = run_shepherd(paths, default_scenario())
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
    if fields.get("expected_branch") != SYNC_BRANCH:
        raise AssertionError(f"dispatch did not bind catalog-sync: {fields!r}")


def assert_status_posted_to_head_sha_not_main(paths: WorkflowPaths) -> None:
    result = run_publish(paths)
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
    if MAIN_SHA in str(posted[0]["argv"]):
        raise AssertionError(f"status post mentioned main SHA {MAIN_SHA}: {posted[0]['argv']!r}")
    if posted[0]["fields"].get("context") != "build":
        raise AssertionError(f"posted context {posted[0]['fields']!r}, expected build")
    if posted[0]["fields"].get("state") != "success":
        raise AssertionError(f"posted state {posted[0]['fields']!r}, expected success")
    target = posted[0]["fields"].get("target_url", "")
    if "111" not in target:
        raise AssertionError(f"missing target_url run link: {posted[0]['fields']!r}")


def assert_dedupe_skips_in_flight(paths: WorkflowPaths, status: str) -> None:
    result = run_shepherd(paths, default_scenario(run_list=[inflight_run(status)]))
    if result.completed.returncode != 0:
        raise AssertionError(
            "shepherd dedupe step failed:\n"
            f"{result.completed.stdout}\n{result.completed.stderr}"
        )
    if workflow_run_calls(result.calls):
        raise AssertionError(f"{status} in-flight head was re-dispatched: {dispatched_shas(result.calls)!r}")


def assert_other_sha_inflight_does_not_block_head(paths: WorkflowPaths) -> None:
    result = run_shepherd(paths, default_scenario(run_list=[inflight_run("in_progress", OTHER_SHA)]))
    if result.completed.returncode != 0:
        raise AssertionError(result.completed.stderr)
    shas = dispatched_shas(result.calls)
    if shas != [HEAD_SHA]:
        raise AssertionError(f"other-SHA in-flight should not block HEAD, got {shas!r}")


def assert_existing_build_status_skips_dispatch(paths: WorkflowPaths) -> None:
    result = run_shepherd(
        paths,
        default_scenario(
            check_runs_by_sha={HEAD_SHA: {"check_runs": []}},
            combined_status_by_sha={HEAD_SHA: {"statuses": [{"context": "build", "state": "success"}]}},
        ),
    )
    if result.completed.returncode != 0:
        raise AssertionError(result.completed.stderr)
    if workflow_run_calls(result.calls):
        raise AssertionError(f"existing build status still dispatched: {dispatched_shas(result.calls)!r}")


def assert_publish_missing_sha_fails_closed(paths: WorkflowPaths) -> None:
    result = run_publish(
        paths,
        expected_sha="",
        scenario=default_scenario(pull=live_pull(head_sha="")),
    )
    if result.completed.returncode == 0:
        raise AssertionError("publish must fail closed on a missing SHA")
    if status_post_calls(result.calls):
        raise AssertionError(f"missing SHA still posted a status: {status_post_calls(result.calls)!r}")


def assert_shepherd_missing_sha_fails_closed(paths: WorkflowPaths, head_sha: str) -> None:
    result = run_shepherd(paths, default_scenario(pr_list=[catalog_pr(head_sha=head_sha)]))
    if result.completed.returncode != 0:
        raise AssertionError(
            "shepherd should skip a bad SHA without aborting the rest of the pass:\n"
            f"{result.completed.stdout}\n{result.completed.stderr}"
        )
    if workflow_run_calls(result.calls):
        raise AssertionError(f"invalid head {head_sha!r} still dispatched: {dispatched_shas(result.calls)!r}")


def assert_validate_reject_missing_sha(paths: WorkflowPaths) -> None:
    result = run_named_step(
        paths,
        "validate",
        "validate",
        "Reject a missing or invalid exact SHA",
        context=gha_context(expected_sha=""),
        scenario=default_scenario(),
    )
    if result.completed.returncode == 0:
        raise AssertionError("validate must fail closed on a missing SHA before checkout")


def assert_publish_maps_result(paths: WorkflowPaths, validate_result: str, expected_state: str) -> None:
    result = run_publish(paths, validate_result=validate_result)
    if result.completed.returncode != 0:
        raise AssertionError(
            f"publish should post {expected_state} for {validate_result!r}:\n"
            f"{result.completed.stdout}\n{result.completed.stderr}"
        )
    posted = status_post_calls(result.calls)
    if len(posted) != 1:
        raise AssertionError(f"expected one status post for {validate_result!r}, got {posted!r}")
    if posted[0]["fields"].get("state") != expected_state:
        raise AssertionError(
            f"{validate_result!r} posted {posted[0]['fields']!r}, expected state={expected_state}"
        )
    if status_post_sha(posted[0]) != HEAD_SHA:
        raise AssertionError(f"mapped status landed on {status_post_sha(posted[0])}")


def assert_publish_refuses_result(paths: WorkflowPaths, validate_result: str) -> None:
    result = run_publish(paths, validate_result=validate_result)
    if result.completed.returncode == 0:
        raise AssertionError(f"publish must fail closed on result {validate_result!r}")
    if status_post_calls(result.calls):
        raise AssertionError(
            f"result {validate_result!r} still posted: {status_post_calls(result.calls)!r}"
        )


def assert_non_catalog_pr_does_not_dispatch(paths: WorkflowPaths, branch: str) -> None:
    result = run_shepherd(paths, default_scenario(pr_list=[catalog_pr(branch=branch)]))
    if result.completed.returncode != 0:
        raise AssertionError(result.completed.stderr)
    if workflow_run_calls(result.calls):
        raise AssertionError(f"{branch} received a self-posted build dispatch: {dispatched_shas(result.calls)!r}")


def assert_publish_refuses_non_catalog_branch(paths: WorkflowPaths, branch: str) -> None:
    result = run_publish(
        paths,
        expected_branch=branch,
        scenario=default_scenario(pull=live_pull(head_sha=HEAD_SHA, branch=branch)),
    )
    if result.completed.returncode == 0:
        raise AssertionError(f"publish must refuse a self-posted build for {branch}")
    if status_post_calls(result.calls):
        raise AssertionError(f"{branch} still received a self-posted build: {status_post_calls(result.calls)!r}")


def assert_publish_refuses_moved_head(paths: WorkflowPaths) -> None:
    result = run_publish(paths, scenario=default_scenario(pull=live_pull(head_sha=OTHER_SHA)))
    if result.completed.returncode == 0:
        raise AssertionError("publish must refuse when the live PR head no longer owns the SHA")
    if status_post_calls(result.calls):
        raise AssertionError("moved head still received a build status")


def assert_publish_retries_transient_post_failure(paths: WorkflowPaths) -> None:
    result = run_publish(paths, scenario=default_scenario(status_post_failures=1))
    if result.completed.returncode != 0:
        raise AssertionError(
            "publish should retry a transient status POST:\n"
            f"{result.completed.stdout}\n{result.completed.stderr}"
        )
    posted = status_post_calls(result.calls)
    if len(posted) < 2:
        raise AssertionError(f"expected a retried POST, got {posted!r}")
    if posted[-1]["fields"].get("state") != "success":
        raise AssertionError(f"retried POST was not success: {posted[-1]['fields']!r}")


def assert_publish_job_wiring(paths: WorkflowPaths) -> None:
    jobs = jobs_document(paths.validate)
    publish = jobs["publish-build-status"]
    kick = jobs["kick-shepherd"]
    if publish.get("if") != "always() && github.event_name == 'workflow_dispatch'":
        raise AssertionError(f"publish if is {publish.get('if')!r}")
    if publish.get("needs") != ["validate"]:
        raise AssertionError(f"publish needs {publish.get('needs')!r}")
    permissions = publish.get("permissions") or {}
    if permissions.get("statuses") != "write":
        raise AssertionError(f"publish permissions {permissions!r}")
    if "publish-build-status" not in (kick.get("needs") or []):
        raise AssertionError(f"kick needs {kick.get('needs')!r}")
    step = named_step(paths.validate, "publish-build-status", "Publish the build status on the validated SHA")
    env = rendered_step_env(step, gha_context())
    if env.get("DISPATCH_REF") != TRUSTED_REF:
        raise AssertionError(f"DISPATCH_REF YAML env is {env.get('DISPATCH_REF')!r}")
    if env.get("DISPATCH_ACTOR") != TRUSTED_ACTOR:
        raise AssertionError(f"DISPATCH_ACTOR YAML env is {env.get('DISPATCH_ACTOR')!r}")
    if env.get("PR_NUMBER") != PR_NUMBER:
        raise AssertionError(f"PR_NUMBER YAML env is {env.get('PR_NUMBER')!r}")
    if env.get("CVE_SYNC_APP_SLUG") != "":
        raise AssertionError(
            f"unset CVE_SYNC_APP_SLUG YAML env is {env.get('CVE_SYNC_APP_SLUG')!r}"
        )
    app_env = rendered_step_env(step, gha_context(app_slug=APP_SLUG))
    if app_env.get("CVE_SYNC_APP_SLUG") != APP_SLUG:
        raise AssertionError(f"CVE_SYNC_APP_SLUG YAML env is {app_env.get('CVE_SYNC_APP_SLUG')!r}")


def assert_publish_reads_named_pull(paths: WorkflowPaths) -> None:
    result = run_publish(paths)
    if result.completed.returncode != 0:
        raise AssertionError(
            "publish should read the named PR:\n"
            f"{result.completed.stdout}\n{result.completed.stderr}"
        )
    paths_hit = pull_get_paths(result.calls)
    expected = f"repos/{REPO_FULL_NAME}/pulls/{PR_NUMBER}"
    if paths_hit != [expected]:
        raise AssertionError(f"publish GET pulls path {paths_hit!r}, expected {[expected]!r}")
    if not status_post_calls(result.calls):
        raise AssertionError("canonical PR GET succeeded but no status was posted")


def assert_failed_build_check_run_skips_dispatch(paths: WorkflowPaths) -> None:
    result = run_shepherd(
        paths,
        default_scenario(
            check_runs_by_sha={
                HEAD_SHA: {"check_runs": [{"name": "build", "conclusion": "failure"}]}
            },
            combined_status_by_sha={HEAD_SHA: {"statuses": []}},
        ),
    )
    if result.completed.returncode != 0:
        raise AssertionError(result.completed.stderr)
    if workflow_run_calls(result.calls):
        raise AssertionError(
            f"failed build check run still dispatched: {dispatched_shas(result.calls)!r}"
        )


def assert_non_build_status_does_not_skip_dispatch(paths: WorkflowPaths) -> None:
    result = run_shepherd(
        paths,
        default_scenario(
            combined_status_by_sha={
                HEAD_SHA: {"statuses": [{"context": "karen-qa", "state": "success"}]}
            }
        ),
    )
    if result.completed.returncode != 0:
        raise AssertionError(result.completed.stderr)
    if dispatched_shas(result.calls) != [HEAD_SHA]:
        raise AssertionError(
            f"a lone karen-qa status must not count as build, got {dispatched_shas(result.calls)!r}"
        )


def assert_non_build_check_run_does_not_skip_dispatch(paths: WorkflowPaths) -> None:
    result = run_shepherd(
        paths,
        default_scenario(
            check_runs_by_sha={
                HEAD_SHA: {"check_runs": [{"name": "CodeQL", "conclusion": "success"}]}
            }
        ),
    )
    if result.completed.returncode != 0:
        raise AssertionError(result.completed.stderr)
    if dispatched_shas(result.calls) != [HEAD_SHA]:
        raise AssertionError(
            f"a lone CodeQL check run must not count as build, got {dispatched_shas(result.calls)!r}"
        )


def assert_publish_refuses_pull(paths: WorkflowPaths, pull: dict[str, Any], why: str) -> None:
    result = run_publish(paths, scenario=default_scenario(pull=pull))
    if result.completed.returncode == 0:
        raise AssertionError(f"publish must refuse {why}")
    if status_post_calls(result.calls):
        raise AssertionError(f"{why} still received a build status: {status_post_calls(result.calls)!r}")


def assert_shepherd_skips_cross_repository_sync_pr(paths: WorkflowPaths) -> None:
    result = run_shepherd(
        paths,
        default_scenario(pr_list=[catalog_pr(is_cross_repository=True)]),
    )
    if result.completed.returncode != 0:
        raise AssertionError(result.completed.stderr)
    if workflow_run_calls(result.calls):
        raise AssertionError(
            f"cross-repo catalog-sync PR was dispatched: {dispatched_shas(result.calls)!r}"
        )


def assert_publish_retries_n_failures_then_posts(paths: WorkflowPaths, failures: int) -> None:
    result = run_publish(paths, scenario=default_scenario(status_post_failures=failures))
    if result.completed.returncode != 0:
        raise AssertionError(
            f"publish should post after {failures} transient POST failures:\n"
            f"{result.completed.stdout}\n{result.completed.stderr}"
        )
    posted = status_post_calls(result.calls)
    expected_attempts = failures + 1
    if len(posted) != expected_attempts:
        raise AssertionError(
            f"{failures} failures should take {expected_attempts} POSTs, got {len(posted)}"
        )
    if posted[-1]["fields"].get("state") != "success":
        raise AssertionError(f"final POST was not success: {posted[-1]['fields']!r}")


def assert_publish_gives_up_after_four_failures(paths: WorkflowPaths) -> None:
    result = run_publish(paths, scenario=default_scenario(status_post_failures=4))
    posted = status_post_calls(result.calls)
    if result.completed.returncode == 0:
        raise AssertionError("publish must exit 1 after 4 POST failures")
    if len(posted) != 4:
        raise AssertionError(f"expected exactly 4 POST attempts, got {len(posted)}: {posted!r}")


def assert_publish_refuses_dispatch_origin(
    paths: WorkflowPaths,
    *,
    dispatch_ref: str = TRUSTED_REF,
    dispatch_actor: str = TRUSTED_ACTOR,
    app_slug: str | None = None,
    why: str,
) -> None:
    result = run_publish(
        paths,
        dispatch_ref=dispatch_ref,
        dispatch_actor=dispatch_actor,
        app_slug=app_slug,
    )
    if result.completed.returncode == 0:
        raise AssertionError(f"publish must refuse {why}")
    if status_post_calls(result.calls):
        raise AssertionError(f"{why} still posted a build status")


def assert_publish_accepts_dispatch_origin(
    paths: WorkflowPaths,
    *,
    dispatch_ref: str = TRUSTED_REF,
    dispatch_actor: str = TRUSTED_ACTOR,
    app_slug: str | None = None,
    why: str,
) -> None:
    result = run_publish(
        paths,
        dispatch_ref=dispatch_ref,
        dispatch_actor=dispatch_actor,
        app_slug=app_slug,
    )
    if result.completed.returncode != 0:
        raise AssertionError(
            f"publish must accept {why}:\n{result.completed.stdout}\n{result.completed.stderr}"
        )
    posted = status_post_calls(result.calls)
    if len(posted) != 1 or posted[0]["fields"].get("context") != "build":
        raise AssertionError(f"{why} did not post build: {posted!r}")


def catalog_delivery_step(sync_path: Path) -> str:
    sync = sync_path.read_text(encoding="utf-8")
    delivery = sync.split("Reconcile, validate, and merge exact catalog revision", 1)[1]
    return delivery.split("\n      - name: ", 1)[0]


def app_token_value(app_slug: str = APP_SLUG) -> str:
    return f"ghs_app_{app_slug}"


def sync_delivery_context(*, app_path: bool, app_slug: str = APP_SLUG) -> dict[str, Any]:
    return {
        "inputs": {},
        "vars": {"CVE_AUTO_MERGE_ENABLED": "false"},
        "needs": {
            "sync": {"outputs": {"head_sha": HEAD_SHA, "pr_number": PR_NUMBER}},
            "validate": {"result": "success"},
        },
        "steps": {
            "automation-auth": {"outputs": {"app_configured": "true" if app_path else "false"}},
            "app-token": {"outputs": {"token": app_token_value(app_slug) if app_path else ""}},
            "app-commit": {"outputs": {"head_sha": HEAD_SHA}},
        },
        "github": {
            "sha": MAIN_SHA,
            "token": GITHUB_ACTIONS_TOKEN,
            "repository": REPO_FULL_NAME,
            "repository_owner": "stevologic",
            "run_id": "111",
            "run_attempt": "1",
            "ref": TRUSTED_REF,
            "actor": TRUSTED_ACTOR,
            "event": {"repository": {"default_branch": "main", "name": "security-recipes.ai"}},
        },
    }


def extract_validation_dispatch_fragment(run_script: str) -> str:
    needle = 'VALIDATION_REF="$(python scripts/cve_catalog_delivery.py validation-ref'
    start = run_script.find(needle)
    if start < 0:
        raise AssertionError("delivery step does not assign VALIDATION_REF from validation-ref")
    close = run_script.find(')"', start)
    if close < 0:
        raise AssertionError("validation-ref assignment is unterminated")
    assignment = run_script[start : close + 2]
    gh_start = run_script.find("gh workflow run cve-catalog-validate.yml", start)
    if gh_start < 0:
        raise AssertionError("delivery step does not dispatch cve-catalog-validate.yml")
    gh_lines: list[str] = []
    for line in run_script[gh_start:].splitlines():
        gh_lines.append(line)
        if not line.rstrip().endswith("\\"):
            break
    return f"{assignment}\n" + "\n".join(gh_lines) + "\n"


def actor_from_dispatched_token(token: str, *, app_slug: str = APP_SLUG) -> str:
    if token == app_token_value(app_slug):
        return f"{app_slug}[bot]"
    if token == GITHUB_ACTIONS_TOKEN:
        return TRUSTED_ACTOR
    raise AssertionError(f"cannot derive actor from dispatched token {token!r}")


@dataclass(frozen=True)
class CapturedSyncDispatch:
    ref: str
    token: str
    actor: str


def capture_sync_validate_dispatch(paths: WorkflowPaths, *, app_path: bool) -> CapturedSyncDispatch:
    step = named_step(paths.sync, SYNC_DELIVERY_JOB, SYNC_DELIVERY_STEP)
    run_script = step.get("run")
    if not isinstance(run_script, str) or not run_script.strip():
        raise AssertionError("catalog delivery step has no run script")
    fragment = extract_validation_dispatch_fragment(run_script)
    fragment = fragment.replace(
        "python scripts/cve_catalog_delivery.py",
        f"{shlex.quote(sys.executable)} {shlex.quote(str(paths.delivery))}",
        1,
    )
    context = sync_delivery_context(app_path=app_path)
    env = platform_env(context)
    env.update(rendered_step_env(step, context))
    env["DATA_ONLY"] = "true"
    env["PYTHONPATH"] = str(ROOT)
    if not app_path:
        env["GH_TOKEN"] = GITHUB_ACTIONS_TOKEN
    result = run_with_gh_stub(fragment, scenario=default_scenario(), env=env, cwd=ROOT)
    if result.completed.returncode != 0:
        raise AssertionError(
            "sync validation dispatch fragment failed:\n"
            f"{result.completed.stdout}\n{result.completed.stderr}"
        )
    dispatched = [
        call
        for call in workflow_run_calls(result.calls)
        if "cve-catalog-validate.yml" in call.get("argv", [])
    ]
    if len(dispatched) != 1:
        raise AssertionError(f"expected one validate dispatch, got {dispatched!r}")
    argv = dispatched[0]["argv"]
    if "--ref" not in argv:
        raise AssertionError(f"dispatch omitted --ref: {argv!r}")
    ref = argv[argv.index("--ref") + 1]
    token = str(dispatched[0].get("gh_token") or "")
    return CapturedSyncDispatch(ref=ref, token=token, actor=actor_from_dispatched_token(token))


def assert_sync_dispatch_accepted_on_main(paths: WorkflowPaths, *, app_path: bool) -> None:
    captured = capture_sync_validate_dispatch(paths, app_path=app_path)
    expected_actor = APP_ACTOR if app_path else TRUSTED_ACTOR
    if captured.actor != expected_actor:
        raise AssertionError(
            f"derived actor {captured.actor!r} for app_path={app_path}, expected {expected_actor!r}"
        )
    if captured.ref != "main":
        raise AssertionError(f"dispatch --ref is {captured.ref!r}, expected main")
    assert_publish_accepts_dispatch_origin(
        paths,
        dispatch_ref=f"refs/heads/{captured.ref}",
        dispatch_actor=captured.actor,
        app_slug=APP_SLUG if app_path else None,
        why=f"captured sync dispatch app_path={app_path} ref={captured.ref} actor={captured.actor}",
    )


def assert_sync_dispatch_forced_to_sync_branch_refused(
    paths: WorkflowPaths, *, app_path: bool
) -> None:
    captured = capture_sync_validate_dispatch(paths, app_path=app_path)
    assert_publish_refuses_dispatch_origin(
        paths,
        dispatch_ref=f"refs/heads/{SYNC_BRANCH}",
        dispatch_actor=captured.actor,
        app_slug=APP_SLUG if app_path else None,
        why=f"forced sync-branch dispatch app_path={app_path} actor={captured.actor}",
    )


def assert_invalid_format_slugs_refused(paths: WorkflowPaths) -> None:
    for slug in INVALID_FORMAT_SLUGS:
        assert_publish_refuses_dispatch_origin(
            paths,
            dispatch_actor=TRUSTED_ACTOR,
            app_slug=slug,
            why=f"invalid slug {slug!r} with github-actions[bot]",
        )


def assert_valid_slug_with_actions_bot_posts_once(paths: WorkflowPaths) -> None:
    result = run_publish(paths, dispatch_actor=TRUSTED_ACTOR, app_slug=APP_SLUG)
    if result.completed.returncode != 0:
        raise AssertionError(
            "valid slug with github-actions[bot] must post:\n"
            f"{result.completed.stdout}\n{result.completed.stderr}"
        )
    posted = status_post_calls(result.calls)
    if len(posted) != 1 or posted[0]["fields"].get("context") != "build":
        raise AssertionError(f"expected exactly 1 build post, got {posted!r}")


def run_validation_ref(delivery_script: Path, *, app_configured: bool) -> str:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    proc = subprocess.run(
        [
            sys.executable,
            str(delivery_script),
            "validation-ref",
            "--data-only",
            "true",
            "--app-configured",
            "true" if app_configured else "false",
            "--default-branch",
            "main",
            "--pr-branch",
            SYNC_BRANCH,
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"validation-ref exited {proc.returncode}:\n{proc.stdout}\n{proc.stderr}"
        )
    return proc.stdout.strip()


def assert_sync_yaml_dispatches_validation_on_main(paths: WorkflowPaths) -> None:
    delivery = catalog_delivery_step(paths.sync)
    if "gh workflow run cve-catalog-validate.yml" not in delivery:
        raise AssertionError("catalog-delivery does not dispatch cve-catalog-validate.yml")
    if '--ref "$VALIDATION_REF"' not in delivery:
        raise AssertionError(f"dispatch ref is not VALIDATION_REF:\n{delivery}")
    if '--ref "$BRANCH"' in delivery:
        raise AssertionError("dispatch still uses the PR branch as --ref")
    if '--field "expected_sha=$EXPECTED_SHA"' not in delivery:
        raise AssertionError("dispatch does not pass the PR head SHA as expected_sha")
    if "python scripts/cve_catalog_delivery.py validation-ref" not in delivery:
        raise AssertionError("VALIDATION_REF is not taken from validation-ref")


def assert_sync_validation_ref_is_main(paths: WorkflowPaths) -> None:
    assert_sync_yaml_dispatches_validation_on_main(paths)
    for app_configured in (True, False):
        ref = run_validation_ref(paths.delivery, app_configured=app_configured)
        if ref != "main":
            raise AssertionError(
                f"validation_ref(app_configured={app_configured}) is {ref!r}, expected main"
            )
        actor = APP_ACTOR if app_configured else TRUSTED_ACTOR
        slug = APP_SLUG if app_configured else None
        assert_publish_accepts_dispatch_origin(
            paths,
            dispatch_ref=f"refs/heads/{ref}",
            dispatch_actor=actor,
            app_slug=slug,
            why=f"sync dispatch app_configured={app_configured} ref={ref} actor={actor}",
        )


def assert_killed(mutant_id: str, behavior: Callable[[WorkflowPaths], None]) -> None:
    with mutant_paths(mutant_id) as paths:
        try:
            behavior(paths)
        except AssertionError:
            return
    raise AssertionError(f"{mutant_id} survived {behavior.__name__}")


class ExactShaBuildStatusControlTests(unittest.TestCase):
    def test_dispatch_carries_pr_head_sha(self) -> None:
        assert_dispatch_carries_pr_head_sha(CONTROL)

    def test_status_is_posted_to_head_sha_not_main(self) -> None:
        assert_status_posted_to_head_sha_not_main(CONTROL)

    def test_status_uses_build_context(self) -> None:
        assert_status_posted_to_head_sha_not_main(CONTROL)

    def test_yaml_env_binds_expected_sha_from_inputs_not_github_sha(self) -> None:
        step = named_step(CONTROL.validate, "publish-build-status", "Publish the build status on the validated SHA")
        env = rendered_step_env(step, gha_context())
        self.assertEqual(env.get("EXPECTED_SHA"), HEAD_SHA)
        self.assertNotEqual(env.get("EXPECTED_SHA"), MAIN_SHA)
        self.assertEqual(env.get("VALIDATE_RESULT"), "success")

    def test_yaml_env_binds_validate_result_from_needs(self) -> None:
        step = named_step(CONTROL.validate, "publish-build-status", "Publish the build status on the validated SHA")
        env = rendered_step_env(step, gha_context(validate_result="failure"))
        self.assertEqual(env.get("VALIDATE_RESULT"), "failure")

    def test_yaml_env_binds_pr_number_from_inputs_not_run_id(self) -> None:
        step = named_step(CONTROL.validate, "publish-build-status", "Publish the build status on the validated SHA")
        env = rendered_step_env(step, gha_context())
        self.assertEqual(env.get("PR_NUMBER"), PR_NUMBER)
        self.assertNotEqual(env.get("PR_NUMBER"), "111")

    def test_yaml_env_binds_dispatch_ref_and_actor(self) -> None:
        step = named_step(CONTROL.validate, "publish-build-status", "Publish the build status on the validated SHA")
        env = rendered_step_env(
            step,
            gha_context(ref="refs/heads/development", actor="evil-bot"),
        )
        self.assertEqual(env.get("DISPATCH_REF"), "refs/heads/development")
        self.assertEqual(env.get("DISPATCH_ACTOR"), "evil-bot")

    def test_publish_gets_the_named_pr_number(self) -> None:
        assert_publish_reads_named_pull(CONTROL)

    def test_existing_build_status_without_check_run_skips_dispatch(self) -> None:
        assert_existing_build_status_skips_dispatch(CONTROL)

    def test_failed_build_check_run_without_status_skips_dispatch(self) -> None:
        assert_failed_build_check_run_skips_dispatch(CONTROL)

    def test_karen_qa_status_alone_does_not_skip_dispatch(self) -> None:
        assert_non_build_status_does_not_skip_dispatch(CONTROL)

    def test_codeql_check_run_alone_does_not_skip_dispatch(self) -> None:
        assert_non_build_check_run_does_not_skip_dispatch(CONTROL)

    def test_queued_validation_skips_dispatch(self) -> None:
        assert_dedupe_skips_in_flight(CONTROL, "queued")

    def test_in_progress_validation_skips_dispatch(self) -> None:
        assert_dedupe_skips_in_flight(CONTROL, "in_progress")

    def test_pending_validation_skips_dispatch(self) -> None:
        assert_dedupe_skips_in_flight(CONTROL, "pending")

    def test_waiting_validation_skips_dispatch(self) -> None:
        assert_dedupe_skips_in_flight(CONTROL, "waiting")

    def test_requested_validation_skips_dispatch(self) -> None:
        assert_dedupe_skips_in_flight(CONTROL, "requested")

    def test_other_sha_in_flight_does_not_block_this_head(self) -> None:
        assert_other_sha_inflight_does_not_block_head(CONTROL)

    def test_null_head_sha_fails_closed(self) -> None:
        assert_shepherd_missing_sha_fails_closed(CONTROL, "null")

    def test_empty_head_sha_fails_closed(self) -> None:
        assert_shepherd_missing_sha_fails_closed(CONTROL, "")

    def test_forty_one_hex_head_sha_fails_closed(self) -> None:
        assert_shepherd_missing_sha_fails_closed(CONTROL, FORTY_ONE_SHA)

    def test_publish_missing_sha_fails_closed(self) -> None:
        assert_publish_missing_sha_fails_closed(CONTROL)

    def test_validate_reject_missing_sha(self) -> None:
        assert_validate_reject_missing_sha(CONTROL)

    def test_success_posts_success(self) -> None:
        assert_publish_maps_result(CONTROL, "success", "success")

    def test_failure_posts_failure(self) -> None:
        assert_publish_maps_result(CONTROL, "failure", "failure")

    def test_cancelled_posts_failure(self) -> None:
        assert_publish_maps_result(CONTROL, "cancelled", "failure")

    def test_skipped_posts_failure(self) -> None:
        assert_publish_maps_result(CONTROL, "skipped", "failure")

    def test_empty_result_fails_closed(self) -> None:
        assert_publish_refuses_result(CONTROL, "")

    def test_unknown_result_fails_closed(self) -> None:
        assert_publish_refuses_result(CONTROL, "wat")

    def test_catalog_sync_pr_is_dispatched(self) -> None:
        assert_dispatch_carries_pr_head_sha(CONTROL)

    def test_dependabot_pr_is_not_dispatched(self) -> None:
        assert_non_catalog_pr_does_not_dispatch(CONTROL, DEPENDABOT_BRANCH)

    def test_content_pr_is_not_dispatched(self) -> None:
        assert_non_catalog_pr_does_not_dispatch(CONTROL, CONTENT_BRANCH)

    def test_publish_refuses_dependabot_branch(self) -> None:
        assert_publish_refuses_non_catalog_branch(CONTROL, DEPENDABOT_BRANCH)

    def test_publish_refuses_content_branch(self) -> None:
        assert_publish_refuses_non_catalog_branch(CONTROL, CONTENT_BRANCH)

    def test_publish_refuses_when_expected_branch_disagrees_with_live_sync(self) -> None:
        result = run_publish(
            CONTROL,
            expected_branch=CONTENT_BRANCH,
            scenario=default_scenario(pull=live_pull(branch=SYNC_BRANCH)),
        )
        if result.completed.returncode == 0:
            raise AssertionError("publish must refuse when expected_branch is not the live catalog-sync head")
        if status_post_calls(result.calls):
            raise AssertionError("mismatched expected_branch still posted a build status")

    def test_substring_lookalike_branch_is_not_dispatched(self) -> None:
        assert_non_catalog_pr_does_not_dispatch(CONTROL, SUBSTRING_BRANCH)

    def test_publish_refuses_when_live_head_moved(self) -> None:
        assert_publish_refuses_moved_head(CONTROL)

    def test_publish_refuses_fork_head_repository(self) -> None:
        assert_publish_refuses_pull(
            CONTROL,
            live_pull(repo={"full_name": "evil/security-recipes.ai"}),
            "a fork head repository",
        )

    def test_publish_refuses_missing_head_repository(self) -> None:
        assert_publish_refuses_pull(CONTROL, live_pull(repo=None), "a deleted/missing head repo")

    def test_publish_refuses_closed_pr(self) -> None:
        assert_publish_refuses_pull(CONTROL, live_pull(state="closed"), "a closed PR")

    def test_publish_refuses_base_not_default_branch(self) -> None:
        assert_publish_refuses_pull(CONTROL, live_pull(base="release"), "base=release")

    def test_shepherd_skips_cross_repository_catalog_sync_pr(self) -> None:
        assert_shepherd_skips_cross_repository_sync_pr(CONTROL)

    def test_shepherd_lookalike_branches_are_not_dispatched(self) -> None:
        for branch in LOOKALIKE_BRANCHES:
            with self.subTest(branch=branch):
                assert_non_catalog_pr_does_not_dispatch(CONTROL, branch)

    def test_publish_lookalike_branches_are_refused(self) -> None:
        for branch in LOOKALIKE_BRANCHES:
            with self.subTest(branch=branch):
                assert_publish_refuses_non_catalog_branch(CONTROL, branch)

    def test_publish_retries_three_failures_then_posts(self) -> None:
        assert_publish_retries_n_failures_then_posts(CONTROL, 3)

    def test_publish_gives_up_after_four_post_failures(self) -> None:
        assert_publish_gives_up_after_four_failures(CONTROL)

    def test_publish_retries_transient_status_post(self) -> None:
        assert_publish_retries_transient_post_failure(CONTROL)

    def test_publish_refuses_non_main_dispatch_ref(self) -> None:
        assert_publish_refuses_dispatch_origin(
            CONTROL,
            dispatch_ref="refs/heads/automation/cve-catalog-sync",
            why="a non-main dispatch ref",
        )

    def test_publish_refuses_main_prefix_lookalike_refs(self) -> None:
        for ref in LOOKALIKE_REFS:
            with self.subTest(ref=ref):
                assert_publish_refuses_dispatch_origin(
                    CONTROL,
                    dispatch_ref=ref,
                    why=f"dispatch ref {ref}",
                )

    def test_publish_refuses_wrong_workflow_actor(self) -> None:
        assert_publish_refuses_dispatch_origin(
            CONTROL,
            dispatch_actor="evil-bot",
            why="a non-actions actor",
        )

    def test_publish_refuses_actor_lookalikes(self) -> None:
        for actor in ("GitHub-Actions[bot]", "github-actions[bot]-extra", "xgithub-actions[bot]"):
            with self.subTest(actor=actor):
                assert_publish_refuses_dispatch_origin(
                    CONTROL,
                    dispatch_actor=actor,
                    why=f"actor {actor}",
                )

    def test_yaml_env_binds_app_slug_from_vars(self) -> None:
        step = named_step(CONTROL.validate, "publish-build-status", "Publish the build status on the validated SHA")
        env = rendered_step_env(step, gha_context())
        self.assertEqual(env.get("CVE_SYNC_APP_SLUG"), "")
        env = rendered_step_env(step, gha_context(app_slug=APP_SLUG))
        self.assertEqual(env.get("CVE_SYNC_APP_SLUG"), APP_SLUG)

    def test_sync_app_token_dispatch_is_accepted_on_main(self) -> None:
        assert_sync_dispatch_accepted_on_main(CONTROL, app_path=True)

    def test_sync_github_actions_token_dispatch_is_accepted_on_main(self) -> None:
        assert_sync_dispatch_accepted_on_main(CONTROL, app_path=False)

    def test_sync_dispatch_forced_to_sync_branch_is_refused(self) -> None:
        for app_path in (True, False):
            with self.subTest(app_path=app_path):
                assert_sync_dispatch_forced_to_sync_branch_refused(CONTROL, app_path=app_path)

    def test_publish_refuses_invalid_format_slugs_with_actions_bot(self) -> None:
        assert_invalid_format_slugs_refused(CONTROL)

    def test_publish_valid_slug_with_actions_bot_posts_once(self) -> None:
        assert_valid_slug_with_actions_bot_posts_once(CONTROL)

    def test_publish_empty_slug_with_actions_bot_posts_once(self) -> None:
        result = run_publish(CONTROL, dispatch_actor=TRUSTED_ACTOR, app_slug=None)
        self.assertEqual(result.completed.returncode, 0, result.completed.stderr)
        posted = status_post_calls(result.calls)
        self.assertEqual(len(posted), 1)
        self.assertEqual(posted[0]["fields"].get("context"), "build")

    def test_publish_keeps_actions_bot_when_app_slug_is_set(self) -> None:
        assert_publish_accepts_dispatch_origin(
            CONTROL,
            app_slug=APP_SLUG,
            why="github-actions[bot] with slug set",
        )

    def test_publish_refuses_app_actor_when_slug_unset(self) -> None:
        assert_publish_refuses_dispatch_origin(
            CONTROL,
            dispatch_actor=APP_ACTOR,
            why="App actor with unset CVE_SYNC_APP_SLUG",
        )

    def test_publish_refuses_app_actor_lookalikes(self) -> None:
        for actor in LOOKALIKE_APP_ACTORS:
            with self.subTest(actor=actor):
                assert_publish_refuses_dispatch_origin(
                    CONTROL,
                    dispatch_actor=actor,
                    app_slug=APP_SLUG,
                    why=f"lookalike App actor {actor!r}",
                )

    def test_publish_refuses_app_actor_on_non_main_refs(self) -> None:
        for ref in LOOKALIKE_REFS:
            with self.subTest(ref=ref):
                assert_publish_refuses_dispatch_origin(
                    CONTROL,
                    dispatch_ref=ref,
                    dispatch_actor=APP_ACTOR,
                    app_slug=APP_SLUG,
                    why=f"App actor on {ref}",
                )

    def test_publish_refuses_regex_wildcard_slug(self) -> None:
        assert_publish_refuses_dispatch_origin(
            CONTROL,
            dispatch_actor="evil[bot]",
            app_slug=REGEX_WILDCARD_SLUG,
            why="CVE_SYNC_APP_SLUG=.* actor evil[bot]",
        )

    def test_publish_refuses_invalid_app_slug(self) -> None:
        assert_publish_refuses_dispatch_origin(
            CONTROL,
            app_slug=REGEX_WILDCARD_SLUG,
            why="invalid CVE_SYNC_APP_SLUG=.*",
        )

    def test_publish_refuses_dot_slug_as_any_char(self) -> None:
        assert_publish_refuses_dispatch_origin(
            CONTROL,
            dispatch_actor=DOT_SLUG_ACTOR,
            app_slug=DOT_SLUG,
            why="slug sync.app actor syncXapp[bot]",
        )

    def test_equivalent_mutants_are_labeled(self) -> None:
        self.assertEqual(
            EQUIVALENT_MUTANTS,
            frozenset(
                {
                    "S-c-filter-after-dispatch-field-head",
                    "P-a-drop-expected-branch-sync-check",
                    "P-b-drop-live-branch-sync",
                    "P-f-drop-head-eq-expected-branch",
                }
            ),
        )

    def test_publish_job_wiring(self) -> None:
        assert_publish_job_wiring(CONTROL)

    def test_prove_step_fails_closed_when_checkout_does_not_match(self) -> None:
        step = named_step(CONTROL.validate, "validate", "Prove validation is attached to the requested revision")
        script = str(step["run"])
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
            matched = run_bash(script, env={"EXPECTED_SHA": actual}, extra_path=Path("/usr/bin"), cwd=repo)
            self.assertEqual(matched.returncode, 0, matched.stderr)
            mismatched = run_bash(script, env={"EXPECTED_SHA": OTHER_SHA}, extra_path=Path("/usr/bin"), cwd=repo)
            self.assertNotEqual(mismatched.returncode, 0)
            missing = run_bash(script, env={"EXPECTED_SHA": ""}, extra_path=Path("/usr/bin"), cwd=repo)
            self.assertNotEqual(missing.returncode, 0)



if __name__ == "__main__":
    unittest.main()
