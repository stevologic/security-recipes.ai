from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
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
    f"{APP_ACTOR} ",
    f"{APP_ACTOR}\u200b",
    "dependabot[bot]",
    "QA-CVE-SYNC[bot]",
    "Qa-Cve-Sync[bot]",
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


CONTROL = WorkflowPaths(shepherd=SHEPHERD_WORKFLOW, validate=VALIDATE_WORKFLOW)


@dataclass
class CommandResult:
    completed: subprocess.CompletedProcess[str]
    calls: list[dict[str, Any]]


@contextmanager
def mutant_paths(mutant_id: str) -> Iterator[WorkflowPaths]:
    with tempfile.TemporaryDirectory(prefix=f"exact-sha-mutant-{mutant_id}-") as tmp:
        dest = Path(tmp)
        shutil.copy(SHEPHERD_WORKFLOW, dest / "automation-shepherd.yml")
        shutil.copy(VALIDATE_WORKFLOW, dest / "cve-catalog-validate.yml")
        apply_edits(dest, mutant_id)
        yield WorkflowPaths(
            shepherd=dest / "automation-shepherd.yml",
            validate=dest / "cve-catalog-validate.yml",
        )


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

    def test_publish_accepts_sync_app_token_dispatch(self) -> None:
        sync = SYNC_WORKFLOW.read_text(encoding="utf-8")
        delivery = sync.split("Reconcile, validate, and merge exact catalog revision", 1)[1]
        delivery = delivery.split("\n      - name: ", 1)[0]
        self.assertIn("GH_TOKEN: ${{ steps.app-token.outputs.token }}", delivery)
        self.assertIn("gh workflow run cve-catalog-validate.yml", delivery)
        self.assertIn('--ref "$VALIDATION_REF"', delivery)
        self.assertIn('--field "expected_sha=$EXPECTED_SHA"', delivery)
        self.assertIn('--field "pr_number=$PR_NUMBER"', delivery)
        self.assertIn('--field "expected_branch=$BRANCH"', delivery)
        assert_publish_accepts_dispatch_origin(
            CONTROL,
            dispatch_ref=TRUSTED_REF,
            dispatch_actor=APP_ACTOR,
            app_slug=APP_SLUG,
            why="catalog-sync App-token dispatch on main",
        )

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


class ExactShaBuildStatusMutantKillTests(unittest.TestCase):
    def test_M1_post_on_main_is_killed(self) -> None:
        assert_killed("M1-post-on-main", assert_status_posted_to_head_sha_not_main)

    def test_M2_drop_sha_input_is_killed(self) -> None:
        assert_killed("M2-drop-sha-input", assert_dispatch_carries_pr_head_sha)

    def test_M3_drop_dedupe_is_killed(self) -> None:
        assert_killed("M3-drop-dedupe", lambda paths: assert_dedupe_skips_in_flight(paths, "in_progress"))

    def test_M4_fail_open_missing_sha_is_killed(self) -> None:
        assert_killed("M4-fail-open-missing-sha", assert_publish_missing_sha_fails_closed)

    def test_M5_wrong_context_name_is_killed(self) -> None:
        assert_killed("M5-wrong-context-name", assert_status_posted_to_head_sha_not_main)

    def test_M6_shepherd_fail_open_missing_sha_is_killed(self) -> None:
        assert_killed("M6-shepherd-fail-open-missing-sha", lambda paths: assert_shepherd_missing_sha_fails_closed(paths, ""))

    def test_K1_null_head_z_guard_is_killed(self) -> None:
        assert_killed("K1-null-head-z-guard", lambda paths: assert_shepherd_missing_sha_fails_closed(paths, "null"))

    def test_K2_unanchored_sha_regex_is_killed(self) -> None:
        assert_killed("K2-unanchored-sha-regex", lambda paths: assert_shepherd_missing_sha_fails_closed(paths, FORTY_ONE_SHA))

    def test_K3_dedupe_without_sha_is_killed(self) -> None:
        assert_killed("K3-dedupe-without-sha", assert_other_sha_inflight_does_not_block_head)

    def test_K4_drop_queued_is_killed(self) -> None:
        assert_killed("K4-drop-queued", lambda paths: assert_dedupe_skips_in_flight(paths, "queued"))

    def test_K5_assign_not_accumulate_is_killed(self) -> None:
        assert_killed("K5-assign-not-accumulate", lambda paths: assert_dedupe_skips_in_flight(paths, "in_progress"))

    def test_K6_drop_statuses_or_is_killed(self) -> None:
        assert_killed("K6-drop-statuses-or", assert_existing_build_status_skips_dispatch)

    def test_K7_pending_gt_one_is_killed(self) -> None:
        assert_killed("K7-pending-gt-one", lambda paths: assert_dedupe_skips_in_flight(paths, "in_progress"))

    def test_K8_failure_posts_success_is_killed(self) -> None:
        assert_killed("K8-failure-posts-success", lambda paths: assert_publish_maps_result(paths, "failure", "failure"))

    def test_K9_cancelled_skipped_not_mapped_is_killed(self) -> None:
        assert_killed("K9-cancelled-skipped-unmapped", lambda paths: assert_publish_maps_result(paths, "cancelled", "failure"))

    def test_K10_unknown_posts_success_is_killed(self) -> None:
        assert_killed("K10-unknown-posts-success", lambda paths: assert_publish_refuses_result(paths, ""))

    def test_K11_drop_target_url_is_killed(self) -> None:
        assert_killed("K11-drop-target-url", assert_status_posted_to_head_sha_not_main)

    def test_K12_hardcoded_validate_result_is_killed(self) -> None:
        assert_killed("K12-hardcoded-validate-result", lambda paths: assert_publish_maps_result(paths, "failure", "failure"))

    def test_K13_expected_sha_from_github_sha_is_killed(self) -> None:
        assert_killed("K13-expected-sha-github-sha", assert_status_posted_to_head_sha_not_main)

    def test_K14_drop_always_is_killed(self) -> None:
        assert_killed("K14-drop-always", assert_publish_job_wiring)

    def test_K15_statuses_not_write_is_killed(self) -> None:
        assert_killed("K15-statuses-not-write", assert_publish_job_wiring)

    def test_K16_kick_without_publish_is_killed(self) -> None:
        assert_killed("K16-kick-without-publish", assert_publish_job_wiring)

    def test_K17_drop_catalog_sync_filter_is_killed(self) -> None:
        assert_killed("K17-drop-catalog-sync-filter", lambda paths: assert_non_catalog_pr_does_not_dispatch(paths, CONTENT_BRANCH))

    def test_K18_prefix_catalog_filter_is_killed(self) -> None:
        assert_killed("K18-prefix-catalog-filter", lambda paths: assert_non_catalog_pr_does_not_dispatch(paths, CONTENT_BRANCH))

    def test_K19_substring_catalog_filter_is_killed(self) -> None:
        assert_killed("K19-substring-catalog-filter", lambda paths: assert_non_catalog_pr_does_not_dispatch(paths, SUBSTRING_BRANCH))

    def test_K20_drop_live_head_check_is_killed(self) -> None:
        assert_killed("K20-drop-live-head-check", assert_publish_refuses_moved_head)

    def test_B1_c_pr_number_from_run_id_is_killed(self) -> None:
        assert_killed("B1-c-pr-number-from-run-id", assert_publish_reads_named_pull)

    def test_B1_e_pulls_path_wrong_pr_is_killed(self) -> None:
        assert_killed("B1-e-pulls-path-wrong-pr", assert_publish_reads_named_pull)

    def test_K6b_drop_check_runs_or_is_killed(self) -> None:
        assert_killed("B2-K6b-drop-checkruns-or", assert_failed_build_check_run_skips_dispatch)

    def test_K6c_status_any_context_is_killed(self) -> None:
        assert_killed("B2-K6c-status-any-context", assert_non_build_status_does_not_skip_dispatch)

    def test_K6d_checkrun_any_name_is_killed(self) -> None:
        assert_killed("B2-K6d-checkrun-any-name", assert_non_build_check_run_does_not_skip_dispatch)

    def test_P_c_fork_head_is_killed(self) -> None:
        assert_killed(
            "P-c-drop-head-repo-check",
            lambda paths: assert_publish_refuses_pull(
                paths, live_pull(repo={"full_name": "evil/security-recipes.ai"}), "a fork head"
            ),
        )

    def test_P_g_missing_head_repo_is_killed(self) -> None:
        assert_killed(
            "P-g-head-repo-default-self",
            lambda paths: assert_publish_refuses_pull(paths, live_pull(repo=None), "missing head repo"),
        )

    def test_P_d_closed_pr_is_killed(self) -> None:
        assert_killed(
            "P-d-drop-state-open",
            lambda paths: assert_publish_refuses_pull(paths, live_pull(state="closed"), "closed PR"),
        )

    def test_P_e_base_not_main_is_killed(self) -> None:
        assert_killed(
            "P-e-drop-base-check",
            lambda paths: assert_publish_refuses_pull(paths, live_pull(base="release"), "base=release"),
        )

    def test_S_d_cross_repo_is_killed(self) -> None:
        assert_killed("S-d-drop-crossrepo-select", assert_shepherd_skips_cross_repository_sync_pr)

    def test_R_b_max_2_is_killed(self) -> None:
        assert_killed("R-b-max-2", lambda paths: assert_publish_retries_n_failures_then_posts(paths, 3))

    def test_R_c_max_3_is_killed(self) -> None:
        assert_killed("R-c-max-3", lambda paths: assert_publish_retries_n_failures_then_posts(paths, 3))

    def test_R_d_max_5_is_killed(self) -> None:
        assert_killed("R-d-max-5", assert_publish_gives_up_after_four_failures)

    def test_R_e_ge_to_gt_is_killed(self) -> None:
        assert_killed("R-e-ge-to-gt", assert_publish_gives_up_after_four_failures)

    def test_S_a_suffix_filter_is_killed(self) -> None:
        assert_killed(
            "S-a-suffix-filter",
            lambda paths: assert_non_catalog_pr_does_not_dispatch(paths, "x/automation/cve-catalog-sync"),
        )

    def test_S_b_prefix_of_sync_is_killed(self) -> None:
        assert_killed(
            "S-b-prefix-of-sync",
            lambda paths: assert_non_catalog_pr_does_not_dispatch(paths, "automation/cve-catalog-sync-2"),
        )

    def test_P_i_prefix_of_sync_is_killed(self) -> None:
        assert_killed(
            "P-i-publish-prefix-of-sync-both",
            lambda paths: assert_publish_refuses_non_catalog_branch(paths, "automation/cve-catalog-sync-2"),
        )

    def test_D1_drop_ref_check_is_killed(self) -> None:
        assert_killed(
            "D1-drop-ref-check",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths, dispatch_ref="refs/heads/automation/cve-catalog-sync", why="non-main ref"
            ),
        )

    def test_D2_ref_prefix_is_killed(self) -> None:
        assert_killed(
            "D2-ref-prefix",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths, dispatch_ref="refs/heads/main-x", why="main-x ref"
            ),
        )

    def test_D3_drop_actor_check_is_killed(self) -> None:
        assert_killed(
            "D3-drop-actor-check",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths, dispatch_actor="evil-bot", why="wrong actor"
            ),
        )

    def test_D4_actor_substring_is_killed(self) -> None:
        assert_killed(
            "D4-actor-substring",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths, dispatch_actor="xgithub-actions[bot]", why="substring actor"
            ),
        )

    def test_D5_guard_exit_0_is_killed(self) -> None:
        assert_killed(
            "D5-guard-exit-0",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths, dispatch_ref="refs/heads/development", why="non-main ref"
            ),
        )

    def test_D2c_ref_suffix_main_is_killed(self) -> None:
        assert_killed(
            "D2c-ref-suffix-main",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths, dispatch_ref="refs/heads/x/main", why="refs/heads/x/main"
            ),
        )

    def test_F_lookalike_bot_is_killed(self) -> None:
        assert_killed(
            "F-lookalike-bot",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths,
                dispatch_actor=f"{APP_SLUG}-x[bot]",
                app_slug=APP_SLUG,
                why="slug-x[bot]",
            ),
        )

    def test_F_any_bot_is_killed(self) -> None:
        assert_killed(
            "F-any-bot",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths,
                dispatch_actor="dependabot[bot]",
                app_slug=APP_SLUG,
                why="dependabot[bot]",
            ),
        )

    def test_F_unset_accepts_app_is_killed(self) -> None:
        assert_killed(
            "F-unset-accepts-app",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths,
                dispatch_actor=APP_ACTOR,
                why="App actor with unset slug",
            ),
        )

    def test_F_app_on_non_main_is_killed(self) -> None:
        assert_killed(
            "F-app-on-non-main",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths,
                dispatch_ref="refs/heads/x/main",
                dispatch_actor=APP_ACTOR,
                app_slug=APP_SLUG,
                why="App actor on refs/heads/x/main",
            ),
        )

    def test_F_loosened_slug_is_killed(self) -> None:
        assert_killed(
            "F-loosened-slug",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths,
                dispatch_actor=f"x{APP_SLUG}[bot]",
                app_slug=APP_SLUG,
                why="xslug[bot]",
            ),
        )

    def test_A6_case_insensitive_app_actor_is_killed(self) -> None:
        assert_killed(
            "A6-case-insensitive-app-actor",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths,
                dispatch_actor="QA-CVE-SYNC[bot]",
                app_slug=APP_SLUG,
                why="QA-CVE-SYNC[bot]",
            ),
        )


if __name__ == "__main__":
    unittest.main()
