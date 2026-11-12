"""Run CVE catalog merge-job shell steps with `gh` stubbed."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "cve-catalog-sync.yml"
DETECT_STEP = "Detect GitHub App automation credentials"
REQUIRE_STEP = "Require GitHub App credentials"
MINT_STEP = "Mint CVE automation GitHub App token"
ATTRIBUTE_STEP = "Attribute catalog revision to the GitHub App"
DELIVERY_STEP = "Reconcile, validate, and merge exact catalog revision"
STUB_SOURCE = Path(__file__).resolve().parent / "cve_sync_gh_stub.py"
FALLBACK_LABEL = "automation:protection-fallback"
CATALOG_BRANCH = "automation/cve-catalog-sync"
DEFAULT_REPO = "stevologic/security-recipes.ai"


@dataclass
class HarnessResult:
    returncode: int
    stdout: str
    stderr: str
    stage: str
    outputs: dict[str, str] = field(default_factory=dict)
    detect_outputs: dict[str, str] = field(default_factory=dict)
    github_output: str = ""
    workflow_runs: list[dict[str, Any]] = field(default_factory=list)
    merge_calls: list[dict[str, Any]] = field(default_factory=list)
    labels_added: list[str] = field(default_factory=list)
    gh_calls: list[dict[str, Any]] = field(default_factory=list)
    mint_calls: list[dict[str, Any]] = field(default_factory=list)
    attribute_calls: list[dict[str, Any]] = field(default_factory=list)
    expected_sha: str = ""
    head_sha: str = ""
    base_sha: str = ""

    @property
    def dispatched_validate(self) -> bool:
        return any(
            run.get("workflow") == "cve-catalog-validate.yml" for run in self.workflow_runs
        )

    @property
    def dispatch_ref(self) -> str:
        for run in self.workflow_runs:
            if run.get("workflow") == "cve-catalog-validate.yml":
                return str(run.get("ref") or "")
        return ""

    @property
    def dispatch_expected_sha(self) -> str:
        for run in self.workflow_runs:
            if run.get("workflow") == "cve-catalog-validate.yml":
                fields = run.get("fields") or {}
                if isinstance(fields, dict):
                    return str(fields.get("expected_sha") or "")
        return ""

    @property
    def dispatch_token(self) -> str:
        for run in self.workflow_runs:
            if run.get("workflow") == "cve-catalog-validate.yml":
                return str(run.get("token") or "")
        return ""


def load_workflow(path: Path | None = None) -> str:
    return (path or WORKFLOW_PATH).read_text(encoding="utf-8")


def merge_job_steps(workflow: str) -> list[dict[str, Any]]:
    document = yaml.safe_load(workflow)
    steps = document["jobs"]["merge"]["steps"]
    if not isinstance(steps, list):
        raise AssertionError("merge job has no steps")
    return [step for step in steps if isinstance(step, dict)]


def step_named(workflow: str, name: str) -> dict[str, Any]:
    for step in merge_job_steps(workflow):
        if step.get("name") == name:
            return step
    raise AssertionError(f"workflow step not found: {name}")


def step_script(workflow: str, name: str) -> str:
    script = step_named(workflow, name).get("run")
    if not isinstance(script, str) or not script.strip():
        raise AssertionError(f"{name} has no run script")
    return script


def parse_github_output(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def should_run_step_if(condition: object, *, app_configured: bool) -> bool:
    if condition is None:
        return True
    text = str(condition)
    if "app_configured == 'true'" in text or 'app_configured == "true"' in text:
        return app_configured
    if "app_configured != 'true'" in text:
        return not app_configured
    return True


def github_or_expr(expr: str, values: dict[str, str]) -> str:
    body = expr.strip()
    if body.startswith("${{") and body.endswith("}}"):
        body = body[3:-2].strip()
    for piece in body.split("||"):
        key = piece.strip()
        value = values.get(key, "")
        if value:
            return value
    return ""


def resolve_expected_sha(
    workflow: str,
    *,
    app_configured: bool,
    app_commit_sha: str,
    sync_head_sha: str,
) -> str:
    env = step_named(workflow, DELIVERY_STEP).get("env")
    if not isinstance(env, dict):
        raise AssertionError("catalog-delivery env is missing")
    expr = str(env.get("EXPECTED_SHA") or "")
    app_value = app_commit_sha if app_configured else ""
    return github_or_expr(
        expr,
        {
            "steps.app-commit.outputs.head_sha": app_value,
            "needs.sync.outputs.head_sha": sync_head_sha,
        },
    )


def _write_executable(path: Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def build_bin_dir(tmp: Path) -> Path:
    bin_dir = tmp / "bin"
    bin_dir.mkdir()
    _write_executable(
        bin_dir / "gh",
        "#!/usr/bin/env python3\n"
        "import runpy\n"
        f"runpy.run_path({str(STUB_SOURCE)!r}, run_name='__main__')\n",
    )
    _write_executable(bin_dir / "sleep", "#!/bin/sh\nexit 0\n")
    python_src = Path(os.environ.get("CVE_SYNC_HARNESS_PYTHON") or shutil.which("python3") or "")
    if not python_src.exists():
        raise AssertionError("python3 is required for the merge-job harness")
    (bin_dir / "python").symlink_to(python_src)
    (bin_dir / "python3").symlink_to(python_src)
    return bin_dir


def init_catalog_repo(path: Path) -> tuple[str, str]:
    path.mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "harness@example.test"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "CVE Harness"], cwd=path, check=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=path, check=True)
    catalog = path / "static" / "api" / "cve-catalog"
    catalog.mkdir(parents=True)
    (catalog / "index.json").write_text("{}\n", encoding="utf-8")
    subprocess.run(["git", "add", "static/api/cve-catalog/index.json"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "base catalog"], cwd=path, check=True)
    base_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()
    (catalog / "index.json").write_text('{"n":1}\n', encoding="utf-8")
    subprocess.run(["git", "add", "static/api/cve-catalog/index.json"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "catalog head"], cwd=path, check=True)
    head_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()
    scripts_dst = path / "scripts"
    scripts_dst.mkdir()
    shutil.copy2(ROOT / "scripts" / "cve_catalog_delivery.py", scripts_dst / "cve_catalog_delivery.py")
    shutil.copy2(ROOT / "scripts" / "cve_catalog_data_paths.py", scripts_dst / "cve_catalog_data_paths.py")
    return base_sha, head_sha


def pr_payload(
    *,
    number: int,
    head_sha: str,
    base_sha: str,
    labels: list[str],
    repository: str = DEFAULT_REPO,
) -> dict[str, Any]:
    return {
        "number": number,
        "state": "open",
        "merged": False,
        "user": {"login": "github-actions[bot]"},
        "head": {
            "sha": head_sha,
            "ref": CATALOG_BRANCH,
            "repo": {"full_name": repository},
        },
        "base": {"sha": base_sha, "ref": "main"},
        "labels": [{"name": name} for name in labels],
        "html_url": f"https://github.com/{repository}/pull/{number}",
    }


def fallback_events(labeled_at: str) -> list[dict[str, Any]]:
    if not labeled_at:
        return []
    return [
        {
            "event": "labeled",
            "label": {"name": FALLBACK_LABEL},
            "created_at": labeled_at,
        }
    ]


def _run_bash(
    script: str,
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-eo", "pipefail", "-c", script],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def run_merge_job(
    workflow: str,
    *,
    app_id: str = "",
    app_private_key: str = "",
    app_token: str = "",
    github_token: str = "github-token",
    auto_merge_enabled: str = "true",
    labels: list[str] | None = None,
    labeled_at: str = "",
    pr_number: int = 475,
    timeout: int = 45,
) -> HarnessResult:
    label_names = list(labels or [])
    with tempfile.TemporaryDirectory(prefix="cve-sync-harness-") as tmp_raw:
        tmp = Path(tmp_raw)
        bin_dir = build_bin_dir(tmp)
        repo = tmp / "repo"
        base_sha, head_sha = init_catalog_repo(repo)
        output_path = tmp / "github_output"
        output_path.write_text("", encoding="utf-8")
        summary_path = tmp / "step_summary"
        summary_path.write_text("", encoding="utf-8")
        state_path = tmp / "gh-state.json"
        log_path = tmp / "gh.jsonl"
        log_path.write_text("", encoding="utf-8")
        path = f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"
        base_env = {
            "PATH": path,
            "HOME": str(tmp),
            "TERM": "dumb",
            "LANG": "C.UTF-8",
            "TZ": "UTC",
            "GH_STUB_STATE": str(state_path),
            "GH_STUB_LOG": str(log_path),
            "GITHUB_OUTPUT": str(output_path),
            "GITHUB_STEP_SUMMARY": str(summary_path),
            "GITHUB_REPOSITORY": DEFAULT_REPO,
            "GITHUB_RUN_ID": "555001",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_DEFAULT_BRANCH": "main",
        }
        detect_env = dict(base_env)
        detect_env["APP_ID"] = app_id
        detect_env["APP_PRIVATE_KEY"] = app_private_key
        detect = _run_bash(
            step_script(workflow, DETECT_STEP),
            cwd=repo,
            env=detect_env,
            timeout=timeout,
        )
        detect_outputs = parse_github_output(output_path.read_text(encoding="utf-8"))
        if detect.returncode != 0:
            return HarnessResult(
                returncode=detect.returncode,
                stdout=detect.stdout,
                stderr=detect.stderr,
                stage="detect",
                detect_outputs=detect_outputs,
                outputs=detect_outputs,
                github_output=output_path.read_text(encoding="utf-8"),
                head_sha=head_sha,
                base_sha=base_sha,
            )
        app_configured = detect_outputs.get("app_configured") == "true"
        if detect_outputs.get("app_configured") != "true":
            require_env = dict(base_env)
            require_env["CREDENTIAL_STATUS"] = detect_outputs.get("credential_status", "")
            require = _run_bash(
                step_script(workflow, REQUIRE_STEP),
                cwd=repo,
                env=require_env,
                timeout=timeout,
            )
            combined_out = detect.stdout + require.stdout
            combined_err = detect.stderr + require.stderr
            if require.returncode != 0:
                return HarnessResult(
                    returncode=require.returncode,
                    stdout=combined_out,
                    stderr=combined_err,
                    stage="require",
                    detect_outputs=detect_outputs,
                    outputs=parse_github_output(output_path.read_text(encoding="utf-8")),
                    github_output=output_path.read_text(encoding="utf-8"),
                    head_sha=head_sha,
                    base_sha=base_sha,
                )
        else:
            combined_out = detect.stdout
            combined_err = detect.stderr
        expected_sha = resolve_expected_sha(
            workflow,
            app_configured=app_configured,
            app_commit_sha=head_sha,
            sync_head_sha=head_sha,
        )
        state = {
            "pr": pr_payload(
                number=pr_number,
                head_sha=head_sha,
                base_sha=base_sha,
                labels=label_names,
            ),
            "events": fallback_events(labeled_at),
            "labels_added": [],
            "workflow_runs": [],
            "merge_calls": [],
            "mint_calls": [],
            "attribute_calls": [],
            "update_branch_calls": [],
            "calls": [],
            "compare_status": "ahead",
            "merge_sha": head_sha,
        }
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        marker_env = dict(base_env)
        marker_env["GH_TOKEN"] = github_token
        mint_step = step_named(workflow, MINT_STEP)
        if should_run_step_if(mint_step.get("if"), app_configured=app_configured):
            _run_bash("gh app-token mint", cwd=repo, env=marker_env, timeout=timeout)
        attribute_step = step_named(workflow, ATTRIBUTE_STEP)
        if should_run_step_if(attribute_step.get("if"), app_configured=app_configured):
            _run_bash("gh app-token attribute", cwd=repo, env=marker_env, timeout=timeout)
        delivery_env = dict(base_env)
        delivery_env.update(
            {
                "APP_CONFIGURED": "true" if app_configured else "false",
                "AUTO_MERGE_ENABLED": auto_merge_enabled,
                "BRANCH": CATALOG_BRANCH,
                "EXPECTED_SHA": expected_sha,
                "APP_TOKEN": app_token,
                "GH_TOKEN": github_token,
                "PR_NUMBER": str(pr_number),
            }
        )
        delivery = _run_bash(
            step_script(workflow, DELIVERY_STEP),
            cwd=repo,
            env=delivery_env,
            timeout=timeout,
        )
        final_state = json.loads(state_path.read_text(encoding="utf-8"))
        github_output = output_path.read_text(encoding="utf-8")
        return HarnessResult(
            returncode=delivery.returncode,
            stdout=combined_out + delivery.stdout,
            stderr=combined_err + delivery.stderr,
            stage="delivery",
            detect_outputs=detect_outputs,
            outputs=parse_github_output(github_output),
            github_output=github_output,
            workflow_runs=list(final_state.get("workflow_runs") or []),
            merge_calls=list(final_state.get("merge_calls") or []),
            mint_calls=list(final_state.get("mint_calls") or []),
            attribute_calls=list(final_state.get("attribute_calls") or []),
            labels_added=list(final_state.get("labels_added") or []),
            gh_calls=list(final_state.get("calls") or []),
            expected_sha=expected_sha,
            head_sha=head_sha,
            base_sha=base_sha,
        )
