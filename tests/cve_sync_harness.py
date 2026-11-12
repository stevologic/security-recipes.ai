"""Run CVE catalog merge-job shell steps with `gh` stubbed.

Step environments come from that step's (and the merge job's) YAML `env:`
block. `${{ }}` expressions are rendered from the fixture contexts
`secrets.*`, `steps.<id>.outputs.*`, `needs.*.outputs.*`, `vars.*`, and
`github.*`. Unknown expressions fail loudly. The harness does not inject
workflow env defaults; it only adds runner plumbing such as PATH, HOME,
and GITHUB_OUTPUT.
"""

from __future__ import annotations

import json
import os
import re
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
ALLOWED_EXPR_ROOTS = frozenset({"secrets", "steps", "needs", "vars", "github"})
EXPR_RE = re.compile(r"\$\{\{\s*(.+?)\s*\}\}")
EXPR_PATH_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*)+$"
)
RUNNER_PLUMBING_KEYS = frozenset(
    {
        "PATH",
        "HOME",
        "TERM",
        "LANG",
        "TZ",
        "GH_STUB_STATE",
        "GH_STUB_LOG",
        "GITHUB_OUTPUT",
        "GITHUB_STEP_SUMMARY",
        "GITHUB_REPOSITORY",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
    }
)


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


def merge_job(workflow: str) -> dict[str, Any]:
    document = yaml.safe_load(workflow)
    job = document["jobs"]["merge"]
    if not isinstance(job, dict):
        raise AssertionError("merge job is missing")
    return job


def stringify_yaml_env_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    raise AssertionError(f"unsupported env value type: {type(value).__name__}")


def lookup_context_path(path: str, ctx: dict[str, Any]) -> str:
    parts = path.split(".")
    node: Any = ctx
    for index, part in enumerate(parts):
        if not isinstance(node, dict) or part not in node:
            if (
                parts[0] == "steps"
                and len(parts) == 4
                and index == 3
                and parts[2] == "outputs"
                and isinstance(node, dict)
            ):
                return ""
            raise AssertionError(f"unresolved GitHub expression: {path}")
        node = node[part]
    if isinstance(node, dict):
        raise AssertionError(f"unresolved GitHub expression: {path}")
    if node is None:
        return ""
    if isinstance(node, bool):
        return "true" if node else "false"
    return str(node)


def evaluate_github_term(piece: str, ctx: dict[str, Any]) -> str:
    if len(piece) >= 2 and piece[0] == piece[-1] and piece[0] in {"'", '"'}:
        return piece[1:-1]
    if not EXPR_PATH_RE.fullmatch(piece):
        raise AssertionError(f"unresolved GitHub expression: {piece!r}")
    root = piece.split(".", 1)[0]
    if root not in ALLOWED_EXPR_ROOTS:
        raise AssertionError(f"unresolved GitHub expression: {piece!r}")
    return lookup_context_path(piece, ctx)


def evaluate_github_expr(body: str, ctx: dict[str, Any]) -> str:
    body = body.strip()
    if not body:
        raise AssertionError("unresolved GitHub expression: empty")
    pieces = [piece.strip() for piece in body.split("||")]
    if not pieces or any(not piece for piece in pieces):
        raise AssertionError(f"unresolved GitHub expression: {body!r}")
    last = ""
    for piece in pieces:
        last = evaluate_github_term(piece, ctx)
        if last:
            return last
    return last


def render_github_value(raw: str, ctx: dict[str, Any]) -> str:
    if "${{" not in raw:
        return raw

    def repl(match: re.Match[str]) -> str:
        return evaluate_github_expr(match.group(1), ctx)

    rendered = EXPR_RE.sub(repl, raw)
    if "${{" in rendered:
        raise AssertionError(f"unresolved GitHub expression: {raw!r}")
    return rendered


def render_env_mapping(
    raw: object, ctx: dict[str, Any], *, source: str
) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise AssertionError(f"{source} env is not a mapping")
    rendered: dict[str, str] = {}
    for key, value in raw.items():
        rendered[str(key)] = render_github_value(stringify_yaml_env_value(value), ctx)
    return rendered


def empty_step_outputs(workflow: str) -> dict[str, Any]:
    steps: dict[str, Any] = {}
    for step in merge_job_steps(workflow):
        step_id = step.get("id")
        if isinstance(step_id, str) and step_id:
            steps[step_id] = {"outputs": {}}
    return steps


def apply_step_outputs(
    ctx: dict[str, Any], step_id: str, outputs: dict[str, str]
) -> None:
    steps = ctx.setdefault("steps", {})
    if not isinstance(steps, dict):
        raise AssertionError("expression context steps is not a mapping")
    step = steps.setdefault(step_id, {"outputs": {}})
    if not isinstance(step, dict):
        raise AssertionError(f"expression context step {step_id} is not a mapping")
    bucket = step.setdefault("outputs", {})
    if not isinstance(bucket, dict):
        raise AssertionError(
            f"expression context step {step_id} outputs is not a mapping"
        )
    bucket.update(outputs)


def build_expression_context(
    workflow: str,
    *,
    app_id: str,
    app_private_key: str,
    github_token: str,
    auto_merge_enabled: str,
    pr_number: int,
    head_sha: str,
    github_run_id: str = "555001",
    github_run_attempt: str = "1",
    default_branch: str = "main",
    repository: str = DEFAULT_REPO,
) -> dict[str, Any]:
    owner, _, name = repository.partition("/")
    return {
        "secrets": {
            "CVE_SYNC_APP_KEY": app_private_key,
        },
        "vars": {
            "CVE_SYNC_APP_ID": app_id,
            "CVE_AUTO_MERGE_ENABLED": auto_merge_enabled,
        },
        "steps": empty_step_outputs(workflow),
        "needs": {
            "sync": {
                "outputs": {
                    "head_sha": head_sha,
                    "pr_number": str(pr_number),
                    "changed": "true",
                    "safe_to_merge": "true",
                }
            }
        },
        "github": {
            "token": github_token,
            "repository": repository,
            "repository_owner": owner,
            "run_id": github_run_id,
            "run_attempt": github_run_attempt,
            "event": {
                "repository": {
                    "name": name or repository,
                    "full_name": repository,
                    "default_branch": default_branch,
                }
            },
        },
    }


def rendered_step_env(
    workflow: str,
    step_name: str,
    ctx: dict[str, Any],
    plumbing: dict[str, str],
) -> dict[str, str]:
    unexpected = sorted(key for key in plumbing if key not in RUNNER_PLUMBING_KEYS)
    if unexpected:
        raise AssertionError(
            "harness injected non-plumbing env: " + ", ".join(unexpected)
        )
    job_env = render_env_mapping(merge_job(workflow).get("env"), ctx, source="merge job")
    step_env = render_env_mapping(
        step_named(workflow, step_name).get("env"), ctx, source=step_name
    )
    return {**plumbing, **job_env, **step_env}


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
        plumbing = {
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
        }
        ctx = build_expression_context(
            workflow,
            app_id=app_id,
            app_private_key=app_private_key,
            github_token=github_token,
            auto_merge_enabled=auto_merge_enabled,
            pr_number=pr_number,
            head_sha=head_sha,
        )
        detect_env = rendered_step_env(workflow, DETECT_STEP, ctx, plumbing)
        detect = _run_bash(
            step_script(workflow, DETECT_STEP),
            cwd=repo,
            env=detect_env,
            timeout=timeout,
        )
        detect_outputs = parse_github_output(output_path.read_text(encoding="utf-8"))
        apply_step_outputs(ctx, "automation-auth", detect_outputs)
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
        require_step = step_named(workflow, REQUIRE_STEP)
        if should_run_step_if(require_step.get("if"), app_configured=app_configured):
            require_env = rendered_step_env(workflow, REQUIRE_STEP, ctx, plumbing)
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
        mint_step = step_named(workflow, MINT_STEP)
        if should_run_step_if(mint_step.get("if"), app_configured=app_configured):
            _run_bash("gh app-token mint", cwd=repo, env=plumbing, timeout=timeout)
            apply_step_outputs(ctx, "app-token", {"token": app_token})
        attribute_step = step_named(workflow, ATTRIBUTE_STEP)
        if should_run_step_if(attribute_step.get("if"), app_configured=app_configured):
            _run_bash("gh app-token attribute", cwd=repo, env=plumbing, timeout=timeout)
            apply_step_outputs(ctx, "app-commit", {"head_sha": head_sha})
        delivery_env = rendered_step_env(workflow, DELIVERY_STEP, ctx, plumbing)
        expected_sha = delivery_env.get("EXPECTED_SHA", "")
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
