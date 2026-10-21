#!/usr/bin/env python3
"""Decide whether a PR may skip karen-qa as CVE catalog data or pipeline.

Stephen's Oct 21, 2026 ruling: Karen does not review CVE refresh jobs, and
the exemption covers catalog data plus the CVE pipeline's own code. Author
does not matter. Every changed path must be on the explicit allowlist.
The gate cannot exempt itself.
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REQUIRED_CHECK_NAME = "karen-qa-or-data-only"
KAREN_QA_CONTEXT = "karen-qa"
CVE_CATALOG_SYNC_BRANCH = "automation/cve-catalog-sync"
CVE_CATALOG_SYNC_WORKFLOW = Path(".github/workflows/cve-catalog-sync.yml")
DEFAULT_BASE_BRANCH = "main"
HEAD_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# Paths the sync workflow `git add`s after writing catalog outputs.
CATALOG_SYNC_COMMIT_PATHS = (
    "static/api/cve-catalog",
    "data/cve/ai-enrichments.json",
    "data/cve/ai-generated-recipes.json",
    "content/recipes/cve",
    "data/evidence",
    "data/context/secure-context-release-pack.json",
    "data/policy/mcp-gateway-policy.json",
    "scripts/generated-output-ownership.json",
)

# Explicit pipeline files only. PR #424 did not add a Daybreak probe
# workflow, so none is listed. Do not use scripts/** or tests/**.
CVE_PIPELINE_PATHS = (
    ".github/workflows/cve-catalog-sync.yml",
    "scripts/sync_cve_catalog.py",
    "scripts/cve_ai_enrichment.py",
    "scripts/cve_ai_recipe.py",
    "scripts/cve_text_quality.py",
    "tests/test_sync_cve_catalog.py",
    "tests/test_cve_ai_enrichment.py",
    "tests/test_cve_ai_recipe.py",
    "tests/test_cve_text_quality.py",
    "tests/test_cve_sync_workflow.py",
)

# Changing the gate or its ruleset docs cannot satisfy the gate.
GATE_PATHS = (
    ".github/workflows/karen-qa-or-data-only.yml",
    "scripts/karen_qa_or_data_only.py",
    "tests/test_karen_qa_or_data_only.py",
    "tests/test_karen_qa_or_data_only_workflow.py",
)

EXEMPT_PATHS = CATALOG_SYNC_COMMIT_PATHS + CVE_PIPELINE_PATHS

_GIT_ADD_PATHS_RE = re.compile(
    r"git add -A -- \\\n(?P<body>(?:[ \t]+\S+[ \t]*\\?\n)+)"
)
_SYNC_BRANCH_RE = re.compile(r"(?m)^[ \t]+BRANCH:[ \t]+(\S+)[ \t]*$")
_SYNC_GIT_USER_RE = re.compile(r'git config user\.name "([^"]+)"')


@dataclass(frozen=True)
class KarenQaOrDataOnlyDecision:
    outcome: str
    reason: str
    status_state: str
    status_context: str = REQUIRED_CHECK_NAME
    data_only: bool = False
    exempt: bool = False

    @property
    def allowed(self) -> bool:
        return self.status_state == "success"

    @property
    def requires_karen_qa(self) -> bool:
        return not self.exempt


class KarenQaOrDataOnlyError(ValueError):
    """Raised when the evaluator cannot parse its inputs."""


def catalog_sync_commit_paths(workflow_text: str) -> tuple[str, ...]:
    """Return the catalog data paths from the sync workflow's git add set."""
    match = _GIT_ADD_PATHS_RE.search(workflow_text)
    if match is None:
        raise KarenQaOrDataOnlyError("cve-catalog-sync workflow is missing its git add path list")
    paths = []
    for raw in match.group("body").splitlines():
        path = raw.strip().rstrip("\\").strip()
        if path:
            paths.append(path)
    if not paths:
        raise KarenQaOrDataOnlyError("cve-catalog-sync git add path list is empty")
    return tuple(paths)


def catalog_sync_branch(workflow_text: str) -> str:
    match = _SYNC_BRANCH_RE.search(workflow_text)
    if match is None:
        raise KarenQaOrDataOnlyError("cve-catalog-sync workflow is missing BRANCH")
    return match.group(1)


def catalog_sync_git_user(workflow_text: str) -> str:
    match = _SYNC_GIT_USER_RE.search(workflow_text)
    if match is None:
        raise KarenQaOrDataOnlyError("cve-catalog-sync workflow is missing git user.name")
    return match.group(1)


def normalize_repo_path(path: str) -> str | None:
    if not isinstance(path, str):
        return None
    text = path.replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    if not text or text.startswith("/") or text.startswith("../"):
        return None
    parts: list[str] = []
    for part in text.split("/"):
        if part in {"", ".", ".."}:
            return None
        parts.append(part)
    return "/".join(parts)


def _is_directory_allowlist_entry(entry: str) -> bool:
    return Path(entry).suffix == ""


def _matches_allowlist_entry(normalized: str, allowed: str) -> bool:
    allowed_norm = normalize_repo_path(allowed)
    if allowed_norm is None:
        return False
    if _is_directory_allowlist_entry(allowed_norm):
        return normalized == allowed_norm or normalized.startswith(f"{allowed_norm}/")
    return normalized == allowed_norm


def is_gate_path(path: str) -> bool:
    normalized = normalize_repo_path(path)
    return normalized in GATE_PATHS if normalized is not None else False


def is_catalog_data_path(path: str, allowlist: tuple[str, ...] = CATALOG_SYNC_COMMIT_PATHS) -> bool:
    normalized = normalize_repo_path(path)
    if normalized is None or normalized in GATE_PATHS:
        return False
    return any(_matches_allowlist_entry(normalized, allowed) for allowed in allowlist)


def is_pipeline_path(path: str, allowlist: tuple[str, ...] = CVE_PIPELINE_PATHS) -> bool:
    normalized = normalize_repo_path(path)
    if normalized is None or normalized in GATE_PATHS:
        return False
    return any(_matches_allowlist_entry(normalized, allowed) for allowed in allowlist)


def is_exempt_path(
    path: str,
    *,
    catalog_allowlist: tuple[str, ...] = CATALOG_SYNC_COMMIT_PATHS,
    pipeline_allowlist: tuple[str, ...] = CVE_PIPELINE_PATHS,
) -> bool:
    return is_catalog_data_path(path, catalog_allowlist) or is_pipeline_path(path, pipeline_allowlist)


# Back-compat alias used by earlier tests.
is_data_only_catalog_path = is_catalog_data_path


def paths_from_pr_files(files: Any) -> tuple[str, ...]:
    """Collect current and previous paths from the Pull Request Files API.

    Uses ``filename`` / ``previous_filename`` / ``status`` only. Diff text
    (``patch``) is ignored. Renames and copies without a previous path, and
    any unreadable entry, are treated as non-exempt.
    """
    entries = _as_list(files)
    if not entries:
        raise KarenQaOrDataOnlyError("PR file list is empty")
    paths: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise KarenQaOrDataOnlyError("PR file list contains a non-object entry")
        filename = entry.get("filename")
        previous = entry.get("previous_filename")
        status = str(entry.get("status") or "")
        if not isinstance(filename, str) or not filename.strip():
            raise KarenQaOrDataOnlyError("PR file entry is missing filename")
        paths.append(filename)
        if status in {"renamed", "copied"}:
            if not isinstance(previous, str) or not previous.strip():
                raise KarenQaOrDataOnlyError("renamed or copied file is missing previous_filename")
            paths.append(previous)
        elif isinstance(previous, str) and previous.strip():
            paths.append(previous)
    return tuple(paths)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("check_runs", "statuses", "files"):
            nested = value.get(key)
            if isinstance(nested, list):
                return nested
        return []
    raise KarenQaOrDataOnlyError("expected a JSON array or an object wrapping a list")


def _payload_sha(entry: dict[str, Any]) -> str:
    for key in ("head_sha", "sha"):
        value = entry.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def has_successful_karen_qa(
    *,
    head_sha: str,
    statuses: Any = None,
    check_runs: Any = None,
) -> bool:
    if not HEAD_SHA_RE.fullmatch(head_sha):
        return False
    for status in _as_list(statuses):
        if not isinstance(status, dict):
            continue
        status_sha = _payload_sha(status)
        if status.get("context") == KAREN_QA_CONTEXT and status.get("state") == "success":
            if not status_sha or status_sha == head_sha:
                return True
    for run in _as_list(check_runs):
        if not isinstance(run, dict):
            continue
        run_sha = _payload_sha(run)
        if run.get("name") == KAREN_QA_CONTEXT and run.get("conclusion") == "success":
            if not run_sha or run_sha == head_sha:
                return True
    return False


def _decision(
    outcome: str,
    reason: str,
    *,
    data_only: bool = False,
    exempt: bool = False,
) -> KarenQaOrDataOnlyDecision:
    allowed = outcome in {"exempt", "data_only", "karen_qa"}
    return KarenQaOrDataOnlyDecision(
        outcome=outcome,
        reason=reason,
        status_state="success" if allowed else "failure",
        data_only=data_only,
        exempt=exempt or allowed and outcome != "karen_qa",
    )


def evaluate_karen_qa_or_data_only(
    *,
    author_login: str,
    head_branch: str,
    base_branch: str,
    repository: str,
    head_repository: str,
    head_sha: str,
    files: Any,
    statuses: Any = None,
    check_runs: Any = None,
    expected_base_branch: str = DEFAULT_BASE_BRANCH,
    extra_bot_logins: Iterable[str] = (),
    allowlist: tuple[str, ...] | None = None,
    catalog_allowlist: tuple[str, ...] = CATALOG_SYNC_COMMIT_PATHS,
    pipeline_allowlist: tuple[str, ...] = CVE_PIPELINE_PATHS,
    sync_branch: str = CVE_CATALOG_SYNC_BRANCH,
) -> KarenQaOrDataOnlyDecision:
    """Return whether this exact head may skip karen-qa or must still have it.

    ``author_login``, ``head_branch``, ``extra_bot_logins``, and
    ``sync_branch`` are accepted for CLI compatibility and ignored: the
    Oct 21, 2026 ruling no longer depends on who opened the PR.
    """
    del author_login, head_branch, extra_bot_logins, sync_branch
    if allowlist is not None:
        catalog_allowlist = allowlist
        pipeline_allowlist = ()
    if not HEAD_SHA_RE.fullmatch(head_sha or ""):
        return _decision("need_karen_qa", "head SHA is missing or not a full commit SHA")
    if base_branch != expected_base_branch:
        return _decision(
            "need_karen_qa",
            f"base branch {base_branch!r} is not {expected_base_branch!r}",
        )
    if head_repository != repository or not repository:
        return _decision("need_karen_qa", "pull request is not from the same repository")

    try:
        changed_paths = paths_from_pr_files(files)
    except KarenQaOrDataOnlyError as exc:
        path_reason = str(exc)
        blocked = True
        catalog_only = False
    else:
        blocked_paths = [
            path
            for path in changed_paths
            if not is_exempt_path(
                path,
                catalog_allowlist=catalog_allowlist,
                pipeline_allowlist=pipeline_allowlist,
            )
        ]
        blocked = bool(blocked_paths)
        catalog_only = not blocked and all(
            is_catalog_data_path(path, catalog_allowlist) for path in changed_paths
        )
        path_reason = (
            "every changed path is catalog data or CVE pipeline code"
            if not blocked
            else f"non-exempt path {blocked_paths[0]!r} is outside the catalog/pipeline allowlist"
        )

    if not blocked:
        outcome = "data_only" if catalog_only else "exempt"
        return _decision(
            outcome,
            path_reason,
            data_only=catalog_only,
            exempt=True,
        )

    if has_successful_karen_qa(head_sha=head_sha, statuses=statuses, check_runs=check_runs):
        return _decision(
            "karen_qa",
            f"karen-qa succeeded on the exact head; {path_reason}",
        )
    return _decision(
        "need_karen_qa",
        f"needs {KAREN_QA_CONTEXT} on {head_sha}; {path_reason}",
    )


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise KarenQaOrDataOnlyError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise KarenQaOrDataOnlyError(f"{path} is not valid JSON: {exc}") from exc


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--author-login", required=True)
    parser.add_argument("--head-branch", required=True)
    parser.add_argument("--base-branch", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--head-repository", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--files-json", type=Path, required=True)
    parser.add_argument("--statuses-json", type=Path)
    parser.add_argument("--check-runs-json", type=Path)
    parser.add_argument("--expected-base-branch", default=DEFAULT_BASE_BRANCH)
    parser.add_argument("--extra-bot-login", action="append", default=[])
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        decision = evaluate_karen_qa_or_data_only(
            author_login=args.author_login,
            head_branch=args.head_branch,
            base_branch=args.base_branch,
            repository=args.repository,
            head_repository=args.head_repository,
            head_sha=args.head_sha,
            files=load_json(args.files_json),
            statuses=load_json(args.statuses_json) if args.statuses_json else [],
            check_runs=load_json(args.check_runs_json) if args.check_runs_json else [],
            expected_base_branch=args.expected_base_branch,
            extra_bot_logins=args.extra_bot_login,
        )
    except KarenQaOrDataOnlyError as exc:
        decision = _decision("need_karen_qa", str(exc))

    description = decision.reason[:140]
    if args.github_output:
        args.github_output.write_text(
            "\n".join(
                [
                    f"outcome={decision.outcome}",
                    f"state={decision.status_state}",
                    f"context={decision.status_context}",
                    f"description={description}",
                    f"data_only={'true' if decision.data_only else 'false'}",
                    f"exempt={'true' if decision.exempt else 'false'}",
                    f"reason={decision.reason}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
    if args.json:
        print(
            json.dumps(
                {
                    "outcome": decision.outcome,
                    "reason": decision.reason,
                    "status_state": decision.status_state,
                    "status_context": decision.status_context,
                    "data_only": decision.data_only,
                    "exempt": decision.exempt,
                    "allowed": decision.allowed,
                },
                indent=2,
            )
        )
    else:
        print(f"{decision.outcome}: {decision.reason}")
    return 0 if decision.allowed else 1


if __name__ == "__main__":
    raise SystemExit(main())
