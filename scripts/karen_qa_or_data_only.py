#!/usr/bin/env python3
"""Decide whether a PR may skip karen-qa as a data-only CVE catalog sync.

Stephen's ruling: data-only catalog PRs from the CVE sync bot skip karen-qa
on main. Every other PR still needs the real karen-qa context on the exact
head. The allowlist is the tight set of paths ``cve-catalog-sync.yml``
commits; it is not a ``scripts/`` or ``.github/`` prefix.
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

# Identities used by cve-catalog-sync.yml: GITHUB_TOKEN opens the PR as
# github-actions[bot]; commits are authored as security-recipes-cve-bot;
# optional CVE_AUTOMATION_APP tokens open the PR as that app's [bot] user.
CVE_CATALOG_SYNC_BOT_LOGINS = frozenset(
    {
        "github-actions[bot]",
        "security-recipes-cve-bot",
        "security-recipes-cve-bot[bot]",
    }
)

# Paths the sync workflow `git add`s after writing catalog outputs. Keep this
# list identical to that commit set; do not widen it to scripts/ or workflows.
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

    @property
    def allowed(self) -> bool:
        return self.status_state == "success"

    @property
    def requires_karen_qa(self) -> bool:
        return not self.data_only


class KarenQaOrDataOnlyError(ValueError):
    """Raised when the evaluator cannot parse its inputs."""


def catalog_sync_commit_paths(workflow_text: str) -> tuple[str, ...]:
    """Return the tight path allowlist from the sync workflow's git add set."""
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


def is_data_only_catalog_path(path: str, allowlist: tuple[str, ...] = CATALOG_SYNC_COMMIT_PATHS) -> bool:
    normalized = normalize_repo_path(path)
    if normalized is None:
        return False
    for allowed in allowlist:
        allowed_norm = normalize_repo_path(allowed)
        if allowed_norm is None:
            continue
        if _is_directory_allowlist_entry(allowed_norm):
            if normalized == allowed_norm or normalized.startswith(f"{allowed_norm}/"):
                return True
            continue
        if normalized == allowed_norm:
            return True
    return False


def paths_from_pr_files(files: Any) -> tuple[str, ...]:
    """Collect current and previous paths from the Pull Request Files API.

    Uses ``filename`` / ``previous_filename`` / ``status`` only. Diff text
    (``patch``) is ignored. Renames and copies without a previous path, and
    any unreadable entry, are treated as non-data.
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


def is_cve_catalog_sync_bot(login: str, extra_logins: Iterable[str] = ()) -> bool:
    allowed = set(CVE_CATALOG_SYNC_BOT_LOGINS)
    for item in extra_logins:
        if isinstance(item, str) and item.strip():
            allowed.add(item.strip())
    return login.strip() in allowed if isinstance(login, str) else False


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


def _decision(outcome: str, reason: str, *, data_only: bool = False) -> KarenQaOrDataOnlyDecision:
    allowed = outcome in {"data_only", "karen_qa"}
    return KarenQaOrDataOnlyDecision(
        outcome=outcome,
        reason=reason,
        status_state="success" if allowed else "failure",
        data_only=data_only,
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
    allowlist: tuple[str, ...] = CATALOG_SYNC_COMMIT_PATHS,
    sync_branch: str = CVE_CATALOG_SYNC_BRANCH,
) -> KarenQaOrDataOnlyDecision:
    """Return whether this exact head may skip karen-qa or must still have it."""
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
        data_only = False
        path_reason = str(exc)
    else:
        blocked = [path for path in changed_paths if not is_data_only_catalog_path(path, allowlist)]
        data_only = not blocked
        path_reason = (
            "every changed path is a catalog sync output"
            if data_only
            else f"non-data path {blocked[0]!r} is outside the catalog sync allowlist"
        )

    bot = is_cve_catalog_sync_bot(author_login, extra_bot_logins)
    branch_ok = head_branch == sync_branch
    if bot and branch_ok and data_only:
        return _decision(
            "data_only",
            "CVE catalog sync bot changed only catalog data paths on the sync branch",
            data_only=True,
        )

    reasons: list[str] = []
    if not bot:
        reasons.append(f"author {author_login!r} is not the CVE catalog sync bot")
    if not branch_ok:
        reasons.append(f"head branch {head_branch!r} is not {sync_branch!r}")
    if not data_only:
        reasons.append(path_reason)

    if has_successful_karen_qa(head_sha=head_sha, statuses=statuses, check_runs=check_runs):
        return _decision(
            "karen_qa",
            "karen-qa succeeded on the exact head; " + "; ".join(reasons),
        )
    return _decision(
        "need_karen_qa",
        f"needs {KAREN_QA_CONTEXT} on {head_sha}; " + "; ".join(reasons),
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
