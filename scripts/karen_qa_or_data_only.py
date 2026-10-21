#!/usr/bin/env python3
"""Decide whether a PR may skip karen-qa as CVE catalog data only.

Stephen's Oct 21, 2026 1:08 PM MST ruling: only CVE catalog content skips
Karen. Pipeline code, docs, and MCP servers still need karen-qa. The
exemption requires the catalog sync bot, the sync branch, a complete
Files API list, regular-file tree modes, and bot-only commits.
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
FILES_API_CAP = 3000
REGULAR_FILE_MODE = "100644"

# Karen QA GitHub App. The main ruleset already pins karen-qa to this
# integration. Statuses and check runs from any other app or user do not count.
KAREN_QA_APP_ID = 5400051
# GitHub Actions app. Documented so the ruleset can pin karen-qa-or-data-only
# to this integration id (a plain commit status cannot satisfy that pin).
GITHUB_ACTIONS_APP_ID = 15368
KAREN_QA_USER_IDS: frozenset[int] = frozenset()

BOT_GIT_NAME = "security-recipes-cve-bot"
BOT_GIT_EMAIL = "security-recipes-cve-bot@users.noreply.github.com"
BOT_PR_LOGINS = frozenset(
    {
        "github-actions[bot]",
        "security-recipes-cve-bot[bot]",
    }
)

# Paths the sync workflow `git add`s after writing outputs. Policy and
# ownership are committed by the sync but are not catalog data and stay
# outside the exemption.
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

CATALOG_DATA_FILES = (
    "data/cve/ai-enrichments.json",
    "data/cve/ai-generated-recipes.json",
)

# Directory prefix -> allowed suffixes. The directory itself is not a data file.
CATALOG_DATA_DIRECTORIES: tuple[tuple[str, frozenset[str]], ...] = (
    ("static/api/cve-catalog", frozenset({".json", ".gz"})),
    ("content/recipes/cve", frozenset({".md"})),
    ("data/evidence", frozenset({".json"})),
)

EXEMPT_PATHS = CATALOG_DATA_FILES + tuple(directory for directory, _exts in CATALOG_DATA_DIRECTORIES)

# Changing the gate or its ruleset docs cannot satisfy the gate.
GATE_PATHS = (
    ".github/workflows/karen-qa-or-data-only.yml",
    "scripts/karen_qa_or_data_only.py",
    "tests/test_karen_qa_or_data_only.py",
    "tests/test_karen_qa_or_data_only_workflow.py",
)

_GIT_ADD_PATHS_RE = re.compile(r"git add -A -- \\\n(?P<body>(?:[ \t]+\S+[ \t]*\\?\n)+)")
_SYNC_BRANCH_RE = re.compile(r"(?m)^[ \t]+BRANCH:[ \t]+(\S+)[ \t]*$")
_SYNC_GIT_USER_RE = re.compile(r'git config user\.name "([^"]+)"')
_SYNC_GIT_EMAIL_RE = re.compile(r'git config user\.email "([^"]+)"')


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

    @property
    def check_conclusion(self) -> str:
        return "success" if self.allowed else "failure"


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


def catalog_sync_git_email(workflow_text: str) -> str:
    match = _SYNC_GIT_EMAIL_RE.search(workflow_text)
    if match is None:
        raise KarenQaOrDataOnlyError("cve-catalog-sync workflow is missing git user.email")
    return match.group(1)


def normalize_repo_path(path: str) -> str | None:
    if not isinstance(path, str):
        return None
    if "\\" in path:
        return None
    text = path.strip()
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


def is_gate_path(path: str) -> bool:
    normalized = normalize_repo_path(path)
    return normalized in GATE_PATHS if normalized is not None else False


def is_catalog_data_path(path: str) -> bool:
    normalized = normalize_repo_path(path)
    if normalized is None or normalized in GATE_PATHS:
        return False
    if normalized in CATALOG_DATA_FILES:
        return True
    suffix = Path(normalized).suffix.lower()
    for directory, extensions in CATALOG_DATA_DIRECTORIES:
        if normalized == directory:
            return False
        if normalized.startswith(f"{directory}/") and suffix in extensions:
            return True
    return False


def is_exempt_path(path: str) -> bool:
    return is_catalog_data_path(path)


# Back-compat alias used by earlier tests.
is_data_only_catalog_path = is_catalog_data_path


def bot_logins(extra_bot_logins: Iterable[str] = ()) -> frozenset[str]:
    allowed = set(BOT_PR_LOGINS)
    for login in extra_bot_logins:
        if isinstance(login, str) and login.endswith("[bot]") and login.strip():
            allowed.add(login)
    return frozenset(allowed)


def is_catalog_sync_bot_author(
    author_login: str,
    author_type: str,
    *,
    extra_bot_logins: Iterable[str] = (),
) -> bool:
    return author_type == "Bot" and author_login in bot_logins(extra_bot_logins)


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


def validate_file_list_complete(files: Any, changed_files: int | None) -> list[Any]:
    entries = _as_list(files)
    if not isinstance(changed_files, int) or isinstance(changed_files, bool) or changed_files < 0:
        raise KarenQaOrDataOnlyError("changed_files is missing or not a count")
    if changed_files >= FILES_API_CAP:
        raise KarenQaOrDataOnlyError(
            f"changed_files {changed_files} meets the Files API cap of {FILES_API_CAP}"
        )
    if len(entries) != changed_files:
        raise KarenQaOrDataOnlyError(
            f"Files API returned {len(entries)} files but changed_files is {changed_files}"
        )
    if not entries:
        raise KarenQaOrDataOnlyError("PR file list is empty")
    return entries


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("check_runs", "statuses", "files", "commits", "tree"):
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


def _int_id(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _app_id(entry: dict[str, Any]) -> int | None:
    app = entry.get("app")
    if isinstance(app, dict):
        return _int_id(app.get("id"))
    return None


def _creator_id(entry: dict[str, Any]) -> int | None:
    creator = entry.get("creator")
    if isinstance(creator, dict):
        return _int_id(creator.get("id"))
    return None


def _result_time(entry: dict[str, Any]) -> str:
    for key in ("completed_at", "updated_at", "started_at", "created_at"):
        value = entry.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def trusted_karen_qa_results(
    *,
    head_sha: str,
    statuses: Any = None,
    check_runs: Any = None,
    karen_qa_app_id: int = KAREN_QA_APP_ID,
    karen_qa_user_ids: Iterable[int] = KAREN_QA_USER_IDS,
) -> list[dict[str, Any]]:
    """Return pinned karen-qa results on ``head_sha``, newest first."""
    allowed_users = frozenset(int(user_id) for user_id in karen_qa_user_ids)
    results: list[dict[str, Any]] = []
    for run in _as_list(check_runs):
        if not isinstance(run, dict):
            continue
        if run.get("name") != KAREN_QA_CONTEXT:
            continue
        if _app_id(run) != karen_qa_app_id:
            continue
        run_sha = _payload_sha(run)
        if run_sha != head_sha:
            continue
        results.append(
            {
                "source": "check_run",
                "ok": run.get("conclusion") == "success",
                "when": _result_time(run),
            }
        )
    for status in _as_list(statuses):
        if not isinstance(status, dict):
            continue
        if status.get("context") != KAREN_QA_CONTEXT:
            continue
        if _creator_id(status) not in allowed_users:
            continue
        status_sha = _payload_sha(status)
        if status_sha != head_sha:
            continue
        results.append(
            {
                "source": "status",
                "ok": status.get("state") == "success",
                "when": _result_time(status),
            }
        )
    results.sort(key=lambda item: item["when"], reverse=True)
    return results


def has_successful_karen_qa(
    *,
    head_sha: str,
    statuses: Any = None,
    check_runs: Any = None,
    karen_qa_app_id: int = KAREN_QA_APP_ID,
    karen_qa_user_ids: Iterable[int] = KAREN_QA_USER_IDS,
) -> bool:
    if not HEAD_SHA_RE.fullmatch(head_sha):
        return False
    results = trusted_karen_qa_results(
        head_sha=head_sha,
        statuses=statuses,
        check_runs=check_runs,
        karen_qa_app_id=karen_qa_app_id,
        karen_qa_user_ids=karen_qa_user_ids,
    )
    return bool(results) and bool(results[0]["ok"])


def _person_is_bot(
    *,
    git_person: Any,
    github_person: Any,
    extra_bot_logins: Iterable[str] = (),
) -> bool:
    allowed = bot_logins(extra_bot_logins)
    if isinstance(git_person, dict):
        if git_person.get("name") == BOT_GIT_NAME or git_person.get("email") == BOT_GIT_EMAIL:
            return True
    if isinstance(github_person, dict) and github_person.get("login") in allowed:
        return True
    return False


def commit_authored_or_pushed_by_bot(commit: Any, *, extra_bot_logins: Iterable[str] = ()) -> bool:
    if not isinstance(commit, dict):
        return False
    commit_block = commit.get("commit")
    git_author = commit_block.get("author") if isinstance(commit_block, dict) else None
    git_committer = commit_block.get("committer") if isinstance(commit_block, dict) else None
    authored = _person_is_bot(
        git_person=git_author,
        github_person=commit.get("author"),
        extra_bot_logins=extra_bot_logins,
    )
    pushed = _person_is_bot(
        git_person=git_committer,
        github_person=commit.get("committer"),
        extra_bot_logins=extra_bot_logins,
    )
    return authored or pushed


def validate_bot_commits(commits: Any, *, extra_bot_logins: Iterable[str] = ()) -> None:
    entries = _as_list(commits)
    if not entries:
        raise KarenQaOrDataOnlyError("PR commit list is empty")
    for commit in entries:
        if not commit_authored_or_pushed_by_bot(commit, extra_bot_logins=extra_bot_logins):
            sha = _payload_sha(commit) if isinstance(commit, dict) else ""
            label = sha or "unknown"
            raise KarenQaOrDataOnlyError(
                f"commit {label} is not authored or pushed by the CVE catalog sync bot"
            )


def tree_modes(tree_payload: Any) -> dict[str, str]:
    if tree_payload is None:
        raise KarenQaOrDataOnlyError("git tree is missing")
    if not isinstance(tree_payload, dict):
        raise KarenQaOrDataOnlyError("git tree must be an object")
    if tree_payload.get("truncated") is True:
        raise KarenQaOrDataOnlyError("git tree is truncated; refusing to evaluate modes")
    entries = tree_payload.get("tree")
    if not isinstance(entries, list):
        raise KarenQaOrDataOnlyError("git tree is missing a tree array")
    modes: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        path = entry.get("path")
        mode = entry.get("mode")
        if isinstance(path, str) and isinstance(mode, str):
            modes[path] = mode
    return modes


def validate_regular_file_modes(
    paths: Iterable[str],
    *,
    head_tree: Any,
    base_tree: Any,
) -> None:
    head_modes = tree_modes(head_tree)
    base_modes = tree_modes(base_tree)
    for path in paths:
        normalized = normalize_repo_path(path)
        if normalized is None:
            raise KarenQaOrDataOnlyError(f"unreadable path {path!r} in git trees")
        head_mode = head_modes.get(normalized)
        base_mode = base_modes.get(normalized)
        if head_mode is None and base_mode is None:
            raise KarenQaOrDataOnlyError(f"path {normalized!r} is missing from the git trees")
        for label, mode in (("head", head_mode), ("base", base_mode)):
            if mode is not None and mode != REGULAR_FILE_MODE:
                raise KarenQaOrDataOnlyError(
                    f"{label} mode {mode} for {normalized!r} is not a regular file"
                )
        if head_mode is not None and base_mode is not None and head_mode != base_mode:
            raise KarenQaOrDataOnlyError(f"mode change for {normalized!r}: {base_mode} -> {head_mode}")


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
    author_type: str = "",
    observed_head_sha: str = "",
    changed_files: int | None = None,
    commits: Any = None,
    head_tree: Any = None,
    base_tree: Any = None,
    statuses: Any = None,
    check_runs: Any = None,
    expected_base_branch: str = DEFAULT_BASE_BRANCH,
    extra_bot_logins: Iterable[str] = (),
    allowlist: tuple[str, ...] | None = None,
    sync_branch: str = CVE_CATALOG_SYNC_BRANCH,
    karen_qa_app_id: int = KAREN_QA_APP_ID,
    karen_qa_user_ids: Iterable[int] = KAREN_QA_USER_IDS,
) -> KarenQaOrDataOnlyDecision:
    """Return whether this exact head may skip karen-qa or must still have it.

    ``allowlist`` is accepted for CLI compatibility and ignored: the
    exemption is the fixed CVE catalog data set, not a caller-supplied list.
    """
    del allowlist
    if not HEAD_SHA_RE.fullmatch(head_sha or ""):
        return _decision("need_karen_qa", "head SHA is missing or not a full commit SHA")
    if observed_head_sha and observed_head_sha != head_sha:
        return _decision("need_karen_qa", "head SHA changed while reading the file list")
    if base_branch != expected_base_branch:
        return _decision(
            "need_karen_qa",
            f"base branch {base_branch!r} is not {expected_base_branch!r}",
        )
    if head_repository != repository or not repository:
        return _decision("need_karen_qa", "pull request is not from the same repository")

    file_reason = ""
    try:
        validate_file_list_complete(files, changed_files)
        changed_paths = paths_from_pr_files(files)
    except KarenQaOrDataOnlyError as exc:
        file_reason = str(exc)
        changed_paths = ()
        path_ok = False
    else:
        blocked_paths = [path for path in changed_paths if not is_catalog_data_path(path)]
        path_ok = not blocked_paths
        file_reason = (
            "every changed path is CVE catalog data"
            if path_ok
            else f"non-exempt path {blocked_paths[0]!r} is outside the catalog data allowlist"
        )

    identity_reasons: list[str] = []
    if not is_catalog_sync_bot_author(author_login, author_type, extra_bot_logins=extra_bot_logins):
        identity_reasons.append("PR author is not the CVE catalog sync bot")
    if head_branch != sync_branch:
        identity_reasons.append(f"head branch {head_branch!r} is not {sync_branch!r}")
    try:
        validate_bot_commits(commits, extra_bot_logins=extra_bot_logins)
    except KarenQaOrDataOnlyError as exc:
        identity_reasons.append(str(exc))

    tree_reason = ""
    if path_ok:
        try:
            validate_regular_file_modes(changed_paths, head_tree=head_tree, base_tree=base_tree)
        except KarenQaOrDataOnlyError as exc:
            tree_reason = str(exc)
            path_ok = False

    if path_ok and not identity_reasons:
        return _decision(
            "data_only",
            file_reason,
            data_only=True,
            exempt=True,
        )

    path_reason = file_reason
    if tree_reason:
        path_reason = tree_reason
    elif identity_reasons and path_ok:
        path_reason = identity_reasons[0]

    if has_successful_karen_qa(
        head_sha=head_sha,
        statuses=statuses,
        check_runs=check_runs,
        karen_qa_app_id=karen_qa_app_id,
        karen_qa_user_ids=karen_qa_user_ids,
    ):
        return _decision(
            "karen_qa",
            f"karen-qa succeeded on the exact head; {path_reason}",
        )
    return _decision(
        "need_karen_qa",
        f"needs {KAREN_QA_CONTEXT} on {head_sha} from Karen QA app {karen_qa_app_id}; {path_reason}",
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
    parser.add_argument("--author-type", required=True)
    parser.add_argument("--head-branch", required=True)
    parser.add_argument("--base-branch", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--head-repository", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--observed-head-sha")
    parser.add_argument("--changed-files", type=int, required=True)
    parser.add_argument("--files-json", type=Path, required=True)
    parser.add_argument("--commits-json", type=Path)
    parser.add_argument("--head-tree-json", type=Path)
    parser.add_argument("--base-tree-json", type=Path)
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
            author_type=args.author_type,
            head_branch=args.head_branch,
            base_branch=args.base_branch,
            repository=args.repository,
            head_repository=args.head_repository,
            head_sha=args.head_sha,
            observed_head_sha=args.observed_head_sha or args.head_sha,
            changed_files=args.changed_files,
            files=load_json(args.files_json),
            commits=load_json(args.commits_json) if args.commits_json else [],
            head_tree=load_json(args.head_tree_json) if args.head_tree_json else None,
            base_tree=load_json(args.base_tree_json) if args.base_tree_json else None,
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
                    f"conclusion={decision.check_conclusion}",
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
                    "check_conclusion": decision.check_conclusion,
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
