#!/usr/bin/env python3
"""Strict allowlist for CVE catalog-data-only pull requests.

A catalog PR written by the CVE sync bot may skip karen-qa and the GitHub App
requirement only when the exact-SHA diff touches these paths. Any workflow,
script, docs, MCP server, or other code path fails closed.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# Exact generated catalog artifacts the sync bot is allowed to rewrite.
# Behaviour-changing pipeline outputs (MCP/gateway policy, evidence packs,
# context packs, generator ownership) are intentionally excluded.
CATALOG_DATA_FILES = frozenset(
    {
        "data/cve/ai-enrichments.json",
        "data/cve/ai-generated-recipes.json",
        "data/cve/enrichment-carryover.json",
    }
)

# Directory prefixes. Matching uses a directory boundary (trailing slash);
# `static/api/cve-catalog-evil/x` must not match `static/api/cve-catalog/`.
CATALOG_DATA_PATH_PREFIXES = ("static/api/cve-catalog/",)

# Recipe drafts are allowlisted only as *.md files under this directory.
CATALOG_RECIPE_PREFIX = "content/recipes/cve/"
CATALOG_RECIPE_SUFFIX = ".md"

# Narrow pathspecs staged onto the self-merged catalog PR.
CATALOG_COMMIT_PATHSPECS = (
    "static/api/cve-catalog",
    "data/cve/ai-enrichments.json",
    "data/cve/ai-generated-recipes.json",
    "data/cve/enrichment-carryover.json",
    ":(glob)content/recipes/cve/*.md",
)

# Generator outputs that change MCP/gateway behaviour. These never self-merge.
GENERATED_BEHAVIOR_OUTPUT_PATHSPECS = (
    "data/evidence",
    "data/context/secure-context-release-pack.json",
    "data/policy/mcp-gateway-policy.json",
    "scripts/generated-output-ownership.json",
)


ALLOWED_FILE_MODE = "100644"
ZERO_MODE = "000000"
SYMLINK_MODE = "120000"


@dataclass(frozen=True)
class DiffPath:
    status: str
    path: str
    previous_path: str | None = None
    src_mode: str = ""
    dst_mode: str = ""


@dataclass(frozen=True)
class CatalogDiffDecision:
    data_only: bool
    sha_matches: bool
    expected_sha: str
    actual_sha: str
    paths: tuple[str, ...]
    rejected_paths: tuple[str, ...]
    unsafe_paths: tuple[str, ...]
    reason: str

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def normalize_sha(value: str | None) -> str | None:
    text = (value or "").strip().lower()
    if SHA_RE.fullmatch(text):
        return text
    return None


def normalize_repo_path(value: str | None) -> str | None:
    """Return a repo-relative POSIX path, or None if the path is unsafe."""

    if not isinstance(value, str):
        return None
    raw = value.replace("\\", "/").strip()
    if not raw or raw.startswith("/") or raw.startswith("~"):
        return None
    if len(raw) >= 2 and raw[1] == ":":
        return None
    parts: list[str] = []
    for part in raw.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            return None
        parts.append(part)
    if not parts:
        return None
    return "/".join(parts)


def path_matches_prefix(path: str, prefix: str) -> bool:
    """True when path is prefix or a descendant, using a directory boundary."""

    directory = (prefix or "").strip().replace("\\", "/").rstrip("/")
    if not directory or not path:
        return False
    return path == directory or path.startswith(directory + "/")


def is_allowed_catalog_recipe_path(path: str) -> bool:
    directory = CATALOG_RECIPE_PREFIX.rstrip("/")
    if path == directory:
        return True
    if not path_matches_prefix(path, directory):
        return False
    name = path.rsplit("/", 1)[-1]
    return name.endswith(CATALOG_RECIPE_SUFFIX) and name != CATALOG_RECIPE_SUFFIX


def is_catalog_data_path(path: str) -> bool:
    normalized = normalize_repo_path(path)
    if normalized is None:
        return False
    if normalized in CATALOG_DATA_FILES:
        return True
    if is_allowed_catalog_recipe_path(normalized):
        return True
    return any(path_matches_prefix(normalized, prefix) for prefix in CATALOG_DATA_PATH_PREFIXES)


def is_karen_gated_generated_output(path: str) -> bool:
    """True only for behaviour-changing packs that go to the Karen-gated review PR.

    Catalog data paths are never Karen-gated. Other non-catalog paths are also
    not Karen-gated: stale CVE-owned or unrelated outputs stay blocking.
    """

    normalized = normalize_repo_path(path)
    if normalized is None:
        return False
    return any(
        path_matches_prefix(normalized, spec)
        for spec in GENERATED_BEHAVIOR_OUTPUT_PATHSPECS
    )


def allowlisted_catalog_paths() -> tuple[str, ...]:
    prefixes = tuple(prefix.rstrip("/") + "/" for prefix in CATALOG_DATA_PATH_PREFIXES)
    recipes = (CATALOG_RECIPE_PREFIX.rstrip("/") + "/*" + CATALOG_RECIPE_SUFFIX,)
    return tuple(sorted(CATALOG_DATA_FILES)) + prefixes + recipes


def catalog_commit_pathspecs() -> tuple[str, ...]:
    return CATALOG_COMMIT_PATHSPECS


def generated_behavior_output_pathspecs() -> tuple[str, ...]:
    return GENERATED_BEHAVIOR_OUTPUT_PATHSPECS


def parse_name_status_z(payload: bytes) -> list[DiffPath]:
    parts = [item.decode("utf-8", "surrogateescape") for item in payload.split(b"\0") if item]
    records: list[DiffPath] = []
    index = 0
    while index < len(parts):
        status = parts[index]
        if not status:
            raise ValueError("empty git name-status field")
        code = status[0]
        if code in {"R", "C"}:
            if index + 2 >= len(parts):
                raise ValueError("truncated git rename/copy name-status")
            records.append(
                DiffPath(status=code, path=parts[index + 2], previous_path=parts[index + 1])
            )
            index += 3
            continue
        if index + 1 >= len(parts):
            raise ValueError("truncated git name-status")
        records.append(DiffPath(status=code, path=parts[index + 1]))
        index += 2
    return records


def parse_name_status_lines(text: str) -> list[DiffPath]:
    records: list[DiffPath] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        fields = line.split("\t")
        status = fields[0]
        if not status:
            raise ValueError(f"invalid git name-status line: {raw_line!r}")
        code = status[0]
        if code in {"R", "C"}:
            if len(fields) < 3:
                raise ValueError(f"truncated git rename/copy name-status: {raw_line!r}")
            records.append(DiffPath(status=code, path=fields[2], previous_path=fields[1]))
            continue
        if len(fields) < 2:
            raise ValueError(f"truncated git name-status: {raw_line!r}")
        records.append(DiffPath(status=code, path=fields[1]))
    return records


def parse_raw_z(payload: bytes) -> list[DiffPath]:
    parts = [item.decode("utf-8", "surrogateescape") for item in payload.split(b"\0") if item]
    records: list[DiffPath] = []
    index = 0
    while index < len(parts):
        meta = parts[index]
        if not meta.startswith(":"):
            raise ValueError(f"invalid git raw header: {meta!r}")
        fields = meta[1:].split()
        if len(fields) < 5:
            raise ValueError(f"truncated git raw header: {meta!r}")
        src_mode, dst_mode, _src_sha, _dst_sha, status = fields[:5]
        code = status[:1]
        if code in {"R", "C"}:
            if index + 2 >= len(parts):
                raise ValueError("truncated git rename/copy raw diff")
            records.append(
                DiffPath(
                    status=code,
                    path=parts[index + 2],
                    previous_path=parts[index + 1],
                    src_mode=src_mode,
                    dst_mode=dst_mode,
                )
            )
            index += 3
            continue
        if index + 1 >= len(parts):
            raise ValueError("truncated git raw diff")
        records.append(
            DiffPath(
                status=code,
                path=parts[index + 1],
                src_mode=src_mode,
                dst_mode=dst_mode,
            )
        )
        index += 2
    return records


def collect_git_name_status(base: str, head: str) -> list[DiffPath]:
    completed = subprocess.run(
        ["git", "diff", "--raw", "--find-renames", "-z", base, head],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip() or "git diff failed"
        raise ValueError(detail)
    return parse_raw_z(completed.stdout)


def unsafe_change_reason(item: DiffPath) -> str | None:
    code = item.status[:1] if item.status else ""
    if code == "T":
        return "type-change"
    modes = {item.src_mode, item.dst_mode} - {""}
    if SYMLINK_MODE in modes:
        return "symlink"
    src = item.src_mode
    dst = item.dst_mode
    if src and dst and src != ZERO_MODE and dst != ZERO_MODE and src != dst:
        return "mode-change"
    if dst and dst not in {ZERO_MODE, ALLOWED_FILE_MODE}:
        return "mode-change"
    if src and src not in {ZERO_MODE, ALLOWED_FILE_MODE} and code != "D":
        return "mode-change"
    return None


def evaluate_catalog_diff(
    files: Iterable[DiffPath],
    *,
    expected_sha: str,
    actual_sha: str,
) -> CatalogDiffDecision:
    expected = normalize_sha(expected_sha)
    actual = normalize_sha(actual_sha)
    expected_text = expected or (expected_sha or "").strip()
    actual_text = actual or (actual_sha or "").strip()
    if expected is None or actual is None or expected != actual:
        return CatalogDiffDecision(
            data_only=False,
            sha_matches=False,
            expected_sha=expected_text,
            actual_sha=actual_text,
            paths=(),
            rejected_paths=(),
            unsafe_paths=(),
            reason=(
                f"Catalog exact SHA mismatch: expected={expected_text or '<invalid>'} "
                f"actual={actual_text or '<invalid>'}."
            ),
        )

    paths: list[str] = []
    rejected: list[str] = []
    unsafe: list[str] = []
    seen: set[str] = set()
    for item in files:
        change_reason = unsafe_change_reason(item)
        if change_reason:
            unsafe.append(f"{item.path} ({change_reason})")
        candidates = (item.path, item.previous_path)
        for candidate in candidates:
            if not candidate:
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            paths.append(candidate)
            normalized = normalize_repo_path(candidate)
            if normalized is None:
                unsafe.append(candidate)
                continue
            if not is_catalog_data_path(normalized):
                rejected.append(normalized)

    if unsafe:
        return CatalogDiffDecision(
            data_only=False,
            sha_matches=True,
            expected_sha=expected,
            actual_sha=actual,
            paths=tuple(paths),
            rejected_paths=tuple(rejected),
            unsafe_paths=tuple(unsafe),
            reason=(
                "Catalog diff contains a path-traversal, symlink, mode change, "
                f"or unsafe path; failing closed: {', '.join(unsafe)}."
            ),
        )
    if rejected:
        return CatalogDiffDecision(
            data_only=False,
            sha_matches=True,
            expected_sha=expected,
            actual_sha=actual,
            paths=tuple(paths),
            rejected_paths=tuple(rejected),
            unsafe_paths=(),
            reason=(
                "Catalog PR is not data-only; code, workflow, docs, and MCP changes "
                f"require karen-qa and real checks. Rejected paths: {', '.join(rejected)}."
            ),
        )
    return CatalogDiffDecision(
        data_only=True,
        sha_matches=True,
        expected_sha=expected,
        actual_sha=actual,
        paths=tuple(paths),
        rejected_paths=(),
        unsafe_paths=(),
        reason=f"Exact SHA {expected} touches only allowlisted catalog data paths.",
    )


def evaluate_git_catalog_diff(*, expected_sha: str, actual_sha: str, base: str, head: str) -> CatalogDiffDecision:
    return evaluate_catalog_diff(
        collect_git_name_status(base, head),
        expected_sha=expected_sha,
        actual_sha=actual_sha,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--actual-sha", required=True)
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument(
        "--name-status",
        help="Path to git name-status text (TAB-separated). Use - for stdin.",
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.name_status:
        if args.name_status == "-":
            payload = sys.stdin.read()
        else:
            payload = Path(args.name_status).read_text(encoding="utf-8")
        files = parse_name_status_lines(payload)
        decision = evaluate_catalog_diff(
            files,
            expected_sha=args.expected_sha,
            actual_sha=args.actual_sha,
        )
    else:
        if not args.base or not args.head:
            raise SystemExit("either --name-status or both --base and --head are required")
        decision = evaluate_git_catalog_diff(
            expected_sha=args.expected_sha,
            actual_sha=args.actual_sha,
            base=args.base,
            head=args.head,
        )
    if args.json:
        print(json.dumps(decision.to_json(), indent=2, sort_keys=True))
        return 0
    print(decision.reason)
    if decision.rejected_paths:
        print("rejected_paths=" + "\n".join(decision.rejected_paths))
    if decision.unsafe_paths:
        print("unsafe_paths=" + "\n".join(decision.unsafe_paths))
    return 0 if decision.data_only and decision.sha_matches else 1


if __name__ == "__main__":
    raise SystemExit(main())
