#!/usr/bin/env python3
"""Retry-safe decisions for CVE catalog PR delivery.

Data-only catalog PRs skip karen-qa and the GitHub App check. If branch
protection still blocks the merge, the sync leaves the PR open and retries
on the next run instead of failing. Non-data-only diffs fail closed.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

ALERT_ACTIONS = frozenset(
    {
        "fail_closed_not_data_only",
        "fail_closed_sha_mismatch",
        "fail_closed_real_checks",
        "fail_closed_missing_in_run_validation",
        "fail_closed_head_mismatch",
        "fail_unexpected",
        "identity_changed",
    }
)
SYNC_BRANCH = "automation/cve-catalog-sync"
FALLBACK_LABEL = "automation:protection-fallback"
PROTECTION_MARKERS = (
    "required status check",
    "required status checks",
    "required checks",
    "rule violations",
    "changes must be made through a pull request",
)


@dataclass(frozen=True)
class CatalogMergePolicy:
    skip_karen_qa: bool
    require_real_checks: bool
    attach_build_check_on_pr_head: bool
    protection_fallback: bool
    merge_with_workflow_token: bool
    action: str
    message: str

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def is_alert_action(action: str) -> bool:
    return action in ALERT_ACTIONS


def policy_for_catalog_pr(*, data_only: bool, sha_matches: bool, app_configured: bool) -> CatalogMergePolicy:
    if not sha_matches:
        return CatalogMergePolicy(
            skip_karen_qa=False,
            require_real_checks=True,
            attach_build_check_on_pr_head=False,
            protection_fallback=False,
            merge_with_workflow_token=False,
            action="fail_closed_sha_mismatch",
            message="Catalog exact SHA mismatch; failing closed.",
        )
    if not data_only:
        return CatalogMergePolicy(
            skip_karen_qa=False,
            require_real_checks=True,
            attach_build_check_on_pr_head=False,
            protection_fallback=False,
            merge_with_workflow_token=False,
            action="fail_closed_not_data_only",
            message=(
                "Catalog PR is not data-only; karen-qa and real workflow checks "
                "are required. Failing closed."
            ),
        )
    return CatalogMergePolicy(
        skip_karen_qa=True,
        require_real_checks=True,
        attach_build_check_on_pr_head=not app_configured,
        protection_fallback=True,
        merge_with_workflow_token=True,
        action="validate_and_merge",
        message=(
            "Data-only catalog PR skips karen-qa and the GitHub App check; "
            "exact-SHA validation satisfies the required build check."
        ),
    )


def validation_ref(
    *,
    data_only: bool,
    app_configured: bool,
    default_branch: str,
    pr_branch: str,
) -> str:
    if data_only and not app_configured:
        return pr_branch
    return default_branch


def can_reuse_in_run_validation(
    *,
    in_run_validation_passed: bool,
    validated_sha: str,
    expected_sha: str,
) -> bool:
    return bool(in_run_validation_passed) and validated_sha == expected_sha and bool(expected_sha)


@dataclass(frozen=True)
class SelfMergeGate:
    allowed: bool
    action: str
    message: str
    used_author: bool

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def self_merge_gate(
    *,
    data_only: bool,
    sha_matches: bool,
    in_run_validation_passed: bool,
    validated_sha: str,
    head_branch: str,
    head_sha: str,
    pushed_sha: str,
    sync_branch: str,
    author: str = "",
) -> SelfMergeGate:
    """Allow self-merge only when (a)+(b)+(c) all hold. Author is never a gate."""

    del author  # github-actions[bot] can be spoofed by any GITHUB_TOKEN workflow.
    if not sha_matches:
        return SelfMergeGate(
            allowed=False,
            action="fail_closed_sha_mismatch",
            message="Catalog exact SHA mismatch; failing closed.",
            used_author=False,
        )
    if not data_only:
        return SelfMergeGate(
            allowed=False,
            action="fail_closed_not_data_only",
            message=(
                "Catalog PR is not data-only; author identity is ignored. "
                "karen-qa and real workflow checks are required. Failing closed."
            ),
            used_author=False,
        )
    if head_branch != sync_branch or head_sha != pushed_sha:
        return SelfMergeGate(
            allowed=False,
            action="fail_closed_head_mismatch",
            message=(
                "Catalog head branch or SHA is not the sync branch revision this "
                "run pushed; failing closed."
            ),
            used_author=False,
        )
    if not in_run_validation_passed or validated_sha != pushed_sha or validated_sha != head_sha:
        return SelfMergeGate(
            allowed=False,
            action="fail_closed_missing_in_run_validation",
            message=(
                "Self-merge requires a passing exact-SHA validation produced in "
                "this sync run on the pushed SHA; failing closed."
            ),
            used_author=False,
        )
    return SelfMergeGate(
        allowed=True,
        action="validate_and_merge",
        message=(
            "Data-only exact-SHA diff, in-run validation, and pushed sync-branch "
            "head all match; author is not a merge gate."
        ),
        used_author=False,
    )


def classify_pr_state(
    *,
    state: str,
    merged: bool,
    head_repository: str,
    head_branch: str,
    head_sha: str,
    base_branch: str,
    expected_repository: str,
    expected_branch: str,
    expected_sha: str,
    expected_base: str,
) -> str:
    if merged:
        return "already_merged"
    if state != "open":
        return "fail_unexpected"
    if (
        head_repository != expected_repository
        or head_branch != expected_branch
        or base_branch != expected_base
    ):
        return "identity_changed"
    if head_sha != expected_sha:
        return "head_moved"
    return "current"


def classify_merge_error(*, data_only: bool, error_text: str) -> str:
    blob = (error_text or "").lower()
    karen = "karen-qa" in blob
    protection = karen or any(marker in blob for marker in PROTECTION_MARKERS)
    if data_only and protection:
        return "protection_fallback"
    if karen:
        return "wait_karen_qa"
    if protection:
        return "fail_closed_real_checks"
    return "fail_unexpected"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    policy = sub.add_parser("policy")
    policy.add_argument("--data-only", required=True, choices=("true", "false"))
    policy.add_argument("--sha-matches", required=True, choices=("true", "false"))
    policy.add_argument("--app-configured", required=True, choices=("true", "false"))

    state = sub.add_parser("pr-state")
    state.add_argument("--pr-json")
    state.add_argument("--pr-json-file")
    state.add_argument("--expected-repository", required=True)
    state.add_argument("--expected-branch", required=True)
    state.add_argument("--expected-sha", required=True)
    state.add_argument("--expected-base", required=True)

    merge_error = sub.add_parser("merge-error")
    merge_error.add_argument("--data-only", required=True, choices=("true", "false"))
    merge_error.add_argument("--error-text", default="")
    merge_error.add_argument("--error-file", action="append", default=[])

    reuse = sub.add_parser("reuse-in-run-validation")
    reuse.add_argument("--in-run-validation-passed", required=True, choices=("true", "false"))
    reuse.add_argument("--validated-sha", required=True)
    reuse.add_argument("--expected-sha", required=True)

    gate = sub.add_parser("self-merge-gate")
    gate.add_argument("--data-only", required=True, choices=("true", "false"))
    gate.add_argument("--sha-matches", required=True, choices=("true", "false"))
    gate.add_argument("--in-run-validation-passed", required=True, choices=("true", "false"))
    gate.add_argument("--validated-sha", required=True)
    gate.add_argument("--head-branch", required=True)
    gate.add_argument("--head-sha", required=True)
    gate.add_argument("--pushed-sha", required=True)
    gate.add_argument("--sync-branch", required=True)
    gate.add_argument("--author", default="")

    ref = sub.add_parser("validation-ref")
    ref.add_argument("--data-only", required=True, choices=("true", "false"))
    ref.add_argument("--app-configured", required=True, choices=("true", "false"))
    ref.add_argument("--default-branch", required=True)
    ref.add_argument("--pr-branch", required=True)

    return parser.parse_args(argv)


def _flag(value: str) -> bool:
    return value == "true"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command == "policy":
        decision = policy_for_catalog_pr(
            data_only=_flag(args.data_only),
            sha_matches=_flag(args.sha_matches),
            app_configured=_flag(args.app_configured),
        )
        print(json.dumps(decision.to_json(), indent=2, sort_keys=True))
        return 0
    if args.command == "pr-state":
        if args.pr_json_file:
            payload = json.loads(Path(args.pr_json_file).read_text(encoding="utf-8"))
        elif args.pr_json:
            payload = json.loads(args.pr_json)
        else:
            raise SystemExit("pr-state requires --pr-json or --pr-json-file")
        head = payload.get("head") or {}
        head_repo = head.get("repo") or {}
        base = payload.get("base") or {}
        action = classify_pr_state(
            state=str(payload.get("state") or ""),
            merged=payload.get("merged") is True,
            head_repository=str(head_repo.get("full_name") or ""),
            head_branch=str(head.get("ref") or ""),
            head_sha=str(head.get("sha") or ""),
            base_branch=str(base.get("ref") or ""),
            expected_repository=args.expected_repository,
            expected_branch=args.expected_branch,
            expected_sha=args.expected_sha,
            expected_base=args.expected_base,
        )
        print(action)
        return 0
    if args.command == "merge-error":
        chunks = [args.error_text]
        for path in args.error_file:
            chunks.append(Path(path).read_text(encoding="utf-8", errors="replace"))
        action = classify_merge_error(data_only=_flag(args.data_only), error_text="\n".join(chunks))
        print(action)
        return 0
    if args.command == "reuse-in-run-validation":
        reuse = can_reuse_in_run_validation(
            in_run_validation_passed=_flag(args.in_run_validation_passed),
            validated_sha=args.validated_sha,
            expected_sha=args.expected_sha,
        )
        print("true" if reuse else "false")
        return 0
    if args.command == "self-merge-gate":
        decision = self_merge_gate(
            data_only=_flag(args.data_only),
            sha_matches=_flag(args.sha_matches),
            in_run_validation_passed=_flag(args.in_run_validation_passed),
            validated_sha=args.validated_sha,
            head_branch=args.head_branch,
            head_sha=args.head_sha,
            pushed_sha=args.pushed_sha,
            sync_branch=args.sync_branch,
            author=args.author,
        )
        print(json.dumps(decision.to_json(), indent=2, sort_keys=True))
        return 0
    if args.command == "validation-ref":
        print(
            validation_ref(
                data_only=_flag(args.data_only),
                app_configured=_flag(args.app_configured),
                default_branch=args.default_branch,
                pr_branch=args.pr_branch,
            )
        )
        return 0
    raise SystemExit(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
